//! 狀態快照寫入（規格 05 第 5 節）：保護 Flash 壽命
//!
//! - 資料平常放記憶體，`stage()` 只是登記「這份資料最新的內容」。
//! - `flush()` 依儲存類型的最短間隔與每日寫入上限決定要不要真的寫。
//! - 內容沒變不寫；寫入用暫存檔 + fsync + 改名，斷電不會留下半個檔案。
//! - 關機時 `flush_all()` 不管間隔與上限，把有變動的都寫出去。

use crate::sysinfo::StorageClass;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct Policy {
    pub class: StorageClass,
    /// 同一個檔案兩次寫入的最短間隔（秒）
    pub min_interval: u64,
    /// 每天最多寫入 Flash 的位元組數（只對 Flash 有效）
    pub daily_budget: u64,
}

impl Policy {
    /// 依設定與儲存類型決定（`interval_min` = 0 表示自動）
    pub fn new(class: StorageClass, interval_min: u64, budget_kb: u64, tiny: bool) -> Policy {
        let auto = match class {
            StorageClass::Flash if tiny => 12 * 60,
            StorageClass::Flash => 6 * 60,
            StorageClass::Ram | StorageClass::Disk => 10,
        };
        let mut minutes = if interval_min > 0 { interval_min } else { auto };
        if class == StorageClass::Flash {
            minutes = minutes.max(60); // Flash 上至少間隔 1 小時，避免設成每分鐘寫
        }
        Policy {
            class,
            min_interval: minutes * 60,
            daily_budget: budget_kb * 1024,
        }
    }
}

#[derive(Default)]
struct Entry {
    written_hash: Option<u64>,
    written_at: u64,
    pending: Option<(u64, Vec<u8>)>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    pub day: u64,
    pub bytes_today: u64,
    pub writes_today: u64,
    pub deferred: u64,
    pub pending: usize,
}

pub struct Persister {
    dir: PathBuf,
    policy: Policy,
    entries: HashMap<String, Entry>,
    stats: Stats,
}

fn hash(b: &[u8]) -> u64 {
    let mut h = DefaultHasher::new();
    b.hash(&mut h);
    h.finish()
}

pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Persister {
    pub fn new(dir: impl Into<PathBuf>, policy: Policy) -> Persister {
        Persister {
            dir: dir.into(),
            policy,
            entries: HashMap::new(),
            stats: Stats::default(),
        }
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    pub fn stats(&self) -> Stats {
        Stats {
            pending: self.entries.values().filter(|e| e.pending.is_some()).count(),
            ..self.stats.clone()
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// 讀取快照，並記下內容雜湊（重開機後內容沒變就不會重寫）
    pub fn load(&mut self, name: &str) -> Option<Vec<u8>> {
        let path = self.path(name);
        let data = std::fs::read(&path).ok()?;
        let mtime = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let e = self.entries.entry(name.to_string()).or_default();
        e.written_hash = Some(hash(&data));
        e.written_at = mtime;
        Some(data)
    }

    /// 登記最新內容（還不寫）；內容跟已寫入的一樣就什麼都不做
    pub fn stage(&mut self, name: &str, data: Vec<u8>) {
        let h = hash(&data);
        let e = self.entries.entry(name.to_string()).or_default();
        e.pending = if e.written_hash == Some(h) { None } else { Some((h, data)) };
    }

    /// 定時呼叫：到了間隔、而且今天的寫入量還沒超過上限的才寫
    pub fn flush(&mut self, now: u64) -> std::io::Result<usize> {
        self.flush_inner(now, false)
    }

    /// 關機時：有變動的全部寫出
    pub fn flush_all(&mut self, now: u64) -> std::io::Result<usize> {
        self.flush_inner(now, true)
    }

    fn flush_inner(&mut self, now: u64, force: bool) -> std::io::Result<usize> {
        let day = now / 86400;
        if self.stats.day != day {
            self.stats = Stats { day, ..Stats::default() };
        }
        let mut names: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, e)| e.pending.is_some())
            .map(|(k, _)| k.clone())
            .collect();
        names.sort();
        let mut n = 0;
        for name in names {
            let (due, size) = {
                let e = &self.entries[&name];
                let size = e.pending.as_ref().map(|p| p.1.len() as u64).unwrap_or(0);
                (
                    e.written_at == 0 || now.saturating_sub(e.written_at) >= self.policy.min_interval,
                    size,
                )
            };
            let over_budget = self.policy.class == StorageClass::Flash && self.stats.bytes_today + size > self.policy.daily_budget;
            if !force && (!due || over_budget) {
                if due && over_budget {
                    self.stats.deferred += 1;
                }
                continue;
            }
            let (h, data) = self.entries.get_mut(&name).unwrap().pending.take().unwrap();
            if let Err(e) = write_atomic(&self.path(&name), &data) {
                self.entries.get_mut(&name).unwrap().pending = Some((h, data));
                return Err(e);
            }
            let e = self.entries.get_mut(&name).unwrap();
            e.written_hash = Some(h);
            e.written_at = now;
            self.stats.bytes_today += size;
            self.stats.writes_today += 1;
            n += 1;
        }
        Ok(n)
    }
}

/// 暫存檔 + fsync + 改名。
///
/// Unix 上檔案一律只有擁有者能讀寫（0600）：狀態目錄裡有 ACME 帳號金鑰、憑證私鑰、設定頁 token、
/// 社群私鑰、含私鑰的備份暫存檔，其餘的快照（查過的網域、統計）也不該讓同一台機器的其他帳號讀到。
/// 暫存檔一開始就用 0600 建立（不是寫完才改權限），所以私鑰不會有短暫可讀的空窗。
pub fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        let mut f = o.open(&tmp)?;
        // 上次留下來的暫存檔可能是舊版用 0644 建的：mode() 只在新建時有效，這裡再收緊一次
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("kuroshio-persist-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[cfg(unix)]
    #[test]
    fn files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("mode");
        let f = dir.join("acme-account.json");
        // 舊版留下、所有人可讀的檔案與暫存檔：重寫之後都收緊成 0600
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&f, b"old").unwrap();
        std::fs::write(f.with_extension("tmp"), b"junk").unwrap();
        for p in [&f, &f.with_extension("tmp")] {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        write_atomic(&f, b"secret").unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"secret");
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(!f.with_extension("tmp").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn policy_intervals() {
        assert_eq!(Policy::new(StorageClass::Flash, 0, 4096, false).min_interval, 6 * 3600);
        assert_eq!(Policy::new(StorageClass::Flash, 0, 4096, true).min_interval, 12 * 3600);
        assert_eq!(
            Policy::new(StorageClass::Flash, 1, 4096, false).min_interval,
            3600,
            "Flash 最短 1 小時"
        );
        assert_eq!(Policy::new(StorageClass::Disk, 0, 4096, false).min_interval, 600);
    }

    #[test]
    fn interval_unchanged_and_shutdown() {
        let dir = tmpdir("a");
        let mut p = Persister::new(&dir, Policy::new(StorageClass::Flash, 0, 4096, false));
        let t0 = 1_000_000;
        p.stage("pools.json", b"v1".to_vec());
        assert_eq!(p.flush(t0).unwrap(), 1, "第一次直接寫");
        assert_eq!(std::fs::read(dir.join("pools.json")).unwrap(), b"v1");

        p.stage("pools.json", b"v1".to_vec());
        assert_eq!(p.stats().pending, 0, "內容沒變不排入");

        p.stage("pools.json", b"v2".to_vec());
        assert_eq!(p.flush(t0 + 3600).unwrap(), 0, "未滿 6 小時不寫");
        assert_eq!(p.flush(t0 + 6 * 3600).unwrap(), 1);
        assert_eq!(std::fs::read(dir.join("pools.json")).unwrap(), b"v2");

        p.stage("pools.json", b"v3".to_vec());
        assert_eq!(p.flush_all(t0 + 6 * 3600 + 5).unwrap(), 1, "關機時不管間隔");
        assert_eq!(p.stats().writes_today, 3);
        assert!(!dir.join("pools.tmp").exists(), "沒有留下暫存檔");

        // 重開機：讀回快照後，內容沒變就不會重寫
        let mut q = Persister::new(&dir, Policy::new(StorageClass::Flash, 0, 4096, false));
        assert_eq!(q.load("pools.json").unwrap(), b"v3");
        q.stage("pools.json", b"v3".to_vec());
        assert_eq!(q.flush(t0 + 100 * 86400).unwrap(), 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn daily_budget_defers() {
        let dir = tmpdir("b");
        let mut p = Persister::new(&dir, Policy::new(StorageClass::Flash, 0, 1, false)); // 每天 1 KB
        let t = 2_000_000 * 86400 / 86400;
        p.stage("a", vec![1; 800]);
        p.stage("b", vec![2; 800]);
        assert_eq!(p.flush(t).unwrap(), 1, "第二份超過今天的上限");
        assert_eq!(p.stats().deferred, 1);
        assert_eq!(p.stats().pending, 1);
        assert_eq!(p.flush(t + 86400).unwrap(), 1, "隔天額度重算");
        // Disk 不受每日上限限制
        let mut d = Persister::new(dir.join("disk"), Policy::new(StorageClass::Disk, 0, 1, false));
        d.stage("a", vec![1; 4096]);
        d.stage("b", vec![2; 4096]);
        assert_eq!(d.flush(t).unwrap(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
