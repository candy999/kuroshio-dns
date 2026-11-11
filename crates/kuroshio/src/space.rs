//! 儲存空間（規格 05 第 5.6 節）：寫快照前看狀態目錄所在的檔案系統還剩多少空間，
//! 不夠時依等級刪掉可以重建的檔案；核心累積的資料絕不自動刪除。
//!
//! | 等級 | 檔案 | 空間不足時 |
//! |---|---|---|
//! | 日誌（`Log`） | 日誌檔、`.log.old`、殘留的暫存檔 | 最先刪 |
//! | 可重建（`Rebuildable`） | 候選 IP、IP 網段分類、統計、常用網域、評測報表、下載的 CDN 範圍 | 其次（舊的、大的先刪），之後會重新學習 / 下載 |
//! | 核心（`Core`） | CDN 網域驗證紀錄、節點池、永久 IPv6 節點、社群身分 / 金鑰 / 好友、設定、自訂規則、黑名單、憑證、其他不認識的檔案 | 絕不自動刪除 |

use std::path::{Path, PathBuf};
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// 最先刪
    Log = 0,
    /// 可以重建
    Rebuildable = 1,
    /// 絕不自動刪除
    Core = 2,
}

impl Tier {
    pub fn name(self) -> &'static str {
        match self {
            Tier::Log => "log",
            Tier::Rebuildable => "rebuildable",
            Tier::Core => "core",
        }
    }
}

/// 狀態目錄裡的檔案（相對路徑，`/` 分隔）屬於哪一級；不認識的一律算核心（寧可不刪）
pub fn tier_of(rel: &str) -> Tier {
    let rel = rel.replace('\\', "/");
    let base = rel.trim_end_matches(".zst");
    if base.ends_with(".log") || base.ends_with(".log.old") || base.ends_with(".tmp") {
        return Tier::Log;
    }
    const REBUILDABLE: [&str; 5] = [
        "cdn/harvest.json",
        "cdn/ip-zone.json",
        "stats.json",
        "hot-names.json",
        "import-last.json",
    ];
    const REBUILDABLE_DIRS: [&str; 3] = ["benchmark/", "cdn/ranges/", "cdn/scan/"];
    if REBUILDABLE.contains(&base) || REBUILDABLE_DIRS.iter().any(|d| base.starts_with(d)) {
        return Tier::Rebuildable;
    }
    Tier::Core
}

/// 檔案系統的可用空間（bytes）；查不到時 None（當作空間足夠）
pub fn free_bytes(dir: &Path) -> Option<u64> {
    let mut p = dir.to_path_buf();
    while !p.exists() {
        if !p.pop() {
            return None;
        }
    }
    free_impl(&p)
}

#[cfg(unix)]
fn free_impl(p: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(p.as_os_str().as_bytes()).ok()?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: c 是以 NUL 結尾的路徑，s 是可寫的 statvfs 結構
    let r = unsafe { libc::statvfs(c.as_ptr(), &mut s) };
    (r == 0).then(|| (s.f_bavail as u64).saturating_mul(s.f_frsize as u64))
}

#[cfg(windows)]
fn free_impl(p: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let w: Vec<u16> = p.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let mut avail: u64 = 0;
    // SAFETY: w 以 0 結尾；其他輸出參數可以是 null
    let ok = unsafe { GetDiskFreeSpaceExW(w.as_ptr(), &mut avail, std::ptr::null_mut(), std::ptr::null_mut()) };
    (ok != 0).then_some(avail)
}

#[cfg(not(any(unix, windows)))]
fn free_impl(_: &Path) -> Option<u64> {
    None
}

/// 一個可以刪的檔案
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub path: PathBuf,
    /// 相對於狀態目錄（外部登記的檔案是完整路徑）
    pub rel: String,
    pub tier: Tier,
    pub size: u64,
    /// 修改時間（Unix 秒）
    pub mtime: u64,
}

static REGISTERED: std::sync::Mutex<Vec<(PathBuf, Tier)>> = std::sync::Mutex::new(Vec::new());

/// 狀態目錄以外、空間不足時可以刪的檔（例如 Windows 的日誌檔；由寫它的模組登記）
pub fn register(path: PathBuf, tier: Tier) {
    let mut r = REGISTERED.lock().unwrap_or_else(|e| e.into_inner());
    if !r.iter().any(|(p, _)| *p == path) {
        r.push((path, tier));
    }
}

/// 列出狀態目錄（最多往下 4 層）與外部登記的檔案裡可以刪的（日誌、可重建），依刪除順序排好：
/// 先日誌、再可重建；同一級裡舊的先刪，一樣舊的大的先刪
pub fn candidates(dir: &Path, extra: &[(PathBuf, Tier)]) -> Vec<Candidate> {
    let mut all: Vec<(PathBuf, Tier)> = extra.to_vec();
    all.extend(REGISTERED.lock().unwrap_or_else(|e| e.into_inner()).iter().cloned());
    candidates_in(dir, &all)
}

fn candidates_in(dir: &Path, extra: &[(PathBuf, Tier)]) -> Vec<Candidate> {
    fn walk(base: &Path, d: &Path, depth: u32, out: &mut Vec<Candidate>) {
        let Ok(rd) = std::fs::read_dir(d) else { return };
        for e in rd.flatten() {
            let p = e.path();
            let Ok(m) = e.metadata() else { continue };
            if m.is_dir() {
                if depth < 4 {
                    walk(base, &p, depth + 1, out);
                }
                continue;
            }
            let rel = p.strip_prefix(base).unwrap_or(&p).to_string_lossy().replace('\\', "/");
            let tier = tier_of(&rel);
            if tier == Tier::Core {
                continue;
            }
            out.push(Candidate {
                mtime: mtime_secs(&m),
                size: m.len(),
                path: p,
                rel,
                tier,
            });
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, 0, &mut out);
    for (p, tier) in extra {
        if *tier == Tier::Core || out.iter().any(|c| &c.path == p) {
            continue;
        }
        if let Some(m) = std::fs::metadata(p).ok().filter(|m| m.is_file()) {
            out.push(Candidate {
                path: p.clone(),
                rel: p.to_string_lossy().into_owned(),
                tier: *tier,
                size: m.len(),
                mtime: mtime_secs(&m),
            });
        }
    }
    out.sort_by(|a, b| a.tier.cmp(&b.tier).then(a.mtime.cmp(&b.mtime)).then(b.size.cmp(&a.size)));
    out
}

fn mtime_secs(m: &std::fs::Metadata) -> u64 {
    m.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 依序刪檔，直到 `enough()` 成立或沒有可刪的；回傳刪掉的檔案（相對路徑）與釋出的 bytes
pub fn free_up(list: Vec<Candidate>, mut enough: impl FnMut(u64) -> bool) -> (Vec<String>, u64) {
    let mut freed = 0u64;
    let mut gone = Vec::new();
    for c in list {
        if enough(freed) {
            break;
        }
        debug_assert!(c.tier != Tier::Core);
        match std::fs::remove_file(&c.path) {
            Ok(()) => {
                info!(
                    "儲存空間不足：刪除{}檔案 {}（{} KB）",
                    if c.tier == Tier::Log { "日誌" } else { "可重建的" },
                    c.rel,
                    c.size.div_ceil(1024)
                );
                freed += c.size;
                gone.push(c.rel);
            }
            Err(e) => warn!("儲存空間不足，刪除 {} 失敗：{e}", c.rel),
        }
    }
    (gone, freed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiers() {
        assert_eq!(tier_of("kuroshio.log"), Tier::Log);
        assert_eq!(tier_of("kuroshio.log.old"), Tier::Log);
        assert_eq!(tier_of("cdn/pools.tmp"), Tier::Log);
        assert_eq!(tier_of("cdn/harvest.json.zst"), Tier::Rebuildable);
        assert_eq!(tier_of("cdn/ip-zone.json"), Tier::Rebuildable);
        assert_eq!(tier_of("stats.json"), Tier::Rebuildable);
        assert_eq!(tier_of("benchmark/2026-11-11/report.json"), Tier::Rebuildable);
        for core in [
            "cdn-domains.json",
            "cdn/domains/16-003.json.zst",
            "cdn/domains/manifest.json",
            "cdn/pools.json.zst",
            "cdn/v6-nodes.json",
            "community/peers.json",
            "community-keys/key.pem",
            "upstreams.json",
            "blacklist.txt",
            "custom-rules.txt",
            "acme/cert.pem",
            "something-new.bin",
        ] {
            assert_eq!(tier_of(core), Tier::Core, "{core}");
        }
        assert!(Tier::Log < Tier::Rebuildable && Tier::Rebuildable < Tier::Core);
    }

    #[test]
    fn deletion_order_and_core_kept() {
        let d = std::env::temp_dir().join(format!("kuroshio-space-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("cdn/domains")).unwrap();
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let put = |rel: &str, n: usize| {
            std::fs::write(d.join(rel), vec![b'x'; n]).unwrap();
            std::fs::File::options()
                .write(true)
                .open(d.join(rel))
                .unwrap()
                .set_modified(t)
                .unwrap();
        };
        put("cdn/domains/16-000.json.zst", 9000);
        put("cdn/pools.json.zst", 9000);
        put("community-keys.pem", 9000);
        put("stats.json", 3000);
        put("cdn/harvest.json.zst", 5000);
        put("x.log.old", 100);
        let ext = d.join("outside.log");
        std::fs::write(&ext, vec![b'y'; 200]).unwrap();
        let list = candidates(&d, &[(ext.clone(), Tier::Log), (d.join("cdn/pools.json.zst"), Tier::Core)]);
        let tiers: Vec<Tier> = list.iter().map(|c| c.tier).collect();
        assert_eq!(
            tiers,
            vec![Tier::Log, Tier::Log, Tier::Rebuildable, Tier::Rebuildable],
            "日誌先、可重建其次、核心不列"
        );
        // 一樣舊的時候大的先刪
        assert_eq!(list[2].rel, "cdn/harvest.json.zst");
        // 要 250 bytes：刪兩個日誌就夠，不動可重建的
        let (gone, freed) = free_up(list, |f| f >= 250);
        assert_eq!(gone.len(), 2);
        assert_eq!(freed, 300);
        assert!(d.join("stats.json").exists() && d.join("cdn/harvest.json.zst").exists());
        // 要很多：可重建的全刪，核心一個都不刪
        let (gone, _) = free_up(candidates(&d, &[]), |_| false);
        assert_eq!(gone.len(), 2);
        for core in ["cdn/domains/16-000.json.zst", "cdn/pools.json.zst", "community-keys.pem"] {
            assert!(d.join(core).exists(), "核心資料 {core} 不能刪");
        }
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn free_space_probe() {
        let f = free_bytes(&std::env::temp_dir().join("does/not/exist/yet"));
        assert!(f.is_some_and(|b| b > 0), "{f:?}");
    }
}
