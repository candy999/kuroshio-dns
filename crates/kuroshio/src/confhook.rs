//! 寫入設定目錄之後呼叫外部指令（環境變數 `KUROSHIO_ON_CONFIG_WRITE`）。
//!
//! 給把設定放在記憶體、要另外執行指令才會寫進 Flash 的韌體用，例如 Padavan 的 `/etc/storage`
//! （`KUROSHIO_ON_CONFIG_WRITE="mtd_storage.sh save"`）。
//!
//! - **只能用環境變數設定**：不開放在設定頁或管理 API 設定，管理介面不能被拿來執行任意指令。
//! - **只看設定目錄**：設定檔所在的資料夾與 `base_dir`（自訂規則、`.bak`、設定頁 token 等）；
//!   快照目錄（學習資料）與執行期目錄不算，所以平常的學習資料寫入不會觸發。
//! - **合併**：最後一次寫入後等 [`DELAY`] 才執行一次（恢復預設規則會連寫兩個檔，只存一次 Flash）。
//! - **逾時**：指令最多跑 [`TIMEOUT`]，超過就結束它；失敗與輸出記在日誌。
//! - **關機前跑完**：還在等待合併的那一次，收到 SIGTERM / SIGINT 時立刻執行（照樣受逾時限制）再結束（[`flush`]）。
//!
//! 指令用 `sh -c`（Windows 是 `cmd /C`）執行，環境變數 `KUROSHIO_CONFIG_FILES` 是這次寫入的檔案（換行分隔）。
//! 排程用自己的執行緒：設定頁存檔後重新載入會換一個 tokio 執行環境，等待中的那一次不能跟著消失。

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// 環境變數名稱
pub const ENV: &str = "KUROSHIO_ON_CONFIG_WRITE";
/// 最後一次寫入後等多久才執行（合併連續的寫入）
pub const DELAY: Duration = Duration::from_secs(3);
/// 指令最多跑多久
pub const TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Default)]
struct St {
    /// 這次要通知的檔案（還沒執行）
    files: BTreeSet<PathBuf>,
    last_touch: Option<Instant>,
    running: bool,
    /// 關機：不等合併，立刻執行
    now: bool,
    runs: u64,
}

struct Hook {
    cmd: String,
    delay: Duration,
    timeout: Duration,
    /// （監看的資料夾, 排除的資料夾）；每次（重新）載入設定時更新
    dirs: Mutex<(Vec<PathBuf>, Vec<PathBuf>)>,
    st: Mutex<St>,
    cv: Condvar,
    worker: OnceLock<()>,
}

static HOOK: OnceLock<Option<Arc<Hook>>> = OnceLock::new();

fn hook() -> Option<&'static Arc<Hook>> {
    HOOK.get_or_init(|| {
        let cmd = std::env::var(ENV).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())?;
        Some(Arc::new(Hook::new(cmd, DELAY, TIMEOUT)))
    })
    .as_ref()
}

/// 有沒有設定外部指令
pub fn enabled() -> bool {
    hook().is_some()
}

fn abs(p: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(p).ok()
}

/// 設定要監看的資料夾（設定檔所在的資料夾、`base_dir`）與排除的資料夾（快照、執行期目錄）。
/// 不存在的資料夾略過。沒有設定外部指令時什麼都不做
pub fn configure(watch: &[&Path], exclude: &[&Path]) {
    let Some(h) = hook() else { return };
    let w: Vec<PathBuf> = watch.iter().filter_map(|p| abs(p)).collect();
    let x: Vec<PathBuf> = exclude.iter().filter_map(|p| abs(p)).collect();
    let first = h.dirs.lock().unwrap().0.is_empty();
    if first {
        info!(
            "寫入設定目錄後會執行：{}（{}；合併 {} 秒內的寫入）",
            h.cmd,
            w.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join("、"),
            h.delay.as_secs()
        );
    }
    *h.dirs.lock().unwrap() = (w, x);
}

/// 寫完一個檔案後呼叫（`persist::write_atomic` 會自動呼叫）：在設定目錄裡就排一次外部指令
pub fn touched(path: &Path) {
    if let Some(h) = hook() {
        h.touch(path);
    }
}

/// 關機前：等待中的那一次立刻執行，等它結束（最多逾時 + 1 秒）。沒有等待中的就馬上回來
pub fn flush() {
    if let Some(h) = hook() {
        h.flush();
    }
}

impl Hook {
    fn new(cmd: String, delay: Duration, timeout: Duration) -> Hook {
        Hook {
            cmd,
            delay,
            timeout,
            dirs: Mutex::new((Vec::new(), Vec::new())),
            st: Mutex::new(St::default()),
            cv: Condvar::new(),
            worker: OnceLock::new(),
        }
    }

    fn watched(&self, path: &Path) -> Option<PathBuf> {
        let parent = path.parent()?;
        let dir = abs(if parent.as_os_str().is_empty() { Path::new(".") } else { parent })?;
        let (w, x) = &*self.dirs.lock().unwrap();
        if x.iter().any(|e| dir.starts_with(e)) || !w.iter().any(|d| dir.starts_with(d)) {
            return None;
        }
        Some(dir.join(path.file_name()?))
    }

    fn touch(self: &Arc<Self>, path: &Path) {
        let Some(file) = self.watched(path) else { return };
        {
            let mut st = self.st.lock().unwrap();
            st.files.insert(file);
            st.last_touch = Some(Instant::now());
        }
        let me = self.clone();
        self.worker.get_or_init(|| {
            let _ = std::thread::Builder::new()
                .name("kuroshio-confhook".into())
                .spawn(move || me.work());
        });
        self.cv.notify_all();
    }

    /// 背景執行緒：有待執行的就等合併時間過去再執行
    fn work(self: Arc<Self>) {
        let mut st = self.st.lock().unwrap();
        loop {
            if st.files.is_empty() {
                st = self.cv.wait(st).unwrap();
                continue;
            }
            let due = st.last_touch.map(|t| t + self.delay).unwrap_or_else(Instant::now);
            let now = Instant::now();
            if !st.now && now < due {
                st = self.cv.wait_timeout(st, due - now).unwrap().0;
                continue;
            }
            let files: Vec<PathBuf> = std::mem::take(&mut st.files).into_iter().collect();
            st.running = true;
            drop(st);
            self.run(&files);
            st = self.st.lock().unwrap();
            st.running = false;
            st.runs += 1;
            if st.files.is_empty() {
                st.now = false;
            }
            self.cv.notify_all();
        }
    }

    fn run(&self, files: &[PathBuf]) {
        let list = files.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join("\n");
        #[cfg(unix)]
        let mut c = std::process::Command::new("sh");
        #[cfg(unix)]
        {
            c.arg("-c").arg(&self.cmd);
            // 自己一個程序群組：逾時時連 sh 底下的子程式一起結束
            std::os::unix::process::CommandExt::process_group(&mut c, 0);
        }
        #[cfg(not(unix))]
        let mut c = std::process::Command::new("cmd");
        #[cfg(not(unix))]
        c.arg("/C").arg(&self.cmd);
        c.env("KUROSHIO_CONFIG_FILES", &list)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let t0 = Instant::now();
        let mut child = match c.spawn() {
            Ok(ch) => ch,
            Err(e) => {
                warn!("寫入設定後的外部指令無法執行（{}）：{e}", self.cmd);
                return;
            }
        };
        // 輸出另外讀（不讀的話輸出多時管線塞住，指令卡著不結束）
        let read = |r: Option<Box<dyn std::io::Read + Send>>| {
            std::thread::spawn(move || {
                let mut s = String::new();
                if let Some(mut r) = r {
                    let _ = std::io::Read::read_to_string(&mut std::io::Read::take(&mut r, 4096), &mut s);
                    let _ = std::io::copy(&mut r, &mut std::io::sink());
                }
                s
            })
        };
        let out = read(child.stdout.take().map(|x| Box::new(x) as Box<dyn std::io::Read + Send>));
        let err = read(child.stderr.take().map(|x| Box::new(x) as Box<dyn std::io::Read + Send>));
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break Some(s),
                Ok(None) if t0.elapsed() >= self.timeout => {
                    #[cfg(unix)]
                    // SAFETY: 只送訊號給自己建立的程序群組
                    unsafe {
                        libc::kill(-(child.id() as i32), libc::SIGKILL);
                    }
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(e) => {
                    warn!("等待外部指令結束失敗：{e}");
                    break None;
                }
            }
        };
        // 逾時結束的：輸出不等了（還有孫程式拿著管線的話會一直讀不完）
        let (out, err) = match status {
            Some(_) => (out.join().unwrap_or_default(), err.join().unwrap_or_default()),
            None => (String::new(), String::new()),
        };
        let tail = |s: &str| s.trim().lines().last().unwrap_or("").to_string();
        match status {
            Some(s) if s.success() => info!(
                "寫入設定後執行 {}：完成（{} 個檔案，{} ms）",
                self.cmd,
                files.len(),
                t0.elapsed().as_millis()
            ),
            Some(s) => warn!(
                "寫入設定後執行 {} 失敗（{s}）：{}",
                self.cmd,
                [tail(&err), tail(&out)].into_iter().find(|x| !x.is_empty()).unwrap_or_default()
            ),
            None => warn!("寫入設定後執行 {}：超過 {} 秒，已經結束它", self.cmd, self.timeout.as_secs()),
        }
    }

    fn flush(&self) {
        let deadline = Instant::now() + self.timeout + Duration::from_secs(1);
        let mut st = self.st.lock().unwrap();
        if st.files.is_empty() && !st.running {
            return;
        }
        info!("結束前先執行寫入設定後的外部指令（{}）", self.cmd);
        st.now = true;
        self.cv.notify_all();
        while !st.files.is_empty() || st.running {
            let now = Instant::now();
            if now >= deadline {
                warn!("寫入設定後的外部指令沒有在結束前跑完");
                return;
            }
            st = self.cv.wait_timeout(st, deadline - now).unwrap().0;
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("kuroshio-confhook-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("state")).unwrap();
        std::fs::create_dir_all(d.join("conf")).unwrap();
        d
    }

    fn setup(d: &Path, delay_ms: u64) -> Arc<Hook> {
        let log = d.join("runs.log");
        let h = Arc::new(Hook::new(
            format!(
                "echo \"$KUROSHIO_CONFIG_FILES\" | tr '\\n' ' ' >> '{}'; echo >> '{}'",
                log.display(),
                log.display()
            ),
            Duration::from_millis(delay_ms),
            Duration::from_secs(5),
        ));
        *h.dirs.lock().unwrap() = (vec![abs(&d.join("conf")).unwrap()], vec![abs(&d.join("state")).unwrap()]);
        h
    }

    fn runs(d: &Path) -> Vec<String> {
        std::fs::read_to_string(d.join("runs.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn merges_writes_and_ignores_state_dir() {
        let d = tmp("merge");
        let h = setup(&d, 300);
        for f in ["conf/a.txt", "conf/b.txt", "conf/a.txt", "state/snap.json", "elsewhere.txt"] {
            std::fs::write(d.join(f), "x").unwrap();
            h.touch(&d.join(f));
        }
        std::thread::sleep(Duration::from_millis(1200));
        let r = runs(&d);
        assert_eq!(r.len(), 1, "連續寫入只執行一次：{r:?}");
        assert!(r[0].contains("a.txt") && r[0].contains("b.txt"), "{r:?}");
        assert!(
            !r[0].contains("snap.json") && !r[0].contains("elsewhere"),
            "快照目錄與其他地方不算：{r:?}"
        );
        // 只有快照目錄的寫入：不執行
        h.touch(&d.join("state/snap.json"));
        std::thread::sleep(Duration::from_millis(600));
        assert_eq!(runs(&d).len(), 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn flush_runs_pending_immediately() {
        let d = tmp("flush");
        // 合併時間很長：不 flush 的話要等 60 秒
        let h = setup(&d, 60_000);
        std::fs::write(d.join("conf/c.txt"), "x").unwrap();
        h.touch(&d.join("conf/c.txt"));
        std::thread::sleep(Duration::from_millis(100));
        assert!(runs(&d).is_empty());
        let t = Instant::now();
        h.flush();
        assert!(t.elapsed() < Duration::from_secs(5));
        let r = runs(&d);
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(r[0].contains("c.txt"));
        // 沒有待執行的：flush 馬上回來
        let t = Instant::now();
        h.flush();
        assert!(t.elapsed() < Duration::from_millis(200));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn timeout_kills_the_command() {
        let d = tmp("timeout");
        let h = Arc::new(Hook::new("sleep 30".into(), Duration::from_millis(10), Duration::from_millis(300)));
        *h.dirs.lock().unwrap() = (vec![abs(&d.join("conf")).unwrap()], vec![]);
        std::fs::write(d.join("conf/x"), "x").unwrap();
        h.touch(&d.join("conf/x"));
        let t = Instant::now();
        std::thread::sleep(Duration::from_millis(50));
        h.flush();
        assert!(t.elapsed() < Duration::from_secs(5), "逾時就結束指令");
        assert_eq!(h.st.lock().unwrap().runs, 1);
        let _ = std::fs::remove_dir_all(&d);
    }
}
