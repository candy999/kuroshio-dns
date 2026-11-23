//! 每日上游評測（dns-benchmark）在子程序裡跑（3.3.3 起）
//!
//! 評測時會有大量短命的小配置（原始答案、連線緩衝）跟同時期的長期資料（快取、統計）交錯，
//! 評測結束後記憶體配置器還不回系統（碎片），主程式的 RSS 就停在評測的高點。放在子程序裡跑，
//! 結束時記憶體一定全部還給系統：主程式的常駐用量固定、可以預估（見 `kuroshio memory-plan`）。
//!
//! - 子程序：同一個執行檔的隱藏指令 [`CHILD_CMD`]。完整設定從標準輸入第一行（JSON）傳進去，
//!   不放在命令列（裡面有 token）；之後的每一行是 `pause` / `resume`（記憶體吃緊、還沒對時時暫停）。
//! - 進度：子程序每秒把 `detail` 以 `{"progress":…}` 印到標準輸出，主程式照樣放進 `/api/jobs` 與 `memory.jobs`。
//! - 日誌：子程序寫到標準錯誤（不含時間），主程式逐行轉進自己的日誌（同一個日誌檔、設定頁看得到）。
//! - 結果：評測本來就寫檔（`upstreams.json`、報表、ASN 快取），主程式照舊定時重新讀。
//! - 排程逾時強制結束：主程式送 SIGTERM，子程序收到後照樣存 ASN 快取與可疑紀錄再結束；10 秒還沒結束就 SIGKILL。
//! - `benchmark.subprocess: false`、或目前的執行檔不是 kuroshio 本身（例如測試程式）時在同一個程式裡跑（以前的做法）。
//! - 惡意網站探測的抽樣（3.5.0 F10，[`crate::probesample`]）：啟動評測前由主程式從已下載的惡意類清單抽，
//!   放進傳給評測的那一份設定的 `benchmark._probeSample`（子程序、同一個程式裡跑都一樣；不存檔）。

use crate::app::{runtime_dir, share_dir, storage_class};
use crate::sysinfo::StorageClass;
use anyhow::{anyhow, Result};
use kuroshio_config::get;
use kuroshio_jobs::scheduler::BoxFuture;
use kuroshio_jobs::{BenchPaths, Benchmark, Job, JobCtx};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// 子程序的隱藏指令
pub const CHILD_CMD: &str = "__job-dns-benchmark";

/// 評測用到的檔案位置：使用者的名單（`benchmark.dir`）不存在就用程式附帶的；兩邊不同時合併。
/// 評測與首次啟動的初始上游（3.5.0）共用
pub fn bench_paths(cfg: &Value, state_dir: &Path, base_dir: &Path) -> BenchPaths {
    let mut paths = BenchPaths::from_config(cfg, state_dir, base_dir);
    let shipped = share_dir(cfg).join("benchmark");
    if !paths.list_dir.is_dir() {
        paths.list_dir = shipped.clone();
    }
    if shipped.is_dir() && shipped != paths.list_dir {
        paths.default_list_dir = Some(shipped);
    }
    paths
}

/// 依設定建一個評測（主程式與子程序共用，路徑一模一樣）
pub fn make_benchmark(cfg: &Value, state_dir: &Path, base_dir: &Path) -> Benchmark {
    let mut paths = bench_paths(cfg, state_dir, base_dir);
    // 評測報表放記憶體：Flash 上不寫每天的報表；
    // 最近一次的摘要（judge.log、eliminated.csv、upstreams.json，各 128 KB 以內）另存到學習資料區，重開機後還查得到
    let mut keep_last = None;
    if storage_class(cfg) != StorageClass::Disk {
        paths.out_root = Some(runtime_dir(cfg).join("benchmark"));
        if get(cfg, "benchmark.keepLastReport").and_then(Value::as_bool) != Some(false) {
            keep_last = Some(crate::app::persist_dir(cfg).join("benchmark-last"));
        }
    }
    // 同時測幾個候選也看可用記憶體（扣掉保留量之後的 1/4）
    let reserve = crate::memgov::reserve_from_cfg(cfg);
    let mut b = Benchmark::new(paths).with_headroom(Arc::new(move || crate::memgov::headroom(&crate::memgov::Reading::now(), &reserve)));
    b.keep_last = keep_last;
    // 分級評測（3.5.0 A3）：`benchmark.tiers = auto` 時依實體記憶體換算（小於 256 MB 只測 A 級，是減量不是關掉）；
    // 設定寫明 `a`／`ab` 時評測自己會照設定，這個值用不到
    let b = b.with_tier_auto(tiers_auto(crate::sysinfo::mem_bytes().0.map(|t| t >> 20)));
    // 上游多樣性（3.4.0）：台灣網段判斷「鄰近」；用唯讀資料目錄的公版（評測只需要大致的範圍）
    b.with_tw(kuroshio_jobs::benchmark::read_tw_ip(&share_dir(cfg).join("geo").join("tw-ip.json")))
}

/// `benchmark.tiers = auto` 用哪一種（實體記憶體 MB；讀不到就照舊全部測）
pub fn tiers_auto(mem_total_mb: Option<u64>) -> kuroshio_jobs::benchmark::tiers::Mode {
    kuroshio_jobs::benchmark::tiers::auto_mode(mem_total_mb)
}

/// 子程序用哪個執行檔：設定允許、而且目前的執行檔是 kuroshio 本身才用
fn child_exe(cfg: &Value) -> Option<PathBuf> {
    if get(cfg, "benchmark.subprocess").and_then(Value::as_bool) == Some(false) {
        return None;
    }
    let exe = std::env::current_exe().ok()?;
    let stem = exe.file_stem()?.to_string_lossy().to_ascii_lowercase();
    (stem == "kuroshio").then_some(exe)
}

/// 排程器裡的每日評測：可以的話在子程序跑，不行就在這個程式裡跑
pub struct BenchJob {
    inner: Benchmark,
    child: Option<(PathBuf, PathBuf, PathBuf)>,
    progress: Arc<Mutex<Option<Value>>>,
    /// 上一次在子程序跑的結果（`/api/jobs` 的 `detail.dns-benchmark.last`、`memory.jobs.lastBenchmark`）：
    /// 結束後還查得到子程序用了多少記憶體
    last: Arc<Mutex<Option<Value>>>,
}

impl BenchJob {
    pub fn new(cfg: &Value, state_dir: &Path, base_dir: &Path) -> BenchJob {
        let child = child_exe(cfg).map(|e| (e, state_dir.to_path_buf(), base_dir.to_path_buf()));
        match &child {
            Some(_) => debug!("每日評測在子程序裡跑（結束後記憶體全部還給系統）"),
            None => debug!("每日評測在這個程式裡跑"),
        }
        BenchJob {
            inner: make_benchmark(cfg, state_dir, base_dir),
            child,
            progress: Default::default(),
            last: Default::default(),
        }
    }

    /// 在子程序裡跑
    pub fn subprocess(&self) -> bool {
        self.child.is_some()
    }
}

impl Job for BenchJob {
    fn run(&self, ctx: JobCtx) -> BoxFuture<Result<()>> {
        // 串接（3.4.0）：上游黑潮給的評測結果新鮮、而且串接中 → 這次不跑（不新鮮、沒串接時照常，跟 3.3.7 一樣）
        if crate::chain::share_skips("dns-benchmark") {
            info!("dns-benchmark：由上游黑潮提供，略過");
            *self.last.lock().unwrap() = Some(json!({
                "finishedAt": crate::persist::now_secs() * 1000,
                "ok": true,
                "skipped": "由上游黑潮提供，略過",
            }));
            return Box::pin(async { Ok(()) });
        }
        // 執行時上線以來從未成功、先不用的自動上游（3.5.0 A7）：寫進學習檔的 neverOk，這次評測照測、不選
        let never_ok = crate::upstreams::take_never_ok();
        if !never_ok.is_empty() {
            let ok = self
                .inner
                .paths
                .learn_file
                .as_ref()
                .is_some_and(|p| kuroshio_jobs::benchmark::learn::merge_never_ok(p, &never_ok, ctx.now_ms()));
            if ok {
                info!("評測：執行時從未成功的自動上游 {} 台，這次照測、不選", never_ok.len());
            } else {
                crate::upstreams::restore_never_ok(never_ok);
            }
        }
        let paths = self.inner.paths.clone();
        match self.child.clone() {
            Some((exe, state, base)) => {
                let (progress, last) = (self.progress.clone(), self.last.clone());
                Box::pin(async move {
                    // 惡意網站探測的網域：主程式抽樣，跟著設定從標準輸入傳給子程序（3.5.0 F10）
                    let ctx = crate::probesample::prepare(ctx, &paths).await;
                    let t0 = std::time::Instant::now();
                    let (r, peak) = run_child_peak(&exe, &state, &base, &ctx, progress).await;
                    *last.lock().unwrap() = Some(json!({
                        "finishedAt": crate::persist::now_secs() * 1000,
                        "ok": r.is_ok(),
                        "durationSec": t0.elapsed().as_secs(),
                        "processPeakRssBytes": (peak > 0).then_some(peak),
                    }));
                    if r.is_ok() {
                        // 自己真的跑完（不是略過）：串接中 7 天內有自己跑過才繼續用上游給的結果（3.4.2）
                        crate::chain::note_own_run("dns-benchmark");
                    }
                    r
                })
            }
            None => {
                let inner = self.inner.clone();
                Box::pin(async move {
                    // 不用子程序：抽樣結果放進同一份設定直接給（3.5.0 F10）
                    let ctx = crate::probesample::prepare(ctx, &paths).await;
                    let r = Job::run(&inner, ctx).await;
                    if r.is_ok() {
                        crate::chain::note_own_run("dns-benchmark");
                    }
                    r
                })
            }
        }
    }

    fn detail(&self) -> Option<Value> {
        match self.child {
            Some(_) => {
                let last = self.last.lock().unwrap().clone();
                match (self.progress.lock().unwrap().clone(), last) {
                    (Some(mut p), last) => {
                        p["last"] = last.unwrap_or(Value::Null);
                        Some(p)
                    }
                    (None, Some(l)) => Some(json!({ "last": l })),
                    (None, None) => None,
                }
            }
            // 在這個程式裡跑：`last` 只有「由上游黑潮提供，略過」時才有
            None => Job::detail(&self.inner).or_else(|| self.last.lock().unwrap().clone().map(|l| json!({ "last": l }))),
        }
    }
}

/// 子程序還在跑時被丟掉（排程逾時）：先 SIGTERM 讓它存檔收尾，10 秒後還在就 SIGKILL；進度清掉
struct ChildGuard {
    child: Option<tokio::process::Child>,
    progress: Arc<Mutex<Option<Value>>>,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        *self.progress.lock().unwrap_or_else(|e| e.into_inner()) = None;
        let Some(mut child) = self.child.take() else { return };
        if let Ok(Some(_)) = child.try_wait() {
            return;
        }
        warn!("[dns-benchmark] 評測被強制結束：通知子程序存檔後結束");
        #[cfg(unix)]
        if let Some(pid) = child.id() {
            // SAFETY: 只送訊號給自己啟動、還沒被回收的子程序
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
            // 10 秒後還在（而且確定還是那個子程序，不是被回收後重用的 pid）就 SIGKILL。
            // Child 交給 tokio 回收（沒設 kill_on_drop，丟掉時不會先被殺掉）
            std::thread::spawn(move || {
                let ours = || {
                    std::fs::read(format!("/proc/{pid}/cmdline"))
                        .map(|c| String::from_utf8_lossy(&c).contains(CHILD_CMD))
                        .unwrap_or(false)
                };
                for _ in 0..100 {
                    std::thread::sleep(Duration::from_millis(100));
                    if !ours() {
                        return;
                    }
                }
                // SAFETY: 同上，剛確認過還是評測子程序
                unsafe {
                    libc::kill(pid as i32, libc::SIGKILL);
                }
            });
        }
        #[cfg(not(unix))]
        let _ = child.start_kill();
    }
}

/// 子程序目前與最高的實體記憶體（Linux：`VmRSS`、`VmHWM`），放進進度：`memory.jobs` 看得到評測實際用了多少
fn add_process_rss(p: &mut Option<Value>, pid: Option<u32>) {
    let (Some(v), Some(pid)) = (p.as_mut(), pid) else { return };
    let Ok(st) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
        return;
    };
    let kb = |k: &str| {
        st.lines()
            .find(|l| l.starts_with(k))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|n| n.parse::<u64>().ok())
    };
    v["processRssBytes"] = json!(kb("VmRSS:").map(|k| k * 1024));
    v["processPeakRssBytes"] = json!(kb("VmHWM:").map(|k| k * 1024));
}

/// 子程序標準錯誤的一行（`LEVEL 訊息`）轉進自己的日誌
fn relay(line: &str, last_error: &mut Option<String>) {
    let t = line.trim();
    if t.is_empty() {
        return;
    }
    let (lvl, msg) = t.split_once(' ').map(|(a, b)| (a, b.trim_start())).unwrap_or(("", t));
    match lvl {
        "ERROR" => {
            error!("{msg}");
            *last_error = Some(msg.to_string());
        }
        "WARN" => warn!("{msg}"),
        "INFO" => info!("{msg}"),
        "DEBUG" | "TRACE" => debug!("{msg}"),
        _ => info!("{t}"),
    }
}

#[cfg(test)]
pub(crate) async fn run_child(exe: &Path, state: &Path, base: &Path, ctx: &JobCtx, progress: Arc<Mutex<Option<Value>>>) -> Result<()> {
    run_child_peak(exe, state, base, ctx, progress).await.0
}

/// 同 [`run_child`]，另外回傳子程序的記憶體高點（bytes；量不到是 0）
async fn run_child_peak(exe: &Path, state: &Path, base: &Path, ctx: &JobCtx, progress: Arc<Mutex<Option<Value>>>) -> (Result<()>, u64) {
    let mut peak = 0u64;
    let r = run_child_inner(exe, state, base, ctx, progress, &mut peak).await;
    (r, peak)
}

async fn run_child_inner(
    exe: &Path,
    state: &Path,
    base: &Path,
    ctx: &JobCtx,
    progress: Arc<Mutex<Option<Value>>>,
    peak: &mut u64,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let mut cmd = tokio::process::Command::new(exe);
    cmd.arg(CHILD_CMD)
        .arg("--state")
        .arg(state)
        .arg("--base")
        .arg(base)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    // Windows：不要另外開主控台視窗（服務模式時尤其不行）
    #[cfg(windows)]
    cmd.creation_flags(0x0800_0000);
    let mut child = cmd.spawn().map_err(|e| anyhow!("無法啟動評測子程序（{}）：{e}", exe.display()))?;
    let mut stdin = child.stdin.take().ok_or_else(|| anyhow!("子程序沒有標準輸入"))?;
    let mut out = BufReader::new(child.stdout.take().ok_or_else(|| anyhow!("子程序沒有標準輸出"))?).lines();
    let mut err = BufReader::new(child.stderr.take().ok_or_else(|| anyhow!("子程序沒有標準錯誤"))?).lines();
    let pid = child.id();
    let mut guard = ChildGuard {
        child: Some(child),
        progress: progress.clone(),
    };
    let mut first = serde_json::to_vec(&*ctx.cfg)?;
    first.push(b'\n');
    stdin.write_all(&first).await?;
    let (mut out_done, mut err_done, mut paused) = (false, false, false);
    let mut last_error: Option<String> = None;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    while !(out_done && err_done) {
        tokio::select! {
            l = out.next_line(), if !out_done => match l {
                Ok(Some(l)) => {
                    if let Ok(v) = serde_json::from_str::<Value>(&l) {
                        if let Some(p) = v.get("progress") {
                            let mut g = progress.lock().unwrap();
                            *g = (!p.is_null()).then(|| p.clone());
                            add_process_rss(&mut g, pid);
                        }
                    }
                }
                _ => out_done = true,
            },
            l = err.next_line(), if !err_done => match l {
                Ok(Some(l)) => relay(&l, &mut last_error),
                _ => err_done = true,
            },
            _ = tick.tick() => {
                {
                    let mut g = progress.lock().unwrap();
                    add_process_rss(&mut g, pid);
                    if let Some(p) = g.as_ref().and_then(|v| v["processPeakRssBytes"].as_u64()) {
                        *peak = (*peak).max(p);
                    }
                }
                // 記憶體吃緊、還沒對時：通知子程序在下一個檢查點暫停（恢復時再通知）
                let d = ctx.should_defer();
                if d != paused {
                    paused = d;
                    let _ = stdin.write_all(if d { b"pause\n" } else { b"resume\n" }).await;
                }
            }
        }
    }
    let status = guard.child.as_mut().ok_or_else(|| anyhow!("子程序不見了"))?.wait().await?;
    guard.child = None;
    *progress.lock().unwrap() = None;
    if *peak > 0 {
        info!(
            "[dns-benchmark] 評測子程序結束，記憶體最高 {:.1} MB（已全部還給系統）",
            *peak as f64 / 1048576.0
        );
    }
    if status.success() {
        Ok(())
    } else {
        Err(anyhow!(
            "評測子程序結束（{status}）{}",
            last_error.map(|e| format!("：{e}")).unwrap_or_default()
        ))
    }
}

/// 子程序的主程式（隱藏指令 [`CHILD_CMD`]）。回傳結束碼：0 成功、1 評測失敗、2 輸入錯誤、3 被要求結束
pub async fn child_main(state: PathBuf, base: PathBuf) -> i32 {
    // 第一行：完整設定（JSON）
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        error!("評測子程序讀不到設定");
        return 2;
    }
    let cfg: Value = match serde_json::from_str(&line) {
        Ok(v) => v,
        Err(e) => {
            error!("評測子程序的設定格式錯誤：{e}");
            return 2;
        }
    };
    crate::tls::set_bootstrap(
        &get(&cfg, "upstream.bootstrap")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect::<Vec<_>>())
            .unwrap_or_default(),
    );
    // 之後的每一行：pause / resume；標準輸入關掉（主程式不見了）就結束
    let paused = Arc::new(AtomicBool::new(false));
    let gone = Arc::new(tokio::sync::Notify::new());
    {
        let (paused, gone) = (paused.clone(), gone.clone());
        std::thread::spawn(move || {
            let mut l = String::new();
            loop {
                l.clear();
                match std::io::stdin().read_line(&mut l) {
                    Ok(0) | Err(_) => {
                        gone.notify_one();
                        return;
                    }
                    Ok(_) => match l.trim() {
                        "pause" => paused.store(true, Ordering::Relaxed),
                        "resume" => paused.store(false, Ordering::Relaxed),
                        _ => {}
                    },
                }
            }
        });
    }
    let bench = make_benchmark(&cfg, &state, &base);
    let p2 = paused.clone();
    let ctx = JobCtx::new("dns-benchmark", "子程序", Arc::new(cfg))
        .with_defer(Arc::new(move || p2.load(Ordering::Relaxed)), Duration::from_secs(2));
    // 進度：有變才印
    let b2 = bench.clone();
    let printer = tokio::spawn(async move {
        let mut last: Option<Value> = None;
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let d = Job::detail(&b2);
            if d != last {
                println!("{}", json!({ "progress": d }));
                last = d;
            }
        }
    });
    let stop = async {
        #[cfg(unix)]
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            s.recv().await;
            return;
        }
        std::future::pending::<()>().await
    };
    // 被要求結束：丟掉評測的 future，裡面的收尾（ASN 快取、可疑紀錄）照樣存檔
    let code = tokio::select! {
        r = bench.run(&ctx) => match r {
            Ok(_) => 0,
            Err(e) => {
                error!("{e:#}");
                1
            }
        },
        _ = stop => 3,
        _ = gone.notified() => 3,
    };
    printer.abort();
    println!("{}", json!({ "progress": Value::Null }));
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiers_auto_follows_memory() {
        use kuroshio_jobs::benchmark::tiers::Mode;
        assert_eq!(tiers_auto(Some(128)), Mode::A, "128 MB 的小機器只測 A 級");
        assert_eq!(tiers_auto(Some(512)), Mode::Ab, "512 MB 的 D3 先照記憶體，全部測");
        assert_eq!(tiers_auto(None), Mode::Ab);
    }

    #[test]
    fn relay_keeps_levels_and_last_error() {
        let mut last = None;
        relay(" INFO [dns-benchmark] 開始", &mut last);
        relay(" WARN 有點慢", &mut last);
        assert!(last.is_none());
        relay("ERROR 沒有任何 DNS 通過資格賽", &mut last);
        assert_eq!(last.as_deref(), Some("沒有任何 DNS 通過資格賽"));
        relay("", &mut last);
    }

    /// 用 sh 腳本假裝子程序：測主程式這一端（進度、日誌、暫停、失敗、強制結束）
    #[cfg(unix)]
    #[tokio::test]
    async fn parent_side_protocol() {
        let d = std::env::temp_dir().join(format!("kuroshio-benchjob-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let script = |name: &str, body: &str| {
            let p = d.join(name);
            std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            p
        };
        let log = d.join("seen.txt");
        let cfg = Arc::new(json!({ "x": 1 }));
        let ctx = || JobCtx::new("dns-benchmark", "test", cfg.clone());
        let progress: Arc<Mutex<Option<Value>>> = Default::default();

        // 成功：設定從第一行收到；進度轉進來，結束後清掉
        let ok = script(
            "ok.sh",
            &format!(
                "read cfg; echo \"$cfg\" > {l}; echo '{{\"progress\":{{\"phase\":\"judge\"}}}}'; echo ' INFO 開始' >&2; sleep 1; exit 0",
                l = log.display()
            ),
        );
        let p2 = progress.clone();
        let watch = tokio::spawn(async move {
            for _ in 0..40 {
                if p2.lock().unwrap().is_some() {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            false
        });
        run_child(&ok, &d, &d, &ctx(), progress.clone()).await.unwrap();
        assert!(watch.await.unwrap(), "執行中看得到進度");
        assert!(progress.lock().unwrap().is_none(), "結束後清掉");
        assert!(std::fs::read_to_string(&log).unwrap().contains("\"x\":1"), "設定從標準輸入傳進去");

        // 失敗：結束碼非 0，錯誤訊息帶最後一行 ERROR
        let bad = script("bad.sh", "read cfg; echo 'ERROR 沒有任何 DNS 通過資格賽' >&2; exit 1");
        let e = run_child(&bad, &d, &d, &ctx(), progress.clone()).await.unwrap_err();
        assert!(format!("{e:#}").contains("資格賽"), "{e:#}");

        // 暫停：should_defer 變成 true 時送 pause
        let pause = script(
            "pause.sh",
            &format!("read cfg; read cmd; echo \"$cmd\" > {l}; exit 0", l = log.display()),
        );
        let c = ctx().with_defer(Arc::new(|| true), Duration::from_millis(10));
        run_child(&pause, &d, &d, &c, progress.clone()).await.unwrap();
        assert_eq!(std::fs::read_to_string(&log).unwrap().trim(), "pause");

        // 強制結束（排程逾時、future 被丟掉）：子程序收到 SIGTERM，有機會收尾
        let term = d.join("term.txt");
        let slow = script(
            "slow.sh",
            &format!(
                "trap 'echo term > {t}; exit 3' TERM; read cfg; while true; do sleep 0.1; done",
                t = term.display()
            ),
        );
        let r = tokio::time::timeout(Duration::from_millis(500), run_child(&slow, &d, &d, &ctx(), progress.clone())).await;
        assert!(r.is_err(), "還在跑");
        for _ in 0..50 {
            if term.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(term.exists(), "子程序收到 SIGTERM");
        assert!(progress.lock().unwrap().is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn test_binaries_run_in_process() {
        // 測試程式的執行檔不是 kuroshio：在同一個程式裡跑
        assert!(child_exe(&json!({})).is_none());
        assert!(child_exe(&json!({ "benchmark": { "subprocess": false } })).is_none());
    }
}
