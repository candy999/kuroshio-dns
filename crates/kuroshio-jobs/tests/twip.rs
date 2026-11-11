//! 台灣 IP 清單的排程工作（規格 08）：跟指令列輸出一樣、資源不夠暫停後續跑、一直失敗或超過期限就放棄、
//! 驗證擋下縮水的清單、429、內容沒變不寫入。全部用本機假伺服器，不連網路。

mod common;

use common::{serve, small_fixture, Fault, Mock, Shared};
use kuroshio_jobs::geo::TwIp;
use kuroshio_jobs::time::{parse_date_utc, Clock, ManualClock, HOUR_MS};
use kuroshio_jobs::twip::{Hooks, Sources, TwIpJob};
use kuroshio_jobs::{Job, JobCtx, Options, Scheduler};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const DAY: &str = "2026-11-11";

fn cfg(extra: Value) -> Arc<Value> {
    let mut j = json!({ "enabled": true, "catchUp": false, "pauseSec": [0, 0], "retrySec": 0.05, "maxFailures": 3 });
    kuroshio_config::merge(&mut j, &extra);
    Arc::new(json!({ "jobs": { "tw-ip": j } }))
}

/// 測試用的接點：目前的清單、安裝了幾次
struct Env {
    current: Arc<Mutex<(Option<Arc<TwIp>>, bool)>>,
    installed: Arc<Mutex<Vec<Vec<u8>>>>,
    mem_calls: Arc<AtomicU32>,
}

fn hooks(env: &Env, mem: impl Fn(u32) -> Option<String> + Send + Sync + 'static) -> Hooks {
    let (cur, cur2, inst) = (env.current.clone(), env.current.clone(), env.installed.clone());
    let calls = env.mem_calls.clone();
    Hooks {
        current: Arc::new(move || cur.lock().unwrap().clone()),
        memory_short: Arc::new(move || mem(calls.fetch_add(1, Ordering::SeqCst))),
        load: Arc::new(|| None),
        install: Arc::new(move |t: TwIp, b: Vec<u8>| {
            *cur2.lock().unwrap() = (Some(Arc::new(t)), true);
            inst.lock().unwrap().push(b);
            Ok(())
        }),
    }
}

fn env(current: Option<TwIp>) -> Env {
    Env {
        current: Arc::new(Mutex::new((current.map(Arc::new), false))),
        installed: Arc::default(),
        mem_calls: Arc::default(),
    }
}

async fn mock(m: Mock) -> (Shared, Sources) {
    let shared = Arc::new(Mutex::new(m));
    let addr = serve(shared.clone()).await;
    (shared, Sources::with_base(&format!("http://{addr}")))
}

fn clock(date: &str) -> Arc<ManualClock> {
    Arc::new(ManualClock::new(parse_date_utc(date).unwrap() + 3 * HOUR_MS))
}

fn ctx(reason: &str, c: Arc<Value>, clk: &Arc<ManualClock>) -> JobCtx {
    JobCtx::new("tw-ip", reason, c).with_clock(clk.clone())
}

// 指令列在另一個程序跑、要等它結束：假伺服器要在別的執行緒上繼續服務
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn job_output_equals_cli_output() {
    let (shared, src) = mock(small_fixture(500)).await;
    let base = src.ripestat.clone();
    let e = env(None);
    let job = TwIpJob::new(src, hooks(&e, |_| None));
    job.run(ctx("手動 (測試)", cfg(json!({})), &clock(DAY))).await.unwrap();
    let job_out = e.installed.lock().unwrap()[0].clone();
    // 指令列：同樣的來源、同一天
    let dir = std::env::temp_dir().join(format!("kuroshio-twip-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join("tw-ip.json");
    let st = std::process::Command::new(env!("CARGO_BIN_EXE_tw-ip"))
        .args(["--sources-base", &base, "--date", DAY, "--pause", "0", "--min-v4", "0"])
        .arg(&out)
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(st.success());
    let cli_out = std::fs::read(&out).unwrap();
    assert_eq!(
        String::from_utf8_lossy(&job_out),
        String::from_utf8_lossy(&cli_out),
        "排程工作與指令列的輸出要一模一樣"
    );
    let t = TwIp::parse(&job_out).unwrap();
    assert_eq!(t.generated_at, DAY);
    assert_eq!(t.group("cht").unwrap().nets.v4_cidrs(), vec!["1.160.0.0/13", "61.216.0.0/15"]);
    assert_eq!(t.group("tanet").unwrap().nets.v4_cidrs(), vec!["140.112.0.0/16"]);
    // 有禮貌：每個 RIPEstat 請求都帶 sourceapp
    let m = shared.lock().unwrap();
    assert!(m
        .log
        .iter()
        .filter(|l| l.contains("announced-prefixes"))
        .all(|l| l.contains("sourceapp=kuroshio-dns")));
    let _ = std::fs::remove_dir_all(&dir);
    let st = job.status_json();
    assert_eq!(st["state"], "done");
    assert_eq!(st["source"], "本機產生");
    assert_eq!(st["listDate"], DAY);
}

#[tokio::test]
async fn pauses_on_memory_pressure_and_resumes_without_starting_over() {
    let (shared, src) = mock(small_fixture(50)).await;
    let e = env(None);
    // 第 3 次檢查（做完 2 個 RIR 之後）記憶體吃緊一次
    let job = TwIpJob::new(src, hooks(&e, |n| (n == 2).then(|| "記憶體吃緊".to_string())));
    let clk = clock(DAY);
    let mut o = Options::new("/nonexistent/state", "/nonexistent");
    o.clock = clk.clone();
    o.tick_interval = Duration::from_millis(50);
    let s = Scheduler::new((*cfg(json!({ "retrySec": 0.2 }))).clone(), None, o);
    s.register("tw-ip", job.clone());
    s.start();
    assert_eq!(s.request("tw-ip", "手動 (測試)")["ok"], true);
    // 先看到暫停（進度還在），之後自己續跑完成
    let mut saw_pause = false;
    for _ in 0..200 {
        let st = s.status()["detail"]["tw-ip"].clone();
        if st["state"] == "paused" {
            saw_pause = true;
            assert!(st["text"].as_str().unwrap().contains("記憶體吃緊"), "{st}");
            assert_eq!(st["progress"], "RIR 2/5");
            assert!(job.has_progress());
        }
        if st["state"] == "done" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(saw_pause, "應該暫停過");
    assert_eq!(job.status_json()["state"], "done");
    assert_eq!(e.installed.lock().unwrap().len(), 1);
    // 續跑：已經抓過的 RIR 不會再抓
    let m = shared.lock().unwrap();
    for (rir, _) in kuroshio_jobs::twip::RIRS {
        assert_eq!(m.count(&format!("/delegated-{rir}-")), 1, "{rir}");
    }
    assert!(!job.has_progress());
}

#[tokio::test]
async fn repeated_failures_abort_and_keep_current_list() {
    let mut m = small_fixture(10);
    m.always_fail.push("/delegated-arin-extended-latest".into());
    let (shared, src) = mock(m).await;
    let cur = TwIp::parse(br#"{"generatedAt":"2026-01-01","groups":[{"id":"other","name":"x","v4":["1.0.0.0/8"]}]}"#).unwrap();
    let e = env(Some(cur));
    let job = TwIpJob::new(src, hooks(&e, |_| None));
    let err = job.run(ctx("手動 (測試)", cfg(json!({})), &clock(DAY))).await.unwrap_err();
    assert!(err.to_string().contains("連續 3 次失敗"), "{err}");
    assert_eq!(shared.lock().unwrap().count("/delegated-arin-"), 3);
    assert!(e.installed.lock().unwrap().is_empty(), "沒有換掉目前的清單");
    assert!(!job.has_progress(), "放棄後丟掉進度");
    let st = job.status_json();
    assert_eq!(st["state"], "aborted");
    assert_eq!(st["listDate"], "2026-01-01");
    assert_eq!(st["source"], "公版");
    // 之後的續跑請求什麼都不做
    job.run(ctx(kuroshio_jobs::twip::RESUME_REASON, cfg(json!({})), &clock(DAY)))
        .await
        .unwrap();
    assert_eq!(shared.lock().unwrap().count("/delegated-apnic-"), 1);
}

#[tokio::test]
async fn deadline_abort() {
    let (_shared, src) = mock(small_fixture(10)).await;
    let e = env(None);
    let clk = clock(DAY);
    let c2 = clk.clone();
    // 一直記憶體吃緊；每檢查一次時間過了一天 → 超過 48 小時的期限就放棄
    let job = TwIpJob::new(
        src,
        hooks(&e, move |_| {
            c2.advance(24 * HOUR_MS);
            Some("記憶體吃緊".into())
        }),
    );
    let err = job
        .run(ctx("手動 (測試)", cfg(json!({ "deadlineHours": 48 })), &clk))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("48 小時"), "{err}");
    assert!(e.installed.lock().unwrap().is_empty());
    assert_eq!(e.mem_calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn validation_rejects_shrunken_list() {
    let (_shared, src) = mock(small_fixture(10)).await;
    // 目前的清單大很多（新的只有一半不到）
    let cur = TwIp::parse(br#"{"generatedAt":"2026-10-01","groups":[{"id":"other","name":"x","v4":["1.0.0.0/8"]}]}"#).unwrap();
    let e = env(Some(cur));
    let job = TwIpJob::new(src, hooks(&e, |_| None));
    let err = job.run(ctx("手動 (測試)", cfg(json!({})), &clock(DAY))).await.unwrap_err();
    assert!(err.to_string().contains("20%"), "{err}");
    assert!(e.installed.lock().unwrap().is_empty());
    assert!(job.status_json()["text"].as_str().unwrap().contains("繼續用目前的清單"));
}

#[tokio::test]
async fn rate_limited_waits_retry_after() {
    let mut m = small_fixture(10);
    m.faults.insert("/ripestat/AS3462".into(), vec![Fault::Status(429, Some("1"))]);
    let (shared, src) = mock(m).await;
    let e = env(None);
    let job = TwIpJob::new(src, hooks(&e, |_| None));
    let t0 = std::time::Instant::now();
    job.run(ctx("手動 (測試)", cfg(json!({})), &clock(DAY))).await.unwrap();
    assert!(t0.elapsed() >= Duration::from_secs(1), "照 Retry-After 等");
    assert_eq!(
        shared.lock().unwrap().count("/data/announced-prefixes/data.json?resource=AS3462&"),
        2
    );
    let t = TwIp::parse(&e.installed.lock().unwrap()[0]).unwrap();
    assert!(!t.group("cht").unwrap().nets.is_empty());
}

#[tokio::test]
async fn unchanged_content_is_not_written_and_young_list_skips() {
    let (shared, src) = mock(small_fixture(10)).await;
    let e = env(None);
    let job = TwIpJob::new(src, hooks(&e, |_| None));
    job.run(ctx("手動 (測試)", cfg(json!({})), &clock("2026-10-01"))).await.unwrap();
    assert_eq!(e.installed.lock().unwrap().len(), 1);
    // 一個月後再跑：網段一樣 → 不寫入（Flash 不動）
    let clk = clock("2026-11-01");
    job.run(ctx("排程", cfg(json!({})), &clk)).await.unwrap();
    assert_eq!(e.installed.lock().unwrap().len(), 1, "內容沒變不寫入");
    let st = job.status_json();
    assert_eq!(st["state"], "done");
    assert!(st["lastResult"].as_str().unwrap().contains("不必寫入"));
    // 排程：目前的清單才 3 天 → 這次不跑（不送任何請求）；手動照跑
    let before = shared.lock().unwrap().log.len();
    clk.set(parse_date_utc("2026-10-04").unwrap());
    job.run(ctx("排程", cfg(json!({})), &clk)).await.unwrap();
    assert_eq!(shared.lock().unwrap().log.len(), before);
    assert_eq!(job.status_json()["state"], "skipped");
    let _ = clk.now_ms();
}

#[tokio::test]
async fn yields_to_other_queued_jobs() {
    let (_shared, src) = mock(small_fixture(10)).await;
    let e = env(None);
    let job = TwIpJob::new(src, hooks(&e, |_| None));
    let clk = clock(DAY);
    let mut o = Options::new("/nonexistent/state", "/nonexistent");
    o.clock = clk.clone();
    o.tick_interval = Duration::from_millis(50);
    let mut c = (*cfg(json!({ "retrySec": 0.1, "pauseSec": [0.05, 0.05] }))).clone();
    c["jobs"]["other"] = json!({ "catchUp": false });
    let s = Scheduler::new(c, None, o);
    s.register("tw-ip", job.clone());
    let ran = Arc::new(AtomicU32::new(0));
    let (r2, j2) = (ran.clone(), job.clone());
    s.register("other", move |_: JobCtx| {
        let r = r2.clone();
        // 插隊的時候台灣 IP 清單還沒做完（進度留著等續跑）
        let mid = j2.has_progress();
        async move {
            r.fetch_add(if mid { 1 } else { 100 }, Ordering::SeqCst);
            Ok(())
        }
    });
    s.start();
    s.request("tw-ip", "手動 (測試)");
    tokio::time::sleep(Duration::from_millis(150)).await;
    s.request("other", "手動 (測試)");
    for _ in 0..400 {
        if job.status_json()["state"] == "done" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(job.status_json()["state"], "done");
    assert_eq!(ran.load(Ordering::SeqCst), 1, "別的工作中途插進來跑完");
    assert_eq!(e.installed.lock().unwrap().len(), 1);
}
