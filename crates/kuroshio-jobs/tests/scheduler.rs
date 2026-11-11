//! 排程器：時間計算（台北時間、跨日、星期）、補跑、一次一個、逾時、手動排入、暫停、狀態

use kuroshio_jobs::scheduler::{self, next_run, Options, Scheduler, CODE_TIMEOUT};
use kuroshio_jobs::time::{days_from_civil, ManualClock, DAY_MS, HOUR_MS, MIN_MS, TPE_OFFSET_MS};
use kuroshio_jobs::JobCtx;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;

/// 台北時間 → Unix 毫秒
fn tpe(y: i64, m: u32, d: u32, h: u64, mi: u64) -> u64 {
    days_from_civil(y, m, d) as u64 * DAY_MS + h * HOUR_MS + mi * MIN_MS - TPE_OFFSET_MS
}

fn opts(clock: &Arc<ManualClock>) -> Options {
    let mut o = Options::new("/nonexistent/state", "/nonexistent");
    o.clock = clock.clone();
    o
}

fn sched(cfg: Value, saved: Option<&[u8]>, clock: &Arc<ManualClock>) -> Scheduler {
    Scheduler::new(cfg, saved, opts(clock))
}

async fn noop(_: JobCtx) -> anyhow::Result<()> {
    Ok(())
}

async fn idle(s: &Scheduler) {
    for _ in 0..10_000 {
        if !s.is_busy() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("工作一直沒結束");
}

#[test]
fn next_run_times() {
    // 2026-11-10 是星期二
    let c = json!({ "at": "04:10" });
    assert_eq!(next_run(&c, tpe(2026, 11, 10, 3, 0)), Some(tpe(2026, 11, 10, 4, 10)));
    // 剛好在排定時間：下一次是明天
    assert_eq!(next_run(&c, tpe(2026, 11, 10, 4, 10)), Some(tpe(2026, 11, 11, 4, 10)));
    assert_eq!(next_run(&c, tpe(2026, 11, 10, 23, 59)), Some(tpe(2026, 11, 11, 4, 10)));
    // 台北午夜（UTC 16:00）前後
    let now = tpe(2026, 11, 10, 0, 30); // = 2026-11-09T16:30Z
    assert_eq!(next_run(&json!({ "at": "00:15" }), now), Some(tpe(2026, 11, 11, 0, 15)));
    assert_eq!(next_run(&json!({ "at": "00:45" }), now), Some(now + 15 * MIN_MS));
    assert_eq!(
        next_run(&json!({ "at": "23:50" }), tpe(2026, 11, 10, 23, 55)),
        Some(tpe(2026, 11, 11, 23, 50))
    );
    // 多個時間、亂序
    let c = json!({ "at": ["15:00", "03:00"] });
    assert_eq!(next_run(&c, tpe(2026, 11, 10, 4, 0)), Some(tpe(2026, 11, 10, 15, 0)));
    assert_eq!(next_run(&c, tpe(2026, 11, 10, 16, 0)), Some(tpe(2026, 11, 11, 3, 0)));
    // 每週日
    let c = json!({ "at": "03:10", "weekdays": [0] });
    assert_eq!(next_run(&c, tpe(2026, 11, 10, 3, 0)), Some(tpe(2026, 11, 15, 3, 10)));
    assert_eq!(next_run(&c, tpe(2026, 11, 15, 3, 9)), Some(tpe(2026, 11, 15, 3, 10)));
    assert_eq!(next_run(&c, tpe(2026, 11, 15, 3, 10)), Some(tpe(2026, 11, 22, 3, 10)));
    // 星期六 23:59（台北）→ 星期日；這時 UTC 還是星期六 15:59
    let c = json!({ "at": "00:00", "weekdays": [0, 3] });
    assert_eq!(next_run(&c, tpe(2026, 11, 14, 23, 59)), Some(tpe(2026, 11, 15, 0, 0)));
    assert_eq!(next_run(&c, tpe(2026, 11, 15, 0, 0)), Some(tpe(2026, 11, 18, 0, 0)));
    // 停用、沒有時間、格式錯誤
    assert_eq!(next_run(&json!({ "at": "04:10", "enabled": false }), 0), None);
    assert_eq!(next_run(&json!({}), tpe(2026, 11, 10, 0, 0)), None);
    assert_eq!(next_run(&json!({ "at": "25:00" }), tpe(2026, 11, 10, 0, 0)), None);
    assert_eq!(
        next_run(&json!({ "at": "4:10" }), tpe(2026, 11, 10, 0, 0)),
        Some(tpe(2026, 11, 10, 4, 10))
    );
    assert_eq!(scheduler::slot_stamp(tpe(2026, 11, 10, 4, 10)), "2026-11-10 04:10");
}

#[test]
fn tick_fires_once_per_slot() {
    let clock = Arc::new(ManualClock::new(tpe(2026, 11, 10, 4, 9)));
    let s = sched(
        json!({ "jobs": { "a": { "at": "04:10" }, "b": { "at": "04:10", "enabled": false }, "zz": { "at": "04:10" } } }),
        None,
        &clock,
    );
    s.register("a", noop);
    s.register("b", noop);
    assert!(s.tick().is_empty());
    clock.set(tpe(2026, 11, 10, 4, 10) + 20_000);
    assert_eq!(s.tick(), vec!["a"]); // b 停用、zz 沒有實作
    assert!(s.tick().is_empty());
    let st = s.status();
    assert_eq!(st["state"]["a"]["lastSlot"], "2026-11-10 04:10");
    assert_eq!(st["queue"], json!([{ "name": "a", "reason": "排程" }]));
    assert_eq!(st["nextRun"]["a"], json!(tpe(2026, 11, 11, 4, 10)));
    assert_eq!(st["nextRun"]["b"], Value::Null);
    // 排程檢查被延誤幾分鐘還是會跑；超過寬限就算錯過（交給補跑）
    let s2 = sched(json!({ "jobs": { "a": { "at": "04:10" } } }), None, &clock);
    s2.register("a", noop);
    clock.set(tpe(2026, 11, 10, 4, 14));
    assert_eq!(s2.tick(), vec!["a"]);
    let s3 = sched(json!({ "jobs": { "a": { "at": "04:10" } } }), None, &clock);
    s3.register("a", noop);
    clock.set(tpe(2026, 11, 10, 4, 16));
    assert!(s3.tick().is_empty());
}

#[test]
fn tick_catches_up_slot_missed_while_running() {
    // 程式一直在跑，但兩次檢查之間跨過了排定時間（系統休眠、時鐘往前跳）：補跑一次，錯過幾次都只跑一次
    let clock = Arc::new(ManualClock::new(tpe(2026, 11, 10, 4, 0)));
    let s = sched(
        json!({ "jobs": {
            "a": { "at": "04:10" },
            "multi": { "at": ["05:00", "06:00", "07:00"] },
            "later": { "at": "12:00" },
        } }),
        None,
        &clock,
    );
    for n in ["a", "multi", "later"] {
        s.register(n, noop);
    }
    assert!(s.tick().is_empty());
    // 休眠到 09:00
    clock.set(tpe(2026, 11, 10, 9, 0));
    let mut got = s.tick();
    got.sort();
    assert_eq!(got, ["a", "multi"]);
    let st = s.status();
    assert_eq!(st["state"]["multi"]["lastSlot"], "2026-11-10 07:00", "記最近的那一次");
    assert!(st["queue"].as_array().unwrap().iter().all(|q| q["reason"] == "排程（補跑錯過的）"));
    assert!(s.tick().is_empty(), "不會重複");
    clock.set(tpe(2026, 11, 10, 11, 0));
    assert!(s.tick().is_empty(), "還沒到的不跑");

    // 排定時間之後已經開始跑過的不補跑（只記下這次排定時間）
    let saved = json!({ "a": { "lastStart": tpe(2026, 11, 11, 4, 20) } }).to_string();
    let clock = Arc::new(ManualClock::new(tpe(2026, 11, 11, 4, 0)));
    let s = sched(json!({ "jobs": { "a": { "at": "04:10" } } }), Some(saved.as_bytes()), &clock);
    s.register("a", noop);
    assert!(s.tick().is_empty());
    clock.set(tpe(2026, 11, 11, 4, 30));
    assert!(s.tick().is_empty());
    assert_eq!(s.status()["state"]["a"]["lastSlot"], "2026-11-11 04:10");

    // 剛啟動、還沒檢查過就已經錯過的：交給啟動補跑（catch_up_plan），這裡不跑
    let clock = Arc::new(ManualClock::new(tpe(2026, 11, 11, 9, 0)));
    let s = sched(json!({ "jobs": { "a": { "at": "04:10" } } }), None, &clock);
    s.register("a", noop);
    assert!(s.tick().is_empty());
    clock.set(tpe(2026, 11, 11, 9, 1));
    assert!(s.tick().is_empty());
}

#[test]
fn catch_up_plan() {
    let now = tpe(2026, 11, 10, 12, 0);
    let clock = Arc::new(ManualClock::new(now));
    let mut o = opts(&clock);
    o.file_exists = Arc::new(|p: &str| p != "state/missing.json");
    let saved = json!({
        "stale": { "lastCode": 0, "lastEnd": now - 2 * DAY_MS },
        "fresh": { "lastCode": 0, "lastEnd": now - HOUR_MS },
        "failedRecently": { "lastCode": 1, "lastEnd": now - HOUR_MS, "lastOkEnd": now - 3 * DAY_MS },
        "weekly": { "lastCode": 1, "lastOkEnd": now - 3 * DAY_MS },
        "present": { "lastCode": 0, "lastEnd": now - HOUR_MS },
    });
    let cfg = json!({ "jobs": {
        "missing": { "at": "04:10", "runIfMissing": "state/missing.json", "startDelaySec": 300 },
        "present": { "at": "04:10", "runIfMissing": "state/present.json" },
        "stale": { "at": "04:10", "startDelaySec": 30 },
        "fresh": { "at": "04:10" },
        "failedRecently": { "at": "04:10", "startDelaySec": 120 },
        "weekly": { "at": "03:10", "weekdays": [0] },
        "never": { "at": "03:10", "catchUp": false },
        "disabled": { "at": "03:10", "enabled": false },
        "unregistered": { "at": "03:10" },
    }});
    let s = Scheduler::new(cfg, Some(saved.to_string().as_bytes()), o);
    for n in [
        "missing",
        "present",
        "stale",
        "fresh",
        "failedRecently",
        "weekly",
        "never",
        "disabled",
    ] {
        s.register(n, noop);
    }
    let plan = s.catch_up_plan();
    assert_eq!(
        plan,
        vec![
            ("stale".to_string(), 30, "補跑（上次成功 2026-11-08 12:00:00）".to_string()),
            (
                "failedRecently".to_string(),
                120,
                "補跑（上次成功 2026-11-07 12:00:00）".to_string()
            ),
            ("missing".to_string(), 300, "首次執行（缺少 state/missing.json）".to_string()),
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn start_skips_slots_before_startup_and_runs_later_ones() {
    let now = tpe(2026, 11, 10, 4, 12);
    let clock = Arc::new(ManualClock::new(now));
    let runs = Arc::new(AtomicU32::new(0));
    let saved = json!({ "a": { "lastCode": 0, "lastEnd": now - HOUR_MS } });
    let s = sched(
        json!({ "jobs": { "a": { "at": "04:10" } } }),
        Some(saved.to_string().as_bytes()),
        &clock,
    );
    let r = runs.clone();
    s.register("a", move |_ctx: JobCtx| {
        let r = r.clone();
        async move {
            r.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    });
    let h = s.start();
    tokio::time::sleep(Duration::from_secs(120)).await;
    assert_eq!(runs.load(Ordering::SeqCst), 0, "啟動前的排程時間不補（交給補跑判斷）");
    clock.set(tpe(2026, 11, 11, 4, 10) + 5_000);
    tokio::time::sleep(Duration::from_secs(31)).await;
    idle(&s).await;
    assert_eq!(runs.load(Ordering::SeqCst), 1);
    let st = s.status();
    assert_eq!(st["state"]["a"]["lastCode"], 0);
    assert_eq!(st["state"]["a"]["reason"], "排程");
    h.abort();
}

#[tokio::test(start_paused = true)]
async fn catch_up_runs_after_start_delay() {
    let clock = Arc::new(ManualClock::new(tpe(2026, 11, 10, 12, 0)));
    let mut o = opts(&clock);
    o.file_exists = Arc::new(|_: &str| false);
    let s = Scheduler::new(
        json!({ "jobs": { "a": { "at": "04:10", "runIfMissing": "state/upstreams.json", "startDelaySec": 300 } } }),
        None,
        o,
    );
    let runs = Arc::new(AtomicU32::new(0));
    let r = runs.clone();
    s.register("a", move |_ctx: JobCtx| {
        let r = r.clone();
        async move {
            r.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    });
    let h = s.start();
    tokio::time::sleep(Duration::from_secs(299)).await;
    assert_eq!(runs.load(Ordering::SeqCst), 0);
    tokio::time::sleep(Duration::from_secs(2)).await;
    idle(&s).await;
    assert_eq!(runs.load(Ordering::SeqCst), 1);
    assert_eq!(s.status()["state"]["a"]["reason"], "首次執行（缺少 state/upstreams.json）");
    h.abort();
}

#[tokio::test(start_paused = true)]
async fn one_at_a_time_and_manual_requests() {
    let clock = Arc::new(ManualClock::new(tpe(2026, 11, 10, 12, 0)));
    let changes = Arc::new(AtomicU32::new(0));
    let mut o = opts(&clock);
    let c = changes.clone();
    o.on_state_change = Some(Arc::new(move || {
        c.fetch_add(1, Ordering::SeqCst);
    }));
    let saved = json!({ "a": { "custom": "保留", "lastCode": 1 }, "legacy-job": { "lastEnd": 1 } });
    let s = Scheduler::new(
        json!({ "jobs": { "a": { "at": "04:10", "catchUp": false } } }),
        Some(saved.to_string().as_bytes()),
        o,
    );
    let gate = Arc::new(Notify::new());
    let order = Arc::new(Mutex::new(Vec::new()));
    let (g, o1) = (gate.clone(), order.clone());
    s.register("a", move |_ctx: JobCtx| {
        let (g, o1) = (g.clone(), o1.clone());
        async move {
            o1.lock().unwrap().push("a 開始");
            g.notified().await;
            o1.lock().unwrap().push("a 結束");
            Ok(())
        }
    });
    let o2 = order.clone();
    s.register("b", move |ctx: JobCtx| {
        let o2 = o2.clone();
        async move {
            assert_eq!(ctx.reason, "手動 (管理介面)");
            o2.lock().unwrap().push("b");
            Ok(())
        }
    });
    let h = s.start();
    assert_eq!(s.request("a", "手動 (管理介面)"), json!({ "ok": true }));
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(s.request("b", "手動 (管理介面)"), json!({ "ok": true }));
    assert_eq!(s.request("a", "x"), json!({ "ok": false, "error": "執行中" }));
    assert_eq!(s.request("b", "x"), json!({ "ok": false, "error": "已在佇列" }));
    assert_eq!(s.request("nope", "x"), json!({ "ok": false, "error": "未知的工作" }));
    tokio::time::sleep(Duration::from_secs(60)).await;
    let st = s.status();
    assert_eq!(st["running"]["name"], "a");
    assert_eq!(st["running"]["pid"], std::process::id());
    assert_eq!(st["queue"], json!([{ "name": "b", "reason": "手動 (管理介面)" }]));
    assert_eq!(st["config"], json!({ "a": { "at": "04:10", "catchUp": false } }));
    assert_eq!(*order.lock().unwrap(), vec!["a 開始"], "a 還沒結束，b 不能開始");
    clock.advance(90_000);
    gate.notify_one();
    idle(&s).await;
    assert_eq!(*order.lock().unwrap(), vec!["a 開始", "a 結束", "b"]);
    let st = s.status();
    assert_eq!(st["running"], Value::Null);
    let a = &st["state"]["a"];
    assert_eq!(a["lastCode"], 0);
    assert_eq!(a["lastOkEnd"], a["lastEnd"]);
    assert_eq!(a["lastEnd"].as_u64().unwrap() - a["lastStart"].as_u64().unwrap(), 90_000);
    assert!(changes.load(Ordering::SeqCst) >= 4);
    // 快照保留不認識的欄位與不認識的工作
    let (name, bytes) = s.snapshot();
    assert_eq!(name, "jobs.json");
    let snap: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(snap["a"]["custom"], "保留");
    assert_eq!(snap["legacy-job"]["lastEnd"], 1);
    assert_eq!(snap["b"]["lastCode"], 0);
    // minGapMin：剛跑過的自動請求忽略
    assert_eq!(
        s.request_with_gap("b", "節點不足", 60.0),
        json!({ "ok": false, "error": "剛執行過" })
    );
    clock.advance(61 * MIN_MS);
    assert_eq!(s.request_with_gap("b", "節點不足", 60.0), json!({ "ok": true }));
    idle(&s).await;
    h.abort();
}

#[tokio::test(start_paused = true)]
async fn timeout_failure_and_panic() {
    let clock = Arc::new(ManualClock::new(tpe(2026, 11, 10, 12, 0)));
    let s = sched(json!({ "jobs": { "slow": { "timeoutMin": 1, "catchUp": false } } }), None, &clock);
    let dropped = Arc::new(AtomicBool::new(false));
    struct Guard(Arc<AtomicBool>);
    impl Drop for Guard {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let d = dropped.clone();
    s.register("slow", move |_ctx: JobCtx| {
        let g = Guard(d.clone());
        async move {
            let _g = g;
            tokio::time::sleep(Duration::from_secs(3600)).await;
            Ok(())
        }
    });
    s.register("fail", |_ctx: JobCtx| async { anyhow::bail!("上游名單讀不到") });
    s.register("boom", |_ctx: JobCtx| async {
        if true {
            panic!("測試用的 panic");
        }
        Ok(())
    });
    s.register("ok", noop);
    let h = s.start();
    for n in ["slow", "fail", "boom", "ok"] {
        assert_eq!(s.request(n, "測試")["ok"], true);
    }
    tokio::time::sleep(Duration::from_secs(59)).await;
    assert_eq!(s.running().as_deref(), Some("slow"));
    idle(&s).await;
    let st = s.status()["state"].clone();
    assert_eq!(st["slow"]["lastCode"], CODE_TIMEOUT);
    assert!(st["slow"]["lastError"].as_str().unwrap().contains("強制結束"));
    assert!(st["slow"].get("lastOkEnd").is_none());
    assert!(dropped.load(Ordering::SeqCst), "逾時的工作要被丟掉");
    assert_eq!(st["fail"]["lastCode"], 1);
    assert_eq!(st["fail"]["lastError"], "上游名單讀不到");
    assert_eq!(st["boom"]["lastCode"], 1);
    assert_eq!(st["ok"]["lastCode"], 0, "前面的工作失敗或 panic，後面的照樣跑");
    h.abort();
}

#[tokio::test(start_paused = true)]
async fn defer_hook_delays_start_and_pauses_at_checkpoint() {
    let clock = Arc::new(ManualClock::new(tpe(2026, 11, 10, 12, 0)));
    let pressure = Arc::new(AtomicBool::new(true));
    let mut o = opts(&clock);
    let p = pressure.clone();
    o.should_defer = Some(Arc::new(move || p.load(Ordering::SeqCst)));
    let s = Scheduler::new(json!({}), None, o);
    let gate = Arc::new(Notify::new());
    let steps = Arc::new(AtomicU32::new(0));
    let (g, st) = (gate.clone(), steps.clone());
    s.register("a", move |ctx: JobCtx| {
        let (g, st) = (g.clone(), st.clone());
        async move {
            st.store(1, Ordering::SeqCst);
            g.notified().await;
            ctx.checkpoint().await;
            st.store(2, Ordering::SeqCst);
            Ok(())
        }
    });
    let h = s.start();
    s.request("a", "測試");
    tokio::time::sleep(Duration::from_secs(300)).await;
    assert_eq!(steps.load(Ordering::SeqCst), 0, "吃緊時不啟動新工作");
    assert!(s.is_busy());
    pressure.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(31)).await;
    assert_eq!(steps.load(Ordering::SeqCst), 1);
    // 執行中又吃緊：停在 checkpoint
    pressure.store(true, Ordering::SeqCst);
    gate.notify_one();
    tokio::time::sleep(Duration::from_secs(600)).await;
    assert_eq!(steps.load(Ordering::SeqCst), 1);
    pressure.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert_eq!(steps.load(Ordering::SeqCst), 2);
    idle(&s).await;
    h.abort();
}

#[cfg(target_os = "linux")]
#[tokio::test(start_paused = true)]
async fn lock_held_by_other_process_skips_job() {
    let dir = std::env::temp_dir().join(format!("kuroshio-jobs-lock-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("a.lock"), "1").unwrap(); // PID 1 一定存在
    let clock = Arc::new(ManualClock::new(tpe(2026, 11, 10, 12, 0)));
    let mut o = opts(&clock);
    o.lock_dir = Some(dir.clone());
    let s = Scheduler::new(json!({}), None, o);
    let runs = Arc::new(AtomicU32::new(0));
    let r = runs.clone();
    s.register("a", move |_ctx: JobCtx| {
        let r = r.clone();
        async move {
            r.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    });
    let h = s.start();
    s.request("a", "測試");
    idle(&s).await;
    assert_eq!(runs.load(Ordering::SeqCst), 0);
    assert!(s.status()["state"].get("a").is_none());
    assert!(s.run_direct("a", "手動").await.unwrap_err().to_string().contains("PID 1"));
    // 鎖釋放後可以跑，跑完鎖檔移除
    std::fs::remove_file(dir.join("a.lock")).unwrap();
    s.request("a", "測試");
    idle(&s).await;
    assert_eq!(runs.load(Ordering::SeqCst), 1);
    assert!(!dir.join("a.lock").exists());
    s.run_direct("a", "手動").await.unwrap();
    assert_eq!(runs.load(Ordering::SeqCst), 2);
    h.abort();
    let _ = std::fs::remove_dir_all(&dir);
}
