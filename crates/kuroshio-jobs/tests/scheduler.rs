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
    assert_eq!(st["queue"], json!([{ "name": "a", "reason": "排程", "priority": false }]));
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
    assert_eq!(
        st["queue"],
        json!([{ "name": "b", "reason": "手動 (管理介面)", "priority": false }])
    );
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

#[test]
fn monthly_and_per_device_jitter() {
    use kuroshio_jobs::scheduler::{jitter_ms, last_slot_seeded, next_run_seeded};
    let c = json!({ "at": "00:50", "monthDays": [1] });
    assert_eq!(next_run(&c, tpe(2026, 11, 10, 3, 0)), Some(tpe(2026, 12, 1, 0, 50)));
    assert_eq!(next_run(&c, tpe(2026, 12, 1, 0, 40)), Some(tpe(2026, 12, 1, 0, 50)));
    assert_eq!(next_run(&c, tpe(2026, 12, 1, 0, 50)), Some(tpe(2027, 1, 1, 0, 50)));
    // 錯開：0–27 天、0–180 分鐘，同一個種子一定落在同一個時間
    let c = json!({ "at": "00:50", "monthDays": [1], "jitterDays": 27, "jitterMin": 180 });
    for seed in [1u64, 7, 12_345, 987_654_321, u64::MAX >> 1] {
        let j = jitter_ms(&c, seed);
        assert!(j <= 27 * DAY_MS + 180 * MIN_MS, "{seed}");
        let n = next_run_seeded(&c, tpe(2026, 11, 10, 3, 0), seed).unwrap();
        assert!(n > tpe(2026, 11, 10, 3, 0));
        // 下一次一定是某個月 1 日 00:50 往後挪 j
        let base = n - j;
        assert!(base == tpe(2026, 11, 1, 0, 50) || base == tpe(2026, 12, 1, 0, 50), "{seed}");
        assert_eq!(last_slot_seeded(&c, n, seed), Some(n));
        assert!(last_slot_seeded(&c, n - 1, seed).map(|t| t < n).unwrap_or(true));
    }
    // 不同裝置分散開
    let spread: std::collections::HashSet<u64> = (1..50u64).map(|s| jitter_ms(&c, s * 7919) / DAY_MS).collect();
    assert!(spread.len() > 10);
}

#[test]
fn jitter_seed_is_created_once_and_saved() {
    let clock = Arc::new(ManualClock::new(tpe(2026, 11, 10, 3, 0)));
    let changed = Arc::new(AtomicU32::new(0));
    let c2 = changed.clone();
    let mut o = opts(&clock);
    o.on_state_change = Some(Arc::new(move || {
        c2.fetch_add(1, Ordering::SeqCst);
    }));
    let cfg = json!({ "jobs": { "m": { "at": "00:50", "monthDays": [1], "jitterDays": 27 } } });
    let s = Scheduler::new(cfg.clone(), None, o);
    s.register("m", noop);
    s.tick();
    let seed = s.status()["state"]["m"]["seed"].as_u64().unwrap();
    assert!(seed > 0);
    assert_eq!(changed.load(Ordering::SeqCst), 1, "種子要存進 jobs.json");
    s.tick();
    assert_eq!(s.status()["state"]["m"]["seed"].as_u64(), Some(seed), "之後固定");
    assert_eq!(changed.load(Ordering::SeqCst), 1);
    // 重新啟動：從 jobs.json 讀回同一個種子、同一個下次時間
    let (_, saved) = s.snapshot();
    let s2 = sched(cfg, Some(&saved), &clock);
    s2.register("m", noop);
    assert_eq!(s2.next_run("m"), s.next_run("m"));
    assert_eq!(s.status()["nextRun"]["m"].as_u64(), s.next_run("m"));
}

#[test]
fn run_if_missing_accepts_compressed_state_file() {
    let dir = std::env::temp_dir().join(format!("kuroshio-rim-{}", std::process::id()));
    let state = dir.join("state");
    std::fs::create_dir_all(state.join("cdn")).unwrap();
    let o = kuroshio_jobs::Options::new(&state, &dir);
    assert!(!(o.file_exists)("state/cdn/pools.json"), "沒有檔案：缺檔");
    std::fs::write(state.join("cdn/pools.json.zst"), b"x").unwrap();
    assert!((o.file_exists)("state/cdn/pools.json"), "只有壓縮檔（pools.json.zst）也算有");
    std::fs::remove_file(state.join("cdn/pools.json.zst")).unwrap();
    std::fs::write(state.join("cdn/pools.json"), b"{}").unwrap();
    assert!((o.file_exists)("state/cdn/pools.json"), "一般檔也算有");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn catch_up_window_parse_and_match() {
    use scheduler::{in_window, parse_window};
    assert_eq!(parse_window("01:00-06:00"), Some((60, 360)));
    assert_eq!(parse_window(" 23:30 - 05:00 "), Some((1410, 300)));
    assert_eq!(parse_window(""), None);
    assert_eq!(parse_window("01:00"), None);
    assert_eq!(parse_window("25:00-06:00"), None);
    assert_eq!(parse_window("03:00-03:00"), None, "開始等於結束 = 不限制");
    let w = parse_window("01:00-06:00").unwrap();
    assert!(in_window(tpe(2026, 11, 10, 1, 0), w));
    assert!(in_window(tpe(2026, 11, 10, 5, 59), w));
    assert!(!in_window(tpe(2026, 11, 10, 6, 0), w));
    assert!(!in_window(tpe(2026, 11, 10, 12, 0), w));
    let night = parse_window("23:00-05:00").unwrap();
    assert!(in_window(tpe(2026, 11, 10, 23, 30), night));
    assert!(in_window(tpe(2026, 11, 11, 4, 0), night));
    assert!(!in_window(tpe(2026, 11, 10, 12, 0), night));
}

/// 3.4.0 補跑時段（padavan-tw 建議）：白天開機時，缺檔的補跑等到時段內才跑；排定時間與手動不受影響
#[tokio::test(start_paused = true)]
async fn catch_up_waits_for_window() {
    let clock = Arc::new(ManualClock::new(tpe(2026, 11, 10, 12, 0)));
    let mut o = opts(&clock);
    o.file_exists = Arc::new(|_: &str| false);
    o.tick_interval = Duration::from_secs(60);
    let s = Scheduler::new(
        json!({
            "system": { "catchUpWindow": "01:00-06:00" },
            "jobs": { "a": { "at": "04:10", "runIfMissing": "state/upstreams.json", "startDelaySec": 60 } }
        }),
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
    tokio::time::sleep(Duration::from_secs(600)).await;
    assert_eq!(runs.load(Ordering::SeqCst), 0, "白天不補跑");
    let st = s.status();
    assert_eq!(st["catchUpWindow"], "01:00-06:00");
    assert_eq!(st["catchUpWaiting"], json!(["a"]));
    // 手動照樣可以跑
    assert_eq!(s.request("a", "手動")["ok"], true);
    idle(&s).await;
    assert_eq!(runs.load(Ordering::SeqCst), 1);
    // 時鐘走到補跑時段：等的這段期間已經手動成功跑過，補跑不再重做（3.4.2）
    clock.set(tpe(2026, 11, 11, 1, 5));
    tokio::time::sleep(Duration::from_secs(120)).await;
    idle(&s).await;
    assert_eq!(runs.load(Ordering::SeqCst), 1);
    assert_eq!(s.status()["catchUpWaiting"], json!([]));
    h.abort();
}

/// 3.4.2：結果由上游黑潮提供（串接中）的工作，補跑不排隊、到時段也不跑，狀態列在 catchUpProvided；
/// 串接解除（不再提供）之後照補跑時段補跑
#[tokio::test(start_paused = true)]
async fn catch_up_skipped_while_provided() {
    let clock = Arc::new(ManualClock::new(tpe(2026, 11, 10, 12, 0)));
    let provided = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let mut o = opts(&clock);
    o.file_exists = Arc::new(|_: &str| false);
    o.tick_interval = Duration::from_secs(60);
    let p2 = provided.clone();
    o.provided = Some(Arc::new(move |n: &str| n == "a" && p2.load(Ordering::SeqCst)));
    let s = Scheduler::new(
        json!({
            "system": { "catchUpWindow": "01:00-06:00" },
            // 只在週日排定（測試走的 11/10～11/12 不會碰到排定時間，只看補跑）
            "jobs": { "a": { "at": "04:10", "weekdays": [0], "runIfMissing": "state/upstreams.json", "startDelaySec": 60 } }
        }),
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
    tokio::time::sleep(Duration::from_secs(600)).await;
    let st = s.status();
    assert_eq!(st["catchUpWaiting"], json!([]), "由上游提供：不列成等時段");
    assert_eq!(st["catchUpProvided"], json!(["a"]));
    // 到了時段也不跑（跑了只會被略過）
    clock.set(tpe(2026, 11, 11, 1, 5));
    tokio::time::sleep(Duration::from_secs(300)).await;
    idle(&s).await;
    assert_eq!(runs.load(Ordering::SeqCst), 0);
    assert_eq!(s.status()["catchUpProvided"], json!(["a"]));
    // 串接解除（白天）：改成等時段
    clock.set(tpe(2026, 11, 11, 12, 0));
    provided.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(120)).await;
    let st = s.status();
    assert_eq!(
        (st["catchUpWaiting"].clone(), st["catchUpProvided"].clone()),
        (json!(["a"]), json!([]))
    );
    assert_eq!(runs.load(Ordering::SeqCst), 0);
    // 下一個時段：補跑
    clock.set(tpe(2026, 11, 12, 1, 5));
    tokio::time::sleep(Duration::from_secs(120)).await;
    idle(&s).await;
    assert_eq!(runs.load(Ordering::SeqCst), 1);
    assert_eq!(s.status()["catchUpWaiting"], json!([]));
    h.abort();
}

/// 3.4.2 Windows 實測：串接了、還沒跟上游黑潮同步過（`provided_pending`）時補跑先等；
/// 同步完成後，由上游提供的不跑，其他的照常補跑
#[tokio::test(start_paused = true)]
async fn catch_up_waits_for_first_share_sync() {
    let clock = Arc::new(ManualClock::new(tpe(2026, 11, 10, 12, 0)));
    let pending = Arc::new(AtomicBool::new(true));
    let provided = Arc::new(AtomicBool::new(false));
    let mut o = opts(&clock);
    o.file_exists = Arc::new(|_: &str| false);
    let (p1, p2) = (pending.clone(), provided.clone());
    o.provided_pending = Some(Arc::new(move || p1.load(Ordering::SeqCst)));
    o.provided = Some(Arc::new(move |n: &str| n == "a" && p2.load(Ordering::SeqCst)));
    let job = json!({ "at": "04:10", "weekdays": [0], "runIfMissing": "state/x.json", "startDelaySec": 30 });
    let s = Scheduler::new(json!({ "jobs": { "a": job.clone(), "b": job } }), None, o);
    let runs: Vec<Arc<AtomicU32>> = (0..2).map(|_| Arc::new(AtomicU32::new(0))).collect();
    for (name, r) in ["a", "b"].into_iter().zip(runs.iter().cloned()) {
        s.register(name, move |_ctx: JobCtx| {
            let r = r.clone();
            async move {
                r.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        });
    }
    let h = s.start();
    tokio::time::sleep(Duration::from_secs(120)).await;
    idle(&s).await;
    assert_eq!(
        (runs[0].load(Ordering::SeqCst), runs[1].load(Ordering::SeqCst)),
        (0, 0),
        "還沒同步：先等"
    );
    // 第一次同步完成：a 由上游提供，b 沒有
    provided.store(true, Ordering::SeqCst);
    pending.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(60)).await;
    idle(&s).await;
    assert_eq!((runs[0].load(Ordering::SeqCst), runs[1].load(Ordering::SeqCst)), (0, 1));
    assert_eq!(s.status()["catchUpProvided"], json!(["a"]));
    h.abort();
}

/// 一直同步不起來（上游一直回 REFUSED）：最多等 10 分鐘，之後照常補跑
#[tokio::test(start_paused = true)]
async fn catch_up_pending_gives_up_after_10_minutes() {
    let clock = Arc::new(ManualClock::new(tpe(2026, 11, 10, 12, 0)));
    let mut o = opts(&clock);
    o.file_exists = Arc::new(|_: &str| false);
    o.provided_pending = Some(Arc::new(|| true));
    let s = Scheduler::new(
        json!({ "jobs": { "a": { "at": "04:10", "weekdays": [0], "runIfMissing": "state/x.json", "startDelaySec": 30 } } }),
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
    tokio::time::sleep(Duration::from_secs(9 * 60)).await;
    idle(&s).await;
    assert_eq!(runs.load(Ordering::SeqCst), 0);
    tokio::time::sleep(Duration::from_secs(2 * 60)).await;
    idle(&s).await;
    assert_eq!(runs.load(Ordering::SeqCst), 1);
    h.abort();
}

/// 沒設補跑時段：跟以前一樣，啟動延遲後就補跑
#[tokio::test(start_paused = true)]
async fn catch_up_without_window_runs_immediately() {
    let clock = Arc::new(ManualClock::new(tpe(2026, 11, 10, 12, 0)));
    let mut o = opts(&clock);
    o.file_exists = Arc::new(|_: &str| false);
    let s = Scheduler::new(
        json!({ "system": { "catchUpWindow": "" }, "jobs": { "a": { "at": "04:10", "runIfMissing": "x", "startDelaySec": 60 } } }),
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
    tokio::time::sleep(Duration::from_secs(61)).await;
    idle(&s).await;
    assert_eq!(runs.load(Ordering::SeqCst), 1);
    assert_eq!(s.status()["catchUpWindow"], Value::Null);
    h.abort();
}

// ---------------- 3.5.0 A9：手動觸發的工作優先 ----------------

/// 長工作 `long` 一直跑到放行；a、b、c 只記下執行順序。回傳（排程器、放行、順序、長工作看到的 priority_waiting）
type Log<T> = Arc<Mutex<Vec<T>>>;

fn priority_fixture(clock: &Arc<ManualClock>) -> (Scheduler, Arc<Notify>, Log<String>, Log<bool>) {
    let cfg = json!({ "jobs": {
        "long": { "at": "04:10", "catchUp": false },
        "a": { "at": "04:10", "catchUp": false },
        "b": { "at": "04:10", "catchUp": false },
        "c": { "at": "04:10", "catchUp": false },
    }});
    let s = sched(cfg, None, clock);
    let gate = Arc::new(Notify::new());
    let order = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (g, o, w) = (gate.clone(), order.clone(), seen.clone());
    s.register("long", move |ctx: JobCtx| {
        let (g, o, w) = (g.clone(), o.clone(), w.clone());
        async move {
            o.lock().unwrap().push("long".to_string());
            g.notified().await;
            w.lock().unwrap().push(ctx.priority_waiting());
            Ok(())
        }
    });
    for n in ["a", "b", "c"] {
        let o = order.clone();
        s.register(n, move |ctx: JobCtx| {
            let o = o.clone();
            async move {
                o.lock().unwrap().push(format!("{}({})", ctx.name, ctx.reason));
                Ok(())
            }
        });
    }
    (s, gate, order, seen)
}

#[tokio::test(start_paused = true)]
async fn manual_request_jumps_queue() {
    let clock = Arc::new(ManualClock::new(tpe(2026, 11, 10, 12, 0)));
    let (s, gate, order, seen) = priority_fixture(&clock);
    let h = s.start();
    assert_eq!(s.request("long", "補跑"), json!({ "ok": true }));
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(s.request("a", "補跑"), json!({ "ok": true }));
    assert_eq!(s.request("b", "排程"), json!({ "ok": true }));
    assert_eq!(s.request_priority("c", "手動 (管理介面)"), json!({ "ok": true }));
    let q = s.status()["queue"].clone();
    assert_eq!(
        q,
        json!([
            { "name": "c", "reason": "手動 (管理介面)", "priority": true },
            { "name": "a", "reason": "補跑", "priority": false },
            { "name": "b", "reason": "排程", "priority": false },
        ])
    );
    // 正在跑的不中斷（一次只跑一個）；手動的不能重複排、正在跑的也不能
    assert_eq!(s.request_priority("long", "手動"), json!({ "ok": false, "error": "執行中" }));
    assert_eq!(s.request_priority("nope", "手動"), json!({ "ok": false, "error": "未知的工作" }));
    gate.notify_one();
    idle(&s).await;
    h.abort();
    assert_eq!(*order.lock().unwrap(), vec!["long", "c(手動 (管理介面))", "a(補跑)", "b(排程)"]);
    assert_eq!(*seen.lock().unwrap(), vec![true], "長工作看得到有優先的工作在等");
}

#[tokio::test(start_paused = true)]
async fn manual_request_moves_existing_entry_to_front() {
    let clock = Arc::new(ManualClock::new(tpe(2026, 11, 10, 12, 0)));
    let (s, gate, order, seen) = priority_fixture(&clock);
    let h = s.start();
    s.request("long", "補跑");
    tokio::time::sleep(Duration::from_millis(10)).await;
    s.request("a", "補跑");
    s.request("b", "補跑");
    // 一般的排入：已在佇列就不動；手動的：移到最前面，原因改成手動
    assert_eq!(s.request("b", "手動"), json!({ "ok": false, "error": "已在佇列" }));
    assert_eq!(s.request_priority("b", "手動 (管理介面)"), json!({ "ok": true }));
    let names: Vec<String> = s.status()["queue"]
        .as_array()
        .unwrap()
        .iter()
        .map(|q| q["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, ["b", "a"], "沒有重複");
    gate.notify_one();
    idle(&s).await;
    h.abort();
    assert_eq!(*order.lock().unwrap(), vec!["long", "b(手動 (管理介面))", "a(補跑)"]);
    assert_eq!(*seen.lock().unwrap(), vec![true]);
    // 只有一般的工作在等：不算優先（長工作不讓出）
    let (s, gate, _, seen) = priority_fixture(&clock);
    let h = s.start();
    s.request("long", "補跑");
    tokio::time::sleep(Duration::from_millis(10)).await;
    s.request("a", "排程");
    gate.notify_one();
    idle(&s).await;
    h.abort();
    assert_eq!(*seen.lock().unwrap(), vec![false]);
}

#[test]
fn catch_up_puts_benchmark_before_scan_when_upstreams_not_benchmarked() {
    let now = tpe(2026, 11, 10, 12, 0);
    let clock = Arc::new(ManualClock::new(now));
    let cfg = json!({ "jobs": {
        "dns-benchmark": { "at": "04:10", "startDelaySec": 300 },
        "cdn-ranges": { "at": "03:10", "weekdays": [0], "startDelaySec": 30 },
        "cdn-scan": { "at": "03:20", "weekdays": [0], "startDelaySec": 60 },
        "cdn-pool": { "at": "05:30", "startDelaySec": 120 },
    }});
    let plan = |benchmarked: bool| {
        let mut o = opts(&clock);
        o.catch_up_first = Some(Arc::new(move |n: &str| n == "dns-benchmark" && !benchmarked));
        let s = Scheduler::new(cfg.clone(), None, o);
        for n in ["dns-benchmark", "cdn-ranges", "cdn-scan", "cdn-pool"] {
            s.register(n, noop);
        }
        s.catch_up_plan().into_iter().map(|(n, d, _)| (n, d)).collect::<Vec<_>>()
    };
    let p = |v: &[(&str, u64)]| v.iter().map(|(n, d)| (n.to_string(), *d)).collect::<Vec<_>>();
    // 自動上游還沒評測過（預設名單）：cdn-scan 排到評測後面；評測與其他工作的延遲不變
    assert_eq!(
        plan(false),
        p(&[("cdn-ranges", 30), ("cdn-pool", 120), ("dns-benchmark", 300), ("cdn-scan", 301)])
    );
    // 評測過了：跟 3.4.4 一樣
    assert_eq!(
        plan(true),
        p(&[("cdn-ranges", 30), ("cdn-scan", 60), ("cdn-pool", 120), ("dns-benchmark", 300)])
    );
}

/// 3.5.0 E1：連續失敗次數，成功拿掉、失敗加 1（飽和到 9,999）
#[tokio::test(start_paused = true)]
async fn fail_streak_counts_and_resets() {
    let clock = Arc::new(ManualClock::new(tpe(2026, 11, 10, 12, 0)));
    let s = sched(json!({ "jobs": { "j": { "at": "04:10", "catchUp": false } } }), None, &clock);
    let fail = Arc::new(AtomicBool::new(true));
    let f = fail.clone();
    s.register("j", move |_ctx: JobCtx| {
        let f = f.clone();
        async move {
            if f.load(Ordering::SeqCst) {
                anyhow::bail!("測試失敗")
            }
            Ok(())
        }
    });
    let h = s.start();
    for n in 1..=3u32 {
        assert_eq!(s.request("j", "測試")["ok"], true);
        idle(&s).await;
        assert_eq!(s.status()["state"]["j"]["failStreak"], n);
        let fr = s.freshness(&["j"]);
        assert_eq!(fr[0].1.fails, n);
        assert!(fr[0].1.failing);
        assert_eq!(fr[0].1.last_ok, None, "從來沒成功過");
    }
    fail.store(false, Ordering::SeqCst);
    assert_eq!(s.request("j", "測試")["ok"], true);
    idle(&s).await;
    let st = s.status()["state"]["j"].clone();
    assert!(st.get("failStreak").is_none(), "成功就拿掉：{st}");
    let fr = s.freshness(&["j"]);
    assert_eq!((fr[0].1.fails, fr[0].1.failing), (0, false));
    assert!(fr[0].1.last_ok.is_some());
    assert_eq!(fr[0].1.period, Some(DAY_MS), "每天一次");
    assert_eq!(fr[0].1.next, Some(tpe(2026, 11, 11, 4, 10)));
    h.abort();
    // 飽和
    let saved = serde_json::to_vec(&json!({ "j": { "lastCode": 1, "failStreak": 9999 } })).unwrap();
    let s = sched(
        json!({ "jobs": { "j": { "at": "04:10", "catchUp": false } } }),
        Some(&saved),
        &clock,
    );
    s.register("j", |_ctx: JobCtx| async { anyhow::bail!("x") });
    let h = s.start();
    assert_eq!(s.request("j", "測試")["ok"], true);
    idle(&s).await;
    assert_eq!(s.status()["state"]["j"]["failStreak"], scheduler::FAIL_STREAK_MAX);
    h.abort();
}

/// 3.5.0 E1：舊的狀態檔沒有 failStreak：lastCode == 0 當 0，否則當 1；停用、沒註冊的不列
#[test]
fn old_state_without_streak_is_inferred() {
    assert_eq!(scheduler::fail_streak(&json!({ "lastCode": 0 })), 0);
    assert_eq!(scheduler::fail_streak(&json!({ "lastCode": 124 })), 1);
    assert_eq!(scheduler::fail_streak(&json!({})), 0);
    assert_eq!(scheduler::fail_streak(&json!({ "lastCode": 1, "failStreak": 5 })), 5);
    let clock = Arc::new(ManualClock::new(tpe(2026, 11, 10, 12, 0)));
    let now = tpe(2026, 11, 10, 12, 0);
    let saved = serde_json::to_vec(&json!({
        "a": { "lastCode": 1, "lastEnd": now - HOUR_MS, "lastOkEnd": now - 3 * DAY_MS },
        "b": { "lastCode": 0, "lastEnd": now - HOUR_MS },
    }))
    .unwrap();
    let s = sched(
        json!({ "jobs": { "a": { "at": "04:10" }, "b": { "at": "03:00", "weekdays": [0] }, "off": { "at": "04:10", "enabled": false }, "unreg": { "at": "04:10" } } }),
        Some(&saved),
        &clock,
    );
    for n in ["a", "b", "off"] {
        s.register(n, noop);
    }
    let fr = s.freshness(&["b", "a", "off", "unreg"]);
    let names: Vec<&str> = fr.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, vec!["b", "a"], "照呼叫的順序；停用、沒註冊的不列");
    let a = &fr[1].1;
    assert_eq!((a.failing, a.fails, a.last_ok), (true, 1, Some(now - 3 * DAY_MS)));
    let b = &fr[0].1;
    assert_eq!((b.failing, b.fails, b.last_ok), (false, 0, Some(now - HOUR_MS)), "舊版只有 lastEnd");
    assert_eq!(b.period, Some(7 * DAY_MS));
}
