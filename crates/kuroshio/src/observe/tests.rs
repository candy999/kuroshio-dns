//! 觀測（E1、E2、E10）的單元測試：都是純函式＋注入的時間，不連網路

use super::*;
use kuroshio_jobs::geo::{Dual, Group};

const DAY: u64 = 86_400_000;
/// 2026-11-23 左右（毫秒）
const NOW: u64 = 1_795_400_000_000;

fn job(last_ok: Option<u64>, failing: bool, fails: u32, period: u64) -> JobFreshness {
    JobFreshness {
        last_ok,
        failing,
        fails,
        next: Some(NOW + 3_600_000),
        period: Some(period),
        provided: false,
    }
}

fn keys(items: &[FreshItem]) -> Vec<&str> {
    items.iter().map(|i| i.key).collect()
}

// ---------------- E1 ----------------

#[test]
fn freshness_marks_chain_provided_jobs() {
    let inp = FreshInputs {
        jobs: vec![
            ("dns-benchmark".into(), job(Some(NOW - 9 * DAY), true, 4, DAY)),
            ("cdn-pool".into(), job(Some(NOW - 2 * DAY), false, 0, DAY)),
        ],
        chain_jobs: vec!["dns-benchmark".into()],
        chain_imported: [("upstreams".to_string(), NOW - 3_600_000)].into_iter().collect(),
        ..FreshInputs::default()
    };
    let items = fresh_items(&inp);
    let b = &items[0];
    assert_eq!(
        (b.key, b.chain, b.failing, b.fails),
        ("benchmark", true, false, 0),
        "上游提供的不算失敗"
    );
    assert_eq!(b.last_ok, Some(NOW - 3_600_000), "取自己跑完與從上游匯入比較新的");
    let v = b.json(NOW);
    assert_eq!(v["source"], "chain");
    assert_eq!(v["stale"], false);
    let p = &items[1];
    assert_eq!(p.json(NOW)["source"], "own");
}

#[test]
fn freshness_stale_after_two_periods() {
    let mut it = job_item("cdn-pool", "節點池", &job(Some(NOW - 2 * DAY), false, 0, DAY), false, None);
    assert!(!it.stale(NOW), "剛好 2 倍不算");
    assert!(it.stale(NOW + 1));
    it.last_ok = Some(NOW - DAY);
    assert!(!it.stale(NOW));
    // 時鐘倒退（上次成功在未來）不算過期
    it.last_ok = Some(NOW + DAY);
    assert!(!it.stale(NOW));
}

#[test]
fn never_ran_is_pending_not_stale() {
    let it = job_item("tw-ip", "台灣 IP 資料", &job(None, false, 0, 30 * DAY), false, None);
    let v = it.json(NOW);
    assert_eq!(v["lastOkAt"], Value::Null);
    assert_eq!(v["stale"], false);
    assert_eq!(v["pending"], true);
    // 失敗中、而且從沒成功過：failing 與 pending 都是 true，fails 至少 1
    let it = job_item("tw-ip", "台灣 IP 資料", &job(None, true, 0, 30 * DAY), false, None);
    assert_eq!((it.failing, it.fails, it.json(NOW)["pending"].clone()), (true, 1, json!(true)));
}

#[test]
fn freshness_omits_disabled_features() {
    // CDN 關（沒有 cdn-* 工作）、沒有好友、沒有串接、路徑檢查關
    let inp = FreshInputs {
        jobs: vec![("dns-benchmark".into(), job(Some(NOW), false, 0, DAY))],
        filter: Some((Some(NOW), 0, DAY)),
        ..FreshInputs::default()
    };
    assert_eq!(keys(&fresh_items(&inp)), vec!["benchmark", "filter-lists"]);
    // 全部都有：固定順序
    let all = FreshInputs {
        jobs: ["tw-ip", "cdn-pool", "cdn-scan", "cdn-ranges", "dns-benchmark", "unknown-job"]
            .iter()
            .map(|n| (n.to_string(), job(Some(NOW), false, 0, DAY)))
            .collect(),
        tw_ip_generated: Some("2026-11-01T00:00:00Z".into()),
        filter: Some((Some(NOW), 2, DAY)),
        path_checked: Some(0),
        chain_sync: Some((Some(NOW), Some(NOW + 1), Some("timeout".into()))),
        friends: Some(kuroshio_community::admin::SyncSummary {
            friends: 3,
            oldest_ok: Some(NOW - 7_200_000),
            failing: 1,
            max_fails: 4,
            failing3: 1,
            next_try: Some(NOW + 60_000),
            interval_ms: 3_600_000,
        }),
        ..FreshInputs::default()
    };
    let items = fresh_items(&all);
    assert_eq!(
        keys(&items),
        vec![
            "benchmark",
            "cdn-ranges",
            "cdn-scan",
            "cdn-pool",
            "tw-ip",
            "filter-lists",
            "path-check",
            "chain-sync",
            "friends-sync"
        ]
    );
    let tw = &items[4];
    assert_eq!(tw.note.as_deref(), Some("資料產生於 2026-11-01"));
    let f = &items[5];
    assert_eq!((f.failing, f.failing_items), (true, Some(2)));
    let p = items[6].json(NOW);
    assert_eq!(
        (p["pending"].clone(), p["stale"].clone()),
        (json!(true), json!(false)),
        "路徑檢查還沒做過"
    );
    let c = &items[7];
    assert!(c.failing && c.chain);
    let fr = items[8].json(NOW);
    assert_eq!(fr["failingItems"], 1);
    assert_eq!(fr["fails"], 4);
    assert_eq!(fr["nextAt"], NOW + 60_000);
    assert_eq!(fr["stale"], false, "2 小時 = 剛好 2 倍");
}

#[test]
fn freshness_capped_at_16() {
    let inp = FreshInputs {
        jobs: (0..40)
            .map(|i| (format!("dns-benchmark{i}"), job(Some(NOW), false, 0, DAY)))
            .collect(),
        ..FreshInputs::default()
    };
    assert!(fresh_items(&inp).is_empty(), "不認得的工作不列");
    // 每一種最多一項，加起來 9 項，不超過 16
    assert!(JOBS.len() + 4 <= FRESH_MAX);
}

// ---------------- E2 ----------------

fn st(key: &'static str, sev: Sev, on: bool) -> Obs {
    Obs::State {
        key,
        sev,
        on,
        text: format!("{key} 測試"),
        hold_ms: 0,
    }
}

fn ev(key: &'static str, counter: u32, at: u64) -> Obs {
    Obs::Event {
        key,
        sev: Sev::Info,
        counter,
        at,
        text: format!("{key} 事件"),
        min_count: 0,
    }
}

fn find<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    v.as_array().unwrap().iter().find(|f| f["key"] == key)
}

#[test]
fn finding_dedup_by_key_and_counts_rising_edges() {
    let mut e = Engine::new();
    e.apply(&[st("upstream-failing", Sev::Warn, true)], NOW);
    e.apply(&[st("upstream-failing", Sev::Warn, true)], NOW + 60_000);
    let v = e.json();
    assert_eq!(v.as_array().unwrap().len(), 1, "同一個 key 只有一筆");
    let f = find(&v, "upstream-failing").unwrap();
    assert_eq!(
        (f["count"].clone(), f["firstAt"].clone(), f["lastAt"].clone()),
        (json!(1), json!(NOW), json!(NOW + 60_000))
    );
    // 不成立 → 成立：次數加 1；不成立時 active = false 但還在
    e.apply(&[st("upstream-failing", Sev::Warn, false)], NOW + 120_000);
    assert_eq!(find(&e.json(), "upstream-failing").unwrap()["active"], false);
    e.apply(&[st("upstream-failing", Sev::Warn, true)], NOW + 180_000);
    let v = e.json();
    let f = find(&v, "upstream-failing").unwrap();
    assert_eq!(
        (f["count"].clone(), f["active"].clone(), f["firstAt"].clone()),
        (json!(2), json!(true), json!(NOW))
    );
}

#[test]
fn event_finding_uses_source_counter_delta() {
    let mut e = Engine::new();
    // 啟動後第一次看到：計數 3 都算
    e.apply(&[ev("pop-switched", 3, NOW - 5_000)], NOW);
    let f = find(&e.json(), "pop-switched").unwrap().clone();
    assert_eq!(
        (f["count"].clone(), f["lastAt"].clone(), f["firstAt"].clone()),
        (json!(3), json!(NOW - 5_000), json!(NOW))
    );
    // 沒人看的幾個小時裡又發生 2 次：用增加量、最近時間用來源給的
    e.apply(&[ev("pop-switched", 5, NOW + 3 * 3_600_000)], NOW + 5 * 3_600_000);
    let f = find(&e.json(), "pop-switched").unwrap().clone();
    assert_eq!((f["count"].clone(), f["lastAt"].clone()), (json!(5), json!(NOW + 3 * 3_600_000)));
    assert_eq!(f["active"], false, "最近一次超過 1 小時：不 active");
    // 計數沒變：次數不變
    e.apply(&[ev("pop-switched", 5, NOW + 3 * 3_600_000)], NOW + 5 * 3_600_000 + 60_000);
    assert_eq!(find(&e.json(), "pop-switched").unwrap()["count"], 5);
    // 來源重建（計數變小）：從 0 算
    e.apply(&[ev("pop-switched", 1, 0)], NOW + 6 * 3_600_000);
    let f = find(&e.json(), "pop-switched").unwrap().clone();
    assert_eq!(
        (f["count"].clone(), f["lastAt"].clone(), f["active"].clone()),
        (json!(6), json!(NOW + 6 * 3_600_000), json!(true))
    );
    // 計數一直是 0：不出現
    let mut e = Engine::new();
    e.apply(&[ev("slower-fallback", 0, 0)], NOW);
    assert_eq!(e.json(), json!([]));
    // min_count：累計到 2 次才顯示
    let mut e = Engine::new();
    let mm = |n| Obs::Event {
        key: "pop-mismatch",
        sev: Sev::Warn,
        counter: n,
        at: 0,
        text: "x".into(),
        min_count: 2,
    };
    e.apply(&[mm(1)], NOW);
    assert_eq!(e.json(), json!([]));
    e.apply(&[mm(2)], NOW + 1);
    assert_eq!(find(&e.json(), "pop-mismatch").unwrap()["count"], 2);
}

#[test]
fn finding_expires_warn_24h_info_6h() {
    let mut e = Engine::new();
    e.apply(
        &[st("upstream-failing", Sev::Warn, true), st("list-copy-no-room", Sev::Info, true)],
        NOW,
    );
    let off = [st("upstream-failing", Sev::Warn, false), st("list-copy-no-room", Sev::Info, false)];
    e.apply(&off, NOW + 6 * 3_600_000);
    assert_eq!(e.json().as_array().unwrap().len(), 2, "剛好 6 小時還在");
    e.apply(&off, NOW + 6 * 3_600_000 + 1);
    let v = e.json();
    assert!(find(&v, "list-copy-no-room").is_none(), "info 6 小時沒再發生就拿掉");
    assert!(find(&v, "upstream-failing").is_some());
    e.apply(&off, NOW + 24 * 3_600_000 + 1);
    assert_eq!(e.json(), json!([]), "warn 24 小時");
    // 還成立的不會過期
    let mut e = Engine::new();
    for h in 0..30 {
        e.apply(&[st("upstream-all-down", Sev::Warn, true)], NOW + h * 3_600_000);
    }
    assert_eq!(find(&e.json(), "upstream-all-down").unwrap()["count"], 1);
}

#[test]
fn findings_capped_at_32_drops_inactive_info_first() {
    const KEYS: [&str; 40] = [
        "k00", "k01", "k02", "k03", "k04", "k05", "k06", "k07", "k08", "k09", "k10", "k11", "k12", "k13", "k14", "k15", "k16", "k17",
        "k18", "k19", "k20", "k21", "k22", "k23", "k24", "k25", "k26", "k27", "k28", "k29", "k30", "k31", "k32", "k33", "k34", "k35",
        "k36", "k37", "k38", "k39",
    ];
    let mut e = Engine::new();
    // 31 筆 active 的 warn、1 筆不 active 的 info（最新的）
    for (i, k) in KEYS.iter().take(31).enumerate() {
        e.apply(&[st(k, Sev::Warn, true)], NOW + i as u64);
    }
    e.apply(&[st("info-off", Sev::Info, true)], NOW + 100);
    e.apply(&[st("info-off", Sev::Info, false)], NOW + 101);
    assert_eq!(e.json().as_array().unwrap().len(), 32);
    // 再放一筆：丟的是不 active 的 info，不是最舊的 warn
    e.apply(&[st("k31", Sev::Warn, true)], NOW + 200);
    let v = e.json();
    assert_eq!(v.as_array().unwrap().len(), 32);
    assert!(find(&v, "info-off").is_none());
    assert!(find(&v, "k00").is_some());
    // 再放：沒有不 active 的 info，丟 lastAt 最舊的
    e.apply(&[st("k32", Sev::Warn, true)], NOW + 300);
    let v = e.json();
    assert_eq!(v.as_array().unwrap().len(), FINDINGS_MAX);
    assert!(find(&v, "k00").is_none());
    assert!(find(&v, "k32").is_some());
    // 排序：warn 在前，同級新的在前
    let mut e = Engine::new();
    e.apply(&[st("a-info", Sev::Info, true)], NOW + 10);
    e.apply(&[st("b-warn", Sev::Warn, true)], NOW);
    e.apply(&[st("c-warn", Sev::Warn, true)], NOW + 5);
    let order: Vec<String> = e
        .json()
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["key"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(order, vec!["c-warn", "b-warn", "a-info"]);
}

#[test]
fn evaluation_at_most_every_30s() {
    let mut e = Engine::new();
    let mut n = 0;
    for i in 0..100u64 {
        e.evaluate(NOW + i * 100, |_| {
            n += 1;
            (vec![st("upstream-failing", Sev::Warn, true)], Sample::default())
        });
    }
    assert_eq!(n, 1, "連續讀 100 次（10 秒內）只評估一次");
    e.evaluate(NOW + EVAL_GAP_MS, |_| {
        n += 1;
        (vec![], Sample::default())
    });
    assert_eq!(n, 2);
}

#[test]
fn clock_unsynced_returns_empty() {
    let eng: Mutex<Option<Engine>> = Mutex::new(None);
    let mut read = false;
    let v = findings_guarded(&eng, false, NOW, || {
        read = true;
        FindInputs::default()
    });
    assert_eq!(v, json!([]));
    assert!(!read, "沒對時不讀狀態、不評估");
    assert!(eng.lock().unwrap().is_none());
    let inp = FindInputs {
        now: NOW,
        upstreams: vec![(true, false), (true, false)],
        ..FindInputs::default()
    };
    let v = findings_guarded(&eng, true, NOW, || inp);
    assert_eq!(find(&v, "upstream-all-down").unwrap()["sev"], "warn");
}

/// 所有會出現的規則都觸發一次的輸入；可以塞進網域與用戶端 IP 的欄位都塞
fn noisy_inputs() -> FindInputs {
    FindInputs {
        now: NOW,
        upstreams: vec![(true, false), (false, false), (true, true)],
        stale_15m: (40, 100),
        counters: kuroshio_cdn::ObserveCounters {
            verify_ok: 5,
            verify_fail: 30,
            pop_mismatch: 3,
            pop_mismatch_at: (NOW / 1000) as u32,
            pop_switches: 1,
            pop_switch_at: (NOW / 1000) as u32,
            pop_flapping: 1,
            pop_flapping_at: (NOW / 1000) as u32,
            slower_fallback: 4,
            slower_fallback_at: (NOW / 1000) as u32,
            slower_fuse_until: (NOW / 1000) as u32 + 3600,
            ..Default::default()
        },
        cdn_observe: json!({
            "reach": { "unconfirmed": 2, "v4": { "text": "www.example.com 192.0.2.7", "pops": [ { "pop": "TPE" } ] }, "v6": { "pops": [] } },
            "popSwitch": { "holds": [ { "provider": "cdn.example.net", "pop": "192.0.2.1", "family": 4, "until": NOW + 600_000, "other": "198.51.100.2" } ] },
        }),
        cdn_pruned: Some(12),
        chain: json!({ "state": "released", "reason": "tampered", "upstream": { "via": "intercept", "since": NOW - 3_600_000, "address": "192.168.1.1" },
                       "audit": { "releases": 1, "last": { "name": "www.example.com", "ip": "198.51.100.9" } } }),
        lists_without_copy: Some(2),
        fresh: vec![FreshItem {
            key: "benchmark",
            label: "每日評測",
            fails: 5,
            ..FreshItem::default()
        }],
        friends_failing3: 1,
        pool_nodes: 0,
    }
}

#[test]
fn finding_text_has_no_domain_or_client_ip() {
    let samples = [Sample {
        at: NOW - 2 * 3_600_000,
        verify_ok: 0,
        verify_fail: 0,
    }];
    let (obs, sample) = rules(&noisy_inputs(), &samples);
    assert_eq!((sample.verify_ok, sample.verify_fail), (5, 30));
    let mut e = Engine::new();
    e.apply(&obs, NOW);
    let v = e.json();
    let keys: Vec<&str> = v.as_array().unwrap().iter().map(|f| f["key"].as_str().unwrap()).collect();
    for k in [
        "upstream-failing",
        "serve-stale-high",
        "cdn-verify-fail-high",
        "chain-released-untrusted",
        "chain-audit-released",
        "list-copy-no-room",
        "cdn-db-pruning",
        "job-failing",
        "friends-sync-failing",
        "reach-single-pop",
        "pop-mismatch",
        "pop-switched",
        "pop-flapping",
        "slower-fallback",
        "slower-fuse",
    ] {
        assert!(keys.contains(&k), "{k} 沒出現：{keys:?}");
    }
    assert!(!keys.contains(&"upstream-all-down"), "benched 的不算，還有一個正常的");
    assert!(!keys.contains(&"chain-intercepted"), "沒有串接中");
    for f in v.as_array().unwrap() {
        let t = f["text"].as_str().unwrap();
        assert!(t.chars().count() <= TEXT_MAX);
        for bad in ["example", "192.0.2", "198.51.100", "192.168", "2001:db8"] {
            assert!(!t.contains(bad), "{}: {t}", f["key"]);
        }
    }
    let sw = find(&v, "pop-switched").unwrap()["text"].as_str().unwrap().to_string();
    assert!(!sw.contains("cdn.example.net"), "看起來像網域的 CDN 名稱不放：{sw}");
    assert_eq!(find(&v, "reach-single-pop").unwrap()["text"], "這條線目前只到得了台北機房");
    // 名稱、句子檢查
    assert_eq!(safe_name("cloudflare"), Some("cloudflare"));
    assert_eq!(safe_name("cdn.example.com"), None);
    assert_eq!(safe_pop("TPE"), Some("TPE"));
    assert_eq!(safe_pop("192.0.2.1"), None);
}

#[test]
fn rules_quiet_when_everything_is_fine() {
    let inp = FindInputs {
        now: NOW,
        upstreams: vec![(false, false), (true, true)],
        stale_15m: (2, 1000),
        cdn_observe: json!({ "reach": { "v4": { "pops": [ { "pop": "TPE" }, { "pop": "KHH" } ] }, "v6": { "pops": [] } } }),
        chain: json!({ "state": "chained", "upstream": { "via": "gateway", "since": NOW - 3_600_000 } }),
        lists_without_copy: Some(0),
        ..FindInputs::default()
    };
    let (obs, _) = rules(&inp, &[]);
    let mut e = Engine::new();
    e.apply(&obs, NOW);
    assert_eq!(e.json(), json!([]), "到得了兩個機房、上游正常、沒有串接問題");
    // 過期快取：查詢不到 50 筆不判斷
    let inp = FindInputs {
        now: NOW,
        stale_15m: (20, 40),
        ..FindInputs::default()
    };
    let (obs, _) = rules(&inp, &[]);
    assert!(obs.iter().all(|o| !matches!(
        o,
        Obs::State {
            key: "serve-stale-high",
            on: true,
            ..
        }
    )));
    // 串接經攔截超過 10 分鐘
    let inp = FindInputs {
        now: NOW,
        chain: json!({ "state": "chained", "upstream": { "via": "intercept", "since": NOW - 11 * 60_000 } }),
        ..FindInputs::default()
    };
    let (obs, _) = rules(&inp, &[]);
    assert!(obs.iter().any(|o| matches!(
        o,
        Obs::State {
            key: "chain-intercepted",
            on: true,
            ..
        }
    )));
}

#[test]
fn reach_none_needs_an_hour() {
    let inp = |now| FindInputs {
        now,
        cdn_observe: json!({ "reach": { "unconfirmed": 0, "v4": { "pops": [] }, "v6": { "pops": [] } } }),
        pool_nodes: 8,
        ..FindInputs::default()
    };
    let mut e = Engine::new();
    let (obs, _) = rules(&inp(NOW), &[]);
    e.apply(&obs, NOW);
    assert!(find(&e.json(), "reach-none").is_none());
    let (obs, _) = rules(&inp(NOW + 3_600_000), &[]);
    e.apply(&obs, NOW + 3_600_000);
    assert!(find(&e.json(), "reach-none").is_some(), "持續 1 小時");
    // WAN 剛變動、串接中（reach.stale）不算
    let mut stale = inp(NOW);
    stale.cdn_observe["reach"]["stale"] = json!(true);
    let (obs, _) = rules(&stale, &[]);
    assert!(obs.iter().any(|o| matches!(
        o,
        Obs::State {
            key: "reach-none",
            on: false,
            ..
        }
    )));
}

#[test]
fn pop_switched_text_reads_holds() {
    let mut inp = FindInputs {
        now: NOW,
        ..FindInputs::default()
    };
    inp.counters.pop_switches = 1;
    inp.counters.pop_switch_at = (NOW / 1000) as u32;
    inp.cdn_observe = json!({ "popSwitch": { "holds": [ { "provider": "cloudflare", "family": 4, "pop": "KHH", "until": NOW + 3_600_000, "other": "TPE" } ] } });
    let (obs, _) = rules(&inp, &[]);
    let t = obs
        .iter()
        .find_map(|o| match o {
            Obs::Event {
                key: "pop-switched", text, ..
            } => Some(text.clone()),
            _ => None,
        })
        .unwrap();
    assert!(
        t.starts_with("機房切換：cloudflare 的 IPv4 把 KHH 機房的節點暫時排到後面（到 "),
        "{t}"
    );
}

#[test]
fn verify_fail_uses_last_hour_samples() {
    let mut inp = FindInputs {
        now: NOW,
        ..FindInputs::default()
    };
    inp.counters.verify_ok = 100;
    inp.counters.verify_fail = 130;
    // 一小時前的取樣：ok 90、fail 100 → 最近一小時 10 ok、30 fail
    let samples = [
        Sample {
            at: NOW - 2 * 3_600_000,
            verify_ok: 0,
            verify_fail: 0,
        },
        Sample {
            at: NOW - 3_600_000,
            verify_ok: 90,
            verify_fail: 100,
        },
        Sample {
            at: NOW - 600_000,
            verify_ok: 99,
            verify_fail: 129,
        },
    ];
    let (obs, _) = rules(&inp, &samples);
    let hit = obs.iter().find_map(|o| match o {
        Obs::State {
            key: "cdn-verify-fail-high",
            on,
            text,
            ..
        } => Some((*on, text.clone())),
        _ => None,
    });
    assert_eq!(hit, Some((true, "最近一小時台灣節點驗證有 30／40 次失敗".to_string())));
    // 取樣至少間隔 5 分鐘、最多 14 筆
    let mut e = Engine::new();
    for i in 0..100u64 {
        e.note_sample(Sample {
            at: NOW + i * 60_000,
            ..Sample::default()
        });
    }
    assert_eq!(e.samples.len(), SAMPLES_MAX);
    assert!(e.samples.windows(2).all(|w| w[1].at - w[0].at >= SAMPLE_GAP_MS));
}

// ---------------- E10 ----------------

fn tw() -> TwIp {
    let g = |id: &str, nets: &[&str]| Group {
        id: id.into(),
        name: id.into(),
        note: String::new(),
        asns: vec![],
        nets: Dual::parse(nets.iter().copied()).0,
    };
    TwIp {
        generated_at: "2026-11-01T00:00:00Z".into(),
        groups: vec![
            g("cht", &["192.0.2.0/24"]),
            g("other", &["198.51.100.0/24"]),
            g("Bad.Id", &["203.0.113.0/24"]),
        ],
    }
}

#[test]
fn isp_group_from_wan_subnet() {
    let t = tw();
    let net = |s: &str| Some((s.parse::<IpAddr>().unwrap(), 24u8));
    assert_eq!(isp_group_of(net("192.0.2.0"), Some(&t)).as_deref(), Some("cht"));
    assert_eq!(isp_group_of(net("198.51.100.0"), Some(&t)), None, "落在 other 不帶");
    assert_eq!(isp_group_of(net("100.64.0.0"), Some(&t)), None, "不在台灣（國外、VPN）");
    assert_eq!(isp_group_of(None, Some(&t)), None, "沒有偵測到對外 IP");
    assert_eq!(isp_group_of(net("192.0.2.0"), None), None, "台灣 IP 資料讀不到");
    assert_eq!(isp_group_of(net("203.0.113.0"), Some(&t)), None, "群組 id 格式不對");
    // 來源更新時重算
    set_isp_sources(net("192.0.2.0"), Some(Arc::new(t)));
    assert_eq!(isp_group().as_deref(), Some("cht"));
    set_isp_tw_ip(None);
    assert_eq!(isp_group(), None);
    set_isp_sources(None, None);
}

#[test]
fn invalid_isp_string_dropped() {
    assert!(valid_isp("cht"));
    assert!(valid_isp("so-net_2"));
    assert!(!valid_isp(""));
    assert!(!valid_isp("CHT"), "大寫");
    assert!(!valid_isp("abcdefghijklmnopq"), "太長");
    assert!(!valid_isp("a.example"));
    assert!(!valid_isp("台灣"));
}
