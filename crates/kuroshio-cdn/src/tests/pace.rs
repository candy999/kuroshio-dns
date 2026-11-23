//! 新網域很多時的 CDN 驗證節流（3.5.0，規格 11 F12）：`Cdn` 這一層（名額的順序、減量中拿掉的工作、開關、計數）。
//! 速率怎麼依 CPU 調、怎麼進出減量中的時間序列在 `pace.rs` 的單元測試（注入時間與 CPU 讀數）

use super::selftest::setup;
use super::*;
use crate::config::CdnConfig;
use crate::Task;
use kuroshio_config::{build_for, Host};

fn count(c: &Cdn) -> (usize, usize, usize, usize) {
    let t = c.take_tasks();
    let n = |f: fn(&Task) -> bool| t.iter().filter(|x| f(x)).count();
    (
        n(|t| matches!(t, Task::Verify { .. })),
        n(|t| matches!(t, Task::Ecs { .. })),
        n(|t| matches!(t, Task::Cross { .. })),
        n(|t| matches!(t, Task::Latency(_))),
    )
}

/// Cloudflare（要驗證）、Fastly（沒有延遲 → 量延遲；原本慢 → 跨 CDN 探索）、Akamai（ECS 突破）各一個新網域
fn queries(c: &Arc<Cdn>, net: &MockNet, tag: &str) {
    let cf = format!("cf-{tag}.example.com");
    let mut m = msg(&cf, 1, &["104.21.0.5"], vec![]);
    c.apply(&mut m, &cf, 1);
    let fl = format!("fl-{tag}.example.com");
    let mut m = msg(&fl, 1, &["151.101.1.140"], vec![]);
    c.apply(&mut m, &fl, 1);
    net.set_cached("151.101.1.141", 80.0);
    let fx = format!("fx-{tag}.example.com");
    let mut m = msg(&fx, 1, &["151.101.1.141"], vec![]);
    c.apply(&mut m, &fx, 1);
    let ak = format!("ak-{tag}.example.com");
    let mut m = msg(&ak, 1, &["192.0.2.80"], vec![cname(&ak, "e1.a.akamaiedge.net", 60)]);
    c.apply(&mut m, &ak, 1);
}

fn pace(c: &Cdn) -> Value {
    c.pace_json()
}

#[test]
fn pace_rmax_by_cores_aes_and_lite() {
    let rmax = |h: Host, over: Value| crate::cdn::pace_rmax(&CdnConfig::from_value(&build_for(&h, &json!({ "cdn": over }))));
    assert_eq!(rmax(Host { cores: 2, aes: false }, json!({})), 60, "MT7621");
    assert_eq!(rmax(Host { cores: 16, aes: true }, json!({})), 480);
    assert_eq!(rmax(Host { cores: 2, aes: false }, json!({ "lite": true })), 30);
    assert_eq!(
        rmax(Host { cores: 2, aes: false }, json!({ "lite": true, "verifyPerMin": 10 })),
        10,
        "填更小的照填的"
    );
    assert_eq!(
        rmax(
            Host { cores: 2, aes: false },
            json!({ "lite": true, "verifyPacing": false, "verifyPerMin": 10 })
        ),
        30,
        "關掉節流＝3.4.2 的 30"
    );
    assert_eq!(rmax(Host { cores: 4, aes: true }, json!({ "verifyPerMin": 100 })), 100);
    let (c, _) = setup(json!({}));
    let p = pace(&c);
    assert_eq!(
        (p["enabled"].clone(), p["maxPerMin"].clone(), p["minPerMin"].clone()),
        (json!(true), json!(60), json!(7))
    );
    assert_eq!(p["paced"], false);
    assert!(c.status_lite()["pace"].is_object() && c.status_lite()["bg"]["verify"]["started"] == 0);
}

#[test]
fn paced_skips_first_seen_domains_and_their_ecs_latency_cross() {
    // 不是減量中：照排
    let (c, net) = setup(json!({}));
    queries(&c, &net, "a");
    assert_eq!(count(&c), (1, 1, 1, 1));
    assert_eq!(pace(&c)["waited"], 0);
    // CPU 很忙 → 減量中：只問過一次的網域，驗證、ECS、跨 CDN、延遲量測都不排；答案照舊是原本的
    let (c, net) = setup(json!({}));
    c.set_load(Some(90));
    assert_eq!(pace(&c)["paced"], true);
    queries(&c, &net, "b");
    assert_eq!(count(&c), (0, 0, 0, 0));
    assert_eq!(pace(&c)["waited"], 4);
    let mut m = msg("cf-c.example.com", 1, &["104.21.0.5"], vec![]);
    let r = c.apply(&mut m, "cf-c.example.com", 1);
    assert_eq!(answer_ips(&m, 1), ["104.21.0.5"]);
    assert_eq!(r.ttl_cap, Some(10), "試用期 TTL 10 秒：真的有人用會很快再問");
    assert_eq!(c.stats().lite_waited, 0, "lite 的計數只算 cdn.lite");
}

#[test]
fn paced_still_verifies_domains_seen_twice() {
    let (c, net) = setup(json!({}));
    c.set_load(Some(90));
    queries(&c, &net, "a");
    c.take_tasks();
    queries(&c, &net, "a");
    let (v, e, x, _) = count(&c);
    assert_eq!((v, e, x), (1, 1, 1), "問過 2 次：照樣驗證、ECS、跨 CDN");
}

#[test]
fn first_seen_use_at_most_half_the_tokens() {
    let (c, _) = setup(json!({ "verifyPerMin": 20 }));
    let mut got = 0;
    for i in 0..25 {
        let n = format!("n{i}.example.com");
        let mut m = msg(&n, 1, &["104.21.0.5"], vec![]);
        c.apply(&mut m, &n, 1);
        got += count(&c).0;
    }
    // 分鐘剛好換過時會多一輪
    assert!((10..=20).contains(&got), "{got}");
    let p = pace(&c);
    assert_eq!(p["paced"], true, "排不進：進入減量中");
    assert!(p["capped"].as_u64().unwrap() >= 1);
    // 留下的一半給問過 2 次以上的
    let mut m = msg("n0.example.com", 1, &["104.21.0.5"], vec![]);
    c.apply(&mut m, "n0.example.com", 1);
    assert_eq!(count(&c).0, 1);
}

#[test]
fn reverify_and_e7_retest_share_the_budget() {
    let (c, _) = setup(json!({ "verifyPerMin": 10 }));
    // 到期重驗、F9 的確認走同一個 schedule()（第 2 類）
    for i in 0..10 {
        c.schedule(Task::Verify {
            name: format!("r{i}.example.com"),
            provider: "cloudflare".into(),
            family: 4,
            orig: None,
        });
    }
    let used = pace(&c)["usedThisMin"].as_u64().unwrap();
    assert!(used >= 1);
    for _ in 0..2 {
        let mut m = msg("seen.example.com", 1, &["104.21.0.5"], vec![]);
        c.apply(&mut m, "seen.example.com", 1);
    }
    let got = count(&c).0;
    if used == 10 {
        assert_eq!(got, 10, "名額用完：問過 2 次的這一次也不排");
        assert!(pace(&c)["capped"].as_u64().unwrap() >= 1);
    }
}

#[tokio::test]
async fn manual_verify_bypasses_but_counts() {
    let (c, _) = setup(json!({ "verifyPerMin": 6 }));
    let mut m = msg("man.example.com", 1, &["104.21.0.5"], vec![]);
    c.apply(&mut m, "man.example.com", 1);
    c.with_pace(|p| while p.take(crate::pace::Cat::Regular, crate::util::now_ms()).0 {});
    let before = pace(&c)["usedThisMin"].as_u64().unwrap();
    let (r, _) = c.verify_now("man.example.com", 4).await.unwrap();
    assert!(r.is_some(), "名額用完照樣驗證");
    let after = pace(&c)["usedThisMin"].as_u64().unwrap();
    assert!(after == before + 1 || after == 1, "算進用量（{before} → {after}）");
}

#[test]
fn no_backlog_after_load_stops() {
    let (c, _) = setup(json!({ "verifyPerMin": 10 }));
    for i in 0..100 {
        let n = format!("b{i}.example.com");
        for _ in 0..2 {
            let mut m = msg(&n, 1, &["104.21.0.5"], vec![]);
            c.apply(&mut m, &n, 1);
        }
    }
    c.take_tasks();
    // 負載停了：沒有新的查詢就沒有新的驗證（排不進的沒有記下來）
    for _ in 0..5 {
        c.set_load(Some(1));
    }
    assert_eq!(count(&c), (0, 0, 0, 0));
}

#[test]
fn pacing_off_matches_previous_behaviour() {
    let (c, net) = setup(json!({ "verifyPacing": false, "verifyPerMin": 6 }));
    c.set_load(Some(99));
    queries(&c, &net, "a");
    assert_eq!(count(&c), (1, 1, 1, 1), "CPU 很忙也照排");
    let mut got = 0;
    for i in 0..100 {
        let n = format!("o{i}.example.com");
        let mut m = msg(&n, 1, &["104.21.0.5"], vec![]);
        c.apply(&mut m, &n, 1);
        got += count(&c).0;
    }
    assert_eq!(got, 100, "一般機器沒有每分鐘上限（3.4.x）");
    let p = pace(&c);
    assert_eq!(
        (p["enabled"].clone(), p["paced"].clone(), p["perMin"].clone()),
        (json!(false), json!(false), Value::Null)
    );
    assert_eq!(p["cpuPct"], 99, "讀數照樣顯示");
}

#[test]
fn lite_counters_unchanged() {
    for pacing in [true, false] {
        let (c, net) = setup(json!({ "lite": true, "verifyPacing": pacing }));
        let mut m = msg("once.example.com", 1, &["104.21.0.5"], vec![]);
        c.apply(&mut m, "once.example.com", 1);
        assert_eq!(count(&c).0, 0);
        assert_eq!(c.stats().lite_waited, 1);
        let mut m = msg("once.example.com", 1, &["104.21.0.5"], vec![]);
        c.apply(&mut m, "once.example.com", 1);
        assert_eq!(count(&c).0, 1);
        let mut got = 0;
        for i in 0..40 {
            let n = format!("l{i}.example.com");
            for _ in 0..2 {
                let mut m = msg(&n, 1, &["104.21.0.5"], vec![]);
                c.apply(&mut m, &n, 1);
            }
            got += count(&c).0;
        }
        assert!((29..=40).contains(&got), "每分鐘 30 個（pacing {pacing}）：{got}");
        assert!(c.stats().lite_capped >= 1);
        assert_eq!(c.stats().lite_waited, 41);
        // cdn.lite 永遠在減量：開著節流時，只問過一次的網域的 ECS／延遲量測／跨 CDN 也不排；關著時照 3.4.2
        queries(&c, &net, "x");
        let (_, e, x, l) = count(&c);
        if pacing {
            assert_eq!((e, x, l), (0, 0, 0));
            assert_eq!(pace(&c)["paced"], true);
        } else {
            assert_eq!((e, x, l), (1, 1, 1));
        }
    }
}

#[test]
fn explain_reports_paced_waiting() {
    let (c, _) = setup(json!({}));
    c.set_load(Some(90));
    let mut m = msg("pw.example.com", 1, &["104.21.0.5"], vec![]);
    c.apply(&mut m, "pw.example.com", 1);
    let v = c.explain("pw.example.com", crate::explain::Context::default());
    assert_eq!(v["decision"], "paced-waiting", "{v}");
}
