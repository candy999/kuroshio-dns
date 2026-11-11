//! 需要網路的行為（驗證、ECS、健檢、IPv6 發現）用假的網路測；另外測尖峰加權、ECS 網段順序、基準統計

use super::selftest::setup;
use super::*;
use crate::cdn::{CrossHint, HintIp, Hints, Task};
use crate::pools::{weighted_qscore, PoolNode};
use crate::util::{intern, now_ms, Num};
use kuroshio_net::iprank::Quality;
use kuroshio_proto::message::rtype;

fn cf_ok(colo: &str) -> ProbeResult {
    resp(
        200,
        &[("cf-ray", &format!("8a-{colo}")), ("server", "cloudflare")],
        "<html><title>Site</title></html>",
    )
}

#[tokio::test]
async fn verifier_ok_collects_all_passing_ips() {
    let (c, net) = setup(json!({}));
    c.with_state(|st| {
        st.db.touch("v.test", "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
    });
    net.on_https(|i, _| match i.to_string().as_str() {
        "104.21.0.5" => cf_ok("NRT"),
        "104.16.161.36" => cf_ok("TPE"),
        "104.18.20.216" => cf_ok("TPE"),
        _ => fail("ECONNREFUSED"),
    });
    let r = c.verify("v.test", "cloudflare", 4, Some(ip("104.21.0.5"))).await;
    assert_eq!(r, Some("ok"));
    let st = c.state();
    let e = st.db.get("v.test").unwrap();
    let v = e.v4.as_ref().unwrap();
    assert_eq!(v.ip, Some(ip("104.16.161.36")));
    assert_eq!(v.ips, Some(ips(&["104.16.161.36", "104.18.20.216"])));
    assert_eq!(v.pop.as_deref(), Some("TPE"));
    assert_eq!((v.algo, v.fails, v.tried), (Some(2), Some(0), Some(1)));
    let b = e.base.as_ref().unwrap();
    assert_eq!((b.pop.as_deref(), b.ok), (Some("NRT"), Some(true)), "基準記下原本的 POP");
    assert!(st.pools.zone_hit("cloudflare", ip("104.18.20.216")));
}

#[tokio::test]
async fn verifier_error_1034_then_fail_and_backoff() {
    let (c, net) = setup(json!({ "verifyFailHours": 6 }));
    c.with_state(|st| {
        st.db.touch("b.test", "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
    });
    // 原站正常；台灣節點都回 Error 1034 → 「這個 IP 不服務這個網站」，全部試完判定失敗
    net.on_https(|i, _| match i.to_string().as_str() {
        "104.21.0.5" => cf_ok("NRT"),
        _ => resp(403, &[("cf-ray", "x-TPE")], "error code: 1034"),
    });
    assert_eq!(c.verify("b.test", "cloudflare", 4, Some(ip("104.21.0.5"))).await, Some("fail"));
    let v = c.state().db.get("b.test").unwrap().v4.clone().unwrap();
    assert!(
        v.reason.as_deref().unwrap().contains("Cloudflare 錯誤 1034（試了 2 個網段）"),
        "{:?}",
        v.reason
    );
    let first_until = v.until.unwrap();
    assert!(first_until > now_ms() + 5 * 3_600_000 && first_until <= now_ms() + 6 * 3_600_000 + 1000);
    assert_eq!(v.fails, Some(1));
    // 第二次失敗：間隔加倍
    assert_eq!(c.verify("b.test", "cloudflare", 4, Some(ip("104.21.0.5"))).await, Some("fail"));
    let v = c.state().db.get("b.test").unwrap().v4.clone().unwrap();
    assert_eq!(v.fails, Some(2));
    assert!(v.until.unwrap() > now_ms() + 11 * 3_600_000);
    // 兩個節點各失敗兩次 → 特定產品專用 IP
    assert!(c.state().pools.is_restricted("cloudflare", ip("104.16.161.36")));
}

#[tokio::test]
async fn verifier_network_failure_is_unknown_and_marks_bad() {
    let (c, net) = setup(json!({}));
    c.with_state(|st| {
        st.db.touch("u.test", "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
    });
    net.on_https(|i, _| if i == ip("104.21.0.5") { cf_ok("NRT") } else { fail("ECONNRESET") });
    assert_eq!(c.verify("u.test", "cloudflare", 4, Some(ip("104.21.0.5"))).await, Some("unknown"));
    let st = c.state();
    let v = st.db.get("u.test").unwrap().v4.clone().unwrap();
    assert!(v.is("unknown"));
    assert_eq!(v.reason.as_deref(), Some("連線失敗 ECONNRESET"));
    assert!(
        st.pools.p["cloudflare"].bad.contains_key(&ip("104.16.161.36")),
        "原站可以連、台灣節點連不上 → 暫停"
    );
}

#[tokio::test]
async fn verifier_pop_drift_and_same_error() {
    let (c, net) = setup(json!({}));
    c.with_state(|st| {
        st.db.touch("d.test", "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
    });
    // 第一個節點漂移到香港、第二個跟原站一樣是 522（網站本身的問題）
    net.on_https(|i, _| match i.to_string().as_str() {
        "104.16.161.36" => cf_ok("HKG"),
        _ => resp(522, &[("cf-ray", "x-TPE")], ""),
    });
    assert_eq!(c.verify("d.test", "cloudflare", 4, Some(ip("104.21.0.5"))).await, Some("ok"));
    let st = c.state();
    assert!(st.pools.p["cloudflare"].bad[&ip("104.16.161.36")].reason.contains("HKG"));
    let v = st.db.get("d.test").unwrap().v4.clone().unwrap();
    assert_eq!(v.reason.as_deref(), Some("原站同樣錯誤"));
    assert_eq!(v.ip, Some(ip("104.18.20.216")));
}

#[tokio::test]
async fn verifier_http_only_site() {
    // 只開 HTTP 的網站（OCSP、軟體更新鏡像）：原站 HTTPS 失敗就改用 HTTP 驗證
    let (c, net) = setup(json!({}));
    c.with_state(|st| {
        st.db.touch("ocsp.test", "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
    });
    net.on_https(|_, _| fail("ECONNREFUSED"));
    net.on_http(|_, _| resp(200, &[("cf-ray", "x-TPE")], "ok"));
    assert_eq!(c.verify("ocsp.test", "cloudflare", 4, Some(ip("104.21.0.5"))).await, Some("ok"));
    assert_eq!(c.state().db.get("ocsp.test").unwrap().v4.as_ref().unwrap().http, Some(true));
}

struct TestHints {
    results: Mutex<Vec<(String, bool)>>,
}

impl Hints for TestHints {
    fn domain_hint(&self, _n: &str, _p: &str, _f: u8) -> Vec<HintIp> {
        vec![HintIp {
            ip: ip("104.16.99.1"),
            from: "friend".into(),
        }]
    }
    fn hint_result(&self, from: &str, ok: bool) {
        self.results.lock().unwrap().push((from.into(), ok));
    }
    fn cross_hint(&self, _n: &str) -> Option<CrossHint> {
        None
    }
}

#[tokio::test]
async fn verifier_tries_community_hints_first() {
    let (c, net) = setup(json!({}));
    let h = Arc::new(TestHints {
        results: Mutex::new(vec![]),
    });
    c.set_hints(Some(h.clone()));
    c.with_state(|st| {
        st.db.touch("h.test", "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
        // 好友給的 IP 不在我的節點池：驗證成功也不會拿來回給用戶端，但命中率照算
    });
    net.on_https(|_, _| cf_ok("TPE"));
    c.verify("h.test", "cloudflare", 4, Some(ip("104.21.0.5"))).await;
    assert!(net.calls("https 104.16.99.1").len() == 1);
    let https: Vec<String> = net.calls("https ");
    assert_eq!(https[1], "https 104.16.99.1 h.test", "原站之後先試好友的");
    assert_eq!(h.results.lock().unwrap().as_slice(), [("friend".to_string(), true)]);
}

/// 好友提示：可以指定多個 IP
struct ListHints {
    list: Vec<(&'static str, &'static str)>,
    results: Mutex<Vec<(String, bool)>>,
}

impl Hints for ListHints {
    fn domain_hint(&self, _n: &str, _p: &str, _f: u8) -> Vec<HintIp> {
        self.list
            .iter()
            .map(|(i, f)| HintIp {
                ip: ip(i),
                from: f.to_string(),
            })
            .collect()
    }
    fn hint_result(&self, from: &str, ok: bool) {
        self.results.lock().unwrap().push((from.into(), ok));
    }
    fn cross_hint(&self, _n: &str) -> Option<CrossHint> {
        None
    }
}

#[tokio::test]
async fn verifier_hint_outside_provider_range_is_never_probed() {
    // 好友給的 IP 不在這家 CDN 的官方範圍（可能是任何人的機器）：連試都不試、算沒命中
    let (c, net) = setup(json!({}));
    let h = Arc::new(ListHints {
        list: vec![("203.0.113.9", "bad"), ("2606:4700::1", "v6"), ("104.16.99.1", "good")],
        results: Mutex::new(vec![]),
    });
    c.set_hints(Some(h.clone()));
    c.with_state(|st| {
        st.db.touch("hr.test", "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
    });
    net.on_https(|_, _| cf_ok("TPE"));
    assert_eq!(c.verify("hr.test", "cloudflare", 4, Some(ip("104.21.0.5"))).await, Some("ok"));
    assert!(net.calls("https 203.0.113.9").is_empty(), "範圍外的不試");
    assert!(net.calls("https 2606:4700::1").is_empty(), "家族不符的不試");
    let mut r = h.results.lock().unwrap().clone();
    r.sort();
    assert_eq!(
        r,
        [("bad".to_string(), false), ("good".to_string(), true), ("v6".to_string(), false)]
    );
    // 判定裡只有自己節點池的 IP：好友的 IP 驗證通過也不回給用戶端
    let st = c.state();
    let v = st.db.get("hr.test").unwrap().v4.clone().unwrap();
    assert_eq!(v.ip, Some(ip("104.16.161.36")));
    assert_eq!(v.ips, Some(ips(&["104.16.161.36", "104.18.20.216"])));
}

#[tokio::test]
async fn verifier_hint_only_pass_is_not_ok() {
    // 只有好友的 IP 通過、自己節點池的都連不上：不能寫成「通過」（查詢時沒有 IP 可以回）
    let (c, net) = setup(json!({}));
    let h = Arc::new(ListHints {
        list: vec![("104.16.99.1", "friend")],
        results: Mutex::new(vec![]),
    });
    c.set_hints(Some(h.clone()));
    c.with_state(|st| {
        st.db.touch("ho.test", "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
    });
    net.on_https(|i, _| match i.to_string().as_str() {
        "104.21.0.5" => cf_ok("NRT"),
        "104.16.99.1" => cf_ok("TPE"),
        _ => fail("ECONNRESET"),
    });
    assert_eq!(c.verify("ho.test", "cloudflare", 4, Some(ip("104.21.0.5"))).await, Some("unknown"));
    assert_eq!(h.results.lock().unwrap().as_slice(), [("friend".to_string(), true)]);
    assert!(c.state().db.get("ho.test").unwrap().v4.as_ref().unwrap().is("unknown"));
}

#[tokio::test]
async fn verifier_http_only_requires_consistent_https() {
    // 原始節點的 HTTPS 只是一時連不上（ECONNRESET）、HTTP 可以用 → 改用 HTTP 驗證。
    // 候選節點 HTTP 也可以用，但 HTTPS 是「憑證不符」：跟原始節點不一樣，不能算通過
    // （否則用 HTTPS 的用戶端會被導到憑證沒驗證過的節點）
    let (c, net) = setup(json!({}));
    c.with_state(|st| {
        st.db.touch("mix.test", "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
    });
    net.on_https(|i, _| {
        if i == ip("104.21.0.5") {
            fail("ECONNRESET")
        } else {
            ProbeResult::failed("ERR_TLS_CERT_ALTNAME_INVALID", true)
        }
    });
    net.on_http(|_, _| resp(200, &[("cf-ray", "x-TPE")], "ok"));
    assert_eq!(c.verify("mix.test", "cloudflare", 4, Some(ip("104.21.0.5"))).await, Some("unknown"));
    let v = c.state().db.get("mix.test").unwrap().v4.clone().unwrap();
    assert!(!v.is("ok"));
    assert!(v.reason.as_deref().unwrap().contains("HTTPS"), "{:?}", v.reason);

    // 候選節點的 HTTPS 有效（憑證驗證過）：比原始節點還好，通過
    net.on_https(|i, _| if i == ip("104.21.0.5") { fail("ECONNRESET") } else { cf_ok("TPE") });
    assert_eq!(c.verify("mix.test", "cloudflare", 4, Some(ip("104.21.0.5"))).await, Some("ok"));
}

#[tokio::test]
async fn ecs_probe_finds_closer_node() {
    let (c, net) = setup(json!({ "ecs": { "twSubnets": ["168.95.0.0/24", "1.160.0.0/24"], "resolvers": ["udp://8.8.8.8"] } }));
    c.with_state(|st| {
        st.db
            .touch("www.ak.test", "akamai", "cname", &ips(&["23.1.1.1"]), &ips(&["2600::1"]), None);
    });
    net.on_dns(|_, name, qtype, ecs| {
        let sub = ecs.map(|e| e.0.to_string()).unwrap_or_default();
        let mut m = msg(name, qtype, &[], vec![]);
        if qtype == rtype::A {
            let a = if sub == "1.160.0.0" { "23.9.9.9" } else { "23.5.5.5" };
            m.answers.push(Record::a(name, 60, a.parse().unwrap()));
        } else {
            m.answers.push(Record::aaaa(name, 60, "2600:9::1".parse().unwrap()));
        }
        Some(m)
    });
    net.set_cached("23.1.1.1", 60.0);
    net.set_cached("23.5.5.5", 50.0);
    net.set_cached("23.9.9.9", 4.0);
    net.set_cached("2600:9::1", 5.0);
    net.on_https(|_, _| resp(200, &[], "ok"));
    c.ecs_probe("www.ak.test", &ips(&["23.1.1.1"]), &ips(&["2600::1"])).await;
    let e = c.state().db.get("www.ak.test").unwrap().ecs.clone().unwrap();
    assert!(e.is("ok"));
    assert_eq!(e.subnet.as_deref(), Some("1.160.0.0/24"));
    assert_eq!(e.ips4, Some(ips(&["23.9.9.9"])));
    assert_eq!(e.ips6, Some(ips(&["2600:9::1"])));
    assert_eq!((e.gain_ms, e.orig_ms, e.ecs_ms), (Num::V(56.0), Num::V(60.0), Num::V(4.0)));
    // 成功過的網段排前面（規格 06 第 3.1 節）；外層指定的優先網段永遠最前面
    assert_eq!(c.ecs_subnets(), ["1.160.0.0/24", "168.95.0.0/24"]);
    c.ecs_set_preferred(vec!["203.0.113.0/24".into(), "壞掉".into()]);
    c.ecs_add_subnet("198.51.100.0/24");
    assert_eq!(
        c.ecs_subnets(),
        ["203.0.113.0/24", "1.160.0.0/24", "198.51.100.0/24", "168.95.0.0/24"]
    );
    // 查詢時改寫
    let mut m = msg(
        "e1.akamaiedge.net",
        1,
        &["23.1.1.1"],
        vec![cname("www.ak.test", "e1.akamaiedge.net", 60)],
    );
    let r = c.apply(&mut m, "www.ak.test", 1);
    assert_eq!(answer_ips(&m, 1), ["23.9.9.9"]);
    assert_eq!(r.gain_ms, Some(56.0));
    let route = c.route(None, &r, &m).unwrap();
    assert!(route.abroad && route.tw && route.saved_ms == Some(56.0));
}

#[tokio::test]
async fn ecs_probe_no_gain_and_no_answer() {
    let (c, net) = setup(json!({ "ecs": { "twSubnets": ["168.95.0.0/24"] } }));
    c.with_state(|st| {
        st.db.touch("n.test", "akamai", "cname", &[], &[], None);
    });
    c.ecs_probe("n.test", &ips(&["23.1.1.1"]), &[]).await;
    assert_eq!(
        c.state().db.get("n.test").unwrap().ecs.as_ref().unwrap().reason.as_deref(),
        Some("ECS 查無結果")
    );
    net.on_dns(|_, name, _, _| {
        let mut m = msg(name, 1, &[], vec![]);
        m.answers.push(Record::a(name, 60, "23.5.5.5".parse().unwrap()));
        Some(m)
    });
    net.set_cached("23.1.1.1", 10.0);
    net.set_cached("23.5.5.5", 9.0);
    c.ecs_probe("n.test", &ips(&["23.1.1.1"]), &[]).await;
    let e = c.state().db.get("n.test").unwrap().ecs.clone().unwrap();
    assert_eq!(e.reason.as_deref(), Some("無明顯改善 (原 10ms / ECS 9ms)"));
}

#[tokio::test]
async fn health_check_marks_and_sorts() {
    let (c, net) = setup(json!({ "minPool": 3 }));
    let low = Arc::new(Mutex::new(Vec::<String>::new()));
    let l2 = low.clone();
    c.set_on_low_pool(move |p| l2.lock().unwrap().push(p.to_string()));
    c.with_state(|st| {
        let mut a = PoolNode::new(ip("104.16.161.36"));
        a.ms = Num::V(9.0);
        let mut b = PoolNode::new(ip("104.18.20.216"));
        b.ms = Num::V(3.0);
        st.pools.p.get_mut("cloudflare").unwrap().pool4 = vec![a, b];
        st.pools.p.get_mut("fastly").unwrap().pool4 = vec![];
    });
    net.on_http(|i, _| if i == ip("104.16.161.36") { cf_ok("TPE") } else { cf_ok("HKG") });
    net.on_ping(|_| lat(2.5));
    assert!(c.health_check().await);
    let st = c.state();
    let d = &st.pools.p["cloudflare"];
    assert_eq!(d.pool4[0].ip, ip("104.16.161.36"), "可用的排前面");
    assert_eq!(d.pool4[0].ms, Num::V(2.5));
    assert_eq!(d.bad[&ip("104.18.20.216")].reason, "POP=HKG");
    drop(st);
    assert_eq!(low.lock().unwrap().as_slice(), ["cloudflare"], "可用節點不足：通知重建節點池");
}

#[tokio::test]
async fn try_v6_discovers_taiwan_node() {
    let (c, net) = setup(json!({}));
    net.on_http(|_, _| resp(200, &[], "fl=1\ncolo=TPE\n"));
    net.on_ping(|_| lat(3.21));
    c.try_v6("cloudflare", ip("2606:4700:3030::9")).await;
    {
        let st = c.state();
        assert_eq!(st.pools.p["cloudflare"].pool6[0].ip, ip("2606:4700:3030::9"));
        assert!(st.v6.contains("cloudflare", ip("2606:4700:3030::9")), "永久保存");
        assert_eq!(
            st.pools.classify(ip("2606:4700:3030::1")).unwrap().cls,
            crate::Cls::Tw,
            "同一個 /48 視為台灣"
        );
    }
    // 同一個 /48 六小時內只試一次
    let n = net.calls("http ").len();
    c.try_v6("cloudflare", ip("2606:4700:3030::10")).await;
    assert_eq!(net.calls("http ").len(), n);
}

#[test]
fn peak_hours_weighting() {
    // 規格 06 第 3.2 節：凌晨很快、晚上很塞的節點，分數要反映尖峰時段
    let now = now_ms();
    let mut x = PoolNode::new(ip("151.101.0.1"));
    x.ms = Num::V(20.0);
    x.jitter = Num::V(0.0);
    x.loss = Num::V(0.0);
    assert_eq!(weighted_qscore(&x, 2.0, now), 20.0, "沒有尖峰量測：跟一般分數一樣");
    x.peak_ms = Num::V(80.0);
    x.peak_jitter = Num::V(10.0);
    x.peak_loss = Num::V(0.0);
    x.peak_at = Some(now - 3_600_000);
    assert_eq!(weighted_qscore(&x, 2.0, now), (20.0 + 2.0 * 100.0) / 3.0);
    x.peak_at = Some(now - 4 * 86_400_000);
    assert_eq!(weighted_qscore(&x, 2.0, now), 20.0, "太舊的尖峰量測不算");
    let cfg = crate::CdnConfig::from_value(&json!({}));
    // 2026-11-10 12:30 UTC = 台北 20:30
    assert!(cfg.is_peak(1_794_313_800_000));
    assert!(!cfg.is_peak(1_794_313_800_000 - 4 * 3_600_000));
}

#[tokio::test]
async fn quality_check_records_peak_samples() {
    let (c, net) = setup(json!({ "peak": { "startHour": 0, "endHour": 24 } }));
    c.with_state(|st| {
        let mut a = PoolNode::new(ip("151.101.0.5"));
        a.pop = Some(intern("NRT"));
        a.ms = Num::V(40.0);
        st.pools.p.get_mut("fastly").unwrap().pool4 = vec![a];
    });
    net.on_quality(|_| Quality {
        ms: 45.0,
        jitter: 1.0,
        loss: 0.0,
        n: 6,
    });
    c.quality_check().await;
    let st = c.state();
    let x = &st.pools.p["fastly"].pool4[0];
    assert_eq!((x.peak_ms, x.peak_jitter, x.score), (Num::V(45.0), Num::V(1.0), Num::V(47.0)));
    assert!(x.peak_at.is_some());
}

#[test]
fn baseline_and_route() {
    let (c, net) = setup(json!({}));
    net.set_cached("104.21.0.5", 60.0);
    net.set_cached("104.16.161.36", 3.0);
    let abroad = msg("s.test", 1, &["104.21.0.5"], vec![]);
    let tw = msg("s.test", 1, &["104.16.161.99"], vec![]);
    let b = c.baseline(&[&abroad, &abroad, &tw]).unwrap();
    assert_eq!((b.provider, b.abroad, b.ms), ("cloudflare", true, Some(60.0)));
    assert!(c.baseline(&[&msg("s.test", 1, &["8.8.8.8"], vec![])]).is_none());
    // 改寫成台灣節點：省下 57ms
    let served = msg("s.test", 1, &["104.16.161.36"], vec![]);
    let res = crate::ApplyResult {
        rewritten: Some(crate::Rewrite::Alias),
        provider: Some("cloudflare"),
        ..Default::default()
    };
    let r = c.route(Some(&b), &res, &served).unwrap();
    assert!(r.abroad && r.tw);
    assert_eq!(r.saved_ms, Some(57.0));
}

#[test]
fn recheck_and_shrink() {
    let (c, _) = setup(json!({}));
    c.with_state(|st| {
        for i in 0..10 {
            let n = format!("r{i}.test");
            st.db.touch(&n, "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
            st.db.set_verdict(&n, 4, |v| {
                v.verdict = Some(intern("ok"));
                v.until = Some(now_ms() + if i < 4 { 600_000 } else { 86_400_000 });
            });
        }
    });
    assert_eq!(c.recheck(), 4, "一小時內到期的先重新驗證");
    assert!(c
        .take_tasks()
        .iter()
        .all(|t| matches!(t, Task::Verify { family: 4, orig: Some(o), .. } if *o == ip("104.21.0.5"))));
    c.shrink(0.5);
    assert_eq!(c.state().db.domains.len(), 5);
}
