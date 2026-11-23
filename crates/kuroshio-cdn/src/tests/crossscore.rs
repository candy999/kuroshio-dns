//! 跨 CDN 替換加實測評分（3.5.0，規格 11 B4；F13 起分數是握手時間）：原本的五個條件不變，另外要「握手比原站快」

use super::selftest::cross_setup;
use super::*;
use crate::cross::{pick_by_score, score_ok, SCORE_EXTRA_PROBES};
use crate::db::Cross;
use crate::util::{intern, now_ms, Num};
use kuroshio_net::iprank::Quality;
use kuroshio_net::probe::Timing;
use std::sync::atomic::{AtomicUsize, Ordering};

const ORIG: &str = "151.101.1.1";
const CF: &str = "104.16.1.1";
const AZ: &str = "13.107.1.1";

/// 同一個網站的回應，帶分段時間（連線＋TLS 握手＝`score` 毫秒；TTFB 固定 120 毫秒，由原站決定）
fn page(headers: &[(&str, &str)], score: f64) -> ProbeResult {
    page_t(headers, score * 0.4, score * 0.6, 120.0)
}

fn page_t(headers: &[(&str, &str)], connect: f64, tls: f64, ttfb: f64) -> ProbeResult {
    let mut hh = vec![("content-type", "text/html; charset=utf-8")];
    hh.extend_from_slice(headers);
    let mut r = resp(200, &hh, "<html><head><title>X</title></head></html>");
    r.timing = Timing {
        connect_ms: connect,
        tls_ms: tls,
        ttfb_ms: ttfb,
    };
    r
}

/// 原站（Fastly，TCP 62 ms）與 Cloudflare（TCP `cf_tcp`）、Azure（TCP `az_tcp`）各自的實測分數
fn setup(orig: f64, cf: (f64, f64), az: (f64, f64), over: Value) -> (Arc<Cdn>, Arc<MockNet>) {
    let (c, net) = if over.is_null() {
        cross_setup()
    } else {
        let (_, net) = cross_setup();
        let mut cfg = json!({
            "providers": { "cloudflare": {"enabled": true}, "cloudfront": {"enabled": true}, "azure": {"enabled": true}, "fastly": {"enabled": true} },
            "ecs": { "twSubnets": [] }, "nearestMinGainMs": 8
        });
        kuroshio_config::merge(&mut cfg, &over);
        let c = cdn_with(cfg, paths_no_seed("crossscore"), net.clone());
        c.with_state(|st| {
            for (p, i) in [("cloudflare", CF), ("cloudfront", "65.9.1.1"), ("azure", AZ)] {
                let mut n = crate::pools::PoolNode::new(ip(i));
                n.ms = Num::V(3.0);
                st.pools.p.get_mut(p).unwrap().pool4 = vec![n];
            }
        });
        (c, net)
    };
    net.on_https(move |i, _| match i.to_string().as_str() {
        ORIG => page(&[], orig),
        CF => page(&[("cf-ray", "abc-TPE")], cf.1),
        AZ => page(&[("x-azure-ref", "r")], az.1),
        _ => ProbeResult::failed("ERR_TLS_CERT_ALTNAME_INVALID", true),
    });
    net.on_quality(move |i| Quality {
        ms: match i.to_string().as_str() {
            ORIG => 62.0,
            CF => cf.0,
            _ => az.0,
        },
        jitter: 0.0,
        loss: 0.0,
        n: 3,
    });
    c.with_state(|st| {
        st.db.touch("x.com", "fastly", "ip", &ips(&[ORIG]), &[], None);
    });
    (c, net)
}

fn rec(c: &Cdn) -> Cross {
    *c.state().db.get("x.com").unwrap().cross4.clone().unwrap()
}

#[test]
fn score_pick_and_threshold() {
    // 分數最低的；差在 10% 以內的幾家看 TCP 延遲
    assert_eq!(pick_by_score(&[(4.0, 60.0), (6.0, 30.0)]), Some(1));
    assert_eq!(pick_by_score(&[(4.0, 32.0), (6.0, 30.0)]), Some(0), "分數接近：TCP 延遲低的");
    assert_eq!(pick_by_score(&[(4.0, 34.0), (6.0, 30.0)]), Some(1), "超過 10% 就不算接近");
    assert_eq!(pick_by_score(&[]), None);
    // 新採用的要快 5% 以上；已經在用的差 10% 以內都留著
    assert!(score_ok(95.0, 100.0, false) && !score_ok(96.0, 100.0, false));
    assert!(score_ok(110.0, 100.0, true) && !score_ok(111.0, 100.0, true));
}

#[tokio::test]
async fn cross_prefers_lower_request_score_over_lower_tcp() {
    // Cloudflare 的 TCP 延遲比較低（4 ms 對 6 ms），但握手 Azure 快一倍：挑 Azure。以前只看 TCP，挑 Cloudflare
    let (c, _) = setup(100.0, (4.0, 60.0), (6.0, 30.0), Value::Null);
    assert_eq!(c.cross_explore("x.com", "fastly", ip(ORIG)).await, "ok");
    let r = rec(&c);
    assert_eq!(r.to.as_deref(), Some("azure"));
    assert_eq!((r.score, r.orig_score), (Num::V(30.0), Num::V(100.0)));
    assert_eq!(r.also, Some(vec!["cloudflare".to_string()]));
    let t = r.tried.unwrap();
    assert_eq!(t.iter().find(|x| &*x.to == "cloudflare").unwrap().score, Num::V(60.0));
    // 分數接近（差 10% 以內）：TCP 延遲低的那一家
    let (c, _) = setup(100.0, (4.0, 32.0), (6.0, 30.0), Value::Null);
    assert_eq!(c.cross_explore("x.com", "fastly", ip(ORIG)).await, "ok");
    assert_eq!(rec(&c).to.as_deref(), Some("cloudflare"));
    // `cdn.cross.requestScore: false`：同 3.4.x，只看 TCP 延遲
    let (c, _) = setup(100.0, (4.0, 60.0), (6.0, 30.0), json!({ "cross": { "requestScore": false } }));
    assert_eq!(c.cross_explore("x.com", "fastly", ip(ORIG)).await, "ok");
    let r = rec(&c);
    assert_eq!(r.to.as_deref(), Some("cloudflare"));
    assert_eq!((r.score, r.orig_score), (Num::Absent, Num::Absent));
}

#[tokio::test]
async fn cross_rejected_when_request_not_faster() {
    // TCP 連線近很多（4 ms 對 62 ms），但握手沒有比原站快：不換
    let (c, _) = setup(100.0, (4.0, 120.0), (6.0, 130.0), Value::Null);
    assert_eq!(c.cross_explore("x.com", "fastly", ip(ORIG)).await, "fail");
    let r = rec(&c);
    assert!(r.is("fail"));
    let reason = r.reason.clone().unwrap();
    assert!(
        reason.contains("連線比較近，但握手沒有比較快") && reason.contains("Cloudflare"),
        "{reason}"
    );
    assert_eq!((r.score, r.orig_score, r.orig_ms), (Num::V(120.0), Num::V(100.0), Num::V(62.0)));
    assert_eq!(c.cross_summary()["scoreRejected"], 1);
    // 只快一點點（不到 5%）也不換
    let (c, _) = setup(100.0, (4.0, 97.0), (6.0, 130.0), Value::Null);
    assert_eq!(c.cross_explore("x.com", "fastly", ip(ORIG)).await, "fail");
    // 沒有這個條件時（3.4.x）會換過去
    let (c, _) = setup(100.0, (4.0, 120.0), (6.0, 130.0), json!({ "cross": { "requestScore": false } }));
    assert_eq!(c.cross_explore("x.com", "fastly", ip(ORIG)).await, "ok");
    assert_eq!(c.cross_summary()["scoreRejected"], 0);
}

#[tokio::test]
async fn cross_score_never_relaxes_tcp_condition() {
    // 條件只增不減：TCP 延遲沒有快 8 ms 以上的，握手再快也不換
    let (c, _) = setup(100.0, (60.0, 10.0), (61.0, 10.0), Value::Null);
    assert_eq!(c.cross_explore("x.com", "fastly", ip(ORIG)).await, "fail");
    let r = rec(&c);
    assert!(r.reason.as_deref().unwrap().contains("可用但沒有比較快"), "{:?}", r.reason);
    assert_eq!(r.score, Num::Absent, "沒有進到分數那一關");
    // 其中一家的 TCP 夠快、另一家分數更好但 TCP 不夠快：只會挑 TCP 也過關的那一家
    let (c, _) = setup(100.0, (4.0, 60.0), (60.0, 10.0), Value::Null);
    assert_eq!(c.cross_explore("x.com", "fastly", ip(ORIG)).await, "ok");
    assert_eq!(rec(&c).to.as_deref(), Some("cloudflare"));
}

#[tokio::test]
async fn cross_recheck_hysteresis() {
    // 已經在用的跨 CDN 結果複驗：分數比原站差 10% 以內都留著（不在邊界每天來回）；超過才撤掉
    let in_use = |c: &Cdn| {
        c.with_state(|st| {
            st.db.set_cross(
                "x.com",
                Cross {
                    verdict: Some(intern("ok")),
                    from: Some(intern("fastly")),
                    to: Some(intern("cloudflare")),
                    ips: Some(ips(&[CF])),
                    until: Some(now_ms() + 86_400_000),
                    recheck_at: Some(now_ms() - 1),
                    ..Default::default()
                },
            )
        })
    };
    let (c, _) = setup(100.0, (4.0, 105.0), (60.0, 10.0), Value::Null);
    assert_eq!(
        c.cross_explore("x.com", "fastly", ip(ORIG)).await,
        "fail",
        "新採用：105 對 100 不夠快"
    );
    in_use(&c);
    assert_eq!(c.cross_explore("x.com", "fastly", ip(ORIG)).await, "ok", "已經在用：差 5% 留著");
    let r = rec(&c);
    assert_eq!(
        (r.to.as_deref(), r.score, r.orig_score),
        (Some("cloudflare"), Num::V(105.0), Num::V(100.0))
    );
    let (c, _) = setup(100.0, (4.0, 115.0), (60.0, 10.0), Value::Null);
    in_use(&c);
    assert_eq!(c.cross_explore("x.com", "fastly", ip(ORIG)).await, "fail", "差 15%：撤掉");
    // 遲滯只給正在用的那一家：換成別家要照新採用的標準
    let (c, _) = setup(100.0, (60.0, 10.0), (4.0, 105.0), Value::Null);
    in_use(&c);
    assert_eq!(c.cross_explore("x.com", "fastly", ip(ORIG)).await, "fail");
}

#[tokio::test]
async fn cross_extra_probes_capped_at_two() {
    // 探測次數：原站 1 ＋ 每家的節點各 1（跟以前一樣）＋ 為了分數最多再 2 次（第一名與原站各一次）
    let (c, net) = setup(100.0, (4.0, 60.0), (6.0, 30.0), Value::Null);
    assert_eq!(c.cross_explore("x.com", "fastly", ip(ORIG)).await, "ok");
    let n = |ipx: &str| net.calls(&format!("https {ipx} ")).len();
    assert_eq!((n(ORIG), n(CF), n(AZ), n("65.9.1.1")), (2, 1, 2, 1), "{:?}", net.calls("https"));
    assert_eq!(net.calls("https").len(), 4 + SCORE_EXTRA_PROBES);
    // 原本的條件就沒過（TCP 不夠快）：不多探測
    let (c, net) = setup(100.0, (60.0, 10.0), (61.0, 10.0), Value::Null);
    assert_eq!(c.cross_explore("x.com", "fastly", ip(ORIG)).await, "fail");
    assert_eq!(net.calls("https").len(), 4);
    // 探測沒有分段時間（量不到）：照原本的規則，也不多探測
    let (c, net) = cross_setup();
    c.with_state(|st| {
        st.db.touch("x.com", "fastly", "ip", &ips(&[ORIG]), &[], None);
    });
    assert_eq!(c.cross_explore("x.com", "fastly", ip(ORIG)).await, "ok");
    assert_eq!(net.calls("https").len(), 4);
    assert_eq!(rec(&c).score, Num::Absent);
}

#[tokio::test]
async fn second_sample_takes_the_smaller() {
    // 只有一次樣本雜訊大：第一名與原站各再量一次，取比較小的。
    // Cloudflare 第一次 97（不夠快）、第二次 80 → 用 80，採用
    let (c, net) = setup(100.0, (4.0, 97.0), (60.0, 10.0), Value::Null);
    let k = Arc::new(AtomicUsize::new(0));
    let k2 = k.clone();
    net.on_https(move |i, _| match i.to_string().as_str() {
        ORIG => page(&[], 100.0),
        CF => page(
            &[("cf-ray", "abc-TPE")],
            if k2.fetch_add(1, Ordering::SeqCst) == 0 { 97.0 } else { 80.0 },
        ),
        AZ => page(&[("x-azure-ref", "r")], 10.0),
        _ => ProbeResult::failed("ERR_TLS_CERT_ALTNAME_INVALID", true),
    });
    assert_eq!(c.cross_explore("x.com", "fastly", ip(ORIG)).await, "ok");
    assert_eq!((rec(&c).score, rec(&c).orig_score), (Num::V(80.0), Num::V(100.0)));
    assert_eq!(k.load(Ordering::SeqCst), 2);
    // 第二次探測失敗：不影響（用第一次的）
    let (c, net) = setup(100.0, (4.0, 60.0), (60.0, 10.0), Value::Null);
    let k = Arc::new(AtomicUsize::new(0));
    net.on_https(move |i, _| match i.to_string().as_str() {
        ORIG => page(&[], 100.0),
        CF if k.fetch_add(1, Ordering::SeqCst) == 0 => page(&[("cf-ray", "abc-TPE")], 60.0),
        CF => fail("TIMEOUT"),
        AZ => page(&[("x-azure-ref", "r")], 10.0),
        _ => ProbeResult::failed("ERR_TLS_CERT_ALTNAME_INVALID", true),
    });
    assert_eq!(c.cross_explore("x.com", "fastly", ip(ORIG)).await, "ok");
    assert_eq!(rec(&c).score, Num::V(60.0));
}

#[tokio::test]
async fn explain_shows_request_scores() {
    let (c, _) = setup(100.0, (4.0, 120.0), (6.0, 130.0), Value::Null);
    c.cross_explore("x.com", "fastly", ip(ORIG)).await;
    let v = c.explain("x.com", crate::explain::Context::default());
    let step = v["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["what"] == "cross")
        .unwrap()
        .clone();
    assert_eq!(
        (step["score"].clone(), step["origScore"].clone()),
        (json!(120.0), json!(100.0)),
        "{v}"
    );
    assert!(step["reason"].as_str().unwrap().contains("握手沒有比較快"));
}

/// 3.5.0 F13（W11 的網站丙）：原站 Fastly 連線 33、TLS 75、TTFB 約 130；Cloudflare 台灣 21、42、約 120。
/// TTFB 兩邊一樣（原站決定），以前「連線＋握手＋TTFB」238 對 183 只差 23%、第二次樣本又可能蓋掉；握手 63 對 108：採用
#[tokio::test]
async fn cross_score_is_handshake_only() {
    let (c, net) = setup(100.0, (4.0, 60.0), (60.0, 10.0), Value::Null);
    net.on_https(move |i, _| match i.to_string().as_str() {
        ORIG => page_t(&[], 33.0, 75.0, 130.0),
        CF => page_t(&[("cf-ray", "abc-TPE")], 21.0, 42.0, 120.0),
        AZ => page(&[("x-azure-ref", "r")], 10.0),
        _ => ProbeResult::failed("ERR_TLS_CERT_ALTNAME_INVALID", true),
    });
    assert_eq!(c.cross_explore("x.com", "fastly", ip(ORIG)).await, "ok");
    let r = rec(&c);
    assert_eq!(
        (r.to.as_deref(), r.score, r.orig_score),
        (Some("cloudflare"), Num::V(63.0), Num::V(108.0))
    );
}

#[tokio::test]
async fn cross_same_ttfb_no_longer_masks_handshake_gain() {
    // 握手快很多（50 對 100），但 TTFB 由原站決定而且這一次台灣那邊剛好慢 400 毫秒：照握手判斷，採用
    let (c, net) = setup(100.0, (4.0, 50.0), (60.0, 10.0), Value::Null);
    net.on_https(move |i, _| match i.to_string().as_str() {
        ORIG => page_t(&[], 40.0, 60.0, 100.0),
        CF => page_t(&[("cf-ray", "abc-TPE")], 20.0, 30.0, 500.0),
        AZ => page(&[("x-azure-ref", "r")], 10.0),
        _ => ProbeResult::failed("ERR_TLS_CERT_ALTNAME_INVALID", true),
    });
    assert_eq!(c.cross_explore("x.com", "fastly", ip(ORIG)).await, "ok");
    assert_eq!(rec(&c).score, Num::V(50.0));
    // 反過來：TTFB 台灣快很多，握手沒有比較快 → 不換（TTFB 不算）
    let (c, net) = setup(100.0, (4.0, 100.0), (60.0, 10.0), Value::Null);
    net.on_https(move |i, _| match i.to_string().as_str() {
        ORIG => page_t(&[], 40.0, 60.0, 600.0),
        CF => page_t(&[("cf-ray", "abc-TPE")], 40.0, 60.0, 20.0),
        AZ => page(&[("x-azure-ref", "r")], 10.0),
        _ => ProbeResult::failed("ERR_TLS_CERT_ALTNAME_INVALID", true),
    });
    assert_eq!(c.cross_explore("x.com", "fastly", ip(ORIG)).await, "fail");
}

#[tokio::test]
async fn cross_no_taiwan_weight() {
    // F9 的台灣加權（× 0.7）不套用：96 對 100 不到快 5%，不換（加權的話 67 會過）
    let (c, _) = setup(100.0, (4.0, 96.0), (60.0, 10.0), Value::Null);
    assert_eq!(c.cross_explore("x.com", "fastly", ip(ORIG)).await, "fail");
    let (c, _) = setup(100.0, (4.0, 95.0), (60.0, 10.0), Value::Null);
    assert_eq!(c.cross_explore("x.com", "fastly", ip(ORIG)).await, "ok");
}
