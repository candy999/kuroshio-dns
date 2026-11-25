//! 「為什麼沒換到台灣」說明（3.5.0，規格 11 B7）：每一種決定、只讀（不 touch、不排背景工作）

use super::selftest::setup;
use super::*;
use crate::db::Policy;
use crate::explain::Context;
use crate::util::now_ms;
use serde_json::json;

fn seen(c: &Arc<Cdn>, name: &str) {
    let mut m = msg(name, 1, &["104.21.0.5"], vec![]);
    assert_eq!(c.apply(&mut m, name, 1).provider, Some("cloudflare"));
    c.take_tasks();
}

fn decision(c: &Cdn, name: &str) -> String {
    c.explain(name, Context::default())["decision"].as_str().unwrap().to_string()
}

#[test]
fn explain_unknown_and_trial() {
    let (c, _) = setup(json!({}));
    let v = c.explain("nobody.test", Context::default());
    assert_eq!((v["decision"].clone(), v["known"].clone()), (json!("unknown"), json!(false)));
    seen(&c, "fresh.test");
    let v = c.explain("Fresh.Test.", Context::default());
    assert_eq!(v["decision"], "trial", "{v}");
    assert_eq!(v["provider"], "cloudflare");
    assert!(v["text"].as_str().unwrap().contains("Cloudflare"), "{v}");
    assert_eq!(v["steps"][0]["what"], "v4");
}

#[test]
fn explain_rewritten_and_failed() {
    let (c, _) = setup(json!({}));
    seen(&c, "ok.test");
    seen(&c, "bad.test");
    let until = now_ms() + 3_600_000;
    c.with_state(|st| {
        st.db.set_verdict("ok.test", 4, |v| {
            v.verdict = Some("ok".into());
            v.until = Some(until);
            v.pop = Some("TPE".into());
            v.ms = crate::util::Num::of(12.0);
        });
        st.db.set_verdict("bad.test", 4, |v| {
            v.verdict = Some("fail".into());
            v.until = Some(until);
            v.reason = Some("試了 3 個節點，都不是這個網站".into());
        });
    });
    let v = c.explain("ok.test", Context::default());
    assert_eq!(v["decision"], "rewritten");
    assert!(v["text"].as_str().unwrap().contains("TPE"), "{v}");
    let v = c.explain("bad.test", Context::default());
    assert_eq!(v["decision"], "verify-failed");
    assert!(v["text"].as_str().unwrap().contains("試了 3 個節點"), "{v}");
    // 過期的「通過」不算：回到驗證中
    c.with_state(|st| st.db.set_verdict("ok.test", 4, |v| v.until = Some(1)));
    assert_eq!(decision(&c, "ok.test"), "trial");
}

#[test]
fn explain_policy_lite_and_context() {
    let (c, _) = setup(json!({}));
    seen(&c, "never.test");
    c.with_state(|st| {
        st.db.set_policy("never.test", Policy::Never);
    });
    assert_eq!(decision(&c, "never.test"), "policy-never");
    let v = c.explain(
        "never.test",
        Context {
            chained: true,
            suspended: false,
        },
    );
    assert_eq!(v["decision"], "chained");
    let v = c.explain(
        "never.test",
        Context {
            chained: false,
            suspended: true,
        },
    );
    assert_eq!(v["decision"], "memory-floor");
    // 小記憶體減量：問過一次還沒驗證
    let (c, _) = setup(json!({ "lite": true }));
    let mut m = msg("once.test", 1, &["104.21.0.5"], vec![]);
    c.apply(&mut m, "once.test", 1);
    c.take_tasks();
    assert_eq!(decision(&c, "once.test"), "lite-waiting");
}

/// 只讀：不增加 hits、不排背景工作
#[test]
fn explain_does_not_touch_or_schedule() {
    let (c, _) = setup(json!({}));
    seen(&c, "quiet.test");
    let hits = c.state().db.get("quiet.test").unwrap().hits;
    for _ in 0..5 {
        c.explain("quiet.test", Context::default());
    }
    assert_eq!(c.state().db.get("quiet.test").unwrap().hits, hits, "沒有增加 hits");
    assert!(c.take_tasks().is_empty(), "沒有排背景工作");
}

/// 3.5.1：退回（F9「比原本慢」）到期之後，上游的答案已經是台灣節點時，跟查詢路徑一樣說「已是台灣」，
/// 不是「還在驗證中」；判斷用最近一次答案的 IP 在節點池裡的分類，不用存著的舊 POP
#[test]
fn explain_expired_slower_with_taiwan_answer_is_already_tw() {
    let (c, _) = setup(json!({}));
    let name = "www.example.com";
    seen(&c, name);
    c.with_state(|st| {
        // 退回的那一筆：存著的基準是國外的 POP，結果已經到期
        st.db.set_base(
            name,
            crate::db::Base {
                ip: Some(ip("104.21.0.5")),
                ok: Some(true),
                pop: Some("HKG".into()),
                ..Default::default()
            },
        );
        st.db.set_verdict(name, 4, |v| {
            v.verdict = Some("fail".into());
            v.until = Some(1);
            v.reason = Some("台灣節點握手連續兩次比原本慢（120 毫秒對 30 毫秒）".into());
            let m = v.extra.0.get_or_insert_with(Default::default);
            m.insert(crate::verifier::SLOWER.into(), json!(true));
        });
    });
    // 最近一次答案還是國外的 IP：照舊是「驗證中」（查詢路徑也會試用、排驗證）
    assert_eq!(decision(&c, name), "trial");
    // 上游改回台灣節點（節點池的分類是 Tw）
    let mut m = msg(name, 1, &["104.16.161.5"], vec![]);
    let r = c.apply(&mut m, name, 1);
    assert!(r.tags.iter().any(|t| t.contains("已是台灣")), "{:?}", r.tags);
    assert!(r.ttl_cap.is_none(), "沒有縮短 TTL");
    assert!(c.take_tasks().is_empty(), "沒有排驗證");
    assert_eq!(decision(&c, name), "already-tw");
    // 舊資料沒有這家的 IP：才用存著的基準 POP
    c.with_state(|st| {
        st.db.domains.get_mut(name).unwrap().ips4 = Box::new([]);
    });
    assert_eq!(decision(&c, name), "trial", "基準 POP 是 HKG");
}

/// 台灣本地的 CDN（3.5.1，中華電信 HiNet CDN）：認得、標成已是台灣，不換、不排任何背景工作
#[test]
fn tw_native_cdn_is_already_taiwan() {
    let (c, _) = setup(json!({}));
    for _ in 0..3 {
        let mut m = msg(
            "www.example.com",
            1,
            &["192.0.2.10"],
            vec![cname("www.example.com", "www.example.com.cdn.hinet.net", 300)],
        );
        let r = c.apply(&mut m, "www.example.com", 1);
        assert_eq!(r.provider, Some("hinet"));
        assert!(r.rewritten.is_none() && r.ttl_cap.is_none(), "{r:?}");
        assert!(r.tags.iter().any(|t| t.contains("已是台灣")), "{:?}", r.tags);
        assert_eq!(answer_ips(&m, 1), ["192.0.2.10"]);
        assert!(c.take_tasks().is_empty(), "不驗證、不跨 CDN、不量延遲");
    }
    let v = c.explain("www.example.com", Context::default());
    assert_eq!(v["decision"], "already-tw", "{v}");
    assert!(v["text"].as_str().unwrap().contains("HiNet"), "{v}");
}
