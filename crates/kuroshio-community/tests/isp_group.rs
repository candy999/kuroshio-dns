//! 3.5.0 E10：ISP 群組（`community.shareIspGroup`，預設關）。開了才在同步回應的 `ctx` 帶群組；
//! 收到的一方只拿來決定好友提示的先後（同群組的先），不影響信任；沒開的一方送也不送、收到也不看

mod common;

use common::*;
use kuroshio_community::envelope::{from_cbor, Envelope, IdentityBody};
use serde_json::json;

fn accept_all() -> Vec<serde_json::Value> {
    vec![json!({ "action": "accept", "domain_suffix": ["test"] })]
}

async fn befriend(a: &Node, b: &Node) {
    let res = a.c.send_request(&b.input(), true).await;
    assert_eq!(res["status"], "accepted", "{res}");
    let from = b.domain.clone();
    wait_for(&format!("{} 第一次完整同步", from), || {
        a.data.received.lock().unwrap().iter().any(|x| x.from == from && x.full)
    })
    .await;
}

fn ctx_isp(a: &Node, from: &str) -> Option<String> {
    a.data
        .received
        .lock()
        .unwrap()
        .iter()
        .rev()
        .find(|x| x.from == from)
        .and_then(|x| x.ctx.isp.clone())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hints_same_group_first_count_unchanged() {
    let r = resolver(&[]);
    let on = |rules: Vec<serde_json::Value>| Spec {
        share_isp: true,
        rules,
        ..Default::default()
    };
    let a = node("ia.test", &r, on(vec![])).await;
    let b = node("ib.test", &r, on(accept_all())).await;
    let c = node("ic.test", &r, on(accept_all())).await;
    // 沒開分享的好友：同群組也不送（「不知道」）
    let d = node(
        "id.test",
        &r,
        Spec {
            rules: accept_all(),
            ..Default::default()
        },
    )
    .await;
    *a.data.isp.lock().unwrap() = Some("cht".into());
    *b.data.isp.lock().unwrap() = Some("cht".into());
    *c.data.isp.lock().unwrap() = Some("twm".into());
    *d.data.isp.lock().unwrap() = Some("cht".into());
    // 同一個網站：同群組的 B 給的 IP 比較大（沒有群組時依 IP 排在後面）
    b.data.set(vec![site_rec("example.com", "104.16.9.9")]);
    c.data.set(vec![site_rec("example.com", "104.16.1.1")]);
    for x in [&b, &c, &d] {
        befriend(&a, x).await;
    }
    assert_eq!(ctx_isp(&a, "ib.test").as_deref(), Some("cht"));
    assert_eq!(ctx_isp(&a, "ic.test").as_deref(), Some("twm"));
    assert_eq!(ctx_isp(&a, "id.test"), None, "沒開分享的好友不送");
    assert_eq!(a.peer("ib.test").info.isp.as_deref(), Some("cht"));
    assert_eq!(a.peer("id.test").info.isp, None);
    assert_eq!(
        a.c.status()["ispGroup"],
        json!({ "share": true, "mine": "cht", "sameGroupFriends": 1 })
    );
    let ips = |n: &Node| -> Vec<String> {
        n.c.site_hints("example.com", "cloudflare", 4)
            .iter()
            .map(|h| h.ip.to_string())
            .collect()
    };
    assert_eq!(ips(&a), vec!["104.16.9.9", "104.16.1.1"], "同群組的先，個數不變");
    // 關掉：照原本的順序、不給 mine
    let mut cfg = a.c.config();
    cfg.share_isp_group = false;
    a.c.set_config(cfg);
    assert_eq!(ips(&a), vec!["104.16.1.1", "104.16.9.9"]);
    assert_eq!(a.c.status()["ispGroup"], json!({ "share": false, "sameGroupFriends": 0 }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn share_off_ignores_received_isp() {
    let r = resolver(&[]);
    let x = node("ix.test", &r, Spec::default()).await;
    let y = node(
        "iy.test",
        &r,
        Spec {
            share_isp: true,
            rules: accept_all(),
            ..Default::default()
        },
    )
    .await;
    *x.data.isp.lock().unwrap() = Some("cht".into());
    *y.data.isp.lock().unwrap() = Some("cht".into());
    befriend(&x, &y).await;
    assert_eq!(ctx_isp(&x, "iy.test"), None, "這台沒開：收到也不看");
    assert_eq!(x.peer("iy.test").info.isp, None);
    assert_eq!(x.c.status()["ispGroup"]["share"], false);
    assert!(x.c.status()["ispGroup"].get("mine").is_none());
    // 反過來：y 收 x 的（x 沒開，不送）
    assert!(y.c.my_isp().is_some());
    assert_eq!(x.c.my_isp(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn identity_doc_never_carries_isp() {
    let r = resolver(&[]);
    let a = node(
        "ii.test",
        &r,
        Spec {
            share_isp: true,
            ..Default::default()
        },
    )
    .await;
    *a.data.isp.lock().unwrap() = Some("cht".into());
    assert_eq!(a.c.my_isp().as_deref(), Some("cht"));
    let env = Envelope::decode(&a.c.identity_bytes()).unwrap();
    let body: IdentityBody = from_cbor(env.body()).unwrap();
    assert_eq!(body.net.isp, None, "身分文件（加好友之前就看得到）不放");
    assert_eq!(body.net.colo, "TPE");
    assert!(!env.body().windows(3).any(|w| w == b"isp"));
}
