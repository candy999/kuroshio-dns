//! 三種管道：HTTPS / TLS（ALPN kuroshio/2）/ QUIC（ALPN kuroshio/2）；選擇順序、記住上次成功的管道、失敗時退回；
//! 整合端用的 serve_stream / serve_quic / handle_http；端點主機一定要等於對方網域

mod common;

use common::*;
use kuroshio_community::transport::{call, Timeouts};
use kuroshio_community::{Endpoint, Scheme};
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn channels_and_fallback() {
    let r = resolver(&[]);
    // d.test 用整合端的 API（serve_stream / serve_quic）
    let d = node(
        "d.test",
        &r,
        Spec {
            direct: true,
            rules: vec![json!({ "action": "accept" })],
            ..Default::default()
        },
    )
    .await;
    let e = node(
        "e.test",
        &r,
        Spec {
            rules: vec![json!({ "action": "accept" })],
            ..Default::default()
        },
    )
    .await;

    // 每種管道都拿得到身分文件
    for s in [Scheme::Doq, Scheme::Dot, Scheme::Https] {
        let idn = e.c.fetch_identity("d.test", vec![d.endpoint(s)], false, true).await.unwrap();
        assert_eq!(idn.channel, s);
        assert_eq!(idn.keys[0].kid, d.c.kid().to_vec());
        assert_eq!(idn.endpoints.len(), 3);
        assert_eq!(idn.proto, vec![2]);
    }
    // 端點主機不是對方網域 → 不連（避免被指使去連別人）
    let wrong = Endpoint {
        scheme: Scheme::Https,
        host: "e.test".into(),
        port: d.https,
    };
    assert!(e.c.fetch_identity("d.test", vec![wrong], false, true).await.is_err());
    // 憑證不符（SNI = e.test、連到 d.test 的伺服器）→ TLS 驗證失敗
    r.set("x.test", &[LOCAL]);
    let t = Timeouts {
        connect: Duration::from_secs(3),
        total: Duration::from_secs(5),
        max_wire: 65536,
    };
    let bad = Endpoint {
        scheme: Scheme::Https,
        host: "x.test".into(),
        port: d.https,
    };
    assert!(call(&*r, &bad, "identity", None, t).await.is_err());

    // 加好友後：依 DoQ → DoT → HTTPS，記住上次成功的管道
    let res = e.c.send_request(&d.input(), true).await;
    assert_eq!(res["status"], "accepted", "{res}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let res = sync(&d, "e.test").await;
    assert!(res["ok"] == true, "{res}");
    assert_eq!(d.peer("e.test").channel.as_deref(), Some("doq"));
    // DoQ 壞掉 → 退回 DoT
    e.faults.quic_down.store(true, Ordering::SeqCst);
    let res = sync(&d, "e.test").await;
    assert_eq!(res["ok"], true, "{res}");
    assert_eq!(d.peer("e.test").channel.as_deref(), Some("dot"));
    // 上次成功的是 DoT：下次直接用 DoT（不再先試 DoQ）
    let before = e.faults.requests.load(Ordering::SeqCst);
    let res = sync(&d, "e.test").await;
    assert_eq!(res["ok"], true, "{res}");
    assert_eq!(e.faults.requests.load(Ordering::SeqCst), before + 1);
    // 管理介面指定管道
    let q: HashMap<String, String> = [
        ("domain".to_string(), "e.test".to_string()),
        ("channel".to_string(), "https".to_string()),
    ]
    .into();
    assert_eq!(d.c.admin("/api/community/channel", &q).await.unwrap()["prefer"], "https");
    sync(&d, "e.test").await;
    assert_eq!(d.peer("e.test").channel.as_deref(), Some("https"));
    e.faults.quic_down.store(false, Ordering::SeqCst);

    // 整合端 API 的路徑處理
    assert!(d.c.handle_http("GET", "/dns-query", b"", LOCAL).await.is_none());
    let (st, _) = d.c.handle_http("POST", "/.well-known/kuroshio/v2/nope", b"", LOCAL).await.unwrap();
    assert_eq!(st, 404);
    let (st, body) =
        d.c.handle_http("GET", "/.well-known/kuroshio/v2/identity", b"", LOCAL)
            .await
            .unwrap();
    assert_eq!(st, 200);
    assert!(kuroshio_community::envelope::Envelope::decode(&body)
        .unwrap()
        .verify_with("identity", &{
            let k = e.peer("d.test").keys[0].public.clone();
            kuroshio_community::util::unb64(&k).unwrap()
        }));
    // 關閉社群模式 → 一律 503
    let mut cfg = d.c.config();
    cfg.enabled = false;
    d.c.set_config(cfg);
    assert_eq!(d.c.handle("identity", b"", LOCAL).await.0, 503);

    // 對方還在 v1：顯示「對方版本較舊」，6 小時後重試，不算連不上、不觸發 staleDays
    let old = node("old.test", &r, Spec::default()).await;
    old.faults.v1_mode.store(true, Ordering::SeqCst);
    let res = e.c.send_request(&format!("old.test:{}", old.https), true).await;
    assert_eq!(res["ok"], false, "{res}");
    assert!(res["reason"].as_str().unwrap().contains("v1"), "{res}");
    let p = e.peer("old.test");
    assert!(p.old_version_since > 0);
    assert_eq!(p.fail_count, 0, "不算連不上");
    assert!(p.next_try > now() + 5 * 3_600_000);
    let peers = e.c.admin("/api/community/peers", &HashMap::new()).await.unwrap();
    assert!(peers
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x["domain"] == "old.test" && x["oldVersion"] == true));
    e.c.with_peer("old.test", |p| {
        p.rel = kuroshio_community::peers::Rel::Friend;
        p.friend_since = now() - 20 * 86_400_000;
        p.last_contact = now() - 10 * 86_400_000;
    });
    e.c.maintain(now());
    assert_eq!(
        e.peer("old.test").rel,
        kuroshio_community::peers::Rel::Friend,
        "等對方升級，最多 30 天"
    );
}
