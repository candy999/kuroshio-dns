//! 金鑰輪替：舊金鑰簽名的通知、錯過通知時從身分文件補上、沒有舊金鑰簽名的變更要人工確認

mod common;

use common::*;
use kuroshio_community::identity::KeyPair;
use kuroshio_community::peers::{PeerKey, Rel};
use kuroshio_community::util::{b64, hex};
use kuroshio_community::Scheme;
use serde_json::json;
use std::collections::HashMap;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn key_rotation() {
    let r = resolver(&[]);
    let auto = Spec {
        rules: vec![json!({ "action": "accept", "domain_suffix": ["test"] })],
        ..Default::default()
    };
    let a = node("ra.test", &r, Spec::default()).await;
    let b = node("rb.test", &r, auto).await;
    let c = node("rc.test", &r, Spec::default()).await;
    b.data.set(vec![node_rec("104.16.1.1")]);
    for n in [&a, &c] {
        let res = n.c.send_request(&b.input(), true).await;
        assert_eq!(res["status"], "accepted", "{res}");
    }
    let old = hex(&b.c.kid());
    let old_fp = b.c.fingerprint();
    wait_for("第一次同步", || {
        a.peer("rb.test").last_sync_ok > 0 && c.peer("rb.test").last_sync_ok > 0
    })
    .await;

    // B 換金鑰：新金鑰由舊金鑰簽名，主動通知好友
    let res = b.c.rotate();
    assert_eq!(res["ok"], true, "{res}");
    let new = hex(&b.c.kid());
    assert_ne!(old, new);
    assert_ne!(b.c.fingerprint(), old_fp);
    assert!(b.key_dir.join("key.old.pem").exists());
    assert_eq!(
        KeyPair::from_pem(&std::fs::read_to_string(b.key_dir.join("key.pem")).unwrap())
            .unwrap()
            .kid,
        b.c.kid()
    );
    wait_for("A 收到輪替通知", || a.peer("rb.test").keys.iter().any(|k| k.kid == new)).await;
    let keys = a.peer("rb.test").keys;
    assert!(keys.iter().find(|k| k.kid == old).unwrap().until.is_some(), "舊金鑰 7 天後失效");
    assert!(a.c.events().iter().any(|e| e.kind == "對方更換金鑰"));

    // 身分文件同時列出兩把金鑰，附輪替聲明
    let idn =
        a.c.fetch_identity("rb.test", vec![b.endpoint(Scheme::Https)], false, true)
            .await
            .unwrap();
    assert_eq!(idn.keys.len(), 2);
    assert_eq!(idn.rot.len(), 1);
    assert_eq!(hex(&idn.signer), new);
    let st = b.c.status();
    assert_eq!(st["keys"].as_array().unwrap().len(), 2);
    assert_eq!(st["rotation"]["oldKid"], old);

    // 用新金鑰簽的資料照常同步
    b.data.set(vec![node_rec("104.16.1.1"), node_rec("104.16.1.5")]);
    b.c.refresh_share(now(), true);
    let res = sync(&a, "rb.test").await;
    assert_eq!(res["status"], "ok", "{res}");
    assert!(!a.peer("rb.test").my_block);

    // 錯過通知的好友：只記得舊金鑰 → 收到新金鑰簽的回應 → 重新讀身分文件、驗證輪替聲明 → 自動改用新金鑰
    wait_for("C 收到輪替通知", || c.peer("rb.test").keys.iter().any(|k| k.kid == new)).await;
    c.c.with_peer("rb.test", |p| {
        p.keys.retain(|k| k.kid == old);
        p.keys[0].until = None;
    });
    let res = sync(&c, "rb.test").await;
    assert_eq!(res["ok"], true, "{res}");
    assert!(c.peer("rb.test").keys.iter().any(|k| k.kid == new));
    assert!(!c.peer("rb.test").my_block);

    // 金鑰變更、沒有舊金鑰的簽名（例如舊金鑰遺失）：好友要人工確認，不封鎖
    let stranger = KeyPair::generate();
    a.c.with_peer("rb.test", |p| {
        p.keys = vec![PeerKey {
            kid: hex(&stranger.kid),
            public: b64(&stranger.public),
            since: 0,
            until: None,
        }];
    });
    let res = sync(&a, "rb.test").await;
    assert_eq!(res["ok"], false, "{res}");
    let p = a.peer("rb.test");
    assert_eq!(p.rel, Rel::Friend, "保留原本的好友狀態");
    assert!(!p.my_block);
    assert_eq!(p.pending_key.as_ref().map(|k| k.kid.clone()), Some(new.clone()));
    let peers = a.c.admin("/api/community/peers", &HashMap::new()).await.unwrap();
    assert!(peers
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x["domain"] == "rb.test" && x["pendingKey"]["kid"] == new));
    let q: HashMap<String, String> = [("domain".to_string(), "rb.test".to_string())].into();
    let res = a.c.admin("/api/community/accept-key", &q).await.unwrap();
    assert_eq!(res["ok"], true, "{res}");
    let res = sync(&a, "rb.test").await;
    assert_eq!(res["ok"], true, "{res}");
    assert!(a.peer("rb.test").pending_key.is_none());
}
