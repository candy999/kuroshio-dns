//! 增量同步、poke、epoch 重置後的完整同步、刪除標記、互相檢查狀態（自動重新請求一次）、資料品質暫停

mod common;

use common::*;
use kuroshio_community::peers::Rel;
use kuroshio_community::{Kind, Outcome};
use serde_json::json;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn incremental_sync_and_poke() {
    let r = resolver(&[]);
    let a = node("sa.test", &r, Spec::default()).await;
    let b = node(
        "sb.test",
        &r,
        Spec {
            rules: vec![json!({ "action": "accept", "domain_suffix": ["test"] })],
            ..Default::default()
        },
    )
    .await;
    b.data.set(vec![
        node_rec("104.16.1.1"),
        node_rec("104.16.1.2"),
        site_rec("example.com", "104.16.2.2"),
    ]);

    let res = a.c.send_request(&b.input(), true).await;
    assert_eq!(res["status"], "accepted", "自動同意：{res}");
    wait_for("第一次完整同步", || {
        a.data.received.lock().unwrap().iter().any(|x| x.full && x.nodes.len() == 2)
    })
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    a.data.take();
    assert_eq!(a.peer("sb.test").channel.as_deref(), Some("doq"), "預設先用 DoQ");

    // B 的資料變了：加一筆、刪一筆 → poke → A 在 1–5 分鐘（測試縮短）內來拉，只拿到變動
    b.data.set(vec![
        node_rec("104.16.1.1"),
        node_rec("104.16.1.3"),
        site_rec("example.com", "104.16.2.2"),
    ]);
    assert!(b.c.refresh_share(now(), true));
    assert!(b.c.poke("sa.test", "data").await);
    wait_for("poke 後來拉", || !a.data.received.lock().unwrap().is_empty()).await;
    let got = a.data.take();
    assert!(!got[0].full, "增量");
    assert_eq!(
        got[0].nodes.iter().map(|n| n.ip.to_string()).collect::<Vec<_>>(),
        vec!["104.16.1.3"]
    );
    assert_eq!(got[0].deleted, vec![("node".to_string(), "cloudflare/104.16.1.2".to_string())]);
    assert!(got[0].sites.is_empty(), "沒變的不重送");
    // 資料 poke 每個好友最多 10 分鐘一次
    assert!(!b.c.poke("sa.test", "data").await);

    // 沒變 → unchanged
    let res = sync(&a, "sb.test").await;
    assert_eq!(res["status"], "unchanged", "{res}");

    // epoch 重置（state 遺失）→ 下次拿完整集合
    b.c.reset_share();
    b.c.refresh_share(now(), true);
    let res = sync(&a, "sb.test").await;
    assert_eq!(res["full"], true, "{res}");
    assert_eq!(res["upserts"], 3);
    let h = a.c.site_hints("example.com", "cloudflare", 4);
    assert_eq!(h[0].ip.to_string(), "104.16.2.2");

    // 資料品質：A 驗證 B 的網站提示一直失敗 → 低於 minHitRate 而且試過 20 次 → 暫停採用（不封鎖）
    let mut cfg = a.c.config();
    cfg.min_hit_rate = 0.5;
    a.c.set_config(cfg);
    for _ in 0..20 {
        a.c.report(&["sb.test".to_string()], Kind::Site, Outcome::Fail);
    }
    let p = a.peer("sb.test");
    assert!(p.score["site"].paused);
    assert!(!p.my_block);
    assert_eq!(p.rel, Rel::Friend);
    assert!(
        a.c.site_hints("example.com", "cloudflare", 4).is_empty(),
        "暫停期間不用這個好友的網站提示"
    );
    let scores = a.c.admin("/api/community/scores", &Default::default()).await.unwrap();
    assert_eq!(scores["peers"][0]["kinds"]["site"]["paused"], true);
    // 恢復
    for _ in 0..60 {
        a.c.report(&["sb.test".to_string()], Kind::Site, Outcome::Ok);
    }
    assert!(!a.peer("sb.test").score["site"].paused);
    assert_eq!(a.c.site_hints("example.com", "cloudflare", 4).len(), 1);

    // 互相檢查狀態（7.5）：A 遺失了好友狀態 → B 同步時 A 回 not-friend → B 用 relation 對一次 →
    // B 改成非好友並自動重新請求一次（每個 pairId 只一次）→ A 沒有墓碑、沒有規則 → 等待人工審核
    let old_pair = b.peer("sa.test").pair_id.clone();
    a.c.with_peer("sb.test", |p| {
        p.rel = Rel::None;
        p.pair_id = None;
    });
    let res = sync(&b, "sa.test").await;
    assert_eq!(res["ok"], false, "{res}");
    assert_ne!(b.peer("sa.test").rel, Rel::Friend);
    assert_eq!(b.peer("sa.test").auto_req_pair, old_pair);
    wait_for("B 自動重新請求", || {
        a.c.peer("sb.test").map(|p| p.rel == Rel::In).unwrap_or(false)
    })
    .await;
    // 同一個配對不會再自動請求第二次
    let res = a.c.decide("sb.test", "accept").await;
    assert_eq!(res["status"], "accepted");
    assert_eq!(b.peer("sa.test").rel, Rel::Friend);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tick_refreshes_and_pokes() {
    let r = resolver(&[]);
    let a = node("ta.test", &r, Spec::default()).await;
    let mut tuning = fast_tuning();
    tuning.share_refresh_ms = 0;
    let b = node(
        "tb.test",
        &r,
        Spec {
            rules: vec![json!({ "action": "accept" })],
            tuning,
            ..Default::default()
        },
    )
    .await;
    b.data.set(vec![node_rec("104.16.1.1")]);
    let res = a.c.send_request(&b.input(), true).await;
    assert_eq!(res["status"], "accepted", "{res}");
    wait_for("第一次同步", || a.data.received.lock().unwrap().iter().any(|x| x.full)).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    a.data.take();
    // 定時工作：分享集合有變動 → poke 好友 → 好友來拉
    b.data.set(vec![node_rec("104.16.1.1"), node_rec("104.16.1.9")]);
    b.c.tick().await;
    wait_for("tick 之後好友來拉", || !a.data.received.lock().unwrap().is_empty()).await;
    let got = a.data.take();
    assert_eq!(
        got[0].nodes.iter().map(|n| n.ip.to_string()).collect::<Vec<_>>(),
        vec!["104.16.1.9"]
    );
    // 快照可以寫回再讀：epoch / seq 不變，好友不必重拿完整集合
    let snaps = b.c.snapshots();
    let share = snaps.iter().find(|(p, _)| p == "community/share.cbor").unwrap();
    let back = kuroshio_community::share::ShareSet::load(&share.1).unwrap();
    assert_eq!(back.len(), 2);
}
