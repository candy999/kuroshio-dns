//! 兩節點整合測試（移植 2.x 的 test/community-test.js，改成 v2 協定）：
//! 加好友、同意、同步、刪除後自動重新請求一次與墓碑、拒絕 7 天、提早重送自動封鎖、雙方同時請求、
//! 偽造簽名自動封鎖、非好友同步、長期連不上自動刪除

mod common;

use common::*;
use kuroshio_community::peers::Rel;
use kuroshio_community::{Kind, Scheme};
use serde_json::json;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn friend_lifecycle() {
    let r = resolver(&["a.test", "b.test", "c.test"]);
    let a = node("a.test", &r, Spec::default()).await;
    let b = node(
        "b.test",
        &r,
        Spec {
            channels: vec![Scheme::Dot, Scheme::Https],
            ..Default::default()
        },
    )
    .await;
    b.data.set(vec![
        node_rec("104.16.1.1"),
        node_rec("8.8.8.8"),
        site_rec("example.com", "104.16.2.2"),
        upstream_rec("https://dns.example.net/dns-query", "doh"),
        upstream_rec("udp://10.0.0.1", "udp"),
    ]);

    // A 加 B 好友：B 沒有規則 → 等待人工審核
    let res = a.c.send_request(&b.input(), true).await;
    assert_eq!(res["status"], "pending", "{res}");
    assert_eq!(a.peer("b.test").rel, Rel::Out);
    let pb = b.peer("a.test");
    assert_eq!(pb.rel, Rel::In);
    assert!(pb.info.rtt_ms.is_some(), "B 有量到延遲");
    assert_eq!(pb.info.ip_match, Some(true), "來源 IP 在 a.test 的解析結果裡");
    assert_eq!(pb.info.has_txt, Some(false));
    assert_eq!(pb.info.asn, Some(3462));
    assert_eq!(pb.keys.len(), 1);
    assert_eq!(pb.keys[0].kid, kuroshio_community::util::hex(&a.c.kid()));

    // B 同意 → relation 通知 A → 雙方成為好友（同一個配對編號）
    let res = b.c.decide("a.test", "accept").await;
    assert_eq!(res["status"], "accepted");
    assert_eq!(a.peer("b.test").rel, Rel::Friend);
    assert_eq!(a.peer("b.test").pair_id, b.peer("a.test").pair_id);

    // 成為好友後自動拉一次資料：範圍外的 IP 當待驗證候選，私有位址的上游算 invalid
    wait_for("A 收到 B 的資料", || {
        a.data.received.lock().unwrap().iter().any(|x| x.from == "b.test" && x.full)
    })
    .await;
    let got = a.data.take();
    let full = got.iter().find(|x| x.full).unwrap();
    let mut nodes: Vec<(String, bool)> = full.nodes.iter().map(|n| (n.ip.to_string(), n.in_range)).collect();
    nodes.sort();
    assert_eq!(nodes, vec![("104.16.1.1".to_string(), true), ("8.8.8.8".to_string(), false)]);
    assert_eq!(
        full.upstreams.iter().map(|u| u.url.as_str()).collect::<Vec<_>>(),
        vec!["https://dns.example.net/dns-query"]
    );
    assert_eq!(full.ctx.colo, "TPE");
    let s = a.peer("b.test").score;
    assert_eq!(s["upstream"].totals(now()), (0, 0, 1), "私有位址的上游記一次 invalid");
    assert!(!a.peer("b.test").my_block, "品質差不封鎖");
    assert_eq!(a.c.upstream_candidates(), vec!["https://dns.example.net/dns-query".to_string()]);

    // 網站驗證結果只用網域雜湊分享；查到該網站時拿得到好友驗證過的 IP
    let snap = b.c.snapshots().into_iter().find(|(p, _)| p == "community/share.cbor").unwrap().1;
    assert!(!snap.windows(11).any(|w| w == b"example.com"), "不含網站名稱");
    let h = a.c.site_hints("example.com", "cloudflare", 4);
    assert_eq!(h.len(), 1);
    assert_eq!(h[0].ip.to_string(), "104.16.2.2");
    assert_eq!(h[0].from, vec!["b.test".to_string()]);
    assert!(a.c.site_hints("example.com", "cloudfront", 4).is_empty());
    a.c.report(&h[0].from, Kind::Site, kuroshio_community::Outcome::Ok);
    assert_eq!(a.peer("b.test").score["site"].totals(now()).0, 1);

    // 資料沒變時回「未變更」
    tokio::time::sleep(Duration::from_millis(200)).await;
    let res = sync(&a, "b.test").await;
    assert_eq!(res["status"], "unchanged", "{res}");
    assert_eq!(a.peer("b.test").channel.as_deref(), Some("dot"), "B 沒有 DoQ：用 DoT");

    // B 加一條「自動同意 .test」規則；B 刪除 A → A 收到 relation → A 自動重新請求一次 → B 有墓碑，人工審核
    let mut cfg = b.c.config();
    cfg.rules = vec![json!({ "name": "測試網域", "action": "accept", "domain_suffix": ["test"] })];
    b.c.set_config(cfg);
    let res = b.c.remove_friend("a.test", false).await;
    assert_eq!(res["ok"], true);
    wait_for("A 自動重新請求", || {
        b.c.peer("a.test").map(|p| p.rel == Rel::In).unwrap_or(false)
    })
    .await;
    wait_for("A 收到「等待審核」", || a.peer("b.test").next_try > now()).await;
    assert_eq!(a.peer("b.test").rel, Rel::Out);
    let evs = b.c.events();
    let ev = evs.iter().find(|e| e.domain == "a.test" && e.kind == "收到好友請求").unwrap();
    assert!(ev.detail.contains("曾被你刪除"), "{ev:?}");

    // A 的請求還在等待時重送，不會產生新的請求事件
    let n = b.c.events().len();
    let res = a.c.send_request("b.test", false).await;
    assert_eq!(res["status"], "pending", "{res}");
    assert_eq!(b.c.events().len(), n);

    // B 拒絕 → A 記下 7 天內不能再請求，自動重送被擋
    let res = b.c.decide("a.test", "reject").await;
    assert_eq!(res["status"], "rejected");
    assert!(a.peer("b.test").their_reject_until > now() + 6 * 86_400_000);
    let res = a.c.send_request(&b.input(), false).await;
    assert_eq!(res["ok"], false);
    assert!(res["reason"].as_str().unwrap().contains("拒絕"), "{res}");

    // 拒絕期間硬是重送 3 次（手動按也會送出，對方照樣拒絕並計次）→ 自動封鎖
    for _ in 0..3 {
        a.c.send_request(&b.input(), true).await;
    }
    assert!(b.peer("a.test").my_block);
    assert!(a.peer("b.test").their_block, "A 知道被封鎖，不再請求");
    let res = a.c.send_request(&b.input(), false).await;
    assert!(res["reason"].as_str().unwrap().contains("封鎖"), "{res}");

    // 雙方同時請求 → 直接成為好友、配對編號一致
    let c = node(
        "c.test",
        &r,
        Spec {
            channels: vec![Scheme::Https],
            ..Default::default()
        },
    )
    .await;
    c.data.set(vec![node_rec("104.17.0.1")]);
    a.c.with_peer("c.test", |p| {
        p.rel = Rel::Out;
        p.out_req_id = Some("0123456789abcdef01234567".into());
    });
    let res = c.c.send_request(&a.input(), true).await;
    assert_eq!(res["status"], "accepted", "{res}");
    assert_eq!(a.peer("c.test").rel, Rel::Friend);
    assert_eq!(c.peer("a.test").rel, Rel::Friend);
    assert_eq!(a.peer("c.test").pair_id, c.peer("a.test").pair_id);
    let joint = kuroshio_community::peers::joint_pair_id("0123456789abcdef01234567", c.peer("a.test").out_req_id.as_deref().unwrap_or(""));
    let _ = joint;

    // 資料簽名被竄改（已驗證的好友管道）→ 視為冒用，自動封鎖
    tokio::time::sleep(Duration::from_millis(300)).await;
    c.faults.corrupt_sig.store(true, std::sync::atomic::Ordering::SeqCst);
    c.c.reset_share();
    let res = sync(&a, "c.test").await;
    assert_eq!(res["ok"], false, "{res}");
    assert!(a.peer("c.test").my_block);
    assert!(a.c.site_hints("x.com", "cloudflare", 4).is_empty());
    c.faults.corrupt_sig.store(false, std::sync::atomic::Ordering::SeqCst);

    // 非好友拉資料 → 回「不是好友」，對一次狀態後 B 改成非好友，不給資料
    b.c.unblock("a.test");
    b.data.take();
    b.c.with_peer("a.test", |p| {
        p.rel = Rel::Friend;
        p.pair_id = Some("forged-pair".into());
    });
    let res = sync(&b, "a.test").await;
    assert_eq!(res["ok"], false, "{res}");
    assert_ne!(b.peer("a.test").rel, Rel::Friend);
    assert!(b.data.take().iter().all(|x| x.from != "a.test"));

    // 好友長期連不上 → 自動刪除（不留刪除紀錄，回來時規則可以再自動同意）
    a.c.with_peer("old.test", |p| {
        p.rel = Rel::Friend;
        p.pair_id = Some("x".into());
        p.friend_since = now() - 30 * 86_400_000;
        p.last_contact = now() - 8 * 86_400_000;
    });
    a.c.maintain(now());
    assert_eq!(a.peer("old.test").rel, Rel::None);
    assert_eq!(a.peer("old.test").deleted_at, 0);

    // 管理 API 的格式（LuCI 用）
    let peers = a.c.admin("/api/community/peers", &Default::default()).await.unwrap();
    let pb = peers.as_array().unwrap().iter().find(|p| p["domain"] == "b.test").unwrap();
    for k in [
        "rel",
        "myBlock",
        "theirBlock",
        "fingerprint",
        "info",
        "stats",
        "scores",
        "channel",
        "keys",
        "ipMatch",
        "hasTxt",
        "lastSyncOk",
    ] {
        assert!(pb.get(k).is_some(), "peers 缺 {k}");
    }
    let st = a.c.admin("/api/community/status", &Default::default()).await.unwrap();
    assert_eq!(st["ready"], true);
    assert_eq!(st["txt"]["value"], a.c.txt_value());
    assert!(st["endpoints"]["doq"].as_str().unwrap().starts_with("doq://a.test:"));
    assert!(a.c.admin("/api/other", &Default::default()).await.is_none());
}
