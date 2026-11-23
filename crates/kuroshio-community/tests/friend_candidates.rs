//! 好友給的資料只當候選：全部好友的資料合計有上限（節點、上游先收）；使用者可以選擇不用好友的
//! CDN 資料（`useHints`）或上游（`useUpstreams`）

mod common;

use common::*;
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn friend_records_budget_and_use_switches() {
    let r = resolver(&[]);
    // 好友資料上限 1 MB → 全部好友合計最多 1024 筆
    let a = node(
        "fa.test",
        &r,
        Spec {
            max_bundle_mb: 1,
            ..Default::default()
        },
    )
    .await;
    let b = node(
        "fb.test",
        &r,
        Spec {
            rules: vec![json!({ "action": "accept", "domain_suffix": ["test"] })],
            ..Default::default()
        },
    )
    .await;
    let mut recs: Vec<_> = (0..1100).map(|i| site_rec(&format!("s{i}.example.com"), "104.16.2.2")).collect();
    recs.push(node_rec("104.16.1.1"));
    recs.push(node_rec("104.16.1.2"));
    recs.push(upstream_rec("https://dns.example.net/dns-query", "doh"));
    b.data.set(recs);

    let res = a.c.send_request(&b.input(), true).await;
    assert_eq!(res["status"], "accepted", "{res}");
    wait_for("第一次完整同步", || a.data.received.lock().unwrap().iter().any(|x| x.full)).await;
    let got = a.data.take();
    let full = got.iter().find(|x| x.full).unwrap();
    assert_eq!(full.nodes.len(), 2, "節點先收");
    assert_eq!(full.upstreams.len(), 1, "上游先收");
    assert_eq!(full.nodes.len() + full.upstreams.len() + full.sites.len(), 1024, "合計不超過上限");
    let st = a.c.status();
    assert_eq!(st["hints"]["domains"], 1021);
    assert_eq!(a.c.upstream_candidates(), vec!["https://dns.example.net/dns-query".to_string()]);
    assert_eq!(a.c.site_hints("s0.example.com", "cloudflare", 4).len(), 1);

    // 不用好友的 CDN 資料與上游：提示、上游候選都拿不到；同步照常（資料照存，重新打開馬上可以用）
    let mut cfg = a.c.config();
    cfg.use_hints = false;
    cfg.use_upstreams = false;
    a.c.set_config(cfg);
    assert!(a.c.site_hints("s0.example.com", "cloudflare", 4).is_empty());
    assert!(a.c.cross_hint("s0.example.com").is_none());
    assert!(a.c.upstream_candidates().is_empty());
    let snap =
        a.c.snapshots()
            .into_iter()
            .find(|(p, _)| p == "community/upstream-candidates.json")
            .unwrap()
            .1;
    let v: serde_json::Value = serde_json::from_slice(&snap).unwrap();
    assert_eq!(v["ids"], json!([]), "每日評測拿不到好友的上游");
    // 新同步到的節點、上游不交給 CDN / 評測
    b.data.set(vec![
        node_rec("104.16.1.3"),
        upstream_rec("https://dns2.example.net/dns-query", "doh"),
    ]);
    assert!(b.c.refresh_share(now(), true));
    // b 換了內容會通知 a，a 可能已經自己拉過（這時手動同步回 unchanged）：兩種都表示新內容已經同步過
    let res = sync(&a, "fb.test").await;
    assert!(matches!(res["status"].as_str(), Some("ok" | "unchanged")), "{res}");
    let got = a.data.take();
    assert!(got
        .iter()
        .all(|x| x.nodes.is_empty() && x.upstreams.is_empty() && x.sites.is_empty()));

    // 重新打開
    let mut cfg = a.c.config();
    cfg.use_hints = true;
    cfg.use_upstreams = true;
    a.c.set_config(cfg);
    assert_eq!(a.c.upstream_candidates(), vec!["https://dns2.example.net/dns-query".to_string()]);
}
