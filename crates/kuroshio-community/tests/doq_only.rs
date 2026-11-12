//! 只剩 QUIC（DoQ 埠，ALPN kuroshio/2）：HTTPS 與 DoT 都不通時，好友之間一律走 DoQ
//!
//! - 第一次連線（還沒有對方的身分文件）依 HTTPS → DoT → DoQ 試，前兩個失敗就用 DoQ
//! - 加好友、對方回連驗證、同步、邀請碼全部經 DoQ 完成，記下的管道是 doq
//! - 同一個測試程式裡有好幾個 `#[tokio::test]`（各自的 runtime）：QUIC 用戶端端點跟著 runtime 走，
//!   前一個測試的 runtime 結束後，後面的測試還是能用 DoQ

mod common;

use common::*;
use kuroshio_community::peers::Rel;
use kuroshio_community::{Endpoint, Scheme, StaticResolver};
use serde_json::json;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncReadExt;

/// 只公告 DoQ，HTTPS / DoT 監聽連上就斷
async fn doq_node(domain: &str, r: &Arc<StaticResolver>) -> Node {
    let n = node(
        domain,
        r,
        Spec {
            channels: vec![Scheme::Doq],
            rules: vec![json!({ "action": "accept" })],
            ..Default::default()
        },
    )
    .await;
    n.faults.tcp_down.store(true, Ordering::SeqCst);
    n
}

/// 在 DoQ 的埠號上也開一個 TCP 監聽：記下依序連進來的是 HTTPS（ALPN http/1.1）還是 DoT（ALPN kuroshio/2），連上就斷
async fn watch_tcp(port: u16) -> Arc<Mutex<Vec<&'static str>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let l = tokio::net::TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    let s = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = l.accept().await {
            let mut buf = vec![0u8; 4096];
            let n = tokio::time::timeout(Duration::from_secs(2), tcp.read(&mut buf))
                .await
                .ok()
                .and_then(|r| r.ok())
                .unwrap_or(0);
            let hello = &buf[..n];
            let has = |p: &[u8]| hello.windows(p.len()).any(|w| w == p);
            s.lock().unwrap().push(if has(b"kuroshio/2") {
                "dot"
            } else if has(b"http/1.1") {
                "https"
            } else {
                "?"
            });
        }
    });
    seen
}

#[test]
fn first_contact_order_is_https_dot_doq() {
    let v: Vec<Scheme> = Endpoint::defaults("x.test", Some(8853)).iter().map(|e| e.scheme).collect();
    assert_eq!(v, [Scheme::Https, Scheme::Dot, Scheme::Doq]);
    assert!(Endpoint::defaults("x.test", Some(8853)).iter().all(|e| e.port == 8853));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn add_by_domain_over_doq_only() {
    let r = resolver(&[]);
    let a = doq_node("qa.test", &r).await;
    let b = doq_node("qb.test", &r).await;
    a.data.set(vec![node_rec("104.16.1.1")]);
    b.data.set(vec![node_rec("104.16.2.2")]);
    let seen = watch_tcp(b.doq).await;

    // 輸入「網域:埠」：HTTPS、DoT、DoQ 都用這個埠；前兩個不通 → DoQ
    let res = a.c.send_request(&format!("qb.test:{}", b.doq), true).await;
    assert_eq!(res["status"], "accepted", "{res}");
    assert_eq!(*seen.lock().unwrap(), ["https", "dot"], "先試 HTTPS、再試 DoT，最後才是 DoQ");
    assert_eq!(a.peer("qb.test").rel, Rel::Friend);
    assert_eq!(b.peer("qa.test").rel, Rel::Friend, "B 經 DoQ 回連 A 驗證身分");
    assert_eq!(a.peer("qb.test").channel.as_deref(), Some("doq"));
    assert_eq!(a.peer("qb.test").endpoints, vec![format!("doq://qb.test:{}", b.doq)]);

    // 同步（雙向）都經 DoQ
    let res = sync(&a, "qb.test").await;
    assert_eq!(res["ok"], true, "{res}");
    let res = sync(&b, "qa.test").await;
    assert_eq!(res["ok"], true, "{res}");
    assert_eq!(b.peer("qa.test").channel.as_deref(), Some("doq"));
    wait_for("A 收到 B 的資料", || {
        a.data.received.lock().unwrap().iter().any(|x| x.from == "qb.test")
    })
    .await;
    wait_for("B 收到 A 的資料", || {
        b.data.received.lock().unwrap().iter().any(|x| x.from == "qa.test")
    })
    .await;
    // 拿到身分文件之後不再試 HTTPS / DoT（對方只公告 DoQ）
    assert_eq!(seen.lock().unwrap().len(), 2);

    // 刪除也經 DoQ 通知對方
    let q = [("domain".to_string(), "qb.test".to_string())].into();
    let res = a.c.admin("/api/community/delete", &q).await.unwrap();
    assert_eq!(res["ok"], true, "{res}");
    wait_for("B 知道被刪除", || b.peer("qa.test").rel != Rel::Friend).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invite_over_doq_only() {
    let r = resolver(&[]);
    let a = doq_node("qia.test", &r).await;
    let b = doq_node("qib.test", &r).await;
    a.data.set(vec![node_rec("104.16.3.3")]);
    let v = a.c.invite_json();
    assert_eq!(v["ok"], true, "{v}");
    let code = v["code"].as_str().unwrap().to_string();
    let res = b.c.use_invite(&code).await;
    assert_eq!(res["ok"], true, "{res}");
    assert_eq!(res["stage"], "accepted", "{res}");
    assert_eq!(a.peer("qib.test").rel, Rel::Friend);
    assert_eq!(b.peer("qia.test").channel.as_deref(), Some("doq"));
    wait_for("B 收到 A 的資料", || {
        b.data.received.lock().unwrap().iter().any(|x| x.from == "qia.test")
    })
    .await;
}
