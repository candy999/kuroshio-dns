//! 整合測試：假上游 + 實際監聽，經 UDP / TCP 查詢

use serde_json::json;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// 假上游：回答 A 1.2.3.4；名稱是 big.test 時回超過 512 bytes 的回應
async fn fake_upstream() -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let (n, peer) = s.recv_from(&mut buf).await.unwrap();
            let q = &buf[..n];
            let qs = kuroshio_proto::question(q).unwrap();
            let mut r = q[..qs.end].to_vec();
            r[2] = 0x81;
            r[3] = 0x80;
            r[10..12].copy_from_slice(&[0, 0]); // 查詢帶 EDNS，回應不帶
            let count: u16 = if qs.name == "big.test" { 60 } else { 1 };
            r[6..8].copy_from_slice(&count.to_be_bytes());
            for i in 0..count {
                r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, (4 + i) as u8]);
            }
            s.send_to(&r, peer).await.unwrap();
        }
    });
    addr
}

fn cfg(upstreams: Vec<String>) -> serde_json::Value {
    let state = std::env::temp_dir().join(format!("kuroshio-test-state-{}", std::process::id()));
    kuroshio_config::with_overrides(&json!({
        "admin": { "port": 0, "auth": false },
        "filter": { "enabled": false },
        "system": { "persistDir": state.to_string_lossy() },
        "listen": { "plain": { "binds": ["127.0.0.1"], "port": 0 } },
        "upstream": { "pinned": upstreams, "fallback": [] },
        "resolver": { "timeoutMs": 800, "lastResort": [], "rankIps": false }
    }))
}

#[tokio::test]
async fn udp_and_tcp_forwarding() {
    let up = fake_upstream().await;
    // 一個會逾時的上游 + 一個正常的：並行查詢，正常的那個勝出
    let started = kuroshio::app::start(
        &cfg(vec!["udp://127.0.0.1:9".into(), format!("udp://{up}")]),
        kuroshio_config::Tier::Large,
    )
    .await
    .unwrap();
    let addr = started.bound[0];

    let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let q = kuroshio_proto::build_query(0x4242, "example.test", 1);
    c.send_to(&q, addr).await.unwrap();
    let mut buf = [0u8; 1500];
    let (n, _) = c.recv_from(&mut buf).await.unwrap();
    let h = kuroshio_proto::header(&buf[..n]).unwrap();
    assert_eq!((h.id, h.rcode, h.ancount), (0x4242, 0, 1));
    assert!(kuroshio_proto::matches(&q, &buf[..n]));

    // 超過 512 bytes：UDP 回 TC，TCP 拿到完整回應
    let big = kuroshio_proto::build_query(7, "big.test", 1);
    c.send_to(&big, addr).await.unwrap();
    let (n, _) = c.recv_from(&mut buf).await.unwrap();
    assert!(kuroshio_proto::header(&buf[..n]).unwrap().tc);

    let mut t = TcpStream::connect(started.bound[1]).await.unwrap();
    let mut msg = (big.len() as u16).to_be_bytes().to_vec();
    msg.extend_from_slice(&big);
    t.write_all(&msg).await.unwrap();
    let len = t.read_u16().await.unwrap() as usize;
    let mut r = vec![0u8; len];
    t.read_exact(&mut r).await.unwrap();
    assert_eq!(kuroshio_proto::header(&r).unwrap().ancount, 60);
}

#[tokio::test]
async fn all_upstreams_down_gives_servfail() {
    let started = kuroshio::app::start(&cfg(vec!["udp://127.0.0.1:9".into()]), kuroshio_config::Tier::Large)
        .await
        .unwrap();
    let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    c.send_to(&kuroshio_proto::build_query(1, "x.test", 1), started.bound[0])
        .await
        .unwrap();
    let mut buf = [0u8; 512];
    let (n, _) = c.recv_from(&mut buf).await.unwrap();
    assert_eq!(kuroshio_proto::header(&buf[..n]).unwrap().rcode, kuroshio_proto::RCODE_SERVFAIL);
}

#[tokio::test]
async fn acl_drops_unlisted_sources() {
    let up = fake_upstream().await;
    let mut c = cfg(vec![format!("udp://{up}")]);
    c["listen"]["plain"]["allowFrom"] = json!(["10.0.0.0/8"]);
    let started = kuroshio::app::start(&c, kuroshio_config::Tier::Large).await.unwrap();
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.send_to(&kuroshio_proto::build_query(1, "x.test", 1), started.bound[0])
        .await
        .unwrap();
    let mut buf = [0u8; 512];
    let r = tokio::time::timeout(std::time::Duration::from_millis(500), s.recv_from(&mut buf)).await;
    assert!(r.is_err(), "不在允許清單的來源不應該收到回應");
}

#[tokio::test]
async fn tiny_tier_asks_two_upstreams_then_hedges() {
    // tiny：只同時問 2 個；前兩個都是會逾時的位址，第三個正常的要在 300 ms 後被加問，仍然拿到答案
    let up = fake_upstream().await;
    let mut c = cfg(vec!["udp://127.0.0.1:9".into(), "udp://127.0.0.1:7".into(), format!("udp://{up}")]);
    c["resolver"]["parallel"] = json!(2);
    c["resolver"]["timeoutMs"] = json!(2000);
    let started = kuroshio::app::start(&c, kuroshio_config::Tier::Tiny).await.unwrap();
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let t0 = std::time::Instant::now();
    s.send_to(&kuroshio_proto::build_query(3, "hedge.test", 1), started.bound[0])
        .await
        .unwrap();
    let mut buf = [0u8; 512];
    let (n, _) = tokio::time::timeout(std::time::Duration::from_secs(3), s.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(kuroshio_proto::header(&buf[..n]).unwrap().rcode, 0);
    assert!(
        t0.elapsed() < std::time::Duration::from_millis(1500),
        "失敗或 300 ms 後就要加問，不能等到逾時"
    );
}

#[tokio::test]
async fn udp_truncation_follows_client_edns_size() {
    use kuroshio_proto::message::{Message, Opt, FLAG_TC};
    let up = fake_upstream().await;
    let started = kuroshio::app::start(&cfg(vec![format!("udp://{up}")]), kuroshio_config::Tier::Large)
        .await
        .unwrap();
    let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let ask = |id: u16, size: Option<u16>| {
        let mut m = Message::parse(&kuroshio_proto::build_query(id, "big.test", 1)).unwrap();
        m.opt = size.map(|udp_size| Opt {
            udp_size,
            ..Default::default()
        });
        m.encode()
    };
    let mut buf = [0u8; 4096];
    // big.test 的完整回應大約 1000 bytes。用戶端宣告只能收 600：要回 TC（原本只要有 EDNS 就一律塞到 1232）
    c.send_to(&ask(1, Some(600)), started.bound[0]).await.unwrap();
    let (n, _) = c.recv_from(&mut buf).await.unwrap();
    let m = Message::parse(&buf[..n]).unwrap();
    assert!(m.flags & FLAG_TC != 0, "超過用戶端宣告的大小要截斷");
    assert!(m.answers.is_empty() && n <= 600);
    assert_eq!(m.id, 1);
    assert!(m.opt.is_some(), "查詢有 EDNS，截斷的回應也帶 OPT");
    // 宣告 4096：放得進 1232，完整回應
    c.send_to(&ask(2, Some(4096)), started.bound[0]).await.unwrap();
    let (n, _) = c.recv_from(&mut buf).await.unwrap();
    let m = Message::parse(&buf[..n]).unwrap();
    assert_eq!((m.flags & FLAG_TC, m.answers.len()), (0, 60));
    assert!(n > 600 && n <= 1232);
    // 沒有 EDNS：512
    c.send_to(&ask(3, None), started.bound[0]).await.unwrap();
    let (n, _) = c.recv_from(&mut buf).await.unwrap();
    let m = Message::parse(&buf[..n]).unwrap();
    assert!(m.flags & FLAG_TC != 0 && m.opt.is_none() && n <= 512);
}
