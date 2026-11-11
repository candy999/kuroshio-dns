//! DoT / DoH 伺服器：自簽憑證、實際查詢、GET / POST、純 HTTP（反向代理）、憑證熱更新

use kuroshio::upstream::Upstream;
use kuroshio_proto::message::{Message, RData, Record};
use rustls::pki_types::CertificateDer;
use serde_json::json;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

async fn upstream() -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let (len, peer) = s.recv_from(&mut buf).await.unwrap();
            let q = Message::parse(&buf[..len]).unwrap();
            let mut r = Message::response_to(&q, 0);
            r.opt = None;
            r.answers.push(Record::a(&q.questions[0].name, 120, Ipv4Addr::new(9, 8, 7, 6)));
            let _ = s.send_to(&r.encode(), peer).await;
        }
    });
    addr
}

fn write_cert(dir: &std::path::Path) -> CertificateDer<'static> {
    let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into(), "localhost".into()]).unwrap();
    std::fs::write(dir.join("cert.pem"), ck.cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), ck.key_pair.serialize_pem()).unwrap();
    CertificateDer::from(ck.cert.der().to_vec())
}

fn q(id: u16, name: &str) -> Vec<u8> {
    kuroshio_proto::build_query(id, name, 1)
}

#[tokio::test]
async fn dot_and_doh_serve_queries() {
    let dir = std::env::temp_dir().join(format!("kuroshio-enc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("state")).unwrap();
    let der = write_cert(&dir);
    kuroshio::tls::add_root(der);
    let up = upstream().await;
    let cfg = kuroshio_config::with_overrides(&json!({
        "system": { "persistDir": dir.join("state").to_string_lossy() },
        "admin": { "port": 0, "auth": false }, "filter": { "enabled": false },
        "listen": {
            "plain": { "binds": ["127.0.0.1"], "port": 0 },
            "dot": { "enabled": true, "host": "127.0.0.1", "port": 0, "cert": "./cert.pem", "key": "./key.pem" },
            "doh": { "enabled": true, "host": "127.0.0.1", "port": 0, "cert": "./cert.pem", "key": "./key.pem", "trustProxy": false, "http3": true },
            "doq": { "enabled": true, "host": "127.0.0.1", "port": 0 },
            "ddr": true
        },
        "site": { "hostname": "dns.example.test" },
        "upstream": { "pinned": [format!("udp://{up}")], "fallback": [] },
        // 關掉快速回應：第一個回應就是正式結果（快速回應的 TTL 最多 10 秒）
        "resolver": { "lastResort": [], "rankIps": false, "fastPath": false }
    }));
    let started = kuroshio::app::start(&cfg).await.unwrap();
    let dot = started.encrypted.dot.expect("DoT 有啟動");
    let doh = started.encrypted.doh.expect("DoH 有啟動");

    // DoT：同一條連線同時多筆
    let u = Upstream::parse(&format!("tls://{dot}")).unwrap();
    let mut set = tokio::task::JoinSet::new();
    for i in 0..10u16 {
        let u = u.clone();
        set.spawn(async move { Message::parse(&u.exchange(&q(i, &format!("d{i}.test")), Duration::from_secs(3)).await.unwrap()).unwrap() });
    }
    while let Some(m) = set.join_next().await {
        assert_eq!(m.unwrap().answers[0].data, RData::A(Ipv4Addr::new(9, 8, 7, 6)));
    }
    // DoH（HTTP/2 POST）
    let u = Upstream::parse(&format!("https://{doh}/dns-query")).unwrap();
    let m = Message::parse(&u.exchange(&q(7, "h.test"), Duration::from_secs(3)).await.unwrap()).unwrap();
    assert_eq!((m.id, m.answers.len()), (7, 1));
    // DoH GET ?dns=（HTTP/1.1，自己發請求）
    let tls = kuroshio::tls::connect_h1("127.0.0.1", doh.port(), Duration::from_secs(3))
        .await
        .unwrap();
    let mut tls = tls;
    let b64 = base64url(&q(0, "g.test"));
    tls.write_all(format!("GET /dns-query?dns={b64} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut out = Vec::new();
    tls.read_to_end(&mut out).await.ok();
    let text = String::from_utf8_lossy(&out);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    let lower = text.to_ascii_lowercase();
    let age: u32 = lower
        .split("cache-control: max-age=")
        .nth(1)
        .and_then(|r| r.split_whitespace().next())
        .and_then(|v| v.parse().ok())
        .expect("有 cache-control");
    assert!((110..=120).contains(&age), "max-age = 答案剩餘 TTL：{age}");
    let doh3 = started.encrypted.doh3.expect("DoH3 有啟動");
    assert!(
        lower.contains(&format!("alt-svc: h3=\":{}\"", doh3.port())),
        "DoH 回應告訴用戶端有 HTTP/3：{lower}"
    );

    // DoQ：同一條 QUIC 連線多筆查詢
    let doq = started.encrypted.doq.expect("DoQ 有啟動");
    let u = Upstream::parse(&format!("quic://{doq}")).unwrap();
    let mut set = tokio::task::JoinSet::new();
    for i in 0..10u16 {
        let u = u.clone();
        set.spawn(async move {
            Message::parse(
                &u.exchange(&q(100 + i, &format!("q{i}.test")), Duration::from_secs(3))
                    .await
                    .unwrap(),
            )
            .unwrap()
        });
    }
    while let Some(m) = set.join_next().await {
        let m = m.unwrap();
        assert!(m.id >= 100, "id 改回原本的");
        assert_eq!(m.answers[0].data, RData::A(Ipv4Addr::new(9, 8, 7, 6)));
    }
    // DoH3
    let u = Upstream::parse(&format!("h3://{doh3}/dns-query")).unwrap();
    for i in 0..3u16 {
        let m = Message::parse(&u.exchange(&q(200 + i, "h3.test"), Duration::from_secs(3)).await.unwrap()).unwrap();
        assert_eq!((m.id, m.answers.len()), (200 + i, 1));
    }
    // 其他路徑 404
    let tls = kuroshio::tls::connect_h1("127.0.0.1", doh.port(), Duration::from_secs(3))
        .await
        .unwrap();
    let mut tls = tls;
    tls.write_all(b"GET /admin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    tls.read_to_end(&mut out).await.ok();
    assert!(String::from_utf8_lossy(&out).starts_with("HTTP/1.1 404"));

    // DDR：區網查 _dns.resolver.arpa SVCB → 列出 DoH(h2,h3)、DoT、DoQ
    let plain = started.bound[0];
    let ddr = kuroshio::upstream::Upstream::parse(&format!("udp://{plain}")).unwrap();
    let m = Message::parse(
        &ddr.exchange(&kuroshio_proto::build_query(5, "_dns.resolver.arpa", 64), Duration::from_secs(2))
            .await
            .unwrap(),
    )
    .unwrap();
    // 測試裡 DoH 與 DoH3 是不同的隨機埠，所以分成兩筆（同埠時合併成 alpn=h2,h3）
    assert_eq!(m.answers.len(), 4, "DoH、DoH3、DoT、DoQ");
    let RData::Raw(first) = &m.answers[0].data else { panic!() };
    assert!(first.windows(4).any(|w| w == b"\x02h2\x00"), "第一筆是 DoH h2");
    assert!(first.ends_with(b"/dns-query{?dns}"));
    let RData::Raw(last) = &m.answers[3].data else { panic!() };
    assert!(last.windows(4).any(|w| w == b"\x03doq"), "最後一筆是 DoQ");

    // Padding：用戶端要求補齊 → DoT 回應補到 468 的倍數
    let mut pq = Message::parse(&q(9, "pad.test")).unwrap();
    pq.opt = Some(kuroshio_proto::message::Opt {
        udp_size: 1232,
        options: vec![(kuroshio_proto::message::opt_code::PADDING, vec![])],
        ..Default::default()
    });
    let u = Upstream::parse(&format!("tls://{dot}")).unwrap();
    let resp = u.exchange(&pq.encode(), Duration::from_secs(3)).await.unwrap();
    assert_eq!(resp.len() % 468, 0, "回應長度 {}", resp.len());
    std::fs::remove_dir_all(&dir).unwrap();
}

fn base64url(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..=c.len() {
            out.push(T[(n >> (18 - 6 * i)) as usize & 63] as char);
        }
    }
    out
}

#[tokio::test]
async fn plain_http_doh_behind_proxy() {
    let dir = std::env::temp_dir().join(format!("kuroshio-enc-plain-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let up = upstream().await;
    let cfg = kuroshio_config::with_overrides(&json!({
        "system": { "persistDir": dir.join("state").to_string_lossy() },
        "admin": { "port": 0, "auth": false }, "filter": { "enabled": false },
        "listen": { "plain": { "binds": ["127.0.0.1"], "port": 0 }, "doh": { "enabled": true, "host": "127.0.0.1", "port": 0, "cert": "", "key": "", "trustProxy": true } },
        "upstream": { "pinned": [format!("udp://{up}")], "fallback": [] },
        "resolver": { "lastResort": [], "rankIps": false }
    }));
    let started = kuroshio::app::start(&cfg).await.unwrap();
    let doh = started.encrypted.doh.unwrap();
    let body = q(3, "p.test");
    let mut s = tokio::net::TcpStream::connect(doh).await.unwrap();
    s.write_all(
        format!("POST /dns-query HTTP/1.1\r\nHost: dns.example\r\nX-Forwarded-For: 203.0.113.9\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())
            .as_bytes(),
    )
    .await
    .unwrap();
    s.write_all(&body).await.unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    let p = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    assert!(out.starts_with(b"HTTP/1.1 200"));
    assert_eq!(Message::parse(&out[p..]).unwrap().id, 3);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cert_hot_reload() {
    let dir = std::env::temp_dir().join(format!("kuroshio-cert-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let store = kuroshio::encrypted::CertStore::new(dir.join("cert.pem"), dir.join("key.pem"));
    assert!(!store.ready(), "檔案還沒有");
    let a = write_cert(&dir);
    assert!(store.reload());
    std::thread::sleep(Duration::from_millis(1100));
    let b = write_cert(&dir);
    assert_ne!(a, b);
    assert!(store.reload(), "換新憑證");
    // 壞掉的檔案：保留舊的
    std::thread::sleep(Duration::from_millis(1100));
    std::fs::write(dir.join("cert.pem"), "garbage").unwrap();
    assert!(store.reload());
    std::fs::remove_dir_all(&dir).unwrap();
}
