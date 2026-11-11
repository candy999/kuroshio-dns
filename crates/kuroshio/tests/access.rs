//! 來源 IP 存取控制（規格 08）：實際的 DoT / DoH / DoQ / 區網 DNS 監聽拒絕不允許的來源
//!
//! 測試只能從 127.0.0.1 連線，所以用 `TEST_LOOPBACK_PUBLIC` 把迴路位址當成公網位址（只在這個測試行程裡）。
//! 這個檔案只有一個測試：情境依序執行，旗標的切換不會影響別的測試。

use kuroshio::ipfilter::{Kind, TEST_LOOPBACK_PUBLIC};
use kuroshio::upstream::Upstream;
use kuroshio_proto::message::{Message, Record};
use serde_json::{json, Value};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
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

fn data_file() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../data/geo/tw-ip.json")
        .to_string_lossy()
        .into_owned()
}

fn q(id: u16, name: &str) -> Vec<u8> {
    kuroshio_proto::build_query(id, name, 1)
}

async fn start(tag: &str, up: SocketAddr, access: Value, doh_tls: bool) -> (kuroshio::app::Started, PathBuf) {
    let dir = std::env::temp_dir().join(format!("kuroshio-access-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("state")).unwrap();
    if doh_tls {
        let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into(), "localhost".into()]).unwrap();
        std::fs::write(dir.join("cert.pem"), ck.cert.pem()).unwrap();
        std::fs::write(dir.join("key.pem"), ck.key_pair.serialize_pem()).unwrap();
        kuroshio::tls::add_root(rustls::pki_types::CertificateDer::from(ck.cert.der().to_vec()));
    }
    let mut a = json!({ "dataFile": data_file() });
    kuroshio_config::merge(&mut a, &access);
    let (cert, key) = if doh_tls { ("./cert.pem", "./key.pem") } else { ("", "") };
    let mut listen = json!({
        "plain": { "binds": ["127.0.0.1"], "port": 0 },
        "doh": { "enabled": true, "host": "127.0.0.1", "port": 0, "cert": cert, "key": key, "trustProxy": !doh_tls },
    });
    if doh_tls {
        listen["dot"] = json!({ "enabled": true, "host": "127.0.0.1", "port": 0, "cert": cert, "key": key });
        listen["doq"] = json!({ "enabled": true, "host": "127.0.0.1", "port": 0 });
    }
    let cfg = kuroshio_config::with_overrides(&json!({
        "system": { "persistDir": dir.join("state").to_string_lossy() },
        "admin": { "port": 0, "auth": false }, "filter": { "enabled": false }, "cdn": { "enabled": false },
        "listen": listen,
        "upstream": { "pinned": [format!("udp://{up}")], "fallback": [] },
        "resolver": { "lastResort": [], "rankIps": false, "fastPath": false },
        "access": a,
    }));
    (kuroshio::app::start(&cfg, kuroshio_config::Tier::Large).await.unwrap(), dir)
}

/// 純 HTTP 的 DoH POST（反向代理模式），回傳狀態列
async fn doh_post(doh: SocketAddr, xff: &str) -> String {
    let body = q(3, "p.test");
    let mut s = tokio::net::TcpStream::connect(doh).await.unwrap();
    s.write_all(
        format!("POST /dns-query HTTP/1.1\r\nHost: dns.example\r\nX-Forwarded-For: {xff}\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())
            .as_bytes(),
    )
    .await
    .unwrap();
    s.write_all(&body).await.unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    String::from_utf8_lossy(&out).lines().next().unwrap_or("").to_string()
}

/// 連上 TCP 之後對方是不是馬上關閉（沒有任何回應，也就是沒做 TLS 握手）
async fn closed_without_reply(addr: SocketAddr) -> bool {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    // 送一點東西（TLS ClientHello 的開頭），對方如果在等握手就不會關
    let _ = s.write_all(&[0x16, 0x03, 0x01, 0x00, 0x05]).await;
    let mut buf = [0u8; 64];
    matches!(
        tokio::time::timeout(Duration::from_secs(3), s.read(&mut buf)).await,
        Ok(Ok(0)) | Ok(Err(_))
    )
}

#[tokio::test]
async fn listeners_reject_denied_sources() {
    let up = upstream().await;

    // 1. 反向代理（trustProxy）：用 X-Forwarded-For 的真正來源判斷；迴路位址本身永遠允許
    let (s, dir) = start("proxy", up, json!({}), false).await;
    let doh = s.encrypted.doh.unwrap();
    assert!(doh_post(doh, "168.95.1.1").await.starts_with("HTTP/1.1 200"), "中華電信：允許");
    assert!(doh_post(doh, "8.8.8.8").await.starts_with("HTTP/1.1 403"), "國外：403");
    let a = s.resolver.access.get().unwrap().status_json();
    assert_eq!(a["denied"]["byListener"]["doh"], json!(1));
    assert_eq!(a["topDenied"][0]["net"], json!("8.8.8.0/24"));
    assert_eq!(a["dataOk"], json!(true));
    // 管理 API
    let st = kuroshio::admin::route(&s.state, "/api/access", &Default::default()).await;
    assert!(st.body["groups"].as_array().unwrap().len() >= 10);
    assert_eq!(st.body["mode"], json!("taiwan"));
    let q8: std::collections::HashMap<String, String> = [("ip".to_string(), "8.8.8.8".to_string())].into();
    let st = kuroshio::admin::route(&s.state, "/api/access", &q8).await;
    assert_eq!(st.body["allowed"], json!(false));
    let st = kuroshio::admin::route(&s.state, "/api/status", &Default::default()).await;
    assert_eq!(st.body["access"]["mode"], json!("taiwan"));
    s.shutdown();
    let _ = std::fs::remove_dir_all(&dir);

    // 以下把迴路位址當成公網位址
    TEST_LOOPBACK_PUBLIC.store(true, Ordering::Relaxed);

    // 2. 預設（只開放台灣）：127.0.0.1 不在台灣網段 → DoT / DoH 連線直接關閉，DoQ 不回應；區網 DNS 預設不套用
    let (s, dir) = start("tw", up, json!({ "applyTo": ["dot", "doh", "doq", "doh3", "site"] }), true).await;
    let (dot, doh, doq) = (s.encrypted.dot.unwrap(), s.encrypted.doh.unwrap(), s.encrypted.doq.unwrap());
    assert!(closed_without_reply(dot).await, "DoT：不握手直接關閉");
    assert!(closed_without_reply(doh).await, "DoH：不握手直接關閉");
    let u = Upstream::parse(&format!("tls://{dot}")).unwrap();
    assert!(u.exchange(&q(1, "a.test"), Duration::from_secs(2)).await.is_err());
    let u = Upstream::parse(&format!("quic://{doq}")).unwrap();
    assert!(
        u.exchange(&q(2, "b.test"), Duration::from_millis(1500)).await.is_err(),
        "DoQ：握手前就忽略"
    );
    let plain = Upstream::parse(&format!("udp://{}", s.bound[0])).unwrap();
    assert!(
        plain.exchange(&q(3, "c.test"), Duration::from_secs(2)).await.is_ok(),
        "區網 DNS 沒套用"
    );
    let acc = s.resolver.access.get().unwrap();
    let c = acc.status_json();
    assert!(c["denied"]["byListener"]["dot"].as_u64().unwrap() >= 2, "{c}");
    assert!(c["denied"]["byListener"]["doh"].as_u64().unwrap() >= 1, "{c}");
    assert!(c["denied"]["byListener"]["doq"].as_u64().unwrap() >= 1, "{c}");
    assert_eq!(acc.check_json("127.0.0.1".parse().unwrap())["allowed"], json!(false));
    s.shutdown();
    let _ = std::fs::remove_dir_all(&dir);

    // 3. 自訂允許：一樣的監聽，加上 127.0.0.1 就可以用
    let (s, dir) = start(
        "allow",
        up,
        json!({ "allow": ["127.0.0.1/32"], "applyTo": ["dot", "doh", "doq", "plain"] }),
        true,
    )
    .await;
    let (dot, doq) = (s.encrypted.dot.unwrap(), s.encrypted.doq.unwrap());
    for u in [format!("tls://{dot}"), format!("quic://{doq}"), format!("udp://{}", s.bound[0])] {
        let m = Message::parse(
            &Upstream::parse(&u)
                .unwrap()
                .exchange(&q(4, "d.test"), Duration::from_secs(3))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(m.answers.len(), 1, "{u}");
    }
    s.shutdown();
    let _ = std::fs::remove_dir_all(&dir);

    // 4. 全開放 + 自訂封鎖：封鎖勝過一切（區網 DNS 也套用時，連區網的 allowFrom 也擋）
    let (s, dir) = start(
        "deny",
        up,
        json!({ "mode": "open", "deny": ["127.0.0.0/8"], "applyTo": ["dot", "plain"] }),
        true,
    )
    .await;
    assert!(closed_without_reply(s.encrypted.dot.unwrap()).await);
    let plain = Upstream::parse(&format!("udp://{}", s.bound[0])).unwrap();
    assert!(
        plain.exchange(&q(5, "e.test"), Duration::from_secs(1)).await.is_err(),
        "區網 DNS 也擋"
    );
    assert!(
        s.resolver.access.get().unwrap().status_json()["denied"]["byListener"]["plain"]
            .as_u64()
            .unwrap()
            >= 1
    );
    s.shutdown();
    let _ = std::fs::remove_dir_all(&dir);

    // 5. 台灣 IP 資料讀不到：不擋（fail open），狀態顯示警告
    let (s, dir) = start("nodata", up, json!({ "dataFile": "/nonexistent/tw-ip.json" }), true).await;
    let u = Upstream::parse(&format!("tls://{}", s.encrypted.dot.unwrap())).unwrap();
    assert!(u.exchange(&q(6, "f.test"), Duration::from_secs(3)).await.is_ok(), "資料讀不到不擋");
    let st = s.resolver.access.get().unwrap().status_json();
    assert_eq!(st["failOpen"], json!(true));
    assert!(st["warning"].as_str().unwrap().contains("讀不到"));
    assert!(s.resolver.access.get().unwrap().applies(Kind::Dot));
    s.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
    TEST_LOOPBACK_PUBLIC.store(false, Ordering::Relaxed);
}
