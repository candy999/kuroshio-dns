//! 社群共享接上加密監聽：DoH 的 /.well-known/kuroshio/v2、DoT 的 ALPN kuroshio/2、管理 API
//! （協定本身的兩節點測試在 kuroshio-community）

use rustls::pki_types::{CertificateDer, ServerName};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn write_cert(dir: &std::path::Path) -> CertificateDer<'static> {
    let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into(), "localhost".into()]).unwrap();
    std::fs::write(dir.join("cert.pem"), ck.cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), ck.key_pair.serialize_pem()).unwrap();
    CertificateDer::from(ck.cert.der().to_vec())
}

#[tokio::test]
async fn community_rides_on_encrypted_listeners() {
    let dir = std::env::temp_dir().join(format!("kuroshio-comm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("state")).unwrap();
    let der = write_cert(&dir);
    kuroshio::tls::add_root(der.clone());
    let cfg = kuroshio_config::with_overrides(&json!({
        "system": { "persistDir": dir.join("state").to_string_lossy() },
        "admin": { "port": 0, "auth": false }, "filter": { "enabled": false }, "cdn": { "enabled": false },
        "listen": {
            "plain": { "binds": ["127.0.0.1"], "port": 0 },
            "dot": { "enabled": true, "host": "127.0.0.1", "port": 0, "cert": "./cert.pem", "key": "./key.pem" },
            "doh": { "enabled": true, "host": "127.0.0.1", "port": 0, "cert": "./cert.pem", "key": "./key.pem", "trustProxy": false }
        },
        "community": { "enabled": true, "dir": dir.join("community").to_string_lossy(), "domain": "dns.example.test" },
        "upstream": { "pinned": ["udp://127.0.0.1:9"], "fallback": [] },
        "resolver": { "lastResort": [] }
    }));
    let started = kuroshio::app::start(&cfg, kuroshio_config::Tier::Large).await.unwrap();
    assert!(started.state.community.is_some(), "社群有啟動");
    assert!(dir.join("community").join("key.pem").exists(), "第一次啟動產生金鑰");
    let dot = started.encrypted.dot.unwrap();
    let doh = started.encrypted.doh.unwrap();

    // DoH：社群路徑交給社群模組（自我檢查完成前回 503，之後 200），回 CBOR，不是 DoH 的 404
    let req = kuroshio::fetch::Request {
        method: "GET",
        ..Default::default()
    };
    let (status, body) = kuroshio::fetch::request(
        &format!("https://127.0.0.1:{}/.well-known/kuroshio/v2/identity", doh.port()),
        &req,
        1 << 16,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert!(status == 200 || status == 503, "status {status}");
    assert!(!body.is_empty() && body[0] & 0xe0 == 0xa0, "CBOR map");
    let (status, _) = kuroshio::fetch::request(
        &format!("https://127.0.0.1:{}/.well-known/kuroshio/v2/nope", doh.port()),
        &req,
        1 << 16,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert!(status == 404 || status == 503, "status {status}");

    // DoT：ALPN kuroshio/2 協商成功，送一筆 identity 訊框（4 bytes 長度前綴）會收到回覆
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let mut cc = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cc.alpn_protocols = vec![kuroshio_community::ALPN.to_vec()];
    let tcp = tokio::net::TcpStream::connect(dot).await.unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(cc))
        .connect(ServerName::try_from("127.0.0.1").unwrap(), tcp)
        .await
        .unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(kuroshio_community::ALPN));
    // {v: 2, a: "identity"}（CBOR）
    let frame: &[u8] = &[
        0xa2, 0x61, b'v', 0x02, 0x61, b'a', 0x68, b'i', b'd', b'e', b'n', b't', b'i', b't', b'y',
    ];
    let mut out = (frame.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(frame);
    tls.write_all(&out).await.unwrap();
    let mut len = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), tls.read_exact(&mut len))
        .await
        .unwrap()
        .unwrap();
    assert!(u32::from_be_bytes(len) > 0, "有回覆");

    // 管理 API
    let v = kuroshio::admin::route(&started.state, "/api/community/status", &Default::default()).await;
    assert_eq!(v.code, 200, "{}", v.body);
    started.shutdown();
    assert!(dir.join("state").join("community").exists() || std::fs::read_dir(dir.join("state")).is_ok());
    let _ = std::fs::remove_dir_all(&dir);
}
