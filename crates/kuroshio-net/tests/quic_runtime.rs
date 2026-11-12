//! QUIC 用戶端端點跟著 tokio runtime 走：
//! 建立端點的 runtime 結束後（設定重新載入、匯入備份後重新啟動、Windows 服務停止再啟動、
//! 測試程式的每個 `#[tokio::test]`），新的 runtime 裡的 DoQ / DoH3 查詢還是要能用，舊的 socket 也不能留著。
//!
//! 模擬伺服器跑在自己的執行緒與 runtime 上（整個測試程式期間都在），用戶端每個測試各自一個 runtime。

use bytes::{Buf, Bytes};
use kuroshio_net::quic::{endpoints_of, Doh3, Doq};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// （DoQ 埠, DoH3 埠）
fn server() -> (u16, u16) {
    static S: OnceLock<(u16, u16)> = OnceLock::new();
    *S.get_or_init(|| {
        let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let der = CertificateDer::from(ck.cert.der().to_vec());
        kuroshio_net::tls::add_root(der.clone());
        let key = ck.key_pair.serialize_der();
        let cfg = |alpn: &[u8]| {
            let mut c = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![der.clone()], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.clone())))
                .unwrap();
            c.alpn_protocols = vec![alpn.to_vec()];
            let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(c)).unwrap();
            quinn::ServerConfig::with_crypto(Arc::new(crypto))
        };
        let (doq_cfg, h3_cfg) = (cfg(b"doq"), cfg(b"h3"));
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let doq = quinn::Endpoint::server(doq_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
                let h3 = quinn::Endpoint::server(h3_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
                tx.send((doq.local_addr().unwrap().port(), h3.local_addr().unwrap().port()))
                    .unwrap();
                tokio::spawn(serve_doq(doq));
                serve_h3(h3).await;
            });
        });
        rx.recv().unwrap()
    })
}

/// 回應 = 查詢本身、QR 設成 1
fn answer(q: &[u8]) -> Vec<u8> {
    let mut r = q.to_vec();
    r[2] |= 0x80;
    r
}

async fn serve_doq(ep: quinn::Endpoint) {
    while let Some(inc) = ep.accept().await {
        tokio::spawn(async move {
            let Ok(conn) = inc.await else { return };
            while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                tokio::spawn(async move {
                    let Ok(buf) = recv.read_to_end(65537).await else { return };
                    let r = answer(&buf[2..]);
                    let mut out = (r.len() as u16).to_be_bytes().to_vec();
                    out.extend_from_slice(&r);
                    let _ = send.write_all(&out).await;
                    let _ = send.finish();
                    let _ = send.stopped().await;
                });
            }
        });
    }
}

async fn serve_h3(ep: quinn::Endpoint) {
    while let Some(inc) = ep.accept().await {
        tokio::spawn(async move {
            let Ok(conn) = inc.await else { return };
            let Ok(mut h3c) = h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn)).await else {
                return;
            };
            while let Ok(Some(res)) = h3c.accept().await {
                tokio::spawn(async move {
                    let Ok((_req, mut stream)) = res.resolve_request().await else {
                        return;
                    };
                    let mut body = Vec::new();
                    while let Ok(Some(mut chunk)) = stream.recv_data().await {
                        let n = chunk.remaining();
                        body.extend_from_slice(&chunk.copy_to_bytes(n));
                    }
                    let resp = http::Response::builder()
                        .status(200)
                        .header("content-type", "application/dns-message")
                        .body(())
                        .unwrap();
                    if stream.send_response(resp).await.is_ok() {
                        let _ = stream.send_data(Bytes::from(answer(&body))).await;
                        let _ = stream.finish().await;
                    }
                });
            }
        });
    }
}

/// 在目前的 runtime 裡各做一次 DoQ 與 DoH3 查詢（每次都是新的上游物件 = 新連線）
async fn exchange_both(id: u16) {
    let (doq, h3) = server();
    let q = kuroshio_proto::build_query(id, "quic.test", 1);
    let t = Duration::from_secs(5);
    let r = Doq::default().exchange("127.0.0.1", doq, &q, t).await.expect("DoQ 查詢");
    assert_eq!(&r[..2], &id.to_be_bytes(), "DoQ 回應的 id 換回原本的");
    assert_eq!(r[2] & 0x80, 0x80);
    let r = Doh3::default()
        .exchange("127.0.0.1", h3, "/dns-query", &q, t)
        .await
        .expect("DoH3 查詢");
    assert_eq!(&r[..2], &id.to_be_bytes(), "DoH3 回應的 id 換回原本的");
    assert_eq!(r[2] & 0x80, 0x80);
}

/// 兩個 `#[tokio::test]` 輪流跑（各自的 runtime，前一個結束才開始下一個）：兩個都要成功
fn turn() -> &'static tokio::sync::Mutex<()> {
    static M: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    M.get_or_init(|| tokio::sync::Mutex::new(()))
}

#[tokio::test]
async fn sequential_runtime_one() {
    let _t = turn().lock().await;
    exchange_both(0x1111).await;
}

#[tokio::test]
async fn sequential_runtime_two() {
    let _t = turn().lock().await;
    exchange_both(0x2222).await;
}

#[test]
fn works_after_first_runtime_dropped() {
    let mut last = None;
    for i in 0..3u16 {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let id = rt.handle().id();
        rt.block_on(exchange_both(0x3000 + i));
        assert_eq!(endpoints_of(id), 1, "這個 runtime 用一個 IPv4 端點");
        drop(rt);
        // runtime 結束：它的端點從表裡移除（socket 關閉，重新啟動很多次也不會累積）
        assert_eq!(endpoints_of(id), 0, "runtime 結束後端點要移除");
        last = Some(id);
    }
    // 多執行緒 runtime 也一樣（服務本身用的那種）
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    assert_ne!(Some(rt.handle().id()), last);
    rt.block_on(async {
        // 同一個 runtime 的多筆查詢共用同一個端點
        exchange_both(0x4001).await;
        exchange_both(0x4002).await;
        assert_eq!(endpoints_of(tokio::runtime::Handle::current().id()), 1);
    });
}

#[test]
fn runtime_shutting_down_does_not_deadlock() {
    // 在 runtime 裡建立端點，然後用 shutdown_background 關掉（服務重新載入時走 shutdown_timeout）
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let id = rt.handle().id();
    rt.block_on(exchange_both(0x5001));
    rt.shutdown_timeout(Duration::from_secs(3));
    assert_eq!(endpoints_of(id), 0);
}
