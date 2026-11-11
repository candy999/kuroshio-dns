//! DoT / DoH 上游：本機自簽憑證的伺服器，測持久連線、管線化、HTTP/2 與 HTTP/1.1、憑證驗證

use kuroshio::upstream::Upstream;
use kuroshio_proto::message::{Message, Record};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn cert(trusted: bool) -> (Arc<rustls::ServerConfig>, Arc<rustls::ServerConfig>) {
    let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into(), "localhost".into()]).unwrap();
    let der = CertificateDer::from(ck.cert.der().to_vec());
    if trusted {
        kuroshio::tls::add_root(der.clone());
    }
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
    let mk = |alpn: Vec<Vec<u8>>| {
        let mut c = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![der.clone()], key.clone_key())
            .unwrap();
        c.alpn_protocols = alpn;
        Arc::new(c)
    };
    (mk(vec![b"h2".to_vec()]), mk(vec![b"http/1.1".to_vec()]))
}

fn answer(q: &[u8]) -> Vec<u8> {
    let q = Message::parse(q).unwrap();
    let mut r = Message::response_to(&q, 0);
    r.answers.push(Record::a(&q.questions[0].name, 60, Ipv4Addr::new(10, 20, 30, 40)));
    r.encode()
}

/// DoT 伺服器：每兩筆查詢反過來回（測試管線化的 id 對應）
async fn dot_server(cfg: Arc<rustls::ServerConfig>) -> (SocketAddr, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let conns = Arc::new(AtomicUsize::new(0));
    let c2 = conns.clone();
    let acc = tokio_rustls::TlsAcceptor::from(cfg);
    tokio::spawn(async move {
        loop {
            let (tcp, _) = l.accept().await.unwrap();
            c2.fetch_add(1, Ordering::SeqCst);
            let acc = acc.clone();
            tokio::spawn(async move {
                let Ok(mut s) = acc.accept(tcp).await else { return };
                let mut held: Option<Vec<u8>> = None;
                loop {
                    let Ok(len) = s.read_u16().await else { return };
                    let mut q = vec![0u8; len as usize];
                    if s.read_exact(&mut q).await.is_err() {
                        return;
                    }
                    let r = answer(&q);
                    let mut out = Vec::new();
                    match held.take() {
                        None => held = Some(r),
                        Some(prev) => {
                            for m in [r, prev] {
                                out.extend_from_slice(&(m.len() as u16).to_be_bytes());
                                out.extend_from_slice(&m);
                            }
                        }
                    }
                    // 單獨一筆等 50 ms 沒有下一筆就直接回
                    if held.is_some() {
                        tokio::select! {
                            r = s.read_u16() => {
                                let Ok(len) = r else { return };
                                let mut q2 = vec![0u8; len as usize];
                                if s.read_exact(&mut q2).await.is_err() { return; }
                                let r2 = answer(&q2);
                                for m in [r2, held.take().unwrap()] {
                                    out.extend_from_slice(&(m.len() as u16).to_be_bytes());
                                    out.extend_from_slice(&m);
                                }
                            }
                            _ = tokio::time::sleep(Duration::from_millis(50)) => {
                                let m = held.take().unwrap();
                                out.extend_from_slice(&(m.len() as u16).to_be_bytes());
                                out.extend_from_slice(&m);
                            }
                        }
                    }
                    if s.write_all(&out).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (addr, conns)
}

async fn h2_server(cfg: Arc<rustls::ServerConfig>) -> (SocketAddr, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let conns = Arc::new(AtomicUsize::new(0));
    let c2 = conns.clone();
    let acc = tokio_rustls::TlsAcceptor::from(cfg);
    tokio::spawn(async move {
        loop {
            let (tcp, _) = l.accept().await.unwrap();
            c2.fetch_add(1, Ordering::SeqCst);
            let acc = acc.clone();
            tokio::spawn(async move {
                let Ok(s) = acc.accept(tcp).await else { return };
                let Ok(mut h) = h2::server::handshake(s).await else { return };
                while let Some(Ok((req, mut respond))) = h.accept().await {
                    tokio::spawn(async move {
                        assert_eq!(req.method(), "POST");
                        assert_eq!(req.uri().path(), "/dns-query");
                        let mut body = req.into_body();
                        let mut q = Vec::new();
                        while let Some(Ok(c)) = body.data().await {
                            let _ = body.flow_control().release_capacity(c.len());
                            q.extend_from_slice(&c);
                        }
                        assert_eq!(&q[..2], &[0, 0], "DoH 查詢 id 要是 0");
                        let resp = http::Response::builder()
                            .status(200)
                            .header("content-type", "application/dns-message")
                            .body(())
                            .unwrap();
                        let mut send = respond.send_response(resp, false).unwrap();
                        send.send_data(bytes::Bytes::from(answer(&q)), true).unwrap();
                    });
                }
            });
        }
    });
    (addr, conns)
}

async fn h1_server(cfg: Arc<rustls::ServerConfig>) -> (SocketAddr, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let conns = Arc::new(AtomicUsize::new(0));
    let c2 = conns.clone();
    let acc = tokio_rustls::TlsAcceptor::from(cfg);
    tokio::spawn(async move {
        loop {
            let (tcp, _) = l.accept().await.unwrap();
            c2.fetch_add(1, Ordering::SeqCst);
            let acc = acc.clone();
            tokio::spawn(async move {
                let Ok(mut s) = acc.accept(tcp).await else { return };
                let mut chunked = false;
                loop {
                    let mut buf = Vec::new();
                    let mut b = [0u8; 1];
                    while !buf.ends_with(b"\r\n\r\n") {
                        if s.read_exact(&mut b).await.is_err() {
                            return;
                        }
                        buf.push(b[0]);
                    }
                    let head = String::from_utf8_lossy(&buf).to_ascii_lowercase();
                    let len: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .unwrap()
                        .trim()
                        .parse()
                        .unwrap();
                    let mut q = vec![0u8; len];
                    s.read_exact(&mut q).await.unwrap();
                    let r = answer(&q);
                    // 第一筆用 content-length、第二筆用 chunked
                    let out = if !chunked {
                        let mut o = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
                            r.len()
                        )
                        .into_bytes();
                        o.extend_from_slice(&r);
                        o
                    } else {
                        let mut o = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
                        let (a, b2) = r.split_at(5);
                        for part in [a, b2] {
                            o.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
                            o.extend_from_slice(part);
                            o.extend_from_slice(b"\r\n");
                        }
                        o.extend_from_slice(b"0\r\n\r\n");
                        o
                    };
                    chunked = !chunked;
                    if s.write_all(&out).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (addr, conns)
}

fn q(id: u16, name: &str) -> Vec<u8> {
    kuroshio_proto::build_query(id, name, 1)
}

async fn many(up: &Upstream, n: u16) {
    let mut set = tokio::task::JoinSet::new();
    for i in 0..n {
        let up = up.clone();
        set.spawn(async move {
            let r = up
                .exchange(&q(1000 + i, &format!("n{i}.test")), Duration::from_secs(3))
                .await
                .unwrap();
            let m = Message::parse(&r).unwrap();
            assert_eq!(m.id, 1000 + i);
            assert_eq!(m.questions[0].name, format!("n{i}.test"));
        });
    }
    while let Some(r) = set.join_next().await {
        r.unwrap();
    }
}

#[tokio::test]
async fn dot_persistent_pipelined() {
    let (h2cfg, _) = cert(true);
    let mut c = (*h2cfg).clone();
    c.alpn_protocols.clear();
    let (addr, conns) = dot_server(Arc::new(c)).await;
    let up = Upstream::parse(&format!("tls://{addr}")).unwrap();
    many(&up, 20).await;
    many(&up, 5).await;
    assert_eq!(conns.load(Ordering::SeqCst), 1, "同一條連線");
}

#[tokio::test]
async fn doh_http2_multiplexed() {
    let (h2cfg, _) = cert(true);
    let (addr, conns) = h2_server(h2cfg).await;
    let up = Upstream::parse(&format!("https://{addr}/dns-query")).unwrap();
    many(&up, 20).await;
    assert_eq!(conns.load(Ordering::SeqCst), 1, "HTTP/2 多工，同一條連線");
}

#[tokio::test]
async fn doh_http1_keepalive_and_chunked() {
    let (_, h1cfg) = cert(true);
    let (addr, conns) = h1_server(h1cfg).await;
    let up = Upstream::parse(&format!("https://{addr}/dns-query")).unwrap();
    for i in 0..4 {
        let r = up.exchange(&q(i, "h1.test"), Duration::from_secs(3)).await.unwrap();
        assert_eq!(Message::parse(&r).unwrap().answers.len(), 1);
    }
    assert_eq!(conns.load(Ordering::SeqCst), 1, "keep-alive");
}

#[tokio::test]
async fn untrusted_certificate_rejected() {
    let (h2cfg, _) = cert(false);
    let (addr, _) = h2_server(h2cfg).await;
    let up = Upstream::parse(&format!("https://{addr}/dns-query")).unwrap();
    assert!(up.exchange(&q(1, "x.test"), Duration::from_secs(2)).await.is_err());
}

#[tokio::test]
async fn dot_reconnects_after_server_closes() {
    let (h2cfg, _) = cert(true);
    let mut c = (*h2cfg).clone();
    c.alpn_protocols.clear();
    let cfg = Arc::new(c);
    // 每條連線只回一筆就關閉
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let acc = tokio_rustls::TlsAcceptor::from(cfg);
    let conns = Arc::new(AtomicUsize::new(0));
    let c2 = conns.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = l.accept().await.unwrap();
            c2.fetch_add(1, Ordering::SeqCst);
            let mut s = acc.accept(tcp).await.unwrap();
            let len = s.read_u16().await.unwrap();
            let mut qb = vec![0u8; len as usize];
            s.read_exact(&mut qb).await.unwrap();
            let r = answer(&qb);
            s.write_all(&(r.len() as u16).to_be_bytes()).await.unwrap();
            s.write_all(&r).await.unwrap();
            s.shutdown().await.ok();
        }
    });
    let up = Upstream::parse(&format!("tls://{addr}")).unwrap();
    for i in 0..3 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        up.exchange(&q(i, "re.test"), Duration::from_secs(3)).await.unwrap();
    }
    assert_eq!(conns.load(Ordering::SeqCst), 3);
}
