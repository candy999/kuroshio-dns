//! 上游回應的 id：DoH 送 0、回應也要是 0（RFC 8484 第 4.1 節）；TCP / DoT 的錯置回應丟掉、繼續等（同 UDP）

use kuroshio::upstream::Upstream;
use kuroshio_proto::message::{Message, Record};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

/// 對 `q` 的回應（id 照 `id`，問題換成 `name`）
fn answer(q: &[u8], id: u16, name: Option<&str>) -> Vec<u8> {
    let mut m = Message::parse(q).unwrap();
    if let Some(n) = name {
        m.questions[0].name = n.into();
    }
    let mut r = Message::response_to(&m, 0);
    r.opt = None;
    r.id = id;
    r.answers.push(Record::a(&m.questions[0].name, 60, Ipv4Addr::new(9, 8, 7, 6)));
    r.encode()
}

async fn read_frame<S: AsyncRead + Unpin>(s: &mut S) -> Option<Vec<u8>> {
    let len = s.read_u16().await.ok()? as usize;
    let mut b = vec![0u8; len];
    s.read_exact(&mut b).await.ok()?;
    Some(b)
}

async fn write_frame<S: AsyncWrite + Unpin>(s: &mut S, b: &[u8]) {
    let mut f = (b.len() as u16).to_be_bytes().to_vec();
    f.extend_from_slice(b);
    s.write_all(&f).await.unwrap();
}

/// 先回 id 錯的、再回問題錯的，`good` 時最後才回正確的
async fn misbehave<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, good: bool) {
    while let Some(q) = read_frame(&mut s).await {
        let id = u16::from_be_bytes([q[0], q[1]]);
        write_frame(&mut s, &answer(&q, id.wrapping_add(1), None)).await;
        write_frame(&mut s, &answer(&q, id, Some("other.example"))).await;
        if good {
            write_frame(&mut s, &answer(&q, id, None)).await;
        }
    }
}

fn q(id: u16, name: &str) -> Vec<u8> {
    kuroshio_proto::build_query(id, name, 1)
}

#[tokio::test]
async fn tcp_skips_mismatched_replies() {
    for good in [true, false] {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                tokio::spawn(misbehave(s, good));
            }
        });
        let u = Upstream::parse(&format!("tcp://{addr}")).unwrap();
        let r = u.exchange(&q(4321, "t.example"), Duration::from_millis(800)).await;
        if good {
            let m = Message::parse(&r.unwrap()).unwrap();
            assert_eq!((m.id, m.questions[0].name.as_str()), (4321, "t.example"));
            assert_eq!(m.answers.len(), 1);
        } else {
            let e = r.unwrap_err().to_string();
            assert!(e.contains("逾時"), "沒有相符的回應：等到逾時（{e}）");
        }
    }
}

fn tls_acceptor(alpn: &[&[u8]]) -> tokio_rustls::TlsAcceptor {
    let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let der = rustls::pki_types::CertificateDer::from(ck.cert.der().to_vec());
    kuroshio::tls::add_root(der.clone());
    let key = rustls::pki_types::PrivateKeyDer::try_from(ck.key_pair.serialize_der()).unwrap();
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der], key)
        .unwrap();
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    tokio_rustls::TlsAcceptor::from(Arc::new(cfg))
}

#[tokio::test]
async fn dot_skips_mismatched_replies() {
    let acc = tls_acceptor(&[]);
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let acc = acc.clone();
            tokio::spawn(async move {
                if let Ok(s) = acc.accept(s).await {
                    misbehave(s, true).await;
                }
            });
        }
    });
    let u = Upstream::parse(&format!("tls://{addr}")).unwrap();
    for i in 0..3u16 {
        let m = Message::parse(&u.exchange(&q(77 + i, "d.example"), Duration::from_secs(3)).await.unwrap()).unwrap();
        assert_eq!((m.id, m.questions[0].name.as_str()), (77 + i, "d.example"));
    }
}

/// HTTP/1.1 的 DoH 伺服器：記下收到的查詢 id，回應的 id 用 `reply_id`（None = 照抄）
async fn doh_server(reply_id: Option<u16>, seen: Arc<Mutex<Vec<u16>>>) -> SocketAddr {
    let acc = tls_acceptor(&[b"http/1.1"]);
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let (acc, seen) = (acc.clone(), seen.clone());
            tokio::spawn(async move {
                let Ok(mut s) = acc.accept(s).await else { return };
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                loop {
                    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4) else {
                        match s.read(&mut tmp).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        }
                        continue;
                    };
                    let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
                    let len: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                    while buf.len() < end + len {
                        match s.read(&mut tmp).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        }
                    }
                    let body: Vec<u8> = buf.drain(..end + len).skip(end).collect();
                    let id = u16::from_be_bytes([body[0], body[1]]);
                    seen.lock().unwrap().push(id);
                    let r = answer(&body, reply_id.unwrap_or(id), None);
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
                        r.len()
                    );
                    s.write_all(head.as_bytes()).await.unwrap();
                    s.write_all(&r).await.unwrap();
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn doh_sends_id_zero_and_restores_client_id() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let addr = doh_server(None, seen.clone()).await;
    let u = Upstream::parse(&format!("https://{addr}/dns-query")).unwrap();
    for id in [1234u16, 4321] {
        let m = Message::parse(&u.exchange(&q(id, "h.example"), Duration::from_secs(3)).await.unwrap()).unwrap();
        assert_eq!((m.id, m.questions[0].name.as_str()), (id, "h.example"), "回應改回用戶端的 id");
    }
    assert_eq!(*seen.lock().unwrap(), [0, 0], "送出的 id 一律是 0");

    // 回應的 id 不是 0：不接受
    let seen = Arc::new(Mutex::new(Vec::new()));
    let addr = doh_server(Some(99), seen.clone()).await;
    let u = Upstream::parse(&format!("https://{addr}/dns-query")).unwrap();
    let e = u.exchange(&q(5, "h.example"), Duration::from_secs(3)).await.unwrap_err();
    assert!(e.to_string().contains("id"), "{e}");
}
