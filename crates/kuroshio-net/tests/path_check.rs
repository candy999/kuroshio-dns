//! 路徑檢查（3.3.6）：用本機的假伺服器模擬各種路上的狀況，確認判斷正確。
//!
//! - 假的一般 DNS：可以只開 UDP、回答「我是黑潮」或 `version.bind`、把 `.invalid` 改成位址、竄改已知答案
//! - 假的加密伺服器：憑證受信任的 TLS（DoT / DoH 正常）、憑證不受信任的 TLS（中途攔截）、關掉的埠（被擋）

use kuroshio_net::path::{self, Interceptor, Proto, Targets, V6Route};
use kuroshio_proto::message::{Message, RData, Record};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

#[derive(Clone, Copy, Default)]
struct Fake {
    /// CHAOS version.kuroshio 回答 kuroshio/3.3.6
    kuroshio: bool,
    /// CHAOS version.bind 的回答
    bind: Option<&'static str>,
    /// `.invalid` 回答這個位址
    nx_rewrite: Option<Ipv4Addr>,
    /// dns.google 回答錯的位址
    tamper: bool,
}

fn answer(q: &[u8], f: Fake) -> Option<Vec<u8>> {
    let m = Message::parse(q).ok()?;
    let qs = m.questions.first()?.clone();
    let mut r = Message::response_to(&m, 0);
    let name = qs.name.trim_end_matches('.').to_ascii_lowercase();
    let txt = |s: &str| {
        let mut b = vec![s.len() as u8];
        b.extend_from_slice(s.as_bytes());
        Record {
            name: qs.name.clone(),
            rtype: 16,
            class: 3,
            ttl: 0,
            data: RData::Raw(b),
        }
    };
    if qs.qclass == 3 {
        match name.as_str() {
            "version.kuroshio" if f.kuroshio => r.answers.push(txt("kuroshio/3.3.6")),
            "version.bind" if f.bind.is_some() => r.answers.push(txt(f.bind.unwrap())),
            _ => r.rcode = 5,
        }
    } else if name.ends_with(".invalid") {
        match f.nx_rewrite {
            Some(ip) => r.answers.push(Record::a(&qs.name, 60, ip)),
            None => r.rcode = 3,
        }
    } else if name == "dns.google" {
        let ip = if f.tamper {
            Ipv4Addr::new(198, 51, 100, 7)
        } else {
            Ipv4Addr::new(8, 8, 8, 8)
        };
        r.answers.push(Record::a(&qs.name, 60, ip));
    } else if name == "one.one.one.one" {
        r.answers.push(Record::a(&qs.name, 60, Ipv4Addr::new(1, 1, 1, 1)));
    } else {
        r.answers.push(Record::a(&qs.name, 60, Ipv4Addr::new(192, 0, 2, 80)));
    }
    Some(r.encode())
}

/// 假的一般 DNS（`tcp` = 也開 TCP）
async fn fake_dns(f: Fake, tcp: bool) -> SocketAddr {
    let u = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = u.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, from)) = u.recv_from(&mut buf).await else { break };
            if let Some(r) = answer(&buf[..n], f) {
                let _ = u.send_to(&r, from).await;
            }
        }
    });
    if tcp {
        let l = TcpListener::bind(addr).await.unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else { break };
                tokio::spawn(async move {
                    let Ok(len) = s.read_u16().await else { return };
                    let mut q = vec![0u8; len as usize];
                    if s.read_exact(&mut q).await.is_err() {
                        return;
                    }
                    if let Some(r) = answer(&q, f) {
                        let mut out = (r.len() as u16).to_be_bytes().to_vec();
                        out.extend_from_slice(&r);
                        let _ = s.write_all(&out).await;
                    }
                });
            }
        });
    }
    addr
}

/// 沒有人在聽的埠（UDP 與 TCP 都關著）
async fn closed() -> SocketAddr {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let a = s.local_addr().unwrap();
    drop(s);
    a
}

/// 假的 TLS 伺服器（`trusted` = 憑證加進受信任清單）。握手完就關閉
async fn fake_tls(trusted: bool) -> SocketAddr {
    let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let der = CertificateDer::from(ck.cert.der().to_vec());
    if trusted {
        kuroshio_net::tls::add_root(der.clone());
    }
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
    let mut c = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der], key)
        .unwrap();
    c.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"dot".to_vec()];
    let acc = tokio_rustls::TlsAcceptor::from(Arc::new(c));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { break };
            let acc = acc.clone();
            tokio::spawn(async move {
                let _ = acc.accept(s).await;
            });
        }
    });
    addr
}

/// 受信任的 TLS 伺服器只建一台（受信任清單是整個程式共用的）
async fn trusted_tls() -> SocketAddr {
    static A: OnceLock<SocketAddr> = OnceLock::new();
    if let Some(a) = A.get() {
        return *a;
    }
    // 伺服器要跑在整個測試程式期間都在的 runtime 上
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async move {
            tx.send(fake_tls(true).await).unwrap();
            std::future::pending::<()>().await
        });
    });
    *A.get_or_init(|| rx.recv().unwrap())
}

/// 測試不連外：一般 DNS 伺服器預設也是關掉的埠（不然會去問真的 bootstrap 伺服器）
fn targets(testnet: Vec<SocketAddr>) -> Targets {
    let nobody = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    Targets {
        testnet_v4: testnet,
        testnet_v6: Vec::new(),
        plain: vec![nobody],
        dot: Vec::new(),
        doh: Vec::new(),
        quic: Vec::new(),
        plain_timeout: Duration::from_millis(400),
        tls_timeout: Duration::from_secs(2),
        read_gateway: false,
        v6_route: Some(V6Route::None("測試：沒有 IPv6".into())),
        ..Targets::default()
    }
}

fn tls_targets(t: &mut Targets, dot: SocketAddr, doh: SocketAddr, quic: SocketAddr) {
    t.dot = vec![(dot, "127.0.0.1".into()), (dot, "127.0.0.1".into())];
    t.doh = vec![(doh, "127.0.0.1".into()), (doh, "127.0.0.1".into())];
    t.quic = vec![(quic, "127.0.0.1".into(), b"h3".to_vec())];
}

#[tokio::test]
async fn upstream_kuroshio_takes_all_port_53() {
    let dns = fake_dns(
        Fake {
            kuroshio: true,
            ..Default::default()
        },
        true,
    )
    .await;
    let tls = trusted_tls().await;
    let mut t = targets(vec![dns]);
    tls_targets(&mut t, tls, tls, closed().await);
    let r = path::check(&t).await;
    assert!(r.plain_v4.udp && r.plain_v4.tcp, "{:?}", r.plain_v4);
    assert_eq!(r.interceptor, Some(Interceptor::Kuroshio("3.3.6".into())));
    assert!(r.nx_rewrite.is_empty() && r.tampered.is_empty());
    assert!(!r.bootstrap_tampered());
    // DoT / DoH 正常，QUIC 連不上 → QUIC 被擋
    assert_eq!(r.blocked, vec![Proto::Quic]);
    assert!(r.tls_intercept.is_none() && !r.offline);
    assert!(r.plain_v6.is_none() && !r.v6_usable());
    let w = r.warnings("skip-plain");
    assert!(
        w.iter()
            .any(|s| s.starts_with("一般 DNS 被路由器") && s.contains("黑潮（3.3.6）") && s.contains("評測不測一般 DNS")),
        "{w:?}"
    );
    assert!(w.iter().any(|s| s.contains("QUIC")), "{w:?}");
    let j = r.to_json();
    assert_eq!(j["plain"]["intercepted"], true);
    assert_eq!(j["interceptor"]["kind"], "kuroshio");
    assert_eq!(j["blocked"][0], "quic");
    assert_eq!(j["ipv6"]["usable"], false);
}

#[tokio::test]
async fn udp_only_interception_by_router_software() {
    let dns = fake_dns(
        Fake {
            bind: Some("dnsmasq-2.90"),
            ..Default::default()
        },
        false,
    )
    .await;
    let tls = trusted_tls().await;
    let mut t = targets(vec![dns]);
    tls_targets(&mut t, tls, tls, tls);
    t.quic.clear();
    let r = path::check(&t).await;
    assert!(r.plain_v4.udp && !r.plain_v4.tcp, "{:?}", r.plain_v4);
    assert_eq!(r.interceptor, Some(Interceptor::Software("dnsmasq-2.90".into())));
    assert!(r.blocked.is_empty());
    assert!(r.warnings("skip-plain")[0].contains("只有 UDP"));
}

#[tokio::test]
async fn not_intercepted_but_resolver_rewrites_and_tampers() {
    let isp = fake_dns(
        Fake {
            nx_rewrite: Some(Ipv4Addr::new(203, 0, 113, 9)),
            tamper: true,
            ..Default::default()
        },
        true,
    )
    .await;
    let tls = trusted_tls().await;
    // 保留位址沒有回答（沒被接走）；一般 DNS 伺服器自己改寫
    let mut t = targets(vec![closed().await]);
    t.plain = vec![isp];
    tls_targets(&mut t, tls, tls, tls);
    t.quic.clear();
    let r = path::check(&t).await;
    assert!(!r.plain_intercepted());
    assert_eq!(r.interceptor, None);
    assert_eq!(r.nx_rewrite, vec![IpAddr::from([203, 0, 113, 9])]);
    assert_eq!(r.tampered.len(), 1);
    assert_eq!(r.tampered[0].name, "dns.google");
    assert!(r.bootstrap_tampered());
    let w = r.warnings("skip-plain");
    assert!(w.iter().any(|s| s.contains("203.0.113.9")), "{w:?}");
    assert!(w.iter().any(|s| s.contains("dns.google")), "{w:?}");
}

#[tokio::test]
async fn dot_port_blocked() {
    let tls = trusted_tls().await;
    let mut t = targets(vec![closed().await]);
    tls_targets(&mut t, closed().await, tls, tls);
    t.quic.clear();
    let r = path::check(&t).await;
    assert_eq!(r.blocked, vec![Proto::Dot]);
    assert!(!r.offline);
}

#[tokio::test]
async fn tls_interception_is_not_blocking() {
    let mitm = fake_tls(false).await;
    let mut t = targets(vec![closed().await]);
    tls_targets(&mut t, mitm, mitm, closed().await);
    t.quic.clear();
    let r = path::check(&t).await;
    assert!(r.tls_intercept.is_some(), "{:?}", r.protocols);
    // 憑證錯誤不算「協定被擋」
    assert!(r.blocked.is_empty(), "{:?}", r.blocked);
    assert!(r.warnings("skip-plain").iter().any(|s| s.contains("中途攔截")));
}

#[tokio::test]
async fn offline_judges_nothing() {
    let mut t = targets(vec![closed().await]);
    let c = closed().await;
    tls_targets(&mut t, c, c, c);
    let r = path::check(&t).await;
    assert!(r.offline);
    assert!(r.blocked.is_empty());
}

#[tokio::test]
async fn apply_sets_flags() {
    let dns = fake_dns(
        Fake {
            kuroshio: true,
            nx_rewrite: Some(Ipv4Addr::new(203, 0, 113, 1)),
            ..Default::default()
        },
        true,
    )
    .await;
    let tls = trusted_tls().await;
    let mut t = targets(vec![dns]);
    tls_targets(&mut t, closed().await, tls, tls);
    t.quic.clear();
    let r = path::check(&t).await;
    path::apply(&r, false);
    assert!(path::plain_intercepted(false));
    assert!(!path::plain_intercepted(true));
    assert!(path::blocked(Proto::Dot) && !path::blocked(Proto::Doh));
    assert!(path::bootstrap_via_doh());
    path::apply(&r, true);
    assert!(!path::plain_intercepted(false), "intercept_policy ignore");
    path::clear();
    assert!(!path::blocked(Proto::Dot) && !path::bootstrap_via_doh() && path::current().is_none());
}
