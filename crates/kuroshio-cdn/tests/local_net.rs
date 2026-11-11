//! 真的連線（`RealNet` + `kuroshio-net`）：本機假的 HTTPS / HTTP / DNS 伺服器，
//! 測探測、驗證（含 SNI / 憑證判斷）、ECS 查詢、背景排程整段流程。不連外部網路。

use kuroshio_cdn::cdn::Paths;
use kuroshio_cdn::pools::{cidr, PoolNode};
use kuroshio_cdn::util::Num;
use kuroshio_cdn::{Cdn, RealNet};
use kuroshio_net::iprank::IpRank;
use kuroshio_net::probe::{self, HttpsOpts};
use kuroshio_proto::message::{opt_code, Message, Record};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::json;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

fn server_cfg(names: &[&str], trusted: bool) -> Arc<rustls::ServerConfig> {
    let ck = rcgen::generate_simple_self_signed(names.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
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
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(c)
}

/// 讀到標頭結束，回傳請求文字
async fn read_req<S: AsyncReadExt + Unpin>(s: &mut S) -> String {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        match s.read(&mut tmp).await {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// HTTPS 伺服器：回應依（本機 IP，Host）決定
async fn https_server(addr: SocketAddr, cfg: Arc<rustls::ServerConfig>, respond: fn(IpAddr, &str) -> String) {
    let l = TcpListener::bind(addr).await.unwrap();
    let acc = tokio_rustls::TlsAcceptor::from(cfg);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = l.accept().await else { return };
            let acc = acc.clone();
            let me = addr.ip();
            tokio::spawn(async move {
                let Ok(mut s) = acc.accept(tcp).await else { return };
                let req = read_req(&mut s).await;
                let host = req.lines().find_map(|l| l.strip_prefix("Host: ")).unwrap_or("").to_string();
                let _ = s.write_all(respond(me, &host).as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
}

fn http(status: &str, headers: &[(&str, &str)], body: &str) -> String {
    let mut h = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n", body.len());
    for (k, v) in headers {
        h.push_str(&format!("{k}: {v}\r\n"));
    }
    format!("{h}\r\n{body}")
}

/// 同一個埠綁在好幾個 127.0.0.x 上
async fn free_port(hosts: &[&str]) -> u16 {
    for _ in 0..50 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        let mut ok = true;
        for h in hosts {
            if std::net::TcpListener::bind((h.parse::<IpAddr>().unwrap(), p)).is_err() {
                ok = false;
                break;
            }
        }
        if ok {
            return p;
        }
    }
    panic!("找不到可用的埠");
}

fn tmp(tag: &str) -> Paths {
    let d = std::env::temp_dir().join(format!("kuroshio-cdn-it-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    Paths {
        state_dir: d.join("state"),
        seed_dir: d.join("none"),
        cdn_data_dir: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/cdn"),
    }
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[tokio::test]
async fn probes_against_local_servers() {
    let port = free_port(&["127.0.0.1"]).await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    // 不受信任的自簽憑證
    https_server(addr, server_cfg(&["untrusted.test"], false), |_, host| {
        http("200 OK", &[("Server", "cloudflare"), ("CF-RAY", "8a-TPE")], &format!("host={host}"))
    })
    .await;
    let r = probe::https_probe(addr, "untrusted.test", "/", &HttpsOpts::default()).await;
    assert!(!r.ok && r.tls_error, "憑證不受信任：{r:?}");
    let r = probe::https_probe(
        addr,
        "untrusted.test",
        "/",
        &HttpsOpts {
            verify: false,
            ..Default::default()
        },
    )
    .await;
    assert!(r.ok, "{r:?}");
    assert_eq!((r.status, r.h("cf-ray")), (200, "8a-TPE"));
    assert_eq!(r.body, format!("host=untrusted.test:{port}"));
    // 下載測速：伺服器慢慢送，約 0.5 秒
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hp = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        read_req(&mut s).await;
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10485760\r\n\r\n").await;
        let chunk = vec![7u8; 1 << 20];
        for _ in 0..10 {
            if s.write_all(&chunk).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(60)).await;
        }
    });
    let mbps = probe::download_speed(ip("127.0.0.1"), Some(hp), "http://deb.debian.org/x", 2000, 30 << 20).await;
    assert!(mbps > 1.0 && mbps < 1000.0, "{mbps}");
}

#[tokio::test]
async fn verify_and_rewrite_end_to_end() {
    // 127.0.0.1 = 網站原本的節點（日本）、127.0.0.2 = 台灣節點、127.0.0.3 = 憑證不是這個網站的
    let port = free_port(&["127.0.0.1", "127.0.0.2", "127.0.0.3"]).await;
    let site = server_cfg(&["site.test"], true);
    let other = server_cfg(&["other.test"], true);
    let respond = |me: IpAddr, _h: &str| {
        let colo = if me == ip("127.0.0.1") { "NRT" } else { "TPE" };
        http(
            "200 OK",
            &[("CF-RAY", &format!("8a-{colo}")), ("Content-Type", "text/html")],
            "<title>Site</title>",
        )
    };
    https_server(format!("127.0.0.1:{port}").parse().unwrap(), site.clone(), respond).await;
    https_server(format!("127.0.0.2:{port}").parse().unwrap(), site, respond).await;
    https_server(format!("127.0.0.3:{port}").parse().unwrap(), other, respond).await;

    let iprank = Arc::new(IpRank::new(
        &kuroshio_config::with_overrides(&json!({ "iprank": { "port": port } })),
        1000,
    ));
    let net = Arc::new(RealNet::new(iprank).with_ports(port, 1));
    let cfg = json!({ "cdn": { "providers": { "cloudflare": { "enabled": true } }, "verifyTimeoutMs": 3000 } });
    let c = Cdn::load(&cfg, tmp("e2e"), net);
    c.with_state(|st| {
        let d = st.pools.p.get_mut("cloudflare").unwrap();
        let n = |s: &str, ms: f64| {
            let mut x = PoolNode::new(ip(s));
            x.ms = Num::V(ms);
            x
        };
        d.pool4 = vec![n("127.0.0.3", 1.0), n("127.0.0.2", 2.0)];
        d.range4 = cidr(&["127.0.0.0/24"]);
        d.global = cidr(&["127.0.0.1/32"]);
        d.tw = cidr(&["127.0.0.2/32", "127.0.0.3/32"]);
    });
    let mk = || {
        let mut m = Message::default();
        m.answers.push(Record::a("site.test", 300, "127.0.0.1".parse().unwrap()));
        m
    };
    // 第一次：原始結果、TTL 10，背景驗證
    let mut m = mk();
    let r = c.apply(&mut m, "site.test", 1);
    assert_eq!(r.ttl_cap, Some(10));
    for _ in 0..100 {
        if c.inflight().0 == 0 && c.state().db.get("site.test").and_then(|e| e.v4.clone()).is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    {
        let st = c.state();
        let e = st.db.get("site.test").unwrap();
        let v = e.v4.as_ref().unwrap();
        assert!(v.is("ok"), "{v:?}");
        assert_eq!(v.ip, Some(ip("127.0.0.2")), "憑證不符的節點跳過");
        assert_eq!(e.base.as_ref().unwrap().pop.as_deref(), Some("NRT"));
        assert!(!st.pools.zone_hit("cloudflare", ip("127.0.0.3")));
    }
    // 驗證通過：換成台灣節點、原始 TTL
    let mut m = mk();
    let r = c.apply(&mut m, "site.test", 1);
    assert_eq!(r.ttl_cap, None);
    assert_eq!(kuroshio_proto::logic::ips_of(&m, 1), vec![ip("127.0.0.2")]);
    // 管理介面的立即驗證
    let (res, entry) = c.verify_now("SITE.test.", 4).await.unwrap();
    assert_eq!(res, Some("ok"));
    assert_eq!(entry["v4"]["verdict"], "ok");
}

/// 假的 DNS：依 ECS 子網路回不同的 A
async fn dns_server() -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let Ok((n, from)) = s.recv_from(&mut buf).await else { return };
            let q = Message::parse(&buf[..n]).unwrap();
            let ecs = q
                .opt
                .as_ref()
                .and_then(|o| o.options.iter().find(|x| x.0 == opt_code::ECS))
                .map(|x| x.1.clone())
                .unwrap_or_default();
            let mut r = Message::response_to(&q, 0);
            let name = q.questions[0].name.clone();
            if q.questions[0].qtype == 1 {
                // ECS 內容：家族(2) 前綴(1) 範圍(1) 位址
                let a = if ecs.get(4..7) == Some(&[1, 160, 0][..]) {
                    "127.0.0.6"
                } else {
                    "127.0.0.5"
                };
                r.answers.push(Record::a(&name, 60, a.parse().unwrap()));
            }
            let _ = s.send_to(&r.encode(), from).await;
        }
    });
    addr
}

#[tokio::test]
async fn ecs_breakthrough_end_to_end() {
    let dns = dns_server().await;
    let port = free_port(&["127.0.0.6"]).await;
    https_server(
        format!("127.0.0.6:{port}").parse().unwrap(),
        server_cfg(&["www.ak.test"], true),
        |_, _| http("200 OK", &[], "ok"),
    )
    .await;
    let iprank = Arc::new(IpRank::new(
        &kuroshio_config::with_overrides(&json!({ "iprank": { "port": port, "timeoutMs": 300 } })),
        1000,
    ));
    let net = Arc::new(RealNet::new(iprank).with_ports(port, 1));
    let cfg = json!({ "cdn": {
        "providers": { "akamai": { "enabled": true, "ecs": true } },
        "ecs": { "resolvers": [format!("udp://{dns}")], "twSubnets": ["168.95.0.0/24", "1.160.0.0/24"] }
    } });
    let c = Cdn::load(&cfg, tmp("ecs"), net.clone());
    c.with_state(|st| {
        st.db.touch("www.ak.test", "akamai", "cname", &[ip("127.0.0.7")], &[], None);
    });
    use kuroshio_cdn::net::Net;
    let m = net
        .dns(
            &format!("udp://{dns}"),
            "www.ak.test",
            1,
            Some((ip("1.160.0.0"), 24)),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(kuroshio_proto::logic::ips_of(&m, 1), vec![ip("127.0.0.6")], "查詢帶了 ECS");
    c.ecs_probe("www.ak.test", &[ip("127.0.0.7")], &[]).await;
    let e = c.domain("www.ak.test").unwrap();
    assert_eq!(e["ecs"]["verdict"], "ok", "{e}");
    assert_eq!(e["ecs"]["subnet"], "1.160.0.0/24");
    assert_eq!(e["ecs"]["ips4"], json!(["127.0.0.6"]));
    assert_eq!(e["ecs"]["origMs"], "∞", "原本連不上（2.x 寫成 ∞）");
}
