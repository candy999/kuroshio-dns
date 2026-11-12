//! 兩節點測試的共用工具：本機起 HTTPS / TLS（ALPN kuroshio/2）/ QUIC 三種伺服器，用自簽憑證（加進信任清單），
//! 網域用 StaticResolver 對到 127.0.0.1（正式環境的檢查不變：端點主機一定要等於網域、憑證要驗證通過）。
#![allow(dead_code)]

use kuroshio_community::envelope::{Envelope, ALPN};
use kuroshio_community::{Community, Config, DataProvider, LocalRecord, Options, RangeCheck, Received, Scheme, StaticResolver, Tuning};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::Value;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

pub fn now() -> u64 {
    kuroshio_community::util::now_ms()
}

pub fn tmpdir(name: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "community-{}-{}-{}",
        std::process::id(),
        name,
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// 假的 CDN / 評測資料：Cloudflare 範圍 104.16.0.0/13
#[derive(Default)]
pub struct Fake {
    pub records: Mutex<Vec<LocalRecord>>,
    pub received: Mutex<Vec<Received>>,
}

impl Fake {
    pub fn set(&self, v: Vec<LocalRecord>) {
        *self.records.lock().unwrap() = v;
    }
    pub fn take(&self) -> Vec<Received> {
        std::mem::take(&mut *self.received.lock().unwrap())
    }
}

impl DataProvider for Fake {
    fn local_records(&self) -> Vec<LocalRecord> {
        self.records.lock().unwrap().clone()
    }
    fn net_ctx(&self) -> kuroshio_community::envelope::NetInfo {
        kuroshio_community::envelope::NetInfo {
            asn: Some(3462),
            colo: "TPE".into(),
        }
    }
    fn in_range(&self, provider: &str, ip: IpAddr) -> RangeCheck {
        if provider != "cloudflare" {
            return RangeCheck::UnknownProvider;
        }
        match ip {
            IpAddr::V4(v) if v.octets()[0] == 104 && (16..24).contains(&v.octets()[1]) => RangeCheck::InRange,
            _ => RangeCheck::OutOfRange,
        }
    }
    fn asn_of(&self, _ip: IpAddr) -> Option<u32> {
        Some(3462)
    }
    fn on_received(&self, b: &Received) {
        self.received.lock().unwrap().push(b.clone());
    }
}

pub fn node_rec(ip: &str) -> LocalRecord {
    LocalRecord::Node {
        p: "cloudflare".into(),
        ip: ip.parse().unwrap(),
        pop: "TPE".into(),
        ms: Some(3),
        obs: now(),
        permanent: false,
    }
}

pub fn site_rec(name: &str, ip: &str) -> LocalRecord {
    LocalRecord::Site {
        name: name.into(),
        p: "cloudflare".into(),
        fam: 4,
        ips: vec![ip.parse().unwrap()],
        pop: "TPE".into(),
        obs: now(),
    }
}

pub fn upstream_rec(url: &str, proto: &str) -> LocalRecord {
    LocalRecord::Upstream {
        url: url.into(),
        proto: proto.into(),
        ms: Some(5),
        ok: 1.0,
        obs: now(),
    }
}

/// 伺服器端故障注入（模擬惡意或壞掉的好友）
#[derive(Default)]
pub struct Faults {
    /// 回應的簽名翻一個位元
    pub corrupt_sig: AtomicBool,
    /// sync 回應換成這個內容
    pub sync_reply: Mutex<Option<Vec<u8>>>,
    /// QUIC 串流不回應就關閉（測管道退回）
    pub quic_down: AtomicBool,
    /// 假裝還是 2.x（v1）：v2 路徑 404、/.well-known/candydns 200、TLS / QUIC 的 kuroshio/2 不通
    pub v1_mode: AtomicBool,
    pub requests: AtomicUsize,
}

fn mangle(f: &Faults, action: &str, body: Vec<u8>) -> Vec<u8> {
    f.requests.fetch_add(1, Ordering::SeqCst);
    if action == "sync" {
        if let Some(r) = f.sync_reply.lock().unwrap().clone() {
            return r;
        }
    }
    if f.corrupt_sig.load(Ordering::SeqCst) && action != "identity" {
        if let Ok(mut e) = Envelope::decode(&body) {
            if let Some(s) = e.sig.as_mut() {
                s[0] ^= 1;
                return e.encode();
            }
        }
    }
    body
}

pub struct Node {
    pub c: Arc<Community>,
    pub data: Arc<Fake>,
    pub faults: Arc<Faults>,
    pub domain: String,
    pub https: u16,
    pub dot: u16,
    pub doq: u16,
    pub key_dir: PathBuf,
    pub state_dir: PathBuf,
}

impl Node {
    pub fn input(&self) -> String {
        format!("{}:{}", self.domain, self.https)
    }
    pub fn peer(&self, d: &str) -> kuroshio_community::peers::Peer {
        self.c.peer(d).unwrap_or_else(|| panic!("{} 沒有 {d} 的紀錄", self.domain))
    }
    pub fn endpoint(&self, s: Scheme) -> kuroshio_community::Endpoint {
        let port = match s {
            Scheme::Https => self.https,
            Scheme::Dot => self.dot,
            Scheme::Doq => self.doq,
        };
        kuroshio_community::Endpoint {
            scheme: s,
            host: self.domain.clone(),
            port,
        }
    }
}

pub struct Spec {
    pub channels: Vec<Scheme>,
    pub rules: Vec<Value>,
    pub pow_bits: u8,
    pub tuning: Tuning,
    pub max_bundle_mb: u32,
    /// 用 serve_stream / serve_quic（整合端會用的 API），不經過故障注入
    pub direct: bool,
    pub key_dir: Option<PathBuf>,
}

pub fn fast_tuning() -> Tuning {
    Tuning {
        connect_timeout: Duration::from_secs(3),
        total_timeout: Duration::from_secs(15),
        poke_pull_ms: (30, 120),
        follow_up_ms: 30,
        rerequest_ms: 150,
        mutual_sync_ms: 30,
        poke_interval_ms: 10 * 60_000,
        share_refresh_ms: 10 * 60_000,
        requests_per_ip_hour: 1000,
        requests_global_hour: 1000,
        all_per_ip_minute: 100_000,
        callbacks_per_domain_hour: 1000,
        probes: 3,
        invite_accepts_hour: 1000,
    }
}

impl Default for Spec {
    fn default() -> Self {
        Spec {
            channels: vec![Scheme::Doq, Scheme::Dot, Scheme::Https],
            rules: vec![],
            pow_bits: 8,
            tuning: fast_tuning(),
            max_bundle_mb: 32,
            direct: false,
            key_dir: None,
        }
    }
}

pub fn resolver(names: &[&str]) -> Arc<StaticResolver> {
    let r = Arc::new(StaticResolver::default());
    for n in names {
        r.set(n, &[LOCAL]);
    }
    r
}

fn tls_config(domain: &str, alpn: &[&[u8]]) -> (Arc<rustls::ServerConfig>, CertificateDer<'static>) {
    let ck = rcgen::generate_simple_self_signed(vec![domain.to_string()]).unwrap();
    let der = CertificateDer::from(ck.cert.der().to_vec());
    kuroshio_net::tls::add_root(der.clone());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
    let mut c = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key)
        .unwrap();
    c.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    (Arc::new(c), der)
}

pub async fn node(domain: &str, r: &Arc<StaticResolver>, spec: Spec) -> Node {
    r.set(domain, &[LOCAL]);
    let (h1cfg, _) = tls_config(domain, &[b"http/1.1"]);
    let (fcfg, _) = tls_config(domain, &[ALPN]);
    let (qtls, _) = tls_config(domain, &[ALPN]);
    let https_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dot_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let qcrypto = quinn::crypto::rustls::QuicServerConfig::try_from(qtls).unwrap();
    let qep = quinn::Endpoint::server(quinn::ServerConfig::with_crypto(Arc::new(qcrypto)), "127.0.0.1:0".parse().unwrap()).unwrap();
    let (https, dot, doq) = (
        https_l.local_addr().unwrap().port(),
        dot_l.local_addr().unwrap().port(),
        qep.local_addr().unwrap().port(),
    );
    let mut endpoints = vec![];
    for s in &spec.channels {
        endpoints.push(match s {
            Scheme::Https => format!("https://{domain}:{https}"),
            Scheme::Dot => format!("dot://{domain}:{dot}"),
            Scheme::Doq => format!("doq://{domain}:{doq}"),
        });
    }
    let cfg = Config {
        enabled: true,
        domain: domain.into(),
        endpoints,
        pow_bits: spec.pow_bits,
        rules: spec.rules,
        max_bundle_mb: spec.max_bundle_mb,
        ..Default::default()
    };
    let key_dir = spec.key_dir.unwrap_or_else(|| tmpdir(&format!("{domain}-key")));
    let state_dir = tmpdir(&format!("{domain}-state"));
    let data = Arc::new(Fake::default());
    let mut opts = Options::new(&key_dir, &state_dir);
    opts.provider = data.clone();
    opts.resolver = r.clone();
    opts.tuning = spec.tuning;
    let c = Community::open(cfg, opts).unwrap();
    let faults = Arc::new(Faults::default());

    // HTTPS（HTTP/1.1）
    {
        let (c, f) = (c.clone(), faults.clone());
        let acc = tokio_rustls::TlsAcceptor::from(h1cfg);
        tokio::spawn(async move {
            loop {
                let Ok((tcp, peer)) = https_l.accept().await else { return };
                let (c, f, acc) = (c.clone(), f.clone(), acc.clone());
                tokio::spawn(async move {
                    let Ok(mut s) = acc.accept(tcp).await else { return };
                    let mut buf = Vec::new();
                    let mut b = [0u8; 4096];
                    let end = loop {
                        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break p + 4;
                        }
                        match s.read(&mut b).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&b[..n]),
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..end]).to_string();
                    let mut it = head.split_whitespace();
                    let (method, path) = (it.next().unwrap_or("").to_string(), it.next().unwrap_or("").to_string());
                    let len: usize = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    let mut body = buf[end..].to_vec();
                    if len > 1024 * 1024 {
                        let _ = s
                            .write_all(b"HTTP/1.1 413 Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                            .await;
                        return;
                    }
                    while body.len() < len {
                        match s.read(&mut b).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => body.extend_from_slice(&b[..n]),
                        }
                    }
                    if f.v1_mode.load(Ordering::SeqCst) {
                        let (st, b) = if path.starts_with("/.well-known/candydns") {
                            (200, "{\"msg\":{}}")
                        } else {
                            (404, "")
                        };
                        let resp = format!(
                            "HTTP/1.1 {st} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
                            b.len()
                        );
                        let _ = s.write_all(resp.as_bytes()).await;
                        let _ = s.shutdown().await;
                        return;
                    }
                    let (status, out) = match c.handle_http(&method, &path, &body, peer.ip()).await {
                        Some((st, out)) => {
                            let action = path.rsplit('/').next().unwrap_or("");
                            (st, mangle(&f, action, out))
                        }
                        None => (404, vec![]),
                    };
                    let resp = format!(
                        "HTTP/1.1 {status} X\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        out.len()
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                    let _ = s.write_all(&out).await;
                    let _ = s.shutdown().await;
                });
            }
        });
    }
    // TLS（ALPN kuroshio/2）：長度前綴訊框
    {
        let (c, f) = (c.clone(), faults.clone());
        let acc = tokio_rustls::TlsAcceptor::from(fcfg);
        let direct = spec.direct;
        tokio::spawn(async move {
            loop {
                let Ok((tcp, peer)) = dot_l.accept().await else { return };
                let (c, f, acc) = (c.clone(), f.clone(), acc.clone());
                tokio::spawn(async move {
                    let Ok(mut s) = acc.accept(tcp).await else { return };
                    if f.v1_mode.load(Ordering::SeqCst) {
                        return;
                    }
                    if direct {
                        c.serve_stream(s, peer.ip()).await;
                        return;
                    }
                    use kuroshio_community::transport::{read_frame, write_frame};
                    while let Ok(Some(frame)) = read_frame(&mut s, 128 * 1024).await {
                        let action = Envelope::decode(&frame).ok().and_then(|e| e.a).unwrap_or_default();
                        let out = mangle(&f, &action, c.handle_frame(&frame, peer.ip()).await);
                        if write_frame(&mut s, &out).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
    }
    // QUIC（ALPN kuroshio/2）
    {
        let (c, f) = (c.clone(), faults.clone());
        let direct = spec.direct;
        tokio::spawn(async move {
            while let Some(inc) = qep.accept().await {
                let (c, f) = (c.clone(), f.clone());
                tokio::spawn(async move {
                    let Ok(conn) = inc.await else { return };
                    if f.v1_mode.load(Ordering::SeqCst) {
                        conn.close(1u32.into(), b"v1");
                        return;
                    }
                    let ip = conn.remote_address().ip();
                    if direct {
                        c.serve_quic(conn, ip).await;
                        return;
                    }
                    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                        let (c, f) = (c.clone(), f.clone());
                        tokio::spawn(async move {
                            let Ok(frame) = recv.read_to_end(128 * 1024).await else { return };
                            if f.quic_down.load(Ordering::SeqCst) {
                                send.reset(1u32.into()).ok();
                                return;
                            }
                            let action = Envelope::decode(&frame).ok().and_then(|e| e.a).unwrap_or_default();
                            let out = mangle(&f, &action, c.handle_frame(&frame, ip).await);
                            let _ = send.write_all(&out).await;
                            let _ = send.finish();
                            let _ = send.stopped().await;
                        });
                    }
                });
            }
        });
    }
    let n = Node {
        c,
        data,
        faults,
        domain: domain.into(),
        https,
        dot,
        doq,
        key_dir,
        state_dir,
    };
    let chk = n.c.check().await;
    assert_eq!(chk["ready"], Value::Bool(true), "{domain} 自我檢查：{chk}");
    n
}

/// 立即同步；背景剛好在同步（busy）就等它結束再來一次
pub async fn sync(n: &Node, d: &str) -> Value {
    for _ in 0..250 {
        let r = n.c.sync_peer(d).await;
        if r["status"] != "busy" {
            return r;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("{} 一直在同步 {d}", n.domain);
}

/// 等到條件成立（最多 15 秒，用實際時間算：Windows 的計時器精度約 15 ms，CI 也比較慢）
pub async fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("等不到：{what}");
}

pub fn local(addr: SocketAddr) -> bool {
    addr.ip().is_loopback()
}
