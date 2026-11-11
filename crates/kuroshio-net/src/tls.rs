//! 加密上游（規格 01 第 1.2 節）：bootstrap、TLS 連線、DoT（持久連線 + 管線化）、DoH（HTTP/2 多工，退回 HTTP/1.1）

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use rustls::pki_types::{CertificateDer, ServerName};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot};
use tokio_rustls::client::TlsStream;
use tracing::debug;

// ---------------- bootstrap：加密上游的主機名稱 → IP ----------------

static BOOTSTRAP: RwLock<Vec<IpAddr>> = RwLock::new(Vec::new());
type BootCache = Mutex<HashMap<String, (Vec<IpAddr>, Instant)>>;
fn boot_cache() -> &'static BootCache {
    static C: OnceLock<BootCache> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn set_bootstrap(list: &[String]) {
    let ips: Vec<IpAddr> = list.iter().filter_map(|s| s.trim().parse().ok()).collect();
    if !ips.is_empty() {
        *BOOTSTRAP.write().unwrap() = ips;
    }
}

fn bootstrap_servers() -> Vec<IpAddr> {
    let b = BOOTSTRAP.read().unwrap().clone();
    if b.is_empty() {
        vec![IpAddr::from([1, 1, 1, 1]), IpAddr::from([8, 8, 8, 8])]
    } else {
        b
    }
}

async fn udp_query(server: IpAddr, name: &str, qtype: u16) -> Result<(Vec<IpAddr>, u32)> {
    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let s = UdpSocket::bind(bind).await?;
    s.connect(SocketAddr::new(server, 53)).await?;
    let id = (Instant::now().elapsed().subsec_nanos() as u16) ^ 0x5a5a;
    let q = kuroshio_proto::build_query(id, name, qtype);
    s.send(&q).await?;
    let mut buf = vec![0u8; 1500];
    let n = tokio::time::timeout(Duration::from_millis(1500), s.recv(&mut buf)).await??;
    if !kuroshio_proto::matches(&q, &buf[..n]) {
        bail!("bootstrap 回應不符");
    }
    let m = kuroshio_proto::Message::parse(&buf[..n])?;
    let ips = kuroshio_proto::logic::ips_of(&m, qtype);
    let ttl = m.answers.iter().map(|r| r.ttl).min().unwrap_or(300);
    Ok((ips, ttl))
}

/// 解析加密上游的主機名稱（IP 直接回傳）；快取至少 5 分鐘，查不到時先用過期的
pub async fn resolve_host(host: &str) -> Result<Vec<IpAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let key = host.to_ascii_lowercase();
    let cached = boot_cache().lock().unwrap().get(&key).cloned();
    if let Some((ips, exp)) = &cached {
        if *exp > Instant::now() {
            return Ok(ips.clone());
        }
    }
    for server in bootstrap_servers() {
        let mut ips = Vec::new();
        let mut ttl = u32::MAX;
        for t in [1u16, 28] {
            if let Ok((v, tl)) = udp_query(server, &key, t).await {
                ips.extend(v);
                ttl = ttl.min(tl);
            }
        }
        if !ips.is_empty() {
            let exp = Instant::now() + Duration::from_secs(ttl.max(300) as u64);
            boot_cache().lock().unwrap().insert(key, (ips.clone(), exp));
            return Ok(ips);
        }
    }
    cached.map(|c| c.0).ok_or_else(|| anyhow!("bootstrap 解析不到 {host}"))
}

/// 查 TXT 記錄（社群共享的 `_kuroshio.<網域>` 第二管道用）：用 bootstrap 伺服器，回傳每筆記錄串起來的字串
pub async fn lookup_txt(name: &str) -> Result<Vec<String>> {
    let key = name.trim_end_matches('.').to_ascii_lowercase();
    let mut last = anyhow!("查不到 {key} 的 TXT");
    for server in bootstrap_servers() {
        let r = async {
            let bind: SocketAddr = if server.is_ipv4() {
                "0.0.0.0:0".parse()?
            } else {
                "[::]:0".parse()?
            };
            let s = UdpSocket::bind(bind).await?;
            s.connect(SocketAddr::new(server, 53)).await?;
            let id = (Instant::now().elapsed().subsec_nanos() as u16) ^ 0x3c3c;
            let q = kuroshio_proto::build_query(id, &key, 16);
            s.send(&q).await?;
            let mut buf = vec![0u8; 4096];
            let n = tokio::time::timeout(Duration::from_millis(2000), s.recv(&mut buf)).await??;
            if !kuroshio_proto::matches(&q, &buf[..n]) {
                bail!("TXT 回應不符");
            }
            let m = kuroshio_proto::Message::parse(&buf[..n])?;
            Ok::<_, anyhow::Error>(
                m.answers
                    .iter()
                    .filter(|r| r.rtype == 16)
                    .filter_map(|r| txt_strings(&r.data))
                    .collect::<Vec<_>>(),
            )
        }
        .await;
        match r {
            Ok(v) => return Ok(v),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// TXT 的 rdata：多段 <長度><內容>，串成一個字串
fn txt_strings(d: &kuroshio_proto::message::RData) -> Option<String> {
    let kuroshio_proto::message::RData::Raw(b) = d else { return None };
    let mut out = String::new();
    let mut i = 0;
    while i < b.len() {
        let n = b[i] as usize;
        let seg = b.get(i + 1..i + 1 + n)?;
        out.push_str(&String::from_utf8_lossy(seg));
        i += 1 + n;
    }
    Some(out)
}

// ---------------- TLS ----------------

static EXTRA_ROOTS: RwLock<Vec<CertificateDer<'static>>> = RwLock::new(Vec::new());

/// 額外信任的憑證（測試用自簽憑證，或使用者指定的私有 CA）
pub fn add_root(cert: CertificateDer<'static>) {
    EXTRA_ROOTS.write().unwrap().push(cert);
}

pub(crate) fn client_config(alpn: &[&[u8]]) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    for c in EXTRA_ROOTS.read().unwrap().iter() {
        let _ = roots.add(c.clone());
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("TLS 版本設定")
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    // 同一個設定共用 session 快取：重新連線時用 TLS session resumption，少一次完整握手
    Arc::new(cfg)
}

fn cached_config(alpn_h2: bool) -> Arc<rustls::ClientConfig> {
    static DOT: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    static DOH: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    if !EXTRA_ROOTS.read().unwrap().is_empty() {
        // 有額外憑證（測試）時不快取，確保新加的憑證生效
        return client_config(if alpn_h2 { &[b"h2", b"http/1.1"] } else { &[] });
    }
    if alpn_h2 {
        DOH.get_or_init(|| client_config(&[b"h2", b"http/1.1"])).clone()
    } else {
        DOT.get_or_init(|| client_config(&[])).clone()
    }
}

/// 一般 HTTPS 下載用（只提供 http/1.1）
pub async fn connect_h1(host: &str, port: u16, timeout: Duration) -> Result<TlsStream<TcpStream>> {
    connect_with(host, port, cached_config_h1(), timeout, None).await
}

/// 同 `connect_h1`，但指定從哪個本機位址 / 網卡連出去（多出口時偵測每個出口的公網 IP）
pub async fn connect_h1_from(host: &str, port: u16, timeout: Duration, from: Option<&LocalBind>) -> Result<TlsStream<TcpStream>> {
    connect_with(host, port, cached_config_h1(), timeout, from).await
}

/// 指定對外連線的出口：本機位址，加上（選用的）網卡名稱。
///
/// 只綁來源位址時，Linux 仍然照路由表選出口（除非另外設了依來源位址的路由規則）；
/// 所以 Linux 會再用 `SO_BINDTODEVICE` 綁網卡（需要 root 或 CAP_NET_RAW，失敗就只綁位址）。
/// Windows 綁來源位址就會從那張網卡送出。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalBind {
    pub ip: IpAddr,
    pub device: Option<String>,
}

impl LocalBind {
    pub fn ip(ip: IpAddr) -> LocalBind {
        LocalBind { ip, device: None }
    }
}

/// TCP 連線；`from` 有值時先綁本機位址（與網卡）。位址族不同（IPv4 出口連 IPv6 位址）直接回錯誤。
pub async fn tcp_connect(addr: SocketAddr, from: Option<&LocalBind>) -> std::io::Result<TcpStream> {
    let Some(b) = from else {
        return TcpStream::connect(addr).await;
    };
    if b.ip.is_ipv4() != addr.is_ipv4() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            format!("出口位址 {} 跟目的地 {} 不是同一種 IP 版本", b.ip, addr.ip()),
        ));
    }
    let sock = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some(dev) = b.device.as_deref().filter(|d| !d.is_empty()) {
        if let Err(e) = sock.bind_device(Some(dev.as_bytes())) {
            tracing::debug!("無法綁定網卡 {dev}（{e}），只綁來源位址 {}", b.ip);
        }
    }
    sock.bind(SocketAddr::new(b.ip, 0))?;
    sock.connect(addr).await
}

fn cached_config_h1() -> Arc<rustls::ClientConfig> {
    static H1: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    if !EXTRA_ROOTS.read().unwrap().is_empty() {
        return client_config(&[b"http/1.1"]);
    }
    H1.get_or_init(|| client_config(&[b"http/1.1"])).clone()
}

/// 連線（依序試每個 IP）並完成 TLS 握手
pub async fn connect(host: &str, port: u16, alpn_h2: bool, timeout: Duration) -> Result<TlsStream<TcpStream>> {
    connect_with(host, port, cached_config(alpn_h2), timeout, None).await
}

/// 不檢查憑證（2.x 的 `verifyCert: false`）：只用來探測節點、測速，不拿來傳使用者資料
#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn cached_config_probe(verify: bool) -> Arc<rustls::ClientConfig> {
    static NOVERIFY: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    if verify {
        return cached_config_h1();
    }
    NOVERIFY
        .get_or_init(|| {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()
                .expect("TLS 版本設定")
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
                .with_no_client_auth();
            cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
            Arc::new(cfg)
        })
        .clone()
}

/// 連到指定 IP（不做 DNS 解析），SNI 用 `sni`，ALPN 只提供 http/1.1：
/// CDN 節點探測、網站驗證、測速用（同 2.x `lib/cdn/probe.js` 的 `httpsProbe`）。
/// `verify = false` 時不檢查憑證（2.x 的 `verifyCert: false`）。
/// 握手失敗時錯誤裡帶著 `rustls::Error`（可用 `downcast_ref` 判斷是不是 TLS 問題）。
pub async fn connect_ip(ip: IpAddr, port: u16, sni: &str, verify: bool, timeout: Duration) -> Result<TlsStream<TcpStream>> {
    let name = match sni.parse::<IpAddr>() {
        Ok(ip) => ServerName::IpAddress(ip.into()),
        Err(_) => ServerName::try_from(sni.to_string()).context("主機名稱格式錯誤")?,
    };
    let connector = tokio_rustls::TlsConnector::from(cached_config_probe(verify));
    tokio::time::timeout(timeout, async {
        let tcp = TcpStream::connect(SocketAddr::new(ip, port)).await?;
        tcp.set_nodelay(true)?;
        Ok::<_, anyhow::Error>(connector.connect(name, tcp).await?)
    })
    .await
    .map_err(|_| anyhow!("連線逾時 {ip}:{port}"))?
}

async fn connect_with(
    host: &str,
    port: u16,
    cfg: Arc<rustls::ClientConfig>,
    timeout: Duration,
    from: Option<&LocalBind>,
) -> Result<TlsStream<TcpStream>> {
    let mut ips = resolve_host(host).await?;
    // 指定出口時只試同一種 IP 版本的位址
    if let Some(b) = from {
        ips.retain(|ip| ip.is_ipv4() == b.ip.is_ipv4());
    }
    let name = match host.parse::<IpAddr>() {
        Ok(ip) => ServerName::IpAddress(ip.into()),
        Err(_) => ServerName::try_from(host.to_string()).context("主機名稱格式錯誤")?,
    };
    let connector = tokio_rustls::TlsConnector::from(cfg);
    let mut last = anyhow!("沒有可用的位址");
    for ip in ips {
        let r = tokio::time::timeout(timeout, async {
            let tcp = tcp_connect(SocketAddr::new(ip, port), from).await?;
            tcp.set_nodelay(true)?;
            Ok::<_, anyhow::Error>(connector.connect(name.clone(), tcp).await?)
        })
        .await;
        match r {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => last = e,
            Err(_) => last = anyhow!("連線逾時 {ip}:{port}"),
        }
    }
    Err(last)
}

/// 指定位址連線（呼叫者自己解析主機名稱，例如社群共享要用自己的解析器），SNI 與憑證驗證一律用 `host`
pub async fn connect_addrs(host: &str, addrs: &[SocketAddr], alpn: &[&[u8]], timeout: Duration) -> Result<TlsStream<TcpStream>> {
    let name = match host.parse::<IpAddr>() {
        Ok(ip) => ServerName::IpAddress(ip.into()),
        Err(_) => ServerName::try_from(host.to_string()).context("主機名稱格式錯誤")?,
    };
    let connector = tokio_rustls::TlsConnector::from(client_config(alpn));
    let mut last = anyhow!("沒有可用的位址");
    for addr in addrs {
        let r = tokio::time::timeout(timeout, async {
            let tcp = TcpStream::connect(*addr).await?;
            tcp.set_nodelay(true)?;
            Ok::<_, anyhow::Error>(connector.connect(name.clone(), tcp).await?)
        })
        .await;
        match r {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => last = e,
            Err(_) => last = anyhow!("連線逾時 {addr}"),
        }
    }
    Err(last)
}

// ---------------- DoT：一條持久連線，同時送多筆查詢（RFC 7766 管線化） ----------------

type Reply = oneshot::Sender<Result<Vec<u8>>>;

struct DotConn {
    tx: mpsc::Sender<(Vec<u8>, Reply)>,
}

#[derive(Default)]
pub struct Dot {
    conn: tokio::sync::Mutex<Option<DotConn>>,
}

impl Dot {
    pub async fn exchange(&self, host: &str, port: u16, q: &[u8], timeout: Duration) -> Result<Vec<u8>> {
        // 用舊連線送一次；失敗（對方已關閉）就重新連線再送一次
        for attempt in 0..2 {
            let tx = {
                let mut slot = self.conn.lock().await;
                match slot.as_ref() {
                    Some(c) if !c.tx.is_closed() => c.tx.clone(),
                    _ => {
                        let s = connect(host, port, false, timeout).await?;
                        let (tx, rx) = mpsc::channel(256);
                        tokio::spawn(dot_task(s, rx));
                        *slot = Some(DotConn { tx: tx.clone() });
                        tx
                    }
                }
            };
            let (rtx, rrx) = oneshot::channel();
            if tx.send((q.to_vec(), rtx)).await.is_err() {
                continue;
            }
            match tokio::time::timeout(timeout, rrx).await {
                Ok(Ok(Ok(r))) => return Ok(r),
                Ok(Ok(Err(e))) if attempt == 0 => debug!("DoT {host} 連線中斷，重新連線：{e}"),
                Ok(Ok(Err(e))) => return Err(e),
                Ok(Err(_)) if attempt == 0 => {}
                Ok(Err(_)) => bail!("DoT 連線中斷"),
                Err(_) => bail!("DoT 逾時"),
            }
        }
        bail!("DoT 連線失敗")
    }
}

/// 連線的讀寫迴圈：每筆查詢換一個連線內不重複的 id，回應依 id 送回；閒置 30 秒關閉。
/// id 對不上任何一筆、或 id 對上但問題不同的回應（偽造或錯置的）丟掉，那筆查詢繼續等（跟 UDP 一樣，等到逾時）
async fn dot_task(s: TlsStream<TcpStream>, mut rx: mpsc::Receiver<(Vec<u8>, Reply)>) {
    let (mut rd, mut wr) = tokio::io::split(s);
    // 連線內的 id →（原本的 id，送出的查詢，回覆）
    let mut pending: HashMap<u16, (u16, Vec<u8>, Reply)> = HashMap::new();
    let mut next: u16 = 1;
    let idle = Duration::from_secs(30);
    let mut len_buf = [0u8; 2];
    let fail_all = |pending: &mut HashMap<u16, (u16, Vec<u8>, Reply)>, why: &str| {
        for (_, (_, _, r)) in pending.drain() {
            let _ = r.send(Err(anyhow!("{why}")));
        }
    };
    loop {
        tokio::select! {
            req = rx.recv() => {
                let Some((mut q, reply)) = req else { break };
                if q.len() < 12 {
                    let _ = reply.send(Err(anyhow!("查詢太短")));
                    continue;
                }
                while pending.contains_key(&next) {
                    next = next.wrapping_add(1);
                }
                let orig = u16::from_be_bytes([q[0], q[1]]);
                q[..2].copy_from_slice(&next.to_be_bytes());
                let mut frame = (q.len() as u16).to_be_bytes().to_vec();
                frame.extend_from_slice(&q);
                if let Err(e) = wr.write_all(&frame).await {
                    let _ = reply.send(Err(e.into()));
                    fail_all(&mut pending, "DoT 寫入失敗");
                    break;
                }
                pending.insert(next, (orig, q, reply));
                next = next.wrapping_add(1);
            }
            r = rd.read_exact(&mut len_buf) => {
                if r.is_err() {
                    fail_all(&mut pending, "DoT 連線被關閉");
                    break;
                }
                let mut resp = vec![0u8; u16::from_be_bytes(len_buf) as usize];
                if rd.read_exact(&mut resp).await.is_err() || resp.len() < 12 {
                    fail_all(&mut pending, "DoT 回應不完整");
                    break;
                }
                let id = u16::from_be_bytes([resp[0], resp[1]]);
                if pending.get(&id).map(|p| kuroshio_proto::matches(&p.1, &resp)).unwrap_or(false) {
                    let (orig, _, reply) = pending.remove(&id).unwrap();
                    resp[..2].copy_from_slice(&orig.to_be_bytes());
                    let _ = reply.send(Ok(resp));
                } else {
                    debug!("DoT 回應的 id / 問題對不上，丟掉");
                }
            }
            _ = tokio::time::sleep(idle), if pending.is_empty() => break,
        }
    }
    rx.close();
    // 關閉後還在排隊的請求回錯誤，讓呼叫端重新連線
    while let Ok((_, r)) = rx.try_recv() {
        let _ = r.send(Err(anyhow!("DoT 連線已關閉")));
    }
}

// ---------------- DoH：HTTP/2 多工；伺服器不支援 h2 時用 HTTP/1.1 keep-alive ----------------

enum DohConn {
    H2(h2::client::SendRequest<Bytes>),
    H1(Arc<tokio::sync::Mutex<TlsStream<TcpStream>>>),
}

#[derive(Default)]
pub struct Doh {
    conn: tokio::sync::Mutex<Option<DohConn>>,
}

impl Doh {
    async fn get(&self, host: &str, port: u16, timeout: Duration, fresh: bool) -> Result<DohConn> {
        let mut slot = self.conn.lock().await;
        if !fresh {
            match slot.as_ref() {
                Some(DohConn::H2(s)) => return Ok(DohConn::H2(s.clone())),
                Some(DohConn::H1(s)) => return Ok(DohConn::H1(s.clone())),
                None => {}
            }
        }
        let s = connect(host, port, true, timeout).await?;
        let h2 = s.get_ref().1.alpn_protocol() == Some(b"h2");
        let c = if h2 {
            let (send, conn) = h2::client::handshake(s).await?;
            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    debug!("DoH HTTP/2 連線結束：{e}");
                }
            });
            DohConn::H2(send)
        } else {
            DohConn::H1(Arc::new(tokio::sync::Mutex::new(s)))
        };
        let out = match &c {
            DohConn::H2(s) => DohConn::H2(s.clone()),
            DohConn::H1(s) => DohConn::H1(s.clone()),
        };
        *slot = Some(c);
        Ok(out)
    }

    /// RFC 8484 POST；查詢 id 改成 0（方便 HTTP 快取），回應的 id 也必須是 0，再改回原本的 id
    pub async fn exchange(&self, host: &str, port: u16, path: &str, q: &[u8], timeout: Duration) -> Result<Vec<u8>> {
        let orig = [q[0], q[1]];
        let mut body = q.to_vec();
        body[..2].copy_from_slice(&[0, 0]);
        let body = Bytes::from(body);
        let mut last = anyhow!("DoH 失敗");
        for attempt in 0..2 {
            let conn = match self.get(host, port, timeout, attempt > 0).await {
                Ok(c) => c,
                Err(e) => return Err(e),
            };
            let r = tokio::time::timeout(timeout, async {
                match conn {
                    DohConn::H2(send) => h2_post(send, host, path, body.clone()).await,
                    DohConn::H1(s) => h1_post(&mut *s.lock().await, host, path, &body).await,
                }
            })
            .await;
            match r {
                Ok(Ok(mut resp)) if resp.len() >= 12 => {
                    if resp[..2] != [0, 0] {
                        bail!("DoH 回應的 id 不是 0（送出的是 0）");
                    }
                    resp[..2].copy_from_slice(&orig);
                    return Ok(resp);
                }
                Ok(Ok(_)) => bail!("DoH 回應太短"),
                Ok(Err(e)) => last = e,
                Err(_) => bail!("DoH 逾時"),
            }
            *self.conn.lock().await = None;
        }
        Err(last)
    }
}

async fn h2_post(send: h2::client::SendRequest<Bytes>, host: &str, path: &str, body: Bytes) -> Result<Vec<u8>> {
    let mut send = send.ready().await?;
    let req = http::Request::builder()
        .method("POST")
        .uri(format!("https://{host}{path}"))
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .header("content-length", body.len())
        .body(())?;
    let (resp, mut stream) = send.send_request(req, false)?;
    stream.send_data(body, true)?;
    let resp = resp.await?;
    if resp.status() != 200 {
        bail!("DoH HTTP {}", resp.status());
    }
    let mut b = resp.into_body();
    let mut out = Vec::new();
    while let Some(chunk) = b.data().await {
        let chunk = chunk?;
        let _ = b.flow_control().release_capacity(chunk.len());
        out.extend_from_slice(&chunk);
        if out.len() > 65535 {
            bail!("DoH 回應太大");
        }
    }
    Ok(out)
}

async fn h1_post(s: &mut TlsStream<TcpStream>, host: &str, path: &str, body: &[u8]) -> Result<Vec<u8>> {
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).await?;
    s.write_all(body).await?;
    // 讀標頭
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    let end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        if buf.len() > 16384 {
            bail!("DoH 標頭太大");
        }
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            bail!("DoH 連線被關閉");
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
    let status: u16 = head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    let mut rest = buf[end..].to_vec();
    let header = |name: &str| {
        head.lines()
            .find_map(|l| l.strip_prefix(&format!("{name}:")).map(|v| v.trim().to_string()))
    };
    let body = if let Some(len) = header("content-length").and_then(|v| v.parse::<usize>().ok()) {
        if len > 65535 {
            bail!("DoH 回應太大");
        }
        while rest.len() < len {
            let n = s.read(&mut tmp).await?;
            if n == 0 {
                bail!("DoH 回應不完整");
            }
            rest.extend_from_slice(&tmp[..n]);
        }
        rest.truncate(len);
        rest
    } else if header("transfer-encoding").map(|v| v.contains("chunked")).unwrap_or(false) {
        let mut out = Vec::new();
        loop {
            while !rest.windows(2).any(|w| w == b"\r\n") {
                let n = s.read(&mut tmp).await?;
                if n == 0 {
                    bail!("DoH chunk 不完整");
                }
                rest.extend_from_slice(&tmp[..n]);
            }
            let p = rest.windows(2).position(|w| w == b"\r\n").unwrap();
            let size = usize::from_str_radix(String::from_utf8_lossy(&rest[..p]).split(';').next().unwrap_or("").trim(), 16)?;
            rest.drain(..p + 2);
            while rest.len() < size + 2 {
                let n = s.read(&mut tmp).await?;
                if n == 0 {
                    bail!("DoH chunk 不完整");
                }
                rest.extend_from_slice(&tmp[..n]);
            }
            out.extend_from_slice(&rest[..size]);
            rest.drain(..size + 2);
            if size == 0 || out.len() > 65535 {
                break;
            }
        }
        out
    } else {
        bail!("DoH 回應沒有長度");
    };
    if status != 200 {
        bail!("DoH HTTP {status}");
    }
    Ok(body)
}
