//! 加密 DNS 伺服器（規格 01 第 1.1 節）：DoT（TCP 853）與 DoH（HTTP/1.1 + HTTP/2）
//!
//! - 憑證檔變更 10 秒內自動換上（同 2.x 的 watchCerts）；檔案還不存在時等它出現，每 10 分鐘提醒一次
//! - DoT：一條連線可以同時送多筆查詢，回應不必照順序（RFC 7766）；閒置 30 秒關閉
//! - DoH：GET `?dns=` 與 POST `application/dns-message`；憑證留空 = 純 HTTP（給 IIS / 反向代理用）
//! - 連線數上限依硬體等級（`system.maxTlsConnections`）；記憶體不足時拒絕新連線

use crate::resolver::{Ctx, Resolver};
use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, Response, StatusCode};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Semaphore};
use tracing::{debug, info, warn};

// ---------------- 憑證（熱更新） ----------------

pub struct CertStore {
    cert: PathBuf,
    key: PathBuf,
    current: RwLock<Option<Arc<CertifiedKey>>>,
    mtime: RwLock<Option<(SystemTime, SystemTime)>>,
    last_warn: RwLock<Option<Instant>>,
}

impl std::fmt::Debug for CertStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CertStore({})", self.cert.display())
    }
}

pub fn load_certified_key(cert: &[u8], key: &[u8]) -> Result<CertifiedKey> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert)
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow!("憑證格式錯誤：{e:?}"))?;
    if chain.is_empty() {
        anyhow::bail!("憑證檔裡沒有憑證");
    }
    let key = PrivateKeyDer::from_pem_slice(key).map_err(|e| anyhow!("私鑰格式錯誤：{e:?}"))?;
    let provider = rustls::crypto::ring::default_provider();
    CertifiedKey::from_der(chain, key, &provider).map_err(|e| anyhow!("憑證與私鑰不符：{e}"))
}

impl CertStore {
    pub fn new(cert: impl Into<PathBuf>, key: impl Into<PathBuf>) -> Arc<CertStore> {
        let s = Arc::new(CertStore {
            cert: cert.into(),
            key: key.into(),
            current: RwLock::new(None),
            mtime: RwLock::new(None),
            last_warn: RwLock::new(None),
        });
        s.reload();
        s
    }

    pub fn ready(&self) -> bool {
        self.current.read().unwrap().is_some()
    }

    /// 檔案有變就重新載入；回傳目前是否有可用的憑證
    pub fn reload(&self) -> bool {
        let m = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
        let (Some(a), Some(b)) = (m(&self.cert), m(&self.key)) else {
            let mut w = self.last_warn.write().unwrap();
            if w.map(|t| t.elapsed() > Duration::from_secs(600)).unwrap_or(true) {
                warn!(
                    "找不到憑證 {} / {}，加密 DNS 暫停，檔案出現後自動啟用",
                    self.cert.display(),
                    self.key.display()
                );
                *w = Some(Instant::now());
            }
            return self.ready();
        };
        if *self.mtime.read().unwrap() == Some((a, b)) {
            return self.ready();
        }
        match (std::fs::read(&self.cert), std::fs::read(&self.key)) {
            (Ok(c), Ok(k)) => match load_certified_key(&c, &k) {
                Ok(ck) => {
                    let first = !self.ready();
                    *self.current.write().unwrap() = Some(Arc::new(ck));
                    *self.mtime.write().unwrap() = Some((a, b));
                    info!("{}憑證：{}", if first { "載入" } else { "更新" }, self.cert.display());
                }
                Err(e) => warn!("憑證無法使用（保留舊的）：{e:#}"),
            },
            _ => warn!("讀不到憑證檔"),
        }
        self.ready()
    }

    pub fn spawn_watch(self: &Arc<Self>) {
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                me.reload();
            }
        });
    }

    pub fn server_config(self: &Arc<Self>, alpn: &[&[u8]]) -> Arc<rustls::ServerConfig> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("TLS 版本設定")
            .with_no_client_auth()
            .with_cert_resolver(self.clone());
        cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
        // 伺服器端不接受 0-RTT（避免重放，規格 01 第 1.2 節）
        cfg.max_early_data_size = 0;
        Arc::new(cfg)
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.current.read().unwrap().clone()
    }
}

/// 連線數上限與記憶體壓力檢查
#[derive(Clone)]
pub struct Limits {
    pub conns: Arc<Semaphore>,
}

impl Limits {
    pub fn new(max: usize) -> Limits {
        Limits {
            conns: Arc::new(Semaphore::new(max.max(1))),
        }
    }
    fn admit(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        if crate::app::pressure() == crate::sysinfo::Pressure::Critical {
            return None;
        }
        self.conns.clone().try_acquire_owned().ok()
    }
}

// ---------------- DoT ----------------

pub async fn listen_dot(addr: SocketAddr, certs: Arc<CertStore>, resolver: Arc<Resolver>, limits: Limits) -> Result<SocketAddr> {
    let l = crate::netif::bind_tcp(addr).with_context(|| format!("DoT 監聽 {addr} 失敗"))?;
    let bound = l.local_addr()?;
    // 社群共享開著時同一個埠也接 ALPN kuroshio/2（規格 03 第 4 節）
    let community = resolver.community.get().is_some();
    let alpn: &[&[u8]] = if community {
        &[b"dot", kuroshio_community::ALPN]
    } else {
        &[b"dot"]
    };
    let acceptor = tokio_rustls::TlsAcceptor::from(certs.server_config(alpn));
    info!("DoT 監聽 {bound}");
    tokio::spawn(async move {
        loop {
            let Ok((tcp, peer)) = l.accept().await else { continue };
            let Some(permit) = limits.admit() else {
                debug!("DoT 連線數已滿或記憶體不足，拒絕 {peer}");
                continue;
            };
            if !certs.ready() {
                continue;
            }
            let (acc, r) = (acceptor.clone(), resolver.clone());
            tokio::spawn(async move {
                let _permit = permit;
                let _ = tcp.set_nodelay(true);
                let Ok(Ok(s)) = tokio::time::timeout(Duration::from_secs(10), acc.accept(tcp)).await else {
                    return;
                };
                if s.get_ref().1.alpn_protocol() == Some(kuroshio_community::ALPN) {
                    if let Some(c) = r.community.get().cloned() {
                        c.serve_stream(s, peer.ip()).await;
                    }
                    return;
                }
                dot_conn(s, peer.ip(), r).await;
            });
        }
    });
    Ok(bound)
}

async fn dot_conn<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>(s: S, client: IpAddr, r: Arc<Resolver>) {
    let (mut rd, mut wr) = tokio::io::split(s);
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
    // 寫出端：回應完成一筆寫一筆（不必照查詢順序）
    let writer = tokio::spawn(async move {
        while let Some(resp) = rx.recv().await {
            let mut frame = (resp.len() as u16).to_be_bytes().to_vec();
            frame.extend_from_slice(&resp);
            if wr.write_all(&frame).await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });
    loop {
        let len = match tokio::time::timeout(Duration::from_secs(30), rd.read_u16()).await {
            Ok(Ok(l)) if l >= 12 => l as usize,
            _ => break,
        };
        let mut q = vec![0u8; len];
        if rd.read_exact(&mut q).await.is_err() {
            break;
        }
        let (r, tx) = (r.clone(), tx.clone());
        tokio::spawn(async move {
            let ctx = Ctx { proto: "dot", client };
            if let Some(resp) = r.handle(&q, &ctx).await {
                let _ = tx.send(resp).await;
            }
        });
    }
    drop(tx);
    let _ = writer.await;
}

// ---------------- DoH ----------------

#[derive(Clone)]
pub struct DohOptions {
    pub path: String,
    /// 反向代理在本機時採用 X-Forwarded-For
    pub trust_proxy: bool,
    /// HTTP/3 開著時加 Alt-Svc
    pub alt_svc: Option<String>,
}

fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            b'=' => continue,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// 回應的快取時間：答案的最小 TTL（沒有答案 0）
fn min_ttl(resp: &[u8]) -> u32 {
    kuroshio_proto::Message::parse(resp)
        .ok()
        .map(|m| kuroshio_proto::logic::min_ttl(&m, 0))
        .unwrap_or(0)
}

fn text(code: StatusCode, s: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(code)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from_static(s.as_bytes())))
        .unwrap()
}

/// DoH 請求（HTTP/1.1、HTTP/2、HTTP/3 共用）
pub struct DohReq {
    pub method: hyper::Method,
    pub path: String,
    pub query: Option<String>,
    pub content_type: String,
    pub forwarded_for: Option<String>,
    /// Host 標頭（HTTP/2、HTTP/3 是 :authority），公開頁沒設定網域時用
    pub host: Option<String>,
    pub body: Vec<u8>,
}

/// DoH 處理核心：回傳狀態碼、標頭、內容
pub async fn doh_core(
    req: DohReq,
    peer: IpAddr,
    r: &Arc<Resolver>,
    opts: &DohOptions,
    proto: &'static str,
) -> (StatusCode, Vec<(&'static str, String)>, Bytes) {
    let txt = |code: StatusCode, s: &'static str| {
        (
            code,
            vec![("content-type", "text/plain; charset=utf-8".to_string())],
            Bytes::from_static(s.as_bytes()),
        )
    };
    let client = if opts.trust_proxy && peer.is_loopback() {
        req.forwarded_for
            .as_deref()
            .and_then(|v| v.split(',').next())
            .and_then(|v| parse_forwarded_ip(v.trim()))
            .unwrap_or(peer)
    } else {
        peer
    };
    if req.path == "/robots.txt" {
        return txt(StatusCode::OK, "User-agent: *\nDisallow: /\n");
    }
    // 社群共享 v2（HTTPS 管道）
    if req.path.starts_with(kuroshio_community::BASE_PATH) {
        if let Some(c) = r.community.get() {
            if let Some((code, body)) = c.handle_http(req.method.as_str(), &req.path, &req.body, client).await {
                let code = StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                let h = if body.is_empty() {
                    vec![]
                } else {
                    vec![("content-type", "application/cbor".to_string())]
                };
                return (code, h, Bytes::from(body));
            }
        }
    }
    // 公開頁（首頁、詳細頁、/api/public/*、描述檔）：不是 DoH 查詢的 GET / HEAD 都先問它
    if let Some(site) = r.site.get() {
        if let Some(resp) = site
            .handle(
                req.method.as_str(),
                &req.path,
                req.query.as_deref().unwrap_or(""),
                client,
                req.host.as_deref(),
            )
            .await
        {
            let code = StatusCode::from_u16(resp.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            return (code, resp.headers, resp.body);
        }
    }
    if req.path != opts.path {
        return txt(StatusCode::NOT_FOUND, "not found\n");
    }
    let query = match req.method {
        hyper::Method::GET => match req
            .query
            .as_deref()
            .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("dns=")))
            .and_then(base64url_decode)
        {
            Some(q) => q,
            None => {
                return txt(
                    StatusCode::OK,
                    "DNS over HTTPS endpoint. Use RFC 8484 GET ?dns= or POST application/dns-message.\n",
                )
            }
        },
        hyper::Method::POST => {
            if !req.content_type.starts_with("application/dns-message") {
                return txt(StatusCode::UNSUPPORTED_MEDIA_TYPE, "需要 application/dns-message\n");
            }
            req.body
        }
        _ => return txt(StatusCode::METHOD_NOT_ALLOWED, "GET / POST\n"),
    };
    if query.len() < 12 {
        return txt(StatusCode::BAD_REQUEST, "bad dns message\n");
    }
    match r.handle(&query, &Ctx { proto, client }).await {
        Some(resp) => {
            let mut h = vec![
                ("content-type", "application/dns-message".to_string()),
                ("cache-control", format!("max-age={}", min_ttl(&resp))),
                ("x-robots-tag", "noindex, nofollow".to_string()),
            ];
            if let Some(a) = &opts.alt_svc {
                h.push(("alt-svc", a.clone()));
            }
            (StatusCode::OK, h, Bytes::from(resp))
        }
        None => txt(StatusCode::BAD_REQUEST, "bad dns message\n"),
    }
}

pub async fn handle_doh(
    req: Request<hyper::body::Incoming>,
    peer: IpAddr,
    r: Arc<Resolver>,
    opts: Arc<DohOptions>,
) -> Response<Full<Bytes>> {
    let hdr = |k: &str| req.headers().get(k).and_then(|v| v.to_str().ok()).map(str::to_string);
    let (content_type, forwarded_for) = (hdr("content-type").unwrap_or_default(), hdr("x-forwarded-for"));
    let host = hdr("host").or_else(|| req.uri().authority().map(|a| a.to_string()));
    let (method, path, query) = (
        req.method().clone(),
        req.uri().path().to_string(),
        req.uri().query().map(str::to_string),
    );
    let body = if method == hyper::Method::POST {
        match Limited::new(req.into_body(), 65535).collect().await {
            Ok(b) => b.to_bytes().to_vec(),
            Err(_) => return text(StatusCode::PAYLOAD_TOO_LARGE, "too large\n"),
        }
    } else {
        Vec::new()
    };
    let (code, headers, body) = doh_core(
        DohReq {
            method,
            path,
            query,
            content_type,
            forwarded_for,
            host,
            body,
        },
        peer,
        &r,
        &opts,
        "doh",
    )
    .await;
    let mut b = Response::builder().status(code);
    for (k, v) in headers {
        b = b.header(k, v);
    }
    b.body(Full::new(body)).unwrap()
}

/// DoH 監聽；`certs` 為 None 時是純 HTTP（給本機反向代理）
pub async fn listen_doh(
    addr: SocketAddr,
    certs: Option<Arc<CertStore>>,
    resolver: Arc<Resolver>,
    opts: DohOptions,
    limits: Limits,
) -> Result<SocketAddr> {
    let l = crate::netif::bind_tcp(addr).with_context(|| format!("DoH 監聽 {addr} 失敗"))?;
    let bound = l.local_addr()?;
    let acceptor = certs
        .as_ref()
        .map(|c| tokio_rustls::TlsAcceptor::from(c.server_config(&[b"h2", b"http/1.1"])));
    info!("DoH 監聽 {}://{bound}{}", if certs.is_some() { "https" } else { "http" }, opts.path);
    let opts = Arc::new(opts);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, peer)) = l.accept().await else { continue };
            let Some(permit) = limits.admit() else { continue };
            if certs.as_ref().map(|c| !c.ready()).unwrap_or(false) {
                continue;
            }
            let (acc, r, o) = (acceptor.clone(), resolver.clone(), opts.clone());
            tokio::spawn(async move {
                let _permit = permit;
                let _ = tcp.set_nodelay(true);
                let svc = hyper::service::service_fn(move |req| {
                    let (r, o) = (r.clone(), o.clone());
                    async move { Ok::<_, std::convert::Infallible>(handle_doh(req, peer.ip(), r, o).await) }
                });
                let builder = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
                let res = match acc {
                    Some(acc) => match tokio::time::timeout(Duration::from_secs(10), acc.accept(tcp)).await {
                        Ok(Ok(s)) => builder.serve_connection(hyper_util::rt::TokioIo::new(s), svc).await,
                        _ => return,
                    },
                    None => builder.serve_connection(hyper_util::rt::TokioIo::new(tcp), svc).await,
                };
                if let Err(e) = res {
                    debug!("DoH 連線結束：{e}");
                }
            });
        }
    });
    Ok(bound)
}

// ---------------- QUIC：DoQ（RFC 9250）與 DoH3 ----------------

/// QUIC 端點：IPv6 位址設 `IPV6_V6ONLY`（`0.0.0.0` 與 `::` 可以同時綁同一個埠）
fn quic_endpoint(cfg: quinn::ServerConfig, addr: SocketAddr) -> std::io::Result<quinn::Endpoint> {
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(cfg),
        crate::netif::bind_udp(addr)?,
        Arc::new(quinn::TokioRuntime),
    )
}

fn quic_server(certs: &Arc<CertStore>, alpn: &[&[u8]], max_conns: u32) -> Result<quinn::ServerConfig> {
    let tls = certs.server_config(alpn);
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(|e| anyhow!("QUIC TLS 設定：{e}"))?;
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut t = quinn::TransportConfig::default();
    t.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    // 每條連線同時最多 128 筆查詢（雙向串流）
    t.max_concurrent_bidi_streams(128u32.into());
    t.max_concurrent_uni_streams(16u32.into());
    cfg.transport_config(Arc::new(t));
    cfg.max_incoming(max_conns.max(1) as usize);
    Ok(cfg)
}

/// DoQ：每筆查詢一條雙向串流，2 bytes 長度 + 訊息，id 必須是 0
pub async fn listen_doq(addr: SocketAddr, certs: Arc<CertStore>, resolver: Arc<Resolver>, limits: Limits) -> Result<SocketAddr> {
    let max = limits.conns.available_permits() as u32;
    let ep = quic_endpoint(
        quic_server(
            &certs,
            if resolver.community.get().is_some() {
                &[b"doq", kuroshio_community::ALPN]
            } else {
                &[b"doq"]
            },
            max,
        )?,
        addr,
    )
    .with_context(|| format!("DoQ 監聽 UDP {addr} 失敗"))?;
    let bound = ep.local_addr()?;
    info!("DoQ 監聽 UDP {bound}");
    tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            let Some(permit) = limits.admit() else {
                incoming.refuse();
                continue;
            };
            let r = resolver.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let Ok(conn) = incoming.await else { return };
                let client = conn.remote_address().ip();
                let proto = conn
                    .handshake_data()
                    .and_then(|h| h.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                    .and_then(|h| h.protocol);
                if proto.as_deref() == Some(kuroshio_community::ALPN) {
                    if let Some(c) = r.community.get().cloned() {
                        c.serve_quic(conn, client).await;
                    }
                    return;
                }
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let r = r.clone();
                    tokio::spawn(async move {
                        let Ok(buf) = recv.read_to_end(65537).await else { return };
                        if buf.len() < 14 {
                            return;
                        }
                        let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                        let Some(q) = buf.get(2..2 + len) else { return };
                        if let Some(resp) = r.handle(q, &Ctx { proto: "doq", client }).await {
                            let mut out = (resp.len() as u16).to_be_bytes().to_vec();
                            out.extend_from_slice(&resp);
                            let _ = send.write_all(&out).await;
                            let _ = send.finish();
                        }
                    });
                }
            });
        }
    });
    Ok(bound)
}

/// DoH3：HTTP/3 上的 DoH，處理邏輯跟 HTTP/1.1、HTTP/2 共用 `doh_core`
pub async fn listen_doh3(
    addr: SocketAddr,
    certs: Arc<CertStore>,
    resolver: Arc<Resolver>,
    opts: DohOptions,
    limits: Limits,
) -> Result<SocketAddr> {
    use bytes::Buf;
    let max = limits.conns.available_permits() as u32;
    let ep = quic_endpoint(quic_server(&certs, &[b"h3"], max)?, addr).with_context(|| format!("DoH3 監聽 UDP {addr} 失敗"))?;
    let bound = ep.local_addr()?;
    info!("DoH3 監聽 UDP {bound}{}", opts.path);
    let opts = Arc::new(opts);
    tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            let Some(permit) = limits.admit() else {
                incoming.refuse();
                continue;
            };
            let (r, o) = (resolver.clone(), opts.clone());
            tokio::spawn(async move {
                let _permit = permit;
                let Ok(conn) = incoming.await else { return };
                let peer = conn.remote_address().ip();
                let Ok(mut h3c) = h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn)).await else {
                    return;
                };
                while let Ok(Some(resolver)) = h3c.accept().await {
                    let (r, o) = (r.clone(), o.clone());
                    tokio::spawn(async move {
                        let Ok((req, mut stream)) = resolver.resolve_request().await else {
                            return;
                        };
                        let hdr = |k: &str| req.headers().get(k).and_then(|v| v.to_str().ok()).map(str::to_string);
                        let mut body = Vec::new();
                        if req.method() == hyper::Method::POST {
                            while let Ok(Some(mut chunk)) = stream.recv_data().await {
                                let n = chunk.remaining();
                                body.extend_from_slice(&chunk.copy_to_bytes(n));
                                if body.len() > 65535 {
                                    return;
                                }
                            }
                        }
                        let dreq = DohReq {
                            method: req.method().clone(),
                            path: req.uri().path().to_string(),
                            query: req.uri().query().map(str::to_string),
                            content_type: hdr("content-type").unwrap_or_default(),
                            forwarded_for: None,
                            host: req.uri().authority().map(|a| a.to_string()).or_else(|| hdr("host")),
                            body,
                        };
                        let (code, headers, out) = doh_core(dreq, peer, &r, &o, "doh3").await;
                        let mut resp = http::Response::builder().status(code.as_u16());
                        for (k, v) in headers {
                            resp = resp.header(k, v);
                        }
                        if stream.send_response(resp.body(()).unwrap()).await.is_ok() {
                            let _ = stream.send_data(out).await;
                            let _ = stream.finish().await;
                        }
                    });
                }
            });
        }
    });
    Ok(bound)
}

/// X-Forwarded-For 的第一段：IIS ARR 預設會帶埠號（`1.2.3.4:5678`、`[2001:db8::1]:5678`）
pub fn parse_forwarded_ip(v: &str) -> Option<IpAddr> {
    v.parse::<IpAddr>()
        .ok()
        .or_else(|| v.parse::<SocketAddr>().ok().map(|s| s.ip()))
        .or_else(|| v.trim_start_matches('[').split(']').next()?.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url() {
        assert_eq!(base64url_decode("AAABAAAB").unwrap(), vec![0, 0, 1, 0, 0, 1]);
        assert_eq!(base64url_decode("_-8").unwrap(), vec![0xff, 0xef]);
        assert!(base64url_decode("a b").is_none());
    }
}
