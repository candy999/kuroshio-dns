//! 以「指定 IP + 指定 Host / SNI」送 HTTP 請求（對齊 2.x `lib/cdn/probe.js`）：
//! 判斷 CDN 節點的 POP、驗證網站換到某個節點後能不能用、下載測速。
//!
//! - 只讀狀態碼、標頭（名稱轉小寫，重複的用 `, ` 接起來）與前面一小段內容（有上限）
//! - `Connection: close`、`Accept-Encoding: identity`；chunked 會解開
//! - 整個請求有總時限，超過回 `TIMEOUT`（同 2.x）

use anyhow::{anyhow, bail, Result};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// 跟 2.x 相同的瀏覽器 User-Agent（有些 CDN 對非瀏覽器回不同內容）
pub const UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36";

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProbeResult {
    /// 有收到 HTTP 回應（不管狀態碼）
    pub ok: bool,
    pub status: u16,
    /// 標頭名稱一律小寫；同名的用 `, ` 接起來
    pub headers: Vec<(String, String)>,
    /// 內容前段（UTF-8，無效位元組換成 U+FFFD）
    pub body: String,
    /// 從開始連線到結束的毫秒數
    pub ms: f64,
    /// 失敗原因（`TIMEOUT`、`ECONNREFUSED`、`ERR_TLS_CERT_ALTNAME_INVALID`…）
    pub error: Option<String>,
    /// 失敗是 TLS 造成的（憑證不符、握手被拒…）：通常代表「這個節點不服務這個網站」
    pub tls_error: bool,
}

impl ProbeResult {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    /// 沒有這個標頭時回空字串（同 2.x 的 `h[name] || ''`）
    pub fn h(&self, name: &str) -> &str {
        self.header(name).unwrap_or("")
    }

    pub fn failed(error: impl Into<String>, tls_error: bool) -> ProbeResult {
        ProbeResult {
            ok: false,
            error: Some(error.into()),
            tls_error,
            ms: f64::INFINITY,
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone)]
pub struct HttpsOpts {
    pub timeout: Duration,
    pub max_body: usize,
    /// GET 或 HEAD
    pub method: &'static str,
    /// false = 不檢查憑證（2.x 的 `verifyCert: false`）
    pub verify: bool,
}

impl Default for HttpsOpts {
    fn default() -> Self {
        HttpsOpts {
            timeout: Duration::from_millis(5000),
            max_body: 16384,
            method: "GET",
            verify: true,
        }
    }
}

/// 網站驗證結果：連到 DNS 回答的 IP，用網域當 SNI 做 TLS 握手並完整檢查憑證
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiteCheck {
    /// 憑證有效、而且是這個網域的：這個 IP 真的在服務這個網站（不是劫持）
    Valid,
    /// 有回應 TLS，但憑證不對（名稱不符、自簽、過期、不受信任）：確定是劫持或攔截頁
    Invalid,
    /// 連不上、逾時、握手被拒：無法判斷（不能當成劫持的證據）
    Unverified,
}

impl SiteCheck {
    pub fn name(self) -> &'static str {
        match self {
            SiteCheck::Valid => "憑證有效",
            SiteCheck::Invalid => "憑證不符",
            SiteCheck::Unverified => "無法驗證",
        }
    }
}

/// 驗證「這個 IP 是不是真的在服務這個網域」（每日評測判斷汙染、黑名單體檢共用）
pub async fn verify_site(ip: IpAddr, domain: &str, timeout: Duration) -> (SiteCheck, String) {
    match crate::tls::connect_ip(ip, 443, domain, true, timeout).await {
        Ok(_) => (SiteCheck::Valid, "OK".into()),
        Err(e) => {
            let (code, tls) = classify_error(&e);
            let invalid = tls && (code.starts_with("ERR_TLS") || code.starts_with("UNABLE_TO") || code.starts_with("CERT_"));
            (if invalid { SiteCheck::Invalid } else { SiteCheck::Unverified }, code)
        }
    }
}

/// 把連線 / TLS 錯誤轉成跟 2.x（node）相近的錯誤代碼
fn classify_error(e: &anyhow::Error) -> (String, bool) {
    if let Some(io) = e.downcast_ref::<std::io::Error>() {
        if let Some(tls) = io.get_ref().and_then(|x| x.downcast_ref::<rustls::Error>()) {
            return (tls_code(tls), true);
        }
        let code = match io.kind() {
            std::io::ErrorKind::ConnectionRefused => "ECONNREFUSED",
            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::BrokenPipe => "ECONNRESET",
            std::io::ErrorKind::ConnectionAborted => "ECONNABORTED",
            std::io::ErrorKind::TimedOut => "ETIMEDOUT",
            std::io::ErrorKind::NetworkUnreachable => "ENETUNREACH",
            std::io::ErrorKind::HostUnreachable => "EHOSTUNREACH",
            std::io::ErrorKind::AddrNotAvailable => "EADDRNOTAVAIL",
            _ => return (io.to_string(), false),
        };
        return (code.to_string(), false);
    }
    if let Some(tls) = e.downcast_ref::<rustls::Error>() {
        return (tls_code(tls), true);
    }
    let s = e.to_string();
    if s.contains("逾時") {
        return ("TIMEOUT".into(), false);
    }
    (s, false)
}

fn tls_code(e: &rustls::Error) -> String {
    use rustls::CertificateError as C;
    match e {
        rustls::Error::InvalidCertificate(c) => match c {
            C::NotValidForName | C::NotValidForNameContext { .. } => "ERR_TLS_CERT_ALTNAME_INVALID".into(),
            C::UnknownIssuer => "UNABLE_TO_VERIFY_LEAF_SIGNATURE".into(),
            C::Expired | C::ExpiredContext { .. } => "CERT_HAS_EXPIRED".into(),
            C::NotValidYet | C::NotValidYetContext { .. } => "CERT_NOT_YET_VALID".into(),
            C::Revoked => "CERT_REVOKED".into(),
            other => format!("CERT_ERROR {other:?}"),
        },
        rustls::Error::AlertReceived(a) => format!("SSL_ALERT {a:?}"),
        other => format!("TLS_ERROR {other}"),
    }
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

struct Head {
    status: u16,
    headers: Vec<(String, String)>,
}

fn parse_head(raw: &[u8]) -> Head {
    let text = String::from_utf8_lossy(raw);
    let mut lines = text.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let mut headers: Vec<(String, String)> = Vec::new();
    for l in lines {
        let Some((k, v)) = l.split_once(':') else { continue };
        let k = k.trim().to_ascii_lowercase();
        let v = v.trim();
        match headers.iter_mut().find(|(n, _)| *n == k) {
            Some((_, old)) => {
                old.push_str(", ");
                old.push_str(v);
            }
            None => headers.push((k, v.to_string())),
        }
    }
    Head { status, headers }
}

/// 解開 chunked：回傳（內容，是否已讀到結尾的 0 長度區塊）
fn dechunk(raw: &[u8], max: usize) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        let Some(p) = raw[i..].windows(2).position(|w| w == b"\r\n") else {
            return (out, false);
        };
        let line = String::from_utf8_lossy(&raw[i..i + p]);
        let Ok(size) = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16) else {
            return (out, true); // 格式錯誤就到此為止
        };
        i += p + 2;
        if size == 0 {
            return (out, true);
        }
        let end = (i + size).min(raw.len());
        out.extend_from_slice(&raw[i..end]);
        if out.len() >= max {
            out.truncate(max);
            return (out, true);
        }
        if i + size + 2 > raw.len() {
            return (out, false);
        }
        i += size + 2;
    }
}

/// 送出請求、讀回標頭與內容前段（`max_body` 為上限）
async fn exchange(s: &mut dyn Io, req: &[u8], max_body: usize, head_only: bool) -> Result<(Head, Vec<u8>)> {
    s.write_all(req).await?;
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = vec![0u8; 8192];
    let end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        if buf.len() > 65536 {
            bail!("標頭太大");
        }
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = parse_head(&buf[..end]);
    let no_body = head_only || head.status == 204 || head.status == 304 || (100..200).contains(&head.status);
    if no_body {
        return Ok((head, Vec::new()));
    }
    let chunked = head
        .headers
        .iter()
        .any(|(k, v)| k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked"));
    let len: Option<usize> = head
        .headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.trim().parse().ok());
    let mut raw = buf[end..].to_vec();
    // 讀取途中連線出錯：跟 2.x 一樣，已收到的部分照樣回傳
    loop {
        if chunked {
            let (body, done) = dechunk(&raw, max_body);
            if done || raw.len() > max_body * 2 + 65536 {
                return Ok((head, body));
            }
        } else {
            if let Some(l) = len {
                if raw.len() >= l {
                    raw.truncate(l.min(max_body));
                    return Ok((head, raw));
                }
            }
            if raw.len() >= max_body {
                raw.truncate(max_body);
                return Ok((head, raw));
            }
        }
        let n: usize = s.read(&mut tmp).await.unwrap_or_default();
        if n == 0 {
            let body = if chunked { dechunk(&raw, max_body).0 } else { raw };
            return Ok((head, body));
        }
        raw.extend_from_slice(&tmp[..n]);
    }
}

fn host_header(host: &str, port: u16, default: u16) -> String {
    let h = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == default {
        h
    } else {
        format!("{h}:{port}")
    }
}

async fn run(addr: SocketAddr, tls: Option<(&str, bool)>, req: String, timeout: Duration, max_body: usize, head_only: bool) -> ProbeResult {
    let t0 = Instant::now();
    let r = tokio::time::timeout(timeout, async {
        let mut s: Box<dyn Io> = match tls {
            Some((sni, verify)) => Box::new(crate::tls::connect_ip(addr.ip(), addr.port(), sni, verify, timeout).await?),
            None => {
                let tcp = TcpStream::connect(addr).await?;
                tcp.set_nodelay(true)?;
                Box::new(tcp)
            }
        };
        exchange(&mut *s, req.as_bytes(), max_body, head_only).await
    })
    .await;
    let ms = t0.elapsed().as_secs_f64() * 1000.0;
    match r {
        Err(_) => ProbeResult {
            ms,
            ..ProbeResult::failed("TIMEOUT", false)
        },
        Ok(Err(e)) => {
            let (code, tls_error) = classify_error(&e);
            ProbeResult {
                ms,
                ..ProbeResult::failed(code, tls_error)
            }
        }
        Ok(Ok((head, body))) => ProbeResult {
            ok: true,
            status: head.status,
            headers: head.headers,
            body: String::from_utf8_lossy(&body).into_owned(),
            ms,
            error: None,
            tls_error: false,
        },
    }
}

/// 純 HTTP 探測（同 CDNtest Step2：連到 IP、帶 Host 標頭），內容最多 4 KB
pub async fn http_probe(addr: SocketAddr, host: &str, path: &str, timeout: Duration) -> ProbeResult {
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {UA}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        host_header(host, addr.port(), 80)
    );
    run(addr, None, req, timeout, 4096, false).await
}

/// HTTPS 探測：連到 IP，SNI 與 Host 用網域名稱
pub async fn https_probe(addr: SocketAddr, hostname: &str, path: &str, opts: &HttpsOpts) -> ProbeResult {
    let method = if opts.method.eq_ignore_ascii_case("HEAD") { "HEAD" } else { "GET" };
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {UA}\r\nAccept: text/html,application/json,*/*;q=0.8\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        host_header(hostname, addr.port(), 443)
    );
    run(
        addr,
        Some((hostname, opts.verify)),
        req,
        opts.timeout,
        opts.max_body,
        method == "HEAD",
    )
    .await
}

/// 下載測速：連到 `ip`（`port` 沒給就用網址的埠），Host / SNI 用網址的主機，回傳 MB/s（兩位小數）。
/// 跟 2.x 一樣：收到標頭後開始計時，`max_ms + 3` 秒或收到 `max_bytes` 就停；不到 0.2 秒或狀態碼 ≥ 300 回 0。
pub async fn download_speed(ip: IpAddr, port: Option<u16>, url: &str, max_ms: u64, max_bytes: u64) -> f64 {
    let Ok(u) = crate::fetch::parse_url(url) else { return 0.0 };
    let addr = SocketAddr::new(ip, port.unwrap_or(u.port));
    let deadline = Instant::now() + Duration::from_millis(max_ms + 3000);
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {UA}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        u.path,
        host_header(&u.host, u.port, if u.tls { 443 } else { 80 })
    );
    let left = || deadline.saturating_duration_since(Instant::now());
    let r: Result<(u64, f64)> = async {
        let mut s: Box<dyn Io> = if u.tls {
            Box::new(crate::tls::connect_ip(addr.ip(), addr.port(), &u.host, true, left()).await?)
        } else {
            Box::new(
                tokio::time::timeout(left(), TcpStream::connect(addr))
                    .await
                    .map_err(|_| anyhow!("逾時"))??,
            )
        };
        tokio::time::timeout(left(), s.write_all(req.as_bytes()))
            .await
            .map_err(|_| anyhow!("逾時"))??;
        let mut buf = Vec::new();
        let mut tmp = vec![0u8; 65536];
        let end = loop {
            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break p + 4;
            }
            if buf.len() > 65536 {
                bail!("標頭太大");
            }
            let n = tokio::time::timeout(left(), s.read(&mut tmp))
                .await
                .map_err(|_| anyhow!("逾時"))??;
            if n == 0 {
                bail!("連線被關閉");
            }
            buf.extend_from_slice(&tmp[..n]);
        };
        if parse_head(&buf[..end]).status >= 300 {
            return Ok((0, 0.0)); // 轉址或錯誤都不算測速
        }
        let start = Instant::now();
        let mut bytes = (buf.len() - end) as u64;
        while bytes < max_bytes {
            match tokio::time::timeout(left(), s.read(&mut tmp)).await {
                Ok(Ok(n)) if n > 0 => bytes += n as u64,
                _ => break,
            }
        }
        Ok((bytes, start.elapsed().as_secs_f64()))
    }
    .await;
    match r {
        Ok((bytes, sec)) if sec > 0.2 => (bytes as f64 / 1_048_576.0 / sec * 100.0).round() / 100.0,
        _ => 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heads_and_chunks() {
        let h = parse_head(b"HTTP/1.1 403 Forbidden\r\nServer: cloudflare\r\nSet-Cookie: a=1\r\nset-cookie: b=2\r\nCF-RAY: 8a-TPE\r\n\r\n");
        assert_eq!(h.status, 403);
        assert_eq!(h.headers[0], ("server".into(), "cloudflare".into()));
        assert_eq!(h.headers[1].1, "a=1, b=2");
        assert_eq!(h.headers[2], ("cf-ray".into(), "8a-TPE".into()));
        let (b, done) = dechunk(b"5\r\nhello\r\n6;x=1\r\n world\r\n0\r\n\r\n", 100);
        assert_eq!((b.as_slice(), done), (&b"hello world"[..], true));
        let (b, done) = dechunk(b"5\r\nhel", 100);
        assert_eq!((b.as_slice(), done), (&b"hel"[..], false));
        let (b, done) = dechunk(b"5\r\nhello\r\n5\r\nworld\r\n", 7);
        assert_eq!((b.as_slice(), done), (&b"hellowo"[..], true));
        assert_eq!(host_header("::1", 8443, 443), "[::1]:8443");
        assert_eq!(host_header("a.test", 443, 443), "a.test");
    }

    #[tokio::test]
    async fn plain_http_probe() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap();
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let host = req.lines().find_map(|l| l.strip_prefix("Host: ")).unwrap_or("").to_string();
                    let body = format!("fl=1\nh={host}\ncolo=TPE\n");
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nServer: cloudflare\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                });
            }
        });
        let r = http_probe(addr, "www.cloudflare.com", "/cdn-cgi/trace", Duration::from_secs(2)).await;
        assert!(r.ok, "{r:?}");
        assert_eq!(r.status, 200);
        assert!(r.body.contains("colo=TPE"));
        assert!(r.body.contains(&format!("h=www.cloudflare.com:{}", addr.port())));
        assert_eq!(r.h("server"), "cloudflare");

        // 沒有人聽的埠：連線被拒
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let caddr = closed.local_addr().unwrap();
        drop(closed);
        let r = http_probe(caddr, "x", "/", Duration::from_secs(2)).await;
        assert!(!r.ok && !r.tls_error);
        // Windows 連到本機沒在聽的埠會重送 SYN 約 2 秒才回「拒絕」，可能先逾時
        let e = r.error.as_deref();
        assert!(e == Some("ECONNREFUSED") || (cfg!(windows) && e == Some("TIMEOUT")), "{e:?}");
    }

    #[tokio::test]
    async fn probe_timeout() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let mut keep = Vec::new();
            loop {
                let (s, _) = l.accept().await.unwrap();
                keep.push(s); // 不回應
            }
        });
        let r = http_probe(addr, "x", "/", Duration::from_millis(200)).await;
        assert_eq!(r.error.as_deref(), Some("TIMEOUT"));
    }
}
