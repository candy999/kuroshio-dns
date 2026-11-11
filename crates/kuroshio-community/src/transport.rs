//! 傳輸（規格 03 第 2 節）：三種管道傳一樣的信封
//!
//! | 管道 | 做法 |
//! |---|---|
//! | HTTPS | `POST /.well-known/kuroshio/v2/<動作>`，`content-type: application/cbor`；身分文件 `GET …/identity` |
//! | TLS（TCP，ALPN `kuroshio/2`） | 每筆 = 4 bytes 長度（big-endian）+ 信封；同一條連線可以連續送 |
//! | QUIC（UDP，ALPN `kuroshio/2`） | 每筆請求一條雙向串流，寫完關閉送出端 |
//!
//! 端點的主機名稱一定要等於對方網域（呼叫端檢查）；TLS 一律驗證公開 CA 憑證，SNI = 對方網域。

use crate::envelope::{Envelope, ALPN, BASE_PATH, PROTO};
use crate::provider::Resolver;
use anyhow::{anyhow, bail, Context, Result};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// 回應（或訊框）超過大小上限
#[derive(Debug)]
pub struct TooLarge(pub usize);
impl std::fmt::Display for TooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "超過大小上限（{} bytes）", self.0)
    }
}
impl std::error::Error for TooLarge {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    Doq,
    Dot,
    Https,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Doq => "doq",
            Scheme::Dot => "dot",
            Scheme::Https => "https",
        }
    }

    pub fn parse(s: &str) -> Option<Scheme> {
        match s.to_ascii_lowercase().as_str() {
            "doq" | "quic" => Some(Scheme::Doq),
            "dot" | "tls" => Some(Scheme::Dot),
            "https" | "doh" => Some(Scheme::Https),
            _ => None,
        }
    }

    /// 沒有上次成功的紀錄時的嘗試順序：DoQ → DoT → HTTPS
    pub fn rank(self) -> u8 {
        match self {
            Scheme::Doq => 0,
            Scheme::Dot => 1,
            Scheme::Https => 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    /// `https://網域[:埠][/路徑]`、`dot://網域[:埠]`、`doq://網域[:埠]`（路徑忽略；v1 的 `…/.well-known/candydns` 也接受）
    pub fn parse(s: &str) -> Option<Endpoint> {
        let (scheme, rest) = s.trim().split_once("://")?;
        let scheme = match scheme.to_ascii_lowercase().as_str() {
            "https" => Scheme::Https,
            "dot" => Scheme::Dot,
            "doq" => Scheme::Doq,
            _ => return None,
        };
        let auth = rest.split(['/', '?', '#']).next()?;
        if auth.contains('@') || auth.starts_with('[') {
            return None;
        }
        let (host, port) = match auth.rsplit_once(':') {
            Some((h, p)) => (h, p.parse::<u16>().ok().filter(|p| *p > 0)?),
            None => (auth, if scheme == Scheme::Https { 443 } else { 853 }),
        };
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if !crate::util::valid_domain(&host) {
            return None;
        }
        Some(Endpoint { scheme, host, port })
    }

    fn default_port(&self) -> u16 {
        if self.scheme == Scheme::Https {
            443
        } else {
            853
        }
    }

    /// 網域的預設端點（還沒拿到身分文件時用）；`port` = 使用者輸入的埠
    pub fn defaults(domain: &str, port: Option<u16>) -> Vec<Endpoint> {
        let mk = |scheme, def| Endpoint {
            scheme,
            host: domain.to_string(),
            port: port.unwrap_or(def),
        };
        // 第一次連線先試 HTTPS（最多人開），身分文件拿到之後才依 DoQ → DoT → HTTPS
        vec![mk(Scheme::Https, 443), mk(Scheme::Dot, 853), mk(Scheme::Doq, 853)]
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.port == self.default_port() {
            write!(f, "{}://{}", self.scheme.as_str(), self.host)
        } else {
            write!(f, "{}://{}:{}", self.scheme.as_str(), self.host, self.port)
        }
    }
}

/// 回應：狀態碼 + 內容（200 = 信封；204 = 沒有內容；其他 = 錯誤信封）
#[derive(Debug, Clone)]
pub struct Reply {
    pub status: u16,
    pub body: Vec<u8>,
    /// 連線（含 TLS / QUIC 握手）花的時間
    pub connect_ms: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    pub connect: Duration,
    pub total: Duration,
    /// 回應上限（線上位元組）
    pub max_wire: usize,
}

async fn addrs(resolver: &dyn Resolver, ep: &Endpoint) -> Result<Vec<SocketAddr>> {
    let ips = resolver.lookup(&ep.host).await?;
    let mut v: Vec<SocketAddr> = ips.into_iter().map(|ip| SocketAddr::new(ip, ep.port)).collect();
    v.dedup();
    if v.is_empty() {
        bail!("解析不到 {}", ep.host);
    }
    Ok(v)
}

/// 送一筆請求。`env = None` 表示取身分文件。
pub async fn call(resolver: &dyn Resolver, ep: &Endpoint, action: &str, env: Option<&Envelope>, t: Timeouts) -> Result<Reply> {
    let a = addrs(resolver, ep).await?;
    tokio::time::timeout(t.total, async {
        match ep.scheme {
            Scheme::Https => https(ep, &a, action, env, t).await,
            Scheme::Dot => framed_tls(ep, &a, action, env, t).await,
            Scheme::Doq => quic(ep, &a, action, env, t).await,
        }
    })
    .await
    .map_err(|_| anyhow!("{ep} 逾時"))?
}

fn framed_payload(action: &str, env: Option<&Envelope>) -> Vec<u8> {
    let mut e = env.cloned().unwrap_or(Envelope {
        v: PROTO,
        ..Default::default()
    });
    e.a = Some(action.to_string());
    e.encode()
}

/// TLS / QUIC 管道的回應：空的 = 204；有 err 的錯誤信封 = 該狀態碼；其他 = 200
fn framed_reply(body: Vec<u8>, connect_ms: u32) -> Reply {
    let status = if body.is_empty() {
        204
    } else {
        Envelope::decode(&body).ok().and_then(|e| e.err).unwrap_or(200)
    };
    Reply { status, body, connect_ms }
}

async fn framed_tls(ep: &Endpoint, a: &[SocketAddr], action: &str, env: Option<&Envelope>, t: Timeouts) -> Result<Reply> {
    let t0 = Instant::now();
    let mut s = kuroshio_net::tls::connect_addrs(&ep.host, a, &[ALPN], t.connect).await?;
    let connect_ms = t0.elapsed().as_millis() as u32;
    if s.get_ref().1.alpn_protocol() != Some(ALPN) {
        bail!("{ep} 不支援 ALPN kuroshio/2");
    }
    let payload = framed_payload(action, env);
    let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&payload);
    s.write_all(&frame).await?;
    s.flush().await?;
    let body = read_frame(&mut s, t.max_wire).await?.ok_or_else(|| anyhow!("{ep} 連線被關閉"))?;
    let _ = s.shutdown().await;
    Ok(framed_reply(body, connect_ms))
}

/// 讀一個長度前綴的訊框；連線在訊框開頭被關閉回 None
pub async fn read_frame<S: AsyncRead + Unpin>(s: &mut S, max: usize) -> Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match s.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let n = u32::from_be_bytes(len) as usize;
    if n > max {
        return Err(TooLarge(n).into());
    }
    let mut b = vec![0u8; n];
    s.read_exact(&mut b).await?;
    Ok(Some(b))
}

pub async fn write_frame<S: AsyncWrite + Unpin>(s: &mut S, b: &[u8]) -> Result<()> {
    let mut f = (b.len() as u32).to_be_bytes().to_vec();
    f.extend_from_slice(b);
    s.write_all(&f).await?;
    s.flush().await?;
    Ok(())
}

async fn quic(ep: &Endpoint, a: &[SocketAddr], action: &str, env: Option<&Envelope>, t: Timeouts) -> Result<Reply> {
    let t0 = Instant::now();
    let conn = kuroshio_net::quic::connect_addrs(&ep.host, a, ALPN, t.connect).await?;
    let connect_ms = t0.elapsed().as_millis() as u32;
    let r = async {
        let (mut send, mut recv) = conn.open_bi().await?;
        send.write_all(&framed_payload(action, env)).await?;
        send.finish()?;
        let body = recv.read_to_end(t.max_wire).await.map_err(|e| match e {
            quinn::ReadToEndError::TooLong => anyhow::Error::new(TooLarge(t.max_wire + 1)),
            e => anyhow!("QUIC 讀取失敗：{e}"),
        })?;
        Ok::<_, anyhow::Error>(body)
    }
    .await;
    conn.close(0u32.into(), b"");
    Ok(framed_reply(r?, connect_ms))
}

async fn https(ep: &Endpoint, a: &[SocketAddr], action: &str, env: Option<&Envelope>, t: Timeouts) -> Result<Reply> {
    let path = format!("{BASE_PATH}/{action}");
    match env {
        None => http_request(ep, a, "GET", &path, None, t).await,
        Some(e) => http_request(ep, a, "POST", &path, Some(&e.encode()), t).await,
    }
}

/// 簡單的 HTTP/1.1 請求（一個請求一條連線）
pub async fn http_request(ep: &Endpoint, a: &[SocketAddr], method: &str, path: &str, body: Option<&[u8]>, t: Timeouts) -> Result<Reply> {
    let t0 = Instant::now();
    let mut s = kuroshio_net::tls::connect_addrs(&ep.host, a, &[b"http/1.1"], t.connect).await?;
    let connect_ms = t0.elapsed().as_millis() as u32;
    let host = if ep.port == 443 {
        ep.host.clone()
    } else {
        format!("{}:{}", ep.host, ep.port)
    };
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: kuroshio/{}\r\nAccept: application/cbor\r\nConnection: close\r\n",
        env!("CARGO_PKG_VERSION")
    );
    if let Some(b) = body {
        head.push_str(&format!("Content-Type: application/cbor\r\nContent-Length: {}\r\n", b.len()));
    }
    head.push_str("\r\n");
    s.write_all(head.as_bytes()).await?;
    if let Some(b) = body {
        s.write_all(b).await?;
    }
    s.flush().await?;
    let (status, body) = read_http_response(&mut s, t.max_wire).await?;
    Ok(Reply { status, body, connect_ms })
}

async fn read_more<S: AsyncRead + Unpin>(s: &mut S, buf: &mut Vec<u8>) -> Result<bool> {
    let mut tmp = [0u8; 16 * 1024];
    match s.read(&mut tmp).await {
        Ok(0) => Ok(false),
        Ok(n) => {
            buf.extend_from_slice(&tmp[..n]);
            Ok(true)
        }
        // 對方沒送 close_notify 就關閉：當成結束
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// 讀 HTTP/1.1 回應：content-length / chunked / 讀到關閉，都有大小上限
pub async fn read_http_response<S: AsyncRead + Unpin>(s: &mut S, max: usize) -> Result<(u16, Vec<u8>)> {
    let mut buf = Vec::new();
    let end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        if buf.len() > 16 * 1024 {
            bail!("HTTP 標頭太大");
        }
        if !read_more(s, &mut buf).await? {
            bail!("連線在標頭前被關閉");
        }
    };
    let head = String::from_utf8_lossy(&buf[..end]).to_string();
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .context("HTTP 狀態列錯誤")?;
    let header = |name: &str| {
        head.lines().skip(1).find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_string())
        })
    };
    let mut rest = buf[end..].to_vec();
    if status == 204 || status == 304 {
        return Ok((status, vec![]));
    }
    if let Some(len) = header("content-length").and_then(|v| v.parse::<usize>().ok()) {
        if len > max {
            return Err(TooLarge(len).into());
        }
        while rest.len() < len {
            if !read_more(s, &mut rest).await? {
                bail!("回應不完整");
            }
        }
        rest.truncate(len);
        return Ok((status, rest));
    }
    if header("transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
    {
        let mut out = Vec::new();
        loop {
            while !rest.windows(2).any(|w| w == b"\r\n") {
                if rest.len() > 64 || !read_more(s, &mut rest).await? {
                    bail!("chunk 不完整");
                }
            }
            let p = rest.windows(2).position(|w| w == b"\r\n").unwrap();
            let size = usize::from_str_radix(String::from_utf8_lossy(&rest[..p]).split(';').next().unwrap_or("").trim(), 16)?;
            rest.drain(..p + 2);
            if out.len() + size > max {
                return Err(TooLarge(out.len() + size).into());
            }
            while rest.len() < size + 2 {
                if !read_more(s, &mut rest).await? {
                    bail!("chunk 不完整");
                }
            }
            out.extend_from_slice(&rest[..size]);
            rest.drain(..size + 2);
            if size == 0 {
                return Ok((status, out));
            }
        }
    }
    while read_more(s, &mut rest).await? {
        if rest.len() > max {
            return Err(TooLarge(rest.len()).into());
        }
    }
    Ok((status, rest))
}

/// v1 偵測：`GET /.well-known/candydns` 回 200 → 對方還在 2.x
pub async fn is_v1(resolver: &dyn Resolver, ep: &Endpoint, t: Timeouts) -> bool {
    let Ok(a) = addrs(resolver, ep).await else { return false };
    let r = tokio::time::timeout(t.total, http_request(ep, &a, "GET", "/.well-known/candydns", None, t)).await;
    matches!(r, Ok(Ok(Reply { status: 200, .. })))
}

/// 來源 IP 比對用：IPv4 對應的 IPv6（::ffff:a.b.c.d）轉回 IPv4
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        x => x,
    }
}

/// 公開網路上的位址（不是本機、區網、連結本地、CGNAT、多播、保留區段）。
/// 對方的網域是對方說的：解析到 127.0.0.1 / 192.168.x.x 的話不能連，否則任何人都能叫這台機器去連區網裡的服務
pub fn is_public_ip(ip: IpAddr) -> bool {
    match canonical_ip(ip) {
        IpAddr::V4(v) => {
            let o = v.octets();
            !(v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_unspecified()
                || v.is_broadcast()
                || v.is_multicast()
                || v.is_documentation()
                || o[0] == 0
                || o[0] >= 240
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] & 0xfe) == 18))
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            !(v.is_loopback()
                || v.is_unspecified()
                || v.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] == 0x2001 && s[1] == 0x0db8)
                // NAT64 / 6to4 / IPv4 相容位址：裡面包的 IPv4 可能是內部位址
                || (s[0] == 0x0064 && s[1] == 0xff9b)
                || s[0] == 0x2002
                || s[..6] == [0, 0, 0, 0, 0, 0])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_ips_only() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "240.0.0.1",
            "198.18.0.1",
            "192.0.0.8",
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:192.168.0.1",
            "64:ff9b::7f00:1",
            "2002:7f00:1::1",
            "::7f00:1",
        ] {
            assert!(!is_public_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "100.128.0.1",
            "172.32.0.1",
            "2606:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            assert!(is_public_ip(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn parse_endpoints() {
        let e = Endpoint::parse("https://DNS.Example.com/.well-known/kuroshio").unwrap();
        assert_eq!((e.scheme, e.host.as_str(), e.port), (Scheme::Https, "dns.example.com", 443));
        assert_eq!(e.to_string(), "https://dns.example.com");
        let e = Endpoint::parse("dot://a.test:8853").unwrap();
        assert_eq!((e.scheme, e.port), (Scheme::Dot, 8853));
        assert_eq!(e.to_string(), "dot://a.test:8853");
        assert_eq!(Endpoint::parse("doq://a.test").unwrap().port, 853);
        assert_eq!(
            Endpoint::parse("https://a.test:8443/.well-known/candydns").unwrap().to_string(),
            "https://a.test:8443"
        );
        for bad in [
            "http://a.test",
            "https://1.2.3.4",
            "https://user@a.test",
            "dot://a.test:0",
            "ftp://a.test",
            "https://[::1]:443",
        ] {
            assert!(Endpoint::parse(bad).is_none(), "{bad}");
        }
    }
}
