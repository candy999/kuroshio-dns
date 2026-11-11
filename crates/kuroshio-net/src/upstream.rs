//! 上游（規格 01 第 1.2 節）。
//!
//! 第一階段：udp:// 與 tcp://（UDP 回應被截斷時自動改用 TCP）。
//! tls:// https:// h3:// quic:// sdns:// 會被辨識，但還沒實作，啟動時略過並記警告。

use anyhow::{anyhow, bail, Result};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Udp,
    Tcp,
    Dot,
    Doh,
    Doh3,
    Doq,
    DnsCrypt,
}

/// 加密上游的持久連線（複製 Upstream 時共用）
#[derive(Default)]
pub struct Client {
    dot: crate::tls::Dot,
    doh: crate::tls::Doh,
    doq: crate::quic::Doq,
    doh3: crate::quic::Doh3,
}

#[derive(Clone)]
pub struct Upstream {
    /// 正規化後的網址，統計與評測都用這個當 id
    pub id: String,
    pub kind: Kind,
    pub host: String,
    pub port: u16,
    /// DoH 的路徑（含查詢字串）
    pub path: String,
    client: Arc<Client>,
}

impl std::fmt::Debug for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.id)
    }
}

impl PartialEq for Upstream {
    fn eq(&self, o: &Self) -> bool {
        self.id == o.id
    }
}

impl Upstream {
    pub fn parse(spec: &str) -> Result<Upstream> {
        let s = spec.trim();
        // 純 IP 或 ip:port、[v6]:port → udp
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(Self::new(Kind::Udp, &ip.to_string(), 53));
        }
        if let Ok(sa) = s.parse::<SocketAddr>() {
            return Ok(Self::new(Kind::Udp, &sa.ip().to_string(), sa.port()));
        }
        let (scheme, rest) = s.split_once("://").ok_or_else(|| anyhow!("上游格式錯誤：{s}"))?;
        let (kind, default_port) = match scheme.to_ascii_lowercase().as_str() {
            "udp" => (Kind::Udp, 53),
            "tcp" => (Kind::Tcp, 53),
            "tls" => (Kind::Dot, 853),
            "https" => (Kind::Doh, 443),
            "h3" => (Kind::Doh3, 443),
            "quic" => (Kind::Doq, 853),
            "sdns" => (Kind::DnsCrypt, 443),
            other => bail!("不支援的上游協議 {other}://"),
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        let (host, port) = split_host_port(authority, default_port)?;
        if host.is_empty() {
            bail!("上游缺少主機：{s}");
        }
        let mut u = Self::new(kind, &host, port);
        u.path = if path.is_empty() || path == "/" {
            "/dns-query".to_string()
        } else {
            path.to_string()
        };
        if matches!(kind, Kind::Doh | Kind::Doh3 | Kind::DnsCrypt) {
            u.id = s.to_string(); // 路徑也是 id 的一部分
        }
        Ok(u)
    }

    fn new(kind: Kind, host: &str, port: u16) -> Upstream {
        let scheme = match kind {
            Kind::Udp => "udp",
            Kind::Tcp => "tcp",
            Kind::Dot => "tls",
            Kind::Doh => "https",
            Kind::Doh3 => "h3",
            Kind::Doq => "quic",
            Kind::DnsCrypt => "sdns",
        };
        let h = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_string()
        };
        Upstream {
            id: format!("{scheme}://{h}:{port}"),
            kind,
            host: host.to_string(),
            port,
            path: String::new(),
            client: Arc::new(Client::default()),
        }
    }

    /// 這個版本能不能用
    pub fn supported(&self) -> bool {
        match self.kind {
            Kind::Udp | Kind::Tcp => self.host.parse::<IpAddr>().is_ok(),
            Kind::Dot | Kind::Doh | Kind::Doq | Kind::Doh3 => true,
            _ => false,
        }
    }

    fn addr(&self) -> Result<SocketAddr> {
        Ok(SocketAddr::new(self.host.parse()?, self.port))
    }

    /// 送出查詢，回傳原始回應（id 已改回原本的）
    pub async fn exchange(&self, query: &[u8], limit: Duration) -> Result<Vec<u8>> {
        let id = next_id();
        let mut q = query.to_vec();
        kuroshio_proto::set_id(&mut q, id);
        // 加密上游：查詢補到 128 的倍數（RFC 8467），封包長度不洩漏查了什麼
        if matches!(self.kind, Kind::Dot | Kind::Doh | Kind::Doq | Kind::Doh3) {
            if let Ok(mut m) = kuroshio_proto::Message::parse(&q) {
                if m.opt.is_some() {
                    kuroshio_proto::logic::pad(&mut m, 128);
                    q = m.encode();
                }
            }
        }
        let mut resp = match self.kind {
            Kind::Udp => {
                let addr = self.addr()?;
                let r = timeout(limit, udp_exchange(addr, &q)).await.map_err(|_| anyhow!("逾時"))??;
                if kuroshio_proto::header(&r).map(|h| h.tc).unwrap_or(false) {
                    timeout(limit, tcp_exchange(addr, &q)).await.map_err(|_| anyhow!("TCP 逾時"))??
                } else {
                    r
                }
            }
            Kind::Tcp => timeout(limit, tcp_exchange(self.addr()?, &q))
                .await
                .map_err(|_| anyhow!("逾時"))??,
            Kind::Dot => self.client.dot.exchange(&self.host, self.port, &q, limit).await?,
            Kind::Doh => self.client.doh.exchange(&self.host, self.port, &self.path, &q, limit).await?,
            Kind::Doq => self.client.doq.exchange(&self.host, self.port, &q, limit).await?,
            Kind::Doh3 => self.client.doh3.exchange(&self.host, self.port, &self.path, &q, limit).await?,
            _ => bail!("{} 還沒實作", self.id),
        };
        if !kuroshio_proto::matches(&q, &resp) {
            bail!("回應跟查詢不符");
        }
        kuroshio_proto::set_id(&mut resp, kuroshio_proto::header(query)?.id);
        Ok(resp)
    }
}

fn split_host_port(a: &str, default_port: u16) -> Result<(String, u16)> {
    if let Some(rest) = a.strip_prefix('[') {
        let (h, tail) = rest.split_once(']').ok_or_else(|| anyhow!("IPv6 位址缺少 ]"))?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse()?,
            None => default_port,
        };
        return Ok((h.to_string(), port));
    }
    match a.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => Ok((h.to_string(), p.parse()?)),
        _ => Ok((a.to_string(), default_port)),
    }
}

fn next_id() -> u16 {
    // 不需要密碼學等級：每次查詢用新的 socket（來源埠隨機），id 只是再多一層
    static SEED: AtomicU32 = AtomicU32::new(0);
    let mut x = SEED.fetch_add(0x9e37_79b9, Ordering::Relaxed)
        ^ std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    x as u16
}

async fn udp_exchange(addr: SocketAddr, q: &[u8]) -> Result<Vec<u8>> {
    let bind: SocketAddr = if addr.is_ipv4() { "0.0.0.0:0".parse()? } else { "[::]:0".parse()? };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(addr).await?;
    sock.send(q).await?;
    let mut buf = vec![0u8; 65535];
    loop {
        let n = sock.recv(&mut buf).await?;
        if kuroshio_proto::matches(q, &buf[..n]) {
            return Ok(buf[..n].to_vec());
        }
        // 不相符的封包（偽造或遲到的）丟掉，繼續等
    }
}

pub async fn tcp_exchange(addr: SocketAddr, q: &[u8]) -> Result<Vec<u8>> {
    let mut s = TcpStream::connect(addr).await?;
    let mut msg = Vec::with_capacity(q.len() + 2);
    msg.extend_from_slice(&(q.len() as u16).to_be_bytes());
    msg.extend_from_slice(q);
    s.write_all(&msg).await?;
    let len = s.read_u16().await? as usize;
    let mut buf = vec![0u8; len];
    s.read_exact(&mut buf).await?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_specs() {
        let u = Upstream::parse("1.1.1.1").unwrap();
        assert_eq!((u.kind, u.id.as_str()), (Kind::Udp, "udp://1.1.1.1:53"));
        assert_eq!(Upstream::parse("udp://8.8.8.8").unwrap().id, "udp://8.8.8.8:53");
        assert_eq!(Upstream::parse("[2606:4700::1111]:53").unwrap().id, "udp://[2606:4700::1111]:53");
        assert_eq!(Upstream::parse("tcp://[::1]:5353").unwrap().port, 5353);
        assert_eq!(Upstream::parse("tls://one.one.one.one").unwrap().kind, Kind::Dot);
        assert_eq!(Upstream::parse("quic://dns.adguard-dns.com").unwrap().port, 853);
        assert_eq!(Upstream::parse("h3://dns.google/dns-query").unwrap().kind, Kind::Doh3);
        assert_eq!(
            Upstream::parse("https://dns.google/dns-query").unwrap().id,
            "https://dns.google/dns-query"
        );
        assert!(Upstream::parse("ftp://x").is_err());
        assert!(Upstream::parse("udp://1.1.1.1").unwrap().supported());
        assert!(Upstream::parse("tls://1.1.1.1").unwrap().supported());
        assert!(Upstream::parse("quic://dns.adguard-dns.com").unwrap().supported());
        assert!(!Upstream::parse("sdns://AQcAAAAAAAAA").unwrap().supported());
        assert_eq!(Upstream::parse("https://dns.google").unwrap().path, "/dns-query");
        assert_eq!(Upstream::parse("https://doh.example/q?x=1").unwrap().path, "/q?x=1");
    }
}
