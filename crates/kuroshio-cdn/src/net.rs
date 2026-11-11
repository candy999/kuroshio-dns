//! CDN 用到的網路操作：全部經過 `Net` 這個介面，正式環境用 `RealNet`（`kuroshio-net`），
//! 測試換成假的實作（不連網路就能測驗證、ECS、跨 CDN、背景工作的判斷）。

use anyhow::{anyhow, Result};
use kuroshio_net::iprank::{IpRank, Latency, Quality};
use kuroshio_net::probe::{self, HttpsOpts, ProbeResult};
use kuroshio_net::upstream::Upstream;
use kuroshio_proto::message::{opt_code, Message, Opt, Question, FLAG_RD};
use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// ECS 子網路（`168.95.0.0/24` → （IP，前綴長度））
pub fn parse_subnet(s: &str) -> Option<(IpAddr, u8)> {
    let (ip, len) = match s.split_once('/') {
        Some((a, b)) => (a, b.parse().ok()?),
        None => (s, if s.contains(':') { 56 } else { 24 }),
    };
    Some((crate::util::parse_ip(ip)?, len))
}

pub trait Net: Send + Sync {
    /// HTTPS 探測：連到 `ip`，SNI / Host 用 `host`
    fn https_probe<'a>(&'a self, ip: IpAddr, host: &'a str, path: &'a str, opts: HttpsOpts) -> BoxFut<'a, ProbeResult>;
    /// 純 HTTP 探測（80 埠）
    fn http_probe<'a>(&'a self, ip: IpAddr, host: &'a str, path: &'a str, timeout: Duration) -> BoxFut<'a, ProbeResult>;
    /// 下載測速（MB/s）
    fn download_speed<'a>(&'a self, ip: IpAddr, url: &'a str, max_ms: u64) -> BoxFut<'a, f64>;
    /// TCP 443 連線延遲（取 `samples` 次最好的，不經過快取）
    fn tcp_ping(&self, ip: IpAddr, timeout: Duration, samples: u32) -> BoxFut<'_, Latency>;
    /// 連線品質（中位數延遲、抖動、掉包）
    fn quality(&self, ip: IpAddr, n: u32, timeout: Duration, gap: Duration) -> BoxFut<'_, Quality>;
    /// 延遲（使用 IP 測速快取）
    fn latency(&self, ip: IpAddr) -> BoxFut<'_, Latency>;
    /// 快取裡的延遲（不連線）
    fn cached(&self, ip: IpAddr) -> Option<Latency>;
    /// 依延遲排序
    fn rank<'a>(&'a self, ips: &'a [IpAddr]) -> BoxFut<'a, Vec<(IpAddr, Latency)>>;
    /// 本機有沒有 IPv6（還不知道是 None）
    fn v6_usable(&self) -> Option<bool>;
    /// 向 `resolver`（`udp://8.8.8.8` 之類）查詢，可帶 ECS
    fn dns<'a>(
        &'a self,
        resolver: &'a str,
        name: &'a str,
        qtype: u16,
        ecs: Option<(IpAddr, u8)>,
        timeout: Duration,
    ) -> BoxFut<'a, Result<Message>>;
    /// 解析主機名稱（bootstrap）
    fn resolve_host<'a>(&'a self, host: &'a str) -> BoxFut<'a, Vec<IpAddr>>;
    /// 下載文字檔（CDN 官方 IP 範圍）
    fn fetch_text<'a>(&'a self, url: &'a str, max: u64, timeout: Duration) -> BoxFut<'a, Result<String>>;
}

/// 正式環境：`kuroshio-net`
pub struct RealNet {
    pub iprank: Arc<IpRank>,
    /// 探測用的埠（測試時換成本機假伺服器的埠）
    pub https_port: u16,
    pub http_port: u16,
    ups: Mutex<HashMap<String, Upstream>>,
}

impl RealNet {
    pub fn new(iprank: Arc<IpRank>) -> RealNet {
        RealNet {
            iprank,
            https_port: 443,
            http_port: 80,
            ups: Mutex::new(HashMap::new()),
        }
    }

    pub fn with_ports(mut self, https: u16, http: u16) -> RealNet {
        self.https_port = https;
        self.http_port = http;
        self
    }

    fn upstream(&self, spec: &str) -> Result<Upstream> {
        let mut m = self.ups.lock().unwrap();
        if let Some(u) = m.get(spec) {
            return Ok(u.clone());
        }
        let u = Upstream::parse(spec)?;
        if m.len() < 64 {
            m.insert(spec.to_string(), u.clone());
        }
        Ok(u)
    }
}

/// 組查詢（RD、EDNS 1232，可帶 ECS）
pub fn build_query(id: u16, name: &str, qtype: u16, ecs: Option<(IpAddr, u8)>) -> Message {
    let mut options = Vec::new();
    if let Some((ip, p)) = ecs {
        options.push((opt_code::ECS, kuroshio_proto::logic::ecs_option(ip, p)));
    }
    Message {
        id,
        flags: FLAG_RD,
        questions: vec![Question {
            name: name.trim_end_matches('.').to_string(),
            qtype,
            qclass: 1,
        }],
        opt: Some(Opt {
            udp_size: 1232,
            options,
            ..Default::default()
        }),
        ..Default::default()
    }
}

impl Net for RealNet {
    fn https_probe<'a>(&'a self, ip: IpAddr, host: &'a str, path: &'a str, opts: HttpsOpts) -> BoxFut<'a, ProbeResult> {
        Box::pin(async move { probe::https_probe(SocketAddr::new(ip, self.https_port), host, path, &opts).await })
    }

    fn http_probe<'a>(&'a self, ip: IpAddr, host: &'a str, path: &'a str, timeout: Duration) -> BoxFut<'a, ProbeResult> {
        Box::pin(async move { probe::http_probe(SocketAddr::new(ip, self.http_port), host, path, timeout).await })
    }

    fn download_speed<'a>(&'a self, ip: IpAddr, url: &'a str, max_ms: u64) -> BoxFut<'a, f64> {
        Box::pin(async move {
            let port = if url.starts_with("http://") {
                self.http_port
            } else {
                self.https_port
            };
            probe::download_speed(ip, Some(port), url, max_ms, 30 * 1024 * 1024).await
        })
    }

    fn tcp_ping(&self, ip: IpAddr, timeout: Duration, samples: u32) -> BoxFut<'_, Latency> {
        Box::pin(async move { self.iprank.tcp_ping(ip, self.iprank.port(), timeout, samples).await })
    }

    fn quality(&self, ip: IpAddr, n: u32, timeout: Duration, gap: Duration) -> BoxFut<'_, Quality> {
        Box::pin(async move { self.iprank.quality(ip, n, timeout, gap).await })
    }

    fn latency(&self, ip: IpAddr) -> BoxFut<'_, Latency> {
        Box::pin(async move { self.iprank.latency(ip).await })
    }

    fn cached(&self, ip: IpAddr) -> Option<Latency> {
        self.iprank.cached(ip)
    }

    fn rank<'a>(&'a self, ips: &'a [IpAddr]) -> BoxFut<'a, Vec<(IpAddr, Latency)>> {
        Box::pin(async move { self.iprank.rank(ips).await })
    }

    fn v6_usable(&self) -> Option<bool> {
        self.iprank.v6_usable()
    }

    fn dns<'a>(
        &'a self,
        resolver: &'a str,
        name: &'a str,
        qtype: u16,
        ecs: Option<(IpAddr, u8)>,
        timeout: Duration,
    ) -> BoxFut<'a, Result<Message>> {
        Box::pin(async move {
            let up = self.upstream(resolver)?;
            let id = (crate::util::now_ms() as u16) ^ 0x4b44;
            let q = build_query(id, name, qtype, ecs).encode();
            let r = up.exchange(&q, timeout).await?;
            Message::parse(&r).map_err(|e| anyhow!("{e}"))
        })
    }

    fn resolve_host<'a>(&'a self, host: &'a str) -> BoxFut<'a, Vec<IpAddr>> {
        Box::pin(async move { kuroshio_net::tls::resolve_host(host).await.unwrap_or_default() })
    }

    fn fetch_text<'a>(&'a self, url: &'a str, max: u64, timeout: Duration) -> BoxFut<'a, Result<String>> {
        Box::pin(async move {
            let mut buf = Vec::new();
            kuroshio_net::fetch::get(url, &Default::default(), max, timeout, |c| {
                buf.extend_from_slice(c);
                Ok(())
            })
            .await?;
            Ok(String::from_utf8_lossy(&buf).into_owned())
        })
    }
}
