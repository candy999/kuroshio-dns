//! 評測的網路層（可注入）：送查詢、解析主機名稱、查 IP 的業者。
//! 正式環境用 `NetProber`（kuroshio-net 的上游傳輸）與 `IpApi`；測試換成本機假伺服器或固定資料。

use super::rules::AsnInfo;
use crate::scheduler::BoxFuture;
use crate::util::is_bogon_v4;
use anyhow::{anyhow, bail, Result};
use kuroshio_net::upstream::{Kind, Upstream};
use kuroshio_proto::logic::is_sinkhole;
use kuroshio_proto::message::rtype;
use kuroshio_proto::Message;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 上游類型名稱（upstreams.json 的 `type`）
pub fn kind_name(k: Kind) -> &'static str {
    match k {
        Kind::Udp => "udp",
        Kind::Tcp => "tcp",
        Kind::Dot => "dot",
        Kind::Doh => "doh",
        Kind::Doh3 => "doh3",
        Kind::Doq => "doq",
        Kind::DnsCrypt => "dnscrypt",
    }
}

/// 送查詢、解析主機名稱
pub trait Prober: Send + Sync + 'static {
    /// 這個版本能不能測這種上游（不能的會被略過並記在結果的 `skippedTypes`）
    fn supports(&self, up: &Upstream) -> bool;
    /// 送出查詢，回傳原始回應
    fn exchange(&self, up: Upstream, query: Vec<u8>, timeout: Duration) -> BoxFuture<Result<Vec<u8>>>;
    /// 主機名稱的 IPv4（查 DNS 擁有者用）
    fn resolve_v4(&self, host: String) -> BoxFuture<Option<Ipv4Addr>>;
}

/// 正式環境：kuroshio-net 的 udp / tcp / dot / doh；主機名稱用 bootstrap 解析
#[derive(Debug, Default, Clone, Copy)]
pub struct NetProber;

impl Prober for NetProber {
    fn supports(&self, up: &Upstream) -> bool {
        up.supported()
    }
    fn exchange(&self, up: Upstream, query: Vec<u8>, timeout: Duration) -> BoxFuture<Result<Vec<u8>>> {
        Box::pin(async move { up.exchange(&query, timeout).await })
    }
    fn resolve_v4(&self, host: String) -> BoxFuture<Option<Ipv4Addr>> {
        Box::pin(async move {
            let ips = kuroshio_net::tls::resolve_host(&host).await.ok()?;
            ips.into_iter().find_map(|ip| match ip {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            })
        })
    }
}

/// 查一批 IPv4 的業者（每個 /16 只會送一個代表進來）
pub trait AsnSource: Send + Sync + 'static {
    /// 回傳查得到的（查不到的不用回）
    fn lookup(&self, ips: Vec<Ipv4Addr>) -> BoxFuture<Vec<(Ipv4Addr, AsnInfo)>>;
}

/// 固定資料（測試、或完全離線）：以 /16（"a.b"）為鍵
#[derive(Debug, Default)]
pub struct StaticAsn(pub HashMap<String, AsnInfo>);

impl AsnSource for StaticAsn {
    fn lookup(&self, ips: Vec<Ipv4Addr>) -> BoxFuture<Vec<(Ipv4Addr, AsnInfo)>> {
        let out = ips
            .into_iter()
            .filter_map(|ip| self.0.get(&sub_key(ip)).map(|i| (ip, i.clone())))
            .collect();
        Box::pin(async move { out })
    }
}

/// /16 鍵（同 2.x 的 `subKey`）
pub fn sub_key(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}", o[0], o[1])
}

// ---------------- ip-api.com（同 2.x：批次 100 筆、免費版只有 http、每分鐘 15 次） ----------------

/// ip-api.com 批次查詢。複製出來的共用同一份速率限制狀態，同一個實例在多次評測之間重複使用。
#[derive(Clone)]
pub struct IpApi {
    inner: Arc<IpApiInner>,
}

struct IpApiInner {
    host: String,
    port: u16,
    /// 下次可以送出的時間（速率限制）
    next_at: tokio::sync::Mutex<Option<Instant>>,
    /// 查詢失敗後等多久再試
    retry_wait: Duration,
}

impl Default for IpApi {
    fn default() -> IpApi {
        IpApi::new("ip-api.com", 80, Duration::from_secs(3))
    }
}

struct HttpResp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpResp {
    fn header(&self, k: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(k))
            .map(|(_, v)| v.as_str())
    }
}

impl IpApi {
    pub fn new(host: &str, port: u16, retry_wait: Duration) -> IpApi {
        IpApi {
            inner: Arc::new(IpApiInner {
                host: host.to_string(),
                port,
                next_at: tokio::sync::Mutex::new(None),
                retry_wait,
            }),
        }
    }
}

impl IpApiInner {
    async fn post(&self, body: &[u8]) -> Result<HttpResp> {
        let ip = match self.host.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => *kuroshio_net::tls::resolve_host(&self.host)
                .await?
                .iter()
                .find(|i| i.is_ipv4())
                .ok_or_else(|| anyhow!("解析不到 {}", self.host))?,
        };
        let limit = Duration::from_secs(15);
        let mut s = tokio::time::timeout(limit, tokio::net::TcpStream::connect(SocketAddr::new(ip, self.port)))
            .await
            .map_err(|_| anyhow!("連線逾時"))??;
        let req = format!(
            "POST /batch?fields=status,query,isp,as,org HTTP/1.1\r\nHost: {}\r\nUser-Agent: kuroshio/{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.host,
            env!("CARGO_PKG_VERSION"),
            body.len()
        );
        let mut raw = Vec::new();
        tokio::time::timeout(limit, async {
            s.write_all(req.as_bytes()).await?;
            s.write_all(body).await?;
            let mut buf = [0u8; 8192];
            loop {
                let n = s.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > 1 << 20 {
                    bail!("回應太大");
                }
            }
            Ok(())
        })
        .await
        .map_err(|_| anyhow!("讀取逾時"))??;
        parse_http(&raw)
    }

    async fn lookup_all(&self, ips: Vec<Ipv4Addr>) -> Vec<(Ipv4Addr, AsnInfo)> {
        let mut out = Vec::new();
        for chunk in ips.chunks(100) {
            let body = serde_json::to_vec(&chunk.iter().map(|i| i.to_string()).collect::<Vec<_>>()).unwrap_or_default();
            for _attempt in 1..=3 {
                let at = *self.next_at.lock().await;
                if let Some(t) = at {
                    tokio::time::sleep_until(t.into()).await;
                }
                let resp = match self.post(&body).await {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::debug!("ip-api 查詢失敗：{e:#}");
                        tokio::time::sleep(self.retry_wait).await;
                        continue;
                    }
                };
                if resp.status == 429 {
                    *self.next_at.lock().await = Some(Instant::now() + Duration::from_secs(60));
                    continue;
                }
                let arr: Vec<serde_json::Value> = serde_json::from_slice(&resp.body).unwrap_or_default();
                for d in &arr {
                    if d.get("status").and_then(|s| s.as_str()) != Some("success") {
                        continue;
                    }
                    let f = |k: &str| d.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let Ok(ip) = f("query").parse::<Ipv4Addr>() else { continue };
                    out.push((ip, AsnInfo::from_ip_api(&f("isp"), &f("org"), &f("as"))));
                }
                // 速率：X-Rl 剩餘次數、X-Ttl 幾秒後重置；同 2.x 每批之間至少間隔 4.2 秒
                let left: Option<u64> = resp.header("x-rl").and_then(|v| v.parse().ok());
                let ttl: Option<u64> = resp.header("x-ttl").and_then(|v| v.parse().ok());
                let wait = match (left, ttl) {
                    (Some(0), Some(t)) if t > 0 => Duration::from_secs(t + 1),
                    _ => Duration::from_millis(4200),
                };
                *self.next_at.lock().await = Some(Instant::now() + wait);
                break;
            }
        }
        out
    }
}

fn parse_http(raw: &[u8]) -> Result<HttpResp> {
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or_else(|| anyhow!("回應不完整"))?;
    let head = std::str::from_utf8(&raw[..end])?;
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("狀態列錯誤"))?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let mut body = raw[end + 4..].to_vec();
    let chunked = headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked"));
    if chunked {
        let mut out = Vec::new();
        let mut i = 0;
        while let Some(p) = body[i..].windows(2).position(|w| w == b"\r\n") {
            let size_line = std::str::from_utf8(&body[i..i + p])?;
            let size = usize::from_str_radix(size_line.split(';').next().unwrap_or("").trim(), 16)?;
            i += p + 2;
            if size == 0 || i + size > body.len() {
                break;
            }
            out.extend_from_slice(&body[i..i + size]);
            i += size + 2;
        }
        body = out;
    }
    Ok(HttpResp { status, headers, body })
}

impl AsnSource for IpApi {
    fn lookup(&self, ips: Vec<Ipv4Addr>) -> BoxFuture<Vec<(Ipv4Addr, AsnInfo)>> {
        let inner = self.inner.clone();
        Box::pin(async move { inner.lookup_all(ips).await })
    }
}

// ---------------- 查詢與分類（同 2.x 的 queryOnce / query） ----------------

/// 一次查詢的結果
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// 正常解析，A 記錄（依回應順序）
    Ok(Vec<Ipv4Addr>),
    /// 被封鎖：NXDOMAIN、沒有 A 記錄、導向 sinkhole / 私有位址
    Blocked(String),
    /// 連線失敗、逾時、REFUSED、SERVFAIL…
    Error(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct QueryResult {
    pub outcome: Outcome,
    pub ms: f64,
}

fn rcode_name(r: u16) -> String {
    match r {
        0 => "NOERROR".into(),
        1 => "FORMERR".into(),
        2 => "SERVFAIL".into(),
        3 => "NXDOMAIN".into(),
        4 => "NOTIMP".into(),
        5 => "REFUSED".into(),
        6 => "YXDOMAIN".into(),
        7 => "YXRRSET".into(),
        8 => "NXRRSET".into(),
        9 => "NOTAUTH".into(),
        10 => "NOTZONE".into(),
        n => format!("RCODE_{n}"),
    }
}

/// 把回應分類（同 2.x：NXDOMAIN / 無 A / 全是 sinkhole 或私有位址 = 封殺）
pub fn classify(resp: &[u8]) -> Outcome {
    let Ok(m) = Message::parse(resp) else {
        return Outcome::Error("BAD_PACKET".into());
    };
    match m.rcode {
        0 => {}
        3 => return Outcome::Blocked("NXDOMAIN".into()),
        r => return Outcome::Error(rcode_name(r)),
    }
    let ips: Vec<Ipv4Addr> = kuroshio_proto::logic::ips_of(&m, rtype::A)
        .into_iter()
        .filter_map(|ip| match ip {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
        .collect();
    if ips.is_empty() {
        return Outcome::Blocked("無 A 記錄".into());
    }
    if ips.iter().all(|ip| is_sinkhole(IpAddr::V4(*ip)) || is_bogon_v4(*ip)) {
        return Outcome::Blocked(format!("導向 {}", ips[0]));
    }
    Outcome::Ok(ips)
}

pub async fn query_once(p: &dyn Prober, up: &Upstream, domain: &str, timeout: Duration) -> QueryResult {
    let q = kuroshio_proto::build_query(0, domain, rtype::A);
    let t0 = Instant::now();
    let r = p.exchange(up.clone(), q, timeout).await;
    let ms = t0.elapsed().as_secs_f64() * 1000.0;
    let outcome = match r {
        Ok(resp) => classify(&resp),
        Err(e) => Outcome::Error(format!("{e}")),
    };
    QueryResult { outcome, ms }
}

/// 失敗時再試一次（中間等 200 ms）
pub async fn query(p: &dyn Prober, up: &Upstream, domain: &str, timeout: Duration, retries: u32) -> QueryResult {
    let mut r = query_once(p, up, domain, timeout).await;
    for _ in 0..retries {
        if !matches!(r.outcome, Outcome::Error(_)) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        r = query_once(p, up, domain, timeout).await;
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_parse() {
        let r = parse_http(b"HTTP/1.1 200 OK\r\nX-Rl: 0\r\nX-Ttl: 7\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n[1,\r\n2\r\n2]\r\n0\r\n\r\n")
            .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.header("x-rl"), Some("0"));
        assert_eq!(r.body, b"[1,2]");
    }
}
