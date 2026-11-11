//! IP 測速（對齊 2.x `lib/iprank.js`）：TCP 443 連線延遲，以 IP 為鍵快取（跨網域共用）

use serde_json::Value;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Latency {
    pub ok: bool,
    /// 毫秒；失敗是無限大
    pub ms: f64,
}

pub struct IpRank {
    port: u16,
    timeout: Duration,
    ok_ttl: Duration,
    fail_ttl: Duration,
    max_entries: usize,
    sem: Arc<Semaphore>,
    cache: Mutex<HashMap<IpAddr, (Latency, Instant)>>,
    /// 本機有沒有 IPv6 連線能力（第一次 v6 測試後決定；同 2.x 的 `v6Usable`）
    v6: Mutex<Option<bool>>,
}

/// 連線品質（`quality`）：中位數延遲、抖動（相鄰樣本差的平均）、掉包率
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Quality {
    pub ms: f64,
    pub jitter: f64,
    pub loss: f64,
    pub n: u32,
}

/// 連一次；回傳延遲與「本機沒有這個位址家族的路由」（ENETUNREACH 之類）
async fn connect_once(ip: IpAddr, port: u16, timeout: Duration) -> (Latency, bool) {
    let t0 = Instant::now();
    match tokio::time::timeout(timeout, TcpStream::connect(SocketAddr::new(ip, port))).await {
        Ok(Ok(_)) => (
            Latency {
                ok: true,
                ms: t0.elapsed().as_secs_f64() * 1000.0,
            },
            false,
        ),
        Ok(Err(e)) => {
            let unreach = matches!(
                e.kind(),
                std::io::ErrorKind::NetworkUnreachable | std::io::ErrorKind::HostUnreachable | std::io::ErrorKind::AddrNotAvailable
            );
            (
                Latency {
                    ok: false,
                    ms: f64::INFINITY,
                },
                unreach,
            )
        }
        Err(_) => (
            Latency {
                ok: false,
                ms: f64::INFINITY,
            },
            false,
        ),
    }
}

impl IpRank {
    pub fn new(cfg: &Value, max_entries: usize) -> IpRank {
        let n = |k: &str, d: u64| kuroshio_config::get(cfg, k).and_then(Value::as_u64).unwrap_or(d);
        IpRank {
            port: n("iprank.port", 443) as u16,
            timeout: Duration::from_millis(n("iprank.timeoutMs", 800)),
            ok_ttl: Duration::from_secs(n("iprank.okTtlSec", 600)),
            fail_ttl: Duration::from_secs(n("iprank.failTtlSec", 120)),
            max_entries: max_entries.max(256),
            sem: Arc::new(Semaphore::new(n("iprank.concurrency", 64).max(1) as usize)),
            cache: Mutex::new(HashMap::new()),
            v6: Mutex::new(None),
        }
    }

    pub fn cached(&self, ip: IpAddr) -> Option<Latency> {
        self.cache.lock().unwrap().get(&ip).map(|(l, _)| *l)
    }

    /// 測速用的埠（預設 443）
    pub fn port(&self) -> u16 {
        self.port
    }

    /// 本機有沒有 IPv6 連線能力：還沒測過是 None
    pub fn v6_usable(&self) -> Option<bool> {
        *self.v6.lock().unwrap()
    }

    fn note_v6(&self, ip: IpAddr, l: &Latency, unreach: bool) {
        if ip.is_ipv6() {
            if l.ok {
                *self.v6.lock().unwrap() = Some(true);
            } else if unreach {
                *self.v6.lock().unwrap() = Some(false);
            }
        }
    }

    async fn ping(&self, ip: IpAddr) -> Latency {
        let _permit = self.sem.acquire().await;
        let (l, unreach) = connect_once(ip, self.port, self.timeout).await;
        self.note_v6(ip, &l, unreach);
        l
    }

    /// 連 `samples` 次取最好的一次（同 2.x `tcpPing`）；不經過快取，也不受同時數限制
    pub async fn tcp_ping(&self, ip: IpAddr, port: u16, timeout: Duration, samples: u32) -> Latency {
        let mut best = Latency {
            ok: false,
            ms: f64::INFINITY,
        };
        for _ in 0..samples.max(1) {
            let (l, unreach) = connect_once(ip, port, timeout).await;
            if l.ok && l.ms < best.ms {
                best = l;
            }
            if !l.ok && unreach && ip.is_ipv6() {
                *self.v6.lock().unwrap() = Some(false);
                break;
            }
        }
        if best.ok && ip.is_ipv6() {
            *self.v6.lock().unwrap() = Some(true);
        }
        best
    }

    /// 連線品質：連續 n 次 TCP 連線（間隔 `gap`），中位數延遲、抖動、掉包率（同 2.x `quality`）。
    /// 海纜壅塞時延遲忽高忽低、偶爾連不上，只看最低延遲會選錯節點。
    pub async fn quality(&self, ip: IpAddr, n: u32, timeout: Duration, gap: Duration) -> Quality {
        let n = n.max(1);
        let mut ms = Vec::with_capacity(n as usize);
        let mut lost = 0u32;
        for i in 0..n {
            let (l, _) = connect_once(ip, self.port, timeout).await;
            if l.ok {
                ms.push(l.ms);
            } else {
                lost += 1;
            }
            if !gap.is_zero() && i + 1 < n {
                tokio::time::sleep(gap).await;
            }
        }
        let mut sorted = ms.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median = if sorted.is_empty() {
            f64::INFINITY
        } else {
            sorted[(sorted.len() - 1) / 2]
        };
        let jitter = if ms.len() > 1 {
            ms.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f64>() / (ms.len() - 1) as f64
        } else {
            0.0
        };
        Quality {
            ms: median,
            jitter,
            loss: lost as f64 / n as f64,
            n,
        }
    }

    /// 直接放一筆結果進快取（社群提示、測試）
    pub fn insert(&self, ip: IpAddr, l: Latency) {
        self.store(ip, l);
    }

    /// 單一 IP 的延遲（使用快取）
    pub async fn latency(&self, ip: IpAddr) -> Latency {
        let now = Instant::now();
        if let Some((l, at)) = self.cache.lock().unwrap().get(&ip) {
            if now.duration_since(*at) < if l.ok { self.ok_ttl } else { self.fail_ttl } {
                return *l;
            }
        }
        let l = self.ping(ip).await;
        self.store(ip, l);
        l
    }

    fn store(&self, ip: IpAddr, l: Latency) {
        let now = Instant::now();
        let mut c = self.cache.lock().unwrap();
        if c.len() >= self.max_entries {
            // 先丟掉過期的；還是太多就丟掉最舊的一半
            c.retain(|_, (l, at)| now.duration_since(*at) < if l.ok { self.ok_ttl } else { self.fail_ttl });
            if c.len() >= self.max_entries {
                let mut v: Vec<(IpAddr, Instant)> = c.iter().map(|(k, (_, at))| (*k, *at)).collect();
                v.sort_by_key(|x| x.1);
                for (k, _) in v.into_iter().take(self.max_entries / 2) {
                    c.remove(&k);
                }
            }
        }
        c.insert(ip, (l, Instant::now()));
    }

    /// 依延遲排序（同時測，數量受 concurrency 限制）
    pub async fn rank(self: &Arc<Self>, ips: &[IpAddr]) -> Vec<(IpAddr, Latency)> {
        let mut uniq: Vec<IpAddr> = Vec::new();
        for ip in ips {
            if !uniq.contains(ip) {
                uniq.push(*ip);
            }
        }
        let mut set = tokio::task::JoinSet::new();
        for ip in uniq {
            let me = self.clone();
            set.spawn(async move { (ip, me.latency(ip).await) });
        }
        let mut out = Vec::new();
        while let Some(Ok(r)) = set.join_next().await {
            out.push(r);
        }
        out.sort_by(|a, b| a.1.ms.partial_cmp(&b.1.ms).unwrap_or(std::cmp::Ordering::Equal));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn ranks_reachable_first() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let _ = l.accept().await;
            }
        });
        let cfg = kuroshio_config::with_overrides(&json!({ "iprank": { "port": port, "timeoutMs": 300 } }));
        let r = Arc::new(IpRank::new(&cfg, 1000));
        // 127.0.0.2 在 Linux 也是本機但沒有人聽這個埠 → 連線被拒
        let out = r
            .rank(&[
                "127.0.0.2".parse().unwrap(),
                "127.0.0.1".parse().unwrap(),
                "127.0.0.1".parse().unwrap(),
            ])
            .await;
        assert_eq!(out.len(), 2, "重複的 IP 只測一次");
        assert_eq!(out[0].0, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert!(out[0].1.ok && !out[1].1.ok);
        assert!(r.cached("127.0.0.1".parse().unwrap()).unwrap().ok);
    }
}
