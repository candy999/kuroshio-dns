//! 「這台裝置有沒有在用黑潮 DNS？」偵測（同 2.x `check.js`）——不需要任何額外的 DNS、憑證或反向代理設定
//!
//! 原理：DoH / DoT / DoQ / 一般 DNS 的每一次查詢，伺服器都知道是哪個 IP 送來的。
//! 有人打開公開頁時，比對他的 IP：
//! - 這個 IP 剛剛透過我們查詢過公開頁的網域本身（打開網頁前一定要先查）→ `yes`（正在使用）
//! - 這個 IP 最近有用我們，但沒查公開頁的網域（可能被快取）→ `network`（這個網路有裝置在用）
//! - 都沒有 → `no`
//!
//! 為了讓「打開網頁前會重新查詢」更準，回答公開頁網域時把 TTL 壓到很短（[`Presence::own_host_ttl`]）。
//! IPv6 以 /64 比對（手機的 IPv6 位址會定期更換）。
//!
//! 記憶體：最多記 `max` 個 IP（預設 5 萬，小記憶體 5 千），用兩代雜湊表做近似 LRU，
//! 不用逐筆掃描；超過 `check.activeMinutes` 的紀錄本來就沒有用，被擠掉也沒關係。

use kuroshio_config::get;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 一般機器記幾個 IP
pub const MAX_ENTRIES: usize = 50_000;
/// 小記憶體機器記幾個 IP
pub const MAX_ENTRIES_TINY: usize = 5_000;

/// 比對用的鍵：IPv4 整個位址、IPv6 前 64 位元
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Key {
    V4(u32),
    V6(u64),
}

impl Key {
    pub fn of(ip: IpAddr) -> Key {
        match ip.to_canonical() {
            IpAddr::V4(v4) => Key::V4(u32::from(v4)),
            IpAddr::V6(v6) => Key::V6((u128::from(v6) >> 64) as u64),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Seen {
    proto: &'static str,
    at: Instant,
    host_at: Option<Instant>,
}

#[derive(Debug, Clone)]
pub struct PresenceConfig {
    /// 多久內有查詢算「有在用」（分鐘）
    pub active_minutes: u64,
    /// 多久內查過公開頁網域算「這台正在用」（秒）
    pub host_window_sec: u64,
    /// 公開頁網域回答的 TTL 上限（秒）
    pub own_host_ttl: u32,
}

impl Default for PresenceConfig {
    fn default() -> Self {
        PresenceConfig {
            active_minutes: 10,
            host_window_sec: 180,
            own_host_ttl: 10,
        }
    }
}

#[derive(Default)]
struct Gens {
    cur: HashMap<Key, Seen>,
    old: HashMap<Key, Seen>,
}

pub struct Presence {
    pub cfg: PresenceConfig,
    /// 公開頁的網域（小寫、沒有結尾的點）；空白 = 沒設定，只能判斷到 `network`
    host: String,
    max: usize,
    seen: Mutex<Gens>,
}

/// 協議代號 → 公開頁顯示的名稱
fn proto_name(p: &str) -> &'static str {
    match p.to_ascii_lowercase().as_str() {
        "doh" => "DoH",
        "doh3" => "DoH3",
        "dot" => "DoT",
        "doq" => "DoQ",
        "tcp" => "TCP",
        "udp" => "UDP",
        _ => "DNS",
    }
}

/// 網域比對用：去掉結尾的點、不分大小寫
fn same_name(a: &str, host: &str) -> bool {
    !host.is_empty() && a.trim_end_matches('.').eq_ignore_ascii_case(host)
}

impl Presence {
    pub fn new(cfg: PresenceConfig, hostname: &str, max: usize) -> Presence {
        Presence {
            cfg,
            host: hostname.trim().trim_end_matches('.').to_ascii_lowercase(),
            max: max.max(2),
            seen: Mutex::new(Gens::default()),
        }
    }

    /// 由設定建立（`check.enabled` 為 false 時回 None，同 2.x：公開頁關掉時也可以單獨開）。
    /// `tiny`：小記憶體等級，最多只記 5 千個 IP
    pub fn from_cfg(cfg: &Value, tiny: bool) -> Option<Arc<Presence>> {
        if !get(cfg, "check.enabled").and_then(Value::as_bool).unwrap_or(true) {
            return None;
        }
        let n = |k: &str, d: u64| get(cfg, k).and_then(Value::as_u64).unwrap_or(d);
        let c = PresenceConfig {
            active_minutes: n("check.activeMinutes", 10),
            host_window_sec: n("check.hostWindowSec", 180),
            own_host_ttl: n("check.ownHostTtl", 10).clamp(1, 86_400) as u32,
        };
        let host = get(cfg, "site.hostname").and_then(Value::as_str).unwrap_or("");
        Some(Arc::new(Presence::new(c, host, if tiny { MAX_ENTRIES_TINY } else { MAX_ENTRIES })))
    }

    /// 公開頁的網域（可能是空字串）
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn is_own_host(&self, qname: &str) -> bool {
        same_name(qname, &self.host)
    }

    /// 回答 `qname` 時的 TTL 上限：是公開頁的網域就回 `Some(check.ownHostTtl)`
    pub fn own_host_ttl(&self, qname: &str) -> Option<u32> {
        self.is_own_host(qname).then_some(self.cfg.own_host_ttl)
    }

    /// 每一次查詢都呼叫（很輕量）。`proto`：udp / tcp / dot / doh / doh3 / doq
    pub fn record(&self, proto: &str, client: IpAddr, qname: &str) {
        self.record_at(Instant::now(), proto, client, qname)
    }

    /// 同 [`Presence::record`]，指定時間（測試用）
    pub fn record_at(&self, now: Instant, proto: &str, client: IpAddr, qname: &str) {
        if client.is_unspecified() {
            return;
        }
        let k = Key::of(client);
        let own = self.is_own_host(qname);
        let proto = proto_name(proto);
        let mut g = self.seen.lock().unwrap();
        let prev = match g.cur.get(&k) {
            Some(e) => Some(*e),
            None => g.old.remove(&k),
        };
        let e = Seen {
            proto,
            at: now,
            host_at: if own { Some(now) } else { prev.and_then(|p| p.host_at) },
        };
        g.cur.insert(k, e);
        if g.cur.len() >= self.max / 2 {
            g.old = std::mem::take(&mut g.cur);
        }
    }

    /// 公開頁呼叫：這個訪客 IP 的狀態 `{state: yes|network|no, protocol, lastSeenSec}`（不回傳 IP）
    pub fn status(&self, ip: IpAddr) -> Value {
        self.status_at(Instant::now(), ip)
    }

    /// 同 [`Presence::status`]，指定時間（測試用）
    pub fn status_at(&self, now: Instant, ip: IpAddr) -> Value {
        let k = Key::of(ip);
        let e = {
            let g = self.seen.lock().unwrap();
            g.cur.get(&k).or_else(|| g.old.get(&k)).copied()
        };
        let age = |t: Instant| now.saturating_duration_since(t);
        let Some(e) = e.filter(|e| age(e.at) <= Duration::from_secs(self.cfg.active_minutes * 60)) else {
            return json!({ "state": "no" });
        };
        let last = (age(e.at).as_millis() as f64 / 1000.0).round() as u64;
        let state = match e.host_at {
            Some(h) if age(h) < Duration::from_secs(self.cfg.host_window_sec) => "yes",
            _ => "network",
        };
        json!({ "state": state, "protocol": e.proto, "lastSeenSec": last })
    }

    /// 目前記著幾個 IP
    pub fn len(&self) -> usize {
        let g = self.seen.lock().unwrap();
        g.cur.len() + g.old.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn info(&self) -> Value {
        json!({ "enabled": true, "method": "ip" })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn states() {
        let p = Presence::new(PresenceConfig::default(), "DNS.Example.", 1000);
        let t0 = Instant::now();
        assert_eq!(p.status_at(t0, ip("192.0.2.1"))["state"], "no");
        p.record_at(t0, "doh", ip("192.0.2.1"), "dns.example");
        let s = p.status_at(t0 + Duration::from_secs(5), ip("192.0.2.1"));
        assert_eq!(s, json!({ "state": "yes", "protocol": "DoH", "lastSeenSec": 5 }));
        // 之後只查別的網域：在 hostWindowSec 內仍然是 yes
        p.record_at(t0 + Duration::from_secs(60), "dot", ip("192.0.2.1"), "www.example.com");
        assert_eq!(p.status_at(t0 + Duration::from_secs(61), ip("192.0.2.1"))["state"], "yes");
        assert_eq!(p.status_at(t0 + Duration::from_secs(61), ip("192.0.2.1"))["protocol"], "DoT");
        assert_eq!(p.status_at(t0 + Duration::from_secs(200), ip("192.0.2.1"))["state"], "network");
        // 超過 activeMinutes
        assert_eq!(p.status_at(t0 + Duration::from_secs(60 + 601), ip("192.0.2.1"))["state"], "no");
        // 只查別的網域 → network
        p.record_at(t0, "udp", ip("192.0.2.9"), "example.org");
        assert_eq!(
            p.status_at(t0, ip("192.0.2.9")),
            json!({ "state": "network", "protocol": "UDP", "lastSeenSec": 0 })
        );
        // IPv4 對應的 IPv6 位址視同 IPv4
        assert_eq!(p.status_at(t0, ip("::ffff:192.0.2.9"))["state"], "network");
        // 0.0.0.0 不記
        p.record_at(t0, "udp", ip("0.0.0.0"), "dns.example");
        assert_eq!(p.status_at(t0, ip("0.0.0.0"))["state"], "no");
    }

    #[test]
    fn ipv6_slash64() {
        let p = Presence::new(PresenceConfig::default(), "dns.example", 1000);
        let t0 = Instant::now();
        p.record_at(t0, "doq", ip("2001:db8:1:2::abcd"), "dns.example");
        assert_eq!(p.status_at(t0, ip("2001:db8:1:2:ffff::1"))["state"], "yes", "同一個 /64");
        assert_eq!(p.status_at(t0, ip("2001:db8:1:2:ffff::1"))["protocol"], "DoQ");
        assert_eq!(p.status_at(t0, ip("2001:db8:1:3::abcd"))["state"], "no", "不同 /64");
    }

    #[test]
    fn own_host_ttl() {
        let p = Presence::new(PresenceConfig::default(), "dns.example", 1000);
        assert_eq!(p.own_host_ttl("dns.example"), Some(10));
        assert_eq!(p.own_host_ttl("DNS.EXAMPLE."), Some(10));
        assert_eq!(p.own_host_ttl("www.dns.example"), None);
        let none = Presence::new(PresenceConfig::default(), "", 1000);
        assert_eq!(none.own_host_ttl(""), None, "沒設定網域時永遠不壓 TTL");
        assert_eq!(none.own_host_ttl("."), None);
        let cfg = kuroshio_config::with_overrides(&json!({ "site": { "hostname": "dns.example" }, "check": { "ownHostTtl": 30 } }));
        assert_eq!(Presence::from_cfg(&cfg, false).unwrap().own_host_ttl("dns.example"), Some(30));
        let off = kuroshio_config::with_overrides(&json!({ "check": { "enabled": false } }));
        assert!(Presence::from_cfg(&off, false).is_none());
    }

    #[test]
    fn bounded() {
        let p = Presence::new(PresenceConfig::default(), "dns.example", 100);
        let t0 = Instant::now();
        for i in 0..1000u32 {
            p.record_at(t0, "udp", IpAddr::from(std::net::Ipv4Addr::from(0x0a00_0000 + i)), "x.example");
        }
        assert!(p.len() <= 100, "最多記 max 個：{}", p.len());
        // 最近的還在
        assert_eq!(
            p.status_at(t0, IpAddr::from(std::net::Ipv4Addr::from(0x0a00_0000 + 999)))["state"],
            "network"
        );
        assert_eq!(p.status_at(t0, IpAddr::from(std::net::Ipv4Addr::from(0x0a00_0000)))["state"], "no");
    }
}
