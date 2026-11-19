//! 上游放行下游：登記表、存取控制的 `chain` 集合、繞過防護清單的豁免（規格第 4 節）
//!
//! - 跟著 `allow_downstream`（預設開），沒有核准名單、沒有管理 API、不存任何檔案：登記表只在記憶體裡，
//!   跟著 [`super::Responder`] 建立（重新載入後清空，下游最慢 5 分鐘內重新登記）
//! - 這裡只管「已經驗過」的登記：簽章、`up`、`peer`、`tok` 四項檢查在回應器（`responder.rs`）做完才呼叫 [`Grants::register`]
//! - 上限（規格第 9 節）：最多 [`MAX_DOWNSTREAMS`] 筆，每筆最多 32 個名稱；每筆 900 秒到期
//! - 熱路徑：解析流程只有在「命中 `bypass` 清單」之後才呼叫 [`Grants::exempt`]；沒有任何登記時只看一個原子變數

use kuroshio_community::chain::{RegAck, RegBody, MAX_REG_NAMES, PROTO};
use kuroshio_community::identity::fingerprint;
use kuroshio_community::util::hex;
use kuroshio_config::chain::ChainSettings;
use serde_json::{json, Value};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tracing::info;

/// 登記表最多幾筆
pub const MAX_DOWNSTREAMS: usize = 16;
/// 登記的有效時間（下游每 5 分鐘跟著心跳更新）
pub const REG_TTL: Duration = Duration::from_secs(900);

/// 一筆登記中的下游
#[derive(Debug, Clone)]
pub struct Downstream {
    pub kid: [u8; 8],
    pub public: [u8; 32],
    /// 登記時的來源位址（canonical；只有這一個位址得到放行）
    pub addr: IpAddr,
    pub app: String,
    /// 登記的上游主機名稱（小寫、沒有結尾的點、去重複，最多 32 個）
    pub names: Vec<String>,
    /// `peer` 是下游自己網卡的位址（false = 中間有 NAT，整個 NAT 一起放行）
    pub local: bool,
    pub expires: Instant,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

/// 上游的登記表
pub struct Grants {
    allow_downstream: bool,
    ttl: Duration,
    table: RwLock<Vec<Downstream>>,
    /// 表裡有沒有任何一筆（熱路徑先看這個，沒有登記時不碰鎖）
    any: AtomicBool,
    /// 登記表變了（新增、位址改變、過期清掉）：叫醒 `app.rs` 更新存取控制
    changed: Notify,
}

fn norm_name(n: &str) -> String {
    n.trim_end_matches('.').to_ascii_lowercase()
}

impl Grants {
    pub fn new(settings: &ChainSettings) -> Arc<Grants> {
        Self::with_ttl(settings, REG_TTL)
    }

    /// 測試用：指定登記的有效時間
    pub fn with_ttl(settings: &ChainSettings, ttl: Duration) -> Arc<Grants> {
        Arc::new(Grants {
            allow_downstream: settings.allow_downstream,
            ttl,
            table: RwLock::new(Vec::new()),
            any: AtomicBool::new(false),
            changed: Notify::new(),
        })
    }

    /// `upstream.allowDownstream`
    pub fn allow_downstream(&self) -> bool {
        self.allow_downstream
    }

    /// 登記表變動時叫醒（`app.rs` 的存取控制更新工作用）
    pub async fn changed(&self) {
        self.changed.notified().await
    }

    /// 已經驗過簽章、up、peer、tok 的登記；回 RegAck 的內容。allow_downstream 關、或表滿了 → Err
    pub fn register(&self, reg: &RegBody, from: IpAddr, now: Instant, now_ms: u64) -> Result<RegAck, &'static str> {
        if !self.allow_downstream {
            return Err("allow_downstream 關閉");
        }
        let kid: [u8; 8] = reg.kid.as_slice().try_into().map_err(|_| "節點 ID 長度不對")?;
        let public: [u8; 32] = reg.public.as_slice().try_into().map_err(|_| "公鑰長度不對")?;
        let addr = from.to_canonical();
        let mut names: Vec<String> = Vec::with_capacity(reg.names.len().min(MAX_REG_NAMES));
        for n in reg.names.iter().map(|n| norm_name(n)) {
            if names.len() >= MAX_REG_NAMES {
                break;
            }
            if !n.is_empty() && !names.contains(&n) {
                names.push(n);
            }
        }
        let app: String = reg.app.chars().take(32).collect();
        let expires = now + self.ttl;
        let mut t = self.table.write().unwrap();
        let before = t.len();
        t.retain(|d| d.expires > now);
        let mut changed = t.len() != before;
        let mut log = false;
        match t.iter().position(|d| d.kid == kid) {
            Some(i) => {
                let d = &mut t[i];
                if d.addr != addr {
                    // 同一台從新位址登記：舊位址的放行立刻失效
                    d.addr = addr;
                    changed = true;
                    log = true;
                }
                d.public = public;
                d.app = app;
                d.names = names;
                d.local = reg.local;
                d.expires = expires;
                d.last_seen_ms = now_ms;
                // 一個位址只對應一筆：同一個位址的其他 kid 拿掉
                t.retain(|x| x.kid == kid || x.addr != addr);
            }
            None => {
                let entry = Downstream {
                    kid,
                    public,
                    addr,
                    app,
                    names,
                    local: reg.local,
                    expires,
                    first_seen_ms: now_ms,
                    last_seen_ms: now_ms,
                };
                match t.iter().position(|d| d.addr == addr) {
                    // 同一個位址換了 kid（重新產生金鑰）：取代那一筆
                    Some(i) => t[i] = entry,
                    None if t.len() >= MAX_DOWNSTREAMS => {
                        drop(t);
                        if changed {
                            self.after_change();
                        }
                        return Err("登記表滿了");
                    }
                    None => t.push(entry),
                }
                changed = true;
                log = true;
            }
        }
        self.any.store(!t.is_empty(), Ordering::Release);
        drop(t);
        if log {
            info!("下游黑潮 {addr}（指紋 {}）已登記", fingerprint(&public));
        }
        if changed {
            self.after_change();
        }
        Ok(RegAck {
            v: PROTO,
            t: "regack".into(),
            kid: kid.to_vec(),
            ttl: self.ttl.as_secs().clamp(1, u64::from(u32::MAX)) as u32,
        })
    }

    fn after_change(&self) {
        // notify_one：工作還沒在等的時候也會記住一次
        self.changed.notify_one();
    }

    /// 存取控制要放行的位址（登記沒過期；allow_downstream 關著時一定是空的）
    pub fn allowed_addrs(&self, now: Instant) -> Vec<IpAddr> {
        if !self.allow_downstream || !self.any.load(Ordering::Acquire) {
            return Vec::new();
        }
        let t = self.table.read().unwrap();
        t.iter().filter(|d| d.expires > now).map(|d| d.addr).collect()
    }

    /// 繞過防護清單的豁免（allow_downstream 開＋登記沒過期＋來源位址相同＋名稱在登記的 names 裡）
    ///
    /// `qname` 已經是小寫、沒有結尾的點（`normalize` 過）；完全相同才算，不含子網域。
    pub fn exempt(&self, client: IpAddr, qname: &str, now: Instant) -> bool {
        if !self.allow_downstream || !self.any.load(Ordering::Acquire) {
            return false;
        }
        let client = client.to_canonical();
        let t = self.table.read().unwrap();
        t.iter()
            .any(|d| d.addr == client && d.expires > now && d.names.iter().any(|n| n == qname))
    }

    /// 清掉過期的登記（每分鐘）
    pub fn sweep(&self, now: Instant) {
        if !self.any.load(Ordering::Acquire) {
            return;
        }
        let mut t = self.table.write().unwrap();
        let before = t.len();
        t.retain(|d| d.expires > now);
        let changed = t.len() != before;
        self.any.store(!t.is_empty(), Ordering::Release);
        drop(t);
        if changed {
            self.after_change();
        }
    }

    /// 登記中（沒過期）的筆數
    pub fn count(&self) -> usize {
        let now = Instant::now();
        self.table.read().unwrap().iter().filter(|d| d.expires > now).count()
    }

    /// `serving.downstreams`：每一筆的指紋、位址、版本、第一次與最後出現時間、有沒有經過 NAT、名稱數
    pub fn json(&self) -> Value {
        let now = Instant::now();
        let t = self.table.read().unwrap();
        let mut v: Vec<&Downstream> = t.iter().filter(|d| d.expires > now).collect();
        v.sort_by_key(|d| d.first_seen_ms);
        Value::Array(
            v.into_iter()
                .map(|d| {
                    let left = d.expires.saturating_duration_since(now).as_millis() as u64;
                    json!({
                        "address": d.addr.to_string(),
                        "nodeId": hex(&d.kid),
                        "fingerprint": fingerprint(&d.public),
                        "version": d.app,
                        "viaNat": !d.local,
                        "names": d.names.len(),
                        "firstSeen": d.first_seen_ms,
                        "lastSeen": d.last_seen_ms,
                        "expiresAt": kuroshio_community::util::now_ms() + left,
                    })
                })
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuroshio_community::identity::{kid_of, KeyPair};

    fn settings(allow: bool) -> ChainSettings {
        ChainSettings {
            chain: true,
            allow_downstream: allow,
            path_check: true,
            warnings: vec![],
        }
    }

    fn reg(k: &KeyPair, names: &[&str]) -> RegBody {
        RegBody {
            v: PROTO,
            t: "reg".into(),
            up: vec![0; 8],
            tok: vec![0; 16],
            peer: String::new(),
            kid: kid_of(&k.public).to_vec(),
            public: k.public.to_vec(),
            app: "3.4.0".into(),
            names: names.iter().map(|s| s.to_string()).collect(),
            local: true,
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn exempt_exact_name_and_address_only() {
        let g = Grants::new(&settings(true));
        let t = Instant::now();
        let k = KeyPair::generate();
        let ack = g
            .register(&reg(&k, &["DNS.Example.NET.", "dns.example.net"]), ip("192.168.1.2"), t, 1)
            .unwrap();
        assert_eq!((ack.t.as_str(), ack.ttl), ("regack", 900));
        assert!(g.exempt(ip("192.168.1.2"), "dns.example.net", t));
        assert!(g.exempt(ip("::ffff:192.168.1.2"), "dns.example.net", t), "IPv4 對應的 IPv6 一樣");
        assert!(!g.exempt(ip("192.168.1.3"), "dns.example.net", t));
        assert!(!g.exempt(ip("192.168.1.2"), "a.dns.example.net", t), "子網域不算");
        assert!(!g.exempt(ip("192.168.1.2"), "example.net", t));
        assert_eq!(g.allowed_addrs(t), vec![ip("192.168.1.2")]);
        // 到期
        let later = t + REG_TTL + Duration::from_secs(1);
        assert!(!g.exempt(ip("192.168.1.2"), "dns.example.net", later));
        assert!(g.allowed_addrs(later).is_empty());
        g.sweep(later);
        assert_eq!(g.json().as_array().unwrap().len(), 0);
    }

    #[test]
    fn off_never_registers() {
        let g = Grants::new(&settings(false));
        let t = Instant::now();
        assert!(g
            .register(&reg(&KeyPair::generate(), &["dns.example.net"]), ip("192.168.1.2"), t, 1)
            .is_err());
        assert!(g.allowed_addrs(t).is_empty());
        assert!(!g.exempt(ip("192.168.1.2"), "dns.example.net", t));
    }

    #[test]
    fn bounded_and_one_entry_per_address() {
        let g = Grants::new(&settings(true));
        let t = Instant::now();
        for i in 0..MAX_DOWNSTREAMS as u8 {
            g.register(&reg(&KeyPair::generate(), &[]), IpAddr::from([10, 0, 0, i]), t, 1)
                .unwrap();
        }
        assert_eq!(g.register(&reg(&KeyPair::generate(), &[]), ip("10.0.1.1"), t, 1), Err("登記表滿了"));
        // 同一個位址換 kid：取代，還是 16 筆
        g.register(&reg(&KeyPair::generate(), &[]), ip("10.0.0.3"), t, 2).unwrap();
        assert_eq!(g.count(), MAX_DOWNSTREAMS);
        // 過期的清掉之後可以再登記
        let later = t + REG_TTL + Duration::from_secs(1);
        g.register(&reg(&KeyPair::generate(), &[]), ip("10.0.1.1"), later, 3).unwrap();
        assert_eq!(g.allowed_addrs(later), vec![ip("10.0.1.1")]);
        // 名稱最多 32 個
        let many: Vec<String> = (0..40).map(|i| format!("n{i}.example.com")).collect();
        let mut r = reg(&KeyPair::generate(), &[]);
        r.names = many;
        g.register(&r, ip("10.0.2.1"), later, 4).unwrap();
        let d = g.table.read().unwrap().iter().find(|d| d.addr == ip("10.0.2.1")).unwrap().clone();
        assert_eq!(d.names.len(), MAX_REG_NAMES);
    }
}
