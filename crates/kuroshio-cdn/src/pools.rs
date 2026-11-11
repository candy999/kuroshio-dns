//! 台灣節點池（對齊 2.x `lib/cdn/pools.js`）：CDN IP 範圍、掃描分類（TW / Global / Dead）、
//! 可用的台灣替換 IP、節點相容性紀錄（ip-zone）。
//!
//! 這裡只有不需要網路的部分；健檢、品質監測、IPv6 即時發現在 `health.rs`。

use crate::cidr::CidrSet;
use crate::config::CdnConfig;
use crate::providers::{self, is_tw_pop};
use crate::util::{self, de_ip, de_opt_arc, de_opt_bool, de_opt_u64, now_ms, ser_opt_arc, Extra, Num};
use crate::v6store::V6Store;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::net::IpAddr;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

pub const FILE: &str = "cdn/pools.json";
pub const ZONE_FILE: &str = "cdn/ip-zone.json";
/// 連線失敗的網段暫停多久
pub const BAD24_MS: u64 = 30 * 60_000;
/// 尖峰時段的量測多久內有效
pub const PEAK_FRESH_MS: u64 = 3 * util::DAY_MS;

/// 節點池裡的一個節點
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PoolNode {
    #[serde(deserialize_with = "de_ip")]
    pub ip: IpAddr,
    #[serde(default, skip_serializing_if = "Num::is_absent")]
    pub ms: Num,
    #[serde(default, skip_serializing_if = "Num::is_absent")]
    pub speed: Num,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "ser_opt_arc",
        deserialize_with = "de_opt_arc"
    )]
    pub pop: Option<Arc<str>>,
    #[serde(default, skip_serializing_if = "Num::is_absent")]
    pub jitter: Num,
    #[serde(default, skip_serializing_if = "Num::is_absent")]
    pub loss: Num,
    #[serde(default, skip_serializing_if = "Num::is_absent")]
    pub score: Num,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_bool")]
    pub permanent: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_u64")]
    pub checked_at: Option<u64>,
    /// 尖峰時段（台北 20–23 點）最近一次量測（3.0 新增，規格 06 第 3.2 節）
    #[serde(default, skip_serializing_if = "Num::is_absent")]
    pub peak_ms: Num,
    #[serde(default, skip_serializing_if = "Num::is_absent")]
    pub peak_jitter: Num,
    #[serde(default, skip_serializing_if = "Num::is_absent")]
    pub peak_loss: Num,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_u64")]
    pub peak_at: Option<u64>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl PoolNode {
    pub fn new(ip: IpAddr) -> PoolNode {
        PoolNode {
            ip,
            ms: Num::Absent,
            speed: Num::Absent,
            pop: None,
            jitter: Num::Absent,
            loss: Num::Absent,
            score: Num::Absent,
            permanent: None,
            checked_at: None,
            peak_ms: Num::Absent,
            peak_jitter: Num::Absent,
            peak_loss: Num::Absent,
            peak_at: None,
            extra: Extra::default(),
        }
    }

    pub fn pop_str(&self) -> &str {
        self.pop.as_deref().unwrap_or("")
    }

    /// 有效的尖峰量測（3 天內）
    pub fn peak_fresh(&self, now: u64) -> bool {
        self.peak_at.map(|t| now.saturating_sub(t) < PEAK_FRESH_MS).unwrap_or(false) && self.peak_ms.get().is_some()
    }
}

/// 2.x 的 `String(pop).substring(0, 3).toUpperCase()`
pub fn pop3(pop: &str) -> String {
    pop.chars().take(3).collect::<String>().to_uppercase()
}

/// `pop3(pop) == p3`，不配置記憶體（每個 Fastly 回應都要對節點池逐一比對）
pub fn pop3_is(pop: &str, p3: &str) -> bool {
    pop.chars().take(3).flat_map(char::to_uppercase).eq(p3.chars())
}

/// 品質分數（越低越好，同 2.x `iprank.qscore`）：延遲 + 2×抖動 + 掉包懲罰；測過速度且低於 1 MB/s 另加懲罰
pub fn qscore_of(ms: Num, jitter: Num, loss: Num, speed: Num) -> f64 {
    let ms = match ms {
        Num::Absent | Num::Inf => return f64::INFINITY,
        Num::Null => 0.0, // 2.x 的 isFinite(null) 是 true
        Num::V(v) if !v.is_finite() => return f64::INFINITY,
        Num::V(v) => v,
    };
    let slow = matches!(speed, Num::V(s) if s < 1.0);
    ms + 2.0 * jitter.or(0.0) + 400.0 * loss.or(0.0) + if slow { 80.0 } else { 0.0 }
}

pub fn qscore(x: &PoolNode) -> f64 {
    qscore_of(x.ms, x.jitter, x.loss, x.speed)
}

/// 加上尖峰時段權重的分數：有 3 天內的尖峰量測時，（平時 + w × 尖峰）/（1 + w）
pub fn weighted_qscore(x: &PoolNode, w: f64, now: u64) -> f64 {
    let s = qscore(x);
    if !x.peak_fresh(now) || w <= 0.0 {
        return s;
    }
    let sp = qscore_of(x.peak_ms, x.peak_jitter, x.peak_loss, x.speed);
    if !s.is_finite() || !sp.is_finite() {
        return s.max(sp);
    }
    (s + w * sp) / (1.0 + w)
}

/// 加上尖峰時段權重的延遲（一般 CDN 健檢排序用）
pub fn weighted_ms(x: &PoolNode, w: f64, now: u64) -> f64 {
    let ms = x.ms.or(999.0);
    match (x.peak_fresh(now), x.peak_ms.get()) {
        (true, Some(p)) if w > 0.0 => (ms + w * p) / (1.0 + w),
        _ => ms,
    }
}

/// 節點的分數（存下來的 `score`，沒有就現算）
pub fn node_score(x: &PoolNode) -> f64 {
    x.score.get().unwrap_or_else(|| qscore(x))
}

#[derive(Debug, Clone, PartialEq)]
pub struct Bad {
    pub at: u64,
    pub reason: String,
    /// 品質檢查標記的（品質恢復就解除）
    pub quality: bool,
}

/// IP 的分類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cls {
    /// 會被導去國外
    Global,
    Tw,
    Dead,
    /// 在官方範圍但沒有掃描過
    Unknown,
}

impl Cls {
    pub fn as_str(self) -> &'static str {
        match self {
            Cls::Global => "global",
            Cls::Tw => "tw",
            Cls::Dead => "dead",
            Cls::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Class {
    pub provider: &'static str,
    pub cls: Cls,
}

/// 站台相容性紀錄（ip-zone.json 的一筆）
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Zone {
    #[serde(default, deserialize_with = "util::de_u32")]
    pub hit: u32,
    #[serde(default, deserialize_with = "util::de_u32")]
    pub miss: u32,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_u64")]
    pub at: Option<u64>,
    #[serde(flatten)]
    pub extra: Extra,
}

fn de_nodes<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Vec<PoolNode>>, D::Error> {
    Ok(match Value::deserialize(d)? {
        Value::Array(a) => Some(a.into_iter().filter_map(|v| serde_json::from_value(v).ok()).collect()),
        _ => None,
    })
}

/// pools.json 裡一家 CDN 的資料
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProvEntry {
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_nodes")]
    pub v4: Option<Vec<PoolNode>>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_nodes")]
    pub v6: Option<Vec<PoolNode>>,
    /// updatedAt、tw48、prefixes 與其他欄位原封保留
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PoolsFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saved_at: Option<String>,
    #[serde(default)]
    pub providers: IndexMap<String, ProvEntry>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl PoolsFile {
    /// 2.x 的種子判斷：有任何一家有 v4 節點才算有資料
    pub fn is_empty(&self) -> bool {
        !self
            .providers
            .values()
            .any(|p| p.v4.as_ref().map(|v| !v.is_empty()).unwrap_or(false))
    }
}

/// 一家 CDN 的節點池與範圍
#[derive(Debug, Clone, Default)]
pub struct ProviderPools {
    // 範圍與分類用 `Arc`：查詢時用的唯讀快照（`Classifier`）直接共用同一份，不必複製。
    // 要改就整個換掉（`d.tw = Arc::new(...)`）；快照靠指標有沒有變來判斷要不要更新
    pub range4: Arc<CidrSet>,
    pub range6: Arc<CidrSet>,
    pub tw: Arc<CidrSet>,
    pub global: Arc<CidrSet>,
    pub dead: Arc<CidrSet>,
    pub pool4: Vec<PoolNode>,
    pub pool6: Vec<PoolNode>,
    pub tw48: Arc<CidrSet>,
    /// 最近節點型（Fastly）：每個 POP 的所有 /24（每日工作掃出來）
    pub prefixes: IndexMap<String, Vec<u32>>,
    pub bad: HashMap<IpAddr, Bad>,
    pub bad24: HashMap<u32, Bad>,
    /// IPv6 即時發現：每個 /48 上次嘗試時間
    pub tried6: IndexMap<u128, u64>,
    /// pools.json 裡這家的其他欄位（updatedAt、tw48、prefixes…）
    pub rest: Map<String, Value>,
    pub has_v4: bool,
    pub has_v6: bool,
}

impl ProviderPools {
    /// 這個 IP（IPv4-mapped 已先轉成 IPv4）在這家 CDN 的分類；不在範圍內回 None
    fn class_of(&self, ip: IpAddr, nearest: bool) -> Option<Cls> {
        if ip.is_ipv4() {
            if self.global.contains(ip) {
                return Some(Cls::Global);
            }
            // 沒有台灣 POP 的 CDN：舊掃描的「TW」是誤判，一律當成國外
            if self.tw.contains(ip) {
                return Some(if nearest { Cls::Global } else { Cls::Tw });
            }
            if self.dead.contains(ip) {
                return Some(Cls::Dead);
            }
            if self.range4.contains(ip) {
                return Some(Cls::Unknown);
            }
        } else if self.range6.contains(ip) {
            return Some(if self.tw48.contains(ip) { Cls::Tw } else { Cls::Global });
        }
        None
    }

    /// 範圍與分類是不是同一份（比指標）
    fn same_ranges(&self, o: &ProviderPools) -> bool {
        Arc::ptr_eq(&self.range4, &o.range4)
            && Arc::ptr_eq(&self.range6, &o.range6)
            && Arc::ptr_eq(&self.tw, &o.tw)
            && Arc::ptr_eq(&self.global, &o.global)
            && Arc::ptr_eq(&self.dead, &o.dead)
            && Arc::ptr_eq(&self.tw48, &o.tw48)
    }
    pub fn pool(&self, family: u8) -> &Vec<PoolNode> {
        if family == 6 {
            &self.pool6
        } else {
            &self.pool4
        }
    }
    pub fn pool_mut(&mut self, family: u8) -> &mut Vec<PoolNode> {
        if family == 6 {
            &mut self.pool6
        } else {
            &mut self.pool4
        }
    }
}

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}

/// 「IP 屬於哪家 CDN、哪一類」的唯讀快照：每個回應都要查，不必拿 `Cdn` 的大鎖。
/// 內容跟 `Pools::classify` 完全一樣（同一個判斷函式、同一份範圍資料）；範圍或分類換掉之後，
/// `Cdn` 在放開鎖的時候會自動換一份新的快照
#[derive(Debug, Default)]
pub struct Classifier {
    /// 所有 CDN 的範圍聯集（先用它篩掉不是 CDN 的 IP）
    any: CidrSet,
    /// （CDN，是不是最近節點型，範圍與分類——只有這幾個欄位有內容）
    list: Vec<(&'static str, bool, ProviderPools)>,
}

impl Classifier {
    pub fn classify(&self, ip: IpAddr) -> Option<Class> {
        let ip = unmap(ip);
        if !self.any.contains(ip) {
            return None;
        }
        self.list
            .iter()
            .find_map(|(name, nearest, d)| d.class_of(ip, *nearest).map(|cls| Class { provider: name, cls }))
    }

    /// 跟 `pools` 目前的範圍是不是同一份（CDN 的數量、順序、每個集合的指標都一樣）
    pub fn same_as(&self, pools: &Pools) -> bool {
        self.list.len() == pools.p.len()
            && self
                .list
                .iter()
                .zip(&pools.p)
                .all(|((name, _, a), (n2, b))| name == n2 && a.same_ranges(b))
    }
}

/// 讀範圍與掃描檔用：相對於 `cdn/` 的路徑 → 內容（先找 state，再找隨程式附帶的 data）
pub type RangeReader<'a> = &'a dyn Fn(&str) -> Option<String>;

/// 版本號來源：全程式共用、只會往上加，換掉整個 `PoolMap` 也不會跟舊的版本號撞在一起
static POOL_GEN: AtomicU32 = AtomicU32::new(1);

fn next_gen() -> u32 {
    POOL_GEN.fetch_add(1, Ordering::Relaxed)
}

/// 各家 CDN 的節點池。用 `&mut` 取用（`get_mut`、`values_mut`、`insert`…）就換一個新的版本號：
/// 依節點池算出來的東西（保留最後一段的 CDN 的 POP 排序與網段，見 `PopView`）看版本號決定要不要重算，
/// 不管是誰、用什麼方式改的都會被發現，不需要每個改的地方記得通知（跟 `Classifier` 快照同樣的想法）
#[derive(Debug)]
pub struct PoolMap {
    map: IndexMap<&'static str, ProviderPools>,
    gen: u32,
}

impl Default for PoolMap {
    fn default() -> PoolMap {
        PoolMap {
            map: IndexMap::new(),
            gen: next_gen(),
        }
    }
}

impl PoolMap {
    /// 目前的版本號（內容一改就換）
    pub fn gen(&self) -> u32 {
        self.gen
    }
}

impl<'a> IntoIterator for &'a PoolMap {
    type Item = (&'a &'static str, &'a ProviderPools);
    type IntoIter = indexmap::map::Iter<'a, &'static str, ProviderPools>;
    fn into_iter(self) -> Self::IntoIter {
        self.map.iter()
    }
}

impl Deref for PoolMap {
    type Target = IndexMap<&'static str, ProviderPools>;
    fn deref(&self) -> &Self::Target {
        &self.map
    }
}

impl DerefMut for PoolMap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.gen = next_gen();
        &mut self.map
    }
}

/// 保留最後一段的 CDN（Fastly）：依品質排序的 POP 與各 POP 目前可用的網段。
/// 每個 Fastly 回應要用好幾次，每次重算約 7 µs；節點池沒變（版本號相同）、也沒有暫停中的網段到期就重複用
#[derive(Debug, Default)]
pub struct PopView {
    /// （POP，網段）依品質順序，同 `active_pops` / `pop_prefixes`
    pub pops: Vec<(String, Vec<u32>)>,
}

impl PopView {
    /// 這個網段在不在任何一個可用 POP 裡
    pub fn has_prefix(&self, pf: u32) -> bool {
        self.pops.iter().any(|(_, l)| l.contains(&pf))
    }
}

struct PopCache {
    provider: &'static str,
    gen: u32,
    /// 有暫停中的網段時：最早恢復的時間（到了要重算）
    until: u64,
    view: Arc<PopView>,
}

pub struct Pools {
    pub cfg: Arc<CdnConfig>,
    pub p: PoolMap,
    /// `pop_view` 的快取
    pop_cache: Mutex<Vec<PopCache>>,
    /// pools.json 裡沒有啟用的 CDN：原封保留
    other: IndexMap<String, ProvEntry>,
    saved_at: Option<String>,
    extra: Extra,
    pub zone: IndexMap<String, Zone>,
    pub dirty: bool,
    pub zone_dirty: bool,
    /// 節點不足、需要重建節點池的 CDN（由外層取出後通知排程）
    pub low_pool: Vec<&'static str>,
}

impl Pools {
    pub fn empty(cfg: Arc<CdnConfig>) -> Pools {
        Pools {
            cfg,
            p: PoolMap::default(),
            pop_cache: Mutex::new(Vec::new()),
            other: IndexMap::new(),
            saved_at: None,
            extra: Extra::default(),
            zone: IndexMap::new(),
            dirty: false,
            zone_dirty: false,
            low_pool: Vec::new(),
        }
    }

    /// 載入範圍、掃描結果與 pools.json（同 2.x `PoolManager.load`）
    pub fn load(cfg: Arc<CdnConfig>, read: RangeReader, file: Option<PoolsFile>, v6: &mut V6Store) -> Pools {
        let mut me = Pools::empty(cfg.clone());
        let mut file = file.unwrap_or_default();
        me.saved_at = file.saved_at.take();
        me.extra = std::mem::take(&mut file.extra);
        for name in cfg.enabled_alias() {
            let prov = providers::get(name).unwrap();
            let pc = cfg.provider(name).unwrap();
            let set = |rel: &str, extra: &[&str]| {
                let mut s = CidrSet::new();
                if let Some(t) = read(rel) {
                    s.add_text(&t);
                }
                s.add_many(extra.iter().copied());
                Arc::new(s.done())
            };
            let range4 = set(&format!("ranges/{name}-ipv4.txt"), prov.extra_v4);
            let range6 = set(&format!("ranges/{name}-ipv6.txt"), prov.extra_v6);
            let tw = set(&format!("scan/{name}-ipv4-TW.txt"), &[]);
            let global = set(&format!("scan/{name}-ipv4-Global.txt"), &[]);
            let dead = set(&format!("scan/{name}-ipv4-Dead.txt"), &[]);
            let saved = file.providers.shift_remove(name).unwrap_or_default();
            let (has_v4, has_v6) = (saved.v4.is_some(), saved.v6.is_some());
            let mut pool4 = saved.v4.unwrap_or_default();
            if pool4.is_empty() && !pc.seed_v4.is_empty() {
                pool4 = seed_nodes(&pc.seed_v4);
            }
            let mut pool6 = saved.v6.unwrap_or_default();
            // 舊的節點池裡已確認是台灣 POP 的 v6，先補進永久紀錄（升級前找到的也不會遺失）
            for x in &pool6 {
                if is_tw_pop(x.pop_str()) && !v6.contains(name, x.ip) {
                    v6.mark_ok(name, x.ip, x.pop_str(), x.ms.get());
                }
            }
            // 永久保存的台灣 v6 節點一律併入
            let keep6 = v6.list(name);
            for k in &keep6 {
                if !pool6.iter().any(|x| x.ip == k.ip) {
                    let mut n = PoolNode::new(k.ip);
                    n.ms = k.node.ms;
                    n.pop = k.node.pop.as_deref().map(util::intern);
                    n.permanent = Some(true);
                    pool6.push(n);
                }
            }
            pool6.sort_by(|a, b| a.ms.or(999.0).partial_cmp(&b.ms.or(999.0)).unwrap_or(std::cmp::Ordering::Equal));
            if pool6.is_empty() && !pc.seed_v6.is_empty() {
                pool6 = seed_nodes(&pc.seed_v6);
            }
            let mut tw48 = CidrSet::new();
            for x in &pool6 {
                tw48.add(&util::subnet_key(x.ip));
            }
            if let Some(a) = saved.rest.get("tw48").and_then(Value::as_array) {
                for s in a.iter().filter_map(Value::as_str) {
                    tw48.add(s);
                }
            }
            let prefixes = parse_prefixes(saved.rest.get("prefixes"));
            let at = saved
                .rest
                .get("updatedAt")
                .and_then(Value::as_str)
                .map(String::from)
                .or_else(|| me.saved_at.clone())
                .unwrap_or_else(|| {
                    if pool4.is_empty() {
                        "尚未建立".into()
                    } else {
                        "種子 IP".into()
                    }
                });
            info!(
                "{}：官方範圍 v4 {} 段 / v6 {} 段｜掃描 TW {} / Global {} / Dead {} 個 /24｜節點池 v4 {} / v6 {}（{}，永久 v6 {}）",
                prov.label,
                range4.v4_len(),
                range6.v6_len(),
                tw.count24(),
                global.count24(),
                dead.count24(),
                pool4.len(),
                pool6.len(),
                at,
                keep6.len()
            );
            me.p.insert(
                name,
                ProviderPools {
                    range4,
                    range6,
                    tw,
                    global,
                    dead,
                    pool4,
                    pool6,
                    tw48: Arc::new(tw48.done()),
                    prefixes,
                    rest: saved.rest,
                    has_v4,
                    has_v6,
                    ..Default::default()
                },
            );
        }
        me.other = file.providers;
        me
    }

    /// 重新讀範圍與掃描檔（每週工作完成後），節點池與狀態不變
    pub fn reload_ranges(&mut self, read: RangeReader) {
        for (name, d) in self.p.iter_mut() {
            let prov = providers::get(name).unwrap();
            let set = |rel: &str, extra: &[&str]| {
                let mut s = CidrSet::new();
                if let Some(t) = read(rel) {
                    s.add_text(&t);
                }
                s.add_many(extra.iter().copied());
                Arc::new(s.done())
            };
            d.range4 = set(&format!("ranges/{name}-ipv4.txt"), prov.extra_v4);
            d.range6 = set(&format!("ranges/{name}-ipv6.txt"), prov.extra_v6);
            d.tw = set(&format!("scan/{name}-ipv4-TW.txt"), &[]);
            d.global = set(&format!("scan/{name}-ipv4-Global.txt"), &[]);
            d.dead = set(&format!("scan/{name}-ipv4-Dead.txt"), &[]);
        }
    }

    pub fn load_zone(&mut self, b: &[u8]) -> anyhow::Result<()> {
        let z: IndexMap<String, Value> = serde_json::from_slice(b)?;
        self.zone = z
            .into_iter()
            .filter_map(|(k, v)| Some((k, serde_json::from_value(v).ok()?)))
            .collect();
        Ok(())
    }

    pub fn zone_json(&self) -> Vec<u8> {
        serde_json::to_vec(&self.zone).unwrap_or_default()
    }

    /// pools.json 的內容
    pub fn to_json(&mut self) -> Vec<u8> {
        self.saved_at = Some(util::iso(now_ms()));
        let mut providers: IndexMap<String, ProvEntry> = IndexMap::new();
        for (name, d) in &self.p {
            providers.insert(
                name.to_string(),
                ProvEntry {
                    v4: (d.has_v4 || !d.pool4.is_empty()).then(|| d.pool4.clone()),
                    v6: (d.has_v6 || !d.pool6.is_empty()).then(|| d.pool6.clone()),
                    rest: d.rest.clone(),
                },
            );
        }
        for (k, v) in &self.other {
            providers.insert(k.clone(), v.clone());
        }
        let f = PoolsFile {
            saved_at: self.saved_at.clone(),
            providers,
            extra: self.extra.clone(),
        };
        serde_json::to_vec(&f).unwrap_or_default()
    }

    /// 換掉某家 CDN 的節點池（節點池工作的結果）
    pub fn replace(&mut self, name: &str, pool4: Vec<PoolNode>, pool6: Vec<PoolNode>, rest: Map<String, Value>) {
        let Some(d) = self.p.get_mut(name) else { return };
        d.prefixes = parse_prefixes(rest.get("prefixes"));
        let mut tw48 = CidrSet::new();
        for x in &pool6 {
            tw48.add(&util::subnet_key(x.ip));
        }
        if let Some(a) = rest.get("tw48").and_then(Value::as_array) {
            for s in a.iter().filter_map(Value::as_str) {
                tw48.add(s);
            }
        }
        d.tw48 = Arc::new(tw48.done());
        d.pool4 = pool4;
        d.pool6 = pool6;
        d.rest = rest;
        d.has_v4 = true;
        d.has_v6 = true;
        d.bad.clear();
        d.bad24.clear();
        self.dirty = true;
    }

    // ------------------------------------------------------------ 站台相容性

    /// 記錄某個池內 IP 能不能服務某個網站
    pub fn zone_note(&mut self, provider: &str, ip: IpAddr, ok: bool) {
        let k = format!("{provider}|{ip}");
        if !self.zone.contains_key(&k) && self.zone.len() >= self.cfg.zone_max.max(16) {
            // 上限：丟掉最久沒更新的
            if let Some(i) = (0..self.zone.len()).min_by_key(|&i| self.zone[i].at.unwrap_or(0)) {
                self.zone.shift_remove_index(i);
            }
        }
        let z = self.zone.entry(k).or_default();
        if ok {
            z.hit += 1;
        } else {
            z.miss += 1;
        }
        z.at = Some(now_ms());
        let warn_now = !ok && z.miss == 2;
        self.zone_dirty = true;
        if warn_now && self.is_restricted(provider, ip) {
            warn!("{provider} 節點 {ip} 多個網站無法使用（可能是特定產品專用 IP），之後排到最後");
        }
    }

    /// 相容性紀錄（鍵是 `provider|ip`）。查詢路徑上每個節點都會查：鍵寫在堆疊上，不配置記憶體
    fn zone_of(&self, provider: &str, ip: IpAddr) -> Option<&Zone> {
        use std::fmt::Write;
        struct Buf {
            b: [u8; 96],
            n: usize,
        }
        impl Write for Buf {
            fn write_str(&mut self, s: &str) -> std::fmt::Result {
                let end = self.n + s.len();
                self.b.get_mut(self.n..end).ok_or(std::fmt::Error)?.copy_from_slice(s.as_bytes());
                self.n = end;
                Ok(())
            }
        }
        let mut k = Buf { b: [0; 96], n: 0 };
        match write!(k, "{provider}|{ip}") {
            Ok(()) => self.zone.get(std::str::from_utf8(&k.b[..k.n]).ok()?),
            Err(_) => self.zone.get(&format!("{provider}|{ip}")),
        }
    }

    pub fn is_restricted(&self, provider: &str, ip: IpAddr) -> bool {
        match self.zone_of(provider, ip) {
            Some(z) => z.miss >= 2 && z.miss > z.hit * 2,
            None => false,
        }
    }

    pub fn zone_hit(&self, provider: &str, ip: IpAddr) -> bool {
        match self.zone_of(provider, ip) {
            Some(z) => z.hit > 0 && !(z.miss >= 2 && z.miss > z.hit * 2),
            None => false,
        }
    }

    // ------------------------------------------------------------ 查詢

    pub fn has(&self, provider: &str) -> bool {
        self.p.contains_key(provider)
    }

    pub fn octet_mode(&self, provider: &str) -> bool {
        providers::get(provider).map(|p| p.octet).unwrap_or(false)
    }

    /// 沒有台灣 POP 的 CDN（Fastly）：改用「最近的節點」
    pub fn is_nearest(&self, provider: &str) -> bool {
        providers::get(provider).map(|p| p.nearest).unwrap_or(false)
    }

    /// IP 仍在節點池且未被暫停
    pub fn usable(&self, provider: &str, ip: IpAddr) -> bool {
        let Some(d) = self.p.get(provider) else { return false };
        if self.octet_mode(provider) {
            if let Some(pf) = util::prefix24(ip) {
                if self.bad24(provider, pf) || self.is_restricted(provider, ip) {
                    return false;
                }
                return self.pop_view(provider).has_prefix(pf);
            }
        }
        if d.bad.contains_key(&ip) {
            return false;
        }
        d.pool(if ip.is_ipv6() { 6 } else { 4 }).iter().any(|x| x.ip == ip)
    }

    /// 依品質排序的 POP：分數不超過第 1 名＋slack，且測過速度的不能低於 1 MB/s
    /// （實測香港延遲最低 26ms，但海纜壅塞時下載只剩 0.09 MB/s，不能拿來用）
    pub fn active_pops(&self, provider: &str) -> Vec<String> {
        self.pop_view(provider).pops.iter().map(|(p, _)| p.clone()).collect()
    }

    /// 依品質排序的 POP 與各 POP 的網段（快取；內容同 `active_pops` ＋ 每個 POP 的 `pop_prefixes`）
    pub fn pop_view(&self, provider: &str) -> Arc<PopView> {
        let gen = self.p.gen();
        let mut cache = self.pop_cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = cache.iter().find(|c| c.provider == provider && c.gen == gen) {
            if c.until == u64::MAX || now_ms() < c.until {
                return c.view.clone();
            }
        }
        let Some((&name, d)) = self.p.get_key_value(provider) else {
            return Arc::default();
        };
        let now = now_ms();
        // 暫停中的網段：最早恢復的那一刻內容會變（`bad24` 只看時間，不會動到版本號）
        let until = d
            .bad24
            .values()
            .filter(|b| now.saturating_sub(b.at) <= BAD24_MS)
            .map(|b| b.at + BAD24_MS + 1)
            .min()
            .unwrap_or(u64::MAX);
        let view = Arc::new(PopView {
            pops: self
                .calc_active_pops(provider)
                .into_iter()
                .map(|pop| {
                    let l = self.pop_prefixes(provider, &pop);
                    (pop, l)
                })
                .collect(),
        });
        cache.retain(|c| c.provider != name);
        cache.push(PopCache {
            provider: name,
            gen,
            until,
            view: view.clone(),
        });
        view
    }

    fn calc_active_pops(&self, provider: &str) -> Vec<String> {
        let Some(d) = self.p.get(provider) else { return vec![] };
        let mut best: IndexMap<String, (f64, bool)> = IndexMap::new();
        for x in &d.pool4 {
            if d.bad.contains_key(&x.ip) {
                continue;
            }
            let pop = pop3(x.pop_str());
            let sc = node_score(x);
            let speed = x.speed.get();
            match best.get_mut(&pop) {
                Some(b) if sc >= b.0 => {
                    if speed.map(|s| s >= 1.0).unwrap_or(false) {
                        b.1 = false;
                    }
                }
                _ => {
                    best.insert(pop, (sc, speed.map(|s| s < 1.0).unwrap_or(false)));
                }
            }
        }
        let mut list: Vec<(String, (f64, bool))> = best.into_iter().collect();
        list.sort_by(|a, b| a.1 .0.partial_cmp(&b.1 .0).unwrap_or(std::cmp::Ordering::Equal));
        let Some(top) = list.first().map(|x| x.1 .0) else { return vec![] };
        let slack = self.cfg.nearest_score_slack;
        list.into_iter()
            .enumerate()
            .filter(|(i, (_, (sc, slow)))| *i == 0 || (*sc <= top + slack && !slow))
            .map(|(_, (pop, _))| pop)
            .collect()
    }

    /// 某個 POP 目前的品質分數（越低越好）
    pub fn pop_score(&self, provider: &str, pop: &str) -> Option<f64> {
        let d = self.p.get(provider)?;
        d.pool4
            .iter()
            .filter(|x| pop3_is(x.pop_str(), pop) && !d.bad.contains_key(&x.ip))
            .map(node_score)
            .reduce(f64::min)
    }

    /// 某 POP 的所有網段（節點池裡的網段 ＋ 每日掃描結果），去掉暫停中的
    pub fn pop_prefixes(&self, provider: &str, pop: &str) -> Vec<u32> {
        let Some(d) = self.p.get(provider) else { return vec![] };
        let mut out: Vec<u32> = Vec::new();
        let from_pool = d
            .pool4
            .iter()
            .filter(|x| pop3_is(x.pop_str(), pop) && !d.bad.contains_key(&x.ip))
            .filter_map(|x| util::prefix24(x.ip));
        for pf in from_pool.chain(d.prefixes.get(pop).into_iter().flatten().copied()) {
            if !out.contains(&pf) {
                out.push(pf);
            }
        }
        out.retain(|pf| !self.bad24(provider, *pf));
        out
    }

    /// 網段暫停中（連線失敗，30 分鐘後自動恢復）
    pub fn bad24(&self, provider: &str, pf: u32) -> bool {
        self.p
            .get(provider)
            .and_then(|d| d.bad24.get(&pf))
            .map(|b| now_ms().saturating_sub(b.at) <= BAD24_MS)
            .unwrap_or(false)
    }

    /// 某個 IP 所在網段屬於哪個 POP
    pub fn pop_of_ip(&self, provider: &str, ip: IpAddr) -> Option<String> {
        let d = self.p.get(provider)?;
        let pf = util::prefix24(ip)?;
        if let Some(e) = d.pool4.iter().find(|x| util::prefix24(x.ip) == Some(pf)) {
            return Some(pop3(e.pop_str()));
        }
        d.prefixes.iter().find(|(_, l)| l.contains(&pf)).map(|(pop, _)| pop3(pop))
    }

    /// 該 POP 目前量到的最佳延遲
    pub fn ip_ms(&self, provider: &str, ip: IpAddr) -> Option<f64> {
        let d = self.p.get(provider)?;
        let pop = self.pop_of_ip(provider, ip)?;
        d.pool4
            .iter()
            .find(|p| pop3_is(p.pop_str(), &pop) && !d.bad.contains_key(&p.ip) && p.ms.truthy())
            .and_then(|x| x.ms.get())
    }

    /// 依原始答案產生要回給用戶端的 IP（一般 CDN = 節點池；保留最後一段的 CDN = 已驗證能服務這組憑證的最佳 POP 網段）
    pub fn map_ips(&self, provider: &str, family: u8, orig: &[IpAddr]) -> Vec<IpAddr> {
        if !self.octet_mode(provider) || family != 4 {
            return self.serve_ips(provider, family);
        }
        let mut octs: Vec<u8> = Vec::new();
        for o in orig.iter().filter_map(|ip| util::last_octet(*ip)) {
            if !octs.contains(&o) {
                octs.push(o);
            }
        }
        let n = self.cfg.serve_count_of(provider);
        // 同一次回應只用同一個 POP：依品質順序，找第一個「這組憑證已驗證可用」的 POP
        for (_, prefs) in &self.pop_view(provider).pops {
            let mut out: Vec<IpAddr> = Vec::new();
            for &o in &octs {
                for &pf in prefs {
                    let ip = util::ip_of(pf, o);
                    if self.zone_hit(provider, ip) && !out.contains(&ip) {
                        out.push(ip);
                    }
                }
            }
            if !out.is_empty() {
                out.truncate(n);
                return out;
            }
        }
        vec![]
    }

    /// 驗證候選（保留最後一段的 CDN）：最佳幾個 POP 裡，依序是
    /// 已知可用的網段 → 這個網域自己的 DNS 曾經回過、且落在該 POP 的 IP → 該 POP 其他網段
    pub fn verify_candidates(&self, provider: &str, orig: Option<IpAddr>, observed: &[IpAddr]) -> Vec<IpAddr> {
        let o = match orig {
            Some(ip @ IpAddr::V4(_)) if self.octet_mode(provider) => util::last_octet(ip).unwrap(),
            _ => return self.serve_ips(provider, if orig.map(|i| i.is_ipv6()).unwrap_or(false) { 6 } else { 4 }),
        };
        let mut out: Vec<IpAddr> = Vec::new();
        let view = self.pop_view(provider);
        for (i, (_, prefs)) in view.pops.iter().take(5).enumerate() {
            let mut order: Vec<u32> = prefs
                .iter()
                .copied()
                .filter(|pf| self.zone_hit(provider, util::ip_of(*pf, o)))
                .collect();
            for ip in observed {
                if util::last_octet(*ip) == Some(o) {
                    if let Some(pf) = util::prefix24(*ip) {
                        if prefs.contains(&pf) && !order.contains(&pf) {
                            order.push(pf);
                        }
                    }
                }
            }
            for pf in prefs {
                if !order.contains(pf) {
                    order.push(*pf);
                }
            }
            let list: Vec<IpAddr> = order
                .into_iter()
                .map(|pf| util::ip_of(pf, o))
                .filter(|ip| !self.is_restricted(provider, *ip))
                .collect();
            let take = if i == 0 { self.cfg.octet_search } else { 3 };
            out.extend(list.into_iter().take(take));
        }
        let mut uniq = Vec::new();
        for ip in out {
            if !uniq.contains(&ip) {
                uniq.push(ip);
            }
        }
        uniq
    }

    /// 目前最佳 POP（節點池第一個可用節點的 POP）
    pub fn best_pop(&self, provider: &str) -> Option<String> {
        let d = self.p.get(provider)?;
        d.pool4.iter().find(|x| !d.bad.contains_key(&x.ip)).map(|x| pop3(x.pop_str()))
    }

    /// 判斷 IP 屬於哪個 CDN 及其分類
    pub fn classify(&self, ip: IpAddr) -> Option<Class> {
        let ip = unmap(ip);
        self.p
            .iter()
            .find_map(|(name, d)| d.class_of(ip, self.is_nearest(name)).map(|cls| Class { provider: name, cls }))
    }

    /// IP 在不在這家 CDN 的官方範圍（含掃描分類）裡。節點池工作的候選（流量收集、舊節點池、種子、
    /// 好友提示）都要先過這一關：範圍外的 IP 可能是任何人的機器，不能因為「HTTP 回了台灣 POP」就放進池
    pub fn in_ranges(&self, provider: &str, ip: IpAddr) -> bool {
        self.p
            .get(provider)
            .and_then(|d| d.class_of(unmap(ip), self.is_nearest(provider)))
            .is_some()
    }

    /// 目前範圍與分類的唯讀快照（共用同一份 `CidrSet`，只複製指標）
    pub fn classifier(&self) -> Classifier {
        // 所有 CDN 的範圍合成一個集合：不在裡面的 IP（絕大多數）查一次就知道不是 CDN
        let mut any = CidrSet::new();
        for d in self.p.values() {
            for s in [&d.range4, &d.range6, &d.tw, &d.global, &d.dead] {
                any.extend_from(s);
            }
        }
        Classifier {
            any: any.done(),
            list: self
                .p
                .iter()
                .map(|(name, d)| {
                    (
                        *name,
                        self.is_nearest(name),
                        ProviderPools {
                            range4: d.range4.clone(),
                            range6: d.range6.clone(),
                            tw: d.tw.clone(),
                            global: d.global.clone(),
                            dead: d.dead.clone(),
                            tw48: d.tw48.clone(),
                            ..Default::default()
                        },
                    )
                })
                .collect(),
        }
    }

    pub fn best_ms(&self, provider: &str, family: u8) -> Option<f64> {
        let d = self.p.get(provider)?;
        d.pool(family)
            .iter()
            .find(|p| !d.bad.contains_key(&p.ip) && p.ms.truthy())
            .and_then(|x| x.ms.get())
    }

    /// 這個 POP 對這家 CDN 來說算不算「目標節點」
    pub fn accept_pop(&self, provider: &str, pop: &str) -> bool {
        if pop.is_empty() {
            return false;
        }
        if is_tw_pop(pop) {
            return true;
        }
        if !self.is_nearest(provider) {
            return false;
        }
        let p3: String = pop.chars().take(3).collect();
        self.p
            .get(provider)
            .map(|d| {
                d.pool4
                    .iter()
                    .chain(&d.pool6)
                    .any(|x| !x.pop_str().is_empty() && x.pop_str().chars().take(3).collect::<String>() == p3)
            })
            .unwrap_or(false)
    }

    /// 要回給用戶端的台灣 IP
    pub fn serve_ips(&self, provider: &str, family: u8) -> Vec<IpAddr> {
        let Some(d) = self.p.get(provider) else { return vec![] };
        let n = self.cfg.serve_count_of(provider);
        let list: Vec<IpAddr> = d.pool(family).iter().filter(|x| !d.bad.contains_key(&x.ip)).map(|x| x.ip).collect();
        let open: Vec<IpAddr> = list.iter().copied().filter(|ip| !self.is_restricted(provider, *ip)).collect();
        let mut out = if open.is_empty() { list } else { open };
        out.truncate(n);
        out
    }

    pub fn pool_size(&self, provider: &str, family: u8) -> usize {
        self.p
            .get(provider)
            .map(|d| d.pool(family).iter().filter(|x| !d.bad.contains_key(&x.ip)).count())
            .unwrap_or(0)
    }

    /// 驗證或健檢發現某個池內 IP 不是台灣節點 / 失效
    pub fn mark_bad(&mut self, provider: &str, ip: IpAddr, reason: &str) {
        let octet = self.octet_mode(provider);
        let Some(d) = self.p.get_mut(provider) else { return };
        let now = now_ms();
        let mut ip = ip;
        if octet {
            if let Some(pf) = util::prefix24(ip) {
                match d.pool4.iter().find(|x| util::prefix24(x.ip) == Some(pf)) {
                    None => {
                        d.bad24.retain(|_, b| now.saturating_sub(b.at) <= BAD24_MS);
                        d.bad24.insert(
                            pf,
                            Bad {
                                at: now,
                                reason: reason.to_string(),
                                quality: false,
                            },
                        );
                        warn!("{provider} 網段 {}.0/24 暫停使用：{reason}", util::prefix24_str(pf));
                        return;
                    }
                    Some(e) => ip = e.ip,
                }
            }
        }
        d.bad.insert(
            ip,
            Bad {
                at: now,
                reason: reason.to_string(),
                quality: false,
            },
        );
        warn!("{provider} 節點 {ip} 暫停使用：{reason}");
        let fam = if ip.is_ipv6() { 6 } else { 4 };
        if self.pool_size(provider, fam) < self.cfg.min_pool {
            self.request_rebuild(provider);
        }
    }

    pub fn request_rebuild(&mut self, provider: &str) {
        if let Some(p) = providers::get(provider) {
            if !self.low_pool.contains(&p.name) {
                self.low_pool.push(p.name);
            }
        }
    }

    /// 狀態（管理介面 `/api/cdn/pools`）
    pub fn status(&self) -> Value {
        let mut o = Map::new();
        for (name, d) in &self.p {
            let list = |pool: &Vec<PoolNode>| -> Vec<Value> {
                pool.iter()
                    .map(|x| {
                        let mut v = serde_json::to_value(x).unwrap_or_default();
                        if let (Some(b), Some(m)) = (d.bad.get(&x.ip), v.as_object_mut()) {
                            m.insert("bad".into(), json!(b.reason));
                        }
                        v
                    })
                    .collect()
            };
            o.insert(
                name.to_string(),
                json!({
                    "v4": list(&d.pool4), "v6": list(&d.pool6),
                    "scan": { "tw": d.tw.v4_len(), "global": d.global.v4_len(), "dead": d.dead.v4_len() },
                    "ranges": { "v4": d.range4.v4_len(), "v6": d.range6.v6_len() },
                }),
            );
        }
        Value::Object(o)
    }
}

fn seed_nodes(list: &[String]) -> Vec<PoolNode> {
    list.iter()
        .filter_map(|s| util::parse_ip(s))
        .map(|ip| {
            let mut n = PoolNode::new(ip);
            n.ms = Num::Null;
            n.pop = Some(util::intern("seed"));
            n
        })
        .collect()
}

fn parse_prefixes(v: Option<&Value>) -> IndexMap<String, Vec<u32>> {
    let mut out = IndexMap::new();
    if let Some(m) = v.and_then(Value::as_object) {
        for (pop, list) in m {
            let l: Vec<u32> = list
                .as_array()
                .map(|a| a.iter().filter_map(|x| x.as_str()).filter_map(util::parse_prefix24).collect())
                .unwrap_or_default();
            out.insert(pop.clone(), l);
        }
    }
    out
}

/// 測試與工作用：由清單建立 CIDR 集合
pub fn cidr(list: &[&str]) -> Arc<CidrSet> {
    let mut s = CidrSet::new();
    s.add_many(list.iter().copied());
    Arc::new(s.done())
}
