//! 台灣節點池（對齊 2.x `lib/cdn/pools.js`）：CDN IP 範圍、掃描分類（TW / Global / Dead）、
//! 可用的台灣替換 IP、節點相容性紀錄（ip-zone）。
//!
//! 這裡只有不需要網路的部分；健檢、品質監測、IPv6 即時發現在 `health.rs`。

use crate::cidr::CidrSet;
use crate::config::CdnConfig;
use crate::providers::{self, is_tw_pop};
use crate::util::{self, de_ip, de_opt_arc, de_opt_bool, de_opt_u32, de_opt_u64, de_u64, now_ms, ser_opt_arc, Extra, Num};
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

/// 測速被限流的那一輪，沒量到的節點最多沿用前幾輪的速度（3.5.0 F15）
pub const SPEED_AGE_MAX: u32 = 3;

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
    /// 相對評分的「慢」（3.5.0 B1）：跟同一家其他節點比，由節點池工作算好存下來。
    /// 沒有這個欄位（舊的 `pools.json`、沒量到速度的節點）沿用舊規則：量到的速度低於 1 MB/s 算慢
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_bool")]
    pub slow: Option<bool>,
    /// 速度是沿用前幾輪的（3.5.0 F15：那一輪測速被對方限流；最多沿用 [`SPEED_AGE_MAX`] 輪）。沒有 = 這一輪量的
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_u32")]
    pub speed_age: Option<u32>,
    /// 測速的量測樣本（3.5.0：B1 的誤差範圍、B2 工作負載分數的量測基礎；只有量過速度的節點才有）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample: Option<Box<NodeSample>>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// 節點的量測樣本（全部來自既有的那一次下載測速，不多連線、不多收資料）
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeSample {
    /// 收到的位元組數（上限 8 MiB；快測 1 MiB）
    #[serde(default, deserialize_with = "de_u64")]
    pub bytes: u64,
    /// 收內容花的秒數
    #[serde(default, skip_serializing_if = "Num::is_absent")]
    pub secs: Num,
    /// 連線＋握手（毫秒）
    #[serde(default, skip_serializing_if = "Num::is_absent")]
    pub connect_ms: Num,
    /// 送出請求到收完標頭（毫秒，TTFB）
    #[serde(default, skip_serializing_if = "Num::is_absent")]
    pub ttfb_ms: Num,
    /// 快測（量到瓶頸之後只收 1 MiB 確認不慢）：`speed` 記的是瓶頸的速度，不是這個節點自己量到的
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_bool")]
    pub quick: Option<bool>,
    /// 收到第 1 MiB 花幾秒（3.5.0 F16：快測門檻的參考；同一條連線順便記）
    #[serde(default, skip_serializing_if = "Num::is_absent")]
    pub head_secs: Num,
    #[serde(flatten)]
    pub extra: Extra,
}

impl NodeSample {
    pub fn of(s: &kuroshio_net::probe::SpeedSample, quick: bool) -> NodeSample {
        let ms = |v: f64| if v > 0.0 { Num::V(util::round(v, 1)) } else { Num::Absent };
        NodeSample {
            bytes: s.bytes,
            secs: if s.secs > 0.0 {
                Num::V(util::round(s.secs, 3))
            } else {
                Num::Absent
            },
            connect_ms: ms(s.connect_ms),
            ttfb_ms: ms(s.ttfb_ms),
            quick: quick.then_some(true),
            head_secs: if s.head_secs > 0.0 {
                Num::V(util::round(s.head_secs, 3))
            } else {
                Num::Absent
            },
            extra: Extra::default(),
        }
    }
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
            slow: None,
            speed_age: None,
            sample: None,
            extra: Extra::default(),
        }
    }

    /// 慢不慢：有相對評分的旗標就用它；沒有（舊資料）沿用舊規則。None = 沒量過速度
    pub fn is_slow(&self) -> Option<bool> {
        self.slow.or_else(|| self.speed.get().map(|s| s < crate::speed::LEGACY_SLOW_MBPS))
    }

    pub fn pop_str(&self) -> &str {
        self.pop.as_deref().unwrap_or("")
    }

    /// 上游宣稱的機房（3.5.0 E4，`extra.upPop`）：串接匯入的節點在本機量到之前才有。
    /// 放在 `extra`（不認得的欄位原樣保留），舊版讀到 `pools.json` 也不受影響
    pub fn up_pop(&self) -> Option<&str> {
        self.extra.get(UP_POP).and_then(Value::as_str)
    }

    pub fn set_up_pop(&mut self, pop: &str) {
        self.extra
            .0
            .get_or_insert_with(Default::default)
            .insert(UP_POP.into(), Value::String(pop.to_string()));
    }

    /// 拿掉 `upPop`（本機量到了、或分享給下游之前），回傳原本的值
    pub fn take_up_pop(&mut self) -> Option<String> {
        let m = self.extra.0.as_mut()?;
        let v = m.remove(UP_POP)?;
        if m.is_empty() {
            self.extra.0 = None;
        }
        v.as_str().map(String::from)
    }

    /// 有效的尖峰量測（3 天內）
    pub fn peak_fresh(&self, now: u64) -> bool {
        self.peak_at.map(|t| now.saturating_sub(t) < PEAK_FRESH_MS).unwrap_or(false) && self.peak_ms.get().is_some()
    }
}

/// `PoolNode.extra` 裡上游宣稱的機房（3.5.0 E4）
pub const UP_POP: &str = "upPop";

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

/// 同 [`qscore_of`]，「慢」由呼叫端算好傳進來（3.5.0 B1 的相對評分）
pub fn qscore_rel(ms: Num, jitter: Num, loss: Num, slow: bool) -> f64 {
    // 速度只用來決定要不要加懲罰：借 `qscore_of` 的舊門檻表示（慢 = 0，不慢 = 沒量）
    qscore_of(ms, jitter, loss, if slow { Num::V(0.0) } else { Num::Absent })
}

pub fn qscore(x: &PoolNode) -> f64 {
    qscore_rel(x.ms, x.jitter, x.loss, x.is_slow() == Some(true))
}

/// 加上尖峰時段權重的分數：有 3 天內的尖峰量測時，（平時 + w × 尖峰）/（1 + w）
pub fn weighted_qscore(x: &PoolNode, w: f64, now: u64) -> f64 {
    let s = qscore(x);
    if !x.peak_fresh(now) || w <= 0.0 {
        return s;
    }
    let sp = qscore_rel(x.peak_ms, x.peak_jitter, x.peak_loss, x.is_slow() == Some(true));
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

/// 同一個位址反覆被驗證標成壞的（3.5.1 K2）：第 n 次暫停 [`STRIKE_BASE_MS`] × 2^(n−1)，最多 [`STRIKE_MAX_MS`]；
/// 最後一次之後 [`STRIKE_FORGET_MS`] 沒再發生就從頭算。暫停期間健檢通過也不恢復（健檢只連業者自己的網站，
/// 證明不了「對這個網站可以用」）
pub const STRIKE_BASE_MS: u64 = BAD24_MS;
pub const STRIKE_MAX_MS: u64 = 8 * util::HOUR_MS;
pub const STRIKE_FORGET_MS: u64 = util::DAY_MS;
/// 每家 CDN 最多記幾個位址（超過丟掉最舊的）
pub const STRIKE_CAP: usize = 256;

/// 一個位址被驗證標成壞的次數與最後一次的時間（3.5.1 K2）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Strike {
    pub n: u32,
    pub at: u64,
}

impl Strike {
    /// 這一次暫停多久
    pub fn hold_ms(&self) -> u64 {
        (STRIKE_BASE_MS << self.n.saturating_sub(1).min(8)).min(STRIKE_MAX_MS)
    }
    /// 還在暫停中
    pub fn held(&self, now: u64) -> bool {
        now < self.at.saturating_add(self.hold_ms())
    }
}

/// 驗證時連不上（3.5.1 K2）：同一個節點在 [`CONN_FAIL_WINDOW_MS`] 內對 [`CONN_FAIL_SITES`] 個以上不同的網站都連不上，
/// 才算節點的問題、暫停節點。只有一個網站連不上多半是那個網站的問題（例如只接受業者專用 IP），
/// 由驗證結果記在網站上（`verifier.rs`）
pub const CONN_FAIL_SITES: usize = 2;
pub const CONN_FAIL_WINDOW_MS: u64 = util::HOUR_MS;

/// 一個節點的連不上紀錄（3.5.1 K2）
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnFail {
    pub at: u64,
    /// 連不上的網站名稱（最多 [`CONN_FAIL_SITES`] 個；只在記憶體裡，暫停時寫進日誌，讓人確認是不同的網站）
    pub sites: Vec<Box<str>>,
}

/// 日誌裡列出幾個網站名稱（「多個網站無法使用」與「幾個網站都連不上」）
pub const LOG_SITES: usize = 3;
/// 記著「不服務」網站名稱（給日誌用）的節點最多幾個：只在記憶體裡，滿了丟掉最早的
pub const ZONE_NAMES_CAP: usize = 256;

/// 日誌用的網站清單：「a.example.com、b.example.com、c.example.com 等」；記得的名稱比總數少時說明其他的沒有名稱
pub(crate) fn sites_text(names: &[Box<str>], total: usize) -> String {
    let shown: Vec<&str> = names.iter().take(LOG_SITES).map(|s| &**s).collect();
    let mut t = shown.join("、");
    let more = total.saturating_sub(shown.len());
    if more > 0 {
        if names.len() > shown.len() || shown.len() == LOG_SITES {
            t.push_str(" 等");
        } else if shown.is_empty() {
            t = format!("{more} 個是之前記的，沒有名稱");
        } else {
            t.push_str(&format!("；另 {more} 個是之前記的，沒有名稱"));
        }
    }
    t
}

/// `/api/cdn/pools` 每家 CDN 列出幾個「特定產品專用」的節點（3.5.1；總數另外給 `restrictedTotal`）
pub const RESTRICTED_LIST_MAX: usize = 32;
/// 消退的日誌每家 CDN 列出幾個節點
const LIFTED_LOG_IPS: usize = 5;

/// 「特定產品專用」消退的日誌內容（`keys` 是相容性紀錄的鍵 `provider|ip`）：同一家 CDN 合併，
/// 「fastly 2 個（192.0.2.1、192.0.2.2）、cloudflare 1 個（198.51.100.3）」；每家最多列 5 個 IP。沒有回 None
pub(crate) fn lifted_text(keys: &[&str]) -> Option<String> {
    let mut by: IndexMap<&str, Vec<&str>> = IndexMap::new();
    for k in keys {
        let (p, ip) = k.split_once('|').unwrap_or((k, ""));
        by.entry(p).or_default().push(ip);
    }
    if by.is_empty() {
        return None;
    }
    let parts: Vec<String> = by
        .iter()
        .map(|(p, ips)| {
            let shown: Vec<&str> = ips.iter().take(LIFTED_LOG_IPS).copied().collect();
            let more = if ips.len() > shown.len() { " 等" } else { "" };
            format!("{p} {} 個（{}{more}）", ips.len(), shown.join("、"))
        })
        .collect();
    Some(parts.join("、"))
}

/// 網站名稱的雜湊（FNV-1a，只用來分辨「是不是同一個網站」）
fn site_hash(name: &str) -> u32 {
    name.bytes().fold(0x811c_9dc5u32, |h, b| (h ^ b as u32).wrapping_mul(0x0100_0193))
}

/// 相容性紀錄判定為「特定產品專用」：2 個以上的網站不服務，而且比服務的次數的兩倍多
fn restricted(z: &Zone) -> bool {
    z.miss >= 2 && z.miss > z.hit.saturating_mul(2)
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
    /// 最後一次「不服務」的時間（3.5.1 L3）：[`ZONE_MISS_KEEP_MS`] 沒有新的就把 `miss` 清掉
    #[serde(
        rename = "missAt",
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de_opt_u64"
    )]
    pub miss_at: Option<u64>,
    /// 「不服務」的網站（名稱的雜湊，最多 [`ZONE_SITES_MAX`] 個）：同一個網站重複失敗只算一次（3.5.1 L3）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sites: Vec<u32>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// 「不服務」的紀錄多久沒有新的就清掉（3.5.1 L3）
pub const ZONE_MISS_KEEP_MS: u64 = 7 * 24 * 3600 * 1000;
/// 每個節點記幾個「不服務」的網站
pub const ZONE_SITES_MAX: usize = 8;

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
    /// 驗證反覆標成壞的位址（3.5.1 K2，暫停時間逐次加倍）。換節點池（`replace()`）時不清，下次再失敗照樣加倍
    pub strikes: HashMap<IpAddr, Strike>,
    /// 驗證時連不上的節點（3.5.1 K2）：節點（保留最後一段的 CDN 是 /24）→ 第一次的時間與連不上的網站（雜湊）
    pub conn_fails: HashMap<IpAddr, ConnFail>,
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

    /// 記一次（3.5.1 K2）：上一次超過 [`STRIKE_FORGET_MS`] 就從 1 算；有上限（丟掉最舊的）
    pub fn strike(&mut self, ip: IpAddr, now: u64) -> Strike {
        self.strikes.retain(|_, s| now.saturating_sub(s.at) <= STRIKE_FORGET_MS);
        let n = self.strikes.get(&ip).map_or(0, |s| s.n);
        if n == 0 && self.strikes.len() >= STRIKE_CAP {
            if let Some(old) = self.strikes.iter().min_by_key(|(_, s)| s.at).map(|(k, _)| *k) {
                self.strikes.remove(&old);
            }
        }
        let s = Strike {
            n: n.saturating_add(1),
            at: now,
        };
        self.strikes.insert(ip, s);
        s
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

pub(crate) fn unmap(ip: IpAddr) -> IpAddr {
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
    /// 相容性紀錄「不服務」的網站名稱（鍵同 `zone`，每個最多 [`LOG_SITES`] 個、最多 [`ZONE_NAMES_CAP`] 個節點）：
    /// 只給「多個網站無法使用」的日誌用，不存檔（`zone` 存的是雜湊），重新啟動後從頭記
    zone_names: IndexMap<String, Vec<Box<str>>>,
    pub dirty: bool,
    pub zone_dirty: bool,
    /// 節點不足、需要重建節點池的 CDN（由外層取出後通知排程）
    pub low_pool: Vec<&'static str>,
    /// 節點池內容換過（`replace()`、`merge_shared()`）：放開狀態鎖時重算 E3 的 `reach`（3.5.0）
    pub reach_dirty: bool,
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
            zone_names: IndexMap::new(),
            dirty: false,
            zone_dirty: false,
            low_pool: Vec::new(),
            reach_dirty: true,
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
        // 3.5.1 L3：很久沒有新的「不服務」的紀錄載入時就消退（之後每小時一次）
        self.decay_zone(now_ms());
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
    /// 串接拿到的節點池（3.4.3）：上游的節點在前、這台原本的節點接在後面（同一個 IP 只留一個），各家族最多 `max`；
    /// 這台記的壞節點（`bad`、`bad24`）不清掉，壞節點也不放進來
    pub fn merge_shared(&mut self, name: &str, mut pool4: Vec<PoolNode>, mut pool6: Vec<PoolNode>, rest: Map<String, Value>, max: usize) {
        let Some(d) = self.p.get(name) else { return };
        let (bad, old4, old6) = (d.bad.clone(), d.pool4.clone(), d.pool6.clone());
        let bad24 = d.bad24.clone();
        let now = now_ms();
        let is_bad = |ip: &IpAddr| {
            bad.contains_key(ip)
                || util::prefix24(*ip).is_some_and(|pf| bad24.get(&pf).is_some_and(|b| now.saturating_sub(b.at) <= BAD24_MS))
        };
        pool4.retain(|x| !is_bad(&x.ip));
        pool6.retain(|x| !is_bad(&x.ip));
        for (pool, old) in [(&mut pool4, old4), (&mut pool6, old6)] {
            for n in old {
                if pool.len() >= max {
                    break;
                }
                if !pool.iter().any(|x| x.ip == n.ip) {
                    pool.push(n);
                }
            }
            pool.truncate(max.max(1));
        }
        self.replace(name, pool4, pool6, rest);
        if let Some(d) = self.p.get_mut(name) {
            d.bad = bad;
            d.bad24 = bad24;
        }
    }

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
        self.reach_dirty = true;
    }

    // ------------------------------------------------------------ 站台相容性

    /// 記錄某個池內 IP 能不能服務某個網站
    pub fn zone_note(&mut self, provider: &str, ip: IpAddr, ok: bool) {
        self.zone_note_site(provider, ip, ok, "");
    }

    /// 相容性紀錄（3.5.1 L3）：「不服務」算**不同的網站**（`site` 是網站名稱；空的 = 不分網站，舊的算法）。
    /// 以前同一個網站每驗證一次就多算一次，幾次重驗就把節點當成「特定產品專用」，而且永遠不會消退
    pub fn zone_note_site(&mut self, provider: &str, ip: IpAddr, ok: bool, site: &str) {
        let k = format!("{provider}|{ip}");
        if !self.zone.contains_key(&k) && self.zone.len() >= self.cfg.zone_max.max(16) {
            // 上限：丟掉最久沒更新的
            if let Some(i) = (0..self.zone.len()).min_by_key(|&i| self.zone[i].at.unwrap_or(0)) {
                if let Some((old, _)) = self.zone.shift_remove_index(i) {
                    self.zone_names.shift_remove(&old);
                }
            }
        }
        let now = now_ms();
        let z = self.zone.entry(k.clone()).or_default();
        let was = restricted(z);
        let mut named = false;
        if ok {
            z.hit = z.hit.saturating_add(1);
        } else {
            z.miss_at = Some(now);
            let h = (!site.is_empty()).then(|| site_hash(site));
            let new_site = match h {
                Some(h) => !z.sites.contains(&h),
                None => true,
            };
            if new_site {
                z.miss = z.miss.saturating_add(1);
                named = h.is_some();
                if let Some(h) = h {
                    if z.sites.len() >= ZONE_SITES_MAX {
                        z.sites.remove(0);
                    }
                    z.sites.push(h);
                }
            }
        }
        z.at = Some(now);
        let (now_restricted, miss, hit) = (restricted(z), z.miss, z.hit);
        self.zone_dirty = true;
        if named {
            // 網站名稱只記前幾個（日誌用）；節點數有上限，滿了丟掉最早的
            if !self.zone_names.contains_key(&k) && self.zone_names.len() >= ZONE_NAMES_CAP {
                self.zone_names.shift_remove_index(0);
            }
            let names = self.zone_names.entry(k.clone()).or_default();
            if names.len() < LOG_SITES {
                names.push(site.into());
            }
        }
        // 剛變成「特定產品專用」時寫一次（3.5.1：附上網站數與前幾個網站，才能確認是不同的網站）
        if !was && now_restricted {
            let names = self.zone_names.get(&k).map(Vec::as_slice).unwrap_or(&[]);
            warn!(
                "{provider} 節點 {ip} 有 {miss} 個網站無法使用（{}），可以用的 {hit} 次；可能是特定產品專用 IP，之後排到最後",
                sites_text(names, miss as usize)
            );
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

    /// 「不服務」的紀錄消退（3.5.1 L3；背景每小時一次、載入時一次，不在查詢路徑上）：[`ZONE_MISS_KEEP_MS`] 沒有新的「不服務」
    /// 就把 `miss` 清掉（舊資料沒有 `missAt` 時看 `at`）；同時也沒有「服務」的整筆拿掉。回傳動了幾筆
    pub fn decay_zone(&mut self, now: u64) -> usize {
        let mut n = 0;
        // 消退的「特定產品專用」節點（3.5.1）：寫一行 INFO，同一家 CDN 的合併
        let mut lifted_keys: Vec<String> = Vec::new();
        self.zone.retain(|k, z| {
            if z.miss == 0 {
                return true;
            }
            let last = z.miss_at.or(z.at).unwrap_or(0);
            if now.saturating_sub(last) < ZONE_MISS_KEEP_MS {
                return true;
            }
            n += 1;
            if restricted(z) {
                lifted_keys.push(k.clone());
            }
            z.miss = 0;
            z.miss_at = None;
            z.sites.clear();
            z.hit > 0
        });
        if n > 0 {
            self.zone_dirty = true;
        }
        let zone = &self.zone;
        self.zone_names.retain(|k, _| zone.get(k).is_some_and(|z| z.miss > 0));
        let lifted: Vec<&str> = lifted_keys.iter().map(String::as_str).collect();
        if let Some(t) = lifted_text(&lifted) {
            info!(
                "特定產品專用的標記消退（{} 天沒有新的網站無法使用）：{t}",
                ZONE_MISS_KEEP_MS / 86_400_000
            );
        }
        n
    }

    /// 目前被標成「特定產品專用」的節點，依 CDN 分組（`/api/cdn/pools` 每家 CDN 的 `restricted`，3.5.1）：
    /// 相容性紀錄只走一次；每組網站數（不同的網站，`sites`）多的在前
    fn restricted_by_provider(&self) -> HashMap<&str, Vec<(IpAddr, &Zone)>> {
        let mut by: HashMap<&str, Vec<(IpAddr, &Zone)>> = HashMap::new();
        for (k, z) in &self.zone {
            if !restricted(z) {
                continue;
            }
            if let Some((p, Ok(ip))) = k.split_once('|').map(|(p, ip)| (p, ip.parse::<IpAddr>())) {
                by.entry(p).or_default().push((ip, z));
            }
        }
        for v in by.values_mut() {
            v.sort_by(|a, b| b.1.miss.cmp(&a.1.miss).then_with(|| a.0.cmp(&b.0)));
        }
        by
    }

    /// 記著的「不服務」網站名稱（日誌用，最多 [`LOG_SITES`] 個；測試與除錯用）
    pub fn zone_site_names(&self, provider: &str, ip: IpAddr) -> Vec<Box<str>> {
        self.zone_names.get(&format!("{provider}|{ip}")).cloned().unwrap_or_default()
    }

    pub fn is_restricted(&self, provider: &str, ip: IpAddr) -> bool {
        self.zone_of(provider, ip).is_some_and(restricted)
    }

    pub fn zone_hit(&self, provider: &str, ip: IpAddr) -> bool {
        match self.zone_of(provider, ip) {
            Some(z) => z.hit > 0 && !restricted(z),
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
            // 慢不慢：相對評分的旗標（3.5.0 B1），舊資料沿用 1 MB/s
            let slow = x.is_slow();
            match best.get_mut(&pop) {
                Some(b) if sc >= b.0 => {
                    if slow == Some(false) {
                        b.1 = false;
                    }
                }
                _ => {
                    best.insert(pop, (sc, slow == Some(true)));
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

    /// 這個 IP 能不能當這一家的「原本的 IP」（驗證的基準，`base.ip`）：這一家有這個位址家族的官方範圍時，
    /// 要在範圍（含掃描分類）裡；沒有範圍資料的不比（3.5.1 測試版第二版 Windows C3）。
    /// 載入時的整理（`Cdn::clean_stale_learning`）用同一個判斷清掉範圍外的基準
    pub fn fits_orig(&self, provider: &str, ip: IpAddr) -> bool {
        let ip = unmap(ip);
        let Some(d) = self.p.get(provider) else { return true };
        let has_range = if ip.is_ipv4() {
            d.range4.v4_len() > 0
        } else {
            d.range6.v6_len() > 0
        };
        !has_range || d.class_of(ip, self.is_nearest(provider)).is_some()
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
                match d.pool4.iter().find(|x| util::prefix24(x.ip) == Some(pf)).map(|x| x.ip) {
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
                    Some(node) => ip = node,
                }
            }
        }
        let s = d.strike(ip, now);
        d.bad.insert(
            ip,
            Bad {
                at: now,
                reason: reason.to_string(),
                quality: false,
            },
        );
        if s.n > 1 {
            warn!(
                "{provider} 節點 {ip} 暫停使用（24 小時內第 {} 次，{} 分鐘內健檢通過也不恢復）：{reason}",
                s.n,
                s.hold_ms() / 60_000
            );
        } else {
            warn!("{provider} 節點 {ip} 暫停使用：{reason}");
        }
        let fam = if ip.is_ipv6() { 6 } else { 4 };
        if self.pool_size(provider, fam) < self.cfg.min_pool {
            self.request_rebuild(provider);
        }
    }

    /// 驗證某個網站時連不上這個節點（3.5.1 K2）：記下來，1 小時內第 2 個不同的網站也連不上才暫停（`mark_bad()`）。
    /// 保留最後一段的 CDN（Fastly）以 /24 為單位算（不同網站用的最後一段不同）。回傳有沒有暫停
    pub fn note_conn_fail(&mut self, provider: &str, ip: IpAddr, site: &str, reason: &str) -> bool {
        let octet = self.octet_mode(provider);
        let Some(d) = self.p.get_mut(provider) else { return false };
        let key = match (octet, util::prefix24(ip)) {
            (true, Some(pf)) => util::ip_of(pf, 0),
            _ => ip,
        };
        let now = now_ms();
        d.conn_fails.retain(|_, c| now.saturating_sub(c.at) <= CONN_FAIL_WINDOW_MS);
        if !d.conn_fails.contains_key(&key) && d.conn_fails.len() >= STRIKE_CAP {
            if let Some(old) = d.conn_fails.iter().min_by_key(|(_, c)| c.at).map(|(k, _)| *k) {
                d.conn_fails.remove(&old);
            }
        }
        let c = d.conn_fails.entry(key).or_insert_with(|| ConnFail {
            at: now,
            sites: Vec::new(),
        });
        if !c.sites.iter().any(|s| &**s == site) {
            c.sites.push(site.into());
        }
        if c.sites.len() < CONN_FAIL_SITES {
            return false;
        }
        let n = c.sites.len();
        let Some(c) = d.conn_fails.remove(&key) else { return false };
        // `mark_bad()` 照舊處理保留最後一段的 CDN：網段裡有節點池的節點就暫停那個節點，沒有就暫停整個 /24。
        // 3.5.1：附上是哪幾個網站（日誌與 `/api/cdn/pools` 的 `bad`），才能確認真的是不同的網站
        self.mark_bad(
            provider,
            ip,
            &format!("{reason}（1 小時內 {n} 個網站都連不上：{}）", sites_text(&c.sites, n)),
        );
        true
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
        let restricted_by = self.restricted_by_provider();
        for (name, d) in &self.p {
            let rs = restricted_by.get(name).map(Vec::as_slice).unwrap_or(&[]);
            let restricted: Vec<Value> = rs
                .iter()
                .take(RESTRICTED_LIST_MAX)
                .map(|(ip, z)| {
                    let at = z.miss_at.or(z.at);
                    json!({ "ip": ip, "sites": z.miss, "hit": z.hit, "missAt": at,
                            "inPool": d.pool4.iter().chain(&d.pool6).any(|x| x.ip == *ip),
                            // 7 天沒有新的網站無法使用就消退（毫秒）
                            "until": at.map(|t| t.saturating_add(ZONE_MISS_KEEP_MS)) })
                })
                .collect();
            let restricted_total = rs.len();
            let list = |pool: &Vec<PoolNode>| -> Vec<Value> {
                pool.iter()
                    .map(|x| {
                        let mut v = serde_json::to_value(x).unwrap_or_default();
                        if let (Some(b), Some(m)) = (d.bad.get(&x.ip), v.as_object_mut()) {
                            m.insert("bad".into(), json!(b.reason));
                            // 24 小時內被驗證標壞的次數（3.5.1 K2）
                            if let Some(s) = d.strikes.get(&x.ip) {
                                m.insert("strikes".into(), json!(s.n));
                            }
                        }
                        v
                    })
                    .collect()
            };
            o.insert(
                name.to_string(),
                json!({
                    "v4": list(&d.pool4), "v6": list(&d.pool6),
                    // 這一次節點池工作的參考速度（MB/s，3.5.0 B1）：節點的 `slow` 是跟它比出來的
                    "speedRef": d.rest.get("speedRef"),
                    // 參考速度沒有算出來的原因（3.5.0 F15）、快測的參考速度（前 1 MiB 的中位數，3.5.0 F16）
                    "speedRefWhy": d.rest.get("speedRefWhy"),
                    "quickRef": d.rest.get("quickRef"),
                    "scan": { "tw": d.tw.v4_len(), "global": d.global.v4_len(), "dead": d.dead.v4_len() },
                    "ranges": { "v4": d.range4.v4_len(), "v6": d.range6.v6_len() },
                    // 被標成「特定產品專用」的節點（3.5.1）：`sites` = 不能用的網站數，7 天沒有新的就消退（`until`）
                    "restricted": restricted, "restrictedTotal": restricted_total,
                }),
            );
        }
        Value::Object(o)
    }
}

/// 網段分散用的網段鍵（3.5.0 E6）：IPv4 是 /24、IPv6 是 /48（兩個家族不會混在同一個節點池）
pub fn net_key(ip: IpAddr) -> Option<u128> {
    match ip {
        IpAddr::V4(_) => util::prefix24(ip).map(u128::from),
        IpAddr::V6(_) => util::v6_48(ip),
    }
}

/// 網段分散（3.5.0 E6）的延遲條件：換上來的節點延遲不超過這個位置原本節點的 1.5 倍＋5 毫秒
pub const SPREAD_RATIO: f64 = 1.5;
pub const SPREAD_ABS_MS: f64 = 5.0;

/// 同機房內的網段分散（3.5.0 E6）：健檢排序之後呼叫，讓回給裝置的前 `n` 個可用節點盡量來自不同的 /24（IPv6 /48）。
///
/// - 只看可用的節點（`skip` 回 false 的：不在 `bad`、沒被 E5 暫緩），只調整前 `n` 個可用位置
/// - 由前往後：第 i 個位置跟前面已經放的同網段，就從後面找第一個「不同網段、不是 B1 判慢的、
///   延遲不超過這個位置原本節點的 [`SPREAD_RATIO`] 倍＋[`SPREAD_ABS_MS`] 毫秒」的節點換上來；找不到就不換
/// - 其餘節點的相對順序不變；不新增、不移除節點，不發任何探測
///
/// 回傳換了幾次
pub fn spread_head(pool: &mut [PoolNode], skip: &dyn Fn(&PoolNode) -> bool, n: usize, key: &dyn Fn(&PoolNode) -> f64) -> usize {
    // 可用節點在節點池裡的位置（健檢排序後是排在前面的一段，但這裡不假設）
    let idx: Vec<usize> = (0..pool.len()).filter(|&i| !skip(&pool[i])).collect();
    let mut seen: Vec<u128> = Vec::with_capacity(n);
    let mut moved = 0;
    for i in 0..n.min(idx.len()) {
        let here = net_key(pool[idx[i]].ip);
        if !here.is_some_and(|k| seen.contains(&k)) {
            seen.extend(here);
            continue;
        }
        let limit = key(&pool[idx[i]]) * SPREAD_RATIO + SPREAD_ABS_MS;
        let found = (i + 1..idx.len()).find(|&j| {
            let x = &pool[idx[j]];
            net_key(x.ip).is_some_and(|k| !seen.contains(&k)) && x.is_slow() != Some(true) && key(x) <= limit
        });
        match found {
            Some(j) => {
                // 把第 j 個可用節點移到第 i 個可用位置，中間的往後挪一格（只在可用的位置之間挪）
                let x = pool[idx[j]].clone();
                for k in (i..j).rev() {
                    pool[idx[k + 1]] = pool[idx[k]].clone();
                }
                pool[idx[i]] = x;
                seen.extend(net_key(pool[idx[i]].ip));
                moved += 1;
            }
            None => seen.extend(here),
        }
    }
    moved
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

#[cfg(test)]
mod tests {
    use super::*;

    fn n(ip: &str, ms: f64) -> PoolNode {
        let mut x = PoolNode::new(ip.parse().unwrap());
        x.ms = Num::V(ms);
        x.pop = Some(util::intern("TPE"));
        x
    }

    fn ips(p: &[PoolNode]) -> Vec<String> {
        p.iter().map(|x| x.ip.to_string()).collect()
    }

    fn ms(x: &PoolNode) -> f64 {
        x.ms.or(999.0)
    }

    #[test]
    fn spread_head_picks_distinct_48_among_permanent_v6() {
        // 永久 IPv6 節點：前 4 名原本都在同一個 /48
        let mut p = vec![
            n("2001:db8:1::1", 2.0),
            n("2001:db8:1::2", 2.1),
            n("2001:db8:1::3", 2.2),
            n("2001:db8:1::4", 2.3),
            n("2001:db8:2::1", 2.5),
            n("2001:db8:3::1", 2.6),
            n("2001:db8:4::1", 2.7),
        ];
        assert_eq!(spread_head(&mut p, &|_| false, 4, &ms), 3);
        assert_eq!(ips(&p[..4]), ["2001:db8:1::1", "2001:db8:2::1", "2001:db8:3::1", "2001:db8:4::1"]);
        // 其餘的相對順序不變、不增不減
        assert_eq!(ips(&p[4..]), ["2001:db8:1::2", "2001:db8:1::3", "2001:db8:1::4"]);
    }

    #[test]
    fn spread_head_keeps_order_when_alternative_too_slow() {
        // 第 2 名同網段（4 ms）；不同網段的要 ≤ 4 × 1.5 + 5 = 11 ms
        let mut p = vec![n("192.0.2.1", 3.0), n("192.0.2.2", 4.0), n("198.51.100.1", 11.5)];
        let before = p.clone();
        assert_eq!(spread_head(&mut p, &|_| false, 4, &ms), 0);
        assert_eq!(p, before);
        let mut p = vec![n("192.0.2.1", 3.0), n("192.0.2.2", 4.0), n("198.51.100.1", 11.0)];
        assert_eq!(spread_head(&mut p, &|_| false, 4, &ms), 1);
        assert_eq!(ips(&p), ["192.0.2.1", "198.51.100.1", "192.0.2.2"]);
        // B1 判慢的不換上來
        let mut slow = n("198.51.100.1", 5.0);
        slow.slow = Some(true);
        let mut p = vec![n("192.0.2.1", 3.0), n("192.0.2.2", 4.0), slow];
        assert_eq!(spread_head(&mut p, &|_| false, 4, &ms), 0);
    }

    #[test]
    fn spread_head_noop_when_already_distinct() {
        let mut p = vec![n("192.0.2.1", 3.0), n("198.51.100.1", 4.0), n("192.0.2.2", 5.0)];
        let before = p.clone();
        assert_eq!(spread_head(&mut p, &|_| false, 2, &ms), 0);
        assert_eq!(p, before);
        // 只動前 n 個位置：第 3 個同網段，但 n = 2
        let mut p = vec![
            n("192.0.2.1", 3.0),
            n("198.51.100.1", 4.0),
            n("192.0.2.2", 5.0),
            n("198.51.100.2", 5.0),
        ];
        let before = p.clone();
        spread_head(&mut p, &|_| false, 2, &ms);
        assert_eq!(p, before);
        assert_eq!(spread_head(&mut [], &|_| false, 4, &ms), 0);
    }

    #[test]
    fn spread_head_skips_bad_and_held() {
        // 壞的、暫緩的不當候選，也不佔位置
        let skip: HashMap<IpAddr, ()> = [("198.51.100.1".parse().unwrap(), ())].into_iter().collect();
        let mut p = vec![
            n("192.0.2.1", 3.0),
            n("192.0.2.2", 4.0),
            n("198.51.100.1", 4.5),
            n("198.51.100.2", 5.0),
        ];
        assert_eq!(spread_head(&mut p, &|x| skip.contains_key(&x.ip), 4, &ms), 1);
        assert_eq!(ips(&p), ["192.0.2.1", "198.51.100.2", "198.51.100.1", "192.0.2.2"]);
        assert_eq!(p[2].ip.to_string(), "198.51.100.1", "跳過的節點留在原本的位置");
    }
}
