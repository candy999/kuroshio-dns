//! CDN 網域資料庫（對齊 2.x `lib/cdn/cdn-db.js`）：蒐集各 CDN 的網域、驗證結果、ECS 突破結果、
//! 跨 CDN 結果、手動策略，以及節點池工作用的候選 IP（harvest）。
//!
//! 每筆紀錄保持精簡：常見字串（CDN 名稱、判定）共用、選填的子物件放在 `Box` 裡，沒有就只佔一個指標。
//! 筆數上限 `cdn.maxEntries`（安全上限，不分機器；記憶體由記憶體控制把冷資料移到磁碟），超過時刪掉最久沒出現的（手動設定策略的不刪）。

use crate::util::{
    self, de_arc, de_ips, de_opt_arc, de_opt_bool, de_opt_ip, de_opt_ips, de_opt_string, de_opt_u32, de_opt_u64, de_u32, de_u64, now_ms,
    ser_arc, ser_opt_arc, Extra, Field, Num,
};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

/// 舊版（分片以前）的單一檔案：讀得到就搬進分片，搬完刪掉；備份檔裡也用這個名字代表整個資料庫
pub const FILE: &str = "cdn-domains.json";
/// 分片目錄（規格 05 第 5.3 節）：網域依名稱的雜湊分到 N 個檔，只重寫有變動的分片
pub const SHARD_DIR: &str = "cdn/domains";
/// 分片清單：記錄 N（一般 JSON、很少變）
pub const MANIFEST: &str = "cdn/domains/manifest.json";
pub const MANIFEST_FORMAT: &str = "kuroshio-cdn-domains";
/// 每個分片壓縮後的目標大小（上限筆數時）：64–128 KB，大約一兩個 Flash 抹除區塊
pub const SHARD_TARGET_BYTES: usize = 128 * 1024;
/// 每筆網域壓縮後約幾 bytes（實測，見規格 05 第 5.5 節）
pub const COMPRESSED_BYTES_PER_ENTRY: usize = 115;
/// 分片數上限
pub const MAX_SHARDS: usize = 256;

// ---- 磁碟預算（3.5.0 C5，規格 05 第 5.7 節）----
// 小 Flash 上分片數還是照 `cdn.maxEntries` 算（改分片數會重寫全部分片），每片的筆數很少，每個檔固定的開銷不能忽略。
// `bench_persist`（`BENCH_SHARDS=256`）實測 256 片：5,000 筆 0.84 MB、10,000 筆 1.50 MB、20,000 筆 2.75 MB、
// 40,000 筆 5.21 MB ≈ 每片 1.1 KB ＋ 每筆 123 bytes。

/// 磁碟預算換算筆數：每個分片檔固定的開銷（bytes）
pub const BUDGET_SHARD_OVERHEAD: u64 = 1100;
/// 磁碟預算換算筆數：小分片裡每筆壓縮後約幾 bytes
pub const BUDGET_BYTES_PER_ENTRY: u64 = 125;
/// 磁碟預算的下限（bytes）：再小就不照預算了（算錯也不會把資料刪光）
pub const BUDGET_MIN_BYTES: u64 = 512 * 1024;
/// 磁碟預算換算出來的筆數下限
pub const BUDGET_MIN_ENTRIES: usize = 2000;
/// 超過預算這個比例（110%）才為了淘汰主動重寫沒有其他變動的分片；以下只順便整理本來就要寫的分片
pub const BUDGET_SWEEP_PERCENT: usize = 110;
/// 淘汰到每片額度的這個比例（90%）：留一點空間，不會每新增一筆就淘汰一次
pub const BUDGET_KEEP_PERCENT: usize = 90;
/// 最近這段時間出現過的網域排在最後才淘汰（正在用；也讓剛出現的網域有機會被問第二次、被驗證）
pub const BUDGET_RECENT_MS: u64 = 24 * 3600 * 1000;
/// 驗證失敗的網域超過這麼久沒再出現就優先淘汰
pub const BUDGET_FAILED_STALE_MS: u64 = 7 * 24 * 3600 * 1000;
/// 驗證成功過的網域，這段時間內出現過的排在後面才淘汰
pub const BUDGET_VERIFIED_FRESH_MS: u64 = 30 * 24 * 3600 * 1000;

/// 磁碟預算（bytes）在 `shards` 個分片下大約放得下幾筆；`None` = 不限
pub fn budget_entries(budget_bytes: Option<u64>, shards: usize) -> Option<usize> {
    let b = budget_bytes?.max(BUDGET_MIN_BYTES);
    let n = b.saturating_sub(shards as u64 * BUDGET_SHARD_OVERHEAD) / BUDGET_BYTES_PER_ENTRY;
    Some((n.min(usize::MAX as u64) as usize).max(BUDGET_MIN_ENTRIES))
}

/// 估計 `entries` 筆在 `shards` 個分片下佔多少磁碟（bytes；狀態頁用）
pub fn budget_disk_estimate(entries: usize, shards: usize) -> u64 {
    if entries == 0 {
        return 0;
    }
    shards as u64 * BUDGET_SHARD_OVERHEAD + entries as u64 * BUDGET_BYTES_PER_ENTRY
}

/// 一輪磁碟預算淘汰的計畫（[`Db::budget_plan`]）
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BudgetPlan {
    /// 這一輪要整理的分片：（編號，留幾筆）
    pub shards: Vec<(usize, usize)>,
    /// 其中為了淘汰主動重寫的（本來沒有重要變動）
    pub forced: usize,
    /// 目前的總筆數（記憶體裡的＋移出記憶體的）與預算換算的筆數
    pub total: usize,
    pub limit: usize,
    /// 這一輪剛開始主動重寫（寫日誌用）
    pub sweep_started: bool,
}

// ------------------------------------------------------------ 多來源 CDN 與第一層 CNAME（3.5.0 B3）

/// 第一層 CNAME 的鍵最長幾個位元組（超過就退到比較短的一層，再超過就不記）
pub const C1_MAX: usize = 64;
/// 除了目前的鍵以外，還記幾個「最近看過的鍵」（網站自己在幾個第一層之間輪流時，不算變了）
pub const C1_SEEN_MAX: usize = 3;
/// 新的鍵要連續看到幾次、而且從第一次看到算起至少隔多久，才算「變了」
/// （`apply()` 連快取命中都會走，同一份快取的答案會重複出現，所以一定要看時間）
pub const C1_CONFIRM_HITS: u8 = 3;
pub const C1_CONFIRM_MS: u64 = 10 * 60 * 1000;
/// 「最近」：業者或第一層的鍵在這段時間內看過
pub const SRC_WINDOW_MS: u64 = 24 * 3600 * 1000;
/// 同一個網域兩次「失效」（清掉跨 CDN、ECS、最佳策略）或「替新的業者開一格」至少隔多久。
/// 這是防風暴的上限：不管網站怎麼輪流，每個網域每 6 小時最多多一次重新驗證
pub const SRC_GAP_MS: u64 = 6 * 3600 * 1000;
/// 多來源的標記在多久沒有再看到兩家輪流之後取消
pub const MULTI_KEEP_MS: u64 = 7 * 24 * 3600 * 1000;

/// 第一層 CNAME 的鍵：取目標名稱的最後三段（可註冊網域再往前一層，跟 `providers.rs` 的 `last2()` 同一套切法）。
/// 前面每次查詢都可能不同的標籤（節點、地區、雜湊）不算進去。不配置記憶體；比對時不分大小寫
pub fn c1_key(target: &str) -> &str {
    let t = target.trim_end_matches('.');
    let mut cut = [0usize; 3]; // 最後三個「.」之後的位置
    let mut n = 0;
    for (i, b) in t.bytes().enumerate().rev() {
        if b == b'.' {
            cut[n] = i + 1;
            n += 1;
            if n == 3 {
                break;
            }
        }
    }
    // n = 看到幾個點：不到 3 個點就是整個名稱（最多三段）
    let last3 = if n == 3 { &t[cut[2]..] } else { t };
    if last3.len() <= C1_MAX {
        return last3;
    }
    let last2 = if n >= 2 { &t[cut[1]..] } else { t };
    if last2.len() <= C1_MAX {
        last2
    } else {
        ""
    }
}

/// 另一家業者的那一格（多來源網域）：跟 `Domain` 上「跟業者有關」的欄位一一對應，回答換成這一家時整格對調
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Alt {
    #[serde(default, skip_serializing_if = "Field::is_absent", with = "field_arc")]
    pub provider: Field<Arc<str>>,
    #[serde(default, skip_serializing_if = "Field::is_absent", with = "field_arc")]
    pub via: Field<Arc<str>>,
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub cname: Field<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "ser_opt_arc",
        deserialize_with = "de_opt_arc"
    )]
    pub c1: Option<Arc<str>>,
    #[serde(default, deserialize_with = "de_ips_box")]
    pub ips4: Box<[IpAddr]>,
    #[serde(default, deserialize_with = "de_ips_box")]
    pub ips6: Box<[IpAddr]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v4: Option<Box<Verdict>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v6: Option<Box<Verdict>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<Box<Base>>,
    /// 這一家最後一次回答的時間
    #[serde(default, deserialize_with = "de_u64")]
    pub last: u64,
}

/// 來源的變動紀錄（只有「看過第二家業者」或「第一層 CNAME 換過」的網域才有；其他網域只佔一個指標）
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Src {
    /// 最近看過的其他第一層鍵（鍵，最後看到的時間），最多 [`C1_SEEN_MAX`] 個
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub seen: Vec<(String, u64)>,
    /// 還沒確認的新鍵：連續看到幾次、第一次看到的時間
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pend: Option<String>,
    #[serde(default, skip_serializing_if = "is_zero_u8")]
    pub pend_n: u8,
    #[serde(default, skip_serializing_if = "is_zero", deserialize_with = "de_u64")]
    pub pend_at: u64,
    /// 最後一次看到「兩家輪流」的時間（0 = 不是多來源）
    #[serde(default, skip_serializing_if = "is_zero", deserialize_with = "de_u64")]
    pub multi_at: u64,
    /// 最後一次失效（清掉跨 CDN、ECS、最佳策略）的時間
    #[serde(default, skip_serializing_if = "is_zero", deserialize_with = "de_u64")]
    pub inval_at: u64,
    /// 最後一次替新的業者開一格的時間
    #[serde(default, skip_serializing_if = "is_zero", deserialize_with = "de_u64")]
    pub slot_at: u64,
    /// 沒有格子可以放的業者（第三家，或 6 小時內的第二次換家）：業者、最後看到的時間
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub other: Option<(String, u64)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alt: Option<Box<Alt>>,
    #[serde(flatten)]
    pub extra: Extra,
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}
fn is_zero_u8(v: &u8) -> bool {
    *v == 0
}

impl Src {
    fn is_empty(&self) -> bool {
        self.seen.is_empty()
            && self.pend.is_none()
            && self.multi_at == 0
            && self.inval_at == 0
            && self.slot_at == 0
            && self.other.is_none()
            && self.alt.is_none()
            && self.extra.is_empty()
    }

    /// 多來源：7 天內看過兩家輪流回答
    pub fn multi(&self, now: u64) -> bool {
        self.multi_at != 0 && now.abs_diff(self.multi_at) < MULTI_KEEP_MS
    }

    fn approx_bytes(&self) -> usize {
        use std::mem::size_of;
        size_of::<Src>()
            + self.seen.iter().map(|s| s.0.len() + size_of::<(String, u64)>()).sum::<usize>()
            + self.pend.as_ref().map_or(0, |p| p.len())
            + self.other.as_ref().map_or(0, |o| o.0.len())
            + self.alt.as_ref().map_or(0, |a| {
                size_of::<Alt>()
                    + a.cname.val().map_or(0, |c| c.len())
                    + (a.ips4.len() + a.ips6.len()) * size_of::<IpAddr>()
                    + if a.v4.is_some() { size_of::<Verdict>() } else { 0 }
                    + if a.v6.is_some() { size_of::<Verdict>() } else { 0 }
                    + if a.base.is_some() { size_of::<Base>() } else { 0 }
            })
    }
}

/// `touch_at()` 看完這次回答的來源之後的結論
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Touch {
    /// 這次回答的業者沒有格子可以放（多來源的第三家，或太快又換一家）：照原始答案回，不驗證、不改寫
    pub held: bool,
    /// 多來源、或剛換業者還沒定下來：不做跨 CDN（網站自己在多家之間選）
    pub no_cross: bool,
    /// 這次清掉了跨 CDN、ECS、最佳策略（給測試與統計看）
    pub invalidated: bool,
    /// 這次替新的業者開了一格
    pub new_slot: bool,
}

pub const HARVEST_FILE: &str = "cdn/harvest.json";
/// 每家 CDN 每個家族最多收集幾個候選 IP（同 2.x）
pub const HARVEST_MAX: usize = 3000;

/// 手動策略
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Policy {
    #[default]
    Auto,
    Always,
    Never,
}

impl Policy {
    pub fn parse(s: &str) -> Option<Policy> {
        match s {
            "auto" => Some(Policy::Auto),
            "always" => Some(Policy::Always),
            "never" => Some(Policy::Never),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Policy::Auto => "auto",
            Policy::Always => "always",
            Policy::Never => "never",
        }
    }
}

impl Serialize for Policy {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Policy {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Value::deserialize(d)?.as_str().and_then(Policy::parse).unwrap_or_default())
    }
}

/// 某個網站最後成功的改寫方式（規格 06 第 3.5 節；JSON 欄位 `best`）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    Alias,
    Ecs,
    Cross,
}

impl Strategy {
    pub fn as_str(self) -> &'static str {
        match self {
            Strategy::Alias => "alias",
            Strategy::Ecs => "ecs",
            Strategy::Cross => "cross",
        }
    }
    pub fn parse(s: &str) -> Option<Strategy> {
        match s {
            "alias" => Some(Strategy::Alias),
            "ecs" => Some(Strategy::Ecs),
            "cross" => Some(Strategy::Cross),
            _ => None,
        }
    }
}

impl Serialize for Strategy {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

fn de_strategy<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Strategy>, D::Error> {
    Ok(Value::deserialize(d)?.as_str().and_then(Strategy::parse))
}

/// 換到台灣節點的驗證結果（`v4` / `v6`）
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Verdict {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "ser_opt_arc",
        deserialize_with = "de_opt_arc"
    )]
    pub verdict: Option<Arc<str>>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_u32")]
    pub fails: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_u64")]
    pub until: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_u32")]
    pub algo: Option<u32>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "ser_opt_arc",
        deserialize_with = "de_opt_arc"
    )]
    pub pop: Option<Arc<str>>,
    #[serde(default, skip_serializing_if = "Num::is_absent")]
    pub ms: Num,
    #[serde(default, skip_serializing_if = "Num::is_absent")]
    pub status: Num,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_ip")]
    pub ip: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_ips")]
    pub ips: Option<Vec<IpAddr>>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_u32")]
    pub tried: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_bool")]
    pub http: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_string")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_u64")]
    pub at: Option<u64>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl Verdict {
    pub fn is(&self, v: &str) -> bool {
        self.verdict.as_deref() == Some(v)
    }
    pub fn valid(&self, now: u64) -> bool {
        self.until.map(|u| u > now).unwrap_or(false)
    }
}

/// 原始 IP 的基準連線結果（`base`）
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Base {
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_ip")]
    pub ip: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_bool")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Num::is_absent")]
    pub status: Num,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "ser_opt_arc",
        deserialize_with = "de_opt_arc"
    )]
    pub pop: Option<Arc<str>>,
    #[serde(default, skip_serializing_if = "Num::is_absent")]
    pub ms: Num,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_string")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_u64")]
    pub at: Option<u64>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// ECS 突破結果（`ecs`）
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ecs {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "ser_opt_arc",
        deserialize_with = "de_opt_arc"
    )]
    pub verdict: Option<Arc<str>>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_string")]
    pub reason: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "ser_opt_arc",
        deserialize_with = "de_opt_arc"
    )]
    pub subnet: Option<Arc<str>>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_ips")]
    pub ips4: Option<Vec<IpAddr>>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_ips")]
    pub ips6: Option<Vec<IpAddr>>,
    #[serde(default, skip_serializing_if = "Num::is_absent")]
    pub gain_ms: Num,
    #[serde(default, skip_serializing_if = "Num::is_absent")]
    pub orig_ms: Num,
    #[serde(default, skip_serializing_if = "Num::is_absent")]
    pub ecs_ms: Num,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_u64")]
    pub until: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_u64")]
    pub at: Option<u64>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl Ecs {
    pub fn is(&self, v: &str) -> bool {
        self.verdict.as_deref() == Some(v)
    }
}

/// 跨 CDN 探索時每一家的結果
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Tried {
    #[serde(serialize_with = "ser_arc", deserialize_with = "de_arc")]
    pub to: Arc<str>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_string")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_bool")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Num::is_absent")]
    pub ms: Num,
    /// 實測分數（3.5.0 B4）：一個請求的連線＋握手＋TTFB（毫秒），通過的節點裡最好的
    #[serde(default, skip_serializing_if = "Num::is_absent")]
    pub score: Num,
    #[serde(flatten)]
    pub extra: Extra,
}

/// 跨 CDN 探索結果（`cross4`）
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cross {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "ser_opt_arc",
        deserialize_with = "de_opt_arc"
    )]
    pub verdict: Option<Arc<str>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "ser_opt_arc",
        deserialize_with = "de_opt_arc"
    )]
    pub from: Option<Arc<str>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "ser_opt_arc",
        deserialize_with = "de_opt_arc"
    )]
    pub to: Option<Arc<str>>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_ips")]
    pub ips: Option<Vec<IpAddr>>,
    #[serde(default, skip_serializing_if = "Num::is_absent")]
    pub ms: Num,
    #[serde(default, skip_serializing_if = "Num::is_absent")]
    pub orig_ms: Num,
    /// 實測分數（3.5.0 B4）：換過去那一家／原站的握手時間（3.5.0 F13 起是「連線＋TLS 握手」，不含 TTFB；
    /// 之前存的是「連線＋握手＋TTFB」，下一次每日複驗時被新的值蓋掉）（毫秒；各取兩次裡比較小的）。
    /// 判定失敗時兩個都有＝「連線比較近，但握手沒有比較快」
    #[serde(default, skip_serializing_if = "Num::is_absent")]
    pub score: Num,
    #[serde(default, skip_serializing_if = "Num::is_absent")]
    pub orig_score: Num,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_ip")]
    pub orig_ip: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub also: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tried: Option<Vec<Tried>>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_u64")]
    pub until: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_u64")]
    pub recheck_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_string")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_u64")]
    pub at: Option<u64>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl Cross {
    pub fn is(&self, v: &str) -> bool {
        self.verdict.as_deref() == Some(v)
    }
}

/// 一個 CDN 網域
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Domain {
    /// 跟資料庫的鍵共用同一份字串
    #[serde(serialize_with = "ser_arc", deserialize_with = "de_name")]
    pub name: Arc<str>,
    #[serde(default, skip_serializing_if = "Field::is_absent", with = "field_arc")]
    pub provider: Field<Arc<str>>,
    #[serde(default, skip_serializing_if = "Field::is_absent", with = "field_arc")]
    pub via: Field<Arc<str>>,
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub cname: Field<String>,
    #[serde(default, deserialize_with = "de_u64")]
    pub first_seen: u64,
    #[serde(default, deserialize_with = "de_u64")]
    pub last_seen: u64,
    #[serde(default, deserialize_with = "de_u32")]
    pub hits: u32,
    #[serde(default, deserialize_with = "de_ips_box")]
    pub ips4: Box<[IpAddr]>,
    #[serde(default, deserialize_with = "de_ips_box")]
    pub ips6: Box<[IpAddr]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<Policy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v4: Option<Box<Verdict>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v6: Option<Box<Verdict>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<Box<Base>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecs: Option<Box<Ecs>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cross4: Option<Box<Cross>>,
    /// 最後成功的改寫方式（3.0 新增；2.x 讀到會原封保留）
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_strategy")]
    pub best: Option<Strategy>,
    /// 第一層 CNAME 的鍵（3.5.0 B3；`c1_key()`）。沒有 CNAME、或舊資料還沒補上時沒有
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "ser_opt_arc",
        deserialize_with = "de_opt_arc"
    )]
    pub c1: Option<Arc<str>>,
    /// 來源的變動紀錄與另一家業者的那一格（3.5.0 B3）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src: Option<Box<Src>>,
    #[serde(flatten)]
    pub extra: Extra,
}

fn de_name<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Arc<str>, D::Error> {
    Ok(Arc::from(String::deserialize(d)?.as_str()))
}

fn de_ips_box<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Box<[IpAddr]>, D::Error> {
    Ok(de_ips(d)?.into_boxed_slice())
}

mod field_arc {
    use super::*;
    pub fn serialize<S: serde::Serializer>(v: &Field<Arc<str>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Field::Val(a) => s.serialize_str(a),
            _ => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Field<Arc<str>>, D::Error> {
        Ok(match Value::deserialize(d)? {
            Value::Null => Field::Null,
            Value::String(s) => Field::Val(util::intern(&s)),
            other => Field::Val(util::intern(&other.to_string())),
        })
    }
}

impl Domain {
    pub fn provider(&self) -> Option<&str> {
        self.provider.val().map(|a| &**a)
    }
    pub fn verdict(&self, family: u8) -> Option<&Verdict> {
        if family == 6 {
            self.v6.as_deref()
        } else {
            self.v4.as_deref()
        }
    }
    pub fn policy(&self) -> Policy {
        self.policy.unwrap_or_default()
    }
    /// 複驗用的原始 IP：v4 用基準 IP 或第一個 A，v6 用第一個 AAAA
    pub fn orig_ip(&self, family: u8) -> Option<IpAddr> {
        if family == 4 {
            self.base.as_ref().and_then(|b| b.ip).or_else(|| self.ips4.first().copied())
        } else {
            self.ips6.first().copied()
        }
    }

    /// 估計佔用的記憶體（bytes；含雜湊表的一格）。只用來估算記憶體控制釋出多少，不必精確
    pub fn approx_bytes(&self) -> usize {
        use std::mem::size_of;
        let boxed = |b: bool, n: usize| if b { n } else { 0 };
        size_of::<Domain>()
            + size_of::<Arc<str>>()
            + 16
            + self.name.len()
            + self.cname.val().map_or(0, |c| c.len())
            + (self.ips4.len() + self.ips6.len()) * size_of::<IpAddr>()
            + boxed(self.v4.is_some(), size_of::<Verdict>())
            + boxed(self.v6.is_some(), size_of::<Verdict>())
            + boxed(self.base.is_some(), size_of::<Base>())
            + boxed(self.ecs.is_some(), size_of::<Ecs>())
            + boxed(self.cross4.is_some(), size_of::<Cross>())
            + self.src.as_ref().map_or(0, |s| s.approx_bytes())
    }

    /// 多來源（7 天內看過兩家輪流回答）
    pub fn multi(&self, now: u64) -> bool {
        self.src.as_ref().is_some_and(|s| s.multi(now))
    }

    /// 不做跨 CDN：多來源，或剛看到第二家、還沒定下來是「換家」還是「輪流」
    pub fn no_cross(&self, now: u64) -> bool {
        self.src.as_ref().is_some_and(|s| s.alt.is_some() || s.multi(now))
    }

    /// 最近看到的業者（業者，最後看到的時間，有沒有自己的一格），最多 3 個：目前這一家、另一格、沒有格子的
    pub fn provs(&self) -> Vec<(String, u64, bool)> {
        let mut out = Vec::new();
        if let Some(p) = self.provider() {
            out.push((p.to_string(), self.last_seen, true));
        }
        if let Some(s) = &self.src {
            if let Some(a) = &s.alt {
                if let Some(p) = a.provider.val() {
                    out.push((p.to_string(), a.last, true));
                }
            }
            if let Some((p, t)) = &s.other {
                out.push((p.clone(), *t, false));
            }
        }
        out
    }

    /// 對調目前這一格與另一格（只換「跟業者有關」的欄位；`last` 由呼叫端處理）
    fn swap_slot(&mut self) {
        let Some(a) = self.src.as_mut().and_then(|s| s.alt.as_deref_mut()) else {
            return;
        };
        std::mem::swap(&mut self.provider, &mut a.provider);
        std::mem::swap(&mut self.via, &mut a.via);
        std::mem::swap(&mut self.cname, &mut a.cname);
        std::mem::swap(&mut self.c1, &mut a.c1);
        std::mem::swap(&mut self.ips4, &mut a.ips4);
        std::mem::swap(&mut self.ips6, &mut a.ips6);
        std::mem::swap(&mut self.v4, &mut a.v4);
        std::mem::swap(&mut self.v6, &mut a.v6);
        std::mem::swap(&mut self.base, &mut a.base);
    }

    /// 清掉不分業者的結果（跨 CDN、ECS、最佳策略）。回傳有沒有東西被清掉
    fn invalidate_shared(&mut self) -> bool {
        let had = self.cross4.is_some() || self.ecs.is_some() || self.best.is_some();
        self.cross4 = None;
        self.ecs = None;
        self.best = None;
        had
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileFmt {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    saved_at: Option<String>,
    #[serde(default)]
    domains: Vec<Domain>,
    #[serde(flatten)]
    extra: Extra,
}

/// 每家 CDN 收集到的候選 IP（IP → 第一次看到的時間），依加入順序淘汰
#[derive(Debug, Clone, Default)]
pub struct HarvestSet {
    pub v4: IndexMap<IpAddr, u64>,
    pub v6: IndexMap<IpAddr, u64>,
    pub extra: Extra,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct HarvestFmt {
    #[serde(default)]
    v4: IndexMap<String, Value>,
    #[serde(default)]
    v6: IndexMap<String, Value>,
    #[serde(flatten)]
    extra: Extra,
}

/// 各家 CDN 的統計摘要（`/api/cdn/summary`）
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub provider: String,
    pub domains: u32,
    pub hits: u64,
    pub base_pop_abroad: u32,
    pub base_pop_tw: u32,
    pub v4ok: u32,
    pub v4fail: u32,
    pub v6ok: u32,
    pub v6fail: u32,
    pub ecs_gain: u32,
    pub pops: IndexMap<String, u32>,
}

/// `query()` 的條件
#[derive(Debug, Clone, Default)]
pub struct Query {
    pub provider: Option<String>,
    pub verdict: Option<String>,
    pub limit: Option<usize>,
    /// 依哪個欄位遞減排序：hits（預設）、lastSeen、firstSeen
    pub sort: Option<String>,
    /// 網域名稱包含這段文字（小寫）
    pub search: Option<String>,
    /// 排序後跳過前幾筆（分頁）
    pub offset: usize,
    /// 只要試過跨 CDN 備援的網域（`cross4` 有結果、不是 none）
    pub cross: bool,
}

/// 分段寫快照時要寫的網域：（查詢次數，名稱）
pub type DumpKeys = Vec<(u32, Arc<str>)>;

/// 分片的檔名（相對於狀態目錄；寫入器會加上 `.zst`）：`cdn/domains/16-003.json`。
/// 檔名帶著 N：分片數改變時新舊兩組檔名不會互相蓋掉，新的一組寫完（清單也更新）才刪舊的
pub fn shard_file(n: usize, i: usize) -> String {
    format!("{SHARD_DIR}/{n}-{i:03}.json")
}

/// 網域名稱的 32 位元雜湊：FNV-1a（各平台、各版本都一樣，不能用 std 的雜湊）。低位元就是分片編號
pub fn name_hash(name: &str) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in name.as_bytes() {
        h ^= *b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

/// 網域屬於哪個分片
pub fn shard_of(name: &str, n: usize) -> usize {
    (name_hash(name) as usize) & (n.max(1) - 1)
}

/// 逐筆讀分片檔裡的網域（不把整片解析成一個大陣列：一次只有一筆在記憶體裡）。
/// 記憶體控制用：冷資料從磁碟找回單一網域、寫分片時把留在磁碟上的冷資料接回去
pub fn scan_shard(bytes: &[u8], f: &mut dyn FnMut(Domain)) -> Result<(), serde_json::Error> {
    use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
    struct Top<'a>(&'a mut dyn FnMut(Domain));
    struct List<'a>(&'a mut dyn FnMut(Domain));
    impl<'de> Visitor<'de> for Top<'_> {
        type Value = ();
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("分片物件")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<(), A::Error> {
            while let Some(k) = m.next_key::<String>()? {
                if k == "domains" {
                    m.next_value_seed(List(&mut *self.0))?;
                } else {
                    m.next_value::<IgnoredAny>()?;
                }
            }
            Ok(())
        }
    }
    impl<'de> DeserializeSeed<'de> for List<'_> {
        type Value = ();
        fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
            d.deserialize_seq(self)
        }
    }
    impl<'de> Visitor<'de> for List<'_> {
        type Value = ();
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("網域陣列")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<(), A::Error> {
            while let Some(d) = s.next_element::<Domain>()? {
                (self.0)(d);
            }
            Ok(())
        }
    }
    let mut de = serde_json::Deserializer::from_slice(bytes);
    serde::Deserializer::deserialize_map(&mut de, Top(f))?;
    de.end()
}

/// 依筆數上限決定分片數（2 的次方）：上限筆數時每片壓縮後約 64–128 KB
pub fn shards_for(max_entries: usize) -> usize {
    let total = max_entries.saturating_mul(COMPRESSED_BYTES_PER_ENTRY);
    total.div_ceil(SHARD_TARGET_BYTES).clamp(1, MAX_SHARDS).next_power_of_two()
}

/// 整個網域資料庫（舊版單一檔案、分片）組成 2.x 格式的單一 JSON（備份匯出、匯入合併時用）；什麼都沒有時 None
/// 內容原樣保留（不經過 `Domain` 轉換，不會多出預設欄位）；選哪些分片的規則同 `Db::load_store`
pub fn read_store_json(state_dir: &std::path::Path) -> Option<Vec<u8>> {
    let read = |rel: &str| crate::statefile::read(&state_dir.join(rel));
    let legacy_bytes = read(FILE);
    let mut top: serde_json::Map<String, Value> = legacy_bytes
        .as_deref()
        .and_then(|b| serde_json::from_slice::<Value>(b).ok())
        .and_then(|v| match v {
            Value::Object(m) => Some(m),
            _ => None,
        })
        .unwrap_or_default();
    let legacy = !top.is_empty();
    let manifest = read(MANIFEST)
        .and_then(|b| serde_json::from_slice::<ManifestFmt>(&b).ok())
        .filter(|m| (1..=MAX_SHARDS).contains(&m.shards) && m.shards.is_power_of_two());
    let n = match &manifest {
        Some(m) => Some(m.shards),
        None if !legacy => {
            let names: Vec<String> = std::fs::read_dir(state_dir.join(SHARD_DIR))
                .map(|rd| rd.flatten().filter_map(|e| e.file_name().into_string().ok()).collect())
                .unwrap_or_default();
            rescue_shards(&names)
        }
        None => None,
    };
    let Some(n) = n else {
        // 只有舊版單一檔案（或什麼都沒有）：原樣
        return legacy_bytes.filter(|_| legacy);
    };
    let mut list: Vec<Value> = match top.remove("domains") {
        Some(Value::Array(a)) => a,
        _ => Vec::new(),
    };
    if let Some(m) = manifest {
        if !legacy {
            for (k, v) in m.extra.0.map(|b| *b).unwrap_or_default() {
                top.insert(k, v);
            }
        }
    }
    for i in 0..n {
        let Some(Ok(Value::Object(mut s))) = read(&shard_file(n, i)).map(|b| serde_json::from_slice::<Value>(&b)) else {
            continue;
        };
        if legacy {
            list.retain(|d| d.get("name").and_then(Value::as_str).map_or(true, |k| shard_of(k, n) != i));
        }
        if let Some(Value::Array(a)) = s.remove("domains") {
            list.extend(a);
        }
    }
    top.insert("domains".into(), Value::Array(list));
    serde_json::to_vec(&top).ok()
}

/// 沒有分片清單時：目錄裡檔案最多的一組分片
fn rescue_shards(names: &[String]) -> Option<usize> {
    let mut count: HashMap<usize, usize> = HashMap::new();
    for f in names {
        let f = f.trim_end_matches(".zst");
        if let Some((a, _)) = f.strip_suffix(".json").and_then(|x| x.split_once('-')) {
            if let Ok(n) = a.parse::<usize>() {
                if (1..=MAX_SHARDS).contains(&n) && n.is_power_of_two() {
                    *count.entry(n).or_default() += 1;
                }
            }
        }
    }
    count.into_iter().max_by_key(|(n, c)| (*c, *n)).map(|(n, _)| n)
}

/// 備份匯入寫出舊版單一檔案之前呼叫：拿掉分片清單與分片，下次啟動時從單一檔案重新搬進分片
/// （先刪清單：中途斷電時，啟動只會看到單一檔案，或還沒刪完的分片與單一檔案——以單一檔案為準）
pub fn retire_shards(state_dir: &std::path::Path) {
    let _ = std::fs::remove_file(state_dir.join(MANIFEST));
}

/// 單一檔案寫好之後：刪掉舊的分片
pub fn remove_shards(state_dir: &std::path::Path) {
    let _ = std::fs::remove_dir_all(state_dir.join(SHARD_DIR));
}

/// 分片的變動程度
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Mark {
    #[default]
    Clean,
    /// 只有計數（查詢次數、最後出現時間）：不單獨觸發寫入，等這片因為別的原因要寫、或到了最久未存的上限
    Counters,
    /// 驗證結果、IP、策略、ECS、跨 CDN、新增 / 刪除網域
    Important,
}

/// 分片清單的內容
#[derive(Debug, Default, Serialize, Deserialize)]
struct ManifestFmt {
    #[serde(default)]
    format: String,
    #[serde(default)]
    version: u32,
    #[serde(default)]
    shards: usize,
    /// 舊版單一檔案最上層不認識的欄位（原樣保留）
    #[serde(flatten)]
    extra: Extra,
}

/// 載入分片的結果
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StoreLoad {
    /// 有讀到舊版的單一檔案
    pub legacy: bool,
    /// 磁碟上的分片數（沒有分片清單、也找不到分片時 None）
    pub shards_on_disk: Option<usize>,
    /// 有沒有分片清單
    pub manifest: bool,
    /// 讀不到 / 壞掉的分片
    pub bad_shards: Vec<usize>,
}

pub struct Db {
    pub domains: HashMap<Arc<str>, Domain>,
    pub harvest: IndexMap<String, HarvestSet>,
    pub max_entries: usize,
    saved_at: Option<String>,
    extra: Extra,
    /// 整個資料庫都要重寫（種子帶入、舊版搬家、分片數改變）
    pub dirty: bool,
    pub harvest_dirty: bool,
    /// 分片數（2 的次方）
    pub shards: usize,
    /// 每個分片的變動程度
    marks: Vec<Mark>,
    /// 要寫分片清單：寫完之後要刪掉的舊檔（相對路徑）
    pub manifest_pending: Option<Vec<String>>,
    /// 記憶體控制暫時移出記憶體的冷資料（規格 09）：只留名稱的 32 位元雜湊（排序、可重複），內容還在磁碟的分片裡。
    /// 查到這些網域時從分片讀回來；寫分片時把它們從舊檔接回去，所以磁碟上不會少
    evicted: Vec<u32>,
    /// 磁碟預算：正在一輪一輪主動重寫超過額度的分片（超過 110% 開始，回到預算以內結束）
    budget_sweep: bool,
    /// 尊重多來源 CDN、第一層 CNAME 變了就失效（3.5.0 B3，`cdn.multiCdn`）。關掉時同 3.4.x：業者欄位直接改寫
    pub multi_cdn: bool,
}

/// `switch_provider()` 的結果
enum Switch {
    Swapped,
    NewSlot { invalidated: bool },
    Held,
}

/// 冷熱分組的年齡邊界（毫秒，由新到舊；3.5.1 G1）：最後出現到現在的時間落在哪一格。
/// 第 0 格（2 分鐘內）永遠不移出：剛查過、剛驗證完的網域很可能馬上又用到
pub const COLD_AGE_EDGES_MS: [u64; 15] = [
    2 * 60_000,
    5 * 60_000,
    10 * 60_000,
    20 * 60_000,
    30 * 60_000,
    3_600_000,
    2 * 3_600_000,
    4 * 3_600_000,
    8 * 3_600_000,
    24 * 3_600_000,
    2 * 24 * 3_600_000,
    7 * 24 * 3_600_000,
    14 * 24 * 3_600_000,
    30 * 24 * 3_600_000,
    90 * 24 * 3_600_000,
];

/// 年齡落在 [`COLD_AGE_EDGES_MS`] 的第幾格（0 = 2 分鐘內，15 = 90 天以上）
pub fn age_bucket(age_ms: u64) -> usize {
    COLD_AGE_EDGES_MS.iter().take_while(|e| age_ms >= **e).count()
}

/// 讀回冷資料時可以直接忘掉的（3.5.1 G1）：只問過一次、沒有任何驗證、ECS、跨 CDN 結果、自動策略。
/// 忘掉不會損失任何東西（沒有結果可以重用；之後再出現就當新網域，照小機器減量的規則問第二次才驗證），
/// 不讀回才不會在記憶體剛恢復時又被大量一次性網域塞滿、來回讓出又恢復
pub fn forgettable(d: &Domain) -> bool {
    d.hits <= 1 && d.policy() == Policy::Auto && !has_learning(d)
}

/// 有學習資料：驗證（v4／v6）、ECS、跨 CDN 的結果，或最後成功的改寫方式（3.5.1 G1）。
/// 記憶體吃緊時這種網域最後才移出記憶體；讀回時一定讀回、不忘掉
pub fn has_learning(d: &Domain) -> bool {
    d.v4.is_some() || d.v6.is_some() || d.ecs.is_some() || d.cross4.is_some() || d.best.is_some()
}

/// 冷資料移出記憶體的結果
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Evicted {
    pub entries: usize,
    /// 估計釋出的記憶體（bytes）
    pub bytes: usize,
}

impl Db {
    pub fn new(max_entries: usize) -> Db {
        Db {
            domains: HashMap::new(),
            harvest: IndexMap::new(),
            max_entries: max_entries.max(100),
            saved_at: None,
            extra: Extra::default(),
            dirty: false,
            harvest_dirty: false,
            shards: shards_for(max_entries.max(100)),
            marks: vec![Mark::Clean; shards_for(max_entries.max(100))],
            manifest_pending: None,
            evicted: Vec::new(),
            budget_sweep: false,
            multi_cdn: true,
        }
    }

    // ------------------------------------------------------------ 冷資料（記憶體控制，規格 09）

    /// 把冷資料移出記憶體（磁碟上的分片保留）：只動「已經寫進磁碟、之後沒有任何變動」的分片
    /// （`persisted(i)` = 快照寫入器裡沒有這片的待寫內容），而且只動最後出現時間早於 `cutoff_ms`、
    /// 自動策略的網域（手動設定的、最近用到的、剛改過的都不動）。
    /// 整個資料庫要重寫、分片清單還沒寫時一律不動（磁碟上的內容還不是最新的）
    pub fn evict_cold(&mut self, cutoff_ms: u64, persisted: &dyn Fn(usize) -> bool) -> Evicted {
        let Some(ok) = self.evictable_shards(persisted) else {
            return Evicted::default();
        };
        let n = self.shards;
        let cold: Vec<Arc<str>> = self
            .domains
            .values()
            .filter(|d| d.policy() == Policy::Auto && d.last_seen < cutoff_ms && ok[shard_of(&d.name, n)])
            .map(|d| d.name.clone())
            .collect();
        self.evict_names(cold)
    }

    /// 可以移出的分片（已經寫進磁碟、之後沒變動）；整個資料庫要重寫、分片清單還沒寫時是 None
    fn evictable_shards(&self, persisted: &dyn Fn(usize) -> bool) -> Option<Vec<bool>> {
        if self.dirty || self.manifest_pending.is_some() {
            return None;
        }
        Some((0..self.shards).map(|i| self.marks[i] == Mark::Clean && persisted(i)).collect())
    }

    /// 記憶體吃緊（3.5.1 G1）：**從最冷的開始**移出，估計釋出的量到 `target` bytes 就停（`usize::MAX` = 能移的全部）。
    ///
    /// 順序：先移沒有學習資料的（[`has_learning`]：沒有驗證、ECS、跨 CDN 結果），再移有的；
    /// 同一組裡最久沒出現的先（年齡分格 [`COLD_AGE_EDGES_MS`]）。有學習資料的網域最後才動，而且只是移出記憶體，磁碟上照樣保留、查到時讀回。
    /// 不動：最後出現在 `protect_ms` 毫秒以內的、手動策略的、`busy(名稱)`（正在排隊或正在做驗證、ECS、跨 CDN）、
    /// 有待寫內容的分片（同 [`Db::evict_cold`]）。
    ///
    /// 兩次掃描、不排序：第一次依（組，年齡格）累計估計用量，找出要移到哪一格；第二次只收那些名稱
    /// （小機器上不為了排序另外配置一份 20 萬筆的陣列）
    pub fn evict_coldest(
        &mut self,
        target: usize,
        protect_ms: u64,
        now: u64,
        busy: &dyn Fn(&str) -> bool,
        persisted: &dyn Fn(usize) -> bool,
    ) -> Evicted {
        let Some(ok) = self.evictable_shards(persisted) else {
            return Evicted::default();
        };
        let n = self.shards;
        const B: usize = COLD_AGE_EDGES_MS.len() + 1;
        let slot = |d: &Domain| -> Option<usize> {
            let age = now.saturating_sub(d.last_seen);
            if d.policy() != Policy::Auto || age < protect_ms || !ok[shard_of(&d.name, n)] || busy(&d.name) {
                return None;
            }
            // 冷的順序：沒有學習資料的在前（組 0），同一組裡年齡格大的（舊的）在前
            let group = usize::from(has_learning(d));
            Some(group * B + (B - 1 - age_bucket(age)))
        };
        let mut bytes = [0usize; 2 * B];
        for d in self.domains.values() {
            if let Some(k) = slot(d) {
                bytes[k] += d.approx_bytes();
            }
        }
        // 從最冷的那格往熱的累計，到 target 為止：那一格之前的全部移出，那一格移到補足為止
        let mut sum = 0usize;
        let mut last = None;
        for (k, b) in bytes.iter().enumerate() {
            if *b == 0 {
                continue;
            }
            last = Some(k);
            sum = sum.saturating_add(*b);
            if sum >= target {
                break;
            }
        }
        let Some(last) = last else {
            return Evicted::default();
        };
        let mut need_last = target.saturating_sub(sum - bytes[last]);
        let mut names = Vec::new();
        for d in self.domains.values() {
            let Some(k) = slot(d) else { continue };
            if k > last {
                continue;
            }
            if k == last {
                if need_last == 0 {
                    continue;
                }
                need_last = need_last.saturating_sub(d.approx_bytes());
            }
            names.push(d.name.clone());
        }
        self.evict_names(names)
    }

    fn evict_names(&mut self, cold: Vec<Arc<str>>) -> Evicted {
        let mut out = Evicted::default();
        for name in cold {
            if let Some(d) = self.domains.remove(&name) {
                out.entries += 1;
                out.bytes += d.approx_bytes();
                self.evicted.push(name_hash(&name));
            }
        }
        if out.entries > 0 {
            self.evicted.sort_unstable();
            self.evicted.shrink_to_fit();
            self.domains.shrink_to_fit();
        }
        out
    }

    /// 這個名稱可能在磁碟上（被移出記憶體）
    pub fn is_evicted(&self, name: &str) -> bool {
        !self.evicted.is_empty() && self.evicted.binary_search(&name_hash(name)).is_ok()
    }

    /// 名稱雜湊（[`name_hash`]）是 `h` 的網域可能在磁碟上（被移出記憶體）：記著名稱雜湊、不記名稱的呼叫端用
    /// （社群分享記著分享過哪些網域，3.5.1）
    pub fn is_evicted_hash(&self, h: u32) -> bool {
        !self.evicted.is_empty() && self.evicted.binary_search(&h).is_ok()
    }

    /// 移出記憶體的筆數
    pub fn evicted_count(&self) -> usize {
        self.evicted.len()
    }

    /// 有移出記憶體的網域的分片
    pub fn evicted_shards(&self) -> Vec<usize> {
        let n = self.shards;
        let mut v: Vec<usize> = self.evicted.iter().map(|h| (*h as usize) & (n - 1)).collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// 這個分片裡被移出的雜湊（寫分片時比對磁碟上的網域用；`n` 跟目前的分片數不同時是空的）
    pub fn evicted_hashes(&self, n: usize, i: usize) -> Vec<u32> {
        if n != self.shards {
            return Vec::new();
        }
        self.evicted.iter().copied().filter(|h| (*h as usize) & (n - 1) == i).collect()
    }

    /// 從移出名單拿掉一筆（讀回來了，或磁碟上已經找不到）
    pub fn unevict(&mut self, name: &str) {
        if let Ok(i) = self.evicted.binary_search(&name_hash(name)) {
            self.evicted.remove(i);
        }
    }

    /// 拿掉這個分片的整個移出名單（全部讀回來了，或分片檔已經不見 / 壞掉）
    pub fn unevict_shard(&mut self, i: usize) {
        let n = self.shards;
        self.evicted.retain(|h| (*h as usize) & (n - 1) != i);
    }

    /// 從磁碟讀回來的網域：記憶體裡沒有才放進去（記憶體裡的比較新），並從移出名單拿掉。回傳有沒有放進去
    pub fn insert_reloaded(&mut self, d: Domain) -> bool {
        let name = d.name.clone();
        self.unevict(&name);
        if self.domains.contains_key(&name) {
            return false;
        }
        self.domains.insert(name, d);
        true
    }

    /// 改分片數（測試、量測用；正式執行由筆數上限決定）
    pub fn set_shards(&mut self, n: usize) {
        self.shards = n.clamp(1, MAX_SHARDS).next_power_of_two();
        self.marks = vec![Mark::Clean; self.shards];
    }

    /// 第 `i` 片只有計數等級的變動（沒有更高等級時才設；3.5.1 G1 讀回時忘掉一次性網域用）
    pub fn mark_counters(&mut self, i: usize) {
        if let Some(m) = self.marks.get_mut(i) {
            if *m == Mark::Clean {
                *m = Mark::Counters;
            }
        }
    }

    /// 這個網域有重要的變動：它的分片要寫
    pub fn mark(&mut self, name: &str) {
        let i = shard_of(name, self.shards);
        self.marks[i] = Mark::Important;
    }

    /// 目前各分片的變動（不清除）
    pub fn marks(&self) -> &[Mark] {
        &self.marks
    }

    /// 有沒有任何還沒取出的變動
    pub fn changed(&self) -> bool {
        self.dirty || self.marks.iter().any(|m| *m != Mark::Clean)
    }

    /// 取出有變動的分片（`all` = 全部算重要變動）並清除：（分片編號，是否重要）
    pub fn take_marks(&mut self, all: bool) -> Vec<(usize, bool)> {
        let full = std::mem::take(&mut self.dirty) || all;
        let out = self
            .marks
            .iter()
            .enumerate()
            .filter(|(_, m)| full || **m != Mark::Clean)
            .map(|(i, m)| (i, full || *m == Mark::Important))
            .collect();
        self.marks.iter_mut().for_each(|m| *m = Mark::Clean);
        out
    }

    /// 分片清單（一般 JSON；只記 N 與舊版不認識的欄位，平常不會變）
    pub fn manifest_json(&self) -> Vec<u8> {
        serde_json::to_vec(&ManifestFmt {
            format: MANIFEST_FORMAT.into(),
            version: 1,
            shards: self.shards,
            extra: self.extra.clone(),
        })
        .unwrap_or_default()
    }

    /// 從狀態目錄載入：舊版單一檔案（有的話）→ 分片清單 → 各分片（分片的內容比舊檔新，蓋過去）。
    /// `read` 給相對路徑、回傳內容（壓縮檔由它處理）；`list_dir` 列出分片目錄裡的檔名（沒有清單時救援用）。
    /// 讀不到或壞掉的分片記一筆警告、略過，其他照常載入——絕不因為一個分片壞掉就不能啟動。
    pub fn load_store(&mut self, read: &dyn Fn(&str) -> Option<Vec<u8>>, list_dir: &dyn Fn() -> Vec<String>) -> StoreLoad {
        let mut out = StoreLoad::default();
        if let Some(b) = read(FILE) {
            match self.load_domains(&b, false) {
                Ok(_) => out.legacy = true,
                Err(e) => tracing::warn!("{FILE} 讀取失敗：{e}"),
            }
        }
        let manifest = read(MANIFEST).and_then(|b| {
            serde_json::from_slice::<ManifestFmt>(&b)
                .map_err(|e| tracing::warn!("{MANIFEST} 讀取失敗：{e}"))
                .ok()
                .filter(|m| (1..=MAX_SHARDS).contains(&m.shards) && m.shards.is_power_of_two())
        });
        out.manifest = manifest.is_some();
        let n = match &manifest {
            Some(m) => Some(m.shards),
            // 沒有清單（或壞掉）而且沒有舊檔：用目錄裡檔案最多的一組分片（救援）
            None if !out.legacy => rescue_shards(&list_dir()),
            None => None,
        };
        if let Some(m) = manifest {
            self.extra = m.extra;
        }
        out.shards_on_disk = n;
        let Some(n) = n else { return out };
        // 不見的分片只記一行（第一次啟動、資料庫還是空的時候可能一片都還沒寫，不要洗版）
        let mut missing: Vec<usize> = Vec::new();
        for i in 0..n {
            let rel = shard_file(n, i);
            match read(&rel).map(|b| serde_json::from_slice::<FileFmt>(&b)) {
                Some(Ok(f)) => {
                    if out.legacy {
                        // 這片已經寫過：裡面的內容比舊檔新
                        self.domains.retain(|k, _| shard_of(k, n) != i);
                    }
                    for d in f.domains {
                        self.domains.insert(d.name.clone(), d);
                    }
                }
                Some(Err(e)) => {
                    tracing::warn!("CDN 網域分片 {rel} 壞掉，略過（其他分片照常載入）：{e}");
                    out.bad_shards.push(i);
                }
                None => {
                    missing.push(i);
                    out.bad_shards.push(i);
                }
            }
        }
        if !missing.is_empty() {
            tracing::warn!(
                "CDN 網域分片有 {} / {n} 片不見了（例如 {}），略過（其他分片照常載入）",
                missing.len(),
                shard_file(n, missing[0])
            );
        }
        if self.domains.len() > self.max_entries {
            self.prune();
        }
        out
    }

    /// 載入之後決定要重寫什麼：舊檔搬家、分片數改變、清單不見 → 全部重寫並寫新清單（寫完刪舊檔）；
    /// 只有幾個分片壞掉 → 只重寫那幾片
    pub fn plan_after_load(&mut self, l: &StoreLoad) {
        let same = l.shards_on_disk == Some(self.shards);
        if l.legacy || !same || !l.manifest {
            if l.legacy || l.shards_on_disk.is_some() {
                self.dirty = true;
            }
            let mut retire = vec![FILE.to_string()];
            if let Some(old) = l.shards_on_disk.filter(|n| *n != self.shards) {
                retire.extend((0..old).map(|i| shard_file(old, i)));
            }
            self.manifest_pending = Some(retire);
        } else {
            for i in &l.bad_shards {
                self.marks[*i] = Mark::Important;
            }
        }
    }

    /// 這個分片裡的網域名稱（拿著鎖時呼叫；之後放開鎖排序、分批寫）
    pub fn shard_keys(&mut self, n: usize, i: usize) -> Vec<Arc<str>> {
        if self.domains.len() > self.max_entries {
            self.prune();
        }
        self.domains.keys().filter(|k| shard_of(k, n) == i).cloned().collect()
    }

    /// 分片內容的開頭（`{"shard":i,"of":n,"domains":[`）與結尾
    pub fn shard_frame(n: usize, i: usize) -> (Vec<u8>, &'static [u8]) {
        (format!("{{\"shard\":{i},\"of\":{n},\"domains\":[").into_bytes(), b"]}")
    }

    /// 把這些網域接到 `out` 後面（期間被刪掉的略過）
    pub fn dump_names(&self, names: &[Arc<str>], out: &mut Vec<u8>, first: &mut bool) {
        for name in names {
            let Some(d) = self.domains.get(name) else { continue };
            if !*first {
                out.push(b',');
            }
            *first = false;
            let _ = serde_json::to_writer(&mut *out, d);
        }
    }

    /// 讀 `cdn-domains.json`；`seed = true` 時把最後出現時間設成現在（同 2.x 的種子匯入）
    pub fn load_domains(&mut self, b: &[u8], seed: bool) -> anyhow::Result<usize> {
        let f: FileFmt = serde_json::from_slice(b)?;
        let now = now_ms();
        self.saved_at = f.saved_at;
        self.extra = f.extra;
        self.domains.clear();
        self.domains.reserve(f.domains.len().min(self.max_entries));
        for mut d in f.domains {
            if seed {
                d.last_seen = now;
                // 另一家業者的那一格也是別台機器驗證的：不帶
                d.src = None;
                // 種子裡「通過」的結果是別台機器在別的網路驗證的：有效期限一律設成現在，
                // 這台機器自己驗證過才換節點（每小時的複驗會處理，第一次查詢也會觸發）。
                // 以前種子匯出後 24 小時內（跨 CDN 是 3 天）安裝，會直接照種子的結果改寫
                for v in [&mut d.v4, &mut d.v6].into_iter().flatten() {
                    if v.is("ok") && v.valid(now) {
                        v.until = Some(now);
                    }
                }
                if let Some(e) = d.ecs.as_mut().filter(|e| e.is("ok") && e.until.unwrap_or(0) > now) {
                    e.until = Some(now);
                }
                if let Some(x) = d.cross4.as_mut().filter(|x| x.is("ok") && x.until.unwrap_or(0) > now) {
                    x.until = Some(now);
                }
            }
            self.domains.insert(d.name.clone(), d);
        }
        if self.domains.len() > self.max_entries {
            self.prune();
        }
        Ok(self.domains.len())
    }

    pub fn load_harvest(&mut self, b: &[u8]) -> anyhow::Result<()> {
        let f: IndexMap<String, HarvestFmt> = serde_json::from_slice(b)?;
        self.harvest.clear();
        for (p, h) in f {
            let conv = |m: IndexMap<String, Value>| -> IndexMap<IpAddr, u64> {
                m.into_iter()
                    .filter_map(|(k, v)| {
                        Some((
                            util::parse_ip(&k)?,
                            v.as_u64().or_else(|| v.as_f64().map(|f| f as u64)).unwrap_or(0),
                        ))
                    })
                    .collect()
            };
            self.harvest.insert(
                p,
                HarvestSet {
                    v4: conv(h.v4),
                    v6: conv(h.v6),
                    extra: h.extra,
                },
            );
        }
        Ok(())
    }

    /// `cdn-domains.json` 內容（依查詢次數多到少）
    pub fn domains_json(&mut self) -> Vec<u8> {
        if self.domains.len() > self.max_entries {
            self.prune();
        }
        self.saved_at = Some(util::iso(now_ms()));
        let mut list: Vec<&Domain> = self.domains.values().collect();
        list.sort_by(|a, b| b.hits.cmp(&a.hits).then_with(|| a.name.cmp(&b.name)));
        // 不複製整份資料：直接把參照序列化
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Out<'a> {
            #[serde(skip_serializing_if = "Option::is_none")]
            saved_at: &'a Option<String>,
            domains: Vec<&'a Domain>,
            #[serde(flatten)]
            extra: &'a Extra,
        }
        serde_json::to_vec(&Out {
            saved_at: &self.saved_at,
            domains: list,
            extra: &self.extra,
        })
        .unwrap_or_default()
    }

    /// 分段寫 `cdn-domains.json` 的第一步（拿著鎖）：整理、定出「開頭」與「結尾」，列出要寫的網域。
    /// 回傳（開頭，結尾，（查詢次數，名稱）——還沒排序）。接著放開鎖排序，再分批呼叫 `dump_chunk`。
    /// 內容跟 `domains_json()` 一樣，只是不必整個過程都拿著鎖（20 萬筆要半秒，期間所有 CDN 回應都卡住）
    pub fn dump_begin(&mut self) -> (Vec<u8>, Vec<u8>, DumpKeys) {
        if self.domains.len() > self.max_entries {
            self.prune();
        }
        self.saved_at = Some(util::iso(now_ms()));
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Out<'a> {
            #[serde(skip_serializing_if = "Option::is_none")]
            saved_at: &'a Option<String>,
            domains: [u8; 0],
            #[serde(flatten)]
            extra: &'a Extra,
        }
        // 外框跟 `domains_json()` 用同一種寫法產生，再從空陣列的地方切開
        let frame = serde_json::to_vec(&Out {
            saved_at: &self.saved_at,
            domains: [],
            extra: &self.extra,
        })
        .unwrap_or_default();
        const MARK: &[u8] = b"\"domains\":[";
        let at = frame
            .windows(MARK.len())
            .position(|w| w == MARK)
            .map(|i| i + MARK.len())
            .unwrap_or(0);
        let keys = self.domains.values().map(|d| (d.hits, d.name.clone())).collect();
        (frame[..at].to_vec(), frame[at..].to_vec(), keys)
    }

    /// 排序方式同 `domains_json()`：查詢次數多到少，同次數依名稱
    pub fn dump_sort(keys: &mut [(u32, Arc<str>)]) {
        keys.sort_unstable_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    }

    /// 把這一批網域接到 `out` 後面（期間被刪掉的略過）
    pub fn dump_chunk(&self, keys: &[(u32, Arc<str>)], out: &mut Vec<u8>, first: &mut bool) {
        for (_, name) in keys {
            let Some(d) = self.domains.get(name) else { continue };
            if !*first {
                out.push(b',');
            }
            *first = false;
            let _ = serde_json::to_writer(&mut *out, d);
        }
    }

    pub fn harvest_json(&self) -> Vec<u8> {
        // 保持加入順序（淘汰依這個順序），不能經過會排序的 serde_json::Map
        #[derive(Serialize)]
        struct Out<'a> {
            v4: IndexMap<String, u64>,
            v6: IndexMap<String, u64>,
            #[serde(flatten)]
            extra: &'a Extra,
        }
        let m = |x: &IndexMap<IpAddr, u64>| x.iter().map(|(ip, t)| (ip.to_string(), *t)).collect::<IndexMap<_, _>>();
        let out: IndexMap<&String, Out> = self
            .harvest
            .iter()
            .map(|(p, h)| {
                (
                    p,
                    Out {
                        v4: m(&h.v4),
                        v6: m(&h.v6),
                        extra: &h.extra,
                    },
                )
            })
            .collect();
        serde_json::to_vec(&out).unwrap_or_default()
    }

    /// 刪掉最久沒出現的，降到上限的 90%（手動設定策略的保留）
    pub fn prune(&mut self) {
        self.drop_oldest((self.max_entries as f64 * 0.9) as usize);
    }

    /// 刪到剩 `keep` 筆（記憶體不足時也用這個）
    pub fn shrink_to(&mut self, keep: usize) {
        self.drop_oldest(keep);
        // 把空出來的記憶體還回去（要重排整個表：只有記憶體不足時才做，平常的整理不做——反正馬上又會長回來）
        self.domains.shrink_to_fit();
    }

    fn drop_oldest(&mut self, keep: usize) {
        if self.domains.len() <= keep {
            return;
        }
        let mut arr: Vec<(u64, Arc<str>)> = self
            .domains
            .values()
            .filter(|d| d.policy() == Policy::Auto)
            .map(|d| (d.last_seen, d.name.clone()))
            .collect();
        let drop = (self.domains.len() - keep).min(arr.len());
        // 只需要「最舊的 drop 筆」，不必整個排序
        if drop > 0 && drop < arr.len() {
            arr.select_nth_unstable(drop - 1);
        }
        for (_, n) in arr.into_iter().take(drop) {
            self.domains.remove(&n);
            self.mark(&n);
        }
    }

    // ------------------------------------------------------------ 磁碟預算（3.5.0 C5，規格 05 第 5.7 節）

    /// 總筆數：記憶體裡的＋移出記憶體（還在磁碟上）的
    pub fn total_entries(&self) -> usize {
        self.domains.len() + self.evicted.len()
    }

    /// 磁碟預算淘汰時的順位（小的先淘汰）；手動設定策略的不在這裡（絕不淘汰）。
    ///
    /// | 順位 | 是什麼 | 為什麼 |
    /// |---|---|---|
    /// | 0 | 只問過 1 次、沒有成功的驗證結果、超過一天沒再出現 | 一次性的網域：留著也用不到 |
    /// | 1 | 沒有成功的驗證結果、驗證失敗、超過 7 天沒再出現 | 換不到台灣節點，也沒有人在問 |
    /// | 2 | 其他超過一天沒出現的（沒驗證過、或驗證成功但超過 30 天沒出現） | |
    /// | 3 | 驗證成功過、30 天內出現過 | 每筆省下一次重新驗證（對 CDN 發 HTTPS 探測） |
    /// | 4 | 一天內出現過 | 正在用；剛出現的也要留到被問第二次、驗證完 |
    pub fn budget_rank(d: &Domain, now_ms: u64) -> u8 {
        let age = now_ms.saturating_sub(d.last_seen);
        if age < BUDGET_RECENT_MS {
            return 4;
        }
        let ok = d.v4.as_ref().is_some_and(|v| v.is("ok"))
            || d.v6.as_ref().is_some_and(|v| v.is("ok"))
            || d.ecs.as_ref().is_some_and(|e| e.is("ok"))
            || d.cross4.as_ref().is_some_and(|c| c.is("ok"));
        if ok {
            return if age < BUDGET_VERIFIED_FRESH_MS { 3 } else { 2 };
        }
        if d.hits <= 1 {
            return 0;
        }
        let failed = d.v4.as_ref().is_some_and(|v| v.is("fail")) || d.v6.as_ref().is_some_and(|v| v.is("fail"));
        if failed && age >= BUDGET_FAILED_STALE_MS {
            return 1;
        }
        2
    }

    /// 決定這一輪要整理哪些分片（`limit` = 預算換算的筆數；最多 `shards / 8` 片，至少 1 片）：
    ///
    /// 1. 總筆數沒超過預算：什麼都不做。
    /// 2. 超過額度（`limit / 分片數`）而且**本來就有重要變動、反正要寫**的分片：順便淘汰到額度的 90%（不多寫一個檔）。
    /// 3. 總筆數超過預算的 110%、而且 `disk_over`（磁碟上的分片實際量起來也超過預算；升級後第一次啟用、匯入大量資料）：
    ///    另外每輪主動重寫最多 `shards / 16` 片（超過最多的先），一輪一輪做到總筆數回到預算以內為止。
    ///    每個分片在一次整理裡只重寫一次
    ///
    /// 整個資料庫要重寫（`dirty`：種子、舊版搬家、分片數改變）時所有分片反正都要寫：全部算第 2 種、不限片數
    /// （寫之前就淘汰好，不必先寫一份大的再寫一份小的）。
    pub fn budget_plan(&mut self, limit: usize, disk_over: bool) -> BudgetPlan {
        let total = self.total_entries();
        let mut plan = BudgetPlan {
            total,
            limit,
            ..BudgetPlan::default()
        };
        if total <= limit {
            self.budget_sweep = false;
            return plan;
        }
        let n = self.shards;
        let quota = (limit / n).max(1);
        let keep = (quota * BUDGET_KEEP_PERCENT / 100).max(1);
        let mut counts = vec![0usize; n];
        for k in self.domains.keys() {
            counts[shard_of(k, n)] += 1;
        }
        for h in &self.evicted {
            counts[(*h as usize) & (n - 1)] += 1;
        }
        let cap = if self.dirty { n } else { (n / 8).max(1) };
        let mut over: Vec<(usize, usize)> = (0..n).filter(|i| counts[*i] > quota).map(|i| (counts[i], i)).collect();
        // 超過最多的先
        over.sort_unstable_by(|a, b| b.cmp(a));
        // 反正要寫的
        for (_, i) in &over {
            if plan.shards.len() >= cap {
                break;
            }
            if self.dirty || self.marks[*i] == Mark::Important {
                plan.shards.push((*i, keep));
            }
        }
        if !self.budget_sweep && disk_over && total.saturating_mul(100) > limit.saturating_mul(BUDGET_SWEEP_PERCENT) {
            self.budget_sweep = true;
            plan.sweep_started = true;
        }
        if self.budget_sweep {
            let forced_cap = (n / 16).max(1);
            for (_, i) in &over {
                if plan.shards.len() >= cap || plan.forced >= forced_cap {
                    break;
                }
                if !plan.shards.iter().any(|(s, _)| s == i) {
                    plan.shards.push((*i, keep));
                    plan.forced += 1;
                }
            }
        }
        plan
    }

    /// 正在一輪一輪主動重寫超過額度的分片
    pub fn budget_sweeping(&self) -> bool {
        self.budget_sweep
    }

    /// 照計畫淘汰：每個分片留 `keep` 筆（手動設定策略的不淘汰、算在筆數裡），依 [`Db::budget_rank`]、
    /// 同一順位最久沒出現的先。有淘汰的分片標成重要變動。回傳淘汰幾筆。
    /// 分片裡還有移出記憶體的冷資料時這片不動（呼叫端要先把它們讀回來，不然不知道誰比較舊）
    pub fn budget_prune(&mut self, plan: &[(usize, usize)], now_ms: u64) -> usize {
        if plan.is_empty() {
            return 0;
        }
        let n = self.shards;
        let mut keep_of: Vec<Option<usize>> = vec![None; n];
        for (i, keep) in plan {
            if *i < n && !self.evicted.iter().any(|h| (*h as usize) & (n - 1) == *i) {
                keep_of[*i] = Some(*keep);
            }
        }
        // （分片，順位，最後出現，名稱）；手動策略的只算筆數
        let mut counts = vec![0usize; n];
        let mut cand: Vec<(usize, u8, u64, Arc<str>)> = Vec::new();
        for d in self.domains.values() {
            let i = shard_of(&d.name, n);
            if keep_of[i].is_none() {
                continue;
            }
            counts[i] += 1;
            if d.policy() == Policy::Auto {
                cand.push((i, Self::budget_rank(d, now_ms), d.last_seen, d.name.clone()));
            }
        }
        cand.sort_unstable();
        let mut dropped = 0;
        for (i, _, _, name) in cand {
            let Some(keep) = keep_of[i] else { continue };
            if counts[i] <= keep {
                continue;
            }
            self.domains.remove(&name);
            self.marks[i] = Mark::Important;
            counts[i] -= 1;
            dropped += 1;
        }
        dropped
    }

    pub fn get(&self, name: &str) -> Option<&Domain> {
        self.domains.get(name)
    }

    pub fn get_mut(&mut self, name: &str) -> Option<&mut Domain> {
        self.domains.get_mut(name)
    }

    /// 每次解析到 CDN 網域時呼叫：登記 / 更新統計（不帶第一層 CNAME 的鍵；測試與舊的呼叫端用）
    pub fn touch(&mut self, name: &str, provider: &str, via: &str, ips4: &[IpAddr], ips6: &[IpAddr], cname: Option<&str>) -> &mut Domain {
        self.touch_at(name, provider, via, ips4, ips6, cname, "", now_ms());
        self.domains.get_mut(name).unwrap()
    }

    /// 每次解析到 CDN 網域時呼叫：登記 / 更新統計，並看這次回答的來源（業者、第一層 CNAME 的鍵 `c1`）有沒有變。
    ///
    /// 多來源（3.5.0 B3，`multi_cdn`）：
    /// - 每個網域最多兩格（目前這一家＋另一家），驗證結果各存各的。回答換成另一家時整格對調，
    ///   所以「兩家輪流回答」不會清掉任何驗證結果，也不算重要變動（不觸發寫入）。
    /// - 第一次看到第二家：替它開一格（從試用期開始驗證），清掉不分業者的結果（跨 CDN、ECS、最佳策略）。
    ///   開新的一格每個網域每 [`SRC_GAP_MS`] 最多一次；不能開的那次回 `held`（照原始答案回）。
    /// - 回到另一格、而且剛剛那一家 24 小時內才回答過 → 兩家在輪流：標成多來源，[`MULTI_KEEP_MS`] 沒再發生就取消。
    /// - 同一家裡第一層 CNAME 的鍵變了：新的鍵要連續看到 [`C1_CONFIRM_HITS`] 次、相隔 [`C1_CONFIRM_MS`] 以上、
    ///   中間沒有再看到舊的鍵才算；24 小時內看過的鍵不算新的。確認之後清掉跨 CDN 與 ECS（驗證結果留著），
    ///   一樣每 [`SRC_GAP_MS`] 最多一次。
    /// - 舊資料沒有鍵：第一次看到時補上，**不算變了**（不然升級後第一輪會把所有網域的結果清掉）。
    #[allow(clippy::too_many_arguments)]
    pub fn touch_at(
        &mut self,
        name: &str,
        provider: &str,
        via: &str,
        ips4: &[IpAddr],
        ips6: &[IpAddr],
        cname: Option<&str>,
        c1: &str,
        now: u64,
    ) -> Touch {
        let mut out = Touch::default();
        if !self.domains.contains_key(name) {
            if self.domains.len() >= self.max_entries {
                self.prune();
            }
            let key: Arc<str> = Arc::from(name);
            self.domains.insert(
                key.clone(),
                Domain {
                    name: key,
                    provider: Field::Val(util::intern(provider)),
                    via: Field::Val(util::intern(via)),
                    cname: cname.map(|c| Field::Val(c.to_string())).unwrap_or(Field::Null),
                    first_seen: now,
                    last_seen: now,
                    hits: 0,
                    policy: Some(Policy::Auto),
                    ..Default::default()
                },
            );
        }
        let shard = shard_of(name, self.shards);
        let multi_cdn = self.multi_cdn;
        let e = self.domains.get_mut(name).unwrap();
        // 剛新增的（hits 還是 0）算重要變動；其他只有計數變了的，不單獨觸發寫入
        let mut important = e.hits == 0;
        if !provider.is_empty() && e.provider() != Some(provider) {
            if !multi_cdn || e.provider().is_none() {
                e.provider = Field::Val(util::intern(provider));
                e.via = Field::Val(util::intern(via));
                important = true;
            } else {
                match Self::switch_provider(e, provider, via, now) {
                    Switch::Swapped => {}
                    Switch::NewSlot { invalidated } => {
                        out.new_slot = true;
                        out.invalidated = invalidated;
                        important = true;
                    }
                    Switch::Held => {
                        // 沒有格子：只記計數，其他都不動（這一家的 IP、CNAME 不能蓋掉目前這一格的）
                        e.last_seen = now;
                        e.hits = e.hits.saturating_add(1);
                        out.held = true;
                        out.no_cross = true;
                        let m = &mut self.marks[shard];
                        if *m == Mark::Clean {
                            *m = Mark::Counters;
                        }
                        return out;
                    }
                }
            }
        }
        e.last_seen = now;
        e.hits = e.hits.saturating_add(1);
        if multi_cdn {
            if !c1.is_empty() && Self::observe_c1(e, c1, now) {
                out.invalidated = true;
                important = true;
            }
            Self::expire_src(e, now);
            out.no_cross = e.no_cross(now);
        }
        if let Some(c) = cname {
            if e.cname.val().map(|x| x.as_str()) != Some(c) {
                e.cname = Field::Val(c.to_string());
                important = true;
            }
        }
        if !ips4.is_empty() && *e.ips4 != ips4[..ips4.len().min(4)] {
            e.ips4 = ips4.iter().take(4).copied().collect();
            important = true;
        }
        if !ips6.is_empty() && *e.ips6 != ips6[..ips6.len().min(2)] {
            e.ips6 = ips6.iter().take(2).copied().collect();
            important = true;
        }
        let m = &mut self.marks[shard];
        if important {
            *m = Mark::Important;
        } else if *m == Mark::Clean {
            *m = Mark::Counters;
        }
        out
    }

    /// 這次回答的業者跟目前這一格不同：對調、開新的一格，或沒有格子
    fn switch_provider(e: &mut Domain, provider: &str, via: &str, now: u64) -> Switch {
        let prev_last = e.last_seen;
        let src = e.src.get_or_insert_with(Default::default);
        let in_alt = src.alt.as_ref().is_some_and(|a| a.provider.val().map(|p| &**p) == Some(provider));
        if in_alt {
            // 另一格就是這一家：整格對調。剛剛那一家 24 小時內才回答過 → 兩家在輪流
            if now.abs_diff(prev_last) < SRC_WINDOW_MS {
                src.multi_at = now;
            }
            src.pend = None;
            src.pend_n = 0;
            src.pend_at = 0;
            e.swap_slot();
            if let Some(a) = e.src.as_mut().and_then(|s| s.alt.as_deref_mut()) {
                a.last = prev_last;
            }
            return Switch::Swapped;
        }
        if src.slot_at != 0 && now.abs_diff(src.slot_at) < SRC_GAP_MS {
            src.other = Some((provider.to_string(), now));
            return Switch::Held;
        }
        // 開新的一格：目前這一格移到另一格（原本在另一格的那一家被擠掉）
        src.slot_at = now;
        src.inval_at = now;
        src.pend = None;
        src.pend_n = 0;
        src.pend_at = 0;
        if src.other.as_ref().is_some_and(|o| o.0 == provider) {
            src.other = None;
        }
        src.alt = Some(Box::new(Alt {
            provider: Field::Val(util::intern(provider)),
            via: Field::Val(util::intern(via)),
            cname: Field::Null,
            ..Default::default()
        }));
        e.swap_slot();
        if let Some(a) = e.src.as_mut().and_then(|s| s.alt.as_deref_mut()) {
            a.last = prev_last;
        }
        Switch::NewSlot {
            invalidated: e.invalidate_shared(),
        }
    }

    /// 同一家裡第一層 CNAME 的鍵。回傳 true = 確認變了、而且這次清掉了跨 CDN／ECS／最佳策略
    fn observe_c1(e: &mut Domain, c1: &str, now: u64) -> bool {
        let Some(cur) = e.c1.as_deref() else {
            // 舊資料或新的一格：補上，不算變了
            e.c1 = Some(util::intern(&c1.to_ascii_lowercase()));
            return false;
        };
        if cur.eq_ignore_ascii_case(c1) {
            // 又看到目前的鍵：等確認中的那個其實是「輪流出現的另一個」，記進最近看過的，以後不算新的
            if let Some(s) = e.src.as_mut() {
                if let Some(p) = s.pend.take() {
                    s.pend_n = 0;
                    s.pend_at = 0;
                    Self::remember_c1(s, p, now);
                }
            }
            return false;
        }
        let s = e.src.get_or_insert_with(Default::default);
        if let Some(x) = s
            .seen
            .iter_mut()
            .find(|x| x.0.eq_ignore_ascii_case(c1) && now.abs_diff(x.1) < SRC_WINDOW_MS)
        {
            x.1 = now;
            return false;
        }
        if s.pend.as_deref().is_some_and(|p| p.eq_ignore_ascii_case(c1)) {
            s.pend_n = s.pend_n.saturating_add(1);
        } else {
            s.pend = Some(c1.to_ascii_lowercase());
            s.pend_n = 1;
            s.pend_at = now;
        }
        if s.pend_n < C1_CONFIRM_HITS || now.saturating_sub(s.pend_at) < C1_CONFIRM_MS {
            return false;
        }
        // 確認變了：舊的鍵記進最近看過的（之後換回來不算新的）
        let new = s.pend.take().unwrap_or_default();
        s.pend_n = 0;
        s.pend_at = 0;
        Self::remember_c1(s, cur.to_string(), now);
        let can = s.inval_at == 0 || now.abs_diff(s.inval_at) >= SRC_GAP_MS;
        if can {
            s.inval_at = now;
        }
        e.c1 = Some(util::intern(&new));
        can && e.invalidate_shared()
    }

    fn remember_c1(s: &mut Src, key: String, now: u64) {
        if let Some(x) = s.seen.iter_mut().find(|x| x.0 == key) {
            x.1 = now;
            return;
        }
        if s.seen.len() >= C1_SEEN_MAX {
            if let Some(i) = (0..s.seen.len()).min_by_key(|&i| s.seen[i].1) {
                s.seen.remove(i);
            }
        }
        s.seen.push((key, now));
    }

    /// 過期的來源紀錄順手清掉（只在這個網域被查到時做；都是幾個時間比較）
    fn expire_src(e: &mut Domain, now: u64) {
        let same = e.provider.val().cloned();
        let Some(s) = e.src.as_mut() else { return };
        if s.multi_at != 0 && !s.multi(now) {
            s.multi_at = 0;
        }
        let keep = if s.multi_at != 0 { MULTI_KEEP_MS } else { SRC_WINDOW_MS };
        // 另一格太久沒回答（換家已經定下來、或多來源取消了）：丟掉。跟目前這一格同一家的（舊版寫回來、匯入合併造成的）也丟
        if s.alt
            .as_ref()
            .is_some_and(|a| now.abs_diff(a.last) >= keep || a.provider.val() == same.as_ref())
        {
            s.alt = None;
        }
        s.seen.retain(|x| now.abs_diff(x.1) < SRC_WINDOW_MS);
        if s.other.as_ref().is_some_and(|o| now.abs_diff(o.1) >= SRC_WINDOW_MS) {
            s.other = None;
        }
        if s.pend.is_some() && now.abs_diff(s.pend_at) >= SRC_WINDOW_MS {
            s.pend = None;
            s.pend_n = 0;
            s.pend_at = 0;
        }
        if s.slot_at != 0 && now.abs_diff(s.slot_at) >= MULTI_KEEP_MS {
            s.slot_at = 0;
        }
        if s.inval_at != 0 && now.abs_diff(s.inval_at) >= MULTI_KEEP_MS {
            s.inval_at = 0;
        }
        if s.is_empty() {
            e.src = None;
        }
    }

    /// 背景工作（驗證）寫結果用：把 `provider` 的那一格暫時換到前面、做完換回來。
    /// 這一家已經沒有格子（被擠掉、過期）回 None：結果不寫（不能寫到別家的格子裡）。
    /// `multi_cdn` 關掉、或這個網域還沒有業者時不分格子，直接做
    pub fn with_slot<R>(&mut self, name: &str, provider: &str, f: impl FnOnce(&mut Db) -> R) -> Option<R> {
        let swapped = {
            let e = self.domains.get_mut(name)?;
            match e.provider() {
                _ if !self.multi_cdn => false,
                None => false,
                Some(p) if p == provider => false,
                Some(_) => {
                    let in_alt = e
                        .src
                        .as_ref()
                        .and_then(|s| s.alt.as_ref())
                        .is_some_and(|a| a.provider.val().map(|p| &**p) == Some(provider));
                    if !in_alt {
                        return None;
                    }
                    e.swap_slot();
                    true
                }
            }
        };
        let r = f(self);
        if swapped {
            if let Some(e) = self.domains.get_mut(name) {
                e.swap_slot();
            }
        }
        Some(r)
    }

    /// 合併更新驗證結果（同 2.x：舊欄位保留、新欄位覆蓋，加上 `at`）
    pub fn set_verdict(&mut self, name: &str, family: u8, f: impl FnOnce(&mut Verdict)) {
        let Some(e) = self.domains.get_mut(name) else { return };
        let slot = if family == 6 { &mut e.v6 } else { &mut e.v4 };
        let v = slot.get_or_insert_with(Default::default);
        f(v);
        v.at = Some(now_ms());
        self.mark(name);
    }

    pub fn clear_verdict(&mut self, name: &str, family: u8) {
        if let Some(e) = self.domains.get_mut(name) {
            if family == 6 {
                e.v6 = None;
            } else {
                e.v4 = None;
            }
            self.mark(name);
        }
    }

    pub fn set_base(&mut self, name: &str, mut base: Base) {
        let Some(e) = self.domains.get_mut(name) else { return };
        base.at = Some(now_ms());
        e.base = Some(Box::new(base));
        self.mark(name);
    }

    pub fn set_ecs(&mut self, name: &str, mut ecs: Ecs) {
        let Some(e) = self.domains.get_mut(name) else { return };
        ecs.at = Some(now_ms());
        e.ecs = Some(Box::new(ecs));
        self.mark(name);
    }

    /// 跨 CDN 探索結果（cross4）
    pub fn set_cross(&mut self, name: &str, mut c: Cross) {
        let Some(e) = self.domains.get_mut(name) else { return };
        c.at = Some(now_ms());
        e.cross4 = Some(Box::new(c));
        self.mark(name);
    }

    /// 記住這個網站最後成功的改寫方式
    pub fn set_best(&mut self, name: &str, s: Strategy) {
        if let Some(e) = self.domains.get_mut(name) {
            if e.best != Some(s) {
                e.best = Some(s);
                self.mark(name);
            }
        }
    }

    pub fn set_policy(&mut self, name: &str, policy: Policy) -> &Domain {
        let now = now_ms();
        self.mark(name);
        let key: Arc<str> = Arc::from(name);
        let e = self.domains.entry(key.clone()).or_insert_with(|| Domain {
            name: key,
            provider: Field::Null,
            via: Field::Val(util::intern("manual")),
            first_seen: now,
            last_seen: now,
            ..Default::default()
        });
        e.policy = Some(policy);
        e
    }

    /// 收集候選節點 IP（給每日節點池工作使用）
    pub fn add_harvest(&mut self, provider: &str, ip: IpAddr) {
        // 每個 CDN 回應都會跑：已經有這家的時候不要為了查表配置字串
        if !self.harvest.contains_key(provider) {
            self.harvest.insert(provider.to_string(), HarvestSet::default());
        }
        let h = self.harvest.get_mut(provider).unwrap();
        let m = if ip.is_ipv6() { &mut h.v6 } else { &mut h.v4 };
        if !m.contains_key(&ip) {
            m.insert(ip, now_ms());
            if m.len() > HARVEST_MAX {
                m.shift_remove_index(0);
            }
            self.harvest_dirty = true;
        }
    }

    /// 別人給的候選節點（好友同步、分享檔）：還有空位才放，不擠掉自己流量收集到的。回傳有沒有新增
    pub fn add_harvest_candidate(&mut self, provider: &str, ip: IpAddr) -> bool {
        let h = self.harvest.entry(provider.to_string()).or_default();
        let m = if ip.is_ipv6() { &mut h.v6 } else { &mut h.v4 };
        if m.contains_key(&ip) || m.len() >= HARVEST_MAX {
            return false;
        }
        m.insert(ip, now_ms());
        self.harvest_dirty = true;
        true
    }

    pub fn harvest_of(&self, provider: &str, v6: bool) -> Vec<IpAddr> {
        self.harvest
            .get(provider)
            .map(|h| {
                if v6 {
                    h.v6.keys().copied().collect()
                } else {
                    h.v4.keys().copied().collect()
                }
            })
            .unwrap_or_default()
    }

    /// 跨 CDN 統計：試了幾個、成功幾個、各轉去哪一家
    pub fn cross_summary(&self) -> Value {
        let (mut explored, mut ok, mut fail, mut none) = (0u32, 0u32, 0u32, 0u32);
        // 連線比較近、但握手沒有比較快而沒有採用的（3.5.0 B4、F13）
        let mut score_rejected = 0u32;
        let mut by_to: IndexMap<String, u32> = IndexMap::new();
        let mut by_from: IndexMap<String, (u32, u32)> = IndexMap::new();
        let mut also: IndexMap<String, u32> = IndexMap::new();
        for e in self.domains.values() {
            let Some(x) = &e.cross4 else { continue };
            let Some(v) = x.verdict.as_deref() else { continue };
            let from = x.from.as_deref().or(e.provider()).unwrap_or("?").to_string();
            let f = by_from.entry(from).or_default();
            if v == "none" {
                none += 1;
                continue;
            }
            explored += 1;
            f.0 += 1;
            if v == "ok" {
                ok += 1;
                f.1 += 1;
                *by_to.entry(x.to.as_deref().unwrap_or("?").to_string()).or_default() += 1;
                for a in x.also.iter().flatten() {
                    *also.entry(a.clone()).or_default() += 1;
                }
            } else {
                fail += 1;
                if x.score.get().is_some() && x.orig_score.get().is_some() {
                    score_rejected += 1;
                }
            }
        }
        json!({
            "explored": explored, "ok": ok, "fail": fail, "none": none, "scoreRejected": score_rejected, "byTo": by_to,
            "byFrom": by_from.into_iter().map(|(k, (e, o))| (k, json!({ "explored": e, "ok": o }))).collect::<serde_json::Map<_, _>>(),
            "also": also,
        })
    }

    /// 分析摘要：各 CDN 有多少網域、多少原本繞國外、置換成功率
    pub fn summary(&self) -> Vec<Summary> {
        let mut out: IndexMap<String, Summary> = IndexMap::new();
        let mut names: Vec<&Domain> = self.domains.values().collect();
        names.sort_by(|a, b| a.first_seen.cmp(&b.first_seen).then_with(|| a.name.cmp(&b.name)));
        for e in names {
            let p = e.provider().unwrap_or("unknown").to_string();
            let s = out.entry(p.clone()).or_insert_with(|| Summary {
                provider: p,
                ..Default::default()
            });
            s.domains += 1;
            s.hits += e.hits as u64;
            if let Some(pop) = e.base.as_ref().and_then(|b| b.pop.as_deref()).filter(|p| !p.is_empty()) {
                *s.pops.entry(pop.to_string()).or_default() += 1;
                // 2.x 這裡用大小寫有別的比對
                if ["TPE", "KHH", "TSA", "RMQ", "TXG", "TNN"].iter().any(|t| pop.starts_with(t)) {
                    s.base_pop_tw += 1;
                } else {
                    s.base_pop_abroad += 1;
                }
            }
            if let Some(v) = &e.v4 {
                s.v4ok += v.is("ok") as u32;
                s.v4fail += v.is("fail") as u32;
            }
            if let Some(v) = &e.v6 {
                s.v6ok += v.is("ok") as u32;
                s.v6fail += v.is("fail") as u32;
            }
            if e.ecs.as_ref().map(|x| x.is("ok")).unwrap_or(false) {
                s.ecs_gain += 1;
            }
        }
        let mut v: Vec<Summary> = out.into_values().collect();
        v.sort_by_key(|s| std::cmp::Reverse(s.hits));
        v
    }

    /// 查詢（管理介面 `/api/cdn/domains`）
    pub fn query(&self, q: &Query) -> Vec<&Domain> {
        let mut arr: Vec<&Domain> = self
            .domains
            .values()
            .filter(|e| q.provider.as_deref().map(|p| e.provider() == Some(p)).unwrap_or(true))
            .filter(|e| {
                q.verdict
                    .as_deref()
                    .map(|v| e.v4.as_ref().map(|x| x.is(v)).unwrap_or(false) || e.v6.as_ref().map(|x| x.is(v)).unwrap_or(false))
                    .unwrap_or(true)
            })
            .filter(|e| q.search.as_deref().map(|t| e.name.contains(t)).unwrap_or(true))
            .filter(|e| !q.cross || e.cross4.as_ref().is_some_and(|c| c.verdict.as_deref().is_some_and(|v| v != "none")))
            .collect();
        let key = |e: &Domain| -> u64 {
            match q.sort.as_deref().unwrap_or("hits") {
                "lastSeen" => e.last_seen,
                "firstSeen" => e.first_seen,
                _ => e.hits as u64,
            }
        };
        arr.sort_by(|a, b| key(b).cmp(&key(a)).then_with(|| a.name.cmp(&b.name)));
        arr.drain(..q.offset.min(arr.len()));
        arr.truncate(q.limit.unwrap_or(1000));
        arr
    }

    /// CSV 匯出（欄位同 2.x）
    pub fn to_csv(rows: &[&Domain]) -> String {
        let cols = [
            "name",
            "provider",
            "via",
            "cname",
            "hits",
            "firstSeen",
            "lastSeen",
            "ips4",
            "ips6",
            "basePop",
            "baseStatus",
            "baseMs",
            "v4Verdict",
            "v4Pop",
            "v4Ms",
            "v4Reason",
            "v6Verdict",
            "v6Pop",
            "v6Reason",
            "ecsVerdict",
            "ecsSubnet",
            "ecsIps",
            "ecsGainMs",
            "policy",
        ];
        fn esc(s: &str) -> String {
            if s.contains([',', '"', '\n', '\r']) {
                format!("\"{}\"", s.replace('"', "\"\""))
            } else {
                s.to_string()
            }
        }
        let n = |x: &Num| {
            x.get()
                .map(|v| if v.fract() == 0.0 { format!("{}", v as i64) } else { v.to_string() })
                .unwrap_or_default()
        };
        let ips = |v: &[IpAddr]| v.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(" ");
        let s = |x: Option<&str>| x.unwrap_or("").to_string();
        let mut out = cols.join(",");
        out.push('\n');
        for e in rows {
            let b = e.base.as_deref();
            let v4 = e.v4.as_deref();
            let v6 = e.v6.as_deref();
            let ec = e.ecs.as_deref();
            let row = [
                e.name.to_string(),
                s(e.provider()),
                s(e.via.val().map(|a| &**a)),
                s(e.cname.val().map(|c| c.as_str())),
                e.hits.to_string(),
                util::iso(e.first_seen),
                util::iso(e.last_seen),
                ips(&e.ips4),
                ips(&e.ips6),
                s(b.and_then(|b| b.pop.as_deref())),
                b.map(|b| n(&b.status)).unwrap_or_default(),
                b.map(|b| n(&b.ms)).unwrap_or_default(),
                s(v4.and_then(|v| v.verdict.as_deref())),
                s(v4.and_then(|v| v.pop.as_deref())),
                v4.map(|v| n(&v.ms)).unwrap_or_default(),
                s(v4.and_then(|v| v.reason.as_deref())),
                s(v6.and_then(|v| v.verdict.as_deref())),
                s(v6.and_then(|v| v.pop.as_deref())),
                s(v6.and_then(|v| v.reason.as_deref())),
                s(ec.and_then(|v| v.verdict.as_deref())),
                s(ec.and_then(|v| v.subnet.as_deref())),
                ec.and_then(|v| v.ips4.as_ref()).map(|v| ips(v)).unwrap_or_default(),
                ec.map(|v| n(&v.gain_ms)).unwrap_or_default(),
                e.policy().as_str().to_string(),
            ];
            out.push_str(&row.iter().map(|c| esc(c)).collect::<Vec<_>>().join(","));
            out.push('\n');
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evict_coldest_order_and_target() {
        // 3.5.1 G1：從最冷的開始、移到目標量就停。沒有學習資料的先（最久沒出現的先），有學習資料的最後；
        // 2 分鐘內出現的、正在驗證的、手動策略的不動
        let mut db = Db::new(1000);
        db.set_shards(1);
        let now = now_ms();
        const MIN: u64 = 60_000;
        for (name, hits, age, learned) in [
            ("once-3m.example.com", 1u32, 3 * MIN, false),
            ("once-30d.example.com", 1, 30 * 24 * 60 * MIN, false),
            ("ok-90d.example.com", 3, 90 * 24 * 60 * MIN, true),
            ("ok-1d.example.com", 3, 24 * 60 * MIN, true),
            ("many-1h.example.com", 5, 60 * MIN, false),
            ("once-1m.example.com", 1, MIN, false),
            ("busy-1d.example.com", 1, 24 * 60 * MIN, false),
            ("manual.example.com", 1, 90 * 24 * 60 * MIN, false),
        ] {
            let d = db.touch(name, "cloudflare", "ip", &[], &[], None);
            d.hits = hits;
            d.last_seen = now - age;
            if learned {
                d.v4 = Some(Box::default());
            }
        }
        db.set_policy("manual.example.com", Policy::Always);
        db.marks = vec![Mark::Clean; 1];
        db.dirty = false;
        db.manifest_pending = None;
        let busy = |n: &str| n == "busy-1d.example.com";
        let mut order = Vec::new();
        loop {
            let before: Vec<String> = db.domains.keys().map(|k| k.to_string()).collect();
            let r = db.evict_coldest(1, 2 * MIN, now, &busy, &|_| true);
            if r.entries == 0 {
                break;
            }
            assert_eq!(r.entries, 1, "目標很小：一次只移一筆");
            order.extend(before.into_iter().filter(|k| db.get(k).is_none()));
        }
        assert_eq!(
            order,
            [
                "once-30d.example.com",
                "many-1h.example.com",
                "once-3m.example.com",
                "ok-90d.example.com",
                "ok-1d.example.com"
            ]
        );
        let mut left: Vec<&str> = db.domains.keys().map(|k| &**k).collect();
        left.sort();
        assert_eq!(left, ["busy-1d.example.com", "manual.example.com", "once-1m.example.com"]);
        // 忘掉：只有「只問過一次、沒有學習資料、自動策略」的
        let mut d = Domain {
            hits: 1,
            ..Default::default()
        };
        assert!(forgettable(&d));
        d.v4 = Some(Box::default());
        assert!(!forgettable(&d), "有驗證結果的要讀回");
        d.v4 = None;
        d.hits = 2;
        assert!(!forgettable(&d), "問過兩次的要讀回");
        assert_eq!(age_bucket(0), 0);
        assert_eq!(age_bucket(2 * MIN), 1);
        assert_eq!(age_bucket(365 * 24 * 60 * MIN), COLD_AGE_EDGES_MS.len());
    }

    #[test]
    fn record_size() {
        // 每筆網域的固定大小（64 位元）：選填的子物件都在 Box 裡、名稱跟鍵共用、IP 用定長切片
        // 3.5.0 B3 多了第一層 CNAME 的鍵（共用字串，兩個指標寬）與來源紀錄（一個指標）：64 位元 +24、32 位元 +12
        assert!(std::mem::size_of::<Domain>() <= 216, "{}", std::mem::size_of::<Domain>());
        assert!(std::mem::size_of::<Option<Box<Src>>>() == std::mem::size_of::<usize>());
        assert_eq!(std::mem::size_of::<Extra>(), std::mem::size_of::<usize>());
        let mut db = Db::new(100);
        db.touch("a.test", "cloudflare", "ip", &[], &[], None);
        let (k, v) = db.domains.iter().next().unwrap();
        assert!(Arc::ptr_eq(k, &v.name), "名稱只存一份");
    }

    #[test]
    fn query_search_offset_cross() {
        let mut db = Db::new(100);
        for i in 0..10u32 {
            db.touch(&format!("d{i}.example"), "fastly", "ip", &[], &[], None);
            db.get_mut(&format!("d{i}.example")).unwrap().hits = 100 - i;
        }
        db.touch("other.test", "cloudflare", "ip", &[], &[], None);
        fn names(db: &Db, q: &Query) -> Vec<String> {
            db.query(q).iter().map(|d| d.name.to_string()).collect()
        }
        let page = Query {
            search: Some("example".into()),
            limit: Some(3),
            offset: 3,
            ..Default::default()
        };
        assert_eq!(
            names(&db, &page),
            ["d3.example", "d4.example", "d5.example"],
            "依查詢次數排序後分頁"
        );
        let past = Query {
            search: Some("example".into()),
            offset: 50,
            ..Default::default()
        };
        assert!(names(&db, &past).is_empty());
        assert_eq!(
            names(
                &db,
                &Query {
                    search: Some("other".into()),
                    ..Default::default()
                }
            ),
            ["other.test"]
        );
        // 只要試過跨 CDN 的
        db.get_mut("d7.example").unwrap().cross4 = Some(Box::new(Cross {
            verdict: Some("ok".into()),
            ..Default::default()
        }));
        db.get_mut("d8.example").unwrap().cross4 = Some(Box::new(Cross {
            verdict: Some("none".into()),
            ..Default::default()
        }));
        assert_eq!(
            names(
                &db,
                &Query {
                    cross: true,
                    ..Default::default()
                }
            ),
            ["d7.example"]
        );
    }

    #[test]
    fn prune_keeps_manual_and_recent() {
        let mut db = Db::new(100);
        for i in 0..100 {
            db.touch(&format!("d{i}.test"), "cloudflare", "ip", &[], &[], None);
            db.get_mut(&format!("d{i}.test")).unwrap().last_seen = i;
        }
        db.set_policy("d0.test", Policy::Never);
        assert_eq!(db.domains.len(), 100);
        db.touch("new.test", "cloudflare", "ip", &[], &[], None);
        assert!(db.domains.len() <= 91, "超過上限時降到 90%：{}", db.domains.len());
        assert!(db.get("d0.test").is_some(), "手動策略的保留");
        assert!(db.get("d1.test").is_none(), "最久沒出現的先刪");
        assert!(db.get("d99.test").is_some());
        assert!(db.get("new.test").is_some());
    }

    // ---- 磁碟預算（3.5.0 C5）----

    const DAY: u64 = 24 * 3600 * 1000;
    const NOW: u64 = 400 * DAY;

    /// 放一筆：`age_days` 天前最後出現、問過 `hits` 次、v4 的驗證結果 `verdict`
    fn put(db: &mut Db, name: &str, age_days: u64, hits: u32, verdict: Option<&str>) {
        db.touch(name, "cloudflare", "ip", &[], &[], None);
        let d = db.get_mut(name).unwrap();
        d.last_seen = NOW - age_days * DAY;
        d.hits = hits;
        if let Some(v) = verdict {
            d.v4 = Some(Box::new(Verdict {
                verdict: Some(Arc::from(v)),
                ..Default::default()
            }));
        }
    }

    /// 一個分片的資料庫（順序只看順位與時間，不受雜湊影響）
    fn one_shard() -> Db {
        let mut db = Db::new(1000);
        db.set_shards(1);
        db
    }

    #[test]
    fn budget_entries_model() {
        assert_eq!(budget_entries(None, 256), None, "沒有預算 = 不限");
        // D3：7.5 MB 的 30% ≈ 2.25 MB、256 片 → 約 1.6 萬筆（每片 1.1 KB 的固定開銷先扣掉）
        let n = budget_entries(Some(2_250 * 1024), 256).unwrap();
        assert!((16_000..17_000).contains(&n), "{n}");
        // 下限：預算小於 512 KB 當 512 KB；換算出來不到 2,000 筆也給 2,000 筆
        assert_eq!(budget_entries(Some(1), 256), budget_entries(Some(BUDGET_MIN_BYTES), 256));
        assert_eq!(budget_entries(Some(BUDGET_MIN_BYTES), 256), Some(BUDGET_MIN_ENTRIES));
        // 估計的磁碟用量跟換算互為反函數（實測 256 片 20,000 筆 2.75 MB）
        let est = budget_disk_estimate(20_000, 256);
        assert!((2_600_000..2_900_000).contains(&est), "{est}");
        assert_eq!(budget_disk_estimate(0, 256), 0);
    }

    /// 分片數只看 `cdn.maxEntries`，不跟著預算變（改分片數會重寫所有分片）
    #[test]
    fn shard_count_unchanged_by_budget() {
        let mut db = Db::new(200_000);
        assert_eq!(db.shards, 256);
        for i in 0..3000 {
            put(&mut db, &format!("d{i}.example.com"), 2, 3, None);
        }
        let limit = budget_entries(Some(BUDGET_MIN_BYTES), db.shards).unwrap();
        let plan = db.budget_plan(limit, true);
        db.budget_prune(&plan.shards, NOW);
        assert_eq!(db.shards, 256);
        assert_eq!(db.marks().len(), 256);
        assert!(db.manifest_pending.is_none() && !db.dirty, "不重寫分片清單、不整個重寫");
    }

    #[test]
    fn prune_order_one_shot_then_failed_then_oldest() {
        let mut db = one_shard();
        put(&mut db, "oneshot.example.com", 3, 1, None);
        put(&mut db, "failed-stale.example.com", 9, 5, Some("fail"));
        put(&mut db, "plain-old.example.com", 20, 5, None);
        put(&mut db, "plain-newer.example.com", 4, 5, None);
        put(&mut db, "failed-recent.example.com", 3, 5, Some("fail"));
        put(&mut db, "ok-long-gone.example.com", 40, 9, Some("ok"));
        put(&mut db, "ok.example.com", 25, 9, Some("ok"));
        put(&mut db, "today.example.com", 0, 1, None);
        let rank = |db: &Db, n: &str| Db::budget_rank(db.get(n).unwrap(), NOW);
        assert_eq!(rank(&db, "oneshot.example.com"), 0);
        assert_eq!(rank(&db, "failed-stale.example.com"), 1);
        assert_eq!(rank(&db, "plain-old.example.com"), 2);
        assert_eq!(rank(&db, "failed-recent.example.com"), 2, "失敗但 7 天內還有人問：跟一般的一樣");
        assert_eq!(rank(&db, "ok-long-gone.example.com"), 2, "驗證成功但超過 30 天沒出現：跟一般的一樣");
        assert_eq!(rank(&db, "ok.example.com"), 3);
        assert_eq!(rank(&db, "today.example.com"), 4, "今天才出現、只問過一次：不能當成一次性的");
        // 一筆一筆淘汰，看順序
        let mut gone = Vec::new();
        for keep in (0..8).rev() {
            let before: Vec<Arc<str>> = db.domains.keys().cloned().collect();
            assert_eq!(db.budget_prune(&[(0, keep)], NOW), 1);
            let dropped = before.iter().find(|k| db.get(k).is_none()).unwrap();
            gone.push(dropped.to_string());
        }
        assert_eq!(
            gone,
            [
                "oneshot.example.com",
                "failed-stale.example.com",
                "ok-long-gone.example.com",
                "plain-old.example.com",
                "plain-newer.example.com",
                "failed-recent.example.com",
                "ok.example.com",
                "today.example.com",
            ]
        );
    }

    #[test]
    fn manual_policy_and_recent_verified_kept() {
        let mut db = one_shard();
        for i in 0..20 {
            put(&mut db, &format!("old{i}.example.com"), 10 + i, 3, None);
        }
        put(&mut db, "verified.example.com", 29, 9, Some("ok"));
        put(&mut db, "in-use.example.com", 0, 2, None);
        // 手動策略：很舊、一次性，也絕不淘汰
        put(&mut db, "manual.example.com", 300, 1, None);
        db.set_policy("manual.example.com", Policy::Never);
        db.take_marks(false);
        assert_eq!(db.budget_prune(&[(0, 3)], NOW), 20);
        let mut left: Vec<&str> = db.domains.keys().map(|k| &**k).collect();
        left.sort_unstable();
        assert_eq!(left, ["in-use.example.com", "manual.example.com", "verified.example.com"]);
        assert_eq!(db.marks()[0], Mark::Important, "有淘汰的分片要重寫");
        // 額度比手動的還少：能淘汰的淘汰完就停，手動的留著
        assert_eq!(db.budget_prune(&[(0, 0)], NOW), 2);
        assert!(db.get("manual.example.com").is_some());
        // 沒超過就不動、也不標變動
        db.take_marks(false);
        assert_eq!(db.budget_prune(&[(0, 5)], NOW), 0);
        assert_eq!(db.marks()[0], Mark::Clean);
    }

    /// 平常（沒有超過預算 110%）只順便整理「本來就要寫」的分片，不為了淘汰多寫一個檔；
    /// 總筆數在預算以內時什麼都不做
    #[test]
    fn budget_piggybacks_on_shards_already_being_written() {
        let mut db = Db::new(100_000);
        db.set_shards(16);
        for i in 0..1040 {
            put(&mut db, &format!("d{i}.example.com"), 2 + (i % 50) as u64, 3, None);
        }
        db.take_marks(false);
        assert!(db.budget_plan(2000, true).shards.is_empty(), "在預算以內");
        // 預算 1,000 筆（每片 62）：超過 4%，沒有分片要寫 → 不動
        let plan = db.budget_plan(1000, true);
        assert!(plan.shards.is_empty() && !plan.sweep_started && plan.total == 1040, "{plan:?}");
        // 其中一片有新網域（重要變動）→ 只整理那一片
        db.touch("new.example.com", "cloudflare", "ip", &[], &[], None);
        let i = shard_of("new.example.com", 16);
        let plan = db.budget_plan(1000, true);
        assert_eq!(plan.forced, 0);
        assert_eq!(plan.shards, vec![(i, 62 * 9 / 10)]);
        let before = db.domains.len();
        let dropped = db.budget_prune(&plan.shards, now_ms());
        assert!(dropped > 0 && db.domains.len() == before - dropped);
        assert!(db.get("new.example.com").is_some(), "剛出現的不淘汰");
        let marked: Vec<usize> = (0..16).filter(|k| db.marks()[*k] != Mark::Clean).collect();
        assert_eq!(marked, vec![i], "其他分片沒有被動到");
    }

    /// 超過預算很多（升級後第一次套用、要淘汰超過一半）：一輪一輪來，每輪主動重寫最多 分片數 / 16 片，
    /// 每個分片只重寫一次，最後回到預算以內就停；磁碟上實際沒超過預算時不主動重寫
    #[test]
    fn first_prune_over_half_is_spread_over_rounds() {
        let mut db = Db::new(100_000);
        db.set_shards(64);
        for i in 0..6400 {
            put(&mut db, &format!("d{i}.example.com"), 2 + (i % 90) as u64, 3, None);
        }
        db.take_marks(false);
        let limit = 2560; // 每片 40 筆
                          // 磁碟上量起來沒超過預算（模型高估了）：不主動重寫
        let plan = db.budget_plan(limit, false);
        assert!(plan.shards.is_empty() && !plan.sweep_started && !db.budget_sweeping());
        let mut rewritten = vec![0u32; 64];
        let mut rounds = 0;
        loop {
            let plan = db.budget_plan(limit, true);
            assert_eq!(plan.sweep_started, rounds == 0, "只在開始時提醒一次");
            if plan.shards.is_empty() {
                break;
            }
            rounds += 1;
            assert!(plan.forced <= 4 && plan.shards.len() <= 8, "每輪上限：{plan:?}");
            let before = db.domains.len();
            let dropped = db.budget_prune(&plan.shards, NOW);
            assert!(dropped <= before / 8, "一輪最多動八分之一的分片：{dropped} / {before}");
            for (i, important) in db.take_marks(false) {
                assert!(important);
                rewritten[i] += 1;
            }
            assert!(rounds <= 64, "要會結束");
        }
        // 64 片、每輪 4 片；每片淘汰到額度的 90%，所以最後一兩輪還沒輪到的分片可以不動
        assert!((14..=16).contains(&rounds), "{rounds}");
        assert!(rewritten.iter().all(|n| *n <= 1), "每個分片最多重寫一次：{rewritten:?}");
        assert!(
            db.domains.len() <= limit && db.domains.len() >= limit * 8 / 10,
            "{}",
            db.domains.len()
        );
        assert!(!db.budget_sweeping(), "回到預算以內就結束");
        // 留下來的是比較新的（原本 2～91 天平均分布；最後沒輪到的一兩片還有舊的）
        let old = db.domains.values().filter(|d| NOW - d.last_seen > 45 * DAY).count();
        assert!(old * 10 < db.domains.len(), "最舊的那批先淘汰：{old} / {}", db.domains.len());
    }

    /// 整個資料庫本來就要重寫（種子、舊版搬家、分片數改變）：寫之前一次淘汰好，不必先寫大的再寫小的
    #[test]
    fn dirty_db_is_pruned_before_the_full_rewrite() {
        let mut db = Db::new(100_000);
        db.set_shards(64);
        for i in 0..6400 {
            put(&mut db, &format!("d{i}.example.com"), 2 + (i % 90) as u64, 3, None);
        }
        db.dirty = true;
        let plan = db.budget_plan(2560, false);
        assert_eq!((plan.shards.len(), plan.forced), (64, 0));
        db.budget_prune(&plan.shards, NOW);
        assert!(db.domains.len() <= 2560);
    }

    #[test]
    fn harvest_cap_and_order() {
        let mut db = Db::new(100);
        for i in 0..(HARVEST_MAX as u32 + 5) {
            db.add_harvest("cloudflare", IpAddr::from(std::net::Ipv4Addr::from(0x6810_0000 + i)));
        }
        let l = db.harvest_of("cloudflare", false);
        assert_eq!(l.len(), HARVEST_MAX);
        assert_eq!(l[0].to_string(), "104.16.0.5", "最早加入的先淘汰");
        let mut db2 = Db::new(100);
        db2.load_harvest(&db.harvest_json()).unwrap();
        assert_eq!(db2.harvest_of("cloudflare", false), l);
    }

    #[test]
    fn verdict_merge_and_csv() {
        let mut db = Db::new(100);
        db.touch("a.test", "cloudflare", "ip", &["104.21.0.5".parse().unwrap()], &[], Some("a.test"));
        db.set_verdict("a.test", 4, |v| {
            v.verdict = Some(util::intern("fail"));
            v.reason = Some("x, \"y\"".into());
        });
        db.set_verdict("a.test", 4, |v| v.verdict = Some(util::intern("ok")));
        let v = db.get("a.test").unwrap().v4.as_ref().unwrap();
        assert!(v.is("ok"));
        assert_eq!(v.reason.as_deref(), Some("x, \"y\""), "舊欄位保留（同 2.x 的合併）");
        let csv = Db::to_csv(&db.query(&Query::default()));
        assert!(csv.contains("a.test,cloudflare,ip,a.test,1,"));
        assert!(csv.contains("\"x, \"\"y\"\"\""));
    }
}
