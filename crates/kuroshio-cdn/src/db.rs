//! CDN 網域資料庫（對齊 2.x `lib/cdn/cdn-db.js`）：蒐集各 CDN 的網域、驗證結果、ECS 突破結果、
//! 跨 CDN 結果、手動策略，以及節點池工作用的候選 IP（harvest）。
//!
//! 每筆紀錄保持精簡：常見字串（CDN 名稱、判定）共用、選填的子物件放在 `Box` 裡，沒有就只佔一個指標。
//! 筆數上限 `cdn.maxEntries`（依硬體等級），超過時刪掉最久沒出現的（手動設定策略的不刪）。

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
}

/// 分段寫快照時要寫的網域：（查詢次數，名稱）
pub type DumpKeys = Vec<(u32, Arc<str>)>;

/// 分片的檔名（相對於狀態目錄；寫入器會加上 `.zst`）：`cdn/domains/16-003.json`。
/// 檔名帶著 N：分片數改變時新舊兩組檔名不會互相蓋掉，新的一組寫完（清單也更新）才刪舊的
pub fn shard_file(n: usize, i: usize) -> String {
    format!("{SHARD_DIR}/{n}-{i:03}.json")
}

/// 網域屬於哪個分片：FNV-1a（各平台、各版本都一樣，不能用 std 的雜湊）
pub fn shard_of(name: &str, n: usize) -> usize {
    let mut h: u32 = 0x811c_9dc5;
    for b in name.as_bytes() {
        h ^= *b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    (h as usize) & (n.max(1) - 1)
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
            list.retain(|d| d.get("name").and_then(Value::as_str).is_none_or(|k| shard_of(k, n) != i));
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
        }
    }

    /// 改分片數（測試、量測用；正式執行由筆數上限決定）
    pub fn set_shards(&mut self, n: usize) {
        self.shards = n.clamp(1, MAX_SHARDS).next_power_of_two();
        self.marks = vec![Mark::Clean; self.shards];
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
                    tracing::warn!("CDN 網域分片 {rel} 不見了，略過（其他分片照常載入）");
                    out.bad_shards.push(i);
                }
            }
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

    pub fn get(&self, name: &str) -> Option<&Domain> {
        self.domains.get(name)
    }

    pub fn get_mut(&mut self, name: &str) -> Option<&mut Domain> {
        self.domains.get_mut(name)
    }

    /// 每次解析到 CDN 網域時呼叫：登記 / 更新統計
    pub fn touch(&mut self, name: &str, provider: &str, via: &str, ips4: &[IpAddr], ips6: &[IpAddr], cname: Option<&str>) -> &mut Domain {
        let now = now_ms();
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
        let e = self.domains.get_mut(name).unwrap();
        // 剛新增的（hits 還是 0）算重要變動；其他只有計數變了的，不單獨觸發寫入
        let mut important = e.hits == 0;
        e.last_seen = now;
        e.hits = e.hits.saturating_add(1);
        if !provider.is_empty() && e.provider() != Some(provider) {
            e.provider = Field::Val(util::intern(provider));
            e.via = Field::Val(util::intern(via));
            important = true;
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
        e
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
            }
        }
        json!({
            "explored": explored, "ok": ok, "fail": fail, "none": none, "byTo": by_to,
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
            .collect();
        let key = |e: &Domain| -> u64 {
            match q.sort.as_deref().unwrap_or("hits") {
                "lastSeen" => e.last_seen,
                "firstSeen" => e.first_seen,
                _ => e.hits as u64,
            }
        };
        arr.sort_by(|a, b| key(b).cmp(&key(a)).then_with(|| a.name.cmp(&b.name)));
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
    fn record_size() {
        // 每筆網域的固定大小（64 位元）：選填的子物件都在 Box 裡、名稱跟鍵共用、IP 用定長切片
        assert!(std::mem::size_of::<Domain>() <= 192, "{}", std::mem::size_of::<Domain>());
        assert_eq!(std::mem::size_of::<Extra>(), std::mem::size_of::<usize>());
        let mut db = Db::new(100);
        db.touch("a.test", "cloudflare", "ip", &[], &[], None);
        let (k, v) = db.domains.iter().next().unwrap();
        assert!(Arc::ptr_eq(k, &v.name), "名稱只存一份");
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
