//! 備份、換機與分享學習資料（`.kuroshio` 檔）
//!
//! 檔案格式：zstd 壓縮的 JSON
//! `{ format: "kuroshio-backup", version: 1, kind: "full" | "share", exportedAt, core, files: { 相對路徑: {json} | {text} | {b64} } }`
//!
//! - `full`（換路由器）：狀態目錄裡學到的全部資料、自訂規則、社群身分與好友。含私鑰，只給自己用。
//! - `share`（分享給朋友）：CDN 網域驗證紀錄（去掉次數、時間、手動設定）、台灣節點池、永久 IPv6 節點、
//!   上游評測結果、汙染 DNS 黑名單。沒有身分、金鑰、統計、自訂規則。
//!
//! 匯入一律「合併」，不直接覆蓋：本機已有的資料比較新就留著。
//! 服務執行中時，記憶體裡的狀態在關機時會寫回檔案、蓋掉合併結果，所以管理 API 只把檔案放到
//! `import-pending.kuroshio`，再讓服務在程式內重新啟動：舊的一輪先把記憶體寫出，新的一輪在
//! 讀取任何狀態之前（`app::start` 最前面）合併，結果存在 `import-last.json`。

use crate::persist::write_atomic;
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use kuroshio_config::get;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

pub const FORMAT: &str = "kuroshio-backup";
pub const VERSION: u64 = 1;
/// 檔案本身與解壓後的大小上限
pub const MAX_BYTES: usize = 64 << 20;
/// 等服務重新啟動時合併的檔案（狀態目錄裡）
pub const PENDING_FILE: &str = "import-pending.kuroshio";
/// 上一次匯入的結果（狀態目錄裡）
pub const LAST_FILE: &str = "import-last.json";

const DOMAINS: &str = "cdn-domains.json";
const POOLS: &str = "cdn/pools.json";
const V6: &str = "cdn/v6-nodes.json";
const HARVEST: &str = "cdn/harvest.json";
const ZONE: &str = "cdn/ip-zone.json";
const UPSTREAMS: &str = "upstreams.json";
const BLACKLIST: &str = "blacklist.txt";
const STATS: &str = crate::app::STATS_FILE;
const HOT: &str = crate::app::HOT_NAMES;
const CUSTOM: &str = "custom-rules.txt";
const COMMUNITY: &str = "community/";
const KEYS: &str = "community-keys/";
const KEY_FILES: [&str; 3] = ["key.pem", "key.old.pem", "identity.json"];

/// 分享檔只能有這些
const SHARE_FILES: [&str; 5] = [DOMAINS, POOLS, V6, UPSTREAMS, BLACKLIST];
/// 完整備份的固定檔案（另外還有 community/*、community-keys/*）
const FULL_FILES: [&str; 10] = [DOMAINS, POOLS, V6, HARVEST, ZONE, UPSTREAMS, BLACKLIST, STATS, HOT, CUSTOM];

/// 分享時從每個網域拿掉的欄位（使用習慣、手動設定）
const PRIVATE_DOMAIN_FIELDS: [&str; 4] = ["hits", "firstSeen", "lastSeen", "policy"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// 換路由器：全部資料（含社群身分）
    Full,
    /// 分享給朋友：只有公開的學習資料
    Share,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Full => "full",
            Kind::Share => "share",
        }
    }
    pub fn parse(s: &str) -> Option<Kind> {
        match s {
            "full" => Some(Kind::Full),
            "share" => Some(Kind::Share),
            _ => None,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Kind::Full => "完整備份",
            Kind::Share => "分享檔",
        }
    }
}

fn label(key: &str) -> &'static str {
    match key {
        DOMAINS => "CDN 網域驗證紀錄",
        POOLS => "台灣節點池",
        V6 => "永久 IPv6 節點",
        HARVEST => "CDN 候選 IP",
        ZONE => "IP 網段分類",
        UPSTREAMS => "上游評測結果",
        BLACKLIST => "汙染 DNS 黑名單",
        STATS => "統計歷史",
        HOT => "常用網域（開機預熱）",
        CUSTOM => "自訂過濾規則",
        k if k.starts_with(COMMUNITY) || k.starts_with(KEYS) => "社群身分與好友",
        _ => "其他",
    }
}

/// 一個檔案的內容
#[derive(Debug, Clone, PartialEq)]
pub enum Data {
    Json(Value),
    Text(String),
    Bin(Vec<u8>),
}

impl Data {
    fn to_value(&self) -> Value {
        match self {
            Data::Json(v) => json!({ "json": v }),
            Data::Text(t) => json!({ "text": t }),
            Data::Bin(b) => json!({ "b64": base64::engine::general_purpose::STANDARD.encode(b) }),
        }
    }
    fn from_value(v: &Value) -> Option<Data> {
        let o = v.as_object()?;
        if o.len() != 1 {
            return None;
        }
        if let Some(j) = o.get("json") {
            return Some(Data::Json(j.clone()));
        }
        if let Some(t) = o.get("text") {
            return Some(Data::Text(t.as_str()?.to_string()));
        }
        let b = o.get("b64")?.as_str()?;
        base64::engine::general_purpose::STANDARD.decode(b).ok().map(Data::Bin)
    }
    /// 寫到磁碟的位元組
    fn bytes(&self) -> Vec<u8> {
        match self {
            Data::Json(v) => serde_json::to_vec(v).unwrap_or_default(),
            Data::Text(t) => t.as_bytes().to_vec(),
            Data::Bin(b) => b.clone(),
        }
    }
    fn text(&self) -> Option<&str> {
        match self {
            Data::Text(t) => Some(t),
            _ => None,
        }
    }
    fn json(&self) -> Option<&Value> {
        match self {
            Data::Json(v) => Some(v),
            _ => None,
        }
    }
}

/// 檔案依副檔名決定存法：.json → json（解析不了就略過）、.txt / .pem → text、其他 → b64
fn read_data(path: &Path, key: &str) -> Option<Data> {
    let b = std::fs::read(path).ok()?;
    if key.ends_with(".json") {
        match serde_json::from_slice(&b) {
            Ok(v) => Some(Data::Json(v)),
            Err(e) => {
                warn!("備份略過 {}：JSON 格式錯誤（{e}）", path.display());
                None
            }
        }
    } else if key.ends_with(".txt") || key.ends_with(".pem") {
        Some(Data::Text(String::from_utf8_lossy(&b).into_owned()))
    } else {
        Some(Data::Bin(b))
    }
}

/// 各種資料在這台機器上的位置
#[derive(Debug, Clone)]
pub struct Locations {
    /// 狀態目錄（`system.persistDir`）
    pub state: PathBuf,
    /// 上游評測結果（`upstream.autoStateFile`）
    pub upstreams: PathBuf,
    /// 社群金鑰目錄（`community.dir`）
    pub key_dir: PathBuf,
    /// 自訂規則（`filter.customRules` 的第一個）
    pub custom_rules: Option<PathBuf>,
}

fn rel(base: &Path, p: &str) -> PathBuf {
    let pp = Path::new(p);
    if pp.is_absolute() {
        pp.to_path_buf()
    } else {
        base.join(pp.strip_prefix("./").unwrap_or(pp))
    }
}

fn same_dir(a: &Path, b: &Path) -> bool {
    let c = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    a == b || c(a) == c(b)
}

impl Locations {
    pub fn from_cfg(cfg: &Value) -> Locations {
        let state = crate::app::persist_dir(cfg);
        let base = state.parent().map(Path::to_path_buf).unwrap_or_else(|| state.clone());
        let s = |k: &str| get(cfg, k).and_then(Value::as_str).filter(|s| !s.is_empty());
        let up = s("upstream.autoStateFile").unwrap_or("./state/upstreams.json");
        Locations {
            upstreams: kuroshio_jobs::resolve_path(&state, &base, up),
            key_dir: s("community.dir").map(|d| rel(&base, d)).unwrap_or_else(|| base.join("community")),
            custom_rules: get(cfg, "filter.customRules")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .and_then(Value::as_str)
                .filter(|p| !p.is_empty())
                .map(|p| rel(&base, p)),
            state,
        }
    }

    /// 只有狀態目錄（測試用）：其他都放在狀態目錄裡的預設位置
    pub fn in_dir(state: &Path) -> Locations {
        Locations {
            state: state.to_path_buf(),
            upstreams: state.join(UPSTREAMS),
            key_dir: state.join("community"),
            custom_rules: Some(state.join(CUSTOM)),
        }
    }

    fn community_dir(&self) -> PathBuf {
        self.state.join("community")
    }

    /// 金鑰目錄跟狀態目錄裡的 community/ 是不是不同的地方（同一個時金鑰只放在 community/）
    fn keys_separate(&self) -> bool {
        !same_dir(&self.key_dir, &self.community_dir())
    }

    /// 備份裡的相對路徑 → 這台機器上的檔案
    fn path_of(&self, key: &str) -> Option<PathBuf> {
        match key {
            UPSTREAMS => Some(self.upstreams.clone()),
            CUSTOM => self.custom_rules.clone(),
            k => {
                if let Some(n) = k.strip_prefix(KEYS) {
                    Some(self.key_dir.join(n))
                } else if let Some(n) = k.strip_prefix(COMMUNITY) {
                    Some(self.community_dir().join(n))
                } else {
                    Some(self.state.join(k))
                }
            }
        }
    }

    pub fn pending_file(&self) -> PathBuf {
        self.state.join(PENDING_FILE)
    }

    pub fn last_file(&self) -> PathBuf {
        self.state.join(LAST_FILE)
    }
}

/// 一份備份
#[derive(Debug, Clone)]
pub struct Bundle {
    pub kind: Kind,
    pub exported_at: u64,
    pub core: String,
    pub files: BTreeMap<String, Data>,
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 檔名裡的一段：只有英數與 `._-`，不是隱藏檔
fn safe_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 64
        && !n.starts_with('.')
        && !n.ends_with(".tmp")
        && n.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

/// 這個相對路徑可不可以出現在這種備份裡（防止寫到狀態目錄以外的地方）
pub fn allowed(kind: Kind, key: &str) -> bool {
    if key.is_empty() || key.contains("..") || key.contains('\\') || key.contains(':') || key.starts_with('/') {
        return false;
    }
    match kind {
        Kind::Share => SHARE_FILES.contains(&key),
        Kind::Full => {
            FULL_FILES.contains(&key)
                || key.strip_prefix(COMMUNITY).is_some_and(safe_name)
                || key.strip_prefix(KEYS).is_some_and(|n| KEY_FILES.contains(&n))
        }
    }
}

/// 分享用：拿掉每個網域的次數、時間、手動設定
fn strip_domains(v: &mut Value) {
    if let Some(list) = v.get_mut("domains").and_then(Value::as_array_mut) {
        for d in list.iter_mut().filter_map(Value::as_object_mut) {
            for k in PRIVATE_DOMAIN_FIELDS {
                d.remove(k);
            }
        }
    }
}

/// 從磁碟組出備份（服務執行中時，呼叫前先把記憶體裡的狀態寫出）
pub fn export(loc: &Locations, kind: Kind) -> Bundle {
    let mut files = BTreeMap::new();
    let list: &[&str] = match kind {
        Kind::Share => &SHARE_FILES,
        Kind::Full => &FULL_FILES,
    };
    for key in list {
        let Some(path) = loc.path_of(key) else { continue };
        let Some(mut d) = read_data(&path, key) else { continue };
        if kind == Kind::Share && *key == DOMAINS {
            if let Data::Json(v) = &mut d {
                strip_domains(v);
            }
        }
        files.insert(key.to_string(), d);
    }
    if kind == Kind::Full {
        if let Ok(rd) = std::fs::read_dir(loc.community_dir()) {
            let mut names: Vec<String> = rd
                .flatten()
                .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| safe_name(n))
                .collect();
            names.sort();
            for n in names {
                let key = format!("{COMMUNITY}{n}");
                if let Some(d) = read_data(&loc.community_dir().join(&n), &key) {
                    files.insert(key, d);
                }
            }
        }
        if loc.keys_separate() {
            for n in KEY_FILES {
                let key = format!("{KEYS}{n}");
                if let Some(d) = read_data(&loc.key_dir.join(n), &key) {
                    files.insert(key, d);
                }
            }
        }
    }
    Bundle {
        kind,
        exported_at: now_ms(),
        core: env!("CARGO_PKG_VERSION").to_string(),
        files,
    }
}

impl Bundle {
    /// 壓縮成 `.kuroshio` 檔
    pub fn encode(&self) -> Vec<u8> {
        let files: Map<String, Value> = self.files.iter().map(|(k, d)| (k.clone(), d.to_value())).collect();
        let v = json!({
            "format": FORMAT, "version": VERSION, "kind": self.kind.name(),
            "exportedAt": self.exported_at, "core": self.core, "files": files,
        });
        let raw = serde_json::to_vec(&v).unwrap_or_default();
        zstd::bulk::compress(&raw, 9).unwrap_or_default()
    }

    /// 讀 `.kuroshio` 檔並檢查（格式、版本、大小、每個路徑）
    pub fn decode(b: &[u8]) -> Result<Bundle> {
        if b.len() > MAX_BYTES {
            bail!("檔案太大（超過 {} MB）", MAX_BYTES >> 20);
        }
        let raw = decompress(b, MAX_BYTES)?;
        let v: Value = serde_json::from_slice(&raw).map_err(|_| anyhow!("不是黑潮 DNS 的備份檔（內容不是 JSON）"))?;
        if v.get("format").and_then(Value::as_str) != Some(FORMAT) {
            bail!("不是黑潮 DNS 的備份檔（format 不對）");
        }
        let ver = v
            .get("version")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("備份檔沒有版本號"))?;
        if ver == 0 || ver > VERSION {
            bail!("備份檔是新版程式產生的（格式版本 {ver}），請先更新黑潮 DNS 再匯入");
        }
        let kind = v
            .get("kind")
            .and_then(Value::as_str)
            .and_then(Kind::parse)
            .ok_or_else(|| anyhow!("備份檔的種類（kind）不對"))?;
        let obj = v
            .get("files")
            .and_then(Value::as_object)
            .ok_or_else(|| anyhow!("備份檔沒有 files"))?;
        let mut files = BTreeMap::new();
        for (k, fv) in obj {
            if !allowed(kind, k) {
                bail!("備份檔裡有不認識或不安全的路徑：{k}");
            }
            let d = Data::from_value(fv).ok_or_else(|| anyhow!("備份檔裡 {k} 的內容格式不對"))?;
            // 各檔案的基本型態
            let ok = match k.as_str() {
                DOMAINS => d.json().is_some_and(|j| j.get("domains").is_some_and(Value::is_array)),
                POOLS | V6 => d.json().is_some_and(|j| j.get("providers").is_some_and(Value::is_object)),
                UPSTREAMS => d.json().is_some_and(Value::is_object),
                BLACKLIST | CUSTOM => d.text().is_some(),
                _ => true,
            };
            if !ok {
                bail!("備份檔裡 {k} 的內容格式不對");
            }
            files.insert(k.clone(), d);
        }
        Ok(Bundle {
            kind,
            exported_at: v.get("exportedAt").and_then(Value::as_u64).unwrap_or(0),
            core: v.get("core").and_then(Value::as_str).unwrap_or("").chars().take(40).collect(),
            files,
        })
    }

    /// 內容摘要（匯入前顯示）
    pub fn preview(&self) -> Value {
        let mut groups: Vec<(String, &'static str, u64, &'static str)> = Vec::new();
        let mut community = 0u64;
        for (k, d) in &self.files {
            if k.starts_with(COMMUNITY) || k.starts_with(KEYS) {
                community += 1;
                continue;
            }
            let (n, unit) = count(k, d);
            groups.push((k.clone(), label(k), n, unit));
        }
        if community > 0 {
            groups.push(("community".into(), label(COMMUNITY), community, "個檔案"));
        }
        json!({
            "kind": self.kind.name(), "kindLabel": self.kind.label(),
            "exportedAt": self.exported_at, "core": self.core,
            "files": groups.iter().map(|(f, l, n, u)| json!({ "file": f, "label": l, "count": n, "unit": u })).collect::<Vec<_>>(),
        })
    }
}

fn rule_lines(t: &str) -> impl Iterator<Item = &str> {
    t.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('!'))
}

fn count(key: &str, d: &Data) -> (u64, &'static str) {
    let arr = |v: Option<&Value>| v.and_then(Value::as_array).map(|a| a.len() as u64).unwrap_or(0);
    let providers = |j: &Value| -> Vec<Value> {
        j.get("providers")
            .and_then(Value::as_object)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    };
    match (key, d) {
        (DOMAINS, Data::Json(j)) => (arr(j.get("domains")), "個網域"),
        (POOLS, Data::Json(j)) => (providers(j).iter().map(|p| arr(p.get("v4")) + arr(p.get("v6"))).sum(), "個節點"),
        (V6, Data::Json(j)) => (
            providers(j)
                .iter()
                .map(|p| p.as_object().map(|o| o.len() as u64).unwrap_or(0))
                .sum(),
            "個節點",
        ),
        (UPSTREAMS, Data::Json(j)) => (arr(j.get("selected")), "台上游"),
        (BLACKLIST | CUSTOM, Data::Text(t)) => (rule_lines(t).count() as u64, "行"),
        _ => (d.bytes().len() as u64, "bytes"),
    }
}

/// zstd 解壓，超過 `max` 就中止（邊解邊數）
fn decompress(b: &[u8], max: usize) -> Result<Vec<u8>> {
    let dec = zstd::stream::read::Decoder::new(b).map_err(|_| anyhow!("不是黑潮 DNS 的備份檔（無法解壓）"))?;
    let mut out = Vec::new();
    let mut lim = dec.take(max as u64 + 1);
    lim.read_to_end(&mut out)
        .map_err(|_| anyhow!("不是黑潮 DNS 的備份檔（無法解壓）"))?;
    if out.len() > max {
        bail!("備份檔解壓後太大（超過 {} MB）", max >> 20);
    }
    Ok(out)
}

// ---------------------------------------------------------------- 合併

/// 一類資料的合併結果
#[derive(Debug, Clone, Default)]
struct Item {
    file: String,
    label: &'static str,
    added: u64,
    updated: u64,
    kept: u64,
    skipped: u64,
    note: Option<String>,
    error: Option<String>,
}

impl Item {
    fn new(file: &str) -> Item {
        Item {
            file: file.to_string(),
            label: label(file),
            ..Default::default()
        }
    }
    fn json(&self) -> Value {
        json!({
            "file": self.file, "label": self.label, "added": self.added, "updated": self.updated,
            "kept": self.kept, "skipped": self.skipped, "note": self.note, "error": self.error,
        })
    }
}

fn read_json(p: &Path) -> Option<Value> {
    std::fs::read(p).ok().and_then(|b| serde_json::from_slice(&b).ok())
}

fn write_json(p: &Path, v: &Value) -> Result<()> {
    write_atomic(p, &serde_json::to_vec(v)?).with_context(|| format!("寫入 {} 失敗", p.display()))
}

/// 網域最後一次驗證的時間（v4、v6、跨 CDN、ECS、基準）
fn verified_at(d: &Value) -> u64 {
    ["v4", "v6", "cross4", "ecs", "base"]
        .iter()
        .filter_map(|k| d.get(*k)?.get("at")?.as_u64())
        .max()
        .unwrap_or(0)
}

/// 3.0 的網域欄位（其他欄位是不認識的，以本機為準保留）
const DOMAIN_FIELDS: [&str; 16] = [
    "name",
    "provider",
    "via",
    "cname",
    "firstSeen",
    "lastSeen",
    "hits",
    "ips4",
    "ips6",
    "policy",
    "v4",
    "v6",
    "base",
    "ecs",
    "cross4",
    "best",
];

fn merge_domains(local: Option<Value>, mut incoming: Value, now: u64, it: &mut Item) -> Value {
    let inc: Vec<Value> = incoming
        .get_mut("domains")
        .and_then(Value::as_array_mut)
        .map(std::mem::take)
        .unwrap_or_default();
    let mut base = local.filter(|l| l.get("domains").is_some_and(Value::is_array)).unwrap_or_else(|| {
        // 本機沒有：用匯入的檔案（不含網域，下面加）
        incoming.clone()
    });
    let list = base
        .as_object_mut()
        .map(|o| o.entry("domains").or_insert_with(|| json!([])))
        .and_then(Value::as_array_mut);
    let Some(list) = list else { return base };
    let mut index: HashMap<String, usize> = HashMap::new();
    for (i, d) in list.iter().enumerate() {
        if let Some(n) = d.get("name").and_then(Value::as_str) {
            index.insert(n.to_string(), i);
        }
    }
    for mut d in inc {
        let Some(name) = d.get("name").and_then(Value::as_str).map(str::to_string) else {
            it.skipped += 1;
            continue;
        };
        if !d.is_object() {
            it.skipped += 1;
            continue;
        }
        match index.get(&name) {
            None => {
                // 新網域：分享檔沒有時間，設成現在（每小時的複驗只處理最近出現過的網域）
                let o = d.as_object_mut().unwrap();
                for k in ["firstSeen", "lastSeen"] {
                    if o.get(k).and_then(Value::as_u64).unwrap_or(0) == 0 {
                        o.insert(k.into(), json!(now));
                    }
                }
                index.insert(name, list.len());
                list.push(d);
                it.added += 1;
            }
            Some(&i) => {
                let l = &list[i];
                if verified_at(&d) <= verified_at(l) {
                    it.kept += 1;
                    continue;
                }
                let lo = l.as_object().cloned().unwrap_or_default();
                let o = d.as_object_mut().unwrap();
                // 本機的使用習慣與手動設定不動
                match lo.get("hits") {
                    Some(h) => o.insert("hits".into(), h.clone()),
                    None => o.remove("hits"),
                };
                match lo.get("policy") {
                    Some(p) => o.insert("policy".into(), p.clone()),
                    None => o.remove("policy"),
                };
                let t = |m: &Map<String, Value>, k: &str| m.get(k).and_then(Value::as_u64).filter(|x| *x > 0);
                if let Some(f) = [t(&lo, "firstSeen"), t(o, "firstSeen")].into_iter().flatten().min() {
                    o.insert("firstSeen".into(), json!(f));
                }
                if let Some(f) = [t(&lo, "lastSeen"), t(o, "lastSeen")].into_iter().flatten().max() {
                    o.insert("lastSeen".into(), json!(f));
                }
                // 本機有、匯入的沒有的未知欄位（新版程式加的）保留
                for (k, v) in &lo {
                    if !DOMAIN_FIELDS.contains(&k.as_str()) && !o.contains_key(k) {
                        o.insert(k.clone(), v.clone());
                    }
                }
                list[i] = d;
                it.updated += 1;
            }
        }
    }
    base
}

/// 節點池：每家的 v4 / v6 依 IP 聯集，本機的優先
fn merge_pools(local: Option<Value>, incoming: Value, it: &mut Item) -> Value {
    let Some(mut base) = local.filter(|l| l.get("providers").is_some_and(Value::is_object)) else {
        it.added += count(POOLS, &Data::Json(incoming.clone())).0;
        return incoming;
    };
    let lp = base["providers"].as_object_mut().unwrap();
    for (p, ip) in incoming.get("providers").and_then(Value::as_object).cloned().unwrap_or_default() {
        match lp.get_mut(&p).and_then(Value::as_object_mut) {
            None => {
                it.added += count(POOLS, &Data::Json(json!({ "providers": { "x": ip.clone() } }))).0;
                lp.insert(p, ip);
            }
            Some(lo) => {
                for fam in ["v4", "v6"] {
                    let inc = ip.get(fam).and_then(Value::as_array).cloned().unwrap_or_default();
                    if inc.is_empty() {
                        continue;
                    }
                    let arr = lo.entry(fam).or_insert_with(|| json!([]));
                    let Some(arr) = arr.as_array_mut() else { continue };
                    let have: HashSet<String> = arr.iter().filter_map(|n| n.get("ip")?.as_str().map(str::to_string)).collect();
                    for n in inc {
                        match n.get("ip").and_then(Value::as_str) {
                            Some(x) if !have.contains(x) => {
                                arr.push(n);
                                it.added += 1;
                            }
                            Some(_) => it.kept += 1,
                            None => it.skipped += 1,
                        }
                    }
                }
                // 其他欄位：本機沒有的才補
                if let Some(io) = ip.as_object() {
                    for (k, v) in io {
                        if k != "v4" && k != "v6" && !lo.contains_key(k) {
                            lo.insert(k.clone(), v.clone());
                        }
                    }
                }
            }
        }
    }
    base
}

/// 永久 IPv6 節點：providers.{家}.{IP} 聯集，本機的優先
fn merge_v6(local: Option<Value>, incoming: Value, it: &mut Item) -> Value {
    let Some(mut base) = local.filter(|l| l.get("providers").is_some_and(Value::is_object)) else {
        it.added += count(V6, &Data::Json(incoming.clone())).0;
        return incoming;
    };
    let lp = base["providers"].as_object_mut().unwrap();
    for (p, nodes) in incoming.get("providers").and_then(Value::as_object).cloned().unwrap_or_default() {
        let Some(nodes) = nodes.as_object() else { continue };
        let lo = lp.entry(p).or_insert_with(|| json!({}));
        let Some(lo) = lo.as_object_mut() else { continue };
        for (ip, n) in nodes {
            if lo.contains_key(ip) {
                it.kept += 1;
            } else {
                lo.insert(ip.clone(), n.clone());
                it.added += 1;
            }
        }
    }
    base
}

/// `generatedAt`：數字（毫秒）或 ISO 字串
fn generated_at(v: &Value) -> Option<String> {
    match v.get("generatedAt")? {
        Value::Number(n) => n.as_u64().map(kuroshio_jobs::time::iso_string),
        Value::String(s) => Some(s.clone()),
        _ => None,
    }
}

fn first_token(line: &str) -> Option<&str> {
    let l = line.split('#').next().unwrap_or("").trim();
    l.split_whitespace().next()
}

/// 黑名單：依每行第一個欄位（IP / 網址）聯集，本機的註解保留
fn merge_blacklist(local: Option<String>, incoming: &str, it: &mut Item) -> Option<String> {
    let Some(mut text) = local else {
        it.added += incoming.lines().filter_map(first_token).count() as u64;
        return Some(incoming.to_string());
    };
    let mut have: HashSet<String> = text.lines().filter_map(first_token).map(str::to_string).collect();
    let mut add = Vec::new();
    for line in incoming.lines() {
        let Some(tok) = first_token(line) else { continue };
        if have.insert(tok.to_string()) {
            add.push(line.trim().to_string());
            it.added += 1;
        } else {
            it.kept += 1;
        }
    }
    if add.is_empty() {
        return None;
    }
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&add.join("\n"));
    text.push('\n');
    Some(text)
}

fn squash(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

/// 自訂規則：本機還是預設內容就直接換掉；改過的話只把本機沒有的規則加在最後
fn merge_custom(local: Option<String>, incoming: &str, now: u64, it: &mut Item) -> Option<String> {
    let default = squash(crate::filtering::DEFAULT_CUSTOM_RULES);
    match local {
        None => {
            it.added += rule_lines(incoming).count() as u64;
            Some(incoming.to_string())
        }
        Some(l) if squash(&l) == squash(incoming) => {
            it.kept += rule_lines(&l).count() as u64;
            None
        }
        Some(l) if squash(&l) == default => {
            it.updated += rule_lines(incoming).count() as u64;
            it.note = Some("本機還是預設規則，直接換成備份裡的".into());
            Some(incoming.to_string())
        }
        Some(mut l) => {
            let have: HashSet<&str> = rule_lines(&l).collect();
            let add: Vec<&str> = rule_lines(incoming).filter(|r| !have.contains(r)).collect();
            let mut seen = HashSet::new();
            let add: Vec<&str> = add.into_iter().filter(|r| seen.insert(*r)).collect();
            it.kept += have.len() as u64;
            if add.is_empty() {
                return None;
            }
            it.added += add.len() as u64;
            it.note = Some("本機改過規則：只把沒有的規則加在檔案最後".into());
            if !l.ends_with('\n') {
                l.push('\n');
            }
            let date = kuroshio_jobs::time::local_date_str(now);
            l.push_str(&format!("\n# ── 從備份匯入（{date}）──\n{}\n", add.join("\n")));
            Some(l)
        }
    }
}

/// 合併到磁碟上的檔案（服務要先停下來，或在啟動最前面呼叫）；回傳結果報告
pub fn merge(loc: &Locations, b: &Bundle) -> Value {
    let now = now_ms();
    let mut items: Vec<Item> = Vec::new();
    let mut put = |it: Item| items.push(it);
    let path = |k: &str| loc.path_of(k).unwrap_or_else(|| loc.state.join(k));
    let write = |it: &mut Item, p: &Path, bytes: &[u8]| {
        if let Err(e) = write_atomic(p, bytes) {
            it.error = Some(format!("寫入 {} 失敗：{e}", p.display()));
        }
    };

    if let Some(Data::Json(inc)) = b.files.get(DOMAINS) {
        let mut it = Item::new(DOMAINS);
        let p = path(DOMAINS);
        let merged = merge_domains(read_json(&p), inc.clone(), now, &mut it);
        if it.added + it.updated > 0 {
            if let Err(e) = write_json(&p, &merged) {
                it.error = Some(format!("{e:#}"));
            }
        }
        put(it);
    }
    for (key, f) in [(POOLS, merge_pools as fn(Option<Value>, Value, &mut Item) -> Value), (V6, merge_v6)] {
        if let Some(Data::Json(inc)) = b.files.get(key) {
            let mut it = Item::new(key);
            let p = path(key);
            let merged = f(read_json(&p), inc.clone(), &mut it);
            if it.added > 0 {
                if let Err(e) = write_json(&p, &merged) {
                    it.error = Some(format!("{e:#}"));
                }
            }
            put(it);
        }
    }
    if let Some(Data::Json(inc)) = b.files.get(UPSTREAMS) {
        let mut it = Item::new(UPSTREAMS);
        let p = path(UPSTREAMS);
        let local = read_json(&p);
        let newer = match (&local, generated_at(inc)) {
            (None, _) => true,
            (Some(l), Some(i)) => !matches!(generated_at(l), Some(lg) if lg >= i),
            (Some(_), None) => false,
        };
        if newer {
            if local.is_some() {
                it.updated = 1;
            } else {
                it.added = 1;
            }
            if let Err(e) = write_json(&p, inc) {
                it.error = Some(format!("{e:#}"));
            }
        } else {
            it.kept = 1;
            it.note = Some("本機的評測結果比較新".into());
        }
        put(it);
    }
    if let Some(Data::Text(inc)) = b.files.get(BLACKLIST) {
        let mut it = Item::new(BLACKLIST);
        let p = path(BLACKLIST);
        if let Some(t) = merge_blacklist(std::fs::read_to_string(&p).ok(), inc, &mut it) {
            write(&mut it, &p, t.as_bytes());
        }
        put(it);
    }
    // 只有完整備份有：本機沒有才用
    if b.kind == Kind::Full {
        for key in [HARVEST, ZONE, STATS, HOT] {
            let Some(d) = b.files.get(key) else { continue };
            let mut it = Item::new(key);
            let p = path(key);
            if p.exists() {
                it.kept = 1;
                it.note = Some("本機已經有，沒有覆蓋".into());
            } else {
                it.added = 1;
                write(&mut it, &p, &d.bytes());
            }
            put(it);
        }
        if let Some(Data::Text(inc)) = b.files.get(CUSTOM) {
            let mut it = Item::new(CUSTOM);
            match loc.custom_rules.clone() {
                None => {
                    it.skipped = rule_lines(inc).count() as u64;
                    it.note = Some("設定裡沒有自訂規則檔（filter.customRules）".into());
                }
                Some(p) => {
                    if let Some(t) = merge_custom(std::fs::read_to_string(&p).ok(), inc, now, &mut it) {
                        write(&mut it, &p, t.as_bytes());
                    }
                }
            }
            put(it);
        }
        let comm: Vec<(&String, &Data)> = b
            .files
            .iter()
            .filter(|(k, _)| k.starts_with(COMMUNITY) || k.starts_with(KEYS))
            .collect();
        if !comm.is_empty() {
            let mut it = Item::new(COMMUNITY);
            it.file = "community".into();
            let has_key = loc.key_dir.join("key.pem").exists();
            let has_peers = loc.community_dir().join("peers.json").exists();
            if has_key || has_peers {
                it.skipped = comm.len() as u64;
                it.note = Some("已有社群身分，沒有覆蓋".into());
            } else {
                for (k, d) in comm {
                    let Some(p) = loc.path_of(k) else { continue };
                    write(&mut it, &p, &d.bytes());
                    it.added += 1;
                }
                it.note = Some("已還原社群身分與好友".into());
            }
            put(it);
        }
    }
    let ok = items.iter().all(|i| i.error.is_none());
    json!({
        "ok": ok,
        "kind": b.kind.name(), "kindLabel": b.kind.label(),
        "exportedAt": b.exported_at, "core": b.core,
        "importedAt": now,
        "items": items.iter().map(Item::json).collect::<Vec<_>>(),
    })
}

/// 報告的文字版（指令列、日誌）
pub fn report_text(r: &Value) -> String {
    let mut out = Vec::new();
    if let Some(e) = r.get("error").and_then(Value::as_str) {
        out.push(format!("匯入失敗：{e}"));
    }
    for i in r.get("items").and_then(Value::as_array).into_iter().flatten() {
        let n = |k: &str| i.get(k).and_then(Value::as_u64).unwrap_or(0);
        let mut parts = Vec::new();
        for (k, w) in [("added", "新增"), ("updated", "更新"), ("kept", "保留本機"), ("skipped", "略過")] {
            if n(k) > 0 {
                parts.push(format!("{w} {}", n(k)));
            }
        }
        if parts.is_empty() {
            parts.push("沒有變動".into());
        }
        let mut line = format!("{}：{}", i["label"].as_str().unwrap_or("?"), parts.join("、"));
        if let Some(note) = i.get("note").and_then(Value::as_str) {
            line.push_str(&format!("（{note}）"));
        }
        if let Some(e) = i.get("error").and_then(Value::as_str) {
            line.push_str(&format!("【錯誤：{e}】"));
        }
        out.push(line);
    }
    out.join("\n")
}

/// 預覽的文字版
pub fn preview_text(p: &Value) -> String {
    let mut out = vec![format!(
        "{}（黑潮 DNS {}，{} 匯出）",
        p["kindLabel"].as_str().unwrap_or("?"),
        p["core"].as_str().unwrap_or("?"),
        p["exportedAt"]
            .as_u64()
            .map(kuroshio_jobs::time::fmt_date_time)
            .unwrap_or_else(|| "?".into())
    )];
    for f in p["files"].as_array().into_iter().flatten() {
        out.push(format!(
            "  {}：{} {}",
            f["label"].as_str().unwrap_or("?"),
            f["count"],
            f["unit"].as_str().unwrap_or("")
        ));
    }
    out.join("\n")
}

/// 管理 API 收到的檔案：檢查後放到 `import-pending.kuroshio`，等服務重新啟動時合併；回傳預覽
pub fn stage_pending(loc: &Locations, bytes: &[u8]) -> Result<Value> {
    let b = Bundle::decode(bytes)?;
    let p = loc.pending_file();
    write_atomic(&p, bytes).with_context(|| format!("寫入 {} 失敗", p.display()))?;
    Ok(b.preview())
}

/// 啟動最前面：有等著合併的備份就合併（不管成功與否都刪掉，免得每次啟動都重來）
pub fn apply_pending(loc: &Locations) -> Option<Value> {
    let p = loc.pending_file();
    let bytes = std::fs::read(&p).ok()?;
    let report = match Bundle::decode(&bytes) {
        Ok(b) => {
            let r = merge(loc, &b);
            info!("匯入{}完成：\n{}", b.kind.label(), report_text(&r));
            r
        }
        Err(e) => {
            warn!("匯入失敗：{e:#}");
            json!({ "ok": false, "error": format!("{e:#}"), "importedAt": now_ms(), "items": [] })
        }
    };
    if let Err(e) = write_json(&loc.last_file(), &report) {
        warn!("{e:#}");
    }
    if let Err(e) = std::fs::remove_file(&p) {
        warn!("無法刪除 {}：{e}", p.display());
    }
    Some(report)
}

/// `GET /api/backup/last-import`
pub fn last_import(loc: &Locations) -> Value {
    read_json(&loc.last_file()).unwrap_or(json!({ "none": true }))
}

/// 下載檔名：kuroshio-full-20261111.kuroshio
pub fn file_name(kind: Kind) -> String {
    let date = kuroshio_jobs::time::local_date_str(now_ms()).replace('-', "");
    format!("kuroshio-{}-{date}.kuroshio", kind.name())
}

/// 服務執行中：先把記憶體裡的狀態寫出（使用者自己按的，寫一次 Flash 沒關係），再從磁碟組出備份
pub fn export_running(st: &crate::app::AppState, kind: Kind) -> Vec<u8> {
    crate::app::stage_hot_names(&st.resolver, &st.persister, st.warm_names);
    crate::app::stage_sources(&st.persister, &st.snap_sources);
    if let Err(e) = st.persister.lock().unwrap().flush_all(crate::persist::now_secs()) {
        warn!("匯出前寫出快照失敗：{e}");
    }
    export(&st.backup, kind).encode()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("kuroshio-backup-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn wj(p: &Path, v: Value) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, serde_json::to_vec(&v).unwrap()).unwrap();
    }

    fn domain(name: &str, at: u64, hits: u64) -> Value {
        json!({ "name": name, "provider": "cloudflare", "firstSeen": 1000, "lastSeen": 2000, "hits": hits,
                "policy": "always", "v4": { "verdict": "ok", "at": at }, "xFuture": 1 })
    }

    fn fill(dir: &Path) -> Locations {
        let loc = Locations::in_dir(dir);
        wj(
            &dir.join(DOMAINS),
            json!({ "savedAt": "x", "domains": [domain("a.example", 100, 7)] }),
        );
        wj(
            &dir.join(POOLS),
            json!({ "providers": { "cloudflare": { "v4": [{ "ip": "1.1.1.1", "ms": 3 }], "v6": [] } } }),
        );
        wj(&dir.join(V6), json!({ "providers": { "cloudflare": { "2606::1": { "ms": 2 } } } }));
        wj(&dir.join(HARVEST), json!({ "cloudflare": {} }));
        wj(&dir.join(STATS), json!({ "days": [] }));
        wj(
            &dir.join(UPSTREAMS),
            json!({ "generatedAt": "2026-11-10T00:00:00.000Z", "selected": ["udp://1.1.1.1"] }),
        );
        std::fs::write(dir.join(BLACKLIST), "# 註解\n9.9.9.9  # 汙染\n").unwrap();
        std::fs::write(dir.join(CUSTOM), "||ads.example^\n").unwrap();
        let c = dir.join("community");
        std::fs::create_dir_all(&c).unwrap();
        std::fs::write(c.join("key.pem"), "-----BEGIN PRIVATE KEY-----\nabc\n").unwrap();
        wj(&c.join("peers.json"), json!({ "peers": [] }));
        std::fs::write(c.join("share.cbor"), [0xa0, 0xff, 0x00]).unwrap();
        loc
    }

    #[test]
    fn round_trip_full_and_share() {
        let d = tmp("rt");
        let loc = fill(&d);
        let full = export(&loc, Kind::Full);
        let b = Bundle::decode(&full.encode()).unwrap();
        assert_eq!(b.kind, Kind::Full);
        assert_eq!(b.files, full.files);
        for k in [
            DOMAINS,
            POOLS,
            V6,
            HARVEST,
            STATS,
            UPSTREAMS,
            BLACKLIST,
            CUSTOM,
            "community/key.pem",
            "community/share.cbor",
        ] {
            assert!(b.files.contains_key(k), "完整備份有 {k}");
        }
        assert!(!b.files.keys().any(|k| k.starts_with(KEYS)), "金鑰目錄跟 community/ 同一個：不重複");
        assert_eq!(b.files["community/share.cbor"], Data::Bin(vec![0xa0, 0xff, 0x00]));
        assert_eq!(b.files[DOMAINS].json().unwrap()["domains"][0]["hits"], 7, "完整備份不去掉次數");

        let share = Bundle::decode(&export(&loc, Kind::Share).encode()).unwrap();
        assert_eq!(share.kind, Kind::Share);
        let keys: Vec<&str> = share.files.keys().map(String::as_str).collect();
        assert_eq!(keys, vec![BLACKLIST, DOMAINS, POOLS, V6, UPSTREAMS]);
        let dom = &share.files[DOMAINS].json().unwrap()["domains"][0];
        for k in PRIVATE_DOMAIN_FIELDS {
            assert!(dom.get(k).is_none(), "分享檔沒有 {k}");
        }
        assert_eq!(dom["v4"]["at"], 100, "驗證結果保留");
        assert_eq!(dom["xFuture"], 1, "不認識的欄位保留");
        let p = share.preview();
        assert_eq!(p["kind"], "share");
        assert!(preview_text(&p).contains("CDN 網域驗證紀錄：1 個網域"));

        // 金鑰目錄在別的地方：放在 community-keys/
        let mut loc2 = loc.clone();
        loc2.key_dir = d.join("keys");
        std::fs::create_dir_all(&loc2.key_dir).unwrap();
        std::fs::write(loc2.key_dir.join("key.pem"), "K").unwrap();
        let f2 = export(&loc2, Kind::Full);
        assert_eq!(f2.files["community-keys/key.pem"], Data::Text("K".into()));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn rejects_bad_bundles() {
        let enc = |v: Value| zstd::bulk::compress(&serde_json::to_vec(&v).unwrap(), 3).unwrap();
        let base = |files: Value| json!({ "format": FORMAT, "version": 1, "kind": "full", "files": files });
        assert!(Bundle::decode(&enc(base(json!({})))).is_ok());
        assert!(Bundle::decode(b"not zstd").is_err());
        let e = Bundle::decode(&enc(json!({ "format": "other", "version": 1, "kind": "full", "files": {} }))).unwrap_err();
        assert!(e.to_string().contains("format"));
        let e = Bundle::decode(&enc(json!({ "format": FORMAT, "version": 2, "kind": "full", "files": {} }))).unwrap_err();
        assert!(e.to_string().contains("新版"));
        for bad in [
            "../etc/passwd",
            "/etc/passwd",
            "community/../../x",
            "community\\x",
            "C:/x",
            "community/sub/x",
            "community/.hidden",
            "unknown.json",
            "community-keys/other.pem",
        ] {
            let e = Bundle::decode(&enc(base(json!({ bad: { "text": "x" } })))).unwrap_err();
            assert!(e.to_string().contains("路徑"), "{bad}：{e}");
        }
        // 分享檔不能帶私人檔案
        let e = Bundle::decode(&enc(json!({ "format": FORMAT, "version": 1, "kind": "share",
            "files": { "custom-rules.txt": { "text": "x" } } })))
        .unwrap_err();
        assert!(e.to_string().contains("路徑"));
        // 型態不對
        assert!(Bundle::decode(&enc(base(json!({ DOMAINS: { "text": "x" } })))).is_err());
        assert!(Bundle::decode(&enc(base(json!({ "community/x.cbor": { "b64": "!!!" } })))).is_err());
        // 解壓後太大（壓縮炸彈）
        let big = vec![b' '; MAX_BYTES + 10];
        let e = Bundle::decode(&zstd::bulk::compress(&big, 3).unwrap()).unwrap_err();
        assert!(e.to_string().contains("太大"), "{e}");
        // 檔案本身太大
        assert!(Bundle::decode(&vec![0u8; MAX_BYTES + 1]).unwrap_err().to_string().contains("太大"));
    }

    #[test]
    fn merge_rules() {
        let src = tmp("src");
        let dst = tmp("dst");
        let sloc = fill(&src);
        // 來源：a 的驗證比較新、多一個 b；節點池多一個 IP 與一家；黑名單多一行；評測比較新
        wj(
            &src.join(DOMAINS),
            json!({ "domains": [domain("a.example", 500, 1), domain("b.example", 50, 3)] }),
        );
        wj(
            &src.join(POOLS),
            json!({ "providers": {
                "cloudflare": { "v4": [{ "ip": "1.1.1.1", "ms": 99 }, { "ip": "1.0.0.1" }], "v6": [{ "ip": "2606::2" }] },
                "fastly": { "v4": [{ "ip": "151.101.1.1" }] } } }),
        );
        wj(
            &src.join(V6),
            json!({ "providers": { "cloudflare": { "2606::1": { "ms": 99 }, "2606::3": {} } } }),
        );
        wj(
            &src.join(UPSTREAMS),
            json!({ "generatedAt": "2026-11-11T00:00:00.000Z", "selected": ["udp://8.8.8.8"] }),
        );
        std::fs::write(src.join(BLACKLIST), "9.9.9.9\n# 另一個\nhttps://bad.example/dns-query  # x\n").unwrap();
        std::fs::write(src.join(CUSTOM), "||ads.example^\n||track.example^\n").unwrap();
        std::fs::write(src.join(HOT), "[\"1|a.example\"]").unwrap();
        let full = Bundle::decode(&export(&sloc, Kind::Full).encode()).unwrap();

        // 目的地：a 的驗證比較舊（次數 42、policy never）、有自己的 c；自訂規則改過；社群身分已存在
        let dloc = Locations::in_dir(&dst);
        let mut a = domain("a.example", 100, 42);
        a["policy"] = json!("never");
        a["firstSeen"] = json!(500);
        a["lastSeen"] = json!(9000);
        a["xLocal"] = json!(true);
        wj(
            &dst.join(DOMAINS),
            json!({ "savedAt": "keep", "domains": [a, domain("c.example", 1, 1)] }),
        );
        wj(
            &dst.join(POOLS),
            json!({ "providers": { "cloudflare": { "v4": [{ "ip": "1.1.1.1", "ms": 3 }] } }, "savedAt": "L" }),
        );
        wj(&dst.join(V6), json!({ "providers": { "cloudflare": { "2606::1": { "ms": 2 } } } }));
        wj(
            &dst.join(UPSTREAMS),
            json!({ "generatedAt": "2026-11-10T00:00:00.000Z", "selected": [] }),
        );
        std::fs::write(dst.join(BLACKLIST), "# 本機\n9.9.9.9 # 本機註解\n").unwrap();
        std::fs::write(dst.join(CUSTOM), "# 我的\n||mine.example^\n").unwrap();
        wj(&dst.join(STATS), json!({ "local": true }));
        std::fs::create_dir_all(dst.join("community")).unwrap();
        std::fs::write(dst.join("community/key.pem"), "LOCAL").unwrap();

        let r = merge(&dloc, &full);
        assert_eq!(r["ok"], true, "{r}");
        let item = |f: &str| r["items"].as_array().unwrap().iter().find(|i| i["file"] == f).unwrap().clone();

        let doms = read_json(&dst.join(DOMAINS)).unwrap();
        assert_eq!(doms["savedAt"], "keep");
        let list = doms["domains"].as_array().unwrap();
        assert_eq!(list.len(), 3);
        let a = list.iter().find(|d| d["name"] == "a.example").unwrap();
        assert_eq!(a["v4"]["at"], 500, "比較新的驗證結果");
        assert_eq!(a["hits"], 42, "本機的次數");
        assert_eq!(a["policy"], "never", "本機的手動設定");
        assert_eq!((a["firstSeen"].as_u64(), a["lastSeen"].as_u64()), (Some(500), Some(9000)));
        assert_eq!(a["xLocal"], true, "本機的未知欄位保留");
        assert!(list.iter().any(|d| d["name"] == "b.example") && list.iter().any(|d| d["name"] == "c.example"));
        let di = item(DOMAINS);
        assert_eq!((di["added"].as_u64(), di["updated"].as_u64()), (Some(1), Some(1)));

        let pools = read_json(&dst.join(POOLS)).unwrap();
        let cf = &pools["providers"]["cloudflare"];
        assert_eq!(cf["v4"].as_array().unwrap().len(), 2);
        assert_eq!(cf["v4"][0]["ms"], 3, "本機的節點優先");
        assert_eq!(cf["v6"][0]["ip"], "2606::2");
        assert!(pools["providers"]["fastly"].is_object(), "本機沒有的業者加進來");
        assert_eq!(pools["savedAt"], "L");
        assert_eq!(item(POOLS)["added"], 3);

        let v6 = read_json(&dst.join(V6)).unwrap();
        assert_eq!(v6["providers"]["cloudflare"]["2606::1"]["ms"], 2);
        assert!(v6["providers"]["cloudflare"]["2606::3"].is_object());

        assert_eq!(
            read_json(&dst.join(UPSTREAMS)).unwrap()["selected"][0],
            "udp://8.8.8.8",
            "評測比較新"
        );

        let bl = std::fs::read_to_string(dst.join(BLACKLIST)).unwrap();
        assert!(bl.starts_with("# 本機\n9.9.9.9 # 本機註解\n"), "{bl}");
        assert_eq!(bl.matches("9.9.9.9").count(), 1);
        assert!(bl.contains("https://bad.example/dns-query  # x"));

        let cr = std::fs::read_to_string(dst.join(CUSTOM)).unwrap();
        assert!(cr.starts_with("# 我的\n||mine.example^\n"));
        assert!(cr.contains("# ── 從備份匯入（") && cr.contains("||ads.example^\n||track.example^"));
        assert_eq!(read_json(&dst.join(STATS)).unwrap()["local"], true, "統計本機已有，不覆蓋");
        assert!(dst.join(HOT).exists(), "本機沒有的才用");
        assert_eq!(item("community")["note"], "已有社群身分，沒有覆蓋");
        assert_eq!(std::fs::read_to_string(dst.join("community/key.pem")).unwrap(), "LOCAL");
        assert!(report_text(&r).contains("CDN 網域驗證紀錄：新增 1、更新 1"));

        // 再匯入一次：都已經有了
        let r2 = merge(&dloc, &full);
        assert_eq!(item_of(&r2, DOMAINS)["added"], 0);
        assert_eq!(item_of(&r2, BLACKLIST)["added"], 0);
        assert_eq!(std::fs::read_to_string(dst.join(CUSTOM)).unwrap(), cr, "規則不會重複附加");

        // 舊的驗證結果不會蓋掉新的
        let mut old = full.clone();
        old.files
            .insert(DOMAINS.into(), Data::Json(json!({ "domains": [domain("a.example", 1, 0)] })));
        let r3 = merge(&dloc, &old);
        assert_eq!(item_of(&r3, DOMAINS)["kept"], 1);
        std::fs::remove_dir_all(&src).unwrap();
        std::fs::remove_dir_all(&dst).unwrap();
    }

    fn item_of(r: &Value, f: &str) -> Value {
        r["items"].as_array().unwrap().iter().find(|i| i["file"] == f).unwrap().clone()
    }

    #[test]
    fn merge_into_empty_and_defaults() {
        let src = tmp("src2");
        let dst = tmp("dst2");
        let sloc = fill(&src);
        let dloc = Locations::in_dir(&dst);
        // 自訂規則還是預設內容 → 直接換成備份的
        std::fs::write(dst.join(CUSTOM), crate::filtering::DEFAULT_CUSTOM_RULES.replace('\n', "\r\n")).unwrap();
        let r = merge(&dloc, &export(&sloc, Kind::Full));
        assert_eq!(r["ok"], true);
        assert_eq!(std::fs::read_to_string(dst.join(CUSTOM)).unwrap(), "||ads.example^\n");
        // 社群：本機沒有身分 → 還原
        assert_eq!(item_of(&r, "community")["note"], "已還原社群身分與好友");
        assert!(dst.join("community/key.pem").exists() && dst.join("community/peers.json").exists());
        assert_eq!(std::fs::read(dst.join("community/share.cbor")).unwrap(), vec![0xa0, 0xff, 0x00]);
        assert!(dst.join(HARVEST).exists() && dst.join(STATS).exists());

        // 分享檔匯入空的機器：網域沒有時間 → 設成現在；沒有私人檔案
        let dst3 = tmp("dst3");
        let r = merge(&Locations::in_dir(&dst3), &export(&sloc, Kind::Share));
        assert_eq!(r["kind"], "share");
        let doms = read_json(&dst3.join(DOMAINS)).unwrap();
        assert!(doms["domains"][0]["lastSeen"].as_u64().unwrap() > 1_000_000_000_000);
        assert!(doms["domains"][0].get("hits").is_none());
        assert!(!dst3.join(STATS).exists() && !dst3.join("community").exists() && !dst3.join(CUSTOM).exists());

        // 等著合併的檔案：合併後刪掉、結果存起來
        let dst4 = tmp("dst4");
        let l4 = Locations::in_dir(&dst4);
        let p = stage_pending(&l4, &export(&sloc, Kind::Share).encode()).unwrap();
        assert_eq!(p["kind"], "share");
        assert!(stage_pending(&l4, b"junk").is_err());
        assert_eq!(last_import(&l4)["none"], true);
        let r = apply_pending(&l4).unwrap();
        assert_eq!(r["ok"], true);
        assert!(!l4.pending_file().exists());
        assert_eq!(last_import(&l4)["importedAt"], r["importedAt"]);
        assert!(apply_pending(&l4).is_none());
        for d in [src, dst, dst3, dst4] {
            std::fs::remove_dir_all(d).unwrap();
        }
    }
}
