//! 種子資料（對齊 2.x `lib/seed.js`）：`seed/` 裡是正式伺服器累積的資料（`kuroshio export-seed` 匯出）。
//! 新安裝的機器第一次啟動時，state 對應的檔案不存在或是空的，就先用種子資料，
//! 不用等每日評測、節點池重建、逐一驗證網站才開始加速；之後各工作照常更新。
//!
//! 2.x 是在伺服器啟動時集中處理四個檔案（上游評測、節點池、IPv6 節點、CDN 網域），這裡照做；
//! 3.5.0 起上游評測結果不再用種子（那是某一條線路上的評測結果），改由 [`initial_upstreams`] 從預設名單的 A 級產生。
//! CDN 模組自己的讀取器若也會在 state 空白時退回種子，兩邊並存也沒關係：這裡先寫入後，
//! state 已經不是空的，CDN 那邊就不會再動。只想處理部分檔案時用 `apply_seeds_with`。

use crate::benchmark::tags::Tier;
use crate::benchmark::BenchPaths;
use crate::time::{Clock, SystemClock};
use crate::util::{read_json, write_json};
use kuroshio_net::upstream::Upstream;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::path::Path;
use tracing::{info, warn};

/// 一種種子檔
#[derive(Clone, Copy)]
pub struct SeedSpec {
    /// 種子目錄裡的檔名
    pub seed: &'static str,
    /// state 目錄裡的相對路徑
    pub state: &'static str,
    pub label: &'static str,
    /// 內容算不算「空的」（null 也算）
    pub empty: fn(&Value) -> bool,
    /// 匯入前的轉換（參數：資料、現在的 Unix 毫秒）
    pub transform: Option<fn(&mut Value, u64)>,
    /// state 裡另外這些檔存在就算「已經有資料」（新格式：壓縮檔、CDN 網域分片清單）。
    /// `state` 本身的 `.zst` 一律也算
    pub present: &'static [&'static str],
}

fn arr_len(v: Option<&Value>) -> usize {
    v.and_then(Value::as_array).map(Vec::len).unwrap_or(0)
}

/// `upstreams.json` 的內容算不算空的（null、沒有 `selected`）
pub fn upstreams_empty(d: &Value) -> bool {
    d.is_null() || arr_len(d.get("selected")) == 0
}

fn pools_empty(d: &Value) -> bool {
    let providers = d.get("providers").and_then(Value::as_object);
    d.is_null() || !providers.map(|p| p.values().any(|x| arr_len(x.get("v4")) > 0)).unwrap_or(false)
}

fn v6_empty(d: &Value) -> bool {
    let providers = d.get("providers").and_then(Value::as_object);
    d.is_null()
        || !providers
            .map(|p| p.values().any(|x| x.as_object().map(|o| !o.is_empty()).unwrap_or(false)))
            .unwrap_or(false)
}

fn domains_empty(d: &Value) -> bool {
    d.is_null() || arr_len(d.get("domains")) == 0
}

/// 匯入時把「最後出現時間」設成現在：每小時的複驗只處理最近 3 天出現過的網域，
/// 這樣熱門網站過期的驗證結果會在背景重新驗證，而不是等有人查到才開始
fn touch_domains(d: &mut Value, now: u64) {
    if let Some(list) = d.get_mut("domains").and_then(Value::as_array_mut) {
        for e in list.iter_mut().filter_map(Value::as_object_mut) {
            e.insert("lastSeen".into(), Value::from(now));
        }
    }
}

/// 2.x 的 `SEEDS`（3.5.0 起不帶上游評測結果：那是別條線路上的結果，第一次啟動改用預設名單的 A 級，
/// 見 [`initial_upstreams`]）
pub const SEEDS: [SeedSpec; 3] = [
    SeedSpec {
        seed: "cdn-pools.json",
        state: "cdn/pools.json",
        label: "台灣節點池",
        empty: pools_empty,
        transform: None,
        present: &[],
    },
    SeedSpec {
        seed: "v6-nodes.json",
        state: "cdn/v6-nodes.json",
        label: "永久 IPv6 節點",
        empty: v6_empty,
        transform: None,
        present: &[],
    },
    SeedSpec {
        seed: "cdn-domains.json",
        state: "cdn-domains.json",
        label: "CDN 網域驗證紀錄",
        empty: domains_empty,
        transform: Some(touch_domains),
        present: &["cdn/domains/manifest.json"],
    },
];

/// 套用所有種子；回傳用到的種子名稱（2.x 的 label）
pub fn apply_seeds(state_dir: &Path, seed_dir: &Path) -> Vec<&'static str> {
    apply_seeds_with(state_dir, seed_dir, &SEEDS, &SystemClock)
}

/// 只套用指定的種子；`seed_dir/meta.json` 不存在就什麼都不做
pub fn apply_seeds_with(state_dir: &Path, seed_dir: &Path, specs: &[SeedSpec], clock: &dyn Clock) -> Vec<&'static str> {
    let Some(meta) = read_json(&seed_dir.join("meta.json")) else {
        return Vec::new();
    };
    let mut used = Vec::new();
    for s in specs {
        let src = seed_dir.join(s.seed);
        let dst = state_dir.join(s.state);
        if !src.exists() || !(s.empty)(&read_json(&dst).unwrap_or(Value::Null)) {
            continue;
        }
        // 新格式（壓縮檔、分片）已經有資料：不要用種子蓋過去
        let mut zst = dst.clone().into_os_string();
        zst.push(".zst");
        if std::path::Path::new(&zst).exists() || s.present.iter().any(|p| state_dir.join(p).exists()) {
            continue;
        }
        let Some(mut data) = read_json(&src) else {
            warn!("種子資料 {} 載入失敗：格式錯誤", s.label);
            continue;
        };
        if (s.empty)(&data) {
            continue;
        }
        if let Some(t) = s.transform {
            t(&mut data, clock.now_ms());
        }
        match write_json(&dst, &data) {
            Ok(()) => used.push(s.label),
            Err(e) => warn!("種子資料 {} 載入失敗：{e}", s.label),
        }
    }
    if !used.is_empty() {
        let at = meta.get("exportedAt").and_then(Value::as_str).unwrap_or("");
        let at: String = at.chars().take(10).collect();
        info!(
            "第一次啟動，帶入種子資料（{} 匯出）：{}",
            if at.is_empty() { "?".into() } else { at },
            used.join("、")
        );
    }
    used
}

// ---------------- 首次啟動的初始上游（3.5.0，規格 11 的 A8） ----------------

/// 初始上游另外準備幾台候補（A7：可用的自動上游不夠時依序補上）
pub const INITIAL_SPARES: usize = 3;
/// `upstreams.json` 的 `source`：還沒評測過、來自預設名單
pub const SOURCE_DEFAULT_LIST: &str = "default-list";

fn strings(cfg: &Value, k: &str) -> Vec<String> {
    kuroshio_config::get(cfg, k)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

/// 全新的 state 第一次啟動時的初始上游：預設名單的 A 級，依名單的 `ms` 由小到大、同一個經營者最多 1 台、
/// 只取 `upstream.autoTypes` 裡有的類型，取 `upstream.autoMax` 台，另外 [`INITIAL_SPARES`] 台當候補。
/// **加密的優先**（DoH、DoT，不夠才 DoQ，再不夠才一般 DNS）：還沒做路徑檢查，不知道一般 DNS 有沒有被接走。
/// 永久黑名單裡的、固定上游、IPv6 位址（還不知道這台有沒有 IPv6）不取。
///
/// 只是「還沒評測前暫時用的」：一樣受暫停與降級保護，評測完成就被取代。名單讀不到、沒有 A 級時回 None
/// （照舊只用固定上游與 `upstream.fallback`）。不查詢任何伺服器
pub fn initial_upstreams(paths: &BenchPaths, cfg: &Value) -> Option<Value> {
    let types = strings(cfg, "upstream.autoTypes");
    let auto_max = kuroshio_config::get(cfg, "upstream.autoMax").and_then(Value::as_u64).unwrap_or(5) as usize;
    if types.is_empty() || auto_max == 0 {
        return None;
    }
    let pinned: HashSet<String> = strings(cfg, "upstream.pinned")
        .iter()
        .filter_map(|p| Upstream::parse(p).ok().map(|u| u.id))
        .collect();
    let mut blacklist: HashSet<String> = HashSet::new();
    let bl_files = [
        Some(paths.list_dir.join("blacklist.txt")),
        paths.default_list_dir.as_ref().map(|d| d.join("blacklist.txt")),
        paths.blacklist_file.clone(),
    ];
    for f in bl_files.iter().flatten() {
        for l in crate::util::read_list(f) {
            if let Some(t) = l.split_whitespace().next() {
                blacklist.insert(t.to_string());
            }
        }
    }
    // （順序，名單的 ms，經營者，上游，名單裡的寫法）
    let mut cands: Vec<(u8, f32, String, Upstream, String)> = Vec::new();
    let files: [(&str, u8); 4] = [("dohlist.txt", 0), ("dotlist.txt", 0), ("doqlist.txt", 1), ("iplist.txt", 2)];
    let mut total = 0usize;
    for (name, group) in files {
        for (line, tag) in paths.read_lists_tagged(name) {
            if tag.tier != Tier::A {
                continue;
            }
            total += 1;
            let tok = line.split_whitespace().next().unwrap_or("");
            let spec = if name == "dotlist.txt" && !tok.contains("://") {
                format!("tls://{tok}")
            } else {
                tok.to_string()
            };
            if blacklist.contains(&spec) {
                continue;
            }
            let Ok(up) = Upstream::parse(&spec) else { continue };
            let kind = crate::benchmark::probe::kind_name(up.kind);
            if !up.supported() || !types.iter().any(|t| t == kind) || pinned.contains(&up.id) || blacklist.contains(&up.id) {
                continue;
            }
            if up.host.parse::<std::net::Ipv6Addr>().is_ok() {
                continue;
            }
            let op = if tag.op.is_empty() { up.host.clone() } else { tag.op };
            cands.push((group, tag.ms.unwrap_or(f32::MAX), op, up, spec));
        }
    }
    // 穩定排序：同一組、同樣的 ms 照名單順序
    cands.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal)));
    let mut ops: HashSet<String> = HashSet::new();
    let mut ids: HashSet<String> = HashSet::new();
    let mut picked: Vec<Value> = Vec::new();
    for (_, ms, op, up, spec) in cands {
        if picked.len() >= auto_max + INITIAL_SPARES {
            break;
        }
        if !ids.insert(up.id.clone()) || !ops.insert(op.to_ascii_lowercase()) {
            continue;
        }
        picked.push(json!({
            "id": spec,
            "type": crate::benchmark::probe::kind_name(up.kind),
            "owner": op,
            "reason": "預設名單",
            "region": "",
            "tier": "A",
            "op": op,
            "listMs": (ms < f32::MAX).then_some(ms as f64),
        }));
    }
    if picked.is_empty() {
        return None;
    }
    let spares = picked.split_off(picked.len().min(auto_max));
    Some(json!({
        "generatedAt": null,
        "source": SOURCE_DEFAULT_LIST,
        "selected": picked,
        "spares": spares,
        "counts": { "candidates": total, "selected": picked.len(), "spares": spares.len() },
    }))
}

/// 啟動時：state 的 `upstreams.json`（或它的 `.zst`）還是空的，就寫入 [`initial_upstreams`]。
/// 回傳有沒有寫入。已經有評測結果（升級、備份匯入、串接匯入）完全不動
pub fn apply_initial_upstreams(paths: &BenchPaths, cfg: &Value) -> bool {
    let dst = &paths.upstreams_file;
    let mut zst = dst.clone().into_os_string();
    zst.push(".zst");
    if !upstreams_empty(&read_json(dst).unwrap_or(Value::Null)) || Path::new(&zst).exists() {
        return false;
    }
    let Some(v) = initial_upstreams(paths, cfg) else {
        info!("第一次啟動：預設名單沒有可用的 A 級上游，暫時只用固定上游與備援");
        return false;
    };
    match write_json(dst, &v) {
        Ok(()) => {
            let ids: Vec<&str> = v["selected"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|x| x["id"].as_str())
                .collect();
            info!("第一次啟動，還沒評測：初始上游用預設名單的 A 級（{}）", ids.join(", "));
            true
        }
        Err(e) => {
            warn!("寫入初始上游失敗：{e}");
            false
        }
    }
}
