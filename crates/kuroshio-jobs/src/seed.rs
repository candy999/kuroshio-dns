//! 種子資料（對齊 2.x `lib/seed.js`）：`seed/` 裡是正式伺服器累積的資料（`kuroshio export-seed` 匯出）。
//! 新安裝的機器第一次啟動時，state 對應的檔案不存在或是空的，就先用種子資料，
//! 不用等每日評測、節點池重建、逐一驗證網站才開始加速；之後各工作照常更新。
//!
//! 2.x 是在伺服器啟動時集中處理四個檔案（上游評測、節點池、IPv6 節點、CDN 網域），這裡照做。
//! CDN 模組自己的讀取器若也會在 state 空白時退回種子，兩邊並存也沒關係：這裡先寫入後，
//! state 已經不是空的，CDN 那邊就不會再動。只想處理部分檔案時用 `apply_seeds_with`。

use crate::time::{Clock, SystemClock};
use crate::util::{read_json, write_json};
use serde_json::Value;
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

fn upstreams_empty(d: &Value) -> bool {
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

/// 2.x 的 `SEEDS`
pub const SEEDS: [SeedSpec; 4] = [
    SeedSpec {
        seed: "upstreams.json",
        state: "upstreams.json",
        label: "上游評測結果",
        empty: upstreams_empty,
        transform: None,
        present: &[],
    },
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
