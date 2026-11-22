//! 串接模式（3.4.0，規格 10）的設定讀取。
//!
//! 只有兩個開關（規格 1.11），都在 `upstream` 底下、預設都開：
//!
//! - `upstream.chain`（下游）：要不要辨識上游的黑潮並索取資料。關閉 = 3.3.7 的「一般 DNS 被接走的網路」
//! - `upstream.allowDownstream`（上游）：要不要提供資料給接在後面的黑潮
//!
//! 其他相關的設定鍵（規格第 10 節）：`resolver.backfill`、`resolver.backfillSample`（背景補問，5.2）、
//! `benchmark.coverageRegion`、`benchmark.nearMaxMs`（上游多樣性，6.2）、`filter.lists[].bypass`（繞過防護清單，4.1）。
//!
//! UCI 的 `'0'` 轉換後可能是布林 `false`、數字 `0` 或字串 `"0"`（JSON 設定檔也可能這樣寫），
//! 讀取一律經過這裡的函式，型別都接受。

use crate::{get, num_or_auto};
use serde_json::Value;

/// `resolver.backfillSample` 的預設值（非 CDN 查詢每幾次抽一次）
pub const DEFAULT_BACKFILL_SAMPLE: u64 = 16;
/// `benchmark.nearMaxMs` 的預設值（最低延遲在這以內就算鄰近）
pub const DEFAULT_NEAR_MAX_MS: f64 = 60.0;

/// 布林設定：true/false、"1"/"0"/"on"/"off"/"true"/"false"/"yes"/"no"、數字（0 = false）；
/// 其他寫法 → (預設值, Some(警告))；沒寫（None / null）→ (預設值, None)
///
/// 空字串（UCI 的「空白 = 用預設值」）也算沒寫，不發警告。字串不分大小寫、前後空白不算。
/// 警告裡沒有設定鍵的名稱，呼叫端自己加上（例如 [`ChainSettings::from_cfg`]）。
pub fn flex_bool(v: Option<&Value>, default: bool) -> (bool, Option<String>) {
    let bad = |shown: String| {
        (
            default,
            Some(format!(
                "{shown} 不是有效的開關值（可以寫 true / false、1 / 0、on / off、yes / no），改用預設值（{}）",
                if default { "開" } else { "關" }
            )),
        )
    };
    match v {
        None | Some(Value::Null) => (default, None),
        Some(Value::Bool(b)) => (*b, None),
        Some(Value::Number(n)) => match n.as_f64() {
            Some(f) if f.is_finite() => (f != 0.0, None),
            _ => bad(n.to_string()),
        },
        Some(Value::String(s)) => match s.trim().to_ascii_lowercase().as_str() {
            "" => (default, None),
            "1" | "true" | "on" | "yes" => (true, None),
            "0" | "false" | "off" | "no" => (false, None),
            _ => bad(format!("\"{s}\"")),
        },
        Some(other) => bad(other.to_string()),
    }
}

/// 串接的兩個開關（規格 1.11），加上會讓串接沒有偵測來源的路徑檢查開關
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainSettings {
    /// `upstream.chain`：下游要不要辨識上游黑潮並索取資料
    pub chain: bool,
    /// `upstream.allowDownstream`：上游要不要提供資料給下游
    pub allow_downstream: bool,
    /// `upstream.pathCheck`：關掉時串接沒有偵測來源，等同 chain 關
    pub path_check: bool,
    /// `upstream.chainPin`（UCI `chain_pin`）：只跟這個指紋的上游黑潮串接（空的＝不限定；3.4.3）。
    /// 只留英數字、轉小寫後比對，寫法可以帶空格或冒號
    pub pin: Option<String>,
    /// 看不懂的寫法（已經改用預設值），啟動時記 warn
    pub warnings: Vec<String>,
}

impl ChainSettings {
    pub fn from_cfg(cfg: &Value) -> ChainSettings {
        let mut warnings = Vec::new();
        let mut read = |key: &str| {
            let (b, w) = flex_bool(get(cfg, key), true);
            if let Some(w) = w {
                warnings.push(format!("{key}：{w}"));
            }
            b
        };
        let chain = read("upstream.chain");
        let allow_downstream = read("upstream.allowDownstream");
        let path_check = read("upstream.pathCheck");
        let pin = get(cfg, "upstream.chainPin")
            .and_then(Value::as_str)
            .map(normalize_fp)
            .filter(|s| !s.is_empty());
        ChainSettings {
            chain,
            allow_downstream,
            path_check,
            pin,
            warnings,
        }
    }

    /// 這個指紋符不符合 `chainPin`（沒設定時一律符合）
    pub fn pin_ok(&self, fingerprint: &str) -> bool {
        match self.pin.as_deref() {
            Some(p) => normalize_fp(fingerprint) == p,
            None => true,
        }
    }

    /// 下游角色實際上有沒有啟用：chain && path_check
    pub fn downstream_enabled(&self) -> bool {
        self.chain && self.path_check
    }
}

/// 指紋的比對形式：只留英數字、轉小寫
pub fn normalize_fp(s: &str) -> String {
    s.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// 背景補問（規格 5.2，`resolver.backfill`）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backfill {
    /// CDN 相關的查詢、加上抽樣的查詢，回答之後在背景問這次沒問到的上游（預設）
    Cdn,
    /// 不補問（3.3.7 的行為）
    Off,
}

/// `resolver.backfill`（`"cdn"`；`"off"`、`0`、`false` = 不補問；其他寫法 = 預設 `cdn`）
/// 與 `resolver.backfillSample`（預設 16；`0` = 不抽樣）
pub fn backfill_of(cfg: &Value) -> (Backfill, u64 /* backfillSample */) {
    let mode = match get(cfg, "resolver.backfill") {
        Some(Value::String(s)) if s.trim().eq_ignore_ascii_case("cdn") => Backfill::Cdn,
        // "off"、"0"、0、false：不補問；其他（"1"、true、看不懂的寫法）照預設
        v => match flex_bool(v, true) {
            (false, None) => Backfill::Off,
            _ => Backfill::Cdn,
        },
    };
    let sample = num_or_auto(get(cfg, "resolver.backfillSample")).unwrap_or(DEFAULT_BACKFILL_SAMPLE);
    (mode, sample)
}

/// 評測選上游時「覆蓋」階段的範圍（規格 6.2，`benchmark.coverageRegion`）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageRegion {
    /// 先在鄰近（台灣、日本、香港、新加坡或延遲低）的候選裡覆蓋，還有名額才用其他的（預設）
    Near,
    /// 不分遠近（3.3.7 的行為）
    Any,
}

/// `benchmark.coverageRegion`（`"near"`／`"any"`，其他寫法 = 預設 `near`）
/// 與 `benchmark.nearMaxMs`（預設 60；數字或數字字串，負數、看不懂 = 預設）
pub fn coverage_region_of(cfg: &Value) -> (CoverageRegion, f64 /* nearMaxMs */) {
    let region = match get(cfg, "benchmark.coverageRegion").and_then(Value::as_str) {
        Some(s) if s.trim().eq_ignore_ascii_case("any") => CoverageRegion::Any,
        _ => CoverageRegion::Near,
    };
    let near = match get(cfg, "benchmark.nearMaxMs") {
        Some(Value::Number(n)) => n.as_f64(),
        Some(Value::String(s)) => s.trim().parse::<f64>().ok(),
        _ => None,
    }
    .filter(|f| f.is_finite() && *f >= 0.0)
    .unwrap_or(DEFAULT_NEAR_MAX_MS);
    (region, near)
}

/// 過濾清單（`filter.lists[]` 的一筆）是不是「繞過防護」類的清單（規格 4.1，`bypass`，預設 false）
pub fn is_bypass_list(list: &Value) -> bool {
    match list.get("bypass") {
        // 明確寫了就照寫的
        Some(v) if !v.is_null() && v.as_str() != Some("") => flex_bool(Some(v), false).0,
        // 沒寫：預設的 HaGeZi doh-vpn-proxy-bypass 依網址認得（3.4.0 之前存下的設定沒有這個標記，不用另外遷移）
        _ => list
            .get("url")
            .and_then(Value::as_str)
            .is_some_and(|u| KNOWN_BYPASS_URLS.contains(&u)),
    }
}

/// 沒寫 `bypass` 時也當成「繞過防護」清單的預設清單網址
pub const KNOWN_BYPASS_URLS: &[&str] = &["https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/doh-vpn-proxy-bypass.txt"];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{build, defaults};
    use serde_json::json;

    #[test]
    fn bypass_list_recognized_by_url_without_flag() {
        let url = KNOWN_BYPASS_URLS[0];
        assert!(is_bypass_list(&json!({ "url": url })), "3.4.0 之前存下的設定沒有標記");
        assert!(!is_bypass_list(&json!({ "url": url, "bypass": false })), "明確關掉的照設定");
        assert!(is_bypass_list(&json!({ "url": "https://example.com/list.txt", "bypass": "1" })));
        assert!(!is_bypass_list(&json!({ "url": "https://example.com/list.txt" })));
    }

    #[test]
    fn flex_bool_accepts_uci_and_json() {
        for (v, want) in [
            (json!(true), true),
            (json!(false), false),
            (json!("1"), true),
            (json!("0"), false),
            (json!("on"), true),
            (json!("off"), false),
            (json!("yes"), true),
            (json!("no"), false),
            (json!("true"), true),
            (json!("false"), false),
            (json!(" OFF "), false),
            (json!("Yes"), true),
            (json!(0), false),
            (json!(1), true),
            (json!(5), true),
            (json!(0.0), false),
        ] {
            for default in [true, false] {
                assert_eq!(flex_bool(Some(&v), default), (want, None), "{v} / 預設 {default}");
            }
        }
        // 沒寫：預設值、沒有警告（空字串 = UCI 的空白）
        for default in [true, false] {
            assert_eq!(flex_bool(None, default), (default, None));
            assert_eq!(flex_bool(Some(&Value::Null), default), (default, None));
            assert_eq!(flex_bool(Some(&json!("")), default), (default, None));
        }
        // 早期草稿的 "auto"、"ask"、陣列、物件：預設值＋警告
        for v in [json!("auto"), json!("ask"), json!(["1"]), json!({ "a": 1 }), json!("2")] {
            let (b, w) = flex_bool(Some(&v), true);
            assert!(b, "{v}");
            assert!(w.as_deref().is_some_and(|w| w.contains("預設值（開）")), "{v}：{w:?}");
            let (b, w) = flex_bool(Some(&v), false);
            assert!(!b, "{v}");
            assert!(w.is_some(), "{v}");
        }
    }

    #[test]
    fn chain_settings_defaults_on() {
        let s = ChainSettings::from_cfg(&json!({}));
        assert!(s.chain && s.allow_downstream && s.path_check);
        assert!(s.warnings.is_empty());
        assert!(s.downstream_enabled());
        let s = ChainSettings::from_cfg(&build(&json!({})));
        assert_eq!(
            s,
            ChainSettings {
                chain: true,
                allow_downstream: true,
                path_check: true,
                pin: None,
                warnings: vec![]
            }
        );
        // 限定上游的指紋（3.4.3）：寫法可以帶空格、冒號、大小寫
        let s = ChainSettings::from_cfg(&build(&json!({ "upstream": { "chainPin": "3F2A-91C0 77ab" } })));
        assert_eq!(s.pin.as_deref(), Some("3f2a91c077ab"));
        assert!(s.pin_ok("3f2a:91c0:77AB"));
        assert!(!s.pin_ok("3F2A-91C0-0000"));
        assert!(ChainSettings::from_cfg(&build(&json!({}))).pin_ok("anything"), "沒設定：不限定");
        // 路徑檢查關掉：串接沒有偵測來源，下游角色等同關閉；上游角色不受影響
        let s = ChainSettings::from_cfg(&build(&json!({ "upstream": { "pathCheck": false } })));
        assert!(s.chain && s.allow_downstream);
        assert!(!s.downstream_enabled());
        // UCI 轉出的數字 0、字串 "0" 一樣算關
        let s = ChainSettings::from_cfg(&json!({ "upstream": { "chain": 0, "allowDownstream": "0" } }));
        assert!(!s.chain && !s.allow_downstream && !s.downstream_enabled());
        // 看不懂的寫法：開，並記一行有設定鍵名稱的警告
        let s = ChainSettings::from_cfg(&json!({ "upstream": { "chain": "auto", "allowDownstream": "ask" } }));
        assert!(s.chain && s.allow_downstream);
        assert_eq!(s.warnings.len(), 2);
        assert!(s.warnings[0].starts_with("upstream.chain："), "{:?}", s.warnings);
        assert!(s.warnings[1].starts_with("upstream.allowDownstream："), "{:?}", s.warnings);
    }

    #[test]
    fn defaults_have_all_chain_keys() {
        let c = build(&json!({}));
        for (k, v) in [
            ("upstream.chain", json!(true)),
            ("upstream.allowDownstream", json!(true)),
            ("resolver.backfill", json!("cdn")),
            ("resolver.backfillSample", json!(16)),
            ("benchmark.coverageRegion", json!("near")),
            ("benchmark.nearMaxMs", json!(60)),
        ] {
            assert_eq!(get(&c, k), Some(&v), "{k}");
        }
        // 只有兩個開關：早期草稿的其他開關不存在
        let up = get(&c, "upstream").and_then(Value::as_object).unwrap();
        for k in ["chainBackup", "chainShare", "downstreamEncrypted", "downstreamBypass", "chainMode"] {
            assert!(!up.contains_key(k), "upstream.{k}");
        }
        // 清單的 bypass：只有 HaGeZi doh-vpn-proxy-bypass 那一筆有，而且那一筆預設停用
        let lists = get(&defaults(), "filter.lists").and_then(Value::as_array).unwrap().clone();
        let marked: Vec<&Value> = lists.iter().filter(|l| is_bypass_list(l)).collect();
        assert_eq!(marked.len(), 1);
        assert!(marked[0]["url"].as_str().unwrap().ends_with("/doh-vpn-proxy-bypass.txt"));
        assert_eq!(marked[0]["bypass"], json!(true));
        assert_eq!(marked[0]["enabled"], json!(false));
        assert!(lists.iter().filter(|l| !is_bypass_list(l)).all(|l| l.get("bypass").is_none()));
        // 讀取函式拿到的就是預設值
        assert_eq!(backfill_of(&c), (Backfill::Cdn, 16));
        assert_eq!(coverage_region_of(&c), (CoverageRegion::Near, 60.0));
        assert_eq!(backfill_of(&json!({})), (Backfill::Cdn, DEFAULT_BACKFILL_SAMPLE));
        assert_eq!(coverage_region_of(&json!({})), (CoverageRegion::Near, DEFAULT_NEAR_MAX_MS));
    }

    #[test]
    fn backfill_and_coverage_accept_uci_values() {
        let bf = |v: Value| backfill_of(&json!({ "resolver": v }));
        for off in [
            json!("off"),
            json!("OFF"),
            json!("0"),
            json!(0),
            json!(false),
            json!("false"),
            json!("no"),
        ] {
            assert_eq!(bf(json!({ "backfill": off })).0, Backfill::Off, "{off}");
        }
        for on in [
            json!("cdn"),
            json!(" CDN "),
            json!(true),
            json!("1"),
            json!("auto"),
            json!(null),
            json!([]),
        ] {
            assert_eq!(bf(json!({ "backfill": on })).0, Backfill::Cdn, "{on}");
        }
        assert_eq!(bf(json!({ "backfillSample": 0 })).1, 0, "0 = 不抽樣");
        assert_eq!(bf(json!({ "backfillSample": "32" })).1, 32);
        assert_eq!(bf(json!({ "backfillSample": "abc" })).1, DEFAULT_BACKFILL_SAMPLE);
        let cr = |v: Value| coverage_region_of(&json!({ "benchmark": v }));
        assert_eq!(cr(json!({ "coverageRegion": "any" })).0, CoverageRegion::Any);
        assert_eq!(cr(json!({ "coverageRegion": "ANY" })).0, CoverageRegion::Any);
        assert_eq!(cr(json!({ "coverageRegion": "near" })).0, CoverageRegion::Near);
        assert_eq!(cr(json!({ "coverageRegion": "far" })).0, CoverageRegion::Near);
        assert_eq!(cr(json!({ "nearMaxMs": 80 })).1, 80.0);
        assert_eq!(cr(json!({ "nearMaxMs": "45.5" })).1, 45.5);
        assert_eq!(cr(json!({ "nearMaxMs": 0 })).1, 0.0);
        assert_eq!(cr(json!({ "nearMaxMs": -1 })).1, DEFAULT_NEAR_MAX_MS);
        assert_eq!(cr(json!({ "nearMaxMs": "x" })).1, DEFAULT_NEAR_MAX_MS);
        // 清單的 bypass：沒寫 = false；UCI 轉出的字串也接受
        assert!(!is_bypass_list(&json!({ "url": "https://example.com/a.txt" })));
        assert!(is_bypass_list(&json!({ "bypass": "1" })));
        assert!(!is_bypass_list(&json!({ "bypass": 0 })));
    }
}
