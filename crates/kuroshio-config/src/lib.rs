//! 黑潮 DNS 的設定。
//!
//! - 預設值只定義在 `defaults.json` 一個地方（由 2.x 的 `config.js` 轉出，去除個人網域）。
//! - 使用者設定只寫「跟預設值不同」的欄位，載入時跟預設值深層合併。
//! - 合併規則：物件逐欄合併；陣列與純量整個取代；`null` 表示「用預設值」。
//! - 不認識的欄位保留（新舊版本來回切換不會遺失設定）。
//! - 依硬體等級調整預設值（規格 05）：內建預設值 → 等級調整值 → 使用者設定。

pub mod uci;

use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;

/// 內建預設值（JSON 原文）
pub const DEFAULTS_JSON: &str = include_str!("../defaults.json");

/// 各硬體等級的預設值調整（規格 05 第 7 節）
pub const PROFILES_JSON: &str = include_str!("../profiles.json");

/// 硬體等級（規格 05 第 1 節）
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    Tiny,
    Small,
    Standard,
    Large,
}

impl Tier {
    pub const ALL: [Tier; 4] = [Tier::Tiny, Tier::Small, Tier::Standard, Tier::Large];

    pub fn name(self) -> &'static str {
        match self {
            Tier::Tiny => "tiny",
            Tier::Small => "small",
            Tier::Standard => "standard",
            Tier::Large => "large",
        }
    }

    pub fn parse(s: &str) -> Option<Tier> {
        Tier::ALL.into_iter().find(|t| t.name().eq_ignore_ascii_case(s.trim()))
    }

    /// 依實體記憶體（MB）分級
    pub fn from_mem_mb(total_mb: u64) -> Tier {
        match total_mb {
            0..200 => Tier::Tiny,
            200..400 => Tier::Small,
            400..1536 => Tier::Standard,
            _ => Tier::Large,
        }
    }
}

/// 這個等級的調整值
pub fn profile(tier: Tier) -> Value {
    let all: Value = serde_json::from_str(PROFILES_JSON).expect("內建 profiles.json 格式錯誤");
    all.get(tier.name()).cloned().unwrap_or(Value::Null)
}

/// 使用者設定裡指定的等級（`system.profile`）；`auto` 或沒寫 → None
pub fn requested_tier(user: &Value) -> Option<Tier> {
    get(user, "system.profile").and_then(Value::as_str).and_then(Tier::parse)
}

/// 內建預設值 → 等級調整值 → 使用者設定 → 綁定網域補齊（`normalize`）
pub fn build(tier: Tier, user: &Value) -> Value {
    let mut cfg = defaults();
    merge(&mut cfg, &profile(tier));
    merge(&mut cfg, user);
    normalize(&mut cfg);
    cfg
}

/// 綁定網域（頂層 `domain`）：整理成小寫、去掉結尾的點
pub fn bound_domain(cfg: &Value) -> String {
    cfg.get("domain")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

/// 合併後的整理：只填了綁定網域 `domain`（固定網域或 DDNS 名稱）時，需要網域的地方自動帶入。
///
/// - `site.hostname`、`community.domain` 空白 → `domain`
/// - `acme.domains` 是空的 → `[domain]`
/// - `ddns.records` 是空的而且 `ddns.enabled` → `[domain]`（DDNS 沒開就不動：固定網域不需要更新記錄）
///
/// 有明確填寫的一律不動；`domain` 空白時什麼都不做。
pub fn normalize(cfg: &mut Value) {
    let domain = bound_domain(cfg);
    if domain.is_empty() {
        return;
    }
    let Some(root) = cfg.as_object_mut() else { return };
    root.insert("domain".into(), Value::String(domain.clone()));
    let blank = |v: Option<&Value>| match v {
        None | Some(Value::Null) => true,
        Some(Value::String(s)) => s.trim().is_empty(),
        Some(Value::Array(a)) => !a.iter().any(|x| x.as_str().is_some_and(|s| !s.trim().is_empty())),
        _ => false,
    };
    let mut fill = |sec: &str, key: &str, val: Value, only_if: Option<&str>| {
        let entry = root.entry(sec.to_string()).or_insert_with(|| Value::Object(Default::default()));
        let Some(m) = entry.as_object_mut() else { return };
        if let Some(flag) = only_if {
            if m.get(flag).and_then(Value::as_bool) != Some(true) {
                return;
            }
        }
        if blank(m.get(key)) {
            m.insert(key.to_string(), val);
        }
    };
    fill("site", "hostname", Value::String(domain.clone()), None);
    fill("community", "domain", Value::String(domain.clone()), None);
    fill("acme", "domains", Value::Array(vec![Value::String(domain.clone())]), None);
    fill("ddns", "records", Value::Array(vec![Value::String(domain)]), Some("enabled"));
}

/// 讀使用者設定檔（只有使用者寫的欄位）；檔案不存在 → 空物件
pub fn read_user_file(path: &Path) -> Result<Value> {
    if !path.exists() {
        return Ok(Value::Object(Default::default()));
    }
    let text = std::fs::read_to_string(path).with_context(|| format!("讀不到設定檔 {}", path.display()))?;
    let text = text.trim_start_matches('\u{feff}');
    let over: Value = serde_json::from_str(text).with_context(|| format!("設定檔不是有效的 JSON：{}", path.display()))?;
    if !over.is_object() {
        anyhow::bail!("設定檔最外層必須是物件：{}", path.display());
    }
    Ok(over)
}

/// 內建預設值
pub fn defaults() -> Value {
    serde_json::from_str(DEFAULTS_JSON).expect("內建 defaults.json 格式錯誤")
}

/// 把 `over` 深層合併進 `base`
pub fn merge(base: &mut Value, over: &Value) {
    match (base, over) {
        (_, Value::Null) => {}
        (Value::Object(b), Value::Object(o)) => {
            for (k, v) in o {
                match b.get_mut(k) {
                    Some(slot) => merge(slot, v),
                    None => {
                        b.insert(k.clone(), v.clone());
                    }
                }
            }
        }
        (b, o) => *b = o.clone(),
    }
}

/// 預設值 + 使用者設定
pub fn with_overrides(over: &Value) -> Value {
    let mut cfg = defaults();
    merge(&mut cfg, over);
    normalize(&mut cfg);
    cfg
}

/// 讀設定檔（JSON）並跟預設值合併（不套用等級）；檔案不存在就只用預設值
pub fn load_file(path: &Path) -> Result<Value> {
    Ok(with_overrides(&read_user_file(path)?))
}

/// 用 `a.b.c` 路徑取值
pub fn get<'a>(cfg: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').try_fold(cfg, |v, k| v.get(k))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn defaults_are_valid_and_private() {
        let d = defaults();
        for k in [
            "listen",
            "upstream",
            "resolver",
            "filter",
            "cdn",
            "community",
            "jobs",
            "ddns",
            "acme",
        ] {
            assert!(d.get(k).is_some(), "缺少 {k}");
        }
        // 不帶任何個人網域、憑證、固定上游
        assert_eq!(get(&d, "site.hostname"), Some(&json!("")));
        assert_eq!(get(&d, "listen.doh.cert"), Some(&json!("")));
        assert_eq!(get(&d, "upstream.pinned"), Some(&json!([])));
        assert!(!DEFAULTS_JSON.contains("candy.moe"));
        // 3.0 新增的協議預設關閉
        assert_eq!(get(&d, "listen.doq.enabled"), Some(&json!(false)));
        assert_eq!(get(&d, "listen.doh.http3"), Some(&json!(false)));
    }

    #[test]
    fn merge_rules() {
        let mut b = json!({"a": {"x": 1, "y": [1, 2]}, "b": 2});
        merge(&mut b, &json!({"a": {"y": [3], "z": true}, "b": null, "c": "new"}));
        assert_eq!(b, json!({"a": {"x": 1, "y": [3], "z": true}, "b": 2, "c": "new"}));
    }

    #[test]
    fn tiers() {
        assert_eq!(Tier::from_mem_mb(120), Tier::Tiny);
        assert_eq!(Tier::from_mem_mb(245), Tier::Small);
        assert_eq!(Tier::from_mem_mb(490), Tier::Standard);
        assert_eq!(Tier::from_mem_mb(1000), Tier::Standard);
        assert_eq!(Tier::from_mem_mb(3900), Tier::Large);
        assert_eq!(Tier::parse(" Tiny"), Some(Tier::Tiny));
        assert_eq!(Tier::parse("auto"), None);
        assert_eq!(requested_tier(&json!({"system": {"profile": "small"}})), Some(Tier::Small));
        assert_eq!(requested_tier(&json!({})), None);
    }

    #[test]
    fn profiles_only_touch_existing_keys() {
        // 等級調整值裡的每個欄位都必須存在於內建預設值（避免拼錯字默默無效）
        fn walk(p: &Value, d: &Value, path: &str) {
            if let Value::Object(m) = p {
                for (k, v) in m {
                    let sub = d.get(k).unwrap_or_else(|| panic!("profiles.json 的 {path}.{k} 不在預設值裡"));
                    walk(v, sub, &format!("{path}.{k}"));
                }
            }
        }
        for t in Tier::ALL {
            walk(&profile(t), &defaults(), t.name());
        }
    }

    #[test]
    fn merge_order_user_wins() {
        let user = json!({"resolver": {"cacheMax": 9999}});
        let tiny = build(Tier::Tiny, &user);
        assert_eq!(get(&tiny, "resolver.cacheMax"), Some(&json!(9999)), "使用者設定優先");
        assert_eq!(get(&tiny, "resolver.parallel"), Some(&json!(2)), "沒寫的由等級決定");
        assert_eq!(get(&tiny, "system.maxQuicConnections"), Some(&json!(0)));
        assert_eq!(get(&tiny, "jobs.cdn-scan.enabled"), Some(&json!(false)));
        assert!(get(&tiny, "jobs.cdn-scan.at").is_some(), "只改 enabled，其他欄位保留");
        let large = build(Tier::Large, &json!({}));
        assert_eq!(large, defaults(), "large 就是內建預設值");
        // 等級越低，預算越小
        let caches: Vec<u64> = Tier::ALL
            .iter()
            .map(|t| get(&build(*t, &json!({})), "resolver.cacheMax").unwrap().as_u64().unwrap())
            .collect();
        assert!(caches.windows(2).all(|w| w[0] < w[1]), "{caches:?}");
    }

    #[test]
    fn bound_domain_fills_empty_fields_only() {
        // 只填 domain、DDNS 沒開（固定網域）：公開頁、社群、ACME 都有網域，DDNS 記錄不動
        let c = build(Tier::Large, &json!({ "domain": " DNS.Example.com. " }));
        assert_eq!(get(&c, "domain"), Some(&json!("dns.example.com")));
        assert_eq!(get(&c, "site.hostname"), Some(&json!("dns.example.com")));
        assert_eq!(get(&c, "community.domain"), Some(&json!("dns.example.com")));
        assert_eq!(get(&c, "acme.domains"), Some(&json!(["dns.example.com"])));
        assert_eq!(get(&c, "ddns.records"), Some(&json!([])), "DDNS 沒開：不產生記錄");
        assert_eq!(get(&c, "ddns.enabled"), Some(&json!(false)));
        // DDNS 開了又沒寫記錄：更新綁定網域
        let c = build(Tier::Large, &json!({ "domain": "dns.example.com", "ddns": { "enabled": true } }));
        assert_eq!(get(&c, "ddns.records"), Some(&json!(["dns.example.com"])));
        // 有明確填寫的不動
        let c = build(
            Tier::Tiny,
            &json!({
                "domain": "dns.example.com",
                "site": { "hostname": "www.example.net" },
                "community": { "domain": "share.example.net" },
                "acme": { "domains": ["a.example.net", "b.example.net"] },
                "ddns": { "enabled": true, "records": ["home.example.net"] }
            }),
        );
        assert_eq!(get(&c, "site.hostname"), Some(&json!("www.example.net")));
        assert_eq!(get(&c, "community.domain"), Some(&json!("share.example.net")));
        assert_eq!(get(&c, "acme.domains"), Some(&json!(["a.example.net", "b.example.net"])));
        assert_eq!(get(&c, "ddns.records"), Some(&json!(["home.example.net"])));
        // 沒有 domain：完全不動（跟以前一樣）
        let c = build(Tier::Large, &json!({ "site": { "hostname": "old.example.net" } }));
        assert_eq!(get(&c, "domain"), Some(&json!("")));
        assert!(get(&c, "community.domain").is_none());
        assert_eq!(get(&c, "acme.domains"), Some(&json!([])));
        // with_overrides（測試用）也一樣
        let c = with_overrides(&json!({ "domain": "dns.example.com" }));
        assert_eq!(get(&c, "site.hostname"), Some(&json!("dns.example.com")));
    }

    #[test]
    fn new_keys_have_safe_defaults() {
        let d = defaults();
        assert_eq!(get(&d, "domain"), Some(&json!("")));
        assert_eq!(get(&d, "tls"), Some(&json!({ "cert": "", "key": "" })));
        assert_eq!(get(&d, "listen.doh.tls"), Some(&json!("auto")));
        for k in [
            "listen.dot.binds",
            "listen.doq.binds",
            "listen.doh.binds",
            "listen.doh.http3Binds",
            "ddns.interfaces",
        ] {
            assert_eq!(get(&d, k), Some(&json!([])), "{k}");
        }
        assert_eq!(get(&d, "ddns.ipv4"), Some(&json!(true)));
        assert_eq!(get(&d, "ddns.ipv6"), Some(&json!(false)), "中華電信常擋 IPv6 連入：AAAA 預設不發布");
    }

    #[test]
    fn load_missing_file_gives_defaults() {
        let v = load_file(Path::new("/nonexistent/kuroshio.json")).unwrap();
        assert_eq!(v, defaults());
    }
}
