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

/// 內建預設值 → 等級調整值 → 使用者設定
pub fn build(tier: Tier, user: &Value) -> Value {
    let mut cfg = defaults();
    merge(&mut cfg, &profile(tier));
    merge(&mut cfg, user);
    cfg
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
    fn load_missing_file_gives_defaults() {
        let v = load_file(Path::new("/nonexistent/kuroshio.json")).unwrap();
        assert_eq!(v, defaults());
    }
}
