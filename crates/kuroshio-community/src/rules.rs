//! 好友請求的自動規則（沿用 v1 `rules.js`，規格 03 第 6 節多兩個條件）
//!
//! 規則由上往下比對，第一條「所有有填的條件都符合」的規則決定動作；都不符合 → 人工審核。
//! 動作：accept 同意 / reject 拒絕 / block 封鎖 / manual 人工審核
//!
//! 條件（沒填就不檢查）：
//!   domain_suffix    對方網域結尾
//!   asn              對方電信業者 ASN（可多個）
//!   same_asn         跟我同一家電信業者
//!   colo             對方 Cloudflare 機房（對方自報）
//!   max_rtt_ms / max_jitter_ms / max_loss   我量到的連線品質上限
//!   min_age_days     對方身分至少運作幾天（對方自報）
//!   min_mutual       至少幾個共同好友
//!   max_friends      我的好友數還沒超過這個數字才符合
//!   require_ip_match 來源 IP 必須在對方網域的解析結果裡（v1 的硬性條件，v2 改成規則）
//!   has_txt          對方有設定 `_kuroshio` TXT 記錄

use crate::peers::PeerInfo;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Accept,
    Reject,
    Block,
    Manual,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Accept => "accept",
            Action::Reject => "reject",
            Action::Block => "block",
            Action::Manual => "manual",
        }
    }
}

pub struct Ctx<'a> {
    pub domain: &'a str,
    pub info: &'a PeerInfo,
    pub my_asn: Option<u32>,
    pub friend_count: usize,
}

/// 單值或陣列都當成清單；空字串、null 不算
fn list(v: Option<&Value>) -> Vec<String> {
    let one = |x: &Value| match x {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    };
    match v {
        Some(Value::Array(a)) => a.iter().filter_map(one).collect(),
        Some(x) => one(x).into_iter().collect(),
        None => vec![],
    }
}

fn num(v: Option<&Value>) -> Option<f64> {
    match v? {
        Value::Number(n) => n.as_f64(),
        Value::String(s) if !s.trim().is_empty() => s.trim().parse().ok(),
        _ => None,
    }
}

fn flag(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64() == Some(1.0),
        Some(Value::String(s)) => s == "1" || s == "true",
        _ => false,
    }
}

/// 沒量到（None）一律不符合
fn le(v: Option<f64>, max: Option<f64>) -> bool {
    match max {
        None => true,
        Some(m) => v.map(|x| x <= m).unwrap_or(false),
    }
}

pub fn matches(rule: &Value, c: &Ctx) -> bool {
    let info = c.info;
    let suffixes: Vec<String> = list(rule.get("domain_suffix"))
        .into_iter()
        .map(|s| s.to_ascii_lowercase().trim_start_matches('.').to_string())
        .collect();
    if !suffixes.is_empty() && !suffixes.iter().any(|s| c.domain == s || c.domain.ends_with(&format!(".{s}"))) {
        return false;
    }
    let asns: Vec<u32> = list(rule.get("asn"))
        .iter()
        .filter_map(|a| a.trim_start_matches(['a', 'A', 's', 'S']).parse().ok())
        .collect();
    if !asns.is_empty() && !info.asn.map(|a| asns.contains(&a)).unwrap_or(false) {
        return false;
    }
    if flag(rule.get("same_asn")) && (info.asn.is_none() || info.asn != c.my_asn) {
        return false;
    }
    let colos: Vec<String> = list(rule.get("colo")).into_iter().map(|s| s.to_ascii_uppercase()).collect();
    if !colos.is_empty() && !colos.contains(&info.colo.to_ascii_uppercase()) {
        return false;
    }
    if !le(info.rtt_ms.map(f64::from), num(rule.get("max_rtt_ms"))) {
        return false;
    }
    if !le(info.jitter_ms.map(f64::from), num(rule.get("max_jitter_ms"))) {
        return false;
    }
    if !le(info.loss_pct.map(f64::from), num(rule.get("max_loss"))) {
        return false;
    }
    if let Some(min) = num(rule.get("min_age_days")) {
        if !info.age_days.map(|d| d as f64 >= min).unwrap_or(false) {
            return false;
        }
    }
    if let Some(min) = num(rule.get("min_mutual")) {
        if !info.mutual.map(|d| d as f64 >= min).unwrap_or(false) {
            return false;
        }
    }
    if let Some(max) = num(rule.get("max_friends")) {
        if (c.friend_count as f64) >= max {
            return false;
        }
    }
    if flag(rule.get("require_ip_match")) && info.ip_match != Some(true) {
        return false;
    }
    if flag(rule.get("has_txt")) && info.has_txt != Some(true) {
        return false;
    }
    true
}

/// 回傳（動作, 規則名稱）
pub fn decide(rules: &[Value], c: &Ctx) -> (Action, String) {
    for r in rules {
        let en = r.get("enabled");
        if matches!(en, Some(Value::Bool(false))) || en.and_then(Value::as_str) == Some("0") || en.and_then(Value::as_i64) == Some(0) {
            continue;
        }
        if matches(r, c) {
            let a = match r.get("action").and_then(Value::as_str) {
                Some("accept") => Action::Accept,
                Some("reject") => Action::Reject,
                Some("block") => Action::Block,
                _ => Action::Manual,
            };
            return (a, r.get("name").and_then(Value::as_str).unwrap_or("").to_string());
        }
    }
    (Action::Manual, String::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx<'a>(domain: &'a str, info: &'a PeerInfo) -> Ctx<'a> {
        Ctx {
            domain,
            info,
            my_asn: Some(3462),
            friend_count: 3,
        }
    }

    #[test]
    fn v1_conditions() {
        let info = PeerInfo {
            asn: Some(3462),
            colo: "TPE".into(),
            rtt_ms: Some(12),
            jitter_ms: Some(3),
            loss_pct: Some(0),
            age_days: Some(40),
            mutual: Some(2),
            ..Default::default()
        };
        let c = ctx("dns.friend.com", &info);
        assert!(matches(&json!({ "domain_suffix": ["friend.com"] }), &c));
        assert!(matches(&json!({ "domain_suffix": ".friend.com" }), &c));
        assert!(!matches(&json!({ "domain_suffix": ["other.com"] }), &c));
        assert!(matches(&json!({ "asn": ["AS3462", "4780"] }), &c));
        assert!(!matches(&json!({ "asn": [9924] }), &c));
        assert!(matches(&json!({ "same_asn": "1" }), &c));
        assert!(matches(&json!({ "colo": ["tpe"] }), &c));
        assert!(matches(&json!({ "max_rtt_ms": "20", "max_jitter_ms": 5, "max_loss": 0 }), &c));
        assert!(!matches(&json!({ "max_rtt_ms": 10 }), &c));
        assert!(matches(&json!({ "min_age_days": 30, "min_mutual": 2 }), &c));
        assert!(!matches(&json!({ "min_mutual": 3 }), &c));
        assert!(matches(&json!({ "max_friends": 4 }), &c));
        assert!(!matches(&json!({ "max_friends": 3 }), &c));
    }

    #[test]
    fn v2_conditions_and_order() {
        let mut info = PeerInfo {
            ip_match: Some(false),
            has_txt: Some(true),
            ..Default::default()
        };
        let rules = vec![
            json!({ "name": "停用", "enabled": "0", "action": "block" }),
            json!({ "name": "IP 要符合", "action": "accept", "require_ip_match": "1" }),
            json!({ "name": "有 TXT", "action": "reject", "has_txt": true }),
        ];
        assert_eq!(decide(&rules, &ctx("a.test", &info)), (Action::Reject, "有 TXT".to_string()));
        info.ip_match = Some(true);
        assert_eq!(decide(&rules, &ctx("a.test", &info)).0, Action::Accept);
        info.ip_match = None;
        info.has_txt = None;
        assert_eq!(decide(&rules, &ctx("a.test", &info)), (Action::Manual, String::new()));
    }
}
