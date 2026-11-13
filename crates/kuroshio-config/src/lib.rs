//! 黑潮 DNS 的設定。
//!
//! - 預設值只定義在 `defaults.json` 一個地方（由 2.x 的 `config.js` 轉出，去除個人網域）。
//! - 使用者設定只寫「跟預設值不同」的欄位，載入時跟預設值深層合併。
//! - 合併規則：物件逐欄合併；陣列與純量整個取代；`null` 表示「用預設值」。
//! - 不認識的欄位保留（新舊版本來回切換不會遺失設定）。
//! - 沒有「硬體等級」：記憶體結構的大小由執行時的記憶體控制動態決定（規格 09），
//!   設定裡的上限只是防濫用的安全上限；並行數之類跟 CPU 有關的值寫 `"auto"`，
//!   載入時依 CPU 核心數換算（[`derive_auto`]，規格 05 第 7 節）。使用者明確填的數字一律優先。
//! - 舊版的 `system.profile` / `system.tier`（硬體等級）、`system.memoryBudgetMB` 照樣接受、不使用（[`legacy_keys`]）。

pub mod uci;

use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;

/// 內建預設值（JSON 原文）
pub const DEFAULTS_JSON: &str = include_str!("../defaults.json");

/// 執行環境（換算 `"auto"` 用）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Host {
    /// CPU 核心數（可用的執行緒數）
    pub cores: usize,
}

impl Host {
    pub fn detect() -> Host {
        Host {
            cores: std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
        }
    }
}

/// 依 CPU 核心數換算的設定（`"auto"` 或沒寫時套用；規格 05 第 7 節）。
/// 每一項：（路徑，每個核心多少，下限，上限）；`resolver.parallel` 另外處理
pub const PER_CORE: [(&str, u64, u64, u64); 10] = [
    // 開機預熱每秒重問幾個名稱：單核心 5、四核心以上 20
    ("resolver.warmRate", 5, 5, 20),
    // 上游 IP 測速同時幾個連線
    ("iprank.concurrency", 8, 8, 64),
    // CDN 節點驗證同時幾個（每個都是 TLS 握手，吃 CPU）
    ("cdn.verifyConcurrency", 2, 2, 8),
    // 每日評測同時幾個上游
    ("benchmark.concurrency", 8, 8, 50),
    // 網段掃描同時幾個探測
    ("scan.concurrency", 50, 32, 400),
    ("pool.latencyConcurrency", 32, 32, 200),
    ("pool.probeConcurrency", 8, 8, 32),
    // 加密連線（每條約 30–60 KB）：核心數決定處理得了多少握手；記憶體由執行時的壓力判斷再收緊
    ("system.maxTlsConnections", 128, 128, 2048),
    ("system.maxQuicConnections", 32, 32, 512),
    // 沒有固定字串、每次查詢都要跑的過濾規則（每 2,000 條約讓每次查詢多 0.5 ms，慢的 CPU 更多）：
    // 核心數少的通常也是慢的 CPU。這是 CPU 時間的上限，不是記憶體上限
    ("filter.maxUnindexed", 250, 200, 2000),
];

/// 數值設定：數字或可以轉成數字的字串（UCI 會給字串）；`"auto"`、空白、沒寫 → None
pub fn num_or_auto(v: Option<&Value>) -> Option<u64> {
    match v? {
        Value::Number(n) => n.as_u64().or_else(|| n.as_f64().filter(|f| *f >= 0.0).map(|f| f as u64)),
        Value::String(s) => s.trim().parse::<u64>().ok(),
        _ => None,
    }
}

/// 把 `"auto"` 換算成數字（使用者填了數字的不動）
pub fn derive_auto(cfg: &mut Value, host: &Host) {
    let c = host.cores.max(1) as u64;
    let mut set = |path: &str, auto: u64| {
        let parts: Vec<&str> = path.split('.').collect();
        let Some(parent) = parts[..parts.len() - 1].iter().try_fold(&mut *cfg, |v, k| v.get_mut(*k)) else {
            return;
        };
        let Some(m) = parent.as_object_mut() else { return };
        let key = parts[parts.len() - 1];
        let val = num_or_auto(m.get(key)).unwrap_or(auto);
        m.insert(key.to_string(), Value::from(val));
    };
    for (path, per, lo, hi) in PER_CORE {
        set(path, (per * c).clamp(lo, hi));
    }
    // 同時問幾個上游：單核心 2、雙核心 3、更多核心全部一起問（0 = 全部）
    set(
        "resolver.parallel",
        match c {
            1 => 2,
            2 => 3,
            _ => 0,
        },
    );
}

/// 使用者設定裡已經不用的舊欄位（啟動時記一次說明，不算錯誤）
pub fn legacy_keys(user: &Value) -> Vec<String> {
    let mut v = Vec::new();
    for k in ["system.profile", "system.tier", "system.memoryBudgetMB"] {
        match get(user, k) {
            None | Some(Value::Null) => {}
            Some(Value::String(s)) if s.trim().is_empty() || s.trim().eq_ignore_ascii_case("auto") => {}
            Some(x) => v.push(format!("{k} = {x}")),
        }
    }
    v
}

/// 3.1.x 的預設過濾清單（`filter.lists`）。設定頁存檔時可能把整份清單寫進使用者設定；
/// 跟這份完全相同（同樣的項目、同樣的順序）就是使用者沒動過，載入時換成新的預設清單（[`old_default_lists`]）
pub const OLD_DEFAULT_LISTS_3_1: &str = r#"[
    {"url": "https://easylist-downloads.adblockplus.org/easylistchina.txt", "category": "ads", "name": "EasyList China"},
    {"url": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_21.txt", "category": "ads", "name": "CHN: anti-AD"},
    {"url": "https://filter.futa.gg/hosts_abp.txt", "category": "ads", "name": "FutaGuard LowTechHost（台灣廣告）"},
    {"url": "https://raw.githubusercontent.com/blocklistproject/Lists/master/tracking.txt", "category": "ads", "name": "blocklistproject tracking", "enabled": false},
    {"url": "https://danny0838.github.io/content-farm-terminator/files/blocklist/content-farms.txt", "category": "ads", "name": "內容農場終結者", "enabled": false},
    {"url": "https://raw.githubusercontent.com/ignaciocastro/a-dove-is-dumb/main/list.txt", "category": "telemetry", "name": "a-dove-is-dumb（Adobe 遙測）"},
    {"url": "https://raw.githubusercontent.com/Ruddernation-Designs/Adobe-URL-Block-List/master/hosts", "category": "telemetry", "name": "Ruddernation（Adobe 驗證）"},
    {"url": "https://raw.githubusercontent.com/blocklistproject/Lists/master/smart-tv.txt", "category": "telemetry", "name": "blocklistproject smart-tv（電視遙測）"},
    {"url": "https://raw.githubusercontent.com/blocklistproject/Lists/master/adobe.txt", "category": "telemetry", "name": "blocklistproject adobe（會擋 Adobe 登入）", "enabled": false},
    {"url": "https://filter.futa.gg/TW165_abp.txt", "category": "malware", "name": "FutaGuard TW165（台灣 165 反詐騙）"},
    {"url": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_44.txt", "category": "malware", "name": "HaGeZi's Threat Intelligence Feeds", "enabled": false},
    {"url": "https://filter.futa.gg/nrd/past-07day_abp.txt", "category": "malware", "name": "FutaGuard 新註冊網域（7 天，誤擋風險高）", "enabled": false}
]"#;

/// 比對用：`enabled` 沒寫等於 `true`（拿掉 `"enabled": true`）；欄位順序本來就不影響比較
fn list_entry_key(v: &Value) -> Value {
    let mut v = v.clone();
    if let Some(m) = v.as_object_mut() {
        if m.get("enabled") == Some(&Value::Bool(true)) {
            m.remove("enabled");
        }
    }
    v
}

/// 使用者設定裡的 `filter.lists` 是不是 3.1.x 的預設清單原封不動（[`OLD_DEFAULT_LISTS_3_1`]）。
/// 是的話 [`build`] 會換成新的預設清單；啟動時用這個判斷要不要記一行說明
pub fn old_default_lists(user: &Value) -> bool {
    let Some(Value::Array(lists)) = get(user, "filter.lists") else {
        return false;
    };
    let old: Vec<Value> = serde_json::from_str(OLD_DEFAULT_LISTS_3_1).expect("OLD_DEFAULT_LISTS_3_1 格式錯誤");
    lists.len() == old.len() && lists.iter().zip(&old).all(|(a, b)| list_entry_key(a) == list_entry_key(b))
}

/// 內建預設值 → 使用者設定 → 綁定網域補齊（`normalize`）→ `"auto"` 換算（這台機器的核心數）
pub fn build(user: &Value) -> Value {
    build_for(&Host::detect(), user)
}

/// 同 [`build`]，指定執行環境（測試用）
pub fn build_for(host: &Host, user: &Value) -> Value {
    let mut cfg = defaults();
    merge(&mut cfg, user);
    if old_default_lists(user) {
        // 舊版預設清單沒動過：用新的預設清單（設定檔本身不改寫）
        if let (Some(slot), Some(new)) = (
            cfg.get_mut("filter").and_then(|f| f.get_mut("lists")),
            get(&defaults(), "filter.lists").cloned(),
        ) {
            *slot = new;
        }
    }
    normalize(&mut cfg);
    derive_auto(&mut cfg, host);
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

/// 自己網域的上層網域（分享檔、好友同步不送出這底下的名稱，避免洩漏自己的子網域）。
///
/// 從綁定網域 `domain`，以及 `site.hostname`、`community.domain`、`ddns.records`、`ddns.zone`、
/// `acme.domains` 取名稱：三段以上去掉第一段（`dns.example.net` → `example.net`、
/// `dns.example.com.tw` → `example.com.tw`），剛好兩段就是它本身；一段、IP 位址不算。
/// 回傳不重複的清單（沒設定任何網域時是空的）
pub fn own_base_domains(cfg: &Value) -> Vec<String> {
    let mut names = vec![bound_domain(cfg)];
    for k in ["site.hostname", "community.domain", "ddns.zone"] {
        if let Some(s) = get(cfg, k).and_then(Value::as_str) {
            names.push(s.to_string());
        }
    }
    for k in ["ddns.records", "acme.domains"] {
        for v in get(cfg, k).and_then(Value::as_array).into_iter().flatten() {
            if let Some(s) = v.as_str() {
                names.push(s.to_string());
            }
        }
    }
    let mut out: Vec<String> = Vec::new();
    for n in names {
        let n = n.trim().trim_end_matches('.').to_ascii_lowercase();
        let n = n.strip_prefix("*.").unwrap_or(&n);
        if n.parse::<std::net::IpAddr>().is_ok() || n.starts_with('[') {
            continue;
        }
        let labels: Vec<&str> = n.split('.').collect();
        if labels.len() < 2 || labels.iter().any(|l| l.is_empty()) {
            continue;
        }
        let base = if labels.len() >= 3 { labels[1..].join(".") } else { n.to_string() };
        if !out.contains(&base) {
            out.push(base);
        }
    }
    out
}

/// `name` 是不是自己的網域（等於某個上層網域，或在它底下）；`bases` 來自 [`own_base_domains`]
pub fn is_own_domain(name: &str, bases: &[String]) -> bool {
    let n = name.trim().trim_end_matches('.').to_ascii_lowercase();
    bases
        .iter()
        .any(|b| n == *b || (n.len() > b.len() && n.ends_with(b.as_str()) && n.as_bytes()[n.len() - b.len() - 1] == b'.'))
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

/// 預設值 + 使用者設定（同 [`build`]）
pub fn with_overrides(over: &Value) -> Value {
    build(over)
}

/// 讀設定檔（JSON）並跟預設值合併；檔案不存在就只用預設值
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
    fn auto_values_follow_cores_and_user_wins() {
        let one = build_for(&Host { cores: 1 }, &json!({}));
        let four = build_for(&Host { cores: 4 }, &json!({}));
        let many = build_for(&Host { cores: 64 }, &json!({}));
        let n = |c: &Value, k: &str| get(c, k).and_then(Value::as_u64).unwrap_or_else(|| panic!("{k} 不是數字"));
        // 每一項都換算成數字；核心越多越大，而且不超過上限、不低於下限
        for (k, _, lo, hi) in PER_CORE {
            assert!(n(&one, k) >= lo && n(&many, k) <= hi, "{k}");
            assert!(n(&one, k) <= n(&four, k) && n(&four, k) <= n(&many, k), "{k}");
        }
        assert_eq!(n(&one, "resolver.parallel"), 2);
        assert_eq!(n(&build_for(&Host { cores: 2 }, &json!({})), "resolver.parallel"), 3);
        assert_eq!(n(&four, "resolver.parallel"), 0, "四核心：全部一起問");
        assert_eq!(n(&one, "scan.concurrency"), 50);
        assert_eq!(n(&four, "scan.concurrency"), 200);
        assert_eq!(n(&many, "scan.concurrency"), 400);
        assert_eq!(n(&one, "system.maxTlsConnections"), 128);
        assert_eq!(n(&many, "system.maxTlsConnections"), 2048);
        assert_eq!(n(&one, "system.maxQuicConnections"), 32, "單核心也不關 QUIC（以前 tiny 等級是 0）");
        // 使用者填的數字（UCI 給的字串也算）優先；"auto" 照樣換算
        let u = build_for(
            &Host { cores: 1 },
            &json!({ "resolver": { "parallel": 0, "warmRate": "7" }, "scan": { "concurrency": 999 }, "iprank": { "concurrency": "auto" } }),
        );
        assert_eq!(n(&u, "resolver.parallel"), 0);
        assert_eq!(n(&u, "resolver.warmRate"), 7);
        assert_eq!(n(&u, "scan.concurrency"), 999, "使用者明確填的不受上限影響");
        assert_eq!(n(&u, "iprank.concurrency"), 8);
        // 記憶體結構的上限不分機器：都是同一個安全上限（實際大小由記憶體控制動態決定）
        for k in [
            "resolver.cacheMax",
            "cdn.maxEntries",
            "filter.maxDomains",
            "system.queryLogRing",
            "community.maxBundleMB",
        ] {
            assert_eq!(get(&one, k), get(&many, k), "{k}");
        }
        assert_eq!(
            get(&one, "jobs.cdn-scan.enabled"),
            Some(&json!(true)),
            "背景工作不再依等級停用：記憶體夠時才跑"
        );
    }

    #[test]
    fn legacy_tier_keys_are_accepted_and_ignored() {
        let user = json!({ "system": { "tier": "tiny", "profile": "small", "memoryBudgetMB": 40 }, "resolver": { "cacheMax": 9999 } });
        let c = build_for(&Host { cores: 4 }, &user);
        assert_eq!(get(&c, "resolver.cacheMax"), Some(&json!(9999)));
        assert_eq!(
            get(&c, "cdn.maxEntries"),
            get(&build_for(&Host { cores: 4 }, &json!({})), "cdn.maxEntries"),
            "等級不影響任何值"
        );
        assert_eq!(legacy_keys(&user).len(), 3);
        assert!(legacy_keys(&json!({ "system": { "profile": "auto" } })).is_empty());
        assert!(legacy_keys(&json!({})).is_empty());
        // 預設值裡不再有等級、預算欄位；新的保留量欄位預設 0（自動）
        let d = defaults();
        for k in ["system.profile", "system.tier", "system.memoryBudgetMB"] {
            assert!(get(&d, k).is_none(), "{k}");
        }
        for k in [
            "system.memoryReserveMB",
            "system.memoryReservePercent",
            "system.storageReserveMB",
            "system.storageReservePercent",
        ] {
            assert_eq!(get(&d, k), Some(&json!(0)), "{k}");
        }
        assert_eq!(get(&d, "system.oomScoreAdj"), Some(&json!(-500)));
        // 最久未存上限預設 24 小時（Flash 上最多 24 小時）
        assert_eq!(get(&d, "system.persistMaxAgeHours").and_then(Value::as_u64), Some(24));
    }

    #[test]
    fn merge_order_user_wins() {
        let user = json!({ "resolver": { "cacheMax": 9999 } });
        let c = build(&user);
        assert_eq!(get(&c, "resolver.cacheMax"), Some(&json!(9999)), "使用者設定優先");
        assert!(get(&c, "jobs.cdn-scan.at").is_some());
    }

    #[test]
    fn own_base_domains_from_config() {
        let b = |user: Value| own_base_domains(&build_for(&Host { cores: 1 }, &user));
        assert!(b(json!({})).is_empty(), "沒設定網域：沒有");
        assert_eq!(b(json!({ "domain": "dns.example.net" })), vec!["example.net"]);
        assert_eq!(b(json!({ "domain": "DNS.Example.com.tw." })), vec!["example.com.tw"]);
        assert_eq!(b(json!({ "domain": "example.net" })), vec!["example.net"], "兩段的網域就是它本身");
        assert_eq!(
            b(json!({
                "domain": "dns.example.net",
                "site": { "hostname": "www.example.net" },
                "ddns": { "enabled": true, "records": ["home.example.com", "192.0.2.1"] },
                "acme": { "domains": ["*.example.org", "localhost"] }
            })),
            vec!["example.net", "example.com", "example.org"],
            "不重複；IP、單段名稱不算"
        );
        let bases = vec!["example.net".to_string()];
        for n in ["example.net", "time.example.net", "a.b.example.net.", "NEXT.Example.NET"] {
            assert!(is_own_domain(n, &bases), "{n}");
        }
        for n in ["notexample.net", "example.network", "example.com", "net"] {
            assert!(!is_own_domain(n, &bases), "{n}");
        }
        assert!(!is_own_domain("example.net", &[]));
    }

    #[test]
    fn bound_domain_fills_empty_fields_only() {
        // 只填 domain、DDNS 沒開（固定網域）：公開頁、社群、ACME 都有網域，DDNS 記錄不動
        let c = build(&json!({ "domain": " DNS.Example.com. " }));
        assert_eq!(get(&c, "domain"), Some(&json!("dns.example.com")));
        assert_eq!(get(&c, "site.hostname"), Some(&json!("dns.example.com")));
        assert_eq!(get(&c, "community.domain"), Some(&json!("dns.example.com")));
        assert_eq!(get(&c, "acme.domains"), Some(&json!(["dns.example.com"])));
        assert_eq!(get(&c, "ddns.records"), Some(&json!([])), "DDNS 沒開：不產生記錄");
        assert_eq!(get(&c, "ddns.enabled"), Some(&json!(false)));
        // DDNS 開了又沒寫記錄：更新綁定網域
        let c = build(&json!({ "domain": "dns.example.com", "ddns": { "enabled": true } }));
        assert_eq!(get(&c, "ddns.records"), Some(&json!(["dns.example.com"])));
        // 有明確填寫的不動
        let c = build(&json!({
            "domain": "dns.example.com",
            "site": { "hostname": "www.example.net" },
            "community": { "domain": "share.example.net" },
            "acme": { "domains": ["a.example.net", "b.example.net"] },
            "ddns": { "enabled": true, "records": ["home.example.net"] }
        }));
        assert_eq!(get(&c, "site.hostname"), Some(&json!("www.example.net")));
        assert_eq!(get(&c, "community.domain"), Some(&json!("share.example.net")));
        assert_eq!(get(&c, "acme.domains"), Some(&json!(["a.example.net", "b.example.net"])));
        assert_eq!(get(&c, "ddns.records"), Some(&json!(["home.example.net"])));
        // 沒有 domain：完全不動（跟以前一樣）
        let c = build(&json!({ "site": { "hostname": "old.example.net" } }));
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
        assert_eq!(v, build(&json!({})));
    }

    fn old_lists() -> Vec<Value> {
        serde_json::from_str(OLD_DEFAULT_LISTS_3_1).unwrap()
    }

    #[test]
    fn old_default_lists_are_replaced() {
        let new = get(&defaults(), "filter.lists").unwrap().clone();
        assert_ne!(Value::Array(old_lists()), new);
        // 原封不動的舊預設清單 → 新的預設清單；其他過濾設定照樣保留
        let user = json!({ "filter": { "lists": old_lists(), "updateIntervalHours": 12 } });
        assert!(old_default_lists(&user));
        let c = build(&user);
        assert_eq!(get(&c, "filter.lists"), Some(&new));
        assert_eq!(get(&c, "filter.updateIntervalHours"), Some(&json!(12)));
        // 設定頁存檔的寫法：明確寫 "enabled": true、欄位順序不同，一樣算沒動過
        let saved: Vec<Value> = old_lists()
            .into_iter()
            .map(|l| {
                let mut m = serde_json::Map::new();
                m.insert("enabled".into(), l.get("enabled").cloned().unwrap_or(json!(true)));
                for k in ["name", "category", "url"] {
                    m.insert(k.into(), l[k].clone());
                }
                Value::Object(m)
            })
            .collect();
        let user = json!({ "filter": { "lists": saved } });
        assert!(old_default_lists(&user));
        assert_eq!(get(&build(&user), "filter.lists"), Some(&new));
    }

    #[test]
    fn modified_lists_are_kept() {
        let keep = |lists: Vec<Value>| {
            let user = json!({ "filter": { "lists": lists.clone() } });
            assert!(!old_default_lists(&user));
            assert_eq!(get(&build(&user), "filter.lists"), Some(&Value::Array(lists)));
        };
        // 改了一個網址
        let mut a = old_lists();
        a[0]["url"] = json!("https://example.com/my-easylist.txt");
        keep(a);
        // 切換了一個啟用狀態（打開本來關閉的、關掉本來打開的）
        let mut b = old_lists();
        b[3]["enabled"] = json!(true);
        keep(b);
        let mut c = old_lists();
        c[6]["enabled"] = json!(false);
        keep(c);
        // 加了保護旗標、少一份、多一份、換順序
        let mut d = old_lists();
        d[9]["protect"] = json!(true);
        keep(d);
        let mut e = old_lists();
        e.pop();
        keep(e);
        let mut f = old_lists();
        f.push(json!({ "url": "https://example.com/a.txt", "category": "ads", "name": "A" }));
        keep(f);
        let mut g = old_lists();
        g.swap(0, 1);
        keep(g);
        // 沒寫 filter.lists：直接用新的預設清單
        assert!(!old_default_lists(&json!({})));
        assert_eq!(get(&build(&json!({})), "filter.lists"), get(&defaults(), "filter.lists"));
    }
}
