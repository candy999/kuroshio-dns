//! 設定：`community.*`（kuroshio-config 的 defaults.json / UCI 轉換）

use serde_json::Value;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    pub enabled: bool,
    /// 我的網域（小寫）
    pub domain: String,
    /// 對外端點：`https://網域[:埠]`、`dot://網域[:埠]`、`doq://網域[:埠]`
    pub endpoints: Vec<String>,
    pub pow_bits: u8,
    pub reject_days: u32,
    pub stale_days: u32,
    pub sync_interval_min: u32,
    pub max_friends: usize,
    /// 資料品質分數下限（0 = 不檢查）
    pub min_hit_rate: f64,
    /// 分數低於下限時自動刪除好友（v1 行為，預設關閉；關閉時只暫停採用）
    pub auto_delete_low_hit_rate: bool,
    pub share_domains: bool,
    pub share_upstreams: bool,
    pub rules: Vec<Value>,
    /// 收到的資料（解壓後）上限，依等級 4 / 8 / 32 MB
    pub max_bundle_mb: u32,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            enabled: false,
            domain: String::new(),
            endpoints: vec![],
            pow_bits: 16,
            reject_days: 7,
            stale_days: 7,
            sync_interval_min: 60,
            max_friends: 50,
            min_hit_rate: 0.0,
            auto_delete_low_hit_rate: false,
            share_domains: true,
            share_upstreams: true,
            rules: vec![],
            max_bundle_mb: 32,
        }
    }
}

fn num(v: Option<&Value>) -> Option<f64> {
    match v? {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn flag(v: Option<&Value>, def: bool) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().map(|x| x != 0.0).unwrap_or(def),
        Some(Value::String(s)) => matches!(s.as_str(), "1" | "true" | "yes" | "on"),
        _ => def,
    }
}

impl Config {
    /// 從 `community` 區段讀；`endpoints` 可以是 `{doh, dot, doq}` 或陣列
    pub fn from_json(c: &Value) -> Config {
        let d = Config::default();
        let endpoints = match c.get("endpoints") {
            Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).map(str::to_string).collect(),
            Some(Value::Object(o)) => ["doq", "dot", "doh", "https"]
                .iter()
                .filter_map(|k| o.get(*k).and_then(Value::as_str))
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect(),
            _ => vec![],
        };
        Config {
            enabled: flag(c.get("enabled"), d.enabled),
            domain: c
                .get("domain")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .trim_end_matches('.')
                .to_ascii_lowercase(),
            endpoints,
            pow_bits: num(c.get("powBits")).map(|x| x.clamp(0.0, 28.0) as u8).unwrap_or(d.pow_bits),
            reject_days: num(c.get("rejectDays")).map(|x| x.max(1.0) as u32).unwrap_or(d.reject_days),
            stale_days: num(c.get("staleDays")).map(|x| x.max(1.0) as u32).unwrap_or(d.stale_days),
            sync_interval_min: num(c.get("syncIntervalMin"))
                .map(|x| x.max(5.0) as u32)
                .unwrap_or(d.sync_interval_min),
            max_friends: num(c.get("maxFriends")).map(|x| x.max(0.0) as usize).unwrap_or(d.max_friends),
            min_hit_rate: num(c.get("minHitRate")).map(|x| x.clamp(0.0, 1.0)).unwrap_or(d.min_hit_rate),
            auto_delete_low_hit_rate: flag(c.get("autoDeleteLowHitRate"), d.auto_delete_low_hit_rate),
            share_domains: flag(c.get("shareDomains"), d.share_domains),
            share_upstreams: flag(c.get("shareUpstreams"), d.share_upstreams),
            rules: c.get("rules").and_then(Value::as_array).cloned().unwrap_or_default(),
            max_bundle_mb: num(c.get("maxBundleMB"))
                .map(|x| x.clamp(1.0, 32.0) as u32)
                .unwrap_or(d.max_bundle_mb),
        }
    }

    /// 一份好友資料解壓後最多多大：`maxBundleMB`（安全上限，最多 32 MB），
    /// 再不超過記憶體控制提供的上限（[`set_memory_cap_mb`]：系統保留量以上可用空間的 1/4）
    pub fn max_plain_bytes(&self) -> usize {
        self.max_plain_bytes_with(MEM_CAP_MB.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// 同 [`Config::max_plain_bytes`]，指定記憶體上限（MB；0 = 不限制）
    pub fn max_plain_bytes_with(&self, mem_cap_mb: u32) -> usize {
        let base = (self.max_bundle_mb as usize * 1024 * 1024).min(crate::envelope::MAX_RESPONSE_PLAIN);
        match mem_cap_mb {
            0 => base,
            mb => base.min(mb as usize * 1024 * 1024),
        }
    }
}

/// 記憶體控制提供的上限（MB；0 = 不限制）
static MEM_CAP_MB: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// 記憶體控制（主程式）每次量測後更新：收好友資料時解壓後不超過這麼多 MB（至少 1 MB；0 = 不限制）
pub fn set_memory_cap_mb(mb: u32) {
    MEM_CAP_MB.store(mb, std::sync::atomic::Ordering::Relaxed);
}

/// 時間與速率參數。正式環境用預設值；測試可以縮短等待時間或放寬速率（不影響任何驗證）
#[derive(Debug, Clone)]
pub struct Tuning {
    pub connect_timeout: Duration,
    pub total_timeout: Duration,
    /// 收到 poke 後隨機等多久再來拉（毫秒，範圍）
    pub poke_pull_ms: (u64, u64),
    /// 成為好友後多久拉第一次資料
    pub follow_up_ms: u64,
    /// 被對方刪除後多久自動重新請求
    pub rerequest_ms: u64,
    /// 好友來拉我的資料、而我超過 5 分鐘沒拉對方的：多久後順便拉一次
    pub mutual_sync_ms: u64,
    /// 同一個好友的資料 poke 最短間隔
    pub poke_interval_ms: u64,
    /// 多久從 DataProvider 重建一次分享集合
    pub share_refresh_ms: u64,
    /// 好友請求：每 IP 每小時 / 全域每小時
    pub requests_per_ip_hour: u32,
    pub requests_global_hour: u32,
    /// 所有社群請求：每 IP 每分鐘
    pub all_per_ip_minute: u32,
    /// 同一個網域每小時最多回連幾次
    pub callbacks_per_domain_hour: u32,
    /// 量連線品質的次數
    pub probes: u32,
}

impl Default for Tuning {
    fn default() -> Self {
        Tuning {
            connect_timeout: Duration::from_secs(10),
            total_timeout: Duration::from_secs(30),
            poke_pull_ms: (60_000, 300_000),
            follow_up_ms: 2_000,
            rerequest_ms: 5_000,
            mutual_sync_ms: 1_000,
            poke_interval_ms: 10 * 60_000,
            share_refresh_ms: 10 * 60_000,
            requests_per_ip_hour: 6,
            requests_global_hour: 60,
            all_per_ip_minute: 120,
            callbacks_per_domain_hour: 6,
            probes: 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn bundle_limit_follows_memory_cap() {
        let c = Config::from_json(&json!({ "maxBundleMB": 8 }));
        assert_eq!(c.max_plain_bytes_with(0), 8 << 20);
        // 記憶體控制：保留量以上只剩一點空間 → 好友資料上限跟著縮小；不限制時回到設定值
        assert_eq!(c.max_plain_bytes_with(2), 2 << 20);
        assert_eq!(c.max_plain_bytes_with(64), 8 << 20, "設定值仍是上限");
    }

    #[test]
    fn from_uci_shape() {
        let c = Config::from_json(&json!({
            "enabled": true, "domain": "DNS.Example.com.", "powBits": "18", "maxBundleMB": 4,
            "endpoints": { "doh": "https://dns.example.com/.well-known/kuroshio", "dot": "dot://dns.example.com:853", "doq": null },
            "rules": [{ "action": "accept" }], "shareDomains": "0"
        }));
        assert!(c.enabled);
        assert_eq!(c.domain, "dns.example.com");
        assert_eq!(c.pow_bits, 18);
        assert_eq!(
            c.endpoints,
            vec!["dot://dns.example.com:853", "https://dns.example.com/.well-known/kuroshio"]
        );
        assert_eq!(c.max_plain_bytes(), 4 * 1024 * 1024);
        assert!(!c.share_domains);
        assert_eq!(c.rules.len(), 1);
    }
}
