//! CDN 設定（`cdn.*`，預設值在 `kuroshio-config/defaults.json`，並行數依 CPU 核心數換算）

use crate::providers::{self, PROVIDERS};
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct ProviderCfg {
    pub name: &'static str,
    pub enabled: bool,
    /// 設定裡的 `ecs`（None = 沒寫）
    pub ecs: Option<bool>,
    pub serve_count: Option<usize>,
    pub v6_policy: Option<String>,
    pub seed_v4: Vec<String>,
    pub seed_v6: Vec<String>,
    pub max_latency_ms: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct EcsCfg {
    pub resolvers: Vec<String>,
    pub tw_subnets: Vec<String>,
    pub min_gain_ms: f64,
    pub min_gain_ratio: f64,
    pub result_hours: f64,
    pub concurrency: usize,
}

#[derive(Debug, Clone)]
pub struct CrossCfg {
    pub enabled: bool,
    pub min_orig_ms: f64,
    pub recheck_hours: f64,
    pub fail_days: f64,
    pub akamai_max_ms: f64,
    pub concurrency: usize,
    /// 跨 CDN 加實測分數（3.5.0 B4，`cdn.cross.requestScore`，預設開）：原本的條件都過了之後，
    /// 還要「握手（連線＋TLS 握手，3.5.0 F13 起不含 TTFB）比原站快 5% 以上」才採用。關掉＝3.4.x（只看 TCP 延遲）
    pub request_score: bool,
}

/// `cdn.lite` 的值：true／false，或 UCI 的 "1"／"0"（"true"／"false"、"on"／"off"）；其他（"auto"、沒寫）是 None
pub fn lite_value(v: Option<&Value>) -> Option<bool> {
    match v? {
        Value::Bool(b) => Some(*b),
        Value::Number(n) => Some(n.as_f64() != Some(0.0)),
        Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "on" | "yes" => Some(true),
            "0" | "false" | "off" | "no" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// 小機器減量：驗證每分鐘最多幾個（3.4.2；padavan-tw 的 D3 單獨運作每秒 10 筆新網域時約每分鐘 150 個）
pub const LITE_VERIFY_PER_MIN: u32 = 30;
/// 小機器減量：節點池下載測速最多幾個節點（一般是 `pool.speedTop` 16）
pub const LITE_SPEED_TOP: usize = 4;
/// `cdn.verifyPerMin` 填數字時的範圍（3.5.0 F12）
pub const VERIFY_PER_MIN_MIN: u32 = 6;
pub const VERIFY_PER_MIN_MAX: u32 = 1200;

#[derive(Debug, Clone)]
pub struct CdnConfig {
    pub enabled: bool,
    /// 小機器減量（3.4.2）：`cdn.lite` 是 true 時（`auto` 由主程式依實體記憶體換算），只驗證問過 2 次以上的網域、
    /// 驗證每分鐘最多 [`LITE_VERIFY_PER_MIN`] 個、節點池測速最多 [`LITE_SPEED_TOP`] 個節點。不是關掉
    pub lite: bool,
    pub trial_ttl: u32,
    /// `trialMode`：`original`（預設，未驗證先回原始）或其他（先換台灣 IP）
    pub trial_original: bool,
    pub nearest_min_gain_ms: f64,
    pub nearest_score_slack: f64,
    pub verify_ok_hours: f64,
    pub verify_fail_hours: f64,
    pub verify_fail_max_days: f64,
    pub verify_timeout_ms: u64,
    pub verify_concurrency: usize,
    /// 新網域很多時的 CDN 驗證節流（3.5.0 F12，`cdn.verifyPacing`，預設開）。關掉＝只有 `cdn.lite` 有每分鐘上限。
    /// 規格 11 第 6.2 節骨架，甲批接上
    pub verify_pacing: bool,
    /// 驗證每分鐘上限 `Rmax`（3.5.0 F12，`cdn.verifyPerMin`）：`"auto"` 由設定載入時依核心數與 AES 換算
    /// （`kuroshio_config::auto_verify_per_min`），填數字的夾在 6～1,200；沒換算過（只有 `cdn` 區塊的測試設定）用 60。
    /// `cdn.lite` 的 30 由使用的地方套用。規格 11 第 6.2 節骨架，甲批接上
    pub verify_per_min: u32,
    pub verify_candidates: usize,
    /// 每小時輪流複驗：還在有效期內、最近有改寫的「驗證通過」網域抽多少比例（0 = 不做）
    pub reverify_ratio: f64,
    /// 每小時輪流複驗的下限 / 上限（個）
    pub reverify_min: usize,
    pub reverify_max: usize,
    pub octet_search: usize,
    pub serve_count: usize,
    pub min_pool: usize,
    pub quality_samples: u32,
    pub v6_policy: String,
    pub max_entries: usize,
    /// 網域資料在磁碟上的預算（bytes；3.5.0 C5，規格 05 第 5.7 節）。`None` = 不限（只受 `max_entries`）。
    /// `cdn.dbDiskBudgetKB` 是數字時直接用（0 = 關，下限 512 KB）；`"auto"` 由主程式依狀態目錄所在的檔案系統大小
    /// 換算成數字再傳進來（這裡看到 `"auto"` 當成不限）
    pub db_disk_budget: Option<u64>,
    /// ip-zone.json（每個節點能不能服務網站的紀錄）上限
    pub zone_max: usize,
    /// 永久 IPv6 節點每家上限
    pub v6_max: usize,
    /// 尖峰時段（台北時間，含起不含迄）與權重（規格 06 第 3.2 節）
    pub peak_start: u32,
    pub peak_end: u32,
    pub peak_weight: f64,
    /// 尊重多來源 CDN、第一層 CNAME 變了就失效（3.5.0 B3，`cdn.multiCdn`，預設開）。關掉＝3.4.x 的行為
    pub multi_cdn: bool,
    /// App 自己選節點的服務只辨識、不改寫（3.5.0 B3，`cdn.appLayer`，預設開）
    pub app_layer: bool,
    /// 機房以本機量到的為準（3.5.0 E4，`cdn.popAudit`，預設開）：記下上游宣稱的機房、串接中搭既有抽查量機房。
    /// 關掉＝不記、不抽查（3.4.x 的行為）。第 5.2 節骨架，甲／乙批接上
    pub pop_audit: bool,
    /// 機房層級的健康與切換（3.5.0 E5，`cdn.popSwitch`，預設開）。關掉＝只彙總、不切換。第 5.2 節骨架，甲批接上
    pub pop_switch: bool,
    /// 同機房內的網段分散（3.5.0 E6，`cdn.spreadPrefixes`，預設開）。關掉＝健檢照延遲排序。第 5.2 節骨架，甲批接上
    pub spread_prefixes: bool,
    /// 台灣節點實測明顯比原本慢就暫時用原本的答案（3.5.0 E7，`cdn.slowerFallback`，預設開）。
    /// 關掉＝驗證通過就換（3.4.x 的行為）。第 5.2 節骨架，甲批接上
    pub slower_fallback: bool,
    pub providers: Vec<ProviderCfg>,
    pub ecs: EcsCfg,
    pub cross: CrossCfg,
}

fn num(v: &Value, k: &str) -> Option<f64> {
    kuroshio_config::get(v, k).and_then(Value::as_f64)
}

/// JS 的 `x || d`：沒有或 0 都用預設
fn or(v: &Value, k: &str, d: f64) -> f64 {
    num(v, k).filter(|x| *x != 0.0).unwrap_or(d)
}

/// JS 的 `x ?? d`
fn nn(v: &Value, k: &str, d: f64) -> f64 {
    num(v, k).unwrap_or(d)
}

fn strs(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

impl CdnConfig {
    /// 由完整設定（含 `cdn` 區塊）或只有 `cdn` 區塊的物件建立
    pub fn from_value(cfg: &Value) -> CdnConfig {
        let c = cfg.get("cdn").unwrap_or(cfg);
        let pv = c.get("providers");
        let providers = PROVIDERS
            .iter()
            .filter_map(|p| {
                let pc = pv.and_then(|x| x.get(p.name))?;
                Some(ProviderCfg {
                    name: p.name,
                    enabled: pc.get("enabled").and_then(Value::as_bool) != Some(false),
                    ecs: pc.get("ecs").and_then(Value::as_bool),
                    serve_count: pc.get("serveCount").and_then(Value::as_u64).filter(|n| *n > 0).map(|n| n as usize),
                    v6_policy: pc
                        .get("v6Policy")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                        .map(String::from),
                    seed_v4: strs(pc.get("seedV4")),
                    seed_v6: strs(pc.get("seedV6")),
                    max_latency_ms: pc.get("maxLatencyMs").and_then(Value::as_f64).filter(|x| *x > 0.0),
                })
            })
            .collect();
        let resolvers = strs(kuroshio_config::get(c, "ecs.resolvers"));
        CdnConfig {
            enabled: c.get("enabled").and_then(Value::as_bool) != Some(false),
            lite: lite_value(c.get("lite")) == Some(true),
            trial_ttl: or(c, "trialTtl", 10.0) as u32,
            trial_original: c.get("trialMode").and_then(Value::as_str).unwrap_or("original") == "original",
            nearest_min_gain_ms: nn(c, "nearestMinGainMs", 8.0),
            nearest_score_slack: nn(c, "nearestScoreSlack", 40.0),
            verify_ok_hours: or(c, "verifyOkHours", 24.0),
            verify_fail_hours: or(c, "verifyFailHours", 6.0),
            verify_fail_max_days: or(c, "verifyFailMaxDays", 7.0),
            verify_timeout_ms: or(c, "verifyTimeoutMs", 5000.0) as u64,
            verify_concurrency: or(c, "verifyConcurrency", 8.0) as usize,
            verify_pacing: lite_value(c.get("verifyPacing")) != Some(false),
            verify_per_min: kuroshio_config::num_or_auto(c.get("verifyPerMin"))
                .map(|n| n.min(u32::MAX as u64) as u32)
                .unwrap_or(60)
                .clamp(VERIFY_PER_MIN_MIN, VERIFY_PER_MIN_MAX),
            verify_candidates: or(c, "verifyCandidates", 4.0) as usize,
            reverify_ratio: nn(c, "reverifyRatio", 0.02).clamp(0.0, 1.0),
            reverify_min: nn(c, "reverifyMin", 5.0).max(0.0) as usize,
            reverify_max: nn(c, "reverifyMax", 50.0).max(0.0) as usize,
            octet_search: or(c, "octetSearch", 10.0) as usize,
            serve_count: or(c, "serveCount", 4.0) as usize,
            min_pool: or(c, "minPool", 3.0) as usize,
            quality_samples: or(c, "qualitySamples", 6.0) as u32,
            v6_policy: c
                .get("v6Policy")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .unwrap_or("drop")
                .to_string(),
            max_entries: or(c, "maxEntries", 200000.0) as usize,
            db_disk_budget: kuroshio_config::num_or_auto(c.get("dbDiskBudgetKB"))
                .filter(|kb| *kb > 0)
                .map(|kb| kb.saturating_mul(1024).max(crate::db::BUDGET_MIN_BYTES)),
            zone_max: or(c, "zoneMax", 8000.0) as usize,
            v6_max: or(c, "v6NodesMax", 2000.0) as usize,
            peak_start: nn(c, "peak.startHour", 20.0) as u32,
            peak_end: nn(c, "peak.endHour", 23.0) as u32,
            peak_weight: nn(c, "peak.weight", 2.0),
            multi_cdn: lite_value(c.get("multiCdn")) != Some(false),
            app_layer: lite_value(c.get("appLayer")) != Some(false),
            pop_audit: lite_value(c.get("popAudit")) != Some(false),
            pop_switch: lite_value(c.get("popSwitch")) != Some(false),
            spread_prefixes: lite_value(c.get("spreadPrefixes")) != Some(false),
            slower_fallback: lite_value(c.get("slowerFallback")) != Some(false),
            providers,
            ecs: EcsCfg {
                resolvers: if resolvers.is_empty() {
                    vec!["udp://8.8.8.8".into(), "udp://8.8.4.4".into()]
                } else {
                    resolvers
                },
                tw_subnets: strs(kuroshio_config::get(c, "ecs.twSubnets")),
                min_gain_ms: nn(c, "ecs.minGainMs", 8.0),
                min_gain_ratio: nn(c, "ecs.minGainRatio", 0.3),
                result_hours: or(c, "ecs.resultHours", 6.0),
                concurrency: or(c, "ecs.concurrency", 4.0) as usize,
            },
            cross: CrossCfg {
                enabled: kuroshio_config::get(c, "cross.enabled").and_then(Value::as_bool) != Some(false),
                min_orig_ms: nn(c, "cross.minOrigMs", 20.0),
                recheck_hours: or(c, "cross.recheckHours", 24.0),
                fail_days: or(c, "cross.failDays", 3.0),
                akamai_max_ms: or(c, "cross.akamaiMaxMs", 15.0),
                concurrency: or(c, "cross.concurrency", 2.0) as usize,
                request_score: lite_value(kuroshio_config::get(c, "cross.requestScore")) != Some(false),
            },
        }
    }

    pub fn provider(&self, name: &str) -> Option<&ProviderCfg> {
        self.providers.iter().find(|p| p.name == name)
    }

    /// 啟用中的 IP 置換型 CDN（順序同廠商表）
    pub fn enabled_alias(&self) -> Vec<&'static str> {
        self.providers
            .iter()
            .filter(|p| p.enabled && providers::get(p.name).map(|x| x.alias).unwrap_or(false))
            .map(|p| p.name)
            .collect()
    }

    /// 走 ECS 突破的 CDN：設定 `ecs: true`，或廠商預設 ECS 且設定沒關掉
    pub fn ecs_providers(&self) -> Vec<&'static str> {
        self.providers.iter().filter(|p| Self::ecs_on(p)).map(|p| p.name).collect()
    }

    /// 這家走不走 ECS 突破（查詢路徑用，不配置記憶體）
    pub fn is_ecs(&self, name: &str) -> bool {
        self.providers.iter().any(|p| p.name == name && Self::ecs_on(p))
    }

    fn ecs_on(p: &ProviderCfg) -> bool {
        p.enabled && (p.ecs == Some(true) || (providers::get(p.name).map(|x| x.ecs).unwrap_or(false) && p.ecs != Some(false)))
    }

    pub fn serve_count_of(&self, provider: &str) -> usize {
        self.provider(provider)
            .and_then(|p| p.serve_count)
            .unwrap_or(self.serve_count)
            .max(1)
    }

    pub fn v6_policy_of(&self, provider: &str) -> &str {
        self.provider(provider)
            .and_then(|p| p.v6_policy.as_deref())
            .unwrap_or(&self.v6_policy)
    }

    /// 現在是不是尖峰時段（台北時間）
    pub fn is_peak(&self, now_ms: u64) -> bool {
        let h = crate::util::taipei_hour(now_ms);
        if self.peak_start <= self.peak_end {
            h >= self.peak_start && h < self.peak_end
        } else {
            h >= self.peak_start || h < self.peak_end
        }
    }
}

/// 背景工作用的設定（`scan.*`、`pool.*`）
#[derive(Debug, Clone)]
pub struct JobsConfig {
    pub scan_samples: usize,
    pub scan_concurrency: usize,
    /// 網段掃描每秒最多開始幾個探測（`scan.maxPerSec`，1～1000；3.5.0）
    pub scan_max_per_sec: u32,
    pub scan_timeout_ms: u64,
    pub candidates_per_provider: usize,
    pub pool_size: usize,
    pub speed_top: usize,
    /// 每個節點收內容最多幾秒（`pool.speedSeconds`）；也要收到 8 MiB 或前 1 MiB 才停（`probe::download_sample`）。
    /// 3.5.1 預設 5 → 2：MT7621 上 HTTPS 解密只跟得上約 2 MB/s，5 秒的上限等於每個節點都收滿 8 MiB（約 4 秒）；
    /// 快的線路 8 MiB 本來就在 2 秒內收完，不受影響
    pub speed_seconds: u64,
    /// 測速的相對評分（3.5.0 B1，`pool.relativeSpeed`，預設開）：慢不慢跟同一家其他節點比、誤差範圍依傳輸時間、
    /// 排序先分級。關掉＝3.4.x（絕對的 1 MB/s、5% 門檻、直接比速度）
    pub relative_speed: bool,
    pub nearest_probe_top: usize,
    pub nearest_pops: usize,
    pub nearest_keep_pops: usize,
    /// 階段 A（延遲粗篩）的同時數
    pub latency_concurrency: usize,
    /// POP 判定的同時數
    pub probe_concurrency: usize,
}

impl JobsConfig {
    pub fn from_value(cfg: &Value) -> JobsConfig {
        let lat = or(cfg, "pool.latencyConcurrency", 200.0) as usize;
        JobsConfig {
            scan_samples: or(cfg, "scan.samplesPerSubnet", 6.0) as usize,
            scan_concurrency: or(cfg, "scan.concurrency", 400.0) as usize,
            scan_max_per_sec: (or(cfg, "scan.maxPerSec", 100.0) as u32).clamp(1, 1000),
            scan_timeout_ms: or(cfg, "scan.timeoutMs", 2000.0) as u64,
            candidates_per_provider: or(cfg, "pool.candidatesPerProvider", 1500.0) as usize,
            pool_size: or(cfg, "pool.poolSize", 12.0) as usize,
            speed_top: or(cfg, "pool.speedTop", 16.0) as usize,
            speed_seconds: or(cfg, "pool.speedSeconds", 2.0) as u64,
            relative_speed: lite_value(kuroshio_config::get(cfg, "pool.relativeSpeed")) != Some(false),
            nearest_probe_top: or(cfg, "pool.nearestProbeTop", 1500.0) as usize,
            nearest_pops: or(cfg, "pool.nearestPops", 6.0) as usize,
            nearest_keep_pops: or(cfg, "pool.nearestKeepPops", 5.0) as usize,
            latency_concurrency: lat,
            probe_concurrency: or(cfg, "pool.probeConcurrency", 32.0) as usize,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuroshio_config::{build_for, Host};
    use serde_json::json;

    #[test]
    fn derived_values() {
        // 規格 05 第 7 節：同時數依 CPU 核心數換算；筆數上限是安全上限，不分機器（實際用多少記憶體由記憶體控制決定）
        let one = build_for(&Host { cores: 1, aes: true }, &json!({}));
        let c = CdnConfig::from_value(&one);
        assert_eq!((c.verify_concurrency, c.max_entries, c.zone_max, c.v6_max), (2, 200000, 8000, 2000));
        let j = JobsConfig::from_value(&one);
        assert_eq!(
            (j.scan_concurrency, j.scan_samples, j.candidates_per_provider, j.latency_concurrency),
            (50, 6, 1500, 32)
        );
        assert_eq!(kuroshio_config::get(&one, "jobs.cdn-scan.enabled"), Some(&json!(true)));
        // 3.5.0 B8：每秒最多幾個探測依核心數（每核心 50、50～200）；每台往後錯開 0～30 分鐘
        assert_eq!(j.scan_max_per_sec, 50);
        assert_eq!(
            JobsConfig::from_value(&build_for(&Host { cores: 2, aes: false }, &json!({}))).scan_max_per_sec,
            100
        );
        assert_eq!(
            JobsConfig::from_value(&build_for(&Host { cores: 8, aes: true }, &json!({}))).scan_max_per_sec,
            200
        );
        assert_eq!(kuroshio_config::get(&one, "jobs.cdn-scan.jitterMin"), Some(&json!(30)));
        let user = build_for(&Host { cores: 8, aes: true }, &json!({ "scan": { "maxPerSec": 5000 } }));
        assert_eq!(JobsConfig::from_value(&user).scan_max_per_sec, 1000, "使用者的值最多 1000");
        let large = CdnConfig::from_value(&build_for(&Host { cores: 8, aes: true }, &json!({})));
        assert_eq!((large.verify_concurrency, large.max_entries), (8, 200000));
        assert_eq!(large.enabled_alias(), ["cloudflare", "cloudfront", "fastly", "gcore", "azure"]);
        assert!(large.ecs_providers().contains(&"akamai"));
        assert_eq!((large.peak_start, large.peak_end, large.peak_weight), (20, 23, 2.0));
        // 使用者關掉某家 CDN、指定每家的回應 IP 數與 v6 策略
        let u = CdnConfig::from_value(&json!({ "cdn": { "v6Policy": "keep", "providers": {
            "cloudflare": { "enabled": false }, "fastly": { "serveCount": 2, "v6Policy": "drop" }, "akamai": { "ecs": false }
        } } }));
        assert_eq!(u.enabled_alias(), ["fastly"]);
        assert!(u.ecs_providers().is_empty());
        assert_eq!(
            (u.serve_count_of("fastly"), u.v6_policy_of("fastly"), u.v6_policy_of("x")),
            (2, "drop", "keep")
        );
    }

    /// 3.5.0 E4～E7 的開關：預設（與沒寫）都開；false、UCI 的 "0" 都是關
    #[test]
    fn line_awareness_switches() {
        let on = |c: &CdnConfig| (c.pop_audit, c.pop_switch, c.spread_prefixes, c.slower_fallback);
        let d = CdnConfig::from_value(&build_for(&Host { cores: 2, aes: false }, &json!({})));
        assert_eq!(on(&d), (true, true, true, true));
        assert_eq!(on(&CdnConfig::from_value(&json!({ "cdn": {} }))), (true, true, true, true));
        let off = CdnConfig::from_value(&json!({ "cdn": {
            "popAudit": false, "popSwitch": "0", "spreadPrefixes": 0, "slowerFallback": "false"
        } }));
        assert_eq!(on(&off), (false, false, false, false));
    }

    /// 3.5.0 F12 的開關與每分鐘上限：預設開、auto 依核心數與 AES；填的數字夾在 6～1,200
    #[test]
    fn verify_pacing_settings() {
        let d3 = CdnConfig::from_value(&build_for(&Host { cores: 2, aes: false }, &json!({})));
        assert!(d3.verify_pacing);
        assert_eq!(d3.verify_per_min, 60, "MT7621：雙核心、沒有 AES");
        let big = CdnConfig::from_value(&build_for(&Host { cores: 16, aes: true }, &json!({})));
        assert_eq!(big.verify_per_min, 480);
        let pm = |v: Value| CdnConfig::from_value(&json!({ "cdn": { "verifyPerMin": v } })).verify_per_min;
        assert_eq!(pm(json!(100)), 100);
        assert_eq!(pm(json!("90")), 90, "UCI 給的字串");
        assert_eq!(pm(json!(1)), 6);
        assert_eq!(pm(json!(99999)), 1200);
        assert_eq!(pm(json!("auto")), 60, "沒換算過的 auto");
        let off = CdnConfig::from_value(&json!({ "cdn": { "verifyPacing": "0" } }));
        assert!(!off.verify_pacing);
        assert!(CdnConfig::from_value(&json!({ "cdn": {} })).verify_pacing);
    }
}
