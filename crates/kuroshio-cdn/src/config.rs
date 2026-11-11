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
}

#[derive(Debug, Clone)]
pub struct CdnConfig {
    pub enabled: bool,
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
    /// ip-zone.json（每個節點能不能服務網站的紀錄）上限
    pub zone_max: usize,
    /// 永久 IPv6 節點每家上限
    pub v6_max: usize,
    /// 尖峰時段（台北時間，含起不含迄）與權重（規格 06 第 3.2 節）
    pub peak_start: u32,
    pub peak_end: u32,
    pub peak_weight: f64,
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
            trial_ttl: or(c, "trialTtl", 10.0) as u32,
            trial_original: c.get("trialMode").and_then(Value::as_str).unwrap_or("original") == "original",
            nearest_min_gain_ms: nn(c, "nearestMinGainMs", 8.0),
            nearest_score_slack: nn(c, "nearestScoreSlack", 40.0),
            verify_ok_hours: or(c, "verifyOkHours", 24.0),
            verify_fail_hours: or(c, "verifyFailHours", 6.0),
            verify_fail_max_days: or(c, "verifyFailMaxDays", 7.0),
            verify_timeout_ms: or(c, "verifyTimeoutMs", 5000.0) as u64,
            verify_concurrency: or(c, "verifyConcurrency", 8.0) as usize,
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
            zone_max: or(c, "zoneMax", 8000.0) as usize,
            v6_max: or(c, "v6NodesMax", 2000.0) as usize,
            peak_start: nn(c, "peak.startHour", 20.0) as u32,
            peak_end: nn(c, "peak.endHour", 23.0) as u32,
            peak_weight: nn(c, "peak.weight", 2.0),
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
    pub scan_timeout_ms: u64,
    pub candidates_per_provider: usize,
    pub pool_size: usize,
    pub speed_top: usize,
    pub speed_seconds: u64,
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
            scan_timeout_ms: or(cfg, "scan.timeoutMs", 2000.0) as u64,
            candidates_per_provider: or(cfg, "pool.candidatesPerProvider", 1500.0) as usize,
            pool_size: or(cfg, "pool.poolSize", 12.0) as usize,
            speed_top: or(cfg, "pool.speedTop", 16.0) as usize,
            speed_seconds: or(cfg, "pool.speedSeconds", 5.0) as u64,
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
        let one = build_for(&Host { cores: 1 }, &json!({}));
        let c = CdnConfig::from_value(&one);
        assert_eq!((c.verify_concurrency, c.max_entries, c.zone_max, c.v6_max), (2, 200000, 8000, 2000));
        let j = JobsConfig::from_value(&one);
        assert_eq!(
            (j.scan_concurrency, j.scan_samples, j.candidates_per_provider, j.latency_concurrency),
            (50, 6, 1500, 32)
        );
        assert_eq!(kuroshio_config::get(&one, "jobs.cdn-scan.enabled"), Some(&json!(true)));
        let large = CdnConfig::from_value(&build_for(&Host { cores: 8 }, &json!({})));
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
}
