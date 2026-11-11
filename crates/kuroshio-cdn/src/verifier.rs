//! 驗證某網域換到台灣節點後是否真的能運作（對齊 2.x `lib/cdn/verifier.js`）：
//! 方案不同、POP 沒開該服務時會失敗（Cloudflare 1xxx、HTTP 421、CloudFront Distribution 錯誤…）。

use crate::cdn::Cdn;
use crate::db::Base;
use crate::providers::{self, detect_from_headers, hv};
use crate::util::{self, intern, now_ms, Num, HOUR_MS};
use kuroshio_net::probe::{HttpsOpts, ProbeResult};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

fn lower(s: &str) -> String {
    s.to_ascii_lowercase()
}

/// `10\d\d` 從 `i` 開始
fn code10(b: &[u8], i: usize) -> Option<&[u8]> {
    let c = b.get(i..i + 4)?;
    (c[0] == b'1' && c[1] == b'0' && c[2].is_ascii_digit() && c[3].is_ascii_digit()).then_some(c)
}

/// `error code:?\s*` 之後的位置
fn after_error_code(b: &[u8], i: usize) -> Option<usize> {
    if !b[i..].starts_with(b"error code") {
        return None;
    }
    let mut j = i + 10;
    if b.get(j) == Some(&b':') {
        j += 1;
    }
    while j < b.len() && (b[j] as char).is_ascii_whitespace() {
        j += 1;
    }
    Some(j)
}

/// Cloudflare 1xxx 錯誤頁：1001 DNS 錯誤、1003 直接 IP、1014 跨帳號 CNAME、1016 來源 DNS、1034 Edge IP 限制…
/// 回傳（是錯誤頁，錯誤代碼）
fn cf_error(body: &str) -> (bool, Option<String>) {
    let low = lower(body);
    let b = low.as_bytes();
    let mut hit = low.contains("cf-error-code") || low.contains("edge ip restricted");
    let mut code = None;
    for i in 0..b.len() {
        if b[i] != b'e' {
            continue;
        }
        // (?:error code:?\s*|Error )(10\d\d)：同一個位置先試第一種寫法
        if let Some(j) = after_error_code(b, i) {
            if let Some(c) = code10(b, j) {
                code.get_or_insert_with(|| String::from_utf8_lossy(c).into_owned());
                hit = true;
                break;
            }
        }
        if b[i..].starts_with(b"error ") {
            if let Some(c) = code10(b, i + 6) {
                code.get_or_insert_with(|| String::from_utf8_lossy(c).into_owned());
                hit = true;
                break;
            }
        }
    }
    (hit, code)
}

/// 回應看起來是「這個節點不服務這個網站」或壞掉了：回傳原因
pub fn looks_broken(provider: &str, status: u16, headers: &providers::Headers, body: &str) -> Option<String> {
    if status == 421 {
        return Some("HTTP 421 Misdirected（該節點不服務此網域）".into());
    }
    if provider == "cloudflare" {
        if (520..=530).contains(&status) {
            return Some(format!("Cloudflare {status}"));
        }
        let (hit, code) = cf_error(body);
        if hit {
            return Some(format!("Cloudflare 錯誤 {}", code.as_deref().unwrap_or("1xxx")));
        }
    }
    if provider == "cloudfront" && lower(hv(headers, "x-cache")).contains("error from cloudfront") && status >= 400 {
        let b = lower(body);
        if b.contains("could not be satisfied") || b.contains("bad request") || b.contains("configured to allow") {
            return Some(format!("CloudFront {status}（此 POP 不服務該 Distribution）"));
        }
        return Some(format!("CloudFront {status}"));
    }
    if status >= 500 {
        return Some(format!("HTTP {status}"));
    }
    None
}

pub fn looks_broken_r(provider: &str, r: &ProbeResult) -> Option<String> {
    looks_broken(provider, r.status, &r.headers, &r.body)
}

/// 「這個 IP 不服務這個網站」類的錯誤（記到相容性紀錄、換下一個再試）
fn zone_kind(broken: &str) -> bool {
    broken.contains("錯誤 1") || broken.contains("421") || broken.contains("Distribution")
}

struct ZoneFail {
    reason: String,
    pop: Option<String>,
    status: Option<u16>,
    ip: IpAddr,
}

/// 成功時寫入的資料
struct Done {
    /// None = 不更新（TLS 失敗時沒有 POP）
    pop: Option<String>,
    ms: Option<f64>,
    status: Option<u16>,
    ip: IpAddr,
    ips: Option<Vec<IpAddr>>,
    tried: Option<u32>,
    http: Option<bool>,
    reason: Option<String>,
    retry_at: Option<u64>,
}

impl Cdn {
    fn until(&self, ok: bool, fails: u32) -> u64 {
        let now = now_ms();
        let c = &self.cfg;
        if ok {
            return now + (c.verify_ok_hours * HOUR_MS as f64) as u64;
        }
        let base = c.verify_fail_hours * HOUR_MS as f64;
        let backoff = base * 2f64.powi(fails.saturating_sub(1).min(30) as i32);
        now + backoff.min(c.verify_fail_max_days * 24.0 * HOUR_MS as f64) as u64
    }

    async fn probe_site(&self, ip: IpAddr, name: &str, http_mode: bool) -> ProbeResult {
        let t = Duration::from_millis(self.cfg.verify_timeout_ms);
        if http_mode {
            self.net.http_probe(ip, name, "/", t).await
        } else {
            self.net
                .https_probe(
                    ip,
                    name,
                    "/",
                    HttpsOpts {
                        timeout: t,
                        ..Default::default()
                    },
                )
                .await
        }
    }

    /// 驗證（同 2.x `Verifier.verify`）：回傳 ok / fail / unknown，沒有候選 IP 回 None
    pub async fn verify(self: &Arc<Self>, name: &str, provider: &str, family: u8, orig: Option<IpAddr>) -> Option<&'static str> {
        let mut hinted: Vec<(IpAddr, String)> = Vec::new();
        let r = self.verify_inner(name, provider, family, orig, &mut hinted).await;
        // 社群提示的命中率：好友給的 IP 在我這邊驗證成功 / 失敗
        if !hinted.is_empty() {
            if let Some(h) = self.hints() {
                let ok_ips: Vec<IpAddr> = {
                    let st = self.state();
                    match st.db.get(name).and_then(|e| e.verdict(family)).filter(|v| v.is("ok")) {
                        Some(v) => v.ips.clone().unwrap_or_else(|| v.ip.into_iter().collect()),
                        None => vec![],
                    }
                };
                for (ip, from) in &hinted {
                    h.hint_result(from, ok_ips.contains(ip));
                }
            }
        }
        r
    }

    async fn verify_inner(
        self: &Arc<Self>,
        name: &str,
        provider: &str,
        family: u8,
        orig: Option<IpAddr>,
        hinted_out: &mut Vec<(IpAddr, String)>,
    ) -> Option<&'static str> {
        let prov = providers::get(provider);
        let label = providers::label(provider);
        let prev_fails = {
            let st = self.state();
            st.db.get(name).and_then(|e| e.verdict(family)).and_then(|v| v.fails).unwrap_or(0)
        };
        let t = Duration::from_millis(self.cfg.verify_timeout_ms);

        // 1. 基準：用原始 IP 連一次，記錄原本被分配到哪個 POP（給分析用）
        // 有些網站只開 HTTP（OCSP / CRL、軟體更新鏡像…），原始節點的 HTTPS 就失敗時改用 HTTP 驗證
        let mut base: Option<ProbeResult> = None;
        let mut http_mode = false;
        if let Some(o) = orig.filter(|o| family == 4 || o.is_ipv6()) {
            let mut b = self.probe_site(o, name, false).await;
            if !b.ok && b.error.as_deref() != Some("TIMEOUT") {
                let b2 = self.net.http_probe(o, name, "/", t).await;
                if b2.ok {
                    b = b2;
                    http_mode = true;
                }
            }
            let det_pop = if b.ok {
                detect_from_headers(&b.headers, &b.body).pop
            } else {
                String::new()
            };
            let pop = match prov.filter(|p| b.ok && p.has_pop()) {
                Some(p) => {
                    let x = p.pop(&b.headers, &b.body);
                    if x.is_empty() {
                        det_pop
                    } else {
                        x
                    }
                }
                None => det_pop,
            };
            self.with_state(|st| {
                st.db.set_base(
                    name,
                    Base {
                        ip: Some(o),
                        ok: Some(b.ok),
                        status: if b.status > 0 { Num::V(b.status as f64) } else { Num::Null },
                        pop: Some(intern(&pop)),
                        ms: if b.ok { Num::V(util::round(b.ms, 1)) } else { Num::Null },
                        error: b.error.clone(),
                        ..Default::default()
                    },
                )
            });
            base = Some(b);
        }
        let base_ok = base.as_ref().filter(|b| b.ok);

        // 2. 依序用台灣池內 IP 測試
        // 保留最後一段的 CDN（Fastly）：候選 = 最佳幾個 POP 的網段 + 原始 IP 最後一段
        let octet = family == 4 && self.state().pools.octet_mode(provider);
        let mut candidates: Vec<IpAddr> = {
            let st = self.state();
            if octet {
                let mut observed: Vec<IpAddr> = st.db.get(name).map(|e| e.ips4.to_vec()).unwrap_or_default();
                if let Some(b) = st.db.get(name).and_then(|e| e.base.as_ref()).and_then(|b| b.ip) {
                    observed.push(b);
                }
                st.pools.verify_candidates(provider, orig, &observed)
            } else {
                let mut v = st.pools.serve_ips(provider, family);
                v.truncate(self.cfg.verify_candidates);
                v
            }
        };
        // 社群好友驗證過這個網站可用的 IP：排在最前面先試
        if let Some(h) = self.hints() {
            let mut seen: HashMap<IpAddr, String> = HashMap::new();
            for x in h.domain_hint(name, provider, family) {
                if let std::collections::hash_map::Entry::Vacant(e) = seen.entry(x.ip) {
                    e.insert(x.from.clone());
                    hinted_out.push((x.ip, x.from));
                }
            }
            if !hinted_out.is_empty() {
                let mut c: Vec<IpAddr> = hinted_out.iter().map(|x| x.0).collect();
                c.extend(candidates.iter().copied().filter(|ip| !seen.contains_key(ip)));
                candidates = c;
            }
        }
        if candidates.is_empty() {
            return None;
        }
        let mut last_reason = "無可用台灣節點".to_string();
        let mut zone_fail: Option<ZoneFail> = None;
        for (idx, &ip) in candidates.iter().enumerate() {
            let r = self.probe_site(ip, name, http_mode).await;
            if !r.ok {
                let err = r.error.clone().unwrap_or_default();
                if r.tls_error {
                    self.with_state(|st| st.pools.zone_note(provider, ip, false));
                    zone_fail.get_or_insert(ZoneFail {
                        reason: format!("TLS 失敗 ({err})"),
                        pop: None,
                        status: None,
                        ip,
                    });
                    continue;
                }
                last_reason = format!("連線失敗 {err}");
                if base_ok.is_some() {
                    self.with_state(|st| st.pools.mark_bad(provider, ip, &format!("驗證 {name} 時 {err}")));
                }
                continue;
            }
            let pop = prov.filter(|p| p.has_pop()).map(|p| p.pop(&r.headers, &r.body)).unwrap_or_default();
            if let Some(p) = prov {
                if p.is_provider(&r.headers) == Some(false) {
                    // 回應裡沒有這家 CDN 的特徵：憑證已驗證是該網域的，只要狀態碼跟原始節點同一類就算可用
                    let same = base_ok.map(|b| b.status / 100 == r.status / 100 && r.status < 500).unwrap_or(false);
                    if !same {
                        last_reason = format!("回應不像 {label}（HTTP {}）", r.status);
                        continue;
                    }
                }
            }
            if !pop.is_empty() && !self.state().pools.accept_pop(provider, &pop) {
                // 節點漂移：這個 IP 已經不是台灣 POP
                self.with_state(|st| st.pools.mark_bad(provider, ip, &format!("POP 變成 {pop}")));
                last_reason = format!("節點漂移 {pop}");
                continue;
            }
            if let Some(broken) = looks_broken_r(provider, &r) {
                let base_broken = base_ok.and_then(|b| looks_broken_r(provider, b));
                if let (Some(b), Some(_)) = (base_ok, base_broken) {
                    if b.status == r.status {
                        // 原始節點也是同樣錯誤 → 網站本身的問題，不算置換失敗
                        return Some(self.done(
                            name,
                            family,
                            true,
                            0,
                            Done {
                                pop: Some(pop),
                                ms: Some(r.ms),
                                status: Some(r.status),
                                ip,
                                ips: None,
                                tried: None,
                                http: None,
                                reason: Some("原站同樣錯誤".into()),
                                retry_at: None,
                            },
                            false,
                        ));
                    }
                }
                if zone_kind(&broken) {
                    self.with_state(|st| st.pools.zone_note(provider, ip, false));
                    zone_fail.get_or_insert(ZoneFail {
                        reason: broken,
                        pop: Some(pop),
                        status: Some(r.status),
                        ip,
                    });
                    continue;
                }
                return Some(self.done(
                    name,
                    family,
                    false,
                    prev_fails,
                    Done {
                        pop: Some(pop),
                        ms: None,
                        status: Some(r.status),
                        ip,
                        ips: None,
                        tried: None,
                        http: None,
                        reason: Some(broken),
                        retry_at: None,
                    },
                    false,
                ));
            }
            if let Some(b) = base_ok {
                if b.status < 400 && r.status >= 400 && r.status != b.status && r.status != 404 {
                    return Some(self.done(
                        name,
                        family,
                        false,
                        prev_fails,
                        Done {
                            pop: Some(pop),
                            ms: None,
                            status: Some(r.status),
                            ip,
                            ips: None,
                            tried: None,
                            http: None,
                            reason: Some(format!("狀態不同 原始 {} / 台灣 {}", b.status, r.status)),
                            retry_at: None,
                        },
                        false,
                    ));
                }
            }
            self.with_state(|st| st.pools.zone_note(provider, ip, true));
            // 其餘候選也逐一確認：回給用戶端的每個 IP 都要驗證過（Cloudflare 有些網站只能用特定 IP）
            let mut ips = vec![ip];
            if !octet {
                for &ip2 in &candidates[idx + 1..] {
                    if self.passes(provider, name, http_mode, ip2, base_ok).await {
                        ips.push(ip2);
                    }
                }
            }
            return Some(self.done(
                name,
                family,
                true,
                0,
                Done {
                    pop: Some(pop),
                    ms: Some(r.ms),
                    status: Some(r.status),
                    ip,
                    ips: Some(ips),
                    tried: Some(idx as u32 + 1),
                    http: http_mode.then_some(true),
                    reason: None,
                    retry_at: None,
                },
                true,
            ));
        }
        // 每個候選 IP 都明確表示「不服務這個網站」→ 判定失敗
        if let Some(z) = zone_fail {
            // Fastly 這類：可能只是還沒掃到放了這組憑證的網段，1 小時後再找一次
            let retry = octet.then(|| now_ms() + HOUR_MS);
            return Some(self.done(
                name,
                family,
                false,
                prev_fails,
                Done {
                    pop: z.pop,
                    ms: None,
                    status: z.status,
                    ip: z.ip,
                    ips: None,
                    tried: None,
                    http: None,
                    reason: Some(format!("{}（試了 {} 個網段）", z.reason, candidates.len())),
                    retry_at: retry,
                },
                false,
            ));
        }
        // 全部因網路或漂移失敗 → 暫不判定，10 分鐘後再試
        self.with_state(|st| {
            st.db.set_verdict(name, family, |v| {
                v.verdict = Some(intern("unknown"));
                v.reason = Some(last_reason.clone());
                v.until = Some(now_ms() + 600_000);
            })
        });
        warn!("{name} IPv{family} 暫無法判定：{last_reason}");
        Some("unknown")
    }

    /// 額外候選 IP 能不能服務這個網站（同樣的判斷，只是不寫判定）
    async fn passes(&self, provider: &str, name: &str, http_mode: bool, ip: IpAddr, base: Option<&ProbeResult>) -> bool {
        let prov = providers::get(provider);
        let r = self.probe_site(ip, name, http_mode).await;
        if !r.ok {
            if r.tls_error {
                self.with_state(|st| st.pools.zone_note(provider, ip, false));
            }
            return false;
        }
        if let Some(p) = prov {
            if p.is_provider(&r.headers) == Some(false) {
                let same = base.map(|b| b.status / 100 == r.status / 100 && r.status < 500).unwrap_or(false);
                if !same {
                    return false;
                }
            }
        }
        let pop = prov.filter(|p| p.has_pop()).map(|p| p.pop(&r.headers, &r.body)).unwrap_or_default();
        if !pop.is_empty() && !self.state().pools.accept_pop(provider, &pop) {
            return false;
        }
        if let Some(broken) = looks_broken_r(provider, &r) {
            if zone_kind(&broken) {
                self.with_state(|st| st.pools.zone_note(provider, ip, false));
            }
            return false;
        }
        if let Some(b) = base {
            if b.status < 400 && r.status >= 400 && r.status != b.status && r.status != 404 {
                return false;
            }
        }
        self.with_state(|st| st.pools.zone_note(provider, ip, true));
        true
    }

    /// 寫入判定（合併到舊紀錄，同 2.x）；`full` = 驗證成功的完整結果（ips / tried / http 一併更新）
    fn done(&self, name: &str, family: u8, ok: bool, prev_fails: u32, d: Done, full: bool) -> &'static str {
        let fails = if ok { 0 } else { prev_fails + 1 };
        let until = d.retry_at.unwrap_or_else(|| self.until(ok, fails));
        let reason = d.reason.clone();
        self.with_state(|st| {
            st.db.set_verdict(name, family, |v| {
                v.verdict = Some(intern(if ok { "ok" } else { "fail" }));
                v.fails = Some(fails);
                v.until = Some(until);
                v.algo = Some(2);
                if let Some(p) = &d.pop {
                    v.pop = Some(intern(p));
                }
                if let Some(m) = d.ms {
                    v.ms = Num::V(util::round(m, 1));
                }
                if let Some(s) = d.status {
                    v.status = Num::V(s as f64);
                }
                v.ip = Some(d.ip);
                if full {
                    v.ips = d.ips.clone();
                    v.tried = d.tried;
                    v.http = d.http;
                }
                if let Some(r) = &d.reason {
                    v.reason = Some(r.clone());
                }
            })
        });
        if ok {
            info!(
                "✔ {name} IPv{family} 台灣節點可用 ({} {} {}ms)",
                d.pop.as_deref().filter(|p| !p.is_empty()).unwrap_or("?"),
                d.status.map(|s| s.to_string()).unwrap_or_default(),
                d.ms.map(|m| util::round(m, 1).to_string()).unwrap_or_default()
            );
        } else {
            warn!("✘ {name} IPv{family} 台灣節點不可用：{}", reason.unwrap_or_default());
        }
        if ok {
            "ok"
        } else {
            "fail"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(kv: &[(&str, &str)]) -> Vec<(String, String)> {
        kv.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn broken_pages() {
        // 對照 2.x selftest「驗證判斷」
        assert!(
            looks_broken("cloudflare", 403, &h(&[]), "error code: 1034").is_some(),
            "Cloudflare 1034 判定失敗"
        );
        assert_eq!(
            looks_broken("cloudflare", 403, &h(&[]), "error code: 1034").unwrap(),
            "Cloudflare 錯誤 1034"
        );
        assert!(
            looks_broken(
                "cloudfront",
                403,
                &h(&[("x-cache", "Error from cloudfront")]),
                "The request could not be satisfied"
            )
            .is_some(),
            "CloudFront POP 不服務判定失敗"
        );
        assert_eq!(looks_broken("cloudflare", 200, &h(&[]), "<html>"), None, "正常 200 不判定失敗");
        assert_eq!(
            looks_broken("cloudflare", 403, &h(&[]), "<b>Error 1016</b>").unwrap(),
            "Cloudflare 錯誤 1016"
        );
        assert_eq!(
            looks_broken("cloudflare", 403, &h(&[]), "edge IP Restricted").unwrap(),
            "Cloudflare 錯誤 1xxx"
        );
        assert_eq!(looks_broken("cloudflare", 525, &h(&[]), "").unwrap(), "Cloudflare 525");
        assert_eq!(
            looks_broken("fastly", 421, &h(&[]), "").unwrap(),
            "HTTP 421 Misdirected（該節點不服務此網域）"
        );
        assert_eq!(looks_broken("fastly", 503, &h(&[]), "").unwrap(), "HTTP 503");
        assert_eq!(
            looks_broken("cloudfront", 404, &h(&[("x-cache", "Error from cloudfront")]), "nope").unwrap(),
            "CloudFront 404"
        );
    }
}
