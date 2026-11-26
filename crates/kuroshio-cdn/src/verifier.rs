//! 驗證某網域換到台灣節點後是否真的能運作（對齊 2.x `lib/cdn/verifier.js`）：
//! 方案不同、POP 沒開該服務時會失敗（Cloudflare 1xxx、HTTP 421、CloudFront Distribution 錯誤…）。

use crate::cdn::Cdn;
use crate::db::Base;
use crate::providers::{self, detect_from_headers, hv, is_tw_pop};
use crate::util::{self, intern, now_ms, Num, HOUR_MS};
use kuroshio_net::probe::{HttpsOpts, ProbeResult};
use std::collections::HashSet;
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

/// 社群好友提示的 IP 與驗證結果（None = 沒輪到試）
struct Hinted {
    ip: IpAddr,
    from: String,
    result: Option<bool>,
}

/// 好友提示最多試幾個（每個都要連一次）
const MAX_HINTS: usize = 4;

/// 一次驗證裡連不上（或憑證不符）幾個不同的台灣節點、一個都沒通過，就算是這個網站的問題（3.5.1 K2）：
/// 記在網站上（`fail`，失敗次數照加、逐次拉長），不暫停那些節點
pub const SITE_FAIL_NODES: usize = 3;

/// 這一次驗證裡連不上的節點（3.5.1 K2）：驗證結束後才決定要不要記到節點上
#[derive(Default)]
struct ConnOut {
    /// （節點，錯誤）
    list: Vec<(IpAddr, String)>,
    /// 判定是網站的問題：不記到節點上
    site_level: bool,
    /// 原本的 IP 連得上（連不上的時候多半是本機的網路，不記）
    base_ok: bool,
}

/// 原始節點 HTTPS 失敗的樣子（只用 HTTP 驗證時，候選節點要跟它一致）
struct HttpsFail {
    tls_error: bool,
    error: Option<String>,
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
    /// 握手比原本慢的判斷（3.5.0 F9）：確認比原本慢（`Fallback`）記成 `fail` 但不增加 `fails`
    slow: SlowMark,
    /// 上一次是「比原本慢」，這一次回到台灣節點（3.5.0 F9 的 `slowerReturned`）
    returned: bool,
}

/// 驗證時內容最多讀多少：判斷只看狀態碼與標頭（內容只用來找 Cloudflare 的 `colo=`，那在 /cdn-cgi/trace，
/// 不在首頁），跟純 HTTP 探測一樣讀 4 KB 就關（3.4.2 以前讀 16 KB）
/// 這家業者在這個網域的哪一格（多來源，3.5.0 B3）
enum Slot<'a> {
    Main,
    Alt(&'a crate::db::Alt),
    None,
}

fn slot_of<'a>(e: &'a crate::db::Domain, provider: &str, multi_cdn: bool) -> Slot<'a> {
    match e.provider() {
        _ if !multi_cdn => Slot::Main,
        None => Slot::Main,
        Some(p) if p == provider => Slot::Main,
        Some(_) => match e.src.as_ref().and_then(|s| s.alt.as_deref()) {
            Some(a) if a.provider.val().map(|p| &**p) == Some(provider) => Slot::Alt(a),
            _ => Slot::None,
        },
    }
}

const VERIFY_MAX_BODY: usize = 4096;

/// 驗證結果 `extra` 裡「比原本慢」的欄位（3.5.0 E7；`score`、`origScore` 同 B4 的 `Cross`，3.5.0 F9 起是握手時間）
pub const SLOWER: &str = "slower";
/// 第一次握手比原本慢、還沒確認（3.5.0 F9）：`{ "at": 毫秒, "score": 台灣, "origScore": 原本 }`
pub const SLOW1: &str = "slow1";

/// 握手比原本慢的判斷結果（3.5.0 F9）
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum SlowMark {
    /// 沒有判、或不慢：清掉 `slow1`／`slower`
    Clear,
    /// 第一次慢：照常換台灣節點，記 `slow1`
    First { tw: f64, og: f64 },
    /// 第一次慢到現在還不到 10 分鐘（手動驗證、別的原因提早重驗）：不算確認，`slow1` 不動
    Keep,
    /// 確認比原本慢：暫時用原本的答案。`gap_min` = 跟第一次相隔幾分鐘；None = 退回之後重驗還是慢
    Fallback { tw: f64, og: f64, gap_min: Option<u64> },
}

/// [`Cdn::slower_check`] 的結果
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SlowCheck {
    pub mark: SlowMark,
    /// 上一次是「比原本慢」，這一次不慢：回到台灣節點
    pub returned: bool,
    /// 手動驗證回應的 `speed`（沒有判的時候 None）
    pub speed: Option<serde_json::Value>,
}

impl SlowCheck {
    fn skipped() -> SlowCheck {
        SlowCheck {
            mark: SlowMark::Clear,
            returned: false,
            speed: None,
        }
    }
}

/// 上一次驗證留下的狀態（3.5.0 F9）
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub(crate) struct PrevSlow {
    /// 上一次是「比原本慢」（退回中，或退回已經到期）
    pub was_slower: bool,
    /// 第一次慢的時間
    pub slow1_at: Option<u64>,
}

impl PrevSlow {
    pub(crate) fn of(v: Option<&crate::db::Verdict>) -> PrevSlow {
        PrevSlow {
            was_slower: v.is_some_and(|v| v.extra.get(SLOWER).and_then(serde_json::Value::as_bool) == Some(true)),
            slow1_at: v.and_then(slow1_at),
        }
    }
}

/// `slow1` 的時間（沒有、或格式不對回 None）
pub(crate) fn slow1_at(v: &crate::db::Verdict) -> Option<u64> {
    v.extra.get(SLOW1).and_then(|x| x.get("at")).and_then(serde_json::Value::as_u64)
}

/// 驗證結果 `extra` 裡「原本的答案已經在台灣機房」的 POP（3.5.1）：有這個欄位的 `fail` 不是驗證失敗，是「不用換」
pub const ORIG_TW: &str = "origTw";

/// 「原本的答案已經在台灣機房」的 POP（沒有回 None）
pub fn orig_tw_pop(v: &crate::db::Verdict) -> Option<&str> {
    v.extra.get(ORIG_TW).and_then(serde_json::Value::as_str)
}

fn clear_orig_tw(extra: &mut util::Extra) {
    if let Some(m) = extra.0.as_mut() {
        m.remove(ORIG_TW);
        if m.is_empty() {
            extra.0 = None;
        }
    }
}

/// 依判斷結果寫入或拿掉 `slower`／`slow1`（只有這兩種狀態存分數；沒有的時候不配置）
fn apply_slow(extra: &mut util::Extra, mark: SlowMark, now: u64) {
    if let Some(m) = extra.0.as_mut() {
        if !matches!(mark, SlowMark::Keep) {
            m.remove(SLOW1);
        }
        if m.remove(SLOWER).is_some() {
            m.remove("score");
            m.remove("origScore");
        }
    }
    match mark {
        SlowMark::Clear | SlowMark::Keep => {}
        SlowMark::First { tw, og } => {
            let m = extra.0.get_or_insert_with(Default::default);
            m.insert(SLOW1.into(), serde_json::json!({ "at": now, "score": tw, "origScore": og }));
        }
        SlowMark::Fallback { tw, og, .. } => {
            let m = extra.0.get_or_insert_with(Default::default);
            m.insert(SLOWER.into(), serde_json::Value::Bool(true));
            m.insert("score".into(), serde_json::json!(tw));
            m.insert("origScore".into(), serde_json::json!(og));
        }
    }
    if extra.0.as_ref().is_some_and(|m| m.is_empty()) {
        extra.0 = None;
    }
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
                        max_body: VERIFY_MAX_BODY,
                        ..Default::default()
                    },
                )
                .await
        }
    }

    /// 驗證（同 2.x `Verifier.verify`）：回傳 ok / fail / unknown，沒有候選 IP 回 None。
    /// 系統時間還沒對時（憑證驗不過）：不驗證、不記任何結果，回 `deferred`
    pub async fn verify(self: &Arc<Self>, name: &str, provider: &str, family: u8, orig: Option<IpAddr>) -> Option<&'static str> {
        if !kuroshio_net::clock::synced() {
            return Some("deferred");
        }
        self.verify_with_speed(name, provider, family, orig).await.0
    }

    /// 同 [`Cdn::verify`]，另外回這一次握手比原本慢的判斷（3.5.0 F9，手動驗證回應的 `speed`；沒有判的時候 None）
    pub(crate) async fn verify_with_speed(
        self: &Arc<Self>,
        name: &str,
        provider: &str,
        family: u8,
        orig: Option<IpAddr>,
    ) -> (Option<&'static str>, Option<serde_json::Value>) {
        if !kuroshio_net::clock::synced() {
            return (Some("deferred"), None);
        }
        let mut hinted: Vec<Hinted> = Vec::new();
        let mut speed = None;
        let mut conn = ConnOut::default();
        let r = self
            .verify_inner(name, provider, family, orig, &mut hinted, &mut speed, &mut conn)
            .await;
        // 連不上的節點（3.5.1 K2）：網站的問題不記；其餘記下來，同一個節點 1 小時內第 2 個網站也連不上才暫停
        if conn.base_ok && !conn.site_level && !conn.list.is_empty() {
            self.with_state(|st| {
                for (ip, err) in &conn.list {
                    st.pools.note_conn_fail(provider, *ip, name, &format!("驗證 {name} 時 {err}"));
                }
            });
        }
        // 社群提示的命中率：好友給的 IP 在我這邊驗證成功 / 失敗（沒輪到試的不算）
        if !hinted.is_empty() {
            if let Some(h) = self.hints() {
                for x in &hinted {
                    if let Some(ok) = x.result {
                        h.hint_result(&x.from, crate::cdn::HintKind::Site, ok);
                    }
                }
            }
        }
        (r, speed)
    }

    /// 只用 HTTP 驗證的網站（原始節點的 HTTPS 連不上）：候選節點的 HTTPS 也要「跟原始節點一樣」或「可以用」。
    /// 原始節點只是一時連不上 HTTPS 的時候，沒有這項檢查就會把「憑證沒驗證過」的節點回給用 HTTPS 的用戶端
    async fn https_consistent(&self, ip: IpAddr, name: &str, base: &HttpsFail) -> bool {
        let r = self.probe_site(ip, name, false).await;
        if r.ok {
            return true; // 憑證有效：比原始節點還好
        }
        r.tls_error == base.tls_error && (r.tls_error || r.error == base.error)
    }

    #[allow(clippy::too_many_arguments)]
    async fn verify_inner(
        self: &Arc<Self>,
        name: &str,
        provider: &str,
        family: u8,
        orig: Option<IpAddr>,
        hinted_out: &mut Vec<Hinted>,
        speed_out: &mut Option<serde_json::Value>,
        conn_out: &mut ConnOut,
    ) -> Option<&'static str> {
        let prov = providers::get(provider);
        let label = providers::label(provider);
        // （上一次的失敗次數，上一次的握手比原本慢的狀態（3.5.0 F9），手動設成「一定換」）
        let (prev_fails, prev_slow, always) = {
            let st = self.state();
            let of = |v: Option<&crate::db::Verdict>| (v.and_then(|v| v.fails).unwrap_or(0), PrevSlow::of(v));
            // 多來源（3.5.0 B3）：這一家已經沒有格子（被別家擠掉、過期）→ 不驗證，結果沒有地方放
            let ((f, w), always) = match st.db.get(name).map(|e| (e, slot_of(e, provider, st.db.multi_cdn))) {
                Some((e, Slot::Main)) => (of(e.verdict(family)), e.policy() == crate::db::Policy::Always),
                Some((e, Slot::Alt(a))) => (
                    of(if family == 6 { a.v6.as_deref() } else { a.v4.as_deref() }),
                    e.policy() == crate::db::Policy::Always,
                ),
                Some((_, Slot::None)) => return None,
                None => ((0, PrevSlow::default()), false),
            };
            (f, w, always)
        };
        let t = Duration::from_millis(self.cfg.verify_timeout_ms);

        // 1. 基準：用原始 IP 連一次，記錄原本被分配到哪個 POP（給分析用）
        // 有些網站只開 HTTP（OCSP / CRL、軟體更新鏡像…），原始節點的 HTTPS 就失敗時改用 HTTP 驗證
        let mut base: Option<ProbeResult> = None;
        // 原本的答案被分配到的 POP（3.5.1：已經是台灣機房就不換）
        let mut base_pop = String::new();
        let mut http_mode = false;
        let mut base_https: Option<HttpsFail> = None;
        // 3.5.1 M2：原本的 IP 要是這個家族的（舊資料的 v4 基準 IP 可能被 v6 驗證蓋成 IPv6，拿它量到的 POP 會判錯 v4）
        if let Some(o) = orig.filter(|o| o.is_ipv6() == (family == 6)) {
            let mut b = self.probe_site(o, name, false).await;
            if !b.ok && b.error.as_deref() != Some("TIMEOUT") {
                let b2 = self.net.http_probe(o, name, "/", t).await;
                if b2.ok {
                    base_https = Some(HttpsFail {
                        tls_error: b.tls_error,
                        error: b.error.clone(),
                    });
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
            // 基準只記 v4（3.5.1 M2）：v6 驗證以前也寫同一格，把 v4 的基準 IP 蓋成 IPv6
            self.with_state(|st| {
                st.db.with_slot(name, provider, |db| {
                    if family != 4 {
                        return;
                    }
                    db.set_base(
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
                })
            });
            base_pop = pop;
            base = Some(b);
        }
        let base_ok = base.as_ref().filter(|b| b.ok);
        conn_out.base_ok = base_ok.is_some();
        // 3.5.1（Azure「台北換台北」）：原本的答案這條線連過去已經落在台灣機房 → 當成已是台灣、不換。
        // 換成節點池裡另一個台灣節點不會更近，實測握手反而常常比較慢（同一個城市換另一個節點）；
        // 也不必再對候選節點一個一個連。範圍同 F9：IPv4、非最近節點型、不是「一定換」、`cdn.slowerFallback` 開著；
        // 原本的回應要正常（狀態碼 500 以下、不像壞掉的頁面）
        if let (Some(b), Some(o)) = (base_ok, orig) {
            if family == 4
                && self.cfg.slower_fallback
                && !always
                && !Cdn::is_nearest(provider)
                && is_tw_pop(&base_pop)
                && b.status < 500
                && looks_broken_r(provider, b).is_none()
            {
                return Some(self.done_orig_tw(name, provider, family, prev_fails, o, &base_pop, b));
            }
        }

        // 2. 依序用台灣池內 IP 測試
        // 保留最後一段的 CDN（Fastly）：候選 = 最佳幾個 POP 的網段 + 原始 IP 最後一段
        let octet = family == 4 && self.state().pools.octet_mode(provider);
        let mut candidates: Vec<IpAddr> = {
            let st = self.state();
            if octet {
                // 這一家那一格看到的 IP（多來源時不能拿別家的 IP 來猜最後一段）
                let (mut observed, base_ip): (Vec<IpAddr>, Option<IpAddr>) =
                    match st.db.get(name).map(|e| (e, slot_of(e, provider, st.db.multi_cdn))) {
                        Some((e, Slot::Main)) => (e.ips4.to_vec(), e.base_ip4()),
                        Some((_, Slot::Alt(a))) => (a.ips4.to_vec(), a.base.as_ref().and_then(|b| b.ip).filter(IpAddr::is_ipv4)),
                        _ => (Vec::new(), None),
                    };
                if let Some(b) = base_ip {
                    observed.push(b);
                }
                st.pools.verify_candidates(provider, orig, &observed)
            } else {
                let mut v = st.pools.serve_ips(provider, family);
                v.truncate(self.cfg.verify_candidates);
                v
            }
        };
        // 自己的節點池沒有候選：好友的提示驗證通過也不能拿來用（見下面的 usable），不用試
        if candidates.is_empty() {
            return None;
        }
        // 社群好友驗證過這個網站可用的 IP：排在最前面先試
        if let Some(h) = self.hints() {
            let mut seen: HashSet<IpAddr> = HashSet::new();
            let st = self.state();
            for x in h.domain_hint(name, provider, family) {
                if !seen.insert(x.ip) {
                    continue;
                }
                // 只收「這家 CDN 官方範圍內、位址家族相符」的：好友給的只是候選，範圍外的（可能是任何人的機器）
                // 連試都不試，直接算沒命中。只用 HTTP 驗證的網站沒有憑證把關，這一關尤其重要
                let in_range = x.ip.is_ipv6() == (family == 6) && st.pools.classify(x.ip).map(|c| c.provider == provider).unwrap_or(false);
                let take = in_range && hinted_out.iter().filter(|h| h.result.is_none()).count() < MAX_HINTS;
                hinted_out.push(Hinted {
                    ip: x.ip,
                    from: x.from,
                    result: if in_range { None } else { Some(false) },
                });
                if !take {
                    seen.remove(&x.ip);
                }
            }
            drop(st);
            if !seen.is_empty() {
                let mut c: Vec<IpAddr> = hinted_out.iter().map(|x| x.ip).filter(|ip| seen.contains(ip)).collect();
                c.extend(candidates.iter().copied().filter(|ip| !seen.contains(ip)));
                candidates = c;
            }
        }
        let note = |hinted: &mut Vec<Hinted>, ip: IpAddr, ok: bool| {
            if let Some(h) = hinted.iter_mut().find(|h| h.ip == ip) {
                h.result = Some(ok);
            }
        };
        let mut last_reason = "無可用台灣節點".to_string();
        let mut zone_fail: Option<ZoneFail> = None;
        // 這一次連不上或憑證不符的不同節點數（3.5.1 K2）
        let mut failed_nodes: Vec<IpAddr> = Vec::new();
        for (idx, &ip) in candidates.iter().enumerate() {
            note(hinted_out, ip, false);
            let r = self.probe_site(ip, name, http_mode).await;
            if !r.ok {
                let err = r.error.clone().unwrap_or_default();
                if !failed_nodes.contains(&ip) {
                    failed_nodes.push(ip);
                }
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
                // 3.5.1 K2：不馬上暫停節點，驗證結束後再看是網站還是節點的問題（`verify_with_speed()`）
                conn_out.list.push((ip, err));
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
                        note(hinted_out, ip, true);
                        if !self.state().pools.usable(provider, ip) {
                            last_reason = "只有不在節點池裡的 IP 可用".into();
                            continue;
                        }
                        return Some(self.done(
                            name,
                            provider,
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
                                slow: SlowMark::Clear,
                                returned: false,
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
                    provider,
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
                        slow: SlowMark::Clear,
                        returned: false,
                    },
                    false,
                ));
            }
            if let Some(b) = base_ok {
                if b.status < 400 && r.status >= 400 && r.status != b.status && r.status != 404 {
                    return Some(self.done(
                        name,
                        provider,
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
                            slow: SlowMark::Clear,
                            returned: false,
                        },
                        false,
                    ));
                }
            }
            if let Some(bh) = &base_https {
                if !self.https_consistent(ip, name, bh).await {
                    last_reason = "HTTP 可以用，但 HTTPS 跟原始節點不一致".into();
                    continue;
                }
            }
            note(hinted_out, ip, true);
            // 驗證通過、但不在自己節點池裡的（好友提示的 IP）不能回給用戶端：只算好友的命中率，繼續找自己能用的。
            // 以前會把判定寫成「通過」，查詢時卻沒有 IP 可以回，於是每次查詢都重新驗證一輪
            if !self.state().pools.usable(provider, ip) {
                last_reason = "只有不在節點池裡的 IP 可用".into();
                continue;
            }
            self.with_state(|st| st.pools.zone_note(provider, ip, true));
            // 3.5.0 F9（E7 第二版）：台灣節點能用，但握手連續兩次（相隔 10 分鐘以上）比原本慢 → 暫時用原本的答案
            // （既有的「驗證失敗 → 原始」），15 分鐘後有人查再重驗。節點沒有壞：不標壞、不增加失敗次數；好友的提示照樣算命中
            let chk = self.slower_check(provider, family, orig, http_mode, base_ok, &r, prev_slow, always);
            speed_out.clone_from(&chk.speed);
            if let SlowMark::Fallback { tw, og, .. } = chk.mark {
                return Some(self.done(
                    name,
                    provider,
                    family,
                    false,
                    prev_fails,
                    Done {
                        pop: Some(pop),
                        ms: Some(r.ms),
                        status: Some(r.status),
                        ip,
                        ips: None,
                        tried: None,
                        http: None,
                        reason: Some(format!("台灣節點握手連續兩次比原本慢（{tw} 毫秒對 {og} 毫秒）")),
                        retry_at: Some(now_ms() + self.slower_retest_ms()),
                        slow: chk.mark,
                        returned: false,
                    },
                    false,
                ));
            }
            // 其餘候選也逐一確認：回給用戶端的每個 IP 都要驗證過（Cloudflare 有些網站只能用特定 IP）
            let mut ips = vec![ip];
            if !octet {
                for &ip2 in &candidates[idx + 1..] {
                    let ok = self.passes(provider, name, http_mode, ip2, base_ok, base_https.as_ref()).await;
                    note(hinted_out, ip2, ok);
                    if ok && self.state().pools.usable(provider, ip2) {
                        ips.push(ip2);
                    }
                }
            } else {
                // 保留最後一段的 CDN（Fastly）：回給用戶端的備援 IP 也要針對這個網站驗證過
                // （以前備援是節點池裡「別的網站驗證過」的同一段 IP）。只找同一個 POP 的，湊到要回的數量為止，最多多試 4 個
                let want = self.cfg.serve_count_of(provider);
                let pop_of = |x: IpAddr| self.state().pools.pop_of_ip(provider, x);
                let my_pop = pop_of(ip);
                let mut extra = 0;
                for &ip2 in &candidates[idx + 1..] {
                    if ips.len() >= want || extra >= 4 {
                        break;
                    }
                    if pop_of(ip2) != my_pop {
                        continue;
                    }
                    extra += 1;
                    let ok = self.passes(provider, name, http_mode, ip2, base_ok, base_https.as_ref()).await;
                    note(hinted_out, ip2, ok);
                    if ok && self.state().pools.usable(provider, ip2) {
                        ips.push(ip2);
                    }
                }
            }
            return Some(self.done(
                name,
                provider,
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
                    slow: chk.mark,
                    returned: chk.returned,
                },
                true,
            ));
        }
        // 一個都沒通過，而且連不上（或憑證不符）的不同節點有 3 個以上：這個網站的問題（例如只接受業者專用的 IP），
        // 不是那些節點的問題（3.5.1 K2：D3 壓測裡 Fastly 節點被暫停的大多是這種）
        conn_out.site_level = base_ok.is_some() && failed_nodes.len() >= SITE_FAIL_NODES;
        // 每個候選 IP 都明確表示「不服務這個網站」→ 判定失敗
        if let Some(z) = zone_fail {
            // Fastly 這類：可能只是還沒掃到放了這組憑證的網段，1 小時後再找一次；
            // 一直找不到就逐次拉長（1、2、4…小時，不超過一般失敗的到期時間；3.5.1 K2）
            let retry = octet.then(|| {
                let normal = self.until(false, prev_fails + 1);
                (now_ms() + (HOUR_MS << prev_fails.min(5))).min(normal)
            });
            return Some(self.done(
                name,
                provider,
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
                    slow: SlowMark::Clear,
                    returned: false,
                },
                false,
            ));
        }
        // 連不上很多個不同的節點（3.5.1 K2）：記在網站上，失敗次數照加、到期時間逐次拉長（以前是「暫不判定、10 分鐘後再試」，
        // 而且每個節點都暫停，結果對其他網站是好的節點一直被暫停又恢復）
        if conn_out.site_level {
            return Some(self.done(
                name,
                provider,
                family,
                false,
                prev_fails,
                Done {
                    pop: None,
                    ms: None,
                    status: None,
                    ip: failed_nodes[0],
                    ips: None,
                    tried: None,
                    http: None,
                    reason: Some(format!(
                        "試了 {} 個台灣節點都連不上（{last_reason}）：這個網站可能只接受業者專用的 IP",
                        failed_nodes.len()
                    )),
                    retry_at: None,
                    slow: SlowMark::Clear,
                    returned: false,
                },
                false,
            ));
        }
        // 全部因網路或漂移失敗 → 暫不判定，10 分鐘後再試
        self.with_state(|st| {
            st.db.with_slot(name, provider, |db| {
                db.set_verdict(name, family, |v| {
                    v.verdict = Some(intern("unknown"));
                    v.reason = Some(last_reason.clone());
                    v.until = Some(now_ms() + 600_000);
                })
            })
        });
        warn!("{name} IPv{family} 暫無法判定：{last_reason}");
        Some("unknown")
    }

    /// 原本的答案已經在台灣機房（3.5.1）：記成 `fail`＋`origTw`（查詢路徑走既有的「驗證失敗 → 原始」），
    /// 不加失敗次數、不標壞節點、不算驗證失敗；[`CdnConfig::verify_fail_hours`]（預設 6 小時）後有人查再看一次
    /// （原本的答案也可能被業者改到國外）
    #[allow(clippy::too_many_arguments)]
    fn done_orig_tw(
        &self,
        name: &str,
        provider: &str,
        family: u8,
        prev_fails: u32,
        orig: IpAddr,
        pop: &str,
        b: &ProbeResult,
    ) -> &'static str {
        let now = now_ms();
        let until = now + (self.cfg.verify_fail_hours * HOUR_MS as f64) as u64;
        self.with_state(|st| {
            st.stats.orig_tw = st.stats.orig_tw.saturating_add(1);
            st.db.with_slot(name, provider, |db| {
                db.set_verdict(name, family, |v| {
                    v.verdict = Some(intern("fail"));
                    v.fails = Some(prev_fails);
                    v.until = Some(until);
                    v.algo = Some(2);
                    v.pop = Some(intern(pop));
                    v.ms = if b.ms > 0.0 { Num::V(util::round(b.ms, 1)) } else { Num::Null };
                    v.status = Num::V(b.status as f64);
                    v.ip = Some(orig);
                    v.reason = Some(format!("原本的答案已經在台灣機房（{pop}），不換"));
                    apply_slow(&mut v.extra, SlowMark::Clear, now);
                    v.extra
                        .0
                        .get_or_insert_with(Default::default)
                        .insert(ORIG_TW.into(), serde_json::json!(pop));
                })
            })
        });
        info!(
            "◎ {name} IPv{family} 原本的答案已經在台灣機房（{pop}），不換；{} 小時後有人查再看一次",
            self.cfg.verify_fail_hours
        );
        "fail"
    }

    /// 確認比原本慢之後退回多久（3.5.0 F9：15 分鐘；`cdn.lite` 1 小時）
    pub(crate) fn slower_retest_ms(&self) -> u64 {
        if self.cfg.lite {
            crate::reach::SLOWER_RETEST_LITE_MS
        } else {
            crate::reach::SLOWER_RETEST_MS
        }
    }

    /// 台灣節點的握手時間是不是比原本的慢（3.5.0 F9，E7 第二版）。
    ///
    /// 只處理 IPv4、非最近節點型、不是手動「一定換」、不是只能用 HTTP 驗證的網站（沒有握手）、原本的 IP 探測成功、
    /// 兩邊的握手時間（`Timing::handshake_ms()`，連線＋TLS，不含 TTFB）都量到的；保險絲跳了不判。
    /// `慢 = 台灣 × 0.7 > 原本 ＋ 10 毫秒`。同一次驗證裡不複測（不多連線）：
    /// - 第一次慢（沒有 `slow1`、或超過 24 小時）→ 照常換台灣節點，記 `slow1`
    /// - `slow1` 已經 10 分鐘以上（24 小時內）還是慢、或上一次已經退回、重驗還是慢 → 確認，退回原本的答案
    /// - `slow1` 不到 10 分鐘（手動驗證等）→ 不算確認，`slow1` 不動
    /// - 不慢 → 清掉；上一次是退回的就回到台灣節點（進去要兩次、回來只要一次）
    ///
    /// 保險絲只算確認的那幾次（`slow1` 不算）
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn slower_check(
        &self,
        provider: &str,
        family: u8,
        orig: Option<IpAddr>,
        http_mode: bool,
        base: Option<&ProbeResult>,
        r: &ProbeResult,
        prev: PrevSlow,
        always: bool,
    ) -> SlowCheck {
        if !self.cfg.slower_fallback || family != 4 || always || http_mode || Cdn::is_nearest(provider) {
            return SlowCheck::skipped();
        }
        if orig.filter(IpAddr::is_ipv4).is_none() {
            return SlowCheck::skipped();
        }
        let (Some(tw), Some(og)) = (r.timing.handshake_ms(), base.and_then(|b| b.timing.handshake_ms())) else {
            return SlowCheck::skipped();
        };
        let now = now_ms();
        if self.state().line.fuse.active(now) {
            return SlowCheck::skipped();
        }
        let (tw, og) = (util::round(tw, 1), util::round(og, 1));
        let slow = crate::reach::slower_than(tw, og);
        let age = prev
            .slow1_at
            .map(|a| now.saturating_sub(a))
            .filter(|a| *a <= crate::reach::SLOWER_FIRST_TTL_MS);
        let gap = crate::reach::SLOWER_CONFIRM_GAP_MS;
        let confirmed = slow && (prev.was_slower || age.is_some_and(|a| a >= gap));
        // 保險絲（只算確認的）：這一次跳的也照驗證通過處理
        let tripped = self.with_state(|st| st.line.fuse.note(confirmed, now));
        let mark = if !slow || tripped {
            SlowMark::Clear
        } else if confirmed {
            SlowMark::Fallback {
                tw,
                og,
                gap_min: if prev.was_slower { None } else { age.map(|a| a / 60_000) },
            }
        } else if age.is_some() {
            SlowMark::Keep
        } else {
            SlowMark::First { tw, og }
        };
        let (state, confirm_after) = match mark {
            SlowMark::Fallback { .. } => ("slower", 0),
            SlowMark::First { .. } => ("slow1", gap),
            SlowMark::Keep => ("slow1", gap.saturating_sub(age.unwrap_or(0))),
            SlowMark::Clear => ("ok", 0),
        };
        SlowCheck {
            mark,
            returned: prev.was_slower && mark == SlowMark::Clear,
            speed: Some(serde_json::json!({
                "score": tw, "origScore": og, "weighted": util::round(tw * crate::reach::SLOWER_TW_WEIGHT, 1),
                "slower": slow, "state": state, "confirmAfter": confirm_after,
            })),
        }
    }

    /// 額外候選 IP 能不能服務這個網站（同樣的判斷，只是不寫判定）
    async fn passes(
        &self,
        provider: &str,
        name: &str,
        http_mode: bool,
        ip: IpAddr,
        base: Option<&ProbeResult>,
        base_https: Option<&HttpsFail>,
    ) -> bool {
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
        if let Some(bh) = base_https {
            if !self.https_consistent(ip, name, bh).await {
                return false;
            }
        }
        self.with_state(|st| st.pools.zone_note(provider, ip, true));
        true
    }

    /// 寫入判定（合併到舊紀錄，同 2.x）；`full` = 驗證成功的完整結果（ips / tried / http 一併更新）
    #[allow(clippy::too_many_arguments)]
    fn done(&self, name: &str, provider: &str, family: u8, ok: bool, prev_fails: u32, d: Done, full: bool) -> &'static str {
        // 比原本慢（3.5.0 E7／F9）：節點沒有壞，失敗次數不加
        let fallback = matches!(d.slow, SlowMark::Fallback { .. });
        let returned = ok && d.returned;
        let fails = if ok {
            0
        } else if fallback {
            prev_fails
        } else {
            prev_fails + 1
        };
        let until = d.retry_at.unwrap_or_else(|| self.until(ok, fails));
        let reason = d.reason.clone();
        let now = now_ms();
        self.with_state(|st| {
            if ok {
                st.stats.verify_ok = st.stats.verify_ok.saturating_add(1);
            } else if fallback {
                st.stats.slower_fallback = st.stats.slower_fallback.saturating_add(1);
                st.line.note_slower(now);
            } else {
                st.stats.verify_fail = st.stats.verify_fail.saturating_add(1);
            }
            if matches!(d.slow, SlowMark::First { .. }) {
                st.stats.slower_first = st.stats.slower_first.saturating_add(1);
            }
            if returned {
                st.stats.slower_returned = st.stats.slower_returned.saturating_add(1);
            }
            st.db.with_slot(name, provider, |db| {
                db.set_verdict(name, family, |v| {
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
                    // 變成 ok 時連 reason 一起清掉（3.5.0 F9／H12：以前只在有新值時才寫，「比原本慢」會一直留著）
                    if ok {
                        v.reason.clone_from(&d.reason);
                    } else if let Some(r) = &d.reason {
                        v.reason = Some(r.clone());
                    }
                    apply_slow(&mut v.extra, d.slow, now);
                    clear_orig_tw(&mut v.extra);
                })
            })
        });
        let minutes = self.slower_retest_ms() / 60_000;
        if let SlowMark::Fallback { tw, og, gap_min } = d.slow {
            match gap_min {
                Some(k) => info!(
                    "↷ {name} IPv{family} 台灣節點能用，但握手連續兩次比原本慢（{tw} 對 {og} 毫秒，相隔 {k} 分鐘）：暫時用原本的答案，{minutes} 分鐘後有人查再重驗"
                ),
                None => info!(
                    "↷ {name} IPv{family} 重驗握手還是比原本慢（{tw} 對 {og} 毫秒）：繼續用原本的答案，{minutes} 分鐘後有人查再重驗"
                ),
            }
        } else if ok {
            let note = match d.slow {
                SlowMark::First { tw, og } => {
                    format!("；握手比原本慢（{tw} 對 {og} 毫秒），先照常換，10 分鐘後有人查再確認一次")
                }
                _ if returned => "；重驗握手不比原本慢，回到台灣節點".to_string(),
                _ => String::new(),
            };
            info!(
                "✔ {name} IPv{family} 台灣節點可用 ({} {} {}ms){note}",
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
