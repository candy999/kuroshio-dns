//! 跨 CDN 備援（對齊 2.x `lib/cdn/cross.js`）：網站原本的 CDN 沒有台灣節點（Fastly），或 ECS 也找不到台灣節點時，
//! 試試同一個網站是不是也放在別家有台灣節點的 CDN 上（大網站常同時簽好幾家）。
//!
//! 用網站自己的網域名稱（SNI / Host）去連 Cloudflare、CloudFront、Azure 的台北節點，以及 Akamai 在台灣的節點
//! （解析 `<網域>.edgekey.net` / `.edgesuite.net`，帶台灣網段 ECS），全部條件都符合才算可用：
//!   1. 憑證有效且是這個網域的
//!   2. 回應確實來自那家 CDN（cf-ray、x-amz-cf-pop、x-azure-ref…）
//!   3. 不是 CDN 的錯誤頁（Cloudflare 1xxx、CloudFront「configured to allow」、Akamai「Invalid URL」…）
//!   4. 跟原本的網站一樣：狀態碼同一類、轉址目的地相同、內容類型相同、HTML 標題相同
//!   5. 比原本快（至少快 `nearestMinGainMs`）
//!
//! 成功就記在網域資料庫（cross4），之後直接使用；每天複驗一次。

use crate::cdn::Cdn;
use crate::db::{Cross, Tried};
use crate::providers::{self, hv, Headers};
use crate::util::{self, intern, now_ms, Num, DAY_MS, HOUR_MS};
use crate::verifier::looks_broken;
use kuroshio_net::probe::{HttpsOpts, ProbeResult};
use kuroshio_proto::message::rtype;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

pub const TARGETS: [&str; 4] = ["cloudflare", "cloudfront", "azure", "akamai"];

/// HTML 標題（`<title …>` 後面 1–200 個非 `<` 字元，再接 `</title>`），連續空白合併
pub fn title(body: &str) -> Option<String> {
    let low = body.to_ascii_lowercase();
    let mut from = 0;
    while let Some(p) = low[from..].find("<title") {
        let start = from + p + 6;
        from = start;
        let Some(gt) = low[start..].find('>') else { break };
        let content_start = start + gt + 1;
        let rest = &body[content_start..];
        let end = rest.find('<').unwrap_or(rest.len());
        let content = &rest[..end];
        let n = content.chars().count();
        if (1..=200).contains(&n) && low[content_start + end..].starts_with("</title>") {
            let t = content.split_whitespace().collect::<Vec<_>>().join(" ");
            return Some(t);
        }
    }
    None
}

/// 內容類型（不含參數，小寫）
pub fn ctype(h: &Headers) -> String {
    hv(h, "content-type").split(';').next().unwrap_or("").trim().to_ascii_lowercase()
}

/// 轉址目的地（主機 + 路徑；相對網址以 `https://x.invalid/` 為基準）
pub fn loc_of(h: &Headers) -> String {
    let l = hv(h, "location").trim();
    if l.is_empty() {
        return String::new();
    }
    let low = l.to_ascii_lowercase();
    let skip = ["https://", "http://", "//"].iter().find(|p| low.starts_with(*p)).map(|p| p.len());
    let (host, path) = if let Some(r) = skip.map(|n| &l[n..]) {
        let end = r.find(['/', '?', '#']).unwrap_or(r.len());
        let auth = &r[..end];
        let auth = auth.rsplit('@').next().unwrap_or(auth).to_ascii_lowercase();
        let auth = auth
            .strip_suffix(":443")
            .or_else(|| auth.strip_suffix(":80"))
            .unwrap_or(&auth)
            .to_string();
        (auth, r[end..].to_string())
    } else if l.starts_with('/') {
        ("x.invalid".to_string(), l.to_string())
    } else {
        ("x.invalid".to_string(), format!("/{l}"))
    };
    let p = path.split(['?', '#']).next().unwrap_or("");
    format!("{host}{}", if p.is_empty() { "/" } else { p })
}

/// 兩個回應是不是同一個網站（回傳不同的原因，相同就回 None）
pub fn same_site(base: &ProbeResult, r: &ProbeResult) -> Option<String> {
    if base.status / 100 != r.status / 100 {
        return Some(format!("狀態不同（原 {}／{}）", base.status, r.status));
    }
    if (300..400).contains(&base.status) && loc_of(&base.headers) != loc_of(&r.headers) {
        return Some("轉址目的地不同".into());
    }
    let (c1, c2) = (ctype(&base.headers), ctype(&r.headers));
    if !c1.is_empty() && !c2.is_empty() && c1 != c2 {
        return Some(format!("內容類型不同（{c1}／{c2}）"));
    }
    if let (Some(t1), Some(t2)) = (title(&base.body), title(&r.body)) {
        if t1 != t2 {
            return Some("頁面標題不同".into());
        }
    }
    None
}

/// 各家 CDN 的通用錯誤頁（設定不存在時回的頁面）
pub fn cross_broken(target: &str, r: &ProbeResult) -> Option<String> {
    if let Some(b) = looks_broken(target, r.status, &r.headers, &r.body) {
        return Some(b);
    }
    let low = r.body.to_ascii_lowercase();
    let reference = ["reference&#32;&#35;", "reference&#32;#"].iter().any(|p| low.contains(p)) || {
        // Reference\s(&#35;|#)
        let b = low.as_bytes();
        let mut found = false;
        let mut from = 0;
        while let Some(p) = low[from..].find("reference") {
            let i = from + p + 9;
            if i < b.len() && (b[i] as char).is_ascii_whitespace() && (low[i + 1..].starts_with("&#35;") || low[i + 1..].starts_with('#')) {
                found = true;
                break;
            }
            from = from + p + 1;
        }
        found
    };
    if (low.contains("invalid url") || low.contains("access denied")) && reference {
        return Some("Akamai 錯誤頁（沒有這個網站的設定）".into());
    }
    let pnf = low
        .find("page not found")
        .map(|i| low[i..].contains("azure front door"))
        .unwrap_or(false);
    if low.contains("our services aren't available right now") || pnf {
        return Some("Azure Front Door 錯誤頁".into());
    }
    None
}

impl Cdn {
    /// 某家 CDN 的候選台灣節點
    async fn target_ips(&self, target: &str, name: &str) -> Vec<IpAddr> {
        if target == "akamai" {
            // 網站有放在 Akamai 才會有 <網域>.edgekey.net / .edgesuite.net；帶台灣網段去問，拿台灣節點
            let subnets: Vec<String> = self.ecs_subnets().into_iter().take(2).collect();
            let mut out: Vec<IpAddr> = Vec::new();
            for edge in [format!("{name}.edgekey.net"), format!("{name}.edgesuite.net")] {
                let list: Vec<Option<&str>> = if subnets.is_empty() {
                    vec![None]
                } else {
                    subnets.iter().map(|s| Some(s.as_str())).collect()
                };
                for s in list {
                    let ips = self.resolve_with_ecs(&edge, rtype::A, s).await;
                    for ip in &ips {
                        if !out.contains(ip) {
                            out.push(*ip);
                        }
                    }
                    if !ips.is_empty() {
                        break;
                    }
                }
                if !out.is_empty() {
                    break;
                }
            }
            if out.is_empty() {
                return vec![];
            }
            let max = self.cfg.cross.akamai_max_ms;
            return self
                .net
                .rank(&out)
                .await
                .into_iter()
                .filter(|(_, l)| l.ok && l.ms <= max)
                .take(2)
                .map(|x| x.0)
                .collect();
        }
        let st = self.state();
        if !st.pools.has(target) {
            return vec![];
        }
        st.pools.serve_ips(target, 4).into_iter().take(2).collect()
    }

    /// 探索（同 2.x `CrossCdn.explore`）：回傳 ok / fail / none
    pub async fn cross_explore(self: &Arc<Self>, name: &str, from: &str, orig: IpAddr) -> &'static str {
        if !orig.is_ipv4() {
            return "none";
        }
        let timeout = Duration::from_millis(self.cfg.verify_timeout_ms);
        let opts = HttpsOpts {
            timeout,
            max_body: 65536,
            ..Default::default()
        };
        let now = now_ms();
        self.with_state(|st| st.cross_explored += 1);
        let base = self.net.https_probe(orig, name, "/", opts.clone()).await;
        if !base.ok {
            self.with_state(|st| {
                st.db.set_cross(
                    name,
                    Cross {
                        verdict: Some(intern("none")),
                        from: Some(intern(from)),
                        reason: Some(format!("原站無法用 HTTPS 連線（{}）", base.error.as_deref().unwrap_or(""))),
                        until: Some(now + 6 * HOUR_MS),
                        ..Default::default()
                    },
                )
            });
            return "none";
        }
        let orig_q = self
            .net
            .quality(orig, 3, Duration::from_millis(1500), Duration::from_millis(50))
            .await;
        let mut tried: Vec<Tried> = Vec::new();
        let mut ok_list: Vec<(String, Vec<IpAddr>, f64)> = Vec::new();
        // 社群好友試過這個網站可以換到哪一家：那一家先試，並帶上好友驗證過的 IP
        let hint = self.hints().and_then(|h| h.cross_hint(name));
        let mut order: Vec<&str> = TARGETS.to_vec();
        if let Some(h) = hint.as_ref().filter(|h| TARGETS.contains(&h.to.as_str())) {
            order.retain(|t| *t != h.to);
            order.insert(0, TARGETS.iter().find(|t| **t == h.to).unwrap());
        }
        for to in order {
            if to == from {
                continue;
            }
            let prov = providers::get(to);
            let mut ips = self.target_ips(to, name).await;
            if let Some(h) = hint.as_ref().filter(|h| h.to == to) {
                let mut l: Vec<IpAddr> = h.ips.iter().map(|x| x.ip).collect();
                for ip in ips {
                    if !l.contains(&ip) {
                        l.push(ip);
                    }
                }
                l.truncate(3);
                ips = l;
            }
            if ips.is_empty() {
                tried.push(Tried {
                    to: intern(to),
                    reason: Some(
                        if to == "akamai" {
                            "沒有 Akamai 設定"
                        } else {
                            "沒有台灣節點"
                        }
                        .into(),
                    ),
                    ..Default::default()
                });
                continue;
            }
            let mut pass = Vec::new();
            let mut why: Option<String> = None;
            for ip in ips {
                let r = self.net.https_probe(ip, name, "/", opts.clone()).await;
                if !r.ok {
                    why = Some(if r.tls_error {
                        "憑證不符（這家沒有放這個網站）".into()
                    } else {
                        format!("連線失敗 {}", r.error.as_deref().unwrap_or(""))
                    });
                    continue;
                }
                if to != "akamai" {
                    if let Some(p) = prov {
                        if p.is_provider(&r.headers) == Some(false) {
                            why = Some(format!("回應不是 {}", p.label));
                            continue;
                        }
                    }
                }
                if let Some(b) = cross_broken(to, &r) {
                    why = Some(b);
                    continue;
                }
                if let Some(d) = same_site(&base, &r) {
                    why = Some(d);
                    continue;
                }
                pass.push(ip);
            }
            if pass.is_empty() {
                tried.push(Tried {
                    to: intern(to),
                    reason: Some(why.unwrap_or_else(|| "不可用".into())),
                    ..Default::default()
                });
                continue;
            }
            let q = self
                .net
                .quality(pass[0], 3, Duration::from_millis(1500), Duration::from_millis(50))
                .await;
            tried.push(Tried {
                to: intern(to),
                ok: Some(true),
                ms: if q.ms.is_finite() {
                    Num::V(util::round(q.ms, 1))
                } else {
                    Num::Null
                },
                ..Default::default()
            });
            ok_list.push((to.to_string(), pass, q.ms));
        }
        ok_list.sort_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal));
        if let (Some(h), Some(hs)) = (hint.as_ref(), self.hints()) {
            let passed: Vec<IpAddr> = ok_list.iter().find(|o| o.0 == h.to).map(|o| o.1.clone()).unwrap_or_default();
            for x in &h.ips {
                hs.hint_result(&x.from, passed.contains(&x.ip));
            }
        }
        let min_gain = self.cfg.nearest_min_gain_ms;
        let orig_ms = orig_q.ms.is_finite().then(|| util::round(orig_q.ms, 1));
        if let Some(best) = ok_list.first().filter(|b| orig_ms.map(|o| b.2 + min_gain <= o).unwrap_or(true)) {
            let also: Vec<String> = ok_list[1..].iter().map(|o| o.0.clone()).collect();
            let (to, ips, ms) = best.clone();
            self.with_state(|st| {
                st.cross_ok += 1;
                st.db.set_cross(
                    name,
                    Cross {
                        verdict: Some(intern("ok")),
                        from: Some(intern(from)),
                        to: Some(intern(&to)),
                        ips: Some(ips),
                        ms: Num::of(util::round(ms, 1)),
                        orig_ms: Num::opt(orig_ms),
                        orig_ip: Some(orig),
                        also: Some(also),
                        tried: Some(tried),
                        until: Some(now + 3 * DAY_MS),
                        recheck_at: Some(now + (self.cfg.cross.recheck_hours * HOUR_MS as f64) as u64),
                        ..Default::default()
                    },
                )
            });
            info!(
                "⇄ {name}：{} → {} 台灣節點可用（{:.0}ms，原本 {}ms）",
                providers::label(from),
                providers::label(&to),
                ms,
                orig_ms.map(|m| m.to_string()).unwrap_or_else(|| "?".into())
            );
            return "ok";
        }
        let om = orig_ms.map(|m| m.to_string()).unwrap_or_else(|| "null".into());
        let reason = match ok_list.first() {
            Some(b) => format!("{} 可用但沒有比較快（{:.0}ms／原本 {om}ms）", providers::label(&b.0), b.2),
            None => "其他 CDN 都沒有這個網站".into(),
        };
        // 大網站簽哪幾家 CDN 很少變動：失敗幾天後再試
        self.with_state(|st| {
            st.db.set_cross(
                name,
                Cross {
                    verdict: Some(intern("fail")),
                    from: Some(intern(from)),
                    reason: Some(reason),
                    orig_ms: Num::opt(orig_ms),
                    tried: Some(tried),
                    until: Some(now + (self.cfg.cross.fail_days * DAY_MS as f64) as u64),
                    ..Default::default()
                },
            )
        });
        "fail"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn html(t: &str, st: u16, h: &[(&str, &str)]) -> ProbeResult {
        let mut headers = vec![("content-type".to_string(), "text/html; charset=utf-8".to_string())];
        headers.extend(h.iter().map(|(k, v)| (k.to_string(), v.to_string())));
        ProbeResult {
            ok: true,
            status: st,
            ms: 30.0,
            headers,
            body: format!("<html><head><title>{t}</title></head></html>"),
            ..Default::default()
        }
    }

    #[test]
    fn same_site_checks() {
        // 對照 2.x selftest「判斷是不是同一個網站：狀態碼、轉址目的地、標題」
        assert_eq!(same_site(&html("X", 200, &[]), &html("X", 200, &[])), None);
        assert!(same_site(&html("X", 200, &[]), &html("X", 403, &[])).is_some());
        assert!(same_site(&html("X", 200, &[]), &html("Cloudflare", 200, &[])).is_some());
        assert_eq!(
            same_site(
                &html("", 301, &[("location", "https://x.com/home")]),
                &html("", 302, &[("location", "https://x.com/home")])
            ),
            None
        );
        assert!(same_site(
            &html("", 301, &[("location", "https://x.com/home")]),
            &html("", 301, &[("location", "https://www.cloudflare.com/")])
        )
        .is_some());
        assert_eq!(title("<TITLE lang=x>\n  A   B \n</Title>"), Some("A B".into()));
        assert_eq!(title("<title></title>"), None);
        assert_eq!(loc_of(&[("location".into(), "/a/b?x=1".into())]), "x.invalid/a/b");
        assert_eq!(loc_of(&[("location".into(), "HTTPS://X.com:443/p#f".into())]), "x.com/p");
    }

    #[test]
    fn broken_pages() {
        // 對照 2.x selftest「認得各家 CDN「沒有這個網站」的錯誤頁」
        let r = |st: u16, h: &[(&str, &str)], body: &str| ProbeResult {
            ok: true,
            status: st,
            headers: h.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            body: body.into(),
            ..Default::default()
        };
        assert!(cross_broken("akamai", &r(400, &[], "<h1>Invalid URL</h1> Reference&#32;&#35;9.1234")).is_some());
        assert!(cross_broken("cloudflare", &r(403, &[("cf-ray", "x-TPE")], "error code: 1001")).is_some());
        assert_eq!(cross_broken("cloudflare", &html("X", 200, &[])), None);
        assert!(cross_broken("azure", &r(404, &[], "<h2>Page not found</h2>\n... Azure Front Door ...")).is_some());
        assert!(cross_broken("akamai", &r(403, &[], "Access Denied ... Reference #18.abc")).is_some());
    }
}
