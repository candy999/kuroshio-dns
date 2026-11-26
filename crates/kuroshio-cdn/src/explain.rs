//! 「為什麼沒換到台灣」說明（3.5.0，規格 11 B7）：管理 API 查一個網域：哪家 CDN、換或不換的原因、驗證結果。
//!
//! **只讀**：不 `touch()`、不增加 `hits`、不排任何背景工作、不發網路請求（要重新驗證用 `POST /api/cdn/verify`）。
//! 被記憶體控制移到磁碟的冷資料會讀回來再回答（這是管理 API，不是查詢路徑）。

use crate::cdn::Cdn;
use crate::db::{Domain, Policy, Verdict};
use crate::providers;
use crate::util::now_ms;
use serde_json::{json, Value};

/// 決定的代碼（介面依代碼顯示；`text` 是核心給的白話）
pub mod decision {
    pub const REWRITTEN: &str = "rewritten";
    pub const ALREADY_TW: &str = "already-tw";
    pub const TRIAL: &str = "trial";
    pub const LITE_WAITING: &str = "lite-waiting";
    /// 新網域很多（驗證減量中）：只問過一次的網域先不驗證（3.5.0 F12）
    pub const PACED_WAITING: &str = "paced-waiting";
    pub const VERIFY_FAILED: &str = "verify-failed";
    /// 驗證通過過，但驗證過的節點已經不在節點池（或被暫停）：先回原本的答案（TTL 10 秒），下次查詢重新驗證（3.5.1 M1）
    pub const POOL_CHANGED: &str = "pool-changed";
    /// 台灣節點能用，但握手連續兩次比原本的答案慢：暫時用原本的答案（3.5.0 E7；F9 起比握手時間）
    pub const SLOWER: &str = "slower";
    pub const NO_TW_NODE: &str = "no-tw-node";
    pub const NO_POOL: &str = "no-pool";
    /// 最近節點型（Fastly，在台灣沒有節點）：已經換成驗證過、比原本快的最近節點（3.5.1 M5）
    pub const NEAREST: &str = "nearest";
    pub const CROSS: &str = "cross";
    pub const ECS: &str = "ecs";
    pub const POLICY_NEVER: &str = "policy-never";
    pub const POLICY_ALWAYS: &str = "policy-always";
    /// 網站自己在多家 CDN 之間分流：不替它換到別家（3.5.0 B3）
    pub const MULTI_CDN: &str = "multi-cdn";
    /// App 自己選節點的服務：只辨識、不改寫（3.5.0 B3）
    pub const APP_LAYER: &str = "app-layer";
    /// 內建一定通過的服務（時間同步、連線偵測、憑證撤銷、地震速報）：不改寫、不擋（3.5.0 F11）
    pub const ESSENTIAL: &str = "essential";
    /// 業者專用 IP（GitHub Pages 這類）：只有那幾個位址服務它，照原本的答案（3.5.1 K2）
    pub const DEDICATED: &str = "dedicated-ip";
    pub const CHAINED: &str = "chained";
    pub const CDN_DISABLED: &str = "cdn-disabled";
    pub const MEMORY_FLOOR: &str = "memory-floor";
    pub const NOT_CDN: &str = "not-cdn";
    pub const UNKNOWN: &str = "unknown";
}
use decision as d;

/// 這台目前的情況（由呼叫端給：串接中、記憶體最低限度暫停 CDN）
#[derive(Debug, Clone, Copy, Default)]
pub struct Context {
    /// 串接中：答案由上游黑潮換好，這台不做 CDN 處理（3.4.1）
    pub chained: bool,
    /// 記憶體控制的最低限度：暫停 CDN 調整
    pub suspended: bool,
}

/// 一句白話（文字集中在這裡，之後跟介面一起調）
pub fn text_of(decision: &str, label: &str, detail: &str) -> String {
    let detail = if detail.is_empty() {
        String::new()
    } else {
        format!("（{detail}）")
    };
    match decision {
        d::REWRITTEN => format!("這個網域用 {label}，已經換成驗證過的台灣節點{detail}。"),
        d::ALREADY_TW => format!("這個網域用 {label}，原本的答案就是台灣節點，不用換{detail}。"),
        d::TRIAL => format!("這個網域用 {label}，台灣節點還在驗證中（試用期先回原本的答案，TTL 10 秒）{detail}。"),
        d::LITE_WAITING => format!("這個網域用 {label}；這台是小記憶體減量模式，問過 2 次以上才驗證台灣節點，現在先回原本的答案。"),
        d::PACED_WAITING => format!("這個網域用 {label}；新網域很多（或 CPU 很忙），CDN 驗證減量中，問過 2 次以上才驗證台灣節點，現在先回原本的答案。"),
        d::POOL_CHANGED => format!("這個網域用 {label}，驗證過的節點已不在節點池，下次查詢重新驗證（這段期間先回原本的答案，TTL 10 秒）{detail}。"),
        d::VERIFY_FAILED => format!("這個網域用 {label}，台灣節點驗證沒通過，暫時用原本的答案{detail}；到期後會重新驗證。"),
        d::SLOWER => slower_text(label, &detail, crate::reach::SLOWER_RETEST_MS / 60_000),
        d::NO_TW_NODE => format!("這個網域用 {label}，找不到可用的台灣節點，跨 CDN 也沒有可用的替代{detail}。"),
        d::NO_POOL if !detail.is_empty() => format!("這個網域用 {label}，但這台的 {label} 台灣節點池{detail}，先用原本的答案。"),
        d::NO_POOL => format!("這個網域用 {label}，但這台還沒有 {label} 的台灣節點池（節點池工作還沒跑完），先用原本的答案。"),
        d::NEAREST => format!("這個網域用 {label}（在台灣沒有節點），已經換成驗證過、比原本快的最近節點{detail}。"),
        d::CROSS => format!("這個網域用 {label}，同一個網站也放在別家 CDN 上，已經換成那家的台灣節點{detail}。"),
        d::ECS => format!("這個網域用 {label}（依查詢來源分流），已經帶台灣網段問到台灣節點{detail}。"),
        d::POLICY_NEVER => "這個網域被手動設成「不換」，照原本的答案。".into(),
        d::POLICY_ALWAYS => format!("這個網域被手動設成「一定換」，有 {label} 的台灣節點就換。"),
        d::MULTI_CDN => format!("這個網站自己在多家 CDN 之間分流（這次是 {label}）{detail}。黑潮不替它換到別家；回答來自驗證過的那一家時照常換成那一家的台灣節點。"),
        d::APP_LAYER => format!("這個網域用 {label}，節點由 App 或服務自己選（影音、系統更新這類），黑潮只辨識、不改寫。要換可以把這個網域手動設成「一定換」。"),
        d::ESSENTIAL => format!("這個網域是內建的{label}服務：不改寫、不擋。"),
        d::DEDICATED => format!("這個網域用 {label} 的業者專用 IP（例如 GitHub Pages），別的節點不服務它，照原本的答案。"),
        d::CHAINED => "串接中：答案由上游黑潮換好台灣節點，這台不再做 CDN 處理。".into(),
        d::CDN_DISABLED => "這台沒有開 CDN 台灣節點。".into(),
        d::MEMORY_FLOOR => "記憶體控制的最低限度：暫停 CDN 調整，照原本的答案。".into(),
        d::NOT_CDN => "資料庫裡有這個網域，但不是認得的 CDN。".into(),
        _ => "這個網域還沒有人查過，或不是 CDN 網域（查過一次之後才有紀錄）。".into(),
    }
}

/// `slower` 的白話（3.5.0 F9；`cdn.lite` 是 60 分鐘）。`detail` 已經加上括號
fn slower_text(label: &str, detail: &str, minutes: u64) -> String {
    format!("這個網域用 {label}，台灣節點能用，但握手連續兩次比原本的答案慢{detail}，暫時用原本的答案；{minutes} 分鐘後有人查再重驗。")
}

/// 上一次驗證握手比原本慢、還沒確認時，`rewritten` 多的一句（3.5.0 F9）
pub const SLOW1_NOTE: &str = "上一次驗證握手比原本慢，再確認一次才會退回。";

/// 內建服務的類別（3.5.0 F11）
fn essential_label(kind: Option<kuroshio_net::comm::CommKind>) -> &'static str {
    use kuroshio_net::comm::CommKind as K;
    match kind {
        Some(K::Ntp) => "時間同步",
        Some(K::NetCheck) => "連線偵測",
        Some(K::Revocation) => "憑證撤銷",
        Some(K::Quake) => "地震速報",
        Some(K::Update) => "系統與安全更新",
        _ => "一定通過的",
    }
}

/// 驗證結果的一步（`v4`／`v6`）
fn verdict_step(what: &str, v: Option<&Verdict>, now: u64) -> Value {
    match v {
        None => json!({ "what": what, "result": "none" }),
        Some(v) => {
            let mut j = json!({
                "what": what,
                "result": if !v.valid(now) { "expired" } else { v.verdict.as_deref().unwrap_or("none") },
                "verdict": v.verdict.as_deref(),
                "pop": v.pop.as_deref(), "ms": v.ms.get(), "reason": v.reason, "at": v.at, "until": v.until,
            });
            // 比原本慢（3.5.0 E7）：兩邊的握手時間（毫秒；3.5.0 F9 起不含 TTFB）
            if is_slower(v) {
                j["slower"] = json!(true);
                j["score"] = v.extra.get("score").cloned().unwrap_or(Value::Null);
                j["origScore"] = v.extra.get("origScore").cloned().unwrap_or(Value::Null);
            }
            // 第一次慢、還沒確認（3.5.0 F9）：`{ at, score, origScore }`
            if let Some(x) = v.extra.get(crate::verifier::SLOW1) {
                j["slow1"] = x.clone();
            }
            // 原本的答案已經在台灣機房、不換（3.5.1）：那時量到的 POP
            if let Some(p) = crate::verifier::orig_tw_pop(v) {
                j["origTw"] = json!(p);
            }
            // 最近節點型換到同一個 POP 不算改善、不換（3.5.1 L11）
            if let Some(p) = crate::verifier::same_pop_of(v) {
                j["samePop"] = json!(p);
            }
            j
        }
    }
}

fn is_slower(v: &Verdict) -> bool {
    v.extra.get(crate::verifier::SLOWER).and_then(Value::as_bool) == Some(true)
}

/// 最近一次答案（`ips4`）裡這家 CDN、需要換的 IP（節點池的分類是 `Global`／`Unknown`；同 `alias_family()` 的 `needs`）
fn needs_of(pools: &crate::pools::Pools, e: &Domain, provider: &str) -> Vec<std::net::IpAddr> {
    e.ips4
        .iter()
        .copied()
        .filter(|ip| {
            pools
                .classify(*ip)
                .is_some_and(|c| c.provider == provider && matches!(c.cls, crate::Cls::Global | crate::Cls::Unknown))
        })
        .collect()
}

/// 最近一次答案（`ips4`）裡這家 CDN 的 IP 是不是都已經是台灣節點（或 Dead）：跟 `alias_family()` 同一個判斷
/// （節點池的分類 `Tw`／`Dead` 不換，`Global`／`Unknown` 才換）。這家的 IP 一個都沒有（舊資料、別家的答案）回 None
fn answer_tw(pools: &crate::pools::Pools, e: &Domain, provider: &str) -> Option<bool> {
    let mut any = false;
    for c in e
        .ips4
        .iter()
        .filter_map(|ip| pools.classify(*ip))
        .filter(|c| c.provider == provider)
    {
        if matches!(c.cls, crate::Cls::Global | crate::Cls::Unknown) {
            return Some(false);
        }
        any = true;
    }
    any.then_some(true)
}

impl Cdn {
    /// `GET /api/cdn/explain?name=`：這個網域換或不換台灣節點、為什麼（只讀）
    pub fn explain(&self, name: &str, ctx: Context) -> Value {
        let name = crate::cdn::normalize(name);
        let now = now_ms();
        let base = |decision: &str, label: &str, detail: &str| json!({ "name": name, "decision": decision, "text": text_of(decision, label, detail) });
        if !self.cfg.enabled {
            return base(d::CDN_DISABLED, "", "");
        }
        // 內建服務（3.5.0 F11）：apply() 不記進資料庫，這裡也不看資料庫
        if crate::cdn::keep_untouched(&name) {
            let kind = kuroshio_net::comm::kind_of(&name);
            let mut v = base(d::ESSENTIAL, essential_label(kind), "");
            v["known"] = json!(true);
            v["essential"] = json!(kind.map(|k| k.as_str()));
            return v;
        }
        // 冷資料讀回來（只讀：讀回來不算「用過」）
        self.ensure_loaded(&name);
        let st = self.state();
        let Some(e) = st.db.get(&name) else {
            let mut v = base(d::UNKNOWN, "", "");
            v["known"] = json!(false);
            return v;
        };
        let Some(provider) = e.provider().map(str::to_string) else {
            let mut v = base(d::NOT_CDN, "", "");
            v["known"] = json!(true);
            return v;
        };
        let prov = providers::get(&provider);
        let label = prov.map(|p| p.label.to_string()).unwrap_or_else(|| provider.clone());
        let (decision, detail) = if ctx.chained {
            (d::CHAINED, String::new())
        } else if ctx.suspended {
            (d::MEMORY_FLOOR, String::new())
        } else {
            self.decide(&st.pools, e, &provider, now)
        };
        let mut v = base(decision, &label, &detail);
        if decision == d::SLOWER && self.cfg.lite {
            let detail = if detail.is_empty() {
                String::new()
            } else {
                format!("（{detail}）")
            };
            v["text"] = json!(slower_text(&label, &detail, crate::reach::SLOWER_RETEST_LITE_MS / 60_000));
        }
        // 第一次慢、還沒確認：決定照舊是換台灣節點，多一句說明（3.5.0 F9）
        if decision == d::REWRITTEN
            && e.v4
                .as_deref()
                .and_then(crate::verifier::slow1_at)
                .is_some_and(|at| now.saturating_sub(at) <= crate::reach::SLOWER_FIRST_TTL_MS)
        {
            v["text"] = json!(format!("{}{SLOW1_NOTE}", v["text"].as_str().unwrap_or("")));
        }
        v["known"] = json!(true);
        v["provider"] = json!(provider);
        v["providerLabel"] = json!(label);
        v["via"] = json!(e.via.val().map(|a| &**a));
        v["cname"] = json!(e.cname.val());
        v["policy"] = json!(e.policy().as_str());
        v["hits"] = json!(e.hits);
        v["best"] = json!(e.best.map(|s| s.as_str()));
        v["c1"] = json!(e.c1.as_deref());
        v["multi"] = json!(e.multi(now));
        v["provs"] = e
            .provs()
            .into_iter()
            .map(|(p, t, slot)| json!({ "provider": p, "lastSeen": t, "verified": slot }))
            .collect();
        let mut steps = vec![verdict_step("v4", e.v4.as_deref(), now), verdict_step("v6", e.v6.as_deref(), now)];
        if let Some(x) = e.ecs.as_deref() {
            steps.push(
                json!({ "what": "ecs", "result": x.verdict.as_deref().unwrap_or("none"), "reason": x.reason,
                               "gainMs": x.gain_ms.get(), "at": x.at, "until": x.until }),
            );
        }
        if let Some(x) = e.cross4.as_deref() {
            steps.push(
                json!({ "what": "cross", "result": Cdn::cross_state(Some(e), now), "to": x.to.as_deref(),
                               "ms": x.ms.get(), "origMs": x.orig_ms.get(), "score": x.score.get(), "origScore": x.orig_score.get(),
                               "reason": x.reason, "at": x.at, "until": x.until }),
            );
        }
        v["steps"] = Value::Array(steps);
        // 多來源（3.5.1 M5）：另一家的那一格也說明——查詢路徑依這次回答的業者用那一家的驗證結果
        // （以前只看目前這一格，例如這一格是只辨識的業者，就說「只辨識不改寫」，回答換成另一家時其實會換）
        if !ctx.chained && !ctx.suspended {
            if let Some(alt) = e.alt_view().filter(|a| now.saturating_sub(a.last_seen) < crate::db::MULTI_KEEP_MS) {
                if let Some(ap) = alt.provider().map(str::to_string) {
                    let alabel = providers::get(&ap).map(|p| p.label.to_string()).unwrap_or_else(|| ap.clone());
                    let (ad, adetail) = self.decide(&st.pools, &alt, &ap, now);
                    let atext = text_of(ad, &alabel, &adetail);
                    if ad != decision {
                        v["text"] = json!(format!("{}回答來自 {alabel} 時：{atext}", v["text"].as_str().unwrap_or("")));
                    }
                    v["alt"] = json!({
                        "provider": ap, "providerLabel": alabel, "decision": ad, "text": atext, "lastSeen": alt.last_seen,
                        "steps": [verdict_step("v4", alt.v4.as_deref(), now), verdict_step("v6", alt.v6.as_deref(), now)],
                    });
                }
            }
        }
        v
    }

    /// 依資料庫紀錄判斷（跟 `apply_locked` 的順序一致：手動策略 → 跨 CDN 最佳 → IP 置換型 → ECS 型 → 只能用 CNAME 認的）。
    /// `pools` 由呼叫端拿著狀態鎖時給，這裡不再拿鎖
    fn decide(&self, pools: &crate::pools::Pools, e: &Domain, provider: &str, now: u64) -> (&'static str, String) {
        let has_pool = pools.has(provider);
        let answer_tw = answer_tw(pools, e, provider);
        match e.policy() {
            Policy::Never => return (d::POLICY_NEVER, String::new()),
            Policy::Always => return (d::POLICY_ALWAYS, String::new()),
            Policy::Auto => {}
        }
        if self.cfg.app_layer && providers::get(provider).is_some_and(|p| p.app_layer) {
            return (d::APP_LAYER, String::new());
        }
        // 台灣本地的 CDN（3.5.1）：跟 `apply_locked` 一樣直接當成已是台灣
        if providers::get(provider).is_some_and(|p| p.tw_native) {
            return (d::ALREADY_TW, "台灣本地的 CDN".into());
        }
        // 業者專用 IP（3.5.1 K2）：最近一次答案全部是那幾個位址
        if providers::has_dedicated(provider)
            && (!e.ips4.is_empty() || !e.ips6.is_empty())
            && e.ips4.iter().chain(e.ips6.iter()).all(|ip| providers::dedicated_ip(provider, *ip))
        {
            return (d::DEDICATED, String::new());
        }
        // 多來源：不做跨 CDN。原本要靠跨 CDN 才換得到台灣的情況，說明成「多來源」
        let no_cross = e.no_cross(now);
        let multi_detail = || {
            let others: Vec<String> = e
                .provs()
                .into_iter()
                .filter(|x| x.0 != provider)
                .map(|x| providers::label(&x.0).to_string())
                .collect();
            if others.is_empty() {
                String::new()
            } else {
                format!("另外看過 {}", others.join("、"))
            }
        };
        let cross = if no_cross { "none" } else { Cdn::cross_state(Some(e), now) };
        let cross_detail = || {
            e.cross4
                .as_deref()
                .and_then(|x| x.to.as_deref())
                .map(|t| format!("換到 {}", providers::get(t).map(|p| p.label).unwrap_or(t)))
                .unwrap_or_default()
        };
        if matches!(cross, "ok" | "ok-recheck") && (e.best == Some(crate::db::Strategy::Cross) || Cdn::is_nearest(provider)) {
            return (d::CROSS, cross_detail());
        }
        let alias = providers::get(provider).map(|p| p.alias).unwrap_or(false);
        if alias {
            if !has_pool {
                return (d::NO_POOL, String::new());
            }
            let nearest = Cdn::is_nearest(provider);
            // 最近一次答案的 IP 在節點池裡已經是台灣節點（3.5.1）：查詢路徑（`alias_family()`）在看驗證結果之前
            // 就照原本的答案回（「已是台灣」），不換、不試用、不排驗證，這裡也一樣先判斷
            if answer_tw == Some(true) {
                return (d::ALREADY_TW, String::new());
            }
            // 以下跟 `alias_family()` 的順序一樣（3.5.1 M5）
            let needs = needs_of(pools, e, provider);
            let pool = pools.map_ips(provider, 4, &needs);
            let octet = pools.octet_mode(provider) && !pools.pop_view(provider).pops.is_empty();
            // 節點池建過了，但裡面沒有可用的 v4 節點（例如 Gcore 一個都沒找到）：查詢路徑直接回原本的答案，
            // 不縮短 TTL、不排驗證（以前這裡說「驗證中，TTL 10 秒」）
            if pool.is_empty() && !octet {
                // 最近節點型要回台灣只能靠跨 CDN：多來源時是因為多來源才沒有換
                if nearest && no_cross {
                    return (d::MULTI_CDN, multi_detail());
                }
                return (d::NO_POOL, "目前沒有可用的節點".into());
            }
            // 最近節點型（Fastly）：最近的節點要明顯比原本快才換（以前這裡一律說「找不到台灣節點」，實際有在換）
            if nearest && !needs.is_empty() && !self.nearest_gain(pools, provider, 4, &needs, &pool).0 {
                return if no_cross {
                    (d::MULTI_CDN, multi_detail())
                } else {
                    (d::NO_TW_NODE, "原本的答案已經是最近的節點".into())
                };
            }
            if let Some(v) = e.v4.as_deref().filter(|v| v.valid(now)) {
                if v.is("ok") {
                    // 3.5.1 M1：跟查詢路徑（`serve_pool`）一樣，驗證過的 IP 要現在還能用（仍在節點池、沒被暫停）；
                    // 都不能用時查詢路徑先回原本的答案（TTL 10 秒）、重新驗證
                    if Cdn::verified_ips(pools, provider, 4, v, Some(&needs)).is_empty() {
                        return (d::POOL_CHANGED, String::new());
                    }
                    let detail = match (v.pop.as_deref(), v.ms.get()) {
                        (Some(p), Some(ms)) => format!("{p}，{ms:.0} ms"),
                        (Some(p), None) => p.to_string(),
                        _ => String::new(),
                    };
                    return (if nearest { d::NEAREST } else { d::REWRITTEN }, detail);
                }
                if v.is("fail") && is_slower(v) {
                    let n = |k: &str| {
                        v.extra
                            .get(k)
                            .and_then(Value::as_f64)
                            .map(|x| format!("{x:.0}"))
                            .unwrap_or_else(|| "?".into())
                    };
                    return (d::SLOWER, format!("{} 對 {} 毫秒", n("score"), n("origScore")));
                }
                // 驗證時原本的答案已經落在台灣機房（3.5.1，例如 Azure 原本就是 TPE）：不換
                if v.is("fail") {
                    if let Some(pop) = crate::verifier::orig_tw_pop(v) {
                        return (d::ALREADY_TW, format!("驗證時原本的答案在 {pop}"));
                    }
                    // 最近節點型：原本的答案跟最近的節點在同一個 POP（3.5.1 L11）
                    if let Some(pop) = crate::verifier::same_pop_of(v) {
                        return (d::NO_TW_NODE, format!("原本的答案已經在 {pop}，換到同一個 POP 不會比較近"));
                    }
                    return (d::VERIFY_FAILED, v.reason.clone().unwrap_or_default());
                }
            }
            // 舊資料沒有最近一次答案的 IP 時，才用存著的基準 POP（那可能是很久以前量的）
            if answer_tw.is_none()
                && e.base_ip4().is_some()
                && e.base.as_deref().and_then(|b| b.pop.as_deref()).is_some_and(providers::is_tw_pop)
            {
                return (d::ALREADY_TW, String::new());
            }
            if self.cfg.lite && e.hits < 2 {
                return (d::LITE_WAITING, String::new());
            }
            if e.hits < 2 && self.pacing_first_seen() {
                return (d::PACED_WAITING, String::new());
            }
            return (d::TRIAL, String::new());
        }
        if self.cfg.is_ecs(provider) {
            if let Some(x) = e.ecs.as_deref().filter(|x| x.until.unwrap_or(0) > now) {
                if x.is("ok") {
                    let detail = x
                        .gain_ms
                        .get()
                        .filter(|g| *g > 0.0)
                        .map(|g| format!("快 {g:.0} ms"))
                        .unwrap_or_default();
                    return (d::ECS, detail);
                }
                if matches!(cross, "ok" | "ok-recheck") {
                    return (d::CROSS, cross_detail());
                }
                if no_cross {
                    return (d::MULTI_CDN, multi_detail());
                }
                return (d::NO_TW_NODE, x.reason.clone().unwrap_or_default());
            }
            return (d::TRIAL, String::new());
        }
        // 只能用 CNAME 認出來的 CDN：原本就慢才試跨 CDN
        if no_cross {
            return (d::MULTI_CDN, multi_detail());
        }
        match cross {
            "ok" | "ok-recheck" => (d::CROSS, cross_detail()),
            "none" => (d::TRIAL, String::new()),
            _ => (
                d::NO_TW_NODE,
                e.cross4.as_deref().and_then(|x| x.reason.clone()).unwrap_or_default(),
            ),
        }
    }
}
