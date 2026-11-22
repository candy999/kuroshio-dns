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
    pub const VERIFY_FAILED: &str = "verify-failed";
    pub const NO_TW_NODE: &str = "no-tw-node";
    pub const NO_POOL: &str = "no-pool";
    pub const CROSS: &str = "cross";
    pub const ECS: &str = "ecs";
    pub const POLICY_NEVER: &str = "policy-never";
    pub const POLICY_ALWAYS: &str = "policy-always";
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
        d::VERIFY_FAILED => format!("這個網域用 {label}，台灣節點驗證沒通過，暫時用原本的答案{detail}；到期後會重新驗證。"),
        d::NO_TW_NODE => format!("這個網域用 {label}，找不到可用的台灣節點，跨 CDN 也沒有可用的替代{detail}。"),
        d::NO_POOL => format!("這個網域用 {label}，但這台還沒有 {label} 的台灣節點池（節點池工作還沒跑完），先用原本的答案。"),
        d::CROSS => format!("這個網域用 {label}，同一個網站也放在別家 CDN 上，已經換成那家的台灣節點{detail}。"),
        d::ECS => format!("這個網域用 {label}（依查詢來源分流），已經帶台灣網段問到台灣節點{detail}。"),
        d::POLICY_NEVER => "這個網域被手動設成「不換」，照原本的答案。".into(),
        d::POLICY_ALWAYS => format!("這個網域被手動設成「一定換」，有 {label} 的台灣節點就換。"),
        d::CHAINED => "串接中：答案由上游黑潮換好台灣節點，這台不再做 CDN 處理。".into(),
        d::CDN_DISABLED => "這台沒有開 CDN 台灣節點。".into(),
        d::MEMORY_FLOOR => "記憶體控制的最低限度：暫停 CDN 調整，照原本的答案。".into(),
        d::NOT_CDN => "資料庫裡有這個網域，但不是認得的 CDN。".into(),
        _ => "這個網域還沒有人查過，或不是 CDN 網域（查過一次之後才有紀錄）。".into(),
    }
}

/// 驗證結果的一步（`v4`／`v6`）
fn verdict_step(what: &str, v: Option<&Verdict>, now: u64) -> Value {
    match v {
        None => json!({ "what": what, "result": "none" }),
        Some(v) => json!({
            "what": what,
            "result": if !v.valid(now) { "expired" } else { v.verdict.as_deref().unwrap_or("none") },
            "verdict": v.verdict.as_deref(),
            "pop": v.pop.as_deref(), "ms": v.ms.get(), "reason": v.reason, "at": v.at, "until": v.until,
        }),
    }
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
            self.decide(e, &provider, st.pools.has(&provider), now)
        };
        let mut v = base(decision, &label, &detail);
        v["known"] = json!(true);
        v["provider"] = json!(provider);
        v["providerLabel"] = json!(label);
        v["via"] = json!(e.via.val().map(|a| &**a));
        v["cname"] = json!(e.cname.val());
        v["policy"] = json!(e.policy().as_str());
        v["hits"] = json!(e.hits);
        v["best"] = json!(e.best.map(|s| s.as_str()));
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
                               "ms": x.ms.get(), "origMs": x.orig_ms.get(), "reason": x.reason, "at": x.at, "until": x.until }),
            );
        }
        v["steps"] = Value::Array(steps);
        v
    }

    /// 依資料庫紀錄判斷（跟 `apply_locked` 的順序一致：手動策略 → 跨 CDN 最佳 → IP 置換型 → ECS 型 → 只能用 CNAME 認的）
    /// `has_pool`：這家 CDN 有沒有台灣節點池（呼叫端拿著狀態鎖時算好，這裡不再拿鎖）
    fn decide(&self, e: &Domain, provider: &str, has_pool: bool, now: u64) -> (&'static str, String) {
        match e.policy() {
            Policy::Never => return (d::POLICY_NEVER, String::new()),
            Policy::Always => return (d::POLICY_ALWAYS, String::new()),
            Policy::Auto => {}
        }
        let cross = Cdn::cross_state(Some(e), now);
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
            if Cdn::is_nearest(provider) {
                return (d::NO_TW_NODE, String::new());
            }
            if let Some(v) = e.v4.as_deref().filter(|v| v.valid(now)) {
                if v.is("ok") {
                    let detail = match (v.pop.as_deref(), v.ms.get()) {
                        (Some(p), Some(ms)) => format!("{p}，{ms:.0} ms"),
                        (Some(p), None) => p.to_string(),
                        _ => String::new(),
                    };
                    return (d::REWRITTEN, detail);
                }
                if v.is("fail") {
                    return (d::VERIFY_FAILED, v.reason.clone().unwrap_or_default());
                }
            }
            if e.base.as_deref().and_then(|b| b.pop.as_deref()).is_some_and(providers::is_tw_pop) {
                return (d::ALREADY_TW, String::new());
            }
            if self.cfg.lite && e.hits < 2 {
                return (d::LITE_WAITING, String::new());
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
                return (d::NO_TW_NODE, x.reason.clone().unwrap_or_default());
            }
            return (d::TRIAL, String::new());
        }
        // 只能用 CNAME 認出來的 CDN：原本就慢才試跨 CDN
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
