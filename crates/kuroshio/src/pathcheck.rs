//! 路徑檢查的排程（3.3.6；檢查本身在 `kuroshio_net::path`）：
//! 啟動後、每 6 小時、WAN 變動（`kuroshio notify wan-changed`）時各做一次，結果套用到連線層
//! （IPv6、bootstrap、被擋的協定），`/api/status` 的 `network.path` 看得到。
//! 每日評測在子程序裡會自己再做一次（評測前的狀況才準）。

use kuroshio_config::get;
use kuroshio_net::path::{self, Report, Targets, V6Mode};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{OnceLock, RwLock};
use std::time::Duration;
use tokio::sync::Notify;
use tracing::{info, warn};

/// 定期檢查的間隔
const INTERVAL: Duration = Duration::from_secs(6 * 3600);
/// 有協定被判定整條被擋時，較快再檢查一次（被擋的那種上游在這段時間不用，恢復要快）
const RECHECK_BLOCKED: Duration = Duration::from_secs(3600);
/// 啟動後多久做第一次（讓監聽、bootstrap 先就緒）
const FIRST_DELAY: Duration = Duration::from_secs(8);

#[derive(Debug, Clone)]
struct Settings {
    enabled: bool,
    policy: &'static str,
}

static SETTINGS: RwLock<Option<Settings>> = RwLock::new(None);
static RUNNING: AtomicBool = AtomicBool::new(false);

fn wake() -> &'static Notify {
    static N: OnceLock<Notify> = OnceLock::new();
    N.get_or_init(Notify::new)
}

/// `upstream.interceptPolicy`
pub fn policy_of(cfg: &Value) -> &'static str {
    match get(cfg, "upstream.interceptPolicy").and_then(Value::as_str).unwrap_or("") {
        "warn" => "warn",
        "ignore" => "ignore",
        _ => "skip-plain",
    }
}

pub fn enabled_of(cfg: &Value) -> bool {
    get(cfg, "upstream.pathCheck").and_then(Value::as_bool) != Some(false)
}

/// 讀設定（啟動與每次重新載入）：IPv6 模式立刻生效；路徑檢查關閉時清掉舊的判斷
pub fn configure(cfg: &Value) {
    path::set_v6_mode(V6Mode::from_value(get(cfg, "upstream.ipv6")));
    let s = Settings {
        enabled: enabled_of(cfg),
        policy: policy_of(cfg),
    };
    if !s.enabled {
        path::clear();
    } else if let Some(r) = path::current() {
        // 攔截政策改了：用上一次的結果重新套用
        path::apply(&r, s.policy == "ignore");
    }
    *SETTINGS.write().unwrap() = Some(s);
}

fn settings() -> Settings {
    SETTINGS.read().unwrap().clone().unwrap_or(Settings {
        enabled: true,
        policy: "skip-plain",
    })
}

/// 立刻再檢查一次（WAN 變動）
pub fn trigger() {
    wake().notify_one();
}

/// 做一次檢查並套用；跟上一次不同時記一行
pub async fn run_once() -> Option<Report> {
    let s = settings();
    if !s.enabled {
        return None;
    }
    if RUNNING.swap(true, Ordering::SeqCst) {
        return path::current();
    }
    let before = path::current().map(|r| path::summary(&r));
    let r = path::check(&Targets::default()).await;
    path::apply(&r, s.policy == "ignore");
    RUNNING.store(false, Ordering::SeqCst);
    let now = path::summary(&r);
    if before.as_deref() != Some(now.as_str()) {
        info!("路徑檢查：{now}");
        for w in r.warnings(s.policy) {
            warn!("路徑檢查：{w}");
        }
    }
    Some(r)
}

/// 背景排程（每次建立 runtime 時呼叫一次；runtime 結束時跟著結束）
pub fn spawn() {
    tokio::spawn(async move {
        tokio::time::sleep(FIRST_DELAY).await;
        loop {
            crate::clock::wait_synced().await;
            let r = run_once().await;
            let wait = if r.as_ref().is_some_and(|r| !r.blocked.is_empty()) {
                RECHECK_BLOCKED
            } else {
                INTERVAL
            };
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = wake().notified() => {
                    // WAN 剛變動：等幾秒讓路由與位址就緒
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    });
}

/// `/api/status` 的 `network.path`
pub fn status_json() -> Value {
    let s = settings();
    match path::current() {
        Some(r) => {
            let mut j = r.to_json();
            j["policy"] = json!(s.policy);
            j["enabled"] = json!(s.enabled);
            j["summary"] = json!(path::summary(&r));
            j["warnings"] = json!(r.warnings(s.policy));
            j
        }
        None => json!({
            "enabled": s.enabled,
            "policy": s.policy,
            "checkedAt": null,
            "ipv6": { "mode": path::v6_mode().as_str(), "usable": path::v6_usable() },
            "warnings": [],
        }),
    }
}

/// 給 `/api/status` 的 `warnings`
pub fn warnings() -> Vec<String> {
    let s = settings();
    path::current().map(|r| r.warnings(s.policy)).unwrap_or_default()
}
