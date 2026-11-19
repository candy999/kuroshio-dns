//! 路徑檢查的排程（3.3.6；檢查本身在 `kuroshio_net::path`）：
//! 啟動後、每 6 小時、WAN 變動（`kuroshio notify wan-changed`）時各做一次，結果套用到連線層
//! （IPv6、bootstrap、被擋的協定），`/api/status` 的 `network.path` 看得到。
//! 每日評測在子程序裡會自己再做一次（評測前的狀況才準）。

use kuroshio_config::get;
use kuroshio_net::path::{self, Report, Targets, V6Mode};
use serde_json::{json, Value};
use std::net::SocketAddr;
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
    // 跟 ChainSettings 同一套讀法：布林、"0"／"1"、數字都接受
    kuroshio_config::chain::flex_bool(get(cfg, "upstream.pathCheck"), true).0
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

/// 路徑檢查有沒有開（`upstream.pathCheck`）
pub fn enabled() -> bool {
    settings().enabled
}

/// 立刻再檢查一次（WAN 變動）
pub fn trigger() {
    wake().notify_one();
}

/// 測試用的目標覆寫（環境變數 `KUROSHIO_PATH_TARGETS`，只給整合測試用，不是給使用者的穩定介面）：
///
/// `{"testnetV4":["127.0.0.1:5301"],"testnetV6":[],"gateway":"127.0.0.1:5301"|null,"encrypted":false}`
///
/// - `encrypted: false`：DoT／DoH／QUIC 的目標清空（不連外；沒有目標時不判斷協定被擋、也不算離線）
/// - `gateway`：串接驗證時「直連閘道」的位址（含埠）；`null` = 沒有閘道。覆寫時不讀系統的預設閘道
/// - 已知答案的名稱清空、一般 DNS 伺服器改成保留位址（測試不連外）
struct Override {
    targets: Targets,
    gateway: Option<SocketAddr>,
}

fn overrides() -> Option<&'static Override> {
    static O: OnceLock<Option<Override>> = OnceLock::new();
    O.get_or_init(|| {
        let raw = std::env::var("KUROSHIO_PATH_TARGETS").ok().filter(|s| !s.trim().is_empty())?;
        match parse_override(&raw) {
            Ok(o) => {
                warn!("路徑檢查：使用測試用的目標覆寫（KUROSHIO_PATH_TARGETS）");
                Some(o)
            }
            Err(e) => {
                warn!("路徑檢查：KUROSHIO_PATH_TARGETS 格式不對（{e}），不使用");
                None
            }
        }
    })
    .as_ref()
}

fn parse_override(raw: &str) -> Result<Override, String> {
    let v: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    let addrs = |k: &str| -> Result<Vec<SocketAddr>, String> {
        v.get(k)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|x| {
                        x.as_str()
                            .and_then(|s| s.parse().ok())
                            .ok_or_else(|| format!("{k} 的位址格式不對：{x}"))
                    })
                    .collect()
            })
            .unwrap_or(Ok(Vec::new()))
    };
    let mut t = Targets {
        testnet_v4: addrs("testnetV4")?,
        testnet_v6: addrs("testnetV6")?,
        known: Vec::new(),
        read_gateway: false,
        ..Targets::default()
    };
    t.plain = t.testnet_v4.clone();
    if v.get("encrypted").and_then(Value::as_bool) == Some(false) {
        t.dot.clear();
        t.doh.clear();
        t.quic.clear();
    }
    if let Some(ms) = v.get("plainTimeoutMs").and_then(Value::as_u64) {
        t.plain_timeout = Duration::from_millis(ms);
    }
    let gateway = match v.get("gateway") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.parse().map_err(|_| format!("gateway 的位址格式不對：{s}"))?),
        Some(x) => return Err(format!("gateway 的格式不對：{x}")),
    };
    Ok(Override { targets: t, gateway })
}

/// 路徑檢查的目標：預設 `Targets::default()`；測試用環境變數覆寫（見 [`Override`]）
pub fn targets() -> Targets {
    overrides().map(|o| o.targets.clone()).unwrap_or_default()
}

/// 串接驗證時「直連閘道」的覆寫：`None` = 沒有覆寫（用路徑檢查讀到的預設閘道）；
/// `Some(None)` = 覆寫成沒有閘道；`Some(Some(位址))` = 用這個位址（含埠，不檢查是不是私有位址）
pub fn gateway_override() -> Option<Option<SocketAddr>> {
    overrides().map(|o| o.gateway)
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
    let r = path::check(&targets()).await;
    path::apply(&r, s.policy == "ignore");
    RUNNING.store(false, Ordering::SeqCst);
    let now = path::summary(&r);
    if before.as_deref() != Some(now.as_str()) {
        info!("路徑檢查：{now}");
        for w in r.warnings(s.policy) {
            warn!("路徑檢查：{w}");
        }
    }
    // 串接模式（3.4.0）：接在路徑檢查之後，不是另一個排程
    if let Some(c) = crate::chain::current() {
        c.on_path_report(&r).await;
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
            j["warnings"] = json!(chain_filter(r.warnings(s.policy)));
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
    chain_filter(path::current().map(|r| r.warnings(s.policy)).unwrap_or_default())
}

/// 「一般 DNS 被…接走」那一條提醒（`Report::warnings` 的第一條）
pub fn is_intercept_warning(w: &str) -> bool {
    w.starts_with("一般 DNS") && w.contains("接走")
}

/// 串接中（3.4.0）：一般 DNS 被上游黑潮接走是預期中的狀況，不列提醒（改由串接狀態說明）
fn chain_filter(mut w: Vec<String>) -> Vec<String> {
    if crate::chain::current().is_some_and(|c| c.is_chained()) {
        w.retain(|x| !is_intercept_warning(x));
    }
    w
}
