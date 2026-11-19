//! 下游的串接狀態機：探測、驗證、綁定、心跳（規格 1.4～1.8、1.10）
//!
//! ```text
//! none ──路徑檢查認出黑潮 ≥ 3.4.0──▶ detected ──探測通過──▶ verifying ──通過──▶ chained
//!   ▲                                  │                        │                  │
//!   └──── wan-changed、chain 關 ───────┴──── released（帶原因）◀─┴──── 心跳失敗等 ──┘
//! ```
//!
//! - 狀態都在一個 `Mutex<Inner>` 裡；狀態轉移是純函式 [`step`]（不做網路 IO），IO 在外層執行 [`Io`]
//!   （發挑戰、設定／清除上游），所以狀態機可以不靠網路測。網路 IO 一律不拿著鎖做。
//! - `chain` 關、沒有攔截、攔截者不是黑潮、版本低於 3.4.0：**不發任何 `chain.kuroshio` 查詢**。
//! - 不存檔：綁定與「公鑰換過」的時間只在行程層級的 [`Client`] 裡（跨重新載入、不跨重開機）。
//! - 不用時間戳判斷回應有沒有過期（下游的時鐘可能還沒對時）：只靠一次性的 nonce 與簽章。
//! - 登記（規格 4.2，[`Client::register`]）：探測／驗證／心跳之後，上游 `allow = true` 而且 `caps` 有 `reg` 時送出
//!   （不必等串接成立）；登記失敗不影響串接狀態，只記在 `chain.upstream.registered`。

use crate::chain::ident::NodeKey;
use crate::chain::responder::Responder;
use crate::upstream::Upstream;
use crate::upstreams::Manager;
use kuroshio_community::chain as proto;
use kuroshio_community::chain::RegAck;
use kuroshio_community::envelope::{from_cbor, to_cbor};
use kuroshio_community::identity::fingerprint;
use kuroshio_community::util::{hex, random_bytes, valid_domain};
use kuroshio_config::chain::ChainSettings;
use kuroshio_net::path::{Interceptor, Report};
use serde_json::{json, Value};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Notify;
use tracing::{info, warn};

/// 「上游節點的金鑰換過」的警告留多久
const KEY_CHANGE_WARN_MS: u64 = 24 * 3600 * 1000;

// ---------------- 狀態與原因 ----------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    None,
    Detected,
    Verifying,
    Chained,
    Released,
}

impl State {
    pub fn code(self) -> &'static str {
        match self {
            State::None => "none",
            State::Detected => "detected",
            State::Verifying => "verifying",
            State::Chained => "chained",
            State::Released => "released",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    UpstreamTooOld,
    Unsupported,
    NotAllowed,
    VerifyFailed,
    UpstreamChanged,
    NoResponse,
    Gone,
    Loop,
    TooDeep,
    Tampered,
}

impl Reason {
    pub fn code(self) -> &'static str {
        match self {
            Reason::UpstreamTooOld => "upstream-too-old",
            Reason::Unsupported => "unsupported",
            Reason::NotAllowed => "not-allowed",
            Reason::VerifyFailed => "verify-failed",
            Reason::UpstreamChanged => "upstream-changed",
            Reason::NoResponse => "no-response",
            Reason::Gone => "gone",
            Reason::Loop => "loop",
            Reason::TooDeep => "too-deep",
            Reason::Tampered => "tampered",
        }
    }

    /// 一句白話（記錄檔用；狀態頁的 `text` 另外組，見 [`Client::status_json`]）
    pub fn text(self) -> &'static str {
        match self {
            Reason::UpstreamTooOld => "上游黑潮的版本不支援串接（需要 3.4.0 以上）",
            Reason::Unsupported => "上游黑潮沒有回應串接查詢",
            Reason::NotAllowed => "上游不提供資料（allow_downstream 關閉）",
            Reason::VerifyFailed => "上游的身分驗證失敗（簽章、nonce 或節點 ID 不對）",
            Reason::UpstreamChanged => "上游節點的金鑰換了",
            Reason::NoResponse => "上游沒有回應",
            Reason::Gone => "一般 DNS 不再被上游黑潮接走",
            Reason::Loop => "上游的串接鏈裡有這台（會形成迴圈）",
            Reason::TooDeep => "上游的串接已經有 4 層（超過上限）",
            Reason::Tampered => "攔截者竄改答案",
        }
    }
}

// ---------------- 時間 ----------------

#[derive(Debug, Clone)]
pub struct Timing {
    /// 一次挑戰的逾時
    pub ask: Duration,
    /// 心跳間隔（實際 ±10%）
    pub heartbeat: Duration,
    /// 綁定後提早心跳的範圍（縮短兩台同時互相綁定時的迴圈時間）
    pub early_min: Duration,
    pub early_max: Duration,
    /// 重試的起點與上限（驗證失敗、沒回應每次加倍；迴圈、太深、沒回應串接查詢直接用上限）
    pub retry_min: Duration,
    pub retry_max: Duration,
    /// 心跳連續幾次沒回應就解除
    pub fail_limit: u32,
}

impl Default for Timing {
    fn default() -> Timing {
        Timing {
            ask: Duration::from_millis(1500),
            heartbeat: Duration::from_secs(300),
            early_min: Duration::from_secs(5),
            early_max: Duration::from_secs(15),
            retry_min: Duration::from_secs(60),
            retry_max: Duration::from_secs(600),
            fail_limit: 3,
        }
    }
}

impl Timing {
    /// 環境變數 `KUROSHIO_CHAIN_TIMING`（JSON，毫秒）覆寫，只給整合測試用：
    /// `{"heartbeat":2000,"earlyMin":200,"earlyMax":400,"retryMin":500,"retryMax":2000}`（另外可以有 `ask`、`failLimit`）
    pub fn from_env() -> Timing {
        let mut t = Timing::default();
        let Some(v) = std::env::var("KUROSHIO_CHAIN_TIMING")
            .ok()
            .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        else {
            return t;
        };
        let ms = |k: &str| v.get(k).and_then(Value::as_u64).map(Duration::from_millis);
        for (k, f) in [
            ("ask", &mut t.ask),
            ("heartbeat", &mut t.heartbeat),
            ("earlyMin", &mut t.early_min),
            ("earlyMax", &mut t.early_max),
            ("retryMin", &mut t.retry_min),
            ("retryMax", &mut t.retry_max),
        ] {
            if let Some(d) = ms(k) {
                *f = d;
            }
        }
        if let Some(n) = v.get("failLimit").and_then(Value::as_u64) {
            t.fail_limit = n.clamp(1, 10) as u32;
        }
        warn!("串接：使用測試用的時間覆寫（KUROSHIO_CHAIN_TIMING）");
        t
    }
}

// ---------------- 探測 ----------------

/// 探測的結果（狀態頁、check-path 用）
///
/// - `error == None`：驗證通過（`public`、`kid` 有值）
/// - `error` 有值、`supported == false`：沒回應或格式不對（不支援串接）
/// - `error` 有值、`supported == true`：有回答串接格式，但驗證不過（簽章、nonce、節點 ID）
#[derive(Debug, Clone)]
pub struct Probe {
    pub supported: bool,
    pub allow: bool,
    pub public: Option<[u8; 32]>,
    pub kid: Option<[u8; 8]>,
    pub version: String,
    pub caps: Vec<String>,
    pub path: Vec<Vec<u8>>,
    pub peer: String,
    pub tok: Vec<u8>,
    pub error: Option<String>,
}

impl Probe {
    fn failed(supported: bool, error: String) -> Probe {
        Probe {
            supported,
            allow: false,
            public: None,
            kid: None,
            version: String::new(),
            caps: Vec::new(),
            path: Vec::new(),
            peer: String::new(),
            tok: Vec::new(),
            error: Some(error),
        }
    }

    pub fn fingerprint(&self) -> Option<String> {
        self.public.map(|p| fingerprint(&p))
    }
}

/// 一次 auth 挑戰（不重試）；`None` = 沒有回應（逾時、連不上）
async fn challenge(addr: SocketAddr, tcp: bool, limit: Duration) -> Result<Probe, String> {
    let nonce = random_bytes::<16>();
    let r = kuroshio_net::path::chaos_txt(addr, &proto::auth_name(&nonce), tcp, None, limit)
        .await
        .map_err(|e| format!("沒有回應（{e:#}）"))?;
    if r.rcode != 0 {
        return Ok(Probe::failed(false, format!("拒絕串接查詢（rcode {}）", r.rcode)));
    }
    let Some(txt) = r.txt else {
        return Ok(Probe::failed(false, "回應裡沒有串接資料".into()));
    };
    Ok(match proto::open_auth(&txt, &nonce) {
        Ok(b) => Probe {
            supported: true,
            allow: b.allow,
            public: b.public.as_slice().try_into().ok(),
            kid: b.kid.as_slice().try_into().ok(),
            version: b.app.chars().take(32).collect(),
            caps: b.caps.into_iter().take(8).map(|c| c.chars().take(16).collect()).collect(),
            // 記憶體上限：鏈超過 MAX_DEPTH 就已經太深，留 2 倍夠判斷迴圈與太深
            path: b.path.into_iter().take(2 * proto::MAX_DEPTH).collect(),
            peer: b.peer.chars().take(64).collect(),
            tok: b.tok.into_iter().take(32).collect(),
            error: None,
        },
        Err(e @ (proto::AuthError::Malformed | proto::AuthError::Version(_) | proto::AuthError::Kind)) => {
            Probe::failed(false, e.to_string())
        }
        Err(e) => Probe::failed(true, e.to_string()),
    })
}

/// 對 `addr` 發 auth 挑戰並驗證（逾時 `limit`，沒有回應再試一次）。不需要服務在跑：check-path 與狀態機共用
pub async fn probe(addr: SocketAddr, tcp: bool, limit: Duration) -> Probe {
    let mut last = String::new();
    for _ in 0..2 {
        match challenge(addr, tcp, limit).await {
            Ok(p) => return p,
            Err(e) => last = e,
        }
    }
    Probe::failed(false, last)
}

/// 探測結果能不能串接（規格 1.5 第 4、5 步）
fn judge(p: &Probe, own: &[[u8; 8]]) -> Result<(), Reason> {
    if p.error.is_some() || p.public.is_none() {
        return Err(if p.supported { Reason::VerifyFailed } else { Reason::Unsupported });
    }
    if !p.allow {
        return Err(Reason::NotAllowed);
    }
    proto::check_path(&p.path, own).map_err(|e| match e {
        proto::PathError::Loop => Reason::Loop,
        proto::PathError::TooDeep => Reason::TooDeep,
    })
}

// ---------------- 狀態 ----------------

/// 路徑檢查結果裡串接要用的部分
#[derive(Debug, Clone, Default)]
struct View {
    /// IPv4 的一般 DNS 被接走（3.4.0 只走 IPv4 那條路）
    intercepted: bool,
    /// 攔截者是黑潮：版本
    kuroshio: Option<String>,
    /// 攔截者竄改答案或改寫「不存在」
    tampered: bool,
    /// 命中的保留位址、是不是只有 TCP
    hit: Option<(SocketAddr, bool)>,
    /// TCP 的一般 DNS 也被接走（經攔截綁定時 TCP 可不可用）
    tcp_ok: bool,
    /// 驗證時直連的閘道（含埠）
    gateway: Option<SocketAddr>,
    /// 顯示用的預設閘道
    gateway_ip: Option<IpAddr>,
}

impl View {
    fn usable_hit(&self) -> Option<(SocketAddr, bool)> {
        self.hit.filter(|(a, _)| self.intercepted && a.is_ipv4())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Via {
    Gateway,
    Intercept,
}

/// 綁定中的上游
#[derive(Debug, Clone)]
struct Bound {
    addr: SocketAddr,
    tcp: bool,
    via: Via,
    /// TCP 可用（共用結果要用 TCP）
    tcp_ok: bool,
    public: [u8; 32],
    since_ms: u64,
    last_ok_ms: u64,
    failures: u32,
    via_nat: bool,
}

struct Inner {
    settings: ChainSettings,
    timing: Timing,
    state: State,
    reason: Option<Reason>,
    view: Option<View>,
    /// 最近一次探測／驗證／心跳的結果
    probe: Option<Probe>,
    bound: Option<Bound>,
    /// 最近一次綁定的公鑰（連續性：跟它不同就是「上游換了」；第一次綁定不算）
    remembered: Option<[u8; 32]>,
    key_changed_at: Option<u64>,
    previous_fp: Option<String>,
    backoff: Option<Duration>,
    unsupported_retried: bool,
    /// 因為上游沒有回應而解除（`no-response`）、還在等它回來：這段期間重試的探測沒有回應
    /// 仍然算 `no-response`（照退避繼續重試），不當成「不支援串接」
    awaiting_return: bool,
    retry_at: Option<Instant>,
    retry_at_ms: Option<u64>,
    next_hb: Option<Instant>,
    hb_fail: u32,
    /// 最近一次登記的結果（`chain.upstream.registered`）
    registered: Option<Registered>,
}

/// 最近一次登記的結果
#[derive(Debug, Clone)]
struct Registered {
    ok: bool,
    at: u64,
    expires_at: Option<u64>,
    names: usize,
    error: Option<String>,
}

impl Registered {
    fn json(&self) -> Value {
        if self.ok {
            json!({ "ok": true, "at": self.at, "expiresAt": self.expires_at, "names": self.names })
        } else {
            json!({ "ok": false, "at": self.at, "names": self.names, "error": self.error })
        }
    }
}

impl Inner {
    fn new(settings: ChainSettings, timing: Timing) -> Inner {
        Inner {
            settings,
            timing,
            state: State::None,
            reason: None,
            view: None,
            probe: None,
            bound: None,
            remembered: None,
            key_changed_at: None,
            previous_fp: None,
            backoff: None,
            unsupported_retried: false,
            awaiting_return: false,
            retry_at: None,
            retry_at_ms: None,
            next_hb: None,
            hb_fail: 0,
            registered: None,
        }
    }
}

/// 狀態機的輸入
#[derive(Debug, Clone)]
enum Event {
    /// 路徑檢查做完
    Report(View),
    /// detected 的探測結果
    Probed(Probe),
    /// verifying 的結果：再一次挑戰、閘道直連（有試的話）
    Verified {
        again: Probe,
        gateway: Option<Box<(SocketAddr, Probe)>>,
    },
    /// 心跳時間到
    HeartbeatDue,
    /// 心跳的結果
    Heartbeat(Probe),
    /// 重試時間到
    Retry,
    WanChanged,
    /// chain 關掉（重新載入）
    Disabled,
}

/// 狀態機要外層做的事
#[derive(Debug, Clone, PartialEq, Eq)]
enum Io {
    Probe {
        addr: SocketAddr,
        tcp: bool,
    },
    Verify {
        addr: SocketAddr,
        tcp: bool,
        gateway: Option<SocketAddr>,
    },
    Heartbeat {
        addr: SocketAddr,
        tcp: bool,
    },
    Bind {
        addr: SocketAddr,
        tcp: bool,
        path: Vec<Vec<u8>>,
    },
    Unbind,
    SetPath(Vec<Vec<u8>>),
    /// 計時改了：叫醒背景工作
    Wake,
}

/// 這次轉移用到的「現在」與亂數（純函式要的輸入）
#[derive(Debug, Clone, Copy)]
struct Now {
    at: Instant,
    ms: u64,
    /// 0..1 的亂數（提早心跳、心跳的 ±10%）
    rnd: f64,
}

impl Now {
    fn get() -> Now {
        let r = u64::from_le_bytes(random_bytes::<8>());
        Now {
            at: Instant::now(),
            ms: now_ms(),
            rnd: (r >> 11) as f64 / (1u64 << 53) as f64,
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn lerp(a: Duration, b: Duration, t: f64) -> Duration {
    if b <= a {
        return a;
    }
    a + (b - a).mul_f64(t.clamp(0.0, 1.0))
}

fn short_fp(p: &[u8; 32]) -> String {
    fingerprint(p)
}

fn set_state(i: &mut Inner, st: State, reason: Option<Reason>) {
    if i.state != st || i.reason != reason {
        match (st, reason) {
            (State::Released, Some(r)) => info!("串接：解除（{}）", r.text()),
            (State::None, Some(r)) => info!("串接：回到未偵測（{}）", r.text()),
            _ => {}
        }
    }
    i.state = st;
    i.reason = reason;
}

/// 解除：拿掉綁定，排重試（`retry` = None：跟著下一次路徑檢查）
fn release(i: &mut Inner, reason: Reason, retry: Option<Duration>, now: Now) -> Vec<Io> {
    let mut io = Vec::new();
    if i.bound.take().is_some() {
        io.push(Io::Unbind);
    }
    set_state(i, State::Released, Some(reason));
    i.awaiting_return = reason == Reason::NoResponse;
    i.next_hb = None;
    i.hb_fail = 0;
    i.retry_at = retry.map(|d| now.at + d);
    i.retry_at_ms = retry.map(|d| now.ms + d.as_millis() as u64);
    io.push(Io::Wake);
    io
}

/// 回到未偵測
fn to_none(i: &mut Inner, reason: Option<Reason>) -> Vec<Io> {
    let mut io = Vec::new();
    if i.bound.take().is_some() {
        io.push(Io::Unbind);
    }
    set_state(i, State::None, reason);
    i.next_hb = None;
    i.hb_fail = 0;
    i.registered = None;
    i.retry_at = None;
    i.retry_at_ms = None;
    i.backoff = None;
    i.unsupported_retried = false;
    i.awaiting_return = false;
    io
}

fn next_backoff(i: &mut Inner) -> Duration {
    let d = match i.backoff {
        Some(b) => (b * 2).min(i.timing.retry_max),
        None => i.timing.retry_min,
    };
    i.backoff = Some(d);
    d
}

/// 探測／驗證／心跳不能串接時的處理
fn reject(i: &mut Inner, r: Reason, now: Now) -> Vec<Io> {
    // 上游沒回應而解除之後的重試：還是沒有回應就維持 no-response，照退避繼續重試（規格 1.4、1.8：上游回來自動接回），
    // 不能變成 unsupported（那個只重試一次，之後要等 6 小時後的路徑檢查）
    let r = if r == Reason::Unsupported && i.awaiting_return {
        Reason::NoResponse
    } else {
        r
    };
    let retry = match r {
        Reason::Unsupported if !i.unsupported_retried => {
            i.unsupported_retried = true;
            Some(i.timing.retry_max)
        }
        Reason::VerifyFailed | Reason::NoResponse => Some(next_backoff(i)),
        Reason::Loop | Reason::TooDeep => Some(i.timing.retry_max),
        _ => None,
    };
    release(i, r, retry, now)
}

/// 開始探測（從 none／released 進 detected）
fn start_probe(i: &mut Inner) -> Vec<Io> {
    match i.view.as_ref().and_then(View::usable_hit) {
        Some((addr, tcp)) => {
            set_state(i, State::Detected, None);
            i.retry_at = None;
            i.retry_at_ms = None;
            vec![Io::Probe { addr, tcp }]
        }
        None => to_none(i, None),
    }
}

/// 狀態轉移（純函式：不做網路 IO；`own` = 自己的 kid）
fn step(i: &mut Inner, ev: Event, own: &[[u8; 8]], now: Now) -> Vec<Io> {
    match ev {
        Event::Disabled => {
            i.probe = None;
            i.remembered = None;
            to_none(i, None)
        }
        Event::WanChanged => {
            i.view = None;
            i.probe = None;
            i.remembered = None;
            to_none(i, None)
        }
        Event::Report(v) => {
            i.view = Some(v.clone());
            if !i.settings.downstream_enabled() {
                i.probe = None;
                return to_none(i, None);
            }
            // 第 1 步：IPv4 的一般 DNS 被接走＋攔截者是黑潮
            let (Some(ver), Some(_)) = (v.kuroshio.clone(), v.usable_hit()) else {
                let was = i.bound.is_some() || i.state == State::Chained;
                i.probe = None;
                return to_none(i, was.then_some(Reason::Gone));
            };
            // 第 2 步：版本低於 3.4.0 不發挑戰
            if !proto::version_ok(&ver) {
                i.probe = None;
                return release(i, Reason::UpstreamTooOld, None, now);
            }
            // 第 3 步：攔截者竄改答案
            if v.tampered {
                return release(i, Reason::Tampered, None, now);
            }
            match i.state {
                State::Chained | State::Detected | State::Verifying => Vec::new(),
                State::None | State::Released => start_probe(i),
            }
        }
        Event::Probed(p) => {
            if i.state != State::Detected {
                return Vec::new();
            }
            let verdict = judge(&p, own);
            i.probe = Some(p);
            if let Err(r) = verdict {
                return reject(i, r, now);
            }
            let Some((addr, tcp)) = i.view.as_ref().and_then(View::usable_hit) else {
                return to_none(i, None);
            };
            set_state(i, State::Verifying, None);
            let gateway = i.view.as_ref().and_then(|v| v.gateway).filter(|g| *g != addr);
            vec![Io::Verify { addr, tcp, gateway }]
        }
        Event::Verified { again, gateway } => {
            if i.state != State::Verifying {
                return Vec::new();
            }
            let first = i.probe.as_ref().and_then(|p| p.public);
            let verdict = judge(&again, own);
            let public = again.public;
            i.probe = Some(again.clone());
            if let Err(r) = verdict {
                return reject(i, r, now);
            }
            let (Some(public), true) = (public, public == first) else {
                warn!("串接：驗證時上游的公鑰跟探測時不同，不串接");
                return reject(i, Reason::VerifyFailed, now);
            };
            let Some((hit, tcp)) = i.view.as_ref().and_then(View::usable_hit) else {
                return to_none(i, None);
            };
            let (addr, via) = match gateway {
                Some(b) if b.1.error.is_none() && b.1.public == Some(public) => (b.0, Via::Gateway),
                _ => (hit, Via::Intercept),
            };
            if let Some(old) = i.remembered.filter(|o| *o != public) {
                i.key_changed_at = Some(now.ms);
                i.previous_fp = Some(short_fp(&old));
                warn!(
                    "串接：上游節點的金鑰換了（舊指紋 {}，新指紋 {}），已自動改綁新的金鑰；如果不是你換的請檢查上游",
                    short_fp(&old),
                    short_fp(&public)
                );
            }
            i.remembered = Some(public);
            i.backoff = None;
            i.unsupported_retried = false;
            i.awaiting_return = false;
            i.retry_at = None;
            i.retry_at_ms = None;
            i.hb_fail = 0;
            let tcp_ok = via == Via::Gateway || i.view.as_ref().is_some_and(|v| v.tcp_ok);
            i.bound = Some(Bound {
                addr,
                tcp,
                via,
                tcp_ok,
                public,
                since_ms: now.ms,
                last_ok_ms: now.ms,
                failures: 0,
                via_nat: false,
            });
            set_state(i, State::Chained, None);
            // 5～15 秒後（隨機）提早做一次心跳：縮短兩台同時互相綁定時的迴圈時間
            i.next_hb = Some(now.at + lerp(i.timing.early_min, i.timing.early_max, now.rnd));
            info!(
                "串接：上游 {}（黑潮 {}，指紋 {}）驗證通過，開始串接{}",
                addr.ip(),
                again.version,
                short_fp(&public),
                if via == Via::Gateway { "" } else { "（經攔截）" }
            );
            vec![
                Io::Bind {
                    addr,
                    tcp,
                    path: again.path.clone(),
                },
                Io::Wake,
            ]
        }
        Event::HeartbeatDue => match (&i.state, &i.bound) {
            (State::Chained, Some(b)) => {
                i.next_hb = None;
                vec![Io::Heartbeat { addr: b.addr, tcp: b.tcp }]
            }
            _ => Vec::new(),
        },
        Event::Heartbeat(p) => {
            if i.state != State::Chained || i.bound.is_none() {
                return Vec::new();
            }
            // 沒有回應（或格式不對）：連續 fail_limit 次才解除
            if p.error.is_some() && !p.supported {
                i.hb_fail += 1;
                let limit = i.timing.fail_limit;
                let b = i.bound.as_mut().expect("檢查過");
                b.failures = i.hb_fail;
                if i.hb_fail >= limit {
                    warn!("串接：上游連續 {limit} 次沒有回應心跳，改用自己的加密上游");
                    return reject(i, Reason::NoResponse, now);
                }
                // 沒回應時不等整個心跳間隔，快一點確認
                i.next_hb = Some(now.at + i.timing.heartbeat.min(i.timing.retry_min));
                return vec![Io::Wake];
            }
            if p.error.is_some() {
                i.probe = Some(p);
                return reject(i, Reason::VerifyFailed, now);
            }
            let bound_pub = i.bound.as_ref().map(|b| b.public);
            if p.public != bound_pub {
                // 上游換了：立刻重新探測，通過就自動綁定新的公鑰（remembered 還是舊的，綁定時記警告）
                warn!(
                    "串接：心跳回來的上游公鑰跟綁定的不同（{} → {}），重新驗證",
                    bound_pub.map(|b| short_fp(&b)).unwrap_or_default(),
                    p.fingerprint().unwrap_or_default()
                );
                let addr = i.bound.as_ref().map(|b| (b.addr, b.tcp));
                i.probe = Some(p);
                let mut io = release(i, Reason::UpstreamChanged, None, now);
                let target = i.view.as_ref().and_then(View::usable_hit).or(addr);
                if let Some((addr, tcp)) = target {
                    set_state(i, State::Detected, None);
                    io.push(Io::Probe { addr, tcp });
                }
                return io;
            }
            let verdict = judge(&p, own);
            let path = p.path.clone();
            let changed = i.probe.as_ref().map(|o| o.path != p.path).unwrap_or(true);
            i.probe = Some(p);
            if let Err(r) = verdict {
                return reject(i, r, now);
            }
            i.hb_fail = 0;
            if let Some(b) = i.bound.as_mut() {
                b.last_ok_ms = now.ms;
                b.failures = 0;
            }
            let jitter = i.timing.heartbeat.mul_f64(0.1);
            i.next_hb = Some(now.at + lerp(i.timing.heartbeat - jitter, i.timing.heartbeat + jitter, now.rnd));
            let mut io = vec![Io::Wake];
            if changed {
                io.push(Io::SetPath(path));
            }
            io
        }
        Event::Retry => {
            i.retry_at = None;
            i.retry_at_ms = None;
            if i.state != State::Released || !i.settings.downstream_enabled() {
                return Vec::new();
            }
            start_probe(i)
        }
    }
}

// ---------------- Client ----------------

pub struct Client {
    key: Arc<NodeKey>,
    inner: Mutex<Inner>,
    mgr: Mutex<Weak<Manager>>,
    responder: Mutex<Option<Weak<Responder>>>,
    /// 計時改了、或串接上游連續失敗：叫醒背景工作
    wake: Notify,
    /// 同一時間只跑一個流程（路徑檢查之後的探測、心跳、重試）
    run: tokio::sync::Mutex<()>,
    /// 背景工作的代數：每一輪 runtime 呼叫一次 spawn，舊的那個看到代數變了就結束
    generation: AtomicU64,
    /// 「直連閘道」的覆寫（測試用；None = 用路徑檢查讀到的預設閘道）
    gateway_override: Mutex<Option<Option<SocketAddr>>>,
    /// 狀態改變時的回呼（WP5 的共用結果：串接解除時檢查資料新不新鮮、叫醒同步）
    on_change: Mutex<Vec<StateFn>>,
}

/// 狀態改變的回呼：（原本的狀態，新的狀態）。不拿著狀態的鎖呼叫
pub type StateFn = Arc<dyn Fn(State, State) + Send + Sync>;

impl Client {
    pub fn new(settings: ChainSettings, key: Arc<NodeKey>, timing: Timing) -> Arc<Client> {
        Arc::new(Client {
            key,
            inner: Mutex::new(Inner::new(settings, timing)),
            mgr: Mutex::new(Weak::new()),
            responder: Mutex::new(None),
            wake: Notify::new(),
            run: tokio::sync::Mutex::new(()),
            generation: AtomicU64::new(0),
            gateway_override: Mutex::new(None),
            on_change: Mutex::new(Vec::new()),
        })
    }

    /// 狀態改變時呼叫 `f`（狀態離開 `Chained`、進入 `Chained` 等；同一個狀態換原因不算）
    pub fn on_state_change(&self, f: StateFn) {
        self.on_change.lock().unwrap().push(f);
    }

    fn changed(&self, from: State) {
        let to = self.inner.lock().unwrap().state;
        if to != from {
            let fs = self.on_change.lock().unwrap().clone();
            for f in fs {
                f(from, to);
            }
        }
    }

    /// 驗證時「直連閘道」的位址覆寫：`Some(None)` = 沒有閘道；`Some(Some(位址))` = 用這個（含埠，不檢查私有位址）；
    /// `None` = 用路徑檢查讀到的預設閘道（私有位址才試、埠 53）。給 `KUROSHIO_PATH_TARGETS` 與測試用
    pub fn set_gateway_override(&self, g: Option<Option<SocketAddr>>) {
        *self.gateway_override.lock().unwrap() = g;
    }

    fn manager(&self) -> Option<Arc<Manager>> {
        self.mgr.lock().unwrap().upgrade()
    }

    fn responder(&self) -> Option<Arc<Responder>> {
        self.responder.lock().unwrap().as_ref().and_then(Weak::upgrade)
    }

    /// 新的一輪：換設定、接上新的 Manager 與 Responder；原本是 Chained 就立刻把綁定接回去。
    /// chain 關著 → 回到 None、清掉綁定
    pub fn attach(self: &Arc<Self>, settings: ChainSettings, mgr: &Arc<Manager>, responder: Option<&Arc<Responder>>) {
        for w in &settings.warnings {
            warn!("設定：{w}");
        }
        *self.mgr.lock().unwrap() = Arc::downgrade(mgr);
        *self.responder.lock().unwrap() = responder.map(Arc::downgrade);
        {
            let me = Arc::downgrade(self);
            mgr.on_chain_trouble(Arc::new(move || {
                if let Some(c) = me.upgrade() {
                    c.trouble();
                }
            }));
        }
        let enabled = settings.downstream_enabled();
        let before = self.inner.lock().unwrap().state;
        let (io, rebind) = {
            let mut i = self.inner.lock().unwrap();
            i.settings = settings;
            if !enabled {
                (step(&mut i, Event::Disabled, &[], Now::get()), None)
            } else if let (State::Chained, Some(b)) = (i.state, &i.bound) {
                let path = i.probe.as_ref().map(|p| p.path.clone()).unwrap_or_default();
                let r = (b.addr, b.tcp, path);
                // 接回後在背景做一次心跳
                i.next_hb = Some(Instant::now());
                (vec![Io::Wake], Some(r))
            } else {
                (Vec::new(), None)
            }
        };
        if let Some((addr, tcp, path)) = rebind {
            self.bind(addr, tcp, path);
        }
        self.exec_sync(io);
        self.changed(before);
    }

    fn bind(&self, addr: SocketAddr, tcp: bool, path: Vec<Vec<u8>>) {
        let spec = format!("{}://{addr}", if tcp { "tcp" } else { "udp" });
        match Upstream::parse(&spec) {
            Ok(u) => {
                if let Some(m) = self.manager() {
                    m.set_chain(Some(u));
                }
            }
            Err(e) => warn!("串接：無法設定上游 {spec}：{e}"),
        }
        if let Some(r) = self.responder() {
            r.set_upstream_path(Some(path));
        }
    }

    fn unbind(&self) {
        if let Some(m) = self.manager() {
            m.set_chain(None);
        }
        if let Some(r) = self.responder() {
            r.set_upstream_path(None);
        }
    }

    /// 不需要網路的 Io
    fn exec_sync(&self, io: Vec<Io>) {
        for x in io {
            match x {
                Io::Bind { addr, tcp, path } => self.bind(addr, tcp, path),
                Io::Unbind => self.unbind(),
                Io::SetPath(p) => {
                    if let Some(r) = self.responder() {
                        r.set_upstream_path(Some(p));
                    }
                }
                Io::Wake => self.wake.notify_one(),
                Io::Probe { .. } | Io::Verify { .. } | Io::Heartbeat { .. } => {
                    debug_assert!(false, "需要網路的 Io 不能在這裡執行")
                }
            }
        }
    }

    /// 執行一個事件，以及它引起的探測、驗證、心跳（拿著 `run`，不拿著狀態的鎖做 IO）
    async fn drive(self: &Arc<Self>, ev: Event) {
        let _run = self.run.lock().await;
        let ask = self.inner.lock().unwrap().timing.ask;
        let mut queue = vec![ev];
        while let Some(ev) = queue.pop() {
            let own = self.key.own_kids();
            let (io, before) = {
                let mut i = self.inner.lock().unwrap();
                let before = i.state;
                (step(&mut i, ev, &own, Now::get()), before)
            };
            self.changed(before);
            for x in io {
                match x {
                    Io::Probe { addr, tcp } => queue.push(Event::Probed(probe(addr, tcp, ask).await)),
                    Io::Verify { addr, tcp, gateway } => {
                        let again = probe(addr, tcp, ask).await;
                        let gw = match gateway {
                            Some(g) if again.error.is_none() => Some(Box::new((g, probe(g, tcp, ask).await))),
                            _ => None,
                        };
                        queue.push(Event::Verified { again, gateway: gw });
                    }
                    Io::Heartbeat { addr, tcp } => queue.push(Event::Heartbeat(probe(addr, tcp, ask).await)),
                    Io::Bind { addr, tcp, path } => {
                        self.bind(addr, tcp, path);
                        self.note_nat();
                    }
                    other => self.exec_sync(vec![other]),
                }
            }
        }
        // 探測、驗證、心跳之後登記（條件不符時不發任何查詢）
        self.register().await;
    }

    /// 送出登記（規格 4.2）：狀態在 detected 之後、最近一次探測驗證通過、`allow = true` 而且 `caps` 有 `reg`、
    /// 自己的 `chain` 開著。回應用探測到（或綁定）的上游公鑰驗 `regack`。失敗只記在狀態裡，不影響串接
    pub async fn register(&self) -> Option<RegAck> {
        let (addr, tcp, probe, ask) = {
            let i = self.inner.lock().unwrap();
            // 上游沒回應、攔截者竄改答案：不登記（上游不在、或不是可以信任的路徑）
            if !i.settings.downstream_enabled() || i.state == State::None || matches!(i.reason, Some(Reason::Tampered | Reason::NoResponse))
            {
                return None;
            }
            let p = i.probe.clone()?;
            if p.error.is_some() || !p.allow || !p.caps.iter().any(|c| c == "reg") || p.public.is_none() || p.kid.is_none() {
                return None;
            }
            // 綁定中用綁定的位址；還沒綁定（或中斷）用攔截命中的保留位址。TCP 可用就走 TCP（登記封包比較大）
            let (addr, tcp) = match &i.bound {
                Some(b) => (b.addr, b.tcp || b.tcp_ok),
                None => {
                    let v = i.view.as_ref()?;
                    let (a, tcp_only) = v.usable_hit()?;
                    (a, tcp_only || v.tcp_ok)
                }
            };
            (addr, tcp, p, i.timing.ask)
        };
        let names = self.manager().map(|m| upstream_hostnames(&m)).unwrap_or_default();
        let n = names.len();
        let res = self.send_reg(addr, tcp, &probe, names, ask).await;
        let at = now_ms();
        let mut i = self.inner.lock().unwrap();
        // 登記期間設定關掉或回到未偵測：結果不記
        if i.state == State::None {
            return None;
        }
        match res {
            Ok(ack) => {
                if !i.registered.as_ref().is_some_and(|r| r.ok) {
                    info!("串接：已向上游黑潮登記（{n} 個主機名稱，{} 秒有效）", ack.ttl);
                }
                i.registered = Some(Registered {
                    ok: true,
                    at,
                    expires_at: Some(at + u64::from(ack.ttl) * 1000),
                    names: n,
                    error: None,
                });
                Some(ack)
            }
            Err(e) => {
                if i.registered.as_ref().map_or(true, |r| r.ok) {
                    warn!("串接：向上游黑潮登記失敗：{e}");
                }
                i.registered = Some(Registered {
                    ok: false,
                    at,
                    expires_at: None,
                    names: n,
                    error: Some(e),
                });
                None
            }
        }
    }

    async fn send_reg(&self, addr: SocketAddr, tcp: bool, p: &Probe, names: Vec<String>, ask: Duration) -> Result<RegAck, String> {
        let (Some(up_pub), Some(up_kid)) = (p.public, p.kid) else {
            return Err("沒有上游的公鑰".into());
        };
        // 這時才讀（或建立）自己的節點金鑰
        let key = self.key.get().map_err(|e| format!("讀不到也建立不了節點金鑰：{e:#}"))?;
        let local = p.peer.parse::<IpAddr>().is_ok_and(is_local_addr);
        let body = proto::RegBody {
            v: proto::PROTO,
            t: "reg".into(),
            up: up_kid.to_vec(),
            tok: p.tok.clone(),
            peer: p.peer.clone(),
            kid: key.kid.to_vec(),
            public: key.public.to_vec(),
            app: env!("CARGO_PKG_VERSION").into(),
            names,
            local,
        };
        let sealed = proto::seal(&key, "reg", to_cbor(&body));
        let r = kuroshio_net::path::chaos_txt(addr, proto::REG_NAME, tcp, Some((proto::OPT_CODE, sealed)), ask)
            .await
            .map_err(|e| format!("上游沒有回應登記（{e:#}）"))?;
        if r.rcode != 0 {
            return Err(format!("上游拒絕登記（rcode {}）", r.rcode));
        }
        let txt = r.txt.ok_or("登記的回應裡沒有資料")?;
        let b = proto::open(&txt, "regack", &up_pub).map_err(|e| format!("登記的回應驗不過（{e:#}）"))?;
        let ack: RegAck = from_cbor(&b).map_err(|_| "登記的回應格式不對".to_string())?;
        if ack.t != "regack" || ack.kid.as_slice() != key.kid {
            return Err("登記的回應不是給這台的".into());
        }
        Ok(ack)
    }

    /// 上游看到的位址是不是自己某張網卡的位址（否 = 中間有 NAT）
    fn note_nat(&self) {
        let peer = self
            .inner
            .lock()
            .unwrap()
            .probe
            .as_ref()
            .and_then(|p| p.peer.parse::<IpAddr>().ok());
        let Some(peer) = peer else { return };
        let local = is_local_addr(peer);
        if let Some(b) = self.inner.lock().unwrap().bound.as_mut() {
            b.via_nat = !local;
        }
    }

    fn view_of(&self, r: &Report) -> View {
        let gw_override = *self.gateway_override.lock().unwrap();
        let gateway = match gw_override {
            Some(g) => g,
            None => r
                .gateway
                .filter(|g| match g {
                    IpAddr::V4(v) => v.is_private(),
                    IpAddr::V6(v) => (v.segments()[0] & 0xfe00) == 0xfc00,
                })
                .map(|g| SocketAddr::new(g, 53)),
        };
        View {
            intercepted: r.plain_v4.intercepted(),
            kuroshio: match &r.interceptor {
                Some(Interceptor::Kuroshio(v)) => Some(v.clone()),
                _ => None,
            },
            tampered: (!r.tampered.is_empty() && r.tampered.iter().any(|t| t.via == "interceptor"))
                || (!r.nx_rewrite.is_empty() && r.nx_via.as_deref() == Some("interceptor")),
            hit: r.hit.map(|a| (a, r.hit_tcp)),
            tcp_ok: r.plain_v4.tcp,
            gateway,
            gateway_ip: r.gateway,
        }
    }

    /// 路徑檢查做完之後呼叫（規格 1.5 的第 1～6 步，通過就接著驗證、綁定）
    pub async fn on_path_report(self: &Arc<Self>, r: &Report) {
        let v = self.view_of(r);
        self.drive(Event::Report(v)).await;
    }

    pub fn on_wan_changed(&self) {
        let (io, before) = {
            let mut i = self.inner.lock().unwrap();
            let before = i.state;
            (step(&mut i, Event::WanChanged, &[], Now::get()), before)
        };
        self.exec_sync(io);
        self.changed(before);
    }

    /// 串接上游連續失敗（解析流程）：立刻補一次心跳
    fn trouble(&self) {
        let mut i = self.inner.lock().unwrap();
        if i.state == State::Chained {
            i.next_hb = Some(Instant::now());
            drop(i);
            self.wake.notify_one();
        }
    }

    pub fn state(&self) -> (State, Option<Reason>) {
        let i = self.inner.lock().unwrap();
        (i.state, i.reason)
    }

    pub fn is_chained(&self) -> bool {
        self.inner.lock().unwrap().state == State::Chained
    }

    /// 綁定中的上游公鑰（WP5 驗清單用）
    pub fn bound_key(&self) -> Option<[u8; 32]> {
        self.inner.lock().unwrap().bound.as_ref().map(|b| b.public)
    }

    /// 綁定位址；第二個值 = TCP 可用（直連閘道一定可以；經攔截時看 TCP 的一般 DNS 有沒有被接走）
    pub fn bound_addr(&self) -> Option<(SocketAddr, bool)> {
        self.inner.lock().unwrap().bound.as_ref().map(|b| (b.addr, b.tcp_ok))
    }

    /// 最近一次探測／驗證／心跳的結果（WP6 登記用：tok、peer）
    pub fn last_probe(&self) -> Option<Probe> {
        self.inner.lock().unwrap().probe.clone()
    }

    /// 「上游黑潮」在狀態文字裡的寫法
    fn upstream_phrase(i: &Inner) -> String {
        match &i.bound {
            Some(b) if b.via == Via::Gateway => format!("上游 {}", b.addr.ip()),
            _ => match i.view.as_ref().and_then(|v| v.gateway_ip) {
                Some(g) => format!("上游 {g}（經攔截）"),
                None => "上游黑潮".to_string(),
            },
        }
    }

    fn version_of(i: &Inner) -> String {
        i.probe
            .as_ref()
            .map(|p| p.version.clone())
            .filter(|v| !v.is_empty())
            .or_else(|| i.view.as_ref().and_then(|v| v.kuroshio.clone()))
            .unwrap_or_else(|| "?".into())
    }

    fn text(i: &Inner, now_ms: u64) -> String {
        let sees_kuroshio = i.view.as_ref().is_some_and(|v| v.kuroshio.is_some() && v.usable_hit().is_some());
        if !i.settings.chain {
            return if sees_kuroshio {
                "已關閉串接（chain 關閉）：把上游黑潮當成一般的 DNS 攔截，自己做評測，會重複使用網路".into()
            } else {
                "已關閉串接（chain 關閉）".into()
            };
        }
        if !i.settings.path_check {
            return "路徑檢查關閉（path_check 0）：沒有偵測來源，不辨識上游黑潮".into();
        }
        let ver = Self::version_of(i);
        match (i.state, i.reason) {
            (State::Chained, _) => {
                let up = Self::upstream_phrase(i);
                match i.key_changed_at.filter(|t| now_ms < t + KEY_CHANGE_WARN_MS) {
                    Some(t) => format!(
                        "串接中：{up}（黑潮 {ver}）；上游節點的金鑰換過（{}），如果不是你換的請檢查上游",
                        kuroshio_jobs::time::fmt_date_time(t)
                    ),
                    None => format!("串接中：{up}（黑潮 {ver}），評測結果與 CDN 節點由上游提供"),
                }
            }
            (State::Detected, _) => format!("偵測到上游黑潮 {ver}：驗證身分中"),
            (State::Verifying, _) => format!("上游黑潮 {ver}：驗證通過，做最後確認中"),
            (State::Released, Some(Reason::NotAllowed)) => {
                format!("上游黑潮 {ver} 不提供資料（allow_downstream 關閉）：自己做評測，會重複使用網路")
            }
            (State::Released, Some(Reason::UpstreamTooOld)) => format!("上游黑潮 {ver} 不支援串接（需要 3.4.0 以上）"),
            (State::Released, Some(Reason::NoResponse)) => "串接中斷：上游沒有回應，暫時用自己的加密上游".into(),
            (State::Released, Some(Reason::Unsupported)) => {
                format!("上游黑潮 {ver} 沒有回應串接查詢：不串接，自己做評測")
            }
            (State::Released, Some(Reason::VerifyFailed)) => "上游黑潮的身分驗證失敗（簽章不對）：不串接，用自己的上游".into(),
            (State::Released, Some(Reason::UpstreamChanged)) => "上游節點的金鑰換了：重新驗證中".into(),
            (State::Released, Some(Reason::Loop)) => "不串接：上游的串接鏈裡有這台（會形成迴圈）".into(),
            (State::Released, Some(Reason::TooDeep)) => "不串接：上游的串接已經有 4 層（超過上限）".into(),
            (State::Released, Some(Reason::Tampered)) => "不串接：攔截者竄改答案，用自己的加密上游".into(),
            _ => "沒有偵測到上游黑潮".into(),
        }
    }

    fn upstream_json(i: &Inner) -> Value {
        let Some(p) = &i.probe else {
            return Value::Null;
        };
        let ids = |v: &[Vec<u8>]| v.iter().map(|k| hex(k)).collect::<Vec<_>>();
        let (address, proto, via) = match &i.bound {
            Some(b) => (
                Value::from(b.addr.ip().to_string()),
                Value::from(if b.tcp { "tcp" } else { "udp" }),
                Value::from(if b.via == Via::Gateway { "gateway" } else { "intercept" }),
            ),
            None => match i.view.as_ref().and_then(View::usable_hit) {
                Some((a, tcp)) => (
                    Value::from(a.ip().to_string()),
                    Value::from(if tcp { "tcp" } else { "udp" }),
                    Value::Null,
                ),
                None => (Value::Null, Value::Null, Value::Null),
            },
        };
        let b = i.bound.as_ref();
        json!({
            "address": address, "proto": proto, "via": via,
            "version": (!p.version.is_empty()).then(|| p.version.clone()),
            "nodeId": p.kid.map(|k| hex(&k)),
            "fingerprint": p.fingerprint(),
            "allowDownstream": p.error.is_none().then_some(p.allow),
            "caps": p.caps,
            "path": ids(&p.path),
            "depth": p.path.len() + 1,
            "viaNat": b.map(|b| b.via_nat),
            "since": b.map(|b| b.since_ms),
            "lastOkAt": b.map(|b| b.last_ok_ms),
            "failures": b.map(|b| b.failures).unwrap_or(i.hb_fail),
            "keyChangedAt": i.key_changed_at,
            "previousFingerprint": i.previous_fp,
            "registered": i.registered.as_ref().map(Registered::json),
            "error": p.error,
        })
    }

    /// 規格 1.10 的 `chain`（`shared` 是共用結果的同步、`serving` 是上游角色）
    pub fn status_json(&self) -> Value {
        let suspended = self.manager().is_some_and(|m| m.chain_suspended());
        // 這兩個會回頭問狀態機（拿狀態的鎖）：先算好
        let shared = crate::chain::share::shared_json();
        let serving = self.responder().map(|r| r.serving_json()).unwrap_or(Value::Null);
        let i = self.inner.lock().unwrap();
        let now = now_ms();
        json!({
            "enabled": i.settings.chain,
            "state": i.state.code(),
            "reason": i.reason.map(Reason::code),
            "text": Self::text(&i, now),
            "upstream": if i.settings.chain { Self::upstream_json(&i) } else { Value::Null },
            "backupActive": suspended || (i.state == State::Released && i.reason == Some(Reason::NoResponse)),
            "retryAt": i.retry_at_ms,
            "shared": if i.settings.chain { shared } else { Value::Null },
            "serving": serving,
        })
    }

    /// `network.path.interceptor.chain`（還沒探測過、或 chain 關著是 null）
    pub fn interceptor_json(&self) -> Value {
        let i = self.inner.lock().unwrap();
        if !i.settings.downstream_enabled() {
            return Value::Null;
        }
        match &i.probe {
            None => Value::Null,
            Some(p) => json!({
                "supported": p.supported,
                "allowDownstream": p.error.is_none() && p.allow,
                "nodeId": p.kid.map(|k| hex(&k)),
                "fingerprint": p.fingerprint(),
                "caps": p.caps,
                "error": p.error,
            }),
        }
    }

    /// 上游公鑰換過、24 小時內：給 /api/status.warnings 的一行；否則 None
    pub fn key_change_warning(&self, now_ms: u64) -> Option<String> {
        let i = self.inner.lock().unwrap();
        let t = i.key_changed_at.filter(|t| now_ms < t + KEY_CHANGE_WARN_MS)?;
        Some(format!(
            "串接：上游節點的金鑰換過（{}，舊指紋 {}）：已自動改綁新的金鑰，如果不是你換的請檢查上游",
            kuroshio_jobs::time::fmt_date_time(t),
            i.previous_fp.as_deref().unwrap_or("?")
        ))
    }

    /// 心跳與重試的背景工作（每一輪 runtime 呼叫一次；舊的一輪的工作跟著 runtime 結束）
    pub fn spawn(self: &Arc<Self>) {
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let me = self.clone();
        tokio::spawn(async move {
            // chain 剛打開（重新載入）：用上一次路徑檢查的結果，不等 6 小時
            let fresh = {
                let i = me.inner.lock().unwrap();
                i.settings.downstream_enabled() && matches!(i.state, State::None | State::Released) && i.retry_at.is_none()
            };
            if fresh {
                if let Some(r) = kuroshio_net::path::current() {
                    me.on_path_report(&r).await;
                }
            }
            loop {
                if me.generation.load(Ordering::SeqCst) != generation {
                    break;
                }
                let (state, hb, retry) = {
                    let i = me.inner.lock().unwrap();
                    (i.state, i.next_hb, i.retry_at)
                };
                let due = match state {
                    State::Chained => hb,
                    State::Released => retry,
                    _ => None,
                };
                match due {
                    Some(t) if t <= Instant::now() => {
                        let ev = if state == State::Chained {
                            Event::HeartbeatDue
                        } else {
                            Event::Retry
                        };
                        me.drive(ev).await;
                    }
                    Some(t) => {
                        tokio::select! {
                            _ = tokio::time::sleep_until(t.into()) => {}
                            _ = me.wake.notified() => {}
                        }
                    }
                    None => me.wake.notified().await,
                }
            }
        });
    }

    pub fn key(&self) -> &Arc<NodeKey> {
        &self.key
    }
}

/// 位址是不是這台自己某張網卡的（含迴路）：上游看到的 `peer` 不是自己的位址 = 中間有 NAT
fn is_local_addr(ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    ip.is_loopback()
        || crate::netif::list()
            .iter()
            .any(|f| f.addrs.iter().any(|a| a.ip.to_canonical() == ip))
}

/// 下游要登記的主機名稱：固定、自動、備援、最後手段裡不是 IP 的主機，去重複、最多 32 個
pub fn upstream_hostnames(mgr: &Manager) -> Vec<String> {
    let mut ids: Vec<String> = mgr
        .list_json()
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|u| u["role"] != "chain")
                .filter_map(|u| u["id"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    ids.extend(mgr.last_resort.iter().map(|u| u.up.id.clone()));
    let mut out: Vec<String> = Vec::new();
    for id in ids {
        let Ok(u) = Upstream::parse(&id) else { continue };
        let h = u.host.trim_end_matches('.').to_ascii_lowercase();
        if h.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>().is_ok() || !valid_domain(&h) || out.contains(&h) {
            continue;
        }
        out.push(h);
        if out.len() >= proto::MAX_REG_NAMES {
            break;
        }
    }
    out
}

/// `/api/status` 的 `chain` 與 `GET /api/chain`：服務還沒建立狀態機時也是完整的物件（方便前端）
pub fn api_json() -> Value {
    match crate::chain::current() {
        Some(c) => c.status_json(),
        None => json!({
            "enabled": false, "state": "none", "reason": null, "text": "已關閉串接（chain 關閉）",
            "upstream": null, "backupActive": false, "retryAt": null, "shared": null, "serving": null,
        }),
    }
}

/// `network.path.interceptor.chain`
pub fn interceptor_api_json() -> Value {
    crate::chain::current().map(|c| c.interceptor_json()).unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuroshio_community::identity::kid_of;

    fn settings(chain: bool) -> ChainSettings {
        ChainSettings {
            chain,
            allow_downstream: true,
            path_check: true,
            warnings: Vec::new(),
        }
    }

    fn inner(chain: bool) -> Inner {
        Inner::new(settings(chain), Timing::default())
    }

    fn now() -> Now {
        Now {
            at: Instant::now(),
            ms: 1_795_000_000_000,
            rnd: 0.5,
        }
    }

    fn hit() -> SocketAddr {
        "192.0.2.1:53".parse().unwrap()
    }

    fn view(ver: Option<&str>) -> View {
        View {
            intercepted: true,
            kuroshio: ver.map(str::to_string),
            tampered: false,
            hit: Some((hit(), false)),
            tcp_ok: true,
            gateway: Some("192.168.1.1:53".parse().unwrap()),
            gateway_ip: Some("192.168.1.1".parse().unwrap()),
        }
    }

    fn ok_probe(public: [u8; 32], path: Vec<Vec<u8>>) -> Probe {
        Probe {
            supported: true,
            allow: true,
            public: Some(public),
            kid: Some(kid_of(&public)),
            version: "3.4.0".into(),
            caps: vec!["share".into(), "reg".into()],
            path,
            peer: "192.168.1.2".into(),
            tok: vec![0; 16],
            error: None,
        }
    }

    fn chained(i: &mut Inner, public: [u8; 32]) {
        assert_eq!(
            step(i, Event::Report(view(Some("3.4.0"))), &[], now()),
            vec![Io::Probe { addr: hit(), tcp: false }]
        );
        let io = step(i, Event::Probed(ok_probe(public, vec![])), &[], now());
        assert!(matches!(io[0], Io::Verify { .. }));
        let gw = ("192.168.1.1:53".parse().unwrap(), ok_probe(public, vec![]));
        let io = step(
            i,
            Event::Verified {
                again: ok_probe(public, vec![]),
                gateway: Some(Box::new(gw)),
            },
            &[],
            now(),
        );
        assert!(matches!(io[0], Io::Bind { .. }), "{io:?}");
        assert_eq!(i.state, State::Chained);
    }

    #[test]
    fn chain_off_never_probes() {
        let mut i = inner(false);
        for v in [view(Some("3.4.0")), view(Some("3.3.7")), view(None)] {
            assert!(step(&mut i, Event::Report(v), &[], now()).is_empty());
            assert_eq!(i.state, State::None);
        }
    }

    #[test]
    fn old_or_missing_kuroshio_never_probes() {
        let mut i = inner(true);
        assert!(step(&mut i, Event::Report(view(None)), &[], now()).is_empty());
        assert_eq!((i.state, i.reason), (State::None, None));
        let io = step(&mut i, Event::Report(view(Some("3.3.7"))), &[], now());
        assert!(!io.iter().any(|x| matches!(x, Io::Probe { .. })));
        assert_eq!((i.state, i.reason), (State::Released, Some(Reason::UpstreamTooOld)));
        // 3.4.0-rc1 算 3.4.0
        let io = step(&mut i, Event::Report(view(Some("3.4.0-rc1"))), &[], now());
        assert!(matches!(io[0], Io::Probe { .. }));
    }

    /// 上游沒回應而解除之後，重試的探測一直沒有回應：維持 no-response、照退避一直重試（不變成 unsupported 而停止），
    /// 上游回來就接回；接回之後同樣沒回應的探測照常算 unsupported
    #[test]
    fn no_response_keeps_retrying_until_upstream_returns() {
        let mut i = inner(true);
        let a = [7u8; 32];
        chained(&mut i, a);
        for _ in 0..3 {
            step(&mut i, Event::Heartbeat(Probe::failed(false, "逾時".into())), &[], now());
        }
        assert_eq!((i.state, i.reason), (State::Released, Some(Reason::NoResponse)));
        let mut last = Duration::ZERO;
        for _ in 0..6 {
            let io = step(&mut i, Event::Retry, &[], now());
            assert!(matches!(io[0], Io::Probe { .. }), "{io:?}");
            assert_eq!(i.state, State::Detected);
            step(&mut i, Event::Probed(Probe::failed(false, "沒有回應（逾時）".into())), &[], now());
            assert_eq!((i.state, i.reason), (State::Released, Some(Reason::NoResponse)));
            let wait = i.retry_at.expect("一直排重試").saturating_duration_since(now().at);
            assert!(wait + Duration::from_millis(50) >= last, "退避不會變短");
            assert!(wait <= i.timing.retry_max + Duration::from_secs(1), "最長 retry_max");
            last = wait;
        }
        assert_eq!(i.backoff, Some(i.timing.retry_max));
        // 上游回來：接回、清掉退避
        step(&mut i, Event::Retry, &[], now());
        step(&mut i, Event::Probed(ok_probe(a, vec![])), &[], now());
        step(
            &mut i,
            Event::Verified {
                again: ok_probe(a, vec![]),
                gateway: None,
            },
            &[],
            now(),
        );
        assert_eq!(i.state, State::Chained);
        assert!(!i.awaiting_return);
        assert!(i.key_changed_at.is_none(), "同一把金鑰");
        // 沒有經過 no-response 的「沒回應串接查詢」：照舊是 unsupported
        let mut j = inner(true);
        step(&mut j, Event::Report(view(Some("3.4.0"))), &[], now());
        step(&mut j, Event::Probed(Probe::failed(false, "沒有回應（逾時）".into())), &[], now());
        assert_eq!((j.state, j.reason), (State::Released, Some(Reason::Unsupported)));
    }

    #[test]
    fn full_path_binds_gateway_and_heartbeat_rules() {
        let mut i = inner(true);
        let a = [7u8; 32];
        chained(&mut i, a);
        assert_eq!(i.bound.as_ref().unwrap().via, Via::Gateway);
        assert!(i.key_changed_at.is_none(), "第一次綁定不算換了");
        // 心跳：沒回應 2 次還在、第 3 次解除
        for n in 1..=3 {
            let io = step(&mut i, Event::Heartbeat(Probe::failed(false, "逾時".into())), &[], now());
            if n < 3 {
                assert_eq!(i.state, State::Chained);
            } else {
                assert_eq!((i.state, i.reason), (State::Released, Some(Reason::NoResponse)));
                assert!(io.contains(&Io::Unbind));
                assert!(i.retry_at.is_some());
            }
        }
        // 重試 → 重新探測 → 同一把金鑰：沒有警告
        let io = step(&mut i, Event::Retry, &[], now());
        assert!(matches!(io[0], Io::Probe { .. }));
        i.state = State::Detected;
        step(&mut i, Event::Probed(ok_probe(a, vec![])), &[], now());
        step(
            &mut i,
            Event::Verified {
                again: ok_probe(a, vec![]),
                gateway: None,
            },
            &[],
            now(),
        );
        assert_eq!(i.state, State::Chained);
        assert_eq!(i.bound.as_ref().unwrap().via, Via::Intercept);
        assert!(i.key_changed_at.is_none());
        // 心跳的公鑰換了 → 重新探測 → 綁定新的、記警告
        let b = [9u8; 32];
        let io = step(&mut i, Event::Heartbeat(ok_probe(b, vec![])), &[], now());
        assert!(
            io.contains(&Io::Unbind) && io.iter().any(|x| matches!(x, Io::Probe { .. })),
            "{io:?}"
        );
        step(&mut i, Event::Probed(ok_probe(b, vec![])), &[], now());
        step(
            &mut i,
            Event::Verified {
                again: ok_probe(b, vec![]),
                gateway: None,
            },
            &[],
            now(),
        );
        assert_eq!(i.state, State::Chained);
        assert_eq!(i.previous_fp.as_deref(), Some(fingerprint(&a).as_str()));
        assert!(i.key_changed_at.is_some());
    }

    #[test]
    fn probe_rejections() {
        let own = [[1u8; 8]];
        let cases: Vec<(Probe, Reason)> = vec![
            (Probe::failed(false, "逾時".into()), Reason::Unsupported),
            (Probe::failed(true, "簽章".into()), Reason::VerifyFailed),
            (
                Probe {
                    allow: false,
                    ..ok_probe([3; 32], vec![])
                },
                Reason::NotAllowed,
            ),
            (ok_probe([3; 32], vec![vec![1; 8]]), Reason::Loop),
            (ok_probe([3; 32], vec![vec![2; 8]; 4]), Reason::TooDeep),
        ];
        for (p, r) in cases {
            let mut i = inner(true);
            step(&mut i, Event::Report(view(Some("3.4.0"))), &own, now());
            let io = step(&mut i, Event::Probed(p), &own, now());
            assert!(!io.iter().any(|x| matches!(x, Io::Bind { .. } | Io::Verify { .. })));
            assert_eq!((i.state, i.reason), (State::Released, Some(r)));
        }
        // 3 層可以
        let mut i = inner(true);
        step(&mut i, Event::Report(view(Some("3.4.0"))), &own, now());
        let io = step(&mut i, Event::Probed(ok_probe([3; 32], vec![vec![2; 8]; 3])), &own, now());
        assert!(matches!(io[0], Io::Verify { .. }));
    }

    #[test]
    fn verify_failed_backoff_doubles_to_max() {
        let mut i = inner(true);
        let mut got = Vec::new();
        for _ in 0..6 {
            step(&mut i, Event::Report(view(Some("3.4.0"))), &[], now());
            step(&mut i, Event::Probed(Probe::failed(true, "簽章".into())), &[], now());
            got.push(i.backoff.unwrap().as_secs());
        }
        assert_eq!(got, vec![60, 120, 240, 480, 600, 600]);
    }

    #[test]
    fn gone_tampered_wan_changed() {
        let mut i = inner(true);
        chained(&mut i, [5; 32]);
        let io = step(&mut i, Event::Report(view(None)), &[], now());
        assert!(io.contains(&Io::Unbind));
        assert_eq!((i.state, i.reason), (State::None, Some(Reason::Gone)));

        let mut i = inner(true);
        chained(&mut i, [5; 32]);
        let mut v = view(Some("3.4.0"));
        v.tampered = true;
        step(&mut i, Event::Report(v), &[], now());
        assert_eq!((i.state, i.reason), (State::Released, Some(Reason::Tampered)));

        let mut i = inner(true);
        chained(&mut i, [5; 32]);
        let io = step(&mut i, Event::WanChanged, &[], now());
        assert_eq!(io, vec![Io::Unbind]);
        assert_eq!(i.state, State::None);
    }

    #[test]
    fn texts_follow_table() {
        let mut i = inner(false);
        i.view = Some(view(Some("3.4.0")));
        assert!(Client::text(&i, 0).contains("把上游黑潮當成一般的 DNS 攔截"));
        i.view = None;
        assert_eq!(Client::text(&i, 0), "已關閉串接（chain 關閉）");
        let mut i = inner(true);
        assert_eq!(Client::text(&i, 0), "沒有偵測到上游黑潮");
        chained(&mut i, [5; 32]);
        assert_eq!(
            Client::text(&i, 0),
            "串接中：上游 192.168.1.1（黑潮 3.4.0），評測結果與 CDN 節點由上游提供"
        );
    }
}
