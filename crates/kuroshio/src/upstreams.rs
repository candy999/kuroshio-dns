//! 上游管理（對齊 2.x `lib/upstreams.js`）：固定上游永不淘汰、每日評測選出的自動上游、備援、最後手段。
//! 自動上游連續失敗 5 次就暫停（1 → 2 → 4 … 分鐘，最長 30 分鐘），成功一次就歸零。
//!
//! 3.4.0 串接模式（規格 10 的 1.6）：串接上游（`Role::Chain`）由串接模組用 [`Manager::set_chain`] 設定，
//! 不寫進設定檔。串接中只問串接上游＋固定上游；串接上游連續失敗 3 次暫停 30 秒，期間跟沒串接一樣。
//! 沒有串接上游時，所有行為跟 3.3.7 完全一樣。
//!
//! 3.5.0（規格 11 的 A7）：自動上游「上線以來從未成功」、第 3 次暫停時（同一段時間別的上游有成功，
//! 不是整台斷網）先不用（`benched`）：每 6 小時只放 1 筆試探，成功就恢復；登記給下一次評測（`neverOk`）。
//! 可用的自動上游不夠時，依序補上評測結果裡的候補（`spares`）；連候補都沒有就提早評測（12 小時內最多一次）。

use crate::upstream::{Kind, Upstream};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Pinned,
    Auto,
    Fallback,
    LastResort,
    /// 串接模式（3.4.0）：驗證過的上游黑潮，第一順位
    Chain,
}

impl Role {
    pub fn name(self) -> &'static str {
        match self {
            Role::Pinned => "pinned",
            Role::Auto => "auto",
            Role::Fallback => "fallback",
            Role::LastResort => "lastResort",
            Role::Chain => "chain",
        }
    }
}

/// 串接上游連續失敗幾次就暫停
pub const CHAIN_FAIL_LIMIT: u32 = 3;
/// 串接上游第一次暫停多久（之後每次加倍，最多 [`CHAIN_PAUSE_MAX`]；3.4.3）
pub const CHAIN_PAUSE: Duration = Duration::from_secs(30);
/// 串接上游暫停的上限
pub const CHAIN_PAUSE_MAX: Duration = Duration::from_secs(600);
/// 暫停這麼多次（中間沒有穩定 10 分鐘）就解除串接，交給串接狀態機照退避重試（3.4.3）：
/// 心跳正常、查詢卻一直失敗時，以前每 30～45 秒暫停、接回一次，沒有盡頭
pub const CHAIN_RELEASE_TRIPS: u32 = 5;

/// 串接上游連續失敗時的通知：參數是第幾次暫停（串接模組立刻補一次心跳；達到 [`CHAIN_RELEASE_TRIPS`] 就解除串接）
pub type TroubleFn = Arc<dyn Fn(u32) + Send + Sync>;

#[derive(Default)]
struct Trouble(RwLock<Option<TroubleFn>>);

impl std::fmt::Debug for Trouble {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Trouble")
    }
}

#[derive(Debug, Default)]
struct Stats {
    ok: u64,
    fail: u64,
    ewma: Option<f64>,
    consec_fail: u32,
    trips: u32,
    open_until: Option<Instant>,
    /// 上線以來從未成功、先不用（3.5.0）：`open_until` 到了只放 1 筆試探
    benched: bool,
}

/// 從未成功的自動上游第幾次暫停時先不用（前兩次是 1、2 分鐘，合計已經失敗 15 筆）
pub const BENCH_TRIPS: u32 = 3;
/// 先不用的上游多久放 1 筆試探
pub const BENCH_PAUSE: Duration = Duration::from_secs(6 * 3600);
/// 放出試探之後，這麼久之內不再放第二筆（試探的那筆沒被問到時，這段時間過了再放）
const PROBE_HOLD: Duration = Duration::from_secs(30);
/// 「同一段時間別的上游有成功」：這麼久以內有任何上游成功過。整台斷網時所有上游都失敗，不算從未成功
pub const PEER_OK_WINDOW: Duration = Duration::from_secs(10 * 60);

/// 一個 Manager 的上游共用：最近一次任何上游（串接上游除外）成功的時間、先不用時的通知
pub struct Pulse {
    base: Instant,
    /// 距 `base` 的秒數 + 1（0 = 還沒有）；32 位元原子（MT7621 沒有 64 位元原子操作）
    last_ok: AtomicU32,
    on_benched: RwLock<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl std::fmt::Debug for Pulse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Pulse")
    }
}

impl Pulse {
    fn new() -> Arc<Pulse> {
        Arc::new(Pulse {
            base: Instant::now(),
            last_ok: AtomicU32::new(0),
            on_benched: RwLock::new(None),
        })
    }

    fn secs(&self, now: Instant) -> u32 {
        now.saturating_duration_since(self.base).as_secs().min(u32::MAX as u64 - 1) as u32 + 1
    }

    /// 有上游成功：一秒內只寫一次（先讀再寫，每筆查詢不必每次都寫同一個快取線）
    fn mark_ok(&self, now: Instant) {
        let t = self.secs(now);
        if self.last_ok.load(Ordering::Relaxed) != t {
            self.last_ok.store(t, Ordering::Relaxed);
        }
    }

    /// `window` 以內有任何上游成功過
    fn ok_within(&self, now: Instant, window: Duration) -> bool {
        let t = self.last_ok.load(Ordering::Relaxed);
        t != 0 && self.secs(now).saturating_sub(t) as u64 <= window.as_secs()
    }
}

/// 執行時上線以來從未成功、先不用的自動上游（正規化的 id）：下一次評測開始前寫進學習檔的 `neverOk`
/// （規格 11 第 0.3 節）。行程層級（重新載入設定不會不見），最多 [`kuroshio_jobs::benchmark::learn::MAX_NEVER_OK`] 筆
static NEVER_OK: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn note_never_ok(id: &str) {
    let mut v = NEVER_OK.lock().unwrap();
    if !v.iter().any(|x| x == id) {
        if v.len() >= kuroshio_jobs::benchmark::learn::MAX_NEVER_OK {
            v.remove(0);
        }
        v.push(id.to_string());
    }
}

/// 取走登記的從未成功的上游（評測開始前寫進學習檔）
pub fn take_never_ok() -> Vec<String> {
    std::mem::take(&mut *NEVER_OK.lock().unwrap())
}

/// 寫檔失敗時放回去，下一次再寫
pub fn restore_never_ok(ids: Vec<String>) {
    for id in ids {
        note_never_ok(&id);
    }
}

/// `select()` 看一個自動上游：可以用、先不用但這筆放出試探、暫停中（包括先不用）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Avail {
    Ok,
    Probe,
    Off,
}

/// `upstreams.json` 的 `source`：還沒評測、初始上游來自預設名單（3.5.0，見 `kuroshio_jobs::seed::initial_upstreams`）
pub const DEFAULT_LIST: &str = "default-list";

/// 暫停過的自動上游，暫停結束後要穩定這麼久才把暫停次數歸零（暫停時間重新從 1 分鐘算）
const TRIP_RESET: Duration = Duration::from_secs(10 * 60);

/// 評測判斷的上游所在地（`upstreams.json` 的 `selected[]`）：只影響顯示
#[derive(Debug, Clone, PartialEq, Eq)]
struct Place {
    /// ISO 國碼；沒有是 None
    region: Option<String>,
    /// `"tw-net"`（位址在台灣網段）或 `"registered"`（IP 的註冊地；舊的 `upstreams.json` 沒有這個欄位也是這個）
    source: &'static str,
    /// 鄰近（評測用量到的最低延遲判斷）
    near: bool,
}

impl Place {
    fn from_json(s: &Value) -> Place {
        Place {
            region: s
                .get("region")
                .and_then(Value::as_str)
                .filter(|r| !r.is_empty())
                .map(str::to_string),
            source: match s.get("regionSource").and_then(Value::as_str) {
                Some("tw-net") => "tw-net",
                _ => "registered",
            },
            near: s.get("near").and_then(Value::as_bool).unwrap_or(false),
        }
    }
}

#[derive(Debug)]
pub struct Up {
    pub up: Upstream,
    pub role: Role,
    stats: Mutex<Stats>,
    /// 每日評測選上的原因（最快、覆蓋）
    reason: Mutex<Option<String>>,
    /// 評測判斷的所在地區（ISO 國碼，3.4.0）與依據、鄰近（3.5.0 B9）；不是評測選上的（固定、備援、串接）是 None
    region: Mutex<Option<Place>>,
    /// 只有串接上游：連續失敗時通知誰
    trouble: Option<Arc<Trouble>>,
    /// Manager 共用的狀態（3.5.0）：沒有時不會「先不用」（判斷不了是不是整台斷網）
    pulse: Option<Arc<Pulse>>,
}

impl Up {
    #[cfg(test)]
    fn new(up: Upstream, role: Role) -> Arc<Up> {
        Up::with_pulse(up, role, None)
    }

    fn with_pulse(up: Upstream, role: Role, pulse: Option<Arc<Pulse>>) -> Arc<Up> {
        Arc::new(Up {
            up,
            role,
            stats: Mutex::new(Stats::default()),
            reason: Mutex::new(None),
            region: Mutex::new(None),
            trouble: None,
            pulse,
        })
    }

    fn new_chain(up: Upstream, trouble: Arc<Trouble>) -> Arc<Up> {
        Arc::new(Up {
            up,
            role: Role::Chain,
            stats: Mutex::new(Stats::default()),
            reason: Mutex::new(None),
            region: Mutex::new(None),
            trouble: Some(trouble),
            pulse: None,
        })
    }

    /// `select()` 用（一次上鎖）：暫停中（含先不用）是 Off；先不用、時間到了就放 1 筆試探，
    /// 之後 [`PROBE_HOLD`] 內不再放（那筆沒被問到的話，時間過了再放）
    fn avail(&self, now: Instant) -> Avail {
        let mut s = self.stats.lock().unwrap();
        let open = s.open_until.is_some_and(|t| t > now);
        if open {
            return Avail::Off;
        }
        if s.benched {
            s.open_until = Some(now + PROBE_HOLD);
            return Avail::Probe;
        }
        Avail::Ok
    }

    /// 現在能不能正常用（不放試探、不改狀態）：沒暫停、沒先不用、路徑沒擋
    fn usable_now(&self, now: Instant) -> bool {
        let s = self.stats.lock().unwrap();
        !s.benched && !s.open_until.is_some_and(|t| t > now) && !self.path_blocked()
    }

    /// 上線以來從未成功、先不用中（3.5.0）
    pub fn benched(&self) -> bool {
        self.stats.lock().unwrap().benched
    }

    /// 路徑檢查（3.3.6）判斷現在不能用：協定整條被擋、IPv6 位址但這台沒有 IPv6
    pub fn path_blocked(&self) -> bool {
        use kuroshio_net::path::{self, Proto};
        let proto = match self.up.kind {
            Kind::Dot => Some(Proto::Dot),
            Kind::Doh => Some(Proto::Doh),
            Kind::Doq | Kind::Doh3 => Some(Proto::Quic),
            _ => None,
        };
        if proto.is_some_and(path::blocked) {
            return true;
        }
        matches!(self.up.host.parse::<std::net::IpAddr>(), Ok(ip) if !path::addr_usable(ip))
    }

    /// 一般 DNS 而且路上有攔截者：實際回答的是攔截者，不是這台。
    /// 串接上游不算（它就是我們要的那台，`decide()` 不能把它的答案排到後面）
    pub fn via_interceptor(&self) -> bool {
        self.role != Role::Chain
            && is_plain(self.up.kind)
            && self
                .up
                .host
                .parse::<std::net::IpAddr>()
                .is_ok_and(kuroshio_net::path::plain_intercepted_for)
    }

    fn paused(&self, now: Instant) -> bool {
        self.stats.lock().unwrap().open_until.map(|t| t > now).unwrap_or(false)
    }

    /// 平均延遲（毫秒）；還沒有成功紀錄是 None
    pub fn ewma(&self) -> Option<f64> {
        self.stats.lock().unwrap().ewma
    }

    pub fn record(&self, ok: bool, ms: f64) {
        self.record_at(ok, ms, Instant::now());
    }

    fn record_at(&self, ok: bool, ms: f64, now: Instant) {
        let mut notify = None;
        let mut benched = false;
        self.record_inner(ok, ms, now, &mut notify, &mut benched);
        if ok && self.role != Role::Chain {
            if let Some(p) = &self.pulse {
                p.mark_ok(now);
            }
        }
        // 放掉 stats 的鎖之後才通知（回呼可能會讀這個上游的狀態）
        if let Some(f) = notify {
            f(0);
        }
        if benched {
            note_never_ok(&self.up.id);
            let f = self.pulse.as_ref().and_then(|p| p.on_benched.read().unwrap().clone());
            if let Some(f) = f {
                f();
            }
        }
    }

    fn record_inner(&self, ok: bool, ms: f64, now: Instant, notify: &mut Option<TroubleFn>, benched: &mut bool) {
        let mut s = self.stats.lock().unwrap();
        if ok {
            s.ok += 1;
            s.consec_fail = 0;
            if s.benched {
                // 試探成功：恢復，照常使用
                s.benched = false;
                s.open_until = None;
                s.trips = 0;
                info!("{} 試探成功，恢復使用", self.up.id);
            }
            // 暫停結束後成功一筆就歸零的話，「時好時壞」的上游（3.4.2 Windows 實測：tls://ordns.he.net 每次接回後
            // 先答幾十筆、再連續逾時）永遠是「暫停 1 分鐘」，每 70 秒重來一輪，暫停時間不會拉長。
            // 改成暫停結束後穩定 10 分鐘才歸零
            if s.open_until.map_or(true, |t| t + TRIP_RESET <= now) {
                s.trips = 0;
            }
            s.ewma = Some(s.ewma.map(|e| e * 0.8 + ms * 0.2).unwrap_or(ms));
        } else {
            s.fail += 1;
            s.consec_fail += 1;
            if self.role == Role::Auto && s.benched {
                // 試探失敗：再等 6 小時（不必再累積 5 筆）
                s.consec_fail = 0;
                s.open_until = Some(now + BENCH_PAUSE);
                tracing::debug!("{} 試探失敗，6 小時後再試", self.up.id);
            } else if self.role == Role::Auto && s.consec_fail >= 5 && s.open_until.map(|t| t < now).unwrap_or(true) {
                s.trips += 1;
                s.consec_fail = 0;
                // 上線以來從未成功、第 3 次暫停，而且同一段時間別的上游有成功（不是整台斷網）：先不用（3.5.0）
                let peers_ok = self.pulse.as_ref().is_some_and(|p| p.ok_within(now, PEER_OK_WINDOW));
                if s.ok == 0 && s.trips >= BENCH_TRIPS && peers_ok {
                    s.benched = true;
                    s.open_until = Some(now + BENCH_PAUSE);
                    *benched = true;
                    warn!("{} 上線以來從未成功，先不用，下一次評測再決定（每 6 小時試一次）", self.up.id);
                } else {
                    let min = 30u64.min(1 << (s.trips - 1).min(5));
                    s.open_until = Some(now + Duration::from_secs(min * 60));
                    warn!(
                        "{} 連續失敗，暫停 {min} 分鐘{}",
                        self.up.id,
                        if s.ok > 0 { "" } else { "（上線以來從未成功）" }
                    );
                }
            }
            if self.role == Role::Chain && s.consec_fail >= CHAIN_FAIL_LIMIT {
                s.trips += 1;
                let pause = CHAIN_PAUSE.saturating_mul(1 << (s.trips - 1).min(8)).min(CHAIN_PAUSE_MAX);
                s.open_until = Some(now + pause);
                s.consec_fail = 0;
                warn!(
                    "串接：上游黑潮 {} 連續失敗 {CHAIN_FAIL_LIMIT} 次，暫停 {} 秒（第 {} 次），先用自己的上游",
                    self.up.id,
                    pause.as_secs(),
                    s.trips
                );
                let trips = s.trips;
                if let Some(f) = self.trouble.as_ref().and_then(|t| t.0.read().unwrap().clone()) {
                    *notify = Some(Arc::new(move |_| f(trips)));
                }
            }
        }
    }

    pub fn json(&self) -> Value {
        let place = self.region.lock().unwrap().clone();
        let s = self.stats.lock().unwrap();
        json!({
            "id": self.up.id, "type": kind_name(self.up.kind), "role": self.role.name(),
            "ok": s.ok, "fail": s.fail,
            "avgMs": s.ewma.map(|e| (e * 10.0).round() / 10.0),
            "paused": s.open_until.map(|t| t > Instant::now()).unwrap_or(false),
            // 3.3.6：選上的原因、路徑檢查判斷不能用、經由攔截者（一般 DNS 被接走時）
            "reason": self.reason.lock().unwrap().clone(),
            // 3.5.0：國別是註冊地還是台灣網段（regionSource）、鄰近（near）；介面用 ui-core.js 的 regionLabel 顯示
            "region": place.as_ref().and_then(|p| p.region.clone()),
            "regionSource": place.as_ref().map(|p| p.source),
            "near": place.as_ref().map(|p| p.near),
            "pathBlocked": self.path_blocked(),
            "via": if self.via_interceptor() { Value::from("interceptor") } else { Value::Null },
            // 3.5.0：上線以來從未成功、先不用（每 6 小時試一次）
            "benched": s.benched,
        })
    }
}

pub fn kind_name(k: Kind) -> &'static str {
    match k {
        Kind::Udp => "udp",
        Kind::Tcp => "tcp",
        Kind::Dot => "dot",
        Kind::Doh => "doh",
        Kind::Doh3 => "doh3",
        Kind::Doq => "doq",
        Kind::DnsCrypt => "dnscrypt",
    }
}

/// 明文上游（UDP / TCP）：不需要 TLS，系統時間沒對時也能用
pub fn is_plain(k: Kind) -> bool {
    matches!(k, Kind::Udp | Kind::Tcp)
}

/// 純函式（3.4.0 串接模式，規格 1.6）：(主要上游, 備援)。之後主要上游再過 [`select_active`]。
///
/// - 沒有串接上游：固定 + 自動；備援 = 備援 + 最後手段（3.3.7 的行為）
/// - 串接中、沒暫停：[串接上游] + 固定上游（自動上游不問）；備援 = 自動 + 備援 + 最後手段
/// - 串接上游暫停中：主要上游跟沒串接時一樣；備援 = 備援 + 最後手段
///
/// 串接時備援都去掉 `via_interceptor()` 為真的（一般 DNS 會回到同一台掛掉的上游）。
/// `auto` 是已經去掉暫停中、路徑檢查判斷不能用的自動上游。
pub fn select_chain(
    chain: Option<&Arc<Up>>,
    suspended: bool,
    pinned: &[Arc<Up>],
    auto: Vec<Arc<Up>>,
    fallback: &[Arc<Up>],
    last_resort: &[Arc<Up>],
) -> (Vec<Arc<Up>>, Vec<Arc<Up>>) {
    let rest = || fallback.iter().chain(last_resort).cloned();
    let Some(chain) = chain else {
        let mut active = pinned.to_vec();
        active.extend(auto);
        return (active, rest().collect());
    };
    let independent = |v: Vec<Arc<Up>>| -> Vec<Arc<Up>> { v.into_iter().filter(|u| !u.via_interceptor()).collect() };
    if suspended {
        let mut active = pinned.to_vec();
        active.extend(auto);
        return (active, independent(rest().collect()));
    }
    let mut active = vec![chain.clone()];
    active.extend(pinned.iter().filter(|p| !Arc::ptr_eq(p, chain)).cloned());
    let backup = independent(auto.into_iter().chain(rest()).collect());
    (active, backup)
}

/// 純函式：這次查詢要用的上游。
/// - 已對時：`list`（固定 + 自動），空的就用備援（原本的行為）
/// - 沒對時：加密上游的憑證驗不過，只留明文的；`list` 裡沒有明文上游時依序改用備援、最後手段裡的明文上游。
///   加密上游完全不問，所以也不會被記成失敗、暫停
pub fn select_active(list: Vec<Arc<Up>>, fallback: &[Arc<Up>], last_resort: &[Arc<Up>], synced: bool) -> Vec<Arc<Up>> {
    if synced {
        return if list.is_empty() { fallback.to_vec() } else { list };
    }
    let plain = |v: &[Arc<Up>]| -> Vec<Arc<Up>> { v.iter().filter(|u| is_plain(u.up.kind)).cloned().collect() };
    for v in [plain(&list), plain(fallback), plain(last_resort)] {
        if !v.is_empty() {
            return v;
        }
    }
    Vec::new()
}

#[cfg(test)]
fn build(specs: &[String], role: Role) -> Vec<Arc<Up>> {
    build_with(specs, role, None)
}

fn build_with(specs: &[String], role: Role, pulse: Option<&Arc<Pulse>>) -> Vec<Arc<Up>> {
    let mut out = Vec::new();
    for s in specs {
        match Upstream::parse(s) {
            Ok(u) if u.supported() => out.push(Up::with_pulse(u, role, pulse.cloned())),
            Ok(u) => warn!("這個版本還不支援 {}，略過", u.id),
            Err(e) => warn!("無法解析上游 {s}：{e}"),
        }
    }
    out
}

/// 評測結果最多讀幾台候補
pub const MAX_SPARES: usize = 3;

struct Auto {
    list: Vec<Arc<Up>>,
    /// 候補（3.5.0）：可用的自動上游不夠時依序補上
    spares: Vec<Arc<Up>>,
    generated_at: Option<String>,
    /// `upstreams.json` 的 `source` 是字串時（3.5.0：`"default-list"` = 還沒評測、來自預設名單）
    source: Option<String>,
    mtime: Option<SystemTime>,
}

pub struct Manager {
    pub pinned: Vec<Arc<Up>>,
    pub fallback: Vec<Arc<Up>>,
    pub last_resort: Vec<Arc<Up>>,
    auto: RwLock<Auto>,
    state_file: PathBuf,
    auto_types: Vec<String>,
    auto_max: usize,
    /// 可用的自動上游少於這個數就補候補（`min(autoMax, benchmark.minAuto)`，3.5.0）
    auto_need: usize,
    pulse: Arc<Pulse>,
    /// 串接上游（3.4.0）：由串接模組設定，不寫進設定檔
    chain: RwLock<Option<Arc<Up>>>,
    chain_trouble: Arc<Trouble>,
}

fn strings(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

impl Manager {
    pub fn new(cfg: &Value, state_file: PathBuf) -> Manager {
        let g = |k| kuroshio_config::get(cfg, k);
        let pulse = Pulse::new();
        let auto_max = g("upstream.autoMax").and_then(Value::as_u64).unwrap_or(6) as usize;
        let min_auto = g("benchmark.minAuto").and_then(Value::as_u64).unwrap_or(3) as usize;
        let m = Manager {
            pinned: build_with(&strings(g("upstream.pinned")), Role::Pinned, Some(&pulse)),
            fallback: build_with(&strings(g("upstream.fallback")), Role::Fallback, Some(&pulse)),
            last_resort: build_with(&strings(g("resolver.lastResort")), Role::LastResort, Some(&pulse)),
            auto: RwLock::new(Auto {
                list: Vec::new(),
                spares: Vec::new(),
                generated_at: None,
                source: None,
                mtime: None,
            }),
            state_file,
            auto_types: strings(g("upstream.autoTypes")),
            auto_max,
            auto_need: auto_max.min(min_auto),
            pulse,
            chain: RwLock::new(None),
            chain_trouble: Arc::new(Trouble::default()),
        };
        m.reload_auto();
        m
    }

    /// 這台有沒有用自動上游（`autoTypes` 有設、`autoMax` 不是 0）。沒有用時評測結果只是記下來，不必檢查夠不夠用
    pub fn uses_auto(&self) -> bool {
        !self.auto_types.is_empty() && self.auto_max > 0
    }

    /// 一份評測結果（`upstreams.json` 的內容）照這台自己的設定（`autoTypes`、`autoMax`、固定上游、這個版本支援的類型）
    /// 能用幾台。串接拿到上游的評測結果時先看這個，不夠就不匯入（3.4.3）
    pub fn usable_auto(&self, st: &Value) -> usize {
        let pinned: Vec<&str> = self.pinned.iter().map(|p| p.up.id.as_str()).collect();
        st.get("selected")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|s| {
                let ty = s.get("type").and_then(Value::as_str).unwrap_or("udp");
                self.auto_types.iter().any(|t| t == ty)
                    && s.get("id")
                        .and_then(Value::as_str)
                        .and_then(|id| Upstream::parse(id).ok())
                        .is_some_and(|u| u.supported() && !pinned.contains(&u.id.as_str()))
            })
            .count()
            .min(self.auto_max)
    }

    /// 讀每日評測結果；檔案沒變就不重讀
    pub fn reload_auto(&self) {
        let mtime = std::fs::metadata(&self.state_file).and_then(|m| m.modified()).ok();
        if mtime.is_some() && mtime == self.auto.read().unwrap().mtime {
            return;
        }
        let st: Option<Value> = std::fs::read(&self.state_file).ok().and_then(|b| serde_json::from_slice(&b).ok());
        let Some(st) = st.filter(|v| v.get("selected").map(Value::is_array).unwrap_or(false)) else {
            let mut a = self.auto.write().unwrap();
            if a.mtime.is_none() && a.generated_at.is_none() {
                warn!("尚無每日評測結果（{}），暫時只用固定上游與備援", self.state_file.display());
            }
            a.mtime = mtime;
            return;
        };
        let old: Vec<Arc<Up>> = {
            let a = self.auto.read().unwrap();
            a.list.iter().chain(&a.spares).cloned().collect()
        };
        let list = self.load_ups(st["selected"].as_array().unwrap(), self.auto_max, &old, &[]);
        // 候補（3.5.0）：autoMax = 0（沒用自動上游）時也不載入；舊的檔沒有 spares 就是沒有候補
        let spares = match st.get("spares").and_then(Value::as_array) {
            Some(a) if self.auto_max > 0 => self.load_ups(a, MAX_SPARES, &old, &list),
            _ => Vec::new(),
        };
        let generated_at = st.get("generatedAt").and_then(Value::as_str).map(str::to_string);
        let source = st.get("source").and_then(Value::as_str).map(str::to_string);
        info!(
            "自動上游已載入（{}）：{}",
            generated_at.as_deref().unwrap_or(if source.as_deref() == Some(DEFAULT_LIST) {
                "預設名單，還沒評測"
            } else {
                "?"
            }),
            if list.is_empty() {
                "無".to_string()
            } else {
                list.iter().map(|u| u.up.id.clone()).collect::<Vec<_>>().join(", ")
            }
        );
        if !spares.is_empty() {
            info!(
                "候補 {} 台（可用的自動上游不夠時補上）：{}",
                spares.len(),
                spares.iter().map(|u| u.up.id.clone()).collect::<Vec<_>>().join(", ")
            );
        }
        *self.auto.write().unwrap() = Auto {
            list,
            spares,
            generated_at,
            source,
            mtime,
        };
    }

    /// `selected[]`／`spares[]` → 上游（類型要在 `autoTypes`、不跟固定上游與 `skip` 重複、這個版本支援），最多 `max` 台；
    /// 原本就有的沿用（統計、暫停狀態不歸零）
    fn load_ups(&self, items: &[Value], max: usize, old: &[Arc<Up>], skip: &[Arc<Up>]) -> Vec<Arc<Up>> {
        let pinned: Vec<&str> = self.pinned.iter().map(|p| p.up.id.as_str()).collect();
        let mut list: Vec<Arc<Up>> = Vec::new();
        for s in items {
            // 先檢查上限：autoMax = 0 時一台都不載入（以前先 push 才檢查，0 也會載入 1 台）
            if list.len() >= max {
                break;
            }
            let (Some(id), ty) = (
                s.get("id").and_then(Value::as_str),
                s.get("type").and_then(Value::as_str).unwrap_or("udp"),
            ) else {
                continue;
            };
            if !self.auto_types.iter().any(|t| t == ty) {
                continue;
            }
            let Ok(u) = Upstream::parse(id) else { continue };
            if pinned.contains(&u.id.as_str()) || !u.supported() {
                continue;
            }
            if skip.iter().chain(&list).any(|x| x.up.id == u.id) {
                continue;
            }
            let up = old
                .iter()
                .find(|o| o.up.id == u.id)
                .cloned()
                .unwrap_or_else(|| Up::with_pulse(u, Role::Auto, Some(self.pulse.clone())));
            *up.reason.lock().unwrap() = s.get("reason").and_then(Value::as_str).map(str::to_string);
            // 上游多樣性（3.4.0）：評測判斷的所在地區
            *up.region.lock().unwrap() = Some(Place::from_json(s));
            list.push(up);
        }
        list
    }

    /// 這次查詢要用的上游：固定上游一律參與、暫停中的自動上游跳過；都沒有就用備援。
    /// 系統時間還沒對時（見 `crate::clock`）：只用明文上游，見 [`select_active`]。
    /// 串接中（3.4.0）：串接上游 + 固定上游，見 [`select_chain`]
    pub fn active(&self) -> Vec<Arc<Up>> {
        let (list, _) = self.select();
        select_active(list, &self.fallback, &self.last_resort, crate::clock::synced())
    }

    /// 主要上游都失敗時改問的：備援 + 最後手段（沒對時只用其中的明文上游）；
    /// 串接中另外加上自己的自動上游（上游黑潮掛掉時退回自己的加密上游，固定行為）
    pub fn backup(&self) -> Vec<Arc<Up>> {
        let synced = crate::clock::synced();
        let (_, backup) = self.select();
        backup.into_iter().filter(|u| synced || is_plain(u.up.kind)).collect()
    }

    fn select(&self) -> (Vec<Arc<Up>>, Vec<Arc<Up>>) {
        let now = Instant::now();
        // 路徑檢查判斷不能用的（協定被擋、沒有 IPv6）先不用；路恢復了（下一次檢查）自動加回。
        // 暫停中、先不用的跳過（先不用的時間到了放 1 筆試探）
        let a = self.auto.read().unwrap();
        let mut auto: Vec<Arc<Up>> = Vec::with_capacity(a.list.len());
        let mut usable = 0usize;
        // 加進這次的名單；回傳是不是正常可用（試探的不算）
        let take = |u: &Arc<Up>, auto: &mut Vec<Arc<Up>>| -> bool {
            if u.path_blocked() {
                return false;
            }
            match u.avail(now) {
                Avail::Ok => {
                    auto.push(u.clone());
                    true
                }
                Avail::Probe => {
                    auto.push(u.clone());
                    false
                }
                Avail::Off => false,
            }
        };
        for u in &a.list {
            usable += take(u, &mut auto) as usize;
        }
        // 可用的不夠（3.5.0）：依序補上候補。只在不夠時才看候補（平常不多做事）
        if usable < self.auto_need {
            for u in &a.spares {
                usable += take(u, &mut auto) as usize;
                if usable >= self.auto_need {
                    break;
                }
            }
        }
        drop(a);
        let chain = self.chain();
        let suspended = chain.as_ref().is_some_and(|c| c.role == Role::Chain && c.paused(now));
        select_chain(chain.as_ref(), suspended, &self.pinned, auto, &self.fallback, &self.last_resort)
    }

    /// 設定／清除串接上游（串接模組在綁定、解除時呼叫）。跟某個固定上游的 `id` 相同時不新增：
    /// 那個固定上游就當成串接上游（`chain()` 回它，角色維持 `Pinned`，不暫停）
    pub fn set_chain(&self, up: Option<Upstream>) {
        let mut c = self.chain.write().unwrap();
        let Some(u) = up else {
            *c = None;
            return;
        };
        if c.as_ref().is_some_and(|x| x.up.id == u.id) {
            return;
        }
        // 同一台上游換位址（3.5.0 C2：經攔截 → 直連閘道，中間沒有解除）：暫停的次數與時間帶過去，
        // 不然換一次位址就把 `CHAIN_RELEASE_TRIPS` 的計數歸零
        let carry = c.as_ref().filter(|x| x.role == Role::Chain).map(|x| {
            let s = x.stats.lock().unwrap();
            (s.trips, s.open_until)
        });
        let new = match self.pinned.iter().find(|p| p.up.id == u.id) {
            Some(p) => p.clone(),
            None => Up::new_chain(u, self.chain_trouble.clone()),
        };
        if let (Some((trips, open_until)), Role::Chain) = (carry, new.role) {
            let mut s = new.stats.lock().unwrap();
            s.trips = trips;
            s.open_until = open_until;
        }
        *c = Some(new);
    }

    /// 目前的串接上游
    pub fn chain(&self) -> Option<Arc<Up>> {
        self.chain.read().unwrap().clone()
    }

    /// 串接上游連續失敗後的 30 秒暫停中
    pub fn chain_suspended(&self) -> bool {
        self.chain().is_some_and(|c| c.role == Role::Chain && c.paused(Instant::now()))
    }

    /// 串接上游連續失敗 3 次時呼叫（通知串接模組補心跳）
    pub fn on_chain_trouble(&self, f: TroubleFn) {
        *self.chain_trouble.0.write().unwrap() = Some(f);
    }

    pub fn list_json(&self) -> Value {
        let auto = self.auto.read().unwrap();
        // 串接上游排第一個（跟固定上游相同的那種已經在固定上游裡，不重複列）
        let chain = self.chain().filter(|c| c.role == Role::Chain);
        // 候補（3.5.0）排在自動上游後面，多 "spare": true
        let spares = auto.spares.iter().map(|u| {
            let mut j = u.json();
            j["spare"] = json!(true);
            j
        });
        Value::Array(
            chain
                .iter()
                .chain(&self.pinned)
                .chain(&auto.list)
                .map(|u| u.json())
                .chain(spares)
                .chain(self.fallback.iter().map(|u| u.json()))
                .collect(),
        )
    }

    /// 可用的自動上游（含候補）少於 `min(autoMax, benchmark.minAuto)`（3.5.0）：先不用的、暫停中、路徑不通的不算。
    /// 沒用自動上游時一律 false
    pub fn auto_short(&self) -> bool {
        if !self.uses_auto() || self.auto_need == 0 {
            return false;
        }
        let now = Instant::now();
        let a = self.auto.read().unwrap();
        a.list.iter().chain(&a.spares).filter(|u| u.usable_now(now)).count() < self.auto_need
    }

    /// 有自動上游先不用時呼叫（3.5.0；`app` 用它在可用的不夠時提早評測）
    pub fn on_auto_benched(&self, f: Arc<dyn Fn() + Send + Sync>) {
        *self.pulse.on_benched.write().unwrap() = Some(f);
    }

    /// 社群分享用：每日評測選出、而且實際用過有成功的上游（網址、協議、平均毫秒、成功率）
    pub fn auto_shared(&self) -> Vec<(String, String, Option<u32>, f32)> {
        self.auto
            .read()
            .unwrap()
            .list
            .iter()
            .filter_map(|u| {
                let s = u.stats.lock().unwrap();
                let total = s.ok + s.fail;
                (s.ok > 0).then(|| {
                    (
                        u.up.id.clone(),
                        kind_name(u.up.kind).to_string(),
                        s.ewma.map(|e| e.round() as u32),
                        s.ok as f32 / total.max(1) as f32,
                    )
                })
            })
            .take(50)
            .collect()
    }

    /// `/api/status` 的 `autoUpstreams`：評測結果的時間與台數；還沒評測、初始上游來自預設名單時（3.5.0）
    /// 是 `{ "generatedAt": null, "count", "source": "default-list" }`；都沒有是 null
    pub fn auto_info(&self) -> Value {
        let a = self.auto.read().unwrap();
        match (&a.generated_at, a.source.as_deref()) {
            (Some(g), _) => json!({ "generatedAt": g, "count": a.list.len(), "spares": a.spares.len() }),
            (None, Some(DEFAULT_LIST)) => {
                json!({ "generatedAt": null, "count": a.list.len(), "spares": a.spares.len(), "source": DEFAULT_LIST })
            }
            _ => Value::Null,
        }
    }

    /// 自動上游還沒評測過（來自預設名單，3.5.0）
    pub fn auto_from_default_list(&self) -> bool {
        let a = self.auto.read().unwrap();
        a.generated_at.is_none() && a.source.as_deref() == Some(DEFAULT_LIST)
    }

    pub fn state_file(&self) -> &Path {
        &self.state_file
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Value {
        kuroshio_config::with_overrides(&json!({
            "upstream": { "pinned": ["udp://10.0.0.1"], "fallback": ["udp://1.0.0.2"], "autoTypes": ["udp", "doh"], "autoMax": 2 },
            "resolver": { "lastResort": ["udp://8.8.8.8"] }
        }))
    }

    /// autoMax = 0：一台自動上游都不載入；selected[].region 帶到狀態
    #[test]
    fn auto_max_zero_and_region() {
        let dir = std::env::temp_dir().join(format!("kuroshio-up0-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("upstreams.json");
        std::fs::write(
            &f,
            r#"{"generatedAt":"2026-11-10 04:30","selected":[
                {"id":"udp://192.0.2.10","type":"udp","region":"TW","near":true},
                {"id":"udp://192.0.2.11","type":"udp","region":""}]}"#,
        )
        .unwrap();
        let mut c = cfg();
        c["upstream"]["autoMax"] = json!(0);
        let m = Manager::new(&c, f.clone());
        assert_eq!(m.active().len(), 1, "只有固定上游");
        let m = Manager::new(&cfg(), f);
        let list = m.list_json();
        let by = |id: &str| list.as_array().unwrap().iter().find(|u| u["id"] == id).cloned().unwrap();
        assert_eq!(by("udp://192.0.2.10:53")["region"], "TW");
        assert_eq!(by("udp://192.0.2.11:53")["region"], Value::Null);
    }

    /// 3.5.0 B9：selected[] 的 regionSource、near 帶到 /api/upstreams；舊的 upstreams.json（沒有 regionSource）一律當註冊地；
    /// 固定上游、備援沒有評測的地區（null）
    #[test]
    fn old_state_defaults_to_registered() {
        let dir = std::env::temp_dir().join(format!("kuroshio-upsrc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("upstreams.json");
        std::fs::write(
            &f,
            r#"{"generatedAt":"2026-11-10 04:30","selected":[
                {"id":"udp://192.0.2.20","type":"udp","region":"TW","regionSource":"tw-net","near":true},
                {"id":"udp://192.0.2.21","type":"udp","region":"GB","regionSource":"registered","near":true},
                {"id":"udp://192.0.2.22","type":"udp","region":"US","near":false},
                {"id":"udp://192.0.2.23","type":"udp","region":"JP","regionSource":"something-new"}]}"#,
        )
        .unwrap();
        let mut c = cfg();
        c["upstream"]["autoMax"] = json!(5);
        let m = Manager::new(&c, f);
        let list = m.list_json();
        let by = |id: &str| list.as_array().unwrap().iter().find(|u| u["id"] == id).cloned().unwrap();
        let src = |id: &str| (by(id)["region"].clone(), by(id)["regionSource"].clone(), by(id)["near"].clone());
        assert_eq!(src("udp://192.0.2.20:53"), (json!("TW"), json!("tw-net"), json!(true)));
        assert_eq!(src("udp://192.0.2.21:53"), (json!("GB"), json!("registered"), json!(true)));
        assert_eq!(
            src("udp://192.0.2.22:53"),
            (json!("US"), json!("registered"), json!(false)),
            "舊的：註冊地"
        );
        assert_eq!(
            src("udp://192.0.2.23:53"),
            (json!("JP"), json!("registered"), json!(false)),
            "不認得的值當註冊地"
        );
        assert_eq!(
            src("udp://10.0.0.1:53"),
            (Value::Null, Value::Null, Value::Null),
            "固定上游沒有評測的地區"
        );
    }

    #[test]
    fn auto_list_and_breaker() {
        let dir = std::env::temp_dir().join(format!("kuroshio-up-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("upstreams.json");
        std::fs::write(
            &f,
            r#"{"generatedAt":"2026-11-10 04:30","selected":[
                {"id":"udp://10.0.0.1","type":"udp"},
                {"id":"tls://dns.example","type":"dot"},
                {"id":"udp://168.95.1.1","type":"udp"},
                {"id":"udp://101.101.101.101","type":"udp"},
                {"id":"udp://9.9.9.9","type":"udp"}]}"#,
        )
        .unwrap();
        let m = Manager::new(&cfg(), f.clone());
        let ids: Vec<String> = m.active().iter().map(|u| u.up.id.clone()).collect();
        // 固定上游在前；評測結果裡跟固定上游重複的、類型不允許的略過；最多 autoMax 個
        assert_eq!(ids, vec!["udp://10.0.0.1:53", "udp://168.95.1.1:53", "udp://101.101.101.101:53"]);
        assert_eq!(m.backup().len(), 2);

        // 自動上游連續失敗 5 次 → 暫停
        let a = m.active()[1].clone();
        for _ in 0..5 {
            a.record(false, 0.0);
        }
        assert_eq!(m.active().len(), 2);
        assert_eq!(a.json()["paused"], json!(true));
        // 固定上游永不暫停
        for _ in 0..20 {
            m.pinned[0].record(false, 0.0);
        }
        assert_eq!(m.active()[0].up.id, "udp://10.0.0.1:53");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unsynced_clock_uses_plain_only() {
        let ups = |specs: &[&str], role| build(&specs.iter().map(|s| s.to_string()).collect::<Vec<_>>(), role);
        let ids = |v: Vec<Arc<Up>>| v.iter().map(|u| u.up.id.clone()).collect::<Vec<_>>();
        let list = ups(
            &["https://dns.example.net/dns-query", "udp://192.0.2.1", "tls://dns.example.com"],
            Role::Auto,
        );
        let fb = ups(&["https://dns.example.org/dns-query", "udp://198.51.100.1"], Role::Fallback);
        let lr = ups(&["tcp://203.0.113.1"], Role::LastResort);
        // 已對時：原本的行為
        assert_eq!(select_active(list.clone(), &fb, &lr, true).len(), 3);
        assert_eq!(ids(select_active(vec![], &fb, &lr, true)).len(), 2);
        // 沒對時：只留明文的
        assert_eq!(ids(select_active(list.clone(), &fb, &lr, false)), vec!["udp://192.0.2.1:53"]);
        // 主要上游全是加密的：改用備援裡的明文上游，再沒有就用最後手段
        let enc = ups(&["https://dns.example.net/dns-query", "quic://dns.example.com"], Role::Pinned);
        assert_eq!(ids(select_active(enc.clone(), &fb, &lr, false)), vec!["udp://198.51.100.1:53"]);
        let fb_enc = ups(&["https://dns.example.org/dns-query"], Role::Fallback);
        assert_eq!(ids(select_active(enc.clone(), &fb_enc, &lr, false)), vec!["tcp://203.0.113.1:53"]);
        // 全都是加密的：不問（問了也只會憑證錯誤、把上游記成失敗）
        assert!(select_active(enc, &fb_enc, &[], false).is_empty());
    }

    #[test]
    fn no_state_uses_pinned_or_fallback() {
        let m = Manager::new(&cfg(), PathBuf::from("/nonexistent/upstreams.json"));
        assert_eq!(m.active().len(), 1);
        let c = kuroshio_config::with_overrides(&json!({ "upstream": { "pinned": [], "fallback": ["udp://1.0.0.2"] } }));
        let m = Manager::new(&c, PathBuf::from("/nonexistent/upstreams.json"));
        assert_eq!(m.active()[0].role, Role::Fallback);
    }

    fn ups(specs: &[&str], role: Role) -> Vec<Arc<Up>> {
        build(&specs.iter().map(|s| s.to_string()).collect::<Vec<_>>(), role)
    }

    fn ids(v: &[Arc<Up>]) -> Vec<String> {
        v.iter().map(|u| u.up.id.clone()).collect()
    }

    fn chain_up(spec: &str) -> Arc<Up> {
        Up::new_chain(Upstream::parse(spec).unwrap(), Arc::new(Trouble::default()))
    }

    #[test]
    fn chain_active_and_backup_rules() {
        let pinned = ups(&["tls://dns.example.com"], Role::Pinned);
        let auto = ups(&["https://dns.example.net/dns-query", "udp://203.0.113.53"], Role::Auto);
        let fb = ups(&["udp://198.51.100.53"], Role::Fallback);
        let lr = ups(&["tcp://192.0.2.53"], Role::LastResort);
        let chain = chain_up("udp://192.168.1.1:53");

        // 沒有串接上游：跟 3.3.7 一樣（固定 + 自動；備援 + 最後手段）
        let (a, b) = select_chain(None, false, &pinned, auto.clone(), &fb, &lr);
        assert_eq!(ids(&a), [ids(&pinned), ids(&auto)].concat());
        assert_eq!(ids(&b), [ids(&fb), ids(&lr)].concat());

        // 串接中、健康：只有串接上游 + 固定上游；自動上游移到備援
        let (a, b) = select_chain(Some(&chain), false, &pinned, auto.clone(), &fb, &lr);
        assert_eq!(
            ids(&a),
            vec!["udp://192.168.1.1:53".to_string(), "tls://dns.example.com:853".into()]
        );
        assert_eq!(a[0].role, Role::Chain);
        assert!(ids(&b).contains(&"https://dns.example.net/dns-query".to_string()), "{:?}", ids(&b));
        assert!(b.iter().all(|u| u.role != Role::Chain));

        // 暫停中：主要上游跟沒串接時一樣
        let (a, _) = select_chain(Some(&chain), true, &pinned, auto.clone(), &fb, &lr);
        assert_eq!(ids(&a), [ids(&pinned), ids(&auto)].concat());

        // 一般 DNS 被接走：備援去掉經由攔截者的明文上游，留下自己的加密上游
        let mut r = kuroshio_net::path::Report::default();
        r.plain_v4.udp = true;
        kuroshio_net::path::apply(&r, false);
        let (_, b) = select_chain(Some(&chain), false, &pinned, auto.clone(), &fb, &lr);
        assert_eq!(ids(&b), vec!["https://dns.example.net/dns-query".to_string()]);
        assert!(!chain.via_interceptor(), "串接上游不算經由攔截者");
        let (_, b) = select_chain(None, false, &pinned, auto.clone(), &fb, &lr);
        assert_eq!(b.len(), 2, "沒串接時備援照舊");
        kuroshio_net::path::clear();
    }

    /// 3.4.2：時好時壞的自動上游，暫停時間照樣拉長（1 → 2 分鐘），不會被暫停結束後的一筆成功歸零
    #[test]
    fn flapping_auto_upstream_backs_off() {
        let u = Up::new(Upstream::parse("tls://dns.example.net").unwrap(), Role::Auto);
        let fail5 = |u: &Up| (0..5).for_each(|_| u.record(false, 0.0));
        let pause_left = |u: &Up| {
            u.stats
                .lock()
                .unwrap()
                .open_until
                .unwrap()
                .saturating_duration_since(Instant::now())
        };
        fail5(&u);
        assert!(pause_left(&u) <= Duration::from_secs(60));
        // 暫停結束（把時間撥到過去），答對一筆，又連續失敗
        u.stats.lock().unwrap().open_until = Some(Instant::now() - Duration::from_secs(1));
        u.record(true, 5.0);
        fail5(&u);
        assert!(pause_left(&u) > Duration::from_secs(90), "第二次暫停 2 分鐘");
        // 暫停結束已經超過 10 分鐘：歸零（開機不到 10 分鐘的機器上 Instant 撥不回去，略過這一段）
        if let Some(t) = Instant::now().checked_sub(TRIP_RESET + Duration::from_secs(1)) {
            u.stats.lock().unwrap().open_until = Some(t);
            u.record(true, 5.0);
            fail5(&u);
            assert!(pause_left(&u) <= Duration::from_secs(60), "穩定 10 分鐘之後重新從 1 分鐘算");
        }
    }

    #[test]
    fn chain_breaker_trips_after_three() {
        let m = Manager::new(&cfg(), PathBuf::from("/nonexistent/upstreams.json"));
        let n = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let n2 = n.clone();
        m.on_chain_trouble(Arc::new(move |_| {
            n2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }));
        m.set_chain(Some(Upstream::parse("udp://192.168.1.1:53").unwrap()));
        let c = m.chain().unwrap();
        assert_eq!(m.active()[0].role, Role::Chain);
        c.record(false, 0.0);
        c.record(false, 0.0);
        c.record(true, 5.0);
        c.record(false, 0.0);
        c.record(false, 0.0);
        assert!(!m.chain_suspended(), "成功一次就歸零");
        c.record(false, 0.0);
        assert!(m.chain_suspended());
        assert_eq!(n.load(std::sync::atomic::Ordering::SeqCst), 1, "回呼被呼叫一次");
        assert!(m.active().iter().all(|u| u.role != Role::Chain), "暫停中不問串接上游");
        assert_eq!(c.json()["role"], "chain");
        assert_eq!(m.list_json()[0]["role"], "chain");
        m.set_chain(None);
        assert!(m.chain().is_none() && !m.chain_suspended());
    }

    fn pause_left(u: &Up) -> Duration {
        u.stats
            .lock()
            .unwrap()
            .open_until
            .map_or(Duration::ZERO, |t| t.saturating_duration_since(Instant::now()))
    }

    /// 3.4.3：串接上游一直失敗、心跳卻正常時，暫停時間逐次加倍（最多 10 分鐘），回呼帶著第幾次
    #[test]
    fn chain_pause_doubles_and_reports_trips() {
        let m = Manager::new(&cfg(), PathBuf::from("/nonexistent/upstreams.json"));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s2 = seen.clone();
        m.on_chain_trouble(Arc::new(move |t| s2.lock().unwrap().push(t)));
        m.set_chain(Some(Upstream::parse("udp://192.168.1.1:53").unwrap()));
        let c = m.chain().unwrap();
        let mut pauses = Vec::new();
        for _ in 0..7 {
            for _ in 0..CHAIN_FAIL_LIMIT {
                c.record(false, 0.0);
            }
            pauses.push(pause_left(&c).as_secs());
            // 暫停結束（模擬）：下一輪的失敗才會再暫停
            c.stats.lock().unwrap().open_until = Some(Instant::now() - Duration::from_secs(1));
        }
        assert_eq!(*seen.lock().unwrap(), vec![1, 2, 3, 4, 5, 6, 7]);
        assert!(pauses[0] <= 30 && pauses[0] >= 29, "{pauses:?}");
        assert!(pauses[1] >= 59 && pauses[2] >= 119, "{pauses:?}");
        assert!(pauses.iter().all(|&p| p <= 600), "最多 10 分鐘：{pauses:?}");
        assert!(pauses[6] >= 599, "{pauses:?}");
    }

    /// 3.5.0 C2：同一台上游換位址（經攔截 → 直連閘道）不把暫停次數歸零；解除之後重新綁定才重新算
    #[test]
    fn rebinding_chain_keeps_trip_count() {
        let m = Manager::new(&cfg(), PathBuf::from("/nonexistent/upstreams.json"));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s2 = seen.clone();
        m.on_chain_trouble(Arc::new(move |t| s2.lock().unwrap().push(t)));
        m.set_chain(Some(Upstream::parse("udp://192.0.2.1:53").unwrap()));
        let trip = |m: &Manager| {
            let c = m.chain().unwrap();
            c.stats.lock().unwrap().open_until = Some(Instant::now() - Duration::from_secs(1));
            for _ in 0..CHAIN_FAIL_LIMIT {
                c.record(false, 0.0);
            }
        };
        trip(&m);
        trip(&m);
        // 換位址：次數帶過去，下一次是第 3 次
        m.set_chain(Some(Upstream::parse("udp://192.168.1.1:53").unwrap()));
        assert_eq!(m.chain().unwrap().up.id, "udp://192.168.1.1:53");
        assert_eq!(m.chain().unwrap().stats.lock().unwrap().trips, 2);
        trip(&m);
        assert_eq!(*seen.lock().unwrap(), vec![1, 2, 3]);
        // 解除再綁定：重新算
        m.set_chain(None);
        m.set_chain(Some(Upstream::parse("udp://192.168.1.1:53").unwrap()));
        assert_eq!(m.chain().unwrap().stats.lock().unwrap().trips, 0);
    }

    #[test]
    fn chain_same_as_pinned_not_duplicated() {
        let m = Manager::new(&cfg(), PathBuf::from("/nonexistent/upstreams.json"));
        m.set_chain(Some(Upstream::parse("udp://10.0.0.1").unwrap()));
        let a = m.active();
        assert_eq!(ids(&a), vec!["udp://10.0.0.1:53"]);
        assert_eq!(m.chain().unwrap().role, Role::Pinned, "角色維持固定上游");
        assert_eq!(m.list_json().as_array().unwrap().len(), 2, "固定 + 備援，沒有重複");
        // 固定上游永不暫停
        for _ in 0..10 {
            m.chain().unwrap().record(false, 0.0);
        }
        assert!(!m.chain_suspended());
    }

    #[test]
    fn unsynced_clock_keeps_chain() {
        let pinned = ups(&["https://dns.example.com/dns-query"], Role::Pinned);
        let chain = chain_up("udp://192.168.1.1:53");
        let (a, _) = select_chain(Some(&chain), false, &pinned, vec![], &[], &[]);
        let a = select_active(a, &[], &[], false);
        assert_eq!(ids(&a), vec!["udp://192.168.1.1:53"], "串接上游是明文，沒對時也能用");
        let tcp = chain_up("tcp://192.168.1.1:53");
        let (a, _) = select_chain(Some(&tcp), false, &pinned, vec![], &[], &[]);
        assert_eq!(select_active(a, &[], &[], false)[0].role, Role::Chain);
    }

    // ---------------- 3.5.0 A7：一直沒成功的自動上游 ----------------

    fn manager_with(name: &str, body: &str, extra: Value) -> (PathBuf, Manager) {
        let dir = std::env::temp_dir().join(format!("kuroshio-a7-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("upstreams.json");
        std::fs::write(&f, body).unwrap();
        let mut c = kuroshio_config::with_overrides(&json!({
            "upstream": { "pinned": [], "fallback": ["udp://198.51.100.53"], "autoTypes": ["udp", "doh", "dot"], "autoMax": 3 },
            "benchmark": { "minAuto": 3 }
        }));
        kuroshio_config::merge(&mut c, &extra);
        (dir, Manager::new(&c, f))
    }

    fn auto_by(m: &Manager, id: &str) -> Arc<Up> {
        let a = m.auto.read().unwrap();
        a.list.iter().chain(&a.spares).find(|u| u.up.id == id).cloned().unwrap()
    }

    /// 連續失敗 5 筆（同一個時間點）
    fn fail5_at(u: &Up, t: Instant) {
        (0..5).for_each(|_| u.record_at(false, 0.0, t));
    }

    /// 三次暫停：1 分鐘、2 分鐘、第三次（回傳第三次的時間）。`peer` 是別的上游，`peer_ok` 時在每一輪之前成功一次
    fn three_trips(u: &Up, peer: &Up, peer_ok: bool, t0: Instant) -> Instant {
        let mut t = t0;
        for step in [61, 121, 0] {
            if peer_ok {
                peer.record_at(true, 5.0, t);
            }
            fail5_at(u, t);
            if step > 0 {
                t += Duration::from_secs(step);
            }
        }
        t
    }

    const TWO: &str = r#"{"generatedAt":"2026-11-10T04:00:00Z","selected":[
        {"id":"tls://never.example.com","type":"dot"},{"id":"tls://good.example.net","type":"dot"}]}"#;

    #[test]
    fn never_ok_auto_is_benched_after_three_trips() {
        let (dir, m) = manager_with("bench", TWO, json!({}));
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c2 = calls.clone();
        m.on_auto_benched(Arc::new(move || {
            c2.fetch_add(1, Ordering::SeqCst);
        }));
        let (bad, good) = (
            auto_by(&m, "tls://never.example.com:853"),
            auto_by(&m, "tls://good.example.net:853"),
        );
        let t0 = Instant::now();
        // 前兩次照舊 1 → 2 分鐘（從未成功也一樣），第三次才先不用
        good.record_at(true, 5.0, t0);
        fail5_at(&bad, t0);
        assert!(!bad.benched());
        assert!(pause_left_at(&bad, t0) <= Duration::from_secs(60));
        let t1 = t0 + Duration::from_secs(61);
        good.record_at(true, 5.0, t1);
        fail5_at(&bad, t1);
        assert!(!bad.benched());
        assert!(pause_left_at(&bad, t1) <= Duration::from_secs(120));
        let t2 = t1 + Duration::from_secs(121);
        good.record_at(true, 5.0, t2);
        fail5_at(&bad, t2);
        assert!(bad.benched(), "上線以來從未成功、第 3 次暫停、別的上游有成功");
        assert!(pause_left_at(&bad, t2) > Duration::from_secs(6 * 3600 - 5));
        assert_eq!(bad.json()["benched"], true);
        assert_eq!(bad.json()["paused"], true);
        assert_eq!(calls.load(Ordering::SeqCst), 1, "通知一次");
        assert!(
            take_never_ok().contains(&"tls://never.example.com:853".to_string()),
            "登記給下一次評測"
        );
        // 成功過的上游照舊 1 → 2 → 4 分鐘（時好時壞，不先不用）
        let t3 = t2 + Duration::from_secs(1);
        fail5_at(&good, t3);
        fail5_at(&good, t3 + Duration::from_secs(61));
        fail5_at(&good, t3 + Duration::from_secs(182));
        assert!(!good.benched());
        assert!(pause_left_at(&good, t3 + Duration::from_secs(182)) <= Duration::from_secs(240));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn pause_left_at(u: &Up, t: Instant) -> Duration {
        u.stats
            .lock()
            .unwrap()
            .open_until
            .map_or(Duration::ZERO, |x| x.saturating_duration_since(t))
    }

    #[test]
    fn benched_probe_every_six_hours_and_recovers() {
        let (dir, m) = manager_with("probe", TWO, json!({}));
        let (bad, good) = (
            auto_by(&m, "tls://never.example.com:853"),
            auto_by(&m, "tls://good.example.net:853"),
        );
        let t0 = Instant::now();
        let t = three_trips(&bad, &good, true, t0);
        assert!(bad.benched());
        assert_eq!(bad.avail(t + Duration::from_secs(3600)), Avail::Off, "6 小時內不問");
        // 6 小時到了：只放 1 筆試探
        let p1 = t + BENCH_PAUSE + Duration::from_secs(1);
        assert_eq!(bad.avail(p1), Avail::Probe);
        assert_eq!(bad.avail(p1), Avail::Off, "同一段時間只放 1 筆");
        assert_eq!(
            bad.avail(p1 + PROBE_HOLD + Duration::from_secs(1)),
            Avail::Probe,
            "那筆沒被問到：過一下再放"
        );
        // 試探失敗：再等 6 小時（不必再累積 5 筆）
        bad.record_at(false, 0.0, p1 + PROBE_HOLD + Duration::from_secs(2));
        assert!(bad.benched());
        assert!(pause_left_at(&bad, p1 + PROBE_HOLD + Duration::from_secs(2)) > BENCH_PAUSE - Duration::from_secs(5));
        // 下一次試探成功：恢復，照常使用
        let p2 = p1 + PROBE_HOLD + BENCH_PAUSE + Duration::from_secs(3);
        assert_eq!(bad.avail(p2), Avail::Probe);
        bad.record_at(true, 8.0, p2);
        assert!(!bad.benched());
        assert_eq!(bad.avail(p2), Avail::Ok);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn not_benched_when_no_upstream_succeeds() {
        // 全部都失敗（整台斷網）：照舊 1 → 2 → 4 分鐘，不先不用
        let (dir, m) = manager_with("offline", TWO, json!({}));
        let (bad, other) = (
            auto_by(&m, "tls://never.example.com:853"),
            auto_by(&m, "tls://good.example.net:853"),
        );
        let t = three_trips(&bad, &other, false, Instant::now());
        assert!(!bad.benched());
        assert!(pause_left_at(&bad, t) <= Duration::from_secs(240) && pause_left_at(&bad, t) > Duration::from_secs(200));
        // 別的上游很久以前成功過（超過 10 分鐘）：也不算
        let (dir2, m2) = manager_with("offline-old", TWO, json!({}));
        let (bad, other) = (
            auto_by(&m2, "tls://never.example.com:853"),
            auto_by(&m2, "tls://good.example.net:853"),
        );
        let t0 = Instant::now();
        other.record_at(true, 5.0, t0);
        three_trips(&bad, &other, false, t0 + PEER_OK_WINDOW + Duration::from_secs(1));
        assert!(!bad.benched());
        // 固定上游、備援成功也算「網路是通的」
        let (dir3, m3) = manager_with("offline-fb", TWO, json!({}));
        let bad = auto_by(&m3, "tls://never.example.com:853");
        let t0 = Instant::now();
        m3.fallback[0].record_at(true, 5.0, t0);
        fail5_at(&bad, t0);
        fail5_at(&bad, t0 + Duration::from_secs(61));
        m3.fallback[0].record_at(true, 5.0, t0 + Duration::from_secs(182));
        fail5_at(&bad, t0 + Duration::from_secs(182));
        assert!(bad.benched());
        for d in [dir, dir2, dir3] {
            std::fs::remove_dir_all(&d).unwrap();
        }
    }

    const WITH_SPARES: &str = r#"{"generatedAt":"2026-11-10T04:00:00Z","selected":[
        {"id":"udp://192.0.2.1","type":"udp"},{"id":"udp://192.0.2.2","type":"udp"},{"id":"udp://192.0.2.3","type":"udp"}],
        "spares":[{"id":"udp://192.0.2.2","type":"udp"},{"id":"quic://dns.example.com","type":"doq"},
        {"id":"udp://198.51.100.4","type":"udp","reason":"候補"},{"id":"udp://198.51.100.5","type":"udp"},
        {"id":"udp://198.51.100.6","type":"udp"},{"id":"udp://198.51.100.7","type":"udp"}]}"#;

    #[test]
    fn spares_fill_when_usable_below_min() {
        let (dir, m) = manager_with("spares", WITH_SPARES, json!({}));
        // 候補：跟 selected 重複的、類型不允許的不算，最多 3 台
        let sp: Vec<String> = m.auto.read().unwrap().spares.iter().map(|u| u.up.id.clone()).collect();
        assert_eq!(sp, ["udp://198.51.100.4:53", "udp://198.51.100.5:53", "udp://198.51.100.6:53"]);
        assert_eq!(m.auto_info()["spares"], 3);
        let list = m.list_json();
        let spare = list
            .as_array()
            .unwrap()
            .iter()
            .find(|u| u["id"] == "udp://198.51.100.4:53")
            .unwrap()
            .clone();
        assert_eq!((spare["spare"].clone(), spare["reason"].clone()), (json!(true), json!("候補")));
        // 夠用：不問候補
        assert_eq!(ids(&m.active()), ["udp://192.0.2.1:53", "udp://192.0.2.2:53", "udp://192.0.2.3:53"]);
        assert!(!m.auto_short());
        // 一台暫停：依序補上第一台候補
        let a = auto_by(&m, "udp://192.0.2.1:53");
        (0..5).for_each(|_| a.record(false, 0.0));
        assert_eq!(
            ids(&m.active()),
            ["udp://192.0.2.2:53", "udp://192.0.2.3:53", "udp://198.51.100.4:53"]
        );
        // 候補也暫停：再補下一台
        let s1 = auto_by(&m, "udp://198.51.100.4:53");
        (0..5).for_each(|_| s1.record(false, 0.0));
        assert_eq!(
            ids(&m.active()),
            ["udp://192.0.2.2:53", "udp://192.0.2.3:53", "udp://198.51.100.5:53"]
        );
        assert!(!m.auto_short(), "還有候補");
        for id in ["udp://192.0.2.2:53", "udp://198.51.100.5:53", "udp://198.51.100.6:53"] {
            let u = auto_by(&m, id);
            (0..5).for_each(|_| u.record(false, 0.0));
        }
        assert!(m.auto_short(), "連候補都不夠");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn old_state_without_spares_unchanged() {
        let body = r#"{"generatedAt":"2026-11-10T04:00:00Z","selected":[
            {"id":"udp://192.0.2.1","type":"udp"},{"id":"udp://192.0.2.2","type":"udp"},{"id":"udp://192.0.2.3","type":"udp"}]}"#;
        let (dir, m) = manager_with("nospares", body, json!({}));
        assert_eq!(m.auto_info()["spares"], 0);
        let a = auto_by(&m, "udp://192.0.2.1:53");
        (0..5).for_each(|_| a.record(false, 0.0));
        assert_eq!(ids(&m.active()), ["udp://192.0.2.2:53", "udp://192.0.2.3:53"], "跟 3.4.4 一樣");
        assert!(m.auto_short());
        assert!(m.list_json().as_array().unwrap().iter().all(|u| u.get("spare").is_none()));
        // autoMax = 0：候補也不載入
        let (dir2, m2) = manager_with("nospares0", WITH_SPARES, json!({ "upstream": { "autoMax": 0 } }));
        assert!(m2.auto.read().unwrap().spares.is_empty());
        assert!(!m2.auto_short(), "沒用自動上游");
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::remove_dir_all(&dir2).unwrap();
    }
}
