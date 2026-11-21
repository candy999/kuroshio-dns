//! 路徑檢查（3.3.6）：判斷「這台機器到網際網路的路上」有沒有人動手腳，而不是哪台上游壞了。
//!
//! - IPv6 能不能用：不送封包的路由檢查（UDP connect 看系統選哪個來源位址），加上連線時遇到
//!   「位址不可用」「網路無法到達」就暫停 IPv6 一段時間
//! - 一般 DNS（53 埠）有沒有被接走：對文件用的保留位址（192.0.2.1、198.51.100.1、2001:db8::1）查詢，
//!   這些位址不會有 DNS 伺服器，有回答就是路上有人把 53 埠全部轉走（上游路由器、業者的透明代理）。UDP、TCP 分開測
//! - 攔截者是誰：CHAOS TXT `version.kuroshio`（黑潮 3.3.6 起會回答）→ 上游黑潮；`version.bind` → 一般 DNS 軟體；
//!   都沒有 → 不明（業者或其他設備）。預設閘道一起記下
//! - 把「不存在」改成位址：`.invalid` 底下的隨機名稱一定不存在（RFC 6761），回答了位址就是被改寫
//! - 竄改：問已知答案的名稱（dns.google、one.one.one.one），答案不對就是被竄改（bootstrap 改用 IP 直連的 DoH）
//! - 加密協定整條被擋：DoT 853、DoH 443、QUIC（DoH3 / DoQ）各試幾台知名伺服器；某個協定全部失敗、其他協定可以，
//!   就是這條路擋了這個協定，不是那幾台伺服器壞了
//! - TLS 中途攔截：好幾台都出現憑證錯誤
//!
//! 判斷結果放在全域狀態（[`apply`]），連線層（bootstrap、DoT / DoH / QUIC 的位址選擇）與評測照著用。

use crate::tls;
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, info};

// ---------------- IPv6 ----------------

/// `upstream_ipv6`：auto（依路由判斷）、1（一律使用）、0（不用 IPv6 連上游）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V6Mode {
    Auto,
    On,
    Off,
}

impl V6Mode {
    pub fn parse(s: &str) -> V6Mode {
        match s.trim().to_ascii_lowercase().as_str() {
            "1" | "on" | "true" | "yes" => V6Mode::On,
            "0" | "off" | "false" | "no" => V6Mode::Off,
            _ => V6Mode::Auto,
        }
    }
    /// 設定值：字串（"auto" / "0" / "1"）、數字（UCI 的 '0' 轉換後是數字 0）、布林都接受；沒設 = auto
    pub fn from_value(v: Option<&Value>) -> V6Mode {
        match v {
            Some(Value::String(s)) => V6Mode::parse(s),
            Some(Value::Number(n)) => match n.as_u64() {
                Some(0) => V6Mode::Off,
                Some(_) => V6Mode::On,
                None => V6Mode::Auto,
            },
            Some(Value::Bool(true)) => V6Mode::On,
            Some(Value::Bool(false)) => V6Mode::Off,
            _ => V6Mode::Auto,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            V6Mode::Auto => "auto",
            V6Mode::On => "1",
            V6Mode::Off => "0",
        }
    }
}

static V6_MODE: AtomicU8 = AtomicU8::new(0);

pub fn set_v6_mode(m: V6Mode) {
    V6_MODE.store(
        match m {
            V6Mode::Auto => 0,
            V6Mode::On => 1,
            V6Mode::Off => 2,
        },
        Ordering::Relaxed,
    );
}

pub fn v6_mode() -> V6Mode {
    match V6_MODE.load(Ordering::Relaxed) {
        1 => V6Mode::On,
        2 => V6Mode::Off,
        _ => V6Mode::Auto,
    }
}

/// 路由檢查的結果
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V6Route {
    /// 有路由，來源是全域位址
    Global,
    /// 有路由，但來源只有 ULA（fc00::/7）：可能是 NAT66，可以試，但連不上會暫停
    Ula,
    /// 沒有路由（或來源只有本機 / 鏈路本地位址）
    None(String),
}

impl V6Route {
    fn as_str(&self) -> &'static str {
        match self {
            V6Route::Global => "global",
            V6Route::Ula => "ula",
            V6Route::None(_) => "none",
        }
    }
}

/// 路由檢查的目標（只用來讓系統選路由，不會送出封包）
const V6_ROUTE_PROBE: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)), 53);
/// 路由檢查結果快取多久（系統呼叫很便宜，但每次連線都做沒必要）
const V6_ROUTE_TTL: Duration = Duration::from_secs(30);
/// 連線時遇到「位址不可用 / 網路無法到達」後暫停 IPv6 多久
const V6_BACKOFF: Duration = Duration::from_secs(600);

fn route_cache() -> &'static Mutex<Option<(Instant, V6Route)>> {
    static C: OnceLock<Mutex<Option<(Instant, V6Route)>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(None))
}

fn backoff() -> &'static Mutex<Option<Instant>> {
    static B: OnceLock<Mutex<Option<Instant>>> = OnceLock::new();
    B.get_or_init(|| Mutex::new(None))
}

/// 這台系統有沒有 IPv6（連 ::1 都綁不了 = 核心沒開 IPv6，或韌體把 IPv6 關掉）
pub fn system_has_ipv6() -> bool {
    std::net::UdpSocket::bind("[::1]:0").is_ok()
}

/// 不送封包的路由檢查：UDP connect 到一個公開的 IPv6 位址，看系統選了哪個來源位址
pub fn v6_route_now() -> V6Route {
    let s = match std::net::UdpSocket::bind("[::]:0") {
        Ok(s) => s,
        Err(e) => return V6Route::None(format!("系統沒有 IPv6（{e}）")),
    };
    if let Err(e) = s.connect(V6_ROUTE_PROBE) {
        return V6Route::None(format!("沒有 IPv6 路由（{e}）"));
    }
    match s.local_addr() {
        Ok(SocketAddr::V6(a)) => classify_v6_source(*a.ip()),
        Ok(_) => V6Route::None("來源位址不是 IPv6".into()),
        Err(e) => V6Route::None(format!("讀不到來源位址（{e}）")),
    }
}

fn classify_v6_source(ip: Ipv6Addr) -> V6Route {
    let s = ip.segments();
    if ip.is_unspecified() || ip.is_loopback() {
        V6Route::None("沒有可用的 IPv6 位址".into())
    } else if s[0] & 0xffc0 == 0xfe80 {
        V6Route::None("只有鏈路本地位址（fe80::）".into())
    } else if s[0] & 0xfe00 == 0xfc00 {
        V6Route::Ula
    } else {
        V6Route::Global
    }
}

fn v6_route_cached() -> V6Route {
    let now = Instant::now();
    let mut c = route_cache().lock().unwrap();
    if let Some((t, r)) = c.as_ref() {
        if now.duration_since(*t) < V6_ROUTE_TTL {
            return r.clone();
        }
    }
    let r = v6_route_now();
    *c = Some((now, r.clone()));
    r
}

fn in_backoff() -> bool {
    let mut b = backoff().lock().unwrap();
    match *b {
        Some(t) if Instant::now() < t => true,
        Some(_) => {
            *b = None;
            false
        }
        None => false,
    }
}

/// 現在能不能用 IPv6 連上游
pub fn v6_usable() -> bool {
    match v6_mode() {
        V6Mode::On => true,
        V6Mode::Off => false,
        V6Mode::Auto => !matches!(v6_route_cached(), V6Route::None(_)) && !in_backoff(),
    }
}

/// 連線錯誤是不是「這台機器沒有 IPv6 / 到不了」（不是對方的問題）
pub fn is_no_route(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    if e.kind() == ErrorKind::AddrNotAvailable {
        return true;
    }
    // NetworkUnreachable / HostUnreachable 在 Rust 1.83 才穩定；用名稱比對，舊版編譯器也能編
    let k = format!("{:?}", e.kind());
    k == "NetworkUnreachable" || k == "HostUnreachable"
}

/// 連線失敗時呼叫：IPv6 位址遇到「沒有路由」就暫停 IPv6（auto 模式）
pub fn note_conn_error(ip: IpAddr, e: &std::io::Error) {
    if ip.is_ipv6() && v6_mode() == V6Mode::Auto && is_no_route(e) {
        let mut b = backoff().lock().unwrap();
        if b.map(|t| t <= Instant::now()).unwrap_or(true) {
            info!("IPv6 連線失敗（{e}），暫停用 IPv6 連上游 {} 分鐘", V6_BACKOFF.as_secs() / 60);
        }
        *b = Some(Instant::now() + V6_BACKOFF);
    }
}

/// 連線用的位址：不能用 IPv6 時拿掉 IPv6 位址（全部都是 IPv6 時照原樣回傳，讓呼叫端得到原本的錯誤）
pub fn filter_addrs(mut ips: Vec<IpAddr>) -> Vec<IpAddr> {
    if ips.iter().any(|i| i.is_ipv6()) && ips.iter().any(|i| i.is_ipv4()) && !v6_usable() {
        ips.retain(|i| i.is_ipv4());
    }
    ips
}

/// 這個位址現在能不能用（IPv4 一律可以）
pub fn addr_usable(ip: IpAddr) -> bool {
    ip.is_ipv4() || v6_usable()
}

// ---------------- 全域判斷結果 ----------------

/// 加密協定
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Dot,
    Doh,
    Quic,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Dot => "dot",
            Proto::Doh => "doh",
            Proto::Quic => "quic",
        }
    }
    fn bit(self) -> u8 {
        match self {
            Proto::Dot => 1,
            Proto::Doh => 2,
            Proto::Quic => 4,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Proto::Dot => "DoT（853 埠）",
            Proto::Doh => "DoH（443 埠）",
            Proto::Quic => "QUIC（DoH3 / DoQ）",
        }
    }
}

static BLOCKED: AtomicU8 = AtomicU8::new(0);
static PLAIN_V4: AtomicBool = AtomicBool::new(false);
static PLAIN_V6: AtomicBool = AtomicBool::new(false);
static BOOT_DOH: AtomicBool = AtomicBool::new(false);
static CURRENT: RwLock<Option<Report>> = RwLock::new(None);

/// 這個協定是不是整條被擋（路徑檢查判斷的；沒檢查過 = 沒被擋）
pub fn blocked(p: Proto) -> bool {
    BLOCKED.load(Ordering::Relaxed) & p.bit() != 0
}

/// 一般 DNS 是不是被接走（`v6` = IPv6 那條）
pub fn plain_intercepted(v6: bool) -> bool {
    if v6 {
        PLAIN_V6.load(Ordering::Relaxed)
    } else {
        PLAIN_V4.load(Ordering::Relaxed)
    }
}

/// 一般 DNS 到這個位址會不會被接走
pub fn plain_intercepted_for(ip: IpAddr) -> bool {
    plain_intercepted(ip.is_ipv6())
}

/// bootstrap 改用 IP 直連的 DoH（一般 DNS 被竄改時）
pub fn bootstrap_via_doh() -> bool {
    BOOT_DOH.load(Ordering::Relaxed)
}

/// 最近一次檢查結果
pub fn current() -> Option<Report> {
    CURRENT.read().unwrap().clone()
}

/// 套用檢查結果（`ignore_intercept` = `intercept_policy ignore`：不把一般 DNS 當成被接走）
pub fn apply(r: &Report, ignore_intercept: bool) {
    let mut bits = 0u8;
    for p in &r.blocked {
        bits |= p.bit();
    }
    BLOCKED.store(bits, Ordering::Relaxed);
    PLAIN_V4.store(!ignore_intercept && r.plain_v4.intercepted(), Ordering::Relaxed);
    PLAIN_V6.store(
        !ignore_intercept && r.plain_v6.as_ref().is_some_and(|p| p.intercepted()),
        Ordering::Relaxed,
    );
    BOOT_DOH.store(r.bootstrap_tampered(), Ordering::Relaxed);
    *CURRENT.write().unwrap() = Some(r.clone());
}

/// 清掉判斷結果（`path_check 0`）
pub fn clear() {
    BLOCKED.store(0, Ordering::Relaxed);
    PLAIN_V4.store(false, Ordering::Relaxed);
    PLAIN_V6.store(false, Ordering::Relaxed);
    BOOT_DOH.store(false, Ordering::Relaxed);
    *CURRENT.write().unwrap() = None;
}

// ---------------- 檢查 ----------------

/// 檢查目標（測試時換成本機的假伺服器）
#[derive(Debug, Clone)]
pub struct Targets {
    /// 一般 DNS 攔截偵測：IPv4 保留位址
    pub testnet_v4: Vec<SocketAddr>,
    /// 一般 DNS 攔截偵測：IPv6 保留位址
    pub testnet_v6: Vec<SocketAddr>,
    /// 已知答案（名稱 → 正確的位址）：檢查一般 DNS 有沒有被竄改
    pub known: Vec<(String, Vec<IpAddr>)>,
    /// 一般 DNS 伺服器（不指定就用 bootstrap 伺服器）
    pub plain: Vec<SocketAddr>,
    /// DoT（位址, 主機名稱）
    pub dot: Vec<(SocketAddr, String)>,
    /// DoH（TCP 443）
    pub doh: Vec<(SocketAddr, String)>,
    /// QUIC（位址, 主機名稱, ALPN）
    pub quic: Vec<(SocketAddr, String, Vec<u8>)>,
    /// 一般 DNS 探測的逾時
    pub plain_timeout: Duration,
    /// 加密協定探測的逾時
    pub tls_timeout: Duration,
    /// 讀不讀系統的預設閘道（測試時關掉）
    pub read_gateway: bool,
    /// IPv6 路由（測試時直接指定）
    pub v6_route: Option<V6Route>,
}

impl Default for Targets {
    fn default() -> Targets {
        let v4 = |a: [u8; 4], p: u16| SocketAddr::new(IpAddr::V4(Ipv4Addr::from(a)), p);
        Targets {
            testnet_v4: vec![v4([192, 0, 2, 1], 53), v4([198, 51, 100, 1], 53)],
            testnet_v6: vec![SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), 53)],
            known: vec![
                ("dns.google".into(), vec![IpAddr::from([8, 8, 8, 8]), IpAddr::from([8, 8, 4, 4])]),
                (
                    "one.one.one.one".into(),
                    vec![IpAddr::from([1, 1, 1, 1]), IpAddr::from([1, 0, 0, 1])],
                ),
            ],
            plain: Vec::new(),
            dot: vec![
                (v4([1, 1, 1, 1], 853), "cloudflare-dns.com".into()),
                (v4([8, 8, 8, 8], 853), "dns.google".into()),
                (v4([9, 9, 9, 9], 853), "dns.quad9.net".into()),
            ],
            doh: vec![
                (v4([1, 1, 1, 1], 443), "cloudflare-dns.com".into()),
                (v4([8, 8, 8, 8], 443), "dns.google".into()),
                (v4([9, 9, 9, 9], 443), "dns.quad9.net".into()),
            ],
            quic: vec![
                (v4([1, 1, 1, 1], 443), "cloudflare-dns.com".into(), b"h3".to_vec()),
                (v4([8, 8, 8, 8], 443), "dns.google".into(), b"h3".to_vec()),
                (v4([94, 140, 14, 140], 853), "unfiltered.adguard-dns.com".into(), b"doq".to_vec()),
            ],
            plain_timeout: Duration::from_millis(1500),
            tls_timeout: Duration::from_secs(5),
            read_gateway: true,
            v6_route: None,
        }
    }
}

/// 一條一般 DNS 路徑（IPv4 或 IPv6）的攔截情形
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plain {
    pub udp: bool,
    pub tcp: bool,
}

impl Plain {
    pub fn intercepted(&self) -> bool {
        self.udp || self.tcp
    }
}

/// 攔截者
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Interceptor {
    /// 上游的黑潮（版本）
    Kuroshio(String),
    /// 一般 DNS 軟體（`version.bind` 的回答）
    Software(String),
    /// 不明（業者或其他設備）
    Unknown,
}

/// 被竄改的答案
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tamper {
    /// 誰回答的（"interceptor" 或伺服器位址）
    pub via: String,
    pub name: String,
    pub answer: Vec<IpAddr>,
}

/// 一個加密協定的探測結果
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProtoResult {
    pub ok: usize,
    pub fail: usize,
    pub cert_errors: usize,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Report {
    /// Unix 毫秒
    pub checked_at: u64,
    pub v6_mode: V6Mode,
    pub v6_route: V6Route,
    pub plain_v4: Plain,
    /// 沒有 IPv6 時是 None（沒測）
    pub plain_v6: Option<Plain>,
    pub interceptor: Option<Interceptor>,
    pub gateway: Option<IpAddr>,
    /// 「不存在」被改成的位址（空的 = 沒有被改）
    pub nx_rewrite: Vec<IpAddr>,
    pub nx_via: Option<String>,
    pub tampered: Vec<Tamper>,
    pub protocols: Vec<(Proto, ProtoResult)>,
    pub blocked: Vec<Proto>,
    /// 好幾台都出現憑證錯誤：路上有 TLS 攔截
    pub tls_intercept: Option<String>,
    /// 加密協定全部連不上（網路斷了）：這次不判斷協定被擋
    pub offline: bool,
    /// 一般 DNS 被接走時命中的保留位址（IPv4 優先；3.4.0 串接模式往這裡發挑戰）。`to_json()` 不輸出
    pub hit: Option<SocketAddr>,
    /// 命中的那條路只有 TCP 被接走（UDP 沒有）
    pub hit_tcp: bool,
}

/// 沒有任何狀況的結果（測試或手動建立用）
impl Default for Report {
    fn default() -> Report {
        Report {
            checked_at: 0,
            v6_mode: V6Mode::Auto,
            v6_route: V6Route::Global,
            plain_v4: Plain::default(),
            plain_v6: None,
            interceptor: None,
            gateway: None,
            nx_rewrite: Vec::new(),
            nx_via: None,
            tampered: Vec::new(),
            protocols: Vec::new(),
            blocked: Vec::new(),
            tls_intercept: None,
            offline: false,
            hit: None,
            hit_tcp: false,
        }
    }
}

impl Report {
    pub fn plain_intercepted(&self) -> bool {
        self.plain_v4.intercepted() || self.plain_v6.as_ref().is_some_and(|p| p.intercepted())
    }

    /// bootstrap（一般 DNS）有沒有被竄改：已知答案不對，或「不存在」被改寫
    pub fn bootstrap_tampered(&self) -> bool {
        !self.tampered.is_empty() || !self.nx_rewrite.is_empty()
    }

    pub fn v6_usable(&self) -> bool {
        match self.v6_mode {
            V6Mode::On => true,
            V6Mode::Off => false,
            V6Mode::Auto => !matches!(self.v6_route, V6Route::None(_)),
        }
    }

    /// 攔截者的白話說明
    pub fn interceptor_text(&self) -> String {
        match &self.interceptor {
            // 有閘道位址：「閘道 192.168.1.1 或更上游的路由器上的黑潮」；沒有：「路由器上的黑潮」（不留多的空格）
            // 攔截的不一定是閘道本身：兩層 NAT 時查詢經閘道轉出去、被更上游的黑潮接走（3.4.2 Windows 實測：
            // 預設路由改走 D3 時，接走的是上游 A，文字卻寫成「路由器 192.168.1.1 上的黑潮」）
            Some(Interceptor::Kuroshio(v)) => match self.gateway {
                Some(g) => format!("閘道 {g} 或更上游的路由器上的黑潮（{v}）"),
                None => format!("路由器上的黑潮（{v}）"),
            },
            Some(Interceptor::Software(v)) => format!("路由器或業者的 DNS 軟體（{v}）"),
            Some(Interceptor::Unknown) | None => "路由器或業者的設備（不明）".to_string(),
        }
    }

    pub fn to_json(&self) -> Value {
        let plain = |p: &Plain| json!({ "udp": p.udp, "tcp": p.tcp, "intercepted": p.intercepted() });
        let interceptor = self.interceptor.as_ref().map(|i| match i {
            Interceptor::Kuroshio(v) => json!({ "kind": "kuroshio", "version": v }),
            Interceptor::Software(v) => json!({ "kind": "dns-software", "version": v }),
            Interceptor::Unknown => json!({ "kind": "unknown" }),
        });
        let protocols: serde_json::Map<String, Value> = self
            .protocols
            .iter()
            .map(|(p, r)| {
                (
                    p.as_str().to_string(),
                    json!({ "ok": r.ok, "fail": r.fail, "certErrors": r.cert_errors, "lastError": r.last_error }),
                )
            })
            .collect();
        json!({
            "checkedAt": self.checked_at,
            "ipv6": {
                "mode": self.v6_mode.as_str(),
                "route": self.v6_route.as_str(),
                "usable": self.v6_usable(),
                "reason": match &self.v6_route { V6Route::None(r) => Value::from(r.clone()), _ => Value::Null },
            },
            "plain": {
                "intercepted": self.plain_intercepted(),
                "v4": plain(&self.plain_v4),
                "v6": self.plain_v6.as_ref().map(plain),
            },
            "interceptor": interceptor,
            "interceptorText": if self.plain_intercepted() { Value::from(self.interceptor_text()) } else { Value::Null },
            "gateway": self.gateway.map(|g| g.to_string()),
            "nxRewrite": self.nx_rewrite.iter().map(|i| i.to_string()).collect::<Vec<_>>(),
            "nxVia": self.nx_via,
            "tampered": self.tampered.iter().map(|t| json!({
                "via": t.via, "name": t.name, "answer": t.answer.iter().map(|i| i.to_string()).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "bootstrapViaDoh": self.bootstrap_tampered(),
            "protocols": protocols,
            "blocked": self.blocked.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
            "tlsIntercept": self.tls_intercept,
            "offline": self.offline,
        })
    }

    /// 給狀態頁的白話提醒（沒有狀況 = 空的）
    pub fn warnings(&self, policy: &str) -> Vec<String> {
        let mut w = Vec::new();
        if self.plain_intercepted() {
            let which = match (self.plain_v4.udp, self.plain_v4.tcp) {
                (true, false) => "（只有 UDP）",
                (false, true) => "（只有 TCP）",
                _ => "",
            };
            let effect = match policy {
                "warn" => "評測照常測一般 DNS，但它們的答案其實都來自攔截者",
                "ignore" => "",
                _ => "評測不測一般 DNS，一般 DNS 只當最後備援",
            };
            // 「一般 DNS 被…」：中文前後的英文留空格；括號說明時接在括號後面
            let mut s = if which.is_empty() {
                format!("一般 DNS 被{}接走", self.interceptor_text())
            } else {
                format!("一般 DNS{which}被{}接走", self.interceptor_text())
            };
            if !effect.is_empty() {
                s.push('：');
                s.push_str(effect);
            }
            w.push(s);
        }
        if !self.nx_rewrite.is_empty() {
            let ips: Vec<String> = self.nx_rewrite.iter().map(|i| i.to_string()).collect();
            w.push(format!(
                "一般 DNS 把不存在的網域改成 {}（廣告頁或導向頁）：主機名稱改用加密 DNS 解析",
                ips.join("、")
            ));
        }
        if !self.tampered.is_empty() {
            let t = &self.tampered[0];
            w.push(format!("一般 DNS 回答的 {} 不正確（被竄改）：主機名稱改用加密 DNS 解析", t.name));
        }
        for p in &self.blocked {
            w.push(format!("這條網路擋了 {}：先不用這種上游，恢復後自動加回", p.label()));
        }
        if let Some(t) = &self.tls_intercept {
            w.push(format!(
                "加密連線被中途攔截（好幾台伺服器的憑證都不對：{t}）：加密 DNS 可能無法使用"
            ));
        }
        w
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn rand16() -> u16 {
    let n = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
    static C: AtomicU8 = AtomicU8::new(0);
    let c = C.fetch_add(1, Ordering::Relaxed) as u32;
    let mut x = n ^ (c.wrapping_mul(0x9e37_79b9)) ^ std::process::id().rotate_left(16);
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    x as u16
}

fn rand_label() -> String {
    format!("k{:04x}{:04x}{:04x}", rand16(), rand16(), rand16())
}

/// CHAOS 類別的查詢（`version.bind`、`version.kuroshio`）
pub fn build_chaos_txt(id: u16, name: &str) -> Vec<u8> {
    let mut q = kuroshio_proto::build_query(id, name, 16);
    let n = q.len();
    q[n - 2..].copy_from_slice(&3u16.to_be_bytes());
    q
}

async fn udp_ask(addr: SocketAddr, q: &[u8], limit: Duration) -> Result<Vec<u8>> {
    let bind: SocketAddr = if addr.is_ipv4() { "0.0.0.0:0".parse()? } else { "[::]:0".parse()? };
    let s = UdpSocket::bind(bind).await?;
    s.connect(addr).await?;
    s.send(q).await?;
    let mut buf = vec![0u8; 4096];
    tokio::time::timeout(limit, async {
        loop {
            let n = s.recv(&mut buf).await?;
            if kuroshio_proto::matches(q, &buf[..n]) {
                return Ok::<_, anyhow::Error>(buf[..n].to_vec());
            }
        }
    })
    .await
    .map_err(|_| anyhow!("逾時"))?
}

async fn tcp_ask(addr: SocketAddr, q: &[u8], limit: Duration) -> Result<Vec<u8>> {
    tokio::time::timeout(limit, async {
        let mut s = TcpStream::connect(addr).await?;
        let mut msg = (q.len() as u16).to_be_bytes().to_vec();
        msg.extend_from_slice(q);
        s.write_all(&msg).await?;
        loop {
            let len = s.read_u16().await? as usize;
            let mut buf = vec![0u8; len];
            s.read_exact(&mut buf).await?;
            if kuroshio_proto::matches(q, &buf) {
                return Ok::<_, anyhow::Error>(buf);
            }
        }
    })
    .await
    .map_err(|_| anyhow!("逾時"))?
}

// ---------------- CH TXT（3.4.0 串接模式的通道） ----------------

/// 一次 CH TXT 查詢的結果
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChaosReply {
    pub rcode: u16,
    /// 第一筆 TXT 記錄的全部字串接起來（二進位，不是文字）；沒有 TXT 是 None
    pub txt: Option<Vec<u8>>,
}

/// TXT 的 RDATA → 所有字串接起來；被截斷 → None
fn txt_concat(rdata: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(rdata.len());
    let mut i = 0;
    while i < rdata.len() {
        let n = rdata[i] as usize;
        out.extend_from_slice(rdata.get(i + 1..i + 1 + n)?);
        i += 1 + n;
    }
    Some(out)
}

fn chaos_reply(resp: &[u8]) -> Result<ChaosReply> {
    let m = kuroshio_proto::Message::parse(resp).map_err(|e| anyhow!("回應格式錯誤：{e}"))?;
    let txt = m.answers.iter().find(|r| r.rtype == 16).and_then(|r| match &r.data {
        kuroshio_proto::message::RData::Raw(b) => txt_concat(b),
        _ => None,
    });
    Ok(ChaosReply { rcode: m.rcode, txt })
}

/// CH TXT 查詢的封包；`opt` = 要帶的 EDNS 選項
fn chaos_query(id: u16, name: &str, opt: Option<(u16, Vec<u8>)>) -> Vec<u8> {
    match opt {
        None => build_chaos_txt(id, name),
        Some(o) => kuroshio_proto::Message {
            id,
            flags: kuroshio_proto::message::FLAG_RD,
            questions: vec![kuroshio_proto::message::Question {
                name: name.to_string(),
                qtype: 16,
                qclass: 3,
            }],
            opt: Some(kuroshio_proto::message::Opt {
                udp_size: 1232,
                options: vec![o],
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode(),
    }
}

/// 一次 CH TXT 查詢；`opt` = 要帶的 EDNS 選項；UDP 回 TC 時自動改 TCP
pub async fn chaos_txt(addr: SocketAddr, name: &str, tcp: bool, opt: Option<(u16, Vec<u8>)>, limit: Duration) -> Result<ChaosReply> {
    let q = chaos_query(rand16(), name, opt);
    if !tcp {
        let r = udp_ask(addr, &q, limit).await?;
        if !kuroshio_proto::header(&r).is_ok_and(|h| h.tc) {
            return chaos_reply(&r);
        }
    }
    chaos_reply(&tcp_ask(addr, &q, limit).await?)
}

/// 同一條 TCP 連線上連續問 CH TXT（共用結果的分段）
pub struct ChaosTcp {
    s: TcpStream,
}

impl ChaosTcp {
    pub async fn connect(addr: SocketAddr, limit: Duration) -> Result<ChaosTcp> {
        let s = tokio::time::timeout(limit, TcpStream::connect(addr))
            .await
            .map_err(|_| anyhow!("連線逾時"))??;
        Ok(ChaosTcp { s })
    }

    pub async fn ask(&mut self, name: &str, limit: Duration) -> Result<ChaosReply> {
        let q = build_chaos_txt(rand16(), name);
        let s = &mut self.s;
        let r = tokio::time::timeout(limit, async {
            let mut msg = (q.len() as u16).to_be_bytes().to_vec();
            msg.extend_from_slice(&q);
            s.write_all(&msg).await?;
            loop {
                let len = s.read_u16().await? as usize;
                let mut buf = vec![0u8; len];
                s.read_exact(&mut buf).await?;
                if kuroshio_proto::matches(&q, &buf) {
                    return Ok::<_, anyhow::Error>(buf);
                }
            }
        })
        .await
        .map_err(|_| anyhow!("逾時"))??;
        chaos_reply(&r)
    }
}

/// TXT 回答的第一段文字
fn txt_answer(resp: &[u8]) -> Option<String> {
    let m = kuroshio_proto::Message::parse(resp).ok()?;
    if m.rcode != 0 {
        return None;
    }
    m.answers.iter().filter(|r| r.rtype == 16).find_map(|r| {
        let s = tls::txt_strings(&r.data)?;
        let s = s.trim().to_string();
        (!s.is_empty()).then(|| s.chars().take(64).collect())
    })
}

fn a_answers(resp: &[u8]) -> Vec<IpAddr> {
    kuroshio_proto::Message::parse(resp)
        .map(|m| kuroshio_proto::logic::ips_of(&m, 1))
        .unwrap_or_default()
}

/// 一般 DNS 有沒有被接走：對保留位址查詢，有任何回答就是被接走
async fn probe_plain(addrs: &[SocketAddr], limit: Duration) -> (Plain, Option<SocketAddr>) {
    let q = kuroshio_proto::build_query(rand16(), "example.com", 1);
    let mut p = Plain::default();
    let mut hit = None;
    for &a in addrs {
        if !p.udp && udp_ask(a, &q, limit).await.is_ok() {
            p.udp = true;
            hit.get_or_insert(a);
        }
        if !p.tcp && tcp_ask(a, &q, limit).await.is_ok() {
            p.tcp = true;
            hit.get_or_insert(a);
        }
        if p.udp && p.tcp {
            break;
        }
    }
    (p, hit)
}

/// 攔截者是誰（問被轉走的那個位址）
async fn identify(addr: SocketAddr, tcp: bool, limit: Duration) -> Interceptor {
    let ask = |name: &'static str| async move {
        let q = build_chaos_txt(rand16(), name);
        let r = if tcp {
            tcp_ask(addr, &q, limit).await
        } else {
            udp_ask(addr, &q, limit).await
        };
        r.ok().and_then(|r| txt_answer(&r))
    };
    if let Some(v) = ask("version.kuroshio").await {
        if let Some(ver) = v.strip_prefix("kuroshio/") {
            return Interceptor::Kuroshio(ver.to_string());
        }
    }
    match ask("version.bind").await {
        Some(v) => Interceptor::Software(v),
        None => Interceptor::Unknown,
    }
}

/// 預設閘道（Linux 讀 /proc/net/route；Windows 讀 `route print -4 0.0.0.0`，取計量最小的一筆；其他系統回 None）。
/// 3.4.2 以前 Windows 一律 None：串接只能靠「被攔截的一般 DNS」，路由器不攔截 53 埠時就串不起來，
/// 狀態頁與 check-path 也寫不出上游是哪一台路由器
pub fn default_gateway() -> Option<IpAddr> {
    #[cfg(windows)]
    {
        windows_default_gateway()
    }
    #[cfg(not(windows))]
    {
        let s = std::fs::read_to_string("/proc/net/route").ok()?;
        parse_route_gateway(&s)
    }
}

#[cfg(windows)]
fn windows_default_gateway() -> Option<IpAddr> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    // 用完整路徑（不靠 PATH）；路由表的數字欄位不受系統語言影響
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    let exe = std::path::Path::new(&root).join("System32").join("ROUTE.EXE");
    let out = Command::new(exe)
        .args(["print", "-4", "0.0.0.0"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    parse_route_print(&String::from_utf8_lossy(&out.stdout))
}

/// `route print -4` 的「使用中的路由」：目的地與遮罩都是 0.0.0.0、閘道是位址（不是 On-link）的，取計量最小的。
/// 「持續路由」那一段只有四欄（沒有介面），不算
#[cfg_attr(not(windows), allow(dead_code))]
fn parse_route_print(s: &str) -> Option<IpAddr> {
    let mut best: Option<(u32, Ipv4Addr)> = None;
    for line in s.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() != 5 || f[0] != "0.0.0.0" || f[1] != "0.0.0.0" {
            continue;
        }
        let (Ok(gw), Ok(_), Ok(metric)) = (f[2].parse::<Ipv4Addr>(), f[3].parse::<Ipv4Addr>(), f[4].parse::<u32>()) else {
            continue;
        };
        if gw.is_unspecified() {
            continue;
        }
        if best.is_none() || best.is_some_and(|(m, _)| metric < m) {
            best = Some((metric, gw));
        }
    }
    best.map(|(_, g)| IpAddr::V4(g))
}

#[cfg_attr(windows, allow(dead_code))]
fn parse_route_gateway(s: &str) -> Option<IpAddr> {
    for line in s.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() > 3 && f[1] == "00000000" {
            let g = u32::from_str_radix(f[2], 16).ok()?;
            if g != 0 {
                // /proc/net/route 印的是位址的 4 個 bytes 當成本機位元組順序的整數（小端機器上看起來反過來）
                return Some(IpAddr::V4(Ipv4Addr::from(g.to_ne_bytes())));
            }
        }
    }
    None
}

/// 檢查一般 DNS 伺服器（或攔截者）的答案：已知答案不對 → 竄改；`.invalid` 有位址 → 改寫「不存在」
async fn probe_answers(
    addr: SocketAddr,
    via: &str,
    t: &Targets,
    nx: &mut Vec<IpAddr>,
    nx_via: &mut Option<String>,
    tampered: &mut Vec<Tamper>,
) {
    let name = format!("{}.invalid", rand_label());
    let q = kuroshio_proto::build_query(rand16(), &name, 1);
    if let Ok(r) = udp_ask(addr, &q, t.plain_timeout).await {
        let ips = a_answers(&r);
        if !ips.is_empty() && nx.is_empty() {
            *nx = ips;
            *nx_via = Some(via.to_string());
        }
    }
    for (name, good) in &t.known {
        let q = kuroshio_proto::build_query(rand16(), name, 1);
        if let Ok(r) = udp_ask(addr, &q, t.plain_timeout).await {
            let ips = a_answers(&r);
            if !ips.is_empty() && ips.iter().any(|i| !good.contains(i)) {
                tampered.push(Tamper {
                    via: via.to_string(),
                    name: name.clone(),
                    answer: ips,
                });
            }
        }
    }
}

fn cert_error_text(e: &anyhow::Error) -> Option<String> {
    for c in e.chain() {
        let r = c.downcast_ref::<rustls::Error>().or_else(|| {
            c.downcast_ref::<std::io::Error>()
                .and_then(|io| io.get_ref())
                .and_then(|i| i.downcast_ref::<rustls::Error>())
        });
        if let Some(rustls::Error::InvalidCertificate(x)) = r {
            return Some(format!("{x:?}"));
        }
    }
    let s = format!("{e:#}");
    s.contains("invalid peer certificate").then_some(s)
}

async fn probe_protocol(p: Proto, t: &Targets) -> ProtoResult {
    let mut set = tokio::task::JoinSet::new();
    let limit = t.tls_timeout;
    match p {
        Proto::Dot | Proto::Doh => {
            let list = if p == Proto::Dot { &t.dot } else { &t.doh };
            for (addr, host) in list.clone() {
                let alpn: Vec<Vec<u8>> = if p == Proto::Dot {
                    vec![b"dot".to_vec()]
                } else {
                    vec![b"h2".to_vec(), b"http/1.1".to_vec()]
                };
                set.spawn(async move {
                    let a: Vec<&[u8]> = alpn.iter().map(|v| v.as_slice()).collect();
                    tls::connect_addrs(&host, &[addr], &a, limit).await.map(|_| ())
                });
            }
        }
        Proto::Quic => {
            for (addr, host, alpn) in t.quic.clone() {
                set.spawn(async move {
                    crate::quic::connect_addrs(&host, &[addr], &alpn, limit)
                        .await
                        .map(|c| c.close(0u32.into(), b""))
                });
            }
        }
    }
    let mut r = ProtoResult::default();
    while let Some(x) = set.join_next().await {
        match x {
            Ok(Ok(())) => r.ok += 1,
            Ok(Err(e)) => {
                r.fail += 1;
                if let Some(c) = cert_error_text(&e) {
                    r.cert_errors += 1;
                    r.last_error = Some(c);
                } else {
                    r.last_error = Some(format!("{e:#}").chars().take(160).collect());
                }
            }
            Err(e) => {
                r.fail += 1;
                r.last_error = Some(e.to_string());
            }
        }
    }
    r
}

/// 做一次完整的路徑檢查（不改全域狀態；要套用請呼叫 [`apply`]）
pub async fn check(t: &Targets) -> Report {
    let v6_route = t.v6_route.clone().unwrap_or_else(v6_route_now);
    let v6_on = match v6_mode() {
        V6Mode::On => true,
        V6Mode::Off => false,
        V6Mode::Auto => !matches!(v6_route, V6Route::None(_)),
    };
    // 加密協定的探測跟一般 DNS 的探測同時進行
    let protos = {
        let t = t.clone();
        tokio::spawn(async move {
            let (a, b, c) = tokio::join!(
                probe_protocol(Proto::Dot, &t),
                probe_protocol(Proto::Doh, &t),
                probe_protocol(Proto::Quic, &t)
            );
            vec![(Proto::Dot, a), (Proto::Doh, b), (Proto::Quic, c)]
        })
    };
    // Windows 要執行 ROUTE.EXE：不佔非同步的執行緒；最多等 5 秒（卡住時當成沒有閘道，路徑檢查照常做完）
    let gateway = if t.read_gateway {
        tokio::time::timeout(Duration::from_secs(5), tokio::task::spawn_blocking(default_gateway))
            .await
            .ok()
            .and_then(|r| r.ok())
            .flatten()
    } else {
        None
    };
    // 保留位址剛好是預設閘道（有些網路真的這樣設）：它本來就可能有 DNS，不能拿來判斷攔截
    let testnet_v4: Vec<SocketAddr> = t.testnet_v4.iter().copied().filter(|a| Some(a.ip()) != gateway).collect();
    let (plain_v4, hit4) = probe_plain(&testnet_v4, t.plain_timeout).await;
    let (plain_v6, hit6) = if v6_on && !t.testnet_v6.is_empty() {
        let (p, h) = probe_plain(&t.testnet_v6, t.plain_timeout).await;
        (Some(p), h)
    } else {
        (None, None)
    };
    let mut interceptor = None;
    let hit = hit4
        .map(|a| (a, !plain_v4.udp))
        .or_else(|| hit6.map(|a| (a, !plain_v6.as_ref().is_some_and(|p| p.udp))));
    if let Some((a, tcp)) = hit {
        interceptor = Some(identify(a, tcp, t.plain_timeout).await);
    }

    // 答案檢查：被接走時問攔截者（一般 DNS 到哪裡都是它回答）；沒被接走時問 bootstrap 伺服器
    let mut nx = Vec::new();
    let mut nx_via = None;
    let mut tampered = Vec::new();
    match hit {
        Some((a, false)) => probe_answers(a, "interceptor", t, &mut nx, &mut nx_via, &mut tampered).await,
        _ => {
            let servers: Vec<SocketAddr> = if t.plain.is_empty() {
                tls::bootstrap_servers()
                    .into_iter()
                    .filter(|ip| ip.is_ipv4() || v6_on)
                    .map(|ip| SocketAddr::new(ip, 53))
                    .collect()
            } else {
                t.plain.clone()
            };
            for s in servers.iter().take(2) {
                probe_answers(*s, &s.ip().to_string(), t, &mut nx, &mut nx_via, &mut tampered).await;
            }
        }
    }

    let protocols = protos.await.unwrap_or_default();
    let get = |p: Proto| protocols.iter().find(|(x, _)| *x == p).map(|(_, r)| r.clone()).unwrap_or_default();
    let total_ok: usize = protocols.iter().map(|(_, r)| r.ok).sum();
    let total_cert: usize = protocols.iter().map(|(_, r)| r.cert_errors).sum();
    // 沒有任何加密協定的目標（測試用的覆寫把它們清空）：沒測就不算離線
    let tested = !(t.dot.is_empty() && t.doh.is_empty() && t.quic.is_empty());
    let offline = tested && total_ok == 0 && total_cert == 0;
    let mut blocked = Vec::new();
    let tls_intercept = if total_cert >= 2 {
        protocols
            .iter()
            .find_map(|(_, r)| (r.cert_errors > 0).then(|| r.last_error.clone()).flatten())
    } else {
        None
    };
    if !offline {
        for p in [Proto::Dot, Proto::Doh, Proto::Quic] {
            let r = get(p);
            // 這個協定全部失敗（而且不是憑證問題），但其他協定連得上 → 這條路擋了它
            if r.ok == 0 && r.fail > 0 && r.cert_errors == 0 && total_ok > 0 {
                blocked.push(p);
            }
        }
    }
    let r = Report {
        checked_at: now_ms(),
        v6_mode: v6_mode(),
        v6_route,
        plain_v4,
        plain_v6,
        interceptor,
        gateway,
        nx_rewrite: nx,
        nx_via,
        tampered,
        protocols,
        blocked,
        tls_intercept,
        offline,
        hit: hit.map(|(a, _)| a),
        hit_tcp: hit.is_some_and(|(_, tcp)| tcp),
    };
    debug!("路徑檢查：{}", r.to_json());
    r
}

/// 一行摘要（記錄檔用）
pub fn summary(r: &Report) -> String {
    let mut parts = Vec::new();
    parts.push(format!("IPv6 {}", if r.v6_usable() { "可用" } else { "不可用" }));
    if r.plain_intercepted() {
        parts.push(format!("一般 DNS 被{}接走", r.interceptor_text()));
    } else {
        parts.push("一般 DNS 沒有被接走".into());
    }
    if !r.nx_rewrite.is_empty() {
        parts.push("「不存在」被改寫".into());
    }
    if !r.tampered.is_empty() {
        parts.push("答案被竄改".into());
    }
    for p in &r.blocked {
        parts.push(format!("{} 被擋", p.label()));
    }
    if r.tls_intercept.is_some() {
        parts.push("TLS 被攔截".into());
    }
    if r.offline {
        parts.push("加密 DNS 全部連不上（網路可能斷了）".into());
    }
    parts.join("，")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interceptor_text_with_and_without_gateway() {
        let mut r = Report {
            interceptor: Some(Interceptor::Kuroshio("3.4.1".into())),
            ..Report::default()
        };
        assert_eq!(r.interceptor_text(), "路由器上的黑潮（3.4.1）", "沒有閘道位址：不留多的空格");
        r.gateway = Some("192.168.1.1".parse().unwrap());
        assert_eq!(r.interceptor_text(), "閘道 192.168.1.1 或更上游的路由器上的黑潮（3.4.1）");
    }

    #[test]
    fn v6_source_kinds() {
        assert_eq!(classify_v6_source("2001:db8::5".parse().unwrap()), V6Route::Global);
        assert_eq!(classify_v6_source("fd00::5".parse().unwrap()), V6Route::Ula);
        assert!(matches!(classify_v6_source("fe80::1".parse().unwrap()), V6Route::None(_)));
        assert!(matches!(classify_v6_source("::1".parse().unwrap()), V6Route::None(_)));
    }

    #[test]
    fn modes_from_config_values() {
        assert_eq!(V6Mode::from_value(Some(&json!(0))), V6Mode::Off);
        assert_eq!(V6Mode::from_value(Some(&json!(1))), V6Mode::On);
        assert_eq!(V6Mode::from_value(Some(&json!("0"))), V6Mode::Off);
        assert_eq!(V6Mode::from_value(Some(&json!(false))), V6Mode::Off);
        assert_eq!(V6Mode::from_value(Some(&json!("auto"))), V6Mode::Auto);
        assert_eq!(V6Mode::from_value(None), V6Mode::Auto);
    }

    #[test]
    fn modes() {
        assert_eq!(V6Mode::parse("0"), V6Mode::Off);
        assert_eq!(V6Mode::parse("1"), V6Mode::On);
        assert_eq!(V6Mode::parse("auto"), V6Mode::Auto);
        assert_eq!(V6Mode::parse(""), V6Mode::Auto);
    }

    #[test]
    fn route_gateway() {
        let s = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                 eth0\t0000000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n\
                 eth0\t00000000\t0100000A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n";
        let g = parse_route_gateway(s).unwrap();
        // 小端機器：0100000A → 10.0.0.1
        if cfg!(target_endian = "little") {
            assert_eq!(g, IpAddr::from([10, 0, 0, 1]));
        }
    }

    #[test]
    fn route_print_picks_lowest_metric_default_route() {
        // Windows 11（兩張網卡，兩個預設閘道；介面計量 15 / 25），加上持續路由一筆
        let s = "===========================================================================
                 Active Routes:
                 Network Destination        Netmask          Gateway       Interface  Metric
                           0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.104     25
                           0.0.0.0          0.0.0.0         10.0.0.1       10.0.0.108     15
                          10.0.0.0    255.255.255.0         On-link        10.0.0.108    271
                 ===========================================================================
                 Persistent Routes:
                   Network Address          Netmask  Gateway Address  Metric
                           0.0.0.0          0.0.0.0      172.16.0.1  Default
";
        assert_eq!(parse_route_print(s), Some("10.0.0.1".parse().unwrap()));
        // 只有 On-link（點對點 VPN）或沒有預設路由
        assert_eq!(
            parse_route_print(
                "  0.0.0.0  0.0.0.0  On-link  10.8.0.2  35
"
            ),
            None
        );
        assert_eq!(
            parse_route_print(
                "Active Routes:
None
"
            ),
            None
        );
    }

    #[test]
    fn chaos_query() {
        let q = build_chaos_txt(7, "version.bind");
        let qs = kuroshio_proto::question(&q).unwrap();
        assert_eq!((qs.name.as_str(), qs.qtype), ("version.bind", 16));
        assert_eq!(&q[q.len() - 2..], &[0, 3]);
    }

    #[test]
    fn no_route_errors() {
        let e = std::io::Error::from(std::io::ErrorKind::AddrNotAvailable);
        assert!(is_no_route(&e));
        let e = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        assert!(!is_no_route(&e));
    }
}
