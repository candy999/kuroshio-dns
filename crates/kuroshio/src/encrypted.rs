//! 加密 DNS 伺服器（規格 01 第 1.1 節）：DoT（TCP 853）與 DoH（HTTP/1.1 + HTTP/2）
//!
//! - 憑證檔變更 10 秒內自動換上（同 2.x 的 watchCerts）；檔案還不存在時等它出現，每 10 分鐘提醒一次
//! - DoT：一條連線可以同時送多筆查詢，回應不必照順序（RFC 7766）；閒置 30 秒關閉
//! - DoH：GET `?dns=` 與 POST `application/dns-message`；憑證留空 = 純 HTTP（給 IIS / 反向代理用）
//! - 連線數上限 `system.maxTlsConnections`（預設依 CPU 核心數）；記憶體接近保留量時新連線最多到
//!   [`LOW_MEMORY_CONNS`] 條，低於保留量一半時暫不接受新的加密連線（區網的明文 DNS 照常回答，規格 09）
//! - 每個來源的連線上限 `system.maxTlsConnectionsPerIp`（DoT 與 DoH 共用一份；DoQ、DoH3 各自一份）。
//!   名額跟著連線的工作（RAII），連線怎麼結束都會還回來；連線被重設時處理中的查詢一起取消（3.5.1 K9）
//! - DoH 同時處理中的請求上限 `system.maxDohInflight`（[`DohGate`]）：滿了立刻回 503 busy，不排隊（3.5.1 K7）
//! - 每筆查詢最多 [`QUERY_DEADLINE`]，逾時回 SERVFAIL；拒絕與逾時有計數（`perf.server`），日誌每一類每分鐘最多一行

use crate::resolver::{Ctx, Resolver};
use crate::server::{hold_while, Fresh, FRESH_GRACE, FRESH_HANDSHAKE};
use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, Response, StatusCode};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Semaphore};
use tracing::{debug, info, warn};

// ---------------- 憑證（熱更新） ----------------

pub struct CertStore {
    cert: PathBuf,
    key: PathBuf,
    current: RwLock<Option<Arc<CertifiedKey>>>,
    mtime: RwLock<Option<(SystemTime, SystemTime)>>,
    last_warn: RwLock<Option<Instant>>,
}

impl std::fmt::Debug for CertStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CertStore({})", self.cert.display())
    }
}

pub fn load_certified_key(cert: &[u8], key: &[u8]) -> Result<CertifiedKey> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert)
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow!("憑證格式錯誤：{e:?}"))?;
    if chain.is_empty() {
        anyhow::bail!("憑證檔裡沒有憑證");
    }
    let key = PrivateKeyDer::from_pem_slice(key).map_err(|e| anyhow!("私鑰格式錯誤：{e:?}"))?;
    let provider = rustls::crypto::ring::default_provider();
    CertifiedKey::from_der(chain, key, &provider).map_err(|e| anyhow!("憑證與私鑰不符：{e}"))
}

impl CertStore {
    pub fn new(cert: impl Into<PathBuf>, key: impl Into<PathBuf>) -> Arc<CertStore> {
        let s = Arc::new(CertStore {
            cert: cert.into(),
            key: key.into(),
            current: RwLock::new(None),
            mtime: RwLock::new(None),
            last_warn: RwLock::new(None),
        });
        s.reload();
        s
    }

    pub fn ready(&self) -> bool {
        self.current.read().unwrap().is_some()
    }

    /// 檔案有變就重新載入；回傳目前是否有可用的憑證
    pub fn reload(&self) -> bool {
        let m = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
        let (Some(a), Some(b)) = (m(&self.cert), m(&self.key)) else {
            let mut w = self.last_warn.write().unwrap();
            if w.map(|t| t.elapsed() > Duration::from_secs(600)).unwrap_or(true) {
                warn!(
                    "找不到憑證 {} / {}，加密 DNS 暫停，檔案出現後自動啟用",
                    self.cert.display(),
                    self.key.display()
                );
                *w = Some(Instant::now());
            }
            return self.ready();
        };
        if *self.mtime.read().unwrap() == Some((a, b)) {
            return self.ready();
        }
        match (std::fs::read(&self.cert), std::fs::read(&self.key)) {
            (Ok(c), Ok(k)) => match load_certified_key(&c, &k) {
                Ok(ck) => {
                    let first = !self.ready();
                    *self.current.write().unwrap() = Some(Arc::new(ck));
                    *self.mtime.write().unwrap() = Some((a, b));
                    info!("{}憑證：{}", if first { "載入" } else { "更新" }, self.cert.display());
                }
                Err(e) => warn!("憑證無法使用（保留舊的）：{e:#}"),
            },
            _ => warn!("讀不到憑證檔"),
        }
        self.ready()
    }

    pub fn spawn_watch(self: &Arc<Self>) {
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                me.reload();
            }
        });
    }

    pub fn server_config(self: &Arc<Self>, alpn: &[&[u8]]) -> Arc<rustls::ServerConfig> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("TLS 版本設定")
            .with_no_client_auth()
            .with_cert_resolver(self.clone());
        cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
        // 伺服器端不接受 0-RTT（避免重放，規格 01 第 1.2 節）
        cfg.max_early_data_size = 0;
        Arc::new(cfg)
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.current.read().unwrap().clone()
    }
}

/// 記憶體接近保留量時，加密連線最多幾條（每條約 30–60 KB）
pub const LOW_MEMORY_CONNS: usize = 32;

/// DoT 一條連線同時處理中的查詢上限（滿了先不讀下一筆；對方只送不收時查詢不會無限堆積）
pub const DOT_MAX_INFLIGHT: usize = 64;
/// DoH（HTTP/2）一條連線同時幾個請求
pub const DOH_MAX_STREAMS: u32 = 64;
/// 讀一筆查詢的內容、HTTP 標頭最多等多久（送了開頭就不送完的連線不會一直佔著）
pub const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// 加密 DNS 每一筆查詢最多等多久（DoT、DoH、DoQ、DoH3、HTTP.sys；3.5.1 K7）：超過就回 SERVFAIL，
/// 處理中的名額馬上還回來。比查詢工作的總期限（`resolver::JOB_DEADLINE`，12 秒）短：
/// 用戶端多半 5 秒內就放棄，伺服器不替已經放棄的人一直等
pub const QUERY_DEADLINE: Duration = Duration::from_secs(10);

/// 每個來源的連線上限（`system.maxTlsConnectionsPerIp` 是 auto 時）：總上限的 1/4，16–256 條（3.5.1 K9）。
/// 3.3.2～3.5.0 是 1/8、8–64 條：四核心以上剛好 64 條，CGNAT、公司、學校共用一個對外 IP 時太容易撞到
pub fn per_ip_default(max: usize) -> usize {
    (max / 4).clamp(16, 256)
}

/// DoH 同時處理中的請求上限（`system.maxDohInflight` 是 auto 時）：TLS 連線總上限的一半，64–1024 個
pub fn doh_inflight_default(max_tls: usize) -> usize {
    (max_tls / 2).clamp(64, 1024)
}

/// 每個來源算一份的鍵：IPv4 用位址；IPv6 用前 64 位元（同一個用戶通常拿到整段 /64）
fn source_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let mut o = v6.octets();
                o[8..].fill(0);
                IpAddr::V6(o.into())
            }
        },
        v4 => v4,
    }
}

// ---------------- 拒絕與逾時：計數與有上限的日誌（3.5.1 K7–K9） ----------------

/// 加密 DNS 伺服器的協定（拒絕的計數與日誌用）
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Dot = 0,
    Doh = 1,
    Doq = 2,
    Doh3 = 3,
}

impl Proto {
    pub fn name(self) -> &'static str {
        match self {
            Proto::Dot => "DoT",
            Proto::Doh => "DoH",
            Proto::Doq => "DoQ",
            Proto::Doh3 => "DoH3",
        }
    }

    /// 解析器的 `Ctx.proto`
    fn tag(self) -> &'static str {
        match self {
            Proto::Dot => "dot",
            Proto::Doh => "doh",
            Proto::Doq => "doq",
            Proto::Doh3 => "doh3",
        }
    }

    fn of_tag(tag: &str) -> Proto {
        match tag {
            "dot" => Proto::Dot,
            "doq" => Proto::Doq,
            "doh3" => Proto::Doh3,
            _ => Proto::Doh,
        }
    }
}

/// 新連線（或 HTTP.sys 的請求）被拒絕的原因
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// 連線總數滿了（`system.maxTlsConnections`、QUIC 是 `system.maxQuicConnections`）
    Total = 0,
    /// 這個來源的連線數滿了（`system.maxTlsConnectionsPerIp`）
    PerSource = 1,
    /// 記憶體偏低（最多 [`LOW_MEMORY_CONNS`] 條）或不足（暫不接受新的加密連線）
    Memory = 2,
}

/// 同一類事件的計數與「上一次寫日誌」的時間：每類每 60 秒最多寫一行，中間的只計數（不會洗版、不會變成風暴）
struct Note {
    /// 上一次寫日誌的時間（行程啟動後第幾秒 + 1；0 = 還沒寫過）
    last: std::sync::atomic::AtomicU32,
    /// 上一行之後沒寫出來的次數
    skipped: std::sync::atomic::AtomicU32,
    /// 累計次數（`/api/status` 的 `perf.server`）
    count: std::sync::atomic::AtomicU32,
}

impl Note {
    const fn new() -> Note {
        use std::sync::atomic::AtomicU32;
        Note {
            last: AtomicU32::new(0),
            skipped: AtomicU32::new(0),
            count: AtomicU32::new(0),
        }
    }
}

/// 事件的編號：前 12 個是「協定 × 拒絕原因」，後面是其他
const NOTE_DOH_BUSY: usize = 12;
const NOTE_DEADLINE: usize = 13;
const NOTE_HTTPSYS_BODY: usize = 14;
static NOTES: [Note; 15] = [
    Note::new(),
    Note::new(),
    Note::new(),
    Note::new(),
    Note::new(),
    Note::new(),
    Note::new(),
    Note::new(),
    Note::new(),
    Note::new(),
    Note::new(),
    Note::new(),
    Note::new(),
    Note::new(),
    Note::new(),
];
/// 同一類事件多久最多寫一行日誌
const NOTE_EVERY_SECS: u32 = 60;

fn uptime_secs() -> u32 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    (START.get_or_init(Instant::now).elapsed().as_secs().min(u32::MAX as u64 - 1) as u32) + 1
}

/// 記一次；這一類 60 秒內還沒寫過日誌就寫一行（`line` 拿到「上一行之後又有幾次」）
fn note(i: usize, line: impl FnOnce(u32) -> String) {
    use std::sync::atomic::Ordering::Relaxed;
    let n = &NOTES[i];
    n.count.fetch_add(1, Relaxed);
    let now = uptime_secs();
    let last = n.last.load(Relaxed);
    if (last != 0 && now.saturating_sub(last) < NOTE_EVERY_SECS) || n.last.compare_exchange(last, now, Relaxed, Relaxed).is_err() {
        n.skipped.fetch_add(1, Relaxed);
        return;
    }
    let skipped = n.skipped.swap(0, Relaxed);
    let more = if skipped > 0 {
        format!("上一行之後又有 {skipped} 次；")
    } else {
        String::new()
    };
    warn!(
        "{}（{more}同一類 1 分鐘內只寫一行，累計次數看 /api/status 的 perf.server）",
        line(skipped)
    );
}

/// `/api/status` 的 `perf.server`：加密 DNS 伺服器拒絕新連線、回 busy、查詢逾時的累計次數
pub fn server_json() -> serde_json::Value {
    use std::sync::atomic::Ordering::Relaxed;
    let c = |i: usize| NOTES[i].count.load(Relaxed);
    let by = |p: Proto| {
        let b = p as usize * 3;
        serde_json::json!({ "total": c(b), "perSource": c(b + 1), "memory": c(b + 2) })
    };
    serde_json::json!({
        "refused": { "dot": by(Proto::Dot), "doh": by(Proto::Doh), "doq": by(Proto::Doq), "doh3": by(Proto::Doh3) },
        "dohBusy": c(NOTE_DOH_BUSY),
        "deadline": c(NOTE_DEADLINE),
        "httpsysBodyBusy": c(NOTE_HTTPSYS_BODY),
    })
}

/// 每個來源目前幾條連線
type BySource = Arc<std::sync::Mutex<std::collections::HashMap<IpAddr, usize>>>;

/// 連線數上限（總數與每個來源）與記憶體壓力檢查
#[derive(Clone)]
pub struct Limits {
    pub conns: Arc<Semaphore>,
    max: usize,
    per_ip: usize,
    by_ip: BySource,
    /// QUIC：還沒完成握手（來源位址還沒驗證）的連線數
    handshaking: Arc<std::sync::atomic::AtomicUsize>,
    /// 未驗證的握手到幾個就先要求 Retry（None = 總上限的 1/4，至少 8）
    retry_after: Option<usize>,
}

/// 一個來源佔的一個名額：結束（drop）時歸還——正常關閉、被重設、握手失敗、逾時、panic 都一樣
pub struct SourceSlot {
    key: IpAddr,
    m: BySource,
}

impl Drop for SourceSlot {
    fn drop(&mut self) {
        let mut m = self.m.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = m.get_mut(&self.key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                m.remove(&self.key);
            }
        }
    }
}

/// 一條連線佔的名額：總數 + 這個來源（本機或不限時沒有）
pub struct Permit {
    _conn: tokio::sync::OwnedSemaphorePermit,
    _src: Option<SourceSlot>,
}

/// QUIC 新連線佔的名額：握手期間只佔總數；握手完成（對方收得到封包 = 來源位址是真的）才計入這個來源
pub struct QuicPermit {
    _conn: tokio::sync::OwnedSemaphorePermit,
    handshaking: Option<Arc<std::sync::atomic::AtomicUsize>>,
    _src: Option<SourceSlot>,
}

impl QuicPermit {
    /// 握手完成：計入這個來源的名額。這個來源已經滿了回傳 false（呼叫端關閉連線；已經記了日誌）
    pub fn established(&mut self, limits: &Limits, proto: Proto, ip: IpAddr) -> bool {
        self.end_handshake();
        match limits.claim_source(ip) {
            Ok(s) => {
                self._src = s;
                true
            }
            Err(why) => {
                limits.refused(proto, why, ip);
                false
            }
        }
    }

    fn end_handshake(&mut self) {
        if let Some(h) = self.handshaking.take() {
            h.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

impl Drop for QuicPermit {
    fn drop(&mut self) {
        self.end_handshake();
    }
}

impl Limits {
    pub fn new(max: usize) -> Limits {
        Limits {
            conns: Arc::new(Semaphore::new(max.max(1))),
            max: max.max(1),
            per_ip: per_ip_default(max.max(1)),
            by_ip: Default::default(),
            handshaking: Default::default(),
            retry_after: None,
        }
    }

    /// 未驗證的握手到幾個就先要求 Retry（0 = 一律 Retry；測試用）
    pub fn with_retry_threshold(mut self, n: usize) -> Limits {
        self.retry_after = Some(n);
        self
    }

    /// 每個來源最多幾條（0 = 不限）
    pub fn with_per_ip(mut self, n: Option<usize>) -> Limits {
        if let Some(n) = n {
            self.per_ip = n;
        }
        self
    }

    /// 每個來源最多幾條（0 = 不限）
    pub fn per_ip(&self) -> usize {
        self.per_ip
    }

    /// 目前佔用的連線數
    pub fn in_use(&self) -> usize {
        self.max - self.conns.available_permits()
    }

    /// 這個來源目前佔了幾條（測試、狀態用）
    pub fn source_count(&self, ip: IpAddr) -> usize {
        self.by_ip
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&source_key(ip))
            .copied()
            .unwrap_or(0)
    }

    /// 這個來源再佔一個名額：Ok(None) = 不算（本機、不限），Err = 滿了
    pub(crate) fn claim_source(&self, ip: IpAddr) -> Result<Option<SourceSlot>, Refusal> {
        if self.per_ip == 0 || ip.is_loopback() {
            return Ok(None);
        }
        let key = source_key(ip);
        let mut m = self.by_ip.lock().unwrap_or_else(|e| e.into_inner());
        let n = m.entry(key).or_insert(0);
        if *n >= self.per_ip {
            return Err(Refusal::PerSource);
        }
        *n += 1;
        Ok(Some(SourceSlot {
            key,
            m: self.by_ip.clone(),
        }))
    }

    /// 新連線（TCP：三向交握已經證明來源位址是真的）：總數、記憶體、這個來源的連線數都還有空間才收。
    /// 本機（反向代理）不算每個來源的上限。拒絕時呼叫端在 TLS 握手之前就關閉，已經建立的連線不受影響
    pub(crate) fn admit_from(&self, ip: IpAddr) -> Result<Permit, Refusal> {
        let src = self.claim_source(ip)?;
        let conn = self.admit()?;
        Ok(Permit { _conn: conn, _src: src })
    }

    /// 拒絕新連線：計數，日誌每一類每分鐘最多一行（寫出原因、上限與怎麼調）
    pub(crate) fn refused(&self, proto: Proto, why: Refusal, ip: IpAddr) {
        let (per_ip, max) = (self.per_ip, self.max);
        note(proto as usize * 3 + why as usize, |_| {
            let p = proto.name();
            match why {
                Refusal::PerSource => format!(
                    "{p} 拒絕來源 {ip} 的新連線：這個來源已經有 {per_ip} 條連線（system.maxTlsConnectionsPerIp，IPv6 以 /64 算一個來源；\
                     CGNAT、公司、學校共用 IP 時可以調大，0 = 不限），已經建立的連線照常服務"
                ),
                Refusal::Total => format!(
                    "{p} 拒絕來源 {ip} 的新連線：連線總數已達上限 {max} 條（{}），已經建立的連線照常服務",
                    if matches!(proto, Proto::Doq | Proto::Doh3) {
                        "system.maxQuicConnections"
                    } else {
                        "system.maxTlsConnections"
                    }
                ),
                Refusal::Memory => format!(
                    "{p} 拒絕來源 {ip} 的新連線：記憶體{}（規格 09），區網的明文 DNS 與已經建立的連線照常服務",
                    if crate::app::pressure() == crate::sysinfo::Pressure::Critical {
                        "不足，暫不接受新的加密連線"
                    } else {
                        "接近保留量，加密連線最多 32 條"
                    }
                ),
            }
        });
    }

    /// 未驗證的握手超過這個數就先要求 Retry（總上限的 1/4，至少 8）
    pub fn retry_threshold(&self) -> usize {
        self.retry_after.unwrap_or((self.max / 4).max(8))
    }

    /// QUIC 新連線（UDP 的來源位址可以偽造）：
    /// - 進行中、來源還沒驗證的握手太多時，先回 Retry 要求對方證明收得到封包（平常不多一次往返）；
    /// - 握手期間只佔總數，不佔「每個來源」的名額：偽造來源的 Initial 握手永遠完成不了，佔不到真實使用者的名額。
    ///
    /// 回傳 None = 已經處理掉（Retry 或拒絕），呼叫端不必再管這個 Incoming
    pub(crate) fn admit_quic(&self, incoming: quinn::Incoming, proto: Proto) -> Option<(quinn::Incoming, QuicPermit)> {
        use std::sync::atomic::Ordering;
        if !incoming.remote_address_validated() && self.handshaking.load(Ordering::Relaxed) >= self.retry_threshold() {
            // 沒驗證過的一定可以 Retry（quinn 保證）；萬一不行就拒絕
            if let Err(e) = incoming.retry() {
                e.into_incoming().refuse();
            }
            return None;
        }
        let conn = match self.admit() {
            Ok(c) => c,
            Err(why) => {
                // 這時來源位址還沒驗證、可能是偽造的；日誌每一類每分鐘最多一行，灌再多也不會洗版
                self.refused(proto, why, incoming.remote_address().ip());
                incoming.refuse();
                return None;
            }
        };
        self.handshaking.fetch_add(1, Ordering::Relaxed);
        Some((
            incoming,
            QuicPermit {
                _conn: conn,
                handshaking: Some(self.handshaking.clone()),
                _src: None,
            },
        ))
    }

    pub(crate) fn admit(&self) -> Result<tokio::sync::OwnedSemaphorePermit, Refusal> {
        use crate::sysinfo::Pressure;
        match crate::app::pressure() {
            Pressure::Critical => return Err(Refusal::Memory),
            Pressure::Low if self.in_use() >= LOW_MEMORY_CONNS => return Err(Refusal::Memory),
            _ => {}
        }
        self.conns.clone().try_acquire_owned().map_err(|_| Refusal::Total)
    }
}

// ---------------- DoH 處理中的請求上限（3.5.1 K7、K8） ----------------

/// DoH 同時處理中的請求上限：HTTP/1.1、HTTP/2、HTTP/3、HTTP.sys 共用一份。滿了**立刻**回 503（不排隊）。
///
/// 跟連線數上限（[`Limits`]）分開：3.5.0 以前 HTTP.sys 模式每個請求佔一個 TLS 連線名額，
/// 處理不完的 DoH 請求把名額佔滿時，DoT 的新連線也跟著被拒絕（DoQ 的連線名額是另一份，所以不受影響）
#[derive(Clone)]
pub struct DohGate {
    sem: Arc<Semaphore>,
    max: usize,
}

/// 一個 DoH 請求佔的名額：結束（drop）時歸還——正常回應、錯誤、逾時、用戶端放棄（future 被丟掉）、panic 都一樣
pub struct DohSlot {
    _p: tokio::sync::OwnedSemaphorePermit,
}

impl DohGate {
    pub fn new(max: usize) -> DohGate {
        let max = max.max(1);
        DohGate {
            sem: Arc::new(Semaphore::new(max)),
            max,
        }
    }

    pub fn max(&self) -> usize {
        self.max
    }

    /// 目前處理中的請求數
    pub fn in_use(&self) -> usize {
        self.max - self.sem.available_permits()
    }

    /// 佔一個名額；滿了回 None（不等）
    pub fn try_enter(&self) -> Option<DohSlot> {
        self.sem.clone().try_acquire_owned().ok().map(|p| DohSlot { _p: p })
    }

    /// 同 [`DohGate::try_enter`]，另外看記憶體（HTTP.sys 模式：請求不經過黑潮的連線上限，
    /// 記憶體不足時不收新的請求、偏低時最多 [`LOW_MEMORY_CONNS`] 個同時處理）
    pub fn try_enter_mem(&self) -> Option<DohSlot> {
        use crate::sysinfo::Pressure;
        match crate::app::pressure() {
            Pressure::Critical => None,
            Pressure::Low if self.in_use() >= LOW_MEMORY_CONNS => None,
            _ => self.try_enter(),
        }
    }

    /// 回了 busy：計數，日誌每分鐘最多一行
    pub fn note_busy(&self, proto: Proto, ip: IpAddr) {
        let max = self.max;
        note(NOTE_DOH_BUSY, |_| {
            format!(
                "{} 回 503 busy 給 {ip}：同時處理中的 DoH 請求已達 {max} 個（system.maxDohInflight），或記憶體不足；\
                 不排隊，處理完的名額馬上給下一個請求",
                proto.name()
            )
        });
    }
}

/// HTTP.sys 讀請求內容的專用執行緒都在忙：計數，日誌每分鐘最多一行
pub fn note_body_busy(ip: IpAddr) {
    note(NOTE_HTTPSYS_BODY, |_| {
        format!("HTTP.sys 回 503 busy 給 {ip}：讀請求內容的執行緒都在等還沒送完的內容（每個最多等 10 秒）")
    });
}

/// 查詢在 [`QUERY_DEADLINE`] 內沒有結果：Err(SERVFAIL 回應；查詢解析不了是 None)。計數，日誌每分鐘最多一行
async fn within_deadline<T, F: std::future::Future<Output = Option<T>>>(
    q: &[u8],
    proto: Proto,
    client: IpAddr,
    fut: F,
) -> Result<Option<T>, Option<Vec<u8>>> {
    within(QUERY_DEADLINE, q, proto, client, fut).await
}

async fn within<T, F: std::future::Future<Output = Option<T>>>(
    limit: Duration,
    q: &[u8],
    proto: Proto,
    client: IpAddr,
    fut: F,
) -> Result<Option<T>, Option<Vec<u8>>> {
    match tokio::time::timeout(limit, fut).await {
        Ok(r) => Ok(r),
        Err(_) => {
            note(NOTE_DEADLINE, |_| {
                format!(
                    "{} 查詢 {} 秒還沒有結果，回 SERVFAIL 給 {client}（處理中的名額馬上還回來）",
                    proto.name(),
                    limit.as_secs()
                )
            });
            Err(servfail_for(q))
        }
    }
}

/// 照著查詢做一個 SERVFAIL 回應（查詢解析不了回 None）
fn servfail_for(q: &[u8]) -> Option<Vec<u8>> {
    kuroshio_proto::Message::parse(q)
        .ok()
        .map(|m| kuroshio_proto::logic::servfail(&m).encode())
}

/// 查詢一筆（DoT、DoQ）：有期限，逾時回 SERVFAIL
async fn answer(r: &Arc<Resolver>, q: &[u8], proto: Proto, client: IpAddr) -> Option<Vec<u8>> {
    let ctx = Ctx {
        proto: proto.tag(),
        client,
    };
    within_deadline(q, proto, client, r.handle(q, &ctx)).await.unwrap_or_else(|e| e)
}

// ---------------- DoT ----------------

/// 剛接受的連線（3.5.1，`Serving::accept`）：連上之後 [`FRESH_GRACE`] 內要送來第一個位元組（TLS 的 ClientHello、
/// HTTP 的請求），不然不再算進處理中（預先連上、閒著的連線，重新載入時交接不等它）
async fn fresh_first_byte(fresh: Option<&Fresh>, tcp: &tokio::net::TcpStream) {
    let _ = hold_while(fresh, FRESH_GRACE, tcp.readable()).await;
}

/// TLS 握手最多 10 秒。剛接受的連線：第一個位元組 [`FRESH_GRACE`] 內要到、握手 [`FRESH_HANDSHAKE`] 內要完成，
/// 不然不再算進處理中（3.5.1）
async fn fresh_tls(
    fresh: Option<&Fresh>,
    tcp: tokio::net::TcpStream,
    acc: &tokio_rustls::TlsAcceptor,
) -> Option<tokio_rustls::server::TlsStream<tokio::net::TcpStream>> {
    fresh_first_byte(fresh, &tcp).await;
    let handshake = tokio::time::timeout(Duration::from_secs(10), acc.accept(tcp));
    match hold_while(fresh, FRESH_HANDSHAKE, handshake).await {
        Ok(Ok(s)) => Some(s),
        _ => None,
    }
}

pub async fn listen_dot(addr: SocketAddr, certs: Arc<CertStore>, resolver: Arc<Resolver>, limits: Limits) -> Result<SocketAddr> {
    let l = crate::netif::shared_tcp("dot", addr).with_context(|| format!("DoT 監聽 {addr} 失敗"))?;
    let bound = l.local_addr()?;
    // 社群共享開著時同一個埠也接 ALPN kuroshio/2（規格 03 第 4 節）
    let community = resolver.community.get().is_some();
    let alpn: &[&[u8]] = if community {
        &[b"dot", kuroshio_community::ALPN]
    } else {
        &[b"dot"]
    };
    let acceptor = tokio_rustls::TlsAcceptor::from(certs.server_config(alpn));
    info!("DoT 監聽 {bound}");
    // 重新載入時先停止接新的連線（`Serving::quiesce`；已經接上的照舊）
    let owner = resolver.clone();
    let accept = tokio::spawn(async move {
        loop {
            let (tcp, peer) = match l.accept().await {
                Ok(x) => x,
                Err(_) => {
                    // 檔案代號用完之類：稍等再接，不空轉
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    continue;
                }
            };
            if !crate::ipfilter::accept_dot(&resolver, peer.ip()) {
                continue; // 存取控制：直接關閉，不做 TLS 握手
            }
            // 連線數（總數、這個來源）或記憶體不夠：TLS 握手之前就關閉，已經建立的連線不受影響
            let permit = match limits.admit_from(peer.ip()) {
                Ok(p) => p,
                Err(why) => {
                    limits.refused(Proto::Dot, why, peer.ip());
                    continue;
                }
            };
            if !certs.ready() {
                continue;
            }
            // 接受了就算進處理中，第一筆查詢回完才放（重新載入時交接會等它，3.5.1；`Serving::accept`）
            let fresh = resolver.serving.accept().map(Arc::new);
            let (acc, r) = (acceptor.clone(), resolver.clone());
            tokio::spawn(async move {
                // 名額跟著這個工作：正常關閉、被重設、握手失敗或逾時、panic，結束時都會還回來
                let _permit = permit;
                let _ = tcp.set_nodelay(true);
                let Some(s) = fresh_tls(fresh.as_deref(), tcp, &acc).await else {
                    return;
                };
                let community = s.get_ref().1.alpn_protocol() == Some(kuroshio_community::ALPN);
                if !crate::ipfilter::after_alpn(&r, crate::ipfilter::Kind::Dot, community, peer.ip()) {
                    return;
                }
                if community {
                    // 社群（節點之間）的連線不算一般查詢：不等
                    drop(fresh);
                    if let Some(c) = r.community.get().cloned() {
                        c.serve_stream(s, peer.ip()).await;
                    }
                    return;
                }
                let client = peer.ip();
                dot_conn(s, fresh, move |q: Vec<u8>| {
                    let r = r.clone();
                    async move { answer(&r, &q, Proto::Dot, client).await }
                })
                .await;
            });
        }
    });
    owner.serving.add_loop(accept.abort_handle());
    Ok(bound)
}

/// 讀一筆 DoT 查詢的結果
enum DotRead {
    Query(Vec<u8>, tokio::sync::OwnedSemaphorePermit),
    /// 對方正常關閉寫的那一邊，或閒置逾時：處理中的照常回完
    End,
    /// 重設、讀取失敗、格式錯誤、送一半不送完、處理中的一直空不出來（對方不收回應）
    Broken,
}

async fn read_dot_query<R: tokio::io::AsyncRead + Unpin>(rd: &mut R, inflight: &Arc<Semaphore>) -> DotRead {
    // 處理中的查詢滿了：等回應送出再讀下一筆（30 秒都沒空出來 = 對方不收回應，關掉）
    let Ok(Ok(slot)) = tokio::time::timeout(Duration::from_secs(30), inflight.clone().acquire_owned()).await else {
        return DotRead::Broken;
    };
    // 閒置多久關閉：記憶體吃緊時縮短，把閒著的連線還回來
    let idle = if crate::app::pressure() == crate::sysinfo::Pressure::Normal {
        30
    } else {
        5
    };
    let len = match tokio::time::timeout(Duration::from_secs(idle), rd.read_u16()).await {
        Ok(Ok(l)) if l >= 12 => l as usize,
        Ok(Ok(_)) => return DotRead::Broken,
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return DotRead::End,
        Ok(Err(_)) => return DotRead::Broken,
        Err(_) => return DotRead::End,
    };
    let mut q = vec![0u8; len];
    if !matches!(tokio::time::timeout(READ_TIMEOUT, rd.read_exact(&mut q)).await, Ok(Ok(_))) {
        return DotRead::Broken;
    }
    DotRead::Query(q, slot)
}

/// DoT 的一條連線（RFC 7766）：同時多筆、回應不必照順序。`handle` 回答一筆查詢（呼叫端已經加上期限）。
///
/// 連線結束時處理中的查詢（3.5.1 K9）：
/// - 對方重設、讀寫失敗、不收回應：處理中的查詢立刻取消，函式馬上結束，連線名額跟著還回來。
///   以前要等每一筆查詢都結束才還：卡住的查詢讓已經斷掉的連線一直佔著這個來源的名額，
///   用戶端重新連線時被「每個來源的上限」拒絕，比例隨著卡住的查詢越積越高；
/// - 對方正常關閉寫的那一邊、閒置逾時：處理中的照常回完（每筆最多 [`QUERY_DEADLINE`]），這段期間寫失敗就全部取消
///
/// `fresh`：剛接受、第一筆查詢還沒回完（3.5.1，`Serving::accept`）。握手之後 [`FRESH_GRACE`] 內沒送查詢、
/// 第一筆回應寫出（或沒有回應）時放掉
pub(crate) async fn dot_conn<S, H, F>(s: S, fresh: Option<Arc<Fresh>>, handle: H)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    H: Fn(Vec<u8>) -> F,
    F: std::future::Future<Output = Option<Vec<u8>>> + Send + 'static,
{
    let (mut rd, mut wr) = tokio::io::split(s);
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
    // 寫出端：回應完成一筆寫一筆（不必照查詢順序）。對方 30 秒都不收就關掉連線
    let mut wrote_first = fresh.clone();
    let mut writer = tokio::spawn(async move {
        while let Some(resp) = rx.recv().await {
            let mut frame = (resp.len() as u16).to_be_bytes().to_vec();
            frame.extend_from_slice(&resp);
            if !matches!(
                tokio::time::timeout(Duration::from_secs(30), wr.write_all(&frame)).await,
                Ok(Ok(()))
            ) {
                return;
            }
            // 第一筆回應寫出去了：之後跟一般的連線一樣
            if let Some(f) = wrote_first.take() {
                f.release();
            }
        }
        let _ = tokio::time::timeout(Duration::from_secs(5), wr.shutdown()).await;
    });
    let mut writer_done = false;
    let inflight = Arc::new(Semaphore::new(DOT_MAX_INFLIGHT));
    // 處理中的查詢（最多 DOT_MAX_INFLIGHT 個）：連線斷掉時一起取消
    let mut tasks = tokio::task::JoinSet::new();
    // 第一筆查詢讀進來之前：握手之後 FRESH_GRACE 內沒送查詢就不再算進處理中
    let mut first = fresh;
    let clean = loop {
        // 收掉已經結束的（JoinSet 留著結束的工作直到被收走）
        while tasks.try_join_next().is_some() {}
        tokio::select! {
            biased;
            // 寫出端結束 = 寫失敗（對方重設或不收）：不用再讀了
            _ = &mut writer => {
                writer_done = true;
                break false;
            }
            r = hold_while(first.as_deref(), FRESH_GRACE, read_dot_query(&mut rd, &inflight)) => match r {
                DotRead::Query(q, slot) => {
                    let (fut, tx, first) = (handle(q), tx.clone(), first.take());
                    tasks.spawn(async move {
                        let _slot = slot;
                        match fut.await {
                            Some(resp) => {
                                let _ = tx.send(resp).await;
                            }
                            // 第一筆沒有回應：不必等寫出端
                            None => {
                                if let Some(f) = first {
                                    f.release();
                                }
                            }
                        }
                    });
                }
                DotRead::End => break true,
                DotRead::Broken => break false,
            }
        }
    };
    drop(tx);
    if clean {
        while !tasks.is_empty() {
            tokio::select! {
                biased;
                _ = &mut writer, if !writer_done => {
                    writer_done = true;
                    break;
                }
                _ = tasks.join_next() => {}
            }
        }
    }
    // 還沒結束的查詢取消（丟掉等待的 future；往上游查的合併工作是另外的工作，照樣做完填快取）
    tasks.abort_all();
    if !writer_done {
        if clean {
            // 回應寫完再關（寫一筆最多 30 秒、關閉最多 5 秒）
            let _ = (&mut writer).await;
        } else {
            writer.abort();
        }
    }
}

// ---------------- DoH ----------------

#[derive(Clone)]
pub struct DohOptions {
    pub path: String,
    /// 反向代理在本機時採用 X-Forwarded-For
    pub trust_proxy: bool,
    /// HTTP/3 開著時加 Alt-Svc
    pub alt_svc: Option<String>,
    /// 同時處理中的請求上限（所有 DoH 共用一份，3.5.1 K7）
    pub gate: DohGate,
}

impl DohOptions {
    pub fn new(path: impl Into<String>, gate: DohGate) -> DohOptions {
        DohOptions {
            path: path.into(),
            trust_proxy: false,
            alt_svc: None,
            gate,
        }
    }
}

fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            b'=' => continue,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

fn text(code: StatusCode, s: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(code)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from_static(s.as_bytes())))
        .unwrap()
}

/// 處理中的請求滿了：503 busy（不排隊；`Retry-After: 1` 請用戶端稍後再試）
pub fn busy_reply() -> (StatusCode, Vec<(&'static str, String)>, Bytes) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        vec![
            ("content-type", "text/plain; charset=utf-8".to_string()),
            ("retry-after", "1".to_string()),
        ],
        Bytes::from_static(b"busy\n"),
    )
}

/// DoH 請求（HTTP/1.1、HTTP/2、HTTP/3 共用）
pub struct DohReq {
    pub method: hyper::Method,
    pub path: String,
    pub query: Option<String>,
    pub content_type: String,
    pub forwarded_for: Option<String>,
    /// Host 標頭（HTTP/2、HTTP/3 是 :authority），公開頁沒設定網域時用
    pub host: Option<String>,
    pub body: Vec<u8>,
}

/// DoH 處理核心：回傳狀態碼、標頭、內容。
///
/// `admitted`：呼叫端已經佔了 [`DohGate`] 的名額（HTTP.sys 在接收的執行緒就先佔）；不然 DNS 查詢在這裡佔，
/// 滿了立刻回 503。查詢最多等 [`QUERY_DEADLINE`]，逾時回 SERVFAIL。這個 future 被丟掉（用戶端放棄、
/// HTTP/2 RST_STREAM、連線斷掉）時名額跟著還回來
pub async fn doh_core(
    req: DohReq,
    peer: IpAddr,
    r: &Arc<Resolver>,
    opts: &DohOptions,
    proto: &'static str,
    admitted: bool,
) -> (StatusCode, Vec<(&'static str, String)>, Bytes) {
    let txt = |code: StatusCode, s: &'static str| {
        (
            code,
            vec![("content-type", "text/plain; charset=utf-8".to_string())],
            Bytes::from_static(s.as_bytes()),
        )
    };
    let client = if opts.trust_proxy && peer.is_loopback() {
        req.forwarded_for
            .as_deref()
            .and_then(|v| v.split(',').next())
            .and_then(|v| parse_forwarded_ip(v.trim()))
            .unwrap_or(peer)
    } else {
        peer
    };
    if req.path == "/robots.txt" {
        return txt(StatusCode::OK, "User-agent: *\nDisallow: /\n");
    }
    // 存取控制（請求層級：反向代理時才知道真正的來源；同一個埠上的服務各自判斷）
    let site_ok = match crate::ipfilter::request_check(r, &req.path, &opts.path, proto, client) {
        Some(ok) => ok,
        None => return txt(StatusCode::FORBIDDEN, "forbidden\n"),
    };
    // 社群共享 v2（HTTPS 管道）
    if req.path.starts_with(kuroshio_community::BASE_PATH) {
        if let Some(c) = r.community.get() {
            if let Some((code, body)) = c.handle_http(req.method.as_str(), &req.path, &req.body, client).await {
                let code = StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                let h = if body.is_empty() {
                    vec![]
                } else {
                    vec![("content-type", "application/cbor".to_string())]
                };
                return (code, h, Bytes::from(body));
            }
        }
    }
    // 公開頁（首頁、詳細頁、/api/public/*、描述檔）：不是 DoH 查詢的 GET / HEAD 都先問它
    if let Some(site) = r.site.get().filter(|_| site_ok) {
        if let Some(resp) = site
            .handle(
                req.method.as_str(),
                &req.path,
                req.query.as_deref().unwrap_or(""),
                client,
                req.host.as_deref(),
            )
            .await
        {
            let code = StatusCode::from_u16(resp.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            return (code, resp.headers, resp.body);
        }
    }
    if req.path != opts.path {
        return txt(StatusCode::NOT_FOUND, "not found\n");
    }
    let query = match req.method {
        hyper::Method::GET => match req
            .query
            .as_deref()
            .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("dns=")))
            .and_then(base64url_decode)
        {
            Some(q) => q,
            None => {
                return txt(
                    StatusCode::OK,
                    "DNS over HTTPS endpoint. Use RFC 8484 GET ?dns= or POST application/dns-message.\n",
                )
            }
        },
        hyper::Method::POST => {
            if !req.content_type.starts_with("application/dns-message") {
                return txt(StatusCode::UNSUPPORTED_MEDIA_TYPE, "需要 application/dns-message\n");
            }
            req.body
        }
        _ => return txt(StatusCode::METHOD_NOT_ALLOWED, "GET / POST\n"),
    };
    if query.len() < 12 {
        return txt(StatusCode::BAD_REQUEST, "bad dns message\n");
    }
    let p = Proto::of_tag(proto);
    let _slot = if admitted {
        None
    } else {
        match opts.gate.try_enter() {
            Some(s) => Some(s),
            None => {
                opts.gate.note_busy(p, client);
                return busy_reply();
            }
        }
    };
    let ctx = Ctx { proto, client };
    match within_deadline(&query, p, client, r.handle_reply(&query, &ctx)).await {
        // 逾時：回 SERVFAIL（DNS 層的錯誤照 RFC 8484 用 200），不讓用戶端快取
        Err(Some(sf)) => (
            StatusCode::OK,
            vec![
                ("content-type", "application/dns-message".to_string()),
                ("cache-control", "max-age=0".to_string()),
                ("x-robots-tag", "noindex, nofollow".to_string()),
            ],
            Bytes::from(sf),
        ),
        Err(None) => busy_reply(),
        Ok(Some(reply)) => {
            // 回應的快取時間：答案的最小 TTL（沒有答案 0）
            let max_age = reply.min_ttl();
            let resp = reply.bytes;
            let mut h = vec![
                ("content-type", "application/dns-message".to_string()),
                ("cache-control", format!("max-age={max_age}")),
                ("x-robots-tag", "noindex, nofollow".to_string()),
            ];
            if let Some(a) = &opts.alt_svc {
                h.push(("alt-svc", a.clone()));
            }
            (StatusCode::OK, h, Bytes::from(resp))
        }
        // 重新載入：這一輪已經把快取交出去、正在結束，沒有答案的（問上游失敗）請用戶端稍後重試（新的一輪會回答）
        Ok(None) if r.serving.retired() => busy_reply(),
        Ok(None) => txt(StatusCode::BAD_REQUEST, "bad dns message\n"),
    }
}

pub async fn handle_doh(
    req: Request<hyper::body::Incoming>,
    peer: IpAddr,
    r: Arc<Resolver>,
    opts: Arc<DohOptions>,
) -> Response<Full<Bytes>> {
    let hdr = |k: &str| req.headers().get(k).and_then(|v| v.to_str().ok()).map(str::to_string);
    let (content_type, forwarded_for) = (hdr("content-type").unwrap_or_default(), hdr("x-forwarded-for"));
    let host = hdr("host").or_else(|| req.uri().authority().map(|a| a.to_string()));
    let (method, path, query) = (
        req.method().clone(),
        req.uri().path().to_string(),
        req.uri().query().map(str::to_string),
    );
    // 內容最多等 READ_TIMEOUT（只送標頭、內容一直不送完的請求不會一直佔著）。
    // 處理中的名額在內容讀完、要查詢時才佔（doh_core）
    let body = if method == hyper::Method::POST {
        match tokio::time::timeout(READ_TIMEOUT, Limited::new(req.into_body(), 65535).collect()).await {
            Ok(Ok(b)) => b.to_bytes().to_vec(),
            Ok(Err(_)) => return text(StatusCode::PAYLOAD_TOO_LARGE, "too large\n"),
            Err(_) => return text(StatusCode::REQUEST_TIMEOUT, "timeout\n"),
        }
    } else {
        Vec::new()
    };
    let (code, headers, body) = doh_core(
        DohReq {
            method,
            path,
            query,
            content_type,
            forwarded_for,
            host,
            body,
        },
        peer,
        &r,
        &opts,
        "doh",
        false,
    )
    .await;
    let mut b = Response::builder().status(code);
    for (k, v) in headers {
        b = b.header(k, v);
    }
    b.body(Full::new(body)).unwrap()
}

/// DoH 監聽；`certs` 為 None 時是純 HTTP（給本機反向代理）
pub async fn listen_doh(
    addr: SocketAddr,
    certs: Option<Arc<CertStore>>,
    resolver: Arc<Resolver>,
    opts: DohOptions,
    limits: Limits,
) -> Result<SocketAddr> {
    let l = crate::netif::shared_tcp("doh", addr).with_context(|| format!("DoH 監聽 {addr} 失敗"))?;
    let bound = l.local_addr()?;
    let acceptor = certs
        .as_ref()
        .map(|c| tokio_rustls::TlsAcceptor::from(c.server_config(&[b"h2", b"http/1.1"])));
    info!("DoH 監聽 {}://{bound}{}", if certs.is_some() { "https" } else { "http" }, opts.path);
    let opts = Arc::new(opts);
    // 重新載入時先停止接新的連線（`Serving::quiesce`；已經接上的照舊）
    let owner = resolver.clone();
    let accept = tokio::spawn(async move {
        loop {
            let (tcp, peer) = match l.accept().await {
                Ok(x) => x,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    continue;
                }
            };
            if !crate::ipfilter::accept_doh(&resolver, peer.ip()) {
                continue; // 存取控制：直接關閉，不做 TLS 握手
            }
            // 連線數（總數、這個來源；跟 DoT 共用）或記憶體不夠：TLS 握手之前就關閉
            let permit = match limits.admit_from(peer.ip()) {
                Ok(p) => p,
                Err(why) => {
                    limits.refused(Proto::Doh, why, peer.ip());
                    continue;
                }
            };
            if certs.as_ref().map(|c| !c.ready()).unwrap_or(false) {
                continue;
            }
            // 接受了就算進處理中，第一個請求回完才放（重新載入時交接會等它，3.5.1；`Serving::accept`）
            let fresh = resolver.serving.accept().map(Arc::new);
            let (acc, r, o) = (acceptor.clone(), resolver.clone(), opts.clone());
            tokio::spawn(async move {
                let _permit = permit;
                let _ = tcp.set_nodelay(true);
                let f = fresh.clone();
                let svc = hyper::service::service_fn(move |req| {
                    let (r, o) = (r.clone(), o.clone());
                    // 第一個請求（還算在處理中時）：開始處理時標記、回完放掉；之後的請求只多一次原子讀取
                    let first = f.as_ref().filter(|f| f.held()).cloned();
                    async move {
                        if let Some(f) = &first {
                            f.start();
                        }
                        let resp = handle_doh(req, peer.ip(), r, o).await;
                        if let Some(f) = first {
                            f.release();
                        }
                        Ok::<_, std::convert::Infallible>(resp)
                    }
                });
                let mut builder = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
                // 標頭要在 10 秒內送完；HTTP/2 每條連線最多 64 個同時進行的請求，定時 ping 清掉斷線的
                builder
                    .http1()
                    .timer(hyper_util::rt::TokioTimer::new())
                    .header_read_timeout(READ_TIMEOUT);
                builder
                    .http2()
                    .timer(hyper_util::rt::TokioTimer::new())
                    .max_concurrent_streams(DOH_MAX_STREAMS)
                    .keep_alive_interval(Duration::from_secs(30))
                    .keep_alive_timeout(Duration::from_secs(10));
                // 剛接受的連線：握手之後（純 HTTP 是連上之後）FRESH_GRACE 內第一個請求沒進來就不再算進處理中
                let res = match acc {
                    Some(acc) => match fresh_tls(fresh.as_deref(), tcp, &acc).await {
                        Some(s) => {
                            let conn = builder.serve_connection(hyper_util::rt::TokioIo::new(s), svc);
                            hold_while(fresh.as_deref(), FRESH_GRACE, conn).await
                        }
                        None => return,
                    },
                    None => {
                        fresh_first_byte(fresh.as_deref(), &tcp).await;
                        let conn = builder.serve_connection(hyper_util::rt::TokioIo::new(tcp), svc);
                        hold_while(fresh.as_deref(), FRESH_GRACE, conn).await
                    }
                };
                if let Err(e) = res {
                    debug!("DoH 連線結束：{e}");
                }
            });
        }
    });
    owner.serving.add_loop(accept.abort_handle());
    Ok(bound)
}

// ---------------- QUIC：DoQ（RFC 9250）與 DoH3 ----------------

/// QUIC 端點：IPv6 位址設 `IPV6_V6ONLY`（`0.0.0.0` 與 `::` 可以同時綁同一個埠）
/// UDP socket 經過 `listenbank`：重新載入時新的 `Endpoint` 建在同一個核心 socket 的複製品上
/// （空窗期間的封包留在接收緩衝區；進行中的 QUIC 連線照舊會斷）
fn quic_endpoint(tag: &'static str, cfg: quinn::ServerConfig, addr: SocketAddr) -> std::io::Result<quinn::Endpoint> {
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(cfg),
        crate::netif::shared_udp(tag, addr)?,
        Arc::new(quinn::TokioRuntime),
    )
}

fn quic_server(certs: &Arc<CertStore>, alpn: &[&[u8]], max_conns: u32) -> Result<quinn::ServerConfig> {
    let tls = certs.server_config(alpn);
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(|e| anyhow!("QUIC TLS 設定：{e}"))?;
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    // 不做路徑 MTU 探測（3.5.1 K3，同用戶端）
    let mut t = kuroshio_net::quic::dns_transport();
    t.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    // 每條連線同時最多 128 筆查詢（雙向串流）
    t.max_concurrent_bidi_streams(128u32.into());
    t.max_concurrent_uni_streams(16u32.into());
    cfg.transport_config(Arc::new(t));
    cfg.max_incoming(max_conns.max(1) as usize);
    Ok(cfg)
}

/// DoQ：每筆查詢一條雙向串流，2 bytes 長度 + 訊息，id 必須是 0
pub async fn listen_doq(addr: SocketAddr, certs: Arc<CertStore>, resolver: Arc<Resolver>, limits: Limits) -> Result<SocketAddr> {
    let max = limits.conns.available_permits() as u32;
    let ep = quic_endpoint(
        "doq",
        quic_server(
            &certs,
            if resolver.community.get().is_some() {
                &[b"doq", kuroshio_community::ALPN]
            } else {
                &[b"doq"]
            },
            max,
        )?,
        addr,
    )
    .with_context(|| format!("DoQ 監聽 UDP {addr} 失敗"))?;
    let bound = ep.local_addr()?;
    info!("DoQ 監聽 UDP {bound}");
    tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            if !crate::ipfilter::accept_doq(&resolver, incoming.remote_address().ip()) {
                incoming.ignore(); // 存取控制：不回任何封包
                continue;
            }
            let Some((incoming, mut permit)) = limits.admit_quic(incoming, Proto::Doq) else {
                continue;
            };
            let (r, limits) = (resolver.clone(), limits.clone());
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                let client = conn.remote_address().ip();
                // 握手完成才計入這個來源的名額；滿了用 DOQ_EXCESSIVE_LOAD（0x4）關閉
                if !permit.established(&limits, Proto::Doq, client) {
                    conn.close(0x4u32.into(), b"");
                    return;
                }
                let _permit = permit;
                let proto = conn
                    .handshake_data()
                    .and_then(|h| h.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                    .and_then(|h| h.protocol);
                let community = proto.as_deref() == Some(kuroshio_community::ALPN);
                if !crate::ipfilter::after_alpn(&r, crate::ipfilter::Kind::Doq, community, client) {
                    return;
                }
                if community {
                    if let Some(c) = r.community.get().cloned() {
                        c.serve_quic(conn, client).await;
                    }
                    return;
                }
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let r = r.clone();
                    tokio::spawn(async move {
                        let Ok(Ok(buf)) = tokio::time::timeout(READ_TIMEOUT, recv.read_to_end(65537)).await else {
                            return;
                        };
                        if buf.len() < 14 {
                            return;
                        }
                        let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                        let Some(q) = buf.get(2..2 + len) else { return };
                        if let Some(resp) = answer(&r, q, Proto::Doq, client).await {
                            let mut out = (resp.len() as u16).to_be_bytes().to_vec();
                            out.extend_from_slice(&resp);
                            let _ = send.write_all(&out).await;
                            let _ = send.finish();
                        }
                    });
                }
            });
        }
    });
    Ok(bound)
}

/// DoH3：HTTP/3 上的 DoH，處理邏輯跟 HTTP/1.1、HTTP/2 共用 `doh_core`
pub async fn listen_doh3(
    addr: SocketAddr,
    certs: Arc<CertStore>,
    resolver: Arc<Resolver>,
    opts: DohOptions,
    limits: Limits,
) -> Result<SocketAddr> {
    use bytes::Buf;
    let max = limits.conns.available_permits() as u32;
    let ep = quic_endpoint("doh3", quic_server(&certs, &[b"h3"], max)?, addr).with_context(|| format!("DoH3 監聽 UDP {addr} 失敗"))?;
    let bound = ep.local_addr()?;
    info!("DoH3 監聽 UDP {bound}{}", opts.path);
    let opts = Arc::new(opts);
    tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            if !crate::ipfilter::accept_doh3(&resolver, incoming.remote_address().ip()) {
                incoming.ignore(); // 存取控制：不回任何封包
                continue;
            }
            let Some((incoming, mut permit)) = limits.admit_quic(incoming, Proto::Doh3) else {
                continue;
            };
            let (r, o, limits) = (resolver.clone(), opts.clone(), limits.clone());
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                let peer = conn.remote_address().ip();
                // 握手完成才計入這個來源的名額；滿了用 H3_EXCESSIVE_LOAD（0x107）關閉
                if !permit.established(&limits, Proto::Doh3, peer) {
                    conn.close(0x107u32.into(), b"");
                    return;
                }
                let _permit = permit;
                let Ok(mut h3c) = h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn)).await else {
                    return;
                };
                while let Ok(Some(resolver)) = h3c.accept().await {
                    let (r, o) = (r.clone(), o.clone());
                    tokio::spawn(async move {
                        let Ok((req, mut stream)) = resolver.resolve_request().await else {
                            return;
                        };
                        let hdr = |k: &str| req.headers().get(k).and_then(|v| v.to_str().ok()).map(str::to_string);
                        let mut body = Vec::new();
                        if req.method() == hyper::Method::POST {
                            // 內容最多等 READ_TIMEOUT
                            let read = async {
                                while let Ok(Some(mut chunk)) = stream.recv_data().await {
                                    let n = chunk.remaining();
                                    body.extend_from_slice(&chunk.copy_to_bytes(n));
                                    if body.len() > 65535 {
                                        return false;
                                    }
                                }
                                true
                            };
                            if !matches!(tokio::time::timeout(READ_TIMEOUT, read).await, Ok(true)) {
                                return;
                            }
                        }
                        let dreq = DohReq {
                            method: req.method().clone(),
                            path: req.uri().path().to_string(),
                            query: req.uri().query().map(str::to_string),
                            content_type: hdr("content-type").unwrap_or_default(),
                            forwarded_for: None,
                            host: req.uri().authority().map(|a| a.to_string()).or_else(|| hdr("host")),
                            body,
                        };
                        let (code, headers, out) = doh_core(dreq, peer, &r, &o, "doh3", false).await;
                        let mut resp = http::Response::builder().status(code.as_u16());
                        for (k, v) in headers {
                            resp = resp.header(k, v);
                        }
                        if stream.send_response(resp.body(()).unwrap()).await.is_ok() {
                            let _ = stream.send_data(out).await;
                            let _ = stream.finish().await;
                        }
                    });
                }
            });
        }
    });
    Ok(bound)
}

/// X-Forwarded-For 的第一段：IIS ARR 預設會帶埠號（`1.2.3.4:5678`、`[2001:db8::1]:5678`）
pub fn parse_forwarded_ip(v: &str) -> Option<IpAddr> {
    v.parse::<IpAddr>()
        .ok()
        .or_else(|| v.parse::<SocketAddr>().ok().map(|s| s.ip()))
        .or_else(|| v.trim_start_matches('[').split(']').next()?.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_source_connection_limit() {
        let l = Limits::new(64).with_per_ip(Some(2));
        let a: IpAddr = "203.0.113.5".parse().unwrap();
        let p1 = l.admit_from(a).unwrap();
        let _p2 = l.admit_from(a).unwrap();
        assert_eq!(l.admit_from(a).err(), Some(Refusal::PerSource), "同一個來源超過上限");
        assert!(l.admit_from("203.0.113.6".parse().unwrap()).is_ok(), "別的來源不受影響");
        // 同一段 /64 的 IPv6 算同一個來源；IPv4-mapped 跟 IPv4 一樣
        let v6a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let v6b: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        let _q1 = l.admit_from(v6a).unwrap();
        let _q2 = l.admit_from(v6b).unwrap();
        assert!(l.admit_from("2001:db8:1:2::77".parse().unwrap()).is_err());
        assert!(l.admit_from("2001:db8:1:3::1".parse().unwrap()).is_ok());
        assert!(l.admit_from("::ffff:203.0.113.5".parse().unwrap()).is_err());
        // 本機（反向代理）不算
        for _ in 0..5 {
            std::mem::forget(l.admit_from("127.0.0.1".parse().unwrap()).unwrap());
        }
        // 連線結束就還回來
        drop(p1);
        assert_eq!(l.source_count(a), 1);
        assert!(l.admit_from(a).is_ok());
        // 3.5.1 K9：總上限的 1/4，16–256（以前 1/8、8–64：四核心以上剛好 64 條）
        assert_eq!(per_ip_default(128), 32);
        assert_eq!(per_ip_default(512), 128);
        assert_eq!(per_ip_default(2048), 256);
        assert_eq!(per_ip_default(32), 16);
        assert_eq!(doh_inflight_default(128), 64);
        assert_eq!(doh_inflight_default(512), 256);
        assert_eq!(doh_inflight_default(4096), 1024);
        // QUIC：握手期間只佔總數，握手完成才計入這個來源；滿了 established 回 false
        let q = Limits::new(64).with_per_ip(Some(1));
        let ip_a: IpAddr = "198.51.100.9".parse().unwrap();
        let mk = |l: &Limits| {
            l.handshaking.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            QuicPermit {
                _conn: l.admit().unwrap(),
                handshaking: Some(l.handshaking.clone()),
                _src: None,
            }
        };
        let (mut h1, mut h2, h3) = (mk(&q), mk(&q), mk(&q));
        assert_eq!(q.handshaking.load(std::sync::atomic::Ordering::Relaxed), 3, "握手中的不佔來源名額");
        assert!(h1.established(&q, Proto::Doq, ip_a));
        assert!(!h2.established(&q, Proto::Doq, ip_a), "這個來源滿了");
        drop(h3);
        assert_eq!(q.handshaking.load(std::sync::atomic::Ordering::Relaxed), 0);
        drop((h1, h2));
        assert!(q.claim_source(ip_a).unwrap().is_some(), "連線結束就還回來");
        assert_eq!(Limits::new(64).retry_threshold(), 16);
        assert_eq!(Limits::new(16).retry_threshold(), 8);
        // 0 = 不限
        let u = Limits::new(64).with_per_ip(Some(0));
        let held: Vec<_> = (0..10).map(|_| u.admit_from(a).unwrap()).collect();
        assert_eq!(held.len(), 10);
        // 總數滿了：原因是 Total，這個來源的名額不會被佔走
        let t = Limits::new(1).with_per_ip(Some(4));
        let _only = t.admit_from(ip_a).unwrap();
        assert_eq!(t.admit_from(ip_a).err(), Some(Refusal::Total));
        assert_eq!(t.source_count(ip_a), 1, "被拒絕的那一次沒有留下來源計數");
        assert_eq!(t.in_use(), 1);
    }

    /// 有上限的日誌：同一類 1 分鐘內只寫一行，次數照算
    #[test]
    fn notes_are_counted_and_rate_limited() {
        use std::sync::atomic::Ordering::Relaxed;
        let n = &NOTES[NOTE_HTTPSYS_BODY];
        let c0 = n.count.load(Relaxed);
        let mut lines = 0;
        for _ in 0..5 {
            note(NOTE_HTTPSYS_BODY, |_| {
                lines += 1;
                "測試".to_string()
            });
        }
        assert_eq!(n.count.load(Relaxed), c0 + 5);
        assert!(lines <= 1, "1 分鐘內最多一行：{lines}");
        assert_eq!(server_json()["httpsysBodyBusy"], serde_json::json!(c0 + 5));
    }

    /// DoH 的處理中名額：滿了立刻拿不到（不等）；正常結束、被取消（用戶端放棄）、panic 都還回來
    #[tokio::test]
    async fn doh_gate_is_immediate_and_always_returned() {
        let g = DohGate::new(2);
        let a = g.try_enter().unwrap();
        let b = g.try_enter().unwrap();
        let t0 = Instant::now();
        assert!(g.try_enter().is_none(), "滿了");
        assert!(t0.elapsed() < Duration::from_millis(50), "不排隊");
        assert_eq!(g.in_use(), 2);
        drop(a);
        assert_eq!(g.in_use(), 1);
        // 處理中的請求被取消（hyper 在 RST_STREAM、連線斷掉時丟掉 future）
        let s = g.try_enter().unwrap();
        let task = tokio::spawn(async move {
            let _s = s;
            std::future::pending::<()>().await
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(g.in_use(), 2);
        task.abort();
        let _ = task.await;
        assert_eq!(g.in_use(), 1, "取消也還回來");
        // panic
        let s = g.try_enter().unwrap();
        let task = tokio::spawn(async move {
            let _s = s;
            panic!("測試用");
        });
        assert!(task.await.is_err());
        assert_eq!(g.in_use(), 1, "panic 也還回來");
        drop(b);
        assert_eq!(g.in_use(), 0);
    }

    /// 查詢逾時回 SERVFAIL（同一個 id）
    #[tokio::test]
    async fn deadline_gives_servfail() {
        let q = kuroshio_proto::build_query(77, "slow.example.com", 1);
        let ip: IpAddr = "192.0.2.7".parse().unwrap();
        let r = within(
            Duration::from_millis(30),
            &q,
            Proto::Dot,
            ip,
            std::future::pending::<Option<Vec<u8>>>(),
        )
        .await;
        let sf = r.unwrap_err().expect("查詢解析得了就有 SERVFAIL");
        let m = kuroshio_proto::Message::parse(&sf).unwrap();
        assert_eq!((m.id, m.rcode), (77, 2));
        let ok = within(Duration::from_secs(1), &q, Proto::Dot, ip, async { Some(vec![1u8]) }).await;
        assert_eq!(ok.unwrap(), Some(vec![1u8]));
        assert!(servfail_for(b"short").is_none());
    }

    /// 讀到 EOF 時回「連線被重設」（模擬用戶端放棄、RST）
    struct ResetOnEof(tokio::io::DuplexStream);

    impl tokio::io::AsyncRead for ResetOnEof {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let before = buf.filled().len();
            match std::pin::Pin::new(&mut self.0).poll_read(cx, buf) {
                std::task::Poll::Ready(Ok(())) if buf.filled().len() == before && buf.remaining() > 0 => {
                    std::task::Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()))
                }
                other => other,
            }
        }
    }

    impl tokio::io::AsyncWrite for ResetOnEof {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
        }
        fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.0).poll_flush(cx)
        }
        fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    fn frame(q: &[u8]) -> Vec<u8> {
        let mut f = (q.len() as u16).to_be_bytes().to_vec();
        f.extend_from_slice(q);
        f
    }

    /// 處理中的查詢被丟掉時加一
    struct Dropped(Arc<std::sync::atomic::AtomicUsize>);

    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// 3.5.1 K9：連線被重設時，卡住的查詢馬上取消、這個來源的名額馬上還回來
    /// （以前要等查詢自己結束：卡住的查詢讓斷掉的連線一直佔著名額，新連線被拒絕的比例越來越高）
    #[tokio::test]
    async fn dot_reset_returns_source_slot_immediately() {
        let l = Limits::new(64).with_per_ip(Some(1));
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        let permit = l.admit_from(ip).unwrap();
        assert_eq!(l.admit_from(ip).err(), Some(Refusal::PerSource));
        let (mut client, server) = tokio::io::duplex(4096);
        let dropped = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let d = dropped.clone();
        let conn = tokio::spawn(async move {
            let _permit = permit;
            dot_conn(ResetOnEof(server), None, move |_q| {
                let g = Dropped(d.clone());
                async move {
                    let _g = g;
                    // 卡住的查詢（測試裡永遠不結束）
                    std::future::pending::<Option<Vec<u8>>>().await
                }
            })
            .await;
        });
        for i in 0..3u16 {
            client
                .write_all(&frame(&kuroshio_proto::build_query(i, "stuck.example.com", 1)))
                .await
                .unwrap();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(l.source_count(ip), 1);
        drop(client); // 用戶端放棄：伺服器讀到「連線被重設」
        tokio::time::timeout(Duration::from_secs(2), conn)
            .await
            .expect("連線被重設要馬上收尾，不等卡住的查詢")
            .unwrap();
        assert_eq!(dropped.load(std::sync::atomic::Ordering::SeqCst), 3, "處理中的查詢都取消了");
        assert_eq!(l.source_count(ip), 0, "名額還回來");
        assert!(l.admit_from(ip).is_ok(), "同一個來源可以再連");
    }

    /// 用戶端只關閉寫的那一邊（還在等回應）：處理中的照常回完
    #[tokio::test]
    async fn dot_half_close_still_answers() {
        let (client, server) = tokio::io::duplex(4096);
        let conn = tokio::spawn(dot_conn(server, None, |q: Vec<u8>| async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let m = kuroshio_proto::Message::parse(&q).ok()?;
            Some(kuroshio_proto::Message::response_to(&m, 0).encode())
        }));
        let (mut rd, mut wr) = tokio::io::split(client);
        wr.write_all(&frame(&kuroshio_proto::build_query(9, "a.example.com", 1)))
            .await
            .unwrap();
        wr.shutdown().await.unwrap();
        let len = tokio::time::timeout(Duration::from_secs(2), rd.read_u16()).await.unwrap().unwrap();
        let mut buf = vec![0u8; len as usize];
        rd.read_exact(&mut buf).await.unwrap();
        assert_eq!(kuroshio_proto::Message::parse(&buf).unwrap().id, 9);
        tokio::time::timeout(Duration::from_secs(2), conn).await.unwrap().unwrap();
    }

    #[test]
    fn b64url() {
        assert_eq!(base64url_decode("AAABAAAB").unwrap(), vec![0, 0, 1, 0, 0, 1]);
        assert_eq!(base64url_decode("_-8").unwrap(), vec![0xff, 0xef]);
        assert!(base64url_decode("a b").is_none());
    }
}
