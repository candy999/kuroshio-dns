//! 解析主流程（對齊 2.x `lib/resolver.js`）：
//! 過濾 → 快取 → 並行上游（第一個正常回應先回）→ 背景合併所有 IP、測速排序。
//! CDN 台灣節點改寫在階段 2 接上。

use crate::cache::{Cache, Entry};
use crate::iprank::IpRank;
use crate::stats::{Kind as StatKind, Stats};
use crate::upstream::Upstream;
use crate::upstreams::{Manager, Role, Up};
use kuroshio_config::chain::Backfill;
use kuroshio_proto::logic::{self, ede, Class};
use kuroshio_proto::message::{normalize, rtype, Message, RData, Record};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tracing::{debug, warn};

/// 過濾判定（由過濾引擎提供）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub block: bool,
    /// 白名單：命中後不再檢查 CNAME 鏈
    pub allow: bool,
    /// ads / telemetry / malware / custom
    pub category: &'static str,
    /// 給日誌與 EDE 看的說明（命中的規則或網域）
    pub rule: String,
    /// 命中的是「繞過防護」清單（`filter.lists[].bypass`；自訂規則一律 false）。
    /// 串接模式（3.4.0）：登記中的下游查它登記的名稱時不擋（規格 10 的 4.4）
    pub bypass: bool,
}

pub trait FilterCheck: Send + Sync {
    fn check(&self, name: &str, qtype: u16) -> Option<Verdict>;
    fn stats(&self) -> Value {
        Value::Null
    }
}

#[derive(Debug, Clone)]
pub struct Params {
    pub timeout: Duration,
    pub window: Duration,
    pub fast_path: bool,
    pub fast_path_ttl: u32,
    pub rank_ips: bool,
    pub max_ips: usize,
    pub max_ttl: u32,
    pub min_ttl: u32,
    pub negative_max_ttl: u32,
    pub serve_stale: u64,
    /// 所有上游都失敗時，過期多久的舊資料還能回（規格 06 第 1.3 節）
    pub stale_if_error: u64,
    pub prefetch_threshold: f64,
    pub prefetch_recent: Duration,
    pub parallel: usize,
    pub hedge: Duration,
    /// 問上游時帶本機對外 IP 的 /24（ECS），讓 CDN 依台灣位置回答
    pub send_ecs: bool,
    /// 背景補問（規格 10 第 5.2 節，`resolver.backfill`）：`parallel` 有限制時，回答之後在背景問這次沒問到的上游
    pub backfill: Backfill,
    /// 非 CDN 的 A／AAAA 查詢每幾次抽一次補問（`resolver.backfillSample`；0 = 不抽樣）
    pub backfill_sample: u64,
    /// 同時最多幾個補問（1～2 核心 2、其他 4；拿不到名額就不補問，不排隊）
    pub backfill_max: usize,
    /// 上游成敗的記法（3.5.0 F4，`upstream.roundAwareFailures`，預設開）：來不及回答（被取消）的上游記得到、
    /// 大家都答不出來的那一輪不算個別上游失敗。關掉＝3.4.x 的記法。規格 11 第 6.2 節骨架，乙批接上
    pub round_aware_failures: bool,
    /// 特殊用途網域（RFC 6761：`.invalid`、`.test`、`.localhost`、`.onion`、`.example`）在本機回答
    /// （`resolver.specialUse`，預設開，3.5.1）。關掉＝3.5.0 的行為：照一般網域問上游
    pub special_use: bool,
    /// 被封鎖的答案的 TTL（秒，`filter.blockedTtl`，預設 60、最多 3600；3.5.0 以前固定 10 秒）
    pub blocked_ttl: u32,
}

impl Params {
    pub fn from_cfg(cfg: &Value) -> Params {
        let n = |k: &str, d: u64| {
            kuroshio_config::get(cfg, &format!("resolver.{k}"))
                .and_then(Value::as_u64)
                .unwrap_or(d)
        };
        let b = |k: &str, d: bool| {
            kuroshio_config::get(cfg, &format!("resolver.{k}"))
                .and_then(Value::as_bool)
                .unwrap_or(d)
        };
        let (backfill, backfill_sample) = kuroshio_config::chain::backfill_of(cfg);
        Params {
            timeout: Duration::from_millis(n("timeoutMs", 1500)),
            window: Duration::from_millis(n("collectWindowMs", 600)),
            fast_path: b("fastPath", true),
            fast_path_ttl: n("fastPathTtl", 10) as u32,
            rank_ips: b("rankIps", true),
            max_ips: n("maxIps", 4).max(1) as usize,
            max_ttl: n("maxTtl", 600) as u32,
            min_ttl: n("minTtl", 0) as u32,
            negative_max_ttl: n("negativeMaxTtl", 300) as u32,
            serve_stale: n("serveStaleSec", 3600),
            stale_if_error: n("staleIfErrorSec", 86400),
            prefetch_threshold: n("prefetchThresholdSec", 5) as f64,
            prefetch_recent: Duration::from_secs(n("prefetchRecentSec", 600)),
            parallel: n("parallel", 0) as usize,
            hedge: Duration::from_millis(300),
            send_ecs: b("sendEcs", true),
            backfill,
            backfill_sample,
            backfill_max: if kuroshio_config::Host::detect().cores <= 2 { 2 } else { 4 },
            round_aware_failures: kuroshio_config::chain::flex_bool(kuroshio_config::get(cfg, "upstream.roundAwareFailures"), true).0,
            special_use: b("specialUse", true),
            blocked_ttl: kuroshio_config::get(cfg, "filter.blockedTtl")
                .and_then(Value::as_u64)
                .unwrap_or(logic::BLOCKED_TTL as u64)
                .min(3600) as u32,
        }
    }
}

/// 特殊用途網域（RFC 6761、RFC 7686）在本機怎麼回答
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecialUse {
    /// `localhost` 與底下的名稱：A 回 127.0.0.1、AAAA 回 ::1、其他類型空答案（RFC 6761 6.3）
    Localhost,
    /// `.invalid`、`.test`、`.onion`、`.example`：一律 NXDOMAIN（根區沒有這些頂級網域，問上游的結果也是不存在）
    NxDomain,
}

/// 名稱（小寫、結尾沒有點）是不是特殊用途網域。只看最後一段：查詢路徑上只多一次字串比較、不配置。
/// `example.com`、`example.net` 是一般網域（IANA 的範例網站），照常解析
pub fn special_use(name: &str) -> Option<SpecialUse> {
    match name.rsplit('.').next()? {
        "localhost" => Some(SpecialUse::Localhost),
        "invalid" | "test" | "onion" | "example" => Some(SpecialUse::NxDomain),
        _ => None,
    }
}

/// 特殊用途網域的回答（不問上游、不快取、不算進排行）
fn special_use_response(query: &Message, kind: SpecialUse) -> Message {
    match kind {
        SpecialUse::NxDomain => Message::response_to(query, 3),
        SpecialUse::Localhost => {
            let mut r = Message::response_to(query, 0);
            if let Some(q) = query.question() {
                match q.qtype {
                    rtype::A => r.answers.push(Record::a(&q.name, 3600, std::net::Ipv4Addr::LOCALHOST)),
                    rtype::AAAA => r.answers.push(Record::aaaa(&q.name, 3600, std::net::Ipv6Addr::LOCALHOST)),
                    _ => {}
                }
            }
            r
        }
    }
}

/// 區網網域與私有 IP 反查交給本機 dnsmasq（OpenWrt 接管 53 埠時）
pub struct LocalForward {
    pub up: Upstream,
    pub domains: Vec<String>,
    pub private_ptr: bool,
}

impl LocalForward {
    pub fn matches(&self, qname: &str) -> bool {
        if self.domains.iter().any(|d| qname == d || qname.ends_with(&format!(".{d}"))) {
            return true;
        }
        if !self.private_ptr {
            return false;
        }
        if let Some(rest) = qname.strip_suffix(".in-addr.arpa") {
            let o: Vec<u32> = rest.split('.').rev().map(|x| x.parse().unwrap_or(999)).collect();
            let (a, b) = (o.first().copied().unwrap_or(999), o.get(1).copied().unwrap_or(999));
            return a == 10
                || a == 127
                || (a == 192 && b == 168)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 169 && b == 254)
                || (a == 100 && (64..=127).contains(&b));
        }
        if let Some(rest) = qname.strip_suffix(".ip6.arpa") {
            let n: String = rest.split('.').rev().collect();
            return n.starts_with("fc")
                || n.starts_with("fd")
                || ["fe8", "fe9", "fea", "feb"].iter().any(|p| n.starts_with(p))
                || n == format!("{}1", "0".repeat(31));
        }
        false
    }
}

struct Answer {
    up: Arc<Up>,
    msg: Message,
    class: Class,
    ms: f64,
}

/// `ask()` 的結果：收到的回答，以及這次沒有問到的上游（`parallel` 有限制時；背景補問用）
#[derive(Default)]
struct Asked {
    answers: Vec<Arc<Answer>>,
    unasked: Vec<Arc<Up>>,
}

struct Decided {
    msg: Message,
    class: Class,
    source: String,
    oks: Vec<Arc<Answer>>,
    /// 用的是串接上游（上游黑潮）的回答：CDN 節點與 IP 排序上游已經做過（3.4.1）
    chained: bool,
}

type Waiters = Vec<oneshot::Sender<Arc<Entry>>>;

pub struct Resolver {
    pub params: Params,
    pub upstreams: Arc<Manager>,
    pub cache: Mutex<Cache>,
    pub stats: Arc<Stats>,
    pub iprank: Arc<IpRank>,
    pub local: Option<LocalForward>,
    pub filter: RwLock<Option<Arc<dyn FilterCheck>>>,
    /// DDR（RFC 9462）：回答 `_dns.resolver.arpa` 的目標網域與各加密協議
    pub ddr: RwLock<Option<(String, Vec<logic::DdrEndpoint>)>>,
    /// CDN 台灣節點（規格 06）：回應前改寫答案
    pub cdn: RwLock<Option<Arc<kuroshio_cdn::Cdn>>>,
    /// 記憶體控制暫停 CDN 調整（規格 09 的最低限度）
    pub cdn_suspended: std::sync::atomic::AtomicBool,
    /// 社群共享（加密監聽上的 `/.well-known/kuroshio/v2`、ALPN `kuroshio/2`）
    pub community: crate::community_bridge::Slot,
    /// 公開頁（DoH 監聽上的首頁與公開 API）
    pub site: std::sync::OnceLock<Arc<crate::site::Site>>,
    /// 「這台裝置有沒有在用」偵測
    pub presence: std::sync::OnceLock<Arc<crate::presence::Presence>>,
    /// 來源 IP 存取控制（規格 08）；沒設定 = 不擋
    pub access: std::sync::OnceLock<Arc<crate::ipfilter::Access>>,
    /// 串接模式的上游回應器（`chain.kuroshio` 的 CH 查詢）；沒設定 = 一律 REFUSED
    pub chain: std::sync::OnceLock<Arc<crate::chain::responder::Responder>>,
    /// 本機對外 IP 的 /24（啟動後偵測）
    pub ecs_subnet: RwLock<Option<(IpAddr, u8)>>,
    /// 查詢紀錄（3.5.0）：只在記憶體、預設關閉、有上限；只給管理 API
    pub querylog: crate::querylog::QueryLog,
    /// 通訊類網域預取中的數量（3.5.0）
    comm_prefetching: AtomicU32,
    inflight: Mutex<HashMap<String, Waiters>>,
    /// 最近一次「所有上游都失敗」的時間（0.1 秒，相對 `base`）；0 = 沒發生過
    last_outage: AtomicU32,
    /// 上一次寫「查詢工作超過期限」日誌的時間（`now_ds`；3.5.1 H1）
    job_timeout_logged: AtomicU32,
    /// 查詢計數，用來每 20 次探索一個平常排在後面的上游
    picks: AtomicU32,
    /// 背景補問的抽樣計數（非 CDN 的 A／AAAA 查詢；跟 `picks` 分開）
    sample_tick: AtomicU32,
    /// 背景補問的名額（`Params::backfill_max`）
    backfills: Arc<tokio::sync::Semaphore>,
    base: Instant,
    errors: Mutex<(u64, Vec<(u64, String)>)>,
}

/// 區網 / 本機的用戶端（`version.kuroshio` 只回答這些）
fn is_private_client(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v) => {
            let o = v.octets();
            v.is_private() || v.is_loopback() || v.is_link_local() || (o[0] == 100 && (o[1] & 0xc0) == 64)
        }
        IpAddr::V6(v) => {
            let s = v.segments()[0];
            v.is_loopback() || (s & 0xfe00) == 0xfc00 || (s & 0xffc0) == 0xfe80
        }
    }
}

pub struct Ctx {
    pub proto: &'static str,
    pub client: IpAddr,
}

/// 解析流程的結果：已經是封包（格式錯誤、本機轉發），或還沒編碼的訊息
enum Out {
    Raw(Vec<u8>),
    Msg(Message),
}

/// 回給用戶端的封包，以及答案的最小 TTL（DoH 的 Cache-Control 用）
pub struct Reply {
    pub bytes: Vec<u8>,
    min_ttl: Option<u32>,
}

impl Reply {
    /// 答案與權威區段的最小 TTL；沒有記錄是 0
    pub fn min_ttl(&self) -> u32 {
        self.min_ttl
            .unwrap_or_else(|| Message::parse(&self.bytes).map(|m| logic::min_ttl(&m, 0)).unwrap_or(0))
    }
}

impl Resolver {
    pub fn new(
        params: Params,
        upstreams: Arc<Manager>,
        cache_max: usize,
        iprank: Arc<IpRank>,
        local: Option<LocalForward>,
    ) -> Arc<Resolver> {
        let backfills = Arc::new(tokio::sync::Semaphore::new(params.backfill_max));
        perf::set_rank(&iprank);
        Arc::new(Resolver {
            params,
            upstreams,
            cache: Mutex::new(Cache::new(cache_max)),
            stats: Arc::new(Stats::default()),
            iprank,
            local,
            filter: RwLock::new(None),
            ddr: RwLock::new(None),
            cdn: RwLock::new(None),
            cdn_suspended: Default::default(),
            community: Default::default(),
            site: std::sync::OnceLock::new(),
            presence: std::sync::OnceLock::new(),
            access: std::sync::OnceLock::new(),
            chain: std::sync::OnceLock::new(),
            ecs_subnet: RwLock::new(None),
            querylog: Default::default(),
            comm_prefetching: AtomicU32::new(0),
            inflight: Mutex::new(HashMap::new()),
            last_outage: AtomicU32::new(0),
            job_timeout_logged: AtomicU32::new(0),
            picks: AtomicU32::new(0),
            sample_tick: AtomicU32::new(0),
            backfills,
            base: Instant::now(),
            errors: Mutex::new((0, Vec::new())),
        })
    }

    /// 存取控制：這個服務允不允許這個來源（沒設定 = 允許）
    pub fn access_allows(&self, k: crate::ipfilter::Kind, ip: IpAddr) -> bool {
        self.access.get().map(|a| a.allow(k, ip)).unwrap_or(true)
    }

    /// 存取控制：連線剛接受時（同一個埠上的服務都要擋才擋，見 `Access::gate`）
    pub fn access_gate(&self, kinds: &[crate::ipfilter::Kind], ip: IpAddr) -> bool {
        self.access.get().map(|a| a.gate(kinds, ip)).unwrap_or(true)
    }

    pub fn set_filter(&self, f: Option<Arc<dyn FilterCheck>>) {
        *self.filter.write().unwrap() = f;
    }

    pub fn set_cdn(&self, c: Option<Arc<kuroshio_cdn::Cdn>>) {
        *self.cdn.write().unwrap() = c;
    }

    pub fn cdn(&self) -> Option<Arc<kuroshio_cdn::Cdn>> {
        self.cdn.read().unwrap().clone().filter(|c| c.enabled())
    }

    /// 查詢時要不要做 CDN 調整：記憶體控制到了最低限度（只轉送）時暫停（規格 09），答案照上游原樣
    fn steer_cdn(&self) -> Option<Arc<kuroshio_cdn::Cdn>> {
        if self.cdn_suspended.load(std::sync::atomic::Ordering::Relaxed) {
            return None;
        }
        self.cdn()
    }

    fn filter_check(&self, name: &str, qtype: u16) -> Option<Verdict> {
        let f = self.filter.read().unwrap().clone();
        f.and_then(|f| f.check(name, qtype))
    }

    /// 串接模式（3.4.0）：這個來源查這個名稱時，「繞過防護」清單的命中豁免（登記中的下游、名稱在它登記的
    /// names 裡）。只在命中 `bypass` 清單之後才呼叫；沒有回應器（或 allow_downstream 關）一律 false
    fn bypass_exempt(&self, client: IpAddr, name: &str) -> bool {
        self.chain.get().is_some_and(|c| c.exempt(client, name))
    }

    /// 快取項目對這個來源是不是封鎖（CNAME 目標被擋）：只有 `bypass` 清單擋的、而且來源是登記了那個目標的下游時不算
    fn entry_blocked(&self, e: &Entry, client: Option<IpAddr>) -> Option<&'static str> {
        let cat = e.blocked?;
        match (&e.blocked_bypass, client) {
            (Some(t), Some(c)) if self.bypass_exempt(c, t) => None,
            _ => Some(cat),
        }
    }

    /// 每分鐘呼叫：清快取（保留到 stale-if-error 的期限）
    pub fn sweep(&self) {
        self.cache
            .lock()
            .unwrap()
            .sweep(Instant::now(), self.params.serve_stale.max(self.params.stale_if_error));
    }

    fn now_ds(&self) -> u32 {
        (self.base.elapsed().as_millis() / 100).min(u32::MAX as u128) as u32
    }

    /// 30 秒內發生過「所有上游都失敗」
    fn in_outage(&self) -> bool {
        let t = self.last_outage.load(Ordering::Relaxed);
        t > 0 && self.now_ds().saturating_sub(t) < 300
    }

    /// 背景預先查詢（開機預熱用，不計入查詢統計）
    pub async fn prefetch(self: &Arc<Self>, name: &str, qtype: u16) {
        let key = Cache::key(qtype, name);
        if self
            .cache
            .lock()
            .unwrap()
            .peek(&key)
            .map(|e| e.remaining(Instant::now()) > 0.0)
            .unwrap_or(false)
        {
            return;
        }
        let Ok(q) = Message::parse(&kuroshio_proto::build_query(0, name, qtype)) else {
            return;
        };
        self.stats.count(StatKind::Prefetch);
        self.fetch(key, q).await;
    }

    pub fn flush(&self) {
        self.cache.lock().unwrap().clear();
    }

    pub fn note_error(&self, msg: String) {
        let mut e = self.errors.lock().unwrap();
        e.0 += 1;
        e.1.insert(0, (crate::persist::now_secs() * 1000, msg));
        e.1.truncate(20);
    }

    pub fn errors_json(&self) -> Value {
        let e = self.errors.lock().unwrap();
        json!({ "count": e.0, "recent": e.1.iter().map(|(at, m)| json!({ "at": at, "msg": m })).collect::<Vec<_>>() })
    }

    /// 入口：用戶端查詢封包 → 回應封包；無法回應（不是查詢）回 None
    pub async fn handle(self: &Arc<Self>, buf: &[u8], ctx: &Ctx) -> Option<Vec<u8>> {
        self.handle_reply(buf, ctx).await.map(|r| r.bytes)
    }

    /// 同 [`Resolver::handle`]，另外帶著答案的最小 TTL（不用為了 TTL 再解析一次回應）
    pub async fn handle_reply(self: &Arc<Self>, buf: &[u8], ctx: &Ctx) -> Option<Reply> {
        let (out, pad) = self.handle_inner(buf, ctx).await?;
        let (mut bytes, min_ttl) = match out {
            Out::Raw(b) => (b, None),
            Out::Msg(m) => {
                let ttl = logic::min_ttl(&m, 0);
                // 加密連線、用戶端要求補齊時：回應補到 468 的倍數（RFC 8467）
                let b = if pad && m.opt.is_some() { m.encode_padded(468) } else { m.encode() };
                (b, Some(ttl))
            }
        };
        // DNS 訊息最大 65535 bytes（TCP / DoT / DoQ 的長度欄位只有 2 bytes）：放不下就回截斷
        if bytes.len() > 65535 {
            bytes = kuroshio_proto::truncated_response(buf, &bytes);
        }
        Some(Reply { bytes, min_ttl })
    }

    /// DDR 回應；沒有設定時回空答案（不往上游問，resolver.arpa 是本機專用網域）
    fn ddr_response(&self, query: &Message) -> Message {
        let mut r = Message::response_to(query, 0);
        if let Some((target, eps)) = self.ddr.read().unwrap().as_ref() {
            for (i, ep) in eps.iter().enumerate() {
                r.answers.push(Record {
                    name: query.questions[0].name.clone(),
                    rtype: rtype::SVCB,
                    class: 1,
                    ttl: 300,
                    data: RData::Raw(logic::svcb_rdata(i as u16 + 1, target, ep)),
                });
            }
        }
        r
    }

    /// 回傳（結果, 要不要補齊）
    async fn handle_inner(self: &Arc<Self>, buf: &[u8], ctx: &Ctx) -> Option<(Out, bool)> {
        let h = kuroshio_proto::header(buf).ok()?;
        if h.qr {
            return None; // 收到的是回應封包：不回（避免反射）
        }
        if h.opcode != 0 {
            // 只處理一般查詢；NOTIFY / UPDATE 之類的回 NOTIMP，不能當成查詢轉給上游
            return Some((Out::Raw(kuroshio_proto::error_response(buf, kuroshio_proto::RCODE_NOTIMP)), false));
        }
        let query = match Message::parse(buf) {
            Ok(m) if m.questions.len() == 1 => m,
            Ok(_) | Err(_) => return Some((Out::Raw(kuroshio_proto::error_response(buf, kuroshio_proto::RCODE_FORMERR)), false)),
        };
        // 加密連線、用戶端的查詢帶 padding 選項 → 回應也補齊
        let pad = matches!(ctx.proto, "dot" | "doh" | "doh3" | "doq") && logic::wants_padding(&query);
        let msg = |m: Message| Some((Out::Msg(m), pad));
        if query.opt.as_ref().is_some_and(|o| o.version != 0) {
            // 只懂 EDNS 版本 0（RFC 6891 6.1.3）：回 BADVERS，OPT 裡帶我們支援的版本
            return msg(Message::response_to(&query, 16));
        }
        let t0 = Instant::now();
        let q = &query.questions[0];
        let qname = normalize(&q.name);
        let (qtype, qclass) = (q.qtype, q.qclass);

        // 路徑檢查（3.3.6）：下游的黑潮用 CHAOS TXT version.kuroshio 認出「一般 DNS 被上游的黑潮接走」。
        // 只回答區網的一般 DNS（公開的 DoH / DoT 不透露版本）
        if qclass == 3 && qname == "version.kuroshio" && matches!(ctx.proto, "udp" | "tcp") && is_private_client(ctx.client) {
            self.stats.count(StatKind::Local);
            let mut r = Message::response_to(&query, 0);
            if qtype == 16 || qtype == 255 {
                let v = format!("kuroshio/{}", env!("CARGO_PKG_VERSION"));
                let mut b = vec![v.len() as u8];
                b.extend_from_slice(v.as_bytes());
                r.answers.push(Record {
                    name: q.name.clone(),
                    rtype: 16,
                    class: 3,
                    ttl: 0,
                    data: RData::Raw(b),
                });
            }
            return msg(r);
        }
        // 串接模式（3.4.0）：CH 類別的 chain.kuroshio 一律在這裡回答，不過濾、不快取、不轉給上游。
        // 條件同 version.kuroshio：只回答區網的一般 DNS，公開的加密監聽一律 REFUSED
        if qclass == 3 && kuroshio_community::chain::in_zone(&qname) {
            self.stats.count(StatKind::Local);
            return msg(match self.chain.get() {
                Some(c) if matches!(ctx.proto, "udp" | "tcp") && is_private_client(ctx.client) => c.answer(&query, &qname, ctx),
                Some(c) => c.refuse_not_private(&query),
                None => Message::response_to(&query, 5),
            });
        }
        if qclass == 1 && (qname == "_dns.resolver.arpa" || qname == "resolver.arpa") {
            self.stats.count(StatKind::Local);
            return msg(if qtype == rtype::SVCB && qname.starts_with('_') {
                self.ddr_response(&query)
            } else {
                Message::response_to(&query, 0)
            });
        }
        if let Some(l) = &self.local {
            if l.matches(&qname) {
                self.stats.count(StatKind::Local);
                return match l.up.exchange(buf, self.params.timeout).await {
                    Ok(r) => Some((Out::Raw(r), false)),
                    Err(_) => msg(logic::servfail(&query)),
                };
            }
        }
        // 特殊用途網域（RFC 6761，3.5.1）：本機直接回答，不問上游、不過濾、不快取、不算進熱門與網站排行。
        // 放在本地轉發之後：使用者把這些網域轉給區網的 DNS 時照轉
        if qclass == 1 && self.params.special_use {
            if let Some(kind) = special_use(&qname) {
                self.stats.count(StatKind::Local);
                return msg(special_use_response(&query, kind));
            }
        }
        self.stats.query(&qname, ctx.client);
        if let Some(p) = self.presence.get() {
            p.record(ctx.proto, ctx.client, &qname);
        }

        // 1. 過濾
        if let Some(v) = self.filter_check(&qname, qtype) {
            // 串接模式（3.4.0）：只有「繞過防護」清單擋的、而且來源是登記了這個名稱的下游黑潮時不擋（照一般查詢往下走）
            if v.block && !(v.bypass && self.bypass_exempt(ctx.client, &qname)) {
                self.stats.blocked(v.category);
                self.stats.blocked_name(&qname, ctx.client, v.category);
                let code = if v.category == "malware" { ede::BLOCKED } else { ede::FILTERED };
                debug!("{} {qname} 攔截（{}）{}", ctx.proto, v.category, v.rule);
                let out = logic::blocked_response(&query, self.params.blocked_ttl, code, &format!("{}：{}", v.category, v.rule));
                self.qlog(&qname, qtype, ctx, crate::querylog::Kind::Blocked, &out, t0, v.category);
                return msg(out);
            }
        }

        if qtype == rtype::A {
            self.stats.site(&qname, ctx.client);
        }

        // 2. 快取（鍵含類別與 DO / CD：要 DNSSEC 記錄的查詢不能拿沒有簽章的快取，反過來也一樣）
        let key = Cache::key_for(
            qtype,
            qclass,
            &qname,
            query.dnssec_ok(),
            query.flags & kuroshio_proto::message::FLAG_CD != 0,
        );
        let now = Instant::now();
        let cached = self.cache.lock().unwrap().get(&key, now);
        if let Some((e, since_last)) = cached {
            let remain = e.remaining(now);
            let p = &self.params;
            let usable = e.class != Class::ServFail;
            let stale_ok = usable && remain > -(p.serve_stale as f64);
            // 外網斷線中：更舊的資料也先回（規格 06 第 1.3 節）
            let outage_ok = usable && remain > -(p.stale_if_error as f64) && self.in_outage();
            if remain > 0.0 || stale_ok || outage_ok {
                let stale = remain <= 0.0;
                let recent = since_last < p.prefetch_recent;
                let popular = e.hits.load(Ordering::Relaxed) >= 3;
                // 自適應預取：剩餘 ≤ max(門檻, 原始 TTL 的 10%)，而且最近有人用或很熱門
                let threshold = p.prefetch_threshold.max(e.ttl as f64 * 0.1);
                if stale || (remain <= threshold && (recent || popular)) {
                    self.refresh(key.clone(), query.clone());
                } else if remain <= threshold && kuroshio_net::comm::flags_of(&qname).prefetch {
                    // 通訊類網域（推播，3.5.0）：快到期就預取，不要求最近問過或很熱門（同時最多 COMM_PREFETCH_MAX 個）。
                    // 3.5.0 F11：只有推播、地震速報、使用者自己加的用這些名額（`prefetch` 旗標）
                    self.refresh_comm(key.clone(), query.clone());
                }
                if stale {
                    self.stats.count(StatKind::Stale);
                }
                if let Some(cat) = self.entry_blocked(&e, Some(ctx.client)) {
                    self.stats.blocked(cat);
                    self.stats.blocked_name(&qname, ctx.client, cat);
                }
                let out = self.serve(&query, &e, if stale { Some(10) } else { None }, Some(ctx.client));
                self.stats.hit(t0.elapsed().as_secs_f64() * 1000.0);
                let k = if stale {
                    crate::querylog::Kind::Stale
                } else {
                    crate::querylog::Kind::Hit
                };
                self.qlog(&qname, qtype, ctx, k, &out, t0, &e.source);
                return msg(out);
            }
        }

        // 3. 上游
        let e = self.fetch(key, query.clone()).await;
        self.stats.count(StatKind::Miss);
        // 上游全部失敗時 store() 會保留舊資料：這時回的是過期的舊資料
        let stale = e.remaining(Instant::now()) <= 0.0 && e.class != Class::ServFail;
        if stale {
            self.stats.count(StatKind::Stale);
            // 3.5.0 F3：上游全部失敗、直接回舊資料（本來就失敗的慢路徑）
            self.stats.note_stale_refresh_fail();
        }
        if let Some(cat) = self.entry_blocked(&e, Some(ctx.client)) {
            self.stats.blocked(cat);
            self.stats.blocked_name(&qname, ctx.client, cat);
        }
        if e.class == Class::ServFail {
            self.stats.count(StatKind::ServFail);
        }
        let out = self.serve(&query, &e, stale.then_some(10), Some(ctx.client));
        self.stats.latency(false, t0.elapsed().as_secs_f64() * 1000.0);
        let k = if stale {
            crate::querylog::Kind::Stale
        } else {
            crate::querylog::Kind::Miss
        };
        self.qlog(&qname, qtype, ctx, k, &out, t0, &e.source);
        msg(out)
    }

    /// 記一筆查詢紀錄（關閉時只有一次原子讀取；開著時拿不到鎖就丟掉，不等）
    #[allow(clippy::too_many_arguments)]
    #[inline]
    fn qlog(&self, qname: &str, qtype: u16, ctx: &Ctx, kind: crate::querylog::Kind, out: &Message, t0: Instant, source: &str) {
        if self.querylog.enabled() {
            let ms = t0.elapsed().as_secs_f64() * 1000.0;
            self.querylog
                .push(crate::querylog::now(), qname, qtype, ctx.client, kind, out.rcode as u8, ms, source);
        }
    }

    /// 由快取項目產生回應：答案 TTL 統一成剩餘秒數（過期回舊資料時用 10 秒）。
    /// `client`：查詢的來源（CNAME 目標命中「繞過防護」清單時，依來源判斷要不要豁免）
    fn serve(&self, query: &Message, e: &Entry, force_ttl: Option<u32>, client: Option<IpAddr>) -> Message {
        if let Some(cat) = self.entry_blocked(e, client) {
            let code = if cat == "malware" { ede::BLOCKED } else { ede::FILTERED };
            return logic::blocked_response(query, self.params.blocked_ttl, code, &format!("{cat}：CNAME"));
        }
        if e.class == Class::ServFail {
            return logic::servfail(query);
        }
        let remain = e.remaining(Instant::now()).ceil().max(1.0) as u32;
        let mut ttl = force_ttl.unwrap_or(remain);
        if e.fast {
            ttl = ttl.min(self.params.fast_path_ttl);
        }
        // 自己的網域 TTL 壓短：打開首頁前一定會重新查詢，「有沒有在用」才判斷得準
        if let Some(cap) = self.presence.get().and_then(|p| p.own_host_ttl(&query.questions[0].name)) {
            ttl = ttl.min(cap.max(1));
        }
        let mut r = Message::response_to(query, e.rcode);
        r.answers = e.answers.iter().map(|a| Record { ttl, ..a.clone() }).collect();
        // CDN 調整會改寫答案：要 DNSSEC 記錄或類別不是 IN 的查詢不動（同 job() 的 verbatim）
        // 下游黑潮自己關掉了 CDN 置換（查詢帶著私有選項）：照原樣回答，不幫它換台灣節點（3.4.3：每台黑潮自己決定）
        let verbatim = query.dnssec_ok() || query.questions[0].qclass != 1 || wants_no_cdn(query);
        if let Some(cdn) = self.steer_cdn().filter(|_| !verbatim && (e.chained || self.chain_active())) {
            // 串接上游（上游黑潮）給的答案：CDN 節點上游已經驗證、換好（3.4.1）。
            // 下游不再改寫、不排背景驗證（MIPS 上的 TLS 驗證很吃 CPU），只記哪家 CDN（統計用，唯讀快照）
            if let Some(p) = cdn.provider_of(&r, query.questions[0].qtype) {
                self.stats.cdn(p, None, None);
            }
        } else if let Some(cdn) = self.steer_cdn().filter(|_| !verbatim) {
            let (qname, qtype) = (&query.questions[0].name, query.questions[0].qtype);
            let res = cdn.apply(&mut r, qname, qtype);
            if let Some(cap) = res.ttl_cap {
                ttl = ttl.min(cap.max(1));
            }
            for a in r.answers.iter_mut() {
                a.ttl = ttl;
            }
            if let Some(p) = res.provider {
                self.stats.cdn(p, res.rewritten.map(|r| r.as_str()), res.cross_to.as_deref());
            }
            // 每一次 A 回應 ≈ 一次連線：記錄是否把「原本會出國」的連線拉回台灣
            if qtype == rtype::A {
                if let Some(rt) = cdn.route(e.baseline.as_ref(), &res, &r) {
                    self.stats.route(&rt.provider, rt.abroad, rt.tw, rt.saved_ms);
                }
            }
        }
        r.authorities = e
            .authorities
            .iter()
            .map(|a| Record {
                ttl: a.ttl.min(ttl).max(1),
                ..a.clone()
            })
            .collect();
        if force_ttl.is_some() {
            logic::add_ede(&mut r, ede::STALE_ANSWER, "上游更新中，先回舊資料");
        }
        r
    }

    /// 串接中（有串接上游、沒有暫停）：CDN 節點由上游處理，下游不改寫也不驗證（3.4.2：
    /// 串接之前存下的、或重新啟動時讀回來的快取也一樣，到期後由上游重新回答）
    pub fn chain_active(&self) -> bool {
        self.upstreams.chain().is_some_and(|c| c.role == Role::Chain) && !self.upstreams.chain_suspended()
    }

    /// 通訊類網域的預取：同時最多 [`COMM_PREFETCH_MAX`] 個
    fn refresh_comm(self: &Arc<Self>, key: String, query: Message) {
        if self.comm_prefetching.load(Ordering::Relaxed) >= COMM_PREFETCH_MAX || self.inflight.lock().unwrap().contains_key(&key) {
            return;
        }
        self.comm_prefetching.fetch_add(1, Ordering::Relaxed);
        self.stats.count(StatKind::Prefetch);
        let me = self.clone();
        tokio::spawn(async move {
            me.fetch(key, query).await;
            me.comm_prefetching.fetch_sub(1, Ordering::Relaxed);
        });
    }

    /// 通訊類網域預取中的數量（狀態頁）
    pub fn comm_prefetching(&self) -> u32 {
        self.comm_prefetching.load(Ordering::Relaxed)
    }

    fn refresh(self: &Arc<Self>, key: String, query: Message) {
        if self.inflight.lock().unwrap().contains_key(&key) {
            return;
        }
        self.stats.count(StatKind::Prefetch);
        let me = self.clone();
        tokio::spawn(async move {
            let e = me.fetch(key, query).await;
            // 3.5.0 F3：背景更新做完還是過期的（上游全部失敗時 store() 保留舊資料）或 SERVFAIL：記一次更新失敗
            // （背景工作裡；命中快取的路徑不動）
            if e.class == Class::ServFail || e.remaining(Instant::now()) <= 0.0 {
                me.stats.note_stale_refresh_fail();
            }
        });
    }

    /// singleflight：同一個鍵同時只問一次上游；呼叫者拿到「快速回應」或最終結果（先到的那個）
    async fn fetch(self: &Arc<Self>, key: String, query: Message) -> Arc<Entry> {
        let (tx, rx) = oneshot::channel();
        let first = {
            let mut inflight = self.inflight.lock().unwrap();
            match inflight.get_mut(&key) {
                Some(w) => {
                    w.push(tx);
                    false
                }
                None => {
                    inflight.insert(key.clone(), vec![tx]);
                    true
                }
            }
        };
        if first {
            let me = self.clone();
            let k = key.clone();
            tokio::spawn(async move {
                // 總期限（3.5.1 H1）：任何一步沒有在期限內結束，就放棄這個工作——`InflightGuard` 把鍵拿掉，
                // 等待的人收到「通道關閉」回 SERVFAIL，之後同一個鍵的查詢重新問。
                // 以前沒有總期限，卡住的那一筆讓同名同類型的查詢全部跟著等，直到重新啟動
                if tokio::time::timeout(JOB_DEADLINE, me.clone().job(k.clone(), query)).await.is_err() {
                    me.note_job_timeout(&k);
                }
            });
        }
        match rx.await {
            Ok(e) => e,
            Err(_) => Arc::new(Entry::new(2, vec![], vec![], Class::ServFail, "內部錯誤".into(), 3, false, None)),
        }
    }

    /// 查詢工作超過 [`JOB_DEADLINE`]：計數；日誌每分鐘最多一行
    fn note_job_timeout(&self, key: &str) {
        perf::note_job_timeout();
        let now = self.now_ds();
        let last = self.job_timeout_logged.load(Ordering::Relaxed);
        if now.saturating_sub(last) >= 600
            && self
                .job_timeout_logged
                .compare_exchange(last, now.max(1), Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            warn!(
                "查詢工作超過 {} 秒沒有結束，先回 SERVFAIL、下一筆重新問（{key}；之後一分鐘內的不再寫日誌，次數看 /api/status 的 perf.jobTimeouts）",
                JOB_DEADLINE.as_secs()
            );
        }
    }

    fn notify(&self, key: &str, e: &Arc<Entry>, done: bool) {
        let mut inflight = self.inflight.lock().unwrap();
        let waiters = if done {
            inflight.remove(key)
        } else {
            inflight.get_mut(key).map(std::mem::take)
        };
        for w in waiters.unwrap_or_default() {
            let _ = w.send(e.clone());
        }
    }

    async fn job(self: Arc<Self>, key: String, query: Message) {
        // 這個工作中途死掉（panic、被取消）時把鍵拿掉：等待的人收到「通道關閉」回 SERVFAIL，
        // 不然他們會永遠等下去，之後同一個鍵的查詢也都會排進沒有人處理的名單
        let guard = InflightGuard(&self.inflight, &key);
        let qtype = query.questions[0].qtype;
        // 要 DNSSEC 記錄（DO）或類別不是 IN 的查詢：答案原樣轉交，不合併 / 重排 IP（改過的 RRset 簽章會驗不過）
        let verbatim = query.dnssec_ok() || query.questions[0].qclass != 1;
        let qname = normalize(&query.questions[0].name);
        let ecs = if self.params.send_ecs {
            *self.ecs_subnet.read().unwrap()
        } else {
            None
        };
        let upq = logic::upstream_query(&query, 0, ecs).encode();
        let mut fast_sent = false;
        let cdn = self.steer_cdn();

        let active = self.upstreams.active();
        let Asked { answers: results, unasked } = self
            .ask(&active, &upq, qtype, false, false, |a| {
                if fast_sent || !self.params.fast_path || a.class != Class::Ok {
                    return;
                }
                // 固定上游（路由器）自帶的 CDN 優選 IP 沒有針對這個網站驗證過，不拿來當快速回應
                if a.up.role == Role::Pinned && cdn.as_ref().is_some_and(|c| !c.pinned_alias(&a.msg, qtype, None).is_empty()) {
                    return;
                }
                fast_sent = true;
                let e = self.store(
                    &key,
                    &a.msg,
                    Class::Ok,
                    a.up.up.id.clone(),
                    &qname,
                    true,
                    None,
                    None,
                    a.up.role == Role::Chain,
                );
                self.notify(&key, &e, false);
            })
            .await;
        let mut decided = decide(&results, false, cdn.as_deref(), qtype);
        let mut used_backup = false;
        if decided.is_none() {
            // 全部失敗或都被上游擋：改問備援
            used_backup = true;
            // 上游黑潮解析不到（SERVFAIL）才改問自己的上游時，多半是網域本身壞了：自己的上游沒回應也先不算失敗，
            // 同一輪有別的上游正常回答才算（跟 SERVFAIL 一樣）。不然串接中自己的上游只收到這些壞網域，
            // 連續失敗一直累積，被暫停 1→2→4 分鐘（3.4.4，3.4.3 複驗 G6）
            let chain_servfail = results.iter().any(|r| r.up.role == Role::Chain && r.class == Class::ServFail);
            let backup = self.upstreams.backup();
            let more = self.ask(&backup, &upq, qtype, false, chain_servfail, |_| {}).await.answers;
            let first = decide(&more, false, cdn.as_deref(), qtype);
            // 上游黑潮解析不到、自己的上游裡只有一台回否定答案（其他都沒回應或也解析不到）：不採用，照上游的 SERVFAIL。
            // 權威伺服器掛掉的網域，偶爾有一台上游回空答案，裝置就以為「網域存在、沒有這種記錄」（3.4.4，3.4.3 複驗 G7）
            let lone = chain_servfail && first.as_ref().is_some_and(|d| lone_negative(d, &more, backup.len()));
            decided = (if lone { None } else { first })
                .map(|mut d| {
                    // 上游黑潮擋掉、下游用自己的上游解析的：來源標出來（狀態頁、日誌看得到是繞過上游的過濾）
                    if results.iter().any(|r| r.up.role == Role::Chain && r.class == Class::Blocked) {
                        d.source = format!("{}(上游擋，改用自己的上游)", d.source);
                        // 狀態頁看得到次數（D3 這類只收 WARN 日誌的機器，看不到來源標籤；3.4.2）
                        self.stats.count(StatKind::ChainBypass);
                    } else if results.iter().any(|r| r.up.role == Role::Chain && r.class == Class::ServFail) {
                        d.source = format!("{}(上游解析不到，改用自己的上游)", d.source);
                        self.stats.count(StatKind::ChainRetry);
                    }
                    d
                })
                .or_else(|| {
                    let all: Vec<Arc<Answer>> = results
                        .iter()
                        .chain(more.iter().filter(|a| !(lone && is_negative(a.class))))
                        .cloned()
                        .collect();
                    decide(&all, true, cdn.as_deref(), qtype)
                });
        }
        if decided.is_none() {
            self.last_outage.store(self.now_ds().max(1), Ordering::Relaxed);
        }
        let e = match decided {
            None => self.store(
                &key,
                &Message {
                    rcode: 2,
                    ..Default::default()
                },
                Class::ServFail,
                "全部失敗".into(),
                &qname,
                false,
                None,
                None,
                false,
            ),
            Some(mut d) => {
                let mut note = None;
                // 串接中（包括上游擋掉、改用自己的上游解析的）不做 TCP 443 測速排序：下游保持輕量（3.4.2）
                if (qtype == rtype::A || qtype == rtype::AAAA)
                    && !d.oks.is_empty()
                    && self.params.rank_ips
                    && !verbatim
                    && !self.chain_active()
                {
                    if let Some((msg, source, n)) = self.merge_rank(&d.oks, &qname, qtype).await {
                        d.msg = msg;
                        d.source = source;
                        note = Some(n);
                    }
                }
                let baseline = baseline_of(cdn.as_deref(), qtype, &results);
                self.store(&key, &d.msg, d.class, d.source, &qname, false, note, baseline, d.chained)
            }
        };
        self.notify(&key, &e, true);
        // 正常結束：notify 已經把鍵拿掉；之後同一個鍵可能已經有新的工作，不能再刪一次
        std::mem::forget(guard);
        // 直系血親（3.4.2）：上游黑潮給的 CDN 答案抽樣查核（不改答案、有上限，見 chain::audit）
        if e.chained && e.class == Class::Ok && (qtype == rtype::A || qtype == rtype::AAAA) && !verbatim {
            self.maybe_audit(&qname, qtype, &e, &upq);
        }
        // 背景補問（規格 10 第 5.2 節）：一定在 notify 之後，用戶端已經拿到回應。
        // 改問過備援的（主要上游都失敗）不補問；串接中只問上游黑潮（下游就是要省自己的加密上游），也不補問
        if used_backup || active.iter().any(|u| u.role == Role::Chain) {
            return;
        }
        self.backfill(Backfilling {
            key,
            qname,
            upq,
            qtype,
            verbatim,
            first: results,
            unasked,
            entry: e,
            cdn,
        });
    }

    /// 抽查上游黑潮給的答案（3.4.3 起不限 CDN）：連到它給的 IP、用網域名稱做 TLS 握手檢查憑證；不符時用自己的加密上游
    /// 解析一次、對自己拿到的 IP 做同樣的檢查，自己的正常才算可疑。1 小時內 3 次可疑 → 解除串接（規格 10 第 3.8 節）
    fn maybe_audit(self: &Arc<Self>, qname: &str, qtype: u16, e: &Entry, upq: &[u8]) {
        if !self.chain_active() || !crate::clock::synced() || crate::app::pressure() != crate::sysinfo::Pressure::Normal {
            return;
        }
        // 不限 CDN 的答案、也不看這台有沒有開 CDN 置換（3.4.3）：以前只查 CDN 答案，下游關掉 CDN 時
        // 對上游完全沒有查核。抽樣、間隔、同時一個的上限照舊
        let msg = Message {
            answers: e.answers.clone(),
            ..Default::default()
        };
        let Some(ip) = logic::ips_of(&msg, qtype).into_iter().next() else {
            return;
        };
        let Some(slot) = crate::chain::audit::AUDIT.claim(crate::memgov::steady_secs()) else {
            return;
        };
        let (me, name, upq) = (self.clone(), qname.to_string(), upq.to_vec());
        tokio::spawn(async move {
            let _slot = slot;
            use crate::chain::audit::Outcome;
            use kuroshio_net::probe::{verify_site, SiteCheck};
            let t = Duration::from_secs(3);
            let outcome = match verify_site(ip, &name, t).await.0 {
                SiteCheck::Valid => {
                    // 3.5.0 E4、F7：握手通過 → 用同一個名額量一次待確認節點的機房（答案的 IP，或 CDN 那一層挑的前幾名）
                    me.pop_audit(ip).await;
                    Outcome::Valid
                }
                SiteCheck::Unverified => Outcome::Unverified,
                SiteCheck::Invalid => {
                    // 自己的加密上游（不經攔截者）解析一次，看是網站本身的問題、還是上游給的答案不對
                    let own = me.upstreams.backup();
                    let asked = me.ask(&own, &upq, qtype, false, false, |_| {}).await;
                    let mine = asked
                        .answers
                        .iter()
                        .filter(|a| a.class == Class::Ok)
                        .flat_map(|a| logic::ips_of(&a.msg, qtype))
                        .find(|x| *x != ip);
                    match mine {
                        None => Outcome::Unverified,
                        Some(m) => match verify_site(m, &name, t).await.0 {
                            SiteCheck::Valid => Outcome::Suspicious,
                            SiteCheck::Invalid => Outcome::SiteInvalid,
                            SiteCheck::Unverified => Outcome::Unverified,
                        },
                    }
                }
            };
            if outcome == Outcome::Suspicious {
                warn!("抽查上游黑潮給的答案：{name} 的 {ip} 憑證不符，自己的上游給的位址正常");
            }
            if crate::chain::audit::AUDIT.record(outcome, &name, &ip.to_string(), crate::persist::now_secs() * 1000) {
                warn!("抽查上游黑潮給的答案：1 小時內 3 次不通過，暫停串接、改用自己的加密上游");
                if let Some(c) = crate::chain::current() {
                    c.audit_failed();
                }
            }
        });
    }

    /// 串接中的機房抽查（3.5.0 E4，規格 11）：只在答案抽查握手通過之後、拿著同一個抽查名額時呼叫（[`pop_audit_probe`]）
    async fn pop_audit(&self, ip: IpAddr) {
        if let Some(cdn) = self.cdn() {
            pop_audit_probe(&cdn, ip).await;
        }
    }

    /// 背景補問：條件符合就在背景問這次沒問到的上游，跟前面的回答合在一起重新 `decide()`、
    /// `merge_rank()`、`store()`（快取換成合併後的）。不呼叫 `notify`（沒有人在等）。
    /// 同時最多 `backfill_max` 個，拿不到名額就放棄（不排隊）；記憶體壓力不是 Normal 不做
    fn backfill(self: &Arc<Self>, b: Backfilling) {
        let p = &self.params;
        // 便宜的條件先看：大部分查詢（parallel = 0、DO、非 A／AAAA、關掉）在這裡就結束
        if !backfill_possible(p, b.qtype, b.verbatim, b.unasked.len()) {
            return;
        }
        let cdn_hit = b.cdn.as_ref().is_some_and(|c| {
            b.entry
                .answers
                .iter()
                .filter(|r| r.rtype == b.qtype)
                .filter_map(logic::ip_of)
                .any(|ip| c.classify(ip).is_some())
        });
        let tick = if cdn_hit || p.backfill_sample == 0 {
            0
        } else {
            self.sample_tick.fetch_add(1, Ordering::Relaxed).wrapping_add(1) as u64
        };
        if !backfill_wanted(p, b.qtype, b.verbatim, b.unasked.len(), cdn_hit, tick) {
            return;
        }
        if crate::app::pressure() != crate::sysinfo::Pressure::Normal {
            return;
        }
        let Ok(permit) = self.backfills.clone().try_acquire_owned() else {
            debug!("背景補問名額已滿，略過：{}", b.qname);
            return;
        };
        self.stats.count(StatKind::Backfill);
        let me = self.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let Backfilling {
                key,
                qname,
                upq,
                qtype,
                first,
                unasked,
                cdn,
                ..
            } = b;
            let more = me.ask(&unasked, &upq, qtype, true, false, |_| {}).await.answers;
            if backfill_mismatch(&first, &more) {
                me.stats.count(StatKind::BackfillMismatch);
                debug!(
                    "背景補問結果不一致：{qname}（類型 {qtype}）前面 {} 個回答、補問 {} 個回答（{}）",
                    first.len(),
                    more.len(),
                    more.iter()
                        .map(|a| format!("{}:{:?}", a.up.up.id, a.class))
                        .collect::<Vec<_>>()
                        .join("、")
                );
            }
            let all: Vec<Arc<Answer>> = first.into_iter().chain(more).collect();
            let Some(mut d) = decide(&all, false, cdn.as_deref(), qtype) else {
                return;
            };
            let mut note = None;
            // 補問只做 A／AAAA、不做 verbatim（backfill_possible），這裡只看 rank_ips
            if !d.oks.is_empty() && me.params.rank_ips {
                if let Some((msg, source, n)) = me.merge_rank(&d.oks, &qname, qtype).await {
                    d.msg = msg;
                    d.source = source;
                    note = Some(n);
                }
            }
            let baseline = baseline_of(cdn.as_deref(), qtype, &all);
            me.store(&key, &d.msg, d.class, d.source, &qname, false, note, baseline, d.chained);
        });
    }

    /// 並行詢問一組上游：全部回來，或第一個正常回應後再等 window；
    /// `parallel` > 0 時先問前幾個，失敗或每隔 hedge 沒有正常回應再加問下一個。
    /// `all`：不套 `parallel`，全部一起問（背景補問用）。回傳收到的回答與這次沒有問到的上游
    /// `defer_silent`：沒有回應的上游跟 SERVFAIL 一樣，同一輪有別的上游正常回答才算失敗（串接上游 SERVFAIL 後的重問用）
    async fn ask(&self, list: &[Arc<Up>], q: &[u8], qtype: u16, all: bool, defer_silent: bool, mut on_each: impl FnMut(&Answer)) -> Asked {
        let mut out = Vec::new();
        if list.is_empty() {
            return Asked::default();
        }
        let p = &self.params;
        let first = if all || p.parallel == 0 {
            list.len()
        } else {
            p.parallel.min(list.len())
        };
        // 有並行限制時：先問平均延遲最低的（還沒有紀錄的排前面，讓它有機會被量到）；
        // 每 20 次把後段的一個換到前面探索（規格 06 第 2.1 節）
        let mut ordered: Vec<Arc<Up>> = list.to_vec();
        if first < ordered.len() {
            ordered.sort_by(|a, b| {
                a.ewma()
                    .unwrap_or(0.0)
                    .partial_cmp(&b.ewma().unwrap_or(0.0))
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            let n = self.picks.fetch_add(1, Ordering::Relaxed);
            if n % 20 == 19 {
                let j = first + (n / 20) as usize % (ordered.len() - first);
                ordered.swap(first - 1, j);
            }
        }
        let list = &ordered[..];
        let mut set = JoinSet::new();
        // 這台自己沒開 CDN 置換：問上游黑潮時請它照原樣回答（3.4.3）
        let no_cdn = self.steer_cdn().is_none().then(|| with_no_cdn(q)).flatten();
        // 3.5.0 F4：哪幾台已經送出、什麼時候送的、回來了沒（list 裡的位置；固定大小、在堆疊上，不配置）。
        // 這一輪結束時還沒回來的就是「來不及回答」
        let round_aware = p.round_aware_failures;
        let t_round = Instant::now();
        let mut sent_at = [t_round; LATE_TRACK];
        let mut back: u32 = 0;
        let spawn = |set: &mut JoinSet<_>, sent_at: &mut [Instant; LATE_TRACK], i: usize, up: Arc<Up>| {
            let q = match &no_cdn {
                Some(nq) if up.role == Role::Chain => nq.clone(),
                _ => q.to_vec(),
            };
            let t = timeout_for(p, &up);
            if i < LATE_TRACK {
                sent_at[i] = Instant::now();
            }
            set.spawn(async move {
                let t0 = Instant::now();
                let r = up.up.exchange(&q, t).await;
                (i, up, r, t0.elapsed().as_secs_f64() * 1000.0)
            });
        };
        for (i, u) in list.iter().enumerate().take(first) {
            spawn(&mut set, &mut sent_at, i, u.clone());
        }
        let mut rest = list.iter().cloned().enumerate().skip(first);
        let longest = list.iter().map(|u| timeout_for(p, u)).max().unwrap_or(p.timeout);
        let hard = tokio::time::sleep(longest + Duration::from_millis(100));
        tokio::pin!(hard);
        let mut window: Option<std::pin::Pin<Box<tokio::time::Sleep>>> = None;
        let mut hedge = Box::pin(tokio::time::sleep(p.hedge));
        let mut got_ok = false;
        // 回 SERVFAIL 的上游：等這一輪結束才決定算不算失敗（3.4.2）。第三個值：逾時（3.5.0 F4，等了 90% 以上才失敗）
        let mut servfails: Vec<(Arc<Up>, f64, bool)> = Vec::new();
        loop {
            tokio::select! {
                r = set.join_next() => {
                    let (i, up, r, ms) = match r {
                        Some(Ok(x)) => x,
                        // 某個上游的工作 panic：當成那個上游失敗，其他的照常等
                        Some(Err(_)) => {
                            if let Some((i, u)) = rest.next() { spawn(&mut set, &mut sent_at, i, u); }
                            continue;
                        }
                        None => break,
                    };
                    if i < LATE_TRACK {
                        back |= 1 << i;
                    }
                    match r.ok().and_then(|b| Message::parse(&b).ok()) {
                        Some(msg) => {
                            let mut class = logic::classify(&msg, qtype);
                            // 上游黑潮擋掉非 A／AAAA 的查詢時回空答案＋EDE（被擋／被過濾）：當成「上游擋」，
                            // 由下游自己的過濾決定要不要擋（3.4.3；以前當成 NODATA 直接回給裝置）
                            if up.role == Role::Chain && class == Class::NoData && blocked_by_ede(&msg) {
                                class = Class::Blocked;
                            }
                            if class == Class::ServFail {
                                up.note_servfail();
                            }
                            if class == Class::ServFail && up.role != Role::Chain {
                                servfails.push((up.clone(), ms, false));
                            } else {
                                up.record(answered_ok(&up, class), ms);
                            }
                            let a = Arc::new(Answer { up, msg, class, ms });
                            on_each(&a);
                            if a.class == Class::Ok {
                                // 否定答案先開了 window 也一樣：有正常回應之後不再加問其他上游
                                got_ok = true;
                                if window.is_none() {
                                    window = Some(Box::pin(tokio::time::sleep(p.window)));
                                }
                            } else if matches!(a.class, Class::NoData | Class::NxDomain) && window.is_none() {
                                // 否定答案也只再等 window 收其他上游的回答（多數決），不等到逾時：以前要等並行的
                                // 每一台都回來，其中一台慢或掛掉（例如一直連續失敗的 DoT）時，每一筆 NODATA／NXDOMAIN
                                // （包括只有 IPv4 的網站的 AAAA）都卡滿 timeoutMs（3.4.2 Windows 實測：1,502 ms）
                                window = Some(Box::pin(tokio::time::sleep(p.window)));
                            }
                            if a.class != Class::Ok {
                                if let Some((i, u)) = rest.next() { spawn(&mut set, &mut sent_at, i, u); }
                            }
                            out.push(a);
                            // 已經有兩台回否定答案、還沒有正常回應：多數決已經定了，不再等其他上游
                            // （正常回應一拿到就先回給用戶端，否定答案以前要等每一台；只有 IPv4 的網站的 AAAA
                            // 在上游 A 實測中位 424 ms、32% 卡 1.5 秒，有 AAAA 的只要 53 ms）
                            // 兩台回「同一種」否定答案才算定了：一台 NODATA、一台 NXDOMAIN 是意見不一，照樣等 window
                            let same = |c: Class| out.iter().filter(|x| x.class == c).count() >= 2;
                            if !got_ok && (same(Class::NoData) || same(Class::NxDomain)) {
                                break;
                            }
                        }
                        None => {
                            // 3.5.0 F4：等到逾時（`timeout_for()` 的 90% 以上）才失敗的，跟 SERVFAIL 一樣先收著，
                            // 這一輪有別的上游正常回答才算它失敗（大家都答不出來的網域不算個別上游的失敗）；
                            // 很快就回來的錯誤（連線被拒、TLS 失敗、HTTP 4xx）照舊立刻記——那是這台自己的問題
                            let timed_out = round_aware
                                && up.role != Role::Chain
                                && ms >= timeout_for(p, &up).as_secs_f64() * 1000.0 * 0.9;
                            if (defer_silent && up.role != Role::Chain) || timed_out {
                                servfails.push((up.clone(), ms, timed_out));
                            } else {
                                up.record(false, ms);
                            }
                            if let Some((i, u)) = rest.next() { spawn(&mut set, &mut sent_at, i, u); }
                        }
                    }
                }
                _ = async { window.as_mut().unwrap().await }, if window.is_some() => break,
                _ = &mut hedge, if !got_ok && rest.len() > 0 => {
                    if let Some((i, u)) = rest.next() { spawn(&mut set, &mut sent_at, i, u); }
                    hedge = Box::pin(tokio::time::sleep(p.hedge));
                }
                _ = &mut hard => break,
            }
        }
        // 3.5.0 F4：這一輪有沒有上游正常回答（Ok、NODATA、NXDOMAIN、上游自己的過濾擋掉都算「答得出來」）
        let answered = out
            .iter()
            .any(|a| matches!(a.class, Class::Ok | Class::NoData | Class::NxDomain | Class::Blocked));
        if round_aware && answered {
            // 來不及回答：已經送出、還沒回來就要被取消的（串接上游除外：它是唯一的主要上游，沒有「別台先答完」）
            let sent = list.len() - rest.len();
            for (i, up) in list.iter().enumerate().take(sent.min(LATE_TRACK)) {
                if back & (1 << i) == 0 && up.role != Role::Chain {
                    up.note_late(sent_at[i].elapsed().as_secs_f64() * 1000.0);
                }
            }
        }
        set.abort_all();
        // SERVFAIL 只在「同一筆有別的上游正常回答」時才算那台失敗：大家都解析不到（剛註冊、權威伺服器壞掉的網域）
        // 是網域的問題，不是上游的。以前照算，壓測新網域時自己的 DoH／DoT 一直被暫停 1→2→4 分鐘
        // （padavan-tw 的 3.4.2 單獨運作測試，每段 35～38 次）。逾時的（3.5.0 F4）也一樣，條件是有別台答得出來
        let any_ok = out.iter().any(|a| a.class == Class::Ok);
        for (up, ms, timed_out) in servfails {
            if (timed_out && answered) || (!timed_out && any_ok) {
                up.record(false, ms);
            } else if timed_out {
                up.note_unanswered();
            }
        }
        // 效能計數器（3.5.0）：這次實際送出幾個上游查詢（list 裡還沒拿出來的就是沒送）
        perf::note_ask(list.len() - rest.len(), all);
        Asked {
            answers: out,
            unasked: rest.map(|(_, u)| u).collect(),
        }
    }

    /// 合併所有上游給的 IP（最終 CNAME 相同的才合併），TCP 443 測速後排序
    async fn merge_rank(&self, oks: &[Arc<Answer>], qname: &str, qtype: u16) -> Option<(Message, String, String)> {
        // 串接上游（上游黑潮）的回答已經合併、測速、排好序（3.4.1）：不在下游再測一次 TCP 443
        if oks.iter().all(|a| a.up.role == Role::Chain) {
            return None;
        }
        let mut all: Vec<IpAddr> = Vec::new();
        for a in oks {
            for ip in logic::ips_of(&a.msg, qtype) {
                if !all.contains(&ip) {
                    all.push(ip);
                }
            }
        }
        if all.len() <= 1 && oks.len() <= 1 {
            return None;
        }
        // 查詢路徑不排隊等測速名額（3.5.1 H1）：名額用完時照上游的順序回答
        let ranked = self.iprank.rank_now(&all).await;
        let best = ranked.iter().find(|r| r.1.ok)?.0;
        let base = oks.iter().find(|a| logic::ips_of(&a.msg, qtype).contains(&best))?;
        let term = logic::terminal_name(&base.msg, qname);
        let same: Vec<IpAddr> = oks
            .iter()
            .filter(|a| logic::terminal_name(&a.msg, qname) == term)
            .flat_map(|a| logic::ips_of(&a.msg, qtype))
            .collect();
        let mut order: Vec<_> = ranked.iter().filter(|r| same.contains(&r.0)).collect();
        if order.iter().any(|r| r.1.ok) {
            order.retain(|r| r.1.ok);
        }
        order.truncate(self.params.max_ips);
        let mut msg = base.msg.clone();
        let recs: Vec<&Record> = msg.answers.iter().filter(|a| a.rtype == qtype).collect();
        let owner = recs.first().map(|r| r.name.clone()).unwrap_or_else(|| qname.to_string());
        let ttl = recs.iter().map(|r| r.ttl).min().unwrap_or(60);
        msg.answers.retain(|a| a.rtype != qtype);
        for (ip, _) in &order {
            let data = match ip {
                IpAddr::V4(v) => RData::A(*v),
                IpAddr::V6(v) => RData::Aaaa(*v),
            };
            msg.answers.push(Record {
                name: owner.clone(),
                rtype: qtype,
                class: 1,
                ttl,
                data,
            });
        }
        let note = format!("{:.0}ms/{}IP", order.first().map(|r| r.1.ms).unwrap_or(0.0), same.len());
        Some((msg, base.up.up.id.clone(), note))
    }

    /// 寫入快取（含 CNAME 鏈過濾、TTL 計算）
    #[allow(clippy::too_many_arguments)]
    fn store(
        &self,
        key: &str,
        msg: &Message,
        class: Class,
        source: String,
        qname: &str,
        fast: bool,
        ranked: Option<String>,
        baseline: Option<kuroshio_cdn::Baseline>,
        chained: bool,
    ) -> Arc<Entry> {
        let p = &self.params;
        let qtype = Cache::key_qtype(key);
        let mut blocked = None;
        // 串接模式（3.4.0）：擋下的 CNAME 目標是「繞過防護」清單命中的（只記名稱；放不放行在 serve() 依來源判斷）
        let mut blocked_bypass = None;
        if class == Class::Ok {
            let me = self.filter_check(qname, qtype);
            if !me.map(|v| v.allow).unwrap_or(false) {
                for t in logic::cname_targets(msg) {
                    if let Some(v) = self.filter_check(&t, qtype) {
                        if !v.block {
                            continue;
                        }
                        if v.bypass && blocked.is_none() {
                            // 第一個命中的是 bypass 清單：再看後面的目標有沒有被其他清單擋
                            blocked = Some(v.category);
                            blocked_bypass = Some(t);
                            continue;
                        }
                        // 其他清單或自訂規則擋的、或第二個 bypass 目標（只記得一個名稱）：任何來源都擋
                        blocked_bypass = None;
                        if !v.bypass {
                            blocked = Some(v.category);
                        }
                        break;
                    }
                }
            }
        }
        let ttl = match class {
            Class::ServFail => 3,
            Class::NxDomain | Class::NoData => logic::negative_ttl(msg).min(p.negative_max_ttl),
            _ => logic::min_ttl(msg, 60).min(p.max_ttl),
        }
        .max(p.min_ttl)
        .max(1);
        let mut cache = self.cache.lock().unwrap();
        let now = Instant::now();
        if class == Class::ServFail {
            // 上游全部失敗：還能用的舊資料保留，不用 SERVFAIL 蓋掉
            if let Some(old) = cache.peek(key) {
                if old.class != Class::ServFail && old.remaining(now) > -(p.stale_if_error as f64) {
                    return old;
                }
            }
        }
        let mut e = Entry::new(
            msg.rcode,
            msg.answers.clone(),
            msg.authorities.clone(),
            class,
            source,
            ttl,
            fast,
            ranked,
        );
        e.blocked = blocked;
        e.blocked_bypass = blocked_bypass;
        e.baseline = baseline;
        e.chained = chained;
        cache.insert(key.to_string(), e, now)
    }
}

/// singleflight 的保險：工作沒有走到最後的 notify 就結束時，把鍵從進行中的名單拿掉
struct InflightGuard<'a>(&'a Mutex<HashMap<String, Waiters>>, &'a str);

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        // 丟掉 sender：等待的人收到「通道關閉」，回 SERVFAIL
        self.0.lock().unwrap_or_else(|e| e.into_inner()).remove(self.1);
    }
}

/// `job()` 交給背景補問的資料
struct Backfilling {
    key: String,
    qname: String,
    upq: Vec<u8>,
    qtype: u16,
    verbatim: bool,
    first: Vec<Arc<Answer>>,
    unasked: Vec<Arc<Up>>,
    entry: Arc<Entry>,
    cdn: Option<Arc<kuroshio_cdn::Cdn>>,
}

/// 「如果用一般 DNS 會怎樣」：固定上游以外的上游給的 A 記錄（串接上游也不採計：它是另一台黑潮挑過的答案）
fn baseline_of(cdn: Option<&kuroshio_cdn::Cdn>, qtype: u16, results: &[Arc<Answer>]) -> Option<kuroshio_cdn::Baseline> {
    match (cdn, qtype == rtype::A) {
        (Some(c), true) => {
            let others: Vec<&Message> = results
                .iter()
                .filter(|r| r.class == Class::Ok && !matches!(r.up.role, Role::Pinned | Role::Chain))
                .map(|r| &r.msg)
                .collect();
            c.baseline(&others)
        }
        _ => None,
    }
}

/// 純函式：有沒有可能補問（跟 CDN、抽樣無關的條件）：沒關掉、不是 verbatim（DO、類別不是 IN）、
/// A／AAAA、而且有沒問到的上游（`parallel` = 0 或串接中一定沒有）
fn backfill_possible(p: &Params, qtype: u16, verbatim: bool, unasked: usize) -> bool {
    p.backfill != Backfill::Off && !verbatim && (qtype == rtype::A || qtype == rtype::AAAA) && unasked > 0
}

/// 純函式：這次要不要補問（規格 10 第 5.2 節）。
/// `cdn_hit`：答案裡有位址被 CDN 範圍認得；`sample_tick`：非 CDN 查詢的抽樣計數（從 1 開始）。
/// 抽樣取每一輪的中間那一次（`backfillSample` = 16 時是第 8、24、40… 次），不是每輪的第一次：
/// 開機後的第一個查詢不會馬上補問
fn backfill_wanted(p: &Params, qtype: u16, verbatim: bool, unasked: usize, cdn_hit: bool, sample_tick: u64) -> bool {
    if !backfill_possible(p, qtype, verbatim, unasked) {
        return false;
    }
    if cdn_hit {
        return true;
    }
    let n = p.backfill_sample;
    n > 0 && sample_tick > 0 && sample_tick % n == n / 2
}

/// 純函式：抽樣比對有沒有不一致：前面有正常回應、補問的多數（至少 2 台而且過半）是 NXDOMAIN／NODATA；
/// 或反過來（前面沒有正常回應、只有 NXDOMAIN／NODATA，補問的多數有正常回應）
fn backfill_mismatch(first: &[Arc<Answer>], more: &[Arc<Answer>]) -> bool {
    let neg = |a: &&Arc<Answer>| matches!(a.class, Class::NxDomain | Class::NoData);
    let ok = |a: &&Arc<Answer>| a.class == Class::Ok;
    let majority = |n: usize| n >= 2 && n * 2 > more.len();
    if first.iter().any(|a| ok(&a)) {
        return majority(more.iter().filter(neg).count());
    }
    first.iter().any(|a| neg(&a)) && majority(more.iter().filter(ok).count())
}

/// 從多個上游結果決定答案（同 2.x）：有正常回應取最快的；否則 nodata / nxdomain 多數決（平手以固定上游為準）
/// 串接上游（上游黑潮）多等的時間。上游解析不到時最久要：問自己的上游逾時（`resolver.timeoutMs`）＋
/// 改問備援再逾時一次，才回 SERVFAIL。下游等得比這短，就會先放棄、改問自己的加密上游（3.4.2：
/// padavan-tw 的串接壓測裡，自己的 DoH／DoT 一直被問到「連續失敗」）。所以等兩倍的逾時再加 1 秒
const CHAIN_EXTRA_TIMEOUT: Duration = Duration::from_millis(1000);

/// 一個往上游查的工作（合併後的那一筆）最多多久（3.5.1 H1）：主要上游一輪、備援一輪、IP 測速排序，正常都在幾秒內；
/// 超過就放棄，等待的人回 SERVFAIL，下一筆重新問。不放棄的話同名同類型的查詢會一直跟著等
pub const JOB_DEADLINE: Duration = Duration::from_secs(12);

fn timeout_for(p: &Params, up: &Up) -> Duration {
    if up.role == Role::Chain {
        p.timeout * 2 + CHAIN_EXTRA_TIMEOUT
    } else {
        p.timeout
    }
}

/// 查詢帶著黑潮的「不要換 CDN 節點」選項（下游黑潮自己關掉了 CDN 置換；3.4.3）
fn wants_no_cdn(q: &Message) -> bool {
    q.opt.as_ref().is_some_and(|o| {
        o.options
            .iter()
            .any(|(c, _)| *c == kuroshio_proto::message::opt_code::KUROSHIO_NO_CDN)
    })
}

/// 在查詢加上「不要換 CDN 節點」選項（沒有 OPT 就加一個）；解析不了 → None（照原樣送）
fn with_no_cdn(q: &[u8]) -> Option<Vec<u8>> {
    let mut m = Message::parse(q).ok()?;
    let o = m.opt.get_or_insert_with(|| kuroshio_proto::message::Opt {
        udp_size: 1232,
        ..Default::default()
    });
    o.options.push((kuroshio_proto::message::opt_code::KUROSHIO_NO_CDN, Vec::new()));
    Some(m.encode())
}

/// 回應帶著 EDE 15（被擋）或 17（被過濾）：上游的過濾擋掉的（RFC 8914）
fn blocked_by_ede(msg: &Message) -> bool {
    msg.opt.as_ref().is_some_and(|o| {
        o.options.iter().any(|(code, d)| {
            *code == kuroshio_proto::message::opt_code::EDE
                && d.len() >= 2
                && matches!(u16::from_be_bytes([d[0], d[1]]), logic::ede::BLOCKED | logic::ede::FILTERED)
        })
    })
}

/// 這個回答算不算上游「有回應」（健康紀錄用）。串接上游回 SERVFAIL 是它自己解析不到（例如權威伺服器太慢），
/// 上游黑潮本身是好的：不算串接失敗。以前算失敗，連續 3 次就暫停串接 30 秒、全部改走自己的加密上游（3.4.2）
fn answered_ok(up: &Up, class: Class) -> bool {
    match class {
        Class::Error => false,
        Class::ServFail => up.role == Role::Chain,
        Class::Refused => up.role != Role::Chain,
        _ => true,
    }
}

/// 串接中的機房抽查（3.5.0 E4，規格 11）：`answer_ip` 是答案抽查握手通過的那個 IP。
/// `Cdn::pop_audit_pick()` 決定量哪個節點、扣名額（上限在 CDN 那一層：10 分鐘 1 個、24 小時 24 個、每個節點一次，
/// `cdn.lite` 30 分鐘 1 個、8 個；`cdn.popAudit` 關、記憶體壓力時回 None）：
/// 答案的 IP 是上游宣稱機房（`upPop`）還沒確認的節點就量它；不是的話（3.5.0 F7）改量一個待確認的前幾名節點。
/// 用健檢同一個探測（那家 CDN 的 `probe` 路徑）量**回傳的那個 IP**，拿到的機房交給 `Cdn::note_local_pop()` 比對。
/// 不動答案抽查的可疑計數、不解除串接（機房不同是線路拓樸，不是不可信）
pub(crate) async fn pop_audit_probe(cdn: &kuroshio_cdn::Cdn, answer_ip: IpAddr) {
    let Some((provider, target)) = cdn.pop_audit_pick(answer_ip) else {
        return;
    };
    let Some((prov, (host, path))) = kuroshio_cdn::providers::get(provider).and_then(|p| Some((p, p.probe?))) else {
        return;
    };
    let r = cdn.net().http_probe(target, host, path, Duration::from_secs(3)).await;
    if !r.ok {
        return;
    }
    let pop = prov.pop(&r.headers, &r.body);
    if !pop.is_empty() {
        cdn.note_local_pop(provider, target, &pop);
    }
}

/// 一輪詢問最多追蹤幾台上游有沒有回來（3.5.0 F4；`ask()` 裡的位元遮罩是 32 位元）。
/// 一輪的上游超過這個數時，後面的不記「來不及回答」（照 3.4.x 的記法）
const LATE_TRACK: usize = 32;

/// 通訊類網域（推播）同時最多預取幾個（3.5.0）
pub const COMM_PREFETCH_MAX: u32 = 16;

/// 效能計數器（3.5.0，規格 11 C12）：每次詢問（ask）實際送出幾個上游查詢、背景補問送出幾個。
/// 只在 ask() 結束時加一次（`AtomicU32`，沒有鎖）；32 位元機器沒有 64 位元原子操作，溢位就從 0 重來
pub mod perf {
    use serde_json::{json, Value};
    use std::sync::atomic::{AtomicU32, Ordering};

    /// 送出 1、2、3、4 個以上上游查詢的次數（0 個不記：沒有可用的上游）
    static FANOUT: [AtomicU32; 4] = [AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0)];
    /// 背景補問送出的上游查詢數
    static BACKFILL: AtomicU32 = AtomicU32::new(0);
    /// 超過總期限被放棄的查詢工作（3.5.1 H1）
    static JOB_TIMEOUTS: AtomicU32 = AtomicU32::new(0);
    /// 查詢路徑因為測速名額用完而沒有排序 IP 的次數（3.5.1 H1；由 `Resolver` 設定來源）
    static RANK: std::sync::Mutex<Option<std::sync::Weak<kuroshio_net::iprank::IpRank>>> = std::sync::Mutex::new(None);

    pub fn note_job_timeout() {
        JOB_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_rank(r: &std::sync::Arc<kuroshio_net::iprank::IpRank>) {
        *RANK.lock().unwrap() = Some(std::sync::Arc::downgrade(r));
    }

    pub fn note_ask(sent: usize, backfill: bool) {
        if backfill {
            BACKFILL.fetch_add(sent as u32, Ordering::Relaxed);
        } else if sent > 0 {
            FANOUT[sent.min(4) - 1].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// `/api/status` 的 `perf`
    pub fn json() -> Value {
        let f: Vec<u32> = FANOUT.iter().map(|a| a.load(Ordering::Relaxed)).collect();
        json!({
            "tls": kuroshio_net::perf::json(),
            // 每次詢問送出 1、2、3、4 個以上上游查詢的次數（一筆查詢可能詢問兩次：先問主要的，再問備援）
            "fanout": { "1": f[0], "2": f[1], "3": f[2], "4+": f[3] },
            "backfillQueries": BACKFILL.load(Ordering::Relaxed),
            "jobTimeouts": JOB_TIMEOUTS.load(Ordering::Relaxed),
            "rankSkipped": RANK.lock().unwrap().as_ref().and_then(|w| w.upgrade()).map_or(0, |r| r.busy_skips()),
            // 加密 DNS 伺服器拒絕新連線、DoH 回 busy、查詢逾時的累計次數（3.5.1 K7–K9）
            "server": crate::encrypted::server_json(),
        })
    }
}

fn is_negative(c: Class) -> bool {
    matches!(c, Class::NoData | Class::NxDomain)
}

/// 決定的否定答案只有一台給、而且問了兩台以上：其他上游都沒有同樣的否定答案
fn lone_negative(d: &Decided, answers: &[Arc<Answer>], asked: usize) -> bool {
    is_negative(d.class) && asked >= 2 && answers.iter().filter(|a| a.class == d.class).count() < 2
}

fn decide(results: &[Arc<Answer>], accept_blocked: bool, cdn: Option<&kuroshio_cdn::Cdn>, qtype: u16) -> Option<Decided> {
    // 一般 DNS 被路上的攔截者接走時（路徑檢查，3.3.6），它們的回答其實是攔截者給的：
    // 有其他上游的回答時，不拿來合併 IP、也不參加多數決
    let independent: Vec<Arc<Answer>>;
    let results = if results.iter().any(|r| r.up.via_interceptor()) && results.iter().any(|r| !r.up.via_interceptor()) {
        independent = results.iter().filter(|r| !r.up.via_interceptor()).cloned().collect();
        &independent[..]
    } else {
        results
    };
    let by = |c: Class| -> Vec<Arc<Answer>> { results.iter().filter(|r| r.class == c).cloned().collect() };
    let mut oks = by(Class::Ok);
    // 固定上游換過的 CDN IP（沒針對這個網站驗證過）：其他上游有給答案時從合併名單拿掉
    if let Some(cdn) = cdn {
        let others: Vec<&Message> = oks.iter().filter(|r| r.up.role != Role::Pinned).map(|r| &r.msg).collect();
        if !others.is_empty() {
            let mut kept = Vec::with_capacity(oks.len());
            for r in &oks {
                if r.up.role != Role::Pinned {
                    kept.push(r.clone());
                    continue;
                }
                let drop = cdn.pinned_alias(&r.msg, qtype, Some(&others));
                if drop.is_empty() {
                    kept.push(r.clone());
                    continue;
                }
                let mut msg = r.msg.clone();
                msg.answers
                    .retain(|a| !(a.rtype == qtype && logic::ip_of(a).is_some_and(|ip| drop.contains(&ip))));
                if msg.answers.iter().any(|a| a.rtype == qtype) {
                    kept.push(Arc::new(Answer {
                        up: r.up.clone(),
                        msg,
                        class: r.class,
                        ms: r.ms,
                    }));
                }
            }
            oks = kept;
        }
    }
    if let Some(first) = oks.iter().min_by(|a, b| a.ms.partial_cmp(&b.ms).unwrap()) {
        return Some(Decided {
            msg: first.msg.clone(),
            class: Class::Ok,
            source: first.up.up.id.clone(),
            oks: oks.clone(),
            chained: first.up.role == Role::Chain,
        });
    }
    let pinned_first = |v: &[Arc<Answer>]| -> Option<Arc<Answer>> {
        let mut v = v.to_vec();
        v.sort_by(|a, b| {
            ((b.up.role == Role::Pinned) as u8)
                .cmp(&((a.up.role == Role::Pinned) as u8))
                .then(a.ms.partial_cmp(&b.ms).unwrap())
        });
        v.into_iter().next()
    };
    let (nodata, nx) = (by(Class::NoData), by(Class::NxDomain));
    if !nodata.is_empty() || !nx.is_empty() {
        let pick = if nodata.len() > nx.len() {
            pinned_first(&nodata)
        } else if nx.len() > nodata.len() {
            pinned_first(&nx)
        } else {
            pinned_first(&[nodata, nx].concat())
        }?;
        return Some(Decided {
            msg: pick.msg.clone(),
            class: pick.class,
            source: pick.up.up.id.clone(),
            oks: vec![],
            chained: pick.up.role == Role::Chain,
        });
    }
    // 串接上游（上游黑潮）解析失敗（SERVFAIL）：第一輪不當成答案，改問自己的上游（3.4.3）。上游黑潮自己的上游
    // 壞了、心跳卻正常時，以前下游每一筆都 SERVFAIL、永遠不會退回自己的上游；每台黑潮都要能自己解析。
    // 自己的上游也解析不到時（最後一輪，`accept_blocked`），才照上游的 SERVFAIL。
    // 上游黑潮「擋掉」的同理：下游的過濾沒有擋，就用自己的加密上游解析一次（下游自己決定要不要擋）
    if let Some(c) = results
        .iter()
        .find(|r| accept_blocked && r.up.role == Role::Chain && r.class == Class::ServFail)
    {
        return Some(Decided {
            msg: c.msg.clone(),
            class: Class::ServFail,
            source: c.up.up.id.clone(),
            oks: vec![],
            chained: true,
        });
    }
    if accept_blocked {
        if let Some(b) = by(Class::Blocked).first() {
            return Some(Decided {
                msg: b.msg.clone(),
                class: Class::Ok,
                source: format!("{}(上游已擋)", b.up.up.id),
                oks: vec![],
                chained: b.up.role == Role::Chain,
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 3.5.0 F7：串接中的機房抽查量 CDN 那一層挑的節點（`pop_audit_pick()`），不是答案的 IP；
    /// 量到的機房交給 `note_local_pop()`（待確認的前幾名少一個）。名額照舊（10 分鐘 1 個），`cdn.popAudit` 關就不量
    #[tokio::test]
    async fn pop_audit_probes_the_node_cdn_picked() {
        use crate::cdntest::{cdn, cf_page, ip, node};
        let (c, net) = cdn("popaudit", json!({}));
        c.with_state(|st| {
            *st.pools.p.get_mut("cloudflare").unwrap().pool_mut(4) =
                vec![node("192.0.2.1", "KHH", 1.0, true), node("192.0.2.2", "KHH", 2.0, true)]
        });
        net.http.lock().unwrap().insert(ip("192.0.2.1"), cf_page("KHH", 5.0));
        assert_eq!(c.observe_json()["popAudit"]["pendingServed"], 2);
        // 答案的 IP 不是待確認的節點（W17：答案抽查一直抽不中）：改量待確認的第 1 名
        pop_audit_probe(&c, ip("198.51.100.99")).await;
        let calls = net.calls("http ");
        assert_eq!(calls.len(), 1, "{calls:?}");
        assert!(calls[0].starts_with("http 192.0.2.1 "), "{calls:?}");
        assert_eq!(c.observe_counters().pop_probes, 1);
        assert_eq!(c.observe_counters().pop_confirmed, 1, "機房一樣：確認");
        assert_eq!(c.observe_json()["popAudit"]["pendingServed"], 1);
        // 名額 10 分鐘 1 個：馬上再來一次不量
        pop_audit_probe(&c, ip("198.51.100.99")).await;
        assert_eq!(net.calls("http ").len(), 1);
        // cdn.popAudit 關：不量
        let (c, net) = cdn("popaudit-off", json!({ "popAudit": false }));
        c.with_state(|st| *st.pools.p.get_mut("cloudflare").unwrap().pool_mut(4) = vec![node("192.0.2.1", "KHH", 1.0, true)]);
        pop_audit_probe(&c, ip("192.0.2.1")).await;
        assert!(net.calls("http ").is_empty());
    }

    /// 3.4.3：下游黑潮自己關掉 CDN 置換時，問上游黑潮的查詢帶著私有選項；上游看到就照原樣回答
    #[test]
    fn no_cdn_option_roundtrip() {
        let q = kuroshio_proto::build_query(7, "www.example.com", 1);
        assert!(!wants_no_cdn(&Message::parse(&q).unwrap()));
        let nq = with_no_cdn(&q).unwrap();
        let m = Message::parse(&nq).unwrap();
        assert!(wants_no_cdn(&m));
        assert_eq!(m.questions[0].name, "www.example.com");
        assert!(with_no_cdn(b"bad").is_none());
    }

    #[test]
    fn local_forward_names() {
        let l = LocalForward {
            up: Upstream::parse("udp://127.0.0.1:53").unwrap(),
            domains: vec!["lan".into()],
            private_ptr: true,
        };
        assert!(l.matches("router.lan"));
        assert!(l.matches("lan"));
        assert!(!l.matches("plan"));
        assert!(l.matches("1.1.168.192.in-addr.arpa"));
        assert!(l.matches("5.0.20.172.in-addr.arpa"));
        assert!(!l.matches("5.0.32.172.in-addr.arpa"));
        assert!(!l.matches("8.8.8.8.in-addr.arpa"));
        assert!(l.matches("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa"));
        assert!(!l.matches("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"));
    }

    fn params(extra: Value) -> Params {
        let mut c = kuroshio_config::defaults();
        kuroshio_config::merge(&mut c, &json!({ "resolver": extra }));
        Params::from_cfg(&c)
    }

    #[test]
    fn backfill_params_from_config() {
        let p = params(json!({}));
        assert_eq!((p.backfill, p.backfill_sample), (Backfill::Cdn, 16));
        assert!(p.backfill_max == 2 || p.backfill_max == 4);
        let p = params(json!({ "backfill": "off", "backfillSample": "4" }));
        assert_eq!((p.backfill, p.backfill_sample), (Backfill::Off, 4));
    }

    /// 3.5.0 F4：`upstream.roundAwareFailures` 預設開；false、UCI 的 "0" 是關
    #[test]
    fn round_aware_failures_from_config() {
        assert!(params(json!({})).round_aware_failures);
        assert!(Params::from_cfg(&json!({})).round_aware_failures, "沒寫 = 開");
        for off in [json!(false), json!("0"), json!(0)] {
            let mut c = kuroshio_config::defaults();
            kuroshio_config::merge(&mut c, &json!({ "upstream": { "roundAwareFailures": off } }));
            assert!(!Params::from_cfg(&c).round_aware_failures, "{c:?}");
        }
    }

    #[test]
    fn backfill_wanted_rules() {
        let p = params(json!({ "backfillSample": 4 }));
        let (a, aaaa) = (rtype::A, rtype::AAAA);
        // CDN 相關：A／AAAA、有沒問到的上游就補問
        assert!(backfill_wanted(&p, a, false, 2, true, 0));
        assert!(backfill_wanted(&p, aaaa, false, 1, true, 0));
        // 不補問：verbatim、不是 A／AAAA、沒有沒問到的上游（parallel = 0、串接中）
        assert!(!backfill_wanted(&p, a, true, 2, true, 0));
        assert!(!backfill_wanted(&p, rtype::TXT, false, 2, true, 0));
        assert!(!backfill_wanted(&p, a, false, 0, true, 0));
        // 抽樣：每 4 次抽 1 次
        let hits = (1..=16).filter(|t| backfill_wanted(&p, a, false, 2, false, *t)).count();
        assert_eq!(hits, 4);
        assert!(!backfill_wanted(&p, a, false, 2, false, 0));
        // backfillSample = 1：每次；0：不抽樣（CDN 相關的照樣補問）
        let one = params(json!({ "backfillSample": 1 }));
        assert!((1..=5).all(|t| backfill_wanted(&one, a, false, 2, false, t)));
        let zero = params(json!({ "backfillSample": 0 }));
        assert!((0..=40).all(|t| !backfill_wanted(&zero, a, false, 2, false, t)));
        assert!(backfill_wanted(&zero, a, false, 2, true, 0));
        // 關掉：什麼都不補問
        let off = params(json!({ "backfill": "off", "backfillSample": 1 }));
        assert!(!backfill_wanted(&off, a, false, 2, true, 1));
        assert!(!backfill_wanted(&off, a, false, 2, false, 1));
    }

    #[test]
    fn backfill_mismatch_rules() {
        let dir = std::env::temp_dir().join(format!("kuroshio-bf-{}", std::process::id()));
        let cfg = kuroshio_config::with_overrides(&json!({
            "upstream": { "pinned": ["udp://192.0.2.1:53"], "fallback": [] },
            "system": { "persistDir": dir.to_string_lossy() }
        }));
        let m = Manager::new(&cfg, dir.join("upstreams.json"));
        let up = m.active().into_iter().next().expect("固定上游");
        let ans = |class: Class| {
            Arc::new(Answer {
                up: up.clone(),
                msg: Message::default(),
                class,
                ms: 1.0,
            })
        };
        let (ok, nx, nd, sf) = (Class::Ok, Class::NxDomain, Class::NoData, Class::ServFail);
        let mm = |first: &[Class], more: &[Class]| {
            let v = |c: &[Class]| c.iter().map(|c| ans(*c)).collect::<Vec<_>>();
            backfill_mismatch(&v(first), &v(more))
        };
        // 前面正常、補問的多數（至少 2 台而且過半）是 NXDOMAIN／NODATA
        assert!(mm(&[ok], &[nx, nd]));
        assert!(mm(&[ok, nx], &[nx, nx, ok]));
        assert!(!mm(&[ok], &[nx]), "只有 1 台不算");
        assert!(!mm(&[ok], &[nx, ok]), "沒有過半");
        assert!(!mm(&[ok], &[nx, nx, ok, ok]));
        assert!(!mm(&[ok], &[ok, ok]));
        // 反過來：前面只有 NXDOMAIN／NODATA，補問的多數有正常回應
        assert!(mm(&[nx, nx], &[ok, ok, ok]));
        assert!(mm(&[nd], &[ok, ok, sf]));
        assert!(!mm(&[nx], &[ok]));
        assert!(!mm(&[nx], &[nx, nx]));
        // 前面全部失敗：沒有可以比對的
        assert!(!mm(&[sf], &[ok, ok]));
        assert!(!mm(&[], &[ok, ok]));
        assert!(!mm(&[ok], &[]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn singleflight_waiters_get_an_answer_when_the_job_dies() {
        let inflight: Arc<Mutex<HashMap<String, Waiters>>> = Arc::default();
        let (tx, rx) = oneshot::channel();
        inflight.lock().unwrap().insert("1|dead.test".into(), vec![tx]);
        let map = inflight.clone();
        // 模擬 job() 中途 panic
        let job = tokio::spawn(async move {
            let _guard = InflightGuard(&map, "1|dead.test");
            panic!("模擬上游處理中 panic");
        });
        assert!(job.await.is_err());
        // 等待的人不會卡住（fetch() 收到通道關閉回 SERVFAIL），鍵也拿掉了：下一個查詢會重新問上游
        let got = tokio::time::timeout(Duration::from_secs(1), rx).await.expect("不能卡住");
        assert!(got.is_err());
        assert!(inflight.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn singleflight_waiters_released_when_the_job_exceeds_its_deadline() {
        // 3.5.1 H1：job() 有一步一直不回來（以前是查詢路徑排隊等 IP 測速名額）：總期限一到就放棄，
        // 鍵拿掉、等待的人回 SERVFAIL，同名同類型的下一筆重新問——不會一直卡到重新啟動
        let inflight: Arc<Mutex<HashMap<String, Waiters>>> = Arc::default();
        let (tx, rx) = oneshot::channel();
        inflight.lock().unwrap().insert("1|www.example.com".into(), vec![tx]);
        let map = inflight.clone();
        let job = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_millis(50), async {
                let _guard = InflightGuard(&map, "1|www.example.com");
                std::future::pending::<()>().await;
            })
            .await
            .is_err()
        });
        assert!(job.await.unwrap(), "超過期限");
        let got = tokio::time::timeout(Duration::from_secs(1), rx).await.expect("不能卡住");
        assert!(got.is_err());
        assert!(inflight.lock().unwrap().is_empty());
        assert!(
            JOB_DEADLINE >= Duration::from_secs(8),
            "主要上游一輪 + 備援一輪 + 測速，正常的查詢不能被它砍掉"
        );
    }
}
