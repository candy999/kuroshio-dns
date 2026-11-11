//! 解析主流程（對齊 2.x `lib/resolver.js`）：
//! 過濾 → 快取 → 並行上游（第一個正常回應先回）→ 背景合併所有 IP、測速排序。
//! CDN 台灣節點改寫在階段 2 接上。

use crate::cache::{Cache, Entry};
use crate::iprank::IpRank;
use crate::stats::{Kind as StatKind, Stats};
use crate::upstream::Upstream;
use crate::upstreams::{Manager, Role, Up};
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
use tracing::debug;

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

struct Decided {
    msg: Message,
    class: Class,
    source: String,
    oks: Vec<Arc<Answer>>,
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
    /// 本機對外 IP 的 /24（啟動後偵測）
    pub ecs_subnet: RwLock<Option<(IpAddr, u8)>>,
    inflight: Mutex<HashMap<String, Waiters>>,
    /// 最近一次「所有上游都失敗」的時間（0.1 秒，相對 `base`）；0 = 沒發生過
    last_outage: AtomicU32,
    /// 查詢計數，用來每 20 次探索一個平常排在後面的上游
    picks: AtomicU32,
    base: Instant,
    errors: Mutex<(u64, Vec<(u64, String)>)>,
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
            ecs_subnet: RwLock::new(None),
            inflight: Mutex::new(HashMap::new()),
            last_outage: AtomicU32::new(0),
            picks: AtomicU32::new(0),
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
        self.stats.query(&qname, ctx.client);
        if let Some(p) = self.presence.get() {
            p.record(ctx.proto, ctx.client, &qname);
        }

        // 1. 過濾
        if let Some(v) = self.filter_check(&qname, qtype) {
            if v.block {
                self.stats.blocked(v.category);
                self.stats.blocked_name(&qname, ctx.client, v.category);
                let code = if v.category == "malware" { ede::BLOCKED } else { ede::FILTERED };
                debug!("{} {qname} 攔截（{}）{}", ctx.proto, v.category, v.rule);
                return msg(logic::blocked_response(&query, code, &format!("{}：{}", v.category, v.rule)));
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
                }
                if stale {
                    self.stats.count(StatKind::Stale);
                }
                if let Some(cat) = e.blocked {
                    self.stats.blocked(cat);
                    self.stats.blocked_name(&qname, ctx.client, cat);
                }
                let out = self.serve(&query, &e, if stale { Some(10) } else { None });
                self.stats.hit(t0.elapsed().as_secs_f64() * 1000.0);
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
        }
        if let Some(cat) = e.blocked {
            self.stats.blocked(cat);
            self.stats.blocked_name(&qname, ctx.client, cat);
        }
        if e.class == Class::ServFail {
            self.stats.count(StatKind::ServFail);
        }
        let out = self.serve(&query, &e, stale.then_some(10));
        self.stats.latency(false, t0.elapsed().as_secs_f64() * 1000.0);
        msg(out)
    }

    /// 由快取項目產生回應：答案 TTL 統一成剩餘秒數（過期回舊資料時用 10 秒）
    fn serve(&self, query: &Message, e: &Entry, force_ttl: Option<u32>) -> Message {
        if let Some(cat) = e.blocked {
            let code = if cat == "malware" { ede::BLOCKED } else { ede::FILTERED };
            return logic::blocked_response(query, code, &format!("{cat}：CNAME"));
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
        let verbatim = query.dnssec_ok() || query.questions[0].qclass != 1;
        if let Some(cdn) = self.steer_cdn().filter(|_| !verbatim) {
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

    fn refresh(self: &Arc<Self>, key: String, query: Message) {
        if self.inflight.lock().unwrap().contains_key(&key) {
            return;
        }
        self.stats.count(StatKind::Prefetch);
        let me = self.clone();
        tokio::spawn(async move {
            me.fetch(key, query).await;
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
            tokio::spawn(async move { me.job(k, query).await });
        }
        match rx.await {
            Ok(e) => e,
            Err(_) => Arc::new(Entry::new(2, vec![], vec![], Class::ServFail, "內部錯誤".into(), 3, false, None)),
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
        let results = self
            .ask(&active, &upq, qtype, |a| {
                if fast_sent || !self.params.fast_path || a.class != Class::Ok {
                    return;
                }
                // 固定上游（路由器）自帶的 CDN 優選 IP 沒有針對這個網站驗證過，不拿來當快速回應
                if a.up.role == Role::Pinned && cdn.as_ref().is_some_and(|c| !c.pinned_alias(&a.msg, qtype, None).is_empty()) {
                    return;
                }
                fast_sent = true;
                let e = self.store(&key, &a.msg, Class::Ok, a.up.up.id.clone(), &qname, true, None, None);
                self.notify(&key, &e, false);
            })
            .await;
        let mut decided = decide(&results, false, cdn.as_deref(), qtype);
        if decided.is_none() {
            // 全部失敗或都被上游擋：改問備援
            let more = self.ask(&self.upstreams.backup(), &upq, qtype, |_| {}).await;
            decided = decide(&more, false, cdn.as_deref(), qtype).or_else(|| {
                let all: Vec<Arc<Answer>> = results.iter().chain(&more).cloned().collect();
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
            ),
            Some(mut d) => {
                let mut note = None;
                if (qtype == rtype::A || qtype == rtype::AAAA) && !d.oks.is_empty() && self.params.rank_ips && !verbatim {
                    if let Some((msg, source, n)) = self.merge_rank(&d.oks, &qname, qtype).await {
                        d.msg = msg;
                        d.source = source;
                        note = Some(n);
                    }
                }
                // 「如果用一般 DNS 會怎樣」：固定上游以外的上游給的 A 記錄
                let baseline = match (&cdn, qtype == rtype::A) {
                    (Some(c), true) => {
                        let others: Vec<&Message> = results
                            .iter()
                            .filter(|r| r.class == Class::Ok && r.up.role != Role::Pinned)
                            .map(|r| &r.msg)
                            .collect();
                        c.baseline(&others)
                    }
                    _ => None,
                };
                self.store(&key, &d.msg, d.class, d.source, &qname, false, note, baseline)
            }
        };
        self.notify(&key, &e, true);
        // 正常結束：notify 已經把鍵拿掉；之後同一個鍵可能已經有新的工作，不能再刪一次
        std::mem::forget(guard);
    }

    /// 並行詢問一組上游：全部回來，或第一個正常回應後再等 window；
    /// `parallel` > 0 時先問前幾個，失敗或每隔 hedge 沒有正常回應再加問下一個
    async fn ask(&self, list: &[Arc<Up>], q: &[u8], qtype: u16, mut on_each: impl FnMut(&Answer)) -> Vec<Arc<Answer>> {
        let mut out = Vec::new();
        if list.is_empty() {
            return out;
        }
        let p = &self.params;
        let first = if p.parallel == 0 { list.len() } else { p.parallel.min(list.len()) };
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
        let spawn = |set: &mut JoinSet<_>, up: Arc<Up>| {
            let q = q.to_vec();
            let t = p.timeout;
            set.spawn(async move {
                let t0 = Instant::now();
                let r = up.up.exchange(&q, t).await;
                (up, r, t0.elapsed().as_secs_f64() * 1000.0)
            });
        };
        for u in list.iter().take(first) {
            spawn(&mut set, u.clone());
        }
        let mut rest = list.iter().skip(first).cloned();
        let hard = tokio::time::sleep(p.timeout + Duration::from_millis(100));
        tokio::pin!(hard);
        let mut window: Option<std::pin::Pin<Box<tokio::time::Sleep>>> = None;
        let mut hedge = Box::pin(tokio::time::sleep(p.hedge));
        let mut got_ok = false;
        loop {
            tokio::select! {
                r = set.join_next() => {
                    let (up, r, ms) = match r {
                        Some(Ok(x)) => x,
                        // 某個上游的工作 panic：當成那個上游失敗，其他的照常等
                        Some(Err(_)) => {
                            if let Some(u) = rest.next() { spawn(&mut set, u); }
                            continue;
                        }
                        None => break,
                    };
                    match r.ok().and_then(|b| Message::parse(&b).ok()) {
                        Some(msg) => {
                            let class = logic::classify(&msg, qtype);
                            up.record(class != Class::Error && class != Class::ServFail, ms);
                            let a = Arc::new(Answer { up, msg, class, ms });
                            on_each(&a);
                            if a.class == Class::Ok && window.is_none() {
                                got_ok = true;
                                window = Some(Box::pin(tokio::time::sleep(p.window)));
                            }
                            if a.class != Class::Ok {
                                if let Some(u) = rest.next() { spawn(&mut set, u); }
                            }
                            out.push(a);
                        }
                        None => {
                            up.record(false, ms);
                            if let Some(u) = rest.next() { spawn(&mut set, u); }
                        }
                    }
                }
                _ = async { window.as_mut().unwrap().await }, if window.is_some() => break,
                _ = &mut hedge, if !got_ok && rest.len() > 0 => {
                    if let Some(u) = rest.next() { spawn(&mut set, u); }
                    hedge = Box::pin(tokio::time::sleep(p.hedge));
                }
                _ = &mut hard => break,
            }
        }
        set.abort_all();
        out
    }

    /// 合併所有上游給的 IP（最終 CNAME 相同的才合併），TCP 443 測速後排序
    async fn merge_rank(&self, oks: &[Arc<Answer>], qname: &str, qtype: u16) -> Option<(Message, String, String)> {
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
        let ranked = self.iprank.rank(&all).await;
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
    ) -> Arc<Entry> {
        let p = &self.params;
        let qtype = Cache::key_qtype(key);
        let mut blocked = None;
        if class == Class::Ok {
            let me = self.filter_check(qname, qtype);
            if !me.map(|v| v.allow).unwrap_or(false) {
                for t in logic::cname_targets(msg) {
                    if let Some(v) = self.filter_check(&t, qtype) {
                        if v.block {
                            blocked = Some(v.category);
                            break;
                        }
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
        e.baseline = baseline;
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

/// 從多個上游結果決定答案（同 2.x）：有正常回應取最快的；否則 nodata / nxdomain 多數決（平手以固定上游為準）
fn decide(results: &[Arc<Answer>], accept_blocked: bool, cdn: Option<&kuroshio_cdn::Cdn>, qtype: u16) -> Option<Decided> {
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
        });
    }
    if accept_blocked {
        if let Some(b) = by(Class::Blocked).first() {
            return Some(Decided {
                msg: b.msg.clone(),
                class: Class::Ok,
                source: format!("{}(上游已擋)", b.up.up.id),
                oks: vec![],
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
