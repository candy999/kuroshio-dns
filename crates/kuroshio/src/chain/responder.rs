//! 上游回應器：回答 `chain.kuroshio` 底下的 CH TXT 查詢（規格 1.9、3.3、4.2）
//!
//! - 只有 `resolver.rs::handle_inner` 呼叫：CH 類別、名稱在 `chain.kuroshio` 區域裡的查詢一律交給這裡，
//!   不論結果都不往下走（不過濾、不快取、不轉給上游）
//! - 3.4.0 的 WP3 只回答 auth（挑戰／回應）；reg、manifest、分段先回 `REFUSED`（WP5、WP6 接上）
//! - `allow_downstream` 關著時照樣簽章回答 auth（`allow = false`、`caps` 是空的），並記下有下游來問過（`probes`）
//! - 速率限制（簽章要花 CPU）：每個來源每秒 4 次、可累積 8 次；全部來源合計每秒 32 次、可累積 64 次；
//!   來源表最多 64 筆，滿了丟最久沒更新的

use super::ident::NodeKey;
use crate::resolver::Ctx;
use kuroshio_community::chain::{parse_name, seal, token, token_ok, txt_rdata, AuthBody, Name, PROTO, TOKEN_WINDOW_MS};
use kuroshio_community::envelope::to_cbor;
use kuroshio_community::util::{now_ms, random_bytes};
use kuroshio_proto::message::{Message, RData, Record};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// 每個來源每秒補幾次
const PER_SOURCE_RATE: f64 = 4.0;
/// 每個來源最多累積幾次
const PER_SOURCE_BURST: f64 = 8.0;
/// 全部來源合計每秒補幾次
const GLOBAL_RATE: f64 = 32.0;
/// 全部來源合計最多累積幾次
const GLOBAL_BURST: f64 = 64.0;
/// 速率限制表最多記幾個來源
pub const MAX_SOURCES: usize = 64;

/// `allow_downstream` 開著時公告的能力。WP3 還沒有共用結果與登記，所以是空的；
/// WP5（`share`）、WP6（`reg`）接上之後加進來（沒有的能力下游不會去問）
const CAPS: &[&str] = &[];

const RCODE_SERVFAIL: u16 = 2;
const RCODE_REFUSED: u16 = 5;

/// 權杖桶：每個來源一個，再加一個全域的
struct Limiter {
    sources: HashMap<IpAddr, (f64, Instant)>,
    global: (f64, Instant),
}

fn refill(b: &mut (f64, Instant), rate: f64, burst: f64, now: Instant) {
    let dt = now.saturating_duration_since(b.1).as_secs_f64();
    b.0 = (b.0 + dt * rate).min(burst);
    b.1 = now;
}

impl Limiter {
    fn new() -> Limiter {
        Limiter {
            sources: HashMap::new(),
            global: (GLOBAL_BURST, Instant::now()),
        }
    }

    /// 這個來源現在可不可以再回答一次（可以就扣掉一次）
    fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        if !self.sources.contains_key(&ip) && self.sources.len() >= MAX_SOURCES {
            // 表滿了：丟掉最久沒更新的一筆
            if let Some(oldest) = self.sources.iter().min_by_key(|(_, b)| b.1).map(|(k, _)| *k) {
                self.sources.remove(&oldest);
            }
        }
        refill(&mut self.global, GLOBAL_RATE, GLOBAL_BURST, now);
        let src = self.sources.entry(ip).or_insert((PER_SOURCE_BURST, now));
        refill(src, PER_SOURCE_RATE, PER_SOURCE_BURST, now);
        if src.0 < 1.0 || self.global.0 < 1.0 {
            return false;
        }
        src.0 -= 1.0;
        self.global.0 -= 1.0;
        true
    }
}

/// `allow_downstream` 關著時收到的 auth 挑戰：每小時一格、24 格（固定大小），加上最後一次的時間
#[derive(Default)]
struct Probes {
    /// (小時編號, 次數)
    hours: [(u64, u32); 24],
    last: Option<u64>,
}

const HOUR_MS: u64 = 3_600_000;

impl Probes {
    fn record(&mut self, now: u64) {
        let h = now / HOUR_MS;
        let slot = &mut self.hours[(h % 24) as usize];
        if slot.0 != h {
            *slot = (h, 0);
        }
        slot.1 = slot.1.saturating_add(1);
        self.last = Some(now);
    }

    fn count24h(&self, now: u64) -> u64 {
        let h = now / HOUR_MS;
        self.hours
            .iter()
            .filter(|(at, n)| *n > 0 && *at <= h && h - *at < 24)
            .map(|(_, n)| u64::from(*n))
            .sum()
    }

    /// 24 小時內最後一次的時間
    fn last_within_24h(&self, now: u64) -> Option<u64> {
        self.last.filter(|t| now.saturating_sub(*t) < 24 * HOUR_MS)
    }
}

/// 「多久以前」的白話
fn ago(now: u64, at: u64) -> String {
    let m = now.saturating_sub(at) / 60_000;
    match m {
        0 => "剛剛".into(),
        1..=59 => format!("{m} 分鐘前"),
        _ => format!("{} 小時前", m / 60),
    }
}

/// 上游回應器
pub struct Responder {
    allow_downstream: bool,
    key: Arc<NodeKey>,
    /// 登記憑據（`tok`）用的密鑰：啟動時產生，不寫檔
    secret: [u8; 32],
    limiter: Mutex<Limiter>,
    /// 自己串接中的上游的鏈（沒串接是 None）
    upstream_path: Mutex<Option<Vec<Vec<u8>>>>,
    probes: Mutex<Probes>,
    refused_rate: AtomicU64,
    refused_not_private: AtomicU64,
    refused_not_allowed: AtomicU64,
    /// 讀不到金鑰的警告只記一次
    key_warned: AtomicBool,
    /// 有沒有啟用「繞過防護」清單（WP6 設定；目前只記著，不影響回答）
    bypass_list_active: AtomicBool,
}

impl Responder {
    pub fn new(settings: &kuroshio_config::chain::ChainSettings, key: Arc<NodeKey>) -> Arc<Responder> {
        Arc::new(Responder {
            allow_downstream: settings.allow_downstream,
            key,
            secret: random_bytes::<32>(),
            limiter: Mutex::new(Limiter::new()),
            upstream_path: Mutex::new(None),
            probes: Mutex::new(Probes::default()),
            refused_rate: AtomicU64::new(0),
            refused_not_private: AtomicU64::new(0),
            refused_not_allowed: AtomicU64::new(0),
            key_warned: AtomicBool::new(false),
            bypass_list_active: AtomicBool::new(false),
        })
    }

    /// qname 在 chain.kuroshio 區域裡時呼叫；一定回一個回應（成功或 REFUSED / SERVFAIL）
    ///
    /// 呼叫端（`handle_inner`）已經確認 `proto` 是 udp／tcp、來源是私有位址。
    pub fn answer(&self, query: &Message, qname: &str, ctx: &Ctx) -> Message {
        let Some(q) = query.questions.first() else {
            return Message::response_to(query, RCODE_REFUSED);
        };
        match parse_name(qname) {
            Some(Name::Auth(nonce)) => self.auth(query, q.qtype, &nonce, ctx),
            Some(Name::Reg | Name::Manifest | Name::Chunk { .. }) => {
                if !self.allow_downstream {
                    self.refused_not_allowed.fetch_add(1, Ordering::Relaxed);
                }
                Message::response_to(query, RCODE_REFUSED)
            }
            None => Message::response_to(query, RCODE_REFUSED),
        }
    }

    /// 不是區網的一般 DNS（公開的加密監聽、公網來源）：一律 REFUSED，不透露節點資訊
    pub fn refuse_not_private(&self, query: &Message) -> Message {
        self.refused_not_private.fetch_add(1, Ordering::Relaxed);
        Message::response_to(query, RCODE_REFUSED)
    }

    fn auth(&self, query: &Message, qtype: u16, nonce: &[u8; 16], ctx: &Ctx) -> Message {
        if qtype != 16 && qtype != 255 {
            return Message::response_to(query, 0);
        }
        let now = now_ms();
        if !self.allow_downstream {
            self.probes.lock().unwrap().record(now);
        }
        let ip = ctx.client.to_canonical();
        if !self.rate_ok(ip) {
            return Message::response_to(query, RCODE_REFUSED);
        }
        let key = match self.key.get() {
            Ok(k) => k,
            Err(e) => {
                if !self.key_warned.swap(true, Ordering::Relaxed) {
                    tracing::warn!(
                        "串接：讀不到也建立不了節點金鑰（{}），下游黑潮的驗證會失敗：{e:#}",
                        self.key.dir().display()
                    );
                }
                return Message::response_to(query, RCODE_SERVFAIL);
            }
        };
        let peer = ip.to_string();
        let path = {
            let up = self.upstream_path.lock().unwrap();
            kuroshio_community::chain::own_path(up.as_deref(), &key.kid)
        };
        let body = AuthBody {
            v: PROTO,
            t: "auth".into(),
            nonce: nonce.to_vec(),
            ts: now,
            kid: key.kid.to_vec(),
            public: key.public.to_vec(),
            app: env!("CARGO_PKG_VERSION").into(),
            allow: self.allow_downstream,
            caps: self.caps().into_iter().map(String::from).collect(),
            tok: token(&self.secret, &peer, now / TOKEN_WINDOW_MS).to_vec(),
            peer,
            path,
        };
        let sealed = seal(&key, "auth", to_cbor(&body));
        let mut r = Message::response_to(query, 0);
        r.answers.push(Record {
            name: query.questions[0].name.clone(),
            rtype: 16,
            class: 3,
            ttl: 0,
            data: RData::Raw(txt_rdata(&sealed)),
        });
        r
    }

    /// 下游狀態機（WP4）在綁定、解除時設定：自己串接中的上游的鏈
    pub fn set_upstream_path(&self, path: Option<Vec<Vec<u8>>>) {
        *self.upstream_path.lock().unwrap() = path;
    }

    /// 公告的能力（`allow_downstream` 關著是空的）
    pub fn caps(&self) -> Vec<&'static str> {
        if self.allow_downstream {
            CAPS.to_vec()
        } else {
            Vec::new()
        }
    }

    /// `upstream.allowDownstream`
    pub fn allow_downstream(&self) -> bool {
        self.allow_downstream
    }

    /// 節點金鑰（WP4 的防迴圈要用 `own_kids`）
    pub fn node_key(&self) -> &Arc<NodeKey> {
        &self.key
    }

    /// 登記（WP6）：`tok` 對這個來源在目前或前一個時間窗有效
    pub fn token_ok(&self, peer: &str, tok: &[u8]) -> bool {
        token_ok(&self.secret, peer, now_ms(), tok)
    }

    /// 速率限制：這個來源現在可不可以再回答一次需要簽章的查詢（可以就扣掉一次；WP5 的清單也要用）
    pub fn rate_ok(&self, ip: IpAddr) -> bool {
        let ok = self.limiter.lock().unwrap().allow(ip.to_canonical(), Instant::now());
        if !ok {
            self.refused_rate.fetch_add(1, Ordering::Relaxed);
        }
        ok
    }

    /// 速率限制表目前記了幾個來源（上限 [`MAX_SOURCES`]）
    pub fn rate_table_len(&self) -> usize {
        self.limiter.lock().unwrap().sources.len()
    }

    /// 有沒有啟用「繞過防護」清單（WP6 用）
    pub fn set_bypass_list_active(&self, on: bool) {
        self.bypass_list_active.store(on, Ordering::Relaxed);
    }

    pub fn bypass_list_active(&self) -> bool {
        self.bypass_list_active.load(Ordering::Relaxed)
    }

    /// `/api/status` 的 `chain.serving`（一定是完整的物件；WP5、WP6 之後會加欄位）
    pub fn serving_json(&self) -> Value {
        let now = now_ms();
        let (count24h, last) = {
            let p = self.probes.lock().unwrap();
            (p.count24h(now), p.last_within_24h(now))
        };
        let (text, note) = if self.allow_downstream {
            (
                "提供資料給下游黑潮：目前沒有下游連上來".to_string(),
                json!("區網裡任何會講這個協定的裝置都拿得到資料與放行；有啟用「繞過防護」清單時建議關閉 allow_downstream"),
            )
        } else {
            let mut t =
                "不提供資料給下游（allow_downstream 關閉）：下游黑潮會自己重做評測、CDN 掃描、下載清單，重複使用網路（含這台的頻寬）"
                    .to_string();
            if let Some(at) = last {
                t.push_str(&format!("；最近有下游黑潮來問過（{}）", ago(now, at)));
            }
            (t, Value::Null)
        };
        json!({
            "allowDownstream": self.allow_downstream,
            "text": text,
            "note": note,
            "nodeId": self.key.node_id(),
            "fingerprint": self.key.fingerprint(),
            "downstreams": [],
            "share": { "requests": 0, "lastAt": null, "cacheBytes": 0 },
            "probes": { "count24h": count24h, "lastAt": last },
            "refused": {
                "rate": self.refused_rate.load(Ordering::Relaxed),
                "notPrivate": self.refused_not_private.load(Ordering::Relaxed),
                "notAllowed": self.refused_not_allowed.load(Ordering::Relaxed),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn limiter_per_source_and_global() {
        let mut l = Limiter::new();
        let t = Instant::now();
        let a: IpAddr = "192.168.1.2".parse().unwrap();
        assert_eq!((0..20).filter(|_| l.allow(a, t)).count(), 8);
        // 1 秒後補 4 次
        let t1 = t + Duration::from_secs(1);
        assert_eq!((0..20).filter(|_| l.allow(a, t1)).count(), 4);
        // 全域：64 次用完之後其他來源也不行
        let mut g = Limiter::new();
        let mut ok = 0;
        for i in 0..40u8 {
            let ip = IpAddr::from([10, 0, 0, i]);
            ok += (0..8).filter(|_| g.allow(ip, t)).count();
        }
        assert_eq!(ok, 64);
        assert!(g.sources.len() <= MAX_SOURCES);
    }

    #[test]
    fn probes_window() {
        let mut p = Probes::default();
        let t = 100 * HOUR_MS;
        p.record(t);
        p.record(t + 1);
        assert_eq!(p.count24h(t + 2), 2);
        assert_eq!(p.count24h(t + 25 * HOUR_MS), 0);
        assert_eq!(p.last_within_24h(t + 25 * HOUR_MS), None);
        assert_eq!(ago(t + 3 * 60_000, t), "3 分鐘前");
    }
}
