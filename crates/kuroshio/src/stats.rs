//! 統計（只在記憶體，規格 05 第 5.2 節：可重建資料不寫 Flash）
//!
//! - 每日計數保留 31 天（公開頁的今天 / 7 天 / 30 天統計用）
//! - 最近 90 分鐘的每分鐘計數（公開頁「最近 60 分鐘」）
//! - 熱門網域、被擋網域、用戶端（詳細頁用，從啟動起累計）
//! - 匿名網站排行（公開頁用，同 2.x `stats.js`）：
//!   - 只存「主網域」（`www.video.example`、`rr3---sn-x.videocdn.example` → `video.example`、`videocdn.example`）
//!   - 不存任何 IP；不同用戶只以「每天更換鹽值的雜湊」計算人數，雜湊不寫出去
//!   - 排行只列出「至少 N 個不同用戶」查過的網站（k-匿名）
//!
//! 想跨重開機保留每日統計時，外層把 [`Stats::snapshot`] 交給快照寫入器，啟動時呼叫 [`Stats::restore`]；
//! 本模組自己不寫檔。
//!
//! 32 位元 MIPS 沒有 64 位元原子操作：所有計數都放在 `Mutex` 裡。

use serde_json::{json, Map, Value};
use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::hash::BuildHasher;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// 回應時間直方圖的區間上限（毫秒）
const BUCKETS: [f64; 12] = [0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 500.0, 1000.0, f64::INFINITY];

/// 每日計數保留幾天（含今天）
pub const RETENTION_DAYS: usize = 31;
/// 每分鐘計數保留幾分鐘
const MINUTES_KEPT: u32 = 90;
/// 每個網站最多記幾個不同用戶的雜湊（只用來判斷是否達到 k-匿名門檻）
const ANON_CLIENTS: usize = 32;
/// 過去的每一天保留前幾名網站
const DAY_SITES_KEPT: usize = 300;
/// 快照格式版本
const SNAPSHOT_VERSION: u64 = 1;

#[derive(Debug, Default, Clone)]
pub struct Histogram {
    counts: [u64; 12],
}

impl Histogram {
    pub fn record(&mut self, ms: f64) {
        let i = BUCKETS.iter().position(|b| ms <= *b).unwrap_or(BUCKETS.len() - 1);
        self.counts[i] += 1;
    }
    pub fn n(&self) -> u64 {
        self.counts.iter().sum()
    }
    /// 百分位數（回傳該區間的上限；最後一區回 null）
    pub fn percentile(&self, p: f64) -> Option<f64> {
        let n = self.n();
        if n == 0 {
            return None;
        }
        let target = (n as f64 * p).ceil().max(1.0) as u64;
        let mut acc = 0;
        for (i, c) in self.counts.iter().enumerate() {
            acc += c;
            if acc >= target {
                return BUCKETS[i].is_finite().then_some(BUCKETS[i]);
            }
        }
        None
    }
    fn json(&self) -> Value {
        json!({ "n": self.n(), "p50": self.percentile(0.5), "p95": self.percentile(0.95) })
    }
    fn from_json(v: Option<&Value>) -> Histogram {
        let mut h = Histogram::default();
        if let Some(a) = v.and_then(Value::as_array) {
            for (i, c) in a.iter().take(12).enumerate() {
                h.counts[i] = c.as_u64().unwrap_or(0);
            }
        }
        h
    }
}

/// 匿名排行的一筆：（網站, 查詢次數, 不同用戶數）
type SiteRow = (String, u64, u32);

#[derive(Debug, Default, Clone)]
struct Day {
    date: String,
    query: u64,
    hit: u64,
    miss: u64,
    blocked: u64,
    blocked_ads: u64,
    blocked_telemetry: u64,
    blocked_malware: u64,
    blocked_custom: u64,
    servfail: u64,
    local: u64,
    stale: u64,
    prefetch: u64,
    lat_hit: Histogram,
    lat_miss: Histogram,
    cdn_served: u64,
    cdn_rewrite: u64,
    ecs_rewrite: u64,
    cross_rewrite: u64,
    cdn: BTreeMap<String, u64>,
    cross: BTreeMap<String, u64>,
    route: BTreeMap<String, RouteStat>,
    /// 匿名網站排行（過去的日子；今天的在 `Inner::sites`）
    sites: Vec<SiteRow>,
    blocked_sites: Vec<SiteRow>,
}

/// 機會成本：一般 DNS 會不會出國、我們有沒有拉回台灣（同 2.x `stats.route`）
#[derive(Debug, Default, Clone)]
struct RouteStat {
    n: u64,
    abroad: u64,
    acc: u64,
    miss: u64,
    saved: f64,
    saved_n: u64,
}

/// 一分鐘的即時計數
#[derive(Debug, Default, Clone, Copy)]
struct Minute {
    /// Unix 分鐘
    m: u32,
    q: u32,
    b: u32,
    acc: u32,
}

/// 今天某個網站的匿名計數
#[derive(Debug, Default)]
struct Anon {
    n: u64,
    /// 不同用戶的鹽值雜湊（最多 `ANON_CLIENTS` 個）
    c: Vec<u32>,
    /// 重新啟動前已知的人數（無法還原雜湊，當作下限）
    base: u32,
}

/// 記憶體上限（小記憶體機器可以調低）
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// 熱門網域 / 被擋網域 / 用戶端各自最多幾筆（超過就只留前 1/4）
    pub top_max: usize,
    /// 今天的匿名網站排行最多幾個網站（超過就不再加新網站）
    pub anon_sites: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            top_max: 20_000,
            anon_sites: 20_000,
        }
    }
}

impl Limits {
    /// 小記憶體（Tiny 等級）用的上限
    pub fn tiny() -> Limits {
        Limits {
            top_max: 2_000,
            anon_sites: 2_000,
        }
    }
}

struct Inner {
    day: Day,
    /// `day` 是哪一天（台北時間的日序；每次查詢只比對數字，換日才產生日期字串）
    day_no: u64,
    /// 過去的日子（舊的在前）
    history: VecDeque<Day>,
    minutes: VecDeque<Minute>,
    top_domains: HashMap<Box<str>, u64>,
    top_blocked: HashMap<Box<str>, u64>,
    top_clients: HashMap<IpAddr, u64>,
    salt: RandomState,
    sites: HashMap<Box<str>, Anon>,
    blocked_sites: HashMap<Box<str>, Anon>,
    limits: Limits,
    /// 記憶體控制縮小排行之前的上限（恢復用）
    saved_top_max: Option<usize>,
}

impl Default for Inner {
    fn default() -> Self {
        Inner {
            day: Day::default(),
            day_no: u64::MAX,
            history: VecDeque::new(),
            minutes: VecDeque::new(),
            top_domains: HashMap::new(),
            top_blocked: HashMap::new(),
            top_clients: HashMap::new(),
            salt: RandomState::new(),
            sites: HashMap::new(),
            blocked_sites: HashMap::new(),
            limits: Limits::default(),
            saved_top_max: None,
        }
    }
}

pub struct Stats {
    started: Instant,
    inner: Mutex<Inner>,
}

/// 由 1970-01-01 起算的日數轉成年月日（Howard Hinnant 的演算法）
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// 台北日期（固定 UTC+8，OpenWrt 的執行環境不一定有時區資料）
pub fn taipei_date(unix: u64) -> String {
    let (y, m, d) = civil(((unix + 8 * 3600) / 86400) as i64);
    format!("{y:04}-{m:02}-{d:02}")
}

/// ISO 8601 UTC 時間（同 JS `new Date(ms).toISOString()`）
pub fn iso_utc(ms: u64) -> String {
    let secs = ms / 1000;
    let (y, m, d) = civil((secs / 86400) as i64);
    let t = secs % 86400;
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        t / 3600,
        t / 60 % 60,
        t % 60,
        ms % 1000
    )
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// 常見的多層公共尾碼（不需要完整 Public Suffix List 也能處理大部分台灣 / 亞洲網站，同 2.x）
const MULTI_SUFFIX: &[&str] = &[
    "com.tw",
    "net.tw",
    "org.tw",
    "edu.tw",
    "gov.tw",
    "idv.tw",
    "game.tw",
    "ebiz.tw",
    "club.tw",
    "com.hk",
    "net.hk",
    "org.hk",
    "edu.hk",
    "gov.hk",
    "com.cn",
    "net.cn",
    "org.cn",
    "gov.cn",
    "edu.cn",
    "co.jp",
    "ne.jp",
    "or.jp",
    "ac.jp",
    "go.jp",
    "co.kr",
    "or.kr",
    "ne.kr",
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "com.au",
    "net.au",
    "org.au",
    "com.sg",
    "com.my",
    "com.ph",
    "co.th",
    "in.th",
    "com.vn",
    "co.id",
    "co.in",
    "com.br",
    "com.mx",
    "co.nz",
    "com.tr",
    "github.io",
    "herokuapp.com",
    "blogspot.com",
    "cloudfront.net",
    "azurewebsites.net",
    "appspot.com",
    "pages.dev",
    "workers.dev",
    "vercel.app",
    "netlify.app",
    "web.app",
    "firebaseapp.com",
];

fn is_ipv4_literal(n: &str) -> bool {
    let parts: Vec<&str> = n.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// 網域 → 主網域（`www.video.example` → `video.example`、`www.shop.example.com.tw` → `example.com.tw`）；
/// IP、反查、區網名稱回 None（同 2.x `siteOf`）
pub fn site_of(name: &str) -> Option<String> {
    let n = name.trim_end_matches('.');
    if n.bytes().any(|b| b.is_ascii_uppercase()) {
        return site_slice(&n.to_ascii_lowercase()).map(str::to_string);
    }
    site_slice(n).map(str::to_string)
}

/// [`site_of`] 的本體：`n` 已經是小寫、結尾沒有點；回傳的是 `n` 的一段（每次查詢都會呼叫，不配置記憶體）
fn site_slice(n: &str) -> Option<&str> {
    if n.is_empty() || !n.contains('.') || is_ipv4_literal(n) {
        return None;
    }
    if [".arpa", ".local", ".lan", ".home", ".internal"].iter().any(|s| n.ends_with(s)) {
        return None;
    }
    // 從右邊數第 k 個點之後的部分（沒有那麼多層就是整個名稱）
    let tail = |k: usize| n.rmatch_indices('.').nth(k - 1).map_or(n, |(i, _)| &n[i + 1..]);
    let last2 = tail(2);
    if MULTI_SUFFIX.contains(&last2) {
        return Some(tail(3));
    }
    Some(last2)
}

#[derive(Debug, Clone, Copy)]
pub enum Kind {
    Query,
    Hit,
    Miss,
    ServFail,
    Local,
    /// 回了過期的舊資料
    Stale,
    /// 背景預取（自適應預取、開機預熱）
    Prefetch,
}

impl Default for Stats {
    fn default() -> Self {
        Stats {
            started: Instant::now(),
            inner: Mutex::new(Inner::default()),
        }
    }
}

fn bump(map: &mut HashMap<Box<str>, u64>, k: &str, max: usize) {
    if let Some(v) = map.get_mut(k) {
        *v += 1;
        return;
    }
    map.insert(k.into(), 1);
    if map.len() > max {
        trim(map, max / 4);
    }
}

/// 只留次數最多的 `keep` 筆
fn trim<K: Clone + Eq + std::hash::Hash>(map: &mut HashMap<K, u64>, keep: usize) {
    let mut v: Vec<(K, u64)> = map.drain().collect();
    v.sort_by_key(|x| std::cmp::Reverse(x.1));
    v.truncate(keep.max(1));
    map.extend(v);
}

fn top_n<K: ToString + Ord>(map: &HashMap<K, u64>, n: usize) -> Value {
    let mut v: Vec<(&K, &u64)> = map.iter().collect();
    v.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    Value::Array(
        v.into_iter()
            .take(n)
            .map(|(k, c)| json!({ "name": k.to_string(), "count": c }))
            .collect(),
    )
}

/// 今天的匿名計數 → 每日紀錄（前 300 名）
fn dump(map: &HashMap<Box<str>, Anon>) -> Vec<SiteRow> {
    let mut v: Vec<SiteRow> = map
        .iter()
        .map(|(k, a)| (k.to_string(), a.n, a.base.max(a.c.len() as u32)))
        .collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v.truncate(DAY_SITES_KEPT);
    v
}

/// 每日紀錄 → 今天的匿名計數（人數無法還原，以已存值為下限）
fn undump(rows: &[SiteRow]) -> HashMap<Box<str>, Anon> {
    rows.iter()
        .map(|(k, n, c)| {
            (
                k.as_str().into(),
                Anon {
                    n: *n,
                    c: Vec::new(),
                    base: *c,
                },
            )
        })
        .collect()
}

fn rows_json(rows: &[SiteRow]) -> Value {
    Value::Object(rows.iter().map(|(k, n, c)| (k.clone(), json!([n, c]))).collect())
}

fn rows_from_json(v: Option<&Value>) -> Vec<SiteRow> {
    let mut out: Vec<SiteRow> = v
        .and_then(Value::as_object)
        .map(|o| {
            o.iter()
                .filter_map(|(k, v)| {
                    let a = v.as_array()?;
                    Some((k.clone(), a.first()?.as_u64()?, a.get(1)?.as_u64()? as u32))
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    out.truncate(DAY_SITES_KEPT);
    out
}

impl Day {
    /// 對齊 2.x 每日紀錄的欄位（不含網站排行）
    fn json(&self) -> Value {
        let d = self;
        json!({
            "date": d.date, "query": d.query, "hit": d.hit, "miss": d.miss, "servfail": d.servfail, "local": d.local,
            "blocked": d.blocked, "blockedAds": d.blocked_ads, "blockedTelemetry": d.blocked_telemetry,
            "blockedMalware": d.blocked_malware, "blockedCustom": d.blocked_custom,
            "cdnServed": d.cdn_served, "cdnRewrite": d.cdn_rewrite, "ecsRewrite": d.ecs_rewrite, "crossRewrite": d.cross_rewrite,
            "cdn": d.cdn, "cross": d.cross,
            "route": d.route_json(),
            "stale": d.stale, "prefetch": d.prefetch,
            "hitRate": if d.hit + d.miss > 0 { json!((d.hit as f64 * 1000.0 / (d.hit + d.miss) as f64).round() / 10.0) } else { Value::Null },
            "latency": { "hit": d.lat_hit.json(), "miss": d.lat_miss.json() }
        })
    }

    fn route_json(&self) -> Value {
        Value::Object(
            self.route
                .iter()
                .map(|(k, r)| {
                    (
                        k.clone(),
                        json!({ "n": r.n, "abroad": r.abroad, "acc": r.acc, "miss": r.miss, "saved": r.saved.round(), "savedN": r.saved_n }),
                    )
                })
                .collect::<Map<_, _>>(),
        )
    }

    /// 快照用（每日計數 + 回應時間直方圖 + 網站排行）
    fn snapshot_json(&self, sites: &[SiteRow], blocked: &[SiteRow]) -> Value {
        let mut v = self.json();
        let o = v.as_object_mut().expect("object");
        o.remove("hitRate");
        o.remove("latency");
        o.insert("latHit".into(), json!(self.lat_hit.counts));
        o.insert("latMiss".into(), json!(self.lat_miss.counts));
        o.insert("sites".into(), rows_json(sites));
        o.insert("blockedSites".into(), rows_json(blocked));
        v
    }

    fn from_json(v: &Value) -> Option<Day> {
        let date = v.get("date")?.as_str()?.to_string();
        if date.len() != 10 {
            return None;
        }
        let n = |k: &str| v.get(k).and_then(Value::as_u64).unwrap_or(0);
        let map = |k: &str| -> BTreeMap<String, u64> {
            v.get(k)
                .and_then(Value::as_object)
                .map(|o| o.iter().filter_map(|(k, v)| Some((k.clone(), v.as_u64()?))).collect())
                .unwrap_or_default()
        };
        let route = v
            .get("route")
            .and_then(Value::as_object)
            .map(|o| {
                o.iter()
                    .map(|(k, r)| {
                        let g = |f: &str| r.get(f).and_then(Value::as_u64).unwrap_or(0);
                        (
                            k.clone(),
                            RouteStat {
                                n: g("n"),
                                abroad: g("abroad"),
                                acc: g("acc"),
                                miss: g("miss"),
                                saved: r.get("saved").and_then(Value::as_f64).unwrap_or(0.0),
                                saved_n: g("savedN"),
                            },
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        Some(Day {
            date,
            query: n("query"),
            hit: n("hit"),
            miss: n("miss"),
            blocked: n("blocked"),
            blocked_ads: n("blockedAds"),
            blocked_telemetry: n("blockedTelemetry"),
            blocked_malware: n("blockedMalware"),
            blocked_custom: n("blockedCustom"),
            servfail: n("servfail"),
            local: n("local"),
            stale: n("stale"),
            prefetch: n("prefetch"),
            lat_hit: Histogram::from_json(v.get("latHit")),
            lat_miss: Histogram::from_json(v.get("latMiss")),
            cdn_served: n("cdnServed"),
            cdn_rewrite: n("cdnRewrite"),
            ecs_rewrite: n("ecsRewrite"),
            cross_rewrite: n("crossRewrite"),
            cdn: map("cdn"),
            cross: map("cross"),
            route,
            sites: rows_from_json(v.get("sites")),
            blocked_sites: rows_from_json(v.get("blockedSites")),
        })
    }

    /// 把另一天的計數加進來（還原快照時，今天已經有計數的話合併）
    fn add(&mut self, o: &Day) {
        self.query += o.query;
        self.hit += o.hit;
        self.miss += o.miss;
        self.blocked += o.blocked;
        self.blocked_ads += o.blocked_ads;
        self.blocked_telemetry += o.blocked_telemetry;
        self.blocked_malware += o.blocked_malware;
        self.blocked_custom += o.blocked_custom;
        self.servfail += o.servfail;
        self.local += o.local;
        self.stale += o.stale;
        self.prefetch += o.prefetch;
        for i in 0..12 {
            self.lat_hit.counts[i] += o.lat_hit.counts[i];
            self.lat_miss.counts[i] += o.lat_miss.counts[i];
        }
        self.cdn_served += o.cdn_served;
        self.cdn_rewrite += o.cdn_rewrite;
        self.ecs_rewrite += o.ecs_rewrite;
        self.cross_rewrite += o.cross_rewrite;
        for (k, v) in &o.cdn {
            *self.cdn.entry(k.clone()).or_default() += v;
        }
        for (k, v) in &o.cross {
            *self.cross.entry(k.clone()).or_default() += v;
        }
        for (k, r) in &o.route {
            let e = self.route.entry(k.clone()).or_default();
            e.n += r.n;
            e.abroad += r.abroad;
            e.acc += r.acc;
            e.miss += r.miss;
            e.saved += r.saved;
            e.saved_n += r.saved_n;
        }
    }
}

impl Inner {
    /// 換日：今天的紀錄（含匿名排行）移到歷史，鹽值換新
    fn roll(&mut self, date: &str) {
        if self.day.date == date {
            return;
        }
        let mut old = std::mem::take(&mut self.day);
        if !old.date.is_empty() {
            old.sites = dump(&self.sites);
            old.blocked_sites = dump(&self.blocked_sites);
            self.history.push_back(old);
        }
        // 時鐘倒退又回來：沿用那一天已有的紀錄
        let day = match self.history.iter().position(|d| d.date == date) {
            Some(i) => self.history.remove(i).unwrap_or_default(),
            None => Day {
                date: date.to_string(),
                ..Day::default()
            },
        };
        self.sites = undump(&day.sites);
        self.blocked_sites = undump(&day.blocked_sites);
        self.day = Day {
            sites: Vec::new(),
            blocked_sites: Vec::new(),
            ..day
        };
        self.salt = RandomState::new();
        self.trim_history();
    }

    fn trim_history(&mut self) {
        self.history.make_contiguous().sort_by(|a, b| a.date.cmp(&b.date));
        while self.history.len() + 1 > RETENTION_DAYS {
            self.history.pop_front();
        }
    }

    fn minute(&mut self, now_min: u32) -> &mut Minute {
        if self.minutes.back().map(|m| m.m) != Some(now_min) {
            self.minutes.push_back(Minute {
                m: now_min,
                ..Minute::default()
            });
            while self.minutes.front().is_some_and(|m| m.m + MINUTES_KEPT < now_min) {
                self.minutes.pop_front();
            }
        }
        self.minutes.back_mut().expect("剛加入")
    }

    fn query_name(&mut self, name: &str, client: IpAddr) {
        let max = self.limits.top_max;
        bump(&mut self.top_domains, name, max);
        *self.top_clients.entry(client.to_canonical()).or_default() += 1;
        if self.top_clients.len() > max {
            trim(&mut self.top_clients, max / 4);
        }
    }

    fn anon(&mut self, blocked: bool, site: &str, client: IpAddr) {
        let h = self.salt.hash_one(client) as u32;
        let max = self.limits.anon_sites;
        let map = if blocked { &mut self.blocked_sites } else { &mut self.sites };
        let e = match map.get_mut(site) {
            Some(e) => e,
            None => {
                if map.len() >= max {
                    return;
                }
                map.entry(site.into()).or_default()
            }
        };
        e.n += 1;
        if e.c.len() < ANON_CLIENTS && !e.c.contains(&h) {
            e.c.push(h);
        }
    }

    /// 全部的日子（舊的在前），今天的匿名排行即時整理
    fn days(&self) -> Vec<(Day, Vec<SiteRow>, Vec<SiteRow>)> {
        let mut out: Vec<(Day, Vec<SiteRow>, Vec<SiteRow>)> = self
            .history
            .iter()
            .map(|d| (d.clone(), d.sites.clone(), d.blocked_sites.clone()))
            .collect();
        if !self.day.date.is_empty() {
            out.push((self.day.clone(), dump(&self.sites), dump(&self.blocked_sites)));
        }
        out
    }
}

impl Stats {
    fn with<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        let now = now_unix();
        let day_no = (now + 8 * 3600) / 86400;
        let mut g = self.inner.lock().unwrap();
        if g.day_no != day_no {
            g.roll(&taipei_date(now));
            g.day_no = day_no;
        }
        f(&mut g)
    }

    fn with_day<R>(&self, f: impl FnOnce(&mut Day) -> R) -> R {
        self.with(|i| f(&mut i.day))
    }

    fn now_min() -> u32 {
        (now_unix() / 60) as u32
    }

    /// 調整記憶體上限（小記憶體機器用 [`Limits::tiny`]）
    pub fn set_limits(&self, l: Limits) {
        self.inner.lock().unwrap().limits = l;
    }

    /// 記憶體控制（規格 09）：`Some(n)` = 熱門網域 / 被擋網域 / 用戶端排行只留前 n 名，之後也最多 n 筆
    /// （公開頁的匿名網站排行不動）；`None` = 恢復原本的上限（之後自然長回來）。回傳估計釋出的 bytes
    pub fn shed_tops(&self, keep: Option<usize>) -> usize {
        let mut g = self.inner.lock().unwrap();
        let i = &mut *g;
        match keep {
            Some(n) => {
                if i.saved_top_max.is_none() {
                    i.saved_top_max = Some(i.limits.top_max);
                }
                i.limits.top_max = n.max(4);
                let before = i.top_domains.len() + i.top_blocked.len() + i.top_clients.len();
                let name_bytes = |m: &HashMap<Box<str>, u64>| m.keys().map(|k| k.len()).sum::<usize>();
                let bytes_before = name_bytes(&i.top_domains) + name_bytes(&i.top_blocked);
                for m in [&mut i.top_domains, &mut i.top_blocked] {
                    if m.len() > n {
                        trim(m, n);
                    }
                    m.shrink_to_fit();
                }
                if i.top_clients.len() > n {
                    trim(&mut i.top_clients, n);
                }
                i.top_clients.shrink_to_fit();
                let after = i.top_domains.len() + i.top_blocked.len() + i.top_clients.len();
                let bytes_after = name_bytes(&i.top_domains) + name_bytes(&i.top_blocked);
                // 每筆：雜湊表一格（鍵 + 次數）約 48 bytes，加上名稱
                (before - after) * 48 + bytes_before.saturating_sub(bytes_after)
            }
            None => {
                if let Some(m) = i.saved_top_max.take() {
                    i.limits.top_max = m;
                }
                0
            }
        }
    }

    pub fn uptime_sec(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    pub fn count(&self, k: Kind) {
        self.with(|i| {
            let d = &mut i.day;
            match k {
                Kind::Query => d.query += 1,
                Kind::Hit => d.hit += 1,
                Kind::Miss => d.miss += 1,
                Kind::ServFail => d.servfail += 1,
                Kind::Local => d.local += 1,
                Kind::Stale => d.stale += 1,
                Kind::Prefetch => d.prefetch += 1,
            }
            if let Kind::Query = k {
                i.minute(Self::now_min()).q += 1;
            }
        })
    }

    /// 一次查詢：等於 `count(Kind::Query)` 加 [`Stats::query_name`]，只鎖一次、只看一次時鐘
    pub fn query(&self, name: &str, client: IpAddr) {
        self.with(|i| {
            i.day.query += 1;
            i.minute(Self::now_min()).q += 1;
            i.query_name(name, client);
        })
    }

    /// 快取命中的回應：等於 `count(Kind::Hit)` 加 `latency(true, ms)`，只鎖一次
    pub fn hit(&self, ms: f64) {
        self.with_day(|d| {
            d.hit += 1;
            d.lat_hit.record(ms);
        })
    }

    /// 回應時間（快取命中 / 問上游分開）
    pub fn latency(&self, hit: bool, ms: f64) {
        self.with_day(|d| if hit { d.lat_hit.record(ms) } else { d.lat_miss.record(ms) })
    }

    /// 攔截：分類 ads / telemetry / malware / custom
    pub fn blocked(&self, category: &str) {
        self.with(|i| {
            let d = &mut i.day;
            d.blocked += 1;
            match category {
                "telemetry" => d.blocked_telemetry += 1,
                "malware" => d.blocked_malware += 1,
                "custom" => d.blocked_custom += 1,
                _ => d.blocked_ads += 1,
            }
            i.minute(Self::now_min()).b += 1;
        })
    }

    /// 每次查詢（跟 `count(Kind::Query)` 同一個地方呼叫）：熱門網域、用戶端（詳細頁用）
    pub fn query_name(&self, name: &str, client: IpAddr) {
        self.with(|i| i.query_name(name, client))
    }

    /// 公開頁網站排行：只算 A 查詢（避免 A / AAAA / HTTPS 重複計算），沒被過濾擋下的才算（同 2.x `stats.site`）
    pub fn site(&self, name: &str, client: IpAddr) {
        let n = name.trim_end_matches('.');
        let lower;
        let n = if n.bytes().any(|b| b.is_ascii_uppercase()) {
            lower = n.to_ascii_lowercase();
            lower.as_str()
        } else {
            n
        };
        let Some(site) = site_slice(n) else { return };
        self.with(|i| i.anon(false, site, client.to_canonical()))
    }

    /// 攔截時的網域（跟 `blocked()` 同一個地方呼叫）：被擋排行；自訂規則擋的不進公開頁排行（同 2.x）
    pub fn blocked_name(&self, name: &str, client: IpAddr, category: &str) {
        let site = (category != "custom").then(|| site_of(name)).flatten();
        self.with(|i| {
            let max = i.limits.top_max;
            bump(&mut i.top_blocked, name, max);
            if let Some(s) = site {
                i.anon(true, &s, client.to_canonical());
            }
        })
    }

    /// 回應用到 CDN（`rewritten`：alias / ecs / cross）
    pub fn cdn(&self, provider: &str, rewritten: Option<&str>, cross_to: Option<&str>) {
        self.with(|i| {
            let d = &mut i.day;
            d.cdn_served += 1;
            *d.cdn.entry(provider.to_string()).or_default() += 1;
            match rewritten {
                Some("alias") => d.cdn_rewrite += 1,
                Some("ecs") => d.ecs_rewrite += 1,
                Some("cross") => {
                    d.cross_rewrite += 1;
                    *d.cross.entry(format!("{provider}>{}", cross_to.unwrap_or("?"))).or_default() += 1;
                    i.minute(Self::now_min()).acc += 1;
                }
                _ => {}
            }
        })
    }

    /// 一次 A 回應 ≈ 一次連線：原本會不會出國（`abroad`）、有沒有拉回台灣（`tw`）、省下幾毫秒
    pub fn route(&self, provider: &str, abroad: bool, tw: bool, saved_ms: Option<f64>) {
        self.with(|i| {
            let r = i.day.route.entry(provider.to_string()).or_default();
            r.n += 1;
            if !abroad {
                return;
            }
            r.abroad += 1;
            if tw {
                r.acc += 1;
                if let Some(ms) = saved_ms.filter(|m| *m > 0.0 && *m < 2000.0) {
                    r.saved += ms;
                    r.saved_n += 1;
                }
                i.minute(Self::now_min()).acc += 1;
            } else {
                r.miss += 1;
            }
        })
    }

    /// 對齊 2.x `/api/status` 的 `stats`（`today` 的欄位維持不變，LuCI 會讀）
    pub fn summary(&self) -> Value {
        let (d, dom, blk, cli) = self.with(|i| {
            (
                i.day.clone(),
                top_n(&i.top_domains, 20),
                top_n(&i.top_blocked, 20),
                top_n(&i.top_clients, 20),
            )
        });
        json!({
            "uptimeSec": self.started.elapsed().as_secs(),
            "today": d.json(),
            "topDomains": dom,
            "topBlocked": blk,
            "topClients": cli,
        })
    }

    /// 每日紀錄（舊的在前），欄位同 2.x `stats.daily[日期]`，含 `sites` / `blockedSites`（`{網站: [次數, 人數]}`）
    pub fn daily(&self) -> Vec<(String, Value)> {
        let days = self.with(|i| i.days());
        days.into_iter()
            .map(|(d, s, b)| {
                let mut v = d.json();
                if let Some(o) = v.as_object_mut() {
                    o.insert("sites".into(), rows_json(&s));
                    o.insert("blockedSites".into(), rows_json(&b));
                }
                (d.date, v)
            })
            .collect()
    }

    /// 每日各 CDN 的機會成本（`/api/routing`：`{日期: {CDN: {...}}}`）
    pub fn routing_json(&self) -> Value {
        let days = self.with(|i| i.days());
        Value::Object(days.into_iter().map(|(d, _, _)| (d.date.clone(), d.route_json())).collect())
    }

    /// 最近 60 分鐘，每分鐘一筆（沒有查詢的分鐘補 0）：`[{t, queries, blocked, accelerated}]`
    pub fn realtime(&self) -> Value {
        let now = Self::now_min();
        let mins: Vec<Minute> = self.with(|i| i.minutes.iter().copied().collect());
        Value::Array(
            (now.saturating_sub(59)..=now)
                .map(|m| {
                    let b = mins.iter().find(|x| x.m == m).copied().unwrap_or_default();
                    json!({ "t": m as u64 * 60_000, "queries": b.q, "blocked": b.b, "accelerated": b.acc })
                })
                .collect(),
        )
    }

    /// 期間內（最近 `days` 天，含今天）的匿名排行：多天合併時人數取各天最大值（保守估計），
    /// 只列出人數 ≥ `min_clients` 的網站。`blocked`：被擋網站排行。回傳 `[{site, count}]`
    pub fn anon_ranking(&self, days: usize, blocked: bool, min_clients: u64, n: usize) -> Value {
        let all = self.with(|i| {
            let mut v: Vec<Vec<SiteRow>> = i
                .history
                .iter()
                .map(|d| if blocked { d.blocked_sites.clone() } else { d.sites.clone() })
                .collect();
            if !i.day.date.is_empty() {
                v.push(dump(if blocked { &i.blocked_sites } else { &i.sites }));
            }
            v
        });
        let mut agg: HashMap<String, (u64, u32)> = HashMap::new();
        for rows in all.iter().skip(all.len().saturating_sub(days)) {
            for (site, cnt, c) in rows {
                let e = agg.entry(site.clone()).or_default();
                e.0 += cnt;
                e.1 = e.1.max(*c);
            }
        }
        let mut v: Vec<(String, (u64, u32))> = agg.into_iter().filter(|(_, (_, c))| *c as u64 >= min_clients).collect();
        v.sort_by(|a, b| b.1 .0.cmp(&a.1 .0).then_with(|| a.0.cmp(&b.0)));
        Value::Array(
            v.into_iter()
                .take(n)
                .map(|(site, (cnt, _))| json!({ "site": site, "count": cnt }))
                .collect(),
        )
    }

    /// 快照（每日計數與網站排行，不含任何 IP 或雜湊）。交給外層的快照寫入器，本模組不寫檔
    pub fn snapshot(&self) -> Vec<u8> {
        let days = self.with(|i| i.days());
        let v = json!({
            "version": SNAPSHOT_VERSION,
            "days": days.iter().map(|(d, s, b)| d.snapshot_json(s, b)).collect::<Vec<_>>(),
        });
        serde_json::to_vec(&v).unwrap_or_default()
    }

    /// 還原 [`Stats::snapshot`]：過去的日子直接放回；今天的計數加到目前的計數上，
    /// 網站排行的人數當作下限（雜湊沒有保存）。格式不對回 false
    pub fn restore(&self, bytes: &[u8]) -> bool {
        let Ok(v) = serde_json::from_slice::<Value>(bytes) else {
            return false;
        };
        let Some(arr) = v.get("days").and_then(Value::as_array) else {
            return false;
        };
        let days: Vec<Day> = arr.iter().filter_map(Day::from_json).collect();
        let now = now_unix();
        let today = taipei_date(now);
        let mut g = self.inner.lock().unwrap();
        g.roll(&today);
        g.day_no = (now + 8 * 3600) / 86400;
        for d in days {
            if d.date == today {
                g.day.add(&d);
                for (rows, blocked) in [(&d.sites, false), (&d.blocked_sites, true)] {
                    let max = g.limits.anon_sites;
                    let map = if blocked { &mut g.blocked_sites } else { &mut g.sites };
                    for (k, n, c) in rows {
                        if let Some(e) = map.get_mut(k.as_str()) {
                            e.n += n;
                            e.base = e.base.max(*c);
                        } else if map.len() < max {
                            map.insert(
                                k.as_str().into(),
                                Anon {
                                    n: *n,
                                    c: Vec::new(),
                                    base: *c,
                                },
                            );
                        }
                    }
                }
            } else if d.date < today {
                g.history.retain(|h| h.date != d.date);
                g.history.push_back(d);
            }
        }
        g.trim_history();
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(taipei_date(0), "1970-01-01");
        assert_eq!(taipei_date(16 * 3600), "1970-01-02", "UTC 16:00 是台北隔天 00:00");
        assert_eq!(taipei_date(1_762_790_400), "2025-11-11");
        assert_eq!(taipei_date(951_782_400), "2000-02-29");
        assert_eq!(iso_utc(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso_utc(1_762_790_400_123), "2025-11-10T16:00:00.123Z");
    }

    #[test]
    fn histogram() {
        let mut h = Histogram::default();
        assert_eq!(h.percentile(0.5), None);
        for _ in 0..90 {
            h.record(0.3);
        }
        for _ in 0..10 {
            h.record(40.0);
        }
        assert_eq!(h.percentile(0.5), Some(0.5));
        assert_eq!(h.percentile(0.95), Some(50.0));
        h.record(99999.0);
        assert_eq!(h.percentile(1.0), None, "超過最大區間");
    }

    #[test]
    fn counting() {
        let s = Stats::default();
        s.count(Kind::Query);
        s.blocked("telemetry");
        s.blocked("weird");
        let v = s.summary();
        assert_eq!(v["today"]["query"], 1);
        assert_eq!(v["today"]["blocked"], 2);
        assert_eq!(v["today"]["blockedTelemetry"], 1);
        assert_eq!(v["today"]["blockedAds"], 1);
        assert!(v["today"].get("sites").is_none(), "LuCI 讀的 today 不帶網站排行");
        let rt = s.realtime();
        assert_eq!(rt.as_array().unwrap().len(), 60);
        assert_eq!(rt[59]["queries"], 1);
        assert_eq!(rt[59]["blocked"], 2);
    }

    #[test]
    fn sites() {
        assert_eq!(site_of("www.video.example").as_deref(), Some("video.example"));
        assert_eq!(site_of("rr3---sn-x.videocdn.example.").as_deref(), Some("videocdn.example"));
        assert_eq!(site_of("www.shop.example.com.tw").as_deref(), Some("example.com.tw"));
        assert_eq!(site_of("example.com").as_deref(), Some("example.com"));
        assert_eq!(site_of("1.2.3.4"), None);
        assert_eq!(site_of("4.3.2.1.in-addr.arpa"), None);
        assert_eq!(site_of("nas.lan"), None);
        assert_eq!(site_of("localhost"), None);
        assert_eq!(site_of("WWW.Example.COM.").as_deref(), Some("example.com"));
        assert_eq!(site_of("com.tw").as_deref(), Some("com.tw"));
        assert_eq!(site_of("example.com.tw").as_deref(), Some("example.com.tw"));
        assert_eq!(site_of("a.b.c.d.example.org").as_deref(), Some("example.org"));
        assert_eq!(site_of(""), None);
        assert_eq!(site_of("."), None);
    }

    #[test]
    fn tops_and_anonymity() {
        let s = Stats::default();
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "::ffff:192.0.2.2".parse().unwrap();
        for _ in 0..3 {
            s.query_name("www.example.com", a);
            s.site("www.example.com", a);
        }
        s.query_name("img.example.com", b);
        s.site("img.example.com", b);
        s.site("only-me.example.org", a);
        s.blocked_name("ads.tracker.example.net", a, "ads");
        s.blocked_name("ads.tracker.example.net", b, "ads");
        s.blocked_name("mine.example.net", a, "custom");
        let v = s.summary();
        assert_eq!(v["topDomains"][0], json!({ "name": "www.example.com", "count": 3 }));
        assert_eq!(v["topClients"][0]["name"], "192.0.2.1");
        assert_eq!(v["topClients"][1]["name"], "192.0.2.2", "IPv4 對應位址轉回 IPv4");
        assert_eq!(v["topBlocked"].as_array().unwrap().len(), 2);
        assert_eq!(
            s.anon_ranking(1, false, 2, 15),
            json!([{ "site": "example.com", "count": 4 }]),
            "只有一人造訪的不列出"
        );
        assert_eq!(s.anon_ranking(1, false, 1, 15).as_array().unwrap().len(), 2);
        assert_eq!(
            s.anon_ranking(1, true, 2, 10),
            json!([{ "site": "example.net", "count": 2 }]),
            "自訂規則不進排行"
        );
    }

    #[test]
    fn snapshot_restore_and_history() {
        let s = Stats::default();
        s.count(Kind::Query);
        s.route("cloudflare", true, true, Some(30.0));
        let today = taipei_date(now_unix());
        let snap: Value = serde_json::from_slice(&s.snapshot()).unwrap();
        assert_eq!(snap["days"][0]["date"], today);
        // 自己做一份帶過去日子的快照
        let old = json!({ "version": 1, "days": [
            { "date": "2000-01-01", "query": 99 },
            { "date": "2000-01-02", "query": 5, "blocked": 1, "route": { "cloudflare": { "n": 4, "abroad": 2, "acc": 1, "miss": 1, "saved": 20, "savedN": 1 } },
              "sites": { "example.com": [7, 3] } },
            { "date": today, "query": 10, "sites": { "example.com": [2, 2] } },
        ]});
        let t = Stats::default();
        t.count(Kind::Query);
        assert!(t.restore(&serde_json::to_vec(&old).unwrap()));
        assert!(!t.restore(b"nope"));
        let daily = t.daily();
        assert_eq!(daily.len(), 3);
        assert_eq!(daily[0].0, "2000-01-01");
        assert_eq!(daily[2].1["query"], 11, "今天的計數相加");
        assert_eq!(t.anon_ranking(30, false, 2, 15), json!([{ "site": "example.com", "count": 9 }]));
        assert_eq!(t.anon_ranking(1, false, 3, 15), json!([]), "今天只有 2 人");
        assert_eq!(t.routing_json()["2000-01-02"]["cloudflare"]["acc"], 1);
        // 再存一次、再還原：過去的日子保持不變
        let u = Stats::default();
        assert!(u.restore(&t.snapshot()));
        assert_eq!(u.daily()[1].1["route"]["cloudflare"]["n"], 4);
        // 保留天數
        let many: Vec<Value> = (1..=40).map(|d| json!({ "date": format!("2001-01-{d:02}"), "query": d })).collect();
        let w = Stats::default();
        assert!(w.restore(&serde_json::to_vec(&json!({ "days": many })).unwrap()));
        let d = w.daily();
        assert_eq!(d.len(), RETENTION_DAYS);
        assert_eq!(d.last().unwrap().0, today);
        assert_eq!(d[0].0, "2001-01-11", "只留最近的日子");
    }

    #[test]
    fn rollover_keeps_sites() {
        let mut i = Inner::default();
        i.roll("2001-01-01");
        i.day.query = 3;
        i.anon(false, "example.com", "192.0.2.1".parse().unwrap());
        i.anon(false, "example.com", "192.0.2.2".parse().unwrap());
        i.roll("2001-01-02");
        assert_eq!(i.history.len(), 1);
        assert_eq!(i.history[0].query, 3);
        assert_eq!(i.history[0].sites, vec![("example.com".to_string(), 2, 2)]);
        assert!(i.sites.is_empty(), "新的一天重新計算");
        i.roll("2001-01-01");
        assert_eq!(i.day.query, 3, "時鐘倒退：沿用原本那天");
        assert_eq!(i.sites["example.com"].base, 2);
    }
}
