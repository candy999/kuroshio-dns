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
use std::sync::atomic::{AtomicU32, Ordering};
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
/// 24 小時歷史（3.5.0 E9）：每格幾秒、幾格
pub const HIST_STEP_SEC: u64 = 300;
pub const HIST_SLOTS: usize = 288;

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
    /// 背景補問次數（規格 10 第 5.2 節）
    backfill: u64,
    /// 背景補問的結果跟前面的不一致（一邊是正常回應、另一邊多數是 NXDOMAIN／NODATA）
    backfill_mismatch: u64,
    /// 串接中：上游黑潮擋掉、下游自己的過濾沒擋，改用自己的加密上游解析的次數（3.4.2）
    chain_bypass: u64,
    /// 串接中：上游黑潮解析不到（SERVFAIL）、改用自己的上游解析到的次數（3.4.3）
    chain_retry: u64,
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
    /// 站長標成「異常、不計入期間統計」的日子（3.5.1，例如壓測那天）：7 天、30 天的統計與網站排行跳過這一天，
    /// 每日紀錄照樣保留（`/api/stats/exclude`）
    excluded: bool,
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
    /// 拉回台灣的連線裡，是跨 CDN 備援改寫的（3.5.1）：這些也算在 `Day::cross_rewrite`，
    /// 加速次數合計時扣掉，不重複算。3.5.1 之前存下來的日子沒有這個欄位（0），照舊
    cross: u64,
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

/// 24 小時歷史的一格（3.5.0 E9）：5 分鐘內各計數的增加量。都是 32 位元（在既有的 `Mutex` 裡，
/// 用 `u32` 是為了省空間；一格 32 位元組 × 288 格 ≈ 9.2 KB）
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Slot {
    q: u32,
    blocked: u32,
    servfail: u32,
    stale: u32,
    miss: u32,
    /// 原本會出國的 CDN 回應（`Day.route` 各家 `abroad` 的增加量）與其中換成台灣的（`acc`）
    abroad: u32,
    tw: u32,
    /// 問上游的延遲百分位（毫秒，無條件進位）：0 = 這一格沒有問上游；[`LAT_OVER`] = 超過 1 秒
    p50: u16,
    p95: u16,
}

/// 延遲超過直方圖最後一個有限區間（1000 毫秒）
const LAT_OVER: u16 = 1001;

/// 「上一格結束時」的 `Day` 累計值（算差用）
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct HistBase {
    q: u64,
    blocked: u64,
    servfail: u64,
    stale: u64,
    miss: u64,
    abroad: u64,
    tw: u64,
    lat: [u64; 12],
    /// [`Stats::stale_refresh_fail`] 的值（32 位元、會繞回，差值用 `wrapping_sub`）
    refresh_fail: u32,
}

impl HistBase {
    fn of(d: &Day, refresh_fail: u32) -> HistBase {
        let (abroad, tw) = d.route.values().fold((0, 0), |(a, t), r| (a + r.abroad, t + r.acc));
        HistBase {
            refresh_fail,
            q: d.query,
            blocked: d.blocked,
            servfail: d.servfail,
            stale: d.stale,
            miss: d.miss,
            abroad,
            tw,
            lat: d.lat_miss.counts,
        }
    }
}

/// 24 小時歷史（3.5.0 E9）：固定大小的環形陣列，啟動時配置一次；不進快照、重新啟動清空
#[derive(Debug)]
struct Hist {
    slots: Box<[Slot]>,
    /// 下一格要寫的位置
    head: usize,
    /// 已經有幾格（最多 [`HIST_SLOTS`]）
    n: usize,
    /// 進行中的那一格的槽號（Unix 秒 ÷ 300）；`u64::MAX` = 還沒開始
    cur: u64,
    base: HistBase,
    /// 3.5.0 F3：最近 4 個格子邊界上 [`Stats::stale_refresh_fail`] 的值（舊的在前）：最新減最舊＝最近 3 格的增加量。
    /// 不放進每一格（`Slot` 維持 32 位元組），只多 16 位元組
    rf_marks: [u32; RF_MARKS],
}

const RF_MARKS: usize = 4;

impl Default for Hist {
    fn default() -> Self {
        Hist {
            slots: vec![Slot::default(); HIST_SLOTS].into_boxed_slice(),
            head: 0,
            n: 0,
            cur: u64::MAX,
            base: HistBase::default(),
            rf_marks: [0; RF_MARKS],
        }
    }
}

fn sat32(x: u64) -> u32 {
    x.min(u32::MAX as u64) as u32
}

/// 直方圖兩個時間點之間的百分位（毫秒，無條件進位；沒有資料是 0，超過 1 秒是 [`LAT_OVER`]）
fn lat_ms(h: &Histogram, p: f64) -> u16 {
    if h.n() == 0 {
        return 0;
    }
    match h.percentile(p) {
        Some(ms) => (ms.ceil() as u16).max(1),
        None => LAT_OVER,
    }
}

impl Hist {
    fn clear(&mut self) {
        self.head = 0;
        self.n = 0;
    }

    fn push(&mut self, s: Slot) {
        self.slots[self.head] = s;
        self.head = (self.head + 1) % HIST_SLOTS;
        self.n = (self.n + 1).min(HIST_SLOTS);
    }

    /// 槽號變了：關掉進行中的那一格（現在的累計值 − 上一格結束時的累計值），中間沒有查詢的格子補 0。
    /// 第一次、時鐘倒退、或跳了超過 288 格：清空、基準重設（不補一整圈的 0）
    fn advance(&mut self, slot: u64, day: &Day, refresh_fail: u32) {
        let now = HistBase::of(day, refresh_fail);
        if self.cur == u64::MAX || slot < self.cur || slot - self.cur > HIST_SLOTS as u64 {
            if self.cur != u64::MAX {
                self.clear();
            }
            self.cur = slot;
            self.base = now;
            self.rf_marks = [now.refresh_fail; RF_MARKS];
            return;
        }
        let b = &self.base;
        let mut lat = Histogram::default();
        for (i, c) in lat.counts.iter_mut().enumerate() {
            *c = now.lat[i].saturating_sub(b.lat[i]);
        }
        let d = |x: u64, y: u64| sat32(x.saturating_sub(y));
        self.push(Slot {
            q: d(now.q, b.q),
            blocked: d(now.blocked, b.blocked),
            servfail: d(now.servfail, b.servfail),
            stale: d(now.stale, b.stale),
            miss: d(now.miss, b.miss),
            abroad: d(now.abroad, b.abroad),
            tw: d(now.tw, b.tw),
            p50: lat_ms(&lat, 0.5),
            p95: lat_ms(&lat, 0.95),
        });
        for _ in 1..(slot - self.cur) {
            self.push(Slot::default());
        }
        // 背景更新失敗的計數：這一格結束時的值，中間沒有查詢的格子同一個值（增加量全部算在第一格，跟上面一樣）
        for _ in 0..(slot - self.cur).min(RF_MARKS as u64) {
            self.rf_marks.rotate_left(1);
            self.rf_marks[RF_MARKS - 1] = now.refresh_fail;
        }
        self.cur = slot;
        self.base = now;
    }

    /// 由舊到新
    fn iter(&self) -> impl Iterator<Item = &Slot> {
        let start = (self.head + HIST_SLOTS - self.n) % HIST_SLOTS;
        (0..self.n).map(move |i| &self.slots[(start + i) % HIST_SLOTS])
    }

    /// 最近 `k` 格（完整的 5 分鐘）的（過期快取, 查詢）總和
    fn stale_window(&self, k: usize) -> (u64, u64) {
        self.iter()
            .skip(self.n.saturating_sub(k))
            .fold((0, 0), |(s, q), x| (s + x.stale as u64, q + x.q as u64))
    }

    /// 最近 3 格（完整的 5 分鐘）的背景更新失敗次數（3.5.0 F3；跟 `stale_window(3)` 同一個時間窗）
    fn refresh_fail_15m(&self) -> u64 {
        self.rf_marks[RF_MARKS - 1].wrapping_sub(self.rf_marks[0]) as u64
    }

    fn json(&self) -> Value {
        let col = |f: fn(&Slot) -> u32| Value::Array(self.iter().map(|s| json!(f(s))).collect());
        let lat = |f: fn(&Slot) -> u16| {
            Value::Array(
                self.iter()
                    .map(|s| match f(s) {
                        0 => Value::Null,
                        v => json!(v),
                    })
                    .collect(),
            )
        };
        let from = if self.cur == u64::MAX {
            0
        } else {
            (self.cur - self.n as u64) * HIST_STEP_SEC
        };
        json!({
            "stepSec": HIST_STEP_SEC, "from": from, "n": self.n,
            "q": col(|s| s.q), "blocked": col(|s| s.blocked), "servfail": col(|s| s.servfail),
            "stale": col(|s| s.stale), "miss": col(|s| s.miss),
            "p50": lat(|s| s.p50), "p95": lat(|s| s.p95),
            "abroad": col(|s| s.abroad), "tw": col(|s| s.tw),
        })
    }
}

/// 今天某個網站的匿名計數
#[derive(Debug, Default)]
struct Anon {
    n: u64,
    /// 不同用戶的鹽值雜湊（最多 `ANON_CLIENTS` 個）
    c: Vec<u32>,
    /// 重新啟動前已知的人數（無法還原雜湊，當作下限）
    base: u32,
    /// 上次被查到的順序（[`Inner::anon_seq`]）：收滿要淘汰時，次數一樣的先淘汰比較久沒被查到的
    last: u32,
}

/// 記憶體上限（小記憶體機器可以調低）
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// 熱門網域 / 被擋網域 / 用戶端各自最多幾筆（超過就只留前 1/4）
    pub top_max: usize,
    /// 今天的匿名網站排行最多幾個網站（收滿時一次淘汰次數最少的一半，見 [`evict_half`]）
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
    /// 匿名排行每被查到一次加 1（只用來比先後，繞回也只影響同次數時誰先被淘汰）
    anon_seq: u32,
    limits: Limits,
    /// 記憶體控制縮小排行之前的上限（恢復用）
    saved_top_max: Option<usize>,
    /// 24 小時歷史（3.5.0 E9）
    hist: Hist,
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
            anon_seq: 0,
            limits: Limits::default(),
            saved_top_max: None,
            hist: Hist::default(),
        }
    }
}

pub struct Stats {
    started: Instant,
    inner: Mutex<Inner>,
    /// 過期快取的背景更新失敗（3.5.0 F3）：`refresh()` 做完拿回來的還是過期的或 SERVFAIL、或上游全部失敗直接回舊資料。
    /// 啟動後累計；只在背景工作或本來就失敗的慢路徑上累加（不拿 `inner` 的鎖），E9 的歷史換格時讀一次
    stale_refresh_fail: AtomicU32,
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

/// 國碼頂級網域（兩個字母）底下常見的類別：`example.com.ua`、`example.co.za`、`example.co.uk`、`example.com.tw`、
/// `example.go.jp` 這類的主網域是三段（3.5.1）。以前只有一份四十幾個的清單（同 2.x），清單外的國家
/// （`xxx.com.ua`、`xxx.co.za`）整個國家的網站都算成同一個「網站」，排行與預熱名單「同一個主網域最多 8 筆」都被影響。
///
/// 每次查詢都會比對（[`site_slice`]）：只看最後兩段的長度與內容，不配置記憶體
#[rustfmt::skip]
const CC_CATEGORY: &[&str] = &[
    "com", "net", "org", "edu", "gov", "mil",
    "ac", "co", "or", "ne", "go",
    "gob", "gouv", "ltd", "plc", "sch", "nom",
];

/// 通用規則（[`CC_CATEGORY`]）以外的多層公共尾碼：台灣的個人、遊戲、商務、社團，泰國的 `in.th`
#[rustfmt::skip]
const MULTI_SUFFIX: &[&str] = &[
    "idv.tw",
    "game.tw",
    "ebiz.tw",
    "club.tw",
    "in.th",
];

/// 最後兩段是「兩個字母的國碼 + 常見類別」（`com.ua`、`co.uk`、`com.tw`）
fn is_cc_category(last2: &str) -> bool {
    let Some((sld, tld)) = last2.split_once('.') else {
        return false;
    };
    tld.len() == 2 && tld.bytes().all(|b| b.is_ascii_lowercase()) && CC_CATEGORY.contains(&sld)
}

/// 託管平台的尾碼（Public Suffix List 的 private 段）：底下每一個名稱是不同使用者的網站，所以跟國碼的類別（[`CC_CATEGORY`]）一樣
/// 多算一段當主網域。開機預熱名單另外限制同一個平台底下的總筆數（`cache::WARM_PER_PLATFORM`，3.5.1）：
/// 這些平台大多對任何子網域都回答，隨機名稱查幾次就是「正常有答案、命中 2 次以上」
pub const PLATFORM_SUFFIX: &[&str] = &[
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

/// [`site_of`] 的不配置版本（開機預熱名單分組用）：`n` 要已經是小寫、結尾沒有點；回傳 `n` 的一段
pub fn site_key(n: &str) -> Option<&str> {
    site_slice(n)
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
    if is_cc_category(last2) || MULTI_SUFFIX.contains(&last2) || PLATFORM_SUFFIX.contains(&last2) {
        return Some(tail(3));
    }
    Some(last2)
}

/// 主網域（[`site_key`] 的結果）在哪一個託管平台底下（[`PLATFORM_SUFFIX`] 的位置）；平台本身、一般網域回 None。
/// 開機預熱名單分組用（背景），不在查詢路徑上
pub fn platform_of(site: &str) -> Option<usize> {
    let (_, rest) = site.split_once('.')?;
    PLATFORM_SUFFIX.iter().position(|p| *p == rest)
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
    /// 背景補問（問這次沒問到的上游，規格 10 第 5.2 節）
    Backfill,
    /// 背景補問抽樣比對到不一致
    BackfillMismatch,
    /// 上游黑潮擋、下游自己解析（3.4.2）
    ChainBypass,
    /// 上游黑潮解析不到、下游自己解析到（3.4.3）
    ChainRetry,
}

impl Default for Stats {
    fn default() -> Self {
        Stats {
            started: Instant::now(),
            inner: Mutex::new(Inner::default()),
            stale_refresh_fail: AtomicU32::new(0),
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

/// 匿名排行收滿時：淘汰次數最少的一半（同樣次數時 `last` 比較小、比較久沒被查到的先）。
/// 只排序（次數, 順序）兩個數字、找出分界，再用 `retain` 刪，不複製網站名稱
fn evict_half(map: &mut HashMap<Box<str>, Anon>) {
    let k = map.len() / 2;
    if k == 0 {
        return;
    }
    let mut v: Vec<(u64, u32)> = map.values().map(|a| (a.n, a.last)).collect();
    let (_, pivot, _) = v.select_nth_unstable(k - 1);
    let pivot = *pivot;
    // 比分界小的全部刪；剛好等於分界的只刪到湊滿 k 個（還原的資料 `last` 都是 0，可能很多筆一樣）
    let less = v.iter().filter(|x| **x < pivot).count();
    let mut eq_quota = k - less;
    map.retain(|_, a| {
        let key = (a.n, a.last);
        if key < pivot {
            return false;
        }
        if key == pivot && eq_quota > 0 {
            eq_quota -= 1;
            return false;
        }
        true
    });
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
                    last: 0,
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
    /// 對齊 2.x 每日紀錄的欄位（不含網站排行）；標成異常的日子多 `"excluded": true`
    fn json(&self) -> Value {
        let mut v = self.json_base();
        if self.excluded {
            if let Some(o) = v.as_object_mut() {
                o.insert("excluded".into(), Value::Bool(true));
            }
        }
        v
    }

    fn json_base(&self) -> Value {
        let d = self;
        json!({
            "date": d.date, "query": d.query, "hit": d.hit, "miss": d.miss, "servfail": d.servfail, "local": d.local,
            "blocked": d.blocked, "blockedAds": d.blocked_ads, "blockedTelemetry": d.blocked_telemetry,
            "blockedMalware": d.blocked_malware, "blockedCustom": d.blocked_custom,
            "cdnServed": d.cdn_served, "cdnRewrite": d.cdn_rewrite, "ecsRewrite": d.ecs_rewrite, "crossRewrite": d.cross_rewrite,
            "cdn": d.cdn, "cross": d.cross,
            "route": d.route_json(),
            "stale": d.stale, "prefetch": d.prefetch,
            "backfill": d.backfill, "backfillMismatch": d.backfill_mismatch,
            "chainBypass": d.chain_bypass,
            "chainRetry": d.chain_retry,
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
                        json!({ "n": r.n, "abroad": r.abroad, "acc": r.acc, "miss": r.miss, "saved": r.saved.round(), "savedN": r.saved_n, "cross": r.cross }),
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
                                cross: g("cross"),
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
            backfill: n("backfill"),
            backfill_mismatch: n("backfillMismatch"),
            chain_bypass: n("chainBypass"),
            chain_retry: n("chainRetry"),
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
            excluded: v.get("excluded") == Some(&Value::Bool(true)),
        })
    }

    /// 把另一天的計數加進來（還原快照時，今天已經有計數的話合併）
    fn add(&mut self, o: &Day) {
        self.excluded |= o.excluded;
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
        self.backfill += o.backfill;
        self.backfill_mismatch += o.backfill_mismatch;
        self.chain_bypass += o.chain_bypass;
        self.chain_retry += o.chain_retry;
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
            e.cross += r.cross;
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
        self.anon_seq = self.anon_seq.wrapping_add(1);
        let seq = self.anon_seq;
        let map = if blocked { &mut self.blocked_sites } else { &mut self.sites };
        let e = match map.get_mut(site) {
            Some(e) => e,
            None => {
                // 收滿：一次淘汰次數最少（同樣次數時最久沒被查到）的一半，再收新的。
                // 3.5.0 以前收滿就不再加，壓測那天被單一來源的一次性網域佔滿，之後真正使用者的新網站都記不到。
                // 每收 max/2 個新網站才做一次（攤銷 O(1)），在既有的鎖裡、不另外配置鍵
                if map.len() >= max.max(2) {
                    evict_half(map);
                }
                map.entry(site.into()).or_default()
            }
        };
        e.last = seq;
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
        self.with_at(now_unix(), f)
    }

    /// 同 [`Stats::with`]，時間由呼叫端給（測試用）
    fn with_at<R>(&self, now: u64, f: impl FnOnce(&mut Inner) -> R) -> R {
        let day_no = (now + 8 * 3600) / 86400;
        let slot = now / HIST_STEP_SEC;
        let mut g = self.inner.lock().unwrap();
        let i = &mut *g;
        // 3.5.0 E9：每筆查詢只多這一次整數比較；先關格、再換日（台北午夜也是 5 分鐘的邊界，
        // 換日前先用舊的 `Day` 算完差值，換日後基準歸零）
        if i.hist.cur != slot {
            i.hist.advance(slot, &i.day, self.stale_refresh_fail.load(Ordering::Relaxed));
        }
        if i.day_no != day_no {
            i.roll(&taipei_date(now));
            i.day_no = day_no;
            i.hist.base = HistBase::of(&i.day, self.stale_refresh_fail.load(Ordering::Relaxed));
        }
        f(i)
    }

    fn with_day<R>(&self, f: impl FnOnce(&mut Day) -> R) -> R {
        self.with(|i| f(&mut i.day))
    }

    fn now_min() -> u32 {
        (now_unix() / 60) as u32
    }

    /// 調整記憶體上限（記憶體吃緊時由記憶體控制縮小熱門排行，見 `shed_tops`）
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
                Kind::Backfill => d.backfill += 1,
                Kind::BackfillMismatch => d.backfill_mismatch += 1,
                Kind::ChainBypass => d.chain_bypass += 1,
                Kind::ChainRetry => d.chain_retry += 1,
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

    /// 一次 A 回應 ≈ 一次連線：原本會不會出國（`abroad`）、有沒有拉回台灣（`tw`）、省下幾毫秒。
    ///
    /// `cross`（3.5.1）：這次是跨 CDN 備援改寫的。`cdn()` 已經把它算進跨 CDN 次數與這一分鐘的拉回，
    /// 這裡照樣記成這家 CDN 的「拉回」（連線去向的三塊要加得起來），另外記一筆 `cross`，
    /// 加速次數合計時扣掉；這一分鐘的拉回不再加（以前同一次連線算兩次）。在既有的鎖裡多一次比較、一個計數
    pub fn route(&self, provider: &str, abroad: bool, tw: bool, saved_ms: Option<f64>, cross: bool) {
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
                if cross {
                    r.cross += 1;
                } else {
                    i.minute(Self::now_min()).acc += 1;
                }
            } else {
                r.miss += 1;
            }
        })
    }

    /// 24 小時歷史（3.5.0 E9）：每 5 分鐘一格、最多 288 格，欄位分開的陣列
    /// （`stepSec`、`from`、`n`、`q`、`blocked`、`servfail`、`stale`、`miss`、`p50`、`p95`、`abroad`、`tw`）。
    /// 從 `Day` 的累計值算差，查詢路徑上不加新的累加；不進快照。
    ///
    /// `from` 是第一格開始的 Unix 秒；最後一格是上一個完整的 5 分鐘（進行中的那一格不給）。
    /// `p50`／`p95` 是問上游的延遲（毫秒）：`null` = 那一格沒有問上游，`1001` = 超過 1 秒。
    pub fn history_json(&self) -> Value {
        self.history_at(now_unix())
    }

    fn history_at(&self, now: u64) -> Value {
        self.with_at(now, |i| i.hist.json())
    }

    /// 過期快取的比率（3.5.0 E8）：`today`、`rateToday`（`Day.stale ÷ Day.query`）、`rate15m`、`rate1h`
    /// （後兩個讀 E9 的環形陣列，只算完整的 5 分鐘）。沒有查詢時比率是 0。
    pub fn stale_rates(&self) -> Value {
        self.stale_rates_at(now_unix())
    }

    fn stale_rates_at(&self, now: u64) -> Value {
        let (today, query, w15, w60, f15) = self.with_at(now, |i| {
            (
                i.day.stale,
                i.day.query,
                i.hist.stale_window(3),
                i.hist.stale_window(12),
                i.hist.refresh_fail_15m(),
            )
        });
        let rate = |s: u64, q: u64| {
            if q == 0 {
                0.0
            } else {
                (s as f64 / q as f64 * 10_000.0).round() / 10_000.0
            }
        };
        json!({ "today": today, "rateToday": rate(today, query), "rate15m": rate(w15.0, w15.1), "rate1h": rate(w60.0, w60.1),
                // 3.5.0 F3：最近 15 分鐘背景更新失敗的次數（跟 rate15m 同一個時間窗）
                "refreshFail15m": f15 })
    }

    /// 過期快取的背景更新失敗了一次（3.5.0 F3；只在背景工作或上游全部失敗的慢路徑上呼叫）
    pub fn note_stale_refresh_fail(&self) {
        self.stale_refresh_fail.fetch_add(1, Ordering::Relaxed);
    }

    /// 最近 15 分鐘（3 格）的背景更新失敗次數（E2 的 `serve-stale-high` 用）
    pub fn stale_refresh_fail_15m(&self) -> u64 {
        self.with(|i| i.hist.refresh_fail_15m())
    }

    /// 最近 15 分鐘（3 格）的（過期快取, 查詢）總和（E2 的 `serve-stale-high` 用）
    pub fn stale_15m(&self) -> (u64, u64) {
        self.with(|i| i.hist.stale_window(3))
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

    /// 把某一天標成「異常、不計入期間統計」（`on`）或取消（3.5.1）。只能標還保留著的日子（最多 [`RETENTION_DAYS`] 天，
    /// 跟著每日紀錄存進 `stats.json`、到期一起刪），所以有上限。回傳之前的狀態；沒有這一天回 None
    pub fn set_excluded(&self, date: &str, on: bool) -> Option<bool> {
        self.with(|i| {
            let d = if i.day.date == date {
                &mut i.day
            } else {
                i.history.iter_mut().find(|d| d.date == date)?
            };
            Some(std::mem::replace(&mut d.excluded, on))
        })
    }

    /// 標成異常的日子（舊的在前）
    pub fn excluded_days(&self) -> Vec<String> {
        self.with(|i| {
            i.history
                .iter()
                .chain(std::iter::once(&i.day))
                .filter(|d| d.excluded && !d.date.is_empty())
                .map(|d| d.date.clone())
                .collect()
        })
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
            let mut v: Vec<(bool, Vec<SiteRow>)> = i
                .history
                .iter()
                .map(|d| (d.excluded, if blocked { d.blocked_sites.clone() } else { d.sites.clone() }))
                .collect();
            if !i.day.date.is_empty() {
                v.push((i.day.excluded, dump(if blocked { &i.blocked_sites } else { &i.sites })));
            }
            v
        });
        let mut agg: HashMap<String, (u64, u32)> = HashMap::new();
        // 期間（7 天、30 天）跳過標成異常的日子；只看今天時照樣列（3.5.1）
        for (_, rows) in all
            .iter()
            .skip(all.len().saturating_sub(days))
            .filter(|(excluded, _)| days <= 1 || !*excluded)
        {
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
                                    last: 0,
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
        // 3.5.0 E9：還原回來的累計值不算進下一格（不會出現一格「今天到目前為止的總和」）
        let base = HistBase::of(&g.day, self.stale_refresh_fail.load(Ordering::Relaxed));
        g.hist.base = base;
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
        assert_eq!(v["today"]["backfill"], 0);
        s.count(Kind::Backfill);
        s.count(Kind::BackfillMismatch);
        s.count(Kind::ChainBypass);
        let v = s.summary();
        assert_eq!(v["today"]["backfill"], 1);
        assert_eq!(v["today"]["backfillMismatch"], 1);
        assert_eq!(v["today"]["chainBypass"], 1);
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
        // 3.5.1：國碼頂級網域底下的常見類別一律算三段（以前清單外的國家整個國家算成同一個網站）
        assert_eq!(site_of("www.shop.example.com.ua").as_deref(), Some("example.com.ua"));
        assert_eq!(site_of("cdn.example.co.za").as_deref(), Some("example.co.za"));
        assert_eq!(site_of("news.example.co.uk").as_deref(), Some("example.co.uk"));
        assert_eq!(site_of("www.example.net.tw").as_deref(), Some("example.net.tw"));
        assert_eq!(site_of("www.example.go.jp").as_deref(), Some("example.go.jp"));
        assert_eq!(site_of("a.example.gob.mx").as_deref(), Some("example.gob.mx"));
        assert_ne!(site_of("a.example.com.ua"), site_of("b.example2.com.ua"), "不同網站不再合併");
        // 特別的項目照舊
        assert_eq!(site_of("blog.someone.idv.tw").as_deref(), Some("someone.idv.tw"));
        assert_eq!(site_of("www.example.in.th").as_deref(), Some("example.in.th"));
        assert_eq!(site_of("user.github.io").as_deref(), Some("user.github.io"));
        // 不是國碼（不是兩個字母）、不是常見類別：照一般的兩段
        assert_eq!(site_of("www.example.com").as_deref(), Some("example.com"));
        assert_eq!(site_of("a.b.example.net").as_deref(), Some("example.net"));
        assert_eq!(site_of("www.shop.example.de").as_deref(), Some("example.de"));
        assert_eq!(site_of("api.example.io").as_deref(), Some("example.io"));
        assert_eq!(site_of("www.example.co").as_deref(), Some("example.co"));
        assert_eq!(site_of("www.com.example").as_deref(), Some("com.example"));
        assert_eq!(site_of("x.shop.example.xn--kpry57d").as_deref(), Some("example.xn--kpry57d"));
        assert_eq!(site_of("co.za").as_deref(), Some("co.za"));
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

    /// 連線去向圖（3.5.1）的三塊：原本就在台灣 + 拉回台灣 + 仍在國外 = 連線數（`n = (n − abroad) + acc + miss`）
    #[test]
    fn route_splits_every_connection_into_three() {
        let s = Stats::default();
        s.route("cloudflare", false, false, None, false); // 一般 DNS 給的已經是台灣節點
        s.route("cloudflare", false, true, None, false); // 一樣算原本就在台灣（沒有出國可以拉回）
        s.route("cloudflare", true, true, Some(30.0), false); // 拉回台灣
        s.route("cloudflare", true, false, None, false); // 仍在國外
        s.route("cloudflare", true, true, Some(5000.0), false); // 拉回台灣；省下的時間不合理，不算樣本
        let daily = s.daily();
        let day = &daily.last().unwrap().1["route"]["cloudflare"];
        let g = |k: &str| day[k].as_u64().unwrap();
        assert_eq!((g("n"), g("abroad"), g("acc"), g("miss"), g("savedN")), (5, 3, 2, 1, 1));
        assert_eq!(g("n") - g("abroad") + g("acc") + g("miss"), g("n"));
        assert_eq!(g("abroad"), g("acc") + g("miss"));
    }

    /// 3.5.1：同一次連線同時是跨 CDN 又是拉回台灣（在台灣有節點的 CDN 走跨 CDN）：跨 CDN 次數、
    /// 這家 CDN 的拉回、這一分鐘的拉回各只加 1；另外記一筆 `cross`，加速次數合計時扣掉
    #[test]
    fn cross_and_route_count_once() {
        let s = Stats::default();
        s.cdn("cloudflare", Some("cross"), Some("cloudfront"));
        s.route("cloudflare", true, true, Some(20.0), true);
        let daily = s.daily();
        let d = &daily.last().unwrap().1;
        assert_eq!(d["crossRewrite"], 1);
        assert_eq!(d["cross"]["cloudflare>cloudfront"], 1);
        let r = &d["route"]["cloudflare"];
        assert_eq!(
            (r["n"].as_u64(), r["acc"].as_u64(), r["cross"].as_u64()),
            (Some(1), Some(1), Some(1))
        );
        let acc: u64 = s
            .realtime()
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["accelerated"].as_u64().unwrap())
            .sum();
        assert_eq!(acc, 1, "這一分鐘的拉回只算一次");
        // 一般的拉回（不是跨 CDN）照舊
        s.route("cloudflare", true, true, None, false);
        let acc: u64 = s
            .realtime()
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["accelerated"].as_u64().unwrap())
            .sum();
        assert_eq!(acc, 2);
        // 存下來再讀回：cross 保留；3.5.1 之前的日子沒有這個欄位當 0
        let t = Stats::default();
        assert!(t.restore(&s.snapshot()));
        assert_eq!(t.daily().last().unwrap().1["route"]["cloudflare"]["cross"], 1);
    }

    #[test]
    fn snapshot_restore_and_history() {
        let s = Stats::default();
        s.count(Kind::Query);
        s.route("cloudflare", true, true, Some(30.0), false);
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

    /// 3.5.1：標成異常的日子不算進 7 天／30 天的網站排行，跟著快照保存；只能標還保留著的日子
    #[test]
    fn excluded_days_skip_period_ranking_and_persist() {
        let st = Stats::default();
        let old = json!({ "days": [
            { "date": "2000-01-01", "query": 5, "sites": { "example.net": [5, 2] } },
            { "date": "2000-01-02", "query": 90_000, "sites": { "flood.example.com": [90_000, 1] } },
        ] });
        assert!(st.restore(&serde_json::to_vec(&old).unwrap()));
        assert_eq!(st.anon_ranking(30, false, 1, 10)[0]["site"], "flood.example.com");
        assert_eq!(st.set_excluded("2000-01-02", true), Some(false));
        assert_eq!(st.set_excluded("2000-01-02", true), Some(true), "已經標過");
        assert_eq!(st.set_excluded("1999-12-31", true), None, "沒有這一天");
        assert_eq!(st.excluded_days(), vec!["2000-01-02"]);
        assert_eq!(st.anon_ranking(30, false, 1, 10), json!([{ "site": "example.net", "count": 5 }]));
        let daily = st.daily();
        assert_eq!(daily[1].1["excluded"], true);
        assert!(daily[0].1.get("excluded").is_none(), "沒標的日子欄位不變");
        // 存檔、讀回來還在；取消
        let back = Stats::default();
        assert!(back.restore(&st.snapshot()));
        assert_eq!(back.excluded_days(), vec!["2000-01-02"]);
        assert_eq!(back.set_excluded("2000-01-02", false), Some(true));
        assert!(back.excluded_days().is_empty());
        assert_eq!(back.anon_ranking(30, false, 1, 10)[0]["site"], "flood.example.com");
        // 今天也可以標：只看今天時照樣列，期間統計跳過
        let today = taipei_date(now_unix());
        st.site("www.example.org", "192.0.2.1".parse().unwrap());
        assert_eq!(st.set_excluded(&today, true), Some(false));
        assert_eq!(st.anon_ranking(1, false, 1, 10)[0]["site"], "example.org");
        assert!(!st.anon_ranking(7, false, 1, 10).to_string().contains("example.org"));
    }

    /// 3.5.1：匿名排行收滿時淘汰次數最少的一半，不再拒收新網站（壓測那天一次性網域佔滿，真正的網站記不到）
    #[test]
    fn anon_full_evicts_least_counted_half() {
        let mut i = Inner::default();
        i.roll("2001-01-01");
        i.limits.anon_sites = 100;
        let ip = |n: u8| -> IpAddr { format!("192.0.2.{n}").parse().unwrap() };
        // 真正使用者的網站：查很多次
        for _ in 0..20 {
            i.anon(false, "example.net", ip(1));
            i.anon(false, "example.org", ip(2));
        }
        // 單一來源的一次性網域塞滿
        for k in 0..98 {
            i.anon(false, &format!("p{k}.example"), ip(9));
        }
        assert_eq!(i.sites.len(), 100);
        // 收滿之後的新網站照樣記得到：淘汰一半（次數最少、最久沒被查到的先）
        i.anon(false, "new.example.com", ip(3));
        assert_eq!(i.sites.len(), 51, "淘汰 50 筆、加 1 筆");
        for s in ["example.net", "example.org", "new.example.com"] {
            assert!(i.sites.contains_key(s), "{s} 要留著");
        }
        assert!(!i.sites.contains_key("p0.example"), "最早的一次性網域先淘汰");
        assert!(i.sites.contains_key("p97.example"), "同樣次數時最近的留著");
        assert_eq!(i.sites["example.net"].n, 20, "留下的計數不變");
        // 一直湧入也有上限，常用的網站一直都在
        for k in 0..1000 {
            i.anon(false, &format!("q{k}.example"), ip(9));
        }
        assert!(i.sites.len() <= 100);
        assert!(i.sites.contains_key("example.net") && i.sites.contains_key("example.org"));
        // 被擋網站的排行同樣處理
        i.limits.anon_sites = 10;
        for k in 0..30 {
            i.anon(true, &format!("b{k}.example"), ip(9));
        }
        assert!(i.blocked_sites.len() <= 10 && i.blocked_sites.contains_key("b29.example"));
    }

    /// 次數一樣（還原的資料順序都是 0）時剛好淘汰一半，不會全部刪掉
    #[test]
    fn evict_half_with_ties_removes_exactly_half() {
        let mut m: HashMap<Box<str>, Anon> = (0..10)
            .map(|k| (format!("s{k}.example").into_boxed_str(), Anon { n: 1, ..Anon::default() }))
            .collect();
        evict_half(&mut m);
        assert_eq!(m.len(), 5);
        let mut one: HashMap<Box<str>, Anon> = HashMap::new();
        one.insert("a.example".into(), Anon::default());
        evict_half(&mut one);
        assert_eq!(one.len(), 1, "只有 1 筆時不刪");
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

    // ---- 3.5.0 E9：24 小時歷史 ----

    /// 台北某天 10:00 整（UTC 02:00），是 5 分鐘的邊界
    const T0: u64 = 1_762_826_400;

    fn bump_at(s: &Stats, now: u64, q: u64, stale: u64, miss_ms: &[f64]) {
        s.with_at(now, |i| {
            i.day.query += q;
            i.day.stale += stale;
            for ms in miss_ms {
                i.day.miss += 1;
                i.day.lat_miss.record(*ms);
            }
        });
    }

    #[test]
    fn history_slot_closes_on_boundary_with_deltas() {
        let s = Stats::default();
        bump_at(&s, T0 + 1, 3, 1, &[]);
        bump_at(&s, T0 + 299, 2, 0, &[]);
        assert_eq!(s.history_at(T0 + 299)["n"], 0, "進行中的那一格不給");
        bump_at(&s, T0 + 300, 7, 0, &[]);
        let h = s.history_at(T0 + 301);
        assert_eq!(h["n"], 1);
        assert_eq!(h["from"], T0);
        assert_eq!(h["stepSec"], 300);
        assert_eq!(h["q"], json!([5]), "第一格：0～299 秒的增加量");
        assert_eq!(h["stale"], json!([1]));
        let h = s.history_at(T0 + 600);
        assert_eq!(h["q"], json!([5, 7]));
        assert_eq!(h["from"], T0);
    }

    #[test]
    fn history_sum_matches_day_totals() {
        let s = Stats::default();
        // 台北 00:00 開始一整天
        let midnight = 1_762_790_400; // 2025-11-11 00:00 台北
        s.with_at(midnight, |_| {});
        for k in 0..288u64 {
            bump_at(&s, midnight + k * 300 + 7, k % 5, k % 2, &[]);
            s.with_at(midnight + k * 300 + 10, |i| {
                let r = i.day.route.entry("cloudflare".into()).or_default();
                r.abroad += 2;
                r.acc += 1;
            });
        }
        let h = s.history_at(midnight + 86_399);
        assert_eq!(h["n"], 287, "最後一格還在進行中");
        let sum = |k: &str| h[k].as_array().unwrap().iter().map(|v| v.as_u64().unwrap()).sum::<u64>();
        let (q, st) = s.with_at(midnight + 86_399, |i| (i.day.query, i.day.stale));
        // 最後一格（第 287 格）還沒關：總和差最後一格
        assert_eq!(sum("q") + 287 % 5, q);
        assert_eq!(sum("stale") + 287 % 2, st);
        assert_eq!(sum("abroad"), 287 * 2);
        assert_eq!(sum("tw"), 287);
    }

    #[test]
    fn history_closes_before_day_roll() {
        let s = Stats::default();
        let midnight = 1_762_790_400; // 台北 00:00
        bump_at(&s, midnight - 200, 9, 0, &[]);
        bump_at(&s, midnight + 5, 1, 0, &[]);
        let h = s.history_at(midnight + 301);
        assert_eq!(h["q"], json!([9, 1]), "跨午夜的那一格不遺失、不變成負的");
        assert_eq!(s.with_at(midnight + 301, |i| i.day.query), 1, "換日了");
    }

    #[test]
    fn history_fills_idle_slots_with_zero_and_caps_at_288() {
        let s = Stats::default();
        bump_at(&s, T0, 4, 0, &[]);
        bump_at(&s, T0 + 3 * 300 + 1, 2, 0, &[]);
        let h = s.history_at(T0 + 4 * 300);
        assert_eq!(h["q"], json!([4, 0, 0, 2]));
        // 一直跑 300 格：最多 288
        for k in 5..310u64 {
            bump_at(&s, T0 + k * 300, 1, 0, &[]);
        }
        let h = s.history_at(T0 + 310 * 300);
        assert_eq!(h["n"], HIST_SLOTS);
        assert_eq!(h["q"].as_array().unwrap().len(), HIST_SLOTS);
        assert_eq!(h["from"], T0 + (310 - 288) * 300);
    }

    #[test]
    fn history_first_slot_after_restore_is_not_whole_day() {
        let s = Stats::default();
        s.count(Kind::Query);
        let today = taipei_date(now_unix());
        let snap = json!({ "version": 1, "days": [ { "date": today, "query": 5000, "stale": 40 } ] });
        assert!(s.restore(&serde_json::to_vec(&snap).unwrap()));
        let now = now_unix();
        let after = (now / 300 + 1) * 300;
        bump_at(&s, now, 2, 0, &[]);
        let h = s.history_at(after + 1);
        let q: u64 = h["q"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap()).sum();
        assert!(q <= 3, "還原的 5000 筆不算進一格：{h}");
        assert_eq!(h["stale"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap()).sum::<u64>(), 0);
    }

    #[test]
    fn history_resets_on_clock_jump_back_or_far_forward() {
        let s = Stats::default();
        for k in 0..5u64 {
            bump_at(&s, T0 + k * 300, 1, 0, &[]);
        }
        assert_eq!(s.history_at(T0 + 5 * 300)["n"], 5);
        // 時鐘倒退
        bump_at(&s, T0 + 100, 1, 0, &[]);
        let h = s.history_at(T0 + 100);
        assert_eq!(h["n"], 0, "清空重來");
        assert_eq!(s.history_at(T0 + 300)["q"], json!([1]));
        // 跳了超過 288 格：清空，不補一整圈的 0
        let far = T0 + 300 + 289 * 300 + 300;
        bump_at(&s, far, 1, 0, &[]);
        assert_eq!(s.history_at(far)["n"], 0);
        assert_eq!(s.history_at(far + 300)["n"], 1);
    }

    #[test]
    fn history_not_in_snapshot() {
        let s = Stats::default();
        bump_at(&s, now_unix(), 3, 0, &[]);
        let snap = String::from_utf8(s.snapshot()).unwrap();
        assert!(!snap.contains("stepSec") && !snap.contains("hist"), "{snap}");
    }

    #[test]
    fn history_p50_from_histogram_delta() {
        let s = Stats::default();
        // 第一格：慢的（200 毫秒）
        bump_at(&s, T0, 10, 0, &[150.0; 10]);
        // 第二格：快的（2 毫秒）與一筆超過 1 秒
        let mut fast = vec![1.5; 19];
        fast.push(5000.0);
        bump_at(&s, T0 + 300, 20, 0, &fast);
        // 第三格：沒有問上游
        bump_at(&s, T0 + 600, 1, 0, &[]);
        let h = s.history_at(T0 + 900);
        assert_eq!(h["p50"], json!([200, 2, null]), "用兩格之間的差，不是今天整天的");
        assert_eq!(h["p95"], json!([200, 2, null]));
        assert_eq!(h["miss"], json!([10, 20, 0]));
        let mut over = Histogram::default();
        over.record(5000.0);
        assert_eq!(lat_ms(&over, 0.5), LAT_OVER);
        let mut sub = Histogram::default();
        sub.record(0.2);
        assert_eq!(lat_ms(&sub, 0.5), 1, "0.5 毫秒的區間無條件進位成 1");
    }

    #[test]
    fn stale_rates_from_history_ring() {
        let s = Stats::default();
        for k in 0..12u64 {
            // 最後 3 格：每格 100 筆、10 筆過期；之前的：每格 100 筆、0 筆
            bump_at(&s, T0 + k * 300, 100, if k >= 9 { 10 } else { 0 }, &[]);
        }
        let r = s.stale_rates_at(T0 + 12 * 300);
        assert_eq!(r["today"], 30);
        assert_eq!(r["rate15m"], 0.1);
        assert_eq!(r["rate1h"], 0.025);
        assert_eq!(r["rateToday"], 0.025);
        let empty = Stats::default().stale_rates_at(T0);
        assert_eq!(
            empty,
            json!({ "today": 0, "rateToday": 0.0, "rate15m": 0.0, "rate1h": 0.0, "refreshFail15m": 0 })
        );
    }

    /// 3.5.0 F3：背景更新失敗的次數跟 `rate15m` 同一個時間窗（最近 3 個完整的 5 分鐘），舊的滾出去
    #[test]
    fn refresh_fail_15m_follows_history_window() {
        let s = Stats::default();
        bump_at(&s, T0, 10, 0, &[]);
        for k in 1..=6u64 {
            // 第 1～3 格每格失敗 2 次，第 4～6 格每格 1 次
            for _ in 0..(if k <= 3 { 2 } else { 1 }) {
                s.note_stale_refresh_fail();
            }
            bump_at(&s, T0 + k * 300 - 1, 10, 1, &[]);
            bump_at(&s, T0 + k * 300, 10, 0, &[]);
        }
        assert_eq!(s.stale_rates_at(T0 + 6 * 300)["refreshFail15m"], 3, "第 4～6 格");
        assert_eq!(s.with_at(T0 + 6 * 300, |i| i.hist.refresh_fail_15m()), 3);
        // 之後 15 分鐘沒有失敗：歸零（中間沒有查詢的格子也算進去）
        bump_at(&s, T0 + 10 * 300, 10, 0, &[]);
        assert_eq!(s.stale_rates_at(T0 + 10 * 300)["refreshFail15m"], 0);
    }

    #[test]
    fn hist_slot_is_32_bytes() {
        assert_eq!(std::mem::size_of::<Slot>(), 32, "288 格 ≈ 9.2 KB");
    }
}
