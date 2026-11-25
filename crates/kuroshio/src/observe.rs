//! 觀測（3.5.0 E 組，規格 11 第 5 節）：資料新鮮度（E1）、發現清單（E2）、這台 WAN 的 ISP 群組（E10）。
//!
//! - 全部是拉取式：`/api/status` 被讀時才組出來，不起背景工作、不發對外探測、不寫 Flash。
//! - `warnings`（`integration.rs`）的格式與內容不動；`findings` 是另外一份，同一件事不兩邊都放。
//! - 新狀態都有固定上限：新鮮度最多 16 項、發現最多 32 筆（會自己過期）、ISP 群組一個字串。

use crate::app::AppState;
use kuroshio_jobs::geo::TwIp;
use kuroshio_jobs::scheduler::JobFreshness;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

// ================= E1：資料新鮮度 =================

/// 新鮮度最多幾項
pub const FRESH_MAX: usize = 16;
/// 路徑檢查的週期（`pathcheck.rs` 的 `INTERVAL`）
const PATH_EVERY_MS: u64 = 6 * 3600 * 1000;
/// 串接同步的週期（`ShareTiming` 的預設 `every`）
const CHAIN_SYNC_EVERY_MS: u64 = 6 * 3600 * 1000;

/// 排程工作：（工作名稱、`key`、白話）；固定順序
const JOBS: [(&str, &str, &str); 5] = [
    ("dns-benchmark", "benchmark", "每日評測"),
    ("cdn-ranges", "cdn-ranges", "CDN 範圍"),
    ("cdn-scan", "cdn-scan", "台灣網段掃描"),
    ("cdn-pool", "cdn-pool", "節點池"),
    ("tw-ip", "tw-ip", "台灣 IP 資料"),
];

/// 新鮮度的一項（`/api/status.freshness[]`）
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FreshItem {
    pub key: &'static str,
    pub label: &'static str,
    /// 上次成功（Unix 毫秒）；從來沒成功過是 `None`（`pending`）
    pub last_ok: Option<u64>,
    pub failing: bool,
    pub fails: u32,
    pub next: Option<u64>,
    /// 週期（毫秒）：上次成功距今超過 2 倍就是 `stale`
    pub period: Option<u64>,
    /// 由上游黑潮提供（串接中）
    pub chain: bool,
    pub failing_items: Option<usize>,
    pub note: Option<String>,
}

impl FreshItem {
    fn new(key: &'static str, label: &'static str) -> FreshItem {
        FreshItem {
            key,
            label,
            ..FreshItem::default()
        }
    }

    pub fn stale(&self, now: u64) -> bool {
        match (self.last_ok, self.period) {
            (Some(t), Some(p)) => now.saturating_sub(t) > p.saturating_mul(2),
            _ => false,
        }
    }

    pub fn json(&self, now: u64) -> Value {
        json!({
            "key": self.key, "label": self.label, "lastOkAt": self.last_ok, "failing": self.failing, "fails": self.fails,
            "nextAt": self.next, "stale": self.stale(now), "pending": self.last_ok.is_none(),
            "source": if self.chain { "chain" } else { "own" },
            "failingItems": self.failing_items, "note": self.note,
        })
    }
}

/// 排程工作的一項。`chain`：現在由上游黑潮提供（`catchUpProvided` 或 `share_skips()`）——
/// 上次成功取「自己跑完」與「從上游匯入」比較新的那一個，不算失敗
pub fn job_item(key: &'static str, label: &'static str, j: &JobFreshness, chain: bool, imported: Option<u64>) -> FreshItem {
    let mut it = FreshItem::new(key, label);
    it.next = j.next;
    it.period = j.period;
    if chain {
        it.chain = true;
        it.last_ok = match (j.last_ok, imported) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
    } else {
        it.last_ok = j.last_ok;
        it.failing = j.failing;
        it.fails = if j.failing { j.fails.max(1) } else { 0 };
    }
    it
}

/// 新鮮度的輸入（全部是已經有的狀態；`collect()` 從 [`AppState`] 讀，測試直接給）
#[derive(Debug, Clone, Default)]
pub struct FreshInputs {
    /// 排程工作（已經濾掉停用、沒註冊的；CDN 關著時呼叫端不給 CDN 的工作）
    pub jobs: Vec<(String, JobFreshness)>,
    /// 現在由上游提供的工作
    pub chain_jobs: Vec<String>,
    /// 從上游匯入的時間（種類 → 毫秒）
    pub chain_imported: HashMap<String, u64>,
    /// 台灣 IP 資料的產生時間（`TwIp.generated_at`）
    pub tw_ip_generated: Option<String>,
    /// 過濾清單：（上次成功, 失敗的清單數, 更新間隔毫秒）
    pub filter: Option<(Option<u64>, usize, u64)>,
    /// 路徑檢查開著時：上次檢查（毫秒；還沒檢查是 0）
    pub path_checked: Option<u64>,
    /// 串接中：（上次同步, 下次同步, 錯誤）
    pub chain_sync: Option<(Option<u64>, Option<u64>, Option<String>)>,
    /// 有好友時
    pub friends: Option<kuroshio_community::admin::SyncSummary>,
}

/// 純函式：組出新鮮度（固定順序、最多 [`FRESH_MAX`] 項）
pub fn fresh_items(inp: &FreshInputs) -> Vec<FreshItem> {
    let mut out = Vec::new();
    for (name, key, label) in JOBS {
        let Some((_, j)) = inp.jobs.iter().find(|(n, _)| n == name) else {
            continue;
        };
        let chain = inp.chain_jobs.iter().any(|n| n == name);
        let imported = crate::chain::share::job_kind(name).and_then(|k| inp.chain_imported.get(k).copied());
        let mut it = job_item(key, label, j, chain, imported);
        if name == "tw-ip" {
            it.note = inp
                .tw_ip_generated
                .as_deref()
                .filter(|g| g.len() >= 10 && g.is_char_boundary(10))
                .map(|g| format!("資料產生於 {}", &g[..10]));
        }
        out.push(it);
    }
    if let Some((last, errors, every)) = inp.filter {
        let mut it = FreshItem::new("filter-lists", "過濾清單");
        it.last_ok = last;
        it.failing = errors > 0;
        it.fails = (errors > 0) as u32;
        it.failing_items = Some(errors);
        it.period = Some(every);
        it.next = last.map(|t| t + every);
        out.push(it);
    }
    if let Some(at) = inp.path_checked {
        let mut it = FreshItem::new("path-check", "路徑檢查");
        it.last_ok = (at > 0).then_some(at);
        it.period = Some(PATH_EVERY_MS);
        it.next = it.last_ok.map(|t| t + PATH_EVERY_MS);
        out.push(it);
    }
    if let Some((last, next, err)) = &inp.chain_sync {
        let mut it = FreshItem::new("chain-sync", "串接同步");
        it.last_ok = *last;
        it.failing = err.is_some();
        it.fails = err.is_some() as u32;
        it.next = *next;
        it.period = Some(CHAIN_SYNC_EVERY_MS);
        it.chain = true;
        out.push(it);
    }
    if let Some(f) = &inp.friends {
        let mut it = FreshItem::new("friends-sync", "好友同步");
        it.last_ok = f.oldest_ok;
        it.failing = f.failing > 0;
        it.fails = f.max_fails;
        it.failing_items = Some(f.failing);
        it.next = f.next_try.or_else(|| f.oldest_ok.map(|t| t + f.interval_ms));
        it.period = Some(f.interval_ms.max(60_000));
        out.push(it);
    }
    out.truncate(FRESH_MAX);
    out
}

/// 從 [`AppState`] 讀新鮮度的輸入。排程器的鎖只拿一次（[`kuroshio_jobs::Scheduler::freshness`]）
fn fresh_inputs(st: &AppState) -> FreshInputs {
    let r = &st.resolver;
    let cdn_on = r.cdn().is_some();
    let names: Vec<&str> = JOBS.iter().map(|j| j.0).filter(|n| cdn_on || !n.starts_with("cdn-")).collect();
    let jobs = st.scheduler.as_ref().map(|s| s.freshness(&names)).unwrap_or_default();
    let mut chain_jobs: Vec<String> = jobs
        .iter()
        .filter(|(n, j)| j.provided || crate::chain::share_skips(n))
        .map(|(n, _)| n.clone())
        .collect();
    chain_jobs.dedup();
    let shared = crate::chain::share::shared_json();
    let chain_imported: HashMap<String, u64> = shared["objects"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|o| Some((o["kind"].as_str()?.to_string(), o["importedAt"].as_u64()?)))
                .collect()
        })
        .unwrap_or_default();
    let chain_sync = shared.is_object().then(|| {
        (
            shared["lastSyncAt"].as_u64(),
            shared["nextSyncAt"].as_u64(),
            shared["error"].as_str().map(str::to_string),
        )
    });
    let path_checked = crate::pathcheck::enabled().then(|| crate::pathcheck::status_json()["checkedAt"].as_u64().unwrap_or(0));
    FreshInputs {
        jobs,
        chain_jobs,
        chain_imported,
        tw_ip_generated: r.access.get().and_then(|a| a.data()).map(|t| t.generated_at.clone()),
        filter: st.filter.as_ref().map(|f| f.freshness()),
        path_checked,
        chain_sync,
        friends: st.community.as_ref().and_then(|c| c.sync_summary()),
    }
}

/// `/api/status` 的 `freshness`（E1）：每一種會過期的資料的上次成功、失敗中、連續失敗、下次預定；
/// 固定順序、最多 16 項；沒有啟用的功能（CDN 關、沒有好友、沒有串接）那一項不出現
pub fn freshness(st: &AppState) -> Value {
    let now = crate::backup::now_ms();
    fresh_value(&fresh_items(&fresh_inputs(st)), now)
}

fn fresh_value(items: &[FreshItem], now: u64) -> Value {
    Value::Array(items.iter().map(|i| i.json(now)).collect())
}

// ================= E2：發現清單 =================

/// 發現最多幾筆
pub const FINDINGS_MAX: usize = 32;
/// 兩次評估最少間隔（毫秒）
pub const EVAL_GAP_MS: u64 = 30_000;
/// 一句話最長幾個字元
pub const TEXT_MAX: usize = 200;
/// 次數上限
pub const COUNT_MAX: u32 = 9_999;
/// 多久沒再發生就拿掉：warn 24 小時、info 6 小時
pub const EXPIRE_WARN_MS: u64 = 24 * 3600 * 1000;
pub const EXPIRE_INFO_MS: u64 = 6 * 3600 * 1000;
/// 事件類的發現在最近一次發生後多久內算 `active`
const EVENT_ACTIVE_MS: u64 = 3600 * 1000;
/// 「最近一小時」的計數用的取樣：至少間隔 5 分鐘、最多 14 筆
const SAMPLE_GAP_MS: u64 = 5 * 60_000;
const SAMPLES_MAX: usize = 14;
const HOUR_MS: u64 = 3600 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Sev {
    Warn,
    Info,
}

impl Sev {
    fn as_str(self) -> &'static str {
        match self {
            Sev::Warn => "warn",
            Sev::Info => "info",
        }
    }
}

/// 一條規則這一次評估的結果
#[derive(Debug, Clone, PartialEq)]
pub enum Obs {
    /// 狀態類：條件成立（`on`）就更新最近時間；從不成立變成立時次數加 1。
    /// `hold_ms`：要持續成立這麼久才算（例如 reach-none 的 1 小時）
    State {
        key: &'static str,
        sev: Sev,
        on: bool,
        text: String,
        hold_ms: u64,
    },
    /// 事件類：來源模組自己的遞增計數與最近一次的時間（毫秒；0 = 不知道，用現在）。
    /// 次數用計數的增加量算，所以沒人開狀態頁的那幾天也是對的。`min_count`：累計到這麼多次才顯示
    Event {
        key: &'static str,
        sev: Sev,
        counter: u32,
        at: u64,
        text: String,
        min_count: u32,
    },
}

#[derive(Debug, Clone, PartialEq)]
struct Finding {
    key: &'static str,
    sev: Sev,
    text: String,
    count: u32,
    first_at: u64,
    last_at: u64,
    active: bool,
    min_count: u32,
}

impl Finding {
    fn json(&self) -> Value {
        json!({ "key": self.key, "sev": self.sev.as_str(), "text": self.text, "count": self.count,
                "firstAt": self.first_at, "lastAt": self.last_at, "active": self.active })
    }

    fn expire_ms(&self) -> u64 {
        match self.sev {
            Sev::Warn => EXPIRE_WARN_MS,
            Sev::Info => EXPIRE_INFO_MS,
        }
    }
}

/// 計數的取樣（算「最近一小時」用）
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Sample {
    pub at: u64,
    pub verify_ok: u32,
    pub verify_fail: u32,
}

/// 發現清單的狀態（只在記憶體；重新啟動、重新載入設定清空）
#[derive(Debug, Default)]
pub struct Engine {
    list: Vec<Finding>,
    /// 事件類：上一次看到的來源計數
    seen: HashMap<&'static str, u32>,
    /// 狀態類：條件從什麼時候開始一直成立（`hold_ms` 用）
    since: HashMap<&'static str, u64>,
    samples: Vec<Sample>,
    last_eval: Option<u64>,
    cached: Option<Value>,
}

fn clip(s: &str) -> String {
    if s.chars().count() <= TEXT_MAX {
        return s.to_string();
    }
    s.chars().take(TEXT_MAX - 1).chain(['…']).collect()
}

impl Engine {
    pub fn new() -> Engine {
        Engine::default()
    }

    /// 兩次評估至少間隔 30 秒：中間的請求回上一次的結果。`eval` 只在真的要評估時才呼叫
    pub fn evaluate(&mut self, now: u64, eval: impl FnOnce(&[Sample]) -> (Vec<Obs>, Sample)) -> Value {
        if let (Some(t), Some(v)) = (self.last_eval, &self.cached) {
            if now >= t && now - t < EVAL_GAP_MS {
                return v.clone();
            }
        }
        let (obs, sample) = eval(&self.samples);
        self.note_sample(sample);
        self.apply(&obs, now);
        let v = self.json();
        self.last_eval = Some(now);
        self.cached = Some(v.clone());
        v
    }

    fn note_sample(&mut self, s: Sample) {
        if self.samples.last().is_some_and(|l| s.at < l.at) {
            // 時鐘倒退：重新取樣
            self.samples.clear();
        }
        // MSRV 1.80 沒有 `Option::is_none_or`
        let gap_ok = match self.samples.last() {
            None => true,
            Some(l) => s.at.saturating_sub(l.at) >= SAMPLE_GAP_MS,
        };
        if gap_ok {
            self.samples.push(s);
            if self.samples.len() > SAMPLES_MAX {
                self.samples.remove(0);
            }
        }
    }

    pub fn apply(&mut self, obs: &[Obs], now: u64) {
        for o in obs {
            match o {
                Obs::State {
                    key,
                    sev,
                    on,
                    text,
                    hold_ms,
                } => {
                    if !*on {
                        self.since.remove(key);
                        if let Some(f) = self.list.iter_mut().find(|f| f.key == *key) {
                            f.active = false;
                        }
                        continue;
                    }
                    let since = *self.since.entry(key).or_insert(now);
                    if now.saturating_sub(since) < *hold_ms {
                        continue;
                    }
                    match self.list.iter_mut().find(|f| f.key == *key) {
                        Some(f) => {
                            if !f.active {
                                f.count = (f.count + 1).min(COUNT_MAX);
                            }
                            f.active = true;
                            f.last_at = now;
                            f.sev = *sev;
                            f.text = clip(text);
                        }
                        None => self.insert(Finding {
                            key,
                            sev: *sev,
                            text: clip(text),
                            count: 1,
                            first_at: now,
                            last_at: now,
                            active: true,
                            min_count: 0,
                        }),
                    }
                }
                Obs::Event {
                    key,
                    sev,
                    counter,
                    at,
                    text,
                    min_count,
                } => {
                    // 來源的計數變小（重新載入、來源重建）：當成從 0 開始
                    let prev = self.seen.insert(key, *counter).filter(|p| *p <= *counter).unwrap_or(0);
                    let delta = counter - prev;
                    let at = if *at == 0 || *at > now.saturating_add(60_000) { now } else { *at };
                    if delta > 0 {
                        match self.list.iter_mut().find(|f| f.key == *key) {
                            Some(f) => {
                                f.count = f.count.saturating_add(delta).min(COUNT_MAX);
                                f.last_at = f.last_at.max(at);
                                f.sev = *sev;
                                f.text = clip(text);
                            }
                            None => self.insert(Finding {
                                key,
                                sev: *sev,
                                text: clip(text),
                                count: delta.min(COUNT_MAX),
                                first_at: now,
                                last_at: at,
                                active: true,
                                min_count: *min_count,
                            }),
                        }
                    }
                    if let Some(f) = self.list.iter_mut().find(|f| f.key == *key) {
                        f.active = now.saturating_sub(f.last_at) < EVENT_ACTIVE_MS;
                    }
                }
            }
        }
        // 過期：不 active、最近一次超過 24 小時（info 6 小時）
        self.list.retain(|f| f.active || now.saturating_sub(f.last_at) <= f.expire_ms());
    }

    fn insert(&mut self, f: Finding) {
        if self.list.len() >= FINDINGS_MAX {
            // 滿了：先丟不 active 的 info，再丟 lastAt 最舊的
            let victim = self
                .list
                .iter()
                .enumerate()
                .filter(|(_, x)| !x.active && x.sev == Sev::Info)
                .min_by_key(|(_, x)| x.last_at)
                .or_else(|| self.list.iter().enumerate().min_by_key(|(_, x)| x.last_at))
                .map(|(i, _)| i);
            if let Some(i) = victim {
                self.list.remove(i);
            }
        }
        self.list.push(f);
    }

    /// 排序：warn 在前，同級依 lastAt 新的在前
    pub fn json(&self) -> Value {
        let mut v: Vec<&Finding> = self.list.iter().filter(|f| f.count >= f.min_count).collect();
        v.sort_by(|a, b| a.sev.cmp(&b.sev).then(b.last_at.cmp(&a.last_at)).then(a.key.cmp(b.key)));
        Value::Array(v.into_iter().map(Finding::json).collect())
    }
}

/// 「最近一小時」的基準：至少一小時前的取樣裡最新的一筆；都還不到一小時就用最舊的
fn hour_base(samples: &[Sample], now: u64) -> Option<Sample> {
    samples
        .iter()
        .rev()
        .find(|s| now.saturating_sub(s.at) >= HOUR_MS)
        .or_else(|| samples.first())
        .copied()
}

/// 名稱看起來不是網域、IP：只能是小寫英數與 `-`、最長 24 個字元（CDN 名稱、上游代號）
fn safe_name(s: &str) -> Option<&str> {
    (!s.is_empty() && s.len() <= 24 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')).then_some(s)
}

/// 機房代碼：大寫英文 3～4 個字
fn safe_pop(s: &str) -> Option<&str> {
    (s.len() >= 3 && s.len() <= 4 && s.bytes().all(|b| b.is_ascii_uppercase())).then_some(s)
}

fn city_of(pop: &str) -> &'static str {
    match pop.get(..3).unwrap_or("") {
        "TPE" | "TSA" => "台北",
        "KHH" => "高雄",
        "RMQ" | "TXG" => "台中",
        "TNN" => "台南",
        _ => "",
    }
}

/// 發現清單的輸入（全部是已經有的狀態）
#[derive(Debug, Clone, Default)]
pub struct FindInputs {
    pub now: u64,
    /// 上游：（暫停中、已經先不用 benched）；候補不算
    pub upstreams: Vec<(bool, bool)>,
    /// 最近 15 分鐘的（過期快取, 查詢）
    pub stale_15m: (u64, u64),
    /// 最近 15 分鐘背景更新失敗的次數（3.5.0 F3；跟 `stale_15m` 同一個時間窗）
    pub stale_fail_15m: u64,
    pub counters: kuroshio_cdn::ObserveCounters,
    /// `Cdn::observe_json()`（CDN 關著是 `null`）
    pub cdn_observe: Value,
    /// `cdn.prunedForBudget`
    pub cdn_pruned: Option<u32>,
    /// `Cdn::pace_json()`（3.5.0 F12：CDN 驗證節流；CDN 關著是 `null`）
    pub cdn_pace: Value,
    /// `/api/chain`（含 `audit`）
    pub chain: Value,
    /// 載入中、但沒有本機副本的清單數
    pub lists_without_copy: Option<usize>,
    /// E1 的結果
    pub fresh: Vec<FreshItem>,
    /// 好友：連續 3 次以上同步失敗的有幾個
    pub friends_failing3: usize,
    /// 節點池裡可用的節點數（不含壞的、最近節點型；`reach-none` 用）
    pub pool_nodes: usize,
    /// 記憶體控制的摘要（3.5.1 H3；記憶體控制關著是 None）
    pub memory: Option<crate::memgov::MemSummary>,
}

fn state(key: &'static str, sev: Sev, on: bool, text: String) -> Obs {
    Obs::State {
        key,
        sev,
        on,
        text,
        hold_ms: 0,
    }
}

fn event(key: &'static str, sev: Sev, counter: u32, at_secs: u32, text: String) -> Obs {
    Obs::Event {
        key,
        sev,
        counter,
        at: at_secs as u64 * 1000,
        text,
        min_count: 0,
    }
}

/// 純函式：每一條規則「讀現有狀態 → 有或沒有」。文字只放數量、CDN 名稱、機房代碼，不放網域與用戶端 IP
pub fn rules(i: &FindInputs, samples: &[Sample]) -> (Vec<Obs>, Sample) {
    let now = i.now;
    let c = &i.counters;
    let mut out = Vec::new();

    // 上游（不含從未成功、已經先不用的 benched）
    let ups: Vec<bool> = i.upstreams.iter().filter(|(_, benched)| !benched).map(|(p, _)| *p).collect();
    let paused = ups.iter().filter(|p| **p).count();
    let all_down = !ups.is_empty() && paused == ups.len();
    out.push(state(
        "upstream-all-down",
        Sev::Warn,
        all_down,
        format!("所有上游（{} 個）都在暫停中", ups.len()),
    ));
    out.push(state(
        "upstream-failing",
        Sev::Warn,
        paused > 0 && !all_down,
        format!("有 {paused} 個上游連續失敗、暫停中（會逐次拉長暫停時間，恢復後自動接回）"),
    ));

    // 過期快取
    // 3.5.0 F3（D23）：查詢少、重複多的家裡，過期的紀錄「先回舊答案、背景再更新」比例本來就高，不代表上游有狀況。
    // 四個都要成立：查詢 100 筆以上、過期佔 5% 以上、背景更新失敗 5 次以上、過期回答裡至少四分之一是更新失敗
    let (s15, q15) = i.stale_15m;
    let err15 = i.stale_fail_15m;
    let pct = if q15 > 0 { s15 as f64 * 100.0 / q15 as f64 } else { 0.0 };
    out.push(state(
        "serve-stale-high",
        Sev::Warn,
        q15 >= 100 && s15 * 20 >= q15 && err15 >= 5 && err15 * 4 >= s15,
        format!("最近 15 分鐘有 {pct:.0}% 的查詢靠過期快取回答，其中 {err15} 次背景更新失敗：上游可能有狀況"),
    ));

    // 台灣節點驗證失敗率（最近一小時）
    let sample = Sample {
        at: now,
        verify_ok: c.verify_ok,
        verify_fail: c.verify_fail,
    };
    let (ok_h, fail_h) = match hour_base(samples, now) {
        Some(b) if b.verify_ok <= c.verify_ok && b.verify_fail <= c.verify_fail => {
            (c.verify_ok - b.verify_ok, c.verify_fail - b.verify_fail)
        }
        _ => (0, 0),
    };
    let total_h = ok_h + fail_h;
    out.push(state(
        "cdn-verify-fail-high",
        Sev::Warn,
        total_h >= 20 && fail_h * 2 >= total_h,
        format!("最近一小時台灣節點驗證有 {fail_h}／{total_h} 次失敗"),
    ));

    // 串接
    let ch = &i.chain;
    let chained = ch["state"] == "chained";
    let since = ch["upstream"]["since"].as_u64();
    out.push(state(
        "chain-intercepted",
        Sev::Info,
        chained && ch["upstream"]["via"] == "intercept" && since.is_some_and(|t| now.saturating_sub(t) > 10 * 60_000),
        "串接超過 10 分鐘還是經由攔截（沒有換成直連閘道）".into(),
    ));
    let untrusted = ch["state"] == "released" && matches!(ch["reason"].as_str(), Some("tampered" | "pin-mismatch"));
    out.push(state(
        "chain-released-untrusted",
        Sev::Warn,
        untrusted,
        "因為上游黑潮不可信（答案被竄改或金鑰不符）解除了串接，先用自己的加密上游".into(),
    ));
    let releases = ch["audit"]["releases"].as_u64().map(|n| n.min(u32::MAX as u64) as u32).unwrap_or(0);
    out.push(Obs::Event {
        key: "chain-audit-released",
        sev: Sev::Warn,
        counter: releases,
        at: 0,
        text: "抽查上游黑潮給的答案不通過（憑證不符），解除了串接，稍後重試".into(),
        min_count: 0,
    });

    // 記憶體（3.5.1 H3）：以前吃緊、不足、連保護清單都暫停時只寫日誌，狀態頁、管理頁的發現清單看不到（D3 壓測）
    if let Some(m) = &i.memory {
        use crate::memgov::State;
        let mb = |b: u64| (b + 512 * 1024) / (1024 * 1024);
        let avail = m.avail.map_or_else(|| "量不到".to_string(), |a| format!("{} MB", mb(a)));
        let shed = if m.shed.is_empty() {
            "還沒有讓出任何東西".to_string()
        } else {
            format!("已經讓出：{}", m.shed.join("、"))
        };
        let tail = if m.protected {
            "；連保護清單都暫停了，只剩自訂規則".to_string()
        } else if m.floor {
            "；只轉送（CDN 調整暫停、快取最小）".to_string()
        } else {
            String::new()
        };
        out.push(state(
            "memory-tight",
            Sev::Warn,
            !m.futile && m.state == State::Tight,
            format!("記憶體吃緊（系統可用 {avail}，保留 {} MB）：停止長大，{shed}{tail}", mb(m.reserve)),
        ));
        out.push(state(
            "memory-critical",
            Sev::Warn,
            !m.futile && m.state == State::Critical,
            format!("記憶體不足（系統可用 {avail}，保留 {} MB）：{shed}{tail}", mb(m.reserve)),
        ));
        out.push(state(
            "memory-futile",
            Sev::Info,
            m.futile,
            format!(
                "系統可用記憶體 {avail}、低於保留量 {} MB，是其他程式造成的：黑潮只停止長大、照常回答",
                mb(m.reserve)
            ),
        ));
    }

    // 清單副本
    if let Some(n) = i.lists_without_copy {
        out.push(state(
            "list-copy-no-room",
            Sev::Info,
            n > 0,
            format!("有 {n} 份清單因為空間不足沒有留本機副本（重新啟動時要重新下載）"),
        ));
    }

    // 磁碟預算淘汰 CDN 網域資料
    if let Some(n) = i.cdn_pruned {
        out.push(event(
            "cdn-db-pruning",
            Sev::Info,
            n,
            0,
            format!("CDN 網域資料超過筆數上限（依磁碟預算與實際大小換算），淘汰了最久沒用的（累計 {n} 筆）"),
        ));
    }

    // 背景工作連續失敗（E1）
    let failing: Vec<String> = i
        .fresh
        .iter()
        .filter(|f| f.fails >= 3)
        .map(|f| format!("{}（{} 次）", f.label, f.fails))
        .collect();
    out.push(state(
        "job-failing",
        Sev::Warn,
        !failing.is_empty(),
        format!("背景工作連續失敗：{}", failing.join("、")),
    ));

    // 好友
    out.push(state(
        "friends-sync-failing",
        Sev::Info,
        i.friends_failing3 > 0,
        format!("有 {} 位好友連續 3 次以上同步失敗", i.friends_failing3),
    ));

    // ---- 線路感知（甲批：E3～E7；欄位還沒有時都不成立）----
    let reach = &i.cdn_observe["reach"];
    if reach.is_object() {
        let pops = |fam: &str| reach[fam]["pops"].as_array().cloned().unwrap_or_default();
        let (p4, p6) = (pops("v4"), pops("v6"));
        let cities = |p: &[Value]| {
            let mut v: Vec<&str> = p
                .iter()
                .filter_map(|x| x["pop"].as_str())
                .map(city_of)
                .filter(|c| !c.is_empty())
                .collect();
            v.dedup();
            v
        };
        let c4 = cities(&p4);
        let single = c4.len() == 1 && cities(&p6).iter().all(|c| *c == c4[0]);
        out.push(state(
            "reach-single-pop",
            Sev::Info,
            single,
            format!("這條線目前只到得了{}機房", c4.first().copied().unwrap_or("")),
        ));
        // 節點池有節點（不含壞的、最近節點型）但沒有任何一個確認在台灣機房；WAN 剛變動、串接中（reach.stale）不算
        out.push(Obs::State {
            key: "reach-none",
            sev: Sev::Warn,
            on: p4.is_empty() && p6.is_empty() && i.pool_nodes > 0 && reach["stale"] != true,
            text: "節點池有節點，但超過 1 小時沒有任何一個確認在台灣機房".into(),
            hold_ms: HOUR_MS,
        });
    }
    if c.pop_mismatch > 0 {
        out.push(Obs::Event {
            key: "pop-mismatch",
            sev: Sev::Warn,
            counter: c.pop_mismatch,
            at: c.pop_mismatch_at as u64 * 1000,
            text: format!(
                "上游給的節點有 {} 個從這台量到的機房不一樣（上游可能有多條對外線路）；已經改用這台量到的",
                c.pop_mismatch
            ),
            min_count: 2,
        });
    }
    if c.pop_switches > 0 {
        // 目前暫緩哪個機房、到幾點（`popSwitch.holds[]`：provider、family、pop、until 毫秒、other）
        let held = i.cdn_observe["popSwitch"]["holds"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|h| {
                let p = safe_name(h["provider"].as_str()?)?;
                let pop = safe_pop(h["pop"].as_str()?)?;
                let until = h["until"].as_u64().map(|t| {
                    let t = if t < 10_000_000_000 { t * 1000 } else { t };
                    kuroshio_jobs::time::fmt_date_time(t)
                });
                Some(format!(
                    "機房切換：{p} 的 IPv{} 把 {pop} 機房的節點暫時排到後面{}",
                    h["family"].as_u64().unwrap_or(4),
                    until.map(|u| format!("（到 {u}）")).unwrap_or_default()
                ))
            })
            .unwrap_or_else(|| "機房切換：把狀況不好的機房的節點暫時排到後面，幾小時後自動恢復".into());
        out.push(event("pop-switched", Sev::Info, c.pop_switches, c.pop_switch_at, held));
    }
    if c.pop_flapping > 0 {
        out.push(event(
            "pop-flapping",
            Sev::Warn,
            c.pop_flapping,
            c.pop_flapping_at,
            "一天內第 3 次想切換機房：不切換，只回報（機房可能時好時壞）".into(),
        ));
    }
    if c.slower_fallback > 0 {
        out.push(event(
            "slower-fallback",
            Sev::Info,
            c.slower_fallback,
            c.slower_fallback_at,
            format!(
                "有網站的台灣節點實測比原本的答案慢，暫時用原本的答案、幾小時後重測（累計 {} 次）",
                c.slower_fallback
            ),
        ));
    }
    let fuse = c.slower_fuse_until as u64 * 1000;
    out.push(state(
        "slower-fuse",
        Sev::Warn,
        fuse > now,
        format!(
            "太多網站都量到「台灣節點比原本慢」，可能是線路當下壅塞或量測有問題：{} 前照常換台灣節點",
            kuroshio_jobs::time::fmt_date_time(fuse)
        ),
    ));

    // 3.5.0 F12：新網域很多（或 CPU 很忙），CDN 驗證減量中（狀態類；欄位不齊時不報）。
    // `cdn.lite` 的機器永遠在減量（`paced` 一直是 true），那是它的常態、不是狀況，不報
    let paced = i.cdn_pace["paced"] == true && i.cdn_pace["lite"] != true;
    let per_min = i.cdn_pace["perMin"].as_u64().unwrap_or(0);
    out.push(state(
        "cdn-verify-paced",
        Sev::Info,
        paced && per_min > 0,
        format!("新網域很多，CDN 驗證減量中（每分鐘 {per_min} 個）"),
    ));
    (out, sample)
}

static ENGINE: Mutex<Option<Engine>> = Mutex::new(None);

/// 重新載入設定：發現清單清空（狀態類的下一次評估就回來）
pub fn reset_findings() {
    *ENGINE.lock().unwrap() = None;
}

fn find_inputs(st: &AppState, now: u64) -> FindInputs {
    let r = &st.resolver;
    let upstreams = r
        .upstreams
        .list_json()
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|u| u["spare"] != true)
                .map(|u| (u["paused"] == true, u["benched"] == true))
                .collect()
        })
        .unwrap_or_default();
    let cdn = r.cdn();
    FindInputs {
        now,
        upstreams,
        stale_15m: r.stats.stale_15m(),
        stale_fail_15m: r.stats.stale_refresh_fail_15m(),
        counters: cdn.as_ref().map(|c| c.observe_counters()).unwrap_or_default(),
        cdn_observe: cdn.as_ref().map(|c| c.observe_json()).unwrap_or(Value::Null),
        cdn_pace: cdn.as_ref().map(|c| c.pace_json()).unwrap_or(Value::Null),
        pool_nodes: cdn.as_ref().map_or(0, |c| {
            let st = c.state();
            st.pools
                .p
                .iter()
                .filter(|(name, _)| kuroshio_cdn::providers::get(name).is_some_and(|p| !p.nearest))
                .map(|(_, d)| d.pool4.iter().chain(&d.pool6).filter(|x| !d.bad.contains_key(&x.ip)).count())
                .sum()
        }),
        cdn_pruned: cdn
            .as_ref()
            .and_then(|c| c.status_lite()["prunedForBudget"].as_u64())
            .map(|n| n.min(u32::MAX as u64) as u32),
        chain: crate::chain::client::api_json(),
        lists_without_copy: st.filter.as_ref().and_then(|f| f.lists_without_copy()),
        fresh: fresh_items(&fresh_inputs(st)),
        friends_failing3: st.community.as_ref().and_then(|c| c.sync_summary()).map_or(0, |s| s.failing3),
        memory: st.memgov.as_ref().map(|g| g.finding_summary()),
    }
}

/// `/api/status` 的 `findings`（E2）：觀察到的現象與它的經過（嚴重度、一句話、次數、第一次與最近一次）；
/// 用 `key` 去重、最多 32 筆、不再發生就過期。兩次評估至少間隔 30 秒，系統時間還沒對時回 `[]`。
/// `firstAt` 是這台第一次看到的時間（沒人開狀態頁時可能比實際晚）
pub fn findings(st: &AppState) -> Value {
    let now = crate::backup::now_ms();
    findings_guarded(&ENGINE, crate::clock::synced(), now, || find_inputs(st, now))
}

/// [`findings`] 的本體（測試用）：沒對時不評估、回 `[]`；`inputs` 只在真的要評估時才讀
fn findings_guarded(engine: &Mutex<Option<Engine>>, synced: bool, now: u64, inputs: impl FnOnce() -> FindInputs) -> Value {
    if !synced {
        return Value::Array(Vec::new());
    }
    let mut g = engine.lock().unwrap();
    g.get_or_insert_with(Engine::new).evaluate(now, |samples| rules(&inputs(), samples))
}

// ================= E10：ISP 群組 =================

/// 群組 id 的格式：最長 16 個字元，只能是小寫英數、`-`、`_`（不符就當沒有）
pub fn valid_isp(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 16
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// 純函式：對外 IPv4 子網路落在某一群、而且不是 `other` → 那一群的 `id`
pub fn isp_group_of(wan: Option<(IpAddr, u8)>, tw: Option<&TwIp>) -> Option<String> {
    let (ip, _) = wan?;
    let tw = tw?;
    let g = tw.groups.iter().find(|g| g.nets.contains(ip))?;
    (g.id != "other" && valid_isp(&g.id)).then(|| g.id.clone())
}

struct IspSources {
    wan: Option<(IpAddr, u8)>,
    tw: Option<Arc<TwIp>>,
    group: Option<String>,
}

static ISP: Mutex<IspSources> = Mutex::new(IspSources {
    wan: None,
    tw: None,
    group: None,
});

/// 這台 WAN 的 ISP 群組（E10，`tw-ip.json` 的群組 `id`，例如 `cht`）：對外 IPv4 的 /24 落在某一群、而且不是 `other`
/// 才有；偵測不到對外 IP、不在任何一群、落在 `other`、台灣 IP 資料讀不到都是 `None`。
/// 要不要送給好友由 `community.shareIspGroup` 決定（呼叫端判斷）。
pub fn isp_group() -> Option<String> {
    ISP.lock().unwrap().group.clone()
}

/// 更新 [`isp_group`] 的來源：對外 IP 的子網路（`Resolver::ecs_subnet`，啟動與 WAN 變動時偵測）與
/// 目前載入的台灣 IP 資料（`Access::data()`）。任一個變動時呼叫一次，群組在這裡重算、存成一個字串。
pub fn set_isp_sources(wan_subnet: Option<(IpAddr, u8)>, tw_ip: Option<Arc<TwIp>>) {
    let mut s = ISP.lock().unwrap();
    s.wan = wan_subnet;
    s.tw = tw_ip;
    s.group = isp_group_of(s.wan, s.tw.as_deref());
}

/// 只換台灣 IP 資料（`tw-ip` 工作換上新的資料時），對外 IP 沿用上一次的
pub fn set_isp_tw_ip(tw_ip: Option<Arc<TwIp>>) {
    let wan = ISP.lock().unwrap().wan;
    set_isp_sources(wan, tw_ip);
}

#[cfg(test)]
mod tests;
