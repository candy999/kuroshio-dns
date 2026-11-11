//! 背景工作排程器（對齊 2.x `lib/scheduler.js`）
//!
//! - 每天 / 每週定時（台北時間，`jobs.<name>.at`、`weekdays`），時間到就排入佇列。
//! - 啟動補跑：缺少 `runIfMissing` 指定的檔案，或上次成功已超過週期（伺服器在排定時間沒開著），
//!   延遲 `startDelaySec` 秒後先跑一次。
//! - 同一時間只跑一個工作；超過 `timeoutMin` 分鐘強制結束。
//! - 2.x 用子程序跑工作，3.0 改成同一個程序裡的 tokio task：工作自己要切小段、呼叫
//!   `JobCtx::checkpoint()` 讓出 CPU（規格 05 第 4 節），強制結束就是把 future 丟掉。
//! - 狀態（`jobs.json`）不自己寫檔：`snapshot()` 交給呼叫者排進快照（規格 05 第 5 節）。
//! - `should_defer`（例如記憶體不足）回 true 時不啟動新工作，執行中的工作在 checkpoint 暫停。

use crate::lock::JobLock;
use crate::time::{self, Clock, SystemClock, DAY_MS, MIN_MS};
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;
use tracing::{error, info, warn};

/// 快照裡的檔名（同 2.x 的 `state/jobs.json`）
pub const JOBS_STATE_FILE: &str = "jobs.json";

/// 工作逾時時的結束碼（同指令列 `timeout`）
pub const CODE_TIMEOUT: i64 = 124;

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;
pub type DeferFn = Arc<dyn Fn() -> bool + Send + Sync>;

/// 一個背景工作。閉包 `Fn(JobCtx) -> impl Future<Output = anyhow::Result<()>>` 也可以直接註冊。
pub trait Job: Send + Sync + 'static {
    fn run(&self, ctx: JobCtx) -> BoxFuture<anyhow::Result<()>>;
}

impl<F, Fut> Job for F
where
    F: Fn(JobCtx) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    fn run(&self, ctx: JobCtx) -> BoxFuture<anyhow::Result<()>> {
        Box::pin(self(ctx))
    }
}

/// 交給工作的環境：目前的完整設定、時鐘、讓出 CPU / 暫停的 checkpoint
#[derive(Clone)]
pub struct JobCtx {
    pub name: String,
    pub reason: String,
    /// 工作開始時的完整設定（含等級預設值）
    pub cfg: Arc<Value>,
    pub clock: Arc<dyn Clock>,
    defer: Option<DeferFn>,
    defer_poll: Duration,
}

impl JobCtx {
    /// 單獨執行（指令列、測試）：系統時鐘、不會暫停
    pub fn new(name: &str, reason: &str, cfg: Arc<Value>) -> JobCtx {
        JobCtx {
            name: name.to_string(),
            reason: reason.to_string(),
            cfg,
            clock: Arc::new(SystemClock),
            defer: None,
            defer_poll: Duration::from_secs(5),
        }
    }

    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> JobCtx {
        self.clock = clock;
        self
    }

    pub fn with_defer(mut self, f: DeferFn, poll: Duration) -> JobCtx {
        self.defer = Some(f);
        self.defer_poll = poll;
        self
    }

    pub fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    pub fn should_defer(&self) -> bool {
        self.defer.as_ref().map(|f| f()).unwrap_or(false)
    }

    /// 每做完一小段就呼叫：讓出 CPU 給 DNS；系統吃緊時在這裡等到恢復
    pub async fn checkpoint(&self) {
        tokio::task::yield_now().await;
        if self.should_defer() {
            info!("[{}] 系統資源吃緊，工作暫停", self.name);
            while self.should_defer() {
                tokio::time::sleep(self.defer_poll).await;
            }
            info!("[{}] 恢復執行", self.name);
        }
    }
}

/// 2.x 的相對路徑（`state/xxx`、`./data/xxx`）換成實際路徑：`state/` 開頭的放到 state 目錄，其他相對於 `base_dir`
pub fn resolve_path(state_dir: &Path, base_dir: &Path, rel: &str) -> PathBuf {
    let p = Path::new(rel);
    if p.is_absolute() {
        return p.to_path_buf();
    }
    let r = rel.trim_start_matches("./");
    match r.strip_prefix("state/") {
        Some(rest) => state_dir.join(rest),
        None if r == "state" => state_dir.to_path_buf(),
        None => base_dir.join(r),
    }
}

pub type ExistsFn = Arc<dyn Fn(&str) -> bool + Send + Sync>;

pub struct Options {
    pub clock: Arc<dyn Clock>,
    /// 回 true 時不啟動新工作；執行中的工作在 checkpoint 暫停（例如記憶體不足）
    pub should_defer: Option<DeferFn>,
    /// `runIfMissing` 的檔案在不在（參數是設定裡的原始字串，例如 `state/upstreams.json`）
    pub file_exists: ExistsFn,
    /// 鎖檔目錄（與指令列互斥）；None 不用鎖檔
    pub lock_dir: Option<PathBuf>,
    /// 狀態有變（工作開始 / 結束）時呼叫，讓呼叫者把 `snapshot()` 排進快照
    pub on_state_change: Option<Arc<dyn Fn() + Send + Sync>>,
    /// 多久檢查一次排程（2.x 是 30 秒）
    pub tick_interval: Duration,
    /// 暫停中的工作多久檢查一次能不能繼續
    pub defer_poll: Duration,
    /// 排定時間過了多久內還算數（檢查被延誤時不會錯過）
    pub slot_grace_ms: u64,
}

impl Options {
    pub fn new(state_dir: impl Into<PathBuf>, base_dir: impl Into<PathBuf>) -> Options {
        let (state_dir, base_dir) = (state_dir.into(), base_dir.into());
        Options {
            clock: Arc::new(SystemClock),
            should_defer: None,
            file_exists: Arc::new(move |rel: &str| resolve_path(&state_dir, &base_dir, rel).exists()),
            lock_dir: None,
            on_state_change: None,
            tick_interval: Duration::from_secs(30),
            defer_poll: Duration::from_secs(5),
            slot_grace_ms: 5 * MIN_MS,
        }
    }
}

// ---------------- 時間計算（純函式） ----------------

/// `at`（"HH:MM" 字串或陣列）→ 當天第幾分鐘，排序、去重
pub fn at_minutes(c: &Value) -> Vec<u32> {
    let list: Vec<&Value> = match c.get("at") {
        Some(Value::Array(a)) => a.iter().collect(),
        Some(v @ Value::String(_)) => vec![v],
        _ => Vec::new(),
    };
    let mut out: Vec<u32> = list
        .into_iter()
        .filter_map(Value::as_str)
        .filter_map(|s| {
            let (h, m) = s.trim().split_once(':')?;
            let (h, m): (u32, u32) = (h.parse().ok()?, m.parse().ok()?);
            (h < 24 && m < 60).then_some(h * 60 + m)
        })
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// `weekdays`（0 = 星期日）；不是陣列就是每天
pub fn weekdays(c: &Value) -> Option<Vec<u32>> {
    c.get("weekdays")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_u64).map(|d| d as u32).collect())
}

fn enabled(c: &Value) -> bool {
    c.get("enabled") != Some(&Value::Bool(false))
}

/// 排程時間點（Unix 毫秒），依時間遞增；`from_day` 到 `to_day` 是相對今天（台北）的天數
fn slots(c: &Value, now: u64, from_day: i64, to_day: i64) -> Vec<u64> {
    let times = at_minutes(c);
    let wd = weekdays(c);
    let today = time::taipei_midnight(now) as i64;
    let mut out = Vec::new();
    for off in from_day..=to_day {
        let start = today + off * DAY_MS as i64;
        if start < 0 {
            continue;
        }
        let w = time::taipei_parts(start as u64).weekday;
        if wd.as_ref().map(|l| !l.contains(&w)).unwrap_or(false) {
            continue;
        }
        out.extend(times.iter().map(|m| start as u64 + *m as u64 * MIN_MS));
    }
    out
}

/// 下次排定的時間（嚴格晚於 now）；停用或沒有 `at` 回 None
pub fn next_run(c: &Value, now: u64) -> Option<u64> {
    if !enabled(c) {
        return None;
    }
    slots(c, now, 0, 7).into_iter().find(|s| *s > now)
}

/// 最近一次已經到的排定時間（≤ now）
pub fn last_slot(c: &Value, now: u64) -> Option<u64> {
    slots(c, now, -7, 0).into_iter().rev().find(|s| *s <= now)
}

/// 排程戳記（同 2.x 的 lastSlot：`YYYY-MM-DD HH:MM`，台北）
pub fn slot_stamp(ms: u64) -> String {
    let p = time::taipei_parts(ms);
    format!("{} {:02}:{:02}", time::local_date_str(ms), p.h, p.mi)
}

fn start_delay_sec(c: &Value) -> u64 {
    match c.get("startDelaySec").and_then(Value::as_f64) {
        Some(s) if s > 0.0 => s as u64,
        _ => 60, // 同 2.x 的 `|| 60`
    }
}

fn timeout_min(c: &Value) -> f64 {
    match c.get("timeoutMin").and_then(Value::as_f64) {
        Some(m) if m > 0.0 => m,
        _ => 180.0,
    }
}

fn ms_field(st: Option<&Value>, k: &str) -> Option<u64> {
    st.and_then(|s| s.get(k))
        .and_then(Value::as_f64)
        .filter(|v| *v > 0.0)
        .map(|v| v as u64)
}

// ---------------- 排程器 ----------------

struct Running {
    name: String,
    reason: String,
    started_at: u64,
}

struct St {
    cfg: Arc<Value>,
    state: Map<String, Value>,
    queue: VecDeque<(String, String)>,
    running: Option<Running>,
    defer_logged: bool,
    unknown_warned: HashSet<String>,
    started_ms: Option<u64>,
    /// 上次 `tick` 的時間：兩次檢查之間跨過了排定時間（系統休眠、時鐘往前跳）就知道是錯過了
    last_tick: Option<u64>,
}

struct Inner {
    opts: Options,
    jobs: Mutex<HashMap<String, Arc<dyn Job>>>,
    st: Mutex<St>,
    notify: Notify,
}

#[derive(Clone)]
pub struct Scheduler {
    inner: Arc<Inner>,
}

impl Scheduler {
    /// `cfg` 是完整設定（讀 `jobs.*`，並原樣交給工作）；`saved` 是上次的 `jobs.json` 內容
    pub fn new(cfg: Value, saved: Option<&[u8]>, opts: Options) -> Scheduler {
        let state = saved
            .and_then(|b| serde_json::from_slice::<Value>(b.strip_prefix("\u{feff}".as_bytes()).unwrap_or(b)).ok())
            .and_then(|v| match v {
                Value::Object(m) => Some(m),
                _ => None,
            })
            .unwrap_or_default();
        Scheduler {
            inner: Arc::new(Inner {
                opts,
                jobs: Mutex::new(HashMap::new()),
                st: Mutex::new(St {
                    cfg: Arc::new(cfg),
                    state,
                    queue: VecDeque::new(),
                    running: None,
                    defer_logged: false,
                    unknown_warned: HashSet::new(),
                    started_ms: None,
                    last_tick: None,
                }),
                notify: Notify::new(),
            }),
        }
    }

    /// 註冊工作（其他 crate 的工作也一樣，例如 CDN 的 cdn-ranges / cdn-scan / cdn-pool）
    pub fn register(&self, name: &str, job: impl Job) {
        self.inner.jobs.lock().unwrap().insert(name.to_string(), Arc::new(job));
    }

    pub fn register_arc(&self, name: &str, job: Arc<dyn Job>) {
        self.inner.jobs.lock().unwrap().insert(name.to_string(), job);
    }

    pub fn is_registered(&self, name: &str) -> bool {
        self.inner.jobs.lock().unwrap().contains_key(name)
    }

    /// 設定重新載入
    pub fn set_config(&self, cfg: Value) {
        self.inner.st.lock().unwrap().cfg = Arc::new(cfg);
        self.inner.notify.notify_one();
    }

    fn jobs_cfg(cfg: &Value) -> Map<String, Value> {
        cfg.get("jobs").and_then(Value::as_object).cloned().unwrap_or_default()
    }

    /// 啟動：排好補跑、開始定時檢查。要在 tokio runtime 裡呼叫。
    pub fn start(&self) -> tokio::task::JoinHandle<()> {
        let now = self.inner.opts.clock.now_ms();
        self.inner.st.lock().unwrap().started_ms = Some(now);
        for (name, delay, why) in self.catch_up_plan() {
            let me = self.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(delay)).await;
                me.request(&name, &why);
            });
        }
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                me.tick();
                me.try_start_next();
                tokio::select! {
                    _ = me.inner.notify.notified() => {}
                    _ = tokio::time::sleep(me.inner.opts.tick_interval) => {}
                }
            }
        })
    }

    /// 啟動補跑的計畫：（工作、延遲秒數、原因），依延遲排序
    pub fn catch_up_plan(&self) -> Vec<(String, u64, String)> {
        let now = self.inner.opts.clock.now_ms();
        let (cfg, state) = {
            let st = self.inner.st.lock().unwrap();
            (Self::jobs_cfg(&st.cfg), st.state.clone())
        };
        let mut list: Vec<(&String, &Value)> = cfg.iter().filter(|(n, c)| enabled(c) && self.is_registered(n)).collect();
        list.sort_by_key(|(_, c)| start_delay_sec(c));
        let mut out = Vec::new();
        for (name, c) in list {
            let st = state.get(name.as_str());
            let period = if weekdays(c).is_some() { 7 } else { 1 } * DAY_MS;
            let rim = c.get("runIfMissing").and_then(Value::as_str).filter(|s| !s.is_empty());
            let missing = rim.map(|p| !(self.inner.opts.file_exists)(p)).unwrap_or(false);
            let ok_code = st.and_then(|s| s.get("lastCode")).and_then(Value::as_i64) == Some(0);
            let last_ok = if ok_code {
                ms_field(st, "lastEnd")
            } else {
                ms_field(st, "lastOkEnd")
            };
            let stale = c.get("catchUp") != Some(&Value::Bool(false))
                && last_ok.map(|t| now.saturating_sub(t) as f64 > period as f64 * 1.05).unwrap_or(true);
            if !missing && !stale {
                continue;
            }
            let why = if missing {
                format!("首次執行（缺少 {}）", rim.unwrap_or_default())
            } else {
                format!(
                    "補跑（上次成功 {}）",
                    last_ok.map(time::fmt_date_time).unwrap_or_else(|| "無紀錄".into())
                )
            };
            out.push((name.clone(), start_delay_sec(c), why));
        }
        out
    }

    /// 檢查排定時間；回傳這次排入的工作。
    ///
    /// 排定時間過了寬限（`slot_grace_ms`）才檢查到的：程式一直在跑、只是兩次檢查之間跨過了排定時間
    /// （系統休眠、時鐘往前跳）就補跑一次——錯過好幾次也只跑一次，排定時間之後已經跑過的不再跑。
    /// 程式剛啟動（還沒檢查過）時錯過的交給 `catch_up_plan`
    pub fn tick(&self) -> Vec<String> {
        let now = self.inner.opts.clock.now_ms();
        let mut due = Vec::new();
        {
            let mut st = self.inner.st.lock().unwrap();
            let started = st.started_ms.unwrap_or(0);
            let prev = st.last_tick.replace(now);
            for (name, c) in Self::jobs_cfg(&st.cfg) {
                if !enabled(&c) {
                    continue;
                }
                let Some(s) = last_slot(&c, now) else { continue };
                if s < started {
                    continue;
                }
                let late = now - s > self.inner.opts.slot_grace_ms;
                // 上次檢查時還沒到這個時間點 = 執行期間錯過的（不是啟動前錯過的）
                if late && !prev.map(|p| p < s).unwrap_or(false) {
                    continue;
                }
                let stamp = slot_stamp(s);
                let entry = st.state.entry(name.clone()).or_insert_with(|| json!({}));
                if entry.get("lastSlot").and_then(Value::as_str) == Some(stamp.as_str()) {
                    continue;
                }
                // 補跑：排定時間之後已經開始跑過（手動、其他模組觸發）就不必再跑
                let ran_since = late && ms_field(Some(&*entry), "lastStart").map(|t| t >= s).unwrap_or(false);
                if let Some(o) = entry.as_object_mut() {
                    o.insert("lastSlot".into(), Value::String(stamp.clone()));
                } else {
                    *entry = json!({ "lastSlot": stamp });
                }
                if ran_since {
                    continue;
                }
                if late {
                    info!("工作 {name} 錯過排定時間 {stamp}（系統休眠或時鐘跳動），補跑一次");
                }
                due.push((name, late));
            }
        }
        let mut queued = Vec::new();
        for (name, late) in due {
            if !self.is_registered(&name) {
                let mut st = self.inner.st.lock().unwrap();
                if st.unknown_warned.insert(name.clone()) {
                    warn!("排程工作 {name} 在這個版本沒有實作，略過");
                }
                continue;
            }
            if self.request(&name, if late { "排程（補跑錯過的）" } else { "排程" })["ok"] == json!(true) {
                queued.push(name);
            }
        }
        queued
    }

    /// 排入工作（手動、補跑、其他模組觸發）
    pub fn request(&self, name: &str, reason: &str) -> Value {
        self.request_with_gap(name, reason, 0.0)
    }

    /// 同 `request`，但 `min_gap_min` 分鐘內跑過的就忽略（2.x 的 `{ minGapMin }`）
    pub fn request_with_gap(&self, name: &str, reason: &str, min_gap_min: f64) -> Value {
        if !self.is_registered(name) {
            return json!({ "ok": false, "error": "未知的工作" });
        }
        let now = self.inner.opts.clock.now_ms();
        {
            let mut st = self.inner.st.lock().unwrap();
            if st.running.as_ref().map(|r| r.name == name).unwrap_or(false) {
                return json!({ "ok": false, "error": "執行中" });
            }
            if st.queue.iter().any(|(n, _)| n == name) {
                return json!({ "ok": false, "error": "已在佇列" });
            }
            if min_gap_min > 0.0 {
                if let Some(last) = ms_field(st.state.get(name), "lastEnd") {
                    if (now.saturating_sub(last) as f64) < min_gap_min * MIN_MS as f64 {
                        return json!({ "ok": false, "error": "剛執行過" });
                    }
                }
            }
            st.queue.push_back((name.to_string(), reason.to_string()));
        }
        info!("排入工作 {name}（{reason}）");
        self.inner.notify.notify_one();
        json!({ "ok": true })
    }

    /// 佇列裡有工作、目前沒在跑、系統不吃緊 → 啟動下一個。回傳有沒有啟動。
    pub fn try_start_next(&self) -> bool {
        let defer = self.inner.opts.should_defer.as_ref().map(|f| f()).unwrap_or(false);
        let picked = {
            let mut st = self.inner.st.lock().unwrap();
            if st.running.is_some() || st.queue.is_empty() {
                return false;
            }
            if defer {
                if !st.defer_logged {
                    st.defer_logged = true;
                    info!("系統資源吃緊，背景工作延後（佇列 {} 個）", st.queue.len());
                }
                return false;
            }
            st.defer_logged = false;
            let mut picked = None;
            while let Some((name, reason)) = st.queue.pop_front() {
                let Some(job) = self.inner.jobs.lock().unwrap().get(&name).cloned() else {
                    continue;
                };
                let lock = match &self.inner.opts.lock_dir {
                    Some(dir) => match JobLock::acquire(dir, &name) {
                        Ok(l) => Some(l),
                        Err(pid) => {
                            info!("{name} 已在另一個程序執行中（PID {pid}），略過");
                            continue;
                        }
                    },
                    None => None,
                };
                let now = self.inner.opts.clock.now_ms();
                st.running = Some(Running {
                    name: name.clone(),
                    reason: reason.clone(),
                    started_at: now,
                });
                let entry = st.state.entry(name.clone()).or_insert_with(|| json!({}));
                if !entry.is_object() {
                    *entry = json!({});
                }
                let o = entry.as_object_mut().unwrap();
                o.insert("lastStart".into(), Value::from(now));
                o.insert("reason".into(), Value::String(reason.clone()));
                let c = Self::jobs_cfg(&st.cfg).get(&name).cloned().unwrap_or(Value::Null);
                let mut ctx = JobCtx::new(&name, &reason, st.cfg.clone()).with_clock(self.inner.opts.clock.clone());
                if let Some(f) = &self.inner.opts.should_defer {
                    ctx = ctx.with_defer(f.clone(), self.inner.opts.defer_poll);
                }
                picked = Some((job, ctx, timeout_min(&c), lock));
                break;
            }
            picked
        };
        let Some((job, ctx, tmin, lock)) = picked else {
            return false;
        };
        self.changed();
        info!("開始工作 {}（{}）", ctx.name, ctx.reason);
        let me = self.clone();
        tokio::spawn(async move {
            let name = ctx.name.clone();
            let fut = job.run(ctx);
            let limit = Duration::from_secs_f64(tmin * 60.0);
            // 另開 task：工作 panic 時排程器不會跟著停
            let res = tokio::spawn(tokio::time::timeout(limit, fut)).await;
            let (code, err) = match res {
                Ok(Ok(Ok(()))) => (0, None),
                Ok(Ok(Err(e))) => {
                    error!("[{name}] 失敗：{e:#}");
                    (1, Some(format!("{e:#}")))
                }
                Ok(Err(_)) => {
                    warn!("{name} 執行超過 {tmin} 分鐘，強制結束");
                    (CODE_TIMEOUT, Some(format!("執行超過 {tmin} 分鐘，強制結束")))
                }
                Err(e) => {
                    error!("[{name}] 異常結束：{e}");
                    (1, Some(format!("異常結束：{e}")))
                }
            };
            drop(lock);
            me.finish(&name, code, err);
        });
        true
    }

    fn finish(&self, name: &str, code: i64, err: Option<String>) {
        let now = self.inner.opts.clock.now_ms();
        {
            let mut st = self.inner.st.lock().unwrap();
            let started = st.running.as_ref().map(|r| r.started_at).unwrap_or(now);
            let entry = st.state.entry(name.to_string()).or_insert_with(|| json!({}));
            if !entry.is_object() {
                *entry = json!({});
            }
            let o = entry.as_object_mut().unwrap();
            o.insert("lastEnd".into(), Value::from(now));
            o.insert("lastCode".into(), Value::from(code));
            if code == 0 {
                o.insert("lastOkEnd".into(), Value::from(now));
                o.remove("lastError");
            } else if let Some(e) = err {
                o.insert("lastError".into(), Value::String(e));
            }
            st.running = None;
            info!("{name} 完成 (code {code})，耗時 {} 秒", (now.saturating_sub(started) + 500) / 1000);
        }
        self.changed();
        self.inner.notify.notify_one();
    }

    fn changed(&self) {
        if let Some(f) = &self.inner.opts.on_state_change {
            f();
        }
    }

    /// 給 `/api/jobs`：`{ running, queue, state, config }`（同 2.x），另外多一個 `nextRun`（各工作下次排定時間，Unix 毫秒）
    pub fn status(&self) -> Value {
        let now = self.inner.opts.clock.now_ms();
        let st = self.inner.st.lock().unwrap();
        let cfg = Self::jobs_cfg(&st.cfg);
        let next: Map<String, Value> = cfg
            .iter()
            .map(|(n, c)| (n.clone(), next_run(c, now).map(Value::from).unwrap_or(Value::Null)))
            .collect();
        json!({
            "running": st.running.as_ref().map(|r| json!({
                "name": r.name, "pid": std::process::id(), "startedAt": r.started_at, "reason": r.reason
            })),
            "queue": st.queue.iter().map(|(n, r)| json!({ "name": n, "reason": r })).collect::<Vec<_>>(),
            "state": Value::Object(st.state.clone()),
            "config": Value::Object(cfg),
            "nextRun": Value::Object(next),
        })
    }

    /// 排程狀態快照：（state 目錄裡的檔名, 內容），交給快照寫入器
    pub fn snapshot(&self) -> (&'static str, Vec<u8>) {
        let st = self.inner.st.lock().unwrap();
        let b = serde_json::to_vec_pretty(&Value::Object(st.state.clone())).unwrap_or_default();
        (JOBS_STATE_FILE, b)
    }

    /// 某個工作下次排定的時間
    pub fn next_run(&self, name: &str) -> Option<u64> {
        let now = self.inner.opts.clock.now_ms();
        let st = self.inner.st.lock().unwrap();
        Self::jobs_cfg(&st.cfg).get(name).and_then(|c| next_run(c, now))
    }

    /// 有工作在跑或在排隊
    pub fn is_busy(&self) -> bool {
        let st = self.inner.st.lock().unwrap();
        st.running.is_some() || !st.queue.is_empty()
    }

    pub fn running(&self) -> Option<String> {
        self.inner.st.lock().unwrap().running.as_ref().map(|r| r.name.clone())
    }

    /// 指令列 `kuroshio job <name>`：不經佇列直接跑（仍然用鎖檔跟服務互斥、仍有逾時），不改排程狀態
    pub async fn run_direct(&self, name: &str, reason: &str) -> anyhow::Result<()> {
        let job = self
            .inner
            .jobs
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("找不到工作 {name}"))?;
        let _lock = match &self.inner.opts.lock_dir {
            Some(dir) => Some(JobLock::acquire(dir, name).map_err(|pid| anyhow::anyhow!("[{name}] 已經有一份在執行中（PID {pid}）"))?),
            None => None,
        };
        let cfg = self.inner.st.lock().unwrap().cfg.clone();
        let tmin = timeout_min(Self::jobs_cfg(&cfg).get(name).unwrap_or(&Value::Null));
        let ctx = JobCtx::new(name, reason, cfg).with_clock(self.inner.opts.clock.clone());
        let t0 = std::time::Instant::now();
        let r = tokio::time::timeout(Duration::from_secs_f64(tmin * 60.0), job.run(ctx))
            .await
            .map_err(|_| anyhow::anyhow!("執行超過 {tmin} 分鐘，強制結束"))?;
        if r.is_ok() {
            info!("[{name}] 完成，耗時 {:.1} 秒", t0.elapsed().as_secs_f64());
        }
        r
    }
}
