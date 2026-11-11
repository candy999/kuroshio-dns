//! 記憶體控制（規格 09）：記憶體寬裕時多留在記憶體（少寫 Flash、沒用的資料有更多機會被淘汰），
//! 吃緊時依「重建成本由低到高」逐步釋出，寬裕了再依相反順序恢復。
//!
//! - **預算**：`system.memoryBudgetMB`（0 = 依等級自動：tiny 24 MB、small 48 MB、standard 128 MB、
//!   large 為實體記憶體的 1/8，256–1024 MB）。自己的常駐記憶體（RSS）超過預算、或系統可用記憶體偏低都算吃緊。
//! - **狀態**：寬裕 / 吃緊 / 不足，有遲滯（進入與離開的門檻不同）與最短停留時間，不會來回跳。
//!   變嚴重立刻反應；放鬆要條件持續 [`Thresholds::dwell`] 秒。
//! - **釋出階梯**（每輪最多做一步，下一輪量到效果再決定要不要做下一步）：
//!   1. 診斷用的緩衝（設定頁日誌、熱門排行）縮小
//!   2. DNS 快取縮到上限的 1/4，留下熱門的
//!   3. CDN 網域資料庫：先寫進磁碟，再把冷資料移出記憶體（磁碟保留，查到時讀回）
//!   4. 過濾清單（只有「不足」時、最後才做）：一次停用一份優先順序最低的；自訂規則與保護清單絕不停用
//! - **恢復**：寬裕持續一段時間，而且估計的空間 ≥ 項目大小 × 1.3，才依相反順序恢復
//!   （過濾清單先——保護最重要——再來 CDN，快取與緩衝恢復上限後自然長回來）。
//!   恢復失敗（例如下載不到清單）用指數退避重試。
//! - **不超過預算**：過濾清單載入前估計大小，放不下的不載入（狀態裡看得到）。
//!
//! 全部只用 32 位元原子操作（MIPS 沒有 64 位元原子操作）；狀態放在 Mutex 裡。

use crate::sysinfo;
use kuroshio_config::Tier;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

pub const MB: u64 = 1 << 20;

/// 記憶體狀態
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum State {
    Comfortable = 0,
    Tight = 1,
    Critical = 2,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Comfortable => "comfortable",
            State::Tight => "tight",
            State::Critical => "critical",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            State::Comfortable => "寬裕",
            State::Tight => "吃緊",
            State::Critical => "不足",
        }
    }
}

/// 一次量測（bytes；量不到是 None）。測試直接造這個，不碰主機真正的記憶體
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Reading {
    /// 自己的常駐記憶體
    pub rss: Option<u64>,
    /// 系統實體記憶體
    pub total: Option<u64>,
    /// 系統可用記憶體
    pub avail: Option<u64>,
}

impl Reading {
    /// 量這台機器（Linux：/proc/self/statm、/proc/meminfo；Windows：GetProcessMemoryInfo、GlobalMemoryStatusEx）
    pub fn now() -> Reading {
        let (total, avail) = sysinfo::mem_bytes();
        Reading {
            rss: sysinfo::rss_bytes(),
            total,
            avail,
        }
    }

    pub fn avail_pct(&self) -> Option<u64> {
        match (self.total, self.avail) {
            (Some(t), Some(a)) if t > 0 => Some(a * 100 / t),
            _ => None,
        }
    }
}

/// 門檻（百分比是可用記憶體佔實體記憶體；RSS 是預算的百分比）
#[derive(Debug, Clone, Copy)]
pub struct Thresholds {
    pub tight_avail_pct: u64,
    pub tight_avail_mb: u64,
    pub crit_avail_pct: u64,
    pub leave_tight_avail_pct: u64,
    pub leave_tight_avail_mb: u64,
    pub leave_crit_avail_pct: u64,
    pub tight_rss_pct: u64,
    pub crit_rss_pct: u64,
    pub leave_tight_rss_pct: u64,
    pub leave_crit_rss_pct: u64,
    /// 放鬆前條件要持續多久、狀態至少停留多久（秒）
    pub dwell: u64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Thresholds {
            tight_avail_pct: 15,
            tight_avail_mb: 24,
            crit_avail_pct: 8,
            leave_tight_avail_pct: 25,
            leave_tight_avail_mb: 32,
            leave_crit_avail_pct: 12,
            tight_rss_pct: 100,
            crit_rss_pct: 120,
            leave_tight_rss_pct: 85,
            leave_crit_rss_pct: 110,
            dwell: 180,
        }
    }
}

/// 狀態與遲滯
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hyst {
    pub state: State,
    /// 上次改變狀態的時間（秒）
    pub changed_at: u64,
    /// 放鬆的條件從什麼時候開始一直成立
    pub calm_since: Option<u64>,
}

impl Hyst {
    pub fn new(now: u64) -> Hyst {
        Hyst {
            state: State::Comfortable,
            changed_at: now,
            calm_since: None,
        }
    }
}

/// 依量測更新狀態（純函式）。變嚴重：立刻；放鬆：一次一級，條件要持續 `dwell` 秒、而且這個狀態已經停留 `dwell` 秒。
/// 回傳狀態有沒有改變
pub fn step_state(h: &mut Hyst, r: &Reading, budget: u64, t: &Thresholds, now: u64) -> bool {
    let pct = r.avail_pct();
    let avail_mb = r.avail.map(|a| a / MB);
    let rss_pct = r.rss.filter(|_| budget > 0).map(|x| x * 100 / budget);
    let lt = |v: Option<u64>, lim: u64| v.is_some_and(|v| v < lim);
    let gt = |v: Option<u64>, lim: u64| v.is_some_and(|v| v > lim);
    let crit = lt(pct, t.crit_avail_pct) || gt(rss_pct, t.crit_rss_pct);
    let tight = crit || lt(pct, t.tight_avail_pct) || lt(avail_mb, t.tight_avail_mb) || gt(rss_pct, t.tight_rss_pct);
    let worst = if crit {
        State::Critical
    } else if tight {
        State::Tight
    } else {
        State::Comfortable
    };
    if worst > h.state {
        h.state = worst;
        h.changed_at = now;
        h.calm_since = None;
        return true;
    }
    let comfy = !lt(pct, t.leave_tight_avail_pct + 1)
        && !lt(avail_mb, t.leave_tight_avail_mb)
        && !rss_pct.is_some_and(|p| p >= t.leave_tight_rss_pct);
    let relax_to = match h.state {
        State::Critical if !crit && !lt(pct, t.leave_crit_avail_pct) && !gt(rss_pct, t.leave_crit_rss_pct) => Some(State::Tight),
        State::Tight if comfy => Some(State::Comfortable),
        _ => None,
    };
    match relax_to {
        Some(to) => {
            let since = *h.calm_since.get_or_insert(now);
            if now.saturating_sub(since) >= t.dwell && now.saturating_sub(h.changed_at) >= t.dwell {
                h.state = to;
                h.changed_at = now;
                h.calm_since = None;
                return true;
            }
            false
        }
        None => {
            h.calm_since = None;
            false
        }
    }
}

/// 自動預算（MB）：依等級與實體記憶體
pub fn auto_budget_mb(tier: Tier, total_mb: Option<u64>) -> u64 {
    let b = match tier {
        Tier::Tiny => 24,
        Tier::Small => 48,
        Tier::Standard => 128,
        Tier::Large => total_mb.map(|t| (t / 8).clamp(256, 1024)).unwrap_or(512),
    };
    // 不超過實體記憶體的一半（手動指定低等級的大機器不受影響，因為上面已經比較小）
    match total_mb {
        Some(t) if t > 0 => b.min((t / 2).max(8)),
        _ => b,
    }
}

/// 可以拿來恢復的空間（bytes）：預算剩下的、與系統可用記憶體保持在「寬裕」門檻以上剩下的，取小的
pub fn headroom(r: &Reading, budget: u64, t: &Thresholds) -> u64 {
    let by_budget = r.rss.map(|x| budget.saturating_sub(x));
    let by_system = match (r.total, r.avail) {
        (Some(tot), Some(a)) => Some(
            a.saturating_sub(tot * t.leave_tight_avail_pct / 100)
                .min(a.saturating_sub(t.leave_tight_avail_mb * MB)),
        ),
        _ => None,
    };
    match (by_budget, by_system) {
        (Some(a), Some(b)) => a.min(b),
        (Some(a), None) | (None, Some(a)) => a,
        (None, None) => u64::MAX,
    }
}

/// 清單層最多可以用多少 bytes（純函式）：預算減掉清單以外的常駐記憶體；
/// 另外重建時新舊兩份會同時存在，新的一份不超過系統可用記憶體的一半
pub fn list_allowance(r: &Reading, budget: u64, lists_bytes: u64) -> Option<u64> {
    let rss = r.rss?;
    let mut a = budget.saturating_sub(rss.saturating_sub(lists_bytes));
    if let Some(av) = r.avail {
        a = a.min(av / 2 + lists_bytes.min(av / 2));
    }
    Some(a)
}

/// 一步的結果
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    /// 估計釋出（或恢復後佔用）的記憶體
    pub bytes: u64,
    /// 說明（例如「快取 4,000 → 1,000 筆」、停用的清單）
    pub detail: String,
}

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// 階梯上的一步
pub trait Step: Send + Sync {
    /// `diagnostics` / `cache` / `cdn` / `filter`
    fn key(&self) -> &'static str;
    fn label(&self) -> &'static str;
    /// 至少要到這個狀態才做
    fn min_state(&self) -> State {
        State::Tight
    }
    /// 還能再釋出
    fn can_shed(&self) -> bool;
    /// 依這次的量測，這一步現在該不該做（預設：該）。過濾清單只在「系統」真的不足時才停用
    fn wanted(&self, _r: &Reading, _t: &Thresholds) -> bool {
        true
    }
    /// 目前有釋出中的東西（要恢復）
    fn is_shed(&self) -> bool;
    /// 恢復下一個項目估計要多少記憶體
    fn restore_need(&self) -> u64 {
        0
    }
    fn shed<'a>(&'a self, r: &'a Reading) -> BoxFut<'a, anyhow::Result<Outcome>>;
    fn restore(&self) -> BoxFut<'_, anyhow::Result<Outcome>>;
}

/// 釋出中的項目（狀態頁用）
#[derive(Debug, Clone)]
struct ShedRec {
    key: &'static str,
    label: &'static str,
    detail: String,
    bytes: u64,
    /// 做之前的 RSS（下一輪量到後算出實際差多少）
    rss_before: Option<u64>,
    rss_delta: Option<i64>,
    at: u64,
}

#[derive(Debug, Clone)]
struct Event {
    at: u64,
    msg: String,
}

struct Inner {
    hyst: Hyst,
    last: Reading,
    shed: Vec<ShedRec>,
    events: VecDeque<Event>,
    next_shed_at: u64,
    next_restore_at: u64,
    restore_fails: u32,
    /// 上次恢復的時間：恢復後很快又吃緊 → 下次恢復等久一點
    last_restore_at: Option<u64>,
    flap: u32,
    freed_total: u64,
    last_change: Option<(u64, State, State)>,
    waiting: Option<String>,
}

/// 記憶體控制器
pub struct Governor {
    pub budget: u64,
    pub t: Thresholds,
    steps: Vec<Box<dyn Step>>,
    inner: Mutex<Inner>,
    /// 每一步之間至少隔多久（秒），讓量測看得到效果
    pub gap: u64,
}

const MAX_EVENTS: usize = 20;
const MAX_BACKOFF: u64 = 6 * 3600;

impl Governor {
    pub fn new(budget: u64, t: Thresholds, steps: Vec<Box<dyn Step>>, now: u64) -> Governor {
        Governor {
            budget,
            t,
            steps,
            inner: Mutex::new(Inner {
                hyst: Hyst::new(now),
                last: Reading::default(),
                shed: Vec::new(),
                events: VecDeque::new(),
                next_shed_at: 0,
                next_restore_at: 0,
                restore_fails: 0,
                last_restore_at: None,
                flap: 0,
                freed_total: 0,
                last_change: None,
                waiting: None,
            }),
            gap: 30,
        }
    }

    pub fn state(&self) -> State {
        self.inner.lock().unwrap().hyst.state
    }

    pub fn last_reading(&self) -> Reading {
        self.inner.lock().unwrap().last
    }

    fn event(i: &mut Inner, now: u64, msg: String) {
        if i.events.len() >= MAX_EVENTS {
            i.events.pop_front();
        }
        i.events.push_back(Event { at: now, msg });
    }

    /// 一輪：更新狀態，必要時做一步釋出或恢復。回傳這輪做了什麼（`shed:鍵` / `restore:鍵`）
    pub async fn tick(&self, r: Reading, now: u64) -> Option<String> {
        enum Plan {
            Shed(usize),
            Restore(usize),
        }
        let plan = {
            let mut g = self.inner.lock().unwrap();
            let i = &mut *g;
            i.last = r;
            // 上一步的實際效果（RSS 差多少）
            for s in i.shed.iter_mut().filter(|s| s.rss_delta.is_none()) {
                if let (Some(b), Some(n)) = (s.rss_before, r.rss) {
                    s.rss_delta = Some(b as i64 - n as i64);
                }
            }
            let from = i.hyst.state;
            if step_state(&mut i.hyst, &r, self.budget, &self.t, now) {
                let to = i.hyst.state;
                i.last_change = Some((now, from, to));
                let msg = format!(
                    "記憶體{}（常駐 {} KB / 預算 {} KB，系統可用 {} KB）",
                    to.label(),
                    r.rss.map(|x| x / 1024).unwrap_or(0),
                    self.budget / 1024,
                    r.avail.map(|x| x / 1024).unwrap_or(0)
                );
                if to > from {
                    warn!("{msg}");
                    // 恢復之後很快又吃緊：下次恢復等久一點
                    if i.last_restore_at.is_some_and(|t| now.saturating_sub(t) < 600) {
                        i.flap = (i.flap + 1).min(8);
                    }
                } else {
                    info!("{msg}");
                }
                Self::event(i, now, msg);
            }
            let state = i.hyst.state;
            i.waiting = None;
            if state > State::Comfortable {
                if now < i.next_shed_at {
                    None
                } else {
                    self.steps
                        .iter()
                        .position(|s| state >= s.min_state() && s.can_shed() && s.wanted(&r, &self.t))
                        .map(Plan::Shed)
                }
            } else if now.saturating_sub(i.hyst.changed_at) >= self.t.dwell && now >= i.next_restore_at {
                match self.steps.iter().rposition(|s| s.is_shed()) {
                    Some(k) => {
                        let need = self.steps[k].restore_need();
                        let room = headroom(&r, self.budget, &self.t);
                        if room as u128 >= need as u128 * 13 / 10 {
                            Some(Plan::Restore(k))
                        } else {
                            i.waiting = Some(format!(
                                "等待空間恢復{}：需要約 {} KB × 1.3，目前約 {} KB",
                                self.steps[k].label(),
                                need / 1024,
                                room / 1024
                            ));
                            None
                        }
                    }
                    None => {
                        i.flap = 0;
                        None
                    }
                }
            } else {
                None
            }
        };
        match plan? {
            Plan::Shed(k) => {
                let s = &self.steps[k];
                let res = s.shed(&r).await;
                let mut g = self.inner.lock().unwrap();
                let i = &mut *g;
                i.next_shed_at = now + self.gap;
                // 把釋出的記憶體還給系統（glibc 不會自己還；musl 大塊會直接還）
                sysinfo::trim_heap();
                match res {
                    Ok(o) => {
                        warn!("記憶體控制：{}（約 {} KB）{}", s.label(), o.bytes / 1024, o.detail);
                        i.freed_total += o.bytes;
                        Self::event(i, now, format!("釋出：{} {}（約 {} KB）", s.label(), o.detail, o.bytes / 1024));
                        i.shed.push(ShedRec {
                            key: s.key(),
                            label: s.label(),
                            detail: o.detail,
                            bytes: o.bytes,
                            rss_before: r.rss,
                            rss_delta: None,
                            at: now,
                        });
                    }
                    Err(e) => {
                        warn!("記憶體控制：{}沒有做：{e:#}", s.label());
                        Self::event(i, now, format!("{}沒有做：{e:#}", s.label()));
                        // 這一步做不了（例如下載失敗）：等久一點再試
                        i.next_shed_at = now + self.gap * 10;
                    }
                }
                Some(format!("shed:{}", s.key()))
            }
            Plan::Restore(k) => {
                let s = &self.steps[k];
                let res = s.restore().await;
                let mut g = self.inner.lock().unwrap();
                let i = &mut *g;
                match res {
                    Ok(o) => {
                        info!("記憶體恢復：{}{}", s.label(), o.detail);
                        i.restore_fails = 0;
                        i.last_restore_at = Some(now);
                        i.next_restore_at = now + (self.gap << i.flap).min(MAX_BACKOFF);
                        // 這一步的項目全部恢復了：從釋出清單拿掉（過濾清單是一份一份恢復）
                        if !s.is_shed() {
                            i.shed.retain(|x| x.key != s.key());
                        } else if let Some(p) = i.shed.iter().rposition(|x| x.key == s.key()) {
                            i.shed.remove(p);
                        }
                        Self::event(i, now, format!("恢復：{}{}", s.label(), o.detail));
                    }
                    Err(e) => {
                        i.restore_fails = (i.restore_fails + 1).min(16);
                        let wait = (300u64 << (i.restore_fails - 1).min(10)).min(MAX_BACKOFF);
                        i.next_restore_at = now + wait;
                        warn!("記憶體恢復：{}失敗（{e:#}），{} 分鐘後重試", s.label(), wait / 60);
                        Self::event(i, now, format!("恢復{}失敗：{e:#}（{} 分鐘後重試）", s.label(), wait / 60));
                    }
                }
                Some(format!("restore:{}", s.key()))
            }
        }
    }

    /// `/api/status.memory`
    pub fn status_json(&self) -> Value {
        let i = self.inner.lock().unwrap();
        let r = i.last;
        let kb = |x: Option<u64>| x.map(|v| v / 1024);
        json!({
            "enabled": true,
            "state": i.hyst.state.as_str(),
            "stateLabel": i.hyst.state.label(),
            "since": i.hyst.changed_at * 1000,
            "rssKB": kb(r.rss),
            "budgetKB": self.budget / 1024,
            "availKB": kb(r.avail),
            "totalKB": kb(r.total),
            "shed": i.shed.iter().map(|s| json!({
                "step": s.key, "label": s.label, "detail": s.detail, "freedBytes": s.bytes,
                "rssDeltaKB": s.rss_delta.map(|d| d / 1024), "at": s.at * 1000,
            })).collect::<Vec<_>>(),
            "freedBytes": i.shed.iter().map(|s| s.bytes).sum::<u64>(),
            "freedTotalBytes": i.freed_total,
            "lastChange": i.last_change.map(|(at, from, to)| json!({ "at": at * 1000, "from": from.as_str(), "to": to.as_str() })),
            "waiting": i.waiting,
            "nextRestoreAt": (i.next_restore_at > 0 && !i.shed.is_empty()).then_some(i.next_restore_at * 1000),
            "events": i.events.iter().rev().map(|e| json!({ "at": e.at * 1000, "msg": e.msg })).collect::<Vec<_>>(),
        })
    }
}

// ------------------------------------------------------------ 各步驟

/// 1. 診斷用的緩衝：設定頁日誌 500 → 50 行、熱門排行只留前 200 名
pub struct DiagStep {
    pub stats: Arc<crate::resolver::Resolver>,
    shed: std::sync::atomic::AtomicBool,
}

impl DiagStep {
    pub fn new(r: Arc<crate::resolver::Resolver>) -> DiagStep {
        DiagStep {
            stats: r,
            shed: Default::default(),
        }
    }
}

/// 熱門排行縮小時留幾名
pub const SHED_TOP_KEEP: usize = 200;

impl Step for DiagStep {
    fn key(&self) -> &'static str {
        "diagnostics"
    }
    fn label(&self) -> &'static str {
        "縮小診斷緩衝（日誌、熱門排行）"
    }
    fn can_shed(&self) -> bool {
        !self.shed.load(std::sync::atomic::Ordering::Relaxed)
    }
    fn is_shed(&self) -> bool {
        !self.can_shed()
    }
    fn shed<'a>(&'a self, _r: &'a Reading) -> BoxFut<'a, anyhow::Result<Outcome>> {
        Box::pin(async move {
            self.shed.store(true, std::sync::atomic::Ordering::Relaxed);
            let a = crate::logring::shed(true);
            let b = self.stats.stats.shed_tops(Some(SHED_TOP_KEEP));
            Ok(Outcome {
                bytes: (a + b) as u64,
                detail: format!("日誌 {} 行、排行前 {SHED_TOP_KEEP} 名", crate::logring::SHED_LINES),
            })
        })
    }
    fn restore(&self) -> BoxFut<'_, anyhow::Result<Outcome>> {
        Box::pin(async move {
            crate::logring::shed(false);
            self.stats.stats.shed_tops(None);
            self.shed.store(false, std::sync::atomic::Ordering::Relaxed);
            Ok(Outcome::default())
        })
    }
}

/// 2. DNS 快取：縮到上限的 1/4（至少 256 筆），留下熱門的；釋出期間上限也維持在那裡
pub struct CacheStep {
    pub resolver: Arc<crate::resolver::Resolver>,
    orig_max: Mutex<Option<usize>>,
}

impl CacheStep {
    pub fn new(r: Arc<crate::resolver::Resolver>) -> CacheStep {
        CacheStep {
            resolver: r,
            orig_max: Mutex::new(None),
        }
    }
}

impl Step for CacheStep {
    fn key(&self) -> &'static str {
        "cache"
    }
    fn label(&self) -> &'static str {
        "縮小 DNS 快取"
    }
    fn can_shed(&self) -> bool {
        self.orig_max.lock().unwrap().is_none()
    }
    fn is_shed(&self) -> bool {
        !self.can_shed()
    }
    fn shed<'a>(&'a self, _r: &'a Reading) -> BoxFut<'a, anyhow::Result<Outcome>> {
        Box::pin(async move {
            let mut c = self.resolver.cache.lock().unwrap();
            let orig = c.max;
            let target = (orig / 4).max(256).min(orig);
            *self.orig_max.lock().unwrap() = Some(orig);
            let before = c.len();
            c.max = target;
            let (_, bytes) = c.shed_to(target);
            Ok(Outcome {
                bytes: bytes as u64,
                detail: format!("{before} → {} 筆（上限 {orig} → {target}）", c.len()),
            })
        })
    }
    fn restore(&self) -> BoxFut<'_, anyhow::Result<Outcome>> {
        Box::pin(async move {
            if let Some(m) = self.orig_max.lock().unwrap().take() {
                self.resolver.cache.lock().unwrap().max = m;
                return Ok(Outcome {
                    bytes: 0,
                    detail: format!("（上限恢復 {m} 筆，之後自然長回來）"),
                });
            }
            Ok(Outcome::default())
        })
    }
}

/// 3. CDN 網域資料庫：先把變動寫進磁碟，再把一小時沒出現的網域移出記憶體（磁碟保留，查到時讀回）
pub struct CdnStep {
    pub cdn: Arc<kuroshio_cdn::Cdn>,
    pub persister: Arc<Mutex<crate::persist::Persister>>,
    pub sources: Vec<crate::app::SnapSource>,
    /// 多久沒出現算冷資料（毫秒）
    pub cold_ms: u64,
    bytes: Mutex<u64>,
}

impl CdnStep {
    pub fn new(
        cdn: Arc<kuroshio_cdn::Cdn>,
        persister: Arc<Mutex<crate::persist::Persister>>,
        sources: Vec<crate::app::SnapSource>,
    ) -> CdnStep {
        CdnStep {
            cdn,
            persister,
            sources,
            cold_ms: 3600 * 1000,
            bytes: Mutex::new(0),
        }
    }
}

impl Step for CdnStep {
    fn key(&self) -> &'static str {
        "cdn"
    }
    fn label(&self) -> &'static str {
        "CDN 網域資料庫冷資料移出記憶體"
    }
    fn can_shed(&self) -> bool {
        self.cdn.evicted_count() == 0
    }
    fn is_shed(&self) -> bool {
        self.cdn.evicted_count() > 0
    }
    fn restore_need(&self) -> u64 {
        *self.bytes.lock().unwrap()
    }
    fn shed<'a>(&'a self, _r: &'a Reading) -> BoxFut<'a, anyhow::Result<Outcome>> {
        Box::pin(async move {
            let (cdn, p, sources, cold) = (self.cdn.clone(), self.persister.clone(), self.sources.clone(), self.cold_ms);
            let r = tokio::task::spawn_blocking(move || -> anyhow::Result<kuroshio_cdn::cdn::ColdReport> {
                // 先寫出：移出的只會是已經在磁碟上、之後沒變過的分片（登記與移出期間不會有新的登記）
                let _g = crate::app::STAGE_LOCK.lock().unwrap();
                crate::app::stage_sources_locked(&p, &sources);
                let mut pg = p.lock().unwrap();
                pg.flush_all(crate::persist::now_secs())?;
                Ok(cdn.evict_cold(cold, &|rel| !pg.is_pending(rel)))
            })
            .await??;
            *self.bytes.lock().unwrap() = r.bytes as u64;
            if r.entries == 0 {
                anyhow::bail!("沒有可以移出的冷資料");
            }
            Ok(Outcome {
                bytes: r.bytes as u64,
                detail: format!("{} 筆（磁碟上保留，查到時讀回）", r.entries),
            })
        })
    }
    fn restore(&self) -> BoxFut<'_, anyhow::Result<Outcome>> {
        Box::pin(async move {
            let cdn = self.cdn.clone();
            let r = tokio::task::spawn_blocking(move || cdn.restore_cold()).await?;
            *self.bytes.lock().unwrap() = 0;
            Ok(Outcome {
                bytes: r.bytes as u64,
                detail: format!("：讀回 {} 筆", r.entries),
            })
        })
    }
}

/// 4. 過濾清單（只在「不足」時、最後才做）：一次停用一份優先順序最低的清單
pub struct FilterStep {
    pub filter: Arc<crate::filtering::FilterService>,
}

impl Step for FilterStep {
    fn key(&self) -> &'static str {
        "filter"
    }
    fn label(&self) -> &'static str {
        "暫時停用過濾清單"
    }
    fn min_state(&self) -> State {
        State::Critical
    }
    fn can_shed(&self) -> bool {
        self.filter.next_shed_bytes().is_some()
    }
    /// 只有系統可用記憶體真的不足（< 8%）才停用；只是自己的常駐記憶體超過預算、系統還有空間時，
    /// 不拿保護去換（前面幾步已經釋出能釋出的）。量不到系統記憶體時才看預算
    fn wanted(&self, r: &Reading, t: &Thresholds) -> bool {
        r.avail_pct().map_or(true, |p| p < t.crit_avail_pct)
    }
    fn is_shed(&self) -> bool {
        !self.filter.unloaded().is_empty()
    }
    fn restore_need(&self) -> u64 {
        self.filter.next_restore_bytes().unwrap_or(0)
    }
    fn shed<'a>(&'a self, r: &'a Reading) -> BoxFut<'a, anyhow::Result<Outcome>> {
        Box::pin(async move {
            // 重建時新舊兩份同時存在：新的一份放不進可用記憶體的一半就不做（不能為了省記憶體反而用光）
            let lists = self.filter.lists_bytes();
            let freed = self.filter.next_shed_bytes().unwrap_or(0);
            if let Some(av) = r.avail {
                if lists.saturating_sub(freed) > av / 2 {
                    anyhow::bail!("可用記憶體不足以安全重建過濾器（需要約 {} KB）", lists.saturating_sub(freed) / 1024);
                }
            }
            match self.filter.unload_one().await? {
                Some(u) => Ok(Outcome {
                    bytes: u.bytes,
                    detail: format!("：{} 清單（{} 條規則）", u.name, u.rules),
                }),
                None => anyhow::bail!("沒有可以停用的清單（其他都是保護清單）"),
            }
        })
    }
    fn restore(&self) -> BoxFut<'_, anyhow::Result<Outcome>> {
        Box::pin(async move {
            match self.filter.restore_one().await? {
                Some(u) => Ok(Outcome {
                    bytes: u.bytes,
                    detail: format!("：{} 清單", u.name),
                }),
                None => Ok(Outcome::default()),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    const T: Thresholds = Thresholds {
        tight_avail_pct: 15,
        tight_avail_mb: 24,
        crit_avail_pct: 8,
        leave_tight_avail_pct: 25,
        leave_tight_avail_mb: 32,
        leave_crit_avail_pct: 12,
        tight_rss_pct: 100,
        crit_rss_pct: 120,
        leave_tight_rss_pct: 85,
        leave_crit_rss_pct: 110,
        dwell: 180,
    };

    /// 1 GB 的機器、預算 100 MB：可用 a MB、RSS r MB
    fn rd(avail_mb: u64, rss_mb: u64) -> Reading {
        Reading {
            rss: Some(rss_mb * MB),
            total: Some(1000 * MB),
            avail: Some(avail_mb * MB),
        }
    }

    #[test]
    fn hysteresis_and_dwell() {
        let b = 100 * MB;
        let mut h = Hyst::new(0);
        assert!(!step_state(&mut h, &rd(500, 50), b, &T, 10));
        // 可用 14%：吃緊（立刻）
        assert!(step_state(&mut h, &rd(140, 50), b, &T, 20));
        assert_eq!(h.state, State::Tight);
        // 回到 20%：還沒到離開門檻（25%），維持吃緊
        assert!(!step_state(&mut h, &rd(200, 50), b, &T, 400));
        assert_eq!(h.state, State::Tight);
        // 26%：條件成立，但要持續 180 秒
        assert!(!step_state(&mut h, &rd(260, 50), b, &T, 500));
        assert!(!step_state(&mut h, &rd(260, 50), b, &T, 600));
        // 中間掉回去一次：重新計時
        assert!(!step_state(&mut h, &rd(200, 50), b, &T, 650));
        assert!(!step_state(&mut h, &rd(260, 50), b, &T, 700));
        assert!(!step_state(&mut h, &rd(260, 50), b, &T, 870));
        assert!(step_state(&mut h, &rd(260, 50), b, &T, 880));
        assert_eq!(h.state, State::Comfortable);
        // RSS 超過預算：吃緊；超過 1.2 倍：不足（立刻，不必等）
        assert!(step_state(&mut h, &rd(500, 101), b, &T, 900));
        assert_eq!(h.state, State::Tight);
        assert!(step_state(&mut h, &rd(500, 121), b, &T, 901));
        assert_eq!(h.state, State::Critical);
        // 不足 → 一次只放鬆一級：RSS 回到 1.05 倍 → 吃緊（要停留夠久）
        assert!(!step_state(&mut h, &rd(500, 105), b, &T, 950));
        assert!(!step_state(&mut h, &rd(500, 105), b, &T, 1080), "停留不到 180 秒");
        assert!(step_state(&mut h, &rd(500, 105), b, &T, 1131));
        assert_eq!(h.state, State::Tight);
        // RSS 90%：還沒到 85% 以下，維持吃緊
        assert!(!step_state(&mut h, &rd(500, 90), b, &T, 2000));
        assert!(!step_state(&mut h, &rd(500, 90), b, &T, 3000));
        assert_eq!(h.state, State::Tight);
        // 可用記憶體不到 8%：不足
        assert!(step_state(&mut h, &rd(70, 10), b, &T, 3001));
        assert_eq!(h.state, State::Critical);
        // 量不到 RSS（只有系統數字）也能判斷；什麼都量不到就維持寬裕
        let mut h = Hyst::new(0);
        let r = Reading {
            rss: None,
            total: Some(1000 * MB),
            avail: Some(100 * MB),
        };
        assert!(step_state(&mut h, &r, b, &T, 1));
        assert_eq!(h.state, State::Tight);
        let mut h = Hyst::new(0);
        assert!(!step_state(&mut h, &Reading::default(), b, &T, 1));
    }

    #[test]
    fn budgets() {
        assert_eq!(auto_budget_mb(Tier::Tiny, Some(120)), 24);
        assert_eq!(auto_budget_mb(Tier::Small, Some(245)), 48);
        assert_eq!(auto_budget_mb(Tier::Standard, Some(1000)), 128);
        assert_eq!(auto_budget_mb(Tier::Large, Some(16000)), 1024);
        assert_eq!(auto_budget_mb(Tier::Large, Some(3900)), 487);
        assert_eq!(auto_budget_mb(Tier::Large, None), 512);
        // 手動指定大等級的小機器：不超過實體記憶體的一半
        assert_eq!(auto_budget_mb(Tier::Large, Some(120)), 60);
        // 空間：預算剩下的與系統保持寬裕以上剩下的，取小的
        let r = rd(500, 40);
        assert_eq!(headroom(&r, 100 * MB, &T), 60 * MB);
        assert_eq!(headroom(&rd(300, 10), 100 * MB, &T), 50 * MB, "300 - 250（25%）");
        assert_eq!(headroom(&Reading::default(), 100 * MB, &T), u64::MAX);
        // 清單層的額度：預算 - 清單以外的常駐記憶體；也不超過可用記憶體一半（重建時兩份並存）
        assert_eq!(
            list_allowance(&rd(500, 30), 24 * MB, 4 * MB),
            Some(0),
            "其他就已經超過預算：一條都不載入"
        );
        assert_eq!(list_allowance(&rd(500, 20), 24 * MB, 4 * MB), Some(8 * MB));
        assert_eq!(
            list_allowance(&rd(6, 20), 24 * MB, 4 * MB),
            Some(6 * MB),
            "可用 6 MB：新的一份 ≤ 3 MB + 舊的 3 MB"
        );
        assert_eq!(list_allowance(&Reading::default(), 24 * MB, 0), None);
    }

    /// 假的步驟：記錄呼叫順序；`units` = 還能釋出幾次（過濾清單一次一份）
    struct Fake {
        key: &'static str,
        min: State,
        units: u32,
        shed_n: AtomicU32,
        need: u64,
        log: Arc<Mutex<Vec<String>>>,
        fail_restore: AtomicBool,
    }

    impl Fake {
        fn new(key: &'static str, min: State, units: u32, need: u64, log: &Arc<Mutex<Vec<String>>>) -> Box<Fake> {
            Box::new(Fake {
                key,
                min,
                units,
                shed_n: AtomicU32::new(0),
                need,
                log: log.clone(),
                fail_restore: AtomicBool::new(false),
            })
        }
    }

    impl Step for Fake {
        fn key(&self) -> &'static str {
            self.key
        }
        fn label(&self) -> &'static str {
            self.key
        }
        fn min_state(&self) -> State {
            self.min
        }
        fn can_shed(&self) -> bool {
            self.shed_n.load(Ordering::Relaxed) < self.units
        }
        /// 跟 FilterStep 一樣：「不足」才做的步驟只在系統真的不足時做
        fn wanted(&self, r: &Reading, t: &Thresholds) -> bool {
            self.min < State::Critical || r.avail_pct().map_or(true, |p| p < t.crit_avail_pct)
        }
        fn is_shed(&self) -> bool {
            self.shed_n.load(Ordering::Relaxed) > 0
        }
        fn restore_need(&self) -> u64 {
            self.need
        }
        fn shed<'a>(&'a self, _r: &'a Reading) -> BoxFut<'a, anyhow::Result<Outcome>> {
            Box::pin(async move {
                self.shed_n.fetch_add(1, Ordering::Relaxed);
                self.log.lock().unwrap().push(format!("shed:{}", self.key));
                Ok(Outcome {
                    bytes: 1000,
                    detail: String::new(),
                })
            })
        }
        fn restore(&self) -> BoxFut<'_, anyhow::Result<Outcome>> {
            Box::pin(async move {
                if self.fail_restore.load(Ordering::Relaxed) {
                    self.log.lock().unwrap().push(format!("fail:{}", self.key));
                    anyhow::bail!("下載失敗");
                }
                self.shed_n.fetch_sub(1, Ordering::Relaxed);
                self.log.lock().unwrap().push(format!("restore:{}", self.key));
                Ok(Outcome::default())
            })
        }
    }

    fn ladder(log: &Arc<Mutex<Vec<String>>>, filter_need: u64) -> Vec<Box<dyn Step>> {
        vec![
            Fake::new("diagnostics", State::Tight, 1, 0, log),
            Fake::new("cache", State::Tight, 1, 0, log),
            Fake::new("cdn", State::Tight, 1, 5 * MB, log),
            Fake::new("filter", State::Critical, 2, filter_need, log),
        ]
    }

    #[tokio::test]
    async fn ladder_order_and_restore_order() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let g = Governor::new(100 * MB, T, ladder(&log, 2 * MB), 0);
        let mut now = 1000;
        // 吃緊：只做到 CDN 為止（過濾清單要到「不足」才動），一輪一步
        for _ in 0..6 {
            g.tick(rd(140, 50), now).await;
            now += 30;
        }
        assert_eq!(*log.lock().unwrap(), ["shed:diagnostics", "shed:cache", "shed:cdn"]);
        // 只是 RSS 超過預算 1.2 倍（不足），系統還有很多可用記憶體：過濾清單不動
        for _ in 0..4 {
            g.tick(rd(600, 130), now).await;
            now += 30;
        }
        assert_eq!(g.state(), State::Critical);
        assert_eq!(log.lock().unwrap().len(), 3, "系統不缺記憶體時不拿保護換");
        // 不足：過濾清單一次停用一份，停完就沒有了
        for _ in 0..4 {
            g.tick(rd(70, 50), now).await;
            now += 30;
        }
        assert_eq!(log.lock().unwrap()[3..], ["shed:filter", "shed:filter"]);
        let st = g.status_json();
        assert_eq!(st["state"], "critical");
        assert_eq!(st["shed"].as_array().unwrap().len(), 5);
        assert_eq!(st["freedBytes"], 5000);
        log.lock().unwrap().clear();
        // 恢復：寬裕而且停留夠久才開始；相反順序（過濾清單先），一輪一項
        for _ in 0..40 {
            g.tick(rd(600, 20), now).await;
            now += 30;
        }
        assert_eq!(
            *log.lock().unwrap(),
            [
                "restore:filter",
                "restore:filter",
                "restore:cdn",
                "restore:cache",
                "restore:diagnostics"
            ]
        );
        assert_eq!(g.status_json()["shed"].as_array().unwrap().len(), 0);
        assert_eq!(g.state(), State::Comfortable);
    }

    #[tokio::test]
    async fn restore_waits_for_headroom_and_backs_off() {
        let log = Arc::new(Mutex::new(Vec::new()));
        // 過濾清單需要 40 MB：要有 52 MB 的空間才恢復
        let steps = ladder(&log, 40 * MB);
        let g = Governor::new(100 * MB, T, steps, 0);
        let mut now = 1000;
        for _ in 0..5 {
            g.tick(rd(70, 50), now).await;
            now += 30;
        }
        assert_eq!(log.lock().unwrap().len(), 5);
        log.lock().unwrap().clear();
        // 寬裕了，但預算只剩 100 - 60 = 40 MB < 52 MB：等，不恢復（也不跳過去恢復別的）
        for _ in 0..20 {
            g.tick(rd(600, 60), now).await;
            now += 30;
        }
        assert!(log.lock().unwrap().is_empty(), "{:?}", log.lock().unwrap());
        assert!(g.status_json()["waiting"].as_str().unwrap().contains("等待空間"));
        // 空間夠了（預算剩 70 MB）
        g.tick(rd(600, 30), now).await;
        assert_eq!(*log.lock().unwrap(), ["restore:filter"]);
    }

    #[tokio::test]
    async fn cache_step_keeps_hot_and_caps_growth_until_restored() {
        use crate::cache::Entry;
        use kuroshio_proto::message::Record;
        let cfg = kuroshio_config::with_overrides(&json!({ "resolver": { "cacheMax": 2000, "lastResort": [], "rankIps": false } }));
        let r = crate::app::build_resolver(&cfg).unwrap();
        let now = std::time::Instant::now();
        let entry = |n: &str| {
            Entry::new(
                0,
                vec![Record::a(n, 600, std::net::Ipv4Addr::new(192, 0, 2, 1))],
                vec![],
                kuroshio_proto::logic::Class::Ok,
                "up".into(),
                600,
                false,
                None,
            )
        };
        {
            let mut c = r.cache.lock().unwrap();
            for i in 0..2000 {
                c.insert(format!("1|n{i}.example"), entry(&format!("n{i}.example")), now);
            }
            for _ in 0..8 {
                c.get("1|n7.example", now);
            }
        }
        let s = CacheStep::new(r.clone());
        let o = s.shed(&Reading::default()).await.unwrap();
        assert!(o.bytes > 0);
        {
            let c = r.cache.lock().unwrap();
            assert_eq!((c.len(), c.max), (500, 500));
            assert!(c.peek("1|n7.example").is_some(), "熱門的留著");
        }
        assert!(!s.can_shed() && s.is_shed());
        // 釋出期間不會長回去（超過上限就清掃）
        {
            let mut c = r.cache.lock().unwrap();
            for i in 0..2000 {
                c.insert(format!("1|m{i}.example"), entry(&format!("m{i}.example")), now);
            }
            assert!(c.len() <= 550, "{}", c.len());
        }
        s.restore().await.unwrap();
        assert_eq!(r.cache.lock().unwrap().max, 2000, "恢復上限，之後自然長回來");
        assert!(s.can_shed());
    }

    #[tokio::test]
    async fn restore_failure_backs_off() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let f = Fake::new("filter", State::Critical, 1, 0, &log);
        f.fail_restore.store(true, Ordering::Relaxed);
        let g = Governor::new(100 * MB, T, vec![f], 0);
        let mut now = 1000;
        g.tick(rd(70, 50), now).await;
        log.lock().unwrap().clear();
        // 寬裕 10 分鐘：失敗一次之後等 5 分鐘、再失敗等 10 分鐘……
        let mut fails = Vec::new();
        for _ in 0..80 {
            now += 30;
            if g.tick(rd(600, 20), now).await.is_some() {
                fails.push(now);
            }
        }
        assert!(fails.len() >= 3, "{fails:?}");
        assert!(fails[1] - fails[0] >= 300);
        assert!(fails[2] - fails[1] >= 600, "指數退避：{fails:?}");
        assert!(log.lock().unwrap().iter().all(|x| x == "fail:filter"));
    }
}
