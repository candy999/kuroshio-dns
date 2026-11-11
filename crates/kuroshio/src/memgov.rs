//! 記憶體控制（規格 09）：記憶體是拿來用的。系統還有餘裕時，快取、CDN 網域資料庫、過濾清單盡量留在記憶體
//! （少寫 Flash、少重新下載）；別的程式需要記憶體時，依「重建成本由低到高」很快地讓出來，寬裕了再依相反順序恢復。
//! 使用者不必設定任何大小，也不分硬體等級。
//!
//! - **系統保留量**（[`Reserve`]）：系統可用記憶體（Linux `MemAvailable`、Windows `ullAvailPhys`）低於保留量就釋出；
//!   高於「保留量 + 遲滯」（[`margin`]）才恢復、才讓記憶體結構繼續長大。預設依平台自動決定（[`auto_reserve`]），
//!   可以用 `system.memoryReserveMB`（絕對值）與 / 或 `system.memoryReservePercent`（實體記憶體的百分比）指定，
//!   兩個都填取大的；0 = 自動。不看自己用了多少（沒有「預算」），只看整台機器還剩多少。
//! - **反應快**：可用記憶體在保留量兩倍以內時每 2–3 秒量一次，離得遠時 30 秒（[`poll_interval`]）；
//!   Linux 有 PSI（`/proc/pressure/memory`）時當作提早的訊號：別的程式已經在等記憶體了，就先讓。
//! - **狀態**：寬裕 / 吃緊 / 不足，有遲滯與最短停留時間，不會來回跳。變嚴重立刻反應；放鬆要條件持續 `dwell` 秒。
//! - **釋出階梯**（離保留量遠時一輪做好幾步，直到估計釋出的量補足差額）：
//!   1. 診斷用的緩衝（設定頁日誌、熱門排行）縮小
//!   2. DNS 快取縮到上限的 1/4，留下熱門的
//!   3. CDN 網域資料庫：先寫進磁碟，再把冷資料移出記憶體（磁碟保留，查到時讀回）
//!   4. 過濾清單（系統真的不足：可用 < 保留量的一半）：一次停用一份優先順序最低的；自訂規則與保護清單不在這一步
//!   5. 最低限度（只轉送）：暫停 CDN 調整、整個 CDN 資料庫移到磁碟、快取只留 [`FLOOR_CACHE`] 筆
//!   6. 保護清單：只有到了最低限度、可用還不到保留量的 1/4（不讓出來連轉送都會失敗）才暫停，狀態頁特別標示
//!
//!   **底線**：監聽、轉送路徑、上游連線永遠不釋出；明文 DNS 一定回答區網的查詢。最深的狀態就是「純轉送」。
//! - **恢復**：寬裕持續一段時間，而且「可用 − 保留量 − 遲滯」≥ 項目大小 × 1.3，才依相反順序恢復；
//!   失敗（例如下載不到清單）用指數退避重試；恢復後很快又吃緊，下次等久一點。
//! - **長大之前先看空間**：寬裕時記憶體結構才長大（快取超過目前大小、過濾清單載入前的估計、CDN 讀回）；
//!   一進入保留量 + 遲滯以內就停止長大（[`growth_allowed`]）。
//! - **不讓核心挑別人**：Linux 上把自己的 `oom_score_adj` 設成負的（預設 -500，[`apply_oom_score_adj`]）：
//!   DNS 停了等於斷網，所以不讓核心優先殺掉本程式；代價是本程式必須自己先讓出記憶體，上面的階梯就是做這件事。
//!
//! 全部只用 32 位元原子操作（MIPS 沒有 64 位元原子操作）；狀態放在 Mutex 裡。

use crate::sysinfo::{self, Pressure};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

pub const MB: u64 = 1 << 20;

/// 最低限度時快取留幾筆（同一個名稱短時間內重複問，例如網頁載入時的多個連線，還是只問上游一次）
pub const FLOOR_CACHE: usize = 64;

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

/// Linux PSI（`/proc/pressure/memory`）：過去 10 秒裡「有工作在等記憶體」的時間比例（%）
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Psi {
    /// 至少一個工作在等
    pub some_avg10: f32,
    /// 全部工作都在等（整台機器卡住）
    pub full_avg10: f32,
}

impl Psi {
    /// 別的程式已經在等記憶體：當作吃緊
    pub fn stalled(&self) -> bool {
        self.some_avg10 >= 30.0 || self.full_avg10 >= 5.0
    }
    /// 整台機器幾乎卡住：當作不足
    pub fn severe(&self) -> bool {
        self.full_avg10 >= 20.0
    }
    /// 幾乎沒有等待：可以放鬆
    pub fn calm(&self) -> bool {
        self.some_avg10 < 10.0 && self.full_avg10 < 1.0
    }
}

/// 解析 `/proc/pressure/memory`
pub fn parse_psi(text: &str) -> Option<Psi> {
    let avg10 = |kind: &str| -> Option<f32> {
        let line = text.lines().find(|l| l.starts_with(kind))?;
        line.split_whitespace()
            .find_map(|f| f.strip_prefix("avg10="))
            .and_then(|v| v.parse().ok())
    };
    Some(Psi {
        some_avg10: avg10("some")?,
        full_avg10: avg10("full").unwrap_or(0.0),
    })
}

/// 一次量測（bytes；量不到是 None）。測試直接造這個，不碰主機真正的記憶體
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Reading {
    /// 自己的常駐記憶體（只顯示，不拿來判斷）
    pub rss: Option<u64>,
    /// 系統實體記憶體
    pub total: Option<u64>,
    /// 系統可用記憶體
    pub avail: Option<u64>,
    pub psi: Option<Psi>,
}

impl Reading {
    /// 量這台機器（Linux：/proc/meminfo、/proc/pressure/memory；Windows：GlobalMemoryStatusEx）
    pub fn now() -> Reading {
        let (total, avail) = sysinfo::mem_bytes();
        Reading {
            rss: sysinfo::rss_bytes(),
            total,
            avail,
            psi: std::fs::read_to_string("/proc/pressure/memory").ok().as_deref().and_then(parse_psi),
        }
    }
}

/// 平台（決定自動保留量）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    Windows,
    Other,
}

impl Platform {
    pub fn current() -> Platform {
        if cfg!(windows) {
            Platform::Windows
        } else if cfg!(target_os = "linux") {
            Platform::Linux
        } else {
            Platform::Other
        }
    }
}

/// 系統保留量
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reserve {
    pub bytes: u64,
    /// 自動決定（沒有使用者設定）
    pub auto: bool,
    /// 怎麼算出來的（狀態頁顯示）
    pub how: String,
}

impl Reserve {
    pub fn fixed(bytes: u64) -> Reserve {
        Reserve {
            bytes,
            auto: false,
            how: "固定".into(),
        }
    }
    pub fn margin(&self) -> u64 {
        margin(self.bytes)
    }
}

/// 自動保留量（bytes，規格 09 第 2 節）。
///
/// - Linux：max(16 MB, 實體記憶體 5%（最多 1 GB）, `vm.min_free_kbytes` × 3)。`MemAvailable` 已經扣掉核心的
///   低水位（low watermark ≈ min_free_kbytes × 1.25），但把「可以回收的檔案快取」算成可用——裡面有正在執行的
///   程式本身（OpenWrt 的 squashfs 上的執行檔與函式庫），全部回收就會一直重讀 Flash（thrashing）。
///   所以再留一段：至少 16 MB（128 MB 路由器上約 12%，夠 dnsmasq、hostapd、netifd 這類常駐程式的工作集），
///   大機器 5%；`min_free_kbytes` × 3 讓保留量一定高過核心開始直接回收（min 水位）與 kswapd 喚醒（low 水位）。
/// - Windows：max(512 MB, 實體記憶體 10%（最多 4 GB）)。`ullAvailPhys` 包含待命清單（standby，可以回收的快取），
///   Windows 會很積極地修剪工作集、把記憶體換到分頁檔；系統預設在可用約 32 MB / 4 GB（最多 64 MB）時才發
///   「記憶體不足」通知，那時桌面早就卡了，所以留多一點。
/// - 一律不超過實體記憶體的一半。
pub fn auto_reserve(total: Option<u64>, platform: Platform, min_free_kb: Option<u64>) -> (u64, String) {
    let (bytes, how) = match platform {
        Platform::Windows => {
            let pct = total.map(|t| (t / 10).min(4096 * MB)).unwrap_or(0);
            (pct.max(512 * MB), "自動：max(512 MB, 實體記憶體 10%)".to_string())
        }
        Platform::Linux | Platform::Other => {
            let pct = total.map(|t| (t / 20).min(1024 * MB)).unwrap_or(0);
            let wm = min_free_kb.unwrap_or(0) * 1024 * 3;
            (
                (16 * MB).max(pct).max(wm),
                format!(
                    "自動：max(16 MB, 實體記憶體 5%, min_free_kbytes {} KB × 3)",
                    min_free_kb.map_or("?".into(), |k| k.to_string())
                ),
            )
        }
    };
    match total {
        Some(t) if t > 0 => (bytes.min(t / 2), how),
        _ => (bytes, how),
    }
}

/// 保留量：使用者設定（MB、百分比，兩個都填取大的）或自動
pub fn derive_reserve(total: Option<u64>, platform: Platform, min_free_kb: Option<u64>, user_mb: u64, user_pct: u64) -> Reserve {
    let pct = user_pct.min(90);
    let by_mb = user_mb * MB;
    let by_pct = total.map(|t| t / 100 * pct).unwrap_or(0);
    if by_mb > 0 || by_pct > 0 {
        let how = match (by_mb > 0, by_pct > 0) {
            (true, true) => format!("設定：max({user_mb} MB, {pct}%)"),
            (true, false) => format!("設定：{user_mb} MB"),
            _ => format!("設定：實體記憶體 {pct}%"),
        };
        return Reserve {
            bytes: by_mb.max(by_pct),
            auto: false,
            how,
        };
    }
    let (bytes, how) = auto_reserve(total, platform, min_free_kb);
    Reserve { bytes, auto: true, how }
}

/// `vm.min_free_kbytes`（Linux）
pub fn read_min_free_kb() -> Option<u64> {
    std::fs::read_to_string("/proc/sys/vm/min_free_kbytes").ok()?.trim().parse().ok()
}

/// 依設定與這台機器決定保留量
pub fn reserve_from_cfg(cfg: &Value) -> Reserve {
    let n = |k: &str| kuroshio_config::num_or_auto(kuroshio_config::get(cfg, k)).unwrap_or(0);
    derive_reserve(
        sysinfo::mem_bytes().0,
        Platform::current(),
        read_min_free_kb(),
        n("system.memoryReserveMB"),
        n("system.memoryReservePercent"),
    )
}

/// 遲滯：可用記憶體回到「保留量 + 這麼多」以上才恢復、才繼續長大（保留量的一半，至少 8 MB）
pub fn margin(reserve: u64) -> u64 {
    (reserve / 2).max(8 * MB)
}

/// 下次量測間隔（秒）：低於保留量 2 秒；保留量兩倍以內、或 PSI 看得到等待 3 秒；其他 30 秒
pub fn poll_interval(r: &Reading, res: &Reserve) -> u64 {
    let Some(a) = r.avail else { return 30 };
    if a < res.bytes {
        2
    } else if a < res.bytes.saturating_mul(2) || r.psi.is_some_and(|p| !p.calm()) {
        3
    } else {
        30
    }
}

/// 立即的判斷（沒有遲滯）
pub fn classify(r: &Reading, res: &Reserve) -> State {
    let psi = r.psi.unwrap_or_default();
    match r.avail {
        Some(a) if a < res.bytes / 2 || psi.severe() => State::Critical,
        Some(a) if a < res.bytes || psi.stalled() => State::Tight,
        None if psi.severe() => State::Critical,
        None if psi.stalled() => State::Tight,
        _ => State::Comfortable,
    }
}

/// 給整個程式的壓力訊號（`app::pressure()`）：
/// 不足（可用 < 保留量的一半，或 PSI 嚴重）→ 拒絕新的加密連線、快照立刻寫出；
/// 偏低（可用 < 保留量 + 遲滯，或 PSI 有等待）→ 背景工作延後、記憶體結構不再長大
pub fn pressure_of(r: &Reading, res: &Reserve) -> Pressure {
    let psi = r.psi.unwrap_or_default();
    match r.avail {
        Some(a) if a < res.bytes / 2 || psi.severe() => Pressure::Critical,
        Some(a) if a < res.bytes + res.margin() || psi.stalled() => Pressure::Low,
        None if psi.severe() => Pressure::Critical,
        None if psi.stalled() => Pressure::Low,
        _ => Pressure::Normal,
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
/// 不足 → 吃緊：可用回到保留量以上；吃緊 → 寬裕：可用回到保留量 + 遲滯以上而且 PSI 平靜。回傳狀態有沒有改變
pub fn step_state(h: &mut Hyst, r: &Reading, res: &Reserve, dwell: u64, now: u64) -> bool {
    let worst = classify(r, res);
    if worst > h.state {
        h.state = worst;
        h.changed_at = now;
        h.calm_since = None;
        return true;
    }
    let psi_calm = r.psi.map_or(true, |p| p.calm());
    let avail_ok = |lim: u64| r.avail.map_or(true, |a| a >= lim);
    let relax_to = match h.state {
        State::Critical if worst < State::Critical && avail_ok(res.bytes) => Some(State::Tight),
        State::Tight if worst == State::Comfortable && avail_ok(res.bytes + res.margin()) && psi_calm => Some(State::Comfortable),
        _ => None,
    };
    match relax_to {
        Some(to) => {
            let since = *h.calm_since.get_or_insert(now);
            if now.saturating_sub(since) >= dwell && now.saturating_sub(h.changed_at) >= dwell {
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

/// 保留量以上還有多少（bytes；量不到是 None）
pub fn headroom(r: &Reading, res: &Reserve) -> Option<u64> {
    r.avail.map(|a| a.saturating_sub(res.bytes))
}

/// 可以拿來恢復 / 長大的空間：可用 − 保留量 − 遲滯（量不到時不限制）
pub fn restore_room(r: &Reading, res: &Reserve) -> u64 {
    match r.avail {
        Some(a) => a.saturating_sub(res.bytes + res.margin()),
        None => u64::MAX,
    }
}

/// 清單層最多可以用多少 bytes（純函式）：目前的清單 + 可以長大的空間 ÷ 1.3；
/// 另外重建時新舊兩份會同時存在，新的一份不超過系統可用記憶體的一半
pub fn list_allowance(r: &Reading, res: &Reserve, lists_bytes: u64) -> Option<u64> {
    let av = r.avail?;
    let grow = restore_room(r, res) / 13 * 10;
    Some((lists_bytes + grow).min(av / 2 + lists_bytes.min(av / 2)))
}

/// 記憶體結構可以長大（整個程式共用；記憶體控制每輪更新）
static GROWTH: AtomicBool = AtomicBool::new(true);

pub fn growth_allowed() -> bool {
    GROWTH.load(Ordering::Relaxed)
}

/// 測試用：直接設定（平常由記憶體控制更新）
pub fn set_growth_allowed(on: bool) {
    GROWTH.store(on, Ordering::Relaxed);
}

/// 預設的 `oom_score_adj`：-500。
///
/// 核心挑選 OOM 犧牲者的分數 ≈ 佔用的記憶體（以實體記憶體的千分比計）+ `oom_score_adj`。
/// -500 = 本程式要多佔「實體記憶體的一半」才會跟一般程式同分：正常情況下核心一定先挑別的程式；
/// 但本程式真的漏記憶體、吃掉超過一半時還是會被挑中（-1000 會完全豁免，那時整台機器會卡死，比 DNS 重啟更糟）。
pub const DEFAULT_OOM_SCORE_ADJ: i64 = -500;

/// 把 `oom_score_adj` 寫進 `path`（平常是 `/proc/self/oom_score_adj`；測試給別的路徑）。
/// 回傳實際寫入的值（限制在 -1000..=1000）。調成負值需要 CAP_SYS_RESOURCE（OpenWrt 上以 root 執行，可以）
pub fn apply_oom_score_adj(path: &Path, v: i64) -> std::io::Result<i64> {
    let v = v.clamp(-1000, 1000);
    std::fs::write(path, format!("{v}\n"))?;
    Ok(v)
}

/// 依設定 `system.oomScoreAdj` 設定自己的 OOM 分數（只有 Linux；失敗記一次、照常執行）
pub fn apply_oom_from_cfg(cfg: &Value) {
    if !cfg!(target_os = "linux") {
        return;
    }
    let v = match kuroshio_config::get(cfg, "system.oomScoreAdj") {
        Some(Value::Number(n)) => n.as_i64().unwrap_or(DEFAULT_OOM_SCORE_ADJ),
        Some(Value::String(s)) => s.trim().parse().unwrap_or(DEFAULT_OOM_SCORE_ADJ),
        _ => DEFAULT_OOM_SCORE_ADJ,
    };
    match apply_oom_score_adj(Path::new("/proc/self/oom_score_adj"), v) {
        Ok(v) => info!("OOM 分數調整 oom_score_adj = {v}（記憶體用完時核心不優先停掉 DNS）"),
        Err(e) => warn!("無法設定 oom_score_adj = {v}：{e}（需要 root 或 CAP_SYS_RESOURCE；照常執行）"),
    }
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
    /// `diagnostics` / `cache` / `cdn` / `filter` / `floor` / `protected`
    fn key(&self) -> &'static str;
    fn label(&self) -> &'static str;
    /// 至少要到這個狀態才做
    fn min_state(&self) -> State {
        State::Tight
    }
    /// 還能再釋出
    fn can_shed(&self) -> bool;
    /// 依這次的量測，這一步現在該不該做（預設：該）。過濾清單只在系統「真的」不足時才停用
    fn wanted(&self, _r: &Reading, _res: &Reserve) -> bool {
        true
    }
    /// 目前有釋出中的東西（要恢復）
    fn is_shed(&self) -> bool;
    /// 恢復下一個項目估計要多少記憶體
    fn restore_need(&self) -> u64 {
        0
    }
    /// 記憶體結構可不可以長大（寬裕 ↔ 接近保留量時呼叫）
    fn set_growth(&self, _allowed: bool) {}
    /// 目前的大小（狀態頁用；例如快取筆數）
    fn sizes(&self, _out: &mut serde_json::Map<String, Value>) {}
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
    /// 做之前的系統可用記憶體（下一輪量到後算出實際差多少）
    avail_before: Option<u64>,
    avail_delta: Option<i64>,
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
    /// 各步驟做不了（例如沒有冷資料、下載失敗）之後，到這個時間之前先跳過、做下一步
    skip_until: Vec<u64>,
    next_restore_at: u64,
    restore_fails: u32,
    /// 上次恢復的時間：恢復後很快又吃緊 → 下次恢復等久一點
    last_restore_at: Option<u64>,
    flap: u32,
    freed_total: u64,
    last_change: Option<(u64, State, State)>,
    waiting: Option<String>,
    growth: bool,
}

type Reader = Box<dyn Fn() -> Reading + Send + Sync>;

/// 記憶體控制器
pub struct Governor {
    pub reserve: Reserve,
    steps: Vec<Box<dyn Step>>,
    inner: Mutex<Inner>,
    /// 釋出之後至少隔多久（秒）再看效果做下一步（離保留量遠時同一輪就連做好幾步）
    pub gap: u64,
    /// 放鬆前條件要持續多久、狀態至少停留多久（秒）
    pub dwell: u64,
    reader: Mutex<Reader>,
}

const MAX_EVENTS: usize = 20;
const MAX_BACKOFF: u64 = 6 * 3600;

impl Governor {
    pub fn new(reserve: Reserve, steps: Vec<Box<dyn Step>>, now: u64) -> Governor {
        let n_steps = steps.len();
        Governor {
            reserve,
            steps,
            inner: Mutex::new(Inner {
                hyst: Hyst::new(now),
                last: Reading::default(),
                shed: Vec::new(),
                events: VecDeque::new(),
                next_shed_at: 0,
                skip_until: vec![0; n_steps],
                next_restore_at: 0,
                restore_fails: 0,
                last_restore_at: None,
                flap: 0,
                freed_total: 0,
                last_change: None,
                waiting: None,
                growth: true,
            }),
            gap: 5,
            dwell: 180,
            reader: Mutex::new(Box::new(Reading::now)),
        }
    }

    /// 換掉量測的方法（測試注入固定的數字）
    pub fn set_reader(&self, f: impl Fn() -> Reading + Send + Sync + 'static) {
        *self.reader.lock().unwrap() = Box::new(f);
    }

    /// 量一次（用目前的量測方法）
    pub fn read(&self) -> Reading {
        (self.reader.lock().unwrap())()
    }

    pub fn state(&self) -> State {
        self.inner.lock().unwrap().hyst.state
    }

    pub fn last_reading(&self) -> Reading {
        self.inner.lock().unwrap().last
    }

    /// 到了最低限度（只轉送）
    pub fn at_floor(&self) -> bool {
        self.steps.iter().any(|s| s.key() == "floor" && s.is_shed())
    }

    fn event(i: &mut Inner, now: u64, msg: String) {
        if i.events.len() >= MAX_EVENTS {
            i.events.pop_front();
        }
        i.events.push_back(Event { at: now, msg });
    }

    /// 這一步現在可以做
    fn eligible(&self, i: &Inner, k: usize, state: State, r: &Reading, now: u64) -> bool {
        let s = &self.steps[k];
        now >= i.skip_until[k] && state >= s.min_state() && s.can_shed() && s.wanted(r, &self.reserve)
    }

    /// 一輪：更新狀態，必要時釋出（離保留量遠時連做好幾步）或恢復一步。
    /// 回傳這輪做了什麼（`shed:鍵` / `restore:鍵`，好幾步用逗號分開）
    pub async fn tick(&self, r: Reading, now: u64) -> Option<String> {
        enum Plan {
            Shed { far: bool, deficit: u64 },
            Restore(usize),
        }
        let (plan, growth_change) = {
            let mut g = self.inner.lock().unwrap();
            let i = &mut *g;
            i.last = r;
            // 上一步的實際效果（系統可用記憶體差多少）
            for s in i.shed.iter_mut().filter(|s| s.avail_delta.is_none()) {
                if let (Some(b), Some(n)) = (s.avail_before, r.avail) {
                    s.avail_delta = Some(n as i64 - b as i64);
                }
            }
            let from = i.hyst.state;
            if step_state(&mut i.hyst, &r, &self.reserve, self.dwell, now) {
                let to = i.hyst.state;
                i.last_change = Some((now, from, to));
                let msg = format!(
                    "記憶體{}（系統可用 {} KB，保留 {} KB）",
                    to.label(),
                    r.avail.map(|x| x / 1024).unwrap_or(0),
                    self.reserve.bytes / 1024
                );
                if to > from {
                    warn!("{msg}");
                    if i.last_restore_at.is_some_and(|t| now.saturating_sub(t) < 600) {
                        i.flap = (i.flap + 1).min(8);
                    }
                } else {
                    info!("{msg}");
                }
                Self::event(i, now, msg);
            }
            let state = i.hyst.state;
            // 長大：寬裕而且離保留量 + 遲滯還有空間
            let growth = state == State::Comfortable && pressure_of(&r, &self.reserve) == Pressure::Normal;
            GROWTH.store(growth, Ordering::Relaxed);
            let growth_change = (growth != i.growth).then_some(growth);
            i.growth = growth;
            i.waiting = None;
            let plan = if state > State::Comfortable {
                let any = (0..self.steps.len()).any(|k| self.eligible(i, k, state, &r, now));
                (now >= i.next_shed_at && any).then(|| {
                    let deficit = r.avail.map_or(0, |a| self.reserve.bytes.saturating_sub(a));
                    let far = state == State::Critical || r.avail.is_some_and(|a| a < self.reserve.bytes / 4 * 3);
                    Plan::Shed { far, deficit }
                })
            } else if now.saturating_sub(i.hyst.changed_at) >= self.dwell && now >= i.next_restore_at {
                match self.steps.iter().rposition(|s| s.is_shed()) {
                    Some(k) => {
                        let need = self.steps[k].restore_need();
                        let room = restore_room(&r, &self.reserve);
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
            };
            (plan, growth_change)
        };
        if let Some(on) = growth_change {
            for s in &self.steps {
                s.set_growth(on);
            }
        }
        match plan? {
            Plan::Shed { far, deficit } => {
                let mut done = Vec::new();
                let mut freed = 0u64;
                for _ in 0..16 {
                    let k = {
                        let i = self.inner.lock().unwrap();
                        let state = i.hyst.state;
                        (0..self.steps.len()).find(|&k| self.eligible(&i, k, state, &r, now))
                    };
                    let Some(k) = k else { break };
                    let s = &self.steps[k];
                    let res = s.shed(&r).await;
                    // 把釋出的記憶體還給系統（glibc 不會自己還；musl 大塊會直接還）
                    sysinfo::trim_heap();
                    let mut g = self.inner.lock().unwrap();
                    let i = &mut *g;
                    i.next_shed_at = now + self.gap;
                    match res {
                        Ok(o) => {
                            warn!("記憶體控制：{}（約 {} KB）{}", s.label(), o.bytes / 1024, o.detail);
                            i.freed_total += o.bytes;
                            freed += o.bytes;
                            Self::event(i, now, format!("釋出：{} {}（約 {} KB）", s.label(), o.detail, o.bytes / 1024));
                            i.shed.push(ShedRec {
                                key: s.key(),
                                label: s.label(),
                                detail: o.detail,
                                bytes: o.bytes,
                                avail_before: r.avail,
                                avail_delta: None,
                                at: now,
                            });
                        }
                        Err(e) => {
                            warn!("記憶體控制：{}沒有做：{e:#}", s.label());
                            Self::event(i, now, format!("{}沒有做：{e:#}", s.label()));
                            // 這一步做不了（例如沒有冷資料、下載失敗）：這一步等久一點再試，先做下一步
                            i.skip_until[k] = now + (self.gap * 10).max(60);
                        }
                    }
                    done.push(format!("shed:{}", s.key()));
                    // 離保留量不遠：一輪一步，下一輪量到效果再決定；遠：繼續做到估計補足差額
                    if !far || (deficit > 0 && freed >= deficit) {
                        break;
                    }
                }
                (!done.is_empty()).then(|| done.join(","))
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
                        i.next_restore_at = now + ((self.gap * 6) << i.flap).min(MAX_BACKOFF);
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
        let mut sizes = serde_json::Map::new();
        for s in &self.steps {
            s.sizes(&mut sizes);
        }
        let floor = self.at_floor();
        let protected = self.steps.iter().any(|s| s.key() == "protected" && s.is_shed());
        let i = self.inner.lock().unwrap();
        let r = i.last;
        let kb = |x: Option<u64>| x.map(|v| v / 1024);
        json!({
            "enabled": true,
            "state": i.hyst.state.as_str(),
            "stateLabel": i.hyst.state.label(),
            "since": i.hyst.changed_at * 1000,
            "rssKB": kb(r.rss),
            "availKB": kb(r.avail),
            "totalKB": kb(r.total),
            "reserveKB": self.reserve.bytes / 1024,
            "reserveAuto": self.reserve.auto,
            "reserveHow": self.reserve.how,
            "marginKB": self.reserve.margin() / 1024,
            "headroomKB": kb(headroom(&r, &self.reserve)),
            "psi": r.psi.map(|p| json!({ "someAvg10": p.some_avg10, "fullAvg10": p.full_avg10 })),
            "pollSec": poll_interval(&r, &self.reserve),
            "growth": i.growth,
            "floor": floor,
            "protectedSuspended": protected,
            "sizes": Value::Object(sizes),
            "shed": i.shed.iter().map(|s| json!({
                "step": s.key, "label": s.label, "detail": s.detail, "freedBytes": s.bytes,
                "availDeltaKB": s.avail_delta.map(|d| d / 1024), "at": s.at * 1000,
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

/// 第 1 步：診斷用的緩衝：設定頁日誌 500 → 50 行、熱門排行只留前 200 名
pub struct DiagStep {
    pub stats: Arc<crate::resolver::Resolver>,
    shed: AtomicBool,
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
        !self.shed.load(Ordering::Relaxed)
    }
    fn is_shed(&self) -> bool {
        !self.can_shed()
    }
    fn shed<'a>(&'a self, _r: &'a Reading) -> BoxFut<'a, anyhow::Result<Outcome>> {
        Box::pin(async move {
            self.shed.store(true, Ordering::Relaxed);
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
            self.shed.store(false, Ordering::Relaxed);
            Ok(Outcome::default())
        })
    }
}

/// 快取上限由誰決定（快取步驟、最低限度步驟、長大開關共用）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheCap {
    /// 設定的上限（`resolver.cacheMax`：安全上限，或使用者明確設定的值）
    pub configured: usize,
    /// 不能再長大時的上限（停止長大那一刻的筆數）
    pub frozen: Option<usize>,
    /// 快取步驟：縮到 1/4
    pub quarter: bool,
    /// 最低限度：只留 [`FLOOR_CACHE`] 筆
    pub floor: bool,
}

impl CacheCap {
    pub fn new(configured: usize) -> CacheCap {
        CacheCap {
            configured,
            frozen: None,
            quarter: false,
            floor: false,
        }
    }

    /// 現在的上限
    pub fn effective(&self) -> usize {
        if self.floor {
            return FLOOR_CACHE.min(self.configured);
        }
        let base = self.frozen.unwrap_or(self.configured).min(self.configured);
        if self.quarter {
            (base / 4).max(256).min(base)
        } else {
            base
        }
    }
}

pub type SharedCap = Arc<Mutex<CacheCap>>;

/// 套用上限並縮到上限以內（留下熱門的）。回傳（之前筆數，之後筆數，釋出 bytes）
fn apply_cap(resolver: &crate::resolver::Resolver, cap: &CacheCap) -> (usize, usize, usize) {
    let mut c = resolver.cache.lock().unwrap();
    let before = c.len();
    c.max = cap.effective().max(16);
    let max = c.max;
    let (_, bytes) = c.shed_to(max);
    (before, c.len(), bytes)
}

/// 第 2 步：DNS 快取：縮到上限的 1/4（至少 256 筆），留下熱門的；釋出期間上限也維持在那裡。
/// 另外負責「長大」：接近保留量時上限停在目前的筆數，寬裕了才恢復設定的上限
pub struct CacheStep {
    pub resolver: Arc<crate::resolver::Resolver>,
    pub cap: SharedCap,
}

impl CacheStep {
    pub fn new(r: Arc<crate::resolver::Resolver>) -> CacheStep {
        let configured = r.cache.lock().unwrap().max;
        CacheStep {
            resolver: r,
            cap: Arc::new(Mutex::new(CacheCap::new(configured))),
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
        !self.cap.lock().unwrap().quarter
    }
    fn is_shed(&self) -> bool {
        !self.can_shed()
    }
    fn set_growth(&self, allowed: bool) {
        let mut cap = self.cap.lock().unwrap();
        if allowed {
            cap.frozen = None;
        } else if cap.frozen.is_none() {
            cap.frozen = Some(self.resolver.cache.lock().unwrap().len().max(256));
        }
        self.resolver.cache.lock().unwrap().max = cap.effective().max(16);
    }
    fn sizes(&self, out: &mut serde_json::Map<String, Value>) {
        let (len, max) = {
            let c = self.resolver.cache.lock().unwrap();
            (c.len(), c.max)
        };
        out.insert("cacheEntries".into(), json!(len));
        out.insert("cacheMax".into(), json!(max));
        out.insert("cacheConfiguredMax".into(), json!(self.cap.lock().unwrap().configured));
    }
    fn shed<'a>(&'a self, _r: &'a Reading) -> BoxFut<'a, anyhow::Result<Outcome>> {
        Box::pin(async move {
            let cap = {
                let mut cap = self.cap.lock().unwrap();
                cap.quarter = true;
                *cap
            };
            let (before, after, bytes) = apply_cap(&self.resolver, &cap);
            Ok(Outcome {
                bytes: bytes as u64,
                detail: format!("{before} → {after} 筆（上限 {}）", cap.effective()),
            })
        })
    }
    fn restore(&self) -> BoxFut<'_, anyhow::Result<Outcome>> {
        Box::pin(async move {
            let cap = {
                let mut cap = self.cap.lock().unwrap();
                cap.quarter = false;
                *cap
            };
            self.resolver.cache.lock().unwrap().max = cap.effective().max(16);
            Ok(Outcome {
                bytes: 0,
                detail: format!("（上限恢復 {} 筆，之後自然長回來）", cap.effective()),
            })
        })
    }
}

/// 先把變動寫進磁碟，再把冷資料移出記憶體（`cold_ms` = 0：全部移出）
async fn evict_cdn(
    cdn: &Arc<kuroshio_cdn::Cdn>,
    persister: &Arc<Mutex<crate::persist::Persister>>,
    sources: &[crate::app::SnapSource],
    cold_ms: u64,
) -> anyhow::Result<kuroshio_cdn::cdn::ColdReport> {
    let (cdn, p, sources) = (cdn.clone(), persister.clone(), sources.to_vec());
    tokio::task::spawn_blocking(move || -> anyhow::Result<kuroshio_cdn::cdn::ColdReport> {
        // 先寫出：移出的只會是已經在磁碟上、之後沒變過的分片（登記與移出期間不會有新的登記）
        let _g = crate::app::STAGE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        crate::app::stage_sources_locked(&p, &sources);
        let mut pg = p.lock().unwrap();
        pg.flush_all(crate::persist::now_secs())?;
        Ok(cdn.evict_cold(cold_ms, &|rel| !pg.is_pending(rel)))
    })
    .await?
}

/// 第 3 步：CDN 網域資料庫：先把變動寫進磁碟，再把一小時沒出現的網域移出記憶體（磁碟保留，查到時讀回）
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
    fn sizes(&self, out: &mut serde_json::Map<String, Value>) {
        out.insert("cdnInRam".into(), json!(self.cdn.domains_in_ram()));
        out.insert("cdnOnDiskOnly".into(), json!(self.cdn.evicted_count()));
    }
    fn shed<'a>(&'a self, _r: &'a Reading) -> BoxFut<'a, anyhow::Result<Outcome>> {
        Box::pin(async move {
            let r = evict_cdn(&self.cdn, &self.persister, &self.sources, self.cold_ms).await?;
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

/// 系統真的不足：可用 < 保留量的一半（量不到可用記憶體時不做）
fn genuinely_short(r: &Reading, res: &Reserve) -> bool {
    r.avail.is_some_and(|a| a < res.bytes / 2)
}

/// 第 4 步：過濾清單（系統真的不足時）：一次停用一份優先順序最低的清單；保護清單不在這一步
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
        !self.filter.all_suspended() && self.filter.next_shed_bytes().is_some()
    }
    /// 只有系統可用記憶體真的不足才停用（PSI 有等待、但可用記憶體還在保留量一半以上時，不拿保護去換）
    fn wanted(&self, r: &Reading, res: &Reserve) -> bool {
        genuinely_short(r, res)
    }
    fn is_shed(&self) -> bool {
        !self.filter.unloaded().is_empty()
    }
    fn restore_need(&self) -> u64 {
        self.filter.next_restore_bytes().unwrap_or(0)
    }
    fn sizes(&self, out: &mut serde_json::Map<String, Value>) {
        out.insert("filterListsBytes".into(), json!(self.filter.lists_bytes()));
        out.insert("filterListRules".into(), json!(self.filter.list_rules()));
        out.insert("filterListsUnloaded".into(), json!(self.filter.unloaded().len()));
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

/// CDN 資料庫、快照寫入器、快照來源（移出記憶體前先寫出）
pub type CdnParts = (
    Arc<kuroshio_cdn::Cdn>,
    Arc<Mutex<crate::persist::Persister>>,
    Vec<crate::app::SnapSource>,
);

/// 第 5 步：最低限度（只轉送）：暫停 CDN 調整、整個 CDN 資料庫移到磁碟、快取只留 [`FLOOR_CACHE`] 筆。
/// 監聽、轉送、上游連線不動：區網的明文 DNS 照樣回答（答案照上游原樣，不做 CDN 調整）
pub struct FloorStep {
    pub resolver: Arc<crate::resolver::Resolver>,
    pub cap: SharedCap,
    pub cdn: Option<CdnParts>,
    on: AtomicBool,
}

impl FloorStep {
    pub fn new(resolver: Arc<crate::resolver::Resolver>, cap: SharedCap, cdn: Option<CdnParts>) -> FloorStep {
        FloorStep {
            resolver,
            cap,
            cdn,
            on: Default::default(),
        }
    }
}

impl Step for FloorStep {
    fn key(&self) -> &'static str {
        "floor"
    }
    fn label(&self) -> &'static str {
        "最低限度：只轉送（暫停 CDN 調整、快取最小）"
    }
    fn min_state(&self) -> State {
        State::Critical
    }
    fn can_shed(&self) -> bool {
        !self.on.load(Ordering::Relaxed)
    }
    fn wanted(&self, r: &Reading, res: &Reserve) -> bool {
        genuinely_short(r, res)
    }
    fn is_shed(&self) -> bool {
        self.on.load(Ordering::Relaxed)
    }
    fn shed<'a>(&'a self, _r: &'a Reading) -> BoxFut<'a, anyhow::Result<Outcome>> {
        Box::pin(async move {
            self.on.store(true, Ordering::Relaxed);
            self.resolver.cdn_suspended.store(true, Ordering::Relaxed);
            let cap = {
                let mut cap = self.cap.lock().unwrap();
                cap.floor = true;
                *cap
            };
            let (before, after, mut bytes) = apply_cap(&self.resolver, &cap);
            let mut detail = format!("快取 {before} → {after} 筆");
            if let Some((cdn, p, sources)) = &self.cdn {
                // CDN 暫停：資料庫整個寫進磁碟、移出記憶體（寫不了也照樣暫停調整）
                match evict_cdn(cdn, p, sources, 0).await {
                    Ok(r) => {
                        bytes += r.bytes;
                        detail.push_str(&format!("、CDN 調整暫停（{} 筆移到磁碟）", r.entries));
                    }
                    Err(e) => detail.push_str(&format!("、CDN 調整暫停（資料庫沒有移出：{e:#}）")),
                }
            }
            Ok(Outcome {
                bytes: bytes as u64,
                detail,
            })
        })
    }
    fn restore(&self) -> BoxFut<'_, anyhow::Result<Outcome>> {
        Box::pin(async move {
            let cap = {
                let mut cap = self.cap.lock().unwrap();
                cap.floor = false;
                *cap
            };
            self.resolver.cache.lock().unwrap().max = cap.effective().max(16);
            self.resolver.cdn_suspended.store(false, Ordering::Relaxed);
            self.on.store(false, Ordering::Relaxed);
            // CDN 資料庫：查到時讀回；CDN 步驟恢復時全部讀回
            Ok(Outcome {
                bytes: 0,
                detail: "：恢復 CDN 調整與快取".into(),
            })
        })
    }
}

/// 第 6 步：保護清單：已經是最低限度、可用記憶體還不到保留量的 1/4（不讓出來連轉送都會失敗）才暫停全部清單。
/// 自訂規則照樣有效。狀態頁特別標示（`protectedSuspended`）
pub struct ProtectedStep {
    pub filter: Arc<crate::filtering::FilterService>,
}

impl Step for ProtectedStep {
    fn key(&self) -> &'static str {
        "protected"
    }
    fn label(&self) -> &'static str {
        "暫停全部過濾清單（含保護清單）"
    }
    fn min_state(&self) -> State {
        State::Critical
    }
    fn can_shed(&self) -> bool {
        !self.filter.all_suspended() && self.filter.lists_bytes() > 0
    }
    fn wanted(&self, r: &Reading, res: &Reserve) -> bool {
        r.avail.is_some_and(|a| a < res.bytes / 4)
    }
    fn is_shed(&self) -> bool {
        self.filter.all_suspended()
    }
    fn restore_need(&self) -> u64 {
        self.filter.suspended_bytes()
    }
    fn shed<'a>(&'a self, _r: &'a Reading) -> BoxFut<'a, anyhow::Result<Outcome>> {
        Box::pin(async move {
            let bytes = self.filter.suspend_all();
            Ok(Outcome {
                bytes,
                detail: "：只剩自訂規則（轉送優先）".into(),
            })
        })
    }
    fn restore(&self) -> BoxFut<'_, anyhow::Result<Outcome>> {
        Box::pin(async move {
            self.filter.resume_all().await?;
            Ok(Outcome {
                bytes: self.filter.lists_bytes(),
                detail: "：重新載入過濾清單".into(),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    /// 1 GB 的機器、保留 100 MB（遲滯 50 MB）：可用 a MB
    fn rd(avail_mb: u64) -> Reading {
        Reading {
            rss: Some(20 * MB),
            total: Some(1000 * MB),
            avail: Some(avail_mb * MB),
            psi: None,
        }
    }

    fn res100() -> Reserve {
        Reserve::fixed(100 * MB)
    }

    #[test]
    fn reserve_derivation() {
        // Linux 自動：max(16 MB, 5%（最多 1 GB）, min_free_kbytes × 3)，不超過一半
        let r = derive_reserve(Some(128 * MB), Platform::Linux, Some(1024), 0, 0);
        assert!(r.auto);
        assert_eq!(r.bytes, 16 * MB, "128 MB 路由器：16 MB");
        assert_eq!(
            derive_reserve(Some(512 * MB), Platform::Linux, Some(16384), 0, 0).bytes,
            48 * MB,
            "min_free_kbytes 16 MB × 3"
        );
        assert_eq!(
            derive_reserve(Some(4000 * MB), Platform::Linux, Some(8192), 0, 0).bytes,
            200 * MB,
            "5%"
        );
        assert_eq!(
            derive_reserve(Some(64000 * MB), Platform::Linux, None, 0, 0).bytes,
            1024 * MB,
            "5% 最多 1 GB"
        );
        assert_eq!(
            derive_reserve(Some(24 * MB), Platform::Linux, None, 0, 0).bytes,
            12 * MB,
            "不超過實體記憶體一半"
        );
        assert_eq!(derive_reserve(None, Platform::Linux, None, 0, 0).bytes, 16 * MB);
        // Windows 自動：max(512 MB, 10%（最多 4 GB）)
        assert_eq!(derive_reserve(Some(4096 * MB), Platform::Windows, None, 0, 0).bytes, 512 * MB);
        assert_eq!(
            derive_reserve(Some(16384 * MB), Platform::Windows, None, 0, 0).bytes,
            16384 * MB / 10
        );
        assert_eq!(derive_reserve(Some(65536 * MB), Platform::Windows, None, 0, 0).bytes, 4096 * MB);
        // 使用者：絕對值、百分比、兩個都填取大的；百分比最多 90%
        let u = derive_reserve(Some(1000 * MB), Platform::Linux, None, 40, 0);
        assert_eq!((u.bytes, u.auto), (40 * MB, false));
        assert_eq!(derive_reserve(Some(1000 * MB), Platform::Linux, None, 0, 7).bytes, 70 * MB);
        assert_eq!(
            derive_reserve(Some(1000 * MB), Platform::Linux, None, 40, 7).bytes,
            70 * MB,
            "取大的"
        );
        assert_eq!(
            derive_reserve(Some(1000 * MB), Platform::Linux, None, 90, 7).bytes,
            90 * MB,
            "取大的"
        );
        assert_eq!(derive_reserve(Some(1000 * MB), Platform::Linux, None, 0, 99).bytes, 900 * MB);
        assert!(derive_reserve(Some(1000 * MB), Platform::Linux, None, 90, 7).how.contains("設定"));
        // 遲滯：一半，至少 8 MB
        assert_eq!(margin(100 * MB), 50 * MB);
        assert_eq!(margin(10 * MB), 8 * MB);
    }

    #[test]
    fn poll_interval_follows_distance_and_psi() {
        let res = res100();
        assert_eq!(poll_interval(&rd(50), &res), 2, "低於保留量");
        assert_eq!(poll_interval(&rd(150), &res), 3, "保留量兩倍以內");
        assert_eq!(poll_interval(&rd(199), &res), 3);
        assert_eq!(poll_interval(&rd(500), &res), 30, "離得遠");
        let mut r = rd(500);
        r.psi = Some(Psi {
            some_avg10: 12.0,
            full_avg10: 0.0,
        });
        assert_eq!(poll_interval(&r, &res), 3, "PSI 看得到等待：量勤一點");
        assert_eq!(poll_interval(&Reading::default(), &res), 30);
        // PSI 解析
        let p = parse_psi("some avg10=12.50 avg60=3.00 avg300=1.00 total=123\nfull avg10=0.40 avg60=0.10 avg300=0.00 total=4\n").unwrap();
        assert_eq!((p.some_avg10, p.full_avg10), (12.5, 0.4));
        assert!(parse_psi("").is_none());
        // PSI 是提早的訊號：可用記憶體還夠，但別的程式在等 → 吃緊；整台卡住 → 不足
        r.psi = Some(Psi {
            some_avg10: 40.0,
            full_avg10: 0.0,
        });
        assert_eq!(classify(&r, &res), State::Tight);
        r.psi = Some(Psi {
            some_avg10: 90.0,
            full_avg10: 25.0,
        });
        assert_eq!(classify(&r, &res), State::Critical);
        assert_eq!(pressure_of(&r, &res), Pressure::Critical);
    }

    #[test]
    fn hysteresis_and_dwell() {
        let res = res100();
        let mut h = Hyst::new(0);
        assert!(!step_state(&mut h, &rd(500), &res, 180, 10));
        // 低於保留量：吃緊（立刻）
        assert!(step_state(&mut h, &rd(90), &res, 180, 20));
        assert_eq!(h.state, State::Tight);
        // 回到 120 MB：還沒到保留量 + 遲滯（150），維持吃緊
        assert!(!step_state(&mut h, &rd(120), &res, 180, 400));
        assert_eq!(h.state, State::Tight);
        // 160：條件成立，但要持續 180 秒；中間掉回去一次重新計時
        assert!(!step_state(&mut h, &rd(160), &res, 180, 500));
        assert!(!step_state(&mut h, &rd(120), &res, 180, 600));
        assert!(!step_state(&mut h, &rd(160), &res, 180, 700));
        assert!(!step_state(&mut h, &rd(160), &res, 180, 870));
        assert!(step_state(&mut h, &rd(160), &res, 180, 880));
        assert_eq!(h.state, State::Comfortable);
        // 低於保留量一半：不足（立刻，不必經過吃緊）
        assert!(step_state(&mut h, &rd(40), &res, 180, 900));
        assert_eq!(h.state, State::Critical);
        // 不足 → 一次只放鬆一級：回到保留量以上 → 吃緊（要停留夠久）
        assert!(!step_state(&mut h, &rd(110), &res, 180, 950));
        assert!(!step_state(&mut h, &rd(110), &res, 180, 1079));
        assert!(step_state(&mut h, &rd(110), &res, 180, 1131));
        assert_eq!(h.state, State::Tight);
        // 什麼都量不到就維持寬裕
        let mut h = Hyst::new(0);
        assert!(!step_state(&mut h, &Reading::default(), &res, 180, 1));
        // 壓力訊號：保留量 + 遲滯以內是「偏低」（背景工作延後、停止長大），一半以下是「不足」
        assert_eq!(pressure_of(&rd(500), &res), Pressure::Normal);
        assert_eq!(pressure_of(&rd(140), &res), Pressure::Low);
        assert_eq!(pressure_of(&rd(49), &res), Pressure::Critical);
    }

    #[test]
    fn room_and_allowance() {
        let res = res100();
        assert_eq!(headroom(&rd(130), &res), Some(30 * MB));
        assert_eq!(restore_room(&rd(200), &res), 50 * MB, "200 − 100 − 50");
        assert_eq!(restore_room(&rd(120), &res), 0);
        assert_eq!(restore_room(&Reading::default(), &res), u64::MAX);
        // 清單層：目前的 + 可以長大的 ÷ 1.3；新的一份不超過可用的一半
        assert_eq!(list_allowance(&rd(280), &res, 4 * MB), Some(4 * MB + 130 * MB / 13 * 10));
        assert_eq!(
            list_allowance(&rd(120), &res, 4 * MB),
            Some(4 * MB),
            "接近保留量：不再長大，現有的照樣"
        );
        assert_eq!(
            list_allowance(&rd(6), &res, 10 * MB),
            Some(3 * MB + 3 * MB),
            "新的一份不超過可用的一半"
        );
        assert_eq!(list_allowance(&Reading::default(), &res, 0), None);
    }

    #[test]
    fn oom_score_adj_written_to_injected_path() {
        let dir = std::env::temp_dir().join(format!("kuroshio-oom-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("oom_score_adj");
        assert_eq!(apply_oom_score_adj(&p, DEFAULT_OOM_SCORE_ADJ).unwrap(), -500);
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "-500\n");
        assert_eq!(apply_oom_score_adj(&p, -5000).unwrap(), -1000, "限制在 -1000..=1000");
        assert!(apply_oom_score_adj(&dir.join("nope/x"), 0).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_cap_combines_growth_shed_and_floor() {
        let mut c = CacheCap::new(100_000);
        assert_eq!(c.effective(), 100_000);
        c.frozen = Some(3000);
        assert_eq!(c.effective(), 3000, "接近保留量：停在目前的筆數");
        c.quarter = true;
        assert_eq!(c.effective(), 750);
        c.floor = true;
        assert_eq!(c.effective(), FLOOR_CACHE);
        c.floor = false;
        c.quarter = false;
        c.frozen = None;
        assert_eq!(c.effective(), 100_000, "使用者設定的上限照樣是上限");
        assert_eq!(CacheCap::new(500).effective(), 500);
    }

    /// 假的步驟：記錄呼叫順序；`units` = 還能釋出幾次（過濾清單一次一份）
    struct Fake {
        key: &'static str,
        min: State,
        units: u32,
        shed_n: AtomicU32,
        need: u64,
        bytes: u64,
        log: Arc<Mutex<Vec<String>>>,
        fail_restore: AtomicBool,
        fail_shed: AtomicBool,
        grow: Arc<Mutex<Vec<bool>>>,
    }

    impl Fake {
        fn new(key: &'static str, min: State, units: u32, need: u64, log: &Arc<Mutex<Vec<String>>>) -> Box<Fake> {
            Box::new(Fake {
                key,
                min,
                units,
                shed_n: AtomicU32::new(0),
                need,
                bytes: 1000,
                log: log.clone(),
                fail_restore: AtomicBool::new(false),
                fail_shed: AtomicBool::new(false),
                grow: Default::default(),
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
        fn wanted(&self, r: &Reading, res: &Reserve) -> bool {
            self.min < State::Critical || genuinely_short(r, res)
        }
        fn is_shed(&self) -> bool {
            self.shed_n.load(Ordering::Relaxed) > 0
        }
        fn restore_need(&self) -> u64 {
            self.need
        }
        fn set_growth(&self, allowed: bool) {
            self.grow.lock().unwrap().push(allowed);
        }
        fn shed<'a>(&'a self, _r: &'a Reading) -> BoxFut<'a, anyhow::Result<Outcome>> {
            Box::pin(async move {
                if self.fail_shed.load(Ordering::Relaxed) {
                    self.log.lock().unwrap().push(format!("fail:{}", self.key));
                    anyhow::bail!("沒有可以移出的");
                }
                self.shed_n.fetch_add(1, Ordering::Relaxed);
                self.log.lock().unwrap().push(format!("shed:{}", self.key));
                Ok(Outcome {
                    bytes: self.bytes,
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
            Fake::new("floor", State::Critical, 1, 0, log),
        ]
    }

    #[tokio::test]
    async fn near_reserve_one_step_per_tick_then_restore_in_reverse() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let g = Governor::new(res100(), ladder(&log, 2 * MB), 0);
        let mut now = 1000;
        // 稍微低於保留量（90 MB）：一輪一步，只做到 CDN 為止（過濾清單要系統真的不足）
        for _ in 0..6 {
            g.tick(rd(90), now).await;
            now += 5;
        }
        assert_eq!(*log.lock().unwrap(), ["shed:diagnostics", "shed:cache", "shed:cdn"]);
        // PSI 嚴重（不足），但可用記憶體還在保留量一半以上：過濾清單不動
        let mut r = rd(90);
        r.psi = Some(Psi {
            some_avg10: 90.0,
            full_avg10: 30.0,
        });
        for _ in 0..4 {
            g.tick(r, now).await;
            now += 5;
        }
        assert_eq!(g.state(), State::Critical);
        assert_eq!(log.lock().unwrap().len(), 3, "系統不缺記憶體時不拿保護換");
        log.lock().unwrap().clear();
        // 恢復：寬裕而且停留夠久才開始；相反順序，一輪一項
        for _ in 0..200 {
            g.tick(rd(600), now).await;
            now += 5;
        }
        assert_eq!(*log.lock().unwrap(), ["restore:cdn", "restore:cache", "restore:diagnostics"]);
        assert_eq!(g.status_json()["shed"].as_array().unwrap().len(), 0);
        assert_eq!(g.state(), State::Comfortable);
    }

    #[tokio::test]
    async fn far_below_reserve_escalates_several_steps_in_one_tick() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let g = Governor::new(res100(), ladder(&log, 2 * MB), 0);
        // 可用只剩 30 MB（保留量的 30%）：同一輪一路做到最低限度（每步只估計釋出 1000 bytes，補不足差額）
        let did = g.tick(rd(30), 1000).await.unwrap();
        assert_eq!(
            did, "shed:diagnostics,shed:cache,shed:cdn,shed:filter,shed:filter,shed:floor",
            "一輪做完整個階梯"
        );
        let st = g.status_json();
        assert_eq!(st["state"], "critical");
        assert_eq!(st["reserveKB"], 100 * 1024);
        assert_eq!(st["pollSec"], 2);
        // 再來一輪：沒有可以做的了（停在最低限度，不會更低）
        assert!(g.tick(rd(30), 1010).await.is_none());

        // 差額小、每步釋出很多：補足差額就停
        let log2 = Arc::new(Mutex::new(Vec::new()));
        let big = vec![
            Box::new(Fake {
                bytes: 30 * MB,
                ..*Fake::new("diagnostics", State::Tight, 1, 0, &log2)
            }) as Box<dyn Step>,
            Box::new(Fake {
                bytes: 30 * MB,
                ..*Fake::new("cache", State::Tight, 1, 0, &log2)
            }),
            Box::new(Fake {
                bytes: 30 * MB,
                ..*Fake::new("cdn", State::Tight, 1, 0, &log2)
            }),
        ];
        let g = Governor::new(res100(), big, 0);
        // 可用 70 MB（差 30 MB，離保留量遠）：一步就補足
        assert_eq!(g.tick(rd(70), 1000).await.unwrap(), "shed:diagnostics");
        assert_eq!(g.tick(rd(40), 1010).await.unwrap(), "shed:cache,shed:cdn", "差 60 MB：兩步");
    }

    #[tokio::test]
    async fn growth_stops_near_reserve_and_resumes_when_comfortable() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let f = Fake::new("cache", State::Tight, 1, 0, &log);
        let grow = f.grow.clone();
        let g = Governor::new(res100(), vec![f], 0);
        g.tick(rd(600), 100).await;
        assert!(grow.lock().unwrap().is_empty(), "一開始就可以長大：沒有變化不通知");
        assert!(growth_allowed());
        // 保留量 + 遲滯（150 MB）以內：還沒低於保留量（不釋出），但停止長大
        assert!(g.tick(rd(140), 105).await.is_none());
        assert_eq!(*grow.lock().unwrap(), [false]);
        assert!(log.lock().unwrap().is_empty(), "還在保留量以上：不釋出");
        assert!(!g.status_json()["growth"].as_bool().unwrap());
        // 回到 160 MB：寬裕，恢復長大
        g.tick(rd(160), 110).await;
        assert_eq!(*grow.lock().unwrap(), [false, true]);
        set_growth_allowed(true);
    }

    #[tokio::test]
    async fn restore_waits_for_headroom_and_backs_off() {
        let log = Arc::new(Mutex::new(Vec::new()));
        // 過濾清單需要 40 MB：要「可用 − 保留量 − 遲滯」≥ 52 MB 才恢復
        let g = Governor::new(res100(), ladder(&log, 40 * MB), 0);
        let mut now = 1000;
        g.tick(rd(30), now).await;
        assert_eq!(log.lock().unwrap().len(), 6);
        log.lock().unwrap().clear();
        // 寬裕了（180 MB）：先恢復最低限度（不需要空間），清單要 52 MB 但只有 30 MB：等，不跳過去恢復別的
        for _ in 0..200 {
            now += 5;
            g.tick(rd(180), now).await;
        }
        assert_eq!(*log.lock().unwrap(), ["restore:floor"], "{:?}", log.lock().unwrap());
        assert!(g.status_json()["waiting"].as_str().unwrap().contains("等待空間"));
        // 空間夠了（210 MB：還有 60 MB）
        now += 600;
        g.tick(rd(210), now).await;
        assert_eq!(*log.lock().unwrap(), ["restore:floor", "restore:filter"]);
    }

    #[tokio::test]
    async fn failing_step_does_not_block_the_ladder() {
        // 例如 CDN 沒有冷資料可以移出：先跳過它，做下一步（過濾清單），過一陣子再試它
        let log = Arc::new(Mutex::new(Vec::new()));
        let cdn = Fake::new("cdn", State::Tight, 1, 0, &log);
        cdn.fail_shed.store(true, Ordering::Relaxed);
        let g = Governor::new(res100(), vec![cdn, Fake::new("filter", State::Critical, 1, 0, &log)], 0);
        let mut now = 1000;
        g.tick(rd(40), now).await;
        assert_eq!(*log.lock().unwrap(), ["fail:cdn", "shed:filter"]);
        // 60 秒內不重試 CDN，之後再試
        for _ in 0..30 {
            now += 5;
            g.tick(rd(40), now).await;
        }
        assert_eq!(log.lock().unwrap().iter().filter(|x| *x == "fail:cdn").count(), 3);
    }

    #[tokio::test]
    async fn restore_failure_backs_off() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let f = Fake::new("filter", State::Critical, 1, 0, &log);
        f.fail_restore.store(true, Ordering::Relaxed);
        let g = Governor::new(res100(), vec![f], 0);
        let mut now = 1000;
        g.tick(rd(40), now).await;
        log.lock().unwrap().clear();
        // 寬裕：失敗一次之後等 5 分鐘、再失敗等 10 分鐘……
        let mut fails = Vec::new();
        for _ in 0..500 {
            now += 5;
            if g.tick(rd(600), now).await.is_some() {
                fails.push(now);
            }
        }
        assert!(fails.len() >= 3, "{fails:?}");
        assert!(fails[1] - fails[0] >= 300);
        assert!(fails[2] - fails[1] >= 600, "指數退避：{fails:?}");
        assert!(log.lock().unwrap().iter().all(|x| x == "fail:filter"));
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
        let fill = |prefix: &str, n: usize| {
            let mut c = r.cache.lock().unwrap();
            for i in 0..n {
                c.insert(format!("1|{prefix}{i}.example"), entry(&format!("{prefix}{i}.example")), now);
            }
        };
        fill("n", 2000);
        for _ in 0..8 {
            r.cache.lock().unwrap().get("1|n7.example", now);
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
        fill("m", 2000);
        assert!(r.cache.lock().unwrap().len() <= 550);
        s.restore().await.unwrap();
        assert_eq!(r.cache.lock().unwrap().max, 2000, "恢復上限，之後自然長回來");
        assert!(s.can_shed());
        // 停止長大：上限停在目前的筆數（至少 256）；寬裕了恢復設定的上限
        let len = r.cache.lock().unwrap().len();
        s.set_growth(false);
        assert_eq!(r.cache.lock().unwrap().max, len.max(256));
        fill("k", 3000);
        assert!(r.cache.lock().unwrap().len() <= len.max(256) * 11 / 10 + 1);
        s.set_growth(true);
        assert_eq!(r.cache.lock().unwrap().max, 2000);
        // 最低限度：只留 FLOOR_CACHE 筆；恢復後回到原本的上限
        let floor = FloorStep::new(r.clone(), s.cap.clone(), None);
        floor.shed(&Reading::default()).await.unwrap();
        assert!(r.cache.lock().unwrap().len() <= FLOOR_CACHE);
        assert!(r.cdn_suspended.load(Ordering::Relaxed), "CDN 調整暫停");
        floor.restore().await.unwrap();
        assert_eq!(r.cache.lock().unwrap().max, 2000);
        assert!(!r.cdn_suspended.load(Ordering::Relaxed));
    }

    #[test]
    fn explicit_user_cache_max_is_still_a_cap() {
        // 使用者明確設定 cacheMax：寬裕時也不會超過
        let cfg = kuroshio_config::with_overrides(&json!({ "resolver": { "cacheMax": 1234, "lastResort": [], "rankIps": false } }));
        let r = crate::app::build_resolver(&cfg).unwrap();
        let s = CacheStep::new(r.clone());
        s.set_growth(true);
        assert_eq!(r.cache.lock().unwrap().max, 1234);
        assert_eq!(s.cap.lock().unwrap().configured, 1234);
    }
}
