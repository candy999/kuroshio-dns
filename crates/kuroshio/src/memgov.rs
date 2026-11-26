//! 記憶體控制（規格 09）：記憶體是拿來用的。系統還有餘裕時，快取、CDN 網域資料庫、過濾清單盡量留在記憶體
//! （少寫 Flash、少重新下載）；別的程式需要記憶體時，依「重建成本由低到高」很快地讓出來，寬裕了再依相反順序恢復。
//! 使用者不必設定任何大小，也不分硬體等級。
//!
//! - **系統保留量**（[`Reserve`]）：系統可用記憶體（Linux `MemAvailable`、Windows `ullAvailPhys`）低於保留量就釋出；
//!   高於「保留量 + 遲滯」（[`margin`]）才恢復、才讓記憶體結構繼續長大。預設依平台自動決定（[`auto_reserve`]），
//!   可以用 `system.memoryReserveMB`（絕對值）與 / 或 `system.memoryReservePercent`（實體記憶體的百分比）指定，
//!   兩個都填取大的；0 = 自動。不看自己用了多少（沒有「預算」），只看整台機器還剩多少。
//! - **退讓於事無補**（3.5.0，[`FutileGate`]）：缺口（保留量 − 可用）大於自己用量的兩倍時（別的程式吃掉的，
//!   自己全部讓出也補不到一半），只停止長大、照樣寫出快照，不走下面的階梯；壓力訊號「不足」降成「偏低」。
//! - **反應快**：可用記憶體在保留量兩倍以內時每 2–3 秒量一次，離得遠時 30 秒（[`poll_interval`]）；
//!   Linux 有 PSI（`/proc/pressure/memory`）時當作提早的訊號：別的程式已經在等記憶體了，就先讓。
//!   沒有 PSI（舊核心，例如 Padavan 的 4.4）只能靠輪詢：比保留量多不到 [`NO_PSI_NEAR`] 時每 3 秒、其他 10 秒。
//! - **先讓出來**（[`Governor::trim`]，`kuroshio notify trim`）：韌體要做一件很佔記憶體的事（例如把韌體映像檔寫進 tmpfs）
//!   之前先呼叫，立刻做「吃緊」時會做的釋出（診斷緩衝、快取、CDN 冷資料；不停用過濾清單），
//!   並在一段時間內不長大、不恢復。
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
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};

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

/// 記憶體控制用的時鐘（秒）：單調遞增，不受系統時間調整影響（Padavan 開機時是 1970，對時後跳到現在，
/// 用牆上時間的話 hold、恢復間隔都會亂掉）。從一個很大的數開始，0 可以當「沒有」
pub fn steady_secs() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START.get_or_init(std::time::Instant::now).elapsed().as_secs() + 1_000_000_000
}

/// [`steady_secs`] 的時間換成牆上時間（Unix 毫秒），狀態頁顯示用
pub fn steady_to_wall_ms(t: u64) -> u64 {
    let back = steady_secs().saturating_sub(t);
    crate::persist::now_secs().saturating_sub(back) * 1000
}

/// 一次量測（bytes；量不到是 None）。測試直接造這個，不碰主機真正的記憶體
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Reading {
    /// 自己的常駐記憶體（Windows 是工作集）：不拿來決定狀態，只用在「於事無補」的判斷（[`futile_enter`]）
    pub rss: Option<u64>,
    /// 系統實體記憶體
    pub total: Option<u64>,
    /// 系統可用記憶體
    pub avail: Option<u64>,
    pub psi: Option<Psi>,
}

impl Reading {
    /// 量這台機器（Linux：/proc/meminfo、/proc/pressure/memory；Windows：GlobalMemoryStatusEx）。
    /// 測試開關（[`simulate`]，3.5.0 C9）開著時，系統可用記憶體換成 min(真實值, 模擬值)：
    /// 所有直接呼叫這裡的地方（記憶體控制、壓力訊號、評測的空間）看到的都一樣。只在背景的監看與工作裡呼叫，不在查詢路徑上
    pub fn now() -> Reading {
        let (total, avail) = sysinfo::mem_bytes();
        let r = Reading {
            rss: sysinfo::rss_bytes(),
            total,
            avail,
            psi: std::fs::read_to_string("/proc/pressure/memory").ok().as_deref().and_then(parse_psi),
        };
        apply_simulation(r, simulation(steady_secs()))
    }
}

// ------------------------------------------------------------ 測試開關：模擬記憶體不足（3.5.0 C9）
//
// 讓測試者在記憶體很多的機器（512 MB 的 D3、Windows）上觸發「吃緊／不足」的整套流程（停用清單、只轉送、恢復）。
// 兩道保險：設定 `system.testHooks: true`（預設 false，不放進 LuCI、設定頁、UCI 範例）才接受，
// 每次都有時間上限（最長 [`SIM_MAX_MINUTES`] 分鐘），到期自動恢復；只放在記憶體裡，重新啟動後不保留。
// 只會讓讀數變小（模擬不足），不能模擬成比真實更寬裕。

/// 一次最長幾分鐘
pub const SIM_MAX_MINUTES: u64 = 30;
/// 沒給 `minutes` 時幾分鐘
pub const SIM_DEFAULT_MINUTES: u64 = 5;
/// 模擬值上限（MB）：只是防呆，反正只會取比較小的
const SIM_MAX_MB: u64 = 1 << 20;
/// [`steady_secs`] 的起點（時間換成 u32 存）
const STEADY_BASE: u64 = 1_000_000_000;

/// 生效中的模擬
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Simulation {
    pub avail_mb: u32,
    /// 到期時間（[`steady_secs`]）
    pub until: u64,
}

fn to_rel(t: u64) -> u32 {
    t.saturating_sub(STEADY_BASE).clamp(1, u32::MAX as u64) as u32
}

/// 模擬的狀態（行程裡一份 [`SIM`]；測試自己造一份，不影響同一個行程裡的其他測試）。
/// 32 位元平台沒有 64 位元原子操作：時間存成「[`steady_secs`] 減掉起點」的 u32 秒
pub struct SimState {
    mb: AtomicU32,
    /// 到期時間；0 = 沒有開
    until: AtomicU32,
    /// 上次寫提醒的時間；0 = 還沒寫過
    warned: AtomicU32,
}

/// 行程裡的模擬狀態（只在記憶體裡：重新啟動後不保留）
pub static SIM: SimState = SimState::new();

impl SimState {
    pub const fn new() -> SimState {
        SimState {
            mb: AtomicU32::new(0),
            until: AtomicU32::new(0),
            warned: AtomicU32::new(0),
        }
    }

    /// 開始模擬（覆蓋前一次）：`minutes` 限制在 1～30。回傳生效的模擬
    pub fn start(&self, avail_mb: u64, minutes: u64, now: u64) -> Simulation {
        let minutes = minutes.clamp(1, SIM_MAX_MINUTES);
        let mb = avail_mb.min(SIM_MAX_MB) as u32;
        let until = now + minutes * 60;
        // 先寫值再寫到期時間：讀的人看到到期時間就一定看得到這次的值
        self.mb.store(mb, Ordering::Release);
        self.until.store(to_rel(until), Ordering::Release);
        self.warned.store(0, Ordering::Relaxed);
        Simulation { avail_mb: mb, until }
    }

    /// 立刻取消。回傳原本有沒有開
    pub fn stop(&self) -> bool {
        self.until.swap(0, Ordering::AcqRel) != 0
    }

    /// 目前生效的模擬（到期了就是 None）
    pub fn get(&self, now: u64) -> Option<Simulation> {
        let until = self.until.load(Ordering::Acquire);
        if until == 0 {
            return None;
        }
        let until = until as u64 + STEADY_BASE;
        (now < until).then(|| Simulation {
            avail_mb: self.mb.load(Ordering::Acquire),
            until,
        })
    }

    /// 記憶體監看每一輪呼叫：生效期間每分鐘回傳一行提醒，到期那一輪回傳「結束」一次（之後都是 None）
    pub fn notice(&self, now: u64) -> Option<String> {
        match self.get(now) {
            Some(s) => {
                let last = self.warned.load(Ordering::Relaxed);
                if last != 0 && now < last as u64 + STEADY_BASE + 60 {
                    return None;
                }
                self.warned.store(to_rel(now), Ordering::Relaxed);
                let left = s.until.saturating_sub(now);
                Some(format!(
                    "測試模式：模擬可用記憶體 {} MB，還有 {} 分鐘（system.testHooks；到期自動恢復，POST /api/memory/simulate?off=1 立刻取消）",
                    s.avail_mb,
                    left.div_ceil(60)
                ))
            }
            None => {
                let until = self.until.load(Ordering::Acquire);
                if until != 0 && self.until.compare_exchange(until, 0, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                    return Some("測試模式結束：記憶體模擬到期，回到真實的量測（之後由記憶體控制照常恢復）".into());
                }
                None
            }
        }
    }
}

impl Default for SimState {
    fn default() -> Self {
        SimState::new()
    }
}

/// 目前行程裡生效的模擬
pub fn simulation(now: u64) -> Option<Simulation> {
    SIM.get(now)
}

/// 設定的 `system.testHooks`（預設 false）：測試用的開關要它開著才接受（3.5.0 C9）
pub fn test_hooks(cfg: &Value) -> bool {
    kuroshio_config::get(cfg, "system.testHooks").and_then(Value::as_bool) == Some(true)
}

/// 純函式：把模擬套到一次量測上（可用記憶體 = min(真實值, 模擬值)；量不到時就是模擬值）
pub fn apply_simulation(mut r: Reading, sim: Option<Simulation>) -> Reading {
    if let Some(s) = sim {
        let cap = s.avail_mb as u64 * (1 << 20);
        r.avail = Some(r.avail.map_or(cap, |a| a.min(cap)));
    }
    r
}

/// `/api/status.memory.simulated`：`{ availMB, until（Unix 毫秒）, remainingSec }`，沒開時 null
pub fn simulation_json(sim: Option<Simulation>, now: u64) -> Value {
    match sim {
        Some(s) => json!({
            "availMB": s.avail_mb,
            "until": steady_to_wall_ms(s.until),
            "remainingSec": s.until.saturating_sub(now),
        }),
        None => Value::Null,
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
/// - Windows：max(128 MB, 實體記憶體 5%)（3.5.0；以前是 max(512 MB, min(10%, 4 GB))）。`ullAvailPhys` 包含待命清單
///   （standby，可以回收的快取），系統預設在可用約 32 MB / 4 GB（最多 64 MB）時才發「記憶體不足」通知，所以還是比 Linux
///   留得多；但 10% 在大記憶體的機器上（例如 64 GB、跑本地 AI 的桌機）一開機就吃緊，黑潮自己全部讓出也只有一兩百 MB。
///   128 MB 是下限：很小的 VM（2 GB）上 5% 只有 100 MB。
/// - 一律不超過實體記憶體的一半。
pub fn auto_reserve(total: Option<u64>, platform: Platform, min_free_kb: Option<u64>) -> (u64, String) {
    let (bytes, how) = match platform {
        Platform::Windows => {
            let pct = total.map(|t| t / 20).unwrap_or(0);
            (pct.max(WINDOWS_RESERVE_FLOOR), "自動：max(128 MB, 實體記憶體 5%)".to_string())
        }
        Platform::Linux | Platform::Other => {
            let pct = total.map(|t| (t / 20).min(1024 * MB)).unwrap_or(0);
            let wm = min_free_kb.unwrap_or(0) * 1024 * 3;
            (
                (16 * MB).max(pct).max(wm),
                format!(
                    "自動：max(16 MB, min(實體記憶體 5%, 1 GB), min_free_kbytes {} KB × 3)",
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

/// Windows 自動保留量的下限（很小的 VM 上 5% 太少）
pub const WINDOWS_RESERVE_FLOOR: u64 = 128 * MB;

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
    } else if r.psi.is_none() && a < res.bytes.saturating_add(NO_PSI_NEAR) {
        // 沒有 PSI：別的程式突然要一大塊（幾秒內寫進 tmpfs 十幾 MB）時沒有提早的訊號，量勤一點
        3
    } else if r.psi.is_none() {
        10
    } else {
        30
    }
}

/// 沒有 PSI 時「離保留量很近」的距離：比保留量多不到這麼多就每 3 秒量一次
pub const NO_PSI_NEAR: u64 = 64 * MB;

/// `kuroshio notify trim` 預設不長大、不恢復的時間（秒）
pub const TRIM_HOLD_DEFAULT: u64 = 300;
/// 最長可以要求多久
pub const TRIM_HOLD_MAX: u64 = 3600;

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

// ------------------------------------------------------------ 退讓於事無補（3.5.0，規格 09 第 12 節）
//
// 缺口（保留量 − 可用）大到黑潮自己全部讓出也補不到一半時（用量 × 2 < 缺口），讓出只會讓 DNS 變差、對系統沒有幫助
// ——例如 Windows 上別的程式吃掉幾十 GB，黑潮自己只有一兩百 MB。這時只停止長大、照樣寫出快照（保護資料），
// 不縮快取、不移出 CDN 冷資料、不縮診斷緩衝、不停用清單、不暫停保護清單；給其他模組的壓力訊號從「不足」降成「偏低」
// （不拒絕新的加密連線，只限 32 條）。路由器上保留量只有十幾到二十幾 MB，缺口最多就是保留量，
// 黑潮自己通常好幾十 MB，所以小機器上不會成立。讀不到自己的用量或可用記憶體時規則不成立（照舊）。

/// 離開「於事無補」要離開的條件連續成立多久（秒）。回到寬裕（可用 ≥ 保留量 + 遲滯）也一樣要連續這麼久
/// （3.5.0 F1：可用記憶體被別的程式拉上拉下時，回到寬裕立刻離開會 5 分鐘進出好幾次）；只有讀不到量測時立刻離開
pub const FUTILE_EXIT_SECS: u64 = 60;

/// 缺口（保留量 − 可用，沒有缺是 0）與自己的用量（bytes）；有一個量不到（或用量是 0）就是 None
pub fn deficit_and_own(r: &Reading, res: &Reserve) -> Option<(u64, u64)> {
    let own = r.rss.filter(|&b| b > 0)?;
    let a = r.avail?;
    Some((res.bytes.saturating_sub(a), own))
}

/// 進入：自己全部讓出也補不到缺口的一半（用量 × 2 < 缺口）
pub fn futile_enter(r: &Reading, res: &Reserve) -> bool {
    deficit_and_own(r, res).is_some_and(|(d, own)| (own as u128) * 2 < d as u128)
}

/// 維持：用量 × 2 < 缺口 × 1.2（離開要「用量 × 2 ≥ 缺口 × 1.2」：比進入的門檻多 20% 的遲滯）
pub fn futile_hold(r: &Reading, res: &Reserve) -> bool {
    deficit_and_own(r, res).is_some_and(|(d, own)| (own as u128) * 20 < d as u128 * 12)
}

/// 「記憶體不足，但缺口是其他程式造成」那一行 INFO：同一段於事無補（從進入到離開）只寫一次
/// （3.5.0 第一階段 Windows W19／J3：可用記憶體被別的程式拉上拉下時，每次掉回保留量以下都再寫一行，5 分鐘 6 次）。
/// 進入時的 WARN 已經說明了；離開之後再進入才重新寫
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FutileNote {
    noted: bool,
}

impl FutileNote {
    /// 每一輪量測後呼叫：不在於事無補（離開了）就重新算
    pub fn observe(&mut self, futile: bool) {
        if !futile {
            self.noted = false;
        }
    }

    /// 這一次要不要寫那一行（寫了就記住，這一段不再寫）
    pub fn take(&mut self) -> bool {
        !std::mem::replace(&mut self.noted, true)
    }
}

/// 「於事無補」的判定與遲滯（純狀態，測試直接造）
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FutileGate {
    pub on: bool,
    /// 離開的條件從什麼時候開始一直成立
    exit_since: Option<u64>,
}

impl FutileGate {
    /// 依量測更新，回傳有沒有改變。進入：立刻（只會少做事）；離開：讀不到量測時立刻（沒有依據繼續判），
    /// 否則「用量 × 2 ≥ 缺口 × 1.2」（包括回到寬裕：沒有缺口）要連續 `dwell` 秒（不會每幾秒切換一次）
    pub fn step(&mut self, r: &Reading, res: &Reserve, dwell: u64, now: u64) -> bool {
        if !self.on {
            if futile_enter(r, res) {
                self.on = true;
                self.exit_since = None;
                return true;
            }
            return false;
        }
        if deficit_and_own(r, res).is_none() {
            self.on = false;
            self.exit_since = None;
            return true;
        }
        // 回到寬裕時缺口是 0，`futile_hold` 不成立，跟「讓得出來」一起算連續時間
        if futile_hold(r, res) {
            self.exit_since = None;
            return false;
        }
        let since = *self.exit_since.get_or_insert(now);
        if now.saturating_sub(since) >= dwell {
            self.on = false;
            self.exit_since = None;
            return true;
        }
        false
    }
}

/// bytes → MB，四捨五入（3.5.0 F6／H12：日誌以前用 `>> 20` 捨去，狀態頁四捨五入，保留量一邊 3,264 一邊 3,265）
pub fn mb_round(bytes: u64) -> u64 {
    bytes.saturating_add(1 << 19) >> 20
}

/// 進入 / 離開「於事無補」的那一行日誌（進入 WARN、離開 info；只在改變時寫）
pub fn futile_message(on: bool, r: &Reading, res: &Reserve) -> String {
    let (d, own) = deficit_and_own(r, res).unwrap_or((0, 0));
    let (d, own) = (mb_round(d), mb_round(own));
    if on {
        format!("可用記憶體不足是其他程式造成（缺口 {d} MB，黑潮全部讓出也只有 {own} MB）：只停止長大、寫出快照，不縮快取、不停用清單")
    } else {
        format!("記憶體缺口回到黑潮讓得出來的範圍（缺口 {d} MB，黑潮 {own} MB）：照一般的方式讓出與恢復")
    }
}

fn log_futile(on: bool, r: &Reading, res: &Reserve) -> String {
    let msg = futile_message(on, r, res);
    if on {
        warn!("{msg}");
    } else {
        info!("{msg}");
    }
    msg
}

/// 給整個程式的壓力訊號：於事無補時「不足」降成「偏低」（不拒絕新的加密連線、清單更新不延後到不足解除）
pub fn signal_pressure(p: Pressure, futile: bool) -> Pressure {
    match p {
        Pressure::Critical if futile => Pressure::Low,
        p => p,
    }
}

/// 目前是不是「於事無補」（記憶體監看每一輪更新；給沒有記憶體控制時的舊做法與狀態頁的提醒）
static FUTILE: AtomicBool = AtomicBool::new(false);

pub fn futile() -> bool {
    FUTILE.load(Ordering::Relaxed)
}

pub fn set_futile(on: bool) {
    FUTILE.store(on, Ordering::Relaxed);
}

/// 記憶體控制關掉時，記憶體監看自己判斷（同一套規則與日誌）
pub fn observe_futile_standalone(gate: &mut FutileGate, r: &Reading, res: &Reserve, now: u64) -> bool {
    if gate.step(r, res, FUTILE_EXIT_SECS, now) {
        log_futile(gate.on, r, res);
    }
    gate.on
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
/// 讓出的記憶體值不值得寫一行 WARN（1 KB 以上）
fn worth_warning(bytes: u64) -> bool {
    bytes >= 1024
}

/// CDN 冷資料移出的結果。沒有冷資料是「做了 0」而不是錯誤（3.5.0 F6／H8：以前記憶體吃緊時每分鐘一行
/// WARN「…沒有做：沒有可以移出的冷資料」）；0 bytes 的結果走 DEBUG，這一步照樣等久一點再試
fn cdn_evict_outcome(entries: usize, bytes: u64) -> Outcome {
    if entries == 0 {
        return Outcome {
            bytes: 0,
            detail: "沒有可以移出的冷資料".into(),
        };
    }
    Outcome {
        bytes,
        detail: format!("{entries} 筆（磁碟上保留，查到時讀回）"),
    }
}

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
    /// 這一步剛讓出、而且還有東西可以讓，只是在等下一次（3.5.1 G1）：後面的步驟先不做。
    /// 大量冷門網域湧入時 CDN 冷資料一輪一輪移出，等待的空檔不能讓過濾清單插隊
    fn holds_later(&self) -> bool {
        false
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
    /// 釋出，`short` = 這一輪還缺多少（bytes；離保留量遠時由 [`Governor::tick`] 算：缺口 − 這一輪前面步驟已經釋出的；
    /// 0 = 只做一個單位）。預設照 [`shed`](Self::shed)；過濾清單依它一次停用幾份、只重建一次（3.5.0 C3）
    fn shed_for<'a>(&'a self, r: &'a Reading, _short: u64) -> BoxFut<'a, anyhow::Result<Outcome>> {
        self.shed(r)
    }
    /// 恢復，`room` = 可以拿來恢復的空間（[`restore_room`]）。預設照 [`restore`](Self::restore)；
    /// 過濾清單依它一次恢復幾份、只重建一次（3.5.0 C3）
    fn restore_for(&self, _room: u64) -> BoxFut<'_, anyhow::Result<Outcome>> {
        self.restore()
    }
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

/// [`Governor::finding_summary`] 的內容
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemSummary {
    pub state: State,
    pub avail: Option<u64>,
    pub reserve: u64,
    pub futile: bool,
    pub floor: bool,
    pub protected: bool,
    /// 讓出了哪些（步驟名稱，依順序、不重複）
    pub shed: Vec<&'static str>,
}

/// 同一步可以一輪一輪讓出的（CDN 冷資料，3.5.1 G1）：同一步最多留這麼多筆紀錄，再多就併進最舊的那一筆
const SHED_RECS_PER_STEP: usize = 4;

/// 記一筆讓出；同一步的紀錄超過 [`SHED_RECS_PER_STEP`] 時把最舊的兩筆合成一筆（大量冷門網域時不會一直長）
fn push_shed(v: &mut Vec<ShedRec>, rec: ShedRec) {
    let key = rec.key;
    v.push(rec);
    let idx: Vec<usize> = v.iter().enumerate().filter(|(_, x)| x.key == key).map(|(k, _)| k).collect();
    if idx.len() > SHED_RECS_PER_STEP {
        let (a, b) = (idx[0], idx[1]);
        let old = v.remove(a);
        let x = &mut v[b - 1];
        x.bytes += old.bytes;
        x.avail_before = old.avail_before.or(x.avail_before);
        x.at = old.at.min(x.at);
    }
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
    /// `trim` 要求的「先不長大、不恢復」到這個時間（秒）
    hold_until: u64,
    /// 退讓於事無補（3.5.0）：由記憶體監看每一輪 [`Governor::observe_futile`] 更新
    futile: FutileGate,
    /// 這一次不寬裕從什麼時候開始（回到寬裕時清掉；3.5.1 N1）
    pressed_since: Option<u64>,
    /// 上一次讓出 [`USEFUL_SHED_BYTES`] 以上的時間
    last_useful_shed: u64,
}

/// 讓出這麼多以上才算「還有東西可以讓」（判斷記憶體回不來用；3.5.1 N1）
pub const USEFUL_SHED_BYTES: u64 = 256 * 1024;
/// 不寬裕而且什麼都讓不出來，持續這麼久才考慮原地重新啟動（秒）
pub const RESTART_STUCK_SECS: u64 = 600;
/// 兩次原地重新啟動至少隔多久（秒；用環境變數 [`RESTART_ENV`] 帶到下一個行程）
pub const RESTART_MIN_GAP_SECS: u64 = 6 * 3600;
/// 最近 15 分鐘平均每秒查詢少於這個才算離峰
pub const RESTART_LOW_QPS: u64 = 10;
/// 自己的用量（RSS）至少佔實體記憶體這麼多 % 才算「是自己回不來」（不是別的程式）
pub const RESTART_OWN_PERCENT: u64 = 30;
/// 上一次原地重新啟動的時間（Unix 秒），重新執行時帶給新的行程
pub const RESTART_ENV: &str = "KUROSHIO_MEMORY_RESTART_AT";

static RESTART_PENDING: AtomicBool = AtomicBool::new(false);
static RESTART_NOTIFY: std::sync::OnceLock<tokio::sync::Notify> = std::sync::OnceLock::new();

fn restart_notify() -> &'static tokio::sync::Notify {
    RESTART_NOTIFY.get_or_init(tokio::sync::Notify::new)
}

/// 記憶體控制要求原地重新啟動（3.5.1 N1）：主程式的停止訊號也等它，收到就照正常停止寫完快照，
/// 再用同一個 PID 重新執行（[`reexec_self`]）
pub async fn restart_requested() {
    if RESTART_PENDING.load(Ordering::Relaxed) {
        return;
    }
    restart_notify().notified().await
}

/// 要求原地重新啟動（記憶體控制判斷回不來時；測試開關 `POST /api/memory/restart`）。已經要求過的不再重複
pub fn request_restart(msg: &str) -> bool {
    if RESTART_PENDING.swap(true, Ordering::Relaxed) {
        return false;
    }
    warn!("{msg}");
    restart_notify().notify_waiters();
    true
}

/// 停止之後要不要原地重新執行
pub fn restart_pending() -> bool {
    RESTART_PENDING.load(Ordering::Relaxed)
}

/// 上一次原地重新啟動的時間（Unix 秒；沒有是 0）
fn last_restart_at() -> u64 {
    std::env::var(RESTART_ENV).ok().and_then(|v| v.parse().ok()).unwrap_or(0)
}

/// 用同一個 PID 重新執行自己（Linux：execve）。參數、環境變數照舊，另外帶上這次的時間（[`RESTART_ENV`]）。
/// 執行檔路徑用 `current_exe()`（`/usr/bin/kuroshio`，行程名稱照舊，看門狗用 `pidof` 找得到）；
/// 檔案被換掉、讀不到時用 `/proc/self/exe`。成功時不會回來；失敗回傳錯誤（呼叫端照一般停止結束）
#[cfg(target_os = "linux")]
pub fn reexec_self() -> std::io::Error {
    use std::os::unix::process::CommandExt;
    let exe = std::env::current_exe()
        .ok()
        .filter(|p| p.exists())
        .unwrap_or_else(|| std::path::PathBuf::from("/proc/self/exe"));
    let mut args = std::env::args_os();
    let arg0 = args.next().unwrap_or_else(|| exe.clone().into_os_string());
    std::process::Command::new(&exe)
        .arg0(arg0)
        .args(args)
        .env(RESTART_ENV, crate::persist::now_secs().to_string())
        .exec()
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
    /// 記憶體回不來時原地重新啟動（`system.memoryRestart`，只有 Linux；3.5.1 N1）
    pub restart: AtomicBool,
    /// 最近 15 分鐘的查詢數（離峰判斷；沒有設定時不重新啟動）
    load_probe: Mutex<Option<Box<dyn Fn() -> u64 + Send + Sync>>>,
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
                hold_until: 0,
                futile: FutileGate::default(),
                pressed_since: None,
                last_useful_shed: 0,
            }),
            gap: 5,
            dwell: 180,
            reader: Mutex::new(Box::new(Reading::now)),
            restart: AtomicBool::new(false),
            load_probe: Mutex::new(None),
        }
    }

    /// 不寬裕的時候也可以先恢復的一步（3.5.1 N1）：只在「真的不足」時才做的步驟（[`Step::min_state`] 是不足：
    /// 停用過濾清單、只轉送、暫停保護清單），觸發它的條件已經不成立（[`Step::wanted`] 是 false）、PSI 平靜、
    /// 讓出之後過了 `dwell`、可用記憶體 − 保留量的一半 ≥ 這一步要的 × 1.3。從最後讓出的開始，一次一步。
    ///
    /// 以前要等整體回到寬裕才恢復：musl 放掉的記憶體不還給系統，洪水過後可用記憶體回不到保留量以上，
    /// 過濾清單（26 萬條規則只佔約 1.9 MB）就一直停用到重新啟動（3.5.1 測試版 D3）
    fn partial_restore(&self, i: &Inner, r: &Reading, now: u64) -> Option<(usize, u64)> {
        if now < i.next_restore_at || i.futile.on || !r.psi.map_or(true, |p| p.calm()) {
            return None;
        }
        let k = self.steps.iter().rposition(|s| s.is_shed())?;
        let s = &self.steps[k];
        if s.min_state() != State::Critical || s.wanted(r, &self.reserve) {
            return None;
        }
        let last_shed = i.shed.iter().rev().find(|x| x.key == s.key()).map_or(0, |x| x.at);
        if now.saturating_sub(last_shed) < self.dwell {
            return None;
        }
        let room = r.avail?.saturating_sub(self.reserve.bytes / 2);
        (room as u128 >= s.restore_need() as u128 * 13 / 10).then_some((k, room))
    }

    /// 最近 15 分鐘的查詢數從哪裡來（離峰判斷；3.5.1 N1）
    pub fn set_load_probe(&self, f: impl Fn() -> u64 + Send + Sync + 'static) {
        *self.load_probe.lock().unwrap() = Some(Box::new(f));
    }

    /// 該不該原地重新啟動（3.5.1 N1）：讓得出的都讓了還回不來（不寬裕持續 10 分鐘以上、10 分鐘內沒有讓出
    /// 256 KB 以上、現在也沒有能做的步驟）、是自己回不來（RSS ≥ 實體記憶體 30%，不是於事無補）、離峰（最近 15 分鐘
    /// 平均每秒 10 筆以下）、離上一次 6 小時以上。原因：musl 的配置器放掉的小塊記憶體不還給系統，洪水過後就一直
    /// 卡在吃緊／不足，過濾清單、快取、CDN 新網域一直減量到重新啟動為止（3.5.1 測試版 D3：停了 15 分鐘 RSS 還是 309 MB）
    fn restart_due(&self, i: &Inner, state: State, r: &Reading, now: u64, wall: u64) -> bool {
        if !self.restart.load(Ordering::Relaxed) || RESTART_PENDING.load(Ordering::Relaxed) {
            return false;
        }
        if state == State::Comfortable || i.futile.on {
            return false;
        }
        let stuck = i.pressed_since.is_some_and(|t| now.saturating_sub(t) >= RESTART_STUCK_SECS)
            && now.saturating_sub(i.last_useful_shed) >= RESTART_STUCK_SECS
            && self.pick(i, state, r, now).is_none();
        if !stuck {
            return false;
        }
        let mine = match (r.rss, r.total) {
            (Some(rss), Some(t)) if t > 0 => rss.saturating_mul(100) >= t.saturating_mul(RESTART_OWN_PERCENT),
            _ => false,
        };
        let quiet = self
            .load_probe
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|f| f() < RESTART_LOW_QPS * 15 * 60);
        let last = last_restart_at();
        mine && quiet && (last == 0 || wall.saturating_sub(last) >= RESTART_MIN_GAP_SECS)
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

    /// 退讓於事無補（3.5.0）：用這次的量測更新判定（記憶體監看每一輪呼叫，在 [`tick`](Self::tick) 之前），
    /// 改變時記一行日誌與事件。回傳現在是不是於事無補
    pub fn observe_futile(&self, r: &Reading, now: u64) -> bool {
        let mut g = self.inner.lock().unwrap();
        let i = &mut *g;
        if i.futile.step(r, &self.reserve, FUTILE_EXIT_SECS, now) {
            let msg = log_futile(i.futile.on, r, &self.reserve);
            Self::event(i, now, msg);
        }
        i.futile.on
    }

    /// 目前是不是「於事無補」
    pub fn is_futile(&self) -> bool {
        self.inner.lock().unwrap().futile.on
    }

    /// 發現清單用的摘要（3.5.1 H3）：狀態、可用與保留量、讓出了哪些（依步驟、不重複）、只轉送、保護清單暫停、於事無補
    pub fn finding_summary(&self) -> MemSummary {
        let (state, avail, futile, mut shed) = {
            let i = self.inner.lock().unwrap();
            let labels: Vec<&'static str> = i.shed.iter().map(|s| s.label).collect();
            (i.hyst.state, i.last.avail, i.futile.on, labels)
        };
        shed.dedup();
        MemSummary {
            state,
            avail,
            reserve: self.reserve.bytes,
            futile,
            floor: self.at_floor(),
            protected: self.steps.iter().any(|s| s.key() == "protected" && s.is_shed()),
            shed,
        }
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

    /// 這一輪要做的步驟：照順序第一個可以做的；前面有步驟在等下一次（[`Step::holds_later`]）時後面的不做（3.5.1 G1）
    fn pick(&self, i: &Inner, state: State, r: &Reading, now: u64) -> Option<usize> {
        for k in 0..self.steps.len() {
            if self.eligible(i, k, state, r, now) {
                return Some(k);
            }
            let s = &self.steps[k];
            if state >= s.min_state() && now >= i.skip_until[k] && s.holds_later() {
                return None;
            }
        }
        None
    }

    /// 一輪：更新狀態，必要時釋出（離保留量遠時連做好幾步）或恢復一步。
    /// 回傳這輪做了什麼（`shed:鍵` / `restore:鍵`，好幾步用逗號分開）
    pub async fn tick(&self, r: Reading, now: u64) -> Option<String> {
        enum Plan {
            Shed { far: bool, deficit: u64 },
            Restore(usize, u64),
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
                // 往回降（不足 → 吃緊）時寫明是「回升」：以前同一句「記憶體吃緊（系統可用 29 GB…）」
                // 看起來像又不夠了（3.4.2 Windows 實測）
                let msg = format!(
                    "記憶體{}{}（系統可用 {} KB，保留 {} KB）",
                    if to < from { "回升，目前" } else { "" },
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
            if state == State::Comfortable {
                i.pressed_since = None;
            } else if i.pressed_since.is_none() {
                i.pressed_since = Some(now);
            }
            if self.restart_due(i, state, &r, now, crate::persist::now_secs()) {
                let msg = format!(
                    "記憶體控制：讓得出的都讓了，可用記憶體還是回不來（系統可用 {} MB，保留 {} MB，黑潮用了 {} MB；\
                     配置器放掉的記憶體沒有還給系統）。現在是離峰：先寫出快照，原地重新啟動一次拿回記憶體（DNS 中斷幾秒；6 小時最多一次）",
                    r.avail.map_or(0, mb_round),
                    mb_round(self.reserve.bytes),
                    r.rss.map_or(0, mb_round)
                );
                if request_restart(&msg) {
                    Self::event(i, now, msg);
                }
            }
            // 長大：寬裕而且離保留量 + 遲滯還有空間（`trim` 要求暫停的期間不長大）
            let held = now < i.hold_until;
            let growth = !held && state == State::Comfortable && pressure_of(&r, &self.reserve) == Pressure::Normal;
            GROWTH.store(growth, Ordering::Relaxed);
            let growth_change = (growth != i.growth).then_some(growth);
            i.growth = growth;
            i.waiting = None;
            let plan = if state > State::Comfortable && i.futile.on {
                // 於事無補：只停止長大（上面已經停了）、快照照樣由寫入器依它自己的量測寫出；不讓出任何東西。
                // 之前已經讓出的照舊等寬裕才恢復（不因為判定改變就恢復或停用，不來回）
                let (d, own) = deficit_and_own(&r, &self.reserve).unwrap_or((0, 0));
                i.waiting = Some(format!(
                    "於事無補：缺口 {} MB 是其他程式造成（黑潮全部讓出也只有 {} MB），只停止長大、不讓出",
                    mb_round(d),
                    mb_round(own)
                ));
                None
            } else if state > State::Comfortable
                && r.avail
                    .is_some_and(|a| a >= self.reserve.bytes.saturating_add(self.reserve.margin()))
                && r.psi.map_or(true, |p| p.calm())
            {
                // 狀態還在等穩定（`dwell`），但這一次的讀數已經回到保留量 + 遲滯以上、PSI 也平靜：沒有缺口，不讓出。
                // 常見的是別的程式（Windows 上的大模型）一下子放掉記憶體：狀態要穩定 180 秒才降，這段時間照狀態去讓出
                // 就會在可用記憶體很多的時候移出 CDN 冷資料、縮診斷緩衝（3.5.0 F1，Windows 實測 H1）。
                // 下一次讀數掉回去就照舊讓出（路由器上本來就沒有缺口的那一刻讓出也沒有用）
                i.waiting = Some("可用記憶體已經回到保留量以上，等狀態穩定，不再讓出".to_string());
                None
            } else if state > State::Comfortable {
                let any = self.pick(i, state, &r, now).is_some();
                if any {
                    (now >= i.next_shed_at).then(|| {
                        let deficit = r.avail.map_or(0, |a| self.reserve.bytes.saturating_sub(a));
                        let far = state == State::Critical || r.avail.is_some_and(|a| a < self.reserve.bytes / 4 * 3);
                        Plan::Shed { far, deficit }
                    })
                } else {
                    self.partial_restore(i, &r, now).map(|(k, room)| Plan::Restore(k, room))
                }
            } else if held {
                i.waiting = Some(format!("應要求先讓出記憶體，{} 秒內不恢復", i.hold_until - now));
                None
            } else if now.saturating_sub(i.hyst.changed_at) >= self.dwell && now >= i.next_restore_at {
                match self.steps.iter().rposition(|s| s.is_shed()) {
                    Some(k) => {
                        let need = self.steps[k].restore_need();
                        let room = restore_room(&r, &self.reserve);
                        if room as u128 >= need as u128 * 13 / 10 {
                            Some(Plan::Restore(k, room))
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
                        self.pick(&i, state, &r, now)
                    };
                    let Some(k) = k else { break };
                    let s = &self.steps[k];
                    // 離保留量遠：告訴這一步還缺多少（過濾清單依它一次停用幾份、只重建一次）；不遠：一次一個單位
                    let short = if far { deficit.saturating_sub(freed) } else { 0 };
                    let res = s.shed_for(&r, short).await;
                    // 把釋出的記憶體還給系統（glibc 不會自己還；musl 大塊會直接還）
                    sysinfo::trim_heap();
                    let mut g = self.inner.lock().unwrap();
                    let i = &mut *g;
                    i.next_shed_at = now + self.gap;
                    match res {
                        Ok(o) => {
                            // 讓出不到 1 KB 的步驟（例如快取已經是空的）不寫 WARN：只收 WARN 日誌的小機器上是雜訊（3.5.0）
                            if worth_warning(o.bytes) {
                                warn!("記憶體控制：{}（約 {} KB）{}", s.label(), o.bytes / 1024, o.detail);
                            } else {
                                debug!("記憶體控制：{}（約 {} KB）{}", s.label(), o.bytes / 1024, o.detail);
                            }
                            if o.bytes == 0 {
                                // 這一步沒有東西可以讓（例如 CDN 沒有冷資料，3.5.0 F6／H8）：不是錯誤、不寫 WARN，
                                // 但跟失敗一樣等久一點再試，不要每一輪都做一次
                                i.skip_until[k] = now + (self.gap * 10).max(60);
                            }
                            i.freed_total += o.bytes;
                            freed += o.bytes;
                            if o.bytes >= USEFUL_SHED_BYTES {
                                i.last_useful_shed = now;
                            }
                            Self::event(i, now, format!("釋出：{} {}（約 {} KB）", s.label(), o.detail, o.bytes / 1024));
                            push_shed(
                                &mut i.shed,
                                ShedRec {
                                    key: s.key(),
                                    label: s.label(),
                                    detail: o.detail,
                                    bytes: o.bytes,
                                    avail_before: r.avail,
                                    avail_delta: None,
                                    at: now,
                                },
                            );
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
            Plan::Restore(k, room) => {
                let s = &self.steps[k];
                let res = s.restore_for(room).await;
                let mut g = self.inner.lock().unwrap();
                let i = &mut *g;
                match res {
                    Ok(o) => {
                        // 步驟名稱是「讓出」的動作（例如「暫時停用過濾清單」），恢復時寫成取消它，不然看起來像又停用了一次
                        info!("記憶體恢復：取消「{}」{}", s.label(), o.detail);
                        i.restore_fails = 0;
                        i.last_restore_at = Some(now);
                        i.next_restore_at = now + ((self.gap * 6) << i.flap).min(MAX_BACKOFF);
                        if !s.is_shed() {
                            i.shed.retain(|x| x.key != s.key());
                        } else if let Some(p) = i.shed.iter().rposition(|x| x.key == s.key()) {
                            i.shed.remove(p);
                        }
                        Self::event(i, now, format!("恢復：取消「{}」{}", s.label(), o.detail));
                    }
                    Err(e) => {
                        i.restore_fails = (i.restore_fails + 1).min(16);
                        let wait = (300u64 << (i.restore_fails - 1).min(10)).min(MAX_BACKOFF);
                        i.next_restore_at = now + wait;
                        warn!("記憶體恢復：取消「{}」失敗（{e:#}），{} 分鐘後重試", s.label(), wait / 60);
                        Self::event(i, now, format!("恢復{}失敗：{e:#}（{} 分鐘後重試）", s.label(), wait / 60));
                    }
                }
                Some(format!("restore:{}", s.key()))
            }
        }
    }

    /// 應要求先讓出記憶體（`kuroshio notify trim`、`POST /api/memory/trim`）：不管目前寬不寬裕，
    /// 立刻做「吃緊」時會做的每一步（[`Step::min_state`] 是吃緊的：診斷緩衝、快取、CDN 冷資料；
    /// 過濾清單與純轉送只在系統真的不足時才做，這裡不碰），然後 `hold` 秒內不長大、不恢復。
    /// 回傳 `{ steps: [...], freedBytes, holdSec, availKB }`
    pub async fn trim(&self, hold: u64, now: u64) -> Value {
        let hold = hold.clamp(1, TRIM_HOLD_MAX);
        {
            let mut i = self.inner.lock().unwrap();
            i.hold_until = i.hold_until.max(now + hold);
            i.growth = false;
        }
        GROWTH.store(false, Ordering::Relaxed);
        for s in &self.steps {
            s.set_growth(false);
        }
        let before = self.read();
        let mut done = Vec::new();
        let mut freed = 0u64;
        for s in self.steps.iter().filter(|s| s.min_state() <= State::Tight) {
            if !s.can_shed() {
                continue;
            }
            match s.shed(&before).await {
                Ok(o) => {
                    info!("記憶體控制（應要求先讓出）：{}（約 {} KB）{}", s.label(), o.bytes / 1024, o.detail);
                    freed += o.bytes;
                    let mut g = self.inner.lock().unwrap();
                    let i = &mut *g;
                    i.freed_total += o.bytes;
                    Self::event(
                        i,
                        now,
                        format!("應要求釋出：{} {}（約 {} KB）", s.label(), o.detail, o.bytes / 1024),
                    );
                    push_shed(
                        &mut i.shed,
                        ShedRec {
                            key: s.key(),
                            label: s.label(),
                            detail: o.detail.clone(),
                            bytes: o.bytes,
                            avail_before: before.avail,
                            avail_delta: None,
                            at: now,
                        },
                    );
                    done.push(json!({ "step": s.key(), "label": s.label(), "freedBytes": o.bytes, "detail": o.detail }));
                }
                Err(e) => done.push(json!({ "step": s.key(), "label": s.label(), "skipped": format!("{e:#}") })),
            }
        }
        sysinfo::trim_heap();
        let after = self.read();
        {
            let mut g = self.inner.lock().unwrap();
            let i = &mut *g;
            i.last = after;
            Self::event(
                i,
                now,
                format!("應要求先讓出記憶體：約 {} KB，{hold} 秒內不長大、不恢復", freed / 1024),
            );
        }
        json!({
            "ok": true,
            "steps": done,
            "freedBytes": freed,
            "holdSec": hold,
            "availKB": after.avail.map(|b| b / 1024),
            "availBeforeKB": before.avail.map(|b| b / 1024),
        })
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
        // 3.4.1：分項加總與「其他」（程式本身、連線與背景工作、配置器還沒還給系統的空間）。
        // 「其他」很大而且讓出記憶體後也不降，多半是配置器沒把空出來的記憶體還給系統
        let accounted: u64 = sizes
            .iter()
            .filter(|(k, _)| k.ends_with("Bytes"))
            .filter_map(|(_, v)| v.as_u64())
            .sum();
        sizes.insert("accountedBytes".into(), json!(accounted));
        sizes.insert("otherBytes".into(), json!(r.rss.map(|rss| rss.saturating_sub(accounted))));
        let kb = |x: Option<u64>| x.map(|v| v / 1024);
        json!({
            "enabled": true,
            "state": i.hyst.state.as_str(),
            "stateLabel": i.hyst.state.label(),
            // 當下的量測（不經遲滯）：normal／low／critical。`state` 放鬆要穩定 `dwell` 秒，兩者會差幾分鐘（3.4.3）
            "pressure": crate::app::pressure().as_str(),
            "since": steady_to_wall_ms(i.hyst.changed_at),
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
            "holdUntil": (i.hold_until > steady_secs()).then(|| steady_to_wall_ms(i.hold_until)),
            "floor": floor,
            "protectedSuspended": protected,
            // 退讓於事無補（3.5.0）：缺口（保留量 − 可用）與自己的用量；量不到是 null
            "futile": i.futile.on,
            "deficitBytes": r.avail.map(|a| self.reserve.bytes.saturating_sub(a)),
            "ownBytes": r.rss,
            "sizes": Value::Object(sizes),
            "shed": i.shed.iter().map(|s| json!({
                "step": s.key, "label": s.label, "detail": s.detail, "freedBytes": s.bytes,
                "availDeltaKB": s.avail_delta.map(|d| d / 1024), "at": steady_to_wall_ms(s.at),
            })).collect::<Vec<_>>(),
            "freedBytes": i.shed.iter().map(|s| s.bytes).sum::<u64>(),
            "freedTotalBytes": i.freed_total,
            "lastChange": i.last_change.map(|(at, from, to)| json!({ "at": steady_to_wall_ms(at), "from": from.as_str(), "to": to.as_str() })),
            "waiting": i.waiting,
            "nextRestoreAt": (i.next_restore_at > 0 && !i.shed.is_empty()).then(|| steady_to_wall_ms(i.next_restore_at)),
            "events": i.events.iter().rev().map(|e| json!({ "at": steady_to_wall_ms(e.at), "msg": e.msg })).collect::<Vec<_>>(),
            // 測試開關（3.5.0 C9）：模擬可用記憶體中（null = 沒開）
            "simulated": simulation_json(simulation(steady_secs()), steady_secs()),
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
        "縮小診斷緩衝（日誌、熱門排行、查詢紀錄）"
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
            // 查詢紀錄（3.5.0）：關閉並釋放緩衝；恢復時不自動再開（暫時開啟的要使用者重新按）
            let q = self.stats.querylog.release();
            let ql = if q > 0 { "、關閉查詢紀錄" } else { "" };
            Ok(Outcome {
                bytes: (a + b) as u64 + q,
                detail: format!("日誌 {} 行、排行前 {SHED_TOP_KEEP} 名{ql}", crate::logring::SHED_LINES),
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
        let (len, max, bytes) = {
            let c = self.resolver.cache.lock().unwrap();
            (c.len(), c.max, c.approx_bytes())
        };
        out.insert("cacheEntries".into(), json!(len));
        out.insert("cacheBytes".into(), json!(bytes));
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

/// 先把變動寫進磁碟，再從最冷的開始把網域移出記憶體，估計釋出到 `target` bytes 就停（`usize::MAX` = 能移的全部）；
/// 最後出現在 `protect_ms` 以內的不動（3.5.1 G1）
async fn evict_cdn(
    cdn: &Arc<kuroshio_cdn::Cdn>,
    persister: &Arc<Mutex<crate::persist::Persister>>,
    sources: &[crate::app::SnapSource],
    target: usize,
    protect_ms: u64,
) -> anyhow::Result<kuroshio_cdn::cdn::ColdReport> {
    let (cdn, p, sources) = (cdn.clone(), persister.clone(), sources.to_vec());
    tokio::task::spawn_blocking(move || -> anyhow::Result<kuroshio_cdn::cdn::ColdReport> {
        // 先寫出：移出的只會是已經在磁碟上、之後沒變過的分片（登記與移出期間不會有新的登記）
        let _g = crate::app::STAGE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        crate::app::stage_sources_locked(&p, &sources);
        let mut pg = p.lock().unwrap();
        pg.flush_all(crate::persist::now_secs())?;
        Ok(cdn.evict_coldest(target, protect_ms, &|rel| !pg.is_pending(rel)))
    })
    .await?
}

/// 最近這麼久以內出現過的網域不移出（3.5.1 G1；剛查過、剛驗證完的很可能馬上又用到）
pub const CDN_PROTECT_MS: u64 = kuroshio_cdn::db::COLD_AGE_EDGES_MS[0];
/// 一次至少移出這麼多（估計），不然每次都要先寫 Flash、只換到一點點
pub const CDN_MIN_UNIT: u64 = 512 * 1024;
/// 讓出後多久才能再做一次（每次都會先把變動寫進 Flash，不能太頻繁）：吃緊時
pub const CDN_RESHED_SECS: u64 = 120;
/// 同上，離保留量遠時
pub const CDN_RESHED_FAR_SECS: u64 = 30;
/// 上一次讓出這麼多以上才算「還有東西可以讓」：等待下一次的期間後面的步驟（過濾清單）不做
pub const CDN_HOLD_MIN_BYTES: u64 = 64 * 1024;

/// 第 3 步：CDN 網域資料庫：先把變動寫進磁碟，再從最冷的開始把網域移出記憶體（磁碟保留，查到時讀回）。
/// 3.5.1 G1：以前固定移出「一小時沒出現」的、做過一次就要等恢復，大量冷門網域湧入時第一個小時沒有東西可以讓、
/// 之後湧進來的也沒辦法再讓，下一步就是停用過濾清單。現在依缺口動態決定移多少：沒有學習資料的先、同一組裡最久沒出現的先，
/// 夠了就停；可以一輪一輪做
pub struct CdnStep {
    pub cdn: Arc<kuroshio_cdn::Cdn>,
    pub persister: Arc<Mutex<crate::persist::Persister>>,
    pub sources: Vec<crate::app::SnapSource>,
    /// 系統保留量（算缺口用；沒有時一次移 [`CDN_MIN_UNIT`]）
    pub reserve: Option<Reserve>,
    /// 移出中的估計用量（bytes；讀回時扣掉）
    bytes: Mutex<u64>,
    /// 上一次讓出：（時間，讓出多少，多久後才能再做）
    last: Mutex<Option<(std::time::Instant, u64, u64)>>,
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
            reserve: None,
            bytes: Mutex::new(0),
            last: Mutex::new(None),
        }
    }

    /// 這一次要移出多少（估計 bytes）：`short` > 0（離保留量遠，[`Governor::tick`] 算的還缺多少）用它，
    /// 不然用「回到保留量 + 遲滯」還差多少；都 × 1.3（估計值偏差、配置器不一定全部還給系統），至少 [`CDN_MIN_UNIT`]
    fn target(&self, r: &Reading, short: u64) -> usize {
        let gap = if short > 0 {
            short
        } else {
            match (&self.reserve, r.avail) {
                (Some(res), Some(a)) => (res.bytes + res.margin()).saturating_sub(a),
                _ => 0,
            }
        };
        let t = (gap as u128 * 13 / 10).max(CDN_MIN_UNIT as u128);
        t.min(usize::MAX as u128) as usize
    }

    /// 還在「讓出後的等待」裡：回上一次讓出多少
    fn cooling(&self) -> Option<u64> {
        let l = *self.last.lock().unwrap();
        l.filter(|(t, _, wait)| t.elapsed().as_secs() < *wait).map(|(_, b, _)| b)
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
        self.cooling().is_none() && self.cdn.domains_in_ram() > 0
    }
    /// 接近保留量：新網域先不記（3.5.1 K4；已經記著的照常）
    fn set_growth(&self, allowed: bool) {
        self.cdn.set_admit_new(allowed);
    }
    fn holds_later(&self) -> bool {
        self.cooling().is_some_and(|b| b >= CDN_HOLD_MIN_BYTES)
    }
    fn is_shed(&self) -> bool {
        self.cdn.evicted_count() > 0
    }
    /// 一次讀回一片的估計（剩下的移出量 ÷ 有移出的分片數）
    fn restore_need(&self) -> u64 {
        let b = *self.bytes.lock().unwrap();
        b / self.cdn.evicted_shard_count().max(1) as u64
    }
    fn sizes(&self, out: &mut serde_json::Map<String, Value>) {
        out.insert("cdnInRam".into(), json!(self.cdn.domains_in_ram()));
        out.insert("cdnBytes".into(), json!(self.cdn.approx_ram_bytes()));
        out.insert("cdnOnDiskOnly".into(), json!(self.cdn.evicted_count()));
    }
    fn shed<'a>(&'a self, r: &'a Reading) -> BoxFut<'a, anyhow::Result<Outcome>> {
        self.shed_for(r, 0)
    }
    fn shed_for<'a>(&'a self, r: &'a Reading, short: u64) -> BoxFut<'a, anyhow::Result<Outcome>> {
        Box::pin(async move {
            let target = self.target(r, short);
            let res = evict_cdn(&self.cdn, &self.persister, &self.sources, target, CDN_PROTECT_MS).await;
            let freed = res.as_ref().map_or(0, |r| r.bytes as u64);
            let wait = if short > 0 { CDN_RESHED_FAR_SECS } else { CDN_RESHED_SECS };
            *self.last.lock().unwrap() = Some((std::time::Instant::now(), freed, wait));
            let r = res?;
            *self.bytes.lock().unwrap() += r.bytes as u64;
            Ok(cdn_evict_outcome(r.entries, r.bytes as u64))
        })
    }
    fn restore(&self) -> BoxFut<'_, anyhow::Result<Outcome>> {
        self.restore_for(u64::MAX)
    }
    /// 依可用空間一次讀回幾片（至少一片），剩下的下一輪再讀；只問過一次、沒有任何結果的不讀回（3.5.1 G1）
    fn restore_for(&self, room: u64) -> BoxFut<'_, anyhow::Result<Outcome>> {
        Box::pin(async move {
            let cdn = self.cdn.clone();
            let max = (room as u128 * 10 / 13).min(usize::MAX as u128) as usize;
            let r = tokio::task::spawn_blocking(move || cdn.restore_cold_upto(max)).await?;
            let left = self.cdn.evicted_count();
            {
                let mut b = self.bytes.lock().unwrap();
                *b = if left == 0 { 0 } else { b.saturating_sub(r.bytes as u64) };
            }
            let mut detail = format!("：讀回 {} 筆", r.entries);
            if r.forgotten > 0 {
                detail.push_str(&format!("，{} 筆只問過一次、沒有結果的不讀回", r.forgotten));
            }
            if left > 0 {
                detail.push_str(&format!("，還有 {left} 筆之後再讀回"));
            }
            Ok(Outcome {
                bytes: r.bytes as u64,
                detail,
            })
        })
    }
}

/// 系統真的不足：可用 < 保留量的一半（量不到可用記憶體時不做）
fn genuinely_short(r: &Reading, res: &Reserve) -> bool {
    r.avail.is_some_and(|a| a < res.bytes / 2)
}

/// 第 4 步：過濾清單（系統真的不足時）：停用優先順序最低的清單；保護清單不在這一步。
/// 離保留量遠時依「還缺多少 × 1.3」一次停用幾份、只重建一次（3.5.0 C3）；恢復時依可用空間一次恢復幾份、也只重建一次
pub struct FilterStep {
    pub filter: Arc<crate::filtering::FilterService>,
}

/// 一次停用的目標：還缺的 × 1.3（估計值偏差、讓出後配置器不一定全部還給系統）；0 = 一份
fn shed_target(short: u64) -> u64 {
    (short as u128 * 13 / 10).min(u64::MAX as u128) as u64
}

/// 停用 / 恢復的說明：「：2 份清單（A、B，共 300 條規則）」；一份時同以前「：A 清單（300 條規則）」
fn lists_detail(v: &[crate::filtering::Unloaded], with_rules: bool) -> String {
    let rules: u64 = v.iter().map(|u| u.rules).sum();
    match v {
        [u] if with_rules => format!("：{} 清單（{} 條規則）", u.name, u.rules),
        [u] => format!("：{} 清單", u.name),
        _ => {
            let line = v.iter().take(5).map(|u| u.name.as_str()).collect::<Vec<_>>().join("、");
            let more = if v.len() > 5 { "……" } else { "" };
            if with_rules {
                format!("：{} 份清單（{line}{more}，共 {rules} 條規則）", v.len())
            } else {
                format!("：{} 份清單（{line}{more}）", v.len())
            }
        }
    }
}

impl Step for FilterStep {
    fn key(&self) -> &'static str {
        "filter"
    }
    /// 記憶體又能長大：留在記憶體的清單內容存成本機副本（只在本機寫出）
    fn set_growth(&self, allowed: bool) {
        if allowed {
            self.filter.persist_held();
        }
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
        self.shed_for(r, 0)
    }
    fn shed_for<'a>(&'a self, r: &'a Reading, short: u64) -> BoxFut<'a, anyhow::Result<Outcome>> {
        Box::pin(async move {
            // 重建時新舊兩份同時存在：停用這幾份之後的新的一份放不進可用記憶體的一半就不做（不能為了省記憶體反而用光）
            let v = self.filter.unload_many(shed_target(short), r.avail.map(|av| av / 2)).await?;
            if v.is_empty() {
                anyhow::bail!("沒有可以停用的清單（其他都是保護清單）");
            }
            Ok(Outcome {
                bytes: v.iter().map(|u| u.bytes).sum(),
                detail: lists_detail(&v, true),
            })
        })
    }
    fn restore(&self) -> BoxFut<'_, anyhow::Result<Outcome>> {
        self.restore_for(0)
    }
    fn restore_for(&self, room: u64) -> BoxFut<'_, anyhow::Result<Outcome>> {
        Box::pin(async move {
            let v = self.filter.restore_many(room).await?;
            if v.is_empty() {
                return Ok(Outcome::default());
            }
            self.filter.persist_held();
            Ok(Outcome {
                bytes: v.iter().map(|u| u.bytes).sum(),
                detail: lists_detail(&v, false),
            })
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
                match evict_cdn(cdn, p, sources, usize::MAX, 0).await {
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
        // 還沒有任何清單（開機就記憶體不足、清單延後更新）時不暫停：省不到記憶體，卻會讓記憶體恢復後的
        // 第一次更新什麼都不做、等到記憶體控制恢復這一步才載入（3.4.2 Windows 複驗：恢復後 9 分鐘才有清單）
        !self.filter.all_suspended() && self.filter.list_rules() > 0
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

    /// 3.5.0 J3：同一段於事無補裡讀數掉回保留量以下好幾次，「缺口是其他程式造成」只寫一次；離開後再進入才重新寫
    #[test]
    fn futile_note_once_per_episode() {
        let mut n = FutileNote::default();
        let mut lines = 0;
        // W19：進入、讀數回升五次又掉回去（都沒有離開）
        for _ in 0..6 {
            n.observe(true);
            if n.take() {
                lines += 1;
            }
        }
        assert_eq!(lines, 1);
        // 離開、再進入：寫一次
        n.observe(false);
        n.observe(true);
        assert!(n.take());
        assert!(!n.take());
    }

    /// 3.5.0：讓出不到 1 KB 的步驟不寫 WARN
    #[test]
    fn tiny_shed_not_warned() {
        assert!(!worth_warning(0));
        assert!(!worth_warning(1023));
        assert!(worth_warning(1024));
    }

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
        // Windows 自動（3.5.0）：max(128 MB, 實體記憶體 5%)，不超過一半（以前 max(512 MB, min(10%, 4 GB))）
        let win = |gb: u64| derive_reserve(Some(gb * 1024 * MB), Platform::Windows, None, 0, 0);
        assert_eq!(win(4).bytes, 4096 * MB / 20, "4 GB：約 205 MB（以前 512 MB）");
        assert_eq!(win(8).bytes, 8192 * MB / 20, "8 GB：約 410 MB（以前 819 MB）");
        assert_eq!(win(16).bytes, 16384 * MB / 20, "16 GB：約 819 MB（以前 1.6 GB）");
        assert_eq!(win(32).bytes, 32768 * MB / 20, "32 GB：約 1.6 GB（以前 3.2 GB）");
        assert_eq!(win(64).bytes, 65536 * MB / 20, "64 GB：約 3.2 GB（以前 4 GB）");
        assert!(win(64).auto && win(64).how.contains("5%"), "{}", win(64).how);
        assert_eq!(win(1).bytes, WINDOWS_RESERVE_FLOOR, "很小的 VM：下限 128 MB（5% 只有 51 MB）");
        assert_eq!(win(2).bytes, WINDOWS_RESERVE_FLOOR, "2 GB：5% 是 102 MB，下限 128 MB");
        assert_eq!(
            derive_reserve(Some(200 * MB), Platform::Windows, None, 0, 0).bytes,
            100 * MB,
            "下限也不超過實體記憶體一半"
        );
        assert_eq!(derive_reserve(None, Platform::Windows, None, 0, 0).bytes, WINDOWS_RESERVE_FLOOR);
        // 使用者設定照舊優先
        assert_eq!(derive_reserve(Some(65536 * MB), Platform::Windows, None, 1024, 0).bytes, 1024 * MB);
        assert_eq!(
            derive_reserve(Some(65536 * MB), Platform::Windows, None, 0, 10).bytes,
            65536 * MB / 100 * 10
        );
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

    /// 可用 a MB、自己用 own MB（實體 1000 MB）
    fn rdo(avail_mb: u64, own_mb: Option<u64>) -> Reading {
        Reading {
            rss: own_mb.map(|o| o * MB),
            ..rd(avail_mb)
        }
    }

    /// 3.5.0 退讓於事無補：用量 × 2 < 缺口才成立；讀不到自己的用量時不成立
    #[test]
    fn futile_enter_and_hold_thresholds() {
        let res = res100();
        // 缺口 70 MB：自己 20 MB（× 2 = 40 < 70）→ 成立；自己 40 MB（80 ≥ 70）→ 不成立
        assert!(futile_enter(&rdo(30, Some(20)), &res));
        assert!(!futile_enter(&rdo(30, Some(40)), &res));
        assert!(!futile_enter(&rdo(30, None), &res), "讀不到自己的用量：照舊");
        assert!(!futile_enter(&rdo(30, Some(0)), &res), "用量 0 當作讀不到");
        assert!(
            !futile_enter(
                &Reading {
                    avail: None,
                    ..rdo(30, Some(1))
                },
                &res
            ),
            "讀不到可用記憶體"
        );
        assert!(!futile_enter(&rdo(150, Some(1)), &res), "沒有缺口");
        // 維持：用量 × 2 < 缺口 × 1.2。缺口 70 × 1.2 = 84：自己 41 MB（82）還維持，42 MB（84）就離開
        assert!(futile_hold(&rdo(30, Some(41)), &res));
        assert!(!futile_hold(&rdo(30, Some(42)), &res));
        assert!(!futile_hold(&rdo(30, None), &res));
        // 壓力訊號：於事無補時「不足」降成「偏低」，其他不變
        assert_eq!(signal_pressure(Pressure::Critical, true), Pressure::Low);
        assert_eq!(signal_pressure(Pressure::Critical, false), Pressure::Critical);
        assert_eq!(signal_pressure(Pressure::Low, true), Pressure::Low);
        assert_eq!(signal_pressure(Pressure::Normal, true), Pressure::Normal);
    }

    /// Windows 實測的情境：64 GB、別的程式吃掉幾十 GB
    #[test]
    fn futile_on_big_windows_machine() {
        let res = derive_reserve(Some(65536 * MB), Platform::Windows, None, 0, 0);
        let r = |avail_mb: u64| Reading {
            rss: Some(180 * MB),
            total: Some(65536 * MB),
            avail: Some(avail_mb * MB),
            psi: None,
        };
        // 可用 3,896 MB：新的保留量（約 3.2 GB）以上，連吃緊都不是
        assert_eq!(classify(&r(3896), &res), State::Comfortable);
        // 可用 1,500 MB（以前的公式下是「不足」）：缺口約 1.7 GB，黑潮 180 MB → 於事無補
        assert_eq!(classify(&r(1500), &res), State::Critical);
        assert!(futile_enter(&r(1500), &res));
        assert!(futile_message(true, &r(1500), &res).contains("黑潮全部讓出也只有 180 MB"));
        // 缺口小（可用 3,000 MB，缺約 277 MB）：讓得出來，照舊
        assert!(!futile_enter(&r(3000), &res));
    }

    /// 遲滯：離開要「用量 × 2 ≥ 缺口 × 1.2」（包括回到寬裕）連續 60 秒；讀不到用量時立刻離開
    #[test]
    fn futile_gate_hysteresis() {
        let res = res100();
        let mut g = FutileGate::default();
        let d = FUTILE_EXIT_SECS;
        assert!(!g.step(&rdo(30, Some(40)), &res, d, 0), "缺口 70、自己 40：不成立");
        assert!(g.step(&rdo(30, Some(20)), &res, d, 2), "缺口 70、自己 20：進入");
        assert!(g.on);
        // 自己 38 MB（76 < 84）：還在遲滯範圍裡，維持
        assert!(!g.step(&rdo(30, Some(38)), &res, d, 4));
        assert!(g.on);
        // 自己 45 MB（90 ≥ 84）：離開的條件成立，但要連續 60 秒；中間掉回去一次重新計時
        assert!(!g.step(&rdo(30, Some(45)), &res, d, 10));
        assert!(!g.step(&rdo(30, Some(45)), &res, d, 40));
        assert!(!g.step(&rdo(30, Some(20)), &res, d, 42));
        assert!(!g.step(&rdo(30, Some(45)), &res, d, 44));
        assert!(!g.step(&rdo(30, Some(45)), &res, d, 103));
        assert!(g.step(&rdo(30, Some(45)), &res, d, 104), "連續 60 秒才離開");
        assert!(!g.on);
        // 每幾秒來回的讀數不會每幾秒切換：進入後只有連續 60 秒都讓得出來才離開
        let mut g = FutileGate::default();
        let mut changes = 0;
        for t in 0..300u64 {
            let own = if t % 2 == 0 { 20 } else { 45 };
            if g.step(&rdo(30, Some(own)), &res, d, t * 3) {
                changes += 1;
            }
        }
        assert_eq!(changes, 1, "只進入一次");
        // 回到寬裕（可用 ≥ 保留量 + 遲滯）：3.5.0 F1 起也要連續 60 秒才離開（以前立刻離開，5 分鐘進出 4 次）
        assert!(
            !g.step(&rdo(30, Some(20)), &res, d, 1998),
            "上面最後一次是讓得出來的讀數：先回到維持"
        );
        assert!(!g.step(&rdo(160, Some(20)), &res, d, 2000));
        assert!(!g.step(&rdo(160, Some(20)), &res, d, 2000 + d - 1));
        assert!(g.on);
        assert!(g.step(&rdo(160, Some(20)), &res, d, 2000 + d), "回到寬裕連續 60 秒才離開");
        assert!(!g.on);
        // 讀不到自己的用量：規則不成立，立刻離開（照舊讓出）
        assert!(g.step(&rdo(30, Some(20)), &res, d, 3000));
        assert!(g.step(&rdo(30, None), &res, d, 3002));
        assert!(!g.on);
        assert!(!g.step(&rdo(30, None), &res, d, 3004), "讀不到就一直照舊");
    }

    /// 小機器的行為不變：路由器的自動保留量只有 16～26 MB，缺口最多就是保留量；黑潮自己 20 MB 以上時
    /// 用量 × 2 一定 ≥ 缺口，可用從 0 到保留量都不成立
    #[test]
    fn futile_never_on_small_routers() {
        let cases = [
            ("128 MB 路由器", derive_reserve(Some(128 * MB), Platform::Linux, Some(1024), 0, 0)),
            ("512 MB（D3）", derive_reserve(Some(512 * MB), Platform::Linux, Some(2048), 0, 0)),
            (
                "512 MB、min_free 16 MB",
                derive_reserve(Some(512 * MB), Platform::Linux, Some(16384), 0, 0),
            ),
        ];
        assert_eq!(cases[0].1.bytes, 16 * MB);
        assert_eq!(cases[1].1.bytes, 512 * MB / 20);
        assert_eq!(cases[2].1.bytes, 48 * MB);
        for (name, res) in &cases {
            // 黑潮的用量：保留量的一半以上就永遠不成立（缺口 ≤ 保留量）
            let own = (res.bytes / 2).max(20 * MB);
            let mut g = FutileGate::default();
            for avail in (0..=res.bytes).step_by(256 * 1024) {
                let r = Reading {
                    rss: Some(own),
                    total: Some(512 * MB),
                    avail: Some(avail),
                    psi: None,
                };
                assert!(!futile_enter(&r, res), "{name}：可用 {} KB", avail / 1024);
                assert!(!g.step(&r, res, FUTILE_EXIT_SECS, avail));
                assert_eq!(
                    signal_pressure(pressure_of(&r, res), g.on),
                    pressure_of(&r, res),
                    "{name}：壓力訊號不變"
                );
            }
        }
    }

    #[test]
    fn poll_interval_follows_distance_and_psi() {
        let res = res100();
        assert_eq!(poll_interval(&rd(50), &res), 2, "低於保留量");
        assert_eq!(poll_interval(&rd(150), &res), 3, "保留量兩倍以內");
        assert_eq!(poll_interval(&rd(199), &res), 3);
        assert_eq!(poll_interval(&rd(150), &res), 3, "保留量兩倍以內");
        assert_eq!(poll_interval(&rd(160), &res), 3, "沒有 PSI、比保留量多不到 64 MB");
        assert_eq!(poll_interval(&rd(500), &res), 10, "沒有 PSI：離得遠也 10 秒量一次");
        let calm = Reading {
            psi: Some(Psi::default()),
            ..rd(500)
        };
        assert_eq!(poll_interval(&calm, &res), 30, "有 PSI 而且平靜：離得遠時 30 秒");
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
        /// 每次釋出時 `tick` 傳下來的「還缺多少」、每次恢復時的可用空間（3.5.0 C3）
        shorts: Arc<Mutex<Vec<u64>>>,
        rooms: Arc<Mutex<Vec<u64>>>,
        /// 讓出後在等下一次（[`Step::holds_later`]；3.5.1 G1）
        hold: Arc<AtomicBool>,
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
                shorts: Default::default(),
                rooms: Default::default(),
                hold: Arc::new(AtomicBool::new(false)),
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
        fn holds_later(&self) -> bool {
            self.hold.load(Ordering::Relaxed)
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
        fn shed_for<'a>(&'a self, r: &'a Reading, short: u64) -> BoxFut<'a, anyhow::Result<Outcome>> {
            self.shorts.lock().unwrap().push(short);
            self.shed(r)
        }
        fn restore_for(&self, room: u64) -> BoxFut<'_, anyhow::Result<Outcome>> {
            self.rooms.lock().unwrap().push(room);
            self.restore()
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

    #[tokio::test]
    async fn filter_waits_while_cdn_still_has_cold_data() {
        // 3.5.1 G1：CDN 冷資料讓出後在等下一次（還有東西可以讓）時，系統再不足也不跳去停用過濾清單
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut steps = ladder(&log, 2 * MB);
        let cdn = Fake::new("cdn", State::Tight, 1, 5 * MB, &log);
        cdn.hold.store(true, Ordering::Relaxed);
        let hold = cdn.hold.clone();
        steps[2] = cdn;
        let g = Governor::new(res100(), steps, 0);
        let mut now = 1000;
        for _ in 0..80 {
            g.tick(rd(30), now).await;
            now += 5;
        }
        assert_eq!(g.state(), State::Critical);
        assert_eq!(
            *log.lock().unwrap(),
            ["shed:diagnostics", "shed:cache", "shed:cdn"],
            "過濾清單等 CDN"
        );
        // CDN 沒東西可以讓了：才輪到過濾清單
        hold.store(false, Ordering::Relaxed);
        for _ in 0..4 {
            g.tick(rd(30), now).await;
            now += 5;
        }
        assert!(log.lock().unwrap().iter().any(|x| x == "shed:filter"), "{:?}", log.lock().unwrap());
    }

    #[tokio::test]
    async fn critical_only_steps_restore_when_their_trigger_is_gone() {
        // 3.5.1 N1：洪水過後可用記憶體回不到保留量以上（musl 不還記憶體），狀態一直是不足。
        // 停用過濾清單只在「真的不足」（可用 < 保留量一半）時做：那個條件不成立、空間夠，就先恢復，不必等寬裕
        let log = Arc::new(Mutex::new(Vec::new()));
        let g = Governor::new(res100(), ladder(&log, 2 * MB), 0);
        let mut now = 1000;
        for _ in 0..40 {
            g.tick(rd(30), now).await;
            now += 5;
        }
        assert!(log.lock().unwrap().iter().any(|x| x == "shed:filter"), "{:?}", log.lock().unwrap());
        log.lock().unwrap().clear();
        // 可用 70 MB：保留量 100 MB 以下（狀態不會回到寬裕），但已經不是「真的不足」
        for _ in 0..100 {
            g.tick(rd(70), now).await;
            now += 5;
        }
        assert_ne!(g.state(), State::Comfortable);
        let l = log.lock().unwrap().clone();
        assert!(l.iter().any(|x| x == "restore:filter"), "{l:?}");
        assert!(
            !l.iter().any(|x| x == "restore:cdn" || x == "restore:cache"),
            "吃緊就會做的步驟照舊等寬裕：{l:?}"
        );
        assert!(!l.iter().any(|x| x.starts_with("shed:")), "恢復之後不再讓出：{l:?}");
    }

    #[test]
    fn restart_only_when_stuck_mine_quiet_and_enabled() {
        // 3.5.1 N1：原地重新啟動的條件：不寬裕 10 分鐘以上、10 分鐘內沒讓出 256 KB 以上、沒有能做的步驟、
        // RSS ≥ 實體記憶體 30%、最近 15 分鐘平均每秒不到 10 筆、有開
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut steps = ladder(&log, 2 * MB);
        steps.truncate(3); // 只有吃緊的步驟，而且都讓過了（units = 1）
        for s in &steps {
            futures_lite_block(s.shed(&rd(30))).unwrap();
        }
        let g = Governor::new(res100(), steps, 0);
        let q = Arc::new(AtomicU32::new(100));
        let q2 = q.clone();
        g.set_load_probe(move || q2.load(Ordering::Relaxed) as u64);
        let r = |rss_mb: u64| Reading {
            rss: Some(rss_mb * MB),
            total: Some(1000 * MB),
            avail: Some(80 * MB),
            psi: None,
        };
        let stuck = |g: &Governor, since: u64, useful: u64| {
            let mut i = g.inner.lock().unwrap();
            i.pressed_since = Some(since);
            i.last_useful_shed = useful;
        };
        let due = |g: &Governor, rss: u64, now: u64| {
            let i = g.inner.lock().unwrap();
            g.restart_due(&i, State::Tight, &r(rss), now, 2_000_000_000)
        };
        stuck(&g, 1000, 1000);
        assert!(!due(&g, 400, 2000), "沒開");
        g.restart.store(true, Ordering::Relaxed);
        assert!(due(&g, 400, 2000), "都成立");
        assert!(!due(&g, 400, 1500), "不寬裕還不到 10 分鐘");
        stuck(&g, 1000, 1700);
        assert!(!due(&g, 400, 2000), "10 分鐘內還讓得出東西");
        stuck(&g, 1000, 1000);
        assert!(!due(&g, 200, 2000), "RSS 不到 30%：不是自己回不來");
        q.store(10 * 15 * 60, Ordering::Relaxed);
        assert!(!due(&g, 400, 2000), "不是離峰");
        q.store(100, Ordering::Relaxed);
        g.inner.lock().unwrap().futile.on = true;
        assert!(!due(&g, 400, 2000), "於事無補（別的程式造成的）");
        g.inner.lock().unwrap().futile.on = false;
        let i = g.inner.lock().unwrap();
        assert!(!g.restart_due(&i, State::Comfortable, &r(400), 2000, 2_000_000_000), "寬裕");
    }

    fn futures_lite_block<T>(f: BoxFut<'_, T>) -> T {
        tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(f)
    }

    #[test]
    fn repeated_sheds_keep_few_records() {
        // 3.5.1 G1：CDN 一輪一輪讓出時紀錄不會一直長：同一步最多 4 筆，最舊的合在一起，總量不變
        let mut v = Vec::new();
        let rec = |key, bytes, at| ShedRec {
            key,
            label: "x",
            detail: String::new(),
            bytes,
            avail_before: Some(at),
            avail_delta: None,
            at,
        };
        push_shed(&mut v, rec("cache", 7, 0));
        for k in 1..=10u64 {
            push_shed(&mut v, rec("cdn", 100, k));
        }
        assert_eq!(v.iter().filter(|x| x.key == "cdn").count(), SHED_RECS_PER_STEP);
        assert_eq!(v.iter().filter(|x| x.key == "cdn").map(|x| x.bytes).sum::<u64>(), 1000);
        assert_eq!(v[0].key, "cache");
        assert_eq!(v[1].at, 1, "合併的那筆記最早的時間");
        assert_eq!(v.last().unwrap().at, 10);
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
    async fn trim_sheds_tight_steps_now_and_holds_restore() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let g = Governor::new(res100(), ladder(&log, 2 * MB), 0);
        g.set_reader(|| rd(600));
        let mut now = 1000;
        // 寬裕時也照做：只做「吃緊」層級的（過濾清單、最低限度不碰）
        let v = g.trim(120, now).await;
        assert_eq!(*log.lock().unwrap(), ["shed:diagnostics", "shed:cache", "shed:cdn"]);
        assert_eq!(v["freedBytes"], 3000);
        assert_eq!(v["holdSec"], 120);
        assert_eq!(g.status_json()["growth"], false, "暫停期間不長大");
        log.lock().unwrap().clear();
        // 暫停期間：寬裕也不恢復、不長大
        while now < 1000 + 115 {
            g.tick(rd(600), now).await;
            now += 5;
        }
        assert!(log.lock().unwrap().is_empty(), "{:?}", log.lock().unwrap());
        assert!(g.status_json()["waiting"].as_str().unwrap().contains("不恢復"));
        // 時間到了：照一般規則依相反順序恢復
        for _ in 0..200 {
            g.tick(rd(600), now).await;
            now += 5;
        }
        assert_eq!(*log.lock().unwrap(), ["restore:cdn", "restore:cache", "restore:diagnostics"]);
        assert_eq!(g.status_json()["growth"], true);
        // 上限 3600 秒
        assert_eq!(g.trim(99_999, now).await["holdSec"], TRIM_HOLD_MAX);
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
        assert!(
            ["normal", "low", "critical"].contains(&st["pressure"].as_str().unwrap()),
            "當下的量測另外列（3.4.3）"
        );
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

    /// 3.5.0 C3：離保留量遠時，每一步拿到「還缺多少」＝缺口 − 這一輪前面步驟已經釋出的；不遠時是 0（一個單位）；
    /// 恢復時拿到可用空間（可用 − 保留量 − 遲滯）
    #[tokio::test]
    async fn tick_passes_shortfall_and_room_to_steps() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mk = |key, min, bytes| {
            Box::new(Fake {
                bytes,
                ..*Fake::new(key, min, 1, 0, &log)
            })
        };
        let (a, b, f) = (
            mk("cache", State::Tight, 10 * MB),
            mk("cdn", State::Tight, 5 * MB),
            mk("filter", State::Critical, MB),
        );
        let (sa, sb, sf, rf) = (a.shorts.clone(), b.shorts.clone(), f.shorts.clone(), f.rooms.clone());
        let g = Governor::new(res100(), vec![a, b, f], 0);
        // 可用 30 MB：缺 70 MB。快取拿到 70、CDN 拿到 60、清單拿到 55
        g.tick(rd(30), 1000).await.unwrap();
        assert_eq!(*sa.lock().unwrap(), [70 * MB]);
        assert_eq!(*sb.lock().unwrap(), [60 * MB]);
        assert_eq!(*sf.lock().unwrap(), [55 * MB]);
        // 恢復：寬裕而且停留夠久；空間 = 可用 − 保留 − 遲滯
        let mut now = 1000;
        while rf.lock().unwrap().is_empty() && now < 3000 {
            now += 5;
            g.tick(rd(400), now).await;
        }
        assert_eq!(*rf.lock().unwrap(), [250 * MB]);
        // 不遠（稍微低於保留量）：一次一個單位
        let log2 = Arc::new(Mutex::new(Vec::new()));
        let c = Fake::new("cache", State::Tight, 1, 0, &log2);
        let sc = c.shorts.clone();
        let g = Governor::new(res100(), vec![c], 0);
        g.tick(rd(90), 1000).await.unwrap();
        assert_eq!(*sc.lock().unwrap(), [0]);
    }

    #[test]
    fn shed_target_is_shortfall_times_1_3() {
        assert_eq!(shed_target(0), 0, "一份");
        assert_eq!(shed_target(10 * MB), 13 * MB);
        assert_eq!(shed_target(u64::MAX), u64::MAX, "不溢位");
    }

    /// 3.5.0 C9：模擬只會讓可用記憶體變小，不會比真實寬裕
    #[test]
    fn simulate_only_lowers_reading() {
        let s = Some(Simulation {
            avail_mb: 20,
            until: u64::MAX,
        });
        assert_eq!(apply_simulation(rd(600), s).avail, Some(20 * MB));
        assert_eq!(apply_simulation(rd(10), s).avail, Some(10 * MB), "真實的比較少：照真實的");
        assert_eq!(apply_simulation(Reading::default(), s).avail, Some(20 * MB), "量不到：用模擬值");
        assert_eq!(apply_simulation(rd(600), None), rd(600), "沒開：不動");
        let r = apply_simulation(rd(600), s);
        assert_eq!((r.total, r.rss, r.psi), (rd(600).total, rd(600).rss, None), "其他欄位不動");
    }

    /// 3.5.0：模擬只讓讀數變小。Windows（保留量是實體記憶體 5%）模擬 20 MB 時缺口遠大於黑潮自己的用量，
    /// 是「於事無補」（W5 驗證這一條）；D3（保留約 25.6 MB）模擬 20 MB、4 MB 都不是，照舊走停用清單的路徑（D11）
    #[test]
    fn simulation_on_windows_is_futile_but_not_on_d3() {
        let sim = Some(Simulation {
            avail_mb: 20,
            until: u64::MAX,
        });
        let win = derive_reserve(Some(16384 * MB), Platform::Windows, None, 0, 0);
        let real = Reading {
            rss: Some(150 * MB),
            total: Some(16384 * MB),
            avail: Some(8000 * MB),
            psi: None,
        };
        let r = apply_simulation(real, sim);
        assert!(futile_enter(&r, &win), "Windows 16 GB：缺口約 800 MB、黑潮 150 MB");
        assert_eq!(signal_pressure(pressure_of(&r, &win), true), Pressure::Low);
        let d3 = derive_reserve(Some(512 * MB), Platform::Linux, Some(2048), 0, 0);
        for mb in [20, 10, 4] {
            let r = apply_simulation(
                Reading {
                    rss: Some(20 * MB),
                    total: Some(512 * MB),
                    avail: Some(300 * MB),
                    psi: None,
                },
                Some(Simulation {
                    avail_mb: mb,
                    until: u64::MAX,
                }),
            );
            assert!(!futile_enter(&r, &d3), "D3 模擬 {mb} MB");
        }
    }

    #[test]
    fn simulate_capped_at_30_minutes() {
        let sim = SimState::new();
        let now = 2_000_000_000;
        assert_eq!(sim.start(20, 999, now).until, now + 30 * 60);
        assert_eq!(sim.start(20, 0, now).until, now + 60, "最短 1 分鐘");
        assert_eq!(sim.start(u64::MAX, 5, now).avail_mb, 1 << 20, "防呆上限");
        assert!(sim.get(now + 5 * 60 - 1).is_some());
        assert!(sim.get(now + 5 * 60).is_none(), "到期");
        assert!(sim.stop());
        assert!(!sim.stop());
    }

    /// 到期自動恢復（注入時鐘）：模擬期間記憶體控制照「不足」讓出；到期後讀回真實值，照常放鬆、恢復。
    /// 提醒每分鐘一行，到期那一輪記一行「結束」
    #[tokio::test]
    async fn simulate_expires_and_restores() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let g = Governor::new(res100(), ladder(&log, 2 * MB), 0);
        let sim = Arc::new(SimState::new());
        // 注入的時鐘：t0 起算的秒數（32 位元平台沒有 AtomicU64）
        let t0: u64 = 2_000_000_000;
        let clock = Arc::new(AtomicU32::new(0));
        let (s2, c2) = (sim.clone(), clock.clone());
        // 真實的可用記憶體一直是 600 MB（寬裕）
        g.set_reader(move || apply_simulation(rd(600), s2.get(t0 + c2.load(Ordering::Relaxed) as u64)));
        sim.start(20, 5, t0);
        let mut notices = Vec::new();
        let mut now = t0;
        while now < t0 + 40 * 60 {
            clock.store((now - t0) as u32, Ordering::Relaxed);
            if let Some(m) = sim.notice(now) {
                notices.push((now - t0, m));
            }
            let r = g.read();
            g.tick(r, now).await;
            now += 5;
        }
        let l = log.lock().unwrap().clone();
        assert!(
            l.contains(&"shed:filter".to_string()) && l.contains(&"shed:floor".to_string()),
            "模擬期間照「不足」讓出：{l:?}"
        );
        assert!(
            l.contains(&"restore:floor".to_string()) && l.contains(&"restore:diagnostics".to_string()),
            "到期後自己恢復：{l:?}"
        );
        assert_eq!(g.state(), State::Comfortable);
        // 提醒：0、60、120、180、240 秒各一行，300 秒到期記「結束」，之後不再記
        let at: Vec<u64> = notices.iter().map(|n| n.0).collect();
        assert_eq!(at, [0, 60, 120, 180, 240, 300], "{notices:?}");
        assert!(notices[0].1.contains("20 MB") && notices[0].1.contains("還有 5 分鐘"));
        assert!(notices[5].1.contains("結束"));
        assert!(sim.get(now).is_none());
        // 狀態頁的欄位
        assert_eq!(simulation_json(None, now), Value::Null);
        let j = simulation_json(
            Some(Simulation {
                avail_mb: 20,
                until: now + 90,
            }),
            now,
        );
        assert_eq!((j["availMB"].clone(), j["remainingSec"].clone()), (json!(20), json!(90)));
    }

    /// 3.5.0 於事無補：不讓出任何東西（不縮快取、不移出 CDN、不縮診斷、不停用清單、不到只轉送）、停止長大、
    /// 壓力訊號是「偏低」（不拒絕新的加密連線），快照寫入器照樣判成「不足」立刻寫出
    #[tokio::test]
    async fn futile_sheds_nothing_but_stops_growth_and_still_flushes() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut steps = ladder(&log, 2 * MB);
        steps.push(Fake::new("protected", State::Critical, 1, 0, &log));
        let grow = {
            let f = Fake::new("cache2", State::Tight, 1, 0, &log);
            let g = f.grow.clone();
            steps.push(f);
            g
        };
        let g = Governor::new(res100(), steps, 0);
        g.tick(rdo(600, Some(20)), 100).await;
        // 可用 30 MB、缺口 70 MB，黑潮自己 20 MB：於事無補
        let r = rdo(30, Some(20));
        let mut now = 1000;
        for _ in 0..20 {
            assert!(g.observe_futile(&r, now));
            assert!(g.tick(r, now).await.is_none(), "什麼都不讓");
            now += 2;
        }
        assert!(log.lock().unwrap().is_empty(), "{:?}", log.lock().unwrap());
        assert_eq!(*grow.lock().unwrap(), [false], "停止長大");
        let st = g.status_json();
        assert_eq!(st["state"], "critical", "狀態照實顯示");
        assert_eq!(st["futile"], true);
        assert_eq!(st["deficitBytes"], 70 * MB);
        assert_eq!(st["ownBytes"], 20 * MB);
        assert_eq!(st["growth"], false);
        assert!(st["waiting"].as_str().unwrap().contains("於事無補"), "{}", st["waiting"]);
        let ev = st["events"].as_array().unwrap();
        assert_eq!(
            ev.iter().filter(|e| e["msg"].as_str().unwrap().contains("其他程式造成")).count(),
            1,
            "進入時記一次，不是每次量測都記：{ev:?}"
        );
        // 給其他模組的訊號：偏低（加密連線不拒絕、清單更新不延後到不足解除）
        assert_eq!(pressure_of(&r, &g.reserve), Pressure::Critical);
        assert_eq!(signal_pressure(pressure_of(&r, &g.reserve), g.is_futile()), Pressure::Low);
        // 快照：寫入器依自己的量測判斷（不看這個訊號），照樣是「不足」、下一輪就寫
        let mem = crate::persist::Mem {
            total_mb: Some(1000),
            avail_mb: Some(30),
            reserve_mb: 100,
        };
        assert_eq!(mem.pressure(), Pressure::Critical);
        assert_eq!(
            crate::persist::effective_interval(&crate::persist::Policy::new(sysinfo::StorageClass::Flash, 0, 256), mem),
            0
        );
        // 缺口變小到讓得出來（黑潮 45 MB：90 ≥ 70 × 1.2）連續 60 秒：離開，照一般的方式讓出
        let r2 = rdo(30, Some(45));
        let end = now + FUTILE_EXIT_SECS + 4;
        while now < end {
            g.observe_futile(&r2, now);
            g.tick(r2, now).await;
            now += 2;
        }
        assert!(!g.is_futile());
        let l = log.lock().unwrap().clone();
        assert!(l.contains(&"shed:filter".to_string()), "{l:?}");
        assert_eq!(g.status_json()["futile"], false);
    }

    /// 之前已經讓出（不是於事無補時）的東西：進入於事無補後不恢復也不再讓；照舊等寬裕才恢復
    #[tokio::test]
    async fn futile_keeps_earlier_sheds_until_comfortable() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let g = Governor::new(res100(), ladder(&log, 2 * MB), 0);
        let mut now = 1000;
        // 黑潮 40 MB、缺口 70 MB（80 ≥ 70）：讓得出來，整個階梯做完
        let r = rdo(30, Some(40));
        assert!(!g.observe_futile(&r, now));
        g.tick(r, now).await;
        assert_eq!(log.lock().unwrap().len(), 6);
        log.lock().unwrap().clear();
        // 別的程式又吃掉更多（可用 5 MB、缺口 95 MB，黑潮讓完剩 30 MB）：於事無補，不恢復也不再讓
        let r = rdo(5, Some(30));
        for _ in 0..200 {
            now += 2;
            assert!(g.observe_futile(&r, now));
            g.tick(r, now).await;
        }
        assert!(log.lock().unwrap().is_empty(), "{:?}", log.lock().unwrap());
        assert_eq!(g.status_json()["floor"], true, "已經只轉送的維持");
        // 回到寬裕：連續 60 秒後離開於事無補（3.5.0 F1；以前立刻離開），照一般規則依相反順序恢復
        let back = now;
        for _ in 0..(FUTILE_EXIT_SECS / 5) {
            now += 5;
            assert!(g.observe_futile(&rdo(600, Some(30)), now), "回到寬裕還不到 60 秒：維持");
            assert!(g.tick(rdo(600, Some(30)), now).await.is_none(), "於事無補期間不讓也不恢復");
        }
        assert!(now - back <= FUTILE_EXIT_SECS);
        for _ in 0..400 {
            now += 5;
            g.observe_futile(&rdo(600, Some(30)), now);
            g.tick(rdo(600, Some(30)), now).await;
        }
        assert!(!g.is_futile());
        let l = log.lock().unwrap().clone();
        assert_eq!(l.first().map(String::as_str), Some("restore:floor"), "{l:?}");
        assert!(l.contains(&"restore:diagnostics".to_string()), "{l:?}");
    }

    /// 3.5.0 F1（Windows 實測 H1，收 Windows 本地 AI 的 patch）：於事無補中，別的程式一下子放掉記憶體
    /// （可用從 30 MB 跳到 600 MB）。於事無補要連續 60 秒才離開；離開之後狀態還在等穩定（`dwell`），
    /// 這段時間讀數沒有缺口，不應該照狀態去讓出（以前會在可用 10 GB 的時候移出 CDN 冷資料）
    #[tokio::test]
    async fn no_shed_after_futile_exit_when_reading_is_back_above_reserve() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let g = Governor::new(res100(), ladder(&log, 2 * MB), 0);
        g.tick(rdo(600, Some(20)), 100).await;
        let mut now = 1000;
        // 可用 30 MB、缺口 70 MB，黑潮 20 MB：於事無補，什麼都不讓
        let low = rdo(30, Some(20));
        for _ in 0..5 {
            assert!(g.observe_futile(&low, now));
            assert!(g.tick(low, now).await.is_none());
            now += 2;
        }
        assert_eq!(g.state(), State::Critical);
        // 別的程式放掉記憶體：回到寬裕的讀數（≥ 保留量 + 遲滯）。於事無補 60 秒後才離開；狀態還在等穩定
        let high = rdo(600, Some(20));
        for _ in 0..40 {
            g.observe_futile(&high, now);
            assert!(g.tick(high, now).await.is_none(), "沒有缺口：不讓出");
            now += 2;
        }
        assert!(!g.is_futile());
        assert!(g.state() > State::Comfortable, "狀態照舊要穩定一段時間才降");
        assert!(log.lock().unwrap().is_empty(), "{:?}", log.lock().unwrap());
        assert!(g.status_json()["waiting"].as_str().unwrap().contains("回到保留量以上"));
        // 讀數再掉回保留量以下（而且讓得出來）：照一般規則讓出
        let r = rdo(90, Some(40));
        g.observe_futile(&r, now);
        assert!(g.tick(r, now).await.is_some());
    }

    /// 3.5.0 F1：W5 情境 3 的時間序列（19:41:06 進、:26 出、:36 進、19:43:21 出、:24 進、:32 出、:42 進）。
    /// 回到寬裕也要連續 60 秒才離開：整段只進入一次、不離開，期間什麼都不讓；之後真的寬裕 60 秒才離開一次
    #[tokio::test]
    async fn futile_exit_needs_60s_even_when_comfortable() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let g = Governor::new(res100(), ladder(&log, 2 * MB), 0);
        g.tick(rdo(600, Some(20)), 100).await;
        let t0 = 1000u64;
        // 相對 19:41:06 的秒數：寬裕的區間（其他時間是缺口很大、黑潮讓了也沒用）
        let high_spans = [(20u64, 30u64), (135, 138), (146, 156)];
        let mut flips = Vec::new();
        let mut was = false;
        for t in (0..=300u64).step_by(2) {
            let high = high_spans.iter().any(|&(a, b)| t >= a && t < b);
            let r = if high { rdo(600, Some(20)) } else { rdo(30, Some(20)) };
            let on = g.observe_futile(&r, t0 + t);
            if on != was {
                flips.push((t, on));
                was = on;
            }
            assert!(g.tick(r, t0 + t).await.is_none(), "t = {t}：什麼都不讓");
        }
        assert_eq!(flips, vec![(0, true)], "只進入一次、沒有來回");
        assert!(log.lock().unwrap().is_empty(), "{:?}", log.lock().unwrap());
        // 真的寬裕連續 60 秒：離開一次
        let mut t = 302;
        while t <= 302 + FUTILE_EXIT_SECS {
            let on = g.observe_futile(&rdo(600, Some(20)), t0 + t);
            if on != was {
                flips.push((t, on));
                was = on;
            }
            t += 2;
        }
        assert_eq!(flips, vec![(0, true), (302 + FUTILE_EXIT_SECS, false)]);
        let ev = g.status_json()["events"].as_array().unwrap().clone();
        assert_eq!(
            ev.iter().filter(|e| e["msg"].as_str().unwrap().contains("讓得出來的範圍")).count(),
            1,
            "離開的日誌只有一行：{ev:?}"
        );
    }

    /// 3.5.0 F6／H8：沒有冷資料可以移出是「做了 0」，不是錯誤：不寫 WARN（`worth_warning` 不成立，走 DEBUG）、
    /// 不記「沒有做」，但這一步照樣等久一點（60 秒）再試，不會每一輪都做
    #[tokio::test]
    async fn evict_with_nothing_cold_is_debug_not_warn() {
        let o = cdn_evict_outcome(0, 0);
        assert_eq!(o.bytes, 0);
        assert!(!worth_warning(o.bytes), "0 KB：DEBUG");
        assert!(o.detail.contains("沒有可以移出的冷資料"));
        let o = cdn_evict_outcome(7679, 4226 * 1024);
        assert!(worth_warning(o.bytes) && o.detail.contains("7679 筆"));
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut cdn = Fake::new("cdn", State::Tight, 99, 0, &log);
        cdn.bytes = 0;
        let g = Governor::new(res100(), vec![cdn], 0);
        g.tick(rd(600), 100).await;
        let mut now = 1000;
        while now < 1000 + 59 {
            g.tick(rd(80), now).await;
            now += 5;
        }
        assert_eq!(*log.lock().unwrap(), ["shed:cdn"], "60 秒內只試一次");
        let ev = g.status_json()["events"].as_array().unwrap().clone();
        assert!(ev.iter().all(|e| !e["msg"].as_str().unwrap().contains("沒有做")), "{ev:?}");
        g.tick(rd(80), 1000 + 60).await;
        assert_eq!(log.lock().unwrap().len(), 2, "60 秒後再試");
    }

    /// 3.5.0 F6／H12：日誌的 MB 跟狀態頁一樣四捨五入（保留量 3,264.6 MB：兩邊都是 3,265）
    #[test]
    fn log_reserve_rounds_like_ui() {
        assert_eq!(mb_round(3264 * MB + MB / 2), 3265);
        assert_eq!(mb_round(3264 * MB + MB / 2 - 1), 3264);
        assert_eq!(mb_round(0), 0);
        assert_eq!(mb_round(u64::MAX), u64::MAX >> 20, "不溢位");
        let res = Reserve::fixed(3264 * MB + MB * 6 / 10);
        let r = Reading {
            rss: Some(180 * MB + MB * 7 / 10),
            total: Some(65536 * MB),
            avail: Some(1000 * MB),
            psi: None,
        };
        let m = futile_message(true, &r, &res);
        assert!(m.contains("缺口 2265 MB") && m.contains("只有 181 MB"), "{m}");
    }

    /// 3.5.0 F1：讀不到量測（可用或自己的用量）時沒有依據繼續判，立刻離開（照舊讓出）
    #[test]
    fn futile_exits_at_once_when_unreadable() {
        let res = res100();
        let d = FUTILE_EXIT_SECS;
        for unreadable in [
            rdo(30, None),
            Reading {
                avail: None,
                ..rdo(30, Some(20))
            },
        ] {
            let mut g = FutileGate::default();
            assert!(g.step(&rdo(30, Some(20)), &res, d, 0));
            assert!(g.step(&unreadable, &res, d, 2), "立刻離開，不等 60 秒");
            assert!(!g.on);
        }
    }

    /// 3.5.0 F1：路由器（保留 16 MB、黑潮 20 MB）不會於事無補；吃緊中某一次讀數彈回保留量 + 遲滯以上時那一輪不讓出，
    /// 下一次讀數掉回去就照舊讓出
    #[tokio::test]
    async fn tight_router_still_sheds_when_reading_drops_again() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let res = Reserve::fixed(16 * MB);
        let g = Governor::new(res, ladder(&log, 2 * MB), 0);
        let r = |avail_mb: u64| Reading {
            rss: Some(20 * MB),
            total: Some(128 * MB),
            avail: Some(avail_mb * MB),
            psi: None,
        };
        g.tick(r(100), 100).await;
        let mut now = 1000;
        // 可用 12 MB（保留 16 MB 以下）：吃緊，讓出一步
        assert!(!g.observe_futile(&r(12), now));
        assert!(g.tick(r(12), now).await.is_some());
        let n = log.lock().unwrap().len();
        // 讀數彈回 30 MB（≥ 16 + 8）：狀態還是吃緊，但這一輪不讓出
        now += 10;
        assert!(!g.observe_futile(&r(30), now));
        assert!(g.tick(r(30), now).await.is_none());
        assert_eq!(log.lock().unwrap().len(), n);
        assert!(g.state() > State::Comfortable);
        assert!(g.status_json()["waiting"].as_str().unwrap().contains("回到保留量以上"));
        // 掉回 12 MB：照舊讓出
        now += 10;
        assert!(!g.observe_futile(&r(12), now));
        assert!(g.tick(r(12), now).await.is_some());
        assert!(log.lock().unwrap().len() > n);
    }

    #[tokio::test]
    async fn growth_stops_near_reserve_and_resumes_when_comfortable() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let f = Fake::new("cache", State::Tight, 1, 0, &log);
        let grow = f.grow.clone();
        let g = Governor::new(res100(), vec![f], 0);
        g.tick(rd(600), 100).await;
        assert!(grow.lock().unwrap().is_empty(), "一開始就可以長大：沒有變化不通知");
        assert_eq!(g.status_json()["growth"], true);
        // 保留量 + 遲滯（150 MB）以內：還沒低於保留量（不釋出），但停止長大
        assert!(g.tick(rd(140), 105).await.is_none());
        assert_eq!(*grow.lock().unwrap(), [false]);
        assert!(log.lock().unwrap().is_empty(), "還在保留量以上：不釋出");
        assert!(!g.status_json()["growth"].as_bool().unwrap());
        // 回到 160 MB：寬裕，恢復長大
        g.tick(rd(160), 110).await;
        assert_eq!(*grow.lock().unwrap(), [false, true]);
        assert_eq!(g.status_json()["growth"], true);
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
