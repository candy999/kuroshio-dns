//! 狀態快照寫入（規格 05 第 5 節）：保護 Flash 壽命，但該存的一定存
//!
//! - 資料平常放記憶體，`stage()` 只是登記「這份資料最新的內容」。
//! - `flush()` 依最短間隔與每日寫入量決定要不要真的寫：每日寫入量是「節奏目標」，
//!   超過就延後——但絕不超過「最久未存」上限（`system.persistMaxAgeHours`，Flash 上最多 24 小時）：
//!   有變動的資料從第一次變動起算，放到上限就不管今天寫了多少，一定寫出去。
//! - 最短間隔跟著記憶體走：記憶體越多、留在記憶體裡越久（寫得越少、重複的變動合併）；
//!   記憶體吃緊時提早寫出去，把記憶體裡的待寫內容放掉（`effective_interval`）。
//! - 只有計數變動的檔（`Opts::lazy`，例如 CDN 分片裡的查詢次數）不單獨觸發寫入，只在到了最久未存上限時寫。
//! - 內容沒變不寫；寫入用暫存檔 + fsync + 改名，斷電不會留下半個檔案。
//! - 大檔可以壓縮（`set_compress`）：存成 `名稱.zst`，讀的時候兩種格式都接受，寫出壓縮檔後刪掉舊的一般 JSON。
//! - 儲存空間跟記憶體同一個想法（規格 05 第 5.6 節）：檔案系統留一段**保留空間**（[`StorageReserve`]，
//!   `system.storageReserveMB` / `system.storageReservePercent`，0 = 自動）。空間在「保留 + 遲滯」以上時，
//!   可重建、可省略的資料（統計、候選 IP、過濾清單的本機副本……）大方留在磁碟上，重開機更快、少重新下載；
//!   空間掉到「保留 + 遲滯」以下就依序刪日誌 → 可省略 → 可重建（舊的、大的先刪）；還是不夠就只寫核心資料，
//!   其他的留在記憶體等下次。核心累積的資料絕不自動刪除。
//! - 關機時 `flush_all()` 不管間隔與上限，把有變動的都寫出去。
//! - 很大的檔（CDN 網域分片）用串流：登記的只是「怎麼產生內容」，
//!   要寫的那一刻才邊序列化邊寫進暫存檔，整份內容不會放在記憶體裡（等寫入間隔的期間也不會）。

use crate::space::{self, Tier};
use crate::sysinfo::{Pressure, StorageClass};
use kuroshio_cdn::statefile;
use serde_json::{json, Value};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::Hasher;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

/// Flash 上「最久未存」的上限（小時）
pub const MAX_AGE_HOURS_CAP: u64 = 24;
/// 記憶體充裕（可用 ≥ 這麼多 MB）：變動留到最久未存上限才寫
pub const MEM_PLENTY_MB: u64 = 256;
/// 記憶體普通（可用 ≥ 這麼多 MB）：間隔拉長到上限的一半
pub const MEM_MEDIUM_MB: u64 = 96;
const MB: u64 = 1 << 20;

/// 儲存空間的保留量（規格 05 第 5.6 節）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageReserve {
    pub bytes: u64,
    pub auto: bool,
    pub how: String,
}

impl StorageReserve {
    /// 遲滯：保留量的一半，至少 1 MB。可省略 / 可重建的資料只在「保留 + 遲滯」以上才寫、以下就刪
    pub fn margin(&self) -> u64 {
        (self.bytes / 2).max(MB)
    }
    /// 可省略 / 可重建的資料要留下的空間（保留 + 遲滯）
    pub fn keep_line(&self) -> u64 {
        self.bytes + self.margin()
    }
}

/// 決定儲存空間的保留量（純函式）。
///
/// 使用者設定：`system.storageReserveMB`、`system.storageReservePercent`（檔案系統大小的百分比，最多 90%）、
/// 舊的 `system.minFreeKB`，有填的取最大。都沒填（0）就自動：
/// - Flash（OpenWrt 的 jffs2 / ubifs overlay、SD 卡、eMMC）：max(1 MB, 檔案系統 10%（最多 64 MB）, 最大一份待寫 × 2)。
///   jffs2 的垃圾回收要有空的抹除區塊才能搬資料（核心預設保留約 5 個區塊給回收，NOR 每塊 64–256 KB），
///   空間太滿時寫入會越來越慢、甚至失敗；ubifs 回報的可用空間是估計值（壓縮率不定）。另外要留給
///   `opkg install`（一般套件 100–500 KB）與改設定檔。
/// - 記憶體（tmpfs）：max(1 MB, 10%（最多 64 MB）, 最大待寫 × 2)——tmpfs 用的是記憶體，記憶體另外由記憶體控制管。
/// - 硬碟、SSD、Windows：max(256 MB, 2%（最多 1 GB）, 最大待寫 × 2)：系統更新、分頁檔、暫存檔都要空間，
///   幾 MB 的狀態檔不該跟它們搶。
/// - 一律不超過檔案系統的一半。
pub fn storage_reserve(
    class: StorageClass,
    total: Option<u64>,
    user_mb: u64,
    user_pct: u64,
    min_free_kb: u64,
    largest_pending: u64,
) -> StorageReserve {
    let pct = user_pct.min(90);
    let user = (user_mb * MB)
        .max(total.map(|t| t / 100 * pct).unwrap_or(0))
        .max(min_free_kb * 1024);
    if user > 0 {
        let mut parts = Vec::new();
        if user_mb > 0 {
            parts.push(format!("{user_mb} MB"));
        }
        if pct > 0 {
            parts.push(format!("{pct}%"));
        }
        if min_free_kb > 0 {
            parts.push(format!("minFreeKB {min_free_kb}"));
        }
        return StorageReserve {
            bytes: user,
            auto: false,
            how: format!("設定：max({})", parts.join(", ")),
        };
    }
    let (floor, pct_of, cap, how) = match class {
        StorageClass::Flash => (MB, 10, 64 * MB, "自動（Flash）：max(1 MB, 10%, 最大待寫 × 2)"),
        StorageClass::Ram => (MB, 10, 64 * MB, "自動（tmpfs）：max(1 MB, 10%, 最大待寫 × 2)"),
        StorageClass::Disk => (256 * MB, 2, 1024 * MB, "自動（硬碟）：max(256 MB, 2%, 最大待寫 × 2)"),
    };
    let by_pct = total.map(|t| (t / 100 * pct_of).min(cap)).unwrap_or(0);
    let mut bytes = floor.max(by_pct).max(largest_pending * 2);
    if let Some(t) = total.filter(|t| *t > 0) {
        bytes = bytes.min(t / 2);
    }
    StorageReserve {
        bytes,
        auto: true,
        how: how.into(),
    }
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub class: StorageClass,
    /// 同一個檔案兩次寫入的最短間隔（秒；記憶體充裕時會再拉長，見 `effective_interval`）
    pub min_interval: u64,
    /// 間隔是自動決定的（`system.persistIntervalMin` = 0）：才會跟著記憶體調整
    pub auto_interval: bool,
    /// 每天寫入 Flash 的節奏目標（bytes，只對 Flash 有效）：超過就延後，但不超過 `max_age`
    pub daily_budget: u64,
    /// 有變動的資料最久放多久一定寫出（秒）
    pub max_age: u64,
    /// 儲存保留量的使用者設定（MB、百分比、舊的 minFreeKB；全 0 = 自動，見 [`storage_reserve`]）
    pub reserve_mb: u64,
    pub reserve_pct: u64,
    pub min_free_kb: u64,
}

impl Policy {
    /// 依設定與儲存類型決定（`interval_min` = 0 表示自動，再依記憶體拉長，見 [`effective_interval`]）。最久未存預設 24 小時
    pub fn new(class: StorageClass, interval_min: u64, budget_kb: u64) -> Policy {
        let auto = match class {
            StorageClass::Flash => 6 * 60,
            StorageClass::Ram | StorageClass::Disk => 10,
        };
        let mut minutes = if interval_min > 0 { interval_min } else { auto };
        if class == StorageClass::Flash {
            minutes = minutes.max(60); // Flash 上至少間隔 1 小時，避免設成每分鐘寫
        }
        Policy {
            class,
            min_interval: minutes * 60,
            auto_interval: interval_min == 0,
            daily_budget: budget_kb * 1024,
            max_age: 0,
            reserve_mb: 0,
            reserve_pct: 0,
            min_free_kb: 0,
        }
        .with_max_age_hours(MAX_AGE_HOURS_CAP)
    }

    /// 最久未存（小時，`system.persistMaxAgeHours`）：Flash 上 1–24 小時；
    /// 硬碟 / 記憶體照舊（最短間隔一到就寫，所以上限就是最短間隔）
    pub fn with_max_age_hours(mut self, hours: u64) -> Policy {
        self.max_age = match self.class {
            StorageClass::Flash => {
                let h = if hours == 0 {
                    MAX_AGE_HOURS_CAP
                } else {
                    hours.clamp(1, MAX_AGE_HOURS_CAP)
                };
                h * 3600
            }
            StorageClass::Ram | StorageClass::Disk => self.min_interval,
        };
        self
    }

    /// 儲存保留量（`system.storageReserveMB`、`system.storageReservePercent`、舊的 `system.minFreeKB`；全 0 = 自動）
    pub fn with_storage_reserve(mut self, mb: u64, pct: u64, min_free_kb: u64) -> Policy {
        self.reserve_mb = mb;
        self.reserve_pct = pct;
        self.min_free_kb = min_free_kb;
        self
    }
}

/// 記憶體狀況（記憶體監看量到的；保留量見規格 09）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mem {
    pub total_mb: Option<u64>,
    pub avail_mb: Option<u64>,
    /// 系統記憶體保留量
    pub reserve_mb: u64,
}

impl Mem {
    pub const UNKNOWN: Mem = Mem {
        total_mb: None,
        avail_mb: None,
        reserve_mb: 0,
    };

    /// 依保留量：低於一半 → 不足；保留 + 遲滯以內 → 偏低（同 `memgov::pressure_of`）
    pub fn pressure(&self) -> Pressure {
        let Some(a) = self.avail_mb else { return Pressure::Normal };
        let res = self.reserve_mb << 20;
        let a = a << 20;
        if a < res / 2 {
            Pressure::Critical
        } else if a < res + crate::memgov::margin(res) {
            Pressure::Low
        } else {
            Pressure::Normal
        }
    }

    /// 保留量以上還有多少（MB）
    pub fn headroom_mb(&self) -> Option<u64> {
        self.avail_mb.map(|a| a.saturating_sub(self.reserve_mb))
    }
}

/// 實際使用的最短間隔（秒）：只看（儲存類型、設定的間隔、最久未存、記憶體）的純函式（規格 05 第 5.3 節）
///
/// - 記憶體不足（`Critical`：可用 < 保留量一半）：0，下一輪就寫，寫完放掉記憶體裡的待寫內容
/// - 記憶體偏低（`Low`：保留 + 遲滯以內）：最多 1 小時
/// - Flash、自動間隔：保留量以上還有 ≥ 256 MB → 最久未存上限；≥ 96 MB → 上限的一半（但不短於預設間隔）；其他 → 預設間隔
/// - 使用者自己設定的間隔、硬碟 / 記憶體：照設定
/// - 一律不超過最久未存上限
pub fn effective_interval(p: &Policy, mem: Mem) -> u64 {
    let base = match mem.pressure() {
        Pressure::Critical => return 0,
        Pressure::Low => p.min_interval.min(3600),
        Pressure::Normal if p.class == StorageClass::Flash && p.auto_interval => match mem.headroom_mb() {
            Some(a) if a >= MEM_PLENTY_MB => p.max_age,
            Some(a) if a >= MEM_MEDIUM_MB => p.min_interval.max(p.max_age / 2),
            _ => p.min_interval,
        },
        Pressure::Normal => p.min_interval,
    };
    base.min(p.max_age.max(1))
}

/// 邊產生邊寫出內容（寫進 `Write`；失敗就回傳錯誤，暫存檔會被丟掉）
pub type StreamFn = Arc<dyn Fn(&mut dyn Write) -> std::io::Result<()> + Send + Sync>;

/// 一份快照的內容
#[derive(Clone)]
pub enum Snapshot {
    Bytes(Vec<u8>),
    /// 要寫的時候才產生（大檔用）
    Stream(StreamFn),
}

/// 登記時的選項
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Opts {
    /// 只有計數之類不重要的變動：不單獨觸發寫入，到了最久未存上限（或關機）才寫
    pub lazy: bool,
    /// 這些檔都寫好（沒有待寫內容）之後才能寫這一份（例如分片清單要等分片）
    pub after: Vec<String>,
    /// 這一份寫好之後要刪掉的舊檔（相對路徑；一般與 .zst 都刪）
    pub retire: Vec<String>,
}

enum Data {
    /// （內容雜湊，內容）
    Bytes(u64, Vec<u8>),
    Stream(StreamFn),
}

struct Pending {
    data: Data,
    /// 第一次出現還沒寫出的變動的時間（Unix 秒）
    since: u64,
    opts: Opts,
}

#[derive(Default)]
struct Entry {
    written_hash: Option<u64>,
    written_at: u64,
    /// 上次寫入在磁碟上的大小（串流的快照寫之前不知道大小，用它估算）
    written_size: u64,
    pending: Option<Pending>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    pub day: u64,
    pub bytes_today: u64,
    pub writes_today: u64,
    /// 昨天（UTC）寫了多少
    pub bytes_yesterday: u64,
    pub deferred: u64,
    pub pending: usize,
    /// 因為到了最久未存上限而寫（不然會再等）的次數（啟動以來）
    pub forced_by_age: u64,
    /// 可用空間（上次查到的，bytes）
    pub free_bytes: Option<u64>,
    /// 空間不足（上次檢查時）
    pub low_space: bool,
    /// 因為空間不足刪掉的檔案大小合計（啟動以來）
    pub freed_bytes: u64,
    /// 因為空間不足沒寫的次數（啟動以來）
    pub skipped: u64,
}

type FreeProbe = Box<dyn Fn(&Path) -> Option<u64> + Send>;
type CompressFn = Box<dyn Fn(&str) -> bool + Send>;

pub struct Persister {
    dir: PathBuf,
    policy: Policy,
    entries: HashMap<String, Entry>,
    stats: Stats,
    mem: Mem,
    compress: CompressFn,
    free_probe: FreeProbe,
    /// 檔案系統大小（bytes；算百分比的保留量用）
    fs_total: Option<u64>,
    /// 狀態目錄以外、空間不足時可以刪的檔（日誌）
    extra_files: Vec<(PathBuf, Tier)>,
    /// 最近因為空間不足刪掉的檔（時間，相對路徑，大小；最多 20 筆）
    deleted: Vec<(u64, String, u64)>,
}

/// 內容雜湊：分段餵進去跟整份一次餵結果相同（串流寫入時邊寫邊算）
struct HashWriter<W> {
    inner: W,
    h: DefaultHasher,
    n: u64,
}

impl<W: Write> HashWriter<W> {
    fn new(inner: W) -> HashWriter<W> {
        HashWriter {
            inner,
            h: DefaultHasher::new(),
            n: 0,
        }
    }
    fn finish(&self) -> (u64, u64) {
        let mut h = self.h.clone();
        h.write_u64(self.n);
        (h.finish(), self.n)
    }
}

impl<W: Write> Write for HashWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let k = self.inner.write(buf)?;
        self.h.write(&buf[..k]);
        self.n += k as u64;
        Ok(k)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn hash(b: &[u8]) -> u64 {
    let mut w = HashWriter::new(std::io::sink());
    let _ = w.write_all(b);
    w.finish().0
}

pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// 為什麼寫
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Why {
    Normal,
    Age,
    Shutdown,
}

impl Persister {
    pub fn new(dir: impl Into<PathBuf>, policy: Policy) -> Persister {
        Persister {
            dir: dir.into(),
            policy,
            entries: HashMap::new(),
            stats: Stats::default(),
            mem: Mem::UNKNOWN,
            compress: Box::new(|_| false),
            free_probe: Box::new(space::free_bytes),
            fs_total: None,
            extra_files: Vec::new(),
            deleted: Vec::new(),
        }
        .with_fs_total()
    }

    fn with_fs_total(mut self) -> Persister {
        self.fs_total = space::total_bytes(&self.dir);
        self
    }

    /// 測試用：指定檔案系統大小
    pub fn set_fs_total(&mut self, t: Option<u64>) {
        self.fs_total = t;
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// 哪些檔要壓縮成 `.zst`
    pub fn set_compress(&mut self, f: impl Fn(&str) -> bool + Send + 'static) {
        self.compress = Box::new(f);
    }

    /// 測試用：換掉可用空間的查法
    pub fn set_free_probe(&mut self, f: impl Fn(&Path) -> Option<u64> + Send + 'static) {
        self.free_probe = Box::new(f);
    }

    /// 登記狀態目錄以外的檔（例如日誌檔），空間不足時依等級可以刪（核心等級不會被刪）
    pub fn register_file(&mut self, path: PathBuf, tier: Tier) {
        if !self.extra_files.iter().any(|(p, _)| *p == path) {
            self.extra_files.push((path, tier));
        }
    }

    /// 記憶體狀況（看門狗每輪更新）
    pub fn set_mem(&mut self, mem: Mem) {
        self.mem = mem;
    }

    pub fn stats(&self) -> Stats {
        Stats {
            pending: self.entries.values().filter(|e| e.pending.is_some()).count(),
            ..self.stats.clone()
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// 這一份快照在磁碟上的路徑（壓縮的是 .zst）
    pub fn file_path(&self, name: &str) -> PathBuf {
        self.stored(name)
    }

    /// 實際寫在磁碟上的路徑
    fn stored(&self, name: &str) -> PathBuf {
        let p = self.path(name);
        if (self.compress)(name) {
            statefile::zst_path(&p)
        } else {
            p
        }
    }

    /// 讀取快照（一般 JSON 或 .zst 都可以），並記下內容雜湊（重開機後內容沒變就不會重寫）。
    /// 讀到的格式跟現在要寫的不同（例如舊版的一般 JSON）就不記雜湊：下次登記時寫成新格式、刪掉舊檔
    pub fn load(&mut self, name: &str) -> Option<Vec<u8>> {
        let l = statefile::load(&self.path(name))?;
        let want_zst = (self.compress)(name);
        let e = self.entries.entry(name.to_string()).or_default();
        e.written_hash = (l.compressed == want_zst).then(|| hash(&l.data));
        e.written_at = l
            .mtime
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        e.written_size = l.disk_size;
        Some(l.data)
    }

    /// 這一份還有沒寫出去的內容（記憶體控制移出 CDN 冷資料之前確認分片已經在磁碟上）
    pub fn is_pending(&self, name: &str) -> bool {
        self.entries.get(name).is_some_and(|e| e.pending.is_some())
    }

    /// 登記最新內容（還不寫）；內容跟已寫入的一樣就什麼都不做
    pub fn stage(&mut self, name: &str, data: Vec<u8>) {
        self.stage_with(name, Snapshot::Bytes(data), Opts::default(), now_secs());
    }

    /// 登記「有變動、要寫的時候這樣產生內容」（大檔用）：只記住產生的方法，不先序列化。
    /// 內容在真的寫入那一刻才產生，所以寫出去的是當時最新的狀態
    pub fn stage_stream(&mut self, name: &str, f: StreamFn) {
        self.stage_with(name, Snapshot::Stream(f), Opts::default(), now_secs());
    }

    /// 依內容種類登記
    pub fn stage_snapshot(&mut self, name: &str, s: Snapshot) {
        self.stage_with(name, s, Opts::default(), now_secs());
    }

    /// 登記（`now` = 變動發生的時間，用來算最久未存）。已經有待寫的內容時，「從什麼時候開始沒存」保留比較早的；
    /// 一般的變動蓋過「只有計數」
    pub fn stage_with(&mut self, name: &str, s: Snapshot, mut opts: Opts, now: u64) {
        let has_retire = opts.retire.iter().any(|r| statefile::exists(&self.dir.join(r)));
        let e = self.entries.entry(name.to_string()).or_default();
        let data = match s {
            Snapshot::Bytes(b) => {
                let h = hash(&b);
                if e.written_hash == Some(h) && !has_retire {
                    e.pending = None;
                    return;
                }
                Data::Bytes(h, b)
            }
            Snapshot::Stream(f) => Data::Stream(f),
        };
        let since = match &e.pending {
            Some(p) => {
                opts.lazy &= p.opts.lazy;
                for r in &p.opts.retire {
                    if !opts.retire.contains(r) {
                        opts.retire.push(r.clone());
                    }
                }
                p.since.min(now)
            }
            None => now,
        };
        e.pending = Some(Pending { data, since, opts });
    }

    /// 定時呼叫：到了間隔、而且今天的寫入量還沒超過節奏目標的才寫；到了最久未存上限的一定寫
    pub fn flush(&mut self, now: u64) -> std::io::Result<usize> {
        self.flush_inner(now, false)
    }

    /// 關機時：有變動的全部寫出
    pub fn flush_all(&mut self, now: u64) -> std::io::Result<usize> {
        self.flush_inner(now, true)
    }

    /// 估計大小（磁碟上）
    fn size_of(e: &Entry) -> u64 {
        match e.pending.as_ref().map(|p| &p.data) {
            Some(Data::Bytes(_, d)) => d.len() as u64,
            _ => e.written_size,
        }
    }

    /// 儲存空間的保留量（依設定、檔案系統大小、最大一份待寫內容）
    pub fn reserve(&self) -> StorageReserve {
        let largest = self
            .entries
            .values()
            .filter(|e| e.pending.is_some())
            .map(Self::size_of)
            .max()
            .unwrap_or(0);
        let p = &self.policy;
        storage_reserve(p.class, self.fs_total, p.reserve_mb, p.reserve_pct, p.min_free_kb, largest)
    }

    /// 可省略 / 可重建的資料現在能不能多寫 `size` bytes（寫完還在保留 + 遲滯以上）。
    /// 例如過濾清單的本機副本：空間大方時才留
    pub fn has_room_for_optional(&self, size: u64) -> bool {
        match (self.free_probe)(&self.dir) {
            Some(free) => free >= size + 64 * 1024 + self.reserve().keep_line(),
            None => true,
        }
    }

    /// 目前留在磁碟上的可省略 / 可重建資料（狀態頁用）：（檔數，bytes）
    pub fn optional_on_disk(&self) -> (usize, u64) {
        let c = space::candidates(&self.dir, &[]);
        let v: Vec<_> = c.iter().filter(|c| c.tier != Tier::Log).collect();
        (v.len(), v.iter().map(|c| c.size).sum())
    }

    /// `/api/status.persist.space`：總量、可用、保留量（怎麼來的）、保留量以上還有多少、留著的可省略資料、刪掉的
    pub fn storage_json(&self) -> Value {
        let r = self.reserve();
        let free = (self.free_probe)(&self.dir).or(self.stats.free_bytes);
        let (n, bytes) = self.optional_on_disk();
        json!({
            "totalBytes": self.fs_total,
            "freeBytes": free,
            "reserveBytes": r.bytes,
            "reserveAuto": r.auto,
            "reserveHow": r.how,
            "marginBytes": r.margin(),
            "headroomBytes": free.map(|f| f.saturating_sub(r.bytes)),
            "optionalFiles": n,
            "optionalBytes": bytes,
            "keepingOptional": free.map_or(true, |f| f >= r.keep_line()),
            "deleted": self.deleted.iter().rev().map(|(at, rel, size)| json!({ "at": at * 1000, "file": rel, "bytes": size })).collect::<Vec<_>>(),
        })
    }

    fn roll_day(&mut self, now: u64) {
        let day = now / 86400;
        if self.stats.day != day {
            let yesterday = if self.stats.day + 1 == day { self.stats.bytes_today } else { 0 };
            self.stats.day = day;
            self.stats.bytes_today = 0;
            self.stats.writes_today = 0;
            self.stats.deferred = 0;
            self.stats.bytes_yesterday = yesterday;
        }
    }

    /// 定時檢查可用空間（不寫檔也會檢查）：掉到「保留 + 遲滯」以下就依序刪日誌、可省略、可重建的檔，
    /// 直到回到線上（核心資料不刪）
    pub fn check_space(&mut self) {
        if let Some(t) = space::total_bytes(&self.dir) {
            self.fs_total = Some(t);
        }
        let line = self.reserve().keep_line();
        let free = (self.free_probe)(&self.dir);
        self.stats.free_bytes = free;
        let Some(free) = free else {
            self.stats.low_space = false;
            return;
        };
        if free < line {
            let freed = self.make_room(line - free, None);
            self.stats.free_bytes = (self.free_probe)(&self.dir);
            self.stats.low_space = free + freed < line;
        } else {
            self.stats.low_space = false;
        }
    }

    /// 刪日誌、可重建的檔，直到多出 `need` bytes（`keep` = 正要寫的那一份，不刪）；回傳釋出多少
    fn make_room(&mut self, need: u64, keep: Option<&Path>) -> u64 {
        let list: Vec<_> = space::candidates(&self.dir, &self.extra_files)
            .into_iter()
            .filter(|c| keep.map_or(true, |k| c.path != k))
            .collect();
        let sizes: HashMap<String, u64> = list.iter().map(|c| (c.rel.clone(), c.size)).collect();
        let (gone, freed) = space::free_up(list, |f| f >= need);
        let now = now_secs();
        for rel in &gone {
            if self.deleted.len() >= 20 {
                self.deleted.remove(0);
            }
            self.deleted.push((now, rel.clone(), sizes.get(rel).copied().unwrap_or(0)));
        }
        for rel in gone {
            // 這份快照被刪掉了：下次登記時就算內容沒變也要重寫
            let name = rel.trim_end_matches(".zst");
            if let Some(e) = self.entries.get_mut(name) {
                e.written_hash = None;
                e.written_size = 0;
            }
        }
        self.stats.freed_bytes += freed;
        freed
    }

    /// 寫這一份之前確認空間：核心資料只要放得下（可以用掉保留空間），其他的寫完還要在「保留 + 遲滯」以上。
    /// 不夠就先刪日誌、可重建的檔；還是不夠就不寫（留在記憶體，下次再試），不會寫到一半才失敗
    fn room_for(&mut self, name: &str, size: u64) -> bool {
        let Some(free) = (self.free_probe)(&self.dir) else { return true };
        let stored = self.stored(name);
        let rel = stored
            .strip_prefix(&self.dir)
            .unwrap_or(&stored)
            .to_string_lossy()
            .replace('\\', "/");
        let tier = space::tier_of(&rel);
        // 暫存檔寫好才改名：寫的期間新舊兩份並存
        let need = size.max(4096) + 64 * 1024;
        let line = self.reserve().keep_line();
        let required = if tier == Tier::Core { need } else { need + line };
        if free >= required {
            self.stats.free_bytes = Some(free);
            return true;
        }
        // 只刪到夠用為止（核心資料只要放得下）
        let freed = self.make_room(required - free, Some(&stored));
        let free = (self.free_probe)(&self.dir).unwrap_or(free + freed);
        self.stats.free_bytes = Some(free);
        if free >= required {
            return true;
        }
        self.stats.low_space = true;
        self.stats.skipped += 1;
        warn!(
            "儲存空間不足（剩 {} KB、需要 {} KB）：{} 先不寫，留在記憶體{}",
            free / 1024,
            required.div_ceil(1024),
            name,
            if tier == Tier::Core { "" } else { "（只寫核心資料）" }
        );
        false
    }

    fn flush_inner(&mut self, now: u64, force: bool) -> std::io::Result<usize> {
        self.roll_day(now);
        let interval = effective_interval(&self.policy, self.mem);
        let critical = self.mem.pressure() == Pressure::Critical;
        let mut names: Vec<(bool, String)> = self
            .entries
            .iter()
            .filter_map(|(k, e)| e.pending.as_ref().map(|p| (!p.opts.after.is_empty(), k.clone())))
            .collect();
        // 有先後順序的（分片清單）放最後
        names.sort();
        let mut n = 0;
        for (_, name) in names {
            let (why, size, age) = {
                let e = &self.entries[&name];
                let Some(p) = e.pending.as_ref() else { continue };
                let deps_ok = p
                    .opts
                    .after
                    .iter()
                    .all(|d| self.entries.get(d).map_or(true, |x| x.pending.is_none()));
                if !deps_ok {
                    continue;
                }
                let size = Self::size_of(e);
                let age = now.saturating_sub(p.since);
                let aged = age >= self.policy.max_age;
                let due = e.written_at == 0 || now.saturating_sub(e.written_at) >= interval;
                let over = self.policy.class == StorageClass::Flash && self.stats.bytes_today + size > self.policy.daily_budget;
                let why = if force {
                    Some(Why::Shutdown)
                } else if p.opts.lazy {
                    aged.then_some(Why::Age)
                } else if due && (!over || critical) {
                    Some(Why::Normal)
                } else if aged {
                    Some(Why::Age)
                } else {
                    if due && over {
                        self.stats.deferred += 1;
                    }
                    None
                };
                (why, size, age)
            };
            let Some(why) = why else { continue };
            if !self.room_for(&name, size) {
                continue;
            }
            let compress = (self.compress)(&name);
            let stored = self.stored(&name);
            let plain = self.path(&name);
            let pending = self.entries.get_mut(&name).unwrap().pending.take().unwrap();
            let r = match &pending.data {
                Data::Bytes(h, data) => write_file(&stored, compress, &mut |w| w.write_all(data)).map(|(_, disk)| (*h, disk)),
                Data::Stream(f) => write_file(&stored, compress, &mut |w| f(w)),
            };
            let (h, disk) = match r {
                Ok(x) => x,
                Err(e) => {
                    self.entries.get_mut(&name).unwrap().pending = Some(pending);
                    return Err(e);
                }
            };
            // 另一種格式的舊檔（例如壓縮前的一般 JSON）：只遷移一次
            let other = if compress { plain } else { statefile::zst_path(&plain) };
            if other.exists() {
                let _ = std::fs::remove_file(&other);
            }
            for r in &pending.opts.retire {
                statefile::remove(&self.dir.join(r));
                if r != &name {
                    self.entries.remove(r);
                }
            }
            if why == Why::Age {
                self.stats.forced_by_age += 1;
                info!(
                    "{name} 已經 {:.1} 小時沒存（上限 {} 小時）：不管今天的寫入量，直接寫入 {disk} bytes",
                    age as f64 / 3600.0,
                    self.policy.max_age / 3600
                );
            }
            let e = self.entries.get_mut(&name).unwrap();
            e.written_hash = Some(h);
            e.written_at = now;
            e.written_size = disk;
            self.stats.bytes_today += disk;
            self.stats.writes_today += 1;
            n += 1;
        }
        Ok(n)
    }

    /// 最久的未存變動（秒）
    pub fn oldest_unsaved(&self, now: u64) -> u64 {
        self.entries
            .values()
            .filter_map(|e| e.pending.as_ref())
            .map(|p| now.saturating_sub(p.since))
            .max()
            .unwrap_or(0)
    }

    /// 預估每天的寫入量（bytes）：昨天的量，或今天到目前為止的量換算成一整天（取大的）
    pub fn estimated_daily(&self, now: u64) -> u64 {
        let elapsed = (now % 86400).max(3600);
        let today = if self.stats.day == now / 86400 { self.stats.bytes_today } else { 0 };
        self.stats.bytes_yesterday.max(today.saturating_mul(86400) / elapsed)
    }

    /// `/api/status` 的 `persist`
    pub fn status_json(&self, now: u64) -> Value {
        let st = self.stats();
        let mut names: Vec<&String> = self.entries.keys().collect();
        names.sort();
        let files: serde_json::Map<String, Value> = names
            .into_iter()
            .map(|k| {
                let e = &self.entries[k];
                (
                    k.clone(),
                    json!({
                        "lastWrite": (e.written_at > 0).then_some(e.written_at * 1000),
                        "pendingSince": e.pending.as_ref().map(|p| p.since * 1000),
                        "countersOnly": e.pending.as_ref().map(|p| p.opts.lazy),
                        "size": e.written_size,
                        "compressed": (self.compress)(k),
                    }),
                )
            })
            .collect();
        json!({
            "class": self.policy.class.name(),
            "storage": self.policy.class.name(),
            "intervalMin": self.policy.min_interval / 60,
            "effectiveIntervalMin": effective_interval(&self.policy, self.mem) / 60,
            "maxAgeHours": self.policy.max_age as f64 / 3600.0,
            "dailyBudgetKB": self.policy.daily_budget / 1024,
            "bytesToday": st.bytes_today,
            "writesToday": st.writes_today,
            "bytesYesterday": st.bytes_yesterday,
            "estimatedDailyBytes": self.estimated_daily(now),
            "deferred": st.deferred,
            "pending": st.pending,
            "oldestUnsavedSec": self.oldest_unsaved(now),
            "forcedByAge": st.forced_by_age,
            "freeBytes": st.free_bytes,
            "minFreeBytes": self.reserve().bytes,
            "space": self.storage_json(),
            "lowSpace": st.low_space,
            "freedBytes": st.freed_bytes,
            "skipped": st.skipped,
            "files": files,
        })
    }
}

/// 暫存檔 + fsync + 改名。
///
/// Unix 上檔案一律只有擁有者能讀寫（0600）：狀態目錄裡有 ACME 帳號金鑰、憑證私鑰、設定頁 token、
/// 社群私鑰、含私鑰的備份暫存檔，其餘的快照（查過的網域、統計）也不該讓同一台機器的其他帳號讀到。
/// 暫存檔一開始就用 0600 建立（不是寫完才改權限），所以私鑰不會有短暫可讀的空窗。
pub fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    write_atomic_with(path, &mut |w| w.write_all(data)).map(|_| ())
}

/// 同 `write_atomic`，內容由 `f` 邊產生邊寫進暫存檔（經過緩衝）。回傳（內容雜湊，大小）
pub fn write_atomic_with(path: &Path, gen: &mut dyn FnMut(&mut dyn Write) -> std::io::Result<()>) -> std::io::Result<(u64, u64)> {
    write_file(path, false, gen)
}

/// 寫檔（`compress` = 邊寫邊 zstd 壓縮）。回傳（壓縮前內容的雜湊，磁碟上的大小）
fn write_file(path: &Path, compress: bool, gen: &mut dyn FnMut(&mut dyn Write) -> std::io::Result<()>) -> std::io::Result<(u64, u64)> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    let r = (|| {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        let f = o.open(&tmp)?;
        // 上次留下來的暫存檔可能是舊版用 0644 建的：mode() 只在新建時有效，這裡再收緊一次
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        let buf = std::io::BufWriter::with_capacity(64 * 1024, f);
        let (h, buf) = if compress {
            let mut w = HashWriter::new(statefile::encoder(buf)?);
            gen(&mut w)?;
            w.flush()?;
            let h = w.finish().0;
            (h, w.inner.finish()?)
        } else {
            let mut w = HashWriter::new(buf);
            gen(&mut w)?;
            w.flush()?;
            (w.finish().0, w.inner)
        };
        let f = buf.into_inner().map_err(|e| e.into_error())?;
        f.sync_all()?;
        let size = f.metadata()?.len();
        Ok((h, size))
    })();
    match r {
        Ok(out) => {
            std::fs::rename(&tmp, path)?;
            Ok(out)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("kuroshio-persist-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[cfg(unix)]
    #[test]
    fn files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("mode");
        let f = dir.join("acme-account.json");
        // 舊版留下、所有人可讀的檔案與暫存檔：重寫之後都收緊成 0600
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&f, b"old").unwrap();
        std::fs::write(f.with_extension("tmp"), b"junk").unwrap();
        for p in [&f, &f.with_extension("tmp")] {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        write_atomic(&f, b"secret").unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"secret");
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(!f.with_extension("tmp").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn policy_intervals() {
        assert_eq!(Policy::new(StorageClass::Flash, 0, 4096).min_interval, 6 * 3600);
        assert_eq!(Policy::new(StorageClass::Flash, 0, 4096).min_interval, 6 * 3600, "不分硬體等級");
        assert_eq!(Policy::new(StorageClass::Flash, 1, 4096).min_interval, 3600, "Flash 最短 1 小時");
        assert_eq!(Policy::new(StorageClass::Disk, 0, 4096).min_interval, 600);
        // 最久未存：Flash 1–24 小時；硬碟照舊（間隔一到就寫）
        let f = |h| Policy::new(StorageClass::Flash, 0, 4096).with_max_age_hours(h).max_age;
        assert_eq!(f(0), 24 * 3600);
        assert_eq!(f(6), 6 * 3600);
        assert_eq!(f(100), 24 * 3600, "Flash 上最多 24 小時");
        assert_eq!(Policy::new(StorageClass::Disk, 0, 4096).with_max_age_hours(24).max_age, 600);
    }

    #[test]
    fn interval_follows_memory() {
        // 保留 16 MB（遲滯 8 MB）
        let mem = |t, a| Mem {
            total_mb: Some(t),
            avail_mb: Some(a),
            reserve_mb: 16,
        };
        let flash = Policy::new(StorageClass::Flash, 0, 4096);
        let h = 3600;
        assert_eq!(
            effective_interval(&flash, mem(1024, 700)),
            24 * h,
            "保留量以上很多：留到最久未存上限"
        );
        assert_eq!(effective_interval(&flash, mem(256, 150)), 12 * h, "普通：上限的一半");
        assert_eq!(effective_interval(&flash, mem(128, 60)), 6 * h, "不多：預設間隔（不分硬體等級）");
        assert_eq!(effective_interval(&flash, Mem::UNKNOWN), 6 * h, "量不到：預設間隔");
        assert_eq!(effective_interval(&flash, mem(128, 20)), h, "保留 + 遲滯以內：最多 1 小時");
        assert_eq!(effective_interval(&flash, mem(1024, 7)), 0, "低於保留量一半：馬上寫");
        // 保留量大的機器（使用者設 512 MB）：同樣的可用量，間隔短一些
        let big = |a| Mem {
            total_mb: Some(4096),
            avail_mb: Some(a),
            reserve_mb: 512,
        };
        assert_eq!(effective_interval(&flash, big(700)), h, "可用 700 MB 還在保留 + 遲滯（768 MB）以內");
        // 一律不超過最久未存上限
        let short = Policy::new(StorageClass::Flash, 0, 4096).with_max_age_hours(4);
        assert_eq!(effective_interval(&short, mem(1024, 700)), 4 * h);
        assert_eq!(effective_interval(&short, mem(128, 60)), 4 * h);
        // 使用者自己設的間隔不跟著記憶體拉長
        let fixed = Policy::new(StorageClass::Flash, 120, 4096);
        assert_eq!(effective_interval(&fixed, mem(1024, 700)), 2 * h);
        // 硬碟：照舊 10 分鐘
        assert_eq!(effective_interval(&Policy::new(StorageClass::Disk, 0, 4096), mem(4096, 3000)), 600);
    }

    #[test]
    fn interval_unchanged_and_shutdown() {
        let dir = tmpdir("a");
        let mut p = Persister::new(&dir, Policy::new(StorageClass::Flash, 0, 4096));
        let t0 = 1_000_000;
        p.stage("pools.json", b"v1".to_vec());
        assert_eq!(p.flush(t0).unwrap(), 1, "第一次直接寫");
        assert_eq!(std::fs::read(dir.join("pools.json")).unwrap(), b"v1");

        p.stage("pools.json", b"v1".to_vec());
        assert_eq!(p.stats().pending, 0, "內容沒變不排入");

        p.stage("pools.json", b"v2".to_vec());
        assert_eq!(p.flush(t0 + 3600).unwrap(), 0, "未滿 6 小時不寫");
        assert_eq!(p.flush(t0 + 6 * 3600).unwrap(), 1);
        assert_eq!(std::fs::read(dir.join("pools.json")).unwrap(), b"v2");

        p.stage("pools.json", b"v3".to_vec());
        assert_eq!(p.flush_all(t0 + 6 * 3600 + 5).unwrap(), 1, "關機時不管間隔");
        assert_eq!(p.stats().writes_today, 3);
        assert!(!dir.join("pools.tmp").exists(), "沒有留下暫存檔");

        // 重開機：讀回快照後，內容沒變就不會重寫
        let mut q = Persister::new(&dir, Policy::new(StorageClass::Flash, 0, 4096));
        assert_eq!(q.load("pools.json").unwrap(), b"v3");
        q.stage("pools.json", b"v3".to_vec());
        assert_eq!(q.flush(t0 + 100 * 86400).unwrap(), 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn daily_budget_defers() {
        let dir = tmpdir("b");
        let mut p = Persister::new(&dir, Policy::new(StorageClass::Flash, 0, 1)); // 每天 1 KB
        let t = 2_000_000 * 86400 / 86400;
        p.stage_with("a", Snapshot::Bytes(vec![1; 800]), Opts::default(), t);
        p.stage_with("b", Snapshot::Bytes(vec![2; 800]), Opts::default(), t);
        assert_eq!(p.flush(t).unwrap(), 1, "第二份超過今天的節奏目標");
        assert_eq!(p.stats().deferred, 1);
        assert_eq!(p.stats().pending, 1);
        assert_eq!(p.flush(t + 86400).unwrap(), 1, "隔天額度重算");
        // Disk 不受每日上限限制
        let mut d = Persister::new(dir.join("disk"), Policy::new(StorageClass::Disk, 0, 1));
        d.stage("a", vec![1; 4096]);
        d.stage("b", vec![2; 4096]);
        assert_eq!(d.flush(t).unwrap(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn max_age_forces_write_over_budget() {
        // (i) 超過每日寫入量也一樣：變動放到最久未存上限就一定寫出
        let dir = tmpdir("age");
        let pol = Policy::new(StorageClass::Flash, 0, 1).with_max_age_hours(24); // 每天 1 KB
        let mut p = Persister::new(&dir, pol);
        let t0 = 3_000 * 86400 + 3600;
        p.stage_with("big", Snapshot::Bytes(vec![7; 900]), Opts::default(), t0);
        assert_eq!(p.flush(t0).unwrap(), 1);
        p.stage_with("other", Snapshot::Bytes(vec![8; 900]), Opts::default(), t0);
        assert_eq!(p.flush(t0 + 7 * 3600).unwrap(), 0, "超過今天的量：延後");
        // 同一天稍後再變動：「從什麼時候開始沒存」還是第一次的時間
        p.stage_with("other", Snapshot::Bytes(vec![9; 900]), Opts::default(), t0 + 10 * 3600);
        assert_eq!(p.flush(t0 + 20 * 3600).unwrap(), 0);
        assert_eq!(p.oldest_unsaved(t0 + 20 * 3600), 20 * 3600);
        // 隔天額度又被別的檔用掉
        p.stage_with("big", Snapshot::Bytes(vec![1; 1000]), Opts::default(), t0 + 22 * 3600);
        assert_eq!(p.flush(t0 + 23 * 3600 + 1).unwrap(), 1, "big 先用掉隔天的額度");
        assert_eq!(p.flush(t0 + 23 * 3600 + 2).unwrap(), 0, "other 還沒滿 24 小時");
        assert_eq!(p.flush(t0 + 24 * 3600).unwrap(), 1, "滿 24 小時：不管額度直接寫");
        assert_eq!(std::fs::read(dir.join("other")).unwrap(), vec![9; 900]);
        assert_eq!(p.stats().forced_by_age, 1);
        assert_eq!(p.oldest_unsaved(t0 + 24 * 3600), 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn counters_only_wait_for_max_age() {
        let dir = tmpdir("lazy");
        let mut p = Persister::new(&dir, Policy::new(StorageClass::Flash, 0, 4096).with_max_age_hours(24));
        let t0 = 4_000 * 86400;
        let lazy = Opts {
            lazy: true,
            ..Opts::default()
        };
        p.stage_with("s1", Snapshot::Bytes(b"x".to_vec()), lazy.clone(), t0);
        assert_eq!(p.flush(t0).unwrap(), 0, "只有計數：不單獨寫");
        assert_eq!(p.flush(t0 + 23 * 3600).unwrap(), 0);
        assert_eq!(p.flush(t0 + 24 * 3600).unwrap(), 1, "到了最久未存上限才寫");
        // 計數之後又有重要變動：照一般的間隔寫，「沒存的時間」從計數變動時算
        p.stage_with("s1", Snapshot::Bytes(b"y".to_vec()), lazy, t0 + 25 * 3600);
        p.stage_with("s1", Snapshot::Bytes(b"z".to_vec()), Opts::default(), t0 + 31 * 3600);
        assert_eq!(p.flush(t0 + 31 * 3600).unwrap(), 1);
        assert_eq!(std::fs::read(dir.join("s1")).unwrap(), b"z");
        // 關機：只有計數的也寫
        p.stage_with(
            "s1",
            Snapshot::Bytes(b"w".to_vec()),
            Opts {
                lazy: true,
                ..Opts::default()
            },
            t0 + 32 * 3600,
        );
        assert_eq!(p.flush_all(t0 + 32 * 3600).unwrap(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn compressed_and_migrated() {
        let dir = tmpdir("zst");
        std::fs::create_dir_all(dir.join("cdn")).unwrap();
        // 舊版留下的一般 JSON
        let body = br#"{"providers":{"cloudflare":{"v4":[{"ip":"104.16.0.1"}]}}}"#.repeat(50);
        std::fs::write(dir.join("cdn/pools.json"), &body).unwrap();
        let mut p = Persister::new(&dir, Policy::new(StorageClass::Flash, 0, 4096));
        p.set_compress(|n| n.starts_with("cdn/"));
        assert_eq!(p.load("cdn/pools.json").unwrap(), body);
        // 內容沒變也要寫一次新格式（只遷移一次）
        p.stage("cdn/pools.json", body.clone());
        assert_eq!(p.flush(now_secs() + 7 * 3600).unwrap(), 1);
        assert!(!dir.join("cdn/pools.json").exists(), "寫出壓縮檔後刪掉一般 JSON");
        let z = std::fs::read(dir.join("cdn/pools.json.zst")).unwrap();
        assert!(z.len() * 10 < body.len(), "壓縮後 {} / {}", z.len(), body.len());
        assert_eq!(p.stats().bytes_today, z.len() as u64, "寫入量算磁碟上的大小");
        // 重開機：讀得回來、內容沒變不重寫
        let mut q = Persister::new(&dir, Policy::new(StorageClass::Flash, 0, 4096));
        q.set_compress(|n| n.starts_with("cdn/"));
        assert_eq!(q.load("cdn/pools.json").unwrap(), body);
        q.stage("cdn/pools.json", body.clone());
        assert_eq!(q.stats().pending, 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ordered_writes_and_retire() {
        // 分片清單要等分片都寫好才寫；寫好之後刪掉舊檔
        let dir = tmpdir("order");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("old.json"), b"legacy").unwrap();
        let mut p = Persister::new(&dir, Policy::new(StorageClass::Flash, 0, 1)); // 每天 1 KB
        let t = 6_000 * 86400;
        p.stage_with("s0", Snapshot::Bytes(vec![1; 600]), Opts::default(), t);
        p.stage_with("s1", Snapshot::Bytes(vec![2; 600]), Opts::default(), t);
        let m = Opts {
            after: vec!["s0".into(), "s1".into()],
            retire: vec!["old.json".into()],
            ..Opts::default()
        };
        p.stage_with("manifest", Snapshot::Bytes(b"m".to_vec()), m, t);
        assert_eq!(p.flush(t).unwrap(), 1, "s1 超過今天的量");
        assert!(!dir.join("manifest").exists() && dir.join("old.json").exists());
        assert_eq!(p.flush(t + 86400).unwrap(), 2, "s1 寫好之後清單才寫");
        assert!(dir.join("manifest").exists() && !dir.join("old.json").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn low_space_deletes_rebuildable_and_skips_non_core() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let dir = tmpdir("space");
        std::fs::create_dir_all(dir.join("cdn")).unwrap();
        std::fs::write(dir.join("stats.json"), vec![0; 300_000]).unwrap();
        std::fs::write(dir.join("cdn/v6-nodes.json"), vec![0; 300_000]).unwrap();
        let log = std::env::temp_dir().join(format!("kuroshio-space-test-{}.log", std::process::id()));
        std::fs::write(&log, vec![0; 100_000]).unwrap();
        // 檔案系統假裝只剩 base + 被刪掉的檔案大小
        let base = Arc::new(AtomicU64::new(100_000));
        let d2 = dir.clone();
        let l2 = log.clone();
        let b2 = base.clone();
        let mut p = Persister::new(&dir, Policy::new(StorageClass::Flash, 0, 4096).with_storage_reserve(0, 0, 1024));
        p.set_free_probe(move |_| {
            let gone = |p: &Path, n: u64| if p.exists() { 0 } else { n };
            Some(b2.load(Ordering::SeqCst) + gone(&d2.join("stats.json"), 300_000) + gone(&l2, 100_000))
        });
        p.register_file(log.clone(), Tier::Log);
        let t = 7_000 * 86400;
        // 核心資料（節點）：放得下就寫，不必留下保留空間；先刪日誌就夠
        p.stage_with("cdn/v6-nodes.json", Snapshot::Bytes(vec![1; 100_000]), Opts::default(), t);
        assert_eq!(p.flush(t).unwrap(), 1);
        assert!(!log.exists(), "先刪日誌");
        assert!(dir.join("stats.json").exists(), "日誌刪完就夠了，可重建的留著");
        // 可重建的資料（統計）要留下 1 MB 保留空間：刪光可重建的還是不夠 → 不寫、留在記憶體
        p.stage_with("cdn/harvest.json", Snapshot::Bytes(vec![2; 50_000]), Opts::default(), t);
        assert_eq!(p.flush(t + 1).unwrap(), 0);
        assert!(!dir.join("stats.json").exists(), "可重建的被刪掉");
        assert!(dir.join("cdn/v6-nodes.json").exists(), "核心資料不刪");
        let s = p.stats();
        assert!(s.low_space && s.skipped == 1 && s.pending == 1);
        assert_eq!(s.freed_bytes, 400_000);
        let j = p.status_json(t + 1);
        assert_eq!(j["lowSpace"], true);
        assert_eq!(j["skipped"], 1);
        // 空間回來了：照常寫
        base.store(10 << 20, Ordering::SeqCst);
        p.check_space();
        assert!(!p.stats().low_space);
        assert_eq!(p.flush(t + 2).unwrap(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn hash_is_chunk_independent() {
        let data: Vec<u8> = (0..200_000u32).map(|i| (i * 7 % 251) as u8).collect();
        let mut w = HashWriter::new(std::io::sink());
        for c in data.chunks(997) {
            w.write_all(c).unwrap();
        }
        assert_eq!(w.finish(), (hash(&data), data.len() as u64));
        assert_ne!(hash(b"ab"), hash(b"abc"));
    }

    #[test]
    fn stream_generates_at_write_time() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let dir = tmpdir("s");
        let mut p = Persister::new(&dir, Policy::new(StorageClass::Flash, 0, 4096));
        let calls = Arc::new(AtomicU32::new(0));
        let ver = Arc::new(AtomicU32::new(1));
        let gen = |calls: &Arc<AtomicU32>, ver: &Arc<AtomicU32>| -> StreamFn {
            let (calls, ver) = (calls.clone(), ver.clone());
            Arc::new(move |w: &mut dyn Write| {
                calls.fetch_add(1, Ordering::SeqCst);
                for _ in 0..1000 {
                    write!(w, "v{};", ver.load(Ordering::SeqCst))?;
                }
                Ok(())
            })
        };
        let t0 = 1_000_000;
        p.stage_stream("cdn-domains.json", gen(&calls, &ver));
        assert_eq!(calls.load(Ordering::SeqCst), 0, "登記時不產生內容");
        assert_eq!(p.stats().pending, 1);
        assert_eq!(p.flush(t0).unwrap(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(std::fs::read(dir.join("cdn-domains.json")).unwrap(), b"v1;".repeat(1000));
        assert_eq!(p.stats().bytes_today, 3000);

        // 等間隔的期間內容又變了：寫出去的是寫入那一刻的內容
        p.stage_stream("cdn-domains.json", gen(&calls, &ver));
        ver.store(2, Ordering::SeqCst);
        assert_eq!(p.flush(t0 + 3600).unwrap(), 0, "未滿 6 小時不寫");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "沒寫就不產生");
        assert_eq!(p.flush(t0 + 6 * 3600).unwrap(), 1);
        assert_eq!(std::fs::read(dir.join("cdn-domains.json")).unwrap(), b"v2;".repeat(1000));

        // 產生到一半失敗：舊檔不動、不留暫存檔，下次再寫
        p.stage_stream(
            "cdn-domains.json",
            Arc::new(|w: &mut dyn Write| {
                w.write_all(b"half")?;
                Err(std::io::Error::other("中斷"))
            }),
        );
        assert!(p.flush_all(t0 + 7 * 3600).is_err());
        assert_eq!(std::fs::read(dir.join("cdn-domains.json")).unwrap(), b"v2;".repeat(1000));
        assert!(!dir.join("cdn-domains.tmp").exists());
        assert_eq!(p.stats().pending, 1);

        // 每日上限用上次寫入的大小估算
        let mut q = Persister::new(&dir, Policy::new(StorageClass::Flash, 0, 4)); // 每天 4 KB
        assert!(q.load("cdn-domains.json").is_some());
        let now = now_secs() + 7 * 3600;
        q.stage_with("a", Snapshot::Bytes(vec![1; 2000]), Opts::default(), now);
        q.stage_with("cdn-domains.json", Snapshot::Stream(gen(&calls, &ver)), Opts::default(), now);
        let before = calls.load(Ordering::SeqCst);
        assert_eq!(q.flush(now).unwrap(), 1, "a 先寫，資料庫（約 3 KB）超過今天的上限");
        assert_eq!(calls.load(Ordering::SeqCst), before, "延後的不產生內容");
        assert_eq!(q.stats().deferred, 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn storage_reserve_derivation() {
        let g = 1u64 << 30;
        // Flash 自動：max(1 MB, 10%（最多 64 MB）, 最大待寫 × 2)，不超過一半
        let f = |total, largest| storage_reserve(StorageClass::Flash, total, 0, 0, 0, largest);
        assert_eq!(f(Some(4 * MB), 0).bytes, MB, "4 MB overlay：1 MB");
        assert_eq!(f(Some(32 * MB), 0).bytes, 32 * MB / 100 * 10);
        assert_eq!(f(Some(8 * g), 0).bytes, 64 * MB, "大的 eMMC：最多 64 MB");
        assert_eq!(f(Some(32 * MB), 3 * MB).bytes, 6 * MB, "最大待寫 × 2");
        assert_eq!(f(Some(MB), 0).bytes, MB / 2, "不超過一半");
        assert!(f(None, 0).auto);
        // 硬碟：max(256 MB, 2%（最多 1 GB）)
        let d = |total| storage_reserve(StorageClass::Disk, total, 0, 0, 0, 0).bytes;
        assert_eq!(d(Some(25 * g)), 25 * g / 100 * 2);
        assert_eq!(d(Some(100 * g)), g, "2% 最多 1 GB");
        assert_eq!(d(Some(5 * g)), 256 * MB);

        // 使用者：MB、百分比、舊的 minFreeKB，取最大
        let u = storage_reserve(StorageClass::Flash, Some(100 * MB), 3, 0, 0, 0);
        assert_eq!((u.bytes, u.auto), (3 * MB, false));
        assert_eq!(
            storage_reserve(StorageClass::Flash, Some(100 * MB), 3, 5, 0, 0).bytes,
            5 * MB,
            "取大的"
        );
        assert_eq!(
            storage_reserve(StorageClass::Flash, Some(100 * MB), 3, 5, 8192, 0).bytes,
            8 * MB,
            "minFreeKB 照樣接受"
        );
        assert_eq!(
            storage_reserve(StorageClass::Flash, Some(100 * MB), 0, 99, 0, 0).bytes,
            90 * MB,
            "百分比最多 90%"
        );
        // 遲滯：一半，至少 1 MB
        assert_eq!(u.margin(), 1536 * 1024);
        assert_eq!(u.keep_line(), 3 * MB + 1536 * 1024);
    }

    #[test]
    fn optional_kept_above_reserve_and_pruned_below_core_never() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let dir = tmpdir("optional");
        std::fs::create_dir_all(dir.join("filter-lists")).unwrap();
        std::fs::create_dir_all(dir.join("cdn")).unwrap();
        // 保留 2 MB（遲滯 1 MB → 線在 3 MB）
        let free = Arc::new(AtomicU64::new(10 * MB));
        let f2 = free.clone();
        let mut p = Persister::new(&dir, Policy::new(StorageClass::Flash, 0, 4096).with_storage_reserve(2, 0, 0));
        p.set_fs_total(Some(100 * MB));
        let d2 = dir.clone();
        p.set_free_probe(move |_| {
            // 刪掉的檔案大小加回可用空間
            let back: u64 = ["filter-lists/a.txt.zst", "stats.json"]
                .iter()
                .filter(|f| !d2.join(f).exists())
                .map(|_| 500_000)
                .sum();
            Some(f2.load(Ordering::SeqCst) + back)
        });
        let t = 9_000 * 86400;
        // 空間大方：可省略的副本照寫
        assert!(p.has_room_for_optional(500_000));
        p.stage_with("filter-lists/a.txt.zst", Snapshot::Bytes(vec![1; 500_000]), Opts::default(), t);
        p.stage_with("stats.json", Snapshot::Bytes(vec![2; 500_000]), Opts::default(), t);
        p.stage_with("cdn/pools.json", Snapshot::Bytes(vec![3; 500_000]), Opts::default(), t);
        assert_eq!(p.flush(t).unwrap(), 3);
        let st = p.storage_json();
        assert_eq!(st["reserveBytes"], 2 * MB);
        assert_eq!(st["reserveAuto"], false);
        assert_eq!(st["optionalFiles"], 2, "副本與統計都留著");
        assert_eq!(st["keepingOptional"], true);
        // 別的程式用掉空間：掉到線（3 MB）以下 → 先刪可省略的（副本），還不夠再刪可重建的；核心不刪
        free.store(2_800_000, Ordering::SeqCst);
        assert!(!p.has_room_for_optional(100_000), "接近保留量：不再留副本");
        p.check_space();
        assert!(!dir.join("filter-lists/a.txt.zst").exists(), "可省略的最先刪");
        assert!(dir.join("stats.json").exists(), "刪副本就回到線上：可重建的留著");
        assert!(dir.join("cdn/pools.json").exists());
        free.store(MB, Ordering::SeqCst);
        p.check_space();
        assert!(!dir.join("stats.json").exists(), "再不夠：刪可重建的");
        assert!(dir.join("cdn/pools.json").exists(), "核心資料絕不自動刪除");
        assert!(p.stats().low_space, "還是不夠：回報、只寫核心");
        let st = p.storage_json();
        assert_eq!(st["deleted"].as_array().unwrap().len(), 2);
        // 只寫核心：可重建的留在記憶體
        p.stage_with("stats.json", Snapshot::Bytes(vec![4; 1000]), Opts::default(), t + 7 * 3600);
        p.stage_with("cdn/pools.json", Snapshot::Bytes(vec![5; 1000]), Opts::default(), t + 7 * 3600);
        assert_eq!(p.flush(t + 7 * 3600).unwrap(), 1);
        assert!(p.is_pending("stats.json") && !p.is_pending("cdn/pools.json"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
