//! 硬體偵測（規格 05）：記憶體、CPU、儲存類型（沒有硬體等級：大小由記憶體控制動態決定，規格 09）

use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct SysInfo {
    /// 實體記憶體（MB）；偵測不到是 None
    pub mem_total_mb: Option<u64>,
    pub mem_available_mb: Option<u64>,
    pub cores: usize,
    pub arch: &'static str,
    /// CPU 有沒有 AES 指令（沒有的話 TLS 優先用 ChaCha20）
    pub aes: bool,
}

impl SysInfo {
    pub fn detect() -> SysInfo {
        let (total, avail) = meminfo();
        SysInfo {
            mem_total_mb: total,
            mem_available_mb: avail,
            cores: std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
            arch: std::env::consts::ARCH,
            aes: has_aes(),
        }
    }

    /// tokio 工作執行緒數：單核心用單執行緒 runtime（回傳 1），多核心最多 4
    pub fn worker_threads(&self, configured: u64) -> usize {
        if configured > 0 {
            return configured as usize;
        }
        self.cores.clamp(1, 4)
    }
}

fn has_aes() -> bool {
    kuroshio_config::has_aes()
}

/// 自己的常駐記憶體（KB，/proc/self/status 的 VmRSS）
pub fn rss_kb() -> Option<u64> {
    let t = std::fs::read_to_string("/proc/self/status").ok()?;
    t.lines().find(|l| l.starts_with("VmRSS:"))?.split_whitespace().nth(1)?.parse().ok()
}

/// 自己的常駐記憶體（bytes）。Linux：/proc/self/statm 的第二欄 × 頁大小；Windows：GetProcessMemoryInfo 的 WorkingSetSize
pub fn rss_bytes() -> Option<u64> {
    #[cfg(windows)]
    {
        win::rss()
    }
    #[cfg(unix)]
    {
        let t = std::fs::read_to_string("/proc/self/statm").ok()?;
        let pages: u64 = t.split_whitespace().nth(1)?.parse().ok()?;
        // SAFETY: sysconf 只讀系統設定
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        Some(pages * if page > 0 { page as u64 } else { 4096 })
    }
    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}

/// 這個程式開機以來用掉的 CPU 時間（使用者＋核心，毫秒；3.5.0 F12，規格 11 第 6 節）。
/// Linux：/proc/self/stat 的 utime＋stime（時脈數換成毫秒）；Windows：GetProcessTimes。量不到是 None。
/// 呼叫端每 10 秒量一次、兩次相減，除以（經過的時間 × 核心數）就是佔整台機器的比例。
/// 規格 11 第 6.2 節骨架：乙批（主程式每 10 秒量一次、交給 `Cdn::set_load()`）接上
pub fn cpu_ms() -> Option<u64> {
    #[cfg(windows)]
    {
        win::cpu_ms()
    }
    #[cfg(unix)]
    {
        let t = std::fs::read_to_string("/proc/self/stat").ok()?;
        // SAFETY: sysconf 只讀系統設定
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        parse_proc_stat_cpu_ms(&t, if hz > 0 { hz as u64 } else { 100 })
    }
    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}

/// 這台黑潮自己用掉的 CPU 佔整台機器的百分比（3.5.0 F12）：兩次 [`cpu_ms`] 之差 ÷（經過的時間 × 核心數）。
/// 量不到、時間沒有前進、計數倒退時是 None；最多 100
pub fn cpu_pct(prev_cpu_ms: u64, now_cpu_ms: u64, wall_ms: u64, cores: usize) -> Option<u8> {
    if wall_ms == 0 || cores == 0 || now_cpu_ms < prev_cpu_ms {
        return None;
    }
    let used = (now_cpu_ms - prev_cpu_ms) as u128 * 100;
    let total = wall_ms as u128 * cores as u128;
    Some(((used + total / 2) / total).min(100) as u8)
}

/// 每 10 秒量一次自己的 CPU 用量（3.5.0 F12；放在記憶體監看的迴圈裡，不另外開背景工作）
#[derive(Debug)]
pub struct CpuMeter {
    cores: usize,
    last: Option<(u64, std::time::Instant)>,
    next: Option<std::time::Instant>,
}

/// 量 CPU 的間隔
pub const CPU_SAMPLE_SECS: u64 = 10;

impl CpuMeter {
    pub fn new(cores: usize) -> CpuMeter {
        CpuMeter {
            cores,
            last: None,
            next: None,
        }
    }

    /// 到了要量的時候回 `Some(這 10 秒的百分比)`（量不到是 `Some(None)`），還沒到回 `None`。
    /// `cpu` 是這一刻的 [`cpu_ms`]（呼叫端傳進來，測試可以注入）
    pub fn tick(&mut self, now: std::time::Instant, cpu: impl FnOnce() -> Option<u64>) -> Option<Option<u8>> {
        if self.next.is_some_and(|t| now < t) {
            return None;
        }
        self.next = Some(now + std::time::Duration::from_secs(CPU_SAMPLE_SECS));
        let cur = cpu();
        let pct = match (self.last, cur) {
            (Some((p, t)), Some(c)) => cpu_pct(p, c, now.saturating_duration_since(t).as_millis() as u64, self.cores),
            _ => None,
        };
        let first = self.last.is_none();
        self.last = cur.map(|c| (c, now));
        // 第一次只記起點（還沒有區間可以算），不回報
        if first && cur.is_some() {
            return None;
        }
        Some(pct)
    }
}

/// /proc/self/stat 的 utime＋stime（第 14、15 欄，單位是時脈數）換成毫秒。
/// 第 2 欄（程式名稱）在括號裡、可能有空白，從最後一個右括號之後開始數
pub fn parse_proc_stat_cpu_ms(stat: &str, hz: u64) -> Option<u64> {
    let rest = &stat[stat.rfind(')')? + 1..];
    let mut f = rest.split_whitespace();
    // 右括號之後第 1 個是第 3 欄（state），utime 是第 14 欄
    let utime: u64 = f.nth(11)?.parse().ok()?;
    let stime: u64 = f.next()?.parse().ok()?;
    Some((utime + stime).saturating_mul(1000) / hz.max(1))
}

/// 把配置器手上空著的記憶體還給系統（記憶體控制釋出之後呼叫）。只有 glibc 需要（musl 釋放大塊時會直接還）
pub fn trim_heap() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    // SAFETY: malloc_trim 只整理配置器自己的空閒區塊
    unsafe {
        libc::malloc_trim(0);
    }
}

/// 系統實體記憶體與可用記憶體（bytes）。Linux：/proc/meminfo；Windows：GlobalMemoryStatusEx。
///
/// Linux 上黑潮在有記憶體上限的 cgroup 裡（韌體用 cgroup 限制它、Docker 的 `--memory`）、而且上限比實體記憶體小時，
/// 用 cgroup 的上限當「實體記憶體」、上限 − 已用（扣掉可以回收的檔案快取）當「可用」，取兩者較小的（3.5.1 N2）。
/// 以前只看整台機器：韌體把上限設得比黑潮自己的判斷低時（D3 實測 150 MB），黑潮一直長到被核心砍，不會先讓出
pub fn mem_bytes() -> (Option<u64>, Option<u64>) {
    #[cfg(windows)]
    {
        win::mem()
    }
    #[cfg(not(windows))]
    {
        let (total, avail) = match std::fs::read_to_string("/proc/meminfo") {
            Ok(t) => {
                let field = |name: &str| {
                    t.lines()
                        .find(|l| l.starts_with(name))
                        .and_then(|l| l.split_whitespace().nth(1))
                        .and_then(|kb| kb.parse::<u64>().ok())
                        .map(|kb| kb * 1024)
                };
                (field("MemTotal:"), field("MemAvailable:"))
            }
            Err(_) => (None, None),
        };
        #[cfg(target_os = "linux")]
        {
            apply_cgroup(total, avail, cgroup::read())
        }
        #[cfg(not(target_os = "linux"))]
        {
            (total, avail)
        }
    }
}

/// 套用 cgroup 的上限（`cg` =（上限，已用）；沒有上限是 None）：上限比實體記憶體小時，實體記憶體 = 上限、
/// 可用 = min(系統可用, 上限 − 已用)
pub fn apply_cgroup(total: Option<u64>, avail: Option<u64>, cg: Option<(u64, u64)>) -> (Option<u64>, Option<u64>) {
    let Some((limit, used)) = cg else {
        return (total, avail);
    };
    if total.is_some_and(|t| limit >= t) {
        return (total, avail);
    }
    let room = limit.saturating_sub(used);
    (Some(limit), Some(avail.map_or(room, |a| a.min(room))))
}

/// 自己所在的記憶體 cgroup（v1 `memory` 控制器、v2 統一階層）的上限與已用（3.5.1 N2）
#[cfg(target_os = "linux")]
pub mod cgroup {
    /// 上限比這個大當成「沒有上限」（v1 沒設時是 2^63 附近的值、v2 是 `max`）
    const UNLIMITED: u64 = 1 << 60;

    /// `/proc/self/cgroup` 的內容 → （v1 memory 的路徑，v2 的路徑）
    pub fn paths(text: &str) -> (Option<String>, Option<String>) {
        let mut v1 = None;
        let mut v2 = None;
        for l in text.lines() {
            let mut it = l.splitn(3, ':');
            let (Some(_), Some(ctrl), Some(path)) = (it.next(), it.next(), it.next()) else {
                continue;
            };
            if ctrl.is_empty() {
                v2 = Some(path.to_string());
            } else if ctrl.split(',').any(|c| c == "memory") {
                v1 = Some(path.to_string());
            }
        }
        (v1, v2)
    }

    /// `memory.stat` 裡某一欄的值
    pub fn stat_field(stat: &str, key: &str) -> Option<u64> {
        stat.lines().find_map(|l| {
            let (k, v) = l.split_once(' ')?;
            (k == key).then(|| v.trim().parse().ok()).flatten()
        })
    }

    /// （上限，已用 − 可以回收的檔案快取）；沒有上限、讀不到時 None
    pub fn from_files(limit: &str, usage: &str, stat: Option<&str>, inactive_key: &str) -> Option<(u64, u64)> {
        let limit: u64 = limit.trim().parse().ok()?;
        if limit >= UNLIMITED {
            return None;
        }
        let usage: u64 = usage.trim().parse().ok()?;
        let inactive = stat.and_then(|s| stat_field(s, inactive_key)).unwrap_or(0);
        Some((limit, usage.saturating_sub(inactive)))
    }

    pub fn read() -> Option<(u64, u64)> {
        let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
        let (v1, v2) = paths(&text);
        let rd = |p: String| std::fs::read_to_string(p).ok();
        if let Some(p) = v1 {
            let base = format!("/sys/fs/cgroup/memory{}", p.trim_end_matches('/'));
            if let (Some(l), Some(u)) = (
                rd(format!("{base}/memory.limit_in_bytes")),
                rd(format!("{base}/memory.usage_in_bytes")),
            ) {
                return from_files(&l, &u, rd(format!("{base}/memory.stat")).as_deref(), "total_inactive_file");
            }
        }
        if let Some(p) = v2 {
            let base = format!("/sys/fs/cgroup{}", p.trim_end_matches('/'));
            let l = rd(format!("{base}/memory.max"))?;
            if l.trim() == "max" {
                return None;
            }
            let u = rd(format!("{base}/memory.current"))?;
            return from_files(&l, &u, rd(format!("{base}/memory.stat")).as_deref(), "inactive_file");
        }
        None
    }
}

#[cfg(windows)]
mod win {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};

    pub fn rss() -> Option<u64> {
        // SAFETY: 結構由我們配置、大小正確；GetCurrentProcess 是虛擬代碼，不用關閉
        unsafe {
            let mut c: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
            c.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
            if K32GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) != 0 {
                Some(c.WorkingSetSize as u64)
            } else {
                None
            }
        }
    }

    /// 使用者＋核心 CPU 時間（毫秒）。FILETIME 的單位是 100 奈秒
    pub fn cpu_ms() -> Option<u64> {
        let v = |t: &FILETIME| (((t.dwHighDateTime as u64) << 32) | t.dwLowDateTime as u64) / 10_000;
        // SAFETY: 四個 FILETIME 由我們配置；GetCurrentProcess 是虛擬代碼，不用關閉
        unsafe {
            let mut c: FILETIME = std::mem::zeroed();
            let mut e: FILETIME = std::mem::zeroed();
            let mut k: FILETIME = std::mem::zeroed();
            let mut u: FILETIME = std::mem::zeroed();
            if GetProcessTimes(GetCurrentProcess(), &mut c, &mut e, &mut k, &mut u) != 0 {
                Some(v(&k) + v(&u))
            } else {
                None
            }
        }
    }

    pub fn mem() -> (Option<u64>, Option<u64>) {
        // SAFETY: 結構由我們配置、dwLength 已設定
        unsafe {
            let mut m: MEMORYSTATUSEX = std::mem::zeroed();
            m.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
            if GlobalMemoryStatusEx(&mut m) != 0 {
                (Some(m.ullTotalPhys), Some(m.ullAvailPhys))
            } else {
                (None, None)
            }
        }
    }
}

/// 實體記憶體與可用記憶體（MB）：Linux 讀 /proc/meminfo，Windows 用 GlobalMemoryStatusEx（[`mem_bytes`]）
pub fn meminfo() -> (Option<u64>, Option<u64>) {
    let (total, avail) = mem_bytes();
    (total.map(|b| b >> 20), avail.map(|b| b >> 20))
}

pub fn parse_meminfo(text: &str) -> (Option<u64>, Option<u64>) {
    let field = |name: &str| {
        text.lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|kb| kb.parse::<u64>().ok())
            .map(|kb| kb / 1024)
    };
    (field("MemTotal:"), field("MemAvailable:"))
}

/// 儲存類型（規格 05 第 5.4 節）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageClass {
    /// tmpfs：不傷 Flash，但重開機就沒了
    Ram,
    /// jffs2 / ubifs / overlay / SD 卡 / eMMC：寫入要節制
    Flash,
    /// 硬碟、SSD、Windows
    Disk,
}

impl StorageClass {
    pub fn name(self) -> &'static str {
        match self {
            StorageClass::Ram => "ram",
            StorageClass::Flash => "flash",
            StorageClass::Disk => "disk",
        }
    }
    pub fn parse(s: &str) -> Option<StorageClass> {
        match s.trim().to_ascii_lowercase().as_str() {
            "ram" => Some(StorageClass::Ram),
            "flash" => Some(StorageClass::Flash),
            "disk" => Some(StorageClass::Disk),
            _ => None,
        }
    }
}

/// 判定某個路徑所在的儲存類型
pub fn storage_class(path: &Path) -> StorageClass {
    if cfg!(windows) {
        return StorageClass::Disk;
    }
    match std::fs::read_to_string("/proc/mounts") {
        Ok(m) => classify_path(&m, &existing_ancestor(path)),
        Err(_) => StorageClass::Disk,
    }
}

fn existing_ancestor(p: &Path) -> PathBuf {
    let mut cur = p.to_path_buf();
    while !cur.exists() {
        if !cur.pop() {
            return PathBuf::from("/");
        }
    }
    cur.canonicalize().unwrap_or(cur)
}

/// 由 /proc/mounts 的內容判定（方便測試）
pub fn classify_path(mounts: &str, path: &Path) -> StorageClass {
    let p = path.to_string_lossy();
    // 找出包含這個路徑、最長的掛載點
    let best = mounts
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            Some((it.next()?, it.next()?, it.next()?))
        })
        .filter(|(_, mp, _)| *mp == "/" || p == *mp || p.starts_with(&format!("{mp}/")))
        .max_by_key(|(_, mp, _)| mp.len());
    match best {
        Some((dev, _, fs)) => classify_fs(dev, fs),
        None => StorageClass::Disk,
    }
}

pub fn classify_fs(dev: &str, fs: &str) -> StorageClass {
    match fs {
        "tmpfs" | "ramfs" => StorageClass::Ram,
        "jffs2" | "ubifs" | "squashfs" | "overlay" | "overlayfs" => StorageClass::Flash,
        _ if dev.contains("mtd") || dev.contains("ubi") || dev.contains("mmcblk") => StorageClass::Flash,
        _ => StorageClass::Disk,
    }
}

/// 記憶體壓力（規格 09：依系統保留量判斷，見 `memgov::pressure_of`）
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Pressure {
    Normal = 0,
    /// 接近保留量（保留量 + 遲滯以內）：背景工作延後、記憶體結構不再長大
    Low = 1,
    /// 低於保留量的一半：快照立刻寫出、暫不接受新的加密連線（明文 DNS 照常回答）
    Critical = 2,
}

impl Pressure {
    /// `/api/status` 的 `memory.pressure`
    pub fn as_str(self) -> &'static str {
        match self {
            Pressure::Normal => "normal",
            Pressure::Low => "low",
            Pressure::Critical => "critical",
        }
    }
}

#[cfg(test)]
mod cgroup_tests {
    use super::*;

    const MB: u64 = 1 << 20;

    #[test]
    fn cgroup_limit_replaces_total_when_smaller() {
        // 3.5.1 N2：韌體把黑潮放進 150 MB 的 cgroup（D3 437 MB）：實體記憶體當 150 MB、可用 = 上限 − 已用
        let (t, a) = apply_cgroup(Some(437 * MB), Some(300 * MB), Some((150 * MB, 120 * MB)));
        assert_eq!((t, a), (Some(150 * MB), Some(30 * MB)));
        // 系統可用比 cgroup 剩的還少：取小的
        assert_eq!(
            apply_cgroup(Some(437 * MB), Some(10 * MB), Some((150 * MB, 20 * MB))).1,
            Some(10 * MB)
        );
        // 上限比實體記憶體大（80% 以上也一樣是上限，這裡 500 > 437）：照舊
        assert_eq!(
            apply_cgroup(Some(437 * MB), Some(300 * MB), Some((500 * MB, 100 * MB))),
            (Some(437 * MB), Some(300 * MB))
        );
        assert_eq!(apply_cgroup(Some(437 * MB), Some(300 * MB), None), (Some(437 * MB), Some(300 * MB)));
        // 用完了：可用 0
        assert_eq!(apply_cgroup(Some(437 * MB), Some(300 * MB), Some((150 * MB, 160 * MB))).1, Some(0));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cgroup_files_parse() {
        use super::cgroup::*;
        // padavan-tw（v1）：memory 控制器的那一行
        let (v1, v2) = paths("4:memory:/kuroshio\n3:cpu,cpuacct:/\n");
        assert_eq!((v1.as_deref(), v2), (Some("/kuroshio"), None));
        let (v1, v2) = paths("0::/system.slice/kuroshio.service\n");
        assert_eq!((v1, v2.as_deref()), (None, Some("/system.slice/kuroshio.service")));
        // 可以回收的檔案快取不算已用（黑潮寫檔的頁快取也算在 cgroup 裡）
        let stat = "cache 1000\ntotal_inactive_file 4194304\nrss 5\n";
        assert_eq!(
            from_files("157286400\n", "125829120\n", Some(stat), "total_inactive_file"),
            Some((150 * MB, 116 * MB))
        );
        assert_eq!(
            from_files("9223372036854771712", "1", None, "total_inactive_file"),
            None,
            "v1 沒設上限"
        );
        assert_eq!(stat_field("anon 1\ninactive_file 2048\n", "inactive_file"), Some(2048));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPENWRT_MOUNTS: &str = "\
/dev/root /rom squashfs ro,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,noatime 0 0
tmpfs /tmp tmpfs rw,nosuid,nodev,noatime 0 0
/dev/ubi0_1 /overlay ubifs rw,noatime 0 0
overlayfs:/overlay / overlay rw,noatime,lowerdir=/,upperdir=/overlay/upper 0 0
/dev/sda1 /mnt/usb ext4 rw,relatime 0 0
";

    #[test]
    fn storage_classes() {
        assert_eq!(classify_path(OPENWRT_MOUNTS, Path::new("/etc/kuroshio/state")), StorageClass::Flash);
        assert_eq!(classify_path(OPENWRT_MOUNTS, Path::new("/tmp/kuroshio")), StorageClass::Ram);
        assert_eq!(classify_path(OPENWRT_MOUNTS, Path::new("/mnt/usb/kuroshio")), StorageClass::Disk);
        assert_eq!(
            classify_path(OPENWRT_MOUNTS, Path::new("/tmpx")),
            StorageClass::Flash,
            "/tmpx 不在 /tmp 底下"
        );
        assert_eq!(classify_fs("/dev/mmcblk0p2", "ext4"), StorageClass::Flash);
        assert_eq!(classify_fs("/dev/nvme0n1p2", "ext4"), StorageClass::Disk);
        assert_eq!(classify_fs("/dev/mtdblock6", "jffs2"), StorageClass::Flash);
    }

    /// 3.5.0 F12：CPU 百分比 = 用掉的 CPU 時間 ÷（經過的時間 × 核心數），四捨五入、最多 100；量不到不調
    #[test]
    fn cpu_pct_of_whole_machine() {
        // 2 核心、10 秒：用掉 11 秒 CPU = 55%
        assert_eq!(cpu_pct(1000, 12_000, 10_000, 2), Some(55));
        assert_eq!(cpu_pct(0, 6_000, 10_000, 2), Some(30));
        assert_eq!(cpu_pct(0, 50_000, 10_000, 2), Some(100), "最多 100");
        assert_eq!(cpu_pct(5, 4, 10_000, 2), None, "計數倒退");
        assert_eq!(cpu_pct(0, 1, 0, 2), None);
        assert_eq!(cpu_pct(0, 1, 10, 0), None);
        // 每 10 秒量一次；第一次只記起點；量不到時回 Some(None)（不調）
        let t0 = std::time::Instant::now();
        let mut m = CpuMeter::new(2);
        assert_eq!(m.tick(t0, || Some(0)), None, "第一次只記起點");
        assert_eq!(m.tick(t0 + std::time::Duration::from_secs(5), || Some(1)), None, "還沒到 10 秒");
        assert_eq!(m.tick(t0 + std::time::Duration::from_secs(10), || Some(11_000)), Some(Some(55)));
        assert_eq!(m.tick(t0 + std::time::Duration::from_secs(20), || None), Some(None), "量不到");
        assert_eq!(
            m.tick(t0 + std::time::Duration::from_secs(30), || Some(20_000)),
            None,
            "上一次量不到：重新記起點"
        );
        assert_eq!(m.tick(t0 + std::time::Duration::from_secs(40), || Some(26_000)), Some(Some(30)));
    }

    /// 3.5.0 F12：/proc/self/stat 的 utime＋stime；程式名稱裡有空白與括號也數得對
    #[test]
    fn proc_stat_cpu_ms() {
        let stat = "1234 (kuro shio (x)) S 1 1234 1234 0 -1 4194560 500 0 0 0 250 50 0 0 20 0 4 0 100 0 0";
        assert_eq!(parse_proc_stat_cpu_ms(stat, 100), Some(3000), "(250 + 50) 個時脈、每秒 100");
        assert_eq!(parse_proc_stat_cpu_ms(stat, 1000), Some(300));
        assert_eq!(parse_proc_stat_cpu_ms("garbage", 100), None);
        assert_eq!(parse_proc_stat_cpu_ms("1 (a) S 1 2", 100), None);
        #[cfg(target_os = "linux")]
        assert!(cpu_ms().is_some());
    }

    #[test]
    fn meminfo() {
        let (t, a) = parse_meminfo("MemTotal:         123456 kB\nMemFree:  1 kB\nMemAvailable:      61440 kB\n");
        assert_eq!((t, a), (Some(120), Some(60)));
    }
}
