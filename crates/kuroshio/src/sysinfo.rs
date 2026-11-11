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
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        std::arch::is_x86_feature_detected!("aes")
    }
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("aes")
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
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

/// 把配置器手上空著的記憶體還給系統（記憶體控制釋出之後呼叫）。只有 glibc 需要（musl 釋放大塊時會直接還）
pub fn trim_heap() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    // SAFETY: malloc_trim 只整理配置器自己的空閒區塊
    unsafe {
        libc::malloc_trim(0);
    }
}

/// 系統實體記憶體與可用記憶體（bytes）。Linux：/proc/meminfo；Windows：GlobalMemoryStatusEx
pub fn mem_bytes() -> (Option<u64>, Option<u64>) {
    #[cfg(windows)]
    {
        win::mem()
    }
    #[cfg(not(windows))]
    {
        match std::fs::read_to_string("/proc/meminfo") {
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
        }
    }
}

#[cfg(windows)]
mod win {
    use windows_sys::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

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

/// 讀 /proc/meminfo：(MemTotal, MemAvailable)，單位 MB
pub fn meminfo() -> (Option<u64>, Option<u64>) {
    match std::fs::read_to_string("/proc/meminfo") {
        Ok(t) => parse_meminfo(&t),
        Err(_) => (None, None),
    }
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

    #[test]
    fn meminfo() {
        let (t, a) = parse_meminfo("MemTotal:         123456 kB\nMemFree:  1 kB\nMemAvailable:      61440 kB\n");
        assert_eq!((t, a), (Some(120), Some(60)));
    }
}
