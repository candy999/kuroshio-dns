//! 系統時間有沒有對時（沒有 RTC 的路由器開機時是 1970 年，NTP 對時之前 TLS 憑證一律驗不過）。
//!
//! 判斷方式：現在時間不早於「建置時間 − 2 天」就算已對時（建置時間由 `build.rs` 寫進執行檔）。
//! 還沒對時的期間：
//! - 解析器只用明文（UDP / TCP）上游，加密上游（DoH / DoT / DoQ / DoH3 / DNSCrypt）暫停不用、也不記失敗；
//!   沒有明文上游時改用備援與最後手段裡的明文上游，讓 DNS（以及 NTP 對時本身）照常運作
//! - 需要 TLS 或正確時間的背景工作延後（排程工作、CDN HTTPS 驗證、DDNS、ACME、社群同步、對外 IP 偵測），
//!   不當成失敗，也不寫進學到的資料
//!
//! 每 30 秒重新檢查；啟動時沒對時記一行、之後對時了再記一行。

use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;
use tracing::{info, warn};

/// 建置時間（Unix 秒）
pub const BUILD_EPOCH: u64 = parse_u64(env!("KUROSHIO_BUILD_EPOCH"));

/// 容許系統時間比建置時間早多久（時區、建置機器時間不準）
pub const GRACE_SECS: u64 = 2 * 86_400;

/// 多久重新檢查一次
pub const CHECK_INTERVAL: Duration = Duration::from_secs(30);

const fn parse_u64(s: &str) -> u64 {
    let b = s.as_bytes();
    let mut i = 0;
    let mut n: u64 = 0;
    while i < b.len() {
        let d = b[i];
        if !d.is_ascii_digit() {
            return 0;
        }
        n = n * 10 + (d - b'0') as u64;
        i += 1;
    }
    n
}

/// 純函式：`now`（Unix 秒）算不算已對時
pub fn synced_at(now: u64, build_epoch: u64) -> bool {
    now.saturating_add(GRACE_SECS) >= build_epoch
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 現在的系統時間算不算已對時（直接看時鐘，不看共用旗標）
pub fn clock_synced() -> bool {
    synced_at(now_secs(), BUILD_EPOCH)
}

/// 目前共用旗標的狀態（解析器、背景工作看這個）
pub fn synced() -> bool {
    kuroshio_net::clock::synced()
}

/// 已經記過的狀態：0 = 還沒記過，1 = 已對時，2 = 沒對時（整個行程只記轉變，重新載入設定不重複記）
static LOGGED: AtomicU8 = AtomicU8::new(0);

/// 要記哪一行日誌
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLine {
    /// 沒對時（啟動時、或時間被調回去）
    Unsynced,
    /// 對時了（之前記過沒對時）
    Synced,
}

/// 純函式：依上次記過的狀態決定要不要記，回傳（要記的行、新的已記狀態）
pub fn log_decision(logged: u8, synced: bool) -> (Option<LogLine>, u8) {
    match (logged, synced) {
        (2, true) => (Some(LogLine::Synced), 1),
        (_, true) => (None, 1),
        (2, false) => (None, 2),
        (_, false) => (Some(LogLine::Unsynced), 2),
    }
}

/// 重新檢查一次：更新共用旗標、需要時記一行。回傳是否已對時
pub fn refresh() -> bool {
    let synced = clock_synced();
    kuroshio_net::clock::set_synced(synced);
    let (line, next) = log_decision(LOGGED.load(Ordering::Relaxed), synced);
    LOGGED.store(next, Ordering::Relaxed);
    match line {
        Some(LogLine::Unsynced) => warn!("系統時間還沒對時（早於這個版本的建置時間），暫時只用明文上游，需要 TLS 的背景工作延後"),
        Some(LogLine::Synced) => info!("系統時間已對時，恢復使用加密上游與背景工作"),
        None => {}
    }
    synced
}

/// 每 30 秒重新檢查（在目前的 tokio 執行環境裡；重新載入設定時跟著那一輪結束）
pub fn spawn_monitor() {
    tokio::spawn(async {
        loop {
            tokio::time::sleep(CHECK_INTERVAL).await;
            refresh();
        }
    });
}

/// 等到系統時間對時（已對時就立刻回來）
pub async fn wait_synced() {
    while !synced() {
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_epoch_is_embedded() {
        const { assert!(BUILD_EPOCH > 1_600_000_000, "build.rs 要寫入建置時間") };
        assert_eq!(parse_u64("1700000000"), 1_700_000_000);
        assert_eq!(parse_u64("x"), 0);
        // 跑測試的機器時間是對的
        assert!(clock_synced());
    }

    #[test]
    fn synced_decision() {
        let build = 1_800_000_000;
        assert!(!synced_at(0, build), "1970 年");
        assert!(!synced_at(86_400 * 365, build));
        assert!(!synced_at(build - GRACE_SECS - 1, build));
        assert!(synced_at(build - GRACE_SECS, build), "容許早 2 天");
        assert!(synced_at(build, build));
        assert!(synced_at(build + 86_400 * 3650, build));
        assert!(synced_at(u64::MAX, build));
    }

    #[test]
    fn logs_only_transitions() {
        // 啟動時已對時：不記
        assert_eq!(log_decision(0, true), (None, 1));
        assert_eq!(log_decision(1, true), (None, 1));
        // 啟動時沒對時：記一次，之後不重複
        assert_eq!(log_decision(0, false), (Some(LogLine::Unsynced), 2));
        assert_eq!(log_decision(2, false), (None, 2));
        // 對時了：記一次
        assert_eq!(log_decision(2, true), (Some(LogLine::Synced), 1));
        // 已對時後時間又被調回去：再記一次
        assert_eq!(log_decision(1, false), (Some(LogLine::Unsynced), 2));
    }
}
