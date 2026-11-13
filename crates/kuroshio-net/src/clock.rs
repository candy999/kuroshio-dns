//! 系統時間有沒有對時（整個程式共用的旗標）。
//!
//! 沒有 RTC 的路由器開機時是 1970 年，NTP 對時之前驗不過任何 TLS 憑證，用牆上時間記下的資料也是錯的。
//! 判斷由核心（`kuroshio::clock`，依建置時間）負責並呼叫 [`set_synced`]；這裡只放旗標，
//! 讓 CDN、社群等其他 crate 也看得到。沒人設定時一律當成已對時（測試、指令列工具不受影響）。

use std::sync::atomic::{AtomicBool, Ordering};

static UNSYNCED: AtomicBool = AtomicBool::new(false);

/// 系統時間是否已對時（沒人設定過 = 已對時）
pub fn synced() -> bool {
    !UNSYNCED.load(Ordering::Relaxed)
}

/// 設定目前的對時狀態，回傳之前的狀態
pub fn set_synced(synced: bool) -> bool {
    !UNSYNCED.swap(!synced, Ordering::Relaxed)
}
