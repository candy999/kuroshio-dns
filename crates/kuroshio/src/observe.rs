//! 觀測（3.5.0 E 組，規格 11 第 5 節）：資料新鮮度（E1）、發現清單（E2）、這台 WAN 的 ISP 群組（E10）。
//!
//! - 全部是拉取式：`/api/status` 被讀時才組出來，不起背景工作、不發對外探測、不寫 Flash。
//! - `warnings`（`integration.rs`）的格式與內容不動；`findings` 是另外一份，同一件事不兩邊都放。
//!
//! 目前是第 5.2 節的骨架：只有簽章，函式回空值，`/api/status` 也還沒有帶出來。第 5.2 節骨架，甲／乙批接上。

use crate::app::AppState;
use kuroshio_jobs::geo::TwIp;
use serde_json::Value;
use std::net::IpAddr;
use std::sync::Arc;

/// `/api/status` 的 `freshness`（E1）：每一種會過期的資料（每日評測、CDN 範圍、網段掃描、節點池、台灣 IP 資料、
/// 過濾清單、路徑檢查、串接同步、好友同步）的上次成功、失敗中、連續失敗、下次預定；固定順序、最多 16 項。
///
/// 第 5.2 節骨架，乙批接上（目前是空陣列）。
pub fn freshness(_st: &AppState) -> Value {
    Value::Array(Vec::new())
}

/// `/api/status` 的 `findings`（E2）：觀察到的現象與它的經過（嚴重度、一句話、次數、第一次與最近一次）；
/// 用 `key` 去重、最多 32 筆、不再發生就過期。兩次評估至少間隔 30 秒，系統時間還沒對時回 `[]`。
///
/// 第 5.2 節骨架，乙批接上（目前是空陣列）。
pub fn findings(_st: &AppState) -> Value {
    Value::Array(Vec::new())
}

/// 這台 WAN 的 ISP 群組（E10，`tw-ip.json` 的群組 `id`，例如 `cht`）：對外 IPv4 的 /24 落在某一群、而且不是 `other`
/// 才有；偵測不到對外 IP、不在任何一群、落在 `other`、台灣 IP 資料讀不到都是 `None`。
/// 要不要送給好友由 `community.shareIspGroup` 決定（呼叫端判斷）。
///
/// 第 5.2 節骨架，乙／丙批接上（目前一律是 `None`）。
pub fn isp_group() -> Option<String> {
    None
}

/// 更新 [`isp_group`] 的來源：對外 IP 的子網路（`Resolver::ecs_subnet`，啟動與 WAN 變動時偵測）與
/// 目前載入的台灣 IP 資料（`Access::data()`）。任一個變動時呼叫一次，群組在這裡重算、存成一個字串。
///
/// 第 5.2 節骨架，乙批接上（目前什麼都不做）。
pub fn set_isp_sources(_wan_subnet: Option<(IpAddr, u8)>, _tw_ip: Option<Arc<TwIp>>) {}
