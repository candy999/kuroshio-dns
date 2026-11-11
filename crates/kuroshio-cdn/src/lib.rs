//! 黑潮 DNS 的 CDN 台灣節點（對齊 2.x `lib/cdn/*` 與 `jobs/cdn-*.js`）。
//!
//! - `Cdn`：網域資料庫、節點池、永久 IPv6 節點都在記憶體裡（一把鎖），`apply()` 在回應前改寫答案；
//!   需要網路的驗證、ECS 突破、跨 CDN 探索、IPv6 即時發現都排到背景（tokio task，依設定限制同時數）。
//! - 狀態檔格式跟 2.x 相同（`state/cdn/pools.json` 等），不認識的欄位原封保留。
//!   常變動的狀態不自己定時寫檔：外層用 `snapshots()` 取出有變動的內容，交給快照寫入器（規格 05 第 5 節）。
//! - 背景工作（CDN 範圍、網段分類、節點池）在 `jobs`，由外層排程。
//! - 所有網路操作都經過 `net::Net`，正式環境用 `RealNet`，測試換成假的。

pub mod cdn;
pub mod cidr;
pub mod config;
pub mod cross;
pub mod db;
pub mod ecs;
mod health;
pub mod jobs;
pub mod net;
pub mod optimizer;
pub mod pools;
pub mod providers;
pub mod statefile;
pub mod svcb;
pub mod util;
pub mod v6store;
pub mod verifier;

#[cfg(test)]
mod tests;

pub use cdn::{Cdn, CrossHint, HintIp, Hints, Paths, Stats, Task};
pub use config::CdnConfig;
pub use net::{Net, RealNet};
pub use optimizer::{ApplyResult, Baseline, Rewrite};
pub use pools::{Class, Cls};
