//! 線路感知（3.5.0 E 組，規格 11 第 5 節）：這條線到得了哪些台灣機房（E3）、機房以本機量到的為準（E4）、
//! 機房層級的健康與切換（E5），以及給主程式觀測用的計數（E2 讀、E7 累加）。
//!
//! 機房是「IP × 這條線路」量出來的，不是 IP 的屬性：別人量到的機房只當參考，這台用的一律是自己量到的。
//! 這裡不新增背景工作、不新增對外探測，也不碰查詢路徑；狀態都在記憶體，不寫 Flash。
//!
//! 目前是第 5.2 節的骨架：只有簽章，函式回空值，行為跟沒有這個檔時一樣。第 5.2 節骨架，甲／乙批接上。

use crate::cdn::{Cdn, FRIEND_MAX_NODES};
use serde_json::{Map, Value};
use std::net::IpAddr;

/// 給主程式的發現清單（E2）讀的計數：都是啟動後的累計值（`u32`，飽和；32 位元 MIPS 沒有 64 位元原子操作），
/// 時間是 Unix 秒（`u32`；0 = 還沒發生）。E2 用「計數的增加量」算次數，所以沒人開狀態頁的那幾天也是對的。
///
/// 第 5.2 節骨架，甲／乙批接上（目前一律是 0）。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ObserveCounters {
    /// 台灣節點驗證通過／失敗的次數（E2 的 `cdn-verify-fail-high`；在 `verifier.rs` 的 `done()` 累加）
    pub verify_ok: u32,
    pub verify_fail: u32,
    /// 上游給的節點，本機量到的機房一樣／不一樣的次數（E4）與最近一次不一樣的時間
    pub pop_confirmed: u32,
    pub pop_mismatch: u32,
    pub pop_mismatch_at: u32,
    /// 機房串接中抽查的次數（E4，一天最多 24 個）
    pub pop_probes: u32,
    /// 機房切換（暫緩）發生的次數與最近一次的時間（E5 的 `pop-switched`）
    pub pop_switches: u32,
    pub pop_switch_at: u32,
    /// 想切換但已經達到每日上限、沒有切的次數與最近一次的時間（E5 的 `pop-flapping`）
    pub pop_flapping: u32,
    pub pop_flapping_at: u32,
    /// 因為台灣節點實測比原本慢、暫時用原本答案的次數與最近一次的時間（E7 的 `slower-fallback`）
    pub slower_fallback: u32,
    pub slower_fallback_at: u32,
    /// E7 的保險絲跳到幾點（Unix 秒；0 = 沒跳）
    pub slower_fuse_until: u32,
}

impl Cdn {
    /// WAN 變動（`/api/notify/wan-changed`）：`wanEpoch` 加 1、`reach` 標成過期、清掉 E5 的連續計數與暫緩。
    /// 不因此補跑健檢或掃描，等下一輪定時健檢自然更新（E3）。
    ///
    /// 第 5.2 節骨架，甲／乙批接上（目前什麼都不做）。
    pub fn on_wan_changed(&self) {}

    /// `/api/status` 的 `cdn` 多帶的觀測欄位：`reach`、`popHealth`、`popSwitch`、`popAudit`、`slowerFuseUntil`
    /// （E3～E5、E7）。在背景工作結束時算好，這裡只複製一份小 JSON。
    ///
    /// 第 5.2 節骨架，甲／乙批接上（目前是空物件）。
    pub fn observe_json(&self) -> Value {
        Value::Object(Map::new())
    }

    /// E2 用的計數與最近時間（見 [`ObserveCounters`]）。
    ///
    /// 第 5.2 節骨架，甲／乙批接上（目前一律是 0）。
    pub fn observe_counters(&self) -> ObserveCounters {
        ObserveCounters::default()
    }

    /// 串接中的機房抽查（E4）：這個 IP 是節點池裡上游宣稱機房（`upPop`）還沒確認的節點、而且還有抽查名額時，
    /// 回那家 CDN 的名稱；呼叫端用同一個抽查名額對它做一次機房探測，結果交給 [`Cdn::note_local_pop`]。
    ///
    /// 第 5.2 節骨架，甲／乙批接上（目前一律不抽查）。
    pub fn pop_audit_wanted(&self, _ip: IpAddr) -> Option<&'static str> {
        None
    }

    /// 本機量到某個節點的機房（E4）：跟上游宣稱的比對，一樣就確認、不一樣就以本機為準並計數。
    ///
    /// 第 5.2 節骨架，甲／乙批接上（目前什麼都不做）。
    pub fn note_local_pop(&self, _provider: &str, _ip: IpAddr, _pop: &str) {}

    /// 同 [`Cdn::add_friend_nodes`]，但每家、每個家族一次最多 `per_batch` 個（E10：確定是別的 ISP 群組的好友降成四分之一）。
    /// 只會變少、不會變多：超過 [`FRIEND_MAX_NODES`] 的照 [`FRIEND_MAX_NODES`] 算；候選名單的總上限不變。
    /// 回傳新增幾個。
    pub fn add_friend_nodes_capped<'a>(&self, nodes: impl IntoIterator<Item = (&'a str, IpAddr)>, per_batch: usize) -> usize {
        self.add_friend_nodes_upto(nodes, per_batch.min(FRIEND_MAX_NODES))
    }
}
