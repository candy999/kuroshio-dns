//! 串接模式（規格 `docs/spec/10-chain.md`）
//!
//! 兩層黑潮時，下游認出「一般 DNS 被上游黑潮接走」、用節點金鑰驗證身分，把上游當成第一順位上游，
//! 並拿上游的每日評測結果、CDN 節點池、過濾清單副本（共用結果）。上游對登記過的下游放寬存取控制與
//! 「繞過防護」清單。協定的編解碼在 `kuroshio_community::chain`（純函式），這裡是接上解析與排程的部分。
//!
//! - [`ident`]：串接用的節點金鑰（社群共享沒啟用也要能載入同一把）
//! - [`responder`]：上游回應 `chain.kuroshio` 的查詢（auth、reg、共用結果）
//! - [`client`]：下游的狀態機（探測、驗證、心跳、登記）
//! - [`share`]：共用結果（上游的 `ShareCache`、下游的匯入）
//! - [`grants`]：上游給登記中下游的放行（存取控制、繞過防護清單）

pub mod client;
pub mod grants;
pub mod ident;
pub mod responder;
pub mod share;

pub use ident::{key_dir, NodeKey};
pub use responder::Responder;

use std::sync::{Arc, Mutex};

/// 行程層級的下游狀態（跨重新載入；做法同 `app.rs` 的 `CACHE_HANDOFF`）。不存檔、不跨重開機
static CURRENT: Mutex<Option<Arc<client::Client>>> = Mutex::new(None);

/// 目前的下游狀態機（服務還沒啟動過是 None）
pub fn current() -> Option<Arc<client::Client>> {
    CURRENT.lock().unwrap().clone()
}

/// 放進行程層級的持有者（第一次啟動時；之後的重新載入用 [`current`] 接回）
pub fn install(c: Arc<client::Client>) {
    *CURRENT.lock().unwrap() = Some(c);
}

/// 行程層級的共用結果同步（跨重新載入；同 [`CURRENT`]）
static SYNCER: Mutex<Option<Arc<share::Syncer>>> = Mutex::new(None);

/// 目前的共用結果同步（服務還沒啟動過是 None）
pub fn syncer() -> Option<Arc<share::Syncer>> {
    SYNCER.lock().unwrap().clone()
}

/// 放進行程層級的持有者（第一次啟動時）
pub fn install_syncer(s: Arc<share::Syncer>) {
    *SYNCER.lock().unwrap() = Some(s);
}

/// 背景工作開頭呼叫：這個工作的結果由上游黑潮提供（共用結果新鮮、而且現在串接中）→ true，這次不跑。
/// 沒有串接、`chain` 關著、上游不提供資料、共用結果不新鮮 → false（照原本的排程跑，跟 3.3.7 一樣）
pub fn share_skips(job: &str) -> bool {
    syncer().is_some_and(|s| s.skip_job(job))
}

/// 64 位元計數器：32 位元 MIPS（mipsel／mips，例如 MT7621）沒有 `AtomicU64`，所以用鎖包一個 u64，
/// 介面跟 `std::sync::atomic::AtomicU64` 一樣（`Ordering` 參數不用；鎖本身就是完整的同步）。
/// 串接模組的計數器都很少更新（每筆串接查詢最多幾次），鎖的成本可以忽略
#[derive(Debug, Default)]
pub struct AtomicU64(std::sync::Mutex<u64>);

impl AtomicU64 {
    pub const fn new(v: u64) -> AtomicU64 {
        AtomicU64(std::sync::Mutex::new(v))
    }
    fn lock(&self) -> std::sync::MutexGuard<'_, u64> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub fn load(&self, _: std::sync::atomic::Ordering) -> u64 {
        *self.lock()
    }
    pub fn store(&self, v: u64, _: std::sync::atomic::Ordering) {
        *self.lock() = v;
    }
    pub fn fetch_add(&self, v: u64, _: std::sync::atomic::Ordering) -> u64 {
        let mut g = self.lock();
        let old = *g;
        *g = old.wrapping_add(v);
        old
    }
    pub fn swap(&self, v: u64, _: std::sync::atomic::Ordering) -> u64 {
        std::mem::replace(&mut *self.lock(), v)
    }
}
