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

/// 串接中：CDN 節點由上游黑潮處理（下游不改寫、不驗證、不做 CDN 的定時檢查；3.4.2）
pub fn cdn_by_upstream() -> bool {
    current().is_some_and(|c| c.is_chained())
}

/// 開機後還不知道會不會串接：`chain` 開著，而且第一次路徑檢查還沒做完、或正在驗證上游黑潮。
/// CDN 的定時檢查先等這段過去（3.4.2：以前開機 20 秒就做節點健康檢查，串接還沒建立，
/// Windows 實測串接中重啟一分鐘內連了約 800 個 CDN 節點）
pub fn deciding() -> bool {
    let Some(c) = current() else { return false };
    c.downstream_enabled()
        && (kuroshio_net::path::current().is_none() || matches!(c.state().0, client::State::Detected | client::State::Verifying))
}

/// 正在等第一次跟上游黑潮同步共用結果：正在驗證上游黑潮，或已經串接（上游有提供共用結果）但還沒同步完成過。
/// 過濾清單在這段期間不從網路下載（3.4.2）
pub fn share_pending() -> bool {
    let Some(c) = current() else { return false };
    match c.state().0 {
        client::State::Detected | client::State::Verifying => true,
        client::State::Chained => {
            c.last_probe().is_some_and(|p| p.caps.iter().any(|x| x == "share")) && syncer().is_some_and(|s| s.never_synced())
        }
        _ => false,
    }
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
