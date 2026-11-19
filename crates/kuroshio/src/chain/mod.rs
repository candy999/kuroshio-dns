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
