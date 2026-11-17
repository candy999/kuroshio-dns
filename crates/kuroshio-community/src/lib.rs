//! 黑潮 DNS 社群共享協定 v2（規格 `docs/spec/03-community-v2.md`）
//!
//! 好友之間交換 CDN 台灣節點、網站驗證結果、跨 CDN 結果、上游 DNS。
//! - 身分 = 網域 + Ed25519 金鑰（PKCS#8，沿用 2.x 的 key.pem），金鑰從 TLS 驗證過的身分文件取得
//! - 信封：CBOR，簽原始 body 位元組；sync 回應 zstd 壓縮
//! - 三種管道：HTTPS、TLS（ALPN `kuroshio/2`）、QUIC（ALPN `kuroshio/2`）
//! - 好友狀態沿用 v1；資料品質分數取代違規次數；增量同步 + poke
//!
//! 模組本身不寫 state、不開埠：整合端負責掛上處理函式（[`Community::handle_http`]、
//! [`Community::serve_stream`]、[`Community::serve_quic`]）、定時呼叫 [`Community::tick`]、
//! 把 [`Community::snapshots`] 寫回 state，並實作 [`DataProvider`] 接上 CDN 與評測模組。

pub mod admin;
pub mod client;
pub mod config;
pub mod envelope;
pub mod identity;
pub mod invite;
pub mod limits;
pub mod node;
pub mod peers;
pub mod provider;
pub mod rules;
pub mod score;
pub mod share;
pub mod transport;
pub mod util;

/// 寫完設定類檔案（金鑰、身分、邀請）後要通知的對象：主程式在啟動時設成「排一次寫入設定後的外部指令」
/// （KUROSHIO_ON_CONFIG_WRITE），第三方韌體才會把金鑰存進 Flash
static ON_WRITE: std::sync::OnceLock<fn(&std::path::Path)> = std::sync::OnceLock::new();

/// 設定寫檔後的通知（只能設一次）
pub fn set_on_write(f: fn(&std::path::Path)) {
    let _ = ON_WRITE.set(f);
}

pub(crate) fn notify_written(path: &std::path::Path) {
    if let Some(f) = ON_WRITE.get() {
        f(path);
    }
}

pub use client::Hint;
pub use config::{Config, Tuning};
pub use envelope::{ALPN, BASE_PATH};
pub use node::{Community, Options, PeerIdentity};
pub use provider::{
    CrossHint, DataProvider, LocalRecord, NoData, NodeCandidate, PublicResolver, RangeCheck, Received, Resolver, SiteHint, StaticResolver,
    UpstreamCandidate,
};
pub use score::{Kind, Outcome};
pub use transport::{Endpoint, Scheme};
