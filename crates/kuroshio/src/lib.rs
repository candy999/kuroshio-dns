//! 黑潮 DNS（Kuroshio DNS）核心。規格見 `docs/spec/`。

pub mod about;
pub mod acl;
pub mod acme;
pub mod admin;
pub mod app;
pub mod backup;
pub mod cache;
pub mod certinfo;
pub mod cloudflare;
pub mod community_bridge;
pub mod compare;
pub mod console;
pub mod ddns;
pub mod dnr;
pub mod encrypted;
pub mod filtering;
pub mod httpsys;
pub mod iiscert;
pub mod logring;
pub mod netif;
pub mod persist;
pub mod presence;
pub mod resolver;
pub mod server;
pub mod site;
pub mod stats;
pub mod sysinfo;
pub mod upstreams;
pub mod webui;
pub mod winsetup;

// 網路層搬到 kuroshio-net；保留原本的路徑（kuroshio::upstream 等）
pub use kuroshio_net::{fetch, iprank, tls, upstream};
