//! 黑潮 DNS 網路層：上游傳輸（UDP / TCP / DoT / DoH）、TLS 與 bootstrap、檔案下載、IP 測速。
//! 核心（`kuroshio`）、CDN 與背景工作都用這一層。
//! `probe`：指定 IP + Host / SNI 的 HTTP(S) 探測與下載測速（CDN 節點與網站驗證用）。

pub mod fetch;
pub mod iprank;
pub mod probe;
pub mod quic;
pub mod tls;
pub mod upstream;
