# 給協助開發的 AI（與人）

動手之前先讀 [docs/principles.md](docs/principles.md)：黑潮的核心理念、六條原則、兩個特別情境（上下游都是黑潮、上游或業者劫持），以及改東西之前的檢查清單。功能細節在 [docs/guide/](docs/guide/README.md)（使用者指南）與 [docs/spec/](docs/spec/README.md)（規格）；首頁 [README.md](README.md) 只放概要與連結。

最常走偏的地方（詳見原則文件）：

- 台灣 CDN 節點是黑潮的本質：小機器是「減量」，不是「關掉」。
- 不當攻擊者：不對同一批伺服器重複大量查詢、不重複做同一件事；判斷標準是「不浪費、不重複」，不是「流量越少越好」。
- 每台黑潮都有自由：上游擋的，下游可以用自己的加密上游決定要不要擋。
- 上下游是「直系血親」：傳承資料，但下游保有自己收集與查核的能力，不深度依賴上游。
- 安全路線：任何機制都要有上限、會自己恢復、不形成風暴或迴圈；不做激進優化。
- 不做讓效能變差的修改（主要目標是 MT7621：兩核心、沒有 AES、32 位元，沒有 64 位元原子操作）。

寫作與內容：

- 文件、介面文字、Release 說明、commit 訊息用繁體中文（台灣用語）。
- 範例只用 `example.com`／`example.net` 與文件用 IP（`192.0.2.0/24`、`198.51.100.0/24`、`2001:db8::/32`；區網範例 `192.168.1.1`／`192.168.1.2`），不寫真的網域、公網位址、金鑰或 token。
- 不採用 hosts 類清單裡的 IP 當答案或節點。

驗證：推之前 `cargo fmt --all --check`、`cargo clippy --all-targets -- -D warnings`、`cargo clippy -p kuroshio --all-targets --features acme -- -D warnings`、`cargo test --workspace` 都要過；行為改變要有測試、更新對應文件與 `docs/release-notes/`。
