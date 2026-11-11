# 黑潮 DNS（Kuroshio DNS）3.0：Rust 改寫規格

> 2.x 的名稱是 candydns（node.js）。3.0 改名為**黑潮 DNS / Kuroshio DNS**，程式、套件、設定、協定一律用 `kuroshio`。

這份規格是改寫的依據：先把現有 node 版（2.2.x）的行為、介面、資料格式寫下來，Rust 版照著做，做完用同一套測試驗收。

| 文件 | 內容 |
|---|---|
| [01-protocols.md](01-protocols.md) | 支援的所有協議：伺服器端、上游、自動發現、DNS 訊息層 |
| [02-architecture.md](02-architecture.md) | 程式架構、設定、state 格式、管理 API、公開頁 / 設定頁、兩個平台 |
| [03-community-v2.md](03-community-v2.md) | 社群共享協定 v2（不相容 v1，兩位使用者一起升級） |
| [04-migration-and-testing.md](04-migration-and-testing.md) | 從 node 版遷移、驗收方式、CI、階段與完成條件 |
| [05-resources.md](05-resources.md) | 資源預算：硬體等級、最低需求、記憶體、Flash 寫入、CPU |
| [06-optimizations.md](06-optimizations.md) | 體驗優化：命中率、回台灣機率、速度（含量測方式） |
| [07-windows.md](07-windows.md) | Windows 版：cmd / 服務、跟 IIS 共用 443（HTTP.sys / 反向代理）、DoH3、憑證、權限、攜帶版 |

## 目標

1. **單一執行檔**：一份 Rust 核心，編成 OpenWrt（各 CPU，含 MIPS）與 Windows 版本，不需要 node、IIS。
2. **功能對齊**：2.2.x 現有功能全部保留，行為一致（以現有測試與並行比對驗收）。
3. **現代協議**：伺服器端與上游都支援 DoH2、DoH3、DoQ，加上 DDR 自動發現等（見 01）。
4. **兩種網頁同時存在**：
   - **公開頁**：分享給親友的設定說明頁（現有 `site`），兩個平台都有，可開可關。
   - **設定頁**：自己管理用。Windows 是本機網頁；OpenWrt 維持 LuCI。
5. **社群 v2**：修正 v1 實際使用時遇到的問題（誤封鎖、來源 IP 檢查、全量同步），見 03。
6. **資料夾重新整理**：見 02 的「資料夾結構」。

## 不做的事

- 不改 LuCI 頁面的操作方式；LuCI 只跟著新增的協議加選項。
- OpenWrt 上系統整合（接管模式、防火牆、dnsmasq、ULA、acme.sh）繼續用 shell 腳本，核心程式不碰系統設定。
- 不做遞迴解析（仍然是轉發 + 優選上游）。
- ODoH、DNSCrypt 伺服器端：先不做（見 01）。

## 決策紀錄

| # | 決策 | 理由 |
|---|---|---|
| D1 | 語言用 Rust，非同步框架用 tokio | QUIC / HTTP3 / rustls 生態最完整；可編 MIPS |
| D2 | 設定檔格式沿用 `config.js` 的結構（JSON） | LuCI 的 UCI 轉換、預設值、測試都能沿用 |
| D3 | state/ 檔案格式不變 | `data/seed/` 種子資料與升級時的累積資料可以直接沿用 |
| D4 | 管理 API（`/api/*`）路徑與回應格式不變，只新增 | LuCI 不用改 |
| D5 | 社群協定直接升 v2、不保留 v1 | 目前只有兩位使用者，可以同時升級；省下雙協定的複雜度 |
| D6 | 執行檔用 `cargo-zigbuild` 編成靜態連結的 musl 執行檔，OpenWrt SDK 只負責打包；MIPS 用 nightly 自己編標準函式庫 | 不用在 SDK 裡編整套 Rust 工具鏈（每種 CPU 省下約 1 小時）；同一個執行檔 24.10、25.12 都能用 |
| D7 | node 版已移到 `legacy-node/`，在 Rust 版對齊前持續維護；對齊並確認後整個刪除，不再支援 node | 兩位使用者不會中斷服務 |
| D8 | 預設值不帶任何個人網域、私鑰不進 repo | 延續 2.x 的原則 |
| D9 | 名稱：中文「黑潮 DNS」、英文「Kuroshio DNS」、識別名稱 `kuroshio` | 黑潮流經台灣、帶來魚群：把連線帶回台灣節點 |
| D10 | 授權 GPL-3.0-or-later | 修改後散布必須開源，避免被拿去做閉源商品 |
| D11 | 開源時用新的公開 repo、乾淨的歷史紀錄 | 舊 repo 歷史裡有私鑰、個人 email、種子資料；舊 repo 保留為私人封存 |

## 名詞

| 名詞 | 意思 |
|---|---|
| 核心 | Rust 寫的 `kuroshio` 執行檔 |
| 平台層 | OpenWrt（UCI、procd、shell 腳本）或 Windows（服務、本機設定頁） |
| 公開頁 | 給親友看的設定說明頁（現有 `lib/site.js`） |
| 設定頁 | 自己管理的頁面：Windows 本機網頁 / OpenWrt LuCI |
| 管理 API | 只聽 127.0.0.1 的 `/api/*`，設定頁與 LuCI（經 rpcd）都透過它操作 |
