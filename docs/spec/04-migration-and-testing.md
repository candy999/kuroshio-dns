# 04 · 遷移、驗收與階段

## 1. 驗收方式

### 1.1 對照資料（tests/vectors）

在階段 0 用 node 2.x 產生，Rust 測試直接讀：

| 資料 | 來源 | 內容 |
|---|---|---|
| `dns/` | `lib/dnsmsg.js` | 查詢重建、ECS、SVCB 改寫、攔截回應：輸入封包 → 預期封包 |
| `filter/` | `lib/filter.js` | 規則檔 + 網域清單 → 每個網域的判定（動作、命中規則、tier、分類） |
| `uci/` | `test-uci-config.js` | UCI JSON → 預期的設定 JSON（5 種接管模式、各區塊） |
| `cdn/` | `lib/cdn/*` | CDN 判斷、官方範圍判斷、驗證決策的輸入 → 預期結果 |
| `state/` | 實際 state 檔 | 讀進來再寫出去，內容不變（含不認識的欄位） |
| `community/` | 規格第 03 份 | v2 信封範例（v2 是新協定，以規格為準，不跟 node 對照） |

`test/selftest.js`（82 項）與 `test/community-test.js`（19 項）的每一項都要有對應的 Rust 測試；community 的部分改成 v2 的版本。

### 1.2 並行比對（tests/diff）

Rust 版對齊前，在真實路由器上**同時跑兩個版本**：

- node 版照常服務（53 / 5335），Rust 版聽另一個埠，例如 5336。
- 比對工具用 dnsmasq 的查詢紀錄（或 node 的 `queryLog`）重播同一批查詢給兩邊，比對：
  - rcode、答案的 IP 集合、TTL 範圍
  - 過濾判定、CDN 置換結果（是否換成台灣節點、換到哪個 POP）
- 差異寫成報表。**允許的差異**：IP 測速造成的順序不同、節點池內不同的 IP。其他差異都要解釋或修掉。
- 對齊的標準：連續 3 天、每天至少 1 萬筆查詢，未解釋差異 < 0.1%。
- 工具：`kuroshio compare <紀錄檔> --a 127.0.0.1:5335 --b 127.0.0.1:5336 --out report.json`
  - 紀錄檔認得 dnsmasq 的 `log-queries`、node 版 queryLog，或一行一個網域（可加類型，例如 `AAAA example.com`）
  - 讀設定裡的 CDN 範圍與節點池分辨「同一家 CDN 的台灣節點」；分類：same / pool（允許）、rcode、filter、cdn、ips、error
  - 結束代碼 0 = 達標（未解釋差異 < 0.1%），報表列出最多 2,000 筆差異樣本

### 1.3 效能目標

| 項目 | 目標 |
|---|---|
| 記憶體 | 沒有固定目標：系統可用記憶體低於保留量時依序讓出，最深仍轉送（規格 09 第 8 節） |
| 常駐記憶體（開 HaGeZi TIF） | < 60 MB |
| 快取命中延遲（區網 UDP） | < 1 ms |
| 啟動到可以回答 | < 3 秒（不等清單下載，先用快取） |
| 執行檔大小 | < 10 MB（strip 後） |

## 2. 階段與完成條件

| 階段 | 內容 | 完成條件 |
|---|---|---|
| **0 規格與整理**（進行中） | 本規格；產生 tests/vectors；state 檔的 JSON Schema；資料夾整理（第 3 節）；移除私鑰 | 規格確認；node 版搬到 `legacy-node/` 後 CI 仍然全綠 |
| **1 DNS 核心** | proto、transport（udp/tcp/dot/doh h1+h2）、server（udp/tcp）、filter、resolver、管理 API `/api/status`、UCI 轉換 | 對照資料的 dns / filter / uci 全過；OpenWrt「作為 dnsmasq 上游」模式可以用 Rust 版跑 |
| **2 CDN 與背景工作** | cdn、jobs（評測、範圍、網段分類、節點池）、IP 測速、種子資料 | 並行比對達標；state 檔能跟 node 版互相讀寫 |
| **3 OpenWrt 取代 node** | DoT / DoH 伺服器、DDNS、社群 v2、完整管理 API、OpenWrt 各 CPU 套件、LuCI 更新 | 兩台路由器都換成 3.0；CI 的 smoke / LuCI e2e / 兩節點社群測試全過 |
| **4 新協議** | DoH3、DoQ（伺服器 + 上游）、DNSCrypt / stamp 上游、DDR、EDE、Padding、Cookies、DNSSEC、ECH 移除 | 各協議有整合測試（用 kdig / q / dnslookup 等外部用戶端交叉測）；評測支援新類型 |
| **5 Windows** | 服務、設定頁、公開頁、內建 ACME、網卡 DNS 設定、防火牆、zip 安裝包 | 在 Windows 11 上安裝、設定、DoH / DoT / DoQ 對外可用，取代原本 IIS 版 |
| **6 收尾** | 刪除 `legacy-node/`、README 全面改寫、v3.0.0 Release | 兩個平台的 Release 都有產出 |

階段 4 可以跟 3 部分並行（DoQ / DoH3 的上游只要 transport 好了就能做）。

## 3. 階段 0 的資料夾整理步驟

1. 開分支 `rust-3.0`（從 `openwrt-x86` 分出）。
2. 把 node 版搬到 `legacy-node/`：`server.js`、`config.js`、`lib/`、`jobs/`、`test/`、`site/`、`package*.json`、`tools/export-seed.js`。
3. `openwrt/candydns/Makefile`（2.x 套件）、CI 的路徑改指向 `legacy-node/`，確認 CI 全綠（這時發布的 2.x 套件仍是 node 版）。
4. `自訂過濾規則.txt` → `rules/default-custom-rules.txt`；`data/benchmark/q.exe` 移除。
5. 移除 `server.legacy.js`、`web.config`、`restart-dot.ps1`（IIS 版用不到了，Windows 版由 3.0 取代；在那之前 Windows 那台照舊跑現有檔案，不受 repo 變動影響）。
6. **私鑰**：
   - 把 `certs/` 從 repo 移除，並加進 `.gitignore`。
   - 公開的 repo 從乾淨的歷史開始（開發期的私有 repo 不公開）。
   - 換掉開發期用過的憑證與私鑰。
7. 建立 Cargo workspace 骨架、`crates/` 空殼，加 Rust 的 CI job（`cargo test`、`clippy`、`fmt`）。

## 4. CI（3.0 完成後）

| job | 內容 |
|---|---|
| `test` | `cargo test`（含對照資料）、`clippy`、`fmt`、LuCI 語法檢查、shellcheck |
| `binaries` | cargo-zigbuild 編各 CPU 的靜態執行檔，用 QEMU 實際執行並查詢 |
| `openwrt` | 官方 SDK 打包 × {24.10, 25.12} × 各 CPU（推送時只做 x86_64；`v3.*` 標籤或手動執行時全部） |
| `build-windows` | `x86_64-pc-windows-msvc`，產出 zip |
| `smoke` | 官方 OpenWrt rootfs 容器：安裝、5 種接管模式、還原、rpcd、各協議查詢（UDP / TCP / DoT / DoH / DoH3 / DoQ） |
| `luci` | 瀏覽器打開每一頁（簡易與專業模式）、儲存、截圖 |
| `community` | 兩節點社群整合測試 |
| `windows-smoke` | Windows runner：服務安裝、設定頁登入、查詢 |
| `release` | `v*` 標籤：附上所有套件與 Windows zip |

## 5. 升級與回退

- OpenWrt：3.0 的 `kuroshio` 套件取代 2.x 的 `candydns`（宣告 `PROVIDES` / `CONFLICTS` 舊名）。`uci-defaults` 把 `/etc/config/candydns` 搬成 `/etc/config/kuroshio`、`/etc/candydns/` 搬成 `/etc/kuroshio/`，並補上 3.0 的新欄位；LuCI 改成 `luci-app-kuroshio`。
- state 檔格式不變，所以**回退到 2.x 也能用**（社群要重新同步一次；v2 的 `peers.json` 回退時由 2.x 讀到不認識的格式會當成空的，所以升級時保留一份 `peers.v1.json` 備份）。
- Windows：先停用 IIS 站台與舊的排程，再安裝服務；`state/` 直接複製到 `%ProgramData%\kuroshio\state\`。

## 6. 開源前檢查清單

| # | 項目 | 狀態 |
|---|---|---|
| 1 | 名稱：黑潮 DNS / Kuroshio DNS（`kuroshio`） | ✅ |
| 2 | 授權：GPL-3.0-or-later（`LICENSE`） | ✅ |
| 3 | 私鑰 `certs/` 移出 repo、`.gitignore` 排除 `*.pem` | ✅（舊 repo 歷史仍有，D11） |
| 4 | 換掉開發期用過的憑證與私鑰 | ⬜ |
| 5 | `q.exe`（第三方執行檔）、`AdGuard.json`（個人設定）、IIS 檔案移除 | ✅ |
| 6 | 種子資料 `data/seed/cdn-domains.json`：維護者決定公開（新安裝不用從零學習） | ✅ |
| 7 | 程式、測試、文件裡的個人網域改成 `example.com` 或設定值 | ✅ |
| 8 | 新的公開 repo（乾淨歷史）、README | ✅（貢獻說明、Issue 範本待補） |
| 9 | 預設自訂規則 `rules/default-custom-rules.txt` 隨專案以 GPL 釋出 | ✅（你自己寫的規則） |
