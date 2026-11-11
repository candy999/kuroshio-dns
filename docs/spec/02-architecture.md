# 02 · 架構

## 1. 整體

```
                 ┌──────────────────────── kuroshio（單一執行檔） ────────────────────────┐
 區網 / 外網 ───▶ │ 監聽：UDP/TCP 53 · DoT · DoQ · DoH(h1/h2) · DoH3                        │
                 │        │                                                               │
                 │        ▼                                                               │
                 │  過濾 ─▶ 快取 ─▶ 解析（並行上游 + IP 測速）─▶ CDN 台灣節點置換         │
                 │                       │                                                │
                 │                       ▼                                                │
                 │  上游：udp · tcp · dot · doh(h2) · doh3 · doq · dnscrypt               │
                 │                                                                        │
                 │  背景工作：DNS 評測 · CDN 範圍 · 網段分類 · 節點池 · DDNS · ACME · 社群 │
                 │                                                                        │
                 │  HTTP：公開頁（對外，可關） · 管理 API 與設定頁（只聽 127.0.0.1）        │
                 └────────────────────────────────────────────────────────────────────────┘
           ▲ 設定（JSON）                         ▲ 管理 API
   OpenWrt：UCI → JSON（核心自己轉）       OpenWrt：LuCI → rpcd → 管理 API
   Windows：config.json                   Windows：瀏覽器 → 設定頁 → 管理 API
```

- 2.x 的排程工作是**子程序**（`jobs/run.js`），3.0 改成核心裡的背景工作（tokio task），同一時間只跑一個（同 2.x 的 `state/locks`）。
- 2.x 在 Windows 用外部 `q.exe` 測 DoQ，3.0 內建，不再需要。

## 2. 程式模組（crate）

| crate | 內容 | 對應 2.x |
|---|---|---|
| `kuroshio-proto` | DNS 封包、EDNS、ECS、SVCB/HTTPS、EDE、Padding、Cookies | `lib/dnsmsg.js` |
| `kuroshio-transport` | 上游用戶端：udp/tcp/dot/doh/doh3/doq/dnscrypt、bootstrap、stamp 解析 | `lib/transport.js` |
| `kuroshio-server` | 各協議監聽、ALPN 分派、來源 ACL、速率限制 | `lib/listeners.js` |
| `kuroshio-filter` | 規則解析（AdGuard / hosts）、分類段落、清單去重、CNAME 鏈檢查 | `lib/filter.js` |
| `kuroshio-resolver` | 快取、並行上游、IP 測速、serve-stale、prefetch、本地網域轉發 | `lib/resolver.js`、`upstreams.js`、`iprank.js` |
| `kuroshio-cdn` | CDN 判斷、驗證、節點池、ECS、跨 CDN、v6 節點 | `lib/cdn/*` |
| `kuroshio-jobs` | 評測、CDN 範圍、網段分類、節點池、排程器 | `jobs/*`、`lib/scheduler.js` |
| `kuroshio-community` | 社群共享 v2（見 03） | `lib/community/*` |
| `kuroshio-ops` | DDNS（Cloudflare）、ACME（instant-acme，DNS-01）、種子資料 | `lib/ddns.js`、`lib/seed.js`、`acme.sh` 腳本 |
| `kuroshio-web` | 管理 API、公開頁、Windows 設定頁、統計 | `lib/admin-api.js`、`site.js`、`check.js`、`stats.js` |
| `kuroshio-config` | 設定結構與預設值、JSON 讀寫、UCI 轉換 | `config.js`、`openwrt/kuroshio/files/uci-config.js` |
| `kuroshio`（bin） | 指令列、服務模式、平台層 | `server.js` |

主要外部套件：`tokio`、`hickory-proto`、`rustls` / `tokio-rustls`、`quinn`、`h3` / `h3-quinn`、`hyper` / `axum`、`reqwest`（rustls）、`ed25519-dalek`、`sha2`、`serde_json`、`ciborium`（社群 v2）、`zstd`、`instant-acme`、`windows-service`、`rust-embed`。

## 3. 指令列

```
kuroshio run      [--config <file> | --uci]     前景執行（OpenWrt procd、除錯）
kuroshio service  install | uninstall | start | stop   （Windows）
kuroshio defaults --json                         輸出完整預設設定（rpcd 的 defaults 用，取代 node -e config.js）
kuroshio config   --uci --print                  印出 UCI 轉換後的 JSON（除錯）
kuroshio job      <name>                         立即跑一個背景工作（取代 jobs/run.js）
kuroshio export-seed <url> [--no-domains]        取代 tools/export-seed.js
kuroshio check-config <file>                     檢查設定檔
```

## 4. 設定

- 結構沿用 `config.js` 的頂層區塊：`listen site check admin log upstream resolver iprank filter cdn community jobs benchmark scan pool`，另外新增 `ddns`、`acme`。
- 預設值只定義在 `kuroshio-config` 一個地方；`kuroshio defaults --json` 輸出給 LuCI 顯示「空白 = 預設值」。
- **新增欄位**：

  | 欄位 | 預設 | 說明 |
  |---|---|---|
  | `listen.doq` | `{ enabled:false, port:853 }` | 共用 DoT 的憑證 |
  | `listen.doh.http3` | `false` | 開啟 DoH3（同埠 UDP） |
  | `listen.ddr` | `false` | DDR 自動發現 |
  | `listen.proxyProtocol` | `false` | PROXY protocol v2 |
  | `resolver.stripEch` | `false` | 移除 HTTPS 記錄的 ECH |
  | `resolver.dnssec` | `false` | 本機 DNSSEC 驗證 |
  | `resolver.cookies` | `false` | DNS Cookies |
  | `upstream.autoTypes` | `['udp','doh','doh3','dot','doq']` | 評測類型 |
  | `acme` | `{ enabled:false, provider:'cloudflare', … }` | Windows 內建 ACME；OpenWrt 預設仍用 acme.sh |

- **OpenWrt**：核心直接讀 UCI（`ubus call uci get '{"config":"kuroshio"}'` 或 init 先存成 `/var/run/kuroshio/uci.json`），轉換規則照 `uci-config.js` 逐條移植（`snake_case → camelCase`、依預設值型別轉換、空白 = 預設、接管模式決定綁定位址等）。`test-uci-config.js` 的案例全部變成 Rust 測試。
- **Windows**：`%ProgramData%\kuroshio\config.json`，只存跟預設值不同的欄位；設定頁存檔時整份寫入（先寫暫存檔再改名），核心偵測變更後重新載入（同 2.x 的 UCI reload）。

## 5. 檔案與 state

### 5.1 位置

| 用途 | OpenWrt | Windows |
|---|---|---|
| 執行檔 | `/usr/bin/kuroshio` | `%ProgramFiles%\kuroshio\kuroshio.exe` |
| 設定 | `/etc/config/kuroshio` | `%ProgramData%\kuroshio\config.json` |
| 自訂規則、憑證、社群金鑰、評測名單 | `/etc/kuroshio/` | `%ProgramData%\kuroshio\` |
| state | `/usr/share/kuroshio/state/`（可改到外接硬碟） | `%ProgramData%\kuroshio\state\` |
| 種子資料 | `/usr/share/kuroshio/seed/` | `%ProgramFiles%\kuroshio\seed\` |

### 5.2 state 檔案（格式不變，3.0 照讀照寫）

| 檔案 | 內容 |
|---|---|
| `state/upstreams.json` | 每日評測結果 |
| `state/benchmark/` | 評測過程資料 |
| `state/cdn-domains.json` | 每個 CDN 網站的驗證 / ECS / 跨 CDN 結果 |
| `state/cdn/pools.json` | 台灣節點池 |
| `state/cdn/v6-nodes.json` | 永久保存的台灣 IPv6 節點 |
| `state/cdn/harvest.json`、`ip-zone.json` | 流量收集候選、IP 區域 |
| `state/cdn/ranges/`、`state/cdn/scan/` | CDN 官方範圍、網段分類 |
| `state/filters/` | 訂閱清單快取 |
| `state/stats.json` | 統計 |
| `state/jobs.json` | 排程狀態 |
| `state/community/` | 社群狀態（3.0 改成 v2 格式，見 03 的遷移） |

規則：
- 讀到不認識的欄位要保留、寫回時不丟掉（新舊版本來回切換不會遺失資料）。
- 寫檔一律「暫存檔 + 改名」。
- 各檔案的欄位清單在階段 0 由 node 版實際輸出整理成 JSON Schema，放在 `docs/spec/schema/`。

## 6. 管理 API

只聽 `127.0.0.1`（`admin.port`，預設 8054）。2.x 的路徑與回應格式**全部保留**：

| 唯讀 | 動作 |
|---|---|
| `/api/status`（`?lite=1`）、`/api/upstreams`、`/api/benchmark`、`/api/cdn/pools`、`/api/cdn/v6nodes`、`/api/cdn/summary`、`/api/cdn/domains`、`/api/jobs`、`/api/trace`、`/api/filter/check`、`/api/routing`、`/api/ddns` | `/api/cache/flush`、`/api/filter/update`、`/api/jobs/run`、`/api/cdn/verify`、`/api/cdn/policy`、`/api/cdn/ecs`、`/api/ddns/update` |
| `/api/community/status`、`/api/community/peers`、`/api/community/events` | `/api/community/check`、`add`、`accept`、`reject`、`block`、`unblock`、`delete`、`sync` |

3.0 新增：

| 路徑 | 用途 |
|---|---|
| `/api/protocols` | 各監聽協議的狀態（是否開啟、埠、憑證、連線數、查詢數） |
| `/api/config`（GET / PUT） | **只有 Windows**：讀寫 `config.json`；OpenWrt 一律回 404（設定走 UCI） |
| `/api/defaults` | 同 `kuroshio defaults --json` |
| `/api/acme`、`/api/acme/issue` | Windows 內建 ACME 狀態與申請 |
| `/api/log` | 最近的日誌（Windows 設定頁用；OpenWrt 仍走 logread） |
| `/api/community/*` | v2 新增的聲譽、候選統計（見 03） |

`rpcd.sh` 的允許清單同步加入新路徑。

**存取控制**：
- OpenWrt：只有 rpcd 會呼叫，維持現狀（只聽 127.0.0.1）。
- Windows：設定頁登入用一次性 token（`kuroshio service install` 時產生，存在 `%ProgramData%\kuroshio\admin.token`，只有系統管理員可讀）；登入後發 HttpOnly、SameSite=Strict 的 cookie。所有會改東西的請求檢查 `Origin` / `Host` 必須是 `127.0.0.1:埠` 或 `localhost:埠`（防 DNS rebinding 與跨站請求）。

## 7. 網頁

### 7.1 公開頁（兩個平台都有，`site.enabled` 控制，預設關）

跟 DoH 共用網域與埠（TCP 與 HTTP/3 都可以）。2.x 功能全部保留：

| 路徑 | 內容 |
|---|---|
| `/` | 首頁：特色、匿名統計、設定教學、「這台裝置有沒有在用」偵測（`check`） |
| `/api/public/stats`、`/presence`、`/info` | 匿名統計、使用偵測、連線資訊 |
| `/apple/doh.mobileconfig`、`/apple/dot.mobileconfig` | Apple 描述檔 |
| `site.detailPath`（預設 `/detail`） | 詳細資料頁（唯讀管理 API，用戶端 IP 打馬賽克） |
| `/robots.txt` | 禁止收錄 |

3.0 新增：
- 設定教學依實際開啟的協議產生：DoH、DoH3、DoT、DoQ 網址，`sdns://` stamp，Android「私人 DNS」主機名稱，Windows 11 DoH 範本，各平台 App 建議。
- 頁面檔案放在 `data/site/`（安裝後是 `/usr/share/kuroshio/site/`），可以用 `site.htmlFile` / `site.detailFile` 換成自己的版本（同 2.x）；`{{HOST}}` 代入 `site.hostname`，沒設定時用請求的 Host。實作見 `crates/kuroshio/src/site.rs`、`presence.rs`。

### 7.2 設定頁

| 平台 | 做法 |
|---|---|
| OpenWrt | LuCI（`luci-app-kuroshio`），只新增 3.0 的協議與選項；`common.js` 改呼叫 `/api/defaults` |
| Windows | 核心內建，`http://127.0.0.1:8054/`；頁面跟 LuCI 相同分頁：狀態、基本設定、廣告過濾、社群、CDN 台灣節點、進階、日誌，也有簡易 / 專業模式 |

Windows 設定頁用原生 JS（不用前端框架、不需要編譯步驟），透過 `/api/*` 操作。頁面的欄位定義（名稱、說明、預設值、簡易 / 專業）整理成一份 `web/fields.json`，Windows 設定頁直接用；LuCI 的說明文字之後也可以從同一份產生，避免兩邊說明不一致。

## 8. 平台層

### 8.1 OpenWrt

- 套件 `kuroshio`：只放執行檔、init、shell 腳本、預設設定、種子、預設規則。**不再需要 node**，24.10、25.12 以後都能裝。
- 每種 CPU 各一個套件（不再是 `all`）。執行檔由 `cargo-zigbuild` 先編好（靜態 musl），SDK 只打包：x86_64、i386_pentium4、aarch64_generic、aarch64_cortex-a53、aarch64_cortex-a72、arm_cortex-a7_neon-vfpv4、arm_cortex-a9_vfpv3-d16、arm_cortex-a15_neon-vfpv4、mipsel_24kc、mips_24kc（見 `.github/workflows/rust.yml`）。
- `luci-app-kuroshio` 仍是 `all`。
- 2.x 的 `candydns.init`、`takeover.sh`、`lan.sh`、`acme.sh`、`rpcd.sh`、`uci-defaults` 改名後保留；只把 `node …/server.js` 換成 `/usr/bin/kuroshio run --uci`，`node -e config.js` 換成 `kuroshio defaults --json`。
- 3.0 預覽版（`openwrt/kuroshio/`）可以跟 2.x 同時安裝：預設不啟用，啟用後只聽 `127.0.0.1:5336`，用來並行比對。
- 記憶體、Flash 寫入、CPU 的預算與依硬體自動調整：見 [05-resources.md](05-resources.md)。

### 8.2 Windows

詳見 [07-windows.md](07-windows.md)：cmd 直接執行與 Windows 服務兩種方式（功能相同、可切換、攜帶版）、跟 IIS 共用 443 的三種模式（獨立 / HTTP.sys 共用 / IIS 反向代理）、DoH3 的提供方式與通知管道、憑證同時給 PEM 與 Windows 憑證存放區、需要系統管理員權限的項目與 `kuroshio.exe setup`。

## 9. 資料夾結構

```
kuroshio/
├─ Cargo.toml                 workspace
├─ crates/                    第 2 節的各 crate
├─ web/
│  ├─ public/                 公開頁（首頁、描述檔範本）
│  ├─ admin/                  Windows 設定頁
│  └─ fields.json             設定欄位定義
├─ openwrt/
│  ├─ kuroshio/               Makefile、files/（init、takeover.sh、lan.sh、acme.sh、rpcd.sh、uci-defaults）
│  ├─ luci-app-kuroshio/
│  └─ tools/                  gen-uci、CI 用腳本
├─ windows/                   服務安裝說明、MSI 設定
├─ data/
│  ├─ seed/                   種子資料
│  └─ benchmark/              評測名單（q.exe 移除）
├─ rules/
│  └─ default-custom-rules.txt   （由「自訂過濾規則.txt」改名）
├─ docs/
│  └─ spec/                   本規格
├─ tests/
│  ├─ vectors/                由 node 版產生的對照資料（封包、規則判定、社群訊息）
│  └─ diff/                   新舊版並行比對工具
├─ legacy-node/               node 2.x（對齊後刪除）
└─ .github/workflows/
```

搬家時一起處理：

| 檔案 | 處理 |
|---|---|
| `certs/`（憑證與私鑰） | 不放進 repo（`.gitignore` 排除 `*.pem`）；公開 repo 從乾淨歷史開始（D11） |
| `server.legacy.js`、`web.config`、`restart-dot.ps1` | 移除（3.0 不再需要 IIS） |
| `AdGuard.json` | AdGuard Home 的清單設定匯出，移到 `docs/reference/` 或刪除 |
| `data/benchmark/q.exe` | 移除（DoQ 測試內建） |
| `node_modules/` | 不進 repo |
