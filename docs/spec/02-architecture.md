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
  | `listen.doh.http3Port` | `0` | DoH3 改用的 UDP 埠（0 = 跟 DoH 同一個數字）；只有那個 UDP 埠被占用時才需要（見 01 第 1.1.1 節） |
  | `listen.doh.publicPort` | `0` | 外面看到的 DoH 埠號（0 = 跟 `listen.doh.port` 一樣）：埠號轉送時填；公開頁、描述檔、Alt-Svc、HTTPS 記錄用它 |
  | `site.minClients` | `1` | 公開頁網站排行最少要有幾位不同使用者造訪過（2.x 是 2）。1 = 全部列出；不想讓訪客看到只有一台裝置去過的網站就調高。管理介面的儀表板不受限制 |
  | `listen.ddr` | `false` | DDR 自動發現 |
  | `listen.proxyProtocol` | `false` | PROXY protocol v2 |
  | `resolver.stripEch` | `false` | 移除 HTTPS 記錄的 ECH |
  | `resolver.dnssec` | `false` | 本機 DNSSEC 驗證 |
  | `resolver.cookies` | `false` | DNS Cookies |
  | `upstream.autoTypes` | `['udp','doh','doh3','dot','doq']` | 評測類型 |
  | `acme` | `{ enabled:false, provider:'cloudflare', … }` | Windows 內建 ACME；OpenWrt 預設仍用 acme.sh |
  | `domain` | `''` | 綁定網域（固定網域或 DDNS 名稱）。`site.hostname`、`community.domain`、`acme.domains` 空白時自動帶入；`ddns.records` 只有 `ddns.enabled` 而且沒寫記錄時才帶入（固定網域不需要 DDNS） |
  | `tls` | `{ cert:'', key:'' }` | 共用憑證位置（自備憑證放這裡，不需要 ACME）。監聽用的憑證：`listen.<x>.cert/key` → `tls.cert/key` → 內建 ACME 的輸出位置（`acme.enabled` 才算）。ACME 的輸出位置：`acme.certFile/keyFile` → `tls.*` → `listen.dot.*` → `listen.doh.*` → `<設定目錄>/cert.pem`、`key.pem`；`acme.enabled` 關閉時絕不寫入，啟動時只檢查（檔案不存在、過期、沒涵蓋 `domain` 會提醒） |
  | `listen.doh.tls` | `'auto'` | DoH 的 TCP 要不要自己做 TLS：`auto` / `true` / `false`。auto：`listen.doh.windowsMode = 'iis-proxy'`，或只監聽 loopback 而且沒有明確寫 `listen.doh.cert` → 明文 HTTP（前面有反向代理）；其他情況找得到憑證就 TLS。UCI 轉出來的設定一律有 `listen.doh.cert`，行為不變 |
  | `listen.<dot\|doq\|doh>.binds` | `[]` | 多位址監聽，有填就取代 `host`；IPv4、IPv6 可以同時寫（IPv6 設 `IPV6_V6ONLY`）。DoH3 跟 DoH 同樣的位址（`listen.doh.http3Binds` 可另外指定）。一個位址綁定失敗只記警告，結果在 `/api/status` 的 `listenersDetail` |
  | `ddns.ipv6` | `false` | AAAA 預設不發布（不少線路會擋外面連進來的 IPv6）；關掉時會移除自己建立的 AAAA |
  | `ddns.ipSource`、`ddns.interfaces` | `'web'`、`[]` | 多網卡 / 多出口：`interfaces` 列出要發布的網卡（舊的 `iface4` / `iface6` 併入）；`web` = 從每張網卡各自連出去查公網 IP，`interface` = 讀網卡上的公網位址。同一個名稱、同一種類型的記錄當成一組：只在這一組裡新增 / 更新 / 刪除；偵測失敗不動記錄；消失的出口連續 3 次才移除 |

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
| `state/cdn/domains/`（`manifest.json`、`{N}-{i}.json.zst`） | 每個 CDN 網站的驗證 / ECS / 跨 CDN 結果，分片、zstd 壓縮（規格 05 第 5.3 節；舊版的 `state/cdn-domains.json` 啟動時自動搬過來） |
| `state/cdn/pools.json(.zst)` | 台灣節點池 |
| `state/cdn/v6-nodes.json(.zst)` | 永久保存的台灣 IPv6 節點 |
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
| `/api/paths` | 存放位置：`configFile`、`configDir`、`stateDir`、`runtimeDir`、`shareDir`、`tls{cert,key,source,exists,info}`（`source`：`manual` / `acme` / `none`）、`acme{enabled,account,domains}`、`adminToken`、`customRules`、`benchmarkDir`、`communityKeyDir`、`logFile`。只有路徑，沒有密鑰內容；命令列：`kuroshio paths [-c CONFIG] [--uci]` |
| `/api/interfaces` | 本機網卡與位址：`interfaces[] { name, label, up, addrs[] { ip, family, scope, temporary?, deprecated? } }`（DDNS 選出口、選監聽位址用） |
| `/api/status` 的 `listenersDetail` | 每個加密監聽位址：`{ proto, bind, port, ok, tls, error }` |
| `/api/ddns` 的 `sources`、`records` | 每個出口偵測到的 IP、每筆記錄的結果 |
| `/api/community/*` | v2 新增的聲譽、候選統計（見 03） |
| `/api/backup/export?kind=full\|share`（GET） | 先把記憶體裡的狀態寫出，再下載 `.kuroshio` 備份檔（`application/octet-stream`、`content-disposition: attachment; filename="kuroshio-<種類>-YYYYMMDD.kuroshio"`） |
| `/api/backup/import`（POST，內容 = 檔案本身，最多 64 MB） | 檢查後存成 `<state>/import-pending.kuroshio`，在程式內重新啟動；回 `{ok, reloading:true, preview}`。新的一輪在讀取任何狀態之前合併（舊的一輪先把記憶體寫出，不會蓋掉合併結果） |
| `/api/backup/last-import` | 上一次匯入的合併結果（`<state>/import-last.json`；沒有時 `{none:true}`） |
| `/api/persist/flush`（POST） | 立即儲存學習資料：有變動的快照全部寫進快照目錄（同 SIGUSR1、`kuroshio notify save`）；回 `{ok, files, bytes, at（Unix 毫秒）, dir}` |
| `/api/filter/reset-rules`（POST） | 恢復預設自訂規則：`filter.customRules` 的第一個檔案先複製成 `<檔名>.bak`，再寫入這個版本的預設規則（`<shareDir>/default-custom-rules.txt`，沒有就用執行檔內建的），立刻重新載入；已經是預設時不動檔案。回 `{ok, changed, file, backup, source（檔案路徑或 builtin）, bytes, reloaded}` |

`rpcd.sh` 的允許清單同步加入新路徑。備份不走 `api` / `action`：rpcd 另有 `backup_export {kind}`（執行 `kuroshio export --uci`，檔案放在 `/tmp/kuroshio-backup.kuroshio` 讓 LuCI 下載）與 `backup_import {}`（匯入 LuCI 上傳的 `/tmp/kuroshio-import.kuroshio`），兩個都需要 ACL 寫入權限。

**備份檔（`.kuroshio`）**：zstd 壓縮的 JSON `{ format: "kuroshio-backup", version: 1, kind: "full"|"share", exportedAt, core, files: { 相對路徑: {json}|{text}|{b64} } }`。
`full` 有狀態目錄的學習資料（CDN 網域、節點池、IPv6 節點、候選 IP、網段分類、評測結果、汙染黑名單、統計、常用網域）、自訂規則（`custom-rules.txt`）、社群狀態與金鑰（`community/`、金鑰目錄不同時 `community-keys/`）；
`share` 只有 CDN 網域（去掉 `hits`、`firstSeen`、`lastSeen`、`policy`，也去掉自己網域底下的名稱：`domain`、`site.hostname`、`community.domain`、`ddns.records`、`ddns.zone`、`acme.domains` 三段以上去掉第一段、兩段照用，等於或在它底下的都不放；好友同步的網站 / 跨 CDN 記錄同樣排除）、節點池、IPv6 節點、評測結果、汙染黑名單。
匯入時拒絕：format 不對、version 大於 1、解壓後超過 64 MB、不認識的路徑、含 `..` / 絕對路徑 / 反斜線的路徑（分享檔只能有上面五個檔案）。
匯入一律合併：網域以名稱比對，匯入的驗證時間比較新才用，但次數、手動設定、最早 / 最晚出現時間以本機為準；節點池與 IPv6 節點依 IP 聯集（本機優先）；評測結果比較新才用；黑名單依每行第一欄聯集；候選 IP、網段分類、統計、常用網域本機沒有才用；自訂規則本機還是預設內容就換掉，否則只把沒有的規則加在最後；社群身分在本機還沒有好友時換成備份的身分（本機自己產生的金鑰另存 key.pem.before-import），已經有好友就不覆蓋。

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
| `/assets/dashboard.js`、`/assets/dashboard.css` | 共用儀表板（見 7.3） |
| `/robots.txt` | 禁止收錄 |

3.0 新增：
- 設定教學依實際開啟的協議產生：DoH、DoH3、DoT、DoQ 網址，`sdns://` stamp，Android「私人 DNS」主機名稱，Windows 11 DoH 範本，各平台 App 建議。
- 頁面檔案放在 `data/site/`（安裝後是 `/usr/share/kuroshio/site/`），可以用 `site.htmlFile` / `site.detailFile` 換成自己的版本（同 2.x）；`{{HOST}}` 代入 `site.hostname`，沒設定時用請求的 Host。DoH 不在 443 時網址要帶埠號，用 `{{DOH_URL}}`（完整 DoH 網址）、`{{SITE_URL}}`（這一頁的網址）、`{{DOH_HOSTPORT}}`（網域加埠號）、`{{DOH_PORT}}`；舊的 `{{HOST}}{{DOH_PATH}}` 寫法不會帶埠號。實作見 `crates/kuroshio/src/site.rs`、`presence.rs`。
- 網站排行（`topSites`、`topBlocked`）只列出至少 `site.minClients` 位不同使用者造訪過的網站，預設 1（全部列出）。

### 7.2 設定頁

| 平台 | 做法 |
|---|---|
| OpenWrt | LuCI（`luci-app-kuroshio`），只新增 3.0 的協議與選項；`common.js` 改呼叫 `/api/defaults` |
| Windows | 核心內建，`http://127.0.0.1:8054/`；頁面跟 LuCI 相同分頁：狀態、基本設定、廣告過濾、社群、CDN 台灣節點、進階、日誌，也有簡易 / 專業模式 |

Windows 設定頁用原生 JS（不用前端框架、不需要編譯步驟），透過 `/api/*` 操作。頁面有嚴格的 CSP（只載入自己的檔案、不允許行內程式與樣式），伺服器給的字串一律用 `textContent`。頁面的欄位定義（名稱、說明、預設值、簡易 / 專業）整理成一份 `web/fields.json`，Windows 設定頁直接用；LuCI 的說明文字之後也可以從同一份產生，避免兩邊說明不一致。

### 7.3 共用儀表板（`data/dashboard/`）

公開頁的圖表與詳細頁的表格（查詢趨勢、查詢去向、上游、CDN 機會成本、路由地圖、台灣節點池、CDN 網域資料庫、跨 CDN 備援、排行、過濾規則、排程工作、追蹤網域）是同一份 `dashboard.js` + `dashboard.css`，三個地方共用：

| 主機 | 載入位置 | 資料（轉接器） |
|---|---|---|
| 公開頁、詳細頁 | `/assets/dashboard.js`、`/assets/dashboard.css` | 公開的唯讀 API：`/api/public/stats`、詳細頁的 `…/api/*`（匿名、IP 打馬賽克、上游網址遮掉） |
| LuCI「黑潮 DNS → 儀表板」 | `/luci-static/resources/kuroshio/`（`luci-app-kuroshio` 從 `data/dashboard/` 安裝） | rpcd `kuroshio.api` 轉送本機管理 API；公開頁關著也能用，不開任何埠 |
| Windows 設定頁「儀表板」分頁 | `/dashboard/dashboard.js`（設定頁靜態檔） | 登入後的管理 API |

- 管理介面是完整資料：統計用 `/api/dashboard?range=today|7d|30d`（跟 `/api/public/stats` 同一份，但排行不受 `site.minClients` 限制、各列 30 筆），上游完整網址、用戶端不打馬賽克。
- 圖表在瀏覽器畫，路由器只給 JSON。CDN 網域資料庫可能有 20 萬筆：管理介面用 `/api/cdn/domains?limit=300&offset=…&q=…&provider=…` 分頁搜尋，跨 CDN 用 `cross=1`；詳細頁維持一次載入 2 萬筆在瀏覽器篩選。
- 安全：不組 HTML 字串、不寫 `style` 屬性（只用 CSSOM），在設定頁的嚴格 CSP 下可用。淺色 / 深色跟著系統（LuCI 跟著 `data-darkmode`），手機寬度下寬表格在框裡捲動。

## 8. 平台層

### 8.1 OpenWrt

- 套件 `kuroshio`：只放執行檔、init、shell 腳本、預設設定、種子、預設規則。**不再需要 node**，24.10、25.12 以後都能裝。
- 每種 CPU 各一個套件（不再是 `all`）。執行檔由 `cargo-zigbuild` 先編好（靜態 musl），SDK 只打包：x86_64、aarch64_generic、aarch64_cortex-a53、aarch64_cortex-a72、aarch64_cortex-a76、arm_cortex-a7_neon-vfpv4、arm_cortex-a9_vfpv3-d16、arm_cortex-a15_neon-vfpv4、mipsel_24kc、mips_24kc（見 `.github/workflows/rust.yml`）。
- `luci-app-kuroshio` 仍是 `all`。
- 2.x 的 `candydns.init`、`takeover.sh`、`lan.sh`、`acme.sh`、`rpcd.sh`、`uci-defaults` 改名後保留；只把 `node …/server.js` 換成 `/usr/bin/kuroshio run --uci`，`node -e config.js` 換成 `kuroshio defaults --json`。
- 3.0 預覽版（`openwrt/kuroshio/`）可以跟 2.x 同時安裝：預設不啟用，啟用後只聽 `127.0.0.1:5336`，用來並行比對。
- 記憶體、Flash 寫入、CPU：沒有硬體等級，記憶體依系統保留量動態控制（[09-memory.md](09-memory.md)），其他見 [05-resources.md](05-resources.md)。
- procd：`kuroshio` 實例 `respawn 3600 1 0`（1 秒後重啟、不放棄）；`guard` 實例（`guard.sh`）在本程式沒有回答時暫時讓 dnsmasq 直接轉送（`main.restart_fallback`）。

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
