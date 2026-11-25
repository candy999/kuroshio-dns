# 07 · Windows 版

Windows 版跟 OpenWrt 版是同一個核心程式（`kuroshio.exe`），差別只在平台層：服務管理、本機設定頁、憑證存放、跟 IIS 共存。

## 1. 執行方式

同一個執行檔、同一份設定，兩種方式功能完全相同（DNS、DoH、DoT、DoQ、DoH3、設定頁、公開頁、CDN 置換）。

| | cmd 直接執行 | Windows 服務 |
|---|---|---|
| 指令 | `kuroshio.exe run [-c config.json]` | `kuroshio.exe service install` / `uninstall` / `start` / `stop` |
| 啟動 | 手動 | 開機自動啟動，不用登入 |
| 關閉 | 關視窗、Ctrl+C、Ctrl+Break、登出、關機都正常收尾、寫出快照、寫日誌（3.5.0；以前只有 Ctrl+C） | 不受登出、關視窗影響 |
| 當掉 | 不會自動重啟 | 自動重啟（服務復原設定） |
| 日誌 | 直接顯示在視窗 | 日誌檔，設定頁「日誌」分頁可看 |
| 適合 | 測試、臨時用、攜帶版 | 長期 24 小時運作 |

- **可以切換**：先用 cmd 測試，再 `service install`，沿用同一份設定與資料。
- **攜帶版**：`kuroshio.exe` 旁邊有 `config.json` 時，設定與資料都放在執行檔所在的資料夾（可以放隨身碟）；沒有的話用 `%ProgramData%\kuroshio\`。
- 啟動時在日誌與設定頁顯示：執行方式（cmd / 服務）、設定來源、是否有系統管理員權限。

### 1.2 主控台關閉／登出／關機（3.5.0）

- `main.rs` 的 `shutdown_signal()` 在 Windows 同時等 tokio 的 `ctrl_c`、`ctrl_break`、`ctrl_close`、`ctrl_logoff`、`ctrl_shutdown`，回傳是哪一種（`app::StopReason`）。
  五種都走同一個正常停止（`Started::shutdown_for`），日誌寫「收到主控台關閉，正常停止（……）」之類的一行（關閉／登出／關機是 WARN，只收警告的日誌也看得到）。
- **時間限制**：`CTRL_CLOSE_EVENT`、`CTRL_LOGOFF_EVENT`、`CTRL_SHUTDOWN_EVENT` 這三種，系統在事件發生後大約 5 秒就強制結束行程。
  tokio 1.54 的處理函式收到這三種時**不回傳**（停在處理函式的執行緒裡，見 tokio `signal/windows/sys.rs` 的 `terminates()`），
  所以行程留給程式自己結束：主迴圈收到通知、寫快照、`main` 回傳，行程就正常結束。不需要自己用 `windows-sys` 註冊 `SetConsoleCtrlHandler`。
- 這三種時寫快照（含準備內容）最多 3 秒（`persist::CONSOLE_SHUTDOWN_BUDGET`，`flush_for_shutdown_within`），小檔先寫，寫不完的下次啟動用上一次存的；
  每一輪的執行環境結束時只等 0.2 秒（平常 3 秒）。Ctrl+C、Ctrl+Break、服務停止照舊 10 秒。檔案日誌是直接寫檔（沒有緩衝），不必另外沖出。
- 服務模式（`winsvc.rs`）不改流程：`ServiceControl::Stop | Shutdown` 照舊，等服務管理員的時間（`wait_hint` 20 秒）。
- 限制：Windows 只把登出與關機事件送給**沒有載入 `user32.dll`／`gdi32.dll`** 的主控台程式（載入了就被當成視窗程式，改收視窗訊息）；
  黑潮沒有直接用這兩個函式庫，但要在 Windows 實測確認（第 6 節）。主控台已經關掉時寫到視窗的日誌會失敗（不影響檔案日誌與快照）。

### 1.1 權限

| 動作 | 需要系統管理員 |
|---|---|
| 監聽 53 / 443 / 853 埠 | 不需要（Windows 沒有「1024 以下保留埠」） |
| HTTP.sys 共用 443（第 2 節模式 B）的網址登記 | 需要（或事先登記 urlacl） |
| 匯入憑證到「本機電腦」憑證存放區、綁定憑證 | 需要 |
| 新增 Windows 防火牆規則 | 需要 |
| 一鍵把網卡 DNS 改成 127.0.0.1 | 需要 |
| 安裝 / 移除服務 | 需要 |

- 一般權限執行時，需要權限的動作失敗**不會讓程式停止**；設定頁列出哪幾項沒完成、需要用系統管理員重新執行。
- `kuroshio.exe setup`（系統管理員執行一次）：一次完成網址登記（urlacl）、憑證匯入與綁定、防火牆規則。之後一般權限也能跑全部功能。
- 第一次監聽時 Windows 可能跳出防火牆詢問，按「允許」即可（setup 已加規則就不會跳）。

## 2. HTTPS 443 與 IIS 共存

**關鍵**：TCP 443 與 UDP 443 是兩個不同的埠。IIS（HTTP.sys）拿走的是 TCP 443；DoH3 用 UDP 443；DoT（TCP 853）、DoQ（UDP 853）跟 IIS 無關，黑潮 DNS 一律自己監聽。

### 2.1 三種模式

`listen.doh.windowsMode`：`auto`（預設）/ `standalone` / `httpsys` / `iis-proxy`

| 模式 | 適用 | TCP 443（DoH h1/h2、公開頁、社群 `/.well-known/kuroshio`） | UDP 443（DoH3） |
|---|---|---|---|
| **A. 獨立** `standalone` | 沒有 IIS、443 沒被占用 | 黑潮 DNS 自己監聽 | 黑潮 DNS 自己監聽 |
| **B. HTTP.sys 共用** `httpsys`（有 IIS 時建議） | IIS 占用 TCP 443 | 透過 Windows HTTP Server API 向 HTTP.sys 登記自己的網址，跟 IIS 共用 443 | 見 2.2 |
| **C. IIS 反向代理** `iis-proxy` | 已經用 IIS ARR 設好（2.x 的做法） | IIS 把請求轉給黑潮 DNS 的本機埠（`127.0.0.1:8053`） | 見 2.2 |

`auto`：TCP 443 沒被占用 → A；被 HTTP.sys / IIS 占用 → B。C 只在明確指定時使用。

#### 模式 B：HTTP.sys 共用（已實作）
- 登記的網址（只登記自己的，IIS 其他網站不受影響）：`https://<網域>:443/dns-query`、`https://<網域>:443/.well-known/kuroshio`、公開頁開啟時加上 `https://<網域>:443/`（同一網域的其他路徑仍可由 IIS 處理時，改登記公開頁的實際路徑）
- TLS 由 HTTP.sys 處理：憑證匯入「本機電腦\個人」存放區，用 `hostnameport`（SNI）綁定到 `<網域>:443`
- 用戶端 IP 直接取得（不需要 X-Forwarded-For）
- HTTP.sys 開了 HTTP/3 時，登記的網址自動支援 DoH3
- 優點：不用安裝 ARR / URL Rewrite、少一層轉送、延遲低；TLS 與 HTTP/2 由核心處理

實作（`crates/kuroshio/src/httpsys.rs`）：
- HTTP Server API 2.0：`HttpInitialize` → `HttpCreateServerSession` → `HttpCreateUrlGroup` → `HttpCreateRequestQueue` →
  `HttpSetUrlGroupProperty(HttpServerBindingProperty)` → `HttpAddUrlToUrlGroup`；兩條專用執行緒同步呼叫
  `HttpReceiveHttpRequest`（`COPY_BODY`），處理交給 tokio、跟 TCP 的 DoH 用同一個 `doh_core`（公開頁、社群、DoH 查詢）；
  內容上限跟 TCP 的 DoH 一樣
- 過載保護（3.5.1 K7、K8；上限與日誌見 [01 第 1.1.2 節](01-protocols.md#112-過載保護連線與請求的上限351)）：
  - 同時處理中的請求跟 TCP 的 DoH 共用 `system.maxDohInflight`，**在接收的執行緒就判斷**：滿了（或記憶體不足）當場回 `503 busy`，
    不排隊、不經過 tokio。不再佔 TLS 連線的名額（3.5.0 以前每個請求佔一個：處理不完的 DoH 請求讓 DoT 的新連線也被拒絕，DoQ 不受影響）
  - 回應（`HttpSendHttpResponse`）加 `HTTP_SEND_RESPONSE_FLAG_BUFFER_DATA`（複製到 HTTP.sys 的緩衝區就返回，不等用戶端收到），
    交給 2 條送回應的專用執行緒；名額送完才還，所以送回應的佇列不會無限長。POST 剩下的內容（`HttpReceiveRequestEntityBody`）交給 4 條讀內容的專用執行緒
    （最多排 32 個，滿了回 `503 busy`）。3.5.0 以前兩者都在 tokio 的 blocking 執行緒（工作執行緒數的兩倍，跟清單重建、快照寫入共用、排隊沒有上限）：
    高負載時回應越排越久，用戶端放棄了還在排，新的請求也等不到回應，壓力解除後要好幾分鐘才消化完
  - 黑潮自己的網址群組設 `HttpServerTimeoutsProperty`：請求內容 10 秒內要送完（`EntityBody`）、在 HTTP.sys 佇列裡最多等 15 秒（`RequestQueue`）；
    HTTP.sys 預設都是 2 分鐘。只設在自己的網址群組，不影響 IIS；設定失敗只記警告
  - 每筆查詢最多 10 秒，逾時回 SERVFAIL。HTTP.sys 不通知用戶端放棄，所以放棄的請求最多佔 10 秒名額
- 網址一律以 `/` 結尾（HTTP.sys 的規定，請求 `/dns-query` 也對得到 `/dns-query/`），埠號是 `listen.doh.port`（要跟 IIS 共用請設 443）
- 公開頁：先登記 `https://<網域>:<埠>/`；已經被 IIS 站台登記（`ERROR_ALREADY_EXISTS`）時改登記公開頁實際用到的路徑
  （`/index.html`、`/robots.txt`、`/favicon.*`、`/qr.svg`、`/api/public/`、`/apple/`、詳細頁），首頁 `/` 照常由 IIS 處理
- 一般權限、沒有 urlacl 時登記失敗（`ERROR_ACCESS_DENIED`）：記警告「請用系統管理員執行一次 kuroshio setup」，其他監聽照常
- 重新載入與結束：`HttpRemoveUrlFromUrlGroup`（全部）＋ `HttpShutdownRequestQueue`，新的一輪重新登記
- `auto`：啟動時試著綁定設定的 DoH 位址與 `0.0.0.0` 的 TCP 埠（位址已被使用），並看 `netsh http show servicestate view=requestq`
  有沒有已登記在這個埠的網址；任一成立 → B，否則 A。結果寫在日誌、`/api/status` 的 `dohMode`（`configured`、`mode`、`reason`、
  各網址登記結果、`enableHttp3`、`altSvc`）、`listenersDetail`（`proto: doh`、`bind: httpsys`）與 cmd 的 `status` 指令
- `kuroshio.exe setup`（`windowsMode` 是 `httpsys` 或 `auto`、DoH 開著時）：`netsh http add urlacl url=… user=<目前帳號>`
  （公開頁開著時登記網域根目錄，涵蓋底下所有路徑）並綁定憑證；服務以 LocalSystem 執行，不需要 urlacl
- `kuroshio.exe httpsys status | cert`：顯示要登記的網址 / 立即同步憑證

#### 模式 C：IIS 反向代理
- `kuroshio.exe iis setup <IIS 站台名稱>`：產生 `web.config`（URL Rewrite 規則把 `/dns-query`、`/.well-known/kuroshio`、公開頁轉給 `http://127.0.0.1:8053`）、啟用 ARR 代理、在回應加上 `Alt-Svc` 自訂標頭
- `listen.doh.trustProxy = true`：用 `X-Forwarded-For` 取得用戶端 IP，只信任來自 127.0.0.1 的代理
- 適合已經用 IIS 管理網站、想沿用現有設定的使用者

### 2.2 DoH3

| Windows 狀態 | DoH3 由誰提供 |
|---|---|
| HTTP.sys 沒開 HTTP/3（Windows 10、Server 2019 一定如此；Windows 11 / Server 2022 預設也沒開） | **黑潮 DNS 自己聽 UDP 443**（三種模式都一樣） |
| HTTP.sys 開了 HTTP/3（Windows 11 / Server 2022，登錄檔 `HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters` 的 `EnableHttp3`） | 模式 B：HTTP.sys 自動提供；模式 C：IIS 提供、轉給黑潮 DNS；模式 A：不會發生（沒有 IIS 時不建議開） |
| UDP 443 被其他程式占用 | 改用其他 UDP 埠（`listen.doh.http3Port`，例如 8443），由下面的通知管道告訴用戶端 |

啟動時讀登錄檔並嘗試綁定 UDP 443，自動判斷屬於哪一種；結果顯示在設定頁（「DoH3：黑潮 DNS 提供 / HTTP.sys 提供 / 改用 UDP 8443 / 無法提供：原因」）。

實作：`/api/status` 的 `doh3Provider`（`provider`：`kuroshio` / `httpsys` / `none`，`reason`）。模式 B 而且 `EnableHttp3 = 1` 時
不綁 UDP（不管 `listen.doh.http3`，HTTP.sys 對所有登記的網址都提供 HTTP/3），`listenersDetail` 列出 `proto: doh3`、`bind: httpsys`；
其他情況照 `listen.doh.http3` 由黑潮 DNS 自己聽 `listen.doh.http3Port`（0 = 跟 DoH 同埠）。

### 2.3 讓用戶端知道有 DoH3

| 管道 | 做法 |
|---|---|
| Alt-Svc 標頭 | DoH 回應帶 `Alt-Svc: h3=":443"; ma=86400`（埠號依實際）。模式 A / B 由黑潮 DNS 加（只宣告真的有在聽的埠：自己的 UDP 沒綁成功就不加）；模式 B 由 HTTP.sys 提供 HTTP/3 時，登錄檔 `EnableAltSvc = 1` 表示 HTTP.sys 自己會送，黑潮 DNS 不重複加，沒開時黑潮 DNS 宣告 HTTP.sys 的埠；模式 C 寫在 `web.config` 的自訂標頭，確保 IIS 一定送出 |
| 網域的 HTTPS 記錄 | 用 DDNS 已有的 Cloudflare API 權杖，自動發布 `<網域> HTTPS 1 . alpn="h3,h2"`（有改埠號時加 `port=`）。瀏覽器第一次連線就直接用 HTTP/3。選項，預設跟著 DoH3 開關 |
| DDR | 區網裝置查 `_dns.resolver.arpa` 時列出 `alpn=h3`（規格 01 第 2 節） |
| 公開頁 | 列出 `h3://` 網址，給 AdGuard 這類可手動設定的 App |

## 3. 憑證

- 只申請一份（內建 ACME，Cloudflare DNS-01，不用開 80 埠）：
  - 存成 PEM：DoT、DoQ、DoH3（黑潮 DNS 自己監聽時）使用
  - 匯入 Windows「本機電腦\個人」存放區：模式 B 的 HTTP.sys 綁定、模式 C 的 IIS 站台綁定
- 續期（到期前 30 天）時自動重新匯入並更新綁定（HTTP.sys `sslcert`、IIS 站台綁定），舊憑證保留到新綁定生效後再移除。不再需要 2.x 的 `restart-dot.ps1`。
  - 實作（`iiscert.rs`）：IIS 與 HTTP.sys 共用同一段流程（`certutil -importPFX` → `netsh http delete/add sslcert hostnameport=<網域>:<埠>` → `certutil -delstore` 舊的）；
    IIS 用 IIS 的 appid、模式 B 用黑潮 DNS 自己的 appid；紀錄分別在 `state\iis-cert.json` / `state\httpsys-cert.json`。
    舊憑證還被另一種綁定使用時先不刪。執行中每 10 分鐘比對一次（設定了 `listen.doh.iisSite`，或這一輪是模式 B）
- 也可以用自己的憑證（`tls.certMode = manual`，指定 PEM 或存放區的指紋）。

## 4. 防火牆與網路

- 設定頁一鍵加入 Windows 防火牆規則：TCP / UDP 443、TCP / UDP 853、UDP / TCP 53（區網）；只加實際開啟的協議。
- 設定頁提醒：**家裡路由器的埠轉發也要加 UDP 443、UDP 853**（很多人只轉了 TCP，DoH3 / DoQ 就連不進來）。公開頁的「自我檢查」從外部測試各協議是否連得到。
- 53 埠被 Hyper-V / 網路連線共用（ICS）占用時，設定頁說明原因與處理方式。
- 一鍵把指定網卡的 DNS 改成 127.0.0.1 / ::1，還原時恢復原值（記錄在設定裡）。

## 5. 與 2.x（IIS + node）的遷移

1. 停用 2.x 的 IIS 站台規則與排程（`restart-dot.ps1`）、停止 node
2. `kuroshio.exe setup`，選模式（原本用 ARR 的可以先選 C，之後再換 B）
3. 2.x 的 `state\` 複製到 `%ProgramData%\kuroshio\state\`（格式相同）
4. 自訂規則 `自訂過濾規則.txt` 改名為 `custom-rules.txt` 放到同一個資料夾

## 6. 驗收

- CI（Windows runner）：cmd 執行、服務安裝 / 啟動 / 停止 / 移除、設定頁登入、DoH / DoT / DoQ / DoH3 查詢
- 實機（Windows 11 + IIS）：模式 B 與 C 各跑一次，IIS 其他網站照常；DoH3 在 HTTP.sys 有開 / 沒開 HTTP/3 兩種情況都能用
- 一般權限 cmd 執行：需要權限的項目失敗時程式照常運作，設定頁正確列出缺少的項目
- 主控台停止（3.5.0）：cmd 執行時關閉視窗、登出、關機、Ctrl+Break、Ctrl+C 五種，各看日誌最後幾行（「收到…，正常停止」「關機前寫出 N 份快照」「結束」）、
  花幾秒、下次啟動有沒有讀到快照；服務模式的停止與關機沒有變（回歸）。CI 沒辦法自動測「關閉視窗」
