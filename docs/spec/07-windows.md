# 07 · Windows 版

Windows 版跟 OpenWrt 版是同一個核心程式（`kuroshio.exe`），差別只在平台層：服務管理、本機設定頁、憑證存放、跟 IIS 共存。

## 1. 執行方式

同一個執行檔、同一份設定，兩種方式功能完全相同（DNS、DoH、DoT、DoQ、DoH3、設定頁、公開頁、CDN 置換）。

| | cmd 直接執行 | Windows 服務 |
|---|---|---|
| 指令 | `kuroshio.exe run [-c config.json]` | `kuroshio.exe service install` / `uninstall` / `start` / `stop` |
| 啟動 | 手動 | 開機自動啟動，不用登入 |
| 關閉 | 關視窗或 Ctrl+C（Ctrl+C 會正常收尾、寫出快照） | 不受登出、關視窗影響 |
| 當掉 | 不會自動重啟 | 自動重啟（服務復原設定） |
| 日誌 | 直接顯示在視窗 | 日誌檔，設定頁「日誌」分頁可看 |
| 適合 | 測試、臨時用、攜帶版 | 長期 24 小時運作 |

- **可以切換**：先用 cmd 測試，再 `service install`，沿用同一份設定與資料。
- **攜帶版**：`kuroshio.exe` 旁邊有 `config.json` 時，設定與資料都放在執行檔所在的資料夾（可以放隨身碟）；沒有的話用 `%ProgramData%\kuroshio\`。
- 啟動時在日誌與設定頁顯示：執行方式（cmd / 服務）、設定來源、是否有系統管理員權限。

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

#### 模式 B：HTTP.sys 共用
- 登記的網址（只登記自己的，IIS 其他網站不受影響）：`https://<網域>:443/dns-query`、`https://<網域>:443/.well-known/kuroshio`、公開頁開啟時加上 `https://<網域>:443/`（同一網域的其他路徑仍可由 IIS 處理時，改登記公開頁的實際路徑）
- TLS 由 HTTP.sys 處理：憑證匯入「本機電腦\個人」存放區，用 `hostnameport`（SNI）綁定到 `<網域>:443`
- 用戶端 IP 直接取得（不需要 X-Forwarded-For）
- HTTP.sys 開了 HTTP/3 時，登記的網址自動支援 DoH3
- 優點：不用安裝 ARR / URL Rewrite、少一層轉送、延遲低；TLS 與 HTTP/2 由核心處理

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

### 2.3 讓用戶端知道有 DoH3

| 管道 | 做法 |
|---|---|
| Alt-Svc 標頭 | DoH 回應帶 `Alt-Svc: h3=":443"; ma=86400`（埠號依實際）。模式 A / B 由黑潮 DNS 加；模式 C 寫在 `web.config` 的自訂標頭，確保 IIS 一定送出 |
| 網域的 HTTPS 記錄 | 用 DDNS 已有的 Cloudflare API 權杖，自動發布 `<網域> HTTPS 1 . alpn="h3,h2"`（有改埠號時加 `port=`）。瀏覽器第一次連線就直接用 HTTP/3。選項，預設跟著 DoH3 開關 |
| DDR | 區網裝置查 `_dns.resolver.arpa` 時列出 `alpn=h3`（規格 01 第 2 節） |
| 公開頁 | 列出 `h3://` 網址，給 AdGuard 這類可手動設定的 App |

## 3. 憑證

- 只申請一份（內建 ACME，Cloudflare DNS-01，不用開 80 埠）：
  - 存成 PEM：DoT、DoQ、DoH3（黑潮 DNS 自己監聽時）使用
  - 匯入 Windows「本機電腦\個人」存放區：模式 B 的 HTTP.sys 綁定、模式 C 的 IIS 站台綁定
- 續期（到期前 30 天）時自動重新匯入並更新綁定（HTTP.sys `sslcert`、IIS 站台綁定），舊憑證保留到新綁定生效後再移除。不再需要 2.x 的 `restart-dot.ps1`。
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
