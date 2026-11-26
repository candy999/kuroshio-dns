# 01 · 支援的協議

狀態：✅ 2.x 已有（Rust 版要對齊） · 🆕 3.0 新增 · ⚙️ 3.0 新增、預設關閉 · ⏸ 先不做

## 1. 傳輸協議

| 協議 | 標準 | 預設埠 | 伺服器端 | 上游 | 上游網址寫法 |
|---|---|---|---|---|---|
| 傳統 DNS，UDP | RFC 1035 | UDP 53 | ✅ | ✅ | `udp://1.1.1.1`、`1.1.1.1`、`[2606:4700::1111]:53` |
| 傳統 DNS，TCP | RFC 7766 | TCP 53 | ✅ | ✅ | `tcp://1.1.1.1` |
| DoT | RFC 7858 | TCP 853 | ✅ | ✅ | `tls://one.one.one.one` |
| DoH，HTTP/1.1 | RFC 8484 | TCP 443 | ✅ | ✅ | `https://…/dns-query`（協商不到 h2 時） |
| DoH，HTTP/2 | RFC 8484 | TCP 443 | 🆕 | 🆕 | `https://…/dns-query`（ALPN 優先 h2） |
| DoH3（HTTP/3） | RFC 8484 + 9114 | UDP 443 | 🆕 | 🆕 | `h3://…/dns-query`（只用 HTTP/3） |
| DoQ | RFC 9250 | UDP 853 | 🆕 | 🆕 | `quic://dns.adguard-dns.com` |
| DNSCrypt v2 | dnscrypt.info 規範 | 依伺服器 | ⏸ | 🆕 | `sdns://…`（DNSCrypt stamp） |
| DNS Stamps | dnscrypt.info 規範 | | 🆕 產生 | 🆕 解析 | `sdns://…`（DoH / DoT / DoQ / 傳統 stamp 也接受，轉成上面的網址） |
| ODoH | RFC 9230 | | ⏸ | ⏸ | 需要第三方中繼、公共服務少 |

### 1.1 伺服器端規則

- **DoH**：同一個 TCP 埠同時支援 HTTP/1.1 與 HTTP/2（ALPN `h2`、`http/1.1`）。路徑 `/dns-query`，GET `?dns=` 與 POST `application/dns-message`。
- **DoH3**：UDP，埠號預設跟 DoH 的 TCP 埠相同。DoH 的回應加上 `Alt-Svc: h3=":埠"; ma=86400`。
- **DoH 可以用任何埠號**（見 1.1.1）：443 被其他程式占用時（IIS、HTTP.sys、路由器的 LuCI…）改用例如 8443，網址寫成 `https://dns.example.net:8443/dns-query`，公開頁也在同一個埠。
- **DoT 與 DoQ**：共用埠號 853（DoT 是 TCP、DoQ 是 UDP）。
- **憑證**：DoH、DoH3、DoT、DoQ 共用同一張憑證；檔案變更 10 秒內自動換上（同 2.x 的 `watchCerts`）。
- **ALPN 對照**：

  | 埠 | ALPN | 交給 |
  |---|---|---|
  | TCP 853 | `dot` 或未指定 | DoT |
  | TCP 853 | `kuroshio/2` | 社群共享（見 03） |
  | UDP 853 | `doq` | DoQ |
  | UDP 853 | `kuroshio/2` | 社群共享（QUIC） |
  | TCP 443/8443 | `h2`、`http/1.1` | DoH / 公開頁 / 社群 `/.well-known/kuroshio` |
  | UDP 443/8443 | `h3` | DoH3 / 公開頁 / 社群 |

#### 1.1.1 DoH 的埠號

- **TCP**：`listen.doh.port` 可以是任何埠號；公開頁跟 DoH 共用同一個監聽，所以兩者的網址一定同埠。
- **DoH3（UDP）**：預設跟 DoH 用同一個數字（`listen.doh.http3Port = 0`）。只有那個 UDP 埠已經被占用時才另外指定（例如 Windows 的 HTTP.sys 開了 HTTP/3、或另一個 QUIC 服務聽著 UDP 443）。用戶端不用另外設定：從 DoH 回應的 `Alt-Svc: h3=":埠"`、或網域的 HTTPS 記錄知道有 HTTP/3、在哪個埠。
- **對外埠號**（`listen.doh.publicPort`，0 = 跟監聽的一樣）：外面看到的埠號跟本機監聽的不同時填（例如路由器把 WAN 443 轉到本機 8443；OpenWrt 開放外網、`wan_port` 跟 `port` 不同時自動帶入）。DoH 本身是明文、前面有反向代理時視為 443。`listen.doh.altSvcPort` 只改 Alt-Svc 宣告的 UDP 埠。
- 用到埠號的地方都跟著實際的埠：

  | 地方 | 埠號 |
  |---|---|
  | 公開頁的網址、複製按鈕、QR 碼、`/api/public/info`（`doh`、`dohPort`、`site`） | 瀏覽器連進來的埠（請求的 Host 標頭；沒帶埠號 = 443），Host 不是這個網域時用對外埠號 |
  | iPhone / Mac 描述檔（`DNSSettings` 的 `ServerURL`） | 同上：`https://網域:8443/dns-query`；DoT 描述檔沒有埠號欄位（固定 853），DoT 不在 853 時公開頁不提供 |
  | Windows 11 DoH 範本、瀏覽器、路由器 | 公開頁上的完整網址（帶埠號） |
  | Android「私人 DNS」 | **只支援 DoT、固定 853 埠**：只能填主機名稱，不能帶埠號、不能填 DoH 網址。DoT 不在 853 時公開頁直接說明不能用、改用瀏覽器（Chrome 的安全 DNS） |
  | `kuroshio url` / 主控台的 `site` | 對外網址帶埠號；DoT 不在 853 時註明 Android 不能用 |
  | DDR（SVCB `port=`）、DNR（`port=`） | 實際監聽的埠（區網裝置直接連本機）；DoH3 另外的 UDP 埠另外列一筆 `alpn=h3` |
  | `Alt-Svc: h3=":埠"` | `altSvcPort` → DoH3 跟 DoH 同埠時用 `publicPort` → DoH3 實際綁定的埠 |
  | Cloudflare HTTPS 記錄（DDNS） | 443：記錄在網域本身、`alpn="h3,h2"`；其他埠（例如 8443）：瀏覽器查的是 `_8443._https.網域`（RFC 9460 第 9.1 節），記錄放那裡、target 是網域、加 `port=8443`；DoH3 另外的 UDP 埠：`alpn="h3" no-default-alpn port=UDP 埠` |
  | 社群 `endpoints.doh` | OpenWrt 由 UCI 轉出（開放外網用 `wan_port`，否則用 `port`；443 不寫埠號）；JSON 設定檔照使用者寫的 |

- **來源 IP**：`trustProxy` 時讀 `X-Forwarded-For`（同 2.x）。另外支援 PROXY protocol v2（⚙️，給前面有反向代理的情況）。
- **限制**：連線數、每個來源的連線數、DoH 同時處理中的請求、每筆查詢的期限都有上限；TCP / TLS / QUIC 閒置逾時。見 1.1.2。

#### 1.1.2 過載保護：連線與請求的上限（3.5.1）

用意：一個來源、一波壓力不能把伺服器拖到「完全不回應」；超過上限就**立刻**拒絕或回 busy，不排隊；
壓力解除後**馬上**恢復，不需要人去處理（原則 5）。拒絕只看當下的計數：**沒有封鎖名單、沒有冷卻時間、不會越限越嚴**，
名額空出來的下一條連線、下一個請求就收。

| 上限 | 設定（`config.json` 的 `system`；OpenWrt 是 `config system` 的同名 snake_case 選項） | 預設（`auto`） | 超過時 |
|---|---|---|---|
| TLS 連線總數（DoT 與 DoH 的 TCP 連線合計） | `maxTlsConnections` | 每核 128（128–2048） | 新連線在 TLS 握手**之前**關閉（用戶端看到握手一開始就被關閉或重設）；已經建立的連線不受影響 |
| 每個來源的連線數（DoT 與 DoH 的 TCP 連線**共用一份**；IPv6 以 /64 算一個來源；本機不算） | `maxTlsConnectionsPerIp`（`max_tls_connections_per_ip`；`0` = 不限） | 總上限 ÷ 4，16–256（3.5.1 起；以前 ÷ 8、8–64） | 同上 |
| QUIC 連線總數（DoQ、DoH3 各自一份，每個監聽位址各一份） | `maxQuicConnections` | 每核 32（32–512） | 拒絕新連線；來源的連線數在握手完成後才算（同上的每個來源上限，另外一份），滿了用 `EXCESSIVE_LOAD` 關閉 |
| 記憶體（規格 09） | `memoryReserveMB` 等 | 偏低時新的加密連線最多 32 條，不足時不收 | 同上；區網的明文 DNS 照常 |
| DoH 同時處理中的請求（HTTP/1.1、HTTP/2、HTTP/3、HTTP.sys **共用一份**） | `maxDohInflight`（`max_doh_inflight`） | TLS 連線總上限 ÷ 2，64–1024 | **立刻**回 `503`、`Content-Type: text/plain`、內容 `busy`、`Retry-After: 1`，不排隊。POST 的內容讀完、要查詢時才佔名額（公開頁、社群不佔）；HTTP.sys 模式在接收的執行緒就判斷（記憶體不足時也回 busy） |
| 每條 DoT 連線處理中的查詢 | 固定 64 | | 先不讀下一筆，等回應送出 |
| 每條 HTTP/2 連線同時的請求、每條 QUIC 連線同時的串流 | 固定 64、128 | | 用戶端照協定等待 |
| 每筆查詢的期限（DoT、DoH、DoQ、DoH3、HTTP.sys） | 固定 10 秒（`QUERY_DEADLINE`；查詢工作本身另有 12 秒總期限，規格 06 第 2.3 項） | | 回 SERVFAIL（DoH 是 `200` + `cache-control: max-age=0`），名額馬上還回來 |
| 讀一筆查詢的內容、HTTP 標頭、POST 內容 | 固定 10 秒 | | 關閉連線／`408` |

名額一定還回來（RAII）：連線與請求的名額跟著處理它的工作，正常結束、錯誤、逾時、握手失敗、被重設、panic、用戶端放棄都會歸還。

- **DoT 連線被重設、讀寫失敗、對方不收回應**：處理中的查詢**立刻取消**，連線的名額馬上還回來。3.5.0 以前要等這條連線的每一筆查詢都結束才還：
  卡住的查詢讓已經斷掉的連線一直佔著這個來源的名額，用戶端重新連線時被「每個來源的上限」拒絕，而且比例隨著卡住的查詢越積越高。
  對方只關閉寫的那一邊（還在等回應）或閒置逾時時，處理中的照常回完（每筆最多 10 秒）。
- **DoH 用戶端放棄**：HTTP/2 的 `RST_STREAM`、連線斷掉時，處理中的請求被丟掉、名額馬上還回來；HTTP/1.1 與 HTTP.sys 看不到用戶端放棄，最多等到每筆查詢的期限（10 秒）。
- **為什麼 DoQ 不受 DoH／DoT 的上限影響**：DoQ（與 DoH3）的連線名額是另一份（`maxQuicConnections`），而且一條 QUIC 連線裡可以同時送很多筆，
  已經連上的不必再開新連線。3.5.0 以前 HTTP.sys 模式的 DoH **每個請求**都佔一個 TLS 連線名額：處理不完的 DoH 請求把名額佔滿時，
  DoH 回 `busy`、DoT 的新連線被關閉，但 DoQ 照常（3.5.1 起 DoH 的請求改用自己的上限，不再佔 TLS 連線名額）。

日誌與計數：拒絕新連線、回 busy、查詢逾時都會寫 WARN，寫出協定、來源、原因、目前的上限與怎麼調；**同一類每分鐘最多一行**（中間的只計數，下一行寫「上一行之後又有幾次」）。
累計次數在 `/api/status` 的 `perf.server`：`refused.{dot,doh,doq,doh3}.{total,perSource,memory}`（新連線被拒絕：總數滿、這個來源滿、記憶體）、
`dohBusy`（DoH 回 503 busy）、`deadline`（查詢超過 10 秒回 SERVFAIL）、`httpsysBodyBusy`（HTTP.sys 讀請求內容的執行緒都在忙）。

CGNAT、公司、學校共用一個對外 IP 時：一台手機的「私人 DNS」平常只開 1～2 條 DoT 連線，預設的每個來源上限（四核心 128 條）大約夠幾十台裝置。
不夠時調大 `maxTlsConnectionsPerIp`（或 `0` 不限），同時確認 `maxTlsConnections` 夠大；每條連線約 30–60 KB 記憶體。

### 1.2 上游規則

- **id**：上游的 id 就是正規化後的網址字串（同 2.x），統計、評測、社群都用這個 id。
- **`https://`**：先用 HTTP/2；回應帶 `Alt-Svc: h3` 時記下來，但**不自動換**。DoH3 另外當成一個獨立上游 `h3://` 參加評測，誰快用誰。
- **bootstrap**：DoH / DoT / DoQ / DoH3 的主機名稱用 bootstrap 傳統 DNS 解析（同 2.x），結果快取至少 300 秒，過期也先用舊的。
- **連線重用**：DoT / DoH2 / DoH3 / DoQ 都保持持久連線；DoT 用管線化（pipelining），DoQ / DoH2 / DoH3 用多工串流。
- **0-RTT**：只對上游啟用（DoQ / DoH3 / TLS 1.3 session resumption）；伺服器端不接受 0-RTT 資料，避免重放。
- **評測類型**：`upstream.autoTypes` 擴充為 `udp, tcp, dot, doh, doh3, doq, dnscrypt`。預設 `udp, doh, doh3, dot, doq`。
- **評測名單檔**（`benchmark/`）：

  | 檔案 | 內容 | 狀態 |
  |---|---|---|
  | `iplist.txt` | 傳統 DNS IP | ✅ |
  | `dohlist.txt` | DoH 網址；每一筆同時測 h2 與 h3 | ✅ 擴充 |
  | `doqlist.txt` | DoQ 網址（2.x 在 Windows 靠外部 `q.exe` 測；3.0 內建，不再需要 `q.exe`） | ✅ 改內建 |
  | `dotlist.txt` | DoT 主機 | 🆕 |
  | `stamps.txt` | `sdns://` stamp（DNSCrypt 等） | 🆕 |
  | `web.txt`、`blacklist.txt` | 檢查用網站、永久黑名單 | ✅ |
  | `protected.txt` | 對照組：有過濾的大型 DNS（任何類型），後面 `filter=` 是預期會擋的類型；照常測、照常判，永遠不選、不算覆蓋、不參加多數決、不記可疑、不看也不進永久黑名單；最多 64 台；結果在 `upstreams.json` 的 `protected`（`detected` 判出過濾、`passed` 沒判出、`untested` 沒測到）與報表的 `protected.csv` | 🆕 3.4.2 |

  名單標記（3.5.0）：行內 `# tier=A op=… ms=… ecs=1`（`iplist.txt` 寫在位址的上一行：`# A <經營者>（AS…）… 3.9 ms ECS`），分段行 `# ---- A 級 ----` 是那一段的預設分級。解析在 `kuroshio-jobs/src/benchmark/tags.rs`，候選帶著標記走完評測（只輸出，不跳過任何檢查）；欄位見 [整合文件](../integration.md#每日評測與預設名單350-起)。

## 2. 自動發現

| 標準 | RFC | 狀態 | 行為 |
|---|---|---|---|
| DDR | 9462、9461 | ⚙️（DoH / DoT / DoQ 任一開啟時可開） | 回答 `_dns.resolver.arpa` 的 SVCB 查詢，列出本機開啟的加密協議（`alpn=h2,h3` + `dohpath`、`alpn=dot`、`alpn=doq`）、埠、網域。只回答區網來源 |
| DNR | 9463 | ⚙️（OpenWrt） | 由 `lan.sh` 寫入 odhcpd 的 DNR 設定（odhcpd 版本支援才顯示選項）；核心只提供網域與埠資訊 |

DDR 注意事項：
- 正式的「驗證式發現」要求憑證包含解析器的 IP，公開 CA 不會發私有 IP 的憑證。
- 對私有 IP 解析器，部分平台（例如 Apple 系統）採「機會式發現」，不需要 IP 憑證；其他平台的行為要實測，結果寫進 README。

## 3. DNS 訊息層

| 功能 | RFC | 狀態 | 規則 |
|---|---|---|---|
| EDNS(0) | 6891 | ✅ | 對上游統一 1232 bytes（同 2.x 的 `rebuildQuery`） |
| ECS | 7871 | ✅ | CDN 台灣節點核心；`resolver.sendEcs`、`cdn.ecs` 行為不變 |
| HTTPS / SVCB 記錄 | 9460 | ✅ | 改寫 `ipv4hint` / `ipv6hint`（同 2.x `dnsmsg.js`） |
| ECH 設定移除 | 9460 / ECH | ⚙️ | 選項 `resolver.stripEch`：移除 HTTPS 記錄的 `ech` 參數。預設保留 |
| Extended DNS Errors | 8914 | 🆕 | 過濾攔截回應加 EDE：廣告 / 遙測 `17 Filtered`、惡意 `15 Blocked`，附文字（分類與命中規則）；上游全失敗 `22 No Reachable Authority`；回舊快取 `3 Stale Answer` |
| EDNS Padding | 7830、8467 | 🆕 | 加密連線（伺服器端回應與上游查詢）用 8467 建議的區塊長度補齊（查詢 128、回應 468） |
| DNS Cookies | 7873 | ⚙️ | 對外開放 UDP 53 時建議開啟 |
| TCP keepalive | 7828 | 🆕 | 伺服器端 TCP / DoT 支援 |
| DNSSEC 驗證 | 4033–4035 | ⚙️ | 本機驗證上游回應。被 CDN 置換或過濾改寫的回應一律不標 AD；DO 位元照 2.x 規則傳遞 |
| 特殊用途網域 | 6761、7686 | ✅ | 3.5.1，`resolver.specialUse`（預設開）：`.invalid`、`.test`、`.onion`、`.example`（含頂級網域本身）在本機回 NXDOMAIN；`localhost` 與底下的名稱 A 回 `127.0.0.1`、AAAA 回 `::1`（TTL 1 小時）、其他類型空答案。不問上游、不過濾、不快取、不算進熱門網域與公開頁的網站排行（計在「本機回答」），開機預熱名單也不收。順序：`version.kuroshio`、串接、DDR 之後，**本地網域轉發（`resolver.localForward`）之後**——區網真的有這些網域時照轉；Windows 等沒有本地轉發的環境可以關掉這個選項。只看最後一段，查詢路徑上只多一次字串比較。`example.com`、`example.net` 是一般網域，照常解析。以前這些名稱都送去問上游（結果一樣是不存在），外部探測的 `.invalid`、`.test` 名稱也進了排行 |

## 4. 攔截回應格式（不變）

延續 2.x：A 回 `0.0.0.0`、AAAA 回 `::`、HTTPS / SVCB 回空答案，其他類型回空答案；TTL 依 2.x 設定。3.0 只多加 EDE。

## 5. 對外開放時的防火牆（OpenWrt）

`open_wan` 開啟時，`takeover.sh` 新增的規則：

| 協議 | 規則 |
|---|---|
| DoT | WAN TCP 853 → 本機 853（✅） |
| DoQ | WAN UDP 853 → 本機 853（🆕） |
| DoH | WAN TCP 443 → 本機 8443（✅） |
| DoH3 | WAN UDP 443 → 本機 8443（🆕） |
