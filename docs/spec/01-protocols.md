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

- **來源 IP**：`trustProxy` 時讀 `X-Forwarded-For`（同 2.x）。另外支援 PROXY protocol v2（⚙️，給前面有反向代理的情況）。
- **限制**：每個來源 IP 的同時連線數與每秒查詢數上限；TCP / TLS / QUIC 閒置逾時。

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
