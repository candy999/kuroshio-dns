# 加密 DNS 與現代協議

[← 使用者指南](README.md)

黑潮可以架 DoT / DoH / DoQ / DoH3 給手機、筆電在外面用；區網裝置透過 DDR / DNR 自動升級成加密連線。

- **預設**：只開一般 DNS（區網）；加密監聽要有網域與憑證（見[網域、憑證與 DDNS](domain-acme-ddns.md)）才開。
- **對外開放時**：預設只讓台灣的 IP 連進來（見[只開放台灣](access.md)）。
- **什麼時候要調**：443 被占用時改用別的埠；用戶端多（CGNAT、學校）時調大每個來源的連線上限。

## 支援的協議

| 協議 | 伺服器 | 上游 |
|---|---|---|
| 傳統 DNS（UDP / TCP） | ✓ | ✓ |
| DoT（DNS over TLS） | ✓ | ✓ |
| DoH（HTTP/1.1、HTTP/2） | ✓ | ✓ |
| **DoH3**（HTTP/3） | ✓ | ✓ |
| **DoQ**（DNS over QUIC） | ✓ | ✓ |

- **DDR**（RFC 9462）：裝置來問「這台有沒有加密 DNS」時，告訴它 DoH / DoT / DoQ 的位址，自動升級成加密連線。
- **DNR**（RFC 9463，OpenWrt）：路由器直接用 DHCP / RA 通告加密 DNS，裝置不用手動設定。需要網域、涵蓋網域的有效憑證、加密監聽聽得到區網位址才會發（寧可不發，也不發連不上的）。`kuroshio dnr` 印出要通告的內容。
- EDNS Padding、EDE；UDP 截斷依裝置宣告的大小處理。
- DNSCrypt 不支援：採用的伺服器少，而且都同時提供 DoH / DoT。

## 設定

| 設定鍵 | 預設 | 說明 |
|---|---|---|
| `listen.doh.enabled` / `listen.dot.enabled` / `listen.doq.enabled` | `false` | 各協議的開關 |
| `listen.doh.port` | `8053` | DoH 的埠（OpenWrt 開放外網時自動設定） |
| `listen.doh.http3` | `false` | 同時提供 DoH3 |
| `listen.doh.http3Port` | `0` | DoH3 另外指定 UDP 埠（`0` ＝ 跟 DoH 同一個數字） |
| `listen.doh.publicPort` | `0` | 路由器把外面的 443 轉到本機其他埠時，填外面看到的埠 |
| `listen.<協議>.binds` | 空 | 同時監聽多個位址（設定頁從本機網卡位址挑） |
| `listen.ddr` | `false` | DDR 自動發現 |
| `system.maxTlsConnectionsPerIp` | `auto` | 每個來源最多幾條 DoT／DoH 連線（OpenWrt：`max_tls_connections_per_ip`；`0` ＝ 不限） |
| `system.maxDohInflight` | `auto` | DoH 同時處理中的請求上限 |

## DoH 可以用任何埠號

- 443 被占用時改用例如 8443，網址寫成 `https://dns.example.net:8443/dns-query`，公開頁也在同一個埠。
- 公開頁的網址、QR 碼、iPhone 描述檔、Windows 範本、`kuroshio url`、Alt-Svc、Cloudflare HTTPS 記錄都跟著帶埠號。
- DoH3 預設用同一個數字的 UDP 埠，只有那個 UDP 埠被占用時（例如 HTTP.sys 開了 HTTP/3、或另一個 QUIC 服務）才用 `listen.doh.http3Port` 另外指定；用戶端從 Alt-Svc 或 HTTPS 記錄知道 HTTP/3 在哪裡。
- 路由器把外面的 443 轉到本機其他埠時填 `listen.doh.publicPort`（OpenWrt 開放外網時自動帶入）。
- 注意 Android「私人 DNS」只支援 DoT、固定 853 埠（不能帶埠號、不能填 DoH 網址），公開頁會說明。

## 多位址監聽

`listen.<協議>.binds` 可以同時監聽多個位址，設定頁從本機網卡位址挑選，並顯示每個位址是否綁定成功。

## 過載保護

| 情況 | 黑潮怎麼做 |
|---|---|
| DoH 同時處理中的請求滿了（`system.maxDohInflight`，`auto` ＝ TLS 連線上限的一半，64～1024） | 立刻回 `503 busy`（帶 `Retry-After: 1`），不排隊 |
| 一筆查詢超過 10 秒 | 回 SERVFAIL，名額馬上還回來 |
| 用戶端放棄（HTTP/2 取消、連線斷掉、連線被重設） | 處理中的查詢立刻取消，名額馬上還回來 |
| 同一個來源的連線太多（預設總上限的 1/4、16～256 條：單核心 32、雙核心 64、四核心 128、八核心以上 256） | 在 TLS 握手之前關閉新連線，已經建立的不受影響 |

- 黑潮**沒有**針對來源 IP 的封鎖名單、冷卻時間或錯誤計數，拒絕只看「當下」的名額，壓力解除後最多 10 秒內恢復。
- 拒絕新連線、回 `busy`、查詢超過 10 秒都會寫 WARN（協定、來源、原因、目前的上限與怎麼調），同一類每分鐘最多一行；累計在 `/api/status` 的 `perf.server`。
- 上限與行為細節：[規格 01 第 1.1.2 節](../spec/01-protocols.md#112-過載保護連線與請求的上限351)。
