# 網域、憑證與 DDNS

[← 使用者指南](README.md)

要對外提供加密 DNS（DoT / DoH / DoQ / DoH3）、公開頁或社群共享，需要一個網域與涵蓋它的憑證。

- **固定網域**：只填 `domain` 就能用，不需要 DDNS。
- **憑證**：內建 Let's Encrypt（Cloudflare DNS 驗證，不用開 80 埠），或用自己的憑證。
- **浮動 IP**：用內建的 Cloudflare DDNS。

## 設定

| 設定鍵 | 預設 | 說明 |
|---|---|---|
| `domain` | 空 | 這台的網域，例如 `dns.example.net` |
| `tls.cert` / `tls.key` | 空 | 自己的憑證與私鑰（程式只讀不寫） |
| `acme.enabled` | `false` | 內建 ACME（Let's Encrypt，Cloudflare DNS 驗證） |
| `acme.renewDays` | `30` | 到期前幾天續期 |
| `ddns.enabled` | `false` | Cloudflare DDNS |
| `ddns.ipv4` / `ddns.ipv6` | `true` / `false` | 發布 A／AAAA；IPv6 預設不發布，要用再開 |
| `ddns.httpsRecord` | `true` | 順便發布 HTTPS 記錄 |
| `ddns.interfaces` | 空 | 多網卡、多出口：每張網卡各自偵測 IP |

## 憑證

- **內建 ACME**：Windows 版用內建的（`kuroshio acme issue [--force]` 立即申請 / 續期）；OpenWrt 用 acme.sh；其他平台自備憑證，或交給前面的反向代理（見 [Docker 使用說明](../docker.md)）。
- **自備憑證**：放在 `tls.cert` / `tls.key`，程式只讀不寫。
- 設定頁顯示憑證主體、到期日、是否涵蓋網域；指令列是 `kuroshio cert-info`。
- Windows 的 IIS／HTTP.sys 憑證匯入與綁定見 [Windows 使用說明](../windows.md)。

## Cloudflare DDNS

- 多網卡、多出口：每張網卡各自偵測 IP，同一個名稱可以發布多個 IP。
- IPv6（AAAA）預設不發布，要用再開。
- 可以順便發布 HTTPS 記錄，讓瀏覽器第一次連線就用 HTTP/3。
- WAN 變了時，`kuroshio notify wan-changed` 讓 DDNS 立即檢查。

## 存放位置一覽

設定頁與 `kuroshio paths` 列出設定、狀態、憑證、token 等檔案的位置，方便其他服務共用憑證（不顯示密鑰內容）。
