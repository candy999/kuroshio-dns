# OpenWrt 套件

- `kuroshio/`：核心套件（Rust 單一執行檔，由 CI 先編好各 CPU 的版本再打包）
- `luci-app-kuroshio/`：LuCI 介面（「服務 → 黑潮 DNS」）
- `tools/`：CI 用的語法檢查、容器實機測試、LuCI 端對端測試

## 安裝

到 GitHub 的 **Actions → Kuroshio DNS (Rust)**（或 Releases）下載對應 OpenWrt 版本與 CPU 的套件：

| OpenWrt 版本 | 套件格式 | 安裝指令 |
|---|---|---|
| 24.10 | `.ipk` | `opkg update && opkg install ./kuroshio_*.ipk ./luci-app-kuroshio_*.ipk` |
| 25.12 以後 | `.apk` | `apk update && apk add --allow-untrusted ./kuroshio-*.apk ./luci-app-kuroshio-*.apk` |

相依套件（`ca-bundle`、`acme-acmesh`、`acme-acmesh-dnsapi`）會自動從官方套件庫安裝。不需要 node。

最低需求與各硬體等級見 [`docs/spec/05-resources.md`](../docs/spec/05-resources.md)。

## 從 2.x（candydns）升級

安裝 `kuroshio` 時會自動帶入 2.x 的設定、自訂規則、憑證、社群金鑰與狀態，但預設不啟用；
確認設定後在 LuCI 啟用，並停用 / 移除 `candydns`。
