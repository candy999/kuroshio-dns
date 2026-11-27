# 指令

[← 使用者指南](README.md)

讀設定的指令都可以用 `-c 設定檔` 指定 JSON 設定檔，OpenWrt 上加 `--uci` 改讀 `/etc/config/kuroshio`。指令的結束碼、`status --json` 的欄位見[整合文件](../integration.md#指令)。

## 執行與狀態

| 指令 | 說明 |
|---|---|
| `kuroshio run [-c 設定檔]` | 執行（設定檔只寫跟預設值不同的欄位） |
| `kuroshio health [--json] [--timeout 毫秒]` | 健康檢查：本機 DNS 有沒有在回答（結束碼 0 / 1 / 2） |
| `kuroshio status [--json]` | 執行中服務的狀態（`--json` 是給其他程式用的固定格式） |
| `kuroshio notify wan-changed` | 通知服務 WAN 變了：DDNS 立即檢查、重新偵測對外 IP、重新做路徑檢查 |
| `kuroshio notify save` | 立刻把學到的資料寫進儲存空間（Windows 要強制存檔用這個） |
| `kuroshio notify trim [--hold 秒]` | 先讓出記憶體（韌體要做很佔記憶體的事之前；預設 300 秒內不長大） |
| `kuroshio paths` | 設定、狀態、憑證、token 等檔案的位置 |
| `kuroshio url [--open]` | 設定頁、公開頁的網址與裝置要填的 DoH / DoT 位址 |
| `kuroshio about [--qr]` | 版本、授權、原始碼網址 |

## 設定

| 指令 | 說明 |
|---|---|
| `kuroshio defaults` | 印出完整預設設定 |
| `kuroshio check-config <檔案>` | 檢查設定檔並印出合併後的結果 |
| `kuroshio uci-migrate [UCI 檔] [--dry-run]` | UCI 設定檔升級遷移（不需要 uci 指令；第三方韌體升級後執行一次） |
| `kuroshio sysinfo [-c 設定檔]` | 偵測到的硬體、記憶體 / 儲存保留量、依 CPU 核心數換算的值 |
| `kuroshio memory-plan [--ram MB…] [--bits 32]` | 推算這台（或 64 / 128 / 256 / 512 MB 的機器）會怎樣運作 |

## 診斷

| 指令 | 說明 |
|---|---|
| `kuroshio query <網域> [-t 類型] [-s 伺服器]` | 查詢（診斷用，類似 dig） |
| `kuroshio check-path [--json]` | 路徑檢查：IPv6、一般 DNS 有沒有被接走（被誰）、協定被擋、TLS 攔截、能不能串接 |
| `kuroshio chain status [--json]` | 串接狀態：上游黑潮、指紋、共用結果、連上來的下游 |
| `kuroshio chain recheck` | 立刻重新做一次路徑檢查與串接探測（背景進行） |
| `kuroshio access check <IP>` | 這個 IP 能不能連進來、符合哪一條規則 |
| `kuroshio access groups` | 台灣 IP 群組（ISP）、大小、是否生效 |
| `kuroshio compare` | 2.x 與 3.0 並行比對（換版前驗證） |

## 資料、好友與憑證

| 指令 | 說明 |
|---|---|
| `kuroshio export [--share] [-o 檔案]` | 匯出學習資料（.kuroshio） |
| `kuroshio import <檔案>` | 匯入（合併） |
| `kuroshio community invite [--refresh]` | 顯示（或重新產生）我的好友邀請碼 |
| `kuroshio community join <邀請碼>` | 貼上好友的邀請碼加好友 |
| `kuroshio acme issue [--force]` | 內建 ACME 立即申請 / 續期 |
| `kuroshio cert-info` | 憑證資訊 |
| `kuroshio dnr` | DNR 要通告的內容（OpenWrt 接管腳本用） |

## Windows

| 指令 | 說明 |
|---|---|
| `kuroshio service install\|uninstall\|start\|stop\|status` | Windows 服務 |
| `kuroshio setup` | 防火牆規則、網址登記（系統管理員執行一次） |
| `kuroshio iis setup <站台> \| cert` | IIS 反向代理、憑證匯入與綁定 |
| `kuroshio httpsys status \| cert` | HTTP.sys 共用 443 |

在命令提示字元前景執行時，可以輸入 `help`、`url`、`open`、`site`、`status`、`paths`、`reload`、`quit`，直接取得設定頁與公開頁的網址。

## 訊號

| 平台 | 做法 |
|---|---|
| Linux / OpenWrt | `SIGHUP` 重新載入設定（同設定頁存檔），`SIGUSR1` 立刻寫出快照（不結束），`SIGTERM` 寫出快照後結束 |
| Windows | 沒有訊號：要立刻寫出快照用 `kuroshio notify save`，或設定頁「工具」的「立即儲存學習資料」 |

Docker、第三方路由器韌體等平台的整合方式（環境變數、系統時間沒對時的行為）見 [docs/integration.md](../integration.md)。
