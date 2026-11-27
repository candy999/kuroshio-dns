# 使用者指南

[← 回首頁](../../README.md)

每一份先說「這是什麼、預設怎樣、什麼時候要調」，接著是設定項目，最後才是運作細節。各版的變化在 [Release 說明](../release-notes/README.md)。

## 開始用

| 文件 | 內容 |
|---|---|
| [安裝與升級](install.md) | OpenWrt、Windows、Docker、其他 Linux、第三方韌體；第一次啟動、升級、支援平台 |
| [指令](commands.md) | `kuroshio` 的所有指令與訊號 |
| [選硬體](../hardware.md) | 依預算推薦的機種；舊機的資料在[各機種刷機資料](../hardware-details.md) |

## 功能

| 文件 | 內容 |
|---|---|
| [把連線帶回台灣](cdn.md) | CDN 節點置換：辨識 CDN、台灣節點池、逐站驗證、跨 CDN、小機器減量 |
| [自動挑上游](upstreams.md) | 每日評測、預設名單與分級、惡意網站探測、汙染判斷、執行時的並行與暫停 |
| [路徑檢查](path-check.md) | 一般 DNS 被接走、「不存在」被改寫、協定被擋、TLS 攔截 |
| [串接模式](chain.md) | 兩台黑潮前後接著：自動認出、共用結果、直系血親 |
| [過濾](filtering.md) | 訂閱清單、自訂規則、內建一定通過的服務 |
| [快取與本機回答](cache.md) | 快取上限、預熱、斷線回舊資料、特殊用途網域 |
| [加密 DNS 與現代協議](protocols.md) | DoT / DoH / DoQ / DoH3、DDR / DNR、任何埠號、過載保護 |
| [只開放台灣](access.md) | 來源 IP 存取控制、台灣 IP 清單 |
| [好友互助](community.md) | 邀請碼、好友給的資料怎麼用、資料品質 |
| [備份、換機與分享](backup.md) | 完整備份、分享檔、匯入怎麼合併 |
| [網域、憑證與 DDNS](domain-acme-ddns.md) | 固定網域、Let's Encrypt、自備憑證、Cloudflare DDNS |
| [公開頁與儀表板](dashboard.md) | 共用儀表板、CDN 連線去向、給親友的公開頁 |
| [記憶體、Flash 與可靠性](memory-and-reliability.md) | 保留量與依序讓出、用量估算、Flash 保護、重新載入不斷線、排程與補跑 |
| [隱私與安全](privacy.md) | 黑潮連到哪裡、管理介面的保護 |

## 更深入

- [核心理念與設計原則](../principles.md)：為什麼這樣設計。
- [整合文件](../integration.md)：指令的結束碼、`/api/status` 的欄位、環境變數（給其他平台與韌體）。
- [規格](../spec/README.md)：給開發者。
- [建置說明](../building.md)：自己編、跨 CPU 編譯。
