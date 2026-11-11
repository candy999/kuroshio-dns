# 黑潮 DNS（Kuroshio DNS）

> 像黑潮把魚群帶到台灣，把你的連線帶回台灣節點。

為台灣網路環境打造的 DNS 伺服器。CDN 常把台灣使用者導到東京、香港的節點，黑潮 DNS 會找出真正在台灣的節點、驗證可用後把連線帶回來，同時過濾廣告、遙測與詐騙網站。

用 Rust 寫成的單一執行檔，不需要任何執行環境：裝在 OpenWrt 路由器上用 LuCI 設定，或在 Windows 上當成服務、用本機網頁設定。

## 特色

### 把連線帶回台灣
- **CDN 台灣節點置換**：辨識 Cloudflare、Fastly、CloudFront、Azure、Gcore 等 CDN，換成實際驗證過的台灣節點（TPE / KHH）。
- **先驗證再使用**：每個網站都會用 HTTPS 實際連線確認，節點池每天實測延遲、POP 與下載速度。
- **ECS 與跨 CDN 備援**：用台灣網段向 CDN 詢問；某一家沒有台灣節點時，自動試同網站的其他 CDN。
- **IPv6 節點**：永久保存驗證過的台灣 IPv6 節點。

### 自動挑最快的上游
- **並行查詢**：同時問多個上游，最快的回答勝出；IP 測速挑出最快的位址。
- **每日評測**：自動測試公共 DNS 的速度、汙染與封殺，選出當天最好的組合。
- **快取**：熱門網域在過期前自動更新；重開機後自動預熱常用網域；外網斷線時先回舊資料，常用網站照樣連得上。

### 過濾
- **廣告、遙測、惡意 / 詐騙** 三種分類，一層一層往上疊；同一個網域出現在多份清單只算一次。
- 支援 AdGuard 與 hosts 語法、檢查 CNAME 鏈；hosts 裡寫的 IP 一律不採用。
- 內建台灣清單（詐騙、內容農場、低品質網站）。
- **自訂規則永遠優先**，可以用 `! @begin 分類` / `! @end` 把規則分段歸類。
- 被擋時回傳 Extended DNS Errors，裝置與日誌看得到原因。

### 現代協議

| 協議 | 伺服器 | 上游 |
|---|---|---|
| 傳統 DNS（UDP / TCP） | ✓ | ✓ |
| DoT（DNS over TLS） | ✓ | ✓ |
| DoH（HTTP/1.1、HTTP/2） | ✓ | ✓ |
| **DoH3**（HTTP/3） | ✓ | ✓ |
| **DoQ**（DNS over QUIC） | ✓ | ✓ |

另外支援：
- **DDR**（RFC 9462）：裝置來問「這台有沒有加密 DNS」時，告訴它 DoH / DoT / DoQ 的位址，自動升級成加密連線
- **DNR**（RFC 9463，OpenWrt）：路由器直接用 DHCP / RA 通告加密 DNS，裝置不用手動設定。
  需要網域、涵蓋網域的有效憑證、加密監聽聽得到區網位址才會發（寧可不發，也不發連不上的）
- EDNS Padding、EDE（說明為什麼被攔截）；DNSSEC 的 DO 位元照實轉送給上游（不在本機驗證：改寫成台灣節點的答案本來就無法帶簽章）

DNSCrypt 不支援：採用的伺服器少，而且都同時提供 DoH / DoT。

### 好友互助（社群共享）
- 跟朋友的路由器互加好友，交換台灣節點、網站驗證結果、好用的上游。
- 每則訊息都有 Ed25519 簽名，收到的資料一定在本機驗證後才使用；只分享網域雜湊，不公開網站名稱。
- 增量同步、自動規則（電信業者、延遲、共同好友…）、資料品質評分、封鎖與拒絕。

### 只開放台灣（來源 IP 存取控制）
- **預設只讓台灣的 IP 連進 DoH / DoT / DoQ / DoH3 與公開頁**：依 ISP 分組（中華電信、台灣大、遠傳、亞太、台灣之星、凱擘、中嘉、台灣寬頻、其他有線寬頻、TANet、政府網路、其他台灣網段），可以只勾其中幾家，或切成「全開放」。
- 自訂允許 / 封鎖的 IP 或網段（封鎖勝過一切）；區網、私有位址、本機網段、社群好友目前的 IP 永遠允許。
- 擋在最前面：TCP 在 accept 時就關閉（不做 TLS 握手），QUIC 在握手前就忽略；OpenWrt 另外產生 nftables 集合，在核心層就丟掉 WAN 來的封包。
- 台灣 IP 清單 `data/geo/tw-ip.json` 由 RIR 配發資料（cc=TW）與各 ISP 的 BGP 宣告產生，GitHub Actions 每月更新；也可以開 `access.autoUpdate` 每天自動下載。
- **這是 3.0 的行為改變**：沒有 `access` 設定的舊設定檔也會套用「只開放台灣」。人在國外、漫遊、用 VPN 的親友會連不上，請改成 `access.mode = "open"` 或把他們的 IP 加進 `access.allow`。
- 限制：應用層過濾擋不了塞滿對外頻寬的流量型 DDoS（那要靠 ISP 或 Cloudflare 之類的服務）；行動網路的網段常變動，所以每月更新。詳見 [規格 08](docs/spec/08-access.md)。

### 系統整合
- **OpenWrt**：五種 DNS 接管方式（不接管、dnsmasq 上游、重定向、積極劫持、取代 dnsmasq），IPv4 / IPv6 分開處理並自動建立 ULA；停用時自動還原。
- **Windows**：Windows 服務、本機設定頁、一鍵設定網卡 DNS 與防火牆。
- **公開頁**：可以開一個設定說明頁給親友，依實際開啟的協議產生 iPhone 描述檔、Android 私人 DNS、Windows 設定方式。
- **憑證與 DDNS**：Let's Encrypt（Cloudflare DNS 驗證，不用開 80 埠）、Cloudflare DDNS。
- **固定網域與自備憑證**：只填 `domain` 就能用固定網域（不需要 DDNS）；把憑證放在 `tls.cert` / `tls.key` 就不需要 ACME（程式只讀不寫）。`kuroshio paths` 列出設定、狀態、憑證、token 等檔案的位置。
- **多網卡**：`ddns.interfaces` 選擇要發布的出口，同一個名稱可以有多個 IP；IPv6（AAAA）預設不發布，要用再開 `ddns.ipv6`。`listen.<協議>.binds` 可以同時監聽多個位址。
- **輕量**：執行檔約 1.2 MB；128 MB 的路由器也能跑（見下方硬體需求）。

## 硬體需求

| | 最低 | 建議 | 全部功能 |
|---|---|---|---|
| 記憶體 | 128 MB | 256 MB | 512 MB 以上 |
| Flash | 16 MB（安裝後剩 4 MB 以上） | 32 MB 以上或 NAND | 128 MB 以上，或外接儲存 |
| CPU | MIPS 24Kc 單核 ~575 MHz | 雙核（MT7621、Cortex-A53） | ARMv8 四核、x86 |

**依硬體自動調整**：啟動時偵測記憶體，分成 tiny（< 200 MB）、small、standard、large（≥ 1.5 GB）四級，低階機器自動調低快取、同時連線數、背景工作規模，並停用太重的功能（例如 tiny 不開 DoQ / DoH3、不做網段掃描、大型過濾清單超過記憶體預算就不載入）。你在設定檔寫了的值一律以你的為準。
`kuroshio sysinfo` 可以看到偵測結果與被調整的項目。

**保護 Flash**：常變動的資料（統計、查詢紀錄、快取、清單原始檔）只放記憶體；節點池、驗證紀錄這些重要資料在 Flash 上最少 6 小時才寫一次（記憶體越多、留在記憶體越久）、內容沒變不寫、壓縮後才寫（約 1/5–1/8），CDN 驗證紀錄分成多個小檔、只重寫有變動的那幾個，關機時一定寫出。

**會不會把 Flash 寫壞？要不要為了 Flash 少開功能？** 不用。功能照用，寫入量跟著實際用量走：一般家庭每天約 1–2 MB（16 MB 的 NOR Flash 照這個量寫一百年也用不完抹寫次數）。每天的寫入量有目標（`system.flashWriteBudgetKB`），超過就延後；但學到的資料最久 24 小時（`system.persistMaxAgeHours`，可以調小）一定會存，不會因為路由器常斷電就一連好幾天的資料都沒存。儲存空間快滿時先刪日誌與可以重建的資料，CDN 驗證紀錄、節點、社群身分這些核心資料絕不自動刪除。

**記憶體**：過濾清單用緊湊結構，每個網域約 9 bytes（預設清單約 16 萬條 ≈ 1.5 MB；105 萬條的 HaGeZi ≈ 10 MB）；看門狗在記憶體不足時自動縮小快取、暫停背景工作。

詳見 [資源預算規格](docs/spec/05-resources.md)。

## 支援平台

| 平台 | CPU |
|---|---|
| OpenWrt 24.10（ipk）、25.12 以後（apk） | x86_64、i386、aarch64（generic / Cortex-A53 / Cortex-A72）、ARMv7（Cortex-A7 / A9 / A15）、**MIPS / MIPSel**（24Kc） |
| Windows 10 / 11 | x86_64 |
| 其他 Linux | 上面所有 CPU 的靜態執行檔 |

## 開發進度

| 功能 | 狀態 |
|---|---|
| 區網 UDP / TCP、並行上游、來源存取控制、診斷指令 `query` | ✅ 可用 |
| 硬體分級與自動調整、Flash 寫入保護、記憶體看門狗、`sysinfo` | ✅ 可用 |
| 快取（自適應預取、開機預熱、斷線回舊資料）、並行上游、IP 測速、管理 API | ✅ 可用 |
| 各平台自動編譯（OpenWrt 套件、Windows、靜態執行檔） | ✅ |
| DoT / DoH 上游（持久連線、HTTP/2）、OpenWrt UCI 設定轉換、清單下載 | ✅ 可用 |
| 過濾引擎（緊湊結構、自訂規則優先、存檔 3 秒生效、與 2.x 對照 5,548 筆一致） | ✅ 可用 |
| CDN 台灣節點（驗證、ECS、跨 CDN、IPv6 永久節點、尖峰時段加權）、每日評測、每週範圍 / 網段工作 | ✅ 可用（與 2.x 對照一致） |
| DoT / DoH / DoQ / DoH3 伺服器與上游 | ✅ 可用 |
| DDR 自動發現、DNR 通告（OpenWrt）、EDNS Padding、EDE | ✅ 可用 |
| DNSCrypt | — 不做（伺服器都同時提供 DoH / DoT） |
| 社群共享 v2（簽章、三種管道、資料品質分數、2.x 好友遷移） | ✅ 可用（實機兩節點待測） |
| Cloudflare DDNS（含 HTTPS 記錄）、內建 ACME（Windows）/ acme.sh（OpenWrt） | ✅ 可用 |
| OpenWrt 正式套件與 LuCI（沿用 2.x 介面） | ✅ 可用 |
| 公開頁、「這台裝置有沒有在用」偵測、統計歷史 | ✅ 可用 |
| Windows：服務、攜帶版、防火牆 `setup`、IIS 反向代理 `iis setup`、設定頁（登入、存檔即重新載入） | 🚧 設定頁介面製作中 |
| Windows：HTTP.sys 共用 443（模式 B，`listen.doh.windowsMode = httpsys / auto`） | ✅ 可用（CI 實機驗證 IIS 共存） |

完整設計見 [`docs/spec/`](docs/spec/README.md)。

## 安裝（預覽版）

GitHub **Actions → Kuroshio DNS (Rust)** 每次執行都有產出（Artifacts），`v3.*` 標籤會自動建立 Release。

```sh
# OpenWrt 24.10
opkg install ./kuroshio_*.ipk
# OpenWrt 25.12 以後
apk add --allow-untrusted ./kuroshio-*.apk

# 預覽版預設不啟用；啟用後聽 127.0.0.1:5336，不會動到 dnsmasq 與防火牆
uci set kuroshio.main.enabled=1 && uci commit kuroshio && /etc/init.d/kuroshio restart
kuroshio query example.com -s 127.0.0.1:5336
```

Windows：解壓 `kuroshio-windows-x86_64.zip`，在命令提示字元執行：

```bat
kuroshio.exe run -c config.json
kuroshio.exe query example.com -s 127.0.0.1:5336
```

有 IIS 占用 TCP 443 時，DoH 可以跟 IIS 共用 443（模式 B）：設定 `domain`、`listen.doh.port = 443`、
`listen.doh.windowsMode = httpsys`（或保持 `auto`，443 被 IIS 占用時自動切換），用系統管理員執行一次
`kuroshio.exe setup`（登記 urlacl、把憑證綁到 HTTP.sys）。黑潮 DNS 只向 HTTP.sys 登記自己的網址
（`/dns-query`、`/.well-known/kuroshio`、公開頁），IIS 其他網站不受影響；`kuroshio.exe httpsys status` 看設定，
`kuroshio.exe httpsys cert` 立即同步憑證。詳見 [規格 07](docs/spec/07-windows.md) 第 2 節。

## 指令

```
kuroshio run [-c 設定檔]          執行（設定檔只寫跟預設值不同的欄位）
kuroshio defaults                 印出完整預設設定
kuroshio check-config <檔案>      檢查設定檔並印出合併後的結果
kuroshio sysinfo [-c 設定檔]       偵測到的硬體、等級，以及因為硬體調整的預設值
kuroshio query <網域> [-t 類型] [-s 伺服器]   查詢（診斷用，類似 dig）
kuroshio export [--share] [-o 檔案]   匯出學習資料（.kuroshio）
kuroshio import <檔案>              匯入（合併）
kuroshio access check <IP>        這個 IP 能不能連進來、符合哪一條規則
kuroshio access groups            台灣 IP 群組（ISP）、大小、是否生效
```

## 備份、換機與分享學習資料

黑潮 DNS 用久了會累積很多學習資料：驗證過的 CDN 網域、台灣節點池、永久 IPv6 節點、每日評測結果、汙染 DNS 黑名單。換路由器或重灌時可以帶過去，也可以分享給朋友，讓他不用從頭學。

- **完整備份**（換路由器）：全部學習資料、統計、自訂規則、社群身分與好友。**含私鑰，請自己保管，不要給別人。**
- **分享給朋友**：CDN 網域驗證紀錄（只有網域名稱與驗證結果，不含查詢次數、時間與手動設定）、台灣節點池、永久 IPv6 節點。朋友匯入後只當候選，他的機器自己驗證通過才使用。沒有身分、金鑰、統計、自訂規則，也沒有上游評測與黑名單（這兩項由每台機器自己判定）。

在哪裡操作：

- OpenWrt：LuCI「黑潮 DNS → 進階 → 備份與分享」，按鈕下載或上傳 `.kuroshio` 檔。
- Windows：設定頁「工具 → 備份與分享」。
- 指令列：`kuroshio export`（完整備份）、`kuroshio export --share`（分享檔）、`kuroshio import 檔案.kuroshio`；OpenWrt 加 `--uci`。服務執行中時會跟服務拿最新的資料、匯入時交給服務；服務停著時直接讀寫磁碟。

匯入是**合併**，不會直接覆蓋：同一個網域以驗證時間比較新的為準，但你自己的查詢次數與手動設定保留；節點池、黑名單取聯集；評測結果比較新才用；自訂規則改過的話只把沒有的規則加在最後；社群身分：新機器還沒有好友就換成備份的身分（好友認得的那一個；新機器自己產生的金鑰另存 `key.pem.before-import`），已經有好友就不覆蓋。服務執行中匯入時，服務會在程式內重新啟動（約幾秒）再合併，完成後顯示每一類資料新增、更新、保留了多少。

設定檔範例：

```json
{
  "listen": { "plain": { "binds": ["127.0.0.1", "::1"], "port": 5336 } },
  "upstream": { "pinned": ["udp://1.1.1.1", "udp://8.8.8.8"] }
}
```

## 開發

```sh
cargo test
cargo run -- run -c config.json
cargo run -- query example.com -s 8.8.8.8
```

跨 CPU 編譯使用 [cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild)：

```sh
pip install ziglang cargo-zigbuild
cargo zigbuild --release -p kuroshio --target aarch64-unknown-linux-musl
# MIPS
RUSTFLAGS="-C relocation-model=static" \
  cargo +nightly zigbuild --release -p kuroshio --target mipsel-unknown-linux-musl -Zbuild-std=std,panic_abort
```

| 資料夾 | 內容 |
|---|---|
| `crates/kuroshio` | 主程式（監聽、轉發、指令列） |
| `crates/kuroshio-config` | 設定結構與預設值 |
| `crates/kuroshio-proto` | DNS 封包工具 |
| `openwrt/` | OpenWrt 套件與 LuCI |
| `windows/` | Windows 版說明 |
| `data/` | 種子資料、評測名單、CDN 官方範圍 |
| `rules/` | 預設自訂過濾規則 |
| `docs/spec/` | 規格 |

## 授權

[GPL-3.0-or-later](LICENSE)
