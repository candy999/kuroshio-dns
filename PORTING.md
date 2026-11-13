# 移植指南

把黑潮 DNS 裝到 OpenWrt、Windows 以外的地方：一般 Linux、NAS、Docker、第三方路由器韌體（Asuswrt-Merlin、Padavan、DD-WRT、FreshTomato……）。

## 先選路線

| 你的環境 | 建議 | 誰負責測試 |
|---|---|---|
| OpenWrt 24.10 / 25.12 | 官方套件（Releases 的 `kuroshio-openwrt-*.zip`），見 [README](README.md#安裝) | 我們（CI） |
| Windows 10 / 11、Windows Server | Windows 版，見 [Windows 使用說明](docs/windows.md) | 我們（CI） |
| 能跑 Docker 的 Linux、NAS（群暉、威聯通、Unraid）、VPS | **Docker 映像**，見 [Docker 說明](docs/docker.md) | 我們（CI） |
| 第三方路由器韌體、不能跑 Docker 的 Linux | **通用 Linux 包**＋本文件，整合腳本由平台維護者撰寫 | 平台維護者 |

能用 Docker 就用 Docker：執行檔與資料的版本一定一致、自動重啟、健康檢查、升級只要換映像，我們每次發布都會實際測試。

第三方韌體我們沒有實機，所以不提供各家專屬的腳本；我們提供的是**穩定的指令介面**（[整合介面](docs/integration.md)）、**通用 Linux 包**，以及下面的做法。平台維護者用自己的實機整合、測試，有問題回報給我們。

## 1. 執行需求

- **CPU**：x86_64、aarch64（ARMv8）、armv7（硬體浮點）、mipsel（MIPS 小端序）、mips（MIPS 大端序）。MIPS 版是軟體浮點，沒有 FPU 的晶片也能跑。
- **連結方式**：musl 靜態連結，不依賴任何系統函式庫；也不需要系統的 CA 憑證清單（根憑證已經編進執行檔）。
- **核心**：Rust 標準函式庫要求 Linux 3.2 以上。我們的 CI 只測新核心（QEMU 使用者模式用的是主機的核心）；3.x / 4.x 舊核心由平台維護者實機回報。已知在 4.4（MT7621）可以執行。
- **系統功能**：`/proc/meminfo`、`/proc/mounts`、`/proc/self/status`、`/proc/net/if_inet6`；`/proc/pressure/memory` 有就用、沒有就略過；`/dev/urandom`（舊核心沒有 `getrandom` 系統呼叫時使用）；epoll。
- **權限**：監聽 53 埠需要 root（或 `CAP_NET_BIND_SERVICE`）；程式會把自己的 `oom_score_adj` 設成 -500（需要 root，做不到只記警告）。其他都不需要 root。
- **檔案描述元**：背景工作會同時開很多連線，建議 `ulimit -n 65535`。
- **記憶體與 Flash**：見 [選硬體、選套件](docs/hardware.md)；128 MB 記憶體可以用，64 MB 以下不支援。

## 2. 通用 Linux 包

Releases 的 `kuroshio-linux-<CPU>.tar.gz`（例如 `kuroshio-linux-mipsel-unknown-linux-musl.tar.gz`）：

```
kuroshio/
  kuroshio          執行檔
  data/             唯讀資料：種子、評測名單、CDN 範圍、台灣 IP 清單、設定頁、公開頁、儀表板
  LICENSE
  README-linux.txt
```

- **`data/` 一定要用同一版**，而且要讓程式找得到：放在執行檔旁邊（自動使用），或用 `KUROSHIO_SHARE` / `system.dataDir` 指定。少了 `data/`，DNS 仍然能用，但「只開放台灣」會因為讀不到台灣 IP 清單而放行所有來源、設定頁與公開頁也打不開。版本不一致時，啟動日誌與 `kuroshio status --json` 會有警告。
- 只要單一執行檔（例如韌體自己打包資料）的話，Releases 也有 `kuroshio-<target>` 執行檔，檔名與 `SHA256SUMS` 格式維持不變。

## 3. 設定

兩種格式，功能相同：

- **JSON**：`kuroshio run -c config.json`。只寫跟預設值不同的欄位；完整預設值用 `kuroshio defaults`，`kuroshio check-config config.json` 檢查並印出合併後的結果。
- **UCI 文字檔**（OpenWrt 格式）：`kuroshio run --uci`，用 `KUROSHIO_UCI_FILE` 指定檔案。沒有 `uci` 指令的韌體也能用：把韌體自己的設定（例如 nvram）寫成 UCI 文字檔再啟動。Padavan 就是這樣做的。

設定欄位只會新增；改名或淘汰時舊名稱照樣讀得進來，並在啟動日誌說明（例如已經不用的 `system.profile`）。

路由器上建議的最小設定（dnsmasq 照常負責 53 埠與 DHCP，查詢轉給黑潮）：

```json
{
  "system": { "dataDir": "/opt/kuroshio/data", "persistDir": "/opt/kuroshio/state" },
  "listen": { "plain": { "port": 5335, "binds": ["127.0.0.1"] } }
}
```

## 4. 檔案與儲存

| 項目 | 預設位置 | 怎麼改 | 要不要保留 |
|---|---|---|---|
| 設定檔 | `-c` 指定；沒指定時用執行檔旁的 `config.json`，否則 `/etc/kuroshio/config.json` | `-c` | 要 |
| 狀態（學到的 CDN、上游評測、節點池、好友……） | `/etc/kuroshio/state` | `system.persistDir` | 建議（遺失可重建，好友名單除外） |
| 自訂規則、社群金鑰、設定頁 token | 狀態目錄的上一層 | `filter.customRules`、`community.dir`、`admin.tokenFile` | 要 |
| 執行期暫存（鎖、評測報表） | `/tmp/kuroshio` | `system.runtimeDir` | 不用（放記憶體） |
| 日誌 | 標準輸出 | — | 交給 syslog / logger |

用 `kuroshio paths -c <設定>` 列出實際位置。

**黑潮不會格式化或抹除任何儲存裝置**，只使用設定給它的目錄。準備可寫的空間（分割區、USB、tmpfs）是平台整合的責任。

**寫入頻率**依狀態目錄所在的檔案系統自動決定（`system.storageClass` 可以強制指定）：

| 檔案系統 | 判定 | 寫入 |
|---|---|---|
| jffs2、ubifs、overlay、mtd / mmcblk 裝置 | flash | 6～24 小時一次（記憶體越多間隔越長），最久未存 24 小時一定寫，每日目標 4 MB |
| tmpfs、ramfs | ram | 10 分鐘一次（寫的是記憶體，重開機會遺失，啟動時警告） |
| 其他（硬碟、SSD、USB） | disk | 10 分鐘一次 |

內容沒變不寫；收到 SIGTERM 時全部寫出；SIGUSR1 立即寫出。

**沒有持久空間時**：狀態目錄放 tmpfs，必須保留的小檔（設定、自訂規則、社群金鑰）用絕對路徑放到持久的地方，再定時匯出、開機匯入：

```sh
kuroshio export -c "$CONF" -o /持久目錄/kuroshio-backup.kuroshio   # 完整備份，含社群私鑰，權限請設 600
kuroshio import /持久目錄/kuroshio-backup.kuroshio -c "$CONF"        # 開機時、啟動前執行
```

完整備份大約 300 KB 起跳（依學到的網域數增加，每個網域約 90 bytes）。

## 5. 接上現有的 DNS

**dnsmasq 上游模式（建議）**：dnsmasq 照常佔 53 埠、負責 DHCP 與區網主機名稱，查詢轉給黑潮。

```
# dnsmasq 設定
no-resolv
cache-size=0
servers-file=/tmp/kuroshio-servers   # 內容：server=127.0.0.1#5335
```

- `cache-size=0`：快取交給黑潮（dnsmasq 再快取一層會讓統計不準、讓「先回快速答案」失效）。
- 用 `servers-file`：dnsmasq 收到 SIGHUP 會重新讀這個檔，退回業者 DNS 時不用重啟 dnsmasq、不會中斷 DHCP。
- 副作用：黑潮看到的來源都是 127.0.0.1（統計分不出裝置）。這跟 OpenWrt 的預設模式一樣。

**獨立模式**：黑潮直接佔 53 埠（`listen.plain.binds` 加上區網位址），DHCP 發黑潮所在的 IP 當 DNS。適合沒有 dnsmasq 的伺服器。

**systemd-resolved（Ubuntu 等）**：它佔用 127.0.0.53:53。黑潮要聽 53 埠時，在 `/etc/systemd/resolved.conf` 設 `DNSStubListener=no` 再重啟 systemd-resolved；或讓黑潮聽其他埠、由 resolved 轉過來（`DNS=127.0.0.1:5335`）。

**DDR / DNR**（讓裝置自動改用加密 DNS）：DDR 設 `listen.ddr = true`，黑潮自己回答 `_dns.resolver.arpa`，dnsmasq 會轉過來。DNR 用 `kuroshio dnr -c <設定> --lan <路由器區網 IP>` 取得內容，`ok` 為 true 時把 `dhcpv4` 欄位寫成 dnsmasq 的 `dhcp-option=162,<十六進位>`。

## 6. 服務管理與故障退回

整合腳本要做三件事：**啟動、當掉自動重開、黑潮停擺時讓 DNS 照常可用**。

健康檢查用 `kuroshio health`（結束碼 0 = 正常回答；1 = 沒有回答或沒在執行；2 = 設定錯誤）。指令、結束碼、`status --json` 的欄位與訊號的完整說明在 [整合介面](docs/integration.md)。它查的是黑潮自己回答的 `_dns.resolver.arpa`，不經過上游，所以 WAN 斷線不會誤判成黑潮停擺。

建議的退回規則（OpenWrt 的 `guard.sh` 就是這樣）：程序不在，或連續 3 次（每次逾時 0.8 秒）沒有回答 → 把 servers-file 換成業者 DNS、SIGHUP dnsmasq；第一次恢復回答 → 換回 `server=127.0.0.1#5335`。程序是否存在每秒檢查，實際查詢每 10 秒一次。

各種服務管理的參考寫法：

**busybox（沒有 procd / systemd 的韌體）**

```sh
#!/bin/sh
ulimit -n 65535
while :; do
	/opt/kuroshio/kuroshio run -c /opt/kuroshio/config.json 2>&1 | logger -t kuroshio
	sleep 1
done
```

停止時對 `kuroshio` 送 SIGTERM，等它結束（最多約 15 秒，會先把資料寫出），關機流程要先停黑潮再做韌體的存檔。

**systemd**

```ini
[Unit]
Description=Kuroshio DNS
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/opt/kuroshio/kuroshio run -c /opt/kuroshio/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=1
LimitNOFILE=65535
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
```

**procd（OpenWrt）**：用官方套件，見 `openwrt/kuroshio/files/kuroshio.init`。

**Docker**：見 [Docker 說明](docs/docker.md)，映像內建健康檢查。

## 7. 開機、斷線、時間還沒對時

- **不需要網路就能啟動**：用內建資料與上次的狀態，約 1 秒內開始回答（x86 實測；慢的 CPU 會久一點）。
- **WAN 斷線**：上游查不到時，快取裡有的會回過期答案頂著；過濾清單下載失敗保留舊的，30 分鐘後重試。
- **時間還沒對時**（沒有 RTC 的路由器開機是 1970 年）：黑潮偵測到系統時間不合理時，暫時只用明文上游（加密上游的憑證檢查會失敗），也暫停需要 TLS 的背景工作，不會因此把節點或上游記成失敗；對時後自動恢復。這段期間 DNS 照常可用，NTP 也查得到。
- **WAN 換 IP**：整合腳本在 WAN 上線時執行 `kuroshio notify wan-changed`，立即檢查 DDNS。

## 8. 檢查清單

1. `kuroshio --version`、`kuroshio paths -c <設定>`：讀到的設定、狀態、`data/` 位置正確。
2. `kuroshio run -c <設定>`：啟動日誌沒有「讀不到 tw-ip.json」「data/ 版本」之類的警告。
3. `kuroshio query www.example.com -s 127.0.0.1:5335`：回答正常。
4. `kuroshio health -c <設定>`：結束碼 0；停掉黑潮後是 1。
5. 故障退回：停掉黑潮，區網裝置仍然能查詢；恢復後重新接回。
6. `kuroshio status --json -c <設定>`：`running`、`storage.class`、`clock.synced`、`data.ok` 符合預期。
7. 儲存：等一個快照週期（或送 SIGUSR1），狀態目錄有檔案；重開機後學到的資料還在（或匯入成功）。
8. 升級：執行檔與 `data/` 一起換，設定與狀態不用動。

## 9. 已知平台

| 平台 | 做法 | 維護者 |
|---|---|---|
| OpenWrt 24.10 / 25.12 | 官方套件（procd、UCI、LuCI、nftables） | 本專案 |
| Windows | 原生版（服務、IIS / HTTP.sys 共存） | 本專案 |
| Docker / NAS | 官方映像 | 本專案 |
| Padavan（padavan-tw） | 官方執行檔＋同版 `data/`、UCI 文字模式、dnsmasq 上游模式、JFFS2 資料區或每日匯出 | padavan-tw |

歡迎其他平台的維護者把做法補進這張表。

## 10. 建置

工具鏈、各 CPU 的編譯方式（MIPS 需要 nightly 與 `-Zbuild-std`）、用 QEMU 測試：見 [建置說明](docs/building.md)。

## 授權

GPL-3.0-or-later。把黑潮放進韌體或映像散布時，請附上授權全文，並提供對應版本的完整原始碼（每個 Release 的原始碼壓縮檔即可；修改過的話要公開修改後的原始碼）。
