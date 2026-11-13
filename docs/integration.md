# 整合介面（給其他平台的穩定約定）

這份文件是黑潮 DNS 對外的**穩定約定**：Docker 映像、第三方路由器韌體（Padavan、Asuswrt-Merlin、DD-WRT…）、一般 Linux 的服務管理（systemd、OpenRC、runit、procd）要監控、管理黑潮 DNS 時，只需要依照這裡寫的指令、結束碼、JSON 欄位、訊號與環境變數，不必猜程式內部的行為。

約定的範圍與相容性：

- 這裡列的指令、參數、結束碼、訊號、環境變數不會在小版本更動；要改會先在發行說明預告。
- JSON 輸出**只會加欄位，不會改名、刪除或改型別**。整合程式請忽略不認識的欄位。
- 給人看的文字（沒有 `--json` 的輸出、日誌）不是約定的一部分，隨時可能調整，請不要拿來比對。

> **原則：黑潮 DNS 不會格式化或抹除任何儲存裝置，只使用設定給它的目錄。**
> 它只讀寫設定檔、快照目錄（`system.persistDir`）、執行期目錄（`system.runtimeDir`）、唯讀資料目錄（data/），以及設定裡明確指定的檔案（憑證、自訂規則、社群金鑰）。用 `kuroshio paths` 可以列出全部位置。不需要也不會要求掛載、分割或清除任何磁碟。

## 指令

所有指令都接受下列共通參數（`notify` 寫在事件名稱後面）：

| 參數 | 說明 |
|---|---|
| `-c, --config <檔案>` | JSON 設定檔。預設：執行檔旁邊有 `config.json` 就用它（攜帶版）；Windows 是 `%ProgramData%\kuroshio\config.json`；其他系統是 `/etc/kuroshio/config.json`。檔案不存在時全部使用預設值（會在標準錯誤輸出提示） |
| `--uci` | 改讀 OpenWrt 的 UCI 設定（見下面的 `KUROSHIO_UCI_JSON`、`KUROSHIO_UCI_FILE`），不讀 JSON |

查詢狀態的指令（`health`、`status`、`notify`）要跟執行中的服務**用同一份設定**，才找得到它的埠號與登入 token。

### `kuroshio health`

```
kuroshio health [-c 設定檔] [--uci] [--timeout 毫秒] [--json]
```

確認服務有沒有在回答 DNS：對本機的明文 DNS 監聽問 `_dns.resolver.arpa`（SVCB）。這個名稱由黑潮 DNS 自己回答，**不經過上游**，所以上游全斷時照樣算「有回答」——它檢查的是程式本身活著，不是對外網路。

- 問哪裡：`listen.plain.port`，位址是 `listen.plain.binds` 的第一個；第一個是 `0.0.0.0` 就問 `127.0.0.1`、是 `::` 就問 `::1`，沒寫就問 `127.0.0.1`。
- `--timeout`：等回答的毫秒數，預設 `800`。
- 只要收到格式正確的 DNS 回應就算有回答（不論 rcode）。

| 結束碼 | 意思 |
|---|---|
| `0` | 有回答 |
| `1` | 沒有回答（沒在執行、卡住、逾時），或明文 DNS 沒有開（`listen.plain.enabled = false`，無法用這個方法檢查） |
| `2` | 設定讀不到（設定檔格式錯誤、UCI 讀不到） |

輸出一行。`--json` 時是：

```json
{"ok":true,"server":"127.0.0.1:5335","ms":1,"rcode":0,"error":null}
```

| 欄位 | 型別 | 說明 |
|---|---|---|
| `ok` | bool | 有回答 |
| `server` | string \| null | 問的位址（設定讀不到、明文 DNS 沒開時是 `null`） |
| `ms` | number \| null | 花了幾毫秒（沒有回答是 `null`） |
| `rcode` | number \| null | 回應的 rcode |
| `error` | string \| null | 沒有回答的原因 |

Docker 的 `HEALTHCHECK` 範例：

```dockerfile
HEALTHCHECK --interval=30s --timeout=5s CMD ["kuroshio", "health", "-c", "/config/config.json"]
```

### `kuroshio status`

```
kuroshio status [-c 設定檔] [--uci] [--json]
```

經由管理 API（`http://127.0.0.1:<admin.port>/api/status`，預設埠 `8054`）讀執行中服務的狀態。`admin.host` 是 `0.0.0.0` / `::` 時改連 `127.0.0.1` / `::1`。管理 API 開了登入（`admin.auth`，Windows 預設開、其他系統預設關）時，自動從登入 token 檔（預設在設定目錄的 `admin.token`，`kuroshio paths` 的 `adminToken`）讀 token，以 `Authorization: Bearer <token>` 送出；所以要用**讀得到 token 檔的帳號**執行。

沒有 `--json` 時印幾行給人看的摘要（不是約定的一部分）。

| 結束碼 | 意思 |
|---|---|
| `0` | 服務執行中，狀態已讀到 |
| `1` | 讀不到狀態：服務沒有在執行（`running: false`），或服務在執行但讀不到（token 不對等，`running: true`）、管理 API 被關掉（`admin.enabled = false`） |
| `2` | 設定讀不到 |

`--json` 輸出一行 JSON。讀不到狀態時：

```json
{"running":false,"error":"管理 API 沒有回應（http://127.0.0.1:8054）：…"}
```

服務執行中時：

```json
{"running":true,"version":"3.0.2","uptimeSec":3600,"mode":"cmd","config":"json",
 "upstreams":[{"url":"udp://192.0.2.53:53","type":"udp","role":"pinned","ok":true}],
 "cache":{"entries":1520,"hitRate":0.82},"filter":{"enabled":true,"rules":152340,"lists":3},
 "storage":{"class":"flash","dir":"/etc/kuroshio/state","oldestUnsavedSec":420},
 "memory":{"pressure":"normal"},"clock":{"synced":true},
 "data":{"dir":"/usr/share/kuroshio","format":1,"version":"3.0.2","ok":true,"warning":null},
 "warnings":[]}
```

（實際輸出是一行；這裡為了好讀換了行。）

| 欄位 | 型別 | 說明 |
|---|---|---|
| `running` | bool | 執行中是 `true` |
| `error` | string | 只有讀不到狀態時才有 |
| `version` | string | 執行中服務的版本 |
| `uptimeSec` | number | 這一輪啟動以來的秒數（重新載入設定會從 0 開始） |
| `mode` | string | `service`（Windows 服務）或 `cmd`（前景執行；procd、systemd、Docker 都是這個） |
| `config` | string | 設定來源：`uci` 或 `json` |
| `upstreams` | array | 上游清單，每一筆 `{url, type, role, ok}` |
| `upstreams[].url` | string | 上游網址（例如 `udp://192.0.2.53:53`、`https://dns.example.net/dns-query`） |
| `upstreams[].type` | string | `udp` / `tcp` / `dot` / `doh` / `doh3` / `doq` / `dnscrypt` |
| `upstreams[].role` | string | `pinned`（固定）/ `auto`（每日評測選出）/ `fallback`（備援） |
| `upstreams[].ok` | bool | 沒有被暫停，而且不是「只失敗過、從沒成功」 |
| `cache.entries` | number | 快取筆數 |
| `cache.hitRate` | number \| null | 今天的快取命中率（0–1）；今天還沒有查詢是 `null` |
| `filter.enabled` | bool | 廣告 / 惡意網域過濾有沒有開 |
| `filter.rules` | number | 規則數（自訂 + 清單，去重後） |
| `filter.lists` | number | 已載入的訂閱清單數 |
| `storage.class` | string | 快照目錄的儲存類型：`flash` / `disk` / `ram` |
| `storage.dir` | string | 快照目錄（`system.persistDir`） |
| `storage.oldestUnsavedSec` | number \| null | 還沒寫進快照目錄的變動，最久的已經多少秒；沒有是 `null` |
| `memory.pressure` | string | `normal` / `low`（接近保留量）/ `critical`（不足） |
| `clock.synced` | bool | 系統時間有沒有對時（見下面「系統時間還沒對時」） |
| `data.dir` | string | 唯讀資料目錄（data/） |
| `data.format` | number \| null | `data/manifest.json` 的 `dataFormat`；沒有檔案是 `null` |
| `data.version` | string \| null | `data/manifest.json` 的 `version` |
| `data.ok` | bool | data/ 跟執行檔相容（有版本標記而且格式相同） |
| `data.warning` | string \| null | data/ 的問題 |
| `warnings` | array of string | 需要注意的事：data/ 不相容、系統時間沒對時、記憶體吃緊、訂閱清單因為記憶體不足被停用。沒有是 `[]`。文字內容不是約定，只約定「空陣列 = 沒事」 |

### `kuroshio notify`

```
kuroshio notify wan-changed [-c 設定檔] [--uci]
```

通知執行中的服務發生了某件事。目前的事件：

| 事件 | 服務會做什麼 |
|---|---|
| `wan-changed` | WAN 變了（重新撥號、換 IP、換線路）：DDNS 立即檢查並更新（等同設定頁的「立即更新」）、重新偵測對外 IP（問上游時帶的 ECS 子網路）。都在背景進行，指令立刻回來 |

適合放在 WAN 撥號成功後會執行的腳本，例如 Padavan 的 `/etc/storage/post_wan_script.sh`、Asuswrt-Merlin 的 `/jffs/scripts/wan-event`、OpenWrt 的 hotplug（`/etc/hotplug.d/iface/`）、`ppp` 的 `ip-up`。

| 結束碼 | 意思 |
|---|---|
| `0` | 已送達（DDNS 沒有啟用也是 0，輸出會寫「DDNS 沒有啟用」） |
| `1` | 服務沒有回應、管理 API 被關掉，或服務拒絕 |
| `2` | 設定讀不到 |

管理 API 的對應路徑是 `POST /api/notify/wan-changed`（只接受 POST），回應 `{"ok":true,"ddns":"started"|"disabled","ecs":"started","clockSynced":bool}`。

### 其他常用指令

| 指令 | 用途 |
|---|---|
| `kuroshio run [-c 設定檔] [--uci]` | 前景執行（給服務管理程式用；不會自己變成背景程式） |
| `kuroshio paths [-c 設定檔] [--uci]` | 列出設定、快照、執行期、唯讀資料、憑證、token 的位置（JSON，不含密鑰內容） |
| `kuroshio check-config <檔案>` | 檢查設定檔，印出合併預設值之後的結果；格式錯誤時結束碼非 0 |
| `kuroshio defaults` | 完整預設設定 |
| `kuroshio query <網域> -s <伺服器>` | 診斷查詢（類似 dig） |

## 訊號（只有 Unix；Windows 沒有）

| 訊號 | 行為 |
|---|---|
| `SIGTERM`、`SIGINT` | 把還沒寫出的快照寫出後結束（結束碼 0）。Flash 上快照可能要幾秒，請給至少 15 秒再強制結束 |
| `SIGHUP` | 重新載入設定：效果跟設定頁按儲存、主控台輸入 `reload` 一樣（在同一個行程裡重新啟動所有監聽與工作，快照先寫出）。用 `--uci` 時重新讀 UCI（`KUROSHIO_UCI_JSON` 有設定就讀那個檔，所以要先更新它） |
| `SIGUSR1` | 立刻把所有還沒寫出的快照寫進快照目錄，不結束（例如路由器要斷電、要備份之前） |

每收到一個訊號都會在日誌記一行（`收到 SIGHUP…`、`收到 SIGUSR1…`）。用 JSON 設定檔時，重新載入後的新設定啟動失敗，會把設定檔改回上一份可以用的內容繼續執行，不會停掉。

## 環境變數

| 變數 | 作用 |
|---|---|
| `KUROSHIO_SHARE` | 唯讀資料目錄（data/：種子、評測名單、CDN 範圍、設定頁、公開頁）。優先於 `system.dataDir`。沒設定時依序找：`system.dataDir` → 執行檔旁的 `data/` → `/usr/share/kuroshio` → `./data` |
| `KUROSHIO_INIT_CONFIG` | 只有 `kuroshio run`（不是 `--uci`）會看：`-c` 指的設定檔**不存在**、而且這個變數指向的檔案存在時，先建立設定檔的上層目錄、把它複製過去再啟動（標準錯誤輸出記一行）。設定檔已經存在就完全不動。讓容器映像附預設設定，同時保留 `/config/config.json` 給使用者改 |
| `KUROSHIO_UCI_JSON` | `--uci`：先讀這個檔（`ubus call uci get '{"config":"kuroshio"}'` 的輸出）；讀不到才讀 UCI 設定檔 |
| `KUROSHIO_UCI_FILE` | `--uci`：UCI 設定檔的位置，預設 `/etc/config/kuroshio` |
| `KUROSHIO_ETC` | `--uci`：UCI 轉換時預設檔案放的目錄（憑證 `cert.pem` / `key.pem`、`custom-rules.txt`、社群金鑰 `community/`、評測名單 `benchmark/`），預設 `/etc/kuroshio` |
| `KUROSHIO_LAN_IP4`、`KUROSHIO_LAN_ULA` | `--uci`：區網 IPv4 與 ULA（積極劫持、取代 dnsmasq 模式下綁定用；OpenWrt 的 init 腳本會給） |
| `KUROSHIO_LOG` | 日誌等級，優先於設定的 `log.level`；寫法同 `tracing` 的 EnvFilter（例如 `info`、`debug`、`warn,kuroshio=debug`） |
| `KUROSHIO_ACCESS_HOOK` | 每月的台灣 IP 清單更新換上之後執行這個程式，參數是 `apply`（OpenWrt 用它重新產生 nftables 規則） |
| `NO_COLOR` | 有設定（任何值）就不輸出 ANSI 色碼（日誌交給 syslog、檔案時用） |

日誌一律寫到標準輸出（Windows 服務例外：寫到設定檔旁邊的 `kuroshio.log`），由服務管理程式收集（procd → logread、systemd → journald、Docker → `docker logs`）。

## 系統時間還沒對時

沒有 RTC（電池時鐘）的路由器開機時系統時間是 1970 年，NTP 對時之前任何 TLS 憑證都驗不過。黑潮 DNS 的判斷方式：**現在時間早於「這個執行檔的建置時間 − 2 天」就算還沒對時**（建置時間在編譯時寫入；可重現建置時取 `SOURCE_DATE_EPOCH`）。

還沒對時的期間：

- **DNS 照常回答**，但只用明文（UDP / TCP）上游：加密上游（DoH / DoT / DoQ / DoH3 / DNSCrypt）暫停不用。目前的上游裡沒有明文的，就改用 `upstream.fallback`、再來 `resolver.lastResort` 裡的明文上游（預設都是 UDP）。所以 NTP 自己要查的網域也查得到。
- 需要 TLS 或正確時間的背景工作**延後**，不算失敗：排程工作（每日評測、CDN、台灣 IP 清單）、CDN 節點的 HTTPS 驗證與健康檢查、DDNS（含 web 方式偵測 IP）、ACME 憑證申請、社群同步、對外 IP 偵測。
- 不會因為時間錯誤把上游、CDN 節點或網域記成壞掉。
- `kuroshio status --json` 的 `clock.synced` 是 `false`，`warnings` 有一筆說明。

每 30 秒重新檢查一次。啟動時沒對時會記一行日誌（`系統時間還沒對時…暫時只用明文上游…`），對時之後再記一行，然後一切恢復正常，不必重新啟動。

## data/ 的版本標記

唯讀資料目錄（data/）裡有 `manifest.json`：

```json
{ "dataFormat": 1, "version": "3.0.2" }
```

- `dataFormat`：data/ 的格式版本。執行檔內建它讀得懂的格式（目前是 `1`）。
- `version`：這份 data/ 跟哪一版的執行檔一起發行。

規則（**一律照常執行，不會拒絕啟動**）：

| 情況 | 結果 |
|---|---|
| 沒有 `manifest.json` | 警告：`data/ 沒有版本標記，可能是舊版的 data/（請用跟執行檔同一版的 data/）`；`data.ok = false` |
| `dataFormat` 跟執行檔不同 | 警告，寫出兩邊的格式與版本；`data.ok = false` |
| 只有 `version` 不同（格式相同） | 只記一行資訊，`data.ok = true`（例如 Windows 小改版只換了執行檔） |
| 完全相同 | 不記 |

打包時請把執行檔與**同一版的 data/ 整個**一起放（OpenWrt 套件放在 `/usr/share/kuroshio/`，含 `manifest.json`；Windows 壓縮檔放在執行檔旁的 `data\`）。發行新版時 `manifest.json` 的 `version` 要跟著改（有單元測試檢查）。

## 給整合者的建議

- **健康檢查**用 `kuroshio health`（不需要管理 API、不需要 token，成本很低，可以每幾秒跑一次）；要細節才用 `kuroshio status --json`。
- **停止**送 `SIGTERM`，等至少 15 秒。不要直接 `SIGKILL`：還沒寫出的學習資料（快照）會遺失。
- **斷電前**（例如 UPS 通知）送 `SIGUSR1` 先把快照寫出。
- **WAN 變動**時執行 `kuroshio notify wan-changed`。
- **容器**：把設定檔與快照目錄放在掛載的磁碟區（例如 `/config/config.json`、`system.persistDir: "/config/state"`），用 `KUROSHIO_INIT_CONFIG` 提供第一次啟動的預設設定，`KUROSHIO_SHARE` 指向映像裡的 data/。
- 管理 API 只聽本機（`127.0.0.1`）、只接受本機的 `Host`；要從別的地方管理請經過反向代理並開啟登入（`admin.auth`）。
