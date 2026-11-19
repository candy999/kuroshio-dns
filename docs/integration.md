# 整合介面（給其他平台的穩定約定）

這份文件是黑潮 DNS 對外的**穩定約定**：Docker 映像、第三方路由器韌體（Padavan、Asuswrt-Merlin、DD-WRT…）、一般 Linux 的服務管理（systemd、OpenRC、runit、procd）要監控、管理黑潮 DNS 時，只需要依照這裡寫的指令、結束碼、JSON 欄位、訊號與環境變數，不必猜程式內部的行為。

約定的範圍與相容性：

- 這裡列的指令、參數、結束碼、訊號、環境變數不會在小版本更動；要改會先在發行說明預告。
- JSON 輸出**只會加欄位，不會改名、刪除或改型別**。整合程式請忽略不認識的欄位。
- 給人看的文字（沒有 `--json` 的輸出、日誌）不是約定的一部分，隨時可能調整，請不要拿來比對。
- 管理 API 的**行為**有不相容的改變時，`/api/status`、`kuroshio about --json`、`kuroshio status --json` 的 `api` 會加 1（見下面「管理 API 版本」）。第三方介面用它判斷，不要比對版本字串。

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
| `api` | number | 管理 API 版本（3.3.0 起是 `2`；舊版服務沒有這個欄位時輸出 `1`） |
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
| `warnings` | array of string | 需要注意的事：data/ 不相容、系統時間沒對時、記憶體吃緊、訂閱清單因為記憶體不足被停用、訂閱清單下載失敗、存取控制的台灣 IP 資料讀不到（公網來源擋下中）、新設定無法套用。沒有是 `[]`。文字內容不是約定，只約定「空陣列 = 沒事」 |

### `kuroshio notify`

```
kuroshio notify wan-changed [-c 設定檔] [--uci]
kuroshio notify save [-c 設定檔] [--uci]
kuroshio notify trim [--hold 秒] [-c 設定檔] [--uci]
```

通知執行中的服務發生了某件事。目前的事件：

| 事件 | 服務會做什麼 |
|---|---|
| `wan-changed` | WAN 變了（重新撥號、換 IP、換線路）：DDNS 立即檢查並更新（等同設定頁的「立即更新」）、重新偵測對外 IP（問上游時帶的 ECS 子網路）、重新做路徑檢查（3.3.6 起，見下面「路徑檢查」）。都在背景進行，指令立刻回來 |
| `save` | 立刻把所有還沒寫出的學習資料（快照）寫進快照目錄，不結束；寫完才回來（同 `SIGUSR1`、LuCI 狀態頁與設定頁的「立即儲存學習資料」）。**Windows 沒有訊號，要強制存檔就用這個**（例如關機、更新程式、UPS 通知之前） |
| `trim` | 先讓出記憶體：立刻做記憶體「吃緊」時會做的釋出（診斷緩衝縮小、DNS 快取縮到 1/4、CDN 冷資料移出記憶體；**不停用過濾清單**），並在 `--hold` 秒內（預設 300，最多 3600）不讓記憶體結構長大、也不恢復。韌體要做很佔記憶體的事之前呼叫，例如把韌體映像檔寫進 tmpfs、解壓縮大檔案。做完才回來（CDN 冷資料移出前要先寫出快照，最多幾秒） |

適合放在 WAN 撥號成功後會執行的腳本，例如 Padavan 的 `/etc/storage/post_wan_script.sh`、Asuswrt-Merlin 的 `/jffs/scripts/wan-event`、OpenWrt 的 hotplug（`/etc/hotplug.d/iface/`）、`ppp` 的 `ip-up`。

| 結束碼 | 意思 |
|---|---|
| `0` | 已送達（DDNS 沒有啟用也是 0，輸出會寫「DDNS 沒有啟用」；`save` 沒有新的變動也是 0） |
| `1` | 服務沒有回應、管理 API 被關掉，或服務拒絕 |
| `2` | 設定讀不到（讀不到時會先用預設的管理埠 `127.0.0.1:8054` 試一次，送到了就是 `0`） |

管理 API 的對應路徑（只接受 POST）：

- `wan-changed`：`POST /api/notify/wan-changed`，回應 `{"ok":true,"ddns":"started"|"disabled","ecs":"started","pathCheck":"started","clockSynced":bool}`（`pathCheck` 3.3.6 起）。
- `save`：`POST /api/persist/flush`，回應 `{"ok":true,"files":寫了幾份,"bytes":磁碟上一共幾 bytes,"at":完成時間（Unix 毫秒）,"dir":"快照目錄"}`；沒有新的變動時 `files` 是 `0`。寫入失敗回 HTTP 500 與 `{"error":"..."}`。
- `trim`：`POST /api/memory/trim?holdSec=秒`，回應 `{"ok":true,"steps":[{"step","label","freedBytes","detail"} 或 {"step","label","skipped"}],"freedBytes":估計釋出的 bytes,"holdSec":實際的秒數,"availBeforeKB","availKB"}`。記憶體控制關掉（`system.memoryGovernor: false`）時回 `{"ok":true,"enabled":false,...}`。暫停期間 `/api/status` 的 `memory.holdUntil` 是結束時間（Unix 毫秒）。

### 管理 API 版本

`/api/status`、`kuroshio about --json` 有 `api`（數字）。3.2.x 以前沒有這個欄位，視為 `1`。

| `api` | 版本 | 不相容的改變 |
|---|---|---|
| 1 | 3.0 – 3.2 | — |
| 2 | 3.3.0 | `POST /api/filter/update`（立即更新過濾清單）改成背景執行，見下面 |

### 立即更新過濾清單（`POST /api/filter/update`）

下載清單在慢的路由器上可能超過一分鐘，所以 API 2 起改成**背景執行**：

- 立刻回 `{"started":true,"running":true,"runId":編號,"startedAt":開始時間（Unix 毫秒）,"update":{...}}`。
- 已經有一次在跑時再呼叫，回 `{"started":false,...}` 和**同一個** `runId`（不會重複下載）。
- 進度與結果在 `/api/status` 的 `filter.update`：`{"state":"running"|"idle","runId","startedAt","finishedAt","changed":true|false|null,"error":string|null}`。`state` 是 `idle`、而且 `runId` 大於等於你拿到的那一個，就是那一次（或之後的一次）已經結束。
- 腳本要等結果：加 `?wait=1`，結束才回，多了 `changed`（舊的行為；失敗回 HTTP 500 與 `{"error":"..."}`）。

`runId` 是開始時間（毫秒），同一次執行的程式裡只會變大；服務重新啟動後 `filter.update` 從 `idle`、`runId: null` 開始。

其他會等一下的動作：`POST /api/jobs/run`（排進佇列就回）、`POST /api/acme/issue`（背景申請）、`kuroshio notify wan-changed` 立刻回來；`POST /api/ddns/update`（每個請求逾時 8 秒，記錄很多時會久一點）、`POST /api/cdn/verify`、`POST /api/cdn/ecs`（一個網域的幾次連線）會等到完成才回。進度都可以從 `/api/status`、`/api/ddns`、`/api/jobs` 查。

### 其他常用指令

| 指令 | 用途 |
|---|---|
| `kuroshio run [-c 設定檔] [--uci]` | 前景執行（給服務管理程式用；不會自己變成背景程式） |
| `kuroshio paths [-c 設定檔] [--uci]` | 列出設定、快照、執行期、唯讀資料、憑證、token 的位置（JSON，不含密鑰內容） |
| `kuroshio check-config <檔案>` | 檢查設定檔，印出合併預設值之後的結果；格式錯誤時結束碼非 0 |
| `kuroshio defaults` | 完整預設設定 |
| `kuroshio uci-migrate [檔案] [-o 輸出] [--dry-run]` | UCI 設定檔的升級遷移（不需要 `uci` 指令）：依 `main.lists_version` 更新沒動過的預設過濾清單、加上新版本的預設清單，使用者改過的不動。規則跟 OpenWrt 套件升級時做的一樣。沒指定檔案時用 `KUROSHIO_UCI_FILE`，再沒有就是 `/etc/config/kuroshio`。**請明確給使用者自己的設定檔路徑**：`KUROSHIO_UCI_FILE` 常常指到韌體每次開機重新產生的暫存檔，改它沒有用。已經是最新的就不改檔。`main.lists_version` 是看不懂的值時不做遷移，只印出一行說明。第三方韌體升級黑潮 DNS 時、啟動前執行一次 |
| `kuroshio import <檔案> [-c 設定檔] [--uci] [--json]` | 匯入（合併）備份。部分項目寫入失敗時結束碼 1（3.3.2 起；以前是 0），服務執行中合併時留下的備份檔改名成 `import-pending.kuroshio.failed` |
| `kuroshio url [-c 設定檔] [--uci] [--open]` | 設定頁、公開頁的網址。要登入時印出含**一次性登入碼**的網址（`/login?code=…`，10 分鐘內、只能用一次；3.3.2 起），不含長期的 token。服務沒在執行時拿不到登入碼，改印說明 |
| `kuroshio query <網域> -s <伺服器>` | 診斷查詢（類似 dig） |
| `kuroshio check-path [-c 設定檔] [--uci] [--json]` | 路徑檢查（3.3.6 起）：立刻檢查這台機器到網際網路的路上有沒有人動手腳，印出結果。不需要服務在跑；見下面「路徑檢查」 |

## 訊號（只有 Unix；Windows 沒有）

| 訊號 | 行為 |
|---|---|
| `SIGTERM`、`SIGINT` | 把還沒寫出的快照寫出後結束（結束碼 0）。Flash 上快照可能要幾秒，請給至少 15 秒再強制結束。日誌會記一行「關機前寫出 N 份快照，X KB，Y ms」，可以依實際數字調整等待時間 |
| `SIGHUP` | 重新載入設定：效果跟設定頁按儲存、主控台輸入 `reload` 一樣（在同一個行程裡重新啟動所有監聽與工作，快照先寫出）。用 `--uci` 時重新讀 UCI（`KUROSHIO_UCI_JSON` 有設定就讀那個檔，所以要先更新它）。**新設定讀不進來或啟動不了時不會結束**，見下面 |
| `SIGUSR1` | 立刻把所有還沒寫出的快照寫進快照目錄，不結束（例如路由器要斷電、要備份之前）。效果同 `kuroshio notify save`（Windows 用那個） |

每收到一個訊號都會在日誌記一行（`收到 SIGHUP…`、`收到 SIGUSR1…`）。服務還在啟動時收到的 `SIGHUP` 不會丟掉：啟動完成後補做一次（3.3.2 起）。

重新載入時，上游、解析（`resolver`）、CDN 這類設定沒變的話，**DNS 快取會留給新的設定繼續用**（3.3.2 起），存檔後不必重新問上游；只改了過濾設定時，答案裡有 CNAME 的項目丟掉。

**重新載入失敗時**（新設定讀不進來、格式錯誤，或用新設定啟動失敗，例如埠號被佔用）：服務**不會結束**，繼續用上一份可以用的設定跑。用 JSON 設定檔時，設定檔也會改回上一份內容；用 `--uci` 時沒有檔案可以改，就用記在記憶體裡的上一份設定（3.3.2 起；以前會直接結束）。失敗原因記在日誌（ERROR），也會出現在 `/api/status` 的 `warnings` 與 `reload`（`{"error":原因,"at":時間,"usingPrevious":true}`；正常時 `error` 是 `null`），以及 `kuroshio status --json` 的 `warnings`。下一次重新載入成功就清掉。第一次啟動就失敗時照舊結束（結束碼非 0），交給服務管理程式處理。

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
| `KUROSHIO_ON_CONFIG_WRITE` | 黑潮 DNS 寫入**設定目錄**之後執行的指令（`sh -c`；Windows 是 `cmd /C`），見下面「寫入設定後的外部指令」 |
| `NO_COLOR` | 有設定（任何值）就不輸出 ANSI 色碼（日誌交給 syslog、檔案時用） |

`KUROSHIO_LOG` 沒設定時，QUIC 函式庫（`quinn_proto`）只記錯誤：它的警告（例如某些伺服器造成的 `duplicate reset token`，每十幾秒一行）跟查詢結果無關，會洗掉路由器很小的 syslog。要看的話設定 `KUROSHIO_LOG=info,quinn_proto=warn`。

### 寫入設定後的外部指令（`KUROSHIO_ON_CONFIG_WRITE`）

給把設定放在記憶體、要另外執行指令才會寫進 Flash 的韌體，例如 Padavan 的 `/etc/storage`：

```sh
KUROSHIO_ON_CONFIG_WRITE="mtd_storage.sh save" kuroshio run --uci
```

- **只能用環境變數設定**，設定頁與管理 API 改不了（管理介面不能被拿來執行任意指令）。
- **哪些寫入會觸發**：設定檔（或 UCI 檔）所在的資料夾、設定目錄（快照目錄的上一層），以及設定裡指到的檔案所在的資料夾：自訂規則（`filter.customRules`，含它的 `.bak`）、憑證與金鑰（`tls.cert` / `key`、`listen.*.cert` / `key`、`acme.certFile` / `keyFile`）、設定頁 token（`admin.tokenFile`）、社群金鑰（`community.dir`）；`--uci` 時另加 `KUROSHIO_ETC`。所以自訂規則放在 `/etc/storage/kuroshio` 這類地方也會觸發（3.3.2 起）。**快照目錄（學習資料）與執行期目錄不會觸發**。黑潮 DNS 只在使用者操作（設定頁存檔、恢復預設自訂規則、匯入備份）或版本升級遷移時寫設定目錄，所以很少執行。
- **合併**：最後一次寫入後等 3 秒才執行一次（恢復預設自訂規則會寫兩個檔，只執行一次）。
- **逾時**：最多 30 秒，超過就結束它（連同它啟動的子程式）；失敗會記在日誌。
- **結束前跑完**：收到 `SIGTERM` / `SIGINT` 時，還在等待合併的那一次立刻執行（同樣受逾時限制），之後才結束。所以停止服務時請至少等 15 秒再強制結束。
- 指令的環境變數 `KUROSHIO_CONFIG_FILES` 是這次寫入的檔案（完整路徑，換行分隔）。
- **社群金鑰、身分、邀請碼**的寫入也會觸發（3.3.2 起）。
- 指令結束後最多再等 1 秒讀它的輸出：指令留下背景程式（例如 `save.sh &`）也不會卡住之後的觸發（3.3.2 起）。

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

## 網頁共用檔（自己的管理頁面要嵌入時）

第三方韌體（Padavan 等）可以把 data/ 底下的網頁檔直接放進自己的網頁目錄，用一般的 `<script>` 載入，不需要編譯、也不依賴任何框架：

| 檔案 | 全域名稱 | 內容 |
|---|---|---|
| `data/dashboard/dashboard.js`、`dashboard.css` | `KuroshioDashboard` | 共用儀表板（圖表、表格），資料從轉接器拿，見 [規格 02 第 7.3 節](spec/02-architecture.md) |
| `data/shared/ui-core.js` | `KuroshioUiCore` | 跟介面框架無關的純函式（不碰 DOM、不發請求），LuCI 與 Windows 設定頁用的是同一份 |

`KuroshioUiCore` 的函式：

| 函式 | 說明 |
|---|---|
| `fmtTime(t, mode, tzOffsetMin)` | 日期時間固定格式：`2026-11-12 10:22`；`mode` = `'sec'`（加秒）、`'date'`、`'time'`、`'timesec'`。`t` 是毫秒、毫秒字串或 ISO 字串，空的回 `-`。`tzOffsetMin` 指定時區（UTC 往東幾分鐘，台灣 = 480），不給 = 瀏覽器的本地時區 |
| `fmtBytes(b)` | `1023 B`、`12 KB`、`1.5 MB` |
| `certCovers(info, domain)` | 憑證（`san` = `DNS:a.example.com, DNS:*.example.net`）有沒有涵蓋這個網域，含萬用字元 |
| `restorePlan(cur, defs, removeOwn)` | 「恢復預設清單」：比對目前的過濾清單與預設清單（先比網址、再比名稱），回傳新的順序 `result` 與變更 `changes`（新增、移除、網址、啟用、其他、保留、順序、`count`） |
| `restoreSummary(changes, tr)` | 把 `changes` 變成要顯示的文字：`{ empty, blocks: [{ cls, title, items }] }`，畫面自己組；`tr` 是翻譯函式（可省略） |
| `format(template, args)` | `%s` / `%d` 代換 |

- 也可以在 Node 用 `require('data/shared/ui-core.js')`（有 `module.exports`）。語法是 ES5，舊瀏覽器也能用。
- 每個函式的輸入與預期輸出在 `data/shared/ui-core.tests.json`，自己移植或改寫時可以拿來對照；CI 用 `node tools/ui-core-test.js` 逐一檢查（`dashboard.js` 的 `fmtTime` 也用同一組向量檢查）。
- **Padavan httpd 的限制**：它會解析 `.js` 檔裡的模板標記，所以 data/ 底下所有 `.js`、`.css` 都不會出現 `<%`、`%>`、`<#`、`#>` 這四種組合（註解、字串、正規表示式都算）。CI 用 `node tools/check-data-assets.js` 檢查，出現時列出檔名與行號並失敗。
- 版本跟執行檔一起走：請用跟執行檔同一版的 data/。LuCI 載入時網址帶 `?v=版本`，升級後瀏覽器不會拿到快取的舊檔；自己嵌入時建議也這樣做。

## 路徑檢查（3.3.6 起）

判斷「這台機器到網際網路的路上」有沒有人動手腳，而不是哪台上游壞了。啟動後幾秒、每 6 小時（有協定被判定被擋時 1 小時）、`kuroshio notify wan-changed` 時各做一次；每日評測開始前（在評測子程序裡）也會再做一次。

| 檢查 | 怎麼判斷 | 判斷之後 |
|---|---|---|
| IPv6 能不能用 | 不送封包的路由檢查（UDP connect 到公開的 IPv6 位址，看系統選的來源位址）；連線時遇到「位址不可用」「網路無法到達」就暫停 IPv6 10 分鐘 | 不能用時只用 IPv4 連上游（DoT / DoH / DoQ / DoH3 / bootstrap 都一樣），評測不測 IPv6 位址的候選 |
| 一般 DNS（53 埠）被接走 | 對文件用的保留位址（192.0.2.1、198.51.100.1、2001:db8::1）查詢，有回答就是路上有人把 53 埠全部轉走。UDP、TCP 分開測；保留位址剛好是預設閘道時不用它 | 評測不測一般 DNS 候選（`intercept_policy`）；執行時一般 DNS 的回答不拿來合併 IP、不參加多數決；一般 DNS 只當最後備援，狀態標成「經由攔截者」 |
| 攔截者是誰 | CHAOS TXT `version.kuroshio`（黑潮 3.3.6 起只對區網的一般 DNS 回答 `kuroshio/版本`）→ 上游的黑潮；`version.bind` → 一般 DNS 軟體；都沒有 → 不明 | 顯示在狀態頁與 `warnings` |
| 「不存在」被改寫 | `.invalid` 底下的隨機名稱一定不存在（RFC 6761），回答了位址就是被改寫 | bootstrap（解析加密上游的主機名稱）改用 IP 直連的 DoH（1.1.1.1、8.8.8.8） |
| 答案被竄改 | `dns.google`、`one.one.one.one` 的答案不對 | 同上 |
| 加密協定整條被擋 | DoT 853、DoH 443、QUIC（DoH3 / DoQ）各試三台知名伺服器；某個協定全部失敗、其他協定可以 | 那種上游先不用（評測也不測），下一次檢查恢復了自動加回 |
| TLS 中途攔截 | 兩台以上出現憑證錯誤 | 顯示提醒；憑證錯誤不算「協定被擋」 |

加密協定全部連不上（網路斷了）時，這次不判斷協定被擋。

設定（UCI 在 `config upstream 'upstream'`；JSON 在 `upstream`）：

| UCI | JSON | 預設 | 說明 |
|---|---|---|---|
| `path_check` | `pathCheck` | `1` / `true` | `0` 整個關掉（不檢查，也不依結果調整） |
| `intercept_policy` | `interceptPolicy` | `skip-plain` | 一般 DNS 被接走時：`skip-plain` 評測不測一般 DNS；`warn` 只提醒，照常測；`ignore` 當成沒被接走 |
| `ipv6` | `ipv6` | `auto` | 用 IPv6 連上游：`auto` 依路由判斷；`1` 一律使用；`0` 不用（路由器的 IPv6 關閉時可以帶 `0`） |

`/api/status` 的 `network.path`：

```json
{
  "enabled": true, "policy": "skip-plain", "checkedAt": 1795000000000,
  "summary": "IPv6 不可用，一般 DNS 被路由器 192.168.1.1 上的黑潮（3.3.6）接走",
  "warnings": ["一般 DNS 被路由器 192.168.1.1 上的黑潮（3.3.6）接走：評測不測一般 DNS，一般 DNS 只當最後備援"],
  "ipv6": { "mode": "auto", "route": "global" | "ula" | "none", "usable": false, "reason": "沒有 IPv6 路由（…）" },
  "plain": { "intercepted": true, "v4": { "udp": true, "tcp": true, "intercepted": true }, "v6": null },
  "interceptor": { "kind": "kuroshio" | "dns-software" | "unknown", "version": "3.3.6" },
  "interceptorText": "路由器 192.168.1.1 上的黑潮（3.3.6）",
  "gateway": "192.168.1.1",
  "nxRewrite": [], "nxVia": null, "tampered": [], "bootstrapViaDoh": false,
  "protocols": { "dot": { "ok": 3, "fail": 0, "certErrors": 0, "lastError": null }, "doh": { … }, "quic": { … } },
  "blocked": [], "tlsIntercept": null, "offline": false
}
```

還沒檢查過時只有 `enabled`、`policy`、`checkedAt: null`、`ipv6`、`warnings: []`。有狀況時同樣的白話提醒也會放進 `/api/status` 的 `warnings`。

`/api/status` 的 `upstreams[]` 多了：`reason`（每日評測選上的原因：最快、覆蓋）、`pathBlocked`（路徑檢查判斷現在不能用）、`via`（`"interceptor"`：一般 DNS 而且路上有攔截者）。

每日評測的 `upstreams.json` 多了 `path`（評測當時的路徑檢查結果，同上的格式加 `policy`）與 `pathSkipped`（依路徑檢查略過的候選數：`plain-intercepted`、`ipv6-unavailable`、`blocked-dot`、`blocked-doh`、`blocked-quic`）。依路徑略過的候選不記可疑、不進黑名單。

**每日評測的判斷也跟著改**（3.3.6 起）：

- 一般 DNS 候選的答案完全一樣時只算一票：沒偵測到攔截的情況下，幾百台一般 DNS 的答案其實都是同一個攔截者給的，不能讓它們變成「多數」。
- 「網站無法驗證」（連不上）的可疑回答，同一個業者群組有 3 家以上互相獨立（不同網域）的加密 DNS 都這樣回答時，今天不用，但不記可疑天數（比較可能是網站或路徑的問題）。憑證不符的照舊。
- 判斷過程的摘要寫成報表目錄的 `judge.log`。報表目錄在記憶體裡時（Flash 機器），最近一次的 `judge.log`、`eliminated.csv`、`upstreams.json`（各 128 KB 以內）另存到學習資料區的 `benchmark-last/`，重開機後還查得到（`benchmark.keepLastReport: false` 關掉）。

## 小記憶體的機器（128 MB 以下）

黑潮 DNS 不依記憶體分等級，**不需要手動設定大小**：

- 記憶體控制只看整台機器還剩多少（不是「自己最多用多少」）。保留量自動決定：Linux 是 max(16 MB, 實體記憶體 5%, `min_free_kbytes` × 3)，例如 128 MB 的機器約 16 MB、`MemTotal` 437 MB / `min_free_kbytes` 12288 的機器是 36 MB。`kuroshio sysinfo` 會印出實際的值。
- 可用記憶體接近保留量，依「重建成本由低到高」讓出：診斷緩衝 → DNS 快取縮到 1/4 → CDN 冷資料移到磁碟 → （真的不足時）停用優先順序最低的過濾清單 → 只剩轉送。DNS 轉送本身永遠不讓出。
- 快照目錄在 tmpfs 時，「CDN 冷資料移到磁碟」一樣有效：移出的只有已經寫進快照、之後沒變過的資料，快照檔本來就在那裡（而且是壓縮的），這一步放掉的是記憶體裡展開的那一份。快照檔佔的記憶體在 `/api/status` 的 `memory.stateInRam`。
- 重新載入過濾清單時新舊兩份會同時存在：載入前先估「建好的大小 + 建置中每條約 16 bytes」，放不進保留量以上的空間就依停用順序先不載入（3.3.2 起；開機那次用本機副本記的規則數估）。
- 背景工作在記憶體吃緊時延後、執行中的會暫停（每日評測、CDN 的範圍 / 網段分類 / 節點池都一樣）。每日評測（dns-benchmark）同時只測 `benchmark.concurrency` 個候選（`auto` = 每核心 8 個，8–50），也不超過「可用記憶體扣掉保留量的 1/4 ÷ 512 KB（3.3.3 起；以前是 128 KB）」；每個候選測完就關閉連線，暫停時先關閉手上的連線。
- 各結構目前的用量在 `/api/status` 的 `memory.sizes`（`cacheBytes`、`cdnBytes`、`filterListsBytes` 等，都是估計值）。背景工作在 `memory.jobs`：`{"running":執行中的工作 | null,"rawBytes":每日評測手上的原始答案（估計）,"openConnections":每日評測開著的連線,"processRssBytes":評測子程序目前的實體記憶體,"processPeakRssBytes":評測子程序的最高值,"lastBenchmark":{"finishedAt":Unix 毫秒,"ok":true,"durationSec":秒,"processPeakRssBytes":上一次評測子程序的最高值}}`（`lastBenchmark` 在評測結束後也查得到，服務重新啟動前一直留著），工作結束後回到 `null` / `0`（資格賽階段也有連線數；3.3.3 起）。
- **每日評測在子程序裡跑**（3.3.3 起）：同一個執行檔的隱藏指令，結束時記憶體全部還給系統，主程式的 RSS 不會停在評測的高點（以前會因為記憶體碎片多留 20 MB 左右）。日誌照樣出現在主程式的日誌裡，結束時記一行「評測子程序結束，記憶體最高 X MB」。進行中 `ps` 會多看到一個 `kuroshio __job-dns-benchmark`；服務管理程式只要管主程式（主程式結束時子程序會跟著結束）。不想要子程序時設 `benchmark.subprocess: false`。
- **`kuroshio memory-plan`**（3.3.3 起）：用跟執行時同一套規則推算這台機器（或 `--ram 64 128` 指定的大小、`--bits 32` 指定 32 位元）的保留量、常駐用量、會載入哪些清單、每日評測同時測幾個、會不會暫停；`--json` 給程式用。常數是實測推算的，輸出裡有列出來。

真的要限制時可以調的設定：

| 設定 | 作用 |
|---|---|
| `system.memoryReserveMB` / `system.memoryReservePercent` | 加大保留量：黑潮 DNS 更早讓出（兩個都填取大的） |
| `resolver.cacheMax` | DNS 快取筆數上限（預設 100,000；記憶體控制另外會依可用記憶體收緊） |
| `benchmark.concurrency` | 每日評測同時測幾個候選 |
| `cdn.verifyConcurrency` | CDN 節點驗證同時幾個（每個都是 TLS 握手） |
| `system.oomScoreAdj` | 預設 -500；設 0 就跟一般程式一樣讓核心挑 |
| `filter.lists` | 少開幾份訂閱清單（每份的大小在 `filter.sources`） |

## 給整合者的建議

- **健康檢查**用 `kuroshio health`（不需要管理 API、不需要 token，成本很低，可以每幾秒跑一次）；要細節才用 `kuroshio status --json`。
- **停止**送 `SIGTERM`，等至少 15 秒。不要直接 `SIGKILL`：還沒寫出的學習資料（快照）會遺失。
- **斷電前**（例如 UPS 通知）送 `SIGUSR1`，或執行 `kuroshio notify save`（Windows 只能用這個），先把快照寫出。
- **WAN 變動**時執行 `kuroshio notify wan-changed`（也會重新做路徑檢查）。
- **多台路由器串在一起**（例如 D3 接在另一台跑黑潮的主路由器後面）：不用特別設定。下游的路徑檢查會認出「一般 DNS 被上游的黑潮接走」，評測只測加密 DNS；上游路由器把 IPv6 關掉時，下游可以帶 `upstream.ipv6 0`。
- **要做很佔記憶體的事之前**（韌體更新把映像檔寫進 tmpfs、解壓縮大檔案）執行 `kuroshio notify trim`。沒有 PSI 的舊核心（例如 Linux 4.4）只能輪詢可用記憶體，突然的大量配置可能來不及讓出；黑潮 DNS 的 `oom_score_adj` 是 -500，來不及時被核心結束的會是別的程式。
- **設定放在記憶體**（要另外存進 Flash）的韌體：設定 `KUROSHIO_ON_CONFIG_WRITE`。
- **容器**：把設定檔與快照目錄放在掛載的磁碟區（例如 `/config/config.json`、`system.persistDir: "/config/state"`），用 `KUROSHIO_INIT_CONFIG` 提供第一次啟動的預設設定，`KUROSHIO_SHARE` 指向映像裡的 data/。
- 管理 API 只聽本機（`127.0.0.1`）、只接受本機的 `Host`；要從別的地方管理請經過反向代理並開啟登入（`admin.auth`）。
