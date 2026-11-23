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
| `upstreams[].role` | string | `pinned`（固定）/ `auto`（每日評測選出）/ `fallback`（備援）/ `lastResort`（最後手段）/ `chain`（串接中的上游黑潮，3.4.0 起，見下面「串接模式」） |
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
kuroshio notify simulate-memory --avail-mb MB [--minutes 分鐘] | --off [-c 設定檔] [--uci]
```

通知執行中的服務發生了某件事。目前的事件：

| 事件 | 服務會做什麼 |
|---|---|
| `wan-changed` | WAN 變了（重新撥號、換 IP、換線路）：DDNS 立即檢查並更新（等同設定頁的「立即更新」）、重新偵測對外 IP（問上游時帶的 ECS 子網路）、重新做路徑檢查（3.3.6 起，見下面「路徑檢查」）。都在背景進行，指令立刻回來 |
| `save` | 立刻把所有還沒寫出的學習資料（快照）寫進快照目錄，不結束；寫完才回來（同 `SIGUSR1`、LuCI 狀態頁與設定頁的「立即儲存學習資料」）。**Windows 沒有訊號，要強制存檔就用這個**（例如關機、更新程式、UPS 通知之前） |
| `trim` | 先讓出記憶體：立刻做記憶體「吃緊」時會做的釋出（診斷緩衝縮小、DNS 快取縮到 1/4、CDN 冷資料移出記憶體；**不停用過濾清單**），並在 `--hold` 秒內（預設 300，最多 3600）不讓記憶體結構長大、也不恢復。韌體要做很佔記憶體的事之前呼叫，例如把韌體映像檔寫進 tmpfs、解壓縮大檔案。做完才回來（CDN 冷資料移出前要先寫出快照，最多幾秒） |
| `simulate-memory` | **只給測試用**（3.5.0）：模擬系統可用記憶體只剩 `--avail-mb` MB，`--minutes` 分鐘（1～30，預設 5）後自動恢復，`--off` 立刻取消。要在設定檔把 `system.testHooks` 設成 `true` 才接受，沒開時服務回 403（結束碼 1）。見 [09-memory.md 第 11 節](spec/09-memory.md#11-測試模擬記憶體不足350) |

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
- `simulate-memory`（3.5.0，測試用）：`POST /api/memory/simulate?availMB=N&minutes=M`，回應 `{"ok":true,"minutes":實際的分鐘數,"simulated":{"availMB","until":到期時間（Unix 毫秒）,"remainingSec"}}`；`?off=1` 回 `{"ok":true,"wasOn":bool,"simulated":null}`。沒開 `system.testHooks` 回 HTTP 403，少了 `availMB` 回 400。生效期間 `/api/status` 的 `memory.simulated` 是同樣的物件（沒開是 `null`）。LuCI 不需要這個路徑（`rpcd.sh` 不加）。

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

其他會等一下的動作：`POST /api/jobs/run`（排進佇列就回；3.5.0 起排在佇列最前面，見[手動執行的工作優先](#手動執行的工作優先)）、`POST /api/acme/issue`（背景申請）、`kuroshio notify wan-changed` 立刻回來；`POST /api/ddns/update`（每個請求逾時 8 秒，記錄很多時會久一點）、`POST /api/cdn/verify`、`POST /api/cdn/ecs`（一個網域的幾次連線）會等到完成才回。進度都可以從 `/api/status`、`/api/ddns`、`/api/jobs` 查。

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
| `kuroshio chain status [-c 設定檔] [--uci] [--json]` | 串接狀態（3.4.0 起，同 `GET /api/chain`）；見下面「串接模式」 |
| `kuroshio chain recheck [-c 設定檔] [--uci]` | 立刻重新做一次路徑檢查與串接探測（背景進行，同 `POST /api/chain/recheck`） |

## 訊號（只有 Unix；Windows 沒有）

| 訊號 | 行為 |
|---|---|
| `SIGTERM`、`SIGINT` | 把還沒寫出的快照寫出後結束（結束碼 0）。Flash 上快照可能要幾秒，請給至少 15 秒再強制結束。日誌會記一行「關機前寫出 N 份快照，X KB，Y ms」，可以依實際數字調整等待時間。3.5.0 起重要變動先寫、只有計數變動的 CDN 分片只用時限的一半，來不及時多一行「關機時間有限（10.0 秒）：重要變動 N 份寫了 M 份、只有計數變動的 K 份有 J 份沒寫」（重要變動都寫完時是 info，不是 WARN） |
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
| `KUROSHIO_PATH_TARGETS`、`KUROSHIO_CHAIN_TIMING` | **只給整合測試用，不是穩定介面**，以後可能改名或拿掉。前者把路徑檢查的保留位址、閘道換成本機的假伺服器；後者縮短串接的心跳與重試時間（JSON，毫秒）。正式環境不要設定 |

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
| `restorePlan(cur, defs, removeOwn)` | 「恢復預設清單」：比對目前的過濾清單與預設清單（先比網址、再比名稱），回傳新的順序 `result` 與變更 `changes`（新增、移除、網址、啟用、其他、保留、順序、`count`）。名稱、分類、保護、繞過防護（`bypass`，3.4.0 起）不同都算「其他」 |
| `restoreSummary(changes, tr)` | 把 `changes` 變成要顯示的文字：`{ empty, blocks: [{ cls, title, items }] }`，畫面自己組；`tr` 是翻譯函式（可省略） |
| `chainView(chain, tr, now)` | 3.4.0 起：`/api/status` 的 `chain` → 狀態頁顯示用的資料 `{ down, up }`（各有 `badge`、`text`、`warn`、`rows: [{ label, value }]`；`down` 另有 `objects`、`skipped`，`up` 另有 `note`、`downstreams`）。主要的句子照 API 原樣；`now` 用來判斷公鑰是不是 24 小時內換過（可省略） |
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
  "summary": "IPv6 不可用，一般 DNS 被閘道 192.168.1.1 或更上游的路由器上的黑潮（3.3.6）接走",
  "warnings": ["一般 DNS 被閘道 192.168.1.1 或更上游的路由器上的黑潮（3.3.6）接走：評測不測一般 DNS，一般 DNS 只當最後備援"],
  "ipv6": { "mode": "auto", "route": "global" | "ula" | "none", "usable": false, "reason": "沒有 IPv6 路由（…）" },
  "plain": { "intercepted": true, "v4": { "udp": true, "tcp": true, "intercepted": true }, "v6": null },
  "interceptor": { "kind": "kuroshio" | "dns-software" | "unknown", "version": "3.3.6" },
  "interceptorText": "閘道 192.168.1.1 或更上游的路由器上的黑潮（3.3.6）",
  "gateway": "192.168.1.1",
  "nxRewrite": [], "nxVia": null, "tampered": [], "bootstrapViaDoh": false,
  "protocols": { "dot": { "ok": 3, "fail": 0, "certErrors": 0, "lastError": null }, "doh": { … }, "quic": { … } },
  "blocked": [], "tlsIntercept": null, "offline": false
}
```

還沒檢查過時只有 `enabled`、`policy`、`checkedAt: null`、`ipv6`、`warnings: []`。有狀況時同樣的白話提醒也會放進 `/api/status` 的 `warnings`。

`/api/status` 的 `upstreams[]` 多了：`reason`（每日評測選上的原因：最快、覆蓋）、`pathBlocked`（路徑檢查判斷現在不能用）、`via`（`"interceptor"`：一般 DNS 而且路上有攔截者）。3.4.0 起再多 `region`（上游所在地區，見下面「上游多樣性」），`role` 多一種 `chain`。

3.4.0 起，攔截者是黑潮時 `network.path.interceptor` 多一個 `chain`（串接探測的結果；還沒探測過、或這台的 `chain` 關著是 `null`），`kuroshio check-path` 也多一行，見下面「串接模式」。

每日評測的 `upstreams.json` 多了 `path`（評測當時的路徑檢查結果，同上的格式加 `policy`）與 `pathSkipped`（依路徑檢查略過的候選數：`plain-intercepted`、`ipv6-unavailable`、`blocked-dot`、`blocked-doh`、`blocked-quic`）。依路徑略過的候選不記可疑、不進黑名單。

**每日評測的判斷也跟著改**（3.3.6 起）：

- 一般 DNS 候選的答案完全一樣時只算一票：沒偵測到攔截的情況下，幾百台一般 DNS 的答案其實都是同一個攔截者給的，不能讓它們變成「多數」。
- 「網站無法驗證」（連不上）的可疑回答，同一個業者群組有 3 家以上互相獨立（不同網域）的加密 DNS 都這樣回答時，不記可疑天數（比較可能是網站或路徑的問題）。3.4.2 起照常計分、今天照用（以前是「今天不用」），`judge.log` 寫成「[保留] … 照常計分、不記可疑」，每題結算多一項「連不上但照用」。憑證不符的照舊。
- 多家 CDN 的網域：規則外的回答裡已經有 2 個以上不同業者憑證有效，這個網域上的「連不上」也不記可疑天數（3.3.6 之後），3.4.2 起同樣照常計分、今天照用。同一個網域底下的多個節點（例如 `sea01.example.net`、`sjc02.example.net`）在「互相獨立」的計算裡本來就算同一家。
- 記錄與黑名單註解裡的業者名稱：ip-api 沒給 AS 編號時顯示「名稱（查不到 AS 編號）」，不再是 `SHERNET__` 這種半截的（`upstreams.json` 的 `owner` 仍是原本的值）。
- 判斷過程的摘要寫成報表目錄的 `judge.log`。報表目錄在記憶體裡時（Flash 機器），最近一次的 `judge.log`、`eliminated.csv`、`upstreams.json`（各 128 KB 以內）另存到學習資料區的 `benchmark-last/`，重開機後還查得到（`benchmark.keepLastReport: false` 關掉）。

## 補跑時段（3.4.0 起）

剛刷機、學習資料不見、或很久沒跑時，排程工作（DNS 評測、CDN 範圍／掃描／節點池等）會在啟動後幾分鐘「補跑」。白天正在用網路時不想被打擾，可以限定補跑的時段：

| UCI | JSON | 預設 | 說明 |
|---|---|---|---|
| `main.catchup_window` | `system.catchUpWindow` | 空白 | 台北時間 `HH:MM-HH:MM`，例如 `01:00-06:00`，可以跨午夜（`23:00-05:00`）。空白、格式錯誤、開始等於結束 = 不限制（跟以前一樣） |

- 只影響補跑：排定時間（`jobs.*.at`）與手動執行（`/api/jobs/run`、設定頁的「立即執行」）照常。
- 等補跑的期間先用預設上游（備援、最後手段，沒有評測結果時本來就是這樣）；串接模式下共用結果照常從上游拿。
- 每次排程檢查（30 秒）重新看時鐘，不先算好要等多久：開機時還沒對時也不會算錯。
- `/api/jobs` 多了 `catchUpWindow`（設定的時段，沒設是 `null`）與 `catchUpWaiting`（正在等時段的工作名稱）；LuCI 與設定頁的排程工作表顯示「等補跑時段（01:00-06:00）」。3.4.2 起多 `catchUpProvided`：要補跑、但結果現在由上游黑潮提供（串接中）而暫不補跑的工作，表上顯示「由上游黑潮提供，暫不補跑」；串接解除後改回等時段。等的期間已經照排定時間或手動成功跑過的工作，補跑不再重做。

## 串接模式（3.4.0 起）

兩台黑潮接在一起（例如 D3 接在另一台跑黑潮、而且積極劫持 53 埠的主路由器後面）：下游自動認出上游黑潮、驗證身分、把它當第一順位的上游，並直接拿上游算好的評測結果與 CDN 節點池，不用自己再做一次。**不用任何設定，也沒有同意或核准的步驟。**

### 兩個開關

只有兩個，都在 `config upstream 'upstream'`（JSON 在 `upstream`），預設都開。**兩邊都開才會通訊**，任一邊關掉就各做各的，行為跟 3.3.7 一樣。

| UCI | JSON | 預設 | 角色 | 意思 |
|---|---|---|---|---|
| `chain` | `chain` | `1` / `true` | 下游 | 要不要辨識上游黑潮並索取需要的資料。關掉：上游是黑潮時，這台會自己重做評測、CDN 掃描、下載清單，重複使用網路 |
| `allow_downstream` | `allowDownstream` | `1` / `true` | 上游 | 要不要提供資料給下游黑潮。關掉：下游會重複做評測、CDN 掃描、下載清單，浪費網路（含這台的頻寬）。開著時區網裡任何會講這個協定的裝置都拿得到資料與放行；有啟用「繞過防護」清單、要管住區網裝置的環境請關掉 |

兩個都是布林；也接受字串 `"1"` / `"0"` / `"on"` / `"off"` / `"true"` / `"false"` / `"yes"` / `"no"` 與數字（0 = 關）。其他寫法當成預設值（開）並記一行警告。

| 下游 `chain` | 上游 `allow_downstream` | 結果 |
|---|---|---|
| 開 | 開 | 串接、登記、共用結果 |
| 開 | 關 | 下游探測一次（之後每次路徑檢查再探測一次），知道上游不提供，自己算 |
| 關 | 開或關 | 下游不發任何串接查詢；上游看不出下游是黑潮 |

上游掛掉時，下游幾秒內改回自己的加密上游；上游回來後自動接回（固定行為，沒有開關）。

### 怎麼運作（整合者需要知道的部分）

- 通道是一般 DNS 的 CHAOS TXT（`chain.kuroshio` 底下），只在路徑檢查發現「一般 DNS 被上游的黑潮接走」時才用。上游只回答區網（私有）來源的 UDP / TCP 53，其他一律 `REFUSED`。
- 身分用節點金鑰的簽章驗證（跟社群共用同一把金鑰，放在 `community.dir`：預設是設定檔旁邊的 `state/community/`，OpenWrt 是 `/etc/kuroshio/community/`）。金鑰第一次需要時才建立，所以剛裝好、還沒有下游來問時，上游角色的指紋是 `null`。
- 上游換了金鑰（重新安裝、換機器）：下游自動改綁新的金鑰，`/api/status` 的 `warnings` 留一行提醒 24 小時，狀態頁顯示新舊指紋。
- 最多 4 層（A ← B ← C ← D）；會形成迴圈時不串接。
- 串接狀態跨重新載入（SIGHUP、設定頁存檔）保留，不跨重開機。`kuroshio notify wan-changed` 會先離開串接，路徑檢查後自動接回。

### 相容性

| 下游 | 上游 | 行為 |
|---|---|---|
| 3.4.0 | 3.4.0 | 完整功能 |
| 3.4.0 | 3.3.6 / 3.3.7 | 認出是舊版（`upstream-too-old`），不發任何串接查詢，跟 3.3.7 的下游一樣 |
| 3.4.0 | 3.3.5 以前、不是黑潮 | `none`（沒有偵測到上游黑潮） |
| 3.3.x | 3.4.0 | 下游不會問；上游的 `version.kuroshio` 回答格式不變 |

管理 API 版本（`api`）不變，只有新增欄位與路徑。

### 共用結果與略過的工作

串接中，下游每隔幾小時向上游拿一次共用結果（有簽章，路上的人改不了；匯入前還會檢查格式與範圍）：

| 種類（`kind`） | 內容 | 新鮮時略過的工作 |
|---|---|---|
| `upstreams` | 每日評測的結果 | `dns-benchmark` |
| `cdn-pools`、`cdn-v6` | 台灣節點池 | `cdn-pool`、`cdn-scan` |
| `cdn-ranges` | CDN 官方範圍 | `cdn-ranges` |
| `filter-copy` | 3.4.0～3.4.2 的過濾清單副本。**3.4.3 起不再提供也不再接收**：每台自己跟清單網址下載；舊版上游的清單裡有這一種時下游略過，不列在 `objects` | — |

- 「新鮮」＝ 36 小時內成功匯入過，而且現在是串接中。略過時日誌寫「由上游黑潮提供，略過」（`dns-benchmark` 在 `/api/jobs` 的 `detail.dns-benchmark.last.skipped` 也有）。
- 不新鮮（上游沒資料、驗證失敗、36 小時沒同步成功、串接解除、`chain` 關著）時，工作照原本的排程自己跑，跟 3.3.7 一樣。匯入的資料不刪，解除後繼續用，直到自己的工作算出新的。
- 狀態記在快照目錄的 `chain-share.json`（幾百 bytes）。`/api/status` 的 `autoUpstreams.source` 是 `"chain"`（上游給的）或 `"benchmark"`（自己評測的）；3.5.0 起還沒評測、來自預設名單的是 `"default-list"`。

### 上游放行下游

`allow_downstream` 開著時，登記過的下游（15 分鐘到期、自動續約）另外得到兩件事：

- 下游的來源位址通過連線來源限制（`access`）。這只對「來源是公網位址的下游」有差別，私有位址本來就允許；`access.deny` 仍然優先。下游在另一台 NAT 後面時放行的是那台 NAT 的位址，狀態頁標「經 NAT」。
- 標成 `bypass`（繞過防護）的清單不擋下游解析**它自己登記的上游主機名稱**（例如它的 DoT 上游）。其他清單、自訂規則照擋；其他用戶端照擋。

UCI 是清單區段的 `option bypass '1'`，JSON 是 `filter.lists[].bypass: true`。預設只有 HaGeZi 的 `doh-vpn-proxy-bypass` 帶這個標記（這份清單預設停用）。

### 狀態欄位

`/api/status` 新增頂層 `chain`（下游與上游兩種角色都在這裡），`GET /api/chain` 回同一個物件：

```json
"chain": {
  "enabled": true,
  "state": "chained", "reason": null,
  "text": "串接中：上游 192.168.1.1（黑潮 3.4.0），評測結果與 CDN 節點由上游提供",
  "upstream": {
    "address": "192.168.1.1", "proto": "udp", "via": "gateway",
    "version": "3.4.0", "nodeId": "a1b2c3d4e5f60718",
    "fingerprint": "3F2A-91C0-77B1-0C4E-5D21-9A60-E3F8-12AB",
    "allowDownstream": true, "caps": ["share", "reg"],
    "path": ["a1b2c3d4e5f60718"], "depth": 2, "viaNat": false,
    "since": 1795000000000, "lastOkAt": 1795000300000, "failures": 0,
    "keyChangedAt": null, "previousFingerprint": null,
    "registered": { "ok": true, "at": 1795000300000, "expiresAt": 1795001200000, "names": 6 },
    "error": null
  },
  "backupActive": false,
  "retryAt": null,
  "shared": {
    "enabled": true, "lastSyncAt": 1795000500000, "nextSyncAt": 1795022100000, "error": null,
    "objects": [
      { "kind": "upstreams", "at": 1794990000000, "bytes": 6624, "importedAt": 1795000500000, "fresh": true, "error": null }
    ],
    "skippedJobs": ["dns-benchmark", "cdn-pool", "cdn-scan", "cdn-ranges"],
    "ownRuns": { "dns-benchmark": { "at": 1794500000000, "dueAt": 1795104800000 }, "cdn-pool": { "at": null, "dueAt": 1795086400000 } }
  },
  "audit": { "sampled": 42, "valid": 40, "unverified": 2, "siteInvalid": 0, "suspicious": 0, "recentSuspicious": 0, "releases": 0, "last": null },
  "serving": {
    "allowDownstream": true,
    "text": "提供資料給下游黑潮：目前 1 台",
    "note": "區網裡任何會講這個協定的裝置都拿得到資料與放行；有啟用「繞過防護」清單時建議關閉 allow_downstream",
    "nodeId": "0f1e2d3c4b5a6978", "fingerprint": "9C01-55E2-0A7B-31D4-8F6C-2E90-B135-7A42",
    "downstreams": [
      { "address": "192.168.1.2", "nodeId": "1a2b3c4d5e6f7081", "fingerprint": "7E44-0C19-D2A8-6B53-1F07-94CE-38A1-E560",
        "version": "3.4.0", "viaNat": false, "names": 6,
        "firstSeen": 1794990000000, "lastSeen": 1795000300000, "expiresAt": 1795001200000 }
    ],
    "share": { "ready": true, "requests": 12, "chunks": 30, "lastAt": 1795000500000, "cacheBytes": 81234 },
    "probes": { "count24h": 0, "lastAt": null },
    "refused": { "rate": 0, "notPrivate": 0, "notAllowed": 0 }
  }
}
```

（時間都是 Unix 毫秒。）

| 欄位 | 說明 |
|---|---|
| `enabled` | 這台的 `chain` 開關 |
| `state` | `none`（沒有偵測到）/ `detected`（偵測到，驗證中）/ `verifying`（做最後確認）/ `chained`（串接中）/ `released`（偵測到但沒有串接，原因在 `reason`） |
| `reason` | `released` 的原因：`not-allowed`（上游的 `allow_downstream` 關）、`upstream-too-old`、`unsupported`（上游沒有回應串接查詢）、`verify-failed`、`pin-mismatch`（3.4.4：上游的指紋跟 `upstream.chainPin` 不符）、`upstream-changed`、`no-response`、`gone`（一般 DNS 不再被接走）、`loop`、`too-deep`、`tampered`（攔截者竄改答案）、`audit-failed`（3.4.2：抽查上游給的答案，1 小時內 3 次憑證不符、而自己的上游的答案正常；10～15 分鐘後重試） |
| `text` | 給狀態頁直接顯示的一行白話，每一種情況都寫出原因與影響（例如「上游黑潮 3.4.0 不提供資料（allow_downstream 關閉）：自己做評測，會重複使用網路」）。文字內容不是約定；請整句顯示，不要截斷或自己拼 |
| `upstream` | 探測到的上游（沒探測過、或 `chain` 關著是 `null`）。`via`：`gateway`（上游就是預設閘道）/ `intercept`（經攔截，`address` 是被轉走的保留位址，`text` 寫閘道並加註「經攔截」）；`depth` 是含這台的層數；`viaNat`：上游看到的來源不是這台（中間隔了 NAT）。3.5.0：先綁成 `intercept` 的，之後知道閘道、而且閘道就是同一台上游（同一把金鑰）時會自動改成 `gateway`（串接不中斷，`since` 不變）；`direct`（沒試過是 `null`）= `{ lastTryAt, lastResult, upgradedAt, failures, blockedUntil }`，`lastResult` 是 `upgraded`／`other-key`（閘道是別台）／`no-response`／`verify-failed`／`not-allowed`／`loop`／`too-deep`／`pin-mismatch`／`suspended`／`direct-failed`（直連沒多久就中斷，`blockedUntil` 之前維持經攔截） |
| `backupActive` | 串接上游暫時不能用，正在用自己的加密上游 |
| `retryAt` | `released` 時下一次重試的時間 |
| `shared` | 共用結果（沒有串接是 `null`）。`error` 與 `objects[].error` 是代碼，例如 `memory`（記憶體不夠，這次沒同步）、`key-changed`（3.4.3：上游的金鑰 24 小時內換過，先不收共用資料）、`import-failed`（例如評測結果照這台的設定篩完不夠用、官方範圍跟這台的差太多）、`newer-format`、`own-newer`（3.4.2：這台自己的評測結果比上游給的新，不拿來蓋掉；只是說明、不是失敗）。`ownRuns`（3.4.2）：這台自己真的跑完每個工作的時間（`at`，還沒跑過是 `null`）與最晚什麼時候會自己跑（`dueAt`）：上游給的資料再新鮮，自己超過 7 天沒跑就照排程自己跑一次 |
| `audit` | 3.4.2：抽查上游給的 CDN 答案（每 16 筆抽 1、每 30 秒最多 1 個）。`valid` 憑證有效、`unverified` 連不上或不判斷、`siteInvalid` 網站本身憑證不符（自己的上游給的也不符）、`suspicious` 上游給的不符而自己的正常、`recentSuspicious` 1 小時內的可疑次數（到 3 就解除串接）、`releases` 因此解除的次數、`last` 最近一次可疑（名稱、IP、時間） |
| `serving` | 上游角色（服務還沒啟動完成時是 `null`）。`text` 開著時是「提供資料給下游黑潮：目前 N 台」或「…目前沒有下游連上來」；關著時是「不提供資料給下游（allow_downstream 關閉）：下游黑潮會自己重做評測、CDN 掃描、下載清單，重複使用網路（含這台的頻寬）」，24 小時內有下游來問過時接著寫「最近有下游黑潮來問過（…）」。`note` 只有開著時有。`probes` 是 `allow_downstream` 關著時收到的探測；`refused` 是拒絕的串接查詢（太頻繁、不是私有來源、沒有開放） |

`chain` 關著而且服務還沒準備好上游角色時，`chain` 仍然是完整的物件（`enabled: false`、`state: "none"`、其他欄位 `null`）。

`network.path.interceptor.chain`（攔截者是黑潮時的探測結果）：

```json
"interceptor": {
  "kind": "kuroshio", "version": "3.4.0",
  "chain": { "supported": true, "allowDownstream": true, "nodeId": "a1b2c3d4e5f60718",
             "fingerprint": "3F2A-91C0-77B1-0C4E-5D21-9A60-E3F8-12AB", "caps": ["share", "reg"], "error": null }
}
```

串接中時 `upstreams[]` 第一筆是 `role: "chain"` 的上游黑潮；`warnings` 不列「一般 DNS 被接走」那一條（被接走正是串接的前提）。

### 管理 API 與指令

| 路徑 | 說明 |
|---|---|
| `GET /api/chain` | 同 `/api/status` 的 `chain` |
| `POST /api/chain/recheck` | 立刻做一次路徑檢查與串接探測（背景進行），回 `{"ok":true,"started":true}`；路徑檢查關著（`upstream.pathCheck: false`）回 HTTP 400 |

兩個都要登入（跟其他管理 API 一樣）。`kuroshio chain status`（`--json` 印出同樣的 JSON）與 `kuroshio chain recheck` 是包一層管理 API，結束碼：`0` 成功、`1` 服務沒有回應或拒絕、`2` 設定讀不到。

`kuroshio check-path`（不需要服務在跑）在攔截者是黑潮時，「攔截者」那一行下面多一行：

```
  串接：上游允許串接，提供資料給下游（節點指紋 3F2A-91C0-77B1-0C4E-5D21-9A60-E3F8-12AB）
```

其他情形：`上游不提供資料（上游的 allow_downstream 關閉）：這台會自己做評測，重複使用網路`、`上游黑潮 3.3.7 不支援串接（需要 3.4.0 以上）`、`上游沒有回應串接查詢`、`上游的身分驗證失敗：…`、`這台的 chain 關閉：不辨識上游黑潮`（這時不發探測）。`--json` 的 `interceptor.chain` 同上。

### 狀態頁

LuCI 與 Windows / Linux 設定頁的狀態頁有「串接」區塊：下游角色與上游角色兩部分一定都顯示，主要的句子直接用 `text`、`serving.text`、`serving.note`，沒有任何要按的按鈕。自己做管理頁面時可以用 `data/shared/ui-core.js` 的 `chainView(chain, tr, now)` 把這個物件整理成「標籤：值」（見上面「網頁共用檔」）。

## 並行數與背景補問（3.4.0 起）

`resolver.parallel` 是 `auto`（預設）時，同時問幾台上游依 CPU 決定：

| 條件 | 同時問幾台 |
|---|---|
| 沒有 AES 指令（MIPS、ARMv7、RISC-V 一律當成沒有） | 2（不管幾核心） |
| 有 AES，1 核心 | 2 |
| 有 AES，2 核心 | 3 |
| 有 AES，3 核心以上 | 全部 |

填了數字一律照填的（`0` ＝ 全部）。`kuroshio sysinfo` 與啟動記錄會寫原因。

只問一部分上游時，回答用戶端之後（**不增加等待**）在背景補問這次沒問到的上游，把結果合併後更新快取：

- CDN 相關的查詢（答案裡有位址屬於某家 CDN）一定補問；其他 A / AAAA 查詢每 `backfillSample` 次抽一次，比對「前面說有、補問的多數說沒有」（或反過來）的情形。
- 不補問：DNSSEC（DO）與不是 IN 類別的查詢、串接中（只有一台上游）、所有上游都問過了、記憶體吃緊、同時已經有 2 個（1～2 核心）或 4 個補問在跑（超過就跳過，不排隊）。

| UCI（`config resolver 'resolver'`） | JSON | 預設 | 說明 |
|---|---|---|---|
| `backfill` | `resolver.backfill` | `cdn` | `cdn`：上面的行為；`off`（或 `0` / `false`）：不補問（3.3.7 的行為） |
| `backfill_sample` | `resolver.backfillSample` | `16` | 非 CDN 查詢每幾次抽一次；`0` ＝ 不抽樣 |

`/api/status` 的 `stats.today` 多 `backfill`（補問次數）與 `backfillMismatch`（抽樣比對不一致的次數）。3.4.2 起另有 `chainBypass`：串接中上游黑潮擋掉、這台自己的過濾沒擋，改用自己的加密上游解析的次數（快取命中不算；自己的上游也沒有答案、照上游擋的也不算）。3.4.3 起另有 `chainRetry`：上游黑潮解析不到（SERVFAIL）、改用自己的加密上游解析到的次數。`memory.pressure`（3.4.3）：當下的記憶體量測（`normal`／`low`／`critical`）；`memory.state` 放鬆前要穩定幾分鐘，兩者會差幾分鐘。

3.5.0：`/api/status` 的 `cdn` 在 CDN 關掉時是 `{"enabled": false}`（以前是 `null`，看不出是關掉還是讀不到）。`/api/status` 多 `perf`（效能計數器，找出沒有 AES 指令的機器把 CPU 花在哪裡）：`perf.tls.dot`／`perf.tls.doh` 各有 `full`（完整握手）、`resumed`（續用 session）、`aes`／`chacha`（協商到的密碼套件）、`fail`（連線或握手失敗）；`perf.tls.quic` 有 `new`、`fail`；`perf.fanout` 是每次詢問送出 1、2、3、4 個以上上游查詢的次數（一筆查詢可能詢問兩次：先問主要的，再問備援），`perf.backfillQueries` 是背景補問送出的上游查詢數。都是啟動以來的累計，32 位元，溢位就從 0 重來。`/api/trace` 的 `upstreams[]` 多 `viaInterceptor`：一般 DNS 被路上的攔截者（路由器）接走時是 `true`，並附一句 `note`，表示回答的其實是攔截者、不是那個位址。

## 上游多樣性（3.4.0 起）

每日評測選「覆蓋」上游時，先在鄰近（台灣、日本、香港、新加坡，或延遲夠低）的候選裡選；名額還有、覆蓋率還不夠才選遠的。這樣 CDN 回的節點比較常在亞洲。

| UCI（`config benchmark 'benchmark'`） | JSON | 預設 | 說明 |
|---|---|---|---|
| `coverage_region` | `benchmark.coverageRegion` | `near` | `near`：上面的做法；`any`：不分遠近（3.3.7 的行為） |
| `near_max_ms` | `benchmark.nearMaxMs` | `60` | 最低延遲在這以內就算鄰近（不管國別；任播位址靠這個判斷）。國別在鄰近四地時放寬到 2 倍 |

地區：位址在 `tw-ip.json` 裡是 `TW`，否則用 ip-api 給的國別，都沒有是空的。輸出：

- `upstreams.json` 的 `selected[]` 每筆多 `region` 與 `near`；`final_dns_smart.csv` 最後多 `Region`、`Near` 兩欄（舊的欄位順序不變）。
- `/api/status` 的 `upstreams[]` 多 `region`（沒有是 `null`）。狀態頁顯示在選上原因的旁邊，例如「自動（覆蓋 · JP）」。
- 3.5.0：`selected[]`／`spares[]` 多 `regionSource`（`"tw-net"` 位址在台灣網段；`"registered"` ip-api 的國別，也就是 IP 的註冊地）。`/api/upstreams`、`/api/status` 的 `upstreams[]` 多 `regionSource` 與 `near`（以前 `near` 只在 `upstreams.json`）；舊的 `upstreams.json` 沒有 `regionSource` 一律是 `"registered"`；固定上游、備援、串接上游三個欄位都是 `null`。`region` 的值不變。顯示規則在 ui-core.js 的 `regionLabel(u)`：`tw-net` →「台灣」、註冊地而且 `near` →「鄰近（註冊地 GB）」、註冊地 →「註冊地 GB」、沒有國別而且 `near` →「鄰近」，其他不顯示。

## 每日評測與預設名單（3.5.0 起）

### 名單標記

評測名單每一筆可以帶「整理名單時的資料」：`dohlist.txt`、`dotlist.txt`、`doqlist.txt`、`protected.txt` 寫在同一行的 `#` 後面（`tier=A op=Example_Net ms=3.1 ecs=1 carrier=1 filter=ads`，不認識的 key 忽略）；`iplist.txt` 同一行不能加註解，寫在位址的上一行（`# A Example_Net（AS64500）TW 3.9 ms ECS`）。分段行 `# ---- A 級 ----`／`# ---- B 級 ----` 是那一段沒寫分級的預設。

- 使用者自己的名單（`benchmark.dir` 跟程式附帶的名單不同時）裡沒寫標記的是 `user`；同一個上游兩邊都有、使用者沒寫標記時用預設名單的標記。社群好友給的候選一律是 `B`，`h3://` 沿用它的 `https://` 那一筆。
- 標記只是起點與排序依據，**不跳過任何檢查**（資格賽、汙染、封殺、憑證）；`ms` 是整理名單那天、那條線路量的，不當成今天的延遲。3.5.0 第 1 批只把標記帶到輸出，不影響選擇。
- 舊格式（沒有標記）照常可用。

輸出（只新增欄位，舊版不認得就不顯示）：

- `upstreams.json`（`/api/benchmark`）的 `selected[]` 每筆多 `tier`（`"A"`／`"B"`／`"user"`；沒標記的算 `"B"`）與 `op`（經營者，最長 64 bytes；沒有是空字串），`counts` 多 `byTier`（候選依分級的台數，固定上游與對照組不算）。
- `final_dns_smart.csv` 最後多 `Tier` 一欄。

### 首次啟動的初始上游

全新的 state 第一次啟動時，`state/upstreams.json` 由預設名單的 A 級產生（不再用種子裡的評測結果）：

- `generatedAt` 是 `null`、`source` 是 `"default-list"`；`selected[]` 的 `reason` 是 `"預設名單"`、`tier` 是 `"A"`、另外有 `listMs`（名單裡的延遲，只是排序依據）；`spares[]` 是候補（格式同 `selected[]`，最多 3 台）。
- `/api/status` 的 `autoUpstreams` 是 `{ "generatedAt": null, "count": 5, "source": "default-list" }`（以前沒有評測結果時是 `null`）。狀態頁顯示「自動上游來自預設名單（還沒評測）」。
- 第一次評測完成就被評測結果取代；串接時不分享給下游。

### 一直沒成功的自動上游與候補

- 自動上游上線以來一次都沒成功、第 3 次暫停時（合計失敗 15 筆，而且 10 分鐘內有別的上游成功過，不是整台斷網）先不用：每 6 小時只放 1 筆試探，成功就恢復。成功過的照舊 1 → 2 → 4 分鐘。固定上游、串接上游不受影響。
- `/api/upstreams`（與 `/api/status` 的 `upstreams[]`）每台多 `benched`（`true` = 先不用；這段時間 `paused` 也是 `true`）；候補多 `spare: true`，排在自動上游後面。`/api/status` 的 `autoUpstreams` 多 `spares`（候補台數）。
- `upstreams.json` 多 `spares[]`（評測沒選上、但合格的前 3 台，依速度；格式同 `selected[]`，`reason` 是 `"候補"`）。可用的自動上游（沒暫停、沒先不用、路徑沒擋）少於 `min(upstream.autoMax, benchmark.minAuto)` 時依序補上。舊的 `upstreams.json` 沒有 `spares` 就是沒有候補（跟 3.4.4 一樣）；舊版下游忽略這個欄位。
- 先不用的上游登記到評測學習檔（`state/benchmark-learn.json.zst` 的 `neverOk`，最多 32 筆）：下一次評測照測、但不選、也不當候補（`judge.log`：「執行時上線以來從未成功，今天照測、不選」），連續 3 次評測之後忘掉重來。學習檔讀不到、格式不對當成空的；不進備份的分享檔、不傳給下游與好友。
- 可用的連候補都不夠時提早評測（原因「自動上游不足」，12 小時內跑過就不排）；串接中由上游提供評測結果時不排。

### 不支援 HTTP/3 的 DoH

- 每一筆 DoH 另外用 HTTP/3（`h3://`）測。`https://` 通過資格賽、`h3://` 連續 3 天（不同日期）連線錯誤的，跳過 7 → 14 → 28 天（加 0～3 天亂數，最多 30 天）不產生這個 `h3://` 候選；到期再測成功就忘掉，失敗 1 次進下一輪。`https://` 照常每天測。
- 不記：`https://` 自己也失敗、路徑檢查判斷 QUIC 被擋、當天沒有任何 `h3://` 連得上。
- 紀錄在評測學習檔的 `h3skip`（`{ "<h3:// id>": { "f": 連續失敗天數, "n": 已跳過幾輪, "until": 跳到哪一天, "last": 最後記錄的日數 } }`，日數是台北日期的 Unix 日數，最多 512 筆）。`judge.log`：「HTTP/3 先不測 N 個」。

### 上游的台灣率

- 評測 Phase 2 之後，每台倖存者算 `twRate`：答案裡有台灣網段 IP（`tw-ip.json`）的網域數 ÷ 至少有一台倖存者回過台灣 IP 的網域數（在台灣根本沒有節點的網站不算進分母）；分母不到 10 是 `null`，台灣網段讀不到時全部是 `null`。
- 只影響排序：選「覆蓋」上游時，貪婪的每一步新增覆蓋差在 10% 以內的候選裡取台灣率高的；差距更大時照舊。「最快」、「備援」、候補、台數上限、覆蓋率目標、`near` 的分輪都不變。不淘汰任何上游，執行時的查詢不用它。
- 輸出：`upstreams.json` 的 `selected[]`、`spares[]` 每筆多 `twRate`（0～1，小數 3 位，或 `null`）與 `ecs`（名單標記 `ecs=1`，評測自己不探測）；`final_dns_smart.csv` 最後多 `TW_Rate` 一欄（`62.5%`，沒有是空的）。`judge.log`：「台灣率：N 個網域至少有一台回過台灣節點」。

### 對照組

`protected.txt` 的對照組（有過濾的大型 DNS）照舊永遠不選、不算覆蓋、不參加多數決、不記可疑、不進永久黑名單。3.5.0 起：

- **資格賽網域被擋**（NXDOMAIN、封鎖位址、導到封鎖頁這種「有回答但不是預期的位址」）的對照組算「判出過濾」（`stage` = `preflight`），而且照樣測評測網域；連線失敗、逾時照舊是 `untested`。以前這些一律是 `untested`、後面的網域也不測。
- `upstreams.json`（`/api/benchmark`）的 `protected[]` 每台多：
  - `stage`：結果在哪個階段決定（`preflight` 資格賽、`domain` 評測網域；A5 之後多 `probe`）。
  - `preflight`：資格賽網域被擋的說明（例如 `封殺 one.one.one.one（資格賽：NXDOMAIN）`），沒有是 `null`。網域判斷也判出時 `result`／`reason` 用網域判斷的，這個欄位照樣留著。
  - `recent`：近 7 天的結果（7 個字元以內，最左邊是今天；`d` 判出、`p` 沒判出、`u` 沒測到、`-` 那天沒跑）。
  - `regress`：`true` = 過去 7 天（不含今天）裡有 3 天以上判出、今天沒判出（`u`、`-` 不算）。
  - `expectMet`：`filter=` 的類型裡至少有一種今天有對應的判斷時，是否在評測網域判出（`true`／`false`；資格賽網域被擋不算）；都沒有對應判斷（例如只擋惡意網站——惡意網站的探測是之後的 A5）或沒測到是 `null`。
- 回歸只報告，不改變選出來的上游：`judge.log` 與日誌各一行 WARN（「對照組 X 以前判得出過濾，今天沒判出」）。今天判出的比例比過去 7 天的中位數少一半以上（今天測到 8 台以上、過去有測到 8 台以上的天數）時另外一行 WARN（評測網域檔或判斷規則可能改壞了）。
- 報表的 `protected.csv` 最後多 `stage,preflight,recent,regress,expectMet`（舊的欄位順序不變）。
- 跨天的紀錄在評測學習檔的 `control`（每台最近 30 天，字串第一個字元是 `controlDay` 那天；最多 64 台，名單裡沒有的刪掉）。
- 介面：共用儀表板的評測區塊有摺疊的對照組表；LuCI 狀態頁、Windows 設定頁的上游區塊有一行摘要（「對照組 37 台：判出 20、沒判出 5、沒測到 12；回歸 0」，ui-core.js 的 `controlSummary`）。

### 手動執行的工作優先

- `POST /api/jobs/run?name=…`（設定頁、LuCI 的「立即執行」）排到佇列**最前面**；已經在佇列裡的移到最前面（不會重複）。排程與補跑照舊排在後面。仍然一次只跑一個：正在跑的不中斷，回 `{"ok": false, "error": "執行中"}`。
- `/api/jobs` 的 `queue[]` 每筆多 `priority`（`true` = 手動、排在最前面的）。
- 正在跑 `cdn-scan`（網段分類，一跑十幾分鐘）時，有手動的工作在等，它在「一家 CDN 掃完」的時候讓出：掃完的那幾家照寫，5 分鐘後續跑（原因「續跑（讓給手動執行的工作）」），續跑時跳過 6 小時內已經掃完的那幾家；一家掃到一半不讓出，最多讓出 3 次，之後跑到完。手動的工作最多等一家 CDN 的時間。
- 補跑的先後：自動上游還沒評測過（`upstreams.json` 沒有 `generatedAt`，例如剛安裝、來自預設名單）時，`dns-benchmark` 的補跑排在 `cdn-scan` 前面（`cdn-scan` 的補跑延到評測之後 1 秒排入；`startDelaySec` 的預設值不變）。

## 重新載入不斷線（3.4.0 起）

重新載入設定（SIGHUP、設定頁存檔）時，舊的一輪要完全結束才建新的一輪，中間有 0.2～0.4 秒沒有人在聽。3.4.0 起監聽 socket 留在程式裡，不跟著舊的一輪關掉：

- 一般 DNS（UDP / TCP 53）、DoT 與 DoH 的 TCP、DoQ 與 DoH3 的 UDP 在空窗期間不會 Connection refused；用戶端看到的是零點幾秒的延遲。
- 設定改了位址、埠或關掉某個協定時，舊的監聽等新的一輪啟動完成後才關掉。新設定啟動不了時，服務照舊用上一份設定，監聽不受影響。
- 已經被舊的一輪讀走、還沒回答的 UDP 查詢會掉（用戶端會重送）；進行中的 QUIC 連線照舊會斷。
- 整合者不用改什麼：`kill -HUP` 與 procd 的 reload 照舊。

## 已知限制（3.4.0）

- **串接的一般 DNS 通道每筆查詢沒有驗證**：身分只在建立串接與心跳時驗證。區網裡能接走下游 53 埠的攻擊者（例如 ARP 欺騙、假 DHCP）可以讓下游把它當上游，之後的查詢都經過它。路徑檢查每 6 小時（與 WAN 變動時）檢查竄改，發現就解除。不信任所在的區網就關掉這台的 `chain`。
- **區網裝置可以自己架一個「下游」，繞過「繞過防護」清單**：上游不逐台核准，任何會講這個協定的裝置都能登記，它登記的主機名稱不會被 `bypass` 清單擋（已決定接受）。啟用「繞過防護」清單、要管住區網裝置的環境，請關掉上游的 `allow_downstream`。
- **規則重疊時，bypass 豁免可能連帶蓋掉另一份清單的同一條規則**：同一個網域同時在 `bypass` 清單與其他清單裡、而且命中時記到的是 `bypass` 那份時，對登記中的下游可能整筆放行。只影響登記中的下游，而且只限它登記的主機名稱。
- **管理 API 重新載入時仍有短暫空窗**：重新載入不斷線只涵蓋 DNS 監聽；設定頁與管理 API 在那零點幾秒可能連不上，重試就好。

## 小記憶體的機器（128 MB 以下）

黑潮 DNS 不依記憶體分等級，**不需要手動設定大小**：

- 記憶體控制只看整台機器還剩多少（不是「自己最多用多少」）。保留量自動決定：Linux 是 max(16 MB, 實體記憶體 5%, `min_free_kbytes` × 3)，例如 128 MB 的機器約 16 MB、`MemTotal` 437 MB / `min_free_kbytes` 12288 的機器是 36 MB。`kuroshio sysinfo` 會印出實際的值。
- 可用記憶體接近保留量，依「重建成本由低到高」讓出：診斷緩衝 → DNS 快取縮到 1/4 → CDN 冷資料移到磁碟 → （真的不足時）停用優先順序最低的過濾清單 → 只剩轉送。DNS 轉送本身永遠不讓出。
- 快照目錄在 tmpfs 時，「CDN 冷資料移到磁碟」一樣有效：移出的只有已經寫進快照、之後沒變過的資料，快照檔本來就在那裡（而且是壓縮的），這一步放掉的是記憶體裡展開的那一份。快照檔佔的記憶體在 `/api/status` 的 `memory.stateInRam`。
- 重新載入過濾清單時新舊兩份會同時存在：載入前先估「建好的大小 + 建置中每條約 16 bytes」，放不進保留量以上的空間就依停用順序先不載入（3.3.2 起；開機那次用本機副本記的規則數估）。
- 背景工作在記憶體吃緊時延後、執行中的會暫停（每日評測、CDN 的範圍 / 網段分類 / 節點池都一樣）。每日評測（dns-benchmark）同時只測 `benchmark.concurrency` 個候選（`auto` = 每核心 8 個，8–50），也不超過「可用記憶體扣掉保留量的 1/4 ÷ 512 KB（3.3.3 起；以前是 128 KB）」；每個候選測完就關閉連線，暫停時先關閉手上的連線。
- 各結構目前的用量在 `/api/status` 的 `memory.sizes`（`cacheBytes`、`cdnBytes`、`filterListsBytes` 等，都是估計值）。3.4.1 起多 `accountedBytes`（分項加總）與 `otherBytes`（實體記憶體減掉分項：程式本身、連線與背景工作、配置器還沒還給系統的空間；讀不到實體記憶體時是 `null`）。CDN 的背景工作在 `cdn.background`：`{"verify":排隊中的驗證,"ecs":排隊中的 ECS 探測,"cross":排隊中的跨 CDN 探索,"deferred":排隊已滿而沒排的累計次數}`。背景工作在 `memory.jobs`：`{"running":執行中的工作 | null,"rawBytes":每日評測手上的原始答案（估計）,"openConnections":每日評測開著的連線,"processRssBytes":評測子程序目前的實體記憶體,"processPeakRssBytes":評測子程序的最高值,"lastBenchmark":{"finishedAt":Unix 毫秒,"ok":true,"durationSec":秒,"processPeakRssBytes":上一次評測子程序的最高值}}`（`lastBenchmark` 在評測結束後也查得到，服務重新啟動前一直留著），工作結束後回到 `null` / `0`（資格賽階段也有連線數；3.3.3 起）。
- **每日評測在子程序裡跑**（3.3.3 起）：同一個執行檔的隱藏指令，結束時記憶體全部還給系統，主程式的 RSS 不會停在評測的高點（以前會因為記憶體碎片多留 20 MB 左右）。日誌照樣出現在主程式的日誌裡，結束時記一行「評測子程序結束，記憶體最高 X MB」。進行中 `ps` 會多看到一個 `kuroshio __job-dns-benchmark`；服務管理程式只要管主程式（主程式結束時子程序會跟著結束）。不想要子程序時設 `benchmark.subprocess: false`。
- **串接的共用結果**（3.4.0 起）：下游一次只處理一個物件，尖峰約 3 MiB，處理完就釋放（過濾清單 3.4.3 起不共用，每台自己下載）。下載到、但這時候存不了本機副本的清單（小 Flash、記憶體吃緊）留在記憶體（壓縮後合計最多 8 MiB，記憶體不足時不留），重建時讀它、不必再下載，空間與記憶體都夠了之後存成副本；`/api/status` 的 `filter.heldCopies` 看得到份數與大小。上游的共用快取最多 1 MiB，30 分鐘沒人用就釋放。串接中的下游不跑每日評測與 CDN 掃描，尖峰反而比較低。
- **`kuroshio memory-plan`**（3.3.3 起）：用跟執行時同一套規則推算這台機器（或 `--ram 64 128` 指定的大小、`--bits 32` 指定 32 位元）的保留量、常駐用量、會載入哪些清單、每日評測同時測幾個、會不會暫停；`--json` 給程式用。常數是實測推算的，輸出裡有列出來。

真的要限制時可以調的設定：

| 設定 | 作用 |
|---|---|
| `system.memoryReserveMB` / `system.memoryReservePercent` | 加大保留量：黑潮 DNS 更早讓出（兩個都填取大的） |
| `resolver.cacheMax` | DNS 快取筆數上限（預設 100,000；記憶體控制另外會依可用記憶體收緊） |
| `benchmark.concurrency` | 每日評測同時測幾個候選 |
| `cdn.verifyConcurrency` | CDN 節點驗證同時幾個（每個都是 TLS 握手） |
| `cdn.lite` | 3.4.2：`auto`（預設，實體記憶體小於 160 MB 時減量）／`true`／`false`（UCI 是 `config cdn` 的 `option lite '1'`／`'0'`）。減量不是關掉：只驗證問過 2 次以上的網域、驗證每分鐘最多 30 個、節點池測速 4 個節點；狀態的 `cdn.lite` 與 `cdn.stats.liteWaited`、`liteCapped`（都是次數：還沒驗證完的網域每查一次就再算一次，不是網域數） |
| `pool.relativeSpeed` | 3.5.0：節點測速用相對評分（預設 `true`；UCI 是 `config pool` 的 `option relative_speed '0'`／`'1'`）。關掉＝3.4.x：低於 1 MB/s 算慢、差 5% 以內才算瓶頸、直接比速度 |
| `cdn.cross.requestScore` | 3.5.0：跨 CDN 加實測分數（預設 `true`；UCI 是 `config cdn` 的 `option cross_request_score '0'`／`'1'`）。關掉＝3.4.x：只看 TCP 延遲 |
| `cdn.multiCdn` | 3.5.0：尊重多來源 CDN、第一層 CNAME 變了就失效（預設 `true`；UCI 是 `config cdn` 的 `option multi_cdn '0'`／`'1'`）。關掉＝3.4.x：每個網域只記一家、業者欄位直接改寫 |
| `cdn.appLayer` | 3.5.0：App 自己選節點的服務（目前 Google、Apple）只辨識、不改寫（預設 `true`；UCI 是 `option app_layer`） |
| `cdn.dbDiskBudgetKB` | 3.5.0：CDN 網域資料在磁碟上的預算。`auto`（預設：狀態目錄所在的檔案系統小於 64 MB 時用總容量的 30%，64 MB 以上或讀不到大小時不限）／數字（KB，下限 512）／`0`（不限）。UCI 是 `config cdn` 的 `option db_disk_budget_kb`。超過時在背景分批淘汰最久沒用的網域（一天內查過的、手動設定策略的不動），不會一次重寫全部分片。狀態：`cdn.dbBudgetKB`、`dbBudgetEntries`、`dbEntries`、`dbDiskKB`（實際）、`dbDiskEstKB`、`prunedForBudget` |
| `system.oomScoreAdj` | 預設 -500；設 0 就跟一般程式一樣讓核心挑 |
| `filter.lists` | 少開幾份訂閱清單（每份的大小在 `filter.sources`） |

## 給整合者的建議

- **健康檢查**用 `kuroshio health`（不需要管理 API、不需要 token，成本很低，可以每幾秒跑一次）；要細節才用 `kuroshio status --json`。
- **停止**送 `SIGTERM`，等至少 15 秒。不要直接 `SIGKILL`：還沒寫出的學習資料（快照）會遺失。
- **斷電前**（例如 UPS 通知）送 `SIGUSR1`，或執行 `kuroshio notify save`（Windows 只能用這個），先把快照寫出。
- **WAN 變動**時執行 `kuroshio notify wan-changed`（也會重新做路徑檢查）。
- **多台路由器串在一起**（例如 D3 接在另一台跑黑潮的主路由器後面）：不用特別設定。下游的路徑檢查會認出「一般 DNS 被上游的黑潮接走」；兩台都是 3.4.0 以上時自動串接（見上面「串接模式」），否則評測只測加密 DNS；上游路由器把 IPv6 關掉時，下游可以帶 `upstream.ipv6 0`。
- **要做很佔記憶體的事之前**（韌體更新把映像檔寫進 tmpfs、解壓縮大檔案）執行 `kuroshio notify trim`。沒有 PSI 的舊核心（例如 Linux 4.4）只能輪詢可用記憶體，突然的大量配置可能來不及讓出；黑潮 DNS 的 `oom_score_adj` 是 -500，來不及時被核心結束的會是別的程式。
- **設定放在記憶體**（要另外存進 Flash）的韌體：設定 `KUROSHIO_ON_CONFIG_WRITE`。
- **容器**：把設定檔與快照目錄放在掛載的磁碟區（例如 `/config/config.json`、`system.persistDir: "/config/state"`），用 `KUROSHIO_INIT_CONFIG` 提供第一次啟動的預設設定，`KUROSHIO_SHARE` 指向映像裡的 data/。
- 管理 API 預設只聽本機（`127.0.0.1`）。`Host` 只接受本機名稱、IP 位址與 `admin.allowedHosts` 裡的名稱（防 DNS rebinding；3.4.2 起接受 IP 位址與 `allowedHosts`，以前只接受本機名稱）。聽在其他位址（`admin.host`，例如 Docker 的 `0.0.0.0`）時請開啟登入（`admin.auth`）；經過反向代理時，把代理用的名稱加到 `allowedHosts`。
- **自己的介面經過白名單轉呼叫管理 API 時**（例如 OpenWrt 的 rpcd、padavan 的 `kuroshio.sh api`）：唯讀的路徑與會改變狀態的路徑要分開，後者一律用 POST。下表是 OpenWrt 的 `rpcd.sh` 在 3.5.0 開放的串接與 CDN 路徑，整合方可以照著開：

  | 路徑 | 種類 | 從哪一版 | LuCI 用到 |
  |---|---|---|---|
  | `/api/chain` | 唯讀 | 3.4.0（rpcd 3.5.0 才開放） | 狀態頁從 `/api/status` 的 `chain` 讀，這條給直接查詢用 |
  | `/api/chain/recheck` | 動作（POST） | 3.4.0（rpcd 3.5.0 才開放） | 狀態頁「重新檢查上游黑潮」 |
  | `/api/cdn/domain` | 唯讀 | 3.0 | 沒有（給查詢用） |
  | `/api/cdn/cross` | 唯讀 | 3.0 | 沒有（給查詢用） |

  `kuroshio` 套件裡有一個測試確認 rpcd 的唯讀白名單沒有會改變狀態的路徑、動作白名單都是會改變狀態的路徑。
- **查詢紀錄**（3.5.0）：`GET /api/querylog?limit=200&name=&client=&since=` 讀最近的查詢（新的在前，`limit` 最多 1,000；`name` 是「包含這段文字」，`client` 是來源 IP，`since` 是毫秒時間戳）；`POST /api/querylog/enable?minutes=10` 暫時開啟（1～60 分鐘，到時間自動關閉並釋放；`minutes=0` 關閉）。`log.queryLog: true` 是常開。每一筆是 `{at, name, type, client, result（hit／miss／blocked／stale）, rcode, ms, source}`。
  - 隱私：查詢紀錄含裝置位址與網域，是最敏感的資料：**只在記憶體**（不寫磁碟、不進備份、不給公開頁、不傳給上游／下游／好友），預設關閉，`/api/status` 的 `queryLog` 只顯示開著與否、到幾點、幾筆。串接中，上游放行的下游黑潮的查詢也會出現在上游的紀錄裡。
  - 上限：筆數（環狀，`system.queryLogRing`，實體記憶體 160 MB 以下最多 1,000、512 MB 以下最多 5,000）、時間（暫時開啟最長 60 分鐘）。查詢不等紀錄的鎖：拿不到就丟掉那一筆（`dropped`）。
  - OpenWrt 的 rpcd 開放 `/api/querylog`（唯讀）與 `/api/querylog/enable`（動作）。
- **為什麼沒換到台灣**（3.5.0）：`GET /api/cdn/explain?name=example.com` 回這個網域哪家 CDN、換或不換台灣節點、為什麼，以及驗證結果（`steps`：`v4`、`v6`、`ecs`、`cross`）。只讀：不增加查詢次數、不排驗證、不連網路（要重新驗證用 `POST /api/cdn/verify`）。CDN 沒開時也回答（`cdn-disabled`）。`decision` 的代碼（介面依代碼顯示；`text` 是核心給的白話）：

  | 代碼 | 意思 |
  |---|---|
  | `rewritten` | 已經換成驗證過的台灣節點 |
  | `already-tw` | 原本的答案就是台灣節點 |
  | `trial` | 台灣節點還在驗證中（先回原本的答案，TTL 10 秒） |
  | `lite-waiting` | 小記憶體減量：問過 2 次以上才驗證 |
  | `verify-failed` | 台灣節點驗證沒通過（到期後重新驗證） |
  | `no-tw-node` | 找不到可用的台灣節點，跨 CDN 也沒有 |
  | `no-pool` | 這家 CDN 的台灣節點池還沒建好 |
  | `cross` | 換成同一個網站在別家 CDN 的台灣節點 |
  | `ecs` | 帶台灣網段問到台灣節點（依查詢來源分流的 CDN） |
  | `policy-never`／`policy-always` | 手動設成不換／一定換 |
  | `multi-cdn` | 3.5.0：網站自己在多家 CDN 之間分流，不替它換到別家（回答來自驗證過的那一家時照常換，那時是 `rewritten`） |
  | `app-layer` | 3.5.0：App 自己選節點的服務，只辨識、不改寫 |
  | `chained` | 串接中：上游黑潮換好，這台不處理 |
  | `memory-floor` | 記憶體控制的最低限度：暫停 CDN 調整 |
  | `cdn-disabled` | 這台沒開 CDN 台灣節點 |
  | `not-cdn`／`unknown` | 不是認得的 CDN／還沒人查過 |

  OpenWrt 的 rpcd 開放 `/api/cdn/explain`（唯讀）。
- **多來源 CDN 的欄位**（3.5.0）：`/api/cdn/domain` 與 `/api/cdn/explain` 多回：
  - `c1`：第一層 CNAME 的鍵（查詢名稱的第一個 CNAME 目標取最後三段，例如 `a1b2.node7.edge.example.net` → `edge.example.net`；最長 64 位元組；沒有 CNAME 就沒有這個欄位）。
  - `multi`：7 天內看過兩家 CDN 輪流回答。
  - `provs`：最近看到的業者，最多 3 個：`[{ "provider": "cloudfront", "lastSeen": 毫秒, "verified": true }]`。`verified: true` 是有自己一格驗證結果的（最多兩家），`false` 是沒有格子、照原始答案回的。
  - `/api/cdn/domain` 的 `src`：原始的來源紀錄（`alt` 是另一家的那一格：`provider`、`v4`、`v6`、`base`、`last`；`seen`、`pend` 是第一層 CNAME 的防抖動狀態；`multiAt`、`invalAt`、`slotAt` 是毫秒時間）。這些欄位 3.4.x 讀到會原樣保留。
  - `/api/status` 的 `cdn.stats`：`srcInvalidated`（來源變了而清掉跨 CDN／ECS 的次數）、`multiHeld`（多來源沒有格子、照原始答案回的次數）、`appLayer`（App 層不改寫的次數）。
- **跨 CDN 的實測分數**（3.5.0）：`/api/cdn/domain` 的 `cross4` 多 `score`（換過去那一家）與 `origScore`（原站）：一個請求的連線＋TLS 握手＋收到回應標頭的毫秒數，各取兩次探測裡比較小的；`cross4.tried[]` 每一家多 `score`（第一次探測的）。`verdict` 是 `fail` 而且兩個分數都有＝「連線比較近，但整個請求沒有比較快」。`/api/cdn/explain` 的 `cross` 步驟一樣多這兩個欄位；`GET /api/cdn/cross` 多 `scoreRejected`（因為這個原因沒有採用的網域數）。探測量不到分段時間時沒有這些欄位，照 3.4.x 的規則判斷。
- **節點池的測速欄位**（3.5.0）：`GET /api/cdn/pools` 每家多 `speedRef`（這一次節點池工作量到速度的節點的中位數，MB/s；量到的不到 3 個時是 `null`），每個節點多：
  - `slow`：`true`／`false`＝相對評分的結果（連加上誤差範圍都不到 `speedRef` 的一半、或低於 0.1 MB/s）；沒有這個欄位＝沒量過速度，或舊資料（那時照舊規則：`speed` 低於 1 MB/s 算慢）。
  - `sample`：`{ "bytes": 8388608, "secs": 0.144, "connectMs": 4.1, "ttfbMs": 9.3, "quick": true }`——那一次下載收到的位元組數、收內容的秒數、連線（含 TLS 握手）與送出請求到收完標頭的毫秒數；`quick` 是量到瓶頸之後只收 1 MiB 的快測（這時節點的 `speed` 記的是瓶頸的速度）。這些是 3.6 工作負載分數的量測基礎，3.5.0 只收集、不參與排序。
  - 3.4.x 讀到這些欄位會原樣保留。
- **通訊類網域**（3.5.0）：推播服務的網域（內建 Apple 推播、Firebase 雲端訊息；`resolver.keepNames` 自己加，最多 64 個後綴）不被訂閱清單誤擋（`filter.protectComm`，預設開；自訂規則照樣優先，`/api/filter/check` 的 `rule` 是 `builtin-comm`）、快到期就預取（同時最多 16 個）、記憶體控制縮快取時優先留下、不換到別家 CDN。`/api/status` 的 `comm` 有內建與自己加的數量、預取中的數量；`filter.commSpared` 是清單本來要擋、照樣放行的次數（每天第一次會記一行 INFO，寫明是哪份清單，方便回報給清單維護者）。

