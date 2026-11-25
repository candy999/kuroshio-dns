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
| `freshness` | array | 3.5.0：資料新鮮度，同 `/api/status` 的 `freshness`（見下面「觀測與線路感知」）；舊版服務沒有是 `[]` |
| `findings` | array | 3.5.0：發現清單，同 `/api/status` 的 `findings`；舊版服務沒有是 `[]`。`warnings` 不受影響（同一件事不兩邊都放） |

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

立即更新有清單失敗（`filter.errors` 不是空的、`error` 有值）時，定時更新接著照它自己的退避重試：1 分鐘後，之後 2、5 分鐘、每 30 分鐘，全部成功就回到正常的更新間隔（3.5.0 起；以前要等到下一次定時更新，每天一次的話是隔天）。重試比原本排的早才提前，手動一直失敗也不會越排越密。

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
| `KUROSHIO_UCI_FILE` | `--uci`：UCI 設定檔的位置，預設 `/etc/config/kuroshio`。`notify`、`status`、`chain`、`health`、`check-path`、`memory-plan` 沒帶 `--uci`、預設的 `config.json` 又不存在時，有這個（或 `KUROSHIO_UCI_JSON`）就照 UCI 讀（3.5.0 起） |
| `KUROSHIO_ETC` | `--uci`：UCI 轉換時預設檔案放的目錄（憑證 `cert.pem` / `key.pem`、`custom-rules.txt`、社群金鑰 `community/`、評測名單 `benchmark/`），預設 `/etc/kuroshio` |
| `KUROSHIO_LAN_IP4`、`KUROSHIO_LAN_ULA` | `--uci`：區網 IPv4 與 ULA（積極劫持、取代 dnsmasq 模式下綁定用；OpenWrt 的 init 腳本會給） |
| `KUROSHIO_LOG` | 日誌等級，優先於設定的 `log.level`；寫法同 `tracing` 的 EnvFilter（例如 `info`、`debug`、`warn,kuroshio=debug`） |
| `KUROSHIO_ACCESS_HOOK` | 每月的台灣 IP 清單更新換上之後執行這個程式，參數是 `apply`（OpenWrt 用它重新產生 nftables 規則） |
| `KUROSHIO_ON_CONFIG_WRITE` | 黑潮 DNS 寫入**設定目錄**之後執行的指令（`sh -c`；Windows 是 `cmd /C`），見下面「寫入設定後的外部指令」 |
| `NO_COLOR` | 有設定（任何值）就不輸出 ANSI 色碼（日誌交給 syslog、檔案時用） |
| `KUROSHIO_PATH_TARGETS`、`KUROSHIO_CHAIN_TIMING` | **只給整合測試用，不是穩定介面**，以後可能改名或拿掉。前者把路徑檢查的保留位址、閘道換成本機的假伺服器；後者縮短串接的心跳與重試時間（JSON，毫秒）。正式環境不要設定 |

`KUROSHIO_LOG` 沒設定時，QUIC 函式庫（`quinn_proto`）只記錯誤：它的警告（例如某些伺服器造成的 `duplicate reset token`，每十幾秒一行）跟查詢結果無關，會洗掉路由器很小的 syslog。要看的話設定 `KUROSHIO_LOG=info,quinn_proto=warn`。3.5.1 起 `quinn_udp`（UDP 送不出去，例如 Windows 的 `sendmsg error: ... 10040`）也只記錯誤：`KUROSHIO_LOG=info,quinn_udp=warn` 可以打開。DoQ／DoH3（用戶端與伺服器）3.5.1 起不做路徑 MTU 探測，封包固定在 1200 位元組以內：quinn 預設每 10 分鐘探測到 1452 位元組的 UDP 內容，IPv6 加標頭剛好 1500，PPPoE（MTU 1492）與 VPN 放不下，Windows 送出時回 WSAEMSGSIZE（10040）；DNS 的訊息幾乎都在 1200 位元組以內，探測沒有好處。

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
| `restorePlan(cur, defs, removeOwn)` | 「恢復預設清單」：比對目前的過濾清單與預設清單（先比網址、再比名稱），回傳新的順序 `result` 與變更 `changes`（新增、移除、網址、啟用、其他、保留、順序、`count`）。名稱、分類、保護、繞過防護（`bypass`，3.4.0 起）、探測抽樣（`probe`，3.5.0 起）不同都算「其他」 |
| `restoreSummary(changes, tr)` | 把 `changes` 變成要顯示的文字：`{ empty, blocks: [{ cls, title, items }] }`，畫面自己組；`tr` 是翻譯函式（可省略） |
| `chainView(chain, tr, now)` | 3.4.0 起：`/api/status` 的 `chain` → 狀態頁顯示用的資料 `{ down, up }`（各有 `badge`、`text`、`warn`、`rows: [{ label, value }]`；`down` 另有 `objects`、`skipped`，`up` 另有 `note`、`downstreams`）。主要的句子照 API 原樣；`now` 用來判斷公鑰是不是 24 小時內換過（可省略） |
| `upstreamExtra(u, tr)` | 3.5.0：上游的 `servfail`、`late` →「SERVFAIL 3、來不及 5」，放在成功率旁邊；都是 0 或沒有這兩欄回 `''` |
| `paceView(pace, tr)` | 3.5.0：`/api/status` 的 `cdn.pace` →`{ text, warn }`（`warn` = 減量中；小機器 `lite: true` 永遠在減量，是常態、`warn` 是 `false`）；舊版、空物件回 `null` |
| `cdnStoreText(cdn, tr)` | 3.5.0：`/api/status` 的 `cdn`（`dbEntries`、`dbDiskKB`、`dbFileKB`、`dbBudgetKB`、`cdnDirKB`）→ 一行摘要；沒有 `dbEntries` 回 `null` |
| `format(template, args)` | `%s` / `%d` 代換（`%%` 是百分比符號本身） |

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
| `self` | 3.5.0：這台自己 `{ nodeId, fingerprint, version, depth }`。`depth` 串接中等於 `upstream.depth`（含這台的層數），沒有串接是 `1`。`chain` 關著、回應器沒有建立時也有；還沒有節點金鑰時 `nodeId`、`fingerprint` 是 `null`（不會為了這個建立金鑰檔）。畫拓樸圖時用它跟 `upstream.path`、別台的 `serving.downstreams[].nodeId` 對起來 |
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

3.5.0：`/api/status` 的 `cdn` 在 CDN 關掉時是 `{"enabled": false}`（以前是 `null`，看不出是關掉還是讀不到）。`/api/status` 多 `perf`（效能計數器，找出沒有 AES 指令的機器把 CPU 花在哪裡）：`perf.tls.dot`／`perf.tls.doh` 各有 `full`（完整握手）、`resumed`（續用 session）、`aes`／`chacha`（協商到的密碼套件）、`fail`（連線或握手失敗）；`perf.tls.quic` 有 `new`（新建的連線數；QUIC 連線每 10 秒送 keep-alive、會一直重複使用，所以前後相減常常是 0）、`fail`、`open`（目前開著的連線數，3.5.0 F4）；`perf.fanout` 是每次詢問送出 1、2、3、4 個以上上游查詢的次數（一筆查詢可能詢問兩次：先問主要的，再問備援），`perf.backfillQueries` 是背景補問送出的上游查詢數。都是啟動以來的累計，32 位元，溢位就從 0 重來。`/api/status?lite=1` 不回 `perf`（3.5.0 起；見「觀測與線路感知」）。`/api/trace` 的 `upstreams[]` 多 `viaInterceptor`：一般 DNS 被路上的攔截者（路由器）接走時是 `true`，並附一句 `note`，表示回答的其實是攔截者、不是那個位址。

3.5.1：`/api/status` 的 `perf` 多 `jobTimeouts`（往上游問的工作超過 12 秒被放棄的次數）、`rankSkipped`（查詢路徑因為測速名額用完而沒有排序 IP 的次數），
以及 `perf.server`（加密 DNS 伺服器的過載保護，見[規格 01 第 1.1.2 節](spec/01-protocols.md#112-過載保護連線與請求的上限351)）：
`refused` 底下 `dot`、`doh`、`doq`、`doh3` 各有 `total`（連線總數滿了）、`perSource`（這個來源的連線數滿了，`system.maxTlsConnectionsPerIp`）、`memory`（記憶體偏低或不足）——新連線被拒絕的次數；
`dohBusy`（DoH 同時處理中的請求滿了、立刻回 `503 busy` 的次數，`system.maxDohInflight`）、`deadline`（一筆查詢 10 秒沒有結果、回 SERVFAIL 的次數）、
`httpsysBodyBusy`（Windows HTTP.sys 模式讀請求內容的執行緒都在忙、回 `503 busy` 的次數）。同樣是啟動以來的累計、32 位元；`lite=1` 不回。
DoH 的 `503` 回應是 `Content-Type: text/plain`、內容 `busy`、帶 `Retry-After: 1`：用戶端稍等就可以重送，不需要換伺服器。

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

### 分級評測

`benchmark.tiers`（UCI `option tiers`）：`auto`（預設）／`a`／`ab`。

- `ab`：全部候選都測（3.4.4 以前的行為）。
- `a`：**只用 A 級**。A 級、使用者自己加的（`user`）、固定上游、對照組照測；人工分級是 B 級的（含沒標記的、好友給的、依歷史升級或試用中的、執行時從未成功的）一個都不測，連上一次 `selected[]`／`spares[]` 裡的也不沿用，所以 B 級不會進 `selected[]`／`spares[]`。依歷史降級的 A 級照下面的規則不測。A 級的多樣性不夠（經營者不到 12 家、某一種類型不到 8 個）只寫進 `judge.log`，不從 B 級補。
- `auto`：實體記憶體 256 MB 以上（含讀不到記憶體大小）用 `ab`；小於 256 MB 是小機器的減量：A 級、使用者自己加的、固定上游、對照組照測；B 級（含沒標記的、好友給的）只測：
  - 沿用：上一次評測 `selected[]`／`spares[]` 裡的（最多 16 個）；
  - 補位：路徑檢查與黑名單略過之後，今天要測的候選裡（只算 `upstream.autoTypes` 的類型）經營者不到 12 家、或某一種類型不到 8 個（那一種類型今天能測的本來就不到 8 個時，有幾個算幾個）→ 從 B 級補，最多 32 個、同一個經營者最多 2 個；順序是評測歷史分數高的先，沒有歷史的依名單的 `ms` 小的先；
  - 探索：B 級依 id 的雜湊排成固定順序、每 40 個一組，每天測「日數 mod 組數」那一組（同一天重跑是同一批）。
  - 其餘 B 級今天不測：不送任何查詢、不算淘汰、不記任何紀錄。
- 經營者：名單的 `op=`；沒有時用主機的可註冊網域（IP 用 /16）。
- `upstreams.json`（`/api/benchmark`）多 `tiers`：`{ "mode": "a"｜"ab", "auto": 設定是不是 auto, "onlyA": 只用 A 級（設定 a）, "a": 今天測的 A 級, "incumbent": 沿用, "fill": 補位, "explore": 探索, "skippedB": 今天不測的 B 級 }`。`mode` 是 `a` 時 `onlyA` 分得出是設定 `a`（`true`，`incumbent`／`fill`／`explore` 都是 0）還是小機器的 `auto`（`false`）；`counts.total`、`counts.byTier` 只算今天實際測的。
- 選上游仍然只看今天的評測結果；串接中的下游自己評測的那一次（超過 7 天沒跑）照自己的 `tiers`。

依評測歷史的升降（學習檔 `state/benchmark-learn.json.zst` 的 `hist`）：

- 格式：`"hist": { "<id>": [t, s, q, ms, dv, e, last] }`。`t`／`s`／`q` 是近 30 天的位元遮罩（最低位是 `last` 那天）：測到、倖存到最後、被判汙染／可疑；`ms`／`dv` 是倖存那幾天平均延遲的 EWMA 與平均偏差（毫秒，小數 1 位）；`e` 是狀態（0 一般、1 升級、2 降級、3 試用）；`last` 是台北日期的 Unix 日數。最多 2,000 筆（超過時先丟名單裡沒有的，再丟最舊的）；名單裡沒有的、30 天都沒測到的每次評測後刪掉。
- 只記「評測成功、而且今天真的測到」的一般候選（固定上游、對照組、使用者自己加的不記）；某一種類型 3 個以上、今天一個都沒過資格賽時那一種類型不記。系統時間倒退時不記、不位移。
- 規則：A 級測到 ≥ 7 天且（倖存率 < 50% 或可疑 ≥ 2 天）→ 降級；降級後倖存率 ≥ 80% 且沒有可疑 → 恢復，測到不滿 7 天（歷史滾出去）→ 照人工分級。B 級今天倖存、30 天內沒失敗、沒有可疑 → 試用（最多 24、每天最多新增 8，今天延遲低的先；失敗 2 天或有可疑就結束）；測到 ≥ 10 天、倖存率 ≥ 90%、沒有可疑、延遲穩定（平均偏差 ≤ 平均的一半或 10 ms）→ 升級（最多 64，分數高的先）；升級後倖存率 < 75% 或有可疑 → 降回。
- 效果只在小機器的 `auto` 看得到：升級與試用中的 B 級每天測，降級的 A 級不測（不補位、不探索）。設定 `a` 只有降級有作用（降級的 A 級不測），升級與試用中的 B 級一樣不測、不選（這時 `promoted`、`trial` 是 0，這一批記在 `promotedSkipped`；3.5.0 D3 第 3 輪之前的測試版照樣寫在 `trial`，容易看成「今天試了幾個」）。依歷史要降級的超過今天 A 級的三分之一時當天不採用降級（`demoteFuse`）。
- `tiers` 另外有 `promoted`、`trial`（今天因為歷史拉上來測的 B 級）、`promotedSkipped`（只用 A 級時：依歷史升上來、今天不測的 B 級；其他模式是 0）、`demoted`（降級中的 A 級）、`demoteFuse`、`promotedToday`、`demotedToday`（今天評測之後新升級、新降級的）。`judge.log`：「[分級] 依近 30 天的評測歷史：升級 N、…」與各前 20 筆的依據。

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
- 重新載入設定時（3.5.0 第一階段後修正，Windows W21）：上線以來從未成功的自動上游（含候補）的「先不用」與暫停次數交給新的一輪——同一個 id、新的評測結果或設定裡還在的才接（不在的丟掉），60 秒內沒人接手就過期，最多 32 台；先不用的照原本的時間每 6 小時放 1 筆試探（會自己恢復）。日誌「重新載入：上線以來從未成功的上游 N 台沿用原本的狀態：先不用 `<id>`（每 6 小時試一次）」。以前每存一次設定，壞掉的上游就從「暫停 1 分 → 2 分 → 先不用」重來（多 3 分鐘、15 筆失敗）。成功過的上游照舊重新算；程式重新啟動不交接。

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
  - `stage`：結果在哪個階段決定（`preflight` 資格賽、`domain` 評測網域、`probe` 惡意網站探測——網域沒判出、探測判出有擋時）。
  - `preflight`：資格賽網域被擋的說明（例如 `封殺 one.one.one.one（資格賽：NXDOMAIN）`），沒有是 `null`。網域判斷也判出時 `result`／`reason` 用網域判斷的，這個欄位照樣留著。
  - `recent`：近 7 天的結果（7 個字元以內，最左邊是今天；`d` 判出、`p` 沒判出、`u` 沒測到、`-` 那天沒跑）。
  - `regress`：`true` = 過去 7 天（不含今天）裡有 3 天以上判出、今天沒判出（`u`、`-` 不算）。
  - `expectMet`：`filter=` 的類型裡至少有一種今天有對應的判斷時，那些類型有沒有判出（`true`／`false`）。廣告、追蹤、成人看評測網域（資格賽網域被擋不算）；惡意網站看惡意網站探測（這一台有回答、而且探測今天有效才算有判斷）。都沒有對應判斷（例如只擋惡意網站、而今天沒有探測網域或探測今天失效）或沒測到是 `null`。
- **觀察中（不設期望）**：沒寫 `filter=` 的對照組（`expect` 是 `?`）照常測、照常記 `recent`，但 `expectMet` 是 `null`、`regress` 一律 `false`（也不算進整體回歸的比例）、不當惡意網站探測的參照。附帶的名單裡，3.5.0 D3 實測 9 個有效探測都沒擋、又不確定它們到底擋不擋的幾台（Quad9 的兩個名稱、DNS4EU Protective）放在這一類，待更多實測再定。
- 回歸只報告，不改變選出來的上游：`judge.log` 與日誌各一行 WARN（「對照組 X 以前判得出過濾，今天沒判出」）。今天判出的比例比過去 7 天的中位數少一半以上（今天測到 8 台以上、過去有測到 8 台以上的天數）時另外一行 WARN（評測網域檔或判斷規則可能改壞了）。
- 報表的 `protected.csv` 最後多 `stage,preflight,recent,regress,expectMet`（舊的欄位順序不變）。
- 跨天的紀錄在評測學習檔的 `control`（每台最近 30 天，字串第一個字元是 `controlDay` 那天；最多 64 台，名單裡沒有的刪掉）。
- 介面：共用儀表板的評測區塊有摺疊的對照組表；LuCI 狀態頁、Windows 設定頁的上游區塊有一行摘要（「對照組 37 台：判出 20、沒判出 5、沒測到 12；回歸 0」，ui-core.js 的 `controlSummary`）。

### 惡意網站探測

`benchmark.malwareProbe`（UCI `option malware_probe`，預設 `true`；關掉＝整段不跑，跟 3.4.4 一樣）。探測網域有兩個來源（3.5.0 F10）：

- **`probe.txt`**（評測名單目錄，使用者的與程式附帶的合併；**可以留空**，附帶的是空的）：格式 `<網域>  # probe=malware src=<出處> checked=<日期>`；沒寫 `probe=malware` 的行不採用；跟 `web.txt` 或資格賽網域重複的不採用；最多讀 8 個。有內容時排最前面、一定參加自我檢查。
- **抽樣**（`benchmark.probeSample`，UCI `option probe_sample`，預設 `true`；`false`＝只用 `probe.txt`、規則也是這一包之前的）：每日評測啟動前，主程式從這台已經下載的惡意類清單的**本機副本**串流解壓、水塘抽樣留 60 個（3.5.0 D3 第 3 輪之後從 40 改成 60）。只收單純的網域規則（`||example.com^` 或只有網域的一行：沒有萬用字元、修飾、不是例外規則、不是 IP、至少兩段、100 個字元以內），排除評測網域、資格賽網域、內建一定通過的服務、`resolver.keepNames`。哪些清單可以抽看 `filter.lists[].probe`（UCI 清單區段的 `option probe '0'`／`'1'`）：沒寫時啟用中、`category` 是 `malware`、不是繞過防護的才抽；預設清單的 TW165、TWNIC-RPZ、新註冊網域、繞過防護明寫 `probe: false`（舊設定沒有這個欄位時依網址認得）。以下情況這次不抽（日誌一行 INFO，評測照樣跑、只用 `probe.txt`）：記憶體壓力不是 Normal、那份清單被記憶體控制停用中、沒有本機副本（**不為了抽樣多下載**；副本還在等寫出時也不讀）。
- 抽樣結果放進傳給評測的那一份設定的 `benchmark._probeSample`（`{ "names": [...], "lists": 份數, "skipped": "沒抽的原因" }`）。**底線開頭＝內部用**：只在主程式交給評測子程序的那一份（標準輸入的第一行），不存檔、`/api/config` 看不到；不用子程序時同一份設定直接給。
- 流程：
  1. **確認還解析得到**（只有抽樣的）：問一台不過濾的參照（通過資格賽、A 級優先、沒有 `filter` 標記的第一台；一個都沒回答就換下一台，最多換一次），每秒最多 5 筆。NXDOMAIN、沒有位址、封鎖位址、沒回答的丟掉，留最多 30 個（同上，從 20 改成 30；每個候選實際用的上限 12 不變）。
  2. **自我檢查**：參照是對照組裡 `filter=` 含 `malware`、資格賽有回答的（不同經營者，最多 6 台），與通過資格賽的一般候選（A 級優先、不同經營者，最多 6 台）。參照不足（對照組不到 2 家、候選不到 3 家）→ `no-reference`，不問。每台參照用一條連線把探測網域（`probe.txt` 的在前）問一輪（最多 12 台 × 38 個 = 456 筆）。
  3. 一個探測網域有效的條件：至少 2 家不同經營者的對照組回封鎖（NXDOMAIN、沒有 A 記錄、`0.0.0.0` 之類），而且不過濾那一邊至少 3 台有回答、其中 70% 以上解析得到。取有效的前 12 個（抽樣關掉時前 4 個）；都沒有 → `invalid`。
  4. 有效的探測網域接在 `web.txt` 的網域後面，每個候選在收集階段用同一條連線順便問（不另外連線、照 `benchmark.paceMs` 的間隔）。
  5. 全部問完之後用全部候選的資料再驗一次同樣的兩個條件。一般候選怎麼算「有擋惡意網站」：抽樣開著時，在有效的探測裡**有回答的至少 6 個、而且擋了一半以上**；有效的不到 6 個時不判斷一般候選。抽樣關掉時照這一包之前的規則：2 個以上有效的探測都擋；有效的不到 2 個時不判斷一般候選。對照組都是「有效的探測裡擋了 min(2, 有效數) 個以上」。
  6. 保險絲：判出的超過有回答的一半 → `fuse`，整段作廢。
- 判出的一般候選比照對照組：照常測評測網域、今天不選、不當候補、不算覆蓋、不參加多數決、不呼叫可疑紀錄、不進永久黑名單；不在 `eliminated.csv`。`judge.log` 建議把它移到 `protected.txt`。評測歷史裡那一天算沒倖存。固定上游不判。
- 只認明確的阻擋；回「另一個位址」（業者自己的警告頁）不判。探測網域不做憑證驗證、不查業者、不算延遲。
- **不寫出抽到的網域**：`judge.log` 的 `[惡意網站探測]` 段只寫來源份數與各階段的數量（「來源：probe.txt 0 個；從 1 份惡意類清單抽樣 60 個」「抽樣的 60 個裡 48 個還解析得到，留 30 個」「自我檢查：30 個（probe.txt 0、抽樣 30）裡 15 個通過（超過上限沒用的 3 個），這次用 12 個（最多 12）；沒過的：有擋惡意網站的對照組不到 2 家擋 15」），抽樣的探測網域失效時寫「抽樣第 N 個」；`probe.txt` 的照舊寫網域。要看抽到哪些用 DEBUG 等級的日誌。`upstreams.json` 也不帶。
- `upstreams.json`（`/api/benchmark`）多 `probe.malware`：`{ "state": "off"｜"empty"｜"no-source"｜"no-reference"｜"invalid"｜"fuse"｜"ok", "domains": 參加自我檢查的個數, "used": 這次用幾個, "valid": 問完之後還有效幾個, "blockedBy": 判出幾台, "filtering": [判出的上游，最多 100], "probed": 有回答的一般候選數, "queries": 探測多送的查詢數, "rule": "ratio"（抽樣開著）｜"count"（抽樣關掉）, "source": { "manual": probe.txt 幾個, "sampled": 抽到幾個, "alive": 其中還解析得到幾個, "lists": 抽了幾份清單 } }`；`counts` 多 `malwareFilter`。`empty` 是 `probe.txt` 沒有、抽樣關掉；`no-source` 是抽樣開著、但 `probe.txt` 沒有也抽不到（或抽到的都解析不到）。
- 對照組：`protected[].stage` 可能是 `probe`（`reason` 是 `封殺 惡意網站探測`）。探測有設定但今天判不出來（`no-source`／`no-reference`／`invalid`／`fuse`）時，預期會擋惡意網站、其他都沒判出的對照組在 `recent` 記成 `u`（沒測到），不算回歸。
- 介面：ui-core.js 的 `benchScope(b)` 把 `tiers` 與 `probe`（含 `source`）寫成一行（LuCI 狀態頁、Windows 設定頁的上游區塊；共用儀表板在評測區塊）。
- 隱私：抽到的是還在活動的惡意網域，線路上的資安設備可能把這台記成「有裝置中毒」；企業或學校網路建議關掉 `benchmark.malwareProbe`。

### 手動執行的工作優先

- `POST /api/jobs/run?name=…`（設定頁、LuCI 的「立即執行」）排到佇列**最前面**；已經在佇列裡的移到最前面（不會重複）。排程與補跑照舊排在後面。仍然一次只跑一個：正在跑的不中斷，回 `{"ok": false, "error": "執行中"}`。
- `/api/jobs` 的 `queue[]` 每筆多 `priority`（`true` = 手動、排在最前面的）。
- 正在跑 `cdn-scan`（網段分類，一跑十幾分鐘）時，有手動的工作在等，它在「一家 CDN 掃完」的時候讓出：掃完的那幾家照寫，5 分鐘後續跑（原因「續跑（讓給手動執行的工作）」），續跑時跳過 6 小時內已經掃完的那幾家；一家掃到一半不讓出，最多讓出 3 次，之後跑到完。手動的工作最多等一家 CDN 的時間。
- 補跑的先後：自動上游還沒評測過（`upstreams.json` 沒有 `generatedAt`，例如剛安裝、來自預設名單）時，`dns-benchmark` 的補跑排在 `cdn-scan` 前面（`cdn-scan` 的補跑延到評測之後 1 秒排入；`startDelaySec` 的預設值不變）。

## 觀測與線路感知（3.5.0 起）

都放在既有的路徑裡（`/api/status`、`/api/dashboard`、`/api/chain`、`/api/community/status`），**沒有新的路徑**：OpenWrt 的 rpcd 白名單、padavan 韌體都不用改。新欄位舊韌體不認得就不顯示；`warnings` 的格式與內容不變。全部是拉取式（被讀時才算），不新增背景工作、不發探測、不寫新檔。

### `/api/status` 的查詢參數

| 參數 | 說明 |
|---|---|
| `lite=1` | 不回大的欄位：`perf`（效能計數器）、`history`、`system.persist.files`（每個快照檔一筆，CDN 網域資料就有 256 片，D3 上約 37 KB；3.5.0 F2）——改帶加總 `system.persist.filesSummary`：`{ "count": 檔數, "bytes": 合計, "compressed": 壓縮的檔數, "pending": 等寫出的檔數, "oldestWriteAt": 最舊的寫出時間（毫秒） }`。LuCI 的 rpcd（`status` 方法）、padavan 韌體每幾秒讀一次用這個。`freshness`、`findings`、`stale`、`cdn.reach`、`cdn.pace` 這些很小，照樣有；`persist` 的其他加總欄位（`bytesToday`、`oldestUnsavedSec`、`maxAgeHours`、`space`…）全部保留。不帶 `lite` 的完整回應 `files` 與 `filesSummary` 都有。（規格 C12 一直寫「`lite=1` 時不回 `perf`」，3.5.0 之前的版本其實沒有處理 `lite`。`persist.files` 文件沒寫過、repo 裡的介面也沒有讀；第三方韌體有讀的話請改讀 `filesSummary` 或不帶 `lite`。） |
| `history=1` | 多帶 `history`（24 小時歷史，約 6 KB）；不帶參數時沒有。跟 `lite=1` 一起時以 `lite` 為準（不帶） |

### `freshness`（資料新鮮度）

```json
"freshness": [
  { "key": "benchmark", "label": "每日評測", "lastOkAt": 1795382000000, "failing": false, "fails": 0,
    "nextAt": 1795450200000, "stale": false, "pending": false, "source": "own", "failingItems": null, "note": null },
  { "key": "tw-ip", "label": "台灣 IP 資料", "lastOkAt": null, "failing": true, "fails": 2,
    "nextAt": 1797000000000, "stale": false, "pending": true, "source": "own", "failingItems": null, "note": "資料產生於 2026-11-01" }
]
```

- 固定順序、最多 16 項：`benchmark`、`cdn-ranges`、`cdn-scan`、`cdn-pool`、`tw-ip`（排程工作，CDN 關著時沒有 `cdn-*`；停用、沒註冊的工作不列）、`filter-lists`（過濾有開才有）、`path-check`（路徑檢查有開才有）、`chain-sync`（串接中才有）、`friends-sync`（有好友才有）。
- `key` 是約定；`label`、`note` 是給人看的白話（內容不是約定）。
- `lastOkAt`：上次成功（毫秒）；從來沒成功過是 `null`，同時 `pending: true`、`stale: false`。過濾清單的「成功」含「檢查過都沒變（304）」。好友同步是所有好友裡最舊的那一次。
- `failing`、`fails`：上一次是失敗的、連續失敗幾次。排程工作的 `fails` 來自排程狀態檔的 `failStreak`（成功拿掉、失敗加 1、飽和到 9,999；3.4.x 留下的狀態檔沒有這個欄位時，上一次失敗當 1）；過濾清單、串接同步沒有連續次數，失敗中記 1；好友同步是最大的連續失敗次數。
- `failingItems`：失敗的清單數（過濾清單）、同步失敗中的好友數（好友同步）；其他是 `null`。
- `stale`：上次成功距今超過週期的 2 倍。排程工作的週期是「下次排定 − 最近一次排定」；過濾清單用 `filter.updateIntervalHours`、路徑檢查 6 小時、串接同步 6 小時、好友同步 `community.syncIntervalMin`。
- `source`：`chain` = 現在由上游黑潮提供（串接中、略過這個工作），不算失敗，上次成功取「自己跑完」與「從上游匯入」比較新的那一個；`own` = 這台自己做。

### `findings`（發現清單）

```json
"findings": [
  { "key": "upstream-failing", "sev": "warn", "text": "有 1 個上游連續失敗、暫停中（會逐次拉長暫停時間，恢復後自動接回）",
    "count": 2, "firstAt": 1795400000000, "lastAt": 1795486200000, "active": true },
  { "key": "reach-single-pop", "sev": "info", "text": "這條線目前只到得了台北機房",
    "count": 1, "firstAt": 1795400000000, "lastAt": 1795486200000, "active": true }
]
```

- 分工：`warnings` = 現在需要處理的；`findings` = 觀察到的現象與經過。同一件事不兩邊都放。
- `key`（約定）：`upstream-failing`、`upstream-all-down`、`serve-stale-high`、`cdn-verify-fail-high`、`chain-intercepted`、`chain-released-untrusted`、`chain-audit-released`、`list-copy-no-room`、`cdn-db-pruning`、`job-failing`、`friends-sync-failing`、`reach-single-pop`、`reach-none`、`pop-mismatch`、`pop-switched`、`pop-flapping`、`slower-fallback`、`slower-fuse`、`cdn-verify-paced`（3.5.0 F12：新網域很多，CDN 驗證減量中）。之後可能會加，不認得的 `key` 請照 `text` 顯示。
- 3.5.0 F3：`serve-stale-high` 要四個條件都成立才出現——最近 15 分鐘查詢 100 筆以上、過期快取回答的佔 5% 以上、背景更新失敗 5 次以上、而且過期回答裡至少四分之一是更新失敗（查詢少、重複多的家裡過期比例本來就高，不代表上游有狀況）；文字寫「…其中 M 次背景更新失敗：上游可能有狀況」。`cdn-db-pruning` 的文字改成「CDN 網域資料超過筆數上限（依磁碟預算與實際大小換算），淘汰了最久沒用的（累計 N 筆）」。
- `sev`：`warn` / `info`。排序：`warn` 在前，同級 `lastAt` 新的在前。
- `text`：一句話（最長 200 個字元，內容不是約定）；只放數量、CDN 名稱、機房代碼，不放網域與用戶端 IP。
- `count`：次數（飽和到 9,999）。狀態類（例如上游暫停中）是「從不成立變成立」的次數；事件類（例如機房切換）用來源模組自己的計數算，沒人開狀態頁的那幾天也是對的。
- `firstAt`：這台第一次看到的時間（沒人讀狀態時可能比實際晚）；`lastAt`：最近一次（狀態類成立時每次評估更新）。`active`：這一次評估條件還成立（事件類是最近一小時內發生過）。
- 上限與過期：最多 32 筆；`lastAt` 超過 24 小時（`info` 6 小時）沒再發生就拿掉；30 秒最多評估一次；只在記憶體，重新啟動、重新載入設定清空；系統時間還沒對時是 `[]`。

### `stale`（過期快取的比率）

```json
"stale": { "today": 120, "rateToday": 0.004, "rate15m": 0.0, "rate1h": 0.001 }
```

3.5.0 F3 多 `refreshFail15m`：最近 15 分鐘背景更新做完、結果還是失敗（上游全部失敗、或 SERVFAIL）的次數，加上上游全部失敗、直接回舊資料的次數（比率的定義不變）。

`today` = 今天回了過期資料的次數（同 `stats.today.stale`）；`rateToday` = `today ÷ 今天的查詢數`；`rate15m`、`rate1h` 讀 24 小時歷史的最近 3、12 格（只算完整的 5 分鐘）。沒有查詢時是 0。`/api/dashboard` 也有同一份。

### `history`（24 小時歷史，`/api/dashboard` 與 `/api/status?history=1`）

```json
"history": { "stepSec": 300, "from": 1795400100, "n": 288,
  "q": [12, 9], "blocked": [1, 0], "servfail": [0, 0], "stale": [0, 0], "miss": [5, 4],
  "p50": [20, null], "p95": [100, null], "abroad": [3, 2], "tw": [3, 2] }
```

- 每 5 分鐘一格、最多 288 格，欄位分開的陣列（每個陣列 `n` 個）。`from` = 第一格開始的 **Unix 秒**；最後一格是上一個完整的 5 分鐘（進行中的那一格不給）。剛啟動時 `n` 不到 288。
- `q` 查詢、`blocked` 攔截、`servfail` 失敗、`stale` 過期快取、`miss` 問上游、`abroad` 原本會出國的 CDN 回應、`tw` 其中換成台灣的（比率 = `tw ÷ abroad`）。
- `p50`、`p95`：問上游的延遲（毫秒，直方圖的區間上限、無條件進位）；`null` = 那一格沒有問上游，`1001` = 超過 1 秒。直方圖只有 12 個區間，圖是階梯狀的。
- 只在記憶體、重新啟動清空；時鐘倒退或跳了超過 24 小時就清空重來。

### `/api/dashboard` 的 `paths`（兩條路比對）

```json
"paths": { "sites": 412,
  "orig": { "ok": 398, "fail": 14, "abroad": 301, "medianMs": 48.0 },
  "tw":   { "ok": 371, "fail": 22, "slower": 5, "medianMs": 6.5 },
  "both": 350, "twFaster": 338, "twSlower": 12, "medianSavedMs": 37.5 }
```

- 來自 CDN 網域資料裡驗證時已經量的兩個數字（原本的 IP、台灣節點），不另外探測。只算在記憶體裡的網域資料（被記憶體控制移到磁碟的冷資料不算）。
- `sites`：有原本或台灣結果的網域數；`orig.ok`／`fail`：原本的 IP 探測成功／失敗；`orig.abroad`：原本在國外機房；`tw.ok`／`fail`：台灣節點驗證通過／沒通過；`tw.slower`：台灣節點能用但實測比原本慢、暫時用原本的答案（E7）；`medianMs` 只算成功的。
- `both`：兩邊都量到延遲的；`twFaster`／`twSlower`：其中台灣比較快／慢的；`medianSavedMs`：原本 − 台灣的中位數（負的 = 台灣比較慢；以前的 `acceleration.medianSavedMs` 只收台灣比較快的，照舊不變）。
- `paths`、`stale`、`history` 是營運狀態，**公開頁（`/api/public/stats`）不帶**。

### `cdn` 的線路感知欄位

`/api/status` 的 `cdn`（`Cdn::status_lite()`）多下面幾個；CDN 關著時 `cdn` 照舊是 `{"enabled": false}`。**`/api/cdn/pools` 不帶 `reach`**（它的最上層鍵是各家 CDN，介面逐一當成 CDN 畫）。

```json
"reach": {
  "at": 1795486200000, "wanEpoch": 0, "stale": false, "unconfirmed": 0,
  "v4": { "text": "這條線目前只到得了台北機房", "multi": false,
          "pops": [ { "pop": "TPE", "city": "台北", "nodes": 31, "prefixes": 22, "providers": 4, "medianMs": 4.1 } ] },
  "v6": { "text": "這條線的 IPv6 目前量不到台灣機房（節點池還沒建立，或節點都連不上）", "multi": false, "pops": [] },
  "nearby": [ { "provider": "fastly", "pop": "NRT", "prefixes": 6 } ]
},
"popHealth": [ { "provider": "cloudflare", "family": 4, "pop": "TPE", "nodes": 9, "bad": 0, "failRate": 0.0,
                 "medianMs": 4.2, "badStreak": 0, "held": false, "heldUntil": null } ],
"popSwitch": { "enabled": true, "eligible": false, "reason": "single-pop", "switches24h": 0,
               "eligibleFamilies": [], "holds": [], "excluded": [ { "provider": "fastly", "reason": "nearest-provider" } ] },
"popAudit": { "enabled": true, "pending": 0, "confirmed": 31, "mismatch": 0, "probes24h": 0,
              "lastMismatchAt": null, "chainPopUnreliable": false, "pendingServed": 0, "lastProbeAt": null, "noTarget": 0 }
```

| 欄位 | 說明 |
|---|---|
| `reach` | 這條線到得了哪些台灣機房（只算這台自己確認過的節點：不在壞節點裡、是台灣機房、不是種子、沒有 `upPop`）。`at` 毫秒或 `null`；`wanEpoch` 每次 WAN 變動加 1（重新啟動歸 0）；`stale` = WAN 變動後、下一輪健檢之前，或串接中；`unconfirmed` = 上游給的、這台還沒量過機房的節點。`v4`／`v6.text` 一句白話（內容不是約定）；`multi` = 兩個以上城市、每個城市至少 2 個節點分在 2 個以上網段（機房切換的資格）；`pops[]` 最多 8 個，依節點數排序，`pop` 是代碼前三碼（TPE、TSA 分開列、城市都是台北），`prefixes` 是 IPv4 /24、IPv6 /48 的數目，`medianMs` 可能是 `null`；`nearby[]` 是 Fastly 這類最近節點型（沒有台灣機房），最多 8 個 |
| `popHealth` | 每一輪健檢依（CDN、家族、檢查前的機房）彙總，最多 64 筆；最近節點型不列。`badStreak` 連續幾輪「變差」（失敗率 ≥ 20%，而且節點數 ≥ 3 或壞的 ≥ 2）；`held`／`heldUntil`（毫秒）= 暫時排到後面 |
| `popSwitch` | 機房切換（`cdn.popSwitch`）。`reason`：`disabled`、`chained`、`chain-pop-unreliable`、`memory`、`single-pop`（沒有家族符合資格）、`ok`；`nearest-provider` 只出現在 `excluded[]`。`eligibleFamilies`：符合資格的家族；`holds[]`：`{ provider, family, pop, until（毫秒）, other }`；`switches24h`：24 小時內暫緩的次數 |
| `popAudit` | 機房以這台量到的為準（`cdn.popAudit`）。`pending`：`upPop` 還在的節點；`confirmed`／`mismatch`：啟動後累計的比對次數；`probes24h`：24 小時內用掉的機房抽查名額（一天最多 24 個、`cdn.lite` 8 個）；`lastMismatchAt` 毫秒或 `null`；`chainPopUnreliable`：24 小時內比對過的一半以上不一樣（至少 4 個），期間不做機房切換。3.5.0 F7：抽到的答案 IP 不是待確認的節點時，改量一個待確認的前幾名節點（每家 CDN、每個位址族排在前 `serveCount` 名的，各家輪流；名額不變）——`pendingServed`：前幾名裡還沒確認的；`lastProbeAt`：上次量機房的時間（毫秒或 `null`）；`noTarget`：拿到名額、但已經沒有要量的次數 |
| `slowerFuseUntil` | 跳了才有（毫秒）：一小時裡「台灣節點比原本慢」超過 30%（至少 10 次），之前照常換台灣節點 |
| `stats.verifyOk`／`verifyFail`／`slowerFallback` | 台灣節點驗證通過／沒通過（不含比原本慢）／比原本慢暫時用原本答案的次數（啟動後累計，32 位元）。3.5.0 F9 多 `slowerFirst`（第一次量到慢，照樣換台灣節點）、`slowerReturned`（退回之後重驗不慢、回台灣節點）。3.5.1 多 `origTw`（驗證時原本的答案已經在台灣機房、不換；不算在 `verifyFail`）、`dedicated`（業者專用 IP 照原本的答案回的次數） |

其他：`/api/cdn/pools` 還沒確認的節點多 `upPop`；3.5.1：被驗證暫停的節點多 `strikes`（24 小時內第幾次，暫停 30 分鐘 × 2^(次數−1)、最多 8 小時，期間健檢通過也不恢復）；`/api/cdn/domain` 的 `v4` 在「比原本慢」時多 `slower: true`、`score`、`origScore`（毫秒）；`/api/cdn/explain` 多決定代碼 `slower`。

3.5.0 F9（比原本慢的第二版）：`score`／`origScore` 的意義改成**連線＋TLS 握手**的毫秒數（台灣節點／原本的 IP；不含收到回應標頭的時間）。判斷是「台灣 × 0.7 > 原本 ＋ 10 毫秒」，要連續 2 次驗證、相隔 10 分鐘以上都慢才退回；第一次慢時 `v4` 多 `slow1: { at, score, origScore }`、照常換台灣節點（`explain` 的 `text` 多一句「上一次驗證握手比原本慢，再確認一次才會退回」）。退回 15 分鐘（`cdn.lite` 1 小時），到期後有人查才重驗，重驗一次不慢就回台灣節點並清掉 `slower`／`score`／`origScore`／`reason`。分數只存在 `slow1`／`slower` 的那幾筆。手動 `POST /api/cdn/verify` 走同一套（不受 F12 的名額限制，但算進用量），回應是 `{ "result": 網域紀錄, "error": "ok"｜"fail"｜…, "entry": …, "speed": … }`，`speed` 是 `{ "score", "origScore", "weighted"（台灣 × 0.7）, "slower"（這一次慢不慢）, "state", "confirmAfter" }`：`state` 是 `ok`、`slow1`（第一次慢，或第一次慢之後不到 10 分鐘又驗：不算確認、`slow1` 的時間不重設）或 `slower`（確認退回）；`confirmAfter` 是 `slow1` 時還要等幾毫秒下一次驗證才算確認，其他是 0。沒有判的時候 `speed` 是 `null`：IPv6、Fastly 這類最近節點型、手動「一定換」、只能用 HTTP 驗證的網站、量不到握手、保險絲跳了、`cdn.slowerFallback` 關掉（這幾種都照驗證通過處理，並清掉 `slow1`）。第一次慢的日誌併在既有的 ✔ 那一行：「✔ example.com IPv4 台灣節點可用 (TPE 200 5ms)；握手比原本慢（250 對 100 毫秒），先照常換，10 分鐘後有人查再確認一次」；確認退回「↷ example.com IPv4 台灣節點能用，但握手連續兩次比原本慢（250 對 100 毫秒，相隔 12 分鐘）：暫時用原本的答案，15 分鐘後有人查再重驗」；退回後重驗還是慢「↷ … 重驗握手還是比原本慢（…）：繼續用原本的答案，15 分鐘後有人查再重驗」；回來「✔ … 台灣節點可用 (…)；重驗握手不比原本慢，回到台灣節點」。`kuroshio notify wan-changed`（`/api/notify/wan-changed`）多做一件事：把 `reach` 標成過期、清掉機房切換的連續計數與暫緩，不補跑健檢或掃描。

### `/api/community/status` 的 `ispGroup`

```json
"ispGroup": { "share": true, "mine": "cht", "sameGroupFriends": 2 }
```

`community.shareIspGroup`（UCI `share_isp_group`，預設關）開著時才有 `mine`（這台 WAN 的 ISP 群組，偵測不到是 `null`）；關著是 `{ "share": false, "sameGroupFriends": 0 }`。`/api/community/peers` 每個好友的 `info` 多 `isp`（對方有給、而且這台也開著才有）。協定：只放在同步回應的 `ctx`（`NetInfo.isp`，最長 16 個字元、小寫英數與 `-`、`_`，不符當沒有），身分文件不放；沒開時不序列化，位元組跟 3.4.x 一樣。

## 實測修正（3.5.0 F 組）

規格 11 第 6 節。全部放在既有路徑的新欄位裡，**沒有新的管理 API 路徑**：OpenWrt 的 `rpcd.sh` 白名單、padavan 韌體的 `kuroshio.sh api` 白名單都不用改。新設定都有安全的預設值；行為改變的幾包都有開關，關掉＝這一包之前的行為。

### 新設定

| JSON | UCI | 預設 | 說明 |
|---|---|---|---|
| `upstream.roundAwareFailures` | `config upstream` 的 `option round_aware_failures` | `true` | 上游成敗照整輪判斷（F4）。`false`＝這一包之前的記法 |
| `benchmark.probeSample` | `config benchmark` 的 `option probe_sample` | `true` | 惡意網站探測的網域從已下載的惡意類清單抽樣（F10，見上面「惡意網站探測」） |
| `filter.lists[].probe` | `config filter_list` 的 `option probe` | 沒寫 | 這份清單能不能抽探測網域；沒寫＝依分類與網址（F10） |
| `cdn.verifyPacing` | `config cdn` 的 `option verify_pacing` | `true` | 新網域很多時 CDN 驗證自動減量（F12） |
| `cdn.verifyPerMin` | `config cdn` 的 `option verify_per_min` | `auto` | CDN 驗證每分鐘上限（F12；6～1,200） |

`/api/config` 的 `auto`（依 CPU 換算、沒填＝自動的欄位）多 `cdn.verifyPerMin`。

### `/api/status`、`/api/upstreams` 的上游（F4）

`upstreams[]` 每台多三個計數（啟動後累計，32 位元；串接上游不算「來不及」）：

- `servfail`：這台正常回應了 SERVFAIL 的次數。同一筆查詢多台都 SERVFAIL＝網域壞掉，不算任何一台失敗；單一上游 SERVFAIL 而別台正常回答才算那台失敗（這一點跟以前一樣，只是分開計）。
- `late`：已經送出、但別的上游先答完，這台還沒回來就被取消的次數。沒有延遲紀錄的上游用等了多久當下限（不再永遠排第一個問）；連續 8 次都來不及、而且這段期間沒成功過才算 1 次失敗（成功一次歸零）。上線以來一次都沒成功過的，第一次這樣時一行 INFO「`<id>` 到現在一次都沒答成功（每次都是別的上游先答完），先排到後面；可能是位址或協定不通」（3.5.0 第一階段後改：以前寫「每次都來不及回答」，其實這一行只在 `ok` 是 0 時寫，不是慢，是沒答成功過）。成功過的不寫這一行。
- `unanswered`：整輪沒有任何上游正常回答（Ok、NODATA、NXDOMAIN 都算正常）、所以沒有算它失敗的次數。等了逾時 90% 以上的失敗與 SERVFAIL 先收著，這一輪有別台正常回答才記失敗；很快就回來的錯誤（連線被拒、TLS 失敗、HTTP 4xx）照舊立刻記。整台斷網時不記失敗、不暫停。

成功率照舊用 `ok ÷ (ok + fail)`；ui-core.js 的 `upstreamExtra(u)` 把 `servfail`、`late` 寫成「SERVFAIL 3、來不及 5」（都是 0 不顯示）。`avgMs`：來不及回答時會被往上修（沒有延遲紀錄的設成等了多久），所以一直來不及的上游不再是 `null`。`upstream.roundAwareFailures` 關掉時不寫 `late`／`unanswered`（`servfail` 照數，只是顯示）。

### CDN 驗證節流（F12）

`/api/status` 的 `cdn` 多：

```json
"pace": { "enabled": true, "lite": false, "perMin": 30, "maxPerMin": 60, "minPerMin": 7, "paced": true,
          "usedLastMin": 30, "usedThisMin": 12, "cpuPct": 41, "waited": 1234, "capped": 56, "since": 1795486200000 },
"bg": { "verify": { "started": 1200, "done": 1190 }, "ecs": { "started": 80, "done": 80 },
        "cross": { "started": 12, "done": 12 }, "latency": { "started": 300, "done": 300 } }
```

- `enabled`：`cdn.verifyPacing`；`lite`：`cdn.lite`。關掉節流時 `perMin`／`maxPerMin` 在小機器是 30（3.4.2 的上限照舊）、其他機器是 `null`，`minPerMin` 是 `null`，`paced` 是 `false`。
- `perMin`：目前的速率，在 `minPerMin`（`max(6, maxPerMin ÷ 8)`）與 `maxPerMin` 之間；`maxPerMin` 依機器換算（小機器 30，或 `cdn.verifyPerMin` 比 30 小時照填的）。主程式每 10 秒量一次黑潮自己這 10 秒用掉的 CPU 佔整台的比例（`cpuPct`；還沒交或量不到是 `null`）：55% 以上減半、30% 以下加 `maxPerMin ÷ 10`、中間不動；記憶體壓力不是 Normal 時是 `minPerMin`。量不到 CPU 時不依 CPU 降，壓力解除後照「30% 以下」慢慢加回 `maxPerMin`。
- `paced`：減量中。這一分鐘有任何一個排不進（名額用完、或只問過一次的網域碰到一半的上限）、或速率低於上限時進入；連續 5 分鐘名額都沒用完而且速率回到上限才離開（主程式沒接上 CPU 讀數時，查詢路徑每分鐘順便檢查一次，照樣會自己離開）。進入、離開各一行 INFO（小機器不寫進入那一行）。減量中只問過 1 次的網域不排驗證、ECS、延遲量測、跨 CDN 探索（照常回原本的答案，`/api/cdn/explain` 是 `paced-waiting`）；`since` 是進入的時間（毫秒，不在減量中是 `null`）。**小機器（`lite: true`）永遠在減量**，`paced` 一直是 `true`、`since` 是 `null`。
- `usedLastMin`：上一個整分鐘用掉的名額，`usedThisMin`：這一分鐘到現在（手動 `POST /api/cdn/verify` 不受限制但算進去）；`waited`：減量中只問過一次、所以沒排的查詢次數；`capped`：名額用完沒排的工作數（都是啟動後累計）。名額在去重與排隊上限之後才用：同一個網域已經在排、或排隊已滿的不用掉名額。同一分鐘裡到期重驗與問過 2 次以上的新網域可以用到 `perMin`，跨 CDN 探索只能把這一分鐘的總用量推到 `perMin` × 3/4，只問過一次的新網域只能推到 `perMin` ÷ 2。`cdn.lite` 照舊有 `stats.liteWaited`／`liteCapped`，`pace.waited`／`capped` 是所有機器的。
- `bg`：驗證、ECS、跨 CDN、延遲量測各自「開始幾個（拿到並行名額、開始做）、完成幾個（正常做完；被取消的不算）」的累計，給壓測分辨成本在哪一種工作。
- `findings` 多 `cdn-verify-paced`（info）「新網域很多，CDN 驗證減量中（每分鐘 N 個）」；小機器永遠在減量，那是常態，不報。
- 舊版核心沒有 `pace`；`pace` 是空物件時介面不顯示（ui-core.js 的 `paceView`；小機器不用提醒樣式）。

### 其他欄位與日誌

- `/api/status` 的 `system.rssKB` 在 Windows 也有值（F6；以前只讀 `/proc`，Windows 上是 `null`）。介面讀不到時退回 `memory.rssKB`。
- `memory.waiting` 多一種文字「可用記憶體已經回到保留量以上，等狀態穩定，不再讓出」（F1）；「於事無補」的離開要條件連續成立 60 秒（包括回到寬裕），離開的日誌在那時才出現。INFO「記憶體不足，但缺口是其他程式造成…」同一段於事無補（從進入到離開）只寫一次（3.5.0 第一階段後修正，Windows W19：讀數被別的程式拉上拉下時以前每次掉回保留量以下都再寫一行）；進入的 WARN 已經說明了。
- 只改 `pool.*` 或只影響 CDN 背景與觀測的鍵（`cdn.dbDiskBudgetKB`、`maxEntries`、`popAudit`、`verifyConcurrency`、`verifyPacing`、`verifyPerMin`、`cross.concurrency`、`cross.requestScore`、`cross.recheckHours`、`healthIntervalMin`、`qualityIntervalMin`）時，重新載入不清 DNS 快取；日誌文字改成「上游、解析或 CDN 的設定有變，DNS 快取重新開始」（F5）。
- 重新載入設定時排隊中的工作與執行中被中斷的工作排回新的一輪（60 秒內有效；手動的照樣優先），日誌「重新載入：保留排隊中的工作 N 個（…）」「…重新載入時中斷，重新執行」。被中斷的那一次重跑時原因保留原本的在前面（例如「手動 (管理介面)；重新載入時中斷，重新執行」，`/api/jobs` 的 `running.reason`、`state.<名稱>.reason` 也是這個），工作照樣看得出是手動（tw-ip 手動時不看清單幾天、一定重新產生；3.5.0 第一階段後修正，Windows W23），但重排的那一筆不標手動優先（`priority: false`）；同一個工作連續因為重新載入中斷 2 次就不再自動排回（WARN）；保留不了的寫「重新載入：取消排隊中的 `<名稱>`（工作已停用）」。程式結束時不交接（F14）。
- 查詢紀錄開、關各一行 INFO（F6）。節點池測速的日誌：被限流時 WARN「[cloudflare] 測速被對方限流（HTTP 429）：這一輪不再對它測速，沿用上一輪的速度與參考值；排序照延遲」，其他失敗印「沒量到（HTTP 403）」「沒量到（連線失敗）」，不再印「0 MB/s」；快測那一行印實際量到的速度（F6、F15）。

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
| `resolver.cacheMax` | DNS 快取筆數上限（預設 `auto`：實體記憶體 × 8% ÷ 600 bytes，4,000～100 萬；3.5.1 以前固定 100,000。記憶體控制另外會依可用記憶體收緊） |
| `benchmark.concurrency` | 每日評測同時測幾個候選 |
| `cdn.verifyConcurrency` | CDN 節點驗證同時幾個（每個都是 TLS 握手） |
| `cdn.lite` | 3.4.2：`auto`（預設，實體記憶體小於 160 MB 時減量）／`true`／`false`（UCI 是 `config cdn` 的 `option lite '1'`／`'0'`）。減量不是關掉：只驗證問過 2 次以上的網域、驗證每分鐘最多 30 個、節點池測速 4 個節點；狀態的 `cdn.lite` 與 `cdn.stats.liteWaited`、`liteCapped`（都是次數：還沒驗證完的網域每查一次就再算一次，不是網域數） |
| `pool.relativeSpeed` | 3.5.0：節點測速用相對評分（預設 `true`；UCI 是 `config pool` 的 `option relative_speed '0'`／`'1'`）。關掉＝3.4.x：低於 1 MB/s 算慢、差 5% 以內才算瓶頸、直接比速度 |
| `cdn.cross.requestScore` | 3.5.0：跨 CDN 加實測分數（預設 `true`；UCI 是 `config cdn` 的 `option cross_request_score '0'`／`'1'`）。分數是連線＋TLS 握手的毫秒數（F13）。關掉＝3.4.x：只看 TCP 延遲 |
| `cdn.verifyPacing` | 3.5.0 F12：新網域很多時 CDN 驗證自動減量（預設 `true`；UCI 是 `config cdn` 的 `option verify_pacing '0'`／`'1'`）。關掉＝只有 `cdn.lite` 有每分鐘 30 個的上限 |
| `cdn.verifyPerMin` | 3.5.0 F12：CDN 驗證每分鐘上限。`auto`（預設：`cdn.lite` 30；沒有 AES 的核心數 × 30；有 AES 的核心數 × 60、最多 480）／數字（6～1,200）。UCI 是 `config cdn` 的 `option verify_per_min`。`kuroshio sysinfo` 印出換算的值 |
| `cdn.multiCdn` | 3.5.0：尊重多來源 CDN、第一層 CNAME 變了就失效（預設 `true`；UCI 是 `config cdn` 的 `option multi_cdn '0'`／`'1'`）。關掉＝3.4.x：每個網域只記一家、業者欄位直接改寫 |
| `cdn.appLayer` | 3.5.0：App 自己選節點的服務（目前 Google、Apple）只辨識、不改寫（預設 `true`；UCI 是 `option app_layer`） |
| `cdn.dbDiskBudgetKB` | 3.5.0：CDN 網域資料在磁碟上的預算。`auto`（預設：狀態目錄所在的檔案系統小於 64 MB 時用總容量的 30%，64 MB 以上或讀不到大小時不限）／數字（KB，下限 512）／`0`（不限）。UCI 是 `config cdn` 的 `option db_disk_budget_kb`。超過時在背景分批淘汰最久沒用的網域（一天內查過的、手動設定策略的不動），不會一次重寫全部分片。狀態：`cdn.dbBudgetKB`、`dbBudgetEntries`、`dbEntries`、`dbDiskKB`（實際）、`dbDiskEstKB`、`prunedForBudget`。3.5.0 F8：`dbDiskKB` 量的是網域分片**實際佔用的磁碟區塊**（Unix 是 `blocks × 512`；`blocks` 是 0 的檔案系統與 Windows 用檔案長度），預算比的就是它；`dbFileKB` 是檔案長度合計（F8 之前 `dbDiskKB` 的量法，小檔多時少算約兩成）；`cdnDirKB` 是整個 `cdn/` 目錄（含節點池、網段掃描等，往下量兩層）實際佔用，只顯示、不算進預算。三個值在每一輪預算時量（不在查詢路徑上）：有預算的機器載入時就量，沒有預算的機器要等第一輪預算（每次登記快照之前）才有值。升級後小 Flash 的網域筆數上限會變低一些，多出來的照既有的方式分批淘汰 |
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
  | `/api/cdn/explain` | 唯讀 | 3.5.0 | CDN 頁「為什麼沒換到台灣」 |
  | `/api/querylog` | 唯讀 | 3.5.0 | 日誌頁「查詢紀錄」 |
  | `/api/querylog/enable` | 動作（POST） | 3.5.0 | 日誌頁「開啟 10 分鐘」「關閉」 |
  | `/api/cdn/status`、`/api/protocols`、`/api/backup/last-import` | 唯讀 | 3.0～3.3（rpcd 3.5.0 才開放） | 沒有（給查詢用） |

  刻意不開放：`/api/memory/simulate`（只給測試，`system.testHooks` 開著才能用）、`/api/notify/wan-changed`（系統通知用）、`/api/session`（網頁登入）；`/api/about`、`/api/defaults`、ACME 走 rpcd 自己的方法。

  `kuroshio` 套件裡有一個測試確認 rpcd 的唯讀白名單沒有會改變狀態的路徑、動作白名單都是會改變狀態的路徑。
- **查詢紀錄**（3.5.0）：`GET /api/querylog?limit=200&name=&client=&since=` 讀最近的查詢（新的在前，`limit` 最多 1,000；`name` 是「包含這段文字」，`client` 是來源 IP，`since` 是毫秒時間戳）；`POST /api/querylog/enable?minutes=10` 暫時開啟（1～60 分鐘，到時間自動關閉並釋放；`minutes=0` 關閉）。`log.queryLog: true` 是常開。每一筆是 `{at, name, type, client, result（hit／miss／blocked／stale）, rcode, ms, source}`。
  - 隱私：查詢紀錄含裝置位址與網域，是最敏感的資料：**只在記憶體**（不寫磁碟、不進備份、不給公開頁、不傳給上游／下游／好友），預設關閉，`/api/status` 的 `queryLog` 只顯示開著與否、到幾點、幾筆。串接中，上游放行的下游黑潮的查詢也會出現在上游的紀錄裡。
  - 上限：筆數（環狀，`system.queryLogRing`，實體記憶體 160 MB 以下最多 1,000、512 MB 以下最多 5,000）、時間（暫時開啟最長 60 分鐘）。查詢不等紀錄的鎖：拿不到就丟掉那一筆（`dropped`）。
  - OpenWrt 的 rpcd 開放 `/api/querylog`（唯讀）與 `/api/querylog/enable`（動作）。
- **為什麼沒換到台灣**（3.5.0）：`GET /api/cdn/explain?name=example.com` 回這個網域哪家 CDN、換或不換台灣節點、為什麼，以及驗證結果（`steps`：`v4`、`v6`、`ecs`、`cross`）。只讀：不增加查詢次數、不排驗證、不連網路（要重新驗證用 `POST /api/cdn/verify`）。CDN 沒開時也回答（`cdn-disabled`）。`decision` 的代碼（介面依代碼顯示；`text` 是核心給的白話）：

  | 代碼 | 意思 |
  |---|---|
  | `rewritten` | 已經換成驗證過的台灣節點 |
  | `already-tw` | 原本的答案就是台灣節點。3.5.1：跟查詢路徑一樣用最近一次答案的 IP 在節點池裡的分類判斷；也包括台灣本地的 CDN（中華電信 HiNet CDN），以及驗證時原本的答案已經在台灣機房、不換的（`steps` 的 `v4` 多 `origTw`：那時量到的 POP） |
  | `trial` | 台灣節點還在驗證中（先回原本的答案，TTL 10 秒） |
  | `lite-waiting` | 小記憶體減量：問過 2 次以上才驗證 |
  | `paced-waiting` | 3.5.0 F12：新網域很多（或 CPU 很忙），CDN 驗證減量中，問過 2 次以上才驗證，先回原本的答案（小機器照舊是 `lite-waiting`） |
  | `slower` | 3.5.0 E7、F9：台灣節點能用，但握手連續兩次比原本的答案慢，暫時用原本的答案（15 分鐘、小機器 60 分鐘後有人查再重驗） |
  | `essential` | 3.5.0 F11：內建的時間同步、連線偵測、憑證撤銷、地震速報服務：不改寫、不擋。多 `known: true` 與 `essential`（類別代碼 `ntp`、`netcheck`、`revocation`、`quake`），沒有 `provider`／`steps`（這些網域不記進資料庫，`/api/cdn/domain` 查不到） |
  | `verify-failed` | 台灣節點驗證沒通過（到期後重新驗證） |
  | `no-tw-node` | 找不到可用的台灣節點，跨 CDN 也沒有 |
  | `no-pool` | 這家 CDN 的台灣節點池還沒建好 |
  | `cross` | 換成同一個網站在別家 CDN 的台灣節點 |
  | `ecs` | 帶台灣網段問到台灣節點（依查詢來源分流的 CDN） |
  | `policy-never`／`policy-always` | 手動設成不換／一定換 |
  | `multi-cdn` | 3.5.0：網站自己在多家 CDN 之間分流，不替它換到別家（回答來自驗證過的那一家時照常換，那時是 `rewritten`） |
  | `app-layer` | 3.5.0：App 自己選節點的服務，只辨識、不改寫 |
  | `dedicated-ip` | 3.5.1：業者專用 IP（GitHub Pages 這類，只有那幾個位址服務它），照原本的答案 |
  | `chained` | 串接中：上游黑潮換好，這台不處理 |
  | `memory-floor` | 記憶體控制的最低限度：暫停 CDN 調整 |
  | `cdn-disabled` | 這台沒開 CDN 台灣節點 |
  | `not-cdn`／`unknown` | 不是認得的 CDN／還沒人查過 |

  內建服務裡的**系統與安全更新**（F11 的 `update` 類，例如 Windows Update、Apple 的更新）只保證不被清單誤擋，CDN 照常判斷（更新是大檔，從台灣節點拿最有感），所以 `explain` 不是 `essential`，而是照一般 CDN 網域的代碼：`rewritten`、`multi-cdn`（網站自己在多家 CDN 之間分流）、`app-layer`（Apple CDN 這類 App 自己選節點的）、`no-tw-node` 等都是正確的結果。`essential` 只給不改寫的四類（時間同步、連線偵測、憑證撤銷、地震速報）。

  OpenWrt 的 rpcd 開放 `/api/cdn/explain`（唯讀）。
- **多來源 CDN 的欄位**（3.5.0）：`/api/cdn/domain` 與 `/api/cdn/explain` 多回：
  - `c1`：第一層 CNAME 的鍵（查詢名稱的第一個 CNAME 目標取最後三段，例如 `a1b2.node7.edge.example.net` → `edge.example.net`；最長 64 位元組；沒有 CNAME 就沒有這個欄位）。
  - `multi`：7 天內看過兩家 CDN 輪流回答。
  - `provs`：最近看到的業者，最多 3 個：`[{ "provider": "cloudfront", "lastSeen": 毫秒, "verified": true }]`。`verified: true` 是有自己一格驗證結果的（最多兩家），`false` 是沒有格子、照原始答案回的。
  - `/api/cdn/domain` 的 `src`：原始的來源紀錄（`alt` 是另一家的那一格：`provider`、`v4`、`v6`、`base`、`last`；`seen`、`pend` 是第一層 CNAME 的防抖動狀態；`multiAt`、`invalAt`、`slotAt` 是毫秒時間）。這些欄位 3.4.x 讀到會原樣保留。
  - `/api/status` 的 `cdn.stats`：`srcInvalidated`（來源變了而清掉跨 CDN／ECS 的次數）、`multiHeld`（多來源沒有格子、照原始答案回的次數）、`appLayer`（App 層不改寫的次數）。
- **跨 CDN 的實測分數**（3.5.0）：`/api/cdn/domain` 的 `cross4` 多 `score`（換過去那一家）與 `origScore`（原站）：連線＋TLS 握手的毫秒數（F13 起不含收到回應標頭的時間，那是原站產生內容的時間、只會蓋掉差距），各取兩次探測裡比較小的；`cross4.tried[]` 每一家多 `score`（第一次探測的）。`verdict` 是 `fail` 而且兩個分數都有＝「連線比較近，但握手沒有比較快」。舊資料（連線＋握手＋TTFB）在下一次每日複驗時被新的值蓋掉。`/api/cdn/explain` 的 `cross` 步驟一樣多這兩個欄位；`GET /api/cdn/cross` 多 `scoreRejected`（因為這個原因沒有採用的網域數）。探測量不到分段時間時沒有這些欄位，照 3.4.x 的規則判斷。
- **節點池的測速欄位**（3.5.0）：`GET /api/cdn/pools` 每家多 `speedRef`（這一次節點池工作量到速度的節點的中位數，MB/s；量到的不到 3 個時是 `null`），每個節點多：
  - `slow`：`true`／`false`＝相對評分的結果（連加上誤差範圍都不到 `speedRef` 的一半、或低於 0.1 MB/s）；沒有這個欄位＝沒量過速度，或舊資料（那時照舊規則：`speed` 低於 1 MB/s 算慢）。
  - `sample`：`{ "bytes": 8388608, "secs": 0.144, "connectMs": 4.1, "ttfbMs": 9.3, "quick": true }`——那一次下載收到的位元組數、收內容的秒數、連線（含 TLS 握手）與送出請求到收完標頭的毫秒數；`quick` 是量到瓶頸之後只收 1 MiB 的快測（這時節點的 `speed` 記的是瓶頸的速度）。這些是 3.6 工作負載分數的量測基礎，3.5.0 只收集、不參與排序。
  - 3.5.0 F15、F16：每家多 `quickRef`（完整測的節點「前 1 MiB」速度的中位數，MB/s：快測的門檻跟它比；沒有時是 `null`、照舊公式）與 `speedRefWhy`（`speedRef` 沒算出來的原因，例如「量到速度的節點只有 2 個（要 3 個）」「被限流」）；`sample` 多 `headSecs`（收到第 1 MiB 的秒數）與 `status`（HTTP 狀態碼，0＝沒連上或沒收到標頭）。遇到 HTTP 429／503 時這一輪對那一家停止測速，沒量到的節點 `speed` 是 `null`（不再記成 0），上一輪有速度的沿用並記 `speedAge`（沿用了幾輪，1～3；這一輪量的沒有這個欄位）：先找同一個 IP，沒有就找同一個 /24（節點池每輪在每個 /24 裡隨機抽一個位址，只比 IP 幾乎沿用不到）。Fastly 這類最近節點型被限流時只停測、不沿用（它的速度只影響品質分數裡的「慢」，沒量到就不罰）。`speedRef` 在被限流那一輪、量到＋沿用的不到 3 個時用上一輪的，`speedRefWhy` 是「被限流（HTTP 429），沿用上一輪」；上一輪也沒有時 `speedRef` 是 `null`、`speedRefWhy` 是「被限流（HTTP 429）」。`quickRef` 要前 4 個完整測的樣本裡至少 3 個量到 `headSecs` 才算，不夠就照舊的公式。`pool.relativeSpeed` 關掉時沒有 `quickRef`，「沒量到留 `null`」兩種規則都套用。
  - 3.4.x 讀到這些欄位會原樣保留。
- **通訊類網域**（3.5.0）：推播服務的網域（內建 Apple 推播、Firebase 雲端訊息；`resolver.keepNames` 自己加，最多 64 個後綴）不被訂閱清單誤擋（`filter.protectComm`，預設開；自訂規則照樣優先，`/api/filter/check` 的 `rule` 是 `builtin-comm`）、快到期就預取（同時最多 16 個）、記憶體控制縮快取時優先留下、不換到別家 CDN。`/api/status` 的 `comm` 有內建與自己加的數量、預取中的數量；`filter.commSpared` 是清單本來要擋、照樣放行的次數（每天第一次會記一行 INFO，寫明是哪份清單，方便回報給清單維護者）。
  - 3.5.0 F11：內建表多五類——時間同步（`ntp`）、連線偵測（`netcheck`）、憑證撤銷（`revocation`）、系統與安全更新（`update`）、地震速報（`quake`）。五類都不被訂閱清單擋（`/api/filter/check` 的 `rule` 是 `builtin-<類別>`，推播照舊 `builtin-comm`）；`ntp`、`netcheck`、`revocation`、`quake` 也不改寫 CDN 答案（不排驗證、不做 ECS 與跨 CDN，`cdn.stats.essentialKept` 加 1，`/api/cdn/explain` 的決定代碼是 `essential`）；`update` 照常換台灣節點。快到期就預取的只有推播、地震速報、自己加的；記憶體吃緊時先留的是推播、`ntp`、`netcheck`、`quake`、自己加的。`/api/status` 的 `comm` 多 `kinds`（每一類內建表的筆數，例如 `{ "apns": 1, "fcm": 3, "ntp": 17, … }`），`essential`（新加的五類有沒有在比對，就是 `filter.protectComm`），`filter` 多 `commSparedByKind`（每一類放行的次數，沒有放行過的類別不列；`commSpared` 照舊是合計）。每一類每天第一次放行寫一行 INFO：「過濾：清單「X」擋到時間同步網域 `<name>`，照樣放行（filter.protectComm；可以回報給清單維護者）」（類別：推播、自己加的通訊類、時間同步、連線偵測、憑證撤銷、系統與安全更新、地震速報）。`filter.protectComm` 關掉＝新的五類一律不比對、推播回到 B6 原本的規則。`resolver.keepNames`（自己加的）只有不擋＋快取優先，不影響 CDN 改寫。內建表是編譯進執行檔的資料（`crates/kuroshio-net/src/comm.rs`）。

