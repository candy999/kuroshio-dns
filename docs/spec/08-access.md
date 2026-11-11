# 08 來源 IP 存取控制（只開放台灣）

公開在網路上的 DoH / DoT / DoQ / DoH3 與公開頁，預設只讓台灣的 IP 連進來，減少國外的掃描、濫用與小規模的攻擊流量。
台灣的網段依 ISP 分組，使用者可以只開放其中幾家；也可以自訂允許 / 封鎖名單，或整個切成「全開放」。

## 1. 設定（`access`）

| 欄位 | 預設 | 說明 |
|---|---|---|
| `mode` | `"taiwan"` | `taiwan`：全部台灣網段（含「其他台灣網段」）；`custom`：只有 `groups` 勾選的群組；`open`：全開放（`deny` 照樣有效） |
| `groups` | `["*"]` | `custom` 模式勾選的群組 id；`"*"` = 全部（之後資料新增的群組也自動包含）；`[]` = 一組都不勾（只剩區網與 `allow`） |
| `allow` | `[]` | 自訂允許的 IP / CIDR（每個模式都有效） |
| `deny` | `[]` | 自訂封鎖的 IP / CIDR：勝過一切（迴路位址除外） |
| `applyTo` | `["dot","doh","doq","doh3","site"]` | 套用在哪些服務：`dot`、`doh`、`doq`、`doh3`、`site`（公開頁）、`community`（社群共享）、`plain`（區網 DNS 53 埠） |
| `log` | `true` | 拒絕時記錄（每分鐘最多一行，含這一分鐘的次數） |
| `autoUpdate` | `true` | 每月在本機重新產生台灣 IP 資料（排程工作 `tw-ip`，見第 5 節）；`false` = 只用隨程式附帶的公版 |
| `dataFile` | `""` | 指定資料檔；空白 = 唯讀資料目錄的 `geo/tw-ip.json` |

**行為改變（3.0）**：沒有 `access` 區段的舊設定檔也會套用預設值，也就是「只開放台灣」。
人在國外、出國漫遊、用 VPN、用國外雲端主機的親友會連不上；請把模式改成 `open`，或把他們的 IP 加進 `allow`。

OpenWrt（UCI）：

```
config access 'access'
	option mode 'custom'            # taiwan / custom / open
	list groups 'cht'
	list groups 'tanet'
	list allow '203.0.113.0/24'
	list deny '198.51.100.7'
	list apply_to 'dot'             # 沒寫 = 預設的五個
	option log '1'
	option auto_update '0'
```

沒有 `config access` 區段 = 預設值；`option groups ''` = 一組都不勾。

## 2. 判斷順序

第一個符合的決定結果：

1. 迴路位址（`127.0.0.0/8`、`::1`）→ 允許（永遠不會把自己鎖在外面）
2. `deny` → 拒絕
3. 私有、CGNAT、鏈路本地、ULA（`10/8`、`172.16/12`、`192.168/16`、`100.64/10`、`169.254/16`、`fc00::/7`、`fe80::/10`），
   以及本機各網卡所在的網段（IPv4 短於 /16、IPv6 短於 /48 的只放位址本身）→ 允許
4. 社群好友目前的 IP（每 10 分鐘解析好友網域的 A / AAAA，加上最近一次連線的來源 IP）→ 允許
5. `allow` → 允許
6. `mode`：`open` → 允許；`taiwan` / `custom` → 在選取的群組裡才允許
7. 其他 → 拒絕

IPv4 對應的 IPv6（`::ffff:a.b.c.d`）一律當成 IPv4 判斷。

**台灣 IP 資料讀不到或格式錯誤時不擋（fail open）**：記錄警告，`/api/status` 的 `access.failOpen = true`、`access.warning` 寫原因；`deny` 照樣有效。

## 3. 在哪裡擋

| 服務 | 時機 | 被拒絕時 |
|---|---|---|
| DoT（TCP） | accept 之後、TLS 握手之前 | 直接關閉連線 |
| DoH（TCP，HTTPS 或純 HTTP） | accept 之後、TLS 握手之前 | 直接關閉連線 |
| DoQ、DoH3（QUIC） | 收到連線請求（Initial）、握手之前 | `Incoming::ignore()`：不回任何封包 |
| 區網 DNS（UDP / TCP 53） | 收到封包 / accept，`listen.plain.allowFrom` 之後再檢查 | 不回應 / 關閉（只有 `applyTo` 含 `plain`；`openBinds` 綁的 ULA 不檢查） |

同一個埠上可能有好幾個服務：DoT 的埠同時接社群共享（ALPN `kuroshio/2`）、DoH 的埠同時是公開頁與社群共享的 HTTPS 入口。
accept 時只有在「這個埠上的每個服務都有套用而且都不允許」才當場關閉；否則先放行，等知道是哪個服務時再判斷：

- DoT / DoQ：握手完成、看 ALPN 是 DNS 還是社群共享
- DoH / DoH3：每個請求依路徑判斷（社群共享的路徑、DoH 路徑、其他 = 公開頁），不允許回 `403`。
  反向代理（`trustProxy`，對方是本機）時用 `X-Forwarded-For` 的真正來源判斷

規則可以在執行中換掉（好友 IP、每月在本機產生的新清單、網卡位址變動），不用重新啟動監聽；設定變更照現有流程整輪重新載入。

### 查詢效率與記憶體

建立規則時把勾選的群組、自訂名單、私有網段各自合併成排序、不重疊的區間（IPv4 `Vec<(u32,u32)>`、IPv6 `Vec<(u128,u128)>`），
每次連線用二分搜尋（O(log n)）。2026-11-11 的資料全部勾選時合併成 993 個區間，約 15.7 KB；
另外保留各群組的網段（說明是哪一組、`/api/access` 用）約 21 KB。

## 4. 台灣 IP 資料（`data/geo/tw-ip.json`）

```json
{
  "version": 1,
  "generatedAt": "2026-11-11",
  "sources": [{ "name": "...", "url": "..." }],
  "total": { "v4": 35741952, "v6_48": 169870359 },
  "groups": [
    { "id": "cht", "name": "中華電信（HiNet、行動上網）", "note": "...", "asns": [3462, 17421, 17419, 131598],
      "size": { "v4": 14016768, "v6_48": 41026816 }, "v4": ["1.160.0.0/12", "..."], "v6": ["2001:b000::/20", "..."] }
  ]
}
```

讀取時檢查：每組有 id（英數、`-`、`_`，不能是 `*`、不能重複），每個 CIDR 都要有效，IPv4 總量不能是 0；不符合就整份不用（fail open）。

### 產生方式（`cargo run -p kuroshio-jobs --bin tw-ip -- data/geo/tw-ip.json 報表.md`）

1. **台灣網段** = 五個 RIR 的 `delegated-*-extended-latest` 裡 cc=TW、狀態 allocated / assigned 的 IPv4 / IPv6（主要是 APNIC / TWNIC，ARIN 與 RIPE NCC 也有少量）。
   這是**登記國別**，不是地理位置。
2. **ISP 群組** = 該 ISP 的 ASN 在 RIPEstat `announced-prefixes` 宣告的網段 ∩ 台灣網段。ISP 在國外宣告的網段（例如海外機房）不收，報表列出被排除的量。
3. **其他台灣網段** = 台灣網段 − 所有 ISP 群組。所以**全部勾選 = 整個台灣**。
4. 排序、合併成最少的 CIDR；同樣的輸入一定得到同樣的輸出。下載的台灣 IPv4 總量少於 2,000 萬就當成資料不完整而失敗。

`--cache 目錄` 會把原始資料存下來（目錄裡已經有的直接用），`--offline` 只用快取。
GitHub Actions `tw-ip.yml` 每月 2 日重新產生，有變動就 commit 到 `tw-ip/<日期>` 分支（不直接推 main），確認報表後再合併。

### ISP 與 ASN

ASN 與持有者名稱對照 RIPE NCC 的 ASN 名稱表（`ftp.ripe.net/ripe/asnames/asn.txt`，來自各 RIR 的 whois）與 RIPEstat whois。
只放一般用戶上網的 ASN；機房、CDN、國際轉接的 ASN（例如 CHTI-DC、CHT-IDC、SPARQ-IDC）留在「其他台灣網段」。

| id | 名稱 | ASN（whois 名稱） |
|---|---|---|
| `cht` | 中華電信（HiNet、行動上網） | 3462 HINET、17421 EMOME-NET（Mobile Business Group）、17419 HINET-IPV6、131598 HILINK（CHTD） |
| `twm` | 台灣大哥大／台灣固網 | 24158、131614、131647–131650 Taiwan Mobile；9924 TFN-TW、4636 TFN-TW-GCN-1、4747 TFN-TW-TTN |
| `tstar` | 台灣之星（已併入台灣大哥大） | 24157 VIBO-NET-AS（Taiwan Star Telecom） |
| `fet` | 遠傳電信／新世紀資通（Seednet） | 9674 FET-TW、18412 FEG-MPLS、4780 SEEDNET（Digital United）、9919 與 24161 NCIC-TW |
| `aptg` | 亞太電信（已併入遠傳） | 17709 APT、24154 APBT-AS-TW、24155 APBW-AS-TW、7482 與 131142 APOL |
| `kbro` | 凱擘大寬頻 | 38841 kbro-AS-TW |
| `cns` | 中嘉寬頻（bb 寬頻） | 9416、18042 KBT（Koos Broadband Telecom；9416 的 org 是 Hoshin Multimedia Center） |
| `tbc` | 台灣寬頻通訊（TBC） | 131596 TBCOM-NET |
| `cable` | 其他有線電視與地區寬頻 | 24159 Tong Ya、131602 Hsin Yeong An、131607 Digidom、131611 San Da、131625 Netwave、131627 Peicity、132738 Shih-Hsin、18413 GBTC、9922 New Kaohsiung Broadband、17809 VEE TIME、18419 DaDa、24163–24165 UBB、18182 So-net |
| `tanet` | TANet／TWAREN 學術網路 | 1659 TANet、17713 與 17717 教育部電算中心、131150 高雄市教育局、18043 新竹市教育處、7539 與 18414 國網中心、9264／18217／24167 中研院、各大學 9916／17711／17712／17716／18047／18177／18420／38844／38847／38848／63899 |
| `gsn` | 政府網路（GSN） | 4782 GSNET（中華電信數據分公司維運） |
| `other` | 其他台灣網段 | 上面以外、登記在台灣的全部網段 |

合併的業者（台灣之星 → 台灣大、亞太 → 遠傳）網段會陸續移到併購方的 ASN；資料裡兩組都保留，大小是 0 表示已經全部移過去。
2026-11-11 的資料裡台灣之星（AS24157）已經沒有宣告任何網段。

## 5. 每月在本機重新產生（排程工作 `tw-ip`）

**沒有中央伺服器**：本專案不架設、也不依賴任何共用伺服器。裝置上的程式不會從本專案（GitHub 或其他地方）下載清單，
而是由排程工作 `tw-ip` 直接向公開資料來源查詢、在本機算出清單。隨程式附帶的 `data/geo/tw-ip.json` 是「公版」預設值，
由 GitHub Actions 每月用同一份程式（指令列 `tw-ip`，`.github/workflows/tw-ip.yml`）產生、跟著版本發布；它不是執行期的相依。

### 5.1 資料來源與做法

- 五個 RIR 的 `delegated-*-extended-latest`（APNIC、ARIN、RIPE NCC、LACNIC、AFRINIC），每個好幾 MB：
  **一次抓一個、邊下載邊一行一行解析**，只留 cc=TW 的 IPv4 / IPv6 配發，整份檔案不放進記憶體；最後用標頭的筆數確認檔案完整。
- RIPEstat `announced-prefixes`：每個 ASN 一個請求（第 4 節的對照表，共 65 個），帶 `sourceapp=kuroshio-dns`（RIPEstat 對 API 使用者的要求），
  回應也是邊收邊掃，只留網段。
- 群組的算法跟第 4 節一樣（ISP 宣告 ∩ 台灣網段，`other` = 台灣 − 所有 ISP）；同樣的輸入一定得到同樣的輸出，
  排程工作與指令列共用 `kuroshio_jobs::twip`，輸出一模一樣（有測試釘住）。

### 5.2 排程與禮貌

| 設定（`jobs.tw-ip.*`） | 預設 | 說明 |
|---|---|---|
| `enabled` | `true` | 也可以用 `access.autoUpdate`（預設 `true`）：兩個都開才會跑；舊設定檔的 `access.autoUpdate: false` = 停用 |
| `at`、`monthDays` | `"00:50"`、`[1]` | 每月 1 日 00:50（台北時間）… |
| `jitterDays`、`jitterMin` | `27`、`180` | …再依這台裝置的亂數種子往後挪 0–27 天、0–180 分鐘（種子存在 `jobs.json`，之後固定）：大家不會同時去打同一個來源 |
| `minAgeDays` | `20` | 排程或補跑時，目前的清單（公版或本機產生）不到 20 天就不跑；「立即執行」照跑 |
| `pauseSec` | `[5, 30]` | 每個 RIPEstat 請求之間隨機停 5–30 秒；HTTP 429 / 503 照 `Retry-After` 等（2 分鐘以內原地等，更久就暫停稍後續跑） |
| `retrySec` | `300` | 網路錯誤或資源不夠時多久再試，之後每次加倍（網路錯誤最多 6 小時、資源不夠最多 2 小時） |
| `maxFailures` | `6` | 連續失敗（含 429）幾次就放棄這一輪 |
| `deadlineHours` | `72` | 從開始算 3 天還沒完成就放棄這一輪 |
| `maxMemKB` | `2048` | 進度資料超過就放棄（實測峰值見下） |
| `maxLoadPerCore` | `2` | 每個核心的 1 分鐘平均負載超過就暫停（讀 `/proc/loadavg`；Windows 不檢查） |
| `timeoutMin` | `120` | 一次執行最久多久；超過時進度保留，10 分鐘後續跑 |

整輪通常花幾十分鐘（65 個 ASN × 平均 17.5 秒的停頓），慢是故意的。執行中如果有別的排程工作在排隊，會先讓出來，等一下再續跑。

### 5.3 暫停、續跑與放棄（資源不夠時的停止機制）

- 每一步之前檢查：期限、記憶體（主程式的記憶體壓力，集中在 `app::job_memory_short`）、CPU 負載、進度資料的大小、有沒有別的工作在等。
- 資源不夠或網路錯誤：**暫停**，進度留在記憶體裡（不寫 Flash），過一陣子由排程器續跑，已經抓過的不會重抓；重開機就丟掉，等下次排程從頭來。
- 超過期限、連續失敗太多次、進度資料太大、驗證沒通過：**放棄這一輪**，丟掉進度、繼續用目前的清單（公版或上次成功的），記錄原因。

### 5.4 換上之前的驗證

格式正確（每個群組都在）、`generatedAt` 比目前的新、台灣 IPv4 總量跟目前的差在 ±20% 以內、
每個 ISP 群組都有網段（目前就已經是空的除外，例如台灣之星）。不通過就保留目前的清單並記錄原因。
網段跟目前的完全一樣（只差日期）時什麼都不寫。

### 5.5 換上

規則立刻換上（`Access::set_data`）；經快照寫入器存成快照目錄的 `tw-ip.json.zst`（壓縮、內容沒變不寫，所以 Flash 大約每月寫一次）；
另外放一份到執行期目錄（記憶體）給指令列用，再執行 `KUROSHIO_ACCESS_HOOK apply`（OpenWrt：重新產生核心層的集合）。
啟動時快照目錄裡本機產生的資料比公版新（而且大小合理）就用它；程式升級帶來較新的公版時用公版。

### 5.6 實測

計數配置器量「比開始時多用了多少」的峰值（`crates/kuroshio-jobs/tests/twip_mem.rs`）：
2026-11-11 的真實資料（五個 RIR 檔共 44.7 MB + 65 個 RIPEstat 回應）峰值多用約 365 KB，不含禮貌停頓的處理時間約 1.5 秒（x86 除錯版）；
產生的清單跟同一份資料用指令列產生的完全一樣。

### 5.7 狀態

`/api/jobs` 的 `detail.tw-ip`、`/api/access` 的 `update`：

| 欄位 | 說明 |
|---|---|
| `state` | `idle` / `running` / `paused` / `aborted` / `done` / `skipped` |
| `reason` | 暫停或放棄的原因 |
| `progress`、`step` | 例如 `RIR 3/5`、`ASN 41/65`；`{ phase: "rir"\|"asn"\|"build", done, total }` |
| `startedAt`、`eta`、`resumeAt`、`lastEnd`、`lastSuccess` | Unix 毫秒 |
| `lastResult` | 上次結果的說明 |
| `listDate`、`source` | 目前清單的日期；`公版` 或 `本機產生` |
| `peakMemKB` | 工作自己估計的進度資料峰值 |
| `text` | 給介面顯示的一句話 |

`/api/access` 另外多 `dataOrigin`（`公版` / `本機產生`）。舊的 `access.updateUrl` 不再使用（記一行說明後略過）。

## 6. 管理 API 與指令

- `/api/status` 多一個 `access`：`mode`、`applyTo`、`active`、`dataOk`、`failOpen`、`warning`、`generatedAt`、`ranges`、`memoryBytes`、`dataBytes`、
  `denied: { total, byListener: { dot, doh, doq, doh3, site, community, plain } }`、`topDenied: [{ net: "a.b.c.0/24" | "x:y:z::/48", count }]`（前 10）
- `GET /api/access`：上面全部，加上 `groups: [{ id, name, note, asns, size: { v4, v6_48 }, cidrs: { v4, v6 }, enabled, checked }]`、
  `selected`（設定的 `groups`）、`allow`、`deny`、`log`、`autoUpdate`、`dataSource`、`dataOrigin`、`update`（第 5.7 節）、`total`、`topDenied`（前 50）
- `GET /api/access?ip=1.2.3.4`：`{ ip, allowed, reason, mode, applyTo }`
- rpcd 的 `api` 白名單加了 `/api/access`
- `kuroshio access check <IP> [--json]`、`kuroshio access groups`：照設定載入（不含好友 IP），不用啟動服務
- `kuroshio access nft --sets 檔案 --rules 檔案`：OpenWrt 核心層丟棄用（第 7 節）

拒絕的統計：每個服務一個計數器（`AtomicU32`），以及被拒絕最多的 /24（IPv6 /48），最多記 512 個網段，滿了先丟掉只出現過一次的。

## 7. OpenWrt：核心層丟棄（nftables）

程式裡的過濾還是要讓封包進到使用者空間；OpenWrt 另外用 fw4 的 include 在核心層就丟掉：

- `/usr/share/nftables.d/table-pre/30-kuroshio-access.nft`：集合 `kuroshio_allow4/6`（勾選的台灣網段 + `allow` + 私有網段 + 本機網段）、`kuroshio_deny4/6`
- `/usr/share/nftables.d/chain-pre/input_<WAN 區域>/30-kuroshio-access.nft`：WAN 區域輸入鏈開頭的規則，只針對 DoT / DoQ / DoH / DoH3 的埠
  （DoH 從 WAN 443 轉進來時，輸入鏈看到的是轉換後的本機埠）
  - `deny`：所有加密監聽埠都丟棄
  - 台灣過濾：只在「這個埠上的每個服務都有套用、而且沒有社群共享」的埠丟棄不在允許集合裡的來源。
    社群共享開著時，好友的 IP 會變，核心層不知道，這些埠交給程式自己判斷
  - `open` 模式只剩 `deny`；資料讀不到時也只剩 `deny`；什麼都不用時兩個檔案都移除
- 不碰區網（LAN 區域的輸入鏈）與 LuCI 的 22 / 80 / 443（除非 DoH 自己就聽 443）
- `access.sh apply`：由 `kuroshio access nft` 產生，內容沒變就不寫、不重新載入防火牆；`fw4 check` 失敗就移除，絕不讓防火牆載入失敗。
  init 啟用時套用、停用 / 停止時移除，設定變更（procd reload）時重新產生；每月的清單換上後由 `KUROSHIO_ACCESS_HOOK` 呼叫

## 8. Windows

只有程式內的過濾（第 3 節）。沒有做 Windows 防火牆規則：Windows 防火牆的「封鎖」規則優先於「允許」規則，
「只允許台灣」要寫成數千條遠端位址範圍的允許規則並移除原本的開放規則，跟使用者自己的規則容易衝突，也沒有辦法在 CI 驗證，所以不做。
需要的話可以在前面放 Cloudflare 之類的服務。

## 9. 限制

- **擋不了流量型 DDoS**：塞滿對外頻寬的攻擊，封包到路由器之前頻寬就滿了；應用層、甚至路由器的核心層過濾都救不了，要靠 ISP 或 Cloudflare 之類的服務。
  這裡能減少的是連線數、握手、查詢造成的 CPU 與記憶體負擔，以及掃描與濫用。
- 人在國外、漫遊（行動網路漫遊時常從國外的閘道出去）、用 VPN 或國外雲端主機的台灣使用者會被擋：改成 `open` 或加進 `allow`。
- 台灣網段是 RIR 的登記國別，不是地理位置；少數登記在台灣的網段實際在國外使用，反之亦然。
- 行動網路與業者合併後的網段會變動，所以資料每月在裝置上重新產生（`autoUpdate`，預設開）。
- 好友的 IP 每 10 分鐘更新一次，好友剛換 IP 時可能有幾分鐘連不上（只影響有套用 `community` 的情況）。
