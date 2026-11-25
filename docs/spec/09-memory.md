# 09 · 記憶體控制：記憶體是拿來用的，別人要用時馬上讓

> 維護者的需求（摘要）：「記憶體是拿來用的。只要系統記憶體沒有用到大約 95%，就可以大膽地用——
> 別的程式需要記憶體時再動態卸載，而不是限制自己只用固定的量。這樣最保護 Flash，也不會讓系統當機。
> 95% 只是例子：找出系統穩定的值，也可以是絕對值（例如系統剩不到 16 MB 就卸載），讓使用者自訂。
> 拿掉等級的概念。真正好的設計是使用者感覺不到的動態控制。」
>
> 後續修正：「這是關鍵基礎設施：DNS 不回答等於斷網，跟裝置當機沒有兩樣。」——不讓核心優先停掉本程式，
> 本程式自己要先讓出記憶體；**最低限度是純 DNS 轉送**（路由器本來就有的功能），不能比它更低。

實作：`crates/kuroshio/src/memgov.rs`（保留量、狀態、階梯與六個步驟）、`app.rs`（記憶體監看 `spawn_monitor`、啟動順序）、
`filtering.rs`（清單停用 / 恢復 / 全部暫停、本機副本）、`kuroshio-cdn` 的 `Db::evict_cold` / `Cdn::ensure_loaded`、
`cache.rs` 的 `Cache::shed_to`、`persist.rs`（寫入節奏與儲存保留量，見 05 第 5 節）。

## 1. 沒有硬體等級

以前依實體記憶體分 tiny / small / standard / large，每級一份固定的大小。現在全部拿掉（`profiles.json` 已刪除）：

- **記憶體結構沒有依機器而定的上限**：DNS 快取、CDN 網域資料庫在記憶體裡的部分、過濾清單、統計排行、到站紀錄、
  好友資料都是「有空間就長大、別人要用時讓出來」。設定裡的上限（`resolver.cacheMax` 100,000、`cdn.maxEntries` 200,000、
  `filter.maxDomains` 1,000 萬……）只是**防濫用的安全上限**，所有機器都一樣；使用者自己填的值照樣是硬上限。
- **跟 CPU 有關的值依核心數換算**（寫 `"auto"` 或沒寫時，見 05 第 7 節）：同時問幾個上游、測速 / 驗證 / 評測 / 掃描的同時數、
  加密連線數、每次查詢都要跑的過濾規則數。
- **背景重工作**（網段掃描等）不再依等級停用：記憶體接近保留量時延後（`Pressure::Low`）。
- 舊設定 `system.profile`、`system.tier`、`system.memoryBudgetMB`（UCI `profile`、`tier`、`memory_budget_mb`）照樣接受、
  不使用，啟動時記一筆說明，不會啟動失敗。

## 2. 系統保留量

只看**整台機器還剩多少**，不看自己用了多少（沒有「預算」）：

- 量測：Linux `/proc/meminfo` 的 `MemAvailable`，Windows `GlobalMemoryStatusEx` 的 `ullAvailPhys`；
  Linux 有 `/proc/pressure/memory`（PSI）時一起讀。自己的 RSS（Windows 是工作集）不拿來決定狀態，
  只用在「退讓於事無補」的判斷（第 12 節，3.5.0）。
- **保留量**（[`Reserve`]）：可用記憶體低於它就讓出記憶體；高於「保留量 + 遲滯」才恢復、才讓記憶體結構長大。
  遲滯 = 保留量的一半，至少 8 MB。
- 使用者設定：`system.memoryReserveMB`（絕對值）與 / 或 `system.memoryReservePercent`（實體記憶體的百分比，最多 90）；
  兩個都填取大的；都 0 = 自動。

### 2.1 自動保留量與理由

| 平台 | 自動 | 128 MB 路由器 | 512 MB | 4 GB | 16 GB |
|---|---|---|---|---|---|
| Linux | max(16 MB, 實體記憶體 5%（最多 1 GB）, `vm.min_free_kbytes` × 3) | 16 MB | 25.6 MB（min_free_kbytes 小時） | 200 MB | 800 MB |
| Windows | max(128 MB, 實體記憶體 5%)（3.5.0） | — | — | 204.8 MB | 819.2 MB |

一律不超過實體記憶體的一半。

Windows 3.5.0 前後對照（以前是 max(512 MB, min(10%, 4 GB))）：

| 實體記憶體 | 2 GB | 4 GB | 8 GB | 16 GB | 32 GB | 64 GB |
|---|---|---|---|---|---|---|
| 以前 | 512 MB | 512 MB | 819.2 MB | 1,638.4 MB | 3,276.8 MB | 4,096 MB |
| 3.5.0 | 128 MB（下限） | 204.8 MB | 409.6 MB | 819.2 MB | 1,638.4 MB | 3,276.8 MB |

- **Linux 的 `MemAvailable`**（核心 3.14 起，`si_mem_available()`）＝ 空閒頁 − 核心保留（各區的 low watermark 合計）
  ＋ 可回收的檔案快取與 slab（各扣掉一半或 low watermark 中較小者）。它估的是「不 swap 還能給新程式多少」。
  但它把**可以回收的檔案快取**都算進去，裡面有正在執行的程式本身：OpenWrt 的執行檔、函式庫在 squashfs 上，
  是以檔案快取的形式在記憶體裡；全部回收掉的話，程式每跑一步就要重讀 Flash（thrashing），系統看起來還有記憶體、其實已經卡死。
  所以要再留一段給這些「工作集」：128 MB 路由器上 16 MB（約 12%）夠 dnsmasq、hostapd、netifd、uhttpd、odhcpd 這類常駐程式。
- **`vm.min_free_kbytes`**：核心的 min 水位（low ＝ min × 1.25、high ＝ min × 1.5）。可用記憶體低於 low 時 kswapd 開始回收，
  低於 min 時配置記憶體的程式自己做直接回收（直接卡住）。保留量 ≥ min × 3，讓本程式在 kswapd 忙起來之前就先讓出。
- **大機器 5%（最多 1 GB）**：x86 / 樹莓派上其他服務多、突發也大；1 GB 封頂，64 GB 的機器不必留 3 GB 給一個 DNS 程式讓。
  這就是維護者說的「大約 95%」，換成依實際機器穩定的值。
- **Windows 的 5%**：`ullAvailPhys` 包含待命清單（standby，可以回收的快取），Windows 很積極修剪工作集、把記憶體換到分頁檔；
  系統預設在可用約 32 MB / 4 GB（最多 64 MB）時才發「記憶體不足」通知（`CreateMemoryResourceNotification` 的 low 門檻），
  那時桌面早就卡了，所以還是比那個門檻高得多。3.5.0 以前是 max(512 MB, min(10%, 4 GB))：Windows 實測一台大記憶體的桌機
  （本地 AI 吃掉幾十 GB），可用只剩 3,896 MB，比 4 GB 的保留量還低，一開機就「吃緊」；掉到 2 GB 以下就「不足」、停用清單、
  拒絕新的加密連線——但黑潮自己全部讓出也只有一兩百 MB，對幾十 GB 的缺口於事無補，只讓 DNS 變差。現在 5%（64 GB 約 3.2 GB），
  另外有 128 MB 的下限，避免很小的 VM（2 GB 以下）上幾乎沒有保留；下限也不超過實體記憶體一半。
  缺口還是比黑潮自己大得多時，由第 12 節的「於事無補」處理。

## 3. 狀態與反應速度

| 狀態 | 進入 | 離開（放鬆一級） |
|---|---|---|
| 寬裕 | — | — |
| 吃緊 | 可用 < 保留量，或 PSI some avg10 ≥ 30% / full avg10 ≥ 5% | 可用 ≥ 保留量 + 遲滯，而且 PSI 平靜（some < 10%、full < 1%） |
| 不足 | 可用 < 保留量的一半，或 PSI full avg10 ≥ 20% | 可用 ≥ 保留量（回到吃緊） |

- 變嚴重：立刻。放鬆：一次一級，條件要**連續**成立 180 秒，而且目前狀態已經停留 180 秒以上。
- **量測頻率**（[`poll_interval`]）：低於保留量每 2 秒、保留量兩倍以內或 PSI 看得到等待每 3 秒、遠的時候 30 秒。
  讀 `/proc/meminfo` 與 `/proc/pressure/memory` 都是幾微秒的事。
- **PSI 是提早的訊號**：別的程式已經在等記憶體（some），就算 `MemAvailable` 還沒掉到保留量也先讓。
- 整個程式的壓力訊號（`app::pressure()`）也從這裡來：
  - **偏低**（可用 < 保留量 + 遲滯，或 PSI 有等待）：背景工作延後、記憶體結構停止長大、新的加密連線最多 32 條。
  - **不足**（可用 < 保留量的一半，或 PSI 嚴重）：快照立刻寫出並放掉待寫內容、暫不接受**新的加密**連線。
    區網的明文 DNS 一律照常回答。
  - **於事無補**（第 12 節，3.5.0）時「不足」降成「偏低」給其他模組；快照寫入器用它自己的量測（`app::mem_now`），照樣立刻寫出。
- 關掉記憶體控制（`system.memoryGovernor: false`）時，壓力訊號照樣依保留量運作（`system.memoryWatchdog`），
  快取與 CDN 用舊的「縮一半、刪三成」做法。

## 4. 釋出階梯（底線：純轉送）

吃緊 / 不足時依「重建成本由低到高」釋出。**離保留量不遠**（可用 ≥ 保留量的 3/4）時一輪一步，下一輪（2–5 秒後）量到效果再決定；
**離得遠**（可用 < 保留量的 3/4，或不足）時同一輪連做好幾步，直到估計釋出的量補足差額或沒有可以做的。
某一步做不了（例如沒有冷資料、下載失敗）就先跳過做下一步，那一步至少 1 分鐘後再試。

| 步驟 | 什麼時候 | 做什麼 | 恢復 |
|---|---|---|---|
| 1. 診斷緩衝 | 吃緊 | 設定頁日誌 500 → 50 行；熱門網域 / 被擋網域 / 用戶端排行只留前 200 名；查詢紀錄關閉並釋放（3.5.0） | 上限恢復，自然長回來；查詢紀錄不自動再開 |
| 2. DNS 快取 | 吃緊 | 縮到目前上限的 1/4（至少 256 筆），留下熱門的 | 上限恢復 |
| 3. CDN 冷資料 | 吃緊 | 先寫進磁碟，再**從最冷的開始**把網域移出記憶體（磁碟保留，查到時讀回），移到補足缺口就停：沒有學習資料的先、同一組裡最久沒出現的先，2 分鐘內出現的不動。可以一輪一輪做（3.5.1） | 依可用空間一次讀回幾片；只問過一次、沒有學習資料的不讀回（3.5.1） |
| 4. 過濾清單 | 不足，而且可用 < 保留量的一半 | 依優先順序（廣告 → 遙測 → 惡意、命中少的先、大的先）停用清單：離保留量遠時**一次**取到估計合計 ≥ 還缺的 × 1.3（至少 1 份）、**只重建一次**（3.5.0）；保護清單不在這一步 | 從最後停用的開始，取到合計 × 1.3 ≤ 可用空間（至少 1 份），重建一次；用本機副本或重新下載 |
| 5. **只轉送** | 同上 | 暫停 CDN 調整（答案照上游原樣）、整個 CDN 資料庫寫進磁碟移出記憶體、快取只留 64 筆（通訊類網域優先留下，3.5.0） | 恢復 CDN 調整與快取上限 |
| 6. 保護清單 | 已經只轉送，而且可用 < 保留量的 1/4（一份清單都還沒有時不做，3.4.2） | 暫停全部清單（含惡意 / 反詐騙），只剩自訂規則 | 重新載入全部清單 |

- **底線**：監聽 socket、轉送路徑、上游連線、設定**永遠不釋出**；明文 DNS 一定回答區網的查詢。
  第 5 步之後的狀態就是路由器內建的功能（純轉送），不會更低。加密上游照常使用（只用到既有的連線與小緩衝）。
- 第 6 步只在「不讓出來連轉送都會失敗」時做：保留量的 1/4 已經低於核心開始直接回收的範圍。
  狀態頁、LuCI 狀態頁用紅色提示「連保護清單都暫停了」；`/api/status.memory.protectedSuspended` = true。
- 細節（沿用前一版）：
  - 快取的熱門分數 = 上次使用時間 + 每多一倍的查詢次數加 5 分鐘。縮的時候在一次掃描裡選出要留的，鎖住的時間是一次 O(n)。
  - CDN 冷資料：先在「登記鎖」底下把變動登記並寫出，只移出已經在磁碟上、之後沒變動的分片裡的網域；記憶體裡只留 32 位元雜湊。
    查到時從分片逐筆解析、只撈那一筆；判定跟移出前完全一樣。分片之後要重寫時從磁碟接回去，磁碟上不會少。
  - **大量冷門網域湧入時先讓 CDN、不停用清單**（3.5.1 G1）：3.5.0 的第 3 步只移出「一小時沒出現」的，而且做過一次就要等恢復才能再做。
    壓測、掃描、大量新註冊網域湧入時，它們全部都是「最近才出現」：第一個小時沒有冷資料可以移出，之後湧進來的也沒辦法再讓，
    記憶體一直往下掉，下一步就是停用過濾清單——拿保護去換一堆不會再被問的網域（3.5.0 D3 壓測：每秒 125 筆、網域資料漲到 6 萬多筆）。現在：
    - **從最冷的開始、依缺口決定移多少**（`Db::evict_coldest`）：不再用固定的「一小時沒出現」。
      這一次要移的量 = 缺口 × 1.3（離保留量遠時是 `Governor::tick` 算的還缺多少；不遠時是回到保留量 + 遲滯還差多少），至少 512 KB（`CDN_MIN_UNIT`）。
      順序：**沒有學習資料的先**（`db::has_learning`：沒有驗證、ECS、跨 CDN 結果、改寫方式），**有學習資料的最後**；同一組裡最久沒出現的先。
      最近 2 分鐘出現的不動（`CDN_PROTECT_MS`），手動策略的、有待寫內容的分片照舊不動。移出只是離開記憶體，磁碟上照樣保留、查到時讀回，學習資料不會少。
      實作是兩次掃描、不排序：第一次依（組，年齡格）累計估計用量，年齡格由新到舊是 2、5、10、20、30 分鐘，1、2、4、8 小時，1、2、7、14、30、90 天（`COLD_AGE_EDGES_MS`），
      找出要移到哪一格；第二次只收那些名稱。小機器上不為了排序另外配置一份 20 萬筆的陣列，鎖住的時間是兩次 O(n)。
    - **可以一輪一輪做**：讓出後吃緊時等 120 秒、離保留量遠時等 30 秒才能再做（每次都會先把變動寫進 Flash，不能每幾秒寫一次）。
      上一次讓出 64 KB 以上時，等待的這段時間後面的步驟（停用過濾清單、只轉送）**不做**（`Step::holds_later`）；
      CDN 真的沒東西可以讓了（讓出不到 64 KB、或什麼都沒有），才輪到過濾清單。
    - 正在排隊或正在做驗證、ECS、跨 CDN 的網域不移出；排隊期間被移出的，工作開始前先讀回（結果才寫得回去，不白做一次）。
    - **恢復時依可用空間一次讀回幾片**（每片的估計 = 移出量 ÷ 有移出的分片數，可用空間 ≥ 一片 × 1.3 就讀，讀到可用空間 ÷ 1.3 為止），剩下的下一輪；
      以前要等空間夠「全部讀回」，大量冷門網域移出後可能一直等不到，後面的快取、診斷緩衝也跟著不恢復。
    - **只問過一次、沒有學習資料的不讀回**（`db::forgettable`）：直接從移出名單拿掉，那一片下次寫出時就不再帶它。
      沒有結果可以重用，忘掉不損失任何東西；之後再出現就當新網域（照驗證節流的規則，問第二次才驗證）。不然記憶體一恢復又被同一批一次性網域塞滿，來回讓出又恢復。
    - 同一步的讓出紀錄（`/api/status.memory.shed`）最多 4 筆，再多就把最舊的合成一筆（總量不變）。
  - 過濾清單：重建時新舊兩份並存，新的一份（停用這幾份之後的大小）放不進可用記憶體的一半就不做。
    **一次停用多份、只重建一次**（3.5.0 C3）：以前缺口大時一份一份停用、每份重建一次，N 份就有 N 次「新舊兩份並存」的尖峰，
    而且都在最缺的時候。現在 `Governor::tick` 把「還缺多少」（缺口 − 同一輪前面步驟估計已經釋出的）傳給這一步
    （`Step::shed_for`），`FilterService::unload_many` 依停用順序取到估計合計 ≥ 還缺的 × 1.3、一次登記、重建一次；失敗時這次登記的全部撤回。
    尖峰估算：舊的清單層 L、停用的合計 S，一次一份的第一次重建尖峰約 L + (L − 第一份)，一次多份約 L + (L − S)，
    只會更低，次數從 N 次變 1 次。恢復也一樣（`restore_many`）：從最後停用的開始、取到合計 × 1.3 ≤ 可用空間，尖峰約 L + (L + 恢復的合計)，
    跟一份一份恢復到同一個量時最後那一次的尖峰差不多，但只重建一次；恢復後 10 分鐘內又吃緊，下次恢復的間隔照樣加倍。
    「系統真的不足」（可用 < 保留量的一半）時缺口一定大於可用記憶體，實際上幾乎都是一次停用全部非保護清單——跟以前同一輪連續停用的結果一樣，只是重建 1 次。保護清單（`filter.lists[].protect`；惡意類預設是）
    在第 4 步絕不停用——「從來沒命中」不代表沒用，詐騙網域大多是第一次出現。

## 5. 長大之前先看空間

寬裕而且可用 ≥ 保留量 + 遲滯時，記憶體結構才長大（[`growth_allowed`]）；一進入遲滯範圍就停止長大（還不釋出）：

| 結構 | 怎麼長大 / 停止 |
|---|---|
| DNS 快取 | 上限 = `resolver.cacheMax`（安全上限或使用者值）；停止長大時上限停在當時的筆數（至少 256），超過就清掃 |
| 過濾清單 | 載入前估計：清單層額度 = 目前大小 + （可用 − 保留量 − 遲滯）÷ 1.3，新的一份也不超過可用的一半；放不下的依停用順序先不載入（原因 `budget`） |
| CDN 網域資料庫 | 冷資料讀回前檢查空間 × 1.3（恢復第 3 步）；查詢時讀回單筆不檢查 |
| 到站紀錄（公開頁） | 安全上限 5 萬個 IP；停止長大時 5 千個就換代 |
| 好友資料（社群） | 解壓後不超過 `community.maxBundleMB`（安全上限 32 MB），也不超過「保留量以上空間」的 1/4 |
| 加密連線 | 偏低時新連線最多 32 條；不足時暫不接受新的加密連線 |
| 過濾清單本機副本（壓縮暫存） | 只在可以長大時才邊下載邊壓縮存成副本；還不能長大、但不是「不足」時，壓縮後留在記憶體（合計 ≤ 8 MiB，3.4.2），恢復途中的重建讀它、不重下載；記憶體能長大時與每恢復一份清單之後，存得下的登記成本機副本、從記憶體拿掉（只在本機寫出）；還沒寫到磁碟前，讀副本讀的是待寫的內容（`Persister::pending_bytes`） |

恢復第 3、4、6 步也一樣要求「可用 − 保留量 − 遲滯 ≥ 項目大小 × 1.3」，不夠就等（狀態裡寫明在等什麼）；
恢復失敗用指數退避（5 分鐘起，每次加倍，最多 6 小時）；恢復後 10 分鐘內又吃緊，下次恢復的間隔加倍。

## 6. 不讓核心挑 DNS：OOM 分數與快速重啟

- Linux 上把自己的 `/proc/self/oom_score_adj` 設成 **-500**（`system.oomScoreAdj`，UCI `oom_score_adj`，範圍 -1000..1000）。
  核心挑 OOM 犧牲者的分數 ≈ 佔用的記憶體（實體記憶體的千分比）+ `oom_score_adj`：
  -500 表示本程式要多佔「實體記憶體的一半」才會跟一般程式同分，平常核心一定先挑別的程式；
  但本程式真的漏記憶體、吃掉超過一半時還是會被挑中——-1000（完全豁免）會讓整台機器卡死，比 DNS 重啟更糟。
  調成負值需要 root 或 CAP_SYS_RESOURCE：OpenWrt 上 procd 以 root 執行，可以；失敗只記一筆警告、照常執行。
  Windows 沒有對應的機制（記憶體不足時 Windows 換頁而不是殺程式），不需要。
- 代價：本程式被保護，就**必須自己先讓出記憶體**——上面的快速量測、PSI 提早訊號、離得遠時一輪連做好幾步，都是為了讓核心永遠不必挑犧牲者。
- **還是當掉時**：
  - OpenWrt：procd `respawn 3600 1 0`——1 秒後重啟、永不放棄。
  - Windows 服務：每次失敗 1 秒後重啟（次數超過動作數時重複最後一個動作），程式以錯誤結束也算失敗。
  - **啟動時先回答 DNS**：設定、存取控制、自訂規則（小）→ 明文 DNS 監聽 → 之後才在背景載入 CDN 網域資料庫（背景執行緒）
    與過濾清單（有本機副本時先用副本，見 05 第 5.6 節）。清單還在下載就已經在轉送（整合測試 `plain_dns_answers_before_lists_load`）。
- **重新啟動期間的 DNS 備援（OpenWrt）**：`/usr/libexec/kuroshio/guard.sh`（procd 的第二個實例，`main.restart_fallback`，預設開）
  每秒看一次：本程式不在、或約 3 秒沒有回答（每 10 秒用 `_dns.resolver.arpa` 自問一次，這個名稱由本程式自己回答、不經上游）
  → `takeover.sh revert`，dnsmasq 回到安裝前的設定、直接用 WAN 的上游轉送；本程式回來而且回答了 → `takeover.sh apply` 重新接管。
  - 取捨：備援期間沒有過濾、沒有 CDN 調整（就是路由器原本的 DNS）；切換時 dnsmasq 重啟一次（約 1 秒）。
    procd 1 秒內就重啟本程式，所以平常的當機根本到不了 3 秒；備援是給「反覆當掉、起不來」的情況，讓區網不會完全沒有 DNS。
  - 只在 `dnsmasq-upstream`（預設）、`redirect`、`hijack` 模式；`exchange` 模式本程式自己佔 53 埠，備援的 dnsmasq 會跟它搶埠，所以不做。
  - 關掉：`uci set kuroshio.main.restart_fallback=0`。

## 7. 誠實說明的限制

- **於事無補時不讓**（第 12 節）：缺口是別的程式造成時，黑潮不縮快取、不停用清單；系統真的用光時由作業系統處理
  （Windows 換頁、Linux 核心回收與 OOM，本程式是 -500）。使用者自己把保留量設得很大（例如 128 MB 的機器設 64 MB）時，
  小機器上也可能成立。

- **比量測更快的突增**：別的程式在 2 秒內一口氣吃掉超過保留量的記憶體時，本程式來不及讓；
  這時靠核心的回收（kswapd、直接回收），真的用光時 OOM killer 會先挑別的程式（本程式是 -500），
  被挑中的程式由它自己的 procd / 服務設定重啟。保留量越大，緩衝越多。
- **配置器不一定把記憶體還給系統**：glibc 釋出後呼叫 `malloc_trim`；musl 釋放大塊時直接還，小塊可能留在行程裡。
  RSS 沒降下來時系統可用記憶體也不會回升，狀態會停在吃緊或不足——已釋出的項目維持釋出，不會更糟，也不會自己長回來。
- **停用清單期間保護變少**：第 4 步從廣告類開始、取到還缺的 × 1.3 為止（不多停）；第 6 步只在連轉送都快保不住時。狀態頁都有明顯提示。
- **CDN 冷資料第一次被查到要讀一次磁碟**（一個分片解壓、逐筆解析）。32 位元雜湊碰撞時最多多讀一次磁碟，不會讓判定出錯。
- **估計值偏保守**（快取、CDN 的估計比實際少 30–40%，見第 8 節），用在恢復的空間判斷不會高估；
  但「離得遠時一輪做到補足差額」會因此多做一兩步——寧可多讓。

## 8. 實測

`cargo test -p kuroshio --test memgov_bench -- --ignored --nocapture`（前一版量的，各步驟的做法沒變；x86_64 除錯組建；預設啟用的 7 份清單、種子 CDN 資料庫 3,961 筆、
快取 15,000 筆、排行 2,000 個網域）。「heap 實測」是配置器實際少掉的位元組。

| 步驟 | heap 實測 | 估計 | 內容 |
|---|---|---|---|
| 1. 診斷緩衝 | 123 KB | 113 KB | 日誌 50 行、排行前 200 名 |
| 2. DNS 快取 | 5,003 KB | 3,508 KB | 15,000 → 3,750 筆 |
| 3. CDN 冷資料 | 3,290 KB | 2,031 KB | 3,564 筆移出（磁碟保留） |
| 4. 非保護清單（6 份） | 1,060 KB | 1,120 KB | 116,359 條規則 |

單元 / 整合測試釘住的行為（全部用注入的量測值，不碰主機真正的記憶體）：

- 保留量：自動（Linux / Windows 各種大小，Windows 4／8／16／32／64 GB、128 MB 下限、下限也不超過一半）、百分比、絕對值、兩個都填取大的、百分比上限、不超過一半（`reserve_derivation`）。
- 於事無補（3.5.0，第 12 節）：門檻與讀不到用量時不成立（`futile_enter_and_hold_thresholds`）、64 GB 的 Windows 情境（`futile_on_big_windows_machine`）、
  遲滯與 60 秒（`futile_gate_hysteresis`）、128 MB／512 MB 的路由器從可用 0 到保留量都不成立（`futile_never_on_small_routers`）、
  不讓出任何東西但停止長大、壓力訊號是偏低、快照照樣寫出（`futile_sheds_nothing_but_stops_growth_and_still_flushes`）、
  之前讓出的照舊等寬裕才恢復（`futile_keeps_earlier_sheds_until_comfortable`）、真的清單不停用不重建（`tests/memgov_lists.rs` 的 `futile_deficit_keeps_lists`）、
  模擬 20 MB 時 Windows 成立、D3 不成立（`simulation_on_windows_is_futile_but_not_on_d3`）。
- 量測間隔：低於保留量 2 秒、兩倍以內 3 秒、遠 30 秒、PSI 有等待 3 秒（`poll_interval_follows_distance_and_psi`）。
- 遲滯：吃緊 → 寬裕要回到保留量 + 遲滯而且持續 180 秒；不足一次只放鬆一級（`hysteresis_and_dwell`）。
- 狀態（`/api/status` 的 `memory.state`）是放鬆前要穩定的那一個；當下的量測另外放在 `memory.pressure`（`normal`／`low`／`critical`，3.4.3）。日誌的「記憶體回到保留量以上」看的是當下的量測，`state` 會晚幾分鐘才變回寬裕，這是刻意的（避免來回切換）。
- 可用只剩保留量的 30%：同一輪做完整個階梯到「只轉送」，下一輪沒有可以做的；差額小時補足就停（`far_below_reserve_escalates_several_steps_in_one_tick`）。
- 接近保留量（保留 + 遲滯以內）：不釋出、停止長大；回到寬裕恢復長大（`growth_stops_near_reserve_and_resumes_when_comfortable`）。
- 恢復依相反順序、等空間 × 1.3、失敗指數退避（`near_reserve_one_step_per_tick_then_restore_in_reverse`、`restore_waits_for_headroom_and_backs_off`、`restore_failure_backs_off`）。
- 一次停用多份、只重建一次（3.5.0 C3）：`tick` 傳給每一步的「還缺多少」（`tick_passes_shortfall_and_room_to_steps`）；
  缺口大時一輪就停用全部非保護清單、重建 1 次（`tests/memgov_lists.rs` 的 `far_deficit_unloads_several_lists_with_one_rebuild`）；
  沒說缺多少時一次一份（`near_deficit_still_unloads_one`）；保護清單不在裡面、停用後放不進可用的一半就不做（`unload_many_never_includes_protected`）；
  失敗全部撤回（`unload_many_rolls_back_on_failure`）；恢復取到空間為止、重建一次（`restore_many_fits_room_and_rebuilds_once`）；
  恢復後又不足時的退避（`restore_then_pressure_again_backs_off`）；挑選的上下限（`filtering.rs` 的 `pick_shed_and_restore_bounds`）。
- 使用者明確設定的 `cacheMax` 仍是上限；快取停止長大、1/4、最低限度三者合併（`explicit_user_cache_max_is_still_a_cap`、`cache_cap_combines_growth_shed_and_floor`）。
- `oom_score_adj` 寫進注入的路徑、限制範圍（`oom_score_adj_written_to_injected_path`）。
- **最深的狀態仍轉送**：真的啟動程式、載入兩份清單後注入「可用 4 MB、保留 64 MB」，跑到只轉送 + 保護清單暫停，
  UDP / TCP 查詢照樣轉送到上游、回答（連原本被擋的名稱也照上游回答）（`tests/filtering.rs` 的 `deepest_shed_state_still_forwards_plain_dns`）。
- 舊的 `tier` / `profile` / `memoryBudgetMB` 接受、不影響任何值（`kuroshio-config` 的 `legacy_tier_keys_are_accepted_and_ignored`、UCI 的 `old_tier_keys_ignored_and_user_wins`）。

## 9. 還沒驗證

- 真的 128 MB 路由器（MIPS / ARM、musl）上：平常的可用記憶體與自動保留量（16 MB）的關係、PSI 在 OpenWrt 核心上是否開啟
  （`CONFIG_PSI`；沒開時只看 `MemAvailable`）、各步驟實際讓可用記憶體回升多少、`oom_score_adj` 寫入是否成功。
- procd 的 `respawn 3600 1 0` 與 `guard.sh` 的切換（CI 的 OpenWrt 容器裡沒有 procd，只驗證了腳本存在與 shellcheck）。
- Windows：`ullAvailPhys` 在待命清單很大時的行為、服務失敗動作（程式碼已編過 Windows 目標的型別檢查，沒有在 Windows 上跑過）。

## 10. 設定與 API

| 設定 | UCI | 預設 | 說明 |
|---|---|---|---|
| `system.memoryGovernor` | `system.memory_governor` | true | 記憶體控制開關 |
| `system.memoryReserveMB` | `system.memory_reserve_mb` | 0 | 保留量（MB）；0 = 自動 |
| `system.memoryReservePercent` | `system.memory_reserve_percent` | 0 | 保留量（實體記憶體 %，最多 90）；跟 MB 都填取大的 |
| `system.oomScoreAdj` | `system.oom_score_adj` | -500 | 自己的 OOM 分數調整（只有 Linux） |
| `system.memoryWatchdog` | `system.memory_watchdog` | true | 關掉記憶體控制時仍依保留量發壓力訊號 |
| `filter.lists[].protect` | `filter_list.protect` | 惡意類 true | 保護清單：第 4 步不停用 |
| — | `main.restart_fallback` | 1 | OpenWrt：重新啟動期間的 DNS 備援 |
| `system.profile` / `tier` / `memoryBudgetMB` | `profile` / `tier` / `memory_budget_mb` | — | 舊欄位：接受、不使用 |

`/api/status.memory`（`/api/status.system.memory` 是同一份）：

| 欄位 | 說明 |
|---|---|
| `enabled` | 有沒有開記憶體控制（沒開時只有量測與保留量） |
| `state` / `stateLabel` / `since` | `comfortable` / `tight` / `critical`（寬裕 / 吃緊 / 不足），進入時間 |
| `totalKB`、`availKB`、`rssKB` | 上次量到的實體記憶體、系統可用記憶體、本程式 RSS |
| `reserveKB`、`reserveAuto`、`reserveHow` | 保留量、是不是自動、怎麼算的（例如「自動：max(16 MB, min(實體記憶體 5%, 1 GB), min_free_kbytes 1024 KB × 3)」） |
| `marginKB`、`headroomKB` | 遲滯、保留量以上還有多少 |
| `psi` | `{ someAvg10, fullAvg10 }`（沒有 PSI 時 null） |
| `pollSec` | 目前的量測間隔 |
| `growth` | 記憶體結構現在可不可以長大 |
| `floor`、`protectedSuspended` | 到了只轉送、保護清單也暫停了（狀態頁紅色提示） |
| `futile`、`deficitBytes`、`ownBytes` | 退讓於事無補（3.5.0，第 12 節）中；缺口（保留量 − 可用，沒有缺是 0）、本程式的用量（RSS／工作集）；量不到是 null |
| `sizes` | 動態大小：`cacheEntries`、`cacheMax`、`cacheConfiguredMax`、`cdnInRam`、`cdnOnDiskOnly`、`filterListsBytes`、`filterListRules`、`filterListsUnloaded` |
| `shed[]` | 釋出中的項目：`step`（`diagnostics` / `cache` / `cdn` / `filter` / `floor` / `protected`）、`label`、`detail`、`freedBytes`（估計）、`availDeltaKB`（下一輪量到的可用記憶體差）、`at` |
| `freedBytes` / `freedTotalBytes` | 目前釋出中合計 / 啟動以來合計 |
| `lastChange`、`waiting`、`nextRestoreAt`、`events[]` | 最近一次狀態變化、在等什麼、下次可以恢復的時間、最近 20 筆事件 |

| `simulated` | 測試開關（3.5.0，第 11 節）：`{ availMB, until, remainingSec }`，沒開是 null |

`/api/status.filter`：`unloaded[]`（`name`、`rules`、`bytes`、`reason`：`memory` / `budget`、`at`）、`notice`、`suspended`（全部暫停中）、
`sources[].protect`、`sources[].hits`。

## 11. 測試：模擬記憶體不足（3.5.0）

讓測試者在記憶體很多的機器（512 MB 的 D3、Windows）上觸發「吃緊／不足」的整套流程（停用清單、只轉送、保護清單暫停與恢復），
不必真的把記憶體吃掉。**正式使用不能誤開**，所以有兩道保險：

1. 設定 `system.testHooks: true`（預設 false；UCI 是 `config system 'system'` 的 `option test_hooks '1'`）。**不放進** LuCI、Windows 設定頁、
   UCI 範例設定，只寫在這裡。沒開時 API 回 HTTP 403 與說明；重新載入設定時關掉了，進行中的模擬一起取消。
2. 每次都有時間上限：`minutes` 1～30（預設 5），到期自動恢復；模擬只放在記憶體裡，重新啟動後不保留。

用法：

```
kuroshio notify simulate-memory --avail-mb 20 --minutes 5     # 或 POST /api/memory/simulate?availMB=20&minutes=5
kuroshio notify simulate-memory --off                        # 或 POST /api/memory/simulate?off=1
```

- 生效期間，`memgov::Reading::now()` 讀到的系統可用記憶體 = min(真實值, N MB)：記憶體控制、整個程式的壓力訊號（`app::pressure()`）、
  每日評測的空間（`benchjob.rs`）、清單載入前的預算都看到同一個值。**只會讓讀數變小**，不能模擬成比真實寬裕；量不到可用記憶體的平台直接用 N。
  `Reading::now()` 只在背景的監看與工作裡呼叫，不在查詢路徑上；模擬值是兩個 `AtomicU32`（MB、到期的相對秒數）。
- 不影響系統層的東西（核心的 OOM、評測子程序的 OOM 設定），只影響黑潮自己的判斷。真正的記憶體是夠的，所以所有讓出的動作都安全；
  到期後由既有的流程自己恢復（剛好也測到恢復路徑：放鬆要穩定 180 秒、恢復要空間 × 1.3）。
- 看得出來：開著 `testHooks` 時啟動與 `kuroshio check-config` 各提醒一行；生效期間每分鐘一行 WARN「測試模式：模擬可用記憶體 N MB，還有 X 分鐘」，
  到期記一行「測試模式結束」；`/api/status` 的 `memory.simulated`；Windows 設定頁與 LuCI 狀態頁的記憶體控制區塊顯示黃色橫幅。
- 不走環境變數：環境變數會留在服務設定裡被忘記；設定 + API + 到期時間比較不會誤留。
- `testHooks` 3.5.0 只有這一個用途；以後的新用途也要走同樣的兩道保險。
- **Windows 上模擬會是「於事無補」**（第 12 節）：模擬只讓讀數變小，Windows 的保留量是實體記憶體 5%（16 GB 約 819 MB），
  模擬 20 MB 時缺口約 800 MB，比黑潮自己的用量 × 2 大得多，所以判成於事無補：不停用清單、只停止長大，日誌一行
  「可用記憶體不足是其他程式造成……」，`memory.futile` 是 true。這是預期行為，規格 11 的 W5 驗證的就是這一條；
  停用清單、只轉送、恢復的路徑由 D3（保留約 25.6 MB，模擬 20 MB 時缺口只有 5.6 MB）的 D11 驗證。

### 11.1 在 D3（512 MB、padavan）上觸發 3.4.2 的 G1／G2 路徑

D3 的自動保留量約 25.6 MB（`kuroshio sysinfo` 的 `reserve`）。「不足」是可用 < 保留量的一半，保護清單暫停（第 6 步）要可用 < 保留量的 1/4。

1. 設定檔（padavan 是 JSON）加 `"system": { "testHooks": true }`，重新載入；日誌有一行「設定開了 system.testHooks」。
2. **G1（一份清單都還沒有時不暫停全部）**：先讓這台一份清單都沒有——停止服務、把狀態目錄的 `filter-lists/` 移到別處（沒有本機副本），
   設定裡的清單網址暫時改成連不到的（例如 `http://192.0.2.1/x.txt`）——啟動後立刻
   `kuroshio notify simulate-memory --avail-mb 4 --minutes 5`（4 MB < 25.6 MB 的 1/4）。預期：做到「只轉送」，
   但 `/api/status` 的 `memory.protectedSuspended` 是 false（沒有清單可以暫停）；到期、記憶體回升後第一次更新就把清單載入，
   不必等記憶體控制恢復第 6 步（測完把清單網址與 `filter-lists/` 改回來）。
3. **G2（待寫的副本讀得到）**：清單都載入後 `--avail-mb 10 --minutes 3`（10 MB < 一半）：日誌「暫時停用 N 份清單：…（重建 1 次）」（C3）。
   到期後恢復時看日誌：恢復的清單讀本機副本或待寫的內容（`Persister::pending_bytes`），**不應該**有「下載清單」或從網路收大量資料；
   `/api/status` 的 `filter.heldCopies` 與流量計數對照。
4. 保護清單暫停：`--avail-mb 4`、清單都載入時，預期一路到 `protectedSuspended: true`，到期後 `resume_all` 重新載入。
5. 每一項看：一次停用幾份、重建幾次（「訂閱清單已載入」出現幾次）、到期後多久恢復、有沒有反覆停用／恢復（恢復後 10 分鐘內又吃緊會加倍間隔）。
6. 測完把 `testHooks` 拿掉（或設 false）、重新載入。

## 12. 退讓於事無補（3.5.0）

**情境**：Windows 實測，一台大記憶體的桌機被別的程式（本地 AI）吃掉幾十 GB，可用只剩幾 GB。照第 4 節的階梯會一路讓到停用清單、
只轉送、拒絕新的加密連線，但黑潮自己全部讓出也只有一兩百 MB，對幾十 GB 的缺口於事無補，只讓 DNS 變差。

**判定**（`memgov.rs` 的 `futile_enter`／`futile_hold`／`FutileGate`，所有平台通用）：

- 缺口 = 保留量 − 系統可用記憶體（沒有缺是 0）；自己的用量 = 本程式的 RSS（Linux `/proc/self/statm`，Windows 工作集 `WorkingSetSize`）。
- **進入**：自己的用量 × 2 < 缺口（就算全部讓出也補不到一半）。立刻生效（只會少做事）。
- **離開**：「用量 × 2 ≥ 缺口 × 1.2」或回到寬裕（可用 ≥ 保留量 + 遲滯），**都要連續成立 60 秒**（`FUTILE_EXIT_SECS`；3.5.0 F1）。
  進入與離開之間差 20%，加上 60 秒，不會每幾秒切換。
  （測試版的「回到寬裕」立刻離開：W5 在 5 分鐘內進出 4 次，可用記憶體被別的程式拉上拉下時沒有遲滯。）
- 讀不到自己的用量、或讀不到可用記憶體時規則**不成立**（照舊）；已經成立時讀不到了就立刻離開（`deficit_and_own()` 是 None：沒有依據繼續判）。
- **離開之後讀數寬裕就不讓出**（3.5.0 F1，H1）：狀態要穩定 180 秒才降回寬裕（第 3 節），測試版在「於事無補剛離開、狀態還是吃緊」的那一輪照狀態讓出，
  W5 在可用 10,528 MB、保留量 3,264 MB 的時候移出了 CDN 冷資料。現在 `Governor::tick()` 在狀態還沒降回寬裕時，**這一次的讀數**已經在保留量＋遲滯以上、
  PSI 平靜，就不讓出，`waiting` 寫「可用記憶體已經回到保留量以上，等狀態穩定，不再讓出」。讀數掉回去的下一輪照舊讓出（路由器在吃緊中某一次讀數彈回時也一樣）；
  PSI 有等待、讀不到可用記憶體時照舊讓出；恢復與停止長大的條件沒有動。
- 由記憶體監看每一輪判斷（開著記憶體控制時由 `Governor::observe_futile`，在 `tick` 之前；關掉時監看自己用同一套），
  不在查詢路徑上：多一次比較，沒有鎖、配置、系統呼叫。

**成立時**：

| 做 | 不做 |
|---|---|
| 停止長大（記憶體控制的狀態照實是吃緊／不足，`growth` = false：快取上限停在當時的筆數、清單載入前的額度不再加、CDN 冷資料不整批讀回） | 縮小 DNS 快取、CDN 冷資料移出、診斷緩衝縮小（第 1～3 步） |
| 快照照樣立刻寫出：快照寫入器用它自己的量測（`app::mem_now`，跟壓力訊號無關），可用 < 保留量的一半就是「不足」、下一輪就寫並放掉待寫內容 | 停用過濾清單、只轉送、暫停保護清單（第 4～6 步） |
| 給其他模組的壓力訊號（`app::pressure()`）從「不足」降成「偏低」：背景工作照樣延後、新的加密連線最多 32 條 | 拒絕新的加密連線；清單更新延後到「不足」解除 |

- 之前（不是於事無補時）已經讓出的東西維持原狀：不因為判定改變就恢復，也不再多讓；恢復條件照舊（寬裕、穩定 180 秒、空間 × 1.3）。
- 記憶體控制關掉（`system.memoryGovernor: false`）時，舊的「縮一半、刪三成」做法在於事無補時也不做。
- 日誌：進入時一行 WARN「可用記憶體不足是其他程式造成（缺口 N MB，黑潮全部讓出也只有 M MB）：只停止長大、寫出快照，不縮快取、不停用清單」，
  離開時一行 info（60 秒後才出現）；不是每次量測都寫。MB 一律四捨五入（3.5.0 F6：以前日誌捨去、介面四捨五入，同一個保留量差 1 MB）。`/api/status.memory` 的 `futile`、`deficitBytes`、`ownBytes`，`waiting` 寫明「於事無補」；
  Windows 設定頁與 LuCI 狀態頁的記憶體控制區塊多一行黃色說明，`warnings` 也換成同樣的說明。

**小機器的行為不變**：路由器上的自動保留量是 16～26 MB（D3 約 25.6 MB），缺口最多就是保留量；黑潮自己的用量通常好幾十 MB，
用量 × 2 一定 ≥ 缺口，所以不會成立（測試 `futile_never_on_small_routers` 從可用 0 到保留量逐一驗證 128 MB、512 MB 的數字）。
只有使用者自己把保留量設得比「黑潮用量 × 2」還大時，小機器上才可能成立。
