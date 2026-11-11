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
  Linux 有 `/proc/pressure/memory`（PSI）時一起讀。自己的 RSS 只顯示，不拿來判斷。
- **保留量**（[`Reserve`]）：可用記憶體低於它就讓出記憶體；高於「保留量 + 遲滯」才恢復、才讓記憶體結構長大。
  遲滯 = 保留量的一半，至少 8 MB。
- 使用者設定：`system.memoryReserveMB`（絕對值）與 / 或 `system.memoryReservePercent`（實體記憶體的百分比，最多 90）；
  兩個都填取大的；都 0 = 自動。

### 2.1 自動保留量與理由

| 平台 | 自動 | 128 MB 路由器 | 512 MB | 4 GB | 16 GB |
|---|---|---|---|---|---|
| Linux | max(16 MB, 實體記憶體 5%（最多 1 GB）, `vm.min_free_kbytes` × 3) | 16 MB | 25.6 MB（min_free_kbytes 小時） | 200 MB | 800 MB |
| Windows | max(512 MB, 10%（最多 4 GB）) | — | — | 512 MB | 1.6 GB |

一律不超過實體記憶體的一半。

- **Linux 的 `MemAvailable`**（核心 3.14 起，`si_mem_available()`）＝ 空閒頁 − 核心保留（各區的 low watermark 合計）
  ＋ 可回收的檔案快取與 slab（各扣掉一半或 low watermark 中較小者）。它估的是「不 swap 還能給新程式多少」。
  但它把**可以回收的檔案快取**都算進去，裡面有正在執行的程式本身：OpenWrt 的執行檔、函式庫在 squashfs 上，
  是以檔案快取的形式在記憶體裡；全部回收掉的話，程式每跑一步就要重讀 Flash（thrashing），系統看起來還有記憶體、其實已經卡死。
  所以要再留一段給這些「工作集」：128 MB 路由器上 16 MB（約 12%）夠 dnsmasq、hostapd、netifd、uhttpd、odhcpd 這類常駐程式。
- **`vm.min_free_kbytes`**：核心的 min 水位（low ＝ min × 1.25、high ＝ min × 1.5）。可用記憶體低於 low 時 kswapd 開始回收，
  低於 min 時配置記憶體的程式自己做直接回收（直接卡住）。保留量 ≥ min × 3，讓本程式在 kswapd 忙起來之前就先讓出。
- **大機器 5%（最多 1 GB）**：x86 / 樹莓派上其他服務多、突發也大；1 GB 封頂，64 GB 的機器不必留 3 GB 給一個 DNS 程式讓。
  這就是維護者說的「大約 95%」，換成依實際機器穩定的值。
- **Windows 留比較多**：`ullAvailPhys` 包含待命清單（standby，可以回收的快取），Windows 很積極修剪工作集、把記憶體換到分頁檔；
  系統預設在可用約 32 MB / 4 GB（最多 64 MB）時才發「記憶體不足」通知（`CreateMemoryResourceNotification` 的 low 門檻），
  那時桌面早就卡了。512 MB 或 10% 讓本程式在使用者感覺到之前就讓出。

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
- 關掉記憶體控制（`system.memoryGovernor: false`）時，壓力訊號照樣依保留量運作（`system.memoryWatchdog`），
  快取與 CDN 用舊的「縮一半、刪三成」做法。

## 4. 釋出階梯（底線：純轉送）

吃緊 / 不足時依「重建成本由低到高」釋出。**離保留量不遠**（可用 ≥ 保留量的 3/4）時一輪一步，下一輪（2–5 秒後）量到效果再決定；
**離得遠**（可用 < 保留量的 3/4，或不足）時同一輪連做好幾步，直到估計釋出的量補足差額或沒有可以做的。
某一步做不了（例如沒有冷資料、下載失敗）就先跳過做下一步，那一步至少 1 分鐘後再試。

| 步驟 | 什麼時候 | 做什麼 | 恢復 |
|---|---|---|---|
| 1. 診斷緩衝 | 吃緊 | 設定頁日誌 500 → 50 行；熱門網域 / 被擋網域 / 用戶端排行只留前 200 名 | 上限恢復，自然長回來 |
| 2. DNS 快取 | 吃緊 | 縮到目前上限的 1/4（至少 256 筆），留下熱門的 | 上限恢復 |
| 3. CDN 冷資料 | 吃緊 | 先寫進磁碟，再把一小時沒出現的網域移出記憶體（磁碟保留，查到時讀回） | 全部讀回 |
| 4. 過濾清單 | 不足，而且可用 < 保留量的一半 | 一次停用一份優先順序最低的清單（廣告 → 遙測 → 惡意、命中少的先、大的先）；保護清單不在這一步 | 一次一份，用本機副本或重新下載 |
| 5. **只轉送** | 同上 | 暫停 CDN 調整（答案照上游原樣）、整個 CDN 資料庫寫進磁碟移出記憶體、快取只留 64 筆 | 恢復 CDN 調整與快取上限 |
| 6. 保護清單 | 已經只轉送，而且可用 < 保留量的 1/4 | 暫停全部清單（含惡意 / 反詐騙），只剩自訂規則 | 重新載入全部清單 |

- **底線**：監聽 socket、轉送路徑、上游連線、設定**永遠不釋出**；明文 DNS 一定回答區網的查詢。
  第 5 步之後的狀態就是路由器內建的功能（純轉送），不會更低。加密上游照常使用（只用到既有的連線與小緩衝）。
- 第 6 步只在「不讓出來連轉送都會失敗」時做：保留量的 1/4 已經低於核心開始直接回收的範圍。
  狀態頁、LuCI 狀態頁用紅色提示「連保護清單都暫停了」；`/api/status.memory.protectedSuspended` = true。
- 細節（沿用前一版）：
  - 快取的熱門分數 = 上次使用時間 + 每多一倍的查詢次數加 5 分鐘。縮的時候在一次掃描裡選出要留的，鎖住的時間是一次 O(n)。
  - CDN 冷資料：先在「登記鎖」底下把變動登記並寫出，只移出已經在磁碟上、之後沒變動的分片裡的網域；記憶體裡只留 32 位元雜湊。
    查到時從分片逐筆解析、只撈那一筆；判定跟移出前完全一樣。分片之後要重寫時從磁碟接回去，磁碟上不會少。
  - 過濾清單：重建時新舊兩份並存，新的一份放不進可用記憶體的一半就不做。保護清單（`filter.lists[].protect`；惡意類預設是）
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
| 過濾清單本機副本（壓縮暫存） | 只在可以長大時才邊下載邊壓縮 |

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

- **比量測更快的突增**：別的程式在 2 秒內一口氣吃掉超過保留量的記憶體時，本程式來不及讓；
  這時靠核心的回收（kswapd、直接回收），真的用光時 OOM killer 會先挑別的程式（本程式是 -500），
  被挑中的程式由它自己的 procd / 服務設定重啟。保留量越大，緩衝越多。
- **配置器不一定把記憶體還給系統**：glibc 釋出後呼叫 `malloc_trim`；musl 釋放大塊時直接還，小塊可能留在行程裡。
  RSS 沒降下來時系統可用記憶體也不會回升，狀態會停在吃緊或不足——已釋出的項目維持釋出，不會更糟，也不會自己長回來。
- **停用清單期間保護變少**：第 4 步一次一份、從廣告類開始；第 6 步只在連轉送都快保不住時。狀態頁都有明顯提示。
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

- 保留量：自動（Linux / Windows 各種大小）、百分比、絕對值、兩個都填取大的、百分比上限、不超過一半（`reserve_derivation`）。
- 量測間隔：低於保留量 2 秒、兩倍以內 3 秒、遠 30 秒、PSI 有等待 3 秒（`poll_interval_follows_distance_and_psi`）。
- 遲滯：吃緊 → 寬裕要回到保留量 + 遲滯而且持續 180 秒；不足一次只放鬆一級（`hysteresis_and_dwell`）。
- 可用只剩保留量的 30%：同一輪做完整個階梯到「只轉送」，下一輪沒有可以做的；差額小時補足就停（`far_below_reserve_escalates_several_steps_in_one_tick`）。
- 接近保留量（保留 + 遲滯以內）：不釋出、停止長大；回到寬裕恢復長大（`growth_stops_near_reserve_and_resumes_when_comfortable`）。
- 恢復依相反順序、等空間 × 1.3、失敗指數退避（`near_reserve_one_step_per_tick_then_restore_in_reverse`、`restore_waits_for_headroom_and_backs_off`、`restore_failure_backs_off`）。
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
| `reserveKB`、`reserveAuto`、`reserveHow` | 保留量、是不是自動、怎麼算的（例如「自動：max(16 MB, 實體記憶體 5%, min_free_kbytes 1024 KB × 3)」） |
| `marginKB`、`headroomKB` | 遲滯、保留量以上還有多少 |
| `psi` | `{ someAvg10, fullAvg10 }`（沒有 PSI 時 null） |
| `pollSec` | 目前的量測間隔 |
| `growth` | 記憶體結構現在可不可以長大 |
| `floor`、`protectedSuspended` | 到了只轉送、保護清單也暫停了（狀態頁紅色提示） |
| `sizes` | 動態大小：`cacheEntries`、`cacheMax`、`cacheConfiguredMax`、`cdnInRam`、`cdnOnDiskOnly`、`filterListsBytes`、`filterListRules`、`filterListsUnloaded` |
| `shed[]` | 釋出中的項目：`step`（`diagnostics` / `cache` / `cdn` / `filter` / `floor` / `protected`）、`label`、`detail`、`freedBytes`（估計）、`availDeltaKB`（下一輪量到的可用記憶體差）、`at` |
| `freedBytes` / `freedTotalBytes` | 目前釋出中合計 / 啟動以來合計 |
| `lastChange`、`waiting`、`nextRestoreAt`、`events[]` | 最近一次狀態變化、在等什麼、下次可以恢復的時間、最近 20 筆事件 |

`/api/status.filter`：`unloaded[]`（`name`、`rules`、`bytes`、`reason`：`memory` / `budget`、`at`）、`notice`、`suspended`（全部暫停中）、
`sources[].protect`、`sources[].hits`。
