# 03 · 社群共享協定 v2

v2 **不相容** v1。目前只有兩位使用者（兩台路由器），兩邊一起升級到 3.0 就好，不保留 v1。
好友關係、金鑰、事件紀錄會自動遷移（第 11 節），不用重新加好友。

## 1. v1 實際使用後的問題

| # | 問題 | 實際影響 | v2 的做法 |
|---|---|---|---|
| P1 | 「違規」用次數判斷，自動封鎖 | 兩台正常的系統因為 CDN 官方範圍更新時間不同，被誤封鎖（2.1.2–2.1.4 修過） | 改成**資料品質分數**；品質差只降低採用，不封鎖。封鎖只用在協定層級的惡意行為（第 8 節） |
| P2 | 請求來源 IP 必須等於網域解析出的 IP | CGNAT、多條 WAN、IPv6 隱私位址、DDNS 還沒更新時都會失敗 | 改成**軟性條件**：不符照樣處理，只標記 `ipMatch:false`，自動規則可以要求必須符合（第 6 節） |
| P3 | 簽名對象是「排序後的 JSON」 | 換語言實作時很容易差一個字元就驗證失敗 | **直接簽原始位元組**，不需要正規化（第 3 節） |
| P4 | 每次同步都傳整包（上限 4 MB） | 每小時重傳大量沒變的資料 | **增量同步**：只傳變動，加 zstd 壓縮（第 7 節） |
| P5 | 純拉取，對方要等下一次排程才會發現變化 | 同意好友、資料更新要等最多 60 分鐘 | 加**輕量通知**：只通知「有新資料」，資料仍然由對方來拉 |
| P6 | 資料沒有觀測時間、觀測者網路 | 無法判斷資料是否新鮮、跟我的網路相不相關 | 每筆記錄帶觀測時間、有效期限，整包帶觀測者 ASN / 機房 |
| P7 | 金鑰不能更換 | 金鑰外洩或遺失只能換新身分、所有好友重加 | **金鑰輪替**：新金鑰由舊金鑰簽名，好友自動接受（第 4 節） |
| P8 | 上游只分享 id 與延遲 | 不知道協議、成功率 | 上游記錄帶協議（含 DoH3 / DoQ）、成功率 |

## 2. 傳輸

所有訊息都是「一個請求、一個回應」，內容是第 3 節的信封（CBOR 位元組）。三種管道傳的內容完全一樣：

| 管道 | 做法 |
|---|---|
| HTTPS（h1 / h2 / h3） | `POST /.well-known/kuroshio/v2/<動作>`，`content-type: application/cbor`；身分文件用 `GET /.well-known/kuroshio/v2/identity` |
| TLS，TCP 853，ALPN `kuroshio/2` | 每筆請求 / 回應 = 4 bytes 長度（big-endian）+ 信封；同一條連線可以連續送 |
| QUIC，UDP 853，ALPN `kuroshio/2` | 每筆請求開一條雙向串流，寫入信封後關閉送出端；對方回應後關閉 |

- 身分文件在三種管道都可以取得（TLS / QUIC 管道用動作 `identity`）。
- 端點寫法：`https://網域[:埠]`、`dot://網域[:埠]`、`doq://網域[:埠]`。端點的主機名稱一定要等於對方網域（同 v1，避免被指使去連別人）。
- 選擇順序：依上次成功的管道；失敗時依 DoQ → DoT → HTTPS 輪流嘗試。
- TLS 一律驗證公開 CA 憑證，SNI = 對方網域。
- 大小上限：請求 64 KB；回應壓縮後 8 MB、解壓後 32 MB（防壓縮炸彈，邊解邊數）。
- 逾時：連線 10 秒、整筆 30 秒。

## 3. 編碼與簽名

```
信封 Envelope（CBOR map）
{
  "v":    2,
  "kid":  bstr(8),      // 簽名用金鑰的 id = SHA-256(公鑰)[0..8]
  "body": bstr,         // 訊息本體（CBOR 編碼後的位元組）
  "sig":  bstr(64)      // Ed25519( "kuroshio/2\0" || 動作名稱 || "\0" || body )
}

訊息本體 Body（CBOR map，解開 body 位元組後）
{
  "t":     tstr,        // 動作：identity / request / relation / sync / poke / rotate
  "from":  tstr,        // 寄件網域（小寫）
  "to":    tstr,        // 收件網域（identity 例外，沒有 to）
  "ts":    uint,        // Unix 毫秒
  "nonce": bstr(12),
  ...                   // 各動作的欄位
}
```

- **簽原始位元組**：驗證時直接拿收到的 `body` 位元組驗簽，驗過才解碼。不需要正規化，Rust、JS、任何語言都不會有差異。
- 簽名內容包含動作名稱，所以 A 動作的簽名不能拿去冒充 B 動作。
- 收到時檢查：`to` 是我、`ts` 誤差在 ±10 分鐘內、`(from, nonce)` 沒出現過（保留 20 分鐘）。
- **PoW**（只有好友請求需要）：`SHA-256("kuroshio/2-pow\0" || body)` 前面要有 `powBits` 個 0 位元；body 裡放 `pow` 欄位（bstr(8)）讓對方調整。預設 16 位元。

## 4. 身分與金鑰

### 4.1 身分文件

```
identity body {
  t:"identity", from, ts, nonce,
  keys: [ { kid, pub: bstr(32), since: uint } ],   // 目前有效的金鑰（輪替期間可能兩把）
  endpoints: [ "doq://…", "dot://…", "https://…" ],
  proto: [2],                                      // 支援的協定版本
  caps: ["sync-delta","poke","zstd"],              // 支援的功能
  since: uint,                                     // 身分建立時間（運作天數）
  net: { asn, colo },                              // 自報的網路資訊
  friends: [ bstr(8) ... ]                         // 好友網域雜湊（共同好友用），上限 200
}
```

- **金鑰與網域的綁定**：身分文件只能從「對方網域、公開 CA 憑證驗證通過」的連線取得，取得的金鑰才算數（同 v1）。
- **第二管道（選用）**：DNS TXT `_kuroshio.<網域>` 內容 `v=cd2; k=<kid hex>`。有設定時一定要一致，不一致就拒絕；沒設定就略過。
- 身分文件快取 1 小時；同一個網域每小時最多回連 6 次（防止被拿去當反射攻擊的跳板）。

### 4.2 金鑰輪替

```
rotate body { t:"rotate", from, ts, nonce, old: kid, new: { kid, pub, since } }
```

- 用**舊金鑰**簽名。好友收到後（主動通知或下次讀身分文件）自動改用新金鑰。
- 輪替期間身分文件同時列出兩把金鑰，7 天後移除舊的。
- 舊金鑰遺失時沒辦法輪替：好友那邊會看到「金鑰變更，未經舊金鑰簽名」，需要人工確認（同意後當成新的好友請求處理，保留原本的好友狀態）。
- 金鑰檔：`/etc/kuroshio/community/key.pem`（PKCS#8；升級時從 2.x 的 `/etc/candydns/community/` 搬過來，同一把金鑰）。

## 5. 好友狀態（沿用 v1 的規則）

狀態與規則跟 v1 一樣，只換傳輸格式：

| 狀態 / 旗標 | 意思 |
|---|---|
| `none` / `out` / `in` / `friend` | 無關係 / 我送出請求 / 對方送來請求 / 好友 |
| `myBlock` | 我封鎖對方：永遠不能再請求 |
| `theirBlock` | 對方封鎖我：不再請求 |
| `rejectedUntil` | 我拒絕對方：7 天內不能再請求，提早重送 3 次自動封鎖 |
| `autoBlockAt` | 自動封鎖（提早重送 3 次、自動規則封鎖）的時間；沒有這個欄位 = 使用者封鎖。自動封鎖最多 300 筆（滿了先清最舊的）、30 天後解除；使用者封鎖永遠不清 |
| `theirRejectUntil` | 對方拒絕我：這之前不再請求 |
| `deletedAt` | 我刪除過對方：之後一律人工審核，不套用自動同意 |
| `pairId` | 配對編號：刪除後清空，舊配對的訊息一律忽略 |
| `autoReqPair` | 被對方刪除後只自動重新請求一次 |

- 成為好友時清掉封鎖 / 拒絕旗標（同 2.1.5）。
- 好友連續 `staleDays`（預設 7）天連不上自動刪除。
- 手動新增好友不受 `theirBlock` / `theirRejectUntil` 限制（同 2.1.5）。
- v1 的 `response`、`notify`、`ack` 合併成一個動作 `relation`：

```
relation body { t:"relation", from, to, ts, nonce, pairId, status, reqId? }
status：accepted / pending / rejected(until) / blocked / deleted / not-friend
```

## 6. 好友請求流程

```
A（請求者）                                   B（接收者）
  │ POST request {pub kid, endpoints, reqId, pow}  │
  │──────────────────────────────────────────────▶│ 1. 速率限制（每 IP、全域）
  │                                               │ 2. 檢查 PoW、時間、nonce
  │                                               │ 3. 已封鎖 → relation blocked
  │                                               │ 4. 回連 A 的網域取身分文件（第 4.1 節）
  │                                               │    → 用文件裡的金鑰驗請求簽名
  │                                               │ 5. 量連線品質（3 次）、查 ASN、算共同好友
  │                                               │ 6. 來源 IP 是否在 A 網域的解析結果裡 → ipMatch
  │                                               │ 7. 自動規則：同意 / 拒絕 / 封鎖 / 人工審核
  │◀──────────────────────────────────────────────│ relation {status, pairId}
  │                                               │
  │（人工審核後）◀─────── poke relation ────────────│ B 通知 A 結果
```

- 跟 v1 的差別：
  - 驗證簽名用的金鑰**一律來自回連 A 網域取得的身分文件**，不採信請求裡自帶的公鑰。
  - 來源 IP 不符不再直接拒絕（P2）。
- 自動規則新增兩個條件：

  | 條件 | 意思 |
  |---|---|
  | `require_ip_match` | 來源 IP 必須等於對方網域解析出的 IP（v1 的行為） |
  | `has_txt` | 對方有設定 `_kuroshio` TXT 記錄 |

  v1 的條件全部保留：`domain_suffix`、`asn`、`same_asn`、`colo`、`max_rtt_ms`、`max_jitter_ms`、`max_loss`、`min_age_days`、`min_mutual`、`max_friends`。

### 6.1 好友邀請碼

不另做公開下載：分享一律走好友同步（雜湊、本機驗證、增量）。邀請碼只是讓「加好友」變成貼一次就好。

- **雙方都要已經符合社群條件**（有網域、DoH / DoT / DoQ 至少一種、網域解析得到；即第 3 節自我檢查的 `problems` 是空的）。沒有單向訂閱。貼上的一方沒就緒時，直接列出 `problems`，什麼都不送。
- **格式**：`KRS1.` + base32（RFC 4648 大寫、不補 `=`）。內容：

  | 欄位 | 長度 | 說明 |
  |---|---|---|
  | 版本 | 1 | `1` |
  | 指紋 | 16 | 擁有者身分金鑰的指紋原始 bytes（SHA-256(SPKI DER) 前 16 bytes，跟顯示用的指紋同一個） |
  | 密鑰 | 16 | 128 位元亂數 |
  | 端點 | 1（+2） | `0` = 照預設（443 / 853）找；`1` doq / `2` dot / `3` https + 埠（big-endian）。只有全部端點都不在預設埠時才放第一個 |
  | 網域 | 1 + n | 長度 + 小寫網域 |
  | 檢查碼 | 4 | SHA-256(`"kuroshio-invite\0"` ‖ 前面全部)[0..4] |

  解析時忽略空白與換行、大小寫不分、`0` / `1` / `8` 當成 `O` / `I` / `B`；最後一個字多出來的位元必須是 0。打錯任何一個字都會被檢查碼（或多出來的位元）擋下。管理介面同時顯示 QR 碼（跟關於頁同一個產生器）。
- **固定、可重複使用**：密鑰存在金鑰目錄的 `invite.json`（`{secret, createdAt}`，只有擁有者能讀寫，跟 `key.pem` 同一套寫法；只在第一次查看與「重新產生」時寫入，不是定時寫入），重新啟動不變，完整備份會帶著。按「重新產生」換新密鑰，舊的立刻失效。邀請碼的指紋是顯示時用目前金鑰算的：輪替金鑰後邀請碼會跟著變，舊的在 7 天重疊期內還能用（見下）。
- **流程**（B 貼上 A 的邀請碼）：
  1. B 檢查格式與檢查碼。
  2. B 自己要就緒（不然列出 `problems`，結束）。
  3. B 用一般的社群管道回連 A 的網域取身分文件（TLS 驗證憑證），**簽名金鑰必須是邀請碼裡的指紋**，或由那一把金鑰簽的輪替聲明換過來的；不符就中止、不送任何東西、也不記住這份身分文件（可能是 DNS 被冒充）。
  4. B 送一般的好友請求，body 多一個選用欄位 `invite`（放在 `pow` 前面；舊版不認得會略過）：`HMAC-SHA256(密鑰, "kuroshio/2-invite\0" ‖ from ‖ 0 ‖ to ‖ 0 ‖ nonce ‖ 0 ‖ reqId)`。密鑰本身不上線，證明綁在這一則請求上。
  5. A 照第 6 節驗完請求，再用常數時間比對證明。對了就**自動同意**（不管自動規則），記一筆「成為好友（透過邀請碼加入）」、好友紀錄的 `invitedAt`；雙方照常在 `followUp` 後開始第一次同步。
- **例外（照既有的語意）**：
  - A 封鎖了 B（`myBlock`）→ 照樣回 `blocked`；A 拒絕過 B（`rejectedUntil`）→ 照樣回 `rejected`（提早重送照樣計數）。
  - A 刪除過 B（墓碑 `deletedAt`）→ 等人工審核（`pending`），記一筆「邀請碼有效：曾被你刪除」。
  - 好友數已達 `maxFriends`、或這一小時的邀請碼自動同意已達上限（10 次）→ 等人工審核。
- **證明不對**（密鑰錯誤、已經重新產生過）：記一筆「邀請碼不符或已重新產生」，接著**當成一般請求照自動規則處理**。回應跟沒帶邀請碼時完全一樣，不透露這台有沒有邀請碼、邀請碼對不對。
- **防濫用**：沿用第 9 節的請求限制（PoW、每 IP / 全域每小時）；帶證明的請求每 IP 每小時另外最多 6 次（超過就不檢查證明，當成一般請求）；自動同意全域每小時 10 次。
- **密鑰不外流**：只有擁有者自己的 `GET /api/community/invite` 給邀請碼；`status` 只給 `invite.createdAt`；事件、日誌、`peers.json` 都不含密鑰或邀請碼。

## 7. 同步（增量）

### 7.1 我的分享集合

每個節點維護一份「分享集合」：只放**我自己驗證過、對我有用**的資料（同 v1 原則，從好友收到的資料要在我這邊驗證通過才會進來）。

- 集合有 `epoch`（隨機 8 bytes，state 重置時換新）與遞增的 `seq`。
- 每筆記錄有 `(kind, key)`、`seq`（最後變更時的序號）、`obs`（觀測時間）、`exp`（有效期限）。
- 記錄到期或不再有用 → 變成刪除標記（保留 7 天，讓對方的增量同步收得到）。
- 自己網域（綁定網域的上層網域，見 02 的備份檔說明）底下的名稱不放進 `site`、`cross`（連雜湊都不送），避免好友比對出自己的子網域。

### 7.2 記錄種類

| kind | key | 內容 | 上限 | 有效期 |
|---|---|---|---|---|
| `node` | `p/ip` | CDN 台灣節點：`p` 業者、`ip`、`fam`、`pop`、`ms` | 4,000 | 3 天（v6 永久節點 30 天） |
| `site` | `h/fam` | 網站驗證結果：`h` 網域雜湊、`p`、`fam`、`ips[≤4]`、`pop` | 20,000 | 3 天 |
| `cross` | `h` | 跨 CDN 結果：`h`、`from`、`to`、`ips[≤4]` | 5,000 | 3 天 |
| `upstream` | `url` | 上游：`url`、`proto`（udp/tcp/dot/doh/doh3/doq/dnscrypt）、`ms`、`ok`（成功率） | 100 | 2 天 |

整包另外附 `ctx: { asn, colo }`（觀測者的網路），接收者可以用來判斷跟自己的網路相不相關（例如同一家電信業者的觀測優先）。

**網域雜湊**：`h = SHA-256("kuroshio/site\0" || 網域小寫)[0..12]`。
限制說明：熱門網站可以用字典反推，雜湊只防「一眼看到網站清單」，不是真正的隱私保護。所以只分享 CDN 網站的驗證結果（同 v1），`shareDomains` 可以關掉。

### 7.3 動作

```
sync 請求 { t:"sync", from, to, ts, nonce, pairId, epoch?, since? }
sync 回應 { t:"sync", from, to, ts, nonce, status, epoch, seq, full:bool,
            ctx:{asn,colo}, upserts:[記錄…], deletes:[[kind,key]…] }
          整個回應 body 用 zstd 壓縮後再簽名（信封多一個欄位 "enc":"zstd"）
status：ok / unchanged / not-friend / blocked / …（同 relation）
```

- `epoch` 與我上次拿到的一樣、而且 `since` 還在對方保留的刪除標記範圍內 → 回增量；否則回完整集合（`full:true`）。
- `seq` 沒變 → `status:"unchanged"`，回應很小。
- 定期拉取：`syncIntervalMin`（預設 60 分鐘）。

### 7.4 通知（poke）

```
poke { t:"poke", from, to, ts, nonce, pairId, what:"data"|"relation"|"rotate", seq? }
```

- 只告訴對方「我這邊有變化」，**不帶資料**；對方在 1–5 分鐘內（隨機）來拉。
- 發送頻率：每個好友最多每 10 分鐘一次；關係變化（同意、刪除）立即送。
- 收到不是好友、或 `pairId` 不符的 poke → 忽略，不回應任何資訊。

### 7.5 互相檢查狀態

延續 2.1.5 的行為：sync 回應的 `status` 不是 `ok` 時，兩邊用 `relation` 對一次狀態，再同步一次。
例如我認為是好友、對方回 `not-friend` → 我改成非好友，並自動重新請求一次（每個 `pairId` 只一次）。

## 8. 接收後的處理與信任

### 8.1 每筆記錄的處理（延續 v1，全部只當候選）

| 情況 | 處理 |
|---|---|
| 格式錯誤、私有 / 保留位址 | 丟掉，記為 `invalid` |
| CDN 官方範圍內 | 收下 |
| 不在我的官方範圍內、或我不認識的 CDN | 節點每次同步最多收 100 筆當「待驗證」候選；網站 / 跨 CDN 提示收下（只在區網有人查到該網站時才實際連線驗證） |
| `node` | 交給每日節點池工作實測延遲、POP、速度，通過才進池 |
| `site`、`cross` | 有人查到該網站時，好友的 IP 優先拿來驗證 |
| `upstream` | 只加進每日評測候選，照常經過汙染 / 封殺 / 速度檢查 |

### 8.2 資料品質分數（取代 v1 的違規次數）

- 每個好友、每種 kind 各自計分：本機驗證結果分成 `ok`（可用）/ `fail`（不可用）/ `invalid`（格式錯誤）。
- 分數 = `(ok + 1) / (ok + fail + invalid × 3 + 2)`，只算最近 14 天。
- **用途**：
  - 多個好友提供同一網站的提示時，分數高的先試。
  - 分數低於 `minHitRate`、而且至少試過 20 次 → 這個好友的這種資料暫停採用（顯示在 LuCI），每 3 天重新試一小批，好了就恢復。
  - 只有使用者在 `minHitRate` 設定了「自動刪除」時才會刪除好友（v1 行為，預設關閉）。
- **品質差不等於惡意**：分數再低也不會自動封鎖。

### 8.3 自動封鎖（只限協定層級的惡意）

| 情況 | 處理 |
|---|---|
| 已驗證的好友管道上收到簽名錯誤的訊息 | 立即封鎖（不可能是正常系統） |
| 24 小時內 3 次格式完全錯誤的回應 / 超過大小上限 | 封鎖 |
| 同一次同步裡 `invalid` ≥ 20 筆、而且超過有效筆數 | 封鎖（同 2.1.4） |
| 其他（範圍外 IP、驗證失敗、連不上） | 只影響分數或「連不上」計時，不封鎖 |

## 9. 防濫用總表

| 威脅 | 防護 |
|---|---|
| 大量假好友請求 | PoW（預設 16 位元，請求太多時自動提高到 20）；每 IP 每小時 6 次、全域每小時 60 次（同 v1）；所有社群請求每 IP 每分鐘 120 次 |
| 拿我當反射攻擊跳板（請我回連第三方） | 只回連請求裡寫的網域本身；同一網域每小時最多回連 6 次；回連只是一次小的 HTTPS 請求，沒有放大效果 |
| 偽造訊息 | 每則訊息 Ed25519 簽名，金鑰來自 TLS 驗證過的身分文件 |
| 重放 | 時間誤差 ±10 分鐘 + nonce 記錄 20 分鐘 + `pairId` |
| 舊關係復活 | `pairId`：刪除後舊配對的訊息一律忽略 |
| 灌爆資料 | 每種 kind 有上限；回應壓縮後 8 MB、解壓後 32 MB；邊解壓邊計數 |
| 用資料指使我去打不相干的主機 | 節點只交給每日工作做小量測試；網站提示只在真的有人查時才用；範圍外節點每次最多 100 筆 |
| 邀請碼外流 / 猜邀請碼 | 128 位元密鑰；請求只帶 HMAC 證明；證明不對時當成一般請求，回應一樣；帶證明的請求每 IP 每小時 6 次；自動同意每小時 10 次；擁有者可以隨時重新產生 |
| 洩漏瀏覽紀錄 | 只分享 CDN 網站的驗證結果、網域只給雜湊；`shareDomains` 可關 |

## 10. 管理 API 與 LuCI 的變化

- 現有 `/api/community/*` 路徑全部保留。
- `peers` 回應新增：`ipMatch`、`hasTxt`、`proto`、每種 kind 的分數與暫停狀態、最後使用的管道（DoQ / DoT / HTTPS）、`keys`（含輪替狀態）。
- 新增：
  - `/api/community/rotate`：產生新金鑰並通知好友。
  - `/api/community/accept-key?domain=`：人工接受未經舊金鑰簽名的金鑰變更。
  - `GET /api/community/invite`：我的邀請碼 `{ok, code, qr（SVG）, createdAt, domain, fingerprint, ready, problems}`；第一次查看時產生密鑰。
  - `POST /api/community/invite/refresh`：重新產生（回應同上），舊的立刻失效。
  - `POST /api/community/invite/use?code=`（或 JSON 內容 `{code}`）：貼上好友的邀請碼。回 `{ok, stage, status, domain, steps:[{step, ok, text}], problems?, reason?}`；`stage` = `format` / `ready` / `self` / `identity` / `fingerprint` / `request` / `sent`（送出了、等對方審核）/ `accepted`。
  - rpcd：`invite` 在查看白名單，`invite/refresh`、`invite/use` 在動作白名單。指令列：`kuroshio community invite [--refresh]`、`kuroshio community join <邀請碼>`（交給執行中的服務）。
- LuCI 社群頁：
  - 好友表加「資料品質」欄（各 kind 的分數）與「管道」欄。
  - 自動規則加 `require_ip_match`、`has_txt`。
  - 「我的身分」加 TXT 記錄建議值與「更換金鑰」按鈕。
  - 事件紀錄沿用。

## 11. 從 v1 遷移

| 項目 | 處理 |
|---|---|
| 金鑰 `community/key.pem` | 直接沿用（同一把 Ed25519），身分不變 |
| `peers.json` | 轉成 v2 格式：關係與所有旗標照搬；`stats.violations` 丟棄；`tried/ok/fail` 換算成初始分數 |
| `events.json` | 照搬 |
| `bundles/` | 丟棄；升級後第一次同步拿完整集合 |
| `upstream-candidates.json` | 保留，下次同步後重建 |

- 對方還在 v1：v2 的請求會失敗；LuCI 顯示「對方版本較舊（v1）」，每 6 小時重試，不算「連不上」、不觸發 `staleDays` 自動刪除，最多等 30 天。
- 兩位使用者的升級順序不限：先升的那台會等另一台。

## 12. 測試

- `tests/vectors/community/`：固定金鑰、固定 nonce、固定時間產生的信封與預期位元組；Rust 實作與規格範例必須逐位元組一致。
- 兩節點整合測試（沿用 2.x CI 的兩節點測試）：
  - 加好友
  - 拒絕 / 封鎖 / 刪除 / 重新請求
  - 增量同步、epoch 重置後的完整同步
  - poke
  - 金鑰輪替
  - 惡意輸入：簽名錯誤、超過大小上限、壓縮炸彈、重放、範圍外 IP
- 從 v1 state 遷移的測試：用 2.x 產生的 `peers.json` 當輸入。

## 13. 之後可以再加（3.0 不做）

| 功能 | 說明 |
|---|---|
| 朋友的朋友 | 好友清單公開（選用），LuCI 顯示「可能認識」；加好友仍要正式請求 |
| 資料轉送 | 記錄由原始觀測者簽名，好友可以原封不動轉給自己的好友；接收者照樣本機驗證 |
| 過濾誤擋回報 | 好友回報「這條規則誤擋」只當建議顯示，不會自動套用 |

## 14. 實作註記（`crates/kuroshio-community`）

規格沒寫死、實作時決定的細節（測試向量 `tests/vectors/community/v2.json` 以這些為準）：

- **TLS / QUIC 管道的請求**：沒有網址路徑，信封多一個 `a`（動作名稱）；取身分文件送 `{v:2, a:"identity"}`。HTTPS 不帶 `a`。
- **錯誤回應**：三種管道一樣是 CBOR `{v:2, err:狀態碼, error:代碼}`（PoW 不足另帶 `powBits`，請求者照這個位元重算一次）；HTTPS 另外用同一個 HTTP 狀態碼。`poke`、`rotate` 成功回 204（TLS / QUIC 是空的回應）。代碼：`not-ready` 503、`rate-limited` 429、`too-large` 413、`bad-envelope` / `bad-body` / `bad-message` / `wrong-recipient` / `bad-sender` / `clock-skew` / `replay` / `pow` 400、`bad-signature` / `unknown-sender` 401。
- **好友請求的回應**是簽過名的 `relation`；狀態多三種只出現在請求回應的：`unverified`（回連驗證失敗，附 `error`）、`key-mismatch`（我記得的金鑰跟你現在的不一樣，等人工確認）。
- **relation 的回應**也是 `relation`：內容是收件者這邊的看法（`accepted`+`pairId` / `pending` / `rejected`+`until` / `blocked` / `not-friend`）。7.5 的「對一次狀態」就是送 `relation{status:accepted, pairId}`、拿回對方的看法再套用。
- **rotate 沒有 `to`**：同一份聲明送給所有好友，也放進身分文件的 `rot: [{body, sig}]`（擴充欄位，輪替後 7 天），錯過通知的好友讀身分文件時用自己記得的舊金鑰驗證。
- **request body** 多一個 `kid`（簽這個請求的金鑰，必須等於信封的 kid），`pow` 一定是最後一個欄位（PoW 只改 body 最後 8 bytes）。
- **記錄的線上格式**：`{kind, key, seq, obs, exp, …欄位}`，`site` 的 key 是 `hex(h)/fam`、`cross` 是 `hex(h)`；收到時 key 跟欄位對不上就算 invalid。
- **第一次連線**（還沒有身分文件）先試 HTTPS 再 DoT、DoQ；拿到身分文件後才照第 2 節的 DoQ → DoT → HTTPS。
- **好友雜湊**：`SHA-256("kuroshio/friend\0" || 網域小寫)[0..8]`。
- **v1 的命中率** `tried/ok/fail` 換算成 `site` 的初始分數；新設定 `community.autoDeleteLowHitRate`（預設 false）= 第 8.2 節的「自動刪除」。
