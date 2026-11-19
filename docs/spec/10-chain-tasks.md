# 10 串接模式：工作分解（3.4.0）

規格在 [10-chain.md](10-chain.md)（以下寫「規格 x.y」）。這份是給實作者的：十個工作包，每個可以獨立交給一位工程師。

## 共同規定（每個工作包都適用）

- 分支：`dev/3.4.0`。每個工作包一個 PR，只動自己「要改的檔案」清單裡的檔案；清單外的檔案需要改時先跟整合者說。
- 程式碼、測試、文件裡**不可以出現任何人的個人網域**；範例用 `example.com`、`example.net`、文件用位址（`192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`、`2001:db8::/32`）；區網位址用 `192.168.1.1`（上游）、`192.168.1.2`（下游）。
- **不可以讀系統的 hosts 檔，也不可以把 hosts 格式清單裡的位址拿來當答案、節點或上游位址。**
- 新的記憶體結構都要有規格第 9 節列的上限，而且有測試證明超過上限時的行為。
- 訊息、記錄、註解用繁體中文（台灣用語），風格跟現有程式碼一致。
- 每個 PR 的共同驗收：

  ```
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets -- -D warnings
  cargo test --workspace
  ```

  三個都要過（最後一個是確認沒有弄壞別人的測試）。各工作包另外列自己的測試指令。
- 測試一律用本機的假伺服器（`127.0.0.1:0`），不可以連到網際網路。假 DNS 伺服器的寫法參考 `crates/kuroshio-net/tests/path_check.rs` 的 `fake_dns`、`crates/kuroshio/tests/forward.rs` 的 `fake_upstream`。
- 開關只有兩個（規格 1.11）：下游 `upstream.chain`、上游 `upstream.allowDownstream`，都是布林、預設開。不可以自己再加開關。
- 向下相容是硬性要求：`chain` 關著、或攔截者不是 3.4.0 以上的黑潮時，下游送出的封包與解析行為要跟 3.3.7 一樣（WP4 有測試守著）。

## 相依與順序

```
WP1 協定編解碼 ─┬─▶ WP3 上游回應器 ─┬─▶ WP5 共用結果 ──┐
                │                    ├─▶ WP6 上游放行 ──┤
WP2 設定 ───────┼─▶ WP4 下游狀態機 ──┘                  ├─▶ 整合測試
                ├─▶ WP7 並行數與背景補問                 │
                ├─▶ WP8 上游多樣性                       │
                └─▶ WP9 介面與文件（等 WP4～WP6 的 API）─┘
WP10 重新載入不斷線（選做，沒有相依）
```

- 第一波（可以同時開始）：WP1、WP2、WP10。
- 第二波（WP1、WP2 合併後，可以同時進行）：WP3、WP4、WP7、WP8。WP9 可以先照規格的 JSON 範例做畫面。
- 第三波（WP3、WP4 合併後，可以同時進行）：WP5、WP6。
- 最後：整合測試、WP9 收尾。

會被好幾個工作包碰到的檔案（各自只加下面講好的那幾行，減少衝突）：

| 檔案 | 誰加什麼 |
|---|---|
| `crates/kuroshio/src/resolver.rs` | WP3：`chain.kuroshio` 的進入點、`Resolver.chain` 欄位；WP6：過濾步驟的豁免、`Verdict.bypass`、`serve()` 的參數；WP7：背景補問 |
| `crates/kuroshio/src/app.rs` | WP3：建立 `Responder`；WP4：接上串接狀態；WP5：工作略過、同步排程；WP6：`Access::set_chain` 的更新；WP10：監聽改用 `ListenBank` |
| `crates/kuroshio/src/admin.rs` | WP4：`/api/chain`、`recheck`、`/api/status.chain`；WP6：不動 |
| `crates/kuroshio/src/chain/mod.rs` | WP1 建骨架；之後每個工作包只改自己的子模組檔 |

---

## WP1　協定編解碼

**相依**：無。**規格**：1.2、1.3、3.2、4.2。

**要改的檔案**

- 新增 `crates/kuroshio-community/src/chain.rs`；`crates/kuroshio-community/src/lib.rs` 加 `pub mod chain;`
- 新增 `crates/kuroshio-community/tests/chain_proto.rs`
- 新增 `tests/vectors/chain/auth.json`、`reg.json`、`manifest.json`（固定金鑰種子產生的測試向量）
- 新增骨架 `crates/kuroshio/src/chain/mod.rs`（只有模組宣告與說明）、空的 `ident.rs`、`responder.rs`、`client.rs`、`share.rs`、`grants.rs`（各一行檔頭註解）；`crates/kuroshio/src/lib.rs` 加 `pub mod chain;`

**要新增的型別與函式**（全部是純函式，不做任何 IO）

```rust
pub const SIG_CONTEXT: &[u8] = b"kuroshio-chain/1\0";
pub const PROTO: u8 = 1;
pub const ZONE: &str = "chain.kuroshio";
pub const REG_NAME: &str = "r.chain.kuroshio";
pub const MANIFEST_NAME: &str = "m.s.chain.kuroshio";
pub const OPT_CODE: u16 = 65313;
pub const MAX_DEPTH: usize = 4;
pub const CHUNK: usize = 32 * 1024;
pub const MIN_VERSION: (u32, u32, u32) = (3, 4, 0);
pub const TOKEN_WINDOW_MS: u64 = 300_000;

/// 查詢名稱（已經 normalize：小寫、沒有結尾的點）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Name { Auth([u8; 16]), Reg, Manifest, Chunk { oid: [u8; 8], idx: u32 } }
pub fn in_zone(qname: &str) -> bool;                 // 等於 ZONE 或以 ".chain.kuroshio" 結尾
pub fn parse_name(qname: &str) -> Option<Name>;      // 在區域裡但格式不對 → None
pub fn auth_name(nonce: &[u8; 16]) -> String;
pub fn chunk_name(oid: &[u8; 8], idx: u32) -> String;

/// TXT 記錄的 RDATA ⇄ 原始 bytes（每段最多 255 bytes）
pub fn txt_rdata(payload: &[u8]) -> Vec<u8>;
pub fn txt_payload(rdata: &[u8]) -> Option<Vec<u8>>;

#[derive(Serialize, Deserialize)] pub struct Sealed { /* serde_bytes */ pub body: Vec<u8>, pub sig: Vec<u8> }
pub fn signing_input(kind: &str, body: &[u8]) -> Vec<u8>;       // SIG_CONTEXT || kind || 0x00 || body
pub fn seal(key: &KeyPair, kind: &str, body: Vec<u8>) -> Vec<u8>;            // CBOR(Sealed)
pub fn open(bytes: &[u8], kind: &str, public: &[u8]) -> Result<Vec<u8>>;     // 驗簽，回 body
pub fn peek_body(bytes: &[u8]) -> Result<Vec<u8>>;                           // 還沒驗簽的 body（公鑰在 body 裡的訊息用）

pub struct AuthBody { v, t, nonce, ts, kid, public /* rename "pub" */, app, allow, caps, peer, tok, path }
pub struct RegBody  { v, t, up, tok, peer, kid, public, app, names, local }
pub struct RegAck   { v, t, kid, ttl }
pub struct ManifestBody { v, t, kid, at, app, objects: Vec<Object> }
pub struct Object { k, fmt, id, sha, size, raw, enc, name, at, rules, hash, etag, last_modified /* rename "lastModified" */ }

#[derive(Debug, PartialEq, Eq)]
pub enum AuthError { Malformed, Version(u8), Kind, Nonce, Kid, Signature }
/// 下游：解開 auth 回應並做規格 1.5 第 4 步的全部檢查
pub fn open_auth(bytes: &[u8], nonce: &[u8; 16]) -> Result<AuthBody, AuthError>;
/// 上游：解開 reg（公鑰取自 body），檢查 kid == kid_of(pub)、names 合法、數量 ≤ 32
pub fn open_reg(bytes: &[u8]) -> Result<RegBody>;

pub fn parse_version(s: &str) -> Option<(u32, u32, u32)>;       // "3.4.0-rc1" → (3,4,0)
pub fn version_ok(s: &str) -> bool;                             // ≥ MIN_VERSION

pub fn token(secret: &[u8; 32], peer: &str, window: u64) -> [u8; 16];       // HMAC-SHA256（ring::hmac）
pub fn token_ok(secret: &[u8; 32], peer: &str, now_ms: u64, tok: &[u8]) -> bool;  // 目前與前一個時間窗

#[derive(Debug, PartialEq, Eq)] pub enum PathError { Loop, TooDeep }
/// path：上游給的鏈；own：自己的 kid（含輪替中的舊 kid）
pub fn check_path(path: &[Vec<u8>], own: &[[u8; 8]]) -> Result<(), PathError>;
/// 自己對外公告的鏈：上游的鏈（沒串接是空的）＋自己
pub fn own_path(upstream: Option<&[Vec<u8>]>, me: &[u8; 8]) -> Vec<Vec<u8>>;
```

**具體做法**

- CBOR 用 `crate::envelope::{to_cbor, from_cbor}`；bytes 欄位用 `serde_bytes`（照 `identity.rs` 的 `KeyInfo`）。結構不要加 `deny_unknown_fields`（規格：不認得的欄位忽略）；選用欄位用 `#[serde(default)]`。
- 十六進位用 `crate::util::{hex, unhex}`；亂數用 `random_bytes`。
- `open()` 用 `crate::identity::verify`。`Sealed.sig` 長度不是 64 直接回錯誤。
- `parse_name`：標籤數與長度都要檢查（`Auth` 的標籤必須剛好 32 個十六進位字；`Chunk` 的 `idx` 是不含正負號、不超過 6 位的十進位）。
- 測試向量：種子用 `[7u8; 32]`（上游）與 `[9u8; 32]`（下游），向量檔記 body 的十六進位、簽章、整個 `Sealed` 的十六進位。向量檔是協定的一部分，之後不能改。

**要寫的測試**（`crates/kuroshio-community/tests/chain_proto.rs`）

| 測試 | 驗證 |
|---|---|
| `names_roundtrip_and_reject_garbage` | 四種名稱來回；大寫、多一個標籤、nonce 長度不對、`idx` 是負數或太長、不在區域裡 |
| `txt_roundtrip_binary_over_255` | 0、1、255、256、70,000 bytes 的內容來回一致；RDATA 被截斷時回 `None` |
| `auth_vector_matches` | 用固定種子產生的 `Sealed` 跟 `tests/vectors/chain/auth.json` 逐 byte 相同 |
| `auth_rejects_wrong_nonce_kid_sig_kind_version` | 五種錯誤各自對到 `AuthError` 的變體；改一個 byte 的 body → `Signature` |
| `sig_context_is_not_community` | 用社群共享的 `signing_input("auth", body)` 簽的東西 `open()` 驗不過 |
| `unknown_fields_ignored` | body 多一個不認得的欄位、多一個 `dot` 欄位照樣解得開 |
| `token_window` | 同一個時間窗、前一個時間窗有效；再前一個、別的 `peer`、別的密鑰無效 |
| `path_rules` | 空的鏈、含自己、含舊 kid、長度 3（可以）、長度 4（`TooDeep`）；`own_path` 的結果 |
| `version_parse` | `3.4.0`、`3.4.1-rc1`、`3.10.0`、`3.3.7`（不夠）、`abc`（`None`） |
| `reg_limits` | 33 個名稱、不合法的網域、`kid` 與公鑰不符都被拒絕 |

**驗收**：`cargo test -p kuroshio-community --test chain_proto`；`cargo clippy -p kuroshio-community --all-targets -- -D warnings`。

**不可以做**：不可以動 `envelope.rs`、`identity.rs` 既有的函式簽章；不可以重用 `envelope::SIG_CONTEXT`；不可以在這個模組做網路或檔案 IO；不可以用 base64 包 TXT 內容（規格定的是二進位）。

---

## WP2　設定

**相依**：無。**規格**：1.11、4.1、5、6.2、第 10 節。

**要改的檔案**

- `crates/kuroshio-config/defaults.json`：加規格第 10 節的全部鍵（`upstream.chain: true`、`upstream.allowDownstream: true`、`resolver.backfill`、`resolver.backfillSample`、`benchmark.coverageRegion`、`benchmark.nearMaxMs`）；HaGeZi `doh-vpn-proxy-bypass` 那一筆清單加 `"bypass": true`
- `crates/kuroshio-config/src/lib.rs`：新增 `pub mod chain;`（設定的讀取函式）
- 新增 `crates/kuroshio-config/src/chain.rs`
- `crates/kuroshio-config/src/uci.rs`：`filter_list` 區段的轉換加 `bypass`；其餘選項確認自動轉換正確
- `crates/kuroshio-config/src/uci_migrate.rs`：預設清單裡 `L_BYPASS` 那一筆帶 `bypass '1'`
- `crates/kuroshio-config/tests/uci.rs`：加測試
- `openwrt/kuroshio/files/kuroshio.config`：`upstream`、`resolver`、`benchmark` 區段與那一筆 `filter_list` 加選項與註解
- `crates/kuroshio/src/app.rs`：只改 `answer_fingerprint`、`filter_fingerprint`（規格第 10 節最後一段）
- `data/admin/fields.json`、`openwrt/luci-app-kuroshio/htdocs/luci-static/resources/view/kuroshio_ui/advanced.js`、`filter.js`：設定欄位（**只有設定表單**；狀態畫面是 WP9）

**要新增的型別與函式**（`crates/kuroshio-config/src/chain.rs`）

```rust
/// 布林設定：true/false、"1"/"0"/"on"/"off"/"true"/"false"/"yes"/"no"、數字（0 = false）；
/// 其他寫法 → (預設值, Some(警告))；沒寫（None / null）→ (預設值, None)
pub fn flex_bool(v: Option<&Value>, default: bool) -> (bool, Option<String>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainSettings {
    pub chain: bool,               // upstream.chain：下游要不要辨識上游黑潮並索取資料
    pub allow_downstream: bool,    // upstream.allowDownstream：上游要不要提供資料給下游
    pub path_check: bool,          // upstream.pathCheck：關掉時串接沒有偵測來源，等同 chain 關
    pub warnings: Vec<String>,
}
impl ChainSettings {
    pub fn from_cfg(cfg: &Value) -> ChainSettings;
    /// 下游角色實際上有沒有啟用：chain && path_check
    pub fn downstream_enabled(&self) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum Backfill { Cdn, Off }
pub fn backfill_of(cfg: &Value) -> (Backfill, u64 /* backfillSample */);
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum CoverageRegion { Near, Any }
pub fn coverage_region_of(cfg: &Value) -> (CoverageRegion, f64 /* nearMaxMs */);
```

**具體做法**

- 串接只有兩個布林，**沒有** `ChainMode`、`chainBackup`、`chainShare`、`downstreamEncrypted`、`downstreamBypass`。早期草稿的字串值（`"auto"`、`"ask"`）不是合法的寫法：`flex_bool` 回預設值（開）與一筆警告。
- UCI：`upstream` 的兩個選項、`resolver` 的兩個、`benchmark` 的兩個都靠 `apply()` 的 snake_case → camelCase，**不要加改名規則**；`defaults.json` 的預設是布林，所以 `option chain '0'` 會轉成 `false`。用測試確認轉換後的 JSON 名稱與型別。`filter_list` 的 `bypass` 在清單區段的轉換裡跟 `enabled`、`protect` 同樣的方式處理。
- **說明文字**（UCI 預設檔的註解、`fields.json` 的 `help`、LuCI 的說明三處意思要一致，照規格 1.11）：
  - `chain`：「辨識上游的黑潮並自動串接：直接用它的評測結果、CDN 節點池與清單副本。關閉時把上游黑潮當成一般的 DNS 攔截，這台會自己重做評測、CDN 掃描、下載清單，重複使用網路。」
  - `allow_downstream`：「提供資料給接在後面的黑潮（串接、評測結果、CDN 節點池、清單副本，並放行它解析自己的上游）。關閉時仍然回答「我是黑潮」，但下游會自己重做評測、CDN 掃描、下載清單，重複浪費網路資源（含這台的頻寬）。開著時區網裡任何會講這個協定的裝置都拿得到；有啟用「繞過防護」清單、要管住區網裝置的環境請關閉。」
  - 清單的 `bypass`：「這份是繞過防護類的清單。上游的 allow_downstream 開著時，不擋已登記的下游黑潮解析它自己的上游主機名稱。」
- UCI 預設檔寫成：

  ```
  	# 串接（3.4.0）：辨識上游的黑潮並自動串接、共用它的評測結果與 CDN 節點；關閉 = 自己重做，重複使用網路
  	option chain '1'
  	# 提供資料給接在後面的黑潮；關閉 = 下游自己重做評測與 CDN 掃描，重複浪費網路資源（含這台的頻寬）
  	option allow_downstream '1'
  ```
- `fields.json`：照既有的 `upstream.pathCheck` 那一筆的格式（`"type": "bool"`）。LuCI `advanced.js`：用現有的 `common.flag`，接在 `path_check`、`intercept_policy` 後面。

**要寫的測試**

| 測試（位置） | 驗證 |
|---|---|
| `flex_bool_accepts_uci_and_json`（`chain.rs` 的單元測試） | 布林、`"1"`／`"0"`／`"on"`／`"off"`／`"yes"`／`"no"`、數字 0／1／5、`null`（預設、沒有警告）、`"auto"`／`"ask"`／陣列（預設＋警告） |
| `chain_settings_defaults_on` | 空設定 → `chain == true`、`allow_downstream == true`；`pathCheck: false` → `downstream_enabled() == false` |
| `defaults_have_all_chain_keys` | `build(&json!({}))` 之後規格第 10 節的每個鍵都在、值等於表裡的預設；`upstream` 底下**沒有** `chainBackup`、`chainShare`、`downstreamEncrypted`、`downstreamBypass` |
| `uci_chain_options_convert`（`tests/uci.rs`） | `option chain '0'` → `upstream.chain == false`；`allow_downstream '0'` → `false`；`backfill_sample '0'`、`coverage_region 'any'`、`near_max_ms '80'` 轉換後的 JSON 名稱與型別；`ChainSettings::from_cfg` 讀得出來 |
| `uci_filter_list_bypass` | `config filter_list` 的 `option bypass '1'` → `filter.lists[i].bypass == true`；沒寫是沒有這個鍵或 `false` |
| `shipped_uci_config_matches_defaults` | `openwrt/kuroshio/files/kuroshio.config` 轉換後，上面這些鍵的值等於 `defaults.json`（防止兩邊不同步） |
| `fingerprints_change_with_chain_settings`（`app.rs` 的單元測試） | 改 `upstream.chain` → `answer_fingerprint` 變；改清單的 `bypass` 或 `upstream.allowDownstream` → `filter_fingerprint` 變 |
| `help_texts_mention_duplicate_work`（`tests/uci.rs` 或 `kuroshio` 的單元測試） | `fields.json` 裡 `upstream.chain` 與 `upstream.allowDownstream` 的 `help`、UCI 預設檔的註解都含「重複」兩個字（守住說明文字不被刪掉） |

**驗收**：`cargo test -p kuroshio-config`；`cargo test -p kuroshio --lib fingerprints_change_with_chain_settings`；`node tools/admin-e2e.js`（現有的設定頁測試，新增的欄位要顯示得出來、存檔後值正確）。

**不可以做**：不可以加規格第 10 節以外的串接開關；不可以改 `resolver.parallel` 的預設值與 `derive_auto`（那是 WP7）；不可以改既有鍵的名稱或預設；`defaults.json` 裡不可以出現真實的個人網域。

---

## WP3　上游回應器（auth）

**相依**：WP1、WP2。**規格**：1.9、1.3（AuthBody）、8.1 的 T7、T11。

**要改的檔案**

- `crates/kuroshio/src/chain/ident.rs`、`responder.rs`、`mod.rs`（重新匯出）
- `crates/kuroshio/src/resolver.rs`：`Resolver` 加 `pub chain: std::sync::OnceLock<Arc<crate::chain::responder::Responder>>`；`handle_inner` 在 `version.kuroshio` 那一段之後加進入點
- `crates/kuroshio/src/app.rs`：`start()` 建立 `Responder` 並 `resolver.chain.set(..)`（放在明文監聽開始之前）
- 新增 `crates/kuroshio/tests/chain_responder.rs`

**要新增的型別與函式**

```rust
// ident.rs：節點金鑰（跟社群共享同一把）
pub struct NodeKey { /* 金鑰目錄、目前的 KeyPair、key.pem 的修改時間、輪替中的舊 kid */ }
impl NodeKey {
    pub fn new(key_dir: PathBuf) -> NodeKey;                     // 不讀檔
    pub fn get(&self) -> anyhow::Result<Arc<KeyPair>>;            // 第一次呼叫才 Identity::load_or_create；key.pem 的修改時間變了就重讀
    pub fn own_kids(&self) -> Vec<[u8; 8]>;                       // 目前的 + 輪替 7 天內的舊 kid
    pub fn fingerprint(&self) -> Option<String>;
}
pub fn key_dir(cfg: &Value, base_dir: &Path) -> PathBuf;          // 跟 app.rs::start_community 算的同一個目錄

// responder.rs
pub struct Responder { /* settings、Arc<NodeKey>、啟動時的 32 bytes 亂數密鑰、速率限制表、上游的鏈、計數 */ }
impl Responder {
    pub fn new(settings: &kuroshio_config::chain::ChainSettings, key: Arc<NodeKey>) -> Arc<Responder>;
    /// qname 在 chain.kuroshio 區域裡時呼叫；一定回一個回應（成功或 REFUSED / NXDOMAIN）
    pub fn answer(&self, query: &Message, qname: &str, ctx: &crate::resolver::Ctx) -> Message;
    /// 下游狀態機（WP4）在綁定、解除時設定：自己串接中的上游的鏈
    pub fn set_upstream_path(&self, path: Option<Vec<Vec<u8>>>);
    pub fn caps(&self) -> Vec<&'static str>;
    pub fn serving_json(&self) -> Value;                          // /api/status 的 chain.serving（WP5、WP6 之後會加欄位）
    pub fn set_bypass_list_active(&self, on: bool);
}
```

**具體做法**

- `handle_inner` 加的程式碼（條件跟 `version.kuroshio` 同一個寫法）：

  ```rust
  if qclass == 3 && kuroshio_community::chain::in_zone(&qname) {
      self.stats.count(StatKind::Local);
      return msg(match self.chain.get() {
          Some(c) if matches!(ctx.proto, "udp" | "tcp") && is_private_client(ctx.client) => c.answer(&query, &qname, ctx),
          _ => Message::response_to(&query, 5),
      });
  }
  ```

  要點：這一段**一定 return**，`chain.kuroshio` 的查詢不可以走到過濾、快取、上游。
- `answer()`：`parse_name` → `Name::Auth(nonce)`：先過速率限制，再 `key.get()`、組 `AuthBody`、`seal(.., "auth", ..)`、放進一筆 TXT（class 3、TTL 0、`RData::Raw(txt_rdata(..))`）。`qtype` 不是 16 或 255 → 空答案。`Name::Reg`、`Name::Manifest`、`Name::Chunk` 在這個工作包先回 `REFUSED`（WP5、WP6 接上）。
- `allow_downstream = false`：`allow: false`、`caps: []`，照樣簽章回答（「我是黑潮，但不提供資料」）；另外記數（`probes`：次數與最後時間，規格 4.5），讓上游的狀態頁看得出有下游來問過。`serving_json()` 一定回完整的物件，含規格 4.5 的 `text`、`note`（不做 `bypassListActive`）。
- `peer`：`ctx.client.to_canonical().to_string()`。`tok`：`chain::token(&secret, &peer, now_ms / TOKEN_WINDOW_MS)`。
- 速率限制：`Mutex<HashMap<IpAddr, (f64 /* 剩餘 */, Instant)>>`，每來源每秒補 4、上限 8；全域每秒補 32、上限 64。表滿 64 筆時刪掉最久沒更新的一筆。超過回 `REFUSED`，`serving_json` 的 `refused.rate` 加 1。
- `NodeKey::get()` 失敗（金鑰目錄不能寫）：回 `SERVFAIL`（rcode 2），記一次警告（不要每個查詢都記）。
- 金鑰目錄的計算從 `start_community` 抽成 `ident::key_dir`，`start_community` 改呼叫它（行為不變）。

**要寫的測試**（`crates/kuroshio/tests/chain_responder.rs`；用 `kuroshio::app::start` 起一個實際監聽的行程內實例，`community.dir` 指到暫存目錄）

| 測試 | 驗證 |
|---|---|
| `auth_over_udp_and_tcp_verifies` | 對監聽埠發 `auth_name(nonce)`（CH TXT），`open_auth` 驗得過；`peer` 是 `127.0.0.1`；`path` 只有自己；`app` 是目前版本；回應小於 512 bytes |
| `auth_creates_key_when_community_disabled` | `community.enabled = false`、金鑰目錄是空的 → 第一次 auth 之後 `key.pem` 存在而且權限 0600（Unix）；第二次的公鑰相同 |
| `auth_same_key_as_community` | 先放一把已知的 `key.pem` → auth 的公鑰就是它 |
| `allow_downstream_off_still_signs` | `allowDownstream: false` → `allow == false`、`caps` 是空的、簽章有效；`serving.text` 含「不提供資料」與「重複」；問過之後 `serving.probes.count24h == 1` |
| `serving_text_when_on` | 預設（開）→ `serving.allowDownstream == true`、`text` 是「提供資料給下游黑潮：目前沒有下游連上來」、`note` 不是空的 |
| `in_class_queries_are_not_treated_as_chain` | 類別 IN 的 `x.chain.kuroshio` 照一般查詢處理（不是 `REFUSED`，也不會有 TXT 簽章） |
| `chain_queries_never_reach_upstream` | 假上游記錄收到的查詢；發各種 `*.chain.kuroshio` 的 CH 查詢（含亂寫的名稱）之後，假上游一筆都沒收到，回應是 `REFUSED` |
| `refused_on_encrypted_proto_or_public_client` | 直接呼叫 `resolver.handle`，`Ctx { proto: "doh", .. }` 或 `client: 203.0.113.9` → `REFUSED` |
| `rate_limit_per_source_and_table_bounded` | 同一個來源連發 30 次，成功的不超過 8 + 經過秒數 × 4；用 100 個不同來源（直接呼叫 `answer`）之後表的大小 ≤ 64 |
| `path_reflects_upstream` | `set_upstream_path(Some([X]))` 之後 auth 的 `path` 是 `[X, 自己]` |
| `version_kuroshio_unchanged` | `version.kuroshio` 的回答仍然是 `kuroshio/<版本>`（3.3.x 的下游靠這個） |

**驗收**：`cargo test -p kuroshio --test chain_responder`；`cargo test -p kuroshio --test resolver`（既有的不能壞）。

**不可以做**：不可以在公開的加密監聽回答；不可以把 `chain.kuroshio` 的查詢轉給上游或寫進快取；不可以在啟動時就建立金鑰（第一次需要才建）；不可以改 `version.kuroshio` 的回答格式；不可以每個查詢都讀一次金鑰檔（只看修改時間，而且最多每 60 秒看一次）。

---

## WP4　下游狀態機

**相依**：WP1、WP2（跟 WP3 平行；單元測試用假的上游）。**規格**：1.4～1.8、1.10、第 2 節。

**要改的檔案**

- `crates/kuroshio-net/src/path.rs`：`Report` 加命中的位址；公開 CH TXT 的查詢函式
- `crates/kuroshio/src/pathcheck.rs`：檢查之後通知串接；測試用的目標覆寫；串接中不列攔截的提醒
- `crates/kuroshio/src/upstreams.rs`：`Role::Chain`、`Manager::set_chain` 等
- `crates/kuroshio/src/resolver.rs`：只有 `Role` 的比對（三處 `Role::Pinned` 的判斷確認 `Chain` 的行為，見下）
- `crates/kuroshio/src/chain/client.rs`、`mod.rs`
- `crates/kuroshio/src/app.rs`：`start()` 接上串接（一行）、`paths_json` 不用動
- `crates/kuroshio/src/admin.rs`：`/api/chain`、`/api/chain/recheck`；`/api/status` 加 `chain` 與 `network.path.interceptor.chain`；`/api/notify/wan-changed` 加一行
- `crates/kuroshio/src/main.rs`：`check-path` 的輸出；`kuroshio chain …` 子指令
- 新增 `crates/kuroshio/tests/chain_client.rs`；`crates/kuroshio-net/tests/path_check.rs` 加測試

**要新增的型別與函式**

```rust
// kuroshio-net/src/path.rs
pub struct Report { /* 既有欄位 */ pub hit: Option<SocketAddr>, pub hit_tcp: bool }   // 命中的保留位址（IPv4 優先）、是不是只有 TCP
pub struct ChaosReply { pub rcode: u16, pub txt: Option<Vec<u8>> /* 第一筆 TXT 的全部字串接起來，二進位 */ }
/// 一次 CH TXT 查詢；`opt` = 要帶的 EDNS 選項；UDP 回 TC 時自動改 TCP
pub async fn chaos_txt(addr: SocketAddr, name: &str, tcp: bool, opt: Option<(u16, Vec<u8>)>, limit: Duration) -> Result<ChaosReply>;
/// 同一條 TCP 連線上連續問（WP5 抓分段用）
pub struct ChaosTcp { /* TcpStream */ }
impl ChaosTcp { pub async fn connect(addr: SocketAddr, limit: Duration) -> Result<ChaosTcp>;
                pub async fn ask(&mut self, name: &str, limit: Duration) -> Result<ChaosReply>; }

// upstreams.rs
pub enum Role { Pinned, Auto, Fallback, LastResort, Chain }       // name() = "chain"
impl Manager {
    pub fn set_chain(&self, up: Option<Upstream>);
    pub fn chain(&self) -> Option<Arc<Up>>;
    pub fn chain_suspended(&self) -> bool;                         // 連續失敗後的 30 秒暫停中
    pub fn on_chain_trouble(&self, f: Arc<dyn Fn() + Send + Sync>); // 連續失敗 3 次時呼叫（通知串接模組補心跳）
}

// chain/client.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State { None, Detected, Verifying, Chained, Released }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason { UpstreamTooOld, Unsupported, NotAllowed, VerifyFailed, UpstreamChanged, NoResponse, Gone, Loop, TooDeep, Tampered }
impl Reason { pub fn code(self) -> &'static str; pub fn text(self) -> &'static str; }

#[derive(Debug, Clone)]
pub struct Timing { pub ask: Duration, pub heartbeat: Duration, pub early_min: Duration, pub early_max: Duration,
                    pub retry_min: Duration, pub retry_max: Duration, pub fail_limit: u32 }
impl Default for Timing { /* 1.5 s、300 s、5 s、15 s、60 s、600 s、3 */ }

/// 探測的結果（狀態頁、check-path 用）
#[derive(Debug, Clone)]
pub struct Probe { pub supported: bool, pub allow: bool, pub public: Option<[u8; 32]>, pub kid: Option<[u8; 8]>,
                   pub version: String, pub caps: Vec<String>, pub path: Vec<Vec<u8>>, pub peer: String, pub tok: Vec<u8>, pub error: Option<String> }
/// 不需要服務在跑：check-path 與狀態機共用
pub async fn probe(addr: SocketAddr, tcp: bool, limit: Duration) -> Probe;

pub struct Client { /* 設定、Timing、Arc<NodeKey>、狀態（Mutex，含綁定的公鑰與「公鑰換過」的時間）、目前接著的 Manager（Weak）、Notify */ }
impl Client {
    pub fn new(settings: ChainSettings, key: Arc<NodeKey>, timing: Timing) -> Arc<Client>;
    /// 新的一輪：換設定、接上新的 Manager 與 Responder；原本是 Chained 就立刻把綁定接回去。chain 關著 → 回到 None、清掉綁定
    pub fn attach(self: &Arc<Self>, settings: ChainSettings, mgr: &Arc<Manager>, responder: Option<&Arc<Responder>>);
    /// 路徑檢查做完之後呼叫（規格 1.5 的第 1～6 步）
    pub async fn on_path_report(self: &Arc<Self>, r: &kuroshio_net::path::Report);
    pub fn on_wan_changed(&self);
    pub fn state(&self) -> (State, Option<Reason>);
    pub fn is_chained(&self) -> bool;
    pub fn bound_key(&self) -> Option<[u8; 32]>;                   // WP5 驗清單用
    pub fn bound_addr(&self) -> Option<(SocketAddr, bool /* tcp 可用 */)>;
    pub fn last_probe(&self) -> Option<Probe>;                     // WP6 登記用（tok、peer）
    pub fn status_json(&self) -> Value;                            // 規格 1.10 的 chain（不含 shared、serving）
    pub fn interceptor_json(&self) -> Value;                       // network.path.interceptor.chain
    /// 上游公鑰換過、24 小時內：給 /api/status.warnings 的一行；否則 None
    pub fn key_change_warning(&self, now_ms: u64) -> Option<String>;
    pub fn spawn(self: &Arc<Self>);                                // 心跳與重試的背景工作（每一輪 runtime 呼叫一次）
}

// chain/mod.rs：行程層級的持有者（跨重新載入；做法同 app.rs 的 CACHE_HANDOFF）
pub fn current() -> Option<Arc<client::Client>>;
pub fn install(c: Arc<client::Client>);

// pathcheck.rs
pub fn targets() -> kuroshio_net::path::Targets;                   // 預設 Targets::default()；測試用環境變數覆寫
```

**具體做法**

1. `path.rs`：`check()` 把 `hit4`（沒有才 `hit6`）記進 `Report.hit`／`hit_tcp`；`Default` 是 `None`／`false`；**`to_json()` 不輸出這兩個欄位**（`/api/status` 的格式不變）。`chaos_txt` 用現有的 `udp_ask`／`tcp_ask`；帶 EDNS 選項時用 `kuroshio_proto::message::Message` 組封包（`opt: Some(Opt { udp_size: 1232, options: vec![..], .. })`）。
2. `pathcheck.rs`：`run_once()` 在 `path::apply` 之後呼叫 `if let Some(c) = crate::chain::current() { c.on_path_report(&r).await }`。`warnings()` 在 `is_chained()` 時濾掉「一般 DNS 被…接走」那一條。
   `targets()`：環境變數 `KUROSHIO_PATH_TARGETS` 有值時解析成 JSON 覆寫（只給測試用，不寫進使用者文件的穩定介面）：
   `{"testnetV4":["127.0.0.1:5301"],"testnetV6":[],"gateway":"127.0.0.1:5301"|null,"encrypted":false}`。`encrypted: false` 把 `dot`／`doh`／`quic` 清空（要確認清空時 `check()` 不會判成「協定被擋」也不會判成離線造成的副作用，必要時在 `check()` 裡對「沒有目標」做處理並加測試）；`gateway` 覆寫串接驗證時「直連閘道」的位址（含埠）。
   同樣地 `KUROSHIO_CHAIN_TIMING`（JSON，毫秒：`{"heartbeat":2000,"earlyMin":200,"earlyMax":400,"retryMin":500,"retryMax":2000}`）覆寫 `Timing`，只給整合測試用。
3. `upstreams.rs`：
   - `Manager` 加 `chain: RwLock<Option<Arc<Up>>>`、`chain_trouble: RwLock<Option<Arc<dyn Fn() + Send + Sync>>>`。
   - `Up::record`：`Role::Chain` 連續失敗 3 次 → `open_until = now + 30 s`、`consec_fail = 0`、呼叫 `chain_trouble`（要先放掉 `stats` 的鎖再呼叫）。
   - `Up::via_interceptor`：`Role::Chain` 回 `false`。
   - `active()`／`backup()` 照規格 1.6 的規則。把選擇的邏輯抽成純函式方便測試：
     `pub fn select_chain(chain: Option<&Arc<Up>>, suspended: bool, pinned: &[Arc<Up>], auto: Vec<Arc<Up>>, fallback: &[Arc<Up>], last_resort: &[Arc<Up>]) -> (Vec<Arc<Up>> /* active */, Vec<Arc<Up>> /* backup */)`，之後再過現有的 `select_active`（時鐘沒對時只用明文）。沒有 `backup` 的設定：上游掛掉時退回自己的加密上游是固定行為。
   - `set_chain(Some(u), ..)`：`u.id` 跟某個固定上游相同時不新增（直接把那個固定上游當串接上游看待：`chain()` 回它，但角色維持 `Pinned`）。
   - `list_json()`：串接上游排第一個。
4. `resolver.rs` 裡三類 `Role::Pinned` 的判斷：快速回應的排除（652 行附近）只針對 `Pinned`，`Chain` 可以當快速回應，**不用改**；`baseline` 的 `r.up.role != Role::Pinned`（700 行附近）改成同時排除 `Chain`；`decide()` 裡 `pinned_alias` 的剔除與平手時以固定上游為準（941、980 行附近）維持只看 `Pinned`。
5. `client.rs`：
   - 狀態都在一個 `Mutex<Inner>` 裡，網路 IO 不可以拿著鎖做。狀態轉移寫成純函式 `fn next(inner: &Inner, ev: Event) -> (State, Option<Reason>, Vec<Action>)`，IO 在外層執行 `Action`（發挑戰、設定／清除上游、排重試），這樣狀態機可以不靠網路測。
   - 探測與驗證用 `probe()`；驗證階段的閘道直連：`report.gateway` 是私有位址才試（`KUROSHIO_PATH_TARGETS` 的 `gateway` 覆寫時不檢查私有）。
   - 綁定：`mgr.set_chain(Some(Upstream::parse("udp://<位址>:<埠>")?))`、`responder.set_upstream_path(Some(上游的 path))`。解除：兩個都設回 `None`。
   - 心跳：`spawn()` 的工作 `select!` 等三件事：心跳計時、`Manager::on_chain_trouble` 的通知、重試計時。每次心跳檢查 `chained` 之外的狀態不發任何封包（`Released` 的重試除外）。
   - 自己的 `kid`：`NodeKey::own_kids()`。下游在探測時**不需要**自己的金鑰存在（只比對 `kid`）；金鑰不存在時 `own_kids()` 回空的、不建立金鑰（WP6 登記時才需要建立）。
   - `status_json().text`：照規格 1.10 的對照表，每一種情況一句（含「上游不提供資料…會重複使用網路」「已關閉串接…會重複使用網路」）；位址顯示規則（`via`）也在那裡。`chain` 關著時用路徑檢查的結果判斷上游是不是黑潮（不探測），選對應的句子。
   - 公鑰換了：`Released(UpstreamChanged)` → 立刻重新探測 → 通過就綁定新的公鑰，記 `keyChangedAt`、`previousFingerprint`，`warn!` 一行（含新舊指紋）。第一次綁定不算「換了」。
   - 記錄：狀態改變時記一行 `info!`（例如「串接：上游 192.168.1.1（黑潮 3.4.0，指紋 …）驗證通過，開始串接」）。
6. `app.rs::start()`：建立 `Manager`、`Responder` 之後：

   ```rust
   let chain = crate::chain::current().unwrap_or_else(|| { /* 建立 Client、install */ });
   chain.attach(ChainSettings::from_cfg(cfg), &resolver.upstreams, resolver.chain.get());
   chain.spawn();
   ```

   串接狀態**不存檔**（沒有 `chain.json`）：綁定與「公鑰換過」的時間只在行程層級的 `Client` 裡，跨重新載入、不跨重開機。`chain` 關著（`!settings.downstream_enabled()`）時 `Client` 照樣建立（狀態頁要顯示「已關閉串接」），但 `on_path_report` 不發任何封包、直接維持 `None`。
7. `admin.rs`：`/api/chain/recheck` 加進需要 POST 的兩個清單（124 行與 1020 行附近的 match）。`/api/notify/wan-changed` 在 `pathcheck::trigger()` 之前呼叫 `on_wan_changed()`，回應 JSON 加 `"chain": "released" | "none"`。`/api/status` 的 `warnings` 加上 `key_change_warning()`（有的話）。
8. `main.rs`：`check_path_cmd` 在攔截者是黑潮而且 `version_ok` 時呼叫 `chain::client::probe()`，文字與 JSON 照規格 1.10。`check-path` 在自己的 `chain` 關著時不探測，輸出「這台的 chain 關閉：不辨識上游黑潮」。`Cmd::Chain { action }`（只有 `status`、`recheck`）照 `notify_cmd` 的寫法（讀設定找管理埠、送請求、結束碼 0／1／2）。

**要寫的測試**

`crates/kuroshio/tests/chain_client.rs`（假的上游黑潮＝本機假 DNS 伺服器，用 WP1 的函式回答；`Client` 直接建構、`Timing` 用毫秒級的值）

| 測試 | 驗證 |
|---|---|
| `no_interception_sends_nothing` | 報告沒有攔截 → 狀態 `None`；假伺服器的查詢計數是 0 |
| `non_kuroshio_interceptor_sends_nothing` | `Interceptor::Software` 與 `Unknown` → `None`、0 筆查詢 |
| `old_kuroshio_gets_no_challenge` | `Interceptor::Kuroshio("3.3.7")` → `Released(UpstreamTooOld)`；假伺服器**沒有收到任何 `chain.kuroshio` 查詢** |
| `chain_off_sends_nothing` | `chain: false`，攔截者是黑潮 3.4.0 → 狀態 `None`、0 筆查詢；`status_json().text` 是「已關閉串接（chain 關閉）：把上游黑潮當成一般的 DNS 攔截，自己做評測，會重複使用網路」；`Manager::active()`、路徑檢查的提醒跟 3.3.7 一樣 |
| `detects_verifies_and_chains_automatically` | 預設設定、攔截者是假的上游黑潮 → 不需要任何操作就到 `Chained`；`active()[0].role == Role::Chain`；`text` 以「串接中：上游」開頭；快照目錄沒有多出任何檔案 |
| `impostor_wrong_signature_rejected` | 冒充者：`version.kuroshio` 回 `kuroshio/3.4.0`，auth 用 A 的公鑰但用 B 的金鑰簽 → `Released(VerifyFailed)`，`active()` 沒變 |
| `impostor_replays_old_response` | 冒充者把先前錄下的合法回應（別的 nonce）原樣回給新的挑戰 → `VerifyFailed` |
| `key_change_rebinds_and_warns` | 串接之後假伺服器換一把金鑰 → 心跳後 `Released(UpstreamChanged)` → 自動重新 `Chained`（綁新的公鑰）；`status_json().upstream.previousFingerprint` 是舊的；`key_change_warning(now)` 有值、`now + 25 小時` 是 `None`；第一次綁定時沒有警告 |
| `allow_false_is_not_allowed` | `allow: false` → `Released(NotAllowed)`、`active()` 沒變；`status_json` 的 `upstream.allowDownstream == false`、`text` 是「上游黑潮 3.4.0 不提供資料（allow_downstream 關閉）：自己做評測，會重複使用網路」；之後除了每次路徑檢查的一次探測，沒有其他 `chain.kuroshio` 查詢（不登記、不問共用結果） |
| `loop_and_depth_rejected` | `path` 含自己的 kid → `Loop`；長度 4 → `TooDeep`；長度 3 → 可以 |
| `gateway_direct_preferred_when_same_key` | 閘道位址的假伺服器用同一把金鑰 → `via == "gateway"`、綁的是閘道位址；不同金鑰或沒回應 → `via == "intercept"` |
| `heartbeat_failure_releases_and_recovers` | 假伺服器停止回答 → 3 次後 `Released(NoResponse)`、`active()` 回到自動上游；恢復回答 → 重試後自動 `Chained` |
| `wan_changed_releases_immediately` | `on_wan_changed()` → `None`、`Manager::chain()` 是 `None`；下一次路徑報告後自動 `Chained` |
| `tampered_interceptor_releases` | 報告裡有 `Tamper { via: "interceptor" }` → `Released(Tampered)` |
| `reload_keeps_binding` | `Chained` 之後對新的 `Manager` 呼叫 `attach` → 新的 `Manager` 立刻有串接上游（不用重新探測才接回）；用 `chain: false` 的設定 `attach` → 新的 `Manager` 沒有串接上游、狀態 `None` |
| `tcp_only_interception_uses_tcp` | `hit_tcp = true` → 探測走 TCP、綁定是 `tcp://` |

`crates/kuroshio/src/upstreams.rs` 的單元測試

| 測試 | 驗證 |
|---|---|
| `chain_active_and_backup_rules` | `select_chain` 的每一格：健康（`active` 只有串接上游＋固定）／暫停（`active` 跟沒串接一樣）；`backup` 有自己的加密自動上游、沒有 `via_interceptor()` 的 |
| `chain_breaker_trips_after_three` | 連續 3 次失敗 → `chain_suspended()`、回呼被呼叫一次；成功一次歸零 |
| `chain_same_as_pinned_not_duplicated` | 串接位址跟固定上游相同 → `active()` 裡只有一筆 |
| `unsynced_clock_keeps_chain` | 時鐘沒對時：`active()` 仍然有串接上游（它是明文） |

`crates/kuroshio/tests/resolver.rs` 加：`chain_upstream_answers_are_not_demoted`（串接上游與一個加密固定上游都回答時，`decide()` 沒有因為 `via_interceptor` 把串接上游的答案排除）。

`crates/kuroshio-net/tests/path_check.rs` 加：`report_records_hit_address`、`chaos_txt_binary_and_tc_fallback`（假伺服器 UDP 回 TC、TCP 回 2,000 bytes 的二進位 TXT）、`chaos_txt_carries_edns_option`。

`crates/kuroshio/tests/integration.rs` 加：`check_path_shows_chain_line`（子程序，`KUROSHIO_PATH_TARGETS` 指到假的上游黑潮；輸出有「串接：上游允許串接」；`--json` 有 `interceptor.chain.allowDownstream`）。

**驗收**

```
cargo test -p kuroshio-net --test path_check
cargo test -p kuroshio --lib upstreams
cargo test -p kuroshio --test chain_client
cargo test -p kuroshio --test resolver --test forward --test integration
```

另外人工確認：`chain` 關著起服務，`/api/status` 的 `chain.state == "none"`，`upstreams[]` 跟 3.3.7 一樣。

**不可以做**：不可以在 `chain` 關著、沒有攔截、攔截者不是黑潮、版本低於 3.4.0 時送出任何 `chain.kuroshio` 查詢；不可以把串接上游寫進設定檔或 `upstreams.json`；不可以拿著狀態的鎖做網路 IO；不可以用時間戳判斷回應有沒有過期；不可以改 `Report::to_json()` 既有欄位；不可以在上游回 `allow = false` 時綁定、登記或索取任何資料；不可以為串接寫任何狀態檔；不可以加同意流程或其他開關；不可以讓 `Role::Pinned` 的既有行為有任何改變。

---

## WP5　共用結果

**相依**：WP1、WP3、WP4。**規格**：第 3 節。

**要改的檔案**

- `crates/kuroshio/src/chain/share.rs`（上游的 `ShareCache` 與下游的同步）
- `crates/kuroshio/src/chain/responder.rs`：`Name::Manifest`、`Name::Chunk` 接到 `ShareCache`；`caps()` 加 `"share"`；`serving_json` 加 `share`
- `crates/kuroshio/src/chain/client.rs`：`status_json` 加 `shared`（呼叫 `share.rs` 的函式）
- `crates/kuroshio-cdn/src/cdn.rs`：`import_shared`、`export_shared`
- `crates/kuroshio/src/benchjob.rs`、`crates/kuroshio/src/app.rs`（`register_cdn_jobs`、`start()`）：工作略過、同步的背景工作
- `crates/kuroshio/src/filtering.rs`：副本的匯出／匯入小函式
- `crates/kuroshio/src/upstreams.rs`：`auto_info()` 加 `source`
- 新增 `crates/kuroshio/tests/chain_share.rs`；`crates/kuroshio-cdn/src/tests/` 加匯入的測試

**要新增的型別與函式**

```rust
// chain/share.rs —— 上游
pub trait ShareSource: Send + Sync {                       // app.rs 實作，測試可以換假的
    fn upstreams(&self) -> Option<Vec<u8>>;                // upstreams.json 的內容（種子資料、空的 → None）
    fn cdn(&self) -> Option<kuroshio_cdn::SharedExport>;
    fn filter_copies(&self) -> Vec<FilterCopy>;
    fn read_copy(&self, file: &str, offset: u64, len: usize) -> Option<Vec<u8>>;
    fn pressure_ok(&self) -> bool;
}
pub struct FilterCopy { pub url: String, pub file: String, pub bytes: u64, pub raw: u64, pub hash: u64, pub rules: u64,
                        pub etag: Option<String>, pub last_modified: Option<String>, pub at: u64 }
pub struct ShareCache { /* 簽好的清單、oid → 物件（記憶體 bytes 或副本檔）、建立時間、最後使用時間 */ }
impl ShareCache {
    pub fn new(src: Arc<dyn ShareSource>) -> ShareCache;
    pub fn manifest(&self, key: &KeyPair, now_ms: u64) -> Option<Vec<u8>>;          // 10 分鐘內回同一份；None = 現在不提供
    pub fn chunk(&self, oid: &[u8; 8], idx: u32) -> Option<Vec<u8>>;                // None → NXDOMAIN
    pub fn sweep(&self, now_ms: u64);                                               // 30 分鐘沒用就釋放（每分鐘呼叫）
    pub fn bytes(&self) -> usize;
}

// chain/share.rs —— 下游
pub trait ShareSink: Send + Sync {                         // app.rs 實作，測試可以換假的
    fn import_upstreams(&self, json: Vec<u8>) -> anyhow::Result<()>;
    fn import_cdn_ranges(&self, files: BTreeMap<String, String>) -> anyhow::Result<()>;
    fn import_cdn_pools(&self, json: &[u8]) -> anyhow::Result<()>;
    fn import_cdn_v6(&self, json: &[u8]) -> anyhow::Result<()>;
    fn wants_filter_copy(&self, o: &Object) -> Result<(), &'static str>;            // Err = 不抓的原因（no-room、not-subscribed、memory…）
    fn import_filter_copy(&self, o: &Object, compressed: Vec<u8>) -> anyhow::Result<()>;
    fn filter_copies_done(&self, changed: usize);                                   // 有新副本 → 用副本優先重建一次
    fn pressure_ok(&self) -> bool;
}
pub struct Syncer { /* Arc<Client>、Arc<dyn ShareSink>、狀態（chain-share.json）、Persister */ }
impl Syncer {
    pub fn new(client: Arc<Client>, sink: Arc<dyn ShareSink>, saved: Option<&[u8]>) -> Arc<Syncer>;
    pub async fn sync_once(&self) -> SyncReport;                                    // 規格 3.2、3.4
    pub fn fresh(&self, kind: &str) -> bool;                                        // 36 小時內匯入過而且現在串接中（chain 關著一定是 false）
    pub fn skip_job(&self, job: &str) -> bool;                                      // 規格 3.5 的對照
    pub fn status_json(&self) -> Value;                                             // chain.shared
    pub fn snapshot(&self) -> Vec<u8>;                                              // chain-share.json
    pub fn spawn(self: &Arc<Self>);                                                 // 串接後 30 秒、之後每 6 小時 ±10 分鐘
}
/// 匯入前的檢查（純函式，規格 3.4 的表）
pub fn check_upstreams(raw: &[u8], upstream_kid: &[u8; 8], now_ms: u64) -> anyhow::Result<Vec<u8>>;   // 回處理過（去明文、加 source）的 JSON
pub fn check_ranges(raw: &[u8]) -> anyhow::Result<BTreeMap<String, String>>;

// kuroshio-cdn/src/cdn.rs
pub struct SharedExport { pub pools: Option<Vec<u8>>, pub v6: Option<Vec<u8>>, pub ranges: BTreeMap<String, String> }
impl Cdn {
    pub fn export_shared(&self) -> SharedExport;
    /// 換掉節點池／IPv6 節點（各自可以是 None）；節點要在那一家的官方範圍裡，每家最多 max_per_provider 個。回傳各家收了幾個
    pub fn import_shared(&self, pools: Option<&[u8]>, v6: Option<&[u8]>, max_per_provider: usize) -> anyhow::Result<Vec<(String, usize)>>;
}
```

**具體做法**

- 上游：`Responder` 持有 `OnceLock<ShareCache>`（`app.rs` 在 CDN、過濾都啟動之後設定）。`Name::Manifest`／`Name::Chunk` 的條件：`ctx.proto == "tcp"`、`allow_downstream`、`pressure_ok()`；不符合回 `REFUSED`。同時傳分段的連線數用 `AtomicUsize` 計（進入加 1、回應後減 1，超過 2 回 `REFUSED`）；每來源每秒 64 段沿用 WP3 的速率限制表（另一組桶）。
- 產生清單：`upstreams`、`cdn-*` 用 `zstd`（等級 3，跟 `persist` 用的同一個 crate）壓縮後放記憶體；合計超過 1 MiB 時依 `cdn-v6` → `cdn-pools` → `cdn-ranges` 的順序放棄。`cdn-ranges` 的 JSON 鍵用 `BTreeMap` 保持順序（內容相同時雜湊才會相同）。
- `filter-copy`：只列 `FilterService::copies()` 有、而且那份清單目前啟用的；`sha` 第一次用串流算（一次讀 64 KiB），以 `(file, bytes, hash)` 為鍵快取在 `ShareCache` 裡（最多 64 筆）。
- 下游 `sync_once()`：`client.bound_addr()` 的 TCP 不可用 → `error = "no-tcp"`。用 `ChaosTcp` 一條連線抓清單與全部分段；清單用 `chain::open(bytes, "manifest", &client.bound_key())` 驗簽、`kid` 要等於綁定的；大小 > 16 KiB 或物件 > 64 個整份丟掉。每個物件抓之前先看 `size`／`raw` 上限，抓的過程累計超過 `size` 立刻中止。SHA-256 用 `kuroshio_community::util::sha256`（或 `ring::digest` 的串流介面）。解壓用 `zstd` 的串流解碼並限制輸出大小（超過 `raw` 或上限就中止，防壓縮炸彈）。
- `check_upstreams`：照規格 3.4；`selected` 裡 `type` 是 `udp`／`tcp` 的拿掉之後如果是空的 → 錯誤（不寫檔）。寫檔用 `crate::persist::write_atomic` 到 `Manager::state_file()`，然後 `reload_auto()`。
- `import_shared`：照 `Cdn::load_with` 裡「節點池」那一段的做法建立，再用 `Pools::replace` 換掉各家；不在範圍裡的節點丟掉並計數；全部被丟掉的那一家保留原本的池。之後標 dirty、15 秒後重新量健康與品質（抄 `register_cdn_jobs` 裡 `cdn-pool` 結束後那一段）。
- 工作略過：`BenchJob::run` 與三個 CDN 工作的 closure 開頭加 `if crate::chain::share_skips("<工作名>") { info!("{name}：由上游黑潮提供，略過"); return Ok(()); }`。`share_skips` 是 `chain/mod.rs` 的自由函式（讀行程層級的 `Syncer`；沒有就是 `false`）。
- 串接解除時（`Client` 的狀態離開 `Chained`）：`Syncer` 檢查 `upstreams` 的匯入時間，超過 48 小時就 `scheduler.request("dns-benchmark", "串接解除")`。`Client` 提供 `on_state_change(f)` 的回呼給 `Syncer` 掛（在 `client.rs` 加這個小函式是這個工作包可以動的範圍）。
- `chain-share.json` 經 `Persister::stage`；內容沒變不 stage。

**要寫的測試**（`crates/kuroshio/tests/chain_share.rs`；上游用真的 `Responder`＋假的 `ShareSource`，下游用 `Syncer`＋假的 `ShareSink`，中間是本機 TCP）

| 測試 | 驗證 |
|---|---|
| `manifest_signed_and_objects_verify` | 下游拿到清單、驗簽、抓回 `upstreams` 與 `cdn-pools`，內容跟上游的一致 |
| `multi_chunk_object` | 200 KiB 的物件分 7 段抓回、雜湊正確 |
| `udp_is_refused` | UDP 問清單或分段 → `REFUSED` |
| `allow_downstream_off_refuses_share` | 直接問清單與分段都是 `REFUSED`；正常的下游（`Released(NotAllowed)`）根本不會來問：`Syncer` 的查詢數是 0、`fresh()` 都是 `false`、沒有工作被略過 |
| `tampered_chunk_rejected` | 中間放一個改掉一個 byte 的代理 → 物件被丟掉、`objects[].error` 有值、`ShareSink` 沒被呼叫 |
| `manifest_signed_by_other_key_rejected` | 冒充者用別的金鑰簽清單 → 整次同步失敗、沒有任何匯入 |
| `oversize_and_bomb_rejected` | `size` 超過上限的物件不抓；宣稱 `raw` 很小但解壓出來很大的物件在超過上限時中止 |
| `unknown_kind_and_newer_fmt_skipped` | `k: "future"`、`fmt: 2` 的物件略過，其他照常匯入 |
| `unchanged_objects_not_refetched` | 第二次同步只問清單，分段查詢數是 0 |
| `stale_object_gives_nxdomain_then_recovers` | 上游重新產生清單後問舊的 `oid` → `NXDOMAIN`；下游重新拿清單後成功 |
| `upstreams_import_filters_plain_and_marks_source` | `check_upstreams`：`udp`／`tcp` 的被拿掉、有 `source.chain`；`selected` 不是陣列、`id` 解析不了、超過 64 筆、全部是明文 → 錯誤 |
| `ranges_reject_bad_names_and_cidrs` | 檔名有 `../`、不是 `-ipv4.txt`／`-ipv6.txt` 結尾、內容不是 CIDR → 錯誤 |
| `jobs_skipped_only_when_fresh_and_chained` | `skip_job` 的每一格：新鮮＋串接、新鮮但解除、超過 36 小時、`chain` 關著、上游 `allow = false`（後三種都不略過） |
| `share_cache_bounded_and_released` | 來源給 3 MiB 的資料 → `bytes() ≤ 1 MiB`；`sweep` 在 30 分鐘後釋放到 0 |
| `filter_copy_only_when_wanted` | `wants_filter_copy` 回 `Err("no-room")` 的不抓（分段查詢數是 0）、`objects[].error == "no-room"` |
| `pressure_defers_sync` | `pressure_ok() == false` → 不發任何查詢 |

`kuroshio-cdn`：`import_shared_drops_out_of_range_nodes`、`import_shared_keeps_pool_when_all_rejected`、`export_then_import_roundtrip`。

**驗收**：`cargo test -p kuroshio --test chain_share`；`cargo test -p kuroshio-cdn`；`cargo test -p kuroshio --test benchjob`（既有的不能壞）。

**不可以做**：不可以把過濾清單副本整份讀進上游的記憶體；不可以在沒有驗過清單簽章與物件雜湊之前呼叫任何 `ShareSink` 的匯入函式；不可以在共用結果不新鮮時略過工作；不可以刪掉下游既有的評測結果或節點池（只在驗證通過後取代）；不可以動過濾器的重建流程（`rebuild_mode`）本身，只能呼叫既有的入口；不可以把匯入的節點池裡不在官方範圍的位址收進來。

---

## WP6　上游放行下游

**相依**：WP1、WP3、WP4。**規格**：第 4 節、8.1 的 T8、T9、第 11 節第 2 項。

**範圍（已決定）**：沒有獨立的開關，跟著上游的 `allow_downstream`（預設開）：登記通過驗證的下游直接得到兩項放行（存取控制、`bypass` 清單的豁免）。這個工作包**沒有**核准名單、沒有管理 API、不存任何檔案、不加任何 `warnings`；登記表只在記憶體裡。

**要改的檔案**

- `crates/kuroshio/src/chain/grants.rs`（登記表、豁免判斷）
- `crates/kuroshio/src/chain/responder.rs`：`Name::Reg` 接上；`caps()` 加 `"reg"`；`serving_json` 加 `downstreams`
- `crates/kuroshio/src/chain/client.rs`：登記的送出（探測之後、每次心跳）；`status_json().upstream.registered`
- `crates/kuroshio/src/ipfilter.rs`：`Rules.chain`、`Reason::Downstream`、`Access::set_chain`
- `crates/kuroshio/src/filtering.rs`：`ListSource.bypass`、`verdict()` 帶出 `bypass`
- `crates/kuroshio/src/resolver.rs`：`Verdict.bypass`、過濾步驟的豁免、`store()`／`serve()` 的 CNAME 處理
- `crates/kuroshio/src/cache.rs`：`Entry.blocked_bypass`
- `crates/kuroshio/src/app.rs`：每分鐘把登記表的位址更新到 `Access`
- 新增 `crates/kuroshio/tests/chain_grants.rs`；`crates/kuroshio/tests/access.rs`、`filtering.rs` 加測試

**要新增的型別與函式**

```rust
// chain/grants.rs
pub struct Downstream { pub kid: [u8; 8], pub public: [u8; 32], pub addr: IpAddr, pub app: String,
                        pub names: Vec<String>, pub local: bool, pub expires: Instant,
                        pub first_seen_ms: u64, pub last_seen_ms: u64 }
pub struct Grants { /* allow_downstream、登記表（最多 16，只在記憶體）、登記的有效時間 */ }
impl Grants {
    pub fn new(settings: &ChainSettings) -> Arc<Grants>;
    pub fn with_ttl(settings: &ChainSettings, ttl: Duration) -> Arc<Grants>;       // 測試用
    /// 已經驗過簽章、up、peer、tok 的登記；回 RegAck 的內容。allow_downstream 關、或表滿了 → Err
    pub fn register(&self, reg: &RegBody, from: IpAddr, now: Instant, now_ms: u64) -> Result<RegAck, &'static str>;
    /// 存取控制要放行的位址（登記沒過期；allow_downstream 關著時一定是空的）
    pub fn allowed_addrs(&self, now: Instant) -> Vec<IpAddr>;
    /// 繞過防護清單的豁免（allow_downstream 開＋登記沒過期＋來源位址相同＋名稱在登記的 names 裡）
    pub fn exempt(&self, client: IpAddr, qname: &str, now: Instant) -> bool;
    pub fn sweep(&self, now: Instant);
    pub fn json(&self) -> Value;                                             // serving.downstreams
}

// responder.rs
impl Responder { pub fn exempt(&self, client: IpAddr, qname: &str) -> bool; pub fn grants(&self) -> &Arc<Grants>; }

// ipfilter.rs
pub enum Reason { /* 既有 */ Downstream }                                   // text() = "已登記的下游黑潮"
impl Access { pub fn set_chain(&self, ips: &[IpAddr]); }

// resolver.rs
pub struct Verdict { /* 既有 */ pub bypass: bool }

// client.rs
impl Client { pub async fn register(&self) -> Option<RegAck>; }             // 用 last_probe() 的 tok、peer
/// 下游要登記的主機名稱：固定、自動、備援、最後手段裡不是 IP 的主機，去重複、最多 32 個
pub fn upstream_hostnames(mgr: &Manager) -> Vec<String>;
```

**具體做法**

- 上游收登記：`Name::Reg` → 從 `query.opt` 找選項 `OPT_CODE` → `chain::open_reg()`（驗下游的簽章、`kid == kid_of(pub)`、`names`）→ `reg.up` 是自己的 kid（含輪替中的舊 kid）→ `reg.peer == ctx.client`（canonical 之後的字串）→ `token_ok(&secret, &reg.peer, now, &reg.tok)` → `grants.register()` → 回 `seal(.., "regack", ..)`。任何一步不過回 `REFUSED`。**這幾項檢查一項都不能省**：沒有核准之後，它們是「綁來源位址、防重放」唯一的保證。`allow_downstream` 關著時 `caps()` 是空的，`Name::Reg` 一律 `REFUSED`（登記表永遠是空的）。
- `register()`：同一個 `kid` 已經在表裡 → 更新位址、名稱、到期時間（`first_seen_ms` 不變）；位址換了，舊位址的放行立刻失效。同一個位址換了 `kid` → 取代那一筆（一個位址只對應一筆）。表滿 16 筆而且是新的 `kid` → `Err`（先 `sweep` 過期的再判斷）。
- 記錄：某個 `kid` 第一次登記成功、或它的位址改變時記一行 `info!`：「下游黑潮 192.168.1.2（指紋 …）已登記」。之後每 5 分鐘的更新不記。
- **不加任何 `warnings`**（預設就是開，固定的警告是噪音）。說明只在 `serving_json()` 的 `text`／`note`（WP3 已經有）；這個工作包負責讓 `downstreams` 列出每一筆的指紋、位址、版本、`firstSeen`、`lastSeen`、`viaNat`、`names`，並讓 `text` 的台數正確。
- 下游送登記：條件照規格 4.2（狀態是 `Detected` 之後的任何一個、探測得到 `allow = true` 而且 `caps` 有 `"reg"`、`chain` 開著）。這時才 `NodeKey::get()`（會建立金鑰）。`local`：`peer` 是不是 `crate::netif` 列出的本機位址之一。用 `chaos_txt(addr, REG_NAME, tcp 可用就 true, Some((OPT_CODE, sealed)), ..)`；回應用綁定（或探測到）的上游公鑰驗 `regack`。登記失敗不影響串接狀態，只記在 `status_json`。
- `ipfilter.rs`：`Rules` 加 `chain: Dual`，`build()` 多一個參數；`allows()`／`explain()` 在 `friends` 之後、`allow` 之前判斷；`Access` 加 `chain: RwLock<Dual>` 與 `set_chain`（照 `set_friends` 的寫法，位址沒變不重建）。`deny` 的順序不動。
- `app.rs`：有 `Responder` 與 `Access` 時起一個每 60 秒的工作：`grants.sweep()`、`access.set_chain(&grants.allowed_addrs())`；`Grants::register` 成功後也立刻更新一次（用 `Notify`）。
- `filtering.rs`：`ListSource` 加 `bypass`（`list_source()` 讀 `l.get("bypass")`，用 WP2 的 `flex_bool`）；`FilterCheck::check` 裡 `v.list` 對到 `self.sources[i].bypass`（注意自訂規則層沒有 `list`，`bypass` 一律 `false`）。`resolver::Verdict` 加欄位後，所有建構 `Verdict` 的地方（含測試裡的假過濾器）都要補上。
- `resolver.rs`：
  - 過濾步驟：`if v.block && !(v.bypass && self.chain.get().is_some_and(|c| c.exempt(ctx.client, &qname))) { …原本的封鎖… }`。
  - `store()`：CNAME 目標命中而且 `v.bypass` → 除了 `blocked = Some(cat)` 之外記 `blocked_bypass = Some(目標名稱)`。
  - `serve()` 加參數 `client: Option<IpAddr>`：`e.blocked` 有值、`e.blocked_bypass` 是 `Some(t)`、而且 `exempt(client, t)` → 不回封鎖，照一般答案處理。`handle_inner` 的兩個呼叫點傳 `Some(ctx.client)`；統計的 `blocked` 也要跟著不計。
- 重新載入後登記表是空的（`Grants` 跟著 `Responder` 重建），下游最慢 5 分鐘內重新登記；這段時間放行暫時失效可以接受（偏安全的那一邊）。

**要寫的測試**

`crates/kuroshio/tests/chain_grants.rs`（行程內起一個上游實例；下游用 WP1 的函式手工組登記）

| 測試 | 驗證 |
|---|---|
| `register_roundtrip_and_listed` | 預設設定（`allowDownstream` 開）：合法的登記 → `regack` 用上游公鑰驗得過；`serving.downstreams` 有一筆，含指紋、位址、`firstSeen`、`lastSeen`；`serving.text` 是「提供資料給下游黑潮：目前 1 台」 |
| `allow_downstream_off_means_no_reg` | `allowDownstream: false` → auth 的 `caps` 是空的、登記 `REFUSED`、登記表是空的、沒有任何豁免、`Access` 的下游集合是空的 |
| `register_requires_valid_token_and_peer` | `tok` 是別的來源位址算出來的、`peer` 跟實際來源不同、`tok` 過期兩個時間窗 → `REFUSED` |
| `register_requires_downstream_signature` | 簽章壞掉、`kid` 與公鑰不符、沒帶 EDNS 選項 → `REFUSED` |
| `register_signed_for_other_upstream_rejected` | `up` 是別台的 kid → `REFUSED` |
| `replayed_registration_from_other_address_rejected` | 把合法的登記封包原樣從另一個來源位址（`127.0.0.2`）重送 → `REFUSED`（`peer` 不符）；原本那一筆不受影響 |
| `unregistered_client_still_blocked` | 沒登記的來源查 `bypass` 清單上的名稱照擋 |
| `registered_downstream_bypass_exact_names_only` | 登記後：登記的名稱不擋；沒登記的名稱照擋；登記名稱的子網域照擋；被**不是** `bypass` 的清單或自訂規則命中的照擋；其他來源位址查同一個名稱照擋 |
| `self_made_downstream_is_granted_by_default` | 預設設定，用一把剛產生的金鑰登記 → 一樣被放行。**這是已決定接受的行為**（規格 T8），測試把它固定下來，並確認 `serving.downstreams` 列得出這一筆；`/api/status.warnings` **沒有**因此多出任何一筆 |
| `reload_with_allow_off_revokes` | 登記之後把 `allowDownstream` 改成 `false` 重新建立 → 豁免與存取控制的放行都沒了 |
| `bypass_exemption_expires` | 登記到期（`with_ttl` 設成 1 秒）後照擋 |
| `cname_target_on_bypass_list` | 假上游回 `a.example.com CNAME dns.example.net`，後者在 `bypass` 清單：登記了 `dns.example.net` 的下游拿到答案；另一個用戶端問同一個名稱（吃同一筆快取）被擋 |
| `registry_bounded` | 17 個不同的 kid 登記 → 第 17 個被拒；同一個 kid 換位址 → 舊位址的放行立刻失效；同一個位址換 kid → 還是一筆 |
| `registry_is_memory_only` | 登記之後快照目錄沒有因為登記多出或改動任何檔案 |

`crates/kuroshio/tests/access.rs` 加：`downstream_addr_allowed_like_friend`（`set_chain([203.0.113.5])` 之後允許、`explain` 是 `Reason::Downstream`）、`deny_beats_downstream`（同一個位址在 `access.deny` → 拒絕）、`downstream_set_only_single_addresses`（`203.0.113.6` 不允許）。

`crates/kuroshio/tests/filtering.rs` 加：`bypass_flag_reaches_verdict`（標了 `bypass` 的清單命中 → `Verdict.bypass == true`；其他清單與自訂規則 → `false`）。

**驗收**：`cargo test -p kuroshio --test chain_grants --test access --test filtering --test resolver`。

**不可以做**：不可以加核准名單、核准用的 API 或任何持久化（已決定不做）；不可以加獨立的放行開關或 `warnings`；不可以在 `allow_downstream` 關著的時候接受登記或給任何放行；不可以省略登記的任何一項檢查（簽章、`up`、`peer`、`tok`）；不可以讓 `deny` 以外的既有判斷順序改變；不可以放行網段（只能單一位址）；不可以讓豁免套用到 `bypass` 以外的清單、自訂規則，或登記以外的名稱；不可以把豁免結果寫進共用的快取狀態（快取項目只記「哪個 CNAME 目標命中 bypass 清單」，放不放行每次依來源判斷）；不可以改快取鍵。

---

## WP7　並行數與背景補問

**相依**：WP2（設定鍵）。**規格**：第 5 節。

**要改的檔案**

- `crates/kuroshio-config/src/lib.rs`：`Host.aes`、`derive_auto`、`pub fn has_aes()`
- `crates/kuroshio/src/sysinfo.rs`：`has_aes()` 改呼叫 `kuroshio_config::has_aes()`
- `crates/kuroshio/src/main.rs`：啟動說明文字（1020 行附近）
- `crates/kuroshio/src/resolver.rs`：`Params`、`ask()`、`job()`、背景補問
- `crates/kuroshio/src/stats.rs`：兩個計數
- `crates/kuroshio/tests/resolver.rs`、`forward.rs`：加測試

**要新增的型別與函式**

```rust
// kuroshio-config
pub struct Host { pub cores: usize, pub aes: bool }
pub fn has_aes() -> bool;
pub fn auto_parallel(host: &Host) -> u64;            // 規格 5.1 的表

// resolver.rs
pub struct Params { /* 既有 */ pub backfill: kuroshio_config::chain::Backfill, pub backfill_sample: u64, pub backfill_max: usize }
struct Asked { answers: Vec<Arc<Answer>>, unasked: Vec<Arc<Up>> }   // ask() 的回傳改成這個
/// 純函式：這次要不要補問
fn backfill_wanted(p: &Params, qtype: u16, verbatim: bool, unasked: usize, cdn_hit: bool, sample_tick: u64) -> bool;
/// 純函式：抽樣比對有沒有不一致（前面是正常回應、補問的多數是 NXDOMAIN / NODATA，或反過來）
fn backfill_mismatch(first: &[Arc<Answer>], more: &[Arc<Answer>]) -> bool;
```

**具體做法**

- `Host { cores }` 的建構點全部補上 `aes`（`Host::detect()`、`lib.rs` 的測試、其他 crate 若有）。`derive_auto` 的 `resolver.parallel` 改呼叫 `auto_parallel`。
- `ask()`：回傳多帶「這次沒有被 spawn 的上游」（`rest` 迭代器剩下的）。既有呼叫點（`job()` 的兩處）跟著改；行為不變。
- `job()`：在 `self.notify(&key, &e, true)` 與 `std::mem::forget(guard)` **之後**判斷補問。條件用 `backfill_wanted`；`cdn_hit` ＝ `cdn` 存在而且 `logic::ips_of(&d.msg, qtype)` 裡有任何一個讓 `cdn.classify(ip)` 回 `Some`；`sample_tick` 用一個新的 `AtomicU32`（不要跟 `picks` 共用）。
- 補問本身：`tokio::spawn`；用 `Arc<tokio::sync::Semaphore>`（`backfill_max` 個）的 `try_acquire_owned()`，拿不到就不做；記憶體壓力不是 `Normal` 不做（`crate::app::pressure()`）。在 task 裡：`self.ask(&unasked, &upq, qtype, |_| {})`（這裡要讓 `ask` 把傳進來的全部一起問：呼叫時暫時不套 `parallel`，給 `ask` 加一個 `all: bool` 參數）→ 把第一輪的 `results` 與新的合在一起 → `decide()` → A／AAAA 而且 `rank_ips` 時 `merge_rank()` → `store()`。**不呼叫 `notify`**（沒有人在等）。
- 抽樣比對：`backfill_mismatch` 為真時 `stats.count` 新的計數，並記 `debug!`。
- `backfill_max`：`Params::from_cfg` 依 `kuroshio_config::Host::detect().cores` 決定（≤ 2 → 2，其他 4）。
- 串接中 `active()` 只有一台，`unasked` 是空的，自然不補問（不用特別處理，但要有測試）。

**要寫的測試**

| 測試（位置） | 驗證 |
|---|---|
| `auto_parallel_table`（`kuroshio-config`） | 規格 5.1 的每一列；填了數字（含 0、字串 `"0"`）不被改 |
| `parallel_two_backfills_cdn_names`（`tests/resolver.rs`） | 4 個假上游、`parallel = 2`、假的 CDN 讓答案的位址被認得：用戶端在前 2 個回答後就收到回應（量時間，< 慢的那兩個的延遲）；稍後另外兩個上游各收到 1 筆查詢；快取裡的答案包含後來的位址 |
| `non_cdn_names_sampled`（同上） | `backfillSample = 4`：16 個不同的非 CDN 名稱，後段上游收到的查詢數是 4（±0） |
| `backfill_off_matches_3_3_7`（同上） | `backfill = "off"`：後段上游完全沒有收到查詢 |
| `backfill_mismatch_fixes_cache`（同上） | 前 2 個上游回 NXDOMAIN、後 3 個回位址（抽到樣本時）→ 計數加 1、之後的查詢拿到位址 |
| `backfill_respects_concurrency_cap`（同上） | 後段上游各延遲 500 ms、同時發 20 個不同的 CDN 名稱 → 同時進行的補問不超過 `backfill_max` |
| `backfill_skips_verbatim`（同上） | 帶 DO 的查詢不補問 |
| `parallel_limit_prefers_fastest_upstream`、`parallel_two_asks_two_upstreams_then_hedges` | 既有的兩個測試不改而且照過 |

**驗收**：`cargo test -p kuroshio-config`；`cargo test -p kuroshio --test resolver --test forward`；在 x86 開發機上 `kuroshio sysinfo` 顯示有 AES、`resolver.parallel` 的 auto 值不變。

**不可以做**：不可以讓補問延後用戶端的回應（補問一定在 `notify` 之後）；不可以排隊（拿不到名額就放棄）；不可以改 `parallel = 0` 與使用者填數字時的行為；不可以改 `resolver.parallel` 在 `defaults.json` 的預設值（`"auto"`）。

---

## WP8　上游多樣性（`coverage_region`）

**相依**：WP2（設定鍵）。**規格**：第 6 節。

**要改的檔案**

- `crates/kuroshio-jobs/src/benchmark/select.rs`：`Scored`、`SelectOpts`、`select()`、`final_csv()`
- `crates/kuroshio-jobs/src/benchmark/rules.rs`：`AsnInfo.cc`
- `crates/kuroshio-jobs/src/benchmark/probe.rs`：ip-api 的 `fields` 加 `countryCode`
- `crates/kuroshio-jobs/src/benchmark/mod.rs`：`select_opts()`、Phase 2 填 `region`／`near`、`upstreams.json` 的輸出、記錄
- `crates/kuroshio/src/benchjob.rs`：把台灣網段（`TwIp`）交給評測
- `crates/kuroshio/src/upstreams.rs`：`Up` 的 `region`（從 `selected[].region` 讀）、`json()` 輸出
- `crates/kuroshio/tests/bench.rs`、`select.rs` 的單元測試

**要新增的型別與函式**

```rust
// select.rs
pub struct Scored { /* 既有 */ pub region: String, pub near: bool }
pub struct SelectOpts { /* 既有 */ pub near_first: bool }                      // coverage_region == near
pub const NEAR_REGIONS: [&str; 4] = ["TW", "JP", "HK", "SG"];
/// 純函式：規格 6.1 的判斷
pub fn classify_region(in_tw: bool, cc: &str, min_ms: f64, near_max_ms: f64) -> (String, bool);

// rules.rs
pub struct AsnInfo { pub raw: String, pub keywords: Vec<String>, pub cc: String }   // to_json / from_json 多一個選用的 "cc"
```

**具體做法**

- `AsnInfo::from_ip_api` 多一個參數 `country_code: &str`；`from_json` 沒有 `"cc"` 時是空字串（舊的 `cidr_cache.json` 照樣讀得進來）；`to_json` 在 `cc` 不是空的時才寫（2.x 相容的兩個鍵不動）。`AsnInfo { .. }` 的建構點全部補上。
- `AsnCache::lookup`：快取裡有這個 /16 但 `cc` 是空的，而且這次查的是決選的上游位址（Phase 2 的那一次呼叫）→ 當成沒查過、重查一次；用一個 `HashSet` 記這次執行已經補查過的，查不到也不重複查。汙染判斷那邊的查詢（量很大）**不補查**：`lookup` 加一個參數 `want_cc: bool`。
- 台灣網段：`BenchPaths`（或 `Benchmark` 的建構參數）加 `tw: Option<Arc<kuroshio_jobs::geo::TwIp>>`，`benchjob.rs` 讀唯讀資料目錄的 `geo/tw-ip.json`（讀不到是 `None`，不影響評測）。評測在子程序跑，資料檔要在子程序裡自己讀（約 41 KB）。
- Phase 2：`all[i].scored(owner)` 之後填 `region`、`near`：`classify_region(tw.contains(ip), &cc, s.min, near_max_ms)`。`min == 0`（沒有成功紀錄）當成不鄰近。
- `select()`：`near_first` 時把「覆蓋」階段跑兩輪（先 `rest` 裡 `near` 的，再其餘的），第二輪的 `pre` 是第一輪結束時的 `covered`；兩輪共用台數上限與覆蓋率的停止條件。`near_first == false` 時跟現在一模一樣（用既有測試守著）。
- 輸出：`selected[]` 每筆加 `"region"`、`"near"`；`final_csv` 最後加兩欄；記錄加一行「覆蓋：鄰近 N 台、其他 M 台」。`Manager::reload_auto` 讀 `region`（沒有是 `None`），`Up::json()` 加 `"region"`。

**要寫的測試**

| 測試 | 驗證 |
|---|---|
| `classify_region_rules` | 在台灣網段 → `("TW", true)`；`cc = "JP"`、`min = 45` → near；`cc = "JP"`、`min = 130` → 不是（超過 2 倍）；`cc = "AU"`、`min = 4`（任播）→ near；`cc = ""`、`min = 80` → 不是；`min = 0` → 不是 |
| `near_candidates_picked_before_far` | 兩個覆蓋量相同的候選，一近一遠 → 選近的；遠的覆蓋量較大但近的也有新增 → 先近的 |
| `far_used_when_near_cannot_reach_target` | 近的候選用完還沒達標而且有名額 → 補遠的 |
| `any_matches_previous_selection` | `near_first = false` 的結果跟改動前的 `select()` 對同一組輸入逐項相同（把現有測試的預期值固定下來） |
| `asn_cache_reads_old_format_and_backfills_cc` | 沒有 `cc` 的快取讀得進來；`want_cc` 時對決選位址補查一次、同一次執行不重複；查不到時 `cc` 是空的、選擇照常 |
| `upstreams_json_has_region`（`tests/bench.rs`） | 假的 ip-api 回 `countryCode`；輸出的 `selected[].region`、`near` 正確；`final_dns_smart.csv` 的表頭最後兩欄是 `Region,Near` |
| `ip_api_offline_still_selects`（同上） | 假的 ip-api 不回應 → 評測照常完成，`region` 只來自台灣網段與延遲 |

**驗收**：`cargo test -p kuroshio-jobs`；`cargo test -p kuroshio --test bench --test benchjob`。

**不可以做**：不可以加入新的外部查詢服務或隨程式附帶新的 geo 資料庫；不可以整批重查 `cidr_cache.json`；不可以改 `reason` 的文字（最快、覆蓋、備援）；不可以改 CSV 既有欄位的順序；不可以讓 ip-api 查不到時評測失敗。

---

## WP9　介面與文件

**相依**：WP2（設定欄位已經在）；狀態畫面依 WP4、WP5、WP6 的 API（可以先照規格的 JSON 範例做）。**規格**：1.10、3.7、4.5。

**要改的檔案**

- `openwrt/luci-app-kuroshio/htdocs/luci-static/resources/view/kuroshio_ui/status.js`（下游角色的串接狀態、上游角色的區塊與「連上來的下游」清單）
- `data/admin/app.js`（同樣的內容）；`data/shared/ui-core.js` 與 `ui-core.tests.json`（共用的文字組合函式）
- `docs/integration.md`：新增「串接模式（3.4.0 起）」一節（設定表、`/api/status.chain` 的 JSON、管理 API、`kuroshio chain` 指令、相容表、測試用環境變數註明「不是穩定介面」）；路徑檢查一節補 `interceptor.chain`；小記憶體一節補共用結果
- `docs/spec/README.md`：索引加第 10 篇
- 新增 `docs/release-notes/v3.4.0.md`
- `tools/admin-e2e.js`：加串接畫面的案例

**具體做法**

- 文字直接用 API 給的 `chain.text`（下游角色）與 `chain.serving.text`、`chain.serving.note`（上游角色），前端不自己拼句子。**沒有任何按鈕**（沒有同意、沒有核准）；兩個區塊都一定顯示，讓兩邊都看得出目前是哪一種情況與原因：
  - 下游角色：`text`；`chained` 時另外顯示上游指紋、`backupActive`、共用結果各種類的時間與略過的工作；`keyChangedAt` 在 24 小時內時顯示新舊指紋。`released`／`not-allowed` 與 `chain` 關著時，`text` 裡「會重複使用網路」那句要完整顯示，不可以截斷。
  - 上游角色：`serving.text`、自己的指紋、「連上來的下游」清單（指紋、位址、版本、第一次與最後出現時間、「經 NAT」）。`allowDownstream` 關著時顯示「不提供資料…重複使用網路（含這台的頻寬）」那句；開著時用一般樣式顯示 `note`。
- `upstreams[]` 的 `role == "chain"` 顯示成「串接」；`region` 有值時顯示在原因旁邊。
- `ui-core.js` 加一個把 `chain` 物件轉成顯示資料的純函式，`ui-core.tests.json` 加案例（五種狀態、每個 `reason`、`chain` 關著的兩種情況、`viaNat`、`backupActive`、公鑰換過、上游角色開／關／有下游）。

**要寫的測試**：`ui-core.tests.json` 的案例（至少 16 筆，涵蓋上面列的）；`tools/admin-e2e.js` 加三個畫面案例（用假的 `/api/status` 回應）：「串接中」、「上游不提供資料（allow_downstream 關閉）…會重複使用網路」、「上游角色：allow_downstream 關閉的說明與開著時的下游清單」。

**驗收**：`node tools/admin-e2e.js`；`node tools/ui-core-test.js`（跑 `ui-core.tests.json`）；人工在 LuCI 與 Windows 設定頁各看一次規格 1.10 對照表的每一種情況與上游角色的開／關（用 `KUROSHIO_PATH_TARGETS` 接到本機的第二個實例）。

**不可以做**：不可以在前端自己判斷狀態轉移或拼接上游位址；不可以在畫面上顯示完整的公鑰以外的任何金鑰資料；文件與截圖裡不可以有個人網域或真實的對外位址。

---

## WP10　重新載入不斷線（選做）

**相依**：無。**規格**：第 7 節。來不及就整包延到 3.4.1，不影響其他工作包。

**要改的檔案**

- 新增 `crates/kuroshio/src/listenbank.rs`；`lib.rs` 加模組
- `crates/kuroshio/src/server.rs`（`Server::listen` 的綁定）、`crates/kuroshio/src/encrypted.rs`（DoT／DoH 的 TCP 監聽、QUIC 的 UDP socket）、`crates/kuroshio/src/netif.rs`（`bind_tcp`／`bind_udp` 的呼叫點）、`crates/kuroshio/src/app.rs`（啟動完成後呼叫 `sweep`）
- `crates/kuroshio/tests/integration.rs`：加測試

**要新增的型別與函式**

```rust
pub enum Proto { Udp, Tcp }
/// 拿這個位址的監聽 socket 的複製品；沒有就用 `bind` 綁一個、留一份在表裡。port 0 不進表（直接綁）
pub fn udp(tag: &'static str, addr: SocketAddr, bind: impl FnOnce() -> io::Result<std::net::UdpSocket>) -> io::Result<std::net::UdpSocket>;
pub fn tcp(tag: &'static str, addr: SocketAddr, bind: impl FnOnce() -> io::Result<std::net::TcpListener>) -> io::Result<std::net::TcpListener>;
/// 新的一輪開始：把「這一輪用過」的記號清掉
pub fn begin();
/// 新的一輪啟動完成：關掉這一輪沒有人拿的
pub fn sweep() -> usize;
pub fn len() -> usize;
```

**具體做法**

- 表是 `static BANK: Mutex<HashMap<(&'static str, Proto, SocketAddr), Entry>>`，`Entry { sock, used: bool }`。`udp()`／`tcp()` 回 `try_clone()` 的結果；`try_clone` 失敗時退回直接綁定（等同現在的行為）並記警告。
- `Server::listen`：`addr.port() != 0` 時 UDP 與 TCP 各自經過 `listenbank`（`bind` 參數就是現有的 `bind_socket(..)`，TCP 的 `listen(256)` 要在放進表之前做）。port 0 的重試邏輯不動。
- 每一輪 `start()` 開頭 `listenbank::begin()`，全部監聽建立之後 `listenbank::sweep()`。啟動失敗時不 sweep（下一輪還用得到）。
- Windows：`std` 的 `try_clone` 可以用；HTTP.sys 模式不經過這裡。
- QUIC：如果 quinn 的 `Endpoint` 建在複製的 socket 上有問題，就只做 UDP／TCP 53 與 DoT／DoH 的 TCP，QUIC 維持現狀，並在 PR 說明。

**要寫的測試**

| 測試 | 驗證 |
|---|---|
| `bank_reuses_and_sweeps`（單元） | 同一個鍵拿兩次是同一個核心 socket（本機位址相同）；`begin` 後沒人拿的在 `sweep` 被關掉、埠可以重新綁定；port 0 不進表 |
| `reload_never_refuses`（`tests/integration.rs`，子程序） | 服務在跑的時候用兩條執行緒連續發 UDP 查詢與新的 TCP 連線（每 5 ms 一次），期間送 3 次 SIGHUP：沒有任何一次 `ECONNREFUSED`；UDP 查詢在一次重送（2 秒）內都有回應；重新載入後答案正確 |
| `reload_with_changed_port_closes_old`（同上） | 改了監聽埠重新載入：舊的埠在啟動完成後連不上、新的埠可以 |
| `failed_reload_keeps_sockets`（同上） | 給一份啟動不了的設定：服務用上一份設定繼續跑，期間同樣沒有拒絕連線 |

**驗收**：`cargo test -p kuroshio --lib listenbank`；`cargo test -p kuroshio --test integration reload_`；在 OpenWrt 實機上 `while true; do dig +tries=1 +time=1 @192.168.1.1 example.com >/dev/null || echo FAIL; done` 期間 `kill -HUP`，沒有 `FAIL`。

**不可以做**：不可以讓兩輪 runtime 同時存在；不可以用 `SO_REUSEPORT`；不可以改 port 0（測試）時的綁定行為；不可以讓表無限長大（設定換位址後舊的一定要在 `sweep` 關掉）。

---

## 整合測試計畫（WP3～WP6 合併後；由 WP4 的負責人撰寫，其他人協助）

**檔案**：新增 `crates/kuroshio/tests/chain_e2e.rs`。用 `tests/integration.rs` 現有的做法起**兩個子程序**（真正的執行檔，各自的設定檔、快照目錄、金鑰目錄、不同的埠）；路徑檢查與串接的狀態是行程層級的，不能把兩台放在同一個行程裡。

### 模擬 DNAT

真實環境裡，下游對 `192.0.2.1:53` 的查詢被上游路由器 DNAT 到上游黑潮。對下游來說，DNAT 的效果就是「對保留位址的查詢由上游黑潮回答」，所以測試用 `KUROSHIO_PATH_TARGETS` 把下游的保留位址直接換成上游的監聽位址：

```
上游 U：listen.plain = 127.0.0.1:PU，admin = 127.0.0.1:AU，upstream.pinned = [假的公開 DNS]
下游 D：listen.plain = 127.0.0.1:PD，admin = 127.0.0.1:AD，
        upstream.pinned = []，upstream.fallback = [假的「加密上游」替身（另一個本機假 DNS，回不同的答案）]
        環境變數 KUROSHIO_PATH_TARGETS={"testnetV4":["127.0.0.1:PU"],"gateway":null,"encrypted":false}
                 KUROSHIO_CHAIN_TIMING={"heartbeat":1500,"earlyMin":200,"earlyMax":400,"retryMin":500,"retryMax":2000}
```

- 上游看到的來源是 `127.0.0.1`（`is_private_client` 為真、在預設的 `allowFrom` 裡）。
- 假的公開 DNS 對每個名稱回固定位址 `198.51.100.10`；下游的替身回 `198.51.100.20`，這樣從答案就看得出查詢走哪一條。
- 每個案例開始先 `POST /api/chain/recheck`（不等路徑檢查啟動後的 8 秒），再輪詢 `/api/chain` 到預期的狀態（最多 15 秒）。
- 冒充者：一個本機假 DNS，回 `version.kuroshio = kuroshio/3.4.0`，auth 的回答可以設定成「別的金鑰」「重放錄下來的回應」「簽章壞掉」。

### 案例

（除非另外寫，U 與 D 都用預設值：`allowDownstream` 開、`chain` 開。）

| 案例 | 步驟 | 預期 |
|---|---|---|
| `e2e_both_on_chains_automatically` | 預設設定 | 不做任何操作，D 到 `chained`，`text` 以「串接中：上游」開頭，`upstream.fingerprint` 等於 U 的 `serving.fingerprint`；對 D 查詢得到 `198.51.100.10`；`upstreams[0].role == "chain"`；U 的 `serving.downstreams` 有 D |
| `e2e_downstream_chain_off` | D 設 `chain: false` | D 是 `none`、`enabled == false`，`text` 是「已關閉串接（chain 關閉）：把上游黑潮當成一般的 DNS 攔截，自己做評測，會重複使用網路」；U（改用會記錄查詢的假上游黑潮驗證）沒有收到任何 `chain.kuroshio` 查詢；D 的解析走替身（`198.51.100.20`）；`network.path` 跟 3.3.7 一樣有「一般 DNS 被…接走」的提醒 |
| `e2e_upstream_allow_off` | U 設 `allowDownstream: false` | D 是 `released`／`not-allowed`，`text` 是「上游黑潮 … 不提供資料（allow_downstream 關閉）：自己做評測，會重複使用網路」；D 的解析走替身；D 的 `shared` 沒有任何物件、`dns-benchmark` 沒有被略過；U 的 `serving.text` 含「不提供資料給下游」與「重複」、`serving.probes.count24h >= 1`、`downstreams` 是空的；`kuroshio check-path`（對 D 的設定）輸出「上游不提供資料」 |
| `e2e_both_off` | 兩邊都關 | D 同 `e2e_downstream_chain_off`；U 的 `serving.probes.count24h == 0` |
| `e2e_upstream_3_3_x` | 上游換成假伺服器，只回答 `version.kuroshio = kuroshio/3.3.7` 並記錄所有查詢 | D 是 `released`／`upstream-too-old`；假伺服器沒有收到任何 `chain.kuroshio` 查詢；D 的解析照常（`198.51.100.20`） |
| `e2e_not_kuroshio` | 上游換成只回答 `version.bind` 的假伺服器 | `none`；沒有 `chain.kuroshio` 查詢 |
| `e2e_impostor_rejected` | D 的保留位址指到冒充者（簽章壞掉、重放錄下來的回應、公鑰與 `kid` 不符，各跑一次） | 都是 `released`／`verify-failed`；D 的 `upstreams` 沒有串接上游 |
| `e2e_upstream_swapped_rebinds_with_warning` | D 串接 U 之後，把 U 停掉，在同一個埠起另一台（新的金鑰目錄） | D 自動重新 `chained`（新的指紋）；`upstream.previousFingerprint` 是舊的；`/api/status.warnings` 有一筆「上游節點的金鑰換過」 |
| `e2e_upstream_down_falls_back_to_encrypted` | 串接後停掉 U | 幾秒內 `released`／`no-response`；查詢得到 `198.51.100.20`（自己的上游）；重新啟動 U（同一把金鑰）後自動回到 `chained`，沒有金鑰換過的警告 |
| `e2e_wan_changed` | 串接後 `kuroshio notify wan-changed` | 立刻離開 `chained`，路徑檢查後自動重新 `chained` |
| `e2e_loop_a_b_a` | 兩台互指：A 的保留位址指到 B、B 的指到 A | 15 秒後不會兩台都是 `chained`；至少一台的 `reason` 是 `loop`；期間對任一台的查詢最慢在 `timeoutMs` 加一點內得到回應（不會卡死） |
| `e2e_three_layers` | A ← B ← C（C 的保留位址指到 B、B 的指到 A） | C 的 `upstream.path` 長度是 2、`depth` 是 3；查詢經 B 到 A |
| `e2e_reload_keeps_chain` | 串接後對 D 送 SIGHUP | 重新載入後 `/api/chain` 立刻是 `chained` |
| `e2e_reload_turns_chain_off` | 串接後把 D 的設定改成 `chain: false` 再 SIGHUP | D 回到 `none`、解析走替身；之後 U 的 `serving.downstreams` 在登記到期後清掉 D |
| `e2e_share` | U 的快照目錄預先放 `upstreams.json`（有 `generatedAt`）與節點池 | D 的 `shared.objects` 有 `upstreams`、`cdn-pools` 而且 `fresh`；D 的 `upstreams.json` 有 `source.chain`；`POST /api/jobs/run?name=dns-benchmark` 之後工作狀態是「由上游黑潮提供，略過」 |
| `e2e_share_falls_back` | U 沒有評測資料 | D 的 `shared.objects` 沒有 `upstreams`；`dns-benchmark` 沒有被略過 |
| `e2e_bypass_exemption` | U：自訂一份標成 `bypass` 的清單（本機檔案，內容 `\|\|dns.example.net^`）；D 的固定上游裡有 `tls://dns.example.net`（指不到也沒關係） | D 登記成功後，D 的來源問 `dns.example.net` 不擋；另一個來源位址（`127.0.0.2`）照擋。U 改成 `allowDownstream: false` 重新載入後 D 也被擋 |
| `e2e_3_3_downstream_unaffected` | 用假的「3.3 下游」行為：只發 `version.kuroshio` 與一般查詢 | U 的回答跟 3.3.7 的格式相同 |

### 執行

```
cargo build -p kuroshio
cargo test -p kuroshio --test chain_e2e -- --test-threads=1
```

（每個案例起兩到三個子程序，循序跑；整個檔案預期 3 分鐘內。）

### 實機驗收（發行前，人工）

1. 主路由器（OpenWrt，黑潮 3.4.0，積極劫持 53 埠）＋ Newifi D3（黑潮 3.4.0）接在它的 LAN。
2. 不做任何設定，D3 的狀態頁在一兩分鐘內顯示「串接中：上游 192.168.1.1（黑潮 3.4.0）…」，指紋跟主路由器狀態頁顯示的相同；主路由器的狀態頁「連上來的下游」列出 D3。
3. D3 的 `kuroshio check-path` 有「串接：上游允許串接」。
4. 隔天確認 D3 的 `dns-benchmark`、`cdn-pool` 顯示「由上游黑潮提供，略過」，`top` 看不到評測的子程序。
5. 主路由器 `/etc/init.d/kuroshio stop`：D3 在 10 秒內改用自己的加密上游，區網裝置照常上網；重新啟動後自動接回。
6. 拔掉 D3 的 WAN 線接到另一台不是黑潮的路由器：D3 回到未偵測，行為跟 3.3.7 一樣。
7. 主路由器降回 3.3.7：D3 顯示「上游黑潮 3.3.7 不支援串接」，兩台都正常。
8. 主路由器關掉 `allow_downstream`：D3 顯示「上游黑潮 3.4.0 不提供資料（allow_downstream 關閉）：自己做評測，會重複使用網路」，主路由器顯示「不提供資料給下游…」；再打開後自動接回。D3 關掉 `chain`：顯示「已關閉串接…」，主路由器看不到 D3。
9. 記憶體：D3（512 MB）與一台 128 MB 的機器各跑 24 小時，比較串接前後的 RSS 尖峰（同步共用結果時不應高出 4 MB 以上）。
