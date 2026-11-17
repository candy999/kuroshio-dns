//! 過濾服務：自訂規則與訂閱清單分成兩份過濾器（規格 05 第 3.2 節、2.x 的 filter.js）
//!
//! - 自訂規則永遠先比對，命中就不看清單（2.x「自訂規則是最高原則」）
//! - 自訂規則檔存檔後 3 秒內生效，不必重新下載清單
//! - 清單邊下載邊解析；任何一份下載失敗就保留舊的過濾器（第一次載入除外），30 分鐘後重試
//! - 清單都沒變（全部 304）就不重建；有變就整個重建，建好才替換（尖峰 = 新舊兩份並存）
//! - 記憶體控制（規格 09）：記憶體不足時可以暫時停用優先順序最低的清單（重建一份不含它的過濾器），
//!   恢復時重新下載。自訂規則與標成「保護」（`protect`，惡意 / 反詐騙預設是）的清單絕不停用。
//!   停用中的清單在狀態裡列得清清楚楚（`unloaded`、`notice`）。
//! - 每份清單的命中次數（`hits`）經快照寫入器保存，停用順序會參考它
//! - 本機副本（規格 05 第 5.6 節）：儲存空間在保留量 + 遲滯以上、記憶體也還能長大時，下載的清單壓縮後留一份在
//!   `filter-lists/`（可省略類，空間不足時最先刪）。內容沒變不重寫；經快照寫入器寫，照樣受寫入間隔與每日寫入量限制。
//!   開機先用副本建好過濾器（不必等下載）、記憶體控制停用 / 恢復清單時也用副本；下載失敗時拿副本頂著

use crate::fetch::{self, Outcome, Validators};
use crate::resolver::{FilterCheck, Verdict};
use kuroshio_filter::{BuildOptions, Category, Filter, FilterBuilder, ListSpec, SourceStatus};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::hash::Hasher;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, SystemTime};
use tracing::{info, warn};

/// 安裝時附帶的預設自訂規則（設定的自訂規則檔不存在時寫出這份）
pub const DEFAULT_CUSTOM_RULES: &str = include_str!("../../../rules/default-custom-rules.txt");

/// 這個版本的預設自訂規則：唯讀資料目錄（OpenWrt 是 `/usr/share/kuroshio`）有 `default-custom-rules.txt` 就用它，
/// 沒有（或讀不出來、是空的）就用執行檔內建的 [`DEFAULT_CUSTOM_RULES`]。回傳（內容, 來源檔案；內建 = None）
pub fn default_custom_rules(share_dir: &Path) -> (String, Option<PathBuf>) {
    let p = share_dir.join("default-custom-rules.txt");
    match std::fs::read(&p).ok().and_then(|b| String::from_utf8(b).ok()) {
        Some(t) if !t.trim().is_empty() => (t, Some(p)),
        _ => (DEFAULT_CUSTOM_RULES.to_string(), None),
    }
}

/// 把自訂規則檔換回預設規則（設定頁的「恢復預設自訂規則」）：原本的內容先複製到同一個資料夾的 `<檔名>.bak`
/// （已經跟預設一樣時不動檔案、也不覆蓋上一次的備份）。回傳 JSON：`{ok, changed, file, backup, source, bytes}`
pub fn reset_custom_rules(file: &Path, share_dir: &Path) -> std::io::Result<Value> {
    let (text, src) = default_custom_rules(share_dir);
    let source = src.map(|p| p.display().to_string()).unwrap_or_else(|| "builtin".into());
    let old = match std::fs::read(file) {
        Ok(b) => Some(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    // 換行不同（記事本存成 CRLF）也算一樣
    let same = old
        .as_deref()
        .is_some_and(|b| String::from_utf8_lossy(b).replace("\r\n", "\n").trim_end() == text.replace("\r\n", "\n").trim_end());
    if same {
        return Ok(json!({ "ok": true, "changed": false, "file": file, "backup": null, "source": source, "bytes": text.len() }));
    }
    let mut bak_name = file
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| "custom-rules.txt".into());
    bak_name.push(".bak");
    let backup = match &old {
        Some(b) => {
            let bak = file.with_file_name(bak_name);
            crate::persist::write_atomic(&bak, b)?;
            Some(bak)
        }
        None => {
            if let Some(dir) = file.parent() {
                std::fs::create_dir_all(dir)?;
            }
            None
        }
    };
    crate::persist::write_atomic(file, text.as_bytes())?;
    info!(
        "自訂規則已恢復成預設（{source}）{}",
        backup
            .as_ref()
            .map(|b| format!("，原本的內容備份在 {}", b.display()))
            .unwrap_or_default()
    );
    Ok(json!({ "ok": true, "changed": true, "file": file, "backup": backup, "source": source, "bytes": text.len() }))
}

/// 各清單命中次數的快照檔
pub const HITS_FILE: &str = "filter-hits.json";

/// 每條網域規則大約佔多少記憶體（8 bytes 雜湊 + 1 byte 分類，加上建置後的零頭）：沒量過的清單用它估
pub const BYTES_PER_DOMAIN: u64 = 9;

#[derive(Debug, Clone)]
pub struct ListSource {
    pub url: String,
    pub name: String,
    pub category: Category,
    /// 保護清單：記憶體不足時也不停用（設定 `filter.lists[].protect`；沒寫時惡意 / 反詐騙類是 true）
    pub protect: bool,
}

/// 暫時停用的清單
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unloaded {
    /// 在 `sources` 裡的位置
    pub idx: usize,
    pub name: String,
    /// 停用前的規則數
    pub rules: u64,
    /// 停用釋出的記憶體（實測：重建前後過濾器大小的差；恢復時要有這麼多空間的 1.3 倍）
    pub bytes: u64,
    /// `memory` = 記憶體控制停用；`budget` = 載入前估計會超過記憶體預算，沒有載入
    pub reason: &'static str,
    /// 停用的時間（Unix 毫秒）
    pub at: u64,
}

/// 記憶體預算：清單層最多可以用多少 bytes（記憶體控制提供；None = 不限制）
pub type AllowanceFn = Arc<dyn Fn() -> Option<u64> + Send + Sync>;

/// 本機副本的索引檔
pub const COPY_INDEX: &str = "filter-lists/index.json";

/// 重建時清單從哪裡來
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    /// 下載（`reuse[i]` = 剛問過沒變、而且有本機副本的直接讀副本；下載失敗拿副本頂著）
    Download,
    /// 有本機副本就用副本，沒有才下載（記憶體控制停用 / 恢復清單）
    PreferCopy,
    /// 只用本機副本：沒有副本的這次不載入（開機時：不必等對時、等下載）
    CopiesOnly,
}

/// 建置中每條網域規則約佔多少記憶體（建好後壓縮成約 9 bytes）：重建的尖峰要算進去
pub const BUILD_BYTES_PER_RULE: u64 = 16;
/// 規則數掉到上次的一半以下、而且上次至少這麼多條：當成下載被截斷，不換上
const DROP_CHECK_MIN_RULES: u64 = 1000;
/// 第一次載入（或更新）有清單下載失敗時的重試間隔：1、2、5 分鐘，之後每 30 分鐘
const RETRY_BACKOFF: [u64; 4] = [60, 120, 300, 1800];

/// 新下載的規則數比上次少一大半：多半是連線中途斷掉、沒有長度資訊的回應被當成完整（回傳說明）
fn suspicious_drop(prev: u64, now: u64) -> Option<String> {
    (prev >= DROP_CHECK_MIN_RULES && now.saturating_mul(2) < prev).then(|| format!("規則數從 {prev} 條掉到 {now} 條，可能下載不完整"))
}

/// 一份副本的紀錄
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyMeta {
    /// 快照名稱（`filter-lists/<網址雜湊>.txt.zst`，內容已經是 zstd）
    pub file: String,
    /// 原始內容的雜湊（內容沒變就不重寫）
    pub hash: u64,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    /// 壓縮後大小
    pub bytes: u64,
    /// 存的時間（Unix 秒）
    pub at: u64,
    /// 這份清單的規則數（開機時估記憶體、檢查新下載的有沒有少一大半；舊版的索引沒有是 0）
    pub rules: u64,
}

/// 過濾清單的本機副本（可省略的資料：空間大方時才留）
pub struct ListCopies {
    pub persister: Arc<Mutex<crate::persist::Persister>>,
    index: Mutex<HashMap<String, CopyMeta>>,
}

fn url_id(url: &str) -> String {
    // FNV-1a：穩定、不同平台一樣
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in url.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    format!("filter-lists/{h:016x}.txt.zst")
}

/// 下載時邊算內容雜湊、（空間夠時）邊壓縮
pub struct CopySink {
    h: std::collections::hash_map::DefaultHasher,
    n: u64,
    enc: Option<zstd::stream::write::Encoder<'static, Vec<u8>>>,
}

impl CopySink {
    pub fn new(keep: bool) -> CopySink {
        CopySink {
            h: Default::default(),
            n: 0,
            enc: keep.then(|| kuroshio_cdn::statefile::encoder(Vec::new()).ok()).flatten(),
        }
    }
    pub fn feed(&mut self, c: &[u8]) {
        use std::io::Write;
        self.h.write(c);
        self.n += c.len() as u64;
        if let Some(e) = &mut self.enc {
            if e.write_all(c).is_err() {
                self.enc = None;
            }
        }
    }
    /// （內容雜湊，壓縮後的內容）
    pub fn finish(self) -> (u64, Option<Vec<u8>>) {
        let mut h = self.h;
        h.write_u64(self.n);
        (h.finish(), self.enc.and_then(|e| e.finish().ok()))
    }
}

impl ListCopies {
    pub fn new(persister: Arc<Mutex<crate::persist::Persister>>) -> ListCopies {
        let mut index = HashMap::new();
        if let Some(b) = persister.lock().unwrap().load(COPY_INDEX) {
            if let Ok(Value::Object(m)) = serde_json::from_slice::<Value>(&b) {
                for (url, v) in m {
                    let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
                    let n = |k: &str| v.get(k).and_then(Value::as_u64).unwrap_or(0);
                    let Some(hash) = s("hash").and_then(|h| u64::from_str_radix(&h, 16).ok()) else {
                        continue;
                    };
                    index.insert(
                        url.clone(),
                        CopyMeta {
                            file: url_id(&url),
                            hash,
                            etag: s("etag"),
                            last_modified: s("lastModified"),
                            bytes: n("bytes"),
                            at: n("at"),
                            rules: n("rules"),
                        },
                    );
                }
            }
        }
        ListCopies {
            persister,
            index: Mutex::new(index),
        }
    }

    /// 現在要不要留副本（空間在保留 + 遲滯以上、記憶體還能長大）；`estimate` = 估計的壓縮後大小
    pub fn wanted(&self, estimate: u64) -> bool {
        crate::memgov::growth_allowed() && self.persister.lock().unwrap().has_room_for_optional(estimate)
    }

    pub fn meta(&self, url: &str) -> Option<CopyMeta> {
        self.index.lock().unwrap().get(url).cloned()
    }

    /// 副本在磁碟上（或還在等寫出）
    pub fn available(&self, url: &str) -> bool {
        let Some(m) = self.meta(url) else { return false };
        let p = self.persister.lock().unwrap();
        p.is_pending(&m.file) || p.file_path(&m.file).exists()
    }

    /// 讀副本（解壓後一段一段交給 `feed`）。回傳有沒有讀到
    pub fn read(&self, url: &str, feed: &mut dyn FnMut(&[u8])) -> bool {
        let Some(m) = self.meta(url) else { return false };
        let path = self.persister.lock().unwrap().file_path(&m.file);
        let Ok(f) = std::fs::File::open(&path) else { return false };
        let Ok(mut dec) = zstd::stream::read::Decoder::new(f) else {
            return false;
        };
        let mut buf = vec![0u8; 64 * 1024];
        let mut h = std::collections::hash_map::DefaultHasher::new();
        let mut n = 0u64;
        loop {
            match dec.read(&mut buf) {
                Ok(0) => break,
                Ok(k) => {
                    h.write(&buf[..k]);
                    n += k as u64;
                    feed(&buf[..k]);
                }
                Err(_) => return false,
            }
        }
        h.write_u64(n);
        h.finish() == m.hash
    }

    /// 下載完成：內容有變（雜湊不同）才登記寫出新的副本；驗證資訊有變就更新索引。回傳有沒有登記新的副本。
    /// 實際壓縮後的大小現在放不下（不刪別的副本）就不登記：小 Flash 上不會每天寫一份、刪一份
    pub fn offer(&self, url: &str, hash: u64, compressed: Option<Vec<u8>>, v: &Validators, now: u64, rules: u64) -> bool {
        let mut idx = self.index.lock().unwrap();
        let same = idx.get(url).is_some_and(|m| m.hash == hash);
        let mut staged = false;
        if !same {
            let Some(z) = compressed else { return false };
            if !self.persister.lock().unwrap().has_room_for_optional(z.len() as u64) {
                return false;
            }
            let file = url_id(url);
            idx.insert(
                url.to_string(),
                CopyMeta {
                    file: file.clone(),
                    hash,
                    etag: v.etag.clone(),
                    last_modified: v.last_modified.clone(),
                    bytes: z.len() as u64,
                    at: now,
                    rules,
                },
            );
            self.persister.lock().unwrap().stage(&file, z);
            staged = true;
        } else if let Some(m) = idx.get_mut(url) {
            m.etag = v.etag.clone();
            m.last_modified = v.last_modified.clone();
            m.rules = rules;
        }
        let body = Self::index_json(&idx);
        drop(idx);
        // 索引內容沒變時，快照寫入器不會重寫
        self.persister.lock().unwrap().stage(COPY_INDEX, body);
        staged
    }

    fn index_json(idx: &HashMap<String, CopyMeta>) -> Vec<u8> {
        let mut keys: Vec<&String> = idx.keys().collect();
        keys.sort();
        let m: serde_json::Map<String, Value> = keys
            .into_iter()
            .map(|k| {
                let c = &idx[k];
                (
                    k.clone(),
                    json!({ "hash": format!("{:016x}", c.hash), "etag": c.etag, "lastModified": c.last_modified, "bytes": c.bytes, "at": c.at, "rules": c.rules }),
                )
            })
            .collect();
        serde_json::to_vec(&Value::Object(m)).unwrap_or_default()
    }

    /// 狀態頁：副本份數、大小
    pub fn status(&self) -> Value {
        let idx = self.index.lock().unwrap();
        json!({ "count": idx.len(), "bytes": idx.values().map(|c| c.bytes).sum::<u64>() })
    }
}

pub struct FilterService {
    opts: BuildOptions,
    custom_paths: Vec<PathBuf>,
    sources: Vec<ListSource>,
    custom: RwLock<Arc<Filter>>,
    lists: RwLock<Arc<Filter>>,
    custom_mtime: Mutex<Vec<Option<SystemTime>>>,
    validators: Mutex<Vec<Validators>>,
    status: Mutex<Value>,
    pub interval: Duration,
    max_bytes: u64,
    /// 各清單命中次數（跟 `sources` 同順序；32 位元平台沒有 64 位元原子操作）
    hits: Vec<AtomicU32>,
    hits_dirty: AtomicBool,
    /// 各清單上次載入時量到的大小（bytes；沒載入過是 0）與規則數
    sizes: Mutex<Vec<(u64, u64)>>,
    /// 暫時停用的清單（依停用順序）
    unloaded: Mutex<Vec<Unloaded>>,
    /// 同一時間只有一個重建（定時更新、記憶體控制的停用 / 恢復）
    rebuild_lock: tokio::sync::Mutex<()>,
    allowance: OnceLock<AllowanceFn>,
    /// 重建時可以用的記憶體（保留量以上還有多少；記憶體控制提供）
    build_room: OnceLock<AllowanceFn>,
    /// 記憶體控制到了最低限度、連保護清單都暫停了（只剩自訂規則）
    suspended: AtomicBool,
    /// 暫停前清單層佔的記憶體（恢復時要有這麼多空間的 1.3 倍）
    suspended_bytes: Mutex<u64>,
    /// 本機副本（快照寫入器設定好才有）
    copies: OnceLock<ListCopies>,
    /// 只用副本建的時候，因為沒有副本而這次沒載入的清單（下一次更新一定下載）
    missing: Mutex<Vec<usize>>,
    /// 手動「立即更新」（`POST /api/filter/update`）：背景執行，進度與結果在狀態的 `filter.update`
    update_run: Mutex<UpdateRun>,
    /// 每次更新結束時送出那一次的 runId（`?wait=1` 等結果用）
    update_done: tokio::sync::watch::Sender<u64>,
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 一次手動更新的狀態（`/api/status` 的 `filter.update`）
#[derive(Debug, Clone, Default)]
pub struct UpdateRun {
    pub running: bool,
    /// 這次的編號：開始時間（Unix 毫秒），同一個程式裡不會重複
    pub run_id: u64,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    pub changed: Option<bool>,
    pub error: Option<String>,
}

impl UpdateRun {
    pub fn json(&self) -> Value {
        json!({
            "state": if self.running { "running" } else { "idle" },
            "runId": (self.run_id > 0).then_some(self.run_id),
            "startedAt": (self.started_at > 0).then_some(self.started_at),
            "finishedAt": self.finished_at,
            "changed": self.changed,
            "error": self.error,
        })
    }
}

/// 清單的停用順序（純函式，方便測試）：保護清單、已經停用的不算；
/// 依（分類的重要性：廣告 < 遙測 < 惡意，歷史命中次數少的先，佔記憶體多的先）
pub fn shed_order(sources: &[ListSource], hits: &[u32], sizes: &[u64], loaded: &[bool]) -> Vec<usize> {
    let mut v: Vec<usize> = (0..sources.len()).filter(|&i| !sources[i].protect && loaded[i]).collect();
    v.sort_by_key(|&i| (sources[i].category as u8, hits[i], std::cmp::Reverse(sizes[i]), i));
    v
}

impl FilterService {
    pub fn from_cfg(cfg: &Value, base_dir: &Path) -> Option<Arc<FilterService>> {
        let g = |k: &str| kuroshio_config::get(cfg, &format!("filter.{k}"));
        if g("enabled").and_then(Value::as_bool) == Some(false) {
            return None;
        }
        let custom_paths: Vec<PathBuf> = g("customRules")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(|p| resolve(base_dir, p)).collect())
            .unwrap_or_default();
        let sources: Vec<ListSource> = g("lists")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter(|l| l.get("enabled") != Some(&Value::Bool(false)))
                    .filter_map(list_source)
                    .collect()
            })
            .unwrap_or_default();
        let opts = BuildOptions {
            max_domains: g("maxDomains").and_then(Value::as_u64).unwrap_or(10_000_000),
            max_complex: g("maxComplex").and_then(Value::as_u64).unwrap_or(20_000),
            max_unindexed: g("maxUnindexed").and_then(Value::as_u64).unwrap_or(2_000),
            relaxed_modifiers: g("relaxedModifiers").and_then(Value::as_bool).unwrap_or(false),
        };
        let hours = g("updateIntervalHours").and_then(Value::as_u64).unwrap_or(24).max(1);
        let n = sources.len();
        Some(Arc::new(FilterService {
            opts,
            custom_mtime: Mutex::new(vec![None; custom_paths.len()]),
            custom_paths,
            sources,
            custom: RwLock::new(Arc::new(Filter::empty())),
            lists: RwLock::new(Arc::new(Filter::empty())),
            validators: Mutex::new(vec![Validators::default(); n]),
            status: Mutex::new(json!({ "updatedAt": null, "errors": [] })),
            interval: Duration::from_secs(hours * 3600),
            max_bytes: 64 << 20,
            hits: (0..n).map(|_| AtomicU32::new(0)).collect(),
            hits_dirty: AtomicBool::new(false),
            sizes: Mutex::new(vec![(0, 0); n]),
            unloaded: Mutex::new(Vec::new()),
            rebuild_lock: tokio::sync::Mutex::new(()),
            allowance: OnceLock::new(),
            build_room: OnceLock::new(),
            suspended: AtomicBool::new(false),
            suspended_bytes: Mutex::new(0),
            copies: OnceLock::new(),
            missing: Mutex::new(Vec::new()),
            update_run: Mutex::new(UpdateRun::default()),
            update_done: tokio::sync::watch::channel(0).0,
        }))
    }

    pub fn sources(&self) -> &[ListSource] {
        &self.sources
    }

    /// 開始一次手動更新（重新讀自訂規則、強制檢查每份清單），在背景執行。
    /// 回傳（這次是不是新開始的, 這一次的狀態）：已經有一次在跑就不再開，回傳正在跑的那一次
    pub fn start_update(self: &Arc<Self>) -> (bool, UpdateRun) {
        let run = {
            let mut u = self.update_run.lock().unwrap();
            if u.running {
                return (false, u.clone());
            }
            // 開始時間（毫秒）當編號；時鐘倒退也不會跟上一次重複
            let now = unix_ms().max(u.run_id + 1);
            *u = UpdateRun {
                running: true,
                run_id: now,
                started_at: now,
                ..Default::default()
            };
            u.clone()
        };
        let me = self.clone();
        let id = run.run_id;
        tokio::spawn(async move {
            me.reload_custom(true);
            let r = me.update_lists(true).await;
            let fin = unix_ms();
            {
                let mut u = me.update_run.lock().unwrap();
                u.running = false;
                u.finished_at = Some(fin);
                match r {
                    Ok(c) => u.changed = Some(c),
                    Err(e) => {
                        warn!("立即更新過濾清單失敗：{e:#}");
                        u.error = Some(format!("{e:#}"));
                    }
                }
            }
            me.update_done.send_replace(id);
        });
        (true, run)
    }

    /// 等 `run_id` 那一次更新結束，回傳結果（`?wait=1`）
    pub async fn wait_update(&self, run_id: u64) -> UpdateRun {
        let mut rx = self.update_done.subscribe();
        loop {
            {
                let u = self.update_run.lock().unwrap();
                if u.run_id != run_id || !u.running {
                    return u.clone();
                }
            }
            if rx.changed().await.is_err() {
                return self.update_run.lock().unwrap().clone();
            }
        }
    }

    pub fn update_status(&self) -> UpdateRun {
        self.update_run.lock().unwrap().clone()
    }

    /// 本機副本存在快照目錄的 `filter-lists/`（只能設定一次）
    pub fn set_copies(&self, p: Arc<Mutex<crate::persist::Persister>>) {
        let _ = self.copies.set(ListCopies::new(p));
        // 副本記著上次的規則數：開機那次就能估記憶體（沒量過的清單本來只受 maxDomains 限制）
        if let Some(c) = self.copies.get() {
            let mut sizes = self.sizes.lock().unwrap();
            for (i, s) in self.sources.iter().enumerate() {
                if sizes[i] == (0, 0) {
                    if let Some(m) = c.meta(&s.url).filter(|m| m.rules > 0) {
                        sizes[i] = (m.rules * 9, m.rules);
                    }
                }
            }
        }
    }

    pub fn copies(&self) -> Option<&ListCopies> {
        self.copies.get()
    }

    /// 開機時：有本機副本的清單先用副本建好過濾器（不必等下載、也不必等對時），驗證資訊也接上
    /// （下一次更新只問「有沒有變」）；沒有副本的清單等之後下載。回傳有沒有建
    pub async fn build_from_copies(&self) -> bool {
        let Some(c) = self.copies.get() else { return false };
        let _g = self.rebuild_lock.lock().await;
        let ex = self.excluded();
        let any = (0..self.sources.len())
            .filter(|&i| !ex[i])
            .any(|i| c.available(&self.sources[i].url));
        if self.sources.is_empty() || !any || self.all_suspended() {
            return false;
        }
        match self.rebuild_mode(Source::CopiesOnly, &[]).await {
            Ok(_) => {
                let mut v = self.validators.lock().unwrap();
                for (i, s) in self.sources.iter().enumerate() {
                    if let Some(m) = c.meta(&s.url) {
                        v[i] = Validators {
                            etag: m.etag,
                            last_modified: m.last_modified,
                        };
                    }
                }
                let missing = self.missing.lock().unwrap().len();
                if missing > 0 {
                    info!("過濾清單：用本機副本先建好，{missing} 份沒有副本的稍後下載");
                } else {
                    info!("過濾清單：用本機副本建好（不必等下載），稍後檢查有沒有更新");
                }
                true
            }
            Err(e) => {
                warn!("用本機副本建過濾器失敗：{e:#}，改成下載");
                false
            }
        }
    }

    /// 記憶體控制提供的預算（只能設定一次）
    pub fn set_allowance(&self, f: AllowanceFn) {
        let _ = self.allowance.set(f);
    }

    /// 重建時可以用的記憶體（只能設定一次）
    pub fn set_build_room(&self, f: AllowanceFn) {
        let _ = self.build_room.set(f);
    }

    /// 自訂規則檔有變就重建（第一次呼叫一定建）；設定的檔案不存在時寫出預設規則
    pub fn reload_custom(&self, force: bool) -> bool {
        let mtimes: Vec<Option<SystemTime>> = self
            .custom_paths
            .iter()
            .map(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok())
            .collect();
        {
            let mut cur = self.custom_mtime.lock().unwrap();
            if !force && *cur == mtimes {
                return false;
            }
            *cur = mtimes;
        }
        let mut b = FilterBuilder::new(BuildOptions {
            max_domains: u64::MAX,
            ..self.opts
        });
        {
            let mut w = b.custom();
            for p in &self.custom_paths {
                match std::fs::read(p) {
                    Ok(bytes) => {
                        w.feed(&bytes);
                        w.feed(b"\n");
                    }
                    Err(_) if !p.exists() => {
                        if let Some(dir) = p.parent() {
                            let _ = std::fs::create_dir_all(dir);
                        }
                        match std::fs::write(p, DEFAULT_CUSTOM_RULES) {
                            Ok(()) => info!("自訂規則檔 {} 不存在，寫入預設規則", p.display()),
                            Err(e) => warn!("自訂規則檔 {} 不存在，也無法建立：{e}（先用預設規則）", p.display()),
                        }
                        w.feed(DEFAULT_CUSTOM_RULES.as_bytes());
                    }
                    Err(e) => warn!("讀不到自訂規則 {}：{e}", p.display()),
                }
            }
        }
        let f = b.finish();
        info!("自訂規則已載入：{} 條", f.stats().custom);
        *self.custom.write().unwrap() = Arc::new(f);
        true
    }

    fn excluded(&self) -> Vec<bool> {
        let mut ex = vec![false; self.sources.len()];
        for u in self.unloaded.lock().unwrap().iter() {
            ex[u.idx] = true;
        }
        ex
    }

    /// 更新訂閱清單；回傳是否重建。`force` = 不管有沒有變都重新下載
    pub async fn update_lists(&self, force: bool) -> anyhow::Result<bool> {
        let _g = self.rebuild_lock.lock().await;
        if self.all_suspended() {
            // 記憶體最低限度：清單暫停中，恢復時才重新載入
            return Ok(false);
        }
        if self.sources.is_empty() {
            *self.lists.write().unwrap() = Arc::new(Filter::empty());
            return Ok(false);
        }
        let timeout = Duration::from_secs(30);
        let have = self.lists.read().unwrap().stats().lists > 0;
        let ex = self.excluded();
        // 1. 都有驗證資訊時先問「有沒有變」：全部 304 就不重建（停用中的清單不問）
        let prev = self.validators.lock().unwrap().clone();
        let active: Vec<usize> = (0..self.sources.len()).filter(|&i| !ex[i]).collect();
        // 有變的那份不在這裡下載（收到第一段就停），重建時才下載一次；沒變而且有本機副本的，重建時直接讀副本
        let mut reuse = vec![false; self.sources.len()];
        let missing = !self.missing.lock().unwrap().is_empty();
        if !force && have && active.iter().any(|&i| prev[i].etag.is_some() || prev[i].last_modified.is_some()) {
            let mut changed = missing;
            for &i in &active {
                if prev[i].etag.is_none() && prev[i].last_modified.is_none() {
                    changed = true;
                    continue;
                }
                let r = fetch::get(&self.sources[i].url, &prev[i], self.max_bytes, timeout, |_| {
                    Err(anyhow::anyhow!("有更新（重建時再下載）"))
                })
                .await;
                match r {
                    Ok(Outcome::NotModified) => reuse[i] = true,
                    _ => changed = true,
                }
            }
            if !changed {
                self.status.lock().unwrap()["checkedAt"] = json!(crate::persist::now_secs() * 1000);
                return Ok(false);
            }
        }
        // 2. 載入前先看記憶體預算：量過大小的清單估計會超過，就依停用順序先不載入（看得到原因）
        self.fit_allowance();
        self.rebuild_mode(Source::Download, &reuse).await.map(|_| true)
    }

    /// 依記憶體預算（記憶體控制提供）先排除會放不下的清單：只用量過的大小估，依停用順序（保護清單絕不排除；
    /// 只剩保護清單還是超過時照樣載入、記警告）。沒量過的清單（第一次載入）只受 `max_domains` 限制
    ///
    /// 重建時新的一份在建置中每條規則約 [`BUILD_BYTES_PER_RULE`]，建好前舊的一份也還在：
    /// 「建好的大小 + 建置中的大小」也要放得進保留量以上的空間（128 MB 的機器載大清單時才會碰到）
    fn fit_allowance(&self) {
        let Some(steady) = self.allowance.get().and_then(|f| f()) else {
            return;
        };
        let room = self.build_room.get().and_then(|f| f());
        let ex = self.excluded();
        let sz: Vec<(u64, u64)> = self.sizes.lock().unwrap().clone();
        let sizes: Vec<u64> = sz.iter().map(|s| s.0).collect();
        // 建置尖峰換算成「建好的大小」的上限：bytes + rules × 16 ≤ room
        let need = |i: usize| sz[i].0 + sz[i].1 * BUILD_BYTES_PER_RULE;
        let mut total: u64 = (0..self.sources.len()).filter(|&i| !ex[i]).map(|i| sizes[i]).sum();
        let mut peak: u64 = (0..self.sources.len()).filter(|&i| !ex[i]).map(need).sum();
        let fits = |total: u64, peak: u64| total <= steady && room.map_or(true, |r| peak <= r);
        let limit = steady;
        if fits(total, peak) {
            return;
        }
        let loaded: Vec<bool> = ex.iter().map(|e| !e).collect();
        for i in shed_order(&self.sources, &self.hits_vec(), &sizes, &loaded) {
            if fits(total, peak) {
                break;
            }
            let (bytes, rules) = sz[i];
            if bytes == 0 {
                continue;
            }
            total -= bytes;
            peak -= need(i);
            warn!(
                "記憶體預算不足：這次不載入清單「{}」（約 {} KB、{rules} 條規則；預算 {} KB{}）",
                self.sources[i].name,
                bytes / 1024,
                limit / 1024,
                room.map(|r| format!("，重建時可用 {} KB", r / 1024)).unwrap_or_default()
            );
            self.unloaded.lock().unwrap().push(Unloaded {
                idx: i,
                name: self.sources[i].name.clone(),
                rules,
                bytes,
                reason: "budget",
                at: crate::persist::now_secs() * 1000,
            });
        }
        if total > limit {
            warn!(
                "保護清單（與停用不了的清單）合計約 {} KB，超過記憶體預算 {} KB：保護清單照樣載入",
                total / 1024,
                limit / 1024
            );
        }
    }

    /// 依目前的停用名單重新下載、建一份清單層（下載失敗而且原本有清單時保留舊的）。回傳（重建前，重建後）的大小
    /// 重建清單層。`mode` 見 [`Source`]；`reuse[i]` = 剛問過沒變（有副本就讀副本，不重新下載）
    async fn rebuild_mode(&self, mode: Source, reuse: &[bool]) -> anyhow::Result<(u64, u64)> {
        let timeout = Duration::from_secs(30);
        let current = self.lists.read().unwrap().clone();
        let have = current.stats().lists > 0;
        let ex = self.excluded();
        // 這次沒有副本、所以沒載入的清單（只用副本建的時候）
        let mut no_copy: Vec<usize> = Vec::new();
        // 下載失敗的清單編號（跟 errors 同順序）
        let mut failed: Vec<usize> = Vec::new();
        let prev_sizes = self.sizes.lock().unwrap().clone();
        // 自訂規則的網域數也算在預算裡
        let (custom_n, custom_unindexed) = {
            let c = self.custom.read().unwrap();
            (c.stats().custom, c.stats().unindexed)
        };
        // 記憶體預算不在這裡套用：maxDomains 依清單順序累計，會先擠掉排在後面的保護清單（例如 TW165）。
        // 量過大小的清單在 `fit_allowance` 依停用順序先排除；第一次載入（還沒量過）只受等級的 maxDomains 限制
        let max_domains = self.opts.max_domains.saturating_sub(custom_n);
        let mut b = FilterBuilder::new(BuildOptions {
            max_domains,
            // 每次查詢都要跑的規則：自訂規則的也算在內（查詢時兩層都要跑）
            max_unindexed: self.opts.max_unindexed.saturating_sub(custom_unindexed),
            ..self.opts
        });
        // 依上次的規則數先預留：建置中的 Vec 不必倍增（倍增時尖峰最多多一倍）
        let expect: u64 = (0..self.sources.len()).filter(|&i| !ex[i]).map(|i| prev_sizes[i].1).sum();
        if expect > 0 {
            b.reserve((expect + expect / 20).min(max_domains as u64) as usize);
        }
        let mut errors = Vec::new();
        let mut validators = Vec::new();
        for (i, s) in self.sources.iter().enumerate() {
            // 停用中的清單也佔一個位置（統計裡是 disabled），清單編號跟命中次數的對應才不會亂
            let mut w = b.list(ListSpec {
                name: s.name.clone(),
                category: s.category,
                enabled: !ex[i],
            })?;
            if ex[i] {
                w.end();
                validators.push(Validators::default());
                continue;
            }
            let copies = self.copies.get();
            let use_copy = match mode {
                Source::Download => reuse.get(i).copied().unwrap_or(false),
                Source::PreferCopy | Source::CopiesOnly => true,
            };
            if use_copy {
                if let Some(c) = copies.filter(|c| c.available(&s.url)) {
                    if c.read(&s.url, &mut |b| w.feed(b)) {
                        w.end();
                        let m = c.meta(&s.url).unwrap_or_else(|| unreachable!());
                        validators.push(Validators {
                            etag: m.etag,
                            last_modified: m.last_modified,
                        });
                        continue;
                    }
                    // 副本壞掉：重新下載（這份清單的規則從頭來）
                    w.reset();
                }
            }
            if mode == Source::CopiesOnly {
                // 只用副本：沒有副本的這次不載入，不在這時候下載
                w.end();
                validators.push(Validators::default());
                no_copy.push(i);
                continue;
            }
            let estimate = copies.and_then(|c| c.meta(&s.url)).map_or(1 << 20, |m| m.bytes);
            let mut sink = CopySink::new(copies.is_some_and(|c| c.wanted(estimate)));
            let r = fetch::get(&s.url, &Validators::default(), self.max_bytes, timeout, |c| {
                w.feed(c);
                sink.feed(c);
                Ok(())
            })
            .await;
            // 下載完成但規則數比上次少一大半：當成下載不完整（不換上、不存副本）
            let prev_rules = match prev_sizes[i].1 {
                0 => copies.and_then(|c| c.meta(&s.url)).map_or(0, |m| m.rules),
                n => n,
            };
            let r = match r {
                Ok(Outcome::Done { .. }) => match suspicious_drop(prev_rules, w.rules()) {
                    Some(why) => Err(anyhow::anyhow!(why)),
                    None => r,
                },
                r => r,
            };
            match r {
                Ok(Outcome::Done { validators: v, .. }) => {
                    let rules = w.rules();
                    w.end();
                    if let Some(c) = copies {
                        let (h, z) = sink.finish();
                        c.offer(&s.url, h, z, &v, crate::persist::now_secs(), rules);
                    }
                    validators.push(v)
                }
                Ok(Outcome::NotModified) => {
                    w.end();
                    validators.push(Validators::default())
                }
                Err(e) => {
                    // 下載失敗：有本機副本就拿副本頂著（這份清單不會整份不見）
                    let fallback = copies.filter(|c| c.available(&s.url)).is_some_and(|c| {
                        w.reset();
                        c.read(&s.url, &mut |b| w.feed(b))
                    });
                    w.end();
                    if fallback {
                        warn!("下載清單「{}」失敗：{e}；先用本機副本", s.name);
                    } else {
                        warn!("下載清單「{}」失敗：{e}", s.name);
                        errors.push(json!({ "name": s.name, "url": s.url, "error": e.to_string() }));
                        failed.push(i);
                    }
                    validators.push(Validators::default());
                }
            }
        }
        let f = b.finish();
        let st = f.stats();
        for s in st.over_budget() {
            if let SourceStatus::OverBudget { rules, remaining } = s.status {
                warn!("清單「{}」超過記憶體預算，未載入（{rules} 條，剩餘額度 {remaining}）", s.name);
            }
        }
        for s in st.sources.iter().filter(|s| s.complex_dropped > 0 || s.unindexed_dropped > 0) {
            warn!(
                "清單「{}」有 {} 條複雜規則超過上限（filter.maxComplex {}）、{} 條沒有固定字串的規則超過上限（filter.maxUnindexed {}），未載入",
                s.name, s.complex_dropped, st.max_complex, s.unindexed_dropped, st.max_unindexed
            );
        }
        // 有清單下載失敗、而且它在目前的過濾器裡是載入的：保留舊的，避免少掉一整份清單。
        // 失敗的清單目前本來就沒有（例如開機時就沒下載到）：換上新的不會更少，其他恢復的清單也能用上
        let lost = failed
            .iter()
            .any(|&i| current.stats().sources.get(i).is_some_and(|x| x.status == SourceStatus::Loaded));
        if lost && have {
            self.status.lock().unwrap()["errors"] = json!(errors);
            anyhow::bail!("{} 份清單下載失敗，保留舊的過濾器", errors.len());
        }
        info!(
            "訂閱清單已載入：{} 條（廣告 {}、遙測 {}、惡意 {}），約 {} KB",
            st.lists,
            st.by_category.get(Category::Ads),
            st.by_category.get(Category::Telemetry),
            st.by_category.get(Category::Malware),
            f.memory_bytes() / 1024
        );
        // 各清單的大小：整個清單層的記憶體依規則數分攤（重複的網域只存一份，所以是估計；停用 / 恢復時會實測差額）
        {
            let total_rules: u64 = st.sources.iter().map(|s| s.domain_rules + s.complex_rules).sum::<u64>().max(1);
            let mem = f.memory_bytes() as u64;
            let mut sizes = self.sizes.lock().unwrap();
            for (i, s) in st.sources.iter().enumerate().take(sizes.len()) {
                if s.status == SourceStatus::Loaded {
                    let rules = s.domain_rules + s.complex_rules;
                    sizes[i] = (mem * rules / total_rules, rules);
                }
            }
        }
        let before = self.lists.read().unwrap().memory_bytes() as u64;
        let after = f.memory_bytes() as u64;
        if self.all_suspended() {
            // 建的期間記憶體控制暫停了全部清單：不換上去
            anyhow::bail!("過濾清單已暫停（記憶體最低限度），這次建好的不使用");
        }
        *self.lists.write().unwrap() = Arc::new(f);
        *self.validators.lock().unwrap() = validators;
        *self.missing.lock().unwrap() = no_copy;
        let mut status = self.status.lock().unwrap();
        status["updatedAt"] = json!(crate::persist::now_secs() * 1000);
        status["errors"] = json!(errors);
        Ok((before, after))
    }

    fn hits_vec(&self) -> Vec<u32> {
        self.hits.iter().map(|h| h.load(Ordering::Relaxed)).collect()
    }

    /// 目前可以停用的清單（依停用順序）
    pub fn shed_candidates(&self) -> Vec<usize> {
        let ex = self.excluded();
        let lists = self.lists.read().unwrap().clone();
        let st = lists.stats();
        let loaded: Vec<bool> = (0..self.sources.len())
            .map(|i| !ex[i] && st.sources.get(i).is_some_and(|s| s.status == SourceStatus::Loaded))
            .collect();
        let sizes: Vec<u64> = self.sizes.lock().unwrap().iter().map(|s| s.0).collect();
        shed_order(&self.sources, &self.hits_vec(), &sizes, &loaded)
    }

    /// 下一份要停用的清單估計可以釋出多少（沒有可停用的清單時 None）
    pub fn next_shed_bytes(&self) -> Option<u64> {
        self.shed_candidates().first().map(|&i| self.sizes.lock().unwrap()[i].0)
    }

    /// 清單層目前佔的記憶體（bytes）
    pub fn lists_bytes(&self) -> u64 {
        self.lists.read().unwrap().memory_bytes() as u64
    }

    /// 清單層目前的規則數
    pub fn list_rules(&self) -> u64 {
        self.lists.read().unwrap().stats().lists
    }

    /// 全部清單（含保護清單）暫停中
    pub fn all_suspended(&self) -> bool {
        self.suspended.load(Ordering::Relaxed)
    }

    /// 暫停前清單層的大小
    pub fn suspended_bytes(&self) -> u64 {
        *self.suspended_bytes.lock().unwrap()
    }

    /// 記憶體控制的最後一步（規格 09）：暫停全部清單，包括保護清單——只在不讓出來連轉送都會失敗時。
    /// 立刻換成空的清單層（不用重建），自訂規則照樣有效。回傳釋出的 bytes
    pub fn suspend_all(&self) -> u64 {
        self.suspended.store(true, Ordering::Relaxed);
        let bytes = self.lists_bytes();
        *self.suspended_bytes.lock().unwrap() = bytes;
        *self.lists.write().unwrap() = Arc::new(Filter::empty());
        warn!(
            "記憶體嚴重不足：暫停全部過濾清單（含保護清單，約 {} KB），只剩自訂規則；DNS 轉送照常",
            bytes / 1024
        );
        self.status.lock().unwrap()["suspended"] = json!(true);
        bytes
    }

    /// 恢復全部清單（重新載入；有本機副本時不用下載）。失敗時維持暫停
    pub async fn resume_all(&self) -> anyhow::Result<()> {
        let _g = self.rebuild_lock.lock().await;
        self.suspended.store(false, Ordering::Relaxed);
        match self.rebuild_mode(Source::PreferCopy, &[]).await {
            Ok(_) => {
                info!("記憶體恢復：重新載入全部過濾清單");
                self.status.lock().unwrap()["suspended"] = json!(false);
                Ok(())
            }
            Err(e) => {
                self.suspended.store(true, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    /// 停用中的清單
    pub fn unloaded(&self) -> Vec<Unloaded> {
        self.unloaded.lock().unwrap().clone()
    }

    /// 下一份要恢復的清單需要多少記憶體（最後停用的先恢復——它的優先順序最高）
    pub fn next_restore_bytes(&self) -> Option<u64> {
        self.unloaded.lock().unwrap().last().map(|u| u.bytes)
    }

    /// 記憶體控制：停用下一份清單（重建一份不含它的過濾器；重建期間舊的照常使用）。
    /// 有本機副本的清單讀副本，沒有的才下載（記憶體控制在自己的工作裡跑，下載期間記憶體監看照常更新）。
    /// 沒有可以停用的回傳 Ok(None)；下載失敗時保留舊的、清單不算停用
    pub async fn unload_one(&self) -> anyhow::Result<Option<Unloaded>> {
        let _g = self.rebuild_lock.lock().await;
        let Some(&i) = self.shed_candidates().first() else {
            return Ok(None);
        };
        let rules = self.sizes.lock().unwrap()[i].1;
        let u = Unloaded {
            idx: i,
            name: self.sources[i].name.clone(),
            rules,
            bytes: 0,
            reason: "memory",
            at: crate::persist::now_secs() * 1000,
        };
        self.unloaded.lock().unwrap().push(u.clone());
        match self.rebuild_mode(Source::PreferCopy, &[]).await {
            Ok((before, after)) => {
                let bytes = before.saturating_sub(after).max(self.sizes.lock().unwrap()[i].0);
                let mut list = self.unloaded.lock().unwrap();
                if let Some(x) = list.iter_mut().find(|x| x.idx == i) {
                    x.bytes = bytes;
                }
                warn!(
                    "記憶體不足，暫時停用：{} 清單（{rules} 條規則，釋出約 {} KB）",
                    u.name,
                    bytes / 1024
                );
                Ok(list.iter().find(|x| x.idx == i).cloned())
            }
            Err(e) => {
                self.unloaded.lock().unwrap().retain(|x| x.idx != i);
                Err(e)
            }
        }
    }

    /// 記憶體控制：恢復最後停用的清單（重新下載）。下載失敗時維持停用，由呼叫端退避重試
    pub async fn restore_one(&self) -> anyhow::Result<Option<Unloaded>> {
        let _g = self.rebuild_lock.lock().await;
        if self.all_suspended() {
            anyhow::bail!("全部清單暫停中，先恢復全部清單");
        }
        let Some(u) = self.unloaded.lock().unwrap().pop() else {
            return Ok(None);
        };
        match self.rebuild_mode(Source::PreferCopy, &[]).await {
            Ok(_) => {
                let loaded = self.lists.read().unwrap().stats().sources.get(u.idx).map(|s| s.status) == Some(SourceStatus::Loaded);
                if !loaded {
                    // 超過 maxDomains / 預算：還是載不進來，維持停用
                    self.unloaded.lock().unwrap().push(u.clone());
                    anyhow::bail!("清單「{}」還是放不下（超過預算），維持停用", u.name);
                }
                info!("記憶體恢復，重新啟用：{} 清單", u.name);
                Ok(Some(u))
            }
            Err(e) => {
                self.unloaded.lock().unwrap().push(u);
                Err(e)
            }
        }
    }

    /// 各清單命中次數（快照用）：{ 清單名稱: 次數 }
    pub fn hits_json(&self) -> Vec<u8> {
        let m: serde_json::Map<String, Value> = self
            .sources
            .iter()
            .zip(&self.hits)
            .map(|(s, h)| (s.name.clone(), json!(h.load(Ordering::Relaxed))))
            .collect();
        serde_json::to_vec(&Value::Object(m)).unwrap_or_default()
    }

    /// 有沒有新的命中（取出並清除）
    pub fn take_hits_dirty(&self) -> bool {
        self.hits_dirty.swap(false, Ordering::Relaxed)
    }

    /// 讀回上次的命中次數（依清單名稱；改過名的清單從 0 開始）
    pub fn restore_hits(&self, b: &[u8]) {
        let Ok(Value::Object(m)) = serde_json::from_slice::<Value>(b) else {
            return;
        };
        for (s, h) in self.sources.iter().zip(&self.hits) {
            if let Some(n) = m.get(&s.name).and_then(Value::as_u64) {
                h.store(n.min(u32::MAX as u64) as u32, Ordering::Relaxed);
            }
        }
    }

    /// 背景工作：清單定時更新、自訂規則每 3 秒檢查
    pub fn spawn(self: &Arc<Self>) {
        self.reload_custom(true);
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(3)).await;
                me.reload_custom(false);
            }
        });
        let me = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;
            // 有本機副本：先用副本建好，1 分鐘後再問上游有沒有更新（大多是 304，不必重建）
            if me.build_from_copies().await {
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
            // 下載要 TLS：系統時間還沒對時（路由器開機時常是 1970）先等，最多 10 分鐘
            let t0 = std::time::Instant::now();
            if !crate::clock::synced() {
                info!("系統時間還沒對時：過濾清單等對時後再下載");
                while !crate::clock::synced() && t0.elapsed() < Duration::from_secs(600) {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
            // 有清單下載失敗（或還有沒載入的）時短間隔重試：1、2、5 分鐘，之後每 30 分鐘；全部成功就回到正常間隔
            let mut tries = 0usize;
            loop {
                // 記憶體吃緊時延後（重建時新舊兩份會同時存在）
                let wait = if crate::app::pressure() == crate::sysinfo::Pressure::Critical {
                    warn!("記憶體不足，延後更新過濾清單");
                    Duration::from_secs(1800)
                } else {
                    let r = me.update_lists(false).await;
                    let partial = me.status.lock().unwrap()["errors"].as_array().is_some_and(|a| !a.is_empty())
                        || !me.missing.lock().unwrap().is_empty();
                    match r {
                        Ok(_) if !partial => {
                            tries = 0;
                            me.interval
                        }
                        r => {
                            let w = Duration::from_secs(RETRY_BACKOFF[tries.min(RETRY_BACKOFF.len() - 1)]);
                            tries += 1;
                            match r {
                                Err(e) => warn!("{e:#}；{} 秒後重試", w.as_secs()),
                                Ok(_) => warn!("有清單還沒載入（下載失敗）：{} 秒後重試", w.as_secs()),
                            }
                            w
                        }
                    }
                };
                tokio::time::sleep(wait).await;
            }
        });
    }
}

/// 設定裡的一份清單
fn list_source(l: &Value) -> Option<ListSource> {
    let url = l.get("url")?.as_str()?.to_string();
    let category = l
        .get("category")
        .and_then(Value::as_str)
        .and_then(Category::parse)
        .filter(|c| *c != Category::Custom)
        .unwrap_or(Category::Ads);
    let name = l.get("name").and_then(Value::as_str).unwrap_or(&url).to_string();
    // 惡意（含反詐騙，例如 TW165）預設是保護清單：記憶體不足也不停用
    let protect = l.get("protect").and_then(Value::as_bool).unwrap_or(category == Category::Malware);
    Some(ListSource {
        url,
        name,
        category,
        protect,
    })
}

fn resolve(base: &Path, p: &str) -> PathBuf {
    let p = Path::new(p);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p.strip_prefix("./").unwrap_or(p))
    }
}

fn verdict(v: kuroshio_filter::Verdict<'_>) -> Verdict {
    Verdict {
        block: v.is_block(),
        allow: v.is_allow(),
        category: v.category.as_str(),
        rule: v.rule().into_owned(),
    }
}

impl FilterCheck for FilterService {
    fn check(&self, name: &str, qtype: u16) -> Option<Verdict> {
        let custom = self.custom.read().unwrap().clone();
        if let Some(v) = custom.check(name, qtype) {
            return Some(verdict(v));
        }
        let lists = self.lists.read().unwrap().clone();
        let v = lists.check(name, qtype)?;
        // 清單層的來源編號就是 sources 的位置（停用中的清單也佔一個位置）
        if let Some(h) = v.list.and_then(|i| self.hits.get(i)) {
            h.fetch_add(1, Ordering::Relaxed);
            self.hits_dirty.store(true, Ordering::Relaxed);
        }
        Some(verdict(v))
    }

    /// 對齊 2.x `filter.stats`（LuCI 狀態頁用 lists / custom），另外附上來源明細與記憶體
    fn stats(&self) -> Value {
        let c = self.custom.read().unwrap().clone();
        let l = self.lists.read().unwrap().clone();
        let (cs, ls) = (c.stats(), l.stats());
        let unloaded = self.unloaded();
        let sources: Vec<Value> = ls
            .sources
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let src = self.sources.get(i);
                let status = if unloaded.iter().any(|u| u.idx == i) {
                    "unloaded"
                } else {
                    match s.status {
                        SourceStatus::Loaded => "loaded",
                        SourceStatus::Disabled => "disabled",
                        SourceStatus::OverBudget { .. } => "overBudget",
                    }
                };
                json!({
                    "name": s.name, "category": s.category.as_str(), "rules": s.domain_rules + s.complex_rules,
                    "complexDropped": s.complex_dropped, "unindexedDropped": s.unindexed_dropped,
                    "status": status,
                    "protect": src.map(|x| x.protect),
                    "hits": self.hits.get(i).map(|h| h.load(Ordering::Relaxed)),
                })
            })
            .collect();
        let status = self.status.lock().unwrap().clone();
        // 停用中的清單：設定頁 / LuCI 顯著提示（停用期間少了這些保護）
        let notice = (!unloaded.is_empty()).then(|| {
            format!(
                "記憶體不足，暫時停用：{}",
                unloaded
                    .iter()
                    .map(|u| format!("{} 清單（{} 條規則）", u.name, u.rules))
                    .collect::<Vec<_>>()
                    .join("、")
            )
        });
        json!({
            "custom": cs.custom, "lists": ls.lists,
            "byCategory": { "ads": ls.by_category.get(Category::Ads), "telemetry": ls.by_category.get(Category::Telemetry), "malware": ls.by_category.get(Category::Malware) },
            "customByCategory": { "custom": cs.custom_by_category.get(Category::Custom), "ads": cs.custom_by_category.get(Category::Ads), "telemetry": cs.custom_by_category.get(Category::Telemetry), "malware": cs.custom_by_category.get(Category::Malware) },
            "skipped": cs.skipped + ls.skipped,
            // 超過上限沒載入的複雜規則（不會默默丟掉：這裡與紀錄檔都看得到）
            "complex": cs.complex + ls.complex, "maxComplex": self.opts.max_complex,
            "complexDropped": ls.complex_dropped,
            "unindexed": cs.unindexed + ls.unindexed, "maxUnindexed": self.opts.max_unindexed,
            "unindexedDropped": ls.unindexed_dropped,
            "domains": c.domain_count() + l.domain_count(),
            "memoryBytes": c.memory_bytes() + l.memory_bytes(),
            "maxDomains": self.opts.max_domains,
            "sources": sources,
            "unloaded": unloaded.iter().map(|u| json!({
                "name": u.name, "rules": u.rules, "bytes": u.bytes, "reason": u.reason, "at": u.at,
            })).collect::<Vec<_>>(),
            "notice": notice,
            "updatedAt": status["updatedAt"], "errors": status["errors"],
            // 手動「立即更新」：背景執行的狀態（API 2）
            "update": self.update_status().json(),
        })
    }
}

#[cfg(test)]
mod copy_tests {
    use super::*;
    use crate::persist::{Persister, Policy};
    use crate::sysinfo::StorageClass;

    #[test]
    fn list_copy_written_only_when_content_changes() {
        let dir = std::env::temp_dir().join(format!("kuroshio-listcopy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let p = Arc::new(Mutex::new(Persister::new(&dir, Policy::new(StorageClass::Disk, 0, 4096))));
        p.lock().unwrap().set_free_probe(|_| Some(10 << 30));
        let c = ListCopies::new(p.clone());
        let url = "https://lists.example.com/ads.txt";
        let body = b"||ads.example.com^\n||track.example.net^\n".repeat(100);
        let v = Validators {
            etag: Some("\"v1\"".into()),
            last_modified: None,
        };
        let sink = |b: &[u8]| {
            let mut s = CopySink::new(true);
            for ch in b.chunks(7) {
                s.feed(ch);
            }
            s.finish()
        };
        let (h, z) = sink(&body);
        assert!(c.offer(url, h, z, &v, 100, 10), "第一次：登記寫出");
        let now = crate::persist::now_secs();
        assert_eq!(p.lock().unwrap().flush(now).unwrap(), 2, "副本 + 索引");
        let file = c.meta(url).unwrap().file;
        assert!(file.starts_with("filter-lists/") && file.ends_with(".txt.zst"));
        assert_eq!(crate::space::tier_of(&file), crate::space::Tier::Optional);
        // 讀回來跟原本一樣（雜湊也對）
        let mut back = Vec::new();
        assert!(c.read(url, &mut |b| back.extend_from_slice(b)));
        assert_eq!(back, body);
        // 內容沒變（只有 ETag 變了）：不重寫副本
        let (h2, z2) = sink(&body);
        let v2 = Validators {
            etag: Some("\"v2\"".into()),
            last_modified: None,
        };
        assert!(!c.offer(url, h2, z2, &v2, 200, 10));
        assert!(!p.lock().unwrap().is_pending(&file), "副本沒有重新登記");
        assert_eq!(c.meta(url).unwrap().etag.as_deref(), Some("\"v2\""));
        // 內容變了：重寫
        let mut body2 = body.clone();
        body2.extend_from_slice(b"||new.example.org^\n");
        let (h3, z3) = sink(&body2);
        assert!(c.offer(url, h3, z3, &v2, 300, 10));
        assert!(p.lock().unwrap().is_pending(&file));
        // 重開機：索引讀得回來
        p.lock().unwrap().flush_all(now).unwrap();
        let p2 = Arc::new(Mutex::new(Persister::new(&dir, Policy::new(StorageClass::Disk, 0, 4096))));
        let c2 = ListCopies::new(p2);
        assert!(c2.available(url));
        let mut back = Vec::new();
        assert!(c2.read(url, &mut |b| back.extend_from_slice(b)));
        assert_eq!(back, body2);
        // 儲存空間不夠（低於保留量 + 遲滯）時不留副本（記憶體能不能長大由記憶體控制決定，見 memgov 的測試）
        p.lock().unwrap().set_free_probe(|_| Some(1 << 20));
        assert!(!c.wanted(1000));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(name: &str, cat: Category, protect: bool) -> ListSource {
        ListSource {
            url: format!("http://127.0.0.1/{name}"),
            name: name.into(),
            category: cat,
            protect,
        }
    }

    #[test]
    fn protect_defaults_follow_category() {
        let l = |v: Value| list_source(&v).unwrap();
        assert!(
            l(json!({ "url": "u", "category": "malware", "name": "TW165" })).protect,
            "惡意 / 反詐騙預設保護"
        );
        assert!(!l(json!({ "url": "u", "category": "ads" })).protect);
        assert!(
            l(json!({ "url": "u", "category": "ads", "protect": true })).protect,
            "可以手動標成保護"
        );
        assert!(
            !l(json!({ "url": "u", "category": "malware", "protect": false })).protect,
            "也可以取消"
        );
        // 內建預設清單：TW165 反詐騙是保護清單
        let cfg = kuroshio_config::defaults();
        let lists = kuroshio_config::get(&cfg, "filter.lists").unwrap().as_array().unwrap().clone();
        let tw = lists.iter().find(|x| x["url"].as_str().unwrap().contains("TW165")).unwrap();
        assert!(list_source(tw).unwrap().protect);
    }

    #[test]
    fn shed_order_never_includes_protected() {
        let s = vec![
            src("惡意", Category::Malware, true),
            src("廣告大", Category::Ads, false),
            src("遙測", Category::Telemetry, false),
            src("廣告常用", Category::Ads, false),
            src("廣告小", Category::Ads, false),
            src("受保護廣告", Category::Ads, true),
            src("已停用", Category::Ads, false),
        ];
        let hits = [0, 5, 0, 900, 5, 0, 0];
        let sizes = [10, 4000, 10, 50, 200, 9999, 1];
        let loaded = [true, true, true, true, true, true, false];
        // 廣告（命中少、大的先）→ 廣告常用 → 遙測；保護清單、已停用的不在裡面
        assert_eq!(shed_order(&s, &hits, &sizes, &loaded), vec![1, 4, 3, 2]);
        // 全部都是保護清單：一份都不停用
        let all: Vec<ListSource> = s
            .iter()
            .map(|x| ListSource {
                protect: true,
                ..x.clone()
            })
            .collect();
        assert!(shed_order(&all, &hits, &sizes, &loaded).is_empty());
    }
}
