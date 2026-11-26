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
    /// 「繞過防護」類的清單（設定 `filter.lists[].bypass`；沒寫時預設的 HaGeZi doh-vpn-proxy-bypass 依網址認得）。
    /// 串接模式（3.4.0）：登記中的下游查它登記的上游主機名稱時，這類清單不擋（規格 10 的 4.4）
    pub bypass: bool,
    /// 惡意網站探測可以從這份抽網域（3.5.0 F10，設定 `filter.lists[].probe`；沒寫時依分類與網址，
    /// 見 `kuroshio_config::chain::is_probe_list`）。規格 11 第 6.2 節骨架，丙批的抽樣接上
    pub probe: bool,
}

/// 這一輪正在用的過濾服務（3.5.0 F10）：每日評測在排程器裡跑、拿不到 `App`，啟動評測前從這裡讀
/// [`FilterService::probe_sources`]。[`FilterService::spawn`] 時登記；只留弱參照，這一輪結束就讀不到
static CURRENT: Mutex<std::sync::Weak<FilterService>> = Mutex::new(std::sync::Weak::new());

fn set_current(f: &Arc<FilterService>) {
    *CURRENT.lock().unwrap_or_else(|e| e.into_inner()) = Arc::downgrade(f);
}

/// 這一輪正在用的過濾服務（沒有開過濾、或這一輪已經結束時是 None）
pub fn current() -> Option<Arc<FilterService>> {
    CURRENT.lock().unwrap_or_else(|e| e.into_inner()).upgrade()
}

/// 惡意網站探測可以抽樣的一份清單（3.5.0 F10，[`FilterService::probe_sources`]）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeSource {
    pub url: String,
    pub name: String,
    /// 本機副本在磁碟上的位置（沒有副本、或還在等寫出時是 None：不為了抽樣多下載）
    pub copy: Option<PathBuf>,
    /// 被記憶體控制停用中（停用中不抽）
    pub unloaded: bool,
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
/// 開機用本機副本建好、而且每份清單都有副本：1 分鐘後再問有沒有更新（之後照上次檢查的時間等到更新間隔）
pub const ALL_COPIES_WAIT: Duration = Duration::from_secs(60);
/// 開機用本機副本建好、但有清單沒有副本：這麼久（再加 0～[`MISSING_FETCH_JITTER_MS`] 亂數）之後只下載缺的那幾份
/// （3.5.0 C6；以前跟「全部都有副本」一樣等 60 秒，缺的清單開機後約 63 秒規則都不在）。
/// 這 10 秒讓開機的路徑檢查、bootstrap、對時先跑，下載不跟它們搶記憶體與網路：不再縮短
pub const MISSING_FETCH_WAIT: Duration = Duration::from_secs(10);
/// 缺副本清單下載前的亂數（毫秒，上限）：很多台同時重新開機（停電後）不會同一秒去問同一個清單伺服器
pub const MISSING_FETCH_JITTER_MS: u64 = 5_000;
/// 開機時等對時、等記憶體的每次間隔
const BOOT_POLL: Duration = Duration::from_secs(5);
/// 等對時最多這麼多次（[`BOOT_POLL`] × 120 = 10 分鐘，同以前）
const BOOT_CLOCK_POLLS: u32 = 120;
/// 補缺的清單前，記憶體「偏低」最多等這麼多次（× 5 秒 = 50 秒：最晚跟以前的 63 秒差不多時開始，偏低不是不下載）
const BOOT_LOW_POLLS: u32 = 10;
/// 記憶體「不足」最多等這麼多次（× 5 秒 = 30 分鐘，同定時更新）；還是不足就交給定時更新的迴圈（它照樣等）
const BOOT_CRITICAL_POLLS: u32 = 360;

/// 開機排程用的等待函式回傳的 future
pub type SleepFut = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

/// 開機排程（[`FilterService::boot`]）用到的時鐘、對時與記憶體狀態：正式執行用 [`BootHooks::real`]，
/// 測試注入假的（不必真的等、可以控制對時與記憶體狀態）
pub struct BootHooks {
    pub sleep: Box<dyn Fn(Duration) -> SleepFut + Send + Sync>,
    pub synced: Box<dyn Fn() -> bool + Send + Sync>,
    pub pressure: Box<dyn Fn() -> crate::sysinfo::Pressure + Send + Sync>,
    /// 補缺的清單前多等的亂數（毫秒，最多 [`MISSING_FETCH_JITTER_MS`]）
    pub jitter_ms: u64,
}

impl BootHooks {
    pub fn real() -> BootHooks {
        let jitter_ms = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos() as u64)
            % (MISSING_FETCH_JITTER_MS + 1);
        BootHooks {
            sleep: Box::new(|d| Box::pin(tokio::time::sleep(d))),
            synced: Box::new(crate::clock::synced),
            pressure: Box::new(crate::app::pressure),
            jitter_ms,
        }
    }
}

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
    /// 上次成功檢查更新的時間（Unix 秒；3.4.2 起，舊版的索引沒有是 0）：重新啟動後不必馬上再問一次
    pub checked: u64,
    /// 上次還是啟用中的清單的時間（Unix 秒；3.5.1 起，每天最多記一次，舊版的索引沒有是 0）：
    /// 不在設定裡（或停用）超過 [`COPY_GRACE_SECS`] 的副本刪掉（[`ListCopies::prune`]）
    pub used: u64,
}

impl CopyMeta {
    /// 最後一次還用得到的時間：啟用中的記號、下載、檢查更新取最晚的（舊版的索引沒有 `used`）
    fn last_used(&self) -> u64 {
        self.used.max(self.at).max(self.checked)
    }
}

/// 不在設定裡、或停用中的清單，副本留多久（秒）：期間重新啟用不必重新下載（3.5.1）
pub const COPY_GRACE_SECS: u64 = 7 * 86400;

/// [`ListCopies::stream`] 送回來的一段
pub enum CopyChunk {
    Data(Vec<u8>),
    /// 讀完了：內容雜湊對不對（false = 副本壞了）
    End(bool),
}

/// zstd 壓縮的清單內容：解壓縮在 blocking 執行緒做，內容一段一段（64 KB）從 channel 送回來，最後核對內容雜湊。
/// `open` 在 blocking 執行緒裡呼叫（打開檔案、或包一份記憶體裡的內容）
fn stream_zstd<R, F>(open: F, hash: u64) -> tokio::sync::mpsc::Receiver<CopyChunk>
where
    R: Read,
    F: FnOnce() -> Option<R> + Send + 'static,
{
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tokio::task::spawn_blocking(move || {
        let ok = (|| {
            let mut dec = zstd::stream::read::Decoder::new(open()?).ok()?;
            let mut h = std::collections::hash_map::DefaultHasher::new();
            let mut n = 0u64;
            loop {
                let mut buf = vec![0u8; 64 * 1024];
                match dec.read(&mut buf) {
                    Ok(0) => break,
                    Ok(k) => {
                        buf.truncate(k);
                        h.write(&buf);
                        n += k as u64;
                        // 收的那一端不要了（重建取消）：停下來
                        tx.blocking_send(CopyChunk::Data(buf)).ok()?;
                    }
                    Err(_) => return None,
                }
            }
            h.write_u64(n);
            Some(h.finish() == hash)
        })()
        .unwrap_or(false);
        let _ = tx.blocking_send(CopyChunk::End(ok));
    });
    rx
}

/// 下載到、但這時候存不了本機副本的清單（zstd）：留在記憶體，重建時讀它，不必再從網路下載（3.4.2）。
/// 不存檔；空間與記憶體都夠了之後存成本機副本（[`FilterService::persist_held`]）
#[derive(Clone)]
struct Held {
    hash: u64,
    z: Arc<Vec<u8>>,
    v: Validators,
    /// 這份內容是什麼時候下載的（Unix 秒）：存成本機副本時當成「上次檢查更新」的時間，
    /// 重新啟動後才會照更新間隔檢查，不會一分鐘後就把剛下載過的清單整份再問一次（3.4.3，Windows 複驗 G3）
    fetched: u64,
}

/// 記憶體裡最多留多少（壓縮後合計）
const HELD_MAX: u64 = 8 << 20;

struct HeldBytes(Arc<Vec<u8>>);

impl AsRef<[u8]> for HeldBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

async fn feed_stream(mut rx: tokio::sync::mpsc::Receiver<CopyChunk>, w: &mut kuroshio_filter::SourceWriter<'_>) -> bool {
    while let Some(m) = rx.recv().await {
        match m {
            CopyChunk::Data(d) => w.feed(&d),
            CopyChunk::End(ok) => return ok,
        }
    }
    false
}

/// 把副本邊收邊交給清單的寫入端（每一段之間讓出執行緒）。回傳有沒有完整讀到
async fn feed_copy(c: &ListCopies, url: &str, w: &mut kuroshio_filter::SourceWriter<'_>) -> bool {
    let Some(rx) = c.stream(url) else { return false };
    feed_stream(rx, w).await
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
                            checked: n("checked"),
                            used: n("used"),
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

    /// 有這份清單的副本、內容雜湊是 `hash`，而且檔案還在（3.4.2：空間不夠時副本檔會被刪掉、索引還留著；
    /// 以前只比索引裡的雜湊，串接同步就當成「一樣、不用傳」，重建時沒有檔案又從網路下載）
    pub fn available_same(&self, url: &str, hash: u64) -> bool {
        self.meta(url).is_some_and(|m| m.hash == hash) && self.available(url)
    }

    /// 讀副本，但解壓縮在 blocking 執行緒做，內容一段一段（64 KB）從 channel 送回來：
    /// 呼叫端在 async 裡邊收邊解析，每一段之間會讓出執行緒，重建大清單時 DNS 照常回答。沒有副本回傳 None
    pub fn stream(&self, url: &str) -> Option<tokio::sync::mpsc::Receiver<CopyChunk>> {
        let m = self.meta(url)?;
        let (pending, path) = {
            let p = self.persister.lock().unwrap();
            (p.pending_bytes(&m.file), p.file_path(&m.file))
        };
        // 還沒寫到磁碟（登記之後要等下一輪快照）：讀記憶體裡的待寫內容。以前直接開檔，開不到就當成副本壞掉、
        // 整份重新下載（3.4.2 Windows 複驗：留在記憶體的清單存成副本後、下一輪快照前恢復清單，又全部下載一次）
        if let Some(z) = pending {
            return Some(stream_zstd(move || Some(std::io::Cursor::new(z)), m.hash));
        }
        Some(stream_zstd(move || std::fs::File::open(&path).ok(), m.hash))
    }

    /// 讀副本（解壓後一段一段交給 `feed`）。回傳有沒有讀到
    pub fn read(&self, url: &str, feed: &mut dyn FnMut(&[u8])) -> bool {
        let Some(m) = self.meta(url) else { return false };
        let (pending, path) = {
            let p = self.persister.lock().unwrap();
            (p.pending_bytes(&m.file), p.file_path(&m.file))
        };
        // 還沒寫到磁碟：讀待寫內容（同 `stream`）
        let src: Box<dyn Read> = match pending {
            Some(z) => Box::new(std::io::Cursor::new(z)),
            None => match std::fs::File::open(&path) {
                Ok(f) => Box::new(f),
                Err(_) => return false,
            },
        };
        let Ok(mut dec) = zstd::stream::read::Decoder::new(src) else {
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
            let checked = idx.get(url).map_or(0, |m| m.checked);
            let used = idx.get(url).map_or(0, |m| m.used);
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
                    checked,
                    used,
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

    /// 這幾份清單剛檢查過更新（全部沒變、或有變的已經下載換上）：記下時間。每次定時更新最多寫一次小小的索引。
    /// 只往後記：留在記憶體的清單存成副本時記的是下載時間，不能把已經記著、比較新的檢查時間蓋回去
    pub fn note_checked(&self, urls: &[&str], now: u64) {
        let mut idx = self.index.lock().unwrap();
        let mut any = false;
        for u in urls {
            if let Some(m) = idx.get_mut(*u).filter(|m| m.checked < now) {
                m.checked = now;
                any = true;
            }
        }
        if !any {
            return;
        }
        let body = Self::index_json(&idx);
        drop(idx);
        self.persister.lock().unwrap().stage(COPY_INDEX, body);
    }

    /// 這幾份清單「最早」的上次檢查時間；有一份沒有副本或沒記過就是 None（照舊開機後就檢查）
    pub fn last_checked(&self, urls: &[&str]) -> Option<u64> {
        let idx = self.index.lock().unwrap();
        let mut min: Option<u64> = None;
        for u in urls {
            let c = idx.get(*u).map(|m| m.checked).filter(|&c| c > 0)?;
            min = Some(min.map_or(c, |m: u64| m.min(c)));
        }
        min
    }

    /// 補記規則數（索引裡是 0 的時候）。索引內容沒變時快照寫入器不會重寫
    pub fn note_rules(&self, url: &str, rules: u64) {
        let mut idx = self.index.lock().unwrap();
        let Some(m) = idx.get_mut(url).filter(|m| m.rules == 0 && rules > 0) else {
            return;
        };
        m.rules = rules;
        let body = Self::index_json(&idx);
        drop(idx);
        self.persister.lock().unwrap().stage(COPY_INDEX, body);
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
                    json!({ "hash": format!("{:016x}", c.hash), "etag": c.etag, "lastModified": c.last_modified, "bytes": c.bytes, "at": c.at, "rules": c.rules, "checked": c.checked, "used": c.used }),
                )
            })
            .collect();
        serde_json::to_vec(&Value::Object(m)).unwrap_or_default()
    }

    /// 清理不再使用的副本（3.5.1）：`active` = 設定裡啟用中的清單網址。
    ///
    /// - 啟用中的：記下「還在用」的時間（每天最多更新一次索引）
    /// - 不在 `active` 裡（從設定拿掉、或停用中）而且最後一次用到（[`CopyMeta::last_used`]）超過 `grace` 秒：
    ///   索引拿掉、副本檔刪掉。寬限期內重新啟用就直接讀副本，不必重新下載
    ///
    /// 以前只會新增、更新，從設定拿掉的清單副本一直留在磁碟上，狀態頁的副本份數也算進去。
    /// 回傳（刪掉幾份, 釋出的 bytes）
    pub fn prune(&self, active: &[&str], now: u64, grace: u64) -> (usize, u64) {
        let mut idx = self.index.lock().unwrap();
        let mut changed = false;
        let mut gone: Vec<String> = Vec::new();
        for (url, m) in idx.iter_mut() {
            if active.contains(&url.as_str()) {
                if now >= m.used.saturating_add(86400) {
                    m.used = now;
                    changed = true;
                }
            } else if now.saturating_sub(m.last_used()) > grace {
                gone.push(url.clone());
            }
        }
        if gone.is_empty() && !changed {
            return (0, 0);
        }
        let files: Vec<String> = gone.iter().filter_map(|u| idx.remove(u)).map(|m| m.file).collect();
        let body = Self::index_json(&idx);
        drop(idx);
        let mut p = self.persister.lock().unwrap();
        let freed = files.iter().map(|f| p.discard(f)).sum();
        p.stage(COPY_INDEX, body);
        (files.len(), freed)
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
    /// 通訊類網域（推播）不被清單誤擋（`filter.protectComm`，預設開；自訂規則照樣優先，3.5.0）
    protect_comm: bool,
    /// 清單本來要擋、因為是通訊類或內建服務而放行的次數（合計與每一類，`CommKind::index()` 的順序）；
    /// 每一類上一次記 INFO 的日數（每一類每天第一次記一行，3.5.0 F11）
    comm_spared: AtomicU32,
    comm_spared_by: [AtomicU32; 8],
    comm_logged_day: [AtomicU32; 8],
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
    /// 清單層重建了幾次（測試與狀態用；32 位元平台沒有 64 位元原子操作）
    rebuilds: AtomicU32,
    /// 下載到、但這台這時候存不了副本的清單（網址 → 內容），見 [`Held`]
    held: Mutex<HashMap<String, Held>>,
}

/// 錯誤是不是「工作被取消」（runtime 結束時 `spawn_blocking` 的工作）
fn is_cancelled(e: &anyhow::Error) -> bool {
    e.chain()
        .any(|c| c.downcast_ref::<tokio::task::JoinError>().is_some_and(|j| j.is_cancelled()))
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

/// 一次要停用哪幾份（3.5.0 C3）：依停用順序（`order`，保護清單本來就不在裡面）累加估計大小，取到合計 ≥ `target` 為止；
/// 至少 1 份（`target` = 0 就是只停用一份，同以前）
pub fn pick_shed(order: &[usize], sizes: &[u64], target: u64) -> Vec<usize> {
    let mut acc = 0u64;
    let mut out = Vec::new();
    for &i in order {
        if !out.is_empty() && acc >= target {
            break;
        }
        acc = acc.saturating_add(sizes.get(i).copied().unwrap_or(0));
        out.push(i);
    }
    out
}

/// 一次要恢復幾份（3.5.0 C3）：從最後停用的開始（`bytes` 是停用順序），取到合計 × 1.3 ≤ `room` 為止；
/// 至少 1 份（記憶體控制已經確認最後一份放得下；同以前一次一份的條件）。回傳份數（從尾端算）
pub fn pick_restore(bytes: &[u64], room: u64) -> usize {
    let mut acc: u128 = 0;
    let mut n = 0;
    for &b in bytes.iter().rev() {
        let next = acc + b as u128;
        if n > 0 && next * 13 / 10 > room as u128 {
            break;
        }
        acc = next;
        n += 1;
    }
    n
}

/// 清單名稱列一行（最多 5 個，其他寫「等 N 份」）
fn names_line(names: &[&str]) -> String {
    let mut s = names.iter().take(5).copied().collect::<Vec<_>>().join("、");
    if names.len() > 5 {
        s.push_str(&format!(" 等 {} 份", names.len()));
    }
    s
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
            protect_comm: g("protectComm").and_then(Value::as_bool) != Some(false),
            comm_spared: AtomicU32::new(0),
            comm_spared_by: Default::default(),
            comm_logged_day: Default::default(),
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
            rebuilds: AtomicU32::new(0),
            held: Mutex::new(HashMap::new()),
        }))
    }

    pub fn sources(&self) -> &[ListSource] {
        &self.sources
    }

    /// 惡意網站探測可以抽樣的清單（3.5.0 F10）：名稱、副本路徑、是不是停用中。唯讀，不下載、不重建。
    ///
    /// - 只列 `probe` 的清單（[`ListSource::probe`]：惡意類、啟用中、不是 TW165／TWNIC-RPZ／新註冊網域／繞過防護，
    ///   或設定明寫 `probe: true`）。
    /// - `copy`：副本**已經寫在磁碟上**才有（索引有、檔案在）；沒有副本、或還在等寫出時是 None——抽樣不為了它多下載，
    ///   也不讀還在記憶體裡等寫出的內容。
    /// - `unloaded`：被記憶體控制停用中，或全部清單暫停中
    pub fn probe_sources(&self) -> Vec<ProbeSource> {
        let ex = self.excluded();
        let all = self.all_suspended();
        let copies = self.copies.get();
        self.sources
            .iter()
            .enumerate()
            .filter(|(_, s)| s.probe)
            .map(|(i, s)| ProbeSource {
                url: s.url.clone(),
                name: s.name.clone(),
                copy: copies.and_then(|c| {
                    let m = c.meta(&s.url)?;
                    let p = c.persister.lock().unwrap();
                    if p.is_pending(&m.file) {
                        return None;
                    }
                    Some(p.file_path(&m.file)).filter(|f| f.is_file())
                }),
                unloaded: all || ex.get(i).copied().unwrap_or(false),
            })
            .collect()
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

    /// 下載到、但這時候存不了副本的清單能不能先留在記憶體：不看記憶體能不能長大（內容已經下載進來了，
    /// 丟掉的話下一次重建又要整份下載），只看合計不超過 [`HELD_MAX`]；記憶體已經「不足」時不留（跟以前一樣）
    fn held_room(&self, url: &str, size: u64) -> bool {
        if crate::app::pressure() == crate::sysinfo::Pressure::Critical {
            return false;
        }
        let used: u64 = self
            .held
            .lock()
            .unwrap()
            .iter()
            .filter(|(u, _)| *u != url)
            .map(|(_, h)| h.z.len() as u64)
            .sum();
        used + size <= HELD_MAX
    }

    /// 留在記憶體的副本份數與大小（狀態頁）
    pub fn held_stats(&self) -> (usize, u64) {
        let h = self.held.lock().unwrap();
        (h.len(), h.values().map(|x| x.z.len() as u64).sum())
    }

    /// 記憶體又能長大時：留在記憶體的清單內容存成本機副本，存得下的從記憶體拿掉（Windows 3.4.2 驗證：
    /// 吃緊時下載、留在記憶體的 10 份清單，恢復、能長大之後一直沒有寫出，重新啟動時又整份下載 12 MB）。
    /// 只在本機登記寫出，不連網路；空間不夠（`offer` 不收）的照舊留在記憶體。回傳存成副本的份數
    pub fn persist_held(&self) -> usize {
        let Some(c) = self.copies.get() else { return 0 };
        if !crate::memgov::growth_allowed() {
            return 0;
        }
        // 先看空間存不存得下，存得下的才拿出來（D3 這種小 Flash 一直存不下：不要每次恢復都把最多 8 MB 白複製一次）
        let items: Vec<(String, Held)> = self
            .held
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, h)| c.wanted(h.z.len() as u64))
            .map(|(u, h)| (u.clone(), h.clone()))
            .collect();
        if items.is_empty() {
            return 0;
        }
        let now = crate::persist::now_secs();
        let mut n = 0;
        for (url, h) in items {
            let rules = self
                .sources
                .iter()
                .position(|s| s.url == url)
                .map_or(0, |i| self.sizes.lock().unwrap()[i].1);
            let staged = c.offer(&url, h.hash, Some(h.z.as_ref().clone()), &h.v, now, rules);
            if staged || c.available_same(&url, h.hash) {
                // 內容是 `fetched` 那時下載的：記成上次檢查時間（沒記的話索引是 0，重新啟動一分鐘後就整份檢查）
                if h.fetched > 0 {
                    c.note_checked(&[url.as_str()], h.fetched.min(now));
                }
                self.held.lock().unwrap().remove(&url);
                n += 1;
            }
        }
        if n > 0 {
            info!("記憶體恢復：{n} 份留在記憶體的清單存成本機副本");
        }
        n
    }

    /// 用「副本優先」重建一次（既有的重建入口；全部清單暫停中時不建）。
    /// 重建只讀磁碟上的副本：剛登記、還在等寫出的副本先寫出去
    pub async fn rebuild_from_copies(&self) -> anyhow::Result<bool> {
        let _g = self.rebuild_lock.lock().await;
        if self.all_suspended() || self.sources.is_empty() {
            return Ok(false);
        }
        if let Some(c) = self.copies.get() {
            let p = c.persister.clone();
            tokio::task::spawn_blocking(move || p.lock().unwrap().flush_all(crate::persist::now_secs())).await??;
        }
        self.rebuild_mode(Source::PreferCopy, &[]).await.map(|_| true)
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
                    info!("過濾清單：用本機副本先建好，{missing} 份沒有副本");
                } else {
                    info!("過濾清單：用本機副本建好（不必等下載），稍後檢查有沒有更新");
                }
                true
            }
            Err(e) if is_cancelled(&e) => {
                // 重新載入（或停止）時舊的 runtime 結束、建到一半的工作被取消：新的 runtime 會重新用副本建，不是失敗（3.4.1）
                info!("過濾清單：重新載入中斷了用本機副本建立的工作，由新的設定接手");
                false
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
        self.prune_copies();
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
                self.note_checked(&active);
                return Ok(false);
            }
        }
        // 2. 載入前先看記憶體預算：量過大小的清單估計會超過，就依停用順序先不載入（看得到原因）
        self.fit_allowance();
        let r = self.rebuild_mode(Source::Download, &reuse).await.map(|_| true);
        let failed = self.status.lock().unwrap()["errors"].as_array().is_some_and(|a| !a.is_empty());
        if r.is_ok() && !failed && self.missing.lock().unwrap().is_empty() && self.unloaded.lock().unwrap().is_empty() {
            self.note_checked(&active);
        }
        r
    }

    /// 清單副本的清理（[`ListCopies::prune`]）：每次檢查更新時做一次（每天最多幾次、背景）。
    /// 系統時間還沒對時不做（時間不可信時算不出寬限期）
    fn prune_copies(&self) {
        let Some(c) = self.copies.get() else { return };
        if !crate::clock::synced() {
            return;
        }
        let active: Vec<&str> = self.sources.iter().map(|s| s.url.as_str()).collect();
        let (n, bytes) = c.prune(&active, crate::persist::now_secs(), COPY_GRACE_SECS);
        if n > 0 {
            info!(
                "刪掉 {n} 份已經不在設定裡（或停用超過 {} 天）的過濾清單副本，釋出 {} KB",
                COPY_GRACE_SECS / 86400,
                bytes / 1024
            );
        }
    }

    /// 記下這幾份清單剛檢查過更新
    fn note_checked(&self, active: &[usize]) {
        if let Some(c) = self.copies.get() {
            let urls: Vec<&str> = active.iter().map(|&i| self.sources[i].url.as_str()).collect();
            c.note_checked(&urls, crate::persist::now_secs());
        }
    }

    /// 開機用副本建好之後，離下一次該檢查更新還有多久：全部清單都有副本、都記過上次檢查時間，
    /// 而且還沒到更新間隔才有值（重新啟動、重新載入不再一分鐘後就把清單全部問一次、有變的整份重新下載）
    pub fn first_check_delay(&self, now: u64) -> Option<Duration> {
        self.check_delay(now, &[])
    }

    /// 同 [`first_check_delay`](Self::first_check_delay)，但 `fresh` 這幾份是剛剛才下載的（開機補缺的清單，3.5.0 C6）：
    /// 不算「缺」，也不看它們的上次檢查時間（存不了副本的清單沒有索引，否則永遠是「馬上全部檢查」）
    fn check_delay(&self, now: u64, fresh: &[usize]) -> Option<Duration> {
        let c = self.copies.get()?;
        // 沒有本機副本的清單：留在記憶體的不算（重建時讀它）
        let missing_unheld = self.missing_unheld().iter().any(|i| !fresh.contains(i));
        // 記憶體控制暫時停用的清單（reason = "memory"）本機副本都還在，恢復時由 `restore_one` 用副本重建，
        // 不算「缺清單」：以前這種情況會跳過更新間隔、立刻整份檢查，記憶體正吃緊時反而從網路下載
        // （3.4.2 Windows 實測：重新啟動 11 分鐘後、系統可用記憶體接近 0 時從網路收了 4.97 MB）
        let budget_unloaded = self.unloaded.lock().unwrap().iter().any(|u| u.reason != "memory");
        if missing_unheld || budget_unloaded {
            return None;
        }
        let ex = self.excluded();
        let urls: Vec<&str> = (0..self.sources.len())
            .filter(|&i| !ex[i] && !fresh.contains(&i))
            .map(|i| self.sources[i].url.as_str())
            .collect();
        if urls.is_empty() {
            return None;
        }
        let last = c.last_checked(&urls)?;
        // 時間倒退（還沒對時、或改過系統時間）：照舊馬上檢查
        if last > now {
            return None;
        }
        let next = last.saturating_add(self.interval.as_secs());
        (next > now).then(|| Duration::from_secs(next - now))
    }

    /// 開機只用副本建的時候沒有副本、這次沒載入，而且也沒有留在記憶體的清單（依清單順序）
    fn missing_unheld(&self) -> Vec<usize> {
        let held = self.held.lock().unwrap();
        self.missing
            .lock()
            .unwrap()
            .iter()
            .copied()
            .filter(|&i| !held.contains_key(&self.sources[i].url))
            .collect()
    }

    /// 只補開機時沒有副本的清單（3.5.0 C6）：缺的下載，有副本的照讀副本、**不發請求**（不在開機時把每份清單都問一遍）。
    /// 回傳這次下載成功、載入的清單。下載失敗的記在狀態的 `errors`（由定時更新照既有的退避重試）
    pub async fn update_missing(&self) -> anyhow::Result<Vec<usize>> {
        let _g = self.rebuild_lock.lock().await;
        if self.all_suspended() || self.sources.is_empty() {
            return Ok(Vec::new());
        }
        let want = self.missing_unheld();
        if want.is_empty() {
            return Ok(Vec::new());
        }
        self.fit_allowance();
        let reuse: Vec<bool> = (0..self.sources.len()).map(|i| !want.contains(&i)).collect();
        self.rebuild_mode(Source::Download, &reuse).await?;
        let ex = self.excluded();
        let lists = self.lists.read().unwrap().clone();
        let st = lists.stats();
        let done: Vec<usize> = want
            .into_iter()
            .filter(|&i| !ex[i] && st.sources.get(i).is_some_and(|s| s.status == SourceStatus::Loaded))
            .collect();
        // 剛下載的就是剛檢查過（存成副本的才有索引可以記）
        self.note_checked(&done);
        Ok(done)
    }

    /// 開機時等對時（下載要 TLS；路由器開機時常是 1970），最多 10 分鐘
    async fn boot_wait_clock(&self, h: &BootHooks) {
        if (h.synced)() {
            return;
        }
        info!("系統時間還沒對時：過濾清單等對時後再下載");
        for _ in 0..BOOT_CLOCK_POLLS {
            (h.sleep)(BOOT_POLL).await;
            if (h.synced)() {
                return;
            }
        }
    }

    /// 開機補缺的清單前看記憶體：不足時等（最多 30 分鐘）、偏低時最多等 50 秒（重建時新舊兩份同時在記憶體裡）。
    /// 回傳現在可不可以下載（還是不足就交給定時更新的迴圈）
    async fn boot_wait_memory(&self, h: &BootHooks) -> bool {
        use crate::sysinfo::Pressure;
        let (mut low, mut critical) = (0u32, 0u32);
        loop {
            match (h.pressure)() {
                Pressure::Normal => return true,
                Pressure::Low if low >= BOOT_LOW_POLLS => return true,
                Pressure::Critical if critical >= BOOT_CRITICAL_POLLS => return false,
                Pressure::Low => {
                    if low == 0 {
                        info!(
                            "記憶體偏低：沒有副本的過濾清單稍等再下載（最多 {} 秒）",
                            BOOT_POLL.as_secs() * BOOT_LOW_POLLS as u64
                        );
                    }
                    low += 1;
                }
                Pressure::Critical => {
                    if critical == 0 {
                        warn!("記憶體不足，延後下載沒有副本的過濾清單（恢復後再下載，最多 30 分鐘）");
                    }
                    critical += 1;
                }
            }
            (h.sleep)(BOOT_POLL).await;
        }
    }

    /// 開機到進入定時更新迴圈之前的排程（3.5.0 C6）：
    ///
    /// 1. 有本機副本的清單先用副本建好過濾器（不必等下載、對時）。
    /// 2. 每份都有副本：1 分鐘後（照舊）；有清單沒有副本：10～15 秒後、對時了、記憶體不是不足，**只下載缺的**。
    /// 3. 上次檢查還沒過更新間隔：等到該檢查的時候（剛補上的清單算剛檢查過）。
    ///
    /// 回傳定時更新迴圈的重試次數起點（補缺的清單下載失敗時已經照退避等過第一次）
    pub async fn boot(&self, h: &BootHooks) -> usize {
        let built = self.build_from_copies().await;
        let mut fresh: Vec<usize> = Vec::new();
        if built {
            let missing = self.missing_unheld();
            if missing.is_empty() {
                (h.sleep)(ALL_COPIES_WAIT).await;
            } else {
                let wait = MISSING_FETCH_WAIT + Duration::from_millis(h.jitter_ms.min(MISSING_FETCH_JITTER_MS));
                let names: Vec<&str> = missing.iter().take(5).map(|&i| self.sources[i].name.as_str()).collect();
                info!(
                    "過濾清單：{} 份沒有副本的 {} 秒後下載（{}{}）",
                    missing.len(),
                    wait.as_secs(),
                    names.join("、"),
                    if missing.len() > 5 { "……" } else { "" }
                );
                (h.sleep)(wait).await;
                self.boot_wait_clock(h).await;
                if !self.boot_wait_memory(h).await {
                    // 還是不足：交給定時更新的迴圈（它照樣先等記憶體）
                    return 0;
                }
                match self.update_missing().await {
                    Ok(done) => fresh = done,
                    Err(e) => warn!("下載沒有副本的過濾清單失敗：{e:#}"),
                }
                let failed =
                    self.status.lock().unwrap()["errors"].as_array().is_some_and(|a| !a.is_empty()) || !self.missing_unheld().is_empty();
                if failed {
                    let w = Duration::from_secs(RETRY_BACKOFF[0]);
                    warn!("有清單還沒載入（下載失敗）：{} 秒後重試", w.as_secs());
                    (h.sleep)(w).await;
                    return 1;
                }
            }
        }
        self.boot_wait_clock(h).await;
        // 3.4.3 起清單一律自己跟清單網址下載（不跟上游黑潮拿副本），不必等串接確定
        // 上次檢查還沒過更新間隔（重新啟動、重新載入、換版）：等到該檢查的時候，不必一開機就全部問一次
        if built {
            if let Some(w) = self.check_delay(crate::persist::now_secs(), &fresh) {
                info!(
                    "過濾清單：{} 分鐘前檢查過更新，{} 分鐘後再檢查",
                    (self.interval.saturating_sub(w)).as_secs() / 60,
                    w.as_secs() / 60
                );
                (h.sleep)(w).await;
            }
        }
        0
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
        let fits = |total: u64, peak: u64| total <= steady && room.is_none_or(|r| peak <= r);
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
        self.rebuilds.fetch_add(1, Ordering::Relaxed);
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
            b.reserve((expect + expect / 20).min(max_domains) as usize);
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
                let held = self.held.lock().unwrap().get(&s.url).cloned();
                if let Some(h) = held {
                    let z = h.z.clone();
                    let rx = stream_zstd(move || Some(std::io::Cursor::new(HeldBytes(z))), h.hash);
                    if feed_stream(rx, &mut w).await {
                        w.end();
                        validators.push(h.v);
                        continue;
                    }
                    // 壞掉（不該發生：收的時候驗過雜湊）：丟掉，改用本機副本或下載
                    self.held.lock().unwrap().remove(&s.url);
                    w.reset();
                }
                if let Some(c) = copies.filter(|c| c.available(&s.url)) {
                    if feed_copy(c, &s.url, &mut w).await {
                        // 舊版（3.3.2 以前）寫的副本沒有記規則數：讀到時補記（記憶體規劃、截斷檢查要用）
                        c.note_rules(&s.url, w.rules());
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
            // 存不了副本（記憶體還不能長大）時，下載到的內容先留在記憶體（合計最多 HELD_MAX）：
            // 記憶體恢復時是一份一份清單重建，每次重建都會把「沒有副本」的清單整份再下載一次
            // （3.4.2 Windows 壓力測試：恢復 7 份清單、每 30 秒一次，10 分鐘從網路收了 44.4 MB）
            let persist = copies.is_some_and(|c| c.wanted(estimate));
            let hold = copies.is_some() && !persist && self.held_room(&s.url, estimate);
            let mut sink = CopySink::new(persist || hold);
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
                        if persist {
                            if c.offer(&s.url, h, z, &v, crate::persist::now_secs(), rules) || c.available_same(&s.url, h) {
                                self.held.lock().unwrap().remove(&s.url);
                            }
                        } else if let Some(z) = z.filter(|z| hold && self.held_room(&s.url, z.len() as u64)) {
                            // 估計值可能比實際小（沒存過副本的清單估 1 MiB）：用壓縮後的實際大小再檢查一次上限
                            self.held.lock().unwrap().insert(
                                s.url.clone(),
                                Held {
                                    hash: h,
                                    z: Arc::new(z),
                                    v: v.clone(),
                                    fetched: crate::persist::now_secs(),
                                },
                            );
                        }
                    }
                    validators.push(v)
                }
                Ok(Outcome::NotModified) => {
                    w.end();
                    validators.push(Validators::default())
                }
                Err(e) => {
                    // 下載失敗：有本機副本就拿副本頂著（這份清單不會整份不見）
                    let fallback = match copies.filter(|c| c.available(&s.url)) {
                        Some(c) => {
                            w.reset();
                            feed_copy(c, &s.url, &mut w).await
                        }
                        None => false,
                    };
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
        // 建索引（排序、壓縮）也是大量計算：放到 blocking 執行緒，不佔住回答查詢的執行緒
        let f = tokio::task::spawn_blocking(move || b.finish()).await?;
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

    /// 資料新鮮度（3.5.0 E1）：（上次成功的毫秒：重建好、或檢查過都沒變；失敗的清單數；更新間隔毫秒）
    pub fn freshness(&self) -> (Option<u64>, usize, u64) {
        let st = self.status.lock().unwrap();
        let ms = |k: &str| st.get(k).and_then(Value::as_u64).filter(|t| *t > 0);
        let last = match (ms("updatedAt"), ms("checkedAt")) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        let errors = st.get("errors").and_then(Value::as_array).map_or(0, Vec::len);
        (last, errors, self.interval.as_millis() as u64)
    }

    /// 發現清單（3.5.0 E2 的 `list-copy-no-room`）：載入中、但沒有本機副本的清單數
    /// （空間不足時不留副本；下次重建要重新下載）。沒有副本功能（沒有快照目錄）是 `None`
    pub fn lists_without_copy(&self) -> Option<usize> {
        let c = self.copies.get()?;
        let l = self.lists.read().unwrap().clone();
        let st = l.stats();
        Some(
            st.sources
                .iter()
                .zip(&self.sources)
                .filter(|(s, src)| s.status == SourceStatus::Loaded && c.meta(&src.url).is_none())
                .count(),
        )
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

    /// 清單層重建了幾次（開機以來）
    pub fn rebuild_count(&self) -> u32 {
        self.rebuilds.load(Ordering::Relaxed)
    }

    /// 記憶體控制：停用下一份清單（同 [`unload_many`](Self::unload_many) 的 `target` = 0；測試與手動路徑用）
    pub async fn unload_one(&self) -> anyhow::Result<Option<Unloaded>> {
        Ok(self.unload_many(0, None).await?.into_iter().next())
    }

    /// 記憶體控制（3.5.0 C3）：依停用順序取到估計合計 ≥ `target` bytes 的幾份清單（至少 1 份；保護清單不在候選裡），
    /// **一次**登記停用、**只重建一次**（以前一份一份停用，缺口大時連續重建 N 次，每次新舊兩份同時在記憶體裡）。
    /// 重建期間舊的過濾器照常使用；有本機副本的清單讀副本，沒有的才下載。
    ///
    /// `max_after`：停用這幾份之後的清單層估計大小超過它就不做（重建時新舊兩份並存：新的一份放不進可用記憶體的一半就不做）。
    /// 一次停用多份時新的一份比較小，重建的尖峰（舊的 + 新的）比一次一份的第一次還低。
    ///
    /// 沒有可以停用的回傳空的；重建失敗（下載失敗而且原本有清單）時這次登記的全部撤回、清單不算停用
    pub async fn unload_many(&self, target: u64, max_after: Option<u64>) -> anyhow::Result<Vec<Unloaded>> {
        let _g = self.rebuild_lock.lock().await;
        let order = self.shed_candidates();
        if order.is_empty() {
            return Ok(Vec::new());
        }
        let sz: Vec<(u64, u64)> = self.sizes.lock().unwrap().clone();
        let est: Vec<u64> = sz.iter().map(|s| s.0).collect();
        let pick = pick_shed(&order, &est, target);
        let est_total: u64 = pick.iter().map(|&i| est[i]).sum();
        if let Some(max) = max_after {
            let after = self.lists_bytes().saturating_sub(est_total);
            if after > max {
                anyhow::bail!("可用記憶體不足以安全重建過濾器（需要約 {} KB）", after / 1024);
            }
        }
        let at = crate::persist::now_secs() * 1000;
        let batch: Vec<Unloaded> = pick
            .iter()
            .map(|&i| Unloaded {
                idx: i,
                name: self.sources[i].name.clone(),
                rules: sz[i].1,
                bytes: 0,
                reason: "memory",
                at,
            })
            .collect();
        self.unloaded.lock().unwrap().extend(batch.iter().cloned());
        match self.rebuild_mode(Source::PreferCopy, &[]).await {
            Ok((before, after)) => {
                // 實測的差額依估計大小分給各份（恢復時要有這麼多空間的 1.3 倍）；實測比估計小時用估計（保守）
                let measured = before.saturating_sub(after).max(est_total);
                let n = pick.len() as u64;
                let share = |i: usize| -> u64 {
                    if est_total == 0 {
                        measured / n
                    } else {
                        (est[i] as u128 * measured as u128 / est_total as u128) as u64
                    }
                };
                let mut list = self.unloaded.lock().unwrap();
                let mut out = Vec::with_capacity(pick.len());
                for &i in &pick {
                    if let Some(x) = list.iter_mut().find(|x| x.idx == i && x.reason == "memory") {
                        x.bytes = share(i);
                        out.push(x.clone());
                    }
                }
                drop(list);
                let rules: u64 = out.iter().map(|u| u.rules).sum();
                let names: Vec<&str> = out.iter().map(|u| u.name.as_str()).collect();
                warn!(
                    "記憶體不足，暫時停用 {} 份清單：{}（{rules} 條規則，釋出約 {} KB，重建 1 次）",
                    out.len(),
                    names_line(&names),
                    measured / 1024
                );
                Ok(out)
            }
            Err(e) => {
                self.unloaded.lock().unwrap().retain(|x| !pick.contains(&x.idx));
                Err(e)
            }
        }
    }

    /// 記憶體控制：恢復最後停用的清單（同 [`restore_many`](Self::restore_many) 只恢復一份；測試與手動路徑用）
    pub async fn restore_one(&self) -> anyhow::Result<Option<Unloaded>> {
        Ok(self.restore_many(0).await?.into_iter().next())
    }

    /// 記憶體控制（3.5.0 C3）：從最後停用的開始，取到合計 × 1.3 ≤ `room` 的幾份（至少 1 份），**重建一次**一起恢復
    /// （以前一份一份恢復、每份重建一次：3.4.2 Windows 實測恢復 7 份重建 7 次）。有本機副本的讀副本；沒有的下載
    /// （留在記憶體的副本讓每份最多下載一次）。下載失敗時這幾份維持停用，由呼叫端退避重試；
    /// 放不下（超過預算）的維持停用，其他照樣恢復
    pub async fn restore_many(&self, room: u64) -> anyhow::Result<Vec<Unloaded>> {
        let _g = self.rebuild_lock.lock().await;
        if self.all_suspended() {
            anyhow::bail!("全部清單暫停中，先恢復全部清單");
        }
        let batch: Vec<Unloaded> = {
            let mut list = self.unloaded.lock().unwrap();
            let bytes: Vec<u64> = list.iter().map(|u| u.bytes).collect();
            let n = pick_restore(&bytes, room);
            let at = list.len() - n;
            list.split_off(at)
        };
        if batch.is_empty() {
            return Ok(Vec::new());
        }
        match self.rebuild_mode(Source::PreferCopy, &[]).await {
            Ok(_) => {
                let lists = self.lists.read().unwrap().clone();
                let st = lists.stats();
                let (ok, still): (Vec<Unloaded>, Vec<Unloaded>) = batch
                    .into_iter()
                    .partition(|u| st.sources.get(u.idx).map(|s| s.status) == Some(SourceStatus::Loaded));
                if !still.is_empty() {
                    // 超過 maxDomains / 預算：還是載不進來，維持停用（順序不變）
                    let names: Vec<&str> = still.iter().map(|u| u.name.as_str()).collect();
                    let line = names_line(&names);
                    self.unloaded.lock().unwrap().extend(still);
                    if ok.is_empty() {
                        anyhow::bail!("清單「{line}」還是放不下（超過預算），維持停用");
                    }
                    warn!("清單「{line}」還是放不下（超過預算），維持停用");
                }
                let names: Vec<&str> = ok.iter().map(|u| u.name.as_str()).collect();
                info!("記憶體恢復，重新啟用 {} 份清單：{}（重建 1 次）", ok.len(), names_line(&names));
                Ok(ok)
            }
            Err(e) => {
                self.unloaded.lock().unwrap().extend(batch);
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
        set_current(self);
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
            // 「立即更新」（管理介面、API）結束的通知：先訂閱，開機補缺期間結束的那一次也看得到
            let mut done = me.update_done.subscribe();
            tokio::time::sleep(Duration::from_secs(2)).await;
            let mut tries = me.boot(&BootHooks::real()).await;
            // 有清單下載失敗（或還有沒載入的）時短間隔重試：1、2、5 分鐘，之後每 30 分鐘；全部成功就回到正常間隔
            loop {
                // 記憶體吃緊時延後（重建時新舊兩份會同時存在）
                let wait = if crate::app::pressure() == crate::sysinfo::Pressure::Critical {
                    // 記憶體一恢復就更新（每 30 秒看一次記憶體狀態，不連網路），最多等 30 分鐘。
                    // 以前固定睡 30 分鐘：開機就記憶體不足時，恢復之後清單還要等到 30 分鐘才載入（Windows 3.4.2 驗證）
                    warn!("記憶體不足，延後更新過濾清單（恢復後再更新，最多 30 分鐘）");
                    let t = std::time::Instant::now();
                    while crate::app::pressure() == crate::sysinfo::Pressure::Critical && t.elapsed() < Duration::from_secs(1800) {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                    }
                    Duration::ZERO
                } else {
                    let r = me.update_lists(false).await;
                    let partial = me.failing();
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
                // 等下一次的時候，「立即更新」結束了：失敗就接著照退避重試（3.5.0 D3 第 3 輪 D22：以前手動的那一次
                // 失敗不影響這裡，網路恢復後要等到下一次定時更新——每天一次的話是隔天——失敗才會消失）
                let failing = || me.failing() || me.update_status().error.is_some();
                tries = wait_next(&mut done, wait, tries, me.interval, failing, &RETRY_STEPS).await;
            }
        });
    }

    /// 有清單更新失敗、或還有沒載入的（定時更新的重試與資料新鮮度的「失敗中」看同一份狀態）
    fn failing(&self) -> bool {
        self.status.lock().unwrap()["errors"].as_array().is_some_and(|a| !a.is_empty()) || !self.missing.lock().unwrap().is_empty()
    }
}

/// 定時更新在等下一次的時候，別的更新（管理介面、API 的「立即更新」）結束了（3.5.0 D3 第 3 輪 D22）：
/// 回傳（從現在起還要等多久, 重試次數）。`remaining` 是原本還要等多久。
///
/// - 那一次有清單失敗：照同一份退避（[`RETRY_BACKOFF`]：1、2、5 分鐘，之後每 30 分鐘）排重試，比原本排的早才提前；
///   重試次數接著算——手動一直按、一直失敗也不會越排越密，最密就是退避本身。
/// - 那一次全部成功、迴圈原本在退避中：回到正常間隔（剛剛已經全部檢查過，不再重複問一次）。
/// - 其他（全部成功、原本就是正常間隔）：不變。
fn after_other_update(failing: bool, tries: usize, remaining: Duration, interval: Duration, steps: &[Duration]) -> (Duration, usize) {
    if failing {
        let w = steps.get(tries.min(steps.len().saturating_sub(1))).copied().unwrap_or(remaining);
        return if w < remaining { (w, tries + 1) } else { (remaining, tries) };
    }
    if tries > 0 {
        return (interval, 0);
    }
    (remaining, tries)
}

/// [`RETRY_BACKOFF`] 換成 `Duration`
const RETRY_STEPS: [Duration; 4] = [
    Duration::from_secs(RETRY_BACKOFF[0]),
    Duration::from_secs(RETRY_BACKOFF[1]),
    Duration::from_secs(RETRY_BACKOFF[2]),
    Duration::from_secs(RETRY_BACKOFF[3]),
];

/// 定時更新等 `wait` 之後再跑下一次；等的時候「立即更新」結束了就照 [`after_other_update`] 調整（3.5.0 D22）。
/// 回傳之後的重試次數。`failing` 是那一次結束之後有沒有清單失敗；`steps` 是退避（正式執行是 [`RETRY_STEPS`]）。
/// 通知的那一端不在了（服務結束）就照原本的時間等完
async fn wait_next(
    done: &mut tokio::sync::watch::Receiver<u64>,
    wait: Duration,
    mut tries: usize,
    interval: Duration,
    failing: impl Fn() -> bool,
    steps: &[Duration],
) -> usize {
    let mut deadline = tokio::time::Instant::now() + wait;
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => return tries,
            r = done.changed() => {
                if r.is_err() {
                    tokio::time::sleep_until(deadline).await;
                    return tries;
                }
                let now = tokio::time::Instant::now();
                let remaining = deadline.saturating_duration_since(now);
                let failed = failing();
                let (w, t) = after_other_update(failed, tries, remaining, interval, steps);
                if failed && w < remaining {
                    info!(
                        "過濾清單：立即更新有清單失敗，{} 秒後自動重試（之後照 1、2、5、30 分鐘的間隔，成功就回到正常間隔）",
                        w.as_secs()
                    );
                } else if !failed && tries > 0 {
                    info!("過濾清單：立即更新全部成功，不再重試，回到正常的更新間隔");
                }
                tries = t;
                deadline = now + w;
            }
        }
    }
}

/// 設定裡的一份清單
/// 清單命中次數加 1，到 `u32::MAX` 就停（3.5.1）。32 位元平台沒有 64 位元原子操作，計數器是 32 位元；
/// 以前 `fetch_add` 會繞回 0，最常用的清單看起來變成最少用，記憶體不足時反而先被停用（[`shed_order`]）。
/// `try_update` 跟 `fetch_add` 一樣是一個 LL/SC（CAS）迴圈，查詢路徑的成本只多一次比較
fn bump_saturating(h: &AtomicU32) {
    let _ = h.try_update(Ordering::Relaxed, Ordering::Relaxed, |x| x.checked_add(1));
}

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
    let bypass = kuroshio_config::chain::is_bypass_list(l);
    let probe = kuroshio_config::chain::is_probe_list(l);
    Some(ListSource {
        url,
        name,
        category,
        protect,
        bypass,
        probe,
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

/// `bypass`：命中的是不是「繞過防護」清單（自訂規則層沒有 `list`，一律 false）
fn verdict(v: kuroshio_filter::Verdict<'_>, bypass: bool) -> Verdict {
    Verdict {
        block: v.is_block(),
        allow: v.is_allow(),
        category: v.category.as_str(),
        rule: v.rule().into_owned(),
        bypass,
    }
}

impl FilterCheck for FilterService {
    fn check(&self, name: &str, qtype: u16) -> Option<Verdict> {
        let custom = self.custom.read().unwrap().clone();
        if let Some(v) = custom.check(name, qtype) {
            return Some(verdict(v, false));
        }
        let lists = self.lists.read().unwrap().clone();
        let v = lists.check(name, qtype)?;
        // 通訊類網域（推播）與內建一定通過的服務（3.5.0 F11：時間同步、連線偵測、憑證撤銷、系統更新、地震速報）：
        // 清單要擋也放行；自訂規則在上面，照樣優先（使用者明確要擋 NTP 也照擋）。只在清單判定要擋之後才比對
        if v.is_block() && self.protect_comm {
            if let Some(k) = kuroshio_net::comm::kind_of(name).filter(|k| k.flags().spare) {
                self.comm_spared.fetch_add(1, Ordering::Relaxed);
                self.comm_spared_by[k.index()].fetch_add(1, Ordering::Relaxed);
                let day = (crate::backup::now_ms() / 86_400_000) as u32;
                if self.comm_logged_day[k.index()].swap(day, Ordering::Relaxed) != day {
                    let list = v.list.and_then(|i| self.sources.get(i)).map(|s| s.name.as_str()).unwrap_or("?");
                    info!(
                        "過濾：清單「{list}」擋到{}網域 {name}，照樣放行（filter.protectComm；可以回報給清單維護者）",
                        k.label()
                    );
                }
                return Some(Verdict {
                    block: false,
                    allow: true,
                    category: v.category.as_str(),
                    rule: k.rule(),
                    bypass: false,
                });
            }
        }
        // 清單層的來源編號就是 sources 的位置（停用中的清單也佔一個位置）
        if let Some(h) = v.list.and_then(|i| self.hits.get(i)) {
            bump_saturating(h);
            self.hits_dirty.store(true, Ordering::Relaxed);
        }
        let bypass = v.list.and_then(|i| self.sources.get(i)).is_some_and(|s| s.bypass);
        Some(verdict(v, bypass))
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
            // 串接中從上游拿到、這台存不下而留在記憶體的清單副本（3.4.2）
            "heldCopies": { "count": self.held_stats().0, "bytes": self.held_stats().1 },
            // 通訊類網域（3.5.0）：清單本來要擋、照樣放行的次數
            "commSpared": self.comm_spared.load(Ordering::Relaxed),
            // 3.5.0 F11：每一類放行的次數（沒有放行過的類別不列）
            "commSparedByKind": kuroshio_net::comm::CommKind::ALL
                .iter()
                .map(|k| (k.as_str(), self.comm_spared_by[k.index()].load(Ordering::Relaxed)))
                .filter(|(_, n)| *n > 0)
                .map(|(k, n)| (k.to_string(), json!(n)))
                .collect::<serde_json::Map<String, Value>>(),
            "protectComm": self.protect_comm,
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
    fn rules_backfilled_for_old_copies() {
        let dir = std::env::temp_dir().join(format!("kuroshio-listcopy-rules-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let p = Arc::new(Mutex::new(Persister::new(&dir, Policy::new(StorageClass::Disk, 0, 4096))));
        p.lock().unwrap().set_free_probe(|_| Some(10 << 30));
        let c = ListCopies::new(p.clone());
        let url = "https://lists.example.com/old.txt";
        let mut sink = CopySink::new(true);
        sink.feed(b"||a.example^\n");
        let (h, z) = sink.finish();
        // 3.3.2 以前寫的副本：規則數是 0
        assert!(c.offer(url, h, z, &Validators::default(), 1, 0));
        assert_eq!(c.meta(url).unwrap().rules, 0);
        c.note_rules(url, 1234);
        assert_eq!(c.meta(url).unwrap().rules, 1234, "用副本載入時補記");
        c.note_rules(url, 99);
        assert_eq!(c.meta(url).unwrap().rules, 1234, "已經有的不蓋掉");
        let _ = std::fs::remove_dir_all(&dir);
    }

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
        // 還沒寫到磁碟（等下一輪快照）就要讀得到：恢復清單時不重新下載
        assert!(c.available_same(url, h));
        let mut early = Vec::new();
        assert!(c.read(url, &mut |b| early.extend_from_slice(b)), "待寫的副本讀得到");
        assert_eq!(early, body);
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

    /// 3.5.1：不在設定裡（或停用）超過 7 天的副本刪掉（索引與檔案），寬限期內的留著；啟用中的記下「還在用」
    #[test]
    fn prune_drops_copies_not_in_config_after_grace() {
        let dir = std::env::temp_dir().join(format!("kuroshio-listprune-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let p = Arc::new(Mutex::new(Persister::new(&dir, Policy::new(StorageClass::Disk, 0, 4096))));
        p.lock().unwrap().set_free_probe(|_| Some(10 << 30));
        let c = ListCopies::new(p.clone());
        let day = 86400;
        let t0 = 1_800_000_000;
        let v = Validators::default();
        let copy = |url: &str, at: u64| {
            let mut s = CopySink::new(true);
            s.feed(format!("||{url}^\n").repeat(50).as_bytes());
            let (h, z) = s.finish();
            assert!(c.offer(url, h, z, &v, at, 50));
        };
        let (keep, old31, paused, removed) = (
            "https://lists.example.com/keep.txt",
            "https://lists.example.com/v31.txt",
            "https://lists.example.com/paused.txt",
            "https://lists.example.net/recent.txt",
        );
        copy(keep, t0);
        // 3.1 時代的舊副本：舊版索引沒有 `used`，30 天前下載、之後沒再檢查
        copy(old31, t0 - 30 * day);
        copy(paused, t0);
        copy(removed, t0 - 2 * day);
        p.lock().unwrap().flush_all(t0).unwrap();
        let file = |u: &str| p.lock().unwrap().file_path(&c.meta(u).unwrap().file);
        let old_file = file(old31);
        assert!(old_file.exists());
        // 啟用中的是 keep 與 paused：v31 超過寬限期刪掉；recent 拿掉才 2 天，留著
        let (n, bytes) = c.prune(&[keep, paused], t0, COPY_GRACE_SECS);
        assert_eq!(n, 1);
        assert!(bytes > 0);
        assert!(c.meta(old31).is_none() && !old_file.exists(), "索引與檔案都刪掉");
        assert!(
            c.meta(removed).is_some() && c.available(removed),
            "寬限期內留著（重新加回不必重新下載）"
        );
        assert_eq!(c.meta(keep).unwrap().used, t0, "啟用中的記下還在用");
        assert_eq!(c.status()["count"], 3);
        // 同一天再做一次：什麼都不變（不重寫索引）
        assert_eq!(c.prune(&[keep, paused], t0 + 3600, COPY_GRACE_SECS), (0, 0));
        assert_eq!(c.meta(keep).unwrap().used, t0);
        // 之後 paused 停用：從最後一次還在用的那天起算 7 天才刪；recent 也到期
        let later = t0 + 7 * day + 1;
        let paused_file = file(paused);
        assert_eq!(c.prune(&[keep], later, COPY_GRACE_SECS).0, 2);
        assert!(c.meta(paused).is_none() && !paused_file.exists());
        assert!(c.meta(removed).is_none());
        assert!(c.meta(keep).is_some());
        assert_eq!(c.status()["count"], 1);
        // 索引寫出去之後重新讀回來也一樣
        p.lock().unwrap().flush_all(later).unwrap();
        let c2 = ListCopies::new(Arc::new(Mutex::new(Persister::new(&dir, Policy::new(StorageClass::Disk, 0, 4096)))));
        assert_eq!(c2.status()["count"], 1);
        assert_eq!(c2.meta(keep).unwrap().used, later);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 3.5.1：命中次數到上限就停，不繞回 0（不然最常用的清單在記憶體不足時先被停用）
    #[test]
    fn hits_saturate_instead_of_wrapping() {
        let h = AtomicU32::new(u32::MAX - 2);
        for _ in 0..5 {
            bump_saturating(&h);
        }
        assert_eq!(h.load(Ordering::Relaxed), u32::MAX);
        let z = AtomicU32::new(0);
        bump_saturating(&z);
        assert_eq!(z.load(Ordering::Relaxed), 1);
        // 停用順序：命中到上限的清單排在最後
        let sources = [src("hot", Category::Ads, false), src("cold", Category::Ads, false)];
        let order = shed_order(&sources, &[u32::MAX, 3], &[1000, 1000], &[true, true]);
        assert_eq!(order.first(), Some(&1), "少用的先停用：{order:?}");
    }

    #[test]
    fn manual_failure_joins_retry_backoff() {
        let (min, day) = (Duration::from_secs(60), Duration::from_secs(86_400));
        // 原本要等到明天，立即更新失敗：1 分鐘後重試，重試次數接著算
        assert_eq!(after_other_update(true, 0, day, day, &RETRY_STEPS), (min, 1));
        // 已經在退避中（下一次 30 秒後）：不提前、不加次數——手動一直失敗也不會越排越密
        assert_eq!(after_other_update(true, 1, min / 2, day, &RETRY_STEPS), (min / 2, 1));
        // 退避到底是每 30 分鐘
        assert_eq!(after_other_update(true, 9, day, day, &RETRY_STEPS), (Duration::from_secs(1800), 10));
        // 立即更新全部成功：退避中就回到正常間隔；本來就正常的不變（不因為手動更新多跑或少跑）
        assert_eq!(after_other_update(false, 3, min, day, &RETRY_STEPS), (day, 0));
        assert_eq!(after_other_update(false, 0, min, day, &RETRY_STEPS), (min, 0));
    }

    #[tokio::test]
    async fn wait_next_retries_soon_after_manual_failure() {
        let steps = [Duration::from_millis(30), Duration::from_millis(60)];
        let (tx, mut rx) = tokio::sync::watch::channel(0u64);
        // 原本要等 60 秒；20 毫秒後一次立即更新失敗 → 照退避 30 毫秒後就回來（重試次數 1）
        let t0 = std::time::Instant::now();
        let h = tokio::spawn(async move {
            let n = wait_next(&mut rx, Duration::from_secs(60), 0, Duration::from_secs(60), || true, &steps).await;
            (n, rx)
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        tx.send_replace(1);
        let (n, mut rx) = tokio::time::timeout(Duration::from_secs(5), h).await.unwrap().unwrap();
        assert_eq!(n, 1);
        assert!(t0.elapsed() < Duration::from_secs(5));
        // 退避中（tries 2），立即更新成功：回到正常間隔（這裡 40 毫秒），次數歸零
        let h =
            tokio::spawn(async move { wait_next(&mut rx, Duration::from_secs(60), 2, Duration::from_millis(40), || false, &steps).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        tx.send_replace(2);
        assert_eq!(tokio::time::timeout(Duration::from_secs(5), h).await.unwrap().unwrap(), 0);
        // 沒有立即更新：照原本的時間等完，次數不變
        let (_tx2, mut rx2) = tokio::sync::watch::channel(0u64);
        let n = wait_next(&mut rx2, Duration::from_millis(10), 3, Duration::from_secs(60), || true, &steps).await;
        assert_eq!(n, 3);
    }

    fn src(name: &str, cat: Category, protect: bool) -> ListSource {
        ListSource {
            url: format!("http://127.0.0.1/{name}"),
            name: name.into(),
            category: cat,
            protect,
            bypass: false,
            probe: false,
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
        // 3.5.0 F10：TW165 不抽惡意網站探測的網域；威脅情資類可以抽、廣告類不抽
        assert!(!list_source(tw).unwrap().probe);
        let tif = lists
            .iter()
            .find(|x| x["url"].as_str().unwrap().ends_with("/tif.mini.txt"))
            .unwrap();
        assert!(list_source(tif).unwrap().probe);
        assert!(!l(json!({ "url": "u", "category": "ads" })).probe);
        assert!(l(json!({ "url": "u", "category": "malware" })).probe);
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

    /// 3.5.0 C3：一次停用取到合計 ≥ 目標（至少 1 份）；一次恢復從尾端取到合計 × 1.3 ≤ 空間（至少 1 份）
    #[test]
    fn pick_shed_and_restore_bounds() {
        let sizes = [100, 50, 30, 20];
        let order = [0, 1, 2, 3];
        assert_eq!(pick_shed(&order, &sizes, 0), [0], "0 = 一份");
        assert_eq!(pick_shed(&order, &sizes, 100), [0]);
        assert_eq!(pick_shed(&order, &sizes, 101), [0, 1]);
        assert_eq!(pick_shed(&order, &sizes, u64::MAX), order, "不夠就全部（只有候選）");
        assert_eq!(pick_shed(&[2, 3], &sizes, 25), [2], "照給的順序");
        assert!(pick_shed(&[], &sizes, 10).is_empty());
        // 恢復：最後停用的先
        let b = [100, 50, 30, 20];
        assert_eq!(pick_restore(&b, 0), 1, "至少 1 份");
        assert_eq!(pick_restore(&b, 65), 2, "(20 + 30) × 1.3 = 65");
        assert_eq!(pick_restore(&b, 64), 1);
        assert_eq!(pick_restore(&b, u64::MAX), 4);
        assert_eq!(pick_restore(&[], 100), 0);
        assert_eq!(pick_restore(&[u64::MAX, u64::MAX], u64::MAX), 1, "不溢位");
    }
}
