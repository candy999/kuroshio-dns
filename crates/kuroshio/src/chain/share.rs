//! 共用結果：上游的 `ShareCache` 與下游的同步、匯入（規格 10 第 3 節）
//!
//! - 上游（[`ShareCache`]）：第一次有下游問清單時才產生，10 分鐘內回同一份，30 分鐘沒人用就整個釋放。
//!   評測結果與 CDN 資料壓縮後放記憶體（合計 1 MiB 以內）；過濾清單副本不進記憶體，分段請求時從檔案讀 32 KiB。
//! - 下游（[`Syncer`]）：串接後 30 秒做第一次，之後每 6 小時（±10 分鐘）。清單用綁定的上游公鑰驗簽，
//!   每個物件抓完驗過 SHA-256、解壓縮（限制輸出大小）、做完規格 3.4 的檢查之後才交給 [`ShareSink`] 匯入；
//!   任何一項不過只丟掉那個物件，不影響其他物件，也不動下游既有的資料。
//! - 跳過自己的工作（[`Syncer::skip_job`]）：36 小時內匯入過、而且現在是 `chained` 才算新鮮；
//!   `chain` 關著、`allow_downstream` 關著、沒有串接、上游沒資料時一律照原本的排程跑（跟 3.3.7 一樣）。
//! - `chain-share.json`（快照目錄，幾百 bytes）記每個種類最後一次成功匯入的時間與雜湊。

use super::client::{Client, State};
use crate::upstream::{Kind, Upstream};
use anyhow::{anyhow, bail, Context, Result};
use kuroshio_community::chain::{self as proto, ManifestBody, Object, CHUNK, MANIFEST_NAME, PROTO};
use kuroshio_community::envelope::{from_cbor, to_cbor};
use kuroshio_community::identity::{kid_of, KeyPair};
use kuroshio_community::util::{hex, now_ms, random_below, sha256};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::hash::Hasher;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::PathBuf;
// 32 位元 MIPS（MT7621）沒有 AtomicU64：建置次數與世代編號用 AtomicU32（不用鎖）
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, SystemTime};
use tokio::sync::Notify;
use tracing::{debug, info, warn};

// ---------------- 種類與上限 ----------------

pub const KIND_UPSTREAMS: &str = "upstreams";
pub const KIND_CDN_POOLS: &str = "cdn-pools";
pub const KIND_CDN_V6: &str = "cdn-v6";
pub const KIND_CDN_RANGES: &str = "cdn-ranges";
pub const KIND_FILTER_COPY: &str = "filter-copy";

/// 處理順序（規格 3.4）；不在這裡的種類略過
const ORDER: [&str; 5] = [KIND_UPSTREAMS, KIND_CDN_RANGES, KIND_CDN_POOLS, KIND_CDN_V6, KIND_FILTER_COPY];

/// 3.4.0 認得的格式版本（每個種類都是 1）
pub const FMT: u8 = 1;

/// 快照目錄裡的狀態檔
pub const STATE_FILE: &str = "chain-share.json";

/// 上游：清單多久內重複問回同一份
const MANIFEST_TTL_MS: u64 = 10 * 60_000;
/// 上游：多久沒人問就整個釋放
const IDLE_RELEASE_MS: u64 = 30 * 60_000;
/// 上游 `ShareCache` 的記憶體上限（清單本身也算在內）
pub const CACHE_MAX: usize = 1 << 20;
/// 清單的大小上限（下游超過整份丟掉；上游產生時也照這個上限）
pub const MANIFEST_MAX: usize = 16 * 1024;
/// 清單裡最多幾個物件
pub const MAX_OBJECTS: usize = 64;
/// 單一過濾清單副本（壓縮後）的上限
pub const COPY_MAX: u64 = 8 << 20;
/// 過濾清單副本解壓後的上限
pub const COPY_RAW_MAX: u64 = 64 << 20;
/// 非過濾類物件（壓縮後）的上限
pub const OBJECT_MAX: u64 = 1 << 20;
/// 上游記著幾份過濾清單副本的 SHA-256（副本沒變不重算）
const SUM_CACHE_MAX: usize = 64;
/// 上游讀副本、下游解壓時一次處理多少
const STREAM_STEP: usize = 64 * 1024;
/// 新鮮：多久內匯入過
pub const FRESH_MS: u64 = 36 * 3600 * 1000;
/// 串接解除時手上的評測結果超過這個時間就請排程器補跑評測
pub const STALE_ON_RELEASE_MS: u64 = 48 * 3600 * 1000;

/// 各種類解壓後的上限（規格 3.4 的表）
pub fn raw_limit(kind: &str) -> u64 {
    match kind {
        KIND_UPSTREAMS => 256 << 10,
        KIND_CDN_RANGES => 2 << 20,
        KIND_CDN_POOLS | KIND_CDN_V6 => 1 << 20,
        KIND_FILTER_COPY => COPY_RAW_MAX,
        _ => 0,
    }
}

/// 這個工作由哪一種共用結果取代（規格 3.5）
pub fn job_kind(job: &str) -> Option<&'static str> {
    match job {
        "dns-benchmark" => Some(KIND_UPSTREAMS),
        "cdn-pool" | "cdn-scan" => Some(KIND_CDN_POOLS),
        "cdn-ranges" => Some(KIND_CDN_RANGES),
        _ => None,
    }
}

/// 會被略過的工作（狀態的 `skippedJobs` 依這個順序）
const JOBS: [&str; 4] = ["dns-benchmark", "cdn-pool", "cdn-scan", "cdn-ranges"];

fn sha_of(b: &[u8]) -> [u8; 32] {
    sha256(&[b])
}

/// 寫進去的 bytes 數（解壓時只算大小，不留內容）
struct Counter(u64);

impl Write for Counter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0 += b.len() as u64;
        if self.0 > COPY_RAW_MAX {
            return Err(std::io::Error::other("解壓後超過上限"));
        }
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// ---------------- 上游 ----------------

/// 一份可以分享的過濾清單副本（上游）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterCopy {
    /// 清單網址
    pub url: String,
    /// 副本檔（[`ShareSource::read_copy`] 認得的名稱；正式環境是檔案路徑）
    pub file: String,
    /// 壓縮後大小
    pub bytes: u64,
    /// 解壓後大小（不知道是 0，`ShareCache` 算 SHA-256 時順便算）
    pub raw: u64,
    /// 原始內容的雜湊（`CopyMeta.hash`）
    pub hash: u64,
    pub rules: u64,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    /// 存副本的時間（Unix 毫秒）
    pub at: u64,
}

/// 上游的資料來源（`app` 用 [`Live`]，測試換成假的）
pub trait ShareSource: Send + Sync {
    /// `upstreams.json` 的內容（種子資料、空的 → None）
    fn upstreams(&self) -> Option<Vec<u8>>;
    fn cdn(&self) -> Option<kuroshio_cdn::SharedExport>;
    fn filter_copies(&self) -> Vec<FilterCopy>;
    /// 讀副本檔的一段（壓縮後的內容）
    fn read_copy(&self, file: &str, offset: u64, len: usize) -> Option<Vec<u8>>;
    /// 記憶體壓力是 Normal
    fn pressure_ok(&self) -> bool;
}

enum Stored {
    Mem(Vec<u8>),
    File { file: String, size: u64 },
}

struct Built {
    at: u64,
    /// 清單裡的物件（依處理順序）
    list: Vec<Object>,
    objects: HashMap<[u8; 8], Stored>,
    /// 記憶體裡的物件合計
    mem: usize,
    /// 簽好的清單（簽章的金鑰 ID，內容）：第一次有人問時才簽（背景建置不讀金鑰，沒人問 auth 就不建立金鑰檔）
    sealed: Option<([u8; 8], Vec<u8>)>,
}

/// 清單的 CBOR 內容
fn manifest_body(kid: &[u8], at: u64, list: &[Object]) -> Vec<u8> {
    to_cbor(&ManifestBody {
        v: PROTO,
        t: "manifest".into(),
        kid: kid.to_vec(),
        at,
        app: env!("CARGO_PKG_VERSION").into(),
        objects: list.to_vec(),
    })
}

/// `Sealed` 外層與簽章多出來的大小（CBOR 的 map、兩個鍵、64 bytes 簽章，留一點餘裕）
const SEAL_OVERHEAD: usize = 128;

#[derive(Default)]
struct CacheState {
    built: Option<Built>,
    last_used: u64,
}

/// （副本檔，大小，內容雜湊）→（SHA-256，解壓後大小）
type SumKey = (String, u64, u64);
/// （SHA-256，解壓後大小）
type Sum = ([u8; 32], u64);

/// 上游的共用結果快取
///
/// 清單在背景建置（`spawn_blocking`，同一時間最多一個）：壓縮評測結果與 CDN 資料、串流讀副本算
/// SHA-256（最多 8 MiB）在小機器上可能要好幾秒，不能卡住回答 DNS 查詢的工作執行緒。
/// 回答查詢時只拿已經建好的那一份（過期了也先用，背景建好再換）。
///
/// 記憶體：一份最多 [`CACHE_MAX`]（1 MiB）。建好換上的那一刻舊的才放掉，所以背景建置期間
/// 短暫會有新舊兩份（最多 2 MiB），換上之後回到一份
pub struct ShareCache {
    src: Arc<dyn ShareSource>,
    state: Mutex<CacheState>,
    sums: Mutex<Vec<(SumKey, Sum)>>,
    /// 背景建置中（避免重複）
    building: AtomicBool,
    /// 建好幾次（測試用）
    builds: AtomicU32,
}

/// zstd 等級 3（跟快照寫入器同一個 crate）
fn compress(b: &[u8]) -> Option<Vec<u8>> {
    zstd::bulk::compress(b, 3).ok()
}

/// `2026-11-10T20:13:34.970Z`、`2026-11-10 04:30` → Unix 毫秒（讀不懂是 0）
fn parse_time(s: &str) -> u64 {
    let Some(day) = s.get(..10).and_then(kuroshio_jobs::time::parse_date_utc) else {
        return 0;
    };
    let rest = s.get(11..).unwrap_or("");
    let f = |a: usize, b: usize| rest.get(a..b).and_then(|x| x.parse::<u64>().ok()).unwrap_or(0);
    day + f(0, 2) * 3_600_000 + f(3, 5) * 60_000 + f(6, 8) * 1000
}

fn mem_object(k: &str, data: &[u8], at: u64) -> Option<(Object, Stored)> {
    let z = compress(data)?;
    let sha = sha_of(&z);
    Some((
        Object {
            k: k.into(),
            fmt: FMT,
            id: sha[..8].to_vec(),
            sha: sha.to_vec(),
            size: z.len() as u64,
            raw: data.len() as u64,
            enc: "zstd".into(),
            at,
            ..Default::default()
        },
        Stored::Mem(z),
    ))
}

impl ShareCache {
    pub fn new(src: Arc<dyn ShareSource>) -> ShareCache {
        ShareCache {
            src,
            state: Mutex::new(CacheState::default()),
            sums: Mutex::new(Vec::new()),
            building: AtomicBool::new(false),
            builds: AtomicU32::new(0),
        }
    }

    /// 簽好的清單（`Sealed`），不在呼叫端建置：
    /// - 有建好的就回那一份（10 分鐘內同一份；過期了也先回舊的，同時觸發背景重建）
    /// - 還沒建好 → None（回應器回 REFUSED，下游晚點再來），同時觸發背景建置
    /// - 記憶體壓力不是 Normal → None
    pub fn manifest(self: &Arc<Self>, key: &KeyPair, now_ms: u64) -> Option<Vec<u8>> {
        if !self.src.pressure_ok() {
            return None;
        }
        let mut st = self.state.lock().unwrap();
        st.last_used = st.last_used.max(now_ms);
        // 還沒建、或已經超過 10 分鐘：背景重建（舊的照樣先用）
        if st.built.as_ref().map_or(true, |b| now_ms.saturating_sub(b.at) >= MANIFEST_TTL_MS) {
            self.spawn_build(now_ms);
        }
        let b = st.built.as_mut()?;
        match &b.sealed {
            Some((kid, m)) if *kid == key.kid => Some(m.clone()),
            // 簽章只要一下子（清單 16 KiB 以內）：在這裡做
            _ => {
                let m = proto::seal(key, "manifest", manifest_body(&key.kid, b.at, &b.list));
                b.sealed = Some((key.kid, m.clone()));
                Some(m)
            }
        }
    }

    /// 啟動時先在背景建一次（第一個下游來問時大多已經就緒）
    pub fn warm(self: &Arc<Self>) {
        if self.src.pressure_ok() {
            self.spawn_build(now_ms());
        }
    }

    /// 已經有建好的清單
    pub fn ready(&self) -> bool {
        self.state.lock().unwrap().built.is_some()
    }

    /// 背景建置中
    pub fn building(&self) -> bool {
        self.building.load(Ordering::SeqCst)
    }

    /// 建置過幾次（測試用）
    pub fn build_count(&self) -> u64 {
        self.builds.load(Ordering::SeqCst) as u64
    }

    /// 背景建置（同一時間最多一個）；在 tokio 裡用 `spawn_blocking`，不在 tokio 裡（測試）用執行緒
    fn spawn_build(self: &Arc<Self>, now: u64) {
        if self.building.swap(true, Ordering::SeqCst) {
            return;
        }
        let me = self.clone();
        let f = move || {
            me.rebuild_now(now);
            me.building.store(false, Ordering::SeqCst);
        };
        match tokio::runtime::Handle::try_current() {
            Ok(h) => {
                h.spawn_blocking(f);
            }
            Err(_) => {
                std::thread::spawn(f);
            }
        }
    }

    /// 立刻建一份並換上（背景建置用；呼叫端會等到建好，不要在回答查詢的路徑上呼叫）。
    /// 建置期間舊的那份照常提供，建好才換掉
    pub fn rebuild_now(&self, now: u64) {
        let b = self.build(now);
        self.builds.fetch_add(1, Ordering::SeqCst);
        let mut st = self.state.lock().unwrap();
        st.built = Some(b);
        // 建好但一直沒人問（啟動時先建的）：從現在開始算 30 分鐘
        st.last_used = st.last_used.max(now);
    }

    fn build(&self, now: u64) -> Built {
        // 1. 評測結果與 CDN 資料：壓縮後放記憶體
        let mut mem: Vec<(Object, Stored)> = Vec::new();
        if let Some(u) = self.src.upstreams() {
            let at = serde_json::from_slice::<Value>(&u)
                .ok()
                .and_then(|v| v.get("generatedAt").and_then(Value::as_str).map(parse_time))
                .unwrap_or(0);
            mem.extend(mem_object(KIND_UPSTREAMS, &u, at));
        }
        if let Some(c) = self.src.cdn() {
            if !c.ranges.is_empty() {
                let j = serde_json::to_vec(&json!({ "files": c.ranges })).unwrap_or_default();
                mem.extend(mem_object(KIND_CDN_RANGES, &j, now));
            }
            if let Some(p) = &c.pools {
                mem.extend(mem_object(KIND_CDN_POOLS, p, now));
            }
            if let Some(v) = &c.v6 {
                mem.extend(mem_object(KIND_CDN_V6, v, now));
            }
        }
        // 合計超過上限：依 cdn-v6 → cdn-pools → cdn-ranges（→ upstreams）的順序放棄
        let budget = CACHE_MAX - MANIFEST_MAX;
        let size = |m: &[(Object, Stored)]| m.iter().map(|(o, _)| o.size as usize).sum::<usize>();
        for k in [KIND_CDN_V6, KIND_CDN_POOLS, KIND_CDN_RANGES, KIND_UPSTREAMS] {
            if size(&mem) <= budget {
                break;
            }
            if let Some(i) = mem.iter().position(|(o, _)| o.k == k) {
                info!("共用結果：{k} 太大（壓縮後 {} KB），這次不列進清單", mem[i].0.size / 1024);
                mem.remove(i);
            }
        }
        let mem_bytes = size(&mem);
        // 2. 過濾清單副本：只記檔名、大小與雜湊（第一次用串流算）
        let mut files: Vec<(Object, Stored)> = Vec::new();
        for c in self.src.filter_copies() {
            if mem.len() + files.len() >= MAX_OBJECTS {
                break;
            }
            if c.bytes == 0 || c.bytes > COPY_MAX {
                continue;
            }
            let Some((sha, raw)) = self.sum(&c) else { continue };
            if raw > COPY_RAW_MAX {
                continue;
            }
            files.push((
                Object {
                    k: KIND_FILTER_COPY.into(),
                    fmt: FMT,
                    id: sha[..8].to_vec(),
                    sha: sha.to_vec(),
                    size: c.bytes,
                    raw,
                    enc: "zstd".into(),
                    name: c.url.clone(),
                    at: c.at,
                    rules: c.rules,
                    hash: format!("{:016x}", c.hash),
                    etag: c.etag.clone().unwrap_or_default(),
                    last_modified: c.last_modified.clone().unwrap_or_default(),
                },
                Stored::File {
                    file: c.file.clone(),
                    size: c.bytes,
                },
            ));
        }
        // 3. 簽好的清單超過 16 KiB 就從最後一份副本開始拿掉（金鑰 ID 長度固定，先用 0 估大小）
        let mut all = mem;
        all.extend(files);
        let size_of = |objs: &[(Object, Stored)]| {
            let list: Vec<Object> = objs.iter().map(|(o, _)| o.clone()).collect();
            manifest_body(&[0u8; 8], now, &list).len() + SEAL_OVERHEAD
        };
        while size_of(&all) > MANIFEST_MAX && all.last().is_some_and(|(o, _)| o.k == KIND_FILTER_COPY) {
            all.pop();
        }
        let mut list = Vec::with_capacity(all.len());
        let mut objects = HashMap::new();
        for (o, s) in all {
            if let Ok(id) = <[u8; 8]>::try_from(o.id.as_slice()) {
                objects.insert(id, s);
            }
            list.push(o);
        }
        debug!("共用結果：產生清單（{} 個物件，記憶體 {} KB）", objects.len(), mem_bytes / 1024);
        Built {
            at: now,
            list,
            objects,
            mem: mem_bytes,
            sealed: None,
        }
    }

    /// 副本的 SHA-256 與解壓後大小（一次讀 64 KiB；以（檔案，大小，雜湊）為鍵記著）
    fn sum(&self, c: &FilterCopy) -> Option<([u8; 32], u64)> {
        let key: SumKey = (c.file.clone(), c.bytes, c.hash);
        if let Some((_, v)) = self.sums.lock().unwrap().iter().find(|(k, _)| *k == key) {
            return Some(*v);
        }
        let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
        let mut dec = zstd::stream::write::Decoder::new(Counter(0)).ok()?;
        let mut off = 0u64;
        let mut over = false;
        while off < c.bytes {
            let n = (c.bytes - off).min(STREAM_STEP as u64) as usize;
            let b = self.src.read_copy(&c.file, off, n)?;
            if b.is_empty() {
                return None;
            }
            ctx.update(&b);
            if !over && dec.write_all(&b).is_err() {
                over = true;
            }
            off += b.len() as u64;
        }
        if !over && dec.flush().is_err() {
            over = true;
        }
        let raw = if over { u64::MAX } else { dec.get_ref().0 };
        let sha: [u8; 32] = ctx.finish().as_ref().try_into().ok()?;
        let mut sums = self.sums.lock().unwrap();
        if sums.len() >= SUM_CACHE_MAX {
            sums.remove(0);
        }
        sums.push((key, (sha, raw)));
        Some((sha, raw))
    }

    /// 一段（32 KiB）。物件不在目前的快取裡 → None（NXDOMAIN，下游重新拿清單）
    pub fn chunk(&self, oid: &[u8; 8], idx: u32) -> Option<Vec<u8>> {
        let (file, off, len) = {
            let mut st = self.state.lock().unwrap();
            st.last_used = st.last_used.max(now_ms());
            let s = st.built.as_ref()?.objects.get(oid)?;
            let off = idx as u64 * CHUNK as u64;
            let size = match s {
                Stored::Mem(b) => b.len() as u64,
                Stored::File { size, .. } => *size,
            };
            if off >= size {
                return (size == 0 && idx == 0).then(Vec::new);
            }
            let len = (size - off).min(CHUNK as u64) as usize;
            match s {
                Stored::Mem(b) => return Some(b[off as usize..off as usize + len].to_vec()),
                Stored::File { file, .. } => (file.clone(), off, len),
            }
        };
        // 副本檔不拿著鎖讀
        self.src.read_copy(&file, off, len)
    }

    /// 30 分鐘沒人用就整個釋放（每分鐘呼叫）
    pub fn sweep(&self, now_ms: u64) {
        let mut st = self.state.lock().unwrap();
        if st.built.is_some() && now_ms.saturating_sub(st.last_used) >= IDLE_RELEASE_MS {
            st.built = None;
            debug!("共用結果：30 分鐘沒有下游來拿，釋放快取");
        }
    }

    /// 目前佔的記憶體（清單＋記憶體裡的物件）
    pub fn bytes(&self) -> usize {
        self.state
            .lock()
            .unwrap()
            .built
            .as_ref()
            .map_or(0, |b| b.mem + b.sealed.as_ref().map_or(MANIFEST_MAX, |s| s.1.len()))
    }

    pub fn pressure_ok(&self) -> bool {
        self.src.pressure_ok()
    }
}

// ---------------- 匯入前的檢查（純函式） ----------------

/// `upstreams` 的檢查與處理（規格 3.4）：拿掉明文（udp／tcp，對下游來說都會回到上游自己），
/// 加上 `source`。回傳要寫進下游 `upstreams.json` 的內容
pub fn check_upstreams(raw: &[u8], upstream_kid: &[u8; 8], now_ms: u64) -> Result<Vec<u8>> {
    if raw.len() as u64 > raw_limit(KIND_UPSTREAMS) {
        bail!("評測結果太大（{} bytes）", raw.len());
    }
    let mut v: Value = serde_json::from_slice(raw).context("評測結果不是 JSON")?;
    let o = v.as_object_mut().ok_or_else(|| anyhow!("評測結果不是 JSON 物件"))?;
    let sel = o
        .get_mut("selected")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| anyhow!("selected 不是陣列"))?;
    if sel.is_empty() || sel.len() > 64 {
        bail!("selected 有 {} 筆（要 1～64 筆）", sel.len());
    }
    let mut keep = Vec::new();
    for s in sel.iter() {
        let id = s
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("selected 裡有沒有 id 的項目"))?;
        let u = Upstream::parse(id).map_err(|e| anyhow!("上游 {id} 解析不了：{e}"))?;
        if !u.supported() {
            bail!("上游 {id} 這個版本不支援");
        }
        let ty = s.get("type").and_then(Value::as_str).unwrap_or("");
        let plain = matches!(ty, "udp" | "tcp") || matches!(u.kind, Kind::Udp | Kind::Tcp);
        if !plain {
            keep.push(s.clone());
        }
    }
    if keep.is_empty() {
        bail!("評測結果只有明文上游（串接時都會回到上游自己）");
    }
    *sel = keep;
    o.insert("source".into(), json!({ "chain": hex(upstream_kid), "at": now_ms }));
    Ok(serde_json::to_vec(&v)?)
}

fn valid_range_name(n: &str) -> bool {
    let stem = n.strip_suffix("-ipv4.txt").or_else(|| n.strip_suffix("-ipv6.txt"));
    stem.is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
}

fn valid_cidr(s: &str, v6: bool) -> bool {
    let Some((ip, len)) = s.split_once('/') else { return false };
    let (Ok(ip), Ok(len)) = (ip.parse::<IpAddr>(), len.parse::<u8>()) else {
        return false;
    };
    match ip {
        IpAddr::V4(_) => !v6 && len <= 32,
        IpAddr::V6(_) => v6 && len <= 128,
    }
}

/// `cdn-ranges` 的檢查（規格 3.4）：`{ "files": { "<cdn>-ipv4.txt": "…" } }`，檔名只能是
/// `[a-z0-9-]+-ipv[46].txt`、每行是合法的 CIDR（空行可以）
pub fn check_ranges(raw: &[u8]) -> Result<BTreeMap<String, String>> {
    if raw.len() as u64 > raw_limit(KIND_CDN_RANGES) {
        bail!("官方範圍太大（{} bytes）", raw.len());
    }
    let v: Value = serde_json::from_slice(raw).context("官方範圍不是 JSON")?;
    let files = v.get("files").and_then(Value::as_object).ok_or_else(|| anyhow!("沒有 files"))?;
    if files.is_empty() {
        bail!("官方範圍是空的");
    }
    let mut out = BTreeMap::new();
    for (name, text) in files {
        if !valid_range_name(name) {
            bail!("官方範圍的檔名不合法：{name}");
        }
        let text = text.as_str().ok_or_else(|| anyhow!("{name} 的內容不是文字"))?;
        let v6 = name.ends_with("-ipv6.txt");
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
            if !valid_cidr(line, v6) {
                bail!("{name} 有不合法的網段：{}", kuroshio_community::util::clip(line, 64));
            }
        }
        out.insert(name.clone(), text.to_string());
    }
    Ok(out)
}

// ---------------- 下游 ----------------

/// 下游的匯入端（`app` 用 [`Live`]，測試換成假的）。只有驗過清單簽章與物件雜湊、做完檢查之後才會被呼叫
pub trait ShareSink: Send + Sync {
    fn import_upstreams(&self, json: Vec<u8>) -> Result<()>;
    fn import_cdn_ranges(&self, files: BTreeMap<String, String>) -> Result<()>;
    fn import_cdn_pools(&self, json: &[u8]) -> Result<()>;
    fn import_cdn_v6(&self, json: &[u8]) -> Result<()>;
    /// Err = 不抓的原因（`no-room`、`not-subscribed`、`memory`…）
    fn wants_filter_copy(&self, o: &Object) -> Result<(), &'static str>;
    fn import_filter_copy(&self, o: &Object, compressed: Vec<u8>) -> Result<()>;
    /// 有新副本 → 用副本優先重建一次
    fn filter_copies_done(&self, changed: usize);
    fn pressure_ok(&self) -> bool;
}

/// 下游的時間（`KUROSHIO_CHAIN_TIMING` 的 `shareFirst`、`shareEvery` 可以覆寫，只給整合測試用）
#[derive(Debug, Clone)]
pub struct ShareTiming {
    /// 串接後第一次同步
    pub first: Duration,
    /// 之後的間隔（實際 ±`jitter`）
    pub every: Duration,
    pub jitter: Duration,
    /// 記憶體壓力大時延後
    pub defer: Duration,
    /// 每一次查詢的逾時
    pub ask: Duration,
}

impl Default for ShareTiming {
    fn default() -> ShareTiming {
        ShareTiming {
            first: Duration::from_secs(30),
            every: Duration::from_secs(6 * 3600),
            jitter: Duration::from_secs(600),
            defer: Duration::from_secs(600),
            ask: Duration::from_secs(5),
        }
    }
}

impl ShareTiming {
    pub fn from_env() -> ShareTiming {
        let mut t = ShareTiming::default();
        let Some(v) = std::env::var("KUROSHIO_CHAIN_TIMING")
            .ok()
            .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        else {
            return t;
        };
        let ms = |k: &str| v.get(k).and_then(Value::as_u64).map(Duration::from_millis);
        if let Some(d) = ms("shareFirst") {
            t.first = d;
        }
        if let Some(d) = ms("shareEvery") {
            t.every = d;
            t.jitter = d / 36;
        }
        t
    }
}

/// 一個種類最後一次成功匯入（`chain-share.json`）
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Imported {
    /// 傳輸內容的 SHA-256（十六進位）
    pub sha: String,
    /// 資料的時間
    pub at: u64,
    pub imported_at: u64,
    pub bytes: u64,
}

/// `chain-share.json`：`{ "v": 1, "kinds": { "<種類>": { "sha", "at", "importedAt", "bytes" } } }`
fn saved_json(kinds: &BTreeMap<String, Imported>) -> Vec<u8> {
    let m: serde_json::Map<String, Value> = kinds
        .iter()
        .map(|(k, i)| {
            (
                k.clone(),
                json!({ "sha": i.sha, "at": i.at, "importedAt": i.imported_at, "bytes": i.bytes }),
            )
        })
        .collect();
    serde_json::to_vec(&json!({ "v": 1, "kinds": m })).unwrap_or_default()
}

fn saved_parse(b: &[u8]) -> BTreeMap<String, Imported> {
    let Ok(v) = serde_json::from_slice::<Value>(b) else {
        return BTreeMap::new();
    };
    let Some(m) = v.get("kinds").and_then(Value::as_object) else {
        return BTreeMap::new();
    };
    let n = |x: &Value, k: &str| x.get(k).and_then(Value::as_u64).unwrap_or(0);
    m.iter()
        // 記憶體上限：種類 4 個＋清單副本最多 64 份
        .take(MAX_OBJECTS + 8)
        .filter_map(|(k, x)| {
            Some((
                k.clone(),
                Imported {
                    sha: x.get("sha")?.as_str()?.to_string(),
                    at: n(x, "at"),
                    imported_at: n(x, "importedAt"),
                    bytes: n(x, "bytes"),
                },
            ))
        })
        .collect()
}

/// 狀態頁的一個物件（最近一次同步）
#[derive(Debug, Clone)]
struct ObjStatus {
    kind: String,
    name: String,
    at: u64,
    bytes: u64,
    error: Option<String>,
}

#[derive(Default)]
struct SyncState {
    kinds: BTreeMap<String, Imported>,
    objects: Vec<ObjStatus>,
    last_sync_at: Option<u64>,
    next_sync_at: Option<u64>,
    error: Option<String>,
}

/// `sync_once` 的結果
#[derive(Debug, Default, Clone)]
pub struct SyncReport {
    /// 整次同步的錯誤（`not-chained`、`no-tcp`、`memory`、`manifest-signature`…）；None = 清單驗過了
    pub error: Option<String>,
    /// 這次匯入的種類
    pub imported: Vec<String>,
    /// （種類，原因）
    pub skipped: Vec<(String, String)>,
    /// 發出的清單查詢、分段查詢數
    pub manifests: usize,
    pub chunks: usize,
}

type PersistFn = Arc<dyn Fn(Vec<u8>) + Send + Sync>;
type StaleFn = Arc<dyn Fn() + Send + Sync>;

/// 下游的同步
pub struct Syncer {
    client: Arc<Client>,
    sink: RwLock<Arc<dyn ShareSink>>,
    state: Mutex<SyncState>,
    persist: Mutex<Option<PersistFn>>,
    on_stale: Mutex<Option<StaleFn>>,
    last_saved: Mutex<Vec<u8>>,
    timing: Mutex<ShareTiming>,
    wake: Notify,
    run: tokio::sync::Mutex<()>,
    generation: AtomicU32,
}

/// 一次同步裡要整次放棄的錯誤
struct Fatal(String);

fn fatal(code: &str) -> Fatal {
    Fatal(code.to_string())
}

/// 一個物件的結果
enum Fetch {
    Done,
    Stale,
}

impl Syncer {
    pub fn new(client: Arc<Client>, sink: Arc<dyn ShareSink>, saved: Option<&[u8]>) -> Arc<Syncer> {
        let kinds = saved.map(saved_parse).unwrap_or_default();
        let s = Arc::new(Syncer {
            client: client.clone(),
            sink: RwLock::new(sink),
            state: Mutex::new(SyncState {
                kinds,
                ..Default::default()
            }),
            persist: Mutex::new(None),
            on_stale: Mutex::new(None),
            last_saved: Mutex::new(saved.map(<[u8]>::to_vec).unwrap_or_default()),
            timing: Mutex::new(ShareTiming::from_env()),
            wake: Notify::new(),
            run: tokio::sync::Mutex::new(()),
            generation: AtomicU32::new(0),
        });
        let w = Arc::downgrade(&s);
        client.on_state_change(Arc::new(move |from, to| {
            if let Some(s) = w.upgrade() {
                s.state_changed(from, to);
            }
        }));
        s
    }

    /// 新的一輪（重新載入）換匯入端
    pub fn set_sink(&self, sink: Arc<dyn ShareSink>) {
        *self.sink.write().unwrap() = sink;
    }

    /// `chain-share.json` 的寫入（快照寫入器的 stage）
    pub fn set_persist(&self, f: PersistFn) {
        *self.persist.lock().unwrap() = Some(f);
    }

    /// 串接解除、手上的評測結果超過 48 小時：請排程器補跑評測
    pub fn set_on_stale(&self, f: StaleFn) {
        *self.on_stale.lock().unwrap() = Some(f);
    }

    pub fn set_timing(&self, t: ShareTiming) {
        *self.timing.lock().unwrap() = t;
    }

    fn sink(&self) -> Arc<dyn ShareSink> {
        self.sink.read().unwrap().clone()
    }

    fn state_changed(&self, from: State, to: State) {
        if from == State::Chained && to != State::Chained {
            let at = self.state.lock().unwrap().kinds.get(KIND_UPSTREAMS).map(|i| i.imported_at);
            if let Some(at) = at.filter(|at| now_ms().saturating_sub(*at) > STALE_ON_RELEASE_MS) {
                info!(
                    "串接解除：上游給的評測結果已經是 {} 小時前的，請排程器補跑評測",
                    now_ms().saturating_sub(at) / 3_600_000
                );
                let f = self.on_stale.lock().unwrap().clone();
                if let Some(f) = f {
                    f();
                }
            }
        }
        self.wake.notify_one();
    }

    /// 這個種類新鮮（36 小時內匯入過，而且現在串接中；chain 關著一定是 false）
    pub fn fresh(&self, kind: &str) -> bool {
        self.client.is_chained() && self.imported_recently(kind)
    }

    fn imported_recently(&self, key: &str) -> bool {
        let now = now_ms();
        self.state
            .lock()
            .unwrap()
            .kinds
            .get(key)
            // 時間在未來（時鐘倒退）不算
            .is_some_and(|i| i.imported_at <= now.saturating_add(60_000) && now.saturating_sub(i.imported_at) < FRESH_MS)
    }

    /// 這個工作要不要略過（規格 3.5 的對照）
    pub fn skip_job(&self, job: &str) -> bool {
        job_kind(job).is_some_and(|k| self.fresh(k))
    }

    /// `chain-share.json` 的內容
    pub fn snapshot(&self) -> Vec<u8> {
        let kinds = self.state.lock().unwrap().kinds.clone();
        saved_json(&kinds)
    }

    /// 內容有變才交給快照寫入器
    fn save(&self) {
        let b = self.snapshot();
        {
            let mut last = self.last_saved.lock().unwrap();
            if *last == b {
                return;
            }
            *last = b.clone();
        }
        let f = self.persist.lock().unwrap().clone();
        if let Some(f) = f {
            f(b);
        }
    }

    /// `/api/status` 的 `chain.shared`（沒啟用或沒串接是 null）
    pub fn status_json(&self) -> Value {
        if !self.client.is_chained() {
            return Value::Null;
        }
        let skipped: Vec<&str> = JOBS.iter().copied().filter(|j| self.skip_job(j)).collect();
        let st = self.state.lock().unwrap();
        let now = now_ms();
        let objects: Vec<Value> = st
            .objects
            .iter()
            .map(|o| {
                let key = kind_key(&o.kind, &o.name);
                let imp = st.kinds.get(&key);
                let fresh =
                    imp.is_some_and(|i| i.imported_at <= now.saturating_add(60_000) && now.saturating_sub(i.imported_at) < FRESH_MS);
                let mut v = json!({
                    "kind": o.kind, "at": o.at, "bytes": o.bytes,
                    "importedAt": imp.map(|i| i.imported_at),
                    "fresh": fresh && o.error.is_none(),
                    "error": o.error,
                });
                if o.kind == KIND_FILTER_COPY {
                    v["name"] = json!(o.name);
                }
                v
            })
            .collect();
        json!({
            "enabled": true,
            "lastSyncAt": st.last_sync_at,
            "nextSyncAt": st.next_sync_at,
            "error": st.error,
            "objects": objects,
            "skippedJobs": skipped,
        })
    }

    /// 拿一次清單、匯入有變的物件（規格 3.2、3.4）
    pub async fn sync_once(&self) -> SyncReport {
        let _run = self.run.lock().await;
        let mut rep = SyncReport::default();
        let r = self.sync_inner(&mut rep).await;
        let now = now_ms();
        {
            let mut st = self.state.lock().unwrap();
            match &r {
                Err(Fatal(e)) if e == "memory" || e == "not-chained" => {}
                _ => st.last_sync_at = Some(now),
            }
            st.error = r.as_ref().err().map(|f| f.0.clone());
        }
        if let Err(Fatal(e)) = r {
            if e != "not-chained" {
                info!("共用結果：這次沒有同步（{e}），相關的工作照原本的排程自己做");
            }
            rep.error = Some(e);
        }
        self.save();
        rep
    }

    async fn sync_inner(&self, rep: &mut SyncReport) -> Result<(), Fatal> {
        if !self.client.is_chained() {
            return Err(fatal("not-chained"));
        }
        if !self.client.last_probe().is_some_and(|p| p.caps.iter().any(|c| c == "share")) {
            return Err(fatal("no-share"));
        }
        let sink = self.sink();
        if !sink.pressure_ok() {
            return Err(fatal("memory"));
        }
        let (addr, tcp_ok) = self.client.bound_addr().ok_or_else(|| fatal("not-chained"))?;
        if !tcp_ok {
            return Err(fatal("no-tcp"));
        }
        let key = self.client.bound_key().ok_or_else(|| fatal("not-chained"))?;
        let ask = self.timing.lock().unwrap().ask;
        let mut conn = kuroshio_net::path::ChaosTcp::connect(addr, ask)
            .await
            .map_err(|_| fatal("no-tcp"))?;
        let mut changed_copies = 0usize;
        // 分段回 NXDOMAIN（上游重新產生了清單）：重新拿一次清單
        for attempt in 0..2 {
            let m = self.fetch_manifest(&mut conn, &key, ask, rep).await?;
            let mut objs: Vec<&Object> = m.objects.iter().filter(|o| ORDER.contains(&o.k.as_str())).collect();
            objs.sort_by_key(|o| ORDER.iter().position(|k| *k == o.k).unwrap_or(ORDER.len()));
            let mut statuses = Vec::new();
            let mut stale = false;
            for o in objs {
                let mut s = ObjStatus {
                    kind: o.k.clone(),
                    name: if o.k == KIND_FILTER_COPY { o.name.clone() } else { String::new() },
                    at: o.at,
                    bytes: o.size,
                    error: None,
                };
                if stale {
                    s.error = Some("stale".into());
                    statuses.push(s);
                    continue;
                }
                match self.fetch_object(&mut conn, o, &m.kid, ask, &sink, rep).await {
                    Ok(Fetch::Done) => {}
                    Ok(Fetch::Stale) => {
                        stale = true;
                        s.error = Some("stale".into());
                    }
                    Err(e) => {
                        debug!("共用結果：{} 沒有匯入（{e}）", o.k);
                        rep.skipped.push((o.k.clone(), e.clone()));
                        s.error = Some(e);
                    }
                }
                if s.error.is_none() && o.k == KIND_FILTER_COPY && rep.imported.iter().any(|k| *k == kind_key(&o.k, &o.name)) {
                    changed_copies += 1;
                }
                statuses.push(s);
            }
            self.state.lock().unwrap().objects = statuses;
            if !stale || attempt == 1 {
                break;
            }
            debug!("共用結果：上游的清單換過了，重新拿一次");
        }
        if changed_copies > 0 {
            sink.filter_copies_done(changed_copies);
        }
        if !rep.imported.is_empty() {
            info!("共用結果：從上游黑潮匯入 {}", rep.imported.join("、"));
        }
        Ok(())
    }

    async fn fetch_manifest(
        &self,
        conn: &mut kuroshio_net::path::ChaosTcp,
        key: &[u8; 32],
        ask: Duration,
        rep: &mut SyncReport,
    ) -> Result<ManifestBody, Fatal> {
        rep.manifests += 1;
        let r = conn.ask(MANIFEST_NAME, ask).await.map_err(|_| fatal("no-response"))?;
        if r.rcode != 0 {
            return Err(Fatal(if r.rcode == 5 {
                "refused".into()
            } else {
                format!("rcode-{}", r.rcode)
            }));
        }
        let bytes = r.txt.ok_or_else(|| fatal("manifest-format"))?;
        if bytes.len() > MANIFEST_MAX {
            return Err(fatal("manifest-too-large"));
        }
        let body = proto::open(&bytes, "manifest", key).map_err(|_| fatal("manifest-signature"))?;
        let m: ManifestBody = from_cbor(&body).map_err(|_| fatal("manifest-format"))?;
        if m.v > PROTO {
            return Err(fatal("manifest-version"));
        }
        if m.t != "manifest" {
            return Err(fatal("manifest-format"));
        }
        if m.kid != kid_of(key) {
            return Err(fatal("manifest-kid"));
        }
        if m.objects.len() > MAX_OBJECTS {
            return Err(fatal("manifest-too-large"));
        }
        Ok(m)
    }

    /// 抓一個物件、驗證、檢查、匯入。Err = 這個物件的錯誤（記在 `objects[].error`）
    async fn fetch_object(
        &self,
        conn: &mut kuroshio_net::path::ChaosTcp,
        o: &Object,
        upstream_kid: &[u8],
        ask: Duration,
        sink: &Arc<dyn ShareSink>,
        rep: &mut SyncReport,
    ) -> Result<Fetch, String> {
        if o.fmt > FMT {
            return Err("newer-format".into());
        }
        let (Ok(oid), Ok(sha)) = (<[u8; 8]>::try_from(o.id.as_slice()), <[u8; 32]>::try_from(o.sha.as_slice())) else {
            return Err("bad-object".into());
        };
        if sha[..8] != oid {
            return Err("bad-object".into());
        }
        let key = kind_key(&o.k, &o.name);
        let sha_hex = hex(&sha);
        let filter = o.k == KIND_FILTER_COPY;
        // 雜湊沒變：不重抓
        if self.state.lock().unwrap().kinds.get(&key).is_some_and(|i| i.sha == sha_hex) {
            return Ok(Fetch::Done);
        }
        let limit = raw_limit(&o.k);
        if filter {
            if o.size > COPY_MAX || o.raw > COPY_RAW_MAX {
                return Err("too-large".into());
            }
            sink.wants_filter_copy(o).map_err(str::to_string)?;
        } else if o.size > OBJECT_MAX || o.raw > limit {
            return Err("too-large".into());
        }
        if !matches!(o.enc.as_str(), "zstd" | "none") {
            return Err("bad-encoding".into());
        }
        // 分段：一次一段，累計超過 size 立刻中止
        let n = o.size.div_ceil(CHUNK as u64).max(1);
        let mut buf: Vec<u8> = Vec::with_capacity(o.size.min(COPY_MAX) as usize);
        for idx in 0..n {
            rep.chunks += 1;
            let r = conn
                .ask(&proto::chunk_name(&oid, idx as u32), ask)
                .await
                .map_err(|_| "no-response".to_string())?;
            match r.rcode {
                0 => {}
                3 => return Ok(Fetch::Stale),
                5 => return Err("refused".into()),
                c => return Err(format!("rcode-{c}")),
            }
            let part = r.txt.ok_or_else(|| "bad-chunk".to_string())?;
            if buf.len() + part.len() > o.size as usize {
                return Err("oversize".into());
            }
            buf.extend_from_slice(&part);
        }
        if buf.len() as u64 != o.size || sha_of(&buf) != sha {
            return Err("hash-mismatch".into());
        }
        let now = now_ms();
        let kid: [u8; 8] = upstream_kid.try_into().map_err(|_| "bad-object".to_string())?;
        let r = if filter {
            // 解壓一遍：確認大小沒有超過宣稱的（防壓縮炸彈），並用這台自己的方式算內容雜湊
            let h = copy_hash(&buf, &o.enc, o.raw.min(COPY_RAW_MAX)).map_err(|e| e.to_string())?;
            let mut o2 = o.clone();
            o2.hash = format!("{h:016x}");
            sink.import_filter_copy(&o2, buf)
        } else {
            let data = decode(&buf, &o.enc, o.raw.min(limit)).map_err(|e| e.to_string())?;
            drop(buf);
            match o.k.as_str() {
                KIND_UPSTREAMS => check_upstreams(&data, &kid, now).and_then(|j| sink.import_upstreams(j)),
                KIND_CDN_RANGES => check_ranges(&data).and_then(|f| sink.import_cdn_ranges(f)),
                KIND_CDN_POOLS => sink.import_cdn_pools(&data),
                KIND_CDN_V6 => sink.import_cdn_v6(&data),
                _ => return Err("unknown-kind".into()),
            }
        };
        if let Err(e) = r {
            warn!("共用結果：{} 沒有匯入：{e:#}", o.k);
            return Err("import-failed".into());
        }
        self.state.lock().unwrap().kinds.insert(
            key.clone(),
            Imported {
                sha: sha_hex,
                at: o.at,
                imported_at: now,
                bytes: o.size,
            },
        );
        rep.imported.push(key);
        Ok(Fetch::Done)
    }

    /// 背景同步：串接後 `first`（30 秒）做第一次，之後每 `every`（6 小時 ±10 分鐘）；
    /// 記憶體壓力大時延後 10 分鐘。每一輪 runtime 呼叫一次（舊的一輪的工作跟著 runtime 結束）
    pub fn spawn(self: &Arc<Self>) {
        let generation = self.generation.fetch_add(1, Ordering::SeqCst).wrapping_add(1);
        let me = self.clone();
        tokio::spawn(async move {
            let alive = |me: &Syncer| me.generation.load(Ordering::SeqCst) == generation;
            while alive(&me) {
                if !me.client.is_chained() {
                    me.state.lock().unwrap().next_sync_at = None;
                    me.wake.notified().await;
                    continue;
                }
                let t = me.timing.lock().unwrap().clone();
                me.state.lock().unwrap().next_sync_at = Some(now_ms() + t.first.as_millis() as u64);
                if !me.sleep_chained(t.first).await {
                    continue;
                }
                // 上游的清單還在背景建置（第一次、或 30 分鐘沒人用釋放過）時會先回 REFUSED：
                // 隔 `first`（30 秒）再試，連續最多 3 次，之後回到正常的間隔
                let mut refused = 0u32;
                while alive(&me) && me.client.is_chained() {
                    let wait = if me.sink().pressure_ok() {
                        let rep = me.sync_once().await;
                        let retry = rep.error.as_deref() == Some("refused") && refused < 3;
                        refused = if retry { refused + 1 } else { 0 };
                        let j = t.jitter.as_millis() as u64;
                        if retry {
                            me.state.lock().unwrap().next_sync_at = Some(now_ms() + t.first.as_millis() as u64);
                            if !me.sleep_chained(t.first).await {
                                break;
                            }
                            continue;
                        }
                        let d = t.every.as_millis() as u64 + random_below(2 * j + 1);
                        Duration::from_millis(d.saturating_sub(j).max(1000))
                    } else {
                        debug!("共用結果：記憶體偏低，延後同步");
                        t.defer
                    };
                    me.state.lock().unwrap().next_sync_at = Some(now_ms() + wait.as_millis() as u64);
                    if !me.sleep_chained(wait).await {
                        break;
                    }
                }
            }
        });
    }

    /// 等 `d` 或狀態改變；回傳之後還是不是串接中
    async fn sleep_chained(&self, d: Duration) -> bool {
        tokio::select! {
            _ = tokio::time::sleep(d) => {}
            _ = self.wake.notified() => {}
        }
        self.client.is_chained()
    }
}

/// 狀態檔裡的鍵：過濾清單副本一份清單一個
fn kind_key(kind: &str, name: &str) -> String {
    if kind == KIND_FILTER_COPY {
        format!("{kind} {name}")
    } else {
        kind.to_string()
    }
}

/// 解壓（限制輸出大小：超過 `limit` 就中止，防壓縮炸彈）
fn decode(buf: &[u8], enc: &str, limit: u64) -> Result<Vec<u8>> {
    if enc == "none" {
        if buf.len() as u64 > limit {
            bail!("too-large");
        }
        return Ok(buf.to_vec());
    }
    let dec = zstd::stream::read::Decoder::new(buf).map_err(|_| anyhow!("bad-encoding"))?;
    let mut out = Vec::new();
    dec.take(limit + 1).read_to_end(&mut out).map_err(|_| anyhow!("bad-encoding"))?;
    if out.len() as u64 > limit {
        bail!("too-large");
    }
    Ok(out)
}

/// 過濾清單副本的內容雜湊（同 `filtering::CopySink` 的算法），邊解壓邊算、不留內容；超過 `limit` 就中止
fn copy_hash(buf: &[u8], enc: &str, limit: u64) -> Result<u64> {
    if enc != "zstd" {
        bail!("bad-encoding");
    }
    let mut dec = zstd::stream::read::Decoder::new(buf).map_err(|_| anyhow!("bad-encoding"))?;
    let mut h = std::collections::hash_map::DefaultHasher::new();
    let mut n = 0u64;
    let mut chunk = vec![0u8; STREAM_STEP];
    loop {
        let k = dec.read(&mut chunk).map_err(|_| anyhow!("bad-encoding"))?;
        if k == 0 {
            break;
        }
        n += k as u64;
        if n > limit {
            bail!("too-large");
        }
        h.write(&chunk[..k]);
    }
    h.write_u64(n);
    Ok(h.finish())
}

// ---------------- 行程層級 ----------------

/// `/api/status` 的 `chain.shared`
pub fn shared_json() -> Value {
    super::syncer().map(|s| s.status_json()).unwrap_or(Value::Null)
}

/// `autoUpstreams.source` 用：（檔案時間，來源）
static AUTO_SOURCE: Mutex<Option<(SystemTime, &'static str)>> = Mutex::new(None);

/// `autoUpstreams`（現有欄位）加上 `source`：`"chain"`（上游黑潮給的）或 `"benchmark"`（自己評測的）
pub fn auto_info(mgr: &crate::upstreams::Manager) -> Value {
    let mut v = mgr.auto_info();
    if let Some(o) = v.as_object_mut() {
        let path = mgr.state_file();
        let mtime = std::fs::metadata(path).and_then(|m| m.modified()).ok();
        let cached = AUTO_SOURCE.lock().unwrap().filter(|(t, _)| Some(*t) == mtime).map(|(_, s)| s);
        let src = cached.unwrap_or_else(|| {
            let s = std::fs::read(path)
                .ok()
                .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
                .filter(|v| v.pointer("/source/chain").is_some_and(Value::is_string))
                .map_or("benchmark", |_| "chain");
            if let Some(t) = mtime {
                *AUTO_SOURCE.lock().unwrap() = Some((t, s));
            }
            s
        });
        o.insert("source".into(), json!(src));
    }
    v
}

// ---------------- 正式環境的來源與匯入端 ----------------

/// `app` 用的 [`ShareSource`] 與 [`ShareSink`]：接到這一輪的 Manager、CDN、過濾
pub struct Live {
    pub mgr: Arc<crate::upstreams::Manager>,
    pub cdn: Option<Arc<kuroshio_cdn::Cdn>>,
    pub filter: Option<Arc<crate::filtering::FilterService>>,
    /// 隨程式附帶的種子評測結果（跟它一樣的不分享）
    pub seed_upstreams: PathBuf,
    /// 匯入節點池時每家最多幾個（`pool.poolSize × 4`）
    pub max_per_provider: usize,
}

impl Live {
    fn cdn_or_err(&self) -> Result<&Arc<kuroshio_cdn::Cdn>> {
        self.cdn.as_ref().ok_or_else(|| anyhow!("這台沒有啟用 CDN"))
    }

    /// 新的節點池：15 秒後重新量一次健康與品質（同 `cdn-pool` 工作結束後的做法）
    fn recheck_later(c: &Arc<kuroshio_cdn::Cdn>) {
        let c = c.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(15)).await;
            c.health_check().await;
            c.quality_check().await;
        });
    }
}

fn generated_at(b: &[u8]) -> Option<String> {
    serde_json::from_slice::<Value>(b)
        .ok()?
        .get("generatedAt")?
        .as_str()
        .map(str::to_string)
}

impl ShareSource for Live {
    fn upstreams(&self) -> Option<Vec<u8>> {
        let b = std::fs::read(self.mgr.state_file()).ok()?;
        let v: Value = serde_json::from_slice(&b).ok()?;
        let g = v.get("generatedAt").and_then(Value::as_str)?;
        if !v.get("selected").and_then(Value::as_array).is_some_and(|a| !a.is_empty()) {
            return None;
        }
        // 種子資料（還沒評測過）：下游自己也有
        if std::fs::read(&self.seed_upstreams).ok().and_then(|s| generated_at(&s)).as_deref() == Some(g) {
            return None;
        }
        // 從別的黑潮拿來的（三層）照樣往下傳
        Some(b)
    }

    fn cdn(&self) -> Option<kuroshio_cdn::SharedExport> {
        self.cdn.as_ref().filter(|c| c.enabled()).map(|c| c.export_shared())
    }

    fn filter_copies(&self) -> Vec<FilterCopy> {
        let Some(f) = &self.filter else { return Vec::new() };
        f.shared_copies()
            .into_iter()
            .map(|(url, m, path)| FilterCopy {
                url,
                bytes: std::fs::metadata(&path).map(|x| x.len()).unwrap_or(m.bytes),
                file: path.to_string_lossy().into_owned(),
                raw: 0,
                hash: m.hash,
                rules: m.rules,
                etag: m.etag,
                last_modified: m.last_modified,
                at: m.at * 1000,
            })
            .collect()
    }

    fn read_copy(&self, file: &str, offset: u64, len: usize) -> Option<Vec<u8>> {
        use std::io::Seek;
        let mut f = std::fs::File::open(file).ok()?;
        f.seek(std::io::SeekFrom::Start(offset)).ok()?;
        let mut out = Vec::with_capacity(len);
        f.take(len as u64).read_to_end(&mut out).ok()?;
        Some(out)
    }

    fn pressure_ok(&self) -> bool {
        crate::app::pressure() == crate::sysinfo::Pressure::Normal
    }
}

impl ShareSink for Live {
    fn import_upstreams(&self, json: Vec<u8>) -> Result<()> {
        crate::persist::write_atomic(self.mgr.state_file(), &json)?;
        self.mgr.reload_auto();
        Ok(())
    }

    fn import_cdn_ranges(&self, files: BTreeMap<String, String>) -> Result<()> {
        let c = self.cdn_or_err()?;
        let dir = c.paths.state_dir.join("cdn").join("ranges");
        std::fs::create_dir_all(&dir)?;
        let mut changed = false;
        for (name, text) in files {
            let p = dir.join(&name);
            if std::fs::read(&p).ok().as_deref() == Some(text.as_bytes()) {
                continue;
            }
            crate::persist::write_atomic(&p, text.as_bytes())?;
            changed = true;
        }
        if changed {
            c.reload_ranges();
        }
        Ok(())
    }

    fn import_cdn_pools(&self, json: &[u8]) -> Result<()> {
        let c = self.cdn_or_err()?;
        let got = c.import_shared(Some(json), None, self.max_per_provider)?;
        if got.is_empty() {
            bail!("沒有可用的節點");
        }
        Self::recheck_later(c);
        Ok(())
    }

    fn import_cdn_v6(&self, json: &[u8]) -> Result<()> {
        let c = self.cdn_or_err()?;
        let got = c.import_shared(None, Some(json), self.max_per_provider)?;
        if got.is_empty() {
            bail!("沒有可用的節點");
        }
        Ok(())
    }

    fn wants_filter_copy(&self, o: &Object) -> Result<(), &'static str> {
        let Some(f) = &self.filter else { return Err("not-subscribed") };
        if !f.subscribes(&o.name) {
            return Err("not-subscribed");
        }
        if !ShareSink::pressure_ok(self) || !f.build_room_ok(o.rules) {
            return Err("memory");
        }
        if !f.copy_wanted(o.size) {
            return Err("no-room");
        }
        Ok(())
    }

    fn import_filter_copy(&self, o: &Object, compressed: Vec<u8>) -> Result<()> {
        let f = self.filter.as_ref().ok_or_else(|| anyhow!("過濾沒有啟用"))?;
        let hash = u64::from_str_radix(&o.hash, 16).map_err(|_| anyhow!("內容雜湊格式錯誤"))?;
        let some = |s: &str| (!s.is_empty()).then(|| s.to_string());
        let v = crate::fetch::Validators {
            etag: some(&o.etag),
            last_modified: some(&o.last_modified),
        };
        f.import_shared_copy(&o.name, hash, compressed, &v, o.rules);
        Ok(())
    }

    fn filter_copies_done(&self, changed: usize) {
        let Some(f) = self.filter.clone() else { return };
        info!("共用結果：從上游黑潮拿到 {changed} 份清單副本，用副本重建過濾器");
        tokio::spawn(async move {
            if let Err(e) = f.rebuild_from_copies().await {
                warn!("用上游給的清單副本重建過濾器失敗：{e:#}");
            }
        });
    }

    fn pressure_ok(&self) -> bool {
        crate::app::pressure() == crate::sysinfo::Pressure::Normal
    }
}

/// `app::start` 的最後（CDN、過濾、排程器都啟動之後）：上游接上 `ShareCache`、下游建立／接回 `Syncer`
pub fn start(
    cfg: &Value,
    resolver: &Arc<crate::resolver::Resolver>,
    cdn: Option<Arc<kuroshio_cdn::Cdn>>,
    filter: Option<Arc<crate::filtering::FilterService>>,
    persister: &Arc<Mutex<crate::persist::Persister>>,
    scheduler: Option<&Arc<kuroshio_jobs::Scheduler>>,
) {
    let live = Arc::new(Live {
        mgr: resolver.upstreams.clone(),
        cdn,
        filter,
        seed_upstreams: crate::app::share_dir(cfg).join("seed").join("upstreams.json"),
        max_per_provider: kuroshio_cdn::config::JobsConfig::from_value(cfg).pool_size.max(1) * 4,
    });
    // 上游
    if let Some(r) = resolver.chain.get() {
        let cache = Arc::new(ShareCache::new(live.clone()));
        r.set_share(cache.clone());
        // 先在背景建一次：第一個下游來問時大多已經就緒
        cache.warm();
        let w: Weak<ShareCache> = Arc::downgrade(&cache);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                let Some(c) = w.upgrade() else { break };
                c.sweep(now_ms());
            }
        });
    }
    // 下游
    let Some(client) = super::current() else { return };
    let s = match super::syncer() {
        Some(s) => {
            s.set_sink(live);
            s
        }
        None => {
            let saved = persister.lock().unwrap().load(STATE_FILE);
            let s = Syncer::new(client, live, saved.as_deref());
            super::install_syncer(s.clone());
            s
        }
    };
    let p = persister.clone();
    s.set_persist(Arc::new(move |b| p.lock().unwrap().stage(STATE_FILE, b)));
    match scheduler {
        Some(sched) => {
            let w = Arc::downgrade(sched);
            s.set_on_stale(Arc::new(move || {
                if let Some(sc) = w.upgrade() {
                    sc.request("dns-benchmark", "串接解除");
                }
            }));
        }
        None => *s.on_stale.lock().unwrap() = None,
    }
    s.spawn();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_generated_at() {
        assert_eq!(parse_time("1970-01-02T01:02:03.000Z"), 86_400_000 + 3_723_000);
        assert_eq!(parse_time("1970-01-02 00:30"), 86_400_000 + 1_800_000);
        assert_eq!(parse_time("abc"), 0);
    }

    #[test]
    fn decode_limits() {
        let z = compress(&[b'a'; 10_000]).unwrap();
        assert_eq!(decode(&z, "zstd", 10_000).unwrap().len(), 10_000);
        assert!(decode(&z, "zstd", 9_999).is_err());
        assert!(decode(b"xx", "none", 1).is_err());
        assert!(copy_hash(&z, "zstd", 9_999).is_err());
        assert!(copy_hash(&z, "zstd", 10_000).is_ok());
    }

    #[test]
    fn jobs_map_to_kinds() {
        assert_eq!(job_kind("dns-benchmark"), Some(KIND_UPSTREAMS));
        assert_eq!(job_kind("cdn-scan"), Some(KIND_CDN_POOLS));
        assert_eq!(job_kind("cdn-ranges"), Some(KIND_CDN_RANGES));
        assert_eq!(job_kind("tw-ip"), None);
    }
}
