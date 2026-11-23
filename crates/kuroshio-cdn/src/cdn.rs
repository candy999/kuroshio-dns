//! `Cdn`：CDN 子系統的進入點（狀態、載入、快照、背景工作排程）

use crate::config::CdnConfig;
use crate::db::{self, Db};
use crate::net::Net;
use crate::pools::{self, Classifier, PoolNode, Pools, PoolsFile, ProvEntry};
use crate::util::{self, now_ms};
use crate::v6store::{self, V6Store};
use indexmap::IndexMap;
use serde_json::{json, Value};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

/// 檔案位置
#[derive(Debug, Clone)]
pub struct Paths {
    /// 狀態目錄（`state/`）：快照與每週工作的輸出（`cdn/ranges`、`cdn/scan`）
    pub state_dir: PathBuf,
    /// 種子資料（`data/seed/`）：狀態是空的時候先用（同 2.x `lib/seed.js`）
    pub seed_dir: PathBuf,
    /// 隨程式附帶的 CDN 範圍與分類（`data/cdn/`）：`state/cdn/` 沒有的時候用
    pub cdn_data_dir: PathBuf,
}

impl Paths {
    /// `data_dir` 是程式附帶資料的根目錄（底下有 `seed/` 與 `cdn/`）
    pub fn new(state_dir: impl Into<PathBuf>, data_dir: impl AsRef<Path>) -> Paths {
        let d = data_dir.as_ref();
        Paths {
            state_dir: state_dir.into(),
            seed_dir: d.join("seed"),
            cdn_data_dir: d.join("cdn"),
        }
    }

    /// `cdn/` 底下的檔案：先找 state（每週工作產生），沒有再用 data（種子）
    pub fn cdn_file(&self, rel: &str) -> Option<PathBuf> {
        let s = self.state_dir.join("cdn").join(rel);
        if s.exists() {
            return Some(s);
        }
        let d = self.cdn_data_dir.join(rel);
        d.exists().then_some(d)
    }

    pub fn read_cdn_text(&self, rel: &str) -> Option<String> {
        self.cdn_file(rel)
            .and_then(|p| std::fs::read(p).ok())
            .map(|b| String::from_utf8_lossy(&b).into_owned())
    }
}

/// 好友同步一次最多放進候選名單幾個節點（每家 CDN、每個家族；同分享檔）
pub const FRIEND_MAX_NODES: usize = 500;

/// 社群提示：好友驗證過的 IP
#[derive(Debug, Clone, PartialEq)]
pub struct HintIp {
    pub ip: IpAddr,
    /// 哪位好友給的
    pub from: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CrossHint {
    pub to: String,
    pub ips: Vec<HintIp>,
}

/// 提示的種類（命中率分開算：網站提示準、跨 CDN 提示不準的好友，只暫停跨 CDN 那一種）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HintKind {
    /// 網站驗證過的台灣節點
    Site,
    /// 跨 CDN 結果
    Cross,
}

/// 社群共享（規格 03）提供的提示；回報命中率
pub trait Hints: Send + Sync {
    fn domain_hint(&self, name: &str, provider: &str, family: u8) -> Vec<HintIp>;
    fn hint_result(&self, from: &str, kind: HintKind, ok: bool);
    fn cross_hint(&self, name: &str) -> Option<CrossHint>;
}

/// 改寫統計（同 2.x 的 `cdn.stats`）
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    pub rewrites: u32,
    pub trials: u32,
    /// 小機器減量：只問過一次、這次先不驗證的（3.4.2）
    pub lite_waited: u32,
    /// 小機器減量：超過每分鐘上限、這次先不驗證的（3.4.2）
    pub lite_capped: u32,
    pub v6dropped: u32,
    pub ecs_rewrites: u32,
    pub cross_rewrites: u32,
    /// 來源變了而清掉跨 CDN／ECS／最佳策略的次數（3.5.0 B3）
    pub src_invalidated: u32,
    /// 多來源：這一家沒有格子、照原始答案回的次數（3.5.0 B3）
    pub multi_held: u32,
    /// App 自己選節點的服務：只辨識、不改寫的次數（3.5.0 B3）
    pub app_layer: u32,
}

/// 背景工作
#[derive(Debug, Clone, PartialEq)]
pub enum Task {
    /// 驗證換到台灣節點後能不能用
    Verify {
        name: String,
        provider: String,
        family: u8,
        orig: Option<IpAddr>,
    },
    /// ECS 突破
    Ecs {
        name: String,
        ips4: Vec<IpAddr>,
        ips6: Vec<IpAddr>,
    },
    /// 跨 CDN 探索
    Cross { name: String, from: String, orig: IpAddr },
    /// 新看到的 IPv6：運氣好就是台灣節點
    TryV6 { provider: String, ip: IpAddr },
    /// 先測個延遲（下次查詢時就有數字可比）
    Latency(IpAddr),
}

pub struct State {
    pub db: Db,
    pub pools: Pools,
    pub v6: V6Store,
    pub stats: Stats,
    pub cross_explored: u32,
    pub cross_ok: u32,
    /// ECS 子網路：外層指定的優先網段（規格 06 第 3.1 節）
    pub ecs_preferred: Vec<String>,
    /// 其他網段（偵測到的 WAN 網段在前，接著是設定的台灣網段）
    pub ecs_subnets: Vec<String>,
    /// 每個網段成功找到更近節點的次數
    pub ecs_wins: HashMap<String, u32>,
    /// 目前公布給查詢用的分類快照（跟 `Cdn::classifier` 是同一份；用來判斷範圍有沒有換過）
    classifier: Arc<Classifier>,
}

/// 拿著狀態鎖的期間。放開的時候如果節點池的範圍 / 分類換過，順便更新查詢用的分類快照
/// （不管是誰、用什麼方式改的都會被發現，不需要每個改的地方記得通知）
pub struct StateGuard<'a> {
    g: MutexGuard<'a, State>,
    cdn: &'a Cdn,
    mutated: bool,
}

impl Deref for StateGuard<'_> {
    type Target = State;
    fn deref(&self) -> &State {
        &self.g
    }
}

impl DerefMut for StateGuard<'_> {
    fn deref_mut(&mut self) -> &mut State {
        self.mutated = true;
        &mut self.g
    }
}

impl Drop for StateGuard<'_> {
    fn drop(&mut self) {
        if self.mutated && !self.g.classifier.same_as(&self.g.pools) {
            let c = Arc::new(self.g.pools.classifier());
            self.g.classifier = c.clone();
            *self.cdn.classifier.write().unwrap_or_else(|e| e.into_inner()) = c;
            // 先換內容、再加版本號（讀的那邊順序相反）：不會有人把舊內容記成新版本
            self.cdn.cls_gen.fetch_add(1, Ordering::Release);
        }
    }
}

#[derive(Default)]
struct Bg {
    record: Option<Vec<Task>>,
    verify: HashSet<String>,
    ecs: HashSet<String>,
    cross: HashSet<String>,
    /// 進行中的節點延遲量測（3.4.1：設上限）
    latency: usize,
    /// 排隊已滿、這次沒有排的背景工作數（3.4.1；之後的查詢會再排）
    deferred: u64,
}

/// 每種背景工作（驗證、ECS、跨 CDN）最多排幾個在等（含進行中）：同時可以做的數量 × 這個倍數，至少 [`QUEUE_MIN`]。
/// 3.4.1：以前每個工作先開好再等名額，MT7621 這種慢 CPU 一波查詢就能堆上千個（記憶體跟著漲，也都很晚才做完）。
/// 排不進的不記任何狀態：網域還是「驗證中」，下一次查詢會再排
const QUEUE_PER_PERMIT: usize = 16;
const QUEUE_MIN: usize = 32;
/// 同時進行的節點延遲量測上限
const LATENCY_MAX: usize = 64;

fn queue_cap(concurrency: usize) -> usize {
    (concurrency.max(1) * QUEUE_PER_PERMIT).max(QUEUE_MIN)
}

#[derive(Clone, Copy)]
enum Kind {
    Verify,
    Ecs,
    Cross,
    Latency,
}

/// 背景工作結束時把名額還回去；工作被取消（重新載入時舊的 runtime 結束）也一樣，
/// 不然留在名單裡的鍵會一直佔著排隊上限
struct BgSlot(Arc<Cdn>, Kind, String);

impl Drop for BgSlot {
    fn drop(&mut self) {
        let mut bg = self.0.bg.lock().unwrap();
        match self.1 {
            Kind::Verify => {
                bg.verify.remove(&self.2);
            }
            Kind::Ecs => {
                bg.ecs.remove(&self.2);
            }
            Kind::Cross => {
                bg.cross.remove(&self.2);
            }
            Kind::Latency => bg.latency = bg.latency.saturating_sub(1),
        }
    }
}

pub struct Cdn {
    pub cfg: Arc<CdnConfig>,
    pub paths: Paths,
    pub(crate) net: Arc<dyn Net>,
    state: Mutex<State>,
    /// IP 分類的唯讀快照：`apply()` 先用它判斷回應是不是 CDN，不是的話完全不碰 `state` 的鎖
    classifier: RwLock<Arc<Classifier>>,
    /// 分類快照的版本號（換一次加一）與這個 `Cdn` 的編號：每個執行緒記住自己上次拿到的那一份，
    /// 版本沒變就不必碰共用的鎖與參照計數（多核心同時查詢時不會互相拖慢）
    cls_gen: AtomicU32,
    cls_id: u32,
    bg: Mutex<Bg>,
    pub(crate) verify_sem: Arc<Semaphore>,
    pub(crate) ecs_sem: Arc<Semaphore>,
    pub(crate) cross_sem: Arc<Semaphore>,
    hints: RwLock<Option<Arc<dyn Hints>>>,
    on_low_pool: RwLock<Option<LowPoolFn>>,
    /// 移出記憶體的冷資料筆數（`Db::evicted_count` 的副本）：0 時查詢路徑完全不必檢查
    evicted_n: AtomicU32,
    /// 小機器減量：這一分鐘（Unix 分鐘）排了幾個驗證
    lite_rate: Mutex<(u64, u32)>,
    /// 磁碟預算（3.5.0 C5）：因為預算淘汰的網域累計筆數、上次量到分片目錄實際佔多少（KB；`u32::MAX` = 還沒量）
    budget_pruned: AtomicU32,
    disk_kb: AtomicU32,
}

/// 一輪磁碟預算淘汰的結果（[`Cdn::budget_round`]）
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BudgetRound {
    /// 淘汰幾筆
    pub dropped: usize,
    /// 整理了幾個分片，其中幾個是為了淘汰主動重寫的
    pub shards: usize,
    pub forced: usize,
}

/// 冷資料移出 / 讀回的結果（記憶體控制，規格 09）
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ColdReport {
    pub entries: usize,
    /// 估計的記憶體（bytes）
    pub bytes: usize,
}

static NEXT_CLS_ID: AtomicU32 = AtomicU32::new(0);

thread_local! {
    /// （`Cdn` 編號，版本號，分類快照）
    static CLS: RefCell<Option<(u32, u32, Arc<Classifier>)>> = const { RefCell::new(None) };
}

type LowPoolFn = Arc<dyn Fn(&str) + Send + Sync>;

/// 拿狀態鎖之前先空轉試幾次（一次幾奈秒；單核心的機器上最多白等幾微秒）
const SPIN_TRIES: u32 = 200;

/// 寫網域資料庫的快照時，每拿一次鎖寫幾筆（一筆約 0.5 KB、幾微秒）
const DUMP_CHUNK: usize = 256;

/// 網域資料庫的變動（`snapshots_sharded`）
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DomainChanges {
    /// 分片數
    pub shards: usize,
    /// 有變動的分片：（編號，是否重要變動——否 = 只有計數）
    pub changed: Vec<(usize, bool)>,
    /// 要寫的分片清單：（內容，清單寫好之後要刪掉的舊檔）。清單要等所有分片都寫好才寫
    pub manifest: Option<(Vec<u8>, Vec<String>)>,
}

/// 狀態檔（相對於狀態目錄）
pub const STATE_FILES: [&str; 5] = [pools::FILE, v6store::FILE, db::FILE, db::HARVEST_FILE, pools::ZONE_FILE];

impl Cdn {
    /// 從狀態目錄載入（沒有或是空的就用種子資料）
    pub fn load(cfg: &Value, paths: Paths, net: Arc<dyn Net>) -> Arc<Cdn> {
        let dir = paths.state_dir.clone();
        Cdn::load_with(cfg, paths, net, &|rel| crate::statefile::read(&dir.join(rel)))
    }

    /// 同 `load`，但狀態檔由 `read`（相對路徑 → 內容）提供，例如快照寫入器的 `load()`
    /// （這樣它會記住目前的內容，沒變就不重寫）
    pub fn load_with(cfg: &Value, paths: Paths, net: Arc<dyn Net>, read: &dyn Fn(&str) -> Option<Vec<u8>>) -> Arc<Cdn> {
        let c = Arc::new(CdnConfig::from_value(cfg));
        let seed_ok = paths.seed_dir.join("meta.json").exists();
        let seed = |name: &str| -> Option<Vec<u8>> {
            if seed_ok {
                crate::statefile::read(&paths.seed_dir.join(name))
            } else {
                None
            }
        };
        let mut used: Vec<&str> = Vec::new();

        // 永久 IPv6 節點
        let mut v6 = read(v6store::FILE)
            .and_then(|b| {
                V6Store::from_json(&b, c.v6_max)
                    .map_err(|e| warn!("{} 讀取失敗：{e}", v6store::FILE))
                    .ok()
            })
            .unwrap_or_else(|| V6Store::new(c.v6_max));
        if v6.is_empty() {
            if let Some(s) = seed("v6-nodes.json")
                .and_then(|b| V6Store::from_json(&b, c.v6_max).ok())
                .filter(|s| !s.is_empty())
            {
                v6 = s;
                v6.dirty = true;
                used.push("永久 IPv6 節點");
            }
        }

        // 節點池
        let parse_pools = |b: Vec<u8>| {
            serde_json::from_slice::<PoolsFile>(&b)
                .map_err(|e| warn!("{} 讀取失敗：{e}", pools::FILE))
                .ok()
        };
        let mut pf = read(pools::FILE).and_then(parse_pools);
        let mut pools_seeded = false;
        if pf.as_ref().map(|p| p.is_empty()).unwrap_or(true) {
            if let Some(s) = seed("cdn-pools.json")
                .and_then(|b| serde_json::from_slice::<PoolsFile>(&b).ok())
                .filter(|p| !p.is_empty())
            {
                pf = Some(s);
                pools_seeded = true;
                used.push("台灣節點池");
            }
        }
        let reader = |rel: &str| paths.read_cdn_text(rel);
        let mut pools = Pools::load(c.clone(), &reader, pf, &mut v6);
        pools.dirty = pools_seeded;
        if let Some(b) = read(pools::ZONE_FILE) {
            if let Err(e) = pools.load_zone(&b) {
                warn!("{} 讀取失敗：{e}", pools::ZONE_FILE);
            }
        }

        // 網域資料庫：分片（舊版的單一檔案也讀，之後搬進分片）
        let mut db = Db::new(c.max_entries);
        db.multi_cdn = c.multi_cdn;
        let shard_dir = paths.state_dir.join(db::SHARD_DIR);
        let list = || -> Vec<String> {
            std::fs::read_dir(&shard_dir)
                .map(|rd| rd.flatten().filter_map(|e| e.file_name().into_string().ok()).collect())
                .unwrap_or_default()
        };
        let store = db.load_store(read, &list);
        if db.domains.is_empty() {
            // 匯入時把「最後出現時間」設成現在：每小時的複驗只處理最近 3 天出現過的網域
            if let Some(b) = seed("cdn-domains.json") {
                if db.load_domains(&b, true).map(|n| n > 0).unwrap_or(false) {
                    db.dirty = true;
                    used.push("CDN 網域驗證紀錄");
                }
            }
        }
        db.plan_after_load(&store);
        if store.legacy {
            info!("CDN 網域資料庫搬進分片（{} 片、壓縮）：寫完之後刪掉舊的 {}", db.shards, db::FILE);
        }
        if let Some(b) = read(db::HARVEST_FILE) {
            if let Err(e) = db.load_harvest(&b) {
                warn!("{} 讀取失敗：{e}", db::HARVEST_FILE);
            }
        }
        info!("CDN 網域資料庫：{} 筆", db.domains.len());
        if !used.is_empty() {
            info!("第一次啟動，帶入種子資料：{}", used.join("、"));
        }

        let classifier = Arc::new(pools.classifier());
        let me = Cdn {
            classifier: RwLock::new(classifier.clone()),
            cls_gen: AtomicU32::new(0),
            cls_id: NEXT_CLS_ID.fetch_add(1, Ordering::Relaxed),
            verify_sem: Arc::new(Semaphore::new(c.verify_concurrency.max(1))),
            lite_rate: Mutex::new((0, 0)),
            ecs_sem: Arc::new(Semaphore::new(c.ecs.concurrency.max(1))),
            cross_sem: Arc::new(Semaphore::new(c.cross.concurrency.max(1))),
            state: Mutex::new(State {
                db,
                pools,
                v6,
                stats: Stats::default(),
                cross_explored: 0,
                cross_ok: 0,
                ecs_preferred: Vec::new(),
                ecs_subnets: c.ecs.tw_subnets.clone(),
                ecs_wins: HashMap::new(),
                classifier,
            }),
            cfg: c,
            paths,
            net,
            bg: Mutex::new(Bg::default()),
            hints: RwLock::new(None),
            on_low_pool: RwLock::new(None),
            evicted_n: AtomicU32::new(0),
            budget_pruned: AtomicU32::new(0),
            disk_kb: AtomicU32::new(u32::MAX),
        };
        me.reset_octet_verdicts();
        // 啟動時先量一次實際的磁碟用量（3.5.0 D3 回報：重新啟動後到第一輪預算之前 dbDiskKB 是 null，
        // 預算換算的筆數也沒辦法用實測校正）。只有設了預算（小 Flash）才量：讀分片目錄裡每個檔的大小
        if me.cfg.db_disk_budget.is_some() {
            let disk = me.shard_dir_bytes();
            me.disk_kb
                .store(disk.div_ceil(1024).min(u32::MAX as u64 - 1) as u32, Ordering::Relaxed);
        }
        Arc::new(me)
    }

    /// 舊版用隨機 IP 驗證 Fastly 必然憑證不符；最後一段跟原始不同的失敗紀錄作廢，重新驗證
    fn reset_octet_verdicts(&self) {
        let mut st = self.state();
        let st = &mut *st;
        let mut reset = Vec::new();
        for e in st.db.domains.values_mut() {
            let Some(p) = e.provider() else { continue };
            if !st.pools.octet_mode(p) {
                continue;
            }
            if e.v4.as_ref().map(|v| v.is("fail") && v.algo != Some(2)).unwrap_or(false) {
                e.v4 = None;
                reset.push(e.name.clone());
            }
        }
        let n = reset.len();
        for name in reset {
            st.db.mark(&name);
        }
        if n > 0 {
            info!("重新驗證 {n} 個 Fastly 網域（舊版只試了少數網段）");
        }
    }

    pub fn enabled(&self) -> bool {
        self.cfg.enabled
    }

    pub fn net(&self) -> &Arc<dyn Net> {
        &self.net
    }

    /// 取得狀態（不要拿著鎖做網路操作）
    pub fn state(&self) -> StateGuard<'_> {
        // 鎖通常只被拿幾微秒：先空轉試幾次再排隊睡覺。多核心同時查 CDN 網域時，
        // 每次都睡覺、叫醒（各幾十微秒）比等鎖本身還久
        let mut g = None;
        for _ in 0..SPIN_TRIES {
            if let Ok(x) = self.state.try_lock() {
                g = Some(x);
                break;
            }
            std::hint::spin_loop();
        }
        StateGuard {
            g: g.unwrap_or_else(|| self.state.lock().unwrap()),
            cdn: self,
            mutated: false,
        }
    }

    /// IP 分類的唯讀快照（不拿狀態鎖）
    pub fn classifier(&self) -> Arc<Classifier> {
        self.classifier.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// 用目前的分類快照做事（查詢路徑用）：這個執行緒上次拿到的那一份還是最新的就直接用
    pub(crate) fn with_classifier<R>(&self, f: impl FnOnce(&Classifier) -> R) -> R {
        let gen = self.cls_gen.load(Ordering::Acquire);
        CLS.with(|slot| {
            let mut slot = slot.borrow_mut();
            match &*slot {
                Some((id, g, c)) if *id == self.cls_id && *g == gen => f(c),
                _ => {
                    let c = self.classifier();
                    let r = f(&c);
                    *slot = Some((self.cls_id, gen, c));
                    r
                }
            }
        })
    }

    /// 改狀態；節點不足的通知在放開鎖之後才送出
    pub fn with_state<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        let (r, low) = {
            let mut st = self.state();
            let r = f(&mut st);
            (r, std::mem::take(&mut st.pools.low_pool))
        };
        if !low.is_empty() {
            if let Some(cb) = self.on_low_pool.read().unwrap().clone() {
                for p in low {
                    cb(p);
                }
            }
        }
        r
    }

    /// 節點不足時呼叫（2.x 的 `onLowPool`：排程重建節點池）
    pub fn set_on_low_pool(&self, f: impl Fn(&str) + Send + Sync + 'static) {
        *self.on_low_pool.write().unwrap() = Some(Arc::new(f));
    }

    /// 好友給的台灣節點（社群同步）：只當候選，跟分享檔的節點一樣處理——
    /// 落在那家 CDN 官方範圍內、我的節點池還沒有的，放進節點池工作的候選名單（`cdn/harvest.json`），
    /// 每家、每個家族一次最多 [`FRIEND_MAX_NODES`] 個，候選名單滿了就不放（不擠掉自己收集的）。
    /// 不會直接寫進節點池：每日節點池工作在本機量測、確認是台灣節點後才會使用。回傳新增幾個
    pub fn add_friend_nodes<'a>(&self, nodes: impl IntoIterator<Item = (&'a str, IpAddr)>) -> usize {
        self.add_friend_nodes_upto(nodes, FRIEND_MAX_NODES)
    }

    /// 同 [`Cdn::add_friend_nodes`]，每家、每個家族一次最多 `cap` 個（呼叫端保證不超過 [`FRIEND_MAX_NODES`]）
    pub(crate) fn add_friend_nodes_upto<'a>(&self, nodes: impl IntoIterator<Item = (&'a str, IpAddr)>, cap: usize) -> usize {
        let mut added = 0;
        let mut taken: HashMap<(String, bool), usize> = HashMap::new();
        self.with_state(|st| {
            for (p, ip) in nodes {
                let ip = crate::pools::unmap(ip);
                if !st.pools.in_ranges(p, ip) {
                    continue;
                }
                let v6 = ip.is_ipv6();
                let in_pool = st
                    .pools
                    .p
                    .get(p)
                    .is_some_and(|d| d.pool(if v6 { 6 } else { 4 }).iter().any(|x| x.ip == ip));
                if in_pool {
                    continue;
                }
                let n = taken.entry((p.to_string(), v6)).or_default();
                if *n >= cap {
                    continue;
                }
                if st.db.add_harvest_candidate(p, ip) {
                    *n += 1;
                    added += 1;
                }
            }
        });
        added
    }

    pub fn set_hints(&self, h: Option<Arc<dyn Hints>>) {
        *self.hints.write().unwrap() = h;
    }

    pub(crate) fn hints(&self) -> Option<Arc<dyn Hints>> {
        self.hints.read().unwrap().clone()
    }

    // ------------------------------------------------------------ 快照

    /// `stream` = 網域資料庫不序列化，只回報哪些分片有變動（由呼叫端用 `write_shard` 邊寫邊產生）
    fn collect(&self, all: bool, stream: bool) -> (Vec<(String, Vec<u8>)>, DomainChanges) {
        let mut out = Vec::new();
        // 網域資料庫（可能有 20 萬筆、上百 MB）分批寫：每批只拿一下鎖，查詢不會被整個擋住
        let mut dump = None;
        let mut changes = DomainChanges::default();
        {
            let mut st = self.state();
            let st = &mut *st;
            if all || st.pools.dirty {
                st.pools.dirty = false;
                out.push((pools::FILE.to_string(), st.pools.to_json()));
            }
            if all || st.v6.dirty {
                st.v6.dirty = false;
                out.push((v6store::FILE.to_string(), st.v6.to_json()));
            }
            if stream {
                changes.shards = st.db.shards;
                changes.changed = st.db.take_marks(all);
                if let Some(retire) = st.db.manifest_pending.take() {
                    changes.manifest = Some((st.db.manifest_json(), retire));
                }
            } else if all {
                // 關機：一次寫完（已經沒有查詢了，內容也要是同一個時間點的）
                st.db.take_marks(true);
                out.push((db::FILE.to_string(), st.db.domains_json()));
            } else if st.db.changed() {
                st.db.take_marks(true);
                dump = Some((out.len(), st.db.dump_begin()));
            }
            if all || st.db.harvest_dirty {
                st.db.harvest_dirty = false;
                out.push((db::HARVEST_FILE.to_string(), st.db.harvest_json()));
            }
            if all || st.pools.zone_dirty {
                st.pools.zone_dirty = false;
                out.push((pools::ZONE_FILE.to_string(), st.pools.zone_json()));
            }
        }
        if let Some((at, (mut buf, tail, keys))) = dump {
            let mut w = |b: &[u8]| -> std::io::Result<()> {
                buf.extend_from_slice(b);
                Ok(())
            };
            let _ = self.dump_rest(keys, &mut w);
            buf.extend_from_slice(&tail);
            out.insert(at, (db::FILE.to_string(), buf)); // 順序跟一次寫完時一樣
        }
        (out, changes)
    }

    /// 分批把網域接到後面（`dump_begin` 之後）：每批只拿一下鎖
    fn dump_rest(&self, mut keys: db::DumpKeys, w: &mut dyn FnMut(&[u8]) -> std::io::Result<()>) -> std::io::Result<()> {
        Db::dump_sort(&mut keys); // 不拿鎖
        let mut first = true;
        let mut buf = Vec::new();
        for chunk in keys.chunks(DUMP_CHUNK) {
            buf.clear();
            self.state().db.dump_chunk(chunk, &mut buf, &mut first);
            w(&buf)?;
            // 鎖已經放開：停一下讓等著的查詢先拿到鎖。只 yield 不夠——等的人被叫醒要幾十微秒，
            // 這邊馬上又把鎖拿走，查詢會一路等到整份寫完（實測 20 萬筆還是被擋 400 ms）
            std::thread::sleep(std::time::Duration::from_micros(100));
        }
        Ok(())
    }

    /// 上次取出之後有變動的狀態檔：（相對於狀態目錄的路徑，內容）。
    /// 內容是 2.x 相容的 JSON（不縮排）。網域資料庫可能很大（20 萬筆約 110 MB、要半秒）：分批序列化，
    /// 每批只拿一下鎖，查詢不會被擋住；但還是要花那麼多 CPU 與記憶體，不要太常呼叫（幾分鐘一次就好）。
    /// 分批期間有變動的網域，內容以寫到它的那一刻為準，下次呼叫會再寫一次。
    /// 正式執行時用 `snapshots_stream`（網域資料庫不整份放在記憶體）
    pub fn snapshots(&self) -> Vec<(String, Vec<u8>)> {
        // 整份寫成單一檔案：移出記憶體的冷資料先讀回來，不然會少
        self.restore_cold();
        self.collect(false, false).0
    }

    /// 全部的狀態檔（關機時）
    pub fn snapshots_all(&self) -> Vec<(String, Vec<u8>)> {
        self.restore_cold();
        self.collect(true, false).0
    }

    /// 正式執行用：同 `snapshots`，但網域資料庫不序列化，只回報哪些分片有變動（`all` = 全部都算重要變動）。
    /// 分片要寫的時候用 `write_shard` 直接寫進檔案，整份 JSON 不會放在記憶體裡
    pub fn snapshots_sharded(&self, all: bool) -> (Vec<(String, Vec<u8>)>, DomainChanges) {
        self.collect(all, true)
    }

    /// 把第 `i` 個分片（共 `n` 片，相對路徑 `db::shard_file(n, i)`）邊序列化邊寫出：分批拿鎖。
    /// 依名稱排序（內容沒變時寫出來的位元組也一樣）
    ///
    /// 這片有移出記憶體的冷資料（記憶體控制）時：從磁碟上的舊檔把它們接回去（依名稱排在一起），
    /// 所以寫出來的內容跟全部都在記憶體裡時一樣，磁碟上不會少
    pub fn write_shard(&self, n: usize, i: usize, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        let (mut keys, cold_hashes) = {
            let mut st = self.state();
            (st.db.shard_keys(n, i), st.db.evicted_hashes(n, i))
        };
        // 冷資料：舊檔裡雜湊對得上、記憶體裡沒有的
        let mut cold: HashMap<Arc<str>, db::Domain> = HashMap::new();
        if !cold_hashes.is_empty() {
            match self.read_shard(n, i) {
                Some(b) => {
                    let mut found = Vec::new();
                    let r = db::scan_shard(&b, &mut |d| {
                        if cold_hashes.binary_search(&db::name_hash(&d.name)).is_ok() {
                            found.push(d);
                        }
                    });
                    if let Err(e) = r {
                        warn!("CDN 網域分片 {} 讀不回來（{e}），移出記憶體的冷資料遺失", db::shard_file(n, i));
                    }
                    let st = self.state();
                    for d in found {
                        if st.db.get(&d.name).is_none() {
                            cold.insert(d.name.clone(), d);
                        }
                    }
                }
                None => {
                    warn!("CDN 網域分片 {} 不見了，移出記憶體的冷資料遺失", db::shard_file(n, i));
                    self.state().db.unevict_shard(i);
                    self.sync_evicted();
                }
            }
            keys.extend(cold.keys().cloned());
        }
        keys.sort_unstable();
        keys.dedup();
        let (head, tail) = Db::shard_frame(n, i);
        w.write_all(&head)?;
        let mut first = true;
        let mut buf = Vec::new();
        for (k, chunk) in keys.chunks(DUMP_CHUNK).enumerate() {
            if k > 0 {
                // 讓等著的查詢先拿到鎖（見 dump_rest）
                std::thread::sleep(std::time::Duration::from_micros(100));
            }
            buf.clear();
            if cold.is_empty() {
                self.state().db.dump_names(chunk, &mut buf, &mut first);
            } else {
                let st = self.state();
                for name in chunk {
                    match cold.get(name) {
                        Some(d) => {
                            if !first {
                                buf.push(b',');
                            }
                            first = false;
                            let _ = serde_json::to_writer(&mut buf, d);
                        }
                        None => st.db.dump_names(std::slice::from_ref(name), &mut buf, &mut first),
                    }
                }
            }
            w.write_all(&buf)?;
        }
        w.write_all(tail)
    }

    // ------------------------------------------------------------ 冷資料（記憶體控制，規格 09）

    /// 磁碟上的分片（一般 JSON 或 .zst）
    fn read_shard(&self, n: usize, i: usize) -> Option<Vec<u8>> {
        crate::statefile::read(&self.paths.state_dir.join(db::shard_file(n, i)))
    }

    fn sync_evicted(&self) {
        let n = self.state().db.evicted_count();
        self.evicted_n.store(n.min(u32::MAX as usize) as u32, Ordering::Relaxed);
    }

    /// 移出記憶體的冷資料筆數
    pub fn evicted_count(&self) -> usize {
        self.evicted_n.load(Ordering::Relaxed) as usize
    }

    /// 記憶體吃緊：把最後出現時間早於 `cold_ms` 毫秒以前的網域移出記憶體（磁碟上的分片保留）。
    /// `persisted(分片相對路徑)` = 這片已經寫進磁碟、沒有待寫內容；呼叫端要先讓快照寫入器把變動寫出去
    pub fn evict_cold(&self, cold_ms: u64, persisted: &dyn Fn(&str) -> bool) -> ColdReport {
        let r = {
            let mut st = self.state();
            let n = st.db.shards;
            let cutoff = now_ms().saturating_sub(cold_ms);
            st.db.evict_cold(cutoff, &|i| persisted(&db::shard_file(n, i)))
        };
        self.sync_evicted();
        ColdReport {
            entries: r.entries,
            bytes: r.bytes,
        }
    }

    /// 查詢用到移出記憶體的網域：從磁碟的分片把那一筆讀回來（只解析、不保留整片）。回傳有沒有讀回來
    pub fn ensure_loaded(&self, name: &str) -> bool {
        if self.evicted_n.load(Ordering::Relaxed) == 0 {
            return false;
        }
        let (n, i) = {
            let st = self.state();
            if st.db.get(name).is_some() || !st.db.is_evicted(name) {
                return false;
            }
            (st.db.shards, db::shard_of(name, st.db.shards))
        };
        let mut found = None;
        if let Some(b) = self.read_shard(n, i) {
            let _ = db::scan_shard(&b, &mut |d| {
                if found.is_none() && &*d.name == name {
                    found = Some(d);
                }
            });
        }
        let loaded = {
            let mut st = self.state();
            match found {
                Some(d) => st.db.insert_reloaded(d),
                None => {
                    st.db.unevict(name);
                    false
                }
            }
        };
        self.sync_evicted();
        loaded
    }

    /// 記憶體恢復：把移出的冷資料全部讀回記憶體（一次一片）。回傳讀回幾筆、多少記憶體
    pub fn restore_cold(&self) -> ColdReport {
        let mut out = ColdReport::default();
        if self.evicted_n.load(Ordering::Relaxed) == 0 {
            return out;
        }
        let (n, shards) = {
            let st = self.state();
            (st.db.shards, st.db.evicted_shards())
        };
        for i in shards {
            let r = self.restore_shard_cold(n, i);
            out.entries += r.entries;
            out.bytes += r.bytes;
        }
        self.sync_evicted();
        out
    }

    /// 把第 `i` 個分片移出記憶體的冷資料讀回來（讀不到的就從移出名單拿掉）
    fn restore_shard_cold(&self, n: usize, i: usize) -> ColdReport {
        let mut out = ColdReport::default();
        let hashes = self.state().db.evicted_hashes(n, i);
        if hashes.is_empty() {
            return out;
        }
        let mut found = Vec::new();
        if let Some(b) = self.read_shard(n, i) {
            let _ = db::scan_shard(&b, &mut |d| {
                if hashes.binary_search(&db::name_hash(&d.name)).is_ok() {
                    found.push(d);
                }
            });
        }
        let mut st = self.state();
        for d in found {
            let bytes = d.approx_bytes();
            if st.db.insert_reloaded(d) {
                out.entries += 1;
                out.bytes += bytes;
            }
        }
        st.db.unevict_shard(i);
        out
    }

    // ------------------------------------------------------------ 磁碟預算（3.5.0 C5，規格 05 第 5.7 節）

    /// 分片目錄在磁碟上實際佔多少（bytes；目錄不存在是 0）
    fn shard_dir_bytes(&self) -> u64 {
        std::fs::read_dir(self.paths.state_dir.join(db::SHARD_DIR))
            .map(|rd| {
                rd.flatten()
                    .filter_map(|e| e.metadata().ok())
                    .filter(|m| m.is_file())
                    .map(|m| m.len())
                    .sum()
            })
            .unwrap_or(0)
    }

    /// 磁碟預算換算的筆數上限（沒有預算時 None）。
    ///
    /// 先用估計模型（每筆 125 bytes、每片 1.1 KB）；量到實際的磁碟用量之後依實測校正（[`calibrated_limit`]），
    /// **只往上調**、最多到模型的 1.5 倍。3.5.0 D3 實測：模型比實際多估約 40%，照模型會多淘汰約三成其實放得下的網域。
    /// 磁碟上的檔案落後記憶體時會估得偏高，但檔案寫出後實際超過預算就會照「磁碟上也超過」開始淘汰，下一次量到就降回來
    pub fn budget_limit(&self) -> Option<usize> {
        let budget = self.cfg.db_disk_budget?;
        let (shards, total) = {
            let st = self.state();
            (st.db.shards, st.db.total_entries())
        };
        let model = db::budget_entries(Some(budget), shards)?;
        let disk_kb = self.disk_kb.load(Ordering::Relaxed);
        let disk = if disk_kb == u32::MAX { 0 } else { u64::from(disk_kb) * 1024 };
        Some(calibrated_limit(model, shards, total, disk, budget).min(self.cfg.max_entries.max(100)))
    }

    /// 磁碟預算的一輪（背景：每次定時登記快照之前呼叫一次，關機時不呼叫；不在查詢路徑上）。
    ///
    /// 小 Flash 上網域資料超過預算時，淘汰最不值得留的（[`Db::budget_rank`]）。為了不在一次重寫所有分片：
    /// 平常只順便整理「本來就要寫」的分片；超過預算 110%、磁碟上實際也超過時，才一輪主動重寫幾片（[`Db::budget_plan`]）。
    /// 沒有設定預算（大磁碟、`cdn.dbDiskBudgetKB: 0`）時只量一下實際大小給狀態頁，什麼都不刪
    pub fn budget_round(&self) -> BudgetRound {
        let mut out = BudgetRound::default();
        let disk = self.shard_dir_bytes();
        self.disk_kb
            .store(disk.div_ceil(1024).min(u32::MAX as u64 - 1) as u32, Ordering::Relaxed);
        let (Some(limit), Some(budget)) = (self.budget_limit(), self.cfg.db_disk_budget) else {
            return out;
        };
        let (plan, n) = {
            let mut st = self.state();
            (st.db.budget_plan(limit, disk > budget), st.db.shards)
        };
        if plan.sweep_started {
            warn!(
                "CDN 網域資料超過磁碟預算（{} 筆、磁碟上 {} KB；預算 {} KB ≈ {} 筆）：開始淘汰最久沒用的網域，\
                 每 5 分鐘最多重寫 {} 個分片，不會一次重寫全部{}。不想淘汰可以把 cdn.dbDiskBudgetKB 設成 0",
                plan.total,
                disk.div_ceil(1024),
                budget / 1024,
                plan.limit,
                (n / 16).max(1),
                if plan.total > plan.limit.saturating_mul(2) {
                    "（要淘汰的超過一半：升級後第一次套用預算時會這樣）"
                } else {
                    ""
                }
            );
        }
        if plan.shards.is_empty() {
            return out;
        }
        // 移出記憶體的冷資料先讀回來才比得出誰比較舊（一次一片；讀檔不拿鎖）
        if self.evicted_n.load(Ordering::Relaxed) > 0 {
            for (i, _) in &plan.shards {
                self.restore_shard_cold(n, *i);
            }
            self.sync_evicted();
        }
        let (dropped, left, sweeping) = {
            let mut st = self.state();
            let d = st.db.budget_prune(&plan.shards, now_ms());
            (d, st.db.total_entries(), st.db.budget_sweeping())
        };
        out.dropped = dropped;
        out.shards = plan.shards.len();
        out.forced = plan.forced;
        if dropped > 0 {
            let total = self
                .budget_pruned
                .load(Ordering::Relaxed)
                .saturating_add(dropped.min(u32::MAX as usize) as u32);
            self.budget_pruned.store(total, Ordering::Relaxed);
            if plan.forced > 0 || sweeping {
                info!(
                    "CDN 網域資料磁碟預算：淘汰 {dropped} 筆（整理 {} 個分片，其中 {} 個是為了淘汰重寫的），剩 {left} 筆（預算約 {} 筆）",
                    plan.shards.len(),
                    plan.forced,
                    plan.limit
                );
            } else {
                debug!(
                    "CDN 網域資料磁碟預算：順便淘汰 {dropped} 筆（{} 個本來就要寫的分片），剩 {left} 筆",
                    plan.shards.len()
                );
            }
        }
        out
    }

    /// `/api/status` 的 `cdn` 裡跟磁碟預算有關的欄位
    fn budget_json(&self, v: &mut Value) {
        let (total, shards) = {
            let st = self.state();
            (st.db.total_entries(), st.db.shards)
        };
        let disk = self.disk_kb.load(Ordering::Relaxed);
        v["dbBudgetKB"] = json!(self.cfg.db_disk_budget.map(|b| b / 1024));
        v["dbBudgetEntries"] = json!(self.budget_limit());
        v["dbEntries"] = json!(total);
        v["dbDiskKB"] = json!((disk != u32::MAX).then_some(disk));
        v["dbDiskEstKB"] = json!(db::budget_disk_estimate(total, shards).div_ceil(1024));
        v["prunedForBudget"] = json!(self.budget_pruned.load(Ordering::Relaxed));
    }

    /// 把網域資料庫（`cdn-domains.json`，內容同 `snapshots`）邊序列化邊寫出：分批拿鎖，
    /// 記憶體裡只有一批（256 筆）的內容
    pub fn write_domains(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        let (head, tail, keys) = self.state().db.dump_begin();
        w.write_all(&head)?;
        self.dump_rest(keys, &mut |b| w.write_all(b))?;
        w.write_all(&tail)
    }

    /// 記憶體不足（規格 05 第 3.2 節的看門狗）：網域資料庫刪到剩 `keep_ratio`（例如 0.5）
    pub fn shrink(&self, keep_ratio: f64) {
        let mut st = self.state();
        let n = (st.db.domains.len() as f64 * keep_ratio.clamp(0.0, 1.0)) as usize;
        st.db.shrink_to(n);
    }

    /// 每週工作更新了範圍或分類檔之後重新讀取
    pub fn reload_ranges(&self) {
        let paths = self.paths.clone();
        let reader = move |rel: &str| paths.read_cdn_text(rel);
        self.state().pools.reload_ranges(&reader);
        info!("CDN 範圍 / 網段分類已更新，重新載入");
    }

    // ------------------------------------------------------------ 背景工作

    /// 測試用：之後的背景工作只記錄、不執行
    pub fn record_tasks(&self) {
        self.bg.lock().unwrap().record = Some(Vec::new());
    }

    /// 測試用：取出記錄的背景工作
    pub fn take_tasks(&self) -> Vec<Task> {
        self.bg.lock().unwrap().record.as_mut().map(std::mem::take).unwrap_or_default()
    }

    /// 排入背景（同一個網域同時只跑一個；沒有 tokio runtime 時略過）
    pub fn schedule(self: &Arc<Self>, t: Task) {
        // 小機器減量（3.4.2）：驗證每分鐘最多 LITE_VERIFY_PER_MIN 個；排不進的跟排隊已滿一樣，下一次查詢再排
        if self.cfg.lite && matches!(t, Task::Verify { .. }) {
            let minute = now_ms() / 60_000;
            let over = {
                let mut r = self.lite_rate.lock().unwrap();
                if r.0 != minute {
                    *r = (minute, 0);
                }
                if r.1 >= crate::config::LITE_VERIFY_PER_MIN {
                    true
                } else {
                    r.1 += 1;
                    false
                }
            };
            if over {
                self.state().stats.lite_capped += 1;
                return;
            }
        }
        let mut bg = self.bg.lock().unwrap();
        if let Some(r) = bg.record.as_mut() {
            if r.len() < 10_000 {
                r.push(t);
            }
            return;
        }
        // 系統時間沒對時：HTTPS 驗證、ECS 探測的結果帶著錯的時間，不做（之後查詢時會再排）
        if !kuroshio_net::clock::synced() {
            return;
        }
        let Ok(rt) = tokio::runtime::Handle::try_current() else { return };
        let me = self.clone();
        match t {
            Task::Verify {
                name,
                provider,
                family,
                orig,
            } => {
                let key = format!("{name}|{family}");
                if bg.verify.len() >= queue_cap(self.cfg.verify_concurrency) && !bg.verify.contains(&key) {
                    bg.deferred += 1;
                    return;
                }
                if !bg.verify.insert(key.clone()) {
                    return;
                }
                rt.spawn(async move {
                    let g = BgSlot(me, Kind::Verify, key);
                    let _permit = g.0.verify_sem.clone().acquire_owned().await;
                    g.0.verify(&name, &provider, family, orig).await;
                });
            }
            Task::Ecs { name, ips4, ips6 } => {
                if bg.ecs.len() >= queue_cap(self.cfg.ecs.concurrency) && !bg.ecs.contains(&name) {
                    bg.deferred += 1;
                    return;
                }
                if !bg.ecs.insert(name.clone()) {
                    return;
                }
                rt.spawn(async move {
                    let g = BgSlot(me, Kind::Ecs, name);
                    let _permit = g.0.ecs_sem.clone().acquire_owned().await;
                    g.0.ecs_probe(&g.2, &ips4, &ips6).await;
                });
            }
            Task::Cross { name, from, orig } => {
                if !self.cfg.cross.enabled {
                    return;
                }
                if bg.cross.len() >= queue_cap(self.cfg.cross.concurrency) && !bg.cross.contains(&name) {
                    bg.deferred += 1;
                    return;
                }
                if !bg.cross.insert(name.clone()) {
                    return;
                }
                rt.spawn(async move {
                    let g = BgSlot(me, Kind::Cross, name);
                    let _permit = g.0.cross_sem.clone().acquire_owned().await;
                    g.0.cross_explore(&g.2, &from, orig).await;
                });
            }
            Task::TryV6 { provider, ip } => {
                rt.spawn(async move { me.try_v6(&provider, ip).await });
            }
            Task::Latency(ip) => {
                if bg.latency >= LATENCY_MAX {
                    bg.deferred += 1;
                    return;
                }
                bg.latency += 1;
                rt.spawn(async move {
                    let g = BgSlot(me, Kind::Latency, String::new());
                    g.0.net.latency(ip).await;
                });
            }
        }
    }

    pub(crate) fn schedule_all(self: &Arc<Self>, tasks: Vec<Task>) {
        for t in tasks {
            self.schedule(t);
        }
    }

    /// 排隊已滿而沒有排的背景工作累計數（3.4.1）
    pub fn deferred(&self) -> u64 {
        self.bg.lock().unwrap().deferred
    }

    /// 背景工作中的數量（驗證，ECS，跨 CDN）
    pub fn inflight(&self) -> (usize, usize, usize) {
        let bg = self.bg.lock().unwrap();
        (bg.verify.len(), bg.ecs.len(), bg.cross.len())
    }

    // ------------------------------------------------------------ 查詢（給解析流程與管理介面）

    /// IP 屬於哪家 CDN、哪一類
    pub fn classify(&self, ip: IpAddr) -> Option<crate::Class> {
        self.with_classifier(|c| c.classify(ip))
    }

    /// 這家是不是 IP 置換型（任播）CDN
    pub fn is_alias(provider: &str) -> bool {
        crate::providers::get(provider).map(|p| p.alias).unwrap_or(false)
    }

    /// 沒有台灣節點、改用最近節點的 CDN（Fastly）
    pub fn is_nearest(provider: &str) -> bool {
        crate::providers::get(provider).map(|p| p.nearest).unwrap_or(false)
    }

    pub fn stats(&self) -> Stats {
        self.state().stats
    }

    /// 記憶體裡的網域筆數（移出到磁碟的冷資料不算；記憶體控制的狀態用）
    pub fn domains_in_ram(&self) -> usize {
        self.state().db.domains.len()
    }

    /// 記憶體裡的網域資料庫大約多大（bytes；狀態頁分項用量用，不必精確）
    pub fn approx_ram_bytes(&self) -> usize {
        // 每筆的估計裡含雜湊表的一格；雜湊表實際配置的格數（容量）比筆數多，空格也佔記憶體（3.4.1 起算進去）
        let st = self.state();
        let m = &st.db.domains;
        let slot = std::mem::size_of::<(Arc<str>, crate::db::Domain)>();
        let items: usize = m.values().map(|d| d.approx_bytes()).sum();
        items + m.capacity().saturating_sub(m.len()) * slot + m.capacity() + 16
    }

    /// `/api/status` 的 cdn 區塊
    pub fn status_lite(&self) -> Value {
        let st = self.state();
        let (verify, ecs, cross, deferred) = {
            let bg = self.bg.lock().unwrap();
            (bg.verify.len(), bg.ecs.len(), bg.cross.len(), bg.deferred)
        };
        let mut v = json!({ "enabled": self.cfg.enabled, "lite": self.cfg.lite, "stats": st.stats, "domains": st.db.domains.len(),
                "background": { "verify": verify, "ecs": ecs, "cross": cross, "deferred": deferred } });
        drop(st);
        self.budget_json(&mut v);
        v
    }

    /// 狀態（同 2.x `optimizer.status()`）
    pub fn status(&self) -> Value {
        let st = self.state();
        json!({
            "enabled": self.cfg.enabled, "stats": st.stats, "pools": st.pools.status(), "domains": st.db.domains.len(),
            "cross": { "explored": st.cross_explored, "ok": st.cross_ok },
        })
    }

    /// `/api/cdn/pools`
    pub fn pools_status(&self) -> Value {
        self.state().pools.status()
    }

    /// `/api/cdn/v6nodes`
    pub fn v6_nodes(&self) -> Value {
        self.state().v6.to_value()
    }

    /// `/api/cdn/summary`
    pub fn summary(&self) -> Value {
        serde_json::to_value(self.state().db.summary()).unwrap_or_default()
    }

    /// `/api/cdn/domains`（JSON）
    pub fn query(&self, q: &db::Query) -> Value {
        let st = self.state();
        Value::Array(
            st.db
                .query(q)
                .into_iter()
                .map(|d| serde_json::to_value(d).unwrap_or_default())
                .collect(),
        )
    }

    /// `/api/cdn/domains?format=csv`
    pub fn query_csv(&self, q: &db::Query) -> String {
        let st = self.state();
        Db::to_csv(&st.db.query(q))
    }

    /// 某個網域的紀錄（`/api/trace` 的 cdnDb）
    pub fn domain(&self, name: &str) -> Option<Value> {
        self.ensure_loaded(&normalize(name));
        let st = self.state();
        st.db.get(&normalize(name)).map(Self::domain_json)
    }

    /// 網域紀錄加上算出來的來源資訊（3.5.0 B3）：`multi`（多來源）、`provs`（最近看到的業者，最多 3 個）
    fn domain_json(d: &db::Domain) -> Value {
        let mut v = serde_json::to_value(d).unwrap_or_default();
        if d.src.is_some() {
            v["multi"] = json!(d.multi(now_ms()));
            v["provs"] = d
                .provs()
                .into_iter()
                .map(|(p, t, slot)| json!({ "provider": p, "lastSeen": t, "verified": slot }))
                .collect();
        }
        v
    }

    /// `/api/cdn/policy`：auto / always / never
    pub fn set_policy(&self, name: &str, policy: &str) -> Option<Value> {
        let p = db::Policy::parse(policy)?;
        self.ensure_loaded(&normalize(name));
        let mut st = self.state();
        Some(serde_json::to_value(st.db.set_policy(&normalize(name), p)).unwrap_or_default())
    }

    /// `/api/cdn/verify`：立即驗證（網域要先解析過一次）。回傳（結果，網域紀錄）；資料庫沒有這個網域回 None
    pub async fn verify_now(self: &Arc<Self>, name: &str, family: u8) -> Option<(Option<&'static str>, Value)> {
        let name = normalize(name);
        self.ensure_loaded(&name);
        let (provider, orig) = {
            let st = self.state();
            let e = st.db.get(&name)?;
            let p = e.provider()?.to_string();
            let o = if family == 6 {
                e.ips6.first().copied()
            } else {
                e.ips4.first().copied()
            };
            (p, o)
        };
        let r = self.verify(&name, &provider, family, orig).await;
        Some((r, self.domain(&name).unwrap_or(Value::Null)))
    }

    /// `/api/cdn/ecs`：立即做一次 ECS 突破
    pub async fn ecs_now(self: &Arc<Self>, name: &str) -> Value {
        let name = normalize(name);
        let (i4, i6) = {
            let st = self.state();
            st.db.get(&name).map(|e| (e.ips4.clone(), e.ips6.clone())).unwrap_or_default()
        };
        if kuroshio_net::clock::synced() {
            self.ecs_probe(&name, &i4, &i6).await;
        }
        self.domain(&name).unwrap_or_else(|| json!({}))
    }

    /// 跨 CDN 統計
    pub fn cross_summary(&self) -> Value {
        self.state().db.cross_summary()
    }

    /// 每小時：熱門且即將到期的「驗證通過」網域先重新驗證，避免掉回 10 秒試用；
    /// 另外輪流抽一小批還在有效期內、最近真的有在改寫的網域複驗（見 `reverify_pick`）。回傳排入幾個
    pub fn recheck(self: &Arc<Self>) -> usize {
        let now = now_ms();
        let soon = now + util::HOUR_MS;
        let recent = now.saturating_sub(3 * util::DAY_MS);
        let mut tasks = Vec::new();
        let sampled;
        {
            let st = self.state();
            for e in st.db.domains.values() {
                if e.last_seen < recent {
                    continue;
                }
                let Some(p) = e.provider() else { continue };
                if !st.pools.has(p) {
                    continue;
                }
                for fam in [4u8, 6] {
                    let Some(v) = e.verdict(fam) else { continue };
                    if v.is("ok") && v.until.unwrap_or(0) < soon {
                        tasks.push(Task::Verify {
                            name: e.name.to_string(),
                            provider: p.to_string(),
                            family: fam,
                            orig: e.orig_ip(fam),
                        });
                    }
                }
            }
            let pick = self.reverify_pick(&st, now);
            sampled = pick.len();
            tasks.extend(pick);
        }
        let n = tasks.len();
        if n > 0 {
            info!("定時複驗：{n} 個網域（其中輪流抽驗 {sampled} 個）");
        }
        self.schedule_all(tasks);
        n
    }

    /// 輪流抽驗：判定「通過」要 24 小時才到期，期間節點一直健康、但某個網站開始不服務它
    /// （例如 Cloudflare 1034）時，會一路回壞掉的節點到到期為止。
    /// 每小時從「最近一天內有改寫（`best` = 換節點）、判定還有效、上次驗證超過一小時」的網域中，
    /// 抽「改寫中網域數 × `reverifyRatio`」個（限制在 `reverifyMin`～`reverifyMax`）重新驗證：
    /// 熱門程度 × 距上次驗證的時間越大越先（熱門的先驗，冷門的放久了也會輪到）。
    /// 驗證失敗就跟判定過期一樣，馬上改回原始結果。即將到期的由 `recheck` 處理，這裡不重複
    pub(crate) fn reverify_pick(&self, st: &State, now: u64) -> Vec<Task> {
        let c = &self.cfg;
        if c.reverify_ratio <= 0.0 || c.reverify_max == 0 {
            return vec![];
        }
        let active_since = now.saturating_sub(util::DAY_MS);
        let soon = now + util::HOUR_MS;
        let mut active = 0usize;
        // （優先度，網域，CDN，家族）
        let mut cand: Vec<(f64, &db::Domain, &str, u8)> = Vec::new();
        for e in st.db.domains.values() {
            if e.last_seen < active_since || e.best != Some(db::Strategy::Alias) || e.policy() != db::Policy::Auto {
                continue;
            }
            let Some(p) = e.provider() else { continue };
            if !st.pools.has(p) {
                continue;
            }
            for fam in [4u8, 6] {
                let Some(v) = e.verdict(fam).filter(|v| v.is("ok") && v.valid(now)) else {
                    continue;
                };
                active += 1;
                let until = v.until.unwrap_or(0);
                let age = now.saturating_sub(v.at.unwrap_or(0));
                if until < soon || age < util::HOUR_MS {
                    continue;
                }
                let score = (e.hits as f64 + 1.0) * (age as f64 / util::HOUR_MS as f64);
                cand.push((score, e, p, fam));
            }
        }
        if cand.is_empty() {
            return vec![];
        }
        let want = ((active as f64 * c.reverify_ratio).ceil() as usize)
            .max(c.reverify_min)
            .min(c.reverify_max)
            .min(cand.len());
        if want == 0 {
            return vec![];
        }
        if want < cand.len() {
            cand.select_nth_unstable_by(want - 1, |a, b| b.0.total_cmp(&a.0));
            cand.truncate(want);
        }
        cand.sort_by(|a, b| b.0.total_cmp(&a.0));
        cand.into_iter()
            .map(|(_, e, p, fam)| Task::Verify {
                name: e.name.to_string(),
                provider: p.to_string(),
                family: fam,
                orig: e.orig_ip(fam),
            })
            .collect()
    }
}

// ------------------------------------------------------------ 共用結果（串接模式，3.4.0）

/// 上游黑潮給下游的 CDN 資料（規格 10 第 3.1 節）：節點池、永久 IPv6 節點、官方範圍
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SharedExport {
    /// `cdn/pools.json` 的內容（只有節點池工作建過的才有；全部是種子資料時是 None）
    pub pools: Option<Vec<u8>>,
    /// `cdn/v6-nodes.json` 的內容（沒有任何節點是 None）
    pub v6: Option<Vec<u8>>,
    /// `cdn/ranges/*.txt`（只有每週工作抓過、在狀態目錄裡的；檔名 → 內容，依檔名排序）
    pub ranges: BTreeMap<String, String>,
}

/// 範圍、分類用的 CIDR 字串的網路位址（`a.b.c.0/24`、`x::/48`）
fn cidr_base(s: &str) -> Option<IpAddr> {
    s.split('/').next()?.trim().parse().ok()
}

impl Cdn {
    /// 共用結果的匯出（上游）：內容只跟資料有關（不加產生時間），資料沒變時每次的位元組都一樣
    pub fn export_shared(&self) -> SharedExport {
        let st = self.state();
        // 節點池：至少有一家是節點池工作建的（有 updatedAt）才分享；種子資料下游自己也有
        let built = st.pools.p.values().any(|d| d.rest.get("updatedAt").is_some_and(Value::is_string));
        let pools = built.then(|| {
            let mut providers: IndexMap<String, ProvEntry> = IndexMap::new();
            for (name, d) in &st.pools.p {
                providers.insert(
                    name.to_string(),
                    ProvEntry {
                        v4: (d.has_v4 || !d.pool4.is_empty()).then(|| d.pool4.clone()),
                        v6: (d.has_v6 || !d.pool6.is_empty()).then(|| d.pool6.clone()),
                        rest: d.rest.clone(),
                    },
                );
            }
            serde_json::to_vec(&PoolsFile {
                saved_at: None,
                providers,
                extra: Default::default(),
            })
            .unwrap_or_default()
        });
        let v6 = (!st.v6.is_empty()).then(|| st.v6.to_json());
        let names: Vec<&'static str> = st.pools.p.keys().copied().collect();
        drop(st);
        let mut ranges = BTreeMap::new();
        for name in names {
            for fam in ["ipv4", "ipv6"] {
                let file = format!("{name}-{fam}.txt");
                let p = self.paths.state_dir.join("cdn").join("ranges").join(&file);
                if let Ok(t) = std::fs::read_to_string(&p) {
                    if !t.trim().is_empty() {
                        ranges.insert(file, t);
                    }
                }
            }
        }
        SharedExport { pools, v6, ranges }
    }

    /// 共用結果的匯入（下游）：換掉節點池／永久 IPv6 節點（各自可以是 None）。
    ///
    /// - 節點一律要在那一家的官方範圍裡（不在的丟掉並記數），每家最多 `max_per_provider` 個
    /// - 全部被丟掉的那一家保留原本的池；這台沒有啟用的 CDN 不收
    /// - 換掉之後標成要寫檔（照平常的快照流程寫出）；重新量健康與品質由呼叫端排
    ///
    /// 回傳各家收了幾個節點
    /// 這些位址有多少比例落在這台目前的 `provider` 官方範圍裡；這台還沒有這家的範圍、或清單是空的 → None（3.4.3）
    pub fn ranges_overlap(&self, provider: &str, ips: &[IpAddr]) -> Option<f64> {
        if ips.is_empty() {
            return None;
        }
        let st = self.state();
        let p = st.pools.p.get(provider)?;
        if p.range4.is_empty() && p.range6.is_empty() {
            return None;
        }
        let inside = ips.iter().filter(|ip| st.pools.in_ranges(provider, **ip)).count();
        Some(inside as f64 / ips.len() as f64)
    }

    pub fn import_shared(&self, pools: Option<&[u8]>, v6: Option<&[u8]>, max_per_provider: usize) -> anyhow::Result<Vec<(String, usize)>> {
        let max = max_per_provider.max(1);
        let mut out: Vec<(String, usize)> = Vec::new();
        // 丟掉的節點分兩種：不在官方範圍裡（資料有問題）、超過每家的上限（只是太多）
        let (mut out_of_range, mut over_cap) = (0usize, 0usize);
        if let Some(b) = pools {
            let mut f: PoolsFile = serde_json::from_slice(b).map_err(|e| anyhow::anyhow!("節點池格式錯誤：{e}"))?;
            if f.is_empty() {
                anyhow::bail!("節點池是空的");
            }
            let mut st = self.state();
            let st = &mut *st;
            let names: Vec<&'static str> = st.pools.p.keys().copied().collect();
            for name in names {
                let Some(e) = f.providers.shift_remove(name) else { continue };
                let total = e.v4.as_ref().map_or(0, Vec::len) + e.v6.as_ref().map_or(0, Vec::len);
                let mut pool4: Vec<PoolNode> = e.v4.unwrap_or_default();
                pool4.retain(|x| x.ip.is_ipv4() && st.pools.in_ranges(name, x.ip));
                let mut pool6: Vec<PoolNode> = e.v6.unwrap_or_default();
                pool6.retain(|x| x.ip.is_ipv6() && st.pools.in_ranges(name, x.ip));
                let in_range = pool4.len() + pool6.len();
                pool4.truncate(max);
                pool6.truncate(max.saturating_sub(pool4.len()));
                let kept = pool4.len() + pool6.len();
                out_of_range += total.saturating_sub(in_range);
                over_cap += in_range - kept;
                if kept == 0 {
                    warn!("共用的節點池：{name} 的節點都不在官方範圍裡，保留原本的節點池");
                    continue;
                }
                // 這台永久紀錄的台灣 v6 節點一律併入（同節點池工作的做法）
                for k in st.v6.list(name) {
                    if !pool6.iter().any(|x| x.ip == k.ip) && st.pools.in_ranges(name, k.ip) {
                        let mut n = PoolNode::new(k.ip);
                        n.ms = k.node.ms;
                        n.pop = k.node.pop.as_deref().map(util::intern);
                        n.permanent = Some(true);
                        pool6.push(n);
                    }
                }
                // updatedAt、tw48、prefixes 用上游的（網段也要在官方範圍裡）；其他欄位照這台原本的
                let mut rest = st.pools.p.get(name).map(|d| d.rest.clone()).unwrap_or_default();
                if let Some(u) = e.rest.get("updatedAt").filter(|v| v.is_string()) {
                    rest.insert("updatedAt".into(), u.clone());
                }
                let in_range = |s: &str| cidr_base(s).is_some_and(|ip| st.pools.in_ranges(name, ip));
                if let Some(a) = e.rest.get("tw48").and_then(Value::as_array) {
                    let l: Vec<Value> = a.iter().filter(|v| v.as_str().is_some_and(in_range)).cloned().collect();
                    rest.insert("tw48".into(), Value::Array(l));
                }
                if let Some(m) = e.rest.get("prefixes").and_then(Value::as_object) {
                    let m: serde_json::Map<String, Value> = m
                        .iter()
                        .map(|(pop, l)| {
                            let l: Vec<Value> = l
                                .as_array()
                                .map(|a| a.iter().filter(|v| v.as_str().is_some_and(in_range)).cloned().collect())
                                .unwrap_or_default();
                            (pop.clone(), Value::Array(l))
                        })
                        .collect();
                    rest.insert("prefixes".into(), Value::Object(m));
                }
                // 合併（3.4.3）：上游的節點在前，這台自己的節點留著（每家上限照舊），自己記的壞節點也不清掉
                // （以前整個換掉：自己觀察到的壞節點紀錄被丟掉，規格 10 第 3.8 節寫的是「合併、兩邊都留著」）
                st.pools.merge_shared(name, pool4, pool6, rest, max);
                out.push((name.to_string(), kept));
            }
        }
        if let Some(b) = v6 {
            let incoming = V6Store::from_json(b, self.cfg.v6_max).map_err(|e| anyhow::anyhow!("IPv6 節點格式錯誤：{e}"))?;
            let have = incoming.provider_names();
            let mut st = self.state();
            let st = &mut *st;
            let names: Vec<&'static str> = st.pools.p.keys().copied().collect();
            for name in names {
                if !have.iter().any(|p| p == name) {
                    continue;
                }
                let list = incoming.list(name);
                let total = list.len();
                let mut keep: Vec<v6store::V6Entry> = list
                    .into_iter()
                    .filter(|e| e.ip.is_ipv6() && st.pools.in_ranges(name, e.ip))
                    .collect();
                out_of_range += total - keep.len();
                over_cap += keep.len().saturating_sub(max);
                keep.truncate(max);
                if keep.is_empty() {
                    warn!("共用的 IPv6 節點：{name} 的節點都不在官方範圍裡，保留原本的紀錄");
                    continue;
                }
                let n = keep.len();
                // 也併進目前的 IPv6 節點池（同載入時的做法）
                if let Some(d) = st.pools.p.get_mut(name) {
                    for k in &keep {
                        if !d.pool6.iter().any(|x| x.ip == k.ip) {
                            let mut p = PoolNode::new(k.ip);
                            p.ms = k.node.ms;
                            p.pop = k.node.pop.as_deref().map(util::intern);
                            p.permanent = Some(true);
                            d.pool6.push(p);
                        }
                    }
                }
                st.pools.dirty = true;
                st.v6.set_provider(name, keep);
                match out.iter_mut().find(|(p, _)| p == name) {
                    Some(x) => x.1 += n,
                    None => out.push((name.to_string(), n)),
                }
            }
        }
        if out_of_range > 0 {
            warn!("共用的 CDN 節點：{out_of_range} 個不在官方範圍裡，已丟掉");
        }
        if over_cap > 0 {
            info!("共用的 CDN 節點：{over_cap} 個超過每家 {max} 個的上限，沒有收");
        }
        Ok(out)
    }
}

/// 磁碟預算換算的筆數：用實測的「每筆實際佔多少磁碟」校正估計模型（[`Cdn::budget_limit`]）。
///
/// 每片固定的部分（模型的 1.1 KB）先扣掉，剩下的照實測換算。實測要夠多（2,000 筆以上、磁碟上 512 KB 以上）才採用；只往上調（不會因為校正而多刪）、最多到模型的 1.5 倍
/// （量錯或檔案落後記憶體時不會整個放開）。沒有實測（`disk_bytes` 是 0）就照模型
pub(crate) fn calibrated_limit(model: usize, shards: usize, total: usize, disk_bytes: u64, budget_bytes: u64) -> usize {
    if total < db::BUDGET_MIN_ENTRIES || disk_bytes < db::BUDGET_MIN_BYTES {
        return model;
    }
    // 每片固定的部分照模型扣掉，剩下的照實測的每筆大小換算（只用比例換算的話，筆數少、固定部分佔比大時會估得太多）
    let overhead = shards as u64 * db::BUDGET_SHARD_OVERHEAD;
    let entry_bytes = disk_bytes.saturating_sub(overhead);
    if entry_bytes == 0 {
        return model;
    }
    let room = budget_bytes.saturating_sub(overhead) as u128;
    let measured = (room * total as u128 / entry_bytes as u128).min(usize::MAX as u128) as usize;
    measured.clamp(model, model.saturating_mul(3) / 2)
}

pub(crate) fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}
