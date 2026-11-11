//! `Cdn`：CDN 子系統的進入點（狀態、載入、快照、背景工作排程）

use crate::config::CdnConfig;
use crate::db::{self, Db};
use crate::net::Net;
use crate::pools::{self, Classifier, Pools, PoolsFile};
use crate::util::{self, now_ms};
use crate::v6store::{self, V6Store};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use tokio::sync::Semaphore;
use tracing::{info, warn};

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

/// 社群共享（規格 03）提供的提示；回報命中率
pub trait Hints: Send + Sync {
    fn domain_hint(&self, name: &str, provider: &str, family: u8) -> Vec<HintIp>;
    fn hint_result(&self, from: &str, ok: bool);
    fn cross_hint(&self, name: &str) -> Option<CrossHint>;
}

/// 改寫統計（同 2.x 的 `cdn.stats`）
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    pub rewrites: u32,
    pub trials: u32,
    pub v6dropped: u32,
    pub ecs_rewrites: u32,
    pub cross_rewrites: u32,
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

/// 狀態檔（相對於狀態目錄）
pub const STATE_FILES: [&str; 5] = [pools::FILE, v6store::FILE, db::FILE, db::HARVEST_FILE, pools::ZONE_FILE];

impl Cdn {
    /// 從狀態目錄載入（沒有或是空的就用種子資料）
    pub fn load(cfg: &Value, paths: Paths, net: Arc<dyn Net>) -> Arc<Cdn> {
        let dir = paths.state_dir.clone();
        Cdn::load_with(cfg, paths, net, &|rel| std::fs::read(dir.join(rel)).ok())
    }

    /// 同 `load`，但狀態檔由 `read`（相對路徑 → 內容）提供，例如快照寫入器的 `load()`
    /// （這樣它會記住目前的內容，沒變就不重寫）
    pub fn load_with(cfg: &Value, paths: Paths, net: Arc<dyn Net>, read: &dyn Fn(&str) -> Option<Vec<u8>>) -> Arc<Cdn> {
        let c = Arc::new(CdnConfig::from_value(cfg));
        let seed_ok = paths.seed_dir.join("meta.json").exists();
        let seed = |name: &str| -> Option<Vec<u8>> {
            if seed_ok {
                std::fs::read(paths.seed_dir.join(name)).ok()
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

        // 網域資料庫
        let mut db = Db::new(c.max_entries);
        let n = read(db::FILE).and_then(|b| db.load_domains(&b, false).map_err(|e| warn!("{} 讀取失敗：{e}", db::FILE)).ok());
        if n.unwrap_or(0) == 0 {
            // 匯入時把「最後出現時間」設成現在：每小時的複驗只處理最近 3 天出現過的網域
            if let Some(b) = seed("cdn-domains.json") {
                if db.load_domains(&b, true).map(|n| n > 0).unwrap_or(false) {
                    db.dirty = true;
                    used.push("CDN 網域驗證紀錄");
                }
            }
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
        };
        me.reset_octet_verdicts();
        Arc::new(me)
    }

    /// 舊版用隨機 IP 驗證 Fastly 必然憑證不符；最後一段跟原始不同的失敗紀錄作廢，重新驗證
    fn reset_octet_verdicts(&self) {
        let mut st = self.state();
        let st = &mut *st;
        let mut n = 0;
        for e in st.db.domains.values_mut() {
            let Some(p) = e.provider() else { continue };
            if !st.pools.octet_mode(p) {
                continue;
            }
            if e.v4.as_ref().map(|v| v.is("fail") && v.algo != Some(2)).unwrap_or(false) {
                e.v4 = None;
                n += 1;
            }
        }
        if n > 0 {
            st.db.dirty = true;
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

    pub fn set_hints(&self, h: Option<Arc<dyn Hints>>) {
        *self.hints.write().unwrap() = h;
    }

    pub(crate) fn hints(&self) -> Option<Arc<dyn Hints>> {
        self.hints.read().unwrap().clone()
    }

    // ------------------------------------------------------------ 快照

    fn collect(&self, all: bool) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        // 網域資料庫（可能有 20 萬筆、上百 MB）分批寫：每批只拿一下鎖，查詢不會被整個擋住
        let mut dump = None;
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
            if all {
                // 關機：一次寫完（已經沒有查詢了，內容也要是同一個時間點的）
                st.db.dirty = false;
                out.push((db::FILE.to_string(), st.db.domains_json()));
            } else if st.db.dirty {
                st.db.dirty = false;
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
        if let Some((at, (mut buf, tail, mut keys))) = dump {
            Db::dump_sort(&mut keys); // 不拿鎖
            let mut first = true;
            for chunk in keys.chunks(DUMP_CHUNK) {
                self.state().db.dump_chunk(chunk, &mut buf, &mut first);
                // 鎖已經放開：停一下讓等著的查詢先拿到鎖。只 yield 不夠——等的人被叫醒要幾十微秒，
                // 這邊馬上又把鎖拿走，查詢會一路等到整份寫完（實測 20 萬筆還是被擋 400 ms）
                std::thread::sleep(std::time::Duration::from_micros(100));
            }
            buf.extend_from_slice(&tail);
            out.insert(at, (db::FILE.to_string(), buf)); // 順序跟一次寫完時一樣
        }
        out
    }

    /// 上次取出之後有變動的狀態檔：（相對於狀態目錄的路徑，內容）。
    /// 內容是 2.x 相容的 JSON（不縮排）。網域資料庫可能很大（20 萬筆約 110 MB、要半秒）：分批序列化，
    /// 每批只拿一下鎖，查詢不會被擋住；但還是要花那麼多 CPU 與記憶體，不要太常呼叫（幾分鐘一次就好）。
    /// 分批期間有變動的網域，內容以寫到它的那一刻為準，下次呼叫會再寫一次。
    pub fn snapshots(&self) -> Vec<(String, Vec<u8>)> {
        self.collect(false)
    }

    /// 全部的狀態檔（關機時）
    pub fn snapshots_all(&self) -> Vec<(String, Vec<u8>)> {
        self.collect(true)
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
        let mut bg = self.bg.lock().unwrap();
        if let Some(r) = bg.record.as_mut() {
            if r.len() < 10_000 {
                r.push(t);
            }
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
                if !bg.verify.insert(key.clone()) {
                    return;
                }
                rt.spawn(async move {
                    let _permit = me.verify_sem.clone().acquire_owned().await;
                    me.verify(&name, &provider, family, orig).await;
                    me.bg.lock().unwrap().verify.remove(&key);
                });
            }
            Task::Ecs { name, ips4, ips6 } => {
                if !bg.ecs.insert(name.clone()) {
                    return;
                }
                rt.spawn(async move {
                    let _permit = me.ecs_sem.clone().acquire_owned().await;
                    me.ecs_probe(&name, &ips4, &ips6).await;
                    me.bg.lock().unwrap().ecs.remove(&name);
                });
            }
            Task::Cross { name, from, orig } => {
                if !self.cfg.cross.enabled || !bg.cross.insert(name.clone()) {
                    return;
                }
                rt.spawn(async move {
                    let _permit = me.cross_sem.clone().acquire_owned().await;
                    me.cross_explore(&name, &from, orig).await;
                    me.bg.lock().unwrap().cross.remove(&name);
                });
            }
            Task::TryV6 { provider, ip } => {
                rt.spawn(async move { me.try_v6(&provider, ip).await });
            }
            Task::Latency(ip) => {
                rt.spawn(async move {
                    me.net.latency(ip).await;
                });
            }
        }
    }

    pub(crate) fn schedule_all(self: &Arc<Self>, tasks: Vec<Task>) {
        for t in tasks {
            self.schedule(t);
        }
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

    /// `/api/status` 的 cdn 區塊
    pub fn status_lite(&self) -> Value {
        let st = self.state();
        json!({ "enabled": self.cfg.enabled, "stats": st.stats, "domains": st.db.domains.len() })
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
        let st = self.state();
        st.db.get(&normalize(name)).map(|d| serde_json::to_value(d).unwrap_or_default())
    }

    /// `/api/cdn/policy`：auto / always / never
    pub fn set_policy(&self, name: &str, policy: &str) -> Option<Value> {
        let p = db::Policy::parse(policy)?;
        let mut st = self.state();
        Some(serde_json::to_value(st.db.set_policy(&normalize(name), p)).unwrap_or_default())
    }

    /// `/api/cdn/verify`：立即驗證（網域要先解析過一次）。回傳（結果，網域紀錄）；資料庫沒有這個網域回 None
    pub async fn verify_now(self: &Arc<Self>, name: &str, family: u8) -> Option<(Option<&'static str>, Value)> {
        let name = normalize(name);
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
        self.ecs_probe(&name, &i4, &i6).await;
        self.domain(&name).unwrap_or_else(|| json!({}))
    }

    /// 跨 CDN 統計
    pub fn cross_summary(&self) -> Value {
        self.state().db.cross_summary()
    }

    /// 每小時：熱門且即將到期的「驗證通過」網域先重新驗證，避免掉回 10 秒試用。回傳排入幾個
    pub fn recheck(self: &Arc<Self>) -> usize {
        let now = now_ms();
        let soon = now + util::HOUR_MS;
        let recent = now.saturating_sub(3 * util::DAY_MS);
        let mut tasks = Vec::new();
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
        }
        let n = tasks.len();
        if n > 0 {
            info!("定時複驗：{n} 個網域");
        }
        self.schedule_all(tasks);
        n
    }
}

pub(crate) fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}
