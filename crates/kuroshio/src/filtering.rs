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

use crate::fetch::{self, Outcome, Validators};
use crate::resolver::{FilterCheck, Verdict};
use kuroshio_filter::{BuildOptions, Category, Filter, FilterBuilder, ListSpec, SourceStatus};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, SystemTime};
use tracing::{info, warn};

/// 安裝時附帶的預設自訂規則（設定的自訂規則檔不存在時寫出這份）
pub const DEFAULT_CUSTOM_RULES: &str = include_str!("../../../rules/default-custom-rules.txt");

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
        }))
    }

    pub fn sources(&self) -> &[ListSource] {
        &self.sources
    }

    /// 記憶體控制提供的預算（只能設定一次）
    pub fn set_allowance(&self, f: AllowanceFn) {
        let _ = self.allowance.set(f);
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
        if !force && have && active.iter().all(|&i| prev[i].etag.is_some() || prev[i].last_modified.is_some()) {
            let mut changed = false;
            for &i in &active {
                match fetch::get(&self.sources[i].url, &prev[i], self.max_bytes, timeout, |_| Ok(())).await {
                    Ok(Outcome::NotModified) => {}
                    _ => {
                        changed = true;
                        break;
                    }
                }
            }
            if !changed {
                self.status.lock().unwrap()["checkedAt"] = json!(crate::persist::now_secs() * 1000);
                return Ok(false);
            }
        }
        // 2. 載入前先看記憶體預算：量過大小的清單估計會超過，就依停用順序先不載入（看得到原因）
        self.fit_allowance();
        self.rebuild().await.map(|_| true)
    }

    /// 依記憶體預算（記憶體控制提供）先排除會放不下的清單（只用量過的大小估；沒量過的交給 `max_domains`）
    fn fit_allowance(&self) {
        let Some(limit) = self.allowance.get().and_then(|f| f()) else {
            return;
        };
        let ex = self.excluded();
        let sizes: Vec<u64> = self.sizes.lock().unwrap().iter().map(|s| s.0).collect();
        let mut total: u64 = (0..self.sources.len()).filter(|&i| !ex[i]).map(|i| sizes[i]).sum();
        if total <= limit {
            return;
        }
        let loaded: Vec<bool> = ex.iter().map(|e| !e).collect();
        for i in shed_order(&self.sources, &self.hits_vec(), &sizes, &loaded) {
            if total <= limit {
                break;
            }
            let (bytes, rules) = self.sizes.lock().unwrap()[i];
            if bytes == 0 {
                continue;
            }
            total -= bytes;
            warn!(
                "記憶體預算不足：這次不載入清單「{}」（約 {} KB、{rules} 條規則；預算 {} KB）",
                self.sources[i].name,
                bytes / 1024,
                limit / 1024
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
    }

    /// 依目前的停用名單重新下載、建一份清單層（下載失敗而且原本有清單時保留舊的）。回傳（重建前，重建後）的大小
    async fn rebuild(&self) -> anyhow::Result<(u64, u64)> {
        let timeout = Duration::from_secs(30);
        let have = self.lists.read().unwrap().stats().lists > 0;
        let ex = self.excluded();
        // 自訂規則的網域數也算在預算裡
        let (custom_n, custom_unindexed) = {
            let c = self.custom.read().unwrap();
            (c.stats().custom, c.stats().unindexed)
        };
        let mut max_domains = self.opts.max_domains.saturating_sub(custom_n);
        // 記憶體預算：還沒量過大小的清單也不會超過（超過的清單整份不載入，統計裡看得到 overBudget）
        if let Some(limit) = self.allowance.get().and_then(|f| f()) {
            max_domains = max_domains.min(limit / BYTES_PER_DOMAIN);
        }
        let mut b = FilterBuilder::new(BuildOptions {
            max_domains,
            // 每次查詢都要跑的規則：自訂規則的也算在內（查詢時兩層都要跑）
            max_unindexed: self.opts.max_unindexed.saturating_sub(custom_unindexed),
            ..self.opts
        });
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
            let r = fetch::get(&s.url, &Validators::default(), self.max_bytes, timeout, |c| {
                w.feed(c);
                Ok(())
            })
            .await;
            w.end();
            match r {
                Ok(Outcome::Done { validators: v, .. }) => validators.push(v),
                Ok(Outcome::NotModified) => validators.push(Validators::default()),
                Err(e) => {
                    warn!("下載清單「{}」失敗：{e}", s.name);
                    errors.push(json!({ "name": s.name, "url": s.url, "error": e.to_string() }));
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
        if !errors.is_empty() && have {
            // 有清單下載失敗：保留舊的，避免少掉一整份清單
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
        *self.lists.write().unwrap() = Arc::new(f);
        *self.validators.lock().unwrap() = validators;
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

    /// 停用中的清單
    pub fn unloaded(&self) -> Vec<Unloaded> {
        self.unloaded.lock().unwrap().clone()
    }

    /// 下一份要恢復的清單需要多少記憶體（最後停用的先恢復——它的優先順序最高）
    pub fn next_restore_bytes(&self) -> Option<u64> {
        self.unloaded.lock().unwrap().last().map(|u| u.bytes)
    }

    /// 記憶體控制：停用下一份清單（重建一份不含它的過濾器；重建期間舊的照常使用）。
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
        match self.rebuild().await {
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
        let Some(u) = self.unloaded.lock().unwrap().pop() else {
            return Ok(None);
        };
        match self.rebuild().await {
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
            loop {
                // 記憶體吃緊時延後（重建時新舊兩份會同時存在）
                let wait = if crate::app::pressure() == crate::sysinfo::Pressure::Critical {
                    warn!("記憶體不足，延後更新過濾清單");
                    Duration::from_secs(1800)
                } else {
                    match me.update_lists(false).await {
                        Ok(_) => me.interval,
                        Err(e) => {
                            warn!("{e:#}；30 分鐘後重試");
                            Duration::from_secs(1800)
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
        })
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
