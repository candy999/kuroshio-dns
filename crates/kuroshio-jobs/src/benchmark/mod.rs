//! 每日 DNS 評測（對齊 2.x `jobs/dns-benchmark.js`，DNStest v16.1 移植＋自動化）
//!
//!  Phase 0  資格賽：one.one.one.one 必須解析出 1.1.1.1 / 1.0.0.1
//!  Phase 1  逐一測 web.txt 網域：
//!           - 被封殺（NXDOMAIN / 0.0.0.0 / 空回應，而多數 DNS 正常）→ 淘汰
//!           - 解析到錯誤 ISP（ASN 分組 + 合作夥伴互信判斷，同 v16.1）→ 判定污染淘汰，加入永久黑名單
//!           - 逾時超過容許次數 → 淘汰
//!  Phase 2  統計延遲、獨有 IP、覆蓋率；輸出與 2.x 相同的 CSV 報表
//!  Phase 3  選出執行期上游：先取最快的一台，再依「新增覆蓋最多」貪婪挑選 → state/upstreams.json
//!  固定上游（upstream.pinned）會一起測、一起算覆蓋，但永遠不會被淘汰。
//!
//! 3.0 的差異：
//! - 支援的類型由 `Prober::supports` 決定（目前 udp / tcp / dot / doh）；doq、doh3、dnscrypt 先略過，
//!   數量記在結果的 `skippedTypes`。之後加上傳輸層，這裡不用改。
//! - 名單多了 `dotlist.txt`（DoT 主機）與 `stamps.txt`（sdns:// stamp）；`dohlist.txt` 的每一筆另外產生一個 h3:// 候選。
//! - 每測完一個網域就呼叫 `checkpoint()`：讓出 CPU，系統吃緊時暫停（規格 05）。
//! - 選擇與報表的計算放到 blocking 執行緒，不卡住 DNS。

pub mod probe;
pub mod rules;
pub mod select;

use crate::scheduler::{resolve_path, BoxFuture, Job, JobCtx};
use crate::time::{fmt_time, iso_string, local_date_str, parse_date_utc, DAY_MS};
use crate::util::{fixed_num, read_json, read_list, to_fixed, write_atomic, write_json};
use anyhow::{bail, Result};
use kuroshio_config::get;
use kuroshio_net::upstream::Upstream;
use probe::{kind_name, query, sub_key, AsnSource, IpApi, NetProber, Outcome, Prober, QueryResult, SiteCheck};
use rules::AsnInfo;
use select::{Scored, SelectOpts, Strategy};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;
use tracing::{info, warn};

/// 工作名稱
pub const JOB_NAME: &str = "dns-benchmark";

/// 2.x 的 PREFLIGHT
pub const PREFLIGHT_DOMAIN: &str = "one.one.one.one";
pub const PREFLIGHT_EXPECTED: [Ipv4Addr; 2] = [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 0, 0, 1)];

/// 結果裡最多保留幾筆封殺紀錄（同 2.x）
const MAX_BLOCKED_REPORT: usize = 500;
/// 固定上游的問題紀錄上限
const MAX_ISSUES: usize = 500;

/// 評測用到的檔案位置
#[derive(Debug, Clone)]
pub struct BenchPaths {
    /// 評測名單：iplist.txt、dohlist.txt、doqlist.txt、dotlist.txt、stamps.txt、web.txt、blacklist.txt（`benchmark.dir`）
    pub list_dir: PathBuf,
    /// 報表與 ASN 快取（`benchmark.outDir`）；None 就不寫報表、ASN 快取只留在這次執行
    pub out_root: Option<PathBuf>,
    /// 結果（`upstream.autoStateFile`，伺服器讀這個）
    pub upstreams_file: PathBuf,
    /// 社群好友提供的上游候選（`state/community/upstream-candidates.json`）
    pub community_candidates: Option<PathBuf>,
    /// 自己評測學到的永久黑名單（`state/blacklist.txt`）；程式附帶的 `list_dir/blacklist.txt` 是唯讀的基本名單，
    /// 學到的寫在 state，升級套件不會被蓋掉
    pub blacklist_file: Option<PathBuf>,
}

impl BenchPaths {
    /// 依設定組出路徑：`state/` 開頭的放到 `state_dir`，其他相對於 `base_dir`
    pub fn from_config(cfg: &Value, state_dir: &Path, base_dir: &Path) -> BenchPaths {
        let s = |k: &str, d: &str| {
            get(cfg, k)
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
                .unwrap_or(d)
                .to_string()
        };
        let r = |p: &str| resolve_path(state_dir, base_dir, p);
        BenchPaths {
            list_dir: r(&s("benchmark.dir", "./data/benchmark")),
            out_root: Some(r(&s("benchmark.outDir", "./state/benchmark"))),
            upstreams_file: r(&s("upstream.autoStateFile", "./state/upstreams.json")),
            community_candidates: Some(r("./state/community/upstream-candidates.json")),
            blacklist_file: Some(r("./state/blacklist.txt")),
        }
    }
}

/// 每日評測工作。`Clone` 很便宜（網路層共用），可以直接註冊進排程器。
#[derive(Clone)]
pub struct Benchmark {
    pub paths: BenchPaths,
    pub prober: Arc<dyn Prober>,
    pub asn: Arc<dyn AsnSource>,
    /// 資格賽用的網域與預期 IP
    pub preflight: (String, Vec<Ipv4Addr>),
}

impl Benchmark {
    /// 正式環境：kuroshio-net 傳輸 + ip-api.com
    pub fn new(paths: BenchPaths) -> Benchmark {
        Benchmark::with(paths, Arc::new(NetProber), Arc::new(IpApi::default()))
    }

    pub fn with(paths: BenchPaths, prober: Arc<dyn Prober>, asn: Arc<dyn AsnSource>) -> Benchmark {
        Benchmark {
            paths,
            prober,
            asn,
            preflight: (PREFLIGHT_DOMAIN.into(), PREFLIGHT_EXPECTED.to_vec()),
        }
    }

    /// 跑一次評測；成功時回傳寫進 upstreams.json 的內容
    pub async fn run(&self, ctx: &JobCtx) -> Result<Value> {
        let mut cache = AsnCache::load(&self.paths);
        let r = self.run_inner(ctx, &mut cache).await;
        // 2.x 每查到新的就寫一次（一天可能寫上百次 340 KB）；這裡只在結束時寫一次
        if let (Some(root), true) = (&self.paths.out_root, cache.dirty) {
            if let Err(e) = cache.save(&root.join("cidr_cache.json")) {
                warn!("ASN 快取寫入失敗：{e}");
            }
        }
        r
    }
}

impl Job for Benchmark {
    fn run(&self, ctx: JobCtx) -> BoxFuture<Result<()>> {
        let me = self.clone();
        Box::pin(async move { Benchmark::run(&me, &ctx).await.map(|_| ()) })
    }
}

// ---------------- 設定 ----------------

struct BenchCfg {
    timeout: Duration,
    conc: usize,
    max_timeouts: u32,
    keep_days: u64,
    pinned: Vec<String>,
    select: SelectOpts,
}

fn pos_f64(cfg: &Value, k: &str) -> Option<f64> {
    get(cfg, k).and_then(Value::as_f64).filter(|v| *v > 0.0)
}

impl BenchCfg {
    fn from(cfg: &Value) -> BenchCfg {
        BenchCfg {
            timeout: Duration::from_millis(pos_f64(cfg, "benchmark.timeoutMs").unwrap_or(1500.0) as u64),
            conc: pos_f64(cfg, "benchmark.concurrency").unwrap_or(50.0) as usize,
            // 2.x 是 `?? 2`：0 也算數
            max_timeouts: get(cfg, "benchmark.maxTimeouts").and_then(Value::as_u64).unwrap_or(2) as u32,
            keep_days: pos_f64(cfg, "benchmark.keepDays").unwrap_or(14.0) as u64,
            pinned: strings(cfg, "upstream.pinned").unwrap_or_default(),
            select: select_opts(cfg),
        }
    }
}

fn strings(cfg: &Value, k: &str) -> Option<Vec<String>> {
    get(cfg, k)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
}

/// 選上游的參數（`upstream.autoTypes`、`autoMax`，`benchmark.maxAvgLatencyMs`、`coverageTarget`、`minAuto`；0 或缺少時用 2.x 的預設）
pub fn select_opts(cfg: &Value) -> SelectOpts {
    SelectOpts {
        auto_types: strings(cfg, "upstream.autoTypes").unwrap_or_else(|| SelectOpts::default().auto_types),
        max_n: pos_f64(cfg, "upstream.autoMax").unwrap_or(5.0) as usize,
        max_avg: pos_f64(cfg, "benchmark.maxAvgLatencyMs").unwrap_or(250.0),
        coverage_target: pos_f64(cfg, "benchmark.coverageTarget").unwrap_or(0.97),
        min_auto: pos_f64(cfg, "benchmark.minAuto").unwrap_or(3.0) as usize,
    }
}

// ---------------- ASN 快取（以 /16 為鍵，同 2.x 的 cidr_cache.json） ----------------

struct AsnCache {
    map: HashMap<String, AsnInfo>,
    /// 這次執行查不到的 /16（不重複查；2.x 每個網域都會重查，ip-api 連不上時每題都要等）
    failed: HashSet<String>,
    dirty: bool,
}

impl AsnCache {
    fn load(paths: &BenchPaths) -> AsnCache {
        let v = paths
            .out_root
            .as_ref()
            .and_then(|r| read_json(&r.join("cidr_cache.json")))
            .or_else(|| read_json(&paths.list_dir.join("cidr_cache.json")));
        let map: HashMap<String, AsnInfo> = v
            .as_ref()
            .and_then(Value::as_object)
            .map(|o| o.iter().filter_map(|(k, v)| Some((k.clone(), AsnInfo::from_json(v)?))).collect())
            .unwrap_or_default();
        info!("[Cache] 已載入 {} 筆 /16 ASN 資料", map.len());
        AsnCache {
            map,
            failed: HashSet::new(),
            dirty: false,
        }
    }

    async fn lookup(&mut self, src: &dyn AsnSource, ips: &[IpAddr]) -> HashMap<IpAddr, AsnInfo> {
        // 每個 /16 只查一個代表
        let mut reps: Vec<Ipv4Addr> = Vec::new();
        let mut seen = HashSet::new();
        for ip in ips {
            if let IpAddr::V4(v4) = ip {
                let k = sub_key(*v4);
                if !self.map.contains_key(&k) && !self.failed.contains(&k) && seen.insert(k) {
                    reps.push(*v4);
                }
            }
        }
        if !reps.is_empty() {
            let got = src.lookup(reps.clone()).await;
            for (ip, info) in got {
                self.map.insert(sub_key(ip), info);
                self.dirty = true;
            }
            for ip in reps {
                let k = sub_key(ip);
                if !self.map.contains_key(&k) {
                    self.failed.insert(k);
                }
            }
        }
        let mut out = HashMap::new();
        for ip in ips {
            let info = match ip {
                IpAddr::V4(v4) => self.map.get(&sub_key(*v4)).cloned(),
                IpAddr::V6(_) => None,
            };
            out.insert(*ip, info.unwrap_or_else(AsnInfo::unknown));
        }
        out
    }

    fn save(&self, path: &Path) -> std::io::Result<()> {
        let o: Map<String, Value> = self.map.iter().map(|(k, v)| (k.clone(), v.to_json())).collect();
        write_json(path, &Value::Object(o))
    }
}

// ---------------- 候選 ----------------

struct Srv {
    /// 名單裡的原始寫法（2.x 的 id，upstreams.json 也寫這個）
    id: String,
    up: Upstream,
    kind: &'static str,
    pinned: bool,
    alive: bool,
    fail_reason: String,
    timeouts: u32,
    lat_sum: f64,
    lat_count: usize,
    lat_min: f64,
    lat_max: f64,
    history: Vec<(u32, Vec<u32>)>,
    issues: Vec<String>,
}

impl Srv {
    fn new(id: String, up: Upstream, pinned: bool) -> Srv {
        Srv {
            id,
            kind: kind_name(up.kind),
            up,
            pinned,
            alive: true,
            fail_reason: String::new(),
            timeouts: 0,
            lat_sum: 0.0,
            lat_count: 0,
            lat_min: f64::INFINITY,
            lat_max: f64::NEG_INFINITY,
            history: Vec::new(),
            issues: Vec::new(),
        }
    }

    fn kill(&mut self, reason: String) {
        if self.pinned {
            if self.issues.len() < MAX_ISSUES {
                self.issues.push(reason);
            }
            return;
        }
        self.alive = false;
        self.fail_reason = reason;
    }

    fn record(&mut self, domain: u32, ms: f64, ips: &[Ipv4Addr]) {
        self.lat_sum += ms;
        self.lat_count += 1;
        self.lat_min = self.lat_min.min(ms);
        self.lat_max = self.lat_max.max(ms);
        let slot = match self.history.iter().position(|(d, _)| *d == domain) {
            Some(p) => p,
            None => {
                self.history.push((domain, Vec::new()));
                self.history.len() - 1
            }
        };
        let list = &mut self.history[slot].1;
        for ip in ips {
            let n = u32::from(*ip);
            if !list.contains(&n) {
                list.push(n);
            }
        }
    }

    fn avg(&self) -> f64 {
        if self.lat_count == 0 {
            9999.0
        } else {
            self.lat_sum / self.lat_count as f64
        }
    }

    /// 交出結算用的資料（歷史紀錄直接搬走，不複製）
    fn scored(&mut self, owner: String) -> Scored {
        let has = self.lat_count > 0;
        Scored {
            id: self.id.clone(),
            kind: self.kind.into(),
            owner,
            pinned: self.pinned,
            avg: self.avg(),
            min: if has { self.lat_min } else { 0.0 },
            max: if has { self.lat_max } else { 0.0 },
            count: self.lat_count,
            history: std::mem::take(&mut self.history),
            ext: Default::default(),
        }
    }
}

/// 名單的一行：有多個欄位時取指定開頭的那一個（同 2.x）
fn pick_token(line: &str, prefix: &str) -> String {
    line.split_whitespace().find(|p| p.starts_with(prefix)).unwrap_or(line).to_string()
}

/// 依 2.x 的順序組出候選清單：udp、doh（含社群提供的加密上游）、doq，再加上 3.0 新增的 dot、doh3、dnscrypt
fn candidate_ids(paths: &BenchPaths) -> (Vec<String>, usize) {
    let dir = &paths.list_dir;
    let mut udp = read_list(&dir.join("iplist.txt"));
    let mut doh: Vec<String> = read_list(&dir.join("dohlist.txt")).iter().map(|l| pick_token(l, "http")).collect();
    let doq: Vec<String> = read_list(&dir.join("doqlist.txt")).iter().map(|l| pick_token(l, "quic")).collect();
    let dot: Vec<String> = read_list(&dir.join("dotlist.txt"))
        .iter()
        .map(|l| {
            let t = l
                .split_whitespace()
                .find(|p| p.contains("://"))
                .unwrap_or_else(|| l.split_whitespace().next().unwrap_or(l));
            if t.contains("://") {
                t.to_string()
            } else {
                format!("tls://{t}")
            }
        })
        .collect();
    let stamps: Vec<String> = read_list(&dir.join("stamps.txt"))
        .iter()
        .map(|l| pick_token(l, "sdns://"))
        .collect();
    // 社群好友提供的上游：只是候選，照常經過資格賽、汙染、封殺、速度檢查
    let shared: Vec<String> = paths
        .community_candidates
        .as_ref()
        .and_then(|p| read_json(p))
        .and_then(|v| v.get("ids").and_then(Value::as_array).cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|x| x.as_str().map(str::to_string))
        .collect();
    for id in &shared {
        if id.starts_with("https://") || id.starts_with("tls://") {
            if !doh.contains(id) {
                doh.push(id.clone());
            }
        } else {
            let ip = id.strip_prefix("udp://").unwrap_or(id);
            if ip.parse::<IpAddr>().is_ok() && !udp.iter().any(|u| u == ip) {
                udp.push(ip.to_string());
            }
        }
    }
    if !shared.is_empty() {
        info!("社群好友提供的上游候選 {} 個", shared.len());
    }
    // DoH 每一筆同時測 HTTP/2 與 HTTP/3（規格 01 第 1.2 節）
    let h3: Vec<String> = doh
        .iter()
        .filter_map(|u| u.strip_prefix("https://").map(|r| format!("h3://{r}")))
        .collect();
    info!(
        "=== 每日 DNS 評測：UDP {} / DoH {} / DoQ {} / DoT {} / DNSCrypt {} ===",
        udp.len(),
        doh.len(),
        doq.len(),
        dot.len(),
        stamps.len()
    );
    let n = shared.len();
    let mut all = udp;
    all.extend(doh);
    all.extend(doq);
    all.extend(dot);
    all.extend(h3);
    all.extend(stamps);
    (all, n)
}

/// 有上限的並行執行（同 2.x 的 `mapLimit`）；task 失敗的位置是 None
async fn map_limit<T, R, F, Fut>(items: Vec<T>, limit: usize, f: F) -> Vec<Option<R>>
where
    F: Fn(T) -> Fut,
    Fut: Future<Output = R> + Send + 'static,
    R: Send + 'static,
{
    let mut out: Vec<Option<R>> = (0..items.len()).map(|_| None).collect();
    let mut it = items.into_iter().enumerate();
    let mut set = JoinSet::new();
    for (i, x) in it.by_ref().take(limit.max(1)) {
        let fut = f(x);
        set.spawn(async move { (i, fut.await) });
    }
    while let Some(r) = set.join_next().await {
        if let Ok((i, v)) = r {
            out[i] = Some(v);
        }
        if let Some((i, x)) = it.next() {
            let fut = f(x);
            set.spawn(async move { (i, fut.await) });
        }
    }
    out
}

fn reason_of(r: &QueryResult) -> String {
    match &r.outcome {
        Outcome::Error(e) => e.clone(),
        Outcome::Blocked(b) => b.clone(),
        Outcome::Ok(ips) => ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(","),
    }
}

/// 永久黑名單：曾被判定「汙染」的 DNS 不再測試（可手動編輯，# 後為註解）
fn read_blacklist(file: &Path) -> HashSet<String> {
    read_list(file)
        .iter()
        .map(|l| l.split('#').next().unwrap_or("").trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

fn append_blacklist(file: &Path, lines: &[String]) {
    let head = if file.exists() {
        ""
    } else {
        "# 永久黑名單：每日評測判定「汙染」（解析到錯誤業者）的 DNS，之後不再測試\n# 要恢復某台就刪掉那一行\n"
    };
    let r = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(file)
        .and_then(|mut f| f.write_all(format!("{head}{}\n", lines.join("\n")).as_bytes()));
    if let Err(e) = r {
        warn!("永久黑名單寫入失敗（{}）：{e}", file.display());
    }
}

/// 網站「無法驗證」幾天（不同日期）才列入永久黑名單
const SUSPECT_DAYS: usize = 3;
/// 網站驗證：每個回答最多驗幾個 IP、同時連線數、逾時
const VERIFY_IPS: usize = 2;
const VERIFY_CONC: usize = 16;
const VERIFY_TIMEOUT: Duration = Duration::from_secs(5);

/// 每台 DNS 被判「網站無法驗證」的日期（`state/blacklist-suspects.json`）；30 天沒再發生就忘掉
struct Strikes {
    file: PathBuf,
    map: BTreeMap<String, Vec<String>>,
    dirty: bool,
}

impl Strikes {
    fn load(file: PathBuf, now_ms: u64) -> Strikes {
        let mut map: BTreeMap<String, Vec<String>> = read_json(&file).and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default();
        let cutoff = local_date_str(now_ms.saturating_sub(30 * DAY_MS));
        let before = map.len();
        map.retain(|_, days| {
            days.retain(|d| *d >= cutoff);
            !days.is_empty()
        });
        let dirty = map.len() != before;
        Strikes { file, map, dirty }
    }
    /// 記一天，回傳累計的不同日期數
    fn add(&mut self, id: &str, day: &str) -> usize {
        let days = self.map.entry(id.to_string()).or_default();
        if !days.iter().any(|d| d == day) {
            days.push(day.to_string());
            self.dirty = true;
        }
        days.len()
    }
    fn save(&self) {
        if self.dirty {
            if let Err(e) = write_json(&self.file, &json!(self.map)) {
                warn!("可疑 DNS 紀錄寫入失敗（{}）：{e}", self.file.display());
            }
        }
    }
}

/// 同一組（2.x `groups` 的一個元素）
struct Group {
    rep: AsnInfo,
    score: f64,
}

impl Benchmark {
    async fn run_inner(&self, ctx: &JobCtx, cache: &mut AsnCache) -> Result<Value> {
        let cfg = BenchCfg::from(&ctx.cfg);
        let now = ctx.now_ms();
        let today = local_date_str(now);
        let out_dir = self.paths.out_root.as_ref().map(|r| r.join(&today));
        let base_bl = self.paths.list_dir.join("blacklist.txt");
        let bl_file = self.paths.blacklist_file.clone().unwrap_or_else(|| base_bl.clone());
        let mut blacklist = read_blacklist(&base_bl);
        blacklist.extend(read_blacklist(&bl_file));
        let (ids, _) = candidate_ids(&self.paths);

        // 候選：固定上游在前；同一個上游（正規化後）只測一次
        let mut seen: HashSet<String> = HashSet::new();
        let mut all: Vec<Srv> = Vec::new();
        let mut skipped: BTreeMap<&'static str, usize> = BTreeMap::new();
        for (spec, pinned) in cfg.pinned.iter().map(|p| (p, true)).chain(ids.iter().map(|i| (i, false))) {
            if !pinned && blacklist.contains(spec.as_str()) {
                *skipped.entry("blacklist").or_default() += 1;
                continue;
            }
            let up = match Upstream::parse(spec) {
                Ok(u) => u,
                Err(e) => {
                    warn!("無法解析上游 {spec}：{e}");
                    continue;
                }
            };
            if !pinned && blacklist.contains(&up.id) {
                *skipped.entry("blacklist").or_default() += 1;
                continue;
            }
            if !seen.insert(up.id.clone()) {
                continue;
            }
            if !self.prober.supports(&up) {
                *skipped.entry(kind_name(up.kind)).or_default() += 1;
                continue;
            }
            all.push(Srv::new(spec.clone(), up, pinned));
        }
        let unsupported: Vec<String> = skipped
            .iter()
            .filter(|(k, _)| **k != "blacklist")
            .map(|(k, n)| format!("{k} {n}"))
            .collect();
        if !unsupported.is_empty() {
            info!("這個版本還不支援的類型先略過（之後版本加入）：{}", unsupported.join("、"));
        }
        info!(
            "候選 {} 個（固定上游 {}，永久黑名單略過 {}）",
            all.len(),
            all.iter().filter(|s| s.pinned).count(),
            skipped.get("blacklist").copied().unwrap_or(0)
        );

        // Phase 0：資格賽
        let (pf_domain, pf_expected) = self.preflight.clone();
        info!("[Phase 0] 資格賽 ({pf_domain})");
        let results = self.query_all(&all, (0..all.len()).collect(), &pf_domain, &cfg).await;
        for (i, r) in results {
            let pass = matches!(&r.outcome, Outcome::Ok(ips) if ips.iter().any(|ip| pf_expected.contains(ip)));
            if !pass {
                all[i].kill(format!("資格賽失敗 ({})", reason_of(&r)));
            }
        }
        let verified: Vec<usize> = (0..all.len()).filter(|i| all[*i].alive).collect();
        info!("資格賽結束：通過 {} / 淘汰 {}", verified.len(), all.len() - verified.len());
        if !verified.iter().any(|i| !all[*i].pinned) {
            bail!("沒有任何 DNS 通過資格賽（本機網路可能異常），保留昨天的結果");
        }
        if let Some(d) = &out_dir {
            let list: Vec<&str> = verified.iter().map(|i| all[*i].id.as_str()).collect();
            report(&d.join("verified_dns_list.csv"), list.join("\n").as_bytes());
        }
        ctx.checkpoint().await;

        // Phase 1：逐一測網域
        let domains = read_list(&self.paths.list_dir.join("web.txt"));
        // 網站驗證結果（同一次評測內同一個 網域 + IP 只連一次）與「無法驗證」的天數紀錄
        let mut site_cache: HashMap<(String, Ipv4Addr), (SiteCheck, String)> = HashMap::new();
        let mut strikes = Strikes::load(bl_file.with_file_name("blacklist-suspects.json"), now);
        let mut universe: HashSet<u64> = HashSet::new();
        let mut blocked_report: Vec<Value> = Vec::new();
        let mut scored = 0usize;
        for (di, domain) in domains.iter().enumerate() {
            ctx.checkpoint().await;
            let survivors: Vec<usize> = verified.iter().copied().filter(|i| all[*i].alive).collect();
            if survivors.is_empty() {
                break;
            }
            info!("[{}/{}] {domain}（倖存 {}）", di + 1, domains.len(), survivors.len());
            let results = self.query_all(&all, survivors, domain, &cfg).await;
            let mut ok: Vec<(usize, Vec<Ipv4Addr>, f64)> = Vec::new();
            let mut blocked: Vec<(usize, String)> = Vec::new();
            let mut errors = 0usize;
            for (i, r) in results {
                match r.outcome {
                    Outcome::Ok(ips) => ok.push((i, ips, r.ms)),
                    Outcome::Blocked(b) => blocked.push((i, b)),
                    Outcome::Error(e) => {
                        errors += 1;
                        let s = &mut all[i];
                        s.timeouts += 1;
                        if s.timeouts > cfg.max_timeouts {
                            s.kill(format!("連線失敗 ({e})"));
                        }
                    }
                }
            }
            let answered = ok.len() + blocked.len();
            // 多數 DNS 都解析不到 → 網域本身有問題（下線 / 只在特定地區），本題不計分
            if answered == 0 || (ok.len() as f64 / answered as f64) < 0.3 {
                info!(
                    "   -> 多數 DNS 都解析不到（成功 {} / 封鎖 {}），此網域略過",
                    ok.len(),
                    blocked.len()
                );
                continue;
            }
            scored += 1;
            let dix = di as u32;
            for (i, reason) in &blocked {
                let s = &mut all[*i];
                s.kill(format!("封殺 {domain} ({reason})"));
                if blocked_report.len() < MAX_BLOCKED_REPORT {
                    blocked_report.push(json!({ "dns": s.id, "domain": domain, "reason": reason, "pinned": s.pinned }));
                }
                if !s.pinned {
                    info!("   [淘汰] {} -> 封殺 ({reason})", s.id);
                }
            }

            // 污染判斷（v16.1 邏輯）
            let all_ips: Vec<IpAddr> = ok.iter().flat_map(|(_, ips, _)| ips.iter().map(|i| IpAddr::V4(*i))).collect();
            let ip_info = cache.lookup(&*self.asn, &all_ips).await;
            for (_, ips, _) in &ok {
                universe.extend(ips.iter().map(|ip| select::item(dix, u32::from(*ip))));
            }
            let infos: Vec<AsnInfo> = ok
                .iter()
                .map(|(_, ips, _)| ip_info.get(&IpAddr::V4(ips[0])).cloned().unwrap_or_else(AsnInfo::unknown))
                .collect();
            let unknown = infos.iter().filter(|i| i.is_unknown()).count();
            if unknown > 0 {
                info!("   ⚠ {unknown} 筆結果查不到 ASN（ip-api 無法連線或受限），這些結果不做污染判斷");
            }
            let mut groups: Vec<Group> = Vec::new();
            for info in infos.iter().filter(|i| !i.is_unknown()) {
                let w = rules::calculate_weight(Some(info), domain);
                match groups.iter_mut().find(|g| rules::is_same_group(Some(&g.rep), Some(info))) {
                    Some(g) => g.score += w,
                    None => groups.push(Group {
                        rep: info.clone(),
                        score: w,
                    }),
                }
            }
            groups.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
            let mut valid: Vec<&Group> = Vec::new();
            if let Some(winner) = groups.first() {
                valid.push(winner);
                for g in &groups[1..] {
                    if rules::is_official_owner(Some(&g.rep), domain)
                        || rules::is_trusted_partner(Some(&winner.rep), Some(&g.rep))
                        || g.score / winner.score > 0.2
                    {
                        valid.push(g);
                    }
                }
            }
            // 規則判定不在多數業者群組裡的回答：不再只看 IP 屬於哪家業者就定罪，
            // 實際連過去用網域檢查憑證（跟替換台灣節點前的驗證同一個標準）。
            // 憑證有效 = 規則沒涵蓋的 CDN（保留）；憑證不符 = 確定劫持（永久黑名單）；連不上 = 今天不用，連續多天才定罪
            let suspects: Vec<usize> = ok
                .iter()
                .zip(&infos)
                .enumerate()
                .filter(|(_, (_, info))| !info.is_unknown() && !valid.iter().any(|g| rules::is_same_group(Some(&g.rep), Some(info))))
                .map(|(k, _)| k)
                .collect();
            let mut verdict: HashMap<usize, (SiteCheck, String)> = HashMap::new();
            if !suspects.is_empty() {
                // 基準：多數群組的正常回答也要能用憑證驗證，這個網域才能用憑證判斷
                // （例如 ctldl.windowsupdate.com 只有 HTTP，連正確的 CDN 也沒有對應的憑證）
                let base: Vec<Ipv4Addr> = ok
                    .iter()
                    .zip(&infos)
                    .filter(|(_, info)| !info.is_unknown() && valid.iter().any(|g| rules::is_same_group(Some(&g.rep), Some(info))))
                    .flat_map(|((_, ips, _), _)| ips.iter().copied())
                    .fold(Vec::new(), |mut v, ip| {
                        if v.len() < VERIFY_IPS && !v.contains(&ip) {
                            v.push(ip);
                        }
                        v
                    });
                let baseline = self.verify_answers(domain, vec![base], &mut site_cache).await.remove(0);
                if baseline.0 == SiteCheck::Valid {
                    let checks = self
                        .verify_answers(domain, suspects.iter().map(|k| ok[*k].1.clone()).collect(), &mut site_cache)
                        .await;
                    verdict = suspects.into_iter().zip(checks).collect();
                } else {
                    info!(
                        "   -> {domain} 的正常回答也無法用憑證驗證（{}），這個網域不判斷汙染（{} 個不同業者的回答照常計分）",
                        baseline.1,
                        suspects.len()
                    );
                }
            }
            let (mut polluted, mut suspicious, mut rescued) = (0usize, 0usize, 0usize);
            let mut newly_bl: Vec<String> = Vec::new();
            for (k, ((i, ips, ms), info)) in ok.iter().zip(&infos).enumerate() {
                let s = &mut all[*i];
                match verdict.remove(&k) {
                    None => s.record(dix, *ms, ips),
                    Some((SiteCheck::Valid, _)) => {
                        rescued += 1;
                        info!(
                            "   [保留] {} -> {}：業者規則沒涵蓋，但 {domain} 的憑證有效（不是劫持）",
                            s.id, info.raw
                        );
                        s.record(dix, *ms, ips);
                    }
                    Some((SiteCheck::Invalid, why)) => {
                        s.kill(format!("汙染 {domain} (判定為 {}，憑證不符 {why})", info.raw));
                        polluted += 1;
                        if !s.pinned {
                            info!("   [淘汰] {} -> 汙染 {}：憑證不符 {why}（加入永久黑名單）", s.id, info.raw);
                            if blacklist.insert(s.id.clone()) {
                                newly_bl.push(format!("{}  # {today} 汙染：{domain} → {}（憑證不符 {why}）", s.id, info.raw));
                            }
                        }
                    }
                    Some((SiteCheck::Unverified, why)) => {
                        s.kill(format!("可疑 {domain} (判定為 {}，網站無法驗證 {why})", info.raw));
                        suspicious += 1;
                        if !s.pinned && strikes.add(&s.id, &today) >= SUSPECT_DAYS && blacklist.insert(s.id.clone()) {
                            info!("   [淘汰] {} -> 連續 {SUSPECT_DAYS} 天回答無法驗證的位址（加入永久黑名單）", s.id);
                            newly_bl.push(format!(
                                "{}  # {today} 汙染：{domain} → {}（連續 {SUSPECT_DAYS} 天網站無法驗證）",
                                s.id, info.raw
                            ));
                        } else if !s.pinned {
                            info!("   [今天不用] {} -> {}：{domain} 網站無法驗證（{why}）", s.id, info.raw);
                        }
                    }
                }
            }
            if !newly_bl.is_empty() {
                append_blacklist(&bl_file, &newly_bl);
            }
            info!(
                "   -> 第一名 [{}]，有效 {}、封殺 {}、汙染 {polluted}、可疑 {suspicious}、規則外但驗證通過 {rescued}、逾時 {errors}",
                groups.first().map(|g| g.rep.raw.as_str()).unwrap_or("無法判定"),
                ok.len() - polluted - suspicious,
                blocked.len()
            );
        }

        strikes.save();
        let finals: Vec<usize> = verified.iter().copied().filter(|i| all[*i].alive).collect();
        if !finals.iter().any(|i| !all[*i].pinned) {
            bail!("沒有倖存的 DNS，保留昨天的結果");
        }

        // Phase 2：查 DNS 擁有者
        info!("=== 最終結算：查詢 DNS 擁有者 ===");
        let mut host_ip: Vec<Option<IpAddr>> = Vec::with_capacity(finals.len());
        for &i in &finals {
            let host = &all[i].up.host;
            let ip = match host.parse::<IpAddr>() {
                Ok(ip) => Some(ip),
                Err(_) => self.prober.resolve_v4(host.clone()).await.map(IpAddr::V4),
            };
            host_ip.push(ip);
        }
        let owner_info = cache
            .lookup(&*self.asn, &host_ip.iter().flatten().copied().collect::<Vec<_>>())
            .await;
        let scored_list: Vec<Scored> = finals
            .iter()
            .zip(&host_ip)
            .map(|(&i, ip)| {
                let owner = match ip {
                    Some(ip) => owner_info.get(ip).map(|x| x.raw.clone()).unwrap_or_else(|| "Unknown".into()),
                    None => "Unknown".into(),
                };
                all[i].scored(owner)
            })
            .collect();
        let eliminated: Vec<(String, &'static str, String)> = all
            .iter()
            .filter(|s| !s.alive)
            .map(|s| (s.id.clone(), s.kind, s.fail_reason.clone()))
            .collect();
        let issues: HashMap<String, Vec<String>> = all.iter().filter(|s| s.pinned).map(|s| (s.id.clone(), s.issues.clone())).collect();
        let counts = json!({ "total": all.len(), "verified": verified.len(), "survivors": finals.len(), "eliminated": eliminated.len() });
        drop(all);
        ctx.checkpoint().await;

        // Phase 2 / 3 的計算可能要幾秒（候選多時），放到 blocking 執行緒
        let total = universe.len();
        drop(universe);
        let opts = cfg.select.clone();
        let want_reports = out_dir.is_some();
        let calc = tokio::task::spawn_blocking(move || compute(scored_list, scored, total, &opts, want_reports, eliminated)).await?;

        let selected: Vec<Value> = calc
            .selection
            .selected
            .iter()
            .map(|p| {
                let s = &calc.finals[p.idx];
                json!({ "id": s.id, "type": s.kind, "owner": s.owner, "avgMs": fixed_num(s.avg, 2), "newItems": p.newly, "reason": p.why })
            })
            .collect();
        let pinned: Vec<Value> = calc
            .finals
            .iter()
            .filter(|s| s.pinned)
            .map(|s| json!({ "id": s.id, "avgMs": fixed_num(s.avg, 2), "coverageItems": s.item_count(), "issues": issues.get(&s.id).cloned().unwrap_or_default() }))
            .collect();
        let state = json!({
            "generatedAt": iso_string(ctx.now_ms()),
            "date": today,
            "universe": total,
            "coverage": if total > 0 { fixed_num(calc.selection.covered as f64 / total as f64, 4) } else { json!(0) },
            "selected": selected,
            "pinned": pinned,
            "counts": counts,
            "blocked": blocked_report,
            "skippedTypes": skipped.iter().filter(|(k, _)| **k != "blacklist").map(|(k, n)| (k.to_string(), json!(n))).collect::<Map<String, Value>>(),
            "reportDir": out_dir.as_ref().map(|d| d.display().to_string()),
        });
        write_json(&self.paths.upstreams_file, &state)?;
        if let Some(d) = &out_dir {
            for (name, body) in &calc.reports {
                report(&d.join(name), body.as_bytes());
            }
            report(&d.join("upstreams.json"), &serde_json::to_vec_pretty(&state).unwrap_or_default());
        }
        info!("=== 今日選出的上游 ===");
        for x in state["selected"].as_array().into_iter().flatten() {
            info!(
                "  {:<48} {:<4} {:>7}ms  +{}  ({}) {}",
                x["id"].as_str().unwrap_or(""),
                x["type"].as_str().unwrap_or(""),
                x["avgMs"].to_string(),
                x["newItems"],
                x["reason"].as_str().unwrap_or(""),
                x["owner"].as_str().unwrap_or("")
            );
        }
        let pinned_line: Vec<String> = state["pinned"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|p| {
                let n = p["issues"].as_array().map(Vec::len).unwrap_or(0);
                format!(
                    "{} {}ms{}",
                    p["id"].as_str().unwrap_or(""),
                    p["avgMs"],
                    if n > 0 { format!(" ⚠ {n} 個問題") } else { String::new() }
                )
            })
            .collect();
        info!(
            "  固定上游：{}",
            if pinned_line.is_empty() {
                "無".into()
            } else {
                pinned_line.join("、")
            }
        );
        info!(
            "  總涵蓋率 {}%（{}/{total}）",
            to_fixed(
                if total > 0 {
                    calc.selection.covered as f64 / total as f64 * 100.0
                } else {
                    0.0
                },
                1
            ),
            calc.selection.covered
        );

        // 清理舊報表
        if let Some(root) = &self.paths.out_root {
            cleanup_reports(root, ctx.now_ms(), cfg.keep_days);
        }
        info!("[{}] 結束 {}", JOB_NAME, fmt_time(ctx.now_ms()));
        Ok(state)
    }

    /// 對 `idx` 這些候選並行查同一個網域；回傳（候選位置, 結果），依輸入順序
    /// 每個可疑回答驗證最多 `VERIFY_IPS` 個 IP：任一個憑證有效 → 有效；否則任一個憑證不符 → 劫持；都連不上 → 無法驗證
    async fn verify_answers(
        &self,
        domain: &str,
        answers: Vec<Vec<Ipv4Addr>>,
        cache: &mut HashMap<(String, Ipv4Addr), (SiteCheck, String)>,
    ) -> Vec<(SiteCheck, String)> {
        let mut todo: Vec<Ipv4Addr> = Vec::new();
        for ips in &answers {
            for ip in ips.iter().take(VERIFY_IPS) {
                if !cache.contains_key(&(domain.to_string(), *ip)) && !todo.contains(ip) {
                    todo.push(*ip);
                }
            }
        }
        if !todo.is_empty() {
            let prober = self.prober.clone();
            let d = domain.to_string();
            let res = map_limit(todo.clone(), VERIFY_CONC, move |ip| {
                let (p, d) = (prober.clone(), d.clone());
                async move { p.verify_site(IpAddr::V4(ip), d, VERIFY_TIMEOUT).await }
            })
            .await;
            for (ip, r) in todo.into_iter().zip(res) {
                let r = r.unwrap_or((SiteCheck::Unverified, "驗證工作失敗".into()));
                cache.insert((domain.to_string(), ip), r);
            }
        }
        answers
            .iter()
            .map(|ips| {
                let rs: Vec<&(SiteCheck, String)> = ips
                    .iter()
                    .take(VERIFY_IPS)
                    .filter_map(|ip| cache.get(&(domain.to_string(), *ip)))
                    .collect();
                if let Some(v) = rs.iter().find(|r| r.0 == SiteCheck::Valid) {
                    return (*v).clone();
                }
                if let Some(v) = rs.iter().find(|r| r.0 == SiteCheck::Invalid) {
                    return (*v).clone();
                }
                rs.first()
                    .map(|r| (*r).clone())
                    .unwrap_or((SiteCheck::Unverified, "沒有 IP".into()))
            })
            .collect()
    }

    async fn query_all(&self, all: &[Srv], idx: Vec<usize>, domain: &str, cfg: &BenchCfg) -> Vec<(usize, QueryResult)> {
        let jobs: Vec<(usize, Upstream)> = idx.iter().map(|&i| (i, all[i].up.clone())).collect();
        let prober = self.prober.clone();
        let timeout = cfg.timeout;
        let domain = domain.to_string();
        let res = map_limit(jobs, cfg.conc, |(i, up)| {
            let prober = prober.clone();
            let domain = domain.clone();
            async move { (i, query(&*prober, &up, &domain, timeout, 1).await) }
        })
        .await;
        idx.iter()
            .zip(res)
            .map(|(&i, r)| {
                r.unwrap_or((
                    i,
                    QueryResult {
                        outcome: Outcome::Error("內部錯誤".into()),
                        ms: 0.0,
                    },
                ))
            })
            .collect()
    }
}

struct Calc {
    /// 依延遲排序
    finals: Vec<Scored>,
    selection: select::Selection,
    reports: Vec<(&'static str, String)>,
}

fn compute(
    mut finals: Vec<Scored>,
    scored_domains: usize,
    total: usize,
    opts: &SelectOpts,
    want_reports: bool,
    eliminated: Vec<(String, &'static str, String)>,
) -> Calc {
    select::extended_metrics(&mut finals, scored_domains);
    finals.sort_by(|a, b| a.avg.partial_cmp(&b.avg).unwrap_or(std::cmp::Ordering::Equal));
    let refs: Vec<&Scored> = finals.iter().collect();
    let asn_best = select::best_per_asn(&refs);
    info!("ASN 過濾：{} → {}", finals.len(), asn_best.len());
    let selection = select::select(&refs, &asn_best, total, opts);
    let mut reports = Vec::new();
    if want_reports {
        let asn_refs: Vec<&Scored> = asn_best.iter().map(|i| refs[*i]).collect();
        reports.push(("final_dns_smart.csv", select::final_csv(&refs)));
        reports.push((
            "dns_coverage_optimization.csv",
            select::greedy_csv(&refs, total, Strategy::Coverage),
        ));
        reports.push(("dns_latency_optimization.csv", select::greedy_csv(&refs, total, Strategy::Latency)));
        reports.push((
            "dns_asn_coverage_optimization.csv",
            select::greedy_csv(&asn_refs, total, Strategy::Coverage),
        ));
        reports.push((
            "dns_asn_latency_optimization.csv",
            select::greedy_csv(&asn_refs, total, Strategy::Latency),
        ));
        let rows: Vec<String> = eliminated
            .iter()
            .map(|(id, kind, why)| format!("{id},{kind},\"{}\"", why.replace('"', "'")))
            .collect();
        reports.push(("eliminated.csv", format!("\u{feff}DNS_Server,Type,Reason\n{}", rows.join("\n"))));
    }
    Calc {
        finals,
        selection,
        reports,
    }
}

fn report(path: &Path, data: &[u8]) {
    if let Err(e) = write_atomic(path, data) {
        warn!("報表寫入失敗（{}）：{e}", path.display());
    }
}

/// 刪掉超過 `keep_days` 天的報表目錄（YYYY-MM-DD）
fn cleanup_reports(root: &Path, now: u64, keep_days: u64) {
    let Ok(rd) = std::fs::read_dir(root) else { return };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if let Some(t) = parse_date_utc(&name) {
            if now.saturating_sub(t) > keep_days * DAY_MS {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
}
