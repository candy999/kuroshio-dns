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
//!  對照組（`protected.txt`，有過濾的大型 DNS）：照常測、照常判，用來確認評測判得出過濾；
//!  永遠不選、不算覆蓋、不參加多數決、不記可疑、不進永久黑名單（3.4.2）。
//!
//! 3.0 的差異：
//! - 支援的類型由 `Prober::supports` 決定（目前 udp / tcp / dot / doh）；doq、doh3、dnscrypt 先略過，
//!   數量記在結果的 `skippedTypes`。之後加上傳輸層，這裡不用改。
//! - 名單多了 `dotlist.txt`（DoT 主機）與 `stamps.txt`（sdns:// stamp）；`dohlist.txt` 的每一筆另外產生一個 h3:// 候選。
//! - 每測完一個網域就呼叫 `checkpoint()`：讓出 CPU，系統吃緊時暫停（規格 05）。
//!
//! 3.3 的差異（記憶體）：Phase 1 分成兩段。
//! - 收集：每個候選用自己的連線依序測完全部網域（每筆之間至少隔 `benchmark.paceMs`），測完就關閉連線；
//!   同時只測 `benchmark.concurrency` 個候選（也看可用記憶體）。以前是「每個網域問一輪全部候選」，
//!   整個評測期間幾百條加密連線一直開著（QUIC 還有 keep-alive），小記憶體的機器會吃不消。
//!   系統吃緊時先關閉手上的連線再暫停，恢復後重新連線。
//! - 判斷：照原本的順序逐網域重跑同樣的規則（封殺、汙染、逾時淘汰），結果跟以前的流程相同。
//!   原始答案只留到判斷完那個網域，被淘汰的候選隨即釋放。
//! - 選擇與報表的計算放到 blocking 執行緒，不卡住 DNS。
//!
//! 3.4.0 的差異（上游多樣性，規格 10 第 6 節）：Phase 2 判斷每台上游的所在地（台灣網段、ip-api 的國別、
//! 量到的最低延遲），`benchmark.coverageRegion = near`（預設）時「覆蓋」階段先挑鄰近的（台灣、日本、香港、新加坡）。

pub mod learn;
pub mod malware;
pub mod probe;
pub mod rules;
pub mod select;
pub mod tags;
pub mod tiers;

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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tags::{Tag, Tier};
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
/// 對照組最多幾台（多的不測）：只是用來確認判斷正常，不需要多
pub const MAX_PROTECTED: usize = 64;

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
    /// 程式附帶的預設名單（OpenWrt：`/usr/share/kuroshio/benchmark`）。`list_dir` 是使用者自己加的名單時，
    /// 兩邊合併一起測：升級套件就會拿到新的預設名單，使用者加的也不會被蓋掉
    pub default_list_dir: Option<PathBuf>,
    /// 自己評測學到的永久黑名單（`state/blacklist.txt`）；程式附帶的 `list_dir/blacklist.txt` 是唯讀的基本名單，
    /// 學到的寫在 state，升級套件不會被蓋掉
    pub blacklist_file: Option<PathBuf>,
    /// 評測學習資料（`state/benchmark-learn.json`，寫成 `.zst`；3.5.0，見 [`learn`]）；None 就不讀不寫
    pub learn_file: Option<PathBuf>,
}

impl BenchPaths {
    /// 名單：使用者的（`list_dir`）加上程式附帶的（`default_list_dir`），保持順序、去掉重複
    pub fn read_lists(&self, name: &str) -> Vec<String> {
        let mut out = read_list(&self.list_dir.join(name));
        if let Some(d) = self.default_list_dir.as_ref().filter(|d| **d != self.list_dir) {
            let key = |l: &str| l.split_whitespace().next().unwrap_or("").trim_end_matches('/').to_ascii_lowercase();
            let mut seen: HashSet<String> = out.iter().map(|l| key(l)).collect();
            for l in read_list(&d.join(name)) {
                if seen.insert(key(&l)) {
                    out.push(l);
                }
            }
        }
        out
    }

    /// 同 [`read_lists`](Self::read_lists)，另外帶著每一筆的標記（3.5.0，見 [`tags`]）。合併與去重的規則相同；
    /// 使用者名單（`list_dir` 跟 `default_list_dir` 不同時）裡沒寫標記的是 [`Tier::User`]；
    /// 同一個上游兩邊都有、使用者那一筆沒寫標記時，用使用者那一筆的網址、預設名單的標記
    pub fn read_lists_tagged(&self, name: &str) -> Vec<(String, Tag)> {
        let read = |d: &Path| tags::parse_tagged(&std::fs::read_to_string(d.join(name)).unwrap_or_default());
        let mut out = read(&self.list_dir);
        let Some(d) = self.default_list_dir.as_ref().filter(|d| **d != self.list_dir) else {
            return out;
        };
        let key = |l: &str| l.split_whitespace().next().unwrap_or("").trim_end_matches('/').to_ascii_lowercase();
        let mut seen: HashMap<String, usize> = HashMap::new();
        for (i, (l, _)) in out.iter().enumerate() {
            seen.entry(key(l)).or_insert(i);
        }
        let mut bare: Vec<bool> = out.iter().map(|(_, t)| t.is_bare()).collect();
        for (l, t) in read(d) {
            match seen.get(&key(&l)) {
                Some(&i) => {
                    if bare[i] {
                        out[i].1 = t;
                        bare[i] = false;
                    }
                }
                None => {
                    seen.insert(key(&l), out.len());
                    out.push((l, t));
                    bare.push(false);
                }
            }
        }
        for (i, (_, t)) in out.iter_mut().enumerate() {
            if bare.get(i).copied().unwrap_or(false) {
                t.tier = Tier::User;
            }
        }
        out
    }

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
            default_list_dir: None,
            learn_file: Some(r("./state/benchmark-learn.json")),
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
    /// 系統還有多少可用記憶體可以用（bytes，扣掉保留量之後）；決定同時測幾個候選。None = 只看設定
    pub headroom: Option<Arc<dyn Fn() -> Option<u64> + Send + Sync>>,
    /// 執行中的進度（`/api/jobs` 的 `detail.dns-benchmark`）
    progress: Arc<Mutex<Option<Value>>>,
    /// 評測前的路徑檢查（3.3.6）
    pub path: PathSource,
    /// 最近一次報表的摘要另存到這裡（報表目錄在記憶體裡時；重開機後還查得到）
    pub keep_last: Option<PathBuf>,
    /// 台灣網段（`geo/tw-ip.json`）：判斷上游在不在台灣（規格 10 的 6.1）。None = 讀不到，只靠國別與延遲
    pub tw: Option<Arc<crate::geo::TwIp>>,
    /// `benchmark.tiers = auto` 時用哪一種（主程式依實體記憶體換算，3.5.0 A3）。預設全部測
    pub tier_auto: tiers::Mode,
}

/// 讀台灣網段（`tw-ip.json`，約 41 KB）給評測用；讀不到或格式錯誤是 None（不影響評測，只少一個訊號）。
/// 評測在子程序跑時要在子程序裡自己讀
pub fn read_tw_ip(path: &Path) -> Option<Arc<crate::geo::TwIp>> {
    let bytes = std::fs::read(path).ok()?;
    match crate::geo::TwIp::parse(&bytes) {
        Ok(t) => Some(Arc::new(t)),
        Err(e) => {
            warn!("[{JOB_NAME}] {} 格式錯誤，判斷上游所在地時不用台灣網段：{e:#}", path.display());
            None
        }
    }
}

/// 評測前的路徑檢查從哪裡來
#[derive(Clone)]
pub enum PathSource {
    /// 不檢查（測試；或 `upstream.pathCheck` 關閉時效果相同）
    Off,
    /// 實際檢查（`kuroshio_net::path::check`），結果套用到這個行程的連線層
    Live,
    /// 固定的結果（測試）
    Fixed(Box<kuroshio_net::path::Report>),
}

/// 每個測試中的候選估計要多少記憶體（一條 TLS / QUIC 連線加上緩衝）。
/// Newifi D3（mipsel）3.3.3 實測：同時 32 個時，收集階段比子程序剛開始多約 16.6 MB（扣掉原始答案 6 MB），每個約 520 KB
const PER_CANDIDATE_BYTES: u64 = 512 * 1024;

impl Benchmark {
    /// 正式環境：kuroshio-net 傳輸 + ip-api.com
    pub fn new(paths: BenchPaths) -> Benchmark {
        let mut b = Benchmark::with(paths, Arc::new(NetProber), Arc::new(IpApi::default()));
        b.path = PathSource::Live;
        b
    }

    pub fn with(paths: BenchPaths, prober: Arc<dyn Prober>, asn: Arc<dyn AsnSource>) -> Benchmark {
        Benchmark {
            paths,
            prober,
            asn,
            preflight: (PREFLIGHT_DOMAIN.into(), PREFLIGHT_EXPECTED.to_vec()),
            headroom: None,
            progress: Arc::new(Mutex::new(None)),
            path: PathSource::Off,
            keep_last: None,
            tw: None,
            tier_auto: tiers::Mode::Ab,
        }
    }

    /// `benchmark.tiers = auto` 時用哪一種（見 [`tiers::auto_mode`]）
    pub fn with_tier_auto(mut self, m: tiers::Mode) -> Benchmark {
        self.tier_auto = m;
        self
    }

    /// 指定台灣網段（`read_tw_ip` 讀出來的）
    pub fn with_tw(mut self, tw: Option<Arc<crate::geo::TwIp>>) -> Benchmark {
        self.tw = tw;
        self
    }

    /// 指定路徑檢查的結果（測試）
    pub fn with_path(mut self, r: kuroshio_net::path::Report) -> Benchmark {
        self.path = PathSource::Fixed(Box::new(r));
        self
    }

    /// 評測前的路徑檢查（`upstream.pathCheck` 關閉時不做）
    async fn path_report(&self, cfg: &Value) -> Option<kuroshio_net::path::Report> {
        if !kuroshio_config::chain::flex_bool(get(cfg, "upstream.pathCheck"), true).0 {
            return None;
        }
        match &self.path {
            PathSource::Off => None,
            PathSource::Fixed(r) => Some((**r).clone()),
            PathSource::Live => {
                kuroshio_net::path::set_v6_mode(kuroshio_net::path::V6Mode::from_value(get(cfg, "upstream.ipv6")));
                let r = kuroshio_net::path::check(&kuroshio_net::path::Targets::default()).await;
                kuroshio_net::path::apply(&r, intercept_policy(cfg) == "ignore");
                Some(r)
            }
        }
    }

    /// 用可用記憶體決定同時測幾個候選（`headroom` 回傳扣掉保留量後還剩多少）
    pub fn with_headroom(mut self, f: Arc<dyn Fn() -> Option<u64> + Send + Sync>) -> Benchmark {
        self.headroom = Some(f);
        self
    }

    fn set_progress(&self, v: Value) {
        *self.progress.lock().unwrap() = Some(v);
    }

    /// 同時測幾個候選：設定值，再用可用記憶體的 1/4 限制（最少 4 個）
    fn effective_conc(&self, cfg: &BenchCfg) -> (usize, Option<u64>) {
        let room = self.headroom.as_ref().and_then(|f| f());
        let by_mem = room.map(|r| ((r / 4) / PER_CANDIDATE_BYTES).max(4) as usize);
        (cfg.conc.min(by_mem.unwrap_or(usize::MAX)).max(1), room)
    }

    /// 跑一次評測；成功時回傳寫進 upstreams.json 的內容
    pub async fn run(&self, ctx: &JobCtx) -> Result<Value> {
        let mut g = RunGuard {
            progress: self.progress.clone(),
            cache: AsnCache::load(&self.paths),
            cache_file: self.paths.out_root.as_ref().map(|r| r.join("cidr_cache.json")),
            finished: false,
        };
        let r = self.run_inner(ctx, &mut g.cache).await;
        g.finished = true;
        r
    }
}

/// 一次評測的收尾：正常結束、出錯、被排程逾時強制結束（future 被丟掉）都會經過這裡的 `Drop`。
/// 清掉進度（`/api/jobs` 才不會一直顯示執行中）、存 ASN 快取（同步寫檔）
struct RunGuard {
    progress: Arc<Mutex<Option<Value>>>,
    cache: AsnCache,
    cache_file: Option<PathBuf>,
    /// `run_inner` 有跑完（沒有被丟掉）
    finished: bool,
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        // 工作 panic 時鎖可能中毒：照樣清掉（在 Drop 裡再 panic 會直接中止整個行程）
        *self.progress.lock().unwrap_or_else(|e| e.into_inner()) = None;
        if !self.finished {
            warn!("[{JOB_NAME}] 評測被強制結束：已清掉進度，已經查到的 ASN 快取與可疑 DNS 紀錄照樣存檔");
        }
        // 2.x 每查到新的就寫一次（一天可能寫上百次 340 KB）；這裡只在結束時寫一次
        if let (Some(f), true) = (&self.cache_file, self.cache.dirty) {
            if let Err(e) = self.cache.save(f) {
                warn!("ASN 快取寫入失敗：{e}");
            }
        }
    }
}

impl Job for Benchmark {
    fn run(&self, ctx: JobCtx) -> BoxFuture<Result<()>> {
        let me = self.clone();
        Box::pin(async move { Benchmark::run(&me, &ctx).await.map(|_| ()) })
    }

    fn detail(&self) -> Option<Value> {
        self.progress.lock().unwrap().clone()
    }
}

// ---------------- 設定 ----------------

struct BenchCfg {
    timeout: Duration,
    conc: usize,
    /// 同一個候選兩筆查詢之間至少隔多久（收集時一個候選連續測全部網域，不要打太快）
    pace: Duration,
    max_timeouts: u32,
    keep_days: u64,
    pinned: Vec<String>,
    select: SelectOpts,
    /// `benchmark.nearMaxMs`：最低延遲在這以內就算鄰近
    near_max_ms: f64,
    /// `benchmark.tiers`：`a`／`ab`；None = `auto`（用 [`Benchmark::tier_auto`]）
    tiers: Option<tiers::Mode>,
    /// `benchmark.malwareProbe`：惡意網站探測（預設開；`probe.txt` 空的就不跑）
    malware_probe: bool,
}

fn pos_f64(cfg: &Value, k: &str) -> Option<f64> {
    get(cfg, k).and_then(Value::as_f64).filter(|v| *v > 0.0)
}

impl BenchCfg {
    fn from(cfg: &Value) -> BenchCfg {
        BenchCfg {
            timeout: Duration::from_millis(pos_f64(cfg, "benchmark.timeoutMs").unwrap_or(1500.0) as u64),
            conc: pos_f64(cfg, "benchmark.concurrency").unwrap_or(50.0) as usize,
            pace: Duration::from_millis(get(cfg, "benchmark.paceMs").and_then(Value::as_u64).unwrap_or(250)),
            // 2.x 是 `?? 2`：0 也算數
            max_timeouts: get(cfg, "benchmark.maxTimeouts").and_then(Value::as_u64).unwrap_or(2) as u32,
            keep_days: pos_f64(cfg, "benchmark.keepDays").unwrap_or(14.0) as u64,
            pinned: strings(cfg, "upstream.pinned").unwrap_or_default(),
            select: select_opts(cfg),
            near_max_ms: kuroshio_config::chain::coverage_region_of(cfg).1,
            tiers: get(cfg, "benchmark.tiers").and_then(Value::as_str).and_then(tiers::Mode::parse),
            malware_probe: kuroshio_config::chain::flex_bool(get(cfg, "benchmark.malwareProbe"), true).0,
        }
    }
}

/// `upstream.interceptPolicy`：skip-plain（預設）、warn、ignore
fn intercept_policy(cfg: &Value) -> &'static str {
    match get(cfg, "upstream.interceptPolicy").and_then(Value::as_str).unwrap_or("") {
        "warn" => "warn",
        "ignore" => "ignore",
        _ => "skip-plain",
    }
}

/// 候選的「經營者」：主機名稱的可註冊網域（例如 dns.example.co.jp → example.co.jp），IP 用 /16。
/// 用來判斷好幾台可疑的回答是不是來自「互相獨立」的業者
fn operator_of(host: &str) -> String {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v) => sub_key(v),
            IpAddr::V6(v) => format!("{:x}:{:x}", v.segments()[0], v.segments()[1]),
        };
    }
    let labels: Vec<&str> = host.trim_end_matches('.').split('.').collect();
    let n = labels.len();
    if n <= 2 {
        return host.to_ascii_lowercase();
    }
    // co.jp、com.tw 這類兩層的國家網域：取三層
    let take = if labels[n - 1].len() == 2 && labels[n - 2].len() <= 3 {
        3
    } else {
        2
    };
    labels[n - take.min(n)..].join(".").to_ascii_lowercase()
}

/// 依路徑檢查結果，這個候選今天要不要略過（回傳原因的代號）
fn path_skip(r: Option<&kuroshio_net::path::Report>, policy: &str, up: &Upstream) -> Option<&'static str> {
    use kuroshio_net::path::Proto;
    use kuroshio_net::upstream::Kind;
    let r = r?;
    let literal = up.host.parse::<IpAddr>().ok();
    if literal.is_some_and(|ip| ip.is_ipv6()) && !r.v6_usable() {
        return Some("ipv6-unavailable");
    }
    if matches!(up.kind, Kind::Udp | Kind::Tcp) && policy == "skip-plain" {
        let v6 = literal.is_some_and(|ip| ip.is_ipv6());
        let hit = if v6 {
            r.plain_v6.as_ref().is_some_and(|p| p.intercepted())
        } else if up.kind == Kind::Udp {
            r.plain_v4.udp
        } else {
            r.plain_v4.tcp
        };
        if hit {
            return Some("plain-intercepted");
        }
    }
    let proto = match up.kind {
        Kind::Dot => Some(Proto::Dot),
        Kind::Doh => Some(Proto::Doh),
        Kind::Doq | Kind::Doh3 => Some(Proto::Quic),
        _ => None,
    };
    if proto.is_some_and(|p| r.blocked.contains(&p)) {
        return Some(match proto.unwrap() {
            Proto::Dot => "blocked-dot",
            Proto::Doh => "blocked-doh",
            Proto::Quic => "blocked-quic",
        });
    }
    None
}

fn path_skip_label(k: &str) -> &'static str {
    match k {
        "ipv6-unavailable" => "IPv6 位址（這台沒有 IPv6）",
        "plain-intercepted" => "一般 DNS（53 埠被路上的攔截者接走）",
        "blocked-dot" => "DoT（853 埠被擋）",
        "blocked-doh" => "DoH（443 埠被擋）",
        "blocked-quic" => "DoQ / DoH3（QUIC 被擋）",
        _ => "其他",
    }
}

/// 一般 DNS（會被路上的攔截者接走的那種）
fn is_plain(kind: &str) -> bool {
    kind == "udp" || kind == "tcp"
}

fn strings(cfg: &Value, k: &str) -> Option<Vec<String>> {
    get(cfg, k)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
}

/// 選上游的參數（`upstream.autoTypes`、`autoMax`，`benchmark.maxAvgLatencyMs`、`coverageTarget`、`minAuto`；0 或缺少時用 2.x 的預設；
/// `benchmark.coverageRegion`：預設 `near`）
pub fn select_opts(cfg: &Value) -> SelectOpts {
    SelectOpts {
        auto_types: strings(cfg, "upstream.autoTypes").unwrap_or_else(|| SelectOpts::default().auto_types),
        max_n: pos_f64(cfg, "upstream.autoMax").unwrap_or(5.0) as usize,
        max_avg: pos_f64(cfg, "benchmark.maxAvgLatencyMs").unwrap_or(250.0),
        coverage_target: pos_f64(cfg, "benchmark.coverageTarget").unwrap_or(0.97),
        min_auto: pos_f64(cfg, "benchmark.minAuto").unwrap_or(3.0) as usize,
        near_first: kuroshio_config::chain::coverage_region_of(cfg).0 == kuroshio_config::chain::CoverageRegion::Near,
    }
}

// ---------------- ASN 快取（以 /16 為鍵，同 2.x 的 cidr_cache.json） ----------------

struct AsnCache {
    map: HashMap<String, AsnInfo>,
    /// 這次執行查不到的 /16（不重複查；2.x 每個網域都會重查，ip-api 連不上時每題都要等）
    failed: HashSet<String>,
    /// 這次執行已經向 ip-api 問過的 /16（含補問國別的）：快取裡沒有國別的舊資料只補問一次，查不到也不重問
    cc_tried: HashSet<String>,
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
            cc_tried: HashSet::new(),
            dirty: false,
        }
    }

    /// 查業者。`want_cc`：快取裡有這個 /16 但沒有國別（3.4.0 以前的快取）時當成沒查過、補問一次
    /// （只用在 Phase 2 決選的上游位址；汙染判斷的查詢量很大，不補問，也不整批重查 cidr_cache.json）
    async fn lookup(&mut self, src: &dyn AsnSource, ips: &[IpAddr], want_cc: bool) -> HashMap<IpAddr, AsnInfo> {
        // 每個 /16 只查一個代表
        let mut reps: Vec<Ipv4Addr> = Vec::new();
        let mut seen = HashSet::new();
        for ip in ips {
            if let IpAddr::V4(v4) = ip {
                let k = sub_key(*v4);
                let need = match self.map.get(&k) {
                    None => !self.failed.contains(&k),
                    Some(i) => want_cc && i.cc.is_empty() && !self.cc_tried.contains(&k),
                };
                if need && seen.insert(k) {
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
                    self.failed.insert(k.clone());
                }
                self.cc_tried.insert(k);
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
    /// 對照組：預期會擋的類型（`filter=` 標記，例如 `ads,adult`）
    protected: Option<String>,
    /// 名單的標記（3.5.0）：只當起點與排序依據，不跳過任何檢查
    tag: Tag,
    /// 執行時上線以來從未成功（主程式登記的 `neverOk`，3.5.0 A7）：照測，但今天不選
    never_ok: bool,
    /// 對照組的資格賽網域被擋（3.5.0 A2）：記為判出過濾（`stage = preflight`），照樣測網域
    preflight: Option<String>,
    /// 惡意網站探測（3.5.0 A5）判出這個一般候選有擋惡意網站：比照對照組（照常評測、今天不選、不記可疑、不進黑名單）
    malware_filter: bool,
    /// 惡意網站探測的結果（對照組用）：Some(true)＝有擋、Some(false)＝沒擋、None＝今天判不出來
    probe: Option<bool>,
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
    fn new(id: String, up: Upstream, pinned: bool, tag: Tag) -> Srv {
        Srv {
            id,
            kind: kind_name(up.kind),
            up,
            pinned,
            protected: None,
            tag,
            never_ok: false,
            preflight: None,
            malware_filter: false,
            probe: None,
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

    /// 經營者（多樣性用）：名單的 `op=`，沒有就用主機的可註冊網域或 /16
    fn op_key(&self) -> String {
        if self.tag.op.is_empty() {
            operator_of(&self.up.host)
        } else {
            self.tag.op.to_ascii_lowercase()
        }
    }

    /// 會不會被選來用（固定上游另外處理，對照組永遠不選）
    fn selectable(&self) -> bool {
        !self.pinned && !self.control_like()
    }

    /// 比照對照組處理：對照組本身，或惡意網站探測判出有擋惡意網站的一般候選（3.5.0 A5）。
    /// 照常測、照常判，但不選、不算覆蓋、不參加多數決、不記可疑、不進永久黑名單
    fn control_like(&self) -> bool {
        self.protected.is_some() || self.malware_filter
    }

    /// 判斷過程摘要裡的稱呼
    fn control_label(&self) -> &'static str {
        if self.protected.is_some() {
            "對照組"
        } else {
            "有擋惡意網站"
        }
    }

    /// 評測結果會不會記下來（可疑天數、永久黑名單）：固定上游與對照組都不記
    fn learns(&self) -> bool {
        self.selectable()
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
            // Phase 2 查完業者之後才填（classify_region）
            region: String::new(),
            near: false,
            region_source: "registered",
            tier: self.tag.tier.name(),
            op: self.tag.op.clone(),
            excluded: self.never_ok,
            // compute() 裡用台灣網段算（3.5.0 B5）
            tw_rate: None,
            ecs: self.tag.ecs,
        }
    }
}

/// 名單的一行：有多個欄位時取指定開頭的那一個（同 2.x）
fn pick_token(line: &str, prefix: &str) -> String {
    line.split_whitespace().find(|p| p.starts_with(prefix)).unwrap_or(line).to_string()
}

/// 對照組（`protected.txt`）：一行一個上游（一般 DNS 的位址或 `https://`、`tls://`、`quic://`、`sdns://`），
/// 後面的 `filter=ads,adult,malware` 是預期會擋的類型；最多 [`MAX_PROTECTED`] 台。
/// 回傳（上游、預期會擋的類型、標記）
fn protected_ids(paths: &BenchPaths) -> Vec<(String, String, Tag)> {
    let lines = paths.read_lists_tagged("protected.txt");
    if lines.len() > MAX_PROTECTED {
        warn!("對照組 {} 台，超過上限 {MAX_PROTECTED}，多的不測", lines.len());
    }
    lines
        .into_iter()
        .take(MAX_PROTECTED)
        .filter_map(|(l, mut tag)| {
            let spec = l.split_whitespace().next()?.to_string();
            tag.protected = true;
            let expect = tag.filter.clone().unwrap_or_else(|| "?".to_string());
            Some((spec, expect, tag))
        })
        .collect()
}

/// 對照組的結果（result, stage, reason）：
/// - `detected`：網域判斷判出過濾（封殺、汙染、可疑，`stage = domain`）；或網域都沒判出、但資格賽網域被擋（`stage = preflight`，3.5.0）
/// - `passed`：網域都沒判出（`stage = domain`）
/// - `untested`：連不上、逾時（資格賽就連不上是 `preflight`，測網域時才連不上是 `domain`）
/// - 網域沒判出、惡意網站探測判出有擋（3.5.0 A5）：`detected`、`stage = probe`
fn protected_outcome(s: &Srv) -> (&'static str, &'static str, String) {
    let judged = ["封殺", "汙染", "可疑"].iter().any(|p| s.fail_reason.starts_with(p));
    if !s.alive && judged {
        return ("detected", "domain", s.fail_reason.clone());
    }
    if s.probe == Some(true) {
        return ("detected", "probe", "封殺 惡意網站探測".to_string());
    }
    if let Some(pf) = &s.preflight {
        return ("detected", "preflight", pf.clone());
    }
    if s.alive {
        return ("passed", "domain", String::new());
    }
    let stage = if s.fail_reason.starts_with("資格賽") {
        "preflight"
    } else {
        "domain"
    };
    ("untested", stage, s.fail_reason.clone())
}

/// 對照組的預期值（`expectMet`）：`filter=` 裡至少有一種類型今天有對應的判斷 → 那些類型裡有沒有判出。
/// - 廣告、追蹤、成人：評測網域（`web.txt`）有，看網域判斷（資格賽網域被擋不算，那不是這些類型）；
/// - 惡意網站：看惡意網站探測（3.5.0 A5）；探測今天沒跑、失效、或這一台沒回答探測時不算有判斷；
/// - 都沒有判斷（例如只擋惡意網站而探測今天失效）或今天沒測到 → None
fn expect_met(expect: &str, result: &str, stage: &str, probe: Option<bool>) -> Option<bool> {
    if result == "untested" {
        return None;
    }
    let (mut checked, mut met) = (false, false);
    for t in expect.split(',') {
        match t.trim() {
            "ads" | "adult" | "tracking" | "telemetry" => {
                checked = true;
                met |= result == "detected" && stage == "domain";
            }
            "malware" => {
                if let Some(hit) = probe {
                    checked = true;
                    met |= hit;
                }
            }
            _ => {}
        }
    }
    checked.then_some(met)
}

/// 對照組一天的結果字元（學習檔的 `control`）。惡意網站探測今天有設定卻判不出來（失效、保險絲、參照不足）時，
/// 預期會擋惡意網站、其他都沒判出的對照組記成「沒測到」：不然探測失效一天就會被報成回歸
fn control_day_char(result: &str, expect: &str, probe_unusable: bool) -> char {
    if result == "passed" && probe_unusable && malware::expects_malware(expect) {
        return 'u';
    }
    day_char(result)
}

/// 一筆探測查詢的分類：只認明確的阻擋（NXDOMAIN、沒有 A 記錄、封鎖位址）；回另一個位址（業者自己的警告頁）不判
fn probe_ans(r: Option<&QueryResult>) -> malware::Ans {
    match r.map(|r| &r.outcome) {
        Some(Outcome::Ok(_)) => malware::Ans::Ok,
        Some(Outcome::Blocked(_)) => malware::Ans::Blocked,
        _ => malware::Ans::None,
    }
}

/// 惡意網站探測這一次的狀態（`upstreams.json` 的 `probe.malware`）
#[derive(Debug, Default)]
struct ProbeRun {
    /// off＝設定關掉、empty＝`probe.txt` 沒有探測網域、no-reference＝參照不足、invalid＝探測都失效、
    /// fuse＝保險絲燒斷、ok＝有判斷
    state: &'static str,
    /// `probe.txt` 裡的探測網域數
    domains: usize,
    /// 自我檢查通過、這次拿去問全部候選的探測網域
    used: Vec<String>,
    /// 事後再驗還有效的個數
    valid: usize,
    /// 判出有擋惡意網站的一般候選
    filtering: Vec<String>,
    /// 有回答探測的一般候選數
    probed: usize,
    /// 今天多送了幾筆查詢（估計：自我檢查＋每個候選的探測）
    queries: usize,
}

impl ProbeRun {
    /// 有設定探測、但今天判不出來
    fn unusable(&self) -> bool {
        matches!(self.state, "no-reference" | "invalid" | "fuse")
    }
    fn to_json(&self) -> Value {
        json!({ "malware": {
            "state": self.state, "domains": self.domains, "used": self.used.len(), "valid": self.valid,
            "blockedBy": self.filtering.len(), "probed": self.probed, "queries": self.queries,
            "filtering": self.filtering.iter().take(MAX_PROBE_REPORT).collect::<Vec<_>>(),
        } })
    }
}

/// 結果裡最多列幾台「有擋惡意網站」的候選
const MAX_PROBE_REPORT: usize = 100;

/// 昨天選上或列為候補的上游（`upstreams.json` 的 `selected[]`、`spares[]`）：分級評測只測 A 級時沿用，
/// 不然探索到的 B 級今天選上、明天又不測。讀不到就是空的
fn incumbent_ids(file: &Path) -> HashSet<String> {
    let Some(v) = read_json(file) else {
        return HashSet::new();
    };
    ["selected", "spares"]
        .iter()
        .flat_map(|k| v[*k].as_array().into_iter().flatten())
        .filter_map(|x| x["id"].as_str().map(str::to_string))
        .collect()
}

/// 分級評測的統計（`upstreams.json` 的 `tiers`）
#[derive(Debug, Clone, Copy)]
struct TierCounts {
    mode: tiers::Mode,
    /// 設定是 `auto`（依記憶體換算出來的）
    auto: bool,
    /// 今天測的 A 級
    a: usize,
    incumbent: usize,
    fill: usize,
    explore: usize,
    skipped_b: usize,
    /// 依歷史拉上來每天測的 B 級（A4）：升級的、試用中的
    promoted: usize,
    trial: usize,
    /// 依歷史降級的 A 級（`a` 模式今天不測）
    demoted: usize,
    /// 降級太多、今天不採用降級
    demote_fuse: bool,
    /// 今天評測之後的升降（A4）
    promoted_today: usize,
    demoted_today: usize,
}

impl TierCounts {
    fn to_json(self) -> Value {
        json!({
            "mode": self.mode.name(), "auto": self.auto, "a": self.a, "incumbent": self.incumbent,
            "fill": self.fill, "explore": self.explore, "skippedB": self.skipped_b,
            "promoted": self.promoted, "trial": self.trial, "demoted": self.demoted, "demoteFuse": self.demote_fuse,
            "promotedToday": self.promoted_today, "demotedToday": self.demoted_today,
        })
    }
}

/// 社群好友提供的上游候選最多收幾個（社群模組已經先合併、排序、限制成 100 個；這裡再擋一次，
/// 檔案是舊版寫的或被改過也不會放大評測）
const MAX_SHARED: usize = 100;

/// 一個候選與它在名單裡的標記（3.5.0）
#[derive(Debug, Clone, PartialEq)]
pub struct Cand {
    pub id: String,
    pub tag: Tag,
}

/// 依 2.x 的順序組出候選清單：udp、doh（含社群提供的加密上游）、doq，再加上 3.0 新增的 dot、doh3、dnscrypt。
/// 回傳（候選、社群好友提供的個數）
pub fn candidate_ids(paths: &BenchPaths) -> (Vec<Cand>, usize) {
    let cand = |(id, tag): (String, Tag)| Cand { id, tag };
    let mut udp: Vec<Cand> = paths.read_lists_tagged("iplist.txt").into_iter().map(cand).collect();
    let mut doh: Vec<Cand> = paths
        .read_lists_tagged("dohlist.txt")
        .into_iter()
        .map(|(l, t)| cand((pick_token(&l, "http"), t)))
        .collect();
    let doq: Vec<Cand> = paths
        .read_lists_tagged("doqlist.txt")
        .into_iter()
        .map(|(l, t)| cand((pick_token(&l, "quic"), t)))
        .collect();
    let dot: Vec<Cand> = paths
        .read_lists_tagged("dotlist.txt")
        .into_iter()
        .map(|(l, t)| {
            let tok = l
                .split_whitespace()
                .find(|p| p.contains("://"))
                .unwrap_or_else(|| l.split_whitespace().next().unwrap_or(&l));
            let id = if tok.contains("://") {
                tok.to_string()
            } else {
                format!("tls://{tok}")
            };
            cand((id, t))
        })
        .collect();
    let stamps: Vec<Cand> = paths
        .read_lists_tagged("stamps.txt")
        .into_iter()
        .map(|(l, t)| cand((pick_token(&l, "sdns://"), t)))
        .collect();
    // 社群好友提供的上游：只是候選，照常經過資格賽、汙染、封殺、速度檢查；
    // 一律當 B 級（好友給的只是候選，不能靠別人的話升到 A）
    let shared: Vec<String> = paths
        .community_candidates
        .as_ref()
        .and_then(|p| read_json(p))
        .and_then(|v| v.get("ids").and_then(Value::as_array).cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|x| x.as_str().map(str::to_string))
        .take(MAX_SHARED)
        .collect();
    let shared_tag = || Tag {
        tier: Tier::B,
        ..Default::default()
    };
    for id in &shared {
        if id.starts_with("https://") || id.starts_with("tls://") {
            if !doh.iter().any(|c| c.id == *id) {
                doh.push(Cand {
                    id: id.clone(),
                    tag: shared_tag(),
                });
            }
        } else {
            let ip = id.strip_prefix("udp://").unwrap_or(id);
            if ip.parse::<IpAddr>().is_ok() && !udp.iter().any(|u| u.id == ip) {
                udp.push(Cand {
                    id: ip.to_string(),
                    tag: shared_tag(),
                });
            }
        }
    }
    if !shared.is_empty() {
        info!("社群好友提供的上游候選 {} 個", shared.len());
    }
    // DoH 每一筆同時測 HTTP/2 與 HTTP/3（規格 01 第 1.2 節）；h3:// 沿用它的 https:// 那一筆的標記
    let h3: Vec<Cand> = doh
        .iter()
        .filter_map(|c| {
            c.id.strip_prefix("https://").map(|r| Cand {
                id: format!("h3://{r}"),
                tag: c.tag.clone(),
            })
        })
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
/// 同一個業者群組有幾家互相獨立（不同經營者）的加密 DNS 都「網站無法驗證」時，照常計分、不記可疑天數
const INDEPENDENT_OPERATORS: usize = 3;
/// 規則外但憑證有效的回答來自幾個以上不同業者時，這個網域算「多家 CDN」：連不上照常計分、不記可疑天數
const MULTI_CDN_GROUPS: usize = 2;
/// 「憑證不符」幾天（不同日期）才列入永久黑名單。當天一律淘汰不用；隔天以後再犯才永久排除——
/// 正常的 DNS 也可能有一天回了舊位址（網站剛搬家、快取還沒過期），那個位址上的憑證就不是這個網站的。
/// 永久黑名單要手動編輯才能恢復，不能因為一天的一題就定罪；真的在劫持的 DNS 隔天還是會被抓到
const CERT_DAYS: usize = 2;
/// 「憑證不符」在可疑紀錄檔裡的鍵（跟「無法驗證」分開算）
fn cert_key(id: &str) -> String {
    format!("cert|{id}")
}
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
    /// 有變動才寫（同步寫檔）；寫過（不論成敗）就不再重寫，`Drop` 不會重複記錄失敗
    fn save(&mut self) {
        if self.dirty {
            self.dirty = false;
            if let Err(e) = write_json(&self.file, &json!(self.map)) {
                warn!("可疑 DNS 紀錄寫入失敗（{}）：{e}", self.file.display());
            }
        }
    }
}

/// 評測中途出錯或被強制結束（future 被丟掉）時也存：已經記下的天數不能丟
/// （永久黑名單是當下就附加寫入的，這份紀錄要跟它一致）
impl Drop for Strikes {
    fn drop(&mut self) {
        self.save();
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
        if let Some(d) = &self.paths.default_list_dir {
            blacklist.extend(read_blacklist(&d.join("blacklist.txt")));
        }
        blacklist.extend(read_blacklist(&bl_file));
        let (ids, _) = candidate_ids(&self.paths);
        let protected = protected_ids(&self.paths);
        // 學習資料（3.5.0）：執行時上線以來從未成功的（主程式登記的）今天照測、不選；排除 3 次之後忘掉重來
        let mut learned = self.paths.learn_file.as_ref().map(|p| learn::Learn::load(p));
        let (never_ok, mut learn_dirty) = learned.as_mut().map(|l| l.take_never_ok_round()).unwrap_or_default();
        let never_ok: HashSet<String> = never_ok.into_iter().collect();
        let today_n = learn::day_of(now);
        // 不支援 HTTP/3 的 DoH（3.5.0 A6）：它的 https:// 已經不在名單的刪掉
        if let Some(l) = learned.as_mut() {
            let h3_ids: HashSet<&str> = ids.iter().filter(|c| c.id.starts_with("h3://")).map(|c| c.id.as_str()).collect();
            learn_dirty |= l.h3_prune(|k| h3_ids.contains(k)) > 0;
        }
        let mut h3_skipped = 0usize;
        // 判斷過程的摘要（judge.log）：報表目錄在記憶體裡（重開機就沒了），最近一次另存一份到持久資料區
        let mut journal = Journal::default();
        // 路徑檢查：一般 DNS 被接走、IPv6 不能用、協定被擋時，那些候選今天不測（測了也只會冤枉它們）
        let policy = intercept_policy(&ctx.cfg);
        let path = self.path_report(&ctx.cfg).await;
        if let Some(r) = &path {
            jinfo!(journal, "[路徑檢查] {}", kuroshio_net::path::summary(r));
            for w in r.warnings(policy) {
                warn!("[路徑檢查] {w}");
            }
        }
        let mut path_skipped: BTreeMap<&'static str, usize> = BTreeMap::new();

        // 候選：固定上游在前；同一個上游（正規化後）只測一次
        let mut seen: HashSet<String> = HashSet::new();
        let mut all: Vec<Srv> = Vec::new();
        let mut skipped: BTreeMap<&'static str, usize> = BTreeMap::new();
        // 順序：固定上游、對照組、一般候選（同一個上游出現在兩邊時，以前面的為準）
        // 固定上游是使用者指定的：標記當成 user
        let user_tag = Tag {
            tier: Tier::User,
            ..Default::default()
        };
        let roles = cfg
            .pinned
            .iter()
            .map(|p| (p, true, None, &user_tag))
            .chain(protected.iter().map(|(p, e, t)| (p, false, Some(e), t)))
            .chain(ids.iter().map(|c| (&c.id, false, None, &c.tag)));
        for (spec, pinned, expect, tag) in roles {
            // 對照組不看永久黑名單：用來確認判斷正常，不能被永久封殺
            let pinned_or_control = pinned || expect.is_some();
            if !pinned_or_control && blacklist.contains(spec.as_str()) {
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
            if !pinned_or_control && blacklist.contains(&up.id) {
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
            if !pinned {
                if let Some(why) = path_skip(path.as_ref(), policy, &up) {
                    *path_skipped.entry(why).or_default() += 1;
                    continue;
                }
            }
            // 連續好幾天 QUIC 連不上（https:// 正常）的 h3://：跳過期間不測（3.5.0 A6）
            if !pinned_or_control
                && up.kind == kuroshio_net::upstream::Kind::Doh3
                && learned.as_ref().is_some_and(|l| l.h3_skipping(spec, today_n))
            {
                h3_skipped += 1;
                continue;
            }
            let mut s = Srv::new(spec.clone(), up, pinned, tag.clone());
            s.protected = expect.cloned();
            s.never_ok = !pinned && expect.is_none() && never_ok.contains(&s.up.id);
            all.push(s);
        }
        // 分級評測（3.5.0 A3）：`a` 模式只測 A 級、使用者的、沿用、補位、探索；其餘 B 級今天不測
        // （不算淘汰、不記任何紀錄）。在路徑檢查、黑名單略過之後才算：多樣性要看今天實際能測的
        let tier_mode = cfg.tiers.unwrap_or(self.tier_auto);
        // 依評測歷史的升降（3.5.0 A4）：人工分級是起點，學習檔的 hist 決定實際分級；讀不到學習檔就照人工分級。
        // 固定上游、對照組、使用者自己加的不參與
        let hist_of = |s: &Srv| -> Option<&learn::Hist> {
            if s.pinned || s.protected.is_some() {
                return None;
            }
            learned.as_ref().filter(|l| today_n >= l.day).and_then(|l| l.hist.get(&s.id))
        };
        let eff: Vec<Tier> = all.iter().map(|s| tiers::effective_tier(s.tag.tier, hist_of(s), today_n)).collect();
        let manual_a = all.iter().filter(|s| s.selectable() && s.tag.tier == Tier::A).count();
        let demoted_now = (0..all.len()).filter(|&i| all[i].tag.tier == Tier::A && eff[i] != Tier::A).count();
        // 保險絲：被降級的超過 A 級的三分之一，多半是線路的問題，今天不採用降級
        let demote_fuse = demoted_now > 0 && tiers::demotion_fuse(manual_a, demoted_now);
        if demote_fuse {
            let line = format!(
                "[分級] 依歷史要降級的 A 級有 {demoted_now} 個，超過 A 級 {manual_a} 個的三分之一：多半是這條線路的問題，今天不採用降級（照人工分級測）"
            );
            warn!("{line}");
            journal.push(line);
        }
        let eff: Vec<Tier> = (0..all.len())
            .map(|i| {
                if demote_fuse && all[i].tag.tier == Tier::A {
                    Tier::A
                } else {
                    eff[i]
                }
            })
            .collect();
        let pulled = |i: usize, st: learn::HistState| {
            matches!(all[i].tag.tier, Tier::B | Tier::Unknown) && eff[i] == Tier::A && hist_of(&all[i]).is_some_and(|h| h.e == st)
        };
        let tier_plan = {
            let incumbents = incumbent_ids(&self.paths.upstreams_file);
            let items: Vec<tiers::Item> = all
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    let aged = hist_of(s).map(|h| h.aged(today_n));
                    tiers::Item {
                        id: &s.id,
                        kind: s.kind,
                        tier: eff[i],
                        op: s.op_key(),
                        ms: s.tag.ms,
                        always: s.pinned || s.protected.is_some() || s.never_ok,
                        incumbent: incumbents.contains(s.id.as_str()),
                        score: aged.as_ref().and_then(learn::Hist::score),
                        bad: aged.as_ref().is_some_and(tiers::history_bad),
                        manual_b: matches!(s.tag.tier, Tier::B | Tier::Unknown),
                    }
                })
                .collect();
            tiers::plan(&items, tier_mode, today_n, &cfg.select.auto_types)
        };
        let mut tier_counts = TierCounts {
            promoted: (0..all.len()).filter(|&i| pulled(i, learn::HistState::Promoted)).count(),
            trial: (0..all.len()).filter(|&i| pulled(i, learn::HistState::Trial)).count(),
            demoted: if demote_fuse { 0 } else { demoted_now },
            demote_fuse,
            mode: tier_mode,
            auto: cfg.tiers.is_none(),
            a: (0..all.len())
                .filter(|&i| tier_plan.why[i] == tiers::Why::Base && all[i].selectable() && all[i].tag.tier == Tier::A)
                .count(),
            incumbent: tier_plan.count(tiers::Why::Incumbent),
            fill: tier_plan.count(tiers::Why::Fill),
            explore: tier_plan.count(tiers::Why::Explore),
            skipped_b: tier_plan.count(tiers::Why::Skip),
            promoted_today: 0,
            demoted_today: 0,
        };
        if tier_mode == tiers::Mode::A {
            let mut k = 0usize;
            all.retain(|_| {
                k += 1;
                tier_plan.tested(k - 1)
            });
            jinfo!(
                journal,
                "[分級] 今天測 A 級 {} 個（另外依歷史降級、今天不測 {} 個）、依歷史拉上來的 B 級 {} 個（試用 {}）、沿用昨天選上或候補的 B 級 {} 個、補位 {} 個{}、探索 {} 個；B 級其餘 {} 個今天不測（不算淘汰、不記紀錄）",
                tier_counts.a,
                tier_counts.demoted,
                tier_counts.promoted + tier_counts.trial,
                tier_counts.trial,
                tier_counts.incumbent,
                tier_counts.fill,
                if tier_plan.fill_reason.is_empty() {
                    String::new()
                } else {
                    format!("（原因：{}）", tier_plan.fill_reason)
                },
                tier_counts.explore,
                tier_counts.skipped_b
            );
        }
        drop(tier_plan);
        if !path_skipped.is_empty() {
            let parts: Vec<String> = path_skipped.iter().map(|(k, n)| format!("{} {n}", path_skip_label(k))).collect();
            jinfo!(
                journal,
                "依路徑檢查略過：{}（不是那些伺服器的問題，不記可疑、不進黑名單）",
                parts.join("、")
            );
        }
        let unsupported: Vec<String> = skipped
            .iter()
            .filter(|(k, _)| **k != "blacklist")
            .map(|(k, n)| format!("{k} {n}"))
            .collect();
        if !unsupported.is_empty() {
            jinfo!(journal, "這個版本還不支援的類型先略過（之後版本加入）：{}", unsupported.join("、"));
        }
        if h3_skipped > 0 {
            jinfo!(
                journal,
                "HTTP/3 先不測 {h3_skipped} 個：連續 {} 天以上 QUIC 連不上、HTTPS 正常（跳過 7～30 天，到期再試）",
                learn::H3_FAIL_DAYS
            );
        }
        for s in all.iter().filter(|s| s.never_ok) {
            jinfo!(journal, "  {}：執行時上線以來從未成功，今天照測、不選", s.id);
        }
        jinfo!(
            journal,
            "候選 {} 個（固定上游 {}，對照組 {}，永久黑名單略過 {}）",
            all.len(),
            all.iter().filter(|s| s.pinned).count(),
            all.iter().filter(|s| s.protected.is_some()).count(),
            skipped.get("blacklist").copied().unwrap_or(0)
        );

        // Phase 0：資格賽
        let (pf_domain, pf_expected) = self.preflight.clone();
        jinfo!(journal, "[Phase 0] 資格賽 ({pf_domain})");
        let results = self.query_all(&all, (0..all.len()).collect(), &pf_domain, &cfg).await;
        // 每個候選的資格賽結果（A6 用：h3:// 與它的 https://）
        let mut pf: Vec<Option<Preflight>> = vec![None; all.len()];
        for (i, r) in results {
            let pass = matches!(&r.outcome, Outcome::Ok(ips) if ips.iter().any(|ip| pf_expected.contains(ip)));
            pf[i] = Some(match (&r.outcome, pass) {
                (_, true) => Preflight::Pass,
                (Outcome::Error(_), _) => Preflight::Error,
                _ => Preflight::Answered,
            });
            if !pass {
                // 對照組（3.5.0 A2）：有回答、只是資格賽網域被擋（NXDOMAIN、封鎖位址、導到封鎖頁）——
                // 家庭／兒童類的過濾 DNS 常把其他公共 DNS 的主機名稱也擋掉（防止繞過）。這也是判出過濾，
                // 而且伺服器是正常的：照樣測網域（對照組本來每天就要測一輪），看評測判不判得出它擋的類型。
                // 連線失敗、逾時照舊是沒測到
                if all[i].protected.is_some() && !matches!(r.outcome, Outcome::Error(_)) {
                    let what = match &r.outcome {
                        Outcome::Ok(ips) => format!("導向 {}", ips.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",")),
                        _ => reason_of(&r),
                    };
                    jinfo!(
                        journal,
                        "   [對照組] {} -> 資格賽網域被擋（{what}）：記為判出過濾，照樣測網域",
                        all[i].id
                    );
                    all[i].preflight = Some(format!("封殺 {pf_domain}（資格賽：{what}）"));
                    continue;
                }
                all[i].kill(format!("資格賽失敗 ({})", reason_of(&r)));
            }
        }
        if let Some(l) = learned.as_mut() {
            let c = record_h3(l, &all, &pf, today_n);
            learn_dirty |= c.any();
            if c.any() || l.h3_skipping_count(today_n) > 0 {
                jinfo!(
                    journal,
                    "HTTP/3：多記一天 {}、開始跳過 {}、恢復 {}（目前跳過 {} 個）",
                    c.counted,
                    c.skipped,
                    c.cleared,
                    l.h3_skipping_count(today_n)
                );
            }
        }
        let verified: Vec<usize> = (0..all.len()).filter(|i| all[*i].alive).collect();
        jinfo!(journal, "資格賽結束：通過 {} / 淘汰 {}", verified.len(), all.len() - verified.len());
        if !verified.iter().any(|i| all[*i].selectable()) {
            bail!("沒有任何 DNS 通過資格賽（本機網路可能異常），保留昨天的結果");
        }
        if let Some(d) = &out_dir {
            let list: Vec<&str> = verified.iter().map(|i| all[*i].id.as_str()).collect();
            report(&d.join("verified_dns_list.csv"), list.join("\n").as_bytes());
        }
        ctx.checkpoint().await;

        // Phase 1：逐一測網域。先收集（每個候選用自己的連線測完全部網域），再照原本的順序逐網域判斷
        let domains = self.paths.read_lists("web.txt");
        // 惡意網站探測（3.5.0 A5）：先用少數幾台參照做自我檢查，通過的探測網域（最多 4 個）接在評測網域後面，
        // 每個候選用同一條連線順便問（不另外連線）；判斷時評測網域照舊，探測的答案另外看
        let mut probe = self
            .probe_precheck(ctx, &all, &verified, &pf, &domains, &pf_domain, &cfg, &mut journal)
            .await;
        let mut ask = domains.clone();
        ask.extend(probe.used.iter().cloned());
        let mut raw = self.collect(ctx, &all, &verified, &ask, &cfg).await;
        drop(ask);
        if !probe.used.is_empty() {
            // 探測的答案拿出來（只留分類），原始答案只留評測網域的
            let mut answers: Vec<Vec<malware::Ans>> = vec![Vec::new(); all.len()];
            for &i in &verified {
                if raw[i].len() > domains.len() {
                    answers[i] = raw[i].drain(domains.len()..).map(|r| probe_ans(r.as_ref())).collect();
                }
            }
            self.probe_judge(&mut all, &verified, answers, &mut probe, &mut journal);
        }
        // 網站驗證結果（同一次評測內同一個 網域 + IP 只連一次）與「無法驗證」的天數紀錄
        let mut site_cache: HashMap<(String, Ipv4Addr), (SiteCheck, String)> = HashMap::new();
        let mut strikes = Strikes::load(bl_file.with_file_name("blacklist-suspects.json"), now);
        let mut universe: HashSet<u64> = HashSet::new();
        let mut blocked_report: Vec<Value> = Vec::new();
        let mut scored = 0usize;
        for (di, domain) in domains.iter().enumerate() {
            ctx.checkpoint().await;
            // 已經淘汰的候選：剩下的原始答案用不到了
            for &i in &verified {
                if !all[i].alive && !raw[i].is_empty() {
                    raw[i] = Vec::new();
                }
            }
            let survivors: Vec<usize> = verified.iter().copied().filter(|i| all[*i].alive).collect();
            if survivors.is_empty() {
                break;
            }
            jinfo!(journal, "[{}/{}] {domain}（倖存 {}）", di + 1, domains.len(), survivors.len());
            let kept: usize = raw.iter().map(|v| v.iter().filter(|x| x.is_some()).count()).sum();
            self.set_progress(json!({
                "phase": "judge", "domain": di + 1, "domains": domains.len(), "survivors": survivors.len(), "openConnections": 0,
                "rawBytes": raw_bytes(kept),
                "text": format!("執行中：判斷第 {} / {} 個網域（倖存 {}）", di + 1, domains.len(), survivors.len()),
            }));
            // 收集時因為逾時太多而提早停下的候選，在這之前就已經依同樣的規則淘汰了
            let results: Vec<(usize, QueryResult)> = survivors
                .iter()
                .filter_map(|&i| raw[i].get_mut(di).and_then(Option::take).map(|r| (i, r)))
                .collect();
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
            // 對照組不參加多數決（它們本來就會擋）
            let ok_n = ok.iter().filter(|(i, _, _)| !all[*i].control_like()).count();
            let blocked_n = blocked.iter().filter(|(i, _)| !all[*i].control_like()).count();
            let answered = ok_n + blocked_n;
            // 多數 DNS 都解析不到 → 網域本身有問題（下線 / 只在特定地區），本題不計分
            if answered == 0 || (ok_n as f64 / answered as f64) < 0.3 {
                jinfo!(journal, "   -> 多數 DNS 都解析不到（成功 {ok_n} / 封鎖 {blocked_n}），此網域略過");
                continue;
            }
            scored += 1;
            let dix = di as u32;
            for (i, reason) in &blocked {
                let s = &mut all[*i];
                s.kill(format!("封殺 {domain} ({reason})"));
                if blocked_report.len() < MAX_BLOCKED_REPORT {
                    blocked_report.push(
                        json!({ "dns": s.id, "domain": domain, "reason": reason, "pinned": s.pinned, "protected": s.protected.is_some() }),
                    );
                }
                if s.control_like() {
                    jinfo!(journal, "   [{}] {} -> 判出過濾：封殺 ({reason})", s.control_label(), s.id);
                } else if !s.pinned {
                    jinfo!(journal, "   [淘汰] {} -> 封殺 ({reason})", s.id);
                }
            }

            // 污染判斷（v16.1 邏輯）
            let all_ips: Vec<IpAddr> = ok.iter().flat_map(|(_, ips, _)| ips.iter().map(|i| IpAddr::V4(*i))).collect();
            let ip_info = cache.lookup(&*self.asn, &all_ips, false).await;
            for (_, ips, _) in ok.iter().filter(|(i, _, _)| !all[*i].control_like()) {
                universe.extend(ips.iter().map(|ip| select::item(dix, u32::from(*ip))));
            }
            let infos: Vec<AsnInfo> = ok
                .iter()
                .map(|(_, ips, _)| ip_info.get(&IpAddr::V4(ips[0])).cloned().unwrap_or_else(AsnInfo::unknown))
                .collect();
            let unknown = infos.iter().filter(|i| i.is_unknown()).count();
            if unknown > 0 {
                jinfo!(
                    journal,
                    "   ⚠ {unknown} 筆結果查不到 ASN（ip-api 無法連線或受限），這些結果不做污染判斷"
                );
            }
            let mut groups: Vec<Group> = Vec::new();
            // 一般 DNS 的答案完全一樣時只算一票：路上有攔截者（沒偵測到的也算）時，幾百台一般 DNS 的答案
            // 其實都是同一個攔截者給的，不能讓它們變成「多數」（padavan-tw 11-19：306 台一般 DNS 全是上游黑潮在回答）
            let mut plain_seen: HashSet<Vec<Ipv4Addr>> = HashSet::new();
            for ((i, ips, _), info) in ok.iter().zip(&infos).filter(|(_, i)| !i.is_unknown()) {
                if all[*i].control_like() {
                    continue;
                }
                let mut w = rules::calculate_weight(Some(info), domain);
                if is_plain(all[*i].kind) {
                    let mut key = ips.clone();
                    key.sort_unstable();
                    if !plain_seen.insert(key) {
                        w = 0.0;
                    }
                }
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
            // 憑證有效 = 規則沒涵蓋的 CDN（保留）；憑證不符 = 今天淘汰，不同的兩天都這樣才列入永久黑名單；
            // 連不上 = 今天不用，多天才定罪
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
                    jinfo!(
                        journal,
                        "   -> {domain} 的正常回答也無法用憑證驗證（{}），這個網域不判斷汙染（{} 個不同業者的回答照常計分）",
                        baseline.1,
                        suspects.len()
                    );
                }
            }
            // 「網站無法驗證」的可疑回答：同一個業者群組有好幾家互相獨立的加密 DNS 都這樣回答，
            // 比較可能是網站或這條路連不上那些位址，不是這些 DNS 一起竄改 → 照常計分，不記可疑天數
            let independent: HashSet<usize> = {
                let unverified: Vec<usize> = verdict
                    .iter()
                    .filter(|(_, (c, _))| *c == SiteCheck::Unverified)
                    .map(|(k, _)| *k)
                    .filter(|k| !is_plain(all[ok[*k].0].kind) && !all[ok[*k].0].control_like())
                    .collect();
                let mut out = HashSet::new();
                for &k in &unverified {
                    let ops: HashSet<String> = unverified
                        .iter()
                        .filter(|j| rules::is_same_group(Some(&infos[**j]), Some(&infos[k])))
                        .map(|j| operator_of(&all[ok[*j].0].up.host))
                        .collect();
                    if ops.len() >= INDEPENDENT_OPERATORS {
                        out.insert(k);
                    }
                }
                out
            };
            // 多家 CDN 的網域：規則外的回答裡，已經有 2 個以上不同業者的回答憑證有效（真的在服務這個網站），
            // 這種網域本來就由很多業者提供，「連不上」不能當成竄改的證據 → 照常計分，不記可疑天數
            // （padavan-tw 3.3.6：cdn-mum.alibabachengdun.com 有 39 個規則外但憑證有效的回答，dnscry.pt 兩台卻因為 TIMEOUT 被記可疑）
            let multi_cdn = {
                let mut seen: Vec<&AsnInfo> = Vec::new();
                for (k, _) in verdict.iter().filter(|(_, (c, _))| *c == SiteCheck::Valid) {
                    let info = &infos[*k];
                    if !seen.iter().any(|g| rules::is_same_group(Some(g), Some(info))) {
                        seen.push(info);
                    }
                }
                seen.len() >= MULTI_CDN_GROUPS
            };
            let (mut polluted, mut suspicious, mut rescued, mut lenient) = (0usize, 0usize, 0usize, 0usize);
            let mut newly_bl: Vec<String> = Vec::new();
            for (k, ((i, ips, ms), info)) in ok.iter().zip(&infos).enumerate() {
                let s = &mut all[*i];
                match verdict.remove(&k) {
                    None => s.record(dix, *ms, ips),
                    Some((SiteCheck::Valid, _)) => {
                        rescued += 1;
                        jinfo!(
                            journal,
                            "   [保留] {} -> {}：業者規則沒涵蓋，但 {domain} 的憑證有效（不是劫持）",
                            s.id,
                            info.label()
                        );
                        s.record(dix, *ms, ips);
                    }
                    Some((SiteCheck::Invalid, why)) => {
                        s.kill(format!("汙染 {domain} (判定為 {}，憑證不符 {why})", info.label()));
                        if s.control_like() {
                            jinfo!(
                                journal,
                                "   [{}] {} -> 判出過濾：汙染 {}（憑證不符 {why}）",
                                s.control_label(),
                                s.id,
                                info.label()
                            );
                            continue;
                        }
                        polluted += 1;
                        if s.learns() && strikes.add(&cert_key(&s.id), &today) >= CERT_DAYS {
                            jinfo!(
                                journal,
                                "   [淘汰] {} -> 汙染 {}：憑證不符 {why}（第 {CERT_DAYS} 天，加入永久黑名單）",
                                s.id,
                                info.label()
                            );
                            if blacklist.insert(s.id.clone()) {
                                newly_bl.push(format!("{}  # {today} 汙染：{domain} → {}（憑證不符 {why}）", s.id, info.label()));
                            }
                        } else if !s.pinned {
                            jinfo!(
                                journal,
                                "   [今天不用] {} -> 汙染 {}：憑證不符 {why}（再發生一天就列入永久黑名單）",
                                s.id,
                                info.label()
                            );
                        }
                    }
                    // 多家 CDN 的網域、或 3 家以上互相獨立的 DNS 同樣回答：連不上是網站或這條路的問題，不是這台 DNS 的錯
                    // → 照常計分（跟「正常回答也無法驗證」一樣），不記可疑、今天也照用。
                    // 3.4.1 以前是「今天不用」：padavan-tw 3.3.7 一個多家 CDN 的網域就讓 41 台正常的加密 DNS 整天出局
                    Some((SiteCheck::Unverified, why)) if multi_cdn || independent.contains(&k) => {
                        lenient += 1;
                        let basis = if independent.contains(&k) {
                            format!("有 {INDEPENDENT_OPERATORS} 家以上獨立的 DNS 同樣回答")
                        } else {
                            format!("這個網域有 {MULTI_CDN_GROUPS} 家以上業者的回答憑證有效（多家 CDN）")
                        };
                        jinfo!(
                            journal,
                            "   [保留] {} -> {}：{domain} 網站無法驗證（{why}），但{basis}，判為網站或路徑問題，照常計分、不記可疑",
                            s.id,
                            info.label()
                        );
                        s.record(dix, *ms, ips);
                    }
                    Some((SiteCheck::Unverified, why)) => {
                        s.kill(format!("可疑 {domain} (判定為 {}，網站無法驗證 {why})", info.label()));
                        if s.control_like() {
                            jinfo!(
                                journal,
                                "   [{}] {} -> 判出過濾：可疑 {}（網站無法驗證 {why}）",
                                s.control_label(),
                                s.id,
                                info.label()
                            );
                            continue;
                        }
                        suspicious += 1;
                        if s.learns() && strikes.add(&s.id, &today) >= SUSPECT_DAYS && blacklist.insert(s.id.clone()) {
                            jinfo!(
                                journal,
                                "   [淘汰] {} -> 連續 {SUSPECT_DAYS} 天回答無法驗證的位址（加入永久黑名單）",
                                s.id
                            );
                            newly_bl.push(format!(
                                "{}  # {today} 汙染：{domain} → {}（連續 {SUSPECT_DAYS} 天網站無法驗證）",
                                s.id,
                                info.label()
                            ));
                        } else if !s.pinned {
                            jinfo!(
                                journal,
                                "   [今天不用] {} -> {}：{domain} 網站無法驗證（{why}）",
                                s.id,
                                info.label()
                            );
                        }
                    }
                }
            }
            if !newly_bl.is_empty() {
                append_blacklist(&bl_file, &newly_bl);
            }
            jinfo!(
                journal,
                "   -> 第一名 [{}]，有效 {}、封殺 {}、汙染 {polluted}、可疑 {suspicious}、規則外但驗證通過 {rescued}、連不上但照用 {lenient}、逾時 {errors}",
                groups.first().map(|g| g.rep.label()).unwrap_or_else(|| "無法判定".into()),
                ok_n - polluted - suspicious,
                blocked_n
            );
        }

        drop(raw);
        strikes.save();
        let finals: Vec<usize> = verified
            .iter()
            .copied()
            .filter(|i| all[*i].alive && !all[*i].control_like())
            .collect();
        if !finals.iter().any(|i| !all[*i].pinned) {
            bail!("沒有倖存的 DNS，保留昨天的結果");
        }

        // Phase 2：查 DNS 擁有者
        jinfo!(journal, "=== 最終結算：查詢 DNS 擁有者 ===");
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
            .lookup(&*self.asn, &host_ip.iter().flatten().copied().collect::<Vec<_>>(), true)
            .await;
        // 所在地（規格 10 的 6.1）：台灣網段 → ip-api 的國別 → 都沒有；鄰近再看量到的最低延遲
        let tw_nets = self.tw.as_ref().map(|t| t.all());
        let scored_list: Vec<Scored> = finals
            .iter()
            .zip(&host_ip)
            .map(|(&i, ip)| {
                let info = ip.and_then(|ip| owner_info.get(&ip));
                let owner = info.map(|x| x.raw.clone()).unwrap_or_else(|| "Unknown".into());
                let mut s = all[i].scored(owner);
                let in_tw = matches!((&tw_nets, ip), (Some(n), Some(ip)) if n.contains(*ip));
                let cc = info.map(|x| x.cc.as_str()).unwrap_or("");
                (s.region, s.near) = select::classify_region(in_tw, cc, s.min, cfg.near_max_ms);
                s.region_source = select::region_source(in_tw);
                s
            })
            .collect();
        drop(tw_nets);
        // 對照組：判出過濾、沒判出、沒測到（不算淘汰，另外列）
        let outcomes: Vec<(&Srv, (&'static str, &'static str, String))> = all
            .iter()
            .filter(|s| s.protected.is_some())
            .map(|s| (s, protected_outcome(s)))
            .collect();
        // 跨天回歸（3.5.0 A2）：學習檔的 control 記每台最近 30 天；名單裡有、今天沒測（路徑檢查略過、不支援）的記 u
        if let Some(l) = learned.as_mut() {
            let tested: HashMap<&str, char> = outcomes
                .iter()
                .map(|(s, (r, _, _))| {
                    (
                        s.id.as_str(),
                        control_day_char(r, s.protected.as_deref().unwrap_or(""), probe.unusable()),
                    )
                })
                .collect();
            let results: Vec<(String, char)> = protected
                .iter()
                .map(|(spec, _, _)| (spec.clone(), tested.get(spec.as_str()).copied().unwrap_or('u')))
                .fold(Vec::new(), |mut v, x| {
                    if !v.iter().any(|(k, _): &(String, char)| *k == x.0) {
                        v.push(x);
                    }
                    v
                });
            learn_dirty |= l.control_record(today_n, &results);
        }
        let hist_of = |id: &str, c: char| -> String {
            match learned
                .as_ref()
                .filter(|l| l.control_day == today_n)
                .and_then(|l| l.control.get(id))
            {
                Some(h) => h.clone(),
                None => c.to_string(),
            }
        };
        let control: Vec<Value> = outcomes
            .iter()
            .map(|(s, (result, stage, reason))| {
                let expect = s.protected.as_deref().unwrap_or("?");
                let hist = hist_of(&s.id, control_day_char(result, expect, probe.unusable()));
                let recent: String = hist.chars().take(learn::CONTROL_RECENT).collect();
                json!({
                    "id": s.id, "type": s.kind, "expect": expect, "result": result, "reason": reason,
                    "stage": stage, "preflight": s.preflight, "recent": recent,
                    "regress": learn::control_regress(&hist), "expectMet": expect_met(expect, result, stage, s.probe),
                })
            })
            .collect();
        drop(outcomes);
        if !control.is_empty() {
            let n = |r: &str| control.iter().filter(|c| c["result"] == r).count();
            let regress: Vec<&str> = control
                .iter()
                .filter(|c| c["regress"] == true)
                .filter_map(|c| c["id"].as_str())
                .collect();
            jinfo!(
                journal,
                "[對照組] {} 台：判出過濾 {}（資格賽網域被擋 {}）、沒判出 {}、沒測到 {}、回歸 {}（永遠不選、不記可疑、不進黑名單）",
                control.len(),
                n("detected"),
                control
                    .iter()
                    .filter(|c| c["stage"] == "preflight" && c["result"] == "detected")
                    .count(),
                n("passed"),
                n("untested"),
                regress.len()
            );
            // 只報告，不改變今天選出來的上游
            for id in &regress {
                let line = format!("[對照組] {id} 以前判得出過濾，今天沒判出：評測可能判不出這一類了");
                warn!("{line}");
                journal.push(line);
            }
            if let Some((t, m)) = learned
                .as_ref()
                .filter(|l| l.control_day == today_n)
                .and_then(|l| learn::control_overall_drop(l.control.values().map(String::as_str)))
            {
                let line = format!(
                    "[對照組] 今天判出過濾的比例 {}% 比過去 7 天的中位數 {}% 少一半以上：評測網域檔或判斷規則可能改壞了",
                    to_fixed(t * 100.0, 0),
                    to_fixed(m * 100.0, 0)
                );
                warn!("{line}");
                journal.push(line);
            }
            for c in control.iter().filter(|c| c["result"] == "passed") {
                jinfo!(
                    journal,
                    "   沒判出：{}（預期會擋 {}）",
                    c["id"].as_str().unwrap_or(""),
                    c["expect"].as_str().unwrap_or("")
                );
            }
        }
        // 評測歷史（3.5.0 A4）：今天真的測到的一般候選各記一筆，再依歷史升降。走到這裡表示評測成功
        // （沒有任何 DNS 通過資格賽、沒有倖存時前面就結束了，不會記到候選頭上）；路徑檢查略過、今天沒輪到的不在 all 裡
        if let Some(l) = learned.as_mut().filter(|l| today_n >= l.day) {
            // 某一種類型今天整批過不了資格賽（3 個以上、一個都沒過）：多半是這條線路擋了那種協定而路徑檢查沒抓到，不記
            let mut kinds: BTreeMap<&'static str, (usize, usize)> = BTreeMap::new();
            let general = |s: &Srv| !s.pinned && s.protected.is_none();
            for (i, s) in all.iter().enumerate().filter(|(_, s)| general(s)) {
                let e = kinds.entry(s.kind).or_default();
                e.0 += 1;
                e.1 += (pf[i] == Some(Preflight::Pass)) as usize;
            }
            let dead: Vec<&'static str> = kinds.iter().filter(|(_, (n, ok))| *n >= 3 && *ok == 0).map(|(k, _)| *k).collect();
            if !dead.is_empty() {
                jinfo!(
                    journal,
                    "[分級] {} 今天整批過不了資格賽：多半是線路的問題，不記進評測歷史",
                    dead.join("、")
                );
            }
            let tested: Vec<tiers::Tested> = all
                .iter()
                .filter(|s| general(s) && s.tag.tier != Tier::User && !dead.contains(&s.kind))
                .map(|s| tiers::Tested {
                    id: s.id.clone(),
                    manual: s.tag.tier,
                    // 惡意網站探測判出有擋的：今天不選，算沒倖存
                    survived: s.alive && !s.malware_filter,
                    suspect: !s.alive && ["汙染", "可疑"].iter().any(|p| s.fail_reason.starts_with(p)),
                    ms: (s.alive && !s.malware_filter && s.lat_count > 0).then(|| s.avg() as f32),
                    trial_ok: !s.never_ok && cfg.select.auto_types.iter().any(|t| t == s.kind),
                })
                .collect();
            let listed: HashSet<&str> = ids.iter().map(|c| c.id.as_str()).collect();
            let ch = tiers::update_history(&mut l.hist, &tested, today_n, |k| listed.contains(k));
            l.hist_cap(|k| listed.contains(k));
            learn_dirty = true;
            tier_counts.promoted_today = ch.promoted.len();
            tier_counts.demoted_today = ch.demoted.len();
            if ch.any() {
                jinfo!(
                    journal,
                    "[分級] 依近 30 天的評測歷史：升級 {}、降回 {}、降級 {}、恢復 {}、開始試用 {}、結束試用 {}（只影響測不測，不影響選不選）",
                    ch.promoted.len(),
                    ch.unpromoted.len(),
                    ch.demoted.len(),
                    ch.restored.len(),
                    ch.trial_in.len(),
                    ch.trial_out.len()
                );
                for (what, list) in [
                    ("升級", &ch.promoted),
                    ("降級", &ch.demoted),
                    ("恢復", &ch.restored),
                    ("降回", &ch.unpromoted),
                ] {
                    for id in list.iter().take(20) {
                        let h = l.hist.get(id).copied().unwrap_or_default();
                        jinfo!(
                            journal,
                            "   [{what}] {id}：近 30 天測到 {} 天、倖存 {} 天、可疑 {} 天、延遲 {} ±{} ms",
                            h.tested(),
                            h.survived(),
                            h.suspect(),
                            to_fixed(h.ms as f64, 1),
                            to_fixed(h.dv as f64, 1)
                        );
                    }
                }
            }
        }
        let eliminated: Vec<(String, &'static str, String)> = all
            .iter()
            .filter(|s| !s.alive && s.protected.is_none())
            .map(|s| (s.id.clone(), s.kind, s.fail_reason.clone()))
            .collect();
        let issues: HashMap<String, Vec<String>> = all.iter().filter(|s| s.pinned).map(|s| (s.id.clone(), s.issues.clone())).collect();
        // 候選的分級（3.5.0）：固定上游與對照組不算
        let mut by_tier: BTreeMap<&'static str, usize> = BTreeMap::new();
        for s in all.iter().filter(|s| s.selectable()) {
            *by_tier.entry(s.tag.tier.name()).or_default() += 1;
        }
        let counts = json!({ "total": all.len(), "verified": verified.len(), "survivors": finals.len(), "eliminated": eliminated.len(), "protected": control.len(), "byTier": by_tier, "malwareFilter": probe.filtering.len() });
        drop(all);
        ctx.checkpoint().await;

        // Phase 2 / 3 的計算可能要幾秒（候選多時），放到 blocking 執行緒
        let total = universe.len();
        drop(universe);
        let opts = cfg.select.clone();
        let want_reports = out_dir.is_some();
        let tw = self.tw.clone();
        let calc = tokio::task::spawn_blocking(move || compute(scored_list, scored, total, &opts, want_reports, eliminated, tw.as_deref()))
            .await?;
        match calc.tw_domains {
            Some(n) if n >= select::TW_RATE_MIN_DOMAINS => jinfo!(
                journal,
                "  台灣率：{n} 個網域至少有一台回過台灣節點（分母）；覆蓋差在 10% 以內時先挑台灣率高的"
            ),
            Some(n) => jinfo!(journal, "  台灣率：只有 {n} 個網域有台灣節點，樣本太少，不算"),
            None => {}
        }

        let selected: Vec<Value> = calc
            .selection
            .selected
            .iter()
            .map(|p| {
                let s = &calc.finals[p.idx];
                json!({ "id": s.id, "type": s.kind, "owner": s.owner, "avgMs": fixed_num(s.avg, 2), "newItems": p.newly, "reason": p.why, "region": s.region, "regionSource": s.region_source, "near": s.near, "tier": s.tier, "op": s.op, "twRate": s.tw_rate.map(|r| fixed_num(r as f64, 3)), "ecs": s.ecs })
            })
            .collect();
        // 候補（3.5.0 A7）：沒選上、但合格的前幾台（依速度）；執行時可用的自動上游不夠時依序補上
        let spares: Vec<Value> = calc
            .spares
            .iter()
            .map(|&i| {
                let s = &calc.finals[i];
                json!({ "id": s.id, "type": s.kind, "owner": s.owner, "avgMs": fixed_num(s.avg, 2), "newItems": 0, "reason": "候補", "region": s.region, "regionSource": s.region_source, "near": s.near, "tier": s.tier, "op": s.op, "twRate": s.tw_rate.map(|r| fixed_num(r as f64, 3)), "ecs": s.ecs })
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
            "spares": spares,
            "pinned": pinned,
            "counts": counts,
            "blocked": blocked_report,
            "protected": control,
            "tiers": tier_counts.to_json(),
            "probe": probe.to_json(),
            "skippedTypes": skipped.iter().filter(|(k, _)| **k != "blacklist").map(|(k, n)| (k.to_string(), json!(n))).collect::<Map<String, Value>>(),
            "pathSkipped": path_skipped.iter().map(|(k, n)| (k.to_string(), json!(n))).collect::<Map<String, Value>>(),
            "path": path.as_ref().map(|r| { let mut j = r.to_json(); j["policy"] = json!(policy); j }),
            "reportDir": out_dir.as_ref().map(|d| d.display().to_string()),
        });
        // 覆蓋階段的遠近（規格 10 的 6.2）：寫進 judge.log
        let (near_n, far_n) = calc
            .selection
            .selected
            .iter()
            .filter(|p| p.why == "覆蓋")
            .fold(
                (0usize, 0usize),
                |(n, f), p| {
                    if calc.finals[p.idx].near {
                        (n + 1, f)
                    } else {
                        (n, f + 1)
                    }
                },
            );
        jinfo!(
            journal,
            "  覆蓋：鄰近 {near_n} 台、其他 {far_n} 台（{}）",
            if cfg.select.near_first {
                format!(
                    "先挑鄰近的，最低延遲 {} ms 以內或台日港新 {} ms 以內",
                    to_fixed(cfg.near_max_ms, 0),
                    to_fixed(cfg.near_max_ms * 2.0, 0)
                )
            } else {
                "不分遠近".to_string()
            }
        );
        write_json(&self.paths.upstreams_file, &state)?;
        // 學習資料：有變動才寫（每天最多一次）；系統時間倒退時不寫
        if let (Some(l), Some(p), true) = (learned.as_mut(), self.paths.learn_file.as_ref(), learn_dirty) {
            if l.advance(learn::day_of(now)) {
                if let Err(e) = l.save(p) {
                    warn!("寫入評測學習資料失敗：{e}");
                }
            }
        }
        if let Some(d) = &out_dir {
            for (name, body) in &calc.reports {
                report(&d.join(name), body.as_bytes());
            }
            report(&d.join("upstreams.json"), &serde_json::to_vec_pretty(&state).unwrap_or_default());
            if let Some(c) = state["protected"].as_array().filter(|c| !c.is_empty()) {
                // 3.5.0 在最後加 stage、preflight、recent、regress、expectMet（舊的欄位順序不變）
                let mut csv = String::from("dns,type,expect,result,reason,stage,preflight,recent,regress,expectMet\n");
                for x in c {
                    let f = |k: &str| match &x[k] {
                        Value::String(v) => v.replace([',', '\n'], " "),
                        Value::Bool(b) => if *b { "Y" } else { "N" }.to_string(),
                        _ => String::new(),
                    };
                    csv.push_str(&format!(
                        "{},{},{},{},{},{},{},{},{},{}\n",
                        f("id"),
                        f("type"),
                        f("expect"),
                        f("result"),
                        f("reason"),
                        f("stage"),
                        f("preflight"),
                        f("recent"),
                        f("regress"),
                        f("expectMet")
                    ));
                }
                report(&d.join("protected.csv"), csv.as_bytes());
            }
            report(&d.join("judge.log"), journal.text().as_bytes());
        }
        jinfo!(journal, "=== 今日選出的上游 ===");
        for x in state["selected"].as_array().into_iter().flatten() {
            jinfo!(
                journal,
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
        jinfo!(
            journal,
            "  固定上游：{}",
            if pinned_line.is_empty() {
                "無".into()
            } else {
                pinned_line.join("、")
            }
        );
        jinfo!(
            journal,
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
        jinfo!(journal, "[{}] 結束 {}", JOB_NAME, fmt_time(ctx.now_ms()));
        if let (Some(keep), Some(d)) = (&self.keep_last, &out_dir) {
            keep_last_report(d, keep, &journal);
        }
        Ok(state)
    }

    /// 惡意網站探測的自我檢查（3.5.0 A5）：讀 `probe.txt`，挑少數幾台參照（有擋惡意網站的對照組、不過濾的候選，
    /// 都取不同經營者的），每台用一條連線把探測網域問一輪；兩邊結果不同的探測網域才算有效，回傳前 4 個。
    /// 沒設定、沒有探測網域、參照不足、都失效時 `used` 是空的：後面整段不跑
    #[allow(clippy::too_many_arguments)]
    async fn probe_precheck(
        &self,
        ctx: &JobCtx,
        all: &[Srv],
        verified: &[usize],
        pf: &[Option<Preflight>],
        web: &[String],
        pf_domain: &str,
        cfg: &BenchCfg,
        journal: &mut Journal,
    ) -> ProbeRun {
        let mut run = ProbeRun {
            state: "off",
            ..Default::default()
        };
        if !cfg.malware_probe {
            return run;
        }
        let mut exclude: HashSet<String> = web.iter().map(|d| d.trim().to_ascii_lowercase()).collect();
        exclude.insert(pf_domain.to_ascii_lowercase());
        let probes = malware::parse_probes(&self.paths.read_lists("probe.txt"), &exclude);
        run.domains = probes.len();
        if probes.is_empty() {
            run.state = "empty";
            return run;
        }
        // 參照：對照組裡預期會擋惡意網站、資格賽有回答的（不同經營者）；不過濾的用通過資格賽的一般候選（A 級優先、不同經營者）
        let mut ops: HashSet<String> = HashSet::new();
        let controls: Vec<usize> = (0..all.len())
            .filter(|&i| {
                all[i].protected.as_deref().is_some_and(malware::expects_malware)
                    && matches!(pf[i], Some(Preflight::Pass | Preflight::Answered))
            })
            .filter(|&i| ops.insert(all[i].op_key()))
            .take(malware::REF_CONTROLS)
            .collect();
        let mut ops: HashSet<String> = HashSet::new();
        let mut open: Vec<usize> = verified
            .iter()
            .copied()
            .filter(|&i| all[i].selectable() && !all[i].never_ok)
            .collect();
        open.sort_by_key(|&i| all[i].tag.tier != Tier::A);
        let open: Vec<usize> = open
            .into_iter()
            .filter(|&i| ops.insert(all[i].op_key()))
            .take(malware::REF_OPEN)
            .collect();
        if controls.len() < malware::MIN_CONTROL_OPS || open.len() < malware::MIN_OPEN {
            run.state = "no-reference";
            jinfo!(
                journal,
                "[惡意網站探測] 參照不足（有擋惡意網站的對照組 {} 家、不過濾的候選 {} 家；至少要 {} 與 {}）：今天整段不跑、不判斷",
                controls.len(),
                open.len(),
                malware::MIN_CONTROL_OPS,
                malware::MIN_OPEN
            );
            return run;
        }
        let refs: Vec<usize> = controls.iter().chain(&open).copied().collect();
        let ctl_ops: Vec<String> = controls.iter().map(|&i| all[i].op_key()).collect();
        let domains = Arc::new(probes.clone());
        let pause = Arc::new(PauseState::default());
        let jobs: Vec<CollectJob> = refs
            .iter()
            .map(|&i| CollectJob {
                prober: self.prober.clone(),
                up: all[i].up.fresh(),
                domains: domains.clone(),
                ctx: ctx.clone(),
                timeout: cfg.timeout,
                pace: cfg.pace,
                stop_after: Some(cfg.max_timeouts),
                pause: pause.clone(),
            })
            .collect();
        let got = map_limit(jobs, self.effective_conc(cfg).0, |j| j.run()).await;
        run.queries = got.iter().flatten().map(Vec::len).sum();
        let ans = |r: usize, k: usize| probe_ans(got[r].as_ref().and_then(|v| v.get(k)).and_then(Option::as_ref));
        for (k, d) in probes.iter().enumerate() {
            let check = malware::self_check(
                ctl_ops.iter().enumerate().map(|(r, o)| (o.as_str(), ans(r, k))),
                (0..open.len()).map(|r| ans(controls.len() + r, k)),
            );
            match check {
                Ok(what) if run.used.len() < malware::PROBE_USE => {
                    jinfo!(journal, "[惡意網站探測] 自我檢查通過 {d}：{what}");
                    run.used.push(d.clone());
                }
                Ok(_) => jinfo!(journal, "[惡意網站探測] {d} 有效，但已經有 {} 個，這次不用", malware::PROBE_USE),
                Err(why) => jinfo!(journal, "[惡意網站探測] 自我檢查沒過 {d}：{why}。這個網域今天不拿來判斷"),
            }
        }
        if run.used.is_empty() {
            run.state = "invalid";
            let line = format!(
                "[惡意網站探測] {} 個探測網域都沒過自我檢查：今天不判斷任何候選（探測網域可能失效了，請檢查 probe.txt）",
                probes.len()
            );
            warn!("{line}");
            journal.push(line);
        } else {
            run.state = "ok";
        }
        run
    }

    /// 惡意網站探測的判斷（3.5.0 A5）：全部候選都問完之後，同樣的條件用全部的資料再驗一次，加上保險絲。
    /// 判出的一般候選比照對照組（今天不選、不記可疑、不進黑名單）；對照組記下有沒有擋（`expectMet` 用）
    fn probe_judge(&self, all: &mut [Srv], verified: &[usize], answers: Vec<Vec<malware::Ans>>, run: &mut ProbeRun, journal: &mut Journal) {
        let ctl_idx: Vec<usize> = (0..all.len()).filter(|&i| all[i].protected.is_some()).collect();
        let controls: Vec<malware::Control> = ctl_idx
            .iter()
            .map(|&i| malware::Control {
                op: all[i].op_key(),
                malware: all[i].protected.as_deref().is_some_and(malware::expects_malware),
                ans: answers[i].clone(),
            })
            .collect();
        let cand_idx: Vec<usize> = verified.iter().copied().filter(|&i| all[i].selectable()).collect();
        let cands: Vec<Vec<malware::Ans>> = cand_idx.iter().map(|&i| answers[i].clone()).collect();
        run.queries += answers.iter().map(Vec::len).sum::<usize>();
        let v = malware::judge(&controls, &cands);
        for (k, r) in v.valid.iter().enumerate() {
            if let Err(why) = r {
                jinfo!(
                    journal,
                    "[惡意網站探測] {} 全部問完之後失效：{why}。不拿來判斷",
                    run.used.get(k).map(String::as_str).unwrap_or("?")
                );
            }
        }
        run.probed = v.probed;
        run.valid = v.valid_count();
        if v.fuse {
            run.state = "fuse";
            let line = format!(
                "[惡意網站探測] 保險絲：有回答的 {} 個候選裡有 {} 個會被判成「有擋惡意網站」，超過一半——多半是探測網域失效，今天整段作廢、不判斷任何候選",
                v.probed, v.would_flag
            );
            warn!("{line}");
            journal.push(line);
            return;
        }
        if run.valid == 0 {
            run.state = "invalid";
            let line = "[惡意網站探測] 全部問完之後沒有有效的探測網域：今天不判斷任何候選".to_string();
            warn!("{line}");
            journal.push(line);
            return;
        }
        for (c, hit) in ctl_idx.iter().zip(&v.controls) {
            all[*c].probe = *hit;
        }
        for &k in &v.flagged {
            let s = &mut all[cand_idx[k]];
            s.malware_filter = true;
            run.filtering.push(s.id.clone());
            jinfo!(
                journal,
                "   [有擋惡意網站] {}：{} 個以上的探測網域回封鎖。比照對照組：今天不選、不記可疑、不進黑名單；建議移到 protected.txt（filter=malware）",
                s.id,
                malware::MIN_VALID_TO_JUDGE
            );
        }
        jinfo!(
            journal,
            "[惡意網站探測] 有效的探測網域 {} 個{}；有回答的一般候選 {} 個，判出有擋惡意網站 {} 個；對照組擋 {}／沒擋 {}",
            run.valid,
            if run.valid < malware::MIN_VALID_TO_JUDGE {
                format!("（不到 {} 個，只看對照組、不判斷一般候選）", malware::MIN_VALID_TO_JUDGE)
            } else {
                String::new()
            },
            v.probed,
            v.flagged.len(),
            v.controls.iter().filter(|c| **c == Some(true)).count(),
            v.controls.iter().filter(|c| **c == Some(false)).count()
        );
    }

    /// Phase 1 的收集：`verified` 裡的每個候選用自己的連線依序測完 `domains`，測完就關閉連線；
    /// 同時只測 [`effective_conc`](Self::effective_conc) 個。回傳以 `all` 的位置為索引，每個網域一格
    /// （因為逾時太多提早停下的，後面的格子就沒有）
    async fn collect(
        &self,
        ctx: &JobCtx,
        all: &[Srv],
        verified: &[usize],
        domains: &[String],
        cfg: &BenchCfg,
    ) -> Vec<Vec<Option<QueryResult>>> {
        let (conc, room) = self.effective_conc(cfg);
        info!(
            "[Phase 1] {} 個網域 × {} 個候選，同時測 {conc} 個{}（每個候選測完就關閉連線）",
            domains.len(),
            verified.len(),
            match room {
                Some(r) if conc < cfg.conc => format!("（可用記憶體 {} MB，設定是 {}）", r >> 20, cfg.conc),
                _ => String::new(),
            }
        );
        let mut out: Vec<Vec<Option<QueryResult>>> = (0..all.len()).map(|_| Vec::new()).collect();
        let domains: Arc<Vec<String>> = Arc::new(domains.to_vec());
        let pause = Arc::new(PauseState::default());
        let total = verified.len();
        let mut done = 0usize;
        let mut last_log = Instant::now();
        self.set_progress(json!({
            "phase": "collect", "done": 0, "total": total, "domains": domains.len(), "concurrency": conc, "openConnections": 0,
            "text": format!("執行中：開始測 {total} 個候選"),
        }));
        let mut it = verified.iter().copied();
        let mut set = JoinSet::new();
        let spawn = |set: &mut JoinSet<(usize, Vec<Option<QueryResult>>)>, i: usize| {
            let s = &all[i];
            let job = CollectJob {
                prober: self.prober.clone(),
                up: s.up.fresh(),
                domains: domains.clone(),
                ctx: ctx.clone(),
                timeout: cfg.timeout,
                pace: cfg.pace,
                // 固定上游永遠不淘汰，要測完全部網域
                stop_after: if s.pinned { None } else { Some(cfg.max_timeouts) },
                pause: pause.clone(),
            };
            set.spawn(async move { (i, job.run().await) });
        };
        for i in it.by_ref().take(conc) {
            spawn(&mut set, i);
        }
        let mut kept = 0usize;
        while let Some(r) = set.join_next().await {
            if let Ok((i, v)) = r {
                kept += v.len();
                out[i] = v;
            }
            done += 1;
            if let Some(i) = it.next() {
                spawn(&mut set, i);
            }
            let open = set.len().saturating_sub(pause.paused.load(Ordering::Relaxed));
            self.set_progress(json!({
                "phase": "collect", "done": done, "total": total, "domains": domains.len(),
                "concurrency": conc, "openConnections": open, "rawBytes": raw_bytes(kept),
                "text": format!("執行中：測完 {done} / {total} 個候選（開著 {open} 條連線）"),
            }));
            if last_log.elapsed() >= Duration::from_secs(60) {
                last_log = Instant::now();
                info!("   收集中：{done} / {total} 個候選測完（同時 {} 個）", set.len());
            }
        }
        info!("   收集完成：{total} 個候選，開始逐網域判斷");
        out
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
        // 不共用連線的複本：輪到才建立、查完就關閉（不然資格賽的幾百條連線會一直開著）
        let jobs: Vec<(usize, Upstream)> = idx.iter().map(|&i| (i, all[i].up.clone())).collect();
        let prober = self.prober.clone();
        let timeout = cfg.timeout;
        let domain = domain.to_string();
        let conc = self.effective_conc(cfg).0;
        // 進度：資格賽也看得到開著幾條連線（以前要到收集階段才有）
        let total = jobs.len();
        let (open, done) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let progress = self.progress.clone();
        let show = {
            let (open, done) = (open.clone(), done.clone());
            move || {
                let (o, d) = (open.load(Ordering::Relaxed), done.load(Ordering::Relaxed));
                *progress.lock().unwrap() = Some(json!({
                    "phase": "qualify", "done": d, "total": total, "concurrency": conc,
                    "openConnections": o, "rawBytes": 0,
                    "text": format!("執行中：資格賽 {d} / {total}（同時 {o} 個）"),
                }));
            }
        };
        show();
        let res = map_limit(jobs, conc, |(i, up)| {
            let prober = prober.clone();
            let domain = domain.clone();
            let (open, done, show) = (open.clone(), done.clone(), show.clone());
            async move {
                let up = up.fresh();
                open.fetch_add(1, Ordering::Relaxed);
                let r = query(&*prober, &up, &domain, timeout, 1).await;
                drop(up);
                open.fetch_sub(1, Ordering::Relaxed);
                done.fetch_add(1, Ordering::Relaxed);
                show();
                (i, r)
            }
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

/// 對照組一天的結果字元（學習檔的 `control`）
fn day_char(result: &str) -> char {
    match result {
        "detected" => 'd',
        "passed" => 'p',
        _ => 'u',
    }
}

/// 一個候選的資格賽結果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Preflight {
    /// 通過
    Pass,
    /// 有回答，但不是預期的（封殺、答案不對）
    Answered,
    /// 連線錯誤、逾時
    Error,
}

/// 不支援 HTTP/3 的 DoH（3.5.0 A6）：一般候選裡的每個 h3://，依它與它的 https:// 的資格賽結果記一筆。
/// 算一次失敗要三個條件都成立：h3:// 是連線錯誤（不是封殺、不是答案不對）、它的 https:// 通過資格賽、
/// 今天至少有一個 h3:// 連得上（全部都連不上時可能是 QUIC 整條被擋、路徑檢查沒抓到，不冤枉）。
/// 路徑檢查判斷 QUIC 被擋時 h3:// 根本不在候選裡，也就不會記
fn record_h3(l: &mut learn::Learn, all: &[Srv], pf: &[Option<Preflight>], today: u32) -> learn::H3Change {
    use learn::H3Seen;
    let mut change = learn::H3Change::default();
    let h3: Vec<usize> = (0..all.len())
        .filter(|&i| all[i].kind == "doh3" && all[i].selectable() && all[i].id.starts_with("h3://"))
        .collect();
    let quic_ok = h3.iter().any(|&i| matches!(pf[i], Some(Preflight::Pass | Preflight::Answered)));
    let by_id: HashMap<&str, usize> = all.iter().enumerate().map(|(i, s)| (s.id.as_str(), i)).collect();
    for &i in &h3 {
        let seen = match pf[i] {
            Some(Preflight::Error) => {
                let https = format!("https://{}", &all[i].id["h3://".len()..]);
                let https_ok = by_id.get(https.as_str()).is_some_and(|&j| pf[j] == Some(Preflight::Pass));
                if quic_ok && https_ok {
                    H3Seen::Fail
                } else {
                    H3Seen::Neutral
                }
            }
            Some(_) => H3Seen::Ok,
            None => H3Seen::Neutral,
        };
        l.h3_record(&all[i].id, today, seen, &mut change);
    }
    change
}

/// 收集到的原始答案大約佔多少記憶體（每筆：結果本身 + 幾個 IP；估計值，誤差約 ±30%）。
/// 只算原始答案，不含每台上游的歷史、ASN 快取、連線緩衝。放在 `/api/status` 的 `memory.jobs.rawBytes`
fn raw_bytes(entries: usize) -> usize {
    entries * (std::mem::size_of::<Option<QueryResult>>() + 16)
}

/// 收集時的暫停狀態（很多個候選各自暫停，只記一次日誌）
#[derive(Default)]
struct PauseState {
    paused: AtomicUsize,
    announced: AtomicBool,
}

/// 一個候選的收集工作
struct CollectJob {
    prober: Arc<dyn Prober>,
    up: Upstream,
    domains: Arc<Vec<String>>,
    ctx: JobCtx,
    timeout: Duration,
    pace: Duration,
    /// 失敗超過幾次就不用再測（跟判斷時的淘汰規則一樣）；None = 測完全部
    stop_after: Option<u32>,
    pause: Arc<PauseState>,
}

impl CollectJob {
    async fn run(self) -> Vec<Option<QueryResult>> {
        let CollectJob {
            prober,
            mut up,
            domains,
            ctx,
            timeout,
            pace,
            stop_after,
            pause,
        } = self;
        let mut out = Vec::with_capacity(domains.len());
        let mut errors = 0u32;
        let mut last: Option<Instant> = None;
        for d in domains.iter() {
            if ctx.should_defer() {
                // 先關閉連線再等：暫停期間不佔記憶體
                up = up.fresh();
                pause.paused.fetch_add(1, Ordering::Relaxed);
                if !pause.announced.swap(true, Ordering::Relaxed) {
                    info!("[{JOB_NAME}] 系統資源吃緊：關閉評測連線並暫停");
                }
                ctx.wait_while_deferred().await;
                pause.paused.fetch_sub(1, Ordering::Relaxed);
                if pause.announced.swap(false, Ordering::Relaxed) {
                    info!("[{JOB_NAME}] 恢復評測");
                }
                last = None;
            }
            if let Some(t) = last {
                let wait = pace.saturating_sub(t.elapsed());
                if !wait.is_zero() {
                    tokio::time::sleep(wait).await;
                }
            }
            last = Some(Instant::now());
            let mut r = query(&*prober, &up, d, timeout, 1).await;
            let failed = matches!(r.outcome, Outcome::Error(_));
            if let Outcome::Ok(ips) = &mut r.outcome {
                ips.shrink_to_fit();
            }
            out.push(Some(r));
            if failed {
                errors += 1;
                if stop_after.is_some_and(|m| errors > m) {
                    break;
                }
            }
        }
        out
    }
}

struct Calc {
    /// 依延遲排序
    finals: Vec<Scored>,
    /// 台灣率的分母（至少有一台回過台灣 IP 的網域數）；沒有台灣網段資料是 None
    tw_domains: Option<usize>,
    selection: select::Selection,
    /// 候補（`finals` 的位置）
    spares: Vec<usize>,
    reports: Vec<(&'static str, String)>,
}

fn compute(
    mut finals: Vec<Scored>,
    scored_domains: usize,
    total: usize,
    opts: &SelectOpts,
    want_reports: bool,
    eliminated: Vec<(String, &'static str, String)>,
    tw: Option<&crate::geo::TwIp>,
) -> Calc {
    select::extended_metrics(&mut finals, scored_domains);
    // 台灣率（3.5.0 B5）：台灣網段讀不到時不算，選擇跟 3.4.4 一樣
    let tw_domains = tw.map(|t| {
        let nets = t.all();
        select::tw_rates(&mut finals, |ip| nets.contains(IpAddr::V4(Ipv4Addr::from(ip))))
    });
    finals.sort_by(|a, b| a.avg.partial_cmp(&b.avg).unwrap_or(std::cmp::Ordering::Equal));
    let refs: Vec<&Scored> = finals.iter().collect();
    let asn_best = select::best_per_asn(&refs);
    info!("ASN 過濾：{} → {}", finals.len(), asn_best.len());
    let selection = select::select(&refs, &asn_best, total, opts);
    let spares = select::spares(&refs, &asn_best, &selection, opts, select::SPARES);
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
        tw_domains,
        selection,
        spares,
        reports,
    }
}

/// 判斷過程摘要的上限（評測一次幾千行；只留前面這麼多）
const JOURNAL_MAX: usize = 192 * 1024;
/// 另存到持久資料區的每個檔案上限（Flash 上每天寫一次，不要太大）
const KEEP_FILE_MAX: usize = 128 * 1024;

macro_rules! jinfo {
    ($j:expr, $($arg:tt)*) => {{
        let s = format!($($arg)*);
        info!("{s}");
        $j.push(s);
    }};
}
use jinfo;

#[derive(Default)]
struct Journal {
    lines: Vec<String>,
    bytes: usize,
    dropped: usize,
}

impl Journal {
    fn push(&mut self, s: String) {
        if self.bytes + s.len() < JOURNAL_MAX {
            self.bytes += s.len() + 1;
            self.lines.push(s);
        } else {
            self.dropped += 1;
        }
    }
    fn text(&self) -> String {
        let mut t = self.lines.join("\n");
        if self.dropped > 0 {
            t.push_str(&format!("\n…（後面還有 {} 行，見系統記錄）", self.dropped));
        }
        t.push('\n');
        t
    }
}

/// 最近一次評測的摘要另存一份（judge.log、eliminated.csv、upstreams.json，各自截到上限）
fn keep_last_report(out_dir: &Path, keep: &Path, journal: &Journal) {
    let cut = |b: Vec<u8>| -> Vec<u8> {
        if b.len() <= KEEP_FILE_MAX {
            return b;
        }
        let mut end = KEEP_FILE_MAX;
        while end > 0 && (b[end] & 0xc0) == 0x80 {
            end -= 1; // 不切在 UTF-8 字元中間
        }
        let mut v = b[..end].to_vec();
        v.extend_from_slice("\n…（已截斷）\n".as_bytes());
        v
    };
    if let Err(e) = std::fs::create_dir_all(keep) {
        warn!("最近一次評測報表另存失敗（{}）：{e}", keep.display());
        return;
    }
    report(&keep.join("judge.log"), &cut(journal.text().into_bytes()));
    for name in ["eliminated.csv", "upstreams.json", "protected.csv"] {
        if let Ok(b) = std::fs::read(out_dir.join(name)) {
            report(&keep.join(name), &cut(b));
        }
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

#[cfg(test)]
mod list_merge_tests {
    use super::*;

    #[test]
    fn user_and_default_lists_are_merged() {
        let root = std::env::temp_dir().join(format!("kuroshio-lists-{}", std::process::id()));
        let (user, shipped) = (root.join("etc"), root.join("share"));
        std::fs::create_dir_all(&user).unwrap();
        std::fs::create_dir_all(&shipped).unwrap();
        std::fs::write(
            user.join("dohlist.txt"),
            "# 自己加的\nhttps://mine.example/dns-query\nhttps://Both.example/dns-query/\n",
        )
        .unwrap();
        std::fs::write(
            shipped.join("dohlist.txt"),
            "\u{feff}https://both.example/dns-query\nhttps://new.example/dns-query  # 新版\n",
        )
        .unwrap();
        let mut p = BenchPaths::from_config(&json!({}), &root.join("state"), &root);
        p.list_dir = user.clone();
        p.default_list_dir = Some(shipped.clone());
        assert_eq!(
            p.read_lists("dohlist.txt"),
            vec![
                "https://mine.example/dns-query",
                "https://Both.example/dns-query/",
                "https://new.example/dns-query  # 新版"
            ]
        );
        // 使用者沒有這個檔：只用程式附帶的
        std::fs::write(shipped.join("dotlist.txt"), "tls://dot.example\n").unwrap();
        assert_eq!(p.read_lists("dotlist.txt"), vec!["tls://dot.example"]);
        let _ = std::fs::remove_dir_all(&root);
    }

    fn two_lists(name: &str) -> (PathBuf, BenchPaths) {
        let root = std::env::temp_dir().join(format!("kuroshio-tags-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (user, shipped) = (root.join("etc"), root.join("share"));
        std::fs::create_dir_all(&user).unwrap();
        std::fs::create_dir_all(&shipped).unwrap();
        let mut p = BenchPaths::from_config(&json!({}), &root.join("state"), &root);
        p.list_dir = user;
        p.default_list_dir = Some(shipped);
        p.community_candidates = Some(root.join("state/community/upstream-candidates.json"));
        (root, p)
    }

    #[test]
    fn user_list_without_tags_is_user_tier() {
        let (root, p) = two_lists("user");
        let user = p.list_dir.clone();
        std::fs::write(
            user.join("dohlist.txt"),
            "https://mine.example.com/dns-query\nhttps://tagged.example.com/dns-query  # tier=B op=Mine\n",
        )
        .unwrap();
        std::fs::write(user.join("iplist.txt"), "192.0.2.7\n").unwrap();
        let l = p.read_lists_tagged("dohlist.txt");
        assert_eq!(l[0].1.tier, Tier::User);
        assert_eq!(l[1].1.tier, Tier::B, "使用者自己寫了標記：照它的");
        assert_eq!(l[1].1.op, "Mine");
        assert_eq!(p.read_lists_tagged("iplist.txt")[0].1.tier, Tier::User);
        // 只有一個名單（list_dir 就是程式附帶的）：沒標記的是 Unknown，不是 User
        let mut single = p.clone();
        single.default_list_dir = None;
        assert_eq!(single.read_lists_tagged("dohlist.txt")[0].1.tier, Tier::Unknown);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn default_tag_kept_when_user_repeats_entry() {
        let (root, p) = two_lists("repeat");
        std::fs::write(
            p.list_dir.join("dohlist.txt"),
            "https://Both.example.com/dns-query/\nhttps://own.example.net/dns-query  # tier=B\n",
        )
        .unwrap();
        std::fs::write(
            p.default_list_dir.as_ref().unwrap().join("dohlist.txt"),
            "# ---- A 級 ----\nhttps://both.example.com/dns-query  # tier=A op=Example_Net ms=3.1\nhttps://own.example.net/dns-query  # tier=A op=Other\nhttps://new.example.com/dns-query  # op=New\n",
        )
        .unwrap();
        let l = p.read_lists_tagged("dohlist.txt");
        let ids: Vec<&str> = l.iter().map(|(i, _)| i.as_str()).collect();
        assert_eq!(
            ids,
            [
                "https://Both.example.com/dns-query/",
                "https://own.example.net/dns-query",
                "https://new.example.com/dns-query"
            ],
            "網址用使用者那一筆、去重"
        );
        assert_eq!(l[0].1.tier, Tier::A, "使用者沒寫標記：用預設名單的");
        assert_eq!(l[0].1.op, "Example_Net");
        assert_eq!(l[1].1.tier, Tier::B, "使用者寫了標記：不被預設名單蓋掉");
        assert_eq!(l[1].1.op, "");
        assert_eq!(l[2].1.tier, Tier::A, "分段行的分級");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn h3_inherits_https_tag() {
        let (root, mut p) = two_lists("h3");
        p.default_list_dir = None;
        std::fs::write(
            p.list_dir.join("dohlist.txt"),
            "https://dns.example.com/dns-query  # tier=A op=Example_Net ecs=1\n",
        )
        .unwrap();
        std::fs::write(
            p.list_dir.join("iplist.txt"),
            "# ---- A 級 ----\n# A Example_Net（AS64500）TW 3.9 ms\n192.0.2.1\n",
        )
        .unwrap();
        let (c, _) = candidate_ids(&p);
        let get = |id: &str| c.iter().find(|x| x.id == id).unwrap_or_else(|| panic!("{id}: {c:?}")).tag.clone();
        let https = get("https://dns.example.com/dns-query");
        assert_eq!(https.tier, Tier::A);
        assert_eq!(get("h3://dns.example.com/dns-query"), https);
        let udp = get("192.0.2.1");
        assert_eq!((udp.tier, udp.op.as_str(), udp.ms), (Tier::A, "Example_Net", Some(3.9)));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn shared_candidates_are_tier_b() {
        let (root, mut p) = two_lists("shared");
        p.default_list_dir = None;
        std::fs::write(p.list_dir.join("dohlist.txt"), "https://dns.example.com/dns-query  # tier=A\n").unwrap();
        let f = p.community_candidates.clone().unwrap();
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        let ids = [
            "https://dns.example.com/dns-query",
            "https://friend.example.net/dns-query",
            "udp://192.0.2.53",
        ];
        std::fs::write(&f, serde_json::to_vec(&json!({ "ids": ids })).unwrap()).unwrap();
        let (c, n) = candidate_ids(&p);
        assert_eq!(n, 3);
        let tier = |id: &str| c.iter().find(|x| x.id == id).map(|x| x.tag.tier);
        assert_eq!(tier("https://dns.example.com/dns-query"), Some(Tier::A), "名單已經有的照名單");
        assert_eq!(tier("https://friend.example.net/dns-query"), Some(Tier::B));
        assert_eq!(tier("h3://friend.example.net/dns-query"), Some(Tier::B));
        assert_eq!(tier("192.0.2.53"), Some(Tier::B));
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod asn_cache_tests {
    use super::*;

    /// 記下每次被問了哪些位址；`offline` 時什麼都不回
    struct Counting {
        calls: Mutex<Vec<Vec<Ipv4Addr>>>,
        offline: bool,
    }

    impl AsnSource for Counting {
        fn lookup(&self, ips: Vec<Ipv4Addr>) -> BoxFuture<Vec<(Ipv4Addr, AsnInfo)>> {
            self.calls.lock().unwrap().push(ips.clone());
            let out = if self.offline {
                Vec::new()
            } else {
                ips.into_iter()
                    .map(|ip| (ip, AsnInfo::from_ip_api("Example Net", "", "AS64500 Example", "JP")))
                    .collect()
            };
            Box::pin(async move { out })
        }
    }

    fn v4(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn asn_cache_reads_old_format_and_backfills_cc() {
        let root = std::env::temp_dir().join(format!("kuroshio-asncc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mut p = BenchPaths::from_config(&json!({}), &root.join("state"), &root);
        p.out_root = Some(root.join("out"));
        std::fs::create_dir_all(root.join("out")).unwrap();
        // 3.3.7 的快取：沒有 cc
        std::fs::write(
            root.join("out/cidr_cache.json"),
            r#"{"198.51":{"raw":"Old_Net__AS64501_Old","keywords":["old","as64501"]},"203.0":{"raw":"Other__AS64502","keywords":["other"]}}"#,
        )
        .unwrap();
        for offline in [false, true] {
            let mut c = AsnCache::load(&p);
            assert_eq!(c.map.len(), 2, "舊格式讀得進來");
            assert_eq!(c.map["198.51"].cc, "");
            let src = Counting {
                calls: Mutex::new(Vec::new()),
                offline,
            };
            // 汙染判斷那邊（want_cc = false）不補查
            let r = c.lookup(&src, &[v4("198.51.100.1"), v4("203.0.113.1")], false).await;
            assert_eq!(r[&v4("198.51.100.1")].raw, "Old_Net__AS64501_Old");
            assert!(src.calls.lock().unwrap().is_empty());
            // 決選的上游位址（want_cc）：沒有國別的 /16 補查一次（同一個 /16 只送一個代表）
            let r = c.lookup(&src, &[v4("198.51.100.1"), v4("198.51.100.2")], true).await;
            assert_eq!(*src.calls.lock().unwrap(), vec![vec!["198.51.100.1".parse::<Ipv4Addr>().unwrap()]]);
            let got = &r[&v4("198.51.100.1")];
            if offline {
                // 查不到：留著舊資料、國別是空的，不算失敗
                assert_eq!(got.raw, "Old_Net__AS64501_Old");
                assert_eq!(got.cc, "");
                assert!(!c.dirty);
            } else {
                assert_eq!(got.cc, "JP");
                assert!(c.dirty);
            }
            // 同一次執行不重複補查
            c.lookup(&src, &[v4("198.51.100.3")], true).await;
            assert_eq!(src.calls.lock().unwrap().len(), 1);
            // 還沒補查過的另一個 /16 照樣補一次
            c.lookup(&src, &[v4("203.0.113.9")], true).await;
            assert_eq!(src.calls.lock().unwrap().len(), 2);
            // 存檔：有國別的才多 "cc"，2.x 的兩個鍵不動
            let f = root.join(format!("saved-{offline}.json"));
            c.save(&f).unwrap();
            let v: Value = serde_json::from_slice(&std::fs::read(&f).unwrap()).unwrap();
            assert_eq!(v["198.51"].get("cc").is_some(), !offline);
            assert!(v["198.51"]["raw"].is_string() && v["198.51"]["keywords"].is_array());
        }
        // 這次執行查不到的 /16：want_cc 時也不重問
        let mut c = AsnCache::load(&p);
        let src = Counting {
            calls: Mutex::new(Vec::new()),
            offline: true,
        };
        c.lookup(&src, &[v4("192.0.2.1")], false).await;
        c.lookup(&src, &[v4("192.0.2.1")], true).await;
        assert_eq!(src.calls.lock().unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod shared_tests {
    use super::*;

    #[test]
    fn shared_candidates_are_capped() {
        let d = std::env::temp_dir().join(format!("kuroshio-bench-shared-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let ids: Vec<String> = (0..300).map(|i| format!("https://dns{i}.example.net/dns-query")).collect();
        let f = d.join("upstream-candidates.json");
        std::fs::write(&f, serde_json::to_vec(&serde_json::json!({ "ids": ids })).unwrap()).unwrap();
        let paths = BenchPaths {
            list_dir: d.join("lists"),
            out_root: None,
            upstreams_file: d.join("upstreams.json"),
            community_candidates: Some(f),
            default_list_dir: None,
            blacklist_file: None,
            learn_file: None,
        };
        let (_, n) = candidate_ids(&paths);
        assert_eq!(n, MAX_SHARED, "好友的上游候選最多 100 個");
        let _ = std::fs::remove_dir_all(&d);
    }
}
