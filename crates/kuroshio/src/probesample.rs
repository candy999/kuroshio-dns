//! 惡意網站探測的網域從這台已經下載的惡意類過濾清單抽樣（3.5.0 F10，規格 11 第 6 節）
//!
//! A5 的探測網域原本只有人工確認過的 `probe.txt`，但這份名單一直是空的（沒有人工確認過的網域），探測整段沒跑。
//! 使用者定案：**不在 repo 放固定名單**，每次評測從這台已經下載的惡意類清單抽。
//!
//! - 誰可以抽：[`crate::filtering::FilterService::probe_sources`]（`filter.lists[].probe`；沒寫時惡意類、啟用中、
//!   不是 TW165／TWNIC-RPZ／新註冊網域／繞過防護）。
//! - 怎麼抽：串流解壓本機副本，水塘抽樣留 [`SAMPLE_MAX`] 個；只收單純的網域規則（[`simple_domain`]）。
//! - 不抽的情況（記一行 INFO，評測照樣跑、只用 `probe.txt`）：記憶體壓力不是 Normal、清單被記憶體控制停用中、
//!   沒有本機副本也沒有下載時順便存的樣本（**不為了抽樣多下載**）。
//! - 沒有本機副本的清單（3.5.1，小 Flash 存不下威脅情資清單）：過濾服務本來就要下載它來載入，**下載時順便**
//!   用 [`LineSampler`] 串流抽 [`SNAP_MAX`] 個，存成快照目錄的 [`SNAP_FILE`]（幾 KB）；7 天內不重抽
//!   （[`SNAP_REFRESH_SECS`]），30 天內的拿來用（[`SNAP_USE_SECS`]）。不另外下載、不存整份清單。
//! - 排除：評測網域（`web.txt`）、資格賽網域、內建一定通過的服務（F11）、`resolver.keepNames`。
//! - 抽到的放進傳給評測的那一份設定的 `benchmark._probeSample`（[`attach`]；底線開頭＝內部用，不存檔、
//!   `/api/config` 看不到），子程序合併 `probe.txt`、先確認還解析得到，再照 A5 的三層保護判斷
//!   （`kuroshio_jobs::benchmark::malware`）。
//! - 抽到的網域不寫進一般日誌（只在 DEBUG）：`judge.log` 與日誌會被回報、貼出來。
//!
//! 在主程式啟動評測前做一次（解壓一份幾百 KB 的副本），記憶體只有水塘的 [`SAMPLE_MAX`] 個（60 個）字串。
//! 下載時順便抽的那份：記憶體是水塘的 [`SNAP_MAX`] 個字串加一行的緩衝（最多 [`NAME_MAX`] + 8 bytes）。

use crate::filtering::ProbeSource;
use kuroshio_config::get;
use kuroshio_jobs::benchmark::{malware::SAMPLE_MAX, ProbeSample, PROBE_SAMPLE_KEY};
use kuroshio_jobs::{BenchPaths, JobCtx};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::io::{BufRead, BufReader};
use std::sync::Arc;
use tracing::{debug, info};

/// 抽樣的網域最長幾個字元
pub const NAME_MAX: usize = 100;

/// 一行清單規則是不是「單純的網域規則」，是的話回傳網域（小寫）。
///
/// 收：`||example.com^`、只有網域的一行（`example.com`）。
/// 不收：註解、例外規則（`@@`）、有修飾（`$`）、有萬用字元或路徑、正規表示式、hosts 格式、IP、只有一段、
/// 超過 [`NAME_MAX`] 個字元、不是合理主機名稱的字元
pub fn simple_domain(line: &str) -> Option<String> {
    let l = line.trim();
    let d = if let Some(rest) = l.strip_prefix("||") {
        rest.strip_suffix('^')?
    } else {
        l
    };
    let d = d.strip_suffix('.').unwrap_or(d);
    if d.is_empty() || d.len() > NAME_MAX || !d.contains('.') {
        return None;
    }
    if !d.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.') {
        return None;
    }
    // 不配置 Vec：下載時順便抽樣（[`LineSampler`]）每一行都會走到這裡
    if d.split('.')
        .any(|p| p.is_empty() || p.len() > 63 || p.starts_with('-') || p.ends_with('-'))
    {
        return None;
    }
    // IP（`192.0.2.1`）與最後一段全是數字的都不是網域
    if d.rsplit('.').next().is_some_and(|t| t.bytes().all(|b| b.is_ascii_digit())) {
        return None;
    }
    Some(d.to_ascii_lowercase())
}

/// 水塘抽樣：不管清單多長，只留 `cap` 個，每一筆被留下的機會一樣
pub struct Reservoir {
    cap: usize,
    seen: u64,
    items: Vec<String>,
    rng: u64,
}

impl Reservoir {
    pub fn new(cap: usize, seed: u64) -> Reservoir {
        Reservoir {
            cap,
            seen: 0,
            items: Vec::with_capacity(cap),
            // xorshift 的狀態不能是 0
            rng: seed | 1,
        }
    }

    fn next(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub fn offer(&mut self, name: String) {
        if self.cap == 0 || self.items.contains(&name) {
            return;
        }
        self.offer_unchecked(name);
    }

    /// 同 [`offer`](Self::offer)，但不檢查重複（一份清單裡的網域本來就不重複；下載時順便抽樣每一行都走到這裡，
    /// 不要每一行都跟水塘裡的比一次）。重複的在 [`into_items`](Self::into_items) 之後自己去掉
    fn offer_unchecked(&mut self, name: String) {
        if self.cap == 0 {
            return;
        }
        self.seen += 1;
        if self.items.len() < self.cap {
            self.items.push(name);
            return;
        }
        let j = (self.next() % self.seen) as usize;
        if j < self.cap {
            self.items[j] = name;
        }
    }

    pub fn into_items(self) -> Vec<String> {
        self.items
    }
}

/// 下載時順便抽的樣本存在快照目錄的這個檔（3.5.1）
pub const SNAP_FILE: &str = "probe-sample.json";
/// 每份清單存幾個：評測每次從這裡再抽 [`SAMPLE_MAX`] 個，存兩倍，每天抽到的才不會都一樣（約 3 KB）
pub const SNAP_MAX: usize = 2 * SAMPLE_MAX;
/// 存的樣本滿 7 天，下一次下載這份清單時重抽（Flash 上一週最多寫一次）
pub const SNAP_REFRESH_SECS: u64 = 7 * 86400;
/// 存的樣本 30 天內拿來用（清單一直沒重新下載、例如一直回 304 時，內容本來就沒變）
pub const SNAP_USE_SECS: u64 = 30 * 86400;
/// 最多存幾份清單的樣本（只留目前設定裡可以抽的）
pub const SNAP_LISTS_MAX: usize = 8;
/// 檔案超過這個大小就不讀（正常是幾 KB）
pub const SNAP_FILE_MAX: usize = 64 * 1024;

/// 一份清單下載時順便抽的樣本
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SnapList {
    /// 抽的時間（Unix 秒）
    pub at: u64,
    pub names: Vec<String>,
}

impl SnapList {
    /// 還能不能用：30 天內；時間在未來超過一天（時鐘曾經跳到很遠的未來）的不用
    pub fn usable(&self, now: u64) -> bool {
        !self.names.is_empty() && self.at <= now.saturating_add(86400) && now.saturating_sub(self.at) <= SNAP_USE_SECS
    }
}

/// [`SNAP_FILE`] 的內容：清單網址 → 樣本。
/// 格式：`{ "v": 1, "lists": { "<網址>": { "at": Unix 秒, "names": [...] } } }`
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Snaps(pub BTreeMap<String, SnapList>);

impl Snaps {
    /// 讀檔的內容：格式不對的整份不要；每個網域再檢查一次（[`simple_domain`]），每份最多 [`SNAP_MAX`] 個、
    /// 最多 [`SNAP_LISTS_MAX`] 份
    pub fn parse(b: &[u8]) -> Snaps {
        if b.len() > SNAP_FILE_MAX {
            return Snaps::default();
        }
        let Ok(v) = serde_json::from_slice::<Value>(b) else {
            return Snaps::default();
        };
        let mut out = BTreeMap::new();
        for (url, l) in v["lists"].as_object().into_iter().flatten().take(SNAP_LISTS_MAX) {
            let Some(at) = l["at"].as_u64() else { continue };
            let mut names: Vec<String> = Vec::new();
            for n in l["names"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                if let Some(d) = simple_domain(n).filter(|d| !names.contains(d)) {
                    names.push(d);
                }
                if names.len() >= SNAP_MAX {
                    break;
                }
            }
            if !names.is_empty() {
                out.insert(url.clone(), SnapList { at, names });
            }
        }
        Snaps(out)
    }

    pub fn to_json(&self) -> Vec<u8> {
        let lists: serde_json::Map<String, Value> = self
            .0
            .iter()
            .map(|(u, l)| (u.clone(), serde_json::json!({ "at": l.at, "names": l.names })))
            .collect();
        serde_json::to_vec(&serde_json::json!({ "v": 1, "lists": lists })).unwrap_or_default()
    }

    /// 這份清單這次下載要不要順便抽：沒有樣本、滿 7 天、或時間在未來（時鐘曾經跳到很遠的未來）
    pub fn due(&self, url: &str, now: u64) -> bool {
        match self.0.get(url) {
            None => true,
            Some(l) => l.at > now.saturating_add(86400) || now.saturating_sub(l.at) >= SNAP_REFRESH_SECS,
        }
    }

    /// 換上一份清單的新樣本，同時拿掉已經不在 `keep`（目前可以抽的清單網址）裡的。抽不到網域時不換（留著舊的）
    pub fn put(&mut self, url: &str, l: SnapList, keep: &[&str]) {
        self.0.retain(|u, _| keep.contains(&u.as_str()));
        if l.names.is_empty() || !keep.contains(&url) {
            return;
        }
        self.0.insert(url.to_string(), l);
        while self.0.len() > SNAP_LISTS_MAX {
            let oldest = self.0.iter().min_by_key(|(_, l)| l.at).map(|(u, _)| u.clone());
            match oldest {
                Some(u) => self.0.remove(&u),
                None => break,
            };
        }
    }
}

/// 下載清單時順便抽樣（3.5.1）：一段一段收下載的內容，切成行、只收單純的網域規則，水塘留 [`SNAP_MAX`] 個。
/// 記憶體：水塘加一行的緩衝（太長的行直接跳過，不會整份放進來）
pub struct LineSampler {
    res: Reservoir,
    line: Vec<u8>,
    /// 這一行已經太長：跳到下一個換行
    skip: bool,
}

impl LineSampler {
    pub fn new(seed: u64) -> LineSampler {
        LineSampler {
            res: Reservoir::new(SNAP_MAX, seed),
            line: Vec::with_capacity(NAME_MAX + 8),
            skip: false,
        }
    }

    pub fn feed(&mut self, mut chunk: &[u8]) {
        while !chunk.is_empty() {
            let (part, rest, end) = match chunk.iter().position(|&b| b == b'\n') {
                Some(p) => (&chunk[..p], &chunk[p + 1..], true),
                None => (chunk, &chunk[chunk.len()..], false),
            };
            if !self.skip {
                if self.line.len() + part.len() > NAME_MAX + 8 {
                    // 太長的行不會是單純的網域規則
                    self.skip = true;
                    self.line.clear();
                } else {
                    self.line.extend_from_slice(part);
                }
            }
            if end {
                self.end_line();
            }
            chunk = rest;
        }
    }

    fn end_line(&mut self) {
        if !self.skip {
            if let Some(d) = std::str::from_utf8(&self.line).ok().and_then(simple_domain) {
                self.res.offer_unchecked(d);
            }
        }
        self.line.clear();
        self.skip = false;
    }

    /// 抽到的（不重複）。最後一行沒有換行也算
    pub fn finish(mut self) -> Vec<String> {
        if !self.line.is_empty() {
            self.end_line();
        }
        let mut seen = HashSet::new();
        self.res.into_items().into_iter().filter(|d| seen.insert(d.clone())).collect()
    }
}

/// 隨機種子（時間＋行程編號）
pub fn seed_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
        ^ ((std::process::id() as u64) << 32)
}

/// 從一份副本（zstd）串流讀出單純的網域規則交給 `f`。回傳讀到幾筆；打不開、格式錯誤時是 Err（讀到的照樣算）
fn read_copy(path: &std::path::Path, f: &mut dyn FnMut(String)) -> Result<u64, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("打不開本機副本：{e}"))?;
    let dec = zstd::stream::read::Decoder::new(file).map_err(|e| format!("本機副本格式錯誤：{e}"))?;
    let mut r = BufReader::with_capacity(64 * 1024, dec);
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    let mut n = 0u64;
    loop {
        buf.clear();
        match r.read_until(b'\n', &mut buf) {
            Ok(0) => return Ok(n),
            Ok(_) => {
                // 太長的行不會是單純的網域規則
                if buf.len() > NAME_MAX + 8 {
                    continue;
                }
                let Ok(l) = std::str::from_utf8(&buf) else { continue };
                if let Some(d) = simple_domain(l) {
                    n += 1;
                    f(d);
                }
            }
            Err(e) => return Err(format!("本機副本讀到一半出錯：{e}")),
        }
    }
}

/// 抽樣（純函式，不下載、不重建；只讀已經在磁碟上的副本）。
///
/// - `normal`：記憶體壓力是 Normal（跟背景工作延後同一個訊號）；不是的話整個跳過。
/// - `exclude`：不收的網域（評測網域、資格賽網域、內建服務、`resolver.keepNames`）。
/// - 沒有副本的清單：用下載時順便存的樣本（[`SnapList::usable`]，3.5.1）；也沒有的跳過（記一行 INFO）。
///   停用中的清單不讀副本（解壓要時間與記憶體），有樣本時照用（只有幾 KB、已經在記憶體裡）。
/// - `now`：Unix 秒（樣本是不是太舊）
pub fn sample(sources: &[ProbeSource], normal: bool, exclude: &dyn Fn(&str) -> bool, seed: u64, now: u64) -> ProbeSample {
    let skip = |why: String| {
        info!("惡意網站探測：{why}，這次不從清單抽樣（評測照樣跑，只用 probe.txt）");
        ProbeSample {
            skipped: Some(why),
            ..Default::default()
        }
    };
    if sources.is_empty() {
        return skip("沒有可以抽樣的清單（啟用中的惡意類清單，TW165、TWNIC-RPZ、新註冊網域、繞過防護不抽）".into());
    }
    if !normal {
        return skip("記憶體吃緊".into());
    }
    let mut res = Reservoir::new(SAMPLE_MAX, seed);
    let mut lists = 0usize;
    let mut why_not: Vec<String> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    for s in sources {
        let snap = s.snap.as_ref().filter(|l| l.usable(now));
        let copy = s.copy.as_ref().filter(|_| !s.unloaded);
        let Some(path) = copy else {
            if let Some(l) = snap {
                // 沒有副本（小 Flash 存不下）、或停用中：用下載時順便抽的樣本，不讀、不下載整份
                let mut offered = 0u64;
                for d in l.names.iter().filter(|d| !exclude(d)) {
                    offered += 1;
                    res.offer(d.clone());
                }
                let days = now.saturating_sub(l.at) / 86400;
                info!(
                    "惡意網站探測：清單「{}」{}，用 {days} 天前下載時順便抽的 {} 個網域",
                    s.name,
                    if s.unloaded { "停用中" } else { "沒有本機副本" },
                    l.names.len()
                );
                notes.push(format!("「{}」用 {days} 天前下載時順便抽的 {} 個", s.name, l.names.len()));
                if offered > 0 {
                    lists += 1;
                }
                continue;
            }
            if s.unloaded {
                info!("惡意網站探測：清單「{}」被記憶體控制停用中，這次不從它抽樣", s.name);
                why_not.push(format!("「{}」停用中", s.name));
            } else {
                info!(
                    "惡意網站探測：清單「{}」沒有本機副本（不為了抽樣下載；下次下載這份清單時順便抽），這次不從它抽樣",
                    s.name
                );
                why_not.push(format!("「{}」沒有本機副本，也還沒有下載時順便抽的樣本", s.name));
            }
            continue;
        };
        let mut offered = 0u64;
        let r = read_copy(path, &mut |d| {
            if !exclude(&d) {
                offered += 1;
                res.offer(d);
            }
        });
        if let Err(e) = r {
            info!("惡意網站探測：清單「{}」{e}，這次不從它抽樣", s.name);
            why_not.push(format!("「{}」副本讀不到", s.name));
            continue;
        }
        debug!("惡意網站探測：清單「{}」有 {offered} 個可以抽的網域", s.name);
        if offered > 0 {
            lists += 1;
        }
    }
    let names = res.into_items();
    if names.is_empty() {
        let why = if why_not.is_empty() {
            "清單裡沒有單純的網域規則".to_string()
        } else {
            why_not.join("、")
        };
        return skip(why);
    }
    info!("惡意網站探測：從 {lists} 份惡意類清單抽了 {} 個網域，交給每日評測", names.len());
    for d in &names {
        debug!("惡意網站探測：抽到 {d}");
    }
    ProbeSample {
        names,
        lists,
        skipped: (!why_not.is_empty()).then(|| why_not.join("、")),
        note: (!notes.is_empty()).then(|| notes.join("、")),
    }
}

/// 這次評測要不要抽樣：`benchmark.malwareProbe` 與 `benchmark.probeSample` 都開著
pub fn wanted(cfg: &Value) -> bool {
    let on = |k: &str| kuroshio_config::chain::flex_bool(get(cfg, k), true).0;
    on("benchmark.malwareProbe") && on("benchmark.probeSample")
}

/// 傳給評測的那一份設定：原本的設定加上 `benchmark._probeSample`（不動原本的那一份）
pub fn attach(cfg: &Value, s: &ProbeSample) -> Value {
    let mut c = cfg.clone();
    if !c.get("benchmark").is_some_and(Value::is_object) {
        c["benchmark"] = serde_json::json!({});
    }
    c["benchmark"][PROBE_SAMPLE_KEY] = s.to_json();
    c
}

/// 不收的網域：評測網域、資格賽網域、內建一定通過的服務（F11）、`resolver.keepNames`
pub fn excluder(cfg: &Value, paths: &BenchPaths) -> impl Fn(&str) -> bool {
    let web: HashSet<String> = paths
        .read_lists("web.txt")
        .iter()
        .filter_map(|l| l.split_whitespace().next())
        .map(|d| d.trim_end_matches('.').to_ascii_lowercase())
        .chain(std::iter::once(kuroshio_jobs::benchmark::PREFLIGHT_DOMAIN.to_string()))
        .collect();
    let keep: Vec<String> = get(cfg, "resolver.keepNames")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(|s| s.trim().trim_matches('.').to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    move |d: &str| {
        web.contains(d)
            || kuroshio_net::comm::kind_of(d).is_some()
            || keep
                .iter()
                .any(|k| d == k || d.strip_suffix(k.as_str()).is_some_and(|p| p.ends_with('.')))
    }
}

/// 評測開始前（主程式）：要抽樣的話從目前的過濾服務抽，回傳帶著 `_probeSample` 的 `ctx`；不用抽的話原樣回傳
pub async fn prepare(ctx: JobCtx, paths: &BenchPaths) -> JobCtx {
    if !wanted(&ctx.cfg) {
        return ctx;
    }
    let sources = crate::filtering::current().map(|f| f.probe_sources()).unwrap_or_default();
    let normal = crate::app::pressure() == crate::sysinfo::Pressure::Normal;
    let ex = excluder(&ctx.cfg, paths);
    let seed = seed_now();
    let now = crate::persist::now_secs();
    // 解壓一份幾百 KB 的副本：在 blocking 執行緒做，不卡住查詢
    let s = tokio::task::spawn_blocking(move || sample(&sources, normal, &ex, seed, now))
        .await
        .unwrap_or_default();
    let mut ctx = ctx;
    ctx.cfg = Arc::new(attach(&ctx.cfg, &s));
    ctx
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("kuroshio-probesample-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn copy(dir: &std::path::Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(format!("{name}.txt.zst"));
        std::fs::write(&p, zstd::encode_all(body.as_bytes(), 3).unwrap()).unwrap();
        p
    }

    fn src(name: &str, copy: Option<PathBuf>, unloaded: bool) -> ProbeSource {
        ProbeSource {
            url: format!("https://example.com/{name}.txt"),
            name: name.to_string(),
            copy,
            unloaded,
            snap: None,
        }
    }

    fn none(_: &str) -> bool {
        false
    }

    /// 測試的「現在」（Unix 秒）
    const NOW: u64 = 1_800_000_000;

    #[test]
    fn sample_skips_complex_rules_and_exceptions() {
        assert_eq!(simple_domain("||bad.example.com^").as_deref(), Some("bad.example.com"));
        assert_eq!(simple_domain("  ||Bad.Example.NET^\r\n").as_deref(), Some("bad.example.net"));
        assert_eq!(simple_domain("plain.example.com").as_deref(), Some("plain.example.com"));
        assert_eq!(simple_domain("||x_y.example.com^").as_deref(), Some("x_y.example.com"));
        for l in [
            "! 註解",
            "# 註解",
            "@@||good.example.com^",
            "||ads.example.com^$third-party",
            "||*.example.com^",
            "||ads*.example.com^",
            "||example.com/path^",
            "/ads[0-9]+\\.example\\.com/",
            "0.0.0.0 hosts.example.com",
            "||192.0.2.1^",
            "198.51.100.7",
            "||localhost^",
            "||example^",
            "||-bad.example.com^",
            "||a..example.com^",
            "|https://example.com^",
            "example.com##.banner",
            "",
        ] {
            assert_eq!(simple_domain(l), None, "{l}");
        }
        let long = format!("||{}.example.com^", "a".repeat(NAME_MAX));
        assert_eq!(simple_domain(&long), None, "超過 100 個字元");
    }

    #[test]
    fn sample_capped_at_60() {
        let d = tmp("cap");
        let body: String = (0..1000).map(|i| format!("||m{i}.example.com^\n")).collect();
        let s = sample(&[src("tif", Some(copy(&d, "tif", &body)), false)], true, &none, 7, NOW);
        assert_eq!(s.names.len(), SAMPLE_MAX);
        assert_eq!(s.lists, 1);
        assert!(s.skipped.is_none());
        let uniq: HashSet<&String> = s.names.iter().collect();
        assert_eq!(uniq.len(), SAMPLE_MAX, "不重複");
        // 水塘抽樣：不是只拿前 60 行
        assert!(s
            .names
            .iter()
            .any(|n| n.trim_start_matches('m').split('.').next().unwrap().parse::<u32>().unwrap() >= SAMPLE_MAX as u32));
        // 兩份清單合起來還是 60 個；同一個網域只出現一次
        let s2 = sample(
            &[
                src("a", Some(copy(&d, "a", &body)), false),
                src("b", Some(copy(&d, "b", "||m1.example.com^\n||other.example.net^\n")), false),
            ],
            true,
            &none,
            9,
            NOW,
        );
        assert_eq!((s2.names.len(), s2.lists), (SAMPLE_MAX, 2));
        // 少於 60 個：全部收
        let s3 = sample(
            &[src(
                "few",
                Some(copy(
                    &d,
                    "few",
                    "||a.example.com^\n@@||b.example.com^\n||c.example.net^$important\n",
                )),
                false,
            )],
            true,
            &none,
            1,
            NOW,
        );
        assert_eq!(s3.names, ["a.example.com"]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn sample_skipped_under_memory_pressure() {
        let d = tmp("mem");
        let s = sample(
            &[src("tif", Some(copy(&d, "tif", "||a.example.com^\n")), false)],
            false,
            &none,
            1,
            NOW,
        );
        assert!(s.names.is_empty());
        assert_eq!(s.skipped.as_deref(), Some("記憶體吃緊"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn sample_skipped_for_unloaded_list() {
        let d = tmp("unloaded");
        let s = sample(
            &[
                src("off", Some(copy(&d, "off", "||off.example.com^\n")), true),
                src("on", Some(copy(&d, "on", "||on.example.com^\n")), false),
            ],
            true,
            &none,
            1,
            NOW,
        );
        assert_eq!(s.names, ["on.example.com"], "停用中的那一份不抽");
        assert_eq!(s.lists, 1);
        assert!(s.skipped.as_deref().unwrap().contains("「off」停用中"));
        let s = sample(
            &[src("off", Some(copy(&d, "off", "||off.example.com^\n")), true)],
            true,
            &none,
            1,
            NOW,
        );
        assert!(s.names.is_empty() && s.skipped.is_some());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn sample_skipped_without_local_copy_and_never_downloads() {
        // 沒有副本（小 Flash 放不下、還在等寫出）：跳過。`sample` 只拿得到檔案路徑，沒有下載的能力；
        // 路徑不存在也只是讀不到，不會產生任何檔案
        let d = tmp("nocopy");
        let s = sample(&[src("tif", None, false)], true, &none, 1, NOW);
        assert!(s.names.is_empty());
        assert!(s.skipped.as_deref().unwrap().contains("沒有本機副本"), "{s:?}");
        let gone = d.join("gone.txt.zst");
        let s = sample(&[src("tif", Some(gone.clone()), false)], true, &none, 1, NOW);
        assert!(s.names.is_empty() && s.skipped.is_some());
        assert!(!gone.exists());
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 0, "沒有寫出任何檔案");
        // 沒有可以抽的清單
        let s = sample(&[], true, &none, 1, NOW);
        assert!(s.names.is_empty() && s.skipped.is_some());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn sample_excludes_web_preflight_builtin_and_keep_names() {
        let d = tmp("exclude");
        std::fs::create_dir_all(d.join("benchmark")).unwrap();
        std::fs::write(d.join("benchmark/web.txt"), "www.example.com\n").unwrap();
        let mut paths = BenchPaths::from_config(&serde_json::json!({}), &d, &d);
        paths.list_dir = d.join("benchmark");
        paths.default_list_dir = None;
        let cfg = serde_json::json!({ "resolver": { "keepNames": ["keep.example.net", ".Kept.Example.org."] } });
        let ex = excluder(&cfg, &paths);
        assert!(ex("www.example.com"));
        assert!(ex(kuroshio_jobs::benchmark::PREFLIGHT_DOMAIN));
        assert!(ex("keep.example.net") && ex("a.keep.example.net") && ex("b.kept.example.org"));
        assert!(!ex("notkeep.example.net") && !ex("bad.example.com"));
        let body = "||www.example.com^\n||a.keep.example.net^\n||bad.example.com^\n";
        let s = sample(&[src("tif", Some(copy(&d, "tif", body)), false)], true, &ex, 1, NOW);
        assert_eq!(s.names, ["bad.example.com"]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn probe_sample_not_in_saved_config_or_api() {
        // 只放在傳給評測的那一份：原本的設定（存檔、/api/config 用的）不變
        let cfg = kuroshio_config::with_overrides(&serde_json::json!({}));
        let s = ProbeSample {
            names: vec!["bad.example.com".into()],
            lists: 1,
            skipped: None,
            note: None,
        };
        let c = attach(&cfg, &s);
        assert!(cfg["benchmark"].get(PROBE_SAMPLE_KEY).is_none());
        assert_eq!(ProbeSample::from_cfg(&c), s);
        assert_eq!(c["benchmark"]["probeSample"], cfg["benchmark"]["probeSample"]);
        // 設定的預設值與 UCI 都沒有這個鍵（底線開頭＝內部用）
        assert!(kuroshio_config::defaults()["benchmark"].get(PROBE_SAMPLE_KEY).is_none());
        // 開關
        assert!(wanted(&cfg));
        assert!(!wanted(&serde_json::json!({ "benchmark": { "probeSample": false } })));
        assert!(!wanted(&serde_json::json!({ "benchmark": { "malwareProbe": "0" } })));
    }

    /// 3.5.1：下載清單時順便抽樣。內容一段一段進來（行可能被切在兩段之間），只收單純的網域規則，
    /// 太長的行跳過、最後一行沒有換行也算；最多 [`SNAP_MAX`] 個、不重複、不是只拿前面的
    #[test]
    fn line_sampler_streams_split_lines_and_caps() {
        let body: String = (0..2000).map(|i| format!("||m{i}.example.com^\n")).collect::<String>()
            + "! 註解\n@@||ok.example.net^\n||ads.example.net^$third-party\n"
            + &format!("||{}.example.com^\n", "x".repeat(300))
            + "||last.example.net^";
        // 每 7 bytes 一段：幾乎每一行都被切開
        let mut p = LineSampler::new(3);
        for c in body.as_bytes().chunks(7) {
            p.feed(c);
        }
        let got = p.finish();
        assert_eq!(got.len(), SNAP_MAX);
        let uniq: HashSet<&String> = got.iter().collect();
        assert_eq!(uniq.len(), SNAP_MAX, "不重複");
        assert!(
            got.iter().all(|d| d.ends_with(".example.com") || d == "last.example.net"),
            "{got:?}"
        );
        assert!(got.iter().all(|d| d.len() <= NAME_MAX), "太長的行不收");
        assert!(
            got.iter()
                .filter_map(|d| d.strip_prefix('m')?.split('.').next()?.parse::<u32>().ok())
                .any(|n| n >= 1000),
            "水塘抽樣：不是只拿前面的"
        );
        // 少於上限：全部收（含最後一行沒有換行的、跨段的 CRLF）
        let mut p = LineSampler::new(1);
        for c in ["||a.exa", "mple.com^\r", "\n0.0.0.0 hosts.example.net\n||b.example.net^"] {
            p.feed(c.as_bytes());
        }
        assert_eq!(p.finish(), ["a.example.com", "b.example.net"]);
        // 一整行超長、沒有換行：記憶體不跟著長
        let mut p = LineSampler::new(1);
        for _ in 0..1000 {
            p.feed(&[b'a'; 1024]);
            assert!(p.line.capacity() <= 4 * (NAME_MAX + 8), "一行的緩衝有上限");
        }
        assert!(p.finish().is_empty());
    }

    /// 樣本檔：格式不對的不收、每份重新檢查網域與上限；7 天後該重抽、30 天內可以用、時間在未來的當成該重抽也不用；
    /// 換上新樣本時拿掉已經不在設定裡的清單
    #[test]
    fn probe_snaps_parse_refresh_and_prune() {
        let day = 86400;
        let names: Vec<String> = (0..300).map(|i| format!("s{i}.example.com")).collect();
        let raw = serde_json::json!({ "v": 1, "lists": {
            "https://example.com/tif.txt": { "at": NOW - 3 * day, "names": names },
            "https://example.net/bad.txt": { "at": NOW, "names": ["*.x.example.net", "192.0.2.1", "nodot", "ok.example.net", "OK.example.net"] },
            "https://example.net/empty.txt": { "at": NOW, "names": [] },
            "https://example.net/noat.txt": { "names": ["a.example.net"] },
        } });
        let s = Snaps::parse(&serde_json::to_vec(&raw).unwrap());
        assert_eq!(s.0.len(), 2, "{s:?}");
        let tif = &s.0["https://example.com/tif.txt"];
        assert_eq!(tif.names.len(), SNAP_MAX, "每份最多 {SNAP_MAX} 個");
        assert_eq!(s.0["https://example.net/bad.txt"].names, ["ok.example.net"]);
        assert!(Snaps::parse(b"not json").0.is_empty());
        assert!(Snaps::parse(&vec![b' '; SNAP_FILE_MAX + 1]).0.is_empty(), "太大不讀");
        // 寫回去再讀一樣
        assert_eq!(Snaps::parse(&s.to_json()), s);
        // 該不該重抽、能不能用
        assert!(!s.due("https://example.com/tif.txt", NOW));
        assert!(!s.due("https://example.com/tif.txt", NOW + 4 * day - 1));
        assert!(s.due("https://example.com/tif.txt", NOW + 4 * day), "滿 7 天");
        assert!(s.due("https://example.com/other.txt", NOW), "沒有樣本");
        assert!(s.due("https://example.com/tif.txt", NOW - 10 * day), "時間在未來（時鐘跳過）");
        assert!(
            tif.usable(NOW) && tif.usable(NOW + 27 * day) && !tif.usable(NOW + 28 * day),
            "30 天內"
        );
        assert!(!tif.usable(NOW - 5 * day), "時間在未來超過一天不用");
        // 換上新的：不在設定裡的拿掉；抽不到網域時留著舊的
        let mut s2 = s.clone();
        let keep = ["https://example.com/tif.txt"];
        s2.put("https://example.com/tif.txt", SnapList { at: NOW, names: vec![] }, &keep);
        assert_eq!(s2.0.len(), 1);
        assert_eq!(s2.0["https://example.com/tif.txt"].at, NOW - 3 * day, "空的不換");
        s2.put(
            "https://example.com/tif.txt",
            SnapList {
                at: NOW,
                names: vec!["n.example.com".into()],
            },
            &keep,
        );
        assert_eq!(s2.0["https://example.com/tif.txt"].names, ["n.example.com"]);
        assert!(s2.to_json().len() < 8 * 1024);
        // 份數上限
        let mut s3 = Snaps::default();
        let urls: Vec<String> = (0..20).map(|i| format!("https://example.com/{i}.txt")).collect();
        let keep: Vec<&str> = urls.iter().map(String::as_str).collect();
        for (i, u) in urls.iter().enumerate() {
            s3.put(
                u,
                SnapList {
                    at: NOW + i as u64,
                    names: vec![format!("n{i}.example.com")],
                },
                &keep,
            );
        }
        assert_eq!(s3.0.len(), SNAP_LISTS_MAX);
        assert!(s3.0.contains_key("https://example.com/19.txt") && !s3.0.contains_key("https://example.com/0.txt"));
    }

    /// 沒有本機副本：用下載時順便抽的樣本（30 天內）；停用中的也用樣本（不讀副本）；太舊、沒有樣本的照舊跳過
    #[test]
    fn sample_uses_download_time_snapshot_without_copy() {
        let names: Vec<String> = (0..SNAP_MAX).map(|i| format!("s{i}.example.com")).collect();
        let snap = |at: u64| Some(SnapList { at, names: names.clone() });
        let mut a = src("tif", None, false);
        a.snap = snap(NOW - 3 * 86400);
        let ex = |d: &str| d == "s0.example.com";
        let s = sample(&[a.clone()], true, &ex, 5, NOW);
        assert_eq!((s.names.len(), s.lists), (SAMPLE_MAX, 1));
        assert!(s.names.iter().all(|d| names.contains(d) && d != "s0.example.com"), "排除的照樣排除");
        assert!(s.skipped.is_none());
        assert_eq!(
            s.note.as_deref(),
            Some(format!("「tif」用 3 天前下載時順便抽的 {SNAP_MAX} 個").as_str())
        );
        // 每天抽到的不一定一樣（樣本是兩倍）
        let other = sample(&[a.clone()], true, &ex, 6, NOW);
        assert_ne!(s.names, other.names);
        // 停用中：不讀副本，有樣本照用
        let mut b = a.clone();
        b.unloaded = true;
        assert_eq!(sample(&[b], true, &ex, 5, NOW).names.len(), SAMPLE_MAX);
        // 太舊（超過 30 天）：照舊跳過
        let mut c = a.clone();
        c.snap = snap(NOW - 31 * 86400);
        let s = sample(&[c], true, &ex, 5, NOW);
        assert!(s.names.is_empty());
        assert!(s.skipped.as_deref().unwrap().contains("沒有本機副本"), "{s:?}");
        // 記憶體吃緊：樣本也不用
        assert!(sample(&[a], false, &ex, 5, NOW).names.is_empty());
    }

    #[test]
    fn reservoir_is_roughly_uniform() {
        // 1000 筆抽 40 筆，重複 200 次：前一半與後一半被抽到的次數差不多（水塘抽樣不偏向前面）
        let (mut front, mut back) = (0u32, 0u32);
        for seed in 0..200u64 {
            let mut r = Reservoir::new(40, seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
            for i in 0..1000 {
                r.offer(format!("{i}"));
            }
            for x in r.into_items() {
                if x.parse::<u32>().unwrap() < 500 {
                    front += 1;
                } else {
                    back += 1;
                }
            }
        }
        let total = (front + back) as f64;
        assert!((front as f64 / total - 0.5).abs() < 0.05, "{front} / {back}");
    }

    /// `FilterService::probe_sources()`：只列可以抽的清單；副本寫在磁碟上才有路徑；全部暫停時算停用
    #[tokio::test]
    async fn sample_only_from_enabled_malware_lists_marked_probe() {
        use crate::filtering::FilterService;
        use std::sync::Mutex;
        let d = tmp("sources");
        // 預設清單：只有威脅情資類（TW165、TWNIC-RPZ、新註冊網域、繞過防護標 probe: false）
        let cfg = kuroshio_config::with_overrides(&serde_json::json!({ "filter": { "customRules": [] } }));
        let f = FilterService::from_cfg(&cfg, &d).unwrap();
        let ps = f.probe_sources();
        assert_eq!(ps.len(), 1, "{ps:?}");
        assert!(ps[0].url.ends_with("/tif.mini.txt"), "{ps:?}");
        assert!(ps[0].copy.is_none() && !ps[0].unloaded, "還沒有副本");
        // 自己的設定：廣告類、停用的、明寫 probe: false 的、繞過防護、TW165 的網址都不抽；明寫 probe: true 的廣告類照抽
        let mut lists = vec![
            serde_json::json!({ "name": "M", "url": "https://example.com/m.txt", "category": "malware" }),
            serde_json::json!({ "name": "A", "url": "https://example.com/a.txt", "category": "ads" }),
            serde_json::json!({ "name": "Off", "url": "https://example.com/off.txt", "category": "malware", "enabled": false }),
            serde_json::json!({ "name": "No", "url": "https://example.com/no.txt", "category": "malware", "probe": false }),
            serde_json::json!({ "name": "By", "url": "https://example.com/by.txt", "category": "malware", "bypass": true }),
            serde_json::json!({ "name": "Yes", "url": "https://example.com/yes.txt", "category": "ads", "probe": true }),
        ];
        for u in kuroshio_config::chain::KNOWN_NO_PROBE_URLS {
            lists.push(serde_json::json!({ "name": u, "url": u, "category": "malware" }));
        }
        let cfg = kuroshio_config::with_overrides(&serde_json::json!({ "filter": { "customRules": [], "lists": lists } }));
        let f = FilterService::from_cfg(&cfg, &d).unwrap();
        let names: Vec<String> = f.probe_sources().into_iter().map(|p| p.name).collect();
        assert_eq!(names, ["M", "Yes"]);
        // 副本：還在等寫出時沒有路徑（不讀記憶體裡的待寫內容）；寫到磁碟之後才有
        let mut p = crate::persist::Persister::new(
            d.join("state"),
            crate::persist::Policy::new(crate::sysinfo::StorageClass::Disk, 0, 4096),
        );
        p.set_free_probe(|_| Some(10 << 30));
        let p = Arc::new(Mutex::new(p));
        f.set_copies(p.clone());
        let z = zstd::encode_all(&b"||bad.example.com^\n"[..], 3).unwrap();
        assert!(f
            .copies()
            .unwrap()
            .offer("https://example.com/m.txt", 1, Some(z), &crate::fetch::Validators::default(), 1, 1));
        assert!(f.probe_sources()[0].copy.is_none(), "還在等寫出");
        p.lock().unwrap().flush_all(crate::persist::now_secs()).unwrap();
        let ps = f.probe_sources();
        let path = ps[0].copy.clone().expect("寫到磁碟之後才有");
        assert!(ps[1].copy.is_none());
        let s = sample(&ps, true, &none, 1, NOW);
        assert_eq!((s.names.clone(), s.lists), (vec!["bad.example.com".to_string()], 1));
        assert!(s.skipped.as_deref().unwrap().contains("「Yes」沒有本機副本"));
        assert!(path.is_file());
        // 全部清單暫停中（記憶體控制的最後一步）：都算停用
        f.suspend_all();
        assert!(f.probe_sources().iter().all(|p| p.unloaded));
        let _ = std::fs::remove_dir_all(&d);
    }
}
