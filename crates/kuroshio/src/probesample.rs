//! 惡意網站探測的網域從這台已經下載的惡意類過濾清單抽樣（3.5.0 F10，規格 11 第 6 節）
//!
//! A5 的探測網域原本只有人工確認過的 `probe.txt`，但這份名單一直是空的（沒有人工確認過的網域），探測整段沒跑。
//! 使用者定案：**不在 repo 放固定名單**，每次評測從這台已經下載的惡意類清單抽。
//!
//! - 誰可以抽：[`crate::filtering::FilterService::probe_sources`]（`filter.lists[].probe`；沒寫時惡意類、啟用中、
//!   不是 TW165／TWNIC-RPZ／新註冊網域／繞過防護）。
//! - 怎麼抽：串流解壓本機副本，水塘抽樣留 [`SAMPLE_MAX`] 個；只收單純的網域規則（[`simple_domain`]）。
//! - 不抽的情況（記一行 INFO，評測照樣跑、只用 `probe.txt`）：記憶體壓力不是 Normal、清單被記憶體控制停用中、
//!   沒有本機副本（**不為了抽樣多下載**）。
//! - 排除：評測網域（`web.txt`）、資格賽網域、內建一定通過的服務（F11）、`resolver.keepNames`。
//! - 抽到的放進傳給評測的那一份設定的 `benchmark._probeSample`（[`attach`]；底線開頭＝內部用，不存檔、
//!   `/api/config` 看不到），子程序合併 `probe.txt`、先確認還解析得到，再照 A5 的三層保護判斷
//!   （`kuroshio_jobs::benchmark::malware`）。
//! - 抽到的網域不寫進一般日誌（只在 DEBUG）：`judge.log` 與日誌會被回報、貼出來。
//!
//! 在主程式啟動評測前做一次（解壓一份幾百 KB 的副本），記憶體只有水塘的 40 個字串。

use crate::filtering::ProbeSource;
use kuroshio_config::get;
use kuroshio_jobs::benchmark::{malware::SAMPLE_MAX, ProbeSample, PROBE_SAMPLE_KEY};
use kuroshio_jobs::{BenchPaths, JobCtx};
use serde_json::Value;
use std::collections::HashSet;
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
    let labels: Vec<&str> = d.split('.').collect();
    if labels
        .iter()
        .any(|p| p.is_empty() || p.len() > 63 || p.starts_with('-') || p.ends_with('-'))
    {
        return None;
    }
    // IP（`192.0.2.1`）與最後一段全是數字的都不是網域
    if labels.last().is_some_and(|t| t.bytes().all(|b| b.is_ascii_digit())) {
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
/// - 停用中、沒有副本的清單跳過（各記一行 INFO）
pub fn sample(sources: &[ProbeSource], normal: bool, exclude: &dyn Fn(&str) -> bool, seed: u64) -> ProbeSample {
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
    for s in sources {
        if s.unloaded {
            info!("惡意網站探測：清單「{}」被記憶體控制停用中，這次不從它抽樣", s.name);
            why_not.push(format!("「{}」停用中", s.name));
            continue;
        }
        let Some(path) = &s.copy else {
            info!("惡意網站探測：清單「{}」沒有本機副本（不為了抽樣下載），這次不從它抽樣", s.name);
            why_not.push(format!("「{}」沒有本機副本", s.name));
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
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
        ^ ((std::process::id() as u64) << 32);
    // 解壓一份幾百 KB 的副本：在 blocking 執行緒做，不卡住查詢
    let s = tokio::task::spawn_blocking(move || sample(&sources, normal, &ex, seed))
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
        }
    }

    fn none(_: &str) -> bool {
        false
    }

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
    fn sample_capped_at_40() {
        let d = tmp("cap");
        let body: String = (0..1000).map(|i| format!("||m{i}.example.com^\n")).collect();
        let s = sample(&[src("tif", Some(copy(&d, "tif", &body)), false)], true, &none, 7);
        assert_eq!(s.names.len(), SAMPLE_MAX);
        assert_eq!(s.lists, 1);
        assert!(s.skipped.is_none());
        let uniq: HashSet<&String> = s.names.iter().collect();
        assert_eq!(uniq.len(), SAMPLE_MAX, "不重複");
        // 水塘抽樣：不是只拿前 40 行
        assert!(s
            .names
            .iter()
            .any(|n| n.trim_start_matches('m').split('.').next().unwrap().parse::<u32>().unwrap() >= 40));
        // 兩份清單合起來還是 40 個；同一個網域只出現一次
        let s2 = sample(
            &[
                src("a", Some(copy(&d, "a", &body)), false),
                src("b", Some(copy(&d, "b", "||m1.example.com^\n||other.example.net^\n")), false),
            ],
            true,
            &none,
            9,
        );
        assert_eq!((s2.names.len(), s2.lists), (SAMPLE_MAX, 2));
        // 少於 40 個：全部收
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
        );
        assert_eq!(s3.names, ["a.example.com"]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn sample_skipped_under_memory_pressure() {
        let d = tmp("mem");
        let s = sample(&[src("tif", Some(copy(&d, "tif", "||a.example.com^\n")), false)], false, &none, 1);
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
        );
        assert_eq!(s.names, ["on.example.com"], "停用中的那一份不抽");
        assert_eq!(s.lists, 1);
        assert!(s.skipped.as_deref().unwrap().contains("「off」停用中"));
        let s = sample(&[src("off", Some(copy(&d, "off", "||off.example.com^\n")), true)], true, &none, 1);
        assert!(s.names.is_empty() && s.skipped.is_some());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn sample_skipped_without_local_copy_and_never_downloads() {
        // 沒有副本（小 Flash 放不下、還在等寫出）：跳過。`sample` 只拿得到檔案路徑，沒有下載的能力；
        // 路徑不存在也只是讀不到，不會產生任何檔案
        let d = tmp("nocopy");
        let s = sample(&[src("tif", None, false)], true, &none, 1);
        assert!(s.names.is_empty());
        assert!(s.skipped.as_deref().unwrap().contains("沒有本機副本"), "{s:?}");
        let gone = d.join("gone.txt.zst");
        let s = sample(&[src("tif", Some(gone.clone()), false)], true, &none, 1);
        assert!(s.names.is_empty() && s.skipped.is_some());
        assert!(!gone.exists());
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 0, "沒有寫出任何檔案");
        // 沒有可以抽的清單
        let s = sample(&[], true, &none, 1);
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
        let s = sample(&[src("tif", Some(copy(&d, "tif", body)), false)], true, &ex, 1);
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
        let s = sample(&ps, true, &none, 1);
        assert_eq!((s.names.clone(), s.lists), (vec!["bad.example.com".to_string()], 1));
        assert!(s.skipped.as_deref().unwrap().contains("「Yes」沒有本機副本"));
        assert!(path.is_file());
        // 全部清單暫停中（記憶體控制的最後一步）：都算停用
        f.suspend_all();
        assert!(f.probe_sources().iter().all(|p| p.unloaded));
        let _ = std::fs::remove_dir_all(&d);
    }
}
