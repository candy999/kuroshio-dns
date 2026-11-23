//! 3.5.0 A3／A4：分級評測（`benchmark.tiers`）與依評測歷史的升降
//! - `a`：A 級、使用者的、沿用、補位、探索；其餘 B 級今天不測（一筆查詢都不送、不算淘汰）
//! - `ab`：跟以前一樣全部測
//!
//! 本機假 DNS 伺服器（每台數自己收到幾筆查詢）、注入的時鐘

use kuroshio_jobs::benchmark::learn::{Hist, HistState, Learn};
use kuroshio_jobs::benchmark::probe::{AsnSource, NetProber, Prober, SiteCheck, StaticAsn};
use kuroshio_jobs::benchmark::rules::AsnInfo;
use kuroshio_jobs::benchmark::tiers::{Mode, B_EXPLORE_MAX, TRIAL_NEW_PER_DAY};
use kuroshio_jobs::scheduler::BoxFuture;
use kuroshio_jobs::time::{days_from_civil, ManualClock, DAY_MS, HOUR_MS, TPE_OFFSET_MS};
use kuroshio_jobs::{BenchPaths, Benchmark, JobCtx};
use kuroshio_net::upstream::{Kind, Upstream};
use kuroshio_proto::message::Record;
use kuroshio_proto::Message;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

/// 一台假 DNS：正常回答；`up` 關掉時不回應；`hits` 是收到的查詢數
struct Mock {
    id: String,
    hits: Arc<AtomicUsize>,
    up: Arc<AtomicBool>,
}

async fn mock(n: u8, delay_ms: u64) -> Mock {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let id = sock.local_addr().unwrap().to_string();
    let hits = Arc::new(AtomicUsize::new(0));
    let up = Arc::new(AtomicBool::new(true));
    let (h2, u2) = (hits.clone(), up.clone());
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            let Ok((len, peer)) = sock.recv_from(&mut buf).await else { break };
            let Ok(q) = Message::parse(&buf[..len]) else { continue };
            h2.fetch_add(1, Ordering::Relaxed);
            if !u2.load(Ordering::Relaxed) {
                continue;
            }
            let name = q.question().map(|x| x.name.clone()).unwrap_or_default();
            let mut r = Message::response_to(&q, 0);
            match name.as_str() {
                "one.one.one.one" => r
                    .answers
                    .extend([Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 0, 0, 1)].map(|i| Record::a(&name, 60, i))),
                "www.example.com" => r.answers.push(Record::a(&name, 60, Ipv4Addr::new(93, 1, 0, n))),
                "cdn.example.net" => r.answers.push(Record::a(&name, 60, Ipv4Addr::new(94, 2, 0, n))),
                _ => r.rcode = 3,
            }
            let sock = sock.clone();
            tokio::spawn(async move {
                if delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
                let _ = sock.send_to(&r.encode(), peer).await;
            });
        }
    });
    Mock { id, hits, up }
}

struct LocalOnly;

impl Prober for LocalOnly {
    fn supports(&self, up: &Upstream) -> bool {
        matches!(up.kind, Kind::Udp) && up.supported()
    }
    fn exchange(&self, up: Upstream, q: Vec<u8>, t: Duration) -> BoxFuture<anyhow::Result<Vec<u8>>> {
        NetProber.exchange(up, q, t)
    }
    fn resolve_v4(&self, _host: String) -> BoxFuture<Option<Ipv4Addr>> {
        Box::pin(async { None })
    }
    fn verify_site(&self, _ip: std::net::IpAddr, _d: String, _t: Duration) -> BoxFuture<(SiteCheck, String)> {
        Box::pin(async { (SiteCheck::Valid, "OK".to_string()) })
    }
}

fn asn() -> Arc<dyn AsnSource> {
    let mut m = HashMap::new();
    m.insert(
        "93.1".to_string(),
        AsnInfo::from_ip_api("Example Web", "Example Web", "AS64496 Example Web", ""),
    );
    m.insert(
        "94.2".to_string(),
        AsnInfo::from_ip_api("Example CDN", "Example CDN", "AS64497 Example CDN", ""),
    );
    Arc::new(StaticAsn(m))
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("kuroshio-bench-tiers-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("benchmark")).unwrap();
    std::fs::create_dir_all(d.join("default")).unwrap();
    std::fs::create_dir_all(d.join("state")).unwrap();
    d
}

fn paths(root: &Path) -> BenchPaths {
    BenchPaths {
        list_dir: root.join("benchmark"),
        out_root: Some(root.join("state/benchmark")),
        upstreams_file: root.join("state/upstreams.json"),
        community_candidates: None,
        blacklist_file: Some(root.join("state/blacklist.txt")),
        default_list_dir: Some(root.join("default")),
        learn_file: Some(root.join("state/benchmark-learn.json")),
    }
}

fn day0() -> u64 {
    days_from_civil(2026, 11, 20) as u64 * DAY_MS + 12 * HOUR_MS - TPE_OFFSET_MS
}

fn cfg(tiers: &str) -> Value {
    kuroshio_config::with_overrides(&json!({
        "upstream": { "pinned": [], "autoTypes": ["udp"], "autoMax": 3 },
        "benchmark": { "timeoutMs": 300, "concurrency": 16, "paceMs": 0, "maxTimeouts": 1, "minAuto": 1, "tiers": tiers }
    }))
}

async fn run_with(b: Benchmark, tiers: &str, clock: &Arc<ManualClock>) -> Value {
    let ctx = JobCtx::new("dns-benchmark", "測試", Arc::new(cfg(tiers))).with_clock(clock.clone());
    b.run(&ctx).await.unwrap()
}

async fn run(p: &BenchPaths, tiers: &str, clock: &Arc<ManualClock>) -> Value {
    run_with(Benchmark::with(p.clone(), Arc::new(LocalOnly), asn()), tiers, clock).await
}

fn report(p: &BenchPaths, up: &Value, name: &str) -> String {
    std::fs::read_to_string(p.out_root.clone().unwrap().join(up["date"].as_str().unwrap()).join(name)).unwrap()
}

struct Lists {
    a: Vec<Mock>,
    b: Vec<Mock>,
    user: Mock,
}

impl Lists {
    fn reset(&self) {
        for m in self.a.iter().chain(&self.b).chain([&self.user]) {
            m.hits.store(0, Ordering::Relaxed);
        }
    }
}

/// 預設名單：A 級 3 台（3 家經營者）、B 級 50 台（10 家經營者，`ms` 由小到大）；使用者自己的名單 1 台（沒有標記）。
/// A 級與使用者的回應慢 25 ms，B 級第一台（`ms` 最小）最快
async fn lists(root: &Path) -> Lists {
    let mut a = Vec::new();
    let mut text = String::from("# ---- A 級 ----\n");
    for n in 1..=3u8 {
        let m = mock(n, 25).await;
        text.push_str(&format!("{}  # tier=A op=Example_A{n} ms={n}\n", m.id));
        a.push(m);
    }
    text.push_str("# ---- B 級 ----\n");
    let mut b = Vec::new();
    for n in 0..50u8 {
        let m = mock(10 + n, if n == 0 { 0 } else { 25 }).await;
        text.push_str(&format!("{}  # tier=B op=Example_B{} ms={}\n", m.id, n % 10, 10 + n));
        b.push(m);
    }
    std::fs::write(root.join("default/iplist.txt"), text).unwrap();
    std::fs::write(root.join("default/web.txt"), "www.example.com\ncdn.example.net\n").unwrap();
    let user = mock(200, 25).await;
    std::fs::write(root.join("benchmark/iplist.txt"), format!("{}\n", user.id)).unwrap();
    std::fs::write(root.join("benchmark/web.txt"), "www.example.com\ncdn.example.net\n").unwrap();
    Lists { a, b, user }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tier_a_tests_only_a_user_fill_and_explore() {
    let root = tmp("a");
    let p = paths(&root);
    let l = lists(&root).await;
    let clock = Arc::new(ManualClock::new(day0()));
    let up = run(&p, "a", &clock).await;
    let t = &up["tiers"];
    assert_eq!(t["mode"], "a", "{t}");
    assert_eq!(t["auto"], false);
    assert_eq!(t["a"], 3);
    // 今天要測的只有 4 家經營者（A 級 3、使用者的 1）、udp 只有 4 個：補 8 家新的（每家 1 個，udp 也就有 8 個以上）
    assert_eq!(t["fill"], 8, "{t}");
    let explore = t["explore"].as_u64().unwrap() as usize;
    assert!(explore <= B_EXPLORE_MAX && explore > 0, "{t}");
    assert_eq!(t["skippedB"].as_u64().unwrap() as usize, 50 - 8 - explore, "{t}");
    assert_eq!(up["counts"]["total"].as_u64().unwrap() as usize, 4 + 8 + explore, "{up:#}");
    // A 級、使用者的都測了
    for m in l.a.iter().chain([&l.user]) {
        assert!(m.hits.load(Ordering::Relaxed) >= 3, "{}", m.id);
    }
    // 今天不測的 B 級：一筆查詢都沒有、不在淘汰名單
    let untouched = l.b.iter().filter(|m| m.hits.load(Ordering::Relaxed) == 0).count();
    assert_eq!(untouched, 50 - 8 - explore);
    assert_eq!(up["counts"]["eliminated"], 0);
    assert_eq!(up["counts"]["byTier"]["user"], 1);
    // 補位依整理名單時的延遲：ms 最小的 8 家各 1 個（B 級第 0～7 台）
    for m in &l.b[..8] {
        assert!(m.hits.load(Ordering::Relaxed) >= 3, "補位應該測到 {}", m.id);
    }
    let log = report(&p, &up, "judge.log");
    assert!(log.contains("[分級] 今天測 A 級 3 個"), "{log}");
    assert!(
        log.contains("補位 8 個（原因：經營者只有 4 家（至少 12）、udp 只有 4 個（至少 8））"),
        "{log}"
    );
    // B 級最快的那一台（補位進來的）選上了：選擇照常只看今天的結果
    assert_eq!(up["selected"][0]["id"], l.b[0].id.as_str(), "{up:#}");
    assert_eq!(up["selected"][0]["tier"], "B");

    // 同一天再跑一次：探索的是同一組（手動多跑幾次不會把 B 級測完）；多出來的只有沿用、試用與補位（各有上限）
    let before = l.b.iter().filter(|m| m.hits.load(Ordering::Relaxed) > 0).count();
    l.reset();
    let again = run(&p, "a", &clock).await;
    let after = l.b.iter().filter(|m| m.hits.load(Ordering::Relaxed) > 0).count();
    assert!(after <= before + 8, "第二次多測了 {} 個 B 級", after as i64 - before as i64);
    // 上一次選上的 B 級照測（沿用，或已經因為表現好開始試用）
    assert!(l.b[0].hits.load(Ordering::Relaxed) > 0);
    let t = &again["tiers"];
    assert!(t["incumbent"].as_u64().unwrap() + t["trial"].as_u64().unwrap() >= 1, "{t}");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tier_ab_matches_previous_behaviour() {
    let root = tmp("ab");
    let p = paths(&root);
    let l = lists(&root).await;
    let clock = Arc::new(ManualClock::new(day0()));
    // 明寫 ab、auto（沒有換算時預設全部測）都跟以前一樣：54 台全部測
    for tiers in ["ab", "auto"] {
        l.reset();
        let up = run(&p, tiers, &clock).await;
        assert_eq!(up["counts"]["total"], 54, "{tiers}");
        assert_eq!(up["counts"]["survivors"], 54);
        assert_eq!(up["counts"]["byTier"], json!({ "A": 3, "B": 50, "user": 1 }));
        let t = &up["tiers"];
        assert_eq!(
            (
                t["mode"].as_str(),
                t["fill"].as_u64(),
                t["explore"].as_u64(),
                t["skippedB"].as_u64()
            ),
            (Some("ab"), Some(0), Some(0), Some(0)),
            "{t}"
        );
        assert_eq!(t["auto"], tiers == "auto");
        assert!(l.a.iter().chain(&l.b).chain([&l.user]).all(|m| m.hits.load(Ordering::Relaxed) >= 3));
        assert!(!report(&p, &up, "judge.log").contains("[分級] 今天測"));
    }
    // auto 換算成 a（小機器）：只測一部分；設定寫明 ab 時不看換算
    let small = || Benchmark::with(p.clone(), Arc::new(LocalOnly), asn()).with_tier_auto(Mode::A);
    let up = run_with(small(), "auto", &clock).await;
    assert_eq!(
        (up["tiers"]["mode"].as_str(), up["tiers"]["auto"].as_bool()),
        (Some("a"), Some(true))
    );
    assert!(up["counts"]["total"].as_u64().unwrap() < 54);
    let up = run_with(small(), "ab", &clock).await;
    assert_eq!(up["counts"]["total"], 54);
    let _ = std::fs::remove_dir_all(&root);
}

fn learn(p: &BenchPaths) -> Learn {
    Learn::load(&p.learn_file.clone().unwrap())
}

async fn try_run(p: &BenchPaths, tiers: &str, clock: &Arc<ManualClock>) -> anyhow::Result<Value> {
    let ctx = JobCtx::new("dns-benchmark", "測試", Arc::new(cfg(tiers))).with_clock(clock.clone());
    Benchmark::with(p.clone(), Arc::new(LocalOnly), asn()).run(&ctx).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_run_does_not_touch_history() {
    let root = tmp("hist");
    let p = paths(&root);
    let l = lists(&root).await;
    let clock = Arc::new(ManualClock::new(day0()));
    // 第 1 天：A 級第 1 台連不上，其他正常
    l.a[0].up.store(false, Ordering::Relaxed);
    run(&p, "ab", &clock).await;
    let h = learn(&p).hist;
    assert_eq!(h.len(), 53, "A 級 3、B 級 50；使用者自己加的不記");
    assert!(!h.contains_key(&l.user.id));
    let dead = h[&l.a[0].id];
    assert_eq!((dead.tested(), dead.survived(), dead.suspect()), (1, 0, 0));
    let ok = h[&l.a[1].id];
    assert_eq!((ok.tested(), ok.survived()), (1, 1));
    assert!(ok.ms > 0.0);
    // 第 2 天：整台斷網（全部連不上）→ 評測失敗，歷史不動：不能把本機的問題記到候選頭上
    clock.advance(DAY_MS);
    for m in l.a.iter().chain(&l.b).chain([&l.user]) {
        m.up.store(false, Ordering::Relaxed);
    }
    let e = try_run(&p, "ab", &clock).await.unwrap_err();
    assert!(e.to_string().contains("沒有任何 DNS 通過資格賽"), "{e}");
    assert_eq!(learn(&p).hist, h);
    // 第 3 天恢復：正常的那台是「測到 2 天、倖存 2 天」，斷網那天不算
    clock.advance(DAY_MS);
    for m in l.a.iter().chain(&l.b).chain([&l.user]) {
        m.up.store(true, Ordering::Relaxed);
    }
    run(&p, "ab", &clock).await;
    let ok = learn(&p).hist[&l.a[1].id];
    assert_eq!((ok.tested(), ok.survived(), ok.t), (2, 2, 0b101));
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn history_demotes_a_and_pulls_up_b() {
    let root = tmp("updown");
    let p = paths(&root);
    let l = lists(&root).await;
    let clock = Arc::new(ManualClock::new(day0()));
    // A 級第 1 台一直連不上
    l.a[0].up.store(false, Ordering::Relaxed);
    let mut up = run(&p, "a", &clock).await;
    // 第 1 天：今天測到、倖存、沒失敗過的 B 級裡，延遲低的 8 個開始試用
    let trial: Vec<String> = learn(&p)
        .hist
        .iter()
        .filter(|(_, h)| h.e == HistState::Trial)
        .map(|(k, _)| k.clone())
        .collect();
    assert_eq!(trial.len(), TRIAL_NEW_PER_DAY);
    assert_eq!(up["tiers"]["trial"], 0, "今天的計畫裡還沒有");
    for day in 2..=7 {
        clock.advance(DAY_MS);
        l.reset();
        up = run(&p, "a", &clock).await;
        // 試用中的每天都測（不靠補位或探索）
        assert!(
            up["tiers"]["trial"].as_u64().unwrap() >= TRIAL_NEW_PER_DAY as u64,
            "第 {day} 天 {}",
            up["tiers"]
        );
        for id in &trial {
            let m = l.b.iter().find(|m| m.id == *id).unwrap();
            assert!(m.hits.load(Ordering::Relaxed) > 0, "第 {day} 天沒測試用中的 {id}");
        }
        assert_eq!(up["tiers"]["a"], 3, "第 {day} 天：還沒降級");
    }
    // 第 7 天：連續 7 天沒倖存 → 降級（只影響測不測）
    assert_eq!(up["tiers"]["demotedToday"], 1, "{}", up["tiers"]);
    assert_eq!(learn(&p).hist[&l.a[0].id].e, HistState::Demoted);
    let log = report(&p, &up, "judge.log");
    assert!(
        log.contains(&format!("[降級] {}：近 30 天測到 7 天、倖存 0 天", l.a[0].id)),
        "{log}"
    );
    // 第 8 天：降級的 A 級不在 A 級裡了（只在探索時輪到）；跑到第 10 天，試用滿 10 天的升級
    for day in 8..=11 {
        clock.advance(DAY_MS);
        up = run(&p, "a", &clock).await;
        assert_eq!(
            (up["tiers"]["a"].as_u64(), up["tiers"]["demoted"].as_u64()),
            (Some(2), Some(1)),
            "第 {day} 天"
        );
    }
    assert!(
        up["tiers"]["promoted"].as_u64().unwrap() >= TRIAL_NEW_PER_DAY as u64,
        "{}",
        up["tiers"]
    );
    let h = learn(&p).hist;
    assert!(trial.iter().all(|id| h[id].e == HistState::Promoted));
    // 選上游照常只看今天的結果：降級的那台本來就沒倖存，其他照選
    assert!(!up["selected"].as_array().unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn demotion_fuse_and_unreadable_learn_file_fall_back_to_manual_tiers() {
    let root = tmp("fuse");
    let p = paths(&root);
    let l = lists(&root).await;
    let clock = Arc::new(ManualClock::new(day0()));
    let today = kuroshio_jobs::benchmark::learn::day_of(day0());
    let demoted = Hist {
        t: 0x7f,
        s: 0,
        e: HistState::Demoted,
        last: today - 1,
        ..Default::default()
    };
    // 3 台 A 級裡 1 台降級：照降（今天不測）
    let mut lf = Learn::default();
    lf.day = today - 1;
    lf.hist.insert(l.a[0].id.clone(), demoted);
    lf.save(&p.learn_file.clone().unwrap()).unwrap();
    let up = run(&p, "a", &clock).await;
    assert_eq!((up["tiers"]["a"].as_u64(), up["tiers"]["demoted"].as_u64()), (Some(2), Some(1)));
    assert_eq!(up["tiers"]["demoteFuse"], false);
    // 3 台裡 2 台降級（超過三分之一）：多半是線路的問題 → 今天不採用降級，全部照人工分級測
    let mut lf = Learn::default();
    lf.day = today - 1;
    lf.hist.insert(l.a[0].id.clone(), demoted);
    lf.hist.insert(l.a[1].id.clone(), demoted);
    lf.save(&p.learn_file.clone().unwrap()).unwrap();
    l.reset();
    let up = run(&p, "a", &clock).await;
    assert_eq!(
        (up["tiers"]["a"].as_u64(), up["tiers"]["demoted"].as_u64()),
        (Some(3), Some(0)),
        "{}",
        up["tiers"]
    );
    assert_eq!(up["tiers"]["demoteFuse"], true);
    assert!(l.a.iter().all(|m| m.hits.load(Ordering::Relaxed) > 0));
    assert!(report(&p, &up, "judge.log").contains("今天不採用降級"));
    // 學習檔壞掉：當成空的，照人工分級跑，不失敗
    let f = p.learn_file.clone().unwrap();
    std::fs::write(format!("{}.zst", f.display()), b"not zstd").unwrap();
    let up = run(&p, "a", &clock).await;
    assert_eq!((up["tiers"]["a"].as_u64(), up["tiers"]["demoted"].as_u64()), (Some(3), Some(0)));
    assert_eq!(up["tiers"]["promoted"], 0);
    // 評測完重新寫出一份好的
    assert_eq!(learn(&p).hist[&l.a[0].id].tested(), 1);
    let _ = std::fs::remove_dir_all(&root);
}
