//! 3.5.0 A3／A4：分級評測（`benchmark.tiers`）與依評測歷史的升降
//! - `a`：A 級、使用者的、沿用、補位、探索；其餘 B 級今天不測（一筆查詢都不送、不算淘汰）
//! - `ab`：跟以前一樣全部測
//!
//! 本機假 DNS 伺服器（每台數自己收到幾筆查詢）、注入的時鐘

use kuroshio_jobs::benchmark::probe::{AsnSource, NetProber, Prober, SiteCheck, StaticAsn};
use kuroshio_jobs::benchmark::rules::AsnInfo;
use kuroshio_jobs::benchmark::tiers::{Mode, B_EXPLORE_MAX};
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
    #[allow(dead_code)]
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

    // 同一天再跑一次：測的是同一批（手動多跑幾次不會把 B 級測完）
    let before: Vec<bool> = l.b.iter().map(|m| m.hits.load(Ordering::Relaxed) > 0).collect();
    l.reset();
    let again = run(&p, "a", &clock).await;
    let after: Vec<bool> = l.b.iter().map(|m| m.hits.load(Ordering::Relaxed) > 0).collect();
    assert_eq!(before, after);
    // 昨天選上或候補的 B 級今天沿用（算在沿用，不佔補位）
    assert!(again["tiers"]["incumbent"].as_u64().unwrap() >= 1, "{}", again["tiers"]);
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
        assert!(!report(&p, &up, "judge.log").contains("[分級]"));
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
