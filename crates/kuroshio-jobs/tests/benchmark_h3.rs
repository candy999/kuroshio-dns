//! 3.5.0 A6：記住不支援 HTTP/3 的 DoH（學習檔的 `h3skip`）。
//! 本機假 DNS 伺服器：DoH（HTTP/2）與 DoH3 都轉到同一台本機 UDP 伺服器；「不支援 HTTP/3」的那幾台 h3:// 一律連線錯誤。
//! 日期用注入的時鐘，一天跑一次評測。

use kuroshio_jobs::benchmark::learn::Learn;
use kuroshio_jobs::benchmark::probe::{AsnSource, NetProber, Prober, SiteCheck, StaticAsn};
use kuroshio_jobs::benchmark::rules::AsnInfo;
use kuroshio_jobs::scheduler::BoxFuture;
use kuroshio_jobs::time::{days_from_civil, ManualClock, DAY_MS, HOUR_MS, TPE_OFFSET_MS};
use kuroshio_jobs::{BenchPaths, Benchmark, Clock, JobCtx};
use kuroshio_net::path::{Proto, Report};
use kuroshio_net::upstream::{Kind, Upstream};
use kuroshio_proto::message::Record;
use kuroshio_proto::Message;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;

/// 正常的 DNS：每台回自己的位址（各有獨有的覆蓋）
async fn mock(n: u8) -> SocketAddr {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            let Ok((len, peer)) = sock.recv_from(&mut buf).await else { break };
            let Ok(q) = Message::parse(&buf[..len]) else { continue };
            let name = q.question().map(|x| x.name.clone()).unwrap_or_default();
            let mut r = Message::response_to(&q, 0);
            match name.as_str() {
                "one.one.one.one" => {
                    r.answers.push(Record::a(&name, 60, Ipv4Addr::new(1, 1, 1, 1)));
                    r.answers.push(Record::a(&name, 60, Ipv4Addr::new(1, 0, 0, 1)));
                }
                "www.example.com" => r.answers.push(Record::a(&name, 60, Ipv4Addr::new(93, 1, 0, n))),
                _ => r.rcode = 3,
            }
            let _ = sock.send_to(&r.encode(), peer).await;
        }
    });
    addr
}

/// DoH / DoH3 依主機名稱轉到本機假伺服器；`no_h3` 的主機 HTTP/3 連不上、`dead` 的主機兩種都連不上。
/// 記下每個 h3:// 被問了幾次
struct Mapped {
    map: HashMap<String, SocketAddr>,
    no_h3: HashSet<String>,
    dead: HashSet<String>,
    h3_asked: Mutex<HashMap<String, usize>>,
}

impl Prober for Mapped {
    fn supports(&self, up: &Upstream) -> bool {
        matches!(up.kind, Kind::Doh | Kind::Doh3) && self.map.contains_key(&up.host)
    }
    fn exchange(&self, up: Upstream, q: Vec<u8>, t: Duration) -> BoxFuture<anyhow::Result<Vec<u8>>> {
        if up.kind == Kind::Doh3 {
            *self.h3_asked.lock().unwrap().entry(up.host.clone()).or_default() += 1;
        }
        if self.dead.contains(&up.host) || (up.kind == Kind::Doh3 && self.no_h3.contains(&up.host)) {
            return Box::pin(async { Err(anyhow::anyhow!("逾時")) });
        }
        let to = Upstream::parse(&format!("udp://{}", self.map[&up.host])).unwrap();
        Box::pin(async move { NetProber.exchange(to, q, t).await })
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
        AsnInfo::from_ip_api("Example Web", "Example Web", "AS64496 Example", ""),
    );
    Arc::new(StaticAsn(m))
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("kuroshio-bench-h3-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("benchmark")).unwrap();
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
        default_list_dir: None,
        learn_file: Some(root.join("state/benchmark-learn.json")),
    }
}

/// 四台 DoH：ok（HTTP/3 正常）、noh3（HTTP/3 連不上）、noh3b（同上）、dead（兩種都連不上）
async fn setup(name: &str) -> (PathBuf, BenchPaths, Arc<Mapped>) {
    let mut map = HashMap::new();
    for (i, h) in ["ok.example.com", "noh3.example.com", "noh3b.example.net", "dead.example.net"]
        .iter()
        .enumerate()
    {
        map.insert(h.to_string(), mock(i as u8 + 1).await);
    }
    let root = tmp(name);
    let p = paths(&root);
    let list: Vec<String> = map.keys().map(|h| format!("https://{h}/dns-query")).collect();
    std::fs::write(p.list_dir.join("dohlist.txt"), list.join("\n")).unwrap();
    std::fs::write(p.list_dir.join("web.txt"), "www.example.com\n").unwrap();
    let prober = Arc::new(Mapped {
        map,
        no_h3: ["noh3.example.com", "noh3b.example.net"].iter().map(|s| s.to_string()).collect(),
        dead: ["dead.example.net"].iter().map(|s| s.to_string()).collect(),
        h3_asked: Mutex::new(HashMap::new()),
    });
    (root, p, prober)
}

fn cfg() -> Value {
    kuroshio_config::with_overrides(&json!({
        "upstream": { "autoTypes": ["doh", "doh3"], "autoMax": 5 },
        "benchmark": { "timeoutMs": 300, "concurrency": 8, "paceMs": 0, "maxTimeouts": 1, "minAuto": 1 }
    }))
}

/// 跑一天的評測；回傳 judge.log
async fn run_day(p: &BenchPaths, prober: Arc<Mapped>, clock: &Arc<ManualClock>, path: Option<Report>) -> String {
    let ctx = JobCtx::new("dns-benchmark", "測試", Arc::new(cfg())).with_clock(clock.clone());
    let mut b = Benchmark::with(p.clone(), prober, asn());
    if let Some(r) = path {
        b = b.with_path(r);
    }
    let state = b.run(&ctx).await.unwrap();
    let day = state["date"].as_str().unwrap().to_string();
    std::fs::read_to_string(p.out_root.clone().unwrap().join(day).join("judge.log")).unwrap()
}

fn day0() -> u64 {
    days_from_civil(2026, 11, 20) as u64 * DAY_MS + 12 * HOUR_MS - TPE_OFFSET_MS
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_skip_after_three_days_only_when_https_ok() {
    let (root, p, prober) = setup("three").await;
    let clock = Arc::new(ManualClock::new(day0()));
    let learn_file = p.learn_file.clone().unwrap();
    let noh3 = "h3://noh3.example.com/dns-query";
    // 前兩天：記失敗、還不跳過；同一天再跑一次不多算
    for d in 0..2 {
        run_day(&p, prober.clone(), &clock, None).await;
        if d == 0 {
            run_day(&p, prober.clone(), &clock, None).await;
        }
        let l = Learn::load(&learn_file);
        assert_eq!(l.h3skip[noh3].f, d + 1, "{:?}", l.h3skip);
        assert_eq!(l.h3skip[noh3].until, 0);
        clock.advance(DAY_MS);
    }
    // 第 3 天：開始跳過
    run_day(&p, prober.clone(), &clock, None).await;
    let l = Learn::load(&learn_file);
    let e = l.h3skip[noh3];
    assert_eq!(e.f, 3);
    let today = kuroshio_jobs::benchmark::learn::day_of(day0()) + 2;
    assert!(e.until >= today + 7 && e.until <= today + 10, "{e:?}");
    assert!(l.h3skip.contains_key("h3://noh3b.example.net/dns-query"));
    assert!(!l.h3skip.contains_key("h3://ok.example.com/dns-query"), "HTTP/3 正常的不記");
    assert!(
        !l.h3skip.contains_key("h3://dead.example.net/dns-query"),
        "https:// 自己也失敗：伺服器或線路的問題，不記"
    );
    // 第 4 天：跳過期間不產生這個候選（沒有送出任何 HTTP/3 查詢），judge.log 記總數
    clock.advance(DAY_MS);
    prober.h3_asked.lock().unwrap().clear();
    let log = run_day(&p, prober.clone(), &clock, None).await;
    assert!(log.contains("HTTP/3 先不測 2 個"), "{log}");
    let asked = prober.h3_asked.lock().unwrap().clone();
    assert!(
        !asked.contains_key("noh3.example.com") && !asked.contains_key("noh3b.example.net"),
        "{asked:?}"
    );
    assert!(asked.contains_key("ok.example.com"), "其他照測：{asked:?}");
    // https:// 那一筆照測
    let up: Value = serde_json::from_slice(&std::fs::read(&p.upstreams_file).unwrap()).unwrap();
    let verified = std::fs::read_to_string(
        p.out_root
            .clone()
            .unwrap()
            .join(up["date"].as_str().unwrap())
            .join("verified_dns_list.csv"),
    )
    .unwrap();
    assert!(verified.contains("https://noh3.example.com/dns-query"), "{verified}");
    assert!(!verified.contains("h3://noh3.example.com/dns-query"), "{verified}");
    // https:// 不在名單了：h3skip 那一筆刪掉
    let list = "https://ok.example.com/dns-query\nhttps://noh3b.example.net/dns-query\nhttps://dead.example.net/dns-query\n";
    std::fs::write(p.list_dir.join("dohlist.txt"), list).unwrap();
    clock.advance(DAY_MS);
    run_day(&p, prober.clone(), &clock, None).await;
    let l = Learn::load(&learn_file);
    assert!(!l.h3skip.contains_key(noh3), "{:?}", l.h3skip);
    assert!(l.h3skip.contains_key("h3://noh3b.example.net/dns-query"));
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_skip_not_recorded_when_quic_path_blocked() {
    let (root, p, prober) = setup("blocked").await;
    let clock = Arc::new(ManualClock::new(day0()));
    let learn_file = p.learn_file.clone().unwrap();
    // 路徑檢查判斷 QUIC 被擋：h3:// 整批不測、不記
    let blocked = Report {
        blocked: vec![Proto::Quic],
        ..Report::default()
    };
    for _ in 0..4 {
        run_day(&p, prober.clone(), &clock, Some(blocked.clone())).await;
        clock.advance(DAY_MS);
    }
    assert!(Learn::load(&learn_file).h3skip.is_empty());
    assert!(prober.h3_asked.lock().unwrap().is_empty(), "QUIC 被擋時不測 h3://");
    // 路徑檢查沒抓到、但今天沒有任何 h3:// 連得上（可能是 QUIC 整條被擋）：也不記
    let all_fail = Arc::new(Mapped {
        map: prober.map.clone(),
        no_h3: prober.map.keys().cloned().collect(),
        dead: prober.dead.clone(),
        h3_asked: Mutex::new(HashMap::new()),
    });
    for _ in 0..4 {
        run_day(&p, all_fail.clone(), &clock, None).await;
        clock.advance(DAY_MS);
    }
    assert!(Learn::load(&learn_file).h3skip.is_empty(), "{:?}", Learn::load(&learn_file).h3skip);
    // 路恢復了：照常記（不用等 30 天）
    run_day(&p, prober.clone(), &clock, None).await;
    assert_eq!(Learn::load(&learn_file).h3skip.len(), 2);
    let _ = std::fs::remove_dir_all(&root);
}

/// 跳過到期再測：成功就整筆刪掉（伺服器之後支援 HTTP/3 就回來）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_retry_after_skip_recovers() {
    let (root, p, prober) = setup("retry").await;
    let clock = Arc::new(ManualClock::new(day0()));
    let learn_file = p.learn_file.clone().unwrap();
    for _ in 0..3 {
        run_day(&p, prober.clone(), &clock, None).await;
        clock.advance(DAY_MS);
    }
    let until = Learn::load(&learn_file).h3skip["h3://noh3.example.com/dns-query"].until;
    // 跳到到期那天，而且伺服器已經支援 HTTP/3
    let today = kuroshio_jobs::benchmark::learn::day_of(clock.now_ms());
    clock.advance((until - today) as u64 * DAY_MS);
    let fixed = Arc::new(Mapped {
        map: prober.map.clone(),
        no_h3: ["noh3b.example.net"].iter().map(|s| s.to_string()).collect(),
        dead: prober.dead.clone(),
        h3_asked: Mutex::new(HashMap::new()),
    });
    run_day(&p, fixed.clone(), &clock, None).await;
    let l = Learn::load(&learn_file);
    assert!(!l.h3skip.contains_key("h3://noh3.example.com/dns-query"), "{:?}", l.h3skip);
    // 另一台到期再測還是失敗：1 次就進下一輪（14～17 天）
    let e = l.h3skip["h3://noh3b.example.net/dns-query"];
    let today = kuroshio_jobs::benchmark::learn::day_of(clock.now_ms());
    assert!(e.until >= today + 14 && e.until <= today + 17, "{e:?}");
    assert_eq!(e.n, 2);
    let _ = std::fs::remove_dir_all(&root);
}
