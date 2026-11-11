//! 每日評測端對端：本機假 DNS 伺服器（正常 / 汙染 / 封殺 / 慢 / 不回應 / 資格賽失敗），
//! 經過排程器執行，檢查寫出的 upstreams.json、永久黑名單、報表，並確認伺服器（kuroshio）讀得懂。

use kuroshio_jobs::benchmark::probe::{classify, AsnSource, NetProber, Outcome, Prober, StaticAsn};
use kuroshio_jobs::benchmark::rules::AsnInfo;
use kuroshio_jobs::scheduler::BoxFuture;
use kuroshio_jobs::time::{days_from_civil, ManualClock, DAY_MS, HOUR_MS, TPE_OFFSET_MS};
use kuroshio_jobs::{BenchPaths, Benchmark, JobCtx, Options, Scheduler};
use kuroshio_net::upstream::{Kind, Upstream};
use kuroshio_proto::message::Record;
use kuroshio_proto::Message;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

#[derive(Clone)]
enum Reply {
    A(Vec<Ipv4Addr>),
    Nx,
    Drop,
}

fn ip(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

/// 正常的 DNS：每個網域回固定的 IP
fn honest(name: &str, n: u8) -> Reply {
    match name {
        "one.one.one.one" => Reply::A(vec![ip("1.1.1.1"), ip("1.0.0.1")]),
        "www.alpha.com" => Reply::A(vec![Ipv4Addr::new(93, 1, 0, n)]),
        "cdn.beta.com" => Reply::A(vec![Ipv4Addr::new(94, 2, 0, n)]),
        "video.gamma.net" => Reply::A(vec![Ipv4Addr::new(95, 3, 0, n)]),
        _ => Reply::Nx,
    }
}

/// 假 DNS 伺服器：每個回應延遲 `delay_ms` 毫秒（各自獨立，不會互相排隊）
async fn mock(bind: &str, delay_ms: u64, f: impl Fn(&str) -> Reply + Send + Sync + 'static) -> SocketAddr {
    let sock = Arc::new(UdpSocket::bind(bind).await.unwrap());
    let addr = sock.local_addr().unwrap();
    let f = Arc::new(f);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else { break };
            let Ok(q) = Message::parse(&buf[..n]) else { continue };
            let name = q.question().map(|x| x.name.clone()).unwrap_or_default();
            let reply = f(&name);
            let sock = sock.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                let mut r = Message::response_to(&q, 0);
                match reply {
                    Reply::A(ips) => r.answers.extend(ips.into_iter().map(|i| Record::a(&name, 60, i))),
                    Reply::Nx => r.rcode = 3,
                    Reply::Drop => return,
                }
                let _ = sock.send_to(&r.encode(), peer).await;
            });
        }
    });
    addr
}

/// 只測本機 UDP（DoH 等其他類型當成不支援，順便測「略過」的計數）
struct LocalOnly;

impl Prober for LocalOnly {
    fn supports(&self, up: &Upstream) -> bool {
        matches!(up.kind, Kind::Udp | Kind::Tcp) && up.supported()
    }
    fn exchange(&self, up: Upstream, q: Vec<u8>, t: Duration) -> BoxFuture<anyhow::Result<Vec<u8>>> {
        NetProber.exchange(up, q, t)
    }
    fn resolve_v4(&self, _host: String) -> BoxFuture<Option<Ipv4Addr>> {
        Box::pin(async { None })
    }
}

fn asn() -> Arc<dyn AsnSource> {
    let mut m = HashMap::new();
    let mut add = |k: &str, isp: &str, as_: &str| {
        m.insert(k.to_string(), AsnInfo::from_ip_api(isp, isp, as_));
    };
    add("93.1", "Alpha Networks", "AS100 Alpha Networks");
    add("94.2", "Beta Hosting", "AS200 Beta Hosting");
    add("95.3", "Gamma Cloud", "AS300 Gamma Cloud");
    add("96.4", "Evil Corp", "AS666 Evil Corp");
    for i in 1..=9 {
        add(&format!("127.{i}"), &format!("Owner{i} Ltd"), &format!("AS90{i} Owner{i}"));
    }
    Arc::new(StaticAsn(m))
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("kuroshio-bench-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn tpe(y: i64, m: u32, d: u32, h: u64) -> u64 {
    days_from_civil(y, m, d) as u64 * DAY_MS + h * HOUR_MS - TPE_OFFSET_MS
}

fn paths(root: &Path) -> BenchPaths {
    BenchPaths {
        list_dir: root.join("benchmark"),
        out_root: Some(root.join("state/benchmark")),
        upstreams_file: root.join("state/upstreams.json"),
        community_candidates: Some(root.join("state/community/upstream-candidates.json")),
    }
}

fn read(p: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn end_to_end_with_mock_servers() {
    let s1 = mock("127.1.0.1:0", 0, |n| honest(n, 1)).await;
    let s2 = mock("127.2.0.1:0", 20, |n| honest(n, 2)).await;
    let s3 = mock("127.3.0.1:0", 0, |n| match n {
        "www.alpha.com" => Reply::A(vec![ip("96.4.0.1")]), // 汙染：解析到別家業者
        _ => honest(n, 1),
    })
    .await;
    let s4 = mock("127.4.0.1:0", 0, |n| match n {
        "cdn.beta.com" => Reply::A(vec![ip("0.0.0.0")]), // 封殺
        _ => honest(n, 1),
    })
    .await;
    let s5 = mock("127.5.0.1:0", 120, |n| honest(n, 1)).await; // 慢、沒有獨有 IP
    let s6 = mock("127.6.0.1:0", 0, |_| Reply::Drop).await; // 不回應
    let s7 = mock("127.7.0.1:0", 0, |n| match n {
        "one.one.one.one" => Reply::A(vec![ip("9.9.9.9")]), // 資格賽失敗
        _ => honest(n, 1),
    })
    .await;
    let s8 = mock("127.8.0.1:0", 0, |n| match n {
        "one.one.one.one" => honest(n, 1),
        _ => Reply::Drop, // 逾時太多次
    })
    .await;
    let pinned = mock("127.9.0.1:0", 5, |n| match n {
        "www.alpha.com" => Reply::A(vec![ip("96.4.0.1")]), // 固定上游也汙染：只記問題，不淘汰
        _ => honest(n, 1),
    })
    .await;
    let s10 = mock("127.1.0.10:0", 0, |n| honest(n, 1)).await; // 在永久黑名單裡

    let root = tmp("e2e");
    let p = paths(&root);
    let list = &p.list_dir;
    std::fs::create_dir_all(list).unwrap();
    let iplist: Vec<String> = [s1, s2, s3, s4, s5, s6, s7, s8, s10].iter().map(|a| a.to_string()).collect();
    std::fs::write(
        list.join("iplist.txt"),
        format!("\u{feff}{}\r\n# 註解\r\n{}\r\n", iplist.join("\r\n"), s1),
    )
    .unwrap();
    std::fs::write(list.join("dohlist.txt"), "https://dns.example/dns-query\n").unwrap();
    std::fs::write(list.join("doqlist.txt"), "quic://dns.example\n").unwrap();
    std::fs::write(list.join("stamps.txt"), "sdns://AgcAAAAAAAAAAAAHOS45LjkuOQ\n").unwrap();
    std::fs::write(list.join("web.txt"), "www.alpha.com\ncdn.beta.com\nvideo.gamma.net\ndead.example\n").unwrap();
    std::fs::write(list.join("blacklist.txt"), format!("# 黑名單\n{s10}  # 測試\n")).unwrap();
    // 舊報表：超過 14 天的刪掉
    let out_root = p.out_root.clone().unwrap();
    std::fs::create_dir_all(out_root.join("2026-10-01")).unwrap();
    std::fs::create_dir_all(out_root.join("2026-11-01")).unwrap();

    let pinned_id = format!("udp://{pinned}");
    let cfg = kuroshio_config::with_overrides(&json!({
        "upstream": { "pinned": [pinned_id], "autoTypes": ["udp", "doh", "dot"], "autoMax": 3 },
        "benchmark": { "timeoutMs": 300, "concurrency": 4, "maxTimeouts": 1, "minAuto": 3 },
        "jobs": { "dns-benchmark": { "at": "04:10", "catchUp": false } }
    }));
    let clock = Arc::new(ManualClock::new(tpe(2026, 11, 10, 12)));
    let mut o = Options::new(root.join("state"), &root);
    o.clock = clock.clone();
    let sched = Scheduler::new(cfg.clone(), None, o);
    sched.register("dns-benchmark", Benchmark::with(p.clone(), Arc::new(LocalOnly), asn()));
    let h = sched.start();
    assert_eq!(sched.request("dns-benchmark", "測試")["ok"], true);
    for _ in 0..600 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if !sched.is_busy() {
            break;
        }
    }
    h.abort();
    let st = sched.status();
    assert_eq!(st["state"]["dns-benchmark"]["lastCode"], 0, "{st}");

    let up = read(&p.upstreams_file);
    let sel: Vec<(String, String, u64)> = up["selected"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            (
                x["id"].as_str().unwrap().into(),
                x["reason"].as_str().unwrap().into(),
                x["newItems"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        sel,
        vec![
            (s1.to_string(), "最快".into(), 1),
            (s2.to_string(), "覆蓋".into(), 3),
            (s5.to_string(), "備援".into(), 0),
        ],
        "{up:#}"
    );
    for x in up["selected"].as_array().unwrap() {
        assert_eq!(x["type"], "udp");
    }
    assert_eq!(up["selected"][0]["owner"], "Owner1_Ltd__AS901_Owner1");
    assert_eq!(up["date"], "2026-11-10");
    assert_eq!(up["universe"], 7);
    assert_eq!(up["coverage"], json!(0.8571));
    assert_eq!(up["counts"], json!({ "total": 9, "verified": 7, "survivors": 4, "eliminated": 5 }));
    assert_eq!(
        up["blocked"],
        json!([{ "dns": s4.to_string(), "domain": "cdn.beta.com", "reason": "導向 0.0.0.0", "pinned": false }])
    );
    assert_eq!(up["pinned"][0]["id"], pinned_id);
    assert_eq!(up["pinned"][0]["coverageItems"], 2);
    assert_eq!(
        up["pinned"][0]["issues"],
        json!(["汙染 www.alpha.com (判定為 Evil_Corp__AS666_Evil_Corp)"])
    );
    assert_eq!(up["skippedTypes"], json!({ "dnscrypt": 1, "doh": 1, "doh3": 1, "doq": 1 }));
    assert!(up["generatedAt"].as_str().unwrap().starts_with("2026-11-10T04:00:00"));

    // 汙染的加入永久黑名單
    let bl = std::fs::read_to_string(list.join("blacklist.txt")).unwrap();
    assert!(
        bl.contains(&format!("{s3}  # 2026-11-10 汙染：www.alpha.com → Evil_Corp__AS666_Evil_Corp")),
        "{bl}"
    );
    assert!(!bl.contains(&s4.to_string()));

    // 報表
    let day = out_root.join("2026-11-10");
    for f in [
        "verified_dns_list.csv",
        "final_dns_smart.csv",
        "dns_coverage_optimization.csv",
        "dns_latency_optimization.csv",
        "dns_asn_coverage_optimization.csv",
        "dns_asn_latency_optimization.csv",
        "eliminated.csv",
        "upstreams.json",
    ] {
        assert!(day.join(f).exists(), "{f}");
    }
    let elim = std::fs::read_to_string(day.join("eliminated.csv")).unwrap();
    assert!(elim.contains(&format!("{s6},udp,\"資格賽失敗 (逾時)\"")), "{elim}");
    assert!(elim.contains(&format!("{s7},udp,\"資格賽失敗 (9.9.9.9)\"")), "{elim}");
    assert!(elim.contains(&format!("{s8},udp,\"連線失敗 (逾時)\"")), "{elim}");
    assert!(elim.contains(&format!("{s4},udp,\"封殺 cdn.beta.com (導向 0.0.0.0)\"")), "{elim}");
    assert!(!out_root.join("2026-10-01").exists());
    assert!(out_root.join("2026-11-01").exists());
    assert!(out_root.join("cidr_cache.json").exists());
    let cache = read(&out_root.join("cidr_cache.json"));
    assert_eq!(
        cache["93.1"]["keywords"],
        json!(["alpha", "networks", "alpha", "networks", "as100", "alpha", "networks"])
    );

    // 伺服器端（kuroshio 的上游管理）讀得懂
    let m = kuroshio::upstreams::Manager::new(&cfg, p.upstreams_file.clone());
    let ids: Vec<String> = m.active().iter().map(|u| u.up.id.clone()).collect();
    assert_eq!(
        ids,
        vec![
            pinned_id.clone(),
            format!("udp://{s1}"),
            format!("udp://{s2}"),
            format!("udp://{s5}")
        ]
    );

    // 第二天：所有候選都過不了資格賽 → 失敗，保留昨天的結果
    let before = std::fs::read(&p.upstreams_file).unwrap();
    std::fs::write(list.join("iplist.txt"), format!("{s6}\n{s7}\n")).unwrap();
    let ctx = JobCtx::new("dns-benchmark", "測試", Arc::new(cfg.clone())).with_clock(clock.clone());
    let b = Benchmark::with(p.clone(), Arc::new(LocalOnly), asn());
    let err = b.run(&ctx).await.unwrap_err();
    assert!(err.to_string().contains("沒有任何 DNS 通過資格賽"), "{err}");
    assert_eq!(std::fs::read(&p.upstreams_file).unwrap(), before);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn classify_answers() {
    let q = Message::parse(&kuroshio_proto::build_query(1, "a.com", 1)).unwrap();
    let mk = |rcode: u16, ips: &[&str]| {
        let mut r = Message::response_to(&q, rcode);
        r.answers.extend(ips.iter().map(|i| Record::a("a.com", 60, ip(i))));
        r.encode()
    };
    assert_eq!(classify(&mk(0, &["1.2.3.4"])), Outcome::Ok(vec![ip("1.2.3.4")]));
    assert_eq!(classify(&mk(3, &[])), Outcome::Blocked("NXDOMAIN".into()));
    assert_eq!(classify(&mk(0, &[])), Outcome::Blocked("無 A 記錄".into()));
    assert_eq!(classify(&mk(0, &["0.0.0.0"])), Outcome::Blocked("導向 0.0.0.0".into()));
    assert_eq!(
        classify(&mk(0, &["10.0.0.1", "146.112.61.104"])),
        Outcome::Blocked("導向 10.0.0.1".into())
    );
    assert_eq!(
        classify(&mk(0, &["10.0.0.1", "1.2.3.4"])),
        Outcome::Ok(vec![ip("10.0.0.1"), ip("1.2.3.4")])
    );
    assert_eq!(classify(&mk(5, &[])), Outcome::Error("REFUSED".into()));
    assert_eq!(classify(&mk(2, &[])), Outcome::Error("SERVFAIL".into()));
    assert_eq!(classify(&[1, 2, 3]), Outcome::Error("BAD_PACKET".into()));
}

/// 真的連上網路測（沙箱裡通常不通）：cargo test -p kuroshio-jobs -- --ignored
#[tokio::test]
#[ignore]
async fn real_internet_smoke() {
    let root = tmp("real");
    let p = paths(&root);
    std::fs::create_dir_all(&p.list_dir).unwrap();
    std::fs::write(p.list_dir.join("iplist.txt"), "1.1.1.1\n8.8.8.8\n9.9.9.9\n").unwrap();
    std::fs::write(p.list_dir.join("dohlist.txt"), "https://dns.google/dns-query\n").unwrap();
    std::fs::write(p.list_dir.join("web.txt"), "www.google.com\nwww.apple.com\n").unwrap();
    let cfg = kuroshio_config::with_overrides(&json!({ "upstream": { "autoMax": 3 } }));
    let ctx = JobCtx::new("dns-benchmark", "測試", Arc::new(cfg));
    let state = Benchmark::new(p.clone()).run(&ctx).await.unwrap();
    assert!(!state["selected"].as_array().unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&root);
}
