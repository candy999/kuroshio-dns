//! 3.5.0 A2：對照組（protected.txt）
//! - 資格賽網域被擋（NXDOMAIN、導到封鎖頁）是判出過濾，照樣測網域；連線失敗、逾時照舊是沒測到
//! - 跨天回歸（學習檔的 control）：以前判得出、今天沒判出 → regress，只報告、不改變選出來的上游
//!
//! 本機假 DNS 伺服器、注入的時鐘

use kuroshio_jobs::benchmark::learn::Learn;
use kuroshio_jobs::benchmark::probe::{AsnSource, NetProber, Prober, SiteCheck, StaticAsn};
use kuroshio_jobs::benchmark::rules::AsnInfo;
use kuroshio_jobs::scheduler::BoxFuture;
use kuroshio_jobs::time::{days_from_civil, ManualClock, DAY_MS, HOUR_MS, TPE_OFFSET_MS};
use kuroshio_jobs::{BenchPaths, Benchmark, JobCtx};
use kuroshio_net::upstream::{Kind, Upstream};
use kuroshio_proto::message::Record;
use kuroshio_proto::Message;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

#[derive(Clone)]
enum Reply {
    A(Vec<Ipv4Addr>),
    Nx,
    Drop,
}

fn honest(name: &str, n: u8) -> Reply {
    match name {
        "one.one.one.one" => Reply::A(vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 0, 0, 1)]),
        "www.example.com" => Reply::A(vec![Ipv4Addr::new(93, 1, 0, n)]),
        "adult.example.net" => Reply::A(vec![Ipv4Addr::new(94, 2, 0, n)]),
        _ => Reply::Nx,
    }
}

async fn mock(f: impl Fn(&str) -> Reply + Send + Sync + 'static) -> String {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr: SocketAddr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else { break };
            let Ok(q) = Message::parse(&buf[..n]) else { continue };
            let name = q.question().map(|x| x.name.clone()).unwrap_or_default();
            let mut r = Message::response_to(&q, 0);
            match f(&name) {
                Reply::A(ips) => r.answers.extend(ips.into_iter().map(|i| Record::a(&name, 60, i))),
                Reply::Nx => r.rcode = 3,
                Reply::Drop => continue,
            }
            let _ = sock.send_to(&r.encode(), peer).await;
        }
    });
    addr.to_string()
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
    /// 93.1 / 94.2 是正常回答（憑證有效）；其他（封鎖頁）憑證不符
    fn verify_site(&self, ip: std::net::IpAddr, _d: String, _t: Duration) -> BoxFuture<(SiteCheck, String)> {
        let s = ip.to_string();
        Box::pin(async move {
            if s.starts_with("93.1.") || s.starts_with("94.2.") {
                (SiteCheck::Valid, "OK".to_string())
            } else {
                (SiteCheck::Invalid, "ERR_TLS_CERT_ALTNAME_INVALID".to_string())
            }
        })
    }
}

fn asn() -> Arc<dyn AsnSource> {
    let mut m = HashMap::new();
    let mut add = |k: &str, isp: &str, as_: &str| {
        m.insert(k.to_string(), AsnInfo::from_ip_api(isp, isp, as_, ""));
    };
    add("93.1", "Example Web", "AS64496 Example Web");
    add("94.2", "Example Adult", "AS64497 Example Adult");
    add("198.51", "Block Page", "AS64498 Block Page");
    Arc::new(StaticAsn(m))
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("kuroshio-bench-control-{name}-{}", std::process::id()));
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

/// 4 台正常的一般 DNS（評測的多數）
async fn normal(root: &Path) -> Vec<String> {
    let mut ids = Vec::new();
    for n in 1..=4u8 {
        ids.push(mock(move |d| honest(d, n)).await);
    }
    std::fs::write(root.join("benchmark/iplist.txt"), ids.join("\n")).unwrap();
    std::fs::write(root.join("benchmark/web.txt"), "www.example.com\nadult.example.net\n").unwrap();
    ids
}

fn day0() -> u64 {
    days_from_civil(2026, 11, 20) as u64 * DAY_MS + 12 * HOUR_MS - TPE_OFFSET_MS
}

async fn run(p: &BenchPaths, clock: &Arc<ManualClock>) -> Value {
    let cfg = kuroshio_config::with_overrides(&json!({
        "upstream": { "pinned": [], "autoTypes": ["udp"], "autoMax": 3 },
        "benchmark": { "timeoutMs": 300, "concurrency": 8, "paceMs": 0, "maxTimeouts": 1, "minAuto": 1 }
    }));
    let ctx = JobCtx::new("dns-benchmark", "測試", Arc::new(cfg)).with_clock(clock.clone());
    Benchmark::with(p.clone(), Arc::new(LocalOnly), asn()).run(&ctx).await.unwrap()
}

fn control<'a>(up: &'a Value, id: &str) -> &'a Value {
    up["protected"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap_or_else(|| panic!("{id} 不在對照組結果：{up:#}"))
}

fn report(p: &BenchPaths, up: &Value, name: &str) -> String {
    std::fs::read_to_string(p.out_root.clone().unwrap().join(up["date"].as_str().unwrap()).join(name)).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_blocked_in_preflight_is_detected() {
    let root = tmp("preflight");
    let p = paths(&root);
    let ids = normal(&root).await;
    // 資格賽網域回 NXDOMAIN，其他正常（評測網域判不出它擋的類型）
    let nx = mock(|d| if d == "one.one.one.one" { Reply::Nx } else { honest(d, 40) }).await;
    // 資格賽網域導到封鎖頁（不是預期的位址），其他正常
    let page = mock(|d| {
        if d == "one.one.one.one" {
            Reply::A(vec![Ipv4Addr::new(198, 51, 100, 7)])
        } else {
            honest(d, 41)
        }
    })
    .await;
    // 資格賽網域被擋，成人網站也擋（網域判斷判得出）
    let both = mock(|d| match d {
        "one.one.one.one" | "adult.example.net" => Reply::Nx,
        _ => honest(d, 42),
    })
    .await;
    // 只擋惡意網站：A5 之前評測判不出來，預期值是 null
    let malware = mock(|d| honest(d, 43)).await;
    std::fs::write(
        p.list_dir.join("protected.txt"),
        format!("{nx}  # filter=adult\n{page}  # filter=ads,adult\n{both}  # filter=adult\n{malware}  # filter=malware\n"),
    )
    .unwrap();
    let clock = Arc::new(ManualClock::new(day0()));
    let up = run(&p, &clock).await;

    let c = control(&up, &nx);
    assert_eq!(
        (c["result"].as_str(), c["stage"].as_str()),
        (Some("detected"), Some("preflight")),
        "{c}"
    );
    assert_eq!(c["reason"], "封殺 one.one.one.one（資格賽：NXDOMAIN）");
    assert_eq!(c["preflight"], c["reason"]);
    assert_eq!(c["expectMet"], false, "成人網站沒判出：資格賽網域被擋不算");
    assert_eq!(c["recent"], "d");
    assert_eq!(c["regress"], false);
    let c = control(&up, &page);
    assert_eq!(
        (c["result"].as_str(), c["stage"].as_str()),
        (Some("detected"), Some("preflight")),
        "{c}"
    );
    assert_eq!(c["reason"], "封殺 one.one.one.one（資格賽：導向 198.51.100.7）");
    let c = control(&up, &both);
    assert_eq!(
        (c["result"].as_str(), c["stage"].as_str()),
        (Some("detected"), Some("domain")),
        "照樣測網域：{c}"
    );
    assert!(c["reason"].as_str().unwrap().starts_with("封殺 adult.example.net"), "{c}");
    assert_eq!(c["preflight"], "封殺 one.one.one.one（資格賽：NXDOMAIN）");
    assert_eq!(c["expectMet"], true);
    let c = control(&up, &malware);
    assert_eq!((c["result"].as_str(), c["stage"].as_str()), (Some("passed"), Some("domain")));
    assert_eq!(c["expectMet"], Value::Null, "惡意網站的探測還沒有（A5）");
    assert_eq!(c["preflight"], Value::Null);
    // 對照組永遠不選、正常的照選
    let picked = up["selected"].to_string();
    for x in [&nx, &page, &both, &malware] {
        assert!(!picked.contains(x.as_str()), "{picked}");
    }
    assert!(ids.iter().any(|h| picked.contains(h.as_str())));
    assert_eq!(up["counts"]["survivors"], 4, "{up:#}");
    // 報表：最後多 stage 等欄位，舊的欄位順序不變
    let csv = report(&p, &up, "protected.csv");
    assert!(
        csv.starts_with("dns,type,expect,result,reason,stage,preflight,recent,regress,expectMet\n"),
        "{csv}"
    );
    assert!(
        csv.contains(&format!(
            "{nx},udp,adult,detected,封殺 one.one.one.one（資格賽：NXDOMAIN）,preflight,"
        )),
        "{csv}"
    );
    let log = report(&p, &up, "judge.log");
    assert!(log.contains("資格賽網域被擋（NXDOMAIN）：記為判出過濾，照樣測網域"), "{log}");
    assert!(
        log.contains("[對照組] 4 台：判出過濾 3（資格賽網域被擋 2）、沒判出 1、沒測到 0、回歸 0"),
        "{log}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_timeout_in_preflight_is_untested() {
    let root = tmp("timeout");
    let p = paths(&root);
    normal(&root).await;
    let dead = mock(|_| Reply::Drop).await;
    std::fs::write(p.list_dir.join("protected.txt"), format!("{dead}  # filter=adult\n")).unwrap();
    let clock = Arc::new(ManualClock::new(day0()));
    let up = run(&p, &clock).await;
    let c = control(&up, &dead);
    assert_eq!(
        (c["result"].as_str(), c["stage"].as_str()),
        (Some("untested"), Some("preflight")),
        "{c}"
    );
    assert!(c["reason"].as_str().unwrap().starts_with("資格賽失敗"), "{c}");
    assert_eq!(c["expectMet"], Value::Null);
    assert_eq!(c["recent"], "u");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_regression_reported_not_enforced() {
    let root = tmp("regress");
    let p = paths(&root);
    normal(&root).await;
    // 前 3 天擋成人網站（判出），第 4 天不擋了（評測判不出來）
    let blocking = Arc::new(AtomicBool::new(true));
    let b2 = blocking.clone();
    let ctl = mock(move |d| {
        if d == "adult.example.net" && b2.load(Ordering::Relaxed) {
            Reply::Nx
        } else {
            honest(d, 50)
        }
    })
    .await;
    std::fs::write(p.list_dir.join("protected.txt"), format!("{ctl}  # filter=adult\n")).unwrap();
    let clock = Arc::new(ManualClock::new(day0()));
    for _ in 0..3 {
        let up = run(&p, &clock).await;
        assert_eq!(control(&up, &ctl)["regress"], false);
        clock.advance(DAY_MS);
    }
    // 中間有一天沒跑：補 -
    clock.advance(DAY_MS);
    blocking.store(false, Ordering::Relaxed);
    let up = run(&p, &clock).await;
    let c = control(&up, &ctl);
    assert_eq!(c["result"], "passed");
    assert_eq!(c["recent"], "p-ddd");
    assert_eq!(c["regress"], true, "{c}");
    assert_eq!(c["expectMet"], false);
    let log = report(&p, &up, "judge.log");
    assert!(log.contains(&format!("[對照組] {ctl} 以前判得出過濾，今天沒判出")), "{log}");
    assert!(log.contains("回歸 1"), "{log}");
    let l = Learn::load(&p.learn_file.clone().unwrap());
    assert_eq!(l.control[&ctl], "p-ddd");
    // 只報告：選擇跟沒有對照組時一樣（倖存、覆蓋、選出的台數；本機延遲有誤差，不比哪一台最快）
    std::fs::remove_file(p.list_dir.join("protected.txt")).unwrap();
    let without = run(&p, &clock).await;
    for k in ["universe", "coverage"] {
        assert_eq!(up[k], without[k], "{k}");
    }
    assert_eq!(up["counts"]["survivors"], without["counts"]["survivors"]);
    assert_eq!(up["counts"]["eliminated"], without["counts"]["eliminated"]);
    assert_eq!(
        up["selected"].as_array().unwrap().len(),
        without["selected"].as_array().unwrap().len()
    );
    assert!(!up["selected"].to_string().contains(&ctl));
    // 名單裡已經沒有的對照組：學習檔刪掉
    assert!(Learn::load(&p.learn_file.clone().unwrap()).control.is_empty());
    let _ = std::fs::remove_dir_all(&root);
}

/// 3.5.0 D3 第 3 輪之後：沒寫 `filter=` 的對照組是「觀察中（不設期望）」——照常測、照常記結果，
/// 但 `expectMet` 是 null、不判回歸（同樣「以前判出、今天沒判出」的情況，有期望的會被報成回歸）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_without_expectation_is_observed_not_regressed() {
    let root = tmp("observe");
    let p = paths(&root);
    normal(&root).await;
    let blocking = Arc::new(AtomicBool::new(true));
    let b2 = blocking.clone();
    let watch = mock(move |d| {
        if d == "adult.example.net" && b2.load(Ordering::Relaxed) {
            Reply::Nx
        } else {
            honest(d, 60)
        }
    })
    .await;
    std::fs::write(
        p.list_dir.join("protected.txt"),
        format!("{watch}  # 觀察中（不設期望）：實測沒判出，待更多實測再定\n"),
    )
    .unwrap();
    let clock = Arc::new(ManualClock::new(day0()));
    for _ in 0..3 {
        let up = run(&p, &clock).await;
        let c = control(&up, &watch);
        assert_eq!((c["result"].as_str(), c["expect"].as_str()), (Some("detected"), Some("?")), "{c}");
        assert_eq!(c["expectMet"], Value::Null);
        clock.advance(DAY_MS);
    }
    blocking.store(false, Ordering::Relaxed);
    let up = run(&p, &clock).await;
    let c = control(&up, &watch);
    assert_eq!(c["result"], "passed");
    assert_eq!(c["recent"], "pddd", "結果照常記");
    assert_eq!(c["regress"], false, "不設期望的不判回歸：{c}");
    assert_eq!(c["expectMet"], Value::Null);
    let log = report(&p, &up, "judge.log");
    assert!(!log.contains("以前判得出過濾，今天沒判出"), "{log}");
    assert!(log.contains("回歸 0"), "{log}");
    assert!(log.contains(&format!("沒判出：{watch}（觀察中，不設期望）")), "{log}");
    let _ = std::fs::remove_dir_all(&root);
}
