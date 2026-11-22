//! 評測依路徑判斷調整（3.3.6）：
//! - 一般 DNS 的答案完全一樣時只算一票（攔截者的幾百票不能變成「多數」）
//! - 路徑檢查判斷一般 DNS 被接走、IPv6 不能用時，那些候選不測、不記可疑
//! - 好幾家互相獨立的加密 DNS 都「網站無法驗證」時，照常計分、今天照用，不記可疑天數
//! - 對照組（protected.txt）：照常測、照常判，永遠不選、不記可疑、不看永久黑名單（3.4.2）

use kuroshio_jobs::benchmark::probe::{AsnSource, NetProber, Prober, SiteCheck, StaticAsn};
use kuroshio_jobs::benchmark::rules::AsnInfo;
use kuroshio_jobs::scheduler::BoxFuture;
use kuroshio_jobs::time::{days_from_civil, ManualClock, DAY_MS, HOUR_MS, TPE_OFFSET_MS};
use kuroshio_jobs::{BenchPaths, Benchmark, Options, Scheduler};
use kuroshio_net::path::{Plain, Report, V6Route};
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

fn ip(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

/// 正常的回答：每台的 www.alpha.com 位址不同（不會被當成同一個攔截者）
fn honest(name: &str, n: u8) -> Option<Vec<Ipv4Addr>> {
    match name {
        "one.one.one.one" => Some(vec![ip("1.1.1.1"), ip("1.0.0.1")]),
        "www.alpha.com" => Some(vec![Ipv4Addr::new(93, 1, 0, n)]),
        "cdn.beta.com" => Some(vec![Ipv4Addr::new(94, 2, 0, n)]),
        _ => None,
    }
}

async fn mock(f: impl Fn(&str) -> Option<Vec<Ipv4Addr>> + Send + Sync + 'static) -> SocketAddr {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else { break };
            let Ok(q) = Message::parse(&buf[..n]) else { continue };
            let name = q.question().map(|x| x.name.clone()).unwrap_or_default();
            let mut r = Message::response_to(&q, 0);
            match f(&name) {
                Some(ips) => r.answers.extend(ips.into_iter().map(|i| Record::a(&name, 60, i))),
                None => r.rcode = 3,
            }
            let _ = sock.send_to(&r.encode(), peer).await;
        }
    });
    addr
}

/// 一般 DNS 走本機 UDP；DoH 候選依主機名稱轉到對應的本機假伺服器（模擬不同業者的加密 DNS）
struct Mapped(HashMap<String, SocketAddr>);

impl Prober for Mapped {
    fn supports(&self, up: &Upstream) -> bool {
        match up.kind {
            Kind::Udp | Kind::Tcp => up.supported(),
            Kind::Doh => self.0.contains_key(&up.host),
            _ => false,
        }
    }
    fn exchange(&self, up: Upstream, q: Vec<u8>, t: Duration) -> BoxFuture<anyhow::Result<Vec<u8>>> {
        match up.kind {
            Kind::Doh => {
                let to = Upstream::parse(&format!("udp://{}", self.0[&up.host])).unwrap();
                Box::pin(async move { to.exchange(&q, t).await })
            }
            _ => NetProber.exchange(up, q, t),
        }
    }
    fn resolve_v4(&self, _host: String) -> BoxFuture<Option<Ipv4Addr>> {
        Box::pin(async { None })
    }
    /// 93 / 94 是正常回答（憑證有效）；其他都連不上（網站無法驗證）
    fn verify_site(&self, ip: std::net::IpAddr, _d: String, _t: Duration) -> BoxFuture<(SiteCheck, String)> {
        let s = ip.to_string();
        Box::pin(async move {
            // 95.3 / 97.5：規則外，但真的在服務網站的 CDN（憑證有效）
            if s.starts_with("93.1.") || s.starts_with("94.2.") || s.starts_with("95.3.") || s.starts_with("97.5.") {
                (SiteCheck::Valid, "OK".to_string())
            } else {
                (SiteCheck::Unverified, "ETIMEDOUT".to_string())
            }
        })
    }
}

fn asn() -> Arc<dyn AsnSource> {
    let mut m = HashMap::new();
    let mut add = |k: &str, isp: &str, as_: &str| {
        m.insert(k.to_string(), AsnInfo::from_ip_api(isp, isp, as_, ""));
    };
    add("93.1", "Alpha Networks", "AS100 Alpha Networks");
    add("94.2", "Beta Hosting", "AS200 Beta Hosting");
    add("98.6", "Quiet Hosting", "AS888 Quiet Hosting");
    add("95.3", "Gamma Cloud", "AS300 Gamma Cloud");
    add("97.5", "Unknown CDN", "AS777 Unknown CDN");
    add("99.7", "Plain Web", "AS999 Plain Web");
    add("1.1", "Cloudflare", "AS13335 Cloudflare");
    add("1.0", "Cloudflare", "AS13335 Cloudflare");
    Arc::new(StaticAsn(m))
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("kuroshio-bpath-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("state")).unwrap();
    std::fs::create_dir_all(d.join("benchmark")).unwrap();
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

fn read(p: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

async fn run(root: &Path, b: Benchmark, types: &[&str]) {
    let cfg = kuroshio_config::with_overrides(&json!({
        "upstream": { "pinned": [], "autoTypes": types, "autoMax": 6 },
        "benchmark": { "timeoutMs": 300, "concurrency": 8, "maxTimeouts": 1, "minAuto": 1 },
        "jobs": { "dns-benchmark": { "at": "04:10", "catchUp": false } }
    }));
    let now = days_from_civil(2026, 11, 20) as u64 * DAY_MS + 12 * HOUR_MS - TPE_OFFSET_MS;
    let mut o = Options::new(root.join("state"), root);
    o.clock = Arc::new(ManualClock::new(now));
    let sched = Scheduler::new(cfg, None, o);
    sched.register("dns-benchmark", b);
    let h = sched.start();
    assert_eq!(sched.request("dns-benchmark", "測試")["ok"], true);
    for _ in 0..600 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if !sched.is_busy() {
            break;
        }
    }
    h.abort();
    assert_eq!(sched.status()["state"]["dns-benchmark"]["lastCode"], 0, "{:#}", sched.status());
}

/// 沒偵測到攔截時：6 台一般 DNS 回答完全一樣（同一個攔截者），只算一票，
/// 不能壓過 3 台各自回答的正常 DNS，正常的也不能被當成可疑
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn identical_plain_answers_count_once() {
    let mut ids = Vec::new();
    let mut honest_ids = Vec::new();
    for n in 1..=3u8 {
        let a = mock(move |d| honest(d, n)).await;
        honest_ids.push(a.to_string());
        ids.push(a.to_string());
    }
    for _ in 0..6 {
        // 攔截者：www.alpha.com 回答別家業者的同一個位址
        let a = mock(|d| match d {
            "www.alpha.com" => Some(vec![ip("98.6.0.1")]),
            _ => honest(d, 9),
        })
        .await;
        ids.push(a.to_string());
    }
    let root = tmp("dedupe");
    let p = paths(&root);
    std::fs::write(p.list_dir.join("iplist.txt"), ids.join("\n")).unwrap();
    std::fs::write(p.list_dir.join("web.txt"), "www.alpha.com\ncdn.beta.com\n").unwrap();
    run(&root, Benchmark::with(p.clone(), Arc::new(Mapped(HashMap::new())), asn()), &["udp"]).await;
    let suspects = std::fs::read_to_string(root.join("state/blacklist-suspects.json")).unwrap_or_default();
    for h in &honest_ids {
        assert!(!suspects.contains(h.as_str()), "正常回答的 DNS 被當成可疑：{suspects}");
    }
    let up = read(&p.upstreams_file);
    let picked = up["selected"].to_string();
    assert!(honest_ids.iter().any(|h| picked.contains(h.as_str())), "{up:#}");
}

/// 路徑檢查判斷一般 DNS（TCP）被接走、沒有 IPv6：那些候選不測，記在 pathSkipped，報表帶路徑判斷
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn path_verdict_skips_candidates() {
    let mut ids = Vec::new();
    for n in 1..=3u8 {
        ids.push(mock(move |d| honest(d, n)).await.to_string());
    }
    ids.push("tcp://127.0.0.1:9".into());
    ids.push("tcp://127.0.0.2:9".into());
    ids.push("2001:db8::53".into());
    let root = tmp("skip");
    let p = paths(&root);
    std::fs::write(p.list_dir.join("iplist.txt"), ids.join("\n")).unwrap();
    std::fs::write(p.list_dir.join("web.txt"), "www.alpha.com\ncdn.beta.com\n").unwrap();
    let r = Report {
        v6_route: V6Route::None("測試".into()),
        plain_v4: Plain { udp: false, tcp: true },
        ..Report::default()
    };
    let mut b = Benchmark::with(p.clone(), Arc::new(Mapped(HashMap::new())), asn()).with_path(r);
    b.keep_last = Some(root.join("persist/benchmark-last"));
    run(&root, b, &["udp"]).await;
    // 判斷過程摘要：報表目錄一份、持久資料區另存一份（重開機後還查得到）
    let log = std::fs::read_to_string(root.join("persist/benchmark-last/judge.log")).unwrap();
    assert!(log.contains("[路徑檢查]") && log.contains("依路徑檢查略過"), "{log}");
    assert!(log.contains("www.alpha.com"), "{log}");
    assert!(root.join("persist/benchmark-last/upstreams.json").is_file());
    assert!(root.join("persist/benchmark-last/eliminated.csv").is_file());
    let up = read(&p.upstreams_file);
    assert_eq!(up["pathSkipped"]["plain-intercepted"], 2, "{up:#}");
    assert_eq!(up["pathSkipped"]["ipv6-unavailable"], 1, "{up:#}");
    assert_eq!(up["counts"]["total"], 3, "{up:#}");
    assert_eq!(up["path"]["plain"]["v4"]["tcp"], true);
    assert_eq!(up["path"]["ipv6"]["usable"], false);
    assert_eq!(up["path"]["policy"], "skip-plain");
    let suspects = std::fs::read_to_string(root.join("state/blacklist-suspects.json")).unwrap_or_default();
    assert!(!suspects.contains("tcp://") && !suspects.contains("2001:db8"), "{suspects}");
}

/// 3 家互相獨立的加密 DNS 回答同一個業者、網站都無法驗證 → 照常計分、今天照用，不記可疑；
/// 只有同一家的 2 台這樣回答 → 照常記可疑、今天不用
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn independent_operators_are_not_suspects() {
    let mut ids = Vec::new();
    for n in 1..=6u8 {
        ids.push(mock(move |d| honest(d, n)).await.to_string());
    }
    let mut map = HashMap::new();
    let mut doh = Vec::new();
    // 不同經營者的三台（98.6 = Quiet Hosting）
    for (k, host) in ["dns.op-a.example", "doh.op-b.example", "resolver.op-c.example.co.jp"]
        .iter()
        .enumerate()
    {
        let a = mock(move |d| match d {
            "www.alpha.com" => Some(vec![Ipv4Addr::new(98, 6, 0, k as u8 + 1)]),
            _ => honest(d, 20 + k as u8),
        })
        .await;
        map.insert(host.to_string(), a);
        doh.push(format!("https://{host}/dns-query"));
    }
    // 同一家的兩台（99.7 = Plain Web）
    for (k, host) in ["a.same-op.example", "b.same-op.example"].iter().enumerate() {
        let a = mock(move |d| match d {
            "www.alpha.com" => Some(vec![Ipv4Addr::new(99, 7, 0, k as u8 + 1)]),
            _ => honest(d, 30 + k as u8),
        })
        .await;
        map.insert(host.to_string(), a);
        doh.push(format!("https://{host}/dns-query"));
    }
    let root = tmp("indep");
    let p = paths(&root);
    std::fs::write(p.list_dir.join("iplist.txt"), ids.join("\n")).unwrap();
    std::fs::write(p.list_dir.join("dohlist.txt"), doh.join("\n")).unwrap();
    std::fs::write(p.list_dir.join("web.txt"), "www.alpha.com\ncdn.beta.com\n").unwrap();
    let mut b = Benchmark::with(p.clone(), Arc::new(Mapped(map)), asn());
    b.keep_last = Some(root.join("persist/benchmark-last"));
    run(&root, b, &["udp", "doh"]).await;
    let suspects: Value = read(&root.join("state/blacklist-suspects.json"));
    let keys: Vec<&String> = suspects.as_object().unwrap().keys().collect();
    assert!(
        !keys.iter().any(|k| k.contains("op-a") || k.contains("op-b") || k.contains("op-c")),
        "{keys:?}"
    );
    assert!(
        keys.iter().any(|k| k.contains("a.same-op")) && keys.iter().any(|k| k.contains("b.same-op")),
        "{keys:?}"
    );
    // 3.4.2 起：連不上不是那幾台的錯，今天照用（倖存）；同一家的兩台照舊今天不用
    let elim = std::fs::read_to_string(root.join("persist/benchmark-last/eliminated.csv")).unwrap();
    for host in ["op-a", "op-b", "op-c"] {
        assert!(!elim.contains(host), "{host} 今天照用：{elim}");
    }
    assert!(elim.contains("a.same-op") && elim.contains("b.same-op"), "{elim}");
}

/// 多家 CDN 的網域（padavan-tw 3.3.6：cdn-mum.alibabachengdun.com）：規則外的回答裡已經有 2 個不同業者憑證有效，
/// 同一家的 2 台回答第 3 個業者但連不上（TIMEOUT）→ 照常計分、今天照用，不記可疑
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multi_cdn_domain_timeouts_are_not_suspects() {
    let mut ids = Vec::new();
    for n in 1..=6u8 {
        ids.push(mock(move |d| honest(d, n)).await.to_string());
    }
    let mut map = HashMap::new();
    let mut doh = Vec::new();
    let answers = [
        ("cdn-a.op-x.example", [95, 3, 0, 1]),
        ("cdn-b.op-y.example", [97, 5, 0, 1]),
        ("sea01.same-op.example", [99, 7, 0, 1]),
        ("sjc02.same-op.example", [99, 7, 0, 2]),
    ];
    for (k, (host, ip)) in answers.iter().enumerate() {
        let ip = Ipv4Addr::from(*ip);
        let a = mock(move |d| match d {
            "www.alpha.com" => Some(vec![ip]),
            _ => honest(d, 40 + k as u8),
        })
        .await;
        map.insert(host.to_string(), a);
        doh.push(format!("https://{host}/dns-query"));
    }
    let root = tmp("multicdn");
    let p = paths(&root);
    std::fs::write(p.list_dir.join("iplist.txt"), ids.join("\n")).unwrap();
    std::fs::write(p.list_dir.join("dohlist.txt"), doh.join("\n")).unwrap();
    std::fs::write(p.list_dir.join("web.txt"), "www.alpha.com\ncdn.beta.com\n").unwrap();
    let mut b = Benchmark::with(p.clone(), Arc::new(Mapped(map)), asn());
    b.keep_last = Some(root.join("persist/benchmark-last"));
    run(&root, b, &["udp", "doh"]).await;
    let suspects = std::fs::read_to_string(root.join("state/blacklist-suspects.json")).unwrap_or_default();
    assert!(!suspects.contains("same-op"), "多家 CDN 的網域連不上不記可疑：{suspects}");
    let log = std::fs::read_to_string(root.join("persist/benchmark-last/judge.log")).unwrap();
    assert!(log.contains("多家 CDN") && log.contains("[保留] https://sea01.same-op"), "{log}");
    assert!(!log.contains("[今天不用] https://sea01.same-op"), "{log}");
}

/// 對照組：擋網域的判出過濾、回答被判可疑的也判出（不記可疑天數），正常回答的「沒判出」但永遠不選；
/// 列在永久黑名單裡的對照組照樣測；對照組不參加多數決
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protected_control_group() {
    let mut ids = Vec::new();
    for n in 1..=4u8 {
        ids.push(mock(move |d| honest(d, n)).await.to_string());
    }
    // 擋 cdn.beta.com（回 NXDOMAIN）
    let blocker = mock(|d| if d == "cdn.beta.com" { None } else { honest(d, 40) }).await.to_string();
    // 正常回答（官方沒寫有沒有過濾、評測也判不出來的那種）
    let quiet = mock(|d| honest(d, 41)).await.to_string();
    // 在永久黑名單裡，也正常回答
    let listed = mock(|d| honest(d, 42)).await.to_string();
    // 回答別家業者、網站無法驗證（擋網站時導到自己的封鎖頁）
    let redirect = mock(|d| match d {
        "www.alpha.com" => Some(vec![ip("99.7.0.9")]),
        _ => honest(d, 43),
    })
    .await
    .to_string();
    let root = tmp("protected");
    let p = paths(&root);
    std::fs::write(p.list_dir.join("iplist.txt"), ids.join("\n")).unwrap();
    std::fs::write(
        p.list_dir.join("protected.txt"),
        format!("# 對照組\n{blocker}  # filter=ads\n{quiet}  # filter=malware\n{listed}  # filter=adult\n{redirect}  # filter=adult\n"),
    )
    .unwrap();
    std::fs::write(p.list_dir.join("blacklist.txt"), format!("{listed}\n")).unwrap();
    std::fs::write(p.list_dir.join("web.txt"), "www.alpha.com\ncdn.beta.com\n").unwrap();
    let mut b = Benchmark::with(p.clone(), Arc::new(Mapped(HashMap::new())), asn());
    b.keep_last = Some(root.join("persist/benchmark-last"));
    run(&root, b, &["udp"]).await;

    let up = read(&p.upstreams_file);
    let result = |id: &str| {
        up["protected"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == id)
            .map(|c| c["result"].as_str().unwrap().to_string())
            .unwrap_or_else(|| panic!("{id} 不在對照組結果：{up:#}"))
    };
    assert_eq!(result(&blocker), "detected", "{up:#}");
    assert_eq!(result(&redirect), "detected", "{up:#}");
    assert_eq!(result(&quiet), "passed", "{up:#}");
    assert_eq!(result(&listed), "passed", "永久黑名單裡的對照組照樣測：{up:#}");
    assert_eq!(up["counts"]["protected"], 4, "{up:#}");
    // 永遠不選；正常的 4 台照常選、照常倖存
    let picked = up["selected"].to_string();
    for c in [&blocker, &quiet, &listed, &redirect] {
        assert!(!picked.contains(c.as_str()), "對照組被選了：{c}");
    }
    assert!(ids.iter().any(|h| picked.contains(h.as_str())), "{up:#}");
    assert_eq!(up["counts"]["survivors"], 4, "{up:#}");
    // 不記可疑、不進永久黑名單、不算淘汰
    let suspects = std::fs::read_to_string(root.join("state/blacklist-suspects.json")).unwrap_or_default();
    assert!(!suspects.contains(redirect.as_str()), "{suspects}");
    let bl = std::fs::read_to_string(root.join("state/blacklist.txt")).unwrap_or_default();
    assert!(!bl.contains(redirect.as_str()) && !bl.contains(blocker.as_str()), "{bl}");
    let elim = std::fs::read_to_string(root.join("persist/benchmark-last/eliminated.csv")).unwrap();
    assert!(!elim.contains(blocker.as_str()) && !elim.contains(redirect.as_str()), "{elim}");
    let csv = std::fs::read_to_string(root.join("persist/benchmark-last/protected.csv")).unwrap();
    assert!(csv.contains(&format!("{blocker},udp,ads,detected,封殺 cdn.beta.com")), "{csv}");
    let log = std::fs::read_to_string(root.join("persist/benchmark-last/judge.log")).unwrap();
    assert!(
        log.contains("對照組 4") && log.contains("[對照組] 4 台：判出過濾 2、沒判出 2、沒測到 0"),
        "{log}"
    );
}
