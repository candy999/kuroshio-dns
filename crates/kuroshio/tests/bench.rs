//! 效能量測（預設不跑）：`cargo test -p kuroshio --test bench -- --ignored --nocapture --test-threads=1`
//! （配置次數是整個行程一起算的，兩個量測同時跑會互相干擾）
//!
//! 印出每次操作的奈秒數與配置次數，改動熱路徑前後各跑一次比較。
//! 除錯組建的時間沒有參考價值，要看時間請加 `CARGO_PROFILE_TEST_OPT_LEVEL=2`；配置次數跟最佳化等級無關。

use kuroshio::resolver::Ctx;
use kuroshio_proto::message::{opt_code, rtype, Message, Opt, RData, Record};
use serde_json::json;
use std::alloc::{GlobalAlloc, Layout, System};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use tokio::net::UdpSocket;

/// 計算配置次數的配置器（只在這個測試檔裡）
struct Counting;
static ALLOCS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.realloc(p, l, n)
    }
}

#[global_allocator]
static A: Counting = Counting;

/// 假上游：CNAME + 4 筆 A（常見的 CDN 回應形狀）
async fn upstream() -> std::net::SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let (len, peer) = s.recv_from(&mut buf).await.unwrap();
            let q = Message::parse(&buf[..len]).unwrap();
            let name = q.questions[0].name.clone();
            let mut r = Message::response_to(&q, 0);
            r.answers.push(Record {
                name: name.clone(),
                rtype: rtype::CNAME,
                class: 1,
                ttl: 300,
                data: RData::Name("edge.cdn.example.net".into()),
            });
            for i in 0..4 {
                r.answers
                    .push(Record::a("edge.cdn.example.net", 300, Ipv4Addr::new(192, 0, 2, 10 + i)));
            }
            let _ = s.send_to(&r.encode(), peer).await;
        }
    });
    addr
}

fn query(name: &str, edns: bool, padding: bool) -> Vec<u8> {
    let mut q = Message::parse(&kuroshio_proto::build_query(0x1234, name, 1)).unwrap();
    if edns {
        q.opt = Some(Opt {
            udp_size: 1232,
            options: if padding { vec![(opt_code::PADDING, vec![0; 20])] } else { vec![] },
            ..Default::default()
        });
    }
    q.encode()
}

fn report(label: &str, n: usize, t0: Instant, a0: usize) {
    let ns = t0.elapsed().as_nanos() as f64 / n as f64;
    let allocs = (ALLOCS.load(Ordering::Relaxed) - a0) as f64 / n as f64;
    println!("BENCH {label:<34} {ns:>9.0} ns/op {allocs:>7.1} allocs/op");
}

#[tokio::test(flavor = "current_thread")]
#[ignore]
async fn bench_cached_hit() {
    let up = upstream().await;
    let cfg = kuroshio_config::with_overrides(&json!({
        "admin": { "port": 0, "auth": false },
        "filter": { "enabled": false },
        "system": { "persistDir": std::env::temp_dir().join("kuroshio-bench").to_string_lossy() },
        "upstream": { "pinned": [format!("udp://{up}")], "fallback": [] },
        "resolver": { "timeoutMs": 800, "collectWindowMs": 50, "lastResort": [], "rankIps": false, "maxTtl": 86400 }
    }));
    let r = kuroshio::app::build_resolver(&cfg).unwrap();
    let client = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 23));
    let udp = Ctx { proto: "udp", client };
    let doh = Ctx { proto: "doh", client };
    let plain = query("www.video.example.com", false, false);
    let edns = query("www.video.example.com", true, false);
    let padded = query("www.video.example.com", true, true);
    // 先查一次放進快取，等背景的完整結果寫入
    r.handle(&plain, &udp).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let n = 200_000;
    for (label, q, ctx) in [
        ("cached hit udp (no EDNS)", &plain, &udp),
        ("cached hit udp (EDNS)", &edns, &udp),
        ("cached hit doh (EDNS)", &edns, &doh),
        ("cached hit doh (EDNS + padding)", &padded, &doh),
    ] {
        for _ in 0..n / 10 {
            std::hint::black_box(r.handle(q, ctx).await.unwrap());
        }
        let (a0, t0) = (ALLOCS.load(Ordering::Relaxed), Instant::now());
        for _ in 0..n {
            std::hint::black_box(r.handle(q, ctx).await.unwrap());
        }
        report(label, n, t0, a0);
    }
    assert_eq!(r.stats.summary()["today"]["miss"], 1, "量到的都是快取命中");
}

#[test]
#[ignore]
fn bench_stats_and_presence() {
    let stats = kuroshio::stats::Stats::default();
    let p = kuroshio::presence::Presence::new(Default::default(), "dns.example.net", 50_000);
    let client = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 23));
    let n = 500_000;
    let (a0, t0) = (ALLOCS.load(Ordering::Relaxed), Instant::now());
    for _ in 0..n {
        stats.count(kuroshio::stats::Kind::Query);
        stats.query_name("www.video.example.com", client);
        stats.site("www.video.example.com", client);
        stats.count(kuroshio::stats::Kind::Hit);
        stats.latency(true, 0.02);
    }
    report("stats per cached query (old calls)", n, t0, a0);
    let (a0, t0) = (ALLOCS.load(Ordering::Relaxed), Instant::now());
    for _ in 0..n {
        stats.query("www.video.example.com", client);
        stats.site("www.video.example.com", client);
        stats.hit(0.02);
    }
    report("stats per cached query", n, t0, a0);
    let (a0, t0) = (ALLOCS.load(Ordering::Relaxed), Instant::now());
    for _ in 0..n {
        p.record("udp", client, "www.video.example.com");
    }
    report("presence.record", n, t0, a0);
}
