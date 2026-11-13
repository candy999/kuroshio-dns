//! 記憶體控制的實測（預設不跑，規格 09 第 6 節的數字）：
//!
//! ```text
//! KUROSHIO_BENCH_LISTS=<放預設清單的資料夾> cargo test -p kuroshio --test memgov_bench -- --ignored --nocapture
//! ```
//!
//! 資料夾裡放內建預設清單（啟用的那幾份）下載下來的原檔，檔名：tw165.txt、twnic.txt、tif.txt、hosts_abp.txt、
//! filter_21.txt、easylistchina.txt、oisd.txt、light.txt、adove.txt、smarttv.txt。用本機的 HTTP 伺服器餵給程式（不連外網）。
//! 情境：small 等級、預設清單、種子 CDN 資料庫（九成設成一小時以上沒出現）、快取填滿（15,000 筆）。
//! 印出每一步釋出的記憶體：配置器實際少了多少（live heap）、結構估計值、RSS 差。

use kuroshio::memgov::{CacheStep, CdnStep, DiagStep, FilterStep, Reading, Step};
use serde_json::json;
use std::alloc::{GlobalAlloc, Layout, System};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// 記錄目前配置中的位元組數
struct Live;
static LIVE: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Live {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        LIVE.fetch_add(l.size(), Ordering::Relaxed);
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        LIVE.fetch_add(n, Ordering::Relaxed);
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
        System.realloc(p, l, n)
    }
}

#[global_allocator]
static A: Live = Live;

const LISTS: [(&str, &str, &str); 10] = [
    ("tw165.txt", "FutaGuard TW165（台灣 165 反詐騙）", "malware"),
    ("twnic.txt", "FutaGuard TWNIC-RPZ（台灣網路資訊中心停止解析）", "malware"),
    ("tif.txt", "HaGeZi TIF 精簡版（威脅情資）", "malware"),
    ("hosts_abp.txt", "FutaGuard LowTechHost（台灣廣告）", "ads"),
    ("filter_21.txt", "CHN: anti-AD", "ads"),
    ("easylistchina.txt", "EasyList China", "ads"),
    ("oisd.txt", "OISD small", "ads"),
    ("light.txt", "HaGeZi Light", "ads"),
    ("adove.txt", "a-dove-is-dumb（Adobe 遙測）", "telemetry"),
    ("smarttv.txt", "blocklistproject smart-tv（電視遙測）", "telemetry"),
];

async fn serve(dir: std::path::PathBuf) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let dir = dir.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req.split_whitespace().nth(1).unwrap_or("/").trim_start_matches('/').to_string();
                let body = std::fs::read(dir.join(&path)).unwrap_or_default();
                let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                let _ = s.write_all(head.as_bytes()).await;
                let _ = s.write_all(&body).await;
            });
        }
    });
    addr
}

fn kb(b: i64) -> String {
    format!("{:.0} KB", b as f64 / 1024.0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn memory_ladder_realistic() {
    let Some(dir) = std::env::var_os("KUROSHIO_BENCH_LISTS").map(std::path::PathBuf::from) else {
        eprintln!("沒有設定 KUROSHIO_BENCH_LISTS，略過");
        return;
    };
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    std::env::set_var("KUROSHIO_SHARE", repo.join("data"));
    let srv = serve(dir.clone()).await;
    // 不存在的清單檔（沒下載到）略過
    let lists: Vec<_> = LISTS
        .iter()
        .filter(|(f, _, _)| dir.join(f).exists())
        .map(|(f, n, c)| json!({ "name": n, "url": format!("http://{srv}/{f}"), "category": c }))
        .collect();
    let tmp = std::env::temp_dir().join(format!("kuroshio-memgov-bench-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(tmp.join("state")).unwrap();
    let cfg = kuroshio_config::build(&json!({
        "system": { "persistDir": tmp.join("state"), "runtimeDir": tmp.join("run"), "storageClass": "disk", "memoryGovernor": false },
        "admin": { "enabled": false },
        "listen": { "plain": { "binds": ["127.0.0.1"], "port": 0 } },
        "upstream": { "pinned": ["udp://127.0.0.1:9"], "fallback": [] },
        "resolver": { "lastResort": [], "rankIps": false, "warmNames": 0 },
        "community": { "enabled": false },
        "filter": { "customRules": [tmp.join("custom-rules.txt")], "lists": lists },
        "jobs": { "dns-benchmark": { "enabled": false }, "cdn-pool": { "enabled": false }, "cdn-ranges": { "enabled": false }, "cdn-scan": { "enabled": false } },
    }));
    let started = kuroshio::app::start(&cfg).await.unwrap();
    let st = started.state.clone();
    let r = started.resolver.clone();
    let f = st.filter.clone().unwrap();
    f.update_lists(true).await.unwrap();
    // 快取填滿：每筆一個 A 記錄（一般網站的回應形狀）
    {
        let mut c = r.cache.lock().unwrap();
        let now = std::time::Instant::now();
        let max = c.max;
        for i in 0..max {
            let name = format!("www{i}.site{}.example", i % 997);
            let e = kuroshio::cache::Entry::new(
                0,
                vec![kuroshio_proto::message::Record::a(
                    &name,
                    300,
                    std::net::Ipv4Addr::new(10, 0, (i >> 8) as u8, i as u8),
                )],
                vec![],
                kuroshio_proto::logic::Class::Ok,
                "udp://192.0.2.1".into(),
                300,
                false,
                None,
            );
            c.insert(format!("1|{name}"), e, now);
            if i % 10 == 0 {
                c.get(&format!("1|{name}"), now);
            }
        }
    }
    // 統計排行：2,000 個網域
    for i in 0..2000 {
        r.stats
            .query(&format!("q{i}.example.com"), std::net::IpAddr::from([192, 168, 1, (i % 50) as u8]));
    }
    // CDN：九成的網域一小時以上沒出現（一天裡大部分網域只在某段時間被查）
    let cdn = r.cdn().unwrap();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let cdn_n = cdn.with_state(|s| {
        for (k, d) in s.db.domains.values_mut().enumerate() {
            if k % 10 != 0 {
                d.last_seen = now_ms - 6 * 3600 * 1000;
            }
        }
        s.db.domains.len()
    });
    let cache_n = r.cache.lock().unwrap().len();
    let fstats = kuroshio::resolver::FilterCheck::stats(&*f);
    println!(
        "情境：small 等級；快取 {cache_n} 筆（約 {}）；CDN 網域 {cdn_n} 筆；過濾清單 {} 條規則、{} 個網域、約 {}",
        kb(r.cache.lock().unwrap().approx_bytes() as i64),
        fstats["lists"],
        fstats["domains"],
        kb(fstats["memoryBytes"].as_i64().unwrap())
    );
    // 原始清單壓縮後的大小（決定「不在 tmpfs 留壓縮副本」的依據）
    let mut raw = 0;
    let mut z = 0;
    for (file, _, _) in LISTS {
        if let Ok(b) = std::fs::read(dir.join(file)) {
            raw += b.len();
            z += zstd::encode_all(&b[..], 3).unwrap().len();
        }
    }
    println!(
        "原始清單 {}，zstd -3 壓縮後 {}（放 tmpfs 就是佔記憶體）",
        kb(raw as i64),
        kb(z as i64)
    );
    println!(
        "常駐記憶體 {}、配置中 {}",
        kb(kuroshio::sysinfo::rss_bytes().unwrap_or(0) as i64),
        kb(LIVE.load(Ordering::Relaxed) as i64)
    );

    let reading = Reading::now();
    let steps: Vec<Box<dyn Step>> = vec![
        Box::new(DiagStep::new(r.clone())),
        Box::new(CacheStep::new(r.clone())),
        Box::new(CdnStep::new(cdn.clone(), st.persister.clone(), st.snap_sources.clone())),
        Box::new(FilterStep { filter: f.clone() }),
    ];
    println!("{:<34} {:>10} {:>10} {:>10}", "步驟", "heap 實測", "估計", "RSS 差");
    let mut total = 0i64;
    for s in &steps {
        loop {
            if !s.can_shed() {
                break;
            }
            let (h0, r0) = (
                LIVE.load(Ordering::Relaxed) as i64,
                kuroshio::sysinfo::rss_bytes().unwrap_or(0) as i64,
            );
            let o = match s.shed(&reading).await {
                Ok(o) => o,
                Err(e) => {
                    println!("{}：{e:#}", s.label());
                    break;
                }
            };
            kuroshio::sysinfo::trim_heap();
            let (h1, r1) = (
                LIVE.load(Ordering::Relaxed) as i64,
                kuroshio::sysinfo::rss_bytes().unwrap_or(0) as i64,
            );
            total += h0 - h1;
            println!(
                "{:<34} {:>10} {:>10} {:>10}  {}",
                s.label(),
                kb(h0 - h1),
                kb(o.bytes as i64),
                kb(r0 - r1),
                o.detail
            );
            if s.key() != "filter" {
                break;
            }
        }
    }
    println!("合計（heap 實測）：{}", kb(total));
    // 恢復（相反順序）：過濾清單重新下載、CDN 讀回
    for s in steps.iter().rev() {
        while s.is_shed() {
            let h0 = LIVE.load(Ordering::Relaxed) as i64;
            let o = s.restore().await.unwrap();
            println!(
                "恢復 {}{}：heap +{}",
                s.label(),
                o.detail,
                kb(LIVE.load(Ordering::Relaxed) as i64 - h0)
            );
        }
    }
    assert_eq!(cdn.evicted_count(), 0);
    assert!(f.unloaded().is_empty());
    started.shutdown();
    let _ = std::fs::remove_dir_all(&tmp);
}
