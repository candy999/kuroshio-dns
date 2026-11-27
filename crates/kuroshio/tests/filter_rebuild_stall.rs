//! 重建過濾清單時，回答查詢的 tokio 工作執行緒不被佔住（3.5.1）。
//!
//! D3（MT7621）記憶體恢復重新啟用 7 份清單（約 35 萬條）時，快取命中的查詢最慢等了 2,835 ms：
//! 解析在工作執行緒上做，讀本機副本時內容一直都有，一次 poll 連續解析好幾段才讓出。
//! 這裡用 1 條工作執行緒（任何一次 poll 佔住它，查詢就要等），重建 35 萬條規則時量兩件事：
//! 重建那個 future 每一次 poll 花多久（就是它佔住工作執行緒多久），以及另一條執行緒一直送的「快取命中」查詢最久等多久。

use kuroshio::resolver::FilterCheck as _;
use kuroshio_filter::{Category, FilterBuilder, ListSpec};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

const LISTS: usize = 7;
const PER_LIST: usize = 50_000;

/// `||<12 個隨機字母>.example.com^`，固定種子
fn rand_lists() -> Vec<String> {
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    (0..LISTS)
        .map(|_| {
            let mut s = String::with_capacity(PER_LIST * 30);
            for _ in 0..PER_LIST {
                let mut v = next();
                s.push_str("||");
                for _ in 0..12 {
                    s.push((b'a' + (v % 26) as u8) as char);
                    v /= 26;
                }
                s.push_str(".example.com^\n");
            }
            s
        })
        .collect()
}

/// `/l{i}.txt` 回第 i 份清單
async fn serve(lists: Arc<Vec<String>>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let lists = lists.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                let i: usize = path.trim_start_matches("/l").trim_end_matches(".txt").parse().unwrap_or(0);
                let b = &lists[i];
                let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", b.len());
                let _ = s.write_all(head.as_bytes()).await;
                let _ = s.write_all(b.as_bytes()).await;
            });
        }
    });
    addr
}

/// 模擬快取命中：收 UDP、查過濾、查一個雜湊表、回覆（跟 `server.rs` 一樣每筆 spawn 一個工作）
async fn query_server(f: Arc<kuroshio::filtering::FilterService>) -> SocketAddr {
    let s = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = s.local_addr().unwrap();
    let cache: Arc<std::collections::HashMap<String, u32>> = Arc::new((0..500).map(|i| (format!("w{i}.example.net"), i)).collect());
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let (n, peer) = s.recv_from(&mut buf).await.unwrap();
            let name = String::from_utf8_lossy(&buf[..n]).to_string();
            let (s, f, cache) = (s.clone(), f.clone(), cache.clone());
            tokio::spawn(async move {
                let _ = f.check(&name, 1);
                let v = cache.get(&name).copied().unwrap_or(0);
                let _ = s.send_to(&v.to_le_bytes(), peer).await;
            });
        }
    });
    addr
}

/// 另一條 OS 執行緒每 5 ms 查一筆，回傳（筆數，最久）
fn prober(addr: SocketAddr, stop: Arc<AtomicBool>) -> std::thread::JoinHandle<(usize, Duration)> {
    std::thread::spawn(move || {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        let (mut n, mut max) = (0, Duration::ZERO);
        let mut buf = [0u8; 16];
        while !stop.load(Ordering::Relaxed) {
            let name = format!("w{}.example.net", n % 500);
            let t = Instant::now();
            s.send_to(name.as_bytes(), addr).unwrap();
            let _ = s.recv_from(&mut buf);
            max = max.max(t.elapsed());
            n += 1;
            std::thread::sleep(Duration::from_millis(5));
        }
        (n, max)
    })
}

/// 量每一次 poll 花多久（在工作執行緒上做了多少事）：輸出（結果，最長一次，合計）
struct Timed<F> {
    f: std::pin::Pin<Box<F>>,
    max: Duration,
    sum: Duration,
}

impl<F: std::future::Future> std::future::Future for Timed<F> {
    type Output = (F::Output, Duration, Duration);
    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        let t = Instant::now();
        let r = self.f.as_mut().poll(cx);
        let d = t.elapsed();
        self.max = self.max.max(d);
        self.sum += d;
        r.map(|o| (o, self.max, self.sum))
    }
}

fn timed<F: std::future::Future>(f: F) -> Timed<F> {
    Timed {
        f: Box::pin(f),
        max: Duration::ZERO,
        sum: Duration::ZERO,
    }
}

/// 35 萬條規則：讀本機副本重建（記憶體恢復的路）與下載重建（每天的更新、改了清單設定），
/// 工作執行緒每次 poll 最多 15 ms、快取查詢最久 60 ms（門檻抓寬。x86 除錯版：改之前讀副本一次 poll 190 ms、下載 31 ms、
/// 查詢最久 186 ms；改之後一次 poll 0.3～0.5 ms、查詢最久約 3 ms）。
/// 建好的跟直接用 `FilterBuilder` 建的一樣
#[test]
fn rebuild_does_not_hold_query_worker() {
    // 1 條工作執行緒：任何一次 poll 佔住它，查詢就排在後面（MT7621 有 4 條，但慢上百倍）
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .max_blocking_threads(2)
        .enable_all()
        .build()
        .unwrap();
    // 重建要在 runtime 的工作執行緒上跑（`block_on` 本身在測試的執行緒上，量不到）
    rt.block_on(async { tokio::spawn(run()).await.unwrap() });
}

async fn run() {
    let lists = Arc::new(rand_lists());
    // 對照：同樣的清單直接用 FilterBuilder 建（以前的建法）
    let want = {
        let mut b = FilterBuilder::new(Default::default());
        for (i, l) in lists.iter().enumerate() {
            b.add_list(ListSpec::new(format!("清單{i}"), Category::Ads), l.as_bytes()).unwrap();
        }
        b.finish()
    };
    let srv = serve(lists.clone()).await;
    let dir = std::env::temp_dir().join(format!("kuroshio-rebuild-stall-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let ls: Vec<_> = (0..LISTS)
        .map(|i| json!({ "name": format!("清單{i}"), "url": format!("http://{srv}/l{i}.txt"), "category": "ads" }))
        .collect();
    let cfg = kuroshio_config::with_overrides(&json!({ "filter": { "customRules": [], "lists": ls } }));
    let f = kuroshio::filtering::FilterService::from_cfg(&cfg, &dir).unwrap();
    let mut p = kuroshio::persist::Persister::new(
        dir.join("state"),
        kuroshio::persist::Policy::new(kuroshio::sysinfo::StorageClass::Disk, 0, 4096),
    );
    p.set_free_probe(|_| Some(10 << 30));
    let p = Arc::new(Mutex::new(p));
    f.set_copies(p.clone());
    assert!(f.update_lists(true).await.unwrap());
    p.lock().unwrap().flush_all(kuroshio::persist::now_secs()).unwrap();
    assert!(
        (0..LISTS).all(|i| f.copies().unwrap().available(&format!("http://{srv}/l{i}.txt"))),
        "每份都有本機副本"
    );

    let q = query_server(f.clone()).await;
    let stop = Arc::new(AtomicBool::new(false));
    let h = prober(q, stop.clone());
    tokio::time::sleep(Duration::from_millis(200)).await;
    let t = Instant::now();
    let (r, copy_max, copy_sum) = timed(f.rebuild_from_copies()).await;
    assert!(r.unwrap());
    let copy_total = t.elapsed();
    let t = Instant::now();
    let (r, dl_max, dl_sum) = timed(f.update_lists(true)).await;
    assert!(r.unwrap());
    let dl_total = t.elapsed();
    tokio::time::sleep(Duration::from_millis(200)).await;
    stop.store(true, Ordering::Relaxed);
    let (n, q_max) = tokio::task::spawn_blocking(move || h.join().unwrap()).await.unwrap();
    eprintln!(
        "副本：{copy_total:?}（工作執行緒上最長一次 {copy_max:?}、合計 {copy_sum:?}）；\
         下載：{dl_total:?}（最長一次 {dl_max:?}、合計 {dl_sum:?}）；查詢 {n} 筆、最久 {q_max:?}"
    );

    // 建好的跟直接建的一樣
    let got = f.lists_layer();
    assert_eq!(got.stats().lists, (LISTS * PER_LIST) as u64);
    assert_eq!(got.stats().domains, want.stats().domains);
    assert_eq!(got.stats().by_category, want.stats().by_category);
    for (a, b) in got.stats().sources.iter().zip(&want.stats().sources) {
        assert_eq!(
            (a.status, a.lines, a.domain_rules, a.complex_rules),
            (b.status, b.lines, b.domain_rules, b.complex_rules)
        );
    }
    // 記憶體只差字串、表頭的容量（名稱是不同方式產生的）
    assert!(got.memory_bytes().abs_diff(want.memory_bytes()) < 1024);
    for (i, l) in lists.iter().enumerate() {
        for line in l.lines().step_by(997) {
            let name = line.trim_start_matches("||").trim_end_matches('^');
            let (a, b) = (got.check(name, 1).unwrap(), want.check(name, 1).unwrap());
            assert!(a.is_block() && b.is_block());
            assert_eq!((a.list, a.rule()), (b.list, b.rule()), "清單 {i}：{name}");
        }
    }
    assert!(got.check("w1.example.net", 1).is_none());

    assert!(copy_max < Duration::from_millis(15), "讀副本重建：工作執行緒一次被佔 {copy_max:?}");
    assert!(dl_max < Duration::from_millis(15), "下載重建：工作執行緒一次被佔 {dl_max:?}");
    assert!(q_max < Duration::from_millis(60), "重建期間快取查詢最久 {q_max:?}");
    let _ = std::fs::remove_dir_all(&dir);
}
