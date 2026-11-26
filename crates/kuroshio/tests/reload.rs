//! 重新載入設定（3.5.1 測試版 D3：每次 SIGHUP RSS 長約 10 MB、不會降）：一輪結束、執行環境關掉之後，
//! 這一輪的結構（整體狀態、解析器、過濾服務、CDN 資料庫）都要放掉，不能被循環參照或背景工作抓著。
//!
//! 每一輪照正式執行的方式在自己的執行環境裡跑（`main.rs` 的 `generation`）：建立、啟動、`shutdown`、關掉執行環境。

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

/// 交接用的是行程層級的位置（快取、清單層、監聽）：這個檔案的測試一個一個跑
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// 清單伺服器（跨好幾個執行環境，所以用一般的執行緒）：每份清單 `n` 條規則，回傳（位址, 收到的請求數）
fn list_server(n: usize) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let mut buf = [0u8; 2048];
            let len = s.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..len]).to_string();
            let path = req.split_whitespace().nth(1).unwrap_or("/").trim_start_matches('/').to_string();
            h.fetch_add(1, Ordering::SeqCst);
            let mut body = String::from("! 測試清單\n");
            for i in 0..n {
                body.push_str(&format!("||{path}-{i}.example.com^\n"));
            }
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"{path}\"\r\n\r\n{body}",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes());
        }
    });
    (addr, hits)
}

fn lists(addr: std::net::SocketAddr, names: &[&str]) -> Value {
    Value::Array(
        names
            .iter()
            .map(|n| json!({ "name": n, "url": format!("http://{addr}/{n}"), "category": "ads" }))
            .collect(),
    )
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("kuroshio-reload-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("state")).unwrap();
    d
}

/// 公開頁、CDN、過濾（自訂規則）都開著；只聽 127.0.0.1 的任意埠、不連外
fn config(dir: &Path, over: Value) -> Value {
    std::fs::write(dir.join("custom-rules.txt"), "||ads.example.com^\n").unwrap();
    let mut cfg = kuroshio_config::with_overrides(&json!({
        "system": { "persistDir": dir.join("state").to_string_lossy(), "dataDir": root().join("data").to_string_lossy(),
                    "runtimeDir": dir.join("run").to_string_lossy(), "memoryRestart": false },
        "admin": { "port": 0, "auth": false },
        "filter": { "enabled": true, "customRules": ["./custom-rules.txt"], "lists": [] },
        "community": { "enabled": false, "dir": dir.join("keys").to_string_lossy() },
        "listen": { "plain": { "binds": ["127.0.0.1"], "port": 0 },
                    "doh": { "enabled": true, "host": "127.0.0.1", "port": 0, "tls": false } },
        "site": { "enabled": true, "hostname": "" },
        "upstream": { "pinned": ["udp://127.0.0.1:9"], "fallback": [], "autoTypes": [] },
        "resolver": { "lastResort": [], "rankIps": false },
        "jobs": { "dns-benchmark": { "enabled": false }, "cdn-pool": { "enabled": false }, "cdn-ranges": { "enabled": false },
                  "cdn-scan": { "enabled": false }, "tw-ip": { "enabled": false } },
    }));
    kuroshio_config::merge(&mut cfg, &over);
    cfg
}

/// 一輪留下的弱參照
struct Gen {
    state: Weak<kuroshio::app::AppState>,
    resolver: Weak<kuroshio::resolver::Resolver>,
    filter: Option<Weak<kuroshio::filtering::FilterService>>,
    cdn: Option<Weak<kuroshio_cdn::Cdn>>,
    access: Option<Weak<kuroshio::ipfilter::Access>>,
}

impl Gen {
    /// 還被誰抓著（空的 = 全部放掉了）
    fn alive(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.state.upgrade().is_some() {
            v.push("AppState");
        }
        if self.resolver.upgrade().is_some() {
            v.push("Resolver");
        }
        if self.filter.as_ref().is_some_and(|w| w.upgrade().is_some()) {
            v.push("FilterService");
        }
        if self.cdn.as_ref().is_some_and(|w| w.upgrade().is_some()) {
            v.push("Cdn");
        }
        if self.access.as_ref().is_some_and(|w| w.upgrade().is_some()) {
            v.push("Access");
        }
        v
    }
}

/// 照正式執行的方式跑一輪：自己的執行環境、啟動、（重新載入的）`shutdown`、關掉執行環境
fn generation(cfg: &Value) -> Gen {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let g = rt.block_on(async {
        let s = kuroshio::app::start(cfg).await.unwrap();
        // 讓背景工作（過濾清單載入、CDN、維護）都跑起來
        tokio::time::sleep(Duration::from_millis(500)).await;
        let g = Gen {
            state: Arc::downgrade(&s.state),
            resolver: Arc::downgrade(&s.resolver),
            filter: s.state.filter.as_ref().map(Arc::downgrade),
            cdn: s.resolver.cdn.read().unwrap().as_ref().map(Arc::downgrade),
            access: s.resolver.access.get().map(Arc::downgrade),
        };
        assert!(s.resolver.site.get().is_some(), "公開頁開著（循環參照要有機會出現）");
        s.shutdown();
        g
    });
    rt.shutdown_timeout(Duration::from_secs(3));
    g
}

/// 等到全部放掉（blocking 執行緒收尾要一點時間），回傳還抓著的
fn settle(g: &Gen) -> Vec<&'static str> {
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        let v = g.alive();
        if v.is_empty() || Instant::now() > end {
            return v;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// 一輪結束之後整體狀態、解析器、過濾服務、CDN 資料庫、存取控制都放掉了。以前公開頁抓著整體狀態
/// （`AppState` → `Resolver` → `Site` → `AppState`），每次重新載入整輪都留在記憶體裡；
/// 存取控制與台灣 IP 清單的工作互相抓著（`Access` → `update_status` → `TwIpJob` → `Access`）
#[test]
fn ended_generation_is_dropped() {
    let _g = serial();
    let dir = tmp("drop");
    let cfg = config(&dir, json!({}));
    let first = generation(&cfg);
    assert!(
        first.filter.is_some() && first.cdn.is_some() && first.access.is_some(),
        "過濾、CDN、存取控制都有啟動"
    );
    assert_eq!(settle(&first), Vec::<&str>::new(), "第一輪結束後還被抓著");
    // 第二輪（重新載入）：上一輪交出的快取、工作、上游狀態接手之後，第二輪結束一樣全部放掉
    let second = generation(&cfg);
    assert_eq!(settle(&second), Vec::<&str>::new(), "第二輪結束後還被抓著");
    let _ = std::fs::remove_dir_all(&dir);
}

/// 跑一輪，過濾清單載入（規則數 ≥ `rules`）之後交給 `f`，再照重新載入的方式結束
fn generation_with<T>(cfg: &Value, rules: u64, f: impl FnOnce(&kuroshio::app::Started) -> T) -> T {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let out = rt.block_on(async {
        let s = kuroshio::app::start(cfg).await.unwrap();
        let fs = s.state.filter.clone().expect("過濾開著");
        let end = Instant::now() + Duration::from_secs(20);
        while fs.list_rules() < rules {
            assert!(Instant::now() < end, "等不到過濾清單載入");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // 開機排程（2 秒後才開始）跑過一次：接手的那一輪這時候不能重建、也不能去問清單伺服器
        tokio::time::sleep(Duration::from_millis(2500)).await;
        let out = f(&s);
        s.shutdown();
        out
    });
    rt.shutdown_timeout(Duration::from_secs(3));
    out
}

/// 3.5.1 測試版 D3：只改一個小設定（`filter.blockedTtl`）重新載入，過濾清單層沿用上一輪的同一份
/// （不重新讀副本、不重新解析、不去問清單伺服器）；清單改了才重建，交出的那一份也跟著放掉
#[test]
fn reload_keeps_list_layer_when_lists_unchanged() {
    let _g = serial();
    let dir = tmp("lists");
    let (addr, hits) = list_server(2000);
    let base = json!({ "filter": { "lists": lists(addr, &["a", "b"]), "blockedTtl": 60 }, "cdn": { "enabled": false } });
    let cfg1 = config(&dir, base.clone());
    let (layer, n1) = generation_with(&cfg1, 4000, |s| {
        let f = s.state.filter.as_ref().unwrap();
        (Arc::downgrade(&f.lists_layer()), f.rebuild_count())
    });
    assert!(n1 >= 1, "第一輪建過清單層");
    assert!(kuroshio::filtering::lists_handoff_pending(), "清單層交給下一輪");
    let asked = hits.load(Ordering::SeqCst);
    assert_eq!(asked, 2, "第一輪下載兩份清單");

    // 只改被擋的 TTL：同一份清單層、沒有重建、沒有再問清單伺服器
    let mut over = base.clone();
    over["filter"]["blockedTtl"] = json!(30);
    let cfg2 = config(&dir, over);
    let (same, n2) = generation_with(&cfg2, 4000, |s| {
        let f = s.state.filter.as_ref().unwrap();
        let l = f.lists_layer();
        (layer.upgrade().is_some_and(|old| Arc::ptr_eq(&old, &l)), f.rebuild_count())
    });
    assert!(same, "只改 blockedTtl：沿用上一輪的同一份清單層");
    assert_eq!(n2, 0, "接手的那一輪沒有重建");
    assert_eq!(hits.load(Ordering::SeqCst), asked, "沒有再去問清單伺服器");

    // 清單改了（少一份）：重建；上一輪交出的那一份放掉
    let mut over = base.clone();
    over["filter"]["lists"] = lists(addr, &["a"]);
    let cfg3 = config(&dir, over);
    let n3 = generation_with(&cfg3, 2000, |s| s.state.filter.as_ref().unwrap().rebuild_count());
    assert!(n3 >= 1, "清單改了：重建");
    // 第三輪結束時又交出它自己的清單層；第一份（第一、二輪用的）已經沒人抓著
    let end = Instant::now() + Duration::from_secs(10);
    while layer.upgrade().is_some() {
        assert!(Instant::now() < end, "清單改了，舊的清單層還被抓著");
        std::thread::sleep(Duration::from_millis(50));
    }

    // 下一輪沒開過濾：交出的清單層丟掉
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let s = kuroshio::app::start(&config(
            &dir,
            json!({ "filter": { "enabled": false }, "cdn": { "enabled": false } }),
        ))
        .await
        .unwrap();
        assert!(!kuroshio::filtering::lists_handoff_pending(), "沒開過濾：交出的清單層丟掉");
        s.shutdown();
    });
    rt.shutdown_timeout(Duration::from_secs(3));
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------- 重新載入的交接那一刻（3.5.1）----------------

/// 假的上游（一般執行緒，跨好幾個執行環境）：A 查詢回 198.51.100.10（TTL 300），每筆延遲 `delay`；回傳（位址, 收到幾筆）
fn counting_upstream(delay: Duration) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    use kuroshio_proto::message::{Message, Record};
    let u = Arc::new(std::net::UdpSocket::bind("127.0.0.1:0").unwrap());
    let addr = u.local_addr().unwrap();
    let asked = Arc::new(AtomicUsize::new(0));
    let n = asked.clone();
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 4096];
        while let Ok((len, from)) = u.recv_from(&mut buf) {
            let Ok(m) = Message::parse(&buf[..len]) else { continue };
            let Some(q) = m.questions.first().cloned() else { continue };
            n.fetch_add(1, Ordering::SeqCst);
            let mut r = Message::response_to(&m, 0);
            if q.qtype == 1 {
                r.answers.push(Record::a(&q.name, 300, answer_ip()));
            }
            let u = u.clone();
            std::thread::spawn(move || {
                std::thread::sleep(delay);
                let _ = u.send_to(&r.encode(), from);
            });
        }
    });
    (addr, asked)
}

fn answer_ip() -> std::net::Ipv4Addr {
    "198.51.100.10".parse().unwrap()
}

/// UDP 與 TCP 都空著的埠（一般 DNS 的監聽要固定的埠才會經過 `listenbank`）
fn free_dns_port() -> u16 {
    loop {
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        if std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

/// 收一筆回應：（id, rcode, A 記錄）
fn recv_answer(sock: &std::net::UdpSocket) -> Option<(u16, u16, Vec<std::net::Ipv4Addr>)> {
    use kuroshio_proto::message::{Message, RData};
    let mut buf = vec![0u8; 4096];
    let n = sock.recv(&mut buf).ok()?;
    let m = Message::parse(&buf[..n]).ok()?;
    let ips = m
        .answers
        .iter()
        .filter_map(|r| match r.data {
            RData::A(a) => Some(a),
            _ => None,
        })
        .collect();
    Some((m.id, m.rcode, ips))
}

fn udp_client(port: u16, wait: Duration) -> std::net::UdpSocket {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    s.connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(wait)).unwrap();
    s
}

/// 只開一般 DNS（固定的埠）、上游只有假的上游
fn plain_config(dir: &Path, port: u16, up: std::net::SocketAddr, over: Value) -> Value {
    let mut v = config(
        dir,
        json!({
            "upstream": { "pinned": [format!("udp://{up}")] },
            "listen": { "plain": { "binds": ["127.0.0.1"], "port": port }, "doh": { "enabled": false } },
            "site": { "enabled": false },
            "cdn": { "enabled": false },
        }),
    );
    kuroshio_config::merge(&mut v, &over);
    v
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

/// 每 10 ms 送一筆 `name` 的查詢（id 從 1000 起），直到 `stop`
fn flood(s: std::net::UdpSocket, name: &'static str, stop: Arc<AtomicBool>, sent: Arc<AtomicUsize>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut id = 1000u16;
        while !stop.load(Ordering::SeqCst) {
            s.send(&kuroshio_proto::build_query(id, name, 1)).unwrap();
            sent.fetch_add(1, Ordering::SeqCst);
            id += 1;
            std::thread::sleep(Duration::from_millis(10));
        }
    })
}

/// 重新載入的交接那一刻（3.5.1）：舊的一輪交出快取之前先停止收查詢、等處理中的做完。
/// - 交接期間一直送的查詢（快取命中的名稱）每一筆都剛好得到一次正確的答案：舊的一輪回答，或留在核心的
///   接收緩衝區給新的一輪回答；沒有 SERVFAIL、沒有空答案、沒有被丟掉的。
/// - 交接時正在問上游的查詢照常回完，問到的答案跟著快取交出去（新的一輪不用再問）。
/// - 快取交出去之後舊的一輪不再讀監聽 socket（以前會讀走、快取沒命中又去問上游，
///   碰上執行環境關閉時回 SERVFAIL，或跟著執行環境一起丟掉）
#[test]
fn reload_stops_reading_before_handing_over_cache() {
    let _g = serial();
    let dir = tmp("quiesce");
    let (up, asked) = counting_upstream(Duration::from_millis(300));
    let port = free_dns_port();
    let cfg = plain_config(&dir, port, up, json!({}));

    // 交接期間一直送的查詢：另一條執行緒收回應，送完之後連續 2 秒收不到才結束
    let client = udp_client(port, Duration::from_millis(200));
    let (stop, sent) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicUsize::new(0)));
    let reader = {
        let (s, stop) = (client.try_clone().unwrap(), stop.clone());
        std::thread::spawn(move || {
            let mut got = Vec::new();
            let mut idle = 0;
            while idle < 10 {
                match recv_answer(&s) {
                    Some(r) => got.push(r),
                    None if stop.load(Ordering::SeqCst) => idle += 1,
                    None => {}
                }
            }
            got
        })
    };

    let rt = runtime();
    let (b, late) = rt.block_on(async {
        let s = kuroshio::app::start(&cfg).await.unwrap();
        // 第一輪：a.example.com 進快取
        let c = udp_client(port, Duration::from_secs(3));
        c.send(&kuroshio_proto::build_query(1, "a.example.com", 1)).unwrap();
        let a = tokio::task::spawn_blocking(move || recv_answer(&c)).await.unwrap();
        assert_eq!(a, Some((1, 0, vec![answer_ip()])));
        let tx = flood(client.try_clone().unwrap(), "a.example.com", stop.clone(), sent.clone());
        tokio::time::sleep(Duration::from_millis(100)).await;
        // 交接時正在問上游的查詢（上游 300 ms 才回）
        let cb = udp_client(port, Duration::from_millis(1));
        cb.send(&kuroshio_proto::build_query(2, "b.example.com", 1)).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        s.shutdown_reload().await;
        assert!(s.resolver.serving.retired(), "快取交出去了");
        assert_eq!(s.resolver.serving.pending(), 0, "處理中的查詢都做完才交出快取");
        // 交接時正在問上游的那一筆：交出快取之前舊的一輪就回了
        let b = recv_answer(&cb);
        // 快取交出去之後送的查詢：舊的一輪（執行環境還在）不讀，留給新的一輪
        let late = udp_client(port, Duration::from_millis(300));
        late.send(&kuroshio_proto::build_query(3, "a.example.com", 1)).unwrap();
        let (late, r) = tokio::task::spawn_blocking(move || {
            let r = recv_answer(&late);
            (late, r)
        })
        .await
        .unwrap();
        assert_eq!(r, None, "快取交出去之後舊的一輪不再讀監聽 socket");
        drop(tx);
        (b, late)
    });
    assert_eq!(b, Some((2, 0, vec![answer_ip()])), "交接時正在問上游的查詢照常回完");
    rt.shutdown_timeout(Duration::from_secs(3));

    // 第二輪（新的一輪）：接手快取（a、b 都在），留在接收緩衝區的查詢由它回答
    let rt = runtime();
    rt.block_on(async {
        let s = kuroshio::app::start(&cfg).await.unwrap();
        assert!(s.resolver.cache_adopted.load(Ordering::SeqCst), "接手上一輪的快取");
        late.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let r = tokio::task::spawn_blocking(move || recv_answer(&late)).await.unwrap();
        assert_eq!(r, Some((3, 0, vec![answer_ip()])), "空窗期間送的查詢由新的一輪回答");
        // b 跟著快取交過來：不用再問上游
        let c = udp_client(port, Duration::from_secs(3));
        c.send(&kuroshio_proto::build_query(4, "b.example.com", 1)).unwrap();
        let r = tokio::task::spawn_blocking(move || recv_answer(&c)).await.unwrap();
        assert_eq!(r, Some((4, 0, vec![answer_ip()])));
        tokio::time::sleep(Duration::from_millis(200)).await;
        stop.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(100)).await;
        s.shutdown_reload().await;
    });
    rt.shutdown_timeout(Duration::from_secs(3));
    let got = reader.join().unwrap();
    let sent = sent.load(Ordering::SeqCst);
    assert!(sent > 10, "交接期間送了 {sent} 筆");
    let bad: Vec<_> = got.iter().filter(|(_, rcode, ips)| *rcode != 0 || *ips != [answer_ip()]).collect();
    assert!(bad.is_empty(), "答案不對（id, rcode, A）：{bad:?}");
    let mut ids: Vec<u16> = got.iter().map(|r| r.0).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!((ids.len(), got.len()), (sent, sent), "每一筆都剛好回一次");
    assert_eq!(
        asked.load(Ordering::SeqCst),
        2,
        "上游只被問過 a、b 各一次（交接時沒有因為快取不在而去問）"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// 重新載入且接手了上一輪的 DNS 快取（3.5.1）：不重跑開機預熱、不送任何查詢；開機與快取沒接手
/// （上游、解析的設定改了）時照舊預熱。以前每次重新載入都把整份常用網域名單再問一次上游
#[test]
fn reload_with_adopted_cache_skips_warmup() {
    let _g = serial();
    let dir = tmp("warm");
    std::fs::write(
        dir.join("state").join("hot-names.json"),
        r#"["1|w1.example.com","1|w2.example.com","28|w1.example.com"]"#,
    )
    .unwrap();
    let (up, asked) = counting_upstream(Duration::ZERO);
    let cfg = plain_config(&dir, 0, up, json!({ "resolver": { "warmRate": 20 } }));
    let round = |cfg: &Value| {
        let rt = runtime();
        let adopted = rt.block_on(async {
            let s = kuroshio::app::start(cfg).await.unwrap();
            // 預熱 3 秒後開始，每秒 20 筆
            tokio::time::sleep(Duration::from_millis(3600)).await;
            let adopted = s.resolver.cache_adopted.load(Ordering::SeqCst);
            s.shutdown_reload().await;
            adopted
        });
        rt.shutdown_timeout(Duration::from_secs(3));
        (adopted, asked.load(Ordering::SeqCst))
    };
    // 開機：照舊預熱名單裡的 3 個
    assert_eq!(round(&cfg), (false, 3), "開機照舊預熱");
    // 名單裡多一個快取裡沒有的（實際上是過期、被清掉或 CNAME 被丟掉的）：以前接手快取之後還是會去問
    std::fs::write(
        dir.join("state").join("hot-names.json"),
        r#"["1|w1.example.com","1|w2.example.com","28|w1.example.com","1|w3.example.com"]"#,
    )
    .unwrap();
    // 重新載入、接手快取：不預熱
    assert_eq!(round(&cfg), (true, 3), "接手快取的那一輪不預熱、不送查詢");
    // 解析的設定改了（快取重新開始）：照舊預熱
    let mut changed = cfg.clone();
    changed["resolver"]["timeoutMs"] = json!(1400);
    // 名單是上一輪寫出的（3.5.1 起跟上一份合併）：`28|w1` 在假的上游是沒有 AAAA（否定答案）不留，其他 3 個照舊預熱
    assert_eq!(round(&changed), (false, 6), "快取沒接手：照舊預熱");
    let _ = std::fs::remove_dir_all(&dir);
}
