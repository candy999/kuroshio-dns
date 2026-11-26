//! 重新載入設定（3.5.1 測試版 D3：每次 SIGHUP RSS 長約 10 MB、不會降）：一輪結束、執行環境關掉之後，
//! 這一輪的結構（整體狀態、解析器、過濾服務、CDN 資料庫）都要放掉，不能被循環參照或背景工作抓著。
//!
//! 每一輪照正式執行的方式在自己的執行環境裡跑（`main.rs` 的 `generation`）：建立、啟動、`shutdown`、關掉執行環境。

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
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
