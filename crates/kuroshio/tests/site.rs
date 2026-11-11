//! 公開網頁：路由、標頭、網域代入、使用偵測、描述檔、公開統計、詳細頁的唯讀 API 與 IP 打馬賽克，
//! 以及跟 node 版的對照（tests/vectors/site/cases.json 由 tests/vectors/site/gen.js 產生）。
//!
//! 不啟動任何監聽、不連外：AppState 直接組出來，上游指向不會用到的本機位址。

use kuroshio::app::{AppState, Encrypted};
use kuroshio::persist::Persister;
use kuroshio::presence::Presence;
use kuroshio::site::{Site, SiteResponse, READ_ONLY};
use serde_json::{json, Value};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("kuroshio-site-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("state")).unwrap();
    d
}

fn config(dir: &std::path::Path, over: Value) -> Value {
    let mut cfg = kuroshio_config::with_overrides(&json!({
        "system": { "persistDir": dir.join("state").to_string_lossy(), "dataDir": root().join("data").to_string_lossy() },
        "upstream": { "pinned": ["udp://127.0.0.1:9"], "fallback": [] },
        "resolver": { "lastResort": [], "rankIps": false, "cacheMax": 100 },
        "cdn": { "enabled": false },
        "site": { "enabled": true, "hostname": "dns.example" },
    }));
    kuroshio_config::merge(&mut cfg, &over);
    cfg
}

fn state(cfg: &Value) -> Arc<AppState> {
    let dir = kuroshio::app::persist_dir(cfg);
    let resolver = kuroshio::app::build_resolver(cfg).unwrap();
    Arc::new(AppState {
        resolver,
        persister: Arc::new(Mutex::new(Persister::new(&dir, kuroshio::app::persist_policy(cfg)))),
        info: kuroshio::sysinfo::SysInfo::detect(),
        reserve: kuroshio::memgov::reserve_from_cfg(cfg),
        persist_dir: dir.clone(),
        warm_names: 0,
        filter: None,
        ddns: None,
        acme: None,
        community: None,
        snap_sources: vec![],
        webui: Arc::new(kuroshio::webui::WebUi::new(cfg, &dir, &dir)),
        reload: Arc::new(tokio::sync::Notify::new()),
        scheduler: None,
        encrypted: Encrypted::default(),
        backup: kuroshio::backup::Locations::from_cfg(cfg),
        cfg: Arc::new(cfg.clone()),
        memgov: None,
    })
}

fn site(cfg: &Value) -> (Arc<Site>, Arc<AppState>, Option<Arc<Presence>>) {
    let st = state(cfg);
    let p = Presence::from_cfg(cfg);
    (Site::new(cfg, st.clone(), p.clone()).expect("site.enabled"), st, p)
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

async fn get(s: &Site, target: &str) -> Option<SiteResponse> {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    s.handle("GET", path, query, ip("192.0.2.10"), Some("ignored.example")).await
}

fn text(r: &SiteResponse) -> String {
    String::from_utf8(r.body.to_vec()).unwrap()
}

fn json_of(r: &SiteResponse) -> Value {
    serde_json::from_slice(&r.body).unwrap()
}

#[tokio::test]
async fn routing_and_headers() {
    let dir = tmp("routing");
    let (s, _, _) = site(&config(&dir, json!({})));

    let r = get(&s, "/").await.unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-type"), Some("text/html; charset=utf-8"));
    assert_eq!(r.header("cache-control"), Some("no-cache"));
    assert_eq!(
        r.header("x-robots-tag"),
        Some("noindex, nofollow, noarchive, nosnippet, noimageindex")
    );
    assert_eq!(r.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(r.header("referrer-policy"), Some("no-referrer"));
    let html = text(&r);
    assert!(html.contains("黑潮 DNS"));
    assert!(html.contains("https://dns.example/dns-query"), "網域與 DoH 路徑已代入");
    assert!(!html.contains("{{"), "沒有剩下的佔位字");
    assert!(!html.contains("ignored.example"), "有設定網域時不用 Host 標頭");
    assert_eq!(get(&s, "/index.html").await.unwrap().status, 200);

    let r = get(&s, "/robots.txt").await.unwrap();
    assert_eq!((r.status, text(&r).as_str()), (200, "User-agent: *\nDisallow: /\n"));
    let r = get(&s, "/favicon.ico").await.unwrap();
    assert_eq!(r.header("content-type"), Some("image/svg+xml"));
    assert_eq!(r.header("cache-control"), Some("max-age=86400"));
    assert!(text(&r).starts_with("<svg"));
    assert_eq!(get(&s, "/favicon.svg").await.unwrap().status, 200);
    let r = get(&s, "/nope").await.unwrap();
    assert_eq!((r.status, text(&r).as_str()), (404, "Not found"));

    // 交給 DoH 的請求
    assert!(get(&s, "/dns-query").await.is_none());
    assert!(get(&s, "/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB")
        .await
        .is_none());
    assert!(get(&s, "/?dns=AAAB").await.is_none(), "任何帶 ?dns= 的請求");
    assert!(s.handle("POST", "/", "", ip("192.0.2.10"), None).await.is_none());
    assert!(s.handle("PUT", "/robots.txt", "", ip("192.0.2.10"), None).await.is_none());

    // HEAD：標頭一樣、沒有內容
    let full = get(&s, "/robots.txt").await.unwrap();
    let h = s.handle("HEAD", "/robots.txt", "", ip("192.0.2.10"), None).await.unwrap();
    assert_eq!(h.status, 200);
    assert!(h.body.is_empty());
    assert_eq!(h.header("content-length"), Some(full.body.len().to_string().as_str()));
    assert_eq!(h.header("content-type"), full.header("content-type"));

    // 詳細頁
    let r = get(&s, "/detail").await.unwrap();
    assert_eq!(r.status, 301);
    assert_eq!(r.header("location"), Some("/detail/"));
    assert_eq!(r.header("x-robots-tag"), Some(kuroshio::site::NOINDEX));
    for p in ["/detail/", "/detail/index.html"] {
        let r = get(&s, p).await.unwrap();
        assert_eq!(r.status, 200, "{p}");
        assert_eq!(r.header("cache-control"), Some("no-store"));
        assert!(text(&r).contains("黑潮 DNS · 詳細數據"));
    }
    assert_eq!(get(&s, "/detailed").await.unwrap().status, 404, "只認整段路徑");
    let r = get(&s, "/detail/api/public?range=7d").await.unwrap();
    assert_eq!(json_of(&r)["range"], "7d");
    assert_eq!(r.header("cache-control"), Some("no-store"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn custom_paths() {
    let dir = tmp("paths");
    // 詳細頁路徑撞到保留路徑 → 用預設；DoH 路徑改過 → 那個路徑交給 DoH
    let cfg = config(
        &dir,
        json!({ "site": { "detailPath": "/api" }, "listen": { "doh": { "path": "/q" } } }),
    );
    let (s, _, _) = site(&cfg);
    assert_eq!(s.detail_path(), "/detail");
    assert!(get(&s, "/q").await.is_none());
    assert!(get(&s, "/dns-query").await.is_none());
    assert!(text(&get(&s, "/").await.unwrap()).contains("https://dns.example/q"));
    let cfg = config(&dir, json!({ "site": { "detailPath": "secret/" } }));
    let (s, _, _) = site(&cfg);
    assert_eq!(get(&s, "/secret").await.unwrap().header("location"), Some("/secret/"));
    assert_eq!(get(&s, "/detail/").await.unwrap().status, 404);
    // 自己的網頁檔
    std::fs::write(dir.join("mine.html"), "<p>{{HOST}}{{DOH_PATH}}</p>").unwrap();
    let cfg = config(&dir, json!({ "site": { "htmlFile": dir.join("mine.html").to_string_lossy() } }));
    let (s, _, _) = site(&cfg);
    assert_eq!(text(&get(&s, "/").await.unwrap()), "<p>dns.example/dns-query</p>");
    // 檔案改了就重新讀
    std::thread::sleep(std::time::Duration::from_millis(20));
    std::fs::write(dir.join("mine.html"), "<p>改過了 {{HOST}}</p>").unwrap();
    let f = std::fs::File::options().write(true).open(dir.join("mine.html")).unwrap();
    f.set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(5))
        .unwrap();
    assert_eq!(text(&get(&s, "/").await.unwrap()), "<p>改過了 dns.example</p>");
    // 網頁檔讀不到 → 500
    let cfg = config(&dir, json!({ "system": { "dataDir": dir.join("none").to_string_lossy() } }));
    let (s, _, _) = site(&cfg);
    assert_eq!(get(&s, "/").await.unwrap().status, 500);
    assert_eq!(get(&s, "/robots.txt").await.unwrap().status, 200);
    // 關掉
    let off = config(&dir, json!({ "site": { "enabled": false } }));
    assert!(Site::new(&off, state(&off), None).is_none());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn empty_hostname_uses_host_header() {
    let dir = tmp("nohost");
    let (s, _, p) = site(&config(&dir, json!({ "site": { "hostname": "" } })));
    let c = ip("192.0.2.10");
    let html = text(&s.handle("GET", "/", "", c, Some("Router.Example:8443")).await.unwrap());
    assert!(html.contains("https://router.example/dns-query"));
    let html = text(&s.handle("GET", "/", "", c, Some("<script>")).await.unwrap());
    assert!(html.contains(kuroshio::site::PLACEHOLDER_HOST), "奇怪的 Host 改用佔位網域");
    assert!(!html.contains("{{HOST}}"));
    let html = text(&s.handle("GET", "/", "", c, None).await.unwrap());
    assert!(html.contains("https://dns.example/dns-query"));
    let info: Value = json_of(&s.handle("GET", "/api/public/info", "", c, Some("[2001:db8::1]:443")).await.unwrap());
    assert_eq!(info["doh"], "https://[2001:db8::1]/dns-query");
    // 沒有網域：TTL 不壓、只能判斷到 network
    let p = p.unwrap();
    assert_eq!(p.own_host_ttl("router.example"), None);
    p.record("doh", c, "router.example");
    assert_eq!(
        json_of(&s.handle("GET", "/api/public/presence", "", c, None).await.unwrap())["state"],
        "network"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn presence_and_info() {
    let dir = tmp("presence");
    let (s, _, p) = site(&config(&dir, json!({})));
    let p = p.unwrap();
    let me = ip("2001:db8:aa:bb::1");
    let presence = |client: IpAddr| {
        let s = s.clone();
        async move {
            let r = s.handle("GET", "/api/public/presence", "", client, None).await.unwrap();
            assert_eq!(r.header("cache-control"), Some("no-store"));
            json_of(&r)
        }
    };
    assert_eq!(presence(me).await, json!({ "state": "no" }));
    p.record("dot", ip("2001:db8:aa:bb::99"), "DNS.EXAMPLE.");
    let st = presence(me).await;
    assert_eq!(st["state"], "yes", "同一個 /64");
    assert_eq!(st["protocol"], "DoT");
    assert!(st.get("ip").is_none());
    p.record("udp", ip("192.0.2.50"), "www.example.com");
    assert_eq!(presence(ip("192.0.2.50")).await["state"], "network");
    assert_eq!(presence(ip("192.0.2.51")).await["state"], "no");
    assert_eq!(p.own_host_ttl("dns.example"), Some(10));
    assert_eq!(p.own_host_ttl("example.com"), None);

    s.set_ips(vec![ip("192.0.2.1")], vec![ip("2001:db8::1")]);
    let info = json_of(&get(&s, "/api/public/info").await.unwrap());
    assert_eq!(info["host"], "dns.example");
    assert_eq!(info["doh"], "https://dns.example/dns-query");
    assert_eq!(info["dot"], "dns.example");
    assert_eq!(info["dotPort"], 853);
    assert_eq!(info["ipv4"], json!(["192.0.2.1"]));
    assert_eq!(info["ipv6"], json!(["2001:db8::1"]));
    assert_eq!(info["presence"], json!({ "enabled": true, "method": "ip" }));

    // 偵測關掉：公開頁回 unknown
    let cfg = config(&dir, json!({ "check": { "enabled": false } }));
    let (s, _, p) = site(&cfg);
    assert!(p.is_none());
    assert_eq!(
        json_of(&get(&s, "/api/public/presence").await.unwrap()),
        json!({ "state": "unknown" })
    );
    assert_eq!(json_of(&get(&s, "/api/public/info").await.unwrap())["presence"], Value::Null);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn mobileconfig() {
    let dir = tmp("apple");
    let (s, _, _) = site(&config(&dir, json!({})));
    let doh = get(&s, "/apple/doh.mobileconfig").await.unwrap();
    assert_eq!(doh.status, 200);
    assert_eq!(doh.header("content-type"), Some("application/x-apple-aspen-config"));
    assert_eq!(
        doh.header("content-disposition"),
        Some("attachment; filename=\"dns.example-doh.mobileconfig\"")
    );
    let x = text(&doh);
    assert!(x.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist"));
    assert!(x.ends_with("</plist>\n"));
    for tag in ["dict", "array", "plist"] {
        assert_eq!(
            x.matches(&format!("<{tag}>")).count() + x.matches(&format!("<{tag} ")).count(),
            x.matches(&format!("</{tag}>")).count(),
            "{tag} 成對"
        );
    }
    assert_eq!(x.matches("<string>").count(), x.matches("</string>").count());
    assert!(x.contains("<key>ServerURL</key><string>https://dns.example/dns-query</string>"));
    assert!(x.contains("<key>PayloadIdentifier</key><string>example.dns.doh</string>"));
    assert!(x.contains("黑潮 DNS"));
    assert_eq!(
        x,
        text(&get(&s, "/apple/doh.mobileconfig").await.unwrap()),
        "每次下載都一樣（UUID 固定）"
    );
    let dot = text(&get(&s, "/apple/dot.mobileconfig").await.unwrap());
    assert!(dot.contains("<key>ServerName</key><string>dns.example</string>"));
    assert!(!dot.contains("ServerURL"));
    let uuids = |t: &str| {
        t.match_indices("<key>PayloadUUID</key><string>")
            .map(|(i, _)| t[i + 31..i + 67].to_string())
            .collect::<Vec<_>>()
    };
    assert_eq!(uuids(&x).len(), 2);
    assert_ne!(uuids(&x), uuids(&dot), "DoH 與 DoT 的 UUID 不同");
    // XML 跳脫
    let odd = kuroshio::site::mobileconfig("dot", "a&b.test", "/dns-query");
    assert!(odd.contains("<string>a&amp;b.test</string>"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn public_stats_ranges() {
    let dir = tmp("stats");
    let (s, st, _) = site(&config(&dir, json!({ "site": { "minClients": 2 } })));
    let stats = &st.resolver.stats;
    // 過去 40 天的快照（每天 query = 日序、blocked = 1），只會留 31 天
    let today = kuroshio::stats::taipei_date(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    );
    let days: Vec<Value> = (1..=40)
        .map(|d| {
            json!({ "date": format!("2001-{:02}-{:02}", 1 + (d - 1) / 28, 1 + (d - 1) % 28), "query": d, "hit": 1, "blocked": 1, "blockedAds": 1,
                "route": { "cloudflare": { "n": 10, "abroad": 4, "acc": 3, "miss": 1, "saved": 30, "savedN": 3 } },
                "cross": { "fastly>cloudflare": 1 }, "crossRewrite": 1, "cdn": { "cloudflare": 2 },
                "sites": { "example.com": [5, 3], "solo.example": [9, 1] } })
        })
        .collect();
    assert!(stats.restore(&serde_json::to_vec(&json!({ "version": 1, "days": days })).unwrap()));
    for _ in 0..4 {
        stats.count(kuroshio::stats::Kind::Query);
    }
    stats.count(kuroshio::stats::Kind::Hit);
    stats.site("www.example.com", ip("192.0.2.1"));
    stats.site("img.example.com", ip("192.0.2.2"));
    stats.site("only.example.net", ip("192.0.2.1"));

    let t = s.public_stats("today");
    assert_eq!(t["range"], "today");
    assert_eq!(t["days"], 1);
    assert_eq!(t["totals"]["queries"], 4);
    assert_eq!(t["totals"]["cacheHitRate"], 0.25);
    assert_eq!(
        t["topSites"],
        json!([{ "site": "example.com", "count": 2 }]),
        "只有一人造訪的網站不列"
    );
    assert_eq!(t["realtime"].as_array().unwrap().len(), 60);
    assert_eq!(t["opportunity"]["connections"], 0.0);
    assert_eq!(t["privacy"]["minClients"], 2);
    assert_eq!(t["trend"].as_array().unwrap().len(), 30);
    assert_eq!(t["trend"].as_array().unwrap().last().unwrap()["date"], today);
    assert!(t["generatedAt"].as_str().unwrap().ends_with('Z'));
    assert!(t["system"]["upstreams"].as_u64().unwrap() >= 1);

    let w = s.public_stats("7d");
    assert_eq!(w["days"], 7);
    // 過去 6 天是 35..=40
    assert_eq!(w["totals"]["queries"], (35..=40).sum::<u64>() + 4);
    assert_eq!(w["totals"]["blocked"], 6);
    assert_eq!(w["opportunity"]["connections"], 60.0);
    assert_eq!(w["opportunity"]["wouldGoAbroad"], 24.0);
    assert_eq!(w["opportunity"]["accelerated"], 18.0 + 6.0, "跨 CDN 也算加速");
    assert_eq!(w["opportunity"]["crossAccelerated"], 6);
    assert_eq!(w["opportunity"]["otherDnsAbroadShare"], 0.4);
    assert_eq!(w["opportunity"]["avgSavedMs"], 10.0);
    assert_eq!(w["routing"][0]["label"], "Cloudflare");
    assert_eq!(w["routing"][0]["successRate"], 0.75);
    assert_eq!(
        w["crossCdn"]["pairs"][0],
        json!({ "from": "fastly", "fromLabel": "Fastly", "to": "cloudflare", "toLabel": "Cloudflare", "count": 6 })
    );
    assert_eq!(w["cdn"][0]["share"], 1.0);
    assert_eq!(w["topSites"][0], json!({ "site": "example.com", "count": 5 * 6 + 2 }));
    assert_eq!(w["topSites"].as_array().unwrap().len(), 1);

    let m = s.public_stats("30d");
    assert_eq!(m["days"], 30);
    assert_eq!(m["totals"]["queries"], (12..=40).sum::<u64>() + 4);
    assert_eq!(s.public_stats("bogus")["range"], "today", "不認識的期間當成今天");
    let r = get(&s, "/api/public/stats?range=30d").await.unwrap();
    assert_eq!(r.header("cache-control"), Some("no-cache"));
    assert_eq!(json_of(&r)["days"], 30);
    let body = text(&r);
    assert!(!body.contains("192.0.2."), "公開統計不含 IP");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn read_only_api_hides_personal_doh_paths() {
    // 個人 DoH 網址的路徑常帶帳號代碼：詳細頁（公開）只給協議 + 主機（+ 非預設埠），管理 API 照樣給完整網址
    let dir = tmp("doh-path");
    let cfg = config(
        &dir,
        json!({ "upstream": { "pinned": ["https://doh.example/dns-query/secret-token", "https://doh.example:8443/q/other-token"] } }),
    );
    let (s, st, _) = site(&cfg);
    for p in ["/detail/api/upstreams", "/detail/api/status"] {
        let r = get(&s, p).await.unwrap();
        assert_eq!(r.status, 200);
        let body = text(&r);
        assert!(!body.contains("token"), "{p}：{body}");
    }
    let v = json_of(&get(&s, "/detail/api/upstreams").await.unwrap());
    let ids: Vec<&str> = v.as_array().unwrap().iter().map(|u| u["id"].as_str().unwrap()).collect();
    assert_eq!(ids, ["https://doh.example", "https://doh.example:8443"]);
    let raw = kuroshio::admin::route(&st, "/api/upstreams", &Default::default()).await.body;
    assert_eq!(raw[0]["id"], "https://doh.example/dns-query/secret-token");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn read_only_api_and_masking() {
    let dir = tmp("readonly");
    let (s, st, _) = site(&config(&dir, json!({})));
    st.resolver.stats.query_name("www.example.com", ip("203.0.113.77"));
    st.resolver.stats.query_name("www.example.com", ip("2001:db8:5:6::7"));

    let r = get(&s, "/detail/api/status").await.unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(r.header("cache-control"), Some("no-store"));
    let v = json_of(&r);
    let names: Vec<&str> = v["stats"]["topClients"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(names.len(), 2);
    assert!(names.contains(&"203.0.x.x"));
    assert!(names.contains(&"2001:db8:…"));
    assert!(!text(&r).contains("203.0.113.77"));
    assert_eq!(v["stats"]["topDomains"][0]["name"], "www.example.com", "網域不打馬賽克");
    // 本機的資料夾路徑不給外面看
    assert_eq!(v["system"]["persist"].get("dir"), None);
    assert!(!text(&r).contains(&dir.to_string_lossy().to_string()), "回應裡沒有狀態目錄的路徑");
    assert!(v["system"]["cores"].is_u64(), "其他欄位照舊");
    assert!(v["system"].get("tier").is_none(), "沒有硬體等級");
    // 本機管理 API 不受影響
    let raw = kuroshio::admin::route(&st, "/api/status", &Default::default()).await.body;
    assert_eq!(raw["stats"]["topClients"][0]["name"], "203.0.113.77");
    assert!(raw["system"]["persist"]["dir"].is_string());

    for p in [
        "/api/cache/flush",
        "/api/jobs/run",
        "/api/filter/update",
        "/api/cdn/verify",
        "/api/cdn/policy",
        "/api/ddns/update",
        "/api/nope",
        "/api/sysinfo",
    ] {
        let r = get(&s, &format!("/detail{p}?name=x")).await.unwrap();
        assert_eq!(r.status, 404, "{p} 不在唯讀清單");
        assert_eq!(json_of(&r), json!({ "error": "not found" }));
    }
    for p in ["/api/upstreams", "/api/jobs", "/api/routing"] {
        assert_eq!(get(&s, &format!("/detail{p}")).await.unwrap().status, 200, "{p}");
    }
    assert_eq!(
        get(&s, "/detail/api/filter/check").await.unwrap().status,
        400,
        "交給管理 API 判斷參數"
    );
    // 追蹤會讓這台去問所有上游、測 IP：同時最多 2 個，多的直接回 429（不排隊）
    let t = "/detail/api/trace?name=www.example.com";
    let (a, b, c, d) = tokio::join!(get(&s, t), get(&s, t), get(&s, t), get(&s, t));
    let codes: Vec<u16> = [a, b, c, d].into_iter().map(|r| r.unwrap().status).collect();
    assert_eq!(codes.iter().filter(|c| **c == 200).count(), 2, "{codes:?}");
    assert_eq!(codes.iter().filter(|c| **c == 429).count(), 2, "{codes:?}");
    // 本機管理 API 不受這個限制
    let q = [("name".to_string(), "www.example.com".to_string())].into_iter().collect();
    assert_eq!(kuroshio::admin::route(&st, "/api/trace", &q).await.code, 200);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn csv_download_with_cdn() {
    let dir = tmp("csv");
    let cfg = config(&dir, json!({ "cdn": { "enabled": true } }));
    let (s, st, _) = site(&cfg);
    let net: Arc<dyn kuroshio_cdn::Net> = Arc::new(kuroshio_cdn::RealNet::new(st.resolver.iprank.clone()));
    let cdn = kuroshio_cdn::Cdn::load(&cfg, kuroshio_cdn::Paths::new(dir.join("state"), dir.join("data")), net);
    st.resolver.set_cdn(Some(cdn));
    let r = get(&s, "/detail/api/cdn/domains?format=csv&provider=cloudflare").await.unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-type"), Some("text/csv; charset=utf-8"));
    assert_eq!(
        r.header("content-disposition"),
        Some("attachment; filename=\"cdn-domains-cloudflare.csv\"")
    );
    assert_eq!(r.header("cache-control"), Some("no-store"));
    // 查詢參數帶換行：不能進到回應標頭（DoH 伺服器組回應時遇到不合法的標頭會 panic，正式版 panic = 整個服務結束）
    for evil in ["x%0d%0aSet-Cookie:%20a=b", "%0a", "%00", "a%22b"] {
        let r = get(&s, &format!("/detail/api/cdn/domains?format=csv&provider={evil}"))
            .await
            .unwrap();
        assert_eq!(r.status, 200);
        for (k, v) in &r.headers {
            assert!(http::HeaderValue::from_str(v).is_ok(), "{k}: {v:?} 不是合法的標頭");
            assert!(!v.contains(['\r', '\n', '\0']), "{k}: {v:?}");
        }
        let cd = r.header("content-disposition").unwrap();
        assert!(
            cd.starts_with("attachment; filename=\"cdn-domains-") && cd.ends_with(".csv\""),
            "{cd}"
        );
        assert_eq!(cd.matches('"').count(), 2, "{cd}");
    }
    // 整個資料庫的輸出每分鐘有上限（上面已經要了 5 次）
    let mut limited = 0;
    for _ in 0..40 {
        let r = get(&s, "/detail/api/cdn/domains?limit=5").await.unwrap();
        if r.status == 429 {
            limited += 1;
            assert_eq!(r.header("cache-control"), Some("no-store"));
        }
    }
    assert_eq!(limited, 15, "每分鐘 30 次");
    // CDN 開著時公開統計也算得出來：加速成效、原本的 POP → 台灣 POP（依查詢次數加權）
    let entries = [
        json!({ "name": "a.example", "provider": "cloudflare", "hits": 5, "base": { "pop": "SJC", "ms": 150 }, "v4": { "verdict": "ok", "pop": "TPE", "ms": 20 } }),
        json!({ "name": "b.example", "provider": "akamai", "hits": 0, "base": { "pop": "HKG", "ms": 50 }, "ecs": { "verdict": "ok", "gainMs": 40 } }),
        json!({ "name": "c.example", "provider": "fastly", "hits": 2, "base": { "pop": "TPE" },
                "cross4": { "verdict": "ok", "from": "fastly", "to": "cloudflare" } }),
    ];
    st.resolver.cdn().unwrap().with_state(|x| {
        for e in &entries {
            let d: kuroshio_cdn::db::Domain = serde_json::from_value(e.clone()).unwrap();
            x.db.domains.insert(d.name.clone(), d);
        }
    });
    let v = s.public_stats("7d");
    assert_eq!(v["acceleration"]["verifiedSites"], 2);
    assert_eq!(v["acceleration"]["sitesRoutedAbroad"], 2);
    assert_eq!(v["acceleration"]["samples"], 2);
    assert_eq!(v["acceleration"]["medianSavedMs"], 130.0);
    assert_eq!(
        v["flows"],
        json!([{ "pop": "SJC", "count": 5, "fixed": 5 }, { "pop": "HKG", "count": 1, "fixed": 0 }])
    );
    assert_eq!(v["toPops"], json!({ "TPE": 5 }));
    assert_eq!(v["crossCdn"]["explored"], 1);
    assert_eq!(v["crossCdn"]["successRate"], 1.0);
    assert_eq!(
        v["crossCdn"]["byTo"],
        json!([{ "provider": "cloudflare", "label": "Cloudflare", "sites": 1 }])
    );
    assert_eq!(
        v["crossCdn"]["byFrom"],
        json!([{ "provider": "fastly", "label": "Fastly", "explored": 1, "ok": 1 }])
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// 分享用的 QR 碼：只產生固定的三種內容（這個頁面、DoH 網址、原始碼），不認識的一律當成這個頁面
#[tokio::test]
async fn share_qr_codes() {
    let dir = tmp("qr");
    let (s, _, _) = site(&config(
        &dir,
        json!({ "about": { "sourceUrl": "https://git.example.org/me/kuroshio" } }),
    ));
    let qr = |t: &str| kuroshio::about::qr_svg(t).unwrap();
    for (q, want) in [
        ("for=site", qr("https://dns.example/")),
        ("for=doh", qr("https://dns.example/dns-query")),
        ("for=source", qr("https://git.example.org/me/kuroshio")),
        ("for=https://evil.example/", qr("https://dns.example/")),
        ("for=", qr("https://dns.example/")),
        ("", qr("https://dns.example/")),
    ] {
        let r = get(&s, &format!("/qr.svg?{q}")).await.unwrap();
        assert_eq!(r.status, 200, "{q}");
        assert_eq!(r.header("content-type"), Some("image/svg+xml"), "{q}");
        assert_eq!(r.header("x-content-type-options"), Some("nosniff"));
        let body = text(&r);
        assert!(body.contains("<svg"), "{q}");
        assert_eq!(body, want, "{q}");
    }
    assert_ne!(
        text(&get(&s, "/qr.svg?for=doh").await.unwrap()),
        text(&get(&s, "/qr.svg?for=site").await.unwrap())
    );

    // 網頁：分享區、關於（版本與原始碼由 /api/public/info 的 about 帶入，不寫死）
    let html = text(&get(&s, "/").await.unwrap());
    for x in [
        "/qr.svg?for=site",
        "/qr.svg?for=doh",
        "/qr.svg?for=source",
        "GPL-3.0",
        "id=\"abSrc\"",
        "https://dns.example/",
        "rel=\"noopener noreferrer\"",
    ] {
        assert!(html.contains(x), "首頁缺少 {x}");
    }
    let detail = text(&get(&s, "/detail/").await.unwrap());
    for x in ["/qr.svg?for=source", "/api/public/info", "GPL-3.0", "id=\"abSrc\""] {
        assert!(detail.contains(x), "詳細頁缺少 {x}");
    }
    let info = json_of(&get(&s, "/api/public/info").await.unwrap());
    assert_eq!(info["about"]["source"], "https://git.example.org/me/kuroshio");
    assert_eq!(info["about"]["license"], "GPL-3.0-or-later");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// 跟 node 版對照
#[test]
fn parity_with_node() {
    let v: Value = serde_json::from_slice(&std::fs::read(root().join("tests/vectors/site/cases.json")).unwrap()).unwrap();
    for c in v["mobileconfig"].as_array().unwrap() {
        let (host, kind) = (c["host"].as_str().unwrap(), c["kind"].as_str().unwrap());
        let x = kuroshio::site::mobileconfig(kind, host, "/dns-query");
        let pick = |key: &str| -> Vec<String> {
            let pat = format!("<key>{key}</key><string>");
            x.match_indices(&pat)
                .map(|(i, _)| {
                    let rest = &x[i + pat.len()..];
                    rest[..rest.find('<').unwrap()].to_string()
                })
                .collect()
        };
        let want = |k: &str| -> Vec<String> { c[k].as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect() };
        assert_eq!(pick("PayloadUUID"), want("uuids"), "{host} {kind}");
        assert_eq!(pick("PayloadIdentifier"), want("identifiers"), "{host} {kind}");
        assert_eq!(pick("ServerURL"), want("serverUrl"), "{host} {kind}");
        assert_eq!(pick("ServerName"), want("serverName"), "{host} {kind}");
    }
    for c in v["sites"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        assert_eq!(
            kuroshio::stats::site_of(name).map(Value::from).unwrap_or(Value::Null),
            c["site"],
            "{name}"
        );
    }
    for c in v["groups"].as_array().unwrap() {
        let (a, b) = (ip(c["a"].as_str().unwrap()), ip(c["b"].as_str().unwrap()));
        assert_eq!(
            kuroshio::presence::Key::of(a) == kuroshio::presence::Key::of(b),
            c["same"].as_bool().unwrap(),
            "{a} / {b}"
        );
    }
    let mut ro: Vec<&str> = READ_ONLY.to_vec();
    ro.sort();
    assert_eq!(json!(ro), v["readOnly"]);
}

/// 不可以寫死任何真實網域
#[test]
fn no_hardcoded_domain() {
    for f in [
        "data/site/index.html",
        "data/site/detail.html",
        "crates/kuroshio/src/site.rs",
        "crates/kuroshio/src/presence.rs",
    ] {
        let t = std::fs::read_to_string(root().join(f)).unwrap().to_lowercase();
        assert!(!t.contains("candy"), "{f}");
    }
}
