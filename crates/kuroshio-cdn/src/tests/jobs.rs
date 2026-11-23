//! 背景工作（範圍下載、網段分類、節點池）用假的網路測

use super::*;
use crate::jobs::{pool, ranges, scan, Checkpoint, JobCtx};
use crate::util::Num;
use kuroshio_net::iprank::{Latency, Quality};
use std::sync::atomic::{AtomicUsize, Ordering};

pub(super) fn ctx_for(providers: Value, extra: Value) -> (JobCtx, Arc<MockNet>, Paths) {
    let net = MockNet::new();
    let paths = paths_no_seed("jobs");
    let mut cfg = json!({ "cdn": { "providers": providers, "ecs": { "twSubnets": ["168.95.0.0/24"] } } });
    kuroshio_config::merge(&mut cfg, &extra);
    let cdn = Cdn::load(&cfg, paths.clone(), net.clone());
    cdn.record_tasks();
    (JobCtx::new(cfg, cdn), net, paths)
}

pub(super) fn write(paths: &Paths, rel: &str, body: &str) {
    let p = paths.state_dir.join("cdn").join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, body).unwrap();
}

fn read(paths: &Paths, rel: &str) -> String {
    std::fs::read_to_string(paths.state_dir.join("cdn").join(rel)).unwrap()
}

#[tokio::test]
async fn ranges_job_writes_only_when_changed() {
    let (ctx, net, paths) = ctx_for(
        json!({ "cloudflare": {"enabled": true}, "fastly": {"enabled": true}, "gcore": {"enabled": true} }),
        json!({}),
    );
    {
        let mut f = net.fetch.lock().unwrap();
        f.insert(
            "https://www.cloudflare.com/ips-v4".into(),
            "173.245.48.0/20\n104.16.0.0/13\n".into(),
        );
        f.insert(
            "https://www.cloudflare.com/ips-v6".into(),
            "2400:cb00::/32\n2606:4700::/32\n".into(),
        );
        f.insert(
            "https://api.fastly.com/public-ip-list".into(),
            r#"{"addresses":["151.101.0.0/16"],"ipv6_addresses":["2a04:4e40::/32"]}"#.into(),
        );
    }
    let r = ranges::run(&ctx).await.unwrap();
    assert!(r.changed);
    assert_eq!(read(&paths, "ranges/cloudflare-ipv4.txt"), "173.245.48.0/20\n104.16.0.0/13\n");
    assert_eq!(read(&paths, "ranges/fastly-ipv6.txt"), "2a04:4e40::/32\n");
    let gcore = r.providers.iter().find(|p| p.provider == "gcore").unwrap();
    assert!(gcore.result.is_err(), "抓取失敗保留舊資料");
    assert!(paths.state_dir.join("cdn/ranges/.done").exists());
    // 重新讀取：新的範圍生效
    assert_eq!(ctx.cdn.classify(ip("173.245.50.1")).unwrap().provider, "cloudflare");
    let done1 = std::fs::metadata(paths.state_dir.join("cdn/ranges/cloudflare-ipv4.txt"))
        .unwrap()
        .modified()
        .unwrap();
    let r2 = ranges::run(&ctx).await.unwrap();
    assert!(!r2.changed, "內容沒變不寫");
    let done2 = std::fs::metadata(paths.state_dir.join("cdn/ranges/cloudflare-ipv4.txt"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(done1, done2);
    // 全部失敗 → 錯誤
    net.fetch.lock().unwrap().clear();
    assert!(ranges::run(&ctx).await.is_err());
}

#[tokio::test]
async fn scan_job_classifies_and_checks_safety() {
    let (ctx, net, paths) = ctx_for(
        json!({ "cloudflare": {"enabled": true} }),
        json!({ "scan": { "samplesPerSubnet": 3, "concurrency": 3 } }),
    );
    write(&paths, "ranges/cloudflare-ipv4.txt", "104.16.0.0/22\n");
    net.on_http(|i, _| {
        let o = match i {
            IpAddr::V4(v) => v.octets()[2],
            _ => 9,
        };
        match o {
            0 => resp(200, &[], "fl=1\ncolo=TPE\n"),
            1 => resp(200, &[("cf-ray", "x-HKG")], ""),
            2 => resp(403, &[], "no pop"),
            _ => fail("TIMEOUT"),
        }
    });
    let r = scan::run(&ctx).await.unwrap();
    let p = &r.providers[0];
    assert_eq!((p.tw, p.global, p.dead, p.written), (1, 2, 1, true));
    assert_eq!(read(&paths, "scan/cloudflare-ipv4-TW.txt"), "104.16.0.0/24\n");
    assert_eq!(read(&paths, "scan/cloudflare-ipv4-Global.txt"), "104.16.1.0/24\n104.16.2.0/24\n");
    assert_eq!(read(&paths, "scan/cloudflare-ipv4-Dead.txt"), "104.16.3.0/24\n");
    assert_eq!(ctx.cdn.classify(ip("104.16.0.9")).unwrap().cls, crate::Cls::Tw, "寫完重新載入");
    // 回應都不是這家 CDN（被攔截）：不覆蓋舊結果
    net.on_http(|_, _| resp(200, &[], "intercepted"));
    let r = scan::run(&ctx).await.unwrap();
    assert!(!r.providers[0].written);
    assert_eq!(read(&paths, "scan/cloudflare-ipv4-TW.txt"), "104.16.0.0/24\n");
}

#[tokio::test]
async fn pool_job_builds_taiwan_pool() {
    let (ctx, net, paths) = ctx_for(
        json!({ "cloudflare": {"enabled": true} }),
        json!({ "pool": { "candidatesPerProvider": 4, "poolSize": 3, "speedTop": 4 } }),
    );
    write(&paths, "scan/cloudflare-ipv4-TW.txt", "104.16.0.0/24\n104.16.1.0/24\n");
    net.on_ping(|i| match i {
        IpAddr::V4(v) if v.octets()[2] == 0 => lat(3.0),
        IpAddr::V4(_) => lat(70.0),
        IpAddr::V6(_) => Latency {
            ok: false,
            ms: f64::INFINITY,
        },
    });
    // 範圍外的 IP 混進流量收集、舊節點池：就算「回了台灣 POP、延遲很低」也不能進節點池，連測都不測
    ctx.cdn.with_state(|st| {
        st.db.add_harvest("cloudflare", ip("203.0.113.5"));
        st.db.add_harvest("cloudflare", ip("2001:db8::5"));
        st.pools
            .p
            .get_mut("cloudflare")
            .unwrap()
            .pool4
            .push(crate::pools::PoolNode::new(ip("198.51.100.9")));
    });
    net.on_ping(|i| match i {
        IpAddr::V4(v) if v.octets()[2] == 0 || v.octets()[0] != 104 => lat(1.0),
        IpAddr::V4(_) => lat(70.0),
        IpAddr::V6(_) => Latency {
            ok: false,
            ms: f64::INFINITY,
        },
    });
    net.on_http(|_, _| resp(200, &[], "colo=TPE"));
    net.on_speed(|_| 55.5);
    net.on_quality(|_| Quality {
        ms: 2.0,
        jitter: 0.1,
        loss: 0.0,
        n: 5,
    });
    let r = pool::run(&ctx).await.unwrap();
    assert!(!r.v6_ok);
    let p = &r.providers[0];
    assert_eq!(p.v4.len(), 1, "每個 /24 只留一個、超過延遲上限的不要");
    assert_eq!(p.v4[0].to_string().rsplit_once('.').unwrap().0, "104.16.0");
    let st = ctx.cdn.state();
    let n = &st.pools.p["cloudflare"].pool4[0];
    assert_eq!((n.ms, n.speed, n.pop.as_deref()), (Num::V(2.0), Num::V(55.5), Some("TPE")));
    assert!(st.pools.p["cloudflare"].rest.contains_key("updatedAt"));
    assert!(st.pools.dirty, "節點池換新後要寫快照");
    drop(st);
    assert!(
        net.calls("http 203.0.113.5").is_empty() && net.calls("http 198.51.100.9").is_empty(),
        "範圍外的不測"
    );
    assert!(!r.providers[0].v4.contains(&ip("203.0.113.5")) && !r.providers[0].v4.contains(&ip("198.51.100.9")));
}

#[tokio::test]
async fn pool_job_nearest_fastly() {
    let (ctx, net, paths) = ctx_for(json!({ "fastly": {"enabled": true} }), json!({}));
    write(&paths, "ranges/fastly-ipv4.txt", "151.101.0.0/22\n");
    let third = |i: IpAddr| match i {
        IpAddr::V4(v) => v.octets()[2],
        _ => 9,
    };
    net.on_ping(move |i| {
        if third(i) == 3 {
            Latency {
                ok: false,
                ms: f64::INFINITY,
            }
        } else {
            lat(20.0)
        }
    });
    net.on_http(move |i, _| match third(i) {
        0 | 1 => resp(200, &[("x-served-by", "cache-hkg17920-HKG")], ""),
        _ => resp(200, &[("x-served-by", "cache-nrt-rjtt8900042-NRT")], ""),
    });
    net.on_quality(move |i| Quality {
        ms: match third(i) {
            0 => 20.0,
            1 => 25.0,
            _ => 40.0,
        },
        jitter: 1.0,
        loss: 0.0,
        n: 10,
    });
    net.on_speed(|_| 10.0);
    net.hosts.lock().unwrap().insert("www.fastly.com".into(), ips(&["151.101.0.57"]));
    let r = pool::run(&ctx).await.unwrap();
    let p = &r.providers[0];
    assert_eq!(p.v4.len(), 3);
    let st = ctx.cdn.state();
    let d = &st.pools.p["fastly"];
    let pops: Vec<&str> = d.pool4.iter().map(|x| x.pop_str()).collect();
    assert_eq!(pops, ["HKG", "HKG", "NRT"]);
    assert_eq!(d.pool4[0].score, Num::V(22.0));
    assert_eq!(d.prefixes["HKG"].len(), 2);
    assert_eq!(st.pools.active_pops("fastly"), ["HKG", "NRT"]);
    assert_eq!(st.pools.best_pop("fastly").as_deref(), Some("HKG"));
}

/// 計數用的檢查點掛勾
fn counting_hook() -> (Checkpoint, Arc<AtomicUsize>) {
    let n = Arc::new(AtomicUsize::new(0));
    let n2 = n.clone();
    let f: Checkpoint = Arc::new(move || {
        n2.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {})
    });
    (f, n)
}

#[tokio::test]
async fn jobs_call_checkpoint_hook() {
    // 範圍下載：每家下載之前各一次
    let (ctx, net, paths) = ctx_for(
        json!({ "cloudflare": {"enabled": true}, "fastly": {"enabled": true} }),
        json!({ "scan": { "samplesPerSubnet": 1, "concurrency": 2 } }),
    );
    net.fetch
        .lock()
        .unwrap()
        .insert("https://www.cloudflare.com/ips-v4".into(), "104.16.0.0/22\n".into());
    net.fetch
        .lock()
        .unwrap()
        .insert("https://www.cloudflare.com/ips-v6".into(), "2606:4700::/32\n".into());
    let (hook, n) = counting_hook();
    let ctx = ctx.with_checkpoint(hook);
    ranges::run(&ctx).await.unwrap();
    assert_eq!(n.load(Ordering::SeqCst), 2, "cloudflare、fastly 各一次");
    // 網段分類：4 個 /24、並行 2 → 每批 8 個，一批一次
    write(&paths, "ranges/cloudflare-ipv4.txt", "104.16.0.0/22\n");
    net.on_http(|_, _| resp(200, &[], "colo=TPE"));
    n.store(0, Ordering::SeqCst);
    scan::run(&ctx).await.unwrap();
    assert!(n.load(Ordering::SeqCst) >= 1);
    // 節點池：每家、每個階段之間
    n.store(0, Ordering::SeqCst);
    pool::run(&ctx).await.unwrap();
    assert!(n.load(Ordering::SeqCst) >= 4, "節點池的檢查點 {}", n.load(Ordering::SeqCst));
    // 沒有掛勾：照常執行
    let (ctx2, _, _) = ctx_for(json!({ "cloudflare": {"enabled": true} }), json!({}));
    assert!(ctx2.checkpoint.is_none());
}

#[tokio::test]
async fn scan_pauses_between_batches_without_probes_in_flight() {
    let (ctx, net, paths) = ctx_for(
        json!({ "cloudflare": {"enabled": true} }),
        json!({ "scan": { "samplesPerSubnet": 1, "concurrency": 1 } }),
    );
    // 32 個 /24、並行 1 → 每批 4 個，共 8 批
    write(&paths, "ranges/cloudflare-ipv4.txt", "104.16.0.0/19\n");
    net.on_http(|_, _| resp(200, &[], "colo=TPE"));
    // 第二次檢查點（第一批做完）暫停，直到測試放行
    let calls = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let paused = Arc::new(tokio::sync::Notify::new());
    let (c2, g2, p2) = (calls.clone(), gate.clone(), paused.clone());
    let hook: Checkpoint = Arc::new(move || {
        let (c, g, p) = (c2.clone(), g2.clone(), p2.clone());
        Box::pin(async move {
            if c.fetch_add(1, Ordering::SeqCst) == 1 {
                p.notify_one();
                g.acquire().await.unwrap().forget();
            }
        })
    });
    let ctx = ctx.with_checkpoint(hook);
    let h = tokio::spawn(async move { scan::run(&ctx).await });
    paused.notified().await;
    let at_pause = net.calls("http").len();
    assert_eq!(at_pause, 4, "暫停時第一批已全部探測完");
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(net.calls("http").len(), at_pause, "暫停期間沒有新的探測");
    gate.add_permits(1);
    let r = h.await.unwrap().unwrap();
    assert_eq!(r.providers[0].tw, 32);
    assert_eq!(net.calls("http").len(), 32);
    assert_eq!(calls.load(Ordering::SeqCst), 8);
}

/// 3.4.2：測速前 4 個節點速度幾乎一樣（量到的是線路或對方的上限）→ 其餘只收 1 MiB 確認不慢，速度記成同一個值
#[tokio::test]
async fn pool_job_quick_checks_after_ceiling() {
    let (ctx, net, paths) = ctx_for(
        json!({ "cloudflare": {"enabled": true} }),
        json!({ "pool": { "candidatesPerProvider": 12, "poolSize": 6, "speedTop": 6 } }),
    );
    let subnets: String = (0..6).map(|i| format!("104.16.{i}.0/24\n")).collect();
    write(&paths, "scan/cloudflare-ipv4-TW.txt", &subnets);
    net.on_ping(|i| match i {
        IpAddr::V4(_) => lat(2.0),
        IpAddr::V6(_) => Latency {
            ok: false,
            ms: f64::INFINITY,
        },
    });
    net.on_http(|_, _| resp(200, &[], "colo=TPE"));
    net.on_speed(|_| 61.0);
    net.on_quality(|_| Quality {
        ms: 2.0,
        jitter: 0.1,
        loss: 0.0,
        n: 5,
    });
    pool::run(&ctx).await.unwrap();
    let full = net
        .calls("speed")
        .iter()
        .filter(|c| c.ends_with(&kuroshio_net::probe::SPEED_MAX_BYTES.to_string()))
        .count();
    let quick = net.calls("speed").iter().filter(|c| c.ends_with(" 1048576")).count();
    assert_eq!((full, quick), (4, 2), "{:?}", net.calls("speed"));
}

/// 3.4.2 Windows 壓力測試：前 4 個裡有連不上的（0 MB/s）時，不算進判斷瓶頸的那幾個，
/// 湊滿 4 個真正量到的速度才判斷（以前 5.45、0、5.46、0 → 減量沒有啟動，17 個全部完整測）
#[tokio::test]
async fn pool_job_ceiling_ignores_failed_probes() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (ctx, net, paths) = ctx_for(
        json!({ "cloudflare": {"enabled": true} }),
        json!({ "pool": { "candidatesPerProvider": 16, "poolSize": 8, "speedTop": 8 } }),
    );
    let subnets: String = (0..8).map(|i| format!("104.16.{i}.0/24\n")).collect();
    write(&paths, "scan/cloudflare-ipv4-TW.txt", &subnets);
    net.on_ping(|i| match i {
        IpAddr::V4(_) => lat(2.0),
        IpAddr::V6(_) => Latency {
            ok: false,
            ms: f64::INFINITY,
        },
    });
    net.on_http(|_, _| resp(200, &[], "colo=TPE"));
    let n = std::sync::Arc::new(AtomicUsize::new(0));
    let k = n.clone();
    // 第 2、4 個完整測速連不上
    net.on_speed(move |_| match k.fetch_add(1, Ordering::SeqCst) {
        1 | 3 => 0.0,
        _ => 61.0,
    });
    net.on_quality(|_| Quality {
        ms: 2.0,
        jitter: 0.1,
        loss: 0.0,
        n: 5,
    });
    pool::run(&ctx).await.unwrap();
    let full = net
        .calls("speed")
        .iter()
        .filter(|c| c.ends_with(&kuroshio_net::probe::SPEED_MAX_BYTES.to_string()))
        .count();
    let quick = net.calls("speed").iter().filter(|c| c.ends_with(" 1048576")).count();
    assert_eq!((full, quick), (6, 2), "{:?}", net.calls("speed"));
}

/// 3.5.0 A9：有手動的工作在等時，一家 CDN 掃完就讓出；續跑跳過已經掃完的那幾家，不重複掃同一批網段
#[tokio::test]
async fn scan_yields_between_providers_and_resumes_skipping_done() {
    let (ctx, net, paths) = ctx_for(
        json!({ "cloudflare": {"enabled": true}, "cloudfront": {"enabled": true}, "fastly": {"enabled": true} }),
        json!({ "scan": { "samplesPerSubnet": 1, "concurrency": 2 } }),
    );
    write(&paths, "ranges/cloudflare-ipv4.txt", "104.16.0.0/23\n");
    write(&paths, "ranges/cloudfront-ipv4.txt", "13.32.0.0/23\n");
    write(&paths, "ranges/fastly-ipv4.txt", "151.101.0.0/23\n");
    net.on_http(|_, _| {
        resp(
            200,
            &[("x-amz-cf-pop", "TPE52-P1"), ("x-served-by", "cache-tpe8000-TPE")],
            "colo=TPE\n",
        )
    });
    let waiting = Arc::new(AtomicUsize::new(1));
    let w = waiting.clone();
    let ctx = ctx.with_yield_check(Arc::new(move || w.load(Ordering::SeqCst) > 0));
    let mut resume = scan::Resume::default();
    let t0 = std::time::Instant::now();
    // 第一次：掃完 cloudflare 就讓出（一家掃到一半不讓出；至少掃完一家才讓）
    let r = scan::run(&ctx).await.unwrap();
    assert!(r.yielded);
    assert_eq!(r.done, ["cloudflare"]);
    assert_eq!(
        read(&paths, "scan/cloudflare-ipv4-TW.txt"),
        "104.16.0.0/24\n104.16.1.0/24\n",
        "掃完的照寫"
    );
    assert!(!paths.state_dir.join("cdn/scan/cloudfront-ipv4-TW.txt").exists());
    assert_eq!(net.calls("http").len(), 2);
    resume.finish(&r, t0);
    // 續跑：跳過 cloudflare，掃完 cloudfront 又讓出
    let (skip, may_yield) = resume.prepare(t0 + Duration::from_secs(300));
    assert_eq!((skip.clone(), may_yield), (vec!["cloudflare".to_string()], true));
    let mut c2 = ctx;
    c2.scan_skip = skip;
    let r = scan::run(&c2).await.unwrap();
    assert!(r.yielded);
    assert_eq!(r.done, ["cloudfront"]);
    assert_eq!(net.calls("http").len(), 4, "cloudflare 沒有重掃");
    resume.finish(&r, t0 + Duration::from_secs(300));
    // 沒有優先的工作在等：跑到完，狀態歸零
    waiting.store(0, Ordering::SeqCst);
    let (skip, _) = resume.prepare(t0 + Duration::from_secs(600));
    assert_eq!(skip, ["cloudflare", "cloudfront"]);
    c2.scan_skip = skip;
    let r = scan::run(&c2).await.unwrap();
    assert!(!r.yielded);
    assert_eq!(r.done, ["fastly"]);
    assert_eq!(net.calls("http").len(), 6, "每個 /24 只掃一次");
    resume.finish(&r, t0 + Duration::from_secs(600));
    assert_eq!(resume.prepare(t0 + Duration::from_secs(900)), (vec![], true));
    // 掃完的超過 6 小時：續跑時不再跳過（那份結果已經舊了）
    let mut old = scan::Resume::default();
    old.finish(
        &scan::Report {
            yielded: true,
            done: vec!["cloudflare".into()],
            ..Default::default()
        },
        t0,
    );
    assert!(old.prepare(t0 + scan::RESUME_SKIP + Duration::from_secs(1)).0.is_empty());
}

#[test]
fn scan_yield_capped_at_three() {
    let t0 = std::time::Instant::now();
    let mut r = scan::Resume::default();
    let yielded = scan::Report {
        yielded: true,
        done: vec!["cloudflare".into()],
        ..Default::default()
    };
    for i in 0..scan::MAX_YIELDS {
        assert!(r.prepare(t0).1, "第 {} 次可以讓出", i + 1);
        r.finish(&yielded, t0);
    }
    assert_eq!(r.yields(), 3);
    assert!(!r.prepare(t0).1, "讓出 3 次之後跑到完");
    // 跑到完：歸零，下一輪又可以讓出
    r.finish(&scan::Report::default(), t0);
    assert_eq!(r.prepare(t0), (vec![], true));
}
