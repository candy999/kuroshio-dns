//! 背景工作（範圍下載、網段分類、節點池）用假的網路測

use super::*;
use crate::jobs::{pool, ranges, scan, JobCtx};
use crate::util::Num;
use kuroshio_net::iprank::{Latency, Quality};

fn ctx_for(providers: Value, extra: Value) -> (JobCtx, Arc<MockNet>, Paths) {
    let net = MockNet::new();
    let paths = paths_no_seed("jobs");
    let mut cfg = json!({ "cdn": { "providers": providers, "ecs": { "twSubnets": ["168.95.0.0/24"] } } });
    kuroshio_config::merge(&mut cfg, &extra);
    let cdn = Cdn::load(&cfg, paths.clone(), net.clone());
    cdn.record_tasks();
    (JobCtx::new(cfg, cdn), net, paths)
}

fn write(paths: &Paths, rel: &str, body: &str) {
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
