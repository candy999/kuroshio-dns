//! 效能量測（平常不跑）：`cargo test -p kuroshio-cdn --release bench_ -- --ignored --nocapture`
//!
//! 用 repo 附帶的種子資料（2.x 正式伺服器匯出的網域、節點池、範圍）量：
//!  - `apply()` 每次要多久（單執行緒、4 執行緒）
//!  - 網域資料庫塞到 20 萬筆時，寫快照會讓查詢停多久

use super::*;
use crate::cdn::Paths;
use crate::util::now_ms;
use kuroshio_proto::message::rtype;
use std::time::Instant;

fn seed_paths(tag: &str) -> Paths {
    let d = tmpdir(tag);
    Paths {
        state_dir: d.join("state"),
        seed_dir: repo().join("data/seed"),
        cdn_data_dir: repo().join("data/cdn"),
    }
}

/// 種子資料載入後，把所有判定的有效期限往後延（模擬「驗證都還有效」的穩定狀態）
fn seeded() -> Arc<Cdn> {
    let cfg = kuroshio_config::build(kuroshio_config::Tier::Large, &json!({}));
    let c = Cdn::load(&cfg, seed_paths("bench"), MockNet::new());
    let far = now_ms() + 30 * 86_400_000;
    c.with_state(|st| {
        for e in st.db.domains.values_mut() {
            for v in [&mut e.v4, &mut e.v6].into_iter().flatten() {
                v.until = Some(far);
            }
            if let Some(x) = e.ecs.as_mut() {
                x.until = Some(far);
            }
            if let Some(x) = e.cross4.as_mut() {
                x.until = Some(far);
                x.recheck_at = Some(far);
            }
        }
    });
    c
}

/// 種子裡每個網域一則 A 回應（有 CNAME 的加上 CNAME 記錄）
fn seed_msgs(c: &Cdn, max: usize) -> Vec<(String, Message)> {
    let st = c.state();
    let mut list: Vec<&crate::db::Domain> = st.db.domains.values().filter(|d| !d.ips4.is_empty()).collect();
    list.sort_by(|a, b| b.hits.cmp(&a.hits).then_with(|| a.name.cmp(&b.name)));
    list.truncate(max);
    list.into_iter()
        .map(|d| {
            let name = d.name.to_string();
            let target = d.cname.val().filter(|t| t.as_str() != name).cloned();
            let owner = target.clone().unwrap_or_else(|| name.clone());
            let mut m = Message {
                id: 1,
                flags: 0x8180,
                ..Default::default()
            };
            if let Some(t) = &target {
                m.answers.push(cname(&name, t, 300));
            }
            for ip in d.ips4.iter() {
                if let IpAddr::V4(v) = ip {
                    m.answers.push(Record::a(&owner, 300, *v));
                }
            }
            (name, m)
        })
        .collect()
}

/// 每次 `apply` 的奈秒數（`threads` 個執行緒各跑 `rounds` 輪；複製訊息不算在內）
fn ns_per_apply(c: &Arc<Cdn>, msgs: &[(String, Message)], threads: usize, rounds: usize) -> f64 {
    let total: u128 = std::thread::scope(|s| {
        let hs: Vec<_> = (0..threads)
            .map(|_| {
                s.spawn(|| {
                    let mut spent = 0u128;
                    for _ in 0..rounds {
                        let mut batch: Vec<Message> = msgs.iter().map(|(_, m)| m.clone()).collect();
                        let t = Instant::now();
                        for (m, (name, _)) in batch.iter_mut().zip(msgs) {
                            std::hint::black_box(c.apply(m, name, rtype::A));
                        }
                        spent += t.elapsed().as_nanos();
                    }
                    spent
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).sum()
    });
    total as f64 / (threads * rounds * msgs.len()) as f64
}

#[test]
#[ignore]
fn bench_apply() {
    let c = seeded();
    let seed = seed_msgs(&c, 2000);
    // 不是 CDN 的回應（最常見）：沒有 CNAME、有兩層 CNAME
    let plain: Vec<(String, Message)> = (0..2000)
        .map(|i| {
            let n = format!("host{i}.example.com");
            let m = msg(&n, 1, &["93.184.216.34", "198.51.100.7"], vec![]);
            (n, m)
        })
        .collect();
    let chained: Vec<(String, Message)> = (0..2000)
        .map(|i| {
            let n = format!("www{i}.example.net");
            let m = msg(
                "lb.hosting.example.org",
                1,
                &["93.184.216.34", "198.51.100.7"],
                vec![
                    cname(&n, &format!("site{i}.hosting.example.org"), 300),
                    cname(&format!("site{i}.hosting.example.org"), "lb.hosting.example.org", 300),
                ],
            );
            (n, m)
        })
        .collect();
    let by = |p: &str| -> Vec<(String, Message)> {
        let st = c.state();
        seed.iter()
            .filter(|(n, _)| st.db.get(n).and_then(|d| d.provider()) == Some(p))
            .cloned()
            .collect()
    };
    let sets: Vec<(&str, Vec<(String, Message)>)> = vec![
        ("非 CDN（無 CNAME）", plain),
        ("非 CDN（兩層 CNAME）", chained),
        ("種子：Cloudflare", by("cloudflare")),
        ("種子：CloudFront", by("cloudfront")),
        ("種子：Fastly", by("fastly")),
        ("種子：Akamai", by("akamai")),
        ("種子：全部（依熱門度前 2000）", seed),
    ];
    println!("網域資料庫 {} 筆", c.state().db.domains.len());
    for (label, msgs) in &sets {
        if msgs.is_empty() {
            continue;
        }
        let rounds = (400_000 / msgs.len()).max(1);
        ns_per_apply(&c, msgs, 1, rounds / 4 + 1); // 暖機
        let one = ns_per_apply(&c, msgs, 1, rounds);
        let four = ns_per_apply(&c, msgs, 4, rounds);
        println!(
            "{label:<30} {:>5} 則｜1 執行緒 {one:>7.0} ns/次｜4 執行緒 {four:>7.0} ns/次（每個執行緒）",
            msgs.len()
        );
    }
}

#[test]
#[ignore]
fn bench_snapshot_stall() {
    let c = seeded();
    // 用種子的紀錄複製出 20 萬筆
    c.with_state(|st| {
        let base: Vec<crate::db::Domain> = st.db.domains.values().cloned().collect();
        let mut i = 0usize;
        while st.db.domains.len() < 200_000 {
            let mut d = base[i % base.len()].clone();
            let name: Arc<str> = Arc::from(format!("n{i}.{}", d.name).as_str());
            d.name = name.clone();
            st.db.domains.insert(name, d);
            i += 1;
        }
        st.db.dirty = true;
    });
    let msgs = seed_msgs(&c, 500);
    let stop = std::sync::atomic::AtomicBool::new(false);
    let (worst, snap_ms, bytes) = std::thread::scope(|s| {
        let h = s.spawn(|| {
            // 模擬查詢：持續呼叫 apply，記下最久的一次
            let mut worst = 0u128;
            let mut i = 0usize;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let (name, m) = &msgs[i % msgs.len()];
                let mut m = m.clone();
                let t = Instant::now();
                std::hint::black_box(c.apply(&mut m, name, rtype::A));
                worst = worst.max(t.elapsed().as_micros());
                i += 1;
            }
            worst
        });
        std::thread::sleep(Duration::from_millis(200));
        let t = Instant::now();
        let out = c.snapshots();
        let ms = t.elapsed().as_millis();
        let bytes: usize = out.iter().map(|(_, b)| b.len()).sum();
        std::thread::sleep(Duration::from_millis(100));
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        (h.join().unwrap(), ms, bytes)
    });
    println!(
        "20 萬筆：snapshots() {snap_ms} ms、{:.1} MB；期間 apply() 最久被擋 {:.1} ms",
        bytes as f64 / 1e6,
        worst as f64 / 1000.0
    );
    // 超過上限時的整理（新增一筆觸發）
    let t = Instant::now();
    c.with_state(|st| {
        st.db.max_entries = st.db.domains.len();
        st.db.touch("brand-new.example.com", "cloudflare", "ip", &[], &[], None);
    });
    println!("到達上限時新增一筆（觸發整理）：{:.1} ms", t.elapsed().as_micros() as f64 / 1000.0);
}

/// 常駐記憶體（KB，Linux 才有）
fn rss_kb() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    let l = s.lines().find(|l| l.starts_with("VmRSS:"))?;
    l.split_whitespace().nth(1)?.parse().ok()
}

/// 每筆網域在快照檔與記憶體裡各佔多少（決定各等級 `cdn.maxEntries` 用）
#[test]
#[ignore]
fn bench_db_size() {
    let c = seeded();
    let n = 50_000usize;
    let bytes = c.with_state(|st| {
        let base: Vec<crate::db::Domain> = st.db.domains.values().cloned().collect();
        let mut i = 0usize;
        while st.db.domains.len() < n {
            let mut d = base[i % base.len()].clone();
            let name: Arc<str> = Arc::from(format!("n{i}.{}", d.name).as_str());
            d.name = name.clone();
            st.db.domains.insert(name, d);
            i += 1;
        }
        st.db.domains_json()
    });
    drop(c);
    // 第一份先用掉剛放掉的記憶體，量第二份（要新配置）才準
    let mut warm = crate::db::Db::new(1_000_000);
    warm.load_domains(&bytes, false).unwrap();
    let before = rss_kb();
    let mut db = crate::db::Db::new(1_000_000);
    db.load_domains(&bytes, false).unwrap();
    let after = rss_kb();
    std::hint::black_box(&warm);
    println!(
        "{n} 筆：快照 {:.1} MB（{} B/筆）；載入後常駐記憶體 +{} KB（約 {} B/筆）",
        bytes.len() as f64 / 1e6,
        bytes.len() / n,
        after.unwrap_or(0).saturating_sub(before.unwrap_or(0)),
        after.unwrap_or(0).saturating_sub(before.unwrap_or(0)) * 1024 / n as u64
    );
    std::hint::black_box(&db);
}
