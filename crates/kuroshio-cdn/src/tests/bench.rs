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
    let cfg = kuroshio_config::build(&json!({}));
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

/// 用種子資料做出 `n` 筆「像真的」網域：名稱不同、時間 / 次數 / IP 最後一段打散（壓縮率才不會好得不真實）
pub fn synthetic_domains(n: usize) -> Vec<u8> {
    let seed: Value = serde_json::from_slice(&std::fs::read(repo().join("data/seed/cdn-domains.json")).unwrap()).unwrap();
    let base = seed["domains"].as_array().unwrap();
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut rnd = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    fn walk(v: &mut Value, r: &mut dyn FnMut() -> u64) {
        match v {
            Value::Object(m) => {
                for (k, x) in m.iter_mut() {
                    match (k.as_str(), &*x) {
                        ("at" | "until" | "firstSeen" | "lastSeen" | "recheckAt", Value::Number(n)) if n.as_u64().is_some() => {
                            *x = json!(n.as_u64().unwrap().saturating_sub(r() % (30 * 86_400_000)));
                        }
                        ("hits", _) => *x = json!(r() % 5000),
                        _ => walk(x, r),
                    }
                }
            }
            Value::Array(a) => a.iter_mut().for_each(|x| walk(x, r)),
            Value::String(s) => {
                if let Ok(std::net::IpAddr::V4(ip)) = s.parse::<std::net::IpAddr>() {
                    let o = ip.octets();
                    *s = std::net::Ipv4Addr::new(o[0], o[1], (r() % 256) as u8, (r() % 254 + 1) as u8).to_string();
                }
            }
            _ => {}
        }
    }
    const WORDS: [&str; 12] = [
        "img", "static", "cdn", "api", "www", "assets", "video", "m", "media", "s", "edge", "files",
    ];
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let mut d = base[i % base.len()].clone();
        let name = d["name"].as_str().unwrap().to_string();
        let w = WORDS[(rnd() % 12) as usize];
        d["name"] = json!(if i < base.len() {
            name
        } else {
            format!("{w}{}.{name}", rnd() % 100_000)
        });
        walk(&mut d, &mut rnd);
        out.push(d);
    }
    serde_json::to_vec(&json!({ "domains": out })).unwrap()
}

/// 壓縮率、分片大小、單一變動要寫多少、每筆常駐記憶體（決定 `cdn.maxEntries` 與分片數用；規格 05 第 5.5 節）。
/// 32 位元：`cargo zigbuild --target i686-unknown-linux-musl` 編好測試程式，直接跑或用 qemu-arm 跑 armv7
#[test]
#[ignore]
fn bench_persist() {
    use crate::statefile;
    let seed = std::fs::read(repo().join("data/seed/cdn-domains.json")).unwrap();
    for level in [1, 3, 9] {
        let t = Instant::now();
        let z = zstd::bulk::compress(&seed, level).unwrap();
        println!(
            "種子 {} 筆 {} KB → zstd {level}：{} KB（{:.1} 倍，{:.0} ms）",
            3961,
            seed.len() / 1024,
            z.len() / 1024,
            seed.len() as f64 / z.len() as f64,
            t.elapsed().as_secs_f64() * 1000.0
        );
    }
    for f in ["cdn-pools.json", "v6-nodes.json"] {
        let b = std::fs::read(repo().join("data/seed").join(f)).unwrap();
        let z = statefile::compress(&b);
        println!(
            "{f}：{} KB → {} KB（{:.1} 倍）",
            b.len() / 1024,
            z.len() / 1024,
            b.len() as f64 / z.len() as f64
        );
    }
    let z = statefile::compress(&seed);
    println!(
        "種子（寫入器的設定：等級 {}、視窗 2^{}）：{} KB，{:.1} 倍",
        statefile::LEVEL,
        statefile::WINDOW_LOG,
        z.len() / 1024,
        seed.len() as f64 / z.len() as f64
    );

    // 每筆常駐記憶體：先載入一份用掉之前放掉的記憶體，再量第二份（要新配置）才準
    {
        let n = 50_000;
        let bytes = synthetic_domains(n);
        let mut warm = crate::db::Db::new(n * 2);
        warm.load_domains(&bytes, false).unwrap();
        let before = rss_kb();
        let mut db = crate::db::Db::new(n * 2);
        db.load_domains(&bytes, false).unwrap();
        let after = rss_kb();
        std::hint::black_box((&warm, &db));
        println!(
            "{n} 筆（{}-bit）載入後常駐記憶體約 {} B/筆",
            usize::BITS,
            after.unwrap_or(0).saturating_sub(before.unwrap_or(0)) * 1024 / n as u64
        );
    }
    let only: Option<usize> = std::env::var("BENCH_N").ok().and_then(|s| s.parse().ok());
    for n in [5_000usize, 20_000, 50_000, 120_000, 200_000] {
        if only.is_some_and(|o| o != n) {
            continue;
        }
        let bytes = synthetic_domains(n);
        let mut db = crate::db::Db::new(n * 2);
        db.load_domains(&bytes, false).unwrap();
        let rss = "";
        let shards = crate::db::shards_for(n);
        db.set_shards(shards);
        // 每片寫出、壓縮
        let mut raw_total = 0;
        let mut z_total = 0;
        let mut z_max = 0;
        let t = Instant::now();
        for i in 0..shards {
            let (head, tail) = crate::db::Db::shard_frame(shards, i);
            let mut keys = db.shard_keys(shards, i);
            keys.sort_unstable();
            let mut buf = head;
            let mut first = true;
            db.dump_names(&keys, &mut buf, &mut first);
            buf.extend_from_slice(tail);
            let z = statefile::compress(&buf);
            raw_total += buf.len();
            z_total += z.len();
            z_max = z_max.max(z.len());
        }
        let ms = t.elapsed().as_secs_f64() * 1000.0;
        println!(
            "{n} 筆（{}-bit）：單一檔 {:.1} MB{rss}；{shards} 片，壓縮後合計 {:.2} MB（{:.0} B/筆、{:.1} 倍），每片平均 {} KB、最大 {} KB；全部重寫 {ms:.0} ms",
            usize::BITS,
            bytes.len() as f64 / 1e6,
            z_total as f64 / 1e6,
            z_total as f64 / n as f64,
            raw_total as f64 / z_total as f64,
            z_total / shards / 1024,
            z_max / 1024,
        );
        drop(db);
    }
}
