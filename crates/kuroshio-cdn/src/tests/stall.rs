//! CDN 網域資料庫的大批處理不能讓查詢停住（3.5.1：D3 上冷資料移出、磁碟預算淘汰時 DNS 停了約 20 秒）。
//!
//! 量測（平常不跑）：`cargo test -p kuroshio-cdn --release stall_bench -- --ignored --nocapture`

use super::*;
use crate::util::now_ms;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

/// 7 萬筆、256 片（預設 `cdn.maxEntries` 20 萬筆的分片數）：年齡、查詢次數、驗證結果各式各樣
pub(super) fn big_cdn(tag: &str, n: usize, cfg: Value) -> Arc<Cdn> {
    let paths = paths_no_seed(tag);
    std::fs::create_dir_all(&paths.state_dir).unwrap();
    let c = Cdn::load(&cfg, paths, MockNet::new());
    let now = now_ms();
    c.with_state(|st| {
        let ip4 = ips(&["104.16.0.5", "104.16.0.6"]);
        for i in 0..n {
            let name = format!("w{i:x}.s{}.example.com", i % 977);
            let d = st
                .db
                .touch(&name, "cloudflare", "ip", &ip4, &[], Some("x.example.net.cdn.cloudflare.net"));
            // 年齡：0～60 天，平均分佈
            d.last_seen = now.saturating_sub((i as u64 * 7_919) % (60 * 86_400_000) + 180_000);
            d.hits = if i % 3 == 0 { 1 } else { (i % 17) as u32 + 2 };
            if i % 4 == 0 {
                st.db.set_verdict(&name, 4, |v| {
                    v.verdict = Some(crate::util::intern(if i % 8 == 0 { "ok" } else { "fail" }));
                    v.until = Some(now.saturating_sub(3_600_000));
                    v.ip = Some(ip("104.16.1.1"));
                    v.ms = crate::util::Num::V(12.0);
                });
            }
        }
    });
    c
}

/// 把變動的分片寫進磁碟（同快照寫入器：邊序列化邊寫、壓縮在鎖外）
pub(super) fn flush(c: &Cdn, all: bool) -> usize {
    let dir = c.paths.state_dir.clone();
    let (_, ch) = c.snapshots_sharded(all);
    for (i, _) in &ch.changed {
        let mut raw = Vec::new();
        c.write_shard(ch.shards, *i, &mut raw).unwrap();
        let p = crate::statefile::zst_path(&dir.join(crate::db::shard_file(ch.shards, *i)));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, crate::statefile::compress(&raw)).unwrap();
    }
    if let Some((m, retire)) = &ch.manifest {
        std::fs::write(dir.join(crate::db::MANIFEST), m).unwrap();
        for r in retire {
            crate::statefile::remove(&dir.join(r));
        }
    }
    ch.changed.len()
}

/// 跑 `f` 的同時，另一個執行緒每 1 ms 拿一次狀態鎖（查詢路徑的 `apply()` 一樣要拿這把鎖），記下最久等了多久。
/// 回（`f` 的結果，`f` 花的時間，最久等鎖）
pub(super) fn with_probe<R>(c: &Cdn, f: impl FnOnce() -> R) -> (R, Duration, Duration) {
    let stop = AtomicBool::new(false);
    std::thread::scope(|s| {
        let h = s.spawn(|| {
            let mut worst = Duration::ZERO;
            while !stop.load(Ordering::Relaxed) {
                let t = Instant::now();
                drop(std::hint::black_box(c.state()));
                worst = worst.max(t.elapsed());
                std::thread::sleep(Duration::from_millis(1));
            }
            worst
        });
        std::thread::sleep(Duration::from_millis(5));
        let t = Instant::now();
        let r = f();
        let spent = t.elapsed();
        std::thread::sleep(Duration::from_millis(5));
        stop.store(true, Ordering::Relaxed);
        (r, spent, h.join().unwrap())
    })
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

#[test]
#[ignore]
fn stall_bench() {
    let n: usize = std::env::var("BENCH_N").ok().and_then(|s| s.parse().ok()).unwrap_or(70_000);
    let t = Instant::now();
    let c = big_cdn("stall-bench", n, kuroshio_config::defaults());
    println!("建立 {n} 筆：{:.0} ms（{} 片）", ms(t.elapsed()), c.state().db.shards);

    let (k, spent, worst) = with_probe(&c, || flush(&c, true));
    println!("寫出全部分片（{k} 片）：{:.0} ms，最久等鎖 {:.1} ms", ms(spent), ms(worst));

    // 單一階段：拿著鎖做的部分
    let (_, spent, _) = with_probe(&c, || {
        let mut st = c.state();
        std::hint::black_box(st.db.shard_keys(256, 7));
    });
    println!("shard_keys 一片：{:.2} ms", ms(spent));

    let (_, spent, _) = with_probe(&c, || {
        let st = c.state();
        let now = now_ms();
        std::hint::black_box(st.db.domains.values().filter(|d| crate::db::forgettable_stale(d, now)).count());
    });
    println!("掃一遍全部（forgettable_stale）：{:.2} ms", ms(spent));

    // 冷資料移出（記憶體吃緊）：約 8.6 MB
    let (r, spent, worst) = with_probe(&c, || c.evict_coldest(8_681 * 1024, 120_000, &|_| true));
    println!(
        "冷資料移出 {} 筆（{} KB）：{:.0} ms，最久等鎖 {:.1} ms",
        r.entries,
        r.bytes / 1024,
        ms(spent),
        ms(worst)
    );

    // 有冷資料時寫分片（從舊檔接回去）
    c.with_state(|st| {
        for i in 0..32 {
            st.db.mark(&format!("w{i:x}.s{}.example.com", i % 977));
        }
    });
    let (k, spent, worst) = with_probe(&c, || flush(&c, false));
    println!("有冷資料時寫 {k} 片：{:.0} ms，最久等鎖 {:.1} ms", ms(spent), ms(worst));

    // 讀回一部分（restore 32 片）
    let (r, spent, worst) = with_probe(&c, || {
        let shards = c.state().db.evicted_shards();
        let mut out = 0;
        for i in shards.into_iter().take(32) {
            out += c.restore_shard_cold(256, i).entries;
        }
        out
    });
    println!("讀回 32 片（{r} 筆）：{:.0} ms，最久等鎖 {:.1} ms", ms(spent), ms(worst));

    let (r, spent, worst) = with_probe(&c, || c.restore_cold());
    println!("讀回全部（{} 筆）：{:.0} ms，最久等鎖 {:.1} ms", r.entries, ms(spent), ms(worst));

    // 一次性網域清理
    let (r, spent, worst) = with_probe(&c, || c.state().db.forget_one_shot(now_ms(), true));
    println!("一次性網域清理 {r} 筆：{:.1} ms，最久等鎖 {:.1} ms", ms(spent), ms(worst));

    // 筆數上限淘汰：上限設成目前的 80%（背景的整理分批做）
    let len = c.state().db.domains.len();
    c.state().db.max_entries = len * 8 / 10;
    let (_, spent, worst) = with_probe(&c, || c.prune_cap());
    println!(
        "筆數上限淘汰 {} 筆：{:.0} ms，最久等鎖 {:.1} ms",
        len - c.state().db.domains.len(),
        ms(spent),
        ms(worst)
    );
    // 同樣的事一次做完（修正前查詢路徑上的做法）
    let len = c.state().db.domains.len();
    let (_, spent, _) = with_probe(&c, || {
        let mut st = c.state();
        st.db.max_entries = len * 8 / 10;
        st.db.prune();
    });
    println!(
        "（對照）一次做完的筆數上限淘汰 {} 筆：拿著鎖 {:.0} ms",
        len - c.state().db.domains.len(),
        ms(spent)
    );
    c.state().db.max_entries = 200_000;
    flush(&c, true);

    // 磁碟預算淘汰：預算換算的筆數約目前的一半
    let left = c.state().db.domains.len();
    let mut cfg = kuroshio_config::defaults();
    let kb = ((left as u64 / 2) * crate::db::BUDGET_BYTES_PER_ENTRY + 256 * crate::db::BUDGET_SHARD_OVERHEAD) / 1024;
    cfg["cdn"]["dbDiskBudgetKB"] = json!(kb);
    let c2 = Cdn::load(&cfg, c.paths.clone(), MockNet::new());
    c2.with_state(|st| {
        for i in 0..20_000 {
            st.db.mark(&format!("w{i:x}.s{}.example.com", i % 977));
        }
    });
    let (r, spent, worst) = with_probe(&c2, || c2.budget_round());
    println!(
        "磁碟預算淘汰 {} 筆（{} 片，主動 {}）：{:.0} ms，最久等鎖 {:.1} ms",
        r.dropped,
        r.shards,
        r.forced,
        ms(spent),
        ms(worst)
    );
    let (k, spent, worst) = with_probe(&c2, || flush(&c2, false));
    println!("接著寫 {k} 片：{:.0} ms，最久等鎖 {:.1} ms", ms(spent), ms(worst));

    // 載入（整理、淘汰）
    let t = Instant::now();
    let c3 = Cdn::load(&kuroshio_config::defaults(), c.paths.clone(), MockNet::new());
    println!("載入 {} 筆：{:.0} ms", c3.state().db.domains.len(), ms(t.elapsed()));
}

/// 單批（[`crate::cdn::BATCH_ENTRIES`] 筆左右）各花多久：決定批次大小用（MT7621 約慢 15～20 倍）
#[test]
#[ignore]
fn stall_bench_batch() {
    let n: usize = std::env::var("BENCH_N").ok().and_then(|s| s.parse().ok()).unwrap_or(70_000);
    let c = big_cdn("stall-batch", n, kuroshio_config::defaults());
    flush(&c, true);
    // 前面幾片湊到一批
    let range = {
        let st = c.state();
        let mut i = 0;
        let mut seen = 0;
        while seen < crate::cdn::BATCH_ENTRIES {
            seen += st.db.domains.shard(i).len();
            i += 1;
        }
        println!("一批：{i} 片、{seen} 筆");
        0..i
    };
    let now = now_ms();
    let busy = |_: &str| false;
    let st = c.state();
    let time = |label: &str, f: &mut dyn FnMut()| {
        let t = Instant::now();
        f();
        println!("{label:<28} {:.3} ms", ms(t.elapsed()));
    };
    let mut sw = st.db.cold_sweep(usize::MAX, 120_000, now, &|_| true).unwrap();
    time("冷資料移出：第一次掃描", &mut || {
        st.db.cold_scan(&mut sw, range.clone(), &busy)
    });
    let mut st2 = st;
    time("冷資料移出：移出（全部）", &mut || {
        sw.plan();
        st2.db.cold_take(&mut sw, range.clone(), &busy)
    });
    for i in range.clone() {
        st2.db.unevict_shard(i);
    }
    drop(st2);
    let c = big_cdn("stall-batch2", n, kuroshio_config::defaults());
    let mut st = c.state();
    let mut cs = st.db.cap_sweep(0, now).unwrap();
    time("筆數上限：第一次掃描", &mut || st.db.cap_scan(&mut cs, range.clone()));
    time("筆數上限：刪除（全部）", &mut || {
        cs.plan(st.db.domains.len());
        st.db.cap_take(&mut cs, range.clone())
    });
    drop(st);
    let c = big_cdn("stall-batch3", n, kuroshio_config::defaults());
    let mut st = c.state();
    let plan: Vec<(usize, usize)> = range.clone().map(|i| (i, 1)).collect();
    time("磁碟預算：每片留 1 筆", &mut || {
        st.db.budget_prune(&plan, now);
    });
    drop(st);
    let c = big_cdn("stall-batch4", n, kuroshio_config::defaults());
    let mut st = c.state();
    let pick = vec![true; st.db.shards];
    let mut left = usize::MAX;
    let mut k = 0;
    time("一次性網域清理", &mut || {
        k = st.db.forget_in(&pick, range.clone(), now + 30 * 86_400_000, &mut left);
    });
    println!("（忘掉 {k} 筆）");
    time("寫一片：shard_keys", &mut || {
        std::hint::black_box(st.db.shard_keys(256, 300 % 256));
    });
    let keys = st.db.shard_keys(256, 200);
    time("寫一片：序列化（一批 256 筆）", &mut || {
        let mut buf = Vec::new();
        let mut first = true;
        let k: Vec<Arc<str>> = st.db.domains.values().take(256).map(|d| d.name.clone()).collect();
        st.db.dump_names(&k, &mut buf, &mut first);
        std::hint::black_box((buf, &keys));
    });
}

/// 查詢等鎖的門檻：修正後 x86 上每批不到 1 ms（除錯版也差不多：花時間的是已經最佳化的標準函式庫雜湊表）；
/// CI 機器忙、Windows 的計時器粗，抓寬一點。修正前 7 萬筆一次拿著鎖做完：冷資料移出約 100 ms、淘汰約 60 ms
const STALL_LIMIT: Duration = Duration::from_millis(40);

#[test]
fn bulk_work_does_not_hold_the_state_lock() {
    // 3.5.1：D3 上冷資料移出、磁碟預算淘汰時 DNS 停了約 20 秒。大批處理要分批、每批放開一次鎖：
    // 另一個執行緒每 1 ms 拿一次查詢路徑的鎖（`apply()`，快取命中的也要拿），最久不能等超過門檻
    let n = 70_000;
    let c = big_cdn("stall", n, kuroshio_config::defaults());
    assert_eq!(c.state().db.shards, 256);
    let (k, _, worst) = with_probe(&c, || flush(&c, true));
    assert_eq!(k, 256);
    assert!(worst < STALL_LIMIT, "寫出全部分片：最久等鎖 {worst:?}");

    // 冷資料移出（記憶體吃緊）：約 8.6 MB，同 D3 那一次
    let (r, _, worst) = with_probe(&c, || c.evict_coldest(8_681 * 1024, 120_000, &|_| true));
    assert!(r.entries > n / 4 && r.bytes >= 8_681 * 1024, "{r:?}");
    assert!(worst < STALL_LIMIT, "冷資料移出 {} 筆：最久等鎖 {worst:?}", r.entries);

    // 有冷資料時寫分片、讀回全部
    c.with_state(|st| (0..64).for_each(|i| st.db.mark(&format!("w{i:x}.s{}.example.com", i % 977))));
    let (_, _, worst) = with_probe(&c, || flush(&c, false));
    assert!(worst < STALL_LIMIT, "有冷資料時寫分片：最久等鎖 {worst:?}");
    let (r, _, worst) = with_probe(&c, || c.restore_cold());
    assert!(r.entries + r.forgotten > n / 4, "{r:?}");
    assert!(worst < STALL_LIMIT, "讀回：最久等鎖 {worst:?}");
    flush(&c, true);

    // 筆數上限淘汰（記憶體不足時的看門狗也走這裡）：刪到剩 8 成
    let before = c.state().db.domains.len();
    let (_, _, worst) = with_probe(&c, || c.shrink(0.8));
    assert_eq!(c.state().db.domains.len(), before * 8 / 10);
    assert!(worst < STALL_LIMIT, "筆數上限淘汰：最久等鎖 {worst:?}");
    flush(&c, true);

    // 磁碟預算淘汰（同 D3 第二次：整理 32 片）與一次性網域清理
    let left = c.state().db.domains.len();
    let mut cfg = kuroshio_config::defaults();
    let kb = ((left as u64 / 2) * crate::db::BUDGET_BYTES_PER_ENTRY + 256 * crate::db::BUDGET_SHARD_OVERHEAD) / 1024;
    cfg["cdn"]["dbDiskBudgetKB"] = json!(kb);
    let c2 = Cdn::load(&cfg, c.paths.clone(), MockNet::new());
    c2.with_state(|st| (0..20_000).for_each(|i| st.db.mark(&format!("w{i:x}.s{}.example.com", i % 977))));
    let (r, _, worst) = with_probe(&c2, || c2.budget_round());
    assert!(r.dropped > 0 && r.shards == 32, "{r:?}");
    assert!(worst < STALL_LIMIT, "磁碟預算淘汰 {} 筆：最久等鎖 {worst:?}", r.dropped);
    let (_, _, worst) = with_probe(&c2, || flush(&c2, false));
    assert!(worst < STALL_LIMIT, "淘汰後寫分片：最久等鎖 {worst:?}");
}

#[test]
fn batches_cover_every_shard_once_and_stay_small() {
    // 每批是連續的幾片、合起來剛好每片一次；每批不超過 `BATCH_ENTRIES` 筆（一片就超過的，那一片自己一批），
    // 也不會小到下一片放得進來還切開
    use crate::cdn::BATCH_ENTRIES;
    let c = big_cdn("batches", 20_000, kuroshio_config::defaults());
    // 有一片特別大（超過一批）
    c.with_state(|st| {
        let mut k = 0;
        let mut added = 0;
        while added < BATCH_ENTRIES + 10 {
            let name = format!("big{k}.example.net");
            k += 1;
            if crate::db::shard_of(&name, 256) == 5 {
                st.db.touch(&name, "cloudflare", "ip", &[], &[], None);
                added += 1;
            }
        }
    });
    let sizes: Vec<usize> = {
        let st = c.state();
        (0..256).map(|i| st.db.domains.shard(i).len()).collect()
    };
    let mut ranges = Vec::new();
    c.in_batches(|_, r| {
        ranges.push(r);
        true
    });
    let mut next = 0;
    for (k, r) in ranges.iter().enumerate() {
        assert_eq!(r.start, next, "連續、不重複");
        assert!(r.end > r.start, "每批至少一片");
        next = r.end;
        let total: usize = sizes[r.clone()].iter().sum();
        assert!(total <= BATCH_ENTRIES || r.len() == 1, "第 {k} 批 {r:?}：{total} 筆");
        if let Some(more) = sizes.get(r.end) {
            assert!(total + more > BATCH_ENTRIES, "第 {k} 批 {r:?} 還放得下下一片");
        }
    }
    assert_eq!(next, 256, "每一片都做到");
    assert!(ranges.contains(&(5..6)), "超過一批的那一片自己一批");
    assert!(ranges.len() < 64, "不會切得太碎：{}", ranges.len());
    // 中途停下來
    let mut seen = 0;
    c.in_batches(|_, _| {
        seen += 1;
        seen < 3
    });
    assert_eq!(seen, 3);
}

#[test]
fn batched_results_match_one_shot() {
    // 分批做跟一次做完，淘汰、移出的是同樣的那些（同一份資料載入兩次比較）
    let c = big_cdn("same", 30_000, kuroshio_config::defaults());
    flush(&c, true);
    let load = || Cdn::load(&kuroshio_config::defaults(), c.paths.clone(), MockNet::new());
    let names = |c: &Cdn| -> std::collections::BTreeSet<String> { c.state().db.domains.keys().map(|k| k.to_string()).collect() };

    // 筆數上限淘汰（最後那一格挑最舊的，結果是確定的）
    let (a, b) = (load(), load());
    a.shrink(0.6);
    {
        let mut st = b.state();
        let keep = st.db.domains.len() * 6 / 10;
        st.db.shrink_to(keep);
    }
    assert_eq!(a.state().db.domains.len(), 18_000);
    assert_eq!(names(&a), names(&b), "筆數上限淘汰");
    // 背景的整理（超過 `cdn.maxEntries`）也一樣，回報的筆數對得上
    for x in [&a, &b] {
        x.state().db.max_entries = 10_000;
    }
    a.prune_cap();
    b.state().db.prune();
    assert_eq!(a.state().db.domains.len(), 9_000);
    assert_eq!(names(&a), names(&b), "背景的筆數上限淘汰");
    assert_eq!(a.state().db.take_cap_pruned(), b.state().db.take_cap_pruned());

    // 冷資料全部移出（同一組規則：2 分鐘以內的、手動策略的不動）
    let (a, b) = (load(), load());
    let ra = a.evict_coldest(usize::MAX, 120_000, &|_| true);
    let rb = {
        let mut st = b.state();
        st.db.evict_coldest(usize::MAX, 120_000, now_ms(), &|_| false, &|_| true)
    };
    assert_eq!((ra.entries, ra.bytes), (rb.entries, rb.bytes));
    assert_eq!(names(&a), names(&b), "冷資料移出");
    // 移出一部分：從最冷的開始，移出的都比留下的冷（同一組裡年齡格不比留下的新）
    let a = load();
    let r = a.evict_coldest(2 << 20, 120_000, &|_| true);
    assert!(r.bytes >= 2 << 20 && r.bytes < (2 << 20) + 4096, "{r:?}");
    let now = now_ms();
    let slot = |d: &crate::db::Domain| {
        (
            crate::db::has_learning(d),
            std::cmp::Reverse(crate::db::age_bucket(now.saturating_sub(d.last_seen))),
        )
    };
    let full = load();
    let kept = names(&a);
    let st = full.state();
    let (mut gone, mut stay): (Vec<_>, Vec<_>) = st.db.domains.values().partition(|d| !kept.contains(&*d.name));
    let coldest_kept = stay.iter_mut().map(|d| slot(d)).min().unwrap();
    let warmest_gone = gone.iter_mut().map(|d| slot(d)).max().unwrap();
    assert!(warmest_gone <= coldest_kept, "{warmest_gone:?} / {coldest_kept:?}");
}
