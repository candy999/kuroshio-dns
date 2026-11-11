//! 效能量測（平常不跑）：`cargo test -p kuroshio-filter --test bench -- --ignored --nocapture`
//!
//! 量 `Filter::check()` 每次要多久：只有網域規則、加上一般的複雜規則、以及最壞情況（沒有固定字串的正規表示式）

use kuroshio_filter::{BuildOptions, Category, FilterBuilder, ListSpec};
use std::time::Instant;

fn names(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| match i % 4 {
            0 => format!("www.site{i}.example.com"),
            1 => format!("cdn{i}.static.example.net"),
            2 => format!("api.v2.service{i}.example.org"),
            _ => format!("ads.host{}.blocked.test", i % 1_000_000), // 會命中
        })
        .collect()
}

fn ns_per_check(f: &kuroshio_filter::Filter, q: &[String], rounds: usize) -> (f64, usize) {
    let mut hits = 0;
    let t = Instant::now();
    for _ in 0..rounds {
        for n in q {
            if std::hint::black_box(f.check(n, 1)).is_some() {
                hits += 1;
            }
        }
    }
    (t.elapsed().as_nanos() as f64 / (rounds * q.len()) as f64, hits / rounds)
}

#[test]
#[ignore]
fn bench_check() {
    let mut domains = String::new();
    for i in 0..1_000_000 {
        domains.push_str(&format!("||host{i}.blocked.test^\n"));
    }
    let q = names(20_000);
    let build = |extra: &str| {
        let mut b = FilterBuilder::new(BuildOptions::default());
        b.add_list(ListSpec::new("大清單", Category::Ads), domains.as_bytes()).unwrap();
        if !extra.is_empty() {
            b.add_list(ListSpec::new("複雜規則", Category::Ads), extra.as_bytes()).unwrap();
        }
        b.finish()
    };
    let report = |label: &str, extra: &str, rounds: usize| {
        let f = build(extra);
        ns_per_check(&f, &q, 1);
        let (ns, hits) = ns_per_check(&f, &q, rounds);
        println!(
            "{label:<44} {ns:>10.0} ns/次（{} 則查詢命中 {hits}；記憶體 {:.1} MB）",
            q.len(),
            f.memory_bytes() as f64 / 1e6
        );
    };
    report("100 萬筆網域規則", "", 20);
    // 一般清單裡的複雜規則：萬用字元、有固定字串的正規表示式（固定字串不在查詢名稱裡 → 只花快速排除的時間）
    let mut typical = String::new();
    for i in 0..2000 {
        typical.push_str(&format!("||ad{i}*.tracker.test^\n/banner{i}[0-9]+\\.adserver\\./\n"));
    }
    report("＋ 4000 條複雜規則（固定字串沒出現在查詢裡）", &typical, 10);
    // 固定字串很常見（3/4 的查詢名稱都有 .example.）：每一條都要真的跑正規表示式
    let mut common = String::new();
    for i in 0..2000 {
        common.push_str(&format!("/x{i}[0-9]+\\.example\\./\n"));
    }
    report("＋ 2000 條複雜規則（固定字串很常見）", &common, 2);
    // 最壞情況：沒有固定字串可以先篩的正規表示式，每個查詢每一條都要跑
    let mut worst = String::new();
    for i in 0..2000 {
        worst.push_str(&format!("/^[a-z]+[0-9]{{{}}}\\.[a-z]+\\.[a-z]+$/\n", 20 + i % 5));
    }
    report("＋ 2000 條沒有固定字串的正規表示式", &worst, 1);
    let dup: String = (0..200).map(|i| format!("/^([a-z0-9.]*)*[A-Z]{{{}}}$/\n", i + 1)).collect();
    let q_small: Vec<String> = q.iter().take(50).cloned().collect();
    let f = build(&dup);
    let (ns, _) = ns_per_check(&f, &q_small, 1);
    println!("＋ 200 條會大量回溯的正規表示式（惡意清單）     {ns:>10.0} ns/次");
}
