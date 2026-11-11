//! 用本機的清單檔建置過濾器，印出規則數、估計記憶體、實際 RSS 與查詢速度。
//!
//! 用法：
//! ```text
//! cargo run --release -p kuroshio-filter --example measure -- \
//!     [--relaxed] [--max-domains N] [--max-complex N] [--custom 自訂規則檔] \
//!     [--queries 查詢名稱檔 --out 判定輸出檔] 分類:清單檔 ...
//! ```
//! 分類：ads / telemetry / malware。清單檔以 64 KB 為單位串流讀取（模擬邊下載邊解析）。
//! `--queries` 每行一個「名稱<TAB>類型數值」（沒有類型就當 A），判定寫到 `--out`，
//! 格式同 tests/vectors/filter/gen.js：`名稱<TAB>類型<TAB>動作<TAB>層<TAB>分類<TAB>規則`。
//!
//! 預設清單的網址在 crates/kuroshio-config/defaults.json 的 `filter.lists`，先用 curl 下載，例如：
//! ```text
//! curl -sSLo /tmp/l1.txt https://adguardteam.github.io/HostlistsRegistry/assets/filter_21.txt
//! cargo run --release -p kuroshio-filter --example measure -- --custom rules/default-custom-rules.txt ads:/tmp/l1.txt
//! ```

use std::io::{BufRead, Read, Write};
use std::time::Instant;

use kuroshio_filter::{BuildOptions, Category, FilterBuilder, ListSpec, SourceStatus};

fn proc_status(field: &str) -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = s.lines().find(|l| l.starts_with(field))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

fn kb(field: &str) -> String {
    proc_status(field).map_or_else(|| "n/a".into(), |v| format!("{:.1} MB", v as f64 / 1024.0))
}

fn feed_file(path: &str, mut feed: impl FnMut(&[u8])) {
    let mut f = std::fs::File::open(path).unwrap_or_else(|e| panic!("開不了 {path}：{e}"));
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).expect("讀取失敗");
        if n == 0 {
            break;
        }
        feed(&buf[..n]);
    }
}

fn main() {
    let mut opts = BuildOptions::default();
    let mut custom = None;
    let mut queries = None;
    let mut out = None;
    let mut lists = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--relaxed" => opts.relaxed_modifiers = true,
            "--max-domains" => opts.max_domains = args.next().and_then(|v| v.parse().ok()).expect("--max-domains 數字"),
            "--max-complex" => opts.max_complex = args.next().and_then(|v| v.parse().ok()).expect("--max-complex 數字"),
            "--custom" => custom = args.next(),
            "--queries" => queries = args.next(),
            "--out" => out = args.next(),
            _ => {
                let (cat, path) = a.split_once(':').expect("清單格式：分類:檔案");
                lists.push((Category::parse(cat).expect("分類：ads / telemetry / malware"), path.to_owned()));
            }
        }
    }

    let rss0 = proc_status("VmRSS:");
    let t0 = Instant::now();
    let mut b = FilterBuilder::new(opts);
    if let Some(c) = &custom {
        let mut w = b.custom();
        feed_file(c, |ch| w.feed(ch));
        w.end();
    }
    for (cat, path) in &lists {
        let name = path.rsplit('/').next().unwrap_or(path).to_owned();
        let mut w = b.list(ListSpec::new(name, *cat)).expect("清單太多");
        feed_file(path, |ch| w.feed(ch));
        w.end();
    }
    let f = b.finish();
    let build_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let rss1 = proc_status("VmRSS:");

    let st = f.stats();
    println!("來源：");
    for s in &st.sources {
        let status = match s.status {
            SourceStatus::Loaded => "載入".to_owned(),
            SourceStatus::Disabled => "停用".to_owned(),
            SourceStatus::OverBudget { rules, remaining } => format!("超過記憶體預算，未載入（{rules} 條，剩 {remaining}）"),
        };
        println!(
            "  {:<40} {:<4} 行 {:>8}  網域 {:>8}  複雜 {:>5}  略過 {:>5}（正規表示式不支援 {}）  丟掉 {}  {}",
            s.name,
            s.category.label(),
            s.lines,
            s.domain_rules,
            s.complex_rules,
            s.unsupported,
            s.regex_unsupported,
            s.complex_dropped,
            status
        );
    }
    println!(
        "規則：自訂 {}、清單 {}（廣告 {}、遙測 {}、惡意 {}）；略過 {}；重複合併 {}；badfilter 取消 {}",
        st.custom,
        st.lists,
        st.by_category.get(Category::Ads),
        st.by_category.get(Category::Telemetry),
        st.by_category.get(Category::Malware),
        st.skipped,
        st.duplicates,
        st.badfilter_removed
    );
    println!(
        "網域筆數 {}（預算已用 {} / {}）；複雜規則 {} / {}（丟掉 {}）",
        st.domains, st.budget_used, st.max_domains, st.complex, st.max_complex, st.complex_dropped
    );
    println!(
        "估計記憶體 {:.2} MB（{:.2} bytes / 網域）",
        f.memory_bytes() as f64 / 1048576.0,
        f.memory_bytes() as f64 / st.domains.max(1) as f64
    );
    println!(
        "建置 {:.0} ms；RSS 建置前 {} → 建置後 {}（差 {}）；尖峰 VmHWM {}",
        build_ms,
        rss0.map_or("n/a".into(), |v| format!("{:.1} MB", v as f64 / 1024.0)),
        rss1.map_or("n/a".into(), |v| format!("{:.1} MB", v as f64 / 1024.0)),
        match (rss0, rss1) {
            (Some(a), Some(b)) => format!("{:.1} MB", (b as f64 - a as f64) / 1024.0),
            _ => "n/a".into(),
        },
        kb("VmHWM:")
    );

    if let Some(q) = queries {
        let file = std::io::BufReader::new(std::fs::File::open(&q).expect("開不了查詢檔"));
        let qs: Vec<(String, u16)> = file
            .lines()
            .map_while(Result::ok)
            .map(|l| match l.split_once('\t') {
                Some((n, t)) => (n.to_owned(), t.parse().unwrap_or(1)),
                None => (l, 1),
            })
            .collect();
        let t = Instant::now();
        let mut blocked = 0usize;
        for (n, qt) in &qs {
            if f.check(n, *qt).is_some_and(|v| v.is_block()) {
                blocked += 1;
            }
        }
        let ns = t.elapsed().as_nanos() as f64 / qs.len().max(1) as f64;
        println!("查詢 {} 筆：封鎖 {}，平均 {:.0} ns / 筆", qs.len(), blocked, ns);
        if let Some(o) = out {
            let mut w = std::io::BufWriter::new(std::fs::File::create(&o).expect("寫不了輸出檔"));
            for (n, qt) in &qs {
                match f.check(n, *qt) {
                    None => writeln!(w, "{n}\t{qt}\tnone"),
                    Some(v) => writeln!(
                        w,
                        "{n}\t{qt}\t{}\t{}\t{}\t{}",
                        if v.is_allow() { "allow" } else { "block" },
                        v.tier.as_str(),
                        v.category.as_str(),
                        v.rule()
                    ),
                }
                .expect("寫入失敗");
            }
        }
    }
}
