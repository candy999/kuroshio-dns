//! 跟 node 版逐筆對照：tests/vectors/filter/cases.json 由 tests/vectors/filter/gen.js 用
//! legacy-node/lib/filter.js 產生。每一筆查詢的動作、層、分類、規則文字都必須相同。

use std::path::PathBuf;

use kuroshio_filter::{BuildOptions, Category, Filter, FilterBuilder, ListSpec};
use serde_json::Value;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// 用固定的偽亂數把資料切成大小不一的塊（會切開多位元組字元與 \r\n），測串流解析
fn feed_chunked(mut feed: impl FnMut(&[u8]), bytes: &[u8], seed: u64) {
    let mut x = seed | 1;
    let mut i = 0;
    while i < bytes.len() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let n = 1 + (x % 23) as usize;
        let end = (i + n).min(bytes.len());
        feed(&bytes[i..end]);
        i = end;
    }
}

fn build(sc: &Value, seed: u64) -> Filter {
    let opts = BuildOptions {
        relaxed_modifiers: sc["relaxedModifiers"].as_bool().unwrap(),
        ..BuildOptions::default()
    };
    let mut b = FilterBuilder::new(opts);
    let mut customs: Vec<Vec<u8>> = sc["custom"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap().as_bytes().to_vec())
        .collect();
    for f in sc["customFiles"].as_array().unwrap() {
        customs.push(std::fs::read(root().join(f.as_str().unwrap())).unwrap());
    }
    for c in &customs {
        let mut w = b.custom();
        feed_chunked(|ch| w.feed(ch), c, seed);
        w.end();
    }
    for l in sc["lists"].as_array().unwrap() {
        let spec = ListSpec {
            name: l["name"].as_str().unwrap().to_owned(),
            category: Category::parse(l["category"].as_str().unwrap()).unwrap(),
            enabled: l["enabled"].as_bool().unwrap(),
        };
        let mut w = b.list(spec).unwrap();
        feed_chunked(|ch| w.feed(ch), l["text"].as_str().unwrap().as_bytes(), seed.wrapping_mul(31));
        w.end();
    }
    b.finish()
}

fn load() -> Value {
    let p = root().join("tests/vectors/filter/cases.json");
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("讀不到 {}：{e}", p.display()))).unwrap()
}

#[test]
fn node_parity() {
    let v = load();
    let mut total = 0;
    let mut bad = Vec::new();
    for sc in v["scenarios"].as_array().unwrap() {
        let name = sc["name"].as_str().unwrap();
        for seed in [7u64, 0x9e37_79b9_7f4a_7c15] {
            let f = build(sc, seed);

            // 統計（node 版 stats.custom / lists / byCategory / skipped）
            let st = f.stats();
            let exp = &sc["stats"];
            let by = |c: &str| exp["byCategory"].get(c).and_then(Value::as_u64).unwrap_or(0);
            let got = (
                st.custom,
                st.lists,
                st.skipped,
                st.by_category.0[1],
                st.by_category.0[2],
                st.by_category.0[3],
            );
            let want = (
                exp["custom"].as_u64().unwrap(),
                exp["lists"].as_u64().unwrap(),
                exp["skipped"].as_u64().unwrap(),
                by("ads"),
                by("telemetry"),
                by("malware"),
            );
            if got != want {
                bad.push(format!("[{name}] 統計不同：rust {got:?} node {want:?}"));
            }

            for c in sc["cases"].as_array().unwrap() {
                total += 1;
                let c = c.as_array().unwrap();
                let (q, qt) = (c[0].as_str().unwrap(), c[1].as_u64().unwrap() as u16);
                let want = if c[2] == "none" {
                    "none".to_owned()
                } else {
                    format!(
                        "{} {} {} {}",
                        c[2].as_str().unwrap(),
                        c[3].as_str().unwrap(),
                        c[4].as_str().unwrap(),
                        c[5].as_str().unwrap()
                    )
                };
                let got = match f.check(q, qt) {
                    None => "none".to_owned(),
                    Some(r) => {
                        // 命中的網域必須是查詢名稱的上層（或本身）
                        if let Some(d) = &r.domain {
                            let n = q.to_lowercase();
                            let n = n.strip_suffix('.').unwrap_or(&n);
                            assert!(n == d || n.ends_with(&format!(".{d}")), "{q} 命中 {d}");
                        }
                        let action = if r.is_allow() { "allow" } else { "block" };
                        format!("{action} {} {} {}", r.tier.as_str(), r.category.as_str(), r.rule())
                    }
                };
                if got != want {
                    bad.push(format!("[{name}] {q:?} type {qt}: rust「{got}」node「{want}」"));
                }
            }

            for c in sc["chains"].as_array().unwrap() {
                let c = c.as_array().unwrap();
                let targets: Vec<&str> = c[1].as_array().unwrap().iter().map(|t| t.as_str().unwrap()).collect();
                let got = f.check_cname(c[0].as_str().unwrap(), targets.iter().copied(), c[2].as_u64().unwrap() as u16);
                let got = got.map(|v| (v.category.as_str().to_owned(), v.rule().into_owned()));
                let want = c[3].as_str().map(|cat| (cat.to_owned(), c[4].as_str().unwrap().to_owned()));
                if got != want {
                    bad.push(format!("[{name}] CNAME {c:?}: rust {got:?}"));
                }
            }
        }
    }
    assert!(total > 1000, "向量太少：{total}");
    assert!(
        bad.is_empty(),
        "{} 筆跟 node 版不同（共 {total} 筆）：\n{}",
        bad.len(),
        bad.iter().take(60).cloned().collect::<Vec<_>>().join("\n")
    );
}
