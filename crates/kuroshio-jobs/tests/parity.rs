//! 跟 2.x 對照：向量由 `tests/parity/gen.js` 直接執行 legacy-node 的原始碼產生
//! （benchmark-rules.js，以及 dns-benchmark.js 的 extendedMetrics / greedy / bestPerAsn / Phase 3 原文）。

use kuroshio_jobs::benchmark::rules::{self, AsnInfo};
use kuroshio_jobs::benchmark::select::{self, Scored, Strategy};
use kuroshio_jobs::benchmark::select_opts;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::net::Ipv4Addr;

fn vectors() -> Value {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/parity/vectors.json");
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

fn info(v: &Value) -> AsnInfo {
    AsnInfo::from_json(v).unwrap()
}

#[test]
fn rules_match_node() {
    let v = vectors();
    for k in v["keywords"].as_array().unwrap() {
        let s = k[0].as_str().unwrap();
        let want: Vec<String> = serde_json::from_value(k[1].clone()).unwrap();
        assert_eq!(rules::extract_keywords(s), want, "extractKeywords({s:?})");
    }
    for k in v["asn"].as_array().unwrap() {
        assert_eq!(rules::extract_asn_number(k[0].as_str().unwrap()), k[1].as_str(), "{}", k[0]);
    }
    let infos: Vec<AsnInfo> = v["infos"].as_array().unwrap().iter().map(info).collect();
    let pair = |x: &Value| (&infos[x[0].as_u64().unwrap() as usize], &infos[x[1].as_u64().unwrap() as usize]);
    for x in v["sameGroup"].as_array().unwrap() {
        let (a, b) = pair(x);
        assert_eq!(
            rules::is_same_group(Some(a), Some(b)),
            x[2].as_bool().unwrap(),
            "isSameGroup {a:?} {b:?}"
        );
    }
    let mut trusted = 0;
    for x in v["trusted"].as_array().unwrap() {
        let (a, b) = pair(x);
        let want = x[2].as_bool().unwrap();
        trusted += want as usize;
        assert_eq!(rules::is_trusted_partner(Some(a), Some(b)), want, "isTrustedPartner {a:?} {b:?}");
    }
    assert!(trusted > 100);
    for x in v["weight"].as_array().unwrap() {
        let a = &infos[x[0].as_u64().unwrap() as usize];
        let d = x[1].as_str().unwrap();
        assert_eq!(
            rules::calculate_weight(Some(a), d),
            x[2].as_f64().unwrap(),
            "calculateWeight {a:?} {d}"
        );
    }
}

/// serde_json 預設的浮點數解析可能差 1 ULP
fn close(a: f64, b: f64) -> bool {
    (a - b).abs() <= 1e-12 * a.abs().max(1.0)
}

fn ip(s: &str) -> u32 {
    u32::from(s.parse::<Ipv4Addr>().unwrap())
}

fn steps(list: &[&Scored], r: &(Vec<select::Step>, Vec<usize>)) -> Value {
    json!({
        "result": r.0.iter().map(|s| json!([list[s.idx].id, s.newly, s.total])).collect::<Vec<_>>(),
        "rest": r.1.iter().map(|i| list[*i].id.clone()).collect::<Vec<_>>(),
    })
}

#[test]
fn selection_matches_node() {
    let v = vectors();
    let mut with_backup = 0;
    for (n, sc) in v["scenarios"].as_array().unwrap().iter().enumerate() {
        let inp = &sc["input"];
        let out = &sc["out"];
        let mut servers: Vec<Scored> = inp["servers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| Scored {
                id: s["id"].as_str().unwrap().into(),
                kind: s["type"].as_str().unwrap().into(),
                owner: s["owner"].as_str().unwrap().into(),
                pinned: s["pinned"].as_bool().unwrap(),
                avg: s["avg"].as_f64().unwrap(),
                count: s["count"].as_u64().unwrap() as usize,
                history: s["history"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|h| {
                        (
                            h[0].as_u64().unwrap() as u32,
                            h[1].as_array().unwrap().iter().map(|x| ip(x.as_str().unwrap())).collect(),
                        )
                    })
                    .collect(),
                ..Default::default()
            })
            .collect();
        let total = inp["total"].as_u64().unwrap() as usize;
        select::extended_metrics(&mut servers, inp["totalDomains"].as_u64().unwrap() as usize);
        for s in &servers {
            let e = &out["ext"][&s.id];
            assert_eq!(s.ext.total_resolved as u64, e["totalResolved"].as_u64().unwrap(), "#{n} {}", s.id);
            assert_eq!(s.ext.exclusive_count as u64, e["exclusiveCount"].as_u64().unwrap(), "#{n} {}", s.id);
            assert!(
                close(s.ext.exclusive_ratio_self, e["exclusiveRatioSelf"].as_f64().unwrap()),
                "#{n} {}",
                s.id
            );
            assert!(
                close(s.ext.exclusive_ratio_global, e["exclusiveRatioGlobal"].as_f64().unwrap()),
                "#{n} {}",
                s.id
            );
            assert!(close(s.ext.success_rate, e["successRate"].as_f64().unwrap()), "#{n} {}", s.id);
        }
        servers.sort_by(|a, b| a.avg.partial_cmp(&b.avg).unwrap());
        let finals: Vec<&Scored> = servers.iter().collect();
        assert_eq!(
            json!(finals.iter().map(|s| s.id.clone()).collect::<Vec<_>>()),
            out["finals"],
            "#{n}"
        );
        let asn_best = select::best_per_asn(&finals);
        let asn_refs: Vec<&Scored> = asn_best.iter().map(|i| finals[*i]).collect();
        assert_eq!(
            json!(asn_refs.iter().map(|s| s.id.clone()).collect::<Vec<_>>()),
            out["asnBest"],
            "#{n}"
        );
        let none = HashSet::new();
        assert_eq!(
            steps(&finals, &select::greedy(&finals, total, Strategy::Coverage, &none)),
            out["coverage"],
            "#{n}"
        );
        assert_eq!(
            steps(&finals, &select::greedy(&finals, total, Strategy::Latency, &none)),
            out["latency"],
            "#{n}"
        );
        assert_eq!(
            steps(&asn_refs, &select::greedy(&asn_refs, total, Strategy::Coverage, &none)),
            out["asnCoverage"],
            "#{n}"
        );

        let cfg = json!({ "upstream": inp["cfg"]["upstream"], "benchmark": inp["bc"] });
        let sel = select::select(&finals, &asn_best, total, &select_opts(&cfg));
        let got: Vec<Value> = sel.selected.iter().map(|p| json!([finals[p.idx].id, p.newly, p.why])).collect();
        assert_eq!(json!(got), out["phase3"]["selected"], "#{n} Phase 3");
        assert_eq!(sel.covered as u64, out["phase3"]["covered"].as_u64().unwrap(), "#{n}");
        with_backup += sel.selected.iter().any(|p| p.why == "備援") as usize;
        if let Some(csv) = out["csv"].as_str() {
            assert_eq!(select::greedy_csv(&finals, total, Strategy::Coverage), csv, "#{n} CSV");
        }
    }
    assert!(with_backup > 5);
}
