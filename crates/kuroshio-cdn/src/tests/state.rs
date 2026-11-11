//! 狀態檔：用 repo 附帶的種子資料（2.x 正式伺服器匯出）測讀寫相容、未知欄位保留、種子帶入

use super::*;
use crate::cdn::STATE_FILES;
use crate::util::now_ms;

fn strip_saved_at(v: &mut Value) {
    if let Some(o) = v.as_object_mut() {
        o.remove("savedAt");
    }
}

fn parse(b: &[u8]) -> Value {
    serde_json::from_slice(b).unwrap()
}

/// 種子資料加上一些不認識的欄位，放進狀態目錄
fn seed_state_with_unknowns(state: &std::path::Path) -> HashMap<&'static str, Value> {
    let seed = repo().join("data/seed");
    let mut pools: Value = parse(&std::fs::read(seed.join("cdn-pools.json")).unwrap());
    pools["futureTop"] = json!({ "a": 1 });
    pools["providers"]["cloudflare"]["futureProv"] = json!("x");
    pools["providers"]["cloudflare"]["v4"][0]["futureNode"] = json!([1, 2]);
    pools["providers"]["someNewCdn"] = json!({ "v4": [{ "ip": "1.2.3.4", "ms": 1 }], "note": "未啟用的 CDN 也保留" });
    let mut v6: Value = parse(&std::fs::read(seed.join("v6-nodes.json")).unwrap());
    v6["futureTop"] = json!(true);
    let first = v6["providers"]["cloudflare"].as_object().unwrap().keys().next().unwrap().clone();
    v6["providers"]["cloudflare"][&first]["futureNode"] = json!({ "k": "v" });
    let mut dom: Value = parse(&std::fs::read(seed.join("cdn-domains.json")).unwrap());
    dom["futureTop"] = json!(1);
    dom["domains"][0]["futureDomain"] = json!("y");
    let i = dom["domains"]
        .as_array()
        .unwrap()
        .iter()
        .position(|d| d.get("v4").is_some())
        .unwrap();
    dom["domains"][i]["v4"]["futureVerdict"] = json!(3);
    let j = dom["domains"]
        .as_array()
        .unwrap()
        .iter()
        .position(|d| d.get("cross4").is_some())
        .unwrap();
    dom["domains"][j]["cross4"]["tried"][0]["futureTried"] = json!(null);
    let harvest = json!({ "cloudflare": { "v4": { "104.16.1.1": 1793085962496u64, "104.16.0.9": 2 }, "v6": {}, "futureH": 1 } });
    let zone = json!({ "cloudflare|104.16.1.1": { "hit": 3, "miss": 1, "at": 1793085962496u64, "futureZ": "z" } });
    let out: HashMap<&'static str, Value> = [
        ("cdn/pools.json", pools),
        ("cdn/v6-nodes.json", v6),
        ("cdn-domains.json", dom),
        ("cdn/harvest.json", harvest),
        ("cdn/ip-zone.json", zone),
    ]
    .into_iter()
    .collect();
    for (k, v) in &out {
        let p = state.join(k);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, serde_json::to_vec(v).unwrap()).unwrap();
    }
    // 候選 IP 的順序有意義（依加入順序淘汰）：直接寫文字，不經過會排序的 json!
    std::fs::write(
        state.join("cdn/harvest.json"),
        r#"{"cloudflare":{"v4":{"104.16.1.1":1793085962496,"104.16.0.9":2},"v6":{},"futureH":1}}"#,
    )
    .unwrap();
    out
}

fn full_cfg() -> Value {
    kuroshio_config::defaults()
}

#[test]
fn round_trip_keeps_format_and_unknown_fields() {
    let paths = paths_no_seed("roundtrip");
    let orig = seed_state_with_unknowns(&paths.state_dir);
    let c = Cdn::load(&full_cfg(), paths.clone(), MockNet::new());
    assert!(c.snapshots().is_empty(), "沒有變動、沒有用種子：不需要寫");
    let snap: HashMap<String, Vec<u8>> = c.snapshots_all().into_iter().collect();
    assert_eq!(snap.len(), STATE_FILES.len());
    for (k, v) in &orig {
        let mut a = v.clone();
        let mut b = parse(&snap[*k]);
        strip_saved_at(&mut a);
        strip_saved_at(&mut b);
        if *k == "cdn-domains.json" {
            // 2.x 用 Map 的順序、3.0 依查詢次數排序：逐筆比對
            let key = |v: &Value| -> Vec<(String, Value)> {
                let mut l: Vec<(String, Value)> = v["domains"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|d| (d["name"].as_str().unwrap().to_string(), d.clone()))
                    .collect();
                l.sort_by(|x, y| x.0.cmp(&y.0));
                l
            };
            let (la, lb) = (key(&a), key(&b));
            assert_eq!(la.len(), lb.len());
            for (x, y) in la.iter().zip(&lb) {
                assert_eq!(x, y, "網域 {} 讀寫後不一樣", x.0);
            }
            a.as_object_mut().unwrap().remove("domains");
            b.as_object_mut().unwrap().remove("domains");
        }
        assert_eq!(a, b, "{k} 讀寫後不一樣");
    }
    // 再讀一次、再寫一次：完全一樣
    let paths2 = paths_no_seed("roundtrip2");
    for (k, v) in &snap {
        let p = paths2.state_dir.join(k);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, v).unwrap();
    }
    let c2 = Cdn::load(&full_cfg(), paths2, MockNet::new());
    let snap2: HashMap<String, Vec<u8>> = c2.snapshots_all().into_iter().collect();
    for (k, v) in &snap {
        let mut a = parse(v);
        let mut b = parse(&snap2[k]);
        strip_saved_at(&mut a);
        strip_saved_at(&mut b);
        assert_eq!(a, b, "{k} 第二次讀寫不一樣");
    }
    // 讀進來的內容可以用
    let st = c2.state();
    assert!(st.pools.serve_ips("cloudflare", 4).len() >= 2);
    assert!(st.db.domains.len() > 1000);
    assert!(st.v6.count("cloudflare") > 10);
    assert_eq!(
        st.db.harvest_of("cloudflare", false),
        ips(&["104.16.1.1", "104.16.0.9"]),
        "候選 IP 保持加入順序"
    );
    assert_eq!(st.pools.zone["cloudflare|104.16.1.1"].hit, 3);
}

#[test]
fn seed_used_when_state_empty() {
    let d = tmpdir("seed");
    let paths = Paths::new(d.join("state"), repo().join("data"));
    let before = now_ms();
    let c = Cdn::load(&full_cfg(), paths, MockNet::new());
    let snap: HashMap<String, Vec<u8>> = c.snapshots().into_iter().collect();
    for k in ["cdn/pools.json", "cdn/v6-nodes.json", "cdn-domains.json"] {
        assert!(snap.contains_key(k), "種子帶入後要寫入 {k}");
    }
    assert!(c.snapshots().is_empty(), "取出後不再重複");
    let st = c.state();
    assert!(
        st.db.domains.values().all(|e| e.last_seen >= before),
        "匯入時把最後出現時間設成現在"
    );
    assert!(!st.pools.serve_ips("cloudflare", 4).is_empty());
    // 種子的節點也會被分類成 Cloudflare 台灣節點（data/cdn 的範圍與分類）
    let first = st.pools.serve_ips("cloudflare", 4)[0];
    assert_eq!(st.pools.classify(first).map(|x| x.provider), Some("cloudflare"));
}

#[test]
fn state_files_are_used_over_seed() {
    let d = tmpdir("noseed-override");
    let paths = Paths::new(d.join("state"), repo().join("data"));
    let pools = json!({ "providers": { "cloudflare": { "v4": [{ "ip": "104.16.0.1", "ms": 1.5, "pop": "TPE" }], "v6": [] } } });
    std::fs::create_dir_all(paths.state_dir.join("cdn")).unwrap();
    std::fs::write(paths.state_dir.join("cdn/pools.json"), serde_json::to_vec(&pools).unwrap()).unwrap();
    let c = Cdn::load(&full_cfg(), paths, MockNet::new());
    assert_eq!(c.state().pools.serve_ips("cloudflare", 4), ips(&["104.16.0.1"]));
    // 沒有 v4 的節點池檔 → 算空的，用種子
    let d2 = tmpdir("empty-pools");
    let paths2 = Paths::new(d2.join("state"), repo().join("data"));
    std::fs::create_dir_all(paths2.state_dir.join("cdn")).unwrap();
    std::fs::write(
        paths2.state_dir.join("cdn/pools.json"),
        br#"{"providers":{"cloudflare":{"v4":[]}}}"#,
    )
    .unwrap();
    let c2 = Cdn::load(&full_cfg(), paths2, MockNet::new());
    assert!(c2.state().pools.serve_ips("cloudflare", 4).len() >= 4);
}

#[test]
fn load_with_custom_reader() {
    // 外層的快照寫入器提供讀取（例如壓縮過的快照）
    let paths = paths_no_seed("reader");
    let calls = Mutex::new(Vec::new());
    let read = |rel: &str| {
        calls.lock().unwrap().push(rel.to_string());
        (rel == "cdn/ip-zone.json").then(|| br#"{"fastly|151.101.1.1":{"hit":1,"miss":0}}"#.to_vec())
    };
    let c = Cdn::load_with(&full_cfg(), paths, MockNet::new(), &read);
    let mut got = calls.lock().unwrap().clone();
    got.sort();
    let mut want: Vec<String> = STATE_FILES.iter().map(|s| s.to_string()).collect();
    want.sort();
    assert_eq!(got, want);
    assert!(c.state().pools.zone_hit("fastly", ip("151.101.1.1")));
}
