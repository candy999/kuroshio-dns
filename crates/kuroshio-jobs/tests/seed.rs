//! 種子資料：state 空白才帶入、不覆蓋已有的、CDN 網域的 lastSeen 設成現在

use kuroshio_jobs::seed::{apply_initial_upstreams, apply_seeds, apply_seeds_with, initial_upstreams, INITIAL_SPARES, SEEDS};
use kuroshio_jobs::time::ManualClock;
use kuroshio_jobs::BenchPaths;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("kuroshio-seed-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write(p: &Path, v: &Value) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, serde_json::to_vec(v).unwrap()).unwrap();
}

fn read(p: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

#[test]
fn seeds_fill_empty_state_only() {
    let (seed, state) = (tmp("src"), tmp("dst"));
    // 沒有 meta.json：什麼都不做
    write(
        &seed.join("upstreams.json"),
        &json!({ "selected": [{ "id": "1.1.1.1", "type": "udp" }] }),
    );
    assert!(apply_seeds(&state, &seed).is_empty());

    write(&seed.join("meta.json"), &json!({ "exportedAt": "2026-10-27T07:35:11.859Z" }));
    write(
        &seed.join("cdn-pools.json"),
        &json!({ "providers": { "cloudflare": { "v4": [{ "ip": "104.16.1.1" }] } } }),
    );
    write(&seed.join("v6-nodes.json"), &json!({ "providers": {} })); // 種子本身是空的 → 不用
    write(
        &seed.join("cdn-domains.json"),
        &json!({ "domains": [{ "d": "a.com", "lastSeen": 1 }, { "d": "b.com" }], "extra": 1 }),
    );
    // state 已有評測結果 → 不覆蓋；節點池是空的 → 帶入
    write(
        &state.join("upstreams.json"),
        &json!({ "selected": [{ "id": "8.8.8.8", "type": "udp" }] }),
    );
    write(
        &state.join("cdn/pools.json"),
        &json!({ "providers": { "cloudflare": { "v4": [] } } }),
    );

    let clock = ManualClock::new(1_794_240_000_000);
    let used = apply_seeds_with(&state, &seed, &SEEDS, &clock);
    assert_eq!(used, vec!["台灣節點池", "CDN 網域驗證紀錄"]);
    assert_eq!(read(&state.join("upstreams.json"))["selected"][0]["id"], "8.8.8.8");
    assert_eq!(
        read(&state.join("cdn/pools.json"))["providers"]["cloudflare"]["v4"][0]["ip"],
        "104.16.1.1"
    );
    assert!(!state.join("cdn/v6-nodes.json").exists());
    let d = read(&state.join("cdn-domains.json"));
    assert_eq!(d["extra"], 1);
    assert_eq!(d["domains"][0]["lastSeen"], 1_794_240_000_000u64);
    assert_eq!(d["domains"][1]["lastSeen"], 1_794_240_000_000u64);
    // 第二次：都有資料了
    assert!(apply_seeds(&state, &seed).is_empty());

    // 新格式：一般 JSON 已經搬進壓縮檔 / 分片，不能被種子蓋過去
    let state2 = tmp("dst-new");
    std::fs::create_dir_all(state2.join("cdn/domains")).unwrap();
    std::fs::write(state2.join("cdn/pools.json.zst"), b"zstd").unwrap();
    std::fs::write(state2.join("cdn/domains/manifest.json"), b"{}").unwrap();
    std::fs::write(state2.join("upstreams.json"), br#"{"selected":[{"id":"x"}]}"#).unwrap();
    assert!(apply_seeds_with(&state2, &seed, &SEEDS, &clock).is_empty());
    assert!(!state2.join("cdn/pools.json").exists() && !state2.join("cdn-domains.json").exists());
    let _ = std::fs::remove_dir_all(&state2);
    let _ = std::fs::remove_dir_all(&seed);
    let _ = std::fs::remove_dir_all(&state);
}

/// 3.5.0：種子不再帶上游評測結果（那是別條線路上的結果）；CDN 的三份照舊
#[test]
fn repository_seed_data_loads() {
    let seed = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/seed");
    assert!(!seed.join("upstreams.json").exists(), "種子不帶上游評測結果");
    let state = tmp("repo");
    let used = apply_seeds(&state, &seed);
    assert_eq!(used, vec!["台灣節點池", "永久 IPv6 節點", "CDN 網域驗證紀錄"]);
    assert!(!state.join("upstreams.json").exists());
    assert!(!read(&state.join("cdn/pools.json"))["providers"].as_object().unwrap().is_empty());
    assert!(!read(&state.join("cdn/v6-nodes.json"))["providers"].as_object().unwrap().is_empty());
    assert!(!read(&state.join("cdn-domains.json"))["domains"].as_array().unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&state);
}

// ---------------- 首次啟動的初始上游（A8） ----------------

fn lists(root: &Path) -> BenchPaths {
    let mut p = BenchPaths::from_config(&json!({}), &root.join("state"), root);
    p.list_dir = root.join("benchmark");
    std::fs::create_dir_all(&p.list_dir).unwrap();
    std::fs::write(
        p.list_dir.join("dohlist.txt"),
        "# ---- A 級 ----\n\
         https://slow.example.com/dns-query  # tier=A op=Slow_Net ms=40\n\
         https://a1.example.com/dns-query  # tier=A op=Example_Net ms=3.1\n\
         https://a2.example.com/dns-query  # tier=A op=Example_Net ms=3.5\n\
         https://bad.example.net/dns-query  # tier=A op=Bad_Net ms=1.0\n\
         # ---- B 級 ----\n\
         https://b1.example.net/dns-query  # tier=B op=Fast_Unknown ms=0.5\n",
    )
    .unwrap();
    std::fs::write(
        p.list_dir.join("dotlist.txt"),
        "tls://dot.example.net  # tier=A op=Other_Net ms=5\ntls://dup.example.com  # tier=A op=example_net ms=2\n",
    )
    .unwrap();
    std::fs::write(
        p.list_dir.join("doqlist.txt"),
        "quic://doq.example.net  # tier=A op=Quic_Net ms=1\n",
    )
    .unwrap();
    std::fs::write(
        p.list_dir.join("iplist.txt"),
        "# ---- A 級 ----\n# A Plain_Net（AS64500）TW 1.0 ms\n192.0.2.1\n# A Plain_V6（AS64501）TW 0.5 ms\n2001:db8::1\n\
         # A Plain_Two（AS64502）TW 2.0 ms\n198.51.100.2\n# ---- B 級 ----\n# B Unknown（AS64503）TW 0.1 ms\n198.51.100.9\n",
    )
    .unwrap();
    std::fs::write(p.list_dir.join("blacklist.txt"), "https://bad.example.net/dns-query  # 汙染\n").unwrap();
    p
}

fn cfg(types: &[&str], max: usize) -> Value {
    kuroshio_config::with_overrides(&json!({ "upstream": { "autoTypes": types, "autoMax": max, "pinned": [] } }))
}

fn ids(v: &Value, k: &str) -> Vec<String> {
    v[k].as_array()
        .unwrap()
        .iter()
        .map(|x| x["id"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn initial_upstreams_picks_a_tier_distinct_operators_encrypted_first() {
    let root = tmp("init-a");
    let p = lists(&root);
    let v = initial_upstreams(&p, &cfg(&["udp", "doh", "dot", "doq"], 4)).unwrap();
    // 加密的先（DoH、DoT 依 ms），再 DoQ，再一般 DNS；同一個經營者只取 1 台（大小寫不分：
    // dup 的 example_net 2 ms 比 a1、a2 快，Example_Net 就是它）；
    // B 級、永久黑名單、IPv6 位址不取
    assert_eq!(
        ids(&v, "selected"),
        [
            "tls://dup.example.com",
            "tls://dot.example.net",
            "https://slow.example.com/dns-query",
            "quic://doq.example.net"
        ]
    );
    assert_eq!(ids(&v, "spares"), ["192.0.2.1", "198.51.100.2"]);
    assert!(v["generatedAt"].is_null());
    assert_eq!(v["source"], "default-list");
    let first = &v["selected"][0];
    assert_eq!(
        (first["type"].as_str(), first["reason"].as_str(), first["tier"].as_str()),
        (Some("dot"), Some("預設名單"), Some("A"))
    );
    assert_eq!(first["op"], "example_net");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn initial_upstreams_respects_auto_types_and_auto_max() {
    let root = tmp("init-types");
    let p = lists(&root);
    let v = initial_upstreams(&p, &cfg(&["udp"], 1)).unwrap();
    assert_eq!(ids(&v, "selected"), ["192.0.2.1"]);
    assert_eq!(ids(&v, "spares"), ["198.51.100.2"], "候補最多 3 台，有幾台給幾台");
    let v = initial_upstreams(&p, &cfg(&["doh"], 2)).unwrap();
    assert_eq!(
        ids(&v, "selected"),
        ["https://a1.example.com/dns-query", "https://slow.example.com/dns-query"]
    );
    assert!(ids(&v, "spares").is_empty());
    // 候補最多 INITIAL_SPARES 台：總共不超過 autoMax + 3（第一次啟動不會一下子用上一大批伺服器）
    let v = initial_upstreams(&p, &cfg(&["udp", "doh", "dot", "doq"], 1)).unwrap();
    assert_eq!(ids(&v, "selected").len(), 1);
    assert_eq!(ids(&v, "spares").len(), INITIAL_SPARES);
    // autoMax = 0、沒有類型：不產生
    assert!(initial_upstreams(&p, &cfg(&["doh"], 0)).is_none());
    // 固定上游不重複放進自動上游（同經營者的下一台補上）
    let mut c = cfg(&["doh"], 1);
    c["upstream"]["pinned"] = json!(["https://a1.example.com/dns-query"]);
    assert_eq!(
        ids(&initial_upstreams(&p, &c).unwrap(), "selected"),
        ["https://a2.example.com/dns-query"]
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn existing_upstreams_json_not_overwritten() {
    let root = tmp("init-keep");
    let p = lists(&root);
    let c = cfg(&["doh"], 2);
    // 全新：寫入，伺服器讀得懂（沒有 generatedAt 也照樣載入、狀態標出來自預設名單）
    assert!(apply_initial_upstreams(&p, &c));
    let m = kuroshio::upstreams::Manager::new(&c, p.upstreams_file.clone());
    assert_eq!(m.active().len(), 2);
    assert_eq!(m.auto_info()["source"], "default-list");
    assert!(m.auto_info()["generatedAt"].is_null());
    assert!(m.auto_from_default_list());
    // 已經有評測結果（升級、匯入）：完全不動
    write(
        &p.upstreams_file,
        &json!({ "generatedAt": "2026-11-10T04:00:00Z", "selected": [{ "id": "udp://192.0.2.53", "type": "udp" }] }),
    );
    assert!(!apply_initial_upstreams(&p, &c));
    assert_eq!(read(&p.upstreams_file)["selected"][0]["id"], "udp://192.0.2.53");
    // 壓縮檔已經有資料：也不動
    std::fs::remove_file(&p.upstreams_file).unwrap();
    std::fs::write(root.join("state/upstreams.json.zst"), b"zstd").unwrap();
    assert!(!apply_initial_upstreams(&p, &c));
    assert!(!p.upstreams_file.exists());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn no_a_tier_falls_back_to_none() {
    let root = tmp("init-none");
    let mut p = BenchPaths::from_config(&json!({}), &root.join("state"), &root);
    p.list_dir = root.join("nonexistent");
    let c = cfg(&["udp", "doh"], 5);
    assert!(initial_upstreams(&p, &c).is_none(), "名單讀不到");
    std::fs::create_dir_all(root.join("b")).unwrap();
    p.list_dir = root.join("b");
    std::fs::write(
        p.list_dir.join("dohlist.txt"),
        "https://b.example.com/dns-query  # tier=B\nhttps://x.example.com/dns-query\n",
    )
    .unwrap();
    assert!(initial_upstreams(&p, &c).is_none(), "沒有 A 級");
    assert!(!apply_initial_upstreams(&p, &c));
    assert!(!p.upstreams_file.exists(), "照舊只用固定上游與 upstream.fallback");
    let _ = std::fs::remove_dir_all(&root);
}

/// 程式附帶的預設名單產生得出初始上游：都是加密的、經營者不重複
#[test]
fn repository_lists_give_encrypted_initial_upstreams() {
    let root = tmp("init-repo");
    let mut p = BenchPaths::from_config(&json!({}), &root.join("state"), &root);
    p.list_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/benchmark");
    let c = kuroshio_config::with_overrides(&json!({}));
    let v = initial_upstreams(&p, &c).unwrap();
    let sel = v["selected"].as_array().unwrap();
    assert_eq!(sel.len(), 5);
    assert!(sel.iter().all(|s| s["type"] == "doh" || s["type"] == "dot"), "{v:#}");
    let mut ops: Vec<&str> = sel
        .iter()
        .chain(v["spares"].as_array().unwrap())
        .map(|s| s["op"].as_str().unwrap())
        .collect();
    let n = ops.len();
    ops.sort_unstable();
    ops.dedup();
    assert_eq!(ops.len(), n, "{v:#}");
    let _ = std::fs::remove_dir_all(&root);
}
