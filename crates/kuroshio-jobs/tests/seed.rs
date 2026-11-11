//! 種子資料：state 空白才帶入、不覆蓋已有的、CDN 網域的 lastSeen 設成現在

use kuroshio_jobs::seed::{apply_seeds, apply_seeds_with, SEEDS};
use kuroshio_jobs::time::ManualClock;
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

#[test]
fn repository_seed_data_loads() {
    let seed = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/seed");
    let state = tmp("repo");
    let used = apply_seeds(&state, &seed);
    assert_eq!(used.len(), 4, "{used:?}");
    let up = read(&state.join("upstreams.json"));
    assert!(!up["selected"].as_array().unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&state);
}
