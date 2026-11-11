//! 從 2.x（v1）state 遷移：輸入是 2.x 的 node 程式實際產生的 key.pem、peers.json、events.json
//! （tests/fixtures/v1，用 legacy-node/lib/community 產生；key.pem 存成 key.pem.txt，因為 .gitignore 排除 *.pem）

mod common;

use common::*;
use kuroshio_community::peers::Rel;
use kuroshio_community::{Community, Config, Options};
use serde_json::Value;
use std::path::Path;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v1").join(name)).unwrap()
}

#[tokio::test]
async fn v1_state_migrates() {
    // 2.x 的配置：金鑰、peers.json、events.json 都在同一個 community 目錄
    let key_dir = tmpdir("v1-key");
    for f in ["key.pem", "peers.json", "events.json"] {
        std::fs::write(key_dir.join(f), fixture(if f == "key.pem" { "key.pem.txt" } else { f })).unwrap();
    }
    let state_dir = tmpdir("v1-state");
    let expected: Value = serde_json::from_slice(&fixture("expected.json")).unwrap();
    let v1: Value = serde_json::from_slice(&fixture("peers.json")).unwrap();
    let cfg = Config {
        enabled: true,
        domain: "me.test".into(),
        ..Default::default()
    };
    let c = Community::open(cfg.clone(), Options::new(&key_dir, &state_dir)).unwrap();

    // 金鑰直接沿用：指紋跟 2.x 顯示的一樣
    assert_eq!(c.fingerprint(), expected["fingerprint"].as_str().unwrap());
    let st = c.status();
    assert_eq!(st["publicKey"], expected["pub"]);

    // 關係與所有旗標照搬
    let f = c.peer("friend.example.net").unwrap();
    let f1 = &v1["peers"]["friend.example.net"];
    assert_eq!(f.rel, Rel::Friend);
    assert_eq!(f.pair_id.as_deref(), Some("aaaaaaaaaaaaaaaaaaaaaaaa"));
    assert_eq!(f.auto_req_pair.as_deref(), Some("zzzzzzzzzzzzzzzzzzzzzzzz"));
    assert_eq!(f.friend_since, f1["friendSince"].as_u64().unwrap());
    assert_eq!(f.info.rtt_ms, Some(12));
    assert_eq!(f.info.asn, Some(3462));
    assert_eq!(f.info.colo, "TPE");
    // 公鑰 → v2 金鑰（kid），指紋不變
    assert_eq!(f.keys.len(), 1);
    let raw = kuroshio_community::identity::public_from_v1(expected["friendPub"].as_str().unwrap()).unwrap();
    assert_eq!(
        f.keys[0].kid,
        kuroshio_community::util::hex(&kuroshio_community::identity::kid_of(&raw))
    );
    assert_eq!(
        kuroshio_community::identity::fingerprint(&raw),
        expected["friendFingerprint"].as_str().unwrap()
    );
    // v1 端點 https://…/.well-known/candydns → v2 端點
    assert_eq!(f.endpoints, vec!["https://friend.example.net:8443".to_string()]);
    // violations 丟掉；tried/ok/fail 換算成網站提示的初始分數
    assert_eq!(f.stats.offered, 120);
    assert!(f.stats.extra.get("violations").is_none());
    assert_eq!(f.score["site"].totals(now()), (24, 6, 0));

    let g = |d: &str| c.peer(d).unwrap();
    assert!(g("bad.example.org").my_block);
    assert_eq!(
        g("nope.example.com").rejected_until,
        v1["peers"]["nope.example.com"]["rejectedUntil"].as_u64().unwrap()
    );
    assert!(g("gone.example.com").deleted_at > 0);
    assert!(g("gone.example.com").pair_id.is_none());
    assert_eq!(
        g("picky.example.com").their_reject_until,
        v1["peers"]["picky.example.com"]["theirRejectUntil"].as_u64().unwrap()
    );
    assert!(g("wall.example.com").their_block);
    assert_eq!(g("wall.example.com").extra["customField"]["keep"], true, "不認識的欄位保留");
    assert_eq!(g("waiting.example.com").rel, Rel::In);
    assert_eq!(g("waiting.example.com").endpoints, vec!["dot://waiting.example.com".to_string()]);

    // 事件照搬（另外加一筆遷移紀錄）
    let evs = c.events();
    assert!(evs.iter().any(|e| e.domain == "bad.example.org" && e.kind == "已封鎖"));
    assert!(evs.iter().any(|e| e.kind == "從 v1 遷移"));

    // 快照：v2 的 peers.json + 原檔備份 peers.v1.json
    let snaps = c.snapshots();
    let get = |p: &str| snaps.iter().find(|(x, _)| x == p).map(|(_, b)| b.clone());
    assert_eq!(get("community/peers.v1.json").unwrap(), fixture("peers.json"));
    let v2: Value = serde_json::from_slice(&get("community/peers.json").unwrap()).unwrap();
    assert_eq!(v2["v"], 2);
    assert!(v2["peers"]["friend.example.net"].get("pubkey").is_none());
    assert!(v2["peers"]["friend.example.net"]["stats"].get("violations").is_none());

    // 寫回 state 後重新開啟：直接讀 v2，不再遷移
    drop(c);
    for (p, b) in &snaps {
        let path = state_dir.join(p);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b).unwrap();
    }
    let c2 = Community::open(cfg, Options::new(&key_dir, &state_dir)).unwrap();
    assert!(c2.snapshots().iter().all(|(p, _)| p != "community/peers.v1.json"));
    assert_eq!(c2.peer("friend.example.net").unwrap().score["site"].totals(now()), (24, 6, 0));
    assert_eq!(c2.fingerprint(), expected["fingerprint"].as_str().unwrap());
    assert_eq!(c2.events().len(), c2.events().len().min(200));
}

#[tokio::test]
async fn v1_key_in_old_state_dir_is_reused() {
    // 2.x 預設把金鑰放在 state/community：新的金鑰目錄還沒有時沿用同一把
    let key_dir = tmpdir("v1b-key");
    let state_dir = tmpdir("v1b-state");
    std::fs::create_dir_all(state_dir.join("community")).unwrap();
    std::fs::write(state_dir.join("community/key.pem"), fixture("key.pem.txt")).unwrap();
    let c = Community::open(Config::default(), Options::new(key_dir.join("community"), &state_dir)).unwrap();
    let expected: Value = serde_json::from_slice(&fixture("expected.json")).unwrap();
    assert_eq!(c.fingerprint(), expected["fingerprint"].as_str().unwrap());
    assert!(key_dir.join("community/key.pem").exists());
}
