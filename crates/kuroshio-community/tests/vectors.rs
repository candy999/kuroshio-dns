//! 測試向量（規格 03 第 12 節）：固定金鑰、固定 nonce、固定時間產生的信封，跟 `tests/vectors/community/v2.json` 逐位元組比對。
//! 更新向量：`KUROSHIO_UPDATE_VECTORS=1 cargo test -p kuroshio-community --test vectors`

use kuroshio_community::envelope::*;
use kuroshio_community::identity::{fingerprint, KeyInfo, KeyPair};
use kuroshio_community::util::{friend_hash, hex, site_hash, unhex};
use serde_json::{json, Value};
use std::path::PathBuf;

const TS: u64 = 1_767_225_600_000; // 2026-01-01T00:00:00Z

fn nonce() -> Vec<u8> {
    (0xa0..0xac).collect()
}

fn key(start: u8) -> KeyPair {
    let seed: [u8; 32] = std::array::from_fn(|i| start + i as u8);
    KeyPair::from_seed(&seed)
}

fn file() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/community/v2.json")
}

fn case(name: &str, action: &str, env: &Envelope, note: &str) -> Value {
    json!({
        "name": name, "action": action, "note": note,
        "kid": env.kid.as_ref().map(|k| hex(k)), "body": env.body.as_ref().map(|b| hex(b)),
        "sig": env.sig.as_ref().map(|s| hex(s)), "envelope": hex(&env.encode()),
    })
}

fn sync_response() -> SyncResponse {
    SyncResponse {
        t: "sync".into(),
        from: "b.example".into(),
        to: "a.example".into(),
        ts: TS,
        nonce: nonce(),
        status: "ok".into(),
        epoch: Some(serde_bytes::ByteBuf::from(vec![1, 2, 3, 4, 5, 6, 7, 8])),
        seq: Some(7),
        full: Some(false),
        ctx: Some(NetInfo {
            asn: Some(3462),
            colo: "TPE".into(),
        }),
        upserts: vec![
            Lenient(Some(WireRecord {
                kind: "node".into(),
                key: "cloudflare/104.16.1.1".into(),
                seq: 6,
                obs: TS - 60_000,
                exp: TS - 60_000 + 3 * 86_400_000,
                p: Some("cloudflare".into()),
                ip: Some("104.16.1.1".into()),
                fam: Some(4),
                pop: Some("TPE".into()),
                ms: Some(3),
                ..Default::default()
            })),
            Lenient(Some(WireRecord {
                kind: "site".into(),
                key: format!("{}/4", hex(&site_hash("example.com"))),
                seq: 7,
                obs: TS - 60_000,
                exp: TS - 60_000 + 3 * 86_400_000,
                p: Some("cloudflare".into()),
                fam: Some(4),
                pop: Some("TPE".into()),
                h: Some(serde_bytes::ByteBuf::from(site_hash("example.com").to_vec())),
                ips: Some(vec!["104.16.2.2".into()]),
                ..Default::default()
            })),
        ],
        deletes: vec![("node".into(), "cloudflare/104.16.1.2".into())],
        ..Default::default()
    }
}

/// 產生所有向量（zstd 那筆另外處理：壓縮器版本不同、壓出來的位元組可能不同，只驗證解得開）
fn build() -> Vec<Value> {
    let k = key(0);
    let k2 = key(32);
    let mut out = vec![];
    let id = IdentityBody {
        t: "identity".into(),
        from: "a.example".into(),
        ts: TS,
        nonce: nonce(),
        keys: vec![KeyInfo {
            kid: k.kid.to_vec(),
            public: k.public.to_vec(),
            since: TS - 86_400_000,
        }],
        endpoints: vec!["doq://a.example".into(), "dot://a.example".into(), "https://a.example".into()],
        proto: vec![2],
        caps: vec!["sync-delta".into(), "poke".into(), "zstd".into()],
        since: 1_735_689_600_000,
        net: NetInfo {
            asn: Some(3462),
            colo: "TPE".into(),
        },
        friends: vec![serde_bytes::ByteBuf::from(friend_hash("b.example").to_vec())],
        rot: vec![],
    };
    out.push(case("identity", "identity", &seal(&k, "identity", to_cbor(&id), None), "身分文件"));
    let req = RequestBody {
        t: "request".into(),
        from: "a.example".into(),
        to: "b.example".into(),
        ts: TS,
        nonce: nonce(),
        kid: k.kid.to_vec(),
        endpoints: vec!["doq://a.example".into(), "https://a.example".into()],
        req_id: "000102030405060708090a0b".into(),
        pow: vec![0; 8],
    };
    let body = solve_pow(to_cbor(&req), 12);
    out.push(case(
        "request",
        "request",
        &seal(&k, "request", body, None),
        "好友請求，PoW 12 位元（最後 8 bytes 是 pow）",
    ));
    let rel = RelationBody {
        t: "relation".into(),
        from: "b.example".into(),
        to: "a.example".into(),
        ts: TS,
        nonce: nonce(),
        pair_id: Some("0123456789abcdef01234567".into()),
        status: "accepted".into(),
        req_id: Some("000102030405060708090a0b".into()),
        ..Default::default()
    };
    out.push(case(
        "relation-accepted",
        "relation",
        &seal(&k, "relation", to_cbor(&rel), None),
        "同意",
    ));
    let sreq = SyncRequest {
        t: "sync".into(),
        from: "a.example".into(),
        to: "b.example".into(),
        ts: TS,
        nonce: nonce(),
        pair_id: Some("0123456789abcdef01234567".into()),
        epoch: Some(serde_bytes::ByteBuf::from(vec![1, 2, 3, 4, 5, 6, 7, 8])),
        since: Some(5),
    };
    out.push(case(
        "sync-request",
        "sync",
        &seal(&k, "sync", to_cbor(&sreq), None),
        "增量同步請求",
    ));
    out.push(case(
        "sync-response",
        "sync",
        &seal(&k, "sync", to_cbor(&sync_response()), None),
        "增量回應（未壓縮）",
    ));
    let poke = PokeBody {
        t: "poke".into(),
        from: "b.example".into(),
        to: "a.example".into(),
        ts: TS,
        nonce: nonce(),
        pair_id: Some("0123456789abcdef01234567".into()),
        what: "data".into(),
        seq: Some(7),
    };
    out.push(case("poke", "poke", &seal(&k, "poke", to_cbor(&poke), None), "通知有新資料"));
    let rot = RotateBody {
        t: "rotate".into(),
        from: "a.example".into(),
        ts: TS,
        nonce: nonce(),
        old: k.kid.to_vec(),
        new: KeyInfo {
            kid: k2.kid.to_vec(),
            public: k2.public.to_vec(),
            since: TS,
        },
    };
    out.push(case(
        "rotate",
        "rotate",
        &seal(&k, "rotate", to_cbor(&rot), None),
        "輪替：舊金鑰簽名",
    ));
    let mut framed = seal(&k, "poke", to_cbor(&poke), None);
    framed.a = Some("poke".into());
    out.push(case("framed-poke", "poke", &framed, "TLS / QUIC 管道的請求多一個 a"));
    let ident_req = Envelope {
        v: 2,
        a: Some("identity".into()),
        ..Default::default()
    };
    out.push(case("framed-identity-request", "identity", &ident_req, "TLS / QUIC 管道取身分文件"));
    out.push(json!({ "name": "error-pow", "action": "", "note": "錯誤回應：PoW 不足（要 20 位元）", "envelope": hex(&pow_reply(20)) }));
    out
}

#[test]
fn vectors_match() {
    let k = key(0);
    let mut cases = build();
    let path = file();
    let update = std::env::var("KUROSHIO_UPDATE_VECTORS").is_ok() || !path.exists();
    if update {
        let plain = to_cbor(&sync_response());
        let env = seal(&k, "sync", compress(&plain), Some("zstd"));
        cases.push(case(
            "sync-response-zstd",
            "sync",
            &env,
            "同一個回應，zstd 壓縮後簽名（簽名對象是壓縮後的位元組）",
        ));
        let doc = json!({
            "spec": "docs/spec/03-community-v2.md",
            "signature": "Ed25519(\"kuroshio/2\\0\" || action || \"\\0\" || body)",
            "pow": "SHA-256(\"kuroshio/2-pow\\0\" || body) 前 N 位元為 0",
            "key": {
                "seed": hex(&(0u8..32).collect::<Vec<_>>()), "pub": hex(&k.public), "kid": hex(&k.kid),
                "fingerprint": fingerprint(&k.public), "pkcs8Pem": k.to_pem(),
            },
            "rotateTo": { "seed": hex(&(32u8..64).collect::<Vec<_>>()), "pub": hex(&key(32).public), "kid": hex(&key(32).kid) },
            "ts": TS, "nonce": hex(&nonce()), "siteHash": { "example.com": hex(&site_hash("example.com")) },
            "cases": cases,
        });
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
    }
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(doc["key"]["pub"], hex(&k.public));
    assert_eq!(KeyPair::from_pem(doc["key"]["pkcs8Pem"].as_str().unwrap()).unwrap().kid, k.kid);
    assert_eq!(doc["siteHash"]["example.com"], hex(&site_hash("example.com")));
    let file_cases = doc["cases"].as_array().unwrap();
    // 每一筆跟現在產生的逐位元組一致（zstd 那筆除外）
    for c in &cases {
        let f = file_cases
            .iter()
            .find(|x| x["name"] == c["name"])
            .unwrap_or_else(|| panic!("向量檔缺 {}", c["name"]));
        if c["name"] != "sync-response-zstd" {
            assert_eq!(f["envelope"], c["envelope"], "{} 的位元組不一致", c["name"]);
        }
    }
    // 每一筆都能獨立驗證
    for f in file_cases {
        let env = Envelope::decode(&unhex(f["envelope"].as_str().unwrap()).unwrap()).unwrap();
        let action = f["action"].as_str().unwrap();
        if env.sig.is_none() {
            continue;
        }
        assert!(env.verify_with(action, &k.public), "{} 簽名", f["name"]);
        assert!(!env.verify_with("other", &k.public), "{} 換動作名稱就驗不過", f["name"]);
        let plain = env.plain_body(MAX_RESPONSE_PLAIN).unwrap();
        let head: Head = from_cbor(&plain).unwrap();
        assert_eq!(head.t, action);
        assert_eq!(head.nonce, nonce());
        if f["name"] == "sync-response-zstd" {
            let plain_case = file_cases.iter().find(|x| x["name"] == "sync-response").unwrap();
            assert_eq!(hex(&plain), plain_case["body"].as_str().unwrap(), "解壓後跟未壓縮的 body 一樣");
        }
        if f["name"] == "request" {
            assert!(pow_ok(&plain, 12));
        }
    }
    assert!(file_cases.iter().any(|x| x["name"] == "sync-response-zstd"));
}
