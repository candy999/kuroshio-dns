//! 串接模式協定編解碼（規格 `docs/spec/10-chain.md` 第 1.2、1.3、3.2、4.2 節，工作包 WP1）
//!
//! 測試向量：固定金鑰種子（上游 `[7u8; 32]`、下游 `[9u8; 32]`）產生的訊息，跟 `tests/vectors/chain/*.json` 逐 byte 比對。
//! 向量檔是協定的一部分，不能改；只有第一次建立時用 `KUROSHIO_UPDATE_VECTORS=1 cargo test -p kuroshio-community --test chain_proto`。

use kuroshio_community::chain::*;
use kuroshio_community::envelope::{from_cbor, to_cbor};
use kuroshio_community::identity::{fingerprint, kid_of, KeyPair};
use kuroshio_community::util::{hex, unhex};
use serde_json::{json, Value};
use std::path::PathBuf;

/// 2026-01-01T00:00:00Z
const TS: u64 = 1_767_225_600_000;
const SECRET: [u8; 32] = [5u8; 32];
const PEER: &str = "192.168.1.2";
const NONCE: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

fn up_key() -> KeyPair {
    KeyPair::from_seed(&[7u8; 32])
}

fn down_key() -> KeyPair {
    KeyPair::from_seed(&[9u8; 32])
}

fn vector_file(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/vectors/chain/{name}.json"))
}

fn auth_body(k: &KeyPair, allow: bool) -> AuthBody {
    AuthBody {
        v: PROTO,
        t: "auth".into(),
        nonce: NONCE.to_vec(),
        ts: TS,
        kid: k.kid.to_vec(),
        public: k.public.to_vec(),
        app: "3.4.0".into(),
        allow,
        caps: if allow { vec!["share".into(), "reg".into()] } else { vec![] },
        peer: PEER.into(),
        tok: token(&SECRET, PEER, TS / TOKEN_WINDOW_MS).to_vec(),
        path: own_path(None, &k.kid),
    }
}

fn reg_body(up: &KeyPair, down: &KeyPair) -> RegBody {
    RegBody {
        v: PROTO,
        t: "reg".into(),
        up: up.kid.to_vec(),
        tok: token(&SECRET, PEER, TS / TOKEN_WINDOW_MS).to_vec(),
        peer: PEER.into(),
        kid: down.kid.to_vec(),
        public: down.public.to_vec(),
        app: "3.4.0".into(),
        names: vec!["dns.example.com".into(), "doh.example.net".into()],
        local: true,
    }
}

fn manifest_body(k: &KeyPair) -> ManifestBody {
    let sha: Vec<u8> = (0u8..32).collect();
    let sha2: Vec<u8> = (32u8..64).collect();
    ManifestBody {
        v: PROTO,
        t: "manifest".into(),
        kid: k.kid.to_vec(),
        at: TS,
        app: "3.4.0".into(),
        objects: vec![
            Object {
                k: "upstreams".into(),
                fmt: 1,
                id: sha[..8].to_vec(),
                sha: sha.clone(),
                size: 2_000,
                raw: 6_624,
                enc: "zstd".into(),
                at: TS - 3_600_000,
                ..Default::default()
            },
            Object {
                k: "filter-copy".into(),
                fmt: 1,
                id: sha2[..8].to_vec(),
                sha: sha2.clone(),
                size: 412_345,
                raw: 1_200_000,
                enc: "zstd".into(),
                name: "https://filter.example.net/list.txt".into(),
                at: TS - 7_200_000,
                rules: 54_321,
                hash: "0123456789abcdef".into(),
                etag: "\"abc\"".into(),
                last_modified: "Thu, 01 Jan 2026 00:00:00 GMT".into(),
            },
        ],
    }
}

fn case(name: &str, kind: &str, sealed: &[u8], note: &str) -> Value {
    let s: Sealed = from_cbor(sealed).unwrap();
    json!({ "name": name, "kind": kind, "note": note, "body": hex(&s.body), "sig": hex(&s.sig), "sealed": hex(sealed) })
}

fn key_json(seed: u8, k: &KeyPair) -> Value {
    json!({ "seed": hex(&[seed; 32]), "pub": hex(&k.public), "kid": hex(&k.kid), "fingerprint": fingerprint(&k.public) })
}

/// 跟向量檔逐 byte 比對（`KUROSHIO_UPDATE_VECTORS` 設了才寫檔）；回傳檔案裡的 cases
fn check_vectors(file: &str, cases: Vec<Value>) -> Vec<Value> {
    let path = vector_file(file);
    if std::env::var("KUROSHIO_UPDATE_VECTORS").is_ok() {
        let doc = json!({
            "spec": "docs/spec/10-chain.md",
            "signature": "Ed25519(\"kuroshio-chain/1\\0\" || kind || \"\\0\" || body)",
            "sealed": "CBOR { \"body\": bytes, \"sig\": bytes(64) }",
            "upstream": key_json(7, &up_key()),
            "downstream": key_json(9, &down_key()),
            "ts": TS, "nonce": hex(&NONCE), "peer": PEER, "tokSecret": hex(&SECRET), "tokWindow": TS / TOKEN_WINDOW_MS,
            "cases": cases,
        });
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
    }
    let doc: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("缺向量檔 {}", path.display()))).unwrap();
    assert_eq!(doc["upstream"]["pub"], hex(&up_key().public));
    assert_eq!(doc["downstream"]["pub"], hex(&down_key().public));
    let file_cases = doc["cases"].as_array().unwrap().clone();
    assert_eq!(file_cases.len(), cases.len(), "{file} 的筆數");
    for c in &cases {
        let f = file_cases
            .iter()
            .find(|x| x["name"] == c["name"])
            .unwrap_or_else(|| panic!("向量檔缺 {}", c["name"]));
        for field in ["body", "sig", "sealed"] {
            assert_eq!(f[field], c[field], "{} 的 {field} 不一致", c["name"]);
        }
    }
    file_cases
}

fn sealed_of(c: &Value) -> Vec<u8> {
    unhex(c["sealed"].as_str().unwrap()).unwrap()
}

#[test]
fn names_roundtrip_and_reject_garbage() {
    let nonce: [u8; 16] = std::array::from_fn(|i| (i * 17) as u8);
    let oid = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03];
    let an = auth_name(&nonce);
    assert_eq!(an, format!("{}.a.chain.kuroshio", hex(&nonce)));
    assert_eq!(parse_name(&an), Some(Name::Auth(nonce)));
    assert_eq!(parse_name(REG_NAME), Some(Name::Reg));
    assert_eq!(parse_name(MANIFEST_NAME), Some(Name::Manifest));
    for idx in [0, 1, 255, 999_999] {
        let cn = chunk_name(&oid, idx);
        assert_eq!(parse_name(&cn), Some(Name::Chunk { oid, idx }), "{cn}");
    }
    assert_eq!(chunk_name(&oid, 3), "3.deadbeef00010203.s.chain.kuroshio");
    for n in [&an, REG_NAME, MANIFEST_NAME, ZONE, "x.y.chain.kuroshio"] {
        assert!(in_zone(n), "{n} 在區域裡");
    }
    // 區域判斷不分大小寫、容忍結尾的點（這些都要交給串接模組回 REFUSED）
    assert!(in_zone("R.CHAIN.KUROSHIO") && in_zone("chain.kuroshio.") && in_zone("Chain.Kuroshio"));

    let bad = [
        // 大寫
        an.to_ascii_uppercase(),
        format!("{}.a.chain.kuroshio", hex(&nonce).to_ascii_uppercase()),
        "R.chain.kuroshio".into(),
        "m.S.chain.kuroshio".into(),
        "3.DEADBEEF00010203.s.chain.kuroshio".into(),
        // 多一個或少一個標籤
        format!("x.{an}"),
        "x.r.chain.kuroshio".into(),
        "x.m.s.chain.kuroshio".into(),
        "s.chain.kuroshio".into(),
        "a.chain.kuroshio".into(),
        "1.2.deadbeef00010203.s.chain.kuroshio".into(),
        "deadbeef00010203.s.chain.kuroshio".into(),
        ZONE.into(),
        // nonce 長度不對、不是十六進位
        format!("{}.a.chain.kuroshio", &hex(&nonce)[..30]),
        format!("{}00.a.chain.kuroshio", hex(&nonce)),
        format!("{}g.a.chain.kuroshio", &hex(&nonce)[..31]),
        // oid 長度不對
        "1.deadbeef000102.s.chain.kuroshio".into(),
        // idx 是負數、太長、有正號、前導 0、不是數字、空的
        "-1.deadbeef00010203.s.chain.kuroshio".into(),
        "1000000.deadbeef00010203.s.chain.kuroshio".into(),
        "+1.deadbeef00010203.s.chain.kuroshio".into(),
        "01.deadbeef00010203.s.chain.kuroshio".into(),
        "x.deadbeef00010203.s.chain.kuroshio".into(),
        ".deadbeef00010203.s.chain.kuroshio".into(),
        // 不在區域裡
        "r.chain.kuroshio.example.com".into(),
        "r.xchain.kuroshio".into(),
        "version.kuroshio".into(),
        "example.com".into(),
        // 結尾的點（應該已經 normalize）
        format!("{REG_NAME}."),
    ];
    for n in &bad {
        assert_eq!(parse_name(n), None, "{n} 不能解析");
    }
    for n in [
        "r.chain.kuroshio.example.com",
        "r.xchain.kuroshio",
        "version.kuroshio",
        "example.com",
        "kuroshio",
    ] {
        assert!(!in_zone(n), "{n} 不在區域裡");
    }
}

#[test]
fn txt_roundtrip_binary_over_255() {
    for len in [0usize, 1, 255, 256, 70_000] {
        let payload: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
        let rdata = txt_rdata(&payload);
        assert!(rdata.len() > payload.len(), "每段都有長度 byte");
        // 每段最多 255 bytes
        let mut i = 0;
        while i < rdata.len() {
            assert!(rdata[i] as usize <= 255);
            i += 1 + rdata[i] as usize;
        }
        assert_eq!(txt_payload(&rdata).as_deref(), Some(payload.as_slice()), "{len} bytes 來回");
        if len > 0 {
            assert_eq!(txt_payload(&rdata[..rdata.len() - 1]), None, "{len} bytes 截斷");
        }
    }
    assert_eq!(txt_rdata(&[]), vec![0]);
    assert_eq!(txt_rdata(&[0xff; 256]).len(), 258);
    assert_eq!(txt_payload(&[]), None);
    assert_eq!(txt_payload(&[3, 1, 2]), None);
    assert_eq!(txt_payload(&[2, 1, 2, 0]), Some(vec![1, 2]));
}

#[test]
fn auth_vector_matches() {
    let k = up_key();
    let allow = seal(&k, "auth", to_cbor(&auth_body(&k, true)));
    let deny = seal(&k, "auth", to_cbor(&auth_body(&k, false)));
    // Ed25519 是確定性的：同一把金鑰、同一個 body 每次簽出來都一樣
    assert_eq!(allow, seal(&k, "auth", to_cbor(&auth_body(&k, true))));
    let cases = vec![
        case("auth-allow", "auth", &allow, "allow_downstream 開：caps = [share, reg]"),
        case("auth-deny", "auth", &deny, "allow_downstream 關：照樣簽章，caps 是空的"),
    ];
    for c in check_vectors("auth", cases) {
        let b = open_auth(&sealed_of(&c), &NONCE).unwrap_or_else(|e| panic!("{}：{e}", c["name"]));
        assert_eq!(b.kid, k.kid.to_vec());
        assert_eq!(b.path, vec![k.kid.to_vec()]);
        assert_eq!(b.allow, c["name"] == "auth-allow");
        assert!(token_ok(&SECRET, PEER, TS, &b.tok));
    }
}

#[test]
fn reg_and_manifest_vectors_match() {
    let (up, down) = (up_key(), down_key());
    let reg = seal(&down, "reg", to_cbor(&reg_body(&up, &down)));
    let ack = seal(
        &up,
        "regack",
        to_cbor(&RegAck {
            v: PROTO,
            t: "regack".into(),
            kid: down.kid.to_vec(),
            ttl: 900,
        }),
    );
    let reg_cases = check_vectors(
        "reg",
        vec![
            case("reg", "reg", &reg, "下游的金鑰簽章；names 是下游的上游主機名稱"),
            case("regack", "regack", &ack, "上游的金鑰簽章；ttl 900 秒"),
        ],
    );
    let r = reg_cases.iter().find(|c| c["name"] == "reg").unwrap();
    assert_eq!(open_reg(&sealed_of(r)).unwrap(), reg_body(&up, &down));
    let a = reg_cases.iter().find(|c| c["name"] == "regack").unwrap();
    let ack: RegAck = from_cbor(&open(&sealed_of(a), "regack", &up.public).unwrap()).unwrap();
    assert_eq!((ack.kid, ack.ttl), (down.kid.to_vec(), 900));

    let m = seal(&up, "manifest", to_cbor(&manifest_body(&up)));
    let mc = check_vectors(
        "manifest",
        vec![case("manifest", "manifest", &m, "兩個物件：upstreams 與 filter-copy")],
    );
    let body: ManifestBody = from_cbor(&open(&sealed_of(&mc[0]), "manifest", &up.public).unwrap()).unwrap();
    assert_eq!(body, manifest_body(&up));
    assert!(open(&sealed_of(&mc[0]), "manifest", &down.public).is_err(), "別的公鑰驗不過");
    assert!(open(&sealed_of(&mc[0]), "auth", &up.public).is_err(), "kind 不同驗不過");
}

#[test]
fn auth_rejects_wrong_nonce_kid_sig_kind_version() {
    let k = up_key();
    let other = down_key();
    let good = auth_body(&k, true);
    let ok = seal(&k, "auth", to_cbor(&good));
    assert!(open_auth(&ok, &NONCE).is_ok());

    // nonce 不符
    let mut n2 = NONCE;
    n2[0] ^= 1;
    assert_eq!(open_auth(&ok, &n2), Err(AuthError::Nonce));
    // kid 跟公鑰不符
    let mut b = good.clone();
    b.kid = other.kid.to_vec();
    assert_eq!(open_auth(&seal(&k, "auth", to_cbor(&b)), &NONCE), Err(AuthError::Kid));
    let mut b = good.clone();
    b.public = k.public[..31].to_vec();
    b.kid = kid_of(&b.public).to_vec();
    assert_eq!(open_auth(&seal(&k, "auth", to_cbor(&b)), &NONCE), Err(AuthError::Kid));
    // 簽章：用別把金鑰簽（body 裡的公鑰是 k）
    assert_eq!(open_auth(&seal(&other, "auth", to_cbor(&good)), &NONCE), Err(AuthError::Signature));
    // 簽章：kind 簽成別的
    assert_eq!(open_auth(&seal(&k, "manifest", to_cbor(&good)), &NONCE), Err(AuthError::Signature));
    // 種類不對
    let mut b = good.clone();
    b.t = "reg".into();
    assert_eq!(open_auth(&seal(&k, "auth", to_cbor(&b)), &NONCE), Err(AuthError::Kind));
    // 版本太新
    let mut b = good.clone();
    b.v = 2;
    assert_eq!(open_auth(&seal(&k, "auth", to_cbor(&b)), &NONCE), Err(AuthError::Version(2)));
    // 改 body 的一個 byte（app 的最後一個字元 "0" → "1"，CBOR 仍然合法）→ 簽章驗不過
    let mut s: Sealed = from_cbor(&ok).unwrap();
    let pos = s.body.windows(5).position(|w| w == b"3.4.0").unwrap() + 4;
    s.body[pos] = b'1';
    assert_eq!(open_auth(&to_cbor(&s), &NONCE), Err(AuthError::Signature));
    // 簽章長度不是 64、不是 CBOR、body 不是 CBOR
    let mut s: Sealed = from_cbor(&ok).unwrap();
    s.sig.pop();
    assert_eq!(open_auth(&to_cbor(&s), &NONCE), Err(AuthError::Malformed));
    assert_eq!(open_auth(b"garbage", &NONCE), Err(AuthError::Malformed));
    let junk = Sealed {
        body: vec![0xff, 0x00],
        sig: vec![0; 64],
    };
    assert_eq!(open_auth(&to_cbor(&junk), &NONCE), Err(AuthError::Malformed));
    // path 裡的節點 ID 不是 8 bytes
    let mut b = good.clone();
    b.path = vec![vec![1, 2, 3]];
    assert_eq!(open_auth(&seal(&k, "auth", to_cbor(&b)), &NONCE), Err(AuthError::Malformed));
    // peek_body 不驗簽
    assert_eq!(peek_body(&seal(&other, "auth", to_cbor(&good))).unwrap(), to_cbor(&good));
}

#[test]
fn sig_context_is_not_community() {
    let k = up_key();
    let body = to_cbor(&auth_body(&k, true));
    assert_eq!(SIG_CONTEXT, b"kuroshio-chain/1\0");
    assert_ne!(SIG_CONTEXT, kuroshio_community::envelope::SIG_CONTEXT);
    // 社群共享的簽章輸入簽出來的東西，串接的 open() 驗不過
    let community_sig = k.sign(&kuroshio_community::envelope::signing_input("auth", &body));
    let forged = to_cbor(&Sealed {
        body: body.clone(),
        sig: community_sig.to_vec(),
    });
    assert!(open(&forged, "auth", &k.public).is_err());
    assert_eq!(open_auth(&forged, &NONCE), Err(AuthError::Signature));
    // 反過來：串接的簽章，社群共享的驗證也不收
    let s: Sealed = from_cbor(&seal(&k, "auth", body.clone())).unwrap();
    assert!(!kuroshio_community::identity::verify(
        &k.public,
        &kuroshio_community::envelope::signing_input("auth", &body),
        &s.sig
    ));
    assert_eq!(open(&seal(&k, "auth", body.clone()), "auth", &k.public).unwrap(), body);
    // 簽章輸入的格式
    let mut want = b"kuroshio-chain/1\0auth\0".to_vec();
    want.extend_from_slice(&body);
    assert_eq!(signing_input("auth", &body), want);
}

/// 在 CBOR map 裡多加欄位
fn with_extra_fields(body: &[u8], extra: Vec<(ciborium::Value, ciborium::Value)>) -> Vec<u8> {
    let mut v: ciborium::Value = from_cbor(body).unwrap();
    let ciborium::Value::Map(m) = &mut v else {
        panic!("body 不是 map")
    };
    m.extend(extra);
    to_cbor(&v)
}

#[test]
fn unknown_fields_ignored() {
    use ciborium::Value as C;
    let k = up_key();
    let good = auth_body(&k, true);
    let body = with_extra_fields(
        &to_cbor(&good),
        vec![
            (C::Text("future".into()), C::Array(vec![C::Integer(1.into()), C::Text("x".into())])),
            (
                C::Text("dot".into()),
                C::Map(vec![
                    (C::Text("port".into()), C::Integer(853.into())),
                    (C::Text("spki".into()), C::Bytes(vec![0xab; 32])),
                ]),
            ),
        ],
    );
    assert_ne!(body, to_cbor(&good));
    assert_eq!(open_auth(&seal(&k, "auth", body), &NONCE).unwrap(), good);

    // 選用欄位沒有也解得開
    let minimal = to_cbor(&C::Map(vec![
        (C::Text("v".into()), C::Integer(1.into())),
        (C::Text("t".into()), C::Text("auth".into())),
        (C::Text("nonce".into()), C::Bytes(NONCE.to_vec())),
        (C::Text("kid".into()), C::Bytes(k.kid.to_vec())),
        (C::Text("pub".into()), C::Bytes(k.public.to_vec())),
    ]));
    let b = open_auth(&seal(&k, "auth", minimal), &NONCE).unwrap();
    assert!(!b.allow && b.caps.is_empty() && b.path.is_empty());

    // reg、manifest 也一樣
    let (up, down) = (up_key(), down_key());
    let reg = with_extra_fields(&to_cbor(&reg_body(&up, &down)), vec![(C::Text("x".into()), C::Bool(true))]);
    assert_eq!(open_reg(&seal(&down, "reg", reg)).unwrap(), reg_body(&up, &down));
    let mut obj_extra: C = from_cbor(&to_cbor(&manifest_body(&up))).unwrap();
    if let C::Map(m) = &mut obj_extra {
        for (key, val) in m.iter_mut() {
            if key == &C::Text("objects".into()) {
                if let C::Array(objs) = val {
                    if let C::Map(o) = &mut objs[0] {
                        o.push((C::Text("newField".into()), C::Integer(7.into())));
                    }
                }
            }
        }
    }
    let mb: ManifestBody = from_cbor(&to_cbor(&obj_extra)).unwrap();
    assert_eq!(mb, manifest_body(&up));
}

#[test]
fn token_window() {
    let now = TS + 123_456;
    let w = now / TOKEN_WINDOW_MS;
    let cur = token(&SECRET, PEER, w);
    let prev = token(&SECRET, PEER, w - 1);
    let older = token(&SECRET, PEER, w - 2);
    assert_ne!(cur, prev);
    assert!(token_ok(&SECRET, PEER, now, &cur), "同一個時間窗");
    assert!(token_ok(&SECRET, PEER, now, &prev), "前一個時間窗");
    assert!(!token_ok(&SECRET, PEER, now, &older), "再前一個時間窗");
    assert!(!token_ok(&SECRET, PEER, now, &token(&SECRET, PEER, w + 1)), "下一個時間窗");
    assert!(!token_ok(&SECRET, "192.168.1.3", now, &cur), "別的 peer");
    assert!(!token_ok(&[6u8; 32], PEER, now, &cur), "別的密鑰");
    assert!(!token_ok(&SECRET, PEER, now, &cur[..15]), "長度不對");
    assert!(!token_ok(&SECRET, PEER, now, &[]), "空的");
    // 時間窗編號 0 沒有前一個
    assert!(token_ok(&SECRET, PEER, 1_000, &token(&SECRET, PEER, 0)));
    // 時間窗邊界：下一個時間窗的開頭，原本目前的那個變成「前一個」
    let next_start = (w + 1) * TOKEN_WINDOW_MS;
    assert!(token_ok(&SECRET, PEER, next_start, &cur));
    assert!(!token_ok(&SECRET, PEER, next_start, &prev));
    // 確定性
    assert_eq!(token(&SECRET, PEER, w), cur);
}

#[test]
fn path_rules() {
    let me = [1u8; 8];
    let old = [2u8; 8];
    let a = vec![0xa0u8; 8];
    let b = vec![0xb0u8; 8];
    let c = vec![0xc0u8; 8];
    let d = vec![0xd0u8; 8];
    assert_eq!(check_path(&[], &[me]), Ok(()));
    assert_eq!(check_path(&[a.clone(), me.to_vec()], &[me]), Err(PathError::Loop));
    assert_eq!(check_path(&[old.to_vec()], &[me, old]), Err(PathError::Loop), "輪替中的舊 kid");
    assert_eq!(check_path(&[a.clone(), b.clone(), c.clone()], &[me, old]), Ok(()), "長度 3 可以");
    assert_eq!(
        check_path(&[a.clone(), b.clone(), c.clone(), d.clone()], &[me]),
        Err(PathError::TooDeep),
        "長度 4 太深"
    );
    // 太深又含自己：先報迴圈
    assert_eq!(
        check_path(&[a.clone(), b.clone(), c.clone(), me.to_vec()], &[me]),
        Err(PathError::Loop)
    );

    assert_eq!(own_path(None, &me), vec![me.to_vec()]);
    assert_eq!(own_path(Some(&[]), &me), vec![me.to_vec()]);
    assert_eq!(
        own_path(Some(&[a.clone(), b.clone()]), &me),
        vec![a.clone(), b.clone(), me.to_vec()]
    );
    // A→B→A：B 串接 A 之後公告 [A, B]，A 看到自己
    let a_kid: [u8; 8] = a.clone().try_into().unwrap();
    let b_path = own_path(Some(&own_path(None, &a_kid)), &[0xb0; 8]);
    assert_eq!(check_path(&b_path, &[a_kid]), Err(PathError::Loop));
}

#[test]
fn version_parse() {
    assert_eq!(parse_version("3.4.0"), Some((3, 4, 0)));
    assert_eq!(parse_version("3.4.1-rc1"), Some((3, 4, 1)));
    assert_eq!(parse_version("3.4.0-rc1"), Some((3, 4, 0)));
    assert_eq!(parse_version("3.10.0"), Some((3, 10, 0)));
    assert_eq!(parse_version("3.3.7"), Some((3, 3, 7)));
    assert_eq!(parse_version("abc"), None);
    assert_eq!(parse_version("3.4"), None);
    assert_eq!(parse_version(""), None);
    assert_eq!(parse_version("3.x.0"), None);
    assert_eq!(parse_version("3.4.0.1"), None);
    assert!(version_ok("3.4.0"));
    assert!(version_ok("3.4.0-rc1"));
    assert!(version_ok("3.4.1-rc1"));
    assert!(version_ok("3.10.0"));
    assert!(version_ok("4.0.0"));
    assert!(!version_ok("3.3.7"));
    assert!(!version_ok("3.3.99"));
    assert!(!version_ok("abc"));
}

#[test]
fn reg_limits() {
    let (up, down) = (up_key(), down_key());
    let good = reg_body(&up, &down);
    assert!(open_reg(&seal(&down, "reg", to_cbor(&good))).is_ok());

    // 32 個名稱可以、33 個不行
    let mut b = good.clone();
    b.names = (0..32).map(|i| format!("dns{i}.example.com")).collect();
    assert!(open_reg(&seal(&down, "reg", to_cbor(&b))).is_ok());
    b.names.push("dns32.example.com".into());
    assert!(open_reg(&seal(&down, "reg", to_cbor(&b))).is_err(), "33 個名稱");
    // 不合法的網域
    for bad in ["localhost", "192.0.2.1", "-a.example.com", "a..example.com", "", "a b.example.com"] {
        let mut b = good.clone();
        b.names = vec!["dns.example.com".into(), bad.into()];
        assert!(open_reg(&seal(&down, "reg", to_cbor(&b))).is_err(), "不合法的網域 {bad:?}");
    }
    // kid 與公鑰不符
    let mut b = good.clone();
    b.kid = up.kid.to_vec();
    assert!(open_reg(&seal(&down, "reg", to_cbor(&b))).is_err(), "kid 與公鑰不符");
    // 簽章不是 body 裡的公鑰簽的
    assert!(open_reg(&seal(&up, "reg", to_cbor(&good))).is_err(), "別的金鑰簽的");
    // kind 不對
    assert!(open_reg(&seal(&down, "auth", to_cbor(&good))).is_err(), "簽成 auth");
    let mut b = good.clone();
    b.t = "auth".into();
    assert!(open_reg(&seal(&down, "reg", to_cbor(&b))).is_err(), "t 不是 reg");
    // 版本太新
    let mut b = good.clone();
    b.v = 2;
    assert!(open_reg(&seal(&down, "reg", to_cbor(&b))).is_err(), "v = 2");
    // up、tok 長度不對
    let mut b = good.clone();
    b.tok = vec![1; 15];
    assert!(open_reg(&seal(&down, "reg", to_cbor(&b))).is_err(), "tok 長度");
    let mut b = good.clone();
    b.up = vec![];
    assert!(open_reg(&seal(&down, "reg", to_cbor(&b))).is_err(), "up 長度");
}
