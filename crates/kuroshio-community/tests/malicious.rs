//! 惡意輸入：沒有工作量證明、簽名錯誤、超過大小上限、壓縮炸彈、重放、收件者不對、時間誤差、
//! 不認識的寄件者、速率限制、大量格式錯誤的資料、TXT 不一致

mod common;

use common::*;
use kuroshio_community::envelope::*;
use kuroshio_community::transport::{call, Reply, Timeouts};
use kuroshio_community::util::{now_ms, random_bytes};
use kuroshio_community::{Community, Scheme, StaticResolver, Tuning};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

fn t() -> Timeouts {
    Timeouts {
        connect: Duration::from_secs(3),
        total: Duration::from_secs(10),
        max_wire: MAX_RESPONSE_WIRE,
    }
}

async fn send(r: &Arc<StaticResolver>, to: &Node, scheme: Scheme, action: &str, env: &Envelope) -> Reply {
    let ep = to.endpoint(scheme);
    call(&**r, &ep, action, Some(env), t())
        .await
        .unwrap_or_else(|e| panic!("{ep} {action}：{e:#}"))
}

fn err_of(r: &Reply) -> (u16, String) {
    let e = Envelope::decode(&r.body).unwrap();
    (r.status, e.error.unwrap_or_default())
}

fn request_body(from: &Community, to: &str, kid: Vec<u8>) -> RequestBody {
    RequestBody {
        t: "request".into(),
        from: from.domain(),
        to: to.into(),
        ts: now_ms(),
        nonce: random_bytes::<12>().to_vec(),
        kid,
        endpoints: from.config().endpoints,
        req_id: "r1".into(),
        pow: vec![0; 8],
    }
}

fn relation(from: &Community, to: &str, ts: u64) -> Vec<u8> {
    to_cbor(&RelationBody {
        t: "relation".into(),
        from: from.domain(),
        to: to.into(),
        ts,
        nonce: random_bytes::<12>().to_vec(),
        status: "pending".into(),
        ..Default::default()
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malicious_inputs() {
    let r = resolver(&[]);
    let m = node(
        "m.test",
        &r,
        Spec {
            max_bundle_mb: 4,
            ..Default::default()
        },
    )
    .await;
    let n = node(
        "n.test",
        &r,
        Spec {
            rules: vec![json!({ "action": "accept", "domain_suffix": "test" })],
            ..Default::default()
        },
    )
    .await;

    // 沒有工作量證明
    let mut body = to_cbor(&request_body(&m.c, "n.test", m.c.kid().to_vec()));
    while pow_ok(&body, 8) {
        body = to_cbor(&request_body(&m.c, "n.test", m.c.kid().to_vec()));
    }
    let rep = send(&r, &n, Scheme::Https, "request", &m.c.seal_envelope("request", body, None)).await;
    assert_eq!(err_of(&rep), (400, "pow".to_string()));
    assert_eq!(Envelope::decode(&rep.body).unwrap().pow_bits, Some(8));

    // 簽名錯誤（回連取得身分文件後，用文件裡的金鑰驗證）
    let body = solve_pow(to_cbor(&request_body(&m.c, "n.test", m.c.kid().to_vec())), 8);
    let mut env = m.c.seal_envelope("request", body, None);
    env.sig.as_mut().unwrap()[5] ^= 0x40;
    let rep = send(&r, &n, Scheme::Dot, "request", &env).await;
    assert_eq!(err_of(&rep), (401, "bad-signature".to_string()));
    assert!(n
        .c
        .peer("m.test")
        .map(|p| p.rel == kuroshio_community::peers::Rel::None)
        .unwrap_or(true));

    // 動作名稱不同的簽名不能冒充（request 的簽名拿去當 relation）
    let body = solve_pow(to_cbor(&request_body(&m.c, "n.test", m.c.kid().to_vec())), 8);
    let env = m.c.seal_envelope("relation", body, None);
    let rep = send(&r, &n, Scheme::Https, "request", &env).await;
    assert_eq!(rep.status, 401);

    // 超過大小上限（請求 64 KB）
    let big = m.c.seal_envelope("relation", vec![0u8; 70 * 1024], None);
    for s in [Scheme::Https, Scheme::Dot, Scheme::Doq] {
        let rep = send(&r, &n, s, "relation", &big).await;
        assert_eq!(rep.status, 413, "{s:?}");
    }

    // 加好友（n 自動同意 .test）
    let res = m.c.send_request(&n.input(), true).await;
    assert_eq!(res["status"], "accepted", "{res}");

    // 重放
    let env = m.c.seal_envelope("relation", relation(&m.c, "n.test", now_ms()), None);
    assert_eq!(send(&r, &n, Scheme::Doq, "relation", &env).await.status, 200);
    assert_eq!(
        err_of(&send(&r, &n, Scheme::Doq, "relation", &env).await),
        (400, "replay".to_string())
    );
    // 收件者不對
    let env = m.c.seal_envelope("relation", relation(&m.c, "x.test", now_ms()), None);
    assert_eq!(
        err_of(&send(&r, &n, Scheme::Https, "relation", &env).await),
        (400, "wrong-recipient".to_string())
    );
    // 時間誤差超過 10 分鐘
    let env =
        m.c.seal_envelope("relation", relation(&m.c, "n.test", now_ms() - 11 * 60_000), None);
    assert_eq!(
        err_of(&send(&r, &n, Scheme::Https, "relation", &env).await),
        (400, "clock-skew".to_string())
    );
    // 不認識的寄件者（n 沒有 u.test 的金鑰）
    let u = node("u.test", &r, Spec::default()).await;
    let env = u.c.seal_envelope("relation", relation(&u.c, "n.test", now_ms()), None);
    assert_eq!(
        err_of(&send(&r, &n, Scheme::Https, "relation", &env).await),
        (401, "unknown-sender".to_string())
    );
    // 不是好友的 poke：一律 204，不透露任何資訊
    let poke = to_cbor(&PokeBody {
        t: "poke".into(),
        from: "u.test".into(),
        to: "n.test".into(),
        ts: now_ms(),
        nonce: random_bytes::<12>().to_vec(),
        pair_id: Some("nope".into()),
        what: "data".into(),
        seq: None,
    });
    assert_eq!(
        send(&r, &n, Scheme::Dot, "poke", &u.c.seal_envelope("poke", poke, None))
            .await
            .status,
        204
    );

    // 回應超過 8 MB → 記一次；壓縮炸彈（解壓後超過 maxBundleMB）→ 再兩次 → 24 小時內 3 次就封鎖
    tokio::time::sleep(Duration::from_millis(300)).await;
    *n.faults.sync_reply.lock().unwrap() = Some(vec![7u8; 9 * 1024 * 1024]);
    let res = sync(&m, "n.test").await;
    assert_eq!(res["ok"], false, "{res}");
    assert_eq!(m.peer("n.test").malformed.len(), 1);
    assert!(!m.peer("n.test").my_block);
    let bomb = compress(&vec![0u8; 40 * 1024 * 1024]);
    assert!(bomb.len() < 64 * 1024);
    *n.faults.sync_reply.lock().unwrap() = Some(n.c.seal_envelope("sync", bomb, Some("zstd")).encode());
    for i in 0..2 {
        let res = sync(&m, "n.test").await;
        assert_eq!(res["ok"], false, "{res}");
        assert!(res["reason"].as_str().unwrap().contains("MB"), "第 {i} 次：{res}");
    }
    assert!(m.peer("n.test").my_block, "24 小時內 3 次格式錯誤 / 超過上限 → 封鎖");

    // 同一次同步裡 invalid ≥ 20 筆、而且超過有效筆數 → 封鎖；只有幾筆錯就只扣分
    let y = node("y.test", &r, Spec::default()).await;
    let mut recs = vec![node_rec("104.16.9.9")];
    recs.extend((1..=3).map(|i| node_rec(&format!("10.0.0.{i}"))));
    y.data.set(recs.clone());
    let res = m.c.send_request(&y.input(), true).await;
    assert_eq!(res["status"], "pending");
    y.c.decide("m.test", "accept").await;
    wait_for("m 拿到 y 的資料", || m.peer("y.test").last_sync_ok > 0).await;
    assert!(!m.peer("y.test").my_block, "3 筆錯不封鎖");
    assert_eq!(m.peer("y.test").score["node"].totals(now_ms()).2, 3);
    recs.extend((10..40).map(|i| node_rec(&format!("192.168.1.{i}"))));
    y.data.set(recs);
    y.c.reset_share();
    let res = sync(&m, "y.test").await;
    assert_eq!(res["status"], "blocked", "{res}");
    assert!(m.peer("y.test").my_block);

    // _kuroshio TXT：有設定就一定要一致
    r.set_txt("_kuroshio.y.test", &["v=cd2; k=0000000000000000"]);
    let e =
        m.c.fetch_identity("y.test", vec![y.endpoint(Scheme::Https)], false, true)
            .await
            .unwrap_err();
    assert!(e.to_string().contains("TXT"), "{e}");
    r.set_txt("_kuroshio.y.test", &[&y.c.txt_value()]);
    let idn =
        m.c.fetch_identity("y.test", vec![y.endpoint(Scheme::Https)], false, true)
            .await
            .unwrap();
    assert!(idn.has_txt);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn request_rate_limits() {
    let r = resolver(&[]);
    // 正式的速率：好友請求每 IP 每小時 6 次
    let v = node(
        "v.test",
        &r,
        Spec {
            tuning: Tuning {
                connect_timeout: Duration::from_secs(3),
                ..Tuning::default()
            },
            ..Default::default()
        },
    )
    .await;
    let w = node("w.test", &r, Spec::default()).await;
    let mut last = vec![];
    for _ in 0..8 {
        // 沒有工作量證明（確定不會剛好滿足 8 位元）
        let mut body = to_cbor(&request_body(&w.c, "v.test", w.c.kid().to_vec()));
        while pow_ok(&body, 8) {
            body = to_cbor(&request_body(&w.c, "v.test", w.c.kid().to_vec()));
        }
        let env = w.c.seal_envelope("request", body, None);
        last.push(send(&r, &v, Scheme::Https, "request", &env).await.status);
    }
    assert!(last[..6].iter().all(|s| *s == 400), "{last:?}");
    assert_eq!(&last[6..], &[429, 429]);
}
