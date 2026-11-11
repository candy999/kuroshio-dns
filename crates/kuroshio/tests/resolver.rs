//! 解析器整合測試：快取、singleflight、否定快取、過濾、CNAME 封鎖、多上游合併、回舊資料

use kuroshio::resolver::{Ctx, FilterCheck, Verdict};
use kuroshio_proto::message::{rtype, Message, RData, Record};
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

/// 可程式化的假上游：依名稱決定回應，並計算收到幾次查詢
async fn upstream(delay_ms: u64, answer: fn(&str, u16) -> (u16, Vec<Record>, u32)) -> (SocketAddr, Arc<AtomicUsize>) {
    let s = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = s.local_addr().unwrap();
    let n = Arc::new(AtomicUsize::new(0));
    let n2 = n.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let (len, peer) = s.recv_from(&mut buf).await.unwrap();
            n2.fetch_add(1, Ordering::SeqCst);
            let q = Message::parse(&buf[..len]).unwrap();
            let (rcode, answers, soa_ttl) = answer(&q.questions[0].name, q.questions[0].qtype);
            let mut r = Message::response_to(&q, rcode);
            r.opt = None;
            r.answers = answers;
            if soa_ttl > 0 {
                r.authorities.push(Record {
                    name: "test".into(),
                    rtype: rtype::SOA,
                    class: 1,
                    ttl: soa_ttl,
                    data: RData::Soa {
                        mname: "ns.test".into(),
                        rname: "h.test".into(),
                        serial: 1,
                        refresh: 1,
                        retry: 1,
                        expire: 1,
                        minimum: 30,
                    },
                });
            }
            let s = s.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                let _ = s.send_to(&r.encode(), peer).await;
            });
        }
    });
    (addr, n)
}

fn a(name: &str, ttl: u32, ip: [u8; 4]) -> Record {
    Record::a(name, ttl, Ipv4Addr::from(ip))
}

fn answer(name: &str, _t: u16) -> (u16, Vec<Record>, u32) {
    match name {
        "nx.test" => (3, vec![], 900),
        "ad-cname.test" => (
            0,
            vec![
                Record {
                    name: name.into(),
                    rtype: rtype::CNAME,
                    class: 1,
                    ttl: 300,
                    data: RData::Name("tracker.bad.test".into()),
                },
                a("tracker.bad.test", 300, [5, 6, 7, 8]),
            ],
            0,
        ),
        "short.test" => (0, vec![a(name, 1, [1, 1, 1, 1])], 0),
        _ => (0, vec![a(name, 300, [1, 2, 3, 4])], 0),
    }
}

fn cfg(ups: &[SocketAddr], extra: serde_json::Value) -> serde_json::Value {
    let mut c = kuroshio_config::with_overrides(&json!({
        "admin": { "port": 0, "auth": false },
        "filter": { "enabled": false },
        "system": { "persistDir": std::env::temp_dir().join("kuroshio-rtest").to_string_lossy() },
        "upstream": { "pinned": ups.iter().map(|u| format!("udp://{u}")).collect::<Vec<_>>(), "fallback": [] },
        "resolver": { "timeoutMs": 800, "collectWindowMs": 100, "lastResort": [], "rankIps": false }
    }));
    kuroshio_config::merge(&mut c, &extra);
    c
}

fn q(id: u16, name: &str, t: u16) -> Vec<u8> {
    kuroshio_proto::build_query(id, name, t)
}

const CTX: Ctx = Ctx {
    proto: "test",
    client: IpAddr::V4(Ipv4Addr::LOCALHOST),
};

#[tokio::test]
async fn cache_hit_and_singleflight() {
    let (up, n) = upstream(50, answer).await;
    let r = kuroshio::app::build_resolver(&cfg(&[up], json!({}))).unwrap();
    // 同時 10 個相同查詢 → 上游只收到 1 次
    let mut set = tokio::task::JoinSet::new();
    for i in 0..10 {
        let r = r.clone();
        set.spawn(async move { r.handle(&q(i, "www.example.test", 1), &CTX).await.unwrap() });
    }
    while let Some(resp) = set.join_next().await {
        let m = Message::parse(&resp.unwrap()).unwrap();
        assert_eq!(m.answers[0].data, RData::A(Ipv4Addr::new(1, 2, 3, 4)));
    }
    assert_eq!(n.load(Ordering::SeqCst), 1, "singleflight");
    // 之後是快取命中，TTL 是剩餘秒數；大小寫不同也命中，回應保留用戶端的大小寫
    let m = Message::parse(&r.handle(&q(77, "WWW.Example.TEST", 1), &CTX).await.unwrap()).unwrap();
    assert_eq!(n.load(Ordering::SeqCst), 1);
    assert_eq!(m.id, 77);
    assert_eq!(m.questions[0].name, "WWW.Example.TEST");
    assert!(m.answers[0].ttl <= 300 && m.answers[0].ttl >= 298);
    assert_eq!(r.stats.summary()["today"]["hit"], 1);
}

#[tokio::test]
async fn negative_cache_uses_soa_minimum() {
    let (up, n) = upstream(0, answer).await;
    let r = kuroshio::app::build_resolver(&cfg(&[up], json!({}))).unwrap();
    for i in 0..3 {
        let m = Message::parse(&r.handle(&q(i, "nx.test", 1), &CTX).await.unwrap()).unwrap();
        assert_eq!(m.rcode, 3);
        assert!(m.authorities[0].ttl <= 30, "否定回應 TTL = min(SOA ttl, minimum)");
    }
    assert_eq!(n.load(Ordering::SeqCst), 1);
}

struct Block;
impl FilterCheck for Block {
    fn check(&self, name: &str, _t: u16) -> Option<Verdict> {
        let blocked = name == "ads.test" || name.ends_with(".bad.test");
        blocked.then(|| Verdict {
            block: true,
            allow: false,
            category: "ads",
            rule: format!("||{name}^"),
        })
    }
}

#[tokio::test]
async fn filter_and_cname_chain() {
    let (up, n) = upstream(0, answer).await;
    let r = kuroshio::app::build_resolver(&cfg(&[up], json!({}))).unwrap();
    r.set_filter(Some(Arc::new(Block)));
    let m = Message::parse(&r.handle(&q(1, "ads.test", 1), &CTX).await.unwrap()).unwrap();
    assert_eq!(m.answers[0].data, RData::A(Ipv4Addr::UNSPECIFIED));
    assert_eq!(n.load(Ordering::SeqCst), 0, "被擋的不問上游");
    // CNAME 指向被擋的網域
    let m = Message::parse(&r.handle(&q(2, "ad-cname.test", 1), &CTX).await.unwrap()).unwrap();
    assert_eq!(m.answers.len(), 1);
    assert_eq!(m.answers[0].data, RData::A(Ipv4Addr::UNSPECIFIED));
    // 快取命中也維持封鎖
    let m = Message::parse(&r.handle(&q(3, "ad-cname.test", 1), &CTX).await.unwrap()).unwrap();
    assert_eq!(m.answers[0].data, RData::A(Ipv4Addr::UNSPECIFIED));
    assert_eq!(r.stats.summary()["today"]["blocked"], 3);
}

fn loop_a(name: &str, _t: u16) -> (u16, Vec<Record>, u32) {
    (0, vec![a(name, 200, [127, 0, 0, 5])], 0)
}
fn loop_b(name: &str, _t: u16) -> (u16, Vec<Record>, u32) {
    (0, vec![a(name, 200, [127, 0, 0, 3]), a(name, 200, [127, 0, 0, 4])], 0)
}

#[tokio::test]
async fn merges_ips_from_all_upstreams_and_ranks() {
    // 只有 127.0.0.4 在測速埠上有人聽：合併兩個上游的 IP 後，它要排第一，連不上的拿掉
    // （127.0.0.1 / 127.0.0.2 是「上游已擋」的 sinkhole 位址，不能拿來測）
    let l = tokio::net::TcpListener::bind("127.0.0.4:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let _ = l.accept().await;
        }
    });
    let (up_a, _) = upstream(0, loop_a).await;
    let (up_b, _) = upstream(30, loop_b).await;
    let c = cfg(
        &[up_a, up_b],
        json!({ "resolver": { "rankIps": true, "fastPath": false }, "iprank": { "port": port, "timeoutMs": 300 } }),
    );
    let r = kuroshio::app::build_resolver(&c).unwrap();
    let m = Message::parse(&r.handle(&q(1, "merge.test", 1), &CTX).await.unwrap()).unwrap();
    let ips: Vec<_> = m.answers.iter().map(|a| a.data.clone()).collect();
    assert_eq!(ips, vec![RData::A(Ipv4Addr::new(127, 0, 0, 4))], "只留測得通的");
    let e = r.cache.lock().unwrap().peek("1|merge.test").unwrap();
    assert!(e.ranked.as_deref().unwrap().ends_with("/3IP"), "{:?}", e.ranked);
}

#[tokio::test]
async fn serves_stale_while_refreshing() {
    let (up, n) = upstream(0, answer).await;
    let r = kuroshio::app::build_resolver(&cfg(&[up], json!({ "resolver": { "serveStaleSec": 3600 } }))).unwrap();
    r.handle(&q(1, "short.test", 1), &CTX).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1300)).await;
    // TTL 1 秒已過期：先回舊資料（TTL 10），背景更新
    let m = Message::parse(&r.handle(&q(2, "short.test", 1), &CTX).await.unwrap()).unwrap();
    assert_eq!(m.answers[0].ttl, 10);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(n.load(Ordering::SeqCst), 2, "背景重新查詢一次");
}

#[tokio::test]
async fn formerr_for_garbage_and_no_reply_to_responses() {
    let (up, _) = upstream(0, answer).await;
    let r = kuroshio::app::build_resolver(&cfg(&[up], json!({}))).unwrap();
    let mut bad = q(5, "x.test", 1);
    bad.truncate(14);
    let resp = r.handle(&bad, &CTX).await.unwrap();
    assert_eq!(kuroshio_proto::header(&resp).unwrap().rcode, kuroshio_proto::RCODE_FORMERR);
    let mut response = q(6, "x.test", 1);
    response[2] |= 0x80;
    assert!(r.handle(&response, &CTX).await.is_none(), "收到的是回應封包：不回（避免反射）");
}

/// 管理 API：用真的 HTTP 打
async fn http_get(addr: SocketAddr, path: &str, host: &str) -> (u16, serde_json::Value) {
    http_req(addr, "GET", path, host).await
}

async fn http_req(addr: SocketAddr, method: &str, path: &str, host: &str) -> (u16, serde_json::Value) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: test\r\nContent-Length: 0\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    let text = String::from_utf8(out).unwrap();
    let code: u16 = text[9..12].parse().unwrap();
    let body = text.split_once("\r\n\r\n").unwrap().1;
    (code, serde_json::from_str(body).unwrap())
}

#[tokio::test]
async fn admin_api() {
    let (up, _) = upstream(0, answer).await;
    let mut c = cfg(&[up], json!({}));
    c["listen"] = json!({ "plain": { "binds": ["127.0.0.1"], "port": 0 } });
    let started = kuroshio::app::start(&c, kuroshio_config::Tier::Small).await.unwrap();
    let admin = started.admin.unwrap();
    started.resolver.handle(&q(1, "www.example.test", 1), &CTX).await.unwrap();

    let (code, st) = http_get(admin, "/api/status?lite=1", "127.0.0.1:8054").await;
    assert_eq!(code, 200);
    assert_eq!(st["stats"]["today"]["query"], 1);
    assert_eq!(st["cacheEntries"], 1);
    assert_eq!(st["system"]["tier"], "small");
    assert!(st["upstreams"].as_array().unwrap().len() == 1);

    started.resolver.set_filter(Some(Arc::new(Block)));
    let (_, f) = http_get(admin, "/api/filter/check?name=ADS.test&type=A", "localhost").await;
    assert_eq!(f["action"], "block");
    let (_, t) = http_get(admin, "/api/trace?name=www.example.test", "localhost").await;
    assert_eq!(t["upstreams"][0]["answers"][0], "1 www.example.test 300 1.2.3.4");
    assert_eq!(t["cache"]["source"], format!("udp://{up}"));

    // 會改東西的動作只接受 POST（GET 任何網頁都能用 <img> 送出）
    let (code, _) = http_get(admin, "/api/cache/flush", "localhost").await;
    assert_eq!(code, 405);
    let (_, st) = http_get(admin, "/api/status", "localhost").await;
    assert_eq!(st["cacheEntries"], 1, "GET 沒有清掉快取");
    let (_, fl) = http_req(admin, "POST", "/api/cache/flush", "localhost").await;
    assert_eq!(fl["ok"], true);
    let (_, st) = http_get(admin, "/api/status", "localhost").await;
    assert_eq!(st["cacheEntries"], 0);

    let (code, _) = http_get(admin, "/api/status", "evil.example.com").await;
    assert_eq!(code, 403, "DNS rebinding 擋下");
    let (code, _) = http_get(admin, "/api/nope", "localhost").await;
    assert_eq!(code, 404);
    let (code, _) = http_get(admin, "/api/filter/check", "localhost").await;
    assert_eq!(code, 400);
}

/// 可以關掉的上游：down=true 時不回應
async fn switchable(answer_ttl: u32) -> (SocketAddr, Arc<std::sync::atomic::AtomicBool>, Arc<AtomicUsize>) {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    let down = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let n = Arc::new(AtomicUsize::new(0));
    let (d2, n2) = (down.clone(), n.clone());
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let (len, peer) = s.recv_from(&mut buf).await.unwrap();
            n2.fetch_add(1, Ordering::SeqCst);
            if d2.load(Ordering::SeqCst) {
                continue;
            }
            let q = Message::parse(&buf[..len]).unwrap();
            let mut r = Message::response_to(&q, 0);
            r.opt = None;
            r.answers.push(a(&q.questions[0].name, answer_ttl, [9, 9, 9, 9]));
            let _ = s.send_to(&r.encode(), peer).await;
        }
    });
    (addr, down, n)
}

#[tokio::test]
async fn stale_if_error_when_all_upstreams_down() {
    let (up, down, _) = switchable(1).await;
    let c = cfg(
        &[up],
        json!({ "resolver": { "serveStaleSec": 0, "staleIfErrorSec": 3600, "timeoutMs": 300 } }),
    );
    let r = kuroshio::app::build_resolver(&c).unwrap();
    r.handle(&q(1, "site.test", 1), &CTX).await.unwrap();
    down.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1200)).await;
    // 過期、上游全掛：回舊資料（TTL 10），不回 SERVFAIL
    let m = Message::parse(&r.handle(&q(2, "site.test", 1), &CTX).await.unwrap()).unwrap();
    assert_eq!(m.rcode, 0);
    assert_eq!(m.answers[0].ttl, 10);
    // 斷線期間：直接回舊資料，不用再等上游逾時
    let t0 = std::time::Instant::now();
    let m = Message::parse(&r.handle(&q(3, "site.test", 1), &CTX).await.unwrap()).unwrap();
    assert_eq!(m.answers[0].data, RData::A(Ipv4Addr::new(9, 9, 9, 9)));
    assert!(t0.elapsed() < Duration::from_millis(100), "{:?}", t0.elapsed());
    assert!(r.stats.summary()["today"]["stale"].as_u64().unwrap() >= 2);
    // 沒有舊資料的名稱照樣 SERVFAIL
    let m = Message::parse(&r.handle(&q(4, "never.test", 1), &CTX).await.unwrap()).unwrap();
    assert_eq!(m.rcode, 2);
}

#[tokio::test]
async fn warmup_from_hot_names() {
    let (up, _, n) = switchable(300).await;
    let dir = std::env::temp_dir().join(format!("kuroshio-warm-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("hot-names.json"), r#"["1|hot-a.test","28|hot-b.test","1|hot-c.test"]"#).unwrap();
    let mut c = cfg(&[up], json!({ "resolver": { "warmRate": 50 } }));
    c["system"]["persistDir"] = json!(dir.to_string_lossy());
    c["listen"] = json!({ "plain": { "binds": ["127.0.0.1"], "port": 0 } });
    let started = kuroshio::app::start(&c, kuroshio_config::Tier::Large).await.unwrap();
    tokio::time::sleep(Duration::from_millis(3400)).await;
    assert_eq!(n.load(Ordering::SeqCst), 3, "開機後重新查詢上次最常用的網域");
    // 用戶第一次查就是快取命中
    started.resolver.handle(&q(9, "hot-a.test", 1), &CTX).await.unwrap();
    assert_eq!(started.resolver.stats.summary()["today"]["hit"], 1);
    assert_eq!(n.load(Ordering::SeqCst), 3);
    // 關機時寫出最常用的網域
    started.resolver.handle(&q(9, "hot-a.test", 1), &CTX).await.unwrap();
    started.shutdown();
    let saved: Vec<String> = serde_json::from_slice(&std::fs::read(dir.join("hot-names.json")).unwrap()).unwrap();
    assert_eq!(saved[0], "1|hot-a.test", "{saved:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn parallel_limit_prefers_fastest_upstream() {
    let (slow, n_slow) = upstream(150, answer).await;
    let (fast, n_fast) = upstream(0, answer).await;
    // 只問 1 個；一開始照設定順序問慢的，探索到快的之後就改問快的
    let c = cfg(&[slow, fast], json!({ "resolver": { "parallel": 1 } }));
    let r = kuroshio::app::build_resolver(&c).unwrap();
    for i in 0..25 {
        r.handle(&q(i, &format!("n{i}.test"), 1), &CTX).await.unwrap();
    }
    let (s0, f0) = (n_slow.load(Ordering::SeqCst), n_fast.load(Ordering::SeqCst));
    assert!(f0 >= 1, "探索過快的上游");
    for i in 0..10 {
        r.handle(&q(i, &format!("m{i}.test"), 1), &CTX).await.unwrap();
    }
    assert_eq!(n_slow.load(Ordering::SeqCst), s0, "之後都問平均延遲較低的");
    assert_eq!(n_fast.load(Ordering::SeqCst), f0 + 10);
}

/// 假上游：查詢帶 DO 時多回一筆 RRSIG（類型 46）；答案的類別照查詢的
async fn dnssec_upstream() -> (SocketAddr, Arc<AtomicUsize>) {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    let n = Arc::new(AtomicUsize::new(0));
    let n2 = n.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let (len, peer) = s.recv_from(&mut buf).await.unwrap();
            n2.fetch_add(1, Ordering::SeqCst);
            let q = Message::parse(&buf[..len]).unwrap();
            let qs = q.questions[0].clone();
            let mut r = Message::response_to(&q, 0);
            r.answers.push(Record {
                class: qs.qclass,
                ..a(&qs.name, 300, [192, 0, 2, 7])
            });
            if q.dnssec_ok() {
                r.answers.push(Record {
                    name: qs.name.clone(),
                    rtype: 46,
                    class: qs.qclass,
                    ttl: 300,
                    data: RData::Raw(vec![0, 1, 13, 2, 0, 0, 1, 44, 1, 2, 3, 4]),
                });
            }
            let _ = s.send_to(&r.encode(), peer).await;
        }
    });
    (addr, n)
}

/// 組查詢：可以指定類別、標頭旗標、EDNS（UDP 大小、DO）
fn q_ext(id: u16, name: &str, qclass: u16, flags: u16, edns: Option<(u16, bool)>) -> Vec<u8> {
    let mut m = Message::parse(&q(id, name, 1)).unwrap();
    m.questions[0].qclass = qclass;
    m.flags = flags;
    m.opt = edns.map(|(size, dnssec)| kuroshio_proto::message::Opt {
        udp_size: size,
        flags: if dnssec { kuroshio_proto::message::EDNS_DO } else { 0 },
        ..Default::default()
    });
    m.encode()
}

#[tokio::test]
async fn cache_key_separates_dnssec_ok_checking_disabled_and_class() {
    use kuroshio_proto::message::{FLAG_CD, FLAG_RD};
    let (up, n) = dnssec_upstream().await;
    let r = kuroshio::app::build_resolver(&cfg(&[up], json!({ "resolver": { "fastPath": false } }))).unwrap();
    let ask = |b: Vec<u8>| {
        let r = r.clone();
        async move { Message::parse(&r.handle(&b, &CTX).await.unwrap()).unwrap() }
    };
    // 一般查詢先進快取
    let m = ask(q_ext(1, "signed.test", 1, FLAG_RD, None)).await;
    assert_eq!(m.answers.len(), 1);
    // 要 DNSSEC 記錄的查詢（DO=1）不能拿沒有簽章的快取：重新問上游，拿到 RRSIG
    let m = ask(q_ext(2, "signed.test", 1, FLAG_RD, Some((1232, true)))).await;
    assert_eq!(m.answers.len(), 2, "DO=1 的用戶端要拿到 RRSIG");
    assert_eq!(m.answers[1].rtype, 46);
    assert!(m.dnssec_ok(), "回應的 DO 位元照抄");
    assert_eq!(n.load(Ordering::SeqCst), 2);
    // 兩種各自命中自己的快取：沒有 DO 的不會拿到多餘的簽章
    let m = ask(q_ext(3, "signed.test", 1, FLAG_RD, Some((1232, false)))).await;
    assert_eq!(m.answers.len(), 1);
    let m = ask(q_ext(4, "SIGNED.test", 1, FLAG_RD, Some((1232, true)))).await;
    assert_eq!(m.answers.len(), 2);
    assert_eq!(n.load(Ordering::SeqCst), 2, "各自命中快取");
    // CD=1（不要上游驗證）也是不同的答案
    let m = ask(q_ext(5, "signed.test", 1, FLAG_RD | FLAG_CD, None)).await;
    assert!(m.flags & FLAG_CD != 0, "CD 照抄");
    assert_eq!(n.load(Ordering::SeqCst), 3);
    // 類別不是 IN（例如 CH）：不能跟 IN 的快取混在一起
    let m = ask(q_ext(6, "signed.test", 3, FLAG_RD, None)).await;
    assert_eq!((m.questions[0].qclass, m.answers[0].class), (3, 3));
    assert_eq!(n.load(Ordering::SeqCst), 4);
    let m = ask(q_ext(7, "signed.test", 1, FLAG_RD, None)).await;
    assert_eq!(m.answers[0].class, 1);
    assert_eq!(n.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn cached_reply_echoes_id_flags_question_and_opt() {
    use kuroshio_proto::message::{FLAG_AA, FLAG_AD, FLAG_QR, FLAG_RA, FLAG_RD, FLAG_TC};
    let (up, n) = upstream(0, answer).await;
    let r = kuroshio::app::build_resolver(&cfg(&[up], json!({ "resolver": { "fastPath": false } }))).unwrap();
    r.handle(&q(1, "echo.test", 1), &CTX).await.unwrap();
    // 快取命中、沒有 EDNS、RD=0：id 與問題（含大小寫）照抄，RD 照抄，不能多出 OPT
    let resp = r.handle(&q_ext(0xbeef, "Echo.TEST", 1, 0, None), &CTX).await.unwrap();
    let m = Message::parse(&resp).unwrap();
    assert_eq!(m.id, 0xbeef);
    assert_eq!(m.questions[0].name, "Echo.TEST");
    assert_eq!(m.flags & (FLAG_QR | FLAG_RA), FLAG_QR | FLAG_RA);
    assert_eq!(
        m.flags & (FLAG_RD | FLAG_AA | FLAG_TC | FLAG_AD),
        0,
        "RD 照抄（0），不自稱權威、不設 AD"
    );
    assert!(m.opt.is_none(), "查詢沒有 EDNS，回應不能帶 OPT");
    assert_eq!(kuroshio_proto::header(&resp).unwrap().arcount, 0);
    assert_eq!(m.answers.len(), 1);
    // 有 EDNS、RD=1：回應帶 OPT（版本 0、1232），RD=1
    let m = Message::parse(
        &r.handle(&q_ext(7, "echo.test", 1, FLAG_RD, Some((4096, false))), &CTX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(m.flags & FLAG_RD != 0);
    let opt = m.opt.expect("查詢有 EDNS，回應要帶 OPT");
    assert_eq!((opt.udp_size, opt.version, opt.flags), (1232, 0, 0));
    assert!(opt.options.is_empty(), "新鮮的快取命中不帶 EDE");
    assert_eq!(n.load(Ordering::SeqCst), 1, "以上都是快取命中");
}

#[tokio::test]
async fn non_query_opcode_and_unknown_edns_version() {
    let (up, n) = upstream(0, answer).await;
    let r = kuroshio::app::build_resolver(&cfg(&[up], json!({}))).unwrap();
    // NOTIFY（opcode 4）：回 NOTIMP，opcode 照抄，不轉給上游
    let mut notify = q(9, "zone.test", 6);
    notify[2] = 4 << 3;
    let resp = r.handle(&notify, &CTX).await.unwrap();
    let h = kuroshio_proto::header(&resp).unwrap();
    assert_eq!((h.id, h.rcode, h.opcode, h.qr), (9, kuroshio_proto::RCODE_NOTIMP, 4, true));
    // EDNS 版本 1：回 BADVERS（rcode 16），OPT 帶我們支援的版本 0
    let mut v1 = Message::parse(&q(10, "v1.test", 1)).unwrap();
    v1.opt = Some(kuroshio_proto::message::Opt {
        udp_size: 1232,
        version: 1,
        ..Default::default()
    });
    let m = Message::parse(&r.handle(&v1.encode(), &CTX).await.unwrap()).unwrap();
    assert_eq!(m.rcode, 16);
    assert_eq!(m.opt.unwrap().version, 0);
    assert!(m.answers.is_empty());
    assert_eq!(n.load(Ordering::SeqCst), 0, "都不該問上游");
}
