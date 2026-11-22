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
            bypass: false,
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
    // 要 DNSSEC 記錄的查詢（DO=1）：答案原樣轉交，不合併、不重排（改過的 RRset 簽章驗不過）
    let m = Message::parse(
        &r.handle(
            &q_ext(2, "merge.test", 1, kuroshio_proto::message::FLAG_RD, Some((1232, true))),
            &CTX,
        )
        .await
        .unwrap(),
    )
    .unwrap();
    let ips: Vec<_> = m.answers.iter().map(|a| a.data.clone()).collect();
    assert_eq!(ips, vec![RData::A(Ipv4Addr::new(127, 0, 0, 5))], "最快的上游給的答案，原樣");
    assert!(r.cache.lock().unwrap().peek("1+1d|merge.test").unwrap().ranked.is_none());
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
    // 追蹤結果看路徑檢查的狀態（viaInterceptor）：跟改它的測試輪流跑
    let _path = PATH_STATE.lock().await;
    let (up, _) = upstream(0, answer).await;
    let mut c = cfg(&[up], json!({}));
    c["listen"] = json!({ "plain": { "binds": ["127.0.0.1"], "port": 0 } });
    let started = kuroshio::app::start(&c).await.unwrap();
    let admin = started.admin.unwrap();
    started.resolver.handle(&q(1, "www.example.test", 1), &CTX).await.unwrap();

    let (code, st) = http_get(admin, "/api/status?lite=1", "127.0.0.1:8054").await;
    assert_eq!(code, 200);
    assert_eq!(st["stats"]["today"]["query"], 1);
    assert_eq!(st["cacheEntries"], 1);
    assert!(st["system"].get("tier").is_none(), "沒有硬體等級");
    assert!(st["system"]["memory"]["reserveKB"].as_u64().is_some());
    assert!(st["upstreams"].as_array().unwrap().len() == 1);

    started.resolver.set_filter(Some(Arc::new(Block)));
    let (_, f) = http_get(admin, "/api/filter/check?name=ADS.test&type=A", "localhost").await;
    assert_eq!(f["action"], "block");
    let (_, t) = http_get(admin, "/api/trace?name=www.example.test", "localhost").await;
    assert_eq!(t["upstreams"][0]["answers"][0], "1 www.example.test 300 1.2.3.4");
    // 一般 DNS 沒有被接走：標 false、沒有說明（3.5.0）
    assert_eq!(t["upstreams"][0]["viaInterceptor"], false);
    assert!(t["upstreams"][0].get("note").is_none());
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

    // 一般 DNS 被接走：追蹤結果標出來（回答的其實是攔截者）
    let mut rep = kuroshio_net::path::Report::default();
    rep.plain_v4.udp = true;
    kuroshio_net::path::apply(&rep, false);
    let (_, t) = http_get(admin, "/api/trace?name=www2.example.test", "localhost").await;
    kuroshio_net::path::clear();
    assert_eq!(t["upstreams"][0]["viaInterceptor"], true, "{t}");
    assert!(t["upstreams"][0]["note"].as_str().unwrap().contains("被閘道接走"));

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
    let started = kuroshio::app::start(&c).await.unwrap();
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

/// 3.4.2 Windows 實測：否定答案（NXDOMAIN／NODATA）不等不回應的上游逾時，只再等 collectWindowMs
#[tokio::test]
async fn negative_answer_does_not_wait_for_silent_upstream() {
    let (up, _n) = upstream(0, answer).await;
    // 收得到查詢、永遠不回的上游
    let hole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let silent = hole.local_addr().unwrap();
    let c = cfg(&[up, silent], json!({ "resolver": { "parallel": 0, "timeoutMs": 1500 } }));
    let r = kuroshio::app::build_resolver(&c).unwrap();
    let t0 = std::time::Instant::now();
    let m = Message::parse(&r.handle(&q(1, "nx.test", 1), &CTX).await.unwrap()).unwrap();
    let ms = t0.elapsed().as_millis();
    assert_eq!(m.rcode, 3);
    assert!(ms < 1000, "只等 collectWindowMs（100 ms），不等 1,500 ms 的逾時：{ms} ms");
    drop(hole);
}

/// 兩台都回 NXDOMAIN、第三台不回：不等 collectWindowMs，第二個否定答案到了就回
#[tokio::test]
async fn two_negative_answers_decide_without_waiting() {
    let (a1, _) = upstream(0, answer).await;
    let (a2, _) = upstream(20, answer).await;
    let hole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let silent = hole.local_addr().unwrap();
    let c = cfg(
        &[a1, a2, silent],
        json!({ "resolver": { "parallel": 0, "timeoutMs": 1500, "collectWindowMs": 1000 } }),
    );
    let r = kuroshio::app::build_resolver(&c).unwrap();
    let t0 = std::time::Instant::now();
    let m = Message::parse(&r.handle(&q(1, "nx.test", 1), &CTX).await.unwrap()).unwrap();
    let ms = t0.elapsed().as_millis();
    assert_eq!(m.rcode, 3);
    assert!(ms < 700, "第二個否定答案（20 ms）到了就決定，不等 1,000 ms 的收集時間：{ms} ms");
    drop(hole);
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

/// 3.3.6：下游的路徑檢查用 CHAOS TXT version.kuroshio 認出上游的黑潮；只回答區網的一般 DNS，不轉給上游
#[tokio::test]
async fn answers_version_kuroshio_to_lan_plain_dns_only() {
    let (up, n) = upstream(0, answer).await;
    let r = kuroshio::app::build_resolver(&cfg(&[up], json!({}))).unwrap();
    let query = kuroshio_net::path::build_chaos_txt(9, "version.kuroshio");
    let lan = Ctx {
        proto: "udp",
        client: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
    };
    let m = Message::parse(&r.handle(&query, &lan).await.unwrap()).unwrap();
    assert_eq!(m.rcode, 0);
    let RData::Raw(b) = &m.answers[0].data else {
        panic!("{:?}", m.answers)
    };
    assert_eq!(String::from_utf8_lossy(&b[1..]), format!("kuroshio/{}", env!("CARGO_PKG_VERSION")));
    assert_eq!(m.answers[0].class, 3);
    assert_eq!(n.load(Ordering::SeqCst), 0, "不轉給上游");
    // 公開的 DoH 不回答版本（照一般 CHAOS 查詢處理）
    let public = Ctx {
        proto: "doh",
        client: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
    };
    let m = Message::parse(&r.handle(&query, &public).await.unwrap()).unwrap();
    assert!(m
        .answers
        .iter()
        .all(|a| a.class != 3 || !matches!(&a.data, RData::Raw(b) if b.starts_with(b"\x0ekuroshio/"))));
}

fn chain_answer(name: &str, _t: u16) -> (u16, Vec<Record>, u32) {
    (0, vec![a(name, 300, [198, 51, 100, 10])], 0)
}

/// 路徑檢查的結果是行程層級的狀態（一般 DNS 被接走時，明文上游不當備援）：改它、或依賴它的測試輪流跑
static PATH_STATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// 3.4.0 串接：一般 DNS 被接走時，經由攔截者的答案會被排到後面；串接上游（就是那台上游黑潮）不算，
/// 它的答案不能被排除（固定上游是一般 DNS，路上有攔截者，它的答案才是被排到後面的那一個）
#[tokio::test]
async fn chain_upstream_answers_are_not_demoted() {
    let _path = PATH_STATE.lock().await;
    let (pinned, _) = upstream(0, answer).await;
    let (chain, n_chain) = upstream(40, chain_answer).await;
    let c = cfg(&[pinned], json!({ "resolver": { "fastPath": false } }));
    let r = kuroshio::app::build_resolver(&c).unwrap();
    let spec = format!("udp://{chain}");
    r.upstreams.set_chain(Some(kuroshio::upstream::Upstream::parse(&spec).unwrap()));
    let mut rep = kuroshio_net::path::Report::default();
    rep.plain_v4.udp = true;
    kuroshio_net::path::apply(&rep, false);
    let m = Message::parse(&r.handle(&q(1, "chain-decide.test", 1), &CTX).await.unwrap()).unwrap();
    kuroshio_net::path::clear();
    assert_eq!(n_chain.load(Ordering::SeqCst), 1);
    assert_eq!(m.answers[0].data, RData::A(Ipv4Addr::new(198, 51, 100, 10)), "{:?}", m.answers);
    assert_eq!(r.upstreams.list_json()[0]["role"], "chain");
}

// ---------------------------------------------------------------- 3.4.0 背景補問（規格 10 第 5.2 節）

/// 背景補問用的假上游：固定回一個位址（`None` = NXDOMAIN），記錄收到幾筆、同時處理中最多幾筆
struct Bf {
    addr: SocketAddr,
    n: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
}

impl Bf {
    fn n(&self) -> usize {
        self.n.load(Ordering::SeqCst)
    }
}

async fn bf_upstream(delay_ms: u64, ip: Option<[u8; 4]>) -> Bf {
    let s = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = s.local_addr().unwrap();
    let (n, peak, cur) = (
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicUsize::new(0)),
    );
    let (n2, peak2) = (n.clone(), peak.clone());
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let (len, from) = s.recv_from(&mut buf).await.unwrap();
            n2.fetch_add(1, Ordering::SeqCst);
            let now = cur.fetch_add(1, Ordering::SeqCst) + 1;
            peak2.fetch_max(now, Ordering::SeqCst);
            let q = Message::parse(&buf[..len]).unwrap();
            let mut r = Message::response_to(&q, if ip.is_some() { 0 } else { 3 });
            r.opt = None;
            if let Some(ip) = ip {
                r.answers = vec![a(&q.questions[0].name, 300, ip)];
            }
            let (s, cur) = (s.clone(), cur.clone());
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                let _ = s.send_to(&r.encode(), from).await;
                cur.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    Bf { addr, n, peak }
}

/// 假的 CDN：`range` 裡的位址被認得（算 Fastly 的範圍：IP 置換型、但用最近節點，固定上游給的位址照樣當快速回應）；
/// 背景工作只記錄、不執行
fn fake_cdn(r: &kuroshio::resolver::Resolver, c: &serde_json::Value, tag: &str, range: &str, probe: [u8; 4]) {
    let dir = std::env::temp_dir().join(format!("kuroshio-bf-{tag}-{}", std::process::id()));
    let net: Arc<dyn kuroshio_cdn::Net> = Arc::new(kuroshio_cdn::RealNet::new(r.iprank.clone()));
    let cdn = kuroshio_cdn::Cdn::load(c, kuroshio_cdn::Paths::new(dir.join("state"), dir.join("data")), net);
    cdn.record_tasks();
    cdn.with_state(|st| st.pools.p.get_mut("fastly").expect("fastly").range4 = kuroshio_cdn::pools::cidr(&[range]));
    assert!(cdn.classify(IpAddr::from(probe)).is_some(), "假的 CDN 要認得 {probe:?}");
    r.set_cdn(Some(cdn));
}

fn today(r: &kuroshio::resolver::Resolver, k: &str) -> u64 {
    r.stats.summary()["today"][k].as_u64().unwrap()
}

/// 等到條件成立（最多 3 秒）
async fn until(what: &str, mut f: impl FnMut() -> bool) {
    let t0 = std::time::Instant::now();
    while !f() {
        assert!(t0.elapsed() < Duration::from_secs(3), "等不到：{what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn parallel_two_backfills_cdn_names() {
    // 測速埠：所有 127.0.0.x 都連得上（合併後的位址都留著）
    let l = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let _ = l.accept().await;
        }
    });
    let f1 = bf_upstream(0, Some([127, 0, 0, 4])).await;
    let f2 = bf_upstream(0, Some([127, 0, 0, 5])).await;
    let b1 = bf_upstream(400, Some([127, 0, 0, 6])).await;
    let b2 = bf_upstream(400, Some([127, 0, 0, 7])).await;
    let c = cfg(
        &[f1.addr, f2.addr, b1.addr, b2.addr],
        json!({ "resolver": { "parallel": 2, "rankIps": true }, "iprank": { "port": port, "timeoutMs": 300 } }),
    );
    let r = kuroshio::app::build_resolver(&c).unwrap();
    fake_cdn(&r, &c, "cdn", "127.0.0.0/24", [127, 0, 0, 4]);
    let t0 = std::time::Instant::now();
    let m = Message::parse(&r.handle(&q(1, "cdn-bf.example.com", 1), &CTX).await.unwrap()).unwrap();
    assert!(
        t0.elapsed() < Duration::from_millis(400),
        "前 2 個回答就回用戶端，不等補問：{:?}",
        t0.elapsed()
    );
    assert_eq!(m.rcode, 0);
    assert!(!m.answers.is_empty());
    until("後段上游各收到 1 筆補問", || b1.n() == 1 && b2.n() == 1).await;
    let has = |ip: [u8; 4]| {
        r.cache
            .lock()
            .unwrap()
            .peek("1|cdn-bf.example.com")
            .is_some_and(|e| e.answers.iter().any(|x| x.data == RData::A(Ipv4Addr::from(ip))))
    };
    until("快取換成合併後的答案（含後段上游的位址）", || {
        has([127, 0, 0, 6]) && has([127, 0, 0, 7])
    })
    .await;
    assert!(has([127, 0, 0, 4]) && has([127, 0, 0, 5]), "前面的位址也還在");
    assert_eq!((f1.n(), f2.n(), b1.n(), b2.n()), (1, 1, 1, 1));
    assert_eq!(today(&r, "backfill"), 1);
    assert_eq!(today(&r, "backfillMismatch"), 0);
}

#[tokio::test]
async fn non_cdn_names_sampled() {
    let f1 = bf_upstream(0, Some([198, 51, 100, 1])).await;
    let f2 = bf_upstream(0, Some([198, 51, 100, 1])).await;
    let b1 = bf_upstream(100, Some([198, 51, 100, 1])).await;
    let b2 = bf_upstream(100, Some([198, 51, 100, 1])).await;
    let c = cfg(
        &[f1.addr, f2.addr, b1.addr, b2.addr],
        json!({ "resolver": { "parallel": 2, "backfillSample": 4 } }),
    );
    let r = kuroshio::app::build_resolver(&c).unwrap();
    // 先讓每個上游都有延遲紀錄（還沒有紀錄的上游會排到前面被問），之後固定先問快的兩個
    for i in 0..2 {
        r.handle(&q(i, &format!("warm{i}.example.com"), 1), &CTX).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (n1, n2) = (b1.n(), b2.n());
    for i in 0..16 {
        r.handle(&q(i, &format!("s{i}.example.com"), 1), &CTX).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(b1.n() - n1, 4, "16 個非 CDN 名稱，每 4 個抽 1 個補問");
    assert_eq!(b2.n() - n2, 4);
}

#[tokio::test]
async fn backfill_off_matches_3_3_7() {
    let f1 = bf_upstream(0, Some([198, 51, 100, 1])).await;
    let f2 = bf_upstream(0, Some([198, 51, 100, 2])).await;
    let b1 = bf_upstream(0, Some([198, 51, 100, 3])).await;
    let b2 = bf_upstream(0, Some([198, 51, 100, 4])).await;
    let c = cfg(
        &[f1.addr, f2.addr, b1.addr, b2.addr],
        json!({ "resolver": { "parallel": 2, "backfill": "off", "backfillSample": 1 } }),
    );
    let r = kuroshio::app::build_resolver(&c).unwrap();
    // CDN 相關、而且每次都抽樣：關掉時一樣不補問
    fake_cdn(&r, &c, "off", "198.51.100.0/24", [198, 51, 100, 1]);
    let m = Message::parse(&r.handle(&q(1, "off.example.com", 1), &CTX).await.unwrap()).unwrap();
    assert_eq!((m.rcode, m.answers.len()), (0, 1));
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!((f1.n(), f2.n()), (1, 1));
    assert_eq!((b1.n(), b2.n()), (0, 0), "後段上游完全沒有收到查詢");
    assert_eq!(today(&r, "backfill"), 0);
}

/// 抽樣比對：前面的上游給了位址，補問的上游多數說這個名稱不存在 → 記一筆不一致，
/// 快取換成合併後 `decide()` 的結果（有正常回應就用正常回應，之後的查詢照樣拿到位址）。
///
/// 反方向（前面只有 NXDOMAIN、補問的多數有位址）在 `ask()` 裡實際上碰不到：第一輪收到不正常的回應
/// 就會立刻加問下一個上游，所以第一輪沒有正常回應時通常已經問完所有上游、沒有可以補問的；
/// 那個方向的判斷由 `resolver.rs` 的單元測試 `backfill_mismatch_rules` 驗證
#[tokio::test]
async fn backfill_mismatch_fixes_cache() {
    let f1 = bf_upstream(0, Some([203, 0, 113, 9])).await;
    let f2 = bf_upstream(0, Some([203, 0, 113, 9])).await;
    let b1 = bf_upstream(0, None).await;
    let b2 = bf_upstream(0, None).await;
    let b3 = bf_upstream(0, None).await;
    let c = cfg(
        &[f1.addr, f2.addr, b1.addr, b2.addr, b3.addr],
        json!({ "resolver": { "parallel": 2, "backfillSample": 1 } }),
    );
    let r = kuroshio::app::build_resolver(&c).unwrap();
    let m = Message::parse(&r.handle(&q(1, "mm.example.com", 1), &CTX).await.unwrap()).unwrap();
    assert_eq!(m.answers[0].data, RData::A(Ipv4Addr::new(203, 0, 113, 9)));
    until("記一筆不一致", || today(&r, "backfillMismatch") == 1).await;
    assert_eq!((b1.n(), b2.n(), b3.n()), (1, 1, 1));
    until("快取換成合併後的", || {
        r.cache
            .lock()
            .unwrap()
            .peek("1|mm.example.com")
            .is_some_and(|e| !e.fast && e.class == kuroshio_proto::logic::Class::Ok)
    })
    .await;
    let m = Message::parse(&r.handle(&q(2, "mm.example.com", 1), &CTX).await.unwrap()).unwrap();
    assert_eq!(m.answers[0].data, RData::A(Ipv4Addr::new(203, 0, 113, 9)), "之後的查詢拿到位址");
    assert_eq!(today(&r, "backfill"), 1, "快取命中不補問");
}

#[tokio::test]
async fn backfill_respects_concurrency_cap() {
    let f1 = bf_upstream(0, Some([198, 51, 100, 1])).await;
    let f2 = bf_upstream(0, Some([198, 51, 100, 2])).await;
    // 平均延遲在中間的上游：每 20 次的「探索」會換它到前面，後段兩個上游只會收到補問
    let x = bf_upstream(100, Some([198, 51, 100, 3])).await;
    let b1 = bf_upstream(500, Some([198, 51, 100, 4])).await;
    let b2 = bf_upstream(500, Some([198, 51, 100, 5])).await;
    let c = cfg(
        &[f1.addr, f2.addr, x.addr, b1.addr, b2.addr],
        json!({ "resolver": { "parallel": 2, "collectWindowMs": 1000 } }),
    );
    let r = kuroshio::app::build_resolver(&c).unwrap();
    fake_cdn(&r, &c, "cap", "198.51.100.0/24", [198, 51, 100, 1]);
    let max = r.params.backfill_max;
    // 先讓每個上游都有延遲紀錄
    r.handle(&q(1, "warm.example.com", 1), &CTX).await.unwrap();
    until("暖身的補問問到後段", || b1.n() == 1 && b2.n() == 1).await;
    tokio::time::sleep(Duration::from_millis(700)).await;
    let done = today(&r, "backfill");
    b1.peak.store(0, Ordering::SeqCst);
    b2.peak.store(0, Ordering::SeqCst);
    let mut set = tokio::task::JoinSet::new();
    for i in 0..20u16 {
        let r = r.clone();
        set.spawn(async move { r.handle(&q(i, &format!("cap{i}.example.com"), 1), &CTX).await.unwrap() });
    }
    while let Some(x) = set.join_next().await {
        assert_eq!(Message::parse(&x.unwrap()).unwrap().rcode, 0);
    }
    tokio::time::sleep(Duration::from_millis(900)).await;
    let (p1, p2) = (b1.peak.load(Ordering::SeqCst), b2.peak.load(Ordering::SeqCst));
    assert!(p1 >= 1 && p1 <= max && p2 <= max, "同時進行的補問 {p1}/{p2}，上限 {max}");
    let started = today(&r, "backfill") - done;
    assert!((1..20).contains(&started), "拿不到名額就放棄、不排隊：{started}");
    assert_eq!(b1.n() - 1, started as usize, "每個補問問後段上游一次");
}

#[tokio::test]
async fn backfill_skips_verbatim() {
    let f1 = bf_upstream(0, Some([198, 51, 100, 1])).await;
    let f2 = bf_upstream(0, Some([198, 51, 100, 2])).await;
    let b1 = bf_upstream(50, Some([198, 51, 100, 3])).await;
    let b2 = bf_upstream(50, Some([198, 51, 100, 4])).await;
    let c = cfg(
        &[f1.addr, f2.addr, b1.addr, b2.addr],
        json!({ "resolver": { "parallel": 2, "backfillSample": 1 } }),
    );
    let r = kuroshio::app::build_resolver(&c).unwrap();
    // 對照：一般查詢每次都補問
    r.handle(&q(1, "ctl.example.com", 1), &CTX).await.unwrap();
    until("一般查詢補問", || b1.n() == 1 && b2.n() == 1).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    // 帶 DO：答案原樣轉交，不補問
    let do_q = q_ext(2, "do.example.com", 1, kuroshio_proto::message::FLAG_RD, Some((1232, true)));
    let m = Message::parse(&r.handle(&do_q, &CTX).await.unwrap()).unwrap();
    assert_eq!(m.rcode, 0);
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!((b1.n(), b2.n()), (1, 1), "帶 DO 的查詢不補問");
    assert_eq!(today(&r, "backfill"), 1);
}

/// 串接中：只問上游黑潮（固定上游照舊排在後面），不在背景補問其他上游
#[tokio::test]
async fn backfill_skipped_while_chained() {
    let pinned = bf_upstream(0, Some([198, 51, 100, 1])).await;
    let chain = bf_upstream(0, Some([198, 51, 100, 10])).await;
    let c = cfg(&[pinned.addr], json!({ "resolver": { "parallel": 1, "backfillSample": 1 } }));
    let r = kuroshio::app::build_resolver(&c).unwrap();
    let spec = format!("udp://{}", chain.addr);
    r.upstreams.set_chain(Some(kuroshio::upstream::Upstream::parse(&spec).unwrap()));
    let m = Message::parse(&r.handle(&q(1, "chained.example.com", 1), &CTX).await.unwrap()).unwrap();
    assert_eq!(m.answers[0].data, RData::A(Ipv4Addr::new(198, 51, 100, 10)));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!((chain.n(), pinned.n()), (1, 0));
    assert_eq!(today(&r, "backfill"), 0);
}

// ---------------------------------------------------------------- 3.4.1 串接時下游不重做 CDN 與 IP 測速

/// 測速埠：記錄有幾個連線進來（IP 測速用 TCP 連線）
async fn probe_port() -> (u16, Arc<AtomicUsize>) {
    let l = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let n = Arc::new(AtomicUsize::new(0));
    let n2 = n.clone();
    tokio::spawn(async move {
        loop {
            if l.accept().await.is_ok() {
                n2.fetch_add(1, Ordering::SeqCst);
            }
        }
    });
    (port, n)
}

fn two_cdn_ips(name: &str, _t: u16) -> (u16, Vec<Record>, u32) {
    (0, vec![a(name, 300, [127, 0, 0, 8]), a(name, 300, [127, 0, 0, 9])], 0)
}

fn recording_cdn(r: &kuroshio::resolver::Resolver, c: &serde_json::Value, tag: &str) -> Arc<kuroshio_cdn::Cdn> {
    let dir = std::env::temp_dir().join(format!("kuroshio-ch-{tag}-{}", std::process::id()));
    let net: Arc<dyn kuroshio_cdn::Net> = Arc::new(kuroshio_cdn::RealNet::new(r.iprank.clone()));
    let cdn = kuroshio_cdn::Cdn::load(c, kuroshio_cdn::Paths::new(dir.join("state"), dir.join("data")), net);
    cdn.record_tasks();
    cdn.with_state(|st| st.pools.p.get_mut("fastly").expect("fastly").range4 = kuroshio_cdn::pools::cidr(&["127.0.0.0/24"]));
    r.set_cdn(Some(cdn.clone()));
    cdn
}

/// 答案來自串接上游（上游黑潮已經換好 CDN 節點、測速排序）：下游不再做 TCP 443 測速、
/// 不排 CDN 背景工作、CDN 資料庫不記這個網域；只統計是哪家 CDN。
/// 同樣的答案從一般上游來時照舊測速（確認這個測試抓得到差別）
#[tokio::test]
async fn chained_answers_skip_cdn_and_ranking() {
    let (port, probes) = probe_port().await;
    let extra = json!({ "resolver": { "rankIps": true, "fastPath": false }, "iprank": { "port": port, "timeoutMs": 300 } });

    // 一般上游：會測速
    let (plain, _) = upstream(0, two_cdn_ips).await;
    let c = cfg(&[plain], extra.clone());
    let r = kuroshio::app::build_resolver(&c).unwrap();
    let _cdn = recording_cdn(&r, &c, "plain");
    r.handle(&q(1, "cdn-plain.example.com", 1), &CTX).await.unwrap();
    assert!(probes.load(Ordering::SeqCst) > 0, "一般上游給兩個位址：照舊測速");

    // 串接上游：不測速、不排背景工作
    let (chain, n_chain) = upstream(0, two_cdn_ips).await;
    let mut c = cfg(&[], extra);
    // 備援（自己的上游的替身）：串接上游正常時不會被問
    let (own, n_own) = upstream(0, two_cdn_ips).await;
    kuroshio_config::merge(&mut c, &json!({ "upstream": { "fallback": [format!("udp://{own}")] } }));
    let r = kuroshio::app::build_resolver(&c).unwrap();
    r.upstreams
        .set_chain(Some(kuroshio::upstream::Upstream::parse(&format!("udp://{chain}")).unwrap()));
    let cdn = recording_cdn(&r, &c, "chain");
    let before = probes.load(Ordering::SeqCst);
    for i in 0..3 {
        let m = Message::parse(&r.handle(&q(i, "cdn-chain.example.com", 1), &CTX).await.unwrap()).unwrap();
        assert_eq!(m.answers.len(), 2, "上游給的兩個位址原樣回給用戶端");
        assert!(m.answers.iter().all(|x| x.ttl > 10), "不套用 CDN 試用期的短 TTL：{:?}", m.answers);
    }
    assert_eq!(n_chain.load(Ordering::SeqCst), 1, "第二次起是快取");
    assert_eq!(n_own.load(Ordering::SeqCst), 0, "串接上游正常：不問自己的上游");
    assert_eq!(probes.load(Ordering::SeqCst), before, "串接上游的答案不再測速");
    assert!(cdn.take_tasks().is_empty(), "不排 CDN 背景工作");
    assert!(cdn.state().db.get("cdn-chain.example.com").is_none(), "CDN 資料庫不記這個網域");
    assert_eq!(r.stats.summary()["today"]["cdn"]["fastly"], 3, "還是統計是哪家 CDN");
}

// ---------------------------------------------------------------- 串接上游的 SERVFAIL／擋掉：下游自己再解析一次（3.4.3）

fn servfail(_name: &str, _t: u16) -> (u16, Vec<Record>, u32) {
    (2, vec![], 0)
}

fn sinkhole(name: &str, _t: u16) -> (u16, Vec<Record>, u32) {
    (0, vec![a(name, 300, [0, 0, 0, 0])], 0)
}

/// 串接上游（上游黑潮）解析不到（SERVFAIL）：下游改問自己的上游（3.4.3；上游黑潮自己的上游壞了、心跳卻正常時，
/// 以前下游每一筆都 SERVFAIL），不算串接失敗；自己的上游也解析不到才照上游的 SERVFAIL。
/// 上游擋掉的（0.0.0.0）：下游的過濾沒擋，就用自己的上游解析一次（下游自己決定），一樣不算串接失敗；
/// 自己的上游也沒有答案才照上游的擋
#[tokio::test]
async fn chain_servfail_and_blocked_fall_back_to_own() {
    // 備援用的是明文上游：一般 DNS 沒有被接走時才會當備援（被接走時只用自己的加密上游繞過）
    let _path = PATH_STATE.lock().await;
    // 上游黑潮 SERVFAIL：改問自己的上游
    let (chain, n_chain) = upstream(0, servfail).await;
    let (own, n_own) = upstream(0, answer_ok_ip).await;
    let mut c = cfg(&[], json!({}));
    kuroshio_config::merge(&mut c, &json!({ "upstream": { "fallback": [format!("udp://{own}")] } }));
    let r = kuroshio::app::build_resolver(&c).unwrap();
    r.upstreams
        .set_chain(Some(kuroshio::upstream::Upstream::parse(&format!("udp://{chain}")).unwrap()));
    for i in 0..5u16 {
        let m = Message::parse(&r.handle(&q(i, &format!("servfail{i}.example.com"), 1), &CTX).await.unwrap()).unwrap();
        assert_eq!(
            m.answers[0].data,
            RData::A(Ipv4Addr::new(198, 51, 100, 77)),
            "上游黑潮解析不到：改用自己的上游"
        );
    }
    assert_eq!(n_chain.load(Ordering::SeqCst), 5);
    assert_eq!(n_own.load(Ordering::SeqCst), 5);
    assert!(!r.upstreams.chain_suspended(), "SERVFAIL 不算串接失敗");
    assert_eq!(r.stats.summary()["today"]["chainRetry"], 5);
    // 自己的上游也解析不到：照上游黑潮的 SERVFAIL
    let (chain, _) = upstream(0, servfail).await;
    let (own, _) = upstream(0, servfail).await;
    let mut c = cfg(&[], json!({}));
    kuroshio_config::merge(&mut c, &json!({ "upstream": { "fallback": [format!("udp://{own}")] } }));
    let r = kuroshio::app::build_resolver(&c).unwrap();
    r.upstreams
        .set_chain(Some(kuroshio::upstream::Upstream::parse(&format!("udp://{chain}")).unwrap()));
    let m = Message::parse(&r.handle(&q(1, "nowhere.example.com", 1), &CTX).await.unwrap()).unwrap();
    assert_eq!(m.rcode, 2, "兩邊都解析不到：SERVFAIL");

    // 上游黑潮擋掉、下游的過濾沒擋：用自己的加密上游解析一次（下游自己決定），不算串接失敗
    let (chain, n_chain) = upstream(0, sinkhole).await;
    let (own, n_own) = upstream(0, answer_ok_ip).await;
    let mut c = cfg(&[], json!({}));
    kuroshio_config::merge(&mut c, &json!({ "upstream": { "fallback": [format!("udp://{own}")] } }));
    let r = kuroshio::app::build_resolver(&c).unwrap();
    r.upstreams
        .set_chain(Some(kuroshio::upstream::Upstream::parse(&format!("udp://{chain}")).unwrap()));
    for i in 0..5u16 {
        let m = Message::parse(&r.handle(&q(i, &format!("blocked{i}.example.com"), 1), &CTX).await.unwrap()).unwrap();
        assert_eq!(m.answers[0].data, RData::A(Ipv4Addr::new(198, 51, 100, 77)), "改用自己的上游");
    }
    // 同一個網域再問：快取命中，不再問任何上游（不會每次都繞一圈）
    let m = Message::parse(&r.handle(&q(9, "blocked0.example.com", 1), &CTX).await.unwrap()).unwrap();
    assert_eq!(m.answers[0].data, RData::A(Ipv4Addr::new(198, 51, 100, 77)));
    assert_eq!(n_chain.load(Ordering::SeqCst), 5);
    assert_eq!(n_own.load(Ordering::SeqCst), 5);
    assert!(!r.upstreams.chain_suspended(), "上游擋掉不算串接失敗");
    assert_eq!(r.upstreams.active()[0].role, kuroshio::upstreams::Role::Chain);
    assert_eq!(r.stats.summary()["today"]["chainBypass"], 5, "狀態頁看得到次數；快取命中不算");

    // 自己的上游也沒有答案（失敗）：照上游黑潮的擋
    let (chain, _) = upstream(0, sinkhole).await;
    let (own, _) = upstream(0, servfail).await;
    let mut c = cfg(&[], json!({}));
    kuroshio_config::merge(&mut c, &json!({ "upstream": { "fallback": [format!("udp://{own}")] } }));
    let r = kuroshio::app::build_resolver(&c).unwrap();
    r.upstreams
        .set_chain(Some(kuroshio::upstream::Upstream::parse(&format!("udp://{chain}")).unwrap()));
    let m = Message::parse(&r.handle(&q(1, "both.example.com", 1), &CTX).await.unwrap()).unwrap();
    assert_eq!(m.answers[0].data, RData::A(Ipv4Addr::new(0, 0, 0, 0)), "自己的上游失敗：照上游的擋");
    assert_eq!(r.stats.summary()["today"]["chainBypass"], 0, "沒有繞過成功：不算");
}

fn answer_ok_ip(name: &str, _t: u16) -> (u16, Vec<Record>, u32) {
    (0, vec![a(name, 300, [198, 51, 100, 77])], 0)
}

/// 串接上游沒有回應（逾時；等兩倍的 timeoutMs 再加 1 秒）：這一筆照舊改問自己的上游，連續 3 次才暫停串接
#[tokio::test]
async fn chain_timeout_still_falls_back() {
    let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap(); // 收了不回
    let chain = dead.local_addr().unwrap();
    let (own, n_own) = upstream(0, answer_ok_ip).await;
    let mut c = cfg(&[], json!({ "resolver": { "timeoutMs": 200 } }));
    kuroshio_config::merge(&mut c, &json!({ "upstream": { "fallback": [format!("udp://{own}")] } }));
    let r = kuroshio::app::build_resolver(&c).unwrap();
    r.upstreams
        .set_chain(Some(kuroshio::upstream::Upstream::parse(&format!("udp://{chain}")).unwrap()));
    let m = Message::parse(&r.handle(&q(1, "dead-chain.example.com", 1), &CTX).await.unwrap()).unwrap();
    assert_eq!(m.answers[0].data, RData::A(Ipv4Addr::new(198, 51, 100, 77)));
    assert_eq!(n_own.load(Ordering::SeqCst), 1);
    drop(dead);
}

/// 3.4.4（3.4.3 複驗 G6）：上游黑潮 SERVFAIL、改問自己的上游時，自己的上游沒回應先不算失敗（多半是網域壞了）；
/// 同一輪有別的上游正常回答時才算
#[tokio::test]
async fn chain_servfail_retry_does_not_count_silent_own() {
    let _path = PATH_STATE.lock().await;
    let fail_of = |r: &kuroshio::resolver::Resolver, id: &str| -> u64 {
        r.upstreams.list_json().as_array().unwrap().iter().find(|u| u["id"] == id).unwrap()["fail"]
            .as_u64()
            .unwrap()
    };
    let (chain, _) = upstream(0, servfail).await;
    let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap(); // 收了不回
    let silent = dead.local_addr().unwrap();
    let mut c = cfg(&[], json!({ "resolver": { "timeoutMs": 200 } }));
    kuroshio_config::merge(&mut c, &json!({ "upstream": { "fallback": [format!("udp://{silent}")] } }));
    let r = kuroshio::app::build_resolver(&c).unwrap();
    r.upstreams
        .set_chain(Some(kuroshio::upstream::Upstream::parse(&format!("udp://{chain}")).unwrap()));
    for i in 0..6u16 {
        let m = Message::parse(&r.handle(&q(i, &format!("broken{i}.example.com"), 1), &CTX).await.unwrap()).unwrap();
        assert_eq!(m.rcode, 2);
    }
    assert_eq!(fail_of(&r, &format!("udp://{silent}")), 0, "大家都解析不到：自己的上游不算失敗");
    // 另一台自己的上游正常回答：沒回應的那台照算失敗
    let (ok, _) = upstream(0, answer_ok_ip).await;
    let mut c = cfg(
        &[],
        json!({ "resolver": { "timeoutMs": 200, "parallel": 0, "collectWindowMs": 600 } }),
    );
    kuroshio_config::merge(
        &mut c,
        &json!({ "upstream": { "fallback": [format!("udp://{silent}"), format!("udp://{ok}")] } }),
    );
    let r = kuroshio::app::build_resolver(&c).unwrap();
    r.upstreams
        .set_chain(Some(kuroshio::upstream::Upstream::parse(&format!("udp://{chain}")).unwrap()));
    let m = Message::parse(&r.handle(&q(9, "mixed.example.com", 1), &CTX).await.unwrap()).unwrap();
    assert_eq!(m.answers[0].data, RData::A(Ipv4Addr::new(198, 51, 100, 77)));
    assert_eq!(fail_of(&r, &format!("udp://{silent}")), 1, "別台有答案：沒回應的算失敗");
    drop(dead);
}

fn nodata(_name: &str, _t: u16) -> (u16, Vec<Record>, u32) {
    (0, vec![], 300)
}

/// 3.4.4（3.4.3 複驗 G7）：上游黑潮 SERVFAIL、改問自己的上游時，只有一台回否定答案（其他沒回應）不採用，照上游的 SERVFAIL；
/// 兩台都回同樣的否定答案才採用。自己的上游只有一台時照用它的答案
#[tokio::test]
async fn chain_servfail_retry_needs_two_negatives() {
    let _path = PATH_STATE.lock().await;
    let (chain, _) = upstream(0, servfail).await;
    let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap(); // 收了不回
    let silent = dead.local_addr().unwrap();
    let (empty, _) = upstream(0, nodata).await;
    let (empty2, _) = upstream(0, nodata).await;
    let build = |own: Vec<String>| {
        let mut c = cfg(
            &[],
            json!({ "resolver": { "timeoutMs": 200, "parallel": 0, "collectWindowMs": 300 } }),
        );
        kuroshio_config::merge(&mut c, &json!({ "upstream": { "fallback": own } }));
        let r = kuroshio::app::build_resolver(&c).unwrap();
        r.upstreams
            .set_chain(Some(kuroshio::upstream::Upstream::parse(&format!("udp://{chain}")).unwrap()));
        r
    };
    // 一台空答案、一台沒回應：照上游的 SERVFAIL
    let r = build(vec![format!("udp://{silent}"), format!("udp://{empty}")]);
    let m = Message::parse(&r.handle(&q(1, "lone.example.com", 1), &CTX).await.unwrap()).unwrap();
    assert_eq!(m.rcode, 2, "只有一台的空答案：不採用");
    // 兩台都回空答案：採用
    let r = build(vec![format!("udp://{empty}"), format!("udp://{empty2}")]);
    let m = Message::parse(&r.handle(&q(2, "agreed.example.com", 1), &CTX).await.unwrap()).unwrap();
    assert_eq!(m.rcode, 0, "兩台一致：採用");
    assert!(m.answers.is_empty());
    // 自己的上游只有一台：照用它的答案（沒有別台可以比）
    let r = build(vec![format!("udp://{empty}")]);
    let m = Message::parse(&r.handle(&q(3, "single.example.com", 1), &CTX).await.unwrap()).unwrap();
    assert_eq!(m.rcode, 0);
    drop(dead);
}

/// 3.4.2：SERVFAIL 只在同一筆有別的上游正常回答時才算那台失敗（大家都解析不到是網域的問題）
#[tokio::test]
async fn servfail_counts_only_when_others_answer() {
    let fail_of = |r: &kuroshio::resolver::Resolver, id: &str| -> u64 {
        r.upstreams.list_json().as_array().unwrap().iter().find(|u| u["id"] == id).unwrap()["fail"]
            .as_u64()
            .unwrap()
    };
    let (a, _) = upstream(0, servfail).await;
    let (b, _) = upstream(0, servfail).await;
    let c = cfg(&[a, b], json!({ "resolver": { "parallel": 0 } }));
    let r = kuroshio::app::build_resolver(&c).unwrap();
    for i in 0..4u16 {
        r.handle(&q(i, &format!("broken{i}.example.com"), 1), &CTX).await.unwrap();
    }
    let (ida, idb) = (format!("udp://{a}"), format!("udp://{b}"));
    assert_eq!((fail_of(&r, &ida), fail_of(&r, &idb)), (0, 0), "兩台都 SERVFAIL：不算失敗");
    // 一台正常、一台 SERVFAIL：SERVFAIL 的那台算失敗
    let (ok, _) = upstream(0, answer_ok_ip).await;
    let c = cfg(&[ok, a], json!({ "resolver": { "parallel": 0, "collectWindowMs": 300 } }));
    let r = kuroshio::app::build_resolver(&c).unwrap();
    r.handle(&q(9, "mixed.example.com", 1), &CTX).await.unwrap();
    assert_eq!(fail_of(&r, &ida), 1);
    assert_eq!(fail_of(&r, &format!("udp://{ok}")), 0);
}

/// 上游黑潮擋掉非 A／AAAA 的查詢：回空答案＋EDE 17（被過濾）。下游當成「上游擋」，自己的過濾沒擋就用自己的上游解析（3.4.3）
#[tokio::test]
async fn chain_ede_blocked_falls_back_to_own() {
    let _path = PATH_STATE.lock().await;
    // 自己組回應：NOERROR、沒有答案、OPT 裡帶 EDE 17
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let chain = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else { break };
            let Ok(qm) = Message::parse(&buf[..n]) else { continue };
            let mut r = Message::response_to(&qm, 0);
            if r.opt.is_none() {
                r.opt = Some(kuroshio_proto::message::Opt::default());
            }
            kuroshio_proto::logic::add_ede(&mut r, kuroshio_proto::logic::ede::FILTERED, "x");
            let _ = sock.send_to(&r.encode(), peer).await;
        }
    });
    let (own, n_own) = upstream(0, answer_txt).await;
    let mut c = cfg(&[], json!({}));
    kuroshio_config::merge(&mut c, &json!({ "upstream": { "fallback": [format!("udp://{own}")] } }));
    let r = kuroshio::app::build_resolver(&c).unwrap();
    r.upstreams
        .set_chain(Some(kuroshio::upstream::Upstream::parse(&format!("udp://{chain}")).unwrap()));
    let m = Message::parse(&r.handle(&q(1, "txt.example.com", 16), &CTX).await.unwrap()).unwrap();
    assert!(!m.answers.is_empty(), "上游擋掉的 TXT：改用自己的上游");
    assert_eq!(n_own.load(Ordering::SeqCst), 1);
    assert_eq!(r.stats.summary()["today"]["chainBypass"], 1);
}

fn answer_txt(name: &str, _t: u16) -> (u16, Vec<Record>, u32) {
    (
        0,
        vec![Record {
            name: name.to_string(),
            rtype: 16,
            class: 1,
            ttl: 300,
            data: RData::Raw(vec![2, b'o', b'k']),
        }],
        0,
    )
}
