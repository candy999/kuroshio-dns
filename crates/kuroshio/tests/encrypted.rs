//! DoT / DoH 伺服器：自簽憑證、實際查詢、GET / POST、純 HTTP（反向代理）、憑證熱更新

use kuroshio::upstream::Upstream;
use kuroshio_proto::message::{Message, RData, Record};
use rustls::pki_types::CertificateDer;
use serde_json::json;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

async fn upstream() -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let (len, peer) = s.recv_from(&mut buf).await.unwrap();
            let q = Message::parse(&buf[..len]).unwrap();
            let mut r = Message::response_to(&q, 0);
            r.opt = None;
            r.answers.push(Record::a(&q.questions[0].name, 120, Ipv4Addr::new(9, 8, 7, 6)));
            let _ = s.send_to(&r.encode(), peer).await;
        }
    });
    addr
}

fn write_cert(dir: &std::path::Path) -> CertificateDer<'static> {
    let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into(), "localhost".into()]).unwrap();
    std::fs::write(dir.join("cert.pem"), ck.cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), ck.key_pair.serialize_pem()).unwrap();
    CertificateDer::from(ck.cert.der().to_vec())
}

fn q(id: u16, name: &str) -> Vec<u8> {
    kuroshio_proto::build_query(id, name, 1)
}

/// 會建立 QUIC 上游連線的測試排隊（`perf.tls.quic.open` 是整個行程共用的計數）
static QUIC_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn dot_and_doh_serve_queries() {
    let _quic = QUIC_TESTS.lock().await;
    let dir = std::env::temp_dir().join(format!("kuroshio-enc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("state")).unwrap();
    let der = write_cert(&dir);
    kuroshio::tls::add_root(der);
    let up = upstream().await;
    let cfg = kuroshio_config::with_overrides(&json!({
        "system": { "persistDir": dir.join("state").to_string_lossy() },
        "admin": { "port": 0, "auth": false }, "filter": { "enabled": false },
        "listen": {
            "plain": { "binds": ["127.0.0.1"], "port": 0 },
            "dot": { "enabled": true, "host": "127.0.0.1", "port": 0, "cert": "./cert.pem", "key": "./key.pem" },
            "doh": { "enabled": true, "host": "127.0.0.1", "port": 0, "cert": "./cert.pem", "key": "./key.pem", "trustProxy": false, "http3": true },
            "doq": { "enabled": true, "host": "127.0.0.1", "port": 0 },
            "ddr": true
        },
        "site": { "hostname": "dns.example.test" },
        "upstream": { "pinned": [format!("udp://{up}")], "fallback": [] },
        // 關掉快速回應：第一個回應就是正式結果（快速回應的 TTL 最多 10 秒）
        "resolver": { "lastResort": [], "rankIps": false, "fastPath": false }
    }));
    let started = kuroshio::app::start(&cfg).await.unwrap();
    let dot = started.encrypted.dot.expect("DoT 有啟動");
    let doh = started.encrypted.doh.expect("DoH 有啟動");

    // 效能計數器（3.5.0）：握手完成時記完整／續用與密碼套件（計數器是整個行程共用的，只看有沒有增加）
    use std::sync::atomic::Ordering::Relaxed;
    let hs = |t: &kuroshio_net::perf::Tls| t.full.load(Relaxed) + t.resumed.load(Relaxed);
    let suites = |t: &kuroshio_net::perf::Tls| t.aes.load(Relaxed) + t.chacha.load(Relaxed);
    let (dot0, doh0, s0) = (
        hs(&kuroshio_net::perf::DOT),
        hs(&kuroshio_net::perf::DOH),
        suites(&kuroshio_net::perf::DOT),
    );
    let quic0 = kuroshio_net::perf::QUIC_NEW.load(Relaxed);

    // DoT：同一條連線同時多筆
    let u = Upstream::parse(&format!("tls://{dot}")).unwrap();
    let mut set = tokio::task::JoinSet::new();
    for i in 0..10u16 {
        let u = u.clone();
        set.spawn(async move { Message::parse(&u.exchange(&q(i, &format!("d{i}.test")), Duration::from_secs(3)).await.unwrap()).unwrap() });
    }
    while let Some(m) = set.join_next().await {
        assert_eq!(m.unwrap().answers[0].data, RData::A(Ipv4Addr::new(9, 8, 7, 6)));
    }
    assert!(hs(&kuroshio_net::perf::DOT) > dot0, "DoT 的握手有記到");
    assert!(suites(&kuroshio_net::perf::DOT) > s0, "協商到的密碼套件有記到");
    // DoH（HTTP/2 POST）
    let u = Upstream::parse(&format!("https://{doh}/dns-query")).unwrap();
    let m = Message::parse(&u.exchange(&q(7, "h.test"), Duration::from_secs(3)).await.unwrap()).unwrap();
    assert_eq!((m.id, m.answers.len()), (7, 1));
    assert!(hs(&kuroshio_net::perf::DOH) > doh0, "DoH 的握手有記到");
    // DoH GET ?dns=（HTTP/1.1，自己發請求）
    let tls = kuroshio::tls::connect_h1("127.0.0.1", doh.port(), Duration::from_secs(3))
        .await
        .unwrap();
    let mut tls = tls;
    let b64 = base64url(&q(0, "g.test"));
    tls.write_all(format!("GET /dns-query?dns={b64} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut out = Vec::new();
    tls.read_to_end(&mut out).await.ok();
    let text = String::from_utf8_lossy(&out);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    let lower = text.to_ascii_lowercase();
    let age: u32 = lower
        .split("cache-control: max-age=")
        .nth(1)
        .and_then(|r| r.split_whitespace().next())
        .and_then(|v| v.parse().ok())
        .expect("有 cache-control");
    assert!((110..=120).contains(&age), "max-age = 答案剩餘 TTL：{age}");
    let doh3 = started.encrypted.doh3.expect("DoH3 有啟動");
    assert!(
        lower.contains(&format!("alt-svc: h3=\":{}\"", doh3.port())),
        "DoH 回應告訴用戶端有 HTTP/3：{lower}"
    );

    // DoQ：同一條 QUIC 連線多筆查詢
    let doq = started.encrypted.doq.expect("DoQ 有啟動");
    let u = Upstream::parse(&format!("quic://{doq}")).unwrap();
    let mut set = tokio::task::JoinSet::new();
    for i in 0..10u16 {
        let u = u.clone();
        set.spawn(async move {
            Message::parse(
                &u.exchange(&q(100 + i, &format!("q{i}.test")), Duration::from_secs(3))
                    .await
                    .unwrap(),
            )
            .unwrap()
        });
    }
    while let Some(m) = set.join_next().await {
        let m = m.unwrap();
        assert!(m.id >= 100, "id 改回原本的");
        assert_eq!(m.answers[0].data, RData::A(Ipv4Addr::new(9, 8, 7, 6)));
    }
    assert!(kuroshio_net::perf::QUIC_NEW.load(Relaxed) > quic0, "QUIC 連線有記到");
    // DoH3
    let u = Upstream::parse(&format!("h3://{doh3}/dns-query")).unwrap();
    for i in 0..3u16 {
        let m = Message::parse(&u.exchange(&q(200 + i, "h3.test"), Duration::from_secs(3)).await.unwrap()).unwrap();
        assert_eq!((m.id, m.answers.len()), (200 + i, 1));
    }
    // 其他路徑 404
    let tls = kuroshio::tls::connect_h1("127.0.0.1", doh.port(), Duration::from_secs(3))
        .await
        .unwrap();
    let mut tls = tls;
    tls.write_all(b"GET /admin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    tls.read_to_end(&mut out).await.ok();
    assert!(String::from_utf8_lossy(&out).starts_with("HTTP/1.1 404"));

    // DDR：區網查 _dns.resolver.arpa SVCB → 列出 DoH(h2,h3)、DoT、DoQ
    let plain = started.bound[0];
    let ddr = kuroshio::upstream::Upstream::parse(&format!("udp://{plain}")).unwrap();
    let m = Message::parse(
        &ddr.exchange(&kuroshio_proto::build_query(5, "_dns.resolver.arpa", 64), Duration::from_secs(2))
            .await
            .unwrap(),
    )
    .unwrap();
    // 測試裡 DoH 與 DoH3 是不同的隨機埠，所以分成兩筆（同埠時合併成 alpn=h2,h3）
    assert_eq!(m.answers.len(), 4, "DoH、DoH3、DoT、DoQ");
    let RData::Raw(first) = &m.answers[0].data else { panic!() };
    assert!(first.windows(4).any(|w| w == b"\x02h2\x00"), "第一筆是 DoH h2");
    assert!(first.ends_with(b"/dns-query{?dns}"));
    let RData::Raw(last) = &m.answers[3].data else { panic!() };
    assert!(last.windows(4).any(|w| w == b"\x03doq"), "最後一筆是 DoQ");

    // Padding：用戶端要求補齊 → DoT 回應補到 468 的倍數
    let mut pq = Message::parse(&q(9, "pad.test")).unwrap();
    pq.opt = Some(kuroshio_proto::message::Opt {
        udp_size: 1232,
        options: vec![(kuroshio_proto::message::opt_code::PADDING, vec![])],
        ..Default::default()
    });
    let u = Upstream::parse(&format!("tls://{dot}")).unwrap();
    let resp = u.exchange(&pq.encode(), Duration::from_secs(3)).await.unwrap();
    assert_eq!(resp.len() % 468, 0, "回應長度 {}", resp.len());

    // DoT：送了長度、內容一直不送 → 10 秒後關掉連線（不會一直佔著連線名額）
    let mut slow = kuroshio::tls::connect_addrs("127.0.0.1", &[dot], &[b"dot"], Duration::from_secs(3))
        .await
        .unwrap();
    slow.write_all(&[0, 40, 0, 1]).await.unwrap();
    let t0 = std::time::Instant::now();
    let mut buf = [0u8; 16];
    let r = tokio::time::timeout(Duration::from_secs(20), slow.read(&mut buf)).await;
    assert!(matches!(r, Ok(Ok(0)) | Ok(Err(_))), "伺服器關閉連線：{r:?}");
    assert!(t0.elapsed() >= Duration::from_secs(8), "{:?}", t0.elapsed());
    std::fs::remove_dir_all(&dir).unwrap();
}

fn base64url(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..=c.len() {
            out.push(T[(n >> (18 - 6 * i)) as usize & 63] as char);
        }
    }
    out
}

#[tokio::test]
async fn plain_http_doh_behind_proxy() {
    let dir = std::env::temp_dir().join(format!("kuroshio-enc-plain-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let up = upstream().await;
    let cfg = kuroshio_config::with_overrides(&json!({
        "system": { "persistDir": dir.join("state").to_string_lossy() },
        "admin": { "port": 0, "auth": false }, "filter": { "enabled": false },
        "listen": { "plain": { "binds": ["127.0.0.1"], "port": 0 }, "doh": { "enabled": true, "host": "127.0.0.1", "port": 0, "cert": "", "key": "", "trustProxy": true } },
        "upstream": { "pinned": [format!("udp://{up}")], "fallback": [] },
        "resolver": { "lastResort": [], "rankIps": false },
        // 測試環境沒有台灣 IP 資料：資料讀不到時公網來源（X-Forwarded-For 203.0.113.9）會被擋，這裡測的是轉發
        "access": { "mode": "open" }
    }));
    let started = kuroshio::app::start(&cfg).await.unwrap();
    let doh = started.encrypted.doh.unwrap();
    let body = q(3, "p.test");
    let mut s = tokio::net::TcpStream::connect(doh).await.unwrap();
    s.write_all(
        format!("POST /dns-query HTTP/1.1\r\nHost: dns.example\r\nX-Forwarded-For: 203.0.113.9\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())
            .as_bytes(),
    )
    .await
    .unwrap();
    s.write_all(&body).await.unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    let p = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    assert!(out.starts_with(b"HTTP/1.1 200"), "{}", String::from_utf8_lossy(&out[..p]));
    assert_eq!(Message::parse(&out[p..]).unwrap().id, 3);
    let _ = std::fs::remove_dir_all(&dir);
}

/// DoQ：未驗證的握手太多時先回 Retry（這裡設成一律 Retry），正常的用戶端照樣查得到
#[tokio::test]
async fn doq_retry_when_many_unvalidated_handshakes() {
    let _quic = QUIC_TESTS.lock().await;
    let dir = std::env::temp_dir().join(format!("kuroshio-enc-retry-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("state")).unwrap();
    let der = write_cert(&dir);
    kuroshio::tls::add_root(der);
    let up = upstream().await;
    let cfg = kuroshio_config::with_overrides(&json!({
        "system": { "persistDir": dir.join("state").to_string_lossy() },
        "upstream": { "pinned": [format!("udp://{up}")], "fallback": [] },
        "resolver": { "lastResort": [], "rankIps": false, "fastPath": false }
    }));
    let r = kuroshio::app::build_resolver(&cfg).unwrap();
    let certs = kuroshio::encrypted::CertStore::new(dir.join("cert.pem"), dir.join("key.pem"));
    let limits = kuroshio::encrypted::Limits::new(32).with_retry_threshold(0);
    let doq = kuroshio::encrypted::listen_doq("127.0.0.1:0".parse().unwrap(), certs, r, limits)
        .await
        .unwrap();
    for i in 0..3u16 {
        let u = Upstream::parse(&format!("quic://{doq}")).unwrap();
        let m = Message::parse(&u.exchange(&q(300 + i, "retry.test"), Duration::from_secs(5)).await.unwrap()).unwrap();
        assert_eq!(m.answers[0].data, RData::A(Ipv4Addr::new(9, 8, 7, 6)));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// 3.5.0 F4（D9）：`perf.tls.quic.open` 是目前開著的 QUIC 上游連線數：連上 +1、同一條連線重複使用不變、
/// 不再使用（上游丟掉）時 −1。`new` 是新建的連線數
#[tokio::test]
async fn quic_open_gauge_follows_connections() {
    use std::sync::atomic::Ordering::Relaxed;
    let _quic = QUIC_TESTS.lock().await;
    let dir = std::env::temp_dir().join(format!("kuroshio-enc-open-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("state")).unwrap();
    let der = write_cert(&dir);
    kuroshio::tls::add_root(der);
    let up = upstream().await;
    let cfg = kuroshio_config::with_overrides(&json!({
        "system": { "persistDir": dir.join("state").to_string_lossy() },
        "upstream": { "pinned": [format!("udp://{up}")], "fallback": [] },
        "resolver": { "lastResort": [], "rankIps": false, "fastPath": false }
    }));
    let r = kuroshio::app::build_resolver(&cfg).unwrap();
    let certs = kuroshio::encrypted::CertStore::new(dir.join("cert.pem"), dir.join("key.pem"));
    let doq = kuroshio::encrypted::listen_doq("127.0.0.1:0".parse().unwrap(), certs, r, kuroshio::encrypted::Limits::new(32))
        .await
        .unwrap();
    let open = || kuroshio_net::perf::QUIC_OPEN.load(Relaxed);
    let until = |what: &'static str, want: u32| async move {
        let t0 = std::time::Instant::now();
        while kuroshio_net::perf::QUIC_OPEN.load(Relaxed) != want {
            assert!(
                t0.elapsed() < Duration::from_secs(5),
                "等不到：{what}（{}）",
                kuroshio_net::perf::QUIC_OPEN.load(Relaxed)
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    // 前一個測試的連線關閉時的 −1 可能還在路上：等到穩定
    let mut base = open();
    loop {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if open() == base {
            break;
        }
        base = open();
    }
    let new0 = kuroshio_net::perf::QUIC_NEW.load(Relaxed);
    let u = Upstream::parse(&format!("quic://{doq}")).unwrap();
    for i in 0..3u16 {
        let m = Message::parse(&u.exchange(&q(400 + i, "open.test"), Duration::from_secs(5)).await.unwrap()).unwrap();
        assert_eq!(m.answers[0].data, RData::A(Ipv4Addr::new(9, 8, 7, 6)));
    }
    until("連上 +1", base + 1).await;
    assert_eq!(
        kuroshio_net::perf::QUIC_NEW.load(Relaxed),
        new0 + 1,
        "同一條連線重複使用：new 只加 1"
    );
    assert_eq!(kuroshio_net::perf::json()["quic"]["open"], json!(base + 1));
    drop(u);
    until("上游丟掉連線：−1", base).await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cert_hot_reload() {
    let dir = std::env::temp_dir().join(format!("kuroshio-cert-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let store = kuroshio::encrypted::CertStore::new(dir.join("cert.pem"), dir.join("key.pem"));
    assert!(!store.ready(), "檔案還沒有");
    let a = write_cert(&dir);
    assert!(store.reload());
    std::thread::sleep(Duration::from_millis(1100));
    let b = write_cert(&dir);
    assert_ne!(a, b);
    assert!(store.reload(), "換新憑證");
    // 壞掉的檔案：保留舊的
    std::thread::sleep(Duration::from_millis(1100));
    std::fs::write(dir.join("cert.pem"), "garbage").unwrap();
    assert!(store.reload());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// 上游：名稱以 `slow` 開頭的永遠不回（模擬卡住的查詢），其他的馬上回 A 9.8.7.6
async fn upstream_with_stuck() -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let (len, peer) = s.recv_from(&mut buf).await.unwrap();
            let Ok(q) = Message::parse(&buf[..len]) else { continue };
            if q.questions.first().is_some_and(|x| x.name.starts_with("slow")) {
                continue;
            }
            let mut r = Message::response_to(&q, 0);
            r.opt = None;
            r.answers.push(Record::a(&q.questions[0].name, 120, Ipv4Addr::new(9, 8, 7, 6)));
            let _ = s.send_to(&r.encode(), peer).await;
        }
    });
    addr
}

/// 卡住的查詢要等很久才會被解析器放棄（上游逾時 8 秒）：測試的動作都在這之前做完
fn stuck_resolver(dir: &std::path::Path, up: SocketAddr) -> std::sync::Arc<kuroshio::resolver::Resolver> {
    let cfg = kuroshio_config::with_overrides(&json!({
        "system": { "persistDir": dir.join("state").to_string_lossy() },
        "upstream": { "pinned": [format!("udp://{up}")], "fallback": [] },
        "resolver": { "lastResort": [], "rankIps": false, "fastPath": false, "timeoutMs": 8000 }
    }));
    kuroshio::app::build_resolver(&cfg).unwrap()
}

async fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    let t0 = std::time::Instant::now();
    while !f() {
        assert!(t0.elapsed() < Duration::from_secs(3), "等不到：{what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// 3.5.1 K9：DoT 連線被重設時，卡住的查詢馬上取消、連線名額馬上還回來，新連線照常接受。
/// 以前要等卡住的查詢自己結束（這裡 8 秒以上），這段期間新連線一律被拒絕
#[tokio::test]
async fn dot_reset_releases_connection_slot() {
    let dir = std::env::temp_dir().join(format!("kuroshio-enc-dotreset-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("state")).unwrap();
    let der = write_cert(&dir);
    kuroshio::tls::add_root(der);
    let r = stuck_resolver(&dir, upstream_with_stuck().await);
    let certs = kuroshio::encrypted::CertStore::new(dir.join("cert.pem"), dir.join("key.pem"));
    assert!(certs.reload());
    // 總共只收 1 條（本機不算每個來源的上限，這裡用總數測同一套名額）
    let limits = kuroshio::encrypted::Limits::new(1);
    let dot = kuroshio::encrypted::listen_dot("127.0.0.1:0".parse().unwrap(), certs, r, limits.clone())
        .await
        .unwrap();
    let refused0 = kuroshio::resolver::perf::json()["server"]["refused"]["dot"]["total"]
        .as_u64()
        .unwrap();
    // A：送一筆會卡住的查詢
    let mut a = kuroshio::tls::connect_addrs("127.0.0.1", &[dot], &[b"dot"], Duration::from_secs(3))
        .await
        .unwrap();
    let mut f = (q(1, "slow.example.com").len() as u16).to_be_bytes().to_vec();
    f.extend_from_slice(&q(1, "slow.example.com"));
    a.write_all(&f).await.unwrap();
    a.flush().await.unwrap();
    wait_until("A 佔著唯一的名額", || limits.in_use() == 1).await;
    // 名額滿了：新連線在 TLS 握手之前就被關閉，有計數
    let b = kuroshio::tls::connect_addrs("127.0.0.1", &[dot], &[b"dot"], Duration::from_secs(2)).await;
    assert!(b.is_err(), "滿了要拒絕");
    let refused = kuroshio::resolver::perf::json()["server"]["refused"]["dot"]["total"]
        .as_u64()
        .unwrap();
    assert!(refused > refused0, "拒絕有計數：{refused0} → {refused}");
    // A 被重設（用戶端放棄：SO_LINGER 0 再關閉 = 送 RST）
    let (tcp, _) = a.into_inner();
    #[allow(deprecated)]
    tcp.set_linger(Some(Duration::ZERO)).unwrap();
    drop(tcp);
    wait_until("被重設的連線馬上還名額（不等卡住的查詢）", || {
        limits.in_use() == 0
    })
    .await;
    // 新連線照常查得到
    let u = Upstream::parse(&format!("tls://{dot}")).unwrap();
    let m = Message::parse(&u.exchange(&q(2, "fast.example.com"), Duration::from_secs(3)).await.unwrap()).unwrap();
    assert_eq!(m.answers[0].data, RData::A(Ipv4Addr::new(9, 8, 7, 6)));
    let _ = std::fs::remove_dir_all(&dir);
}

/// 3.5.1 K7：DoH 處理中的請求滿了**立刻**回 503 busy（不排隊）；用戶端放棄（HTTP/2 RST_STREAM）後名額馬上還回來
#[tokio::test]
async fn doh_busy_is_immediate_and_abandoned_requests_free_slots() {
    let dir = std::env::temp_dir().join(format!("kuroshio-enc-dohbusy-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("state")).unwrap();
    let r = stuck_resolver(&dir, upstream_with_stuck().await);
    let gate = kuroshio::encrypted::DohGate::new(1);
    let opts = kuroshio::encrypted::DohOptions::new("/dns-query", gate.clone());
    // 純 HTTP（h2c）：不用憑證
    let doh = kuroshio::encrypted::listen_doh("127.0.0.1:0".parse().unwrap(), None, r, opts, kuroshio::encrypted::Limits::new(64))
        .await
        .unwrap();
    let tcp = tokio::net::TcpStream::connect(doh).await.unwrap();
    let (mut h2c, conn) = h2::client::handshake(tcp).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let post = |h2c: &mut h2::client::SendRequest<bytes::Bytes>, body: Vec<u8>| {
        let req = http::Request::post(format!("http://{doh}/dns-query"))
            .header("content-type", "application/dns-message")
            .body(())
            .unwrap();
        let (resp, mut send) = h2c.send_request(req, false).unwrap();
        send.send_data(bytes::Bytes::from(body), true).unwrap();
        resp
    };
    // A：卡住的查詢佔著唯一的名額
    h2c = h2c.ready().await.unwrap();
    let stuck = post(&mut h2c, q(1, "slow.example.com"));
    wait_until("A 佔著名額", || gate.in_use() == 1).await;
    // B：滿了 → 立刻 503 busy
    h2c = h2c.ready().await.unwrap();
    let t0 = std::time::Instant::now();
    let resp = tokio::time::timeout(Duration::from_secs(2), post(&mut h2c, q(2, "fast.example.com")))
        .await
        .expect("滿了要立刻回應，不排隊")
        .unwrap();
    assert_eq!(resp.status(), 503);
    assert_eq!(resp.headers()["retry-after"], "1");
    let mut body = resp.into_body();
    let mut text = Vec::new();
    while let Some(Ok(c)) = body.data().await {
        text.extend_from_slice(&c);
    }
    assert_eq!(text, b"busy\n");
    assert!(t0.elapsed() < Duration::from_secs(1), "{:?}", t0.elapsed());
    // A 的用戶端放棄（丟掉回應 = RST_STREAM CANCEL）：伺服器丟掉處理中的請求，名額馬上還回來
    drop(stuck);
    wait_until("放棄的請求還名額", || gate.in_use() == 0).await;
    // C：照常回答
    h2c = h2c.ready().await.unwrap();
    let resp = tokio::time::timeout(Duration::from_secs(3), post(&mut h2c, q(3, "fast.example.com")))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resp.status(), 200);
    let mut body = resp.into_body();
    let mut out = Vec::new();
    while let Some(Ok(c)) = body.data().await {
        out.extend_from_slice(&c);
    }
    let m = Message::parse(&out).unwrap();
    assert_eq!(m.answers[0].data, RData::A(Ipv4Addr::new(9, 8, 7, 6)));
    assert!(kuroshio::resolver::perf::json()["server"]["dohBusy"].as_u64().unwrap() >= 1);
    let _ = std::fs::remove_dir_all(&dir);
}
