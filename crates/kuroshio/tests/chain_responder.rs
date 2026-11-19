//! 串接模式的上游回應器（3.4.0 WP3，規格 1.9）：實際監聽的行程內實例 + 假上游

use kuroshio::resolver::Ctx;
use kuroshio_community::chain::{auth_name, open_auth, txt_payload, AuthBody};
use kuroshio_community::identity::{kid_of, KeyPair};
use kuroshio_proto::message::{Message, RData, Record};
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// 假上游：IN A 回 192.0.2.1，其他回空答案；記錄收到幾筆查詢
async fn fake_upstream() -> (SocketAddr, Arc<AtomicUsize>) {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    let n = Arc::new(AtomicUsize::new(0));
    let n2 = n.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let (len, peer) = s.recv_from(&mut buf).await.unwrap();
            n2.fetch_add(1, Ordering::SeqCst);
            let Ok(q) = Message::parse(&buf[..len]) else { continue };
            let mut r = Message::response_to(&q, 0);
            r.opt = None;
            if q.questions[0].qtype == 1 && q.questions[0].qclass == 1 {
                r.answers.push(Record::a(&q.questions[0].name, 300, Ipv4Addr::new(192, 0, 2, 1)));
            }
            let _ = s.send_to(&r.encode(), peer).await;
        }
    });
    (addr, n)
}

/// 每個測試自己的暫存目錄（community.dir 在 `<dir>/keys`）
fn test_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("kuroshio-chain-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("state")).unwrap();
    d
}

fn cfg(dir: &std::path::Path, up: SocketAddr, upstream_extra: Value) -> Value {
    let mut upstream = json!({ "pinned": [format!("udp://{up}")], "fallback": [], "pathCheck": false });
    for (k, v) in upstream_extra.as_object().unwrap() {
        upstream[k] = v.clone();
    }
    kuroshio_config::with_overrides(&json!({
        "admin": { "port": 0, "auth": false },
        "filter": { "enabled": false },
        "cdn": { "enabled": false },
        "system": { "persistDir": dir.join("state").to_string_lossy() },
        "community": { "enabled": false, "dir": dir.join("keys").to_string_lossy() },
        "listen": { "plain": { "binds": ["127.0.0.1"], "port": 0 } },
        "upstream": upstream,
        "resolver": { "timeoutMs": 800, "lastResort": [], "rankIps": false }
    }))
}

async fn start(dir: &std::path::Path, up: SocketAddr, upstream_extra: Value) -> kuroshio::app::Started {
    kuroshio::app::start(&cfg(dir, up, upstream_extra)).await.unwrap()
}

fn chaos(id: u16, name: &str) -> Vec<u8> {
    kuroshio_net::path::build_chaos_txt(id, name)
}

async fn ask_udp(addr: SocketAddr, q: &[u8]) -> Vec<u8> {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.send_to(q, addr).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(3), s.recv_from(&mut buf))
        .await
        .expect("UDP 沒有回應")
        .unwrap();
    buf.truncate(n);
    buf
}

async fn ask_tcp(addr: SocketAddr, q: &[u8]) -> Vec<u8> {
    let mut t = TcpStream::connect(addr).await.unwrap();
    let mut m = (q.len() as u16).to_be_bytes().to_vec();
    m.extend_from_slice(q);
    t.write_all(&m).await.unwrap();
    let len = t.read_u16().await.unwrap() as usize;
    let mut r = vec![0u8; len];
    t.read_exact(&mut r).await.unwrap();
    r
}

fn nonce(i: u8) -> [u8; 16] {
    let mut n = kuroshio_community::util::random_bytes::<16>();
    n[0] = i;
    n
}

/// 回應 → 驗過簽章的 AuthBody
fn auth_of(resp: &[u8], nonce: &[u8; 16]) -> AuthBody {
    let m = Message::parse(resp).unwrap();
    assert_eq!(m.rcode, 0, "auth 要成功");
    assert_eq!(m.answers.len(), 1);
    let a = &m.answers[0];
    assert_eq!((a.rtype, a.class, a.ttl), (16, 3, 0));
    let RData::Raw(rd) = &a.data else { panic!("{:?}", a.data) };
    open_auth(&txt_payload(rd).unwrap(), nonce).expect("簽章要驗得過")
}

async fn auth_udp(addr: SocketAddr, i: u8) -> AuthBody {
    let n = nonce(i);
    auth_of(&ask_udp(addr, &chaos(u16::from(i), &auth_name(&n))).await, &n)
}

fn rcode(resp: &[u8]) -> u16 {
    Message::parse(resp).unwrap().rcode
}

#[tokio::test]
async fn auth_over_udp_and_tcp_verifies() {
    let dir = test_dir("udp-tcp");
    let (up, _) = fake_upstream().await;
    let s = start(&dir, up, json!({})).await;
    let me = s.resolver.chain.get().unwrap().node_key().clone();

    let n = nonce(1);
    let resp = ask_udp(s.bound[0], &chaos(1, &auth_name(&n))).await;
    assert!(resp.len() < 512, "回應 {} bytes，要放得進不帶 EDNS 的 UDP", resp.len());
    let b = auth_of(&resp, &n);
    assert_eq!(b.peer, "127.0.0.1");
    assert_eq!(b.app, env!("CARGO_PKG_VERSION"));
    assert!(b.allow);
    assert_eq!(b.tok.len(), 16);
    assert_eq!(b.path, vec![b.kid.clone()], "沒串接別人：path 只有自己");
    assert_eq!(me.own_kids(), vec![<[u8; 8]>::try_from(b.kid.as_slice()).unwrap()]);

    let n = nonce(2);
    let b2 = auth_of(&ask_tcp(s.bound[1], &chaos(2, &auth_name(&n))).await, &n);
    assert_eq!(b2.public, b.public);
    assert_eq!(b2.peer, "127.0.0.1");
}

#[tokio::test]
async fn auth_creates_key_when_community_disabled() {
    let dir = test_dir("create-key");
    let (up, _) = fake_upstream().await;
    let s = start(&dir, up, json!({})).await;
    let key = dir.join("keys").join("key.pem");
    assert!(!key.exists(), "啟動時不建立金鑰（第一次需要才建）");
    let b1 = auth_udp(s.bound[0], 1).await;
    assert!(key.exists(), "第一次 auth 之後建立 key.pem");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let b2 = auth_udp(s.bound[0], 2).await;
    assert_eq!(b1.public, b2.public, "第二次用同一把");
    assert_eq!(b1.kid, kid_of(&b1.public).to_vec());
}

#[tokio::test]
async fn auth_same_key_as_community() {
    let dir = test_dir("same-key");
    let known = KeyPair::generate();
    std::fs::create_dir_all(dir.join("keys")).unwrap();
    std::fs::write(dir.join("keys").join("key.pem"), known.to_pem()).unwrap();
    let (up, _) = fake_upstream().await;
    let s = start(&dir, up, json!({})).await;
    let b = auth_udp(s.bound[0], 1).await;
    assert_eq!(b.public, known.public.to_vec());
    let r = s.resolver.chain.get().unwrap();
    assert_eq!(r.serving_json()["fingerprint"], json!(known.fingerprint()));
}

#[tokio::test]
async fn allow_downstream_off_still_signs() {
    let dir = test_dir("off");
    let (up, n) = fake_upstream().await;
    let s = start(&dir, up, json!({ "allowDownstream": false })).await;
    let r = s.resolver.chain.get().unwrap().clone();
    let before = r.serving_json();
    assert_eq!(before["probes"]["count24h"], json!(0));
    assert_eq!(before["note"], Value::Null);

    let b = auth_udp(s.bound[0], 1).await;
    assert!(!b.allow);
    assert!(b.caps.is_empty());
    assert!(r.caps().is_empty());

    // 關著時登記、共用結果一律 REFUSED，記在 notAllowed
    for name in ["r.chain.kuroshio", "m.s.chain.kuroshio"] {
        assert_eq!(rcode(&ask_udp(s.bound[0], &chaos(3, name)).await), 5);
    }
    let v = r.serving_json();
    assert_eq!(v["allowDownstream"], json!(false));
    let text = v["text"].as_str().unwrap();
    assert!(text.contains("不提供資料") && text.contains("重複"), "{text}");
    assert!(text.contains("最近有下游黑潮來問過"), "{text}");
    assert_eq!(v["probes"]["count24h"], json!(1));
    assert!(v["probes"]["lastAt"].is_u64());
    assert_eq!(v["refused"]["notAllowed"], json!(2));
    assert_eq!(n.load(Ordering::SeqCst), 0, "不轉給上游");
}

#[tokio::test]
async fn serving_text_when_on() {
    let dir = test_dir("on");
    let (up, _) = fake_upstream().await;
    let s = start(&dir, up, json!({})).await;
    let v = s.resolver.chain.get().unwrap().serving_json();
    assert_eq!(v["allowDownstream"], json!(true));
    assert_eq!(v["text"], json!("提供資料給下游黑潮：目前沒有下游連上來"));
    assert!(!v["note"].as_str().unwrap().is_empty());
    // 還沒有人問過：不建立金鑰，nodeId / fingerprint 是 null
    assert_eq!(v["nodeId"], Value::Null);
    assert!(v["downstreams"].as_array().unwrap().is_empty());
    for k in ["share", "probes", "refused"] {
        assert!(v[k].is_object(), "{k}");
    }
    let b = auth_udp(s.bound[0], 1).await;
    let v = s.resolver.chain.get().unwrap().serving_json();
    assert_eq!(v["nodeId"], json!(kuroshio_community::util::hex(&b.kid)));
    assert_eq!(v["probes"]["count24h"], json!(0), "開著時不算 probes");
}

#[tokio::test]
async fn in_class_queries_are_not_treated_as_chain() {
    let dir = test_dir("in-class");
    let (up, n) = fake_upstream().await;
    let s = start(&dir, up, json!({})).await;
    let q = kuroshio_proto::build_query(7, "x.chain.kuroshio", 16);
    let m = Message::parse(&ask_udp(s.bound[0], &q).await).unwrap();
    assert_ne!(m.rcode, 5, "IN 類別照一般查詢處理");
    assert!(m.answers.iter().all(|a| a.class != 3));
    assert!(n.load(Ordering::SeqCst) >= 1, "一般查詢照常問上游");
}

/// 向下相容：兩個開關都關時，chain 區域以外的查詢跟 3.3.7 一樣（含其他 CH 查詢照常轉給上游）
#[tokio::test]
async fn both_switches_off_other_queries_unchanged() {
    let dir = test_dir("both-off");
    let (up, n) = fake_upstream().await;
    let s = start(&dir, up, json!({ "chain": false, "allowDownstream": false })).await;
    let m = Message::parse(&ask_udp(s.bound[0], &kuroshio_proto::build_query(1, "www.example.com", 1)).await).unwrap();
    assert_eq!(m.rcode, 0);
    assert_eq!(m.answers[0].data, RData::A(Ipv4Addr::new(192, 0, 2, 1)));
    let before = n.load(Ordering::SeqCst);
    let m = Message::parse(&ask_udp(s.bound[0], &chaos(2, "hostname.bind")).await).unwrap();
    assert_ne!(m.rcode, 5);
    assert_eq!(n.load(Ordering::SeqCst), before + 1, "其他 CH 查詢照常轉給上游");
    assert!(!dir.join("keys").join("key.pem").exists(), "沒人問 auth 就不建立金鑰");
}

#[tokio::test]
async fn chain_queries_never_reach_upstream() {
    let dir = test_dir("never-upstream");
    let (up, n) = fake_upstream().await;
    let s = start(&dir, up, json!({})).await;
    let names = [
        "chain.kuroshio",
        "r.chain.kuroshio",
        "m.s.chain.kuroshio",
        "0.0011223344556677.s.chain.kuroshio",
        "zz.a.chain.kuroshio",
        "0011.a.chain.kuroshio",
        "garbage.chain.kuroshio",
        "a.b.c.d.chain.kuroshio",
        "CHAIN.Kuroshio.",
    ];
    for (i, name) in names.iter().enumerate() {
        assert_eq!(rcode(&ask_udp(s.bound[0], &chaos(i as u16, name)).await), 5, "{name}");
        assert_eq!(rcode(&ask_tcp(s.bound[1], &chaos(i as u16, name)).await), 5, "{name}（TCP）");
    }
    // 其他型別的 auth 名稱：空答案，也不問上游
    let mut q = Message::parse(&chaos(99, &auth_name(&nonce(1)))).unwrap();
    q.questions[0].qtype = 1;
    let m = Message::parse(&ask_udp(s.bound[0], &q.encode()).await).unwrap();
    assert_eq!((m.rcode, m.answers.len()), (0, 0));
    assert_eq!(n.load(Ordering::SeqCst), 0, "假上游一筆都不該收到");
}

#[tokio::test]
async fn refused_on_encrypted_proto_or_public_client() {
    let dir = test_dir("refused");
    let (up, n) = fake_upstream().await;
    let s = start(&dir, up, json!({})).await;
    let q = chaos(1, &auth_name(&nonce(1)));
    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let public = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
    for ctx in [
        Ctx {
            proto: "doh",
            client: loopback,
        },
        Ctx {
            proto: "dot",
            client: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
        },
        Ctx {
            proto: "udp",
            client: public,
        },
        Ctx {
            proto: "tcp",
            client: public,
        },
    ] {
        let m = Message::parse(&s.resolver.handle(&q, &ctx).await.unwrap()).unwrap();
        assert_eq!(m.rcode, 5, "{} {}", ctx.proto, ctx.client);
        assert!(m.answers.is_empty());
    }
    let v = s.resolver.chain.get().unwrap().serving_json();
    assert_eq!(v["refused"]["notPrivate"], json!(4));
    assert_eq!(n.load(Ordering::SeqCst), 0);
    assert!(!dir.join("keys").join("key.pem").exists(), "拒絕的查詢不碰金鑰");
}

#[tokio::test]
async fn rate_limit_per_source_and_table_bounded() {
    let dir = test_dir("rate");
    let (up, _) = fake_upstream().await;
    let s = start(&dir, up, json!({})).await;
    let r = s.resolver.chain.get().unwrap().clone();
    let t0 = Instant::now();
    let mut ok = 0u32;
    for i in 0..30u8 {
        if rcode(&ask_udp(s.bound[0], &chaos(u16::from(i), &auth_name(&nonce(i)))).await) == 0 {
            ok += 1;
        }
    }
    let secs = t0.elapsed().as_secs_f64();
    let max = 8.0 + secs * 4.0;
    assert!(ok >= 8, "前 8 次要成功（{ok}）");
    assert!(f64::from(ok) <= max.floor() + 1.0, "成功 {ok} 次，超過 8 + {secs:.2} 秒 × 4");
    assert!(r.serving_json()["refused"]["rate"].as_u64().unwrap() >= 1);

    // 100 個不同來源：表最多 64 筆
    for i in 0..100u8 {
        let ctx = Ctx {
            proto: "udp",
            client: IpAddr::V4(Ipv4Addr::new(10, 0, 1, i)),
        };
        let qname = auth_name(&nonce(i));
        let q = Message::parse(&chaos(u16::from(i), &qname)).unwrap();
        let m = r.answer(&q, &qname, &ctx);
        assert!(m.rcode == 0 || m.rcode == 5);
    }
    assert!(r.rate_table_len() <= kuroshio::chain::responder::MAX_SOURCES);
    assert!(r.rate_table_len() > 0);
}

#[tokio::test]
async fn path_reflects_upstream() {
    let dir = test_dir("path");
    let (up, _) = fake_upstream().await;
    let s = start(&dir, up, json!({})).await;
    let r = s.resolver.chain.get().unwrap().clone();
    let x = vec![0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18];
    r.set_upstream_path(Some(vec![x.clone()]));
    let b = auth_udp(s.bound[0], 1).await;
    assert_eq!(b.path, vec![x, b.kid.clone()]);
    r.set_upstream_path(None);
    let b = auth_udp(s.bound[0], 2).await;
    assert_eq!(b.path, vec![b.kid.clone()]);
}

#[tokio::test]
async fn version_kuroshio_unchanged() {
    let dir = test_dir("version");
    let (up, n) = fake_upstream().await;
    let s = start(&dir, up, json!({})).await;
    let m = Message::parse(&ask_udp(s.bound[0], &chaos(5, "version.kuroshio")).await).unwrap();
    assert_eq!(m.rcode, 0);
    let RData::Raw(b) = &m.answers[0].data else {
        panic!("{:?}", m.answers)
    };
    assert_eq!(String::from_utf8_lossy(&b[1..]), format!("kuroshio/{}", env!("CARGO_PKG_VERSION")));
    assert_eq!((m.answers[0].class, m.answers[0].ttl), (3, 0));
    assert_eq!(n.load(Ordering::SeqCst), 0);
}
