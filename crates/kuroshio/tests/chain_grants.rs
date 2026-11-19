//! 串接模式（3.4.0 WP6，規格第 4 節）：上游放行下游。行程內起一個上游實例，下游用 WP1 的函式手工組登記。
//!
//! - 登記的四項檢查（下游簽章、`up` 是這台、`peer` 等於實際來源、`tok` 有效）一項都不能省
//! - 放行跟著 `allow_downstream`（預設開），不逐台核准；登記表只在記憶體、有上限、會過期
//! - 繞過防護清單（`bypass`）只對登記中的下游、它登記的名稱（含 CNAME 目標）豁免

use kuroshio::chain::client::{Client, Timing};
use kuroshio::chain::grants::Grants;
use kuroshio::chain::responder::Responder;
use kuroshio::chain::NodeKey;
use kuroshio::ipfilter::Reason;
use kuroshio::resolver::{Ctx, FilterCheck, Verdict};
use kuroshio_community::chain::{
    self as proto, auth_name, open, open_auth, seal, txt_payload, AuthBody, RegAck, RegBody, OPT_CODE, PROTO, REG_NAME,
};
use kuroshio_community::envelope::{from_cbor, to_cbor};
use kuroshio_community::identity::{fingerprint, kid_of, KeyPair};
use kuroshio_config::chain::ChainSettings;
use kuroshio_proto::message::{Message, Opt, Question, RData, Record};
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

// ---------------- 假伺服器 ----------------

/// 假上游：`a.example.com`、`b.example.com` 回 CNAME `dns.example.net` + A；其他名稱回 A 192.0.2.1
async fn fake_upstream() -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let (len, peer) = s.recv_from(&mut buf).await.unwrap();
            let Ok(q) = Message::parse(&buf[..len]) else { continue };
            let mut r = Message::response_to(&q, 0);
            r.opt = None;
            let name = q.questions[0].name.to_ascii_lowercase();
            if q.questions[0].qtype == 1 {
                if name == "a.example.com" || name == "b.example.com" {
                    r.answers.push(Record {
                        name: q.questions[0].name.clone(),
                        rtype: 5,
                        class: 1,
                        ttl: 300,
                        data: RData::Name("dns.example.net".into()),
                    });
                    r.answers.push(Record::a("dns.example.net", 300, Ipv4Addr::new(192, 0, 2, 1)));
                } else {
                    r.answers.push(Record::a(&q.questions[0].name, 300, Ipv4Addr::new(192, 0, 2, 1)));
                }
            }
            let _ = s.send_to(&r.encode(), peer).await;
        }
    });
    addr
}

/// 過濾清單伺服器：`/bypass.txt`（繞過防護）、`/ads.txt`（一般清單）
async fn list_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let body = if req.starts_with("GET /bypass.txt") {
                    "||dns.example.net^\n||other.example.net^\n||custom.example.net^\n"
                } else {
                    "||adsdns.example.net^\n"
                };
                let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len());
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    addr
}

// ---------------- 上游實例 ----------------

fn test_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("kuroshio-grants-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("state")).unwrap();
    d
}

/// `lists`：過濾清單伺服器（None = 不過濾）
fn cfg(dir: &Path, up: SocketAddr, lists: Option<SocketAddr>, allow_downstream: bool) -> Value {
    let filter = match lists {
        Some(l) => {
            std::fs::write(dir.join("custom-rules.txt"), "||custom.example.net^\n").unwrap();
            json!({
                "enabled": true,
                "customRules": ["./custom-rules.txt"],
                "lists": [
                    { "name": "繞過防護", "url": format!("http://{l}/bypass.txt"), "category": "ads", "bypass": true },
                    { "name": "廣告", "url": format!("http://{l}/ads.txt"), "category": "ads" }
                ]
            })
        }
        None => json!({ "enabled": false }),
    };
    kuroshio_config::with_overrides(&json!({
        "admin": { "port": 0, "auth": false },
        "filter": filter,
        "cdn": { "enabled": false },
        "system": { "persistDir": dir.join("state").to_string_lossy() },
        "community": { "enabled": false, "dir": dir.join("keys").to_string_lossy() },
        "listen": { "plain": { "binds": ["127.0.0.1"], "port": 0 } },
        "upstream": { "pinned": [format!("udp://{up}")], "fallback": [], "pathCheck": false, "allowDownstream": allow_downstream },
        "resolver": { "timeoutMs": 800, "lastResort": [], "rankIps": false }
    }))
}

struct Up {
    s: kuroshio::app::Started,
    dir: PathBuf,
}

impl Up {
    fn responder(&self) -> Arc<Responder> {
        self.s.resolver.chain.get().unwrap().clone()
    }

    fn serving(&self) -> Value {
        self.responder().serving_json()
    }

    async fn status(&self) -> Value {
        kuroshio::admin::route(&self.s.state, "/api/status", &Default::default()).await.body
    }
}

async fn start(name: &str, allow_downstream: bool, filter: bool) -> Up {
    let dir = test_dir(name);
    let up = fake_upstream().await;
    let lists = if filter { Some(list_server().await) } else { None };
    let s = kuroshio::app::start(&cfg(&dir, up, lists, allow_downstream)).await.unwrap();
    let u = Up { s, dir };
    if filter {
        // 清單啟動後 2 秒才下載：等到 bypass 清單生效
        let t0 = Instant::now();
        while !is_blocked(&u.s.resolver, ip("192.168.1.9"), "other.example.net").await {
            assert!(t0.elapsed() < Duration::from_secs(15), "清單沒有載入");
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
    u
}

// ---------------- 下游（手工組登記） ----------------

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn ctx(client: IpAddr) -> Ctx {
    Ctx { proto: "udp", client }
}

fn chaos(id: u16, name: &str) -> Vec<u8> {
    kuroshio_net::path::build_chaos_txt(id, name)
}

/// 從這個來源做一次 auth（拿 tok、peer、上游的 kid 與公鑰）
async fn auth_from(r: &Arc<kuroshio::resolver::Resolver>, client: IpAddr) -> AuthBody {
    let nonce = kuroshio_community::util::random_bytes::<16>();
    let resp = r.handle(&chaos(1, &auth_name(&nonce)), &ctx(client)).await.unwrap();
    let m = Message::parse(&resp).unwrap();
    assert_eq!(m.rcode, 0, "auth 要成功");
    open_auth(&txt_of(&m).unwrap(), &nonce).unwrap()
}

fn txt_of(m: &Message) -> Option<Vec<u8>> {
    match &m.answers.first()?.data {
        RData::Raw(rd) => txt_payload(rd),
        _ => None,
    }
}

fn reg_body(key: &KeyPair, auth: &AuthBody, names: &[&str]) -> RegBody {
    RegBody {
        v: PROTO,
        t: "reg".into(),
        up: auth.kid.clone(),
        tok: auth.tok.clone(),
        peer: auth.peer.clone(),
        kid: key.kid.to_vec(),
        public: key.public.to_vec(),
        app: "3.4.0".into(),
        names: names.iter().map(|s| s.to_string()).collect(),
        local: true,
    }
}

/// 登記查詢：`sealed` = None 時不帶 EDNS 選項
fn reg_query(id: u16, sealed: Option<Vec<u8>>) -> Vec<u8> {
    Message {
        id,
        questions: vec![Question {
            name: REG_NAME.into(),
            qtype: 16,
            qclass: 3,
        }],
        opt: Some(Opt {
            udp_size: 1232,
            options: sealed.map(|s| vec![(OPT_CODE, s)]).unwrap_or_default(),
            ..Default::default()
        }),
        ..Default::default()
    }
    .encode()
}

fn sealed_reg(key: &KeyPair, body: &RegBody) -> Vec<u8> {
    seal(key, "reg", to_cbor(body))
}

async fn send_reg(r: &Arc<kuroshio::resolver::Resolver>, client: IpAddr, q: &[u8]) -> Message {
    Message::parse(&r.handle(q, &ctx(client)).await.unwrap()).unwrap()
}

/// 完整登記一次（auth → reg），回 rcode 與驗過的 RegAck
async fn register(r: &Arc<kuroshio::resolver::Resolver>, client: IpAddr, key: &KeyPair, names: &[&str]) -> (u16, Option<RegAck>) {
    let auth = auth_from(r, client).await;
    let m = send_reg(r, client, &reg_query(2, Some(sealed_reg(key, &reg_body(key, &auth, names))))).await;
    let ack = txt_of(&m).map(|t| {
        let b = open(&t, "regack", &auth.public).expect("regack 要用上游公鑰驗得過");
        from_cbor::<RegAck>(&b).unwrap()
    });
    (m.rcode, ack)
}

/// A 記錄是 0.0.0.0（被擋）
async fn is_blocked(r: &Arc<kuroshio::resolver::Resolver>, client: IpAddr, name: &str) -> bool {
    let resp = r.handle(&kuroshio_proto::build_query(9, name, 1), &ctx(client)).await.unwrap();
    let m = Message::parse(&resp).unwrap();
    m.answers.iter().any(|a| a.data == RData::A(Ipv4Addr::UNSPECIFIED))
}

async fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    let t0 = Instant::now();
    while !f() {
        assert!(t0.elapsed() < Duration::from_secs(5), "等不到：{what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

const DOWN: &str = "192.168.1.2";
const OTHER: &str = "192.168.1.3";

// ---------------- 登記 ----------------

#[tokio::test]
async fn register_roundtrip_and_listed() {
    let u = start("roundtrip", true, false).await;
    let key = KeyPair::generate();
    // 實際走 UDP 監聽
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let nonce = kuroshio_community::util::random_bytes::<16>();
    sock.send_to(&chaos(1, &auth_name(&nonce)), u.s.bound[0]).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let auth = open_auth(&txt_of(&Message::parse(&buf[..n]).unwrap()).unwrap(), &nonce).unwrap();
    assert!(auth.caps.contains(&"reg".to_string()), "{:?}", auth.caps);
    assert_eq!(auth.peer, "127.0.0.1");
    let body = reg_body(&key, &auth, &["dns.example.net", "doh.example.com"]);
    sock.send_to(&reg_query(2, Some(sealed_reg(&key, &body))), u.s.bound[0])
        .await
        .unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let m = Message::parse(&buf[..n]).unwrap();
    assert_eq!(m.rcode, 0);
    let b = open(&txt_of(&m).unwrap(), "regack", &auth.public).expect("regack 用上游公鑰驗得過");
    let ack: RegAck = from_cbor(&b).unwrap();
    assert_eq!((ack.v, ack.t.as_str(), ack.ttl), (PROTO, "regack", 900));
    assert_eq!(ack.kid, key.kid.to_vec());

    let v = u.serving();
    assert_eq!(v["text"], "提供資料給下游黑潮：目前 1 台");
    let d = v["downstreams"].as_array().unwrap();
    assert_eq!(d.len(), 1);
    assert_eq!(d[0]["address"], "127.0.0.1");
    assert_eq!(d[0]["fingerprint"], fingerprint(&key.public));
    assert_eq!(d[0]["nodeId"], kuroshio_community::util::hex(&key.kid));
    assert_eq!(d[0]["version"], "3.4.0");
    assert_eq!(d[0]["viaNat"], false);
    assert_eq!(d[0]["names"], 2);
    assert!(d[0]["firstSeen"].as_u64().unwrap() > 0);
    assert!(d[0]["lastSeen"].as_u64().unwrap() >= d[0]["firstSeen"].as_u64().unwrap());
    assert!(d[0]["expiresAt"].as_u64().unwrap() > d[0]["lastSeen"].as_u64().unwrap());
    // /api/status 的 chain（下游狀態機的 status_json）帶的 serving 就是這個回應器的 serving_json。
    // 行程層級的狀態機在平行測試裡會被別的實例接走，所以這裡自己接一個
    let c = Client::new(
        ChainSettings::from_cfg(&json!({})),
        Arc::new(NodeKey::new(u.dir.join("down-keys"))),
        Timing::default(),
    );
    let mgr = u.s.resolver.upstreams.clone();
    c.attach(ChainSettings::from_cfg(&json!({})), &mgr, Some(&u.responder()));
    let st = c.status_json();
    println!("chain.serving = {}", serde_json::to_string_pretty(&st["serving"]).unwrap());
    // 比對下游是誰（時間欄位可能在兩次讀取之間更新，不比）
    let ids = |x: &serde_json::Value| -> Vec<(String, String)> {
        x["downstreams"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| (d["address"].to_string(), d["fingerprint"].to_string()))
            .collect()
    };
    assert_eq!(ids(&st["serving"]), ids(&v));
    assert_eq!(st["serving"]["text"], v["text"]);
}

#[tokio::test]
async fn allow_downstream_off_means_no_reg() {
    let u = start("off", false, true).await;
    let r = &u.s.resolver;
    let auth = auth_from(r, ip(DOWN)).await;
    assert!(auth.caps.is_empty());
    assert!(!auth.allow);
    let key = KeyPair::generate();
    let m = send_reg(
        r,
        ip(DOWN),
        &reg_query(2, Some(sealed_reg(&key, &reg_body(&key, &auth, &["dns.example.net"])))),
    )
    .await;
    assert_eq!(m.rcode, 5);
    // 回應器直接收到公網來源的登記（呼叫端的私有位址檢查之外）也一樣拒絕
    let resp = u.responder();
    let pubip = ip("203.0.113.5");
    let q = Message::parse(&reg_query(3, Some(sealed_reg(&key, &reg_body(&key, &auth, &["dns.example.net"]))))).unwrap();
    assert_eq!(resp.answer(&q, REG_NAME, &ctx(pubip)).rcode, 5);
    assert!(u.serving()["downstreams"].as_array().unwrap().is_empty());
    assert!(resp.grants().allowed_addrs(Instant::now()).is_empty());
    assert!(!resp.exempt(ip(DOWN), "dns.example.net"));
    assert!(is_blocked(r, ip(DOWN), "dns.example.net").await, "沒有任何豁免");
    let access = r.access.get().unwrap();
    assert_ne!(access.rules().explain(pubip).1, Reason::Downstream, "存取控制的下游集合是空的");
}

#[tokio::test]
async fn register_requires_valid_token_and_peer() {
    let u = start("token", true, false).await;
    let r = &u.s.resolver;
    let key = KeyPair::generate();
    // tok 是別的來源位址算出來的（peer 寫成自己）
    let a_other = auth_from(r, ip(OTHER)).await;
    let mut b = reg_body(&key, &a_other, &["dns.example.net"]);
    b.peer = DOWN.into();
    assert_eq!(
        send_reg(r, ip(DOWN), &reg_query(1, Some(sealed_reg(&key, &b)))).await.rcode,
        5,
        "tok 綁別的位址"
    );
    // peer 跟實際來源不同（tok 與 peer 都是別人的）
    let b = reg_body(&key, &a_other, &["dns.example.net"]);
    assert_eq!(
        send_reg(r, ip(DOWN), &reg_query(2, Some(sealed_reg(&key, &b)))).await.rcode,
        5,
        "peer 不符"
    );
    // tok 過期兩個時間窗
    let a = auth_from(r, ip(DOWN)).await;
    let now = kuroshio_community::util::now_ms();
    let mut b = reg_body(&key, &a, &["dns.example.net"]);
    b.tok = u.responder().token_at(DOWN, now - 2 * proto::TOKEN_WINDOW_MS).to_vec();
    assert_eq!(
        send_reg(r, ip(DOWN), &reg_query(3, Some(sealed_reg(&key, &b)))).await.rcode,
        5,
        "tok 過期"
    );
    assert!(u.serving()["downstreams"].as_array().unwrap().is_empty());
    // 前一個時間窗的 tok 還可以（下游每 5 分鐘更新）
    b.tok = u.responder().token_at(DOWN, now - proto::TOKEN_WINDOW_MS).to_vec();
    assert_eq!(send_reg(r, ip(DOWN), &reg_query(4, Some(sealed_reg(&key, &b)))).await.rcode, 0);
    // 合法的
    assert_eq!(register(r, ip(DOWN), &key, &["dns.example.net"]).await.0, 0);
    assert_eq!(u.serving()["downstreams"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn register_requires_downstream_signature() {
    let u = start("signature", true, false).await;
    let r = &u.s.resolver;
    let key = KeyPair::generate();
    let a = auth_from(r, ip(DOWN)).await;
    let body = reg_body(&key, &a, &["dns.example.net"]);
    // 簽章壞掉
    let mut s: proto::Sealed = from_cbor(&sealed_reg(&key, &body)).unwrap();
    s.sig[0] ^= 1;
    assert_eq!(send_reg(r, ip(DOWN), &reg_query(1, Some(to_cbor(&s)))).await.rcode, 5, "簽章壞掉");
    // 別人簽的（公鑰寫這把）
    let other = KeyPair::generate();
    assert_eq!(
        send_reg(r, ip(DOWN), &reg_query(2, Some(sealed_reg(&other, &body)))).await.rcode,
        5,
        "簽章不是 body 裡的公鑰"
    );
    // kid 與公鑰不符（簽章本身正確）
    let mut b = body.clone();
    b.kid = kid_of(&other.public).to_vec();
    assert_eq!(
        send_reg(r, ip(DOWN), &reg_query(3, Some(sealed_reg(&key, &b)))).await.rcode,
        5,
        "kid 不符"
    );
    // 沒帶 EDNS 選項
    assert_eq!(send_reg(r, ip(DOWN), &reg_query(4, None)).await.rcode, 5, "沒帶選項");
    // 不合法的名稱
    let mut b = body.clone();
    b.names = vec!["不合法 名稱".into()];
    assert_eq!(
        send_reg(r, ip(DOWN), &reg_query(5, Some(sealed_reg(&key, &b)))).await.rcode,
        5,
        "names 不合法"
    );
    assert!(u.serving()["downstreams"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn register_signed_for_other_upstream_rejected() {
    let u = start("other-up", true, false).await;
    let r = &u.s.resolver;
    let key = KeyPair::generate();
    let a = auth_from(r, ip(DOWN)).await;
    let mut b = reg_body(&key, &a, &["dns.example.net"]);
    b.up = KeyPair::generate().kid.to_vec();
    assert_eq!(send_reg(r, ip(DOWN), &reg_query(1, Some(sealed_reg(&key, &b)))).await.rcode, 5);
    assert!(u.serving()["downstreams"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn replayed_registration_from_other_address_rejected() {
    let u = start("replay", true, false).await;
    let key = KeyPair::generate();
    let a = auth_from(&u.s.resolver, ip("127.0.0.1")).await;
    let q = reg_query(1, Some(sealed_reg(&key, &reg_body(&key, &a, &["dns.example.net"]))));
    let ask = |from: &'static str, q: Vec<u8>, to: SocketAddr| async move {
        let s = UdpSocket::bind(format!("{from}:0")).await.unwrap();
        s.send_to(&q, to).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let (n, _) = tokio::time::timeout(Duration::from_secs(3), s.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        Message::parse(&buf[..n]).unwrap().rcode
    };
    assert_eq!(ask("127.0.0.1", q.clone(), u.s.bound[0]).await, 0);
    // 原樣從另一個來源位址重送
    assert_eq!(ask("127.0.0.2", q, u.s.bound[0]).await, 5, "peer 不符");
    let d = u.serving()["downstreams"].as_array().unwrap().clone();
    assert_eq!(d.len(), 1);
    assert_eq!(d[0]["address"], "127.0.0.1", "原本那一筆不受影響");
    assert!(u.responder().exempt(ip("127.0.0.1"), "dns.example.net"));
    assert!(!u.responder().exempt(ip("127.0.0.2"), "dns.example.net"));
}

// ---------------- 繞過防護清單 ----------------

#[tokio::test]
async fn unregistered_client_still_blocked() {
    let u = start("unregistered", true, true).await;
    let r = &u.s.resolver;
    assert!(is_blocked(r, ip(DOWN), "dns.example.net").await);
    // 只做了 auth、沒有登記：照擋
    auth_from(r, ip(DOWN)).await;
    assert!(is_blocked(r, ip(DOWN), "dns.example.net").await);
}

#[tokio::test]
async fn registered_downstream_bypass_exact_names_only() {
    let u = start("exact", true, true).await;
    let r = &u.s.resolver;
    let key = KeyPair::generate();
    let names = ["dns.example.net", "adsdns.example.net", "custom.example.net"];
    assert_eq!(register(r, ip(DOWN), &key, &names).await.0, 0);
    assert!(!is_blocked(r, ip(DOWN), "dns.example.net").await, "登記的名稱不擋");
    assert!(!is_blocked(r, ip(DOWN), "DNS.Example.NET.").await, "大小寫、結尾的點一樣");
    assert!(is_blocked(r, ip(DOWN), "other.example.net").await, "沒登記的名稱照擋");
    assert!(is_blocked(r, ip(DOWN), "x.dns.example.net").await, "登記名稱的子網域照擋");
    assert!(is_blocked(r, ip(DOWN), "adsdns.example.net").await, "不是 bypass 的清單照擋");
    assert!(is_blocked(r, ip(DOWN), "custom.example.net").await, "自訂規則照擋");
    assert!(is_blocked(r, ip(OTHER), "dns.example.net").await, "其他來源位址照擋");
    assert!(!is_blocked(r, ip(DOWN), "dns.example.net").await, "快取之後還是一樣");
}

#[tokio::test]
async fn self_made_downstream_is_granted_by_default() {
    // 已決定接受的行為（規格 T8）：任何能產生金鑰、會講協定的裝置都能登記並得到放行
    let u = start("self-made", true, true).await;
    let r = &u.s.resolver;
    let warnings_before = u.status().await["warnings"].clone();
    let key = KeyPair::generate();
    assert_eq!(register(r, ip(DOWN), &key, &["dns.example.net"]).await.0, 0);
    assert!(!is_blocked(r, ip(DOWN), "dns.example.net").await);
    let v = u.serving();
    let d = v["downstreams"].as_array().unwrap().clone();
    assert_eq!(d.len(), 1);
    assert_eq!(d[0]["fingerprint"], fingerprint(&key.public));
    assert_eq!(d[0]["address"], DOWN);
    assert!(
        v["note"].as_str().is_some_and(|n| n.contains("allow_downstream")),
        "說明只在 serving.note"
    );
    let w = u.status().await["warnings"].clone();
    assert_eq!(w, warnings_before, "不加任何 warnings");
    assert!(
        !w.as_array()
            .unwrap()
            .iter()
            .any(|x| x.as_str().is_some_and(|t| t.contains("下游") || t.contains("登記"))),
        "{w}"
    );
}

#[tokio::test]
async fn reload_with_allow_off_revokes() {
    let dir = test_dir("reload");
    let up = fake_upstream().await;
    let lists = list_server().await;
    let s = kuroshio::app::start(&cfg(&dir, up, Some(lists), true)).await.unwrap();
    let u = Up { s, dir: dir.clone() };
    let t0 = Instant::now();
    while !is_blocked(&u.s.resolver, ip(OTHER), "other.example.net").await {
        assert!(t0.elapsed() < Duration::from_secs(15), "清單沒有載入");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let key = KeyPair::generate();
    assert_eq!(register(&u.s.resolver, ip(DOWN), &key, &["dns.example.net"]).await.0, 0);
    assert!(!is_blocked(&u.s.resolver, ip(DOWN), "dns.example.net").await);
    // 公網位址的下游（直接交給回應器，略過私有位址檢查）：存取控制當成好友那一級放行
    let pubip = ip("203.0.113.5");
    let resp = u.responder();
    let a = {
        let nonce = kuroshio_community::util::random_bytes::<16>();
        let q = Message::parse(&chaos(1, &auth_name(&nonce))).unwrap();
        let m = resp.answer(&q, &auth_name(&nonce), &ctx(pubip));
        open_auth(&txt_of(&m).unwrap(), &nonce).unwrap()
    };
    let q = Message::parse(&reg_query(2, Some(sealed_reg(&key, &reg_body(&key, &a, &["dns.example.net"]))))).unwrap();
    assert_eq!(resp.answer(&q, REG_NAME, &ctx(pubip)).rcode, 0);
    let access = u.s.resolver.access.get().unwrap().clone();
    wait_for("存取控制更新", || access.rules().explain(pubip) == (true, Reason::Downstream)).await;

    // 重新建立（allowDownstream 關）：登記表跟著回應器重建，豁免與存取控制的放行都沒了
    let s2 = kuroshio::app::start(&cfg(&dir, up, Some(lists), false)).await.unwrap();
    let r2 = s2.resolver.clone();
    let t0 = Instant::now();
    while !is_blocked(&r2, ip(OTHER), "other.example.net").await {
        assert!(t0.elapsed() < Duration::from_secs(15), "清單沒有載入");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(is_blocked(&r2, ip(DOWN), "dns.example.net").await);
    let resp2 = r2.chain.get().unwrap();
    assert!(!resp2.exempt(ip(DOWN), "dns.example.net"));
    assert!(resp2.grants().allowed_addrs(Instant::now()).is_empty());
    assert_ne!(r2.access.get().unwrap().rules().explain(pubip).1, Reason::Downstream);
    // 舊的下游重送登記也不接受
    assert_eq!(register(&r2, ip(DOWN), &key, &["dns.example.net"]).await.0, 5);
}

/// 假過濾器：`dns.example.net` 被 bypass 清單擋、`ads.example.net` 被一般清單擋
struct FakeFilter;
impl FilterCheck for FakeFilter {
    fn check(&self, name: &str, _t: u16) -> Option<Verdict> {
        let bypass = name == "dns.example.net";
        (bypass || name == "ads.example.net").then(|| Verdict {
            block: true,
            allow: false,
            category: "ads",
            rule: format!("||{name}^"),
            bypass,
        })
    }
}

#[tokio::test]
async fn bypass_exemption_expires() {
    let dir = test_dir("expires");
    let up = fake_upstream().await;
    let c = cfg(&dir, up, None, true);
    let r = kuroshio::app::build_resolver(&c).unwrap();
    r.set_filter(Some(Arc::new(FakeFilter)));
    let settings = ChainSettings::from_cfg(&c);
    let grants = Grants::with_ttl(&settings, Duration::from_secs(1));
    let _ = r.chain.set(Responder::with_grants(
        &settings,
        Arc::new(NodeKey::new(dir.join("keys"))),
        grants.clone(),
    ));
    let key = KeyPair::generate();
    let (rc, ack) = register(&r, ip(DOWN), &key, &["dns.example.net", "ads.example.net"]).await;
    assert_eq!(rc, 0);
    assert_eq!(ack.unwrap().ttl, 1);
    assert!(!is_blocked(&r, ip(DOWN), "dns.example.net").await);
    assert!(is_blocked(&r, ip(DOWN), "ads.example.net").await, "不是 bypass 的清單照擋");
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(is_blocked(&r, ip(DOWN), "dns.example.net").await, "登記到期後照擋");
    assert!(grants.allowed_addrs(Instant::now()).is_empty());
    grants.sweep(Instant::now());
    assert_eq!(grants.count(), 0);
}

#[tokio::test]
async fn cname_target_on_bypass_list() {
    let u = start("cname", true, true).await;
    let r = &u.s.resolver;
    let key = KeyPair::generate();
    assert_eq!(register(r, ip(DOWN), &key, &["dns.example.net"]).await.0, 0);
    let blocked0 = r.stats.summary()["today"]["blocked"].as_u64().unwrap();
    // 下游先問：拿到答案
    let resp = r
        .handle(&kuroshio_proto::build_query(1, "a.example.com", 1), &ctx(ip(DOWN)))
        .await
        .unwrap();
    let m = Message::parse(&resp).unwrap();
    assert!(
        m.answers.iter().any(|a| a.data == RData::A(Ipv4Addr::new(192, 0, 2, 1))),
        "{:?}",
        m.answers
    );
    assert_eq!(r.stats.summary()["today"]["blocked"].as_u64().unwrap(), blocked0, "豁免的不算攔截");
    // 快取項目只記「哪個 CNAME 目標命中 bypass 清單」
    let e = r.cache.lock().unwrap().peek("1|a.example.com").unwrap();
    assert_eq!(e.blocked_bypass.as_deref(), Some("dns.example.net"));
    assert!(e.blocked.is_some());
    // 另一個用戶端吃同一筆快取：被擋
    assert!(is_blocked(r, ip(OTHER), "a.example.com").await);
    // 反過來：另一個用戶端先問（寫進快取），下游再問同一筆
    assert!(is_blocked(r, ip(OTHER), "b.example.com").await);
    assert!(!is_blocked(r, ip(DOWN), "b.example.com").await);
}

#[tokio::test]
async fn registry_bounded() {
    let u = start("bounded", true, false).await;
    let r = &u.s.resolver;
    let keys: Vec<KeyPair> = (0..17).map(|_| KeyPair::generate()).collect();
    for (i, k) in keys.iter().enumerate() {
        let from = IpAddr::from([192, 168, 2, i as u8 + 1]);
        let (rc, _) = register(r, from, k, &["dns.example.net"]).await;
        if i < 16 {
            assert_eq!(rc, 0, "第 {} 個", i + 1);
        } else {
            assert_eq!(rc, 5, "第 17 個被拒");
        }
    }
    let resp = u.responder();
    assert_eq!(resp.grants().count(), 16);
    assert!(!resp.exempt(ip("192.168.2.17"), "dns.example.net"));
    // 同一個 kid 換位址：舊位址的放行立刻失效
    assert_eq!(register(r, ip("192.168.3.1"), &keys[0], &["dns.example.net"]).await.0, 0);
    assert!(!resp.exempt(ip("192.168.2.1"), "dns.example.net"));
    assert!(resp.exempt(ip("192.168.3.1"), "dns.example.net"));
    assert!(!resp.grants().allowed_addrs(Instant::now()).contains(&ip("192.168.2.1")));
    assert_eq!(resp.grants().count(), 16);
    // 同一個位址換 kid：還是一筆
    let fresh = KeyPair::generate();
    assert_eq!(register(r, ip("192.168.3.1"), &fresh, &["dns.example.net"]).await.0, 0);
    assert_eq!(resp.grants().count(), 16);
    let d = u.serving()["downstreams"].as_array().unwrap().clone();
    let at: Vec<&Value> = d.iter().filter(|x| x["address"] == "192.168.3.1").collect();
    assert_eq!(at.len(), 1);
    assert_eq!(at[0]["fingerprint"], fingerprint(&fresh.public));
}

/// 目錄底下所有檔案（路徑、大小、修改時間）
fn snapshot(dir: &Path) -> Vec<(PathBuf, u64, std::time::SystemTime)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let m = e.metadata().unwrap();
            if m.is_dir() {
                stack.push(e.path());
            } else {
                out.push((e.path(), m.len(), m.modified().unwrap()));
            }
        }
    }
    out.sort();
    out
}

#[tokio::test]
async fn registry_is_memory_only() {
    let u = start("memory-only", true, false).await;
    let r = &u.s.resolver;
    // 先做一次 auth（第一次 auth 會建立上游的節點金鑰，那不是登記造成的）
    auth_from(r, ip(DOWN)).await;
    let before = snapshot(&u.dir);
    let key = KeyPair::generate();
    assert_eq!(register(r, ip(DOWN), &key, &["dns.example.net"]).await.0, 0);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(u.responder().grants().count(), 1);
    assert_eq!(snapshot(&u.dir), before, "登記不寫任何檔案");
}

/// 相容：`allow_downstream` 關、或開著但沒有任何登記時，過濾（含 CNAME 目標、統計）與存取控制跟 3.3.7 一樣
#[tokio::test]
async fn no_downstreams_behaves_like_3_3_7() {
    for allow in [true, false] {
        let u = start(if allow { "compat-on" } else { "compat-off" }, allow, true).await;
        let r = &u.s.resolver;
        // 有人做過 auth（拿到 tok）但沒有登記
        auth_from(r, ip(DOWN)).await;
        let blocked0 = r.stats.summary()["today"]["blocked"].as_u64().unwrap();
        let mut n = 0;
        for client in [DOWN, OTHER] {
            for name in ["dns.example.net", "a.example.com", "adsdns.example.net", "custom.example.net"] {
                assert!(is_blocked(r, ip(client), name).await, "allow {allow}：{client} {name}");
                n += 1;
            }
            assert!(!is_blocked(r, ip(client), "fine.example.com").await);
        }
        assert_eq!(
            r.stats.summary()["today"]["blocked"].as_u64().unwrap(),
            blocked0 + n,
            "每一次都算攔截"
        );
        let access = r.access.get().unwrap();
        let (ok, why) = access.rules().explain(ip("203.0.113.5"));
        assert!(!ok && why != Reason::Downstream, "{why:?}");
        assert!(u.responder().grants().allowed_addrs(Instant::now()).is_empty());
    }
}
