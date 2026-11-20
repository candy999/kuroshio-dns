//! 串接模式（3.4.0）的下游狀態機：用本機的假上游黑潮（WP1 的 `seal`／`AuthBody` 自己組回應）與冒充者，
//! 確認探測、驗證、綁定、心跳、解除與重新綁定，以及「不該發的時候一筆 `chain.kuroshio` 查詢都不發」。

use kuroshio::chain::client::{Client, Reason, State, Timing};
use kuroshio::chain::ident::NodeKey;
use kuroshio::upstreams::{Manager, Role};
use kuroshio_community::chain::{self as proto, AuthBody};
use kuroshio_community::envelope::to_cbor;
use kuroshio_community::identity::{fingerprint, Identity, KeyPair};
use kuroshio_config::chain::ChainSettings;
use kuroshio_net::path::{Interceptor, Plain, Report, Tamper};
use kuroshio_proto::message::{Message, RData, Record};
use serde_json::json;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

// ---------------- 假的上游黑潮 ----------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// 正常回答
    Legit,
    /// 冒充者：公鑰寫 `key` 的，簽章用 `other`
    WrongSigner,
    /// 冒充者：把先前錄下的合法回應原樣回給新的挑戰（別的 nonce）
    Replay,
}

struct Upstream {
    key: Mutex<KeyPair>,
    other: KeyPair,
    mode: Mutex<Mode>,
    allow: AtomicBool,
    path: Mutex<Vec<Vec<u8>>>,
    /// 停止回答（模擬上游掛掉）
    silent: AtomicBool,
    /// 收到的 chain.kuroshio 查詢數（UDP／TCP）
    chain_udp: AtomicUsize,
    chain_tcp: AtomicUsize,
    /// 最近一次合法回應的內容（重放用）
    recorded: Mutex<Option<Vec<u8>>>,
    /// 收到並接受的登記（WP6）
    regs: Mutex<Vec<proto::RegBody>>,
}

impl Upstream {
    fn new() -> Arc<Upstream> {
        Arc::new(Upstream {
            key: Mutex::new(KeyPair::generate()),
            other: KeyPair::generate(),
            mode: Mutex::new(Mode::Legit),
            allow: AtomicBool::new(true),
            path: Mutex::new(Vec::new()),
            silent: AtomicBool::new(false),
            chain_udp: AtomicUsize::new(0),
            chain_tcp: AtomicUsize::new(0),
            recorded: Mutex::new(None),
            regs: Mutex::new(Vec::new()),
        })
    }

    fn chain_queries(&self) -> usize {
        self.chain_udp.load(Ordering::SeqCst) + self.chain_tcp.load(Ordering::SeqCst)
    }

    fn public(&self) -> [u8; 32] {
        self.key.lock().unwrap().public
    }

    fn answer(&self, q: &[u8], tcp: bool) -> Option<Vec<u8>> {
        let m = Message::parse(q).ok()?;
        let qs = m.questions.first()?.clone();
        let name = qs.name.to_ascii_lowercase();
        if proto::in_zone(&name) {
            if tcp {
                self.chain_tcp.fetch_add(1, Ordering::SeqCst);
            } else {
                self.chain_udp.fetch_add(1, Ordering::SeqCst);
            }
        }
        if self.silent.load(Ordering::SeqCst) {
            return None;
        }
        let mut r = Message::response_to(&m, 0);
        let payload = match (qs.qclass, proto::parse_name(&name)) {
            (3, Some(proto::Name::Auth(nonce))) => self.auth(&nonce),
            (3, Some(proto::Name::Reg)) => match self.reg(&m) {
                Some(p) => p,
                None => {
                    r.rcode = 5;
                    return Some(r.encode());
                }
            },
            (3, _) => {
                r.rcode = 5;
                return Some(r.encode());
            }
            _ => {
                r.answers.push(Record::a(&qs.name, 60, "198.51.100.10".parse().unwrap()));
                return Some(r.encode());
            }
        };
        r.answers.push(Record {
            name: qs.name.clone(),
            rtype: 16,
            class: 3,
            ttl: 0,
            data: RData::Raw(proto::txt_rdata(&payload)),
        });
        Some(r.encode())
    }

    /// 登記：驗下游的簽章、`up` 是自己，回 regack（真的上游另外檢查 peer 與 tok，見 chain_grants.rs）
    fn reg(&self, m: &Message) -> Option<Vec<u8>> {
        let opt = m.opt.as_ref()?.options.iter().find(|(c, _)| *c == proto::OPT_CODE)?;
        let body = proto::open_reg(&opt.1).ok()?;
        let key = self.key.lock().unwrap();
        if body.up != key.kid.to_vec() {
            return None;
        }
        let ack = proto::RegAck {
            v: proto::PROTO,
            t: "regack".into(),
            kid: body.kid.clone(),
            ttl: 900,
        };
        self.regs.lock().unwrap().push(body);
        Some(proto::seal(&key, "regack", to_cbor(&ack)))
    }

    fn auth(&self, nonce: &[u8; 16]) -> Vec<u8> {
        let mode = *self.mode.lock().unwrap();
        if mode == Mode::Replay {
            if let Some(old) = self.recorded.lock().unwrap().clone() {
                return old;
            }
        }
        let key = self.key.lock().unwrap();
        let allow = self.allow.load(Ordering::SeqCst);
        let mut path = self.path.lock().unwrap().clone();
        path.push(key.kid.to_vec());
        let body = AuthBody {
            v: proto::PROTO,
            t: "auth".into(),
            nonce: nonce.to_vec(),
            ts: 1,
            kid: key.kid.to_vec(),
            public: key.public.to_vec(),
            app: "3.4.0".into(),
            allow,
            caps: if allow { vec!["share".into(), "reg".into()] } else { vec![] },
            peer: "127.0.0.1".into(),
            tok: vec![7; 16],
            path,
        };
        let signer = if mode == Mode::WrongSigner { &self.other } else { &*key };
        let sealed = proto::seal(signer, "auth", to_cbor(&body));
        if mode == Mode::Legit {
            *self.recorded.lock().unwrap() = Some(sealed.clone());
        }
        sealed
    }
}

/// 假的上游黑潮（UDP 與 TCP 同一個埠）
async fn fake_upstream(u: Arc<Upstream>) -> SocketAddr {
    // UDP 與 TCP 要同一個埠：TCP 那個埠剛好被占用就換一個
    let (s, l) = loop {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        if let Ok(l) = TcpListener::bind(s.local_addr().unwrap()).await {
            break (s, l);
        }
    };
    let addr = s.local_addr().unwrap();
    {
        let u = u.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, from)) = s.recv_from(&mut buf).await else { break };
                if let Some(r) = u.answer(&buf[..n], false) {
                    let _ = s.send_to(&r, from).await;
                }
            }
        });
    }
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { break };
            let u = u.clone();
            tokio::spawn(async move {
                loop {
                    let Ok(len) = s.read_u16().await else { return };
                    let mut q = vec![0u8; len as usize];
                    if s.read_exact(&mut q).await.is_err() {
                        return;
                    }
                    let Some(r) = u.answer(&q, true) else { continue };
                    let mut out = (r.len() as u16).to_be_bytes().to_vec();
                    out.extend_from_slice(&r);
                    if s.write_all(&out).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

/// 沒有人在聽的埠
fn closed() -> SocketAddr {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    s.local_addr().unwrap()
}

// ---------------- 下游 ----------------

fn timing() -> Timing {
    Timing {
        ask: Duration::from_millis(300),
        heartbeat: Duration::from_millis(400),
        early_min: Duration::from_millis(50),
        early_max: Duration::from_millis(100),
        retry_min: Duration::from_millis(200),
        retry_max: Duration::from_millis(800),
        fail_limit: 3,
    }
}

fn settings(chain: bool) -> ChainSettings {
    ChainSettings::from_cfg(&kuroshio_config::build(&json!({ "upstream": { "chain": chain } })))
}

struct Down {
    client: Arc<Client>,
    mgr: Arc<Manager>,
    dir: PathBuf,
}

impl Drop for Down {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn tmpdir(tag: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!(
        "kuroshio-chain-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// 下游的 Manager：固定上游一台（文件用位址），自動上游一台加密的（評測結果檔）
fn manager(dir: &std::path::Path) -> Arc<Manager> {
    let state = dir.join("upstreams.json");
    std::fs::write(
        &state,
        r#"{"generatedAt":"2026-11-10 04:30","selected":[{"id":"https://dns.example.net/dns-query","type":"doh"}]}"#,
    )
    .unwrap();
    let cfg = kuroshio_config::with_overrides(&json!({
        "upstream": { "pinned": ["udp://198.51.100.53"], "fallback": [], "autoTypes": ["udp", "doh"] },
        "resolver": { "lastResort": [] }
    }));
    Arc::new(Manager::new(&cfg, state))
}

fn down(chain: bool) -> Down {
    let dir = tmpdir("down");
    std::fs::create_dir_all(dir.join("community")).unwrap();
    let key = Arc::new(NodeKey::new(dir.join("community")));
    let s = settings(chain);
    let client = Client::new(s.clone(), key, timing());
    let mgr = manager(&dir);
    client.attach(s, &mgr, None);
    client.spawn();
    Down { client, mgr, dir }
}

fn report(hit: Option<SocketAddr>, interceptor: Option<Interceptor>) -> Report {
    Report {
        plain_v4: Plain {
            udp: hit.is_some(),
            tcp: hit.is_some(),
        },
        interceptor: hit.and(interceptor),
        hit,
        ..Report::default()
    }
}

fn kuroshio(addr: SocketAddr) -> Report {
    report(Some(addr), Some(Interceptor::Kuroshio("3.4.0".into())))
}

async fn wait_for(what: &str, limit: Duration, mut f: impl FnMut() -> bool) {
    let t0 = Instant::now();
    while !f() {
        assert!(t0.elapsed() < limit, "等不到：{what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn ids(m: &Manager) -> Vec<String> {
    m.active().iter().map(|u| u.up.id.clone()).collect()
}

fn own_ids() -> Vec<String> {
    vec!["udp://198.51.100.53:53".into(), "https://dns.example.net/dns-query".into()]
}

// ---------------- 不發任何查詢 ----------------

#[tokio::test]
async fn no_interception_sends_nothing() {
    let u = Upstream::new();
    let _a = fake_upstream(u.clone()).await;
    let d = down(true);
    d.client.on_path_report(&report(None, None)).await;
    assert_eq!(d.client.state(), (State::None, None));
    assert_eq!(u.chain_queries(), 0);
    assert_eq!(ids(&d.mgr), own_ids());
    assert_eq!(d.client.status_json()["text"], "沒有偵測到上游黑潮");
    assert!(d.client.interceptor_json().is_null());
}

#[tokio::test]
async fn non_kuroshio_interceptor_sends_nothing() {
    let u = Upstream::new();
    let a = fake_upstream(u.clone()).await;
    let d = down(true);
    for i in [Interceptor::Software("dnsmasq-2.90".into()), Interceptor::Unknown] {
        d.client.on_path_report(&report(Some(a), Some(i))).await;
        assert_eq!(d.client.state().0, State::None);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(u.chain_queries(), 0);
}

#[tokio::test]
async fn old_kuroshio_gets_no_challenge() {
    let u = Upstream::new();
    let a = fake_upstream(u.clone()).await;
    let d = down(true);
    d.client
        .on_path_report(&report(Some(a), Some(Interceptor::Kuroshio("3.3.7".into()))))
        .await;
    assert_eq!(d.client.state(), (State::Released, Some(Reason::UpstreamTooOld)));
    tokio::time::sleep(Duration::from_millis(1000)).await;
    assert_eq!(u.chain_queries(), 0, "沒有收到任何 chain.kuroshio 查詢");
    assert_eq!(ids(&d.mgr), own_ids());
    assert_eq!(d.client.status_json()["text"], "上游黑潮 3.3.7 不支援串接（需要 3.4.0 以上）");
}

#[tokio::test]
async fn chain_off_sends_nothing() {
    let u = Upstream::new();
    let a = fake_upstream(u.clone()).await;
    let d = down(false);
    let r = kuroshio(a);
    d.client.on_path_report(&r).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(d.client.state(), (State::None, None));
    assert_eq!(u.chain_queries(), 0);
    let s = d.client.status_json();
    assert_eq!(s["enabled"], false);
    assert_eq!(
        s["text"],
        "已關閉串接（chain 關閉）：把上游黑潮當成一般的 DNS 攔截，自己做評測，會重複使用網路"
    );
    assert!(s["upstream"].is_null());
    assert!(d.client.interceptor_json().is_null());
    // 解析跟 3.3.7 一樣：固定 + 自動；路徑檢查照樣有「一般 DNS 被…接走」的提醒
    assert_eq!(ids(&d.mgr), own_ids());
    assert!(d.mgr.chain().is_none());
    assert!(!d.client.is_chained());
    assert!(r
        .warnings("skip-plain")
        .iter()
        .any(|w| kuroshio::pathcheck::is_intercept_warning(w)));
}

// ---------------- 串接 ----------------

#[tokio::test]
async fn detects_verifies_and_chains_automatically() {
    let u = Upstream::new();
    let a = fake_upstream(u.clone()).await;
    let d = down(true);
    let before: Vec<_> = std::fs::read_dir(&d.dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();
    d.client.on_path_report(&kuroshio(a)).await;
    assert_eq!(d.client.state(), (State::Chained, None));
    let active = d.mgr.active();
    assert_eq!(active[0].role, Role::Chain);
    assert_eq!(active[0].up.id, format!("udp://{a}"));
    assert_eq!(active.len(), 2, "串接上游 + 固定上游，自動上游不問");
    assert!(
        d.mgr.backup().iter().any(|x| x.up.id.starts_with("https://")),
        "自己的加密上游在備援"
    );
    let s = d.client.status_json();
    assert!(s["text"].as_str().unwrap().starts_with("串接中：上游"), "{s}");
    assert_eq!(s["state"], "chained");
    assert_eq!(s["upstream"]["fingerprint"], fingerprint(&u.public()));
    assert_eq!(s["upstream"]["via"], "intercept");
    assert_eq!(s["upstream"]["proto"], "udp");
    assert_eq!(s["upstream"]["depth"], 2);
    assert_eq!(s["upstream"]["allowDownstream"], true);
    assert_eq!(d.client.bound_key(), Some(u.public()));
    assert_eq!(d.client.bound_addr(), Some((a, true)));
    assert_eq!(d.client.last_probe().unwrap().tok, vec![7; 16]);
    let ic = d.client.interceptor_json();
    assert_eq!(ic["supported"], true);
    assert_eq!(ic["allowDownstream"], true);
    assert_eq!(ic["caps"], json!(["share", "reg"]));
    assert!(d.mgr.list_json()[0]["role"] == "chain");
    // 不寫任何狀態檔（金鑰只在 community 目錄裡）
    let after: Vec<_> = std::fs::read_dir(&d.dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();
    assert_eq!(before, after);
    // 上游公告了 reg：探測之後登記（WP6），這時才建立自己的節點金鑰
    assert_eq!(s["upstream"]["registered"]["ok"], true, "{s}");
    assert_eq!(
        s["upstream"]["registered"]["names"], 1,
        "自動上游 dns.example.net（固定上游是 IP，不算）"
    );
    assert!(s["upstream"]["registered"]["expiresAt"].as_u64().unwrap() > s["upstream"]["registered"]["at"].as_u64().unwrap());
    {
        let regs = u.regs.lock().unwrap();
        assert_eq!(regs.len(), 1);
        assert_eq!(regs[0].names, vec!["dns.example.net".to_string()]);
        assert_eq!(regs[0].peer, "127.0.0.1");
        assert_eq!(regs[0].tok, vec![7; 16]);
        assert!(regs[0].local, "127.0.0.1 是這台自己的位址：沒有經過 NAT");
    }
    assert!(d.dir.join("community").join("key.pem").exists());
    assert!(d.client.key_change_warning(kuroshio_community::util::now_ms()).is_none());
    // 提早心跳之後照樣串接中
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(d.client.is_chained());
}

#[tokio::test]
async fn impostor_wrong_signature_rejected() {
    let u = Upstream::new();
    *u.mode.lock().unwrap() = Mode::WrongSigner;
    let a = fake_upstream(u.clone()).await;
    let d = down(true);
    d.client.on_path_report(&kuroshio(a)).await;
    assert_eq!(d.client.state(), (State::Released, Some(Reason::VerifyFailed)));
    assert_eq!(ids(&d.mgr), own_ids());
    assert!(d.mgr.chain().is_none());
    let ic = d.client.interceptor_json();
    assert_eq!(ic["supported"], true);
    assert!(ic["error"].as_str().unwrap().contains("簽章"), "{ic}");
}

#[tokio::test]
async fn impostor_replays_old_response() {
    let u = Upstream::new();
    let a = fake_upstream(u.clone()).await;
    // 先錄下一個合法回應
    let p = kuroshio::chain::client::probe(a, false, Duration::from_millis(500)).await;
    assert!(p.error.is_none());
    *u.mode.lock().unwrap() = Mode::Replay;
    let d = down(true);
    d.client.on_path_report(&kuroshio(a)).await;
    assert_eq!(d.client.state(), (State::Released, Some(Reason::VerifyFailed)));
    assert!(d.mgr.chain().is_none());
    assert!(d.client.interceptor_json()["error"].as_str().unwrap().contains("nonce"));
}

#[tokio::test]
async fn key_change_rebinds_and_warns() {
    let u = Upstream::new();
    let a = fake_upstream(u.clone()).await;
    let d = down(true);
    d.client.on_path_report(&kuroshio(a)).await;
    assert!(d.client.is_chained());
    let old = fingerprint(&u.public());
    let now = kuroshio_community::util::now_ms();
    assert!(d.client.key_change_warning(now).is_none(), "第一次綁定沒有警告");
    // 上游換了一把金鑰（重灌、換機器、或有人冒充）
    *u.key.lock().unwrap() = KeyPair::generate();
    let new = u.public();
    let c = d.client.clone();
    wait_for("綁定新的公鑰", Duration::from_secs(5), || {
        c.bound_key() == Some(new) && c.is_chained()
    })
    .await;
    let s = d.client.status_json();
    assert_eq!(s["upstream"]["previousFingerprint"], old);
    assert_eq!(s["upstream"]["fingerprint"], fingerprint(&new));
    assert!(s["upstream"]["keyChangedAt"].is_u64());
    assert!(s["text"].as_str().unwrap().contains("上游節點的金鑰換過"), "{s}");
    let now = kuroshio_community::util::now_ms();
    let w = d.client.key_change_warning(now).expect("24 小時內有警告");
    assert!(w.contains("上游節點的金鑰換過") && w.contains(&old), "{w}");
    assert!(d.client.key_change_warning(now + 25 * 3600 * 1000).is_none());
    assert_eq!(d.mgr.active()[0].role, Role::Chain);
}

#[tokio::test]
async fn allow_false_is_not_allowed() {
    let u = Upstream::new();
    u.allow.store(false, Ordering::SeqCst);
    let a = fake_upstream(u.clone()).await;
    let d = down(true);
    d.client.on_path_report(&kuroshio(a)).await;
    assert_eq!(d.client.state(), (State::Released, Some(Reason::NotAllowed)));
    assert_eq!(ids(&d.mgr), own_ids());
    let s = d.client.status_json();
    assert_eq!(s["upstream"]["allowDownstream"], false);
    assert_eq!(
        s["text"],
        "上游黑潮 3.4.0 不提供資料（allow_downstream 關閉）：自己做評測，會重複使用網路；每 10 分鐘確認一次，上游重新開放就自動接回"
    );
    assert!(s["retryAt"].is_u64(), "排了下一次確認：{s}");
    assert_eq!(d.client.interceptor_json()["allowDownstream"], false);
    assert_eq!(u.chain_queries(), 1);
    // 3.4.2：每隔 retry_max（測試裡 0.8 秒，加 0～20%）只探測一次，不登記、不問共用結果
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(u.chain_queries(), 2, "過了一次 retry_max：再探測一次");
    assert_eq!(d.client.state().1, Some(Reason::NotAllowed));
    // 上游重新開放：下一次確認就自動接回，不必等路徑檢查
    u.allow.store(true, Ordering::SeqCst);
    let t0 = std::time::Instant::now();
    while d.client.state().0 != State::Chained {
        assert!(
            t0.elapsed() < Duration::from_secs(3),
            "上游重新開放後沒有自動接回：{:?}",
            d.client.state()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(d.mgr.active()[0].role, Role::Chain);
}

#[tokio::test]
async fn loop_and_depth_rejected() {
    let u = Upstream::new();
    let a = fake_upstream(u.clone()).await;
    let d = down(true);
    // 這台自己的金鑰（跟社群共享同一把）
    let me = Identity::load_or_create(&d.dir.join("community")).unwrap().key.kid;
    *u.path.lock().unwrap() = vec![me.to_vec()];
    d.client.on_path_report(&kuroshio(a)).await;
    assert_eq!(d.client.state(), (State::Released, Some(Reason::Loop)));
    // 上游的鏈已經 4 層（含上游自己）
    *u.path.lock().unwrap() = vec![vec![1; 8], vec![2; 8], vec![3; 8]];
    d.client.on_path_report(&kuroshio(a)).await;
    assert_eq!(d.client.state(), (State::Released, Some(Reason::TooDeep)));
    assert!(d.mgr.chain().is_none());
    // 3 層可以
    *u.path.lock().unwrap() = vec![vec![1; 8], vec![2; 8]];
    d.client.on_path_report(&kuroshio(a)).await;
    assert_eq!(d.client.state(), (State::Chained, None));
    assert_eq!(d.client.status_json()["upstream"]["depth"], 4);
}

#[tokio::test]
async fn gateway_direct_preferred_when_same_key() {
    let u = Upstream::new();
    let a = fake_upstream(u.clone()).await;
    // 閘道上的是同一台（同一把金鑰）
    let g = Arc::new(Upstream {
        key: Mutex::new(KeyPair::from_pem(&u.key.lock().unwrap().to_pem()).unwrap()),
        ..Arc::into_inner(Upstream::new()).unwrap()
    });
    let ga = fake_upstream(g).await;
    let d = down(true);
    d.client.set_gateway_override(Some(Some(ga)));
    d.client.on_path_report(&kuroshio(a)).await;
    assert!(d.client.is_chained());
    assert_eq!(d.client.status_json()["upstream"]["via"], "gateway");
    assert_eq!(d.mgr.chain().unwrap().up.id, format!("udp://{ga}"));
    assert!(d.client.status_json()["text"]
        .as_str()
        .unwrap()
        .starts_with(&format!("串接中：上游 {}（黑潮 3.4.0）", ga.ip())));

    // 閘道上是別台（不同金鑰）或沒回應 → 用命中的保留位址
    let other = fake_upstream(Upstream::new()).await;
    for gw in [other, closed()] {
        let d = down(true);
        d.client.set_gateway_override(Some(Some(gw)));
        d.client.on_path_report(&kuroshio(a)).await;
        assert!(d.client.is_chained());
        assert_eq!(d.client.status_json()["upstream"]["via"], "intercept");
        assert_eq!(d.mgr.chain().unwrap().up.id, format!("udp://{a}"));
        assert!(d.client.status_json()["text"].as_str().unwrap().starts_with("串接中：上游黑潮"));
    }
}

#[tokio::test]
async fn heartbeat_failure_releases_and_recovers() {
    let u = Upstream::new();
    let a = fake_upstream(u.clone()).await;
    let d = down(true);
    d.client.on_path_report(&kuroshio(a)).await;
    assert!(d.client.is_chained());
    u.silent.store(true, Ordering::SeqCst);
    let c = d.client.clone();
    wait_for("沒回應而解除", Duration::from_secs(10), || {
        c.state() == (State::Released, Some(Reason::NoResponse))
    })
    .await;
    assert_eq!(ids(&d.mgr), own_ids(), "回到自己的上游");
    let s = d.client.status_json();
    assert_eq!(s["backupActive"], true);
    assert_eq!(s["text"], "串接中斷：上游沒有回應，暫時用自己的加密上游");
    assert!(s["retryAt"].is_u64());
    // 上游回來：重試後自動接回，同一把金鑰不算換了
    u.silent.store(false, Ordering::SeqCst);
    wait_for("自動接回", Duration::from_secs(10), || c.is_chained()).await;
    assert_eq!(d.mgr.active()[0].role, Role::Chain);
    assert!(d.client.key_change_warning(kuroshio_community::util::now_ms()).is_none());
}

#[tokio::test]
async fn wan_changed_releases_immediately() {
    let u = Upstream::new();
    let a = fake_upstream(u.clone()).await;
    let d = down(true);
    d.client.on_path_report(&kuroshio(a)).await;
    assert!(d.client.is_chained());
    d.client.on_wan_changed();
    assert_eq!(d.client.state().0, State::None);
    assert!(d.mgr.chain().is_none());
    assert_eq!(ids(&d.mgr), own_ids());
    d.client.on_path_report(&kuroshio(a)).await;
    assert!(d.client.is_chained());
}

#[tokio::test]
async fn tampered_interceptor_releases() {
    let u = Upstream::new();
    let a = fake_upstream(u.clone()).await;
    let d = down(true);
    d.client.on_path_report(&kuroshio(a)).await;
    assert!(d.client.is_chained());
    let mut r = kuroshio(a);
    r.tampered = vec![Tamper {
        via: "interceptor".into(),
        name: "dns.google".into(),
        answer: vec!["198.51.100.7".parse().unwrap()],
    }];
    d.client.on_path_report(&r).await;
    assert_eq!(d.client.state(), (State::Released, Some(Reason::Tampered)));
    assert!(d.mgr.chain().is_none());
    // 竄改的是 bootstrap 伺服器（不是攔截者）：照樣串接
    let mut r = kuroshio(a);
    r.tampered = vec![Tamper {
        via: "203.0.113.53".into(),
        name: "dns.google".into(),
        answer: vec!["198.51.100.7".parse().unwrap()],
    }];
    d.client.on_path_report(&r).await;
    assert!(d.client.is_chained());
}

#[tokio::test]
async fn reload_keeps_binding() {
    let u = Upstream::new();
    let a = fake_upstream(u.clone()).await;
    let d = down(true);
    d.client.on_path_report(&kuroshio(a)).await;
    assert!(d.client.is_chained());
    let n = u.chain_queries();
    // 新的一輪：新的 Manager 立刻有串接上游（不用重新探測）
    let m2 = manager(&d.dir);
    d.client.attach(settings(true), &m2, None);
    assert_eq!(m2.chain().unwrap().up.id, format!("udp://{a}"));
    assert_eq!(m2.active()[0].role, Role::Chain);
    assert_eq!(u.chain_queries(), n, "接回不需要探測");
    // 接回後在背景做一次心跳
    d.client.spawn();
    let u2 = u.clone();
    wait_for("接回後的心跳", Duration::from_secs(3), || u2.chain_queries() > n).await;
    // 改成 chain 關：新的 Manager 沒有串接上游、狀態 None
    let m3 = manager(&d.dir);
    d.client.attach(settings(false), &m3, None);
    assert!(m3.chain().is_none());
    assert_eq!(d.client.state().0, State::None);
    assert_eq!(d.client.status_json()["enabled"], false);
}

#[tokio::test]
async fn tcp_only_interception_uses_tcp() {
    let u = Upstream::new();
    let a = fake_upstream(u.clone()).await;
    let d = down(true);
    let mut r = kuroshio(a);
    r.plain_v4.udp = false;
    r.hit_tcp = true;
    d.client.on_path_report(&r).await;
    assert!(d.client.is_chained());
    assert_eq!(u.chain_udp.load(Ordering::SeqCst), 0, "只走 TCP");
    assert!(u.chain_tcp.load(Ordering::SeqCst) >= 2);
    assert_eq!(d.mgr.chain().unwrap().up.id, format!("tcp://{a}"));
    assert_eq!(d.client.status_json()["upstream"]["proto"], "tcp");
}
