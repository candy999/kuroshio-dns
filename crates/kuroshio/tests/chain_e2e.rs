#![cfg(unix)]
//! 串接模式（3.4.0）的端對端測試：兩到三個真正的 `kuroshio run` 子程序（各自的設定檔、快照目錄、
//! 金鑰目錄、不同的埠），照 `docs/spec/10-chain-tasks.md` 最後的「整合測試計畫」。
//!
//! - 路徑檢查與串接的狀態是行程層級的，所以每一台都是獨立的子程序。
//! - 模擬 DNAT：下游的 `KUROSHIO_PATH_TARGETS` 把保留位址換成測試裡的轉送器（[`Dnat`]），轉送器把
//!   UDP／TCP 原封不動轉給上游黑潮（目標可以換：上游停掉、換一台時下游看到的位址不變，跟真的 DNAT 一樣）。
//! - 版本：工作區的版本還沒改成 3.4.0 之前（發行前才改），上游回答的 `version.kuroshio` 是
//!   `kuroshio/3.3.x`，下游會判斷成「版本太舊」而不發挑戰。這時轉送器只把 `version.kuroshio` 的回答
//!   改寫成 `kuroshio/3.4.0`；版本改好之後這個改寫自動不做（見 [`rewrite_version`]）。
//! - 不連外：上游黑潮的上游是測試裡的假 DNS（`198.51.100.10`），下游自己的上游是另一個假 DNS
//!   （`198.51.100.20`，代替「自己的加密上游」），`autoTypes: []` 不載入種子資料裡的網際網路上游，
//!   評測、CDN、社群共享都關掉；路徑檢查的加密目標清空、已知答案的名稱清空。
//! - 時間：`KUROSHIO_CHAIN_TIMING` 把心跳、重試、共用結果的第一次同步縮短到 1～2 秒內；
//!   每個案例開始先 `POST /api/chain/recheck`（不等啟動後 8 秒的路徑檢查），每個等待都有上限。
//! - 平行：每個案例自己的目錄與埠（同一個測試行程裡不會給同一個埠兩次），可以平行跑。

use kuroshio_community::chain as proto;
use kuroshio_community::identity::KeyPair;
use kuroshio_proto::message::{Message, RData, Record};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 上游黑潮的上游（假的公開 DNS）回的位址
const VIA_UPSTREAM: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);
/// 下游自己的上游（「加密上游」的替身）回的位址
const OWN: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);
/// 心跳、重試、共用結果同步都縮短（毫秒）
const TIMING: &str =
    r#"{"ask":800,"heartbeat":1500,"earlyMin":200,"earlyMax":400,"retryMin":500,"retryMax":2000,"shareFirst":300,"shareEvery":600000}"#;
/// 等串接狀態的上限
const WAIT: Duration = Duration::from_secs(15);
/// 解析器的逾時（`resolver.timeoutMs`）
const TIMEOUT_MS: u64 = 1500;

// ---------------- 共用 ----------------

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("kuroshio-e2e-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// 空著的埠（TCP 與 UDP 都空著）。同一個測試行程裡不會給同一個埠兩次（平行跑的案例不會撞埠）
fn free_port() -> u16 {
    static GIVEN: Mutex<Vec<u16>> = Mutex::new(Vec::new());
    loop {
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        if UdpSocket::bind(("127.0.0.1", port)).is_err() {
            continue;
        }
        let mut given = GIVEN.lock().unwrap();
        if !given.contains(&port) {
            given.push(port);
            return port;
        }
    }
}

/// 每次不同的查詢名稱（不吃到快取）
fn fresh_name() -> String {
    static N: AtomicUsize = AtomicUsize::new(0);
    format!("q{}-{}.example.com", std::process::id(), N.fetch_add(1, Ordering::SeqCst))
}

fn until<T>(what: &str, limit: Duration, ctx: &dyn Fn() -> String, mut f: impl FnMut() -> Option<T>) -> T {
    let t0 = Instant::now();
    loop {
        if let Some(v) = f() {
            return v;
        }
        if t0.elapsed() > limit {
            panic!("{} 秒內等不到{what}\n{}", limit.as_secs(), ctx());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

// ---------------- 假 DNS ----------------

type Answer = Arc<dyn Fn(&Message) -> Option<Message> + Send + Sync>;
/// 收到的封包 → 回應的封包
type Handler = Arc<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync>;

/// 本機的假 DNS（UDP 與 TCP 同一個埠）：記下收到的 `chain.kuroshio` 查詢數
struct Fake {
    addr: SocketAddr,
    chain_queries: Arc<AtomicUsize>,
}

impl Fake {
    fn chain_queries(&self) -> usize {
        self.chain_queries.load(Ordering::SeqCst)
    }
}

fn serve(answer: Answer) -> Fake {
    let chain = Arc::new(AtomicUsize::new(0));
    let handle: Handler = {
        let chain = chain.clone();
        Arc::new(move |q: &[u8]| {
            let m = Message::parse(q).ok()?;
            let name = m.questions.first()?.name.to_ascii_lowercase();
            if proto::in_zone(&name) {
                chain.fetch_add(1, Ordering::SeqCst);
            }
            answer(&m).map(|r| r.encode())
        })
    };
    let (u, l) = loop {
        let u = UdpSocket::bind("127.0.0.1:0").unwrap();
        if let Ok(l) = TcpListener::bind(u.local_addr().unwrap()) {
            break (u, l);
        }
    };
    let addr = u.local_addr().unwrap();
    {
        let handle = handle.clone();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 4096];
            while let Ok((n, from)) = u.recv_from(&mut buf) {
                if let Some(r) = handle(&buf[..n]) {
                    let _ = u.send_to(&r, from);
                }
            }
        });
    }
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let handle = handle.clone();
            std::thread::spawn(move || {
                let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
                while let Some(q) = read_frame(&mut s) {
                    let Some(r) = handle(&q) else { return };
                    if write_frame(&mut s, &r).is_err() {
                        return;
                    }
                }
            });
        }
    });
    Fake {
        addr,
        chain_queries: chain,
    }
}

fn read_frame(s: &mut TcpStream) -> Option<Vec<u8>> {
    let mut len = [0u8; 2];
    s.read_exact(&mut len).ok()?;
    let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut q).ok()?;
    Some(q)
}

fn write_frame(s: &mut TcpStream, b: &[u8]) -> std::io::Result<()> {
    let mut out = (b.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(b);
    s.write_all(&out)
}

fn txt_record(name: &str, payload: &[u8]) -> Record {
    Record {
        name: name.to_string(),
        rtype: 16,
        class: 3,
        ttl: 0,
        data: RData::Raw(proto::txt_rdata(payload)),
    }
}

/// 一般查詢的回答：`.invalid` 回不存在（路徑檢查用它判斷有沒有改寫「不存在」），A 回 `ip`，其他類型回空的
fn a_reply(m: &Message, ip: Ipv4Addr) -> Message {
    let q = &m.questions[0];
    let mut r = Message::response_to(m, 0);
    if q.name.trim_end_matches('.').to_ascii_lowercase().ends_with(".invalid") {
        r.rcode = 3;
    } else if q.qtype == 1 {
        r.answers.push(Record::a(&q.name, 60, ip));
    }
    r
}

/// 假的公開 DNS：IN 類別照 [`a_reply`]，CHAOS 類別一律拒絕
fn public_dns(ip: Ipv4Addr) -> Fake {
    serve(Arc::new(move |m: &Message| {
        Some(if m.questions[0].qclass == 1 {
            a_reply(m, ip)
        } else {
            Message::response_to(m, 5)
        })
    }))
}

/// 冒充者的花樣
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// 正常簽章（只當「會記錄查詢的假上游黑潮」用）
    Legit,
    /// 公鑰寫 A 的，簽章用 B 的金鑰（簽章壞掉）
    BadSig,
    /// 把先前錄下的合法回應原樣回給新的挑戰（別的 nonce）
    Replay,
    /// 公鑰與 `kid` 不符
    KidMismatch,
}

/// 攔截者的種類
#[derive(Clone, Copy, Debug)]
enum Interceptor {
    /// `version.kuroshio` 回這個版本，不回答串接查詢（3.3.x 的黑潮）
    Old(&'static str),
    /// 只回答 `version.bind`（一般 DNS 軟體）
    Software,
    /// `version.kuroshio = kuroshio/3.4.0`，auth 照 [`Mode`]
    Kuroshio(Mode),
}

/// 假的攔截者：一般查詢回 `198.51.100.10`；CHAOS 類別照 `kind`
fn interceptor(kind: Interceptor) -> Fake {
    let key = Arc::new(KeyPair::generate());
    let other = Arc::new(KeyPair::generate());
    // 公鑰一律寫 `key` 的；簽章的金鑰與 kid 依花樣換
    let auth = {
        let key = key.clone();
        move |nonce: &[u8], signer: &KeyPair, kid: &[u8]| {
            let body = proto::AuthBody {
                v: proto::PROTO,
                t: "auth".into(),
                nonce: nonce.to_vec(),
                kid: kid.to_vec(),
                public: key.public.to_vec(),
                app: "3.4.0".into(),
                allow: true,
                caps: vec![],
                peer: "127.0.0.1".into(),
                tok: vec![0; 16],
                path: vec![key.kid.to_vec()],
                ..Default::default()
            };
            proto::seal(signer, "auth", kuroshio_community::envelope::to_cbor(&body))
        }
    };
    // 重放用：先錄一份合法的回應（給別的 nonce）
    let recorded = auth(&[7u8; 16], &key, &key.kid);
    serve(Arc::new(move |m: &Message| {
        let q = &m.questions[0];
        if q.qclass != 3 {
            return Some(a_reply(m, VIA_UPSTREAM));
        }
        let name = q.name.to_ascii_lowercase();
        let mut r = Message::response_to(m, 0);
        match (kind, name.as_str(), proto::parse_name(&name)) {
            (Interceptor::Old(v), "version.kuroshio", _) => r.answers.push(txt_record(&q.name, format!("kuroshio/{v}").as_bytes())),
            (Interceptor::Software, "version.bind", _) => r.answers.push(txt_record(&q.name, b"9.18.24")),
            (Interceptor::Kuroshio(_), "version.kuroshio", _) => r.answers.push(txt_record(&q.name, b"kuroshio/3.4.0")),
            (Interceptor::Kuroshio(mode), _, Some(proto::Name::Auth(nonce))) => {
                let payload = match mode {
                    Mode::Legit => auth(&nonce, &key, &key.kid),
                    Mode::BadSig => auth(&nonce, &other, &key.kid),
                    Mode::KidMismatch => auth(&nonce, &key, &other.kid),
                    Mode::Replay => recorded.clone(),
                };
                r.answers.push(txt_record(&q.name, &payload));
            }
            _ => r.rcode = 5,
        }
        Some(r)
    }))
}

// ---------------- 模擬 DNAT ----------------

/// 工作區的版本還沒改成 3.4.0 之前（發行前才改），把上游回答的 `version.kuroshio` 改寫成 `kuroshio/3.4.0`；
/// 版本夠新時原封不動。其他封包一律原封不動
fn rewrite_version(reply: Vec<u8>) -> Vec<u8> {
    if proto::version_ok(env!("CARGO_PKG_VERSION")) {
        return reply;
    }
    let Ok(mut m) = Message::parse(&reply) else { return reply };
    let Some(q) = m.questions.first().cloned() else { return reply };
    if q.qclass != 3 || !q.name.eq_ignore_ascii_case("version.kuroshio") || m.rcode != 0 || m.answers.is_empty() {
        return reply;
    }
    m.answers = vec![txt_record(&q.name, b"kuroshio/3.4.0")];
    m.encode()
}

/// 模擬上游路由器的 DNAT：對 `addr` 的 UDP／TCP 一律轉給目前的目標（上游黑潮），回應原路送回。
/// 目標可以換（上游停掉、換一台時，下游看到的「保留位址」不變）
struct Dnat {
    addr: SocketAddr,
    target: Arc<Mutex<SocketAddr>>,
}

impl Dnat {
    fn new(target: SocketAddr) -> Dnat {
        let t = Arc::new(Mutex::new(target));
        let (u, l) = loop {
            let u = UdpSocket::bind("127.0.0.1:0").unwrap();
            if let Ok(l) = TcpListener::bind(u.local_addr().unwrap()) {
                break (u, l);
            }
        };
        let addr = u.local_addr().unwrap();
        {
            let t = t.clone();
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 4096];
                while let Ok((n, from)) = u.recv_from(&mut buf) {
                    let (q, to) = (buf[..n].to_vec(), *t.lock().unwrap());
                    let Ok(back) = u.try_clone() else { continue };
                    std::thread::spawn(move || {
                        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
                        let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
                        if s.send_to(&q, to).is_err() {
                            return;
                        }
                        let mut r = vec![0u8; 4096];
                        if let Ok((n, _)) = s.recv_from(&mut r) {
                            let _ = back.send_to(&rewrite_version(r[..n].to_vec()), from);
                        }
                    });
                }
            });
        }
        {
            let t = t.clone();
            std::thread::spawn(move || {
                for c in l.incoming() {
                    let Ok(mut c) = c else { continue };
                    let to = *t.lock().unwrap();
                    std::thread::spawn(move || {
                        let _ = c.set_read_timeout(Some(Duration::from_secs(10)));
                        let Ok(mut up) = TcpStream::connect_timeout(&to, Duration::from_secs(2)) else {
                            return;
                        };
                        let _ = up.set_read_timeout(Some(Duration::from_secs(5)));
                        while let Some(q) = read_frame(&mut c) {
                            if write_frame(&mut up, &q).is_err() {
                                return;
                            }
                            let Some(r) = read_frame(&mut up) else { return };
                            if write_frame(&mut c, &rewrite_version(r)).is_err() {
                                return;
                            }
                        }
                    });
                }
            });
        }
        Dnat { addr, target: t }
    }

    fn set(&self, to: SocketAddr) {
        *self.target.lock().unwrap() = to;
    }
}

// ---------------- 查詢 ----------------

/// 對 `port` 查 `name` 的 A（來源位址 `from`）：回（rcode、位址）；`None` = 等不到
fn query(port: u16, name: &str, from: Ipv4Addr, wait: Duration) -> Option<(u16, Vec<Ipv4Addr>)> {
    static ID: AtomicU16 = AtomicU16::new(1);
    let s = UdpSocket::bind((from, 0)).unwrap();
    s.connect(("127.0.0.1", port)).unwrap();
    let id = ID.fetch_add(1, Ordering::SeqCst);
    let t0 = Instant::now();
    // 第一次沒回應，一半的時間後重送一次
    let mut sent = 0;
    let mut buf = vec![0u8; 4096];
    while t0.elapsed() < wait {
        if sent == 0 || (sent == 1 && t0.elapsed() > wait / 2) {
            let _ = s.send(&kuroshio_proto::build_query(id, name, 1));
            sent += 1;
        }
        let _ = s.set_read_timeout(Some(Duration::from_millis(100)));
        if let Ok(n) = s.recv(&mut buf) {
            let Ok(m) = Message::parse(&buf[..n]) else { continue };
            if m.id != id {
                continue;
            }
            let ips = m
                .answers
                .iter()
                .filter_map(|r| match r.data {
                    RData::A(a) => Some(a),
                    _ => None,
                })
                .collect();
            return Some((m.rcode, ips));
        }
    }
    None
}

/// 一般的用戶端位址（Linux 整段 127/8 都是本機）：跟下游黑潮的來源（127.0.0.1）不同
fn other_client() -> Ipv4Addr {
    Ipv4Addr::new(127, 0, 0, 2)
}

fn loopback() -> Ipv4Addr {
    Ipv4Addr::LOCALHOST
}

// ---------------- 子程序 ----------------

/// 管理 API（沒有登入）：回（狀態碼、JSON）
fn http(port: u16, method: &str, path: &str) -> Result<(u16, Value), String> {
    let to: SocketAddr = ([127, 0, 0, 1], port).into();
    let mut s = TcpStream::connect_timeout(&to, Duration::from_secs(2)).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(10))).map_err(|e| e.to_string())?;
    let body = if method == "POST" { "{}" } else { "" };
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .map_err(|e| e.to_string())?;
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).map_err(|e| e.to_string())?;
    let resp = String::from_utf8_lossy(&resp).to_string();
    let (head, body) = resp.split_once("\r\n\r\n").ok_or_else(|| format!("回應格式不對：{resp}"))?;
    let code = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| format!("回應格式不對：{head}"))?;
    let v = serde_json::from_str(body).map_err(|e| format!("{e}：{body}"))?;
    Ok((code, v))
}

/// 一台黑潮（子程序 `kuroshio run`）
struct Node {
    name: String,
    dir: PathBuf,
    conf: PathBuf,
    cfg: Value,
    env: Vec<(String, String)>,
    dns: u16,
    admin: u16,
    child: Option<Child>,
    log: Arc<Mutex<String>>,
    /// 這一次啟動的時間
    started: Instant,
}

/// 設定：只聽 127.0.0.1、沒有登入、過濾／CDN／社群共享／背景工作都關掉、不用種子資料裡的自動上游
fn base_cfg(dir: &Path, dns: u16, admin: u16) -> Value {
    json!({
        "system": { "persistDir": dir.join("state").to_string_lossy(), "dataDir": root().join("data").to_string_lossy(),
                    "runtimeDir": dir.join("run").to_string_lossy() },
        "admin": { "port": admin, "auth": false },
        "filter": { "enabled": false }, "cdn": { "enabled": false },
        "community": { "enabled": false, "dir": dir.join("keys").to_string_lossy() },
        "listen": { "plain": { "binds": ["127.0.0.1"], "port": dns } },
        "upstream": { "pinned": [], "fallback": [], "autoTypes": [] },
        "resolver": { "lastResort": [], "rankIps": false, "timeoutMs": TIMEOUT_MS },
        "jobs": { "dns-benchmark": { "enabled": false }, "cdn-pool": { "enabled": false }, "cdn-ranges": { "enabled": false },
                  "cdn-scan": { "enabled": false }, "tw-ip": { "enabled": false } },
    })
}

/// 把 `extra` 的欄位併進 `v`（物件遞迴合併）
fn merge(v: &mut Value, extra: &Value) {
    match (v, extra) {
        (Value::Object(a), Value::Object(b)) => {
            for (k, x) in b {
                merge(a.entry(k.clone()).or_insert(Value::Null), x);
            }
        }
        (a, b) => *a = b.clone(),
    }
}

impl Node {
    /// 起一台：`extra` 併進設定，`env` 是額外的環境變數
    fn start(dir: &Path, name: &str, extra: Value, env: Vec<(String, String)>) -> Node {
        let nd = dir.join(name);
        std::fs::create_dir_all(nd.join("state")).unwrap();
        let mut n = Node {
            name: name.to_string(),
            conf: nd.join("config.json"),
            dir: nd,
            cfg: Value::Null,
            env,
            dns: 0,
            admin: 0,
            child: None,
            log: Default::default(),
            started: Instant::now(),
        };
        n.launch(extra);
        n
    }

    /// 用新的埠（同一個目錄、同一把金鑰）啟動
    fn launch(&mut self, extra: Value) {
        self.dns = free_port();
        self.admin = free_port();
        let mut cfg = base_cfg(&self.dir, self.dns, self.admin);
        merge(&mut cfg, &extra);
        self.cfg = cfg;
        self.write_cfg();
        let mut c = Command::new(env!("CARGO_BIN_EXE_kuroshio"));
        c.args(["run", "-c"])
            .arg(&self.conf)
            .env("NO_COLOR", "1")
            .env("KUROSHIO_LOG", "info")
            .env_remove("KUROSHIO_PATH_TARGETS")
            .env_remove("KUROSHIO_CHAIN_TIMING")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());
        // 不連外：代理伺服器的設定不帶進去
        for k in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"] {
            c.env_remove(k);
        }
        for (k, v) in &self.env {
            c.env(k, v);
        }
        let mut child = c.spawn().unwrap();
        self.started = Instant::now();
        self.log = Default::default();
        for pipe in [
            Box::new(child.stdout.take().unwrap()) as Box<dyn Read + Send>,
            Box::new(child.stderr.take().unwrap()),
        ] {
            let log = self.log.clone();
            std::thread::spawn(move || {
                for l in BufReader::new(pipe).lines().map_while(Result::ok) {
                    let mut g = log.lock().unwrap();
                    g.push_str(&l);
                    g.push('\n');
                }
            });
        }
        self.child = Some(child);
        until(
            &format!(" {} 的管理 API", self.name),
            Duration::from_secs(20),
            &|| self.log(),
            || http(self.admin, "GET", "/api/status").ok().filter(|(c, _)| *c == 200),
        );
        until(
            &format!(" {} 啟動完成", self.name),
            Duration::from_secs(20),
            &|| self.log(),
            || (self.rounds() >= 1).then_some(()),
        );
    }

    fn write_cfg(&self) {
        std::fs::write(&self.conf, serde_json::to_vec_pretty(&self.cfg).unwrap()).unwrap();
    }

    fn log(&self) -> String {
        let l = self.log.lock().unwrap();
        let start = l.len().saturating_sub(6000);
        let start = (start..l.len()).find(|i| l.is_char_boundary(*i)).unwrap_or(l.len());
        format!("---- {} 的記錄（最後一段）----\n{}", self.name, &l[start..])
    }

    /// 啟動完成的輪數（每一輪啟動完成記一次快照目錄）
    fn rounds(&self) -> usize {
        self.log.lock().unwrap().matches("快照目錄 ").count()
    }

    fn get(&self, path: &str) -> Value {
        match http(self.admin, "GET", path) {
            Ok((200, v)) => v,
            other => panic!("{} GET {path}：{other:?}\n{}", self.name, self.log()),
        }
    }

    fn post(&self, path: &str) -> Value {
        match http(self.admin, "POST", path) {
            Ok((200, v)) => v,
            other => panic!("{} POST {path}：{other:?}\n{}", self.name, self.log()),
        }
    }

    fn chain(&self) -> Value {
        self.get("/api/chain")
    }

    fn status(&self) -> Value {
        self.get("/api/status")
    }

    /// 立刻做一次路徑檢查與探測（不等啟動後 8 秒）
    fn recheck(&self) {
        assert_eq!(self.post("/api/chain/recheck")["ok"], true);
    }

    /// 輪詢 `/api/chain` 到 `f` 成立（最多 `limit`）
    fn wait_chain(&self, what: &str, limit: Duration, f: impl Fn(&Value) -> bool) -> Value {
        until(what, limit, &|| format!("{}\n/api/chain = {}", self.log(), self.chain()), || {
            let c = self.chain();
            f(&c).then_some(c)
        })
    }

    fn wait_state(&self, state: &str, reason: Option<&str>) -> Value {
        self.wait_chain(&format!(" {} 的串接狀態 {state}／{reason:?}", self.name), WAIT, |c| {
            c["state"] == state && c["reason"].as_str() == reason
        })
    }

    /// 等路徑檢查做完（`network.path.checkedAt` 有值）
    fn wait_path_checked(&self) -> Value {
        until(&format!(" {} 的路徑檢查", self.name), WAIT, &|| self.log(), || {
            let s = self.status();
            (!s["network"]["path"]["checkedAt"].is_null()).then_some(s)
        })
    }

    fn fingerprint(&self) -> String {
        self.chain()["serving"]["fingerprint"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_default()
    }

    fn node_id(&self) -> Option<String> {
        self.chain()["serving"]["nodeId"].as_str().map(str::to_string)
    }

    fn resolve(&self, from: Ipv4Addr) -> Option<(u16, Vec<Ipv4Addr>)> {
        query(self.dns, &fresh_name(), from, Duration::from_millis(TIMEOUT_MS + 1500))
    }

    /// 等到啟動後的第一次自動路徑檢查（啟動後 8 秒）做完：之後 6 小時內不會再自動檢查，
    /// 測試自己控制什麼時候檢查（上游停掉時路徑檢查會判斷「沒被接走」，那是另一個案例）
    fn past_first_path_check(&self) {
        let at = self.started + Duration::from_millis(9500);
        if let Some(d) = at.checked_duration_since(Instant::now()) {
            std::thread::sleep(d);
        }
    }

    fn pid(&self) -> i32 {
        self.child.as_ref().expect("還在跑").id() as i32
    }

    /// 改設定、送 SIGHUP，等新的一輪啟動完成
    fn reload_with(&mut self, extra: Value) {
        merge(&mut self.cfg, &extra);
        self.write_cfg();
        let n = self.rounds();
        assert_eq!(unsafe { libc::kill(self.pid(), libc::SIGHUP) }, 0);
        until(
            &format!(" {} 重新載入完成", self.name),
            Duration::from_secs(20),
            &|| self.log(),
            || (self.rounds() > n).then_some(()),
        );
    }

    /// 直接結束（模擬上游掛掉）
    fn kill(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.kill();
    }
}

fn targets(to: SocketAddr) -> String {
    json!({ "testnetV4": [to.to_string()], "testnetV6": [], "gateway": null, "encrypted": false, "plainTimeoutMs": 500 }).to_string()
}

/// 下游的環境變數：保留位址指到 `to`（DNAT 或假的攔截者）、縮短的時間
fn down_env(to: SocketAddr) -> Vec<(String, String)> {
    vec![
        ("KUROSHIO_PATH_TARGETS".into(), targets(to)),
        ("KUROSHIO_CHAIN_TIMING".into(), TIMING.into()),
    ]
}

/// 上游黑潮：上游是假的公開 DNS，不做路徑檢查（它自己沒有上一層）
fn upstream_node(dir: &Path, name: &str, public: &Fake, allow: bool) -> Node {
    Node::start(
        dir,
        name,
        json!({ "upstream": { "pinned": [format!("udp://{}", public.addr)], "pathCheck": false, "allowDownstream": allow } }),
        vec![],
    )
}

/// 下游黑潮：沒有固定上游，備援是 `own`（自己的上游的替身），保留位址指到 `to`
fn downstream_node(dir: &Path, name: &str, to: SocketAddr, own: &Fake, extra: Value) -> Node {
    let mut cfg = json!({ "upstream": { "fallback": [format!("udp://{}", own.addr)] } });
    merge(&mut cfg, &extra);
    Node::start(dir, name, cfg, down_env(to))
}

/// 上游的 `serving.downstreams` 裡有這台下游（依節點 ID）
fn lists_downstream(up: &Node, down: &Node) -> bool {
    let Some(id) = down.node_id() else { return false };
    up.chain()["serving"]["downstreams"]
        .as_array()
        .is_some_and(|a| a.iter().any(|d| d["nodeId"] == id))
}

/// `/api/status.upstreams` 有沒有串接上游
fn has_chain_upstream(status: &Value) -> bool {
    status["upstreams"]
        .as_array()
        .is_some_and(|a| a.iter().any(|u| u["role"] == "chain"))
}

/// 一台上游黑潮＋DNAT＋一台下游黑潮，下游已經串接
struct Pair {
    dir: PathBuf,
    public: Fake,
    /// 下游自己的上游（替身）：跟著 Pair 活著
    _own: Fake,
    dnat: Dnat,
    up: Node,
    down: Node,
}

fn chained_pair(tag: &str) -> Pair {
    let dir = tmp(tag);
    let public = public_dns(VIA_UPSTREAM);
    let own = public_dns(OWN);
    let up = upstream_node(&dir, "up", &public, true);
    let dnat = Dnat::new(([127, 0, 0, 1], up.dns).into());
    let down = downstream_node(&dir, "down", dnat.addr, &own, json!({}));
    down.recheck();
    down.wait_state("chained", None);
    Pair {
        dir,
        public,
        _own: own,
        dnat,
        up,
        down,
    }
}

impl Drop for Pair {
    fn drop(&mut self) {
        self.down.kill();
        self.up.kill();
        if !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

fn cleanup(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}

// ---------------- 案例 ----------------

/// 兩邊都用預設值：不做任何操作就串接；查詢經上游；上游列出下游
#[test]
fn e2e_both_on_chains_automatically() {
    let p = chained_pair("both-on");
    let c = p.down.chain();
    assert_eq!(c["enabled"], true);
    assert!(c["text"].as_str().unwrap().starts_with("串接中：上游"), "{c}");
    let fp = p.up.fingerprint();
    assert!(!fp.is_empty(), "上游有指紋：{}", p.up.chain());
    assert_eq!(c["upstream"]["fingerprint"], fp, "下游綁定的是上游的金鑰");
    assert_eq!(c["upstream"]["address"], "127.0.0.1");
    assert_eq!(c["upstream"]["depth"], 2);
    let st = p.down.status();
    assert_eq!(st["upstreams"][0]["role"], "chain", "{}", st["upstreams"]);
    // 查詢經上游黑潮（它的上游回 198.51.100.10）
    let r = p.down.resolve(other_client());
    assert_eq!(r, Some((0, vec![VIA_UPSTREAM])), "{}", p.down.log());
    // 上游的「連上來的下游」有這台（登記在串接之後馬上送）
    until(
        " 上游列出下游",
        WAIT,
        &|| format!("{}\n{}", p.up.chain(), p.down.log()),
        || lists_downstream(&p.up, &p.down).then_some(()),
    );
    let c = p.down.chain();
    assert_eq!(c["upstream"]["registered"]["ok"], true, "{c}");
}

/// 下游 `chain: false`：不發任何串接查詢，自己解析，路徑檢查照 3.3.7 提醒「一般 DNS 被接走」
#[test]
fn e2e_downstream_chain_off() {
    let dir = tmp("down-off");
    let own = public_dns(OWN);
    // 會記錄查詢的假上游黑潮（合法簽章）
    let up = interceptor(Interceptor::Kuroshio(Mode::Legit));
    let down = downstream_node(&dir, "down", up.addr, &own, json!({ "upstream": { "chain": false } }));
    down.recheck();
    let st = down.wait_path_checked();
    std::thread::sleep(Duration::from_millis(500));
    let c = down.chain();
    assert_eq!(c["state"], "none", "{c}");
    assert_eq!(c["enabled"], false);
    assert_eq!(
        c["text"],
        "已關閉串接（chain 關閉）：把上游黑潮當成一般的 DNS 攔截，自己做評測，會重複使用網路"
    );
    assert_eq!(up.chain_queries(), 0, "chain 關著不能發任何 chain.kuroshio 查詢");
    assert_eq!(down.resolve(other_client()), Some((0, vec![OWN])), "{}", down.log());
    let path = &st["network"]["path"];
    assert_eq!(path["interceptor"]["kind"], "kuroshio", "{path}");
    let warned = path["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|w| w.as_str().is_some_and(|w| w.starts_with("一般 DNS") && w.contains("接走")));
    assert!(warned, "跟 3.3.7 一樣提醒一般 DNS 被接走：{path}");
    assert!(!has_chain_upstream(&down.status()));
    drop(down);
    cleanup(&dir);
}

/// 上游 `allowDownstream: false`：下游自己做，上游說明不提供資料並記下有人問過
#[test]
fn e2e_upstream_allow_off() {
    let dir = tmp("allow-off");
    let (public, own) = (public_dns(VIA_UPSTREAM), public_dns(OWN));
    let up = upstream_node(&dir, "up", &public, false);
    let dnat = Dnat::new(([127, 0, 0, 1], up.dns).into());
    let down = downstream_node(&dir, "down", dnat.addr, &own, json!({}));
    down.recheck();
    let c = down.wait_state("released", Some("not-allowed"));
    let text = c["text"].as_str().unwrap();
    assert!(text.starts_with("上游黑潮 "), "{text}");
    assert!(
        text.ends_with("不提供資料（allow_downstream 關閉）：自己做評測，會重複使用網路；每 10 分鐘確認一次，上游重新開放就自動接回"),
        "{text}"
    );
    assert_eq!(down.resolve(other_client()), Some((0, vec![OWN])), "{}", down.log());
    // 沒有串接：沒有共用結果，也不略過自己的工作
    assert!(
        c["shared"].is_null() || c["shared"]["objects"].as_array().is_some_and(Vec::is_empty),
        "{c}"
    );
    assert!(!c["shared"]["skippedJobs"]
        .as_array()
        .is_some_and(|a| a.iter().any(|j| j == "dns-benchmark")));
    assert!(!has_chain_upstream(&down.status()));
    let s = up.chain()["serving"].clone();
    let t = s["text"].as_str().unwrap();
    assert!(t.contains("不提供資料給下游") && t.contains("重複"), "{t}");
    assert!(s["probes"]["count24h"].as_u64().unwrap() >= 1, "{s}");
    assert_eq!(s["downstreams"], json!([]), "{s}");
    // check-path（對下游的設定、同樣的保留位址）
    let out = Command::new(env!("CARGO_BIN_EXE_kuroshio"))
        .args(["check-path", "-c"])
        .arg(&down.conf)
        .env("KUROSHIO_PATH_TARGETS", targets(dnat.addr))
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("上游不提供資料"), "{text}");
    drop((down, up));
    cleanup(&dir);
}

/// 兩邊都關：下游同 chain 關閉，上游沒有收到任何探測
#[test]
fn e2e_both_off() {
    let dir = tmp("both-off");
    let (public, own) = (public_dns(VIA_UPSTREAM), public_dns(OWN));
    let up = upstream_node(&dir, "up", &public, false);
    let dnat = Dnat::new(([127, 0, 0, 1], up.dns).into());
    let down = downstream_node(&dir, "down", dnat.addr, &own, json!({ "upstream": { "chain": false } }));
    down.recheck();
    down.wait_path_checked();
    std::thread::sleep(Duration::from_millis(500));
    let c = down.chain();
    assert_eq!((c["state"].as_str(), c["enabled"].as_bool()), (Some("none"), Some(false)), "{c}");
    assert!(c["text"].as_str().unwrap().starts_with("已關閉串接（chain 關閉）"), "{c}");
    assert_eq!(down.resolve(other_client()), Some((0, vec![OWN])), "{}", down.log());
    assert_eq!(up.chain()["serving"]["probes"]["count24h"], 0, "{}", up.chain());
    drop((down, up));
    cleanup(&dir);
}

/// 上游是 3.3.x 的黑潮：不發挑戰，解析照常
#[test]
fn e2e_upstream_3_3_x() {
    let dir = tmp("old-up");
    let own = public_dns(OWN);
    let old = interceptor(Interceptor::Old("3.3.7"));
    let down = downstream_node(&dir, "down", old.addr, &own, json!({}));
    down.recheck();
    let c = down.wait_state("released", Some("upstream-too-old"));
    assert_eq!(c["text"], "上游黑潮 3.3.7 不支援串接（需要 3.4.0 以上）");
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(old.chain_queries(), 0, "3.3.x 的上游不能收到 chain.kuroshio 查詢");
    assert_eq!(down.resolve(other_client()), Some((0, vec![OWN])), "{}", down.log());
    drop(down);
    cleanup(&dir);
}

/// 攔截者不是黑潮（只回答 version.bind）：未偵測，不發串接查詢
#[test]
fn e2e_not_kuroshio() {
    let dir = tmp("not-kuroshio");
    let own = public_dns(OWN);
    let sw = interceptor(Interceptor::Software);
    let down = downstream_node(&dir, "down", sw.addr, &own, json!({}));
    down.recheck();
    let st = down.wait_path_checked();
    assert_eq!(st["network"]["path"]["interceptor"]["kind"], "dns-software", "{}", st["network"]);
    std::thread::sleep(Duration::from_millis(500));
    let c = down.chain();
    assert_eq!(c["state"], "none", "{c}");
    assert_eq!(c["text"], "沒有偵測到上游黑潮");
    assert_eq!(sw.chain_queries(), 0);
    assert_eq!(down.resolve(other_client()), Some((0, vec![OWN])));
    drop(down);
    cleanup(&dir);
}

/// 冒充者（簽章壞掉、重放錄下來的回應、公鑰與 kid 不符）：都是 verify-failed，不串接
#[test]
fn e2e_impostor_rejected() {
    let dir = tmp("impostor");
    let own = public_dns(OWN);
    for mode in [Mode::BadSig, Mode::Replay, Mode::KidMismatch] {
        let fake = interceptor(Interceptor::Kuroshio(mode));
        let down = downstream_node(&dir, &format!("{mode:?}"), fake.addr, &own, json!({}));
        down.recheck();
        let c = down.wait_state("released", Some("verify-failed"));
        assert!(c["upstream"]["error"].is_string(), "{mode:?}：{c}");
        assert!(fake.chain_queries() >= 1, "{mode:?}");
        let st = down.status();
        assert!(!has_chain_upstream(&st), "{mode:?}：{}", st["upstreams"]);
        assert_eq!(down.resolve(other_client()), Some((0, vec![OWN])), "{mode:?}");
    }
    cleanup(&dir);
}

/// 串接後上游換成另一台（新的金鑰）：自動重新串接，留下舊指紋與警告
#[test]
fn e2e_upstream_swapped_rebinds_with_warning() {
    let mut p = chained_pair("swapped");
    let old = p.up.fingerprint();
    let up2 = upstream_node(&p.dir, "up2", &p.public, true);
    // 同一個保留位址後面換了一台
    p.dnat.set(([127, 0, 0, 1], up2.dns).into());
    p.up.kill();
    let c = p.down.wait_chain(" 下游綁定新的金鑰", WAIT, |c| {
        c["state"] == "chained" && c["upstream"]["fingerprint"].as_str().is_some_and(|f| f != old)
    });
    // 新的那台第一次被問 auth 才建立金鑰：綁定之後再讀它的指紋
    assert_eq!(c["upstream"]["fingerprint"], up2.fingerprint(), "綁定的是新的那台");
    assert_eq!(c["upstream"]["previousFingerprint"], old, "{c}");
    assert!(c["upstream"]["keyChangedAt"].is_u64(), "{c}");
    assert!(c["text"].as_str().unwrap().contains("上游節點的金鑰換過"), "{c}");
    let st = p.down.status();
    let warned = st["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|w| w.as_str().is_some_and(|w| w.contains("上游節點的金鑰換過")));
    assert!(warned, "{}", st["warnings"]);
    assert_eq!(p.down.resolve(other_client()), Some((0, vec![VIA_UPSTREAM])));
    drop(up2);
}

/// 串接後上游停掉：幾秒內改用自己的上游；上游（同一把金鑰）回來後自動接回，沒有金鑰換過的警告
#[test]
fn e2e_upstream_down_falls_back_to_encrypted() {
    let mut p = chained_pair("down-fallback");
    let fp = p.up.fingerprint();
    p.down.past_first_path_check();
    assert_eq!(p.down.chain()["state"], "chained");
    p.up.kill();
    // 解除之後會一直重試；先看到 no-response
    let c = p.down.wait_state("released", Some("no-response"));
    assert_eq!(c["text"], "串接中斷：上游沒有回應，暫時用自己的加密上游");
    assert_eq!(c["backupActive"], true, "{c}");
    assert_eq!(p.down.resolve(other_client()), Some((0, vec![OWN])), "{}", p.down.log());
    assert!(!has_chain_upstream(&p.down.status()));
    // 上游停著的期間一直重試（retryMin 0.5 秒起加倍、最長 2 秒），狀態維持 no-response，
    // 不會因為重試沒回應就變成「不支援串接」而停止重試（規格 1.4、1.8：上游回來自動接回）
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(6) {
        let c = p.down.chain();
        assert!(
            c["state"] == "detected" || (c["state"] == "released" && c["reason"] == "no-response"),
            "上游停著時要維持 no-response 並繼續重試：{c}\n{}",
            p.down.log()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    // 上游回來（同一個目錄、同一把金鑰；DNAT 換到新的埠）
    let extra = json!({ "upstream": { "pinned": [format!("udp://{}", p.public.addr)], "pathCheck": false, "allowDownstream": true } });
    p.up.launch(extra);
    p.dnat.set(([127, 0, 0, 1], p.up.dns).into());
    let c = p
        .down
        .wait_chain(" 上游回來後自動接回", Duration::from_secs(20), |c| c["state"] == "chained");
    assert_eq!(c["upstream"]["fingerprint"], fp);
    assert!(c["upstream"]["previousFingerprint"].is_null(), "{c}");
    let st = p.down.status();
    assert!(
        !st["warnings"].to_string().contains("金鑰換過"),
        "同一把金鑰不警告：{}",
        st["warnings"]
    );
    assert_eq!(p.down.resolve(other_client()), Some((0, vec![VIA_UPSTREAM])));
}

/// `kuroshio notify wan-changed`：立刻離開 chained，路徑檢查之後自動重新串接
#[test]
fn e2e_wan_changed() {
    let p = chained_pair("wan-changed");
    let out = Command::new(env!("CARGO_BIN_EXE_kuroshio"))
        .args(["notify", "wan-changed", "-c"])
        .arg(&p.down.conf)
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
    let c = p.down.chain();
    assert_ne!(c["state"], "chained", "WAN 變動要立刻離開 chained：{c}");
    assert!(!has_chain_upstream(&p.down.status()));
    // WAN 變動後等 5 秒再做路徑檢查
    p.down
        .wait_chain(" 路徑檢查後重新串接", Duration::from_secs(20), |c| c["state"] == "chained");
}

/// 兩台互指（A 的保留位址指到 B、B 的指到 A）：不會兩台都串接，查詢不會卡死
#[test]
fn e2e_loop_a_b_a() {
    let dir = tmp("loop");
    let public = public_dns(VIA_UPSTREAM);
    let to_b = Dnat::new(([127, 0, 0, 1], 9).into());
    let to_a = Dnat::new(([127, 0, 0, 1], 9).into());
    let extra = json!({ "upstream": { "pinned": [format!("udp://{}", public.addr)] } });
    // 提早心跳的範圍放寬（0.2～2 秒）：兩台同時互相綁定之後，兩邊的提早心跳剛好同時發出、
    // 同時看到迴圈而同時解除（之後又同時重試）的機會變小
    let env = |to: SocketAddr| {
        let mut e = down_env(to);
        e[1].1 = TIMING.replace(r#""earlyMax":400"#, r#""earlyMax":2000"#);
        e
    };
    let a = Node::start(&dir, "a", extra.clone(), env(to_b.addr));
    let b = Node::start(&dir, "b", extra, env(to_a.addr));
    to_b.set(([127, 0, 0, 1], b.dns).into());
    to_a.set(([127, 0, 0, 1], a.dns).into());
    a.recheck();
    b.recheck();
    let both = || (a.chain(), b.chain());
    // 15 秒內：至少一台因為迴圈不串接，而且不是兩台都串接
    let (ca, cb) = until(
        " 迴圈被擋下",
        WAIT,
        &|| format!("{}\n{}\n{:?}", a.log(), b.log(), both()),
        || {
            let (ca, cb) = both();
            let looped = ca["reason"] == "loop" || cb["reason"] == "loop";
            let two = ca["state"] == "chained" && cb["state"] == "chained";
            (looped && !two).then_some((ca, cb))
        },
    );
    assert!(
        ca["state"] == "chained" || cb["state"] == "chained" || ca["reason"] == "loop",
        "{ca}\n{cb}"
    );
    // 之後 5 秒：就算兩台剛好同時重試又同時互相綁定（規格 1.7 允許），也會在提早心跳（最多 2 秒）之後解開，
    // 不會一直兩台都串接；查詢都在逾時加一點內回來（不會卡死）
    let t0 = Instant::now();
    let mut both_since: Option<Instant> = None;
    while t0.elapsed() < Duration::from_secs(5) {
        let (ca, cb) = both();
        if ca["state"] == "chained" && cb["state"] == "chained" {
            let since = *both_since.get_or_insert_with(Instant::now);
            assert!(
                since.elapsed() < Duration::from_secs(3),
                "兩台都串接（迴圈）超過 3 秒：\n{ca}\n{cb}\n{}\n{}",
                a.log(),
                b.log()
            );
        } else {
            both_since = None;
        }
        for n in [&a, &b] {
            let t = Instant::now();
            let r = query(n.dns, &fresh_name(), other_client(), Duration::from_millis(TIMEOUT_MS + 1000));
            assert!(r.is_some(), "{} 的查詢卡住了\n{}", n.name, n.log());
            assert!(t.elapsed() < Duration::from_millis(TIMEOUT_MS + 1000));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    drop((a, b));
    cleanup(&dir);
}

/// 三層：A ← B ← C（C 的保留位址指到 B、B 的指到 A）
#[test]
fn e2e_three_layers() {
    let dir = tmp("three");
    let (public, own) = (public_dns(VIA_UPSTREAM), public_dns(OWN));
    let a = upstream_node(&dir, "a", &public, true);
    let to_a = Dnat::new(([127, 0, 0, 1], a.dns).into());
    let b = downstream_node(&dir, "b", to_a.addr, &own, json!({}));
    b.recheck();
    b.wait_state("chained", None);
    let to_b = Dnat::new(([127, 0, 0, 1], b.dns).into());
    let c = downstream_node(&dir, "c", to_b.addr, &own, json!({}));
    c.recheck();
    let st = c.wait_chain(" C 的鏈是 B、A", WAIT, |x| {
        x["state"] == "chained" && x["upstream"]["path"].as_array().is_some_and(|p| p.len() == 2)
    });
    assert_eq!(st["upstream"]["depth"], 3, "{st}");
    let ids: Vec<String> = st["upstream"]["path"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect();
    assert_eq!(ids, vec![a.node_id().unwrap(), b.node_id().unwrap()], "鏈從最上層排到 B：A、B");
    // 3.5.0 E13：每一台的 self 跟別台看到的對得起來
    let (sa, sb) = (a.chain()["self"].clone(), b.chain()["self"].clone());
    assert_eq!((sa["nodeId"].as_str(), sa["depth"].as_u64()), (a.node_id().as_deref(), Some(1)));
    assert_eq!(sb["nodeId"].as_str(), b.node_id().as_deref());
    assert_eq!(sb["depth"], 2);
    assert_eq!(st["self"]["depth"], 3);
    assert_eq!(c.resolve(other_client()), Some((0, vec![VIA_UPSTREAM])), "查詢經 B 到 A");
    drop((c, b, a));
    cleanup(&dir);
}

/// 串接後對下游送 SIGHUP：重新載入後立刻還是 chained
#[test]
fn e2e_reload_keeps_chain() {
    let mut p = chained_pair("reload-keep");
    let fp = p.down.chain()["upstream"]["fingerprint"].clone();
    p.down.reload_with(json!({}));
    let c = p.down.chain();
    assert_eq!(c["state"], "chained", "重新載入後立刻是 chained：{c}");
    assert_eq!(c["upstream"]["fingerprint"], fp);
    assert_eq!(p.down.status()["upstreams"][0]["role"], "chain");
    assert_eq!(p.down.resolve(other_client()), Some((0, vec![VIA_UPSTREAM])));
}

/// 串接後把下游改成 `chain: false` 再 SIGHUP：回到未偵測，解析走自己的上游
///
/// 上游的 `serving.downstreams` 要等登記到期（`REG_TTL` 固定 15 分鐘，沒有測試用的覆寫）才清掉，
/// 這裡只確認下游不再心跳、不再登記（上游那筆的 `lastSeen` 不再更新）
#[test]
fn e2e_reload_turns_chain_off() {
    let mut p = chained_pair("reload-off");
    until(" 上游列出下游", WAIT, &|| p.up.chain().to_string(), || {
        lists_downstream(&p.up, &p.down).then_some(())
    });
    p.down.reload_with(json!({ "upstream": { "chain": false } }));
    let c = p.down.chain();
    assert_eq!((c["state"].as_str(), c["enabled"].as_bool()), (Some("none"), Some(false)), "{c}");
    assert!(c["upstream"].is_null(), "{c}");
    assert!(!has_chain_upstream(&p.down.status()));
    assert_eq!(p.down.resolve(other_client()), Some((0, vec![OWN])), "{}", p.down.log());
    let seen = |up: &Node| up.chain()["serving"]["downstreams"][0]["lastSeen"].clone();
    let before = seen(&p.up);
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(seen(&p.up), before, "chain 關掉之後不再心跳、登記");
}

fn upstreams_json() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "generatedAt": "2026-11-18T04:30:00.000Z",
        "selected": [
            { "id": "https://dns.example.net/dns-query", "type": "doh" },
            { "id": "tls://dns.example.com", "type": "dot" }
        ]
    }))
    .unwrap()
}

/// 共用結果：上游有評測結果 → 下游匯入（新鮮）、記下來源、略過自己的 dns-benchmark
///
/// CDN 節點池（`cdn-pools`）要兩邊都開 CDN，CDN 服務啟動後會連外（節點範圍、掃描），這裡不做；
/// 節點池的分享與匯入由 `tests/chain_share.rs`（同一個行程裡的假上游）涵蓋
#[test]
fn e2e_share() {
    let dir = tmp("share");
    let (public, own) = (public_dns(VIA_UPSTREAM), public_dns(OWN));
    std::fs::create_dir_all(dir.join("up/state")).unwrap();
    std::fs::write(dir.join("up/state/upstreams.json"), upstreams_json()).unwrap();
    let up = upstream_node(&dir, "up", &public, true);
    let dnat = Dnat::new(([127, 0, 0, 1], up.dns).into());
    let down = downstream_node(&dir, "down", dnat.addr, &own, json!({}));
    down.recheck();
    down.wait_state("chained", None);
    let c = down.wait_chain(" 共用結果同步", WAIT, |c| {
        c["shared"]["objects"]
            .as_array()
            .is_some_and(|a| a.iter().any(|o| o["kind"] == "upstreams" && o["fresh"] == true))
    });
    let skipped = &c["shared"]["skippedJobs"];
    assert!(skipped.as_array().unwrap().iter().any(|j| j == "dns-benchmark"), "{c}");
    let saved: Value = serde_json::from_slice(&std::fs::read(down.dir.join("state/upstreams.json")).unwrap()).unwrap();
    assert!(saved["source"]["chain"].is_string(), "{saved}");
    assert_eq!(saved["generatedAt"], "2026-11-18T04:30:00.000Z");
    assert_eq!(down.status()["autoUpstreams"]["source"], "chain");
    // CDN 關著：狀態給 enabled false，不是 null（3.5.0）
    assert_eq!(down.status()["cdn"]["enabled"], false);
    assert!(up.chain()["serving"]["share"]["requests"].as_u64().unwrap() >= 1);
    // 手動跑 dns-benchmark：由上游提供，略過（不會真的評測）
    let r = down.post("/api/jobs/run?name=dns-benchmark");
    assert_ne!(r["ok"], false, "{r}");
    until(" dns-benchmark 略過", WAIT, &|| down.log(), || {
        down.log().contains("dns-benchmark：由上游黑潮提供，略過").then_some(())
    });
    drop((down, up));
    cleanup(&dir);
}

/// 上游沒有評測資料：下游沒有 upstreams 物件，dns-benchmark 照跑（不略過）
#[test]
fn e2e_share_falls_back() {
    let p = chained_pair("share-none");
    let c = p.down.wait_chain(" 共用結果同步", WAIT, |c| c["shared"]["lastSyncAt"].is_u64());
    let objects = c["shared"]["objects"].as_array().cloned().unwrap_or_default();
    assert!(!objects.iter().any(|o| o["kind"] == "upstreams"), "{c}");
    assert!(
        !c["shared"]["skippedJobs"].as_array().unwrap().iter().any(|j| j == "dns-benchmark"),
        "{c}"
    );
    // 3.5.0：全新的 state 不帶種子評測結果（以前帶入種子，這裡是 "benchmark"）；這組測試的 autoTypes 是空的，
    // 也不產生預設名單的初始上游：沒有任何自動上游的來源
    assert!(p.down.status()["autoUpstreams"].is_null(), "{}", p.down.status()["autoUpstreams"]);
}

/// 過濾清單伺服器：`/bypass.txt`（繞過防護）
fn list_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf);
            let body = "||dns.example.net^\n";
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    addr
}

fn blocked(r: Option<(u16, Vec<Ipv4Addr>)>) -> bool {
    r.is_some_and(|(_, ips)| ips.contains(&Ipv4Addr::UNSPECIFIED))
}

/// 繞過防護的豁免：登記過的下游問自己的上游主機名稱不擋，其他來源照擋；上游關掉 allowDownstream 後也擋
#[test]
fn e2e_bypass_exemption() {
    let dir = tmp("bypass");
    let (public, own) = (public_dns(VIA_UPSTREAM), public_dns(OWN));
    let lists = list_server();
    let filter = json!({ "filter": { "enabled": true, "lists": [
        { "name": "繞過防護", "url": format!("http://{lists}/bypass.txt"), "category": "ads", "bypass": true }
    ] } });
    let mut up_extra = json!({ "upstream": { "pinned": [format!("udp://{}", public.addr)], "pathCheck": false } });
    merge(&mut up_extra, &filter);
    let mut up = Node::start(&dir, "up", up_extra, vec![]);
    let port = up.dns;
    let ask = move |from: Ipv4Addr| query(port, "dns.example.net", from, Duration::from_millis(TIMEOUT_MS + 1500));
    // 清單載入（啟動後幾秒才下載）
    until(" 繞過防護清單生效", WAIT, &|| up.log(), || {
        blocked(ask(other_client())).then_some(())
    });
    let dnat = Dnat::new(([127, 0, 0, 1], up.dns).into());
    // 下游的上游主機名稱：tls://dns.example.net（放在最後手段，平常不會用到，不連外）
    let down = downstream_node(
        &dir,
        "down",
        dnat.addr,
        &own,
        json!({ "resolver": { "lastResort": ["tls://dns.example.net"] } }),
    );
    down.recheck();
    down.wait_chain(" 下游登記", WAIT, |c| {
        c["state"] == "chained" && c["upstream"]["registered"]["ok"] == true && c["upstream"]["registered"]["names"] == 1
    });
    // 下游的來源（127.0.0.1）不擋；其他來源照擋
    let r = until(" 下游的來源豁免", WAIT, &|| up.log(), || {
        ask(loopback()).filter(|r| !blocked(Some(r.clone())))
    });
    assert_eq!(r, (0, vec![VIA_UPSTREAM]));
    assert!(blocked(ask(other_client())), "其他來源照擋");
    // 上游關掉 allowDownstream：下游也擋
    up.reload_with(json!({ "upstream": { "allowDownstream": false } }));
    until(" 關掉之後下游也擋", WAIT, &|| up.log(), || {
        blocked(ask(loopback())).then_some(())
    });
    drop((down, up));
    cleanup(&dir);
}

/// 3.3.x 的下游（只發 version.kuroshio 與一般查詢）：上游的回答跟 3.3.7 的格式相同
#[test]
fn e2e_3_3_downstream_unaffected() {
    let dir = tmp("old-down");
    let public = public_dns(VIA_UPSTREAM);
    let up = upstream_node(&dir, "up", &public, true);
    let s = UdpSocket::bind((loopback(), 0)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.connect(("127.0.0.1", up.dns)).unwrap();
    s.send(&kuroshio_net::path::build_chaos_txt(4242, "version.kuroshio")).unwrap();
    let mut buf = vec![0u8; 4096];
    let n = s.recv(&mut buf).unwrap();
    let m = Message::parse(&buf[..n]).unwrap();
    assert_eq!((m.id, m.rcode), (4242, 0));
    assert_eq!(m.answers.len(), 1, "{m:?}");
    let a = &m.answers[0];
    assert_eq!((a.rtype, a.class, a.ttl), (16, 3, 0));
    let want = format!("kuroshio/{}", env!("CARGO_PKG_VERSION"));
    let mut rdata = vec![want.len() as u8];
    rdata.extend_from_slice(want.as_bytes());
    assert_eq!(a.data, RData::Raw(rdata), "一段文字 kuroshio/<版本>（3.3.7 的格式）");
    assert_eq!(
        query(up.dns, &fresh_name(), loopback(), Duration::from_secs(3)),
        Some((0, vec![VIA_UPSTREAM]))
    );
    // 3.3.x 的下游不發 chain.kuroshio：上游沒有任何探測紀錄
    assert_eq!(up.chain()["serving"]["probes"]["count24h"], 0);
    assert_eq!(up.chain()["serving"]["downstreams"], json!([]));
    drop(up);
    cleanup(&dir);
}
