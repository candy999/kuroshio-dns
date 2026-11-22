//! 串接模式（3.4.0 WP5，規格 10 第 3 節）的共用結果：上游用真的 `Responder` ＋ 假的 `ShareSource`，
//! 下游用 `Syncer` ＋ 假的 `ShareSink`，中間是本機 TCP（同一個埠也聽 UDP，給 auth 用）。

use kuroshio::chain::client::{Client, Reason, State, Timing};
use kuroshio::chain::ident::NodeKey;
use kuroshio::chain::responder::Responder;
use kuroshio::chain::share::{
    check_ranges, check_upstreams, ShareCache, ShareSink, ShareSource, Syncer, CACHE_MAX, KIND_CDN_POOLS, KIND_CDN_RANGES,
    KIND_FILTER_COPY, KIND_UPSTREAMS,
};
use kuroshio::resolver::Ctx;
use kuroshio_community::chain::{self as proto, ManifestBody, Object, CHUNK};
use kuroshio_community::envelope::{from_cbor, to_cbor};
use kuroshio_community::identity::KeyPair;
use kuroshio_community::util::{now_ms, random_bytes, sha256};
use kuroshio_config::chain::ChainSettings;
use kuroshio_net::path::{Interceptor, Plain, Report};
use kuroshio_proto::message::{Message, RData};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

// ---------------- 上游的假資料來源 ----------------

#[derive(Default)]
#[allow(clippy::disallowed_types)] // 測試只在 64 位元的 CI 上跑；正式程式碼不能用（32 位元 MIPS 沒有 64 位元原子操作）
struct FakeSource {
    upstreams: Mutex<Option<Vec<u8>>>,
    cdn: Mutex<Option<kuroshio_cdn::SharedExport>>,
    pressure_bad: AtomicBool,
    /// 建置時多花的時間（模擬小機器上壓縮、算雜湊很慢）
    delay_ms: std::sync::atomic::AtomicU64,
}

impl ShareSource for FakeSource {
    fn upstreams(&self) -> Option<Vec<u8>> {
        std::thread::sleep(Duration::from_millis(self.delay_ms.load(Ordering::SeqCst)));
        self.upstreams.lock().unwrap().clone()
    }
    fn cdn(&self) -> Option<kuroshio_cdn::SharedExport> {
        self.cdn.lock().unwrap().clone()
    }
    fn pressure_ok(&self) -> bool {
        !self.pressure_bad.load(Ordering::SeqCst)
    }
}

fn upstreams_json(tag: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "generatedAt": "2026-11-18T04:30:00.000Z",
        "tag": tag,
        "selected": [
            { "id": "https://dns.example.net/dns-query", "type": "doh" },
            { "id": "192.0.2.53", "type": "udp" },
            { "id": "tls://dns.example.com", "type": "dot" }
        ]
    }))
    .unwrap()
}

fn pools_json() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "providers": { "cloudflare": { "v4": [{ "ip": "104.16.1.1", "ms": 5 }], "updatedAt": "2026-11-18T05:30:00.000Z" } }
    }))
    .unwrap()
}

fn export(pools: Option<Vec<u8>>, ranges: &[(&str, &str)]) -> kuroshio_cdn::SharedExport {
    kuroshio_cdn::SharedExport {
        pools,
        v6: None,
        ranges: ranges.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
    }
}

// ---------------- 下游的假匯入端 ----------------

struct FakeSink {
    calls: Mutex<Vec<String>>,
    upstreams: Mutex<Option<Vec<u8>>>,
    ranges: Mutex<Option<BTreeMap<String, String>>>,
    pools: Mutex<Option<Vec<u8>>>,
    pressure_bad: AtomicBool,
}

impl FakeSink {
    fn new() -> Arc<FakeSink> {
        Arc::new(FakeSink {
            calls: Mutex::new(Vec::new()),
            upstreams: Mutex::new(None),
            ranges: Mutex::new(None),
            pools: Mutex::new(None),
            pressure_bad: AtomicBool::new(false),
        })
    }
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
    fn note(&self, s: &str) {
        self.calls.lock().unwrap().push(s.to_string());
    }
}

impl ShareSink for FakeSink {
    fn import_upstreams(&self, json: Vec<u8>) -> anyhow::Result<()> {
        self.note("upstreams");
        *self.upstreams.lock().unwrap() = Some(json);
        Ok(())
    }
    fn import_cdn_ranges(&self, files: BTreeMap<String, String>) -> anyhow::Result<()> {
        self.note("cdn-ranges");
        *self.ranges.lock().unwrap() = Some(files);
        Ok(())
    }
    fn import_cdn_pools(&self, json: &[u8]) -> anyhow::Result<()> {
        self.note("cdn-pools");
        *self.pools.lock().unwrap() = Some(json.to_vec());
        Ok(())
    }
    fn import_cdn_v6(&self, _json: &[u8]) -> anyhow::Result<()> {
        self.note("cdn-v6");
        Ok(())
    }
    fn pressure_ok(&self) -> bool {
        !self.pressure_bad.load(Ordering::SeqCst)
    }
}

// ---------------- 上游：真的 Responder，外面包一層本機 DNS 伺服器 ----------------

/// 自己組的清單與分段（冒充者、宣稱的大小不對、未來的種類）
struct Custom {
    manifest: Vec<u8>,
    objects: HashMap<[u8; 8], Vec<u8>>,
}

struct Up {
    resp: Arc<Responder>,
    key: Arc<NodeKey>,
    src: Arc<FakeSource>,
    manifests: AtomicUsize,
    chunks: AtomicUsize,
    /// 分段的內容改掉一個 byte（路上的人竄改）
    tamper: AtomicBool,
    custom: Mutex<Option<Custom>>,
    _dir: TempDir,
}

impl Up {
    fn share_queries(&self) -> usize {
        self.manifests.load(Ordering::SeqCst) + self.chunks.load(Ordering::SeqCst)
    }

    fn keypair(&self) -> Arc<KeyPair> {
        self.key.get().unwrap()
    }

    fn answer(&self, q: &[u8], tcp: bool) -> Option<Vec<u8>> {
        let m = Message::parse(q).ok()?;
        let qs = m.questions.first()?.clone();
        let name = qs.name.trim_end_matches('.').to_ascii_lowercase();
        if qs.qclass != 3 || !proto::in_zone(&name) {
            return Some(Message::response_to(&m, 0).encode());
        }
        let parsed = proto::parse_name(&name);
        match parsed {
            Some(proto::Name::Manifest) => self.manifests.fetch_add(1, Ordering::SeqCst),
            Some(proto::Name::Chunk { .. }) => self.chunks.fetch_add(1, Ordering::SeqCst),
            _ => 0,
        };
        let custom = self.custom.lock().unwrap();
        let mut r = match (&*custom, &parsed) {
            (Some(c), Some(proto::Name::Manifest)) => txt(&m, &c.manifest),
            (Some(c), Some(proto::Name::Chunk { oid, idx })) => match c.objects.get(oid) {
                Some(b) => {
                    let off = (*idx as usize * CHUNK).min(b.len());
                    txt(&m, &b[off..(off + CHUNK).min(b.len())])
                }
                None => Message::response_to(&m, 3),
            },
            _ => {
                let ctx = Ctx {
                    proto: if tcp { "tcp" } else { "udp" },
                    client: IpAddr::V4(Ipv4Addr::LOCALHOST),
                };
                self.resp.answer(&m, &name, &ctx)
            }
        };
        drop(custom);
        if self.tamper.load(Ordering::SeqCst) && matches!(parsed, Some(proto::Name::Chunk { .. })) {
            if let Some(RData::Raw(b)) = r.answers.first_mut().map(|a| &mut a.data) {
                if b.len() > 10 {
                    b[10] ^= 0x01;
                }
            }
        }
        Some(r.encode())
    }
}

fn txt(q: &Message, payload: &[u8]) -> Message {
    let mut r = Message::response_to(q, 0);
    r.answers.push(kuroshio_proto::message::Record {
        name: q.questions[0].name.clone(),
        rtype: 16,
        class: 3,
        ttl: 0,
        data: RData::Raw(proto::txt_rdata(payload)),
    });
    r
}

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tmpdir(tag: &str) -> TempDir {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!(
        "kuroshio-share-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    TempDir(d)
}

fn settings(chain: bool, allow: bool) -> ChainSettings {
    ChainSettings::from_cfg(&kuroshio_config::build(
        &json!({ "upstream": { "chain": chain, "allowDownstream": allow } }),
    ))
}

/// 上游（`share` = 接上共用結果）。回傳（上游，位址）
async fn upstream(allow: bool, src: Arc<FakeSource>, share: bool) -> (Arc<Up>, SocketAddr) {
    let dir = tmpdir("up");
    let key = Arc::new(NodeKey::new(dir.0.join("keys")));
    let resp = Responder::new(&settings(true, allow), key.clone());
    if share {
        let cache = Arc::new(ShareCache::new(src.clone()));
        // 正式環境在啟動時背景先建；測試直接建好，下游第一次來就拿得到
        cache.rebuild_now(now_ms());
        resp.set_share(cache);
    }
    let up = Arc::new(Up {
        resp,
        key,
        src,
        manifests: AtomicUsize::new(0),
        chunks: AtomicUsize::new(0),
        tamper: AtomicBool::new(false),
        custom: Mutex::new(None),
        _dir: dir,
    });
    let (s, l) = loop {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        if let Ok(l) = TcpListener::bind(s.local_addr().unwrap()).await {
            break (s, l);
        }
    };
    let addr = s.local_addr().unwrap();
    {
        let u = up.clone();
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
    {
        let u = up.clone();
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
    }
    (up, addr)
}

// ---------------- 下游 ----------------

struct Down {
    client: Arc<Client>,
    _dir: TempDir,
}

fn timing() -> Timing {
    Timing {
        ask: Duration::from_millis(500),
        heartbeat: Duration::from_secs(60),
        early_min: Duration::from_secs(30),
        early_max: Duration::from_secs(40),
        retry_min: Duration::from_secs(30),
        retry_max: Duration::from_secs(60),
        fail_limit: 3,
    }
}

fn kuroshio(addr: SocketAddr) -> Report {
    Report {
        plain_v4: Plain { udp: true, tcp: true },
        interceptor: Some(Interceptor::Kuroshio("3.4.0".into())),
        hit: Some(addr),
        ..Report::default()
    }
}

/// 下游的狀態機，對 `addr` 做一次路徑檢查之後的流程（通過就綁定）
async fn down(chain: bool, addr: SocketAddr) -> Down {
    let dir = tmpdir("down");
    let key = Arc::new(NodeKey::new(dir.0.join("keys")));
    let client = Client::new(settings(chain, true), key, timing());
    client.set_gateway_override(Some(None));
    client.on_path_report(&kuroshio(addr)).await;
    Down { client, _dir: dir }
}

/// 兩邊都開、上游有評測結果與節點池
async fn pair(src: Arc<FakeSource>) -> (Arc<Up>, Down, Arc<Syncer>, Arc<FakeSink>) {
    let (up, addr) = upstream(true, src, true).await;
    let d = down(true, addr).await;
    assert_eq!(d.client.state(), (State::Chained, None));
    let sink = FakeSink::new();
    let s = Syncer::new(d.client.clone(), sink.clone(), None);
    (up, d, s, sink)
}

fn src_basic() -> Arc<FakeSource> {
    let s = Arc::new(FakeSource::default());
    *s.upstreams.lock().unwrap() = Some(upstreams_json("a"));
    *s.cdn.lock().unwrap() = Some(export(Some(pools_json()), &[("cloudflare-ipv4.txt", "104.16.0.0/13\n")]));
    s
}

async fn ask_tcp(addr: SocketAddr, name: &str) -> Message {
    let q = kuroshio_net::path::build_chaos_txt(7, name);
    let mut t = TcpStream::connect(addr).await.unwrap();
    let mut m = (q.len() as u16).to_be_bytes().to_vec();
    m.extend_from_slice(&q);
    t.write_all(&m).await.unwrap();
    let len = t.read_u16().await.unwrap() as usize;
    let mut r = vec![0u8; len];
    t.read_exact(&mut r).await.unwrap();
    Message::parse(&r).unwrap()
}

async fn ask_udp(addr: SocketAddr, name: &str) -> Message {
    let q = kuroshio_net::path::build_chaos_txt(8, name);
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.send_to(&q, addr).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(3), s.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    Message::parse(&buf[..n]).unwrap()
}

fn txt_of(m: &Message) -> Vec<u8> {
    let RData::Raw(b) = &m.answers[0].data else { panic!() };
    proto::txt_payload(b).unwrap()
}

/// 用 `key` 簽一份清單；`objects` =（物件，傳輸內容）。物件的 id／sha／size 沒填就照內容算
fn craft(key: &KeyPair, objects: Vec<(Object, Vec<u8>)>) -> Custom {
    let mut map = HashMap::new();
    let mut list = Vec::new();
    for (mut o, body) in objects {
        if o.sha.is_empty() {
            let sha = sha256(&[&body]);
            o.sha = sha.to_vec();
            o.id = sha[..8].to_vec();
        }
        if o.size == 0 {
            o.size = body.len() as u64;
        }
        if o.enc.is_empty() {
            o.enc = "zstd".into();
        }
        map.insert(<[u8; 8]>::try_from(o.id.as_slice()).unwrap(), body);
        list.push(o);
    }
    let body = ManifestBody {
        v: proto::PROTO,
        t: "manifest".into(),
        kid: key.kid.to_vec(),
        at: 1,
        app: "3.4.0".into(),
        objects: list,
    };
    Custom {
        manifest: proto::seal(key, "manifest", to_cbor(&body)),
        objects: map,
    }
}

fn obj(k: &str, raw: u64) -> Object {
    Object {
        k: k.into(),
        fmt: 1,
        raw,
        ..Default::default()
    }
}

fn zstd(b: &[u8]) -> Vec<u8> {
    zstd::bulk::compress(b, 3).unwrap()
}

fn status_obj(s: &Syncer, kind: &str) -> Value {
    s.status_json()["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["kind"] == kind)
        .cloned()
        .unwrap_or(Value::Null)
}

// ---------------- 測試 ----------------

#[tokio::test]
async fn manifest_signed_and_objects_verify() {
    let (up, d, s, sink) = pair(src_basic()).await;
    // 上游公告 share，下游看得到
    assert_eq!(up.resp.caps(), vec!["share", "reg"]);
    assert!(d.client.last_probe().unwrap().caps.contains(&"share".to_string()));
    let rep = s.sync_once().await;
    assert_eq!(rep.error, None, "{rep:?}");
    assert_eq!(
        sink.calls(),
        vec!["upstreams", "cdn-pools", "cdn-ranges"],
        "照規格的順序（3.4.3 起節點池在官方範圍之前）"
    );
    // 節點池原封不動
    assert_eq!(sink.pools.lock().unwrap().as_deref(), Some(&pools_json()[..]));
    assert_eq!(
        sink.ranges.lock().unwrap().as_ref().unwrap()["cloudflare-ipv4.txt"],
        "104.16.0.0/13\n"
    );
    // 評測結果：明文拿掉、加上來源
    let u: Value = serde_json::from_slice(sink.upstreams.lock().unwrap().as_ref().unwrap()).unwrap();
    let ids: Vec<&str> = u["selected"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["https://dns.example.net/dns-query", "tls://dns.example.com"]);
    assert_eq!(u["source"]["chain"], kuroshio_community::util::hex(&up.keypair().kid));
    assert_eq!(u["tag"], "a");
    // 狀態
    let st = s.status_json();
    assert_eq!(st["enabled"], true);
    assert!(st["error"].is_null());
    assert!(st["lastSyncAt"].as_u64().is_some());
    let o = status_obj(&s, "upstreams");
    assert_eq!(o["fresh"], true);
    assert!(o["importedAt"].as_u64().is_some());
    assert_eq!(o["at"].as_u64().unwrap(), 1_794_976_200_000, "評測的 generatedAt");
    assert_eq!(st["skippedJobs"], json!(["dns-benchmark", "cdn-pool", "cdn-scan", "cdn-ranges"]));
    // 上游的狀態
    let sv = up.resp.serving_json();
    assert_eq!(sv["share"]["requests"], 1);
    assert_eq!(sv["share"]["ready"], true);
    assert!(sv["share"]["cacheBytes"].as_u64().unwrap() > 0);
    assert!(sv["share"]["lastAt"].as_u64().is_some());
    // 狀態檔
    let snap: Value = serde_json::from_slice(&s.snapshot()).unwrap();
    assert!(snap["kinds"]["upstreams"]["sha"].as_str().unwrap().len() == 64);
}

#[tokio::test]
async fn multi_chunk_object() {
    let src = Arc::new(FakeSource::default());
    // 亂數壓不小：壓縮後還是 200 KiB 多一點 → 7 段
    let data: Vec<u8> = (0..200 * 1024 / 32).flat_map(|_| random_bytes::<32>()).collect();
    *src.cdn.lock().unwrap() = Some(export(Some(data.clone()), &[]));
    let (up, _d, s, sink) = pair(src).await;
    let rep = s.sync_once().await;
    assert_eq!(rep.error, None, "{rep:?}");
    assert_eq!(rep.chunks, 7);
    assert_eq!(up.chunks.load(Ordering::SeqCst), 7);
    assert_eq!(sink.pools.lock().unwrap().as_deref(), Some(&data[..]));
    assert!(rep.imported.contains(&KIND_CDN_POOLS.to_string()));
}

#[tokio::test]
async fn udp_is_refused() {
    let (up, addr) = upstream(true, src_basic(), true).await;
    assert_eq!(ask_udp(addr, proto::MANIFEST_NAME).await.rcode, 5);
    // TCP 拿得到清單；同一個物件的分段用 UDP 問也是 REFUSED
    let m = ask_tcp(addr, proto::MANIFEST_NAME).await;
    assert_eq!(m.rcode, 0);
    let body = proto::open(&txt_of(&m), "manifest", &up.keypair().public).unwrap();
    let mb: ManifestBody = from_cbor(&body).unwrap();
    let oid: [u8; 8] = mb.objects[0].id.as_slice().try_into().unwrap();
    assert_eq!(ask_udp(addr, &proto::chunk_name(&oid, 0)).await.rcode, 5);
    assert_eq!(ask_tcp(addr, &proto::chunk_name(&oid, 0)).await.rcode, 0);
}

#[tokio::test]
async fn allow_downstream_off_refuses_share() {
    let (up, addr) = upstream(false, src_basic(), true).await;
    assert!(up.resp.caps().is_empty());
    assert_eq!(up.resp.serving_json()["share"]["ready"], false);
    assert_eq!(ask_tcp(addr, proto::MANIFEST_NAME).await.rcode, 5);
    assert_eq!(ask_tcp(addr, &proto::chunk_name(&[1; 8], 0)).await.rcode, 5);
    up.manifests.store(0, Ordering::SeqCst);
    up.chunks.store(0, Ordering::SeqCst);
    // 正常的下游：Released(NotAllowed)，根本不會來問
    let d = down(true, addr).await;
    assert_eq!(d.client.state(), (State::Released, Some(Reason::NotAllowed)));
    let sink = FakeSink::new();
    let s = Syncer::new(d.client.clone(), sink.clone(), None);
    let rep = s.sync_once().await;
    assert_eq!(rep.error.as_deref(), Some("not-chained"));
    assert_eq!(up.share_queries(), 0);
    for k in [KIND_UPSTREAMS, KIND_CDN_POOLS, KIND_CDN_RANGES] {
        assert!(!s.fresh(k));
    }
    for j in ["dns-benchmark", "cdn-pool", "cdn-scan", "cdn-ranges"] {
        assert!(!s.skip_job(j), "{j}");
    }
    assert!(sink.calls().is_empty());
    assert!(s.status_json().is_null(), "沒串接時 shared 是 null");
}

#[tokio::test]
async fn tampered_chunk_rejected() {
    let (up, _d, s, sink) = pair(src_basic()).await;
    up.tamper.store(true, Ordering::SeqCst);
    let rep = s.sync_once().await;
    assert_eq!(rep.error, None);
    assert!(sink.calls().is_empty(), "{:?}", sink.calls());
    for k in [KIND_UPSTREAMS, KIND_CDN_RANGES, KIND_CDN_POOLS] {
        assert_eq!(status_obj(&s, k)["error"], "hash-mismatch", "{k}");
        assert_eq!(status_obj(&s, k)["fresh"], false);
        assert!(!s.fresh(k));
    }
    assert!(!s.skip_job("dns-benchmark"));
    // 竄改停止後下一次就正常
    up.tamper.store(false, Ordering::SeqCst);
    s.sync_once().await;
    assert_eq!(sink.calls(), vec!["upstreams", "cdn-pools", "cdn-ranges"]);
}

#[tokio::test]
async fn manifest_signed_by_other_key_rejected() {
    let (up, _d, s, sink) = pair(src_basic()).await;
    let other = KeyPair::generate();
    let body = zstd(&upstreams_json("x"));
    *up.custom.lock().unwrap() = Some(craft(&other, vec![(obj(KIND_UPSTREAMS, 1000), body)]));
    let rep = s.sync_once().await;
    assert_eq!(rep.error.as_deref(), Some("manifest-signature"));
    assert_eq!(rep.chunks, 0);
    assert_eq!(up.chunks.load(Ordering::SeqCst), 0);
    assert!(sink.calls().is_empty());
    assert_eq!(s.status_json()["error"], "manifest-signature");
    assert!(!s.skip_job("dns-benchmark"));
}

#[tokio::test]
async fn oversize_and_bomb_rejected() {
    let (up, _d, s, sink) = pair(src_basic()).await;
    let key = up.keypair();
    // 宣稱 2 MiB 的評測結果：不抓
    let mut big = obj(KIND_UPSTREAMS, 1000);
    big.size = 2 << 20;
    let big_body = zstd(b"{}");
    // 宣稱解壓後 100 bytes，實際是 900 KiB 的零：解壓到超過就中止
    let bomb_body = zstd(&vec![0u8; 900 << 10]);
    let bomb = obj(KIND_CDN_POOLS, 100);
    *up.custom.lock().unwrap() = Some(craft(&key, vec![(big, big_body), (bomb, bomb_body)]));
    let rep = s.sync_once().await;
    assert_eq!(rep.error, None, "{rep:?}");
    assert_eq!(status_obj(&s, KIND_UPSTREAMS)["error"], "too-large");
    assert_eq!(status_obj(&s, KIND_CDN_POOLS)["error"], "too-large");
    assert_eq!(rep.chunks, 1, "只抓了節點池那一段");
    assert!(sink.calls().is_empty());
}

#[tokio::test]
async fn unknown_kind_and_newer_fmt_skipped() {
    let (up, _d, s, sink) = pair(src_basic()).await;
    let key = up.keypair();
    let mut newer = obj(KIND_CDN_POOLS, pools_json().len() as u64);
    newer.fmt = 2;
    let u = upstreams_json("b");
    *up.custom.lock().unwrap() = Some(craft(
        &key,
        vec![
            (obj("future", 10), zstd(b"0123456789")),
            (newer, zstd(&pools_json())),
            (obj(KIND_UPSTREAMS, u.len() as u64), zstd(&u)),
        ],
    ));
    let rep = s.sync_once().await;
    assert_eq!(rep.error, None);
    assert_eq!(sink.calls(), vec!["upstreams"]);
    assert_eq!(status_obj(&s, KIND_CDN_POOLS)["error"], "newer-format");
    assert!(status_obj(&s, "future").is_null(), "不認得的種類不列");
    assert_eq!(rep.chunks, 1);
    assert!(s.skip_job("dns-benchmark"));
    assert!(!s.skip_job("cdn-pool"));
}

#[tokio::test]
async fn unchanged_objects_not_refetched() {
    let (up, _d, s, sink) = pair(src_basic()).await;
    let first = s.sync_once().await;
    assert!(first.chunks >= 3);
    let n = up.chunks.load(Ordering::SeqCst);
    let rep = s.sync_once().await;
    assert_eq!(rep.error, None);
    assert_eq!(rep.manifests, 1);
    assert_eq!(rep.chunks, 0);
    assert_eq!(up.chunks.load(Ordering::SeqCst), n);
    assert_eq!(sink.calls().len(), 3, "沒有重新匯入");
    assert_eq!(status_obj(&s, KIND_UPSTREAMS)["fresh"], true);
}

#[tokio::test]
async fn stale_object_gives_nxdomain_then_recovers() {
    let (up, d, s, sink) = pair(src_basic()).await;
    let (addr, _) = d.client.bound_addr().unwrap();
    s.sync_once().await;
    let old = ask_tcp(addr, proto::MANIFEST_NAME).await;
    let mb: ManifestBody = from_cbor(&proto::open(&txt_of(&old), "manifest", &up.keypair().public).unwrap()).unwrap();
    let old_oid: [u8; 8] = mb
        .objects
        .iter()
        .find(|o| o.k == KIND_UPSTREAMS)
        .unwrap()
        .id
        .as_slice()
        .try_into()
        .unwrap();
    // 上游的評測換了，清單重新產生（超過 10 分鐘）
    *up.src.upstreams.lock().unwrap() = Some(upstreams_json("new"));
    up.resp.share().unwrap().rebuild_now(now_ms());
    assert_eq!(ask_tcp(addr, &proto::chunk_name(&old_oid, 0)).await.rcode, 3, "舊的物件 → NXDOMAIN");
    let rep = s.sync_once().await;
    assert_eq!(rep.error, None);
    assert_eq!(rep.imported, vec![KIND_UPSTREAMS.to_string()]);
    let u: Value = serde_json::from_slice(sink.upstreams.lock().unwrap().as_ref().unwrap()).unwrap();
    assert_eq!(u["tag"], "new");
}

#[test]
fn upstreams_import_filters_plain_and_marks_source() {
    let kid = [0xab; 8];
    let out: Value = serde_json::from_slice(&check_upstreams(&upstreams_json("t"), &kid, 42).unwrap()).unwrap();
    assert_eq!(out["selected"].as_array().unwrap().len(), 2);
    assert!(out["selected"]
        .as_array()
        .unwrap()
        .iter()
        .all(|s| s["type"] != "udp" && s["type"] != "tcp"));
    assert_eq!(out["source"], json!({ "chain": "abababababababab", "at": 42 }));
    assert_eq!(out["generatedAt"], "2026-11-18T04:30:00.000Z", "其他欄位照舊");
    let bad = |v: Value| check_upstreams(&serde_json::to_vec(&v).unwrap(), &kid, 1).is_err();
    assert!(bad(json!({ "selected": { "id": "x" } })), "selected 不是陣列");
    assert!(bad(json!({ "selected": [] })));
    assert!(bad(json!({ "selected": [{ "id": "gopher://dns.example.net" }] })), "id 解析不了");
    assert!(bad(json!({ "selected": [{ "type": "doh" }] })), "沒有 id");
    assert!(
        bad(json!({ "selected": [{ "id": "udp://dns.example.net", "type": "udp" }] })),
        "不支援"
    );
    let many: Vec<Value> = (0..65)
        .map(|i| json!({ "id": format!("https://dns{i}.example.net/dns-query"), "type": "doh" }))
        .collect();
    assert!(bad(json!({ "selected": many })), "超過 64 筆");
    assert!(
        bad(json!({ "selected": [{ "id": "192.0.2.1", "type": "udp" }, { "id": "tcp://192.0.2.2", "type": "tcp" }] })),
        "全部是明文"
    );
    assert!(bad(json!([1, 2])), "不是物件");
    assert!(check_upstreams(b"not json", &kid, 1).is_err());
    assert!(check_upstreams(&vec![b' '; 300 << 10], &kid, 1).is_err(), "太大");
}

#[test]
fn ranges_reject_bad_names_and_cidrs() {
    let ok = |files: Value| check_ranges(&serde_json::to_vec(&json!({ "files": files })).unwrap());
    let r = ok(json!({ "cloudflare-ipv4.txt": "104.16.0.0/13\n\n173.245.48.0/20\n", "cloudflare-ipv6.txt": "2606:4700::/32\n" })).unwrap();
    assert_eq!(r.len(), 2);
    assert!(ok(json!({ "../cloudflare-ipv4.txt": "104.16.0.0/13" })).is_err());
    assert!(ok(json!({ "cloudflare/x-ipv4.txt": "104.16.0.0/13" })).is_err());
    assert!(ok(json!({ "cloudflare.txt": "104.16.0.0/13" })).is_err());
    assert!(ok(json!({ "Cloudflare-ipv4.txt": "104.16.0.0/13" })).is_err());
    assert!(ok(json!({ "-ipv4.txt": "104.16.0.0/13" })).is_err());
    assert!(ok(json!({ "cloudflare-ipv4.txt": "not a cidr" })).is_err());
    assert!(ok(json!({ "cloudflare-ipv4.txt": "104.16.0.0/33" })).is_err());
    // 前綴太短（整個網路都算成這家 CDN）：不收（3.4.3）
    assert!(ok(json!({ "cloudflare-ipv4.txt": "0.0.0.0/0" })).is_err());
    assert!(ok(json!({ "cloudflare-ipv4.txt": "104.0.0.0/7" })).is_err());
    assert!(ok(json!({ "cloudflare-ipv6.txt": "::/0" })).is_err());
    assert!(ok(json!({ "cloudflare-ipv4.txt": "104.0.0.0/8" })).is_ok());
    assert!(ok(json!({ "cloudflare-ipv4.txt": "2606:4700::/32" })).is_err(), "家族不符");
    assert!(ok(json!({ "cloudflare-ipv4.txt": 5 })).is_err());
    assert!(ok(json!({})).is_err());
    assert!(check_ranges(b"[]").is_err());
}

fn saved(at: u64) -> Vec<u8> {
    saved_kid(at, "")
}

/// 3.4.3：紀錄帶著是哪一台上游給的（金鑰 ID）；「新鮮」只算目前綁定的那一台給的
fn saved_kid(at: u64, kid: &str) -> Vec<u8> {
    let k = |sha: &str| json!({ "sha": sha.repeat(64), "at": 1, "importedAt": at, "bytes": 10, "kid": kid });
    serde_json::to_vec(&json!({ "v": 1, "kinds": { "upstreams": k("a"), "cdn-pools": k("b"), "cdn-ranges": k("c") } })).unwrap()
}

fn kid_hex(c: &Client) -> String {
    kuroshio_community::util::hex(&kuroshio_community::identity::kid_of(&c.bound_key().unwrap()))
}

#[tokio::test]
async fn jobs_skipped_only_when_fresh_and_chained() {
    const JOBS: [&str; 4] = ["dns-benchmark", "cdn-pool", "cdn-scan", "cdn-ranges"];
    // 行程裡沒有同步：一律不略過（跟 3.3.7 一樣）
    assert!(JOBS.iter().all(|j| !kuroshio::chain::share_skips(j)));
    // 新鮮＋串接：略過
    let (_up, d, s, _sink) = pair(src_basic()).await;
    s.sync_once().await;
    assert!(JOBS.iter().all(|j| s.skip_job(j)));
    assert!(!s.skip_job("tw-ip"));
    // 新鮮但解除（換網路）：不略過
    d.client.on_wan_changed();
    assert!(!d.client.is_chained());
    assert!(JOBS.iter().all(|j| !s.skip_job(j)));
    // 串接中，但匯入是 37 小時前（狀態檔讀回來的）：不略過；1 小時前：略過
    let (up2, addr2) = upstream(true, src_basic(), true).await;
    let d2 = down(true, addr2).await;
    let kid = kid_hex(&d2.client);
    let old = Syncer::new(
        d2.client.clone(),
        FakeSink::new(),
        Some(&saved_kid(now_ms() - 37 * 3600 * 1000, &kid)),
    );
    assert!(JOBS.iter().all(|j| !old.skip_job(j)));
    let recent = Syncer::new(d2.client.clone(), FakeSink::new(), Some(&saved_kid(now_ms() - 3600 * 1000, &kid)));
    assert!(JOBS.iter().all(|j| recent.skip_job(j)));
    // 3.4.2 以前的紀錄（沒有記是哪一台）或別台給的：不算新鮮（下一次同步會重新確認）
    let other = Syncer::new(d2.client.clone(), FakeSink::new(), Some(&saved(now_ms() - 3600 * 1000)));
    assert!(JOBS.iter().all(|j| !other.skip_job(j)));
    // chain 關著：不發查詢、不略過
    up2.manifests.store(0, Ordering::SeqCst);
    let d3 = down(false, addr2).await;
    assert_eq!(d3.client.state(), (State::None, None));
    let off = Syncer::new(d3.client.clone(), FakeSink::new(), Some(&saved(now_ms())));
    assert_eq!(off.sync_once().await.error.as_deref(), Some("not-chained"));
    assert!(JOBS.iter().all(|j| !off.skip_job(j)));
    assert_eq!(up2.share_queries(), 0);
    // 上游 allow = false：不略過
    let (_up4, addr4) = upstream(false, src_basic(), true).await;
    let d4 = down(true, addr4).await;
    assert_eq!(d4.client.state().1, Some(Reason::NotAllowed));
    let na = Syncer::new(d4.client.clone(), FakeSink::new(), Some(&saved(now_ms())));
    assert!(JOBS.iter().all(|j| !na.skip_job(j)));
}

fn saved_own(at: u64, own: u64, kid: &str) -> Vec<u8> {
    let mut v: serde_json::Value = serde_json::from_slice(&saved_kid(at, kid)).unwrap();
    v["own"] = json!({ "dns-benchmark": own, "cdn-pool": own, "cdn-scan": own, "cdn-ranges": own });
    serde_json::to_vec(&v).unwrap()
}

/// 3.4.2 直系血親：上游的資料新鮮也不會永遠略過，這台自己 7 天內有真的跑過才略過；
/// 第一次串接當成 6 天前跑過（24 小時後才第一次自己跑）；自己的紀錄存在 chain-share.json 的 `own`
#[tokio::test]
async fn own_jobs_still_run_every_7_days() {
    const JOBS: [&str; 4] = ["dns-benchmark", "cdn-pool", "cdn-scan", "cdn-ranges"];
    let (_up, addr) = upstream(true, src_basic(), true).await;
    let d = down(true, addr).await;
    let kid = kid_hex(&d.client);
    let fresh = now_ms() - 3600 * 1000;
    // 自己 8 天前跑過：上游的新鮮也照樣自己跑
    let stale_own = Syncer::new(
        d.client.clone(),
        FakeSink::new(),
        Some(&saved_own(fresh, now_ms() - 8 * 24 * 3600 * 1000, &kid)),
    );
    assert!(JOBS.iter().all(|j| !stale_own.skip_job(j)));
    // 自己跑完一次：之後略過，紀錄寫進快照
    stale_own.note_own_run("cdn-pool");
    assert!(stale_own.skip_job("cdn-pool"));
    assert!(!stale_own.skip_job("cdn-scan"));
    let snap: serde_json::Value = serde_json::from_slice(&stale_own.snapshot()).unwrap();
    assert!(snap["own"]["cdn-pool"].as_u64().unwrap() >= now_ms() - 60_000);
    // 沒有紀錄（第一次串接）：當成 6 天前跑過 → 現在略過，24 小時後到期
    let first = Syncer::new(d.client.clone(), FakeSink::new(), Some(&saved_kid(fresh, &kid)));
    assert!(JOBS.iter().all(|j| first.skip_job(j)));
    let due = first.status_json()["ownRuns"]["dns-benchmark"]["dueAt"].as_u64().unwrap();
    let day = 24 * 3600 * 1000;
    assert!(due > now_ms() + day - 120_000 && due < now_ms() + day + 120_000, "{due}");
    // 時間在未來（時鐘倒退）不算跑過
    let future = Syncer::new(
        d.client.clone(),
        FakeSink::new(),
        Some(&saved_own(fresh, now_ms() + 3600 * 1000, &kid)),
    );
    assert!(JOBS.iter().all(|j| !future.skip_job(j)));
}

/// 3.4.2 直系血親：這台自己的評測結果比上游給的新，同步時不蓋掉自己的（`own-newer`）；
/// 上游有更新的資料時照常匯入
#[tokio::test]
async fn own_newer_benchmark_not_overwritten() {
    let (up, d, _s, _sink) = pair(src_basic()).await;
    let sink = FakeSink::new();
    let s = Syncer::new(d.client.clone(), sink.clone(), None);
    let key = up.keypair();
    let u = upstreams_json("own");
    let mut o = obj(KIND_UPSTREAMS, u.len() as u64);
    o.at = now_ms() - 3600 * 1000;
    *up.custom.lock().unwrap() = Some(craft(&key, vec![(o, zstd(&u))]));
    s.note_own_run("dns-benchmark");
    let rep = s.sync_once().await;
    assert_eq!(rep.error, None);
    assert!(sink.calls().is_empty(), "自己的比較新：不匯入");
    assert_eq!(status_obj(&s, KIND_UPSTREAMS)["error"], "own-newer");
    assert!(s.skip_job("dns-benchmark"), "看過上游這份、自己剛跑過：照樣略過");
    // 上游有更新的一份（時間比自己的新、內容不同）：照常匯入
    let u2 = upstreams_json("newer");
    let mut o2 = obj(KIND_UPSTREAMS, u2.len() as u64);
    o2.at = now_ms() + 1000;
    *up.custom.lock().unwrap() = Some(craft(&key, vec![(o2, zstd(&u2))]));
    s.sync_once().await;
    assert_eq!(sink.calls(), vec!["upstreams"]);
    // 上游宣稱一個未來的時間（10 天後）：不採信，自己剛跑過的比較新，不被蓋掉（3.4.3）
    s.note_own_run("dns-benchmark");
    let u3 = upstreams_json("future");
    let mut o3 = obj(KIND_UPSTREAMS, u3.len() as u64);
    o3.at = now_ms() + 10 * 86_400_000;
    *up.custom.lock().unwrap() = Some(craft(&key, vec![(o3, zstd(&u3))]));
    s.sync_once().await;
    assert_eq!(sink.calls(), vec!["upstreams"], "沒有再匯入");
    assert_eq!(status_obj(&s, KIND_UPSTREAMS)["error"], "own-newer");
}

async fn wait_ready(c: &ShareCache) {
    for _ in 0..500 {
        if c.ready() && !c.building() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("背景建置沒有完成");
}

#[tokio::test]
async fn share_cache_bounded_and_released() {
    let src = Arc::new(FakeSource::default());
    let rnd = |n: usize| -> Vec<u8> { (0..n / 32).flat_map(|_| random_bytes::<32>()).collect() };
    *src.upstreams.lock().unwrap() = Some(rnd(1 << 20));
    *src.cdn.lock().unwrap() = Some(kuroshio_cdn::SharedExport {
        pools: Some(rnd(1 << 20)),
        v6: Some(rnd(1 << 20)),
        ranges: BTreeMap::new(),
    });
    let c = Arc::new(ShareCache::new(src.clone()));
    let key = KeyPair::generate();
    let now = now_ms();
    assert!(c.manifest(&key, now).is_none(), "還沒建好：回 None，背景建置");
    wait_ready(&c).await;
    let m = c.manifest(&key, now).unwrap();
    assert!(c.bytes() > 0);
    assert!(c.bytes() <= CACHE_MAX, "{} > 1 MiB", c.bytes());
    let mb: ManifestBody = from_cbor(&proto::open(&m, "manifest", &key.public).unwrap()).unwrap();
    assert_eq!(mb.objects.len(), 0, "每一種都超過 1 MiB：全部不列");
    // 小一點的：v6 先被放棄。過了 10 分鐘：先回舊的，背景建好再換
    *src.upstreams.lock().unwrap() = Some(rnd(300 << 10));
    *src.cdn.lock().unwrap() = Some(kuroshio_cdn::SharedExport {
        pools: Some(rnd(400 << 10)),
        v6: Some(rnd(400 << 10)),
        ranges: BTreeMap::new(),
    });
    assert_eq!(c.manifest(&key, now + 11 * 60_000).unwrap(), m, "過期了也先回舊的");
    wait_ready(&c).await;
    assert_eq!(c.build_count(), 2);
    let m = c.manifest(&key, now + 11 * 60_000).unwrap();
    let mb: ManifestBody = from_cbor(&proto::open(&m, "manifest", &key.public).unwrap()).unwrap();
    let kinds: Vec<&str> = mb.objects.iter().map(|o| o.k.as_str()).collect();
    assert_eq!(kinds, vec!["upstreams", "cdn-pools"]);
    assert!(c.bytes() <= CACHE_MAX);
    // 10 分鐘內回同一份、不再建置
    assert_eq!(c.manifest(&key, now + 12 * 60_000).unwrap(), m);
    assert!(!c.building());
    assert_eq!(c.build_count(), 2);
    let oid: [u8; 8] = mb.objects[0].id.as_slice().try_into().unwrap();
    assert!(c.chunk(&oid, 0).is_some());
    // 記憶體壓力：不提供
    src.pressure_bad.store(true, Ordering::SeqCst);
    assert!(c.manifest(&key, now + 12 * 60_000).is_none());
    src.pressure_bad.store(false, Ordering::SeqCst);
    // 30 分鐘沒人用：釋放（最後一次用是 now + 12 分鐘）
    c.sweep(now + 41 * 60_000);
    assert!(c.bytes() > 0);
    c.sweep(now + 43 * 60_000);
    assert_eq!(c.bytes(), 0);
    assert!(c.chunk(&oid, 0).is_none());
}

/// 建置很慢（小機器）：第一次問清單立刻回 None、不等建置；同時很多次只建一次；建好之後回新的
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn manifest_never_blocks_and_builds_once() {
    let src = src_basic();
    src.delay_ms.store(400, Ordering::SeqCst);
    let c = Arc::new(ShareCache::new(src.clone()));
    let key = Arc::new(KeyPair::generate());
    let t0 = std::time::Instant::now();
    let mut hs = Vec::new();
    for _ in 0..16 {
        let (c, key) = (c.clone(), key.clone());
        hs.push(tokio::spawn(async move { c.manifest(&key, now_ms()) }));
    }
    for h in hs {
        assert!(h.await.unwrap().is_none(), "還沒建好：立即回 None");
    }
    assert!(t0.elapsed() < Duration::from_millis(300), "不等建置：{:?}", t0.elapsed());
    assert!(c.building());
    wait_ready(&c).await;
    assert_eq!(c.build_count(), 1, "同時很多次只建一次");
    let m = c.manifest(&key, now_ms()).unwrap();
    let mb: ManifestBody = from_cbor(&proto::open(&m, "manifest", &key.public).unwrap()).unwrap();
    assert_eq!(mb.objects.len(), 3);
    // 簽章用問的那把金鑰（同一份內容換金鑰就重簽）
    let other = KeyPair::generate();
    let m2 = c.manifest(&other, now_ms()).unwrap();
    assert!(proto::open(&m2, "manifest", &other.public).is_ok());
    assert_eq!(c.build_count(), 1);
    // 啟動時先建：之後第一次問就拿得到
    let c2 = Arc::new(ShareCache::new(src));
    c2.warm();
    wait_ready(&c2).await;
    assert!(c2.manifest(&key, now_ms()).is_some());
    assert_eq!(c2.build_count(), 1);
}

/// 3.5.0 C11：下游登記成功時先建好清單（之後第一次同步不必先拿到 REFUSED）；10 分鐘內不重建；
/// 記憶體壓力大不建；同時很多次也只建一次
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prewarm_builds_manifest_once() {
    let src = src_basic();
    let c = Arc::new(ShareCache::new(src.clone()));
    src.pressure_bad.store(true, Ordering::SeqCst);
    c.prewarm(now_ms());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!c.ready() && !c.building(), "記憶體壓力大：不建");
    src.pressure_bad.store(false, Ordering::SeqCst);
    for _ in 0..8 {
        c.prewarm(now_ms());
    }
    wait_ready(&c).await;
    assert_eq!(c.build_count(), 1, "同時很多次只建一次");
    let key = KeyPair::generate();
    assert!(c.manifest(&key, now_ms()).is_some(), "登記之後第一次同步就拿得到");
    c.prewarm(now_ms() + 5 * 60_000);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(c.build_count(), 1, "10 分鐘內不重建");
}

/// 3.5.0 C11：REFUSED 之後的重試間隔是 5、15、30 秒（`first` 30 秒的 1/6、1/2、1 倍，加 0～20% 亂數）
#[test]
fn refused_retry_waits_5_15_30() {
    let first = Duration::from_secs(30);
    for (n, lo) in [(1u32, 5u64), (2, 15), (3, 30)] {
        for _ in 0..50 {
            let w = kuroshio::chain::share::refused_wait(n, first);
            assert!(
                w >= Duration::from_secs(lo) && w <= Duration::from_millis(lo * 1200),
                "第 {n} 次：{w:?}"
            );
        }
    }
}

/// 上游的清單還沒建好時回 REFUSED（不卡住回答查詢），建好之後下游同步成功
#[tokio::test]
async fn responder_refuses_until_built() {
    let src = src_basic();
    let dir = tmpdir("not-ready");
    let resp = Responder::new(&settings(true, true), Arc::new(NodeKey::new(dir.0.join("keys"))));
    resp.set_share(Arc::new(ShareCache::new(src)));
    let q = Message::parse(&kuroshio_net::path::build_chaos_txt(1, proto::MANIFEST_NAME)).unwrap();
    let ctx = Ctx {
        proto: "tcp",
        client: IpAddr::V4(Ipv4Addr::LOCALHOST),
    };
    assert_eq!(resp.answer(&q, proto::MANIFEST_NAME, &ctx).rcode, 5);
    wait_ready(resp.share().unwrap()).await;
    let r = resp.answer(&q, proto::MANIFEST_NAME, &ctx);
    assert_eq!(r.rcode, 0);
    assert_eq!(resp.serving_json()["share"]["requests"], 1);
}

/// 3.4.3：清單副本不再共用。舊版上游的清單裡還有 `filter-copy`：下游不抓、不列、不算錯誤，其他照常匯入
#[tokio::test]
async fn old_upstream_filter_copy_ignored() {
    let (up, _d, s, sink) = pair(src_basic()).await;
    let key = up.keypair();
    let body = zstd(b"||ads.example.com^\n");
    let mut fc = obj(KIND_FILTER_COPY, 19);
    fc.name = "https://filter.example.net/list.txt".into();
    fc.hash = "0123456789abcdef".into();
    let u = upstreams_json("fc");
    *up.custom.lock().unwrap() = Some(craft(&key, vec![(obj(KIND_UPSTREAMS, u.len() as u64), zstd(&u)), (fc, body)]));
    let rep = s.sync_once().await;
    assert_eq!(rep.error, None);
    assert_eq!(sink.calls(), vec!["upstreams"]);
    assert_eq!(rep.chunks, 1, "只抓評測結果那一段，清單副本不抓");
    assert!(status_obj(&s, KIND_FILTER_COPY).is_null(), "不列在狀態裡");
}

#[tokio::test]
async fn pressure_defers_sync() {
    let (up, _d, s, sink) = pair(src_basic()).await;
    sink.pressure_bad.store(true, Ordering::SeqCst);
    let rep = s.sync_once().await;
    assert_eq!(rep.error.as_deref(), Some("memory"));
    assert_eq!(rep.manifests, 0);
    assert_eq!(up.share_queries(), 0);
    assert!(sink.calls().is_empty());
    // 上游記憶體壓力大：清單 REFUSED
    sink.pressure_bad.store(false, Ordering::SeqCst);
    up.src.pressure_bad.store(true, Ordering::SeqCst);
    let rep = s.sync_once().await;
    assert_eq!(rep.error.as_deref(), Some("refused"));
    assert!(sink.calls().is_empty());
    assert!(!s.skip_job("dns-benchmark"));
}

/// 只會回同一份清單的 HTTP 伺服器；記下載了幾次
async fn list_server(body: String) -> (SocketAddr, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let n = Arc::new(AtomicUsize::new(0));
    let n2 = n.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { break };
            n2.fetch_add(1, Ordering::SeqCst);
            let body = body.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await;
                let r = format!("HTTP/1.1 200 OK\r\nETag: \"v1\"\r\nContent-Length: {}\r\n\r\n{body}", body.len());
                let _ = s.write_all(r.as_bytes()).await;
            });
        }
    });
    (addr, n)
}

fn persister(dir: &std::path::Path) -> Arc<Mutex<kuroshio::persist::Persister>> {
    let mut p = kuroshio::persist::Persister::new(
        dir.join("state"),
        kuroshio::persist::Policy::new(kuroshio::sysinfo::StorageClass::Disk, 0, 4096),
    );
    p.set_free_probe(|_| Some(10 << 30));
    Arc::new(Mutex::new(p))
}

fn live(dir: &std::path::Path) -> Arc<kuroshio::chain::share::Live> {
    let cfg = kuroshio_config::with_overrides(&json!({ "upstream": { "pinned": ["udp://192.0.2.53"], "fallback": [] } }));
    Arc::new(kuroshio::chain::share::Live {
        mgr: Arc::new(kuroshio::upstreams::Manager::new(&cfg, dir.join("state").join("upstreams.json"))),
        cdn: None,
        seed_upstreams: dir.join("no-seed.json"),
        max_per_provider: 48,
        min_auto: 3,
    })
}

/// 3.4.3：正式的上游（`Live`）有本機清單副本也不列進共用清單：每台黑潮自己跟清單網址下載
#[tokio::test]
async fn live_upstream_does_not_offer_filter_copies() {
    let body: String = (0..300).map(|i| format!("||ads{i}.example.com^\n")).collect();
    let (srv, downloads) = list_server(body).await;
    let cfg = kuroshio_config::with_overrides(&json!({ "filter": { "customRules": [], "lists": [
        { "name": "A", "url": format!("http://{srv}/a.txt"), "category": "ads" }
    ] } }));
    let ud = tmpdir("fc-up");
    let up_p = persister(&ud.0);
    let fu = kuroshio::filtering::FilterService::from_cfg(&cfg, &ud.0).unwrap();
    fu.set_copies(up_p.clone());
    assert!(fu.update_lists(false).await.unwrap());
    up_p.lock().unwrap().flush_all(kuroshio::persist::now_secs()).unwrap();
    assert_eq!(downloads.load(Ordering::SeqCst), 1);
    let up_state = ud.0.join("state").join("upstreams.json");
    std::fs::create_dir_all(up_state.parent().unwrap()).unwrap();
    std::fs::write(&up_state, upstreams_json("live")).unwrap();
    let (up, addr) = upstream(true, Arc::new(FakeSource::default()), false).await;
    let cache = Arc::new(ShareCache::new(live(&ud.0)));
    cache.rebuild_now(now_ms());
    up.resp.set_share(cache);
    let d = down(true, addr).await;
    let sink = FakeSink::new();
    let s = Syncer::new(d.client.clone(), sink.clone(), None);
    let rep = s.sync_once().await;
    assert_eq!(rep.error, None);
    assert_eq!(sink.calls(), vec!["upstreams"], "只有評測結果，沒有清單副本");
    assert!(status_obj(&s, KIND_FILTER_COPY).is_null());
}

/// 3.4.2 Windows 壓力測試：單獨運作、存不了副本（記憶體恢復途中、空間不夠）時，下載到的清單留在記憶體；
/// 記憶體控制一份一份恢復清單時，每次重建都讀記憶體裡那份，不再整份重下載（以前 10 分鐘 26 次、44 MB）
#[tokio::test]
async fn downloaded_list_held_when_copy_not_stored() {
    use kuroshio::resolver::FilterCheck;
    let body: String = (0..3000).map(|i| format!("||ads{i}.example.net^\n")).collect();
    let (srv, downloads) = list_server(body).await;
    let url = format!("http://{srv}/a.txt");
    let cfg = kuroshio_config::with_overrides(&json!({ "filter": { "customRules": [], "lists": [
        { "name": "A", "url": url, "category": "ads" }
    ] } }));
    let d = tmpdir("held-standalone");
    let small = {
        let mut p = kuroshio::persist::Persister::new(
            d.0.join("state"),
            kuroshio::persist::Policy::new(kuroshio::sysinfo::StorageClass::Disk, 0, 4096),
        );
        p.set_free_probe(|_| Some(1 << 20));
        Arc::new(Mutex::new(p))
    };
    let f = kuroshio::filtering::FilterService::from_cfg(&cfg, &d.0).unwrap();
    f.set_copies(small);
    assert!(f.update_lists(false).await.unwrap());
    assert_eq!(downloads.load(Ordering::SeqCst), 1);
    assert!(f.copies().unwrap().meta(&url).is_none(), "存不下：沒有副本");
    assert_eq!(f.stats()["heldCopies"]["count"], 1, "留在記憶體");
    for _ in 0..2 {
        f.rebuild_from_copies().await.unwrap();
        assert!(f.check("ads2999.example.net", 1).unwrap().block);
    }
    assert_eq!(downloads.load(Ordering::SeqCst), 1, "重建讀記憶體裡那份，不再下載");
}

/// 3.4.2 Windows 最後一版驗證（F2）：留在記憶體的清單，空間夠、記憶體能長大之後存成本機副本；
/// 以前要等到下一次清單更新（約 1 天後），中間重新啟動就整份再下載
#[tokio::test]
async fn held_list_persisted_when_room_returns() {
    use kuroshio::resolver::FilterCheck;
    use std::sync::atomic::AtomicUsize;
    let body: String = (0..3000).map(|i| format!("||ads{i}.example.net^\n")).collect();
    let (srv, downloads) = list_server(body).await;
    let url = format!("http://{srv}/a.txt");
    let cfg = kuroshio_config::with_overrides(&json!({ "filter": { "customRules": [], "lists": [
        { "name": "A", "url": url, "category": "ads" }
    ] } }));
    let d = tmpdir("held-persist");
    // 一開始沒有空間，之後空出來
    let free = Arc::new(AtomicUsize::new(1 << 20));
    let pers = {
        let mut p = kuroshio::persist::Persister::new(
            d.0.join("state"),
            kuroshio::persist::Policy::new(kuroshio::sysinfo::StorageClass::Disk, 0, 4096),
        );
        let f = free.clone();
        p.set_free_probe(move |_| Some(f.load(Ordering::SeqCst) as u64));
        Arc::new(Mutex::new(p))
    };
    let f = kuroshio::filtering::FilterService::from_cfg(&cfg, &d.0).unwrap();
    f.set_copies(pers.clone());
    assert!(f.update_lists(false).await.unwrap());
    assert_eq!(f.stats()["heldCopies"]["count"], 1);
    assert_eq!(f.persist_held(), 0, "還是沒有空間：照舊留在記憶體，不白存");
    assert_eq!(f.stats()["heldCopies"]["count"], 1);
    free.store(1 << 34, Ordering::SeqCst);
    assert_eq!(f.persist_held(), 1);
    assert_eq!(f.stats()["heldCopies"]["count"], 0, "存成副本就從記憶體拿掉");
    assert!(f.copies().unwrap().meta(&url).is_some());
    // 還沒寫到磁碟（等下一輪快照）就重建：讀待寫的內容，不重新下載（3.4.2 Windows 複驗 G2）
    assert!(!pers
        .lock()
        .unwrap()
        .file_path(&f.copies().unwrap().meta(&url).unwrap().file)
        .exists());
    // 記憶體控制停用、再恢復這份清單（restore_one 不會先寫出待寫的內容；rebuild_from_copies 會，測不到）
    assert!(f.unload_one().await.unwrap().is_some());
    assert!(f.check("ads2999.example.net", 1).is_none());
    assert!(f.restore_one().await.unwrap().is_some());
    assert!(f.check("ads2999.example.net", 1).unwrap().block);
    assert_eq!(downloads.load(Ordering::SeqCst), 1, "副本還在待寫時恢復：不重新下載");
    pers.lock().unwrap().flush_all(kuroshio::persist::now_secs()).unwrap();
    // 重新啟動：用本機副本建好，不再下載
    let f2 = kuroshio::filtering::FilterService::from_cfg(&cfg, &d.0).unwrap();
    f2.set_copies(pers.clone());
    assert!(f2.build_from_copies().await);
    assert_eq!(downloads.load(Ordering::SeqCst), 1, "重新啟動不再下載");
    // 存成副本時記了下載時間當「上次檢查」：重新啟動後照更新間隔檢查，不是一分鐘後就整份問一次（3.4.3，Windows 複驗 G3）
    assert!(
        f2.first_check_delay(kuroshio::persist::now_secs()).is_some(),
        "留在記憶體再存成的副本也要記上次檢查時間"
    );
}

/// 正式的匯入端：評測結果寫到 `upstream.autoStateFile`、Manager 重讀（明文拿掉），`autoUpstreams.source` 是 chain；
/// 種子資料的評測結果上游不分享
#[tokio::test]
async fn live_upstreams_import_and_source() {
    let dd = tmpdir("live-up");
    std::fs::create_dir_all(dd.0.join("state")).unwrap();
    let cfg = kuroshio_config::with_overrides(&json!({
        "upstream": { "pinned": ["udp://192.0.2.53"], "fallback": [], "autoTypes": ["udp", "doh", "dot"] }
    }));
    let state = dd.0.join("state").join("upstreams.json");
    std::fs::write(
        &state,
        br#"{"generatedAt":"2026-11-01 04:30","selected":[{"id":"192.0.2.99","type":"udp"}]}"#,
    )
    .unwrap();
    let mgr = Arc::new(kuroshio::upstreams::Manager::new(&cfg, state.clone()));
    assert_eq!(kuroshio::chain::share::auto_info(&mgr)["source"], "benchmark");
    let l = kuroshio::chain::share::Live {
        mgr: mgr.clone(),
        cdn: None,
        seed_upstreams: dd.0.join("seed.json"),
        max_per_provider: 48,
        min_auto: 3,
    };
    let j = check_upstreams(&upstreams_json("live"), &[1; 8], 5).unwrap();
    std::thread::sleep(Duration::from_millis(20));
    ShareSink::import_upstreams(&l, j).unwrap();
    let ids: Vec<String> = mgr
        .list_json()
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|u| u["id"].as_str().map(String::from))
        .collect();
    assert!(ids.iter().any(|i| i.starts_with("https://dns.example.net")), "{ids:?}");
    assert!(!ids.iter().any(|i| i.contains("192.0.2.99")), "{ids:?}");
    let auto = kuroshio::chain::share::auto_info(&mgr);
    assert_eq!(auto["source"], "chain");
    assert_eq!(auto["generatedAt"], "2026-11-18T04:30:00.000Z");
    // 上游：種子資料（generatedAt 跟附帶的種子一樣）不分享；CDN、過濾沒啟用 → 沒有
    assert!(ShareSource::upstreams(&l).is_some());
    std::fs::copy(&state, dd.0.join("seed.json")).unwrap();
    assert!(ShareSource::upstreams(&l).is_none());
    // 3.5.0：預設名單產生的初始上游（沒有 generatedAt）不分享；以前附帶的種子（種子檔已經移除）也認得
    let _ = std::fs::remove_file(dd.0.join("seed.json"));
    std::thread::sleep(Duration::from_millis(20));
    std::fs::write(
        &state,
        br#"{"generatedAt":null,"source":"default-list","selected":[{"id":"https://dns.example.com/dns-query","type":"doh","reason":"default"}]}"#,
    )
    .unwrap();
    mgr.reload_auto();
    assert!(ShareSource::upstreams(&l).is_none());
    let auto = kuroshio::chain::share::auto_info(&mgr);
    assert_eq!(
        (auto["source"].as_str(), auto["count"].as_u64()),
        (Some("default-list"), Some(1)),
        "{auto}"
    );
    std::fs::write(
        &state,
        br#"{"generatedAt":"2026-11-10T20:13:34.970Z","selected":[{"id":"https://dns.example.com/dns-query","type":"doh"}]}"#,
    )
    .unwrap();
    assert!(ShareSource::upstreams(&l).is_none(), "3.4.x 的種子");
    assert!(ShareSource::cdn(&l).is_none());
    // 沒有 CDN：節點池匯入失敗（不會被當成匯入過）
    assert!(ShareSink::import_cdn_pools(&l, &pools_json()).is_err());
    // 照這台的設定（只用 DoQ）一台都不能用：不匯入、不算新鮮，自己的評測照排程跑（3.4.3）
    let cfg2 = kuroshio_config::with_overrides(&json!({ "upstream": { "pinned": [], "fallback": [], "autoTypes": ["doq"] } }));
    let state2 = dd.0.join("state").join("upstreams-doq.json");
    let mgr2 = Arc::new(kuroshio::upstreams::Manager::new(&cfg2, state2.clone()));
    let l2 = kuroshio::chain::share::Live {
        mgr: mgr2,
        cdn: None,
        seed_upstreams: dd.0.join("seed.json"),
        max_per_provider: 48,
        min_auto: 3,
    };
    let j = check_upstreams(&upstreams_json("doq"), &[1; 8], 5).unwrap();
    let e = ShareSink::import_upstreams(&l2, j).unwrap_err().to_string();
    assert!(e.contains("not-usable"), "{e}");
    assert!(!state2.exists(), "沒有寫進評測結果");
}

/// 真的服務當上游（評測結果在快照目錄、不是種子）：auth 公告 share、下游拿得到評測結果；
/// `/api/status` 的 `chain.serving.share` 與下游的 `chain.shared`
#[tokio::test]
async fn app_upstream_serves_benchmark_and_status() {
    let dir = tmpdir("app");
    std::fs::create_dir_all(dir.0.join("state")).unwrap();
    std::fs::write(dir.0.join("state").join("upstreams.json"), upstreams_json("app")).unwrap();
    let cfg = kuroshio_config::with_overrides(&json!({
        "admin": { "enabled": false },
        "filter": { "enabled": false },
        "cdn": { "enabled": false },
        "system": { "persistDir": dir.0.join("state").to_string_lossy() },
        "community": { "enabled": false, "dir": dir.0.join("keys").to_string_lossy() },
        "listen": { "plain": { "binds": ["127.0.0.1"], "port": 0 } },
        "upstream": { "pinned": ["udp://192.0.2.53"], "fallback": [], "pathCheck": false },
        "resolver": { "timeoutMs": 800, "lastResort": [], "rankIps": false }
    }));
    let s = kuroshio::app::start(&cfg).await.unwrap();
    let r = s.resolver.chain.get().unwrap().clone();
    assert_eq!(r.caps(), vec!["share", "reg"], "CDN、過濾都啟動之後就緒（WP6 的登記一直都有）");
    // 啟動時已經在背景建置
    wait_ready(r.share().unwrap()).await;
    let d = down(true, s.bound[0]).await;
    assert_eq!(d.client.state(), (State::Chained, None));
    let sink = FakeSink::new();
    let sy = Syncer::new(d.client.clone(), sink.clone(), None);
    let rep = sy.sync_once().await;
    assert_eq!(rep.error, None, "{rep:?}");
    assert_eq!(sink.calls(), vec!["upstreams"], "CDN 沒啟用：只有評測結果");
    let u: Value = serde_json::from_slice(sink.upstreams.lock().unwrap().as_ref().unwrap()).unwrap();
    assert_eq!(u["tag"], "app");
    // 上游的 /api/status.chain（這個行程的狀態機是上游自己的，沒有串接：shared 是 null）
    let st = kuroshio::chain::client::api_json();
    let share = &st["serving"]["share"];
    println!("chain.serving.share = {share}");
    println!("chain.shared（下游）= {}", sy.status_json());
    assert_eq!(share["requests"], 1);
    assert_eq!(share["ready"], true);
    assert!(share["cacheBytes"].as_u64().unwrap() > 0);
    assert!(st["shared"].is_null());
    let auto = kuroshio::chain::share::auto_info(&s.resolver.upstreams);
    assert_eq!(auto["source"], "benchmark");
}

/// 3.4.2 Windows 複驗 G1：一份清單都還沒有（開機就記憶體不足、清單延後）時，記憶體控制不做「暫停全部清單」：
/// 省不到記憶體，卻會讓記憶體恢復後的第一次更新什麼都不做（以前要等記憶體控制恢復這一步，9 分鐘才有清單）
#[tokio::test]
async fn protected_step_not_shed_without_lists() {
    use kuroshio::memgov::Step;
    let cfg = kuroshio_config::with_overrides(&json!({ "filter": { "customRules": [], "lists": [
        { "name": "A", "url": "http://192.0.2.1:9/a.txt", "category": "ads" }
    ] } }));
    let d = tmpdir("protected-empty");
    let f = kuroshio::filtering::FilterService::from_cfg(&cfg, &d.0).unwrap();
    assert_eq!(f.list_rules(), 0);
    let step = kuroshio::memgov::ProtectedStep { filter: f.clone() };
    assert!(!step.can_shed(), "沒有清單：不暫停");
}

/// 3.4.3：因為「上游不可信」（抽查不通過）解除串接：請排程器補跑評測、CDN 範圍與節點池（以前只在評測結果
/// 超過 48 小時時補跑評測，不可信的上游給的範圍與節點池照用到自己的排程）
#[tokio::test]
async fn distrust_release_requests_own_jobs() {
    let (_up, d, s, _sink) = pair(src_basic()).await;
    let asked = Arc::new(Mutex::new(Vec::<String>::new()));
    let a2 = asked.clone();
    s.set_on_stale(Arc::new(move |jobs: &[&str]| {
        a2.lock().unwrap().extend(jobs.iter().map(|j| j.to_string()));
    }));
    assert_eq!(s.sync_once().await.error, None);
    d.client.audit_failed();
    for _ in 0..50 {
        if !asked.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(*asked.lock().unwrap(), vec!["dns-benchmark", "cdn-ranges", "cdn-pool"]);
}

/// 3.4.3：「新鮮」只算目前綁定的那一台上游給的；換成另一台（另一把金鑰）的上游，舊上游給的資料不能再讓這台略過自己的工作
#[tokio::test]
async fn freshness_bound_to_upstream_key() {
    let (_up, d, s, _sink) = pair(src_basic()).await;
    assert_eq!(s.sync_once().await.error, None);
    assert!(s.fresh(KIND_UPSTREAMS));
    // 另一台上游（另一把金鑰）
    let (_up2, addr2) = upstream(true, src_basic(), true).await;
    let d2 = down(true, addr2).await;
    let s2 = Syncer::new(d2.client.clone(), FakeSink::new(), Some(&s.snapshot()));
    assert!(!s2.fresh(KIND_UPSTREAMS), "舊上游給的紀錄：對新上游不算新鮮");
    drop(d);
}
