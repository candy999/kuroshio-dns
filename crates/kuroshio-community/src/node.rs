//! 社群節點：狀態、身分文件、伺服器端處理（規格 03 第 3–9 節）
//!
//! 整合方式：
//! - HTTPS（DoH / DoH3 伺服器）：`/.well-known/kuroshio/v2/*` 交給 [`Community::handle_http`]
//! - TCP 853 ALPN `kuroshio/2`：TLS 連線交給 [`Community::serve_stream`]
//! - UDP 853 ALPN `kuroshio/2`：QUIC 連線交給 [`Community::serve_quic`]
//! - 每分鐘呼叫 [`Community::tick`]；定時把 [`Community::snapshots`] 寫回 state（本模組自己不寫 state）

use crate::config::{Config, Tuning};
use crate::envelope::*;
use crate::identity::{kid_of, Identity, KeyInfo, SignedStmt};
use crate::limits::{NonceCache, RateLimit};
use crate::peers::{load_peers, save_peers, Event, PeerInfo, PeerKey, PeerStore, Rel, View};
use crate::provider::{DataProvider, NoData, PublicResolver, Resolver};
use crate::rules::{self, Action};
use crate::share::{remote_load, remote_snapshot, RemoteSet, ShareSet};
use crate::transport::{canonical_ip, Endpoint, Scheme, Timeouts};
use crate::util::{b64, friend_hash, hex, now_ms, random_bytes, unb64, valid_domain, DAY, HOUR, MINUTE};
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, Weak};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tracing::debug;

/// 允許的時間誤差
pub const MAX_SKEW_MS: u64 = 10 * MINUTE;
/// nonce 保留時間
pub const NONCE_KEEP_MS: u64 = 20 * MINUTE;
/// 身分文件快取
pub const IDENTITY_CACHE_MS: u64 = HOUR;

pub struct Options {
    /// 金鑰目錄（key.pem、identity.json；OpenWrt：/etc/kuroshio/community）
    pub key_dir: PathBuf,
    /// state 根目錄；社群狀態在 `<state_dir>/community/`
    pub state_dir: PathBuf,
    pub provider: Arc<dyn DataProvider>,
    pub resolver: Arc<dyn Resolver>,
    pub tuning: Tuning,
}

impl Options {
    pub fn new(key_dir: impl Into<PathBuf>, state_dir: impl Into<PathBuf>) -> Options {
        Options {
            key_dir: key_dir.into(),
            state_dir: state_dir.into(),
            provider: Arc::new(NoData),
            resolver: Arc::new(PublicResolver),
            tuning: Tuning::default(),
        }
    }
}

/// 對方的身分文件（驗證過簽名）
#[derive(Debug, Clone)]
pub struct PeerIdentity {
    pub domain: String,
    pub keys: Vec<KeyInfo>,
    pub signer: [u8; 8],
    pub endpoints: Vec<String>,
    pub proto: Vec<u8>,
    pub caps: Vec<String>,
    pub since: u64,
    pub net: NetInfo,
    pub friends: Vec<Vec<u8>>,
    pub rot: Vec<SignedStmt>,
    pub has_txt: bool,
    pub channel: Scheme,
    pub rtt_ms: Option<u32>,
    pub jitter_ms: Option<u32>,
    pub loss_pct: Option<u32>,
}

/// 對方還在 v1
#[derive(Debug)]
pub struct OldVersion;
impl std::fmt::Display for OldVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("對方版本較舊（v1）")
    }
}
impl std::error::Error for OldVersion {}

#[derive(Debug, Clone)]
pub(crate) enum Job {
    Sync(String),
    Request(String),
    Identity(String),
    Rotate(String),
    Poke(String, &'static str),
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Check {
    pub ready: bool,
    pub problems: Vec<String>,
    pub at: u64,
    pub resolved: Vec<String>,
}

pub(crate) struct State {
    pub store: PeerStore,
    pub share: ShareSet,
    pub share_at: u64,
    pub remote: HashMap<String, RemoteSet>,
    pub nonces: NonceCache,
    pub rl_all: RateLimit,
    pub rl_req_ip: RateLimit,
    pub rl_req_global: RateLimit,
    pub rl_callback: RateLimit,
    pub id_cache: HashMap<String, (PeerIdentity, u64)>,
    pub busy: HashSet<String>,
    pub pending: HashSet<String>,
    pub poke_last: HashMap<String, u64>,
    pub check: Check,
    pub external: (Vec<String>, Option<Value>),
    pub last_inbound: Option<(String, u64)>,
    pub v1_backup: Option<Vec<u8>>,
    pub doc: Option<(Vec<u8>, u64)>,
    pub pow_need: HashMap<String, u8>,
    pub last_hourly: u64,
}

pub struct Community {
    pub(crate) me: Weak<Community>,
    pub(crate) cfg: RwLock<Config>,
    pub(crate) ident: RwLock<Identity>,
    pub(crate) st: Mutex<State>,
    pub(crate) provider: Arc<dyn DataProvider>,
    pub(crate) resolver: Arc<dyn Resolver>,
    pub(crate) tuning: Tuning,
    jobs: mpsc::UnboundedSender<(u64, Job)>,
    jobs_rx: Mutex<Option<mpsc::UnboundedReceiver<(u64, Job)>>>,
}

type Fail = (u16, &'static str);

fn read_opt(p: &Path) -> Option<Vec<u8>> {
    std::fs::read(p).ok()
}

impl Community {
    /// 讀取金鑰與 state（v1 的 peers.json 會自動轉成 v2，原檔保留成 peers.v1.json）
    pub fn open(cfg: Config, opts: Options) -> Result<Arc<Community>> {
        let cdir = opts.state_dir.join("community");
        // 2.x 預設把金鑰放在 state/community；新的金鑰目錄還沒有時沿用同一把
        let key_file = opts.key_dir.join("key.pem");
        if !key_file.exists() {
            if let Some(old) = read_opt(&cdir.join("key.pem")) {
                std::fs::create_dir_all(&opts.key_dir)?;
                std::fs::write(&key_file, old)?;
            }
        }
        let ident = Identity::load_or_create(&opts.key_dir)?;
        let now = now_ms();
        let mut store = PeerStore::new(cfg.reject_days);
        let mut v1_backup = None;
        // peers.json：先找 v2 位置，再找 2.x 放在金鑰目錄的
        let peers_bytes = read_opt(&cdir.join("peers.json")).or_else(|| read_opt(&opts.key_dir.join("peers.json")));
        if let Some(b) = peers_bytes {
            let (peers, migrated) = load_peers(&b, now);
            store.peers = peers;
            if migrated {
                v1_backup = Some(b);
            }
        }
        let ev = read_opt(&cdir.join("events.json")).or_else(|| read_opt(&opts.key_dir.join("events.json")));
        if let Some(b) = ev {
            store.events = serde_json::from_slice::<Vec<Value>>(&b)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|v| serde_json::from_value::<Event>(v).ok())
                .collect();
        }
        if v1_backup.is_some() {
            let n = store.peers.len();
            store.event("-", "從 v1 遷移", &format!("{n} 筆好友紀錄"));
        }
        let share = read_opt(&cdir.join("share.cbor"))
            .and_then(|b| ShareSet::load(&b))
            .unwrap_or_default();
        let remote = read_opt(&cdir.join("received.cbor.zst"))
            .map(|b| remote_load(&b))
            .unwrap_or_default();
        let t = &opts.tuning;
        let st = State {
            store,
            share,
            share_at: 0,
            remote,
            nonces: NonceCache::new(NONCE_KEEP_MS),
            rl_all: RateLimit::new(t.all_per_ip_minute, MINUTE),
            rl_req_ip: RateLimit::new(t.requests_per_ip_hour, HOUR),
            rl_req_global: RateLimit::new(t.requests_global_hour, HOUR),
            rl_callback: RateLimit::new(t.callbacks_per_domain_hour, HOUR),
            id_cache: HashMap::new(),
            busy: HashSet::new(),
            pending: HashSet::new(),
            poke_last: HashMap::new(),
            check: Check {
                problems: vec!["尚未檢查".into()],
                ..Default::default()
            },
            external: (vec![], None),
            last_inbound: None,
            v1_backup,
            doc: None,
            pow_need: HashMap::new(),
            last_hourly: now,
        };
        let (tx, rx) = mpsc::unbounded_channel();
        let c = Arc::new_cyclic(|me| Community {
            me: me.clone(),
            cfg: RwLock::new(cfg),
            ident: RwLock::new(ident),
            st: Mutex::new(st),
            provider: opts.provider,
            resolver: opts.resolver,
            tuning: opts.tuning,
            jobs: tx,
            jobs_rx: Mutex::new(Some(rx)),
        });
        c.ensure_worker();
        Ok(c)
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn config(&self) -> Config {
        self.cfg.read().unwrap().clone()
    }

    /// 更新設定（規則、上限等可以直接生效）
    pub fn set_config(&self, cfg: Config) {
        let mut st = self.lock();
        st.store.reject_days = cfg.reject_days.max(1) as u64;
        st.doc = None;
        *self.cfg.write().unwrap() = cfg;
    }

    pub fn domain(&self) -> String {
        self.cfg.read().unwrap().domain.clone()
    }

    /// 整合端的額外檢查結果（例如憑證不符、剩不到 7 天），會出現在 check.problems 與狀態頁
    pub fn set_external_check(&self, problems: Vec<String>, cert: Option<Value>) {
        self.lock().external = (problems, cert);
    }

    pub fn is_ready(&self) -> bool {
        self.cfg.read().unwrap().enabled && self.lock().check.ready
    }

    // ---------------- 背景工作（延遲執行的後續動作） ----------------

    fn ensure_worker(&self) {
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let Some(mut rx) = self.jobs_rx.lock().unwrap().take() else {
            return;
        };
        let me = self.me.clone();
        tokio::spawn(async move {
            while let Some((delay, job)) = rx.recv().await {
                let w = me.clone();
                tokio::spawn(async move {
                    if delay > 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                    }
                    if let Some(c) = w.upgrade() {
                        c.run_job(job).await;
                    }
                });
            }
        });
    }

    pub(crate) fn later(&self, delay_ms: u64, job: Job) {
        self.ensure_worker();
        if let Job::Sync(d) = &job {
            if !self.lock().pending.insert(format!("sync:{d}")) {
                return;
            }
        }
        let _ = self.jobs.send((delay_ms, job));
    }

    async fn run_job(&self, job: Job) {
        match job {
            Job::Sync(d) => {
                self.lock().pending.remove(&format!("sync:{d}"));
                self.sync_peer(&d).await;
            }
            Job::Request(d) => {
                self.send_request(&d, false).await;
            }
            Job::Identity(d) => {
                self.refresh_identity(&d).await;
            }
            Job::Rotate(d) => self.send_rotate(&d).await,
            Job::Poke(d, what) => {
                let _ = self.poke(&d, what).await;
            }
        }
    }

    // ---------------- 自我檢查 ----------------

    /// 開啟條件：有網域、至少一個端點（主機 = 網域）、網域解析得到；外加整合端的檢查（憑證）
    pub async fn check(&self) -> Value {
        let cfg = self.config();
        let mut problems = vec![];
        if !cfg.enabled {
            problems.push("社群模式沒有啟用".to_string());
        }
        if !valid_domain(&cfg.domain) {
            problems.push("沒有設定網域".into());
        }
        let eps: Vec<Endpoint> = cfg.endpoints.iter().filter_map(|e| Endpoint::parse(e)).collect();
        if eps.is_empty() {
            problems.push("DoH、DoT、DoQ 至少要開一種".into());
        }
        for e in &eps {
            if e.host != cfg.domain {
                problems.push(format!("端點 {e} 的主機不是 {}", cfg.domain));
            }
        }
        let mut resolved = vec![];
        if valid_domain(&cfg.domain) {
            match self.resolver.lookup(&cfg.domain).await {
                Ok(v) if !v.is_empty() => resolved = v.iter().map(|i| i.to_string()).collect(),
                _ => problems.push(format!("公共 DNS 解析不到 {}", cfg.domain)),
            }
        }
        let mut st = self.lock();
        problems.extend(st.external.0.iter().cloned());
        st.check = Check {
            ready: problems.is_empty(),
            problems,
            at: now_ms(),
            resolved,
        };
        st.doc = None;
        drop(st);
        self.check_json()
    }

    pub(crate) fn check_json(&self) -> Value {
        let cfg = self.config();
        let st = self.lock();
        json!({
            "domain": cfg.domain, "endpoints": self.endpoints_json(&cfg), "cert": st.external.1,
            "resolved": st.check.resolved, "problems": st.check.problems, "ready": st.check.ready, "at": st.check.at,
        })
    }

    pub(crate) fn endpoints_json(&self, cfg: &Config) -> Value {
        let mut o = serde_json::Map::new();
        for e in cfg.endpoints.iter().filter_map(|e| Endpoint::parse(e)) {
            let k = match e.scheme {
                Scheme::Https => "doh",
                Scheme::Dot => "dot",
                Scheme::Doq => "doq",
            };
            o.insert(k.into(), json!(e.to_string()));
        }
        Value::Object(o)
    }

    // ---------------- 身分文件 ----------------

    pub(crate) fn my_endpoints(&self) -> Vec<String> {
        let cfg = self.cfg.read().unwrap();
        let mut v: Vec<Endpoint> = cfg
            .endpoints
            .iter()
            .filter_map(|e| Endpoint::parse(e))
            .filter(|e| e.host == cfg.domain)
            .collect();
        v.sort_by_key(|e| e.scheme.rank());
        v.dedup();
        v.iter().map(|e| e.to_string()).collect()
    }

    /// 簽好名的身分文件（快取 60 秒）
    pub fn identity_bytes(&self) -> Vec<u8> {
        let now = now_ms();
        if let Some((b, at)) = &self.lock().doc {
            if now.saturating_sub(*at) < MINUTE {
                return b.clone();
            }
        }
        let friends: Vec<serde_bytes::ByteBuf> = self
            .lock()
            .store
            .friends()
            .take(200)
            .map(|p| serde_bytes::ByteBuf::from(friend_hash(&p.domain).to_vec()))
            .collect();
        let id = self.ident.read().unwrap();
        let body = IdentityBody {
            t: "identity".into(),
            from: self.domain(),
            ts: now,
            nonce: random_bytes::<12>().to_vec(),
            keys: id.keys(now),
            endpoints: self.my_endpoints(),
            proto: vec![PROTO],
            caps: vec!["sync-delta".into(), "poke".into(), "zstd".into()],
            since: id.since,
            net: self.provider.net_ctx(),
            friends,
            rot: id.rotation_stmts(now),
        };
        let b = seal(&id.key, "identity", to_cbor(&body), None).encode();
        drop(id);
        self.lock().doc = Some((b.clone(), now));
        b
    }

    /// 用我目前的金鑰簽一個信封
    pub fn seal_envelope(&self, action: &str, body: Vec<u8>, enc: Option<&str>) -> Envelope {
        seal(&self.ident.read().unwrap().key, action, body, enc)
    }

    pub(crate) fn sealed(&self, action: &str, body: Vec<u8>) -> (u16, Vec<u8>) {
        (200, self.seal_envelope(action, body, None).encode())
    }

    pub(crate) fn timeouts(&self, max_wire: usize) -> Timeouts {
        Timeouts {
            connect: self.tuning.connect_timeout,
            total: self.tuning.total_timeout,
            max_wire,
        }
    }

    /// 取得並驗證對方的身分文件。`probe` = 順便量連線品質（3 次）；`fresh` = 不用快取
    pub async fn fetch_identity(&self, domain: &str, cands: Vec<Endpoint>, probe: bool, fresh: bool) -> Result<PeerIdentity> {
        let now = now_ms();
        {
            let mut st = self.lock();
            if !fresh {
                if let Some((idn, at)) = st.id_cache.get(domain) {
                    if now.saturating_sub(*at) < IDENTITY_CACHE_MS && (!probe || idn.rtt_ms.is_some()) {
                        return Ok(idn.clone());
                    }
                }
            }
            // 同一個網域每小時最多回連 6 次（防止被拿去當反射攻擊的跳板）
            if !st.rl_callback.take(domain, now) {
                return Err(anyhow!("回連 {domain} 太頻繁，稍後再試"));
            }
        }
        let mut last = anyhow!("沒有可用的端點");
        let mut saw_404 = None;
        let t = self.timeouts(MAX_REQUEST);
        for ep in cands.into_iter().filter(|e| e.host == domain) {
            let n = if probe { self.tuning.probes.max(1) } else { 1 };
            let (mut times, mut fails, mut got) = (vec![], 0u32, None);
            for i in 0..n {
                match crate::transport::call(&*self.resolver, &ep, "identity", None, t).await {
                    Ok(r) if r.status == 200 => {
                        times.push(r.connect_ms);
                        got = Some(r.body);
                    }
                    Ok(r) => {
                        if r.status == 404 && ep.scheme == Scheme::Https {
                            saw_404 = Some(ep.clone());
                        }
                        last = anyhow!("{ep} 回應 HTTP {}", r.status);
                        fails += 1;
                        if i == 0 {
                            break;
                        }
                    }
                    Err(e) => {
                        last = e;
                        fails += 1;
                        if i == 0 {
                            break;
                        }
                    }
                }
            }
            let Some(body) = got else { continue };
            match self.parse_identity(domain, &body, ep.scheme).await {
                Ok(mut idn) => {
                    if probe && !times.is_empty() {
                        times.sort_unstable();
                        idn.rtt_ms = Some(times[times.len() / 2]);
                        idn.jitter_ms = Some(times[times.len() - 1] - times[0]);
                        idn.loss_pct = Some(fails * 100 / n);
                    }
                    self.lock().id_cache.insert(domain.to_string(), (idn.clone(), now));
                    return Ok(idn);
                }
                Err(e) => last = e,
            }
        }
        if let Some(ep) = saw_404 {
            if crate::transport::is_v1(&*self.resolver, &ep, t).await {
                return Err(anyhow::Error::new(OldVersion));
            }
        }
        Err(last)
    }

    async fn parse_identity(&self, domain: &str, bytes: &[u8], channel: Scheme) -> Result<PeerIdentity> {
        let env = Envelope::decode(bytes)?;
        let signer = env.kid().ok_or_else(|| anyhow!("身分文件沒有 kid"))?;
        let b: IdentityBody = from_cbor(env.body())?;
        if b.t != "identity" || b.from != domain {
            return Err(anyhow!("身分文件的網域不符"));
        }
        if b.keys.is_empty() || b.keys.len() > 4 || b.keys.iter().any(|k| k.public.len() != 32 || k.kid != kid_of(&k.public)) {
            return Err(anyhow!("身分文件的金鑰格式錯誤"));
        }
        let key = b
            .keys
            .iter()
            .find(|k| k.kid == signer)
            .ok_or_else(|| anyhow!("身分文件的簽名金鑰不在金鑰清單裡"))?;
        if !env.verify_with("identity", &key.public) {
            return Err(anyhow!("身分文件簽名不符"));
        }
        // 第二管道：_kuroshio TXT，有設定時一定要一致
        let mut has_txt = false;
        if let Ok(v) = self.resolver.txt(&format!("_kuroshio.{domain}")).await {
            let kids: Vec<[u8; 8]> = v.iter().filter_map(|s| crate::identity::parse_txt(s)).collect();
            if !kids.is_empty() {
                has_txt = true;
                if !kids.iter().any(|k| b.keys.iter().any(|x| x.kid == k)) {
                    return Err(anyhow!("TXT 記錄 _kuroshio.{domain} 的金鑰跟身分文件不一致"));
                }
            }
        }
        let endpoints = b
            .endpoints
            .iter()
            .filter_map(|e| Endpoint::parse(e))
            .filter(|e| e.host == domain)
            .take(8)
            .map(|e| e.to_string())
            .collect();
        Ok(PeerIdentity {
            domain: domain.to_string(),
            keys: b.keys,
            signer,
            endpoints,
            proto: b.proto.into_iter().take(8).collect(),
            caps: b.caps.into_iter().take(16).map(|c| crate::util::clip(&c, 32)).collect(),
            since: b.since,
            net: NetInfo {
                asn: b.net.asn,
                colo: crate::util::clip(&b.net.colo, 8),
            },
            friends: b.friends.into_iter().take(200).map(|f| f.into_vec()).collect(),
            rot: b.rot.into_iter().take(4).collect(),
            has_txt,
            channel,
            rtt_ms: None,
            jitter_ms: None,
            loss_pct: None,
        })
    }

    /// 比對對方的金鑰：第一次記住；輪替聲明（舊金鑰簽的）自動接受；
    /// 沒有舊金鑰簽名的變更 → 好友 / 已封鎖的對象要人工確認（回 Err），沒有關係的舊紀錄直接換新
    pub(crate) fn reconcile_keys(&self, domain: &str, idn: &PeerIdentity, now: u64) -> std::result::Result<(), String> {
        let mut st = self.lock();
        let p = st.store.ensure(domain, now);
        let doc_keys: Vec<PeerKey> = idn
            .keys
            .iter()
            .map(|k| PeerKey {
                kid: hex(&k.kid),
                public: b64(&k.public),
                since: k.since,
                until: None,
            })
            .collect();
        if p.active_keys(now).next().is_none() {
            p.keys = doc_keys;
            return Ok(());
        }
        for stmt in &idn.rot {
            apply_rotation(&mut p.keys, domain, &stmt.body, &stmt.sig, now);
        }
        let signer = hex(&idn.signer);
        if p.active_keys(now).any(|k| k.kid == signer) {
            p.pending_key = None;
            return Ok(());
        }
        if p.rel == Rel::Friend || p.my_block {
            let k = doc_keys.into_iter().find(|k| k.kid == signer);
            let first = p.pending_key.as_ref().map(|x| x.kid.clone()) != k.as_ref().map(|x| x.kid.clone());
            p.pending_key = k;
            if first {
                st.store.event(domain, "金鑰變更", "未經舊金鑰簽名，等待人工確認");
            }
            return Err("對方換了金鑰，未經舊金鑰簽名，需要人工確認".into());
        }
        p.keys = doc_keys;
        p.pending_key = None;
        Ok(())
    }

    /// 驗證對方訊息用的公鑰；不認得的 kid → 重新讀一次身分文件（可能剛輪替）
    pub(crate) async fn peer_key(&self, domain: &str, kid: &[u8; 8], refresh: bool) -> Option<Vec<u8>> {
        let now = now_ms();
        let find = |st: &State| {
            st.store
                .get(domain)
                .and_then(|p| p.active_keys(now).find(|k| k.kid == hex(kid)).and_then(|k| unb64(&k.public)))
        };
        if let Some(k) = find(&self.lock()) {
            return Some(k);
        }
        let known = self.lock().store.get(domain).map(|p| !p.keys.is_empty()).unwrap_or(false);
        if !refresh || !known {
            return None;
        }
        self.refresh_identity(domain).await;
        find(&self.lock())
    }

    /// 重新讀對方的身分文件（不用快取），套用輪替聲明
    pub(crate) async fn refresh_identity(&self, domain: &str) -> bool {
        let eps = self.peer_endpoints(domain);
        match self.fetch_identity(domain, eps, false, true).await {
            Ok(idn) => {
                let ok = self.reconcile_keys(domain, &idn, now_ms()).is_ok();
                if ok {
                    let mut st = self.lock();
                    if let Some(p) = st.store.get_mut(domain) {
                        p.endpoints = idn.endpoints.clone();
                    }
                }
                ok
            }
            Err(e) => {
                debug!("社群：重新讀取 {domain} 的身分文件失敗：{e}");
                false
            }
        }
    }

    /// 對方的端點，依「指定的管道 → 上次成功的管道 → DoQ → DoT → HTTPS」排序
    pub(crate) fn peer_endpoints(&self, domain: &str) -> Vec<Endpoint> {
        let st = self.lock();
        let Some(p) = st.store.get(domain) else {
            return Endpoint::defaults(domain, None);
        };
        let mut v: Vec<Endpoint> = p
            .endpoints
            .iter()
            .filter_map(|e| Endpoint::parse(e))
            .filter(|e| e.host == domain)
            .collect();
        if v.is_empty() {
            return Endpoint::defaults(domain, None);
        }
        let prefer = p.prefer_channel.as_deref().and_then(Scheme::parse);
        let last = p.channel.as_deref().and_then(Scheme::parse);
        v.sort_by_key(|e| (Some(e.scheme) != prefer, Some(e.scheme) != last, e.scheme.rank()));
        v.dedup();
        v
    }

    // ---------------- 伺服器端 ----------------

    /// HTTPS：`GET /.well-known/kuroshio/v2/identity`、`POST /.well-known/kuroshio/v2/<動作>`。
    /// 不是社群路徑回 None。回應內容一律 `application/cbor`（204 沒有內容）。
    pub async fn handle_http(&self, method: &str, path: &str, body: &[u8], peer_ip: IpAddr) -> Option<(u16, Vec<u8>)> {
        let path = path.split('?').next().unwrap_or("");
        let rest = path.strip_prefix(BASE_PATH)?;
        let action = rest.strip_prefix('/').unwrap_or(rest);
        let r = match (method, action) {
            ("GET", "identity") | ("GET", "") => self.handle("identity", &[], peer_ip).await,
            ("POST", a) if ACTIONS.contains(&a) && a != "identity" => self.handle(a, body, peer_ip).await,
            _ => (404, error_reply(404, "not-found")),
        };
        Some(r)
    }

    /// TLS / QUIC 管道的一筆請求（信封帶 `a`）→ 回應內容（204 是空的）
    pub async fn handle_frame(&self, frame: &[u8], peer_ip: IpAddr) -> Vec<u8> {
        if frame.len() > MAX_REQUEST {
            return error_reply(413, "too-large");
        }
        let Some(a) = Envelope::decode(frame).ok().and_then(|e| e.a) else {
            return error_reply(400, "bad-envelope");
        };
        let (status, body) = if a == "identity" {
            self.handle("identity", &[], peer_ip).await
        } else {
            self.handle(&a, frame, peer_ip).await
        };
        if status == 204 {
            vec![]
        } else {
            body
        }
    }

    /// TCP 853（ALPN `kuroshio/2`）的 TLS 連線：長度前綴的訊框，可以連續送；閒置 30 秒關閉
    pub async fn serve_stream<S: AsyncRead + AsyncWrite + Unpin>(&self, mut s: S, peer_ip: IpAddr) {
        loop {
            let f = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                crate::transport::read_frame(&mut s, MAX_REQUEST),
            )
            .await;
            let frame = match f {
                Ok(Ok(Some(f))) => f,
                Ok(Err(e)) => {
                    let _ = crate::transport::write_frame(&mut s, &error_reply(413, "too-large")).await;
                    debug!("社群 TLS 連線 {peer_ip}：{e}");
                    break;
                }
                _ => break,
            };
            let resp = self.handle_frame(&frame, peer_ip).await;
            if crate::transport::write_frame(&mut s, &resp).await.is_err() {
                break;
            }
        }
    }

    /// UDP 853（ALPN `kuroshio/2`）的 QUIC 連線：每筆請求一條雙向串流
    pub async fn serve_quic(&self, conn: quinn::Connection, peer_ip: IpAddr) {
        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
            let Some(me) = self.me.upgrade() else { break };
            tokio::spawn(async move {
                let resp = match recv.read_to_end(MAX_REQUEST).await {
                    Ok(b) => me.handle_frame(&b, peer_ip).await,
                    Err(_) => error_reply(413, "too-large"),
                };
                let _ = send.write_all(&resp).await;
                let _ = send.finish();
                let _ = send.stopped().await;
            });
        }
    }

    /// 處理一個動作；`body` 是收到的信封位元組。回傳（狀態碼, 回應內容）
    pub async fn handle(&self, action: &str, body: &[u8], peer_ip: IpAddr) -> (u16, Vec<u8>) {
        self.ensure_worker();
        let ip = canonical_ip(peer_ip);
        let now = now_ms();
        if !self.is_ready() {
            return (503, error_reply(503, "not-ready"));
        }
        if !self.lock().rl_all.take(&ip.to_string(), now) {
            return (429, error_reply(429, "rate-limited"));
        }
        if action == "identity" {
            return (200, self.identity_bytes());
        }
        if body.len() > MAX_REQUEST {
            return (413, error_reply(413, "too-large"));
        }
        let env = match Envelope::decode(body) {
            Ok(e) if e.err.is_none() => e,
            _ => return (400, error_reply(400, "bad-envelope")),
        };
        let r = match action {
            "request" => self.on_request(&env, ip).await,
            "relation" => self.on_relation(&env).await,
            "sync" => self.on_sync(&env).await,
            "poke" => self.on_poke(&env).await,
            "rotate" => self.on_rotate(&env).await,
            _ => Err((404, "not-found")),
        };
        match r {
            Ok(x) => x,
            Err((s, code)) => (s, error_reply(s, code)),
        }
    }

    /// 共同檢查：信封完整、型別、收件者、寄件者、時間、重放（簽名由各動作驗）
    fn pre_check(&self, env: &Envelope, action: &str, now: u64) -> std::result::Result<Head, Fail> {
        if env.enc.is_some() || env.kid().is_none() || env.sig.as_ref().map(|s| s.len()) != Some(64) || env.body.is_none() {
            return Err((400, "bad-envelope"));
        }
        let head: Head = from_cbor(env.body()).map_err(|_| (400, "bad-body"))?;
        if head.t != action {
            return Err((400, "bad-message"));
        }
        let me = self.domain();
        if (action != "rotate" || head.to.is_some()) && head.to.as_deref() != Some(me.as_str()) {
            return Err((400, "wrong-recipient"));
        }
        if !valid_domain(&head.from) || head.from != head.from.to_ascii_lowercase() || head.from == me {
            return Err((400, "bad-sender"));
        }
        if head.ts.abs_diff(now) > MAX_SKEW_MS {
            return Err((400, "clock-skew"));
        }
        if head.nonce.len() != 12 {
            return Err((400, "bad-message"));
        }
        if self.lock().nonces.seen(&head.from, &head.nonce) {
            return Err((400, "replay"));
        }
        Ok(head)
    }

    fn take_nonce(&self, head: &Head, now: u64) -> std::result::Result<(), Fail> {
        if self.lock().nonces.insert(&head.from, &head.nonce, now) {
            Ok(())
        } else {
            Err((400, "replay"))
        }
    }

    fn required_pow(&self, now: u64) -> u8 {
        let base = self.cfg.read().unwrap().pow_bits;
        let busy = self.lock().rl_req_global.count("all", now) > self.tuning.requests_global_hour / 2;
        if busy {
            base.max(20)
        } else {
            base
        }
    }

    fn relation_reply(&self, to: &str, v: &View, req_id: Option<String>, error: Option<String>) -> (u16, Vec<u8>) {
        let b = RelationBody {
            t: "relation".into(),
            from: self.domain(),
            to: to.to_string(),
            ts: now_ms(),
            nonce: random_bytes::<12>().to_vec(),
            pair_id: v.pair_id.clone(),
            status: v.status.clone(),
            req_id,
            until: v.until,
            error,
        };
        self.sealed("relation", to_cbor(&b))
    }

    /// 好友請求（規格 03 第 6 節）
    async fn on_request(&self, env: &Envelope, ip: IpAddr) -> std::result::Result<(u16, Vec<u8>), Fail> {
        let now = now_ms();
        {
            let mut st = self.lock();
            if !st.rl_req_ip.take(&ip.to_string(), now) || !st.rl_req_global.take("all", now) {
                return Err((429, "rate-limited"));
            }
        }
        let bits = self.required_pow(now);
        if !pow_ok(env.body(), bits) {
            return Ok((400, pow_reply(bits)));
        }
        let head = self.pre_check(env, "request", now)?;
        let req: RequestBody = from_cbor(env.body()).map_err(|_| (400, "bad-body"))?;
        if Some(&req.kid[..]) != env.kid.as_deref().map(|k| k.as_slice()) || req.req_id.is_empty() || req.req_id.len() > 64 {
            return Err((400, "bad-message"));
        }
        let from = head.from.clone();
        if self.lock().store.get(&from).map(|p| p.my_block).unwrap_or(false) {
            return Ok(self.relation_reply(&from, &View::of("blocked"), Some(req.req_id), None));
        }
        // 回連對方網域取身分文件：只連請求裡寫的網域本身
        let mut cands: Vec<Endpoint> = req
            .endpoints
            .iter()
            .take(4)
            .filter_map(|e| Endpoint::parse(e))
            .filter(|e| e.host == from)
            .collect();
        if cands.is_empty() {
            cands = Endpoint::defaults(&from, None);
        }
        cands.sort_by_key(|e| e.scheme.rank());
        let idn = match self.fetch_identity(&from, cands, true, false).await {
            Ok(x) => x,
            Err(e) => {
                self.lock().store.event(&from, "請求被拒", &format!("無法驗證對方身分：{e}"));
                return Ok(self.relation_reply(&from, &View::of("unverified"), Some(req.req_id), Some(e.to_string())));
            }
        };
        let Some(key) = idn
            .keys
            .iter()
            .find(|k| Some(&k.kid[..]) == env.kid.as_deref().map(|k| k.as_slice()))
        else {
            return Ok(self.relation_reply(
                &from,
                &View::of("unverified"),
                Some(req.req_id),
                Some("請求的金鑰不在對方的身分文件裡".into()),
            ));
        };
        if !env.verify_with("request", &key.public) {
            return Err((401, "bad-signature"));
        }
        self.take_nonce(&head, now)?;
        // 來源 IP 是否在對方網域的解析結果裡：只標記，不再直接拒絕
        let ip_match = self
            .resolver
            .lookup(&from)
            .await
            .map(|v| v.into_iter().any(|x| canonical_ip(x) == ip))
            .unwrap_or(false);
        if let Err(e) = self.reconcile_keys(&from, &idn, now) {
            return Ok(self.relation_reply(&from, &View::of("key-mismatch"), Some(req.req_id), Some(e)));
        }
        let cfg = self.config();
        let my_friends: HashSet<Vec<u8>> = self.lock().store.friends().map(|p| friend_hash(&p.domain).to_vec()).collect();
        let info = PeerInfo {
            rtt_ms: idn.rtt_ms,
            jitter_ms: idn.jitter_ms,
            loss_pct: idn.loss_pct,
            asn: self.provider.asn_of(ip),
            colo: idn.net.colo.clone(),
            age_days: Some((now.saturating_sub(idn.since) / DAY) as u32),
            mutual: Some(idn.friends.iter().filter(|f| my_friends.contains(*f)).count() as u32),
            ip: Some(ip.to_string()),
            ip_match: Some(ip_match),
            has_txt: Some(idn.has_txt),
            proto: idn.proto.clone(),
            caps: idn.caps.clone(),
            ..Default::default()
        };
        let my_asn = self.provider.net_ctx().asn;
        let mut rule_name = String::new();
        let view = {
            let mut st = self.lock();
            st.last_inbound = Some((from.clone(), now));
            let v = st
                .store
                .on_request(&from, &req.req_id, idn.endpoints.clone(), info, now, |p, friend_count| {
                    let (a, name) = rules::decide(
                        &cfg.rules,
                        &rules::Ctx {
                            domain: &from,
                            info: &p.info,
                            my_asn,
                            friend_count,
                        },
                    );
                    rule_name = name;
                    if a == Action::Accept && friend_count >= cfg.max_friends {
                        Action::Manual
                    } else {
                        a
                    }
                });
            if !rule_name.is_empty() {
                st.store.event(&from, "套用規則", &rule_name);
            }
            v
        };
        if view.status == "accepted" {
            self.later(self.tuning.follow_up_ms, Job::Sync(from.clone()));
        }
        Ok(self.relation_reply(&from, &view, Some(req.req_id), None))
    }

    /// relation：對方同意 / 拒絕 / 封鎖 / 刪除了我，或要對一次狀態；回應我這邊的看法
    async fn on_relation(&self, env: &Envelope) -> std::result::Result<(u16, Vec<u8>), Fail> {
        let now = now_ms();
        let head = self.pre_check(env, "relation", now)?;
        let from = head.from.clone();
        let key = self
            .peer_key(&from, &env.kid().unwrap(), true)
            .await
            .ok_or((401, "unknown-sender"))?;
        if !env.verify_with("relation", &key) {
            return Err((401, "bad-signature"));
        }
        self.take_nonce(&head, now)?;
        let rb: RelationBody = from_cbor(env.body()).map_err(|_| (400, "bad-body"))?;
        let v = View {
            status: rb.status.clone(),
            pair_id: rb.pair_id.clone(),
            until: rb.until,
            req_id: rb.req_id.clone(),
        };
        let (follow, friend, mine) = {
            let mut st = self.lock();
            st.last_inbound = Some((from.clone(), now));
            let f = st.store.on_notify(&from, &v, now);
            let p = st.store.get(&from);
            let friend = p.map(|p| p.rel == Rel::Friend).unwrap_or(false);
            let pid = p.and_then(|p| p.pair_id.clone());
            (f, friend, st.store.view_of(&from, pid.as_deref(), now))
        };
        if rb.status == "accepted" && friend {
            self.later(self.tuning.follow_up_ms, Job::Sync(from.clone()));
        }
        if follow.re_request {
            self.later(self.tuning.rerequest_ms, Job::Request(from.clone()));
        }
        Ok(self.relation_reply(&from, &mine, None, None))
    }

    /// sync：好友來拉資料（只有好友、而且配對編號相符才給）
    async fn on_sync(&self, env: &Envelope) -> std::result::Result<(u16, Vec<u8>), Fail> {
        let now = now_ms();
        let head = self.pre_check(env, "sync", now)?;
        let from = head.from.clone();
        let req: SyncRequest = from_cbor(env.body()).map_err(|_| (400, "bad-body"))?;
        let mut resp = SyncResponse {
            t: "sync".into(),
            from: self.domain(),
            to: from.clone(),
            ts: now,
            nonce: random_bytes::<12>().to_vec(),
            ..Default::default()
        };
        let Some(key) = self.peer_key(&from, &env.kid().unwrap(), true).await else {
            resp.status = "not-friend".into();
            return Ok(self.sealed("sync", to_cbor(&resp)));
        };
        if !env.verify_with("sync", &key) {
            return Err((401, "bad-signature"));
        }
        self.take_nonce(&head, now)?;
        self.refresh_share(now, false);
        let mut st = self.lock();
        st.last_inbound = Some((from.clone(), now));
        let v = st.store.view_of(&from, req.pair_id.as_deref(), now);
        if v.status != "accepted" {
            drop(st);
            resp.status = v.status;
            resp.until = v.until;
            return Ok(self.sealed("sync", to_cbor(&resp)));
        }
        let mutual = {
            let p = st.store.get_mut(&from).unwrap();
            p.last_contact = now;
            now.saturating_sub(p.last_sync_ok) > 5 * MINUTE
        };
        let d = st.share.delta(req.epoch.as_deref().map(|e| e.as_slice()), req.since);
        resp.epoch = Some(serde_bytes::ByteBuf::from(st.share.epoch.to_vec()));
        resp.seq = Some(st.share.seq);
        drop(st);
        // 互相同步：好友來拉我的資料，而我超過 5 分鐘沒拉對方的，就順便拉一次
        if mutual {
            self.later(self.tuning.mutual_sync_ms, Job::Sync(from.clone()));
        }
        resp.ctx = Some(self.provider.net_ctx());
        if d.unchanged {
            resp.status = "unchanged".into();
            return Ok(self.sealed("sync", to_cbor(&resp)));
        }
        resp.status = "ok".into();
        resp.full = Some(d.full);
        resp.upserts = d.upserts.into_iter().map(|r| Lenient(Some(r))).collect();
        resp.deletes = d.deletes;
        let plain = to_cbor(&resp);
        Ok((200, self.seal_envelope("sync", compress(&plain), Some("zstd")).encode()))
    }

    /// poke：好友說「我這邊有變化」；不是好友或 pairId 不符一律忽略，回應都一樣
    async fn on_poke(&self, env: &Envelope) -> std::result::Result<(u16, Vec<u8>), Fail> {
        let now = now_ms();
        let quiet = Ok((204, vec![]));
        let Ok(head) = self.pre_check(env, "poke", now) else { return quiet };
        let Some(key) = self.peer_key(&head.from, &env.kid().unwrap(), false).await else {
            return quiet;
        };
        if !env.verify_with("poke", &key) || self.take_nonce(&head, now).is_err() {
            return quiet;
        }
        let Ok(pk) = from_cbor::<PokeBody>(env.body()) else { return quiet };
        let ok = {
            let st = self.lock();
            st.store
                .get(&head.from)
                .map(|p| p.rel == Rel::Friend && p.pair_id.is_some() && p.pair_id == pk.pair_id)
                .unwrap_or(false)
        };
        if !ok {
            return quiet;
        }
        let (lo, hi) = self.tuning.poke_pull_ms;
        let delay = lo + crate::util::random_below(hi.saturating_sub(lo) + 1);
        match pk.what.as_str() {
            "data" | "relation" => self.later(delay, Job::Sync(head.from.clone())),
            "rotate" => self.later(0, Job::Identity(head.from.clone())),
            _ => {}
        }
        quiet
    }

    /// rotate：對方換金鑰（舊金鑰簽名）
    async fn on_rotate(&self, env: &Envelope) -> std::result::Result<(u16, Vec<u8>), Fail> {
        let now = now_ms();
        let head = self.pre_check(env, "rotate", now)?;
        let rb: RotateBody = from_cbor(env.body()).map_err(|_| (400, "bad-body"))?;
        if Some(&rb.old[..]) != env.kid.as_deref().map(|k| k.as_slice()) {
            return Err((400, "bad-message"));
        }
        let mut st = self.lock();
        let Some(p) = st.store.get_mut(&head.from) else {
            return Err((401, "unknown-sender"));
        };
        if !p.active_keys(now).any(|k| k.kid == hex(&rb.old)) {
            return Err((401, "unknown-sender"));
        }
        if !apply_rotation(&mut p.keys, &head.from, env.body(), env.sig.as_deref().unwrap(), now) {
            return Err((401, "bad-signature"));
        }
        drop(st);
        self.take_nonce(&head, now)?;
        let mut st = self.lock();
        st.id_cache.remove(&head.from);
        st.store.event(&head.from, "對方更換金鑰", &format!("新金鑰 {}", hex(&rb.new.kid)));
        Ok((204, vec![]))
    }

    // ---------------- 分享集合 ----------------

    /// 從 DataProvider 重建分享集合（10 分鐘一次；`force` 立即）；有變動回 true
    pub fn refresh_share(&self, now: u64, force: bool) -> bool {
        {
            let st = self.lock();
            if !force && st.share_at != 0 && now.saturating_sub(st.share_at) < self.tuning.share_refresh_ms {
                return false;
            }
        }
        let cfg = self.config();
        let recs: Vec<WireRecord> = self
            .provider
            .local_records()
            .iter()
            .filter(|r| match r {
                crate::provider::LocalRecord::Site { .. } | crate::provider::LocalRecord::Cross { .. } => cfg.share_domains,
                crate::provider::LocalRecord::Upstream { .. } => cfg.share_upstreams,
                _ => true,
            })
            .filter_map(|r| crate::share::to_wire(r, now))
            .collect();
        let mut st = self.lock();
        st.share_at = now;
        st.share.refresh(recs, now)
    }

    /// state 重置：換新的 epoch，好友下次同步拿完整集合
    pub fn reset_share(&self) {
        let mut st = self.lock();
        st.share.reset();
        st.share_at = 0;
    }

    // ---------------- 快照 ----------------

    /// 要寫回 state 的檔案（相對 state 根目錄的路徑, 內容）；寫入時機由整合端決定（暫存檔 + 改名、內容沒變不寫）
    pub fn snapshots(&self) -> Vec<(String, Vec<u8>)> {
        let now = now_ms();
        let st = self.lock();
        let mut v = vec![
            ("community/peers.json".to_string(), save_peers(&st.store.peers, now)),
            (
                "community/events.json".to_string(),
                serde_json::to_vec(&st.store.events[st.store.events.len().saturating_sub(500)..]).unwrap_or_default(),
            ),
            ("community/share.cbor".to_string(), st.share.snapshot()),
            ("community/received.cbor.zst".to_string(), remote_snapshot(&st.remote)),
        ];
        let ids = crate::client::upstream_ids(&st);
        v.push((
            "community/upstream-candidates.json".to_string(),
            serde_json::to_vec(&json!({ "updatedAt": now, "ids": ids })).unwrap_or_default(),
        ));
        if let Some(b) = &st.v1_backup {
            v.push(("community/peers.v1.json".to_string(), b.clone()));
        }
        v
    }

    /// 我的身分資訊（admin 與測試用）
    pub fn kid(&self) -> [u8; 8] {
        self.ident.read().unwrap().key.kid
    }

    pub fn fingerprint(&self) -> String {
        self.ident.read().unwrap().key.fingerprint()
    }

    pub fn txt_value(&self) -> String {
        self.ident.read().unwrap().txt_value()
    }

    /// 某個好友的狀態（JSON，同 admin peers 的一筆）
    pub fn peer(&self, domain: &str) -> Option<crate::peers::Peer> {
        self.lock().store.get(domain).cloned()
    }

    /// 直接修改好友紀錄（管理工具、測試用）
    pub fn with_peer<R>(&self, domain: &str, f: impl FnOnce(&mut crate::peers::Peer) -> R) -> R {
        let now = now_ms();
        let mut st = self.lock();
        f(st.store.ensure(domain, now))
    }

    pub fn events(&self) -> Vec<Event> {
        self.lock().store.events.iter().rev().take(200).cloned().collect()
    }
}

/// 驗證並套用輪替聲明：舊金鑰（必須是我記住的）簽的 → 加入新金鑰，舊的 7 天後失效。成功回 true
pub(crate) fn apply_rotation(keys: &mut Vec<PeerKey>, domain: &str, body: &[u8], sig: &[u8], now: u64) -> bool {
    let Ok(rb) = from_cbor::<RotateBody>(body) else { return false };
    if rb.t != "rotate" || rb.from != domain || rb.new.public.len() != 32 || rb.new.kid != kid_of(&rb.new.public) {
        return false;
    }
    let old = hex(&rb.old);
    let Some(oldk) = keys
        .iter()
        .find(|k| k.kid == old && k.until.map(|u| now < u).unwrap_or(true))
        .cloned()
    else {
        return false;
    };
    let Some(public) = unb64(&oldk.public) else { return false };
    if sig.len() != 64 || !crate::identity::verify(&public, &signing_input("rotate", body), sig) {
        return false;
    }
    let newkid = hex(&rb.new.kid);
    if !keys.iter().any(|k| k.kid == newkid) {
        keys.push(PeerKey {
            kid: newkid,
            public: b64(&rb.new.public),
            since: rb.new.since,
            until: None,
        });
    }
    for k in keys.iter_mut().filter(|k| k.kid == old) {
        k.until = Some(k.until.unwrap_or(u64::MAX).min(now + crate::identity::ROTATE_OVERLAP_MS));
    }
    true
}
