//! 由設定組出整個服務

use crate::acl::Acl;
use crate::iprank::IpRank;
use crate::persist::{Persister, Policy};
use crate::resolver::{LocalForward, Params, Resolver};
use crate::server::Server;
use crate::sysinfo::{self, Pressure, StorageClass, SysInfo};
use crate::upstream::Upstream;
use crate::upstreams::Manager;
use anyhow::{bail, Result};
use kuroshio_config::{get, Tier};
use serde_json::{json, Value};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{info, warn};

fn strings(v: Option<&Value>) -> Vec<String> {
    v.and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

/// 2.x 的 state 路徑（`./state/xxx`）對應到 3.0 的快照目錄
pub fn state_path(cfg: &Value, rel: &str) -> PathBuf {
    let rel = rel.trim_start_matches("./");
    let rel = rel.strip_prefix("state/").unwrap_or(rel);
    persist_dir(cfg).join(rel)
}

/// 由設定組出解析器
pub fn build_resolver(cfg: &Value) -> Result<Arc<Resolver>> {
    let state = get(cfg, "upstream.autoStateFile")
        .and_then(Value::as_str)
        .unwrap_or("./state/upstreams.json");
    crate::tls::set_bootstrap(&strings(get(cfg, "upstream.bootstrap")));
    let ups = Arc::new(Manager::new(cfg, state_path(cfg, state)));
    if ups.active().is_empty() && ups.backup().is_empty() {
        bail!("沒有可用的上游（upstream.pinned / upstream.fallback / resolver.lastResort）");
    }
    let cache_max = get(cfg, "resolver.cacheMax").and_then(Value::as_u64).unwrap_or(100_000) as usize;
    let iprank = Arc::new(IpRank::new(cfg, cache_max / 2));
    // 區網網域交給本機 dnsmasq（OpenWrt 的 UCI 轉換會在需要時設定 resolver.localForward）
    let local = get(cfg, "resolver.localForward").and_then(|lf| {
        let server = lf.get("server")?.as_str()?;
        let up = Upstream::parse(server).ok()?;
        let domains = strings(lf.get("domains"))
            .iter()
            .map(|d| d.trim_matches('.').to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect();
        Some(LocalForward {
            up,
            domains,
            private_ptr: lf.get("privatePtr").and_then(Value::as_bool).unwrap_or(true),
        })
    });
    Ok(Resolver::new(Params::from_cfg(cfg), ups, cache_max, iprank, local))
}

#[derive(Debug, Default, Clone)]
pub struct Encrypted {
    pub dot: Option<SocketAddr>,
    pub doh: Option<SocketAddr>,
    pub doq: Option<SocketAddr>,
    pub doh3: Option<SocketAddr>,
}

fn rel_path(base: &std::path::Path, p: &str) -> PathBuf {
    let pp = std::path::Path::new(p);
    if pp.is_absolute() {
        pp.to_path_buf()
    } else {
        base.join(pp.strip_prefix("./").unwrap_or(pp))
    }
}

/// DoT / DoH 伺服器（規格 01 第 1.1 節）；開不起來只記警告，區網 DNS 照常
async fn start_encrypted(cfg: &Value, resolver: &Arc<Resolver>, base: &std::path::Path) -> Encrypted {
    use crate::encrypted::{listen_doh, listen_doh3, listen_doq, listen_dot, CertStore, DohOptions, Limits};
    let mut out = Encrypted::default();
    let limits = Limits::new(get(cfg, "system.maxTlsConnections").and_then(Value::as_u64).unwrap_or(2048) as usize);
    let mut stores: std::collections::HashMap<(PathBuf, PathBuf), Arc<CertStore>> = std::collections::HashMap::new();
    let mut store_for = |c: &str, k: &str| -> Arc<CertStore> {
        let key = (rel_path(base, c), rel_path(base, k));
        stores
            .entry(key.clone())
            .or_insert_with(|| {
                let s = CertStore::new(key.0.clone(), key.1.clone());
                s.spawn_watch();
                s
            })
            .clone()
    };
    let addr = |sec: &str, dport: u64| -> Option<SocketAddr> {
        let host = get(cfg, &format!("listen.{sec}.host")).and_then(Value::as_str).unwrap_or("0.0.0.0");
        let port = get(cfg, &format!("listen.{sec}.port")).and_then(Value::as_u64).unwrap_or(dport) as u16;
        host.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, port))
    };
    let on = |sec: &str| get(cfg, &format!("listen.{sec}.enabled")).and_then(Value::as_bool).unwrap_or(false);
    let s = |k: &str| get(cfg, k).and_then(Value::as_str).unwrap_or("").to_string();
    if on("dot") {
        let (c, k) = (s("listen.dot.cert"), s("listen.dot.key"));
        match (addr("dot", 853), c.is_empty() || k.is_empty()) {
            (_, true) => warn!("DoT 需要憑證（listen.dot.cert / key），沒有啟動"),
            (None, _) => warn!("DoT 監聽位址格式錯誤"),
            (Some(a), false) => match listen_dot(a, store_for(&c, &k), resolver.clone(), limits.clone()).await {
                Ok(b) => out.dot = Some(b),
                Err(e) => warn!("{e:#}"),
            },
        }
    }
    // DoQ（UDP 853）：跟 DoT 共用憑證（沒有 DoT 憑證時用 DoH 的）
    let quic_max = get(cfg, "system.maxQuicConnections").and_then(Value::as_u64).unwrap_or(512) as usize;
    if on("doq") {
        let (mut c, mut k) = (s("listen.dot.cert"), s("listen.dot.key"));
        if c.is_empty() || k.is_empty() {
            (c, k) = (s("listen.doh.cert"), s("listen.doh.key"));
        }
        match (addr("doq", 853), c.is_empty() || k.is_empty()) {
            (_, true) => warn!("DoQ 需要憑證（listen.dot.cert / key），沒有啟動"),
            (None, _) => warn!("DoQ 監聽位址格式錯誤"),
            (Some(_), false) if quic_max == 0 => {
                warn!("這台硬體的等級不開 QUIC（system.maxQuicConnections = 0），DoQ 沒有啟動；要強制開請設定 system.maxQuicConnections")
            }
            (Some(a), false) => match listen_doq(a, store_for(&c, &k), resolver.clone(), Limits::new(quic_max)).await {
                Ok(b) => out.doq = Some(b),
                Err(e) => warn!("{e:#}"),
            },
        }
    }
    if on("doh") {
        let (c, k) = (s("listen.doh.cert"), s("listen.doh.key"));
        let certs = if c.is_empty() || k.is_empty() {
            None
        } else {
            Some(store_for(&c, &k))
        };
        let path = {
            let p = s("listen.doh.path");
            if p.is_empty() {
                "/dns-query".to_string()
            } else {
                p
            }
        };
        let trust_proxy = get(cfg, "listen.doh.trustProxy").and_then(Value::as_bool).unwrap_or(false);
        let mut opts = DohOptions {
            path: path.clone(),
            trust_proxy,
            alt_svc: None,
        };
        // DoH3（UDP，預設跟 DoH 同一個埠號）：需要憑證；開成功時 DoH 的回應加 Alt-Svc
        if get(cfg, "listen.doh.http3").and_then(Value::as_bool).unwrap_or(false) {
            let h3_port = get(cfg, "listen.doh.http3Port").and_then(Value::as_u64).filter(|p| *p > 0);
            match (addr("doh", 8443), &certs) {
                (_, None) => warn!("DoH3 需要憑證，沒有啟動"),
                (None, _) => warn!("DoH 監聽位址格式錯誤"),
                _ if quic_max == 0 => warn!("這台硬體的等級不開 QUIC（system.maxQuicConnections = 0），DoH3 沒有啟動"),
                (Some(a), Some(c)) => {
                    let ua = SocketAddr::new(a.ip(), h3_port.map(|p| p as u16).unwrap_or(a.port()));
                    let o3 = DohOptions {
                        path,
                        trust_proxy: false,
                        alt_svc: None,
                    };
                    match listen_doh3(ua, c.clone(), resolver.clone(), o3, Limits::new(quic_max)).await {
                        Ok(b) => {
                            out.doh3 = Some(b);
                            // 對外埠號可能不同（例如 WAN 443 → 本機 8443）：listen.doh.altSvcPort 可以指定
                            let adv = get(cfg, "listen.doh.altSvcPort")
                                .and_then(Value::as_u64)
                                .filter(|p| *p > 0)
                                .unwrap_or(b.port() as u64);
                            opts.alt_svc = Some(format!("h3=\":{adv}\"; ma=86400"));
                        }
                        Err(e) => warn!("{e:#}"),
                    }
                }
            }
        }
        match addr("doh", 8443) {
            None => warn!("DoH 監聽位址格式錯誤"),
            Some(a) => match listen_doh(a, certs, resolver.clone(), opts, limits.clone()).await {
                Ok(b) => out.doh = Some(b),
                Err(e) => warn!("{e:#}"),
            },
        }
    }
    out
}

/// DDR：區網裝置查 `_dns.resolver.arpa` 時告訴它們有哪些加密協議（規格 01 第 2 節）
fn set_ddr(cfg: &Value, r: &Resolver, e: &Encrypted) {
    use kuroshio_proto::logic::DdrEndpoint;
    if !get(cfg, "listen.ddr").and_then(Value::as_bool).unwrap_or(false) {
        return;
    }
    let target = get(cfg, "site.hostname").and_then(Value::as_str).unwrap_or("").to_string();
    if target.is_empty() {
        warn!("DDR 需要網域（tls.domain / site.hostname），沒有啟用");
        return;
    }
    let path = get(cfg, "listen.doh.path").and_then(Value::as_str).unwrap_or("/dns-query");
    let mut eps = Vec::new();
    if let Some(d) = e.doh {
        let mut alpn = vec!["h2".to_string()];
        if e.doh3.map(|h| h.port() == d.port()).unwrap_or(false) {
            alpn.push("h3".into());
        }
        eps.push(DdrEndpoint {
            alpn,
            port: d.port(),
            dohpath: Some(format!("{path}{{?dns}}")),
        });
    }
    if let Some(h) = e.doh3.filter(|h| e.doh.map(|d| d.port() != h.port()).unwrap_or(true)) {
        eps.push(DdrEndpoint {
            alpn: vec!["h3".into()],
            port: h.port(),
            dohpath: Some(format!("{path}{{?dns}}")),
        });
    }
    if let Some(d) = e.dot {
        eps.push(DdrEndpoint {
            alpn: vec!["dot".into()],
            port: d.port(),
            dohpath: None,
        });
    }
    if let Some(d) = e.doq {
        eps.push(DdrEndpoint {
            alpn: vec!["doq".into()],
            port: d.port(),
            dohpath: None,
        });
    }
    if eps.is_empty() {
        warn!("DDR：沒有任何加密協議在執行，沒有啟用");
        return;
    }
    info!("DDR 已啟用：{target}（{} 種加密協議）", eps.len());
    *r.ddr.write().unwrap() = Some((target, eps));
}

/// 唯讀資料（種子、評測名單、CDN 官方範圍）的位置：
/// KUROSHIO_SHARE → system.dataDir → 執行檔旁的 data/ → /usr/share/kuroshio → ./data
pub fn share_dir(cfg: &Value) -> PathBuf {
    if let Some(p) = std::env::var_os("KUROSHIO_SHARE") {
        return PathBuf::from(p);
    }
    if let Some(p) = get(cfg, "system.dataDir").and_then(Value::as_str).filter(|p| !p.is_empty()) {
        return PathBuf::from(p);
    }
    if let Some(d) = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|p| p.join("data")))
        .filter(|d| d.is_dir())
    {
        return d;
    }
    let sys = PathBuf::from("/usr/share/kuroshio");
    if sys.is_dir() {
        return sys;
    }
    PathBuf::from("./data")
}

/// 執行期暫存（鎖、評測報表）：一律放記憶體（tmpfs / 暫存資料夾），不寫 Flash
pub fn runtime_dir(cfg: &Value) -> PathBuf {
    match get(cfg, "system.runtimeDir").and_then(Value::as_str).filter(|p| !p.is_empty()) {
        Some(p) => PathBuf::from(p),
        None if cfg!(windows) => std::env::temp_dir().join("kuroshio"),
        None => PathBuf::from("/tmp/kuroshio"),
    }
}

/// 排程器：每日上游評測、CDN 範圍 / 網段分類（每週）、台灣節點池（每日）
fn start_scheduler(
    cfg: &Value,
    persister: &Arc<Mutex<Persister>>,
    base_dir: &std::path::Path,
    cdn: Option<&Arc<kuroshio_cdn::Cdn>>,
) -> Arc<kuroshio_jobs::Scheduler> {
    use kuroshio_jobs::{BenchPaths, Benchmark, Options, Scheduler, JOBS_STATE_FILE};
    let state_dir = persist_dir(cfg);
    let mut o = Options::new(&state_dir, base_dir);
    o.should_defer = Some(Arc::new(|| pressure() != Pressure::Normal));
    o.lock_dir = Some(runtime_dir(cfg).join("locks"));
    let slot: Arc<std::sync::OnceLock<std::sync::Weak<Scheduler>>> = Arc::new(std::sync::OnceLock::new());
    let (s2, p2) = (slot.clone(), persister.clone());
    o.on_state_change = Some(Arc::new(move || {
        if let Some(s) = s2.get().and_then(|w| w.upgrade()) {
            let (name, bytes) = s.snapshot();
            p2.lock().unwrap().stage(name, bytes);
        }
    }));
    let saved = persister.lock().unwrap().load(JOBS_STATE_FILE);
    let sched = Arc::new(Scheduler::new(cfg.clone(), saved.as_deref(), o));
    let _ = slot.set(Arc::downgrade(&sched));
    let mut paths = BenchPaths::from_config(cfg, &state_dir, base_dir);
    let shipped = share_dir(cfg).join("benchmark");
    if !paths.list_dir.is_dir() {
        paths.list_dir = shipped.clone();
    }
    if shipped.is_dir() && shipped != paths.list_dir {
        paths.default_list_dir = Some(shipped);
    }
    // 評測報表放記憶體：Flash 上不寫每天的報表
    if storage_class(cfg) != StorageClass::Disk {
        paths.out_root = Some(runtime_dir(cfg).join("benchmark"));
    }
    sched.register("dns-benchmark", Benchmark::new(paths));
    if let Some(cdn) = cdn {
        register_cdn_jobs(&sched, cdn);
    }
    sched.start();
    sched
}

/// CDN 的三個背景工作（同 2.x `jobs/cdn-*.js`，但在同一個行程裡跑，直接更新記憶體裡的狀態）
fn register_cdn_jobs(sched: &Arc<kuroshio_jobs::Scheduler>, cdn: &Arc<kuroshio_cdn::Cdn>) {
    use kuroshio_cdn::jobs::{pool, ranges, scan, JobCtx as CdnCtx};
    let c = cdn.clone();
    sched.register("cdn-ranges", move |ctx: kuroshio_jobs::JobCtx| {
        let c = c.clone();
        async move {
            let r = ranges::run(&CdnCtx::new((*ctx.cfg).clone(), c)).await?;
            info!(
                "CDN 官方範圍：{} 家，{}",
                r.providers.len(),
                if r.changed { "有更新" } else { "沒有變動" }
            );
            Ok(())
        }
    });
    let c = cdn.clone();
    sched.register("cdn-scan", move |ctx: kuroshio_jobs::JobCtx| {
        let c = c.clone();
        async move {
            let r = scan::run(&CdnCtx::new((*ctx.cfg).clone(), c)).await?;
            info!(
                "CDN 網段分類：{} 家，{}",
                r.providers.len(),
                if r.changed { "有更新" } else { "沒有變動" }
            );
            Ok(())
        }
    });
    let c = cdn.clone();
    sched.register("cdn-pool", move |ctx: kuroshio_jobs::JobCtx| {
        let c = c.clone();
        async move {
            let r = pool::run(&CdnCtx::new((*ctx.cfg).clone(), c.clone())).await?;
            info!(
                "台灣節點池更新：{} 家（IPv6 {}）",
                r.providers.len(),
                if r.v6_ok { "可用" } else { "不可用" }
            );
            // 新的節點池：15 秒後重新量一次健康與品質
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(15)).await;
                c.health_check().await;
                c.quality_check().await;
            });
            Ok(())
        }
    });
    // 某一家的節點不夠：提早跑節點池（至少隔 60 分鐘）
    let weak = Arc::downgrade(sched);
    cdn.set_on_low_pool(move |provider| {
        if let Some(s) = weak.upgrade() {
            s.request_with_gap("cdn-pool", &format!("{provider} 節點不足"), 60.0);
        }
    });
}

/// 社群共享 v2（規格 03）：金鑰在 community.dir，狀態經快照寫入器存在 state/community/
fn start_community(
    cfg: &Value,
    base_dir: &std::path::Path,
    resolver: &Arc<Resolver>,
    cdn: Option<Arc<kuroshio_cdn::Cdn>>,
) -> Option<Arc<kuroshio_community::Community>> {
    use kuroshio_community::{Community, Config, Options};
    let c = Config::from_json(get(cfg, "community")?);
    if !c.enabled {
        return None;
    }
    let key_dir = get(cfg, "community.dir")
        .and_then(Value::as_str)
        .filter(|d| !d.is_empty())
        .map(|d| rel_path(base_dir, d))
        .unwrap_or_else(|| base_dir.join("community"));
    let mut opts = Options::new(key_dir, persist_dir(cfg));
    opts.provider = Arc::new(crate::community_bridge::CdnData {
        cdn: cdn.clone(),
        upstreams: Some(resolver.upstreams.clone()),
    });
    let node = match Community::open(c, opts) {
        Ok(n) => n,
        Err(e) => {
            warn!("社群共享無法啟動：{e:#}");
            return None;
        }
    };
    resolver.community.set(node.clone());
    if let Some(cdn) = &cdn {
        cdn.set_hints(Some(Arc::new(crate::community_bridge::CommunityHints(Arc::downgrade(&node)))));
    }
    let n = node.clone();
    tokio::spawn(async move {
        // 加密監聽啟動後再做自我檢查（回連自己的網域）
        tokio::time::sleep(Duration::from_secs(10)).await;
        n.check().await;
        let mut minute = 0u64;
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            minute += 1;
            if pressure() == Pressure::Critical {
                continue;
            }
            // tick 內含每小時的維護（長期失聯的好友、品質分數、過期資料）
            n.tick().await;
            if minute % 60 == 0 {
                n.check().await;
            }
        }
    });
    info!("社群共享已啟用");
    Some(node)
}

/// 加密監聽沒有指定憑證時用 ACME 申請的那一份
fn with_acme_cert(cfg: &Value, a: &crate::acme::AcmeConfig) -> Value {
    let mut c = cfg.clone();
    for sec in ["dot", "doh"] {
        let Some(l) = c.get_mut("listen").and_then(|l| l.get_mut(sec)).and_then(Value::as_object_mut) else {
            continue;
        };
        let empty = |k: &str| l.get(k).and_then(Value::as_str).unwrap_or("").is_empty();
        if empty("cert") || empty("key") {
            l.insert("cert".into(), json!(a.cert.to_string_lossy()));
            l.insert("key".into(), json!(a.key.to_string_lossy()));
        }
    }
    c
}

type BoxFut = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

/// CDN 台灣節點：讀狀態（經過快照寫入器，記下雜湊）、接上解析器、啟動定時檢查
fn start_cdn(cfg: &Value, resolver: &Arc<Resolver>, persister: &Arc<Mutex<Persister>>) -> Option<Arc<kuroshio_cdn::Cdn>> {
    if !get(cfg, "cdn.enabled").and_then(Value::as_bool).unwrap_or(true) {
        return None;
    }
    let net: Arc<dyn kuroshio_cdn::Net> = Arc::new(kuroshio_cdn::RealNet::new(resolver.iprank.clone()));
    let paths = kuroshio_cdn::Paths::new(persist_dir(cfg), share_dir(cfg));
    let cdn = kuroshio_cdn::Cdn::load_with(cfg, paths, net, &|rel| persister.lock().unwrap().load(rel));
    if !cdn.enabled() {
        return None;
    }
    resolver.set_cdn(Some(cdn.clone()));
    let min = |k: &str, d: u64| Duration::from_secs(get(cfg, k).and_then(Value::as_u64).unwrap_or(d).max(1) * 60);
    let periodic = |first: Duration, every: Duration, f: fn(Arc<kuroshio_cdn::Cdn>) -> BoxFut| {
        let c = cdn.clone();
        tokio::spawn(async move {
            tokio::time::sleep(first).await;
            loop {
                if pressure() == Pressure::Normal {
                    f(c.clone()).await;
                }
                tokio::time::sleep(every).await;
            }
        });
    };
    periodic(Duration::from_secs(20), min("cdn.healthIntervalMin", 30), |c| {
        Box::pin(async move {
            c.health_check().await;
        })
    });
    // 沒有台灣 POP 的 CDN（Fastly）：量各鄰近節點的延遲 / 抖動 / 掉包，海纜壅塞時自動換 POP
    periodic(Duration::from_secs(60), min("cdn.qualityIntervalMin", 5), |c| {
        Box::pin(async move {
            c.quality_check().await;
        })
    });
    // 啟動 2 分鐘後先複驗一次：種子資料裡過期的驗證結果不用等一小時
    periodic(Duration::from_secs(120), Duration::from_secs(3600), |c| {
        Box::pin(async move {
            c.recheck();
        })
    });
    spawn_wan_subnet(resolver.clone(), Some(cdn.clone()));
    Some(cdn)
}

/// 偵測本機對外 IPv4（Cloudflare /cdn-cgi/trace），用它的 /24 當 ECS 子網路
fn spawn_wan_subnet(resolver: Arc<Resolver>, cdn: Option<Arc<kuroshio_cdn::Cdn>>) {
    tokio::spawn(async move {
        for attempt in 0..5u64 {
            tokio::time::sleep(Duration::from_secs(5 + attempt * 30)).await;
            let req = crate::fetch::Request {
                method: "GET",
                headers: vec![],
                body: None,
            };
            let Ok((200, body)) = crate::fetch::request("https://1.1.1.1/cdn-cgi/trace", &req, 4096, Duration::from_secs(5)).await else {
                continue;
            };
            let text = String::from_utf8_lossy(&body);
            let field = |k: &str| text.lines().find_map(|l| l.strip_prefix(k)).map(str::trim).map(String::from);
            let Some(ip) = field("ip=").and_then(|s| s.parse::<std::net::Ipv4Addr>().ok()) else {
                continue;
            };
            let o = ip.octets();
            let net = std::net::Ipv4Addr::new(o[0], o[1], o[2], 0);
            *resolver.ecs_subnet.write().unwrap() = Some((IpAddr::V4(net), 24));
            if let Some(c) = &cdn {
                c.ecs_add_subnet(&format!("{net}/24"));
            }
            info!(
                "本機對外 IP 的 ECS 子網路 {net}/24（Cloudflare 目前分配到 {}）",
                field("colo=").unwrap_or_default()
            );
            return;
        }
        warn!("無法偵測對外 IP：問上游時不帶 ECS");
    });
}

pub const HOT_NAMES: &str = "hot-names.json";
/// 統計歷史快照
pub const STATS_FILE: &str = "stats.json";

/// 把最常查的網域（只有名稱與類型）交給快照排程（規格 06 第 1.2 節）
pub fn stage_hot_names(r: &Resolver, p: &Mutex<Persister>, n: usize) {
    if n == 0 {
        return;
    }
    let keys = r.cache.lock().unwrap().hot_keys(n);
    if keys.is_empty() {
        return;
    }
    if let Ok(b) = serde_json::to_vec(&keys) {
        p.lock().unwrap().stage(HOT_NAMES, b);
    }
}

/// 開機預熱：依序重新查詢上次最常用的網域，每秒 `rate` 筆
fn spawn_warmup(r: Arc<Resolver>, p: Arc<Mutex<Persister>>, rate: u64) {
    let keys: Vec<String> = p
        .lock()
        .unwrap()
        .load(HOT_NAMES)
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    if keys.is_empty() || rate == 0 {
        return;
    }
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(3)).await;
        info!("開機預熱：重新查詢上次最常用的 {} 個網域", keys.len());
        let gap = Duration::from_millis(1000 / rate.max(1));
        for k in keys {
            let Some((t, name)) = k.split_once('|') else { continue };
            let Ok(t) = t.parse::<u16>() else { continue };
            let (r, name) = (r.clone(), name.to_string());
            tokio::spawn(async move { r.prefetch(&name, t).await });
            tokio::time::sleep(gap).await;
        }
    });
}

fn spawn_hot_names(r: Arc<Resolver>, p: Arc<Mutex<Persister>>, n: usize) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(600)).await;
            stage_hot_names(&r, &p, n);
        }
    });
}

fn spawn_maintenance(r: Arc<Resolver>) {
    tokio::spawn(async move {
        let mut tick = 0u64;
        let mut was_critical = false;
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            tick += 1;
            r.upstreams.reload_auto();
            if tick % 2 == 0 {
                r.sweep();
                // 記憶體偏低：快取縮到一半（規格 05 第 3.2 節）
                if pressure() != Pressure::Normal {
                    let mut c = r.cache.lock().unwrap();
                    let max = c.max;
                    c.max = (max / 2).max(256);
                    c.sweep(std::time::Instant::now(), 0);
                    c.max = max;
                }
                // 記憶體不足：CDN 網域資料庫刪掉最少用的三成（進入不足狀態時一次）
                let critical = pressure() == Pressure::Critical;
                if critical && !was_critical {
                    if let Some(c) = r.cdn() {
                        c.shrink(0.7);
                    }
                }
                was_critical = critical;
            }
        }
    });
}

/// 管理 API 需要的整體狀態
pub struct AppState {
    pub resolver: Arc<Resolver>,
    pub persister: Arc<Mutex<Persister>>,
    pub tier: Tier,
    pub info: SysInfo,
    pub persist_dir: PathBuf,
    pub warm_names: usize,
    pub filter: Option<Arc<crate::filtering::FilterService>>,
    pub ddns: Option<Arc<crate::ddns::Ddns>>,
    pub acme: Option<Arc<crate::acme::Acme>>,
    pub community: Option<Arc<kuroshio_community::Community>>,
    /// 會產生快照的模組（關機時全部寫出）
    pub snap_sources: Vec<SnapSource>,
    /// 設定頁（登入、靜態檔、設定檔路徑）
    pub webui: Arc<crate::webui::WebUi>,
    /// 設定頁存檔後通知外層重新載入
    pub reload: Arc<tokio::sync::Notify>,
    pub scheduler: Option<Arc<kuroshio_jobs::Scheduler>>,
    /// 實際在監聽的加密協議
    pub encrypted: Encrypted,
    /// 備份 / 匯入用到的檔案位置
    pub backup: crate::backup::Locations,
}

impl AppState {
    pub fn system_json(&self) -> Value {
        let (total, avail) = sysinfo::meminfo();
        let p = self.persister.lock().unwrap();
        let st = p.stats();
        let pol = p.policy();
        json!({
            "tier": self.tier.name(),
            "memTotalMB": total.or(self.info.mem_total_mb),
            "memAvailableMB": avail,
            "rssKB": sysinfo::rss_kb(),
            "pressure": format!("{:?}", pressure()).to_lowercase(),
            "cores": self.info.cores,
            "arch": self.info.arch,
            "aes": self.info.aes,
            "persist": {
                "dir": self.persist_dir, "storage": pol.class.name(),
                "intervalMin": pol.min_interval / 60, "dailyBudgetKB": pol.daily_budget / 1024,
                "bytesToday": st.bytes_today, "writesToday": st.writes_today, "deferred": st.deferred, "pending": st.pending,
            },
        })
    }
}

pub struct Started {
    /// 加密 DNS 實際監聽的位址（DoT / DoH）
    pub encrypted: Encrypted,
    pub server: Arc<Server>,
    pub state: Arc<AppState>,
    pub admin: Option<SocketAddr>,
    pub resolver: Arc<Resolver>,
    pub bound: Vec<SocketAddr>,
    pub persister: Arc<Mutex<Persister>>,
}

impl Started {
    /// 關機：把有變動的快照全部寫出（規格 05 第 5.3 節）
    pub fn shutdown(&self) {
        stage_hot_names(&self.resolver, &self.persister, self.state.warm_names);
        stage_sources(&self.persister, &self.state.snap_sources);
        let mut p = self.persister.lock().unwrap();
        match p.flush_all(crate::persist::now_secs()) {
            Ok(n) if n > 0 => info!("關機前寫出 {n} 份快照"),
            Ok(_) => {}
            Err(e) => warn!("關機前寫出快照失敗：{e}"),
        }
    }
}

/// 目前的記憶體壓力（看門狗每 30 秒更新）
pub static PRESSURE: AtomicU8 = AtomicU8::new(0);

pub fn pressure() -> Pressure {
    match PRESSURE.load(Ordering::Relaxed) {
        2 => Pressure::Critical,
        1 => Pressure::Low,
        _ => Pressure::Normal,
    }
}

/// 快照目錄（`system.persistDir`，空白 = 平台預設）
/// 攜帶版：執行檔旁邊有 config.json 時，設定、快照、日誌都放在執行檔的資料夾（規格 07 第 1 節）
pub fn portable_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(PathBuf::from))
        .filter(|d| d.join("config.json").is_file())
}

pub fn persist_dir(cfg: &Value) -> PathBuf {
    match get(cfg, "system.persistDir").and_then(Value::as_str) {
        Some(d) if !d.is_empty() => PathBuf::from(d),
        _ if portable_dir().is_some() && cfg!(windows) => portable_dir().unwrap().join("state"),
        _ if cfg!(windows) => {
            let base = std::env::var_os("ProgramData")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
            base.join("kuroshio").join("state")
        }
        _ => PathBuf::from("/etc/kuroshio/state"),
    }
}

/// 快照目錄的儲存類型（`system.storageClass` 可以強制指定）
pub fn storage_class(cfg: &Value) -> StorageClass {
    get(cfg, "system.storageClass")
        .and_then(Value::as_str)
        .and_then(StorageClass::parse)
        .unwrap_or_else(|| sysinfo::storage_class(&persist_dir(cfg)))
}

pub fn persist_policy(cfg: &Value, tiny: bool) -> Policy {
    let n = |k: &str| get(cfg, k).and_then(Value::as_u64).unwrap_or(0);
    Policy::new(
        storage_class(cfg),
        n("system.persistIntervalMin"),
        n("system.flashWriteBudgetKB").max(64),
        tiny,
    )
}

fn spawn_watchdog() {
    tokio::spawn(async move {
        let mut last = Pressure::Normal;
        loop {
            if let (Some(t), Some(a)) = sysinfo::meminfo() {
                let p = sysinfo::pressure(t, a);
                PRESSURE.store(p as u8, Ordering::Relaxed);
                if p != last {
                    match p {
                        Pressure::Normal => info!("記憶體恢復正常（可用 {a} / {t} MB）"),
                        Pressure::Low => warn!("記憶體偏低（可用 {a} / {t} MB）：縮小快取、暫停背景工作"),
                        Pressure::Critical => warn!("記憶體不足（可用 {a} / {t} MB）：拒絕新的加密連線"),
                    }
                    last = p;
                }
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
}

/// 會產生快照的模組（CDN、社群）：只在要寫的時候才序列化，有變動的才給
pub type SnapSource = Arc<dyn Fn() -> Vec<(String, Vec<u8>)> + Send + Sync>;

pub fn stage_sources(p: &Mutex<Persister>, sources: &[SnapSource]) {
    for src in sources {
        let snaps = src();
        let mut p = p.lock().unwrap();
        for (name, bytes) in snaps {
            p.stage(&name, bytes);
        }
    }
}

fn spawn_persist_loop(p: Arc<Mutex<Persister>>, sources: Vec<SnapSource>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(300)).await;
            stage_sources(&p, &sources);
            if let Err(e) = p.lock().unwrap().flush(crate::persist::now_secs()) {
                warn!("寫入快照失敗：{e}");
            }
        }
    });
}

pub async fn start(cfg: &Value, tier: Tier) -> Result<Started> {
    let tiny = tier == Tier::Tiny;
    // 設定頁 / 指令列匯入的備份：在讀取任何狀態之前合併（上一輪關機時已經把記憶體寫出）
    let backup = crate::backup::Locations::from_cfg(cfg);
    crate::backup::apply_pending(&backup);
    let persister = Arc::new(Mutex::new(Persister::new(persist_dir(cfg), persist_policy(cfg, tiny))));
    {
        let p = persister.lock().unwrap();
        if p.policy().class == StorageClass::Ram {
            warn!(
                "快照目錄 {} 在記憶體（tmpfs）裡，重開機後節點池與驗證紀錄會遺失",
                persist_dir(cfg).display()
            );
        }
    }
    if get(cfg, "system.memoryWatchdog").and_then(Value::as_bool).unwrap_or(true) {
        spawn_watchdog();
    }
    // 第一次啟動：state 還是空的就帶入種子資料（評測結果、節點池、網站驗證紀錄）
    // （apply_seeds 自己會記錄帶入了哪些）
    let _ = kuroshio_jobs::apply_seeds(&persist_dir(cfg), &share_dir(cfg).join("seed"));
    let resolver = build_resolver(cfg)?;
    // 統計歷史（公開頁 7 / 30 天）：重開機後接續
    if tiny {
        resolver.stats.set_limits(crate::stats::Limits::tiny());
    }
    if let Some(b) = persister.lock().unwrap().load(STATS_FILE) {
        resolver.stats.restore(&b);
    }
    if let Some(p) = crate::presence::Presence::from_cfg(cfg, tiny) {
        let _ = resolver.presence.set(p);
    }
    let cdn = start_cdn(cfg, &resolver, &persister);
    if cdn.is_none() {
        spawn_wan_subnet(resolver.clone(), None);
    }
    let mut snap_sources: Vec<SnapSource> = Vec::new();
    {
        let r = resolver.clone();
        snap_sources.push(Arc::new(move || vec![(STATS_FILE.to_string(), r.stats.snapshot())]));
    }
    if let Some(c) = &cdn {
        let c = c.clone();
        snap_sources.push(Arc::new(move || c.snapshots()));
    }
    spawn_maintenance(resolver.clone());
    // 過濾：自訂規則與清單路徑以設定目錄（快照目錄的上一層）為基準
    let base_dir = persist_dir(cfg)
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| persist_dir(cfg));
    let filter = crate::filtering::FilterService::from_cfg(cfg, &base_dir);
    if let Some(f) = &filter {
        f.spawn();
        resolver.set_filter(Some(f.clone()));
    }
    let warm_names = get(cfg, "resolver.warmNames").and_then(Value::as_u64).unwrap_or(0) as usize;
    let warm_rate = get(cfg, "resolver.warmRate").and_then(Value::as_u64).unwrap_or(20);
    spawn_warmup(resolver.clone(), persister.clone(), warm_rate);
    spawn_hot_names(resolver.clone(), persister.clone(), warm_names);
    let acl_list = strings(get(cfg, "listen.plain.allowFrom"));
    let server = Arc::new(Server {
        resolver: resolver.clone(),
        acl: Arc::new(Acl::new(acl_list.iter().map(String::as_str))),
    });
    let port = get(cfg, "listen.plain.port").and_then(Value::as_u64).unwrap_or(53) as u16;
    let mut bound = Vec::new();
    if get(cfg, "listen.plain.enabled").and_then(Value::as_bool).unwrap_or(true) {
        for b in strings(get(cfg, "listen.plain.binds")) {
            let ip: IpAddr = match b.parse() {
                Ok(ip) => ip,
                Err(_) => {
                    warn!("監聽位址格式錯誤：{b}");
                    continue;
                }
            };
            // 單一位址綁定失敗（例如沒有 IPv6）只記警告，其他位址照常監聽
            let open = strings(get(cfg, "listen.plain.openBinds"))
                .iter()
                .any(|o| o.parse::<IpAddr>().ok() == Some(ip));
            match server.listen(SocketAddr::new(ip, port), open).await {
                Ok(b) => bound.extend(b),
                Err(e) => warn!("{e:#}，略過這個位址"),
            }
        }
    }
    if bound.is_empty() {
        bail!("沒有任何監聽位址（listen.plain.binds）");
    }
    // 內建 ACME：憑證不存在或快到期就先申請（最多等 3 分鐘），再啟動加密監聽
    let acme = crate::acme::AcmeConfig::from_cfg(cfg, &base_dir, &persist_dir(cfg)).map(crate::acme::Acme::new);
    let tls_cfg = match &acme {
        Some(a) => {
            if crate::acme::renewal_reason(&a.cfg.cert, &a.cfg.domains, a.cfg.renew_days).is_some() {
                let _ = tokio::time::timeout(Duration::from_secs(180), a.ensure(false)).await;
            }
            a.spawn();
            with_acme_cert(cfg, &a.cfg)
        }
        None => cfg.clone(),
    };
    let community = start_community(cfg, &base_dir, &resolver, cdn.clone());
    if let Some(c) = &community {
        let c = c.clone();
        snap_sources.push(Arc::new(move || c.snapshots()));
    }
    spawn_persist_loop(persister.clone(), snap_sources.clone());
    let encrypted = start_encrypted(&tls_cfg, &resolver, &base_dir).await;
    let scheduler = Some(start_scheduler(cfg, &persister, &base_dir, cdn.as_ref()));
    let ddns = crate::ddns::Config::from_cfg(cfg).map(crate::ddns::Ddns::new);
    if let Some(d) = &ddns {
        d.spawn();
    }
    set_ddr(cfg, &resolver, &encrypted);
    let state = Arc::new(AppState {
        resolver: resolver.clone(),
        persister: persister.clone(),
        tier,
        info: SysInfo::detect(),
        persist_dir: persist_dir(cfg),
        warm_names,
        filter,
        ddns,
        acme,
        community,
        snap_sources,
        webui: Arc::new(crate::webui::WebUi::new(cfg, &base_dir, &share_dir(cfg))),
        reload: Arc::new(tokio::sync::Notify::new()),
        scheduler,
        encrypted: encrypted.clone(),
        backup,
    });
    // 公開頁：需要整體狀態（唯讀 API），所以最後才建立；DoH 監聽之後才會開始轉給它
    if let Some(site) = crate::site::Site::new(cfg, state.clone(), resolver.presence.get().cloned()) {
        site.spawn();
        let _ = resolver.site.set(site);
    }
    let mut admin = None;
    if get(cfg, "admin.enabled").and_then(Value::as_bool).unwrap_or(true) {
        let host: IpAddr = get(cfg, "admin.host")
            .and_then(Value::as_str)
            .and_then(|h| h.parse().ok())
            .unwrap_or(IpAddr::from([127, 0, 0, 1]));
        let port = get(cfg, "admin.port").and_then(Value::as_u64).unwrap_or(8054) as u16;
        match crate::admin::listen(state.clone(), SocketAddr::new(host, port)).await {
            Ok(a) => admin = Some(a),
            Err(e) => warn!("管理 API 無法監聽 {host}:{port}：{e}"),
        }
    }
    Ok(Started {
        encrypted,
        server,
        state,
        admin,
        resolver,
        bound,
        persister,
    })
}
