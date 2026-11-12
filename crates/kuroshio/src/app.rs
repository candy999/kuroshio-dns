//! 由設定組出整個服務

use crate::acl::Acl;
use crate::iprank::IpRank;
use crate::persist::{Mem, Opts, Persister, Policy, Snapshot};
use crate::resolver::{LocalForward, Params, Resolver};
use crate::server::Server;
use crate::sysinfo::{self, Pressure, StorageClass, SysInfo};
use crate::upstream::Upstream;
use crate::upstreams::Manager;
use anyhow::{bail, Result};
use kuroshio_config::get;
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
    /// 每個監聽位址的結果（多位址 `binds`、綁定失敗的原因）
    pub detail: Vec<ListenerInfo>,
    /// DoH 的 Windows 模式（`/api/status` 的 `dohMode`；DoH 沒開時 Null）
    pub doh_mode: Value,
    /// DoH3 由誰提供（`/api/status` 的 `doh3Provider`）
    pub doh3_provider: Value,
    /// 模式 B：向 HTTP.sys 登記的網址（關機、重新載入時移除）
    pub httpsys: Option<Arc<crate::httpsys::Server>>,
    /// 模式 B 的埠號（憑證自動同步到 HTTP.sys 的 `hostnameport`）
    pub httpsys_port: Option<u16>,
}

/// 一個加密監聽位址的結果（`/api/status` 的 `listenersDetail`）
#[derive(Debug, Clone)]
pub struct ListenerInfo {
    /// dot / doq / doh / doh3
    pub proto: &'static str,
    /// 設定裡寫的位址
    pub bind: String,
    pub port: u16,
    /// 實際監聽的位址（失敗 = None）
    pub bound: Option<SocketAddr>,
    /// 這個監聽自己做 TLS（DoH 在反向代理後面時是 false）
    pub tls: bool,
    pub error: Option<String>,
}

impl Encrypted {
    pub fn detail_json(&self) -> Value {
        self.detail
            .iter()
            .map(|l| {
                json!({
                    "proto": l.proto, "bind": l.bind, "port": l.bound.map(|b| b.port()).unwrap_or(l.port),
                    "ok": l.bound.is_some(), "tls": l.tls, "error": l.error,
                })
            })
            .collect()
    }
}

fn rel_path(base: &std::path::Path, p: &str) -> PathBuf {
    let pp = std::path::Path::new(p);
    if pp.is_absolute() {
        pp.to_path_buf()
    } else {
        base.join(pp.strip_prefix("./").unwrap_or(pp))
    }
}

/// 設定裡的一組憑證 / 私鑰路徑（`<prefix>.cert`、`<prefix>.key`），兩個都有填才算
fn cert_pair(cfg: &Value, prefix: &str, base: &std::path::Path) -> Option<(PathBuf, PathBuf)> {
    let s = |k: &str| {
        get(cfg, &format!("{prefix}.{k}"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
    };
    Some((rel_path(base, s("cert")?), rel_path(base, s("key")?)))
}

/// 某個加密協議（dot / doq / doh / doh3）用哪一份憑證：
/// 自己的 `listen.<x>.cert / key` → 共用的 `tls.cert / key` → 內建 ACME 的輸出位置（`acme.enabled` 才算）。
/// DoQ 沒有自己的憑證時沿用 DoT 的、再來 DoH 的；DoH3 跟 DoH 同一份。都沒有 → None。
pub fn cert_for(cfg: &Value, proto: &str, base: &std::path::Path) -> Option<(PathBuf, PathBuf)> {
    let own: &[&str] = match proto {
        "dot" => &["listen.dot"],
        "doq" => &["listen.doq", "listen.dot", "listen.doh"],
        "doh" | "doh3" => &["listen.doh"],
        _ => return None,
    };
    own.iter()
        .find_map(|p| cert_pair(cfg, p, base))
        .or_else(|| cert_pair(cfg, "tls", base))
        .or_else(|| {
            get(cfg, "acme.enabled")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                .then(|| crate::acme::cert_paths(cfg, base))
        })
}

/// 監聽位址：`listen.<x>.binds` 有填就用它（可以同時有 IPv4 與 IPv6），沒填用 `listen.<x>.host`
fn listen_hosts(cfg: &Value, sec: &str) -> Vec<String> {
    let binds: Vec<String> = strings(get(cfg, &format!("listen.{sec}.binds")))
        .into_iter()
        .map(|b| b.trim().to_string())
        .filter(|b| !b.is_empty())
        .collect();
    if !binds.is_empty() {
        return binds;
    }
    let host = get(cfg, &format!("listen.{sec}.host"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .unwrap_or("0.0.0.0");
    vec![host.to_string()]
}

fn parse_host(h: &str) -> Option<IpAddr> {
    h.trim_start_matches('[').trim_end_matches(']').parse().ok()
}

fn cfg_port(cfg: &Value, key: &str) -> Option<u16> {
    get(cfg, key)
        .and_then(Value::as_u64)
        .filter(|p| *p > 0 && *p <= 65535)
        .map(|p| p as u16)
}

/// 裝置從外面連 DoH 用的 TCP 埠號（公開頁、描述檔、QR 碼、Cloudflare HTTPS 記錄、Alt-Svc 都用這個）：
/// 1. `listen.doh.publicPort`（> 0）：外面看到的埠號跟監聽的不同時（例如路由器把 WAN 443 轉到本機 8443）
/// 2. DoH 自己做 TLS（`tls`）：`listen.doh.port`——DoH 可以用任何埠號，例如 443 被占用時改用 8443
/// 3. 前面有反向代理（IIS、nginx…，DoH 本身是明文）：443
pub fn public_doh_port(cfg: &Value, tls: bool) -> u16 {
    if let Some(p) = cfg_port(cfg, "listen.doh.publicPort") {
        return p;
    }
    if tls {
        cfg_port(cfg, "listen.doh.port").unwrap_or(443)
    } else {
        443
    }
}

/// 裝置從外面連 DoH3（HTTP/3，UDP）用的埠號：
/// `listen.doh.altSvcPort` → DoH3 跟 DoH 同一個埠號（`http3Port` 是 0 或一樣）時同 [`public_doh_port`] → `listen.doh.http3Port`
pub fn public_doh3_port(cfg: &Value, tls: bool) -> u16 {
    if let Some(p) = cfg_port(cfg, "listen.doh.altSvcPort") {
        return p;
    }
    let listen = cfg_port(cfg, "listen.doh.port").unwrap_or(443);
    match cfg_port(cfg, "listen.doh.http3Port") {
        Some(h3) if h3 != listen => h3,
        _ => public_doh_port(cfg, tls),
    }
}

/// DoH 的 TCP 監聽要不要自己做 TLS（`listen.doh.tls`：`"auto"` / `true` / `false`）。
///
/// auto：
/// - `listen.doh.windowsMode == "iis-proxy"`（IIS 在前面做 TLS）→ 明文 HTTP
/// - 只監聽本機（loopback）而且沒有明確寫 `listen.doh.cert / key`（前面有反向代理）→ 明文 HTTP
/// - 其他：找得到憑證（`cert_for`）就做 TLS，找不到就明文
///
/// OpenWrt 的 UCI 設定一律會寫 `listen.doh.cert / key`，所以行為跟以前一樣（TLS）。
pub fn doh_uses_tls(cfg: &Value, base: &std::path::Path) -> bool {
    // 模式 B：TLS 由 HTTP.sys 處理，對外一定是 HTTPS
    if cfg!(windows) && crate::httpsys::configured(cfg) == "httpsys" {
        return true;
    }
    match get(cfg, "listen.doh.tls") {
        Some(Value::Bool(b)) => return *b,
        Some(Value::String(s)) => match s.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "on" | "yes" => return true,
            "false" | "0" | "off" | "no" => return false,
            _ => {}
        },
        _ => {}
    }
    if get(cfg, "listen.doh.windowsMode").and_then(Value::as_str) == Some("iis-proxy") {
        return false;
    }
    let explicit = cert_pair(cfg, "listen.doh", base).is_some();
    let loopback = listen_hosts(cfg, "doh")
        .iter()
        .all(|h| parse_host(h).is_some_and(|ip| ip.is_loopback()));
    if loopback && !explicit {
        return false;
    }
    cert_for(cfg, "doh", base).is_some()
}

/// DoT / DoH 伺服器（規格 01 第 1.1 節）；開不起來只記警告，區網 DNS 照常。
/// 一個協議可以監聽多個位址（`binds`）；其中一個綁定失敗只記警告，其他照常。
async fn start_encrypted(cfg: &Value, resolver: &Arc<Resolver>, base: &std::path::Path) -> Encrypted {
    use crate::encrypted::{listen_doh, listen_doh3, listen_doq, listen_dot, CertStore, DohOptions, Limits};
    let mut out = Encrypted::default();
    let limits = Limits::new(get(cfg, "system.maxTlsConnections").and_then(Value::as_u64).unwrap_or(2048) as usize);
    let mut stores: std::collections::HashMap<(PathBuf, PathBuf), Arc<CertStore>> = std::collections::HashMap::new();
    let mut store_for = |key: (PathBuf, PathBuf)| -> Arc<CertStore> {
        stores
            .entry(key.clone())
            .or_insert_with(|| {
                let s = CertStore::new(key.0.clone(), key.1.clone());
                s.spawn_watch();
                s
            })
            .clone()
    };
    let port_of = |sec: &str, dport: u64| get(cfg, &format!("listen.{sec}.port")).and_then(Value::as_u64).unwrap_or(dport) as u16;
    let on = |sec: &str| get(cfg, &format!("listen.{sec}.enabled")).and_then(Value::as_bool).unwrap_or(false);
    // 記下每個位址的結果；回傳要監聽的位址（格式錯誤的直接記成失敗）
    fn targets(out: &mut Encrypted, proto: &'static str, hosts: &[String], port: u16, tls: bool) -> Vec<(usize, SocketAddr)> {
        let mut v = Vec::new();
        for h in hosts {
            let ip = parse_host(h);
            out.detail.push(ListenerInfo {
                proto,
                bind: h.clone(),
                port,
                bound: None,
                tls,
                error: ip.is_none().then(|| "位址格式錯誤".to_string()),
            });
            match ip {
                Some(ip) => v.push((out.detail.len() - 1, SocketAddr::new(ip, port))),
                None => warn!("{} 監聽位址格式錯誤：{h}", proto_label(proto)),
            }
        }
        v
    }
    fn done(out: &mut Encrypted, i: usize, r: Result<SocketAddr>) -> Option<SocketAddr> {
        match r {
            Ok(b) => {
                out.detail[i].bound = Some(b);
                Some(b)
            }
            Err(e) => {
                warn!("{e:#}，略過這個位址");
                out.detail[i].error = Some(format!("{e:#}"));
                None
            }
        }
    }
    fn skip(out: &mut Encrypted, proto: &'static str, hosts: &[String], port: u16, why: &str) {
        warn!("{why}");
        for h in hosts {
            out.detail.push(ListenerInfo {
                proto,
                bind: h.clone(),
                port,
                bound: None,
                tls: true,
                error: Some(why.to_string()),
            });
        }
    }
    if on("dot") {
        let (hosts, port) = (listen_hosts(cfg, "dot"), port_of("dot", 853));
        match cert_for(cfg, "dot", base) {
            None => skip(
                &mut out,
                "dot",
                &hosts,
                port,
                "DoT 需要憑證（tls.cert / key 或 listen.dot.cert / key），沒有啟動",
            ),
            Some(pair) => {
                let certs = store_for(pair);
                for (i, a) in targets(&mut out, "dot", &hosts, port, true) {
                    let r = listen_dot(a, certs.clone(), resolver.clone(), limits.clone()).await;
                    if let Some(b) = done(&mut out, i, r) {
                        out.dot.get_or_insert(b);
                    }
                }
            }
        }
    }
    // DoQ（UDP 853）：跟 DoT 共用憑證（沒有 DoT 憑證時用 DoH 的）
    let quic_max = get(cfg, "system.maxQuicConnections").and_then(Value::as_u64).unwrap_or(512) as usize;
    if on("doq") {
        let (hosts, port) = (listen_hosts(cfg, "doq"), port_of("doq", 853));
        match cert_for(cfg, "doq", base) {
            None => skip(
                &mut out,
                "doq",
                &hosts,
                port,
                "DoQ 需要憑證（tls.cert / key 或 listen.dot.cert / key），沒有啟動",
            ),
            Some(_) if quic_max == 0 => skip(
                &mut out,
                "doq",
                &hosts,
                port,
                "設定了 system.maxQuicConnections = 0（不開 QUIC），DoQ 沒有啟動",
            ),
            Some(pair) => {
                let certs = store_for(pair);
                for (i, a) in targets(&mut out, "doq", &hosts, port, true) {
                    let r = listen_doq(a, certs.clone(), resolver.clone(), Limits::new(quic_max)).await;
                    if let Some(b) = done(&mut out, i, r) {
                        out.doq.get_or_insert(b);
                    }
                }
            }
        }
    }
    if on("doh") {
        use crate::httpsys::{Doh3Plan, WinMode};
        let (hosts, port) = (listen_hosts(cfg, "doh"), port_of("doh", 8443));
        let path = match get(cfg, "listen.doh.path").and_then(Value::as_str).unwrap_or("") {
            "" => "/dns-query".to_string(),
            p => p.to_string(),
        };
        // Windows：跟 IIS 共用 443 的方式（規格 07 第 2 節），啟動時決定一次
        let configured = crate::httpsys::configured(cfg);
        let host_ips: Vec<IpAddr> = hosts.iter().filter_map(|h| parse_host(h)).collect();
        let (mode, mode_reason) = crate::httpsys::decide(&configured, cfg!(windows), port, || crate::httpsys::probe_port(&host_ips, port));
        if cfg!(windows) {
            info!("DoH 的 Windows 模式：{}（{mode_reason}）", mode.name());
        } else if configured == "httpsys" {
            warn!("listen.doh.windowsMode = httpsys：{mode_reason}");
        }
        let (sys_h3, sys_alt) = if mode == WinMode::HttpSys {
            crate::httpsys::registry_http3()
        } else {
            (false, false)
        };
        let http3 = get(cfg, "listen.doh.http3").and_then(Value::as_bool).unwrap_or(false);
        let plan3 = crate::httpsys::doh3_plan(mode, http3, sys_h3);
        let trust_proxy = mode != WinMode::HttpSys && get(cfg, "listen.doh.trustProxy").and_then(Value::as_bool).unwrap_or(false);
        let mut opts = DohOptions {
            path: path.clone(),
            trust_proxy,
            alt_svc: None,
        };
        // DoH3（UDP，預設跟 DoH 同樣的位址與埠號；`listen.doh.http3Binds` 可以另外指定位址）：
        // 一定要憑證；開成功時 DoH 的回應加 Alt-Svc。HTTP.sys 開了 HTTP/3 的模式 B 由 HTTP.sys 提供，不綁 UDP
        if plan3 == Doh3Plan::Kuroshio {
            let h3_port = get(cfg, "listen.doh.http3Port")
                .and_then(Value::as_u64)
                .filter(|p| *p > 0)
                .map(|p| p as u16)
                .unwrap_or(port);
            let h3_hosts: Vec<String> = match strings(get(cfg, "listen.doh.http3Binds")) {
                b if b.iter().any(|x| !x.trim().is_empty()) => {
                    b.into_iter().map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()
                }
                _ => hosts.clone(),
            };
            match cert_for(cfg, "doh3", base) {
                None => skip(&mut out, "doh3", &h3_hosts, h3_port, "DoH3 需要憑證，沒有啟動"),
                Some(_) if quic_max == 0 => skip(
                    &mut out,
                    "doh3",
                    &h3_hosts,
                    h3_port,
                    "設定了 system.maxQuicConnections = 0（不開 QUIC），DoH3 沒有啟動",
                ),
                Some(pair) => {
                    let certs = store_for(pair);
                    for (i, a) in targets(&mut out, "doh3", &h3_hosts, h3_port, true) {
                        let o3 = DohOptions {
                            path: path.clone(),
                            trust_proxy: false,
                            alt_svc: None,
                        };
                        let r = listen_doh3(a, certs.clone(), resolver.clone(), o3, Limits::new(quic_max)).await;
                        if let Some(b) = done(&mut out, i, r) {
                            out.doh3.get_or_insert(b);
                        }
                    }
                }
            }
        }
        // 對外埠號可能不同（例如 WAN 443 → 本機 8443）：listen.doh.altSvcPort 可以指定
        // 沒有指定時：DoH3 跟 DoH 同埠號、而且設定了 listen.doh.publicPort（埠號轉送）→ 宣告外面看到的埠號
        let adv = match cfg_port(cfg, "listen.doh.altSvcPort") {
            Some(p) => p,
            None => match cfg_port(cfg, "listen.doh.publicPort") {
                Some(p) if out.doh3.map(|b| b.port()) == Some(port) => p,
                _ => 0,
            },
        };
        opts.alt_svc = crate::httpsys::alt_svc(plan3, out.doh3.map(|b| b.port()), port, sys_alt, adv);
        let mut urls_json = Vec::new();
        if mode == WinMode::HttpSys {
            out.httpsys_port = Some(port);
            let started = crate::httpsys::plan(cfg)
                .map_err(anyhow::Error::msg)
                .and_then(|(_, _, p)| crate::httpsys::start(&p, resolver.clone(), opts.clone(), limits.clone()));
            let any = SocketAddr::new(IpAddr::from([0, 0, 0, 0]), port);
            match started {
                Ok(srv) => {
                    let failed: Vec<String> = srv.urls.iter().filter_map(|u| u.error.clone()).collect();
                    for u in &srv.urls {
                        urls_json.push(json!({ "url": u.url, "ok": u.error.is_none(), "error": u.error }));
                    }
                    out.detail.push(ListenerInfo {
                        proto: "doh",
                        bind: "httpsys".into(),
                        port,
                        bound: Some(any),
                        tls: true,
                        error: (!failed.is_empty()).then(|| failed.join("；")),
                    });
                    out.doh = Some(any);
                    if plan3 == Doh3Plan::HttpSys {
                        out.detail.push(ListenerInfo {
                            proto: "doh3",
                            bind: "httpsys".into(),
                            port,
                            bound: Some(any),
                            tls: true,
                            error: None,
                        });
                        out.doh3 = Some(any);
                    }
                    out.httpsys = Some(Arc::new(srv));
                }
                // 登記失敗（沒有權限、沒有網域…）只記警告，其他監聽照常
                Err(e) => skip(
                    &mut out,
                    "doh",
                    &["httpsys".to_string()],
                    port,
                    &format!("HTTP.sys 共用沒有啟動：{e:#}"),
                ),
            }
        } else {
            let tls = doh_uses_tls(cfg, base);
            match (tls, cert_for(cfg, "doh", base)) {
                (true, None) => skip(
                    &mut out,
                    "doh",
                    &hosts,
                    port,
                    "DoH 設定成要 TLS（listen.doh.tls）但是沒有憑證（tls.cert / key 或 listen.doh.cert / key），沒有啟動",
                ),
                (tls, pair) => {
                    let certs = pair.filter(|_| tls).map(&mut store_for);
                    for (i, a) in targets(&mut out, "doh", &hosts, port, tls) {
                        let r = listen_doh(a, certs.clone(), resolver.clone(), opts.clone(), limits.clone()).await;
                        if let Some(b) = done(&mut out, i, r) {
                            out.doh.get_or_insert(b);
                        }
                    }
                }
            }
        }
        out.doh_mode = json!({
            "configured": configured, "mode": mode.name(), "reason": mode_reason,
            "urls": urls_json, "enableHttp3": sys_h3, "enableAltSvc": sys_alt,
            "altSvc": opts.alt_svc,
        });
        out.doh3_provider = match plan3 {
            Doh3Plan::Off => json!({ "provider": "none", "reason": "沒有開 HTTP/3（listen.doh.http3）" }),
            Doh3Plan::HttpSys if out.doh3.is_some() => {
                json!({ "provider": "httpsys", "reason": format!("HTTP.sys 開了 HTTP/3（EnableHttp3），登記的網址自動支援 UDP {port}") })
            }
            Doh3Plan::HttpSys => json!({ "provider": "none", "reason": "HTTP.sys 開了 HTTP/3，但是網址沒有登記成功" }),
            Doh3Plan::Kuroshio => match out.doh3 {
                Some(b) => json!({ "provider": "kuroshio", "reason": format!("黑潮 DNS 自己聽 UDP {}", b.port()) }),
                None => json!({
                    "provider": "none",
                    "reason": out.detail.iter().filter(|l| l.proto == "doh3").find_map(|l| l.error.clone()).unwrap_or_else(|| "DoH3 沒有啟動".into()),
                }),
            },
        };
    }
    out
}

fn proto_label(p: &str) -> &'static str {
    match p {
        "dot" => "DoT",
        "doq" => "DoQ",
        "doh3" => "DoH3",
        _ => "DoH",
    }
}

/// 自備憑證（沒開內建 ACME）的啟動檢查：檔案不存在、過期、沒有涵蓋綁定網域時提醒。只讀不寫。
fn warn_manual_certs(cfg: &Value, base: &std::path::Path) {
    if get(cfg, "acme.enabled").and_then(Value::as_bool).unwrap_or(false) {
        return;
    }
    let on = |sec: &str| get(cfg, &format!("listen.{sec}.enabled")).and_then(Value::as_bool).unwrap_or(false);
    let http3 = on("doh") && get(cfg, "listen.doh.http3").and_then(Value::as_bool).unwrap_or(false);
    let used = [
        ("dot", on("dot")),
        ("doq", on("doq")),
        ("doh", on("doh") && doh_uses_tls(cfg, base)),
        ("doh3", http3),
    ];
    let mut seen: Vec<(PathBuf, PathBuf)> = Vec::new();
    let domain = kuroshio_config::bound_domain(cfg);
    for (proto, enabled) in used {
        let Some(pair) = cert_for(cfg, proto, base).filter(|_| enabled) else {
            continue;
        };
        if seen.contains(&pair) {
            continue;
        }
        for p in crate::certinfo::problems(&pair.0, &pair.1, &domain) {
            warn!("{p}");
        }
        seen.push(pair);
    }
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

/// 排程器：每日上游評測、CDN 範圍 / 網段分類（每週）、台灣節點池（每日）、台灣 IP 清單（每月）
fn start_scheduler(
    cfg: &Value,
    persister: &Arc<Mutex<Persister>>,
    base_dir: &std::path::Path,
    cdn: Option<&Arc<kuroshio_cdn::Cdn>>,
    access: Option<&Arc<crate::ipfilter::Access>>,
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
    let mut scfg = cfg.clone();
    // access.localUpdate=false 也關掉台灣 IP 清單的每月工作（排程清單裡顯示「已停用」）
    if access.map(|a| !a.settings.auto_update).unwrap_or(false) {
        if let Some(j) = scfg.pointer_mut("/jobs/tw-ip").and_then(Value::as_object_mut) {
            j.insert("enabled".into(), json!(false));
        }
    }
    let sched = Arc::new(Scheduler::new(scfg, saved.as_deref(), o));
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
    if let Some(a) = access {
        register_twip_job(&sched, a, persister, runtime_dir(cfg));
    }
    sched.start();
    sched
}

/// 背景工作用的記憶體檢查：吃緊時回傳原因。記憶體控制改版時只要改這裡
pub fn job_memory_short() -> Option<String> {
    match pressure() {
        Pressure::Normal => None,
        Pressure::Low => Some("記憶體偏低".into()),
        Pressure::Critical => Some("記憶體不足".into()),
    }
}

/// 台灣 IP 清單（規格 08）：每月在本機慢慢重新產生，不連任何專案伺服器。
/// 成功後換上規則、經快照寫入器壓縮存檔（內容沒變不寫）、通知防火牆
fn register_twip_job(
    sched: &Arc<kuroshio_jobs::Scheduler>,
    access: &Arc<crate::ipfilter::Access>,
    persister: &Arc<Mutex<Persister>>,
    runtime: PathBuf,
) {
    use kuroshio_jobs::twip::{system_load, Hooks, Sources, TwIpJob};
    let (a1, a2, p2) = (access.clone(), access.clone(), persister.clone());
    let hooks = Hooks {
        current: Arc::new(move || a1.data_and_origin()),
        memory_short: Arc::new(job_memory_short),
        load: Arc::new(system_load),
        install: Arc::new(move |t, bytes: Vec<u8>| {
            a2.set_data(t, crate::ipfilter::LOCAL_SOURCE);
            p2.lock().unwrap().stage(crate::ipfilter::STATE_FILE, bytes.clone());
            tokio::spawn(crate::ipfilter::after_update(runtime.clone(), bytes));
            Ok(())
        }),
    };
    let job = TwIpJob::new(Sources::default(), hooks);
    let j2 = job.clone();
    access.set_update_status(Arc::new(move || j2.status_json()));
    sched.register("tw-ip", job);
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
    if let Some(a) = resolver.access.get() {
        crate::community_bridge::spawn_friend_ips(Arc::downgrade(&node), a.clone());
    }
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

type BoxFut = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

/// CDN 台灣節點：讀狀態（經過快照寫入器，記下雜湊）、接上解析器、啟動定時檢查
/// CDN 網域資料庫：在背景執行緒載入（大的分片要解壓、解析），DNS 監聽已經在回答查詢了
async fn start_cdn(cfg: &Value, resolver: &Arc<Resolver>, persister: &Arc<Mutex<Persister>>) -> Option<Arc<kuroshio_cdn::Cdn>> {
    if !get(cfg, "cdn.enabled").and_then(Value::as_bool).unwrap_or(true) {
        return None;
    }
    let net: Arc<dyn kuroshio_cdn::Net> = Arc::new(kuroshio_cdn::RealNet::new(resolver.iprank.clone()));
    let paths = kuroshio_cdn::Paths::new(persist_dir(cfg), share_dir(cfg));
    let (c2, p2) = (cfg.clone(), persister.clone());
    let cdn = tokio::task::spawn_blocking(move || kuroshio_cdn::Cdn::load_with(&c2, paths, net, &|rel| p2.lock().unwrap().load(rel)))
        .await
        .ok()?;
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

/// `legacy` = 沒有記憶體控制（`system.memoryGovernor: false`）時，照舊在記憶體偏低時縮快取、刪 CDN 網域
fn spawn_maintenance(r: Arc<Resolver>, legacy: bool) {
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
                if legacy && pressure() != Pressure::Normal {
                    let mut c = r.cache.lock().unwrap();
                    let max = c.max;
                    c.max = (max / 2).max(256);
                    c.sweep(std::time::Instant::now(), 0);
                    c.max = max;
                }
                // 記憶體不足：CDN 網域資料庫刪掉最少用的三成（進入不足狀態時一次）
                let critical = legacy && pressure() == Pressure::Critical;
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
    pub info: SysInfo,
    /// 系統記憶體保留量（規格 09）
    pub reserve: crate::memgov::Reserve,
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
    /// 合併後的設定（`/api/paths` 用）
    pub cfg: Arc<Value>,
    /// 記憶體控制（規格 09；`system.memoryGovernor: false` 時沒有）
    pub memgov: Option<Arc<crate::memgov::Governor>>,
}

impl AppState {
    /// `/api/status.memory`：記憶體控制的狀態（沒啟用時只有 RSS）
    pub fn memory_json(&self) -> Value {
        match &self.memgov {
            Some(g) => g.status_json(),
            None => {
                let r = crate::memgov::Reading::now();
                json!({
                    "enabled": false,
                    "rssKB": r.rss.map(|b| b / 1024),
                    "availKB": r.avail.map(|b| b / 1024),
                    "totalKB": r.total.map(|b| b / 1024),
                    "reserveKB": self.reserve.bytes / 1024,
                    "reserveAuto": self.reserve.auto,
                    "reserveHow": self.reserve.how,
                    "headroomKB": crate::memgov::headroom(&r, &self.reserve).map(|b| b / 1024),
                })
            }
        }
    }

    pub fn system_json(&self) -> Value {
        let (total, avail) = sysinfo::meminfo();
        let p = self.persister.lock().unwrap();
        let mut persist = p.status_json(crate::persist::now_secs());
        persist["dir"] = json!(self.persist_dir);
        json!({
            "memTotalMB": total.or(self.info.mem_total_mb),
            "memAvailableMB": avail,
            "rssKB": sysinfo::rss_kb(),
            "pressure": format!("{:?}", pressure()).to_lowercase(),
            "memory": self.memory_json(),
            "cores": self.info.cores,
            "arch": self.info.arch,
            "aes": self.info.aes,
            "persist": persist,
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
        // 模式 B：先移除 HTTP.sys 的網址（重新載入時新的一輪要重新登記）
        if let Some(h) = &self.encrypted.httpsys {
            h.stop();
        }
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

/// 目前的記憶體壓力（記憶體監看依系統保留量更新；離保留量近時每 2–3 秒）
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

/// 設定目錄：快照目錄的上一層（相對路徑都以它為基準）
pub fn config_dir(cfg: &Value) -> PathBuf {
    let state = persist_dir(cfg);
    state.parent().map(|p| p.to_path_buf()).unwrap_or(state)
}

/// 各種檔案放在哪裡（`GET /api/paths`、`kuroshio paths`）。只有路徑與憑證的公開資訊，不含任何密鑰內容。
///
/// `tls.source`：`acme`（內建 ACME 申請、會寫入）、`manual`（自備憑證，只讀）、`none`（沒有設定憑證）
pub fn paths_json(cfg: &Value, config_file: Option<&std::path::Path>) -> Value {
    let state = persist_dir(cfg);
    let base = config_dir(cfg);
    let loc = crate::backup::Locations::from_cfg(cfg);
    let acme_on = get(cfg, "acme.enabled").and_then(Value::as_bool).unwrap_or(false);
    let (pair, source) = if acme_on {
        (Some(crate::acme::cert_paths(cfg, &base)), "acme")
    } else {
        match cert_pair(cfg, "tls", &base).or_else(|| ["dot", "doh", "doq"].iter().find_map(|p| cert_for(cfg, p, &base))) {
            Some(p) => (Some(p), "manual"),
            None => (None, "none"),
        }
    };
    let (cert, key) = pair.map(|(c, k)| (Some(c), Some(k))).unwrap_or((None, None));
    let exists = cert.as_ref().is_some_and(|c| c.is_file()) && key.as_ref().is_some_and(|k| k.is_file());
    let info = cert.as_ref().and_then(|c| crate::certinfo::read(c).ok());
    // 評測報表：Flash 上放記憶體（執行期暫存），硬碟才照 benchmark.outDir
    let bench = if storage_class(cfg) != StorageClass::Disk {
        Some(runtime_dir(cfg).join("benchmark"))
    } else {
        kuroshio_jobs::benchmark::BenchPaths::from_config(cfg, &state, &base).out_root
    };
    // 日誌檔：Windows 服務寫在設定檔旁邊；其他平台輸出到標準輸出（OpenWrt 用 logread 看）
    let log_file = config_file
        .filter(|_| cfg!(windows))
        .map(|f| f.parent().unwrap_or(std::path::Path::new(".")).join("kuroshio.log"));
    json!({
        "configFile": config_file,
        "configDir": base,
        "stateDir": state,
        "runtimeDir": runtime_dir(cfg),
        "shareDir": share_dir(cfg),
        "tls": { "cert": cert, "key": key, "source": source, "exists": exists, "info": info },
        "acme": {
            "enabled": acme_on,
            "account": state.join("acme-account.json"),
            "domains": strings(get(cfg, "acme.domains")),
        },
        "adminToken": crate::webui::token_file(cfg, &base),
        "customRules": loc.custom_rules,
        "benchmarkDir": bench,
        "communityKeyDir": loc.key_dir,
        "logFile": log_file,
    })
}

/// 快照目錄的儲存類型（`system.storageClass` 可以強制指定）
pub fn storage_class(cfg: &Value) -> StorageClass {
    get(cfg, "system.storageClass")
        .and_then(Value::as_str)
        .and_then(StorageClass::parse)
        .unwrap_or_else(|| sysinfo::storage_class(&persist_dir(cfg)))
}

pub fn persist_policy(cfg: &Value) -> Policy {
    let n = |k: &str| kuroshio_config::num_or_auto(get(cfg, k)).unwrap_or(0);
    Policy::new(
        storage_class(cfg),
        n("system.persistIntervalMin"),
        n("system.flashWriteBudgetKB").max(64),
    )
    .with_max_age_hours(n("system.persistMaxAgeHours"))
    .with_storage_reserve(
        n("system.storageReserveMB"),
        n("system.storageReservePercent"),
        n("system.minFreeKB"),
    )
}

/// 快照寫入器：依設定建立，CDN 的檔壓縮
pub fn new_persister(cfg: &Value) -> Persister {
    let mut p = Persister::new(persist_dir(cfg), persist_policy(cfg));
    p.set_compress(compressed_file);
    p.set_mem(mem_now(&crate::memgov::reserve_from_cfg(cfg)));
    p
}

/// 記憶體監看（規格 09）：依系統保留量更新整個程式的壓力訊號，記憶體控制開著時順便跑一輪控制。
/// 離保留量近（兩倍以內）或 PSI 看得到等待時每 2–3 秒量一次，遠的時候 30 秒
fn spawn_monitor(reserve: crate::memgov::Reserve, gov: Option<Arc<crate::memgov::Governor>>) {
    use crate::memgov::{poll_interval, pressure_of, Reading};
    tokio::spawn(async move {
        let mut last = Pressure::Normal;
        loop {
            let r = match &gov {
                Some(g) => g.read(),
                None => Reading::now(),
            };
            let p = pressure_of(&r, &reserve);
            PRESSURE.store(p as u8, Ordering::Relaxed);
            // 好友資料（社群共享）：解壓後不超過保留量以上可用空間的 1/4（至少 1 MB）
            let cap = crate::memgov::headroom(&r, &reserve).map_or(0, |h| ((h >> 20) / 4).clamp(1, u32::MAX as u64) as u32);
            kuroshio_community::config::set_memory_cap_mb(cap);
            if p != last {
                let (a, res) = (r.avail.unwrap_or(0) >> 20, reserve.bytes >> 20);
                match p {
                    Pressure::Normal => info!("記憶體恢復正常（可用 {a} MB，保留 {res} MB）"),
                    Pressure::Low => info!("記憶體接近保留量（可用 {a} MB，保留 {res} MB）：背景工作延後、記憶體結構不再長大"),
                    Pressure::Critical => warn!("記憶體不足（可用 {a} MB，保留 {res} MB）：快照立刻寫出、暫不接受新的加密連線"),
                }
                last = p;
            }
            if let Some(g) = &gov {
                g.tick(r, crate::persist::now_secs()).await;
            }
            tokio::time::sleep(Duration::from_secs(poll_interval(&r, &reserve))).await;
        }
    });
}

/// 會產生快照的模組（CDN、社群）：只在要寫的時候才序列化，有變動的才給
pub type SnapSource = Arc<dyn Fn() -> Vec<(String, Snapshot, Opts)> + Send + Sync>;

/// 一般模組：整份內容
fn bytes_source(f: impl Fn() -> Vec<(String, Vec<u8>)> + Send + Sync + 'static) -> SnapSource {
    Arc::new(move || f().into_iter().map(|(n, b)| (n, Snapshot::Bytes(b), Opts::default())).collect())
}

/// 哪些狀態檔壓縮成 `.zst`：CDN 的檔（網域分片、節點池、IPv6 節點、候選 IP、網段分類）與本機產生的台灣 IP 清單。
/// 分片清單很小、方便人看，維持一般 JSON
pub fn compressed_file(name: &str) -> bool {
    (name.starts_with("cdn/") && name != kuroshio_cdn::db::MANIFEST) || name == crate::ipfilter::STATE_FILE
}

/// CDN：網域資料庫分片寫（規格 05 第 5.3 節）。只登記有變動的分片，內容要寫的那一刻才邊序列化邊寫進檔案；
/// 只有計數變動的分片標成 `lazy`（不單獨觸發寫入，最久未存上限到了才寫）。分片清單等分片都寫好才寫
fn cdn_source(c: Arc<kuroshio_cdn::Cdn>) -> SnapSource {
    Arc::new(move || {
        let (small, ch) = c.snapshots_sharded(false);
        let mut v: Vec<(String, Snapshot, Opts)> = small.into_iter().map(|(n, b)| (n, Snapshot::Bytes(b), Opts::default())).collect();
        let n = ch.shards;
        for (i, important) in ch.changed {
            let c = c.clone();
            v.push((
                kuroshio_cdn::db::shard_file(n, i),
                Snapshot::Stream(Arc::new(move |w| c.write_shard(n, i, w))),
                Opts {
                    lazy: !important,
                    ..Opts::default()
                },
            ));
        }
        if let Some((m, retire)) = ch.manifest {
            v.push((
                kuroshio_cdn::db::MANIFEST.to_string(),
                Snapshot::Bytes(m),
                Opts {
                    after: (0..n).map(|i| kuroshio_cdn::db::shard_file(n, i)).collect(),
                    retire,
                    ..Opts::default()
                },
            ));
        }
        v
    })
}

/// 登記快照（`stage_sources`）的鎖：記憶體控制移出 CDN 冷資料時，「寫出 → 確認已在磁碟 → 移出」期間不能有新的登記
/// （登記會把分片的變動取走，取走之後到寫出之前，記憶體裡的才是最新的）
pub static STAGE_LOCK: Mutex<()> = Mutex::new(());

pub fn stage_sources(p: &Mutex<Persister>, sources: &[SnapSource]) {
    let _g = STAGE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    stage_sources_locked(p, sources);
}

/// 同 `stage_sources`，呼叫端已經拿著 [`STAGE_LOCK`]
pub fn stage_sources_locked(p: &Mutex<Persister>, sources: &[SnapSource]) {
    let now = crate::persist::now_secs();
    for src in sources {
        let snaps = src();
        let mut p = p.lock().unwrap();
        for (name, s, o) in snaps {
            p.stage_with(&name, s, o, now);
        }
    }
}

/// 各清單命中次數：只在有新命中時登記，而且是「只有計數」（不單獨觸發寫入，跟著別的檔或最久未存上限寫）
fn filter_hits_source(f: Arc<crate::filtering::FilterService>) -> SnapSource {
    Arc::new(move || {
        if !f.take_hits_dirty() {
            return Vec::new();
        }
        vec![(
            crate::filtering::HITS_FILE.to_string(),
            Snapshot::Bytes(f.hits_json()),
            Opts {
                lazy: true,
                ..Opts::default()
            },
        )]
    })
}

/// 記憶體控制（規格 09）：系統保留量、釋出階梯（由 [`spawn_monitor`] 依距離調整頻率呼叫）
fn start_governor(
    reserve: crate::memgov::Reserve,
    resolver: &Arc<Resolver>,
    persister: &Arc<Mutex<Persister>>,
    sources: &[SnapSource],
    cdn: Option<&Arc<kuroshio_cdn::Cdn>>,
    filter: Option<&Arc<crate::filtering::FilterService>>,
) -> Arc<crate::memgov::Governor> {
    use crate::memgov::{self, Governor, Step};
    let cache = memgov::CacheStep::new(resolver.clone());
    let cap = cache.cap.clone();
    let mut steps: Vec<Box<dyn Step>> = vec![Box::new(memgov::DiagStep::new(resolver.clone())), Box::new(cache)];
    if let Some(c) = cdn {
        steps.push(Box::new(memgov::CdnStep::new(c.clone(), persister.clone(), sources.to_vec())));
    }
    if let Some(f) = filter {
        steps.push(Box::new(memgov::FilterStep { filter: f.clone() }));
    }
    steps.push(Box::new(memgov::FloorStep::new(
        resolver.clone(),
        cap,
        cdn.map(|c| (c.clone(), persister.clone(), sources.to_vec())),
    )));
    if let Some(f) = filter {
        steps.push(Box::new(memgov::ProtectedStep { filter: f.clone() }));
    }
    let g = Arc::new(Governor::new(reserve.clone(), steps, crate::persist::now_secs()));
    if let Some(f) = filter {
        // 清單載入前先看空間：可以長大的部分放不下的不載入
        let (w, gw, res) = (Arc::downgrade(f), Arc::downgrade(&g), reserve.clone());
        f.set_allowance(Arc::new(move || {
            let f = w.upgrade()?;
            let r = gw.upgrade().map(|g| g.read()).unwrap_or_else(memgov::Reading::now);
            memgov::list_allowance(&r, &res, f.lists_bytes())
        }));
    }
    info!(
        "記憶體控制：系統保留 {} MB（{}），可用記憶體低於保留量時依序讓出記憶體",
        reserve.bytes >> 20,
        reserve.how
    );
    g
}

/// 目前的記憶體狀況（給快照寫入器決定間隔）
fn mem_now(reserve: &crate::memgov::Reserve) -> Mem {
    let (total_mb, avail_mb) = sysinfo::meminfo();
    Mem {
        total_mb,
        avail_mb,
        reserve_mb: reserve.bytes >> 20,
    }
}

fn spawn_persist_loop(p: Arc<Mutex<Persister>>, sources: Vec<SnapSource>, reserve: crate::memgov::Reserve) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(300)).await;
            stage_sources(&p, &sources);
            let mut p = p.lock().unwrap();
            // 記憶體越多、留在記憶體越久；記憶體吃緊時提早寫出、放掉待寫內容
            p.set_mem(mem_now(&reserve));
            p.check_space();
            if let Err(e) = p.flush(crate::persist::now_secs()) {
                warn!("寫入快照失敗：{e}");
            }
        }
    });
}

pub async fn start(cfg: &Value) -> Result<Started> {
    // 記憶用完時核心不優先停掉 DNS（規格 09）：代價是本程式自己要先讓出記憶體
    crate::memgov::apply_oom_from_cfg(cfg);
    let reserve = crate::memgov::reserve_from_cfg(cfg);
    // 設定頁 / 指令列匯入的備份：在讀取任何狀態之前合併（上一輪關機時已經把記憶體寫出）
    let backup = crate::backup::Locations::from_cfg(cfg);
    crate::backup::apply_pending(&backup);
    let persister = Arc::new(Mutex::new(new_persister(cfg)));
    {
        let p = persister.lock().unwrap();
        if p.policy().class == StorageClass::Ram {
            warn!(
                "快照目錄 {} 在記憶體（tmpfs）裡，重開機後節點池與驗證紀錄會遺失",
                persist_dir(cfg).display()
            );
        }
    }
    // 第一次啟動：state 還是空的就帶入種子資料（評測結果、節點池、網站驗證紀錄）
    // （apply_seeds 自己會記錄帶入了哪些）
    let _ = kuroshio_jobs::apply_seeds(&persist_dir(cfg), &share_dir(cfg).join("seed"));
    let resolver = build_resolver(cfg)?;
    // 來源 IP 存取控制（規格 08）：在任何監聽啟動之前
    let access = {
        let saved = persister.lock().unwrap().load(crate::ipfilter::STATE_FILE);
        crate::ipfilter::Access::from_cfg(cfg, &share_dir(cfg), saved)
    };
    access.refresh_local_in_background();
    let _ = resolver.access.set(access.clone());
    crate::ipfilter::spawn_tasks(access.clone());
    // 統計歷史（公開頁 7 / 30 天）：重開機後接續
    if let Some(b) = persister.lock().unwrap().load(STATS_FILE) {
        resolver.stats.restore(&b);
    }
    if let Some(p) = crate::presence::Presence::from_cfg(cfg) {
        let _ = resolver.presence.set(p);
    }
    let governor_on = get(cfg, "system.memoryGovernor").and_then(Value::as_bool).unwrap_or(true);
    spawn_maintenance(resolver.clone(), !governor_on);
    // 過濾：自訂規則與清單路徑以設定目錄（快照目錄的上一層）為基準。自訂規則很小，先載入；
    // 訂閱清單在背景下載 / 讀本機副本（載入期間照樣回答查詢）
    let base_dir = persist_dir(cfg)
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| persist_dir(cfg));
    let filter = crate::filtering::FilterService::from_cfg(cfg, &base_dir);
    if let Some(f) = &filter {
        if let Some(b) = persister.lock().unwrap().load(crate::filtering::HITS_FILE) {
            f.restore_hits(&b);
        }
        f.set_copies(persister.clone());
        f.spawn();
        resolver.set_filter(Some(f.clone()));
    }
    // 明文 DNS 監聽：越早越好（重新啟動時區網斷線的時間越短）。CDN 網域資料庫、過濾清單等大的載入都在這之後
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
    let cdn = start_cdn(cfg, &resolver, &persister).await;
    if cdn.is_none() {
        spawn_wan_subnet(resolver.clone(), None);
    }
    let mut snap_sources: Vec<SnapSource> = Vec::new();
    {
        let r = resolver.clone();
        snap_sources.push(bytes_source(move || vec![(STATS_FILE.to_string(), r.stats.snapshot())]));
    }
    if let Some(c) = &cdn {
        snap_sources.push(cdn_source(c.clone()));
    }
    if let Some(f) = &filter {
        snap_sources.push(filter_hits_source(f.clone()));
    }
    let warm_names = get(cfg, "resolver.warmNames").and_then(Value::as_u64).unwrap_or(0) as usize;
    let warm_rate = get(cfg, "resolver.warmRate").and_then(Value::as_u64).unwrap_or(20);
    spawn_warmup(resolver.clone(), persister.clone(), warm_rate);
    spawn_hot_names(resolver.clone(), persister.clone(), warm_names);
    // 內建 ACME：憑證不存在或快到期就先申請（最多等 3 分鐘），再啟動加密監聽
    let acme = crate::acme::AcmeConfig::from_cfg(cfg, &base_dir, &persist_dir(cfg)).map(crate::acme::Acme::new);
    match &acme {
        Some(a) => {
            if crate::acme::renewal_reason(&a.cfg.cert, &a.cfg.domains, a.cfg.renew_days).is_some() {
                let _ = tokio::time::timeout(Duration::from_secs(180), a.ensure(false)).await;
            }
            a.spawn();
        }
        // 自備憑證：只檢查、提醒，絕不申請或覆蓋
        None => warn_manual_certs(cfg, &base_dir),
    }
    let community = start_community(cfg, &base_dir, &resolver, cdn.clone());
    if let Some(c) = &community {
        let c = c.clone();
        snap_sources.push(bytes_source(move || c.snapshots()));
    }
    spawn_persist_loop(persister.clone(), snap_sources.clone(), reserve.clone());
    let memgov = governor_on.then(|| start_governor(reserve.clone(), &resolver, &persister, &snap_sources, cdn.as_ref(), filter.as_ref()));
    if governor_on || get(cfg, "system.memoryWatchdog").and_then(Value::as_bool).unwrap_or(true) {
        spawn_monitor(reserve.clone(), memgov.clone());
    }
    let encrypted = start_encrypted(cfg, &resolver, &base_dir).await;
    let scheduler = Some(start_scheduler(cfg, &persister, &base_dir, cdn.as_ref(), Some(&access)));
    let ddns = crate::ddns::Config::from_cfg(cfg).map(crate::ddns::Ddns::new);
    if let Some(d) = &ddns {
        d.spawn();
    }
    set_ddr(cfg, &resolver, &encrypted);
    let state = Arc::new(AppState {
        resolver: resolver.clone(),
        persister: persister.clone(),
        info: SysInfo::detect(),
        reserve,
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
        cfg: Arc::new(cfg.clone()),
        memgov,
    });
    // 公開頁：需要整體狀態（唯讀 API），所以最後才建立；DoH 監聽之後才會開始轉給它
    if let Some(site) = crate::site::Site::new(cfg, state.clone(), resolver.presence.get().cloned()) {
        site.spawn();
        let _ = resolver.site.set(site);
    }
    // 憑證續期後自動重新匯入並更新綁定（只有 Windows）：IIS 站台（設定了 listen.doh.iisSite）、HTTP.sys 共用模式
    crate::iiscert::spawn_auto_sync(cfg, base_dir.clone(), persist_dir(cfg), encrypted.httpsys_port);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn cfg(over: Value) -> Value {
        kuroshio_config::with_overrides(&over)
    }

    #[test]
    fn cert_resolution_order() {
        let base = Path::new("/etc/kuroshio");
        let p = |a: &str, b: &str| Some((PathBuf::from(a), PathBuf::from(b)));
        // 什麼都沒設定
        let c = cfg(json!({}));
        for proto in ["dot", "doq", "doh", "doh3"] {
            assert_eq!(cert_for(&c, proto, base), None, "{proto}");
        }
        assert_eq!(cert_for(&c, "plain", base), None);
        // 只有共用憑證：全部協議都用它（相對路徑以設定目錄為基準）
        let c = cfg(json!({ "tls": { "cert": "tls/fullchain.pem", "key": "/certs/privkey.pem" } }));
        for proto in ["dot", "doq", "doh", "doh3"] {
            assert_eq!(
                cert_for(&c, proto, base),
                p("/etc/kuroshio/tls/fullchain.pem", "/certs/privkey.pem"),
                "{proto}"
            );
        }
        // 監聽自己的憑證優先；DoQ 沿用 DoT 的，DoH3 跟 DoH
        let c = cfg(json!({
            "tls": { "cert": "/t/c.pem", "key": "/t/k.pem" },
            "listen": { "dot": { "cert": "/d/c.pem", "key": "/d/k.pem" }, "doh": { "cert": "/h/c.pem", "key": "/h/k.pem" } },
        }));
        assert_eq!(cert_for(&c, "dot", base), p("/d/c.pem", "/d/k.pem"));
        assert_eq!(cert_for(&c, "doq", base), p("/d/c.pem", "/d/k.pem"));
        assert_eq!(cert_for(&c, "doh", base), p("/h/c.pem", "/h/k.pem"));
        assert_eq!(cert_for(&c, "doh3", base), p("/h/c.pem", "/h/k.pem"));
        // 只填一半不算
        let c = cfg(json!({ "tls": { "cert": "/t/c.pem", "key": "/t/k.pem" }, "listen": { "dot": { "cert": "/d/c.pem" } } }));
        assert_eq!(cert_for(&c, "dot", base), p("/t/c.pem", "/t/k.pem"));
        // 內建 ACME：沒有其他憑證時用它的輸出位置；ACME 關閉時不會冒出預設路徑
        let c = cfg(json!({ "domain": "dns.example.com", "acme": { "enabled": true, "apiToken": "t" } }));
        assert_eq!(cert_for(&c, "dot", base), p("/etc/kuroshio/cert.pem", "/etc/kuroshio/key.pem"));
        assert_eq!(cert_for(&c, "doh", base), Some(crate::acme::cert_paths(&c, base)));
        let c = cfg(json!({ "domain": "dns.example.com", "acme": { "enabled": false, "certFile": "/a/c.pem", "keyFile": "/a/k.pem" } }));
        assert_eq!(cert_for(&c, "dot", base), None);
    }

    #[test]
    fn doh_tls_modes() {
        let base = Path::new("/etc/kuroshio");
        let tls = json!({ "cert": "/t/c.pem", "key": "/t/k.pem" });
        let t = |over: Value| doh_uses_tls(&cfg(over), base);
        // 預設（只聽本機、沒有憑證）：明文
        assert!(!t(json!({})));
        // 只聽本機＋共用憑證：前面有反向代理，明文
        assert!(!t(json!({ "tls": tls })));
        assert!(!t(json!({ "tls": tls, "listen": { "doh": { "binds": ["127.0.0.1", "::1"] } } })));
        // 只聽本機但明確寫了 DoH 自己的憑證：TLS
        assert!(t(json!({ "listen": { "doh": { "cert": "/h/c.pem", "key": "/h/k.pem" } } })));
        // 對外監聽：有憑證就 TLS，沒有就明文
        assert!(t(json!({ "tls": tls, "listen": { "doh": { "host": "0.0.0.0" } } })));
        assert!(t(
            json!({ "tls": tls, "listen": { "doh": { "binds": ["127.0.0.1", "192.0.2.1"] } } })
        ));
        assert!(!t(json!({ "listen": { "doh": { "host": "0.0.0.0" } } })));
        assert!(t(
            json!({ "domain": "dns.example.com", "acme": { "enabled": true }, "listen": { "doh": { "host": "::" } } })
        ));
        // IIS 在前面：一律明文
        assert!(!t(
            json!({ "tls": tls, "listen": { "doh": { "host": "0.0.0.0", "windowsMode": "iis-proxy" } } })
        ));
        // 明確指定
        assert!(t(json!({ "listen": { "doh": { "tls": true } } })));
        assert!(!t(json!({ "tls": tls, "listen": { "doh": { "host": "0.0.0.0", "tls": false } } })));
        assert!(t(
            json!({ "tls": tls, "listen": { "doh": { "tls": true, "windowsMode": "iis-proxy" } } })
        ));
        // OpenWrt（UCI 轉出來的設定一律有 listen.doh.cert / key，host 預設 0.0.0.0）：跟以前一樣是 TLS
        let uci = json!({ "listen": { "doh": { "enabled": true, "host": "0.0.0.0", "port": 8443, "cert": "/etc/kuroshio/cert.pem", "key": "/etc/kuroshio/key.pem" } } });
        assert!(t(uci));
    }

    #[test]
    fn paths_listing() {
        let dir = std::env::temp_dir().join(format!("kuroshio-paths-{}", std::process::id()));
        let state = dir.join("state");
        let c = cfg(json!({
            "domain": "dns.example.com",
            "system": { "persistDir": state, "runtimeDir": dir.join("run") },
            "admin": { "auth": true },
            "tls": { "cert": "tls/fullchain.pem", "key": "tls/privkey.pem" },
        }));
        let conf = dir.join("config.json");
        let p = paths_json(&c, Some(&conf));
        assert_eq!(p["configFile"], json!(conf));
        assert_eq!(p["configDir"], json!(dir));
        assert_eq!(p["stateDir"], json!(state));
        assert_eq!(p["runtimeDir"], json!(dir.join("run")));
        assert_eq!(p["tls"]["cert"], json!(dir.join("tls/fullchain.pem")));
        assert_eq!(p["tls"]["key"], json!(dir.join("tls/privkey.pem")));
        assert_eq!(p["tls"]["source"], "manual");
        assert_eq!(p["tls"]["exists"], false);
        assert_eq!(p["tls"]["info"], Value::Null);
        assert_eq!(p["acme"]["enabled"], false);
        assert_eq!(p["acme"]["domains"], json!(["dns.example.com"]));
        assert_eq!(p["acme"]["account"], json!(state.join("acme-account.json")));
        assert_eq!(p["adminToken"], json!(dir.join("admin.token")));
        assert_eq!(p["customRules"], json!(dir.join("custom-rules.txt")));
        assert_eq!(p["communityKeyDir"], json!(dir.join("state/community")));
        for k in ["shareDir", "benchmarkDir", "logFile"] {
            assert!(p.get(k).is_some(), "{k}");
        }
        // 內建 ACME：來源是 acme，位置照 ACME 的輸出順序
        let c = cfg(json!({ "domain": "dns.example.com", "system": { "persistDir": state }, "acme": { "enabled": true } }));
        let p = paths_json(&c, None);
        assert_eq!(p["tls"]["source"], "acme");
        assert_eq!(p["tls"]["cert"], json!(dir.join("cert.pem")));
        assert_eq!(p["configFile"], Value::Null);
        // 沒有憑證
        let c = cfg(json!({ "system": { "persistDir": state } }));
        let p = paths_json(&c, None);
        assert_eq!(p["tls"]["source"], "none");
        assert_eq!(p["tls"]["cert"], Value::Null);
    }

    /// 多位址監聽：其中一個綁不起來（不是這台機器的位址、格式錯誤）只記錄，其他照常
    #[tokio::test]
    async fn multiple_binds_and_one_failure() {
        let c = cfg(json!({
            "resolver": { "lastResort": [], "rankIps": false },
            "listen": { "doh": { "enabled": true, "port": 0, "binds": ["192.0.2.1", "127.0.0.1", "不是位址", "127.0.0.2"] } },
        }));
        let r = build_resolver(&c).unwrap();
        let e = start_encrypted(&c, &r, Path::new("/nonexistent")).await;
        let d = e.detail_json();
        let d = d.as_array().unwrap();
        assert_eq!(d.len(), 4);
        assert_eq!(d[0]["ok"], false);
        assert!(d[0]["error"].is_string());
        assert_eq!(d[1]["ok"], true);
        assert_eq!(d[1]["tls"], false);
        assert_eq!(d[1]["proto"], "doh");
        assert_eq!(d[1]["bind"], "127.0.0.1");
        assert_eq!(d[2]["ok"], false);
        assert_eq!(d[2]["error"], "位址格式錯誤");
        // 127.0.0.2：Linux 整個 127/8 都能綁；其他平台可能不行，只要求不影響前面的
        assert_eq!(e.doh.map(|a| a.ip().to_string()).as_deref(), Some("127.0.0.1"));
        // 要 TLS 卻沒有憑證：不啟動，每個位址都記下原因
        let c = cfg(json!({
            "resolver": { "lastResort": [], "rankIps": false },
            "listen": { "doh": { "enabled": true, "port": 0, "tls": true, "binds": ["127.0.0.1"] }, "dot": { "enabled": true, "port": 0 } },
        }));
        let e = start_encrypted(&c, &r, Path::new("/nonexistent")).await;
        assert!(e.doh.is_none() && e.dot.is_none());
        assert_eq!(e.detail.len(), 2);
        assert!(e.detail.iter().all(|l| l.error.is_some()));
    }

    /// 模式與 DoH3 的狀態一定會回報；Windows 以外的系統 httpsys 改成自己監聽
    #[cfg(not(windows))]
    #[tokio::test]
    async fn doh_mode_is_reported() {
        let c = cfg(json!({
            "resolver": { "lastResort": [], "rankIps": false },
            "domain": "dns.example.net",
            "listen": { "doh": { "enabled": true, "port": 0, "binds": ["127.0.0.1"], "windowsMode": "httpsys", "http3": true } },
        }));
        let r = build_resolver(&c).unwrap();
        let e = start_encrypted(&c, &r, Path::new("/nonexistent")).await;
        assert_eq!(e.doh_mode["configured"], "httpsys");
        assert_eq!(e.doh_mode["mode"], "standalone");
        assert!(e.doh_mode["reason"].as_str().unwrap().contains("只有 Windows"));
        assert!(e.httpsys.is_none() && e.httpsys_port.is_none());
        assert!(e.doh.is_some(), "照常自己監聽");
        // DoH3 要憑證，沒有：none + 原因；沒綁 UDP 就不宣告 Alt-Svc
        assert_eq!(e.doh3_provider["provider"], "none");
        assert!(e.doh3_provider["reason"].as_str().unwrap().contains("憑證"));
        assert_eq!(e.doh_mode["altSvc"], Value::Null);
        let c = cfg(json!({
            "resolver": { "lastResort": [], "rankIps": false },
            "listen": { "doh": { "enabled": true, "port": 0, "binds": ["127.0.0.1"] } },
        }));
        let e = start_encrypted(&c, &r, Path::new("/nonexistent")).await;
        assert_eq!(
            (e.doh_mode["mode"].as_str(), e.doh3_provider["provider"].as_str()),
            (Some("standalone"), Some("none"))
        );
    }

    /// `0.0.0.0` 與 `::` 可以同時綁同一個埠（IPv6 設了 V6ONLY）
    #[tokio::test]
    async fn v4_and_v6_share_a_port() {
        let Ok(l6) = crate::netif::bind_tcp("[::]:0".parse().unwrap()) else {
            return; // 這台機器沒有 IPv6
        };
        let port = l6.local_addr().unwrap().port();
        crate::netif::bind_tcp(SocketAddr::new(IpAddr::from([0, 0, 0, 0]), port)).expect("IPv4 同一個埠");
        let u6 = crate::netif::bind_udp("[::]:0".parse().unwrap()).unwrap();
        let port = u6.local_addr().unwrap().port();
        crate::netif::bind_udp(SocketAddr::new(IpAddr::from([0, 0, 0, 0]), port)).expect("IPv4 同一個 UDP 埠");
    }
}
