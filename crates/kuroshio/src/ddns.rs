//! DDNS（對齊 2.x 的 lib/ddns.js）：公網 IP 變了就用 Cloudflare API 更新 DNS 記錄
//!
//! - IP 來源：`web` = 問 Cloudflare 的 /cdn-cgi/trace（用 IP 位址連線，分得出 IPv4 / IPv6）；`interface` = 讀本機網卡
//! - 多網卡 / 多出口（`ddns.interfaces`）：每張網卡各偵測一次（`web` 會從那張網卡連出去問），
//!   一個名稱可以同時有好幾筆 A / AAAA 記錄；沒有指定網卡 = 系統預設路由
//! - IPv6 預設不發布（`ddns.ipv6 = false`）：中華電信的線路常常擋掉連入的 IPv6
//! - 只在 IP 變了、或距上次確認超過 forceHours 才呼叫 API（Cloudflare API 有頻率限制）
//! - 記錄以「一組 IP」對帳：少的建立、內容要換的就地更新、不再使用的刪除。
//!   **正確優先**：
//!   - 偵測失敗（問不到）不代表出口不見了：保留上次的記錄，整族都問不到時完全不動
//!   - 只有在同一族還有其他出口偵測成功、而且這個 IP 連續 `GONE_RUNS` 次都確定不在了，才刪除
//!   - 只刪除黑潮 DNS 自己建立 / 接手的記錄（記錄的 comment 有 `kuroshio-ddns`）；
//!     其他類型、其他名稱、別人手動加的記錄一律不動
//!   - 關掉某一族（例如 `ddns.ipv6 = false`）：下次執行時刪掉自己發布的那一族記錄並記到日誌
//! - 選用：發布網域的 HTTPS 記錄（`alpn="h3,h2"`），讓瀏覽器第一次連線就用 HTTP/3（規格 07 第 2.3 節）

use crate::cloudflare::Cloudflare;
use crate::netif::{self, Iface};
use anyhow::{anyhow, bail, Result};
use kuroshio_net::fetch::{request_from, LocalBind, Request};
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// 黑潮 DNS 建立 / 接手的記錄在 Cloudflare 上的註解（comment）：只有帶這個標記的記錄才會被刪除
pub const MARK: &str = "kuroshio-ddns";

/// 一個 IP 連續幾次「確定不在任何出口上」才刪除它的記錄
pub const GONE_RUNS: u32 = 3;

/// 要偵測的網卡（出口）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfaceSel {
    pub name: String,
    pub v4: bool,
    pub v6: bool,
}

impl IfaceSel {
    pub fn both(name: &str) -> IfaceSel {
        IfaceSel {
            name: name.to_string(),
            v4: true,
            v6: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub api_token: String,
    pub records: Vec<String>,
    pub zone: String,
    pub ipv4: bool,
    pub ipv6: bool,
    pub proxied: bool,
    pub ttl: u64,
    pub interval: Duration,
    pub force: Duration,
    pub ip_source: String,
    /// 指定的網卡（出口）；空的 = 系統預設路由
    pub interfaces: Vec<IfaceSel>,
    pub url4: String,
    pub url6: String,
    pub api: String,
    /// 發布 HTTPS 記錄（alpn h3,h2）的網域；空白 = 不發布
    pub https_record: Option<String>,
    /// 裝置從外面連 DoH 的埠號：（TCP, DoH3 的 UDP），見 [`crate::app::public_doh_port`]
    pub https_ports: (u16, u16),
    /// 連續幾次確定不在了才刪除（預設 `GONE_RUNS`）
    pub gone_runs: u32,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            api_token: String::new(),
            records: Vec::new(),
            zone: String::new(),
            ipv4: true,
            ipv6: false,
            proxied: false,
            ttl: 1,
            interval: Duration::from_secs(300),
            force: Duration::from_secs(86400),
            ip_source: "web".into(),
            interfaces: Vec::new(),
            url4: "https://1.1.1.1/cdn-cgi/trace".into(),
            url6: "https://[2606:4700:4700::1111]/cdn-cgi/trace".into(),
            api: "https://api.cloudflare.com/client/v4".into(),
            https_record: None,
            https_ports: (443, 443),
            gone_runs: GONE_RUNS,
        }
    }
}

/// HTTPS 記錄（RFC 9460）的（名稱, target, SvcParams）。
///
/// - DoH 在 443：記錄放在網域本身，`target = "."`（同一個名稱）
/// - DoH 在其他埠（例如 8443）：瀏覽器查的是 `_8443._https.<網域>`（RFC 9460 第 9.1 節），
///   target 要寫網域本身（`_8443._https…` 沒有 A / AAAA），並加上 `port=`
/// - DoH3 的 UDP 埠跟 TCP 不同：記錄只宣告 h3（`no-default-alpn`，不支援 HTTP/3 的用戶端會略過這筆、直接連原本的埠），
///   `port=` 是 UDP 的埠號
pub fn https_record(domain: &str, tcp: u16, udp: u16) -> (String, String, String) {
    let (name, target) = if tcp == 443 {
        (domain.to_string(), ".".to_string())
    } else {
        (format!("_{tcp}._https.{domain}"), format!("{domain}."))
    };
    let value = if udp == tcp {
        if tcp == 443 {
            "alpn=\"h3,h2\"".to_string()
        } else {
            format!("alpn=\"h3,h2\" port={tcp}")
        }
    } else {
        format!("alpn=\"h3\" no-default-alpn port={udp}")
    };
    (name, target, value)
}

/// `ddns.interfaces`；沒寫時，`ipSource = interface` 沿用舊的 `iface4` / `iface6`
/// （舊欄位分開指定 IPv4 / IPv6 用哪張網卡；`iface6` 沒填時 IPv6 也用 `iface4`）。
/// `ipSource = web` 以前不看 `iface4` / `iface6`，現在也不看（行為不變）。
pub fn interfaces_from_cfg(cfg: &Value) -> Vec<IfaceSel> {
    let g = |k: &str| kuroshio_config::get(cfg, &format!("ddns.{k}"));
    let s = |k: &str| g(k).and_then(Value::as_str).map(str::trim).unwrap_or("").to_string();
    let mut out: Vec<IfaceSel> = Vec::new();
    for name in g("interfaces")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|n| !n.is_empty())
    {
        if !out.iter().any(|i| i.name == name) {
            out.push(IfaceSel::both(name));
        }
    }
    if out.is_empty() && s("ipSource") == "interface" {
        let (i4, i6) = (s("iface4"), s("iface6"));
        if !i4.is_empty() {
            out.push(IfaceSel {
                v4: true,
                v6: i6.is_empty() || i6 == i4,
                name: i4.clone(),
            });
        }
        if !i6.is_empty() && i6 != i4 {
            out.push(IfaceSel {
                name: i6,
                v4: false,
                v6: true,
            });
        }
    }
    out
}

impl Config {
    pub fn from_cfg(cfg: &Value) -> Option<Config> {
        let g = |k: &str| kuroshio_config::get(cfg, &format!("ddns.{k}"));
        if !g("enabled").and_then(Value::as_bool).unwrap_or(false) {
            return None;
        }
        let d = Config::default();
        let s = |k: &str, d: &str| g(k).and_then(Value::as_str).filter(|v| !v.is_empty()).unwrap_or(d).to_string();
        let n = |k: &str, d: u64| g(k).and_then(Value::as_u64).unwrap_or(d);
        let b = |k: &str, d: bool| g(k).and_then(Value::as_bool).unwrap_or(d);
        let domain = kuroshio_config::get(cfg, "site.hostname")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let h3 = kuroshio_config::get(cfg, "listen.doh.http3")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            && kuroshio_config::get(cfg, "listen.doh.enabled")
                .and_then(Value::as_bool)
                .unwrap_or(false);
        Some(Config {
            api_token: s("apiToken", ""),
            records: g("records")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(|r| r.trim().to_string())
                        .filter(|r| !r.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            zone: s("zone", ""),
            ipv4: b("ipv4", true),
            ipv6: b("ipv6", false),
            proxied: b("proxied", false),
            ttl: n("ttl", 1),
            interval: Duration::from_secs(n("intervalMin", 5).max(1) * 60),
            force: Duration::from_secs(n("forceHours", 24) * 3600),
            ip_source: s("ipSource", "web"),
            interfaces: interfaces_from_cfg(cfg),
            url4: s("url4", &d.url4),
            url6: s("url6", &d.url6),
            api: s("api", &d.api),
            https_record: (b("httpsRecord", true) && h3 && !domain.is_empty()).then_some(domain),
            https_ports: {
                let tls = crate::app::doh_uses_tls(cfg, &crate::app::config_dir(cfg));
                (crate::app::public_doh_port(cfg, tls), crate::app::public_doh3_port(cfg, tls))
            },
            gone_runs: GONE_RUNS,
        })
    }
}

/// 一個出口的偵測結果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Ok,
    /// 確定沒有：網卡不存在、沒連線、沒有這一族的位址
    Gone,
    /// 偵測失敗（問不到）：不確定，保留上次的結果
    Failed,
}

#[derive(Debug, Clone)]
struct Source {
    /// 網卡名稱；空白 = 系統預設路由
    interface: String,
    v6: bool,
    ip: Option<IpAddr>,
    state: State,
    error: Option<String>,
}

impl Source {
    fn ok(interface: &str, v6: bool, ip: IpAddr) -> Source {
        Source {
            interface: interface.to_string(),
            v6,
            ip: Some(ip),
            state: State::Ok,
            error: None,
        }
    }
    fn bad(interface: &str, v6: bool, state: State, error: String) -> Source {
        Source {
            interface: interface.to_string(),
            v6,
            ip: None,
            state,
            error: Some(error),
        }
    }
    fn json(&self) -> Value {
        json!({
            "interface": self.interface, "family": if self.v6 { 6 } else { 4 },
            "ip": self.ip.map(|i| i.to_string()), "ok": self.state == State::Ok, "error": self.error,
        })
    }
}

/// 從指定網卡連出去要綁的來源位址（Linux 另外綁網卡本身）
pub fn egress_bind(ifs: &[Iface], name: &str, v6: bool) -> std::result::Result<LocalBind, String> {
    let fam = if v6 { 6 } else { 4 };
    let Some(i) = netif::find(ifs, name) else {
        return Err(format!("找不到網卡 {name}"));
    };
    if !i.up {
        return Err(format!("網卡 {name} 沒有連線"));
    }
    match i.source_addr(v6) {
        Some(ip) => Ok(LocalBind {
            ip,
            device: Some(i.name.clone()),
        }),
        None => Err(format!("網卡 {name} 沒有 IPv{fam} 位址")),
    }
}

/// 問 /cdn-cgi/trace：回傳看到的公網 IP 與整份回應（`from` = 從哪個出口問；None = 預設路由）
pub async fn trace(url: &str, from: Option<&LocalBind>) -> Result<(Option<IpAddr>, String)> {
    let (status, body) = request_from(
        url,
        &Request {
            method: "GET",
            ..Default::default()
        },
        65536,
        Duration::from_secs(8),
        from,
    )
    .await?;
    if status != 200 {
        bail!("{url} HTTP {status}");
    }
    let text = String::from_utf8_lossy(&body).to_string();
    let ip = text
        .lines()
        .find_map(|l| l.strip_prefix("ip="))
        .and_then(|v| v.trim().parse::<IpAddr>().ok());
    Ok((ip, text))
}

type NetifFn = Arc<dyn Fn() -> Vec<Iface> + Send + Sync>;

/// 對帳用的狀態（只在記憶體裡；重新啟動後從 Cloudflare 上的記錄重新對一次）
#[derive(Default)]
struct Memory {
    /// `類型|名稱` → （上次對帳的 IP 組合, 時間, 還有待處理的記錄）
    last: HashMap<String, (String, Instant, bool)>,
    /// `類型|名稱|內容` → 連續幾次確定不在了
    misses: HashMap<String, u32>,
    /// （網卡, 是不是 IPv6）→ 上次偵測到的 IP
    last_src: HashMap<(String, bool), Vec<IpAddr>>,
    /// 已經清過的「關掉的那一族」：`類型|名稱`
    off_done: HashSet<String>,
    /// 已經提醒過的「不是黑潮 DNS 建立的記錄」
    foreign_warned: HashSet<String>,
}

pub struct Ddns {
    pub cfg: Config,
    cf: Cloudflare,
    mem: Mutex<Memory>,
    status: Mutex<Value>,
    netif: NetifFn,
}

fn rtype(v6: bool) -> &'static str {
    if v6 {
        "AAAA"
    } else {
        "A"
    }
}

fn owned(r: &Value) -> bool {
    r["comment"].as_str().is_some_and(|c| c.contains(MARK))
}

impl Ddns {
    pub fn new(cfg: Config) -> Arc<Ddns> {
        Ddns::with_netif(cfg, Arc::new(netif::list))
    }

    /// 測試用：自訂「本機有哪些網卡」
    pub fn with_netif(cfg: Config, netif: NetifFn) -> Arc<Ddns> {
        Arc::new(Ddns {
            cf: Cloudflare::new(&cfg.api, &cfg.api_token, &cfg.zone),
            cfg,
            mem: Mutex::new(Memory::default()),
            status: Mutex::new(json!({ "enabled": true })),
            netif,
        })
    }

    pub fn status(&self) -> Value {
        self.status.lock().unwrap().clone()
    }

    /// 偵測這一族每個出口的公網 IP
    async fn detect(&self, v6: bool, ifs: &[Iface]) -> Vec<Source> {
        let c = &self.cfg;
        let fam = if v6 { 6 } else { 4 };
        let sel: Vec<&IfaceSel> = c.interfaces.iter().filter(|i| if v6 { i.v6 } else { i.v4 }).collect();
        let mut out = Vec::new();
        if c.ip_source == "interface" {
            // 讀網卡上設定的公網位址
            let targets: Vec<(String, Option<&Iface>)> = if c.interfaces.is_empty() {
                // 沒有指定：預設路由走的那張網卡
                vec![(String::new(), netif::default_iface(ifs, v6))]
            } else {
                sel.iter().map(|s| (s.name.clone(), netif::find(ifs, &s.name))).collect()
            };
            for (name, iface) in targets {
                let shown = if name.is_empty() {
                    "預設路由的網卡".to_string()
                } else {
                    format!("網卡 {name}")
                };
                match iface {
                    None if name.is_empty() => out.push(Source::bad(
                        &name,
                        v6,
                        State::Failed,
                        format!("找不到 IPv{fam} 預設路由的網卡（請在 ddns.interfaces 指定網卡）"),
                    )),
                    None => out.push(Source::bad(&name, v6, State::Gone, format!("找不到{shown}"))),
                    Some(i) if !i.up => out.push(Source::bad(&name, v6, State::Gone, format!("{shown}沒有連線"))),
                    Some(i) => {
                        let ips = i.public_addrs(v6);
                        if ips.is_empty() {
                            out.push(Source::bad(
                                &name,
                                v6,
                                State::Gone,
                                format!("{shown}沒有公網 IPv{fam} 位址（在 NAT 後面的話請把 IP 來源改成 web）"),
                            ));
                        }
                        out.extend(ips.into_iter().map(|ip| Source::ok(&name, v6, ip)));
                    }
                }
            }
            return out;
        }
        // web：從每個出口各問一次（沒有指定網卡 = 預設路由問一次）
        let url = if v6 { &c.url6 } else { &c.url4 };
        let binds: Vec<(String, std::result::Result<Option<LocalBind>, String>)> = if c.interfaces.is_empty() {
            vec![(String::new(), Ok(None))]
        } else {
            sel.iter()
                .map(|s| (s.name.clone(), egress_bind(ifs, &s.name, v6).map(Some)))
                .collect()
        };
        for (name, bind) in binds {
            let bind = match bind {
                Ok(b) => b,
                Err(e) => {
                    out.push(Source::bad(&name, v6, State::Gone, e));
                    continue;
                }
            };
            match trace(url, bind.as_ref()).await {
                Ok((Some(ip), _)) if ip.is_ipv6() == v6 => out.push(Source::ok(&name, v6, ip)),
                Ok(_) => out.push(Source::bad(&name, v6, State::Failed, format!("取不到公網 IPv{fam}"))),
                Err(e) => out.push(Source::bad(&name, v6, State::Failed, format!("{e:#}"))),
            }
        }
        out
    }

    async fn upsert(&self, name: &str, rtype: &str, body: Value, same: impl Fn(&Value) -> bool) -> Result<(&'static str, Option<String>)> {
        let zid = self.cf.zone_id(name).await?;
        let recs = self
            .cf
            .api("GET", &format!("/zones/{zid}/dns_records?type={rtype}&name={name}"), None)
            .await?;
        match recs.get(0) {
            None => {
                self.cf.api("POST", &format!("/zones/{zid}/dns_records"), Some(&body)).await?;
                Ok(("created", None))
            }
            Some(r) if same(r) => Ok(("unchanged", r["content"].as_str().map(str::to_string))),
            Some(r) => {
                let id = r["id"].as_str().ok_or_else(|| anyhow!("記錄沒有 id"))?;
                self.cf.api("PATCH", &format!("/zones/{zid}/dns_records/{id}"), Some(&body)).await?;
                Ok(("updated", r["content"].as_str().map(str::to_string)))
            }
        }
    }

    /// 把 `name` 的 `rtype` 記錄對成 `want` 這一組 IP。
    ///
    /// - `determinate`：這一族每個出口這次都有明確結果（成功，或確定沒有）。有出口偵測失敗時不刪除、不改寫別的記錄。
    /// - `prev`：新 IP → 同一個出口上次的 IP（就地更新時優先改那一筆）
    ///
    /// 回傳（每筆記錄的結果, 還有沒有待處理的記錄）
    async fn reconcile(
        &self,
        name: &str,
        rtype: &'static str,
        want: &BTreeSet<String>,
        determinate: bool,
        prev: &HashMap<String, String>,
    ) -> Result<(Vec<Value>, bool)> {
        let c = &self.cfg;
        let zid = self.cf.zone_id(name).await?;
        let recs = self.cf.list_records(&zid, rtype, name).await?;
        let content = |r: &Value| r["content"].as_str().unwrap_or("").to_string();
        let id_of = |r: &Value| r["id"].as_str().map(str::to_string).ok_or_else(|| anyhow!("記錄沒有 id"));
        let body = |ip: &str| json!({ "type": rtype, "name": name, "content": ip, "ttl": c.ttl, "proxied": c.proxied, "comment": MARK });
        let res = |ip: &str, action: &str| json!({ "name": name, "type": rtype, "content": ip, "ip": ip, "ok": true, "action": action });
        let any_owned = recs.iter().any(owned);
        let mut results = Vec::new();
        let mut pending = false;

        // 1. 已經有的：設定一樣就不動；代理 / TTL 不同、或還沒標記成自己的，就地更新
        let mut have: BTreeSet<String> = BTreeSet::new();
        let mut stale: Vec<&Value> = Vec::new();
        for r in &recs {
            let ip = content(r);
            if !want.contains(&ip) || !have.insert(ip.clone()) {
                stale.push(r); // 不在這一組裡，或同一個 IP 重複的記錄
                continue;
            }
            let same_settings = r["proxied"].as_bool().unwrap_or(false) == c.proxied && r["ttl"].as_u64() == Some(c.ttl);
            if same_settings && owned(r) {
                results.push(res(&ip, "unchanged"));
                continue;
            }
            self.cf
                .api("PATCH", &format!("/zones/{zid}/dns_records/{}", id_of(r)?), Some(&body(&ip)))
                .await?;
            if same_settings {
                // 內容沒變，只是標記成黑潮 DNS 管理（以後這個出口不用了才知道可以刪）
                results.push(res(&ip, "unchanged"));
            } else {
                info!("DDNS {name} {rtype} {ip}：更新代理 / TTL 設定");
                let mut v = res(&ip, "updated");
                v["previous"] = json!(ip);
                results.push(v);
            }
        }

        // 2. 可以改寫的舊記錄：自己的；這個名稱還沒有任何自己的記錄時（舊版建立的、第一次接手）也包含沒標記的
        let (mut pool, foreign): (Vec<&Value>, Vec<&Value>) = stale.into_iter().partition(|r| owned(r) || !any_owned);

        // 3. 缺的：有舊記錄可以改就就地更新（同一個出口換 IP），否則建立。
        //    知道是哪個出口換了 IP 就改它原本那一筆；不知道時，只有在每個出口都有明確結果才拿別的舊記錄來改
        //    （有出口這次問不到：舊記錄可能就是那個出口的，不能拿來改）
        for ip in want.iter().filter(|ip| !have.contains(*ip)) {
            let pick = prev
                .get(ip)
                .and_then(|p| pool.iter().position(|r| content(r) == *p))
                .or(if determinate && !pool.is_empty() { Some(0) } else { None });
            match pick {
                Some(i) => {
                    let old = pool.remove(i);
                    self.cf
                        .api("PATCH", &format!("/zones/{zid}/dns_records/{}", id_of(old)?), Some(&body(ip)))
                        .await?;
                    info!("DDNS {name} {rtype} → {ip}（更新，原本是 {}）", content(old));
                    let mut v = res(ip, "updated");
                    v["previous"] = json!(content(old));
                    results.push(v);
                }
                None => {
                    self.cf.api("POST", &format!("/zones/{zid}/dns_records"), Some(&body(ip))).await?;
                    info!("DDNS {name} {rtype} → {ip}（建立）");
                    let mut v = res(ip, "created");
                    v["previous"] = Value::Null;
                    results.push(v);
                }
            }
        }

        // 4. 多出來的舊記錄：連續 gone_runs 次都確定不在任何出口上才刪除
        let mut live_keys: HashSet<String> = HashSet::new();
        for r in pool {
            let ip = content(r);
            let key = format!("{rtype}|{name}|{ip}");
            if !determinate {
                // 有出口這次問不到：不確定這筆是不是它的，先保留（計數不變）
                live_keys.insert(key);
                let mut v = res(&ip, "kept");
                v["note"] = json!("有出口這次偵測失敗，先保留");
                results.push(v);
                pending = true;
                continue;
            }
            let n = {
                let mut m = self.mem.lock().unwrap();
                let n = m.misses.entry(key.clone()).or_insert(0);
                *n += 1;
                *n
            };
            if n >= c.gone_runs.max(1) {
                self.cf
                    .api("DELETE", &format!("/zones/{zid}/dns_records/{}", id_of(r)?), None)
                    .await?;
                self.mem.lock().unwrap().misses.remove(&key);
                info!("DDNS {name} {rtype} {ip}：這個 IP 已經不在任何出口上（連續 {n} 次），刪除記錄");
                results.push(res(&ip, "deleted"));
            } else {
                live_keys.insert(key);
                let mut v = res(&ip, "kept");
                v["note"] = json!(format!("不在目前的出口上（{n} / {} 次後刪除）", c.gone_runs.max(1)));
                results.push(v);
                pending = true;
            }
        }
        // 回到出口上、或已經不存在的記錄：計數歸零
        let prefix = format!("{rtype}|{name}|");
        self.mem
            .lock()
            .unwrap()
            .misses
            .retain(|k, _| !k.starts_with(&prefix) || live_keys.contains(k));

        // 5. 別人的記錄：不動，只提醒一次
        for r in foreign {
            let ip = content(r);
            if self.mem.lock().unwrap().foreign_warned.insert(format!("{rtype}|{name}|{ip}")) {
                warn!("DDNS {name} {rtype} {ip}：這筆記錄不是黑潮 DNS 建立的，沒有更動（不需要的話請到 Cloudflare 手動刪除）");
            }
            let mut v = res(&ip, "kept");
            v["note"] = json!("不是黑潮 DNS 建立的記錄，沒有更動");
            results.push(v);
        }
        Ok((results, pending))
    }

    /// 關掉的那一族：刪掉自己發布過的記錄（每次啟動、每個名稱檢查一次；force 時再檢查一次）
    async fn cleanup_off(&self, v6: bool, force: bool) -> Vec<Value> {
        let rtype = rtype(v6);
        let fam = if v6 { 6 } else { 4 };
        let mut results = Vec::new();
        for name in &self.cfg.records {
            let key = format!("{rtype}|{name}");
            if !force && self.mem.lock().unwrap().off_done.contains(&key) {
                continue;
            }
            let r: Result<()> = async {
                let zid = self.cf.zone_id(name).await?;
                let recs = self.cf.list_records(&zid, rtype, name).await?;
                let mut others = Vec::new();
                for r in &recs {
                    let ip = r["content"].as_str().unwrap_or("").to_string();
                    if !owned(r) {
                        others.push(ip);
                        continue;
                    }
                    let id = r["id"].as_str().ok_or_else(|| anyhow!("記錄沒有 id"))?;
                    self.cf.api("DELETE", &format!("/zones/{zid}/dns_records/{id}"), None).await?;
                    info!("DDNS：IPv{fam} 已關閉（ddns.ipv{fam} = false），刪除 {name} 的 {rtype} 記錄 {ip}");
                    results.push(json!({ "name": name, "type": rtype, "content": ip, "ip": ip, "ok": true, "action": "deleted" }));
                }
                if !others.is_empty() && self.mem.lock().unwrap().foreign_warned.insert(format!("{key}|off")) {
                    warn!(
                        "DDNS：IPv{fam} 已關閉，但 {name} 還有 {} 筆不是黑潮 DNS 建立的 {rtype} 記錄（{}），沒有更動；不需要的話請到 Cloudflare 手動刪除",
                        others.len(),
                        others.join(", ")
                    );
                }
                Ok(())
            }
            .await;
            match r {
                Ok(()) => {
                    self.mem.lock().unwrap().off_done.insert(key);
                }
                Err(e) => warn!("DDNS {name} {rtype}（清除已關閉的 IPv{fam} 記錄）：{e:#}"),
            }
        }
        results
    }

    /// 立即檢查並更新；force = 不管 IP 有沒有變都呼叫 API 確認
    pub async fn update(&self, force: bool) -> Value {
        let c = &self.cfg;
        if !crate::clock::synced() {
            // 系統時間沒對時：TLS 驗不過，不做也不蓋掉上次的狀態
            let mut st = self.status();
            st["deferred"] = json!(true);
            st["note"] = json!("系統時間還沒對時，DDNS 延後到對時之後");
            return st;
        }
        let mut st = json!({
            "enabled": true, "lastRun": kuroshio_net::fetch::now_ms(), "ip4": null, "ip6": null,
            "ips4": [], "ips6": [], "sources": [], "records": [], "error": null,
        });
        if c.api_token.is_empty() {
            st["error"] = json!("沒有設定 Cloudflare API Token");
        } else if c.records.is_empty() {
            st["error"] = json!("沒有設定要更新的記錄");
        } else {
            let mut results = Vec::new();
            let mut sources = Vec::new();
            // 有指定網卡、或直接讀網卡時才列舉本機網卡
            let ifs = if c.interfaces.is_empty() && c.ip_source != "interface" {
                Vec::new()
            } else {
                (self.netif)()
            };
            for v6 in [false, true] {
                let rtype = rtype(v6);
                let fam = if v6 { 6 } else { 4 };
                if (!v6 && !c.ipv4) || (v6 && !c.ipv6) {
                    results.extend(self.cleanup_off(v6, force).await);
                    continue;
                }
                let srcs = self.detect(v6, &ifs).await;
                sources.extend(srcs.iter().map(Source::json));
                let ok: BTreeSet<IpAddr> = srcs.iter().filter(|s| s.state == State::Ok).filter_map(|s| s.ip).collect();
                st[if v6 { "ip6" } else { "ip4" }] = json!(ok.iter().next().map(|i| i.to_string()));
                st[if v6 { "ips6" } else { "ips4" }] = json!(ok.iter().map(|i| i.to_string()).collect::<Vec<_>>());
                if ok.is_empty() {
                    // 整族都問不到：完全不動（保留上次的記錄）
                    let why = srcs
                        .iter()
                        .find_map(|s| s.error.clone())
                        .unwrap_or_else(|| format!("取不到公網 IPv{fam}"));
                    if st["error"].is_null() {
                        st["error"] = json!(why);
                    }
                    for name in &c.records {
                        results.push(
                            json!({ "name": name, "type": rtype, "ok": false, "action": "skip", "error": format!("取不到公網 IPv{fam}") }),
                        );
                    }
                    continue;
                }
                // 這一組 = 這次偵測到的 + 偵測失敗的出口上次的 IP（保留）
                let determinate = srcs.iter().all(|s| s.state != State::Failed);
                let mut want: BTreeSet<String> = ok.iter().map(|i| i.to_string()).collect();
                let mut prev: HashMap<String, String> = HashMap::new();
                {
                    let mut m = self.mem.lock().unwrap();
                    let mut by_iface: HashMap<&str, (Vec<IpAddr>, State)> = HashMap::new();
                    for s in &srcs {
                        let e = by_iface.entry(s.interface.as_str()).or_insert((Vec::new(), s.state));
                        e.0.extend(s.ip);
                        e.1 = s.state;
                    }
                    for (iface, (ips, state)) in by_iface {
                        let key = (iface.to_string(), v6);
                        match state {
                            State::Failed => {
                                want.extend(m.last_src.get(&key).into_iter().flatten().map(|i| i.to_string()));
                            }
                            State::Gone => {
                                m.last_src.remove(&key);
                            }
                            State::Ok => {
                                let old = m.last_src.insert(key, ips.clone()).unwrap_or_default();
                                let mut gone = old.iter().filter(|o| !ips.contains(o));
                                for new in ips.iter().filter(|n| !old.contains(n)) {
                                    if let Some(o) = gone.next() {
                                        prev.insert(new.to_string(), o.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
                let finger = format!("{}|{determinate}", want.iter().cloned().collect::<Vec<_>>().join(","));
                for name in &c.records {
                    let key = format!("{rtype}|{name}");
                    let fresh = self
                        .mem
                        .lock()
                        .unwrap()
                        .last
                        .get(&key)
                        .map(|(p, at, pending)| *p == finger && !pending && at.elapsed() < c.force)
                        .unwrap_or(false);
                    if !force && fresh {
                        results.extend(
                            want.iter().map(
                                |ip| json!({ "name": name, "type": rtype, "content": ip, "ip": ip, "ok": true, "action": "unchanged" }),
                            ),
                        );
                        continue;
                    }
                    match self.reconcile(name, rtype, &want, determinate, &prev).await {
                        Ok((r, pending)) => {
                            self.mem.lock().unwrap().last.insert(key, (finger.clone(), Instant::now(), pending));
                            results.extend(r);
                        }
                        Err(e) => {
                            warn!("DDNS {name} {rtype}：{e:#}");
                            self.mem.lock().unwrap().last.remove(&key);
                            let ip = want.iter().next().cloned();
                            results.push(
                                json!({ "name": name, "type": rtype, "content": ip, "ip": ip, "ok": false, "action": "error", "error": e.to_string() }),
                            );
                        }
                    }
                }
            }
            // HTTPS 記錄：一天確認一次
            if let Some(domain) = &c.https_record {
                let (name, target, value) = https_record(domain, c.https_ports.0, c.https_ports.1);
                let key = format!("HTTPS|{name}|{value}");
                let fresh = self
                    .mem
                    .lock()
                    .unwrap()
                    .last
                    .get(&key)
                    .map(|(_, at, _)| at.elapsed() < Duration::from_secs(86400))
                    .unwrap_or(false);
                if force || !fresh {
                    let body =
                        json!({ "type": "HTTPS", "name": name, "ttl": 300, "data": { "priority": 1, "target": target, "value": value } });
                    // Cloudflare 可能把參數整理成別的寫法（加引號、空白）：去掉引號與空白再比
                    let norm = |v: &str| v.chars().filter(|c| *c != '"' && !c.is_whitespace()).collect::<String>();
                    match self
                        .upsert(&name, "HTTPS", body, |r| {
                            r["data"]["value"].as_str().map(norm) == Some(norm(&value))
                                && r["data"]["target"].as_str().map(|t| t.trim_end_matches('.')) == Some(target.trim_end_matches('.'))
                        })
                        .await
                    {
                        Ok((action, _)) => {
                            self.mem.lock().unwrap().last.insert(key, (String::new(), Instant::now(), false));
                            results.push(json!({ "name": name, "type": "HTTPS", "ok": true, "action": action }));
                        }
                        Err(e) => {
                            results.push(json!({ "name": name, "type": "HTTPS", "ok": false, "action": "error", "error": e.to_string() }))
                        }
                    }
                }
            }
            st["sources"] = Value::Array(sources);
            st["records"] = Value::Array(results);
        }
        *self.status.lock().unwrap() = st.clone();
        st
    }

    pub fn spawn(self: &Arc<Self>) {
        let me = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            loop {
                // Cloudflare API 與 web 偵測都是 TLS：系統時間對時之後才做（不記成失敗）
                crate::clock::wait_synced().await;
                me.update(false).await;
                tokio::time::sleep(me.cfg.interval).await;
            }
        });
    }
}

#[cfg(test)]
mod https_record_tests {
    use super::*;

    #[test]
    fn port_443_and_others() {
        assert_eq!(
            https_record("dns.example.net", 443, 443),
            ("dns.example.net".into(), ".".into(), "alpn=\"h3,h2\"".into())
        );
        // DoH 在 8443（443 被占用）：瀏覽器查 _8443._https，target 是網域本身
        assert_eq!(
            https_record("dns.example.net", 8443, 8443),
            (
                "_8443._https.dns.example.net".into(),
                "dns.example.net.".into(),
                "alpn=\"h3,h2\" port=8443".into()
            )
        );
        // DoH3 另外用 UDP 8444：只宣告 h3
        assert_eq!(
            https_record("dns.example.net", 443, 8444).2,
            "alpn=\"h3\" no-default-alpn port=8444"
        );
    }

    #[test]
    fn ports_from_config() {
        let c = |over: Value| {
            let mut cfg = kuroshio_config::build(&json!({ "domain": "dns.example.net", "ddns": { "enabled": true } }));
            kuroshio_config::merge(&mut cfg, &over);
            Config::from_cfg(&cfg).unwrap().https_ports
        };
        // 自己做 TLS（明確給了憑證）、聽 8443：外面也是 8443，DoH3 預設同一個埠號
        let tls = json!({ "listen": { "doh": { "enabled": true, "host": "0.0.0.0", "port": 8443, "tls": true, "http3": true } } });
        assert_eq!(c(tls.clone()), (8443, 8443));
        let mut sep = tls.clone();
        sep["listen"]["doh"]["http3Port"] = json!(8444);
        assert_eq!(c(sep), (8443, 8444));
        // 路由器把 WAN 443 轉到本機 8443
        let mut fwd = tls;
        fwd["listen"]["doh"]["publicPort"] = json!(443);
        assert_eq!(c(fwd), (443, 443));
        // 反向代理在前面（DoH 本身是明文）：外面是 443
        assert_eq!(
            c(json!({ "listen": { "doh": { "enabled": true, "host": "127.0.0.1", "port": 8053, "tls": false, "http3": true } } })),
            (443, 443)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interfaces_and_legacy_fields() {
        let c = |v: Value| interfaces_from_cfg(&kuroshio_config::with_overrides(&json!({ "ddns": v })));
        assert!(c(json!({})).is_empty(), "預設：系統預設路由");
        assert_eq!(
            c(json!({ "interfaces": ["pppoe-wan", " wanb ", "pppoe-wan", ""] })),
            vec![IfaceSel::both("pppoe-wan"), IfaceSel::both("wanb")]
        );
        // 舊欄位：只有「讀網卡」模式用到；iface6 沒填時 IPv6 也讀 iface4
        assert_eq!(
            c(json!({ "ipSource": "interface", "iface4": "eth1" })),
            vec![IfaceSel::both("eth1")]
        );
        assert_eq!(
            c(json!({ "ipSource": "interface", "iface4": "eth1", "iface6": "eth2" })),
            vec![
                IfaceSel {
                    name: "eth1".into(),
                    v4: true,
                    v6: false
                },
                IfaceSel {
                    name: "eth2".into(),
                    v4: false,
                    v6: true
                }
            ]
        );
        assert!(
            c(json!({ "ipSource": "web", "iface4": "eth1" })).is_empty(),
            "web 模式以前不看 iface4：行為不變"
        );
        assert_eq!(
            c(json!({ "ipSource": "interface", "iface4": "eth1", "interfaces": ["wan"] })),
            vec![IfaceSel::both("wan")],
            "有寫 interfaces 就以它為準"
        );
    }

    #[test]
    fn defaults_publish_ipv4_only() {
        let c = Config::from_cfg(&kuroshio_config::with_overrides(
            &json!({ "domain": "dns.example.com", "ddns": { "enabled": true, "apiToken": "x" } }),
        ))
        .unwrap();
        assert!(c.ipv4 && !c.ipv6, "IPv6 預設不發布");
        assert_eq!(c.records, vec!["dns.example.com"], "只填綁定網域：更新它");
        assert!(c.interfaces.is_empty());
        assert_eq!(c.gone_runs, GONE_RUNS);
    }
}
