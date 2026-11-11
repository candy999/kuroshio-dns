//! DDNS（對齊 2.x 的 lib/ddns.js）：公網 IP 變了就用 Cloudflare API 更新 DNS 記錄
//!
//! - IP 來源：`web` = 問 Cloudflare 的 /cdn-cgi/trace（用 IP 位址連線，分得出 IPv4 / IPv6）；`interface` = 讀本機網卡
//! - 只在 IP 變了、或距上次確認超過 forceHours 才呼叫 API（Cloudflare API 有頻率限制）
//! - 記錄不存在就建立
//! - 選用：發布網域的 HTTPS 記錄（`alpn="h3,h2"`），讓瀏覽器第一次連線就用 HTTP/3（規格 07 第 2.3 節）

use crate::cloudflare::Cloudflare;
use anyhow::{anyhow, bail, Result};
use kuroshio_net::fetch::{request, Request};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{info, warn};

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
    pub iface4: String,
    pub iface6: String,
    pub url4: String,
    pub url6: String,
    pub api: String,
    /// 發布 HTTPS 記錄（alpn h3,h2）的網域；空白 = 不發布
    pub https_record: Option<String>,
}

impl Config {
    pub fn from_cfg(cfg: &Value) -> Option<Config> {
        let g = |k: &str| kuroshio_config::get(cfg, &format!("ddns.{k}"));
        if !g("enabled").and_then(Value::as_bool).unwrap_or(false) {
            return None;
        }
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
                .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
                .unwrap_or_default(),
            zone: s("zone", ""),
            ipv4: b("ipv4", true),
            ipv6: b("ipv6", false),
            proxied: b("proxied", false),
            ttl: n("ttl", 1),
            interval: Duration::from_secs(n("intervalMin", 5).max(1) * 60),
            force: Duration::from_secs(n("forceHours", 24) * 3600),
            ip_source: s("ipSource", "web"),
            iface4: s("iface4", ""),
            iface6: s("iface6", ""),
            url4: s("url4", "https://1.1.1.1/cdn-cgi/trace"),
            url6: s("url6", "https://[2606:4700:4700::1111]/cdn-cgi/trace"),
            api: s("api", "https://api.cloudflare.com/client/v4"),
            https_record: (b("httpsRecord", true) && h3 && !domain.is_empty()).then_some(domain),
        })
    }
}

pub struct Ddns {
    pub cfg: Config,
    cf: Cloudflare,
    last: Mutex<HashMap<String, (String, Instant)>>,
    status: Mutex<Value>,
}

/// 是不是公網位址（私有、迴路、鏈路本地、CGNAT 都不算）
fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            !(v.is_private() || v.is_loopback() || v.is_link_local() || v.is_unspecified() || (o[0] == 100 && (64..128).contains(&o[1])))
        }
        IpAddr::V6(v) => {
            let s = v.segments()[0];
            !(v.is_loopback() || v.is_unspecified() || (s & 0xffc0) == 0xfe80 || (s & 0xfe00) == 0xfc00)
        }
    }
}

/// 讀網卡的公網位址（Linux：IPv6 讀 /proc/net/if_inet6，IPv4 用 `ip` 指令）
fn iface_ip(iface: &str, v6: bool) -> Option<IpAddr> {
    if v6 {
        let t = std::fs::read_to_string("/proc/net/if_inet6").ok()?;
        return t
            .lines()
            .filter_map(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                if f.len() < 6 || f[5] != iface {
                    return None;
                }
                let hex = f[0];
                let segs: Vec<u16> = (0..8)
                    .filter_map(|i| u16::from_str_radix(&hex[i * 4..i * 4 + 4], 16).ok())
                    .collect();
                (segs.len() == 8).then(|| {
                    IpAddr::V6(std::net::Ipv6Addr::new(
                        segs[0], segs[1], segs[2], segs[3], segs[4], segs[5], segs[6], segs[7],
                    ))
                })
            })
            .find(|ip| is_public(*ip));
    }
    let out = std::process::Command::new("ip")
        .args(["-4", "-o", "addr", "show", "dev", iface])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .filter_map(|w| w.split('/').next()?.parse::<IpAddr>().ok())
        .find(|ip| is_public(*ip))
}

impl Ddns {
    pub fn new(cfg: Config) -> Arc<Ddns> {
        Arc::new(Ddns {
            cf: Cloudflare::new(&cfg.api, &cfg.api_token, &cfg.zone),
            cfg,
            last: Mutex::new(HashMap::new()),
            status: Mutex::new(json!({ "enabled": true })),
        })
    }

    pub fn status(&self) -> Value {
        self.status.lock().unwrap().clone()
    }

    async fn current_ip(&self, v6: bool) -> Result<Option<IpAddr>> {
        if self.cfg.ip_source == "interface" {
            let iface = if v6 && !self.cfg.iface6.is_empty() {
                &self.cfg.iface6
            } else {
                &self.cfg.iface4
            };
            if iface.is_empty() {
                bail!("IP 來源設為網卡，但沒有指定 IPv{} 網卡", if v6 { 6 } else { 4 });
            }
            return Ok(iface_ip(iface, v6));
        }
        let url = if v6 { &self.cfg.url6 } else { &self.cfg.url4 };
        let (status, body) = request(
            url,
            &Request {
                method: "GET",
                ..Default::default()
            },
            65536,
            Duration::from_secs(8),
        )
        .await?;
        if status != 200 {
            bail!("{url} HTTP {status}");
        }
        let ip = String::from_utf8_lossy(&body)
            .lines()
            .find_map(|l| l.strip_prefix("ip="))
            .and_then(|v| v.trim().parse::<IpAddr>().ok());
        Ok(ip.filter(|ip| ip.is_ipv6() == v6))
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

    /// 立即檢查並更新；force = 不管 IP 有沒有變都呼叫 API 確認
    pub async fn update(&self, force: bool) -> Value {
        let c = &self.cfg;
        let mut st =
            json!({ "enabled": true, "lastRun": kuroshio_net::fetch::now_ms(), "ip4": null, "ip6": null, "records": [], "error": null });
        if c.api_token.is_empty() {
            st["error"] = json!("沒有設定 Cloudflare API Token");
        } else if c.records.is_empty() {
            st["error"] = json!("沒有設定要更新的記錄");
        } else {
            let mut results = Vec::new();
            for v6 in [false, true] {
                if (!v6 && !c.ipv4) || (v6 && !c.ipv6) {
                    continue;
                }
                let rtype = if v6 { "AAAA" } else { "A" };
                let ip = match self.current_ip(v6).await {
                    Ok(ip) => ip,
                    Err(e) => {
                        st["error"] = json!(e.to_string());
                        None
                    }
                };
                st[if v6 { "ip6" } else { "ip4" }] = json!(ip.map(|i| i.to_string()));
                let Some(ip) = ip.map(|i| i.to_string()) else {
                    for name in &c.records {
                        results.push(json!({ "name": name, "type": rtype, "ok": false, "action": "skip", "error": format!("取不到公網 IPv{}", if v6 { 6 } else { 4 }) }));
                    }
                    continue;
                };
                for name in &c.records {
                    let key = format!("{rtype}|{name}");
                    let fresh = self
                        .last
                        .lock()
                        .unwrap()
                        .get(&key)
                        .map(|(p, at)| *p == ip && at.elapsed() < c.force)
                        .unwrap_or(false);
                    if !force && fresh {
                        results.push(json!({ "name": name, "type": rtype, "ip": ip, "ok": true, "action": "unchanged" }));
                        continue;
                    }
                    let body = json!({ "type": rtype, "name": name, "content": ip, "ttl": c.ttl, "proxied": c.proxied });
                    let (proxied, ttl) = (c.proxied, c.ttl);
                    let ip2 = ip.clone();
                    match self
                        .upsert(name, rtype, body, move |r| {
                            r["content"] == json!(ip2)
                                && r["proxied"].as_bool().unwrap_or(false) == proxied
                                && r["ttl"].as_u64() == Some(ttl)
                        })
                        .await
                    {
                        Ok((action, previous)) => {
                            self.last.lock().unwrap().insert(key, (ip.clone(), Instant::now()));
                            if action != "unchanged" {
                                info!(
                                    "DDNS {name} {rtype} → {ip}（{}）",
                                    if action == "created" { "建立" } else { "更新" }
                                );
                            }
                            results
                                .push(json!({ "name": name, "type": rtype, "ip": ip, "ok": true, "action": action, "previous": previous }));
                        }
                        Err(e) => {
                            warn!("DDNS {name} {rtype}：{e:#}");
                            results.push(
                                json!({ "name": name, "type": rtype, "ip": ip, "ok": false, "action": "error", "error": e.to_string() }),
                            );
                        }
                    }
                }
            }
            // HTTPS 記錄：一天確認一次
            if let Some(domain) = &c.https_record {
                let key = format!("HTTPS|{domain}");
                let fresh = self
                    .last
                    .lock()
                    .unwrap()
                    .get(&key)
                    .map(|(_, at)| at.elapsed() < Duration::from_secs(86400))
                    .unwrap_or(false);
                if force || !fresh {
                    let value = "alpn=\"h3,h2\"";
                    let body =
                        json!({ "type": "HTTPS", "name": domain, "ttl": 300, "data": { "priority": 1, "target": ".", "value": value } });
                    match self
                        .upsert(domain, "HTTPS", body, |r| {
                            r["data"]["value"].as_str().map(|v| v.contains("h3")).unwrap_or(false)
                        })
                        .await
                    {
                        Ok((action, _)) => {
                            self.last.lock().unwrap().insert(key, (String::new(), Instant::now()));
                            results.push(json!({ "name": domain, "type": "HTTPS", "ok": true, "action": action }));
                        }
                        Err(e) => {
                            results.push(json!({ "name": domain, "type": "HTTPS", "ok": false, "action": "error", "error": e.to_string() }))
                        }
                    }
                }
            }
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
                me.update(false).await;
                tokio::time::sleep(me.cfg.interval).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_ips() {
        assert!(is_public("1.2.3.4".parse().unwrap()));
        assert!(!is_public("192.168.1.1".parse().unwrap()));
        assert!(!is_public("100.64.1.1".parse().unwrap()), "CGNAT");
        assert!(is_public("2001:db8::1".parse().unwrap()));
        assert!(!is_public("fd00::1".parse().unwrap()));
        assert!(!is_public("fe80::1".parse().unwrap()));
    }
}
