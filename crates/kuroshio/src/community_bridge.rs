//! 社群共享 ↔ CDN 台灣節點、上游（規格 03 第 5 節，對齊 2.x `community/share.js` 的 buildBundle）
//!
//! - 分享（`DataProvider::local_records`）：台灣節點池（排除壞節點與種子資料）、v6 節點、
//!   網站驗證結果（OK 的，只分享網域雜湊）、跨 CDN 結果、每日評測選出的上游
//! - 收到的資料一律只是候選：網站與跨 CDN 提示經 `kuroshio_cdn::Hints` 交給 CDN，CDN 在本機驗證後回報命中率

use kuroshio_cdn::{Cdn, CrossHint as CdnCross, HintIp, Hints};
use kuroshio_community::provider::{DataProvider, LocalRecord, RangeCheck};
use kuroshio_community::score::{Kind, Outcome};
use kuroshio_community::Community;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock, Weak};

/// 每類最多分享幾筆（同 2.x LIMITS）
const MAX_NODES: usize = 400;
const MAX_V6: usize = 2000;
const MAX_SITES: usize = 20000;
const MAX_CROSS: usize = 5000;
const IPS_PER_ITEM: usize = 4;
/// 只分享最近 30 天內驗證過的
const SINCE_MS: u64 = 30 * 86400 * 1000;

pub struct CdnData {
    pub cdn: Option<Arc<Cdn>>,
    pub upstreams: Option<Arc<crate::upstreams::Manager>>,
    /// 自己網域的上層網域（[`kuroshio_config::own_base_domains`]）：這底下的網站、跨 CDN 結果不分享給好友
    pub own_bases: Vec<String>,
}

/// 拿掉自己網域底下的網站與跨 CDN 記錄（即使只分享雜湊，也不讓好友能比對出自己的子網域）
fn drop_own(out: &mut Vec<LocalRecord>, own_bases: &[String]) {
    if own_bases.is_empty() {
        return;
    }
    out.retain(|r| match r {
        LocalRecord::Site { name, .. } | LocalRecord::Cross { name, .. } => !kuroshio_config::is_own_domain(name, own_bases),
        _ => true,
    });
}

fn now_ms() -> u64 {
    kuroshio_net::fetch::now_ms()
}

impl DataProvider for CdnData {
    fn local_records(&self) -> Vec<LocalRecord> {
        let mut out = Vec::new();
        let now = now_ms();
        if let Some(cdn) = &self.cdn {
            cdn.with_state(|st| {
                let (mut n4, mut n6) = (0, 0);
                for (p, d) in st.pools.p.iter() {
                    for (list, v6) in [(&d.pool4, false), (&d.pool6, true)] {
                        for x in list.iter() {
                            let pop = x.pop.as_deref().unwrap_or("");
                            if d.bad.contains_key(&x.ip) || pop.is_empty() || pop == "seed" {
                                continue;
                            }
                            let n = if v6 { &mut n6 } else { &mut n4 };
                            if *n >= if v6 { MAX_V6 } else { MAX_NODES } {
                                continue;
                            }
                            *n += 1;
                            out.push(LocalRecord::Node {
                                p: p.to_string(),
                                ip: x.ip,
                                pop: pop.to_string(),
                                ms: x.ms.get().map(|m| m.round().max(0.0) as u32),
                                obs: now,
                                permanent: v6,
                            });
                        }
                    }
                }
                let (mut sites, mut cross) = (0, 0);
                for e in st.db.domains.values() {
                    let Some(p) = e.provider.val() else { continue };
                    if kuroshio_config::is_own_domain(&e.name, &self.own_bases) {
                        continue;
                    }
                    for (fam, v) in [(4u8, &e.v4), (6u8, &e.v6)] {
                        let Some(v) = v else { continue };
                        let at = v.at.unwrap_or(0);
                        if sites >= MAX_SITES || v.verdict.as_deref() != Some("ok") || now.saturating_sub(at) > SINCE_MS {
                            continue;
                        }
                        let ips: Vec<IpAddr> = v
                            .ips
                            .clone()
                            .unwrap_or_default()
                            .into_iter()
                            .chain(v.ip)
                            .take(IPS_PER_ITEM)
                            .collect();
                        if ips.is_empty() {
                            continue;
                        }
                        sites += 1;
                        out.push(LocalRecord::Site {
                            name: e.name.to_string(),
                            p: p.to_string(),
                            fam,
                            ips,
                            pop: v.pop.as_deref().unwrap_or("").to_string(),
                            obs: at,
                        });
                    }
                    if let Some(c) = &e.cross4 {
                        let at = c.at.unwrap_or(0);
                        let ips: Vec<IpAddr> = c.ips.clone().unwrap_or_default().into_iter().take(IPS_PER_ITEM).collect();
                        if cross < MAX_CROSS && c.verdict.as_deref() == Some("ok") && now.saturating_sub(at) <= SINCE_MS && !ips.is_empty()
                        {
                            cross += 1;
                            out.push(LocalRecord::Cross {
                                name: e.name.to_string(),
                                from: c.from.as_deref().unwrap_or(p).to_string(),
                                to: c.to.as_deref().unwrap_or("").to_string(),
                                ips,
                                obs: at,
                            });
                        }
                    }
                }
            });
        }
        if let Some(m) = &self.upstreams {
            for u in m.auto_shared() {
                out.push(LocalRecord::Upstream {
                    url: u.0,
                    proto: u.1,
                    ms: u.2,
                    ok: u.3,
                    obs: now,
                });
            }
        }
        drop_own(&mut out, &self.own_bases);
        out
    }

    fn in_range(&self, provider: &str, ip: IpAddr) -> RangeCheck {
        let Some(cdn) = &self.cdn else { return RangeCheck::UnknownProvider };
        if kuroshio_cdn::providers::get(provider).is_none() {
            return RangeCheck::UnknownProvider;
        }
        match cdn.classify(ip) {
            Some(c) if c.provider == provider => RangeCheck::InRange,
            _ => RangeCheck::OutOfRange,
        }
    }
}

/// 好友的網站 / 跨 CDN 提示交給 CDN（CDN 驗證後用 hint_result 回報）
pub struct CommunityHints(pub Weak<Community>);

impl Hints for CommunityHints {
    fn domain_hint(&self, name: &str, provider: &str, family: u8) -> Vec<HintIp> {
        let Some(c) = self.0.upgrade() else { return vec![] };
        c.site_hints(name, provider, family)
            .into_iter()
            .map(|h| HintIp {
                ip: h.ip,
                from: h.from.join(","),
            })
            .collect()
    }

    fn hint_result(&self, from: &str, ok: bool) {
        let Some(c) = self.0.upgrade() else { return };
        let froms: Vec<String> = from.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect();
        c.report(&froms, Kind::Site, if ok { Outcome::Ok } else { Outcome::Fail });
    }

    fn cross_hint(&self, name: &str) -> Option<CdnCross> {
        let c = self.0.upgrade()?;
        let (to, hints) = c.cross_hint(name)?;
        Some(CdnCross {
            to,
            ips: hints
                .into_iter()
                .map(|h| HintIp {
                    ip: h.ip,
                    from: h.from.join(","),
                })
                .collect(),
        })
    }
}

/// 加密監聽上的社群入口（DoH `/.well-known/kuroshio/v2/*`、DoT / DoQ 的 ALPN `kuroshio/2`）
#[derive(Default)]
pub struct Slot(OnceLock<Arc<Community>>);

impl Slot {
    pub fn set(&self, c: Arc<Community>) {
        let _ = self.0.set(c);
    }
    pub fn get(&self) -> Option<&Arc<Community>> {
        self.0.get()
    }
}

/// 好友的網域與最近一次連線的來源 IP（`peers_json` 裡 rel = friend 的）
pub fn friend_targets(peers: &serde_json::Value) -> (Vec<String>, Vec<IpAddr>) {
    let (mut domains, mut ips) = (Vec::new(), Vec::new());
    for p in peers.as_array().into_iter().flatten() {
        if p.get("rel").and_then(serde_json::Value::as_str) != Some("friend") {
            continue;
        }
        if let Some(d) = p.get("domain").and_then(serde_json::Value::as_str) {
            domains.push(d.to_string());
        }
        if let Some(ip) = p
            .pointer("/info/ip")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| s.parse().ok())
        {
            ips.push(ip);
        }
    }
    (domains, ips)
}

/// 存取控制（規格 08）：好友目前的 IP 永遠允許。每 10 分鐘解析一次好友網域（A / AAAA）
pub fn spawn_friend_ips(node: Weak<Community>, access: Arc<crate::ipfilter::Access>) {
    tokio::spawn(async move {
        loop {
            let Some(n) = node.upgrade() else { return };
            let (domains, mut ips) = friend_targets(&n.peers_json());
            drop(n);
            for d in domains {
                let look = tokio::net::lookup_host((d.as_str(), 443));
                if let Ok(Ok(addrs)) = tokio::time::timeout(std::time::Duration::from_secs(5), look).await {
                    ips.extend(addrs.map(|a| a.ip()));
                }
            }
            ips.sort();
            ips.dedup();
            access.set_friends(&ips);
            tokio::time::sleep(std::time::Duration::from_secs(600)).await;
        }
    });
}

#[cfg(test)]
mod own_domain_tests {
    use super::*;

    #[test]
    fn own_domains_are_not_shared() {
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        let site = |name: &str| LocalRecord::Site {
            name: name.into(),
            p: "cloudflare".into(),
            fam: 4,
            ips: vec![ip],
            pop: "TPE".into(),
            obs: 1,
        };
        let cross = |name: &str| LocalRecord::Cross {
            name: name.into(),
            from: "cloudflare".into(),
            to: "akamai".into(),
            ips: vec![ip],
            obs: 1,
        };
        let mut out = vec![
            site("time.example.net"),
            site("next.example.net"),
            site("example.net"),
            site("www.example.com"),
            cross("cdn.example.net"),
            cross("img.example.com"),
            LocalRecord::Node {
                p: "cloudflare".into(),
                ip,
                pop: "TPE".into(),
                ms: Some(3),
                obs: 1,
                permanent: false,
            },
        ];
        let cfg = kuroshio_config::build(&serde_json::json!({ "domain": "dns.example.net" }));
        let bases = kuroshio_config::own_base_domains(&cfg);
        drop_own(&mut out, &bases);
        let names: Vec<&str> = out
            .iter()
            .filter_map(|r| match r {
                LocalRecord::Site { name, .. } | LocalRecord::Cross { name, .. } => Some(name.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(names, vec!["www.example.com", "img.example.com"], "自己網域底下的不分享");
        assert_eq!(out.len(), 3, "節點照樣分享");
        // 沒有綁定網域：全部照舊
        let mut all = vec![site("time.example.net")];
        drop_own(
            &mut all,
            &kuroshio_config::own_base_domains(&kuroshio_config::build(&serde_json::json!({}))),
        );
        assert_eq!(all.len(), 1);
    }
}

#[cfg(test)]
mod access_tests {
    use super::friend_targets;
    use serde_json::json;

    #[test]
    fn only_friends_are_listed() {
        let peers = json!([
            { "domain": "a.example.com", "rel": "friend", "info": { "ip": "203.0.113.5" } },
            { "domain": "b.example.com", "rel": "in", "info": { "ip": "198.51.100.1" } },
            { "domain": "c.example.net", "rel": "friend", "info": {} }
        ]);
        let (d, ips) = friend_targets(&peers);
        assert_eq!(d, vec!["a.example.com", "c.example.net"]);
        assert_eq!(ips, vec!["203.0.113.5".parse::<std::net::IpAddr>().unwrap()]);
    }
}
