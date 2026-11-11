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
