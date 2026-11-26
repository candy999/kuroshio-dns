//! 社群共享 ↔ CDN 台灣節點、上游（規格 03 第 5 節，對齊 2.x `community/share.js` 的 buildBundle）
//!
//! - 分享（`DataProvider::local_records`）：台灣節點池（排除壞節點與種子資料）、v6 節點、
//!   網站驗證結果（OK 的，只分享網域雜湊）、跨 CDN 結果、每日評測選出的上游
//! - 收到的資料一律只是候選：網站與跨 CDN 提示經 `kuroshio_cdn::Hints` 交給 CDN，CDN 在本機驗證後回報命中率；
//!   台灣節點放進節點池工作的候選名單（`DataProvider::on_received`），量測過才使用

use kuroshio_cdn::{Cdn, CrossHint as CdnCross, HintIp, HintKind, Hints};
use kuroshio_community::provider::{DataProvider, LocalRecord, RangeCheck, Received};
use kuroshio_community::score::{Kind, Outcome};
use kuroshio_community::Community;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock, Weak};

/// 每類最多分享幾筆（同 2.x LIMITS）
const MAX_NODES: usize = 400;
const MAX_V6: usize = 2000;
const MAX_SITES: usize = 20000;
const MAX_CROSS: usize = 5000;
const IPS_PER_ITEM: usize = 4;
/// 只分享最近 30 天內驗證過的
const SINCE_MS: u64 = 30 * 86400 * 1000;
/// 網站、跨 CDN 結果只分享被查過幾次以上的網域（3.5.1）：一次性網域（壓測、外部探測的隨機子網域）不分享
const MIN_HITS: u32 = 2;

/// 分享過哪些網域的網站、跨 CDN 記錄（3.5.1）：名稱雜湊（[`kuroshio_cdn::db::name_hash`]）→（網站雜湊, 分享了哪些：
/// [`SHARED_V4`]、[`SHARED_V6`]、[`SHARED_CROSS`]）。只用來認出「這次沒有、是因為移出記憶體」的網域，
/// 每筆 20 位元組左右，筆數不超過分享的上限（[`MAX_SITES`] + [`MAX_CROSS`]）
pub type SharedMemo = HashMap<u32, ([u8; 12], u8)>;
const SHARED_V4: u8 = 1;
const SHARED_V6: u8 = 2;
const SHARED_CROSS: u8 = 4;

pub struct CdnData {
    pub cdn: Option<Arc<Cdn>>,
    pub upstreams: Option<Arc<crate::upstreams::Manager>>,
    /// 自己網域的上層網域（[`kuroshio_config::own_base_domains`]）：這底下的網站、跨 CDN 結果不分享給好友
    pub own_bases: Vec<String>,
    /// 上一次分享的網域（[`SharedMemo`]）
    pub shared: Mutex<SharedMemo>,
    /// 這一次「還存在、只是不在記憶體裡」的記錄（[`DataProvider::kept_keys`]）
    pub kept: Mutex<Vec<(String, String)>>,
}

impl CdnData {
    pub fn new(cdn: Option<Arc<Cdn>>, upstreams: Option<Arc<crate::upstreams::Manager>>, own_bases: Vec<String>) -> CdnData {
        CdnData {
            cdn,
            upstreams,
            own_bases,
            shared: Mutex::new(HashMap::new()),
            kept: Mutex::new(Vec::new()),
        }
    }
}

/// 從 CDN 資料庫挑要分享的網站與跨 CDN 記錄（加到 `out`），回傳（這次分享的網域, 還存在但不在記憶體裡的記錄鍵）。
///
/// - 只分享被查過 [`MIN_HITS`] 次以上、有學習資料（驗證、跨 CDN 結果）的網域：一次性網域不分享
/// - `prev`（上一次分享的）裡這次沒有的網域：如果只是被記憶體控制移出記憶體（[`kuroshio_cdn::db::Db::is_evicted_hash`]），
///   回傳它的鍵，分享集合照樣保留（到期為止）、不發刪除標記；真的不在了（刪掉、驗證不再通過）才刪。
///   以前直接從記憶體裡的資料取，移出記憶體就當成刪除：壓測時分享集合被換成壓測網域，已經同步給好友
pub fn share_domains(
    db: &kuroshio_cdn::db::Db,
    own_bases: &[String],
    now: u64,
    prev: &SharedMemo,
    out: &mut Vec<LocalRecord>,
) -> (SharedMemo, Vec<(String, String)>) {
    use kuroshio_community::share::{cross_key, site_key};
    let mut memo: SharedMemo = HashMap::new();
    let (mut sites, mut cross) = (0, 0);
    for e in db.domains.values() {
        let Some(p) = e.provider.val() else { continue };
        if e.hits < MIN_HITS || !kuroshio_cdn::db::has_learning(e) || kuroshio_config::is_own_domain(&e.name, own_bases) {
            continue;
        }
        let mut bits = 0u8;
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
            bits |= if fam == 4 { SHARED_V4 } else { SHARED_V6 };
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
            if cross < MAX_CROSS && c.verdict.as_deref() == Some("ok") && now.saturating_sub(at) <= SINCE_MS && !ips.is_empty() {
                cross += 1;
                bits |= SHARED_CROSS;
                out.push(LocalRecord::Cross {
                    name: e.name.to_string(),
                    from: c.from.as_deref().unwrap_or(p).to_string(),
                    to: c.to.as_deref().unwrap_or("").to_string(),
                    ips,
                    obs: at,
                });
            }
        }
        if bits != 0 {
            memo.insert(
                kuroshio_cdn::db::name_hash(&e.name),
                (kuroshio_community::util::site_hash(&e.name), bits),
            );
        }
    }
    // 上一次分享、這次沒有的：只是移出記憶體的照樣保留（記號也留著，讀回來或真的不在了再說）
    let mut kept = Vec::new();
    if db.evicted_count() > 0 {
        for (nh, (h, bits)) in prev {
            if memo.contains_key(nh) || !db.is_evicted_hash(*nh) {
                continue;
            }
            for (bit, fam) in [(SHARED_V4, 4u8), (SHARED_V6, 6)] {
                if bits & bit != 0 {
                    kept.push(("site".to_string(), site_key(h, fam)));
                }
            }
            if bits & SHARED_CROSS != 0 {
                kept.push(("cross".to_string(), cross_key(h)));
            }
            memo.insert(*nh, (*h, *bits));
        }
    }
    (memo, kept)
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
                let mut memo = self.shared.lock().unwrap();
                let (next, kept) = share_domains(&st.db, &self.own_bases, now, &memo, &mut out);
                *memo = next;
                *self.kept.lock().unwrap() = kept;
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

    fn kept_keys(&self) -> Vec<(String, String)> {
        std::mem::take(&mut *self.kept.lock().unwrap())
    }

    /// 好友給的資料：網站與跨 CDN 提示等有人查到時才經 [`CommunityHints`] 拿；台灣節點在這裡放進
    /// 節點池工作的候選名單（同分享檔的節點：只收官方範圍內的，每日節點池工作量測過才使用）
    fn on_received(&self, batch: &Received) {
        let Some(cdn) = &self.cdn else { return };
        if batch.nodes.is_empty() {
            return;
        }
        // 3.5.0 E10：確定是別的 ISP 群組的好友，這一批每家每個家族的上限降成四分之一（500 → 125）；
        // 同群組與「不知道」（舊版好友、沒開分享的好友、這台自己偵測不到）照舊。只會變少，候選名單總上限不變
        let cap = friend_node_cap(crate::observe::isp_group().as_deref(), batch.ctx.isp.as_deref());
        let n = cdn.add_friend_nodes_capped(batch.nodes.iter().map(|x| (x.p.as_str(), x.ip)), cap);
        if n > 0 {
            tracing::debug!("社群：{} 給的台灣節點 {n} 個放進候選名單（每日節點池工作量測後才使用）", batch.from);
        }
    }

    /// 這台 WAN 的 ISP 群組（3.5.0 E10）；要不要送由社群那邊看 `community.shareIspGroup`
    fn isp_group(&self) -> Option<String> {
        crate::observe::isp_group()
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

/// 好友節點候選的每批上限（3.5.0 E10）：雙方的群組都知道、而且不一樣才降成四分之一
pub fn friend_node_cap(mine: Option<&str>, theirs: Option<&str>) -> usize {
    match (mine, theirs) {
        (Some(a), Some(b)) if a != b => kuroshio_cdn::cdn::FRIEND_MAX_NODES / 4,
        _ => kuroshio_cdn::cdn::FRIEND_MAX_NODES,
    }
}

/// CDN 回報的提示種類 → 好友資料品質分數的種類（網站、跨 CDN 分開算，各自暫停）
fn score_kind(k: HintKind) -> Kind {
    match k {
        HintKind::Site => Kind::Site,
        HintKind::Cross => Kind::Cross,
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

    fn hint_result(&self, from: &str, kind: HintKind, ok: bool) {
        let Some(c) = self.0.upgrade() else { return };
        let froms: Vec<String> = from.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect();
        c.report(&froms, score_kind(kind), if ok { Outcome::Ok } else { Outcome::Fail });
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

/// 每個好友網域解析到的位址最多允許幾個（IPv4、IPv6 合計）
pub const FRIEND_IPS_PER_DOMAIN: usize = 4;

/// 好友網域解析到的位址：去掉重複後 IPv4、IPv6 交錯取，最多 [`FRIEND_IPS_PER_DOMAIN`] 個
/// （兩種位址都有機會；好友的網域是對方設定的，不能讓它把一大串位址塞進允許清單）
pub fn pick_friend_ips(addrs: impl IntoIterator<Item = IpAddr>) -> Vec<IpAddr> {
    let (mut v4, mut v6) = (Vec::new(), Vec::new());
    for ip in addrs {
        let l = if ip.is_ipv4() { &mut v4 } else { &mut v6 };
        if !l.contains(&ip) {
            l.push(ip);
        }
    }
    let mut out = Vec::with_capacity(FRIEND_IPS_PER_DOMAIN);
    let (mut a, mut b) = (v4.into_iter(), v6.into_iter());
    while out.len() < FRIEND_IPS_PER_DOMAIN {
        let (x, y) = (a.next(), b.next());
        if x.is_none() && y.is_none() {
            break;
        }
        out.extend(x);
        if out.len() < FRIEND_IPS_PER_DOMAIN {
            out.extend(y);
        }
    }
    out
}

/// 存取控制（規格 08）：好友目前的 IP 永遠允許。每 10 分鐘解析一次好友網域（A / AAAA），
/// 每個網域最多 [`FRIEND_IPS_PER_DOMAIN`] 個位址，再加上好友最近一次連線的來源 IP
pub fn spawn_friend_ips(node: Weak<Community>, access: Arc<crate::ipfilter::Access>) {
    tokio::spawn(async move {
        loop {
            let Some(n) = node.upgrade() else { return };
            let (domains, mut ips) = friend_targets(&n.peers_json());
            drop(n);
            for d in domains {
                let look = tokio::net::lookup_host((d.as_str(), 443));
                if let Ok(Ok(addrs)) = tokio::time::timeout(std::time::Duration::from_secs(5), look).await {
                    ips.extend(pick_friend_ips(addrs.map(|a| a.ip())));
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
    fn hint_kinds_are_scored_separately() {
        // 跨 CDN 提示的結果記在跨 CDN 的分數（以前一律記成網站，跨 CDN 提示再不準也不會暫停）
        assert_eq!(score_kind(HintKind::Site), Kind::Site);
        assert_eq!(score_kind(HintKind::Cross), Kind::Cross);
    }

    /// 3.5.1：只分享查過 2 次以上、有學習資料的網域；記憶體控制移出記憶體的不算刪除（分享集合照樣保留），
    /// 真的不在了才刪
    #[test]
    fn evicted_domains_are_kept_one_shot_not_shared() {
        use kuroshio_cdn::db::{Cross, Db, Verdict};
        use kuroshio_community::share::{to_wire, ShareSet};
        let now = 1_800_000_000_000u64;
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        let ok = || {
            Some(Box::new(Verdict {
                verdict: Some("ok".into()),
                at: Some(now - 1000),
                ips: Some(vec![ip]),
                ..Default::default()
            }))
        };
        let mut db = Db::new(1000);
        db.set_shards(1);
        for (name, hits, cold) in [
            ("www.example.com", 5u32, true),
            ("img.example.com", 3, false),
            ("p0abcdefgh.example.net", 1, false),
            ("p1abcdefgh.example.net", 1, true),
        ] {
            let d = db.touch(name, "cloudflare", "ip", &[ip], &[], None);
            d.hits = hits;
            d.v4 = ok();
            d.last_seen = if cold { now - 86_400_000 } else { now };
        }
        db.touch("cross.example.com", "cloudflare", "ip", &[ip], &[], None).hits = 4;
        db.domains.get_mut("cross.example.com").unwrap().cross4 = Some(Box::new(Cross {
            verdict: Some("ok".into()),
            to: Some("akamai".into()),
            at: Some(now - 1000),
            ips: Some(vec![ip]),
            ..Default::default()
        }));
        db.domains.get_mut("cross.example.com").unwrap().last_seen = now - 86_400_000;
        let names = |out: &[LocalRecord]| -> Vec<String> {
            let mut v: Vec<String> = out
                .iter()
                .filter_map(|r| match r {
                    LocalRecord::Site { name, .. } => Some(format!("site:{name}")),
                    LocalRecord::Cross { name, .. } => Some(format!("cross:{name}")),
                    _ => None,
                })
                .collect();
            v.sort();
            v
        };
        let mut out = Vec::new();
        let (memo, kept) = share_domains(&db, &[], now, &HashMap::new(), &mut out);
        assert_eq!(
            names(&out),
            ["cross:cross.example.com", "site:img.example.com", "site:www.example.com"],
            "只查過一次的不分享"
        );
        assert!(kept.is_empty());
        assert_eq!(memo.len(), 3);
        let mut set = ShareSet::new();
        set.refresh(out.iter().filter_map(|r| to_wire(r, now)).collect(), now);
        assert_eq!(set.len(), 3);
        // 記憶體控制把冷的移出記憶體：www 與 cross 不在記憶體裡了，但不是刪除
        db.take_marks(true);
        let ev = db.evict_cold(now - 3_600_000, &|_| true);
        assert_eq!(ev.entries, 3, "www、cross、p1 移出");
        let mut out = Vec::new();
        let (memo, kept) = share_domains(&db, &[], now + 600_000, &memo, &mut out);
        assert_eq!(names(&out), ["site:img.example.com"]);
        assert_eq!(kept.len(), 2, "www 的網站記錄與 cross 的跨 CDN 記錄：{kept:?}");
        let before = set.len();
        set.refresh_keeping(out.iter().filter_map(|r| to_wire(r, now)).collect(), &kept, now + 600_000);
        assert_eq!(set.len(), before, "移出記憶體的照樣分享，不發刪除標記");
        // 真的不在了（不在記憶體、移出的名單裡也沒有，例如磁碟上的分片被淘汰）才刪
        db.unevict("www.example.com");
        let mut out = Vec::new();
        let (memo, kept) = share_domains(&db, &[], now + 1_200_000, &memo, &mut out);
        assert_eq!(kept.len(), 1, "只剩 cross 還在磁碟上");
        assert!(memo.len() >= 2);
        set.refresh_keeping(out.iter().filter_map(|r| to_wire(r, now)).collect(), &kept, now + 1_200_000);
        assert_eq!(set.len(), 2, "www 不在記憶體也不在磁碟上：刪除");
        // 記錄到期（觀測後 3 天）就算還在磁碟上也拿掉
        let late = now + 4 * 86_400_000;
        set.refresh_keeping(Vec::new(), &kept, late);
        assert_eq!(set.len(), 0);
    }

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
    use super::{friend_targets, pick_friend_ips, FRIEND_IPS_PER_DOMAIN};
    use std::net::IpAddr;

    #[test]
    fn friend_domain_ips_are_capped() {
        let p = |s: &str| s.parse::<IpAddr>().unwrap();
        // 一大串位址：最多 4 個，IPv4、IPv6 交錯
        let many: Vec<IpAddr> = (1..=20)
            .map(|i| p(&format!("192.0.2.{i}")))
            .chain((1..=20).map(|i| p(&format!("2001:db8::{i}"))))
            .collect();
        assert_eq!(
            pick_friend_ips(many),
            vec![p("192.0.2.1"), p("2001:db8::1"), p("192.0.2.2"), p("2001:db8::2")]
        );
        // 只有 IPv4、有重複
        let v4: Vec<IpAddr> = [
            "198.51.100.1",
            "198.51.100.1",
            "198.51.100.2",
            "198.51.100.3",
            "198.51.100.4",
            "198.51.100.5",
        ]
        .iter()
        .map(|s| p(s))
        .collect();
        let got = pick_friend_ips(v4);
        assert_eq!(got.len(), FRIEND_IPS_PER_DOMAIN);
        assert_eq!(got[0..2], [p("198.51.100.1"), p("198.51.100.2")]);
        assert!(pick_friend_ips(Vec::new()).is_empty());
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 3.5.0 E10：確定是別群組的降成四分之一；同群組、「不知道」（任一邊沒有）照舊
    #[test]
    fn other_group_quota_is_quarter_unknown_is_full() {
        let full = kuroshio_cdn::cdn::FRIEND_MAX_NODES;
        assert_eq!(friend_node_cap(Some("cht"), Some("twm")), full / 4);
        assert_eq!(friend_node_cap(Some("cht"), Some("twm")), 125);
        assert_eq!(friend_node_cap(Some("cht"), Some("cht")), full);
        assert_eq!(friend_node_cap(Some("cht"), None), full, "舊版好友、沒開分享的好友不被懲罰");
        assert_eq!(friend_node_cap(None, Some("twm")), full, "這台自己偵測不到群組：不做");
        assert_eq!(friend_node_cap(None, None), full);
    }
}
