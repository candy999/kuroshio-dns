//! 分享集合與增量同步（規格 03 第 7 節）
//!
//! - 我的分享集合：`epoch`（隨機 8 bytes，state 重置時換新）+ 遞增的 `seq`；每筆記錄帶最後變更時的 seq、觀測時間、有效期限
//! - 記錄到期或不再有用 → 刪除標記（保留 7 天）；對方的 since 比最舊的刪除標記還舊 → 回完整集合
//! - 好友的集合（RemoteSet）：套用完整 / 增量回應，收到的每筆都先檢查格式（第 8.1 節）

use crate::envelope::{NetInfo, WireRecord};
use crate::provider::LocalRecord;
use crate::score::Kind;
use crate::util::{hex, is_private_ip, random_bytes, site_hash, DAY, HOUR, MINUTE};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

pub const TOMBSTONE_KEEP_MS: u64 = 7 * DAY;
pub const MAX_IPS: usize = 4;

pub fn limit_of(k: Kind) -> usize {
    match k {
        Kind::Node => 4_000,
        Kind::Site => 20_000,
        Kind::Cross => 5_000,
        Kind::Upstream => 100,
    }
}

pub fn ttl_of(k: Kind) -> u64 {
    match k {
        Kind::Upstream => 2 * DAY,
        _ => 3 * DAY,
    }
}

fn mkey(kind: &str, key: &str) -> String {
    format!("{kind}\0{key}")
}

fn ips_str(v: &[IpAddr]) -> Vec<String> {
    v.iter().take(MAX_IPS).map(|i| i.to_string()).collect()
}

/// 本機資料 → 線上格式（過期的丟掉）
pub fn to_wire(r: &LocalRecord, now: u64) -> Option<WireRecord> {
    let w = match r {
        LocalRecord::Node {
            p,
            ip,
            pop,
            ms,
            obs,
            permanent,
        } => WireRecord {
            kind: "node".into(),
            key: format!("{p}/{ip}"),
            obs: *obs,
            exp: obs + if *permanent && ip.is_ipv6() { 30 * DAY } else { ttl_of(Kind::Node) },
            p: Some(p.clone()),
            ip: Some(ip.to_string()),
            fam: Some(if ip.is_ipv6() { 6 } else { 4 }),
            pop: Some(pop.clone()),
            ms: *ms,
            ..Default::default()
        },
        LocalRecord::Site {
            name,
            p,
            fam,
            ips,
            pop,
            obs,
        } => {
            let h = site_hash(name);
            WireRecord {
                kind: "site".into(),
                key: format!("{}/{fam}", hex(&h)),
                obs: *obs,
                exp: obs + ttl_of(Kind::Site),
                p: Some(p.clone()),
                fam: Some(*fam),
                pop: Some(pop.clone()),
                h: Some(serde_bytes::ByteBuf::from(h.to_vec())),
                ips: Some(ips_str(ips)),
                ..Default::default()
            }
        }
        LocalRecord::Cross { name, from, to, ips, obs } => {
            let h = site_hash(name);
            WireRecord {
                kind: "cross".into(),
                key: hex(&h),
                obs: *obs,
                exp: obs + ttl_of(Kind::Cross),
                h: Some(serde_bytes::ByteBuf::from(h.to_vec())),
                from: Some(from.clone()),
                to: Some(to.clone()),
                ips: Some(ips_str(ips)),
                ..Default::default()
            }
        }
        LocalRecord::Upstream { url, proto, ms, ok, obs } => WireRecord {
            kind: "upstream".into(),
            key: url.clone(),
            obs: *obs,
            exp: obs + ttl_of(Kind::Upstream),
            url: Some(url.clone()),
            proto: Some(proto.clone()),
            ms: *ms,
            ok: Some(*ok),
            ..Default::default()
        },
    };
    (w.exp > now).then_some(w)
}

/// 內容一樣（不看 seq / obs；有效期限差不到 12 小時也算一樣，避免每次重新驗證就重送整包）
fn same_content(a: &WireRecord, b: &WireRecord) -> bool {
    let strip = |r: &WireRecord| WireRecord {
        seq: 0,
        obs: 0,
        exp: 0,
        ..r.clone()
    };
    strip(a) == strip(b) && a.exp.abs_diff(b.exp) <= 12 * HOUR
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Tomb {
    kind: String,
    key: String,
    seq: u64,
    at: u64,
}

#[derive(Serialize, Deserialize)]
struct ShareSnap {
    #[serde(with = "serde_bytes")]
    epoch: Vec<u8>,
    seq: u64,
    floor: u64,
    recs: Vec<WireRecord>,
    tombs: Vec<Tomb>,
}

/// 我的分享集合
pub struct ShareSet {
    pub epoch: [u8; 8],
    pub seq: u64,
    /// 已清掉的刪除標記中最大的 seq：對方的 since 比這個舊就要回完整集合
    pub floor: u64,
    recs: HashMap<String, WireRecord>,
    tombs: HashMap<String, Tomb>,
}

/// 一次同步要回的內容
#[derive(Debug, Clone, Default)]
pub struct Delta {
    pub unchanged: bool,
    pub full: bool,
    pub upserts: Vec<WireRecord>,
    pub deletes: Vec<(String, String)>,
}

impl Default for ShareSet {
    fn default() -> Self {
        ShareSet::new()
    }
}

impl ShareSet {
    pub fn new() -> ShareSet {
        ShareSet {
            epoch: random_bytes::<8>(),
            seq: 0,
            floor: 0,
            recs: HashMap::new(),
            tombs: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.recs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.recs.is_empty()
    }

    pub fn records(&self) -> impl Iterator<Item = &WireRecord> {
        self.recs.values()
    }

    /// state 重置：換新的 epoch，所有好友下次拿完整集合
    pub fn reset(&mut self) {
        *self = ShareSet::new();
    }

    /// 用本機目前的資料更新；有變動回 true
    pub fn refresh(&mut self, incoming: Vec<WireRecord>, now: u64) -> bool {
        // 每種 kind 有上限：新觀測的優先
        let mut by_kind: HashMap<String, Vec<WireRecord>> = HashMap::new();
        for r in incoming.into_iter().filter(|r| r.exp > now) {
            by_kind.entry(r.kind.clone()).or_default().push(r);
        }
        let mut want: HashMap<String, WireRecord> = HashMap::new();
        for (kind, mut v) in by_kind {
            let Some(k) = Kind::parse(&kind) else { continue };
            v.sort_by_key(|r| std::cmp::Reverse(r.obs));
            let mut n = 0;
            for r in v {
                if n >= limit_of(k) {
                    break;
                }
                if let std::collections::hash_map::Entry::Vacant(e) = want.entry(mkey(&r.kind, &r.key)) {
                    e.insert(r);
                    n += 1;
                }
            }
        }
        let before = self.seq;
        let gone: Vec<String> = self.recs.keys().filter(|k| !want.contains_key(*k)).cloned().collect();
        for k in gone {
            if let Some(r) = self.recs.remove(&k) {
                self.seq += 1;
                self.tombs.insert(
                    k,
                    Tomb {
                        kind: r.kind,
                        key: r.key,
                        seq: self.seq,
                        at: now,
                    },
                );
            }
        }
        let mut keys: Vec<String> = want.keys().cloned().collect();
        keys.sort();
        for k in keys {
            let mut r = want.remove(&k).unwrap();
            if self.recs.get(&k).map(|old| same_content(old, &r)).unwrap_or(false) {
                continue;
            }
            self.seq += 1;
            r.seq = self.seq;
            self.tombs.remove(&k);
            self.recs.insert(k, r);
        }
        self.prune(now);
        self.seq != before
    }

    /// 清掉超過 7 天的刪除標記
    pub fn prune(&mut self, now: u64) {
        let mut floor = self.floor;
        self.tombs.retain(|_, t| {
            let keep = now.saturating_sub(t.at) <= TOMBSTONE_KEEP_MS;
            if !keep {
                floor = floor.max(t.seq);
            }
            keep
        });
        self.floor = floor;
    }

    /// 依對方上次拿到的 epoch / seq 決定回什麼
    pub fn delta(&self, epoch: Option<&[u8]>, since: Option<u64>) -> Delta {
        if epoch == Some(&self.epoch[..]) {
            if let Some(s) = since {
                if s == self.seq {
                    return Delta {
                        unchanged: true,
                        ..Default::default()
                    };
                }
                if s < self.seq && s >= self.floor {
                    let mut upserts: Vec<WireRecord> = self.recs.values().filter(|r| r.seq > s).cloned().collect();
                    upserts.sort_by_key(|r| r.seq);
                    let mut del: Vec<&Tomb> = self.tombs.values().filter(|t| t.seq > s).collect();
                    del.sort_by_key(|t| t.seq);
                    return Delta {
                        unchanged: false,
                        full: false,
                        upserts,
                        deletes: del.into_iter().map(|t| (t.kind.clone(), t.key.clone())).collect(),
                    };
                }
            }
        }
        let mut upserts: Vec<WireRecord> = self.recs.values().cloned().collect();
        upserts.sort_by_key(|r| r.seq);
        Delta {
            unchanged: false,
            full: true,
            upserts,
            deletes: vec![],
        }
    }

    pub fn snapshot(&self) -> Vec<u8> {
        let mut recs: Vec<WireRecord> = self.recs.values().cloned().collect();
        recs.sort_by_key(|r| r.seq);
        let mut tombs: Vec<Tomb> = self.tombs.values().cloned().collect();
        tombs.sort_by_key(|t| t.seq);
        crate::envelope::to_cbor(&ShareSnap {
            epoch: self.epoch.to_vec(),
            seq: self.seq,
            floor: self.floor,
            recs,
            tombs,
        })
    }

    pub fn load(b: &[u8]) -> Option<ShareSet> {
        let s: ShareSnap = crate::envelope::from_cbor(b).ok()?;
        Some(ShareSet {
            epoch: s.epoch.try_into().ok()?,
            seq: s.seq,
            floor: s.floor,
            recs: s.recs.into_iter().map(|r| (mkey(&r.kind, &r.key), r)).collect(),
            tombs: s.tombs.into_iter().map(|t| (mkey(&t.kind, &t.key), t)).collect(),
        })
    }
}

// ---------------- 收到的資料 ----------------

/// 單筆檢查結果
#[derive(Debug, Clone, PartialEq)]
pub enum Check {
    Valid(Kind, Box<WireRecord>),
    /// 已過期：不收，也不算錯
    Expired,
    /// 格式錯誤、私有 / 保留位址
    Invalid(Option<Kind>),
}

fn public_ip(s: &str, fam: Option<u8>) -> Option<IpAddr> {
    let ip: IpAddr = s.parse().ok()?;
    let f = if ip.is_ipv6() { 6 } else { 4 };
    if fam.map(|x| x != f).unwrap_or(false) || is_private_ip(ip) {
        return None;
    }
    Some(ip)
}

fn short_name(s: &Option<String>) -> Option<String> {
    let s = s.as_deref()?;
    (!s.is_empty() && s.len() <= 32 && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))).then(|| s.to_ascii_lowercase())
}

fn check_ips(v: &Option<Vec<String>>, fam: Option<u8>) -> Option<Vec<String>> {
    let v = v.as_ref()?;
    if v.is_empty() || v.len() > MAX_IPS {
        return None;
    }
    v.iter().map(|s| public_ip(s, fam).map(|ip| ip.to_string())).collect()
}

const UPSTREAM_PROTOS: [(&str, &str); 7] = [
    ("udp", "udp"),
    ("tcp", "tcp"),
    ("dot", "tls"),
    ("doh", "https"),
    ("doh3", "h3"),
    ("doq", "quic"),
    ("dnscrypt", "sdns"),
];

fn check_upstream(r: &WireRecord) -> Option<()> {
    let url = r.url.as_deref()?;
    if url.len() > 200 || r.key != url {
        return None;
    }
    let proto = r.proto.as_deref()?;
    let scheme = UPSTREAM_PROTOS.iter().find(|(p, _)| *p == proto)?.1;
    if !url.to_ascii_lowercase().starts_with(&format!("{scheme}://")) {
        return None;
    }
    if scheme != "sdns" {
        let u = kuroshio_net::upstream::Upstream::parse(url).ok()?;
        let host = u.host.to_ascii_lowercase();
        if let Ok(ip) = host.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>() {
            if is_private_ip(ip) {
                return None;
            }
        }
        if host == "localhost"
            || host.ends_with(".local")
            || host.ends_with(".lan")
            || host.ends_with(".internal")
            || host.ends_with(".home.arpa")
        {
            return None;
        }
    }
    if let Some(ok) = r.ok {
        if !(0.0..=1.0).contains(&ok) {
            return None;
        }
    }
    Some(())
}

/// 檢查一筆收到的記錄，回傳正規化後的內容
pub fn validate(r: &WireRecord, now: u64) -> Check {
    let Some(kind) = Kind::parse(&r.kind) else {
        return Check::Invalid(None);
    };
    if r.exp <= now {
        return Check::Expired;
    }
    let mut out = r.clone();
    out.obs = r.obs.min(now + 10 * MINUTE);
    out.exp = r.exp.min(now + 31 * DAY);
    out.pop = r.pop.as_ref().map(|s| crate::util::clip(s, 8));
    let ok = match kind {
        Kind::Node => (|| {
            let p = short_name(&r.p)?;
            let ip = public_ip(r.ip.as_deref()?, r.fam)?;
            (r.key == format!("{p}/{ip}")).then_some(())?;
            out.p = Some(p);
            out.fam = Some(if ip.is_ipv6() { 6 } else { 4 });
            Some(())
        })(),
        Kind::Site => (|| {
            let h = r.h.as_ref().filter(|h| h.len() == 12)?;
            let fam = r.fam.filter(|f| *f == 4 || *f == 6)?;
            (r.key == format!("{}/{fam}", hex(h))).then_some(())?;
            out.p = Some(short_name(&r.p)?);
            out.ips = Some(check_ips(&r.ips, Some(fam))?);
            Some(())
        })(),
        Kind::Cross => (|| {
            let h = r.h.as_ref().filter(|h| h.len() == 12)?;
            (r.key == hex(h)).then_some(())?;
            out.from = Some(short_name(&r.from)?);
            out.to = Some(short_name(&r.to)?);
            out.ips = Some(check_ips(&r.ips, None)?);
            Some(())
        })(),
        Kind::Upstream => check_upstream(r),
    };
    match ok {
        Some(()) => Check::Valid(kind, Box::new(out)),
        None => Check::Invalid(Some(kind)),
    }
}

#[derive(Serialize, Deserialize)]
struct RemoteSnap {
    domain: String,
    #[serde(with = "serde_bytes")]
    epoch: Vec<u8>,
    seq: u64,
    ctx: NetInfo,
    updated: u64,
    recs: Vec<WireRecord>,
}

/// 一個好友的集合（套用增量用）
#[derive(Debug, Clone, Default)]
pub struct RemoteSet {
    pub epoch: Vec<u8>,
    pub seq: u64,
    pub ctx: NetInfo,
    pub updated: u64,
    pub recs: HashMap<String, WireRecord>,
}

impl RemoteSet {
    pub fn get(&self, kind: &str, key: &str) -> Option<&WireRecord> {
        self.recs.get(&mkey(kind, key))
    }

    pub fn upsert(&mut self, r: WireRecord) {
        self.recs.insert(mkey(&r.kind, &r.key), r);
    }

    pub fn delete(&mut self, kind: &str, key: &str) -> bool {
        self.recs.remove(&mkey(kind, key)).is_some()
    }

    pub fn count(&self, k: Kind) -> usize {
        let p = format!("{}\0", k.as_str());
        self.recs.keys().filter(|x| x.starts_with(&p)).count()
    }

    pub fn expire(&mut self, now: u64) {
        self.recs.retain(|_, r| r.exp > now);
    }
}

pub fn remote_snapshot(sets: &HashMap<String, RemoteSet>) -> Vec<u8> {
    let mut v: Vec<RemoteSnap> = sets
        .iter()
        .map(|(d, s)| {
            let mut recs: Vec<WireRecord> = s.recs.values().cloned().collect();
            recs.sort_by(|a, b| (&a.kind, &a.key).cmp(&(&b.kind, &b.key)));
            RemoteSnap {
                domain: d.clone(),
                epoch: s.epoch.clone(),
                seq: s.seq,
                ctx: s.ctx.clone(),
                updated: s.updated,
                recs,
            }
        })
        .collect();
    v.sort_by(|a, b| a.domain.cmp(&b.domain));
    crate::envelope::compress(&crate::envelope::to_cbor(&v))
}

pub fn remote_load(b: &[u8]) -> HashMap<String, RemoteSet> {
    let Ok(plain) = crate::envelope::decompress(b, crate::envelope::MAX_RESPONSE_PLAIN * 4) else {
        return HashMap::new();
    };
    let Ok(v) = crate::envelope::from_cbor::<Vec<RemoteSnap>>(&plain) else {
        return HashMap::new();
    };
    v.into_iter()
        .map(|s| {
            (
                s.domain,
                RemoteSet {
                    epoch: s.epoch,
                    seq: s.seq,
                    ctx: s.ctx,
                    updated: s.updated,
                    recs: s.recs.into_iter().map(|r| (mkey(&r.kind, &r.key), r)).collect(),
                },
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(ip: &str, obs: u64) -> LocalRecord {
        LocalRecord::Node {
            p: "cloudflare".into(),
            ip: ip.parse().unwrap(),
            pop: "TPE".into(),
            ms: Some(3),
            obs,
            permanent: false,
        }
    }

    #[test]
    fn delta_and_tombstones() {
        let now = 100 * DAY;
        let mut s = ShareSet::new();
        let w = |v: &[LocalRecord]| v.iter().filter_map(|r| to_wire(r, now)).collect::<Vec<_>>();
        assert!(s.refresh(w(&[node("104.16.1.1", now), node("104.16.1.2", now)]), now));
        assert_eq!(s.seq, 2);
        let e = s.epoch;
        assert!(s.delta(Some(&e), Some(2)).unchanged);
        // 內容沒變：不動 seq
        assert!(!s.refresh(w(&[node("104.16.1.1", now + HOUR), node("104.16.1.2", now)]), now + HOUR));
        // 刪一筆、加一筆
        assert!(s.refresh(w(&[node("104.16.1.1", now), node("104.16.1.3", now)]), now + HOUR));
        let d = s.delta(Some(&e), Some(2));
        assert!(!d.full);
        assert_eq!(
            d.upserts.iter().map(|r| r.key.as_str()).collect::<Vec<_>>(),
            vec!["cloudflare/104.16.1.3"]
        );
        assert_eq!(d.deletes, vec![("node".to_string(), "cloudflare/104.16.1.2".to_string())]);
        // 別的 epoch → 完整集合
        let f = s.delta(Some(&[0u8; 8]), Some(2));
        assert!(f.full);
        assert_eq!(f.upserts.len(), 2);
        // 刪除標記保留 7 天，之後太舊的 since 回完整集合
        s.refresh(
            w(&[node("104.16.1.1", now + 8 * DAY), node("104.16.1.3", now + 8 * DAY)]),
            now + 8 * DAY + HOUR,
        );
        assert!(s.floor >= 3);
        assert!(s.delta(Some(&e), Some(2)).full);
        // 快照
        let back = ShareSet::load(&s.snapshot()).unwrap();
        assert_eq!((back.epoch, back.seq, back.floor, back.len()), (s.epoch, s.seq, s.floor, s.len()));
    }

    #[test]
    fn limits_per_kind() {
        let now = 10 * DAY;
        let mut s = ShareSet::new();
        let v: Vec<WireRecord> = (0..120)
            .filter_map(|i| {
                to_wire(
                    &LocalRecord::Upstream {
                        url: format!("https://dns{i}.example.net/dns-query"),
                        proto: "doh".into(),
                        ms: Some(5),
                        ok: 1.0,
                        obs: now - i,
                    },
                    now,
                )
            })
            .collect();
        s.refresh(v, now);
        assert_eq!(s.len(), 100);
    }

    #[test]
    fn validation() {
        let now = 10 * DAY;
        let good = to_wire(&node("104.16.1.1", now), now).unwrap();
        assert!(matches!(validate(&good, now), Check::Valid(Kind::Node, _)));
        let mut private = good.clone();
        private.ip = Some("10.0.0.1".into());
        private.key = "cloudflare/10.0.0.1".into();
        assert_eq!(validate(&private, now), Check::Invalid(Some(Kind::Node)));
        let mut wrong_key = good.clone();
        wrong_key.key = "x/1.1.1.1".into();
        assert_eq!(validate(&wrong_key, now), Check::Invalid(Some(Kind::Node)));
        assert_eq!(validate(&good, now + 4 * DAY), Check::Expired);
        let site = to_wire(
            &LocalRecord::Site {
                name: "Example.com".into(),
                p: "cloudflare".into(),
                fam: 4,
                ips: vec!["104.16.2.2".parse().unwrap()],
                pop: "TPE".into(),
                obs: now,
            },
            now,
        )
        .unwrap();
        assert!(matches!(validate(&site, now), Check::Valid(Kind::Site, _)));
        assert_eq!(site.h.as_ref().unwrap().as_slice(), &site_hash("example.com"));
        let up = |url: &str, proto: &str| WireRecord {
            kind: "upstream".into(),
            key: url.into(),
            exp: now + DAY,
            url: Some(url.into()),
            proto: Some(proto.into()),
            ok: Some(0.9),
            ..Default::default()
        };
        assert!(matches!(
            validate(&up("https://dns.example.net/dns-query", "doh"), now),
            Check::Valid(..)
        ));
        assert!(matches!(validate(&up("quic://dns.adguard-dns.com", "doq"), now), Check::Valid(..)));
        assert_eq!(validate(&up("udp://10.0.0.1:53", "udp"), now), Check::Invalid(Some(Kind::Upstream)));
        assert_eq!(validate(&up("udp://router.lan", "udp"), now), Check::Invalid(Some(Kind::Upstream)));
        assert_eq!(
            validate(&up("https://dns.example.net/dns-query", "udp"), now),
            Check::Invalid(Some(Kind::Upstream))
        );
    }
}
