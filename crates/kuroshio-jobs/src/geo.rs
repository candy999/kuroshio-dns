//! 位址範圍集合（台灣 IP 清單 `data/geo/tw-ip.json` 的產生與查詢共用）
//!
//! - `RangeSet<T>`：排序、合併、互不重疊的閉區間 `[start, end]`；IPv4 用 `u32`、IPv6 用 `u128`
//! - 建立時排序合併一次，之後查詢用二分搜尋（O(log n)）
//! - 聯集、差集、交集、轉回最少的 CIDR 清單（產生器用）
//! - `TwIp`：`tw-ip.json` 的格式（規格 08）

use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// 位址型別（`u32` / `u128`）
pub trait Addr: Copy + Ord + std::fmt::Debug {
    const BITS: u32;
    const MAX: Self;
    const ZERO: Self;
    fn inc(self) -> Option<Self>;
    fn dec(self) -> Option<Self>;
    /// 前綴長度 `len` 的網段起點與終點（`len` 超過位元數回 None）
    fn net(self, len: u8) -> Option<(Self, Self)>;
    /// 從 `self` 開始、不超過 `end` 的最大 CIDR 前綴長度
    fn largest_block(self, end: Self) -> u8;
    /// 區間大小（位址數，超過 u128 就飽和）；IPv6 通常再換算成 /48 數量
    fn span(a: Self, b: Self) -> u128;
}

macro_rules! impl_addr {
    ($t:ty) => {
        impl Addr for $t {
            const BITS: u32 = <$t>::BITS;
            const MAX: Self = <$t>::MAX;
            const ZERO: Self = 0;
            fn inc(self) -> Option<Self> {
                self.checked_add(1)
            }
            fn dec(self) -> Option<Self> {
                self.checked_sub(1)
            }
            fn net(self, len: u8) -> Option<(Self, Self)> {
                if len as u32 > Self::BITS {
                    return None;
                }
                let host: Self = if len == 0 {
                    <$t>::MAX
                } else {
                    (<$t>::MAX).checked_shr(len as u32).unwrap_or(0)
                };
                let start = self & !host;
                Some((start, start | host))
            }
            fn largest_block(self, end: Self) -> u8 {
                // 起點對齊限制：尾端連續 0 的位元數；長度限制：區間能放下的最大 2 的冪次
                let mut host = if self == 0 { Self::BITS } else { self.trailing_zeros() };
                loop {
                    let size_minus_1: Self = if host >= Self::BITS {
                        <$t>::MAX
                    } else {
                        ((1 as $t) << host) - 1
                    };
                    if let Some(last) = self.checked_add(size_minus_1) {
                        if last <= end {
                            return (Self::BITS - host) as u8;
                        }
                    }
                    host -= 1;
                }
            }
            fn span(a: Self, b: Self) -> u128 {
                ((b - a) as u128).saturating_add(1)
            }
        }
    };
}
impl_addr!(u32);
impl_addr!(u128);

/// 排序、合併後互不重疊的閉區間
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RangeSet<T: Addr> {
    r: Vec<(T, T)>,
}

impl<T: Addr> RangeSet<T> {
    pub fn new() -> Self {
        RangeSet { r: Vec::new() }
    }

    /// 任意順序、可能重疊或相鄰的區間 → 合併
    pub fn from_ranges(mut v: Vec<(T, T)>) -> Self {
        v.retain(|(a, b)| a <= b);
        v.sort_unstable();
        let mut out: Vec<(T, T)> = Vec::with_capacity(v.len());
        for (a, b) in v {
            if let Some(last) = out.last_mut() {
                // 重疊或相鄰（last.1 + 1 >= a）就併起來
                if last.1.inc().map(|n| n >= a).unwrap_or(true) {
                    if b > last.1 {
                        last.1 = b;
                    }
                    continue;
                }
            }
            out.push((a, b));
        }
        out.shrink_to_fit();
        RangeSet { r: out }
    }

    pub fn ranges(&self) -> &[(T, T)] {
        &self.r
    }

    pub fn len(&self) -> usize {
        self.r.len()
    }

    pub fn is_empty(&self) -> bool {
        self.r.is_empty()
    }

    /// 二分搜尋：最後一個起點 <= x 的區間有沒有包含 x
    pub fn contains(&self, x: T) -> bool {
        let i = self.r.partition_point(|(a, _)| *a <= x);
        i > 0 && self.r[i - 1].1 >= x
    }

    /// 包含 x 的那個區間
    pub fn find(&self, x: T) -> Option<(T, T)> {
        let i = self.r.partition_point(|(a, _)| *a <= x);
        (i > 0 && self.r[i - 1].1 >= x).then(|| self.r[i - 1])
    }

    pub fn union(&self, o: &Self) -> Self {
        let mut v = self.r.clone();
        v.extend_from_slice(&o.r);
        Self::from_ranges(v)
    }

    /// self − o
    pub fn subtract(&self, o: &Self) -> Self {
        let mut out = Vec::new();
        let mut j = 0;
        for &(a, b) in &self.r {
            let mut cur = Some(a);
            while j < o.r.len() && o.r[j].1 < a {
                j += 1;
            }
            let mut k = j;
            while let Some(start) = cur {
                if k >= o.r.len() || o.r[k].0 > b {
                    out.push((start, b));
                    break;
                }
                let (oa, ob) = o.r[k];
                if oa > start {
                    out.push((start, oa.dec().unwrap()));
                }
                cur = if ob >= b { None } else { ob.inc() };
                k += 1;
            }
        }
        RangeSet { r: out }
    }

    /// self ∩ o
    pub fn intersect(&self, o: &Self) -> Self {
        let (mut i, mut j) = (0, 0);
        let mut out = Vec::new();
        while i < self.r.len() && j < o.r.len() {
            let (a, b) = self.r[i];
            let (c, d) = o.r[j];
            let lo = a.max(c);
            let hi = b.min(d);
            if lo <= hi {
                out.push((lo, hi));
            }
            if b < d {
                i += 1;
            } else {
                j += 1;
            }
        }
        RangeSet { r: out }
    }

    /// 位址總數（u128 飽和）
    pub fn size(&self) -> u128 {
        self.r.iter().fold(0u128, |s, (a, b)| s.saturating_add(T::span(*a, *b)))
    }

    /// 轉回最少的 CIDR（起點, 前綴長度）
    pub fn to_cidrs(&self) -> Vec<(T, u8)> {
        let mut out = Vec::new();
        for &(a, b) in &self.r {
            let mut s = a;
            loop {
                let len = s.largest_block(b);
                out.push((s, len));
                let (_, last) = s.net(len).unwrap();
                if last >= b {
                    break;
                }
                s = last.inc().unwrap();
            }
        }
        out
    }

    /// 佔用的記憶體（位元組，不含 Vec 本身的 24 位元組）
    pub fn heap_bytes(&self) -> usize {
        self.r.capacity() * std::mem::size_of::<(T, T)>()
    }
}

/// 解析 CIDR（或單一位址）；主機位元不是 0 也接受（取網段）。IPv4 對應的 IPv6（::ffff:a.b.c.d/x）轉成 IPv4
pub fn parse_cidr(s: &str) -> Option<Net> {
    let s = s.trim();
    let (ip, len) = match s.split_once('/') {
        Some((ip, l)) => (ip, Some(l.trim().parse::<u8>().ok()?)),
        None => (s, None),
    };
    match ip.trim().parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) => {
            let len = len.unwrap_or(32);
            let (a, b) = u32::from(v4).net(len)?;
            Some(Net::V4(a, b))
        }
        IpAddr::V6(v6) => {
            let len = len.unwrap_or(128);
            if let (Some(v4), true) = (v6.to_ipv4_mapped(), len >= 96) {
                let (a, b) = u32::from(v4).net(len - 96)?;
                return Some(Net::V4(a, b));
            }
            let (a, b) = u128::from(v6).net(len)?;
            Some(Net::V6(a, b))
        }
    }
}

/// 一個網段（閉區間）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Net {
    V4(u32, u32),
    V6(u128, u128),
}

/// IPv4 / IPv6 各一個範圍集合
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dual {
    pub v4: RangeSet<u32>,
    pub v6: RangeSet<u128>,
}

impl Dual {
    /// CIDR 清單（格式錯誤的略過，回傳略過的那些）
    pub fn parse<'a>(list: impl IntoIterator<Item = &'a str>) -> (Dual, Vec<String>) {
        let (mut v4, mut v6, mut bad) = (Vec::new(), Vec::new(), Vec::new());
        for s in list {
            match parse_cidr(s) {
                Some(Net::V4(a, b)) => v4.push((a, b)),
                Some(Net::V6(a, b)) => v6.push((a, b)),
                None if s.trim().is_empty() => {}
                None => bad.push(s.to_string()),
            }
        }
        (Dual::from_ranges(v4, v6), bad)
    }

    pub fn from_ranges(v4: Vec<(u32, u32)>, v6: Vec<(u128, u128)>) -> Dual {
        Dual {
            v4: RangeSet::from_ranges(v4),
            v6: RangeSet::from_ranges(v6),
        }
    }

    /// IPv4 對應的 IPv6（::ffff:a.b.c.d）當成 IPv4 查
    pub fn contains(&self, ip: IpAddr) -> bool {
        match canonical(ip) {
            IpAddr::V4(a) => self.v4.contains(u32::from(a)),
            IpAddr::V6(a) => self.v6.contains(u128::from(a)),
        }
    }

    pub fn union(&self, o: &Dual) -> Dual {
        Dual {
            v4: self.v4.union(&o.v4),
            v6: self.v6.union(&o.v6),
        }
    }

    pub fn subtract(&self, o: &Dual) -> Dual {
        Dual {
            v4: self.v4.subtract(&o.v4),
            v6: self.v6.subtract(&o.v6),
        }
    }

    pub fn intersect(&self, o: &Dual) -> Dual {
        Dual {
            v4: self.v4.intersect(&o.v4),
            v6: self.v6.intersect(&o.v6),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    pub fn heap_bytes(&self) -> usize {
        self.v4.heap_bytes() + self.v6.heap_bytes()
    }

    /// 大小：IPv4 位址數、IPv6 /48 數量
    pub fn size_json(&self) -> Value {
        json!({ "v4": self.v4.size() as u64, "v6_48": (self.v6.size() >> 80).min(u64::MAX as u128) as u64 })
    }

    pub fn v4_cidrs(&self) -> Vec<String> {
        self.v4
            .to_cidrs()
            .into_iter()
            .map(|(a, l)| format!("{}/{l}", Ipv4Addr::from(a)))
            .collect()
    }

    pub fn v6_cidrs(&self) -> Vec<String> {
        self.v6
            .to_cidrs()
            .into_iter()
            .map(|(a, l)| format!("{}/{l}", Ipv6Addr::from(a)))
            .collect()
    }
}

/// IPv4 對應的 IPv6 → IPv4
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

/// `tw-ip.json` 的一個群組（ISP）
#[derive(Debug, Clone)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub note: String,
    pub asns: Vec<u32>,
    pub nets: Dual,
}

/// 整份 `tw-ip.json`
#[derive(Debug, Clone, Default)]
pub struct TwIp {
    pub generated_at: String,
    pub groups: Vec<Group>,
}

impl TwIp {
    /// 讀 JSON 並檢查格式：每個群組要有 id、name，CIDR 必須全部有效、IPv4 總量不能是 0
    pub fn parse(bytes: &[u8]) -> anyhow::Result<TwIp> {
        let v: Value = serde_json::from_slice(bytes)?;
        let generated_at = v
            .get("generatedAt")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("缺少 generatedAt"))?
            .to_string();
        let gs = v
            .get("groups")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("缺少 groups"))?;
        let mut groups = Vec::with_capacity(gs.len());
        for g in gs {
            let s = |k: &str| g.get(k).and_then(Value::as_str).unwrap_or("").to_string();
            let id = s("id");
            if id.is_empty() || id == "*" || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                anyhow::bail!("群組 id 格式錯誤：{id:?}");
            }
            if groups.iter().any(|x: &Group| x.id == id) {
                anyhow::bail!("群組 id 重複：{id}");
            }
            let list = |k: &str| -> Vec<&str> {
                g.get(k)
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default()
            };
            let (v4, v6) = (list("v4"), list("v6"));
            let (nets, bad) = Dual::parse(v4.iter().chain(v6.iter()).copied());
            if !bad.is_empty() {
                anyhow::bail!("群組 {id} 有格式錯誤的網段：{}", bad.join(", "));
            }
            groups.push(Group {
                id,
                name: s("name"),
                note: s("note"),
                asns: g
                    .get("asns")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_u64).map(|x| x as u32).collect())
                    .unwrap_or_default(),
                nets,
            });
        }
        let t = TwIp { generated_at, groups };
        if t.all().v4.size() == 0 {
            anyhow::bail!("IPv4 網段是空的");
        }
        Ok(t)
    }

    /// 全部群組的聯集
    pub fn all(&self) -> Dual {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for g in &self.groups {
            v4.extend_from_slice(g.nets.v4.ranges());
            v6.extend_from_slice(g.nets.v6.ranges());
        }
        Dual::from_ranges(v4, v6)
    }

    pub fn group(&self, id: &str) -> Option<&Group> {
        self.groups.iter().find(|g| g.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> u32 {
        u32::from(s.parse::<Ipv4Addr>().unwrap())
    }

    #[test]
    fn merge_and_lookup_v4() {
        let s = RangeSet::from_ranges(vec![(10, 20), (21, 30), (5, 12), (40, 50), (100, 100), (60, 55)]);
        assert_eq!(s.ranges(), &[(5, 30), (40, 50), (100, 100)], "重疊與相鄰合併、反向區間丟掉");
        for x in [5, 17, 30, 40, 50, 100] {
            assert!(s.contains(x), "{x}");
        }
        for x in [0, 4, 31, 39, 51, 99, 101, u32::MAX] {
            assert!(!s.contains(x), "{x}");
        }
        // 邊界：0 與最大值
        let e = RangeSet::from_ranges(vec![(0u32, 0), (u32::MAX, u32::MAX), (u32::MAX - 1, u32::MAX - 1)]);
        assert_eq!(e.ranges(), &[(0, 0), (u32::MAX - 1, u32::MAX)]);
        assert!(e.contains(0) && e.contains(u32::MAX) && !e.contains(1));
        assert!(!RangeSet::<u32>::new().contains(0));
        let full = RangeSet::from_ranges(vec![(0u32, u32::MAX), (5, 6)]);
        assert_eq!(full.size(), 1u128 << 32);
    }

    #[test]
    fn set_ops() {
        let a = RangeSet::from_ranges(vec![(0u32, 100), (200, 300)]);
        let b = RangeSet::from_ranges(vec![(50u32, 60), (90, 210), (300, 400)]);
        assert_eq!(a.subtract(&b).ranges(), &[(0, 49), (61, 89), (211, 299)]);
        assert_eq!(a.intersect(&b).ranges(), &[(50, 60), (90, 100), (200, 210), (300, 300)]);
        assert_eq!(a.union(&b).ranges(), &[(0, 400)]);
        // 差集再聯集回來 == 原本的聯集
        let back = a.subtract(&b).union(&b);
        assert_eq!(back, a.union(&b));
        let full = RangeSet::from_ranges(vec![(0u32, u32::MAX)]);
        assert!(full.subtract(&full).is_empty());
        assert_eq!(full.subtract(&RangeSet::from_ranges(vec![(0, 0)])).ranges(), &[(1, u32::MAX)]);
        assert_eq!(
            full.subtract(&RangeSet::from_ranges(vec![(u32::MAX, u32::MAX)])).ranges(),
            &[(0, u32::MAX - 1)]
        );
    }

    #[test]
    fn cidr_roundtrip() {
        let (d, bad) = Dual::parse([
            "1.160.0.0/12",
            "10.0.0.1/8",
            "2001:b000::/20",
            "::ffff:8.8.8.0/120",
            "nope",
            "1.2.3.4/33",
        ]);
        assert_eq!(bad, vec!["nope", "1.2.3.4/33"]);
        assert_eq!(d.v4_cidrs(), vec!["1.160.0.0/12", "8.8.8.0/24", "10.0.0.0/8"]);
        assert_eq!(d.v6_cidrs(), vec!["2001:b000::/20"]);
        // 非 2 的冪次的區間（RIR 的 IPv4 配發常見）→ 最少的 CIDR
        let r = RangeSet::from_ranges(vec![(v4("1.0.0.0"), v4("1.0.2.255"))]);
        let c: Vec<String> = r.to_cidrs().iter().map(|(a, l)| format!("{}/{l}", Ipv4Addr::from(*a))).collect();
        assert_eq!(c, vec!["1.0.0.0/23", "1.0.2.0/24"]);
        let full = RangeSet::from_ranges(vec![(0u128, u128::MAX)]);
        assert_eq!(full.to_cidrs(), vec![(0, 0)]);
        let odd = RangeSet::from_ranges(vec![(1u32, u32::MAX)]);
        let back = RangeSet::from_ranges(odd.to_cidrs().iter().map(|(a, l)| a.net(*l).unwrap()).collect());
        assert_eq!(back, odd);
        assert_eq!(odd.to_cidrs().len(), 32);
    }

    #[test]
    fn lookup_v6_and_mapped() {
        let (d, _) = Dual::parse(["1.160.0.0/12", "2001:b000::/20", "2402:7500::/32"]);
        assert!(d.contains("1.175.255.255".parse().unwrap()));
        assert!(!d.contains("1.176.0.0".parse().unwrap()));
        assert!(d.contains("::ffff:1.160.0.1".parse().unwrap()), "IPv4 對應的 IPv6");
        assert!(d.contains("2001:b000::1".parse().unwrap()));
        assert!(d.contains("2001:bfff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()));
        assert!(!d.contains("2001:c000::".parse().unwrap()));
        assert!(!d.contains("2402:7501::".parse().unwrap()));
        assert_eq!(d.size_json()["v6_48"], json!((1u64 << 28) + (1u64 << 16)));
    }

    #[test]
    fn twip_parse_checks_shape() {
        let ok = br#"{"generatedAt":"2026-11-11","groups":[{"id":"a","name":"A","asns":[1],"v4":["1.0.0.0/24"],"v6":["2001:db8::/32"]},{"id":"b","name":"B","v4":["1.0.1.0/24"]}]}"#;
        let t = TwIp::parse(ok).unwrap();
        assert_eq!(t.groups.len(), 2);
        assert_eq!(t.all().v4.ranges(), &[(v4("1.0.0.0"), v4("1.0.1.255"))]);
        assert!(t.group("a").unwrap().nets.contains("2001:db8::5".parse().unwrap()));
        for bad in [
            &br#"{"groups":[]}"#[..],
            br#"{"generatedAt":"x","groups":[{"id":"a","v4":["1.0.0.0/33"]}]}"#,
            br#"{"generatedAt":"x","groups":[{"id":"a","v4":["1.0.0.0/8"]},{"id":"a"}]}"#,
            br#"{"generatedAt":"x","groups":[{"id":"*","v4":["1.0.0.0/8"]}]}"#,
            br#"{"generatedAt":"x","groups":[{"id":"a","v6":["2001:db8::/32"]}]}"#,
            b"not json",
        ] {
            assert!(TwIp::parse(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }
}
