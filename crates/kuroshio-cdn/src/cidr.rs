//! CIDR 集合（對齊 2.x `lib/cidr.js`）：排序合併後的區段，用二分搜尋判斷 IP 在不在裡面。
//! IPv4 每段 8 bytes、IPv6 每段 32 bytes；CloudFront 一萬多個 /24 合併後只剩幾百段。

use std::net::IpAddr;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CidrSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
    sorted: bool,
}

impl CidrSet {
    pub fn new() -> CidrSet {
        CidrSet {
            sorted: true,
            ..Default::default()
        }
    }

    /// 加一筆（`a.b.c.d/len`、單一 IP、v6 同理）；註解、空行、格式錯誤回 false
    pub fn add(&mut self, cidr: &str) -> bool {
        let s = cidr.trim();
        if s.is_empty() || s.starts_with('#') {
            return false;
        }
        let (ip, len) = match s.split_once('/') {
            Some((a, b)) => (a.trim(), Some(b.trim())),
            None => (s, None),
        };
        let Some(ip) = crate::util::parse_ip(ip) else { return false };
        match ip {
            IpAddr::V4(v) => {
                let len: u32 = match len {
                    None => 32,
                    Some(l) => match l.parse() {
                        Ok(n) if n <= 32 => n,
                        _ => return false,
                    },
                };
                let host = 32 - len;
                let mask = if len == 0 { 0 } else { u32::MAX << host };
                let start = u32::from(v) & mask;
                let end = start | !mask;
                self.v4.push((start, end));
            }
            IpAddr::V6(v) => {
                let len: u32 = match len {
                    None => 128,
                    Some(l) => match l.parse() {
                        Ok(n) if n <= 128 => n,
                        _ => return false,
                    },
                };
                let host = 128 - len;
                let mask = if len == 0 { 0 } else { u128::MAX << host };
                let start = u128::from(v) & mask;
                self.v6.push((start, start | !mask));
            }
        }
        self.sorted = false;
        true
    }

    pub fn add_many<'a>(&mut self, list: impl IntoIterator<Item = &'a str>) -> &mut Self {
        for c in list {
            self.add(c);
        }
        self
    }

    /// 清單檔內容（每行一筆，去 BOM）
    pub fn add_text(&mut self, text: &str) -> &mut Self {
        for l in text.trim_start_matches('\u{feff}').lines() {
            self.add(l);
        }
        self
    }

    pub fn add_v4_range(&mut self, start: u32, end: u32) {
        self.v4.push((start, end));
        self.sorted = false;
    }

    /// 把另一個集合的區段全部加進來（之後要 `finalize`）
    pub fn extend_from(&mut self, o: &CidrSet) {
        self.v4.extend_from_slice(&o.v4);
        self.v6.extend_from_slice(&o.v6);
        self.sorted = false;
    }

    /// 排序並合併相鄰 / 重疊的區段
    pub fn finalize(&mut self) -> &mut Self {
        fn merge<T: Ord + Copy>(arr: &mut Vec<(T, T)>, adjacent: impl Fn(T, T) -> bool) {
            arr.sort_unstable();
            let mut out: Vec<(T, T)> = Vec::with_capacity(arr.len());
            for &(a, b) in arr.iter() {
                if let Some(last) = out.last_mut() {
                    if a <= last.1 || adjacent(last.1, a) {
                        if b > last.1 {
                            last.1 = b;
                        }
                        continue;
                    }
                }
                out.push((a, b));
            }
            out.shrink_to_fit();
            *arr = out;
        }
        merge(&mut self.v4, |end, a| end.checked_add(1) == Some(a));
        merge(&mut self.v6, |end, a| end.checked_add(1) == Some(a));
        self.sorted = true;
        self
    }

    pub fn done(mut self) -> CidrSet {
        self.finalize();
        self
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        debug_assert!(self.sorted, "CidrSet 要先 finalize");
        match ip {
            IpAddr::V4(v) => find(&self.v4, u32::from(v)),
            IpAddr::V6(v) => match v.to_ipv4_mapped() {
                Some(m) => find(&self.v4, u32::from(m)),
                None => find(&self.v6, u128::from(v)),
            },
        }
    }

    /// 合併後的 IPv4 區段數
    pub fn v4_len(&self) -> usize {
        self.v4.len()
    }

    pub fn v6_len(&self) -> usize {
        self.v6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    /// 換算成幾個 /24（狀態頁顯示用，同 2.x 的 `count24`）
    pub fn count24(&self) -> u64 {
        self.v4
            .iter()
            .map(|&(a, b)| (((b as u64 - a as u64 + 1) as f64 / 256.0).round() as u64).max(1))
            .sum()
    }
}

fn find<T: Ord + Copy>(arr: &[(T, T)], v: T) -> bool {
    // 第一個起點 > v 的位置，前一段就是唯一可能包含 v 的區段
    let i = arr.partition_point(|r| r.0 <= v);
    i > 0 && arr[i - 1].1 >= v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn membership_and_merge() {
        let mut s = CidrSet::new();
        s.add_many([
            "104.16.0.0/13",
            "104.24.0.0/14",
            "# 註解",
            "",
            "bad",
            "1.2.3.4",
            "2606:4700::/32",
            "10.0.0.0/33",
        ]);
        s.finalize();
        assert_eq!(s.v4_len(), 2, "104.16/13 與 104.24/14 相鄰，合併成一段");
        assert!(s.contains(ip("104.16.161.36")));
        assert!(s.contains(ip("104.27.255.255")));
        assert!(!s.contains(ip("104.28.0.0")));
        assert!(s.contains(ip("1.2.3.4")));
        assert!(!s.contains(ip("1.2.3.5")));
        assert!(s.contains(ip("2606:4700:3030::1")));
        assert!(!s.contains(ip("2606:4701::1")));
        assert!(s.contains(ip("::ffff:104.16.0.1")), "IPv4-mapped 當成 IPv4");
        assert!(!s.contains(ip("10.0.0.1")));
        let mut z = CidrSet::new();
        z.add("0.0.0.0/0");
        z.finalize();
        assert!(z.contains(ip("255.255.255.255")));
        assert_eq!(z.count24(), 1 << 24);
    }
}
