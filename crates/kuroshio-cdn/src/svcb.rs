//! SVCB / HTTPS 記錄（type 64 / 65）的 ipv4hint / ipv6hint 讀取與改寫（同 2.x `dnsmsg.js` 的
//! `svcbHints` / `rewriteSvcbHints`）。瀏覽器會照提示直接連，CDN 改寫時要一起改。

use std::net::{Ipv4Addr, Ipv6Addr};

const KEY_V4: u16 = 4;
const KEY_V6: u16 = 6;

struct Svcb<'a> {
    /// 優先權 + 目標名稱（原始位元組）
    head: &'a [u8],
    params: Vec<(u16, &'a [u8])>,
}

fn parse(rdata: &[u8]) -> Option<Svcb<'_>> {
    if rdata.len() < 3 {
        return None;
    }
    // 目標名稱：不壓縮的 label 序列
    let mut i = 2;
    loop {
        let len = *rdata.get(i)? as usize;
        i += 1;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 {
            return None;
        }
        i += len;
        if i > rdata.len() {
            return None;
        }
    }
    let head = &rdata[..i];
    let mut params = Vec::new();
    while i + 4 <= rdata.len() {
        let key = u16::from_be_bytes([rdata[i], rdata[i + 1]]);
        let len = u16::from_be_bytes([rdata[i + 2], rdata[i + 3]]) as usize;
        let end = (i + 4 + len).min(rdata.len());
        params.push((key, &rdata[i + 4..end]));
        i += 4 + len;
    }
    Some(Svcb { head, params })
}

/// 讀出提示（格式錯誤回空的）
pub fn hints(rdata: &[u8]) -> (Vec<Ipv4Addr>, Vec<Ipv6Addr>) {
    let Some(s) = parse(rdata) else { return (vec![], vec![]) };
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for (k, v) in &s.params {
        if *k == KEY_V4 {
            v4.extend(v.chunks_exact(4).map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3])));
        }
        if *k == KEY_V6 {
            v6.extend(v.chunks_exact(16).map(|c| Ipv6Addr::from(<[u8; 16]>::try_from(c).unwrap())));
        }
    }
    (v4, v6)
}

/// 改寫方式
#[derive(Debug, Clone, PartialEq)]
pub enum Hint<T> {
    /// 保留原本的
    Keep,
    /// 拿掉這個提示
    Remove,
    /// 換成這些（空的等於拿掉）
    Set(Vec<T>),
}

/// 改寫 ipv4hint / ipv6hint；參數依 key 排序重新組回（同 2.x）。格式錯誤回 None
pub fn rewrite(rdata: &[u8], v4: &Hint<Ipv4Addr>, v6: &Hint<Ipv6Addr>) -> Option<Vec<u8>> {
    let s = parse(rdata)?;
    let mut params: Vec<(u16, Vec<u8>)> = s.params.iter().map(|(k, v)| (*k, v.to_vec())).collect();
    match v4 {
        Hint::Keep => {}
        h => {
            params.retain(|p| p.0 != KEY_V4);
            if let Hint::Set(l) = h {
                if !l.is_empty() {
                    params.push((KEY_V4, l.iter().flat_map(|ip| ip.octets()).collect()));
                }
            }
        }
    }
    match v6 {
        Hint::Keep => {}
        h => {
            params.retain(|p| p.0 != KEY_V6);
            if let Hint::Set(l) = h {
                if !l.is_empty() {
                    params.push((KEY_V6, l.iter().flat_map(|ip| ip.octets()).collect()));
                }
            }
        }
    }
    params.sort_by_key(|p| p.0);
    let mut out = s.head.to_vec();
    for (k, v) in params {
        out.extend_from_slice(&k.to_be_bytes());
        out.extend_from_slice(&(v.len() as u16).to_be_bytes());
        out.extend_from_slice(&v);
    }
    Some(out)
}

/// 測試用：組一筆 HTTPS 記錄（alpn h3,h2 + ipv4hint + 可選的 ipv6hint 2606:4700::1）
pub fn build_test_rdata(v4: &[&str], v6: bool) -> Vec<u8> {
    let mut out = vec![0, 1, 0];
    let mut p = |k: u16, v: &[u8]| {
        out.extend_from_slice(&k.to_be_bytes());
        out.extend_from_slice(&(v.len() as u16).to_be_bytes());
        out.extend_from_slice(v);
    };
    p(1, &[2, b'h', b'3', 2, b'h', b'2']);
    let b4: Vec<u8> = v4.iter().flat_map(|s| s.parse::<Ipv4Addr>().unwrap().octets()).collect();
    p(4, &b4);
    if v6 {
        p(6, &"2606:4700::1".parse::<Ipv6Addr>().unwrap().octets());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_and_rewrite() {
        // 對照 2.x selftest「SVCB 提示讀取 / 改寫」
        let r = build_test_rdata(&["104.16.1.1", "104.16.2.2"], true);
        let (v4, v6) = hints(&r);
        assert_eq!(v4, vec![Ipv4Addr::new(104, 16, 1, 1), Ipv4Addr::new(104, 16, 2, 2)]);
        assert_eq!(v6, vec!["2606:4700::1".parse::<Ipv6Addr>().unwrap()]);
        let out = rewrite(
            &build_test_rdata(&["104.16.1.1"], true),
            &Hint::Set(vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 0, 0, 1)]),
            &Hint::Remove,
        )
        .unwrap();
        let (v4, v6) = hints(&out);
        assert_eq!(v4, vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 0, 0, 1)]);
        assert!(v6.is_empty());
        assert!(out.windows(3).any(|w| w == [2, b'h', b'3']), "保留 alpn");
        assert_eq!(rewrite(&r, &Hint::Keep, &Hint::Keep).unwrap(), r);
        assert_eq!(hints(&[0, 1]), (vec![], vec![]));
        assert!(rewrite(&[0, 1, 5, b'a'], &Hint::Keep, &Hint::Remove).is_none());
    }
}
