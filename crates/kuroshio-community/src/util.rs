//! 小工具：時間、亂數、雜湊、網域與位址檢查

use ring::rand::{SecureRandom, SystemRandom};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

pub const MINUTE: u64 = 60_000;
pub const HOUR: u64 = 3_600_000;
pub const DAY: u64 = 86_400_000;

/// Unix 毫秒
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    SystemRandom::new().fill(&mut b).expect("系統亂數");
    b
}

/// 0..n 之間的亂數（n = 0 回 0）
pub fn random_below(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    u64::from_le_bytes(random_bytes::<8>()) % n
}

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut c = ring::digest::Context::new(&ring::digest::SHA256);
    for p in parts {
        c.update(p);
    }
    let d = c.finish();
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

pub fn hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

pub fn b64(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

pub fn unb64(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s.trim()).ok()
}

/// 網域格式（同 v1 的 DOMAIN_RE）：至少兩段、每段 1–63 個英數或連字號、頂級網域 2–63 個英文字母
pub fn valid_domain(d: &str) -> bool {
    if d.is_empty() || d.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = d.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let tld = labels[labels.len() - 1];
    if tld.len() < 2 || tld.len() > 63 || !tld.bytes().all(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    labels.iter().all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    })
}

/// 私有、保留、本機、多播等不該出現在公開資料裡的位址
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_broadcast()
                || v.is_documentation()
                || v.is_unspecified()
                || v.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // CGNAT 100.64/10
                || (o[0] == 198 && (o[1] & 0xfe) == 18) // 測試網段 198.18/15
                || o[0] >= 240
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            if let Some(m) = v.to_ipv4_mapped() {
                return is_private_ip(IpAddr::V4(m));
            }
            v.is_loopback()
                || v.is_unspecified()
                || v.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // ULA
                || (s[0] & 0xffc0) == 0xfe80 // link-local
                || (s[0] == 0x2001 && s[1] == 0x0db8) // 文件用
                || (s[0] & 0xe000) != 0x2000 // 不在全球單播範圍
        }
    }
}

/// 網站雜湊：SHA-256("kuroshio/site\0" || 網域小寫)[0..12]
pub fn site_hash(name: &str) -> [u8; 12] {
    let n = name.trim_end_matches('.').to_ascii_lowercase();
    let d = sha256(&[b"kuroshio/site\0", n.as_bytes()]);
    let mut out = [0u8; 12];
    out.copy_from_slice(&d[..12]);
    out
}

/// 好友網域雜湊（身分文件的 friends，算共同好友用）：SHA-256("kuroshio/friend\0" || 網域)[0..8]
pub fn friend_hash(domain: &str) -> [u8; 8] {
    let d = sha256(&[b"kuroshio/friend\0", domain.to_ascii_lowercase().as_bytes()]);
    let mut out = [0u8; 8];
    out.copy_from_slice(&d[..8]);
    out
}

/// 截斷字串（以字元為單位，不會切到半個 UTF-8 字元）
pub fn clip(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

/// 給人看的日期（UTC，事件說明用）
pub fn fmt_date(ms: u64) -> String {
    let days = (ms / DAY) as i64;
    // 公曆換算（Howard Hinnant 的 civil_from_days）
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains() {
        assert!(valid_domain("dns.example.com"));
        assert!(valid_domain("a.test"));
        assert!(!valid_domain("localhost"));
        assert!(!valid_domain("a..com"));
        assert!(!valid_domain("-a.com"));
        assert!(!valid_domain("a.c0m"));
    }

    #[test]
    fn private() {
        for ip in [
            "10.0.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "100.64.1.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "0.1.2.3",
            "224.0.0.1",
        ] {
            assert!(is_private_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["104.16.1.1", "8.8.8.8", "2606:4700::1111"] {
            assert!(!is_private_ip(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn hex_and_dates() {
        assert_eq!(hex(&[0, 0xab, 0x10]), "00ab10");
        assert_eq!(unhex("00ab10").unwrap(), vec![0, 0xab, 0x10]);
        assert_eq!(fmt_date(0), "1970-01-01");
        assert_eq!(fmt_date(1_700_000_000_000), "2023-11-14");
    }
}
