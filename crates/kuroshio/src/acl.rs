//! 來源 IP 存取控制（listen.plain.allowFrom）

use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct Cidr {
    net: IpAddr,
    bits: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Option<Cidr> {
        let (ip, bits) = match s.trim().split_once('/') {
            Some((ip, b)) => (ip, Some(b.parse::<u8>().ok()?)),
            None => (s.trim(), None),
        };
        let net: IpAddr = ip.parse().ok()?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        let bits = bits.unwrap_or(max);
        (bits <= max).then_some(Cidr { net, bits })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            v4 => v4,
        };
        match (self.net, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => prefix_eq(&n.octets(), &a.octets(), self.bits),
            (IpAddr::V6(n), IpAddr::V6(a)) => prefix_eq(&n.octets(), &a.octets(), self.bits),
            _ => false,
        }
    }
}

fn prefix_eq(a: &[u8], b: &[u8], bits: u8) -> bool {
    let full = (bits / 8) as usize;
    if a[..full] != b[..full] {
        return false;
    }
    let rest = bits % 8;
    rest == 0 || (a[full] ^ b[full]) & (0xffu8 << (8 - rest)) == 0
}

/// 空清單 = 全部允許
#[derive(Debug, Clone, Default)]
pub struct Acl(Vec<Cidr>);

impl Acl {
    pub fn new<'a>(list: impl IntoIterator<Item = &'a str>) -> Acl {
        Acl(list.into_iter().filter_map(Cidr::parse).collect())
    }
    pub fn allows(&self, ip: IpAddr) -> bool {
        self.0.is_empty() || self.0.iter().any(|c| c.contains(ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr() {
        let acl = Acl::new(["10.0.0.0/8", "192.168.0.0/16", "fc00::/7", "::1/128"]);
        for ok in ["10.1.2.3", "192.168.9.9", "fd12:3456::1", "::1", "::ffff:10.0.0.1"] {
            assert!(acl.allows(ok.parse().unwrap()), "{ok}");
        }
        for no in ["11.0.0.1", "192.169.0.1", "2001:db8::1", "8.8.8.8"] {
            assert!(!acl.allows(no.parse().unwrap()), "{no}");
        }
        assert!(Acl::default().allows("8.8.8.8".parse().unwrap()));
        assert!(Cidr::parse("1.2.3.4/33").is_none());
        assert!(Cidr::parse("100.64.0.0/10").unwrap().contains("100.127.255.255".parse().unwrap()));
        assert!(!Cidr::parse("100.64.0.0/10").unwrap().contains("100.128.0.0".parse().unwrap()));
    }
}
