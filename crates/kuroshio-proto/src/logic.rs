//! 解析流程用的判斷與回應產生（對齊 2.x 的 `lib/dnsmsg.js`）

use crate::message::{normalize, opt_code, rtype, Message, Opt, RData, Record, EDNS_DO};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// 上游回應的分類
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    Ok,
    NoData,
    NxDomain,
    /// 被上游自己的過濾擋掉（0.0.0.0 之類的 sinkhole 位址）
    Blocked,
    ServFail,
    Refused,
    Error,
}

/// 各家過濾型 DNS 的 sinkhole 位址（同 2.x）
const SINKHOLE_V4: [[u8; 4]; 12] = [
    [0, 0, 0, 0],
    [127, 0, 0, 1],
    [0, 0, 0, 1],
    [127, 0, 0, 2],
    [146, 112, 61, 104],
    [146, 112, 61, 105],
    [146, 112, 61, 106],
    [146, 112, 61, 107],
    [146, 112, 61, 108],
    [146, 112, 61, 110],
    [94, 140, 14, 35],
    [94, 140, 14, 33],
];

pub fn is_sinkhole(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => SINKHOLE_V4.contains(&v4.octets()),
        IpAddr::V6(v6) => v6.is_unspecified() || v6.is_loopback(),
    }
}

pub fn classify(msg: &Message, qtype: u16) -> Class {
    match msg.rcode {
        0 => {}
        3 => return Class::NxDomain,
        2 => return Class::ServFail,
        5 => return Class::Refused,
        _ => return Class::Error,
    }
    if msg.answers.is_empty() {
        return Class::NoData;
    }
    for a in &msg.answers {
        match a.data {
            RData::A(ip) if is_sinkhole(IpAddr::V4(ip)) => return Class::Blocked,
            RData::Aaaa(ip) if is_sinkhole(IpAddr::V6(ip)) => return Class::Blocked,
            _ => {}
        }
    }
    let has_type = msg.answers.iter().any(|a| a.rtype == qtype);
    if !has_type && (qtype == rtype::A || qtype == rtype::AAAA) {
        return Class::NoData; // 只有 CNAME 沒有最終位址
    }
    Class::Ok
}

/// 答案與權威區段的最小 TTL（不含 OPT）；沒有記錄回 fallback
pub fn min_ttl(msg: &Message, fallback: u32) -> u32 {
    msg.answers.iter().chain(&msg.authorities).map(|r| r.ttl).min().unwrap_or(fallback)
}

/// 否定回應的 TTL：SOA 的 min(ttl, minimum)，沒有 SOA 用 60
pub fn negative_ttl(msg: &Message) -> u32 {
    msg.authorities
        .iter()
        .find_map(|r| match &r.data {
            RData::Soa { minimum, .. } => Some(r.ttl.min(*minimum)),
            _ => None,
        })
        .unwrap_or(60)
}

/// CNAME 鏈的最後一個名稱（小寫、無結尾點）
pub fn terminal_name(msg: &Message, qname: &str) -> String {
    let mut cur = normalize(qname);
    for _ in 0..16 {
        let next = msg
            .answers
            .iter()
            .find(|a| a.rtype == rtype::CNAME && normalize(&a.name) == cur)
            .and_then(|a| a.target());
        match next {
            Some(t) => cur = normalize(t),
            None => break,
        }
    }
    cur
}

/// 回應裡所有 CNAME 的目標
pub fn cname_targets(msg: &Message) -> Vec<String> {
    msg.answers
        .iter()
        .filter(|a| a.rtype == rtype::CNAME)
        .filter_map(|a| a.target())
        .map(normalize)
        .collect()
}

/// A / AAAA 記錄的 IP
pub fn ip_of(r: &Record) -> Option<IpAddr> {
    match r.data {
        RData::A(ip) => Some(IpAddr::V4(ip)),
        RData::Aaaa(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    }
}

/// 回應裡某個類型的所有 IP
pub fn ips_of(msg: &Message, qtype: u16) -> Vec<IpAddr> {
    msg.answers.iter().filter(|a| a.rtype == qtype).filter_map(ip_of).collect()
}

/// ECS 選項（RFC 7871）內容
pub fn ecs_option(ip: IpAddr, prefix: u8) -> Vec<u8> {
    let (family, bytes, max): (u16, Vec<u8>, u8) = match ip {
        IpAddr::V4(v) => (1, v.octets().to_vec(), 32),
        IpAddr::V6(v) => (2, v.octets().to_vec(), 128),
    };
    let prefix = prefix.min(max);
    let n = (prefix as usize).div_ceil(8);
    let mut addr = bytes[..n].to_vec();
    if prefix % 8 != 0 {
        if let Some(last) = addr.last_mut() {
            *last &= 0xffu8 << (8 - prefix % 8);
        }
    }
    let mut out = family.to_be_bytes().to_vec();
    out.push(prefix);
    out.push(0);
    out.extend_from_slice(&addr);
    out
}

/// 由用戶端查詢重新產生乾淨的上游查詢：統一 EDNS 1232、照抄 DO、可加 ECS
pub fn upstream_query(client: &Message, id: u16, ecs: Option<(IpAddr, u8)>) -> Message {
    let mut options = Vec::new();
    if let Some((ip, p)) = ecs {
        options.push((opt_code::ECS, ecs_option(ip, p)));
    }
    Message {
        id,
        flags: crate::message::FLAG_RD | (client.flags & crate::message::FLAG_CD),
        rcode: 0,
        questions: client.questions.iter().take(1).cloned().collect(),
        opt: Some(Opt {
            udp_size: 1232,
            flags: if client.dnssec_ok() { EDNS_DO } else { 0 },
            options,
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Extended DNS Errors（RFC 8914）的資訊代碼
pub mod ede {
    pub const STALE_ANSWER: u16 = 3;
    pub const BLOCKED: u16 = 15;
    pub const FILTERED: u16 = 17;
    pub const NO_REACHABLE_AUTHORITY: u16 = 22;
}

/// 用戶端有 EDNS 時加上 EDE
pub fn add_ede(resp: &mut Message, code: u16, text: &str) {
    if let Some(o) = resp.opt.as_mut() {
        let mut d = code.to_be_bytes().to_vec();
        d.extend_from_slice(text.as_bytes());
        o.options.push((opt_code::EDE, d));
    }
}

/// 被封鎖的回應（同 2.x）：A → 0.0.0.0、AAAA → ::、其他 → 空回應；TTL 10 秒
pub fn blocked_response(query: &Message, ede_code: u16, why: &str) -> Message {
    let mut r = Message::response_to(query, 0);
    if let Some(q) = query.question() {
        match q.qtype {
            rtype::A => r.answers.push(Record::a(&q.name, 10, Ipv4Addr::UNSPECIFIED)),
            rtype::AAAA => r.answers.push(Record::aaaa(&q.name, 10, Ipv6Addr::UNSPECIFIED)),
            _ => {}
        }
    }
    add_ede(&mut r, ede_code, why);
    r
}

pub fn servfail(query: &Message) -> Message {
    let mut r = Message::response_to(query, 2);
    add_ede(&mut r, ede::NO_REACHABLE_AUTHORITY, "所有上游都沒有回應");
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_query;

    fn resp(rcode: u16, answers: Vec<Record>) -> Message {
        let q = Message::parse(&build_query(1, "a.test", 1)).unwrap();
        let mut m = Message::response_to(&q, rcode);
        m.answers = answers;
        m
    }

    #[test]
    fn classification() {
        assert_eq!(classify(&resp(3, vec![]), 1), Class::NxDomain);
        assert_eq!(classify(&resp(0, vec![]), 1), Class::NoData);
        assert_eq!(
            classify(&resp(0, vec![Record::a("a.test", 60, Ipv4Addr::new(0, 0, 0, 0))]), 1),
            Class::Blocked
        );
        assert_eq!(
            classify(&resp(0, vec![Record::a("a.test", 60, Ipv4Addr::new(146, 112, 61, 106))]), 1),
            Class::Blocked
        );
        assert_eq!(
            classify(&resp(0, vec![Record::a("a.test", 60, Ipv4Addr::new(1, 1, 1, 1))]), 1),
            Class::Ok
        );
        let cname = Record {
            name: "a.test".into(),
            rtype: rtype::CNAME,
            class: 1,
            ttl: 60,
            data: RData::Name("b.test".into()),
        };
        assert_eq!(classify(&resp(0, vec![cname.clone()]), 1), Class::NoData, "只有 CNAME");
        assert_eq!(classify(&resp(0, vec![cname]), 16), Class::Ok);
        assert_eq!(classify(&resp(2, vec![]), 1), Class::ServFail);
    }

    #[test]
    fn chain_and_ttl() {
        let m = resp(
            0,
            vec![
                Record {
                    name: "A.test".into(),
                    rtype: rtype::CNAME,
                    class: 1,
                    ttl: 300,
                    data: RData::Name("B.test.".into()),
                },
                Record {
                    name: "b.test".into(),
                    rtype: rtype::CNAME,
                    class: 1,
                    ttl: 30,
                    data: RData::Name("c.test".into()),
                },
                Record::a("c.test", 120, Ipv4Addr::new(1, 2, 3, 4)),
            ],
        );
        assert_eq!(terminal_name(&m, "a.test."), "c.test");
        assert_eq!(cname_targets(&m), vec!["b.test", "c.test"]);
        assert_eq!(min_ttl(&m, 60), 30);
        assert_eq!(ips_of(&m, 1), vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
    }

    #[test]
    fn blocked_and_ede() {
        let mut q = Message::parse(&build_query(5, "ads.test", 28)).unwrap();
        q.opt = Some(Opt {
            udp_size: 4096,
            ..Default::default()
        });
        let r = Message::parse(&blocked_response(&q, ede::FILTERED, "廣告").encode()).unwrap();
        assert_eq!(r.answers[0].data, RData::Aaaa(Ipv6Addr::UNSPECIFIED));
        assert_eq!(r.answers[0].ttl, 10);
        let ede = &r.opt.as_ref().unwrap().options[0];
        assert_eq!(ede.0, opt_code::EDE);
        assert_eq!(&ede.1[..2], &17u16.to_be_bytes());
        // 沒有 EDNS 的查詢不加 OPT
        let q2 = Message::parse(&build_query(5, "ads.test", 1)).unwrap();
        assert!(blocked_response(&q2, ede::FILTERED, "x").opt.is_none());
    }

    #[test]
    fn ecs_and_upstream_query() {
        assert_eq!(ecs_option("203.0.113.77".parse().unwrap(), 24), vec![0, 1, 24, 0, 203, 0, 113]);
        assert_eq!(ecs_option("203.0.113.77".parse().unwrap(), 20), vec![0, 1, 20, 0, 203, 0, 112]);
        let mut c = Message::parse(&build_query(9, "x.test", 1)).unwrap();
        c.opt = Some(Opt {
            udp_size: 512,
            flags: EDNS_DO,
            ..Default::default()
        });
        let u = upstream_query(&c, 77, None);
        assert_eq!((u.id, u.opt.as_ref().unwrap().udp_size), (77, 1232));
        assert!(u.dnssec_ok());
    }
}

/// EDNS Padding（RFC 7830 / 8467）：把訊息補到 `block` 的倍數。沒有 OPT 的訊息不動
pub fn pad(msg: &mut Message, block: usize) {
    let Some(opt) = msg.opt.as_mut() else { return };
    opt.options.retain(|(c, _)| *c != crate::message::opt_code::PADDING);
    let len = msg.encode().len() + 4; // 加上 padding 選項本身的 4 bytes
    let n = (block - len % block) % block;
    msg.opt
        .as_mut()
        .unwrap()
        .options
        .push((crate::message::opt_code::PADDING, vec![0; n]));
}

/// 查詢有沒有帶 padding 選項（用戶端要求補齊）
pub fn wants_padding(msg: &Message) -> bool {
    msg.opt
        .as_ref()
        .map(|o| o.options.iter().any(|(c, _)| *c == crate::message::opt_code::PADDING))
        .unwrap_or(false)
}

/// DDR（RFC 9462）：`_dns.resolver.arpa` 的 SVCB 記錄
#[derive(Debug, Clone)]
pub struct DdrEndpoint {
    /// h2,h3 / dot / doq
    pub alpn: Vec<String>,
    pub port: u16,
    /// DoH 路徑（`/dns-query{?dns}` 範本）
    pub dohpath: Option<String>,
}

pub fn svcb_rdata(priority: u16, target: &str, ep: &DdrEndpoint) -> Vec<u8> {
    let mut b = priority.to_be_bytes().to_vec();
    for label in target.trim_end_matches('.').split('.').filter(|l| !l.is_empty()) {
        b.push(label.len().min(63) as u8);
        b.extend_from_slice(&label.as_bytes()[..label.len().min(63)]);
    }
    b.push(0);
    // SvcParams 依 key 由小到大：1 alpn、3 port、7 dohpath
    let mut alpn = Vec::new();
    for a in &ep.alpn {
        alpn.push(a.len() as u8);
        alpn.extend_from_slice(a.as_bytes());
    }
    let mut param = |key: u16, val: &[u8]| {
        b.extend_from_slice(&key.to_be_bytes());
        b.extend_from_slice(&(val.len() as u16).to_be_bytes());
        b.extend_from_slice(val);
    };
    param(1, &alpn);
    param(3, &ep.port.to_be_bytes());
    if let Some(p) = &ep.dohpath {
        param(7, p.as_bytes());
    }
    b
}

#[cfg(test)]
mod pad_tests {
    use super::*;
    use crate::message::Opt;

    #[test]
    fn padding_blocks() {
        let mut q = Message::parse(&crate::build_query(1, "a.test", 1)).unwrap();
        q.opt = Some(Opt {
            udp_size: 1232,
            options: vec![(crate::message::opt_code::PADDING, vec![])],
            ..Default::default()
        });
        assert!(wants_padding(&q));
        pad(&mut q, 128);
        assert_eq!(q.encode().len(), 128);
        pad(&mut q, 468);
        assert_eq!(q.encode().len(), 468, "重新補齊不會累加");
        let mut none = Message::parse(&crate::build_query(1, "a.test", 1)).unwrap();
        pad(&mut none, 128);
        assert!(none.opt.is_none());
    }

    #[test]
    fn svcb() {
        let ep = DdrEndpoint {
            alpn: vec!["h2".into(), "h3".into()],
            port: 8443,
            dohpath: Some("/dns-query{?dns}".into()),
        };
        let r = svcb_rdata(1, "dns.example.com", &ep);
        assert_eq!(&r[..2], &[0, 1]);
        assert_eq!(&r[2..19], b"\x03dns\x07example\x03com\x00");
        assert_eq!(&r[19..27], &[0, 1, 0, 6, 2, b'h', b'2', 2]);
        assert!(r.ends_with(b"/dns-query{?dns}"));
    }
}
