//! DNS 封包工具（RFC 1035）。
//!
//! 第一階段只做轉發需要的部分：讀標頭、讀第一個問題、改 id、產生錯誤回應。
//! EDNS / ECS / SVCB / EDE / Padding 依規格 01 第 3 節陸續加入。

pub mod logic;
pub mod message;
pub use message::{Message, RData};

pub const HEADER_LEN: usize = 12;
/// 回應碼
pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_FORMERR: u8 = 1;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NOTIMP: u8 = 4;
pub const RCODE_REFUSED: u8 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub id: u16,
    pub qr: bool,
    pub opcode: u8,
    pub tc: bool,
    pub rd: bool,
    pub rcode: u8,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// 小寫、不含結尾的點；根網域是空字串
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    /// 問題區段在封包裡的結束位置
    pub end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    TooShort,
    BadName,
    NoQuestion,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Error::TooShort => "封包太短",
            Error::BadName => "網域名稱格式錯誤",
            Error::NoQuestion => "沒有問題區段",
        })
    }
}

impl std::error::Error for Error {}

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

pub fn header(b: &[u8]) -> Result<Header, Error> {
    if b.len() < HEADER_LEN {
        return Err(Error::TooShort);
    }
    Ok(Header {
        id: u16_at(b, 0).unwrap(),
        qr: b[2] & 0x80 != 0,
        opcode: (b[2] >> 3) & 0x0f,
        tc: b[2] & 0x02 != 0,
        rd: b[2] & 0x01 != 0,
        rcode: b[3] & 0x0f,
        qdcount: u16_at(b, 4).unwrap(),
        ancount: u16_at(b, 6).unwrap(),
        nscount: u16_at(b, 8).unwrap(),
        arcount: u16_at(b, 10).unwrap(),
    })
}

/// 讀第一個問題（問題區段不會用名稱壓縮）
pub fn question(b: &[u8]) -> Result<Question, Error> {
    let h = header(b)?;
    if h.qdcount == 0 {
        return Err(Error::NoQuestion);
    }
    let mut i = HEADER_LEN;
    let mut name = String::new();
    loop {
        let len = *b.get(i).ok_or(Error::TooShort)? as usize;
        i += 1;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 || name.len() + len > 254 {
            return Err(Error::BadName);
        }
        let label = b.get(i..i + len).ok_or(Error::TooShort)?;
        if !name.is_empty() {
            name.push('.');
        }
        for &c in label {
            name.push(c.to_ascii_lowercase() as char);
        }
        i += len;
    }
    let qtype = u16_at(b, i).ok_or(Error::TooShort)?;
    let qclass = u16_at(b, i + 2).ok_or(Error::TooShort)?;
    Ok(Question {
        name,
        qtype,
        qclass,
        end: i + 4,
    })
}

pub fn set_id(b: &mut [u8], id: u16) {
    if b.len() >= 2 {
        b[..2].copy_from_slice(&id.to_be_bytes());
    }
}

/// 由查詢產生只有標頭與問題的錯誤回應（SERVFAIL、REFUSED…）
pub fn error_response(query: &[u8], rcode: u8) -> Vec<u8> {
    let qend = question(query).map(|q| q.end).unwrap_or(HEADER_LEN.min(query.len()));
    let mut r = query[..qend].to_vec();
    r.resize(qend.max(HEADER_LEN), 0);
    let has_q = qend > HEADER_LEN;
    r[2] = 0x80 | (r[2] & 0x79); // QR=1，保留 opcode 與 RD，清掉 AA / TC
    r[3] = 0x80 | (rcode & 0x0f); // RA=1
    r[4..6].copy_from_slice(&(has_q as u16).to_be_bytes());
    r[6..12].fill(0);
    r
}

/// 查詢帶的 EDNS UDP 大小（OPT 記錄的 class 欄位）；沒有 OPT 回 None。
/// 只掃過記錄的外框，不展開名稱，給「UDP 回應要不要截斷」這種每個封包都要問的地方用。
pub fn edns_udp_size(b: &[u8]) -> Option<u16> {
    let h = header(b).ok()?;
    let mut i = HEADER_LEN;
    for _ in 0..h.qdcount {
        i = skip_name(b, i).ok()? + 4;
    }
    for _ in 0..h.ancount as usize + h.nscount as usize + h.arcount as usize {
        i = skip_name(b, i).ok()?;
        if u16_at(b, i)? == message::rtype::OPT {
            return u16_at(b, i + 2);
        }
        i += 10 + u16_at(b, i + 8)? as usize;
    }
    None
}

/// 用戶端這次 UDP 查詢最多能收多大的回應：沒有 EDNS 是 512（RFC 1035），
/// 有 EDNS 用它宣告的大小，但不低於 512、不超過 1232（避免 IP 分片，DNS Flag Day 2020 的建議值）
pub fn udp_limit(query: &[u8]) -> usize {
    match edns_udp_size(query) {
        Some(n) => (n as usize).clamp(512, 1232),
        None => 512,
    }
}

/// 回應放不進去時改回的「截斷」回應：標頭照原本的回應（rcode、RA…）、只留問題、TC=1，
/// 用戶端看到 TC 會改用 TCP 重問。查詢有 EDNS 的話帶一筆空的 OPT（RFC 6891 第 7 節）
pub fn truncated_response(query: &[u8], resp: &[u8]) -> Vec<u8> {
    let rcode = header(resp).map(|h| h.rcode).unwrap_or(RCODE_NOERROR);
    let mut r = error_response(query, rcode);
    r[2] |= 0x02;
    if edns_udp_size(query).is_some() {
        r[11] = 1;
        r.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
    }
    r
}

/// 回應是否對應這個查詢（id 與問題都一樣）
pub fn matches(query: &[u8], resp: &[u8]) -> bool {
    match (header(query), header(resp), question(query), question(resp)) {
        (Ok(hq), Ok(hr), Ok(q), Ok(r)) => hr.qr && hq.id == hr.id && q.name == r.name && q.qtype == r.qtype && q.qclass == r.qclass,
        _ => false,
    }
}

/// 回應裡的一筆資源記錄（只取轉發與診斷需要的欄位）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub rtype: u16,
    pub ttl: u32,
    pub data: Vec<u8>,
}

/// 跳過一個（可能壓縮的）名稱，回傳下一個位置
fn skip_name(b: &[u8], mut i: usize) -> Result<usize, Error> {
    loop {
        let len = *b.get(i).ok_or(Error::TooShort)?;
        if len & 0xc0 == 0xc0 {
            b.get(i + 1).ok_or(Error::TooShort)?;
            return Ok(i + 2);
        }
        if len & 0xc0 != 0 {
            return Err(Error::BadName);
        }
        i += 1 + len as usize;
        if len == 0 {
            return Ok(i);
        }
    }
}

/// 讀答案區段的所有記錄
pub fn answers(b: &[u8]) -> Result<Vec<Record>, Error> {
    let h = header(b)?;
    let mut i = HEADER_LEN;
    for _ in 0..h.qdcount {
        i = skip_name(b, i)? + 4;
    }
    let mut out = Vec::with_capacity(h.ancount as usize);
    for _ in 0..h.ancount {
        i = skip_name(b, i)?;
        let rtype = u16_at(b, i).ok_or(Error::TooShort)?;
        let ttl = u32::from_be_bytes(b.get(i + 4..i + 8).ok_or(Error::TooShort)?.try_into().unwrap());
        let len = u16_at(b, i + 8).ok_or(Error::TooShort)? as usize;
        let data = b.get(i + 10..i + 10 + len).ok_or(Error::TooShort)?.to_vec();
        out.push(Record { rtype, ttl, data });
        i += 10 + len;
    }
    Ok(out)
}

/// 組一個查詢（測試與健康檢查用）
pub fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut b = Vec::with_capacity(HEADER_LEN + name.len() + 6);
    b.extend_from_slice(&id.to_be_bytes());
    b.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.').filter(|l| !l.is_empty()) {
        b.push(label.len() as u8);
        b.extend_from_slice(label.as_bytes());
    }
    b.push(0);
    b.extend_from_slice(&qtype.to_be_bytes());
    b.extend_from_slice(&1u16.to_be_bytes());
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_query() {
        let q = build_query(0x1234, "WWW.Example.com.", 28);
        let h = header(&q).unwrap();
        assert_eq!(h.id, 0x1234);
        assert!(!h.qr && h.rd);
        let qs = question(&q).unwrap();
        assert_eq!(qs.name, "www.example.com");
        assert_eq!(qs.qtype, 28);
        assert_eq!(qs.end, q.len());
    }

    #[test]
    fn root_and_errors() {
        assert_eq!(question(&build_query(1, ".", 2)).unwrap().name, "");
        assert_eq!(header(&[0; 5]), Err(Error::TooShort));
        let mut bad = build_query(1, "a.b", 1);
        bad[12] = 0xc0;
        assert_eq!(question(&bad), Err(Error::BadName));
    }

    #[test]
    fn read_answers() {
        let q = build_query(9, "a.test", 1);
        let mut r = q.clone();
        r[2] = 0x81;
        r[3] = 0x80;
        r[6..8].copy_from_slice(&2u16.to_be_bytes());
        for ip in [[1, 2, 3, 4], [5, 6, 7, 8]] {
            r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0, 0, 4]);
            r.extend_from_slice(&ip);
        }
        let a = answers(&r).unwrap();
        assert_eq!(a.len(), 2);
        assert_eq!((a[1].rtype, a[1].ttl, a[1].data.as_slice()), (1, 256, &[5u8, 6, 7, 8][..]));
        assert_eq!(answers(&r[..r.len() - 1]), Err(Error::TooShort));
    }

    #[test]
    fn udp_limit_and_truncation() {
        use crate::message::{Message, Opt};
        let plain = build_query(7, "example.com", 1);
        assert_eq!(edns_udp_size(&plain), None);
        assert_eq!(udp_limit(&plain), 512);
        let with = |size: u16| {
            let mut m = Message::parse(&plain).unwrap();
            m.opt = Some(Opt {
                udp_size: size,
                ..Default::default()
            });
            m.encode()
        };
        assert_eq!(edns_udp_size(&with(4096)), Some(4096));
        assert_eq!(udp_limit(&with(4096)), 1232, "不超過 1232");
        assert_eq!(udp_limit(&with(900)), 900, "用戶端宣告比較小就照它的");
        assert_eq!(udp_limit(&with(100)), 512, "不低於 512");
        // 截斷回應：TC=1、只有問題；查詢有 EDNS 才帶 OPT
        let mut resp = error_response(&plain, 3);
        resp.extend_from_slice(&[0; 600]);
        let t = truncated_response(&plain, &resp);
        let h = header(&t).unwrap();
        assert!(h.tc && h.qr);
        assert_eq!((h.id, h.rcode, h.qdcount, h.ancount, h.arcount), (7, 3, 1, 0, 0));
        assert!(matches(&plain, &t));
        let t = truncated_response(&with(1232), &resp);
        let m = Message::parse(&t).unwrap();
        assert!(m.flags & crate::message::FLAG_TC != 0);
        assert_eq!(m.opt.unwrap().udp_size, 1232);
        assert!(t.len() < 60);
    }

    #[test]
    fn servfail_keeps_question() {
        let q = build_query(7, "example.com", 1);
        let r = error_response(&q, RCODE_SERVFAIL);
        let h = header(&r).unwrap();
        assert!(h.qr && h.rd);
        assert_eq!((h.id, h.rcode, h.qdcount, h.ancount), (7, RCODE_SERVFAIL, 1, 0));
        assert!(matches(&q, &r));
        let mut other = r.clone();
        set_id(&mut other, 8);
        assert!(!matches(&q, &other));
    }

    #[test]
    fn question_match_ignores_letter_case() {
        // 網域名稱不分大小寫（RFC 4343）：上游把問題改成小寫或大小寫混合都算同一題
        let q = build_query(9, "WWW.Example.COM", 1);
        let r = error_response(&build_query(9, "www.example.com", 1), RCODE_SERVFAIL);
        assert!(matches(&q, &r));
        let other = error_response(&build_query(9, "www.example.net", 1), RCODE_SERVFAIL);
        assert!(!matches(&q, &other), "不同名稱仍然不算");
    }
}
