//! 完整的 DNS 訊息：解析（含名稱壓縮）與編碼（壓縮擁有者名稱與常見記錄裡的名稱）。
//!
//! 解析時名稱一律展開成字串（保留原本的大小寫，比對時用小寫），未知類型的 RDATA 原封保留。
//! EDNS 的 OPT 記錄另外放在 `Message::opt`，不放進 additionals。

use crate::Error;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

pub mod rtype {
    pub const A: u16 = 1;
    pub const NS: u16 = 2;
    pub const CNAME: u16 = 5;
    pub const SOA: u16 = 6;
    pub const PTR: u16 = 12;
    pub const MX: u16 = 15;
    pub const TXT: u16 = 16;
    pub const AAAA: u16 = 28;
    pub const SRV: u16 = 33;
    pub const DNAME: u16 = 39;
    pub const OPT: u16 = 41;
    pub const SVCB: u16 = 64;
    pub const HTTPS: u16 = 65;
}

/// EDNS 選項代碼
pub mod opt_code {
    pub const ECS: u16 = 8;
    pub const COOKIE: u16 = 10;
    pub const PADDING: u16 = 12;
    pub const EDE: u16 = 15;
}

pub const FLAG_QR: u16 = 0x8000;
pub const FLAG_AA: u16 = 0x0400;
pub const FLAG_TC: u16 = 0x0200;
pub const FLAG_RD: u16 = 0x0100;
pub const FLAG_RA: u16 = 0x0080;
pub const FLAG_AD: u16 = 0x0020;
pub const FLAG_CD: u16 = 0x0010;
/// OPT 的 DO 位元（DNSSEC OK）
pub const EDNS_DO: u16 = 0x8000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    /// CNAME、NS、PTR、DNAME
    Name(String),
    Mx(u16, String),
    Soa {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Raw(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub rtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: RData,
}

impl Record {
    pub fn a(name: &str, ttl: u32, ip: Ipv4Addr) -> Record {
        Record {
            name: name.to_string(),
            rtype: rtype::A,
            class: 1,
            ttl,
            data: RData::A(ip),
        }
    }
    pub fn aaaa(name: &str, ttl: u32, ip: Ipv6Addr) -> Record {
        Record {
            name: name.to_string(),
            rtype: rtype::AAAA,
            class: 1,
            ttl,
            data: RData::Aaaa(ip),
        }
    }
    /// CNAME / NS / PTR / DNAME 的目標名稱
    pub fn target(&self) -> Option<&str> {
        match &self.data {
            RData::Name(n) => Some(n),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Opt {
    pub udp_size: u16,
    pub ext_rcode: u8,
    pub version: u8,
    pub flags: u16,
    pub options: Vec<(u16, Vec<u8>)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Message {
    pub id: u16,
    /// 標頭第 3–4 bytes（不含 rcode 的低 4 位元）
    pub flags: u16,
    /// 完整 rcode（含 EDNS 擴充位元）
    pub rcode: u16,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
    pub opt: Option<Opt>,
}

/// 名稱比對用：小寫、去掉結尾的點
pub fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Result<u8, Error> {
        let v = *self.b.get(self.i).ok_or(Error::TooShort)?;
        self.i += 1;
        Ok(v)
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(((self.u8()? as u16) << 8) | self.u8()? as u16)
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(((self.u16()? as u32) << 16) | self.u16()? as u32)
    }
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let s = self.b.get(self.i..self.i + n).ok_or(Error::TooShort)?;
        self.i += n;
        Ok(s)
    }
    /// 讀一個名稱（處理壓縮指標，防止迴圈）
    fn name(&mut self) -> Result<String, Error> {
        let mut out = String::new();
        let mut pos = self.i;
        let mut jumped = false;
        let mut hops = 0;
        loop {
            let len = *self.b.get(pos).ok_or(Error::TooShort)? as usize;
            if len & 0xc0 == 0xc0 {
                let lo = *self.b.get(pos + 1).ok_or(Error::TooShort)? as usize;
                if !jumped {
                    self.i = pos + 2;
                    jumped = true;
                }
                hops += 1;
                if hops > 64 {
                    return Err(Error::BadName);
                }
                pos = ((len & 0x3f) << 8) | lo;
                continue;
            }
            if len & 0xc0 != 0 {
                return Err(Error::BadName);
            }
            if len == 0 {
                if !jumped {
                    self.i = pos + 1;
                }
                break;
            }
            let label = self.b.get(pos + 1..pos + 1 + len).ok_or(Error::TooShort)?;
            if !out.is_empty() {
                out.push('.');
            }
            for &c in label {
                // 不可列印或會造成歧義的字元用 \DDD 表示
                if c.is_ascii_graphic() && c != b'.' && c != b'\\' {
                    out.push(c as char);
                } else {
                    out.push_str(&format!("\\{c:03}"));
                }
            }
            if out.len() > 1024 {
                return Err(Error::BadName);
            }
            pos += 1 + len;
        }
        Ok(out)
    }
}

fn parse_record(r: &mut Reader) -> Result<(Record, Option<Opt>), Error> {
    let name = r.name()?;
    let rtype = r.u16()?;
    let class = r.u16()?;
    let ttl = r.u32()?;
    let len = r.u16()? as usize;
    let start = r.i;
    let end = start + len;
    if end > r.b.len() {
        return Err(Error::TooShort);
    }
    if rtype == rtype::OPT {
        let mut options = Vec::new();
        let mut o = Reader { b: &r.b[..end], i: start };
        while o.i < end {
            let code = o.u16()?;
            let l = o.u16()? as usize;
            options.push((code, o.bytes(l)?.to_vec()));
        }
        r.i = end;
        let opt = Opt {
            udp_size: class,
            ext_rcode: (ttl >> 24) as u8,
            version: (ttl >> 16) as u8,
            flags: ttl as u16,
            options,
        };
        return Ok((
            Record {
                name,
                rtype,
                class,
                ttl,
                data: RData::Raw(Vec::new()),
            },
            Some(opt),
        ));
    }
    let data = {
        let mut d = Reader { b: &r.b[..end], i: start };
        let v = match (rtype, len) {
            (rtype::A, 4) => RData::A(Ipv4Addr::new(d.u8()?, d.u8()?, d.u8()?, d.u8()?)),
            (rtype::AAAA, 16) => RData::Aaaa(Ipv6Addr::from(<[u8; 16]>::try_from(d.bytes(16)?).unwrap())),
            (rtype::CNAME | rtype::NS | rtype::PTR | rtype::DNAME, _) => {
                // 名稱可能指向封包前面，所以用完整封包讀
                let mut full = Reader { b: r.b, i: start };
                RData::Name(full.name()?)
            }
            (rtype::MX, _) => {
                let pref = d.u16()?;
                let mut full = Reader { b: r.b, i: start + 2 };
                RData::Mx(pref, full.name()?)
            }
            (rtype::SOA, _) => {
                let mut full = Reader { b: r.b, i: start };
                let mname = full.name()?;
                let rname = full.name()?;
                RData::Soa {
                    mname,
                    rname,
                    serial: full.u32()?,
                    refresh: full.u32()?,
                    retry: full.u32()?,
                    expire: full.u32()?,
                    minimum: full.u32()?,
                }
            }
            (rtype::SRV, _) => {
                let (priority, weight, port) = (d.u16()?, d.u16()?, d.u16()?);
                let mut full = Reader { b: r.b, i: start + 6 };
                RData::Srv {
                    priority,
                    weight,
                    port,
                    target: full.name()?,
                }
            }
            _ => RData::Raw(d.bytes(len)?.to_vec()),
        };
        v
    };
    r.i = end;
    Ok((
        Record {
            name,
            rtype,
            class,
            ttl,
            data,
        },
        None,
    ))
}

impl Message {
    pub fn parse(b: &[u8]) -> Result<Message, Error> {
        let mut r = Reader { b, i: 0 };
        let id = r.u16()?;
        let fl = r.u16()?;
        let (qd, an, ns, ar) = (r.u16()?, r.u16()?, r.u16()?, r.u16()?);
        let mut m = Message {
            id,
            flags: fl & 0xfff0,
            rcode: fl & 0x000f,
            ..Default::default()
        };
        for _ in 0..qd {
            let name = r.name()?;
            m.questions.push(Question {
                name,
                qtype: r.u16()?,
                qclass: r.u16()?,
            });
        }
        for _ in 0..an {
            m.answers.push(parse_record(&mut r)?.0);
        }
        for _ in 0..ns {
            m.authorities.push(parse_record(&mut r)?.0);
        }
        for _ in 0..ar {
            match parse_record(&mut r)? {
                (_, Some(opt)) => {
                    m.rcode |= (opt.ext_rcode as u16) << 4;
                    m.opt = Some(opt);
                }
                (rec, None) => m.additionals.push(rec),
            }
        }
        Ok(m)
    }

    pub fn question(&self) -> Option<&Question> {
        self.questions.first()
    }

    pub fn is_response(&self) -> bool {
        self.flags & FLAG_QR != 0
    }

    pub fn dnssec_ok(&self) -> bool {
        self.opt.as_ref().map(|o| o.flags & EDNS_DO != 0).unwrap_or(false)
    }

    /// 依照查詢產生回應的骨架：同 id、同問題、RD 照抄、RA=1；查詢有 EDNS 才加 OPT（1232）
    pub fn response_to(query: &Message, rcode: u16) -> Message {
        Message {
            id: query.id,
            flags: FLAG_QR | FLAG_RA | (query.flags & FLAG_RD) | (query.flags & FLAG_CD),
            rcode,
            questions: query.questions.clone(),
            opt: query.opt.as_ref().map(|_| Opt {
                udp_size: 1232,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer {
            b: Vec::with_capacity(512),
            names: HashMap::new(),
        };
        w.u16(self.id);
        w.u16((self.flags & 0xfff0) | (self.rcode & 0x0f));
        w.u16(self.questions.len() as u16);
        w.u16(self.answers.len() as u16);
        w.u16(self.authorities.len() as u16);
        w.u16((self.additionals.len() + self.opt.is_some() as usize) as u16);
        for q in &self.questions {
            w.name(&q.name, true);
            w.u16(q.qtype);
            w.u16(q.qclass);
        }
        for r in self.answers.iter().chain(&self.authorities).chain(&self.additionals) {
            w.record(r);
        }
        if let Some(o) = &self.opt {
            w.b.push(0);
            w.u16(rtype::OPT);
            w.u16(o.udp_size);
            let ext = ((self.rcode >> 4) & 0xff) as u32;
            w.u32((ext << 24) | ((o.version as u32) << 16) | o.flags as u32);
            let len: usize = o.options.iter().map(|(_, d)| 4 + d.len()).sum();
            w.u16(len as u16);
            for (code, d) in &o.options {
                w.u16(*code);
                w.u16(d.len() as u16);
                w.b.extend_from_slice(d);
            }
        }
        w.b
    }
}

struct Writer {
    b: Vec<u8>,
    /// 小寫名稱後綴 → 位置（只記 0x3fff 以內的位置）
    names: HashMap<String, u16>,
}

impl Writer {
    fn u16(&mut self, v: u16) {
        self.b.extend_from_slice(&v.to_be_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.b.extend_from_slice(&v.to_be_bytes());
    }

    /// 寫名稱；compress = 可以用前面出現過的後綴（並記下自己的後綴給後面用）
    fn name(&mut self, name: &str, compress: bool) {
        let labels = split_labels(name);
        for i in 0..labels.len() {
            let suffix = labels[i..]
                .iter()
                .map(|l| String::from_utf8_lossy(l).to_ascii_lowercase())
                .collect::<Vec<_>>()
                .join(".");
            if compress {
                if let Some(&pos) = self.names.get(&suffix) {
                    self.u16(0xc000 | pos);
                    return;
                }
                if self.b.len() < 0x3fff {
                    self.names.insert(suffix, self.b.len() as u16);
                }
            }
            let l = &labels[i];
            self.b.push(l.len() as u8);
            self.b.extend_from_slice(l);
        }
        self.b.push(0);
    }

    fn record(&mut self, r: &Record) {
        self.name(&r.name, true);
        self.u16(r.rtype);
        self.u16(r.class);
        self.u32(r.ttl);
        let len_pos = self.b.len();
        self.u16(0);
        let start = self.b.len();
        match &r.data {
            RData::A(ip) => self.b.extend_from_slice(&ip.octets()),
            RData::Aaaa(ip) => self.b.extend_from_slice(&ip.octets()),
            // RFC 3597：只有 RFC 1035 定義的類型可以壓縮 RDATA 裡的名稱
            RData::Name(n) => self.name(n, r.rtype != rtype::DNAME),
            RData::Mx(p, n) => {
                self.u16(*p);
                self.name(n, true);
            }
            RData::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                self.name(mname, true);
                self.name(rname, true);
                for v in [serial, refresh, retry, expire, minimum] {
                    self.u32(*v);
                }
            }
            RData::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                self.u16(*priority);
                self.u16(*weight);
                self.u16(*port);
                self.name(target, false);
            }
            RData::Raw(d) => self.b.extend_from_slice(d),
        }
        let len = (self.b.len() - start) as u16;
        self.b[len_pos..len_pos + 2].copy_from_slice(&len.to_be_bytes());
    }
}

/// 把名稱拆成標籤（處理 \DDD 與 \. 跳脫）
fn split_labels(name: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    let b = name.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'.' => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
                i += 1;
            }
            b'\\' if i + 3 < b.len() && b[i + 1..i + 4].iter().all(u8::is_ascii_digit) => {
                let v = (b[i + 1] - b'0') as u16 * 100 + (b[i + 2] - b'0') as u16 * 10 + (b[i + 3] - b'0') as u16;
                cur.push(v.min(255) as u8);
                i += 4;
            }
            b'\\' if i + 1 < b.len() => {
                cur.push(b[i + 1]);
                i += 2;
            }
            c => {
                cur.push(c);
                i += 1;
            }
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out.into_iter()
        .map(|mut l| {
            l.truncate(63);
            l
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Message {
        let q = Message::parse(&crate::build_query(0x1234, "WWW.Example.com", rtype::A)).unwrap();
        let mut m = Message::response_to(&q, 0);
        m.answers.push(Record {
            name: "WWW.Example.com".into(),
            rtype: rtype::CNAME,
            class: 1,
            ttl: 300,
            data: RData::Name("edge.cdn.example.net".into()),
        });
        m.answers.push(Record::a("edge.cdn.example.net", 60, Ipv4Addr::new(1, 2, 3, 4)));
        m.answers
            .push(Record::aaaa("edge.cdn.example.net", 60, "2001:db8::1".parse().unwrap()));
        m.authorities.push(Record {
            name: "example.net".into(),
            rtype: rtype::SOA,
            class: 1,
            ttl: 900,
            data: RData::Soa {
                mname: "ns1.example.net".into(),
                rname: "hostmaster.example.net".into(),
                serial: 1,
                refresh: 2,
                retry: 3,
                expire: 4,
                minimum: 120,
            },
        });
        m.answers.push(Record {
            name: "example.net".into(),
            rtype: rtype::TXT,
            class: 1,
            ttl: 5,
            data: RData::Raw(b"\x05hello".to_vec()),
        });
        m.opt = Some(Opt {
            udp_size: 1232,
            flags: EDNS_DO,
            options: vec![(opt_code::EDE, vec![0, 17])],
            ..Default::default()
        });
        m
    }

    #[test]
    fn roundtrip_with_compression() {
        let m = sample();
        let b = m.encode();
        let back = Message::parse(&b).unwrap();
        assert_eq!(back, m);
        // 壓縮有效：同樣的名稱只出現一次
        let raw = String::from_utf8_lossy(&b);
        assert_eq!(raw.matches("xample").count(), 2, "example.com 與 example.net 各一次");
        // 舊的簡易解析器也讀得懂
        assert_eq!(crate::answers(&b).unwrap().len(), 4);
        assert!(back.dnssec_ok());
    }

    #[test]
    fn pointer_loop_and_garbage() {
        // 指標指向自己
        let mut b = crate::build_query(1, "a.b", 1);
        b[1] = 1;
        let mut r = b[..12].to_vec();
        r[5] = 1; // qdcount=1
        r.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
        assert_eq!(Message::parse(&r), Err(Error::BadName));
        assert!(Message::parse(&[0; 5]).is_err());
        // 亂數資料不能讓解析器 panic
        let mut x: u32 = 12345;
        for _ in 0..2000 {
            let mut buf = sample().encode();
            for _ in 0..4 {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                let i = x as usize % buf.len();
                buf[i] = (x >> 8) as u8;
            }
            let _ = Message::parse(&buf);
        }
    }

    #[test]
    fn escapes_and_case() {
        let mut m = sample();
        m.answers[0].data = RData::Name("we\\.ird\\032name.example.net".into());
        let back = Message::parse(&m.encode()).unwrap();
        // 點用 \046 表示，編碼回去是同樣的位元組
        assert_eq!(back.answers[0].target(), Some("we\\046ird\\032name.example.net"));
        assert_eq!(Message::parse(&back.encode()).unwrap(), back);
        assert_eq!(back.questions[0].name, "WWW.Example.com", "保留大小寫");
        assert_eq!(normalize("WWW.Example.COM."), "www.example.com");
    }
}
