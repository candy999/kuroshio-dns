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
    /// 走過一個名稱的所有標籤（處理壓縮指標），每個標籤呼叫一次 `f`；回傳名稱之後的位置。
    ///
    /// 防護：指標最多跳 64 次；展開後的名稱（含長度位元組與結尾的 0）不能超過 255 bytes（RFC 1035 2.3.4）。
    /// 兩個限制加起來，再怎麼繞圈的惡意封包也只會走固定的步數就結束。
    fn walk_name(&self, start: usize, mut f: impl FnMut(&'a [u8])) -> Result<usize, Error> {
        let mut pos = start;
        let mut next = None;
        let mut hops = 0;
        let mut wire = 1usize;
        loop {
            let len = *self.b.get(pos).ok_or(Error::TooShort)? as usize;
            if len & 0xc0 == 0xc0 {
                let lo = *self.b.get(pos + 1).ok_or(Error::TooShort)? as usize;
                next.get_or_insert(pos + 2);
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
                return Ok(next.unwrap_or(pos + 1));
            }
            wire += 1 + len;
            if wire > MAX_NAME_WIRE {
                return Err(Error::BadName);
            }
            f(self.b.get(pos + 1..pos + 1 + len).ok_or(Error::TooShort)?);
            pos += 1 + len;
        }
    }

    /// 讀一個名稱，展開成字串（保留大小寫；不可列印或會造成歧義的字元用 \DDD 表示）
    fn name(&mut self) -> Result<String, Error> {
        // 先算好長度再配置：一個名稱只配置一次，而且沒有多餘的容量（名稱會留在快取裡）
        let mut len = 0usize;
        let next = self.walk_name(self.i, |label| {
            len += 1 + label.iter().map(|&c| if plain_char(c) { 1 } else { 4 }).sum::<usize>();
        })?;
        let mut out = String::with_capacity(len.saturating_sub(1));
        self.walk_name(self.i, |label| {
            if !out.is_empty() {
                out.push('.');
            }
            for &c in label {
                if plain_char(c) {
                    out.push(c as char);
                } else {
                    out.push('\\');
                    out.push((b'0' + c / 100) as char);
                    out.push((b'0' + c / 10 % 10) as char);
                    out.push((b'0' + c % 10) as char);
                }
            }
        })?;
        self.i = next;
        Ok(out)
    }
}

/// 展開後的名稱在封包裡最多 255 bytes
const MAX_NAME_WIRE: usize = 255;

/// 可以直接放進名稱字串的字元（其他的用 \DDD）
fn plain_char(c: u8) -> bool {
    c.is_ascii_graphic() && c != b'.' && c != b'\\'
}

/// 區段的記錄數是封包自己說的，不能照單全收：預留空間時以「剩下的位元組最多放得下幾筆」為上限
fn cap(count: u16, remaining: usize, min_size: usize) -> usize {
    (count as usize).min(remaining / min_size)
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
        let mut used = start;
        let v = match (rtype, len) {
            (rtype::A, 4) => RData::A(Ipv4Addr::new(d.u8()?, d.u8()?, d.u8()?, d.u8()?)),
            (rtype::AAAA, 16) => RData::Aaaa(Ipv6Addr::from(<[u8; 16]>::try_from(d.bytes(16)?).unwrap())),
            (rtype::CNAME | rtype::NS | rtype::PTR | rtype::DNAME, _) => {
                // 名稱可能指向封包前面，所以用完整封包讀
                let mut full = Reader { b: r.b, i: start };
                let v = RData::Name(full.name()?);
                used = full.i;
                v
            }
            (rtype::MX, _) => {
                let pref = d.u16()?;
                let mut full = Reader { b: r.b, i: start + 2 };
                let v = RData::Mx(pref, full.name()?);
                used = full.i;
                v
            }
            (rtype::SOA, _) => {
                let mut full = Reader { b: r.b, i: start };
                let mname = full.name()?;
                let rname = full.name()?;
                let v = RData::Soa {
                    mname,
                    rname,
                    serial: full.u32()?,
                    refresh: full.u32()?,
                    retry: full.u32()?,
                    expire: full.u32()?,
                    minimum: full.u32()?,
                };
                used = full.i;
                v
            }
            (rtype::SRV, _) => {
                let (priority, weight, port) = (d.u16()?, d.u16()?, d.u16()?);
                let mut full = Reader { b: r.b, i: start + 6 };
                let v = RData::Srv {
                    priority,
                    weight,
                    port,
                    target: full.name()?,
                };
                used = full.i;
                v
            }
            _ => RData::Raw(d.bytes(len)?.to_vec()),
        };
        // RDATA 裡的名稱與欄位不能超出 RDLENGTH 宣告的範圍（不然等於讀到下一筆記錄的內容）
        if used > end {
            return Err(Error::TooShort);
        }
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
        m.questions.reserve_exact(cap(qd, b.len(), 5));
        for _ in 0..qd {
            let name = r.name()?;
            m.questions.push(Question {
                name,
                qtype: r.u16()?,
                qclass: r.u16()?,
            });
        }
        m.answers.reserve_exact(cap(an, b.len().saturating_sub(r.i), 11));
        for _ in 0..an {
            m.answers.push(parse_record(&mut r)?.0);
        }
        m.authorities.reserve_exact(cap(ns, b.len().saturating_sub(r.i), 11));
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
        self.encode_inner(None)
    }

    /// 編碼並用 EDNS Padding（RFC 7830 / 8467）補到 `block` 的倍數；沒有 OPT 的訊息不補。
    /// 原本帶著的 padding 選項不算（重新補），其他選項照寫。
    /// 比「先 `logic::pad` 再 `encode`」少編碼一次。
    pub fn encode_padded(&self, block: usize) -> Vec<u8> {
        self.encode_inner(Some(block))
    }

    fn encode_inner(&self, pad: Option<usize>) -> Vec<u8> {
        let mut w = Writer::new();
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
            let pad = pad.filter(|b| *b > 0);
            w.b.push(0);
            w.u16(rtype::OPT);
            w.u16(o.udp_size);
            let ext = ((self.rcode >> 4) & 0xff) as u32;
            w.u32((ext << 24) | ((o.version as u32) << 16) | o.flags as u32);
            let len_pos = w.b.len();
            w.u16(0);
            let start = w.b.len();
            for (code, d) in &o.options {
                if pad.is_some() && *code == opt_code::PADDING {
                    continue;
                }
                w.u16(*code);
                w.u16(d.len() as u16);
                w.b.extend_from_slice(d);
            }
            if let Some(block) = pad {
                let total = w.b.len() + 4; // 加上 padding 選項本身的 4 bytes
                let n = (block - total % block) % block;
                w.u16(opt_code::PADDING);
                w.u16(n as u16);
                w.b.resize(w.b.len() + n, 0);
            }
            let len = (w.b.len() - start) as u16;
            w.b[len_pos..len_pos + 2].copy_from_slice(&len.to_be_bytes());
        }
        w.b
    }
}

/// 鍵本身已經是雜湊值的 `HashMap` 用：不再雜湊一次
#[derive(Default)]
struct IdHasher(u64);

impl std::hash::Hasher for IdHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = (self.0 << 8) | b as u64;
        }
    }
    fn write_u64(&mut self, v: u64) {
        self.0 = v;
    }
}

struct Writer {
    b: Vec<u8>,
    /// 寫過的名稱後綴：小寫內容的雜湊 → 在封包裡的位置（只記指標指得到的 0x3fff 以內）。
    /// 命中後會回頭比對封包裡的內容，雜湊碰巧相同也不會壓縮成錯的名稱。
    names: HashMap<u64, u16, std::hash::BuildHasherDefault<IdHasher>>,
    /// 目前這個名稱的標籤（封包格式：長度 + 內容，保留大小寫）；每個名稱重複使用，不重新配置
    labels: Vec<u8>,
    /// 每個標籤在 `labels` 裡的位置，與「從這個標籤到結尾」的雜湊
    marks: Vec<(usize, u64)>,
}

impl Writer {
    fn new() -> Writer {
        Writer {
            b: Vec::with_capacity(512),
            names: HashMap::with_capacity_and_hasher(16, Default::default()),
            labels: Vec::with_capacity(64),
            marks: Vec::with_capacity(8),
        }
    }

    fn u16(&mut self, v: u16) {
        self.b.extend_from_slice(&v.to_be_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.b.extend_from_slice(&v.to_be_bytes());
    }

    /// 封包裡 `pos` 開始的名稱（可能含指標）是不是剛好等於 `want`（一串「長度 + 內容」，不分大小寫）
    fn same_name(&self, mut pos: usize, mut want: &[u8]) -> bool {
        let mut hops = 0;
        loop {
            let Some(&len) = self.b.get(pos) else { return false };
            if len & 0xc0 == 0xc0 {
                let Some(&lo) = self.b.get(pos + 1) else { return false };
                hops += 1;
                if hops > 128 {
                    return false;
                }
                pos = ((len as usize & 0x3f) << 8) | lo as usize;
                continue;
            }
            if len == 0 {
                return want.is_empty();
            }
            let n = 1 + len as usize;
            match self.b.get(pos..pos + n) {
                Some(have) if want.len() >= n && have.eq_ignore_ascii_case(&want[..n]) => {}
                _ => return false,
            }
            want = &want[n..];
            pos += n;
        }
    }

    /// 寫名稱；compress = 可以用前面出現過的後綴（並記下自己的後綴給後面用）
    fn name(&mut self, name: &str, compress: bool) {
        wire_labels(name, &mut self.labels, &mut self.marks);
        // 由後往前算每個後綴的雜湊（FNV-1a，小寫）：每個標籤只走一次
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for m in self.marks.iter_mut().rev() {
            let len = self.labels[m.0] as usize;
            for &c in &self.labels[m.0..m.0 + 1 + len] {
                h = (h ^ c.to_ascii_lowercase() as u64).wrapping_mul(0x0000_0100_0000_01b3);
            }
            // 再攪一次，讓高低位元都夠亂（雜湊表直接拿這個值當索引）
            let mut x = h ^ (h >> 29);
            x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
            m.1 = x ^ (x >> 32);
        }
        for i in 0..self.marks.len() {
            let (off, hash) = self.marks[i];
            if compress {
                match self.names.get(&hash).copied() {
                    Some(pos) if self.same_name(pos as usize, &self.labels[off..]) => {
                        self.u16(0xc000 | pos);
                        return;
                    }
                    Some(_) => {}
                    None if self.b.len() < 0x4000 => {
                        self.names.insert(hash, self.b.len() as u16);
                    }
                    None => {}
                }
            }
            let end = off + 1 + self.labels[off] as usize;
            self.b.extend_from_slice(&self.labels[off..end]);
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

/// 把名稱字串拆成封包格式的標籤（處理 \DDD 與 \. 跳脫），寫進 `out`（長度 + 內容，一個接一個，沒有結尾的 0），
/// 每個標籤的位置記在 `marks`。空標籤（連續的點）略過；超過 63 bytes 的部分丟掉。
fn wire_labels(name: &str, out: &mut Vec<u8>, marks: &mut Vec<(usize, u64)>) {
    out.clear();
    marks.clear();
    let b = name.as_bytes();
    let mut i = 0;
    // 目前這個標籤的長度位元組在 `out` 裡的位置；None = 還沒開始
    let mut cur: Option<usize> = None;
    while i < b.len() {
        let c = match b[i] {
            b'.' => {
                cur = None;
                i += 1;
                continue;
            }
            b'\\' if i + 3 < b.len() && b[i + 1..i + 4].iter().all(u8::is_ascii_digit) => {
                let v = (b[i + 1] - b'0') as u16 * 100 + (b[i + 2] - b'0') as u16 * 10 + (b[i + 3] - b'0') as u16;
                i += 4;
                v.min(255) as u8
            }
            b'\\' if i + 1 < b.len() => {
                i += 2;
                b[i - 1]
            }
            c => {
                i += 1;
                c
            }
        };
        let at = *cur.get_or_insert_with(|| {
            marks.push((out.len(), 0));
            out.push(0);
            out.len() - 1
        });
        if out[at] < 63 {
            out[at] += 1;
            out.push(c);
        }
    }
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
