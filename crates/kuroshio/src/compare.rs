//! 2.x 與 3.0 並行比對（規格 04 第 1.2 節）：`kuroshio compare`
//!
//! 同一批查詢同時問兩邊（node 版例如 5335、Rust 版例如 5336），比對 rcode、答案 IP、TTL、過濾判定、
//! CDN 置換結果。查詢來源可以是 dnsmasq 的查詢紀錄（`log-queries`）、node 版的 queryLog，或一行一個網域。
//!
//! **允許的差異**：IP 順序（測速）、同一家 CDN 的台灣節點池內不同 IP。其他都列進報表。

use kuroshio_proto::logic;
use kuroshio_proto::message::{rtype, Message};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::net::IpAddr;

/// 從紀錄檔取出 (類型, 網域)；認得 dnsmasq、node queryLog、純網域清單
pub fn parse_line(line: &str) -> Option<(u16, String)> {
    let line = strip_ansi(line);
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    // dnsmasq：... dnsmasq[123]: query[AAAA] example.com from 192.168.1.2
    if let Some(i) = line.find("query[") {
        let rest = &line[i + 6..];
        let (t, rest) = rest.split_once(']')?;
        let name = rest.split_whitespace().next()?;
        return Some((qtype_of(t)?, norm(name)?));
    }
    // node 2.x queryLog：[時間] [proto] client | A      example.com | HIT | src | TTL: 60
    if line.starts_with('[') && line.contains(" | ") {
        let seg = line.split(" | ").nth(1)?;
        let mut it = seg.split_whitespace();
        let (t, name) = (it.next()?, it.next()?);
        return Some((qtype_of(t)?, norm(name)?));
    }
    // 一行一個網域（可以寫「AAAA example.com」）
    let mut it = line.split_whitespace();
    let a = it.next()?;
    match it.next() {
        Some(name) => Some((qtype_of(a)?, norm(name)?)),
        None => Some((rtype::A, norm(a)?)),
    }
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\u{1b}' {
            for d in it.by_ref() {
                if d.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn norm(n: &str) -> Option<String> {
    let n = n.trim().trim_end_matches('.').to_ascii_lowercase();
    (!n.is_empty() && n.contains('.') && n.chars().all(|c| c.is_ascii_alphanumeric() || "-._".contains(c))).then_some(n)
}

pub fn qtype_of(t: &str) -> Option<u16> {
    Some(match t.to_ascii_uppercase().as_str() {
        "A" => rtype::A,
        "AAAA" => rtype::AAAA,
        "CNAME" => rtype::CNAME,
        "MX" => 15,
        "TXT" => 16,
        "NS" => 2,
        "PTR" => 12,
        "SRV" => 33,
        "SVCB" => rtype::SVCB,
        "HTTPS" => rtype::HTTPS,
        n => n.strip_prefix("TYPE").unwrap_or(n).parse().ok()?,
    })
}

/// 一邊的結果
#[derive(Debug, Clone, PartialEq)]
pub enum Side {
    Answer {
        rcode: u16,
        ips: BTreeSet<IpAddr>,
        min_ttl: Option<u32>,
        blocked: bool,
    },
    Error(String),
}

impl Side {
    pub fn from_msg(m: &Message, qtype: u16) -> Side {
        let ips: BTreeSet<IpAddr> = logic::ips_of(m, qtype).into_iter().collect();
        let blocked = !ips.is_empty() && ips.iter().all(|ip| ip.is_unspecified());
        Side::Answer {
            rcode: m.rcode,
            min_ttl: m.answers.iter().map(|a| a.ttl).min(),
            ips,
            blocked,
        }
    }
}

/// 差異分類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Same,
    /// 允許：同一家 CDN 的台灣節點池內不同 IP
    PoolDiff,
    Rcode,
    Filter,
    /// 一邊換成台灣節點、另一邊沒有
    Cdn,
    Ips,
    Error,
}

impl Verdict {
    pub fn name(self) -> &'static str {
        match self {
            Verdict::Same => "same",
            Verdict::PoolDiff => "pool",
            Verdict::Rcode => "rcode",
            Verdict::Filter => "filter",
            Verdict::Cdn => "cdn",
            Verdict::Ips => "ips",
            Verdict::Error => "error",
        }
    }
    pub fn allowed(self) -> bool {
        matches!(self, Verdict::Same | Verdict::PoolDiff)
    }
}

/// IP 屬於哪一家 CDN 的台灣節點（None = 不是 / 不知道）
pub type TwOf<'a> = &'a dyn Fn(IpAddr) -> Option<String>;

pub fn judge(a: &Side, b: &Side, tw_of: TwOf) -> Verdict {
    let (
        Side::Answer {
            rcode: ra,
            ips: ia,
            blocked: ba,
            ..
        },
        Side::Answer {
            rcode: rb,
            ips: ib,
            blocked: bb,
            ..
        },
    ) = (a, b)
    else {
        return if a == b { Verdict::Same } else { Verdict::Error };
    };
    if ba != bb {
        return Verdict::Filter;
    }
    if ra != rb {
        return Verdict::Rcode;
    }
    if ia == ib {
        return Verdict::Same;
    }
    let tw = |s: &BTreeSet<IpAddr>| -> Option<BTreeSet<String>> {
        let v: Option<BTreeSet<String>> = s.iter().map(|ip| tw_of(*ip)).collect();
        v.filter(|x| !x.is_empty())
    };
    match (tw(ia), tw(ib)) {
        (Some(x), Some(y)) if x == y => Verdict::PoolDiff,
        (Some(_), None) | (None, Some(_)) => Verdict::Cdn,
        _ => Verdict::Ips,
    }
}

/// 報表彙整
#[derive(Default)]
pub struct Report {
    pub total: u64,
    pub counts: std::collections::BTreeMap<&'static str, u64>,
    pub samples: Vec<Value>,
}

impl Report {
    pub fn add(&mut self, qtype: u16, name: &str, a: &Side, b: &Side, v: Verdict) {
        self.total += 1;
        *self.counts.entry(v.name()).or_default() += 1;
        if !v.allowed() && self.samples.len() < 2000 {
            let side = |s: &Side| match s {
                Side::Answer {
                    rcode,
                    ips,
                    min_ttl,
                    blocked,
                } => json!({ "rcode": rcode, "ips": ips, "ttl": min_ttl, "blocked": blocked }),
                Side::Error(e) => json!({ "error": e }),
            };
            self.samples
                .push(json!({ "type": qtype, "name": name, "kind": v.name(), "a": side(a), "b": side(b) }));
        }
    }

    pub fn unexplained(&self) -> u64 {
        self.counts
            .iter()
            .filter(|(k, _)| !matches!(**k, "same" | "pool"))
            .map(|(_, n)| n)
            .sum()
    }

    pub fn json(&self) -> Value {
        let rate = if self.total > 0 {
            self.unexplained() as f64 * 100.0 / self.total as f64
        } else {
            0.0
        };
        json!({
            "total": self.total, "counts": self.counts, "unexplained": self.unexplained(),
            "unexplainedPct": (rate * 1000.0).round() / 1000.0,
            // 規格 04：未解釋差異 < 0.1% 才算對齊
            "pass": self.total > 0 && rate < 0.1,
            "samples": self.samples,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_log_formats() {
        assert_eq!(
            parse_line("Nov 10 12:00:01 dnsmasq[812]: query[AAAA] WWW.Example.com from 192.168.1.20"),
            Some((rtype::AAAA, "www.example.com".into()))
        );
        assert_eq!(
            parse_line("\u{1b}[90m[12:00:01] [udp] 192.168.1.20     | A      cdn.example.net | \u{1b}[32mHIT\u{1b}[0m | - | TTL: 60"),
            Some((rtype::A, "cdn.example.net".into()))
        );
        assert_eq!(parse_line("example.org"), Some((rtype::A, "example.org".into())));
        assert_eq!(parse_line("HTTPS example.org."), Some((rtype::HTTPS, "example.org".into())));
        assert_eq!(parse_line("# comment"), None);
        assert_eq!(parse_line("localhost"), None, "沒有點的名稱略過");
        assert_eq!(
            parse_line("dnsmasq[1]: query[TYPE65] a.example from x"),
            Some((65, "a.example".into()))
        );
    }

    fn ans(rcode: u16, ips: &[&str]) -> Side {
        let ips: BTreeSet<IpAddr> = ips.iter().map(|s| s.parse().unwrap()).collect();
        let blocked = !ips.is_empty() && ips.iter().all(|ip| ip.is_unspecified());
        Side::Answer {
            rcode,
            ips,
            min_ttl: Some(60),
            blocked,
        }
    }

    #[test]
    fn verdicts() {
        let tw = |ip: IpAddr| -> Option<String> { ip.to_string().starts_with("104.16.").then(|| "cloudflare".to_string()) };
        let j = |a: &Side, b: &Side| judge(a, b, &tw);
        assert_eq!(
            j(&ans(0, &["1.1.1.1", "2.2.2.2"]), &ans(0, &["2.2.2.2", "1.1.1.1"])),
            Verdict::Same,
            "順序不同"
        );
        assert_eq!(j(&ans(0, &["104.16.1.1"]), &ans(0, &["104.16.9.9"])), Verdict::PoolDiff);
        assert_eq!(j(&ans(0, &["104.16.1.1"]), &ans(0, &["172.64.1.1"])), Verdict::Cdn);
        assert_eq!(j(&ans(0, &["0.0.0.0"]), &ans(0, &["1.2.3.4"])), Verdict::Filter);
        assert_eq!(j(&ans(3, &[]), &ans(0, &[])), Verdict::Rcode);
        assert_eq!(j(&ans(0, &["1.1.1.1"]), &ans(0, &["9.9.9.9"])), Verdict::Ips);
        assert_eq!(j(&Side::Error("逾時".into()), &ans(0, &[])), Verdict::Error);
        let mut r = Report::default();
        for _ in 0..999 {
            r.add(1, "a.example", &ans(0, &[]), &ans(0, &[]), Verdict::Same);
        }
        r.add(1, "b.example", &ans(0, &["1.1.1.1"]), &ans(0, &["9.9.9.9"]), Verdict::Ips);
        let v = r.json();
        assert_eq!(v["unexplained"], 1);
        assert_eq!(v["pass"], false, "0.1% 不算通過");
        assert_eq!(v["samples"].as_array().unwrap().len(), 1);
    }
}
