//! 單行規則解析：逐字移植 node 版 `parseRule`（legacy-node/lib/filter.js）。

use crate::js;
use crate::regex::{Regex, RegexError};

/// `$dnstype=`：include 為空代表不限；exclude 是 `~` 開頭的類型（都已轉大寫）
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DnsType {
    pub include: Vec<Box<str>>,
    pub exclude: Vec<Box<str>>,
}

impl DnsType {
    fn parse(spec: &str) -> DnsType {
        let mut d = DnsType {
            include: Vec::new(),
            exclude: Vec::new(),
        };
        for t in spec.split('|') {
            match t.strip_prefix('~') {
                Some(x) => push_unique(&mut d.exclude, js::upper(x)),
                None => push_unique(&mut d.include, js::upper(t)),
            }
        }
        d
    }

    pub fn matches(&self, qtype: &str) -> bool {
        if !self.include.is_empty() && !self.include.iter().any(|t| &**t == qtype) {
            return false;
        }
        !self.exclude.iter().any(|t| &**t == qtype)
    }

    pub fn heap_bytes(&self) -> usize {
        (self.include.capacity() + self.exclude.capacity()) * std::mem::size_of::<Box<str>>()
            + self.include.iter().chain(&self.exclude).map(|s| s.len()).sum::<usize>()
    }
}

fn push_unique(v: &mut Vec<Box<str>>, s: String) {
    if !v.iter().any(|x| **x == *s) {
        v.push(s.into_boxed_str());
    }
}

#[derive(Debug)]
pub(crate) enum Body {
    /// hosts 格式、`|domain^`：只比對網域本身
    Exact(String),
    /// `||domain^`、純網域行：網域本身與所有子網域
    Suffix(String),
    /// 正規表示式或萬用字元；`lit` 是快速排除用的固定字串
    Pattern { re: Regex, lit: Option<String> },
}

#[derive(Debug)]
pub(crate) struct Rule {
    pub allow: bool,
    pub important: bool,
    pub badfilter: bool,
    pub dnstype: Option<DnsType>,
    pub body: Body,
}

#[derive(Debug)]
pub(crate) enum Parsed {
    /// 註解、空行、化妝品規則、無效行（node 版回傳 null，不計數）
    Skip,
    /// 不適用 DNS 的規則（node 版 `{ unsupported: true }`，計入 skipped）。
    /// `regex_feature` 為真表示 node 版其實能載入、但本引擎不支援的正規表示式語法。
    Unsupported {
        regex_feature: bool,
    },
    Rule(Rule),
}

const DNS_MODIFIERS: [&str; 7] = ["important", "badfilter", "dnstype", "client", "ctag", "denyallow", "dnsrewrite"];
const IGNORED_SAFE: [&str; 1] = ["match-case"];
const RELAXABLE: [&str; 21] = [
    "third-party",
    "~third-party",
    "3p",
    "~3p",
    "first-party",
    "1p",
    "script",
    "image",
    "stylesheet",
    "xmlhttprequest",
    "xhr",
    "subdocument",
    "media",
    "font",
    "other",
    "object",
    "ping",
    "websocket",
    "all",
    "popup",
    "beacon",
];

/// 化妝品 / 頁面規則：`/#[@?$%]?#|#@\$#|\$\$/`
fn is_cosmetic(s: &str) -> bool {
    ["##", "#@#", "#?#", "#$#", "#%#", "#@$#", "$$"].iter().any(|p| s.contains(p))
}

/// hosts 格式：`^((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F]*:[0-9a-fA-F:.]*)\s+([^\s#]+)`，回傳第二個群組
fn hosts_domain(s: &str) -> Option<&str> {
    let b = s.as_bytes();
    let ipv4_end = || -> Option<usize> {
        let mut i = 0;
        for g in 0..4 {
            let st = i;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            if i == st || i - st > 3 {
                return None;
            }
            if g < 3 {
                if b.get(i) != Some(&b'.') {
                    return None;
                }
                i += 1;
            }
        }
        Some(i)
    };
    let ipv6_end = || -> Option<usize> {
        let mut i = 0;
        while i < b.len() && b[i].is_ascii_hexdigit() {
            i += 1;
        }
        if b.get(i) != Some(&b':') {
            return None;
        }
        i += 1;
        while i < b.len() && (b[i].is_ascii_hexdigit() || b[i] == b':' || b[i] == b'.') {
            i += 1;
        }
        Some(i)
    };
    let tail = |end: usize| -> Option<&str> {
        let rest = &s[end..];
        let after = rest.trim_start_matches(js::is_space);
        if after.len() == rest.len() {
            return None;
        }
        let n = after.find(|c: char| js::is_space(c) || c == '#').unwrap_or(after.len());
        (n > 0).then(|| &after[..n])
    };
    ipv4_end().and_then(tail).or_else(|| ipv6_end().and_then(tail))
}

/// 修飾詞值的 JS 真假值：沒有 `=` 時是 true；`=` 後面空字串是 false
type Opt<'a> = Option<Option<&'a str>>;
fn truthy(o: Opt<'_>) -> bool {
    match o {
        None => false,
        Some(None) => true,
        Some(Some(v)) => !v.is_empty(),
    }
}

/// 快速排除用固定字串：樣式依 `[^a-z0-9.\-_]+` 切開，取最長（≥ 3 字元）的一段
fn literal_of(src: &str) -> Option<String> {
    let mut best: Option<&str> = None;
    for part in src.split(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-' || c == '_')) {
        if part.len() >= 3 && best.map_or(true, |b| part.len() > b.len()) {
            best = Some(part);
        }
    }
    best.map(str::to_owned)
}

/// 解析單行規則（`line` 是原始行，不含換行字元）
pub(crate) fn parse_rule(line: &str, relaxed: bool) -> Parsed {
    let s = js::trim(line);
    if s.is_empty() || s.starts_with('!') || s.starts_with('#') || s.starts_with('[') {
        return Parsed::Skip;
    }
    if is_cosmetic(s) {
        return Parsed::Skip;
    }

    // hosts 格式：「IP 網域」。不管清單寫的是哪個 IP，一律當成封鎖這個網域，絕不採用清單裡的 IP
    if let Some(d) = hosts_domain(s) {
        let d = js::lower(d);
        if matches!(&*d, "localhost" | "localhost.localdomain" | "0.0.0.0" | "local" | "broadcasthost") || !js::is_domain(&d) {
            return Parsed::Skip;
        }
        let key = d.strip_suffix('.').unwrap_or(&d).to_owned();
        return Parsed::Rule(Rule {
            allow: false,
            important: false,
            badfilter: false,
            dnstype: None,
            body: Body::Exact(key),
        });
    }

    let (allow, mut s) = match s.strip_prefix("@@") {
        Some(rest) => (true, rest),
        None => (false, s),
    };

    // 正規表示式規則 /.../ 或 /.../$修飾詞
    if s.starts_with('/') {
        let last = s.rfind('/').unwrap_or(0);
        let tail = &s[last + 1..];
        if last > 0 && (tail.is_empty() || tail.starts_with('$')) {
            let mut important = false;
            let mut dnstype = None;
            if !tail.is_empty() {
                for raw in tail[1..].split(',') {
                    let mut kv = js::trim(raw).split('=');
                    let key = js::lower(kv.next().unwrap_or(""));
                    let v = kv.next();
                    if key.is_empty() {
                        continue;
                    }
                    if key == "important" {
                        important = true;
                    } else if key == "dnstype" {
                        dnstype = Some(DnsType::parse(v.unwrap_or("")));
                    } else if !IGNORED_SAFE.contains(&&*key) {
                        return Parsed::Unsupported { regex_feature: false };
                    }
                }
            }
            return match Regex::parse(&s[1..last]) {
                Ok(re) => {
                    let lit = re.required_literal();
                    Parsed::Rule(Rule {
                        allow,
                        important,
                        badfilter: false,
                        dnstype,
                        body: Body::Pattern { re, lit },
                    })
                }
                Err(RegexError::Syntax) => Parsed::Skip,
                Err(RegexError::Unsupported) => Parsed::Unsupported { regex_feature: true },
            };
        }
        return Parsed::Unsupported { regex_feature: false };
    }

    // 修飾詞
    let mut important: Opt = None;
    let mut badfilter: Opt = None;
    let mut dnstype: Opt = None;
    let mut client: Opt = None;
    let mut ctag: Opt = None;
    let mut denyallow: Opt = None;
    let mut dnsrewrite: Opt = None;
    if let Some(dollar) = s.rfind('$').filter(|&d| d > 0) {
        let opt_str = &s[dollar + 1..];
        s = &s[..dollar];
        for raw in opt_str.split(',') {
            let o = js::trim(raw);
            if o.is_empty() {
                continue;
            }
            let mut kv = o.split('=');
            let key = js::lower(kv.next().unwrap_or(""));
            let v = kv.next();
            if !DNS_MODIFIERS.contains(&&*key) && !IGNORED_SAFE.contains(&&*key) {
                if relaxed && RELAXABLE.contains(&&*key) {
                    continue;
                }
                return Parsed::Unsupported { regex_feature: false };
            }
            let slot = match &*key {
                "important" => &mut important,
                "badfilter" => &mut badfilter,
                "dnstype" => &mut dnstype,
                "client" => &mut client,
                "ctag" => &mut ctag,
                "denyallow" => &mut denyallow,
                "dnsrewrite" => &mut dnsrewrite,
                _ => continue,
            };
            *slot = Some(v);
        }
        if truthy(client) || truthy(ctag) || truthy(denyallow) || truthy(dnsrewrite) {
            return Parsed::Unsupported { regex_feature: false };
        }
    }

    let (anchor_domain, anchor_start) = if let Some(rest) = s.strip_prefix("||") {
        s = rest;
        (true, false)
    } else if let Some(rest) = s.strip_prefix('|') {
        s = rest;
        (false, true)
    } else {
        (false, false)
    };

    // 含路徑的網址規則在 DNS 層無法套用（允許結尾單一 "/"）
    if let Some(slash) = s.find('/') {
        if slash != s.len() - 1 {
            return Parsed::Unsupported { regex_feature: false };
        }
        s = &s[..slash];
    }
    let s = js::lower(s);
    if s.is_empty() || s == "*" || s == "^" {
        return Parsed::Skip;
    }

    let important = truthy(important);
    let badfilter = truthy(badfilter);
    let dnstype = truthy(dnstype).then(|| DnsType::parse(dnstype.flatten().unwrap_or("true")));

    // 純網域：快速路徑
    let mut plain: &str = &s;
    if let Some(p) = plain.strip_suffix("^|") {
        plain = p;
    } else if let Some(p) = plain.strip_suffix('^') {
        plain = p;
    }
    if let Some(p) = plain.strip_suffix('|') {
        plain = p;
    }
    if !plain.contains('*') && !plain.contains('^') && js::is_domain(plain) {
        let key = plain.strip_suffix('.').unwrap_or(plain).to_owned();
        let body = if anchor_domain {
            Some(Body::Suffix(key))
        } else if anchor_start && (s.ends_with('^') || s.ends_with('|')) {
            // |example.org^ → 精確比對
            Some(Body::Exact(key))
        } else if !anchor_start {
            // 沒有錨點的純網域（domains-only 清單）視為含子網域
            Some(Body::Suffix(key))
        } else {
            None
        };
        if let Some(body) = body {
            return Parsed::Rule(Rule {
                allow,
                important,
                badfilter,
                dnstype,
                body,
            });
        }
    }
    let re = Regex::from_adblock(&s, anchor_domain, anchor_start);
    Parsed::Rule(Rule {
        allow,
        important,
        badfilter,
        dnstype,
        body: Body::Pattern { re, lit: literal_of(&s) },
    })
}

/// `$badfilter` 規則要取消的規則文字：
/// `text.replace(/(\$|,)badfilter/i, '').replace(/\$$/, '').trim()`
pub(crate) fn badfilter_target(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    let mut out = line.to_owned();
    // 找第一個「$badfilter」或「,badfilter」（不分大小寫）
    let b = lower.as_bytes();
    let mut i = 0;
    while let Some(p) = lower[i..].find("badfilter") {
        let at = i + p;
        if at > 0 && (b[at - 1] == b'$' || b[at - 1] == b',') {
            out.replace_range(at - 1..at + "badfilter".len(), "");
            break;
        }
        i = at + 1;
    }
    if out.ends_with('$') {
        out.pop();
    }
    js::trim(&out).to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kind(line: &str) -> String {
        match parse_rule(line, false) {
            Parsed::Skip => "skip".into(),
            Parsed::Unsupported { .. } => "unsupported".into(),
            Parsed::Rule(r) => {
                let b = match r.body {
                    Body::Exact(d) => format!("exact:{d}"),
                    Body::Suffix(d) => format!("suffix:{d}"),
                    Body::Pattern { lit, .. } => format!("pattern:{}", lit.unwrap_or_default()),
                };
                format!("{}{}{}", if r.allow { "@@" } else { "" }, b, if r.important { "!" } else { "" })
            }
        }
    }

    #[test]
    fn syntax() {
        assert_eq!(kind("||ads.example.com^"), "suffix:ads.example.com");
        assert_eq!(kind("@@||ads.example.com^$important"), "@@suffix:ads.example.com!");
        assert_eq!(kind("0.0.0.0 Hosts.Example.org. # x"), "exact:hosts.example.org");
        assert_eq!(kind(":: v6.example"), "exact:v6.example");
        assert_eq!(kind("127.0.0.1 localhost"), "skip");
        assert_eq!(kind("|exact.example.com^"), "exact:exact.example.com");
        assert_eq!(kind("|prefix.example.com"), "pattern:prefix.example.com");
        assert_eq!(kind("plain.example.com"), "suffix:plain.example.com");
        assert_eq!(kind("||x.com^$third-party"), "unsupported");
        assert_eq!(kind("||x.com/ads.js"), "unsupported");
        assert_eq!(kind("||x.com^/"), "suffix:x.com");
        assert_eq!(kind("example.com##.ad"), "skip");
        assert_eq!(kind("/^ad[0-9]+\\.x$/"), "pattern:");
        assert_eq!(kind("/(a)\\1/"), "unsupported");
        assert_eq!(kind("/a**/"), "skip");
        assert_eq!(kind("||cl*.apple.com^"), "pattern:.apple.com");
        assert!(matches!(parse_rule("||x.com^$third-party", true), Parsed::Rule(_)));
    }

    #[test]
    fn badfilter_text() {
        assert_eq!(badfilter_target("||bad.example.com^$badfilter"), "||bad.example.com^");
        assert_eq!(
            badfilter_target("||bad.example.com^$important,BadFilter"),
            "||bad.example.com^$important"
        );
        assert_eq!(badfilter_target("  ||x^$badfilter  "), "||x^");
    }
}
