//! 污染判斷規則（逐條對齊 2.x `jobs/lib/benchmark-rules.js`，原始來源 DNStest v16.1）：
//! 網域別名、台灣 ISP、CDN 合作夥伴互信、ASN 分組。要調整污染判斷請改這個檔案。

use serde_json::{json, Value};

/// 一個 IP 的業者資訊（ip-api 查到的 ISP / AS，2.x 的 `{ raw, keywords }`，也是 cidr_cache.json 的格式）
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AsnInfo {
    pub raw: String,
    pub keywords: Vec<String>,
}

impl AsnInfo {
    /// 查不到時用的
    pub fn unknown() -> AsnInfo {
        AsnInfo {
            raw: "Unknown_ISP".into(),
            keywords: Vec::new(),
        }
    }

    /// 由 ip-api 的欄位組出（同 2.x）：raw = `isp__as`（空白換成 _），關鍵字取自 `isp org as`
    pub fn from_ip_api(isp: &str, org: &str, as_: &str) -> AsnInfo {
        let raw = format!("{isp}__{as_}");
        let mut out = String::with_capacity(raw.len());
        let mut in_space = false;
        for c in raw.chars() {
            if js_is_space(c) {
                if !in_space {
                    out.push('_');
                }
                in_space = true;
            } else {
                out.push(c);
                in_space = false;
            }
        }
        AsnInfo {
            raw: out,
            keywords: extract_keywords(&format!("{isp} {org} {as_}")),
        }
    }

    pub fn is_unknown(&self) -> bool {
        self.keywords.is_empty()
    }

    pub fn to_json(&self) -> Value {
        json!({ "raw": self.raw, "keywords": self.keywords })
    }

    pub fn from_json(v: &Value) -> Option<AsnInfo> {
        Some(AsnInfo {
            raw: v.get("raw")?.as_str()?.to_string(),
            keywords: v
                .get("keywords")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|k| k.as_str().map(str::to_string)).collect())
                .unwrap_or_default(),
        })
    }

    fn has(&self, k: &str) -> bool {
        self.keywords.iter().any(|x| x == k)
    }

    fn any_in(&self, list: &[&str]) -> bool {
        self.keywords.iter().any(|k| list.contains(&k.as_str()))
    }
}

pub const TRUSTED_CROSS_ISPS: &[(&str, &[&str])] = &[
    (
        "chinanet",
        &["unicom", "mobile", "telecom", "guangdong", "tianjin", "alibaba", "taobao", "alipay"],
    ),
    (
        "unicom",
        &[
            "chinanet",
            "mobile",
            "telecom",
            "guangdong",
            "tianjin",
            "alibaba",
            "taobao",
            "alipay",
        ],
    ),
    (
        "mobile",
        &[
            "chinanet",
            "unicom",
            "telecom",
            "guangdong",
            "tianjin",
            "alibaba",
            "taobao",
            "alipay",
        ],
    ),
    (
        "telecom",
        &[
            "chinanet",
            "unicom",
            "mobile",
            "guangdong",
            "tianjin",
            "alibaba",
            "taobao",
            "alipay",
        ],
    ),
    // 阿里系
    ("alibaba", ALI_TRUST_ALIBABA),
    ("taobao", ALI_TRUST_TAOBAO),
    ("alipay", ALI_TRUST_ALIPAY),
    // 區域 ISP 反向信任阿里系
    ("huashu", ALI),
    ("idc", ALI),
    ("macau", ALI),
    ("topway", ALI),
    ("dxtnet", ALI),
    ("shernet", ALI),
    ("gxblnet", ALI),
    ("hebbtn", ALI),
    ("tng", ALI),
    ("edgeuno", ALI),
    ("hoshin", ALI),
    // 解決 x.com（Cloudflare 與 Fastly 雙 CDN 互信）
    ("cloudflare", &["fastly", "akamai"]),
    ("fastly", &["cloudflare", "akamai", "core"]),
    // G-Core / Core-Backbone 修正（加入對 Apple、Cloudflare 的互信）
    (
        "core",
        &[
            "akamai",
            "chunghwa",
            "hinet",
            "telecom",
            "fastly",
            "microsoft",
            "apple",
            "cloudflare",
        ],
    ),
    ("microsoft", &["core"]),
    ("akamai", &["core"]),
    ("chunghwa", &["core"]),
    ("hinet", &["core"]),
    ("apple", &["core", "terrahost", "gigahost", "backbone"]), // 解決 Apple 歐洲節點互信
];

const ALI: &[&str] = &["alibaba", "taobao", "alipay"];
const ALI_TRUST_ALIBABA: &[&str] = &[
    "taobao",
    "alipay",
    "unicom",
    "mobile",
    "telecom",
    "chinanet",
    "guangdong",
    "tianjin",
    "idc",
    "huashu",
    "macau",
    "hoshin",
    "topway",
    "dxtnet",
    "shernet",
    "gxblnet",
    "hebbtn",
    "tng",
    "edgeuno",
    "media",
    "video",
];
const ALI_TRUST_TAOBAO: &[&str] = &[
    "alibaba",
    "alipay",
    "unicom",
    "mobile",
    "telecom",
    "chinanet",
    "guangdong",
    "tianjin",
    "idc",
    "huashu",
    "macau",
    "hoshin",
    "topway",
    "dxtnet",
    "shernet",
    "gxblnet",
    "hebbtn",
    "tng",
    "edgeuno",
    "media",
    "video",
];
const ALI_TRUST_ALIPAY: &[&str] = &[
    "alibaba",
    "taobao",
    "unicom",
    "mobile",
    "telecom",
    "chinanet",
    "guangdong",
    "tianjin",
    "idc",
    "huashu",
    "macau",
    "hoshin",
    "topway",
    "dxtnet",
    "shernet",
    "gxblnet",
    "hebbtn",
    "tng",
    "edgeuno",
    "media",
    "video",
];

/// 1. 網域別名（網域主體 → 品牌）
pub const DOMAIN_ALIASES: &[(&str, &[&str])] = &[
    // Twitter / X 家族
    ("x", &["cloudflare", "fastly", "twitter"]),
    ("twitter", &["cloudflare", "fastly", "x"]),
    ("twimg", &["cloudflare", "fastly", "twitter"]),
    ("alipayobjects", &["alibaba", "taobao", "alipay", "antgroup", "zenlayer"]),
    ("alibabachengdun", &["alibaba", "taobao", "alipay", "antgroup"]),
    ("taobao", &["alibaba", "alicdn", "kunlun", "zenlayer"]),
    ("tmall", &["alibaba", "alicdn", "zenlayer"]),
    ("alipay", &["alibaba", "antgroup", "zenlayer"]),
    ("qq", &["tencent", "aceville"]),
    ("weixin", &["tencent", "aceville"]),
    ("wechat", &["tencent", "aceville"]),
    ("fbcdn", &["facebook", "meta"]),
    ("instagram", &["facebook", "meta"]),
    ("whatsapp", &["facebook", "meta"]),
    ("googleusercontent", &["google"]),
    ("youtu", &["google"]),
    ("gstatic", &["google"]),
    ("azure", &["microsoft"]),
    ("bing", &["microsoft"]),
    ("office", &["microsoft"]),
    ("live", &["microsoft"]),
    ("xbox", &["microsoft"]),
    ("windowsupdate", &["microsoft"]),
    ("netflix", &["netflix", "nflx", "amazon", "aws", "cloud", "compute"]),
    ("nflxvideo", &["netflix", "nflx"]),
    ("nflxso", &["netflix", "nflx"]),
    ("nflxext", &["netflix", "nflx"]),
    ("apple", &["apple", "akamai"]),
    ("icloud", &["apple", "akamai", "google"]),
    ("mzstatic", &["apple", "akamai"]),
    ("aaplimg", &["apple", "akamai"]),
    ("line", &["line", "naver", "ly_corp", "akamai", "amazon"]),
    ("line-apps", &["line", "naver", "ly_corp"]),
    ("line-scdn", &["line", "akamai", "amazon"]),
    ("shopee", &["shopee", "sea_group", "garena"]),
    ("momoshop", &["taiwan", "tfn", "momo"]),
    ("pchome", &["pchome", "chief", "chunghwa"]),
    ("gamer", &["gamer", "bahamut", "cloudflare"]),
    ("net", &["akamai"]),
    ("yahoo", &["yahoo", "oath", "verizon", "aol", "edgecast"]),
];

/// 台灣 ISP
pub const TAIWAN_ISPS: &[&str] = &[
    "chunghwa",
    "hinet",
    "data_communication",
    "taiwan",
    "fixed",
    "network",
    "tfn",
    "taiwan_mobile",
    "far_eastone",
    "fareastone",
    "ncic",
    "seed",
    "digital_united",
    "tbcom",
    "tbc",
    "taiwan_broadband",
    "kbro",
    "chief",
    "tanet",
    "academic",
    "sonet",
    "so_net",
    "asia_pacific",
    "aptg",
    "taiwan_digital_streaming",
    "hoshin",
    "homeplus",
    "cns",
    "smart",
];

/// 資料中心、主機商通用字根（core、backbone、host、cloud 等），解決 Apple 歐洲節點被淘汰的問題
pub const GENERIC_ISP_KEYWORDS: &[&str] = &[
    "telecom",
    "telecommunications",
    "mobile",
    "net",
    "network",
    "networks",
    "broadband",
    "cable",
    "communication",
    "communications",
    "data",
    "internet",
    "online",
    "connect",
    "digital",
    "systems",
    "wireless",
    "wholesale",
    "ix",
    "exchange",
    "fiber",
    "solution",
    "solutions",
    "multimedia",
    "fuzion",
    "sia",
    "idc",
    "dxtnet",
    "shernet",
    "gxblnet",
    "hebbtn",
    "tng",
    "macau",
    "topway",
    "huashu",
    "media",
    "video",
    "hoshin",
    "edgeuno",
    "core",
    "backbone",
    "host",
    "hosting",
    "terrahost",
    "gigahost",
    "cloud",
];

/// 巨頭贏得第一時，自動信任上面所有的通用 ISP 節點（含 Cloudflare）
pub const GIANTS_ALLOWING_ISPS: &[&str] = &[
    "akamai",
    "apple",
    "microsoft",
    "google",
    "facebook",
    "meta",
    "netflix",
    "line",
    "fastly",
    "amazon",
    "aws",
    "edgecast",
    "alibaba",
    "taobao",
    "alipay",
    "tencent",
    "byte",
    "bytedance",
    "cloudflare",
];

const SPECIFIC_ISPS: &[&str] = &[
    "hoshin", "sejong", "hgc", "pccw", "kisti", "qwilt", "corix", "verizon", "aceville", "zenlayer",
];

const AKAMAI_EXTRA: &[&str] = &[
    "china_telecom",
    "china_unicom",
    "china_mobile",
    "telstra",
    "iij",
    "internet_initiative_japan",
    "softbank",
    "kddi",
    "ntt",
    "retn",
    "arelion",
    "telia",
    "level_3",
    "lumen",
    "cogent",
    "pccw",
    "hkt",
    "hgc",
    "sejong",
    "kisti",
    "korea_telecom",
    "lg",
    "qwilt",
    "corix",
    "verizon",
    "aceville",
    "zenlayer",
    "xmission",
    "sovam",
    "cjsc",
    "moldtelecom",
];
const FASTLY_EXTRA: &[&str] = &["microsoft", "akamai", "g_core", "qwilt", "telstra"];
const APPLE_EXTRA: &[&str] = &[
    "akamai",
    "china_telecom",
    "pccw",
    "hkt",
    "sejong",
    "telstra",
    "lwlcom",
    "swisscom",
    "transtelco",
    "rcn",
    "xmission",
    "sovam",
    "asociatia",
    "edgeuno",
    "edgeix",
    "baltnet",
    "superloop",
    "hurricane",
    "fibernet",
    "vimpelcom",
    "stowarzyszenie",
    "kielnet",
];
const NETFLIX_EXTRA: &[&str] = &["amazon", "aws", "qwilt"];
const ALI_CDN_PARTNERS: &[&str] = &[
    "china_telecom",
    "china_unicom",
    "china_mobile",
    "zenlayer",
    "aceville",
    "tianjin_communication",
    "Chinanet",
    "China_Mobile",
];

/// 2. 合作夥伴信任鏈（有些清單在 2.x 是「…＋台灣 ISP」，這裡分成兩段）
pub const CDN_PARTNERS: &[(&str, &[&str], bool)] = &[
    ("akamai", AKAMAI_EXTRA, true),
    (
        "microsoft",
        &["akamai", "edgecast", "limelight", "fastly", "g_core", "gcore", "qwilt", "verizon"],
        false,
    ),
    ("g_core", &["microsoft", "akamai", "fastly", "qwilt"], false),
    ("gcore", &["microsoft", "akamai", "fastly", "qwilt"], false),
    ("fastly", FASTLY_EXTRA, true),
    ("apple", APPLE_EXTRA, true),
    ("netflix", NETFLIX_EXTRA, true),
    (
        "google",
        &[
            "chunghwa",
            "hinet",
            "taiwan_mobile",
            "far_eastone",
            "chief",
            "google_cloud",
            "gcp",
            "qwilt",
        ],
        false,
    ),
    ("shopee", &["shopee", "sea_group", "zenlayer"], false),
    ("alibaba", ALI_CDN_PARTNERS, false),
    ("alicdn", ALI_CDN_PARTNERS, false),
    ("zenlayer", &["alibaba", "alicdn", "tencent", "shopee"], false),
    ("taiwan", &[], true),
    ("chunghwa", &[], true),
    ("hinet", &[], true),
    ("momo", &[], true),
];

const STOPWORDS: &[&str] = &[
    "inc",
    "llc",
    "ltd",
    "corp",
    "corporation",
    "technology",
    "technologies",
    "international",
    "bv",
    "co",
    "plc",
    "srl",
    "gmbh",
    "province",
    "limited",
    "services",
    "business",
    "solutions",
    "holding",
    "holdings",
    "jsc",
    "ojsc",
    "pjsc",
];

/// JavaScript 正規表示式的 `\s`
pub fn js_is_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{0B}' | '\u{0C}' | '\r' | ' ' | '\u{A0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200A}' | '\u{2028}' | '\u{2029}' | '\u{202F}' | '\u{205F}' | '\u{3000}' | '\u{FEFF}'
    )
}

/// JavaScript 的 `!isNaN(w)`（w 只會有小寫英數字與底線）：十進位、指數、0x / 0o / 0b
fn js_numeric(w: &str) -> bool {
    let all = |s: &str, f: fn(&u8) -> bool| !s.is_empty() && s.as_bytes().iter().all(f);
    if let Some(h) = w.strip_prefix("0x") {
        return all(h, u8::is_ascii_hexdigit);
    }
    if let Some(o) = w.strip_prefix("0o") {
        return all(o, |c| (b'0'..=b'7').contains(c));
    }
    if let Some(b) = w.strip_prefix("0b") {
        return all(b, |c| *c == b'0' || *c == b'1');
    }
    match w.split_once('e') {
        Some((m, e)) => all(m, u8::is_ascii_digit) && all(e, u8::is_ascii_digit),
        None => all(w, u8::is_ascii_digit),
    }
}

/// 取業者名稱裡的關鍵字（同 2.x `extractKeywords`）
pub fn extract_keywords(s: &str) -> Vec<String> {
    if s.is_empty() {
        return Vec::new();
    }
    // 小寫、非 [A-Za-z0-9_] 與空白以外的字元換成空白
    // （2.x 接著把 g-core / so-net 換成 g_core / sonet，但 - 已經被換掉了，那兩行實際上不會作用）
    let clean: String = s
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || js_is_space(c) {
                c
            } else {
                ' '
            }
        })
        .collect();
    clean
        .split(js_is_space)
        .filter(|w| w.len() >= 2 && !STOPWORDS.contains(w) && !js_numeric(w))
        .map(str::to_string)
        .collect()
}

/// raw 裡的 AS 號碼（`/AS(\d+)/i`）
pub fn extract_asn_number(raw: &str) -> Option<&str> {
    let b = raw.as_bytes();
    let mut i = 0;
    while i + 2 < b.len() {
        if b[i].eq_ignore_ascii_case(&b'a') && b[i + 1].eq_ignore_ascii_case(&b's') && b[i + 2].is_ascii_digit() {
            let start = i + 2;
            let mut end = start;
            while end < b.len() && b[end].is_ascii_digit() {
                end += 1;
            }
            return Some(&raw[start..end]);
        }
        i += 1;
    }
    None
}

fn alias(body: &str) -> Option<&'static [&'static str]> {
    DOMAIN_ALIASES.iter().find(|(k, _)| *k == body).map(|(_, v)| *v)
}

/// 網域主體（倒數第二段；是 com / net / org… 時再往前一段）
fn domain_body(domain: &str) -> String {
    let parts: Vec<&str> = domain.split('.').collect();
    let mut body = if parts.len() >= 2 {
        parts[parts.len() - 2].to_lowercase()
    } else {
        domain.to_string()
    };
    if ["com", "net", "org", "edu", "gov", "co", "ne"].contains(&body.as_str()) && parts.len() >= 3 {
        body = parts[parts.len() - 3].to_lowercase();
    }
    body
}

/// 權重：業者就是這個網域的擁有者（或別名品牌）→ 3，否則 1
pub fn calculate_weight(info: Option<&AsnInfo>, domain: &str) -> f64 {
    let Some(info) = info else { return 1.0 };
    let body = domain_body(domain);
    if info.has(&body) {
        return 3.0;
    }
    if let Some(a) = alias(&body) {
        if info.any_in(a) {
            return 3.0;
        }
    }
    1.0
}

pub fn is_official_owner(info: Option<&AsnInfo>, domain: &str) -> bool {
    calculate_weight(info, domain) >= 3.0
}

/// 第一名的業者是否信任候選業者（跨網互信、CDN 合作夥伴、巨頭信任通用 ISP）
pub fn is_trusted_partner(winner: Option<&AsnInfo>, cand: Option<&AsnInfo>) -> bool {
    let (Some(w), Some(c)) = (winner, cand) else { return false };
    for (key, trusted) in TRUSTED_CROSS_ISPS {
        if w.has(key) && c.any_in(trusted) {
            return true;
        }
    }
    for (owner, partners, with_tw) in CDN_PARTNERS {
        if w.has(owner) && (c.any_in(partners) || (*with_tw && c.any_in(TAIWAN_ISPS))) {
            return true;
        }
    }
    if w.any_in(GIANTS_ALLOWING_ISPS) && (c.any_in(GENERIC_ISP_KEYWORDS) || c.any_in(SPECIFIC_ISPS)) {
        return true;
    }
    false
}

/// 同一組：AS 號碼相同，或關鍵字有交集
pub fn is_same_group(a: Option<&AsnInfo>, b: Option<&AsnInfo>) -> bool {
    let (Some(a), Some(b)) = (a, b) else { return false };
    if let (Some(x), Some(y)) = (extract_asn_number(&a.raw), extract_asn_number(&b.raw)) {
        if x == y {
            return true;
        }
    }
    a.keywords.iter().any(|k| b.keywords.contains(k))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(isp: &str, org: &str, as_: &str) -> AsnInfo {
        AsnInfo::from_ip_api(isp, org, as_)
    }

    #[test]
    fn keywords() {
        let i = info("Cloudflare, Inc.", "Cloudflare, Inc.", "AS13335 Cloudflare, Inc.");
        assert_eq!(i.raw, "Cloudflare,_Inc.__AS13335_Cloudflare,_Inc.");
        assert_eq!(i.keywords, vec!["cloudflare", "cloudflare", "as13335", "cloudflare"]);
        assert_eq!(
            extract_keywords("G-Core Labs 123 1e5 0x1f ab_1 Ünïcode"),
            vec!["core", "labs", "ab_1", "code"]
        );
        assert_eq!(extract_asn_number("x__as4134_chinanet"), Some("4134"));
        assert_eq!(extract_asn_number("Unknown_ISP"), None);
    }

    #[test]
    fn weights_and_trust() {
        let cf = info("Cloudflare, Inc.", "", "AS13335 Cloudflare, Inc.");
        let fastly = info("Fastly, Inc.", "", "AS54113 Fastly, Inc.");
        let hinet = info(
            "Chunghwa Telecom Co., Ltd.",
            "Data Communication Business Group",
            "AS3462 Data Communication Business Group",
        );
        let fb = info("Facebook, Inc.", "", "AS32934 Facebook, Inc.");
        assert_eq!(calculate_weight(Some(&cf), "x.com"), 3.0);
        assert_eq!(calculate_weight(Some(&fb), "www.instagram.com"), 3.0);
        assert_eq!(calculate_weight(Some(&hinet), "www.google.com.tw"), 1.0);
        assert_eq!(calculate_weight(None, "a.com"), 1.0);
        assert!(is_trusted_partner(Some(&cf), Some(&fastly)));
        assert!(is_trusted_partner(Some(&cf), Some(&hinet))); // 巨頭 + 通用 ISP（telecom）
        assert!(!is_trusted_partner(Some(&hinet), Some(&fb)));
        assert!(is_same_group(Some(&cf), Some(&info("CF", "", "AS13335 x"))));
        assert!(!is_same_group(Some(&cf), Some(&fb)));
    }
}
