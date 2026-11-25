//! CDN 廠商定義（對齊 2.x `lib/cdn/providers.js`）：辨識方式（IP 範圍 / CNAME / 回應標頭）、POP 判斷、測速網址。
//!
//! - `alias`：走 IP 置換（任播型 CDN，任何節點都能服務任何網域，靠 SNI / Host 分流）
//! - `ecs`：走 ECS 突破（DNS 分流型 CDN，用台灣子網路去問權威 DNS 拿台灣節點）
//! - 只有 CNAME 的廠商只做網域蒐集與分析（設定裡開 `ecs: true` 也會嘗試 ECS 突破）

use std::collections::HashMap;
use std::sync::OnceLock;

/// 回應標頭（名稱小寫）
pub type Headers = [(String, String)];

/// 取標頭；沒有回空字串（同 2.x 的 `h[name] || ''`）
pub fn hv<'a>(h: &'a Headers, k: &str) -> &'a str {
    h.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str()).unwrap_or("")
}

#[derive(Debug)]
pub struct Provider {
    pub name: &'static str,
    pub label: &'static str,
    pub alias: bool,
    /// 預設走 ECS 突破（設定的 `ecs: false` 可以關掉）
    pub ecs: bool,
    pub ecs_capable: bool,
    /// 官方網路地圖沒有台灣 POP，改用「品質最好的鄰近節點」策略（Fastly）
    pub nearest: bool,
    /// IP 最後一段代表哪一組 TLS 憑證，換節點只換前三段（Fastly）
    pub octet: bool,
    pub cname: &'static [&'static str],
    /// POP 探測：（Host，路徑）
    pub probe: Option<(&'static str, &'static str)>,
    pub speed_url: Option<&'static str>,
    pub max_latency_ms: f64,
    pub seed_hosts: &'static [&'static str],
    /// 不在官方清單、但由這家服務的客戶自有網段
    pub extra_v4: &'static [&'static str],
    pub extra_v6: &'static [&'static str],
    /// App 自己選節點的服務（3.5.0 B3）：用戶端的 App 或服務自己的排程決定連哪個節點（影音、系統更新這類），
    /// DNS 的答案只是它的起點。只辨識與統計，不改寫、不 ECS、不跨 CDN（`cdn.appLayer` 可以關，
    /// 個別網域可以用 `/api/cdn/policy` 設成「一定換」）
    pub app_layer: bool,
    /// 台灣本地的 CDN（3.5.1）：節點本來就在台灣（中華電信 HiNet CDN）。只辨識、標成「已是台灣」，
    /// 不換、不 ECS、不跨 CDN（個別網域可以用 `/api/cdn/policy` 設成「一定換」）
    pub tw_native: bool,
}

const fn base(name: &'static str, label: &'static str, cname: &'static [&'static str]) -> Provider {
    Provider {
        name,
        label,
        alias: false,
        ecs: false,
        ecs_capable: false,
        nearest: false,
        octet: false,
        cname,
        probe: None,
        speed_url: None,
        max_latency_ms: 60.0,
        seed_hosts: &[],
        extra_v4: &[],
        extra_v6: &[],
        app_layer: false,
        tw_native: false,
    }
}

const fn tw_native(mut p: Provider) -> Provider {
    p.tw_native = true;
    p
}

const fn app_layer(mut p: Provider) -> Provider {
    p.app_layer = true;
    p
}

const fn capable(mut p: Provider) -> Provider {
    p.ecs_capable = true;
    p
}

/// 廠商表（順序同 2.x：IP 判斷與標頭判斷都依這個順序）
pub static PROVIDERS: &[Provider] = &[
    Provider {
        alias: true,
        probe: Some(("www.cloudflare.com", "/cdn-cgi/trace")),
        speed_url: Some("https://speed.cloudflare.com/__down?bytes=20000000"),
        max_latency_ms: 50.0,
        seed_hosts: &["www.cloudflare.com", "one.one.one.one", "speed.cloudflare.com", "discord.com", "www.canva.com", "medium.com"],
        ..base("cloudflare", "Cloudflare", &["cdn.cloudflare.net", "cloudflare.net", "cloudflare-ipfs.com"])
    },
    Provider {
        alias: true,
        probe: Some(("d1.awsstatic.com", "/")),
        speed_url: Some(
            "https://images-assets.nasa.gov/video/GSFC_20100722_Hubble_m10619_Exoplanets/GSFC_20100722_Hubble_m10619_Exoplanets~orig.mp4",
        ),
        seed_hosts: &["d1.awsstatic.com", "aws.amazon.com", "www.amazon.com", "images-assets.nasa.gov", "m.media-amazon.com", "www.primevideo.com"],
        ..base("cloudfront", "Amazon CloudFront", &["cloudfront.net"])
    },
    Provider {
        alias: true,
        nearest: true,
        octet: true,
        // GitHub（release-assets / objects / raw / avatars.githubusercontent.com、github.githubassets.com、GitHub Pages）
        extra_v4: &["185.199.108.0/22"],
        extra_v6: &["2606:50c0::/32"],
        probe: Some(("www.fastly.com", "/")),
        // Debian 官方鏡像（Fastly 服務）：純 HTTP 依 Host 分流，任何網段都能測，不受 TLS 憑證組影響
        speed_url: Some("http://deb.debian.org/debian/ls-lR.gz"),
        seed_hosts: &["www.fastly.com", "github.githubassets.com", "pypi.org", "www.reddit.com", "cdn.jsdelivr.net"],
        ..base("fastly", "Fastly", &["fastly.net", "fastlylb.net", "fastly-edge.com", "global.ssl.fastly.net"])
    },
    Provider {
        alias: true,
        probe: Some(("cdn.gcore.com", "/")),
        speed_url: Some("https://cc1-speedtest.tools.gcore.com/speedtest-backend/garbage.php?cors=true&ckSize=100"),
        seed_hosts: &["gcore.com", "cdn.gcore.com"],
        ..base("gcore", "Gcore", &["gcdn.co", "gcorelabs.net", "gcore.com"])
    },
    Provider {
        alias: true,
        probe: Some(("www.microsoft.com", "/")),
        speed_url: Some(
            "https://vscode.download.prss.microsoft.com/dbazure/download/stable/994fd12f8d3a5aa16f17d42c041e5809167e845a/VSCodeUserSetup-x64-1.107.1.exe",
        ),
        ..base(
            "azure",
            "Azure Front Door / CDN",
            &["azureedge.net", "azurefd.net", "afd.azureedge.net", "t-msedge.net", "a-msedge.net", "azurefd-t-prod.trafficmanager.net"],
        )
    },
    Provider {
        ecs: true,
        ..base(
            "akamai",
            "Akamai",
            &[
                "akamaiedge.net",
                "edgekey.net",
                "edgesuite.net",
                "akamai.net",
                "akamaized.net",
                "akamaihd.net",
                "akamaitechnologies.com",
                "akamaitechnologies.fr",
                "akadns.net",
                "akamaiedge-staging.net",
            ],
        )
    },
    // ---- 以下只做蒐集分析（CNAME 辨識），設定開 ecs: true 也會嘗試 ECS 突破 ----
    capable(base(
        "edgio",
        "Edgio / Edgecast / Limelight",
        &["edgecastcdn.net", "systemcdn.net", "edgio.net", "llnwd.net", "llnwi.net", "edgecastdns.net", "transactcdn.com"],
    )),
    capable(base("cdn77", "CDN77", &["cdn77.org", "cdn77.net", "rsc.cdn77.org"])),
    base("bunny", "BunnyCDN", &["b-cdn.net", "bunnycdn.ru", "bunny.net"]),
    capable(base("cdnetworks", "CDNetworks", &["cdngc.net", "cdnetworks.net", "panthercdn.com", "gccdn.net", "cdnga.net"])),
    capable(base(
        "tencent",
        "Tencent Cloud CDN / EdgeOne",
        &[
            "cdn.dnsv1.com",
            "dnsv1.com",
            "tdnsv5.com",
            "tdnsv6.com",
            "cdntip.com",
            "qcloudcdn.com",
            // EdgeOne 的 `eo.dnseN.com` 還有其他編號：由 [`CNAME_PATTERNS`] 比對，這兩個留著（索引直接命中）
            "eo.dnse0.com",
            "eo.dnse1.com",
            "edgeone.app",
            "dsa.dnsv1.com",
        ],
    )),
    capable(base(
        "alibaba",
        "Alibaba Cloud CDN",
        &[
            "alikunlun.com",
            "alikunlun.net",
            "kunlunca.com",
            "kunlunsl.com",
            "kunlungr.com",
            "cdngslb.com",
            "alicdngslb.com",
            "tbcache.com",
            "w.alikunlun.com",
            // 3.5.1：官方文件寫的是「`*.*kunlun*.com`」，其他 `kunlunXX.com` 由 [`CNAME_PATTERNS`] 比對
            "kunluncan.com",
            "kunlunaq.com",
            "kunlunpi.com",
        ],
    )),
    capable(base(
        "wangsu",
        "Wangsu / ChinaNetCenter",
        &[
            "wscdns.com",
            "wsglb0.com",
            "chinanetcenter.com",
            "lxdns.com",
            "wscloudcdn.com",
            "ourwebpic.com",
            // 3.5.1：權威 DNS 跟既有的網宿後綴同一組（`cdn30.org`）
            "wswebpic.com",
            "wswebcdn.com",
            "cdn20.com",
        ],
    )),
    capable(base(
        "bytedance",
        "BytePlus / Volcengine",
        &["bytecdn.cn", "bytedns.net", "volcgslb.com", "bytegslb.com", "tiktokcdn.com", "byteeffecttos.com", "bytednsdoc.com",
          // 3.5.1：權威 DNS 是火山引擎（`volc-dns`）
          "cdnbuild.net"],
    )),
    // Google（影音、更新下載）與 Apple（系統更新、App Store）：節點由服務自己排程，標成 App 層（3.5.0 B3）
    app_layer(base(
        "google",
        "Google",
        &["googlehosted.com", "ghs.google.com", "googleusercontent.com", "gvt1.com", "l.google.com", "googlevideo.com"],
    )),
    app_layer(capable(base(
        "apple",
        "Apple CDN",
        &["aaplimg.com", "apple-dns.net", "cdn-apple.com", "apple.com.edgekey.net"],
    ))),
    base("microsoft", "Microsoft", &["msedge.net", "trafficmanager.net", "msecnd.net", "vo.msecnd.net", "footprintdns.com"]),
    base("stackpath", "StackPath / Highwinds", &["stackpathdns.com", "hwcdn.net", "netdna-cdn.com", "netdna-ssl.com"]),
    base("imperva", "Imperva", &["incapdns.net", "impervadns.net"]),
    // `vercel-dns-0NN.com` 這類有編號的由 [`CNAME_PATTERNS`] 比對
    base("vercel", "Vercel", &["vercel-dns.com", "vercel.app"]),
    base("netlify", "Netlify", &["netlify.app", "netlifyglobalcdn.com"]),
    base("keycdn", "KeyCDN", &["kxcdn.com"]),
    base("cachefly", "CacheFly", &["cachefly.net"]),
    base("qwilt", "Qwilt", &["qwilted-cds.cqloud.com", "qwilt.com"]),
    base("github", "GitHub Pages", &["github.io", "githubusercontent.com"]),
    base("shopify", "Shopify", &["myshopify.com", "shops.myshopify.com"]),
    base("line", "LINE CDN", &["line-scdn.net", "line-apps.com"]),
    // ---- 3.5.1 新增：只認得（CNAME 辨識），沒有官方公布的台灣節點範圍，黑潮不換（收或不收的理由見規格 06 第 3.9 節）----
    // 台灣本地的 CDN：節點本來就在台灣，標成「已是台灣」
    tw_native(base("hinet", "中華電信 HiNet CDN", &["cdn.hinet.net"])),
    base("baishan", "白山雲 Baishan", &["bsclink.cn", "trpcdn.net"]),
    base("jiashule", "知道創宇 加速樂", &["jiashule.com"]),
    base("baidu", "百度雲加速", &["shifen.com"]),
    base("radware", "Radware Cloud WAF", &["radwarecloud.net"]),
    base("f5xc", "F5 Distributed Cloud", &["ves.io"]),
    base("aliwaf", "阿里雲 WAF", &["yundunwaf3.com"]),
    base("huaweiwaf", "華為雲 WAF", &["huaweicloudwaf.com"]),
    base("wpengine", "WP Engine", &["wpeproxy.com"]),
    base("hostinger", "Hostinger CDN", &["cdn.hstgr.net"]),
    base("jstream", "J-Stream", &["stream.ne.jp"]),
];

/// 有編號的 CNAME 後綴（3.5.1）：倒數第二段是「固定前綴＋數字或英文字母」，編號會一直增加，不逐一列舉。
/// 只在 [`provider_by_cname`] 的索引沒命中時比（幾個位元組的前綴比對，不配置）
struct CnamePattern {
    /// 倒數第二段的開頭（小寫）
    prefix: &'static str,
    /// 開頭之後接幾個字元（最少，最多）
    len: (usize, usize),
    /// 接的是數字（true）還是英文字母（false）
    digits: bool,
    /// 最後一段（小寫）
    tld: &'static str,
    /// 倒數第三段一定要是這個（`eo.dnse2.com` 的 `eo`）
    before: Option<&'static str>,
    provider: &'static str,
}

static CNAME_PATTERNS: &[CnamePattern] = &[
    // 騰訊 EdgeOne：`<網域>.eo.dnse0.com`～`eo.dnse5.com`…
    CnamePattern {
        prefix: "dnse",
        len: (1, 2),
        digits: true,
        tld: "com",
        before: Some("eo"),
        provider: "tencent",
    },
    // Vercel：`vercel-dns-013.com`、`vercel-dns-016.com`、`vercel-dns-017.com`…
    CnamePattern {
        prefix: "vercel-dns-",
        len: (1, 3),
        digits: true,
        tld: "com",
        before: None,
        provider: "vercel",
    },
    // 阿里雲 CDN：`<網域>.w.kunluncan.com`、`kunlunaq.com`、`kunlunpi.com`…（官方文件寫「`*.*kunlun*.com`」）
    CnamePattern {
        prefix: "kunlun",
        len: (2, 4),
        digits: false,
        tld: "com",
        before: None,
        provider: "alibaba",
    },
];

/// 倒數第三段是不是 `b`（`host` 是 `…b.<k>`，`b` 前面是開頭或點）
fn label_before(host: &[u8], k_len: usize, b: &str) -> bool {
    let b = b.as_bytes();
    let Some(end) = host.len().checked_sub(k_len + 1) else {
        return false;
    };
    if host[end] != b'.' || end < b.len() {
        return false;
    }
    let start = end - b.len();
    host[start..end].eq_ignore_ascii_case(b) && (start == 0 || host[start - 1] == b'.')
}

/// 依 [`CNAME_PATTERNS`] 判斷。`host` 已經去掉結尾的點，`k` 是它的最後兩段
pub(crate) fn provider_by_pattern(host: &str, k: &str) -> Option<&'static str> {
    let (label, tld) = k.split_once('.')?;
    let l = label.as_bytes();
    CNAME_PATTERNS
        .iter()
        .find(|p| {
            let n = l.len().saturating_sub(p.prefix.len());
            l.len() > p.prefix.len()
                && (p.len.0..=p.len.1).contains(&n)
                && tld.eq_ignore_ascii_case(p.tld)
                && l[..p.prefix.len()].eq_ignore_ascii_case(p.prefix.as_bytes())
                && l[p.prefix.len()..]
                    .iter()
                    .all(|c| if p.digits { c.is_ascii_digit() } else { c.is_ascii_alphabetic() })
                && match p.before {
                    Some(b) => label_before(host.as_bytes(), k.len(), b),
                    None => true,
                }
        })
        .map(|p| p.provider)
}

pub fn get(name: &str) -> Option<&'static Provider> {
    PROVIDERS.iter().find(|p| p.name == name)
}

/// 顯示名稱（不認識的就用代號）
pub fn label(name: &str) -> &str {
    get(name).map(|p| p.label).unwrap_or(name)
}

/// CNAME 後綴索引：依「最後兩段」分組（`d111.cloudfront.net` 只要比 `cloudfront.net` 那一組），
/// 組內長的在前（同 2.x：長的先比）。只有一段的後綴放 `rest`
struct CnameIndex {
    by2: HashMap<&'static str, Vec<(&'static str, &'static str)>>,
    rest: Vec<(&'static str, &'static str)>,
}

/// 最後兩段（不到兩段回 None）
pub(crate) fn last2(s: &str) -> Option<&str> {
    let i = s.rfind('.')?;
    Some(match s[..i].rfind('.') {
        Some(j) => &s[j + 1..],
        None => s,
    })
}

fn cname_index() -> &'static CnameIndex {
    static IDX: OnceLock<CnameIndex> = OnceLock::new();
    IDX.get_or_init(|| {
        let mut v: Vec<(&str, &str)> = PROVIDERS.iter().flat_map(|p| p.cname.iter().map(move |s| (*s, p.name))).collect();
        v.sort_by_key(|x| std::cmp::Reverse(x.0.len())); // 長的先比（穩定排序，同 2.x）
        let mut idx = CnameIndex {
            by2: HashMap::new(),
            rest: Vec::new(),
        };
        for x in v {
            match last2(x.0) {
                Some(k) => idx.by2.entry(k).or_default().push(x),
                None => idx.rest.push(x),
            }
        }
        idx
    })
}

/// 依 CNAME 後綴判斷廠商
pub fn provider_by_cname(host: &str) -> Option<&'static str> {
    // 每個有 CNAME 的回應都會跑：不配置記憶體，不分大小寫比對結尾
    let host = host.trim_end_matches('.');
    let h = host.as_bytes();
    let hit = |list: &[(&'static str, &'static str)]| {
        list.iter()
            .find(|(suf, _)| {
                let s = suf.as_bytes();
                h.len() >= s.len()
                    && h[h.len() - s.len()..].eq_ignore_ascii_case(s)
                    && (h.len() == s.len() || h[h.len() - s.len() - 1] == b'.')
            })
            .map(|x| x.1)
    };
    let idx = cname_index();
    if let Some(k) = last2(host) {
        let mut buf = [0u8; 64];
        let group = if k.len() <= buf.len() {
            let b = &mut buf[..k.len()];
            b.copy_from_slice(k.as_bytes());
            b.make_ascii_lowercase();
            std::str::from_utf8(b).ok().and_then(|k| idx.by2.get(k))
        } else {
            idx.by2.get(k.to_ascii_lowercase().as_str())
        };
        if let Some(p) = group.and_then(|g| hit(g)) {
            return Some(p);
        }
        if let Some(p) = provider_by_pattern(host, k) {
            return Some(p);
        }
    }
    hit(&idx.rest)
}

/// 台灣 POP：TPE 台北、KHH 高雄、TSA 松山、RMQ 台中、TXG 台中、TNN 台南（開頭比對，不分大小寫）
pub fn is_tw_pop(pop: &str) -> bool {
    let b = pop.as_bytes();
    b.len() >= 3
        && ["TPE", "KHH", "TSA", "RMQ", "TXG", "TNN"]
            .iter()
            .any(|p| b[..3].eq_ignore_ascii_case(p.as_bytes()))
}

fn is_alpha(c: u8) -> bool {
    c.is_ascii_alphabetic()
}

/// 第一段連續 3 個英文字母（轉大寫）
fn first3(s: &str) -> String {
    let b = s.as_bytes();
    (0..b.len().saturating_sub(2))
        .find(|&i| b[i..i + 3].iter().all(|&c| is_alpha(c)))
        .map(|i| s[i..i + 3].to_ascii_uppercase())
        .unwrap_or_default()
}

fn contains_ci(hay: &str, needle: &str) -> bool {
    hay.to_ascii_lowercase().contains(needle)
}

/// `needle` 後面緊接 3 個英文字母的第一個位置（needle 不分大小寫與否由 `ci` 決定）
fn after3(hay: &str, needle: &str, ci: bool) -> Option<String> {
    let low;
    let h: &str = if ci {
        low = hay.to_ascii_lowercase();
        &low
    } else {
        hay
    };
    let b = hay.as_bytes();
    let mut from = 0;
    while let Some(p) = h[from..].find(needle) {
        let i = from + p + needle.len();
        if i + 3 <= b.len() && b[i..i + 3].iter().all(|&c| is_alpha(c)) {
            return Some(hay[i..i + 3].to_string());
        }
        from = from + p + 1;
    }
    None
}

/// 結尾是 `-XXX`（3 個字母）
fn dash3_end(s: &str, ci: bool) -> Option<String> {
    let b = s.as_bytes();
    if b.len() < 4 || b[b.len() - 4] != b'-' {
        return None;
    }
    let t = &b[b.len() - 3..];
    let ok = if ci {
        t.iter().all(|&c| is_alpha(c))
    } else {
        t.iter().all(|c| c.is_ascii_uppercase())
    };
    ok.then(|| s[s.len() - 3..].to_string())
}

impl Provider {
    /// 從回應判斷 POP（三碼機場代號）；判斷不出來回空字串
    pub fn pop(&self, h: &Headers, body: &str) -> String {
        match self.name {
            "cloudflare" => {
                if let Some(m) = after3(body, "colo=", true) {
                    return m.to_ascii_uppercase();
                }
                dash3_end(hv(h, "cf-ray"), true).map(|m| m.to_ascii_uppercase()).unwrap_or_default()
            }
            "cloudfront" => first3(hv(h, "x-amz-cf-pop")),
            "fastly" => {
                let v = hv(h, "x-served-by");
                let last = v.rsplit(',').next().unwrap_or("").trim();
                if let Some(m) = dash3_end(last, false) {
                    return m;
                }
                // cache-xxx 後面至少一個數字
                let low = last.to_ascii_lowercase();
                let b = low.as_bytes();
                let mut from = 0;
                while let Some(p) = low[from..].find("cache-") {
                    let i = from + p + 6;
                    if i + 4 <= b.len() && b[i..i + 3].iter().all(|&c| is_alpha(c)) && b[i + 3].is_ascii_digit() {
                        return low[i..i + 3].to_ascii_uppercase();
                    }
                    from = from + p + 1;
                }
                String::new()
            }
            "gcore" => {
                let id = match hv(h, "x-id") {
                    "" => hv(h, "x-id-fe"),
                    v => v,
                };
                let b = id.as_bytes();
                let letters = b.iter().take_while(|&&c| is_alpha(c)).count();
                if letters == 0 {
                    return String::new();
                }
                let digits = b[letters..].iter().take_while(|c| c.is_ascii_digit()).count();
                if b.get(letters + digits) != Some(&b'-') {
                    return String::new();
                }
                id[..letters.min(3)].to_ascii_uppercase()
            }
            "azure" => {
                let r = match hv(h, "x-azure-ref") {
                    "" => hv(h, "x-msedge-ref"),
                    v => v,
                };
                if let Some(m) = after3(r, "Ref B: ", false) {
                    return m.to_ascii_uppercase();
                }
                let up = r.to_ascii_uppercase();
                match (up.find("TPE"), up.find("KHH")) {
                    (Some(a), Some(b)) => (if a < b { "TPE" } else { "KHH" }).to_string(),
                    (Some(_), None) => "TPE".into(),
                    (None, Some(_)) => "KHH".into(),
                    _ => String::new(),
                }
            }
            _ => String::new(),
        }
    }

    /// 回應是不是來自這家 CDN；沒有標頭特徵可判斷的廠商回 None
    pub fn is_provider(&self, h: &Headers) -> Option<bool> {
        Some(match self.name {
            "cloudflare" => !hv(h, "cf-ray").is_empty() || contains_ci(hv(h, "server"), "cloudflare"),
            "cloudfront" => {
                !hv(h, "x-amz-cf-pop").is_empty() || contains_ci(hv(h, "via"), "cloudfront") || contains_ci(hv(h, "x-cache"), "cloudfront")
            }
            "fastly" => {
                let v = hv(h, "x-served-by");
                !v.is_empty() && v.contains("cache-")
            }
            "gcore" => !hv(h, "x-id").is_empty() || !hv(h, "x-id-fe").is_empty(),
            "azure" => !hv(h, "x-azure-ref").is_empty() || !hv(h, "x-msedge-ref").is_empty(),
            "akamai" => {
                contains_ci(hv(h, "server"), "akamai")
                    || !hv(h, "x-akamai-transformed").is_empty()
                    || contains_ci(hv(h, "x-cache"), "akamai")
            }
            _ => return None,
        })
    }

    /// 有 POP 判斷方式的廠商（2.x 有定義 `pop()` 的）
    pub fn has_pop(&self) -> bool {
        matches!(self.name, "cloudflare" | "cloudfront" | "fastly" | "gcore" | "azure" | "akamai")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detected {
    pub provider: Option<&'static str>,
    pub pop: String,
}

fn is_word(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// `\b([A-Z]{3})\d*\b` 的第一個符合
fn generic_pop(s: &str) -> Option<String> {
    let b = s.as_bytes();
    for i in 0..b.len().saturating_sub(2) {
        if i > 0 && is_word(b[i - 1]) {
            continue;
        }
        if !b[i..i + 3].iter().all(|c| c.is_ascii_uppercase()) {
            continue;
        }
        let mut j = i + 3;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        if j == b.len() || !is_word(b[j]) {
            return Some(s[i..i + 3].to_string());
        }
    }
    None
}

/// 從回應標頭推測 CDN 廠商與 POP（驗證與分析用）
pub fn detect_from_headers(h: &Headers, body: &str) -> Detected {
    for p in PROVIDERS {
        if p.is_provider(h) == Some(true) {
            return Detected {
                provider: Some(p.name),
                pop: p.pop(h, body),
            };
        }
    }
    // 通用：一些 CDN 會把 IATA 代碼放在這些標頭（server 不算）
    for k in ["x-edge-location", "x-pop", "x-served-by", "x-cache-pop", "cdn-pop", "x-bunny-pop"] {
        if let Some(pop) = generic_pop(hv(h, k)) {
            return Detected { provider: None, pop };
        }
    }
    Detected {
        provider: None,
        pop: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(kv: &[(&str, &str)]) -> Vec<(String, String)> {
        kv.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn cname_suffixes() {
        assert_eq!(provider_by_cname("e1.dscx.akamaiedge.net."), Some("akamai"));
        assert_eq!(provider_by_cname("x.cdn.cloudflare.net"), Some("cloudflare"));
        assert_eq!(provider_by_cname("dualstack.reddit.map.fastly.net"), Some("fastly"));
        assert_eq!(provider_by_cname("apple.com.edgekey.net"), Some("apple"), "長的後綴先比");
        assert_eq!(provider_by_cname("www.apple.com.edgekey.net"), Some("apple"));
        assert_eq!(provider_by_cname("foo.edgekey.net"), Some("akamai"));
        assert_eq!(provider_by_cname("notcloudfront.net"), None);
        assert_eq!(provider_by_cname("CLOUDFRONT.NET"), Some("cloudfront"));
        assert_eq!(provider_by_cname("x.vo.msecnd.net"), Some("microsoft"));
    }

    /// 3.5.1：已收錄業者的新後綴、有編號的後綴用規則比對；舊的比對不受影響
    #[test]
    fn cname_new_suffixes_and_patterns() {
        // 騰訊 EdgeOne：eo.dnse0～eo.dnse5 以後的編號
        for n in 0..=9 {
            assert_eq!(
                provider_by_cname(&format!("www.example.com.eo.dnse{n}.com.")),
                Some("tencent"),
                "{n}"
            );
        }
        assert_eq!(provider_by_cname("www.example.com.EO.DNSE12.COM"), Some("tencent"));
        assert_eq!(provider_by_cname("eo.dnse2.com"), Some("tencent"));
        // 一定要有 `eo` 那一段、編號是數字、最多兩位
        for host in [
            "www.example.com.dnse2.com",
            "www.example.com.xeo.dnse2.com",
            "www.example.com.eo.dnsex.com",
            "www.example.com.eo.dnse.com",
            "www.example.com.eo.dnse123.com",
            "www.example.com.eo.dnse2.net",
            "dnse2.com",
        ] {
            assert_eq!(provider_by_cname(host), None, "{host}");
        }
        // Vercel：vercel-dns-0NN
        for host in [
            "cname.vercel-dns-016.com",
            "cname.vercel-dns-017.com.",
            "x.vercel-dns-013.com",
            "vercel-dns-1.com",
        ] {
            assert_eq!(provider_by_cname(host), Some("vercel"), "{host}");
        }
        assert_eq!(provider_by_cname("cname.vercel-dns.com"), Some("vercel"), "舊的照舊");
        for host in [
            "x.vercel-dns-.com",
            "x.vercel-dns-0167.com",
            "x.vercel-dns-01a.com",
            "x.myvercel-dns-016.com",
        ] {
            assert_eq!(provider_by_cname(host), None, "{host}");
        }
        // 阿里雲：<網域>.w.kunlunXX.com
        for host in [
            "www.example.com.w.kunluncan.com",
            "www.example.com.w.kunlunaq.com",
            "www.example.com.w.kunlunpi.com",
            "www.example.com.w.kunlunhuf.com",
            "www.example.com.w.kunlunca.com",
            "www.example.com.w.alikunlun.com",
        ] {
            assert_eq!(provider_by_cname(host), Some("alibaba"), "{host}");
        }
        for host in [
            "x.kunlun.com",
            "x.kunlun1.com",
            "x.kunlunabcde.com",
            "x.xkunlunca.com",
            "x.kunlunca.net",
        ] {
            assert_eq!(provider_by_cname(host), None, "{host}");
        }
        // 網宿、火山引擎的新後綴
        for host in [
            "www.example.com.wswebpic.com",
            "www.example.com.wswebcdn.com",
            "www.example.com.cdn20.com",
        ] {
            assert_eq!(provider_by_cname(host), Some("wangsu"), "{host}");
        }
        assert_eq!(provider_by_cname("www.example.com.cdnbuild.net"), Some("bytedance"));
        // 新的業者（只認得）
        for (host, p) in [
            ("www.example.com.cdn.hinet.net", "hinet"),
            ("www.example.com.bsclink.cn", "baishan"),
            ("www.example.com.trpcdn.net", "baishan"),
            ("www.example.com.jiashule.com", "jiashule"),
            ("www.example.com.n.shifen.com", "baidu"),
            ("www.example.com.radwarecloud.net", "radware"),
            ("www.example.com.ves.io", "f5xc"),
            ("www.example.com.yundunwaf3.com", "aliwaf"),
            ("www.example.com.huaweicloudwaf.com", "huaweiwaf"),
            ("www.example.com.wpeproxy.com", "wpengine"),
            ("www.example.com.cdn.hstgr.net", "hostinger"),
            ("www.example.com.stream.ne.jp", "jstream"),
        ] {
            assert_eq!(provider_by_cname(host), Some(p), "{host}");
        }
        // 只有 `cdn.hinet.net` 底下才是 HiNet CDN（ISP 其他主機名稱不算）
        assert_eq!(provider_by_cname("host.dynamic.hinet.net"), None);
        assert!(get("hinet").unwrap().tw_native && !get("hinet").unwrap().alias);
        assert!(PROVIDERS
            .iter()
            .filter(|p| p.tw_native)
            .all(|p| !p.alias && !p.ecs && !p.ecs_capable));
    }

    #[test]
    fn tw_pops() {
        for p in ["TPE", "tpe51", "KHH", "TSA", "RMQ", "TXG", "TNN", "TPE50-C1"] {
            assert!(is_tw_pop(p), "{p}");
        }
        for p in ["HKG", "NRT", "", "TP", "XTPE"] {
            assert!(!is_tw_pop(p), "{p}");
        }
    }

    #[test]
    fn pops_from_headers() {
        let cf = get("cloudflare").unwrap();
        assert_eq!(cf.pop(&h(&[]), "fl=1\nip=1.2.3.4\ncolo=tpe\n"), "TPE");
        assert_eq!(cf.pop(&h(&[("cf-ray", "8a1b2c3d-KHH")]), ""), "KHH");
        assert_eq!(cf.pop(&h(&[("cf-ray", "8a1b2c3d")]), ""), "");
        let cfr = get("cloudfront").unwrap();
        assert_eq!(cfr.pop(&h(&[("x-amz-cf-pop", "TPE52-P1")]), ""), "TPE");
        let f = get("fastly").unwrap();
        assert_eq!(
            f.pop(&h(&[("x-served-by", "cache-iad-kiad7000-IAD, cache-hkg17920-HKG")]), ""),
            "HKG"
        );
        assert_eq!(f.pop(&h(&[("x-served-by", "cache-nrt-rjtt8900042-NRT")]), ""), "NRT");
        assert_eq!(f.pop(&h(&[("x-served-by", "cache-tyo11953")]), ""), "TYO");
        assert_eq!(f.pop(&h(&[("x-served-by", "cache-tyo")]), ""), "");
        let g = get("gcore").unwrap();
        assert_eq!(g.pop(&h(&[("x-id", "fr5-hw-edge-gc17")]), ""), "FR");
        assert_eq!(g.pop(&h(&[("x-id", ""), ("x-id-fe", "tpe1-up-gc23")]), ""), "TPE");
        assert_eq!(g.pop(&h(&[("x-id", "-x")]), ""), "");
        let az = get("azure").unwrap();
        assert_eq!(
            az.pop(&h(&[("x-azure-ref", "0abc Ref A: 123 Ref B: TPE30EDGE0108 Ref C: 2026")]), ""),
            "TPE"
        );
        assert_eq!(az.pop(&h(&[("x-msedge-ref", "Ref A: x Ref B: 12 khh")]), ""), "KHH");
        assert!(get("akamai").unwrap().is_provider(&h(&[("server", "AkamaiGHost")])).unwrap());
        assert_eq!(get("bunny").unwrap().is_provider(&h(&[])), None);
    }

    #[test]
    fn detect() {
        let d = detect_from_headers(&h(&[("server", "cloudflare"), ("cf-ray", "x-TPE")]), "");
        assert_eq!((d.provider, d.pop.as_str()), (Some("cloudflare"), "TPE"));
        let d = detect_from_headers(&h(&[("x-bunny-pop", "BunnyCDN-TW1-1103")]), "");
        assert_eq!((d.provider, d.pop.as_str()), (None, ""));
        let d = detect_from_headers(&h(&[("x-pop", "edge TPE12 x")]), "");
        assert_eq!((d.provider, d.pop.as_str()), (None, "TPE"));
        let d = detect_from_headers(&h(&[("server", "NGX TPE")]), "");
        assert_eq!(d.pop, "", "server 不算");
    }
}
