//! 公開網頁（同 2.x `site.js`，規格 02 第 7.1 節）：跟 DoH 共用網域與埠
//!
//! | 路徑 | 內容 |
//! |---|---|
//! | `/`、`/index.html` | 首頁（特色、匿名統計、設定教學、「這台裝置有沒有在用」偵測） |
//! | `/api/public/stats?range=today\|7d\|30d` | 匿名統計（不含任何 IP、只列多人共同造訪的網站） |
//! | `/api/public/presence` | 這個訪客 IP 有沒有在用（見 [`crate::presence`]） |
//! | `/api/public/info` | 連線資訊（DoH 網址、DoT 主機、IP） |
//! | `/apple/doh.mobileconfig`、`/apple/dot.mobileconfig` | iPhone / iPad / Mac 描述檔 |
//! | `/favicon.ico`、`/favicon.svg`、`/robots.txt` | 圖示、禁止搜尋引擎收錄 |
//! | `site.detailPath`（預設 `/detail`）`/` | 隱藏的詳細數據頁（不出現在首頁任何連結），`…/api/*` 是唯讀的管理 API |
//!
//! 網頁檔放在 `data/site/`（執行期是 `app::share_dir(cfg)/site/`），`site.htmlFile` / `site.detailFile`
//! 可以換成自己的版本；檔案裡的 `{{HOST}}` 換成網域、`{{DOH_PATH}}` 換成 DoH 路徑。
//!
//! **網域**只來自設定 `site.hostname`。沒設定（空白）時改用請求的 `Host` 標頭（檢查過只含網域字元），
//! 連 `Host` 都沒有就顯示中性的佔位網域 [`PLACEHOLDER_HOST`]；這時 IP 查詢與「正在使用」偵測只能判斷到
//! 「這個網路有裝置在用」。
//!
//! # 怎麼接（給整合的人）
//!
//! 1. 啟動時（`AppState` 建好之後）：
//!    ```ignore
//!    let presence = kuroshio::presence::Presence::from_cfg(cfg); // check.enabled=false 時是 None
//!    let site = kuroshio::site::Site::new(cfg, state.clone(), presence.clone());      // site.enabled=false 時是 None
//!    if let Some(s) = &site { s.spawn(); }                                            // 每小時查一次網域自己的 IP
//!    ```
//! 2. DoH 監聽（HTTP/1.1、HTTP/2、HTTP/3 都一樣）收到請求時，**先**問網頁，`None` 才交給原本的 DoH 處理：
//!    ```ignore
//!    let client = kuroshio::site::client_ip(peer, xff_header, opts.trust_proxy);
//!    if let Some(r) = site.handle(method.as_str(), uri.path(), uri.query().unwrap_or(""), client, host_header).await {
//!        // r.status、r.headers、r.body 原樣寫回；HEAD 的 body 已經是空的（content-length 標頭是 GET 的長度）
//!    }
//!    ```
//!    `handle` 對 DoH 路徑（`listen.doh.path` 與 `/dns-query`）、帶 `?dns=` 的請求、GET / HEAD 以外的方法都回 `None`。
//!    `host_header` 是 HTTP/1.1 的 `Host` 或 HTTP/2、3 的 `:authority`（`uri.authority()`）。
//! 3. 解析器（`Resolver::handle_inner`）：
//!    - 每次查詢（跟 `stats.count(Kind::Query)` 同一個地方）：`presence.record(ctx.proto, ctx.client, &qname)`，
//!      以及 `stats.query_name(&qname, ctx.client)`
//!    - 過濾沒擋下、`qtype == A` 時：`stats.site(&qname, ctx.client)`（公開頁的網站排行）
//!    - 每個呼叫 `stats.blocked(cat)` 的地方再加 `stats.blocked_name(&qname, ctx.client, cat)`
//!    - `serve()` 決定 TTL 時：`if let Some(cap) = presence.own_host_ttl(qname) { ttl = ttl.min(cap) }`，
//!      寫入快取時也一樣壓短（2.x 連 CNAME 過去的 DDNS 名稱一起壓，見 `resolver.js` 的 `isOwnName`）
//! 4. 統計想跨重開機保留時：`stats.snapshot()` 交給 `Persister`（例如檔名 `stats.json`），啟動時 `stats.restore()`；
//!    記憶體吃緊時記憶體控制會縮小熱門排行（`stats.shed_tops`）。管理 API 的 `/api/routing` 可以改回傳
//!    `stats.routing_json()`（每天一筆，同 2.x）。

use crate::admin::parse_query;
use crate::app::AppState;
use crate::presence::Presence;
use bytes::Bytes;
use kuroshio_config::get;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

/// 搜尋引擎不收錄（同 2.x）
pub const NOINDEX: &str = "noindex, nofollow, noarchive, nosnippet, noimageindex";

/// 沒設定網域、請求也沒有 Host 時顯示的佔位網域（`.example` 是保留給文件用的頂級網域）
pub const PLACEHOLDER_HOST: &str = "dns.example";

/// 詳細數據頁可以呼叫的管理 API（只能看、不能改；同 2.x `admin-api.js` 的 `READ_ONLY`）
pub const READ_ONLY: &[&str] = &[
    "/api/status",
    "/api/upstreams",
    "/api/benchmark",
    "/api/cdn/pools",
    "/api/cdn/v6nodes",
    "/api/cdn/summary",
    "/api/cdn/domains",
    "/api/jobs",
    "/api/trace",
    "/api/filter/check",
    "/api/routing",
];

/// 詳細數據頁的預設路徑
const DEFAULT_DETAIL_PATH: &str = "/detail";

/// 公開統計的快取時間
const STATS_CACHE: Duration = Duration::from_secs(10);

/// 詳細頁比較花力氣的唯讀 API 每分鐘最多幾次（全部訪客合計）。
/// 詳細頁只靠「知道路徑」保護，預設路徑又是公開的，不能讓外面的人無限次叫這台去問所有上游、測 IP、輸出整個資料庫
const TRACE_PER_MINUTE: u32 = 20;
const DOMAINS_PER_MINUTE: u32 = 30;
/// 同時進行的追蹤
const TRACE_CONCURRENCY: usize = 2;

/// 圖示：深靛藍的海 + 三道洋流（跟公開頁的標誌一樣）
const FAVICON: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#0b2152"/><g fill="none" stroke-width="5" stroke-linecap="round"><path d="M12 24c7-6 13-6 20 0s13 6 20 0" stroke="#22d3c5"/><path d="M12 35c7-6 13-6 20 0s13 6 20 0" stroke="#27b4ea"/><path d="M12 46c7-6 13-6 20 0s13 6 20 0" stroke="#fff"/></g></svg>"##;

/// 網頁回應：狀態碼、標頭、內容（HEAD 時內容是空的）
#[derive(Debug, Clone)]
pub struct SiteResponse {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub body: Bytes,
}

impl SiteResponse {
    /// 取某個標頭（測試、記錄用）
    pub fn header(&self, k: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(k))
            .map(|(_, v)| v.as_str())
    }
}

/// 一般回應：加上不收錄、nosniff、no-referrer（同 2.x `send()`）
fn send(status: u16, ctype: &str, body: impl Into<Bytes>, extra: &[(&'static str, String)]) -> SiteResponse {
    let mut headers = vec![
        ("content-type", ctype.to_string()),
        ("x-robots-tag", NOINDEX.to_string()),
        ("x-content-type-options", "nosniff".to_string()),
        ("referrer-policy", "no-referrer".to_string()),
    ];
    headers.extend(extra.iter().cloned());
    SiteResponse {
        status,
        headers,
        body: body.into(),
    }
}

fn json_resp(status: u16, v: &Value, cache: &str) -> SiteResponse {
    send(
        status,
        "application/json; charset=utf-8",
        serde_json::to_vec(v).unwrap_or_default(),
        &[("cache-control", cache.to_string())],
    )
}

/// 隱藏詳細頁給親友看，不顯示誰的 IP（只留前兩段，同 2.x `maskIp`）
pub fn mask_ip(ip: &str) -> String {
    if ip.contains(':') {
        let p: Vec<&str> = ip.split(':').take(2).collect();
        return format!("{}:…", p.join(":"));
    }
    let p: Vec<&str> = ip.split('.').collect();
    if p.len() == 4 {
        format!("{}.{}.x.x", p[0], p[1])
    } else {
        "…".to_string()
    }
}

/// 訪客的真實 IP：反向代理在本機（`trust_proxy` 且連線來自 127.0.0.1 / ::1）時採用 X-Forwarded-For 的第一個位址，
/// 也接受 IIS 會帶的 `1.2.3.4:5678`、`[::1]:5678` 格式（同 2.x `cleanIp`）
pub fn client_ip(peer: IpAddr, forwarded_for: Option<&str>, trust_proxy: bool) -> IpAddr {
    let peer = peer.to_canonical();
    if !(trust_proxy && peer.is_loopback()) {
        return peer;
    }
    let Some(first) = forwarded_for.and_then(|v| v.split(',').next()).map(str::trim) else {
        return peer;
    };
    first
        .parse::<IpAddr>()
        .ok()
        .or_else(|| first.parse::<SocketAddr>().ok().map(|s| s.ip()))
        .or_else(|| first.trim_start_matches('[').split(']').next().and_then(|s| s.parse().ok()))
        .map(|ip| ip.to_canonical())
        .unwrap_or(peer)
}

/// 請求的 Host 標頭 → 網域（去掉埠號、只接受網域字元，避免把奇怪的內容塞進網頁）
pub fn request_host(h: &str) -> Option<String> {
    let h = h.trim();
    if let Some(rest) = h.strip_prefix('[') {
        let ip: std::net::Ipv6Addr = rest.split(']').next()?.parse().ok()?;
        return Some(format!("[{ip}]"));
    }
    let name = match h.rsplit_once(':') {
        Some((n, port)) if port.bytes().all(|b| b.is_ascii_digit()) => n,
        Some(_) => return None,
        None => h,
    };
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let ok = !name.is_empty()
        && name.len() <= 253
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && !name.starts_with('.')
        && !name.contains("..");
    ok.then_some(name)
}

/// 請求的 Host 標頭裡的埠號（`dns.example.net:8443`、`[2001:db8::1]:8443`）；沒寫埠號回 None
pub fn request_port(h: &str) -> Option<u16> {
    let h = h.trim();
    let rest = match h.strip_prefix('[') {
        Some(r) => r.split_once(']')?.1,
        None => h,
    };
    let (_, p) = rest.rsplit_once(':')?;
    p.parse::<u16>().ok().filter(|p| *p > 0)
}

/// `https://網域[:埠號]`（443 不寫埠號；IPv6 位址加中括號）
pub fn https_origin(host: &str, port: u16) -> String {
    let h = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == 443 {
        format!("https://{h}")
    } else {
        format!("https://{h}:{port}")
    }
}

fn html_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

/// XML 跳脫（同 2.x：只換 & < >）
pub fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// 由字串產生固定的 UUID（SHA-1，同 2.x `uuidFrom`：同一個網域每次下載的描述檔 UUID 都一樣，重裝會覆蓋而不是多一份）
pub fn uuid_from(s: &str) -> String {
    let d = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, s.as_bytes());
    let h: String = d.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    format!("{}-{}-5{}-a{}-{}", &h[0..8], &h[8..12], &h[13..16], &h[17..20], &h[20..32]).to_uppercase()
}

/// Apple 描述檔（`kind`：`doh` / `dot`）。`doh_port`：DoH 的埠號（不是 443 時寫進 ServerURL）；
/// DoT 的描述檔沒有埠號欄位（Apple 固定用 853）
pub fn mobileconfig(kind: &str, host: &str, doh_path: &str, doh_port: u16) -> String {
    let h = host;
    let id: Vec<&str> = h.split('.').rev().collect();
    let id = id.join(".");
    let (settings, label) = if kind == "doh" {
        (
            format!(
                "<key>DNSProtocol</key><string>HTTPS</string>\n\t\t\t\t<key>ServerURL</key><string>{}{}</string>",
                xml_escape(&https_origin(h, doh_port)),
                xml_escape(doh_path)
            ),
            "DNS over HTTPS",
        )
    } else {
        (
            format!(
                "<key>DNSProtocol</key><string>TLS</string>\n\t\t\t\t<key>ServerName</key><string>{}</string>",
                xml_escape(h)
            ),
            "DNS over TLS",
        )
    };
    let xh = xml_escape(h);
    let xid = xml_escape(&id);
    let inner_uuid = uuid_from(&format!("{h}{kind}inner"));
    let outer_uuid = uuid_from(&format!("{h}{kind}"));
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>DNSSettings</key>
			<dict>
				{settings}
			</dict>
			<key>PayloadDescription</key><string>使用黑潮 DNS（{xh}）加密 DNS（{label}）：過濾廣告與惡意網站、CDN 走台灣節點。</string>
			<key>PayloadDisplayName</key><string>黑潮 DNS（{label}）</string>
			<key>PayloadIdentifier</key><string>{xid}.{kind}.dnssettings</string>
			<key>PayloadType</key><string>com.apple.dnsSettings.managed</string>
			<key>PayloadUUID</key><string>{inner_uuid}</string>
			<key>PayloadVersion</key><integer>1</integer>
			<key>ProhibitDisablement</key><false/>
		</dict>
	</array>
	<key>PayloadDescription</key><string>安裝後，這台裝置的 DNS 會透過加密連線使用黑潮 DNS（{xh}）。可隨時在「設定 › 一般 › VPN 與裝置管理」移除。</string>
	<key>PayloadDisplayName</key><string>黑潮 DNS（{xh}）</string>
	<key>PayloadIdentifier</key><string>{xid}.{kind}</string>
	<key>PayloadRemovalDisallowed</key><false/>
	<key>PayloadType</key><string>Configuration</string>
	<key>PayloadUUID</key><string>{outer_uuid}</string>
	<key>PayloadVersion</key><integer>1</integer>
</dict>
</plist>
"#
    )
}

/// 詳細頁的路徑（簡單好記即可，例如 /detail），不能跟其他路徑撞到（撞到就用預設值，同 2.x `_detailPath`）
pub fn detail_path(configured: &str, doh_path: &str) -> String {
    let mut p = configured.trim().to_string();
    if !p.starts_with('/') {
        p.insert(0, '/');
    }
    let p = p.trim_end_matches('/').to_string();
    let reserved = [
        "",
        "/api",
        "/apple",
        "/assets",
        "/dns-query",
        "/robots.txt",
        "/index.html",
        "/favicon.ico",
        "/favicon.svg",
    ];
    if reserved.contains(&p.as_str()) || p == doh_path || p.starts_with("/api/") || p.starts_with("/apple/") || p.starts_with("/assets/") {
        return DEFAULT_DETAIL_PATH.to_string();
    }
    p
}

fn r4(x: f64) -> f64 {
    (x * 10000.0).round() / 10000.0
}

fn r1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 網頁檔快取（依修改時間重新讀取）
struct FileCache {
    modified: Option<SystemTime>,
    text: Arc<str>,
}

pub struct Site {
    state: Arc<AppState>,
    presence: Option<Arc<Presence>>,
    /// `site.hostname`（小寫；可能是空白）
    hostname: String,
    min_clients: u64,
    /// 版本、授權、原始碼網址（about.rs）
    about: Value,
    html_file: PathBuf,
    detail_file: PathBuf,
    detail_path: String,
    doh_path: String,
    /// 設定算出來的對外 DoH 埠號（請求的 Host 標頭沒帶網域時用，見 [`Site::port_for`]）
    doh_port: u16,
    dot_port: u16,
    /// 共用儀表板（`share/dashboard/`：dashboard.js、dashboard.css），公開頁與詳細頁從 `/assets/` 載入
    dash_dir: PathBuf,
    files: Mutex<HashMap<PathBuf, FileCache>>,
    /// 網域自己的 IP（每小時更新）
    ips: RwLock<(Vec<IpAddr>, Vec<IpAddr>)>,
    cache: Mutex<HashMap<&'static str, (Instant, Value)>>,
    /// 詳細頁唯讀 API 的次數限制：路徑 →（這一分鐘的開始, 次數）
    limits: Mutex<HashMap<&'static str, (Instant, u32)>>,
    trace_slots: tokio::sync::Semaphore,
}

/// 設定的檔案路徑：空白用 `share/site/<預設檔名>`；相對路徑以設定目錄為準，找不到再退回內建的檔案
fn page_file(cfg: &Value, key: &str, default_name: &str) -> PathBuf {
    let builtin = crate::app::share_dir(cfg).join("site").join(default_name);
    let Some(p) = get(cfg, key).and_then(Value::as_str).map(str::trim).filter(|p| !p.is_empty()) else {
        return builtin;
    };
    let pp = Path::new(p);
    let path = if pp.is_absolute() {
        pp.to_path_buf()
    } else {
        let base = crate::app::persist_dir(cfg)
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        base.join(pp.strip_prefix("./").unwrap_or(pp))
    };
    if path.is_file() {
        path
    } else {
        warn!("網頁檔 {} 不存在（{key}），改用內建的 {}", path.display(), builtin.display());
        builtin
    }
}

impl Site {
    /// 由設定建立；`site.enabled` 為 false 時回 None。不會啟動背景工作（另外呼叫 [`Site::spawn`]）
    pub fn new(cfg: &Value, state: Arc<AppState>, presence: Option<Arc<Presence>>) -> Option<Arc<Site>> {
        if !get(cfg, "site.enabled").and_then(Value::as_bool).unwrap_or(false) {
            return None;
        }
        let hostname = get(cfg, "site.hostname")
            .and_then(Value::as_str)
            .map(|h| h.trim().trim_end_matches('.').to_ascii_lowercase())
            .unwrap_or_default();
        let doh_path = get(cfg, "listen.doh.path")
            .and_then(Value::as_str)
            .filter(|p| p.starts_with('/'))
            .unwrap_or("/dns-query")
            .to_string();
        let dp = detail_path(
            get(cfg, "site.detailPath").and_then(Value::as_str).unwrap_or(DEFAULT_DETAIL_PATH),
            &doh_path,
        );
        if hostname.is_empty() {
            info!("公開網頁：沒有設定 site.hostname，網頁改用瀏覽器連進來的網域；詳細數據頁在 {dp}/");
        } else {
            info!("詳細數據頁（擁有連結才能看）：https://{hostname}{dp}/");
        }
        Some(Arc::new(Site {
            presence,
            about: crate::about::json(cfg),
            min_clients: get(cfg, "site.minClients").and_then(Value::as_u64).unwrap_or(1).max(1),
            html_file: page_file(cfg, "site.htmlFile", "index.html"),
            detail_file: page_file(cfg, "site.detailFile", "detail.html"),
            detail_path: dp,
            doh_path,
            doh_port: crate::app::public_doh_port(cfg, crate::app::doh_uses_tls(cfg, &crate::app::config_dir(cfg))),
            dot_port: get(cfg, "listen.dot.port").and_then(Value::as_u64).unwrap_or(853) as u16,
            dash_dir: crate::app::share_dir(cfg).join("dashboard"),
            hostname,
            state,
            files: Mutex::new(HashMap::new()),
            ips: RwLock::new((Vec::new(), Vec::new())),
            cache: Mutex::new(HashMap::new()),
            limits: Mutex::new(HashMap::new()),
            trace_slots: tokio::sync::Semaphore::new(TRACE_CONCURRENCY),
        }))
    }

    /// 背景工作：每小時用系統的解析器查一次網域自己的 IP（給 Windows 教學的「慣用 DNS」）
    pub fn spawn(self: &Arc<Self>) {
        if self.hostname.is_empty() {
            return;
        }
        let me: Weak<Site> = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                match me.upgrade() {
                    Some(s) => s.refresh_ips().await,
                    None => return,
                }
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        });
    }

    /// 查網域自己的 IP（查不到就保留上一次的結果）
    pub async fn refresh_ips(&self) {
        if self.hostname.is_empty() {
            return;
        }
        match tokio::net::lookup_host((self.hostname.as_str(), 443)).await {
            Ok(addrs) => {
                let (mut v4, mut v6): (Vec<IpAddr>, Vec<IpAddr>) = addrs.map(|a| a.ip()).partition(IpAddr::is_ipv4);
                for v in [&mut v4, &mut v6] {
                    v.sort();
                    v.dedup();
                }
                let mut g = self.ips.write().unwrap();
                if !v4.is_empty() {
                    g.0 = v4;
                }
                if !v6.is_empty() {
                    g.1 = v6;
                }
            }
            Err(e) => debug!("查 {} 的 IP 失敗：{e}", self.hostname),
        }
    }

    /// 手動指定網域的 IP（測試用）
    pub fn set_ips(&self, v4: Vec<IpAddr>, v6: Vec<IpAddr>) {
        *self.ips.write().unwrap() = (v4, v6);
    }

    pub fn presence(&self) -> Option<&Arc<Presence>> {
        self.presence.as_ref()
    }

    pub fn detail_path(&self) -> &str {
        &self.detail_path
    }

    /// 這個請求要顯示的網域：設定 → Host 標頭 → 佔位網域
    pub fn host_for(&self, req_host: Option<&str>) -> String {
        if !self.hostname.is_empty() {
            return self.hostname.clone();
        }
        req_host.and_then(request_host).unwrap_or_else(|| PLACEHOLDER_HOST.to_string())
    }

    /// 這個請求要顯示的 DoH 埠號。公開頁跟 DoH 共用同一個監聽，所以瀏覽器連進來的埠號就是 DoH 的埠號：
    /// Host 標頭的網域跟要顯示的網域一樣時，帶了埠號就用它、沒帶就是 443（https 的預設埠）。
    /// 沒有 Host、或 Host 是別的名稱（例如反向代理改寫成 `127.0.0.1:8053`）時用設定算出來的對外埠號
    pub fn port_for(&self, req_host: Option<&str>) -> u16 {
        let shown = self.host_for(req_host);
        match req_host {
            Some(h) if request_host(h).as_deref() == Some(shown.as_str()) => request_port(h).unwrap_or(443),
            _ => self.doh_port,
        }
    }

    /// DoH 網址（`https://網域[:埠號]/dns-query`）
    fn doh_url(&self, host: &str, port: u16) -> String {
        format!("{}{}", https_origin(host, port), self.doh_path)
    }

    /// 處理一個 HTTP 請求；不是網頁的請求（DoH 查詢、POST…）回 None，交給 DoH 處理
    pub async fn handle(&self, method: &str, path: &str, query: &str, client: IpAddr, host: Option<&str>) -> Option<SiteResponse> {
        let head = method.eq_ignore_ascii_case("HEAD");
        if !head && !method.eq_ignore_ascii_case("GET") {
            return None;
        }
        let q = parse_query(query);
        if q.contains_key("dns") {
            return None; // RFC 8484 GET 查詢
        }
        let mut r = self.route(path, &q, client, host).await?;
        if head {
            let len = r.body.len();
            r.body = Bytes::new();
            if !r.headers.iter().any(|(k, _)| *k == "content-length") {
                r.headers.push(("content-length", len.to_string()));
            }
        }
        Some(r)
    }

    async fn route(&self, p: &str, q: &HashMap<String, String>, client: IpAddr, req_host: Option<&str>) -> Option<SiteResponse> {
        // 隱藏詳細頁與它的唯讀 API
        let dp = self.detail_path.as_str();
        if let Some(sub) = p.strip_prefix(dp).filter(|s| s.is_empty() || s.starts_with('/')) {
            return Some(self.detail(sub, q, req_host).await);
        }
        if p == self.doh_path || p == "/dns-query" {
            return None; // 交給 DoH（說明文字或查詢）
        }
        let host = self.host_for(req_host);
        let port = self.port_for(req_host);
        // 不認識的期間由 public_stats 當成 today
        let range = || q.get("range").map(String::as_str).unwrap_or("today");
        Some(match p {
            "/robots.txt" => send(200, "text/plain; charset=utf-8", "User-agent: *\nDisallow: /\n", &[]),
            "/" | "/index.html" => match self.page(&self.html_file, &host, port) {
                Some(html) => send(200, "text/html; charset=utf-8", html, &[("cache-control", "no-cache".into())]),
                None => send(500, "text/plain; charset=utf-8", "error", &[]),
            },
            "/api/public/stats" => json_resp(200, &self.public_stats(range()), "no-cache"),
            "/api/public/presence" => {
                // 用訪客 IP 比對最近的 DNS 查詢（不回傳 IP）
                let st = match &self.presence {
                    Some(pr) => pr.status(client),
                    None => json!({ "state": "unknown" }),
                };
                json_resp(200, &st, "no-store")
            }
            "/api/public/info" => json_resp(200, &self.info(&host, port), "no-cache"),
            "/apple/doh.mobileconfig" | "/apple/dot.mobileconfig" => {
                let kind = if p.contains("doh") { "doh" } else { "dot" };
                send(
                    200,
                    "application/x-apple-aspen-config",
                    mobileconfig(kind, &host, &self.doh_path, port),
                    &[
                        (
                            "content-disposition",
                            format!(
                                "attachment; filename=\"{}\"",
                                crate::admin::safe_filename(&format!(
                                    "{}-{kind}.mobileconfig",
                                    host.trim_matches(['[', ']']).replace(':', "-")
                                ))
                            ),
                        ),
                        ("cache-control", "no-cache".to_string()),
                    ],
                )
            }
            // QR 碼只給固定的三種內容（不當成任意文字的產生器）
            "/qr.svg" => {
                let text = match q.get("for").map(String::as_str) {
                    Some("doh") => self.doh_url(&host, port),
                    Some("source") => self.about["source"].as_str().unwrap_or(crate::about::DEFAULT_SOURCE).to_string(),
                    _ => format!("{}/", https_origin(&host, port)),
                };
                match crate::about::qr_svg(&text) {
                    // 沒設定網域時內容跟著 Host 標頭變：只讓瀏覽器自己快取，中間的代理不要存
                    Some(svg) => send(200, "image/svg+xml", svg, &[("cache-control", "private, max-age=3600".into())]),
                    None => send(500, "text/plain; charset=utf-8", "error", &[]),
                }
            }
            "/favicon.ico" | "/favicon.svg" => send(200, "image/svg+xml", FAVICON, &[("cache-control", "max-age=86400".into())]),
            // 共用儀表板（公開頁與詳細頁的圖表、表格）：瀏覽器自己畫，伺服器只給 JSON
            "/assets/dashboard.js" | "/assets/dashboard.css" => self.asset(p),
            _ => send(404, "text/plain; charset=utf-8", "Not found", &[]),
        })
    }

    async fn detail(&self, sub: &str, q: &HashMap<String, String>, req_host: Option<&str>) -> SiteResponse {
        let no_store = || ("cache-control", "no-store".to_string());
        match sub {
            "" => SiteResponse {
                status: 301,
                headers: vec![
                    ("location", format!("{}/", self.detail_path)),
                    ("x-robots-tag", NOINDEX.to_string()),
                ],
                body: Bytes::new(),
            },
            "/" | "/index.html" => match self.page(&self.detail_file, &self.host_for(req_host), self.port_for(req_host)) {
                Some(html) => send(200, "text/html; charset=utf-8", html, &[no_store()]),
                None => send(500, "text/plain; charset=utf-8", "error", &[]),
            },
            "/api/public" => json_resp(
                200,
                &self.public_stats(q.get("range").map(String::as_str).unwrap_or("today")),
                "no-store",
            ),
            _ => self.read_only_api(sub, q).await,
        }
    }

    /// 這一分鐘還能不能再做一次（固定時間窗，全部訪客合計）
    fn allow(&self, key: &'static str, per_minute: u32) -> bool {
        let now = Instant::now();
        let mut m = self.limits.lock().unwrap();
        let e = m.entry(key).or_insert((now, 0));
        if now.duration_since(e.0) >= Duration::from_secs(60) {
            *e = (now, 0);
        }
        e.1 += 1;
        e.1 <= per_minute
    }

    /// 詳細頁的唯讀管理 API：只開放 [`READ_ONLY`]。這一頁在公開的 DoH 埠上、只靠路徑保護，所以回應要再整理：
    /// 用戶端 IP 打馬賽克、不帶本機的資料夾路徑、追蹤不回報內部位址通不通，花力氣的 API 有次數上限
    pub async fn read_only_api(&self, sub: &str, q: &HashMap<String, String>) -> SiteResponse {
        if !READ_ONLY.contains(&sub) {
            return json_resp(404, &json!({ "error": "not found" }), "no-store");
        }
        let busy = || json_resp(429, &json!({ "error": "查詢太頻繁，請稍後再試" }), "no-store");
        let _slot = match sub {
            "/api/trace" => {
                // 追蹤會去問每一台上游、再測每個 IP：限制次數與同時數，不讓外面的人拿來放大流量
                let Ok(slot) = self.trace_slots.try_acquire() else { return busy() };
                if !self.allow("/api/trace", TRACE_PER_MINUTE) {
                    return busy();
                }
                Some(slot)
            }
            "/api/cdn/domains" => {
                if !self.allow("/api/cdn/domains", DOMAINS_PER_MINUTE) {
                    return busy();
                }
                None
            }
            _ => None,
        };
        let r = crate::admin::route(&self.state, sub, q).await;
        if let Some((ctype, name, text)) = r.raw {
            return send(
                r.code,
                ctype,
                text,
                &[
                    (
                        "content-disposition",
                        format!("attachment; filename=\"{}\"", crate::admin::safe_filename(&name)),
                    ),
                    ("cache-control", "no-store".to_string()),
                ],
            );
        }
        let mut body = r.body;
        match sub {
            "/api/status" => {
                mask_clients(&mut body);
                strip_paths(&mut body);
            }
            "/api/benchmark" => strip_paths(&mut body),
            "/api/trace" => hide_internal_probes(&mut body),
            _ => {}
        }
        // 其他 API（工作狀態、錯誤訊息…）的文字裡也可能帶本機路徑：一律換掉
        let loc = &self.state.backup;
        let mut dirs: Vec<String> = [
            Some(loc.state.as_path()),
            Some(loc.data.as_path()),
            Some(loc.key_dir.as_path()),
            loc.upstreams.parent(),
        ]
        .into_iter()
        .flatten()
        .map(|d| d.to_string_lossy().into_owned())
        .collect();
        scrub_dirs(&mut body, &mut dirs);
        redact_upstream_urls(&mut body);
        json_resp(r.code, &body, "no-store")
    }

    /// 共用儀表板的檔案（`/assets/dashboard.js`、`/assets/dashboard.css`）
    fn asset(&self, p: &str) -> SiteResponse {
        let (name, ctype) = match p {
            "/assets/dashboard.js" => ("dashboard.js", "text/javascript; charset=utf-8"),
            _ => ("dashboard.css", "text/css; charset=utf-8"),
        };
        match std::fs::read(self.dash_dir.join(name)) {
            Ok(b) => send(200, ctype, b, &[("cache-control", "no-cache".into())]),
            Err(e) => {
                warn!("讀取 {} 失敗：{e}", self.dash_dir.join(name).display());
                send(404, "text/plain; charset=utf-8", "Not found", &[])
            }
        }
    }

    /// 讀網頁檔並代入網域（檔案有改就重新讀）。佔位字：`{{HOST}}` 網域、`{{DOH_PATH}}` DoH 路徑、
    /// `{{DOH_URL}}` 完整的 DoH 網址（埠號不是 443 時帶埠號）、`{{SITE_URL}}` 這一頁的網址、`{{DOH_PORT}}` DoH 埠號、
    /// `{{DOH_HOSTPORT}}` 網域加埠號（443 時只有網域）
    fn page(&self, file: &Path, host: &str, port: u16) -> Option<String> {
        let modified = std::fs::metadata(file).and_then(|m| m.modified()).ok();
        let text = {
            let mut files = self.files.lock().unwrap();
            match files.get(file) {
                Some(c) if c.modified == modified && modified.is_some() => c.text.clone(),
                _ => match std::fs::read_to_string(file) {
                    Ok(t) => {
                        let t: Arc<str> = t.into();
                        files.insert(file.to_path_buf(), FileCache { modified, text: t.clone() });
                        t
                    }
                    Err(e) => {
                        warn!("讀取網頁檔 {} 失敗：{e}", file.display());
                        return None;
                    }
                },
            }
        };
        Some(
            text.replace("{{DOH_URL}}", &html_escape(&self.doh_url(host, port)))
                .replace("{{SITE_URL}}", &html_escape(&format!("{}/", https_origin(host, port))))
                .replace("{{DOH_PORT}}", &port.to_string())
                .replace(
                    "{{DOH_HOSTPORT}}",
                    &html_escape(https_origin(host, port).trim_start_matches("https://")),
                )
                .replace("{{HOST}}", &html_escape(host))
                .replace("{{DOH_PATH}}", &html_escape(&self.doh_path)),
        )
    }

    /// `/api/public/info`：連線資訊（`port`：這個請求看到的 DoH 埠號，見 [`Site::port_for`]）
    pub fn info(&self, host: &str, port: u16) -> Value {
        let (v4, v6) = self.ips.read().unwrap().clone();
        let e = &self.state.encrypted;
        json!({
            "host": host, "doh": self.doh_url(host, port), "dohPort": port, "site": format!("{}/", https_origin(host, port)),
            "dot": host, "dotPort": self.dot_port,
            "ipv4": v4, "ipv6": v6,
            "presence": self.presence.as_ref().map(|p| p.info()),
            "protocols": { "doh": e.doh.is_some(), "doh3": e.doh3.is_some(), "dot": e.dot.is_some(), "doq": e.doq.is_some() },
            "about": self.about,
        })
    }

    /// `/api/public/stats`：匿名統計（`range`：today / 7d / 30d；10 秒快取）
    pub fn public_stats(&self, range: &str) -> Value {
        let range: &'static str = match range {
            "7d" => "7d",
            "30d" => "30d",
            _ => "today",
        };
        if let Some((at, v)) = self.cache.lock().unwrap().get(range) {
            if at.elapsed() < STATS_CACHE {
                return v.clone();
            }
        }
        let v = self.build_public_stats(range);
        self.cache.lock().unwrap().insert(range, (Instant::now(), v.clone()));
        v
    }

    fn build_public_stats(&self, range: &str) -> Value {
        dashboard_stats(&self.state, range, self.min_clients, PUBLIC_TOP)
    }
}

/// 公開頁的排行筆數：（熱門網站, 被擋網站）
pub const PUBLIC_TOP: (usize, usize) = (15, 10);
/// 管理介面儀表板的排行筆數（不受 `site.minClients` 限制）
pub const ADMIN_TOP: (usize, usize) = (30, 30);

/// 儀表板的統計（公開頁 `/api/public/stats` 與管理 API `/api/dashboard` 共用）。
/// `range`：today / 7d / 30d（其他當成 today）；`min_clients`：網站排行最少要有幾位不同使用者；
/// `top`：（熱門網站, 被擋網站）各列幾筆。內容只有彙總數字與網站名稱，不含任何 IP
pub fn dashboard_stats(state: &AppState, range: &str, min_clients: u64, top: (usize, usize)) -> Value {
    let range = match range {
        "7d" => "7d",
        "30d" => "30d",
        _ => "today",
    };
    let days = match range {
        "30d" => 30,
        "7d" => 7,
        _ => 1,
    };
    let r = &state.resolver;
    let stats = &r.stats;
    let daily = stats.daily();
    let keys = &daily[daily.len().saturating_sub(days)..];
    let n = |d: &Value, k: &str| d.get(k).and_then(Value::as_u64).unwrap_or(0);
    let f = |d: &Value, k: &str| d.get(k).and_then(Value::as_f64).unwrap_or(0.0);
    const SUM: [&str; 12] = [
        "query",
        "hit",
        "miss",
        "blocked",
        "blockedAds",
        "blockedMalware",
        "blockedTelemetry",
        "blockedCustom",
        "cdnServed",
        "cdnRewrite",
        "ecsRewrite",
        "crossRewrite",
    ];
    let mut sum: HashMap<&str, u64> = SUM.iter().map(|k| (*k, 0)).collect();
    let mut cdn_agg: BTreeMap<String, u64> = BTreeMap::new();
    // 機會成本：一般 DNS 會把多少 CDN 連線送出國、我們拉回台灣多少
    let mut route_agg: BTreeMap<String, [f64; 6]> = BTreeMap::new();
    let mut cross_pairs: BTreeMap<String, u64> = BTreeMap::new();
    for (_, d) in keys {
        for k in SUM {
            *sum.get_mut(k).expect("SUM") += n(d, k);
        }
        for (p, c) in d.get("cdn").and_then(Value::as_object).into_iter().flatten() {
            *cdn_agg.entry(p.clone()).or_default() += c.as_u64().unwrap_or(0);
        }
        for (p, rt) in d.get("route").and_then(Value::as_object).into_iter().flatten() {
            let a = route_agg.entry(p.clone()).or_default();
            for (i, k) in ["n", "abroad", "acc", "miss", "saved", "savedN"].iter().enumerate() {
                a[i] += f(rt, k);
            }
        }
        for (pair, c) in d.get("cross").and_then(Value::as_object).into_iter().flatten() {
            *cross_pairs.entry(pair.clone()).or_default() += c.as_u64().unwrap_or(0);
        }
    }
    let s = |k: &str| sum[k];
    let label = |p: &str| kuroshio_cdn::providers::label(p).to_string();
    let trend: Vec<Value> = daily[daily.len().saturating_sub(30)..]
        .iter()
        .map(|(date, d)| json!({ "date": date, "queries": n(d, "query"), "blocked": n(d, "blocked") }))
        .collect();
    let cdn_total: u64 = cdn_agg.values().sum();
    let mut cdn_list: Vec<(String, u64)> = cdn_agg.into_iter().collect();
    cdn_list.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let cdn: Vec<Value> = cdn_list
        .iter()
        .take(8)
        .map(|(p, c)| {
            json!({ "provider": p, "label": label(p), "count": c, "share": if cdn_total > 0 { r4(*c as f64 / cdn_total as f64) } else { 0.0 } })
        })
        .collect();

    // CDN 加速成效（只有統計數字，不列網域）；原本被導去哪個 POP → 改到哪個台灣 POP（依查詢次數加權）
    let (mut verified, mut was_abroad, mut v4nodes, mut v6nodes) = (0u64, 0u64, 0usize, 0usize);
    let mut saved: Vec<f64> = Vec::new();
    let mut from_pops: HashMap<String, (u64, u64)> = HashMap::new();
    let mut to_pops: BTreeMap<String, u64> = BTreeMap::new();
    let mut cs = json!({ "explored": 0, "ok": 0, "fail": 0, "byTo": {}, "byFrom": {}, "also": {} });
    if let Some(c) = r.cdn() {
        use kuroshio_cdn::providers::is_tw_pop;
        let st = c.state();
        for e in st.db.domains.values() {
            let ok4 = e.v4.as_ref().is_some_and(|v| v.verdict.as_deref() == Some("ok"));
            let ok_ecs = e.ecs.as_ref().is_some_and(|v| v.verdict.as_deref() == Some("ok"));
            if ok4 || ok_ecs {
                verified += 1;
            }
            let base_pop = e.base.as_ref().and_then(|b| b.pop.as_deref()).filter(|p| !p.is_empty());
            let abroad = base_pop.is_some_and(|p| !is_tw_pop(p));
            if abroad {
                was_abroad += 1;
            }
            if ok4 && abroad {
                let bms = e.base.as_ref().and_then(|b| b.ms.get()).filter(|m| *m != 0.0);
                let vms = e.v4.as_ref().and_then(|v| v.ms.get()).filter(|m| *m != 0.0);
                if let (Some(b), Some(v)) = (bms, vms) {
                    if b > v {
                        saved.push(b - v);
                    }
                }
            }
            if ok_ecs {
                if let Some(g) = e.ecs.as_ref().and_then(|x| x.gain_ms.get()).filter(|g| *g > 0.0) {
                    saved.push(g);
                }
            }
            if let (true, Some(pop)) = (abroad, base_pop) {
                let w = (e.hits as u64).max(1);
                let fp = from_pops.entry(pop.to_string()).or_default();
                fp.0 += w;
                let tw_pop = e.v4.as_ref().and_then(|v| v.pop.as_deref()).filter(|p| is_tw_pop(p));
                if let (true, Some(tp)) = (ok4, tw_pop) {
                    fp.1 += w;
                    *to_pops.entry(tp.chars().take(3).collect()).or_default() += w;
                }
            }
        }
        for d in st.pools.p.values() {
            v4nodes += d.pool4.iter().filter(|x| !d.bad.contains_key(&x.ip)).count();
            v6nodes += d.pool6.iter().filter(|x| !d.bad.contains_key(&x.ip)).count();
        }
        cs = st.db.cross_summary();
    }
    saved.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median = saved.get(saved.len() / 2).copied();

    let mut routing_rows: Vec<(String, [f64; 6])> = route_agg.into_iter().filter(|(_, a)| a[0] > 0.0).collect();
    routing_rows.sort_by(|a, b| {
        b.1[0]
            .partial_cmp(&a.1[0])
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    let mut rt = [0f64; 6];
    for (_, a) in &routing_rows {
        for i in 0..6 {
            rt[i] += a[i];
        }
    }
    let routing: Vec<Value> = routing_rows
        .iter()
        .map(|(p, a)| {
            json!({
                "provider": p, "label": label(p),
                "connections": a[0], "wouldGoAbroad": a[1], "accelerated": a[2], "stillAbroad": a[3],
                "abroadShare": if a[0] > 0.0 { r4(a[1] / a[0]) } else { 0.0 },
                "successRate": if a[1] > 0.0 { json!(r4(a[2] / a[1])) } else { Value::Null },
                "avgSavedMs": if a[5] > 0.0 { json!(r1(a[4] / a[5])) } else { Value::Null },
            })
        })
        .collect();

    // 跨 CDN 備援：原本的 CDN 沒有台灣節點時，同一個網站能不能改走別家的台灣節點
    let cross_serves = s("crossRewrite");
    let obj = |k: &str| cs.get(k).and_then(Value::as_object).cloned().unwrap_or_default();
    let mut by_to: Vec<(String, u64)> = obj("byTo").into_iter().map(|(k, v)| (k, v.as_u64().unwrap_or(0))).collect();
    by_to.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let mut by_from: Vec<(String, u64, u64)> = obj("byFrom")
        .into_iter()
        .map(|(k, v)| (k, n(&v, "explored"), n(&v, "ok")))
        .filter(|x| x.1 > 0)
        .collect();
    by_from.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let mut pairs: Vec<(String, u64)> = cross_pairs.into_iter().collect();
    pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let explored = n(&cs, "explored");
    let cross_cdn = json!({
        "explored": explored, "ok": n(&cs, "ok"), "fail": n(&cs, "fail"),
        "successRate": if explored > 0 { json!(r4(n(&cs, "ok") as f64 / explored as f64)) } else { Value::Null },
        "byTo": by_to.iter().map(|(p, c)| json!({ "provider": p, "label": label(p), "sites": c })).collect::<Vec<_>>(),
        "byFrom": by_from.iter().map(|(p, e, o)| json!({ "provider": p, "label": label(p), "explored": e, "ok": o })).collect::<Vec<_>>(),
        "serves": cross_serves,
        "pairs": pairs.iter().take(8).map(|(k, c)| {
            let (f, t) = k.split_once('>').unwrap_or((k.as_str(), ""));
            json!({ "from": f, "fromLabel": label(f), "to": t, "toLabel": label(t), "count": c })
        }).collect::<Vec<_>>(),
    });

    // 跨 CDN 的連線也是「原本出國、改走台灣」：算進加速次數
    let opportunity = json!({
        "connections": rt[0], "wouldGoAbroad": rt[1], "accelerated": rt[2] + cross_serves as f64, "stillAbroad": rt[3],
        "otherDnsAbroadShare": if rt[0] > 0.0 { r4(rt[1] / rt[0]) } else { 0.0 },
        "oursAbroadShare": if rt[0] > 0.0 { r4(rt[3] / rt[0]) } else { 0.0 },
        "avgSavedMs": if rt[5] > 0.0 { json!(r1(rt[4] / rt[5])) } else { Value::Null },
        "totalSavedSec": r1(rt[4] / 1000.0),
        "crossAccelerated": cross_serves,
    });

    let mut flows: Vec<(String, (u64, u64))> = from_pops.into_iter().collect();
    flows.sort_by(|a, b| b.1 .0.cmp(&a.1 .0).then_with(|| a.0.cmp(&b.0)));
    let flows: Vec<Value> = flows
        .into_iter()
        .take(12)
        .map(|(pop, (c, fx))| json!({ "pop": pop, "count": c, "fixed": fx }))
        .collect();

    let filter = r.filter.read().unwrap().as_ref().map(|f| f.stats());
    let rules = filter.filter(|v| !v.is_null()).map(|v| {
        json!({ "custom": v.get("custom").cloned().unwrap_or(json!(0)), "lists": v.get("lists").cloned().unwrap_or(json!(0)), "byCategory": v.get("byCategory").cloned().unwrap_or(json!({})) })
    });
    let auto = r.upstreams.auto_info();
    let q = s("query");
    let blocked = s("blocked");
    let min_c = min_clients.max(1);
    json!({
        "generatedAt": crate::stats::iso_utc(now_ms()),
        "range": range, "days": keys.len(),
        "totals": {
            "queries": q, "blocked": blocked, "blockedAds": s("blockedAds"), "blockedMalware": s("blockedMalware"),
            "blockedTelemetry": s("blockedTelemetry"), "blockedCustom": s("blockedCustom"),
            "blockRate": if q > 0 { r4(blocked as f64 / q as f64) } else { 0.0 },
            "cacheHitRate": if q > 0 { r4(s("hit") as f64 / q as f64) } else { 0.0 },
            "cdnServed": s("cdnServed"), "cdnAccelerated": s("cdnRewrite") + s("ecsRewrite") + cross_serves,
            "accelerated": rt[2] + cross_serves as f64,
        },
        "acceleration": {
            "verifiedSites": verified, "sitesRoutedAbroad": was_abroad, "medianSavedMs": median.map(r1), "samples": saved.len(),
            "twNodesV4": v4nodes, "twNodesV6": v6nodes,
        },
        "trend": trend, "cdn": cdn, "routing": routing, "opportunity": opportunity, "flows": flows,
        "toPops": Value::Object(to_pops.into_iter().map(|(k, v)| (k, json!(v))).collect::<Map<_, _>>()),
        "crossCdn": cross_cdn,
        "realtime": stats.realtime(),
        "outcomes": {
            "cache": s("hit"), "upstream": q.saturating_sub(s("hit") + blocked),
            "ads": s("blockedAds") + s("blockedCustom") + s("blockedTelemetry"), "malware": s("blockedMalware"),
        },
        "topSites": stats.anon_ranking(days, false, min_c, top.0),
        "topBlocked": stats.anon_ranking(days, true, min_c, top.1),
        "privacy": { "minClients": min_c },
        "system": {
            "uptimeSec": stats.uptime_sec(),
            "rules": rules,
            "upstreams": r.upstreams.pinned.len() as u64 + auto.get("count").and_then(Value::as_u64).unwrap_or(0),
            "benchmarkAt": auto.get("generatedAt").cloned().unwrap_or(Value::Null),
        },
    })
}

/// 區網、本機、連結本地之類不是公開網路的位址
fn internal_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v) => {
            let o = v.octets();
            v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_unspecified()
                || v.is_broadcast()
                || v.is_multicast()
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            v.is_loopback() || v.is_unspecified() || v.is_multicast() || (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80
        }
    }
}

/// 追蹤結果裡「這個 IP 通不通、多少毫秒」：內部位址的不回報。
/// 外面的人可以追蹤一個自己控制、指向 192.168.x.x 的網域，不能讓他藉此知道區網裡哪些主機開著
pub fn hide_internal_probes(body: &mut Value) {
    if let Some(list) = body.get_mut("ranking").and_then(Value::as_array_mut) {
        list.retain(|x| {
            x.get("ip")
                .and_then(Value::as_str)
                .and_then(|s| s.parse::<IpAddr>().ok())
                .is_some_and(|ip| !internal_ip(ip))
        });
    }
}

/// 拿掉本機的資料夾路徑（`/api/status` 的 `system.persist.dir`、評測結果的 `reportDir`）
pub fn strip_paths(body: &mut Value) {
    if let Some(p) = body.pointer_mut("/system/persist").and_then(Value::as_object_mut) {
        p.remove("dir");
    }
    if let Some(o) = body.as_object_mut() {
        o.remove("reportDir");
    }
}

/// 所有字串裡出現的本機資料夾路徑換成 `…`（長的先換；太短的像 `/` 不處理）
pub fn scrub_dirs(body: &mut Value, dirs: &mut Vec<String>) {
    dirs.retain(|d| d.trim_end_matches(['/', '\\']).len() >= 4);
    dirs.sort_by_key(|d| std::cmp::Reverse(d.len()));
    dirs.dedup();
    fn walk(v: &mut Value, dirs: &[String]) {
        match v {
            Value::String(s) => {
                for d in dirs {
                    if s.contains(d.as_str()) {
                        *s = s.replace(d.as_str(), "…");
                    }
                }
            }
            Value::Array(a) => a.iter_mut().for_each(|x| walk(x, dirs)),
            Value::Object(o) => o.values_mut().for_each(|x| walk(x, dirs)),
            _ => {}
        }
    }
    if !dirs.is_empty() {
        walk(body, dirs);
    }
}

/// 上游網址的協議與預設埠（`kuroshio_net::upstream::Upstream::parse` 認得的，加上 http）
fn upstream_scheme(s: &str) -> Option<u16> {
    Some(match s.to_ascii_lowercase().as_str() {
        "udp" | "tcp" => 53,
        "tls" | "quic" => 853,
        "https" | "h3" | "sdns" => 443,
        "http" => 80,
        _ => return None,
    })
}

/// 文字裡的上游網址只留「協議://主機」（不是預設埠的話加上埠）：個人 DoH 網址的路徑常帶帳號代碼
/// （`https://dns.example/dns-query/abc123`），帳號密碼（`user:pass@`）也拿掉。DNSCrypt 的 `sdns://` 戳記整段藏起來
pub fn redact_urls(text: &str) -> std::borrow::Cow<'_, str> {
    if !text.contains("://") {
        return text.into();
    }
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    let mut i = 0;
    while let Some(k) = text[i..].find("://") {
        let at = i + k;
        // 往前找協議名稱（英數字與 + - .）
        let mut st = at;
        while st > last && (b[st - 1].is_ascii_alphanumeric() || matches!(b[st - 1], b'+' | b'-' | b'.')) {
            st -= 1;
        }
        let scheme = &text[st..at];
        let rest = &text[at + 3..];
        // 網址到空白、引號、括號或全形標點為止
        let end = rest
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '）' | '，' | '、' | '；' | '。'))
            .unwrap_or(rest.len());
        let Some(default_port) = upstream_scheme(scheme) else {
            i = at + 3;
            continue;
        };
        let url = &rest[..end];
        let auth = &url[..url.find(['/', '?', '#']).unwrap_or(url.len())];
        let auth = auth.rsplit_once('@').map(|x| x.1).unwrap_or(auth);
        let kept = if scheme.eq_ignore_ascii_case("sdns") {
            "…".to_string()
        } else {
            // 主機（IPv6 用中括號）與埠：預設埠拿掉
            let (host, port) = match auth.strip_prefix('[').and_then(|x| x.split_once(']')) {
                Some((h, p)) => (format!("[{h}]"), p.strip_prefix(':')),
                None => match auth.rsplit_once(':') {
                    Some((h, p)) if !h.contains(':') => (h.to_string(), Some(p)),
                    _ => (auth.to_string(), None),
                },
            };
            match port.filter(|p| !p.is_empty() && p.parse::<u16>().ok() != Some(default_port)) {
                Some(p) => format!("{host}:{p}"),
                None => host,
            }
        };
        out.push_str(&text[last..st]);
        out.push_str(scheme);
        out.push_str("://");
        out.push_str(&kept);
        last = at + 3 + end;
        i = last;
    }
    if last == 0 {
        return text.into();
    }
    out.push_str(&text[last..]);
    out.into()
}

/// 詳細頁（公開、唯讀）的回應：所有字串（含物件的鍵）裡的上游網址都換成 [`redact_urls`] 的樣子。
/// 管理 API 本身（要登入）照樣回完整網址
pub fn redact_upstream_urls(v: &mut Value) {
    match v {
        Value::String(s) => {
            if let std::borrow::Cow::Owned(n) = redact_urls(s) {
                *s = n;
            }
        }
        Value::Array(a) => a.iter_mut().for_each(redact_upstream_urls),
        Value::Object(o) => {
            if o.keys().any(|k| k.contains("://")) {
                let old = std::mem::take(o);
                for (k, mut x) in old {
                    redact_upstream_urls(&mut x);
                    let base = redact_urls(&k).into_owned();
                    // 同一台主機的兩個個人網址：鍵不能撞在一起
                    let mut key = base.clone();
                    let mut n = 2;
                    while o.contains_key(&key) {
                        key = format!("{base} #{n}");
                        n += 1;
                    }
                    o.insert(key, x);
                }
            } else {
                o.values_mut().for_each(redact_upstream_urls);
            }
        }
        _ => {}
    }
}

/// `/api/status` 的 `stats.topClients[].name` 打馬賽克
pub fn mask_clients(body: &mut Value) {
    if let Some(list) = body.pointer_mut("/stats/topClients").and_then(Value::as_array_mut) {
        for c in list {
            if let Some(name) = c.get("name").and_then(Value::as_str).map(mask_ip) {
                c["name"] = json!(name);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_ports() {
        assert_eq!(request_port("dns.example.net:8443"), Some(8443));
        assert_eq!(request_port("dns.example.net"), None);
        assert_eq!(request_port("[2001:db8::1]:8443"), Some(8443));
        assert_eq!(request_port("[2001:db8::1]"), None);
        assert_eq!(request_port("dns.example.net:0"), None);
        assert_eq!(request_port("dns.example.net:99999"), None);
        assert_eq!(https_origin("dns.example.net", 443), "https://dns.example.net");
        assert_eq!(https_origin("dns.example.net", 8443), "https://dns.example.net:8443");
        assert_eq!(https_origin("2001:db8::1", 8443), "https://[2001:db8::1]:8443");
        assert!(
            mobileconfig("doh", "dns.example.net", "/dns-query", 8443).contains("<string>https://dns.example.net:8443/dns-query</string>")
        );
        assert_eq!(detail_path("/assets", "/dns-query"), "/detail", "儀表板檔案的路徑保留給 /assets");
    }

    #[test]
    fn masking() {
        assert_eq!(mask_ip("192.168.1.23"), "192.168.x.x");
        assert_eq!(mask_ip("2001:db8:1::5"), "2001:db8:…");
        assert_eq!(mask_ip("nonsense"), "…");
        let mut v = json!({ "stats": { "topClients": [{ "name": "10.1.2.3", "count": 5 }] } });
        mask_clients(&mut v);
        assert_eq!(v["stats"]["topClients"][0], json!({ "name": "10.1.x.x", "count": 5 }));
    }

    #[test]
    fn detail_api_scrubbing() {
        let mut v = json!({ "system": { "tier": "small", "persist": { "dir": "/etc/kuroshio/state", "storage": "flash" } } });
        strip_paths(&mut v);
        assert_eq!(v, json!({ "system": { "tier": "small", "persist": { "storage": "flash" } } }));
        let mut b = json!({ "generatedAt": "x", "reportDir": "C:\\ProgramData\\kuroshio\\state\\reports" });
        strip_paths(&mut b);
        assert_eq!(b, json!({ "generatedAt": "x" }));
        let mut t = json!({ "ranking": [
            { "ip": "192.168.1.1", "ok": true, "ms": 0.4 }, { "ip": "10.0.0.5", "ok": false, "ms": null },
            { "ip": "127.0.0.1", "ok": true, "ms": 0.1 }, { "ip": "169.254.1.1", "ok": true, "ms": 1 },
            { "ip": "100.64.0.1", "ok": true, "ms": 1 }, { "ip": "fd00::1", "ok": true, "ms": 1 },
            { "ip": "fe80::1", "ok": true, "ms": 1 }, { "ip": "::ffff:192.168.1.1", "ok": true, "ms": 1 },
            { "ip": "nonsense", "ok": true, "ms": 1 },
            { "ip": "203.0.113.7", "ok": true, "ms": 12.5 }, { "ip": "2606:4700::1", "ok": true, "ms": 9 },
        ] });
        hide_internal_probes(&mut t);
        assert_eq!(
            t["ranking"],
            json!([{ "ip": "203.0.113.7", "ok": true, "ms": 12.5 }, { "ip": "2606:4700::1", "ok": true, "ms": 9 }])
        );
    }

    #[test]
    fn public_api_hides_upstream_paths() {
        assert_eq!(redact_urls("https://dns.example/dns-query/abc123"), "https://dns.example");
        assert_eq!(redact_urls("https://dns.example:8443/q/abc"), "https://dns.example:8443");
        assert_eq!(redact_urls("h3://dns.example:443/dns-query/x"), "h3://dns.example");
        assert_eq!(redact_urls("tls://1.1.1.1:853"), "tls://1.1.1.1");
        assert_eq!(redact_urls("udp://[2001:db8::1]:5353"), "udp://[2001:db8::1]:5353");
        assert_eq!(redact_urls("quic://[2001:db8::1]:853"), "quic://[2001:db8::1]");
        assert_eq!(redact_urls("https://user:pw@dns.example/x"), "https://dns.example");
        assert_eq!(redact_urls("sdns://AQcAAAAAAAAAFDE3Ni4xMDMu"), "sdns://…");
        assert_eq!(
            redact_urls("上游 https://dns.example/dns-query/abc 逾時；改用 tls://dns.example:853"),
            "上游 https://dns.example 逾時；改用 tls://dns.example"
        );
        assert_eq!(redact_urls("沒有網址 1.2.3.4"), "沒有網址 1.2.3.4");
        assert_eq!(redact_urls("ftp://x.example/a"), "ftp://x.example/a", "不是上游的協議不動");
        let mut v = json!({
            "upstreams": [{ "id": "https://dns.example/dns-query/abc123", "ok": 1 }],
            "results": { "https://dns.example/p/one": { "ms": 1 }, "https://dns.example/p/two": { "ms": 2 }, "tls://9.9.9.9:853": {} },
            "errors": { "recent": [{ "msg": "https://dns.example/p/one 連線失敗" }] },
        });
        redact_upstream_urls(&mut v);
        assert_eq!(v["upstreams"][0]["id"], "https://dns.example");
        let keys: Vec<&String> = v["results"].as_object().unwrap().keys().collect();
        assert_eq!(keys.len(), 3, "同一台主機的鍵不會撞在一起：{keys:?}");
        assert!(keys.iter().all(|k| !k.contains("/p/")));
        assert!(v["results"].get("tls://9.9.9.9").is_some());
        assert_eq!(v["errors"]["recent"][0]["msg"], "https://dns.example 連線失敗");
    }

    #[test]
    fn scrubs_local_dirs_everywhere() {
        let mut v = json!({ "jobs": [{ "last": "寫入 /srv/kuroshio/state/cdn/pools.json 失敗", "n": 1 }],
            "file": "/srv/kuroshio/state/upstreams.json", "other": "/srv/kuroshio/data/x", "keep": "/tmp/a" });
        let mut dirs = vec!["/srv/kuroshio/state".to_string(), "/srv/kuroshio".to_string(), "/".to_string()];
        scrub_dirs(&mut v, &mut dirs);
        assert_eq!(v["jobs"][0]["last"], "寫入 …/cdn/pools.json 失敗");
        assert_eq!(v["file"], "…/upstreams.json");
        assert_eq!(v["other"], "…/data/x");
        assert_eq!(v["keep"], "/tmp/a", "太短的路徑（/）不處理");
    }

    #[test]
    fn hosts_and_clients() {
        assert_eq!(request_host("Dns.Example:8443").as_deref(), Some("dns.example"));
        assert_eq!(request_host("dns.example.").as_deref(), Some("dns.example"));
        assert_eq!(request_host("[2001:db8::1]:443").as_deref(), Some("[2001:db8::1]"));
        assert_eq!(request_host("evil<script>"), None);
        assert_eq!(request_host("a\"b.example"), None);
        assert_eq!(request_host(""), None);
        assert_eq!(request_host("x..y"), None);
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        let far: IpAddr = "198.51.100.7".parse().unwrap();
        assert_eq!(
            client_ip(lo, Some("203.0.113.5, 10.0.0.1"), true),
            "203.0.113.5".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            client_ip(lo, Some("203.0.113.5:5678"), true),
            "203.0.113.5".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            client_ip(lo, Some("[2001:db8::9]:5678"), true),
            "2001:db8::9".parse::<IpAddr>().unwrap()
        );
        assert_eq!(client_ip(lo, Some("203.0.113.5"), false), lo, "不信任代理");
        assert_eq!(client_ip(far, Some("203.0.113.5"), true), far, "不是本機代理");
        assert_eq!(client_ip("::ffff:198.51.100.7".parse().unwrap(), None, true), far);
    }

    #[test]
    fn detail_paths() {
        assert_eq!(detail_path("/secret/", "/dns-query"), "/secret");
        assert_eq!(detail_path("secret", "/dns-query"), "/secret");
        for bad in [
            "",
            "/",
            "/api",
            "/api/x",
            "/apple/x",
            "/dns-query",
            "/robots.txt",
            "/favicon.ico",
            "/q",
        ] {
            assert_eq!(detail_path(bad, "/q"), "/detail", "{bad}");
        }
    }

    #[test]
    fn uuid_and_xml() {
        // 跟 2.x 的 uuidFrom 一致（SHA-1 hex 依固定位置切開）
        assert_eq!(uuid_from("abc"), "A9993E36-4706-516A-AA3E-25717850C26C");
        assert_eq!(xml_escape("a&b<c>\"d"), "a&amp;b&lt;c&gt;\"d");
        assert_eq!(
            html_escape("<a href='x'>&\"</a>"),
            "&lt;a href=&#39;x&#39;&gt;&amp;&quot;&lt;/a&gt;"
        );
    }
}
