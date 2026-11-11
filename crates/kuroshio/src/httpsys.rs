//! 模式 B「HTTP.sys 共用」（規格 07 第 2 節）：透過 Windows HTTP Server API（HTTP API 2.0）向 HTTP.sys
//! 登記黑潮 DNS 自己的網址，跟 IIS 共用 TCP 443；TLS（與開了 `EnableHttp3` 時的 HTTP/3）由 HTTP.sys 處理。
//!
//! - 登記：`https://<網域>:<埠>/dns-query/`、`https://<網域>:<埠>/.well-known/kuroshio/`，公開頁開啟時加上
//!   `https://<網域>:<埠>/`；首頁已經被 IIS 站台登記時，改登記公開頁的實際路徑（`/api/public/`、`/apple/`…）
//! - 請求交給跟 TCP DoH 一樣的 [`crate::encrypted::doh_core`] 處理；用戶端 IP 取自 HTTP.sys（不看 X-Forwarded-For）
//! - 接收：兩條專用執行緒做同步的 `HttpReceiveHttpRequest`，處理交給 tokio；回應與讀剩下的內容走 `spawn_blocking`
//! - 停止（重新載入、結束）：移除網址、`HttpShutdownRequestQueue`，最後一個參照放掉時關閉所有 handle
//!
//! 模式判斷、網址清單、Alt-Svc、urlacl 指令、標頭對照等純邏輯跨平台（在任何系統上都能測試）；呼叫 HTTP.sys 只在 Windows。

use crate::iiscert::Step;
use kuroshio_config::get;
use serde_json::Value;
use std::net::IpAddr;

/// `listen.doh.windowsMode` 決定後的結果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WinMode {
    /// A：黑潮 DNS 自己監聽 TCP
    Standalone,
    /// B：向 HTTP.sys 登記網址
    HttpSys,
    /// C：IIS 反向代理（IIS 轉給本機埠）
    IisProxy,
}

impl WinMode {
    pub fn name(self) -> &'static str {
        match self {
            WinMode::Standalone => "standalone",
            WinMode::HttpSys => "httpsys",
            WinMode::IisProxy => "iis-proxy",
        }
    }
}

/// 設定裡寫的模式（小寫；沒寫 = auto）
pub fn configured(cfg: &Value) -> String {
    match get(cfg, "listen.doh.windowsMode")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_ascii_lowercase())
    {
        Some(s) if !s.is_empty() => s,
        _ => "auto".into(),
    }
}

/// auto 模式偵測 TCP 埠的結果
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortProbe {
    Free,
    /// 被 HTTP.sys / IIS 占用（說明）
    Busy(String),
}

/// 決定這一輪用哪個模式（啟動時決定一次）。`probe` 只在 Windows 的 auto 模式才會呼叫。回傳 (模式, 原因)
pub fn decide(configured: &str, windows: bool, port: u16, probe: impl FnOnce() -> PortProbe) -> (WinMode, String) {
    match configured {
        "iis-proxy" => (WinMode::IisProxy, "設定指定 IIS 反向代理".into()),
        _ if !windows => (
            WinMode::Standalone,
            if configured == "httpsys" {
                "HTTP.sys 只有 Windows 有，改成自己監聽".into()
            } else {
                "自己監聽".into()
            },
        ),
        "standalone" => (WinMode::Standalone, "設定指定獨立監聽".into()),
        "httpsys" => (WinMode::HttpSys, "設定指定 HTTP.sys 共用".into()),
        other => {
            let note = if other == "auto" {
                String::new()
            } else {
                format!("（不認識的模式「{other}」，當成 auto）")
            };
            match probe() {
                PortProbe::Free => (WinMode::Standalone, format!("自動：TCP {port} 沒被占用，自己監聽{note}")),
                PortProbe::Busy(why) => (
                    WinMode::HttpSys,
                    format!("自動：TCP {port} 已被 HTTP.sys / IIS 占用（{why}），跟 HTTP.sys 共用{note}"),
                ),
            }
        }
    }
}

/// 要登記的網址
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prefixes {
    /// DoH 與社群（一定要登記）
    pub doh: Vec<String>,
    /// 公開頁開啟時的整個網域（`https://<網域>:<埠>/`）
    pub site_root: Option<String>,
    /// 首頁已經被 IIS 登記時，改登記公開頁的實際路徑
    pub site_paths: Vec<String>,
}

impl Prefixes {
    /// urlacl 要登記的網址（首頁涵蓋底下所有路徑）
    pub fn acl(&self) -> Vec<String> {
        let mut v = self.doh.clone();
        match &self.site_root {
            Some(r) => v.push(r.clone()),
            None => v.extend(self.site_paths.iter().cloned()),
        }
        v
    }
}

/// HTTP.sys 的網址前置字串一定以 `/` 結尾；請求 `/dns-query`（沒有結尾斜線）也會對到 `/dns-query/`
fn prefix(domain: &str, port: u16, path: &str) -> String {
    let p = path.trim_matches('/');
    if p.is_empty() {
        format!("https://{domain}:{port}/")
    } else {
        format!("https://{domain}:{port}/{p}/")
    }
}

/// 網址清單。`site`：公開頁開啟時的詳細頁路徑
pub fn url_prefixes(domain: &str, port: u16, doh_path: &str, site: Option<&str>) -> Prefixes {
    let community = kuroshio_community::BASE_PATH.trim_end_matches('/');
    // 社群用 /.well-known/kuroshio/ 底下的路徑（版本可能再加）
    let community = community.rsplit_once('/').map(|(a, _)| a).unwrap_or(community);
    let mut doh = vec![prefix(domain, port, doh_path), prefix(domain, port, community)];
    doh.dedup();
    let (site_root, site_paths) = match site {
        Some(detail) => {
            let mut v: Vec<String> = [
                "/index.html",
                "/robots.txt",
                "/favicon.ico",
                "/favicon.svg",
                "/qr.svg",
                "/api/public",
                "/apple",
                detail,
            ]
            .iter()
            .map(|p| prefix(domain, port, p))
            .filter(|p| !doh.contains(p))
            .collect();
            v.dedup();
            (Some(prefix(domain, port, "/")), v)
        }
        None => (None, Vec::new()),
    };
    Prefixes {
        doh,
        site_root,
        site_paths,
    }
}

/// 依設定算出 HTTP.sys 模式的網域、埠號與網址；缺網域時回傳原因
pub fn plan(cfg: &Value) -> Result<(String, u16, Prefixes), String> {
    let domain = crate::iiscert::domain(cfg).ok_or("HTTP.sys 共用需要網域（domain / site.hostname）")?;
    if !crate::iiscert::valid_domain(&domain) {
        return Err(format!("網域格式不對：{domain}"));
    }
    let port = doh_port(cfg);
    let doh_path = match get(cfg, "listen.doh.path").and_then(Value::as_str).unwrap_or("").trim() {
        "" => "/dns-query".to_string(),
        p => p.to_string(),
    };
    let site_on = get(cfg, "site.enabled").and_then(Value::as_bool).unwrap_or(false);
    let detail = site_on.then(|| crate::site::detail_path(get(cfg, "site.detailPath").and_then(Value::as_str).unwrap_or(""), &doh_path));
    let p = url_prefixes(&domain, port, &doh_path, detail.as_deref());
    Ok((domain, port, p))
}

pub fn doh_port(cfg: &Value) -> u16 {
    get(cfg, "listen.doh.port")
        .and_then(Value::as_u64)
        .filter(|p| *p > 0)
        .unwrap_or(443) as u16
}

/// DoH3 由誰提供（規格 07 第 2.2 節）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Doh3Plan {
    /// 沒開
    Off,
    /// 黑潮 DNS 自己聽 UDP
    Kuroshio,
    /// HTTP.sys 開了 HTTP/3：登記的網址自動支援，黑潮 DNS 不綁 UDP
    HttpSys,
}

/// `http3`：設定 `listen.doh.http3`；`httpsys_h3`：登錄檔 `EnableHttp3`
pub fn doh3_plan(mode: WinMode, http3: bool, httpsys_h3: bool) -> Doh3Plan {
    match (mode == WinMode::HttpSys && httpsys_h3, http3) {
        // HTTP.sys 的 HTTP/3 對所有登記的網址都有效，不管 listen.doh.http3
        (true, _) => Doh3Plan::HttpSys,
        (false, true) => Doh3Plan::Kuroshio,
        (false, false) => Doh3Plan::Off,
    }
}

/// DoH 回應要不要帶 Alt-Svc（規格 07 第 2.3 節）。
/// - 黑潮 DNS 自己聽 UDP：宣告實際綁定的埠（`listen.doh.altSvcPort` 優先）；沒綁成功就不宣告
/// - HTTP.sys 提供 HTTP/3：登錄檔 `EnableAltSvc` 開著時 HTTP.sys 自己會送，不重複；沒開時由黑潮 DNS 宣告 HTTP.sys 的埠
pub fn alt_svc(plan: Doh3Plan, kuroshio_h3_port: Option<u16>, httpsys_port: u16, httpsys_alt_svc: bool, adv_port: u16) -> Option<String> {
    let port = match plan {
        Doh3Plan::Off => return None,
        Doh3Plan::Kuroshio => kuroshio_h3_port?,
        Doh3Plan::HttpSys if httpsys_alt_svc => return None,
        Doh3Plan::HttpSys => httpsys_port,
    };
    let p = if adv_port > 0 { adv_port } else { port };
    Some(format!("h3=\":{p}\"; ma=86400"))
}

/// `kuroshio setup` 要不要做 HTTP.sys 的準備（urlacl、憑證綁定）：DoH 開著、模式是 httpsys 或 auto
pub fn setup_wanted(cfg: &Value) -> bool {
    get(cfg, "listen.doh.enabled").and_then(Value::as_bool).unwrap_or(false) && matches!(configured(cfg).as_str(), "httpsys" | "auto")
}

/// urlacl：先刪舊的（沒有也沒關係），再登記給這個帳號
pub fn urlacl_steps(prefixes: &[String], user: &str) -> Vec<Step> {
    let mut v = Vec::new();
    for p in prefixes {
        v.push(Step {
            cmd: "netsh".into(),
            args: vec!["http".into(), "delete".into(), "urlacl".into(), format!("url={p}")],
            required: false,
        });
        v.push(Step {
            cmd: "netsh".into(),
            args: vec![
                "http".into(),
                "add".into(),
                "urlacl".into(),
                format!("url={p}"),
                format!("user={user}"),
            ],
            required: true,
        });
    }
    v
}

/// `netsh http show servicestate view=requestq` 裡登記在這個埠的網址（輸出會翻譯，只認網址本身）
pub fn registered_on_port(text: &str, port: u16) -> Vec<String> {
    let needle = format!(":{port}/");
    let mut v: Vec<String> = text
        .split_whitespace()
        .filter(|t| {
            let l = t.to_ascii_lowercase();
            (l.starts_with("http://") || l.starts_with("https://")) && l.contains(&needle)
        })
        .map(str::to_string)
        .collect();
    v.dedup();
    v
}

/// 原始網址拆成路徑與查詢字串（跟 hyper 的 `uri().path()` / `query()` 一樣：不解碼）
pub fn split_raw_url(raw: &str) -> (String, Option<String>) {
    // 絕對形式（`https://host/path?x`）去掉 scheme 與主機
    let rest = match raw.find("://") {
        Some(i) if !raw[..i].contains('/') => {
            let after = &raw[i + 3..];
            match after.find(['/', '?']) {
                Some(j) => &after[j..],
                None => "",
            }
        }
        _ => raw,
    };
    let (path, query) = match rest.split_once('?') {
        Some((p, q)) => (p, Some(q.to_string())),
        None => (rest, None),
    };
    let path = if path.is_empty() { "/".to_string() } else { path.to_string() };
    (path, query)
}

/// HTTP.sys 的動詞代碼（`HTTP_VERB`）
pub fn verb_name(v: i32) -> Option<&'static str> {
    Some(match v {
        3 => "OPTIONS",
        4 => "GET",
        5 => "HEAD",
        6 => "POST",
        7 => "PUT",
        8 => "DELETE",
        9 => "TRACE",
        10 => "CONNECT",
        _ => return None,
    })
}

/// 回應標頭在 `HTTP_RESPONSE_HEADERS.KnownHeaders` 裡的位置（`HTTP_HEADER_ID`）；不在表上的放 UnknownHeaders
pub fn known_response_header(name: &str) -> Option<usize> {
    const NAMES: [&str; 30] = [
        "cache-control",
        "connection",
        "date",
        "keep-alive",
        "pragma",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "via",
        "warning",
        "allow",
        "content-length",
        "content-type",
        "content-encoding",
        "content-language",
        "content-location",
        "content-md5",
        "content-range",
        "expires",
        "last-modified",
        "accept-ranges",
        "age",
        "etag",
        "location",
        "proxy-authenticate",
        "retry-after",
        "server",
        "set-cookie",
        "vary",
        "www-authenticate",
    ];
    NAMES.iter().position(|n| n.eq_ignore_ascii_case(name))
}

/// SOCKADDR（Windows 的記憶體排列）→ IP。AF_INET = 2、AF_INET6 = 23
pub fn sockaddr_ip(b: &[u8]) -> Option<IpAddr> {
    let family = u16::from_le_bytes([*b.first()?, *b.get(1)?]);
    match family {
        2 => {
            let a: [u8; 4] = b.get(4..8)?.try_into().ok()?;
            Some(IpAddr::from(a))
        }
        23 => {
            let a: [u8; 16] = b.get(8..24)?.try_into().ok()?;
            Some(IpAddr::from(a).to_canonical())
        }
        _ => None,
    }
}

/// 一個網址登記的結果（`/api/status` 用）
#[derive(Debug, Clone)]
pub struct UrlResult {
    pub url: String,
    pub error: Option<String>,
}

/// 登記失敗的錯誤碼 → 給人看的原因
pub fn add_url_error(url: &str, code: u32) -> String {
    match code {
        5 => format!(
            "沒有權限向 HTTP.sys 登記 {url}：請用「以系統管理員身分執行」的命令提示字元執行一次 kuroshio setup（會登記 urlacl），或用系統管理員 / 服務身分執行"
        ),
        183 => format!("{url} 已經有別的程式登記（IIS 站台或另一個黑潮 DNS）"),
        87 => format!("{url} 格式不被 HTTP.sys 接受"),
        c => format!("向 HTTP.sys 登記 {url} 失敗（錯誤碼 {c}）"),
    }
}

/// 執行中的 HTTP.sys 登記；`stop` 之後網址立刻移除
pub struct Server {
    #[cfg(windows)]
    inner: imp::Running,
    pub urls: Vec<UrlResult>,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "httpsys::Server({} 個網址)",
            self.urls.iter().filter(|u| u.error.is_none()).count()
        )
    }
}

impl Server {
    /// 移除網址、停止接收（可以重複呼叫）
    pub fn stop(&self) {
        #[cfg(windows)]
        self.inner.stop();
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
    }
}

/// auto 模式：TCP 埠是不是已經被 HTTP.sys / IIS 占用（試著綁定 + 看 HTTP.sys 已登記的網址）
#[cfg(windows)]
pub fn probe_port(hosts: &[IpAddr], port: u16) -> PortProbe {
    let mut addrs: Vec<IpAddr> = hosts.to_vec();
    addrs.push(IpAddr::from([0, 0, 0, 0]));
    for ip in addrs {
        if let Err(e) = std::net::TcpListener::bind((ip, port)) {
            if e.kind() == std::io::ErrorKind::AddrInUse {
                return PortProbe::Busy(format!("綁定 {ip}:{port} 時位址已被使用"));
            }
        }
    }
    let text = std::process::Command::new("netsh")
        .args(["http", "show", "servicestate", "view=requestq"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    match registered_on_port(&text, port).first() {
        Some(u) => PortProbe::Busy(format!("HTTP.sys 已有登記 {u}")),
        None => PortProbe::Free,
    }
}

#[cfg(not(windows))]
pub fn probe_port(_hosts: &[IpAddr], _port: u16) -> PortProbe {
    PortProbe::Free
}

/// 登錄檔 `HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters` 的 (EnableHttp3, EnableAltSvc)
#[cfg(windows)]
pub fn registry_http3() -> (bool, bool) {
    (imp::reg_dword("EnableHttp3") == Some(1), imp::reg_dword("EnableAltSvc") == Some(1))
}

#[cfg(not(windows))]
pub fn registry_http3() -> (bool, bool) {
    (false, false)
}

#[cfg(windows)]
pub use imp::start;

#[cfg(not(windows))]
pub fn start(
    _p: &Prefixes,
    _r: std::sync::Arc<crate::resolver::Resolver>,
    _opts: crate::encrypted::DohOptions,
    _limits: crate::encrypted::Limits,
) -> anyhow::Result<Server> {
    anyhow::bail!("HTTP.sys 只有 Windows 有")
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::encrypted::{doh_core, DohOptions, DohReq, Limits};
    use crate::resolver::Resolver;
    use anyhow::{bail, Result};
    use bytes::Bytes;
    use std::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use tracing::{debug, info, warn};
    use windows_sys::Win32::Foundation::{
        ERROR_ALREADY_EXISTS, ERROR_CONNECTION_INVALID, ERROR_HANDLE_EOF, ERROR_INVALID_HANDLE, ERROR_MORE_DATA, ERROR_OPERATION_ABORTED,
        HANDLE, NO_ERROR,
    };
    use windows_sys::Win32::Networking::HttpServer::*;

    const V2: HTTPAPI_VERSION = HTTPAPI_VERSION {
        HttpApiMajorVersion: 2,
        HttpApiMinorVersion: 0,
    };
    /// 請求內容上限（跟 TCP 的 DoH 一樣）
    const MAX_BODY: usize = 65535;
    /// 標頭最大 1 MB，超過直接回 431
    const MAX_HEADER_BUF: usize = 1 << 20;
    const RECEIVERS: usize = 2;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn reg_dword(name: &str) -> Option<u32> {
        use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD};
        let key = wide(r"SYSTEM\CurrentControlSet\Services\HTTP\Parameters");
        let name = wide(name);
        let mut v: u32 = 0;
        let mut size = 4u32;
        // SAFETY：緩衝區是 4 bytes 的 u32，大小正確
        let rc = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                name.as_ptr(),
                RRF_RT_REG_DWORD,
                null_mut(),
                &mut v as *mut u32 as *mut _,
                &mut size,
            )
        };
        (rc == NO_ERROR).then_some(v)
    }

    /// HTTP.sys 的 handle：最後一個參照放掉時才關（處理中的請求還在用）
    struct Queue {
        h: HANDLE,
        session: u64,
        group: u64,
    }
    // SAFETY：HTTP Server API 的 handle 可以在多條執行緒同時使用
    unsafe impl Send for Queue {}
    unsafe impl Sync for Queue {}

    impl Drop for Queue {
        fn drop(&mut self) {
            // SAFETY：handle 是這個結構自己建立的，只關一次
            unsafe {
                if self.group != 0 {
                    HttpCloseUrlGroup(self.group);
                }
                if self.session != 0 {
                    HttpCloseServerSession(self.session);
                }
                if !self.h.is_null() {
                    HttpCloseRequestQueue(self.h);
                }
                HttpTerminate(HTTP_INITIALIZE_SERVER, null_mut());
            }
        }
    }

    pub struct Running {
        q: Arc<Queue>,
        stopped: Arc<AtomicBool>,
        threads: Mutex<Vec<std::thread::JoinHandle<()>>>,
    }

    impl Running {
        pub fn stop(&self) {
            if self.stopped.swap(true, Ordering::SeqCst) {
                return;
            }
            // SAFETY：handle 還開著（Queue 還有參照）
            unsafe {
                HttpRemoveUrlFromUrlGroup(self.q.group, null(), HTTP_URL_FLAG_REMOVE_ALL);
                HttpShutdownRequestQueue(self.q.h);
            }
            for t in self.threads.lock().unwrap().drain(..) {
                let _ = t.join();
            }
            info!("HTTP.sys：已移除登記的網址");
        }
    }

    struct Shared {
        rt: tokio::runtime::Handle,
        resolver: Arc<Resolver>,
        opts: DohOptions,
        limits: Limits,
    }

    fn check(what: &str, rc: u32) -> Result<()> {
        if rc != NO_ERROR {
            bail!("HTTP.sys {what} 失敗（錯誤碼 {rc}）");
        }
        Ok(())
    }

    pub fn start(p: &Prefixes, resolver: Arc<Resolver>, opts: DohOptions, limits: Limits) -> Result<Server> {
        let rt = tokio::runtime::Handle::current();
        // SAFETY：以下都是 HTTP Server API 的標準呼叫順序，指標都指向這裡的區域變數
        let q = unsafe {
            check("HttpInitialize", HttpInitialize(V2, HTTP_INITIALIZE_SERVER, null_mut()))?;
            let mut q = Queue {
                h: null_mut(),
                session: 0,
                group: 0,
            };
            check("HttpCreateServerSession", HttpCreateServerSession(V2, &mut q.session, 0))?;
            check("HttpCreateUrlGroup", HttpCreateUrlGroup(q.session, &mut q.group, 0))?;
            check("HttpCreateRequestQueue", HttpCreateRequestQueue(V2, null(), null(), 0, &mut q.h))?;
            let binding = HTTP_BINDING_INFO {
                Flags: HTTP_PROPERTY_FLAGS { _bitfield: 1 },
                RequestQueueHandle: q.h,
            };
            check(
                "HttpSetUrlGroupProperty",
                HttpSetUrlGroupProperty(
                    q.group,
                    HttpServerBindingProperty,
                    &binding as *const _ as *const _,
                    std::mem::size_of::<HTTP_BINDING_INFO>() as u32,
                ),
            )?;
            Arc::new(q)
        };
        let add = |url: &str| -> u32 {
            let w = wide(url);
            // SAFETY：w 以 0 結尾，呼叫期間有效
            unsafe { HttpAddUrlToUrlGroup(q.group, w.as_ptr(), 0, 0) }
        };
        let mut urls = Vec::new();
        let mut record = |url: &str, rc: u32| {
            let error = (rc != NO_ERROR).then(|| add_url_error(url, rc));
            match &error {
                None => info!("HTTP.sys：已登記 {url}"),
                Some(e) => warn!("{e}"),
            }
            urls.push(UrlResult {
                url: url.to_string(),
                error,
            });
        };
        for u in &p.doh {
            record(u, add(u));
        }
        if let Some(root) = &p.site_root {
            match add(root) {
                // 首頁已經是 IIS 的：只登記公開頁用到的路徑，首頁照常由 IIS 處理
                ERROR_ALREADY_EXISTS => {
                    info!("HTTP.sys：{root} 已經由 IIS 處理，公開頁改登記實際路徑");
                    for u in &p.site_paths {
                        record(u, add(u));
                    }
                }
                rc => record(root, rc),
            }
        }
        if !urls.iter().any(|u| u.error.is_none()) {
            let why: Vec<String> = urls.iter().filter_map(|u| u.error.clone()).collect();
            bail!("沒有任何網址登記成功：{}", why.join("；"));
        }
        let stopped = Arc::new(AtomicBool::new(false));
        let shared = Arc::new(Shared {
            rt,
            resolver,
            opts,
            limits,
        });
        let mut threads = Vec::new();
        for i in 0..RECEIVERS {
            let (q, s, st) = (q.clone(), shared.clone(), stopped.clone());
            threads.push(
                std::thread::Builder::new()
                    .name(format!("httpsys-{i}"))
                    .spawn(move || recv_loop(q, s, st))?,
            );
        }
        Ok(Server {
            inner: Running {
                q,
                stopped,
                threads: Mutex::new(threads),
            },
            urls,
        })
    }

    /// 一筆請求（從 HTTP.sys 的緩衝區複製出來）
    struct Incoming {
        id: u64,
        method: hyper::Method,
        raw_url: String,
        content_type: String,
        host: Option<String>,
        peer: IpAddr,
        http3: bool,
        body: Vec<u8>,
        more: bool,
    }

    /// SAFETY：`p` 指向 `len` bytes（或 null）
    unsafe fn text(p: *const u8, len: usize) -> String {
        if p.is_null() || len == 0 {
            return String::new();
        }
        String::from_utf8_lossy(std::slice::from_raw_parts(p, len)).into_owned()
    }

    /// SAFETY：`r` 是 HttpReceiveHttpRequest 剛填好的緩衝區
    unsafe fn parse(r: &HTTP_REQUEST_V1) -> Incoming {
        let method = match verb_name(r.Verb) {
            Some(v) => v.to_string(),
            None => text(r.pUnknownVerb, r.UnknownVerbLength as usize),
        };
        let method = hyper::Method::from_bytes(method.as_bytes()).unwrap_or(hyper::Method::GET);
        let known = |id: i32| {
            let h = r.Headers.KnownHeaders[id as usize];
            let s = text(h.pRawValue, h.RawValueLength as usize);
            (!s.is_empty()).then_some(s)
        };
        let peer = if r.Address.pRemoteAddress.is_null() {
            None
        } else {
            let a = r.Address.pRemoteAddress as *const u8;
            // 先看位址族再決定長度（SOCKADDR_IN 16 bytes、SOCKADDR_IN6 28 bytes）
            let len = if u16::from_le_bytes([*a, *a.add(1)]) == 23 { 28 } else { 16 };
            sockaddr_ip(std::slice::from_raw_parts(a, len))
        };
        let mut body = Vec::new();
        for i in 0..r.EntityChunkCount as usize {
            let c = &*r.pEntityChunks.add(i);
            if c.DataChunkType == HttpDataChunkFromMemory {
                let m = c.Anonymous.FromMemory;
                if !m.pBuffer.is_null() {
                    body.extend_from_slice(std::slice::from_raw_parts(m.pBuffer as *const u8, m.BufferLength as usize));
                }
            }
        }
        Incoming {
            id: r.RequestId,
            method,
            raw_url: text(r.pRawUrl, r.RawUrlLength as usize),
            content_type: known(HttpHeaderContentType).unwrap_or_default(),
            host: known(HttpHeaderHost),
            peer: peer.unwrap_or(IpAddr::from([0, 0, 0, 0])),
            http3: r.Flags & HTTP_REQUEST_FLAG_HTTP3 != 0,
            body,
            more: r.Flags & HTTP_REQUEST_FLAG_MORE_ENTITY_BODY_EXISTS != 0,
        }
    }

    fn recv_loop(q: Arc<Queue>, s: Arc<Shared>, stopped: Arc<AtomicBool>) {
        const SMALL: usize = 16 * 1024;
        // u64 對齊（HTTP_REQUEST 裡有 64 位元欄位）
        let mut buf: Vec<u64> = vec![0; SMALL / 8];
        let mut id: u64 = 0;
        loop {
            let mut got = 0u32;
            // SAFETY：buf 夠大而且對齊，同步呼叫（沒有 OVERLAPPED）
            let rc = unsafe {
                HttpReceiveHttpRequest(
                    q.h,
                    id,
                    HTTP_RECEIVE_REQUEST_FLAG_COPY_BODY,
                    buf.as_mut_ptr() as *mut HTTP_REQUEST_V2,
                    (buf.len() * 8) as u32,
                    &mut got,
                    null_mut(),
                )
            };
            match rc {
                NO_ERROR => {
                    // SAFETY：成功時緩衝區開頭是 HTTP_REQUEST_V2（第一個欄位是 V1）
                    let inc = unsafe { parse(&*(buf.as_ptr() as *const HTTP_REQUEST_V1)) };
                    id = 0;
                    if buf.len() * 8 > SMALL {
                        buf = vec![0; SMALL / 8];
                    }
                    let (q2, s2) = (q.clone(), s.clone());
                    s.rt.spawn(serve(q2, s2, inc));
                }
                ERROR_MORE_DATA => {
                    // SAFETY：ERROR_MORE_DATA 時 RequestId 已經填好
                    id = unsafe { (*(buf.as_ptr() as *const HTTP_REQUEST_V1)).RequestId };
                    let need = got as usize;
                    if need > MAX_HEADER_BUF {
                        let q2 = q.clone();
                        let rid = id;
                        id = 0;
                        send(&q2, rid, 431, &[], Bytes::new(), false);
                        continue;
                    }
                    buf = vec![0; need.div_ceil(8).max(SMALL / 8)];
                }
                ERROR_CONNECTION_INVALID if id != 0 => id = 0,
                ERROR_OPERATION_ABORTED | ERROR_INVALID_HANDLE => break,
                other => {
                    if stopped.load(Ordering::SeqCst) {
                        break;
                    }
                    debug!("HTTP.sys 接收失敗（錯誤碼 {other}）");
                    id = 0;
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
            if stopped.load(Ordering::SeqCst) {
                break;
            }
        }
    }

    /// 讀剩下的請求內容；超過上限回傳 None
    fn read_rest(q: &Queue, id: u64, mut body: Vec<u8>) -> Option<Vec<u8>> {
        let mut chunk = vec![0u8; 16 * 1024];
        loop {
            let mut got = 0u32;
            // SAFETY：chunk 在呼叫期間有效，同步呼叫
            let rc =
                unsafe { HttpReceiveRequestEntityBody(q.h, id, 0, chunk.as_mut_ptr() as *mut _, chunk.len() as u32, &mut got, null_mut()) };
            match rc {
                NO_ERROR => body.extend_from_slice(&chunk[..got as usize]),
                ERROR_HANDLE_EOF => return Some(body),
                _ => return None,
            }
            if body.len() > MAX_BODY {
                return None;
            }
        }
    }

    async fn serve(q: Arc<Queue>, s: Arc<Shared>, inc: Incoming) {
        let head = inc.method == hyper::Method::HEAD;
        let id = inc.id;
        let reply = |code: u16, body: &'static str| {
            let q = q.clone();
            tokio::task::spawn_blocking(move || {
                send(
                    &q,
                    id,
                    code,
                    &[("content-type", "text/plain; charset=utf-8".to_string())],
                    Bytes::from_static(body.as_bytes()),
                    head,
                )
            })
        };
        let Some(_permit) = s.limits.admit() else {
            let _ = reply(503, "busy\n").await;
            return;
        };
        let body = if inc.method == hyper::Method::POST {
            let (q2, first, more) = (q.clone(), inc.body, inc.more);
            let b = if more {
                tokio::task::spawn_blocking(move || read_rest(&q2, id, first)).await.ok().flatten()
            } else {
                Some(first)
            };
            match b.filter(|b| b.len() <= MAX_BODY) {
                Some(b) => b,
                None => {
                    let _ = reply(413, "too large\n").await;
                    return;
                }
            }
        } else {
            Vec::new()
        };
        let (path, query) = split_raw_url(&inc.raw_url);
        let req = DohReq {
            method: inc.method,
            path,
            query,
            content_type: inc.content_type,
            // HTTP.sys 直接給用戶端 IP，不採用 X-Forwarded-For
            forwarded_for: None,
            host: inc.host,
            body,
        };
        let proto = if inc.http3 { "doh3" } else { "doh" };
        let (code, headers, out) = doh_core(req, inc.peer, &s.resolver, &s.opts, proto).await;
        let _ = tokio::task::spawn_blocking(move || send(&q, id, code.as_u16(), &headers, out, head)).await;
    }

    /// 送出整個回應（同步，回應很小）
    fn send(q: &Queue, id: u64, code: u16, headers: &[(&'static str, String)], body: Bytes, head: bool) {
        let mut resp: HTTP_RESPONSE_V2 = Default::default();
        let reason = http::StatusCode::from_u16(code)
            .ok()
            .and_then(|c| c.canonical_reason())
            .unwrap_or("Unknown");
        resp.Base.StatusCode = code;
        resp.Base.pReason = reason.as_ptr();
        resp.Base.ReasonLength = reason.len() as u16;
        let mut values: Vec<(Option<usize>, &str, String)> =
            headers.iter().map(|(k, v)| (known_response_header(k), *k, v.clone())).collect();
        if !values.iter().any(|v| v.0 == Some(11)) {
            values.push((Some(11), "content-length", body.len().to_string()));
        }
        let mut unknown: Vec<HTTP_UNKNOWN_HEADER> = Vec::new();
        for (known, name, value) in &values {
            match known {
                Some(i) => {
                    resp.Base.Headers.KnownHeaders[*i] = HTTP_KNOWN_HEADER {
                        RawValueLength: value.len() as u16,
                        pRawValue: value.as_ptr(),
                    }
                }
                None => unknown.push(HTTP_UNKNOWN_HEADER {
                    NameLength: name.len() as u16,
                    RawValueLength: value.len() as u16,
                    pName: name.as_ptr(),
                    pRawValue: value.as_ptr(),
                }),
            }
        }
        resp.Base.Headers.UnknownHeaderCount = unknown.len() as u16;
        resp.Base.Headers.pUnknownHeaders = unknown.as_mut_ptr();
        let mut chunk = HTTP_DATA_CHUNK {
            DataChunkType: HttpDataChunkFromMemory,
            ..Default::default()
        };
        if !head && !body.is_empty() {
            chunk.Anonymous.FromMemory = HTTP_DATA_CHUNK_0_0 {
                pBuffer: body.as_ptr() as *mut _,
                BufferLength: body.len() as u32,
            };
            resp.Base.EntityChunkCount = 1;
            resp.Base.pEntityChunks = &mut chunk;
        }
        let mut sent = 0u32;
        // SAFETY：所有指標（標頭、內容）在這個同步呼叫結束前都有效
        let rc = unsafe { HttpSendHttpResponse(q.h, id, 0, &resp, null(), &mut sent, null(), 0, null_mut(), null()) };
        if rc != NO_ERROR {
            debug!("HTTP.sys 回應失敗（錯誤碼 {rc}）");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn mode_decision() {
        let never = || -> PortProbe { panic!("不該偵測") };
        assert_eq!(decide("iis-proxy", true, 443, never).0, WinMode::IisProxy);
        assert_eq!(decide("iis-proxy", false, 443, never).0, WinMode::IisProxy);
        assert_eq!(decide("standalone", true, 443, never).0, WinMode::Standalone);
        assert_eq!(decide("httpsys", true, 443, never).0, WinMode::HttpSys);
        let (m, why) = decide("httpsys", false, 443, never);
        assert_eq!(m, WinMode::Standalone);
        assert!(why.contains("只有 Windows"));
        assert_eq!(decide("auto", false, 443, never).0, WinMode::Standalone, "不是 Windows 不偵測");
        let (m, why) = decide("auto", true, 443, || PortProbe::Free);
        assert_eq!(m, WinMode::Standalone);
        assert!(why.contains("TCP 443 沒被占用"), "{why}");
        let (m, why) = decide("auto", true, 443, || PortProbe::Busy("HTTP.sys 已有登記 https://*:443/".into()));
        assert_eq!(m, WinMode::HttpSys);
        assert!(why.contains("https://*:443/"), "{why}");
        let (m, why) = decide("bogus", true, 8443, || PortProbe::Free);
        assert_eq!(m, WinMode::Standalone);
        assert!(why.contains("bogus"));
        assert_eq!(configured(&json!({})), "auto");
        assert_eq!(
            configured(&json!({ "listen": { "doh": { "windowsMode": " HttpSys " } } })),
            "httpsys"
        );
    }

    #[test]
    fn url_list() {
        let p = url_prefixes("dns.example.net", 443, "/dns-query", None);
        assert_eq!(
            p.doh,
            vec![
                "https://dns.example.net:443/dns-query/",
                "https://dns.example.net:443/.well-known/kuroshio/"
            ]
        );
        assert!(p.site_root.is_none() && p.site_paths.is_empty());
        assert_eq!(p.acl(), p.doh);
        let p = url_prefixes("dns.example.net", 8443, "/q/", Some("/stats"));
        assert_eq!(p.doh[0], "https://dns.example.net:8443/q/");
        assert_eq!(p.site_root.as_deref(), Some("https://dns.example.net:8443/"));
        assert!(p.site_paths.contains(&"https://dns.example.net:8443/api/public/".to_string()));
        assert!(p.site_paths.contains(&"https://dns.example.net:8443/stats/".to_string()));
        assert!(p.site_paths.contains(&"https://dns.example.net:8443/apple/".to_string()));
        assert!(p.site_paths.iter().all(|u| u.ends_with('/')));
        // urlacl 登記首頁就涵蓋底下所有路徑
        assert_eq!(p.acl().len(), 3);
        // 從設定
        let cfg = json!({ "domain": "DNS.example.net", "listen": { "doh": { "port": 443, "path": "/dns-query" } }, "site": { "enabled": true, "detailPath": "/detail" } });
        let (d, port, p) = plan(&cfg).unwrap();
        assert_eq!((d.as_str(), port), ("dns.example.net", 443));
        assert!(p.site_paths.contains(&"https://dns.example.net:443/detail/".to_string()));
        assert!(plan(&json!({})).unwrap_err().contains("網域"));
    }

    #[test]
    fn doh3_and_alt_svc() {
        use Doh3Plan::*;
        assert_eq!(doh3_plan(WinMode::HttpSys, true, true), HttpSys);
        assert_eq!(doh3_plan(WinMode::HttpSys, false, true), HttpSys, "HTTP.sys 開了 HTTP/3 就一定有");
        assert_eq!(doh3_plan(WinMode::HttpSys, true, false), Kuroshio);
        assert_eq!(doh3_plan(WinMode::Standalone, true, true), Kuroshio, "模式 A 不管登錄檔");
        assert_eq!(doh3_plan(WinMode::Standalone, false, false), Off);
        assert_eq!(
            alt_svc(Kuroshio, Some(443), 443, false, 0).as_deref(),
            Some("h3=\":443\"; ma=86400")
        );
        assert_eq!(
            alt_svc(Kuroshio, Some(8443), 443, false, 443).as_deref(),
            Some("h3=\":443\"; ma=86400")
        );
        assert_eq!(alt_svc(Kuroshio, None, 443, false, 0), None, "UDP 沒綁成功就不宣告");
        assert_eq!(alt_svc(HttpSys, None, 443, true, 0), None, "HTTP.sys 自己送 Alt-Svc");
        assert_eq!(alt_svc(HttpSys, None, 443, false, 0).as_deref(), Some("h3=\":443\"; ma=86400"));
        assert_eq!(alt_svc(Off, Some(443), 443, false, 0), None);
    }

    #[test]
    fn setup_decision() {
        assert!(!setup_wanted(&json!({})));
        assert!(setup_wanted(&json!({ "listen": { "doh": { "enabled": true } } })));
        assert!(setup_wanted(
            &json!({ "listen": { "doh": { "enabled": true, "windowsMode": "httpsys" } } })
        ));
        assert!(!setup_wanted(
            &json!({ "listen": { "doh": { "enabled": true, "windowsMode": "iis-proxy" } } })
        ));
        assert!(!setup_wanted(
            &json!({ "listen": { "doh": { "enabled": true, "windowsMode": "standalone" } } })
        ));
    }

    #[test]
    fn urlacl_plan() {
        let s = urlacl_steps(&["https://dns.example.net:443/dns-query/".into()], r"PC\user");
        let line = |i: usize| format!("{} {}", s[i].cmd, s[i].args.join(" "));
        assert_eq!(line(0), "netsh http delete urlacl url=https://dns.example.net:443/dns-query/");
        assert!(!s[0].required);
        assert_eq!(
            line(1),
            r"netsh http add urlacl url=https://dns.example.net:443/dns-query/ user=PC\user"
        );
        assert!(s[1].required);
    }

    #[test]
    fn servicestate_parsing() {
        let text = "要求佇列:\n    URL 群組識別碼: FF00000140000001\n        已登記的 URL:\n            HTTPS://*:443/\n            HTTP://*:80/\n            HTTPS://LOCALHOST:8443/DNS-QUERY/\n";
        assert_eq!(registered_on_port(text, 443), vec!["HTTPS://*:443/"]);
        assert_eq!(registered_on_port(text, 8443), vec!["HTTPS://LOCALHOST:8443/DNS-QUERY/"]);
        assert!(registered_on_port(text, 853).is_empty());
    }

    #[test]
    fn raw_url_and_headers() {
        assert_eq!(split_raw_url("/dns-query?dns=AAAB"), ("/dns-query".into(), Some("dns=AAAB".into())));
        assert_eq!(split_raw_url("/"), ("/".into(), None));
        assert_eq!(split_raw_url("https://h.example:443/a/b?x=1"), ("/a/b".into(), Some("x=1".into())));
        assert_eq!(split_raw_url("https://h.example"), ("/".into(), None));
        assert_eq!(split_raw_url("/p%20q?r"), ("/p%20q".into(), Some("r".into())), "不解碼");
        assert_eq!(verb_name(4), Some("GET"));
        assert_eq!(verb_name(6), Some("POST"));
        assert_eq!(verb_name(1), None);
        assert_eq!(known_response_header("Content-Type"), Some(12));
        assert_eq!(known_response_header("content-length"), Some(11));
        assert_eq!(known_response_header("cache-control"), Some(0));
        assert_eq!(known_response_header("location"), Some(23));
        assert_eq!(known_response_header("alt-svc"), None);
        assert_eq!(known_response_header("x-robots-tag"), None);
    }

    #[test]
    fn sockaddr() {
        let mut v4 = vec![2u8, 0, 0x01, 0xbb, 192, 0, 2, 7];
        v4.resize(16, 0);
        assert_eq!(sockaddr_ip(&v4), Some("192.0.2.7".parse().unwrap()));
        let mut v6 = vec![23u8, 0, 0, 0, 0, 0, 0, 0];
        v6.extend_from_slice(&"2001:db8::5".parse::<std::net::Ipv6Addr>().unwrap().octets());
        v6.extend_from_slice(&[0; 4]);
        assert_eq!(sockaddr_ip(&v6), Some("2001:db8::5".parse().unwrap()));
        let mut mapped = vec![23u8, 0, 0, 0, 0, 0, 0, 0];
        mapped.extend_from_slice(&"::ffff:198.51.100.1".parse::<std::net::Ipv6Addr>().unwrap().octets());
        assert_eq!(sockaddr_ip(&mapped), Some("198.51.100.1".parse().unwrap()));
        assert_eq!(sockaddr_ip(&[9, 9]), None);
        assert!(add_url_error("u", 5).contains("kuroshio setup"));
    }
}
