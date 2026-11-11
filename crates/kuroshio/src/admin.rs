//! 管理 API（規格 02 第 6 節）：只聽 127.0.0.1，路徑與回應格式沿用 2.x，LuCI 經 rpcd 呼叫。
//!
//! 只是本機用的小型 HTTP/1.1 伺服器（一個請求一條連線），不需要完整的 HTTP 函式庫。
//! Host 標頭必須是本機名稱，防止 DNS rebinding 從瀏覽器打進來。

use crate::app::AppState;
use crate::webui::Req;
use kuroshio_proto::message::{normalize, Message};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

pub async fn listen(state: Arc<AppState>, addr: SocketAddr) -> anyhow::Result<SocketAddr> {
    if !addr.ip().is_loopback() {
        warn!("管理 API 聽在 {addr}，不是本機位址：任何連得到的人都能操作，建議改回 127.0.0.1");
    }
    let l = TcpListener::bind(addr).await?;
    let bound = l.local_addr()?;
    info!("管理 API http://{bound}/api/status");
    // 同時處理的連線有上限：慢慢送標頭的連線、同時上傳很多大檔案都不會把記憶體用光
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNS));
    tokio::spawn(async move {
        loop {
            let Ok(permit) = slots.clone().acquire_owned().await else { return };
            let Ok((s, peer)) = l.accept().await else { continue };
            let st = state.clone();
            tokio::spawn(async move {
                if let Err(e) = conn(st, s).await {
                    debug!("管理 API {peer}：{e}");
                }
                drop(permit);
            });
        }
    });
    Ok(bound)
}

pub struct Response {
    pub code: u16,
    pub body: Value,
    /// 非 JSON 回應（CSV 下載）：(content-type, 檔名, 內容)
    pub raw: Option<(&'static str, String, String)>,
}

fn ok(body: Value) -> Response {
    Response {
        code: 200,
        body,
        raw: None,
    }
}

fn bad(msg: &str, code: u16) -> Response {
    Response {
        code,
        body: json!({ "error": msg }),
        raw: None,
    }
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                match u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("zz"), 16) {
                    Ok(v) => out.push(v),
                    Err(_) => out.extend_from_slice(&b[i..i + 3]),
                }
                i += 2;
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn parse_query(q: &str) -> HashMap<String, String> {
    q.split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (pct_decode(k), pct_decode(v))
        })
        .collect()
}

/// Host 標頭是不是本機（沒有 Host 的 HTTP/1.0 請求也算，uclient-fetch 會帶）
pub fn local_host(host: Option<&str>) -> bool {
    let Some(h) = host else { return true };
    let h = h.trim();
    let name = if let Some(rest) = h.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        h.rsplit_once(':').map(|x| x.0).unwrap_or(h)
    };
    name.eq_ignore_ascii_case("localhost") || name.parse::<IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false)
}

/// 匯入備份的路徑（內容上限是備份檔的上限，不是 1 MB）
const IMPORT_PATH: &str = "/api/backup/import";

/// 同時處理的連線數上限
const MAX_CONNS: usize = 64;

/// 登入失敗時多等這麼久才回應（猜 token 的速度上限 = 連線數上限 ÷ 這個時間）
const LOGIN_FAIL_DELAY: Duration = Duration::from_millis(500);

/// 會改變狀態、或讓服務對外連線做事的路徑：只接受 POST。
///
/// GET 不帶 Origin，瀏覽器裡任何網頁都能用 `<img src>` 送出；關掉登入（OpenWrt 預設、或 `admin.auth=false`）時
/// 那樣就能清快取、改 CDN 策略、加好友。POST 一定帶 Origin，跨站的會被 `same_origin` 擋下。
pub fn is_action(path: &str, q: &HashMap<String, String>) -> bool {
    match path {
        "/api/cache/flush" | "/api/jobs/run" | "/api/acme/issue" | "/api/ddns/update" | "/api/filter/update" | "/api/cdn/verify"
        | "/api/cdn/policy" | "/api/cdn/ecs" => true,
        p => match p.strip_prefix("/api/community/") {
            Some("status" | "peers" | "events" | "scores") => false,
            // 不帶 channel 是查詢，帶了是指定管道
            Some("channel") => q.contains_key("channel"),
            Some(_) => true,
            None => false,
        },
    }
}

/// 下載檔名只留英數與 `._-`（檔名的一部分來自查詢參數，不能讓它帶換行塞進回應標頭）
pub fn safe_filename(name: &str) -> String {
    let s: String = name
        .chars()
        .take(80)
        .map(|c| if c.is_ascii_alphanumeric() || "._-".contains(c) { c } else { '_' })
        .collect();
    if s.is_empty() {
        "download".into()
    } else {
        s
    }
}

/// `Transfer-Encoding: chunked` 的內容（uclient-fetch 的 POST 一律用這個）；`raw` 是已經讀進來的部分
async fn read_chunked(s: &mut TcpStream, mut raw: Vec<u8>, max: usize, deadline: Instant) -> anyhow::Result<Vec<u8>> {
    let mut tmp = [0u8; 16384];
    let mut body = Vec::new();
    loop {
        // 這一塊的長度（十六進位，後面可能有 `;擴充`）
        let line_end = loop {
            if let Some(p) = raw.windows(2).position(|w| w == b"\r\n") {
                break p;
            }
            if raw.len() > 256 {
                anyhow::bail!("chunked 格式錯誤");
            }
            let n = tokio::time::timeout_at(deadline.into(), s.read(&mut tmp)).await??;
            if n == 0 {
                anyhow::bail!("內容不完整");
            }
            raw.extend_from_slice(&tmp[..n]);
        };
        let line = std::str::from_utf8(&raw[..line_end]).unwrap_or("");
        let size =
            usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16).map_err(|_| anyhow::anyhow!("chunked 格式錯誤"))?;
        if size == 0 {
            // 後面的 trailer 不需要
            return Ok(body);
        }
        if size > max || body.len() + size > max {
            anyhow::bail!("內容太大");
        }
        let start = line_end + 2;
        while raw.len() < start + size + 2 {
            let n = tokio::time::timeout_at(deadline.into(), s.read(&mut tmp)).await??;
            if n == 0 {
                anyhow::bail!("內容不完整");
            }
            raw.extend_from_slice(&tmp[..n]);
        }
        body.extend_from_slice(&raw[start..start + size]);
        raw.drain(..start + size + 2);
    }
}

/// 讀一個 HTTP/1.1 請求（標頭最多 16 KB、內容最多 1 MB；已登入的匯入備份最多 64 MB）
async fn read_req(s: &mut TcpStream, ui: &crate::webui::WebUi) -> anyhow::Result<Option<Req>> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 16384];
    let mut deadline = Instant::now() + Duration::from_secs(10);
    let head_end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p;
        }
        if buf.len() > 16 * 1024 {
            anyhow::bail!("標頭太大");
        }
        let n = tokio::time::timeout_at(deadline.into(), s.read(&mut tmp)).await??;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.split("\r\n");
    let mut parts = lines.next().unwrap_or("").split_whitespace();
    let (method, target) = (parts.next().unwrap_or("").to_string(), parts.next().unwrap_or("/").to_string());
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let mut req = Req {
        method,
        headers,
        ..Default::default()
    };
    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
    (req.path, req.query) = (path.to_string(), query.to_string());
    let len: usize = req.header("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    // 大檔案只收「會被處理的」：已登入、本機來源的匯入。沒登入的人不能讓服務先收下 64 MB 再回 401
    let max = if req.path == IMPORT_PATH && req.method == "POST" && req.same_origin() && ui.authorized(&req) {
        deadline += Duration::from_secs(50);
        crate::backup::MAX_BYTES
    } else {
        1 << 20
    };
    if len > max {
        anyhow::bail!("內容太大");
    }
    if req
        .header("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
    {
        req.body = read_chunked(s, buf[head_end + 4..].to_vec(), max, deadline).await?;
        return Ok(Some(req));
    }
    let mut body = buf[head_end + 4..].to_vec();
    body.reserve(len.saturating_sub(body.len()));
    while body.len() < len {
        let n = tokio::time::timeout_at(deadline.into(), s.read(&mut tmp)).await??;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(len);
    req.body = body;
    Ok(Some(req))
}

/// 要送出的回應
struct Out {
    code: u16,
    ctype: &'static str,
    headers: Vec<String>,
    body: Vec<u8>,
}

impl Out {
    fn json(code: u16, v: &Value) -> Out {
        Out {
            code,
            ctype: "application/json; charset=utf-8",
            headers: vec![],
            body: serde_json::to_vec_pretty(v).unwrap_or_default(),
        }
    }
    fn redirect(to: &str, cookie: Option<String>) -> Out {
        let mut headers = vec![format!("location: {to}")];
        headers.extend(cookie.map(|c| format!("set-cookie: {c}")));
        Out {
            code: 303,
            ctype: "text/plain; charset=utf-8",
            headers,
            body: vec![],
        }
    }
    fn from_response(r: Response) -> Out {
        match r.raw {
            Some((t, name, text)) => Out {
                code: r.code,
                ctype: t,
                headers: vec![format!("content-disposition: attachment; filename=\"{}\"", safe_filename(&name))],
                body: text.into_bytes(),
            },
            None => Out::json(r.code, &r.body),
        }
    }
}

async fn conn(st: Arc<AppState>, mut s: TcpStream) -> anyhow::Result<()> {
    let req = match read_req(&mut s, &st.webui).await {
        Ok(Some(r)) => r,
        Ok(None) => return Ok(()),
        Err(e) => {
            // 太大或格式錯誤：回一個看得懂的狀態碼再關（用戶端才不會只看到連線被切斷）
            let body = serde_json::to_vec(&json!({ "error": e.to_string() })).unwrap_or_default();
            let head = format!(
                "HTTP/1.1 400 Bad Request\r\ncontent-type: application/json; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(head.as_bytes()).await;
            let _ = s.write_all(&body).await;
            let _ = s.shutdown().await;
            return Err(e);
        }
    };
    let out = handle(&st, &req).await;
    let reason = match out.code {
        200 => "OK",
        303 => "See Other",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        429 => "Too Many Requests",
        _ => "Error",
    };
    let mut head = format!(
        "HTTP/1.1 {} {reason}\r\ncontent-type: {}\r\ncontent-length: {}\r\ncache-control: no-store\r\nx-content-type-options: nosniff\r\nx-frame-options: DENY\r\nreferrer-policy: same-origin\r\nconnection: close\r\n",
        out.code,
        out.ctype,
        out.body.len()
    );
    for h in &out.headers {
        head.push_str(h);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    // 對方不收也不會一直占著連線（與回應的記憶體）
    tokio::time::timeout(Duration::from_secs(60), async {
        s.write_all(head.as_bytes()).await?;
        if req.method != "HEAD" {
            s.write_all(&out.body).await?;
        }
        s.shutdown().await.ok();
        Ok::<_, std::io::Error>(())
    })
    .await??;
    Ok(())
}

async fn handle(st: &Arc<AppState>, req: &Req) -> Out {
    if !local_host(req.header("host")) {
        return Out::from_response(bad("只接受本機連線", 403));
    }
    let ui = &st.webui;
    let m = req.method.as_str();
    let write = m == "POST" || m == "PUT";
    if write && !req.same_origin() {
        return Out::from_response(bad("拒絕跨站請求", 403));
    }
    // 瀏覽器會標明請求是不是別的網站發的：別的網站連讀取類的 API 也不給碰（不讓它量回應時間、或幫忙猜 token）
    if req.path.starts_with("/api/") && req.cross_site_fetch() {
        return Out::from_response(bad("拒絕跨站請求", 403));
    }
    match req.path.as_str() {
        "/login" => {
            let q = if m == "POST" {
                parse_query(&String::from_utf8_lossy(&req.body))
            } else {
                parse_query(&req.query)
            };
            if !ui.auth_enabled() {
                return Out::redirect("/", None);
            }
            match q.get("token") {
                Some(t) if ui.check_token(t) => {
                    let sid = ui.new_session();
                    Out::redirect(
                        "/",
                        Some(format!("{}={sid}; Path=/; HttpOnly; SameSite=Strict", crate::webui::COOKIE)),
                    )
                }
                _ => {
                    tokio::time::sleep(LOGIN_FAIL_DELAY).await;
                    Out::redirect("/?login=failed", None)
                }
            }
        }
        "/logout" => {
            if let Some(c) = req.cookie(crate::webui::COOKIE) {
                ui.logout(c);
            }
            Out::redirect(
                "/",
                Some(format!("{}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict", crate::webui::COOKIE)),
            )
        }
        "/api/session" => Out::json(200, &ui.session_json(req, ui.config_file.get().is_none())),
        // 關於（版本、授權、原始碼）與原始碼網址的 QR 碼：不用登入
        "/api/about" => Out::json(200, &ui.about),
        "/api/qr" => match crate::about::qr_svg(ui.about["source"].as_str().unwrap_or(crate::about::DEFAULT_SOURCE)) {
            Some(svg) => Out {
                code: 200,
                ctype: "image/svg+xml",
                headers: vec![],
                body: svg.into_bytes(),
            },
            None => Out::from_response(bad("error", 500)),
        },
        p if p.starts_with("/api/") => {
            if !ui.authorized(req) {
                return Out::from_response(bad("需要登入", 401));
            }
            match (m, p) {
                ("GET", "/api/config") | ("PUT", "/api/config") => Out::from_response(config_api(st, req)),
                ("GET", "/api/backup/export") => backup_export(st, req).await,
                ("POST", IMPORT_PATH) => Out::from_response(backup_import(st, req).await),
                ("GET", "/api/log") => {
                    let n = parse_query(&req.query)
                        .get("lines")
                        .and_then(|n| n.parse().ok())
                        .unwrap_or(200usize);
                    Out::json(200, &json!({ "lines": crate::logring::lines(n) }))
                }
                ("GET" | "POST" | "HEAD", _) => {
                    let q = parse_query(&req.query);
                    if m != "POST" && is_action(p, &q) {
                        let mut out = Out::from_response(bad("這個動作只接受 POST", 405));
                        out.headers.push("allow: POST".into());
                        return out;
                    }
                    Out::from_response(route(st, p, &q).await)
                }
                _ => Out::from_response(bad("不支援這個方法", 405)),
            }
        }
        p if m == "GET" || m == "HEAD" => match ui.static_file(p) {
            Some((ctype, body)) => Out {
                code: 200,
                ctype,
                headers: vec![],
                body,
            },
            None => Out::from_response(bad("not found", 404)),
        },
        _ => Out::from_response(bad("不支援這個方法", 405)),
    }
}

/// `/api/config`：只有用 JSON 設定檔時（OpenWrt 用 UCI，回 404）
fn config_api(st: &Arc<AppState>, req: &Req) -> Response {
    let Some(file) = st.webui.config_file.get() else {
        return bad("這個平台的設定不走設定檔（OpenWrt 請用 LuCI）", 404);
    };
    if req.method == "GET" {
        let user: Value = std::fs::read(file)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_else(|| json!({}));
        let tier = kuroshio_config::requested_tier(&user).unwrap_or(st.tier);
        let mut effective = kuroshio_config::build(tier, &user);
        // API Token 之類的密碼不送到瀏覽器：換成遮罩，存檔時遮罩 = 沒改
        let mut user = user;
        crate::webui::mask_secrets(&mut user);
        crate::webui::mask_secrets(&mut effective);
        return ok(json!({
            "file": file, "user": user, "tier": st.tier.name(),
            "effective": effective,
            "defaults": kuroshio_config::build(tier, &json!({})),
        }));
    }
    let mut v: Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(e) => return bad(&format!("JSON 格式錯誤：{e}"), 400),
    };
    // 送回來的遮罩換回檔案裡原本的值
    let old: Value = std::fs::read(file)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Value::Null);
    crate::webui::unmask_secrets(&mut v, &old);
    if let Err(e) = crate::webui::validate_config(&v) {
        return bad(&e, 400);
    }
    let text = serde_json::to_string_pretty(&v).unwrap_or_default() + "\n";
    if let Err(e) = crate::persist::write_atomic(file, text.as_bytes()) {
        return bad(&format!("寫入 {} 失敗：{e}", file.display()), 500);
    }
    info!("設定頁更新了 {}，重新載入", file.display());
    // 先回應，再重新載入（目前這個管理 API 也會關掉重開）
    let r = st.reload.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        r.notify_one();
    });
    ok(json!({ "ok": true, "reloading": true }))
}

/// `GET /api/backup/export?kind=full|share`：先把記憶體裡的狀態寫出，再下載 `.kuroshio` 檔
async fn backup_export(st: &Arc<AppState>, req: &Req) -> Out {
    let q = parse_query(&req.query);
    let Some(kind) = crate::backup::Kind::parse(q.get("kind").map(String::as_str).unwrap_or("full")) else {
        return Out::from_response(bad("kind 只能是 full 或 share", 400));
    };
    let s2 = st.clone();
    match tokio::task::spawn_blocking(move || crate::backup::export_running(&s2, kind)).await {
        Ok(body) => {
            info!("匯出{}（{} KB）", kind.label(), body.len().div_ceil(1024));
            Out {
                code: 200,
                ctype: "application/octet-stream",
                headers: vec![format!(
                    "content-disposition: attachment; filename=\"{}\"",
                    crate::backup::file_name(kind)
                )],
                body,
            }
        }
        Err(e) => Out::from_response(bad(&format!("匯出失敗：{e}"), 500)),
    }
}

/// `POST /api/backup/import`（內容 = 檔案本身）：檢查後放著，服務在程式內重新啟動時合併
async fn backup_import(st: &Arc<AppState>, req: &Req) -> Response {
    if req.body.is_empty() {
        return bad("沒有收到檔案", 400);
    }
    let preview = match crate::backup::stage_pending(&st.backup, &req.body) {
        Ok(p) => p,
        Err(e) => return bad(&format!("{e:#}"), 400),
    };
    info!("收到{}，重新載入後合併", preview["kindLabel"].as_str().unwrap_or("備份"));
    let r = st.reload.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        r.notify_one();
    });
    ok(json!({ "ok": true, "reloading": true, "preview": preview }))
}

fn qtype_num(t: &str) -> Option<u16> {
    Some(match t.to_ascii_uppercase().as_str() {
        "" | "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "SVCB" => 64,
        "HTTPS" => 65,
        n => n.parse().ok()?,
    })
}

/// 路由（獨立出來方便測試）
pub async fn route(st: &Arc<AppState>, path: &str, q: &HashMap<String, String>) -> Response {
    let r = &st.resolver;
    match path {
        "/api/status" => {
            let (cache_entries, cache_bytes) = {
                let c = r.cache.lock().unwrap();
                (c.len(), c.approx_bytes())
            };
            let filter = r.filter.read().unwrap().as_ref().map(|f| f.stats()).unwrap_or(Value::Null);
            ok(json!({
                "version": env!("CARGO_PKG_VERSION"),
                "stats": r.stats.summary(),
                "cacheEntries": cache_entries,
                "cacheBytes": cache_bytes,
                "errors": r.errors_json(),
                "ownIp": null,
                "upstreams": r.upstreams.list_json(),
                "autoUpstreams": r.upstreams.auto_info(),
                "filter": filter,
                "cdn": r.cdn().map(|c| c.status_lite()),
                "jobs": st.scheduler.as_ref().map(|s| s.status()),
                "system": st.system_json(),
                "listeners": {
                    "doh": st.encrypted.doh.map(|a| a.port()), "doh3": st.encrypted.doh3.map(|a| a.port()),
                    "dot": st.encrypted.dot.map(|a| a.port()), "doq": st.encrypted.doq.map(|a| a.port()),
                    "ddr": st.resolver.ddr.read().unwrap().is_some(),
                },
                "listenersDetail": st.encrypted.detail_json(),
            }))
        }
        "/api/upstreams" => ok(r.upstreams.list_json()),
        "/api/benchmark" => ok(std::fs::read(r.upstreams.state_file())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(Value::Null)),
        "/api/sysinfo" => ok(st.system_json()),
        "/api/interfaces" => ok(crate::netif::json()),
        "/api/paths" => ok(crate::app::paths_json(&st.cfg, st.webui.config_file.get().map(|p| p.as_path()))),
        "/api/backup/last-import" => ok(crate::backup::last_import(&st.backup)),
        "/api/cache/flush" => {
            r.flush();
            ok(json!({ "ok": true }))
        }
        "/api/jobs" => ok(st.scheduler.as_ref().map(|s| s.status()).unwrap_or(Value::Null)),
        "/api/jobs/run" => match (&st.scheduler, q.get("name")) {
            (None, _) => bad("排程器未啟動", 400),
            (_, None) => bad("需要 name", 400),
            (Some(s), Some(n)) => ok(s.request(n, "手動 (管理介面)")),
        },
        // 規格 02 第 6 節
        "/api/defaults" => ok(kuroshio_config::build(st.tier, &json!({}))),
        "/api/protocols" => ok(json!({
            "plain": true,
            "doh": st.encrypted.doh.map(|a| a.port()), "doh3": st.encrypted.doh3.map(|a| a.port()),
            "dot": st.encrypted.dot.map(|a| a.port()), "doq": st.encrypted.doq.map(|a| a.port()),
            "ddr": st.resolver.ddr.read().unwrap().is_some(),
            "community": st.community.is_some(),
            "site": st.resolver.site.get().is_some(),
        })),
        "/api/acme" => ok(st.acme.as_ref().map(|a| a.status()).unwrap_or(json!({ "enabled": false }))),
        "/api/acme/issue" => match &st.acme {
            None => bad("內建 ACME 沒有啟用（acme.enabled）", 400),
            Some(a) => {
                let a = a.clone();
                let force = q.get("force").map(String::as_str) == Some("1");
                tokio::spawn(async move {
                    let _ = a.ensure(force).await;
                });
                ok(json!({ "started": true }))
            }
        },
        "/api/ddns" => ok(st.ddns.as_ref().map(|d| d.status()).unwrap_or(json!({ "enabled": false }))),
        "/api/ddns/update" => match &st.ddns {
            None => bad("DDNS 未啟用", 400),
            Some(d) => ok(d.update(true).await),
        },
        "/api/filter/update" => match &st.filter {
            None => bad("過濾未啟用", 400),
            Some(f) => {
                f.reload_custom(true);
                match f.update_lists(true).await {
                    Ok(changed) => ok(json!({ "changed": changed })),
                    Err(e) => bad(&format!("{e:#}"), 500),
                }
            }
        },
        "/api/filter/check" => {
            let Some(name) = q.get("name").filter(|n| !n.is_empty()) else {
                return bad("需要 name", 400);
            };
            let Some(t) = qtype_num(q.get("type").map(String::as_str).unwrap_or("A")) else {
                return bad("不認識的類型", 400);
            };
            let f = r.filter.read().unwrap().clone();
            match f {
                None => ok(json!({ "action": "none", "enabled": false })),
                Some(f) => ok(match f.check(&normalize(name), t) {
                    Some(v) => {
                        json!({ "action": if v.block { "block" } else if v.allow { "allow" } else { "none" }, "rule": v.rule, "cat": v.category, "tier": if v.category == "custom" { "custom" } else { "list" } })
                    }
                    None => json!({ "action": "none" }),
                }),
            }
        }
        "/api/trace" => {
            let Some(name) = q.get("name").filter(|n| !n.is_empty()) else {
                return bad("需要 name", 400);
            };
            let Some(t) = qtype_num(q.get("type").map(String::as_str).unwrap_or("A")) else {
                return bad("不認識的類型", 400);
            };
            ok(trace(st, &normalize(name), t).await)
        }
        // 每日各 CDN 的機會成本（最多 31 天）
        "/api/routing" => ok(r.stats.routing_json()),
        p if p.starts_with("/api/cdn/") => match r.cdn() {
            None => bad("CDN 台灣節點沒有啟用", 404),
            Some(c) => cdn_route(&c, p, q).await,
        },
        p if p.starts_with("/api/community/") => match &st.community {
            None => bad("社群共享沒有啟用", 404),
            Some(c) => match c.admin(p, q).await {
                Some(v) => ok(v),
                None => bad("not found", 404),
            },
        },
        _ => bad("not found", 404),
    }
}

async fn cdn_route(c: &Arc<kuroshio_cdn::Cdn>, path: &str, q: &HashMap<String, String>) -> Response {
    let name = q.get("name").map(|n| normalize(n)).filter(|n| !n.is_empty());
    match path {
        "/api/cdn/status" => ok(c.status()),
        "/api/cdn/pools" => ok(c.pools_status()),
        "/api/cdn/v6nodes" => ok(c.v6_nodes()),
        "/api/cdn/summary" => ok(c.summary()),
        "/api/cdn/cross" => ok(c.cross_summary()),
        "/api/cdn/domains" => {
            let query = kuroshio_cdn::db::Query {
                provider: q.get("provider").cloned().filter(|s| !s.is_empty()),
                verdict: q.get("verdict").cloned().filter(|s| !s.is_empty()),
                limit: Some(q.get("limit").and_then(|l| l.parse().ok()).unwrap_or(1000usize).min(200_000)),
                sort: q.get("sort").cloned(),
            };
            if q.get("format").map(String::as_str) == Some("csv") {
                let file = safe_filename(&format!("cdn-domains-{}.csv", query.provider.as_deref().unwrap_or("all")));
                return Response {
                    code: 200,
                    body: Value::Null,
                    raw: Some(("text/csv; charset=utf-8", file, c.query_csv(&query))),
                };
            }
            ok(c.query(&query))
        }
        "/api/cdn/domain" => match name.and_then(|n| c.domain(&n)) {
            Some(v) => ok(v),
            None => bad("資料庫裡沒有這個網域", 404),
        },
        "/api/cdn/verify" => {
            let Some(n) = name else { return bad("需要 name", 400) };
            let fam = if q.get("family").map(String::as_str) == Some("6") { 6 } else { 4 };
            match c.verify_now(&n, fam).await {
                Some((err, v)) => ok(json!({ "result": v, "error": err, "entry": c.domain(&n) })),
                None => bad("資料庫裡沒有這個網域（先查詢一次）", 404),
            }
        }
        "/api/cdn/policy" => {
            let Some(n) = name else { return bad("需要 name", 400) };
            match c.set_policy(&n, q.get("policy").map(String::as_str).unwrap_or("auto")) {
                Some(v) => ok(v),
                None => bad("policy 只能是 auto / always / never，或沒有這個網域", 400),
            }
        }
        "/api/cdn/ecs" => {
            let Some(n) = name else { return bad("需要 name", 400) };
            ok(c.ecs_now(&n).await)
        }
        _ => bad("not found", 404),
    }
}

/// 除錯用：完整追蹤一個網域（過濾、每個上游的回答、IP 測速、快取）
async fn trace(st: &Arc<AppState>, name: &str, qtype: u16) -> Value {
    let r = &st.resolver;
    let filter = r.filter.read().unwrap().clone().and_then(|f| f.check(name, qtype));
    let query = Message::parse(&kuroshio_proto::build_query(0, name, qtype)).unwrap_or_default();
    let upq = kuroshio_proto::logic::upstream_query(&query, 0, None).encode();
    let mut list = r.upstreams.active();
    list.extend(r.upstreams.fallback.iter().cloned());
    let mut set = tokio::task::JoinSet::new();
    for u in list {
        let q = upq.clone();
        let t = r.params.timeout;
        set.spawn(async move {
            let t0 = Instant::now();
            let res = u.up.exchange(&q, t).await;
            let ms = (t0.elapsed().as_secs_f64() * 10000.0).round() / 10.0;
            match res.ok().and_then(|b| Message::parse(&b).ok()) {
                Some(m) => json!({
                    "id": u.up.id, "role": u.role.name(), "ms": ms, "rcode": m.rcode,
                    "cls": format!("{:?}", kuroshio_proto::logic::classify(&m, qtype)).to_lowercase(),
                    "answers": m.answers.iter().map(|a| format!("{} {} {} {}", a.rtype, a.name, a.ttl, rdata_text(&a.data))).collect::<Vec<_>>(),
                }),
                None => json!({ "id": u.up.id, "role": u.role.name(), "ms": ms, "error": "沒有回應或格式錯誤" }),
            }
        });
    }
    let mut ups = Vec::new();
    while let Some(Ok(v)) = set.join_next().await {
        ups.push(v);
    }
    ups.sort_by(|a, b| a["ms"].as_f64().partial_cmp(&b["ms"].as_f64()).unwrap_or(std::cmp::Ordering::Equal));
    let mut ips: Vec<IpAddr> = Vec::new();
    for u in &ups {
        for a in u["answers"].as_array().into_iter().flatten() {
            if let Some(ip) = a.as_str().and_then(|s| s.rsplit(' ').next()).and_then(|s| s.parse::<IpAddr>().ok()) {
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
        }
    }
    let ranking: Vec<Value> = r
        .iprank
        .rank(&ips)
        .await
        .into_iter()
        .map(|(ip, l)| json!({ "ip": ip, "ok": l.ok, "ms": if l.ok { json!((l.ms * 10.0).round() / 10.0) } else { Value::Null } }))
        .collect();
    let cache = r.cache.lock().unwrap().peek(&crate::cache::Cache::key(qtype, name)).map(|e| {
        json!({
            "source": e.source, "cls": format!("{:?}", e.class).to_lowercase(),
            "expiresInSec": e.remaining(Instant::now()).round(),
            "answers": e.answers.iter().map(|a| format!("{} {} {}", a.rtype, a.name, rdata_text(&a.data))).collect::<Vec<_>>(),
        })
    });
    json!({
        "name": name, "type": qtype,
        "filter": filter.map(|v| json!({ "action": if v.block { "block" } else if v.allow { "allow" } else { "none" }, "rule": v.rule, "cat": v.category })),
        "upstreams": ups, "ranking": ranking, "cache": cache,
        "cdn": r.cdn().map(|c| ips.iter().map(|ip| json!({ "ip": ip, "cls": c.classify(*ip).map(|k| json!({ "provider": k.provider, "cls": k.cls.as_str() })) })).collect::<Vec<_>>()),
        "cdnDb": r.cdn().and_then(|c| c.domain(name)),
    })
}

fn rdata_text(d: &kuroshio_proto::RData) -> String {
    use kuroshio_proto::RData::*;
    match d {
        A(ip) => ip.to_string(),
        Aaaa(ip) => ip.to_string(),
        Name(n) => n.clone(),
        Mx(p, n) => format!("{p} {n}"),
        Soa { mname, minimum, .. } => format!("{mname} … {minimum}"),
        Srv {
            priority,
            weight,
            port,
            target,
        } => format!("{priority} {weight} {port} {target}"),
        Raw(b) => format!("<{} bytes>", b.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_and_host() {
        let q = parse_query("name=www.example.com&type=AAAA&x=a%20b+c&flag");
        assert_eq!(q["name"], "www.example.com");
        assert_eq!(q["x"], "a b c");
        assert_eq!(q["flag"], "");
        assert!(local_host(Some("127.0.0.1:8054")));
        assert!(local_host(Some("localhost")));
        assert!(local_host(Some("[::1]:8054")));
        assert!(local_host(None));
        assert!(!local_host(Some("evil.example.com:8054")), "DNS rebinding");
        assert!(!local_host(Some("192.168.1.1")));
        assert_eq!(qtype_num("https"), Some(65));
        assert_eq!(qtype_num("nope"), None);
    }

    #[test]
    fn actions_are_post_only_and_filenames_are_clean() {
        let none = HashMap::new();
        for p in [
            "/api/cache/flush",
            "/api/jobs/run",
            "/api/acme/issue",
            "/api/ddns/update",
            "/api/filter/update",
            "/api/cdn/verify",
            "/api/cdn/policy",
            "/api/cdn/ecs",
            "/api/community/add",
            "/api/community/accept",
            "/api/community/delete",
            "/api/community/rotate",
            "/api/community/accept-key",
            "/api/community/check",
            "/api/community/sync",
        ] {
            assert!(is_action(p, &none), "{p}");
        }
        for p in [
            "/api/status",
            "/api/trace",
            "/api/filter/check",
            "/api/cdn/domains",
            "/api/jobs",
            "/api/ddns",
            "/api/acme",
            "/api/community/status",
            "/api/community/peers",
            "/api/community/events",
            "/api/community/scores",
            "/api/community/channel",
        ] {
            assert!(!is_action(p, &none), "{p}");
        }
        assert!(is_action("/api/community/channel", &parse_query("domain=a.example&channel=doq")));
        // 查詢參數裡的換行不能進到 content-disposition
        let evil = parse_query("provider=x%0d%0aSet-Cookie:%20a=b");
        let name = safe_filename(&format!("cdn-domains-{}.csv", evil["provider"]));
        assert_eq!(name, "cdn-domains-x__Set-Cookie__a_b.csv");
        assert_eq!(safe_filename("kuroshio-full-20261111.kuroshio"), "kuroshio-full-20261111.kuroshio");
        assert_eq!(safe_filename("\"\r\n"), "___");
        assert_eq!(safe_filename(""), "download");
    }
}
