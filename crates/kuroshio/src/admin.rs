//! 管理 API（規格 02 第 6 節）：只聽 127.0.0.1，路徑與回應格式沿用 2.x，LuCI 經 rpcd 呼叫。
//!
//! 只是本機用的小型 HTTP/1.1 伺服器（一個請求一條連線），不需要完整的 HTTP 函式庫。
//! Host 標頭必須是本機名稱、IP 位址或 `admin.allowedHosts` 裡的名稱，防止 DNS rebinding 從瀏覽器打進來。

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

/// 查詢參數的開關：`1`、`true` 才算（`lite=1`、`history=1`）
fn flag(q: &HashMap<String, String>, k: &str) -> bool {
    matches!(q.get(k).map(String::as_str), Some("1" | "true"))
}

/// Host 標頭是不是本機（沒有 Host 的 HTTP/1.0 請求也算，uclient-fetch 會帶）
pub fn local_host(host: Option<&str>) -> bool {
    let Some(h) = host else { return true };
    let name = host_name(h);
    name.eq_ignore_ascii_case("localhost") || name.parse::<IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false)
}

/// Host 標頭裡的名稱（去掉埠號與 IPv6 的方括號）
fn host_name(h: &str) -> &str {
    let h = h.trim();
    if let Some(rest) = h.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        h.rsplit_once(':').map(|x| x.0).unwrap_or(h)
    }
}

/// 管理介面接受的 Host（3.4.2）：
/// - 本機名稱（localhost、127.0.0.1、::1），以及沒有 Host 的（指令列工具、rpcd）
/// - 任何 IP 位址：DNS rebinding 一定要透過網域名稱（攻擊者的網域改指到這台），直接用 IP 開的不會是這種攻擊。
///   管理介面聽在 0.0.0.0 時（Docker、NAS），區網其他電腦用這台的 IP 開才開得起來
/// - `admin.allowedHosts` 裡的名稱（例如反向代理或 NAS 的名稱 `nas.example.com`、`diskstation.local`），不分大小寫
pub fn host_allowed(host: Option<&str>, allowed: &[String]) -> bool {
    let Some(h) = host else { return true };
    let name = host_name(h);
    if name.is_empty() {
        return false;
    }
    // 結尾的點（完整網域名稱 `nas.example.com.`）跟 allowedHosts 一樣去掉再比：以前設定裡的會去掉、Host 的不會，
    // 用「名稱.」開永遠被擋，訊息還叫人把「名稱.」加進設定（加了也會被去掉）
    let bare = name.strip_suffix('.').unwrap_or(name);
    local_host(Some(h)) || name.parse::<IpAddr>().is_ok() || allowed.iter().any(|a| a.eq_ignore_ascii_case(bare))
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
        "/api/cache/flush"
        | "/api/jobs/run"
        | "/api/acme/issue"
        | "/api/ddns/update"
        | "/api/filter/update"
        | "/api/filter/reset-rules"
        | "/api/persist/flush"
        | "/api/memory/trim"
        | "/api/memory/simulate"
        | "/api/memory/restart"
        | "/api/cdn/verify"
        | "/api/cdn/policy"
        | "/api/cdn/ecs"
        | "/api/notify/wan-changed"
        | "/api/chain/recheck"
        | "/api/querylog/enable" => true,
        // 帶 date 是改標記（動作）；不帶是看目前標了哪些
        "/api/stats/exclude" => q.contains_key("date"),
        p => match p.strip_prefix("/api/community/") {
            Some("status" | "peers" | "events" | "scores" | "invite") => false,
            // 不帶 channel 是查詢，帶了是指定管道
            Some("channel") => q.contains_key("channel"),
            Some(_) => true,
            None => false,
        },
    }
}

/// `POST /api/memory/simulate?availMB=N&minutes=M`（`M` 1～30，預設 5）／`?off=1`（3.5.0 C9）：
/// 到期前記憶體控制讀到的系統可用記憶體 = min(真實值, N MB)。沒開 `system.testHooks` 時 403
/// `POST /api/memory/restart`（3.5.1 N1，要 `system.testHooks`）：馬上走一次「寫出快照、用同一個 PID 原地重新執行」
fn memory_restart(cfg: &Value) -> Response {
    if !crate::memgov::test_hooks(cfg) {
        return bad("測試開關沒有開：要在設定檔把 system.testHooks 設成 true（只給測試用）", 403);
    }
    if !cfg!(target_os = "linux") {
        return bad("原地重新啟動只有 Linux 有", 400);
    }
    let first = crate::memgov::request_restart("測試模式：應要求原地重新啟動（POST /api/memory/restart；system.testHooks）");
    ok(json!({ "ok": true, "requested": first }))
}

fn memory_simulate(cfg: &Value, q: &HashMap<String, String>, sim: &crate::memgov::SimState, now: u64) -> Response {
    if !crate::memgov::test_hooks(cfg) {
        return bad(
            "測試開關沒有開：記憶體模擬只給測試用，要在設定檔把 system.testHooks 設成 true（見 docs/spec/09-memory.md 第 11 節）",
            403,
        );
    }
    if q.get("off").is_some_and(|v| v != "0") {
        let was = sim.stop();
        if was {
            warn!("測試模式：記憶體模擬已取消，回到真實的量測");
        }
        return ok(json!({ "ok": true, "wasOn": was, "simulated": Value::Null }));
    }
    let Some(mb) = q.get("availMB").and_then(|v| v.trim().parse::<u64>().ok()) else {
        return bad("要給 availMB（模擬的系統可用記憶體，MB）", 400);
    };
    let minutes = match q.get("minutes") {
        Some(v) => match v.trim().parse::<u64>() {
            Ok(m) => m,
            Err(_) => return bad("minutes 要是 1～30 的整數", 400),
        },
        None => crate::memgov::SIM_DEFAULT_MINUTES,
    };
    let s = sim.start(mb, minutes, now);
    let minutes = (s.until - now) / 60;
    warn!(
        "測試模式：模擬可用記憶體 {} MB，{minutes} 分鐘後自動恢復（system.testHooks；只影響黑潮自己的判斷）",
        s.avail_mb
    );
    ok(json!({
        "ok": true,
        "minutes": minutes,
        "simulated": crate::memgov::simulation_json(Some(s), now),
    }))
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

/// 大檔匯入同時只收一個（沒有登入機制的平台上，本機任何程式都能送；不讓幾個 64 MB 同時進記憶體）
static IMPORT_SLOT: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

/// 這次匯入最多收多大：64 MB，但不超過目前可用記憶體的 1/4（解壓縮與合併還要再用到記憶體）
fn import_limit() -> usize {
    let avail = crate::sysinfo::mem_bytes().1.map_or(usize::MAX, |a| (a / 4) as usize);
    crate::backup::MAX_BYTES.min(avail.max(1 << 20))
}

/// 讀一個 HTTP/1.1 請求（標頭最多 16 KB、內容最多 1 MB；已登入的匯入備份最多 64 MB，同時只收一個）
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
    let mut _slot = None;
    let max = if req.path == IMPORT_PATH && req.method == "POST" && req.same_origin_with(&ui.allowed_hosts) && ui.authorized(&req) {
        deadline += Duration::from_secs(50);
        _slot = Some(IMPORT_SLOT.try_acquire().map_err(|_| anyhow::anyhow!("已經有一個匯入正在上傳"))?);
        let lim = import_limit();
        if len > lim {
            anyhow::bail!("檔案太大：目前可用記憶體只夠收 {} MB", lim >> 20);
        }
        lim
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
    let ui = &st.webui;
    if !host_allowed(req.header("host"), &ui.allowed_hosts) {
        let name = req.header("host").map(host_name).unwrap_or_default();
        return Out::from_response(bad(
            &format!("不接受用「{name}」這個名稱開管理介面：請改用 IP 位址開，或把 {name} 加到設定的 admin.allowedHosts"),
            403,
        ));
    }
    let m = req.method.as_str();
    let write = m == "POST" || m == "PUT";
    if write && !req.same_origin_with(&ui.allowed_hosts) {
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
            // 一次性登入碼（印給人點的網址）或 token（登入頁貼上、舊的網址）
            let good = q.get("code").is_some_and(|c| ui.take_login_code(c)) || q.get("token").is_some_and(|t| ui.check_token(t));
            match good {
                true => {
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
                // 一次性登入碼（`kuroshio url` 用 token 換一個，印出不含 token 的網址）
                ("POST", "/api/login-code") => match ui.new_login_code() {
                    Some(c) => Out::json(
                        200,
                        &json!({ "code": c, "path": format!("/login?code={c}"), "expiresIn": crate::webui::LOGIN_CODE_TTL.as_secs() }),
                    ),
                    None => Out::from_response(bad("這個平台不需要登入（admin.auth 關閉）", 404)),
                },
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
                    let mut q = parse_query(&req.query);
                    // 貼上邀請碼也可以放在 JSON 內容 {"code": "..."}（網址參數優先）
                    if m == "POST" && p == "/api/community/invite/use" && !q.contains_key("code") {
                        if let Some(c) = serde_json::from_slice::<Value>(&req.body)
                            .ok()
                            .and_then(|v| v["code"].as_str().map(String::from))
                        {
                            q.insert("code".into(), c);
                        }
                    }
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
        let mut effective = kuroshio_config::build(&user);
        // API Token 之類的密碼不送到瀏覽器：換成遮罩，存檔時遮罩 = 沒改
        let mut user = user;
        crate::webui::mask_secrets(&mut user);
        crate::webui::mask_secrets(&mut effective);
        return ok(json!({
            "file": file, "user": user,
            "effective": effective,
            "defaults": kuroshio_config::build(&json!({})),
            // 依 CPU 核心數換算的欄位（沒填 = auto）
            "auto": kuroshio_config::PER_CORE.iter().map(|x| x.0).chain(["resolver.parallel", "cdn.verifyPerMin"]).collect::<Vec<_>>(),
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
    // 解壓縮檢查與寫檔是同步的工作：放到 blocking 執行緒，不卡住其他請求
    let (loc, body) = (st.backup.clone(), req.body.clone());
    let preview = match tokio::task::spawn_blocking(move || crate::backup::stage_pending(&loc, &body)).await {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => return bad(&format!("{e:#}"), 400),
        Err(e) => return bad(&format!("{e}"), 500),
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
            let data = crate::manifest::check(&crate::app::share_dir(&st.cfg));
            let synced = crate::clock::synced();
            let access = r.access.get().map(|a| a.status_json()).unwrap_or(Value::Null);
            let mut warnings = crate::integration::warnings(&data, synced, crate::app::pressure(), &filter, &access);
            // 路徑檢查（3.3.6）：一般 DNS 被接走、協定被擋之類的狀況（串接中不列「被接走」那一條）
            warnings.extend(crate::pathcheck::warnings());
            // 串接（3.4.0）：上游節點的金鑰換過（24 小時內）
            if let Some(w) = crate::chain::current().and_then(|c| c.key_change_warning(crate::backup::now_ms())) {
                warnings.push(w);
            }
            let mut path = crate::pathcheck::status_json();
            if let Some(i) = path.get_mut("interceptor").filter(|i| i.is_object()) {
                i["chain"] = crate::chain::client::interceptor_api_json();
            }
            // `lite=1`（LuCI 的 rpcd、padavan 韌體每幾秒讀一次）：不回大的欄位（`perf`、`history`、`system.persist.files`；
            // 規格 11 C12、E9、F2）
            let lite = flag(q, "lite");
            // 線路感知（3.5.0 E3～E7）：`reach`、`popHealth`、`popSwitch`、`popAudit`、`slowerFuseUntil` 由 `status_lite()` 帶出
            // 3.5.0 F8、F12：`dbDiskKB`／`dbFileKB`／`cdnDirKB`、驗證節流 `pace`、背景工作 `bg` 也在 `status_lite()` 裡
            let cdn = r.cdn().map(|c| c.status_lite()).unwrap_or_else(|| json!({ "enabled": false }));
            let mut out = json!({
                "version": env!("CARGO_PKG_VERSION"),
                // 管理 API 的版本（docs/integration.md）：行為有不相容的改變才加 1
                "api": crate::integration::API_VERSION,
                // 執行方式：service（Windows 服務）/ cmd（前景）；uci = 設定來自 OpenWrt UCI
                "mode": st.webui.run_mode.get().copied().unwrap_or("cmd"),
                "uci": st.webui.config_file.get().is_none(),
                "clock": { "synced": synced, "buildEpoch": crate::clock::BUILD_EPOCH },
                "data": data.json(),
                "warnings": warnings,
                // 重新載入設定失敗時：原因，以及正在用上一份設定
                "reload": crate::integration::reload_json(),
                "stats": r.stats.summary(),
                "cacheEntries": cache_entries,
                "cacheBytes": cache_bytes,
                "errors": r.errors_json(),
                "ownIp": null,
                "upstreams": r.upstreams.list_json(),
                // 路徑檢查：IPv6、一般 DNS 有沒有被接走（被誰）、「不存在」被改寫、被擋的協定、TLS 攔截
                "network": { "path": path },
                // 串接模式（3.4.0，規格 1.10）：下游與上游兩種角色
                "chain": crate::chain::client::api_json(),
                // source：chain（上游黑潮給的）／benchmark（自己評測的）
                "autoUpstreams": crate::chain::share::auto_info(&r.upstreams),
                "filter": filter,
                // CDN 關掉時給 `{"enabled": false}`，不是 null（3.5.0；D3 3.4.3 回報 null 看不出是關掉還是讀不到）
                "cdn": cdn,
                "jobs": st.scheduler.as_ref().map(|s| s.status()),
                "system": st.system_json(),
                // 記憶體控制（規格 09）：狀態、預算、釋出中的項目（system.memory 是同一份）
                "memory": st.memory_json(),
                "listeners": {
                    "doh": st.encrypted.doh.map(|a| a.port()), "doh3": st.encrypted.doh3.map(|a| a.port()),
                    "dot": st.encrypted.dot.map(|a| a.port()), "doq": st.encrypted.doq.map(|a| a.port()),
                    "ddr": st.resolver.ddr.read().unwrap().is_some(),
                },
                "listenersDetail": st.encrypted.detail_json(),
                "dohMode": st.encrypted.doh_mode,
                "doh3Provider": st.encrypted.doh3_provider,
                "access": access,
                // 效能計數器（3.5.0）：加密上游的握手（完整／續用、AES／ChaCha）、每次詢問送出幾個上游查詢
                "perf": crate::resolver::perf::json(),
                // 查詢紀錄只放狀態（開著嗎、到幾點），內容要另外用 /api/querylog 讀
                "queryLog": r.querylog.status(crate::querylog::now()),
                // 通訊類網域（3.5.0）：內建與自己加的後綴數、預取中的數量（被清單擋到又放行的次數在 filter.commSpared）
                "comm": {
                    "builtin": kuroshio_net::comm::COMM_SUFFIXES.len(), "user": kuroshio_net::comm::user_count(),
                    "prefetching": r.comm_prefetching(),
                    // 3.5.0 F11：內建表每一類幾個後綴；新加的五類有沒有在比對（filter.protectComm）
                    "kinds": kuroshio_net::comm::builtin_kinds()
                        .into_iter()
                        .map(|(k, n)| (k.to_string(), json!(n)))
                        .collect::<serde_json::Map<String, Value>>(),
                    "essential": kuroshio_net::comm::enabled(),
                },
                // 3.5.0 E1：每一種會過期的資料的上次成功、失敗中、下次預定
                "freshness": crate::observe::freshness(st),
                // 3.5.0 E2：觀察到的現象與它的經過（`warnings` 照舊、不重複放）
                "findings": crate::observe::findings(st),
                // 3.5.0 E8：過期快取的比率（今天、最近 15 分鐘、最近 1 小時）
                "stale": r.stats.stale_rates(),
            });
            if lite {
                if let Some(o) = out.as_object_mut() {
                    o.remove("perf");
                }
                // 3.5.0 F2（D32）：每個快照檔一筆的 `system.persist.files` 不帶（D3 上 37 KB），`filesSummary` 照帶
                if let Some(p) = out.pointer_mut("/system/persist").and_then(Value::as_object_mut) {
                    p.remove("files");
                }
            } else if flag(q, "history") {
                // 3.5.0 E9：24 小時歷史（約 6 KB，要明確要求才給）
                out["history"] = r.stats.history_json();
            }
            ok(out)
        }
        // 來源 IP 存取控制（規格 08）；?ip= 說明這個 IP 的判斷結果
        "/api/access" => match (r.access.get(), q.get("ip")) {
            (None, _) => ok(json!({ "mode": "open", "active": false })),
            (Some(a), None) => ok(a.api_json()),
            (Some(a), Some(ip)) => match ip.trim().parse::<std::net::IpAddr>() {
                Ok(ip) => ok(a.check_json(ip)),
                Err(_) => bad("IP 格式錯誤", 400),
            },
        },
        "/api/upstreams" => ok(r.upstreams.list_json()),
        // 串接模式（3.4.0）：同 /api/status 的 chain；recheck = 立刻做一次路徑檢查與探測（背景進行）
        "/api/chain" => ok(crate::chain::client::api_json()),
        // 查詢紀錄（3.5.0）：只在記憶體、預設關閉；`limit` 最多 1,000，`name`（包含這段）、`client`、`since`（毫秒）可以篩選
        "/api/querylog" => {
            let now = crate::querylog::now();
            let limit = q.get("limit").and_then(|v| v.parse().ok()).unwrap_or(200);
            let client = q.get("client").and_then(|v| v.parse().ok());
            let since = q.get("since").and_then(|v| v.parse::<u64>().ok()).map(|ms| (ms / 1000) as u32);
            ok(r.querylog.read(now, limit, q.get("name").map(String::as_str), client, since))
        }
        // 暫時開啟 minutes 分鐘（1～60，預設 10）；minutes=0 關閉暫時開啟
        "/api/querylog/enable" => {
            let now = crate::querylog::now();
            let m = q.get("minutes").and_then(|v| v.parse().ok()).unwrap_or(10);
            r.querylog.enable_for(m, now);
            ok(r.querylog.status(now))
        }
        "/api/chain/recheck" => {
            if !crate::pathcheck::enabled() {
                return bad("路徑檢查關閉（upstream.pathCheck）：串接沒有偵測來源", 400);
            }
            tokio::spawn(async {
                crate::pathcheck::run_once().await;
            });
            ok(json!({ "ok": true, "started": true }))
        }
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
            // 手動的排到佇列最前面，不等補跑的長工作（3.5.0）
            (Some(s), Some(n)) => ok(s.request_priority(n, "手動 (管理介面)")),
        },
        // 規格 02 第 6 節
        "/api/defaults" => ok(kuroshio_config::build(&json!({}))),
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
        // `kuroshio notify wan-changed`：WAN 變了（重新撥號、換 IP）。DDNS 立即檢查、重新偵測 ECS 用的對外 IP；
        // 都在背景做，立刻回應（熱插拔腳本不用等）
        "/api/notify/wan-changed" => {
            info!("收到通知：WAN 變動，立即檢查 DDNS、重新偵測對外 IP");
            let ddns = match &st.ddns {
                Some(d) => {
                    let d = d.clone();
                    tokio::spawn(async move {
                        d.update(true).await;
                    });
                    "started"
                }
                None => "disabled",
            };
            // 線路感知（3.5.0 E3）：wanEpoch 加 1、reach 標成過期、清掉機房切換的連續計數與暫緩（不補跑健檢或掃描）
            if let Some(c) = r.cdn() {
                c.on_wan_changed();
            }
            crate::app::spawn_wan_subnet(r.clone(), 0, true);
            // 串接（3.4.0）：立刻拿掉串接上游，接著的路徑檢查重新偵測、自動接回
            let chain = match crate::chain::current() {
                Some(c) if c.state().0 != crate::chain::client::State::None => {
                    c.on_wan_changed();
                    "released"
                }
                _ => "none",
            };
            crate::pathcheck::trigger();
            ok(
                json!({ "ok": true, "ddns": ddns, "ecs": "started", "pathCheck": "started", "clockSynced": crate::clock::synced(), "chain": chain }),
            )
        }
        // 立即更新過濾清單（API 2：背景執行）：立刻回 `{started, running, runId, startedAt}`，
        // 進度與結果看 `/api/status` 的 `filter.update`。正在跑時再呼叫一次，回 `started: false` 與同一個 runId。
        // `?wait=1`：等到這一次結束才回，多了 `changed`（舊的行為，給腳本用）
        "/api/filter/update" => match &st.filter {
            None => bad("過濾未啟用", 400),
            Some(f) => {
                let (started, run) = f.start_update();
                if matches!(q.get("wait").map(String::as_str), Some("1" | "true")) {
                    let done = f.wait_update(run.run_id).await;
                    return match &done.error {
                        Some(e) if done.run_id == run.run_id => bad(e, 500),
                        _ => ok(json!({
                            "changed": done.changed.unwrap_or(false), "runId": run.run_id, "started": started,
                            "update": done.json(),
                        })),
                    };
                }
                ok(json!({
                    "started": started, "running": true, "runId": run.run_id, "startedAt": run.started_at,
                    "update": run.json(),
                }))
            }
        },
        // 恢復預設自訂規則：原本的內容先備份成 <檔名>.bak，寫入這個版本的預設規則，立刻重新載入
        "/api/filter/reset-rules" => {
            let Some(file) = crate::backup::Locations::from_cfg(&st.cfg).custom_rules else {
                return bad("設定裡沒有自訂規則檔（filter.customRules）", 400);
            };
            let share = crate::app::share_dir(&st.cfg);
            match tokio::task::spawn_blocking(move || crate::filtering::reset_custom_rules(&file, &share)).await {
                Ok(Ok(mut v)) => {
                    let reloaded = st.filter.as_ref().map(|f| f.reload_custom(true));
                    v["reloaded"] = json!(reloaded.unwrap_or(false));
                    ok(v)
                }
                Ok(Err(e)) => bad(&format!("恢復預設自訂規則失敗：{e}"), 500),
                Err(e) => bad(&format!("恢復預設自訂規則失敗：{e}"), 500),
            }
        }
        // 先讓出記憶體（`kuroshio notify trim`）：韌體要做很佔記憶體的事之前呼叫；`holdSec` 秒內不長大、不恢復
        "/api/memory/trim" => {
            let hold = q
                .get("holdSec")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(crate::memgov::TRIM_HOLD_DEFAULT);
            match &st.memgov {
                Some(g) => ok(g.trim(hold, crate::memgov::steady_secs()).await),
                None => {
                    crate::sysinfo::trim_heap();
                    ok(json!({ "ok": true, "enabled": false, "steps": [], "freedBytes": 0, "holdSec": 0 }))
                }
            }
        }
        // 測試開關（3.5.0 C9）：模擬記憶體不足。要設定 `system.testHooks: true` 才接受，最長 30 分鐘、到期自動恢復
        "/api/memory/simulate" => memory_simulate(&st.cfg, q, &crate::memgov::SIM, crate::memgov::steady_secs()),
        // 3.5.1 N1：原地重新啟動的測試開關（記憶體控制判斷回不來時會自己做；這裡只給測試用）
        "/api/memory/restart" => memory_restart(&st.cfg),
        // 立即儲存學習資料：有變動的快照全部寫進快照目錄（Windows 沒有 SIGUSR1，就靠這個或 `kuroshio notify save`）
        "/api/persist/flush" => {
            let s2 = st.clone();
            match tokio::task::spawn_blocking(move || s2.flush_counted()).await {
                Ok(Ok((files, bytes))) => {
                    let at = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0);
                    info!("手動儲存學習資料：寫了 {files} 份快照（{bytes} bytes）");
                    ok(json!({ "ok": true, "files": files, "bytes": bytes, "at": at, "dir": st.persist_dir }))
                }
                Ok(Err(e)) => bad(&format!("寫入快照失敗：{e}"), 500),
                Err(e) => bad(&format!("寫入快照失敗：{e}"), 500),
            }
        }
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
        // 把某一天標成「異常、不計入公開頁的 7 天／30 天統計」（3.5.1，例如壓測那天）：`date=YYYY-MM-DD`、`on=0` 取消。
        // 只能標還保留著的日子（最多 31 天），跟著每日紀錄存進 stats.json（POST）；不帶 date 是看目前標了哪些
        "/api/stats/exclude" => {
            let list = |r: &crate::resolver::Resolver| json!({ "excluded": r.stats.excluded_days() });
            let Some(date) = q.get("date") else {
                return ok(list(r));
            };
            if date.len() != 10 {
                return bad("date 要是 YYYY-MM-DD", 400);
            }
            let on = !matches!(q.get("on").map(String::as_str), Some("0" | "false"));
            match r.stats.set_excluded(date, on) {
                Some(was) => {
                    if was != on {
                        info!(
                            "統計：{date} {}",
                            if on {
                                "標成異常、不計入期間統計"
                            } else {
                                "取消異常標記"
                            }
                        );
                    }
                    let mut v = list(r);
                    v["date"] = json!(date);
                    v["changed"] = json!(was != on);
                    ok(v)
                }
                None => bad("沒有這一天的統計（只保留最近 31 天）", 404),
            }
        }
        // 儀表板（LuCI、Windows 設定頁）：跟公開頁同一份統計，但排行不受 site.minClients 限制、列得比較多
        "/api/dashboard" => ok(crate::site::dashboard_stats(
            st,
            q.get("range").map(String::as_str).unwrap_or("today"),
            1,
            crate::site::ADMIN_TOP,
            crate::site::View::Admin,
        )),
        // 「為什麼沒換到台灣」（3.5.0）：只讀；CDN 沒開時也回答（說明沒開）
        "/api/cdn/explain" => {
            let Some(n) = q.get("name").map(|n| normalize(n)).filter(|n| !n.is_empty()) else {
                return bad("需要 name", 400);
            };
            let ctx = kuroshio_cdn::explain::Context {
                chained: r.chain_active(),
                suspended: r.cdn_suspended.load(std::sync::atomic::Ordering::Relaxed),
            };
            match r.cdn() {
                Some(c) => ok(c.explain(&n, ctx)),
                None => {
                    ok(json!({ "name": n, "decision": "cdn-disabled", "text": kuroshio_cdn::explain::text_of("cdn-disabled", "", "") }))
                }
            }
        }
        p if p.starts_with("/api/cdn/") => match r.cdn() {
            None => bad("CDN 台灣節點沒有啟用", 404),
            Some(c) => cdn_route(&c, p, q).await,
        },
        p if p.starts_with("/api/community/") => match &st.community {
            None => bad("社群共享沒有啟用", 404),
            Some(c) => match c.admin(p, q).await {
                // 邀請碼另外附 QR 碼（SVG，跟關於頁同一個產生器）
                Some(mut v) if matches!(p, "/api/community/invite" | "/api/community/invite/refresh") => {
                    if let Some(code) = v["code"].as_str() {
                        v["qr"] = json!(crate::about::qr_svg(code));
                    }
                    ok(v)
                }
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
                search: q.get("q").map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty()),
                offset: q.get("offset").and_then(|o| o.parse().ok()).unwrap_or(0),
                cross: q.get("cross").map(String::as_str) == Some("1"),
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
            match c.verify_now_speed(&n, fam).await {
                // 3.5.0 F9：這一次驗證的握手判斷（`score`、`origScore`、`weighted`、`slower`、`state`、`confirmAfter`）
                // 只放在回應裡、不存檔；沒有判（IPv6、最近節點型、手動「一定換」、量不到握手…）是 null
                Some((err, v, speed)) => ok(json!({ "result": v, "error": err, "entry": c.domain(&n), "speed": speed })),
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
/// 追蹤結果裡，被攔截的一般 DNS 的說明
const INTERCEPTED_NOTE: &str = "被閘道接走：一般 DNS 在路上被路由器（或更上游的設備）攔下，回答的其實是攔截者，不是這個位址";

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
            let mut v = match res.ok().and_then(|b| Message::parse(&b).ok()) {
                Some(m) => json!({
                    "id": u.up.id, "role": u.role.name(), "ms": ms, "rcode": m.rcode,
                    "cls": format!("{:?}", kuroshio_proto::logic::classify(&m, qtype)).to_lowercase(),
                    "answers": m.answers.iter().map(|a| format!("{} {} {} {}", a.rtype, a.name, a.ttl, rdata_text(&a.data))).collect::<Vec<_>>(),
                }),
                None => json!({ "id": u.up.id, "role": u.role.name(), "ms": ms, "error": "沒有回應或格式錯誤" }),
            };
            // 一般 DNS 被路上的攔截者接走（路徑檢查）：回答的其實是攔截者，不是這個位址（3.5.0；D3 3.4.2 回報）
            v["viaInterceptor"] = json!(u.via_interceptor());
            if u.via_interceptor() {
                v["note"] = json!(INTERCEPTED_NOTE);
            }
            v
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

    /// 3.5.0 F9：`POST /api/cdn/verify` 的回應最上層帶這一次的握手判斷（`speed`）；CDN 那一層的規則在
    /// `kuroshio-cdn` 的 `manual_verify_reports_speed_and_follows_same_rules`，這裡只看主程式有沒有接上
    #[tokio::test]
    async fn cdn_verify_reports_speed() {
        use crate::cdntest::{cdn, cf_page, ip, node};
        const SITE: &str = "slow.example.com";
        const ORIG: &str = "198.51.100.200";
        let (c, net) = cdn("admin-verify", json!({}));
        c.with_state(|st| {
            *st.pools.p.get_mut("cloudflare").unwrap().pool_mut(4) =
                vec![node("192.0.2.1", "TPE", 3.0, false), node("198.51.100.1", "TPE", 4.0, false)];
            st.db.touch(SITE, "cloudflare", "ip", &[ip(ORIG)], &[], None);
        });
        {
            let mut h = net.https.lock().unwrap();
            h.insert(ip(ORIG), cf_page("NRT", 100.0));
            h.insert(ip("192.0.2.1"), cf_page("TPE", 250.0));
            h.insert(ip("198.51.100.1"), cf_page("TPE", 250.0));
        }
        let q: HashMap<String, String> = [("name".to_string(), SITE.to_string())].into_iter().collect();
        let r = cdn_route(&c, "/api/cdn/verify", &q).await;
        assert_eq!(r.code, 200, "{}", r.body);
        assert_eq!(r.body["error"], "ok", "{}", r.body);
        let s = &r.body["speed"];
        assert_eq!(s["state"], "slow1", "{}", r.body);
        assert_eq!((s["score"].as_f64(), s["origScore"].as_f64()), (Some(250.0), Some(100.0)));
        assert_eq!(s["slower"], true);
        assert!(s["confirmAfter"].as_u64().unwrap() > 0);
        assert!(r.body["result"].get("speed").is_none(), "只放在最上層");
        assert!(r.body["entry"].is_object());
        // IPv6：不判，speed 是 null
        let q6: HashMap<String, String> = [("name".to_string(), SITE.to_string()), ("family".to_string(), "6".to_string())]
            .into_iter()
            .collect();
        let r = cdn_route(&c, "/api/cdn/verify", &q6).await;
        assert!(r.body["speed"].is_null(), "{}", r.body);
        // 資料庫裡沒有的網域
        let qx: HashMap<String, String> = [("name".to_string(), "none.example.com".to_string())].into_iter().collect();
        assert_eq!(cdn_route(&c, "/api/cdn/verify", &qx).await.code, 404);
    }

    /// LuCI 的 API 白名單（openwrt/kuroshio/files/rpcd.sh）：唯讀那一段（`api`）的路徑都不能是會改變狀態的，
    /// 動作那一段（`action`，用 POST）都要是會改變狀態的（3.5.0，規格 11 C13）
    #[test]
    fn rpcd_whitelists_match_actions() {
        let sh = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../openwrt/kuroshio/files/rpcd.sh")).unwrap();
        let section = |name: &str| -> Vec<String> {
            let start = sh.find(&format!("\t{name})\n")).unwrap_or_else(|| panic!("rpcd.sh 沒有 {name})"));
            let body = &sh[start..];
            let end = body.find("*) echo").unwrap();
            body[..end]
                .lines()
                .filter_map(|l| l.trim().strip_suffix(") ;;"))
                .flat_map(|l| l.split('|').map(str::to_string).collect::<Vec<_>>())
                .filter(|p| p.starts_with("/api/"))
                .collect()
        };
        let q: HashMap<String, String> = [("channel".to_string(), "x".to_string())].into_iter().collect();
        let empty = HashMap::new();
        let read = section("api");
        let act = section("action");
        assert!(read.iter().any(|p| p == "/api/chain"), "LuCI 讀得到串接狀態");
        assert!(act.iter().any(|p| p == "/api/chain/recheck"), "LuCI 可以重新檢查串接");
        for p in &read {
            assert!(!is_action(p, &empty), "{p} 會改變狀態，不能放在唯讀白名單");
        }
        for p in &act {
            assert!(is_action(p, &q), "{p} 不會改變狀態，不必放在動作白名單（要用 POST 的才放）");
        }
    }

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
    }

    /// 3.4.2：管理介面聽在 0.0.0.0（Docker、NAS）時，區網用 IP 開要開得起來；網域名稱只接受 allowedHosts 裡的
    #[test]
    fn host_allow_policy() {
        let none: Vec<String> = Vec::new();
        assert!(host_allowed(Some("127.0.0.1:8054"), &none));
        assert!(host_allowed(None, &none));
        assert!(host_allowed(Some("192.168.1.2:8054"), &none), "IP 位址：不會是 DNS rebinding");
        assert!(host_allowed(Some("[2001:db8::2]:8054"), &none));
        assert!(!host_allowed(Some("evil.example.com:8054"), &none), "DNS rebinding");
        assert!(!host_allowed(Some(""), &none));
        let allowed = vec!["nas.example.com".to_string()];
        assert!(host_allowed(Some("NAS.example.com:8054"), &allowed));
        assert!(!host_allowed(Some("nas.example.com.evil.example:8054"), &allowed));
        assert!(host_allowed(Some("nas.example.com.:8054"), &allowed), "結尾的點跟設定一樣去掉");
        assert_eq!(qtype_num("https"), Some(65));
        assert_eq!(qtype_num("nope"), None);
    }

    /// 3.5.0 C9：沒開 `system.testHooks` 時 403、不改任何狀態；開了才接受
    #[test]
    fn simulate_requires_test_hooks() {
        let sim = crate::memgov::SimState::new();
        let now = 2_000_000_000;
        let off = kuroshio_config::with_overrides(&json!({}));
        let on = kuroshio_config::with_overrides(&json!({ "system": { "testHooks": true } }));
        let q = parse_query("availMB=20&minutes=5");
        let r = memory_simulate(&off, &q, &sim, now);
        assert_eq!(r.code, 403);
        assert!(r.body["error"].as_str().unwrap().contains("system.testHooks"));
        assert!(sim.get(now).is_none(), "沒開：不生效");
        // 字串 "true" 不算（只認布林）
        let s = kuroshio_config::with_overrides(&json!({ "system": { "testHooks": "true" } }));
        assert_eq!(memory_simulate(&s, &q, &sim, now).code, 403);
        // 開了：生效
        let r = memory_simulate(&on, &q, &sim, now);
        assert_eq!(r.code, 200);
        assert_eq!(r.body["minutes"], 5);
        assert_eq!(r.body["simulated"]["availMB"], 20);
        assert_eq!(sim.get(now).unwrap().avail_mb, 20);
        // 參數錯
        assert_eq!(memory_simulate(&on, &parse_query("minutes=5"), &sim, now).code, 400);
        assert_eq!(memory_simulate(&on, &parse_query("availMB=20&minutes=x"), &sim, now).code, 400);
        // 最長 30 分鐘、最短 1 分鐘
        let r = memory_simulate(&on, &parse_query("availMB=20&minutes=999"), &sim, now);
        assert_eq!(r.body["minutes"], 30);
        assert_eq!(
            memory_simulate(&on, &parse_query("availMB=20&minutes=0"), &sim, now).body["minutes"],
            1
        );
        // 取消（沒開 testHooks 也不能取消：同一道保險；到期本來就會自己恢復）
        assert_eq!(memory_simulate(&off, &parse_query("off=1"), &sim, now).code, 403);
        let r = memory_simulate(&on, &parse_query("off=1"), &sim, now);
        assert_eq!((r.code, r.body["wasOn"].clone()), (200, json!(true)));
        assert!(sim.get(now).is_none());
        assert_eq!(memory_simulate(&on, &parse_query("off=1"), &sim, now).body["wasOn"], false);
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
            "/api/filter/reset-rules",
            "/api/persist/flush",
            "/api/memory/trim",
            "/api/memory/simulate",
            "/api/cdn/verify",
            "/api/cdn/policy",
            "/api/cdn/ecs",
            "/api/notify/wan-changed",
            "/api/chain/recheck",
            "/api/querylog/enable",
            "/api/community/add",
            "/api/community/accept",
            "/api/community/delete",
            "/api/community/rotate",
            "/api/community/accept-key",
            "/api/community/check",
            "/api/community/sync",
            "/api/community/invite/refresh",
            "/api/community/invite/use",
        ] {
            assert!(is_action(p, &none), "{p}");
        }
        for p in [
            "/api/status",
            "/api/chain",
            "/api/querylog",
            "/api/cdn/explain",
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
            "/api/community/invite",
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
