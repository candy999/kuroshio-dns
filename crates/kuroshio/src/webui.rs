//! Windows 本機設定頁（規格 02 第 6、7.2 節、規格 07）
//!
//! - 只聽 127.0.0.1（管理 API 同一個埠）；Host 必須是本機名稱（防 DNS rebinding）
//! - 登入：一次性 token（`admin.token`，第一次啟動時產生，只有系統管理員可讀的資料夾）→
//!   HttpOnly、SameSite=Strict 的 cookie；腳本也可以用 `Authorization: Bearer <token>`
//! - 會改東西的請求（POST / PUT）檢查 Origin 必須是本機
//! - `admin.auth`：`auto`（預設：Windows 開、OpenWrt 關——OpenWrt 由 rpcd 代理，只聽本機）/ true / false
//! - 靜態檔：`<share>/admin/`（index.html、app.js、style.css、fields.json）
//! - `/api/config`（只有用 JSON 設定檔時）：GET 讀、PUT 整份寫入後重新載入；`/api/log`：最近的日誌

use kuroshio_config::get;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tracing::{info, warn};

pub const COOKIE: &str = "kuroshio_session";
const MAX_SESSIONS: usize = 32;
/// 登入後多久要重新登入
const SESSION_TTL: Duration = Duration::from_secs(30 * 86400);
/// 密碼類欄位送到瀏覽器時的遮罩；存檔時收到這個值 = 沒改
pub const SECRET_MASK: &str = "********";

/// session id → 登入時間
type Sessions = Arc<Mutex<HashMap<String, Instant>>>;

/// 設定頁的狀態
pub struct WebUi {
    /// None = 不需要登入
    token: Option<String>,
    pub token_file: Option<PathBuf>,
    sessions: Sessions,
    pub static_dir: PathBuf,
    /// 共用儀表板（dashboard.js、dashboard.css）：設定頁用 `/dashboard/<檔名>` 載入
    pub dashboard_dir: PathBuf,
    /// 用 JSON 設定檔執行時的路徑（UCI 時沒有：設定走 LuCI）
    pub config_file: OnceLock<PathBuf>,
    /// 執行方式（cmd / 服務），給設定頁顯示
    pub run_mode: OnceLock<&'static str>,
    /// 版本、授權、原始碼網址
    pub about: Value,
}

/// 登入的 session 依 token 放在整個程式共用的地方：設定頁存檔後重新載入（WebUi 重建）
/// 不用重新登入；token 換了就是另一組，舊的 session 自然失效
fn session_store(token: &str) -> Sessions {
    static STORES: Mutex<BTreeMap<String, Sessions>> = Mutex::new(BTreeMap::new());
    let mut all = STORES.lock().unwrap();
    // token 換過很多次時不留一堆舊的（舊 token 的 session 本來就該失效）
    if all.len() >= 8 && !all.contains_key(token) {
        all.clear();
    }
    all.entry(token.to_string()).or_default().clone()
}

/// 這個設定欄位是不是密碼（API Token…）。`tokenFile` 之類的是路徑，不算
fn is_secret_key(k: &str) -> bool {
    let k = k.to_ascii_lowercase();
    k.ends_with("token") || k.ends_with("password") || k.ends_with("secret") || k == "apikey"
}

/// 設定裡的密碼欄位（有填的）換成遮罩，送到瀏覽器前呼叫
pub fn mask_secrets(v: &mut Value) {
    match v {
        Value::Object(o) => {
            for (k, x) in o.iter_mut() {
                match x {
                    Value::String(s) if is_secret_key(k) => {
                        if !s.is_empty() {
                            *s = SECRET_MASK.to_string();
                        }
                    }
                    _ => mask_secrets(x),
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(mask_secrets),
        _ => {}
    }
}

/// 存檔時：密碼欄位收到遮罩 = 沒改，換回 `old`（目前的設定檔）同一個位置的值；原本沒有就拿掉
pub fn unmask_secrets(v: &mut Value, old: &Value) {
    match v {
        Value::Object(o) => {
            let mut drop = Vec::new();
            for (k, x) in o.iter_mut() {
                let prev = old.get(k.as_str());
                match x {
                    Value::String(s) if is_secret_key(k) => {
                        if s == SECRET_MASK {
                            match prev.and_then(Value::as_str) {
                                Some(p) => *s = p.to_string(),
                                None => drop.push(k.clone()),
                            }
                        }
                    }
                    _ => unmask_secrets(x, prev.unwrap_or(&Value::Null)),
                }
            }
            for k in drop {
                o.remove(&k);
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter_mut().enumerate() {
                unmask_secrets(x, old.get(i).unwrap_or(&Value::Null));
            }
        }
        _ => {}
    }
}

/// token 檔只給擁有者（與系統管理員）讀。
///
/// Unix：`write_atomic` 已經用 0600 建立；舊版留下的檔案在這裡收緊。
/// Windows：`%ProgramData%\kuroshio` 預設讓這台電腦的所有使用者都能讀，一般使用者讀到 token 就能改
/// 以 SYSTEM 身分執行的服務的設定。用系統內建的 icacls 拿掉繼承的權限，只留 SYSTEM、Administrators 與檔案擁有者。
fn restrict_token_file(f: &std::path::Path) {
    static DONE: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
    {
        let mut done = DONE.lock().unwrap();
        if done.iter().any(|p| p == f) {
            return;
        }
        done.push(f.to_path_buf());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(m) = std::fs::metadata(f) {
            if m.permissions().mode() & 0o077 != 0 {
                match std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o600)) {
                    Ok(()) => info!("設定頁 token {} 原本其他帳號也能讀，已改成只有擁有者能讀", f.display()),
                    Err(e) => warn!("無法收緊 {} 的權限：{e}", f.display()),
                }
            }
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use std::process::{Command, Stdio};
        // S-1-5-18 = SYSTEM、S-1-5-32-544 = Administrators、S-1-3-4 = 檔案擁有者（一般權限用 cmd 執行時就是那位使用者）
        let r = Command::new("icacls")
            .arg(f)
            .args(["/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F", "*S-1-3-4:F"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
            .status();
        match r {
            Ok(st) if st.success() => {}
            Ok(st) => warn!(
                "無法收緊 {} 的權限（icacls 結束碼 {:?}）：這台電腦的其他使用者可能讀得到登入 token",
                f.display(),
                st.code()
            ),
            Err(e) => warn!("無法收緊 {} 的權限（{e}）：這台電腦的其他使用者可能讀得到登入 token", f.display()),
        }
    }
}

/// 隨機十六進位字串（作業系統亂數）
pub fn random_hex(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    if getrandom(&mut b).is_err() {
        // 不應該發生；退而求其次用時間與位址混合
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
            ^ (&b as *const _ as u128);
        for (i, x) in b.iter_mut().enumerate() {
            *x = (seed >> ((i % 16) * 8)) as u8 ^ (i as u8).wrapping_mul(151);
        }
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn getrandom(b: &mut [u8]) -> Result<(), ()> {
    use rustls::crypto::ring::default_provider;
    default_provider().secure_random.fill(b).map_err(|_| ())
}

/// 固定時間比較（token 不讓時間差洩漏）
fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// 設定頁要不要登入；要的話 token 檔在哪裡（`admin.auth`、`admin.tokenFile`）
pub fn token_file(cfg: &Value, base_dir: &std::path::Path) -> Option<PathBuf> {
    let auth = match get(cfg, "admin.auth") {
        Some(Value::Bool(b)) => *b,
        _ => cfg!(windows),
    };
    auth.then(
        || match get(cfg, "admin.tokenFile").and_then(Value::as_str).filter(|s| !s.is_empty()) {
            Some(p) => PathBuf::from(p),
            None => base_dir.join("admin.token"),
        },
    )
}

impl WebUi {
    pub fn new(cfg: &Value, base_dir: &std::path::Path, share_dir: &std::path::Path) -> WebUi {
        let token_file = token_file(cfg, base_dir);
        let token = token_file
            .as_ref()
            .map(|f| match std::fs::read_to_string(f).map(|t| t.trim().to_string()) {
                Ok(t) if t.len() >= 16 => t,
                _ => {
                    let t = random_hex(24);
                    if let Err(e) = crate::persist::write_atomic(f, format!("{t}\n").as_bytes()) {
                        warn!("無法寫入設定頁 token {}：{e}", f.display());
                    } else {
                        info!("已產生設定頁登入 token：{}", f.display());
                    }
                    t
                }
            });
        if let Some(f) = token_file.as_ref().filter(|f| f.exists()) {
            restrict_token_file(f);
        }
        let static_dir = get(cfg, "admin.webDir")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| share_dir.join("admin"));
        let sessions = token.as_deref().map(session_store).unwrap_or_default();
        // 設定頁資料夾旁邊的 dashboard/（開發時 admin.webDir 指到原始碼的 data/admin），沒有再用 share/dashboard
        let dashboard_dir = static_dir
            .parent()
            .map(|p| p.join("dashboard"))
            .filter(|d| d.is_dir())
            .unwrap_or_else(|| share_dir.join("dashboard"));
        WebUi {
            token,
            token_file,
            sessions,
            static_dir,
            dashboard_dir,
            config_file: OnceLock::new(),
            run_mode: OnceLock::new(),
            about: crate::about::json(cfg),
        }
    }

    /// 不啟動服務、也不產生 token，只看目前的 token 與它的檔案位置（`kuroshio url` 用）：(token, 檔案)
    pub fn peek(cfg: &Value, base_dir: &std::path::Path) -> (Option<String>, Option<PathBuf>) {
        let auth = match get(cfg, "admin.auth") {
            Some(Value::Bool(b)) => *b,
            _ => cfg!(windows),
        };
        if !auth {
            return (None, None);
        }
        let file = match get(cfg, "admin.tokenFile").and_then(Value::as_str).filter(|s| !s.is_empty()) {
            Some(p) => PathBuf::from(p),
            None => base_dir.join("admin.token"),
        };
        let token = std::fs::read_to_string(&file)
            .ok()
            .map(|t| t.trim().to_string())
            .filter(|t| t.len() >= 16);
        (token, Some(file))
    }

    pub fn auth_enabled(&self) -> bool {
        self.token.is_some()
    }

    /// 登入用網址（指令列 `kuroshio admin-url`、cmd 啟動時顯示）
    pub fn login_url(&self, port: u16) -> String {
        match &self.token {
            Some(t) => format!("http://127.0.0.1:{port}/login?token={t}"),
            None => format!("http://127.0.0.1:{port}/"),
        }
    }

    pub fn check_token(&self, t: &str) -> bool {
        self.token.as_deref().is_some_and(|tok| ct_eq(tok, t.trim()))
    }

    /// 登入成功：發一個 session
    pub fn new_session(&self) -> String {
        let id = random_hex(24);
        let now = Instant::now();
        let mut s = self.sessions.lock().unwrap();
        s.retain(|_, at| now.duration_since(*at) < SESSION_TTL);
        // 滿了就擠掉最舊的一個（不是全部清掉，其他分頁不會突然被登出）
        while s.len() >= MAX_SESSIONS {
            let Some(oldest) = s.iter().min_by_key(|(_, at)| **at).map(|(k, _)| k.clone()) else {
                break;
            };
            s.remove(&oldest);
        }
        s.insert(id.clone(), now);
        id
    }

    pub fn logout(&self, id: &str) {
        self.sessions.lock().unwrap().remove(id);
    }

    /// 這個請求有沒有登入（cookie 或 Bearer token）
    pub fn authorized(&self, req: &Req) -> bool {
        if self.token.is_none() {
            return true;
        }
        if let Some(b) = req.header("authorization").and_then(|v| v.strip_prefix("Bearer ")) {
            if self.check_token(b) {
                return true;
            }
        }
        req.cookie(COOKIE)
            .is_some_and(|c| self.sessions.lock().unwrap().get(c).is_some_and(|at| at.elapsed() < SESSION_TTL))
    }

    /// 讀靜態檔（只允許 static_dir 底下的一層檔名；`dashboard/<檔名>` 是共用儀表板）
    pub fn static_file(&self, path: &str) -> Option<(&'static str, Vec<u8>)> {
        let (dir, name) = match path.trim_start_matches('/') {
            "" => (&self.static_dir, "index.html"),
            p => match p.strip_prefix("dashboard/") {
                Some(n) => (&self.dashboard_dir, n),
                None => (&self.static_dir, p),
            },
        };
        if name.contains('/') || name.contains('\\') || name.starts_with('.') {
            return None;
        }
        let ctype = match name.rsplit('.').next()? {
            "html" => "text/html; charset=utf-8",
            "js" => "text/javascript; charset=utf-8",
            "css" => "text/css; charset=utf-8",
            "json" => "application/json; charset=utf-8",
            "svg" => "image/svg+xml",
            "png" => "image/png",
            _ => return None,
        };
        std::fs::read(dir.join(name)).ok().map(|b| (ctype, b))
    }

    pub fn session_json(&self, req: &Req, uci: bool) -> Value {
        let logged_in = self.authorized(req);
        json!({
            "auth": self.auth_enabled(),
            "loggedIn": logged_in,
            "mode": self.run_mode.get().copied().unwrap_or("cmd"),
            // 還沒登入的人不需要知道設定檔放在哪裡
            "configFile": if logged_in { self.config_file.get() } else { None },
            "uci": uci,
            "os": std::env::consts::OS,
            "version": env!("CARGO_PKG_VERSION"),
        })
    }
}

/// 解析後的 HTTP 請求
#[derive(Debug, Default)]
pub struct Req {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Req {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn cookie(&self, name: &str) -> Option<&str> {
        self.header("cookie")?
            .split(';')
            .filter_map(|kv| kv.trim().split_once('='))
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v)
    }

    /// 會改東西的請求：Origin（有的話）必須是本機，而且跟這個請求的 Host 是同一個（同主機、同埠）。
    /// 只檢查「是本機」不夠：同一台電腦上別的埠的網頁（開發用的伺服器、其他程式的介面）也是本機
    pub fn same_origin(&self) -> bool {
        match self.header("origin") {
            None => true,
            Some(o) => {
                let host = o.strip_prefix("http://").or_else(|| o.strip_prefix("https://")).unwrap_or(o);
                let same_host = match self.header("host") {
                    Some(h) => h.trim().eq_ignore_ascii_case(host),
                    None => true,
                };
                crate::admin::local_host(Some(host)) && same_host
            }
        }
    }

    /// 瀏覽器標明這是別的網站（或同一台主機別的埠）發出的 fetch / 圖片 / 表單（`Sec-Fetch-Site`）。
    /// 沒有這個標頭的（指令列工具、rpcd、舊瀏覽器）不算
    pub fn cross_site_fetch(&self) -> bool {
        matches!(self.header("sec-fetch-site"), Some(v) if v.eq_ignore_ascii_case("cross-site") || v.eq_ignore_ascii_case("same-site"))
    }
}

/// 設定檔驗證：必須是物件，而且能合併出完整設定
pub fn validate_config(v: &Value) -> Result<(), String> {
    if !v.is_object() {
        return Err("設定必須是 JSON 物件".into());
    }
    let full = kuroshio_config::build(v);
    for (k, want) in [("listen.plain.port", "數字"), ("admin.port", "數字")] {
        if let Some(x) = get(&full, k) {
            if !x.is_u64() {
                return Err(format!("{k} 必須是{want}"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(headers: &[(&str, &str)]) -> Req {
        Req {
            headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn login_and_sessions() {
        let dir = std::env::temp_dir().join(format!("kuroshio-webui-{}", std::process::id()));
        let cfg = json!({ "admin": { "auth": true } });
        let w = WebUi::new(&cfg, &dir, &dir);
        assert!(w.auth_enabled());
        let tok = std::fs::read_to_string(dir.join("admin.token")).unwrap().trim().to_string();
        assert_eq!(tok.len(), 48);
        assert!(w.check_token(&tok) && !w.check_token("nope"));
        // 第二次啟動沿用同一個 token
        let w2 = WebUi::new(&cfg, &dir, &dir);
        assert!(w2.check_token(&tok));
        // 重新載入（WebUi 重建）後已登入的 session 仍然有效
        let sid0 = w.new_session();
        assert!(w2.authorized(&req(&[("Cookie", &format!("{COOKIE}={sid0}"))])));
        assert!(!w.authorized(&req(&[])));
        assert!(w.authorized(&req(&[("Authorization", &format!("Bearer {tok}"))])));
        let sid = w.new_session();
        assert!(w.authorized(&req(&[("Cookie", &format!("a=1; {COOKIE}={sid}"))])));
        w.logout(&sid);
        assert!(!w.authorized(&req(&[("Cookie", &format!("{COOKIE}={sid}"))])));
        assert!(w.login_url(8054).contains(&tok));
        let _ = std::fs::remove_dir_all(&dir);
        // 關閉登入
        let w = WebUi::new(&json!({ "admin": { "auth": false } }), &dir, &dir);
        assert!(!w.auth_enabled() && w.authorized(&req(&[])));
    }

    #[test]
    fn origin_and_static_paths() {
        assert!(req(&[]).same_origin());
        assert!(req(&[("Origin", "http://127.0.0.1:8054")]).same_origin());
        assert!(req(&[("Origin", "http://localhost:8054")]).same_origin());
        assert!(!req(&[("Origin", "http://evil.example")]).same_origin());
        assert!(!req(&[("Origin", "null")]).same_origin(), "沙箱 iframe");
        assert!(!req(&[("Origin", "http://127.0.0.1.evil.example")]).same_origin());
        // Origin 要跟 Host 同一個：同一台電腦別的埠的網頁不算
        assert!(req(&[("Host", "127.0.0.1:8054"), ("Origin", "http://127.0.0.1:8054")]).same_origin());
        assert!(req(&[("Host", "LOCALHOST:8054"), ("Origin", "http://localhost:8054")]).same_origin());
        assert!(!req(&[("Host", "127.0.0.1:8054"), ("Origin", "http://127.0.0.1:3000")]).same_origin());
        assert!(!req(&[("Host", "127.0.0.1:8054"), ("Origin", "http://localhost:8054")]).same_origin());
        assert!(req(&[("Sec-Fetch-Site", "cross-site")]).cross_site_fetch());
        assert!(req(&[("Sec-Fetch-Site", "same-site")]).cross_site_fetch());
        assert!(!req(&[("Sec-Fetch-Site", "same-origin")]).cross_site_fetch());
        assert!(!req(&[("Sec-Fetch-Site", "none")]).cross_site_fetch());
        assert!(!req(&[]).cross_site_fetch(), "rpcd、指令列工具不帶這個標頭");
        let w = WebUi::new(
            &json!({ "admin": { "auth": false } }),
            std::path::Path::new("/nonexistent"),
            std::path::Path::new("/nonexistent"),
        );
        assert!(w.static_file("/../etc/passwd").is_none());
        assert!(w.static_file("/.hidden.js").is_none());
        assert!(w.static_file("/a/b.js").is_none());
        // 共用儀表板：設定頁資料夾旁的 dashboard/，一樣只認一層檔名
        let base = std::env::temp_dir().join(format!("kuroshio-webui-dash-{}", std::process::id()));
        std::fs::create_dir_all(base.join("admin")).unwrap();
        std::fs::create_dir_all(base.join("dashboard")).unwrap();
        std::fs::write(base.join("dashboard/dashboard.js"), "x").unwrap();
        std::fs::write(base.join("admin/index.html"), "<p>").unwrap();
        let w = WebUi::new(
            &json!({ "admin": { "auth": false, "webDir": base.join("admin").to_string_lossy() } }),
            std::path::Path::new("/nonexistent"),
            std::path::Path::new("/nonexistent"),
        );
        assert_eq!(
            w.static_file("/dashboard/dashboard.js").unwrap(),
            ("text/javascript; charset=utf-8", b"x".to_vec())
        );
        assert!(w.static_file("/dashboard/../admin/index.html").is_none());
        assert!(w.static_file("/dashboard/nope.js").is_none());
        assert!(w.static_file("/").is_some());
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn sessions_are_bounded_and_evict_oldest() {
        let dir = std::env::temp_dir().join(format!("kuroshio-webui-sess-{}", std::process::id()));
        let w = WebUi::new(&json!({ "admin": { "auth": true } }), &dir, &dir);
        let first = w.new_session();
        let second = w.new_session();
        for _ in 0..MAX_SESSIONS - 2 {
            w.new_session();
        }
        let cookie = |id: &str| req(&[("Cookie", &format!("{COOKIE}={id}"))]);
        assert!(w.authorized(&cookie(&first)));
        // 再登入一次：只擠掉最舊的那個，其他的還在
        let newest = w.new_session();
        assert!(!w.authorized(&cookie(&first)));
        assert!(w.authorized(&cookie(&second)) && w.authorized(&cookie(&newest)));
        assert_eq!(w.sessions.lock().unwrap().len(), MAX_SESSIONS);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join("admin.token")).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "token 檔只有擁有者能讀");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn old_world_readable_token_is_tightened() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("kuroshio-webui-mode-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("admin.token");
        std::fs::write(&f, "0123456789abcdef0123456789abcdef\n").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        let w = WebUi::new(&json!({ "admin": { "auth": true } }), &dir, &dir);
        assert!(w.check_token("0123456789abcdef0123456789abcdef"), "沿用原本的 token");
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn secrets_are_masked_and_restored() {
        let file = json!({
            "ddns": { "enabled": true, "apiToken": "cf-secret-1", "zone": "example.com" },
            "acme": { "apiToken": "" },
            "admin": { "tokenFile": "/etc/kuroshio/admin.token" },
            "upstream": { "pinned": [{ "url": "https://dns.example/dns-query", "password": "pw" }] },
        });
        let mut shown = file.clone();
        mask_secrets(&mut shown);
        assert_eq!(shown["ddns"]["apiToken"], SECRET_MASK);
        assert_eq!(shown["acme"]["apiToken"], "", "沒填的不遮");
        assert_eq!(shown["admin"]["tokenFile"], "/etc/kuroshio/admin.token", "路徑不是密碼");
        assert_eq!(shown["upstream"]["pinned"][0]["password"], SECRET_MASK);
        assert_eq!(shown["ddns"]["zone"], "example.com");
        assert!(!shown.to_string().contains("cf-secret-1") && !shown.to_string().contains("\"pw\""));

        // 原樣存回來：遮罩換回檔案裡的值
        let mut back = shown.clone();
        unmask_secrets(&mut back, &file);
        assert_eq!(back, file);
        // 使用者改了 token：用新的
        let mut edited = shown.clone();
        edited["ddns"]["apiToken"] = json!("cf-secret-2");
        unmask_secrets(&mut edited, &file);
        assert_eq!(edited["ddns"]["apiToken"], "cf-secret-2");
        // 清空：就是清空
        let mut cleared = shown.clone();
        cleared["ddns"]["apiToken"] = json!("");
        unmask_secrets(&mut cleared, &file);
        assert_eq!(cleared["ddns"]["apiToken"], "");
        // 檔案裡原本沒有、卻送來遮罩：不能把遮罩字串當成 token 寫進去
        let mut bogus = json!({ "acme": { "apiToken": SECRET_MASK } });
        unmask_secrets(&mut bogus, &json!({}));
        assert_eq!(bogus, json!({ "acme": {} }));
    }

    #[test]
    fn config_validation() {
        assert!(validate_config(&json!([])).is_err());
        assert!(validate_config(&json!({ "listen": { "plain": { "port": "x" } } })).is_err());
        assert!(validate_config(&json!({ "listen": { "plain": { "port": 5353 } } })).is_ok());
    }
}
