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
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use tracing::{info, warn};

pub const COOKIE: &str = "kuroshio_session";
const MAX_SESSIONS: usize = 32;

/// 設定頁的狀態
pub struct WebUi {
    /// None = 不需要登入
    token: Option<String>,
    pub token_file: Option<PathBuf>,
    sessions: Arc<Mutex<HashSet<String>>>,
    pub static_dir: PathBuf,
    /// 用 JSON 設定檔執行時的路徑（UCI 時沒有：設定走 LuCI）
    pub config_file: OnceLock<PathBuf>,
    /// 執行方式（cmd / 服務），給設定頁顯示
    pub run_mode: OnceLock<&'static str>,
    /// 版本、授權、原始碼網址
    pub about: Value,
}

/// 登入的 session 依 token 放在整個程式共用的地方：設定頁存檔後重新載入（WebUi 重建）
/// 不用重新登入；token 換了就是另一組，舊的 session 自然失效
fn session_store(token: &str) -> Arc<Mutex<HashSet<String>>> {
    static STORES: Mutex<BTreeMap<String, Arc<Mutex<HashSet<String>>>>> = Mutex::new(BTreeMap::new());
    STORES.lock().unwrap().entry(token.to_string()).or_default().clone()
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

impl WebUi {
    pub fn new(cfg: &Value, base_dir: &std::path::Path, share_dir: &std::path::Path) -> WebUi {
        let auth = match get(cfg, "admin.auth") {
            Some(Value::Bool(b)) => *b,
            _ => cfg!(windows),
        };
        let token_file = auth.then(
            || match get(cfg, "admin.tokenFile").and_then(Value::as_str).filter(|s| !s.is_empty()) {
                Some(p) => PathBuf::from(p),
                None => base_dir.join("admin.token"),
            },
        );
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
        let static_dir = get(cfg, "admin.webDir")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| share_dir.join("admin"));
        let sessions = token.as_deref().map(session_store).unwrap_or_default();
        WebUi {
            token,
            token_file,
            sessions,
            static_dir,
            config_file: OnceLock::new(),
            run_mode: OnceLock::new(),
            about: crate::about::json(cfg),
        }
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
        let mut s = self.sessions.lock().unwrap();
        if s.len() >= MAX_SESSIONS {
            s.clear();
        }
        s.insert(id.clone());
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
        req.cookie(COOKIE).is_some_and(|c| self.sessions.lock().unwrap().contains(c))
    }

    /// 讀靜態檔（只允許 static_dir 底下的一層檔名）
    pub fn static_file(&self, path: &str) -> Option<(&'static str, Vec<u8>)> {
        let name = match path.trim_start_matches('/') {
            "" => "index.html",
            p => p,
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
        std::fs::read(self.static_dir.join(name)).ok().map(|b| (ctype, b))
    }

    pub fn session_json(&self, req: &Req, uci: bool) -> Value {
        json!({
            "auth": self.auth_enabled(),
            "loggedIn": self.authorized(req),
            "mode": self.run_mode.get().copied().unwrap_or("cmd"),
            "configFile": self.config_file.get(),
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

    /// 會改東西的請求：Origin（有的話）必須是本機
    pub fn same_origin(&self) -> bool {
        match self.header("origin") {
            None => true,
            Some(o) => {
                let host = o.strip_prefix("http://").or_else(|| o.strip_prefix("https://")).unwrap_or(o);
                crate::admin::local_host(Some(host))
            }
        }
    }
}

/// 設定檔驗證：必須是物件，而且能合併出完整設定
pub fn validate_config(v: &Value) -> Result<(), String> {
    if !v.is_object() {
        return Err("設定必須是 JSON 物件".into());
    }
    let tier = kuroshio_config::requested_tier(v).unwrap_or(kuroshio_config::Tier::Standard);
    let full = kuroshio_config::build(tier, v);
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
        let w = WebUi::new(
            &json!({ "admin": { "auth": false } }),
            std::path::Path::new("/nonexistent"),
            std::path::Path::new("/nonexistent"),
        );
        assert!(w.static_file("/../etc/passwd").is_none());
        assert!(w.static_file("/.hidden.js").is_none());
        assert!(w.static_file("/a/b.js").is_none());
    }

    #[test]
    fn config_validation() {
        assert!(validate_config(&json!([])).is_err());
        assert!(validate_config(&json!({ "listen": { "plain": { "port": "x" } } })).is_err());
        assert!(validate_config(&json!({ "listen": { "plain": { "port": 5353 } } })).is_ok());
    }
}
