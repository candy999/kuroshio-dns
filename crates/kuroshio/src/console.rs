//! cmd 執行時的互動指令（規格 07 第 1 節）：在視窗裡輸入 help、url、site… 就能拿到設定頁與公開頁的網址
//!
//! 只在「前景執行、而且標準輸入是終端機」時啟用；Windows 服務、背景執行、輸入被導向時不會讀標準輸入。
//! 沒在跑的時候（或服務模式）用 `kuroshio url` 看同樣的網址。

use crate::app::AppState;
use kuroshio_config::get;
use serde_json::Value;
use std::sync::Arc;

/// 這一輪執行的網址與位置（設定重新載入後會換新的）
#[derive(Debug, Clone, Default)]
pub struct Info {
    /// 設定頁（含登入 token 的網址；沒開管理 API 時 None）
    pub admin_url: Option<String>,
    /// 登入 token 檔的位置
    pub token_file: Option<String>,
    /// 公開頁網址（對外的網域優先，再來是本機）
    pub site_urls: Vec<String>,
    /// 隱藏的詳細數據頁
    pub detail_url: Option<String>,
    /// 給裝置設定用的位址
    pub doh_url: Option<String>,
    pub dot_host: Option<String>,
    /// 公開頁沒開的原因（開著時 None）
    pub site_off: Option<String>,
    pub config_file: Option<String>,
    pub state_dir: String,
}

pub struct Ctx {
    pub info: Info,
    pub state: Option<Arc<AppState>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    None,
    Quit,
    Reload,
    /// 用預設瀏覽器打開
    Open,
}

pub const HELP: &str = "可以用的指令：
  help     顯示這份說明（也可以輸入 ?）
  url      設定頁的網址（含登入 token）
  open     用瀏覽器打開設定頁
  site     公開頁、詳細數據頁的網址，以及裝置要填的 DoH / DoT 位址
  status   目前狀態：今天的查詢數、命中率、攔截數、監聽的協議
  paths    設定檔與資料放在哪裡
  reload   重新讀取設定檔
  quit     正常結束（也可以按 Ctrl+C）";

/// DoH 監聽是不是 HTTPS（有憑證）；DNR 也用這個判斷
pub fn doh_tls(cfg: &Value) -> bool {
    crate::app::doh_uses_tls(cfg, &crate::app::config_dir(cfg))
}

fn with_port(scheme: &str, host: &str, port: u16) -> String {
    let default = if scheme == "https" { 443 } else { 80 };
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == default {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}:{port}")
    }
}

impl Info {
    /// 依設定與實際監聽的埠算出各個網址。`doh_port`：DoH 實際監聽的埠；`site_on`：公開頁有沒有啟動
    pub fn build(
        cfg: &Value,
        admin_url: Option<String>,
        token_file: Option<String>,
        doh_port: Option<u16>,
        dot_port: Option<u16>,
        site_on: bool,
    ) -> Info {
        Info::build_with(cfg, admin_url, token_file, doh_port, dot_port, site_on, false)
    }

    /// 同 [`Info::build`]；`httpsys`：這一輪 DoH 是向 HTTP.sys 登記的（模式 B）——對外一定是 HTTPS，
    /// 而且只登記了網域的網址，沒有本機網址
    pub fn build_with(
        cfg: &Value,
        admin_url: Option<String>,
        token_file: Option<String>,
        doh_port: Option<u16>,
        dot_port: Option<u16>,
        site_on: bool,
        httpsys: bool,
    ) -> Info {
        let s = |k: &str| get(cfg, k).and_then(Value::as_str).unwrap_or("").trim().to_string();
        let domain = [s("site.hostname"), s("domain")].into_iter().find(|d| !d.is_empty());
        let doh_path = match s("listen.doh.path") {
            p if p.is_empty() => "/dns-query".to_string(),
            p => p,
        };
        let iis = s("listen.doh.windowsMode") == "iis-proxy";
        let tls = httpsys || doh_tls(cfg);
        // 對外的網址：IIS 反向代理時走 IIS 的 443
        let public = domain.as_ref().and_then(|d| match (iis, doh_port) {
            (true, _) => Some(format!("https://{d}")),
            // listen.doh.publicPort：外面看到的埠號跟監聽的不同（埠號轉送）
            (false, Some(p)) => Some(with_port(
                if tls { "https" } else { "http" },
                d,
                get(cfg, "listen.doh.publicPort")
                    .and_then(Value::as_u64)
                    .filter(|x| *x > 0 && *x <= 65535)
                    .map(|x| x as u16)
                    .unwrap_or(p),
            )),
            (false, None) => None,
        });
        let local = doh_port
            .filter(|_| !httpsys)
            .map(|p| with_port(if tls { "https" } else { "http" }, "127.0.0.1", p));
        let mut info = Info {
            admin_url,
            token_file,
            config_file: None,
            state_dir: crate::app::persist_dir(cfg).display().to_string(),
            // 裝置只能用 HTTPS 的 DoH；純 HTTP（給反向代理用的本機埠）不列出來
            doh_url: public
                .as_ref()
                .filter(|u| u.starts_with("https://"))
                .map(|u| format!("{u}{doh_path}")),
            dot_host: domain.clone().filter(|_| dot_port.is_some()).map(|d| match dot_port {
                Some(853) | None => d,
                Some(p) => format!("{d}:{p}"),
            }),
            ..Default::default()
        };
        if !site_on {
            info.site_off = Some(if get(cfg, "site.enabled").and_then(Value::as_bool).unwrap_or(false) {
                "公開頁需要 DoH 監聽（listen.doh.enabled），目前沒有啟動".into()
            } else {
                "公開頁沒有開（設定頁「公開頁」→ 啟用，或設定檔 site.enabled = true）".into()
            });
            return info;
        }
        let detail = crate::site::detail_path(&s("site.detailPath"), &doh_path);
        for base in public.iter().chain(local.iter()) {
            info.site_urls.push(format!("{base}/"));
        }
        info.detail_url = public.or(local).map(|b| format!("{b}{detail}/"));
        info
    }
}

/// 處理一行輸入，回傳要印出來的文字與要做的事
pub fn handle(line: &str, ctx: Option<&Ctx>) -> (String, Action) {
    let cmd = line.trim().trim_start_matches('/').to_lowercase();
    if cmd.is_empty() {
        return (String::new(), Action::None);
    }
    let Some(ctx) = ctx else {
        return match cmd.as_str() {
            "quit" | "exit" | "q" => (String::new(), Action::Quit),
            _ => ("服務正在啟動或重新載入，請稍等再輸入".into(), Action::None),
        };
    };
    let i = &ctx.info;
    let out = match cmd.as_str() {
        "help" | "?" | "h" | "說明" => HELP.to_string(),
        "url" | "admin" | "設定" | "設定頁" => match &i.admin_url {
            Some(u) => format!(
                "設定頁：{u}\n（只有這台電腦能開；網址裡的 token 就是登入密碼，不要給別人{}）",
                i.token_file.as_ref().map(|f| format!("。token 存在 {f}")).unwrap_or_default()
            ),
            None => "管理 API 沒有開（admin.enabled = false）".into(),
        },
        "open" => match &i.admin_url {
            Some(_) => return ("正在用瀏覽器打開設定頁…".into(), Action::Open),
            None => "管理 API 沒有開（admin.enabled = false）".into(),
        },
        "site" | "public" | "公開" | "公開頁" => {
            let mut v = Vec::new();
            match &i.site_off {
                Some(why) => v.push(why.clone()),
                None => {
                    for (n, u) in i.site_urls.iter().enumerate() {
                        v.push(format!("{}：{u}", if n == 0 { "公開頁" } else { "公開頁（本機）" }));
                    }
                    if let Some(d) = &i.detail_url {
                        v.push(format!("詳細數據頁（知道網址的人才看得到）：{d}"));
                    }
                }
            }
            if let Some(d) = &i.doh_url {
                v.push(format!("DoH（瀏覽器、Windows、iOS）：{d}"));
            }
            if let Some(d) = &i.dot_host {
                // Android「私人 DNS」只支援 DoT、只能填主機名稱（固定 853 埠，不能帶埠號、也不能填 DoH 網址）
                if d.contains(':') {
                    v.push(format!(
                        "DoT：{d}（Android「私人 DNS」只能用 853 埠，這個埠號沒辦法在 Android 使用）"
                    ));
                } else {
                    v.push(format!("DoT（Android 私人 DNS）：{d}"));
                }
            }
            if i.doh_url.is_none() && i.dot_host.is_none() {
                v.push("還沒有設定網域（domain），或加密監聽沒有開，所以沒有可以給裝置填的 DoH / DoT 位址".into());
            }
            v.join("\n")
        }
        "status" | "狀態" => match &ctx.state {
            Some(st) => status_line(st),
            None => "服務正在啟動".into(),
        },
        "paths" | "path" | "位置" => {
            let mut v = Vec::new();
            if let Some(c) = &i.config_file {
                v.push(format!("設定檔：{c}"));
            }
            v.push(format!("資料（快照、學習結果）：{}", i.state_dir));
            if let Some(t) = &i.token_file {
                v.push(format!("設定頁登入 token：{t}"));
            }
            v.push("完整清單（憑證、金鑰、名單…）：設定頁「關於」或執行 kuroshio paths".into());
            v.join("\n")
        }
        "reload" | "重新載入" => return ("重新讀取設定檔…".into(), Action::Reload),
        "quit" | "exit" | "q" | "結束" => return ("正在結束（寫出快照）…".into(), Action::Quit),
        other => format!("不認識的指令「{other}」。輸入 help 看可以用的指令"),
    };
    (out, Action::None)
}

fn status_line(st: &AppState) -> String {
    let s = st.resolver.stats.summary();
    let t = &s["today"];
    let e = &st.encrypted;
    let mut l = vec!["一般 DNS".to_string()];
    for (name, a) in [("DoH", e.doh), ("DoH3", e.doh3), ("DoT", e.dot), ("DoQ", e.doq)] {
        if let Some(a) = a {
            l.push(format!("{name} {}", a.port()));
        }
    }
    let mut out = format!(
        "今天查詢 {}、快取命中率 {}、攔截 {}；已執行 {} 分鐘\n監聽：{}",
        t["query"],
        t["hitRate"].as_f64().map(|h| format!("{h}%")).unwrap_or_else(|| "—".into()),
        t["blocked"],
        s["uptimeSec"].as_u64().unwrap_or(0) / 60,
        l.join("、")
    );
    if let Some(m) = doh_mode_line(&e.doh_mode, &e.doh3_provider) {
        out.push('\n');
        out.push_str(&m);
    }
    out
}

/// DoH 的 Windows 模式與 DoH3 由誰提供（`status` 指令；只有 Windows 會顯示）
pub fn doh_mode_line(mode: &Value, doh3: &Value) -> Option<String> {
    if !cfg!(windows) && mode["configured"] != "httpsys" {
        return None;
    }
    let name = match mode["mode"].as_str()? {
        "httpsys" => "HTTP.sys 共用",
        "iis-proxy" => "IIS 反向代理",
        _ => "獨立監聽",
    };
    let mut v = vec![format!("DoH 模式：{name}（{}）", mode["reason"].as_str().unwrap_or(""))];
    for u in mode["urls"].as_array().into_iter().flatten() {
        v.push(match u["error"].as_str() {
            None => format!("  已登記 {}", u["url"].as_str().unwrap_or("")),
            Some(e) => format!("  沒登記：{e}"),
        });
    }
    let p = match doh3["provider"].as_str() {
        Some("kuroshio") => "黑潮 DNS 提供",
        Some("httpsys") => "HTTP.sys 提供",
        _ => "無法提供",
    };
    v.push(format!("DoH3：{p}（{}）", doh3["reason"].as_str().unwrap_or("")));
    Some(v.join("\n"))
}

/// 用預設瀏覽器打開網址（失敗就算了，網址已經印在畫面上）
pub fn open_browser(url: &str) -> bool {
    #[cfg(windows)]
    let r = std::process::Command::new("cmd").args(["/C", "start", "", url]).spawn();
    #[cfg(target_os = "macos")]
    let r = std::process::Command::new("open").arg(url).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let r = std::process::Command::new("xdg-open").arg(url).spawn();
    r.is_ok()
}

/// 標準輸入是終端機時，開一條執行緒逐行讀取（讀到結尾就結束）
pub fn spawn_reader() -> Option<tokio::sync::mpsc::UnboundedReceiver<String>> {
    use std::io::{BufRead, IsTerminal};
    if !std::io::stdin().is_terminal() {
        return None;
    }
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    std::thread::Builder::new()
        .name("console".into())
        .spawn(move || {
            for line in std::io::stdin().lock().lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        })
        .ok()?;
    Some(rx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx(info: Info) -> Ctx {
        Ctx { info, state: None }
    }

    #[test]
    fn urls_from_config() {
        // 獨立模式：自己聽 443，有憑證
        let cfg = json!({ "domain": "dns.example.net", "site": { "enabled": true }, "tls": { "cert": "c.pem", "key": "k.pem" } });
        let i = Info::build(&cfg, None, None, Some(443), Some(853), true);
        assert_eq!(i.site_urls, vec!["https://dns.example.net/", "https://127.0.0.1/"]);
        assert_eq!(i.detail_url.as_deref(), Some("https://dns.example.net/detail/"));
        assert_eq!(i.doh_url.as_deref(), Some("https://dns.example.net/dns-query"));
        assert_eq!(i.dot_host.as_deref(), Some("dns.example.net"));
        // 非標準埠
        let i = Info::build(&cfg, None, None, Some(8443), Some(8853), true);
        assert_eq!(i.site_urls[0], "https://dns.example.net:8443/");
        assert_eq!(i.dot_host.as_deref(), Some("dns.example.net:8853"));
        // IIS 反向代理：對外是 IIS 的 443，本機是純 HTTP
        let cfg = json!({ "site": { "enabled": true, "hostname": "dns.example.net", "detailPath": "/stats" },
            "listen": { "doh": { "windowsMode": "iis-proxy" } }, "acme": { "enabled": true } });
        let i = Info::build(&cfg, None, None, Some(8053), None, true);
        assert_eq!(i.site_urls, vec!["https://dns.example.net/", "http://127.0.0.1:8053/"]);
        assert_eq!(i.detail_url.as_deref(), Some("https://dns.example.net/stats/"));
        assert_eq!(i.dot_host, None);
        // 純 HTTP 的 DoH（沒有憑證）不能給裝置用
        let i = Info::build(
            &json!({ "domain": "dns.example.net", "site": { "enabled": true } }),
            None,
            None,
            Some(8053),
            None,
            true,
        );
        assert_eq!(
            (i.site_urls[0].as_str(), i.doh_url.as_deref()),
            ("http://dns.example.net:8053/", None)
        );
        // 沒有網域：只有本機網址，沒有給裝置填的位址
        let i = Info::build(&json!({ "site": { "enabled": true } }), None, None, Some(8053), None, true);
        assert_eq!(i.site_urls, vec!["http://127.0.0.1:8053/"]);
        assert_eq!(i.doh_url, None);
        // HTTP.sys 共用：一定是 HTTPS，沒有本機網址
        let cfg = json!({ "domain": "dns.example.net", "site": { "enabled": true }, "listen": { "doh": { "host": "127.0.0.1" } } });
        let i = Info::build_with(&cfg, None, None, Some(443), None, true, true);
        assert_eq!(i.site_urls, vec!["https://dns.example.net/"]);
        assert_eq!(i.doh_url.as_deref(), Some("https://dns.example.net/dns-query"));
        // DoH 在 8443（443 被占用）：網址都帶埠號
        let cfg = json!({ "domain": "dns.example.net", "site": { "enabled": true }, "tls": { "cert": "c.pem", "key": "k.pem" } });
        let i = Info::build(&cfg, None, None, Some(8443), Some(853), true);
        assert_eq!(i.doh_url.as_deref(), Some("https://dns.example.net:8443/dns-query"));
        assert_eq!(i.detail_url.as_deref(), Some("https://dns.example.net:8443/detail/"));
        // 路由器把 443 轉到本機 8443（listen.doh.publicPort = 443）：對外網址不帶埠號，本機網址照實際的埠
        let cfg = json!({ "domain": "dns.example.net", "site": { "enabled": true }, "tls": { "cert": "c.pem", "key": "k.pem" },
            "listen": { "doh": { "publicPort": 443 } } });
        let i = Info::build(&cfg, None, None, Some(8443), Some(853), true);
        assert_eq!(i.site_urls, vec!["https://dns.example.net/", "https://127.0.0.1:8443/"]);
        assert_eq!(i.doh_url.as_deref(), Some("https://dns.example.net/dns-query"));
        // 公開頁沒開
        let i = Info::build(&json!({ "domain": "dns.example.net" }), None, None, Some(443), None, false);
        assert!(i.site_urls.is_empty() && i.site_off.is_some());
    }

    #[test]
    fn commands() {
        let c = ctx(Info {
            admin_url: Some("http://127.0.0.1:8054/login?token=abc".into()),
            token_file: Some("C:\\ProgramData\\kuroshio\\admin.token".into()),
            site_urls: vec!["https://dns.example.net/".into()],
            detail_url: Some("https://dns.example.net/detail/".into()),
            doh_url: Some("https://dns.example.net/dns-query".into()),
            dot_host: Some("dns.example.net".into()),
            state_dir: "state".into(),
            ..Default::default()
        });
        let (out, act) = handle("help", Some(&c));
        assert!(out.contains("url") && out.contains("site") && act == Action::None);
        assert_eq!(handle(" ? ", Some(&c)).0, HELP);
        let (out, _) = handle("URL", Some(&c));
        assert!(out.contains("http://127.0.0.1:8054/login?token=abc") && out.contains("admin.token"));
        let (out, _) = handle("site", Some(&c));
        assert!(out.contains("公開頁：https://dns.example.net/") && out.contains("詳細數據頁") && out.contains("DoT"));
        assert_eq!(handle("open", Some(&c)).1, Action::Open);
        assert_eq!(handle("reload", Some(&c)).1, Action::Reload);
        assert_eq!(handle("/quit", Some(&c)).1, Action::Quit);
        assert_eq!(handle("", Some(&c)), (String::new(), Action::None));
        assert!(handle("nope", Some(&c)).0.contains("help"));
        assert!(handle("status", Some(&c)).0.contains("啟動"));
        // 啟動中：只有 quit 有作用
        assert_eq!(handle("quit", None).1, Action::Quit);
        assert_eq!(handle("url", None).1, Action::None);
        // 公開頁沒開時說明原因
        let off = ctx(Info {
            site_off: Some("公開頁沒有開".into()),
            state_dir: "s".into(),
            ..Default::default()
        });
        assert!(handle("site", Some(&off)).0.contains("公開頁沒有開"));
        // DoT 不在 853：Android 私人 DNS 不能用，要講清楚
        let odd = ctx(Info {
            doh_url: Some("https://dns.example.net:8443/dns-query".into()),
            dot_host: Some("dns.example.net:8853".into()),
            state_dir: "s".into(),
            ..Default::default()
        });
        let out = handle("site", Some(&odd)).0;
        assert!(
            out.contains("https://dns.example.net:8443/dns-query") && out.contains("只能用 853 埠"),
            "{out}"
        );
    }
}
