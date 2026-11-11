//! Windows 一次性設定（規格 07 第 1.1、2 節）
//!
//! - `kuroshio setup`：系統管理員執行一次，加 Windows 防火牆規則（之後一般權限也能跑全部功能）
//! - `kuroshio iis setup <站台>`：IIS 反向代理模式（模式 C）——產生 web.config 的轉送規則與 Alt-Svc 標頭、
//!   開啟 ARR 代理、X-Forwarded-For 不帶埠號
//!
//! 產生內容的部分（埠號、web.config）跨平台，可以在任何系統上測試；真正執行 netsh / appcmd 的部分只在 Windows。

use anyhow::Result;
use kuroshio_config::get;
use serde_json::Value;

/// 需要開放的埠（依設定）：(協議, 埠號, 說明)
pub fn firewall_ports(cfg: &Value) -> Vec<(&'static str, u16, &'static str)> {
    let on = |k: &str| get(cfg, k).and_then(Value::as_bool).unwrap_or(false);
    let port = |k: &str, d: u64| get(cfg, k).and_then(Value::as_u64).unwrap_or(d) as u16;
    let local = |k: &str| {
        get(cfg, k)
            .and_then(Value::as_str)
            .and_then(|h| h.parse::<std::net::IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback())
    };
    let mut v = Vec::new();
    if !local("listen.plain.host") {
        let p = port("listen.plain.port", 53);
        v.push(("UDP", p, "區網 DNS"));
        v.push(("TCP", p, "區網 DNS"));
    }
    if on("listen.dot.enabled") {
        v.push(("TCP", port("listen.dot.port", 853), "DoT"));
    }
    if on("listen.doq.enabled") {
        v.push(("UDP", port("listen.doq.port", 853), "DoQ"));
    }
    if on("listen.doh.enabled") {
        let p = port("listen.doh.port", 443);
        if !local("listen.doh.host") {
            v.push(("TCP", p, "DoH"));
        }
        if on("listen.doh.http3") {
            let h3 = match port("listen.doh.http3Port", 0) {
                0 => p,
                x => x,
            };
            v.push(("UDP", h3, "DoH3"));
        }
    }
    v.sort();
    v.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
    v
}

/// IIS 反向代理的設定
pub struct IisOptions {
    /// 黑潮 DNS 本機 DoH 的位址（`listen.doh.host:port`，HTTP）
    pub backend: String,
    /// DoH 路徑（`listen.doh.path`）
    pub doh_path: String,
    /// Alt-Svc 要宣告的 UDP 埠（DoH3 關閉時 None）
    pub h3_port: Option<u16>,
    /// 公開頁也交給黑潮 DNS（`site.enabled`）：(詳細頁路徑)
    pub site: Option<String>,
}

impl IisOptions {
    pub fn from_cfg(cfg: &Value) -> IisOptions {
        let s = |k: &str, d: &str| {
            get(cfg, k)
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
                .unwrap_or(d)
                .to_string()
        };
        let n = |k: &str| get(cfg, k).and_then(Value::as_u64).unwrap_or(0) as u16;
        let on = |k: &str| get(cfg, k).and_then(Value::as_bool).unwrap_or(false);
        let host = match s("listen.doh.host", "127.0.0.1").as_str() {
            "0.0.0.0" | "::" => "127.0.0.1".to_string(),
            h => h.to_string(),
        };
        let port = match n("listen.doh.port") {
            0 => 8053,
            p => p,
        };
        // DoH3 由黑潮 DNS 自己聽 UDP（規格 07 第 2.2 節）：宣告實際的埠
        let h3_port = on("listen.doh.http3").then(|| {
            [n("listen.doh.altSvcPort"), n("listen.doh.http3Port")]
                .into_iter()
                .find(|p| *p != 0)
                .unwrap_or(443)
        });
        IisOptions {
            backend: format!("{host}:{port}"),
            doh_path: s("listen.doh.path", "/dns-query").trim_start_matches('/').to_string(),
            h3_port,
            site: on("site.enabled").then(|| s("site.detailPath", "/detail").trim_matches('/').to_string()),
        }
    }
}

fn regex_escape(s: &str) -> String {
    let mut o = String::new();
    for c in s.chars() {
        if "\\.+*?()|[]{}^$".contains(c) {
            o.push('\\');
        }
        o.push(c);
    }
    o
}

fn xml_attr(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// IIS 的 URL Rewrite 規則：DoH、社群（`/.well-known/kuroshio/`），公開頁開啟時加上首頁與公開 API
pub fn web_config(o: &IisOptions) -> String {
    let mut pattern = format!("^({}|\\.well-known/kuroshio/.*)$", regex_escape(&o.doh_path));
    if let Some(detail) = &o.site {
        let mut parts = vec![
            String::new(),
            "index\\.html".into(),
            "robots\\.txt".into(),
            "favicon\\.(ico|svg)".into(),
            "api/public/.*".into(),
            "apple/.*".into(),
        ];
        if !detail.is_empty() {
            parts.push(format!("{}(/.*)?", regex_escape(detail)));
        }
        pattern = format!("^({}|\\.well-known/kuroshio/.*|{})$", regex_escape(&o.doh_path), parts.join("|"));
    }
    let alt_svc = o
        .h3_port
        .map(|p| {
            format!(
                "    <httpProtocol>\n      <customHeaders>\n        <remove name=\"Alt-Svc\" />\n        <add name=\"Alt-Svc\" value=\"{}\" />\n      </customHeaders>\n    </httpProtocol>\n",
                xml_attr(&format!("h3=\":{p}\"; ma=86400"))
            )
        })
        .unwrap_or_default();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!-- 黑潮 DNS（Kuroshio DNS）IIS 反向代理：kuroshio iis setup 產生，需要 URL Rewrite 與 ARR -->
<configuration>
  <system.webServer>
    <rewrite>
      <rules>
        <rule name="kuroshio" stopProcessing="true">
          <match url="{}" />
          <action type="Rewrite" url="http://{}/{{R:0}}" appendQueryString="true" />
        </rule>
      </rules>
    </rewrite>
{}  </system.webServer>
</configuration>
"#,
        xml_attr(&pattern),
        o.backend,
        alt_svc
    )
}

#[cfg(not(windows))]
pub fn setup(_cfg: &Value) -> Result<()> {
    anyhow::bail!("kuroshio setup 只用在 Windows；OpenWrt 由套件的防火牆設定處理")
}

#[cfg(not(windows))]
pub fn iis_setup(_cfg: &Value, _site: &str, _force: bool) -> Result<()> {
    anyhow::bail!("IIS 只在 Windows 上")
}

#[cfg(windows)]
pub use imp::{iis_setup, setup};

#[cfg(windows)]
mod imp {
    use super::*;
    use anyhow::{bail, Context};
    use std::path::PathBuf;
    use std::process::Command;

    fn run(cmd: &str, args: &[&str]) -> Result<String> {
        let out = Command::new(cmd).args(args).output().with_context(|| format!("無法執行 {cmd}"))?;
        let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
        if !out.status.success() {
            bail!("{cmd} {} 失敗：{}", args.join(" "), text.trim());
        }
        Ok(text)
    }

    /// 是不是系統管理員：`net session` 只有系統管理員能執行
    fn is_admin() -> bool {
        Command::new("net")
            .arg("session")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    pub fn setup(cfg: &Value) -> Result<()> {
        if !is_admin() {
            bail!("請用「以系統管理員身分執行」的命令提示字元執行 kuroshio setup");
        }
        let exe = std::env::current_exe()?;
        let program = format!("program={}", exe.display());
        let ports = firewall_ports(cfg);
        for proto in ["UDP", "TCP"] {
            let name = format!("name=黑潮 DNS（{proto}）");
            // 先刪掉舊規則（埠號可能改過），沒有也沒關係
            let _ = run("netsh", &["advfirewall", "firewall", "delete", "rule", &name]);
            let list: Vec<String> = ports.iter().filter(|p| p.0 == proto).map(|p| p.1.to_string()).collect();
            if list.is_empty() {
                continue;
            }
            let localport = format!("localport={}", list.join(","));
            let protocol = format!("protocol={proto}");
            run(
                "netsh",
                &[
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    &name,
                    "dir=in",
                    "action=allow",
                    &protocol,
                    &localport,
                    &program,
                    "profile=any",
                ],
            )?;
            println!("防火牆：允許 {proto} {}", list.join(", "));
        }
        for (proto, port, what) in &ports {
            println!("  {what}：{proto} {port}");
        }
        println!("完成。之後一般權限也能執行全部功能；服務模式請再執行 kuroshio service install");
        Ok(())
    }

    fn appcmd() -> PathBuf {
        let windir = std::env::var_os("windir")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        windir.join(r"System32\inetsrv\appcmd.exe")
    }

    pub fn iis_setup(cfg: &Value, site: &str, force: bool) -> Result<()> {
        if !is_admin() {
            bail!("請用「以系統管理員身分執行」的命令提示字元執行 kuroshio iis setup");
        }
        let appcmd = appcmd();
        if !appcmd.exists() {
            bail!("找不到 IIS（{}）", appcmd.display());
        }
        let inetsrv = appcmd.parent().unwrap().to_path_buf();
        if !inetsrv.join("rewrite.dll").exists() {
            bail!("沒有安裝 IIS URL Rewrite 模組（https://www.iis.net/downloads/microsoft/url-rewrite）");
        }
        if !inetsrv.join("requestRouter.dll").exists() {
            bail!("沒有安裝 IIS Application Request Routing（ARR）");
        }
        let a = appcmd.to_string_lossy().to_string();
        let dir =
            run(&a, &["list", "vdir", &format!("{site}/"), "/text:physicalPath"]).with_context(|| format!("找不到 IIS 站台「{site}」"))?;
        let dir = PathBuf::from(
            std::env::var("SystemDrive")
                .map(|d| dir.trim().replace("%SystemDrive%", &d))
                .unwrap_or_else(|_| dir.trim().to_string()),
        );
        // ARR：開啟代理、保留 Host、X-Forwarded-For 不帶埠號
        run(
            &a,
            &[
                "set",
                "config",
                "-section:system.webServer/proxy",
                "/enabled:True",
                "/preserveHostHeader:True",
                "/includePortInXForwardedFor:False",
                "/commit:apphost",
            ],
        )?;
        let o = IisOptions::from_cfg(cfg);
        let xml = web_config(&o);
        let target = dir.join("web.config");
        if target.exists() && !force {
            let alt = dir.join("web.config.kuroshio.xml");
            std::fs::write(&alt, &xml)?;
            println!("站台已經有 web.config，沒有覆蓋。黑潮 DNS 的規則寫在 {}", alt.display());
            println!("請把裡面的 <rule name=\"kuroshio\"> 與 Alt-Svc 標頭合併進去，或加 --force 覆蓋（會先備份成 web.config.bak）");
        } else {
            if target.exists() {
                std::fs::copy(&target, dir.join("web.config.bak"))?;
            }
            std::fs::write(&target, &xml)?;
            println!("已寫入 {}", target.display());
        }
        println!("IIS 會把 /{} 轉給 http://{}", o.doh_path, o.backend);
        if !get(cfg, "listen.doh.enabled").and_then(Value::as_bool).unwrap_or(false) {
            println!("注意：設定裡 listen.doh.enabled 還沒開，請開啟並讓它聽 {}（不用憑證）", o.backend);
        }
        if let Some(p) = o.h3_port {
            println!("DoH3 由黑潮 DNS 自己聽 UDP {p}，IIS 回應會帶 Alt-Svc 標頭");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ports_follow_config() {
        let cfg = json!({
            "listen": {
                "plain": { "host": "0.0.0.0", "port": 53 },
                "dot": { "enabled": true, "port": 853 },
                "doq": { "enabled": true, "port": 853 },
                "doh": { "enabled": true, "host": "0.0.0.0", "port": 443, "http3": true, "http3Port": 0 }
            }
        });
        let p: Vec<(&str, u16)> = firewall_ports(&cfg).into_iter().map(|(a, b, _)| (a, b)).collect();
        assert_eq!(
            p,
            vec![("TCP", 53), ("TCP", 443), ("TCP", 853), ("UDP", 53), ("UDP", 443), ("UDP", 853)]
        );
        // IIS 模式：DoH 只聽本機，不用開 TCP；DoH3 換埠
        let cfg = json!({ "listen": { "plain": { "host": "127.0.0.1" }, "doh": { "enabled": true, "host": "127.0.0.1", "port": 8053, "http3": true, "http3Port": 8443 } } });
        let p: Vec<(&str, u16)> = firewall_ports(&cfg).into_iter().map(|(a, b, _)| (a, b)).collect();
        assert_eq!(p, vec![("UDP", 8443)]);
    }

    #[test]
    fn web_config_rules() {
        let cfg = json!({ "listen": { "doh": { "enabled": true, "host": "0.0.0.0", "port": 8053, "path": "/dns-query", "http3": true, "http3Port": 0 } } });
        let x = web_config(&IisOptions::from_cfg(&cfg));
        assert!(x.contains(r#"<match url="^(dns-query|\.well-known/kuroshio/.*)$" />"#), "{x}");
        assert!(x.contains(r#"url="http://127.0.0.1:8053/{R:0}""#), "{x}");
        assert!(x.contains(r#"value="h3=&quot;:443&quot;; ma=86400""#), "{x}");
        // DoH3 關閉：不宣告；公開頁開啟：加上首頁與詳細頁
        let cfg = json!({ "listen": { "doh": { "port": 8053 } }, "site": { "enabled": true, "detailPath": "/stats" } });
        let x = web_config(&IisOptions::from_cfg(&cfg));
        assert!(!x.contains("Alt-Svc"));
        assert!(x.contains(r#"<match url="^(dns-query|\.well-known/kuroshio/.*||index\.html|robots\.txt|favicon\.(ico|svg)|api/public/.*|apple/.*|stats(/.*)?)$" />"#), "{x}");
    }

    #[test]
    fn forwarded_with_port() {
        use crate::encrypted::parse_forwarded_ip;
        assert_eq!(parse_forwarded_ip("1.2.3.4"), Some("1.2.3.4".parse().unwrap()));
        assert_eq!(parse_forwarded_ip("1.2.3.4:5678"), Some("1.2.3.4".parse().unwrap()));
        assert_eq!(parse_forwarded_ip("[2001:db8::1]:5678"), Some("2001:db8::1".parse().unwrap()));
        assert_eq!(parse_forwarded_ip("2001:db8::1"), Some("2001:db8::1".parse().unwrap()));
        assert_eq!(parse_forwarded_ip("garbage"), None);
    }
}
