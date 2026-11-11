//! DDNS：本機模擬 Cloudflare API 與 /cdn-cgi/trace，測建立、沒變不呼叫、變了更新、HTTPS 記錄、錯誤訊息

use kuroshio::ddns::{Config, Ddns};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Default)]
struct Cf {
    ip: String,
    records: Vec<Value>,
    calls: Vec<String>,
}

async fn mock(state: Arc<Mutex<Cf>>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let st = state.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut b = [0u8; 1];
                while !buf.ends_with(b"\r\n\r\n") {
                    if s.read_exact(&mut b).await.is_err() {
                        return;
                    }
                    buf.push(b[0]);
                }
                let head = String::from_utf8_lossy(&buf).to_string();
                let len: usize = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse().unwrap())
                    })
                    .unwrap_or(0);
                let mut body = vec![0u8; len];
                s.read_exact(&mut body).await.unwrap();
                let mut p = head.split_whitespace();
                let (method, path) = (p.next().unwrap().to_string(), p.next().unwrap().to_string());
                assert!(path == "/trace" || head.contains("Authorization: Bearer TOKEN"), "API 要帶權杖");
                let resp = {
                    let mut st = st.lock().unwrap();
                    st.calls.push(format!("{method} {}", path.split('?').next().unwrap()));
                    if path == "/trace" {
                        format!("fl=1\nip={}\nts=1\n", st.ip)
                    } else if path.starts_with("/zones?name=example.com") {
                        json!({ "success": true, "result": [{ "id": "Z1" }] }).to_string()
                    } else if path.starts_with("/zones?") {
                        json!({ "success": true, "result": [] }).to_string()
                    } else if method == "GET" {
                        let (t, n) = (
                            path.split("type=").nth(1).unwrap().split('&').next().unwrap().to_string(),
                            path.split("name=").nth(1).unwrap().to_string(),
                        );
                        let found: Vec<Value> = st.records.iter().filter(|r| r["type"] == t && r["name"] == n).cloned().collect();
                        json!({ "success": true, "result": found }).to_string()
                    } else if method == "POST" {
                        let mut r: Value = serde_json::from_slice(&body).unwrap();
                        r["id"] = json!(format!("R{}", st.records.len()));
                        st.records.push(r);
                        json!({ "success": true, "result": {} }).to_string()
                    } else {
                        let id = path.rsplit('/').next().unwrap().to_string();
                        let new: Value = serde_json::from_slice(&body).unwrap();
                        for r in st.records.iter_mut().filter(|r| r["id"] == json!(id)) {
                            r["content"] = new["content"].clone();
                        }
                        json!({ "success": true, "result": {} }).to_string()
                    }
                };
                let out = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{resp}", resp.len());
                let _ = s.write_all(out.as_bytes()).await;
            });
        }
    });
    addr
}

fn cfg(addr: SocketAddr, https: Option<&str>) -> Config {
    Config {
        api_token: "TOKEN".into(),
        records: vec!["home.example.com".into()],
        zone: String::new(),
        ipv4: true,
        ipv6: false,
        proxied: false,
        ttl: 1,
        interval: Duration::from_secs(300),
        force: Duration::from_secs(86400),
        ip_source: "web".into(),
        iface4: String::new(),
        iface6: String::new(),
        url4: format!("http://{addr}/trace"),
        url6: format!("http://{addr}/trace"),
        api: format!("http://{addr}"),
        https_record: https.map(str::to_string),
    }
}

#[tokio::test]
async fn create_skip_update() {
    let st = Arc::new(Mutex::new(Cf {
        ip: "203.0.113.5".into(),
        ..Default::default()
    }));
    let addr = mock(st.clone()).await;
    let d = Ddns::new(cfg(addr, Some("dns.example.com")));

    let r = d.update(false).await;
    assert_eq!(r["ip4"], "203.0.113.5");
    assert_eq!(r["records"][0]["action"], "created", "{r}");
    assert_eq!(r["records"][1]["type"], "HTTPS");
    assert_eq!(r["records"][1]["action"], "created");
    {
        let s = st.lock().unwrap();
        assert!(s.calls.contains(&"GET /zones".to_string()));
        let https = s.records.iter().find(|x| x["type"] == "HTTPS").unwrap();
        assert_eq!(https["data"]["value"], "alpn=\"h3,h2\"");
    }

    // IP 沒變：不呼叫 API
    let before = st.lock().unwrap().calls.len();
    let r = d.update(false).await;
    assert_eq!(r["records"][0]["action"], "unchanged");
    assert_eq!(st.lock().unwrap().calls.len(), before + 1, "只問了 trace");

    // IP 變了：更新
    st.lock().unwrap().ip = "203.0.113.77".into();
    let r = d.update(false).await;
    assert_eq!(r["records"][0]["action"], "updated");
    assert_eq!(r["records"][0]["previous"], "203.0.113.5");
    assert!(st.lock().unwrap().records.iter().any(|x| x["content"] == "203.0.113.77"));
}

#[tokio::test]
async fn errors_are_reported() {
    let st = Arc::new(Mutex::new(Cf {
        ip: "203.0.113.5".into(),
        ..Default::default()
    }));
    let addr = mock(st).await;
    let mut c = cfg(addr, None);
    c.records = vec!["home.other.org".into()];
    let r = Ddns::new(c).update(false).await;
    assert_eq!(r["records"][0]["ok"], false);
    assert!(r["records"][0]["error"].as_str().unwrap().contains("zone"), "{r}");
    let mut c = cfg(addr, None);
    c.api_token.clear();
    assert!(Ddns::new(c).update(false).await["error"].as_str().unwrap().contains("Token"));
}

#[test]
fn from_cfg_https_record_only_with_doh3() {
    let base =
        json!({ "ddns": { "enabled": true, "apiToken": "x", "records": ["a.example.com"] }, "site": { "hostname": "dns.example.com" } });
    let c = Config::from_cfg(&kuroshio_config::with_overrides(&base)).unwrap();
    assert!(c.https_record.is_none(), "沒開 DoH3 不發布");
    let mut on = base.clone();
    on["listen"] = json!({ "doh": { "enabled": true, "http3": true } });
    let c = Config::from_cfg(&kuroshio_config::with_overrides(&on)).unwrap();
    assert_eq!(c.https_record.as_deref(), Some("dns.example.com"));
    assert!(Config::from_cfg(&kuroshio_config::defaults()).is_none(), "預設關閉");
}
