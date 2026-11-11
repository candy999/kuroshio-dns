//! DDNS：本機模擬 Cloudflare API 與 /cdn-cgi/trace
//!
//! - 建立、沒變不呼叫、變了更新、HTTPS 記錄、錯誤訊息
//! - 多出口：一個名稱多筆 A 記錄、增加 / 移除出口、其中一個出口換 IP
//! - IPv6 開 / 關、偵測失敗時保留記錄、分頁、別人的記錄不動

use kuroshio::ddns::{Config, Ddns, IfaceSel, MARK};
use kuroshio::netif::{Addr, Iface, Scope};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Default)]
struct Cf {
    /// /trace 回的 IP（依連進來的來源位址另外指定時用 `by_peer`）
    ip: String,
    by_peer: HashMap<IpAddr, String>,
    /// 這些來源位址問 /trace 時回 HTTP 500（偵測失敗）
    fail_peers: HashSet<IpAddr>,
    fail_all: bool,
    records: Vec<Value>,
    calls: Vec<String>,
    next_id: u32,
}

impl Cf {
    fn contents(&self, rtype: &str, name: &str) -> Vec<String> {
        let mut v: Vec<String> = self
            .records
            .iter()
            .filter(|r| r["type"] == rtype && r["name"] == name)
            .map(|r| r["content"].as_str().unwrap().to_string())
            .collect();
        v.sort();
        v
    }
    fn mutations(&self) -> usize {
        self.calls.iter().filter(|c| !c.starts_with("GET ")).count()
    }
    fn add(&mut self, rtype: &str, name: &str, content: &str, comment: Option<&str>) {
        self.next_id += 1;
        self.records.push(
            json!({ "id": format!("R{}", self.next_id), "type": rtype, "name": name, "content": content, "ttl": 1, "proxied": false, "comment": comment }),
        );
    }
}

fn query(path: &str, key: &str) -> Option<String> {
    let q = path.split_once('?')?.1;
    q.split('&').find_map(|kv| kv.strip_prefix(&format!("{key}="))).map(str::to_string)
}

async fn mock(state: Arc<Mutex<Cf>>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, peer) = l.accept().await.unwrap();
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
                let mut code = 200;
                let resp = {
                    let mut st = st.lock().unwrap();
                    st.calls.push(format!("{method} {}", path.split('?').next().unwrap()));
                    if path == "/trace" {
                        if st.fail_all || st.fail_peers.contains(&peer.ip()) {
                            code = 500;
                            String::new()
                        } else {
                            let ip = st.by_peer.get(&peer.ip()).cloned().unwrap_or_else(|| st.ip.clone());
                            format!("fl=1\nip={ip}\nts=1\n")
                        }
                    } else if path.starts_with("/zones?name=example.com") {
                        json!({ "success": true, "result": [{ "id": "Z1" }] }).to_string()
                    } else if path.starts_with("/zones?") {
                        json!({ "success": true, "result": [] }).to_string()
                    } else if method == "GET" {
                        let (t, n) = (query(&path, "type").unwrap(), query(&path, "name").unwrap());
                        let found: Vec<Value> = st.records.iter().filter(|r| r["type"] == t && r["name"] == n).cloned().collect();
                        // 分頁：一頁最多 100 筆（跟 Cloudflare 一樣）
                        let per: usize = query(&path, "per_page").and_then(|v| v.parse().ok()).unwrap_or(100).min(100);
                        let page: usize = query(&path, "page").and_then(|v| v.parse().ok()).unwrap_or(1);
                        let total_pages = found.len().div_ceil(per).max(1);
                        let slice: Vec<Value> = found.iter().skip((page - 1) * per).take(per).cloned().collect();
                        json!({ "success": true, "result": slice,
                                "result_info": { "page": page, "per_page": per, "total_pages": total_pages, "total_count": found.len() } })
                        .to_string()
                    } else if method == "POST" {
                        let mut r: Value = serde_json::from_slice(&body).unwrap();
                        st.next_id += 1;
                        r["id"] = json!(format!("R{}", st.next_id));
                        st.records.push(r);
                        json!({ "success": true, "result": {} }).to_string()
                    } else if method == "DELETE" {
                        let id = path.rsplit('/').next().unwrap().to_string();
                        st.records.retain(|r| r["id"] != json!(id));
                        json!({ "success": true, "result": { "id": id } }).to_string()
                    } else {
                        let id = path.rsplit('/').next().unwrap().to_string();
                        let new: Value = serde_json::from_slice(&body).unwrap();
                        for r in st.records.iter_mut().filter(|r| r["id"] == json!(id)) {
                            for (k, v) in new.as_object().unwrap() {
                                r[k] = v.clone();
                            }
                        }
                        json!({ "success": true, "result": {} }).to_string()
                    }
                };
                let out = format!(
                    "HTTP/1.1 {code} {}\r\nContent-Length: {}\r\n\r\n{resp}",
                    if code == 200 { "OK" } else { "Error" },
                    resp.len()
                );
                let _ = s.write_all(out.as_bytes()).await;
            });
        }
    });
    addr
}

const NAME: &str = "home.example.com";

fn cfg(addr: SocketAddr, https: Option<&str>) -> Config {
    Config {
        api_token: "TOKEN".into(),
        records: vec![NAME.into()],
        url4: format!("http://{addr}/trace"),
        url6: format!("http://{addr}/trace"),
        api: format!("http://{addr}"),
        https_record: https.map(str::to_string),
        ..Default::default()
    }
}

fn state(ip: &str) -> Arc<Mutex<Cf>> {
    Arc::new(Mutex::new(Cf {
        ip: ip.into(),
        ..Default::default()
    }))
}

/// 假的網卡（位址的種類自己指定：測試時用 127.x 當「出口位址」）
fn iface(name: &str, up: bool, addrs: &[(&str, Scope)]) -> Iface {
    Iface {
        name: name.into(),
        label: name.into(),
        up,
        addrs: addrs
            .iter()
            .map(|(ip, scope)| Addr {
                ip: ip.parse().unwrap(),
                scope: *scope,
                temporary: false,
                deprecated: false,
            })
            .collect(),
    }
}

type Nics = Arc<Mutex<Vec<Iface>>>;

fn ddns_with(c: Config, nics: &Nics) -> Arc<Ddns> {
    let n = nics.clone();
    Ddns::with_netif(c, Arc::new(move || n.lock().unwrap().clone()))
}

fn actions(r: &Value, rtype: &str) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = r["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| x["type"] == rtype)
        .map(|x| {
            (
                x["content"].as_str().unwrap_or("").to_string(),
                x["action"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    v.sort();
    v
}

fn pair(ip: &str, action: &str) -> (String, String) {
    (ip.to_string(), action.to_string())
}

#[tokio::test]
async fn create_skip_update() {
    let st = state("203.0.113.5");
    let addr = mock(st.clone()).await;
    let d = Ddns::new(cfg(addr, Some("dns.example.com")));

    let r = d.update(false).await;
    assert_eq!(r["ip4"], "203.0.113.5");
    assert_eq!(r["ips4"], json!(["203.0.113.5"]));
    assert_eq!(
        r["sources"],
        json!([{ "interface": "", "family": 4, "ip": "203.0.113.5", "ok": true, "error": null }])
    );
    assert_eq!(r["records"][0]["action"], "created", "{r}");
    assert_eq!(r["records"][0]["content"], "203.0.113.5");
    assert_eq!(r["records"][1]["type"], "HTTPS");
    assert_eq!(r["records"][1]["action"], "created");
    {
        let s = st.lock().unwrap();
        assert!(s.calls.contains(&"GET /zones".to_string()));
        let https = s.records.iter().find(|x| x["type"] == "HTTPS").unwrap();
        assert_eq!(https["data"]["value"], "alpn=\"h3,h2\"");
        let a = s.records.iter().find(|x| x["type"] == "A").unwrap();
        assert_eq!(a["comment"], MARK, "自己建立的記錄有標記");
        assert_eq!((a["ttl"].as_u64(), a["proxied"].as_bool()), (Some(1), Some(false)));
    }

    // IP 沒變：不呼叫 API
    let before = st.lock().unwrap().calls.len();
    let r = d.update(false).await;
    assert_eq!(r["records"][0]["action"], "unchanged");
    assert_eq!(st.lock().unwrap().calls.len(), before + 1, "只問了 trace");

    // IP 變了：就地更新（不是刪掉再建）
    st.lock().unwrap().ip = "203.0.113.77".into();
    let r = d.update(false).await;
    assert_eq!(r["records"][0]["action"], "updated");
    assert_eq!(r["records"][0]["previous"], "203.0.113.5");
    let s = st.lock().unwrap();
    assert_eq!(s.contents("A", NAME), vec!["203.0.113.77"]);
    assert!(!s.calls.iter().any(|c| c.starts_with("DELETE")));
}

#[tokio::test]
async fn errors_are_reported() {
    let st = state("203.0.113.5");
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
    // 只填綁定網域（沒寫 site.hostname、沒寫記錄）：HTTPS 記錄與 A 記錄都用它
    let bound = json!({ "domain": "dns.example.com", "ddns": { "enabled": true, "apiToken": "x" }, "listen": { "doh": { "enabled": true, "http3": true } } });
    let c = Config::from_cfg(&kuroshio_config::with_overrides(&bound)).unwrap();
    assert_eq!(c.https_record.as_deref(), Some("dns.example.com"));
    assert_eq!(c.records, vec!["dns.example.com"]);
}

/// 兩個出口各有一個公網 IP：一個名稱兩筆 A 記錄；移除出口、換 IP、再加回來
#[tokio::test]
async fn multiple_egresses_as_a_record_set() {
    let st = state("");
    let addr = mock(st.clone()).await;
    let nics: Nics = Arc::new(Mutex::new(vec![
        iface("wan1", true, &[("203.0.113.5", Scope::Public), ("192.168.1.2", Scope::Private)]),
        iface("wan2", true, &[("198.51.100.7", Scope::Public)]),
    ]));
    let mut c = cfg(addr, None);
    c.ip_source = "interface".into();
    c.interfaces = vec![IfaceSel::both("wan1"), IfaceSel::both("wan2")];
    let d = ddns_with(c, &nics);
    // 其他類型、其他名稱的記錄：從頭到尾都不能動
    {
        let mut s = st.lock().unwrap();
        s.add("TXT", NAME, "v=spf1 -all", None);
        s.add("A", "other.example.com", "192.0.2.99", Some(MARK));
    }

    let r = d.update(false).await;
    assert_eq!(r["ips4"], json!(["198.51.100.7", "203.0.113.5"]));
    assert_eq!(r["sources"].as_array().unwrap().len(), 2);
    assert_eq!(r["sources"][0]["interface"], "wan1");
    assert_eq!(
        actions(&r, "A"),
        vec![pair("198.51.100.7", "created"), pair("203.0.113.5", "created")]
    );
    assert_eq!(st.lock().unwrap().contents("A", NAME), vec!["198.51.100.7", "203.0.113.5"]);

    // 沒變：不呼叫 API
    let before = st.lock().unwrap().calls.len();
    let r = d.update(false).await;
    assert_eq!(
        actions(&r, "A"),
        vec![pair("198.51.100.7", "unchanged"), pair("203.0.113.5", "unchanged")]
    );
    assert_eq!(st.lock().unwrap().calls.len(), before, "讀網卡不用連線，也沒有呼叫 API");

    // wan1 換 IP：改的是 wan1 原本那一筆，wan2 的不動
    nics.lock().unwrap()[0] = iface("wan1", true, &[("203.0.113.88", Scope::Public)]);
    let wan2_id = {
        let s = st.lock().unwrap();
        s.records.iter().find(|x| x["content"] == "198.51.100.7").unwrap()["id"].clone()
    };
    let r = d.update(false).await;
    let upd = r["records"].as_array().unwrap().iter().find(|x| x["action"] == "updated").unwrap();
    assert_eq!(
        (upd["content"].as_str(), upd["previous"].as_str()),
        (Some("203.0.113.88"), Some("203.0.113.5"))
    );
    {
        let s = st.lock().unwrap();
        assert_eq!(s.contents("A", NAME), vec!["198.51.100.7", "203.0.113.88"]);
        assert_eq!(s.records.iter().find(|x| x["content"] == "198.51.100.7").unwrap()["id"], wan2_id);
    }

    // wan2 不見了（線拔掉）：另一個出口還在，連續 3 次確定不在才刪
    nics.lock().unwrap().remove(1);
    for n in 1..=2 {
        let r = d.update(false).await;
        assert_eq!(
            actions(&r, "A"),
            vec![pair("198.51.100.7", "kept"), pair("203.0.113.88", "unchanged")],
            "第 {n} 次：先保留"
        );
        assert_eq!(st.lock().unwrap().contents("A", NAME).len(), 2);
    }
    assert_eq!(r_source_error(&d.status(), "wan2"), "找不到網卡 wan2");
    let r = d.update(false).await;
    assert_eq!(
        actions(&r, "A"),
        vec![pair("198.51.100.7", "deleted"), pair("203.0.113.88", "unchanged")]
    );
    assert_eq!(st.lock().unwrap().contents("A", NAME), vec!["203.0.113.88"]);

    // 中途回來的話計數歸零：加回 wan2 → 建立；再拔掉一次只算第 1 次
    nics.lock().unwrap().push(iface("wan2", true, &[("198.51.100.7", Scope::Public)]));
    let r = d.update(false).await;
    assert_eq!(
        actions(&r, "A"),
        vec![pair("198.51.100.7", "created"), pair("203.0.113.88", "unchanged")]
    );
    nics.lock().unwrap()[1].up = false;
    let r = d.update(false).await;
    assert_eq!(actions(&r, "A")[0], pair("198.51.100.7", "kept"));
    nics.lock().unwrap()[1].up = true;
    d.update(false).await;
    nics.lock().unwrap()[1].up = false;
    for _ in 0..2 {
        d.update(false).await;
    }
    assert_eq!(st.lock().unwrap().contents("A", NAME).len(), 2, "重新算起：2 次還不刪");

    // 其他類型、其他名稱完全沒被碰過
    let s = st.lock().unwrap();
    assert_eq!(s.contents("TXT", NAME), vec!["v=spf1 -all"]);
    assert_eq!(s.contents("A", "other.example.com"), vec!["192.0.2.99"]);
}

fn r_source_error(st: &Value, iface: &str) -> String {
    st["sources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["interface"] == iface)
        .and_then(|s| s["error"].as_str())
        .unwrap_or("")
        .to_string()
}

/// IPv6 預設不發布；打開才有 AAAA；關掉後下次執行刪掉自己發布的 AAAA（別人的不動）
#[tokio::test]
async fn ipv6_is_opt_in_and_removed_when_switched_off() {
    let st = state("");
    let addr = mock(st.clone()).await;
    let nics: Nics = Arc::new(Mutex::new(vec![iface(
        "wan",
        true,
        &[
            ("203.0.113.5", Scope::Public),
            ("2001:db8::5", Scope::Public),
            ("fe80::1", Scope::LinkLocal),
        ],
    )]));
    let mut c = cfg(addr, None);
    c.ip_source = "interface".into();
    c.interfaces = vec![IfaceSel::both("wan")];

    // 預設（ipv6 = false）：只有 A，而且不會去動原本就有的 AAAA（不是自己建立的）
    st.lock().unwrap().add("AAAA", NAME, "2001:db8::aaaa", None);
    let d = ddns_with(c.clone(), &nics);
    let r = d.update(false).await;
    assert_eq!(r["ip6"], Value::Null);
    assert_eq!(actions(&r, "A"), vec![pair("203.0.113.5", "created")]);
    assert!(actions(&r, "AAAA").is_empty());
    assert_eq!(
        st.lock().unwrap().contents("AAAA", NAME),
        vec!["2001:db8::aaaa"],
        "別人的 AAAA 不動"
    );
    assert_eq!(st.lock().unwrap().mutations(), 1, "只建立了一筆 A");
    // 之後每次執行不再重複檢查關掉的那一族
    let before = st.lock().unwrap().calls.len();
    d.update(false).await;
    assert_eq!(st.lock().unwrap().calls.len(), before);

    // 打開 IPv6：這個名稱的 AAAA 交給黑潮 DNS 管（跟 2.x 一樣接手原本那一筆，就地更新並標記）
    let mut on = c.clone();
    on.ipv6 = true;
    let d = ddns_with(on, &nics);
    let r = d.update(false).await;
    assert_eq!(r["ip6"], "2001:db8::5");
    assert_eq!(r["ips6"], json!(["2001:db8::5"]));
    assert_eq!(actions(&r, "AAAA"), vec![pair("2001:db8::5", "updated")]);
    assert_eq!(st.lock().unwrap().contents("AAAA", NAME), vec!["2001:db8::5"]);
    // 之後別人另外加的 AAAA（沒有標記）就不是自己的了
    st.lock().unwrap().add("AAAA", NAME, "2001:db8::aaaa", None);

    // 關掉 IPv6（設定重新載入 = 新的 Ddns）：下次執行就刪掉自己的 AAAA；A 與別人的 AAAA 不動
    let d = ddns_with(c, &nics);
    let r = d.update(false).await;
    assert_eq!(actions(&r, "AAAA"), vec![pair("2001:db8::5", "deleted")]);
    let s = st.lock().unwrap();
    assert_eq!(s.contents("AAAA", NAME), vec!["2001:db8::aaaa"]);
    assert_eq!(s.contents("A", NAME), vec!["203.0.113.5"]);
}

/// 問不到公網 IP（整族失敗）：完全不動，保留上次的記錄
#[tokio::test]
async fn detection_failure_keeps_records() {
    let st = state("203.0.113.5");
    let addr = mock(st.clone()).await;
    let d = Ddns::new(cfg(addr, None));
    d.update(false).await;
    assert_eq!(st.lock().unwrap().contents("A", NAME), vec!["203.0.113.5"]);
    let before = st.lock().unwrap().mutations();

    st.lock().unwrap().fail_all = true;
    for force in [false, true, true, true] {
        let r = d.update(force).await;
        assert_eq!(r["ip4"], Value::Null);
        assert_eq!(r["records"][0]["action"], "skip", "{r}");
        assert_eq!(r["records"][0]["ok"], false);
        assert!(r["error"].as_str().unwrap().contains("500"), "{r}");
        assert_eq!(r["sources"][0]["ok"], false);
    }
    let s = st.lock().unwrap();
    assert_eq!(s.contents("A", NAME), vec!["203.0.113.5"], "記錄還在");
    assert_eq!(s.mutations(), before, "沒有呼叫任何會改記錄的 API");
}

/// 從每個出口各問一次（綁來源位址）；其中一個出口問不到時保留它的記錄，確定不在了才刪
#[cfg(target_os = "linux")]
#[tokio::test]
async fn web_detection_per_interface() {
    let st = state("");
    {
        let mut s = st.lock().unwrap();
        s.by_peer.insert("127.0.0.1".parse().unwrap(), "203.0.113.5".into());
        s.by_peer.insert("127.0.0.2".parse().unwrap(), "198.51.100.7".into());
    }
    let addr = mock(st.clone()).await;
    // 兩張「網卡」的出口位址分別是 127.0.0.1 與 127.0.0.2（模擬的 trace 依來源位址回不同的公網 IP）
    let nics: Nics = Arc::new(Mutex::new(vec![
        iface("test-wan-a", true, &[("127.0.0.1", Scope::Private)]),
        iface("test-wan-b", true, &[("127.0.0.2", Scope::Private)]),
    ]));
    let mut c = cfg(addr, None);
    c.interfaces = vec![IfaceSel::both("test-wan-a"), IfaceSel::both("test-wan-b")];
    let d = ddns_with(c, &nics);

    let r = d.update(false).await;
    assert_eq!(
        r["sources"],
        json!([
            { "interface": "test-wan-a", "family": 4, "ip": "203.0.113.5", "ok": true, "error": null },
            { "interface": "test-wan-b", "family": 4, "ip": "198.51.100.7", "ok": true, "error": null },
        ]),
        "每個出口問到的是自己的公網 IP"
    );
    assert_eq!(st.lock().unwrap().contents("A", NAME), vec!["198.51.100.7", "203.0.113.5"]);

    // 出口 b 問不到（不確定它還在不在）：記錄保留，跑再多次都不刪
    st.lock().unwrap().fail_peers.insert("127.0.0.2".parse().unwrap());
    let before = st.lock().unwrap().mutations();
    for _ in 0..5 {
        let r = d.update(true).await;
        assert_eq!(r["ips4"], json!(["203.0.113.5"]));
        assert_eq!(r["sources"][1]["ok"], false);
        assert_eq!(
            actions(&r, "A"),
            vec![pair("198.51.100.7", "unchanged"), pair("203.0.113.5", "unchanged")]
        );
    }
    assert_eq!(st.lock().unwrap().mutations(), before);

    // 出口 a 換 IP、b 還是問不到：只改 a 那一筆
    st.lock()
        .unwrap()
        .by_peer
        .insert("127.0.0.1".parse().unwrap(), "203.0.113.66".into());
    let r = d.update(false).await;
    assert_eq!(
        actions(&r, "A"),
        vec![pair("198.51.100.7", "unchanged"), pair("203.0.113.66", "updated")]
    );

    // 出口 b 的網卡不見了（確定沒有）：3 次後刪除
    nics.lock().unwrap().remove(1);
    for _ in 0..2 {
        d.update(false).await;
        assert_eq!(st.lock().unwrap().contents("A", NAME).len(), 2);
    }
    d.update(false).await;
    assert_eq!(st.lock().unwrap().contents("A", NAME), vec!["203.0.113.66"]);
}

/// 重新啟動後（不記得上次的 IP）有出口問不到：不知道舊記錄是誰的，不刪也不改寫，只補上新的
#[cfg(target_os = "linux")]
#[tokio::test]
async fn unknown_state_after_restart_does_not_rewrite() {
    let st = state("");
    {
        let mut s = st.lock().unwrap();
        s.by_peer.insert("127.0.0.1".parse().unwrap(), "203.0.113.66".into());
        s.fail_peers.insert("127.0.0.2".parse().unwrap());
        s.add("A", NAME, "203.0.113.5", Some(MARK));
        s.add("A", NAME, "198.51.100.7", Some(MARK));
    }
    let addr = mock(st.clone()).await;
    let nics: Nics = Arc::new(Mutex::new(vec![
        iface("test-wan-a", true, &[("127.0.0.1", Scope::Private)]),
        iface("test-wan-b", true, &[("127.0.0.2", Scope::Private)]),
    ]));
    let mut c = cfg(addr, None);
    c.interfaces = vec![IfaceSel::both("test-wan-a"), IfaceSel::both("test-wan-b")];
    let d = ddns_with(c, &nics);
    for _ in 0..4 {
        d.update(false).await;
    }
    assert_eq!(
        st.lock().unwrap().contents("A", NAME),
        vec!["198.51.100.7", "203.0.113.5", "203.0.113.66"],
        "舊的兩筆都保留，新 IP 另外建立"
    );
    // 出口 b 恢復：現在確定了，沒人用的 203.0.113.5 連續 3 次後刪除
    st.lock().unwrap().fail_peers.clear();
    st.lock()
        .unwrap()
        .by_peer
        .insert("127.0.0.2".parse().unwrap(), "198.51.100.7".into());
    for _ in 0..3 {
        d.update(false).await;
    }
    assert_eq!(st.lock().unwrap().contents("A", NAME), vec!["198.51.100.7", "203.0.113.66"]);
}

/// 超過 100 筆記錄（分頁）：第二頁的也讀得到，不會重複建立
#[tokio::test]
async fn pagination_over_100_records() {
    let st = state("203.0.113.5");
    {
        let mut s = st.lock().unwrap();
        for i in 0..130 {
            s.add("A", NAME, &format!("192.0.2.{}", i % 250 + 1), None);
        }
        // 自己的記錄排在第二頁
        s.add("A", NAME, "203.0.113.5", Some(MARK));
    }
    let addr = mock(st.clone()).await;
    let d = Ddns::new(cfg(addr, None));
    let r = d.update(false).await;
    let s = st.lock().unwrap();
    assert_eq!(
        s.calls.iter().filter(|c| *c == "GET /zones/Z1/dns_records").count(),
        3,
        "A 記錄讀了兩頁（另外一次是檢查沒開的 AAAA）"
    );
    assert_eq!(s.mutations(), 0, "已經有了：不建立、不刪除");
    assert_eq!(s.records.len(), 131);
    let all = r["records"].as_array().unwrap();
    assert_eq!(all.iter().filter(|x| x["action"] == "unchanged").count(), 1);
    assert_eq!(all.iter().filter(|x| x["action"] == "kept").count(), 130, "別人的 130 筆都沒動");
}

/// 舊版建立的記錄（沒有標記）：第一次接手時就地更新並標記；之後別人手動加的記錄不動
#[tokio::test]
async fn legacy_takeover_and_foreign_records() {
    let st = state("203.0.113.5");
    st.lock().unwrap().add("A", NAME, "203.0.113.1", None);
    let addr = mock(st.clone()).await;
    let d = Ddns::new(cfg(addr, None));
    let r = d.update(false).await;
    assert_eq!(r["records"][0]["action"], "updated");
    assert_eq!(r["records"][0]["previous"], "203.0.113.1");
    {
        let s = st.lock().unwrap();
        assert_eq!(s.contents("A", NAME), vec!["203.0.113.5"]);
        assert_eq!(s.records[0]["comment"], MARK, "接手後標記成自己的");
    }
    // 內容一樣但沒標記（升級後第一次執行）：只補標記，不算變更
    st.lock().unwrap().records[0]["comment"] = Value::Null;
    let r = Ddns::new(cfg(addr, None)).update(false).await;
    assert_eq!(r["records"][0]["action"], "unchanged");
    assert_eq!(st.lock().unwrap().records[0]["comment"], MARK);
    // 代理 / TTL 被改掉：改回設定的值
    st.lock().unwrap().records[0]["ttl"] = json!(300);
    let r = Ddns::new(cfg(addr, None)).update(false).await;
    assert_eq!(r["records"][0]["action"], "updated");
    assert_eq!(st.lock().unwrap().records[0]["ttl"], 1);

    // 有人手動加了另一筆 A：不是自己的，跑再多次都不刪、IP 變了也不會改到它
    st.lock().unwrap().add("A", NAME, "192.0.2.50", None);
    let d = Ddns::new(cfg(addr, None));
    for _ in 0..4 {
        d.update(true).await;
    }
    st.lock().unwrap().ip = "203.0.113.9".into();
    let r = d.update(false).await;
    assert_eq!(actions(&r, "A"), vec![pair("192.0.2.50", "kept"), pair("203.0.113.9", "updated")]);
    assert_eq!(st.lock().unwrap().contents("A", NAME), vec!["192.0.2.50", "203.0.113.9"]);
}
