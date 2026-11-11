//! DNR（RFC 9463）：路由器用 DHCP / RA 直接告訴區網裝置「這裡有加密 DNS」，裝置不用手動設定就會改用 DoH / DoT / DoQ
//!
//! 跟 DDR（RFC 9462，裝置自己來問 `_dns.resolver.arpa`）互補。這裡只負責算出要發的內容，
//! 由 OpenWrt 的接管腳本（takeover.sh）寫進 DHCP 設定：
//! - IPv4：dnsmasq 還沒有原生支援，用原始的 DHCP 選項 162（十六進位）
//! - IPv6（RA 與 DHCPv6）：odhcpd 的 `list dnr '<優先順序> <網域> <IP,…> <參數>…'`（OpenWrt 25.12 起；舊版會忽略）
//!
//! 裝置會用網域（ADN）驗證憑證，所以只有「網域有設定、憑證存在而且涵蓋這個網域、加密監聽有開」才會發；
//! 位址只列監聽實際涵蓋的（例如 DoT 只聽 IPv4 就不會列 IPv6 位址）。寧可不發，也不發一個連不上的。

use kuroshio_config::get;
use kuroshio_proto::logic::DdrEndpoint;
use serde_json::{json, Value};
use std::net::IpAddr;
use std::path::Path;

/// 一種加密協議要發的內容
#[derive(Debug, Clone)]
pub struct Instance {
    pub priority: u16,
    pub ep: DdrEndpoint,
    /// 這個協議的監聽涵蓋的區網位址
    pub addrs: Vec<IpAddr>,
}

#[derive(Debug, Clone, Default)]
pub struct Plan {
    pub adn: String,
    pub instances: Vec<Instance>,
    /// 沒有東西可發的原因
    pub reason: Option<String>,
}

fn s(cfg: &Value, k: &str) -> String {
    get(cfg, k).and_then(Value::as_str).unwrap_or("").trim().to_string()
}

fn on(cfg: &Value, k: &str) -> bool {
    get(cfg, k).and_then(Value::as_bool).unwrap_or(false)
}

fn port(cfg: &Value, k: &str, d: u16) -> u16 {
    get(cfg, k)
        .and_then(Value::as_u64)
        .map(|p| p as u16)
        .filter(|p| *p != 0)
        .unwrap_or(d)
}

/// 這個監聽（`listen.<proto>`）有沒有涵蓋某個位址：`binds`（有的話）或 `host`
fn covers(cfg: &Value, proto: &str, ip: IpAddr) -> bool {
    let mut hosts: Vec<IpAddr> = get(cfg, &format!("listen.{proto}.binds"))
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).filter_map(|h| h.parse().ok()).collect())
        .unwrap_or_default();
    if hosts.is_empty() {
        hosts.extend(s(cfg, &format!("listen.{proto}.host")).parse::<IpAddr>().ok());
    }
    hosts
        .iter()
        .any(|h| *h == ip || (h.is_unspecified() && h.is_ipv4() == ip.is_ipv4()))
}

/// 這個監聽用的憑證檔（各自指定的優先，再來是共用的 `tls.cert`）
fn cert_of(cfg: &Value, proto: &str, base: &Path) -> Option<std::path::PathBuf> {
    let p = [s(cfg, &format!("listen.{proto}.cert")), s(cfg, "tls.cert")]
        .into_iter()
        .find(|p| !p.is_empty())?;
    let p = Path::new(&p);
    Some(if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p.strip_prefix("./").unwrap_or(p))
    })
}

/// 依設定算出要發的內容。`lan`：路由器的區網位址；`base`：相對路徑的基準（設定檔所在的資料夾）
pub fn plan(cfg: &Value, lan: &[IpAddr], base: &Path) -> Plan {
    let adn = [s(cfg, "site.hostname"), s(cfg, "domain")]
        .into_iter()
        .find(|d| !d.is_empty())
        .unwrap_or_default()
        .trim_end_matches('.')
        .to_lowercase();
    let fail = |why: &str| Plan {
        adn: adn.clone(),
        instances: vec![],
        reason: Some(why.to_string()),
    };
    if adn.is_empty() {
        return fail("沒有設定網域（裝置要用網域驗證憑證）");
    }
    if adn.len() > 253 || adn.split('.').any(|l| l.is_empty() || l.len() > 63) {
        return fail("網域格式不對");
    }
    if lan.is_empty() {
        return fail("不知道路由器的區網位址");
    }
    // 憑證要存在、沒過期、而且涵蓋這個網域：否則裝置連得上也會驗證失敗
    let cert_ok = |proto: &str| -> Result<(), String> {
        let c = cert_of(cfg, proto, base).ok_or("沒有憑證")?;
        match crate::acme::renewal_reason(&c, std::slice::from_ref(&adn), 0) {
            None => Ok(()),
            Some(why) => Err(format!("憑證 {}：{why}", c.display())),
        }
    };
    let path = match s(cfg, "listen.doh.path") {
        p if p.is_empty() => "/dns-query".to_string(),
        p => p,
    };
    let mut eps: Vec<(&str, DdrEndpoint)> = Vec::new();
    let mut problems: Vec<String> = Vec::new();
    // 順序同 DDR：DoH（同埠有 HTTP/3 就一起）、DoT、DoQ
    if on(cfg, "listen.doh.enabled") && crate::console::doh_tls(cfg) {
        match cert_ok("doh") {
            Ok(()) => {
                let p = port(cfg, "listen.doh.port", 443);
                let h3 = on(cfg, "listen.doh.http3");
                let h3_port = port(cfg, "listen.doh.http3Port", p);
                let dohpath = Some(format!("{path}{{?dns}}"));
                let mut alpn = vec!["h2".to_string()];
                if h3 && h3_port == p {
                    alpn.push("h3".into());
                }
                eps.push((
                    "doh",
                    DdrEndpoint {
                        alpn,
                        port: p,
                        dohpath: dohpath.clone(),
                    },
                ));
                if h3 && h3_port != p {
                    eps.push((
                        "doh",
                        DdrEndpoint {
                            alpn: vec!["h3".into()],
                            port: h3_port,
                            dohpath,
                        },
                    ));
                }
            }
            Err(e) => problems.push(format!("DoH：{e}")),
        }
    }
    if on(cfg, "listen.dot.enabled") {
        match cert_ok("dot") {
            Ok(()) => eps.push((
                "dot",
                DdrEndpoint {
                    alpn: vec!["dot".into()],
                    port: port(cfg, "listen.dot.port", 853),
                    dohpath: None,
                },
            )),
            Err(e) => problems.push(format!("DoT：{e}")),
        }
    }
    if on(cfg, "listen.doq.enabled") {
        // DoQ 跟 DoT 共用憑證（沒有 DoT 憑證時用 DoH 的）
        match cert_ok("dot").or_else(|_| cert_ok("doh")) {
            Ok(()) => eps.push((
                "doq",
                DdrEndpoint {
                    alpn: vec!["doq".into()],
                    port: port(cfg, "listen.doq.port", 853),
                    dohpath: None,
                },
            )),
            Err(e) => problems.push(format!("DoQ：{e}")),
        }
    }
    let instances: Vec<Instance> = eps
        .into_iter()
        .filter_map(|(proto, ep)| {
            let addrs: Vec<IpAddr> = lan.iter().copied().filter(|ip| covers(cfg, proto, *ip)).collect();
            (!addrs.is_empty()).then_some((ep, addrs))
        })
        .enumerate()
        .map(|(i, (ep, addrs))| Instance {
            priority: i as u16 + 1,
            ep,
            addrs,
        })
        .collect();
    let reason = instances.is_empty().then(|| {
        if problems.is_empty() {
            "沒有加密監聽（DoH / DoT / DoQ）涵蓋區網位址".to_string()
        } else {
            problems.join("；")
        }
    });
    Plan { adn, instances, reason }
}

/// SvcParams（RFC 9460 線上格式，key 由小到大：1 alpn、3 port、7 dohpath）
fn svc_params(ep: &DdrEndpoint) -> Vec<u8> {
    let mut b = Vec::new();
    let mut alpn = Vec::new();
    for a in &ep.alpn {
        alpn.push(a.len() as u8);
        alpn.extend_from_slice(a.as_bytes());
    }
    let mut param = |key: u16, val: &[u8]| {
        b.extend_from_slice(&key.to_be_bytes());
        b.extend_from_slice(&(val.len() as u16).to_be_bytes());
        b.extend_from_slice(val);
    };
    param(1, &alpn);
    param(3, &ep.port.to_be_bytes());
    if let Some(p) = &ep.dohpath {
        param(7, p.as_bytes());
    }
    b
}

fn adn_wire(adn: &str) -> Vec<u8> {
    let mut b = Vec::new();
    for l in adn.split('.') {
        b.push(l.len() as u8);
        b.extend_from_slice(l.as_bytes());
    }
    b.push(0);
    b
}

impl Plan {
    /// DHCPv4 選項 162 的內容（RFC 9463 第 5.1 節）：每個協議一筆
    /// `長度(2) 優先順序(2) ADN 長度(1) ADN 位址長度(1) IPv4… SvcParams`。
    /// 一個 DHCP 選項最多 255 bytes：放不下時從優先順序最低的開始捨棄。沒有 IPv4 位址時回 None。
    pub fn dhcpv4(&self) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        for i in &self.instances {
            let v4: Vec<u8> = i
                .addrs
                .iter()
                .filter_map(|a| match a {
                    IpAddr::V4(v) => Some(v.octets()),
                    IpAddr::V6(_) => None,
                })
                .flatten()
                .collect();
            if v4.is_empty() {
                continue;
            }
            let adn = adn_wire(&self.adn);
            let mut d = i.priority.to_be_bytes().to_vec();
            d.push(adn.len() as u8);
            d.extend_from_slice(&adn);
            d.push(v4.len() as u8);
            d.extend_from_slice(&v4);
            d.extend_from_slice(&svc_params(&i.ep));
            if out.len() + 2 + d.len() > 255 {
                break;
            }
            out.extend_from_slice(&(d.len() as u16).to_be_bytes());
            out.extend_from_slice(&d);
        }
        (!out.is_empty()).then_some(out)
    }

    /// odhcpd 的 `list dnr`（RA、DHCPv6，以及 odhcpd 管 DHCPv4 時）。
    /// RA / DHCPv6 的 DNR 只能帶 IPv6 位址：沒有 IPv6 位址的協議不列（免得裝置拿到只有網域、沒有位址的通告）
    pub fn odhcpd(&self) -> Vec<String> {
        self.instances
            .iter()
            .filter(|i| i.addrs.iter().any(IpAddr::is_ipv6))
            .map(|i| {
                let addrs: Vec<String> = i.addrs.iter().map(IpAddr::to_string).collect();
                let mut v = vec![
                    i.priority.to_string(),
                    self.adn.clone(),
                    addrs.join(","),
                    format!("alpn={}", i.ep.alpn.join(",")),
                ];
                v.push(format!("port={}", i.ep.port));
                if let Some(p) = &i.ep.dohpath {
                    v.push(format!("dohpath={p}"));
                }
                v.join(" ")
            })
            .collect()
    }

    /// `kuroshio dnr` 的輸出
    pub fn json(&self) -> Value {
        let hex = self
            .dhcpv4()
            .map(|b| b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":"));
        json!({
            "ok": !self.instances.is_empty(),
            "reason": self.reason,
            "adn": self.adn,
            "dhcpv4": hex,
            "odhcpd": self.odhcpd(),
            "protocols": self.instances.iter().map(|i| json!({
                "priority": i.priority, "alpn": i.ep.alpn, "port": i.ep.port, "dohpath": i.ep.dohpath,
                "addrs": i.addrs,
            })).collect::<Vec<_>>(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn plan_of(instances: Vec<Instance>) -> Plan {
        Plan {
            adn: "dns.example.net".into(),
            instances,
            reason: None,
        }
    }

    fn dot(addrs: &[&str]) -> Instance {
        Instance {
            priority: 1,
            ep: DdrEndpoint {
                alpn: vec!["dot".into()],
                port: 853,
                dohpath: None,
            },
            addrs: addrs.iter().map(|a| ip(a)).collect(),
        }
    }

    #[test]
    fn dhcpv4_wire_format() {
        let p = plan_of(vec![dot(&["192.168.1.1", "fd00::1"])]);
        let b = p.dhcpv4().unwrap();
        #[rustfmt::skip]
        let want: Vec<u8> = vec![
            0x00, 0x27,                                     // 這一筆後面的長度：2 + 1 + 17 + 1 + 4 + 14 = 39
            0x00, 0x01,                                     // 優先順序 1
            0x11,                                           // ADN 長度 17
            3, b'd', b'n', b's', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'n', b'e', b't', 0,
            0x04, 192, 168, 1, 1,                           // IPv4 位址（IPv6 的不放）
            0x00, 0x01, 0x00, 0x04, 3, b'd', b'o', b't',    // alpn=dot
            0x00, 0x03, 0x00, 0x02, 0x03, 0x55,             // port=853
        ];
        assert_eq!(b, want);
        // 只有 IPv6 位址：DHCPv4 沒有東西可發
        assert_eq!(plan_of(vec![dot(&["fd00::1"])]).dhcpv4(), None);
    }

    #[test]
    fn dhcpv4_drops_low_priority_when_too_long() {
        let long = format!("{}.example.net", "a".repeat(60));
        let mk = |prio: u16| Instance {
            priority: prio,
            ep: DdrEndpoint {
                alpn: vec!["h2".into(), "h3".into()],
                port: 8443,
                dohpath: Some("/dns-query{?dns}".into()),
            },
            addrs: vec![ip("192.168.1.1")],
        };
        let p = Plan {
            adn: long,
            instances: vec![mk(1), mk(2), mk(3)],
            reason: None,
        };
        let b = p.dhcpv4().unwrap();
        assert!(b.len() <= 255);
        // 逐筆走訪：長度欄位要剛好接起來，而且至少留下第一筆
        let (mut i, mut n) = (0, 0);
        while i < b.len() {
            i += 2 + u16::from_be_bytes([b[i], b[i + 1]]) as usize;
            n += 1;
        }
        assert_eq!(i, b.len());
        assert!((1..3).contains(&n), "{n}");
    }

    #[test]
    fn odhcpd_entries() {
        let doh = Instance {
            priority: 1,
            ep: DdrEndpoint {
                alpn: vec!["h2".into(), "h3".into()],
                port: 8443,
                dohpath: Some("/dns-query{?dns}".into()),
            },
            addrs: vec![ip("192.168.1.1"), ip("fd00::1")],
        };
        let mut v4only = dot(&["192.168.1.1"]);
        v4only.priority = 2;
        let p = plan_of(vec![doh, v4only]);
        assert_eq!(
            p.odhcpd(),
            vec!["1 dns.example.net 192.168.1.1,fd00::1 alpn=h2,h3 port=8443 dohpath=/dns-query{?dns}"],
            "沒有 IPv6 位址的協議不列"
        );
    }

    #[test]
    fn plan_requires_domain_cert_and_reachable_listener() {
        let dir = std::env::temp_dir().join(format!("kuroshio-dnr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ck = rcgen::generate_simple_self_signed(vec!["dns.example.net".into()]).unwrap();
        std::fs::write(dir.join("cert.pem"), ck.cert.pem()).unwrap();
        let lan = [ip("192.168.1.1"), ip("fd00::1")];
        let cfg = |extra: Value| {
            let mut c = json!({
                "domain": "dns.example.net",
                "tls": { "cert": "./cert.pem", "key": "./key.pem" },
                "listen": {
                    "doh": { "enabled": true, "host": "0.0.0.0", "port": 8443, "http3": true, "path": "/dns-query" },
                    "dot": { "enabled": true, "host": "0.0.0.0", "port": 853 },
                    "doq": { "enabled": true, "host": "0.0.0.0", "port": 853, "binds": ["0.0.0.0", "::"] }
                }
            });
            if let (Some(a), Some(b)) = (c.as_object_mut(), extra.as_object()) {
                for (k, v) in b {
                    a.insert(k.clone(), v.clone());
                }
            }
            c
        };
        let p = plan(&cfg(json!({})), &lan, &dir);
        assert_eq!(p.reason, None);
        let got: Vec<(u16, String, u16, usize)> = p
            .instances
            .iter()
            .map(|i| (i.priority, i.ep.alpn.join(","), i.ep.port, i.addrs.len()))
            .collect();
        // DoH、DoT 只聽 IPv4；DoQ 兩種都聽
        assert_eq!(
            got,
            vec![(1, "h2,h3".into(), 8443, 1), (2, "dot".into(), 853, 1), (3, "doq".into(), 853, 2)]
        );
        assert_eq!(p.odhcpd(), vec!["3 dns.example.net 192.168.1.1,fd00::1 alpn=doq port=853"]);
        assert!(p.json()["dhcpv4"].as_str().unwrap().starts_with("00:"));

        // 沒有網域
        assert!(plan(&cfg(json!({ "domain": "" })), &lan, &dir).reason.unwrap().contains("網域"));
        // 憑證不涵蓋這個網域：不發
        let p = plan(&cfg(json!({ "domain": "other.example.org" })), &lan, &dir);
        assert!(p.instances.is_empty() && p.reason.unwrap().contains("憑證"), "憑證不符就不發");
        // 憑證不存在
        let p = plan(&cfg(json!({ "tls": { "cert": "./none.pem" } })), &lan, &dir);
        assert!(p.instances.is_empty());
        // 只聽本機：區網裝置連不到，不發
        let mut c = cfg(json!({}));
        for k in ["doh", "dot", "doq"] {
            c["listen"][k]["host"] = json!("127.0.0.1");
            c["listen"][k].as_object_mut().unwrap().remove("binds");
        }
        let p = plan(&c, &lan, &dir);
        assert!(p.instances.is_empty() && p.reason.unwrap().contains("區網位址"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
