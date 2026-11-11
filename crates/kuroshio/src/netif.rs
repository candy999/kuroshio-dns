//! 本機網卡（Linux / Windows 共用）：名稱、位址與位址的種類
//!
//! - 多網卡、多條對外線路時，DDNS 與 ECS 子網路要知道「哪一張網卡、哪一個位址」才能指定出口
//! - 設定頁用 `GET /api/interfaces` 列出來給使用者選（`ddns.interfaces`）
//! - 列舉用 `if-addrs`（Unix：`getifaddrs`；Windows：`GetAdaptersAddresses`），不呼叫外部指令
//! - Linux 另外讀 `/proc/net/if_inet6` 分辨 IPv6 的臨時位址（隱私延伸）與已淘汰的位址；
//!   Windows 分不出來（`temporary` 一律是 false）

use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// 位址的種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// 公網位址（可以直接發布到 DNS）
    Public,
    /// 私有位址（10/8、172.16/12、192.168/16，以及其他不會出現在網際網路上的保留範圍）
    Private,
    /// 電信商的 CGNAT（100.64.0.0/10）：外面連不進來
    Cgnat,
    /// 鏈路本地（169.254/16、fe80::/10）
    LinkLocal,
    /// IPv6 的區網位址（fc00::/7）
    Ula,
    Loopback,
}

impl Scope {
    pub fn name(self) -> &'static str {
        match self {
            Scope::Public => "public",
            Scope::Private => "private",
            Scope::Cgnat => "cgnat",
            Scope::LinkLocal => "linklocal",
            Scope::Ula => "ula",
            Scope::Loopback => "loopback",
        }
    }
}

fn classify_v4(v: Ipv4Addr) -> Scope {
    let o = v.octets();
    if v.is_loopback() {
        Scope::Loopback
    } else if v.is_link_local() {
        Scope::LinkLocal
    } else if o[0] == 100 && (64..128).contains(&o[1]) {
        Scope::Cgnat
    } else if v.is_private()
        || v.is_unspecified()
        || v.is_broadcast()
        || v.is_multicast()
        || o[0] == 0
        || o[0] >= 240
        // 192.0.0.0/24（DS-Lite 等協定保留）、198.18.0.0/15（測試用）
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
    {
        Scope::Private
    } else {
        Scope::Public
    }
}

fn classify_v6(v: Ipv6Addr) -> Scope {
    if let Some(v4) = v.to_ipv4_mapped() {
        return classify_v4(v4);
    }
    let s = v.segments()[0];
    if v.is_loopback() {
        Scope::Loopback
    } else if (s & 0xffc0) == 0xfe80 {
        Scope::LinkLocal
    } else if (s & 0xfe00) == 0xfc00 {
        Scope::Ula
    } else if (s & 0xe000) == 0x2000 {
        // 全球單點位址 2000::/3
        Scope::Public
    } else {
        Scope::Private
    }
}

/// 這個位址屬於哪一種
pub fn classify(ip: IpAddr) -> Scope {
    match ip {
        IpAddr::V4(v) => classify_v4(v),
        IpAddr::V6(v) => classify_v6(v),
    }
}

/// 是不是公網位址（私有、迴路、鏈路本地、CGNAT、ULA 都不算）
pub fn is_public(ip: IpAddr) -> bool {
    classify(ip) == Scope::Public
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Addr {
    pub ip: IpAddr,
    pub scope: Scope,
    /// IPv6 臨時位址（隱私延伸，每天會換）：不適合發布到 DNS
    pub temporary: bool,
    /// 已淘汰（preferred lifetime 用完）：不再用來建立新連線
    pub deprecated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Iface {
    /// 設定裡用的名稱（Linux：`eth0`、`pppoe-wan`；Windows：連線名稱，例如「乙太網路」）
    pub name: String,
    /// 顯示用的名稱
    pub label: String,
    pub up: bool,
    pub addrs: Vec<Addr>,
}

impl Iface {
    /// 這張網卡上可以發布的公網位址。IPv6 有穩定位址時不用臨時 / 已淘汰的位址。
    pub fn public_addrs(&self, v6: bool) -> Vec<IpAddr> {
        let all: Vec<&Addr> = self
            .addrs
            .iter()
            .filter(|a| a.ip.is_ipv6() == v6 && a.scope == Scope::Public)
            .collect();
        let stable: Vec<IpAddr> = all.iter().filter(|a| !a.temporary && !a.deprecated).map(|a| a.ip).collect();
        if !stable.is_empty() {
            return stable;
        }
        let usable: Vec<IpAddr> = all.iter().filter(|a| !a.deprecated).map(|a| a.ip).collect();
        if !usable.is_empty() {
            return usable;
        }
        all.iter().map(|a| a.ip).collect()
    }

    /// 從這張網卡連出去時要綁的來源位址：公網（穩定的優先）→ CGNAT / 私有（在 NAT 後面）→ ULA。
    /// 鏈路本地與迴路位址連不到網際網路，不用。
    pub fn source_addr(&self, v6: bool) -> Option<IpAddr> {
        if let Some(ip) = self.public_addrs(v6).first() {
            return Some(*ip);
        }
        [Scope::Cgnat, Scope::Private, Scope::Ula].iter().find_map(|s| {
            self.addrs
                .iter()
                .find(|a| a.ip.is_ipv6() == v6 && a.scope == *s && !a.deprecated)
                .map(|a| a.ip)
        })
    }
}

/// Linux：`/proc/net/if_inet6` 的旗標（IFA_F_TEMPORARY = 0x01、IFA_F_DEPRECATED = 0x20）
/// 每行：32 個十六進位字元的位址、介面編號、前綴長度、範圍、旗標、介面名稱
pub fn parse_inet6_flags(text: &str) -> Vec<(Ipv6Addr, bool, bool)> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 6 || f[0].len() != 32 || !f[0].is_ascii() {
                return None;
            }
            let raw = u128::from_str_radix(f[0], 16).ok()?;
            let flags = u32::from_str_radix(f[4], 16).ok()?;
            Some((Ipv6Addr::from(raw), flags & 0x01 != 0, flags & 0x20 != 0))
        })
        .collect()
}

fn inet6_flags() -> Vec<(Ipv6Addr, bool, bool)> {
    if cfg!(any(target_os = "linux", target_os = "android")) {
        std::fs::read_to_string("/proc/net/if_inet6")
            .map(|t| parse_inet6_flags(&t))
            .unwrap_or_default()
    } else {
        Vec::new()
    }
}

/// 把（網卡名稱, 是否運作中, 位址）整理成每張網卡一筆；順序照第一次出現的順序
fn group(raw: impl IntoIterator<Item = (String, bool, IpAddr)>, flags: &[(Ipv6Addr, bool, bool)]) -> Vec<Iface> {
    let mut out: Vec<Iface> = Vec::new();
    for (name, up, ip) in raw {
        let (temporary, deprecated) = match ip {
            IpAddr::V6(v) => flags.iter().find(|f| f.0 == v).map(|f| (f.1, f.2)).unwrap_or((false, false)),
            IpAddr::V4(_) => (false, false),
        };
        let addr = Addr {
            ip,
            scope: classify(ip),
            temporary,
            deprecated,
        };
        match out.iter_mut().find(|i| i.name == name) {
            Some(i) => {
                i.up |= up;
                if !i.addrs.iter().any(|a| a.ip == ip) {
                    i.addrs.push(addr);
                }
            }
            None => out.push(Iface {
                label: name.clone(),
                name,
                up,
                addrs: vec![addr],
            }),
        }
    }
    out
}

/// 讀網卡清單最多等多久。系統呼叫平常幾毫秒就回來；
/// 但在某些環境（例如 QEMU 模擬大端序 MIPS）netlink 會一直不回，不能讓呼叫端跟著卡住
const IFADDRS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// 同一時間只讓一個讀取在進行：卡住的那一個沒結束前，不再開新的執行緒
static IFADDRS_BUSY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// `if_addrs::get_if_addrs()`，但在另一條執行緒做、最多等 `IFADDRS_TIMEOUT`
pub fn if_addrs_bounded() -> std::io::Result<Vec<if_addrs::Interface>> {
    use std::sync::atomic::Ordering;
    if IFADDRS_BUSY.swap(true, Ordering::AcqRel) {
        return Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "上一次讀取網卡清單還沒結束"));
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let spawned = std::thread::Builder::new().name("ifaddrs".into()).spawn(move || {
        let r = if_addrs::get_if_addrs();
        IFADDRS_BUSY.store(false, Ordering::Release);
        let _ = tx.send(r);
    });
    if let Err(e) = spawned {
        IFADDRS_BUSY.store(false, Ordering::Release);
        return Err(e);
    }
    rx.recv_timeout(IFADDRS_TIMEOUT)
        .unwrap_or_else(|_| Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "讀網卡清單超過 2 秒沒有回應")))
}

/// 列出本機所有有位址的網卡（讀不到時回空清單）
pub fn list() -> Vec<Iface> {
    match if_addrs_bounded() {
        Ok(v) => group(v.into_iter().map(|i| (i.name.clone(), i.is_oper_up(), i.ip())), &inet6_flags()),
        Err(e) => {
            tracing::warn!("讀不到本機網卡清單：{e}");
            Vec::new()
        }
    }
}

/// 用名稱找網卡（不分大小寫；名稱或顯示名稱都可以）
pub fn find<'a>(list: &'a [Iface], name: &str) -> Option<&'a Iface> {
    let want = name.trim();
    list.iter().find(|i| i.name == want).or_else(|| {
        list.iter()
            .find(|i| i.name.eq_ignore_ascii_case(want) || i.label.eq_ignore_ascii_case(want))
    })
}

/// 系統預設路由對外連線時用的來源位址（不送任何封包：只讓系統選好路由）
pub fn default_source(v6: bool) -> Option<IpAddr> {
    let (bind, probe) = if v6 {
        ("[::]:0", "[2606:4700:4700::1111]:53")
    } else {
        ("0.0.0.0:0", "1.1.1.1:53")
    };
    let s = std::net::UdpSocket::bind(bind).ok()?;
    s.connect(probe).ok()?;
    s.local_addr().ok().map(|a| a.ip()).filter(|ip| !ip.is_unspecified())
}

/// 預設路由走的那張網卡
pub fn default_iface(list: &[Iface], v6: bool) -> Option<&Iface> {
    let src = default_source(v6)?;
    list.iter().find(|i| i.addrs.iter().any(|a| a.ip == src))
}

pub fn to_json(list: &[Iface]) -> Value {
    let ifs: Vec<Value> = list
        .iter()
        .map(|i| {
            let addrs: Vec<Value> = i
                .addrs
                .iter()
                .map(|a| {
                    let mut v = json!({ "ip": a.ip, "family": if a.ip.is_ipv6() { 6 } else { 4 }, "scope": a.scope.name() });
                    if a.temporary {
                        v["temporary"] = json!(true);
                    }
                    if a.deprecated {
                        v["deprecated"] = json!(true);
                    }
                    v
                })
                .collect();
            json!({ "name": i.name, "label": i.label, "up": i.up, "addrs": addrs })
        })
        .collect();
    json!({ "interfaces": ifs })
}

/// `GET /api/interfaces`
pub fn json() -> Value {
    to_json(&list())
}

/// TCP 監聽：IPv6 位址一律 `IPV6_V6ONLY`，`0.0.0.0` 與 `::` 才能同時綁同一個埠
pub fn bind_tcp(addr: std::net::SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        s.set_only_v6(true)?;
    }
    // Windows 的 SO_REUSEADDR 會讓兩個程式搶同一個埠，只在 Unix 設
    #[cfg(unix)]
    s.set_reuse_address(true)?;
    s.set_nonblocking(true)?;
    s.bind(&addr.into())?;
    s.listen(1024)?;
    tokio::net::TcpListener::from_std(s.into())
}

/// UDP（QUIC）監聽：同樣對 IPv6 設 `IPV6_V6ONLY`
pub fn bind_udp(addr: std::net::SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    if addr.is_ipv6() {
        s.set_only_v6(true)?;
    }
    s.set_nonblocking(true)?;
    s.bind(&addr.into())?;
    Ok(s.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(s: &str) -> Scope {
        classify(s.parse().unwrap())
    }

    #[test]
    fn classification() {
        assert_eq!(scope("1.2.3.4"), Scope::Public);
        assert_eq!(scope("203.0.113.5"), Scope::Public);
        assert_eq!(scope("192.168.1.1"), Scope::Private);
        assert_eq!(scope("10.0.0.1"), Scope::Private);
        assert_eq!(scope("172.16.0.1"), Scope::Private);
        assert_eq!(scope("172.32.0.1"), Scope::Public, "172.16/12 之外");
        assert_eq!(scope("100.64.1.1"), Scope::Cgnat);
        assert_eq!(scope("100.127.255.254"), Scope::Cgnat);
        assert_eq!(scope("100.128.0.1"), Scope::Public);
        assert_eq!(scope("169.254.10.1"), Scope::LinkLocal);
        assert_eq!(scope("127.0.0.1"), Scope::Loopback);
        assert_eq!(scope("0.0.0.0"), Scope::Private);
        assert_eq!(scope("192.0.0.2"), Scope::Private, "DS-Lite");
        assert_eq!(scope("198.18.0.1"), Scope::Private);
        assert_eq!(scope("240.0.0.1"), Scope::Private);
        assert_eq!(scope("2001:db8::1"), Scope::Public);
        assert_eq!(scope("2001:b011::1"), Scope::Public);
        assert_eq!(scope("fd00::1"), Scope::Ula);
        assert_eq!(scope("fc00::1"), Scope::Ula);
        assert_eq!(scope("fe80::1"), Scope::LinkLocal);
        assert_eq!(scope("::1"), Scope::Loopback);
        assert_eq!(scope("::"), Scope::Private);
        assert_eq!(scope("64:ff9b::1"), Scope::Private, "NAT64 前綴不是本機的公網位址");
        assert_eq!(scope("::ffff:192.168.1.1"), Scope::Private, "IPv4 對應位址照 IPv4 分類");
        assert_eq!(scope("::ffff:1.2.3.4"), Scope::Public);
        assert!(is_public("1.2.3.4".parse().unwrap()));
        assert!(!is_public("100.64.1.1".parse().unwrap()));
        assert_eq!(Scope::LinkLocal.name(), "linklocal");
    }

    #[test]
    fn inet6_flags_and_stable_preference() {
        let proc = "\
20010db8000000000000000000000001 02 40 00 80 eth0\n\
20010db80000000012345678abcdef01 02 40 00 01 eth0\n\
20010db8000000000000000000000002 02 40 00 20 eth0\n\
fe800000000000000000000000000001 02 40 20 80 eth0\n\
garbage\n";
        let flags = parse_inet6_flags(proc);
        assert_eq!(flags.len(), 4);
        assert_eq!(flags[1], ("2001:db8::1234:5678:abcd:ef01".parse().unwrap(), true, false));
        assert_eq!(flags[2], ("2001:db8::2".parse().unwrap(), false, true));
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let ifs = group(
            [
                ("eth0".to_string(), true, ip("192.168.1.2")),
                ("eth0".to_string(), true, ip("2001:db8::1234:5678:abcd:ef01")),
                ("eth0".to_string(), true, ip("2001:db8::1")),
                ("eth0".to_string(), true, ip("2001:db8::2")),
                ("eth0".to_string(), true, ip("fe80::1")),
                ("pppoe-wan".to_string(), true, ip("203.0.113.9")),
                ("wanb".to_string(), false, ip("100.64.3.4")),
            ],
            &flags,
        );
        assert_eq!(ifs.len(), 3);
        let eth = find(&ifs, "ETH0").unwrap();
        assert_eq!(eth.addrs.len(), 5);
        assert_eq!(
            eth.public_addrs(true),
            vec![ip("2001:db8::1")],
            "只發布穩定的位址，不發布臨時 / 已淘汰的"
        );
        assert!(eth.public_addrs(false).is_empty(), "私有位址不發布");
        assert_eq!(eth.source_addr(false), Some(ip("192.168.1.2")), "在 NAT 後面：用私有位址當來源");
        assert_eq!(eth.source_addr(true), Some(ip("2001:db8::1")));
        let ppp = find(&ifs, "pppoe-wan").unwrap();
        assert_eq!(ppp.public_addrs(false), vec![ip("203.0.113.9")]);
        assert_eq!(ppp.source_addr(true), None, "沒有 IPv6");
        let wanb = find(&ifs, "wanb").unwrap();
        assert!(!wanb.up);
        assert_eq!(wanb.source_addr(false), Some(ip("100.64.3.4")));
        assert!(find(&ifs, "nope").is_none());
        // 只有臨時位址時還是用它（總比沒有好）
        let only_tmp = group([("eth1".to_string(), true, ip("2001:db8::1234:5678:abcd:ef01"))], &flags);
        assert_eq!(only_tmp[0].public_addrs(true), vec![ip("2001:db8::1234:5678:abcd:ef01")]);

        let j = to_json(&ifs);
        assert_eq!(j["interfaces"][0]["name"], "eth0");
        assert_eq!(j["interfaces"][0]["label"], "eth0");
        assert_eq!(j["interfaces"][0]["up"], true);
        assert_eq!(
            j["interfaces"][0]["addrs"][0],
            json!({ "ip": "192.168.1.2", "family": 4, "scope": "private" })
        );
        assert_eq!(j["interfaces"][0]["addrs"][1]["temporary"], true);
        assert_eq!(j["interfaces"][0]["addrs"][1]["family"], 6);
        assert_eq!(j["interfaces"][1]["addrs"][0]["scope"], "public");
        assert_eq!(j["interfaces"][2]["addrs"][0]["scope"], "cgnat");
    }

    #[test]
    fn enumerates_this_machine() {
        // 每台機器至少有迴路介面；位址分類要跟 classify 一致
        let ifs = list();
        assert!(!ifs.is_empty(), "至少有迴路介面");
        assert!(ifs.iter().any(|i| i.addrs.iter().any(|a| a.scope == Scope::Loopback)));
        for i in &ifs {
            assert!(!i.name.is_empty());
            for a in &i.addrs {
                assert_eq!(a.scope, classify(a.ip));
            }
        }
        assert!(json()["interfaces"].is_array());
    }
}
