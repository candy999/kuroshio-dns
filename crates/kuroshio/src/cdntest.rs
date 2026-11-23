//! 測試共用（只在 `cargo test`）：主程式這一層呼叫 CDN 的地方（機房抽查、`/api/cdn/*`）用的假網路與 `Cdn`。
//! CDN 那一層自己的 `MockNet` 在它的測試模組裡，這裡用不到，所以另外寫一個只有探測的版本：
//! 每個 IP 回固定的結果、記下探測了誰，其他網路操作一律失敗。範例只用文件用 IP 與 example.com

use anyhow::{anyhow, Result};
use kuroshio_cdn::net::BoxFut;
use kuroshio_cdn::util::Num;
use kuroshio_cdn::{Cdn, Net, Paths};
use kuroshio_net::iprank::{Latency, Quality};
use kuroshio_net::probe::{HttpsOpts, ProbeResult, Timing};
use kuroshio_proto::message::Message;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// 假的網路：HTTPS／HTTP 探測照 IP 回設定好的結果（沒設是連不上），呼叫都記在 `log`
#[derive(Default)]
pub struct TestNet {
    pub https: Mutex<HashMap<IpAddr, ProbeResult>>,
    pub http: Mutex<HashMap<IpAddr, ProbeResult>>,
    pub log: Mutex<Vec<String>>,
}

fn refused() -> ProbeResult {
    ProbeResult::failed("ECONNREFUSED", false)
}

fn down() -> Latency {
    Latency {
        ok: false,
        ms: f64::INFINITY,
    }
}

impl TestNet {
    pub fn calls(&self, prefix: &str) -> Vec<String> {
        self.log.lock().unwrap().iter().filter(|s| s.starts_with(prefix)).cloned().collect()
    }
}

impl Net for TestNet {
    fn https_probe<'a>(&'a self, ip: IpAddr, host: &'a str, _path: &'a str, _o: HttpsOpts) -> BoxFut<'a, ProbeResult> {
        self.log.lock().unwrap().push(format!("https {ip} {host}"));
        let r = self.https.lock().unwrap().get(&ip).cloned().unwrap_or_else(refused);
        Box::pin(async move { r })
    }
    fn http_probe<'a>(&'a self, ip: IpAddr, host: &'a str, _path: &'a str, _t: Duration) -> BoxFut<'a, ProbeResult> {
        self.log.lock().unwrap().push(format!("http {ip} {host}"));
        let r = self.http.lock().unwrap().get(&ip).cloned().unwrap_or_else(refused);
        Box::pin(async move { r })
    }
    fn download_speed<'a>(&'a self, _ip: IpAddr, _url: &'a str, _max: u64, _max_bytes: u64) -> BoxFut<'a, f64> {
        Box::pin(async { 0.0 })
    }
    fn tcp_ping(&self, _ip: IpAddr, _t: Duration, _s: u32) -> BoxFut<'_, Latency> {
        Box::pin(async { down() })
    }
    fn quality(&self, _ip: IpAddr, n: u32, _t: Duration, _g: Duration) -> BoxFut<'_, Quality> {
        Box::pin(async move {
            Quality {
                ms: f64::INFINITY,
                jitter: 0.0,
                loss: 1.0,
                n,
            }
        })
    }
    fn latency(&self, _ip: IpAddr) -> BoxFut<'_, Latency> {
        Box::pin(async { down() })
    }
    fn cached(&self, _ip: IpAddr) -> Option<Latency> {
        None
    }
    fn rank<'a>(&'a self, ips: &'a [IpAddr]) -> BoxFut<'a, Vec<(IpAddr, Latency)>> {
        let out = ips.iter().map(|ip| (*ip, down())).collect();
        Box::pin(async move { out })
    }
    fn v6_usable(&self) -> Option<bool> {
        None
    }
    fn dns<'a>(
        &'a self,
        _resolver: &'a str,
        _name: &'a str,
        _qtype: u16,
        _ecs: Option<(IpAddr, u8)>,
        _t: Duration,
    ) -> BoxFut<'a, Result<Message>> {
        Box::pin(async { Err(anyhow!("沒有回應")) })
    }
    fn resolve_host<'a>(&'a self, _host: &'a str) -> BoxFut<'a, Vec<IpAddr>> {
        Box::pin(async { Vec::new() })
    }
    fn fetch_text<'a>(&'a self, _url: &'a str, _max: u64, _t: Duration) -> BoxFut<'a, Result<String>> {
        Box::pin(async { Err(anyhow!("HTTP 404")) })
    }
}

pub fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// Cloudflare 回應：`cf-ray` 帶機房代碼；`hs` 是連線＋TLS 握手的毫秒數（3.5.0 F9 比的就是它）
pub fn cf_page(colo: &str, hs: f64) -> ProbeResult {
    ProbeResult {
        ok: true,
        status: 200,
        headers: vec![("cf-ray".into(), format!("8a-{colo}")), ("server".into(), "cloudflare".into())],
        body: "<html></html>".into(),
        ms: hs,
        error: None,
        tls_error: false,
        timing: Timing {
            connect_ms: hs * 0.4,
            tls_ms: hs * 0.6,
            ttfb_ms: 100.0,
        },
    }
}

/// 節點池的節點：延遲 `ms`；`up_pop` 是上游宣稱的機房（還沒確認）
pub fn node(s: &str, pop: &str, ms: f64, up_pop: bool) -> kuroshio_cdn::pools::PoolNode {
    let mut n = kuroshio_cdn::pools::PoolNode::new(ip(s));
    n.ms = Num::V(ms);
    n.pop = Some(kuroshio_cdn::util::intern(pop));
    if up_pop {
        n.set_up_pop(pop);
    }
    n
}

/// 只有 Cloudflare、節點池是空的（範圍是文件用位址）、狀態目錄是空的 `Cdn`
pub fn cdn(tag: &str, over: Value) -> (Arc<Cdn>, Arc<TestNet>) {
    let d = std::env::temp_dir().join(format!("kuroshio-cdntest-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let paths = Paths {
        state_dir: d.join("state"),
        seed_dir: d.join("no-seed"),
        cdn_data_dir: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/cdn"),
    };
    let mut cfg = json!({
        "enabled": true, "trialTtl": 10, "v6Policy": "keep",
        "providers": { "cloudflare": { "enabled": true } },
        "ecs": { "twSubnets": [] }
    });
    kuroshio_config::merge(&mut cfg, &over);
    let net = Arc::new(TestNet::default());
    let c = Cdn::load(&json!({ "cdn": cfg }), paths, net.clone());
    c.with_state(|st| {
        use kuroshio_cdn::pools::cidr;
        let cf = st.pools.p.get_mut("cloudflare").unwrap();
        cf.pool4 = vec![];
        cf.pool6 = vec![];
        cf.bad.clear();
        cf.range4 = cidr(&["192.0.2.0/24", "198.51.100.0/24"]);
        cf.range6 = cidr(&["2001:db8::/32"]);
        cf.global = cidr(&[]);
        cf.tw = cidr(&[]);
        cf.dead = cidr(&[]);
        cf.tw48 = cidr(&[]);
    });
    (c, net)
}
