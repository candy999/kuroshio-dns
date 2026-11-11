//! 測試共用：假的網路（`MockNet`）與建立 `Cdn` 的輔助函式

mod behaviors;
mod bench;
mod jobs;
mod parity;
mod selftest;
mod state;

use crate::cdn::{Cdn, Paths};
use crate::net::{BoxFut, Net};
use anyhow::{anyhow, Result};
use kuroshio_net::iprank::{Latency, Quality};
use kuroshio_net::probe::{HttpsOpts, ProbeResult};
use kuroshio_proto::message::{Message, Record};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

type F<A, R> = Box<dyn Fn(A) -> R + Send + Sync>;
type DnsArgs = (String, String, u16, Option<(IpAddr, u8)>);

/// 假的網路：每種操作都可以換成閉包，預設全部失敗
pub struct MockNet {
    pub https: Mutex<F<(IpAddr, String), ProbeResult>>,
    pub http: Mutex<F<(IpAddr, String), ProbeResult>>,
    pub ping: Mutex<F<IpAddr, Latency>>,
    pub quality: Mutex<F<IpAddr, Quality>>,
    pub speed: Mutex<F<IpAddr, f64>>,
    /// （解析器，名稱，類型，ECS）→ 回應
    pub dns: Mutex<F<DnsArgs, Option<Message>>>,
    pub cache: Mutex<HashMap<IpAddr, Latency>>,
    pub hosts: Mutex<HashMap<String, Vec<IpAddr>>>,
    pub fetch: Mutex<HashMap<String, String>>,
    pub v6: Mutex<Option<bool>>,
    /// 呼叫紀錄
    pub log: Mutex<Vec<String>>,
}

pub fn fail(e: &str) -> ProbeResult {
    ProbeResult::failed(e, false)
}

pub fn resp(status: u16, headers: &[(&str, &str)], body: &str) -> ProbeResult {
    ProbeResult {
        ok: true,
        status,
        headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        body: body.to_string(),
        ms: 5.0,
        error: None,
        tls_error: false,
    }
}

pub fn lat(ms: f64) -> Latency {
    Latency { ok: true, ms }
}

impl MockNet {
    pub fn new() -> Arc<MockNet> {
        Arc::new(MockNet {
            https: Mutex::new(Box::new(|_| fail("ECONNREFUSED"))),
            http: Mutex::new(Box::new(|_| fail("ECONNREFUSED"))),
            ping: Mutex::new(Box::new(|_| Latency {
                ok: false,
                ms: f64::INFINITY,
            })),
            quality: Mutex::new(Box::new(|_| Quality {
                ms: f64::INFINITY,
                jitter: 0.0,
                loss: 1.0,
                n: 1,
            })),
            speed: Mutex::new(Box::new(|_| 0.0)),
            dns: Mutex::new(Box::new(|_| None)),
            cache: Mutex::new(HashMap::new()),
            hosts: Mutex::new(HashMap::new()),
            fetch: Mutex::new(HashMap::new()),
            v6: Mutex::new(None),
            log: Mutex::new(Vec::new()),
        })
    }

    pub fn on_https(&self, f: impl Fn(IpAddr, &str) -> ProbeResult + Send + Sync + 'static) {
        *self.https.lock().unwrap() = Box::new(move |(ip, h)| f(ip, &h));
    }
    pub fn on_http(&self, f: impl Fn(IpAddr, &str) -> ProbeResult + Send + Sync + 'static) {
        *self.http.lock().unwrap() = Box::new(move |(ip, h)| f(ip, &h));
    }
    pub fn on_ping(&self, f: impl Fn(IpAddr) -> Latency + Send + Sync + 'static) {
        *self.ping.lock().unwrap() = Box::new(f);
    }
    pub fn on_quality(&self, f: impl Fn(IpAddr) -> Quality + Send + Sync + 'static) {
        *self.quality.lock().unwrap() = Box::new(f);
    }
    pub fn on_speed(&self, f: impl Fn(IpAddr) -> f64 + Send + Sync + 'static) {
        *self.speed.lock().unwrap() = Box::new(f);
    }
    pub fn on_dns(&self, f: impl Fn(&str, &str, u16, Option<(IpAddr, u8)>) -> Option<Message> + Send + Sync + 'static) {
        *self.dns.lock().unwrap() = Box::new(move |(r, n, t, e)| f(&r, &n, t, e));
    }
    pub fn set_cached(&self, ip: &str, ms: f64) {
        self.cache.lock().unwrap().insert(ip.parse().unwrap(), lat(ms));
    }
    fn note(&self, s: String) {
        self.log.lock().unwrap().push(s);
    }
    pub fn calls(&self, prefix: &str) -> Vec<String> {
        self.log.lock().unwrap().iter().filter(|s| s.starts_with(prefix)).cloned().collect()
    }
}

impl Net for MockNet {
    fn https_probe<'a>(&'a self, ip: IpAddr, host: &'a str, _path: &'a str, _o: HttpsOpts) -> BoxFut<'a, ProbeResult> {
        self.note(format!("https {ip} {host}"));
        let r = (self.https.lock().unwrap())((ip, host.to_string()));
        Box::pin(async move { r })
    }
    fn http_probe<'a>(&'a self, ip: IpAddr, host: &'a str, _path: &'a str, _t: Duration) -> BoxFut<'a, ProbeResult> {
        self.note(format!("http {ip} {host}"));
        let r = (self.http.lock().unwrap())((ip, host.to_string()));
        Box::pin(async move { r })
    }
    fn download_speed<'a>(&'a self, ip: IpAddr, _url: &'a str, _max: u64) -> BoxFut<'a, f64> {
        self.note(format!("speed {ip}"));
        let r = (self.speed.lock().unwrap())(ip);
        Box::pin(async move { r })
    }
    fn tcp_ping(&self, ip: IpAddr, _t: Duration, _s: u32) -> BoxFut<'_, Latency> {
        let r = (self.ping.lock().unwrap())(ip);
        Box::pin(async move { r })
    }
    fn quality(&self, ip: IpAddr, n: u32, _t: Duration, _g: Duration) -> BoxFut<'_, Quality> {
        let mut r = (self.quality.lock().unwrap())(ip);
        r.n = n;
        Box::pin(async move { r })
    }
    fn latency(&self, ip: IpAddr) -> BoxFut<'_, Latency> {
        let r = self
            .cache
            .lock()
            .unwrap()
            .get(&ip)
            .copied()
            .unwrap_or_else(|| (self.ping.lock().unwrap())(ip));
        Box::pin(async move { r })
    }
    fn cached(&self, ip: IpAddr) -> Option<Latency> {
        self.cache.lock().unwrap().get(&ip).copied()
    }
    fn rank<'a>(&'a self, ips: &'a [IpAddr]) -> BoxFut<'a, Vec<(IpAddr, Latency)>> {
        let mut out: Vec<(IpAddr, Latency)> = Vec::new();
        for ip in ips {
            if out.iter().any(|x| x.0 == *ip) {
                continue;
            }
            let l = self
                .cache
                .lock()
                .unwrap()
                .get(ip)
                .copied()
                .unwrap_or_else(|| (self.ping.lock().unwrap())(*ip));
            out.push((*ip, l));
        }
        out.sort_by(|a, b| a.1.ms.partial_cmp(&b.1.ms).unwrap());
        Box::pin(async move { out })
    }
    fn v6_usable(&self) -> Option<bool> {
        *self.v6.lock().unwrap()
    }
    fn dns<'a>(
        &'a self,
        resolver: &'a str,
        name: &'a str,
        qtype: u16,
        ecs: Option<(IpAddr, u8)>,
        _t: Duration,
    ) -> BoxFut<'a, Result<Message>> {
        self.note(format!("dns {resolver} {name} {qtype} {ecs:?}"));
        let r = (self.dns.lock().unwrap())((resolver.to_string(), name.to_string(), qtype, ecs));
        Box::pin(async move { r.ok_or_else(|| anyhow!("沒有回應")) })
    }
    fn resolve_host<'a>(&'a self, host: &'a str) -> BoxFut<'a, Vec<IpAddr>> {
        let r = self.hosts.lock().unwrap().get(host).cloned().unwrap_or_default();
        Box::pin(async move { r })
    }
    fn fetch_text<'a>(&'a self, url: &'a str, _max: u64, _t: Duration) -> BoxFut<'a, Result<String>> {
        let r = self.fetch.lock().unwrap().get(url).cloned();
        Box::pin(async move { r.ok_or_else(|| anyhow!("HTTP 404")) })
    }
}

pub fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// 每個測試自己的暫存目錄
pub fn tmpdir(tag: &str) -> PathBuf {
    static N: Mutex<u32> = Mutex::new(0);
    let n = {
        let mut g = N.lock().unwrap();
        *g += 1;
        *g
    };
    let d = std::env::temp_dir().join(format!("kuroshio-cdn-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// 狀態目錄是空的、沒有種子資料，但用 repo 附帶的 CDN 範圍與分類檔
pub fn paths_no_seed(tag: &str) -> Paths {
    let d = tmpdir(tag);
    Paths {
        state_dir: d.join("state"),
        seed_dir: d.join("no-seed"),
        cdn_data_dir: repo().join("data/cdn"),
    }
}

pub fn cdn_with(cfg: Value, paths: Paths, net: Arc<MockNet>) -> Arc<Cdn> {
    let c = Cdn::load(&json!({ "cdn": cfg }), paths, net);
    c.record_tasks();
    c
}

pub fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

pub fn ips(l: &[&str]) -> Vec<IpAddr> {
    l.iter().map(|s| ip(s)).collect()
}

/// 答案：（類型，名稱，IP / 目標）
pub fn msg(name: &str, typ: u16, list: &[&str], extra: Vec<Record>) -> Message {
    let mut m = Message {
        id: 1,
        flags: 0x8180,
        ..Default::default()
    };
    m.answers = extra;
    for s in list {
        match ip(s) {
            IpAddr::V4(v) if typ == 1 => m.answers.push(Record::a(name, 300, v)),
            IpAddr::V6(v) if typ == 28 => m.answers.push(Record::aaaa(name, 300, v)),
            _ => panic!("類型不符"),
        }
    }
    m
}

pub fn cname(name: &str, target: &str, ttl: u32) -> Record {
    Record {
        name: name.into(),
        rtype: 5,
        class: 1,
        ttl,
        data: kuroshio_proto::RData::Name(target.into()),
    }
}

pub fn answer_ips(m: &Message, typ: u16) -> Vec<String> {
    kuroshio_proto::logic::ips_of(m, typ).iter().map(|i| i.to_string()).collect()
}
