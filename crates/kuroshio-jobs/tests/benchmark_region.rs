//! 上游多樣性（3.4.0，規格 10 第 6 節）端對端：本機假 DNS 伺服器加上假的 ip-api（回 `countryCode`），
//! 檢查 upstreams.json 的 `selected[].region`／`near`、`final_dns_smart.csv` 的新欄位、
//! `coverageRegion = near` 先挑鄰近的，以及 ip-api 查不到時評測照常完成。

use kuroshio_jobs::benchmark::probe::{IpApi, NetProber, Prober, SiteCheck};
use kuroshio_jobs::geo::TwIp;
use kuroshio_jobs::scheduler::BoxFuture;
use kuroshio_jobs::{BenchPaths, Benchmark, JobCtx};
use kuroshio_net::upstream::{Kind, Upstream};
use kuroshio_proto::message::Record;
use kuroshio_proto::Message;
use serde_json::{json, Value};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// 假 DNS 伺服器：每個回應延遲 `delay_ms` 毫秒；網域各自回這台專屬的 IP（每台都有獨有的覆蓋）
async fn mock(bind: &str, delay_ms: u64, n: u8) -> SocketAddr {
    let sock = Arc::new(UdpSocket::bind(bind).await.unwrap());
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            let Ok((len, peer)) = sock.recv_from(&mut buf).await else { break };
            let Ok(q) = Message::parse(&buf[..len]) else { continue };
            let name = q.question().map(|x| x.name.clone()).unwrap_or_default();
            let sock = sock.clone();
            tokio::spawn(async move {
                if name != "one.one.one.one" {
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
                let mut r = Message::response_to(&q, 0);
                match name.as_str() {
                    "one.one.one.one" => {
                        r.answers.push(Record::a(&name, 60, Ipv4Addr::new(1, 1, 1, 1)));
                        r.answers.push(Record::a(&name, 60, Ipv4Addr::new(1, 0, 0, 1)));
                    }
                    "www.example.com" => r.answers.push(Record::a(&name, 60, Ipv4Addr::new(93, 1, 0, n))),
                    "cdn.example.net" => r.answers.push(Record::a(&name, 60, Ipv4Addr::new(94, 2, 0, n))),
                    _ => r.rcode = 3,
                }
                let _ = sock.send_to(&r.encode(), peer).await;
            });
        }
    });
    addr
}

/// 只測本機 UDP；網站驗證一律有效
struct LocalOnly;

impl Prober for LocalOnly {
    fn supports(&self, up: &Upstream) -> bool {
        matches!(up.kind, Kind::Udp | Kind::Tcp) && up.supported()
    }
    fn exchange(&self, up: Upstream, q: Vec<u8>, t: Duration) -> BoxFuture<anyhow::Result<Vec<u8>>> {
        NetProber.exchange(up, q, t)
    }
    fn resolve_v4(&self, _host: String) -> BoxFuture<Option<Ipv4Addr>> {
        Box::pin(async { None })
    }
    fn verify_site(&self, _ip: std::net::IpAddr, _domain: String, _t: Duration) -> BoxFuture<(SiteCheck, String)> {
        Box::pin(async { (SiteCheck::Valid, "OK".to_string()) })
    }
}

/// 假的 ip-api 批次查詢：127.N.x.x → 業者 OwnerN、國別依 `cc`；127.5 回 fail（查不到）。
/// 回傳（位址, 收到幾次查詢）
async fn fake_ip_api() -> (SocketAddr, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { break };
            let h = h.clone();
            tokio::spawn(async move {
                let mut raw = Vec::new();
                let mut buf = [0u8; 4096];
                let (head, body) = loop {
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    raw.extend_from_slice(&buf[..n]);
                    let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let head = String::from_utf8_lossy(&raw[..end]).to_string();
                    let len: usize = head
                        .lines()
                        .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().to_string()))
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    if raw.len() >= end + 4 + len {
                        break (head, raw[end + 4..end + 4 + len].to_vec());
                    }
                };
                assert!(head.contains("fields=") && head.contains("countryCode"), "{head}");
                h.fetch_add(1, Ordering::SeqCst);
                let ips: Vec<String> = serde_json::from_slice(&body).unwrap_or_default();
                let out: Vec<Value> = ips
                    .iter()
                    .map(|ip| {
                        let o: Vec<u8> = ip.split('.').filter_map(|x| x.parse().ok()).collect();
                        let cc = match o.get(1) {
                            Some(1) => "US",
                            Some(2) => "JP", // 但在台灣網段裡 → TW
                            Some(3) => "JP",
                            Some(4) => "US",
                            _ => "",
                        };
                        if o.get(1) == Some(&5) {
                            return json!({ "status": "fail", "query": ip });
                        }
                        let n = o.get(1).copied().unwrap_or(0);
                        json!({
                            "status": "success", "query": ip, "isp": format!("Owner{n} Ltd"),
                            "org": format!("Owner{n} Ltd"), "as": format!("AS6450{n} Owner{n}"), "countryCode": cc
                        })
                    })
                    .collect();
                let body = serde_json::to_vec(&out).unwrap();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Rl: 14\r\nX-Ttl: 60\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.write_all(&body).await;
            });
        }
    });
    (addr, hits)
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("kuroshio-bench-region-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn paths(root: &Path) -> BenchPaths {
    BenchPaths {
        list_dir: root.join("benchmark"),
        out_root: Some(root.join("state/benchmark")),
        upstreams_file: root.join("state/upstreams.json"),
        community_candidates: None,
        blacklist_file: Some(root.join("state/blacklist.txt")),
        default_list_dir: None,
    }
}

fn read(p: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

/// 五台：s1（0 ms、US）、s2（0 ms、台灣網段）、s3（90 ms、JP）、s4（70 ms、US）、s5（70 ms、ip-api 查不到）
async fn setup(name: &str) -> (PathBuf, BenchPaths, [String; 5]) {
    let s = [
        mock("127.1.0.1:0", 0, 1).await,
        mock("127.2.0.1:0", 0, 2).await,
        mock("127.3.0.1:0", 90, 3).await,
        mock("127.4.0.1:0", 70, 4).await,
        mock("127.5.0.1:0", 70, 5).await,
    ];
    let root = tmp(name);
    let p = paths(&root);
    std::fs::create_dir_all(&p.list_dir).unwrap();
    let ids: Vec<String> = s.iter().map(|a| a.to_string()).collect();
    std::fs::write(p.list_dir.join("iplist.txt"), ids.join("\n")).unwrap();
    std::fs::write(p.list_dir.join("web.txt"), "www.example.com\ncdn.example.net\n").unwrap();
    // 答案的 /16 先放進快取（汙染判斷不用問 ip-api）；舊格式，沒有 cc
    let out_root = p.out_root.clone().unwrap();
    std::fs::create_dir_all(&out_root).unwrap();
    std::fs::write(
        out_root.join("cidr_cache.json"),
        r#"{"93.1":{"raw":"Example_Web__AS64496_Example","keywords":["example","web","as64496"]},
            "94.2":{"raw":"Example_Web__AS64496_Example","keywords":["example","web","as64496"]}}"#,
    )
    .unwrap();
    (root, p, ids.try_into().unwrap())
}

fn cfg(region: &str) -> Value {
    kuroshio_config::with_overrides(&json!({
        "upstream": { "autoTypes": ["udp"], "autoMax": 5 },
        "benchmark": { "timeoutMs": 800, "concurrency": 8, "paceMs": 0, "maxTimeouts": 1, "minAuto": 1, "coverageRegion": region }
    }))
}

fn tw() -> Option<Arc<TwIp>> {
    let j = r#"{"generatedAt":"2026-11-01","groups":[{"id":"test","name":"測試","v4":["127.2.0.0/16"]}]}"#.as_bytes();
    Some(Arc::new(TwIp::parse(j).unwrap()))
}

/// selected[] → （id, region, near, reason）
fn picks(state: &Value) -> Vec<(String, String, bool, String)> {
    state["selected"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            (
                x["id"].as_str().unwrap().to_string(),
                x["region"].as_str().unwrap().to_string(),
                x["near"].as_bool().unwrap(),
                x["reason"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstreams_json_has_region() {
    let (root, p, ids) = setup("json").await;
    let (api, hits) = fake_ip_api().await;
    let ip_api = IpApi::new("127.0.0.1", api.port(), Duration::from_millis(10));
    let ctx = JobCtx::new("dns-benchmark", "測試", Arc::new(cfg("near")));
    let b = Benchmark::with(p.clone(), Arc::new(LocalOnly), Arc::new(ip_api)).with_tw(tw());
    let state = b.run(&ctx).await.unwrap();
    assert_eq!(read(&p.upstreams_file), state);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "只問一次：決選的上游位址（同時補上沒有國別的舊快取）"
    );

    let sel = picks(&state);
    assert_eq!(sel.len(), 5, "{state}");
    let get = |id: &str| sel.iter().find(|x| x.0 == id).cloned().unwrap();
    assert_eq!(get(&ids[0]).1, "US");
    assert!(get(&ids[0]).2, "延遲低：不管國別都算鄰近");
    assert_eq!(
        (get(&ids[1]).1.as_str(), get(&ids[1]).2),
        ("TW", true),
        "台灣網段優先於 ip-api 的國別"
    );
    assert_eq!((get(&ids[2]).1.as_str(), get(&ids[2]).2), ("JP", true), "日本、延遲在 2 倍以內");
    assert_eq!((get(&ids[3]).1.as_str(), get(&ids[3]).2), ("US", false));
    assert_eq!((get(&ids[4]).1.as_str(), get(&ids[4]).2), ("", false), "ip-api 查不到");
    // 先挑鄰近的：s3（90 ms）比 s4、s5（70 ms）慢，還是排在它們前面
    assert_eq!(sel[0].3, "最快");
    assert!(sel[..3].iter().all(|x| x.2), "{sel:?}");
    assert_eq!(sel[2].0, ids[2]);
    assert!(sel[1..].iter().all(|x| x.3 == "覆蓋"), "reason 的文字不變");

    let out = p.out_root.clone().unwrap().join(state["date"].as_str().unwrap());
    let csv = std::fs::read_to_string(out.join("final_dns_smart.csv")).unwrap();
    let mut lines = csv.lines();
    assert_eq!(
        lines.next().unwrap(),
        "\u{feff}Rank,DNS_Server,Type,DNS_Owner,Min,Max,Avg,Count,Success_Rate,Total_IPs,Unique_IPs,Unique_Ratio_Self,Unique_Ratio_Global,Pinned,Region,Near"
    );
    let row = |id: &str| csv.lines().find(|l| l.split(',').nth(1) == Some(id)).unwrap().to_string();
    assert!(row(&ids[1]).ends_with(",,TW,Y"), "{csv}");
    assert!(row(&ids[3]).ends_with(",,US,"), "{csv}");
    let log = std::fs::read_to_string(out.join("judge.log")).unwrap();
    assert!(log.contains("覆蓋：鄰近 2 台、其他 2 台"), "{log}");
    // 快取：新查到的有 cc，答案的 /16（只在汙染判斷用到）不補查
    let cache = read(&p.out_root.clone().unwrap().join("cidr_cache.json"));
    assert_eq!(cache["127.3"]["cc"], "JP");
    assert!(cache["93.1"].get("cc").is_none());

    // coverageRegion = any：跟 3.3.7 一樣不分遠近（s3 最慢，最後才選）
    let ctx = JobCtx::new("dns-benchmark", "測試", Arc::new(cfg("any")));
    let (api2, hits2) = fake_ip_api().await;
    let ip_api = IpApi::new("127.0.0.1", api2.port(), Duration::from_millis(10));
    let b = Benchmark::with(p.clone(), Arc::new(LocalOnly), Arc::new(ip_api)).with_tw(tw());
    let state = b.run(&ctx).await.unwrap();
    let sel = picks(&state);
    assert_eq!(sel.len(), 5);
    assert_eq!(sel[4].0, ids[2], "{sel:?}");
    assert_eq!(
        hits2.load(Ordering::SeqCst),
        1,
        "國別已經在快取裡；只有上次查不到的 127.5 再問一次（跟以前一樣，每次執行重試一次）"
    );
    let log = std::fs::read_to_string(out.join("judge.log")).unwrap();
    assert!(log.contains("不分遠近"), "{log}");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ip_api_offline_still_selects() {
    let (root, p, ids) = setup("offline").await;
    // 上游位址的業者在 3.3.7 的快取裡（沒有 cc）：補查國別失敗，業者照用、國別是空的
    let cache_file = p.out_root.clone().unwrap().join("cidr_cache.json");
    let mut cache = read(&cache_file);
    for n in 1..=5 {
        cache[format!("127.{n}")] =
            json!({ "raw": format!("Owner{n}_Ltd__AS6450{n}_Owner{n}"), "keywords": [format!("owner{n}"), format!("as6450{n}")] });
    }
    std::fs::write(&cache_file, serde_json::to_vec(&cache).unwrap()).unwrap();
    // 沒有人在聽的埠：ip-api 連不上
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let ip_api = IpApi::new("127.0.0.1", port, Duration::from_millis(10));
    let ctx = JobCtx::new("dns-benchmark", "測試", Arc::new(cfg("near")));
    let b = Benchmark::with(p.clone(), Arc::new(LocalOnly), Arc::new(ip_api)).with_tw(tw());
    let state = b.run(&ctx).await.unwrap();
    let sel = picks(&state);
    assert_eq!(sel.len(), 5, "{state}");
    let get = |id: &str| sel.iter().find(|x| x.0 == id).cloned().unwrap();
    // 只剩台灣網段與延遲
    assert_eq!((get(&ids[0]).1.as_str(), get(&ids[0]).2), ("", true));
    assert_eq!((get(&ids[1]).1.as_str(), get(&ids[1]).2), ("TW", true));
    assert_eq!((get(&ids[2]).1.as_str(), get(&ids[2]).2), ("", false), "查不到國別、延遲超過 60 ms");
    assert_eq!((get(&ids[3]).1.as_str(), get(&ids[3]).2), ("", false));
    let _ = std::fs::remove_dir_all(&root);
}
