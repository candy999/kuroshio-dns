//! 過濾接上解析器：清單下載、自訂規則優先、存檔 3 秒內生效、管理 API

use kuroshio::resolver::Ctx;
use kuroshio_proto::message::{Message, RData};
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

async fn list_server(body: &'static str) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf).await;
                let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len());
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    addr
}

async fn upstream() -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let (len, peer) = s.recv_from(&mut buf).await.unwrap();
            let q = Message::parse(&buf[..len]).unwrap();
            let mut r = Message::response_to(&q, 0);
            r.opt = None;
            r.answers.push(kuroshio_proto::message::Record::a(
                &q.questions[0].name,
                60,
                Ipv4Addr::new(1, 2, 3, 4),
            ));
            let _ = s.send_to(&r.encode(), peer).await;
        }
    });
    addr
}

const CTX: Ctx = Ctx {
    proto: "test",
    client: IpAddr::V4(Ipv4Addr::LOCALHOST),
};

async fn resolve(r: &std::sync::Arc<kuroshio::resolver::Resolver>, name: &str) -> RData {
    let resp = r.handle(&kuroshio_proto::build_query(1, name, 1), &CTX).await.unwrap();
    Message::parse(&resp).unwrap().answers[0].data.clone()
}

#[tokio::test]
async fn lists_custom_priority_and_reload() {
    let lists = list_server("! 測試清單\n||ads.example^\n0.0.0.0 tracker.example\n||malware.example^\n").await;
    let up = upstream().await;
    let dir = std::env::temp_dir().join(format!("kuroshio-filter-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("state")).unwrap();
    std::fs::write(dir.join("custom-rules.txt"), "@@||ok.ads.example^\n||mine.example^\n").unwrap();
    let cfg = kuroshio_config::with_overrides(&json!({
        "system": { "persistDir": dir.join("state").to_string_lossy() },
        "admin": { "port": 0, "auth": false },
        "listen": { "plain": { "binds": ["127.0.0.1"], "port": 0 } },
        "upstream": { "pinned": [format!("udp://{up}")], "fallback": [] },
        "resolver": { "lastResort": [], "rankIps": false, "cacheMax": 1000 },
        "filter": {
            "customRules": ["./custom-rules.txt"],
            "lists": [
                { "name": "測試廣告", "url": format!("http://{lists}/ads.txt"), "category": "ads" },
                { "name": "關掉的", "url": format!("http://{lists}/off.txt"), "category": "ads", "enabled": false }
            ]
        }
    }));
    let started = kuroshio::app::start(&cfg, kuroshio_config::Tier::Large).await.unwrap();
    let r = started.resolver.clone();
    // 自訂規則啟動時就載入；清單 2 秒後下載
    assert_eq!(resolve(&r, "mine.example").await, RData::A(Ipv4Addr::UNSPECIFIED));
    tokio::time::sleep(Duration::from_millis(2600)).await;
    assert_eq!(
        resolve(&r, "x.ads.example").await,
        RData::A(Ipv4Addr::UNSPECIFIED),
        "清單的子網域封鎖"
    );
    assert_eq!(resolve(&r, "tracker.example").await, RData::A(Ipv4Addr::UNSPECIFIED), "hosts 格式");
    assert_eq!(
        resolve(&r, "ok.ads.example").await,
        RData::A(Ipv4Addr::new(1, 2, 3, 4)),
        "自訂白名單優先於清單"
    );
    assert_eq!(resolve(&r, "fine.example").await, RData::A(Ipv4Addr::new(1, 2, 3, 4)));

    // 改自訂規則：3 秒內生效，不用重新下載清單
    std::fs::write(dir.join("custom-rules.txt"), "||fine.example^\n").unwrap();
    tokio::time::sleep(Duration::from_millis(3500)).await;
    r.flush();
    assert_eq!(resolve(&r, "fine.example").await, RData::A(Ipv4Addr::UNSPECIFIED));
    assert_eq!(
        resolve(&r, "ok.ads.example").await,
        RData::A(Ipv4Addr::UNSPECIFIED),
        "白名單拿掉後回到清單判定"
    );

    // 管理 API
    let st = kuroshio::admin::route(&started.state, "/api/status", &Default::default())
        .await
        .body;
    assert_eq!(st["filter"]["lists"], 3);
    assert_eq!(st["filter"]["custom"], 1);
    assert_eq!(st["filter"]["sources"].as_array().unwrap().len(), 1, "停用的清單不下載");
    assert_eq!(st["stats"]["today"]["blockedAds"], 3, "清單命中");
    assert_eq!(st["stats"]["today"]["blockedCustom"], 2, "自訂規則命中");
    let q = [("name".to_string(), "a.malware.example".to_string())].into_iter().collect();
    let c = kuroshio::admin::route(&started.state, "/api/filter/check", &q).await.body;
    assert_eq!(c["action"], "block");
    assert_eq!(c["rule"], "||malware.example^");
    let u = kuroshio::admin::route(&started.state, "/api/filter/update", &Default::default())
        .await
        .body;
    assert_eq!(u["changed"], true);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn missing_custom_file_gets_defaults() {
    let dir = std::env::temp_dir().join(format!("kuroshio-filter-def-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let cfg = kuroshio_config::with_overrides(&json!({ "filter": { "customRules": ["./custom-rules.txt"], "lists": [] } }));
    let f = kuroshio::filtering::FilterService::from_cfg(&cfg, &dir).unwrap();
    f.reload_custom(true);
    assert_eq!(
        std::fs::read_to_string(dir.join("custom-rules.txt")).unwrap(),
        kuroshio::filtering::DEFAULT_CUSTOM_RULES
    );
    use kuroshio::resolver::FilterCheck;
    assert!(f.stats()["custom"].as_u64().unwrap() > 100, "預設自訂規則已載入");
    std::fs::remove_dir_all(&dir).unwrap();
}
