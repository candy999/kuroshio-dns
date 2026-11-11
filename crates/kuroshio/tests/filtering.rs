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
    let lists =
        list_server("! 測試清單\n||ads.example^\n0.0.0.0 tracker.example\n||malware.example^\n/^[0-9]+\\.x$/\n/^[0-9]+\\.y$/\n").await;
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
            "maxUnindexed": 1,
            "lists": [
                { "name": "測試廣告", "url": format!("http://{lists}/ads.txt"), "category": "ads" },
                { "name": "關掉的", "url": format!("http://{lists}/off.txt"), "category": "ads", "enabled": false }
            ]
        }
    }));
    let started = kuroshio::app::start(&cfg).await.unwrap();
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
    assert_eq!(st["filter"]["lists"], 4);
    // 記憶體控制（規格 09）：預設開啟，系統保留量自動決定（至少 16 MB）
    assert_eq!(st["memory"]["enabled"], true);
    assert!(st["memory"]["reserveKB"].as_u64().unwrap() >= 16 * 1024);
    assert_eq!(st["memory"]["reserveAuto"], true);
    assert!(st["memory"]["sizes"]["cacheMax"].as_u64().is_some());
    assert!(st["memory"]["shed"].as_array().unwrap().is_empty());
    assert_eq!(st["system"]["memory"]["state"], st["memory"]["state"]);
    assert_eq!(st["filter"]["notice"], serde_json::Value::Null);
    // 沒有固定字串的規則超過上限：不載入，但統計看得到（不會默默丟掉）
    assert_eq!(st["filter"]["unindexed"], 1);
    assert_eq!(st["filter"]["unindexedDropped"], 1);
    assert_eq!(st["filter"]["sources"][0]["unindexedDropped"], 1);
    assert_eq!(resolve(&r, "12.x").await, RData::A(Ipv4Addr::UNSPECIFIED));
    assert_eq!(resolve(&r, "12.y").await, RData::A(Ipv4Addr::new(1, 2, 3, 4)));
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

/// 依路徑回不同內容的清單伺服器；`down` = true 時全部回 503（模擬下載失敗）
async fn lists_by_path(lists: Vec<(&'static str, String)>, down: std::sync::Arc<std::sync::atomic::AtomicBool>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let lists = std::sync::Arc::new(lists);
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let (lists, down) = (lists.clone(), down.clone());
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                let body = lists.iter().find(|(p, _)| path == format!("/{p}")).map(|x| x.1.clone());
                let resp = match body {
                    Some(b) if !down.load(std::sync::atomic::Ordering::Relaxed) => {
                        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{b}", b.len())
                    }
                    _ => "HTTP/1.1 503 Busy\r\nContent-Length: 0\r\n\r\n".to_string(),
                };
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    addr
}

fn many(prefix: &str, n: usize) -> String {
    (0..n).map(|i| format!("||{prefix}{i}.example^\n")).collect()
}

/// 記憶體控制（規格 09）：清單停用順序、保護清單絕不停用、恢復順序、下載失敗保留舊的、預算放不下的不載入
#[tokio::test]
async fn memory_shedding_of_lists() {
    use kuroshio::resolver::FilterCheck;
    use std::sync::atomic::{AtomicBool, Ordering};
    let down = std::sync::Arc::new(AtomicBool::new(false));
    let srv = lists_by_path(
        vec![
            ("tw165.txt", many("scam", 50)),
            ("ads-big.txt", many("big", 3000)),
            ("ads-hot.txt", many("hot", 500)),
            ("tele.txt", many("tele", 200)),
            ("ads-protected.txt", many("keep", 100)),
        ],
        down.clone(),
    )
    .await;
    let dir = std::env::temp_dir().join(format!("kuroshio-memshed-{}", std::process::id()));
    let cfg = kuroshio_config::with_overrides(&json!({ "filter": { "customRules": [], "lists": [
        { "name": "反詐騙", "url": format!("http://{srv}/tw165.txt"), "category": "malware" },
        { "name": "大廣告", "url": format!("http://{srv}/ads-big.txt"), "category": "ads" },
        { "name": "常用廣告", "url": format!("http://{srv}/ads-hot.txt"), "category": "ads" },
        { "name": "遙測", "url": format!("http://{srv}/tele.txt"), "category": "telemetry" },
        { "name": "保護廣告", "url": format!("http://{srv}/ads-protected.txt"), "category": "ads", "protect": true },
    ] } }));
    let f = kuroshio::filtering::FilterService::from_cfg(&cfg, &dir).unwrap();
    assert!(f.update_lists(true).await.unwrap());
    assert!(f.check("hot1.example", 1).unwrap().block);
    // 「常用廣告」常常命中：同樣是廣告，先停用「大廣告」
    for _ in 0..20 {
        f.check("hot1.example", 1);
    }
    let before = f.lists_bytes();
    let u = f.unload_one().await.unwrap().unwrap();
    assert_eq!((u.name.as_str(), u.rules), ("大廣告", 3000));
    assert!(u.bytes > 3000 * 8, "實測釋出：{}", u.bytes);
    assert!(f.lists_bytes() < before);
    assert!(f.check("big1.example", 1).is_none(), "停用中");
    assert!(f.check("scam1.example", 1).unwrap().block, "其他照常");
    let st = f.stats();
    assert_eq!(st["unloaded"][0]["name"], "大廣告");
    assert_eq!(st["notice"], "記憶體不足，暫時停用：大廣告 清單（3000 條規則）");
    assert_eq!(st["sources"][1]["status"], "unloaded");
    assert_eq!(st["sources"][0]["protect"], true);
    assert_eq!(st["sources"][2]["hits"], 21);
    // 接下來：常用廣告 → 遙測；反詐騙（惡意，預設保護）與標成保護的清單永遠不停用
    assert_eq!(f.unload_one().await.unwrap().unwrap().name, "常用廣告");
    assert_eq!(f.unload_one().await.unwrap().unwrap().name, "遙測");
    assert!(f.unload_one().await.unwrap().is_none(), "只剩保護清單");
    assert!(f.check("scam1.example", 1).unwrap().block);
    assert!(f.check("keep1.example", 1).unwrap().block);
    // 恢復：最後停用的先恢復；下載失敗時維持停用（舊的過濾器照常）
    down.store(true, Ordering::Relaxed);
    assert!(f.restore_one().await.is_err());
    assert_eq!(f.unloaded().len(), 3);
    assert!(f.check("scam1.example", 1).unwrap().block, "下載失敗保留舊的");
    down.store(false, Ordering::Relaxed);
    assert_eq!(f.restore_one().await.unwrap().unwrap().name, "遙測");
    assert_eq!(f.restore_one().await.unwrap().unwrap().name, "常用廣告");
    assert_eq!(f.restore_one().await.unwrap().unwrap().name, "大廣告");
    assert!(f.restore_one().await.unwrap().is_none());
    assert!(f.check("big1.example", 1).unwrap().block);
    assert_eq!(f.stats()["notice"], serde_json::Value::Null);
    // 命中次數保存 / 讀回（依名稱）
    let saved = f.hits_json();
    let f2 = kuroshio::filtering::FilterService::from_cfg(&cfg, &dir).unwrap();
    f2.restore_hits(&saved);
    assert_eq!(f2.hits_json(), saved);

    // 預算：第一次載入（還沒量過大小）只受 maxDomains 限制；量過之後依停用順序先不載入（看得到原因），
    // 保護清單就算超過預算也照樣載入
    let f3 = kuroshio::filtering::FilterService::from_cfg(&cfg, &dir).unwrap();
    f3.set_allowance(std::sync::Arc::new(|| Some(100 * kuroshio::filtering::BYTES_PER_DOMAIN)));
    f3.update_lists(true).await.unwrap();
    assert!(f3.unloaded().is_empty(), "第一次載入不估");
    f3.update_lists(true).await.unwrap();
    let mut gone: Vec<String> = f3.unloaded().into_iter().map(|u| u.name).collect();
    gone.sort();
    assert_eq!(gone, ["大廣告", "常用廣告", "遙測"]);
    assert!(f3.unloaded().iter().all(|u| u.reason == "budget"));
    assert!(f3.check("scam1.example", 1).unwrap().block, "保護清單超過預算也照樣載入");
    assert!(f3.check("keep1.example", 1).unwrap().block);
    assert!(f3.check("big1.example", 1).is_none());
    let f4 = kuroshio::filtering::FilterService::from_cfg(&cfg, &dir).unwrap();
    f4.update_lists(true).await.unwrap();
    let full = f4.lists_bytes();
    let limit = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(u32::MAX));
    let l2 = limit.clone();
    f4.set_allowance(std::sync::Arc::new(move || Some(u64::from(l2.load(Ordering::Relaxed)))));
    limit.store((full / 2) as u32, Ordering::Relaxed);
    f4.update_lists(true).await.unwrap();
    let st = f4.stats();
    assert_eq!(st["unloaded"][0]["name"], "大廣告");
    assert_eq!(st["unloaded"][0]["reason"], "budget");
    assert!(f4.lists_bytes() <= full / 2, "{} / {full}", f4.lists_bytes());
    assert!(f4.check("scam1.example", 1).unwrap().block);
}

/// 清單伺服器：先送出標頭與一部分內容，之後卡住（模擬很慢、很大的清單下載）
async fn stalled_list_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf).await;
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n||slow.example^\n")
                    .await;
                tokio::time::sleep(Duration::from_secs(120)).await;
            });
        }
    });
    addr
}

async fn udp_query(addr: SocketAddr, id: u16, name: &str) -> Option<Message> {
    let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    c.send_to(&kuroshio_proto::build_query(id, name, 1), addr).await.unwrap();
    let mut buf = [0u8; 1500];
    let (n, _) = tokio::time::timeout(Duration::from_secs(3), c.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;
    Message::parse(&buf[..n]).ok()
}

#[tokio::test]
async fn plain_dns_answers_before_lists_load() {
    // 啟動順序（規格 09）：明文 DNS 監聽在清單、CDN 資料庫這些大的載入之前；清單還在下載就已經回答查詢
    let lists = stalled_list_server().await;
    let up = upstream().await;
    let dir = std::env::temp_dir().join(format!("kuroshio-early-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("state")).unwrap();
    std::fs::write(dir.join("custom-rules.txt"), "||mine.example^\n").unwrap();
    let cfg = kuroshio_config::with_overrides(&json!({
        "system": { "persistDir": dir.join("state").to_string_lossy() },
        "admin": { "port": 0, "auth": false },
        "listen": { "plain": { "binds": ["127.0.0.1"], "port": 0 } },
        "upstream": { "pinned": [format!("udp://{up}")], "fallback": [] },
        "resolver": { "lastResort": [], "rankIps": false },
        "filter": { "customRules": ["./custom-rules.txt"], "lists": [{ "name": "慢", "url": format!("http://{lists}/a.txt"), "category": "ads" }] }
    }));
    let started = kuroshio::app::start(&cfg).await.unwrap();
    // 清單下載卡在半路：照樣轉送、照樣套用自訂規則
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let f = started.state.filter.clone().unwrap();
    assert_eq!(f.list_rules(), 0, "清單還沒載入");
    let m = udp_query(started.bound[0], 11, "www.example.org")
        .await
        .expect("清單還在下載就要回答");
    assert_eq!(m.answers[0].data, RData::A(Ipv4Addr::new(1, 2, 3, 4)));
    let m = udp_query(started.bound[0], 12, "mine.example").await.unwrap();
    assert_eq!(m.answers[0].data, RData::A(Ipv4Addr::UNSPECIFIED), "自訂規則啟動時就有效");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn deepest_shed_state_still_forwards_plain_dns() {
    // 底線（規格 09）：記憶體控制做到最深（含保護清單），區網的明文 DNS 照樣轉送到上游、回答
    let lists = list_server("||ads.example^\n||evil.example^\n").await;
    let up = upstream().await;
    let dir = std::env::temp_dir().join(format!("kuroshio-floor-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("state")).unwrap();
    let cfg = kuroshio_config::with_overrides(&json!({
        "system": { "persistDir": dir.join("state").to_string_lossy(), "memoryReserveMB": 64 },
        "admin": { "port": 0, "auth": false },
        "listen": { "plain": { "binds": ["127.0.0.1"], "port": 0 } },
        "upstream": { "pinned": [format!("udp://{up}")], "fallback": [] },
        "resolver": { "lastResort": [], "rankIps": false },
        "filter": { "lists": [
            { "name": "廣告", "url": format!("http://{lists}/ads.txt"), "category": "ads" },
            { "name": "惡意", "url": format!("http://{lists}/mal.txt"), "category": "malware" }
        ] }
    }));
    let started = kuroshio::app::start(&cfg).await.unwrap();
    let g = started.state.memgov.clone().expect("記憶體控制預設開啟");
    let addr = started.bound[0];
    tokio::time::sleep(Duration::from_millis(2600)).await;
    let f = started.state.filter.clone().unwrap();
    assert!(f.list_rules() > 0, "清單載入了");
    let m = udp_query(addr, 1, "ads.example").await.unwrap();
    assert_eq!(m.answers[0].data, RData::A(Ipv4Addr::UNSPECIFIED), "清單有效");
    // 注入：系統可用記憶體只剩 4 MB（保留 64 MB 的 1/16）
    let low = kuroshio::memgov::Reading {
        rss: Some(20 << 20),
        total: Some(128 << 20),
        avail: Some(4 << 20),
        psi: None,
    };
    g.set_reader(move || low);
    let mut now = kuroshio::persist::now_secs();
    for _ in 0..10 {
        g.tick(low, now).await;
        now += 10;
    }
    let st = g.status_json();
    assert_eq!(st["state"], "critical");
    assert_eq!(st["floor"], true, "到了最低限度");
    assert_eq!(st["protectedSuspended"], true, "連保護清單都暫停（不讓出來連轉送都會失敗）");
    assert!(f.all_suspended());
    assert_eq!(f.list_rules(), 0);
    assert!(started.resolver.cache.lock().unwrap().max <= kuroshio::memgov::FLOOR_CACHE);
    started.resolver.flush();
    // 還是要轉送、回答：原本被清單擋的名稱也照上游回答（只剩轉送）
    for (i, n) in ["www.example.org", "ads.example", "x.evil.example"].iter().enumerate() {
        let m = udp_query(addr, 100 + i as u16, n)
            .await
            .unwrap_or_else(|| panic!("{n}：最深的狀態也要回答"));
        assert_eq!(m.answers[0].data, RData::A(Ipv4Addr::new(1, 2, 3, 4)), "{n}");
    }
    // TCP 也一樣
    let mut t = tokio::net::TcpStream::connect(started.bound[1]).await.unwrap();
    let q = kuroshio_proto::build_query(9, "tcp.example.org", 1);
    let mut msg = (q.len() as u16).to_be_bytes().to_vec();
    msg.extend_from_slice(&q);
    t.write_all(&msg).await.unwrap();
    let len = t.read_u16().await.unwrap() as usize;
    let mut r = vec![0u8; len];
    t.read_exact(&mut r).await.unwrap();
    assert_eq!(Message::parse(&r).unwrap().answers[0].data, RData::A(Ipv4Addr::new(1, 2, 3, 4)));
    // 不會比底線更低：再跑一輪也沒有可以釋出的
    assert!(g.tick(low, now).await.is_none());
    // 管理 API 看得到
    let api = kuroshio::admin::route(&started.state, "/api/status", &Default::default())
        .await
        .body;
    assert_eq!(api["memory"]["floor"], true);
    assert_eq!(api["memory"]["protectedSuspended"], true);
    let _ = std::fs::remove_dir_all(&dir);
}
