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
        "resolver": { "specialUse": false, "lastResort": [], "rankIps": false, "cacheMax": 1000 },
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
    // API 2：立刻回「已開始」，結果在狀態的 filter.update；?wait=1 等結果（舊的行為）
    let u = kuroshio::admin::route(&started.state, "/api/filter/update", &Default::default())
        .await
        .body;
    assert_eq!(u["started"], true, "{u}");
    let id = u["runId"].as_u64().unwrap();
    assert!(u["changed"].is_null(), "背景執行：還沒有結果");
    let again = kuroshio::admin::route(&started.state, "/api/filter/update", &Default::default())
        .await
        .body;
    if again["started"] == false {
        assert_eq!(again["runId"], id, "正在跑：回同一個 runId");
    }
    let mut done = serde_json::Value::Null;
    for _ in 0..100 {
        let st = kuroshio::admin::route(&started.state, "/api/status", &Default::default())
            .await
            .body;
        if st["filter"]["update"]["state"] == "idle" {
            done = st["filter"]["update"].clone();
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(done["runId"].as_u64().unwrap() >= id, "{done}");
    assert!(done["finishedAt"].is_u64(), "{done}");
    assert!(done["error"].is_null(), "{done}");
    let w = [("wait".to_string(), "1".to_string())].into_iter().collect();
    let u = kuroshio::admin::route(&started.state, "/api/filter/update", &w).await.body;
    assert_eq!(u["started"], true, "{u}");
    assert_eq!(u["changed"], true, "強制更新：重新建好（{u}）");
    assert_eq!(u["update"]["state"], "idle");
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
        "resolver": { "specialUse": false, "lastResort": [], "rankIps": false },
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
        "resolver": { "specialUse": false, "lastResort": [], "rankIps": false },
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
    // 注入：系統可用記憶體只剩 4 MB（保留 64 MB 的 1/16）。黑潮自己 40 MB：用量 × 2 ≥ 缺口 60 MB，
    // 讓得出來（不是「於事無補」，3.5.0）——記憶體監看也用這個量測判斷，自己用量太小會整段不讓
    let low = kuroshio::memgov::Reading {
        rss: Some(40 << 20),
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

/// 有 ETag 的清單伺服器：`If-None-Match` 對得上回 304；記每份清單回了幾次 200；`down` 裡的路徑回 503
#[derive(Default)]
struct EtagLists {
    lists: std::collections::HashMap<String, (String, String)>,
    down: std::collections::HashSet<String>,
    full: std::collections::HashMap<String, usize>,
    /// 每份清單收到幾次請求（含 304 與 503）
    reqs: std::collections::HashMap<String, usize>,
}

async fn etag_server(st: std::sync::Arc<std::sync::Mutex<EtagLists>>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let st = st.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req.split_whitespace().nth(1).unwrap_or("/").trim_start_matches('/').to_string();
                let inm = req.lines().find_map(|l| {
                    l.to_ascii_lowercase()
                        .starts_with("if-none-match:")
                        .then(|| l[14..].trim().to_string())
                });
                let resp = {
                    let mut g = st.lock().unwrap();
                    *g.reqs.entry(path.clone()).or_default() += 1;
                    match g.lists.get(&path).cloned() {
                        Some(_) if g.down.contains(&path) => "HTTP/1.1 503 Busy\r\nContent-Length: 0\r\n\r\n".to_string(),
                        Some((etag, _)) if inm.as_deref() == Some(etag.as_str()) => {
                            format!("HTTP/1.1 304 Not Modified\r\nETag: {etag}\r\nContent-Length: 0\r\n\r\n")
                        }
                        Some((etag, body)) => {
                            *g.full.entry(path.clone()).or_default() += 1;
                            format!("HTTP/1.1 200 OK\r\nETag: {etag}\r\nContent-Length: {}\r\n\r\n{body}", body.len())
                        }
                        None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string(),
                    }
                };
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    addr
}

/// 3.3.2：第一次載入有清單失敗時先用其他的、之後補上；沒變的清單讀本機副本不重新下載；
/// 規則數掉一大半的下載當成不完整（用副本頂著）；開機時有副本的先用副本建
#[tokio::test]
async fn partial_loads_copies_and_truncated_lists() {
    use kuroshio::resolver::FilterCheck;
    use std::sync::{Arc, Mutex};
    let st = Arc::new(Mutex::new(EtagLists::default()));
    {
        let mut g = st.lock().unwrap();
        g.lists.insert("a.txt".into(), ("\"a1\"".into(), many("aa", 2000)));
        g.lists.insert("b.txt".into(), ("\"b1\"".into(), many("bb", 100)));
        g.lists.insert("c.txt".into(), ("\"c1\"".into(), many("cc", 100)));
        g.down.insert("b.txt".into());
    }
    let srv = etag_server(st.clone()).await;
    let dir = std::env::temp_dir().join(format!("kuroshio-partial-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let cfg = kuroshio_config::with_overrides(&json!({ "filter": { "customRules": [], "lists": [
        { "name": "A", "url": format!("http://{srv}/a.txt"), "category": "ads" },
        { "name": "B", "url": format!("http://{srv}/b.txt"), "category": "ads" },
        { "name": "C", "url": format!("http://{srv}/c.txt"), "category": "ads" },
    ] } }));
    let persister = || {
        let mut p = kuroshio::persist::Persister::new(
            dir.join("state"),
            kuroshio::persist::Policy::new(kuroshio::sysinfo::StorageClass::Disk, 0, 4096),
        );
        p.set_free_probe(|_| Some(10 << 30));
        Arc::new(Mutex::new(p))
    };
    let p = persister();
    let f = kuroshio::filtering::FilterService::from_cfg(&cfg, &dir).unwrap();
    f.set_copies(p.clone());
    // 1. 第一次載入：B 失敗 → A、C 先用上，B 記在錯誤裡
    assert!(f.update_lists(false).await.unwrap());
    assert!(f.check("aa1.example", 1).unwrap().block && f.check("cc1.example", 1).unwrap().block);
    assert!(f.check("bb1.example", 1).is_none());
    assert_eq!(f.stats()["errors"][0]["name"], "B");
    p.lock().unwrap().flush_all(kuroshio::persist::now_secs()).unwrap();

    // 2. B 恢復、A 有新版：A、B 下載，C 沒變 → 讀副本（C 只下載過第一次那 1 次）
    {
        let mut g = st.lock().unwrap();
        g.down.clear();
        g.lists.insert("a.txt".into(), ("\"a2\"".into(), many("aa", 2100)));
    }
    assert!(f.update_lists(false).await.unwrap());
    assert!(f.check("bb1.example", 1).unwrap().block, "B 補上了");
    assert!(f.check("aa2050.example", 1).unwrap().block, "A 是新版");
    assert_eq!(f.stats()["errors"], json!([]));
    assert_eq!(st.lock().unwrap().full.get("c.txt"), Some(&1), "C 沒變：讀本機副本");
    p.lock().unwrap().flush_all(kuroshio::persist::now_secs()).unwrap();

    // 3. A 的新版只剩 100 條（下載被截斷）：不換上，用本機副本頂著，副本也不被蓋掉
    st.lock().unwrap().lists.insert("a.txt".into(), ("\"a3\"".into(), many("aa", 100)));
    f.update_lists(false).await.unwrap();
    assert!(f.check("aa2050.example", 1).unwrap().block, "規則數掉一大半：用副本頂著");
    let meta = f.copies().unwrap().meta(&format!("http://{srv}/a.txt")).unwrap();
    assert_eq!(meta.rules, 2100, "副本還是完整的那份");
    p.lock().unwrap().flush_all(kuroshio::persist::now_secs()).unwrap();

    // 4. 重新啟動、而且清單伺服器全部連不上：有副本的先用副本建好（不用等下載）
    st.lock()
        .unwrap()
        .down
        .extend(["a.txt".to_string(), "b.txt".to_string(), "c.txt".to_string()]);
    let f2 = kuroshio::filtering::FilterService::from_cfg(&cfg, &dir).unwrap();
    f2.set_copies(persister());
    assert!(f2.build_from_copies().await);
    assert!(f2.check("aa2050.example", 1).unwrap().block && f2.check("bb1.example", 1).unwrap().block);
    let _ = std::fs::remove_dir_all(&dir);
}

/// 3.4.2：記下上次檢查更新的時間；重新啟動後還沒過更新間隔就不馬上再問一次（以前開機一分鐘後就全部問、
/// 有變的整份重新下載：padavan-tw 的 D3 每次重啟約 9 MB、Windows 串接中重啟約 12 MB）
#[tokio::test]
async fn restart_waits_for_next_check() {
    use std::sync::{Arc, Mutex};
    let st = Arc::new(Mutex::new(EtagLists::default()));
    {
        let mut g = st.lock().unwrap();
        g.lists.insert("a.txt".into(), ("\"a1\"".into(), many("aa", 200)));
        g.lists.insert("b.txt".into(), ("\"b1\"".into(), many("bb", 200)));
    }
    let srv = etag_server(st.clone()).await;
    let dir = std::env::temp_dir().join(format!("kuroshio-checked-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let lists = json!([
        { "name": "A", "url": format!("http://{srv}/a.txt"), "category": "ads" },
        { "name": "B", "url": format!("http://{srv}/b.txt"), "category": "ads" },
    ]);
    let cfg = kuroshio_config::with_overrides(&json!({ "filter": { "customRules": [], "lists": lists } }));
    let persister = || {
        let mut p = kuroshio::persist::Persister::new(
            dir.join("state"),
            kuroshio::persist::Policy::new(kuroshio::sysinfo::StorageClass::Disk, 0, 4096),
        );
        p.set_free_probe(|_| Some(10 << 30));
        Arc::new(Mutex::new(p))
    };
    let now = kuroshio::persist::now_secs();
    let p = persister();
    let f = kuroshio::filtering::FilterService::from_cfg(&cfg, &dir).unwrap();
    f.set_copies(p.clone());
    // 還沒有副本：沒有等待時間（照舊）
    assert_eq!(f.first_check_delay(now), None);
    assert!(f.update_lists(false).await.unwrap());
    p.lock().unwrap().flush_all(now).unwrap();

    // 重新啟動：用副本建好，上次檢查是剛剛 → 等到更新間隔（預設 24 小時）到了才檢查
    let f2 = kuroshio::filtering::FilterService::from_cfg(&cfg, &dir).unwrap();
    f2.set_copies(persister());
    assert!(f2.build_from_copies().await);
    let w = f2.first_check_delay(now + 600).expect("剛檢查過：要等");
    let day = 24 * 3600;
    // 上次檢查的時間可能比 `now` 晚一兩秒記下（秒數剛好進位）
    assert!(w.as_secs() <= day - 600 + 5 && w.as_secs() >= day - 700, "{w:?}");
    // 過了更新間隔、或時間倒退（還沒對時）：馬上檢查
    assert_eq!(f2.first_check_delay(now + day + 1), None);
    assert_eq!(f2.first_check_delay(now.saturating_sub(3600)), None);

    // 全部 304 的那一輪也記時間；之後加了一份新清單（沒有副本）：馬上檢查
    let p3 = persister();
    let f3 = kuroshio::filtering::FilterService::from_cfg(&cfg, &dir).unwrap();
    f3.set_copies(p3.clone());
    assert!(f3.build_from_copies().await);
    assert!(!f3.update_lists(false).await.unwrap(), "都沒變：不重建");
    assert_eq!(st.lock().unwrap().full.get("a.txt"), Some(&1), "只下載過第一次");
    p3.lock().unwrap().flush_all(now).unwrap();
    let mut more = lists.as_array().unwrap().clone();
    more.push(json!({ "name": "C", "url": format!("http://{srv}/c.txt"), "category": "ads" }));
    let cfg2 = kuroshio_config::with_overrides(&json!({ "filter": { "customRules": [], "lists": more } }));
    let f4 = kuroshio::filtering::FilterService::from_cfg(&cfg2, &dir).unwrap();
    f4.set_copies(persister());
    assert!(f4.build_from_copies().await);
    assert_eq!(f4.first_check_delay(now + 600), None, "有清單沒有副本：照舊馬上檢查");
    let _ = std::fs::remove_dir_all(&dir);
}

/// 串接模式（3.4.0 WP6）：標了 `bypass` 的清單命中 → `Verdict.bypass`；其他清單與自訂規則 → false。
/// 沒寫標記的預設 HaGeZi doh-vpn-proxy-bypass 依網址認得（WP2 的 `is_bypass_list`）
#[tokio::test]
async fn bypass_flag_reaches_verdict() {
    use kuroshio::resolver::FilterCheck;
    let down = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let srv = lists_by_path(
        vec![
            ("bypass.txt", "||dns.example.net^\n||both.example.org^\n".into()),
            ("ads.txt", "||ads.example.net^\n".into()),
        ],
        down,
    )
    .await;
    let dir = std::env::temp_dir().join(format!("kuroshio-filter-bypass-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("custom.txt"), "||mine.example.net^\n").unwrap();
    let cfg = kuroshio_config::with_overrides(&json!({
        "filter": {
            "customRules": ["./custom.txt"],
            "lists": [
                { "name": "廣告", "url": format!("http://{srv}/ads.txt"), "category": "ads" },
                { "name": "繞過防護", "url": format!("http://{srv}/bypass.txt"), "category": "ads", "bypass": "1" }
            ]
        }
    }));
    let f = kuroshio::filtering::FilterService::from_cfg(&cfg, &dir).unwrap();
    assert_eq!(f.sources().iter().map(|s| s.bypass).collect::<Vec<_>>(), vec![false, true]);
    f.reload_custom(true);
    f.update_lists(true).await.unwrap();
    let v = f.check("dns.example.net", 1).unwrap();
    assert!(v.block && v.bypass, "{v:?}");
    assert!(f.check("x.dns.example.net", 1).unwrap().bypass, "子網域一樣是 bypass 清單命中");
    let v = f.check("ads.example.net", 1).unwrap();
    assert!(v.block && !v.bypass, "一般清單");
    let v = f.check("mine.example.net", 1).unwrap();
    assert!(v.block && !v.bypass, "自訂規則");
    assert!(f.check("fine.example.net", 1).is_none());
    // 沒寫標記：預設的 HaGeZi doh-vpn-proxy-bypass 依網址認得；其他清單沒寫就是 false
    let cfg = kuroshio_config::with_overrides(&json!({
        "filter": { "lists": [
            { "url": kuroshio_config::chain::KNOWN_BYPASS_URLS[0] },
            { "url": "https://example.com/list.txt" }
        ] }
    }));
    let f = kuroshio::filtering::FilterService::from_cfg(&cfg, &dir).unwrap();
    assert_eq!(f.sources().iter().map(|s| s.bypass).collect::<Vec<_>>(), vec![true, false]);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- 3.5.0 C6：開機後缺副本的清單 10～15 秒後只補缺的 ----

use kuroshio::resolver::FilterCheck as _;

/// 開機排程的假環境：等待不真的等，記下每次等多久、當時 c.txt 收過幾次請求；對時與記憶體狀態依呼叫次數決定
struct FakeBoot {
    sleeps: std::sync::Arc<std::sync::Mutex<Vec<(Duration, usize)>>>,
}

fn fake_boot(
    st: std::sync::Arc<std::sync::Mutex<EtagLists>>,
    jitter_ms: u64,
    unsynced_calls: usize,
    pressure: impl Fn(usize) -> kuroshio::sysinfo::Pressure + Send + Sync + 'static,
) -> (kuroshio::filtering::BootHooks, FakeBoot) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    let sleeps = Arc::new(Mutex::new(Vec::new()));
    let rec = sleeps.clone();
    let synced_n = Arc::new(AtomicUsize::new(0));
    let pressure_n = Arc::new(AtomicUsize::new(0));
    let hooks = kuroshio::filtering::BootHooks {
        sleep: Box::new(move |d| {
            let c = st.lock().unwrap().reqs.get("c.txt").copied().unwrap_or(0);
            rec.lock().unwrap().push((d, c));
            Box::pin(async {})
        }),
        synced: Box::new(move || synced_n.fetch_add(1, Ordering::Relaxed) >= unsynced_calls),
        pressure: Box::new(move || pressure(pressure_n.fetch_add(1, Ordering::Relaxed))),
        jitter_ms,
    };
    (hooks, FakeBoot { sleeps })
}

/// A、B 先下載一次（存成本機副本、記下檢查時間）；回傳清單伺服器狀態、狀態目錄、
/// 「A、B、C」的設定（C 沒有副本）與「A、B」的設定
async fn boot_setup(
    tag: &str,
) -> (
    std::sync::Arc<std::sync::Mutex<EtagLists>>,
    std::path::PathBuf,
    serde_json::Value,
    serde_json::Value,
) {
    use std::sync::{Arc, Mutex};
    let st = Arc::new(Mutex::new(EtagLists::default()));
    {
        let mut g = st.lock().unwrap();
        g.lists.insert("a.txt".into(), ("\"a1\"".into(), many("aa", 200)));
        g.lists.insert("b.txt".into(), ("\"b1\"".into(), many("bb", 200)));
        g.lists.insert("c.txt".into(), ("\"c1\"".into(), many("cc", 200)));
    }
    let srv = etag_server(st.clone()).await;
    let dir = std::env::temp_dir().join(format!("kuroshio-boot-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let ab = json!([
        { "name": "A", "url": format!("http://{srv}/a.txt"), "category": "ads" },
        { "name": "B", "url": format!("http://{srv}/b.txt"), "category": "ads" },
    ]);
    let mut abc = ab.as_array().unwrap().clone();
    abc.push(json!({ "name": "C", "url": format!("http://{srv}/c.txt"), "category": "ads" }));
    let cfg_ab = kuroshio_config::with_overrides(&json!({ "filter": { "customRules": [], "lists": ab } }));
    let cfg_abc = kuroshio_config::with_overrides(&json!({ "filter": { "customRules": [], "lists": abc } }));
    let p = boot_persister(&dir);
    let f = kuroshio::filtering::FilterService::from_cfg(&cfg_ab, &dir).unwrap();
    f.set_copies(p.clone());
    assert!(f.update_lists(false).await.unwrap());
    p.lock().unwrap().flush_all(kuroshio::persist::now_secs()).unwrap();
    assert_eq!(st.lock().unwrap().reqs.get("a.txt"), Some(&1));
    (st, dir, cfg_abc, cfg_ab)
}

fn boot_persister(dir: &std::path::Path) -> std::sync::Arc<std::sync::Mutex<kuroshio::persist::Persister>> {
    let mut p = kuroshio::persist::Persister::new(
        dir.join("state"),
        kuroshio::persist::Policy::new(kuroshio::sysinfo::StorageClass::Disk, 0, 4096),
    );
    p.set_free_probe(|_| Some(10 << 30));
    std::sync::Arc::new(std::sync::Mutex::new(p))
}

fn normal(_: usize) -> kuroshio::sysinfo::Pressure {
    kuroshio::sysinfo::Pressure::Normal
}

const DAY: Duration = Duration::from_secs(24 * 3600);

/// 以前：用副本建好後固定等 60 秒才下載缺的清單（開機約 63 秒才有）。現在 10 秒 + 0～5 秒亂數
#[tokio::test]
async fn missing_lists_fetched_within_15s_after_copy_build() {
    let (st, dir, cfg, _) = boot_setup("within15").await;
    for jitter in [0u64, 5_000, 99_999] {
        let f = kuroshio::filtering::FilterService::from_cfg(&cfg, &dir).unwrap();
        f.set_copies(boot_persister(&dir));
        let before = st.lock().unwrap().reqs.get("c.txt").copied().unwrap_or(0);
        let (h, fake) = fake_boot(st.clone(), jitter, 0, normal);
        assert_eq!(f.boot(&h).await, 0);
        let sleeps = fake.sleeps.lock().unwrap().clone();
        // 第一次等待：10～15 秒（亂數有上限），那時候 C 還沒被請求
        let (first, c_then) = sleeps[0];
        assert!(first >= Duration::from_secs(10) && first <= Duration::from_secs(15), "{first:?}");
        assert_eq!(first, Duration::from_millis(10_000 + jitter.min(5_000)));
        assert_eq!(c_then, before, "等待之前不下載");
        // 之後 C 已經下載、生效；接著等到 A、B 的更新間隔（剛檢查過），不是馬上再全部問一次
        assert_eq!(sleeps.len(), 2, "{sleeps:?}");
        assert_eq!(sleeps[1].1, before + 1, "C 下載了一次");
        assert!(sleeps[1].0 > DAY - Duration::from_secs(3600), "{:?}", sleeps[1]);
        assert!(f.check("cc1.example", 1).unwrap().block, "C 的規則生效");
        assert!(f.check("aa1.example", 1).unwrap().block, "A 的副本照用");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// 只補缺的：有副本的 A、B 一次請求都沒有（連 304 都不問）
#[tokio::test]
async fn only_missing_lists_requested() {
    let (st, dir, cfg, _) = boot_setup("only").await;
    let f = kuroshio::filtering::FilterService::from_cfg(&cfg, &dir).unwrap();
    f.set_copies(boot_persister(&dir));
    let (h, _fake) = fake_boot(st.clone(), 1_000, 0, normal);
    assert_eq!(f.boot(&h).await, 0);
    let g = st.lock().unwrap();
    assert_eq!(g.reqs.get("a.txt"), Some(&1), "A 只有第一次下載");
    assert_eq!(g.reqs.get("b.txt"), Some(&1), "B 只有第一次下載");
    assert_eq!(g.reqs.get("c.txt"), Some(&1), "C 補下載一次");
    assert_eq!(f.stats()["errors"], json!([]));
    drop(g);
    let _ = std::fs::remove_dir_all(&dir);
}

/// 全部都有副本：照舊 60 秒，之後等到更新間隔（不發請求）
#[tokio::test]
async fn all_copies_present_keeps_60s_then_interval() {
    let (st, dir, _, cfg_ab) = boot_setup("allcopies").await;
    let f = kuroshio::filtering::FilterService::from_cfg(&cfg_ab, &dir).unwrap();
    f.set_copies(boot_persister(&dir));
    let (h, fake) = fake_boot(st.clone(), 5_000, 0, normal);
    assert_eq!(f.boot(&h).await, 0);
    let sleeps = fake.sleeps.lock().unwrap().clone();
    assert_eq!(sleeps.len(), 2, "{sleeps:?}");
    assert_eq!(sleeps[0].0, kuroshio::filtering::ALL_COPIES_WAIT);
    assert_eq!(sleeps[0].0, Duration::from_secs(60));
    assert!(
        sleeps[1].0 > DAY - Duration::from_secs(3600) && sleeps[1].0 <= DAY,
        "{:?}",
        sleeps[1]
    );
    assert_eq!(st.lock().unwrap().reqs.get("a.txt"), Some(&1), "沒有再問");
    let _ = std::fs::remove_dir_all(&dir);
}

/// 還沒對時：10 秒之後照樣等對時（每 5 秒看一次）才下載
#[tokio::test]
async fn missing_fetch_waits_for_clock_sync() {
    let (st, dir, cfg, _) = boot_setup("clock").await;
    let f = kuroshio::filtering::FilterService::from_cfg(&cfg, &dir).unwrap();
    f.set_copies(boot_persister(&dir));
    let (h, fake) = fake_boot(st.clone(), 0, 3, normal);
    assert_eq!(f.boot(&h).await, 0);
    let sleeps = fake.sleeps.lock().unwrap().clone();
    let five = Duration::from_secs(5);
    let waits: Vec<Duration> = sleeps.iter().map(|s| s.0).collect();
    assert_eq!(&waits[..4], &[Duration::from_secs(10), five, five, five], "{sleeps:?}");
    assert!(sleeps[..4].iter().all(|s| s.1 == 0), "對時前不下載：{sleeps:?}");
    assert_eq!(sleeps[4].1, 1, "對時後下載");
    let _ = std::fs::remove_dir_all(&dir);
}

/// 記憶體：不足時等（恢復就下載）、偏低最多等 50 秒、一直不足就不下載（交給定時更新的迴圈）
#[tokio::test]
async fn missing_fetch_waits_for_memory() {
    use kuroshio::sysinfo::Pressure;
    let (st, dir, cfg, _) = boot_setup("memory").await;
    let five = Duration::from_secs(5);
    // 不足 2 次後恢復
    let f = kuroshio::filtering::FilterService::from_cfg(&cfg, &dir).unwrap();
    f.set_copies(boot_persister(&dir));
    let (h, fake) = fake_boot(st.clone(), 0, 0, |n| if n < 2 { Pressure::Critical } else { Pressure::Normal });
    assert_eq!(f.boot(&h).await, 0);
    let sleeps = fake.sleeps.lock().unwrap().clone();
    assert_eq!(sleeps[1..3].iter().map(|s| s.0).collect::<Vec<_>>(), vec![five, five], "{sleeps:?}");
    assert!(sleeps[..3].iter().all(|s| s.1 == 0), "不足時不下載");
    assert_eq!(sleeps[3].1, 1, "恢復後下載");
    // 一直偏低：最多等 10 次（50 秒）就下載
    let f = kuroshio::filtering::FilterService::from_cfg(&cfg, &dir).unwrap();
    f.set_copies(boot_persister(&dir));
    let (h, fake) = fake_boot(st.clone(), 0, 0, |_| Pressure::Low);
    assert_eq!(f.boot(&h).await, 0);
    let sleeps = fake.sleeps.lock().unwrap().clone();
    assert_eq!(sleeps.iter().filter(|s| s.0 == five).count(), 10, "{sleeps:?}");
    assert_eq!(sleeps.last().unwrap().1, 2, "偏低等完照樣下載");
    // 一直不足：等 30 分鐘後不下載，交給定時更新的迴圈（它照樣先等記憶體）
    let f = kuroshio::filtering::FilterService::from_cfg(&cfg, &dir).unwrap();
    f.set_copies(boot_persister(&dir));
    let (h, fake) = fake_boot(st.clone(), 0, 0, |_| Pressure::Critical);
    assert_eq!(f.boot(&h).await, 0);
    let sleeps = fake.sleeps.lock().unwrap().clone();
    let total: Duration = sleeps.iter().map(|s| s.0).sum();
    assert_eq!(total, Duration::from_secs(10 + 30 * 60), "{}", sleeps.len());
    assert_eq!(st.lock().unwrap().reqs.get("c.txt"), Some(&2), "一直不足：沒有下載");
    assert!(f.check("cc1.example", 1).is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

/// 補缺的清單下載失敗：照退避等 60 秒、交給定時更新（重試次數從 1 開始）；有副本的還是沒被請求
#[tokio::test]
async fn missing_fetch_failure_backs_off() {
    let (st, dir, cfg, _) = boot_setup("fail").await;
    st.lock().unwrap().down.insert("c.txt".into());
    let f = kuroshio::filtering::FilterService::from_cfg(&cfg, &dir).unwrap();
    f.set_copies(boot_persister(&dir));
    let (h, fake) = fake_boot(st.clone(), 0, 0, normal);
    assert_eq!(f.boot(&h).await, 1);
    let sleeps = fake.sleeps.lock().unwrap().clone();
    assert_eq!(sleeps.last().unwrap().0, Duration::from_secs(60), "{sleeps:?}");
    assert_eq!(f.stats()["errors"][0]["name"], "C");
    assert_eq!(st.lock().unwrap().reqs.get("a.txt"), Some(&1));
    assert!(f.check("aa1.example", 1).unwrap().block, "A 的副本照用");
    let _ = std::fs::remove_dir_all(&dir);
}

/// 3.5.0 B6：通訊類網域（推播）不被清單誤擋，自訂規則照樣優先；`filter.protectComm` 關掉就照清單擋
#[tokio::test]
async fn comm_not_blocked_by_list_but_blocked_by_custom_rule() {
    use kuroshio::resolver::FilterCheck;
    // 用內建表的第一組（不在測試裡寫真的網域）
    let suffix = kuroshio_net::comm::COMM_SUFFIXES[0].0;
    let comm = format!("gateway.{suffix}");
    let custom_comm = format!("blocked.{suffix}");
    let down = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let srv = lists_by_path(vec![("ads.txt", format!("||{suffix}^\n||ads.example.net^\n"))], down).await;
    let dir = std::env::temp_dir().join(format!("kuroshio-filter-comm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("custom.txt"), format!("||{custom_comm}^\n")).unwrap();
    let make = |protect: bool| {
        kuroshio_config::with_overrides(&json!({
            "filter": {
                "protectComm": protect,
                "customRules": ["./custom.txt"],
                "lists": [{ "name": "廣告", "url": format!("http://{srv}/ads.txt"), "category": "ads" }]
            }
        }))
    };
    let f = kuroshio::filtering::FilterService::from_cfg(&make(true), &dir).unwrap();
    f.reload_custom(true);
    f.update_lists(true).await.unwrap();
    let v = f.check(&comm, 1).unwrap();
    assert!(
        !v.block && v.allow && v.rule == "builtin-comm",
        "清單要擋的通訊類網域照樣放行：{v:?}"
    );
    assert!(f.check("ads.example.net", 1).unwrap().block, "其他網域照擋");
    assert!(f.check(&custom_comm, 1).unwrap().block, "自訂規則照樣優先");
    assert_eq!(f.stats()["commSpared"], 1);
    // 關掉保護：照清單擋
    let f = kuroshio::filtering::FilterService::from_cfg(&make(false), &dir).unwrap();
    f.update_lists(true).await.unwrap();
    assert!(f.check(&comm, 1).unwrap().block, "protectComm 關掉：照清單擋");
    let _ = std::fs::remove_dir_all(&dir);
}

/// 3.5.0 F11：內建一定通過的服務（五類各一，測試用 `*.essential.example.com` 注入）：清單要擋時放行、
/// `rule` 是 `builtin-<類別>`、每一類分開計；自訂規則要擋照擋（使用者明確要擋 NTP 也照擋）；`filter.protectComm` 關掉照清單擋
#[tokio::test]
async fn essential_not_blocked_by_list_but_blocked_by_custom_rule() {
    use kuroshio::resolver::FilterCheck;
    use kuroshio_net::comm::{CommKind, TEST_ENTRIES};
    kuroshio_net::comm::set_test_entries(TEST_ENTRIES);
    let list: String = TEST_ENTRIES.iter().map(|(s, _)| format!("||{s}^\n")).collect();
    let down = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let srv = lists_by_path(vec![("mal.txt", format!("{list}||bad.example.net^\n"))], down).await;
    let dir = std::env::temp_dir().join(format!("kuroshio-filter-essential-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // 自訂規則擋時間同步那一個的子網域
    std::fs::write(dir.join("custom.txt"), "||blocked.ntp.essential.example.com^\n").unwrap();
    let make = |protect: bool| {
        kuroshio_config::with_overrides(&json!({
            "filter": {
                "protectComm": protect,
                "customRules": ["./custom.txt"],
                "lists": [{ "name": "惡意", "url": format!("http://{srv}/mal.txt"), "category": "malware" }]
            }
        }))
    };
    let f = kuroshio::filtering::FilterService::from_cfg(&make(true), &dir).unwrap();
    f.reload_custom(true);
    f.update_lists(true).await.unwrap();
    for (s, k) in TEST_ENTRIES {
        let v = f.check(&format!("gw.{s}"), 1).unwrap();
        assert!(!v.block && v.allow, "{k:?}：清單要擋照樣放行：{v:?}");
        assert_eq!(v.rule, format!("builtin-{}", k.as_str()));
    }
    assert!(f.check("bad.example.net", 1).unwrap().block, "其他網域照擋");
    assert!(f.check("blocked.ntp.essential.example.com", 1).unwrap().block, "自訂規則照樣優先");
    let st = f.stats();
    assert_eq!(st["commSpared"], 5);
    assert_eq!(st["commSparedByKind"]["ntp"], 1);
    assert_eq!(st["commSparedByKind"]["quake"], 1);
    assert!(st["commSparedByKind"].get("apns").is_none(), "沒有放行過的不列");
    assert_eq!(CommKind::Apns.rule(), "builtin-comm", "推播照舊");
    // 關掉保護：照清單擋
    let f = kuroshio::filtering::FilterService::from_cfg(&make(false), &dir).unwrap();
    f.update_lists(true).await.unwrap();
    for (s, _) in TEST_ENTRIES {
        assert!(f.check(&format!("gw.{s}"), 1).unwrap().block, "protectComm 關掉：照清單擋 {s}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// 3.5.0 F11：自訂規則放行的照樣放行（內建表只在清單要擋時介入，`rule` 是自訂規則的）
#[tokio::test]
async fn custom_allow_still_wins() {
    use kuroshio::resolver::FilterCheck;
    use kuroshio_net::comm::TEST_ENTRIES;
    kuroshio_net::comm::set_test_entries(TEST_ENTRIES);
    let down = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let srv = lists_by_path(vec![("ads.txt", "||essential.example.com^\n".to_string())], down).await;
    let dir = std::env::temp_dir().join(format!("kuroshio-filter-essential-allow-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("custom.txt"), "@@||ocsp.essential.example.com^\n").unwrap();
    let cfg = kuroshio_config::with_overrides(&json!({
        "filter": {
            "customRules": ["./custom.txt"],
            "lists": [{ "name": "廣告", "url": format!("http://{srv}/ads.txt"), "category": "ads" }]
        }
    }));
    let f = kuroshio::filtering::FilterService::from_cfg(&cfg, &dir).unwrap();
    f.reload_custom(true);
    f.update_lists(true).await.unwrap();
    let v = f.check("gw.ocsp.essential.example.com", 1).unwrap();
    assert!(!v.block && v.allow, "{v:?}");
    assert!(!v.rule.starts_with("builtin-"), "自訂規則先判：{v:?}");
    assert_eq!(f.stats()["commSpared"], 0);
    // 不在內建表裡的同網域：照清單擋
    assert!(f.check("www.essential.example.com", 1).unwrap().block);
    let _ = std::fs::remove_dir_all(&dir);
}
