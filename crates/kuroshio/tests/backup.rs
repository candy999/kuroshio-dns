//! 備份匯出 / 匯入接上執行中的服務：管理 API 下載、上傳後等重新啟動才合併（記憶體裡的狀態先寫出，不會蓋掉合併結果）

use kuroshio::backup::{Bundle, Data, Kind, PENDING_FILE};
use serde_json::{json, Value};
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn domain(name: &str, at: u64, hits: u64) -> Value {
    json!({ "name": name, "provider": "cloudflare", "via": "cname", "firstSeen": 1000, "lastSeen": 2000, "hits": hits,
            "ips4": ["104.16.0.1"], "v4": { "verdict": "ok", "ip": "104.16.0.1", "at": at } })
}

fn config(dir: &Path) -> Value {
    kuroshio_config::with_overrides(&json!({
        "system": { "persistDir": dir.join("state").to_string_lossy(), "dataDir": dir.join("share").to_string_lossy() },
        "admin": { "port": 0, "auth": false }, "filter": { "enabled": false },
        "listen": { "plain": { "binds": ["127.0.0.1"], "port": 0 } },
        "upstream": { "pinned": ["udp://127.0.0.1:9"], "fallback": [] },
        "resolver": { "lastResort": [], "rankIps": false }
    }))
}

/// 一個 HTTP 請求（回 狀態碼、標頭、內容）
async fn http(addr: std::net::SocketAddr, method: &str, target: &str, headers: &[(&str, &str)], body: &[u8]) -> (u16, String, Vec<u8>) {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut head = format!(
        "{method} {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    s.write_all(head.as_bytes()).await.unwrap();
    s.write_all(body).await.unwrap();
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), s.read_to_end(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&buf[..end]).to_string();
    let code = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (code, head.to_ascii_lowercase(), buf[end + 4..].to_vec())
}

async fn get_json(addr: std::net::SocketAddr, target: &str) -> Value {
    req_json(addr, "GET", target).await
}

/// 會改東西的動作（POST）
async fn post_json(addr: std::net::SocketAddr, target: &str) -> Value {
    req_json(addr, "POST", target).await
}

async fn req_json(addr: std::net::SocketAddr, method: &str, target: &str) -> Value {
    let (code, _, b) = http(addr, method, target, &[], b"").await;
    assert_eq!(code, 200, "{target}：{}", String::from_utf8_lossy(&b));
    serde_json::from_slice(&b).unwrap()
}

/// 整個網域資料庫（分片或舊版單一檔案）
fn store_json(state: &Path) -> Value {
    serde_json::from_slice(&kuroshio_cdn::db::read_store_json(state).unwrap()).unwrap()
}

#[tokio::test]
async fn export_import_through_running_service() {
    let dir = std::env::temp_dir().join(format!("kuroshio-backup-it-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let state = dir.join("state");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::create_dir_all(dir.join("share")).unwrap();
    std::fs::write(
        state.join("cdn-domains.json"),
        serde_json::to_vec(&json!({ "domains": [domain("a.example", 100, 5)] })).unwrap(),
    )
    .unwrap();
    std::fs::write(state.join("blacklist.txt"), "# 本機\n203.0.113.9\n").unwrap();
    let cfg = config(&dir);

    let started = kuroshio::app::start(&cfg, kuroshio_config::Tier::Large).await.unwrap();
    let admin = started.admin.unwrap();
    assert!(started.resolver.cdn().is_some(), "CDN 有啟動");

    // 記憶體裡的變動（還沒寫到磁碟）
    let r = post_json(admin, "/api/cdn/policy?name=a.example&policy=always").await;
    assert_eq!(r["policy"], "always", "{r}");
    assert!(!String::from_utf8_lossy(&kuroshio_cdn::db::read_store_json(&state).unwrap()).contains("always"));

    // 匯出分享檔：先寫出記憶體，檔名、型態對；不含次數與手動設定
    let (code, head, body) = http(admin, "GET", "/api/backup/export?kind=share", &[], b"").await;
    assert_eq!(code, 200);
    assert!(head.contains("content-type: application/octet-stream"), "{head}");
    assert!(
        head.contains("content-disposition: attachment; filename=\"kuroshio-share-"),
        "{head}"
    );
    let share = Bundle::decode(&body).unwrap();
    assert_eq!(share.kind, Kind::Share);
    let d = &share.files["cdn-domains.json"];
    let Data::Json(dj) = d else { panic!("json") };
    assert_eq!(dj["domains"][0]["name"], "a.example");
    assert!(dj["domains"][0].get("hits").is_none() && dj["domains"][0].get("policy").is_none());
    assert!(
        !share.files.contains_key("blacklist.txt") && !share.files.contains_key("upstreams.json"),
        "分享檔不含上游評測與黑名單"
    );
    assert_eq!(
        store_json(&state)["domains"][0]["policy"],
        "always",
        "匯出前把記憶體裡的狀態寫出"
    );
    assert!(
        !state.join("cdn-domains.json").exists() && state.join("cdn/domains/manifest.json").exists(),
        "舊版單一檔案搬進分片（壓縮）後刪掉"
    );

    // 完整備份：有次數
    let (code, head, body) = http(admin, "GET", "/api/backup/export?kind=full", &[], b"").await;
    assert_eq!(code, 200);
    assert!(head.contains("filename=\"kuroshio-full-"));
    let full = Bundle::decode(&body).unwrap();
    let Data::Json(fj) = &full.files["cdn-domains.json"] else {
        panic!("json")
    };
    assert_eq!(fj["domains"][0]["hits"], 5);
    assert_eq!(http(admin, "GET", "/api/backup/export?kind=nope", &[], b"").await.0, 400);

    // 朋友給的分享檔（不信任）：a 的驗證「比較新」、多一個 b、多一筆黑名單
    let mut friend = share.clone();
    friend.files.insert(
        "cdn-domains.json".into(),
        Data::Json(json!({ "domains": [domain("a.example", 999, 0), domain("b.example", 500, 0)] })),
    );
    friend
        .files
        .insert("blacklist.txt".into(), Data::Text("198.51.100.7  # 朋友的\n203.0.113.9\n".into()));
    let bytes = friend.encode();

    // 存取控制與檢查
    let (code, _, _) = http(admin, "POST", "/api/backup/import", &[("Origin", "http://evil.example")], &bytes).await;
    assert_eq!(code, 403, "跨站請求");
    let (code, _, b) = http(admin, "POST", "/api/backup/import", &[], b"junk").await;
    assert_eq!(code, 400);
    assert!(String::from_utf8_lossy(&b).contains("不是黑潮 DNS 的備份檔"));
    assert!(!state.join(PENDING_FILE).exists());

    // 匯入前，記憶體裡又改了一次（關機時才會寫出）
    post_json(admin, "/api/cdn/policy?name=a.example&policy=never").await;
    let (code, _, b) = http(
        admin,
        "POST",
        "/api/backup/import",
        &[("Content-Type", "application/octet-stream")],
        &bytes,
    )
    .await;
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&b));
    let r: Value = serde_json::from_slice(&b).unwrap();
    assert_eq!((r["ok"].as_bool(), r["reloading"].as_bool()), (Some(true), Some(true)));
    assert_eq!(r["preview"]["kind"], "share");
    assert!(state.join(PENDING_FILE).exists(), "等重新啟動才合併");
    assert_eq!(get_json(admin, "/api/backup/last-import").await["none"], true);

    // 重新載入：舊的一輪寫出記憶體（policy never），新的一輪在讀狀態之前合併
    started.shutdown();
    let again = kuroshio::app::start(&cfg, kuroshio_config::Tier::Large).await.unwrap();
    assert!(!state.join(PENDING_FILE).exists(), "合併後刪掉");
    let a2 = again.admin.unwrap();
    let last = get_json(a2, "/api/backup/last-import").await;
    assert_eq!(last["ok"], true, "{last}");
    let item = |f: &str| last["items"].as_array().unwrap().iter().find(|i| i["file"] == f).unwrap().clone();
    assert_eq!(
        (
            item("cdn-domains.json")["added"].as_u64(),
            item("cdn-domains.json")["updated"].as_u64()
        ),
        (Some(1), Some(0))
    );
    assert_eq!(item("cdn-domains.json")["kept"], 1);
    assert_eq!(item("blacklist.txt")["added"], 0, "分享檔的黑名單不匯入");

    let cdn = again.resolver.cdn().unwrap();
    let a = cdn.domain("a.example").unwrap();
    assert_eq!(a["v4"]["at"], 100, "本機的驗證結果不會被分享檔蓋掉：{a}");
    assert_eq!(a["policy"], "never", "本機在記憶體裡的設定沒有被蓋掉");
    assert_eq!(a["hits"], 5, "本機的次數");
    // 新網域只是候選：沒有分享檔給的 IP、驗證已過期（本機重新驗證通過才會改寫）
    let b = cdn.domain("b.example").expect("新網域");
    assert_eq!(b["v4"]["verdict"], "ok");
    assert!(b["v4"].get("ip").is_none() && b["v4"].get("at").is_none(), "{b}");
    assert_eq!(b["v4"]["until"], 0, "{b}");
    assert_eq!(
        std::fs::read_to_string(state.join("blacklist.txt")).unwrap(),
        "# 本機\n203.0.113.9\n"
    );

    // 服務停著時：直接合併到磁碟
    again.shutdown();
    let r = kuroshio::backup::merge(&kuroshio::backup::Locations::from_cfg(&cfg), &friend);
    assert_eq!(r["ok"], true);
    let _ = std::fs::remove_dir_all(&dir);
}
