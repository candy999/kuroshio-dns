//! 管理 API 的防護：會改東西的動作只收 POST、跨站請求擋下、密碼不送到瀏覽器、
//! 回應標頭不能被查詢參數塞東西、沒登入的人不能讓服務收大檔案、uclient-fetch 的 chunked POST 讀得懂

use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn config(dir: &Path, auth: bool) -> Value {
    kuroshio_config::with_overrides(&json!({
        "system": { "persistDir": dir.join("state").to_string_lossy(), "dataDir": dir.join("share").to_string_lossy() },
        "admin": { "port": 0, "auth": auth }, "filter": { "enabled": false },
        "listen": { "plain": { "binds": ["127.0.0.1"], "port": 0 } },
        "upstream": { "pinned": ["udp://127.0.0.1:9"], "fallback": [] },
        "resolver": { "lastResort": [], "rankIps": false }
    }))
}

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("kuroshio-adminsec-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("state")).unwrap();
    std::fs::create_dir_all(d.join("share")).unwrap();
    d
}

/// 送出原始請求（`raw` 是標頭之後的全部內容），回（狀態碼、標頭小寫、內容）
async fn send(addr: SocketAddr, head: &str, raw: &[u8]) -> (u16, String, Vec<u8>) {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(head.as_bytes()).await.unwrap();
    let _ = s.write_all(raw).await;
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(30), s.read_to_end(&mut buf))
        .await
        .unwrap();
    let end = buf.windows(4).position(|w| w == b"\r\n\r\n").expect("有回應");
    let head = String::from_utf8_lossy(&buf[..end]).to_string();
    let code = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (code, head.to_ascii_lowercase(), buf[end + 4..].to_vec())
}

async fn http(addr: SocketAddr, method: &str, target: &str, headers: &[(&str, &str)], body: &[u8]) -> (u16, String, Vec<u8>) {
    let mut head = format!("{method} {target} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\n", body.len());
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    send(addr, &head, body).await
}

fn js(b: &[u8]) -> Value {
    serde_json::from_slice(b).unwrap_or(Value::Null)
}

#[tokio::test]
async fn state_changing_routes_need_post_and_same_origin() {
    let dir = tmp("post");
    // 關掉登入（OpenWrt 的預設）：這時候擋跨站請求只能靠方法與來源檢查
    let started = kuroshio::app::start(&config(&dir, false), kuroshio_config::Tier::Large)
        .await
        .unwrap();
    let admin = started.admin.unwrap();
    let origin = format!("http://{admin}");

    // 網頁用 <img src> 就能送出的 GET：一律 405，而且真的沒有執行
    for p in [
        "/api/cache/flush",
        "/api/jobs/run?name=benchmark",
        "/api/cdn/policy?name=a.example&policy=never",
        "/api/cdn/verify?name=a.example",
        "/api/ddns/update",
        "/api/acme/issue",
        "/api/filter/update",
        "/api/community/add?domain=evil.example",
        "/api/community/delete?domain=friend.example",
        "/api/community/rotate",
    ] {
        let (code, head, _) = http(admin, "GET", p, &[], b"").await;
        assert_eq!(code, 405, "{p}");
        assert!(head.contains("allow: post"), "{p}");
        assert_eq!(http(admin, "HEAD", p, &[], b"").await.0, 405, "{p}");
    }
    // 查看類的照常
    assert_eq!(http(admin, "GET", "/api/status", &[], b"").await.0, 200);
    assert_eq!(http(admin, "GET", "/api/jobs", &[], b"").await.0, 200);

    // POST：同一個來源可以；別的網站、同一台電腦別的埠、沙箱 iframe 都不行
    assert_eq!(http(admin, "POST", "/api/cache/flush", &[("Origin", &origin)], b"").await.0, 200);
    assert_eq!(
        http(admin, "POST", "/api/cache/flush", &[], b"").await.0,
        200,
        "rpcd / 指令列不帶 Origin"
    );
    for o in ["http://evil.example", "http://127.0.0.1:1", "http://localhost:1", "null"] {
        let (code, _, _) = http(admin, "POST", "/api/cache/flush", &[("Origin", o)], b"").await;
        assert_eq!(code, 403, "Origin {o}");
    }
    // 瀏覽器標明是跨站的請求：連查看類的也不給
    for site in ["cross-site", "same-site"] {
        let (code, _, _) = http(admin, "GET", "/api/status", &[("Sec-Fetch-Site", site)], b"").await;
        assert_eq!(code, 403, "{site}");
    }
    assert_eq!(
        http(admin, "GET", "/api/status", &[("Sec-Fetch-Site", "same-origin")], b"").await.0,
        200
    );

    // uclient-fetch --post-data 送的是 chunked，沒有 Content-Length
    let head = format!("POST /api/cache/flush HTTP/1.1\r\nHost: {admin}\r\nTransfer-Encoding: chunked\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n");
    let (code, _, body) = send(admin, &head, b"1\r\n_\r\n0\r\n\r\n").await;
    assert_eq!((code, js(&body)["ok"].clone()), (200, json!(true)));
    // 分好幾段、帶擴充欄位也可以；超過上限的拒絕
    let (code, _, _) = send(admin, &head, b"3;x=1\r\nabc\r\n2\r\nde\r\n0\r\nTrailer: x\r\n\r\n").await;
    assert_eq!(code, 200);
    let (code, _, body) = send(admin, &head, b"200000\r\n").await;
    assert_eq!(code, 400, "{}", String::from_utf8_lossy(&body));
    let (code, _, _) = send(admin, &head, b"zz\r\n").await;
    assert_eq!(code, 400);

    // 查詢參數不能在回應標頭裡多塞一行
    let (code, head, _) = http(
        admin,
        "GET",
        "/api/cdn/domains?format=csv&provider=x%0d%0aSet-Cookie:%20evil=1",
        &[],
        b"",
    )
    .await;
    assert_eq!(code, 200);
    assert!(!head.contains("\nset-cookie"), "{head}");
    assert!(
        head.contains("content-disposition: attachment; filename=\"cdn-domains-x__set-cookie__evil_1.csv\""),
        "{head}"
    );

    started.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn login_secrets_and_upload_limits() {
    let dir = tmp("auth");
    let cfg_file = dir.join("config.json");
    let user_cfg = json!({ "ddns": { "apiToken": "cf-real-token-123", "zone": "example.com" }, "resolver": { "timeoutMs": 1234 } });
    std::fs::write(&cfg_file, serde_json::to_vec_pretty(&user_cfg).unwrap()).unwrap();
    let started = kuroshio::app::start(&config(&dir, true), kuroshio_config::Tier::Large)
        .await
        .unwrap();
    let admin = started.admin.unwrap();
    let ui = &started.state.webui;
    let _ = ui.config_file.set(cfg_file.clone());
    let token = std::fs::read_to_string(ui.token_file.as_ref().unwrap()).unwrap().trim().to_string();
    let bearer = format!("Bearer {token}");
    let auth = [("Authorization", bearer.as_str())];

    // 沒登入：API 401；/api/session 不透露設定檔位置
    assert_eq!(http(admin, "GET", "/api/status", &[], b"").await.0, 401);
    let (_, _, b) = http(admin, "GET", "/api/session", &[], b"").await;
    assert_eq!(js(&b)["configFile"], Value::Null);
    assert!(!String::from_utf8_lossy(&b).contains("config.json"));
    let (_, _, b) = http(admin, "GET", "/api/session", &auth, b"").await;
    assert!(js(&b)["configFile"].as_str().unwrap().ends_with("config.json"));

    // 登入失敗要等一下才回應；成功拿到 HttpOnly、SameSite=Strict 的 cookie
    let t0 = Instant::now();
    let (code, head, _) = http(admin, "GET", "/login?token=wrong", &[], b"").await;
    assert_eq!(code, 303);
    assert!(head.contains("location: /?login=failed") && !head.contains("set-cookie"));
    assert!(t0.elapsed() >= Duration::from_millis(450), "猜 token 有延遲：{:?}", t0.elapsed());
    let (code, head, _) = http(admin, "GET", &format!("/login?token={token}"), &[], b"").await;
    assert_eq!(code, 303);
    assert!(head.contains("httponly") && head.contains("samesite=strict"), "{head}");

    // 讀設定：Token 換成遮罩，哪裡都看不到原本的值
    let (code, _, b) = http(admin, "GET", "/api/config", &auth, b"").await;
    assert_eq!(code, 200);
    let text = String::from_utf8_lossy(&b).to_string();
    assert!(!text.contains("cf-real-token-123"), "設定頁拿不到 API Token");
    let v = js(&b);
    assert_eq!(v["user"]["ddns"]["apiToken"], "********");
    assert_eq!(v["effective"]["ddns"]["apiToken"], "********");
    assert_eq!(v["user"]["ddns"]["zone"], "example.com");

    // 原樣存回去（遮罩）＋改別的欄位：檔案裡的 Token 不變
    let mut edited = v["user"].clone();
    edited["resolver"]["timeoutMs"] = json!(1500);
    let body = serde_json::to_vec(&edited).unwrap();
    let (code, _, b) = http(admin, "PUT", "/api/config", &auth, &body).await;
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&b));
    let saved: Value = serde_json::from_slice(&std::fs::read(&cfg_file).unwrap()).unwrap();
    assert_eq!(saved["ddns"]["apiToken"], "cf-real-token-123");
    assert_eq!(saved["resolver"]["timeoutMs"], 1500);
    // 填新的 Token：換掉
    edited["ddns"]["apiToken"] = json!("cf-new-token-456");
    let body = serde_json::to_vec(&edited).unwrap();
    assert_eq!(http(admin, "PUT", "/api/config", &auth, &body).await.0, 200);
    let saved: Value = serde_json::from_slice(&std::fs::read(&cfg_file).unwrap()).unwrap();
    assert_eq!(saved["ddns"]["apiToken"], "cf-new-token-456");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&cfg_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "設定檔（有 API Token）只有擁有者能讀");
    }

    // 沒登入的人說要上傳 8 MB：不收內容直接拒絕（已登入的匯入才有 64 MB 的額度）
    let head = format!(
        "POST /api/backup/import HTTP/1.1\r\nHost: {admin}\r\nContent-Length: {}\r\n\r\n",
        8 << 20
    );
    let t0 = Instant::now();
    let (code, _, b) = send(admin, &head, b"x").await;
    assert_eq!(code, 400, "{}", String::from_utf8_lossy(&b));
    assert!(t0.elapsed() < Duration::from_secs(5), "不等內容送完");
    // 已登入、但來源是別的網站：一樣不收
    let head = format!(
        "POST /api/backup/import HTTP/1.1\r\nHost: {admin}\r\nAuthorization: {bearer}\r\nOrigin: http://evil.example\r\nContent-Length: {}\r\n\r\n",
        8 << 20
    );
    assert_eq!(send(admin, &head, b"x").await.0, 400);
    // 已登入：8 MB 的垃圾收得下來，由備份格式檢查拒絕（不是大小）
    let junk = vec![b'x'; 2 << 20];
    let (code, _, b) = http(admin, "POST", "/api/backup/import", &auth, &junk).await;
    assert_eq!(code, 400);
    assert!(
        js(&b)["error"].as_str().unwrap().contains("備份檔"),
        "{}",
        String::from_utf8_lossy(&b)
    );

    started.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}
