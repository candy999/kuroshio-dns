//! 記憶體「不足」路徑的測試開關（3.5.0 C9）：`POST /api/memory/simulate` 只收 POST、要登入、要 `system.testHooks`。
//!
//! 獨立一個測試檔（獨立的行程）：模擬狀態是整個行程共用的，服務啟動時（testHooks 沒開）會取消進行中的模擬，
//! 跟其他會啟動服務的測試放在一起會互相干擾

use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
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
    let d = std::env::temp_dir().join(format!("kuroshio-memsim-{tag}-{}", std::process::id()));
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

/// 3.5.0 C9：記憶體模擬是會改變狀態的動作（只收 POST、要登入）；沒開 `system.testHooks` 時 403；
/// 開了才接受，`/api/status` 的 `memory.simulated` 看得到，`off=1` 立刻取消
#[tokio::test]
async fn memory_simulate_needs_post_login_and_test_hooks() {
    let base = |dir: &Path, hooks: bool| {
        let mut c = config(dir, true);
        c["system"]["testHooks"] = json!(hooks);
        c
    };
    // 沒開：登入了也是 403
    let dir = tmp("simoff");
    let started = kuroshio::app::start(&base(&dir, false)).await.unwrap();
    let admin = started.admin.unwrap();
    let token = std::fs::read_to_string(started.state.webui.token_file.as_ref().unwrap()).unwrap();
    let bearer = format!("Bearer {}", token.trim());
    let auth = [("Authorization", bearer.as_str())];
    let target = "/api/memory/simulate?availMB=1048576&minutes=1";
    assert_eq!(http(admin, "POST", target, &[], b"").await.0, 401, "要登入");
    assert_eq!(http(admin, "GET", target, &auth, b"").await.0, 405, "只收 POST");
    let (code, _, b) = http(admin, "POST", target, &auth, b"").await;
    assert_eq!(code, 403);
    assert!(js(&b)["error"].as_str().unwrap().contains("system.testHooks"));
    let (_, _, b) = http(admin, "GET", "/api/status", &auth, b"").await;
    assert_eq!(js(&b)["memory"]["simulated"], Value::Null);
    drop(started);

    // 開了：接受。模擬值給很大（取 min(真實值, 模擬值) = 真實值），同一個行程裡的其他測試不受影響
    let dir = tmp("simon");
    let started = kuroshio::app::start(&base(&dir, true)).await.unwrap();
    let admin = started.admin.unwrap();
    let token = std::fs::read_to_string(started.state.webui.token_file.as_ref().unwrap()).unwrap();
    let bearer = format!("Bearer {}", token.trim());
    let auth = [("Authorization", bearer.as_str())];
    assert_eq!(
        http(admin, "POST", "/api/memory/simulate?minutes=3", &auth, b"").await.0,
        400,
        "要給 availMB"
    );
    let (code, _, b) = http(admin, "POST", target, &auth, b"").await;
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&b));
    assert_eq!(js(&b)["minutes"], 1);
    let (_, _, b) = http(admin, "GET", "/api/status", &auth, b"").await;
    let sim = &js(&b)["memory"]["simulated"];
    assert_eq!(sim["availMB"], 1_048_576, "{sim}");
    assert!(sim["remainingSec"].as_u64().unwrap() <= 60);
    assert!(sim["until"].as_u64().unwrap() > 0);
    let (code, _, b) = http(admin, "POST", "/api/memory/simulate?off=1", &auth, b"").await;
    assert_eq!((code, js(&b)["wasOn"].clone()), (200, json!(true)));
    let (_, _, b) = http(admin, "GET", "/api/status", &auth, b"").await;
    assert_eq!(js(&b)["memory"]["simulated"], Value::Null);
}
