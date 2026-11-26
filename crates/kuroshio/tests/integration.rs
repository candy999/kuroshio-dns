//! 給其他平台用的介面（docs/integration.md）：`kuroshio health`、`kuroshio status --json`、
//! `kuroshio notify wan-changed` 的結束碼與輸出，以及（Unix）SIGHUP / SIGUSR1、`KUROSHIO_INIT_CONFIG`。
//!
//! 實際執行編好的 `kuroshio` 指令；服務在測試行程裡啟動（或另外啟動 `kuroshio run`）。
//! 上游指向不會用到的本機位址，背景工作、CDN、過濾都關掉，不連外。

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("kuroshio-integration-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("state")).unwrap();
    d
}

/// 使用者設定（JSON 檔的內容）
fn user_cfg(dir: &Path, dns_port: u16, admin_port: u16, auth: bool) -> Value {
    json!({
        "system": { "persistDir": dir.join("state").to_string_lossy(), "dataDir": root().join("data").to_string_lossy(),
                    "runtimeDir": dir.join("run").to_string_lossy() },
        "admin": { "port": admin_port, "auth": auth },
        "filter": { "enabled": false }, "cdn": { "enabled": false },
        "listen": { "plain": { "binds": ["127.0.0.1"], "port": dns_port } },
        "upstream": { "pinned": ["udp://127.0.0.1:9"], "fallback": [] },
        "resolver": { "lastResort": [], "rankIps": false },
        "jobs": { "dns-benchmark": { "enabled": false }, "cdn-pool": { "enabled": false }, "cdn-ranges": { "enabled": false },
                  "cdn-scan": { "enabled": false }, "tw-ip": { "enabled": false } },
    })
}

fn write_cfg(path: &Path, v: &Value) {
    std::fs::write(path, serde_json::to_vec_pretty(v).unwrap()).unwrap();
}

/// 執行 kuroshio（阻塞，放在 spawn_blocking 裡）：回（結束碼、標準輸出）
fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_kuroshio"))
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).to_string())
}

async fn run_async(args: Vec<String>) -> (i32, String) {
    tokio::task::spawn_blocking(move || run(&args.iter().map(String::as_str).collect::<Vec<_>>()))
        .await
        .unwrap()
}

fn one_line_json(s: &str) -> Value {
    assert_eq!(s.trim().lines().count(), 1, "只有一行：{s}");
    serde_json::from_str(s.trim()).unwrap_or_else(|e| panic!("{e}：{s}"))
}

/// 空著的埠。同一個測試行程裡不會給同一個埠兩次（系統配的埠關掉之後很快又會配出來，
/// 平行跑的測試各自起的服務會撞在同一個埠上）
fn free_port() -> u16 {
    static GIVEN: std::sync::Mutex<Vec<u16>> = std::sync::Mutex::new(Vec::new());
    loop {
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let mut given = GIVEN.lock().unwrap();
        if !given.contains(&port) {
            given.push(port);
            return port;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_status_notify_exit_codes() {
    let dir = tmp("cli");
    // 先在測試行程裡啟動（埠號 0），再把實際的埠號寫進給指令列讀的設定檔；開登入，指令列要從 token 檔拿 token
    let cfg = kuroshio_config::with_overrides(&user_cfg(&dir, 0, 0, true));
    let started = kuroshio::app::start(&cfg).await.unwrap();
    let dns = started.bound.iter().find(|a| a.is_ipv4()).unwrap().port();
    let admin = started.admin.unwrap().port();
    let file = dir.join("config.json");
    write_cfg(&file, &user_cfg(&dir, dns, admin, true));
    // `kuroshio run` 會記下設定檔（不是 UCI）；這裡在行程內啟動，自己記
    let _ = started.state.webui.config_file.set(file.clone());
    let c = file.to_string_lossy().to_string();
    let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();

    // health：有回答
    let (code, out) = run_async(a(&["health", "-c", &c, "--json"])).await;
    let v = one_line_json(&out);
    assert_eq!(code, 0, "{out}");
    assert_eq!(v["ok"], true);
    assert_eq!(v["server"], format!("127.0.0.1:{dns}"));
    assert!(v["ms"].is_u64());
    assert_eq!(v["error"], Value::Null);
    let (code, out) = run_async(a(&["health", "-c", &c])).await;
    assert_eq!(code, 0);
    assert!(out.contains("有回答"), "{out}");

    // status --json：穩定欄位
    let (code, out) = run_async(a(&["status", "--json", "-c", &c])).await;
    assert_eq!(code, 0, "{out}");
    let s = one_line_json(&out);
    assert_eq!(s["running"], true);
    assert_eq!(s["version"], env!("CARGO_PKG_VERSION"));
    assert!(s["uptimeSec"].is_u64());
    assert_eq!(s["config"], "json");
    assert_eq!(s["upstreams"][0]["url"], "udp://127.0.0.1:9");
    assert_eq!(s["upstreams"][0]["type"], "udp");
    assert!(s["cache"]["entries"].is_u64());
    assert_eq!(s["filter"]["enabled"], false);
    assert!(s["storage"]["class"].is_string());
    assert_eq!(s["storage"]["dir"], json!(dir.join("state")));
    assert_eq!(s["clock"]["synced"], true);
    assert_eq!(s["data"]["ok"], true, "{s}");
    assert_eq!(s["data"]["format"], kuroshio::manifest::DATA_FORMAT);
    assert_eq!(s["data"]["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(s["warnings"], json!([]), "{s}");
    let (code, out) = run_async(a(&["status", "-c", &c])).await;
    assert_eq!(code, 0);
    assert!(out.contains("執行中"), "{out}");

    // notify wan-changed：送達（DDNS 沒開也是 0）
    let (code, out) = run_async(a(&["notify", "wan-changed", "-c", &c])).await;
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("DDNS 沒有啟用"), "{out}");

    // notify save：立刻寫出快照（Windows 沒有 SIGUSR1，用這個）
    let (code, out) = run_async(a(&["notify", "save", "-c", &c])).await;
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("已儲存學習資料"), "{out}");

    // notify trim：先讓出記憶體，指定時間內不長大、不恢復
    let (code, out) = run_async(a(&["notify", "trim", "--hold", "60", "-c", &c])).await;
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("已先讓出記憶體") || out.contains("記憶體控制沒有啟用"), "{out}");
    assert!(out.contains("60 秒") || out.contains("沒有啟用"), "{out}");

    // token 錯了：服務在，但讀不到狀態
    let token = kuroshio::webui::token_file(&cfg, &dir).unwrap();
    let real = std::fs::read(&token).unwrap();
    std::fs::write(&token, b"wrong").unwrap();
    let (code, out) = run_async(a(&["status", "--json", "-c", &c])).await;
    assert_eq!(code, 1);
    assert_eq!(one_line_json(&out)["running"], true);
    std::fs::write(&token, real).unwrap();

    // 明文 DNS 關掉：health 沒辦法檢查 → 1
    let off = dir.join("off.json");
    let mut u = user_cfg(&dir, dns, admin, true);
    u["listen"]["plain"]["enabled"] = json!(false);
    write_cfg(&off, &u);
    let (code, out) = run_async(a(&["health", "-c", off.to_str().unwrap(), "--json"])).await;
    assert_eq!(code, 1);
    assert!(one_line_json(&out)["error"].as_str().unwrap().contains("沒有開啟"));

    // 設定檔壞掉：2
    let bad = dir.join("bad.json");
    std::fs::write(&bad, b"{ not json").unwrap();
    for cmd in [vec!["health", "--json"], vec!["status", "--json"]] {
        let mut args = a(&cmd);
        args.extend(a(&["-c", bad.to_str().unwrap()]));
        let (code, out) = run_async(args).await;
        assert_eq!(code, 2, "{cmd:?} {out}");
        assert!(one_line_json(&out).get("error").is_some());
    }
    let (code, _) = run_async(a(&["notify", "wan-changed", "-c", bad.to_str().unwrap()])).await;
    assert_eq!(code, 2);
    // --uci 卻沒有 /etc/config/kuroshio（第三方韌體直接執行）：提示設定 KUROSHIO_UCI_FILE
    if !Path::new("/etc/config/kuroshio").exists() && std::env::var_os("KUROSHIO_UCI_FILE").is_none() {
        let (code, out) = run(&["status", "--json", "--uci"]);
        assert_eq!(code, 2, "{out}");
        assert!(
            one_line_json(&out)["error"].as_str().unwrap_or("").contains("KUROSHIO_UCI_FILE"),
            "{out}"
        );
    }

    // 服務停了：都是 1
    started.shutdown();
    drop(started);
    let gone = dir.join("gone.json");
    write_cfg(&gone, &user_cfg(&dir, free_port(), free_port(), true));
    let g = gone.to_string_lossy().to_string();
    let (code, out) = run_async(a(&["health", "-c", &g, "--json", "--timeout", "300"])).await;
    assert_eq!(code, 1, "{out}");
    assert_eq!(one_line_json(&out)["ok"], false);
    let (code, out) = run_async(a(&["status", "--json", "-c", &g])).await;
    assert_eq!(code, 1);
    let v = one_line_json(&out);
    assert_eq!(v["running"], false);
    assert!(v["error"].is_string());
    let (code, _) = run_async(a(&["notify", "wan-changed", "-c", &g])).await;
    assert_eq!(code, 1);
    let (code, _) = run_async(a(&["notify", "save", "-c", &g])).await;
    assert_eq!(code, 1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `POST /api/persist/flush`（立即儲存學習資料）與 `POST /api/filter/reset-rules`（恢復預設自訂規則）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn persist_flush_and_reset_custom_rules() {
    let dir = tmp("flush");
    // 唯讀資料目錄放一份「這個版本的預設自訂規則」：優先用它，不用執行檔內建的
    let share = dir.join("share");
    std::fs::create_dir_all(&share).unwrap();
    std::fs::write(share.join("default-custom-rules.txt"), "! 預設\n||default.example.com^\n").unwrap();
    let rules = dir.join("custom-rules.txt");
    std::fs::write(&rules, "||mine.example.com^\n").unwrap();
    let mut u = user_cfg(&dir, 0, 0, false);
    u["system"]["dataDir"] = json!(share);
    u["filter"] = json!({ "enabled": true, "customRules": ["./custom-rules.txt"], "lists": [] });
    let cfg = kuroshio_config::with_overrides(&u);
    let started = kuroshio::app::start(&cfg).await.unwrap();
    let st = &started.state;
    let none = Default::default();
    let check = |name: &'static str| {
        let q = [("name".to_string(), name.to_string())].into_iter().collect();
        async move { kuroshio::admin::route(st, "/api/filter/check", &q).await.body["action"].clone() }
    };
    assert_eq!(check("mine.example.com").await, "block");

    // 立即儲存學習資料：回寫了幾份、幾 bytes、時間（毫秒）
    let r = kuroshio::admin::route(st, "/api/persist/flush", &none).await;
    assert_eq!(r.code, 200, "{}", r.body);
    assert_eq!(r.body["ok"], true);
    assert!(r.body["files"].is_u64() && r.body["bytes"].is_u64(), "{}", r.body);
    assert!(r.body["at"].as_u64().unwrap() > 1_700_000_000_000);
    assert_eq!(r.body["dir"], json!(dir.join("state")));
    // 馬上再按一次：沒有新的變動
    let r = kuroshio::admin::route(st, "/api/persist/flush", &none).await;
    assert_eq!(r.body["files"], 0, "{}", r.body);
    assert_eq!(r.body["bytes"], 0);

    // 恢復預設自訂規則：原本的內容備份成 custom-rules.txt.bak，立刻生效
    let r = kuroshio::admin::route(st, "/api/filter/reset-rules", &none).await;
    assert_eq!(r.code, 200, "{}", r.body);
    assert_eq!(r.body["changed"], true);
    assert_eq!(r.body["reloaded"], true);
    assert_eq!(
        r.body["source"],
        json!(share.join("default-custom-rules.txt").display().to_string())
    );
    let bak = dir.join("custom-rules.txt.bak");
    assert_eq!(r.body["backup"], json!(bak));
    assert_eq!(std::fs::read_to_string(&bak).unwrap(), "||mine.example.com^\n");
    assert_eq!(std::fs::read_to_string(&rules).unwrap(), "! 預設\n||default.example.com^\n");
    assert_eq!(check("mine.example.com").await, "none");
    assert_eq!(check("default.example.com").await, "block");
    // 已經是預設：不動檔案，也不蓋掉上一次的備份
    let r = kuroshio::admin::route(st, "/api/filter/reset-rules", &none).await;
    assert_eq!(r.body["changed"], false, "{}", r.body);
    assert_eq!(std::fs::read_to_string(&bak).unwrap(), "||mine.example.com^\n");
    started.shutdown();
    drop(started);

    // 唯讀資料目錄沒有預設規則檔：用執行檔內建的；自訂規則檔不存在時沒有備份
    std::fs::remove_file(share.join("default-custom-rules.txt")).unwrap();
    std::fs::remove_file(&rules).unwrap();
    let v = kuroshio::filtering::reset_custom_rules(&rules, &share).unwrap();
    assert_eq!(v["source"], "builtin");
    assert_eq!(v["backup"], Value::Null);
    assert_eq!(std::fs::read_to_string(&rules).unwrap(), kuroshio::filtering::DEFAULT_CUSTOM_RULES);
    let _ = std::fs::remove_dir_all(&dir);
}

/// 3.5.0 F2（D32）：`/api/status?lite=1` 不帶每個快照檔一筆的 `system.persist.files`，改帶 `filesSummary`；
/// 不帶 `lite` 的完整回應兩個都有，而且加總跟逐檔的一致
async fn status_with(st: &std::sync::Arc<kuroshio::app::AppState>, lite: bool) -> Value {
    let q = if lite {
        [("lite".to_string(), "1".to_string())].into_iter().collect()
    } else {
        Default::default()
    };
    let r = kuroshio::admin::route(st, "/api/status", &q).await;
    assert_eq!(r.code, 200, "{}", r.body);
    r.body
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_lite_omits_persist_files_but_has_summary() {
    let dir = tmp("lite");
    let cfg = kuroshio_config::with_overrides(&user_cfg(&dir, 0, 0, false));
    let started = kuroshio::app::start(&cfg).await.unwrap();
    let st = &started.state;
    // 先寫一次，讓快照檔有大小與寫入時間
    let r = kuroshio::admin::route(st, "/api/persist/flush", &Default::default()).await;
    assert_eq!(r.code, 200, "{}", r.body);
    let v = status_with(st, true).await;
    let p = &v["system"]["persist"];
    assert!(p.get("files").is_none(), "lite=1 不帶 files：{p}");
    let sum = &p["filesSummary"];
    for k in ["count", "bytes", "compressed", "pending"] {
        assert!(sum[k].is_u64(), "{k}：{sum}");
    }
    assert!(sum.get("oldestWriteAt").is_some(), "{sum}");
    // 其他加總欄位照帶（介面讀的就是這些）
    for k in ["bytesToday", "oldestUnsavedSec", "maxAgeHours", "space"] {
        assert!(p.get(k).is_some(), "{k}：{p}");
    }
    assert!(v.get("perf").is_none(), "perf 照舊不帶");
    // 3.5.0 F6／H12：system.rssKB 每個平台都有（跟 memory.rssKB 同一個來源）
    assert!(v["system"]["rssKB"].as_u64().is_some_and(|k| k > 0), "{}", v["system"]["rssKB"]);
    started.shutdown();
    drop(started);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_full_keeps_files() {
    let dir = tmp("full");
    let cfg = kuroshio_config::with_overrides(&user_cfg(&dir, 0, 0, false));
    let started = kuroshio::app::start(&cfg).await.unwrap();
    let st = &started.state;
    let r = kuroshio::admin::route(st, "/api/persist/flush", &Default::default()).await;
    assert_eq!(r.code, 200, "{}", r.body);
    let v = status_with(st, false).await;
    let p = &v["system"]["persist"];
    let files = p["files"].as_object().unwrap_or_else(|| panic!("完整回應有 files：{p}"));
    let sum = &p["filesSummary"];
    assert_eq!(sum["count"], json!(files.len()), "{sum}");
    let bytes: u64 = files.values().map(|f| f["size"].as_u64().unwrap_or(0)).sum();
    assert_eq!(sum["bytes"], json!(bytes));
    let compressed = files.values().filter(|f| f["compressed"] == true).count();
    assert_eq!(sum["compressed"], json!(compressed));
    let oldest = files.values().filter_map(|f| f["lastWrite"].as_u64()).min();
    assert_eq!(sum["oldestWriteAt"], json!(oldest));
    assert!(v.get("perf").is_some());
    started.shutdown();
    drop(started);
    let _ = std::fs::remove_dir_all(&dir);
}

/// 3.5.0 F14：重新載入（`shutdown()`）把排隊中與執行中的工作交給下一輪；程式結束（`shutdown_for()`）不交接
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exit_does_not_hand_off() {
    let dir = tmp("handoff");
    let cfg = kuroshio_config::with_overrides(&user_cfg(&dir, 0, 0, false));
    // 一個一直跑的工作與一個排隊中的（本機的假工作，不連外）
    let busy = |started: &kuroshio::app::Started| {
        let s = started.state.scheduler.clone().unwrap();
        s.register("test-wait", |_ctx: kuroshio_jobs::JobCtx| async {
            std::future::pending::<()>().await;
            Ok(())
        });
        s.register("test-next", |_ctx: kuroshio_jobs::JobCtx| async { Ok(()) });
        assert_eq!(s.request("test-wait", "測試"), json!({ "ok": true }));
        assert_eq!(s.request("test-next", "測試"), json!({ "ok": true }));
        s
    };
    let started = kuroshio::app::start(&cfg).await.unwrap();
    let s = busy(&started);
    let t0 = std::time::Instant::now();
    while s.running().is_none() {
        assert!(t0.elapsed() < std::time::Duration::from_secs(5));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    started.shutdown_for(kuroshio::app::StopReason::Quit);
    assert!(!kuroshio::app::job_handoff_pending(), "程式結束：不交接");
    drop(started);
    // 重新載入：交接
    let started = kuroshio::app::start(&cfg).await.unwrap();
    let s = busy(&started);
    let t0 = std::time::Instant::now();
    while s.running().is_none() {
        assert!(t0.elapsed() < std::time::Duration::from_secs(5));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    started.shutdown();
    assert!(kuroshio::app::job_handoff_pending(), "重新載入：交給下一輪");
    drop(started);
    // 下一輪（同一個快照目錄）接手：假工作在新的一輪沒有註冊，取消並寫日誌，交接清空
    let started = kuroshio::app::start(&cfg).await.unwrap();
    let t0 = std::time::Instant::now();
    while kuroshio::app::job_handoff_pending() {
        assert!(t0.elapsed() < std::time::Duration::from_secs(5), "下一輪沒有接手");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    started.shutdown_for(kuroshio::app::StopReason::Quit);
    drop(started);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `kuroshio run`：KUROSHIO_INIT_CONFIG 建立設定檔；SIGUSR1 寫出快照、SIGHUP 重新載入（都不結束）；SIGTERM 結束
#[cfg(unix)]
#[test]
fn run_signals_and_init_config() {
    use std::io::{BufRead, BufReader};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    let dir = tmp("run");
    let (dns, admin) = (free_port(), free_port());
    let init = dir.join("image-default.json");
    write_cfg(&init, &user_cfg(&dir, dns, admin, false));
    let conf = dir.join("config/sub/config.json");
    let c = conf.to_string_lossy().to_string();
    let mut child = Command::new(env!("CARGO_BIN_EXE_kuroshio"))
        .args(["run", "-c", &c])
        .env("NO_COLOR", "1")
        .env("KUROSHIO_LOG", "info")
        .env("KUROSHIO_INIT_CONFIG", &init)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .stdin(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let log = Arc::new(Mutex::new(String::new()));
    for pipe in [
        Box::new(child.stdout.take().unwrap()) as Box<dyn std::io::Read + Send>,
        Box::new(child.stderr.take().unwrap()),
    ] {
        let log = log.clone();
        std::thread::spawn(move || {
            for l in BufReader::new(pipe).lines().map_while(Result::ok) {
                let mut g = log.lock().unwrap();
                g.push_str(&l);
                g.push('\n');
            }
        });
    }
    let wait_for = |pred: &dyn Fn(&str) -> bool, what: &str| {
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(30) {
            if pred(&log.lock().unwrap()) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("等不到 {what}：\n{}", log.lock().unwrap());
    };
    let healthy = || {
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(30) {
            if run(&["health", "-c", &c, "--timeout", "500"]).0 == 0 {
                return;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        panic!("服務沒有回答：\n{}", log.lock().unwrap());
    };
    healthy();
    assert!(conf.is_file(), "從 KUROSHIO_INIT_CONFIG 複製");
    assert_eq!(std::fs::read(&conf).unwrap(), std::fs::read(&init).unwrap());
    assert!(log.lock().unwrap().contains("KUROSHIO_INIT_CONFIG"));
    let pid = child.id() as i32;
    let kill = |sig: i32| assert_eq!(unsafe { libc::kill(pid, sig) }, 0);
    kill(libc::SIGUSR1);
    wait_for(&|l| l.contains("收到 SIGUSR1"), "SIGUSR1 的紀錄");
    kill(libc::SIGHUP);
    wait_for(&|l| l.contains("收到 SIGHUP") && l.contains("重新載入"), "SIGHUP 的紀錄");
    assert!(child.try_wait().unwrap().is_none(), "收到 SIGHUP / SIGUSR1 不結束");
    healthy();
    assert_eq!(run(&["status", "--json", "-c", &c]).0, 0);
    kill(libc::SIGTERM);
    let t0 = Instant::now();
    let st = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break st;
        }
        assert!(t0.elapsed() < Duration::from_secs(30), "SIGTERM 後要結束");
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(st.success(), "{st:?}\n{}", log.lock().unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}

/// 3.5.1 N1：記憶體回不來時的原地重新啟動：照正常停止寫完快照，用同一個 PID 重新執行（看門狗、procd 不會誤判），
/// 新的行程帶著這次的時間（`KUROSHIO_MEMORY_RESTART_AT`，6 小時內不再做），DNS 幾秒內恢復
#[cfg(target_os = "linux")]
#[test]
fn memory_restart_reexecs_with_same_pid() {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    let dir = tmp("memrestart");
    let (dns, admin) = (free_port(), free_port());
    let conf = dir.join("config.json");
    let mut cfg = user_cfg(&dir, dns, admin, false);
    cfg["system"]["testHooks"] = json!(true);
    write_cfg(&conf, &cfg);
    let c = conf.to_string_lossy().to_string();
    let mut child = Command::new(env!("CARGO_BIN_EXE_kuroshio"))
        .args(["run", "-c", &c])
        .env("NO_COLOR", "1")
        .env("KUROSHIO_LOG", "info")
        .env_remove(kuroshio::memgov::RESTART_ENV)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .stdin(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let log = Arc::new(Mutex::new(String::new()));
    for pipe in [
        Box::new(child.stdout.take().unwrap()) as Box<dyn std::io::Read + Send>,
        Box::new(child.stderr.take().unwrap()),
    ] {
        let log = log.clone();
        std::thread::spawn(move || {
            for l in BufReader::new(pipe).lines().map_while(Result::ok) {
                let mut g = log.lock().unwrap();
                g.push_str(&l);
                g.push('\n');
            }
        });
    }
    let healthy = || {
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(30) {
            if run(&["health", "-c", &c, "--timeout", "500"]).0 == 0 {
                return;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        panic!("服務沒有回答：\n{}", log.lock().unwrap());
    };
    healthy();
    let pid = child.id();
    let environ = || std::fs::read(format!("/proc/{pid}/environ")).unwrap_or_default();
    let has_env = |e: &[u8]| {
        e.split(|b| *b == 0)
            .any(|kv| kv.starts_with(kuroshio::memgov::RESTART_ENV.as_bytes()))
    };
    assert!(!has_env(&environ()));
    // 測試開關要求原地重新啟動（沒有登入：測試設定沒開 auth）
    let mut s = std::net::TcpStream::connect(("127.0.0.1", admin)).unwrap();
    write!(
        s,
        "POST /api/memory/restart HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut resp = String::new();
    let _ = s.read_to_string(&mut resp);
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    let t0 = Instant::now();
    while !has_env(&environ()) {
        assert!(t0.elapsed() < Duration::from_secs(30), "等不到重新執行：\n{}", log.lock().unwrap());
        assert!(child.try_wait().unwrap().is_none(), "不能結束：\n{}", log.lock().unwrap());
        std::thread::sleep(Duration::from_millis(100));
    }
    healthy();
    assert!(child.try_wait().unwrap().is_none(), "同一個 PID 繼續跑");
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap();
    assert_eq!(comm.trim(), "kuroshio", "行程名稱照舊（pidof 找得到）");
    let l = log.lock().unwrap().clone();
    assert!(l.contains("原地重新啟動"), "{l}");
    assert!(l.contains("正常停止"), "照正常停止寫完快照：{l}");
    assert_eq!(unsafe { libc::kill(pid as i32, libc::SIGTERM) }, 0);
    let t0 = Instant::now();
    let st = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break st;
        }
        assert!(t0.elapsed() < Duration::from_secs(30), "SIGTERM 後要結束");
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(st.success(), "{st:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// UCI 模式（第三方韌體）：SIGHUP 時新設定讀不進來 → 照舊用上一份設定跑，`/api/status` 看得到原因；
/// 設定目錄在快照目錄以外（Padavan 的 KUROSHIO_ETC）時，恢復預設自訂規則照樣觸發 KUROSHIO_ON_CONFIG_WRITE
#[cfg(unix)]
#[test]
fn uci_reload_failure_keeps_running_and_config_hook_fires() {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    let dir = tmp("uci-reload");
    let etc = dir.join("etc");
    std::fs::create_dir_all(&etc).unwrap();
    let (dns, admin) = (free_port(), free_port());
    let uci = dir.join("tmp/kuroshio.uci");
    std::fs::create_dir_all(uci.parent().unwrap()).unwrap();
    let text = format!(
        "config kuroshio 'main'\n\toption enabled '1'\n\toption dns_port '{dns}'\n\toption admin_port '{admin}'\n\toption data_dir '{}'\n\toption listen_ipv6 '0'\n\nconfig filter 'filter'\n\toption enabled '1'\n\nconfig job 'dns_benchmark'\n\toption enabled '0'\n",
        dir.join("media/kuroshio/state").display()
    );
    std::fs::write(&uci, &text).unwrap();
    let marker = dir.join("hook.log");
    let cmd = |args: &[&str]| {
        let o = Command::new(env!("CARGO_BIN_EXE_kuroshio"))
            .args(args)
            .env("KUROSHIO_UCI_FILE", &uci)
            .env("KUROSHIO_ETC", &etc)
            .env("KUROSHIO_SHARE", root().join("data"))
            .env("NO_COLOR", "1")
            .output()
            .unwrap();
        (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).to_string())
    };
    let mut child = Command::new(env!("CARGO_BIN_EXE_kuroshio"))
        .args(["run", "--uci"])
        .env("KUROSHIO_UCI_FILE", &uci)
        .env("KUROSHIO_ETC", &etc)
        .env("KUROSHIO_SHARE", root().join("data"))
        .env(
            "KUROSHIO_ON_CONFIG_WRITE",
            format!("echo \"$KUROSHIO_CONFIG_FILES\" >> '{}'", marker.display()),
        )
        .env("NO_COLOR", "1")
        .env("KUROSHIO_LOG", "info")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .stdin(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let log = Arc::new(Mutex::new(String::new()));
    for pipe in [
        Box::new(child.stdout.take().unwrap()) as Box<dyn std::io::Read + Send>,
        Box::new(child.stderr.take().unwrap()),
    ] {
        let log = log.clone();
        std::thread::spawn(move || {
            for l in BufReader::new(pipe).lines().map_while(Result::ok) {
                let mut g = log.lock().unwrap();
                g.push_str(&l);
                g.push('\n');
            }
        });
    }
    let until = |what: &str, f: &dyn Fn() -> bool| {
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(30) {
            if f() {
                return;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        panic!("等不到 {what}：\n{}", log.lock().unwrap());
    };
    until("服務回答", &|| cmd(&["health", "--uci", "--timeout", "500"]).0 == 0);
    let status = || one_line_json(&cmd(&["status", "--json", "--uci"]).1);
    until("管理 API", &|| status()["running"] == true);
    let st0 = status();
    assert_eq!(st0["warnings"], json!([]), "{st0}\n{}", log.lock().unwrap());
    // 沒帶 --uci、預設的 config.json 不存在、環境變數指了 UCI：照 UCI 讀，不提示「設定檔不存在」（3.5.0 D3：padavan 的 notify）
    if !Path::new("/etc/kuroshio/config.json").exists() {
        let o = Command::new(env!("CARGO_BIN_EXE_kuroshio"))
            .args(["status", "--json"])
            .env("KUROSHIO_UCI_FILE", &uci)
            .env("KUROSHIO_ETC", &etc)
            .env("KUROSHIO_SHARE", root().join("data"))
            .env("NO_COLOR", "1")
            .output()
            .unwrap();
        let (out, err) = (String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
        assert_eq!(o.status.code(), Some(0), "{out}\n{err}");
        assert_eq!(one_line_json(&out)["running"], true, "{out}");
        assert!(!err.contains("不存在"), "{err}");
    }

    // 恢復預設自訂規則：custom-rules.txt 在 KUROSHIO_ETC（不在快照目錄的上一層）
    std::fs::write(etc.join("custom-rules.txt"), "||mine.example^\n").unwrap();
    let mut s = std::net::TcpStream::connect(("127.0.0.1", admin)).unwrap();
    write!(
        s,
        "POST /api/filter/reset-rules HTTP/1.1\r\nHost: 127.0.0.1:{admin}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
    )
    .unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    until("寫入設定後的外部指令", &|| {
        std::fs::read_to_string(&marker).is_ok_and(|t| t.contains("custom-rules.txt"))
    });
    let hook = std::fs::read_to_string(&marker).unwrap();
    assert!(hook.contains("custom-rules.txt.bak"), "合併成一次：{hook}");
    assert_eq!(hook.lines().filter(|l| !l.is_empty()).count(), 2, "一次執行，兩個檔案：{hook}");

    // 新設定讀不進來（檔案不見了）：不結束，繼續用上一份設定
    std::fs::rename(&uci, uci.with_extension("gone")).unwrap();
    let pid = child.id() as i32;
    assert_eq!(unsafe { libc::kill(pid, libc::SIGHUP) }, 0);
    until("重新載入失敗的紀錄", &|| log.lock().unwrap().contains("繼續用上一份設定"));
    assert!(child.try_wait().unwrap().is_none(), "不能結束：\n{}", log.lock().unwrap());
    std::fs::rename(uci.with_extension("gone"), &uci).unwrap();
    until("用上一份設定回答", &|| cmd(&["health", "--uci", "--timeout", "500"]).0 == 0);
    until("狀態裡的重新載入錯誤", &|| {
        status()["warnings"].to_string().contains("繼續用上一份設定")
    });

    // 設定恢復正常後再 SIGHUP：成功，警告清掉
    assert_eq!(unsafe { libc::kill(pid, libc::SIGHUP) }, 0);
    until("重新載入成功", &|| status()["warnings"] == json!([]));

    assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
    let t0 = Instant::now();
    let st = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break st;
        }
        assert!(t0.elapsed() < Duration::from_secs(30), "SIGTERM 後要結束");
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(st.success(), "{st:?}\n{}", log.lock().unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}

/// 假的上游黑潮 3.4.0（UDP 與 TCP）：`version.kuroshio`、auth 挑戰；`.invalid` 回不存在、其他回固定位址
async fn fake_upstream_kuroshio(allow: bool) -> (std::net::SocketAddr, String) {
    use kuroshio_community::chain as proto;
    use kuroshio_proto::message::{Message, RData, Record};
    use std::sync::Arc;
    let key = Arc::new(kuroshio_community::identity::KeyPair::generate());
    let fp = key.fingerprint();
    let answer = move |q: &[u8]| -> Option<Vec<u8>> {
        let m = Message::parse(q).ok()?;
        let qs = m.questions.first()?.clone();
        let mut r = Message::response_to(&m, 0);
        let txt = |payload: &[u8]| Record {
            name: qs.name.clone(),
            rtype: 16,
            class: 3,
            ttl: 0,
            data: RData::Raw(proto::txt_rdata(payload)),
        };
        match (qs.qclass, proto::parse_name(&qs.name)) {
            (3, Some(proto::Name::Auth(nonce))) => {
                let body = proto::AuthBody {
                    v: proto::PROTO,
                    t: "auth".into(),
                    nonce: nonce.to_vec(),
                    kid: key.kid.to_vec(),
                    public: key.public.to_vec(),
                    app: "3.4.0".into(),
                    allow,
                    caps: if allow { vec!["share".into()] } else { vec![] },
                    peer: "127.0.0.1".into(),
                    tok: vec![0; 16],
                    path: vec![key.kid.to_vec()],
                    ..Default::default()
                };
                r.answers
                    .push(txt(&proto::seal(&key, "auth", kuroshio_community::envelope::to_cbor(&body))));
            }
            (3, _) if qs.name == "version.kuroshio" => r.answers.push(txt(b"kuroshio/3.4.0")),
            (3, _) => r.rcode = 5,
            _ if qs.name.ends_with(".invalid") => r.rcode = 3,
            _ => r.answers.push(Record::a(&qs.name, 60, "198.51.100.10".parse().unwrap())),
        }
        Some(r.encode())
    };
    let answer = Arc::new(answer);
    // UDP 與 TCP 要同一個埠：TCP 那個埠剛好被占用就換一個
    let (u, l) = loop {
        let u = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        if let Ok(l) = tokio::net::TcpListener::bind(u.local_addr().unwrap()).await {
            break (u, l);
        }
    };
    let addr = u.local_addr().unwrap();
    {
        let answer = answer.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, from)) = u.recv_from(&mut buf).await else { break };
                if let Some(r) = answer(&buf[..n]) {
                    let _ = u.send_to(&r, from).await;
                }
            }
        });
    }
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let Ok((mut s, _)) = l.accept().await else { break };
            let answer = answer.clone();
            tokio::spawn(async move {
                let Ok(len) = s.read_u16().await else { return };
                let mut q = vec![0u8; len as usize];
                if s.read_exact(&mut q).await.is_err() {
                    return;
                }
                if let Some(r) = answer(&q) {
                    let mut out = (r.len() as u16).to_be_bytes().to_vec();
                    out.extend_from_slice(&r);
                    let _ = s.write_all(&out).await;
                }
            });
        }
    });
    (addr, fp)
}

/// 3.4.0：`kuroshio check-path` 在攔截者是黑潮 ≥ 3.4.0、而且自己的 chain 開著時多做一次探測
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn check_path_shows_chain_line() {
    let dir = tmp("check-path-chain");
    let (up, fp) = fake_upstream_kuroshio(true).await;
    let (closed_up, _) = fake_upstream_kuroshio(false).await;
    let targets = |a: std::net::SocketAddr| {
        json!({ "testnetV4": [a.to_string()], "testnetV6": [], "gateway": null, "encrypted": false, "plainTimeoutMs": 500 }).to_string()
    };
    let check = |cfg: PathBuf, target: String, json_out: bool| {
        tokio::task::spawn_blocking(move || {
            let mut c = Command::new(env!("CARGO_BIN_EXE_kuroshio"));
            c.args(["check-path", "-c"])
                .arg(&cfg)
                .env("KUROSHIO_PATH_TARGETS", target)
                .env("NO_COLOR", "1");
            if json_out {
                c.arg("--json");
            }
            let out = c.output().unwrap();
            (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).to_string())
        })
    };
    let on = dir.join("on.json");
    write_cfg(&on, &json!({ "upstream": { "pinned": [] } }));
    let (code, text) = check(on.clone(), targets(up), false).await.unwrap();
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("黑潮（3.4.0）"), "{text}");
    assert!(text.contains("串接：上游允許串接"), "{text}");
    assert!(text.contains(&fp), "{text}");

    let (_, out) = check(on.clone(), targets(up), true).await.unwrap();
    let j: Value = serde_json::from_str(&out).unwrap_or_else(|e| panic!("{e}：{out}"));
    assert_eq!(j["interceptor"]["kind"], "kuroshio");
    assert_eq!(j["interceptor"]["chain"]["allowDownstream"], true, "{j}");
    assert_eq!(j["interceptor"]["chain"]["fingerprint"], fp);
    assert!(j.get("hit").is_none(), "Report::to_json 的格式不變");

    // 上游的 allow_downstream 關閉
    let (_, text) = check(on.clone(), targets(closed_up), false).await.unwrap();
    assert!(text.contains("上游不提供資料"), "{text}");

    // 自己的 chain 關閉：不探測
    let off = dir.join("off.json");
    write_cfg(&off, &json!({ "upstream": { "pinned": [], "chain": false } }));
    let (_, text) = check(off.clone(), targets(up), false).await.unwrap();
    assert!(text.contains("這台的 chain 關閉：不辨識上游黑潮"), "{text}");
    let (_, out) = check(off, targets(up), true).await.unwrap();
    let j: Value = serde_json::from_str(&out).unwrap();
    assert!(j["interceptor"]["chain"].is_null());
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------- 3.4.0 WP10：重新載入不斷線（listenbank） ----------------
#[cfg(unix)]
mod reload {
    use super::*;

    /// UDP 與 TCP 都空著的埠
    fn free_dns_port() -> u16 {
        loop {
            let port = free_port();
            if std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() {
                return port;
            }
        }
    }

    /// 假的上游（UDP）：A 查詢一律回 198.51.100.10，其他類型回沒有答案
    fn fake_a_upstream() -> std::net::SocketAddr {
        use kuroshio_proto::message::{Message, Record};
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = u.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 4096];
            while let Ok((n, from)) = u.recv_from(&mut buf) {
                let Ok(m) = Message::parse(&buf[..n]) else { continue };
                let Some(q) = m.questions.first().cloned() else { continue };
                let mut r = Message::response_to(&m, 0);
                if q.qtype == 1 {
                    r.answers.push(Record::a(&q.name, 300, "198.51.100.10".parse().unwrap()));
                }
                let _ = u.send_to(&r.encode(), from);
            }
        });
        addr
    }

    /// 重新載入測試用的設定：上游只有假的上游（種子資料裡的自動上游不用、不做路徑檢查與串接，不連外）
    fn reload_cfg(dir: &Path, dns: u16, admin: u16, up: std::net::SocketAddr) -> Value {
        let mut v = user_cfg(dir, dns, admin, false);
        v["upstream"] = json!({
            "pinned": [format!("udp://{up}")], "fallback": [], "autoTypes": [], "pathCheck": false, "chain": false,
        });
        v
    }

    /// 查 example.com 的 A：回答案裡的位址（`None` = 等不到）；拒絕連線回 `Err(ConnectionRefused)`
    fn query_a(sock: &std::net::UdpSocket, id: u16, wait: std::time::Duration) -> std::io::Result<Option<Vec<std::net::IpAddr>>> {
        use kuroshio_proto::message::{Message, RData};
        let t0 = std::time::Instant::now();
        sock.send(&kuroshio_proto::build_query(id, "example.com", 1))?;
        let mut buf = vec![0u8; 4096];
        while let Some(left) = wait.checked_sub(t0.elapsed()).filter(|d| !d.is_zero()) {
            sock.set_read_timeout(Some(left))?;
            match sock.recv(&mut buf) {
                Ok(n) => {
                    let Ok(m) = Message::parse(&buf[..n]) else { continue };
                    if m.id != id {
                        continue; // 上一筆查詢遲到的回應
                    }
                    let ips = m
                        .answers
                        .iter()
                        .filter_map(|r| match r.data {
                            RData::A(a) => Some(std::net::IpAddr::V4(a)),
                            _ => None,
                        })
                        .collect();
                    return Ok(Some(ips));
                }
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(None)
    }

    /// 用戶端的來源位址：Linux 整段 127/8 都是本機，用 127.0.0.2 —— 連續開的大量用戶端埠
    /// 不會占到平行跑的其他測試剛挑好、還沒綁定的 127.0.0.1 埠
    fn client_ip() -> std::net::IpAddr {
        if cfg!(target_os = "linux") {
            [127, 0, 0, 2].into()
        } else {
            [127, 0, 0, 1].into()
        }
    }

    fn connected_udp(port: u16) -> std::net::UdpSocket {
        let s = std::net::UdpSocket::bind((client_ip(), 0)).unwrap();
        s.connect(("127.0.0.1", port)).unwrap();
        s
    }

    /// 新的 TCP 連線（來源位址同 `client_ip`）
    fn tcp_connect(port: u16) -> std::io::Result<std::net::TcpStream> {
        use socket2::{Domain, Socket, Type};
        let s = Socket::new(Domain::IPV4, Type::STREAM, None)?;
        s.bind(&std::net::SocketAddr::new(client_ip(), 0).into())?;
        let to: std::net::SocketAddr = ([127, 0, 0, 1], port).into();
        s.connect_timeout(&to.into(), std::time::Duration::from_secs(2))?;
        Ok(s.into())
    }

    fn answer_ip() -> std::net::IpAddr {
        "198.51.100.10".parse().unwrap()
    }

    /// 服務在跑的時候兩條執行緒連續發 UDP 查詢與新的 TCP 連線（每 5 ms 一次），記下拒絕連線與沒有回應
    struct Prober {
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        errors: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        threads: Vec<std::thread::JoinHandle<usize>>,
    }

    impl Prober {
        fn start(port: u16) -> Prober {
            use std::sync::atomic::{AtomicBool, Ordering};
            use std::sync::{Arc, Mutex};
            use std::time::Duration;
            let stop = Arc::new(AtomicBool::new(false));
            let errors: Arc<Mutex<Vec<String>>> = Default::default();
            let udp = {
                let (stop, errors) = (stop.clone(), errors.clone());
                std::thread::spawn(move || {
                    let sock = connected_udp(port);
                    let (mut id, mut ok) = (0u16, 0usize);
                    while !stop.load(Ordering::Relaxed) {
                        id = id.wrapping_add(1);
                        // 第一次等 2 秒，沒回應重送一次再等 2 秒
                        let mut got = None;
                        for _ in 0..2 {
                            match query_a(&sock, id, Duration::from_secs(2)) {
                                Ok(Some(ips)) => {
                                    got = Some(ips);
                                    break;
                                }
                                Ok(None) => {}
                                Err(e) => {
                                    errors.lock().unwrap().push(format!("UDP 查詢 #{id}：{e}（{:?}）", e.kind()));
                                    break;
                                }
                            }
                        }
                        match got {
                            Some(ips) if ips == [answer_ip()] => ok += 1,
                            Some(ips) => errors.lock().unwrap().push(format!("UDP 查詢 #{id}：答案不對 {ips:?}")),
                            None => errors.lock().unwrap().push(format!("UDP 查詢 #{id}：重送一次之後還是沒有回應")),
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    ok
                })
            };
            let tcp = {
                let (stop, errors) = (stop.clone(), errors.clone());
                std::thread::spawn(move || {
                    let mut ok = 0usize;
                    while !stop.load(Ordering::Relaxed) {
                        match tcp_connect(port) {
                            Ok(_) => ok += 1,
                            Err(e) => errors.lock().unwrap().push(format!("TCP 連線：{e}（{:?}）", e.kind())),
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    ok
                })
            };
            Prober {
                stop,
                errors,
                threads: vec![udp, tcp],
            }
        }

        /// 停下來：回（錯誤、UDP 成功次數、TCP 成功次數）
        fn finish(self) -> (Vec<String>, usize, usize) {
            self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
            let n: Vec<usize> = self.threads.into_iter().map(|t| t.join().unwrap()).collect();
            let errors = std::mem::take(&mut *self.errors.lock().unwrap());
            (errors, n[0], n[1])
        }
    }

    /// 子程序 `kuroshio run`，收集輸出
    struct Svc {
        child: std::process::Child,
        log: std::sync::Arc<std::sync::Mutex<String>>,
        conf: String,
    }

    impl Svc {
        fn start(conf: &Path) -> Svc {
            use std::io::{BufRead, BufReader};
            let mut child = Command::new(env!("CARGO_BIN_EXE_kuroshio"))
                .args(["run", "-c"])
                .arg(conf)
                .env("NO_COLOR", "1")
                .env("KUROSHIO_LOG", "info")
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .stdin(std::process::Stdio::null())
                .spawn()
                .unwrap();
            let log: std::sync::Arc<std::sync::Mutex<String>> = Default::default();
            for pipe in [
                Box::new(child.stdout.take().unwrap()) as Box<dyn std::io::Read + Send>,
                Box::new(child.stderr.take().unwrap()),
            ] {
                let log = log.clone();
                std::thread::spawn(move || {
                    for l in BufReader::new(pipe).lines().map_while(Result::ok) {
                        let mut g = log.lock().unwrap();
                        g.push_str(&l);
                        g.push('\n');
                    }
                });
            }
            let svc = Svc {
                child,
                log,
                conf: conf.to_string_lossy().to_string(),
            };
            svc.until("服務回答", &|| run(&["health", "-c", &svc.conf, "--timeout", "500"]).0 == 0);
            svc.until("啟動完成", &|| svc.rounds() >= 1);
            svc
        }

        fn log(&self) -> String {
            self.log.lock().unwrap().clone()
        }

        /// 啟動完成的輪數（每一輪啟動完成記一次快照目錄）
        fn rounds(&self) -> usize {
            self.log().matches("快照目錄 ").count()
        }

        fn until(&self, what: &str, f: &dyn Fn() -> bool) {
            let t0 = std::time::Instant::now();
            while t0.elapsed() < std::time::Duration::from_secs(30) {
                if f() {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            panic!("等不到 {what}：\n{}", self.log());
        }

        fn hup(&self) {
            assert_eq!(unsafe { libc::kill(self.child.id() as i32, libc::SIGHUP) }, 0);
        }

        /// 送 SIGHUP，等新的一輪啟動完成
        fn reload(&self) {
            let n = self.rounds();
            self.hup();
            self.until("重新載入完成", &|| self.rounds() > n);
        }

        fn stop(mut self) {
            assert_eq!(unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM) }, 0);
            let t0 = std::time::Instant::now();
            let st = loop {
                if let Some(st) = self.child.try_wait().unwrap() {
                    break st;
                }
                assert!(t0.elapsed() < std::time::Duration::from_secs(30), "SIGTERM 後要結束");
                std::thread::sleep(std::time::Duration::from_millis(100));
            };
            assert!(st.success(), "{st:?}\n{}", self.log());
        }
    }

    /// 重新載入期間連續查詢：沒有任何一次 Connection refused；UDP 在一次重送內都有回應；答案正確
    #[test]
    fn reload_never_refuses() {
        let dir = tmp("reload-refuse");
        let (dns, admin, up) = (free_dns_port(), free_port(), fake_a_upstream());
        let conf = dir.join("config.json");
        write_cfg(&conf, &reload_cfg(&dir, dns, admin, up));
        let svc = Svc::start(&conf);
        let probe = Prober::start(dns);
        std::thread::sleep(std::time::Duration::from_millis(300));
        for _ in 0..3 {
            svc.reload();
            std::thread::sleep(std::time::Duration::from_millis(300));
        }
        let (errors, udp_ok, tcp_ok) = probe.finish();
        assert!(errors.is_empty(), "重新載入期間不能拒絕連線：{errors:#?}\n{}", svc.log());
        assert!(udp_ok > 10 && tcp_ok > 10, "UDP {udp_ok} 次、TCP {tcp_ok} 次");
        // 重新載入之後答案正確
        let ips = query_a(&connected_udp(dns), 7, std::time::Duration::from_secs(2)).unwrap();
        assert_eq!(ips, Some(vec![answer_ip()]));
        assert_eq!(svc.log().matches("收到 SIGHUP").count(), 3);
        svc.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 改了監聽埠重新載入：舊的埠在啟動完成後連不上（UDP、TCP 都拒絕），新的埠可以
    #[test]
    fn reload_with_changed_port_closes_old() {
        let dir = tmp("reload-port");
        let (old, admin, up) = (free_dns_port(), free_port(), fake_a_upstream());
        let conf = dir.join("config.json");
        write_cfg(&conf, &reload_cfg(&dir, old, admin, up));
        let svc = Svc::start(&conf);
        let new = loop {
            let p = free_dns_port();
            if p != old {
                break p;
            }
        };
        write_cfg(&conf, &reload_cfg(&dir, new, admin, up));
        svc.reload();
        // 新的埠可以
        let ips = query_a(&connected_udp(new), 1, std::time::Duration::from_secs(2)).unwrap();
        assert_eq!(ips, Some(vec![answer_ip()]), "{}", svc.log());
        tcp_connect(new).expect("新的 TCP 埠可以連");
        // 舊的埠：啟動完成（sweep）之後就關掉了
        let e = tcp_connect(old).expect_err("舊的 TCP 埠要關掉");
        assert_eq!(e.kind(), std::io::ErrorKind::ConnectionRefused, "{e}");
        let sock = connected_udp(old);
        let mut refused = false;
        for id in 0..3 {
            match query_a(&sock, id, std::time::Duration::from_millis(500)) {
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                    refused = true;
                    break;
                }
                Ok(Some(ips)) => panic!("舊的 UDP 埠還在回答：{ips:?}"),
                _ => {}
            }
        }
        assert!(refused, "舊的 UDP 埠要關掉");
        assert!(svc.log().contains("關掉上一輪的監聽 plain"), "{}", svc.log());
        svc.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 給一份啟動不了的設定：服務用上一份設定繼續跑，期間同樣沒有拒絕連線
    #[test]
    fn failed_reload_keeps_sockets() {
        let dir = tmp("reload-failed");
        let (dns, admin, up) = (free_dns_port(), free_port(), fake_a_upstream());
        let conf = dir.join("config.json");
        let good = reload_cfg(&dir, dns, admin, up);
        write_cfg(&conf, &good);
        let svc = Svc::start(&conf);
        let probe = Prober::start(dns);
        std::thread::sleep(std::time::Duration::from_millis(300));
        // 只監聽一個這台沒有的位址（文件用位址）：沒有任何監聽位址，啟動失敗
        let mut bad = good.clone();
        bad["listen"]["plain"]["binds"] = json!(["192.0.2.1"]);
        write_cfg(&conf, &bad);
        let n = svc.rounds();
        svc.hup();
        svc.until("改回上一份設定", &|| svc.log().contains("改回上一份可以用的設定"));
        svc.until("用上一份設定重新啟動", &|| svc.rounds() > n);
        std::thread::sleep(std::time::Duration::from_millis(300));
        let (errors, udp_ok, tcp_ok) = probe.finish();
        assert!(errors.is_empty(), "啟動失敗期間不能拒絕連線：{errors:#?}\n{}", svc.log());
        assert!(udp_ok > 10 && tcp_ok > 10, "UDP {udp_ok} 次、TCP {tcp_ok} 次");
        let now: Value = serde_json::from_slice(&std::fs::read(&conf).unwrap()).unwrap();
        assert_eq!(now, good, "設定檔改回上一份");
        let ips = query_a(&connected_udp(dns), 1, std::time::Duration::from_secs(2)).unwrap();
        assert_eq!(ips, Some(vec![answer_ip()]));
        svc.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
