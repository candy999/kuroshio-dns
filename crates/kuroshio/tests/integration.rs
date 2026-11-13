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

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
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
