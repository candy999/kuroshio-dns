//! 黑潮 DNS（Kuroshio DNS）指令列，見規格 02 第 3 節

mod winsvc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use kuroshio::sysinfo::SysInfo;
use kuroshio_config::Tier;
use std::path::PathBuf;
use tracing::info;

#[derive(Parser)]
#[command(name = "kuroshio", version, about = "黑潮 DNS（Kuroshio DNS）：把連線帶回台灣節點的 DNS 伺服器")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// 前景執行
    Run {
        /// 設定檔（JSON，只寫跟預設值不同的欄位）
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
        /// 從 OpenWrt 的 /etc/config/kuroshio（UCI）讀設定，不讀 JSON
        #[arg(long)]
        uci: bool,
    },
    /// Windows 服務：install / uninstall / start / stop / status（需要系統管理員）
    Service {
        action: String,
        /// 服務使用的設定檔（安裝時記下來）
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// Windows 服務管理員呼叫的進入點（不要直接執行）
    #[command(hide = true)]
    ServiceRun {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// Windows：系統管理員執行一次，加防火牆規則（規格 07 第 1.1 節）
    Setup {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// Windows：IIS 反向代理模式，`kuroshio iis setup <站台名稱>`（規格 07 第 2 節模式 C）
    Iis {
        /// 目前只有 setup
        action: String,
        /// IIS 站台名稱（例如 "Default Web Site"）
        site: String,
        /// 站台已經有 web.config 時覆蓋（先備份成 web.config.bak）
        #[arg(long)]
        force: bool,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// 內建 ACME：`kuroshio acme issue [--force]` 立即申請 / 續期（Cloudflare DNS 驗證）
    Acme {
        /// issue（需要時申請）或 status
        action: String,
        /// 不管到期日都重新申請
        #[arg(long)]
        force: bool,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// 憑證資訊（JSON）：主體、簽發者、網域、到期日、剩幾天；OpenWrt 的 acme.sh status 用
    CertInfo {
        file: PathBuf,
        /// 一併附上 acme.sh 日誌的最後 60 行
        #[arg(long)]
        log: Option<PathBuf>,
        /// 申請程序是否執行中
        #[arg(long, default_value_t = false)]
        running: bool,
    },
    /// 2.x 與 3.0 並行比對：同一批查詢問兩邊，列出差異（規格 04 第 1.2 節）
    Compare {
        /// 查詢來源：dnsmasq 查詢紀錄、node 版 queryLog，或一行一個網域
        names: PathBuf,
        /// 第一邊（通常是 2.x）
        #[arg(long, default_value = "127.0.0.1:5335")]
        a: String,
        /// 第二邊（通常是 3.0）
        #[arg(long, default_value = "127.0.0.1:5336")]
        b: String,
        /// 最多比幾筆（重複的網域只比一次）
        #[arg(long, default_value_t = 20000)]
        limit: usize,
        /// 同時幾筆
        #[arg(long, default_value_t = 8)]
        concurrency: usize,
        /// 報表（JSON）寫到這個檔案
        #[arg(long)]
        out: Option<PathBuf>,
        /// 讀這份設定的 CDN 範圍與節點池，分辨「節點池內不同 IP」（允許的差異）
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(long)]
        uci: bool,
    },
    /// 版本、授權、原始碼網址（JSON）；--qr 附上原始碼網址的 QR 碼（SVG），LuCI 用
    About {
        #[arg(long)]
        qr: bool,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(long)]
        uci: bool,
    },
    /// 輸出完整預設設定
    Defaults {
        /// JSON 格式（目前只有這一種）
        #[arg(long, default_value_t = true)]
        json: bool,
    },
    /// 檢查設定檔並印出合併後的結果（含硬體等級調整）
    CheckConfig {
        /// JSON 設定檔（用 --uci 時可省略）
        file: Option<PathBuf>,
        /// 改讀 OpenWrt 的 UCI 設定
        #[arg(long)]
        uci: bool,
    },
    /// 顯示偵測到的硬體、等級，以及哪些預設值因為硬體被調低
    Sysinfo {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(long)]
        uci: bool,
    },
    /// 查詢一個網域（診斷用，類似 dig）
    Query {
        name: String,
        /// 記錄類型：A、AAAA、HTTPS…或數字
        #[arg(short = 't', long, default_value = "A")]
        qtype: String,
        /// 伺服器，寫法同上游：127.0.0.1:5336、udp://…、tcp://…
        #[arg(short, long, default_value = "127.0.0.1:53")]
        server: String,
        /// 逾時（毫秒）
        #[arg(long, default_value_t = 3000)]
        timeout: u64,
        /// 額外信任的憑證（PEM，例如自簽憑證）
        #[arg(long)]
        ca: Option<PathBuf>,
    },
}

fn default_config_path() -> PathBuf {
    // 攜帶版：執行檔旁邊有 config.json 就用它（規格 07 第 1 節）
    if let Some(d) = kuroshio::app::portable_dir() {
        return d.join("config.json");
    }
    if cfg!(windows) {
        let base = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        base.join("kuroshio").join("config.json")
    } else {
        PathBuf::from("/etc/kuroshio/config.json")
    }
}

/// 記錄到檔案（Windows 服務用）：超過 5 MB 時改名成 .old 再重新開始
fn init_log_to(cfg: Option<&serde_json::Value>, file: Option<&std::path::Path>) {
    use tracing_subscriber::fmt::writer::MakeWriterExt;
    use tracing_subscriber::prelude::*;
    let level = cfg
        .and_then(|c| kuroshio_config::get(c, "log.level"))
        .and_then(|v| v.as_str())
        .unwrap_or("info")
        .to_string();
    let filter = tracing_subscriber::EnvFilter::try_from_env("KUROSHIO_LOG").unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    if let Some(path) = file {
        if std::fs::metadata(path).map(|m| m.len() > 5 << 20).unwrap_or(false) {
            let _ = std::fs::rename(path, path.with_extension("log.old"));
        }
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_ansi(false)
                .with_target(false)
                .with_writer(std::sync::Mutex::new(f).and(kuroshio::logring::RingWriter))
                .init();
            return;
        }
    }
    let ansi = std::env::var_os("NO_COLOR").is_none();
    // 設定頁的「日誌」分頁另外存一份不含色碼的
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_ansi(ansi).with_target(false))
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_target(false)
                .with_writer(kuroshio::logring::RingWriter),
        )
        .init();
}

/// 工作執行緒數：單核心用單執行緒 runtime，tiny 最多 2 條（規格 05 第 3.2 節）
fn thread_count(config: &std::path::Path, uci: bool) -> usize {
    let user = user_config(config, uci).unwrap_or_default();
    let n = kuroshio_config::get(&user, "system.workerThreads")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let info = SysInfo::detect();
    let tier = kuroshio_config::requested_tier(&user).unwrap_or_else(|| info.tier());
    let t = info.worker_threads(n);
    if tier == Tier::Tiny && n == 0 {
        t.min(2)
    } else {
        t
    }
}

pub fn build_runtime(threads: usize) -> std::io::Result<tokio::runtime::Runtime> {
    if threads <= 1 {
        tokio::runtime::Builder::new_current_thread().enable_all().build()
    } else {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(threads)
            .max_blocking_threads(threads * 2)
            .enable_all()
            .build()
    }
}

/// 執行服務直到 `stop` 完成（cmd 的 Ctrl+C / SIGTERM，或 Windows 服務的「停止」）
pub async fn serve(
    config: PathBuf,
    uci: bool,
    threads: usize,
    log_file: Option<PathBuf>,
    stop: impl std::future::Future<Output = ()>,
) -> Result<()> {
    let (cfg, ..) = effective(&config, uci)?;
    init_log_to(Some(&cfg), log_file.as_deref());
    let src = if uci {
        "/etc/config/kuroshio（UCI）".to_string()
    } else {
        config.display().to_string()
    };
    let mode = if log_file.is_some() { "service" } else { "cmd" };
    info!(
        "黑潮 DNS {} 啟動（設定：{src}{}）",
        env!("CARGO_PKG_VERSION"),
        if mode == "service" { "，Windows 服務" } else { "" }
    );
    tokio::pin!(stop);
    let mut first = true;
    // 上一份成功啟動的設定檔內容：設定頁存了一份啟動不了的設定時改回來（不讓服務整個停掉）
    let mut last_good: Option<Vec<u8>> = None;
    loop {
        let current = if uci { None } else { std::fs::read(&config).ok() };
        // 每一輪（設定頁存檔後重新載入）都在自己的執行環境裡跑：結束時所有工作與監聽一起關掉
        let (cfg, tier, auto, info) = effective(&config, uci)?;
        if first {
            info!(
                "硬體等級 {}（{}）：{}，{} 條工作執行緒",
                tier.name(),
                if auto { "自動偵測" } else { "設定指定" },
                describe(&info),
                threads
            );
        }
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<Result<bool>>();
        let (config2, show_url) = (config.clone(), first && mode == "cmd");
        std::thread::Builder::new().name("kuroshio".into()).spawn(move || {
            let r = (|| -> Result<bool> {
                let rt = build_runtime(threads)?;
                let r = rt.block_on(generation(cfg, tier, config2, uci, mode, show_url, stop_rx));
                rt.shutdown_timeout(std::time::Duration::from_secs(3));
                r
            })();
            let _ = done_tx.send(r);
        })?;
        tokio::pin!(done_rx);
        let result = tokio::select! {
            _ = &mut stop => {
                let _ = stop_tx.send(());
                (&mut done_rx).await.unwrap_or(Ok(false)).map(|_| false)
            }
            r = &mut done_rx => r.unwrap_or(Ok(false)),
        };
        let reload = match result {
            Ok(r) => {
                last_good = current;
                r
            }
            Err(e) => match (&last_good, &current) {
                (Some(good), cur) if cur.as_ref() != Some(good) => {
                    tracing::error!("新設定無法啟動：{e:#}；改回上一份可以用的設定");
                    kuroshio::persist::write_atomic(&config, good)?;
                    true
                }
                _ => return Err(e),
            },
        };
        if !reload {
            break;
        }
        info!("設定已變更，重新載入");
        first = false;
    }
    info!("結束");
    Ok(())
}

/// 一輪執行：啟動、等到停止（回 false）或設定頁要求重新載入（回 true），收尾寫出快照
async fn generation(
    cfg: serde_json::Value,
    tier: Tier,
    config: PathBuf,
    uci: bool,
    mode: &'static str,
    show_url: bool,
    stop: tokio::sync::oneshot::Receiver<()>,
) -> Result<bool> {
    let started = kuroshio::app::start(&cfg, tier).await?;
    let ui = &started.state.webui;
    if !uci {
        let _ = ui.config_file.set(std::fs::canonicalize(&config).unwrap_or(config));
    }
    let _ = ui.run_mode.set(mode);
    if let (Some(a), true) = (started.admin, ui.auth_enabled() || cfg!(windows)) {
        if show_url {
            println!("設定頁：{}", ui.login_url(a.port()));
        } else if let Some(f) = &ui.token_file {
            info!("設定頁 http://127.0.0.1:{}/（登入 token：{}）", a.port(), f.display());
        }
    }
    let p = started.persister.lock().unwrap().policy().clone();
    info!(
        "快照目錄 {}（{}），最短間隔 {} 分鐘，每天寫入上限 {} KB",
        kuroshio::app::persist_dir(&cfg).display(),
        p.class.name(),
        p.min_interval / 60,
        p.daily_budget / 1024
    );
    let reload = started.state.reload.clone();
    let again = tokio::select! {
        _ = stop => false,
        _ = reload.notified() => true,
    };
    started.shutdown();
    Ok(again)
}

fn main() {
    let cli = Cli::parse();
    // 執行緒數依硬體決定：單核心用單執行緒 runtime（規格 05 第 3.2 節）
    let threads = match &cli.cmd {
        Cmd::Run { config, uci } => thread_count(config, *uci),
        // Windows 服務：服務管理員另外呼叫，執行環境在服務執行緒裡建立
        Cmd::ServiceRun { config } => {
            if let Err(e) = winsvc::dispatch(config.clone()) {
                eprintln!("錯誤：{e:#}");
                std::process::exit(2);
            }
            return;
        }
        _ => 1,
    };
    // 外層只負責指令列與等待停止訊號；服務本身在 serve() 另外建立的執行環境裡跑
    let rt = build_runtime(1);
    let rt = match rt {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("錯誤：無法建立執行環境：{e}");
            std::process::exit(2);
        }
    };
    if let Err(e) = rt.block_on(real_main(cli, threads)) {
        eprintln!("錯誤：{e:#}");
        std::process::exit(2);
    }
}

/// 使用者設定 → 等級（指定的或自動偵測的）→ 有效設定
/// 使用者設定：JSON 檔，或 OpenWrt 的 UCI
fn user_config(config: &std::path::Path, uci: bool) -> Result<serde_json::Value> {
    if uci {
        kuroshio_config::uci::load(&kuroshio_config::uci::Env::from_process()).with_context(|| "讀取 UCI 設定失敗")
    } else {
        kuroshio_config::read_user_file(config).with_context(|| "載入設定失敗")
    }
}

fn effective(config: &std::path::Path, uci: bool) -> Result<(serde_json::Value, Tier, bool, SysInfo)> {
    let user = user_config(config, uci)?;
    let info = SysInfo::detect();
    let requested = kuroshio_config::requested_tier(&user);
    let tier = requested.unwrap_or_else(|| info.tier());
    Ok((kuroshio_config::build(tier, &user), tier, requested.is_none(), info))
}

fn describe(info: &SysInfo) -> String {
    let mem = info
        .mem_total_mb
        .map(|m| format!("記憶體 {m} MB"))
        .unwrap_or_else(|| "記憶體未知".into());
    format!(
        "{mem}、{} 核 {}、{}",
        info.cores,
        info.arch,
        if info.aes {
            "有 AES 指令"
        } else {
            "沒有 AES 指令（TLS 優先用 ChaCha20）"
        }
    )
}

async fn real_main(cli: Cli, threads: usize) -> Result<()> {
    match cli.cmd {
        Cmd::CertInfo { file, log, running } => {
            let mut out = serde_json::json!({ "running": running, "cert": null, "log": "" });
            match kuroshio::certinfo::read(&file) {
                Ok(c) => out["cert"] = c,
                Err(e) => out["certError"] = serde_json::json!(e),
            }
            if let Some(l) = log {
                let t = std::fs::read_to_string(l).unwrap_or_default();
                let lines: Vec<&str> = t.lines().collect();
                out["log"] = serde_json::json!(lines[lines.len().saturating_sub(60)..].join("\n"));
            }
            println!("{out}");
        }
        Cmd::Defaults { .. } => {
            println!("{}", serde_json::to_string_pretty(&kuroshio_config::defaults())?);
        }
        Cmd::CheckConfig { file, uci } => {
            let (cfg, ..) = effective(&file.unwrap_or_else(default_config_path), uci)?;
            println!("{}", serde_json::to_string_pretty(&cfg)?);
        }
        Cmd::Sysinfo { config, uci } => sysinfo_report(&config, uci)?,
        Cmd::Query {
            name,
            qtype,
            server,
            timeout,
            ca,
        } => {
            if let Some(ca) = ca {
                let pem = std::fs::read(&ca).with_context(|| format!("讀不到 {}", ca.display()))?;
                use rustls::pki_types::pem::PemObject;
                for c in rustls::pki_types::CertificateDer::pem_slice_iter(&pem).flatten() {
                    kuroshio::tls::add_root(c);
                }
            }
            std::process::exit(query(&name, &qtype, &server, timeout).await?);
        }
        Cmd::Compare {
            names,
            a,
            b,
            limit,
            concurrency,
            out,
            config,
            uci,
        } => {
            std::process::exit(compare(names, a, b, limit, concurrency, out, config, uci).await?);
        }
        Cmd::About { qr, config, uci } => {
            let cfg = effective(&config, uci)
                .map(|e| e.0)
                .unwrap_or_else(|_| kuroshio_config::build(Tier::Standard, &serde_json::json!({})));
            let mut v = kuroshio::about::json(&cfg);
            if qr {
                v["qrSource"] = serde_json::json!(kuroshio::about::qr_svg(v["source"].as_str().unwrap_or("")));
            }
            println!("{}", serde_json::to_string(&v)?);
        }
        Cmd::Run { config, uci } => serve(config, uci, threads, None, shutdown_signal()).await?,
        Cmd::ServiceRun { .. } => unreachable!(),
        Cmd::Service { action, config } => winsvc::control(&action, &config)?,
        Cmd::Acme { action, force, config } => {
            let (cfg, ..) = effective(&config, false)?;
            let base = kuroshio::app::persist_dir(&cfg).parent().map(PathBuf::from).unwrap_or_default();
            let Some(ac) = kuroshio::acme::AcmeConfig::from_cfg(&cfg, &base, &kuroshio::app::persist_dir(&cfg)) else {
                anyhow::bail!("設定裡 acme.enabled 沒有開");
            };
            let a = kuroshio::acme::Acme::new(ac);
            match action.as_str() {
                "issue" => {
                    if a.ensure(force).await? {
                        println!("已更新：{}", a.cfg.cert.display());
                    } else {
                        println!("憑證還有效，不用續期（要強制請加 --force）");
                    }
                }
                "status" => println!("{}", serde_json::to_string_pretty(&a.status())?),
                other => anyhow::bail!("不認識的動作 {other}（issue / status）"),
            }
        }
        Cmd::Setup { config } => kuroshio::winsetup::setup(&effective(&config, false)?.0)?,
        Cmd::Iis {
            action,
            site,
            force,
            config,
        } => match action.as_str() {
            "setup" => kuroshio::winsetup::iis_setup(&effective(&config, false)?.0, &site, force)?,
            other => anyhow::bail!("不認識的動作 {other}（目前只有 setup）"),
        },
    }
    Ok(())
}

/// `kuroshio sysinfo`：偵測結果與等級調整
fn sysinfo_report(config: &std::path::Path, uci: bool) -> Result<()> {
    let (cfg, tier, auto, info) = effective(config, uci)?;
    println!("硬體：{}", describe(&info));
    if let Some(a) = info.mem_available_mb {
        println!("目前可用記憶體：{a} MB");
    }
    println!(
        "硬體等級：{}（{}）",
        tier.name(),
        if auto { "自動偵測" } else { "設定指定 system.profile" }
    );
    let p = kuroshio::app::persist_policy(&cfg, tier == Tier::Tiny);
    println!(
        "快照目錄：{}（{}），最短間隔 {} 分鐘，每天寫入上限 {} KB",
        kuroshio::app::persist_dir(&cfg).display(),
        p.class.name(),
        p.min_interval / 60,
        p.daily_budget / 1024
    );
    let user = user_config(config, uci)?;
    let mut changes = Vec::new();
    diff(
        "",
        &kuroshio_config::profile(tier),
        &kuroshio_config::defaults(),
        &user,
        &mut changes,
    );
    if changes.is_empty() {
        println!("預設值沒有因為硬體調整。");
    } else {
        println!("因為硬體等級調整的預設值（你在設定檔寫了的欄位以你的為準）：");
        for c in changes {
            println!("  {c}");
        }
    }
    Ok(())
}

fn diff(path: &str, prof: &serde_json::Value, def: &serde_json::Value, user: &serde_json::Value, out: &mut Vec<String>) {
    if let serde_json::Value::Object(m) = prof {
        for (k, v) in m {
            let p = if path.is_empty() { k.clone() } else { format!("{path}.{k}") };
            diff(
                &p,
                v,
                def.get(k).unwrap_or(&serde_json::Value::Null),
                user.get(k).unwrap_or(&serde_json::Value::Null),
                out,
            );
        }
    } else {
        let mark = if user.is_null() { "" } else { "（你的設定優先）" };
        out.push(format!("{path}: {def} → {prof}{mark}"));
    }
}

fn qtype_num(t: &str) -> Option<u16> {
    Some(match t.to_ascii_uppercase().as_str() {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "SVCB" => 64,
        "HTTPS" => 65,
        n => n.parse().ok()?,
    })
}

/// 回傳結束碼：0 = 有答案，1 = 沒有答案或錯誤
async fn query(name: &str, qtype: &str, server: &str, timeout_ms: u64) -> Result<i32> {
    let t = qtype_num(qtype).with_context(|| format!("不認識的記錄類型 {qtype}"))?;
    let up = kuroshio::upstream::Upstream::parse(server)?;
    let q = kuroshio_proto::build_query(0x5a5a, name, t);
    let started = std::time::Instant::now();
    let r = up.exchange(&q, std::time::Duration::from_millis(timeout_ms)).await?;
    let h = kuroshio_proto::header(&r)?;
    let ans = kuroshio_proto::answers(&r)?;
    println!(
        "{} {} @{}：rcode {}，{} 筆答案，{} ms",
        name,
        qtype.to_uppercase(),
        up.id,
        h.rcode,
        ans.len(),
        started.elapsed().as_millis()
    );
    for a in &ans {
        let text = match (a.rtype, a.data.len()) {
            (1, 4) => std::net::Ipv4Addr::new(a.data[0], a.data[1], a.data[2], a.data[3]).to_string(),
            (28, 16) => std::net::Ipv6Addr::from(<[u8; 16]>::try_from(a.data.as_slice()).unwrap()).to_string(),
            _ => format!("({} bytes)", a.data.len()),
        };
        println!("  type {:<5} ttl {:<6} {}", a.rtype, a.ttl, text);
    }
    Ok(if h.rcode == 0 && !ans.is_empty() { 0 } else { 1 })
}

#[allow(clippy::too_many_arguments)]
async fn compare(
    names: PathBuf,
    a: String,
    b: String,
    limit: usize,
    concurrency: usize,
    out: Option<PathBuf>,
    config: PathBuf,
    uci: bool,
) -> Result<i32> {
    use kuroshio::compare::{judge, parse_line, Report, Side};
    use std::sync::Arc;
    let text = std::fs::read_to_string(&names).with_context(|| format!("讀不到 {}", names.display()))?;
    let mut seen = std::collections::HashSet::new();
    let list: Vec<(u16, String)> = text
        .lines()
        .filter_map(parse_line)
        .filter(|x| seen.insert(x.clone()))
        .take(limit)
        .collect();
    if list.is_empty() {
        anyhow::bail!("{} 裡沒有可以比對的查詢", names.display());
    }
    let (ua, ub) = (kuroshio::upstream::Upstream::parse(&a)?, kuroshio::upstream::Upstream::parse(&b)?);
    // CDN 分類（唯讀）：判斷兩邊是不是都給了同一家 CDN 的台灣節點
    let cdn = effective(&config, uci).ok().and_then(|(cfg, ..)| {
        let rank = Arc::new(kuroshio::iprank::IpRank::new(&cfg, 1000));
        let paths = kuroshio_cdn::Paths::new(kuroshio::app::persist_dir(&cfg), kuroshio::app::share_dir(&cfg));
        let c = kuroshio_cdn::Cdn::load(&cfg, paths, Arc::new(kuroshio_cdn::RealNet::new(rank)));
        c.enabled().then_some(c)
    });
    eprintln!(
        "比對 {} 筆：A = {a}，B = {b}{}",
        list.len(),
        if cdn.is_some() { "（有 CDN 分類）" } else { "" }
    );
    let ask = |u: kuroshio::upstream::Upstream, t: u16, n: String| async move {
        let q = kuroshio_proto::build_query(0, &n, t);
        match u.exchange(&q, std::time::Duration::from_secs(5)).await {
            Ok(r) => match kuroshio_proto::Message::parse(&r) {
                Ok(m) => Side::from_msg(&m, t),
                Err(e) => Side::Error(format!("格式錯誤：{e}")),
            },
            Err(e) => Side::Error(format!("{e:#}")),
        }
    };
    let mut report = Report::default();
    let tw_of = |ip: std::net::IpAddr| -> Option<String> {
        let c = cdn.as_ref()?.classify(ip)?;
        (c.cls == kuroshio_cdn::Cls::Tw).then(|| c.provider.to_string())
    };
    for chunk in list.chunks(concurrency.max(1)) {
        let mut set = tokio::task::JoinSet::new();
        for (t, n) in chunk.iter().cloned() {
            let (ua, ub) = (ua.clone(), ub.clone());
            set.spawn(async move {
                let (x, y) = tokio::join!(ask(ua, t, n.clone()), ask(ub, t, n.clone()));
                (t, n, x, y)
            });
        }
        while let Some(Ok((t, n, x, y))) = set.join_next().await {
            let v = judge(&x, &y, &tw_of);
            report.add(t, &n, &x, &y, v);
        }
        if report.total % 1000 < concurrency as u64 {
            eprintln!("  {} / {}", report.total, list.len());
        }
    }
    let v = report.json();
    eprintln!(
        "完成：{} 筆，未解釋差異 {}（{}%）{}",
        v["total"],
        v["unexplained"],
        v["unexplainedPct"],
        if v["pass"] == true { "，達標" } else { "" }
    );
    eprintln!("{}", serde_json::to_string(&v["counts"])?);
    let text = serde_json::to_string_pretty(&v)?;
    match out {
        Some(p) => std::fs::write(&p, text)?,
        None => println!("{text}"),
    }
    Ok(if v["pass"] == true { 0 } else { 1 })
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("signal");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
