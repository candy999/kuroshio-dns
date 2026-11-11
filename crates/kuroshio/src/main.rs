//! 黑潮 DNS（Kuroshio DNS）指令列，見規格 02 第 3 節

mod winsvc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use kuroshio::sysinfo::SysInfo;
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
        /// setup：設定反向代理並綁定憑證；cert：只把憑證同步到 IIS
        action: String,
        /// IIS 站台名稱（例如 "Default Web Site"）
        site: String,
        /// 站台已經有 web.config 時覆蓋（先備份成 web.config.bak）
        #[arg(long)]
        force: bool,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// Windows：HTTP.sys 共用模式（規格 07 第 2 節模式 B）。cert：把憑證匯入並綁到 HTTP.sys；
    /// status：要登記的網址、HTTP.sys 的 HTTP/3 設定、目前的憑證綁定
    Httpsys {
        /// cert 或 status
        action: String,
        /// 憑證不涵蓋網域也照樣綁定
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
    /// 匯出學習資料（.kuroshio）：預設是完整備份（換路由器用，含社群身分，請自己保管）；--share 是給朋友的分享檔
    Export {
        /// 分享給朋友：只有 CDN 網域驗證紀錄（不含次數與時間）、節點池、評測結果、汙染黑名單
        #[arg(long)]
        share: bool,
        /// 輸出檔（預設 kuroshio-full-日期.kuroshio，放在目前的資料夾）
        #[arg(short, long)]
        out: Option<PathBuf>,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(long)]
        uci: bool,
    },
    /// 匯入 .kuroshio（合併，不會直接覆蓋本機比較新的資料）；服務執行中時交給服務，重新啟動後合併
    Import {
        file: PathBuf,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(long)]
        uci: bool,
        /// 只輸出一行 JSON 結果（LuCI 用）
        #[arg(long)]
        json: bool,
    },
    /// 設定頁、公開頁的網址與裝置要填的 DoH / DoT 位址（服務模式看不到視窗時用）
    Url {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(long)]
        uci: bool,
        /// 用瀏覽器打開設定頁
        #[arg(long)]
        open: bool,
    },
    /// DNR（RFC 9463）要發給區網裝置的內容（JSON）；OpenWrt 的接管腳本用它寫進 DHCP / RA 設定
    Dnr {
        /// 路由器的區網位址（逗號分隔，例如 192.168.1.1,fd00::1）
        #[arg(long, value_delimiter = ',')]
        lan: Vec<std::net::IpAddr>,
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
    /// 檢查設定檔並印出合併後的結果（含依 CPU 核心數換算的值）
    CheckConfig {
        /// JSON 設定檔（用 --uci 時可省略）
        file: Option<PathBuf>,
        /// 改讀 OpenWrt 的 UCI 設定
        #[arg(long)]
        uci: bool,
    },
    /// 顯示偵測到的硬體、記憶體 / 儲存保留量、依 CPU 核心數換算的值
    Sysinfo {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(long)]
        uci: bool,
    },
    /// 列出設定檔、狀態、憑證、token 等檔案的位置（JSON；不含密鑰內容）
    Paths {
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
    /// 來源 IP 存取控制（只開放台灣 / 自訂名單）
    Access {
        #[command(subcommand)]
        cmd: AccessCmd,
    },
}

#[derive(Subcommand)]
enum AccessCmd {
    /// 這個 IP 能不能連進來、符合哪一條規則（不含社群好友的 IP：那要服務執行中才知道）
    Check {
        ip: std::net::IpAddr,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(long)]
        uci: bool,
        /// JSON 格式
        #[arg(long)]
        json: bool,
    },
    /// 列出群組（ISP）、大小、是否生效
    Groups {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(long)]
        uci: bool,
    },
    /// OpenWrt：產生核心層丟棄用的 nftables 集合與規則（fw4 include；access.sh 呼叫）。
    /// 不需要過濾時兩個檔案都是空的
    Nft {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(long)]
        uci: bool,
        /// 集合（放 /usr/share/nftables.d/table-pre/）
        #[arg(long)]
        sets: PathBuf,
        /// 規則（放 /usr/share/nftables.d/chain-pre/input_wan/）
        #[arg(long)]
        rules: PathBuf,
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
        // 儲存空間不足時日誌最先刪（規格 05 第 5.6 節）
        kuroshio::space::register(path.with_extension("log.old"), kuroshio::space::Tier::Log);
        kuroshio::space::register(path.to_path_buf(), kuroshio::space::Tier::Log);
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

/// 工作執行緒數：單核心用單執行緒 runtime，多核心最多 4 條（規格 05 第 3.2 節）
fn thread_count(config: &std::path::Path, uci: bool) -> usize {
    let user = user_config(config, uci).unwrap_or_default();
    let n = kuroshio_config::get(&user, "system.workerThreads")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    SysInfo::detect().worker_threads(n)
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
    // cmd 執行：可以在視窗裡輸入 help、url、site…（標準輸入是終端機時才讀）
    let console: ConsoleSlot = Default::default();
    let mut console_rx = if mode == "cmd" { kuroshio::console::spawn_reader() } else { None };
    let mut first = true;
    // 上一份成功啟動的設定檔內容：設定頁存了一份啟動不了的設定時改回來（不讓服務整個停掉）
    let mut last_good: Option<Vec<u8>> = None;
    loop {
        let current = if uci { None } else { std::fs::read(&config).ok() };
        // 每一輪（設定頁存檔後重新載入）都在自己的執行環境裡跑：結束時所有工作與監聽一起關掉
        let (cfg, info, legacy) = effective(&config, uci)?;
        if first {
            info!("{}，{} 條工作執行緒", describe(&info), threads);
            if !legacy.is_empty() {
                info!(
                    "設定裡的 {} 已經不用了：沒有硬體等級，記憶體依系統保留量動態調整（system.memoryReserveMB / memoryReservePercent）",
                    legacy.join("、")
                );
            }
        }
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<Result<bool>>();
        let (config2, show_url) = (config.clone(), first && mode == "cmd");
        let (slot, interactive) = (console.clone(), console_rx.is_some());
        std::thread::Builder::new().name("kuroshio".into()).spawn(move || {
            let r = (|| -> Result<bool> {
                let rt = build_runtime(threads)?;
                let r = rt.block_on(generation(cfg, config2, uci, mode, show_url, interactive, slot.clone(), stop_rx));
                *slot.lock().unwrap() = None;
                rt.shutdown_timeout(std::time::Duration::from_secs(3));
                r
            })();
            let _ = done_tx.send(r);
        })?;
        tokio::pin!(done_rx);
        let mut stop_tx = Some(stop_tx);
        let result = loop {
            tokio::select! {
                _ = &mut stop => {
                    if let Some(t) = stop_tx.take() {
                        let _ = t.send(());
                    }
                    break (&mut done_rx).await.unwrap_or(Ok(false)).map(|_| false);
                }
                r = &mut done_rx => break r.unwrap_or(Ok(false)),
                Some(line) = console_line(&mut console_rx) => {
                    use kuroshio::console::Action;
                    let (out, act, url, reload) = {
                        let g = console.lock().unwrap();
                        let (out, act) = kuroshio::console::handle(&line, g.as_ref());
                        (
                            out,
                            act,
                            g.as_ref().and_then(|c| c.info.admin_url.clone()),
                            g.as_ref().and_then(|c| c.state.as_ref().map(|s| s.reload.clone())),
                        )
                    };
                    if !out.is_empty() {
                        println!("{out}");
                    }
                    match act {
                        Action::Quit => {
                            if let Some(t) = stop_tx.take() {
                                let _ = t.send(());
                            }
                            break (&mut done_rx).await.unwrap_or(Ok(false)).map(|_| false);
                        }
                        Action::Reload => {
                            if let Some(r) = reload {
                                r.notify_one();
                            }
                        }
                        Action::Open => {
                            if let Some(u) = url {
                                if !kuroshio::console::open_browser(&u) {
                                    println!("打不開瀏覽器，請自己複製網址：{u}");
                                }
                            }
                        }
                        Action::None => {}
                    }
                }
            }
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
        info!("重新載入（設定變更或匯入備份）");
        first = false;
    }
    info!("結束");
    Ok(())
}

/// 把黑潮 DNS 的憑證匯入 Windows 憑證存放區並綁到 IIS 站台。`soft`：憑證還沒準備好時只提示，不當成錯誤
fn iis_cert(config: &std::path::Path, site: &str, force: bool, soft: bool) -> Result<()> {
    let (cfg, ..) = effective(config, false)?;
    let state = kuroshio::app::persist_dir(&cfg);
    let base = state.parent().map(PathBuf::from).unwrap_or_default();
    match kuroshio::iiscert::sync(&cfg, site, &base, &state, force) {
        Ok(msg) => println!("{msg}"),
        Err(e) if soft => {
            println!("憑證還沒有綁到 IIS：{e:#}");
            println!("準備好網域與憑證後執行：kuroshio iis cert \"{site}\"（服務執行中也會每 10 分鐘自動同步）");
        }
        Err(e) => return Err(e),
    }
    Ok(())
}

type ConsoleSlot = std::sync::Arc<std::sync::Mutex<Option<kuroshio::console::Ctx>>>;

/// 互動指令的下一行；沒有終端機（或輸入已結束）時永遠不會回來
async fn console_line(rx: &mut Option<tokio::sync::mpsc::UnboundedReceiver<String>>) -> Option<String> {
    match rx {
        Some(r) => match r.recv().await {
            Some(l) => Some(l),
            None => {
                *rx = None;
                std::future::pending().await
            }
        },
        None => std::future::pending().await,
    }
}

/// 設定頁、公開頁的網址與位置（互動指令與 `kuroshio url` 共用）
fn console_info(
    cfg: &serde_json::Value,
    config: Option<&std::path::Path>,
    started: Option<&kuroshio::app::Started>,
) -> kuroshio::console::Info {
    use kuroshio_config::get;
    let n = |k: &str, d: u64| get(cfg, k).and_then(|v| v.as_u64()).unwrap_or(d) as u16;
    let on = |k: &str| get(cfg, k).and_then(|v| v.as_bool()).unwrap_or(false);
    let (admin_url, token_file, doh, dot, site_on, httpsys) = match started {
        Some(s) => {
            let ui = &s.state.webui;
            (
                s.admin.map(|a| ui.login_url(a.port())),
                ui.token_file.as_ref().map(|f| f.display().to_string()),
                s.state.encrypted.doh.map(|a| a.port()),
                s.state.encrypted.dot.map(|a| a.port()),
                s.state.resolver.site.get().is_some(),
                s.state.encrypted.doh_mode["mode"] == "httpsys",
            )
        }
        // 沒在這個行程裡跑（kuroshio url）：照設定推算，token 從檔案讀
        None => {
            let base = kuroshio::app::persist_dir(cfg).parent().map(PathBuf::from).unwrap_or_default();
            let ui = kuroshio::webui::WebUi::peek(cfg, &base);
            let admin = get(cfg, "admin.enabled").and_then(|v| v.as_bool()).unwrap_or(true);
            (
                admin.then(|| match (&ui.0, &ui.1) {
                    (Some(t), _) => format!("http://127.0.0.1:{}/login?token={t}", n("admin.port", 8054)),
                    // 要登入但 token 還沒產生：服務還沒啟動過
                    (None, Some(_)) => format!("http://127.0.0.1:{}/（登入 token 會在服務第一次啟動時產生）", n("admin.port", 8054)),
                    (None, None) => format!("http://127.0.0.1:{}/", n("admin.port", 8054)),
                }),
                ui.1.map(|f| f.display().to_string()),
                on("listen.doh.enabled").then(|| n("listen.doh.port", 8053)),
                on("listen.dot.enabled").then(|| n("listen.dot.port", 853)),
                on("site.enabled") && on("listen.doh.enabled"),
                cfg!(windows) && kuroshio::httpsys::configured(cfg) == "httpsys",
            )
        }
    };
    let mut info = kuroshio::console::Info::build_with(cfg, admin_url, token_file, doh, dot, site_on, httpsys);
    info.config_file = config.map(|c| std::fs::canonicalize(c).unwrap_or_else(|_| c.to_path_buf()).display().to_string());
    info
}

/// 一輪執行：啟動、等到停止（回 false）或設定頁要求重新載入（回 true），收尾寫出快照
#[allow(clippy::too_many_arguments)]
async fn generation(
    cfg: serde_json::Value,
    config: PathBuf,
    uci: bool,
    mode: &'static str,
    show_url: bool,
    interactive: bool,
    console: ConsoleSlot,
    stop: tokio::sync::oneshot::Receiver<()>,
) -> Result<bool> {
    let started = kuroshio::app::start(&cfg).await?;
    let ui = &started.state.webui;
    if !uci {
        let _ = ui
            .config_file
            .set(std::fs::canonicalize(&config).unwrap_or_else(|_| config.clone()));
    }
    let _ = ui.run_mode.set(mode);
    let cinfo = console_info(&cfg, (!uci).then_some(config.as_path()), Some(&started));
    if let (Some(a), true) = (started.admin, ui.auth_enabled() || cfg!(windows)) {
        if show_url {
            println!("設定頁：{}", ui.login_url(a.port()));
            if let Some(u) = cinfo.site_urls.first() {
                println!("公開頁：{u}");
            }
            if interactive {
                println!("輸入 help 可以看指令（url 設定頁網址、site 公開頁網址、status 狀態、quit 結束）");
            }
        } else if let Some(f) = &ui.token_file {
            info!("設定頁 http://127.0.0.1:{}/（登入 token：{}）", a.port(), f.display());
        }
    }
    *console.lock().unwrap() = Some(kuroshio::console::Ctx {
        info: cinfo,
        state: Some(started.state.clone()),
    });
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

/// `kuroshio access …`：照設定載入存取控制（台灣 IP 資料、本機網段），不啟動服務
fn access_cmd(cmd: AccessCmd) -> Result<()> {
    let (config, uci) = match &cmd {
        AccessCmd::Check { config, uci, .. } | AccessCmd::Groups { config, uci } | AccessCmd::Nft { config, uci, .. } => {
            (config.clone(), *uci)
        }
    };
    let (cfg, ..) = effective(&config, uci)?;
    // 自動更新下載的資料：快照目錄（Flash）與執行期目錄（記憶體）取比較新的
    let saved = [
        kuroshio::app::persist_dir(&cfg).join(kuroshio::ipfilter::STATE_FILE),
        kuroshio::app::runtime_dir(&cfg).join(kuroshio::ipfilter::STATE_FILE),
    ]
    .iter()
    .filter_map(|p| std::fs::read(p).ok())
    .filter_map(|b| kuroshio_jobs::geo::TwIp::parse(&b).ok().map(|t| (t.generated_at, b)))
    .max_by(|a, b| a.0.cmp(&b.0))
    .map(|(_, b)| b);
    let a = kuroshio::ipfilter::Access::from_cfg(&cfg, &kuroshio::app::share_dir(&cfg), saved);
    a.refresh_local();
    match cmd {
        AccessCmd::Check { ip, json, .. } => {
            let v = a.check_json(ip);
            if json {
                println!("{}", serde_json::to_string_pretty(&v)?);
            } else {
                println!(
                    "{ip}：{}（{}）\n模式 {}，套用在 {}",
                    if v["allowed"] == true { "允許" } else { "拒絕" },
                    v["reason"].as_str().unwrap_or(""),
                    v["mode"].as_str().unwrap_or(""),
                    v["applyTo"]
                        .as_array()
                        .map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join("、"))
                        .unwrap_or_default()
                );
            }
        }
        AccessCmd::Groups { .. } => println!("{}", serde_json::to_string_pretty(&a.api_json())?),
        AccessCmd::Nft { sets, rules, .. } => {
            let (s, r) = kuroshio::ipfilter::nft_render(&cfg, &a);
            std::fs::write(&sets, &s).with_context(|| format!("寫入 {}", sets.display()))?;
            std::fs::write(&rules, &r).with_context(|| format!("寫入 {}", rules.display()))?;
            if s.is_empty() {
                println!("不需要核心層過濾（全開放且沒有自訂封鎖，或沒有開啟的加密監聽）");
            } else {
                let st = a.status_json();
                println!(
                    "核心層過濾：{} 模式，資料 {}，規則 {} 行",
                    st["mode"].as_str().unwrap_or(""),
                    st["generatedAt"].as_str().unwrap_or("（讀不到，只套用自訂封鎖）"),
                    r.lines().filter(|l| !l.starts_with('#')).count()
                );
            }
        }
    }
    Ok(())
}

/// 合併後的設定、偵測到的硬體、設定裡已經不用的舊欄位（硬體等級、記憶體預算）
fn effective(config: &std::path::Path, uci: bool) -> Result<(serde_json::Value, SysInfo, Vec<String>)> {
    let user = user_config(config, uci)?;
    let info = SysInfo::detect();
    let legacy = kuroshio_config::legacy_keys(&user);
    Ok((kuroshio_config::build(&user), info, legacy))
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
        Cmd::Access { cmd } => access_cmd(cmd)?,
        Cmd::Paths { config, uci } => {
            let (cfg, ..) = effective(&config, uci)?;
            let file = (!uci).then(|| std::fs::canonicalize(&config).unwrap_or(config));
            println!(
                "{}",
                serde_json::to_string_pretty(&kuroshio::app::paths_json(&cfg, file.as_deref()))?
            );
        }
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
                .unwrap_or_else(|_| kuroshio_config::build(&serde_json::json!({})));
            let mut v = kuroshio::about::json(&cfg);
            if qr {
                v["qrSource"] = serde_json::json!(kuroshio::about::qr_svg(v["source"].as_str().unwrap_or("")));
            }
            println!("{}", serde_json::to_string(&v)?);
        }
        Cmd::Export { share, out, config, uci } => export_cmd(share, out, &config, uci).await?,
        Cmd::Import { file, config, uci, json } => {
            let r = import_cmd(&file, &config, uci, json).await;
            if json {
                let v = r.unwrap_or_else(|e| serde_json::json!({ "ok": false, "error": format!("{e:#}") }));
                println!("{}", serde_json::to_string(&v)?);
                if v["ok"] != true {
                    std::process::exit(1);
                }
            } else {
                r?;
            }
        }
        Cmd::Dnr { lan, config, uci } => {
            let (cfg, ..) = effective(&config, uci)?;
            let base = kuroshio::app::persist_dir(&cfg).parent().map(PathBuf::from).unwrap_or_default();
            println!("{}", kuroshio::dnr::plan(&cfg, &lan, &base).json());
        }
        Cmd::Url { config, uci, open } => {
            let (cfg, ..) = effective(&config, uci)?;
            let info = console_info(&cfg, (!uci).then_some(config.as_path()), None);
            let ctx = kuroshio::console::Ctx { info, state: None };
            println!("{}", kuroshio::console::handle("url", Some(&ctx)).0);
            println!("{}", kuroshio::console::handle("site", Some(&ctx)).0);
            if open {
                if let Some(u) = &ctx.info.admin_url {
                    kuroshio::console::open_browser(u);
                }
            }
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
        Cmd::Httpsys { action, force, config } => {
            let (cfg, ..) = effective(&config, false)?;
            let state = kuroshio::app::persist_dir(&cfg);
            let base = state.parent().map(PathBuf::from).unwrap_or_default();
            let (domain, port, prefixes) = kuroshio::httpsys::plan(&cfg).map_err(anyhow::Error::msg)?;
            match action.as_str() {
                "cert" => {
                    let kind = kuroshio::iiscert::Kind::HttpSys(port);
                    println!("{}", kuroshio::iiscert::sync_kind(&cfg, &kind, &base, &state, force)?);
                }
                "status" => {
                    let (h3, alt) = kuroshio::httpsys::registry_http3();
                    let bound: serde_json::Value = std::fs::read(state.join(kuroshio::iiscert::HTTPSYS_STATE_FILE))
                        .ok()
                        .and_then(|b| serde_json::from_slice(&b).ok())
                        .unwrap_or(serde_json::Value::Null);
                    let v = serde_json::json!({
                        "configured": kuroshio::httpsys::configured(&cfg), "domain": domain, "port": port,
                        "urls": prefixes.doh, "siteRoot": prefixes.site_root, "sitePaths": prefixes.site_paths,
                        "urlacl": prefixes.acl(), "enableHttp3": h3, "enableAltSvc": alt, "cert": bound,
                    });
                    println!("{}", serde_json::to_string_pretty(&v)?);
                }
                other => anyhow::bail!("不認識的動作 {other}（cert：憑證綁到 HTTP.sys；status：顯示設定）"),
            }
        }
        Cmd::Setup { config } => kuroshio::winsetup::setup(&effective(&config, false)?.0)?,
        Cmd::Iis {
            action,
            site,
            force,
            config,
        } => match action.as_str() {
            "setup" => {
                kuroshio::winsetup::iis_setup(&effective(&config, false)?.0, &site, force)?;
                // 把反向代理模式要的設定寫進設定檔（DoH 聽本機純 HTTP、記下站台名稱）
                let mut user: serde_json::Value = std::fs::read(&config)
                    .ok()
                    .and_then(|b| serde_json::from_slice(&b).ok())
                    .unwrap_or_else(|| serde_json::json!({}));
                let changed = kuroshio::iiscert::apply_iis_config(&mut user, &site);
                if !changed.is_empty() {
                    kuroshio::persist::write_atomic(&config, (serde_json::to_string_pretty(&user)? + "\n").as_bytes())?;
                    println!("已更新設定檔 {}：", config.display());
                    for c in &changed {
                        println!("  {c}");
                    }
                    println!("服務執行中的話，請重新啟動服務（或在設定頁按儲存）讓它生效");
                }
                iis_cert(&config, &site, force, true)?;
            }
            "cert" => iis_cert(&config, &site, force, false)?,
            other => anyhow::bail!("不認識的動作 {other}（setup：設定反向代理並綁定憑證；cert：只同步憑證）"),
        },
    }
    Ok(())
}

/// `kuroshio sysinfo`：偵測結果、記憶體 / 儲存保留量、依 CPU 核心數換算的設定
fn sysinfo_report(config: &std::path::Path, uci: bool) -> Result<()> {
    let (cfg, info, legacy) = effective(config, uci)?;
    println!("硬體：{}", describe(&info));
    if let Some(a) = info.mem_available_mb {
        println!("目前可用記憶體：{a} MB");
    }
    let res = kuroshio::memgov::reserve_from_cfg(&cfg);
    println!(
        "記憶體保留量：{} MB（{}）；可用記憶體低於它就讓出記憶體，高於它 + {} MB 才恢復、長大",
        res.bytes >> 20,
        res.how,
        res.margin() >> 20
    );
    let p = kuroshio::app::persist_policy(&cfg);
    let persister = kuroshio::persist::Persister::new(kuroshio::app::persist_dir(&cfg), p.clone());
    let sr = persister.reserve();
    println!(
        "快照目錄：{}（{}），最短間隔 {} 分鐘，每天寫入上限 {} KB；儲存保留 {} KB（{}）",
        kuroshio::app::persist_dir(&cfg).display(),
        p.class.name(),
        p.min_interval / 60,
        p.daily_budget / 1024,
        sr.bytes / 1024,
        sr.how
    );
    let user = user_config(config, uci)?;
    println!("依 CPU 核心數換算的設定（你在設定檔寫了的以你的為準）：");
    let keys = kuroshio_config::PER_CORE.iter().map(|x| x.0).chain(["resolver.parallel"]);
    for k in keys {
        let mine = kuroshio_config::num_or_auto(kuroshio_config::get(&user, k)).is_some();
        println!(
            "  {k}: {}{}",
            kuroshio_config::get(&cfg, k).cloned().unwrap_or_default(),
            if mine { "（你的設定）" } else { "" }
        );
    }
    if !legacy.is_empty() {
        println!("已經不用的舊欄位（不影響執行）：{}", legacy.join("、"));
    }
    Ok(())
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

/// 正在執行的服務的管理 API（網址、登入 token）；admin.enabled 關掉時沒有
fn admin_endpoint(cfg: &serde_json::Value) -> Option<(String, Option<String>)> {
    use kuroshio_config::get;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    if get(cfg, "admin.enabled").and_then(|v| v.as_bool()) == Some(false) {
        return None;
    }
    let host: IpAddr = get(cfg, "admin.host")
        .and_then(|v| v.as_str())
        .and_then(|h| h.parse().ok())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    // 聽在 0.0.0.0 / :: 時從本機連
    let host = match host {
        IpAddr::V4(a) if a.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(a) if a.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        h => h,
    };
    let port = get(cfg, "admin.port").and_then(|v| v.as_u64()).unwrap_or(8054) as u16;
    let base = kuroshio::app::persist_dir(cfg).parent().map(PathBuf::from).unwrap_or_default();
    let token = kuroshio::webui::token_file(cfg, &base)
        .and_then(|f| std::fs::read_to_string(f).ok())
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty());
    Some((format!("http://{}", std::net::SocketAddr::new(host, port)), token))
}

/// 呼叫管理 API（帶登入 token）
async fn admin_call(
    ep: &(String, Option<String>),
    method: &'static str,
    path: &str,
    body: Option<&[u8]>,
    timeout: std::time::Duration,
) -> Result<(u16, Vec<u8>)> {
    let mut headers = vec![];
    if let Some(t) = &ep.1 {
        headers.push(("Authorization".to_string(), format!("Bearer {t}")));
    }
    if body.is_some() {
        headers.push(("Content-Type".to_string(), "application/octet-stream".to_string()));
    }
    let req = kuroshio::fetch::Request { method, headers, body };
    kuroshio::fetch::request(&format!("{}{path}", ep.0), &req, kuroshio::backup::MAX_BYTES as u64, timeout).await
}

/// 服務有沒有在執行（管理 API 有回應）
async fn admin_up(ep: &(String, Option<String>)) -> bool {
    admin_call(ep, "GET", "/api/session", None, std::time::Duration::from_secs(3))
        .await
        .is_ok_and(|(c, _)| c == 200)
}

fn api_error(code: u16, body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v["error"].as_str().map(String::from))
        .unwrap_or_else(|| format!("HTTP {code}"))
}

/// `kuroshio export`：服務執行中跟服務拿（先寫出記憶體裡的最新狀態），沒有執行就從磁碟組
async fn export_cmd(share: bool, out: Option<PathBuf>, config: &std::path::Path, uci: bool) -> Result<()> {
    use kuroshio::backup::{self, Kind};
    let (cfg, ..) = effective(config, uci)?;
    let kind = if share { Kind::Share } else { Kind::Full };
    let mut data = None;
    if let Some(ep) = admin_endpoint(&cfg) {
        if admin_up(&ep).await {
            let path = format!("/api/backup/export?kind={}", kind.name());
            match admin_call(&ep, "GET", &path, None, std::time::Duration::from_secs(120)).await {
                Ok((200, b)) => data = Some(b),
                Ok((code, b)) => eprintln!("服務沒有給檔案（{}），改從磁碟上的資料匯出", api_error(code, &b)),
                Err(e) => eprintln!("服務沒有給檔案（{e:#}），改從磁碟上的資料匯出"),
            }
        }
    }
    let data = match data {
        Some(d) => d,
        None => backup::export(&backup::Locations::from_cfg(&cfg), kind).encode(),
    };
    let out = out.unwrap_or_else(|| PathBuf::from(backup::file_name(kind)));
    {
        use std::io::Write;
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        // 完整備份含社群私鑰：只有自己能讀
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        let mut f = o.open(&out).with_context(|| format!("無法寫入 {}", out.display()))?;
        f.write_all(&data)?;
    }
    let p = backup::Bundle::decode(&data)?.preview();
    println!("已匯出{}：{}（{} KB）", kind.label(), out.display(), data.len().div_ceil(1024));
    println!("{}", backup::preview_text(&p));
    if kind == Kind::Full {
        println!("完整備份含社群身分（私鑰），請自己保管，不要分享給別人；要給朋友請用 --share。");
    }
    Ok(())
}

/// `kuroshio import`：服務執行中交給服務（重新啟動後合併），沒有執行就直接合併到磁碟
async fn import_cmd(file: &std::path::Path, config: &std::path::Path, uci: bool, quiet: bool) -> Result<serde_json::Value> {
    use kuroshio::backup::{self, Bundle};
    let (cfg, ..) = effective(config, uci)?;
    let len = std::fs::metadata(file).with_context(|| format!("讀不到 {}", file.display()))?.len();
    if len > backup::MAX_BYTES as u64 {
        anyhow::bail!("檔案太大（超過 {} MB）", backup::MAX_BYTES >> 20);
    }
    let data = std::fs::read(file).with_context(|| format!("讀不到 {}", file.display()))?;
    let bundle = Bundle::decode(&data)?;
    let preview = bundle.preview();
    if !quiet {
        println!("{}", backup::preview_text(&preview));
    }
    let ep = admin_endpoint(&cfg);
    let running = match &ep {
        Some(ep) => admin_up(ep).await,
        None => false,
    };
    let mut report = match (&ep, running) {
        (Some(ep), true) => {
            // 上一次的匯入結果：等到出現新的一筆（時間不早於送出前）才算完成
            let last = |b: &[u8]| {
                serde_json::from_slice::<serde_json::Value>(b)
                    .ok()
                    .and_then(|v| v["importedAt"].as_u64())
            };
            let prev = match admin_call(ep, "GET", "/api/backup/last-import", None, std::time::Duration::from_secs(3)).await {
                Ok((200, b)) => last(&b),
                _ => None,
            };
            let t0 = backup::now_ms();
            let (code, b) = admin_call(ep, "POST", "/api/backup/import", Some(&data), std::time::Duration::from_secs(120)).await?;
            if code != 200 {
                anyhow::bail!("服務拒絕匯入：{}", api_error(code, &b));
            }
            if !quiet {
                println!("已交給執行中的服務，重新啟動後合併…");
            }
            // 等服務重新啟動、合併完成（最多 60 秒）
            let mut done = None;
            for _ in 0..120 {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                let r = admin_call(ep, "GET", "/api/backup/last-import", None, std::time::Duration::from_secs(3)).await;
                if let Ok((200, b)) = r {
                    let v: serde_json::Value = serde_json::from_slice(&b).unwrap_or_default();
                    if v["importedAt"].as_u64().is_some_and(|t| t >= t0 && Some(t) != prev) {
                        done = Some(v);
                        break;
                    }
                }
            }
            done.unwrap_or_else(|| {
                serde_json::json!({ "ok": true, "pending": true, "items": [],
                    "note": "服務還沒有重新啟動完成；合併結果之後會記在日誌裡" })
            })
        }
        _ => {
            if ep.is_none() && !quiet {
                eprintln!("管理 API 沒有開（admin.enabled）：如果服務正在執行，請先停止服務再匯入，否則關機時會蓋掉匯入的資料。");
            }
            let loc = backup::Locations::from_cfg(&cfg);
            let r = backup::merge(&loc, &bundle);
            let _ = kuroshio::persist::write_atomic(&loc.last_file(), &serde_json::to_vec(&r)?);
            r
        }
    };
    if !quiet {
        match report["note"].as_str() {
            Some(n) if report["pending"] == true => println!("{n}"),
            _ => println!("{}", backup::report_text(&report)),
        }
    }
    report["preview"] = preview;
    Ok(report)
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
