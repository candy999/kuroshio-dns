//! 黑潮 DNS（Kuroshio DNS）指令列，見規格 02 第 3 節

mod winsvc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use kuroshio::app::StopReason;
use kuroshio::sysinfo::SysInfo;
use std::path::PathBuf;
use tracing::{info, warn};

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
        /// 分享給朋友：只有 CDN 網域驗證紀錄（不含次數與時間）、台灣節點池、永久 IPv6 節點（上游評測與黑名單由每台機器自己判定，不放）
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
    /// 每日評測的子程序（服務自己呼叫；設定從標準輸入傳進來）
    #[command(name = "__job-dns-benchmark", hide = true)]
    JobBenchmark {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        base: PathBuf,
    },
    /// UCI 設定檔的升級遷移（不需要 uci 指令；規則同 OpenWrt 套件升級時做的）：
    /// 依 main.lists_version 更新沒動過的預設過濾清單、加上新的預設清單，使用者改過的不動
    UciMigrate {
        /// UCI 設定檔；沒寫就用 KUROSHIO_UCI_FILE，再沒有就是 /etc/config/kuroshio
        file: Option<PathBuf>,
        /// 寫到另一個檔案（沒寫就直接改原檔）
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// 只顯示會做什麼，不寫檔
        #[arg(long)]
        dry_run: bool,
    },
    /// 記憶體規劃：用跟執行時同一套規則，推算這台機器（與 64 / 128 / 256 / 512 MB 的機器）會怎樣運作
    MemoryPlan {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(long)]
        uci: bool,
        /// 要推算的實體記憶體大小（MB），可以給多個；沒給就是 64 128 256 512
        #[arg(long, num_args = 1..)]
        ram: Vec<u64>,
        /// 依 32 或 64 位元的程式推算（沒給 = 這個執行檔；在電腦上推算路由器用 32）
        #[arg(long)]
        bits: Option<u32>,
        /// 輸出 JSON
        #[arg(long)]
        json: bool,
    },
    /// 路徑檢查：立刻檢查這台機器到網際網路的路上有沒有人動手腳
    /// （IPv6、一般 DNS 被接走（被誰）、「不存在」被改寫、答案被竄改、加密協定被擋、TLS 中途攔截）
    CheckPath {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(long)]
        uci: bool,
        /// 輸出 JSON
        #[arg(long)]
        json: bool,
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
    /// 社群好友的邀請碼（要服務執行中）
    Community {
        #[command(subcommand)]
        cmd: CommunityCmd,
    },
    /// 健康檢查：對本機明文 DNS 問 _dns.resolver.arpa（不經上游）。
    /// 結束碼 0 = 有回答，1 = 沒有回答 / 沒在執行 / 明文 DNS 沒開，2 = 設定讀不到
    Health {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(long)]
        uci: bool,
        /// 逾時（毫秒）
        #[arg(long, default_value_t = 800)]
        timeout: u64,
        /// 輸出一行 JSON：{"ok","server","ms","rcode","error"}
        #[arg(long)]
        json: bool,
    },
    /// 執行中服務的狀態（經管理 API）。結束碼 0 = 執行中，1 = 沒有回應，2 = 設定讀不到。
    /// --json 的欄位見 docs/integration.md
    Status {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(long)]
        uci: bool,
        /// 輸出一行 JSON（給其他程式用；欄位固定）
        #[arg(long)]
        json: bool,
    },
    /// 通知執行中的服務發生了某件事（例如 WAN 變動）。結束碼 0 = 已送達，1 = 服務沒有回應，2 = 設定讀不到
    Notify {
        #[command(subcommand)]
        event: NotifyEvent,
    },
    /// 串接模式（3.4.0）：執行中服務的串接狀態、立刻重新偵測上游黑潮（經管理 API）。
    /// 結束碼 0 = 成功，1 = 服務沒有回應，2 = 設定讀不到
    Chain {
        #[command(subcommand)]
        action: ChainAction,
    },
}

#[derive(Subcommand)]
enum ChainAction {
    /// 串接狀態（同 /api/chain）
    Status {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(long)]
        uci: bool,
        /// 輸出 JSON
        #[arg(long)]
        json: bool,
    },
    /// 立刻做一次路徑檢查與串接探測（背景進行；用 `kuroshio chain status` 看結果）
    Recheck {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(long)]
        uci: bool,
    },
}

#[derive(Subcommand)]
enum NotifyEvent {
    /// WAN 變了（重新撥號、換 IP、換線路）：DDNS 立即檢查、重新偵測 ECS 用的對外 IP
    WanChanged {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(long)]
        uci: bool,
    },
    /// 立刻把學到的資料（快照）寫進儲存空間，不結束（同 SIGUSR1；Windows 沒有訊號，用這個）
    Save {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(long)]
        uci: bool,
    },
    /// 先讓出記憶體：韌體要做很佔記憶體的事（例如把韌體映像檔寫進 tmpfs）之前呼叫。
    /// 立刻縮小快取、把 CDN 冷資料移出記憶體（不停用過濾清單），並在 --hold 秒內不長大、不恢復
    Trim {
        /// 多久之內不長大、不恢復（秒，最多 3600）
        #[arg(long, default_value_t = 300)]
        hold: u64,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(long)]
        uci: bool,
    },
    /// 測試用（3.5.0）：模擬系統可用記憶體只剩 --avail-mb MB，觸發記憶體「吃緊／不足」的整套流程，--minutes 分鐘後自動恢復。
    /// 要在設定檔把 system.testHooks 設成 true 才會接受（正式使用不要開）；--off 立刻取消
    SimulateMemory {
        /// 模擬的系統可用記憶體（MB；只會比真實的少）
        #[arg(long, required_unless_present = "off")]
        avail_mb: Option<u64>,
        /// 幾分鐘後自動恢復（1～30）
        #[arg(long, default_value_t = 5)]
        minutes: u64,
        /// 立刻取消模擬
        #[arg(long)]
        off: bool,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(long)]
        uci: bool,
    },
}

#[derive(Subcommand)]
enum CommunityCmd {
    /// 顯示我的邀請碼（給好友貼上）；--refresh 重新產生，舊的立刻失效
    Invite {
        #[arg(long)]
        refresh: bool,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(long)]
        uci: bool,
    },
    /// 貼上好友的邀請碼：驗證對方身分指紋後送出好友請求
    Join {
        code: String,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(long)]
        uci: bool,
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

/// 預設的日誌過濾：設定的等級，加上 QUIC 函式庫只記錯誤。
/// `quinn_udp`（3.5.1 K3）：UDP 送不出去（例如 Windows 的 `sendmsg error: 10040` 封包太大）是 WARN、每分鐘最多一行，
/// QUIC 本來就會重送、逾時，上游失敗由黑潮自己的上游成敗紀錄處理；`KUROSHIO_LOG=quinn_udp=warn` 可以打開
fn default_log_directives(level: &str) -> String {
    format!("{level},quinn_proto=error,quinn=warn,quinn_udp=error")
}

/// 記錄到檔案（Windows 服務用）：超過 5 MB 時改名成 .old 再重新開始
/// 程式錯誤（panic）的原因也寫進日誌：Windows 的服務模式、被包裝器接走輸出時，標準錯誤看不到
/// （3.4.2 Windows 壓力測試：三次在啟動途中無聲結束，查不到原因）。原本的處理照舊
fn install_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let msg = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "（沒有訊息）".into());
        let at = info.location().map(|l| format!("{}:{}", l.file(), l.line())).unwrap_or_default();
        let th = std::thread::current().name().unwrap_or("?").to_string();
        tracing::error!("程式錯誤（panic，執行緒 {th}）：{msg}（{at}）");
        prev(info);
    }));
}

fn init_log_to(cfg: Option<&serde_json::Value>, file: Option<&std::path::Path>) {
    install_panic_hook();
    use tracing_subscriber::fmt::writer::MakeWriterExt;
    use tracing_subscriber::prelude::*;
    let level = cfg
        .and_then(|c| kuroshio_config::get(c, "log.level"))
        .and_then(|v| v.as_str())
        .unwrap_or("info")
        .to_string();
    // QUIC 函式庫（quinn-proto）的警告跟查詢結果無關，而且某些伺服器會讓它每十幾秒一行（例如 duplicate reset token），
    // 路由器的 syslog 很小，會把其他日誌洗掉：預設只記它的錯誤。KUROSHIO_LOG 可以整個覆寫
    let filter = tracing_subscriber::EnvFilter::try_from_env("KUROSHIO_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_log_directives(&level)));
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
    let ansi = std::env::var_os("NO_COLOR").is_none() && kuroshio::console::enable_ansi();
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

/// 收到系統只給幾秒的停止事件（Windows 主控台關閉／登出／關機）：每一輪的執行環境結束時不多等（3.5.0 C1）
static FAST_EXIT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// 執行服務直到 `stop` 完成（cmd 的 Ctrl+C / SIGTERM / 主控台關閉，或 Windows 服務的「停止」）；`stop` 的結果是停止的原因，
/// 決定日誌與關機寫快照的時間上限（3.5.0 C1）
pub async fn serve(
    config: PathBuf,
    uci: bool,
    threads: usize,
    log_file: Option<PathBuf>,
    stop: impl std::future::Future<Output = StopReason>,
) -> Result<()> {
    let (cfg, ..) = effective(&config, uci)?;
    init_log_to(Some(&cfg), log_file.as_deref());
    let src = if uci {
        format!("{}（UCI）", kuroshio_config::uci::file_path())
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
    // cmd 視窗的「快速編輯模式」：點一下視窗就會卡住畫面輸出（連帶卡住 DNS），啟動時先關掉
    if mode == "cmd" && kuroshio::console::disable_quick_edit() {
        info!("已關閉主控台的「快速編輯模式」（避免在視窗裡點一下就讓程式暫停）");
    }
    let mut first = true;
    // SIGHUP：重新載入設定；SIGUSR1：立刻寫出快照（只有 Unix）
    let mut signals = Signals::new();
    // 上一份成功啟動的設定檔內容：設定頁存了一份啟動不了的設定時改回來（不讓服務整個停掉）
    let mut last_good: Option<Vec<u8>> = None;
    // 上一份成功啟動的設定（合併後的內容）：重新載入時新設定讀不進來或啟動不了，就用它繼續跑
    // （UCI 沒有檔案可以改回去，JSON 設定檔改回去失敗時也靠這個；不讓服務整個停掉）
    let mut good_cfg: Option<serde_json::Value> = None;
    let mut use_good = false;
    // 剛把 JSON 設定檔改回上一份：下一輪讀到的是舊內容，失敗原因要留著
    let mut restored = false;
    // 收到停止（SIGTERM、Ctrl+C、quit）：這一輪結束後不再重新啟動。`stop` 只能等一次（完成後不能再 poll）
    let mut stopping = false;
    // 服務還在啟動時收到的 SIGHUP / reload：啟動完成後補做一次
    let mut pending_reload = false;
    let outcome: Result<()> = 'run: loop {
        let current = if uci { None } else { std::fs::read(&config).ok() };
        // 每一輪（設定頁存檔後重新載入）都在自己的執行環境裡跑：結束時所有工作與監聽一起關掉
        let loaded = if use_good {
            Err(anyhow::anyhow!("（用上一份設定）"))
        } else {
            effective(&config, uci)
        };
        let mut fallback = false;
        let (cfg, info, legacy) = match (loaded, &good_cfg) {
            (Ok(t), _) => t,
            (Err(e), Some(good)) => {
                if !use_good {
                    tracing::error!("新設定讀不進來：{e:#}；繼續用上一份設定");
                    kuroshio::integration::set_reload_error(Some(format!("{e:#}")));
                }
                use_good = false;
                fallback = true;
                (good.clone(), SysInfo::detect(), Vec::new())
            }
            (Err(e), None) => break 'run Err(e),
        };
        let this_cfg = cfg.clone();
        // 從設定檔正常讀進來：先清掉上一次的失敗紀錄（這一輪啟動失敗會再記上；用上一份設定頂著跑的那一輪不清）
        if !fallback && !restored {
            kuroshio::integration::set_reload_error(None);
        }
        restored = false;
        if first {
            info!("{}，{} 條工作執行緒", describe(&info), threads);
            if !legacy.is_empty() {
                info!(
                    "設定裡的 {} 已經不用了：沒有硬體等級，記憶體依系統保留量動態調整（system.memoryReserveMB / memoryReservePercent）",
                    legacy.join("、")
                );
            }
            // 設定檔裡的過濾清單是 3.1.x 的預設值原封不動：載入時已經換成新的預設清單（設定檔不改寫）
            if user_config(&config, uci).is_ok_and(|u| kuroshio_config::old_default_lists(&u)) {
                info!("過濾清單是舊版預設值，已更新成新的預設清單");
            }
        }
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<StopReason>();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<Result<bool>>();
        let (config2, show_url) = (config.clone(), first && mode == "cmd");
        let (slot, interactive) = (console.clone(), console_rx.is_some());
        std::thread::Builder::new().name("kuroshio".into()).spawn(move || {
            let r = (|| -> Result<bool> {
                let rt = build_runtime(threads)?;
                let r = rt.block_on(generation(cfg, config2, uci, mode, show_url, interactive, slot.clone(), stop_rx));
                *slot.lock().unwrap() = None;
                // 主控台關閉／登出／關機：快照已經寫了，剩下的工作不等（系統大約 5 秒就強制結束）
                let fast = FAST_EXIT.load(std::sync::atomic::Ordering::Relaxed);
                rt.shutdown_timeout(std::time::Duration::from_millis(if fast { 200 } else { 3000 }));
                r
            })();
            let _ = done_tx.send(r);
        })?;
        tokio::pin!(done_rx);
        let mut stop_tx = Some(stop_tx);
        let result = loop {
            tokio::select! {
                why = &mut stop, if !stopping => {
                    stopping = true;
                    if why.time_limited() {
                        FAST_EXIT.store(true, std::sync::atomic::Ordering::Relaxed);
                        warn!("{}", why.log_line());
                    } else {
                        info!("{}", why.log_line());
                    }
                    if let Some(t) = stop_tx.take() {
                        let _ = t.send(why);
                    }
                    break (&mut done_rx).await.unwrap_or(Ok(false)).map(|_| false);
                }
                r = &mut done_rx => break r.unwrap_or(Ok(false)),
                // 啟動中收到的重新載入：每半秒看一次啟動完成了沒
                _ = tokio::time::sleep(std::time::Duration::from_millis(500)), if pending_reload => {
                    let state = console.lock().unwrap().as_ref().and_then(|c| c.state.clone());
                    if let Some(st) = state {
                        info!("啟動完成：補做啟動期間收到的重新載入");
                        pending_reload = false;
                        st.reload.notify_one();
                    }
                }
                sig = signals.next() => {
                    let state = console.lock().unwrap().as_ref().and_then(|c| c.state.clone());
                    match (sig, state) {
                        (Sig::Reload, None) => {
                            info!("收到 SIGHUP：服務還在啟動，啟動完成後重新載入");
                            pending_reload = true;
                        }
                        (Sig::Flush, None) => info!("收到 SIGUSR1：服務還在啟動，還沒有快照可以寫"),
                        (Sig::Reload, Some(st)) => {
                            info!("收到 SIGHUP：重新載入設定");
                            st.reload.notify_one();
                        }
                        (Sig::Flush, Some(st)) => match st.flush_now() {
                            Ok(n) => info!("收到 SIGUSR1：立刻寫出快照，寫了 {n} 份"),
                            Err(e) => tracing::warn!("收到 SIGUSR1：寫出快照失敗：{e}"),
                        },
                    }
                }
                Some(line) = console_line(&mut console_rx) => {
                    use kuroshio::console::Action;
                    let (out, act, url, reload) = {
                        let g = console.lock().unwrap();
                        let (out, act) = kuroshio::console::handle(&line, g.as_ref());
                        (
                            out,
                            act,
                            g.as_ref().and_then(kuroshio::console::fresh_admin_url),
                            g.as_ref().and_then(|c| c.state.as_ref().map(|s| s.reload.clone())),
                        )
                    };
                    if !out.is_empty() {
                        println!("{out}");
                    }
                    match act {
                        Action::Quit => {
                            stopping = true;
                            if let Some(t) = stop_tx.take() {
                                let _ = t.send(StopReason::Quit);
                            }
                            break (&mut done_rx).await.unwrap_or(Ok(false)).map(|_| false);
                        }
                        Action::Reload => match reload {
                            Some(r) => r.notify_one(),
                            None => pending_reload = true,
                        },
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
                // 用上一份設定頂著跑的那一輪：設定檔還是讀不進來的那份，不能記成「可以用」
                if !fallback {
                    last_good = current;
                }
                good_cfg = Some(this_cfg);
                r
            }
            // 已經要停止：這一輪的錯誤記下來就結束，不再用舊設定重開
            Err(e) if stopping => {
                tracing::error!("停止時發生錯誤：{e:#}");
                false
            }
            Err(e) => match (&last_good, &current, &good_cfg) {
                // JSON 設定檔：改回上一份可以用的內容（設定頁看到的也是舊的）
                (Some(good), cur, _) if cur.as_ref() != Some(good) => {
                    tracing::error!("新設定無法啟動：{e:#}；改回上一份可以用的設定");
                    kuroshio::integration::set_reload_error(Some(format!("{e:#}")));
                    match kuroshio::persist::write_atomic(&config, good) {
                        Ok(()) => restored = true,
                        // 改不回去（例如 Flash 唯讀）：不結束，用記在記憶體裡的上一份設定繼續跑
                        Err(w) => {
                            tracing::error!("設定檔改不回上一份：{w:#}；用記在記憶體裡的上一份設定繼續跑");
                            match &good_cfg {
                                Some(_) => use_good = true,
                                None => break 'run Err(e),
                            }
                        }
                    }
                    true
                }
                // UCI（沒有檔案可以改回去）：用記在記憶體裡的上一份設定重新啟動
                (_, _, Some(good)) if *good != this_cfg => {
                    tracing::error!("新設定無法啟動：{e:#}；繼續用上一份設定");
                    kuroshio::integration::set_reload_error(Some(format!("{e:#}")));
                    use_good = true;
                    true
                }
                _ => break 'run Err(e),
            },
        };
        if !reload || stopping {
            break 'run Ok(());
        }
        info!("重新載入（設定變更或匯入備份）");
        first = false;
    };
    // 還在等待合併的「寫入設定後的外部指令」：結束前先跑完（例如 Padavan 存進 Flash）；啟動失敗也一樣
    kuroshio::confhook::flush();
    if outcome.is_ok() {
        info!("結束");
    }
    outcome
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
                // 要登入：網址不放長期的 token，`kuroshio url` 會再向執行中的服務換一次性登入碼
                admin.then(|| match (&ui.0, &ui.1) {
                    (Some(_), _) => format!("http://127.0.0.1:{}/", n("admin.port", 8054)),
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
    stop: tokio::sync::oneshot::Receiver<StopReason>,
) -> Result<bool> {
    // KUROSHIO_ON_CONFIG_WRITE：監看設定檔所在的資料夾與設定目錄（快照目錄的上一層），不含快照與執行期目錄
    {
        let state = kuroshio::app::persist_dir(&cfg);
        let base = state.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| state.clone());
        let conf_file = if uci {
            PathBuf::from(kuroshio_config::uci::file_path())
        } else {
            config.clone()
        };
        let conf_dir = conf_file
            .parent()
            .map(|p| if p.as_os_str().is_empty() { std::path::Path::new(".") } else { p });
        // 自訂規則、憑證、社群金鑰、token 可能放在別的地方（例如 Padavan 的 KUROSHIO_ETC = /etc/storage/kuroshio）
        let mut dirs = kuroshio::confhook::config_dirs(&cfg, &base);
        dirs.extend(conf_dir.map(std::path::Path::to_path_buf));
        if uci {
            dirs.push(PathBuf::from(kuroshio_config::uci::Env::from_process().etc));
        }
        let watch: Vec<&std::path::Path> = dirs.iter().map(PathBuf::as_path).collect();
        let runtime = kuroshio::app::runtime_dir(&cfg);
        kuroshio::confhook::configure(&watch, &[&state, &runtime]);
        // 社群模組自己寫金鑰、身分、邀請：寫完也要排一次外部指令
        kuroshio_community::set_on_write(kuroshio::confhook::touched);
    }
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
    let (again, why) = tokio::select! {
        r = stop => (false, r.ok()),
        _ = reload.notified() => (true, None),
    };
    // 停止：依原因決定寫快照的時間上限（主控台關閉／登出／關機只有大約 5 秒，3.5.0 C1）；重新載入照舊
    match why {
        Some(w) => started.shutdown_for(w),
        // 重新載入：交出快取之前先停止收查詢、等處理中的做完（3.5.1）
        None => started.shutdown_reload().await,
    }
    Ok(again)
}

/// 實驗（3.4.1，`--features mimalloc`）：改用 mimalloc。預設的建置不受影響
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    let cli = Cli::parse();
    // 容器：設定檔不存在時從 KUROSHIO_INIT_CONFIG 複製映像附的預設設定（之後使用者可以自己改）
    if let Cmd::Run { config, uci: false } = &cli.cmd {
        let init = std::env::var("KUROSHIO_INIT_CONFIG").ok();
        match kuroshio::integration::apply_init_config(config, init.as_deref()) {
            Ok(Some(src)) => eprintln!(
                "設定檔 {} 不存在，已從 KUROSHIO_INIT_CONFIG（{}）複製預設設定",
                config.display(),
                src.display()
            ),
            Ok(None) => {}
            Err(e) => eprintln!("無法把 KUROSHIO_INIT_CONFIG 複製到 {}：{e}", config.display()),
        }
    }
    // 每日評測的子程序：日誌寫到標準錯誤（不含時間，主程式逐行轉進自己的日誌）
    if let Cmd::JobBenchmark { state, base } = &cli.cmd {
        let filter = tracing_subscriber::EnvFilter::try_from_env("KUROSHIO_LOG")
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_log_directives("info")));
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .without_time()
            .with_target(false)
            .with_ansi(false)
            .with_writer(std::io::stderr)
            .init();
        let code = match build_runtime(2) {
            Ok(rt) => rt.block_on(kuroshio::benchjob::child_main(state.clone(), base.clone())),
            Err(e) => {
                eprintln!("ERROR 無法建立執行環境：{e}");
                2
            }
        };
        std::process::exit(code);
    }
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
        if !config.exists() {
            // 打錯路徑、記事本存成 config.json.txt 時，不提示的話只會看到「功能都沒開」
            static WARNED: std::sync::Once = std::sync::Once::new();
            WARNED.call_once(|| eprintln!("注意：設定檔 {} 不存在，全部使用預設值", config.display()));
        }
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
    // 本機產生的資料：快照目錄（Flash，壓縮的 .zst 或一般 JSON）與執行期目錄（記憶體）取比較新的
    let saved = [
        kuroshio::app::persist_dir(&cfg).join(kuroshio::ipfilter::STATE_FILE),
        kuroshio::app::runtime_dir(&cfg).join(kuroshio::ipfilter::STATE_FILE),
    ]
    .iter()
    .filter_map(|p| kuroshio_cdn::statefile::load(p).map(|l| l.data))
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
            // resolver.parallel 的 auto 在沒有 AES 時是 2（規格 10 第 5.1 節）
            "沒有 AES 指令（TLS 優先用 ChaCha20；先問最快的 2 個上游，其他在背景補問）"
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
        // main() 一開始就處理掉了
        Cmd::JobBenchmark { .. } => unreachable!(),
        Cmd::Defaults { .. } => {
            println!("{}", serde_json::to_string_pretty(&kuroshio_config::defaults())?);
        }
        Cmd::UciMigrate { file, output, dry_run } => {
            let file = file.unwrap_or_else(|| PathBuf::from(kuroshio_config::uci::file_path()));
            let text = std::fs::read_to_string(&file).with_context(|| format!("讀不到 {}", file.display()))?;
            let m = kuroshio_config::uci_migrate::migrate(&text)?;
            if m.log.is_empty() {
                println!("{}：已經是最新的，不需要遷移", file.display());
            } else {
                for l in &m.log {
                    println!("- {l}");
                }
                if dry_run {
                    println!("（--dry-run：沒有寫檔）");
                } else {
                    let out = output.unwrap_or(file);
                    kuroshio::persist::write_atomic(&out, m.text.as_bytes())?;
                    println!("已寫入 {}", out.display());
                }
            }
        }
        Cmd::CheckConfig { file, uci } => {
            let (cfg, ..) = effective(&file.unwrap_or_else(default_config_path), uci)?;
            if kuroshio::memgov::test_hooks(&cfg) {
                eprintln!("提醒：system.testHooks 開著（只給測試用：可以模擬記憶體不足）；正式使用請關掉");
            }
            println!("{}", serde_json::to_string_pretty(&cfg)?);
        }
        Cmd::Sysinfo { config, uci } => sysinfo_report(&config, uci)?,
        Cmd::CheckPath { config, uci, json } => check_path_cmd(&config, uci, json).await?,
        Cmd::MemoryPlan {
            config,
            uci,
            ram,
            bits,
            json,
        } => memory_plan_cmd(&config, uci, ram, bits, json).await?,
        Cmd::Access { cmd } => access_cmd(cmd)?,
        Cmd::Community { cmd } => community_cmd(cmd).await?,
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
            } else if r?["ok"] == false {
                // 部分項目寫入失敗：結束碼非 0（整合方的腳本才知道要重試）
                std::process::exit(1);
            }
        }
        Cmd::Dnr { lan, config, uci } => {
            let (cfg, ..) = effective(&config, uci)?;
            let base = kuroshio::app::persist_dir(&cfg).parent().map(PathBuf::from).unwrap_or_default();
            println!("{}", kuroshio::dnr::plan(&cfg, &lan, &base).json());
        }
        Cmd::Url { config, uci, open } => {
            let (cfg, ..) = effective(&config, uci)?;
            let mut info = console_info(&cfg, (!uci).then_some(config.as_path()), None);
            // 要登入：向執行中的服務換一次性登入碼（用 token 檔驗證），網址裡不放 token
            let base = kuroshio::app::persist_dir(&cfg).parent().map(PathBuf::from).unwrap_or_default();
            if kuroshio::webui::WebUi::peek(&cfg, &base).0.is_some() {
                if let (Some(ep), Some(u)) = (admin_endpoint(&cfg), info.admin_url.clone()) {
                    let r = admin_call(&ep, "POST", "/api/login-code", Some(b""), std::time::Duration::from_secs(3)).await;
                    match r {
                        Ok((200, b)) => {
                            let v: serde_json::Value = serde_json::from_slice(&b).unwrap_or_default();
                            if let Some(p) = v["path"].as_str() {
                                info.admin_url = Some(format!("{}{p}", u.trim_end_matches('/')));
                            }
                        }
                        _ => {
                            info.login_note =
                                Some("服務沒有在執行：啟動後再執行 kuroshio url 拿登入網址，或打開設定頁後貼上 token 檔裡的內容".into())
                        }
                    }
                }
            }
            let ctx = kuroshio::console::Ctx { info, state: None };
            println!("{}", kuroshio::console::handle("url", Some(&ctx)).0);
            println!("{}", kuroshio::console::handle("site", Some(&ctx)).0);
            if open {
                if let Some(u) = &ctx.info.admin_url {
                    kuroshio::console::open_browser(u);
                }
            }
        }
        Cmd::Run { config, uci } => {
            serve(config, uci, threads, None, shutdown_signal()).await?;
            // 3.5.1 N1：記憶體控制要求的原地重新啟動：快照已經照正常停止寫完，用同一個 PID 重新執行
            #[cfg(target_os = "linux")]
            if kuroshio::memgov::restart_pending() {
                let e = kuroshio::memgov::reexec_self();
                eprintln!("原地重新啟動失敗（{e}），照一般停止結束；看門狗或服務管理會重新啟動");
            }
        }
        Cmd::Health {
            config,
            uci,
            timeout,
            json,
        } => std::process::exit(health_cmd(&config, uci, timeout, json).await),
        Cmd::Status { config, uci, json } => std::process::exit(status_cmd(&config, uci, json).await),
        Cmd::Notify { event } => std::process::exit(notify_cmd(event).await),
        Cmd::Chain { action } => std::process::exit(chain_cmd(action).await),
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
    println!("依 CPU 核心數（resolver.parallel、cdn.verifyPerMin 另看 AES 指令）換算的設定（你在設定檔寫了的以你的為準）：");
    let keys = kuroshio_config::PER_CORE
        .iter()
        .map(|x| x.0)
        .chain(["resolver.parallel", "cdn.verifyPerMin"]);
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

/// `kuroshio community invite / join`：交給執行中的服務（邀請碼放在內容裡，不放網址）
async fn community_cmd(cmd: CommunityCmd) -> Result<()> {
    let (config, uci) = match &cmd {
        CommunityCmd::Invite { config, uci, .. } | CommunityCmd::Join { config, uci, .. } => (config.clone(), *uci),
    };
    let (cfg, ..) = effective(&config, uci)?;
    let ep = admin_endpoint(&cfg).ok_or_else(|| anyhow::anyhow!("管理 API 沒有開啟（admin.enabled = false），無法操作社群"))?;
    if !admin_up(&ep).await {
        anyhow::bail!("服務沒有在執行：邀請碼要服務執行中才能查看或使用");
    }
    let t = std::time::Duration::from_secs(120);
    let json = |code: u16, b: &[u8]| -> Result<serde_json::Value> {
        if code != 200 {
            anyhow::bail!("{}", api_error(code, b));
        }
        Ok(serde_json::from_slice(b)?)
    };
    match cmd {
        CommunityCmd::Invite { refresh, .. } => {
            let (code, b) = if refresh {
                admin_call(&ep, "POST", "/api/community/invite/refresh", Some(b"_"), t).await?
            } else {
                admin_call(&ep, "GET", "/api/community/invite", None, t).await?
            };
            let v = json(code, &b)?;
            if v["ok"] != true {
                anyhow::bail!("{}", v["reason"].as_str().unwrap_or("無法取得邀請碼"));
            }
            println!("{}", v["code"].as_str().unwrap_or(""));
            eprintln!(
                "網域 {}，身分指紋 {}{}",
                v["domain"].as_str().unwrap_or(""),
                v["fingerprint"].as_str().unwrap_or(""),
                if refresh {
                    "；已重新產生，舊的邀請碼已失效"
                } else {
                    ""
                }
            );
            eprintln!("邀請碼等同好友密碼：只給想加的好友，可以重複使用；外流了就用 --refresh 重新產生。");
            if v["ready"] != true {
                let p: Vec<&str> = v["problems"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
                    .unwrap_or_default();
                eprintln!("注意：社群模式還沒就緒（{}），好友暫時無法用這個邀請碼加你", p.join("；"));
            }
        }
        CommunityCmd::Join { code, .. } => {
            let body = serde_json::to_vec(&serde_json::json!({ "code": code }))?;
            let (status, b) = admin_call(&ep, "POST", "/api/community/invite/use", Some(&body), t).await?;
            let v = json(status, &b)?;
            for s in v["steps"].as_array().into_iter().flatten() {
                println!(
                    "{} {}",
                    if s["ok"] == true { "[完成]" } else { "[失敗]" },
                    s["text"].as_str().unwrap_or("")
                );
            }
            for p in v["problems"].as_array().into_iter().flatten() {
                println!("  - {}", p.as_str().unwrap_or(""));
            }
            if v["ok"] != true {
                anyhow::bail!("{}", v["reason"].as_str().unwrap_or("加好友失敗"));
            }
        }
    }
    Ok(())
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

/// `kuroshio memory-plan`
/// `kuroshio check-path`：在這個行程裡做一次完整的路徑檢查（不需要服務在跑）
async fn check_path_cmd(config: &std::path::Path, uci: bool, as_json: bool) -> Result<()> {
    use kuroshio_net::path;
    let cfg = config_for_cli(config, uci).unwrap_or_else(|_| kuroshio_config::build(&serde_json::json!({})));
    kuroshio::tls::set_bootstrap(
        &kuroshio_config::get(&cfg, "upstream.bootstrap")
            .and_then(serde_json::Value::as_array)
            .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect::<Vec<_>>())
            .unwrap_or_default(),
    );
    path::set_v6_mode(path::V6Mode::from_value(kuroshio_config::get(&cfg, "upstream.ipv6")));
    let policy = kuroshio::pathcheck::policy_of(&cfg);
    let r = path::check(&kuroshio::pathcheck::targets()).await;
    let chain = check_path_chain(&cfg, &r).await;
    if as_json {
        let mut j = r.to_json();
        j["policy"] = serde_json::json!(policy);
        j["summary"] = serde_json::json!(path::summary(&r));
        j["warnings"] = serde_json::json!(r.warnings(policy));
        if let Some(i) = j.get_mut("interceptor").filter(|i| i.is_object()) {
            i["chain"] = chain.as_ref().map(|c| c.1.clone()).unwrap_or(serde_json::Value::Null);
        }
        println!("{}", serde_json::to_string_pretty(&j)?);
        return Ok(());
    }
    let mut text = check_path_text(&r, policy);
    if let Some((line, _)) = chain {
        // 「攔截者」那一行之後
        let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
        let at = lines
            .iter()
            .position(|l| l.starts_with("  攔截者"))
            .map(|i| i + 1)
            .unwrap_or(lines.len());
        lines.insert(at, format!("  串接：{line}"));
        text = lines.join("\n");
    }
    println!("{text}");
    Ok(())
}

/// check-path 的串接那一行（規格 1.10）：攔截者是黑潮時才有；自己的 chain 關著不探測
async fn check_path_chain(cfg: &serde_json::Value, r: &kuroshio_net::path::Report) -> Option<(String, serde_json::Value)> {
    use kuroshio::chain::client;
    let kuroshio_net::path::Interceptor::Kuroshio(ver) = r.interceptor.as_ref()? else {
        return None;
    };
    if !r.plain_v4.intercepted() {
        return None;
    }
    let settings = kuroshio_config::chain::ChainSettings::from_cfg(cfg);
    if !settings.downstream_enabled() {
        return Some(("這台的 chain 關閉：不辨識上游黑潮".into(), serde_json::Value::Null));
    }
    if !kuroshio_community::chain::version_ok(ver) {
        return Some((format!("上游黑潮 {ver} 不支援串接（需要 3.4.0 以上）"), serde_json::Value::Null));
    }
    let hit = r.hit.filter(|a| a.is_ipv4())?;
    let p = client::probe(hit, r.hit_tcp, client::Timing::default().ask).await;
    let line = match (&p.error, p.allow) {
        (None, true) => format!("上游允許串接，提供資料給下游（節點指紋 {}）", p.fingerprint().unwrap_or_default()),
        (None, false) => "上游不提供資料（上游的 allow_downstream 關閉）：這台會自己做評測，重複使用網路".into(),
        (Some(e), _) if p.supported => format!("上游的身分驗證失敗：{e}"),
        (Some(_), _) => "上游沒有回應串接查詢".into(),
    };
    let j = serde_json::json!({
        "supported": p.supported,
        "allowDownstream": p.error.is_none() && p.allow,
        "nodeId": p.kid.map(|k| kuroshio_community::util::hex(&k)),
        "fingerprint": p.fingerprint(),
        "caps": p.caps,
        "error": p.error,
    });
    Some((line, j))
}

fn check_path_text(r: &kuroshio_net::path::Report, policy: &str) -> String {
    use kuroshio_net::path::{Proto, V6Route};
    let yes = |b: bool| if b { "是" } else { "否" };
    let mut out = Vec::new();
    out.push("路徑檢查".to_string());
    out.push(format!(
        "  IPv6：{}（設定 {}，路由 {}）",
        if r.v6_usable() { "可用" } else { "不可用" },
        r.v6_mode.as_str(),
        match &r.v6_route {
            V6Route::Global => "全域位址".to_string(),
            V6Route::Ula => "只有 ULA".to_string(),
            V6Route::None(why) => why.clone(),
        }
    ));
    out.push(format!(
        "  一般 DNS 被接走：IPv4 UDP {}、TCP {}{}",
        yes(r.plain_v4.udp),
        yes(r.plain_v4.tcp),
        match &r.plain_v6 {
            Some(p) => format!("；IPv6 UDP {}、TCP {}", yes(p.udp), yes(p.tcp)),
            None => String::new(),
        }
    ));
    if r.plain_intercepted() {
        out.push(format!("  攔截者：{}", r.interceptor_text()));
    }
    if let Some(g) = r.gateway {
        out.push(format!("  預設閘道：{g}"));
    }
    out.push(format!(
        "  「不存在」被改寫：{}",
        if r.nx_rewrite.is_empty() {
            "否".to_string()
        } else {
            r.nx_rewrite.iter().map(|i| i.to_string()).collect::<Vec<_>>().join("、")
        }
    ));
    out.push(format!(
        "  答案被竄改：{}",
        if r.tampered.is_empty() {
            "否".to_string()
        } else {
            r.tampered
                .iter()
                .map(|t| format!("{}（{}）", t.name, t.via))
                .collect::<Vec<_>>()
                .join("、")
        }
    ));
    for (p, x) in &r.protocols {
        let name = match p {
            Proto::Dot => "DoT 853",
            Proto::Doh => "DoH 443",
            Proto::Quic => "QUIC",
        };
        out.push(format!(
            "  {name}：成功 {} / 失敗 {}{}{}",
            x.ok,
            x.fail,
            if r.blocked.contains(p) { "（被擋）" } else { "" },
            match (&x.last_error, x.ok) {
                (Some(e), 0) => format!("：{e}"),
                _ => String::new(),
            }
        ));
    }
    if let Some(t) = &r.tls_intercept {
        out.push(format!("  TLS 中途攔截：{t}"));
    }
    if r.offline {
        out.push("  加密 DNS 全部連不上：網路可能斷了，這次不判斷協定是否被擋".into());
    }
    let w = r.warnings(policy);
    if !w.is_empty() {
        out.push(String::new());
        for x in w {
            out.push(format!("⚠ {x}"));
        }
    }
    out.join("\n")
}

async fn memory_plan_cmd(config: &std::path::Path, uci: bool, ram: Vec<u64>, bits: Option<u32>, as_json: bool) -> Result<()> {
    use kuroshio::memplan::{plan, text, Assumptions, Input};
    use serde_json::{json, Value};
    let mut notes: Vec<String> = Vec::new();
    let cfg = match config_for_cli(config, uci) {
        Ok(c) => c,
        Err(e) => {
            notes.push(format!("設定讀不到（{e}），用預設設定推算"));
            kuroshio_config::build(&json!({}))
        }
    };
    let n = |k: &str| kuroshio_config::num_or_auto(kuroshio_config::get(&cfg, k)).unwrap_or(0);
    // 啟用的清單：規則數從本機副本的索引（3.3.2 起記錄）拿，沒有的用預設清單的實測值估
    let index: Value = kuroshio_cdn::statefile::read(&kuroshio::app::persist_dir(&cfg).join(kuroshio::filtering::COPY_INDEX))
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    // 各清單的規則數（還沒扣掉不同清單之間重複的網域）：
    // 本機副本記的實際值 → 內建清單 2026-11 實測的行數 → 其他每份估 5 萬條
    let (mut sum, mut prot_sum, mut no_copy, mut no_rules) = (0u64, 0u64, 0usize, 0usize);
    for l in kuroshio_config::get(&cfg, "filter.lists")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if l.get("enabled").and_then(Value::as_bool) == Some(false) {
            continue;
        }
        let url = l.get("url").and_then(Value::as_str).unwrap_or("");
        let cat = l.get("category").and_then(Value::as_str).unwrap_or("ads");
        let prot = l.get("protect").and_then(Value::as_bool).unwrap_or(cat == "malware");
        let r = match index.get(url) {
            Some(m) if m["rules"].as_u64().unwrap_or(0) > 0 => m["rules"].as_u64().unwrap_or(0),
            other => {
                // 有副本但沒記規則數（3.3.2 以前寫的；3.3.3 起下次用副本載入時補記）／ 沒有副本
                if other.is_some() {
                    no_rules += 1;
                } else {
                    no_copy += 1;
                }
                kuroshio::memplan::KNOWN_RULES
                    .iter()
                    .find(|(u, _)| *u == url)
                    .map_or(kuroshio::memplan::UNKNOWN_LIST_RULES, |(_, n)| *n)
            }
        };
        sum += r;
        if prot {
            prot_sum += r;
        }
    }
    // 不同清單重複的網域只算一次（預設清單約少 25%）
    let mut rules = sum * kuroshio::memplan::DEDUP_PCT / 100;
    let mut protected = prot_sum * kuroshio::memplan::DEDUP_PCT / 100;
    if no_copy > 0 {
        notes.push(format!("{no_copy} 份清單還沒有本機副本：規則數用內建清單 2026-11 實測的行數估"));
    }
    if no_rules > 0 {
        notes.push(format!(
            "{no_rules} 份清單的本機副本沒記規則數（3.3.2 以前寫的；服務下次用副本載入時會補記）：先用內建清單實測的行數估"
        ));
    }
    // 服務正在執行：直接用它實際載入的規則數（已經扣掉重複），比上面的估計準
    let mut running: Option<Value> = None;
    if let Some(ep) = admin_endpoint(&cfg) {
        if let Ok((200, b)) = admin_call(&ep, "GET", "/api/status", None, std::time::Duration::from_secs(3)).await {
            running = serde_json::from_slice::<Value>(&b).ok();
        }
    }
    if let Some(f) = running
        .as_ref()
        .map(|v| &v["filter"])
        .filter(|f| f["lists"].as_u64().unwrap_or(0) > 0)
    {
        rules = f["lists"].as_u64().unwrap_or(rules);
        let p: u64 = f["sources"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|s| s["protect"] == true && s["status"] == "loaded")
            .filter_map(|s| s["rules"].as_u64())
            .sum();
        protected = (p * kuroshio::memplan::DEDUP_PCT / 100).min(rules);
        notes.push(format!("清單規則數用執行中服務實際載入的 {rules} 條"));
    }
    let sys = kuroshio::sysinfo::SysInfo::detect();
    let conc = match n("benchmark.concurrency") {
        0 => (8 * sys.cores as u64).clamp(8, 50),
        c => c,
    };
    let base = |total: u64| Input {
        total,
        avail_before: None,
        min_free_kb: None,
        reserve_mb: n("system.memoryReserveMB"),
        reserve_pct: n("system.memoryReservePercent"),
        rules,
        protected_rules: protected,
        cache_max: kuroshio_config::cache_max(&cfg, Some(total)),
        bench_conc: conc,
    };
    let a = match bits {
        Some(b @ (32 | 64)) => Assumptions::for_bits(b),
        Some(b) => anyhow::bail!("--bits 只能是 32 或 64（收到 {b}）"),
        None => Assumptions::for_this_build(),
    };
    let mut rows = Vec::new();
    // 這台機器：實際的記憶體；服務正在跑時，把它目前的用量加回去當「啟動前可用」
    if ram.is_empty() && bits.is_none() {
        if let (Some(total), Some(avail)) = kuroshio::sysinfo::mem_bytes() {
            let mut i = base(total);
            i.min_free_kb = kuroshio::memgov::read_min_free_kb();
            let mut own = 0u64;
            if let Some(kb) = running.as_ref().and_then(|v| v["memory"]["rssKB"].as_u64()) {
                own = kb * 1024;
                notes.push(format!(
                    "服務正在執行：目前實際用 {:.1} MB（RSS），推算時把它加回「啟動前可用」",
                    own as f64 / 1048576.0
                ));
            }
            i.avail_before = Some(avail + own);
            let mut r = plan(&i, &a);
            r["thisMachine"] = json!(true);
            rows.push(r);
        }
    }
    let sizes = if ram.is_empty() { vec![64, 128, 256, 512] } else { ram };
    for mb in sizes {
        rows.push(plan(&base(mb << 20), &a));
    }
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({ "rows": rows, "assumptions": a.json(), "notes": notes }))?
        );
    } else {
        println!("{}", text(&rows, &a));
        for n in &notes {
            println!("註：{n}");
        }
    }
    Ok(())
}

/// 不啟動服務的指令（notify、status、chain、health、check-path、memory-plan）沒帶 `--uci`、預設的 JSON 設定檔不存在，但環境變數指了 UCI 設定（第三方韌體的做法）：
/// 照 UCI 讀，不提示「設定檔不存在」（3.5.0 D3 回報：padavan 上每次 `kuroshio notify` 都印這行）。
/// 明確用 `-c` 指了別的檔案、或預設的檔案存在時照舊
fn implied_uci(config: &std::path::Path, uci: bool) -> bool {
    uci || (std::env::var_os("KUROSHIO_UCI_FILE").is_some() || std::env::var_os("KUROSHIO_UCI_JSON").is_some())
        && config == default_config_path()
        && !config.exists()
}

/// 設定讀不到時：結束碼 2
fn config_for_cli(config: &std::path::Path, uci: bool) -> std::result::Result<serde_json::Value, String> {
    let uci = implied_uci(config, uci);
    user_config(config, uci).map(|u| kuroshio_config::build(&u)).map_err(|e| {
        let mut m = format!("{e:#}");
        // 第三方韌體直接執行 `--uci`：預設找 /etc/config/kuroshio（OpenWrt 的位置）
        if uci && std::env::var_os("KUROSHIO_UCI_FILE").is_none() && std::env::var_os("KUROSHIO_UCI_JSON").is_none() {
            m.push_str("。不是 OpenWrt 的話，請用環境變數 KUROSHIO_UCI_FILE 指定 UCI 設定檔的位置（跟啟動服務時一樣）");
        }
        m
    })
}

/// `kuroshio health`：結束碼 0 = 有回答，1 = 沒有回答，2 = 設定讀不到
async fn health_cmd(config: &std::path::Path, uci: bool, timeout_ms: u64, json: bool) -> i32 {
    use kuroshio::integration::{health_json, health_target};
    let fail = |server: Option<std::net::SocketAddr>, msg: String, code: i32| {
        if json {
            let v = serde_json::json!({ "ok": false, "server": server.map(|s| s.to_string()), "ms": null, "rcode": null, "error": msg });
            println!("{v}");
        } else {
            match server {
                Some(s) => println!("{s} 沒有回答：{msg}"),
                None => println!("無法檢查：{msg}"),
            }
        }
        code
    };
    let cfg = match config_for_cli(config, uci) {
        Ok(c) => c,
        Err(e) => return fail(None, e, 2),
    };
    let server = match health_target(&cfg) {
        Ok(s) => s,
        Err(e) => return fail(None, e, 1),
    };
    let up = match kuroshio::upstream::Upstream::parse(&format!("udp://{server}")) {
        Ok(u) => u,
        Err(e) => return fail(Some(server), format!("{e:#}"), 2),
    };
    // SVCB _dns.resolver.arpa：服務自己回答（DDR），不經上游，上游全斷也照樣有答案
    let q = kuroshio_proto::build_query(0x4b48, "_dns.resolver.arpa", 64);
    let t0 = std::time::Instant::now();
    let r = up.exchange(&q, std::time::Duration::from_millis(timeout_ms.max(1))).await;
    let ms = t0.elapsed().as_millis() as u64;
    let header = r
        .map_err(|e| format!("{e:#}"))
        .and_then(|b| kuroshio_proto::header(&b).map_err(|e| format!("回應格式錯誤：{e}")));
    let rcode = match header {
        Ok(h) => h.rcode,
        Err(e) => return fail(Some(server), e, 1),
    };
    if json {
        println!("{}", health_json(server, Some(ms), Some(rcode), None));
    } else {
        println!("{server} 有回答（rcode {rcode}，{ms} ms）");
    }
    0
}

/// `kuroshio status [--json]`：結束碼 0 = 執行中，1 = 沒有回應（或讀不到狀態），2 = 設定讀不到
async fn status_cmd(config: &std::path::Path, uci: bool, json: bool) -> i32 {
    let fail = |running: bool, msg: String, code: i32| {
        if json {
            println!("{}", serde_json::json!({ "running": running, "error": msg }));
        } else if running {
            println!("黑潮 DNS 執行中，但{msg}");
        } else {
            println!("黑潮 DNS 沒有在執行：{msg}");
        }
        code
    };
    let (cfg, why) = cli_config_or_default(config, uci, json);
    let Some(mut ep) = admin_endpoint(&cfg) else {
        return fail(false, "管理 API 沒有開啟（admin.enabled = false），無法查詢狀態".into(), 1);
    };
    if why.is_some() {
        ep.1 = None;
    }
    match admin_call(&ep, "GET", "/api/status", None, std::time::Duration::from_secs(5)).await {
        // 讀不到設定、預設的管理埠也沒回應：照樣把設定的錯誤（含 KUROSHIO_UCI_FILE 的提示）講出來
        Err(e) => match &why {
            Some(w) => fail(false, format!("設定讀不到：{w}（預設的管理埠 {} 也沒有回應：{e:#}）", ep.0), 2),
            None => fail(false, format!("管理 API 沒有回應（{}）：{e:#}", ep.0), 1),
        },
        Ok((401, _)) => fail(
            true,
            "管理 API 需要登入，讀不到登入 token（請用同一個設定檔、有權限讀 token 檔的帳號執行）".into(),
            1,
        ),
        Ok((200, body)) => match serde_json::from_slice::<serde_json::Value>(&body) {
            Ok(api) => {
                let s = kuroshio::integration::summarize_status(&api);
                if json {
                    println!("{s}");
                } else {
                    println!("{}", kuroshio::integration::status_text(&s));
                }
                0
            }
            Err(e) => fail(true, format!("狀態格式錯誤：{e}"), 1),
        },
        Ok((code, body)) => fail(true, format!("讀不到狀態：{}", api_error(code, &body)), 1),
    }
}

/// 讀設定給只需要管理 API 的指令（notify、status、chain）：讀不到時改用預設的管理埠（127.0.0.1:8054、不帶 token），
/// 第三方韌體沒有設 `KUROSHIO_UCI_FILE` 也查得到（3.4.1 起 status、chain 也這樣）。
/// 回傳 (設定, 讀不到設定的原因)；有原因（備援）時呼叫端要把 token 拿掉，送不到時結束碼用 2（設定讀不到）
fn cli_config_or_default(config: &std::path::Path, uci: bool, quiet: bool) -> (serde_json::Value, Option<String>) {
    match config_for_cli(config, uci) {
        Ok(c) => (c, None),
        Err(e) => {
            if !quiet {
                eprintln!("注意：設定讀不到（{e}）；改用預設的管理埠 8054");
            }
            (kuroshio_config::build(&serde_json::json!({})), Some(e))
        }
    }
}

/// `kuroshio notify <事件>`：結束碼 0 = 已送達，1 = 服務沒有回應，2 = 設定讀不到
async fn notify_cmd(event: NotifyEvent) -> i32 {
    let (config, uci, path, timeout) = match event {
        NotifyEvent::WanChanged { config, uci } => (config, uci, "/api/notify/wan-changed".to_string(), 10),
        // 快照可能有好幾 MB（CDN 網域庫），慢的儲存裝置要多等一下
        NotifyEvent::Save { config, uci } => (config, uci, "/api/persist/flush".to_string(), 120),
        // CDN 冷資料移出前要先寫出快照
        NotifyEvent::Trim { hold, config, uci } => (config, uci, format!("/api/memory/trim?holdSec={hold}"), 60),
        NotifyEvent::SimulateMemory {
            avail_mb,
            minutes,
            off,
            config,
            uci,
        } => {
            let path = match (off, avail_mb) {
                (false, Some(mb)) => format!("/api/memory/simulate?availMB={mb}&minutes={minutes}"),
                _ => "/api/memory/simulate?off=1".to_string(),
            };
            (config, uci, path, 10)
        }
    };
    let path = path.as_str();
    // 讀不到設定也試一次預設的管理埠（127.0.0.1:8054，不帶 token）：通知送得到就好，不必知道其他設定。
    // 送不到時結束碼照樣是 2（設定讀不到）
    let (cfg, why) = cli_config_or_default(&config, uci, false);
    let fallback = why.is_some();
    let fail_code = if fallback { 2 } else { 1 };
    let Some(mut ep) = admin_endpoint(&cfg) else {
        eprintln!("管理 API 沒有開啟（admin.enabled = false），無法通知服務");
        return 1;
    };
    // 備援時明確不帶 token（Windows 預設要登入，admin_endpoint 會去讀預設位置的 token 檔；那不一定是這個服務的）
    if fail_code == 2 {
        ep.1 = None;
    }
    let r = admin_call(&ep, "POST", path, Some(b"{}"), std::time::Duration::from_secs(timeout)).await;
    match r {
        Err(e) => {
            eprintln!("服務沒有回應（{}）：{e:#}", ep.0);
            fail_code
        }
        Ok((200, body)) => {
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            if path == "/api/persist/flush" {
                println!("{}", kuroshio::integration::save_text(&v));
                return 0;
            }
            if path.starts_with("/api/memory/trim") {
                println!("{}", kuroshio::integration::trim_text(&v));
                return 0;
            }
            if path.starts_with("/api/memory/simulate") {
                println!("{}", kuroshio::integration::simulate_text(&v));
                return 0;
            }
            println!(
                "已通知服務：WAN 變動。{}；重新偵測對外 IP（ECS）{}",
                if v["ddns"] == "disabled" {
                    "DDNS 沒有啟用"
                } else {
                    "DDNS 立即檢查（背景進行）"
                },
                if v["clockSynced"] == false {
                    "（系統時間還沒對時，等對時之後才做）"
                } else {
                    ""
                }
            );
            0
        }
        Ok((code, body)) => {
            eprintln!("服務拒絕通知：{}", api_error(code, &body));
            fail_code
        }
    }
}

/// `kuroshio chain status|recheck`：結束碼 0 = 成功，1 = 服務沒有回應，2 = 設定讀不到
async fn chain_cmd(action: ChainAction) -> i32 {
    let (config, uci, method, path, json) = match action {
        ChainAction::Status { config, uci, json } => (config, uci, "GET", "/api/chain", json),
        ChainAction::Recheck { config, uci } => (config, uci, "POST", "/api/chain/recheck", false),
    };
    let (cfg, why) = cli_config_or_default(&config, uci, json);
    let fallback = why.is_some();
    let fail_code = if fallback { 2 } else { 1 };
    let Some(mut ep) = admin_endpoint(&cfg) else {
        eprintln!("管理 API 沒有開啟（admin.enabled = false），無法查詢串接狀態");
        return 1;
    };
    if fallback {
        ep.1 = None;
    }
    let body = (method == "POST").then_some(&b"{}"[..]);
    match admin_call(&ep, method, path, body, std::time::Duration::from_secs(10)).await {
        Err(e) => {
            match &why {
                Some(w) => eprintln!("設定讀不到（{w}），預設的管理埠也沒有回應（{}）：{e:#}", ep.0),
                None => eprintln!("服務沒有回應（{}）：{e:#}", ep.0),
            }
            fail_code
        }
        Ok((200, body)) => {
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            if json {
                println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            } else if path == "/api/chain/recheck" {
                println!("已開始重新偵測上游黑潮（背景進行）；稍後用 kuroshio chain status 看結果");
            } else {
                println!("{}", chain_status_text(&v));
            }
            0
        }
        Ok((code, body)) => {
            eprintln!("服務拒絕：{}", api_error(code, &body));
            fail_code
        }
    }
}

fn chain_status_text(v: &serde_json::Value) -> String {
    let s = |x: &serde_json::Value| x.as_str().unwrap_or("").to_string();
    let mut out = vec![format!("串接：{}", s(&v["text"]))];
    out.push(format!(
        "  狀態：{}{}",
        s(&v["state"]),
        v["reason"].as_str().map(|r| format!("（{r}）")).unwrap_or_default()
    ));
    let u = &v["upstream"];
    if u.is_object() {
        if let Some(a) = u["address"].as_str() {
            out.push(format!(
                "  上游：{a}（{}{}）",
                s(&u["proto"]),
                u["via"].as_str().map(|x| format!("，{x}")).unwrap_or_default()
            ));
        }
        if let Some(f) = u["fingerprint"].as_str() {
            out.push(format!("  節點指紋：{f}"));
        }
        if let Some(p) = u["previousFingerprint"].as_str() {
            out.push(format!("  之前的指紋：{p}"));
        }
    }
    out.join("\n")
}

/// 執行中可以收的訊號（只有 Unix；Windows 沒有）
#[derive(Clone, Copy)]
enum Sig {
    /// SIGHUP：重新載入設定（同設定頁存檔、主控台的 reload）
    Reload,
    /// SIGUSR1：立刻寫出快照（不結束）
    Flush,
}

struct Signals {
    #[cfg(unix)]
    hup: Option<tokio::signal::unix::Signal>,
    #[cfg(unix)]
    usr1: Option<tokio::signal::unix::Signal>,
}

impl Signals {
    fn new() -> Signals {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            Signals {
                hup: signal(SignalKind::hangup()).ok(),
                usr1: signal(SignalKind::user_defined1()).ok(),
            }
        }
        #[cfg(not(unix))]
        Signals {}
    }

    /// 下一個訊號；沒有（或不是 Unix）時永遠不會回來
    async fn next(&mut self) -> Sig {
        #[cfg(unix)]
        {
            async fn recv(s: &mut Option<tokio::signal::unix::Signal>) -> Option<()> {
                match s {
                    Some(s) => s.recv().await,
                    None => std::future::pending().await,
                }
            }
            tokio::select! {
                Some(_) = recv(&mut self.hup) => Sig::Reload,
                Some(_) = recv(&mut self.usr1) => Sig::Flush,
                else => std::future::pending().await,
            }
        }
        #[cfg(not(unix))]
        std::future::pending().await
    }
}

/// cmd／前景執行時等停止訊號，回傳是哪一種（3.5.0 C1）
///
/// Windows：Ctrl+C、Ctrl+Break、關閉主控台視窗、登出、關機都走同一個正常停止。後三種系統在事件發生後大約 5 秒
/// 就強制結束行程：tokio 1.54 的處理函式收到這三種事件時不會回傳（停在那裡），行程留給程式自己結束，
/// 所以在時限內寫完快照、`main` 回傳時行程就正常結束；關機寫快照的上限縮成 3 秒（[`StopReason::flush_budget`]）。
/// 有一種註冊失敗（不該發生）時其他的照等
async fn shutdown_signal() -> StopReason {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("signal");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => StopReason::CtrlC,
            _ = term.recv() => StopReason::Terminate,
            _ = kuroshio::memgov::restart_requested() => StopReason::MemoryRestart,
        }
    }
    #[cfg(windows)]
    {
        use tokio::signal::windows;
        let mut c = windows::ctrl_c().ok();
        let mut brk = windows::ctrl_break().ok();
        let mut close = windows::ctrl_close().ok();
        let mut logoff = windows::ctrl_logoff().ok();
        let mut shut = windows::ctrl_shutdown().ok();
        // 每一種都是「有註冊就等它、沒有就永遠不會來」
        macro_rules! wait {
            ($s:expr) => {
                async {
                    match $s.as_mut() {
                        Some(s) => {
                            s.recv().await;
                        }
                        None => std::future::pending::<()>().await,
                    }
                }
            };
        }
        tokio::select! {
            _ = wait!(c) => StopReason::CtrlC,
            _ = wait!(brk) => StopReason::CtrlBreak,
            _ = wait!(close) => StopReason::ConsoleClose,
            _ = wait!(logoff) => StopReason::Logoff,
            _ = wait!(shut) => StopReason::SystemShutdown,
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = tokio::signal::ctrl_c().await;
        StopReason::CtrlC
    }
}

#[cfg(test)]
mod tests {
    /// QUIC 函式庫的日誌預設只記錯誤（3.5.1 K3 加上 `quinn_udp`：Windows 的 `sendmsg error` 不洗版）
    #[test]
    fn default_log_quiets_quic_libraries() {
        let d = super::default_log_directives("info");
        assert_eq!(d, "info,quinn_proto=error,quinn=warn,quinn_udp=error");
        assert!(tracing_subscriber::EnvFilter::try_new(&d).is_ok());
    }
}
