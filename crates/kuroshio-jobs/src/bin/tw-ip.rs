//! 產生台灣 IP 清單 `data/geo/tw-ip.json`（依 ISP 分組，規格 08）
//!
//! 產生的方法、資料來源、ASN 對照表都在 `kuroshio_jobs::twip`（裝置上的每月排程工作 `tw-ip` 用同一份程式）。
//! 這個指令列給 GitHub Actions 每月更新隨程式附帶的公版清單用；裝置不會從本專案下載任何東西。
//!
//! 用法（需要網路）：
//!   cargo run --release -p kuroshio-jobs --bin tw-ip -- data/geo/tw-ip.json [報表.md]
//! 選項：
//!   --cache DIR       下載的原始資料存到 DIR；DIR 裡已經有的檔案直接用（離線重跑、或先用 curl 下載好）
//!   --offline         只用 --cache 裡的檔案，缺檔就失敗
//!   --date D          generatedAt 用 D（預設今天，UTC）
//!   --pause SEC       每個 RIPEstat 請求之間停幾秒（預設 1）
//!   --sources-base U  全部來源改成 U 開頭（測試用：U/delegated-<rir>-extended-latest、U/data/announced-prefixes/...）
//!   --min-v4 N        台灣 IPv4 總量下限（預設 20,000,000；測試用）

use anyhow::Result;
use kuroshio_jobs::twip::{compact, today, Simple, Sources};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mut s = Simple {
        sources: Sources::default(),
        cache: None,
        offline: false,
        pause: Duration::from_secs(1),
        min_v4: 20_000_000,
    };
    let (mut date, mut pos) = (None, Vec::new());
    while let Some(a) = args.next() {
        match a.as_str() {
            "--cache" => s.cache = args.next().map(PathBuf::from),
            "--offline" => s.offline = true,
            "--date" => date = args.next(),
            "--pause" => s.pause = Duration::from_secs_f64(args.next().and_then(|v| v.parse().ok()).unwrap_or(1.0)),
            "--sources-base" => s.sources = Sources::with_base(&args.next().unwrap_or_default()),
            "--min-v4" => s.min_v4 = args.next().and_then(|v| v.parse().ok()).unwrap_or(0),
            _ => pos.push(a),
        }
    }
    let out = PathBuf::from(pos.first().map(String::as_str).unwrap_or("data/geo/tw-ip.json"));
    let date = date.unwrap_or_else(today);
    let (json, report) = s.run(&date).await?;
    if let Some(dir) = out.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&out, compact(&json))?;
    eprintln!("{report}");
    if let Some(r) = pos.get(1) {
        std::fs::write(Path::new(r), report)?;
    }
    Ok(())
}
