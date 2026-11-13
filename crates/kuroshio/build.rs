//! 建置時間（`KUROSHIO_BUILD_EPOCH`，Unix 秒）：判斷系統時間有沒有對時用（見 `src/clock.rs`）。
//! 有 `SOURCE_DATE_EPOCH`（可重現建置）就用它，否則用現在時間。
//! 只有這個檔或 `SOURCE_DATE_EPOCH` 變了才重新執行：平常改程式碼時建置時間不會跟著變（比較舊只會更寬鬆）。

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    let epoch = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        });
    println!("cargo:rustc-env=KUROSHIO_BUILD_EPOCH={epoch}");
}
