# 建置說明

各平台的執行檔都由 GitHub Actions（[`.github/workflows/rust.yml`](../.github/workflows/rust.yml)）編譯、實際執行測試後才打包。這份說明 CI 怎麼編、自己怎麼編，以及 MIPS 用的 nightly 怎麼更新。動手改東西之前先讀[核心理念與設計原則](principles.md)。

## 開發

```sh
cargo test
cargo run -- run -c config.json
cargo run -- query example.com -s 8.8.8.8
```

推之前要過：`cargo fmt --all --check`、`cargo clippy --all-targets -- -D warnings`、`cargo clippy -p kuroshio --all-targets --features acme -- -D warnings`、`cargo test --workspace`。改了設定頁、公開頁或儀表板的，另外跑 `node tools/check-data-assets.js`、`node tools/site-e2e.js`、`node tools/admin-e2e.js`；改了文件的，跑 `node tools/check-doc-links.js` 檢查連結與錨點。

| 資料夾 | 內容 |
|---|---|
| `crates/kuroshio` | 主程式（監聽、轉發、管理 API、記憶體控制、存檔、指令列） |
| `crates/kuroshio-config` | 設定結構、預設值、UCI 轉換 |
| `crates/kuroshio-proto` | DNS 封包工具 |
| `crates/kuroshio-net` | 上游連線（UDP / TCP / DoT / DoH / DoQ / DoH3）、TLS、下載、測速 |
| `crates/kuroshio-filter` | 過濾引擎 |
| `crates/kuroshio-cdn` | CDN 台灣節點 |
| `crates/kuroshio-jobs` | 排程與背景工作（每日評測、台灣 IP 清單…） |
| `crates/kuroshio-community` | 社群共享 |
| `openwrt/` | OpenWrt 套件與 LuCI |
| `windows/` | Windows 版說明 |
| `linux/` | Linux 通用版說明 |
| `docker/` | 容器映像檔、Compose 範例、映像檔測試 |
| `data/` | 設定頁、公開頁、共用儀表板、種子資料、評測名單、CDN 官方範圍、台灣 IP 公版 |
| `rules/` | 預設自訂過濾規則 |
| `tools/` | 設定頁與公開頁的測試、儀表板範例資料、文件連結檢查、原始碼包 |
| `docs/guide/` | 使用者指南 |
| `docs/spec/` | 規格 |
| `docs/release-notes/` | 各版的 Release 說明 |

## 工具鏈

| 用途 | 工具鏈 |
|---|---|
| 測試、x86_64 / aarch64 / armv7、Windows | Rust stable（`rust-version` 跟著最新的 stable，3.5.1 起是 1.100） |
| MIPS（`mipsel` / `mips`） | **最新的 nightly**＋`rust-src`，用 `-Zbuild-std` 自己編標準函式庫；編不過時自動改用備用日期 |
| Linux 各 CPU 的連結 | [cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild)（用 zig 當 C 編譯器與連結器，不必裝各 CPU 的 GCC） |

**跟著最新的 stable**（3.5.1 起）：使用者拿到的都是 CI 編好的執行檔（Release、OpenWrt 套件、韌體都不在使用者那邊編譯），所以程式碼用最新 stable 的寫法，不為舊的編譯器保留相容寫法。新的 stable 把某個 API 標成棄用、或有更好的寫法時，直接改用新的，並把 `Cargo.toml` 的 `rust-version` 提高到那個版本；CI 一直用最新的 stable，警告一律當錯誤。MIPS 的 nightly（含備用日期）一定比 stable 新，不受影響。

為什麼 MIPS 要 nightly：MIPS 在 Rust 是 **tier 3**，官方不提供編好的標準函式庫（`rustup target add` 裝不到），只能用 nightly 才有的 `-Zbuild-std` 從原始碼編。CI 平常跟著最新的 nightly 編；nightly 偶爾會壞，最新的編不過時會自動改用 workflow 開頭 `MIPS_NIGHTLY_FALLBACK` 指定的、已知能編也通過 QEMU 測試的日期（目前 `nightly-2026-11-13`），日誌會出現警告。

## CI 怎麼編

| 工作 | 目標 | 做法 |
|---|---|---|
| 測試 | 主機（x86_64 Linux） | `cargo fmt --check`、`cargo clippy`、`cargo test`、shellcheck、設定頁 / 公開頁的 Playwright 測試 |
| 執行檔 | `x86_64-unknown-linux-musl` | `cargo zigbuild --release -p kuroshio --target …`，直接執行測試 |
| 執行檔 | `aarch64-unknown-linux-musl`、`armv7-unknown-linux-musleabihf` | 同上，用 QEMU user-mode 實際執行 |
| 執行檔 | `mipsel-unknown-linux-musl`、`mips-unknown-linux-musl` | 最新的 nightly（編不過時用 `MIPS_NIGHTLY_FALLBACK`），`RUSTFLAGS="-C relocation-model=static"`（MIPS 的 static-pie 一啟動就 segfault），`-Zbuild-std=std,panic_abort`，用 QEMU 實際執行 |
| Windows | `x86_64-pc-windows-msvc` | windows-latest 上 `cargo build --release -p kuroshio --features acme`（C 執行階段靜態連結，見 `.cargo/config.toml`），測服務、防火牆、IIS / HTTP.sys |
| OpenWrt | 各套件架構 × 24.10 / 25.12 | 把上面的靜態執行檔交給 OpenWrt SDK 打包（不在 SDK 裡編 Rust），再在 OpenWrt 容器裡安裝測試、跑 LuCI |
| 容器映像檔 | amd64（每次推送）；amd64 / arm64 / armv7（標籤） | 用上面的靜態執行檔 `docker build`，[`docker/test.sh`](../docker/test.sh) 測試；見 [Docker 使用說明](docker.md) |

QEMU 測試會真的查詢 DoT / DoH / DoQ / DoH3 上游、啟動伺服器查自己、下載預設的訂閱清單，確認 TLS、QUIC 在每種 CPU 上都能用。

每個執行檔產生兩種成品：

- `kuroshio-<target>`：單獨的執行檔（Release 上的檔名固定，下游韌體依檔名與雜湊下載，不要改）
- `kuroshio-linux-<target>.tar.gz`：`kuroshio/` 資料夾，裡面是執行檔、`data/`、`LICENSE`、`README-linux.txt`

推送 `v3.*` 標籤時建立 Release：OpenWrt 套件 zip、Windows zip、上面兩種 Linux 成品、`SHA256SUMS`，附建置來源證明（`gh attestation verify <檔案> --repo candy999/kuroshio-dns`），並推送多 CPU 的容器映像檔。

## 自己編

```sh
cargo test
cargo build --release -p kuroshio
```

跨 CPU：

```sh
pip install ziglang cargo-zigbuild
rustup target add aarch64-unknown-linux-musl armv7-unknown-linux-musleabihf x86_64-unknown-linux-musl
cargo zigbuild --release -p kuroshio --target aarch64-unknown-linux-musl

# MIPS：用 CI 同一天的 nightly
rustup toolchain install nightly-2026-11-13 --component rust-src
RUSTFLAGS="-C relocation-model=static" \
  cargo +nightly-2026-11-13 zigbuild --release -p kuroshio --target mipsel-unknown-linux-musl -Zbuild-std=std,panic_abort
```

成品在 `target/<target>/release/kuroshio`，是靜態連結的單一執行檔；把它跟 `data/` 放在同一個資料夾就能用。

## 用 QEMU 在電腦上執行其他 CPU 的執行檔

執行檔是靜態連結的，QEMU user-mode 直接就能跑，不需要整個系統映像：

```sh
sudo apt-get install qemu-user-static     # 新版 Ubuntu 沒有的話改裝 qemu-user
qemu-aarch64-static target/aarch64-unknown-linux-musl/release/kuroshio --version
qemu-mipsel-static  target/mipsel-unknown-linux-musl/release/kuroshio query example.com -s 8.8.8.8
qemu-mips-static    target/mips-unknown-linux-musl/release/kuroshio run -c /tmp/k.json
```

（`armv7` 用 `qemu-arm-static`。）裝了 `binfmt-support` 的話也可以直接 `./kuroshio` 執行。CI 的「用 QEMU 實際執行」那一步就是這樣測的，可以照著跑一遍。

## 更新備用的 nightly 日期

1. 挑一個日期，先在自己電腦上試：

   ```sh
   rustup toolchain install nightly-YYYY-MM-DD --component rust-src
   RUSTFLAGS="-C relocation-model=static" \
     cargo +nightly-YYYY-MM-DD zigbuild --release -p kuroshio --target mips-unknown-linux-musl -Zbuild-std=std,panic_abort
   qemu-mips-static target/mips-unknown-linux-musl/release/kuroshio query example.com -s 8.8.8.8
   ```

2. 改 `.github/workflows/rust.yml` 開頭的 `MIPS_NIGHTLY_FALLBACK`（只有這一個地方），連同註解裡的 rustc 版本，推送。平常不用動它；最新的 nightly 編不過（日誌出現「改用 nightly-…」的警告）而且備用日期太舊時再更新。
3. 確認「執行檔 mipsel-unknown-linux-musl」「執行檔 mips-unknown-linux-musl」兩個工作都通過（編譯、QEMU 實際執行）。
4. 再跑一次完整的 OpenWrt 打包與實機測試（手動執行 workflow，`full` 打勾）比較保險。

`nightly-YYYY-MM-DD` 是 rustup 發布的日期，裡面的 rustc 版本字串通常是前一天的 commit 日期（例如 `nightly-2026-11-13` 是 `rustc 1.102.0-nightly (8eb778d04 2026-11-12)`）。
