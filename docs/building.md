# 建置說明

各平台的執行檔都由 GitHub Actions（[`.github/workflows/rust.yml`](../.github/workflows/rust.yml)）編譯、實際執行測試後才打包。這份說明 CI 怎麼編、自己怎麼編，以及 MIPS 用的 nightly 怎麼更新。

## 工具鏈

| 用途 | 工具鏈 |
|---|---|
| 測試、x86_64 / aarch64 / armv7、Windows | Rust stable（最低 1.80） |
| MIPS（`mipsel` / `mips`） | **固定日期的 nightly**＋`rust-src`，用 `-Zbuild-std` 自己編標準函式庫 |
| Linux 各 CPU 的連結 | [cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild)（用 zig 當 C 編譯器與連結器，不必裝各 CPU 的 GCC） |

為什麼 MIPS 要 nightly：MIPS 在 Rust 是 **tier 3**，官方不提供編好的標準函式庫（`rustup target add` 裝不到），只能用 nightly 才有的 `-Zbuild-std` 從原始碼編。nightly 每天都在變、偶爾會壞，所以 CI 固定在一個已知可以編、QEMU 測試也通過的日期，寫在 workflow 開頭的 `MIPS_NIGHTLY`（目前 `nightly-2026-11-13`）。

## CI 怎麼編

| 工作 | 目標 | 做法 |
|---|---|---|
| 測試 | 主機（x86_64 Linux） | `cargo fmt --check`、`cargo clippy`、`cargo test`、shellcheck、設定頁 / 公開頁的 Playwright 測試 |
| 執行檔 | `x86_64-unknown-linux-musl` | `cargo zigbuild --release -p kuroshio --target …`，直接執行測試 |
| 執行檔 | `aarch64-unknown-linux-musl`、`armv7-unknown-linux-musleabihf` | 同上，用 QEMU user-mode 實際執行 |
| 執行檔 | `mipsel-unknown-linux-musl`、`mips-unknown-linux-musl` | `MIPS_NIGHTLY` 的 nightly，`RUSTFLAGS="-C relocation-model=static"`（MIPS 的 static-pie 一啟動就 segfault），`-Zbuild-std=std,panic_abort`，用 QEMU 實際執行 |
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

## 更新 MIPS 的 nightly

1. 挑一個日期，先在自己電腦上試：

   ```sh
   rustup toolchain install nightly-YYYY-MM-DD --component rust-src
   RUSTFLAGS="-C relocation-model=static" \
     cargo +nightly-YYYY-MM-DD zigbuild --release -p kuroshio --target mips-unknown-linux-musl -Zbuild-std=std,panic_abort
   qemu-mips-static target/mips-unknown-linux-musl/release/kuroshio query example.com -s 8.8.8.8
   ```

2. 改 `.github/workflows/rust.yml` 開頭的 `MIPS_NIGHTLY`（只有這一個地方），連同註解裡的 rustc 版本，推送。
3. 確認「執行檔 mipsel-unknown-linux-musl」「執行檔 mips-unknown-linux-musl」兩個工作都通過（編譯、QEMU 實際執行），日誌裡的 `rustc … -nightly` 是新的日期。
4. 再跑一次完整的 OpenWrt 打包與實機測試（手動執行 workflow，`full` 打勾）比較保險。

`nightly-YYYY-MM-DD` 是 rustup 發布的日期，裡面的 rustc 版本字串通常是前一天的 commit 日期（例如 `nightly-2026-11-13` 是 `rustc 1.102.0-nightly (8eb778d04 2026-11-12)`）。
