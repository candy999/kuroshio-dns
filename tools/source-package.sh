#!/bin/sh
# 原始碼包（GPL-3.0 的對應原始碼）：目前 commit 的原始碼 + 全部依賴套件（cargo vendor），可以完全離線編譯。
# 用法：tools/source-package.sh <版本> <輸出資料夾>
# 產生 <輸出資料夾>/kuroshio-dns-<版本>-source.tar.xz。同一個 commit 產生的內容相同（檔案時間固定成 commit 時間、依檔名排序）
set -eu
v=$1
out=$2
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
git archive --format=tar --prefix="kuroshio-dns-$v/" HEAD | tar -x -C "$work"
(
	cd "$work/kuroshio-dns-$v"
	mkdir -p .cargo
	# 接在 repo 原本的 .cargo/config.toml 後面（Windows 的 +crt-static 等設定要留著），不是蓋掉
	{
		echo
		echo "# cargo vendor：只用 vendor/ 裡的依賴套件（離線編譯）"
		cargo vendor --locked --versioned-dirs vendor
	} >> .cargo/config.toml
	grep -q 'crt-static' .cargo/config.toml || { echo "原始碼包的 .cargo/config.toml 少了 +crt-static" >&2; exit 1; }
	# 檢查：只用 vendor/ 也解析得了全部依賴
	cargo metadata --offline --locked --format-version 1 > /dev/null
)
t=$(git log -1 --format=%ct)
mkdir -p "$out"
tar -C "$work" --sort=name --mtime="@$t" --owner=0 --group=0 --numeric-owner -cf - "kuroshio-dns-$v" | xz -T1 -9 > "$out/kuroshio-dns-$v-source.tar.xz"
ls -la "$out/kuroshio-dns-$v-source.tar.xz"
