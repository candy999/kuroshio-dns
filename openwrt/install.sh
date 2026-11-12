#!/bin/sh
# 黑潮 DNS 一鍵安裝（OpenWrt）：把整個資料夾放到路由器上，執行 sh install.sh
# 會檢查 CPU 架構與 OpenWrt 版本是否相符，再一起安裝 kuroshio 與 luci-app-kuroshio。
set -e
cd "$(dirname "$0")"

ARCH=""
OPENWRT=""
# 壓縮檔裡的 PACKAGE_INFO：ARCH=（套件架構）、OPENWRT=（24.10 或 25.12）
# shellcheck disable=SC1091
[ -f ./PACKAGE_INFO ] && . ./PACKAGE_INFO

err() { echo "錯誤：$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || err "請用 root 執行"
[ -f /etc/openwrt_release ] || err "找不到 /etc/openwrt_release：這台不是 OpenWrt？"

SYS_ARCH=$(. /etc/openwrt_release; echo "$DISTRIB_ARCH")
SYS_REL=$(. /etc/openwrt_release; echo "$DISTRIB_RELEASE")
echo "路由器：OpenWrt $SYS_REL，架構 $SYS_ARCH"
[ -n "$ARCH" ] && echo "套件：OpenWrt $OPENWRT，架構 $ARCH"

if [ -n "$ARCH" ] && [ -n "$SYS_ARCH" ] && [ "$ARCH" != "$SYS_ARCH" ]; then
	err "這個壓縮檔是給 $ARCH 的，你的路由器是 $SYS_ARCH。請下載檔名結尾是 -$SYS_ARCH.zip 的那一個"
fi

if command -v apk >/dev/null 2>&1; then
	# OpenWrt 25.12 以後：apk
	set -- ./kuroshio-[0-9]*.apk
	[ -e "$1" ] || err "這是 OpenWrt 24.10（.ipk）的套件，你的路由器用的是 apk（25.12 以後）。請下載 kuroshio-openwrt-25.12-$SYS_ARCH.zip"
	apk update || echo "（apk update 失敗；如果缺相依套件，請確認路由器能連上網路後再試一次）"
	apk add --allow-untrusted ./kuroshio-[0-9]*.apk ./luci-app-kuroshio-*.apk
elif command -v opkg >/dev/null 2>&1; then
	# OpenWrt 24.10：opkg
	set -- ./kuroshio_*.ipk
	[ -e "$1" ] || err "這是 OpenWrt 25.12（.apk）的套件，你的路由器用的是 opkg（24.10）。請下載 kuroshio-openwrt-24.10-$SYS_ARCH.zip"
	opkg update || echo "（opkg update 失敗；如果缺相依套件，請確認路由器能連上網路後再試一次）"
	opkg install ./kuroshio_*.ipk ./luci-app-kuroshio_*.ipk
else
	err "找不到 opkg 或 apk"
fi

# 讓 LuCI 馬上看到新的選單
rm -rf /tmp/luci-indexcache* /tmp/luci-modulecache 2>/dev/null || true
/etc/init.d/rpcd reload 2>/dev/null || true

echo
echo "安裝完成。"
echo "  1. 打開 LuCI：服務 → 黑潮 DNS"
echo "  2. 確認設定後按「啟用」；從 2.x（candydns）升級的話，舊設定已經自動帶入"
echo "  3. 指令列也可以：kuroshio query example.com -s 127.0.0.1"
