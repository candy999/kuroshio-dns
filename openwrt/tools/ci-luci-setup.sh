#!/bin/sh
# CI：在 OpenWrt rootfs 容器裡裝好 LuCI 並手動啟動 ubusd / rpcd / uhttpd（容器裡沒有 procd）
set -e
# 用法：ci-luci-setup.sh [candydns|kuroshio]（預設 candydns，2.x）
NAME=${1:-candydns}
PKG=/pkgs/$NAME
LUCI=/pkgs/luci-app-$NAME
mkdir -p /var/lock /var/run /tmp/lock
if command -v apk >/dev/null 2>&1; then
	apk update >/dev/null
	# 映像裡的 uhttpd / libucode 可能比套件庫舊：先升級，免得新的 uhttpd-mod-ucode 載入失敗
	apk upgrade >/dev/null 2>&1 || true
	if [ "$NAME" = candydns ] && ! apk add --simulate node >/dev/null 2>&1; then
		echo "::warning::這個 OpenWrt 版本的官方套件庫沒有 node，candydns 無法安裝，略過 LuCI 測試"
		touch /src/.luci-skip
		exit 0
	fi
	apk add luci-base luci-mod-admin-full luci-theme-bootstrap uhttpd uhttpd-mod-ubus uhttpd-mod-ucode ucode-mod-uloop ucode-mod-ubus rpcd-mod-luci rpcd-mod-file rpcd-mod-iwinfo luci-lib-base
	apk add --allow-untrusted "$PKG"-[0-9]*.apk "$LUCI"-*.apk
else
	opkg update >/dev/null
	opkg install luci-base luci-mod-admin-full luci-theme-bootstrap uhttpd uhttpd-mod-ubus uhttpd-mod-ucode ucode-mod-uloop ucode-mod-ubus rpcd-mod-luci rpcd-mod-file
	opkg install "$PKG"_*.ipk "$LUCI"_*.ipk
fi
sh "/etc/uci-defaults/90-$NAME" 2>/dev/null || true
for f in /etc/uci-defaults/*luci* /etc/uci-defaults/*rpcd*; do [ -f "$f" ] && sh "$f" 2>/dev/null; done
ubusd &
sleep 1
rpcd &
sleep 2
# 沒有 procd：補 ubus system 物件給 LuCI
ucode /src/openwrt/tools/ci-fake-system.uc > /tmp/fake-system.log 2>&1 &
sleep 1
ubus call system board || cat /tmp/fake-system.log
# LuCI（ucode 版）：-o 是網址前綴、-O 是處理腳本，要成對給。
# 處理腳本的位置各版本不同：找不到就改走 /www/cgi-bin/luci（CGI），兩個都沒有就印出線索
H=$(find /usr/share/ucode -name uhttpd.uc 2>/dev/null | head -n 1)
if [ -n "$H" ]; then
	echo "LuCI ucode 處理腳本：$H"
	for so in /usr/lib/uhttpd_ucode.so /usr/lib/libucode.so*; do [ -e "$so" ] && echo "  $so"; done
	set -- -o /cgi-bin/luci -O "$H"
elif [ -x /www/cgi-bin/luci ]; then
	echo "沒有 ucode 處理腳本，改用 CGI /www/cgi-bin/luci"
	set --
else
	echo "::error::找不到 LuCI 的進入點（uhttpd.uc 或 /www/cgi-bin/luci）"
	find /usr/share/ucode 2>/dev/null | head -n 40
	(apk info -L luci-base 2>/dev/null || opkg files luci-base 2>/dev/null) | head -n 60
	set --
fi
uhttpd -f -h /www -r OpenWrt -x /cgi-bin -u /ubus -t 60 -T 30 -k 20 -A 1 -n 3 -N 100 -R -p 0.0.0.0:80 \
	"$@" > /tmp/uhttpd.log 2>&1 &
sleep 2
uclient-fetch -q -O - http://127.0.0.1/cgi-bin/luci/ | head -60
tail -20 /tmp/uhttpd.log
if grep -q "Unable to open ucode handler" /tmp/uhttpd.log; then
	echo "::error::uhttpd 載入不了 ucode 外掛"
	(apk info -v uhttpd uhttpd-mod-ucode ucode libucode 2>/dev/null || opkg list-installed | grep -E "uhttpd|ucode") | head
	ldd /usr/lib/uhttpd_ucode.so 2>&1 | head
fi
echo "LuCI ready"
