#!/bin/sh
# =====================================================================
#  CI：在官方 OpenWrt rootfs 容器裡安裝黑潮 DNS 3.0 套件並實際測試
#    docker run -v $PWD:/src -v $PWD/pkgs:/pkgs openwrt/rootfs:x86_64-openwrt-24.10 /src/openwrt/tools/ci-smoke-kuroshio.sh
#  容器裡沒有 procd，所以手動啟動 ubusd / rpcd，服務本身也直接執行。
# =====================================================================
set -e
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "  ✔ $1"; }
bad() { FAIL=$((FAIL + 1)); echo "  ✘ $1"; }
check() { # check <說明> <指令…>
	local msg=$1
	shift
	local out
	if out=$("$@" 2>&1); then ok "$msg"; else bad "$msg：$(echo "$out" | tail -n 2)"; fi
}
eq() { # eq <說明> <實際> <預期>
	if [ "$2" = "$3" ]; then ok "$1"; else bad "$1（實際：'$2'，預期：'$3'）"; fi
}

mkdir -p /var/lock /var/run /tmp/lock

echo "== 安裝套件（不需要 node）"
if command -v apk >/dev/null 2>&1; then
	apk update >/dev/null
	apk add --allow-untrusted /pkgs/kuroshio-[0-9]*.apk || exit 1
else
	opkg update >/dev/null
	opkg install /pkgs/kuroshio_*.ipk || exit 1
fi

echo "== 安裝結果"
check "執行檔" test -x /usr/bin/kuroshio
check "版本" /usr/bin/kuroshio --version
check "沒有 node 也能裝" sh -c '! command -v node'
check "依賴 acme.sh 已自動安裝" test -x /usr/lib/acme/client/acme.sh
check "預設設定檔" test -f /etc/config/kuroshio
check "種子資料已打包" test -f /usr/share/kuroshio/seed/meta.json
check "CDN 官方範圍已打包" test -d /usr/share/kuroshio/cdn
sh /etc/uci-defaults/90-kuroshio 2>/dev/null || true
eq "uci-defaults 補齊區段" "$(uci -q get kuroshio.system)" "system"
eq "預設不啟用" "$(uci -q get kuroshio.main.enabled)" "0"
eq "預設不帶入任何網域" "$(uci -q get kuroshio.tls.domain)" ""
check "自訂規則已放好" test -s /etc/kuroshio/custom-rules.txt
check "自己的評測名單已放好" test -s /etc/kuroshio/benchmark/iplist.txt
check "程式附帶的預設名單（含 DoT）" test -s /usr/share/kuroshio/benchmark/dotlist.txt
check "預設值不帶個人網域" sh -c '! /usr/bin/kuroshio defaults | grep -q candy.moe'
ubus call uci get '{"config":"kuroshio"}' > /tmp/uci.json 2>/dev/null || true
check "UCI 轉換：dnsmasq 上游模式聽 5335" sh -c 'KUROSHIO_UCI_JSON=/tmp/uci.json /usr/bin/kuroshio check-config --uci | grep -q 5335 || /usr/bin/kuroshio check-config --uci | grep -q 5335'
check "硬體等級偵測" sh -c '/usr/bin/kuroshio sysinfo --uci | grep -q 硬體等級'
/usr/bin/kuroshio sysinfo --uci

echo "== DNS 接管（takeover.sh）"
T=/usr/libexec/kuroshio/takeover.sh
# Docker 版 rootfs 沒有開機流程產生的 network / dhcp 設定，補上最基本的內容
touch /etc/config/network /etc/config/dhcp /etc/config/firewall
uci -q get dhcp.@dnsmasq[0] >/dev/null || { uci add dhcp dnsmasq >/dev/null; uci set dhcp.@dnsmasq[0].domain='lan'; }
uci -q get dhcp.lan >/dev/null || { uci set dhcp.lan=dhcp; uci set dhcp.lan.interface='lan'; }
uci commit dhcp
uci set network.lan=interface
uci set network.lan.ipaddr='192.168.1.1'
uci set network.globals=globals
uci set network.globals.ula_prefix='fdab:cd12:3456::/48'
uci commit network
# 模擬使用者原本就設定好的 DHCP：IPv4 選項 6 已經指向路由器（還原時不能被刪掉）
uci add_list dhcp.lan.dhcp_option='6,192.168.1.1'
uci commit dhcp
uci export dhcp > /tmp/dhcp.before
uci export firewall > /tmp/fw.before

uci set kuroshio.main.redirect='dnsmasq-upstream'
# 預設 DoH / DoT 不開；這裡打開並開放外網，測試防火牆規則
uci set kuroshio.doh.enabled='1'
uci set kuroshio.doh.open_wan='1'
uci set kuroshio.dot.enabled='1'
uci set kuroshio.dot.open_wan='1'
uci set kuroshio.doq.enabled='1'
uci set kuroshio.doh.http3='1'
uci commit kuroshio
$T apply
eq "upstream：dnsmasq 轉給 127.0.0.1#5335" "$(uci -q get dhcp.@dnsmasq[0].server)" "127.0.0.1#5335"
eq "upstream：noresolv" "$(uci -q get dhcp.@dnsmasq[0].noresolv)" "1"
eq "upstream：dnsmasq 不快取" "$(uci -q get dhcp.@dnsmasq[0].cachesize)" "0"
eq "WAN DoH：443 → 8443" "$(uci -q get firewall.kuroshio_doh.src_dport)>$(uci -q get firewall.kuroshio_doh.dest_port)" "443>8443"
eq "WAN DoT：開放 853" "$(uci -q get firewall.kuroshio_dot.dest_port)" "853"
eq "WAN DoT / DoQ 同埠：TCP + UDP" "$(uci -q get firewall.kuroshio_dot.proto)" "tcp udp"
eq "WAN DoH + DoH3：TCP + UDP" "$(uci -q get firewall.kuroshio_doh.proto)" "tcp udp"

uci set kuroshio.main.dns_port='6053'
uci set kuroshio.main.redirect='redirect'
uci commit kuroshio
$T apply
eq "redirect：移除舊的 dnsmasq 上游" "$(uci -q get dhcp.@dnsmasq[0].server)" ""
eq "redirect：dnsmasq 快取還原" "$(uci -q get dhcp.@dnsmasq[0].cachesize)" "$(sed -n 's/^cachesize=//p' /etc/kuroshio/.dnsmasq-backup)"
eq "redirect（基本）：單一規則、不分 IPv4/IPv6、不指定目的位址" "$(uci -q get firewall.kuroshio_dns.family)|$(uci -q get firewall.kuroshio_dns.dest_ip)|$(uci -q get firewall.kuroshio_dns.src_dport)>$(uci -q get firewall.kuroshio_dns.dest_port)|$(uci -q get firewall.kuroshio_dns6)" "||53>6053|"
eq "redirect（基本）：不動 DHCP" "$(uci -q get dhcp.lan.dns)" ""

uci set kuroshio.main.redirect='hijack'
uci commit kuroshio
$T apply
eq "hijack：IPv4 53 → 192.168.1.1:6053" "$(uci -q get firewall.kuroshio_dns.family) $(uci -q get firewall.kuroshio_dns.src_dport)>$(uci -q get firewall.kuroshio_dns.dest_ip):$(uci -q get firewall.kuroshio_dns.dest_port)" "ipv4 53>192.168.1.1:6053"
eq "hijack：IPv6 53 → ULA fdab:cd12:3456::1:6053" "$(uci -q get firewall.kuroshio_dns6.family) $(uci -q get firewall.kuroshio_dns6.src_dport)>$(uci -q get firewall.kuroshio_dns6.dest_ip):$(uci -q get firewall.kuroshio_dns6.dest_port)" "ipv6 53>fdab:cd12:3456::1:6053"
eq "hijack：來源區域 lan" "$(uci -q get firewall.kuroshio_dns.src)/$(uci -q get firewall.kuroshio_dns6.src)" "lan/lan"
eq "hijack：IPv4 DHCP 選項 6（原本就有，不重複加）" "$(uci -q get dhcp.lan.dhcp_option)" "6,192.168.1.1"
eq "hijack：IPv6 DNS 發 ULA" "$(uci -q get dhcp.lan.dns)" "fdab:cd12:3456::1"

uci set kuroshio.main.redirect='exchange'
uci commit kuroshio
$T apply
eq "exchange：dnsmasq 改聽 5354" "$(uci -q get dhcp.@dnsmasq[0].port)" "5354"
eq "exchange：IPv4 DHCP 選項 6（原本就有，不重複加）" "$(uci -q get dhcp.lan.dhcp_option)" "6,192.168.1.1"
eq "exchange：IPv6 DNS 發 ULA" "$(uci -q get dhcp.lan.dns)" "fdab:cd12:3456::1"
eq "exchange：移除重定向規則" "$(uci -q get firewall.kuroshio_dns)$(uci -q get firewall.kuroshio_dns6)" ""

uci set kuroshio.main.listen_ipv6='0'
uci commit kuroshio
$T apply
eq "exchange 不聽 IPv6：移除 IPv6 DNS、關閉 odhcpd DNS 通告" "$(uci -q get dhcp.lan.dns)/$(uci -q get dhcp.lan.dns_service)" "/0"

uci set kuroshio.main.redirect='none'
uci set kuroshio.doh.open_wan='0'
uci commit kuroshio
$T apply
eq "none：dnsmasq 回到 53" "$(uci -q get dhcp.@dnsmasq[0].port)" ""
eq "none：保留使用者原本的 DHCP 選項" "$(uci -q get dhcp.lan.dhcp_option)" "6,192.168.1.1"
eq "關閉 WAN DoH 規則" "$(uci -q get firewall.kuroshio_doh)" ""

$T revert
uci export dhcp > /tmp/dhcp.after
uci export firewall > /tmp/fw.after
check "revert：dhcp 設定完全還原" cmp /tmp/dhcp.before /tmp/dhcp.after
check "revert：防火牆設定完全還原" cmp /tmp/fw.before /tmp/fw.after

echo "== 建立 ULA（ensure_ula）"
uci -q delete network.globals.ula_prefix || true
uci -q delete network.lan.ip6assign || true
uci commit network
( set +e; . /usr/libexec/kuroshio/lan.sh; ensure_ula )
NEW_ULA=$(uci -q get network.globals.ula_prefix)
echo "$NEW_ULA" | grep -qE '^fd[0-9a-f]{2}:[0-9a-f]{4}:[0-9a-f]{4}::/48$' && ok "沒有 ULA 時產生隨機 fdXX:XXXX:XXXX::/48（$NEW_ULA）" || bad "沒有 ULA 時產生隨機 ULA 前綴（$NEW_ULA）"
eq "lan 補上 ip6assign" "$(uci -q get network.lan.ip6assign)" "60"
( set +e; . /usr/libexec/kuroshio/lan.sh; ensure_ula )
eq "已有 ULA 前綴就不再改" "$(uci -q get network.globals.ula_prefix)" "$NEW_ULA"

echo "== rpcd / ubus"
ubusd &
sleep 1
rpcd &
sleep 2
check "ubus 上有 kuroshio 物件" sh -c "ubus list | grep -qx kuroshio"
ubus call kuroshio defaults | grep -q '"resolver"' && ok "kuroshio.defaults" || bad "kuroshio.defaults"
ubus call kuroshio status | grep -q '"running": false' && ok "kuroshio.status（未啟動）" || bad "kuroshio.status（未啟動）"
ubus call kuroshio api '{"path":"/etc/passwd"}' | grep -q '不允許' && ok "api 白名單擋下其他路徑" || bad "api 白名單擋下其他路徑"

echo "== 實際啟動服務"
uci set kuroshio.main.enabled='1'
uci set kuroshio.main.redirect='dnsmasq-upstream'
uci set kuroshio.main.dns_port='5335'
uci set kuroshio.doh.enabled='1'
uci set kuroshio.doh.http3='1'
uci set kuroshio.dot.enabled='1'
uci set kuroshio.doq.enabled='1'
uci set kuroshio.filter.enabled='0'
uci set kuroshio.system.profile='small'
# 測試憑證的網域是 localhost：DNR 需要網域與涵蓋它的有效憑證
uci set kuroshio.tls.domain='localhost'
uci commit kuroshio
mkdir -p /var/run/kuroshio
ubus call uci get '{"config":"kuroshio"}' > /var/run/kuroshio/uci.json
# 測試用自簽憑證（CI 在 runner 上用 openssl 產生，放在 /pkgs）
cp /pkgs/test-cert.pem /etc/kuroshio/cert.pem
cp /pkgs/test-key.pem /etc/kuroshio/key.pem
KUROSHIO_UCI_JSON=/var/run/kuroshio/uci.json KUROSHIO_ETC=/etc/kuroshio KUROSHIO_SHARE=/usr/share/kuroshio NO_COLOR=1 \
	/usr/bin/kuroshio run --uci > /tmp/kuroshio.log 2>&1 &
PID=$!
sleep 6
Q="/usr/bin/kuroshio query example.com --ca /pkgs/test-cert.pem"
check "區網 DNS 127.0.0.1:5335（UDP）" $Q -s 127.0.0.1:5335
check "區網 DNS 127.0.0.1:5335（TCP）" $Q -s tcp://127.0.0.1:5335
check "DoH 8443" $Q -s https://127.0.0.1:8443/dns-query
check "DoH3 8443（UDP）" $Q -s h3://127.0.0.1:8443/dns-query
check "DoT 853" $Q -s tls://127.0.0.1:853
check "DoQ 853（UDP）" $Q -s quic://127.0.0.1:853
check "快取命中" $Q -s 127.0.0.1:5335
ubus call kuroshio api '{"path":"/api/upstreams"}' | grep -q '"ok": true' && ok "rpcd → 管理 API" || bad "rpcd → 管理 API"
ubus call kuroshio api '{"path":"/api/trace","query":"name=example.com&type=A"}' | grep -q '"ok": true' && ok "網域追蹤" || bad "網域追蹤"
ubus call kuroshio api '{"path":"/api/sysinfo"}' | grep -q '"tier": "small"' && ok "硬體等級（UCI 指定）" || bad "硬體等級（UCI 指定）"
ubus call kuroshio defaults | grep -q '"resolver"' && ok "kuroshio.defaults（不用 node）" || bad "kuroshio.defaults（不用 node）"
ubus call kuroshio acme_status | grep -q '"daysLeft"' && ok "憑證狀態（不用 node）" || bad "憑證狀態（不用 node）"
# DNR（RFC 9463）：網域 + 有效憑證 + 加密監聽 → 用 DHCP 選項 162 通告
DNR=$(/usr/bin/kuroshio dnr --uci --lan 192.168.1.1)
[ "$(echo "$DNR" | jsonfilter -e '@.ok')" = true ] && ok "DNR：有網域與有效憑證時會發" || bad "DNR：沒有發（$DNR）"
$T apply
uci -q get dhcp.lan.dhcp_option | tr ' ' '\n' | grep -q '^162,' && ok "DNR：接管時寫入 DHCP 選項 162" || bad "DNR：沒有寫入 DHCP 選項 162"
$T revert
uci -q get dhcp.lan.dhcp_option | tr ' ' '\n' | grep -q '^162,' && bad "DNR：還原後應該移除選項 162" || ok "DNR：還原時移除選項 162"
# 備份與分享：匯出分享檔，再當成上傳的檔案匯入（服務在程式內重新啟動後合併）
ubus call kuroshio backup_export '{"kind":"share"}' | grep -q '"ok": true' && [ -s /tmp/kuroshio-backup.kuroshio ] && ok "備份：匯出分享檔" || bad "備份：匯出分享檔"
cp /tmp/kuroshio-backup.kuroshio /tmp/kuroshio-import.kuroshio 2>/dev/null
ubus -t 90 call kuroshio backup_import | grep -q '"ok": true' && ok "備份：匯入（重新啟動後合併）" || bad "備份：匯入"
[ ! -e /tmp/kuroshio-import.kuroshio ] && ok "備份：匯入後刪掉上傳的檔案" || bad "備份：匯入後刪掉上傳的檔案"
kill "$PID" 2>/dev/null
sleep 2
grep -q '結束' /tmp/kuroshio.log && ok "收到 SIGTERM 正常結束（寫出快照）" || bad "收到 SIGTERM 正常結束"

echo "== 服務日誌"
head -60 /tmp/kuroshio.log

echo
echo "結果：$PASS 通過、$FAIL 失敗"
[ "$FAIL" = 0 ]
