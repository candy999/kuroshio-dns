#!/bin/sh
# =====================================================================
#  kuroshio — DNS 接管與防火牆
#    takeover.sh apply    依 /etc/config/kuroshio 設定 dnsmasq 與防火牆
#    takeover.sh revert   還原成安裝前的 dnsmasq 設定、移除防火牆規則
#
#  接管模式（kuroshio.main.redirect）：
#    none              不動 dnsmasq，自己把裝置的 DNS 指到 路由器:dns_port
#    dnsmasq-upstream  dnsmasq 照常佔 53 埠，查詢轉給本程式（保留 DHCP 主機名稱，最安全）
#    redirect          重定向（基本）：一條防火牆規則把區網送往 53 埠的查詢轉到本程式，不分 IPv4 / IPv6、不指定目的位址
#    hijack            積極劫持：IPv4 / IPv6 分開，IPv4 導向區網 IP、IPv6 導向 ULA（有 IPv6 但沒有 ULA 就建立），
#                      DHCP 也發路由器當 DNS（IPv4 選項 6、IPv6 發 ULA）
#    exchange          本程式佔 53 埠，dnsmasq 改到 exchange_port 只負責 DHCP 與區網主機名稱
#
#  每次 apply 都先回到原始狀態再套用，切換模式不會留下舊設定；設定沒變就不重啟 dnsmasq / 防火牆。
# =====================================================================

BACKUP=/etc/kuroshio/.dnsmasq-backup
APPLIED=/etc/kuroshio/.applied      # 上次實際加進 dnsmasq 的內容，下次才能精確移除
DNSMASQ='dhcp.@dnsmasq[0]'

get() { uci -q get "kuroshio.$1"; }
# shellcheck source=lan.sh
. /usr/libexec/kuroshio/lan.sh
bool() { case "$1" in 1|on|true|yes|enabled) return 0 ;; esac; return 1; }

# 清單裡還沒有才加入，並記下來；還原時只移除自己加的（使用者原本就設定的值不會被刪掉）
add_list_once() { # add_list_once <uci 路徑> <值> <記錄名稱>
	uci -q get "$1" | tr ' ' '\n' | grep -qxF "$2" && return 0
	uci add_list "$1=$2"
	echo "$3=$2" >> "$APPLIED"
}

save_backup() {
	[ -f "$BACKUP" ] && return
	mkdir -p "${BACKUP%/*}"
	{
		echo "noresolv=$(uci -q get "$DNSMASQ".noresolv)"
		echo "cachesize=$(uci -q get "$DNSMASQ".cachesize)"
		echo "port=$(uci -q get "$DNSMASQ".port)"
		echo "dns_service=$(uci -q get dhcp.lan.dns_service)"
	} > "$BACKUP"
}

restore_opt() { # restore_opt <uci 路徑> <備份欄位>
	local v
	v=$(sed -n "s/^$2=//p" "$BACKUP" 2>/dev/null)
	if [ -n "$v" ]; then uci set "$1=$v"; else uci -q delete "$1"; fi
}

# 回到安裝前的 dnsmasq 設定（只改 uci，還沒 commit）
reset_dnsmasq() {
	local k v
	[ -f "$APPLIED" ] && while IFS='=' read -r k v; do
		case "$k" in
		server) uci -q del_list "$DNSMASQ.server=$v" ;;
		dhcp_option) uci -q del_list "dhcp.lan.dhcp_option=$v" ;;
		dhcp_dns) uci -q del_list "dhcp.lan.dns=$v" ;;
		esac
	done < "$APPLIED"
	rm -f "$APPLIED"
	[ -f "$BACKUP" ] || return 0
	restore_opt "$DNSMASQ".noresolv noresolv
	restore_opt "$DNSMASQ".cachesize cachesize
	restore_opt "$DNSMASQ".port port
	restore_opt dhcp.lan.dns_service dns_service
}

reset_firewall() {
	local s
	for s in kuroshio_dns kuroshio_dns6 kuroshio_doh kuroshio_dot kuroshio_doq; do
		uci -q delete "firewall.$s"
	done
}

commit_if_changed() { # commit_if_changed <config> <重啟指令…>
	local conf="$1"
	shift
	[ -n "$(uci -q changes "$conf")" ] || return 0
	uci commit "$conf"
	"$@"
}

# 下面兩個由 commit_if_changed 間接呼叫
# shellcheck disable=SC2329
restart_dhcp() {
	/etc/init.d/dnsmasq restart >/dev/null 2>&1
	/etc/init.d/odhcpd restart >/dev/null 2>&1
}

# shellcheck disable=SC2329
reload_fw() { /etc/init.d/firewall reload >/dev/null 2>&1; }

apply() {
	local mode port xport v6 ip ula lan wan
	mode=$(get main.redirect)
	port=$(get main.dns_port)
	xport=$(get main.exchange_port)
	lan=$(get main.lan_zone)
	wan=$(get main.wan_zone)
	v6=$(get main.listen_ipv6)
	ip=$(lan_ip4)
	ula=$(lan_ula6)
	: "${mode:=dnsmasq-upstream}" "${port:=5335}" "${xport:=5354}" "${lan:=lan}" "${wan:=wan}" "${v6:=1}"

	local old_mode
	old_mode=$(sed -n 's/^mode=//p' "$APPLIED" 2>/dev/null)
	save_backup
	reset_dnsmasq
	reset_firewall
	echo "mode=$mode" > "$APPLIED"
	# 從 exchange 換到其他模式：dnsmasq 要拿回 53 埠，先停掉還佔著 53 埠的舊程式（procd 隨後會用新設定啟動）
	if [ "$old_mode" = exchange ] && [ "$mode" != exchange ]; then
		ubus call service delete '{"name":"kuroshio"}' >/dev/null 2>&1
		sleep 1
	fi

	case "$mode" in
	dnsmasq-upstream)
		add_list_once "$DNSMASQ.server" "127.0.0.1#$port" server
		uci set "$DNSMASQ".noresolv='1'
		# 快取與預取交給本程式；dnsmasq 再快取一層會讓 TTL 10 的「先回快速答案」失效、統計也不準
		uci set "$DNSMASQ".cachesize='0'
		;;
	redirect)
		# 基本版：原本的單一規則，交給防火牆自己決定導向路由器的哪個位址
		uci set firewall.kuroshio_dns=redirect
		uci set firewall.kuroshio_dns.name='kuroshio: DNS 重定向'
		uci set firewall.kuroshio_dns.src="$lan"
		uci set firewall.kuroshio_dns.proto='tcp udp'
		uci set firewall.kuroshio_dns.src_dport='53'
		uci set firewall.kuroshio_dns.dest_port="$port"
		uci set firewall.kuroshio_dns.target='DNAT'
		;;
	hijack)
		# 積極劫持：區網裝置送往任何 DNS 的 53 埠查詢都轉到本程式。
		# IPv4 導向區網 IP；IPv6 導向路由器的 ULA（fd00::/8），不用 2001: 公網位址（ISP 換前綴就失效）
		if [ -n "$ip" ]; then
			uci set firewall.kuroshio_dns=redirect
			uci set firewall.kuroshio_dns.name='kuroshio: DNS 劫持 IPv4'
			uci set firewall.kuroshio_dns.family='ipv4'
			uci set firewall.kuroshio_dns.src="$lan"
			uci set firewall.kuroshio_dns.proto='tcp udp'
			uci set firewall.kuroshio_dns.src_dport='53'
			uci set firewall.kuroshio_dns.dest_ip="$ip"
			uci set firewall.kuroshio_dns.dest_port="$port"
			uci set firewall.kuroshio_dns.target='DNAT'
			add_list_once dhcp.lan.dhcp_option "6,$ip" dhcp_option
		else
			logger -t kuroshio "找不到區網 IPv4 位址，沒有建立 IPv4 DNS 劫持"
		fi
		if bool "$v6" && has_ipv6; then
			ensure_ula
			_LAN_JSON=
			ula=$(lan_ula6)
		fi
		if bool "$v6" && [ -n "$ula" ]; then
			uci set firewall.kuroshio_dns6=redirect
			uci set firewall.kuroshio_dns6.name='kuroshio: DNS 劫持 IPv6'
			uci set firewall.kuroshio_dns6.family='ipv6'
			uci set firewall.kuroshio_dns6.src="$lan"
			uci set firewall.kuroshio_dns6.proto='tcp udp'
			uci set firewall.kuroshio_dns6.src_dport='53'
			uci set firewall.kuroshio_dns6.dest_ip="$ula"
			uci set firewall.kuroshio_dns6.dest_port="$port"
			uci set firewall.kuroshio_dns6.target='DNAT'
			add_list_once dhcp.lan.dns "$ula" dhcp_dns
		fi
		;;
	exchange)
		# dnsmasq 讓出 53 埠，只負責 DHCP 與區網主機名稱（本程式把 .lan 與私有 IP 反查轉給它）；
		# noresolv 且不設上游，dnsmasq 不會把查詢再轉回來，不會形成迴圈
		uci set "$DNSMASQ".port="$xport"
		uci set "$DNSMASQ".noresolv='1'
		# dnsmasq 不在 53 埠就不會把自己當 DNS 發給裝置，要明確指定：
		# IPv4 用 DHCP 選項 6；IPv6 用 odhcpd 的 dns 清單，填路由器的 ULA（不用公網位址）
		[ -n "$ip" ] && add_list_once dhcp.lan.dhcp_option "6,$ip" dhcp_option
		if bool "$v6" && [ -n "$ula" ]; then
			add_list_once dhcp.lan.dns "$ula" dhcp_dns
		else
			# 本程式沒聽 IPv6（或沒有 ULA）：叫 odhcpd 不要發 IPv6 DNS，裝置改用 IPv4 查詢
			uci set dhcp.lan.dns_service='0'
		fi
		;;
	esac

	# WAN：讓外面的親友用 DoH / DoT / DoQ / DoH3（QUIC 走 UDP，同埠號）
	local doh_on doh_port doh_wan dot_on dot_port doq_on doq_port doh_proto=tcp dot_proto=tcp
	doh_on=$(get doh.enabled); doh_port=$(get doh.port); doh_wan=$(get doh.wan_port)
	dot_on=$(get dot.enabled); dot_port=$(get dot.port)
	doq_on=$(get doq.enabled); doq_port=$(get doq.port)
	: "${doh_port:=8443}" "${doh_wan:=443}" "${dot_port:=853}" "${doq_port:=853}"
	bool "$(get doh.http3)" && doh_proto='tcp udp'
	if bool "$doh_on" && bool "$(get doh.open_wan)"; then
		if [ "$doh_wan" = "$doh_port" ]; then
			uci set firewall.kuroshio_doh=rule
			uci set firewall.kuroshio_doh.dest_port="$doh_port"
			uci set firewall.kuroshio_doh.target='ACCEPT'
		else
			# LuCI（uhttpd）通常佔用 443，DoH 聽其他埠，由防火牆把 WAN 的 443 轉過來
			uci set firewall.kuroshio_doh=redirect
			uci set firewall.kuroshio_doh.src_dport="$doh_wan"
			uci set firewall.kuroshio_doh.dest_port="$doh_port"
			uci set firewall.kuroshio_doh.target='DNAT'
		fi
		uci set firewall.kuroshio_doh.name='kuroshio: DoH'
		uci set firewall.kuroshio_doh.src="$wan"
		uci set firewall.kuroshio_doh.proto="$doh_proto"
	fi
	# DoQ 跟 DoT 同埠號時合成一條規則；DoQ 沿用 DoT 的「開放外網」開關
	if bool "$doq_on" && [ "$doq_port" = "$dot_port" ]; then dot_proto='tcp udp'; fi
	if bool "$dot_on" && bool "$(get dot.open_wan)"; then
		uci set firewall.kuroshio_dot=rule
		uci set firewall.kuroshio_dot.name='kuroshio: DoT / DoQ'
		uci set firewall.kuroshio_dot.src="$wan"
		uci set firewall.kuroshio_dot.proto="$dot_proto"
		uci set firewall.kuroshio_dot.dest_port="$dot_port"
		uci set firewall.kuroshio_dot.target='ACCEPT'
		if bool "$doq_on" && [ "$doq_port" != "$dot_port" ]; then
			uci set firewall.kuroshio_doq=rule
			uci set firewall.kuroshio_doq.name='kuroshio: DoQ'
			uci set firewall.kuroshio_doq.src="$wan"
			uci set firewall.kuroshio_doq.proto='udp'
			uci set firewall.kuroshio_doq.dest_port="$doq_port"
			uci set firewall.kuroshio_doq.target='ACCEPT'
		fi
	fi

	commit_if_changed dhcp restart_dhcp
	commit_if_changed firewall reload_fw
}

revert() {
	reset_dnsmasq
	reset_firewall
	commit_if_changed dhcp restart_dhcp
	commit_if_changed firewall reload_fw
}

case "$1" in
apply) apply ;;
revert) revert ;;
*) echo "用法：$0 apply|revert" >&2; exit 1 ;;
esac
# 設定已經寫入；dnsmasq / 防火牆重新載入失敗不算這個腳本失敗（init 腳本才不會因此中止）
exit 0
