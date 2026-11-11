#!/bin/sh
# =====================================================================
#  kuroshio — 取得區網介面的實際位址（takeover.sh 與 init 腳本共用）
#    lan_ip4    路由器的區網 IPv4，例如 10.0.0.1
#    lan_ula6   路由器的區網 ULA IPv6（fd00::/8），例如 fd00::1
#               不用 2001: 這類公網位址：ISP 換前綴就失效，而且導向公網位址的封包可能被丟棄
#    has_ipv6   這個環境有沒有 IPv6
#    ensure_ula 有 IPv6 但區網沒有 ULA 時建立
#  先問 netifd（ubus），容器或開機早期問不到時退回 /etc/config/network。
# =====================================================================

LAN_IFACE=${LAN_IFACE:-lan}

_lan_status() {
	[ -n "$_LAN_JSON" ] || _LAN_JSON=$(ubus call "network.interface.$LAN_IFACE" status 2>/dev/null)
	echo "$_LAN_JSON"
}

_jf() { _lan_status | jsonfilter -e "$1" 2>/dev/null; }

lan_ip4() {
	local ip
	ip=$(_jf '@["ipv4-address"][0].address')
	[ -n "$ip" ] || ip=$(uci -q get "network.$LAN_IFACE.ipaddr" | awk '{print $1}' | cut -d/ -f1)
	echo "$ip"
}

lan_ula6() {
	local a
	for a in $(_jf '@["ipv6-prefix-assignment"][*]["local-address"].address') $(_jf '@["ipv6-address"][*].address'); do
		case "$a" in f[cd]*) echo "$a"; return ;; esac
	done
	# 退回：ULA 前綴（例如 fd00::/48、fdab:cd::/48）的第一個位址，跟預設 ip6hint 0 的路由器位址一致
	a=$(uci -q get network.globals.ula_prefix | cut -d/ -f1)
	case "$a" in
	f[cd]*::) echo "${a}1" ;;
	f[cd]*) echo "$a" ;;
	esac
}

# 區網現在實際有沒有 ULA（只看 netifd 的即時狀態，不看設定檔）
lan_ula6_live() {
	local a
	for a in $(_jf '@["ipv6-prefix-assignment"][*]["local-address"].address') $(_jf '@["ipv6-address"][*].address'); do
		case "$a" in f[cd]*) echo "$a"; return ;; esac
	done
}

# 這個環境有沒有 IPv6：區網有配到前綴、或任何一個介面有 IPv6 位址 / 預設路由
has_ipv6() {
	[ -n "$(_jf '@["ipv6-prefix-assignment"][*].address')" ] && return 0
	ubus call network.interface dump 2>/dev/null |
		jsonfilter -e '@.interface[*]["ipv6-address"][*].address' -e '@.interface[*]["ipv6-prefix"][*].address' 2>/dev/null | grep -q . && return 0
	ip -6 route show default 2>/dev/null | grep -q . && return 0
	return 1
}

# 確保區網有 ULA：沒有 ULA 前綴就隨機產生一個 fdXX:XXXX:XXXX::/48（RFC 4193），lan 沒有 ip6assign 就補上，
# 重新載入網路後等 ULA 出現。停用服務時不會刪掉（刪掉會讓區網裝置的 fd 位址消失）
ensure_ula() {
	local pfx rnd _
	[ -n "$(lan_ula6_live)" ] && return 0
	pfx=$(uci -q get network.globals.ula_prefix)
	case "$pfx" in
	f[cd]*) ;;
	*)
		rnd=$(tr -dc 'a-f0-9' < /dev/urandom | head -c 10)
		pfx="fd$(echo "$rnd" | cut -c1-2):$(echo "$rnd" | cut -c3-6):$(echo "$rnd" | cut -c7-10)::/48"
		uci -q get network.globals >/dev/null || uci set network.globals=globals
		uci set network.globals.ula_prefix="$pfx"
		logger -t kuroshio "區網沒有 IPv6 ULA，建立 ULA 前綴 $pfx"
		echo "ula_prefix=$pfx" > /etc/kuroshio/.ula-created
		;;
	esac
	[ -n "$(uci -q get "network.$LAN_IFACE.ip6assign")" ] || uci set "network.$LAN_IFACE.ip6assign=60"
	[ -n "$(uci -q changes network)" ] || return 0
	uci commit network
	ubus call network reload >/dev/null 2>&1 || true
	_LAN_JSON=
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		[ -n "$(lan_ula6_live)" ] && return 0
		sleep 1
		_LAN_JSON=
	done
	return 0
}
