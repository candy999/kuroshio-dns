#!/bin/sh
# =====================================================================
#  kuroshio — 重新啟動期間的 DNS 備援（規格 09）
#
#  DNS 停了等於斷網。程式當掉時 procd 1 秒內重新啟動，通常裝置重送一次查詢就有答案；
#  但如果一直起不來（例如設定壞了、反覆當掉），區網會完全沒有 DNS。這個守護程式每秒看一次：
#    - 程式不在、或連續 3 次（約 3 秒）沒有回答 → 暫時還原 dnsmasq 的一般設定（takeover.sh revert）：
#      dnsmasq 直接用 WAN 的上游轉送，裝置一定有答案（這段期間沒有過濾、沒有 CDN 調整）
#    - 程式回來而且回答了 → 重新接管（takeover.sh apply）
#  只在 dnsmasq-upstream、redirect、hijack 模式有效；exchange 模式本程式自己佔 53 埠，
#  備援會跟它搶埠，所以不做（記在系統日誌）。
#  關掉：uci set kuroshio.main.restart_fallback=0
# =====================================================================

BIN=/usr/bin/kuroshio
T=/usr/libexec/kuroshio/takeover.sh

mode=$(uci -q get kuroshio.main.redirect)
: "${mode:=dnsmasq-upstream}"

case "$mode" in
dnsmasq-upstream | redirect | hijack) ;;
*)
	logger -t kuroshio "DNS 備援：$mode 模式不做備援（本程式佔 53 埠）"
	# 不結束：procd 會把結束的守護程式一直重啟
	exec sleep 2147483647
	;;
esac

# 本程式有沒有在回答（kuroshio health：對 127.0.0.1 的區網 DNS 埠問 _dns.resolver.arpa，由本程式自己回答，不經上游；
# 埠號跟 UCI 轉換一致：exchange 模式 53，其他 main.dns_port）
answering() {
	pidof kuroshio >/dev/null 2>&1 || return 1
	"$BIN" health --uci --timeout 800 >/dev/null 2>&1
}

fallback=0
bad=0
n=0
while :; do
	sleep 1
	n=$((n + 1))
	if ! pidof kuroshio >/dev/null 2>&1; then
		bad=$((bad + 1))
	elif [ "$fallback" = 1 ] || [ $((n % 10)) = 0 ]; then
		# 程式在：備援中每秒確認一次有沒有回答，平常每 10 秒
		if answering; then bad=0; else bad=$((bad + 1)); fi
	else
		bad=0
	fi
	if [ "$fallback" = 0 ] && [ "$bad" -ge 3 ]; then
		logger -t kuroshio "DNS 備援：本程式沒有回答，暫時由 dnsmasq 直接轉送（沒有過濾）"
		"$T" revert
		fallback=1
	elif [ "$fallback" = 1 ] && [ "$bad" = 0 ]; then
		logger -t kuroshio "DNS 備援：本程式恢復回答，重新接管 DNS"
		"$T" apply
		fallback=0
	fi
done
