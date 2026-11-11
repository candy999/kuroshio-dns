#!/bin/sh
# =====================================================================
#  kuroshio — 來源 IP 存取控制的核心層丟棄（nftables / fw4，規格 08）
#    access.sh apply    依設定產生集合與 WAN 輸入規則（fw4 include），有變動才重新載入防火牆
#    access.sh remove   移除，重新載入防火牆
#
#  - 集合放 table-pre、規則放 WAN 區域輸入鏈（input_<wan_zone>）的開頭：只影響從 WAN 連進來的封包，
#    而且只針對黑潮 DNS 的加密監聽埠（DoT / DoQ / DoH / DoH3）；區網、LuCI（22 / 80 / 443）都不受影響
#  - 內容由 kuroshio access nft 產生（跟程式裡的判斷用同一份資料與設定）
#  - 檔案內容沒變就不寫（保護 Flash），也不重新載入防火牆
#  - 防火牆檢查失敗（例如語法不被這版 nftables 接受）就移除，絕不讓整個防火牆載入失敗
# =====================================================================

BIN=${KUROSHIO_BIN:-/usr/bin/kuroshio}
NFTD=${KUROSHIO_NFTD:-/usr/share/nftables.d}
SETS=$NFTD/table-pre/30-kuroshio-access.nft
NAME=30-kuroshio-access.nft
RUN=${KUROSHIO_RUN:-/var/run/kuroshio}

wan_zone() {
	local z
	z=$(uci -q get kuroshio.main.wan_zone)
	echo "${z:-wan}"
}

# 核心可以操作 nftables 時才檢查 / 重新載入（容器、測試環境沒有權限就只寫檔案）
nft_ok() { nft list tables >/dev/null 2>&1; }

reload_fw() {
	nft_ok || return 0
	/etc/init.d/firewall reload >/dev/null 2>&1
}

remove_files() { # 回傳 0 = 有刪掉東西
	local f removed=1
	for f in "$SETS" "$NFTD"/chain-pre/input_*/"$NAME"; do
		[ -e "$f" ] || continue
		rm -f "$f"
		removed=0
	done
	return $removed
}

# 內容不同才換上（回傳 0 = 有變動）
install_if_changed() { # install_if_changed <暫存檔> <目的地>
	if [ -f "$2" ] && cmp -s "$1" "$2"; then
		rm -f "$1"
		return 1
	fi
	mkdir -p "${2%/*}"
	mv -f "$1" "$2"
	return 0
}

apply() {
	local f rules tmp_s tmp_r changed=1
	rules="$NFTD/chain-pre/input_$(wan_zone)/$NAME"
	mkdir -p "$RUN"
	tmp_s="$RUN/access-sets.nft"
	tmp_r="$RUN/access-rules.nft"
	[ -f "$RUN/uci.json" ] && export KUROSHIO_UCI_JSON="$RUN/uci.json"
	if ! KUROSHIO_ETC=${KUROSHIO_ETC:-/etc/kuroshio} KUROSHIO_SHARE=${KUROSHIO_SHARE:-/usr/share/kuroshio} "$BIN" access nft --uci --sets "$tmp_s" --rules "$tmp_r" >/dev/null 2>"$RUN/access-err.txt"; then
		logger -t kuroshio "存取控制：產生 nftables 規則失敗：$(tail -n 1 "$RUN/access-err.txt")"
		rm -f "$tmp_s" "$tmp_r"
		remove_files && reload_fw
		return 0
	fi
	if [ ! -s "$tmp_s" ]; then
		rm -f "$tmp_s" "$tmp_r"
		remove_files && reload_fw
		return 0
	fi
	# WAN 區域改名過：移除舊區域鏈裡的規則
	for f in "$NFTD"/chain-pre/input_*/"$NAME"; do
		[ -e "$f" ] && [ "$f" != "$rules" ] && rm -f "$f" && changed=0
	done
	install_if_changed "$tmp_s" "$SETS" && changed=0
	install_if_changed "$tmp_r" "$rules" && changed=0
	[ "$changed" = 0 ] || return 0
	if nft_ok && ! fw4 -q check >/dev/null 2>&1; then
		logger -t kuroshio "存取控制：防火牆檢查失敗，移除核心層規則（程式內的過濾照常）"
		remove_files
	fi
	reload_fw
}

case "$1" in
apply) apply ;;
remove) remove_files && reload_fw ;;
*) echo "用法：$0 apply|remove" >&2; exit 1 ;;
esac
exit 0
