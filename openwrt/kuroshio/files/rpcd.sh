#!/bin/sh
# =====================================================================
#  kuroshio — rpcd 外掛（LuCI 透過 ubus 呼叫 kuroshio.*）
#  轉送到本機管理 API（127.0.0.1:admin_port），只開放白名單內的路徑。
#    status        執行狀態＋/api/status
#    api           查看類 API（追蹤、規則檢查、上游、節點池…）
#    action        會改變狀態的 API（清快取、更新清單、執行工作、驗證…）     ← ACL 寫入權限
#    defaults      內建預設值（kuroshio defaults --json，LuCI 顯示成提示文字）
#    acme_status   憑證資訊與申請紀錄
#    acme_issue    背景申請憑證                                          ← ACL 寫入權限
#    log           最近的執行紀錄
#    dnr           DNR 會發布什麼、沒發的原因（kuroshio dnr；區網位址在這裡自己取，不收參數）
#    backup_export 匯出學習資料到 /tmp/kuroshio-backup.kuroshio（LuCI 再下載）  ← ACL 寫入權限
#    backup_import 匯入 LuCI 上傳的 /tmp/kuroshio-import.kuroshio（合併）       ← ACL 寫入權限
# =====================================================================
. /usr/share/libubox/jshn.sh


# 埠號只接受數字（設定值會接進網址，不能讓它變成別台主機）
port() {
	p=$(uci -q get kuroshio.main.admin_port)
	case "$p" in ''|*[!0-9]*) p=8054 ;; esac
	echo "$p"
}

# 呼叫管理 API，輸出包成 {"result":…}（rpcd 只接受物件）
# 會改變狀態的動作用 POST（管理 API 不接受用 GET 做這些事，網頁才沒辦法用一張圖片的網址偷偷觸發）；
# 參數仍然放在網址，--post-data 只是讓 uclient-fetch 改用 POST（內容不能是空的）
fetch() { # fetch <path> [query] [post]
	local url
	url="http://127.0.0.1:$(port)$1"
	[ -n "$2" ] && url="$url?$2"
	local body
	if [ "$3" = post ]; then
		body=$(uclient-fetch -q -T 60 --post-data="${2:-_}" -O - "$url" 2>/dev/null)
	else
		body=$(uclient-fetch -q -T 60 -O - "$url" 2>/dev/null)
	fi
	if [ -n "$body" ]; then printf '{"ok":true,"result":%s}' "$body"
	else printf '{"ok":false,"error":"服務沒有回應（可能尚未啟動）"}'; fi
}

valid_query() { case "$1" in *[!A-Za-z0-9._=\&%:-]*) return 1 ;; esac; return 0; }

read_input() {
	local input
	read -r input
	json_load "$input" 2>/dev/null
	json_get_var P_PATH path
	json_get_var P_QUERY query
	json_get_var P_LINES lines
	json_get_var P_KIND kind
}

BACKUP_OUT=/tmp/kuroshio-backup.kuroshio
BACKUP_IN=/tmp/kuroshio-import.kuroshio

case "$1" in
list)
	cat <<-'EOF'
	{"status":{},"api":{"path":"str","query":"str"},"action":{"path":"str","query":"str"},"defaults":{},"acme_status":{},"acme_issue":{},"log":{"lines":64},"about":{},"backup_export":{"kind":"str"},"backup_import":{},"dnr":{}}
	EOF
	;;
call)
	case "$2" in
	status)
		running=false
		ubus call service list '{"name":"kuroshio"}' 2>/dev/null | grep -q '"running": true' && running=true
		if [ "$running" = true ]; then
			printf '{"running":true,"api":%s}' "$(fetch /api/status lite=1)"
		else
			printf '{"running":false}'
		fi
		;;
	api)
		read_input
		case "$P_PATH" in
		/api/status|/api/access|/api/sysinfo|/api/upstreams|/api/benchmark|/api/cdn/pools|/api/cdn/v6nodes|/api/cdn/summary|/api/cdn/domains|/api/jobs|/api/trace|/api/filter/check|/api/routing|/api/ddns|/api/paths|/api/interfaces) ;;
		/api/community/status|/api/community/peers|/api/community/events|/api/community/invite) ;;
		*) echo '{"ok":false,"error":"不允許的路徑"}'; exit 0 ;;
		esac
		valid_query "$P_QUERY" || { echo '{"ok":false,"error":"參數格式錯誤"}'; exit 0; }
		fetch "$P_PATH" "$P_QUERY"
		;;
	action)
		read_input
		case "$P_PATH" in
		/api/cache/flush|/api/filter/update|/api/jobs/run|/api/cdn/verify|/api/cdn/policy|/api/cdn/ecs|/api/ddns/update) ;;
		/api/community/check|/api/community/add|/api/community/accept|/api/community/reject|/api/community/block|/api/community/unblock|/api/community/delete|/api/community/sync) ;;
		/api/community/invite/refresh|/api/community/invite/use) ;;
		/api/community/rotate|/api/community/accept-key|/api/community/channel) ;;
		*) echo '{"ok":false,"error":"不允許的路徑"}'; exit 0 ;;
		esac
		valid_query "$P_QUERY" || { echo '{"ok":false,"error":"參數格式錯誤"}'; exit 0; }
		fetch "$P_PATH" "$P_QUERY" post
		;;
	about)
		# 核心版本、授權、原始碼（含 QR 碼）＋ LuCI 介面版本
		ui=$(cat /usr/share/luci-app-kuroshio/version 2>/dev/null)
		core=$(/usr/bin/kuroshio about --uci --qr 2>/dev/null || echo null)
		printf '{"core":%s,"ui":"%s"}' "$core" "${ui:-unknown}"
		;;
	defaults)
		printf '{"result":%s}' "$(/usr/bin/kuroshio defaults --json 2>/dev/null || echo null)"
		;;
	acme_status)
		/usr/libexec/kuroshio/acme.sh status
		;;
	acme_issue)
		/usr/libexec/kuroshio/acme.sh issue-bg
		;;
	backup_export)
		# 完整備份（預設）或分享檔；完整備份含社群私鑰，檔案只有 root 能讀，LuCI 下載後會刪掉
		read_input
		kind=full
		if [ "$P_KIND" = share ]; then kind=share; set -- --share; else set --; fi
		# /tmp 是大家都能寫的資料夾：先寫到 mktemp 建的檔案（只有 root 能讀寫、別人換不掉），再改名成固定的檔名。
		# 直接寫固定檔名的話，別的帳號可以先在那裡放一個自己的檔案或符號連結，備份（含私鑰）就會寫到他手上
		rm -rf "$BACKUP_OUT"
		tmp=$(umask 077; mktemp /tmp/kuroshio-backup.XXXXXX) || tmp=
		json_init
		# shellcheck disable=SC3067 # test -O（檔案是我的）不在 POSIX 裡，BusyBox ash 有
		if [ -n "$tmp" ] && msg=$(umask 077; /usr/bin/kuroshio export --uci "$@" -o "$tmp" 2>&1) && [ -s "$tmp" ] \
			&& mv -f "$tmp" "$BACKUP_OUT" && [ -f "$BACKUP_OUT" ] && [ ! -L "$BACKUP_OUT" ] && [ -O "$BACKUP_OUT" ]; then
			json_add_boolean ok 1
			json_add_int size "$(wc -c < "$BACKUP_OUT" | tr -d ' ')"
			json_add_string name "kuroshio-$kind-$(date +%Y%m%d).kuroshio"
			json_add_string path "$BACKUP_OUT"
		else
			[ -n "$tmp" ] && rm -f "$tmp"
			rm -rf "$BACKUP_OUT"
			json_add_boolean ok 0
			json_add_string error "${msg:-匯出失敗}"
		fi
		json_dump
		;;
	backup_import)
		# 服務執行中：交給服務、等它重新啟動合併；沒有執行：直接合併。輸出合併結果（JSON）
		if [ ! -s "$BACKUP_IN" ]; then
			echo '{"ok":false,"error":"沒有收到檔案"}'
			exit 0
		fi
		# 只收 LuCI（root）上傳的一般檔案：別的帳號先在 /tmp 放好的檔案或符號連結不匯入
		# shellcheck disable=SC3067
		if [ -L "$BACKUP_IN" ] || [ ! -f "$BACKUP_IN" ] || [ ! -O "$BACKUP_IN" ]; then
			rm -f "$BACKUP_IN"
			echo '{"ok":false,"error":"上傳的檔案不是 LuCI 建立的，沒有匯入"}'
			exit 0
		fi
		out=$(/usr/bin/kuroshio import --uci --json "$BACKUP_IN" 2>/dev/null)
		rm -f "$BACKUP_IN"
		case "$out" in
		'{'*) printf '%s' "$out" ;;
		*) echo '{"ok":false,"error":"kuroshio 沒有回應"}' ;;
		esac
		;;
	dnr)
		# 區網位址從 netifd / UCI 取得（跟 takeover.sh 發布時一樣），不接受呼叫端給的參數；
		# 只把 IP 用得到的字元交給 kuroshio，再確認輸出是 JSON 物件
		# shellcheck source=lan.sh
		. /usr/libexec/kuroshio/lan.sh
		lan=$(printf '%s,%s' "$(lan_ip4)" "$(lan_ula6)" | sed 's/^,//; s/,$//')
		case "$lan" in
		''|*[!0-9A-Fa-f.:,]*) echo '{"ok":false,"error":"讀不到路由器的區網位址"}'; exit 0 ;;
		esac
		out=$(/usr/bin/kuroshio dnr --uci --lan "$lan" 2>/dev/null)
		case "$out" in
		'{'*) printf '%s' "$out" ;;
		*) echo '{"ok":false,"error":"kuroshio 沒有回應"}' ;;
		esac
		;;
	log)
		read_input
		n=${P_LINES:-200}
		case "$n" in *[!0-9]*) n=200 ;; esac
		tmp=$(mktemp)
		logread -e 'kuroshio' 2>/dev/null | tail -n "$n" > "$tmp"
		json_init
		json_add_array lines
		while IFS= read -r line; do
			json_add_string "" "$line"
		done < "$tmp"
		json_close_array
		rm -f "$tmp"
		json_dump
		;;
	esac
	;;
esac
