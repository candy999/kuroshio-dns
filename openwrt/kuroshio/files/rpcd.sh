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
#    backup_export 匯出學習資料到 /tmp/kuroshio-backup.kuroshio（LuCI 再下載）  ← ACL 寫入權限
#    backup_import 匯入 LuCI 上傳的 /tmp/kuroshio-import.kuroshio（合併）       ← ACL 寫入權限
# =====================================================================
. /usr/share/libubox/jshn.sh


port() { p=$(uci -q get kuroshio.main.admin_port); echo "${p:-8054}"; }

# 呼叫管理 API，輸出包成 {"result":…}（rpcd 只接受物件）
fetch() { # fetch <path> [query]
	local url
	url="http://127.0.0.1:$(port)$1"
	[ -n "$2" ] && url="$url?$2"
	local body
	body=$(uclient-fetch -q -T 60 -O - "$url" 2>/dev/null)
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
	{"status":{},"api":{"path":"str","query":"str"},"action":{"path":"str","query":"str"},"defaults":{},"acme_status":{},"acme_issue":{},"log":{"lines":64},"about":{},"backup_export":{"kind":"str"},"backup_import":{}}
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
		/api/status|/api/sysinfo|/api/upstreams|/api/benchmark|/api/cdn/pools|/api/cdn/v6nodes|/api/cdn/summary|/api/cdn/domains|/api/jobs|/api/trace|/api/filter/check|/api/routing|/api/ddns) ;;
		/api/community/status|/api/community/peers|/api/community/events) ;;
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
		*) echo '{"ok":false,"error":"不允許的路徑"}'; exit 0 ;;
		esac
		valid_query "$P_QUERY" || { echo '{"ok":false,"error":"參數格式錯誤"}'; exit 0; }
		fetch "$P_PATH" "$P_QUERY"
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
		rm -f "$BACKUP_OUT"
		json_init
		if msg=$(umask 077; /usr/bin/kuroshio export --uci "$@" -o "$BACKUP_OUT" 2>&1) && [ -s "$BACKUP_OUT" ]; then
			json_add_boolean ok 1
			json_add_int size "$(wc -c < "$BACKUP_OUT" | tr -d ' ')"
			json_add_string name "kuroshio-$kind-$(date +%Y%m%d).kuroshio"
			json_add_string path "$BACKUP_OUT"
		else
			rm -f "$BACKUP_OUT"
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
		out=$(/usr/bin/kuroshio import --uci --json "$BACKUP_IN" 2>/dev/null)
		rm -f "$BACKUP_IN"
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
