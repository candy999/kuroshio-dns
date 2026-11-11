#!/bin/sh
# =====================================================================
#  kuroshio — Let's Encrypt 憑證（acme.sh + Cloudflare DNS 驗證）
#    acme.sh issue       申請 / 更新憑證，裝到 /etc/kuroshio/cert.pem、key.pem
#    acme.sh issue-bg    背景執行 issue（LuCI 用），紀錄在 /tmp/kuroshio-acme.log
#    acme.sh cron        每日續期檢查（到期前 30 天才會真的續期）
#    acme.sh cron-sync   依設定加入 / 移除 crontab 的續期工作
#    acme.sh status      目前憑證資訊（JSON）
#  用 DNS 驗證，不需要開 80 / 443 埠；Cloudflare API Token 與 DDNS 共用
#  （權限：Zone → DNS → Edit、Zone → Zone → Read）。
#  DoH / DoT 會偵測憑證檔案變更，10 秒內自動換上新憑證，不用重啟。
# =====================================================================

ACME=/usr/lib/acme/client/acme.sh
HOME_DIR=/etc/kuroshio/acme
CERT=/etc/kuroshio/cert.pem
KEY=/etc/kuroshio/key.pem
LOG=/tmp/kuroshio-acme.log
PID=/var/run/kuroshio-acme.pid
CRON=/etc/crontabs/root
CRON_LINE="23 4 * * * /usr/libexec/kuroshio/acme.sh cron >/dev/null 2>&1 # kuroshio"

get() { uci -q get "kuroshio.$1"; }

issue() {
	local domain email server key token ecc rc
	domain=$(get tls.domain); email=$(get tls.acme_email)
	server=$(get tls.acme_server); key=$(get tls.acme_key)
	token=$(get cf_account.api_token)
	: "${server:=letsencrypt}" "${key:=ec-256}"
	[ -x "$ACME" ] || { echo "找不到 acme.sh，請安裝套件 acme-acmesh 與 acme-acmesh-dnsapi"; return 1; }
	[ -n "$domain" ] || { echo "沒有設定網域"; return 1; }
	[ -n "$token" ] || { echo "沒有設定 Cloudflare API Token"; return 1; }
	mkdir -p "$HOME_DIR"
	case "$key" in ec-*) ecc=--ecc ;; *) ecc= ;; esac

	echo "申請 $domain 的憑證（$server，金鑰 $key，Cloudflare DNS 驗證）"
	CF_Token="$token" "$ACME" --home "$HOME_DIR" --config-home "$HOME_DIR" --issue \
		--dns dns_cf -d "$domain" --server "$server" --keylength "$key" \
		${email:+--accountemail "$email"}
	rc=$?
	# 0 = 申請成功；2 = 還沒到續期時間（照樣安裝，確保檔案存在）
	[ "$rc" = 0 ] || [ "$rc" = 2 ] || { echo "申請失敗（代碼 $rc）"; return "$rc"; }

	"$ACME" --home "$HOME_DIR" --config-home "$HOME_DIR" --install-cert -d "$domain" $ecc \
		--fullchain-file "$CERT" --key-file "$KEY" --reloadcmd "chmod 600 $KEY" || return 1
	echo "完成：$CERT"
	# 有了有效憑證：重新判斷要不要用 DNR 通告加密 DNS
	/usr/libexec/kuroshio/takeover.sh apply >/dev/null 2>&1
}

issue_bg() {
	if [ -f "$PID" ] && kill -0 "$(cat "$PID")" 2>/dev/null; then
		echo '{"started":false,"error":"已經在申請中"}'
		return
	fi
	# 背景程序不能繼承 stdout，否則 rpcd 會等它結束才回應
	( issue > "$LOG" 2>&1; echo "exit=$?" >> "$LOG"; rm -f "$PID" ) </dev/null >/dev/null 2>&1 &
	echo $! > "$PID"
	echo '{"started":true}'
}

cron_renew() {
	[ "$(get tls.cert_mode)" = acme ] || return 0
	"$ACME" --home "$HOME_DIR" --config-home "$HOME_DIR" --cron >> "$LOG" 2>&1
}

cron_sync() {
	local want=0
	[ "$(get main.enabled)" = 1 ] && [ "$(get tls.cert_mode)" = acme ] && want=1
	touch "$CRON"
	if [ "$want" = 1 ]; then
		grep -qF "# kuroshio" "$CRON" && return 0
		echo "$CRON_LINE" >> "$CRON"
	else
		grep -qF "# kuroshio" "$CRON" || return 0
		sed -i '/# kuroshio$/d' "$CRON"
	fi
	/etc/init.d/cron restart >/dev/null 2>&1
}

status() {
	local running=false
	[ -f "$PID" ] && kill -0 "$(cat "$PID")" 2>/dev/null && running=true
	local cert=$CERT
	[ "$(get tls.cert_mode)" = manual ] && cert=$(get tls.cert)
	if [ "$running" = true ]; then
		/usr/bin/kuroshio cert-info "${cert:-$CERT}" --log "$LOG" --running
	else
		/usr/bin/kuroshio cert-info "${cert:-$CERT}" --log "$LOG"
	fi
}

case "$1" in
issue) issue ;;
issue-bg) issue_bg ;;
cron) cron_renew ;;
cron-sync) cron_sync ;;
status) status ;;
*) echo "用法：$0 issue|issue-bg|cron|cron-sync|status" >&2; exit 1 ;;
esac
