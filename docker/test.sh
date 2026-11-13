#!/usr/bin/env bash
# 容器映像檔測試（CI 的 docker 工作；本機有 docker 也能跑）：
#   docker build -f docker/Dockerfile -t kuroshio-dns:test .
#   docker/test.sh kuroshio-dns:test
# 主機上要有能執行的 kuroshio（KUROSHIO_BIN，預設 docker/bin/amd64/kuroshio），拿來當查詢工具。
#
# 1. 空的 /config 第一次啟動：從 KUROSHIO_INIT_CONFIG 建立 config.json、HEALTHCHECK 變成 healthy
# 2. 從主機查詢對應出來的埠（GitHub 的 runner 上 systemd-resolved 佔用 127.0.0.53:53，所以不用 53）
# 3. docker restart：正常收尾（SIGTERM），/config 的 token、state/ 都還在
# 4. Caddy（內部 CA 的 HTTPS）→ 黑潮 DNS 不加密的 DoH（8053），用 Caddy 的根憑證查詢
set -euo pipefail

IMAGE=${1:-kuroshio-dns:test}
BIN=${KUROSHIO_BIN:-docker/bin/amd64/kuroshio}
CADDY_IMAGE=${CADDY_IMAGE:-caddy:2}
DNS_PORT=${DNS_PORT:-15353}
CADDY_PORT=${CADDY_PORT:-18443}
P=kuroshio-test # 容器、volume、網路名稱的字首
WORK=$(mktemp -d)

remove_all() {
	docker rm -f "$P-1" "$P-2" "$P-caddy" >/dev/null 2>&1 || true
	docker volume rm "$P-1" "$P-2" >/dev/null 2>&1 || true
	docker network rm "$P" >/dev/null 2>&1 || true
}
cleanup() {
	remove_all
	rm -rf "$WORK"
}
trap cleanup EXIT
remove_all

fail() {
	echo "::error::$*"
	for c in "$P-1" "$P-2" "$P-caddy"; do
		docker inspect "$c" >/dev/null 2>&1 || continue
		echo "----- $c 的日誌 -----"
		docker logs --tail 100 "$c" 2>&1 || true
		docker inspect --format '{{json .State.Health}}' "$c" 2>/dev/null || true
	done
	exit 1
}

# 等容器的 HEALTHCHECK（kuroshio health）變成 healthy，最多 90 秒
wait_healthy() {
	local s=""
	for _ in $(seq 1 90); do
		s=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$1")
		if [ "$s" = healthy ]; then
			echo "$1：healthy"
			return 0
		fi
		[ "$(docker inspect --format '{{.State.Running}}' "$1")" = true ] || fail "$1 已經結束"
		sleep 1
	done
	fail "$1 90 秒內沒有變成 healthy（目前：${s:-沒有 HEALTHCHECK}）"
}

# 容器裡的檔案 → 標準輸出（映像檔是 scratch，沒有 cat；docker cp 停止的容器也能用）
cat_file() {
	docker cp "$1:$2" - | tar -xO
}

# _dns.resolver.arpa 由伺服器自己回答，不需要外部網路。沒開 DDR 時是 0 筆答案、
# kuroshio query 的結束碼是 1，所以看輸出的 rcode
expect_rcode0() {
	local out
	out=$("$BIN" query _dns.resolver.arpa -t SVCB "$@" 2>&1) || true
	echo "$out"
	grep -q 'rcode 0' <<<"$out" || fail "查詢沒有得到 rcode 0：$*"
}

[ -x "$BIN" ] || fail "找不到主機上的 kuroshio：$BIN（設定 KUROSHIO_BIN）"
docker image inspect "$IMAGE" >/dev/null || fail "沒有映像檔 $IMAGE"

echo "== 1. 空的 /config 第一次啟動"
docker volume create "$P-1" >/dev/null
docker run -d --name "$P-1" -v "$P-1:/config" \
	-p "127.0.0.1:$DNS_PORT:53/udp" -p "127.0.0.1:$DNS_PORT:53/tcp" "$IMAGE" >/dev/null
wait_healthy "$P-1"
cat_file "$P-1" /config/config.json >"$WORK/config.json" || fail "第一次啟動沒有建立 /config/config.json"
grep -q '"/config/state"' "$WORK/config.json" || fail "/config/config.json 不是映像檔裡的預設設定：$(cat "$WORK/config.json")"
echo "已從預設設定建立 /config/config.json"
TOKEN=$(cat_file "$P-1" /config/admin.token | tr -d '[:space:]')
[ "${#TOKEN}" -ge 16 ] || fail "設定頁 token 沒有建立（/config/admin.token）"
URL=$(docker exec "$P-1" /usr/bin/kuroshio url -c /config/config.json)
echo "$URL"
grep -q "login?token=$TOKEN" <<<"$URL" || fail "kuroshio url 沒有顯示 token 登入網址"

echo "== 2. 從主機查詢（127.0.0.1:$DNS_PORT → 容器的 53）"
expect_rcode0 -s "127.0.0.1:$DNS_PORT"
expect_rcode0 -s "tcp://127.0.0.1:$DNS_PORT"
# 真的往上游查：runner 的網路偶爾不通，只記警告
"$BIN" query example.com -s "127.0.0.1:$DNS_PORT" || echo "::warning::example.com 查詢失敗（外部網路？）"

echo "== 3. docker restart 之後 /config 都還在"
echo "ci-$$" >"$WORK/marker"
docker cp "$WORK/marker" "$P-1:/config/state/ci-marker"
docker restart -t 15 "$P-1" >/dev/null
docker logs "$P-1" >"$WORK/log" 2>&1
grep -q '結束' "$WORK/log" || fail "收到 SIGTERM 沒有正常收尾（日誌沒有「結束」）"
wait_healthy "$P-1"
[ "$(cat_file "$P-1" /config/state/ci-marker)" = "ci-$$" ] || fail "/config/state 的檔案在重新啟動後不見了"
[ "$(cat_file "$P-1" /config/admin.token | tr -d '[:space:]')" = "$TOKEN" ] || fail "重新啟動後設定頁 token 變了"
docker cp "$P-1:/config/state" - | tar -t >"$WORK/state.txt"
grep -v -e '/$' -e 'ci-marker' "$WORK/state.txt" >"$WORK/snapshots.txt" || fail "結束時沒有寫出任何快照到 /config/state"
echo "/config/state 有 $(wc -l <"$WORK/snapshots.txt") 個快照檔，例如："
grep -v '/cdn/' "$WORK/snapshots.txt" | head -n 8 | sed 's/^/  /'
expect_rcode0 -s "127.0.0.1:$DNS_PORT"

echo "== 4. Caddy（HTTPS，內部 CA）→ 黑潮 DNS 的 DoH（8053，不加密）"
docker network create "$P" >/dev/null
docker volume create "$P-2" >/dev/null
cat >"$WORK/config.json" <<'EOF'
{
  "system": { "persistDir": "/config/state", "dataDir": "/usr/share/kuroshio" },
  "listen": {
    "plain": { "binds": ["0.0.0.0"], "port": 53 },
    "doh": { "enabled": true, "host": "0.0.0.0", "port": 8053, "tls": false, "trustProxy": true }
  },
  "admin": { "enabled": false }
}
EOF
docker create --name "$P-2" --network "$P" --network-alias kuroshio -v "$P-2:/config" "$IMAGE" >/dev/null
docker cp "$WORK/config.json" "$P-2:/config/config.json"
docker start "$P-2" >/dev/null
# 用 IP 當網址：查詢工具不看 /etc/hosts（主機名稱一律問 bootstrap 伺服器）。
# 沒有 SNI 的連線用 default_sni 挑憑證
cat >"$WORK/Caddyfile" <<'EOF'
{
	admin off
	skip_install_trust
	default_sni 127.0.0.1
}
https://127.0.0.1:8443 {
	tls internal
	reverse_proxy kuroshio:8053
}
EOF
docker create --name "$P-caddy" --network "$P" -p "127.0.0.1:$CADDY_PORT:8443" "$CADDY_IMAGE" >/dev/null
docker cp "$WORK/Caddyfile" "$P-caddy:/etc/caddy/Caddyfile"
docker start "$P-caddy" >/dev/null
wait_healthy "$P-2"
for _ in $(seq 1 30); do
	docker cp "$P-caddy:/data/caddy/pki/authorities/local/root.crt" "$WORK/root.crt" >/dev/null 2>&1 && break
	sleep 1
done
[ -s "$WORK/root.crt" ] || fail "Caddy 沒有產生內部 CA 的根憑證"
# Caddy 簽發憑證是非同步的：最多等 30 秒
for _ in $(seq 1 30); do
	"$BIN" query _dns.resolver.arpa -t SVCB -s "https://127.0.0.1:$CADDY_PORT/dns-query" --ca "$WORK/root.crt" 2>&1 | grep -q 'rcode 0' && break
	sleep 1
done
expect_rcode0 -s "https://127.0.0.1:$CADDY_PORT/dns-query" --ca "$WORK/root.crt"

echo "全部通過"
