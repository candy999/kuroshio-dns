# Docker 使用說明

映像檔：`ghcr.io/candy999/kuroshio-dns`，支援 `linux/amd64`、`linux/arm64`、`linux/arm/v7`（MIPS 等其他 CPU 用 Releases 的 `kuroshio-linux-<target>.tar.gz`）。

| 標籤 | 內容 |
|---|---|
| `latest` | 最新的正式版（預覽版不會更新它） |
| `3.2` | 3.2.x 的最新一版 |
| `3.2.1` | 固定版本 |

映像檔裡只有一個靜態執行檔與唯讀資料（`FROM scratch`，沒有 shell），跟 Releases 的 `kuroshio-<target>` 是同一批 CI 編好、測過的執行檔。

## 1. 快速開始（Docker Compose）

```sh
mkdir kuroshio && cd kuroshio
curl -fsSLO https://raw.githubusercontent.com/candy999/kuroshio-dns/main/docker/compose.yml
docker compose up -d
docker ps          # STATUS 出現 (healthy) 就是在回答查詢了
```

[`docker/compose.yml`](../docker/compose.yml) 的內容：

```yaml
services:
  kuroshio:
    image: ghcr.io/candy999/kuroshio-dns:latest
    container_name: kuroshio
    network_mode: host
    volumes:
      - ./config:/config
    restart: unless-stopped
    stop_grace_period: 15s
```

不用 Compose 的話：

```sh
docker run -d --name kuroshio --network host -v "$PWD/config:/config" \
  --restart unless-stopped --stop-timeout 15 ghcr.io/candy999/kuroshio-dns:latest
```

### 為什麼一定要 host 網路

- **看得到用戶端真正的 IP**：用 bridge 網路加 `-p 53:53/udp` 時，Docker 的埠對應可能把來源 IP 換成閘道位址（例如 `172.17.0.1`）。存取控制（預設「只開放台灣」與區網）、統計、「這台裝置有沒有在用」都要看真正的來源 IP，換掉之後不是全部放行就是全部擋掉。
- **53 埠直接開在主機上**，區網裝置把 DNS 指到這台主機的 IP 就能用；DoT、DoQ、DoH3 也不用一個一個對應。

### Ubuntu：53 埠被 systemd-resolved 佔用

Ubuntu（以及其他用 systemd-resolved 的發行版）在 `127.0.0.53:53` 有一個本機 DNS，黑潮 DNS 開在 `0.0.0.0:53` 會失敗（日誌出現 `Address already in use`）。三種做法擇一：

1. **關掉 systemd-resolved 的 53 埠**（主機本身改用黑潮 DNS）：

   ```sh
   sudo mkdir -p /etc/systemd/resolved.conf.d
   printf '[Resolve]\nDNS=127.0.0.1\nDNSStubListener=no\n' | sudo tee /etc/systemd/resolved.conf.d/kuroshio.conf
   sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
   sudo systemctl restart systemd-resolved
   docker restart kuroshio
   ```

2. **只聽區網 IP**：`config.json` 的 `listen.plain.binds` 改成 `["192.168.1.10"]`（這台主機的區網 IP），不跟 `127.0.0.53` 衝突。
3. **換埠號**：`listen.plain.port` 改成例如 `5336`（裝置就不能直接用了，適合給另一台 DNS 轉發）。

## 2. 設定

第一次啟動時 `/config` 是空的，會自動建立 `/config/config.json`（映像檔裡的 [`docker/config.json`](../docker/config.json)）：

```json
{
  "system": { "persistDir": "/config/state", "dataDir": "/usr/share/kuroshio" },
  "listen": { "plain": { "binds": ["0.0.0.0", "::"], "port": 53 } },
  "admin": { "host": "0.0.0.0", "auth": true, "tokenFile": "/config/admin.token" },
  "filter": { "customRules": ["/config/custom-rules.txt"] }
}
```

- 明文 DNS 開在所有位址的 53 埠，`listen.plain.allowFrom` 用預設值：只回答私有網段（區網）的查詢。
- 設定頁開在 `8054`、所有位址，**一定要登入**（容器裡用 `0.0.0.0`，所以把 Linux 預設不登入的設定頁打開登入）。不想讓區網其他電腦開設定頁，把 `admin.host` 改回 `127.0.0.1`。
- 改的方法：直接編輯 `./config/config.json`（只寫跟預設值不同的欄位，完整預設值 `docker exec kuroshio kuroshio defaults`），或在設定頁上改。手動編輯後 `docker restart kuroshio`。
- 檢查設定檔：`docker exec kuroshio kuroshio check-config /config/config.json`

### 設定頁

```sh
docker exec kuroshio kuroshio url -c /config/config.json
```

會印出含 token 的登入網址 `http://127.0.0.1:8054/login?token=…`。在別台電腦開的話把 `127.0.0.1` 換成這台主機的 IP。token 存在 `./config/admin.token`，刪掉後重新啟動會產生新的。

### /config 裡有什麼

| 檔案 | 內容 |
|---|---|
| `config.json` | 設定 |
| `admin.token` | 設定頁登入 token |
| `custom-rules.txt` | 自訂過濾規則（第一次啟動時從預設規則建立） |
| `state/` | 學到的 CDN 節點、評測結果、統計、好友、台灣 IP 清單……（結束時寫出快照） |

**備份就是備份整個 `./config` 資料夾**（停止容器後複製最完整）。換機器時整個資料夾搬過去即可。

### 時區

排程（每日上游評測、每週 CDN 範圍、每月台灣 IP 清單）與統計的日期在程式裡固定用台灣時間（UTC+8，台灣沒有日光節約），不看容器的 `TZ`，映像檔裡也不需要時區資料；不用設定 `TZ`。日誌的時間是 UTC（結尾的 `Z`）。

### 升級

```sh
docker compose pull && docker compose up -d
```

`/config` 不受影響。想固定在某個版本，把 `latest` 改成例如 `3.0.2`；只想收 3.0.x 的修正就用 `3.0`。

### 健康檢查

映像檔內建 `HEALTHCHECK`（`kuroshio health`：明文 DNS 有在回答就是 healthy），`docker ps` 看得到狀態。停止時送 SIGTERM，黑潮 DNS 會寫出快照再結束，所以 `stop_grace_period` 給 15 秒。

### 日誌裡常見、可以忽略的警告

- `無法設定 oom_score_adj = -500：Permission denied`：容器裡沒有 `CAP_SYS_RESOURCE`，不影響執行。
- `UDP 綁定 [::]:53 失敗: Address family not supported`：這台主機（或 Docker）沒有開 IPv6，只用 IPv4。

## 3. NAS

原則都一樣：**網路用 host**、**把一個資料夾對應到 `/config`**。NAS 自己的 DNS 伺服器套件（例如 Synology 的 DNS Server）如果在用 53 埠，要先停用或改埠。

- **Synology（Container Manager）**：「專案」→ 新增，路徑選例如 `/volume1/docker/kuroshio`，貼上上面的 `compose.yml`。或「映像」下載 `ghcr.io/candy999/kuroshio-dns` 後建立容器：網路選 `host`，「儲存空間設定」把 `docker/kuroshio/config` 對應到 `/config`。
- **QNAP（Container Station）**：「應用程式」→ 建立，貼上 `compose.yml`；或建立容器時網路模式選「Host」，共用資料夾對應到 `/config`。
- **Unraid**：Docker → Add Container，Repository 填 `ghcr.io/candy999/kuroshio-dns:latest`，Network Type 選 `Host`，新增 Path：Container Path `/config`、Host Path `/mnt/user/appdata/kuroshio`。

## 4. 放在反向代理後面（DoH 用 443）

主機上已經有網站伺服器佔用 443 時，DoH 可以交給它轉送。通用的四條規則：

1. **用專屬的子網域**（例如 `dns.example.net`），整個子網域都轉給黑潮 DNS；至少要轉 `/dns-query`、`/.well-known/kuroshio/` 與公開頁（`/`、`/index.html`、`/api/public/`……，所以用整個子網域最簡單）。轉到 `http://127.0.0.1:8053`。
2. **帶 `X-Forwarded-For`**，黑潮 DNS 設 `listen.doh.trustProxy: true`。只有連線來自本機（127.0.0.1 / ::1）時才採用這個標頭，所以反向代理要跟黑潮 DNS 在同一台主機、用 host 網路。
3. **代理到黑潮 DNS 用不加密的 HTTP**：`listen.doh.tls: false`，HTTPS 由網站伺服器處理。
4. **HTTP/3**：網站伺服器有提供（Caddy 預設就有）就好；沒有的話黑潮 DNS 可以自己聽 UDP 443：`listen.doh.http3: true`、`http3Port: 443`、`http3Binds: ["0.0.0.0", "::"]`，並設定 `tls.cert` / `tls.key`（DoH3 一定要憑證）。

對應的黑潮 DNS 設定（[`docker/config.caddy.json`](../docker/config.caddy.json)）：

```json
{
  "domain": "dns.example.net",
  "listen": {
    "doh": { "enabled": true, "host": "127.0.0.1", "port": 8053, "tls": false, "trustProxy": true }
  }
}
```

（再加上第 2 節的預設內容。）

### Caddy（CI 實際測試過）

[`docker/compose.caddy.yml`](../docker/compose.caddy.yml) 與 [`docker/Caddyfile.example`](../docker/Caddyfile.example)：Caddy 自動申請、續期 Let's Encrypt 憑證，HTTP/3 預設開著，`reverse_proxy` 預設帶 `X-Forwarded-For`。

```
dns.example.net {
	reverse_proxy 127.0.0.1:8053
}
```

```sh
cp Caddyfile.example Caddyfile                      # 改成你的子網域
mkdir -p config && cp config.caddy.json config/config.json   # 同樣改 domain
docker compose -f compose.caddy.yml up -d
```

CI 每次推送都會用 Caddy（內部 CA 的 HTTPS）轉送到黑潮 DNS 的 8053，再從外面用 Caddy 的根憑證做 DoH 查詢。

**DoT（TCP 853）、DoQ（UDP 853）不經過 Caddy**，黑潮 DNS 要自己讀憑證檔。`compose.caddy.yml` 已經把 Caddy 的憑證資料夾唯讀掛到 `/caddy-certs`，在 `config.json` 加上：

```json
{
  "tls": {
    "cert": "/caddy-certs/acme-v02.api.letsencrypt.org-directory/dns.example.net/dns.example.net.crt",
    "key": "/caddy-certs/acme-v02.api.letsencrypt.org-directory/dns.example.net/dns.example.net.key"
  },
  "listen": { "dot": { "enabled": true }, "doq": { "enabled": true } }
}
```

（Caddy 改用 ZeroSSL 簽發時資料夾名稱是 `acme.zerossl.com-v2-dv90`，用 `ls caddy-data/caddy/certificates` 確認。）憑證檔有變就會自動重新載入，Caddy 續期後不用重新啟動。不需要 DoT / DoQ 的話不設定就好。

### Nginx（參考寫法，未經 CI 驗證）

```nginx
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name dns.example.net;
    ssl_certificate     /etc/letsencrypt/live/dns.example.net/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/dns.example.net/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8053;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Nginx 1.25 以後可以加 `listen 443 quic reuseport;` 與 `add_header Alt-Svc 'h3=":443"; ma=86400';` 提供 HTTP/3；否則照第 4 條讓黑潮 DNS 自己聽 UDP 443。

### Apache（參考寫法，未經 CI 驗證）

需要 `mod_ssl`、`mod_proxy`、`mod_proxy_http`、`mod_http2`（`a2enmod ssl proxy proxy_http http2`）。`ProxyPass` 會自動帶 `X-Forwarded-For`。

```apache
<VirtualHost *:443>
    ServerName dns.example.net
    Protocols h2 http/1.1
    SSLEngine on
    SSLCertificateFile    /etc/letsencrypt/live/dns.example.net/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/dns.example.net/privkey.pem

    ProxyPreserveHost On
    ProxyPass        / http://127.0.0.1:8053/
    ProxyPassReverse / http://127.0.0.1:8053/
</VirtualHost>
```

Apache 沒有 HTTP/3，照第 4 條讓黑潮 DNS 自己聽 UDP 443。

### 其他網站伺服器

**Tomcat**：Tomcat 本身不適合當反向代理；通常前面已經有 Apache 或 Nginx，在那一層把 `dns.example.net` 轉給黑潮 DNS，Tomcat 不用動。只有 Tomcat 的話，讓黑潮 DNS 的 DoH 用別的埠（例如 8443，`listen.doh.tls` 用 `auto` 並設定憑證），網址帶埠號。

**Node.js**：用 `http-proxy` 之類的套件把 `dns.example.net` 的請求原封不動轉到 `http://127.0.0.1:8053`，要保留 `Content-Type: application/dns-message` 與 POST 的二進位內容（不要經過 JSON / 文字的 body parser），並加上 `X-Forwarded-For`。

**LiteSpeed / OpenLiteSpeed**：建立「Web Server」類型的 External App 指向 `127.0.0.1:8053`，再在 `dns.example.net` 的虛擬主機加一條 Context `/` 用 Proxy 指到它；LiteSpeed 會帶 `X-Forwarded-For`，HTTP/3 由 LiteSpeed 提供。

### certbot 的憑證（DoT / DoQ / DoH3 用）

用 certbot 申請的話，憑證在：

- `/etc/letsencrypt/live/<網域>/fullchain.pem`（憑證加中繼憑證，**不要用** `cert.pem`）
- `/etc/letsencrypt/live/<網域>/privkey.pem`

`live/` 裡是指到 `archive/` 的符號連結，所以要掛整個 `/etc/letsencrypt`：在 `compose.yml` 的 `volumes` 加 `- /etc/letsencrypt:/etc/letsencrypt:ro`，`config.json` 寫

```json
{
  "tls": {
    "cert": "/etc/letsencrypt/live/dns.example.net/fullchain.pem",
    "key": "/etc/letsencrypt/live/dns.example.net/privkey.pem"
  }
}
```

權限：`privkey.pem` 只有 root 讀得到。容器裡的黑潮 DNS 是 root 執行，直接可以讀；不用容器、以一般使用者執行時，要讓它讀得到 `archive/` 與 `live/`（例如建立群組 `ssl-cert`，`chgrp -R ssl-cert /etc/letsencrypt/{live,archive}`、`chmod -R g+rX` 同樣兩個資料夾，再把使用者加進群組）。certbot 續期後檔案有變，黑潮 DNS 會自動換上新憑證。

## 5. 驗證下載的檔案

Releases 的檔案與映像檔都有 GitHub 的建置來源證明（build provenance），可以確認是這個 repo 的 GitHub Actions 編出來的：

```sh
gh attestation verify kuroshio-linux-x86_64-unknown-linux-musl.tar.gz --repo candy999/kuroshio-dns
gh attestation verify oci://ghcr.io/candy999/kuroshio-dns:3.0.2 --repo candy999/kuroshio-dns
```

## 6. 自己建置映像檔

映像檔裡不編譯，用編好的靜態執行檔（見 [建置說明](building.md)）：

```sh
mkdir -p docker/bin/amd64
cp target/x86_64-unknown-linux-musl/release/kuroshio docker/bin/amd64/
docker build -f docker/Dockerfile -t kuroshio-dns:test .
docker/test.sh kuroshio-dns:test      # CI 用的同一套測試
```

`docker/bin/arm64/`、`docker/bin/armv7/` 放 `aarch64-unknown-linux-musl`、`armv7-unknown-linux-musleabihf` 的執行檔，就可以用 `docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7` 建多種 CPU。
