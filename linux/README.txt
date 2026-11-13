黑潮 DNS（Kuroshio DNS）Linux 通用版 3.0

這是什麼：單一靜態執行檔（musl，不需要另外安裝任何函式庫），一般 Linux 主機、NAS、虛擬機、
沒有 OpenWrt 套件的設備都能直接執行。OpenWrt 請改用 kuroshio-openwrt-*.zip（含 LuCI 介面與 DNS 接管）；
想用 Docker 見 https://github.com/candy999/kuroshio-dns/blob/main/docs/docker.md

檔案擺放：
  kuroshio 與 data/ 要放在同一個資料夾。執行檔會自動使用自己旁邊的 data/
  （台灣 IP 清單、種子資料、評測名單、設定頁、公開頁，不要刪）。

快速開始：
  1. 在旁邊放一份 config.json，只寫跟預設值不同的欄位（完整預設值：./kuroshio defaults），例如：
       {
         "system": { "persistDir": "/var/lib/kuroshio/state" },
         "listen": { "plain": { "binds": ["127.0.0.1"], "port": 5336 } }
       }
  2. ./kuroshio check-config config.json      檢查設定檔
  3. ./kuroshio run -c config.json            前景執行（Ctrl+C 正常結束並寫出快照）
  4. ./kuroshio query example.com -s 127.0.0.1:5336
     ./kuroshio url -c config.json            設定頁網址（預設 http://127.0.0.1:8054/ ，只有本機能開）

注意：
  - system.persistDir 沒設定時，快照放在 /etc/kuroshio/state；admin.token、custom-rules.txt 等
    相對路徑都以 persistDir 的上一層為準（上面的例子是 /var/lib/kuroshio）。
  - 53 埠要 root，或先執行 sudo setcap cap_net_bind_service=+ep ./kuroshio
  - Ubuntu 的 systemd-resolved 佔用 127.0.0.53:53，要開在 53 埠時見 docs/docker.md 的說明。
  - 長期執行：自己寫 systemd 服務，或用 Docker。

移植到其他系統（整合介面、檔案位置、指令）：
  https://github.com/candy999/kuroshio-dns/blob/main/PORTING.md
