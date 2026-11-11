黑潮 DNS（Kuroshio DNS）Windows 版：3.0 預覽

功能：區網 DNS、DoH / DoH3 / DoT / DoQ、廣告 / 遙測 / 詐騙過濾、CDN 台灣節點置換、
每日上游評測、Cloudflare DDNS、內建 Let's Encrypt（Cloudflare DNS 驗證）、本機設定頁、
公開頁、社群共享、Windows 服務、IIS 共存。

快速開始（命令提示字元）：
  kuroshio.exe run                           前景執行（Ctrl+C 正常結束並寫出快照）
                                             啟動時會印出設定頁的登入網址與公開頁網址
                                             執行中可以直接在視窗輸入指令：
                                               help    指令說明
                                               url     設定頁網址（含登入 token）
                                               open    用瀏覽器打開設定頁
                                               site    公開頁網址、裝置要填的 DoH / DoT 位址
                                               status  今天的查詢數、命中率、監聽的協議
                                               reload  重新讀取設定檔
                                               quit    正常結束
  kuroshio.exe url [--open]                  不在視窗裡（例如服務模式）時看同樣的網址
  kuroshio.exe query example.com -s 127.0.0.1:53

長期執行（用「以系統管理員身分執行」的命令提示字元）：
  kuroshio.exe setup                         一次加好 Windows 防火牆規則（HTTP.sys 共用模式另外登記 urlacl 與憑證）
  kuroshio.exe service install               安裝成服務（開機自動啟動、當掉自動重啟）
  kuroshio.exe service start | stop | status | uninstall

設定：
  - 設定頁：http://127.0.0.1:8054/ ，登入 token 在設定資料夾的 admin.token
  - 設定檔 config.json 只寫跟預設值不同的欄位；完整預設值：kuroshio.exe defaults
  - 設定資料夾：執行檔旁邊有 config.json 時就是這個資料夾（攜帶版），
    否則是 %ProgramData%\kuroshio\
  - data\ 是程式附帶的唯讀資料（種子、評測名單、CDN 範圍、設定頁、公開頁），不要刪

憑證：
  kuroshio.exe acme issue                    立即申請 / 續期（需要 acme.enabled 與 Cloudflare API Token）

IIS 已經占用 443 時（建議：HTTP.sys 共用，模式 B）：
  設定 domain、listen.doh.enabled = true、listen.doh.port = 443、
  listen.doh.windowsMode = "httpsys"（預設 "auto"：TCP 443 被 IIS / HTTP.sys 占用時自動用這個模式）
  kuroshio.exe setup                         系統管理員執行一次：登記 urlacl（之後一般權限也能登記網址）、
                                             把憑證匯入「本機電腦\個人」並綁到 HTTP.sys（hostnameport，SNI）
  kuroshio.exe httpsys status                要登記的網址、HTTP.sys 的 HTTP/3 設定、目前綁定的憑證
  kuroshio.exe httpsys cert                  立即同步憑證（執行中每 10 分鐘也會自動檢查，續期後自動更新）
  只登記 https://網域:443/dns-query/、/.well-known/kuroshio/ 與公開頁，IIS 其他網站照常；
  用戶端 IP 直接取得。HTTP.sys 開了 HTTP/3（登錄檔 EnableHttp3）時 DoH3 由 HTTP.sys 提供，
  否則黑潮 DNS 自己聽 UDP 443。設定頁與 status 指令會顯示目前的模式與 DoH3 由誰提供。

IIS 已經占用 443 時（反向代理模式，沿用 2.x 的 ARR 設定）：
  kuroshio.exe iis setup "Default Web Site"  產生 web.config 轉送規則與 Alt-Svc 標頭、更新設定檔，
                                             並把憑證匯入 Windows 憑證存放區、綁到站台的 HTTPS
  kuroshio.exe iis cert "Default Web Site"   只同步憑證（服務執行中每 10 分鐘也會自動檢查，續期後自動更新）
  DoH3（UDP 443）、DoT（TCP 853）、DoQ（UDP 853）仍由黑潮 DNS 自己監聽

提醒：家裡路由器的埠轉發也要加 UDP 443 與 UDP 853，DoH3 / DoQ 才連得進來。

說明文件：docs/spec/07-windows.md
授權：GPL-3.0-or-later
