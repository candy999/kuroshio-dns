# Windows 使用說明

Windows 10 / 11、Windows Server（64 位元）。單一執行檔，不需要安裝 Visual C++ 執行階段或其他元件。

這份說明照「先放好檔案 → 寫設定 → 第一次設定 → 執行 → 測試」的順序；最後是常見問題。

## 1. 放好檔案

從 [Releases](https://github.com/candy999/kuroshio-dns/releases) 下載 `kuroshio-windows-x86_64.zip`，解壓後裡面是一個 `kuroshio\` 資料夾：

```
kuroshio\
  kuroshio.exe
  data\            ← 唯讀資料：台灣 IP 清單、種子資料、評測名單、CDN 範圍、設定頁、公開頁、儀表板
  LICENSE
  README.txt
```

把整個資料夾放到你要的位置，例如 `D:\kuroshio\`。**`data\` 一定要跟 `kuroshio.exe` 放在一起**（或用 `system.dataDir` 指定位置）：少了它 DNS 照樣能用，但「只開放台灣」會因為讀不到台灣 IP 清單而全部放行，設定頁與公開頁也打不開。

### 設定與資料放哪裡

| 情況 | 設定檔 | 狀態資料（學到的 CDN、評測結果、好友……） |
|---|---|---|
| **攜帶版**：`kuroshio.exe` 旁邊有 `config.json` | `kuroshio.exe` 旁邊的 `config.json` | `kuroshio.exe` 旁邊的 `state\` |
| 旁邊沒有 `config.json` | `%ProgramData%\kuroshio\config.json` | `%ProgramData%\kuroshio\state\` |
| 執行時加 `-c 檔案` | 指定的檔案 | 預設同上；可以用 `system.persistDir` 指定 |

建議用攜帶版：所有東西都在同一個資料夾，搬家、備份、看得到在哪裡。

用 `kuroshio.exe paths` 可以列出實際使用的每一個位置（設定檔、狀態、自訂規則、憑證、設定頁 token）。

## 2. config.json

### 規則

- **只寫跟預設值不同的欄位**，其他都用預設值。完整預設值：`kuroshio.exe defaults`。
- 格式是 JSON：字串用雙引號、最後一項後面不能有逗號。
- **路徑用 `/`**（`D:/kuroshio/certs/cert.pem`），或把 `\` 寫成兩個（`D:\\kuroshio\\certs\\cert.pem`）。
- 用記事本存檔時「存檔類型」選「所有檔案」，否則會存成 `config.json.txt`（檔案總管預設隱藏副檔名，看起來一樣）。編碼用 UTF-8。
- 寫完檢查：`kuroshio.exe check-config config.json` 會印出合併後的完整設定；格式錯誤會直接告訴你哪一行。
- 設定檔不存在時程式照樣啟動、全部用預設值，並在開頭提示「設定檔不存在」。

不想手寫也可以：先什麼都不寫直接執行，在視窗輸入 `url` 打開本機設定頁，在網頁上改，存檔就會寫回 `config.json`。

### 範例 A：只給這台電腦用

不需要設定檔。程式預設聽 `127.0.0.1:53`，把這台電腦網卡的 DNS 改成 `127.0.0.1` 即可（控制台 → 網路連線 → 網卡內容 → IPv4 → DNS 伺服器）。

### 範例 B：給家裡區網的其他裝置用

```json
{
  "listen": {
    "plain": { "binds": ["127.0.0.1", "192.168.1.10"] }
  }
}
```

`192.168.1.10` 換成這台電腦的區網 IP，再把路由器 DHCP 發的 DNS 改成這個 IP。預設只回答私有網段（區網）的查詢。

### 範例 C：對外提供 DoH / DoT / DoQ / DoH3（沒有 IIS）

要有自己的網域。憑證可以讓黑潮 DNS 自己申請（Let's Encrypt，Cloudflare DNS 驗證，不用開 80 埠）：

```json
{
  "domain": "dns.example.net",
  "acme": { "enabled": true, "apiToken": "<Cloudflare API Token>", "email": "you@example.net" },
  "listen": {
    "doh": { "enabled": true, "host": "0.0.0.0", "port": 443, "http3": true },
    "dot": { "enabled": true },
    "doq": { "enabled": true }
  },
  "site": { "enabled": true }
}
```

- Cloudflare API Token 權限：Zone → DNS → Edit、Zone → Zone → Read。申請好的憑證放在設定資料夾的 `cert.pem`、`key.pem`，到期前 30 天自動續期，續期後不用重啟。
- 網域的 IP 會變（浮動 IP）：加上 `"ddns": { "enabled": true }`，用同一把 Token 自動更新 Cloudflare 的 A 記錄。
- 已經有憑證（例如 win-acme 產生的 PEM）：不要開 `acme`，改寫 `"tls": { "cert": "...", "key": "..." }`，見範例 D。
- `site.enabled` 是給親友看的設定說明頁（`https://dns.example.net/`），不需要可以拿掉。

### 範例 D：這台電腦有 IIS，跟 IIS 共用 443（HTTP.sys 共用，建議）

IIS 佔著 TCP 443 時，黑潮 DNS 透過 Windows 的 HTTP.sys 只登記自己的網址（`/dns-query`、`/.well-known/kuroshio/`、公開頁），IIS 其他網站照常。

```json
{
  "domain": "dns.example.net",
  "tls": {
    "cert": "D:/certs/dns.example.net-chain.pem",
    "key": "D:/certs/dns.example.net-key.pem"
  },
  "listen": {
    "doh": {
      "enabled": true,
      "port": 443,
      "windowsMode": "httpsys",
      "http3": true,
      "http3Binds": ["0.0.0.0"]
    },
    "dot": { "enabled": true },
    "doq": { "enabled": true }
  },
  "site": { "enabled": true }
}
```

- **`http3Binds` 一定要寫**：DoH3 用 UDP 443，由黑潮 DNS 自己監聽（HTTP.sys 有開 HTTP/3 時改由 HTTP.sys 提供）。不寫的話會跟 DoH 一樣只聽 `127.0.0.1`，外面連不到。
- **win-acme 的憑證**：用 `-chain.pem`（憑證加中繼憑證）和 `-key.pem`，不要用只有憑證本身的 `-crt.pem`。win-acme 續期後，DoT / DoQ / DoH3 在 10 秒內換上新憑證，HTTP.sys 的綁定在 10 分鐘內自動更新（需要系統管理員權限或服務模式）。
- 也可以用範例 C 的 `acme` 讓黑潮 DNS 自己申請，結果一樣會自動匯入並綁定到 HTTP.sys。
- 同一個網域原本有 IIS 站台：網站首頁 `/` 仍由 IIS 回應，黑潮 DNS 只登記公開頁用到的路徑（`/index.html`、`/api/public/`……）。想讓首頁直接是公開頁，在站台加一條 `/` 導向 `/index.html` 的規則（見下面的 web.config），或拿掉站台在這個網域 443 的綁定。

**放在 IIS 網站資料夾裡的話**，用 `web.config` 擋掉設定與狀態檔，避免被 IIS 送出去（黑潮 DNS 的網址由 HTTP.sys 直接交給它，不經過 IIS，不受影響）：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <security>
      <requestFiltering>
        <hiddenSegments>
          <add segment="state" />
          <add segment="data" />
          <add segment="certs" />
        </hiddenSegments>
        <fileExtensions allowUnlisted="true">
          <add fileExtension=".json" allowed="false" />
          <add fileExtension=".txt" allowed="false" />
          <add fileExtension=".pem" allowed="false" />
          <add fileExtension=".token" allowed="false" />
          <add fileExtension=".kuroshio" allowed="false" />
          <add fileExtension=".exe" allowed="false" />
          <add fileExtension=".cmd" allowed="false" />
          <add fileExtension=".log" allowed="false" />
        </fileExtensions>
      </requestFiltering>
    </security>
    <rewrite>
      <rules>
        <rule name="kuroshio-home" stopProcessing="true">
          <match url="^$" />
          <action type="Redirect" url="/index.html" redirectType="Found" />
        </rule>
      </rules>
    </rewrite>
  </system.webServer>
</configuration>
```

（`rewrite` 需要 IIS 的 URL Rewrite 模組。）

### 範例 E：已經用 IIS ARR 反向代理（2.x 的做法）

```bat
kuroshio.exe iis setup "Default Web Site"
```

會產生 `web.config` 轉送規則（`/dns-query`、`/.well-known/kuroshio`、公開頁 → `http://127.0.0.1:8053`）、加上 Alt-Svc 標頭、更新設定檔，並把憑證匯入、綁到站台。DoH3（UDP 443）、DoT、DoQ 仍由黑潮 DNS 自己監聽。新安裝建議用範例 D。

### DoH 不用 443

443 被占用又不想共用時，DoH 可以用任何埠，例如 `"port": 8443`，網址就是 `https://dns.example.net:8443/dns-query`，公開頁也在同一個埠。

## 3. 第一次設定（系統管理員執行一次）

開「以系統管理員身分執行」的命令提示字元：

```bat
cd /d D:\kuroshio
kuroshio.exe paths
kuroshio.exe setup
```

- `paths`：確認讀的是你的 `config.json`、狀態資料夾、`data\`（`shareDir`）、憑證（`tls.exists` 要是 `true`）都在預期的地方。
- `setup`：加 Windows 防火牆規則（只加實際開啟的協議）；範例 D 另外登記 HTTP.sys 網址（urlacl）、把憑證匯入「本機電腦\個人」並綁到 HTTP.sys。
  如果 `setup` 只加了 53 埠的規則，代表沒讀到你的設定（見常見問題）。
- 範例 D 再看一次 `kuroshio.exe httpsys status`：`urls` 是登記的網址，`cert.thumbprint` 是綁定的憑證。

路由器（或防火牆）的埠轉發：DoH 用 TCP 443、DoH3 用 **UDP** 443、DoT 用 TCP 853、DoQ 用 **UDP** 853。很多人只轉了 TCP，DoH3 / DoQ 就連不進來。

## 4. 執行

### 方式一：命令提示字元（測試、臨時用）

```bat
kuroshio.exe run
```

視窗裡可以直接輸入：`help`、`status`（今天的查詢、監聽中的協議）、`url`（設定頁網址，含登入 token）、`open`（用瀏覽器打開設定頁）、`site`（公開頁網址、裝置要填的 DoH / DoT 位址）、`reload`、`quit`（正常結束並寫出資料）。Ctrl+C 也會正常結束。

想要當掉自動重開、雙擊就能跑，可以存成 `run.cmd` 放在 `kuroshio.exe` 旁邊（記事本存成 UTF-8；`KDIR` 改成你的資料夾）：

```bat
@echo off
chcp 65001 >nul
setlocal
set "KDIR=D:\kuroshio"

if not exist "%KDIR%\kuroshio.exe" (
  echo 找不到 %KDIR%\kuroshio.exe
  pause
  exit /b 1
)
cd /d "%KDIR%"

net session >nul 2>&1
if errorlevel 1 (
  echo 請按右鍵「以系統管理員身分執行」這個檔案
  pause
  exit /b 1
)

title Kuroshio DNS
:loop
"%KDIR%\kuroshio.exe" run
set "RC=%errorlevel%"
if "%RC%"=="0" goto end
echo [%date% %time%] 黑潮 DNS 異常結束（代碼 %RC%），5 秒後重新啟動，按 Ctrl+C 取消
timeout /t 5 >nul
goto loop
:end
endlocal
```

- 用系統管理員執行，是為了讓憑證續期後能自動重新匯入、綁定 HTTP.sys / IIS。只跑一般 DNS 的話不需要。
- 正常結束（`quit`、Ctrl+C）就停下；異常結束才重開。
- ConEmu、Windows Terminal、cmd 都可以用，日誌有顏色。不要顏色可以在 `setlocal` 下面加 `set "NO_COLOR=1"`。
- 傳統 cmd 視窗的「快速編輯模式」會讓你在視窗裡點一下滑鼠時暫停輸出、DNS 也跟著卡住（按 Esc 恢復）。3.1.0 起 `kuroshio run` 啟動時會自動把它關掉（日誌會有一行「已關閉主控台的「快速編輯模式」」），不用自己設定。
  - 3.1.0 以前的版本：在視窗標題列按右鍵 →「內容」→ 取消「快速編輯模式」，或改用服務。

### 方式二：Windows 服務（長期 24 小時運作，建議）

```bat
kuroshio.exe service install -c D:\kuroshio\config.json
kuroshio.exe service start
kuroshio.exe service status
```

開機自動啟動、不用登入、當掉 1 秒內自動重啟；跟 cmd 用同一份設定與資料，可以先用 cmd 測試再改成服務。日誌寫在設定檔旁邊的 `kuroshio.log`（設定頁「日誌」分頁也看得到）。`service stop`、`service uninstall` 停止與移除。服務執行中用 `kuroshio.exe url` 取得設定頁網址。

## 5. 測試

```bat
kuroshio.exe query www.google.com -s 127.0.0.1:53
kuroshio.exe query www.google.com -s https://dns.example.net/dns-query
kuroshio.exe query www.google.com -s h3://dns.example.net/dns-query
kuroshio.exe query www.google.com -s tls://dns.example.net
kuroshio.exe query www.google.com -s quic://dns.example.net
```

從外面測：手機關掉 Wi-Fi，Android「私人 DNS」填 `dns.example.net`（DoT）；瀏覽器開 `https://dns.example.net/` 看公開頁。預設只開放台灣 IP 與區網（「連線來源」可以改），用國外 VPN 測會被擋。

## 6. 升級

停止（`quit` 或 `service stop`）→ 用新版的 `kuroshio.exe` 和 `data\` 取代舊的 → 啟動。`config.json`、`state\`、`custom-rules.txt` 不用動。

## 常見問題

| 狀況 | 原因與處理 |
|---|---|
| `setup` 只加了 53 埠的防火牆規則、`httpsys status` 說需要網域 | 沒讀到你的 `config.json`：路徑打錯、或存成了 `config.json.txt`。`dir` 看檔名，`kuroshio.exe paths` 看 `configFile` |
| `'kuroshio.exe' is not recognized`（代碼 9009） | 執行的資料夾裡沒有 `kuroshio.exe`。`run.cmd` 的 `KDIR` 改成實際的資料夾 |
| 日誌出現「讀不到 …\geo\tw-ip.json」「台灣 IP 資料不能用，暫時不擋任何來源」 | `data\` 不在執行檔旁邊（或 `system.dataDir` 指錯）。zip 解壓後是 `kuroshio\data\`，要放的是這個 `data` 資料夾本身 |
| 公開頁 / 設定頁打不開，日誌有「讀取網頁檔 …\site\index.html 失敗」 | 同上，`data\` 位置不對 |
| 畫面出現 `[2m`、`[32m` 這種字 | 3.0.1 以前的版本在傳統主控台不會開啟顏色；升級，或設 `NO_COLOR=1` |
| DoH 通了，DoH3 外面連不到 | 範例 D 少了 `http3Binds`；或路由器沒有轉 UDP 443 |
| DoQ 外面連不到 | 路由器沒有轉 UDP 853 |
| 憑證續期了但 HTTPS 還是舊的 | HTTP.sys / IIS 的綁定要系統管理員權限才能更新：cmd 用系統管理員執行，或改用服務。`kuroshio.exe httpsys cert` 立即同步 |
| 53 埠被占用（日誌說監聽失敗） | Hyper-V 的預設交換器、網路連線共用（ICS）、其他 DNS 軟體會佔 53 埠：`netstat -ano \| findstr :53` 找出程式（最後一欄是 PID），或改 `listen.plain.port` |
| cmd 視窗點一下之後畫面不動、DNS 也沒回應，按 Esc 才恢復 | 傳統主控台的「快速編輯模式」。3.1.0 起啟動時會自動關掉；以前的版本在標題列右鍵 →「內容」取消，或改用服務 |
| 啟動失敗、不知道設定哪裡錯 | `kuroshio.exe check-config config.json`；設定頁存了一份啟動不了的設定時，程式會自動退回上一份能用的 |

更多細節：[規格 07 · Windows 版](spec/07-windows.md)。
