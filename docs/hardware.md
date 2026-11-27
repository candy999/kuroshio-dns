# 選硬體

黑潮 DNS 可以裝在 OpenWrt 路由器、軟路由，以及 Padavan 等第三方韌體上。這份文件告訴你**該買什麼**；手邊已經有舊機、想查怎麼刷的，看[各機種刷機資料](hardware-details.md)。

> 只列一般人公開買得到的機種（台灣通路、淘寶、閒魚的新品或二手）。資料整理於 2026 年 11 月，依據 OpenWrt 24.10 / 25.12、ImmortalWrt 25.12 的正式版機種清單與恩山論壇、OpenWrt 論壇的討論。標「未查證」的是還沒找到可靠來源的項目。

## 先看這裡：照預算買

### 💲 千元以下：一台 Wi-Fi 6 路由器

| 用途 | 買這些 |
|---|---|
| Wi-Fi 路由器 | **MT7981**：中國移動 RAX3000M、H3C NX30 Pro、小米 AX3000T（台灣小米有賣，約一千出頭）、小米 WR30U、360 T7<br>**IPQ807x 二手**：紅米 AX6、小米 AX3600 |
| 有線軟路由（Wi-Fi 另接 AP） | NanoPi R2S / R2C、HINLINK H28K、Orange Pi R1 Plus LTS |

### 💲💲 一千到三千

| 用途 | 買這些 |
|---|---|
| Wi-Fi 路由器 | **MT7986**：紅米 AX6000、磊科 N60 Pro、TP-Link XDR6086 / XDR6088、京東雲百里<br>**IPQ807x**：小米 AX9000、Linksys MX4200 |
| 新機、要保固 | OpenWrt One、Cudy WR3000 系列 |
| 有線軟路由 | NanoPi R5S / R4S / R5C、電犀牛 R66S |

### 💲💲💲 三千到八千：高階 Wi-Fi 6 路由器

| 用途 | 買這些 |
|---|---|
| Wi-Fi 路由器 | **MT7986**：GL.iNet MT6000（Flint 2）、ASUS TUF-AX6000、ASUS TUF-AX4200；開發板 Banana Pi R3 |
| 有線軟路由 | NanoPi R6S / R6C（RK3588S） |

### 💲💲💲💲 八千以上：N100 軟路由 + AP

**預算超過 N100 軟路由加一台 AP 的價錢，就不要再買更貴的 Wi-Fi 路由器（例如上萬元的 Wi-Fi 7 機）**，改買「Intel N100 多網口軟路由 + 無線基地台（AP）」：

- **為什麼**：N100 跑滿 2.5G PPPoE 也很輕鬆，記憶體夠大可以把黑潮 DNS 的大清單全開，OpenWrt 對 x86 的支援最穩。Wi-Fi 交給 AP，之後想升級 Wi-Fi 7 只要換 AP。企業、重視穩定的也建議這個組合。
- **大概要多少**（2026 年 11 月台灣行情，會變動）：
  - 四口 2.5G 的 N100 準系統：約新台幣 5,000–6,500 元
  - 記憶體：**今年漲了四到五倍**，DDR4 8 GB 筆電記憶體約 2,000–3,600 元，DDR5 更貴。黑潮 DNS 加 OpenWrt 4–8 GB 就很夠，**選用 DDR4 的機種比較省**
  - 儲存：小容量 SSD 或 eMMC 就夠（SSD 也在漲價）
  - AP：拿一台小米 AX3000T 當 AP 約 1,000–1,300 元；吸頂 AP（Zyxel NWA50AX、UniFi U6 Lite）約 2,600–4,500 元
  - **合計約 9,000–14,000 元**。淘寶的準系統便宜很多，但記憶體一樣貴，還要算運費與保固
- **軟路由**：Intel N100 / N150 的四至六口 2.5G 小主機，網卡選 Intel i226 或 i225 B3（見 [x86](#intel--amd-x86_64)）。
- **AP**：**不用刷 OpenWrt**，原廠韌體設成 AP 模式就好（黑潮 DNS 只裝在軟路由上）。
  - 最省：拿一台 💲💲 的小米 AX3000T 或 💲 的 RAX3000M 當 AP
  - 吸頂 AP：COMFAST CF-E393AX（💲）、Zyxel NWA50AX、TP-Link EAP613（💲💲～💲💲💲）
  - 企業常用：Ubiquiti UniFi U6-LR、U6 Lite（💲💲💲）

### 特殊用途

| 需求 | 買這些 |
|---|---|
| 旅行路由器 | GL.iNet MT3000、Cudy TR3000（💲💲）；預算更低：GL.iNet MT300N-V2、AR750S（128 MB，夠用但偏緊） |
| 5G 插卡 | Zbtlink Z8102AX（💲💲，5G 模組另購） |
| 企業、重視穩定 | N100 以上的 x86 軟路由 + UniFi / Zyxel / TP-Link Omada 的 AP（約 1 萬元起），全部是 OpenWrt 官方支援、資源最多的組合 |
| 手邊已有舊機 | 照樣可以用，不用為了黑潮 DNS 換機；刷機方式見[各機種刷機資料](hardware-details.md) |
| 手邊是 MT7621 低階機（128 MB 記憶體、16 MB 儲存，例如紅米 AC2100、小米 4A 千兆、斐訊 K2P、小米 CR6608） | 改刷 [padavan-tw](#低階路由器改用-padavan-tw)，比 OpenWrt 輕，已經整合黑潮 DNS |
| 避開 | 記憶體 64 MB 以下、儲存 8 MB 的機種；J1900、AMD GX-415GA 這類跑不滿千兆的 x86；桌上型與舊伺服器（太耗電）；比 N100 + AP 還貴的 Wi-Fi 路由器（上萬元的 Wi-Fi 7 機，改 N100 + AP） |

## 黑潮 DNS 需要多少

- **記憶體**：64 MB 以下不支援；128 MB 可以用（預設清單）；256 MB 舒適；512 MB 以上可以開預設不勾選的大清單。
- **儲存**：8 MB 裝不下；16 MB 安裝後要剩 4 MB 以上；32 MB 以上或 NAND / eMMC 最舒適。
  - 放學習資料的空間很小時（例如 padavan 的 7.5 MB 狀態分割區）：3.5.0 起 CDN 網域資料最多用 30%，超過就淘汰最久沒人查的網域，把空間留給過濾清單的本機副本（`cdn.dbDiskBudgetKB`，64 MB 以上不限）。功能都在，只是記得的網域比較少。
- **CPU**：DNS 本身很輕，差別在加密連線多的時候、CDN 驗證與每日評測的速度。

## 怎麼看後面的表

- **類別**：🧩 開源型號（出貨就是 OpenWrt、開發板）　🛒 市售新品　♻️ 二手、停產、拆機　📡 電信業者客製版（閒魚、淘寶公開買得到）
- **成熟度**：🟢 官方正式版支援、教學很多　🟡 官方支援但教學少　🟠 只有分支韌體支援
- **刷機**：① 原廠網頁直刷　② 要 SSH / 漏洞　③ 要接序列埠或 TFTP　④ 要編程器
- **價位**：💲 新台幣一千以下　💲💲 一千到三千　💲💲💲 三千到八千　💲💲💲💲 八千以上（二手照二手行情）

表格只列**推薦買**的機種。同價位有更好選擇的、比 N100 + AP 還貴的、又貴支援又少的，都列在每節最後的摺疊清單。

## 推薦的晶片組

### MediaTek MT7981（Filogic 820）

- **規格**：雙核 Cortex-A53 1.3 GHz、Wi-Fi 6（AX3000）；記憶體 256 MB–1 GB，儲存多半是 128 MB NAND
- **套件架構**：`aarch64_cortex-a53`
- **適合**：💲 預算的首選。官方支援幾十台，恩山資源最多
- **注意**：恩山的 bl-mt798x U-Boot 和 OpenWrt 官方的 ubootmod 分區互不相容，刷哪一套就要用對應的韌體

| 類別 | 型號 | 記憶體 / 儲存 | 成熟度 | 刷機 | 價位 | 備註 |
|---|---|---|---|---|---|---|
| 📡 | 中國移動 RAX3000M / RAX3000Me | 512 MB / 128 MB NAND 或 64 GB eMMC | 🟢 | ② | 💲 | 恩山最熱門的刷機機。NAND 版與 eMMC 版韌體不同（機身標 `CH EC` 是 eMMC） |
| 🛒 | H3C Magic NX30 Pro | 256 MB / 128 MB NAND | 🟢 | ② | 💲 | 中國零售機，淘寶、閒魚 |
| 🛒 | 小米 AX3000T（台灣 RD23、中國 RD03） | 256 MB / 128 MB NAND | 🟢 | ② | 💲～💲💲 | 台灣小米有賣。新批次（RD23 原廠韌體 1.0.76、RD03 1.0.84 以後）換了交換器晶片，官方韌體網路埠不能用，要恩山的分支韌體 |
| 📡 | 小米 WR30U（中國聯通版） | 256 MB / 128 MB NAND | 🟢 | ② | 💲 | 聯通版的 AX3000，閒魚 |
| ♻️ | 360 T7 | 256 MB / 128 MB NAND | 🟢 | ③ | 💲 | 已停產，閒魚很多；恩山有免拆方法（未查證是否所有批次都適用） |
| 🧩 | OpenWrt One | 1 GB / 16 MB NOR + 128 MB NAND | 🟢 | ① | 💲💲 | OpenWrt 官方硬體，幾乎刷不壞；要從海外購買 |
| 🛒 | Cudy WR3000 系列 | 256–512 MB / 16 MB NOR 或 128–256 MB NAND | 🟢 | ① | 💲💲 | 原廠提供 OpenWrt 過渡韌體；每個型號韌體不同，WR3000 2.0 不支援 |
| 🧩 | GL.iNet GL-MT3000 | 512 MB / 256 MB NAND | 🟢 | ① | 💲💲 | 旅行路由器，2.5G WAN；台灣蝦皮、PChome 有賣 |
| 🛒 | Cudy TR3000 v1 | 512 MB / 128–256 MB NAND | 🟢 | ① | 💲💲 | 旅行路由器；序號 2544 以後換了快閃記憶體，不能刷舊版韌體 |
| 🛒 | Zbtlink ZBT-Z8102AX | 1 GB / 128 MB NAND | 🟡 | ① | 💲💲 | 5G 插卡路由器（模組另購），原廠就是 OpenWrt |
| 🛒 | COMFAST CF-E393AX / CF-E395AX | 256 MB / 128 MB NAND | 🟡 | ② | 💲 | 便宜的吸頂 AP |

<details>
<summary>不建議特地買的 MT7981 機種</summary>

- **同價位有更好的**：GL.iNet MT2500、ASUS RT-AX52、D-Link M30、MERCUSYS MR80X v3、磊科 N30 Pro、JCG Q30 Pro、銳捷 X30E、中國移動 XR30、中國移動 A10、Nokia EA0326GMP、ABT ASR3000、創維 CT3003、康佳 A31 → 💲 改買上表的 RAX3000M、紅米 AX6；💲💲 改買 NanoPi R5S、磊科 N60 Pro
- **貴又支援少**：GL.iNet X3000、Zyxel NWA50AX Pro、UniFi U6+
- **台灣、中國不好買**：Keenetic、Routerich、ipTIME、Netgear EAX、ELECOM、TP-Link Festa、Teltonika RUTC50

</details>

### MediaTek MT7986（Filogic 830）

- **規格**：四核 Cortex-A53 2.0 GHz、Wi-Fi 6（AX6000）、支援 2.5G；記憶體 512 MB–1 GB
- **套件架構**：`aarch64_cortex-a53`
- **適合**：💲💲～💲💲💲 預算的 Wi-Fi 6 主路由首選，效能明顯比 MT7981 好

| 類別 | 型號 | 記憶體 / 儲存 | 成熟度 | 刷機 | 價位 | 備註 |
|---|---|---|---|---|---|---|
| ♻️ | 紅米 Redmi AX6000 | 512 MB / 128 MB NAND | 🟢 | ② | 💲💲 | 閒魚很多，恩山教學最多 |
| 🛒 | 磊科 Netcore N60 Pro | 512 MB / 128 MB NAND | 🟢 | ② | 💲💲 | 中國零售機，恩山很熱門 |
| 🛒 | TP-Link TL-XDR6086 / XDR6088 / XDR4288 | 512 MB / 128 MB NAND | 🟢 | ② | 💲💲 | 中國版 TP-Link（不是台灣版），淘寶、閒魚 |
| ♻️ | 京東雲 RE-CP-03（百里 AX6000） | 1 GB / 128 GB eMMC | 🟢 | ② | 💲💲 | eMMC 很大，可當小 NAS；要先刷過渡韌體 |
| 🧩 | GL.iNet GL-MT6000（Flint 2） | 1 GB / 8 GB eMMC | 🟢 | ① | 💲💲💲 | 原廠就是 OpenWrt，OpenWrt 論壇最推薦的 Wi-Fi 6 主路由之一 |
| 🛒 | ASUS TUF-AX6000 | 512 MB / 256 MB NAND | 🟢 | ③ | 💲💲💲 | 台灣有賣；序列埠從外殼孔接，不用拆機也不用焊 |
| 🛒 | ASUS TUF-AX4200 / TUF-AX4200Q | 512 MB / 256 MB NAND | 🟢 | ③ | 💲💲💲 | 台灣有賣；4200Q 可從原廠網頁直刷 |
| 🧩 | Banana Pi BPi-R3 | 2 GB / NAND + NOR + 8 GB eMMC | 🟢 | ① | 💲💲💲 | 開發板，2 個 SFP；外殼、天線要自己配 |

<details>
<summary>不建議特地買的 MT7986 機種</summary>

- **同價位有更好的**：磊科 N60、TP-Link XTR8488、銳捷 RG-X60 Pro → 改買上表的機種
- **貴又支援少**：Banana Pi R3 Mini、ASUS RT-AX59U、D-Link M60、Acer W6、MERCUSYS MR90X
- **台灣、中國不好買**：Zyxel EX5601、JioRouter、Adtran SDG、Buffalo、ELECOM、ipTIME、TP-Link Archer AX80、Netgear WAX220、Wavlink

</details>

### Qualcomm IPQ807x

- **規格**：四核 Cortex-A53 1.4–2.2 GHz、Wi-Fi 6；記憶體 512 MB–2 GB
- **套件架構**：`aarch64_cortex-a53`
- **適合**：便宜買到 512 MB 以上的二手 Wi-Fi 6 機
- **注意**：硬體加速（NSS）只在第三方分支韌體有，官方版 NAT 靠 CPU；黑潮 DNS 不受影響

| 類別 | 型號 | 記憶體 / 儲存 | 成熟度 | 刷機 | 價位 | 備註 |
|---|---|---|---|---|---|---|
| ♻️ | 紅米 AX6 | 512 MB / 128 MB NAND | 🟢 | ② | 💲 | 閒魚很便宜，教學多 |
| ♻️ | 小米 AX3600 | 512 MB / 256 MB NAND | 🟢 | ② | 💲～💲💲 | 恩山最熱門的 Wi-Fi 6 機之一 |
| ♻️ | 小米 AX9000 | 1 GB / 256 MB NAND | 🟢 | ② | 💲💲 | 三頻，2.2 GHz |
| ♻️ | Linksys MX4200 v1 / v2 | 512 MB–1 GB / 512 MB NAND | 🟢 | ① | 💲💲 | 原廠網頁直刷、雙分區，刷壞可以切回去 |
| ♻️ | Linksys MX4300 | 2 GB / 1 GB NAND | 🟢 | ① | 💲💲 | 美國 Costco 版，閒魚、淘寶有（台灣通路未查證） |

<details>
<summary>不建議特地買的 IPQ807x 機種</summary>

- **同價位有更好的**：Linksys MX5300、Netgear Orbi RBK752、ZTE MF269、中國移動 RM2-6 → 改買上表的機種
- **貴又支援少**：ASUS RT-AX89X
- **台灣、中國不好買**：Dynalink WRX36、Netgear RAX120v2 / WAX、QNAP 301W、Buffalo WXR-5950AX12、Zyxel NBG7815、TP-Link EAP620 / EAP660 HD

</details>

### Rockchip（NanoPi 等軟路由盒子）

- **規格**：RK3328 / RK3528（入門）、RK3568 / RK3399（主流）、RK3588（高階）；記憶體 1–8 GB，microSD 或 eMMC 開機
- **套件架構**：`aarch64_generic`
- **適合**：有線軟路由（沒有路由用的 Wi-Fi，另接 AP），3–10 W、多數免風扇
- **注意**：刷機就是把映像檔寫進 microSD 卡；變磚按 MaskROM 鍵用 USB 救回

| 類別 | 型號 | 記憶體 / 儲存 | 成熟度 | 刷機 | 價位 | 備註 |
|---|---|---|---|---|---|---|
| 🧩 | NanoPi R2S / R2C（RK3328） | 1 GB / microSD | 🟢 | ① | 💲～💲💲 | 2 個千兆口，教學最多；其中一個是 USB 轉網卡，滿載會熱 |
| 🛒 | HINLINK H28K（RK3528） | 1–4 GB / microSD 或 eMMC | 🟢 | ① | 💲 | 2 個千兆口（不是 2.5G），USB-C 供電 |
| 🧩 | Orange Pi R1 Plus LTS（RK3328） | 1 GB / microSD | 🟢 | ① | 💲 | 比 R2S 便宜 |
| 🧩 | NanoPi R5S（RK3568） | 2–4 GB / 8–32 GB eMMC | 🟢 | ① | 💲💲～💲💲💲 | 2 個 2.5G + 1 個千兆，恩山討論最多的 2.5G ARM 軟路由 |
| 🧩 | NanoPi R5C（RK3568） | 1–4 GB / 0–32 GB eMMC | 🟢 | ① | 💲💲 | 2 個 2.5G，有 M.2 Wi-Fi 插槽 |
| 🧩 | NanoPi R4S（RK3399） | 1 或 4 GB / microSD | 🟢 | ① | 💲💲 | 2 個千兆口經典款，多為二手 |
| 🛒 | 電犀牛 R66S（RK3568） | 1–4 GB / microSD | 🟢 | ① | 💲💲 | 2 個 2.5G，淘寶、閒魚 |
| 🧩 | NanoPi R6S（RK3588S） | 8 GB / 32 GB eMMC | 🟢 | ① | 💲💲💲 | 2 個 2.5G + 1 個千兆，ARM 軟路由效能頂端 |
| 🧩 | NanoPi R6C（RK3588S） | 4–8 GB / 0–32 GB eMMC | 🟢 | ① | 💲💲💲 | 1 個 2.5G + 1 個千兆，有 M.2 NVMe |

<details>
<summary>不建議特地買的 Rockchip 機種</summary>

- **同價位有更好的**：NanoPi R3S、NanoPi R76S、Radxa E20C、Radxa E52C、電犀牛 R68S、EasePi R1 → 💲 改買 H28K、R2S；💲💲 改買 R5S、R4S
- **貴又支援少**：Radxa ROCK 5、Orange Pi 5 Plus
- 電視盒改機（RK3528 / RK3566）要短接 eMMC，也沒有正式韌體，不建議

</details>

### Intel / AMD x86_64

- **套件架構**：`x86_64`（一個韌體通吃，寫進隨身碟或 SSD 開機）
- **適合**：八千元以上的預算（N100 + AP）、企業、多 WAN、要開大清單；二手精簡型電腦加網卡可以更便宜
- **選購條件**：
  - 至少兩個網口；網卡選 Intel i226、i225 **B3**、i210 / i211（i225 B1 / B2 會掉線），Realtek RTL8125 也可以；不要用 USB 網卡當主要網口
  - 記憶體 2 GB 就夠，4 GB 以上很充裕（記憶體 2026 年大漲，不用買到 16 GB）；儲存 8 GB 以上 SSD 或 eMMC
  - CPU 要有 AES-NI（加密 DNS、VPN 會用到）
  - 24 小時開機：CPU 功耗 25 W 以下、整機閒置 15 W 以下（每 10 W 一年約 260–440 元電費）

| CPU | 功耗 | 常見在哪 | 1000M PPPoE | 2.5G | 價位 |
|---|---|---|---|---|---|
| **Intel N100 / N150**（首選） | 6 W | 新品四至六口 2.5G 小主機 | ✅ | ✅ | 💲💲💲💲（整機） |
| Intel N200 / N305 / N355 | 6–15 W | 新品多口機、10G 版 | ✅ | ✅ | 💲💲💲💲 |
| Intel N5095 / N5105 / N6005 | 10–15 W | 上一代四口 2.5G 機（二手） | ✅ | ✅（未查證） | 💲💲💲 |
| Intel J4105 / J4125 / J5005 | 10 W | 四口 i225 機、Dell Wyse 5070、Fujitsu S740 | ✅ | 約 1.8 Gbps | 💲💲～💲💲💲（二手） |
| AMD RX-427BB | 15 W | HP t730（二手，可加網卡） | ✅ | 未查證 | 💲💲 |
| AMD Ryzen R1505G / R1606G | 12–25 W | HP t640（二手） | ✅ | ✅（未查證） | 💲💲 |
| Intel Core i3 / i5 低壓版 | 15 W | 中高階多口機 | ✅ | ✅ | 💲💲💲💲 |

- **勉強可用**（二手很便宜才考慮）：Intel J3455 / J3160、Celeron 3855U–5205U（雙核）、Atom E38xx / C2000（二手防火牆；C2000 有老化瑕疵）、AMD GX-412TC（PC Engines APU）、AMD GX-420CA / GX-424CC（HP t620 Plus、Wyse 5060）、Atom x5-Z8350（Wyse 3040，單網口）、Ryzen V1756B（HP t740，35–54 W 太耗電）
- **不划算**：Intel J1900（沒有 AES-NI，PPPoE 跑不滿）、AMD GX-212JC / GX-217GA / GX-415GA（HP t520、t620）、桌上型與舊伺服器 CPU（閒置 20–100 W）→ 改買 N100 新機，或 J4125、N5105 二手機
- **虛擬機**：Proxmox、ESXi、Hyper-V、群暉 / 威聯通都能跑；主機重開機會全家斷網，NAS 上的虛擬機建議只當次要 DNS

## 不建議特地買的晶片組

手邊已經有的**照樣可以用**，刷機方式見[各機種刷機資料](hardware-details.md)；要買的話照[先看這裡](#先看這裡照預算買)的建議。

| 晶片組 | 為什麼不建議 | 改買 |
|---|---|---|
| MediaTek MT7621（MIPS） | 效能比同價位的 MT7981 差很多；手邊有的建議改刷 [padavan-tw](#低階路由器改用-padavan-tw) | 💲 MT7981 |
| MediaTek MT7620 / MT7628（MIPS） | 單核、多數只有 64 MB；只剩 GL.iNet MT300N-V2 這類旅行路由器還能用 | 💲 MT7981 |
| MediaTek MT7622 | 上一代，同價位 MT7981 更好；UniFi U6-LR 這類 AP 照樣好用 | 💲 MT7981 |
| MediaTek MT7987 / MT7988（Wi-Fi 7） | 驅動還在成熟中，能刷的市售機少 | 💲💲～💲💲💲 MT7986，或 N100 + AP |
| Qualcomm IPQ60xx / IPQ50xx | 官方 25.12 才開始支援，多數機種只有分支韌體 | 💲 紅米 AX6；💲💲 MT7986 |
| Qualcomm IPQ40xx / IPQ806x（32 位元 ARM） | 上一代，同價位效能差很多 | 💲 MT7981 / 紅米 AX6 |
| Marvell Armada 385 / 3720 / 7040 | 二手不便宜、新品少；Turris Omnia 官方支援很好但比 N100 + AP 貴 | 💲💲 MT7986，或 N100 + AP |
| 樹莓派 3 / 4 / 5 | 只有一個網口，同價位的 NanoPi 有兩個 | 💲 NanoPi R2S；💲💲 NanoPi R5S |
| Allwinner（全志） | 多是單網口開發板 | 💲 H28K、R2S |
| Qualcomm Atheros ath79、Lantiq（MIPS） | 多數只有 64 MB；Lantiq 是歐洲 DSL 機 | 💲 MT7981 |

## 低階路由器：改用 padavan-tw

記憶體 128 MB、儲存 16 MB 的 MT7621 老機，裝 OpenWrt 加 LuCI 再加黑潮 DNS 會很吃緊。這類機器建議改刷 [padavan-tw](https://github.com/candy999/padavan-tw)：

- **是什麼**：為台灣網路環境打造的 Padavan 韌體，用聯發科原廠的閉源無線與硬體 NAT 驅動，比 OpenWrt 輕、穩定，介面是台灣中文，已經在 Newifi D3 實機整合黑潮 DNS
- **正式維護**（每次修改都編譯、有實機測試）：Newifi D3（新路由 3）、小米 CR6608（CR6606 / CR6609 理論上也適用）
- **社群支援**（可以自己用 GitHub Actions 編譯，維護者沒有實機測試）：紅米 / 小米 AC2100、小米 4A 千兆版、小米 R3G / R3P / 路由器 4、斐訊 K2P、D-Link DIR-878 / DIR-882、ASUS RT-AC85P、Linksys EA7500、Netgear R6800 / R7450、JCG Q20 / Y2、京東雲 RE-SP-01B / RE-CP-02、H3C TX1801 Plus、中興 E8820S 等 50 多台，完整清單見 padavan-tw 的 README
- **接在另一台黑潮後面**：MT7621 沒有 AES 指令，加密 DNS 比較吃 CPU。主路由器也跑黑潮（3.4.0 以上）、而且把 53 埠接走時，兩台會自動串接：這台直接問主路由器、用它的評測結果與 CDN 節點池，不再自己跑每日評測與 CDN 掃描（見[串接模式](guide/chain.md)）
- **注意**：只支援 MT7621；Linux 4.4 核心已經停止官方維護，不要把管理頁面或 SSH 開放到 WAN
- MT7620 / MT7628 這類更低階、記憶體只有 64 MB 的機器，padavan-tw 和黑潮 DNS 都不支援，建議換一台 💲 的 MT7981

## 查你的路由器、下載套件

在路由器上用 SSH 執行：

```sh
cat /etc/openwrt_release      # DISTRIB_ARCH（套件架構）、DISTRIB_RELEASE（OpenWrt 版本）
free -m                       # 記憶體
df -h /overlay                # 剩餘的儲存空間
```

- 到 GitHub **Releases** 下載 `kuroshio-openwrt-<OpenWrt 版本>-<套件架構>.zip`，例如 OpenWrt 24.10 的 NanoPi R2S 下載 `kuroshio-openwrt-24.10-aarch64_generic.zip`。安裝方式見 [`openwrt/README.md`](../openwrt/README.md)。
- 24.10 用 `.ipk`，25.12 以後用 `.apk`；ImmortalWrt 等分支看它跟哪一版 OpenWrt 同步。
- Padavan、梅林等第三方韌體用 `kuroshio-linux-<CPU>.tar.gz`（見 [移植指南](../PORTING.md)）；x86 電腦也可以用 Linux 執行檔、Windows 版或 [Docker](docker.md)。

## 價格依據

價位級距與 N100 + AP 的估算依據 2026 年 11 月的比價網站與報導，價格變動很快（記憶體、SSD 今年大漲），買之前請以賣場當下的價格為準：

- N100 軟路由：[飛比價格](https://feebee.com.tw/s/n100%E8%BB%9F%E8%B7%AF%E7%94%B1/)、[BigGo「n100 2.5g」](https://biggo.com.tw/s/n100%202.5g/)、[BigGo「N100 雙網口」](https://biggo.com.tw/s/N100%20%E9%9B%99%E7%B6%B2%E5%8F%A3)；中國行情：[什麼值得買](https://post.smzdm.com/p/aqrq9w9k/)、[V2EX](https://fast.v2ex.com/t/1190659)
- 記憶體：[飛比價格 DDR5 16GB](https://feebee.com.tw/all/ddr5%2016gb/)、[BigGo DDR4 8GB SO-DIMM](https://biggo.com.tw/s/SO%20Dimm%20DDR4%208GB)、[新新聞：記憶體漲幅五倍半](https://www.storm.mg/article/5571855)
- AP：[UniFi U6-Lite（英菲達）](https://store.innotrust.com.tw/product/detail/570925)、[BigGo「wifi6 ap」](https://biggo.com.tw/s/wifi6%20ap)
- 路由器：[小米 AX3000T（momo）](https://www.momoshop.com.tw/product/13334699)、[ASUS TUF-AX6000（PChome）](https://24h.pchome.com.tw/prod/DRAFJ5-A900GR2WG)、[GL.iNet MT6000（官網）](https://www.gl-inet.com/en-us/products/gl-mt6000)

