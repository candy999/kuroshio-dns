# 各機種刷機資料

這是選購調查的完整資料：每台機種的規格、刷機方式、救磚方法與注意事項，給**手邊已經有這些機器**、想刷 OpenWrt 跑黑潮 DNS 的人查。**要買什麼請看[選硬體](hardware.md)**，這裡很多機種並不建議特地去買。

> 資料整理於 2026 年 11 月，依據 OpenWrt 24.10 / 25.12、ImmortalWrt 25.12 的正式版機種清單、OpenWrt 硬體表、恩山論壇與 OpenWrt 論壇。同一個型號常有不同硬體版本，刷之前請以你手上那台的實際版本為準。標「未查證」的是還沒找到可靠來源的項目。x86 依 CPU 挑，見[選硬體的 x86 一節](hardware.md#intel--amd-x86_64)。

- **類別**：🧩 開源型號　🛒 市售新品　♻️ 二手、停產、拆機　📡 電信業者客製版
- **成熟度**：🟢 官方正式版支援、教學很多　🟡 官方支援但教學少　🟠 只有分支韌體支援　🔴 冷門
- **刷機**：① 原廠網頁直刷　② 要 SSH / 漏洞　③ 要接序列埠或 TFTP　④ 要編程器
- **價位**：💲 新台幣一千以下　💲💲 一千到三千　💲💲💲 三千以上（調查時的級距；目前行情見[選硬體的價格依據](hardware.md#價格依據)）

## 1. 64 位元 ARM（AArch64）—— 新機首選

目前主流：Wi-Fi 6 / 7 路由器、軟路由盒子、開發板都是這一類。效能好、記憶體大，黑潮 DNS 全部功能都能開。

### MediaTek MT7981（Filogic 820）

雙核 Cortex-A53 1.3 GHz，內建 Wi-Fi 6 雙頻 2x2（AX3000），套件架構 `aarch64_cortex-a53`（OpenWrt target `mediatek/filogic`）。記憶體大多是 256 MB 或 512 MB，少數 1 GB；儲存大多是 128 MB SPI-NAND，少數是 16 MB NOR（空間很緊）或 eMMC。這顆是現在「便宜刷機路由器」的主流：中國的電信機、小米、H3C 都很便宜就買得到，OpenWrt 官方支援幾十台，跑黑潮 DNS 綽綽有餘。沒有 64 MB 記憶體的機種。整個 filogic 家族的機種多半刷 hanwckf / 237 的 `bl-mt798x` U-Boot（網頁救援，按住 reset 開機進 192.168.1.1），或 OpenWrt 官方的「OpenWrt U-Boot layout（ubootmod）」，**這兩套分區互不相容**，選哪一套就要用對應的韌體。

| 類別 | 型號 | 記憶體 / 儲存 | 成熟度 | 刷機 | 價位 | 備註 |
|---|---|---|---|---|---|---|
| 🧩 | GL.iNet GL-MT3000（Beryl AX） | 512 MB / 256 MB NAND | 🟢 | ① | 💲💲 | 原廠韌體就是 OpenWrt，可直接刷官方 sysupgrade；內建 U-Boot 網頁救援。台灣蝦皮、PChome 買得到的旅行路由器，2.5G WAN。 |
| 🧩 | OpenWrt One | 1 GB / 16 MB NOR + 128 MB NAND | 🟢 | ① | 💲💲 | OpenWrt 官方硬體，出貨就是 OpenWrt；NOR 上有救援系統，幾乎刷不壞。台灣要從海外（AliExpress 等）購買。 |
| 🧩 | GL.iNet GL-MT2500（Brume 2） | 1 GB / 8 GB eMMC | 🟡 | ① | 💲💲 | **沒有 Wi-Fi**，是有線的小型閘道器 / VPN 盒，拿來當旁路 DNS 很合適。有 MaxLinear 與 Airoha PHY 兩個版本，韌體不同，要選對。救磚要接序列埠。 |
| 🧩 | GL.iNet GL-X3000 / GL-XE3000 | 512 MB / 8 GB eMMC + microSD | 🟡 | ① | 💲💲💲 | 5G 行動網路路由器（XE3000 是電池版），原廠是 OpenWrt。 |
| 🛒 | 小米路由器 AX3000T（台灣版 RD23、中國版 RD03） | 256 MB / 128 MB NAND | 🟢 | ② | 💲 | 台灣小米官網有賣。用 xmir-patcher 開 SSH 再刷 U-Boot。**注意**：新批次（RD03 原廠韌體 1.0.84 以後、RD23 1.0.76 以後）換成 AN8855 交換器晶片，OpenWrt 官方 25.12 不支援網路埠，只能用恩山的 `ax3000t_an8855` U-Boot 加分支韌體；買之前先看韌體版本。 |
| 🛒 | Cudy TR3000 v1 | 512 MB / 128 MB 或 256 MB NAND | 🟢 | ① | 💲💲 | 小型旅行路由器，2.5G 埠。Cudy 官網提供「OpenWrt 中繼韌體」可從原廠網頁直接刷。128 MB 與 256 MB 快閃記憶體版本的韌體不同；2025 年 11 月起生產（序號 2544 以後）換了 F50L1G41LC 快閃記憶體，刷舊版韌體會無法開機。恩山熱度高。 |
| 🛒 | Cudy WR3000 系列（WR3000 v1、WR3000S、WR3000E、WR3000H、WR3000P、WR3000U） | WR3000 v1：256 MB / 16 MB NOR；S、E、H：256 MB / 128 MB NAND；P、U：512 MB / 128 MB 或 256 MB NAND | 🟢 | ① | 💲💲 | 每個型號的韌體都不一樣，要對型號與版本（WR3000 2.0 是別的晶片，不支援）。WR3000 v1 只有 16 MB NOR，裝不了太多套件。Cudy 有繁中官網，台灣通路未查證，蝦皮跨境、AliExpress 買得到。 |
| 🛒 | ASUS RT-AX52 / RT-AX52 PRO | 256 MB / 128 MB NAND | 🟡 | ① | 💲💲 | 可從華碩原廠網頁上傳 OpenWrt 的 `initramfs.trx`，再 sysupgrade。台灣通路有沒有在賣（未查證）。 |
| 🛒 | D-Link AQUILA PRO AI M30（另有 E30） | 512 MB / 128 MB NAND | 🟡 | ① | 💲💲 | 台灣友訊有賣。用原廠救援網頁（192.168.200.1）刷 recovery 映像檔，不用拆機。原廠是雙分區，OpenWrt 只能放在目前使用中的分區。E30 是同系列的 Mesh 款，台灣有沒有賣（未查證）。 |
| 🛒 | Zyxel NWA50AX Pro / NWA90AX Pro | 512 MB / 256 MB NAND | 🟡 | ① | 💲💲💲 | 企業型吸頂 AP，台灣合勤有賣。原廠網頁可上傳 factory 映像檔，但只能刷在 Slot A。適合當 AP，不適合當主路由。 |
| 🛒 | Ubiquiti UniFi U6+ | 256 MB / 16 MB NOR + 4 GB eMMC | 🟡 | ② | 💲💲💲 | 用 SSH（預設帳密 ubnt）刷。吸頂 AP，台灣有代理。 |
| 🛒 | MERCUSYS MR80X **v3** | 512 MB / 128 MB NAND | 🟡 | ③ | 💲💲 | 只有 v3 是 MT7981，v1、v2 不支援。要接 TTL 用 TFTP 開 initramfs。台灣曾經上市（未查證現在還有沒有貨）。 |
| 🛒 | H3C Magic NX30 Pro | 256 MB / 128 MB NAND | 🟢 | ② | 💲 | 中國零售機，恩山最熱門的 MT7981 之一。原廠有 telnet（`telnet 192.168.124.1 99`），刷 Yuzhii 雙分區 U-Boot 就能刷 ImmortalWrt。恩山甚至有 Padavan 移植。淘寶、閒魚買。 |
| 🛒 | 磊科 Netcore N30 Pro（netis NX30 V2、POWER 30AX 同機） | 256 MB / 128 MB NAND | 🟡 | ② | 💲 | 中國零售機。SSH / telnet 進去刷 BL2 與 FIP。恩山有附 DHCP 的 U-Boot 與閉源驅動韌體。淘寶買。 |
| 🛒 | JCG Q30 Pro | 256 MB / 128 MB NAND | 🟡 | ③ | 💲 | 中國零售機，恩山有 EasyMesh 韌體。官方說明要接 TTL。 |
| 🛒 | Zbtlink ZBT-Z8102AX（另有 Z8103AX、Z8106AX） | Z8102AX：1 GB / 128 MB NAND；Z8103AX、Z8106AX：256 MB / 128 MB NAND | 🟡 | ① | 💲💲 | 中國廠牌的 5G 插卡路由器（M.2 模組要另買），原廠就是 OpenWrt 改版，有 U-Boot 網頁救援。淘寶、AliExpress 買。 |
| 🛒 | COMFAST CF-E393AX / CF-E395AX | 256 MB / 128 MB NAND | 🟡 | ② | 💲 | 中國廉價吸頂 AP。匯出設定檔改密碼開 SSH。淘寶買。 |
| 🛒 | 銳捷 Ruijie 星耀 X30E / X30E Pro | 256 MB / 128 MB NAND（未查證） | 🟠 | ② | 💲 | OpenWrt 官方沒有，靠恩山的 MT798x U-Boot（支援清單有 `ruijie_rg-x30e`）加 ImmortalWrt-mt798x 分支。淘寶、閒魚買。 |
| ♻️ | 360 T7 | 256 MB / 128 MB NAND | 🟢 | ③ | 💲 | 中國零售機，已停產，閒魚很多。官方說明要接 TTL 進 failsafe；恩山有「免拆」與 U-Boot 2025 方案（未查證是否所有批次都適用）。快閃記憶體有 ESMT、Winbond、GigaDevice 三種，恩山有各自的完整備份。 |
| 📡 | 中國移動 CMCC RAX3000M / RAX3000Me | 512 MB / 128 MB NAND 或 64 GB eMMC（算力版） | 🟢 | ② | 💲 | 恩山最熱門的刷機機，閒魚很便宜。NAND 版與 eMMC 版看機身標籤（`CH EC` 是 eMMC），韌體不同；還有 DDR3 與 DDR4 之分，要看開機記錄選對 BL2。匯出設定檔解密改開 SSH，再刷 U-Boot。新批次換 AN8855 交換器，OpenWrt 25.12 已支援。 |
| 📡 | 中國移動 CMCC XR30（NAND / eMMC） | 512 MB / 128 MB NAND 或 eMMC（未查證） | 🟠 | ② | 💲 | RAX3000M 的姊妹機，OpenWrt 官方沒有獨立型號，靠恩山 U-Boot（`cmcc_xr30`、`cmcc_xr30-emmc`）加 ImmortalWrt-mt798x 分支。用設定檔開 SSH；恩山有人回報 2024 年 4 月以後的批次無法用設定檔解鎖，只能接 TTL。 |
| 📡 | 小米 WR30U（中國聯通版） | 256 MB / 128 MB NAND | 🟢 | ② | 💲 | 聯通客製版的 AX3000，閒魚很便宜。開 SSH 後刷 OpenWrt U-Boot（ubootmod）。 |
| 📡 | 中國移動 CMCC A10（超級電子 ZN-M5 / ZN-M8 同機） | 256 MB / 128 MB NAND | 🟡 | ② | 💲 | 閒魚非常便宜。ZN-M5、ZN-M8 有另一版改用中興 ZX279128 晶片，**那一版不能刷**。 |
| 📡 | 諾基亞 Nokia EA0326GMP | 256 MB / 128 MB NAND | 🟡 | ② | 💲 | 電信配發機，閒魚有。改設定檔開 SSH。恩山有 EasyMesh 韌體。 |
| 📡 | ABT ASR3000 | 256 MB / 128 MB NAND | 🟡 | ② | 💲 | 電信配發機，閒魚有。改設定檔開 telnet。 |
| 📡 | 創維 Cetron CT3003 | 256 MB / 128 MB NAND | 🟡 | ① | 💲 | 電信配發機，閒魚有。可從原廠網頁直接上傳 factory.bin。 |
| 📡 | 康佳 Konka KOMI A31（E-Life ETR631-T / ETR635-U 同機） | 256 MB / 128 MB NAND | 🟡 | ② | 💲 | 電信配發機，閒魚有。改設定檔開 telnet。 |

其他官方有支援、但台灣與中國不容易買到的（沒列）：Keenetic、Routerich、ipTIME、Netgear EAX 系列、ELECOM、TP-Link Festa、Teltonika RUTC50、Airtel 等。

### MediaTek MT7986（Filogic 830）

四核 Cortex-A53 2.0 GHz，內建 Wi-Fi 6 雙頻 4x4（AX6000，MT7986A；MT7986B 是較低階的版本），支援 2.5G 網路，套件架構 `aarch64_cortex-a53`。記憶體 512 MB 到 1 GB（開發板 2 GB），儲存 128–256 MB NAND 或 eMMC。效能明顯比 MT7981 好，是現在 Wi-Fi 6 刷機主路由的首選；N60 是少數只有 256 MB 記憶體的。

| 類別 | 型號 | 記憶體 / 儲存 | 成熟度 | 刷機 | 價位 | 備註 |
|---|---|---|---|---|---|---|
| 🧩 | GL.iNet GL-MT6000（Flint 2） | 1 GB / 8 GB eMMC | 🟢 | ① | 💲💲💲 | 原廠是 OpenWrt，可直接刷官方韌體，U-Boot 網頁救援。台灣買得到，OpenWrt 論壇最推薦的 Wi-Fi 6 主路由之一。 |
| 🧩 | Banana Pi BPi-R3 | 2 GB / 128 MB NAND + 32 MB NOR + 8 GB eMMC + microSD | 🟢 | ① | 💲💲💲 | 開發板，2 個 SFP、4x4 Wi-Fi，用 SD 卡開機再裝進 NAND / eMMC。要自己配外殼、天線。淘寶、蝦皮有賣。 |
| 🧩 | Banana Pi BPi-R3 Mini | 2 GB / 128 MB NAND + 8 GB eMMC | 🟡 | ① | 💲💲💲 | 小型版，兩個 2.5G 埠。 |
| 🛒 | ASUS TUF-AX4200 / TUF-AX4200Q | 512 MB / 256 MB NAND | 🟢 | ③ | 💲💲💲 | 台灣有賣。要接 TTL（不用焊）在 U-Boot 用 TFTP 開 initramfs；4200Q 可從原廠網頁上傳 `initramfs.trx`。 |
| 🛒 | ASUS TUF-AX6000 | 512 MB / 256 MB NAND | 🟢 | ③ | 💲💲💲 | 台灣有賣。序列埠可從外殼孔接，不用拆機也不用焊。 |
| 🛒 | ASUS RT-AX59U | 512 MB / 128 MB NAND | 🟡 | ③ | 💲💲💲 | 要接 TTL。台灣通路未查證。 |
| 🛒 | D-Link AQUILA PRO AI M60 | 512 MB / 128 MB NAND | 🟡 | ① | 💲💲💲 | 台灣友訊有賣。原廠網頁或救援網頁刷；只有第一個分區在使用中時才能成功刷入。 |
| 🛒 | Acer Predator Connect W6（另有 W6d、Vero W6m） | 1 GB / 4 GB eMMC（W6d、W6m 為 512 MB，未查證） | 🟡 | ③ | 💲💲💲 | 台灣宏碁有賣（W6 有 6 GHz Wi-Fi 6E）。要接 TTL 改 U-Boot 設定。 |
| 🛒 | MERCUSYS MR90X v1 | 512 MB / 128 MB NAND | 🟡 | ③ | 💲💲💲 | 台灣曾上市（未查證現在還有沒有貨）。要接 TTL。 |
| 🛒 | 磊科 Netcore N60 Pro | 512 MB / 128 MB NAND | 🟢 | ② | 💲💲 | 中國零售機，恩山很熱門（高功率韌體、改 512 MB 快閃記憶體的硬改教學）。SSH（帳號 useradmin）刷 U-Boot。淘寶買。 |
| 🛒 | 磊科 Netcore N60 | 256 MB / 128 MB NAND | 🟡 | ② | 💲 | 跟 N60 Pro 同方法，記憶體只有 256 MB，跑黑潮 DNS 夠用但不寬裕。 |
| 🛒 | TP-Link TL-XDR6086 / TL-XDR6088 / TL-XDR4288 | 512 MB / 128 MB NAND | 🟢 | ② | 💲💲 | 中國 TP-Link（普聯）機種，不是台灣版。用 nc shell 漏洞取得 root 再換 bootloader。恩山 XDR6088 討論很多。淘寶、閒魚買。 |
| 🛒 | TP-Link TL-XTR8488 | 1 GB / 128 MB NAND | 🟡 | ② | 💲💲 | 中國版三頻機，刷法同 XDR 系列。 |
| 🛒 | 銳捷 Ruijie RG-X60 Pro（另有 RG-X60，僅 ImmortalWrt） | 512 MB / 128 MB NAND | 🟡 | ③ | 💲💲 | 中國零售機，要拆機接 TTL 用 TFTP。RG-X60（非 Pro）只有 ImmortalWrt 有。 |
| ♻️ | 紅米 Redmi AX6000 | 512 MB / 128 MB NAND | 🟢 | ② | 💲💲 | 中國零售機，閒魚很多。恩山「刷 SSH + 固化 SSH」教學超過 20 萬人看過。官方有原廠分區（stock）與 ubootmod 兩種韌體。 |
| ♻️ | 京東雲 RE-CP-03（百里 AX6000） | 1 GB / 128 GB eMMC | 🟢 | ② | 💲💲 | 閒魚二手。先刷 ImmortalWrt 提供的「vendor migration」韌體，再寫入 GPT、BL2、FIP。官方 OpenWrt 韌體一定要搭配官方 U-Boot，不能用 bl-mt798x 的 U-Boot。 |

其他官方有支援、但台灣與中國不容易買到的（沒列）：Zyxel EX5601-T0 / T-56（荷蘭電信）、JioRouter（印度電信）、Adtran SDG（美國電信）、Buffalo、ELECOM、ipTIME、TP-Link Archer AX80 / RE6000XD（台灣有沒有賣未查證）、Netgear WAX220、Wavlink 等。

### MediaTek MT7987（Filogic 的 Wi-Fi 7 入門款）

四核 Cortex-A53 2.0 GHz，有內建 2.5G PHY。晶片本身沒有 Wi-Fi，要外掛 MT7992（BE7200 等級）或 MT7990（BE3600 等級）才有 Wi-Fi 7。套件架構一樣是 `aarch64_cortex-a53`（target `mediatek/filogic`）。記憶體 512 MB 到 2 GB，儲存 128–512 MB NAND 或 eMMC。OpenWrt 從 25.12 才開始支援（24.10 一台都沒有），Wi-Fi 7 驅動還在成熟中，比較適合想先玩 Wi-Fi 7 的人；只要穩定的話，MT7986 還是比較穩。

| 類別 | 型號 | 記憶體 / 儲存 | 成熟度 | 刷機 | 價位 | 備註 |
|---|---|---|---|---|---|---|
| 🧩 | GL.iNet GL-MT3600BE（Beryl 7） | 512 MB / 512 MB NAND | 🟡 | ① | 💲💲💲 | 旅行路由器，Wi-Fi 7 用 MT7990（BE3600），2 個 2.5G 埠。原廠是 OpenWrt 改版，GL.iNet 都有 U-Boot 網頁救援。OpenWrt 官方 25.12 起才支援，教學還不多。GL.iNet 在台灣蝦皮、PChome 有賣，這台有沒有上架未查證。 |
| 🧩 | Banana Pi BPi-R4 Lite | 2 GB / 32 MB NOR + 256 MB NAND + 8 GB eMMC | 🟡 | ① | 💲💲💲 | 開發板，4 個 1G 埠、1 個 SFP、1 個 2.5G WAN，Wi-Fi 7 模組要另外買（mPCIe）。用 SD 卡開機再裝進 NAND / NOR / eMMC（方法跟 BPi-R3 一樣）。淘寶有賣（台灣代理未查證）。 |
| 🛒 | 騰達 Tenda 泰山 BE12 Pro（BE7200 Ultra） | 512 MB / 128 MB NAND | 🟠 | ① | 💲💲 | 中國零售機，恩山很熱門（「不拆機刷 OpenWrt + 刷回原廠」教學有 1.5 萬次瀏覽，另有多份 ImmortalWrt-798x 閉源驅動韌體）。OpenWrt 主線已加入，但 25.12 與 ImmortalWrt 25.12 的 profiles.json 都沒有，現在要用恩山的分支韌體。官方 commit 寫的是接 TTL 用 TFTP，恩山有不拆機的方法。淘寶買。 |
| 🛒 | Hiveton H5000M / Airpi H5000M | 1 GB / 8 GB eMMC | 🟡 | ① | 💲💲 | 中國廠牌，原廠是 ImmortalWrt-798x 改版，有 U-Boot 網頁救援（192.168.1.1），恩山的 MT798x U-Boot 支援清單裡有 `airpi_h5000m`。2 個 2.5G 埠，Wi-Fi 用 MT7992。目前 Wi-Fi 校準資料有問題，官方建議先用 OpenWrt 內建的 EEPROM。淘寶買（未查證）。 |

官方 25.12 有支援、但台灣與中國不容易買到的（沒列）：Routerich BE7200（俄羅斯品牌）。GL.iNet GL-BE10000 只在 OpenWrt 主線，還沒進正式版。

### MediaTek MT7988（Filogic 880 / 860）

MT7988A（Filogic 880）是四核 Cortex-A73 1.8 GHz，有 10G 介面，搭配 MT7996 / MT7992 做 Wi-Fi 7；MT7988D（Filogic 860，未查證）是三核 A73 的版本，多數市售 Wi-Fi 7 機用這顆。套件架構一樣是 `aarch64_cortex-a53`。記憶體 512 MB 到 4 GB。效能是這幾顆中最強的，但 Wi-Fi 7 驅動還在成熟中，能刷的市售機不多，比較適合想玩高階、或要 10G 的人。

| 類別 | 型號 | 記憶體 / 儲存 | 成熟度 | 刷機 | 價位 | 備註 |
|---|---|---|---|---|---|---|
| 🧩 | Banana Pi BPi-R4 | 4 GB（另有 8 GB 版）/ 128 MB NAND + 8 GB eMMC 或 microSD | 🟢 | ① | 💲💲💲 | 開發板，2 個 10G SFP+，Wi-Fi 7 模組另購。SD 卡開機再裝進 NAND / eMMC。淘寶、蝦皮有賣。 |
| 🧩 | Banana Pi BPi-R4 2.5GE（PoE 版） | 4 GB / 128 MB NAND + 8 GB eMMC 或 microSD | 🟡 | ① | 💲💲💲 | 把一個 SFP+ 換成 2.5G 電口（可 PoE）。 |
| 🛒 | ASUS ZenWiFi BT8 | 1 GB / 128 MB NAND | 🟡 | ① | 💲💲💲 | MT7988D。台灣有賣（Wi-Fi 7 Mesh）。官方有 factory 映像檔，也有 U-Boot mod 版本；教學少，刷前先看 OpenWrt 論壇。 |
| 🛒 | TP-Link TL-7DR7230 v1 / v2、TL-7DR7250 v1 | 512 MB / 128 MB NAND | 🟠 | ② | 💲💲 | MT7988D。中國 TP-Link 的 Wi-Fi 7 機，只有 ImmortalWrt 有正式韌體（OpenWrt 主線已加入，下一版才會有）。v1、v2 記憶體不同（DDR4 / DDR3），韌體不能混用。淘寶買。 |

其他官方有支援、但台灣與中國不容易買到的（沒列）：Keenetic / Netcraze KN-1812、Adtran SDG-8733 / 8734、Arcadyan Mozart、TP-Link BE450（是哪個市場的型號未查證）。MT7987 見下一節。

### MediaTek MT7622

雙核 Cortex-A53 1.35 GHz，晶片內建的只有 2.4 GHz Wi-Fi 4（4x4 b/g/n），5 GHz 要外掛 MT7615（Wi-Fi 5）或 MT7915（Wi-Fi 6），套件架構 `aarch64_cortex-a53`（target `mediatek/mt7622`）。記憶體 256–512 MB，儲存大多是 128 MB NAND。這是 Filogic 之前的上一代，現在主要是二手機，便宜、穩定，OpenWrt 支援很成熟，當 DNS / 主路由都還夠用。

| 類別 | 型號 | 記憶體 / 儲存 | 成熟度 | 刷機 | 價位 | 備註 |
|---|---|---|---|---|---|---|
| 🧩 | Banana Pi BPi-R64 | 1 GB / 8 GB eMMC（部分有 SPI-NAND）+ microSD | 🟡 | ① | 💲💲 | 開發板，沒有內建 5 GHz（要接 mini PCIe 網卡）。淘寶還找得到（未查證是否停產）。 |
| 🛒 | D-Link EAGLE PRO AI M32 / R32 | 512 MB / 128 MB NAND | 🟡 | ① | 💲💲 | 台灣友訊有賣過（AX3200，5 GHz 為 MT7915）。原廠救援網頁刷 recovery 映像檔。 |
| 🛒 | Ubiquiti UniFi 6 Long-Range（U6-LR v1 / v2 / v3） | 512 MB / 64 MB NOR | 🟢 | ② | 💲💲💲 | 台灣有代理（新品多為 v3）。三個版本韌體不同；另有 U-Boot mod 版本。二手也多。 |
| ♻️ | 紅米 Redmi AX6S、小米 AX3200 | 256 MB / 128 MB NAND | 🟢 | ② | 💲 | 小米 AX3200 是國際版，台灣曾經有賣；閒魚、蝦皮二手很多。用序號算 telnet 密碼開 SSH。5 GHz 為 MT7915。 |
| ♻️ | 銳捷 Ruijie RG-EW3200GX PRO | 256 MB / 16 MB NOR | 🟡 | ③ | 💲 | 中國零售機，閒魚便宜。要接 TTL；只有 16 MB NOR，套件空間有限。 |
| ♻️ | TP-Link TL-XDR3230 v1 / TL-XDR3250 v1 | 256 MB / 16 MB NOR | 🟠 | ② | 💲 | 中國 TP-Link 機，只有 ImmortalWrt 有。閒魚很便宜。 |

其他官方有支援、但台灣與中國不容易買到的（沒列）：Linksys E8450 / Belkin RT3200（美國，OpenWrt 論壇非常熱門，但台灣很少見）、Netgear WAX206（台灣有沒有賣未查證）、Buffalo WSR-2533DHP2 / WSR-3200AX4S、ELECOM、TOTOLINK A8000RU（台灣有沒有賣未查證）、Reyee AX3200-E5。

### Qualcomm IPQ807x（Networking Pro 600 / 800 系列，Wi-Fi 6）

四核 Cortex-A53，IPQ8071A / IPQ8174 跑 1.4 GHz，IPQ8072A / IPQ8074A 跑 2.2 GHz；Wi-Fi 6（ath11k 驅動），記憶體 512 MB 到 2 GB，儲存多為 128–512 MB NAND。套件架構 `aarch64_cortex-a53`（target `qualcommax/ipq807x`）。OpenWrt 24.10 / 25.12 都有正式版，小米 AX3600、紅米 AX6、Linksys MX4200 的教學最多，適合想用便宜價格買到 512 MB 以上 Wi-Fi 6 機的人。**NSS 硬體加速只在分支有**：OpenWrt 官方和 ImmortalWrt 25.12 正式版只有乙太網路驅動（`kmod-qca-nss-dp`），沒有 NSS 卸載，NAT 跟 PPPoE 都靠 CPU。要 NSS 得用 qosmio/openwrt-ipq、LiBwrt、VIKINGYFY/immortalwrt 這類第三方韌體。開 NSS 時 SQM、UA2F 不能用；黑潮 DNS 只處理 DNS，有沒有 NSS 都不受影響。

| 類別 | 型號 | 記憶體 / 儲存 | 成熟度 | 刷機 | 價位 | 備註 |
|---|---|---|---|---|---|---|
| 🛒 | ASUS RT-AX89X | 1 GB / 256 MB NAND | 🟡 | ③ | 💲💲💲 | 台灣有賣過，現在多半剩庫存或二手（蝦皮、露天）；有 10G 電口和 SFP+；刷機步驟比較長（要不要接 TTL 未查證） |
| ♻️ | 小米 AX3600 | 512 MB / 256 MB NAND | 🟢 | ② | 💲～💲💲 | 恩山最熱門的 Wi-Fi 6 機型之一；降到舊版原廠韌體、用漏洞開 SSH 再刷；ImmortalWrt 另外有 stock layout 版（不用改分區）；閒魚二手很多 |
| ♻️ | 紅米 AX6 | 512 MB / 128 MB NAND | 🟢 | ② | 💲 | 同樣是 IPQ8071A，閒魚很便宜；開 SSH 流程和 AX3600 一樣；NSS 分支韌體也多 |
| ♻️ | 小米 AX9000 | 1 GB / 256 MB NAND | 🟢 | ② | 💲💲 | IPQ8072A 2.2 GHz，三頻；閒魚二手 |
| ♻️ | Linksys MX4200 v1 / v2（Velop AX4200） | v1：512 MB / 512 MB NAND；v2：1 GB / 512 MB NAND | 🟢 | ① | 💲💲 | 台灣有賣過；原廠網頁直接刷；雙分區，刷壞可以切回另一個分區；蝦皮、閒魚二手（美國退役品很多） |
| ♻️ | Linksys MX4300 | 2 GB / 1 GB NAND | 🟢 | ① | 💲💲 | 美國 Costco 版本，記憶體跟儲存都特別大；閒魚、淘寶上有美國流出的二手（未查證台灣有沒有） |
| ♻️ | Linksys MX5300 | 1 GB / 512 MB NAND | 🟡 | ① | 💲💲 | 作法和 MX4200 一樣 |
| ♻️ | Netgear Orbi RBK752 / RBK852（RBR750 / RBR850） | 1 GB / 256 或 512 MB NAND | 🟠 | ③ | 💲💲 | 台灣有賣過，二手常見；只有 OpenWrt snapshot 和 VIKINGYFY 分支有，25.12 正式版沒有 |
| 📡 | ZTE MF269 | 512 MB（NAND 容量未查證） | 🟡 | ③ | 💲 | 中國移動 5G CPE 配套的路由器；ImmortalWrt 有 stock layout 版；閒魚二手便宜 |
| 📡 | 中國移動 RM2-6 | 512 MB / 256 MB NAND | 🟡 | ③ | 💲 | 閒魚二手 |

> 官方還支援 Dynalink WRX36、Netgear RAX120v2 / WAX 系列、QNAP 301W、Buffalo WXR-5950AX12、Zyxel NBG7815、TP-Link EAP620 HD / EAP660 HD 等，但台灣和中國都很少見，就不列了。

### Qualcomm IPQ60xx（IPQ6000 / IPQ6010 / IPQ6018，Wi-Fi 6）

四核 Cortex-A53，IPQ6000 跑 1.2 GHz，IPQ6010 / IPQ6018 最高 1.8 GHz；Wi-Fi 6（ath11k），IPQ6000 不支援 160 MHz。記憶體 256 MB 到 2 GB，儲存是 NAND 或 eMMC。套件架構 `aarch64_cortex-a53`（target `qualcommax/ipq60xx`）。**OpenWrt 24.10 還沒有這個 subtarget，25.12 才第一次出正式版。** 恩山上熱門的京東雲亞瑟 / 雅典娜，在 25.12 正式版和 ImmortalWrt 25.12 正式版都沒有，只有 OpenWrt 主線（snapshot）和分支有；紅米 AX5、小米 AX1800 只有分支（LiBwrt、VIKINGYFY、Lean）有。NSS 一樣只在分支有。256 MB 的 IPQ6000 機種，恩山作者多半建議先換成 512 MB 或 1 GB 記憶體再刷 NSS 韌體。

| 類別 | 型號 | 記憶體 / 儲存 | 成熟度 | 刷機 | 價位 | 備註 |
|---|---|---|---|---|---|---|
| 🧩 | GL.iNet GL-AXT1800（Slate AX） | 512 MB / 128 MB NAND | 🟡 | ① | 💲💲💲 | 原廠韌體就是 OpenWrt 改的，可以直接上傳官方 sysupgrade；也有 U-Boot 網頁救援；官方版只有 25.12 才有；蝦皮、網購買得到 |
| 🧩 | GL.iNet GL-AX1800（Flint） | 512 MB / 128 MB NAND | 🟡 | ① | 💲💲💲 | 同上 |
| 🛒 | Linksys MR7350 | 512 MB / 256 MB NAND | 🟡 | ① | 💲💲 | 原廠網頁直接刷；雙分區；台灣新品還有沒有貨未查證，二手可找 |
| ♻️ | 京東雲 亞瑟 AX1800 Pro（RE-SS-01） | 512 MB / 64 或 128 GB eMMC | 🟠 | ② | 💲 | 恩山熱門的 PCDN 機（京東雲、網心雲那一類），eMMC 很大，可以當小 NAS；舊版原廠韌體可以免拆開 SSH、刷 U-Boot，4.3.0.r4211 之後的版本要走 9008 或 TTL；閒魚很多 |
| ♻️ | 京東雲 雅典娜 AX6600（RE-CS-02） | 1 GB / 128 或 256 GB eMMC | 🟠 | ② | 💲💲 | IPQ6010 三頻；救磚方式和亞瑟一樣（不死 U-Boot）；恩山有 LiBwrt 25.12-nss 全卸載韌體 |
| ♻️ | 360 V6 | 512 MB / 128 MB NAND | 🟡 | ③（未查證） | 💲 | 官方版只有 25.12 才有；方案和小米 AX1800 差不多；閒魚二手 |
| ♻️ | 紅米 AX5、小米 AX1800 | 256 MB / 128 MB NAND | 🟠 | ② | 💲 | 只有分支有；原裝 256 MB 跑 NSS 和無線很吃緊，恩山多數 NSS 韌體要求先換記憶體；閒魚很便宜 |
| 📡 | 兆能 M2、中移物聯 AX18 | 256 MB（M2）、AX18 未查證 / 128 MB NAND | 🟠 | ③（未查證） | 💲 | 中國電信業者的 OEM 機，只有分支有；恩山建議 M2 先換記憶體；閒魚二手 |

### Qualcomm IPQ50xx（IPQ5018，Wi-Fi 6）

雙核 Cortex-A53 1.0 GHz，2.4 GHz Wi-Fi 6 內建在 SoC 裡，5 GHz 靠外掛的 QCN6122 / QCN9024；記憶體 256–512 MB，128–256 MB SPI NAND。套件架構 `aarch64_cortex-a53`（target `qualcommax/ipq50xx`）。OpenWrt 25.12 第一次出正式版，但只有 6 台，而且多半是台灣、中國少見的機種；小米 AX6000、GL-B3000 只有 ImmortalWrt 有。256 MB 機種（ELECOM WRC-X3000GS2、中國移動 PZ-L8、RAX3000Q）把無線關掉了，不要買。NSS 在這個平台還沒成功。整體還在起步，適合不怕當白老鼠的人。

| 類別 | 型號 | 記憶體 / 儲存 | 成熟度 | 刷機 | 價位 | 備註 |
|---|---|---|---|---|---|---|
| 🧩 | GL.iNet GL-B3000（Marble） | 512 MB / 128 MB NAND | 🟠 | ① | 💲💲💲 | 原廠韌體是 OpenWrt 改的；要官方版只能用 ImmortalWrt |
| 🛒 | 小米 AX6000（IPQ5018 版） | 512 MB / 128 MB NAND（未查證） | 🟠 | ② | 💲💲 | 只有 ImmortalWrt 有；要先刷 UBI 格式的 initramfs 當過渡。注意和紅米 AX6000（MT7986）是不同機器 |
| 🛒 | TP-Link Archer AX55 v1 | 512 MB / 128 MB NAND | 🟠 | ③（未查證） | 💲💲 | 台灣量販店常見，但只有 v1 是高通方案，買之前要看清楚版本；只有 snapshot 和 VIKINGYFY 分支有 |
| ♻️ | 紅米 AX5400 | 512 MB / 128 MB NAND | 🟠 | ② | 💲 | 只有 snapshot 和分支有；閒魚二手 |
| 📡 | 中國移動 MR3000D-CI | 512 MB / 128 MB NAND | 🟡 | ③ | 💲 | 官方版只有 25.12 才有；閒魚二手 |

### Rockchip RK3328 / RK3399 / RK3528 / RK3566 / RK3568 / RK3576 / RK3582 / RK3588(S)（rockchip/armv8）

OpenWrt 把所有 Rockchip 64 位元晶片放在同一個 `rockchip/armv8` target，套件架構一律是 `aarch64_generic`：RK3328 / RK3528 是 4 核 A53（1.3–2.0 GHz），RK3566 / RK3568 是 4 核 A55（1.8–2.0 GHz），RK3399 是 2×A72 + 4×A53，RK3576 是 4×A72 + 4×A53，RK3582 / RK3588(S) 是 A76 大核 + A55 小核（最高 2.4 GHz）。這些都是**沒有路由用 Wi-Fi 的有線軟路由**（無線要另接 AP），記憶體 1–16 GB，用 microSD 或 eMMC 開機，跑黑潮 DNS 綽綽有餘，整機 3–10 W、多數免風扇。OpenWrt 25.12.6 官方收錄 48 款（比 24.10.6 多 12 款），ImmortalWrt 25.12.2 另外多 17 款；下表只留淘寶、閒魚、台灣通路（蝦皮、露天、PChome）實際買得到的。網口多是 Realtek RTL8125（2.5G）/ RTL8211F / RTL8111H（1G）；刷機都是把映像檔寫進 microSD 卡（或從 SD 開機後寫入 eMMC），出廠是 FriendlyWrt / iStoreOS 的也可以直接在網頁升級，變磚時按 MaskROM 鍵、用 USB 線救回。拿 RK3528 / RK3566 電視盒（例如 HK1 RBox、H96 Max）改機要短接 eMMC 或線刷，也沒有正式韌體，一般人不建議。

| 類別 | 型號 | 記憶體 / 儲存 | 成熟度 | 刷機 | 價位 | 備註 |
|---|---|---|---|---|---|---|
| 🧩 | FriendlyElec NanoPi R5S（RK3568B2） | 2 / 4 GB LPDDR4X / 8–32 GB eMMC + M.2 NVMe | 🟢 | ①（出廠 FriendlyWrt 網頁升級，或 SD 卡開機後寫入 eMMC） | 💲💲～💲💲💲 | 2× 2.5G + 1× 1G，恩山討論最多的 2.5G ARM 軟路由。eMMC 空的時候會先從 SD 開機；2 GB 版跑 Docker 會吃緊。淘寶、蝦皮都有。 |
| 🧩 | FriendlyElec NanoPi R4S / R4S Enterprise（RK3399） | 1 GB DDR4 或 4 GB LPDDR4 / microSD | 🟢 | ①（寫 microSD 卡） | 💲💲 | 2× GbE 經典款。官方韌體只列 4 GB 版，1 GB 版要用 FriendlyWrt / ImmortalWrt。已逐漸停產，閒魚二手很多。 |
| 🧩 | FriendlyElec NanoPi R2S / R2S Plus（RK3328） | 1 GB DDR4 / microSD（Plus 另有 32 GB eMMC） | 🟢 | ①（寫 microSD 卡） | 💲～💲💲 | 2× GbE，其中一個是 USB 3.0 轉網卡（RTL8153），千兆滿載會發熱、吃緊。教學最多，閒魚二手很便宜。 |
| 🧩 | FriendlyElec NanoPi R2C / R2C Plus（RK3328） | 1 GB DDR4 / microSD（Plus 另有 8 GB eMMC） | 🟢 | ①（寫 microSD 卡） | 💲～💲💲 | R2S 的改版（換了 PHY），用法相同，多為二手。 |
| 🧩 | FriendlyElec NanoPi R6S（RK3588S） | 8 GB LPDDR4X / 32 GB eMMC | 🟢 | ①（同 R5S） | 💲💲💲 | 2× 2.5G + 1× 1G，ARM 軟路由效能頂端，多撥、全家 Docker 都撐得住。 |
| 🧩 | FriendlyElec NanoPi R5C（RK3568B2） | 1 GB / 4 GB LPDDR4X / 0 或 32 GB eMMC | 🟢 | ①（寫 microSD 或 eMMC） | 💲💲 | 2× 2.5G，有 M.2 Wi-Fi 插槽（官方韌體預帶 RTL8822CE 驅動），沒有 NVMe。 |
| 🧩 | FriendlyElec NanoPi R6C（RK3588S） | 4 / 8 GB LPDDR4X / 0 或 32 GB eMMC | 🟢 | ①（寫 microSD 或 eMMC） | 💲💲💲 | 1× 2.5G + 1× 1G，有 M.2 NVMe；只需要兩個網口的話比 R6S 便宜。 |
| 🧩 | FriendlyElec NanoPi R3S（RK3566） | 2 GB LPDDR4X / 32 GB eMMC | 🟢 | ①（寫 microSD 或 eMMC） | 💲💲 | 2× GbE，小巧便宜，適合千兆主路由或純 DNS 旁路由。 |
| 🧩 | FriendlyElec NanoPi R76S（RK3576） | 2 / 4 GB LPDDR4X、16 GB LPDDR5 / 32（或 64）GB eMMC | 🟡 | ①（寫 microSD 或 eMMC） | 💲💲～💲💲💲 | 2× 2.5G，2025 年新款，25.12 才進官方，教學還少。附 SDIO Wi-Fi 模組（RTL8822CS）。 |
| 🧩 | Radxa E20C（RK3528A） | 1–4 GB LPDDR4 / microSD（是否有 eMMC 版未查證） | 🟡 | ①（寫 microSD） | 💲 | 2× GbE、金屬殼，最便宜的入門款，25.12 才進官方。Radxa 淘寶店、AliExpress。 |
| 🧩 | Radxa E52C（RK3582） | 2 / 4 / 8 GB / 16 / 32 / 64 GB eMMC | 🟡 | ①（寫 microSD 或 eMMC） | 💲💲 | 2× 2.5G（RTL8125BG），內建 USB 序列埠 console；價格接近 R5S，CPU 強很多。 |
| 🧩 | Radxa ROCK 5B / 5B+ / 5C / 5T（RK3588 / RK3588S） | 4–32 GB LPDDR4X / LPDDR5 / microSD、eMMC 模組、NVMe | 🟡 | ①（寫 microSD） | 💲💲💲 | 一般用途開發板。5B / 5B+ / 5C 只有 1 個網口，要另加 USB 或 PCIe 網卡；5T 有 2× 2.5G。台灣有代理商。 |
| 🧩 | Orange Pi R1 Plus LTS（RK3328） | 1 GB DDR4 / microSD | 🟢 | ①（寫 microSD） | 💲 | 2× GbE（和 R2S 一樣，其中一個是 USB 轉網卡），比 R2S 便宜，Orange Pi 淘寶店還在賣。舊版 R1 Plus（DDR3）多為二手。 |
| 🧩 | Orange Pi 5 Plus（RK3588） | 4 / 8 / 16 / 32 GB LPDDR4X / microSD、eMMC 模組、NVMe | 🟠 | ①（寫 microSD） | 💲💲💲 | 2× 2.5G，淘寶、蝦皮都很常見，但 OpenWrt 官方沒有，要用 ImmortalWrt。適合兼 NAS。 |
| 🛒 | HINLINK H28K / LinkStar H28K（RK3528） | 1 / 2 / 4 GB LPDDR4X / 0、8 或 32 GB eMMC + microSD | 🟢 | ①（寫 microSD 或 eMMC） | 💲 | 2× GbE（RTL8111H + RTL8211F，**不是** 2.5G），USB-C PD 供電，很便宜的旅行路由。25.12 進官方，恩山有大量固件。淘寶或 Seeed 海外通路。 |
| 🛒 | Lunzn FastRhino 電犀牛 R66S（RK3568） | 1 / 4 GB LPDDR4X（未查證）/ microSD | 🟢 | ①（寫 microSD） | 💲💲 | 2× 2.5G，無 eMMC。恩山討論多，淘寶、閒魚好買。 |
| 🛒 | Lunzn FastRhino 電犀牛 R68S（RK3568）；金屬殼版 LYT T68M | 2 / 4 GB LPDDR4X / 16 / 32 GB eMMC | 🟠 | ①（出廠 iStoreOS 網頁升級，或 dd 寫入 eMMC） | 💲💲 | 2× 2.5G + 2× 1G，恩山很熱門，但 OpenWrt 官方沒收，要用 ImmortalWrt / iStoreOS（兩款 ImmortalWrt 各有韌體，不要刷錯）。 |
| 🛒 | LinkEase 易有雲 EasePi R1（RK3568） | 2 / 4 GB LPDDR4 / 16 GB eMMC + M.2 NVMe | 🟡 | ①（出廠 iStoreOS 網頁升級） | 💲💲 | 2× 2.5G + 2× 1G、HDMI，24.10.5 起進官方，教學還少。淘寶購買。 |

### Broadcom BCM2710 / BCM2711 / BCM2712（樹莓派，bcm27xx）

OpenWrt 為樹莓派每一代各出一個通用韌體：`bcm2710`（樹莓派 3 / Zero 2，Cortex-A53 1.2–1.4 GHz，`aarch64_cortex-a53`）、`bcm2711`（樹莓派 4B / 400 / CM4，Cortex-A72 1.5–1.8 GHz，`aarch64_cortex-a72`）、`bcm2712`（樹莓派 5 / 500 / CM5，Cortex-A76 2.4 GHz，`aarch64_cortex-a76`）。記憶體 512 MB–16 GB，24.10 與 25.12 都有正式韌體，寫 microSD 卡就能開機，教學極多。最大的限制是**只有 1 個網口**（3B+ 以前還是掛在 USB 2.0 上），當主路由必須另接 USB 3.0 網卡（RTL8153 / AX88179）、用 VLAN 交換器做單臂路由，或改用雙網口的 CM4 路由底板；內建 Wi-Fi 只適合當旅行用 AP。適合手邊已經有樹莓派、想跑黑潮 DNS 當旁路由或 DNS 伺服器的人。

| 類別 | 型號 | 記憶體 / 儲存 | 成熟度 | 刷機 | 價位 | 備註 |
|---|---|---|---|---|---|---|
| 🧩 | CM4 雙網口路由底板（DFRobot IoT Router Carrier Board Mini、Seeed Dual Gigabit Carrier / reRouter CM4、52Pi CM4 Router Board） | 依 CM4 模組：1–8 GB / 0–32 GB eMMC | 🟢 | ①（寫 microSD；eMMC 版 CM4 用 `rpiboot` 寫入） | 💲💲（底板）+ CM4 模組 | 2× GbE（BCM2711 內建 + PCIe 或 USB 3.0 網卡），用 `bcm2711` 韌體。DFRobot、Seeed 在淘寶都有店；reRouter 出廠就是 OpenWrt。 |
| 🛒 | Raspberry Pi 4 Model B / Pi 400 / CM4（BCM2711） | 1 / 2 / 4 / 8 GB LPDDR4 / microSD（CM4 可選 8–32 GB eMMC） | 🟢 | ①（寫 microSD） | 💲💲 | 1× GbE + USB 3.0，加一支 USB 3.0 網卡就能跑千兆。台灣代理商、PChome、蝦皮都買得到。 |
| 🛒 | Raspberry Pi 5 / Pi 500 / CM5（BCM2712） | 1 / 2 / 4 / 8 / 16 GB LPDDR4X / microSD，可加 NVMe HAT（CM5 可選 eMMC） | 🟢 | ①（寫 microSD） | 💲💲～💲💲💲 | 1× GbE，有 PCIe 2.0 x1，可接 RTL8125 2.5G HAT。效能接近 RK3588，但價格不比 NanoPi R6S 便宜。 |
| ♻️ | Raspberry Pi 3 Model B / B+（BCM2710） | 1 GB / microSD | 🟡 | ①（寫 microSD） | 💲 | 網口掛在 USB 2.0 上，3B+ 實測約 300 Mbps；只建議當 DNS 伺服器或旁路由。Zero 2 W（512 MB）同一個韌體，沒有網口。 |

### Marvell Armada 3720 / 7040（mvebu cortexa53 / cortexa72）

mvebu 的 64 位元部分分兩群：`cortexa53`（Armada 3720，2 核 A53 1.0–1.2 GHz，`aarch64_cortex-a53`）與 `cortexa72`（Armada 7040 / 8040、CN913x，4 核 A72 1.4–2.2 GHz，`aarch64_cortex-a72`）。OpenWrt 主線支援完整，但大多是國外的開發板或企業網通設備（MOCHAbin、MACCHIATObin、Turris MOX、Check Point、iEi 等），台灣與中國都難買，這裡只留買得到的三款。同一個 target 的 32 位元 `cortexa9`（Linksys WRT 系列、Turris Omnia）不在這一節。

| 類別 | 型號 | 記憶體 / 儲存 | 成熟度 | 刷機 | 價位 | 備註 |
|---|---|---|---|---|---|---|
| 🧩 | GL.iNet GL-MV1000 Brume / MV1000W（Armada 3720） | 1 GB DDR4 / 16 MB NOR + 8 GB eMMC + microSD | 🟢 | ①（原廠就是 OpenWrt，網頁直刷；U-Boot 網頁救援） | 💲💲 | 3× GbE 的 VPN 閘道，W 版有 Wi-Fi。已被 Brume 2（MT7981）取代，蝦皮、閒魚找二手。 |
| 🧩 | Globalscale ESPRESSObin v7（Armada 3720） | 1 / 2 GB DDR4 / microSD（可選 4 GB eMMC） | 🟡 | ③（接 micro-USB console 改 U-Boot 環境變數，從 SD 開機） | 💲💲 | 3× GbE 開發板，淘寶偶有新品 / 二手（貨源未查證），步驟比較麻煩。 |
| 🛒 | MikroTik RB5009UG+S+IN（Armada 7040） | 1 GB DDR4 / 16 MB NOR + 1 GB NAND | 🟡 | ③（RouterBOOT TFTP 網路開機，不用拆機） | 💲💲💲 | 7× GbE + 1× 2.5G + 1× 10G SFP+，台灣有代理、蝦皮買得到。先 TFTP 開 initramfs 再寫入，回原廠要用 Netinstall。 |

### Allwinner H5 / H616 / H618（sunxi）

全志晶片分 `sunxi/cortexa53`（H5、H6、H616 / H618、A64，`aarch64_cortex-a53`，25.12 有 14 款）與 `sunxi/cortexa7`（H2+、H3、A20 等 32 位元，`arm_cortex-a7_neon-vfpv4`，32 款），幾乎都是單網口開發板，記憶體 256 MB–4 GB。OpenWrt 支援穩定，但很少有人拿來當路由器，恩山討論也少；Orange Pi PC / One / Zero、Banana Pi M2、Cubieboard 這些老板子多已停產，不列。

| 類別 | 型號 | 記憶體 / 儲存 | 成熟度 | 刷機 | 價位 | 備註 |
|---|---|---|---|---|---|---|
| 🧩 | Orange Pi Zero 3 / Zero 2W（H618） | 1 / 1.5 / 2 / 4 GB / microSD | 🟡 | ①（寫 microSD） | 💲 | Zero 3 有 1× GbE，Zero 2W 沒有網口。便宜，只適合當專職 DNS 伺服器。淘寶、蝦皮都有。 |
| ♻️ | FriendlyElec NanoPi R1S-H5（H5） | 512 MB DDR3 / microSD | 🟡 | ①（寫 microSD） | 💲 | 2× GbE（其中一個是 USB 轉網卡）+ Wi-Fi，已停產，閒魚二手；512 MB 跑黑潮 DNS 夠用。H3 版 R1S 不在官方清單。 |

## 2. 32 位元 ARM —— 上一代主力，二手便宜

Wi-Fi 5 時代的高階機，現在二手很便宜。記憶體多半 256–512 MB，跑黑潮 DNS 沒問題。

### Qualcomm IPQ40xx（IPQ4018 / IPQ4019，Wi-Fi 5 Wave 2）

四核 Cortex-A7 717 MHz，雙頻 802.11ac Wave 2（ath10k），記憶體 128–512 MB。套件架構 `arm_cortex-a7_neon-vfpv4`（target `ipq40xx/generic`、`ipq40xx/mikrotik`）。官方支援非常成熟，二手便宜，適合想用低價跑 DNS、廣告過濾的人；CPU 比 IPQ807x 弱很多，千兆 NAT 跑不滿，也沒有 NSS。官方表上有八十多台，多數是歐美電信或企業機（FritzBox、Meraki、Aruba、ZTE 4G CPE 等），台灣和中國少見，不列。

| 類別 | 型號 | 記憶體 / 儲存 | 成熟度 | 刷機 | 價位 | 備註 |
|---|---|---|---|---|---|---|
| 🧩 | GL.iNet GL-A1300（Slate Plus） | 256 MB / 128 MB NAND | 🟢 | ① | 💲💲 | 旅行路由器；原廠韌體是 OpenWrt 改的；蝦皮、網購買得到 |
| 🧩 | GL.iNet GL-B1300、GL-B2200 | B1300：256 MB / 32 MB NOR；B2200：512 MB / 8 GB eMMC | 🟢 | ① | 💲💲 | 有 U-Boot 網頁救援；新品可能已經不多，二手可找 |
| 🛒 | MikroTik hAP ac³ | 256 MB / 16 MB NOR + 128 MB NAND | 🟡 | ③ | 💲💲 | 台灣有代理，蝦皮買得到；用 RouterBOOT 從網路開機（TFTP）跑 initramfs 再 sysupgrade，不用拆機；之後可以用 Netinstall 刷回 RouterOS。hAP ac² 只有 128 MB，是下限 |
| ♻️ | ASUS RT-ACRH17 / RT-AC42U | 256 MB / 128 MB NAND | 🟢 | ③ | 💲 | 台灣二手常見；用原廠救援模式（TFTP）刷 |
| ♻️ | ASUS RT-AC58U / RT-ACRH13 | 128 MB / 128 MB SPI NAND | 🟢 | ③ | 💲 | 台灣、恩山都很常見，但 128 MB 是下限；RT-AC58U v2 / v3 是 ath79 方案 |
| ♻️ | ASUS Lyra（MAP-AC2200） | 256 MB / 128 MB NAND | 🟡 | ③ | 💲 | 台灣有賣過，二手 Mesh 便宜 |
| ♻️ | Netgear Orbi RBK50（RBR50 / RBS50） | 512 MB / 4 GB eMMC | 🟢 | ① | 💲～💲💲 | 原廠網頁直接刷；nmrpflash 救援；台灣二手很多 |
| ♻️ | Linksys Velop WHW03（三頻）、WHW01（雙頻） | WHW03：512 MB / 4 GB eMMC（v2：512 MB NAND）；WHW01：256 MB / 256 MB NAND | 🟢 | ① | 💲 | 台灣有賣過，二手多；雙分區 |
| ♻️ | Linksys EA8300、MR8300、EA6350 v3 | EA8300：256 MB / 256 MB NAND；MR8300：512 MB / 256 MB NAND；EA6350 v3：256 MB / 128 MB NAND | 🟢 | ① | 💲 | 原廠網頁直接刷；EA6350 v4 換成 MT7621 |
| ♻️ | 竞斗云 2.0（P&W R619AC） | 512 MB / 16 MB NOR + 128 MB NAND（另有 64 MB NAND 版） | 🟢 | ① | 💲 | 恩山經典 IPQ40xx 機，閒魚很便宜 |
| ♻️ | MobiPromo CM520-79F | 512 MB / 128 MB NAND | 🟡 | ③（未查證） | 💲 | 恩山常見的便宜機，閒魚二手 |

### Qualcomm IPQ806x（IPQ8064 / IPQ8065，Wi-Fi 5）

雙核 Krait（ARMv7），1.4–1.7 GHz；Wi-Fi 5（QCA9984 / QCA9980，ath10k），記憶體 256–512 MB，儲存多為 128–256 MB NAND。套件架構 `arm_cortex-a15_neon-vfpv4`（target `ipq806x/generic`）。官方支援十年以上，大部分機種可以在原廠網頁直接刷。原廠有 NSS 協處理器，官方沒有驅動；ACwifidude 在 OpenWrt 論壇的「Ipq806x NSS build」串有持續維護的 NSS 韌體（R7800 / C2600 / EA8500）。全部都停產了，只剩二手。

| 類別 | 型號 | 記憶體 / 儲存 | 成熟度 | 刷機 | 價位 | 備註 |
|---|---|---|---|---|---|---|
| ♻️ | Netgear R7800（Nighthawk X4S） | 512 MB / 128 MB NAND | 🟢 | ① | 💲～💲💲 | 最經典的 OpenWrt 二手機；原廠網頁直接刷；TFTP（nmrp）救援；台灣蝦皮、閒魚都有 |
| ♻️ | Netgear XR500、R7500 v2、D7800 | XR500：512 MB / 256 MB NAND；R7500 v2：256 MB / 128 MB NAND；D7800：512 MB / 128 MB NAND | 🟢（XR500）/ 🟡 | ① | 💲 | R7800 的兄弟機 |
| ♻️ | TP-Link Archer C2600 | 512 MB / 32 MB NOR | 🟢 | ① | 💲 | 原廠網頁直接刷 |
| ♻️ | Linksys EA8500 | 512 MB / 128 MB NAND | 🟢 | ① | 💲 | 雙分區 |
| ♻️ | Zyxel NBG6817（Armor Z2） | 512 MB / 4 GB eMMC | 🟢 | ① | 💲💲 | 台灣有賣過 |
| ♻️ | 小米路由器 HD（R3D） | 512 MB / 256 MB NAND（未查證） | 🟠 | ②（未查證） | 💲 | 只有 ImmortalWrt 有；閒魚二手 |

### Marvell Armada 385 / 388（mvebu/cortexa9）

雙核 Cortex-A9，1.3–1.866 GHz，記憶體 512 MB–2 GB；路由器用 Wi-Fi 5（mwlwifi 驅動，已經很少人維護）。套件架構 `arm_cortex-a9_vfpv3-d16`。官方支援非常成熟，Linksys WRT 系列可以在原廠網頁直接刷、有雙分區；Turris Omnia 是專為開源設計的機器，原廠系統就是 OpenWrt 改的。同一個 subtarget 還有 Fortinet 防火牆、各種 NAS（Armada 370 / XP / 380），台灣少見，不列。

| 類別 | 型號 | 記憶體 / 儲存 | 成熟度 | 刷機 | 價位 | 備註 |
|---|---|---|---|---|---|---|
| 🧩 | CZ.NIC Turris Omnia | 1 或 2 GB / 8 GB eMMC | 🟢 | ① | 💲💲💲 | 原廠 Turris OS 就是 OpenWrt 改的；台灣要海外訂購（未查證有無代理） |
| ♻️ | Linksys WRT3200ACM、WRT32X | 512 MB / 256 MB NAND | 🟢 | ① | 💲💲 | 台灣有賣過，二手（蝦皮、露天）；原廠網頁直接刷；雙分區；mwlwifi 無線驅動有已知問題 |
| ♻️ | Linksys WRT1900ACS、WRT1200AC | 512 MB / 128 MB NAND | 🟢 | ① | 💲 | 台灣二手常見；WRT1900AC v1 是 Armada XP |

## 3. MIPS —— 存量最大，選記憶體夠的

MIPS 分**小端序**（`mipsel_24kc`，MediaTek）和**大端序**（`mips_24kc`，Qualcomm Atheros、Lantiq）兩種，互不相容，一定要選對。效能比 ARM 弱很多，AES 沒有硬體加速；128 MB 夠用但偏緊。

### MediaTek MT7621（MT7621A / AT / DAT / N / S / ST）

> 128 MB 記憶體、16 MB 儲存的 MT7621 機器，建議改刷 [padavan-tw](https://github.com/candy999/padavan-tw)（比 OpenWrt 輕，已整合黑潮 DNS），說明見[選硬體](hardware.md#低階路由器改用-padavan-tw)。下表備註裡的「Padavan 支援」指 Padavan 系列韌體有這台的設定檔。

MT7621A / AT 是雙核 MIPS 1004Kc 880 MHz（4 執行緒），內建 5 埠 Gigabit 交換器與硬體 NAT。MT7621DAT 是內建 128 MB 記憶體的雙核版，MT7621N / S / ST 則是單核雙執行緒（網件 R6220、WAC104 這類用的是 ST）。Wi-Fi 晶片外掛，常見 Wi-Fi 5（MT7603 + MT7612 / MT7615），新一點的機種搭 Wi-Fi 6（MT7905 + MT7975 或 MT7915）。記憶體 128–512 MB，套件架構 `mipsel_24kc`。OpenWrt 25.12.6 有 288 個 profile，是 OpenWrt 支援最完整、恩山教學最多的平台，二手很便宜。缺點是 MIPS 效能弱，AES 沒有硬體加速。128 MB 的機種跑黑潮 DNS 夠用但偏緊，想多裝套件請挑 256 MB 以上。少數單核或 64 MB 的機種（例如 Buffalo WSR-600DHP、I-O DATA WN-GX300GR、TP-Link RE350 v1）不建議。表格只列在淘寶、閒魚或台灣通路實際買得到的機種。日本（ELECOM、I-O DATA、Buffalo）、韓國（ipTIME）、俄羅斯電信機（Beeline、Keenetic 等）和其他冷門白牌機，雖然有官方韌體，但台灣與中國很難買到，都沒有列。

| 類別 | 型號 | 記憶體 / 儲存 | 成熟度 | 刷機 | 價位 | 備註 |
|---|---|---|---|---|---|---|
| 🧩 | GL.iNet GL-MT1300（Beryl） | 256 MB / 32 MB NOR + microSD | 🟢 | ① | 💲💲 | 原廠就是 OpenWrt 改版，有 U-Boot 網頁救援。已停產，二手為主，後繼機改用 MT7981。 |
| 🧩 | Zbtlink ZBT-WG3526 / WE1326 / WG1608 / WG2626 / WE3526 | 512 MB（WG1608 為 256 MB）/ 16 或 32 MB NOR，部分有 microSD | 🟡 | ① | 💲 | 中國工控 / 白牌機，原廠就是 OpenWrt 系韌體，淘寶買新品。Padavan 支援 WE1326、WG3526。 |
| 🧩 | Huasifei WS1208V2 | 256 MB / 16 MB NOR | 🟡 | ① | 💲💲 | 原廠就是 OpenWrt，淘寶 / AliExpress 有賣。 |
| 🛒 | TP-Link Archer AX23 v1 | 128 MB / 16 MB NOR | 🟢 | ① | 💲💲 | 台灣通路常見的 Wi-Fi 6 機（MT7905 + MT7975），只限 v1。有 U-Boot 網頁救援。 |
| 🛒 | TP-Link Archer C6 v3 / A6 v3 / C6U v1 | 128 MB / 16 MB NOR | 🟢 | ① | 💲 | 用的是 MT7621DAT。只限 v3，C6 v2 是高通晶片，換別的晶片組。其他版本（未查證）。 |
| 🛒 | ASUS RT-AX53U / RT-AX1800U | 256 MB / 128 MB NAND | 🟢 | ③ | 💲💲 | 用 ASUS 救援模式 TFTP 刷，不用拆機。Wi-Fi 6，有 USB。 |
| 🛒 | ASUS RT-AX54 / RT-AX54HP / RT-AX1800HP / RT-AX1800S | 256 MB / 128 MB NAND | 🟢 | ③ | 💲💲 | 同上，用救援模式 TFTP 刷。 |
| 🛒 | TP-Link ER605 v1 / v2（TL-R605、FR205） | v1：128 MB / 16 MB NOR；v2：256 MB / 128 MB NAND | 🟡 | ②（未查證） | 💲💲 | Omada 有線多 WAN 路由器，沒有 Wi-Fi。v2 從 24.10 開始支援，v1 是 25.12 才加的，教學還少。 |
| 🛒 | Ubiquiti EdgeRouter X / ER-X-SFP / EdgePoint R6 | 256 MB / 256 MB NAND | 🟢 | ② | 💲💲 | 有線軟路由入門經典，從 EdgeOS SSH 刷。救磚要 TTL + TFTP。Padavan（padavan-ng）也支援 ER-X。 |
| 🛒 | MikroTik hEX RB750Gr3 / hEX S RB760iGS | 256 MB / 16 MB NOR + microSD | 🟢 | ③ | 💲💲 | 要用 MikroTik netinstall（TFTP）刷，不用拆機。hEX S 多一個 SFP。 |
| 🛒 | Ubiquiti UniFi U6 Lite | 256 MB / 32 MB NOR | 🟢 | ② | 💲💲💲 | 吸頂 AP，要 SSH 進去刷。適合當 AP，不適合當主路由。 |
| 🛒 | Ubiquiti UniFi nanoHD / FlexHD | 128 MB / 32 MB NOR | 🟡 | ② | 💲💲 | Wi-Fi 5 AP，台灣二手多。 |
| 🛒 | Zyxel NWA50AX / NWA90AX | 256 MB / 128 MB NAND | 🟡 | ① | 💲💲 | 原廠網頁就能刷 factory 檔。Wi-Fi 6 PoE AP，雙韌體分區。 |
| 🛒 | TOTOLINK X5000R | 256 MB / 16 MB NOR | 🟢 | ① | 💲💲 | 台灣 TOTOLINK 有賣，Wi-Fi 6，原廠網頁直刷。 |
| 🛒 | TOTOLINK A7000R | 128 MB / 16 MB NOR | 🟡 | ① | 💲 | Wi-Fi 5，原廠網頁直刷。 |
| 🛒 | Cudy X6 v1 / v1.1 / v2 | 256 MB / v1 32 MB、v2 16 MB NOR | 🟢 | ① | 💲💲 | Cudy 官網提供 OpenWrt 過渡韌體，直接從原廠網頁刷。台灣通路主要是蝦皮（未查證）。 |
| 🛒 | Cudy WR2100 / WR1300 v1–v3 / R700 | 128 MB / 16 MB NOR | 🟢 | ① | 💲 | R700 是沒有 Wi-Fi 的有線多 WAN 版。同樣有官方 OpenWrt 過渡韌體。 |
| 🛒 | TP-Link EAP613 v1 / EAP615-Wall v1 | EAP613：256 MB / 16 MB；EAP615-Wall：128 MB / 16 MB | 🟡 | ②（未查證） | 💲💲 | Omada 吸頂 / 壁裝 AP。EAP235-Wall 已從 25.12 移除。 |
| ♻️ | 紅米 AC2100、小米 AC2100 | 128 MB / 128 MB NAND | 🟢 | ② | 💲 | 恩山最熱門的入門刷機機種。原廠韌體 2.0.23 可以用 URL 注入開 SSH 刷 Breed（恩山 thread-4066963）。兩台韌體不通用。Padavan 支援（RM2100 / R2100）。 |
| ♻️ | 小米路由器 4A 千兆版 v1 / v2、小米 R3G v2 | 128 MB / 16 MB NOR | 🟢 | ② | 💲 | 用 OpenWRTInvasion 開 SSH，恩山有 Breed 教學（thread-8261014）。v2 要選 `-v2` 韌體。Padavan 支援（MI-R4A、R3Gv2）。 |
| ♻️ | 小米 R3G（v1） | 256 MB / 128 MB NAND | 🟢 | ② | 💲 | 有 USB 3.0。Breed 有專用版（xiaomi-r3g），Padavan 支援。 |
| ♻️ | 小米 R3P（Mi Router 3 Pro） | 512 MB / 256 MB NAND | 🟢 | ② | 💲 | 4x4 MT7615，記憶體大，很適合跑 DNS。Padavan 支援（R3P）。 |
| ♻️ | 小米路由器 4（R4） | 128 MB / 128 MB NAND | 🟡 | ② | 💲 | Padavan 支援（MI-4）。 |
| ♻️ | 斐訊 K2P A1 / A2、KE 2P | 128 MB / 16 MB NOR | 🟢 | ② | 💲 | B1 / B2 是博通晶片，不支援。舊版原廠韌體可用免拆工具刷 Breed，新版要 TTL。Padavan 支援。 |
| ♻️ | 聯想新路由 3（Newifi D2，常被叫成 Newifi D3） | 512 MB / 32 MB NOR | 🟢 | ② | 💲 | 恩山的經典大記憶體機。Breed 有專用版，Padavan 支援（NEWIFI3）。OpenWrt 韌體選「Newifi D2」。 |
| ♻️ | 聯想 Newifi D1（新路由 2） | 256 MB / 32 MB NOR | 🟢 | ② | 💲 | Breed 專用版，Padavan（padavan-ng）支援。 |
| ♻️ | 網件 R6220 / R6260 / R6350 / R6850 / WAC104 / WAC124 | 128 MB / 128 MB NAND | 🟢 | ① | 💲 | 原廠網頁直刷，救磚用 nmrpflash。R6220 / WAC104 是單核 MT7621ST。R6220 有 Breed，Padavan 支援 R6220 與 NETGEAR-CHJ 系列（R6260 / R6350 / R6850 / WAC124）。 |
| ♻️ | 網件 R6800 / R6700 v2 / R6900 v2 / R7200 / R7450 / Nighthawk AC2400 | 256 MB / 128 MB NAND | 🟢 | ① | 💲 | 原廠網頁直刷，救磚用 nmrpflash。Padavan 支援 NETGEAR-BZV 系列（R6800 / R6700v2 / R7200 / AC2400）。 |
| ♻️ | ASUS RT-AC85P / RT-AC65P | 256 MB / 128 MB NAND | 🟢 | ③ | 💲 | 用救援模式 TFTP 刷，不用拆機。 |
| ♻️ | D-Link DIR-882 / DIR-878 / DIR-867 / DIR-860L B1（含 R1 版） | 128 MB / 16 MB NOR | 🟢 | ① | 💲 | 用 D-Link Recovery GUI 刷。Padavan 支援 DIR-882、DIR-878、DIR-860L。 |
| ♻️ | Linksys EA7500 v2 / EA7300 v1 / v2 / EA8100 v1 / v2 | 256 MB / 128 MB NAND | 🟡 | ① | 💲 | 有雙韌體分區，原廠網頁直刷。Padavan（padavan-ng）支援 EA8100。 |
| ♻️ | 極路由 HC5962（極路由 4 增強版 / B70） | 256 MB / 128 MB NAND | 🟢 | ② | 💲 | Breed 專用版。Padavan 支援的「B70」應該就是這台（未查證）。 |
| ♻️ | 優酷路由寶 YK-L2 | 256 MB / 16 MB NOR | 🟢 | ② | 💲 | Breed 專用版。 |
| ♻️ | JCG Q20 | 256 MB / 128 MB NAND | 🟢 | ① | 💲 | Wi-Fi 6，原廠網頁直刷，閒魚很便宜。 |
| ♻️ | JCG Y2 / JHR-AC876M | 256 MB / 16 MB NOR | 🟢 | ① | 💲 | 原廠網頁直刷。Padavan 支援 Y2。 |
| ♻️ | 京東雲無線寶 RE-SP-01B（京東雲一代） | 512 MB / 32 MB NOR + 32–128 GB eMMC | 🟢 | ②（未查證） | 💲 | eMMC 可當儲存，恩山有大量教學，有 Breed 專用版（jd-cloud-1）。閒魚二手。 |
| ♻️ | 京東雲 RE-CP-02（AX1800 魯班） | 512 MB / 16 MB NOR + TF 卡槽 | 🟡 | ②（未查證） | 💲 | Wi-Fi 6。閒魚二手。 |
| ♻️ | H3C TX1800 Plus / TX1801 Plus / TX1806 | 256 MB / 128 MB NAND | 🟢 | ② | 💲 | 便宜的 Wi-Fi 6 機。刷機方法見 OpenWrt PR #9488（telnet）。閒魚二手。 |
| ♻️ | 歌華鏈 GHL-R-001、創意盒子 CreativeBox v1、小娛 XY-C5 | 512 MB / 32 MB NOR | 🟡 | ②（XY-C5 為 ③ TFTP） | 💲 | 恩山上的「大記憶體垃圾佬」機種，都有 Breed。GHL 用 telnet 刷。 |
| 📡 | 小米 CR6606（聯通）/ CR6608（移動）/ CR6609（電信） | 256 MB / 128 MB NAND | 🟢 | ② | 💲 | 恩山最熱門的電信版 Wi-Fi 6 機。要先降級到 1.0.103 以下再開 SSH。CR6606 跟 CR6608 / 6609 的 pbboot 不同，刷回 AX1800 時要注意。Padavan 支援（CR660x）。閒魚二手。 |
| 📡 | 中興 ZTE E8820S | 256 MB / 128 MB NAND | 🟠 | ② | 💲 | 只有 ImmortalWrt 支援，有 Breed 專用版。Padavan 支援（ZTE_E8820S）。是哪家電信的版本（未查證）。 |
| 📡 | 瑞斯康達 RAISECOM MSG1500 X.00（Nokia A-040W-Q） | 256 MB / 128 MB NAND | 🟡 | ② | 💲 | 中國電信系的光貓旁掛路由（未查證）。Padavan 支援（MSG1500）。 |

### MediaTek MT7620 / MT7628 / MT7688（只列 128 MB 以上）

MT7620A 是單核 MIPS 24KEc 580 MHz，Wi-Fi 4（2.4 GHz 2x2，5 GHz 要外掛 MT7610 / MT7612）。MT7628 / MT7688 是單核 580 MHz，只有 2.4 GHz Wi-Fi 4，乙太網路只有 100 Mbps。套件架構都是 `mipsel_24kc`，25.12.6 仍分別有 132 個（mt7620）和 129 個（mt76x8）profile。這兩個晶片絕大多數機種只有 64 MB 甚至 32 MB 記憶體，跑不動黑潮 DNS，例如小米 4A 百兆版 / 4C、TP-Link Archer C20 / C50、TL-WR840N / WR841N v13+。下面只列 128 MB 以上、還買得到的，大多是閒魚二手，效能只適合實驗或當小型旅行路由器。

| 類別 | 型號 | 記憶體 / 儲存 | 成熟度 | 刷機 | 價位 | 備註 |
|---|---|---|---|---|---|---|
| 🧩 | GL.iNet GL-MT300N-V2（Mango） | 128 MB / 16 MB NOR | 🟢 | ① | 💲 | MT7628，原廠就是 OpenWrt，有 U-Boot 網頁救援。Padavan 支援。 |
| 🧩 | GL.iNet microuter-N300 | 128 MB / 16 MB NOR | 🟡 | ① | 💲 | MT7628 迷你旅行路由器。 |
| 🧩 | Onion Omega2+、VoCore2、Hi-Link HLK-7628N / HLK-7688A | 128 MB / 16–32 MB NOR | 🟡 | ①（模組板多為 ③ TFTP） | 💲 | MT7628 / MT7688 的 IoT 模組和開發板，淘寶買得到，適合實驗，不適合當主路由。 |
| ♻️ | 聯想 Newifi Y1S | 256 MB / 16 MB NOR | 🟢 | ② | 💲 | MT7620A + 外掛 Gigabit 交換器。Breed 專用版，Padavan 支援。 |
| ♻️ | 聯想 Newifi mini Y1、小米 MiWiFi Mini | 128 MB / 16 MB NOR | 🟢 | ② | 💲 | MT7620A，都有 Breed 專用版，Padavan 支援。 |
| ♻️ | 優酷路由寶 YK-L1 / YK-L1W / YK-L1c | 128 MB / 32 MB（L1c 為 16 MB） | 🟢 | ① | 💲 | MT7620A，Breed（youku-yk1），Padavan 支援。 |
| ♻️ | 極路由 HC5661 / HC5761 / HC5861（MT7620A）、HC5661A / HC5761A / HC5861B（MT7628） | 128 MB / 16 MB NOR | 🟡 | ② | 💲 | 要開極路由開發者模式才能刷，HC5761 / HC5861 / HC5661A 有 Breed。Padavan 支援 MT7628 的 A / B 版。 |
| ♻️ | Zbtlink ZBT-WE826（B0 / T / E）、WE1026-H | 128 MB / 16 或 32 MB NOR | 🟡 | ① | 💲 | MT7620A 工控機，有 U-Boot 網頁救援。Padavan 支援 WE826-T2。 |

### Qualcomm Atheros ath79（QCA956x / QCA955x，MIPS）

單核 MIPS 74Kc，720–775 MHz，Wi-Fi 4 / 5，**大多數機種只有 64 MB 記憶體，跑不動黑潮 DNS**（例如 TP-Link TL-WR1043ND v2–v5、小米 4Q、Archer C60）。128 MB 的機種是下限，CPU 也很弱，只建議拿來練習或當 AP。套件架構 `mips_24kc`（target `ath79/generic`、`ath79/nand`）。下面列的都在 24.10 / 25.12 正式版裡。

| 類別 | 型號 | 記憶體 / 儲存 | 成熟度 | 刷機 | 價位 | 備註 |
|---|---|---|---|---|---|---|
| 🧩 | GL.iNet GL-AR750S（Slate）、GL-AR300M | 128 MB / 16 MB NOR + 128 MB NAND | 🟢 | ① | 💲～💲💲 | 原廠韌體是 OpenWrt 改的；有 U-Boot 網頁救援 |
| 🛒 | TP-Link Archer A6 v2（US / TW）、Archer C6 v2 | 128 MB / 16 MB NOR | 🟢 | ① | 💲 | profiles.json 寫明有台灣版；v3 以後換成 MediaTek，買之前要看清楚版本（現在新品多半已經是 v3 以後） |
| ♻️ | TP-Link Archer C7 v2 / v4 / v5、Archer A7 v5 | 128 MB / 16 MB NOR | 🟢 | ① | 💲 | 經典老機；原廠網頁直接刷 |
| ♻️ | ASUS RT-AC1500G PLUS、RT-AC58U v2 / v3、RT-AC57U v2 / v3（RT-AC59U 系列） | 128 MB / 16 或 32 MB NOR | 🟡 | ③ | 💲 | 台灣量販賣過；用 ASUS 救援模式（TFTP） |
| ♻️ | 小米 AIoT AC2350 | 128 MB / 16 MB NOR | 🟡 | ② | 💲 | 閒魚二手 |

### Lantiq xRX200（VRX288 / VRX220，MIPS 34Kc）

MIPS 34Kc 500 MHz，內建 VDSL2 / ADSL 數據機，記憶體 64–256 MB，套件架構 `mips_24kc`。24.10 / 25.12 都還有支援，但 128 MB 以上的機種全部是歐洲電信或 AVM 的 DSL 數據機（FRITZ!Box 7490 / 3490、BT Home Hub 5A、TP-Link VR200v 等）。台灣和中國都沒有通路，台灣也用不到 DSL，**不建議購買，不列表**。
