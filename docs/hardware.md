# 選硬體、選套件

黑潮 DNS 支援四大平台：**64 位元 ARM、32 位元 ARM、MIPS、x86**。這份說明各平台有哪些常見的晶片與機種、規格大概多少、跑黑潮 DNS 的感受，以及要下載哪一個套件。

> 機種規格以常見版本為準；同一個型號常有不同硬體版本（例如記憶體減半的「青春版」），請以你手上那台的實際規格為準。

## 先查你的路由器是哪一種

在路由器上用 SSH 執行：

```sh
cat /etc/openwrt_release      # 看 DISTRIB_ARCH（套件架構）和 DISTRIB_RELEASE（OpenWrt 版本）
free -m                       # 記憶體
df -h /overlay                # 剩餘的儲存空間
```

LuCI 的「狀態 → 總覽」也看得到架構與記憶體。

- **套件架構**：下載檔名裡同名的那一個（例如 `DISTRIB_ARCH='aarch64_cortex-a53'` → 下載 `aarch64_cortex-a53` 的套件）。
- **OpenWrt 版本**：24.10 用 `.ipk`，25.12 以後用 `.apk`。

## 黑潮 DNS 需要多少

| 記憶體 | 可以怎麼用 |
|---|---|
| **64 MB 以下** | ❌ 不支援 |
| **128 MB** | ✅ 可以用。預設過濾清單、少量好友；記憶體吃緊時會自動讓出快取與冷門資料，最低保留 DNS 轉發 |
| **256 MB** | ✅ 舒適。全部功能都能開，預設清單加幾份額外清單 |
| **512 MB 以上** | ✅ 全開。大型清單（例如 HaGeZi 百萬條）、DoQ / DoH3 伺服器、好友、CDN 掃描同時開也沒問題 |

| 儲存空間（Flash） | 可以怎麼用 |
|---|---|
| **8 MB** | ❌ 裝不下 |
| **16 MB** | ✅ 安裝後要剩 4 MB 以上 |
| **32 MB 以上，或 NAND / eMMC / SD** | ✅ 舒適；空間大方時會多存過濾清單的本機副本，重開機不用等下載 |

CPU 方面：DNS 本身很輕，單核 MIPS 也跑得動；差別在 DoT / DoH 這類加密連線多、CDN 驗證與每日評測的速度。多核 ARM 與 x86 明顯比較從容。

## 1. ARMv8 / AArch64（64 位元 ARM）—— 目前主流，買新機首選

新一代 Wi-Fi 6 / 7 路由器、NanoPi、樹莓派都是這一類。效能好、記憶體大，黑潮 DNS 全部功能都能開。

| 晶片 | CPU | 常見記憶體 / 儲存 | 代表機種 | 套件架構 |
|---|---|---|---|---|
| **MediaTek MT7981B**（Filogic 820） | 雙核 Cortex-A53 1.3 GHz | 256 MB–1 GB / 128–256 MB NAND | OpenWrt One、小米 AX3000T、GL.iNet MT3000 | `aarch64_cortex-a53` |
| **MediaTek MT7986A**（Filogic 830） | 四核 Cortex-A53 2.0 GHz | 512 MB–2 GB / NAND 或 eMMC | GL.iNet MT6000、Banana Pi R3 | `aarch64_cortex-a53` |
| MediaTek MT7988A（Filogic 880） | 四核 Cortex-A73 1.8 GHz | 4 GB / eMMC | Banana Pi R4 | `aarch64_cortex-a53` |
| MediaTek MT7622 | 雙核 Cortex-A53 1.35 GHz | 512 MB / 128 MB NAND | Linksys E8450、Belkin RT3200 | `aarch64_cortex-a53` |
| **Qualcomm IPQ807x** | 四核 Cortex-A53 2.2 GHz | 512 MB–1 GB / NAND | 小米 AX3600 / AX9000、Dynalink DL-WRX36 | `aarch64_cortex-a53` |
| **Qualcomm IPQ60xx**（IPQ6000 / 6010 / 6018） | 四核 Cortex-A53 1.2–1.8 GHz | 512 MB–1 GB / NAND | 紅米 AX5、各家 Wi-Fi 6 機 | `aarch64_cortex-a53` |
| Qualcomm IPQ50xx | 雙核 Cortex-A53 | 256–512 MB / NAND | 部分 Wi-Fi 6 入門機 | `aarch64_cortex-a53` |
| **Rockchip RK3328** | 四核 Cortex-A53 1.3 GHz | 1 GB / microSD | NanoPi R2S、R2C | `aarch64_generic` |
| Rockchip RK3399 | 雙核 A72 + 四核 A53 | 1–4 GB / microSD | NanoPi R4S | `aarch64_generic` |
| Rockchip RK3568 / RK3588 | 四核 A55 / 八核 A76+A55 | 2–8 GB / eMMC | NanoPi R5S、R6S | `aarch64_generic` |
| Raspberry Pi 3 | 四核 Cortex-A53 1.2 GHz | 1 GB / microSD | — | `aarch64_cortex-a53` |
| Raspberry Pi 4 | 四核 Cortex-A72 1.5 GHz | 1–8 GB / microSD | — | `aarch64_cortex-a72` |
| Raspberry Pi 5 | 四核 Cortex-A76 2.4 GHz | 2–16 GB / microSD | — | `aarch64_cortex-a76` |

- 這一類全部用同一個黑潮 DNS 執行檔，只是依 OpenWrt 的套件架構名稱包成不同的套件；請下載跟 `DISTRIB_ARCH` 同名的那一個。
- IPQ60xx / IPQ807x 很多機種跑的是 ImmortalWrt 等分支；套件架構一樣是 `aarch64_cortex-a53`，但請依分支的 OpenWrt 版本選 `.ipk`（24.10）或 `.apk`（25.12 以後）。

## 2. ARMv7（32 位元 ARM）—— 上一代主力，仍然很好用

| 晶片 | CPU | 常見記憶體 / 儲存 | 代表機種 | 套件架構 |
|---|---|---|---|---|
| **Qualcomm IPQ4018 / IPQ4019** | 四核 Cortex-A7 717 MHz | 128–512 MB / 32 MB NOR 或 128 MB NAND | Google WiFi、Linksys EA6350 v3、GL.iNet B1300、ASUS RT-AC58U | `arm_cortex-a7_neon-vfpv4` |
| Qualcomm IPQ806x | 雙核 Krait 1.4–1.7 GHz | 512 MB / 128 MB NAND | Netgear R7800、TP-Link C2600、Linksys EA8500 | `arm_cortex-a15_neon-vfpv4` |
| Marvell Armada 385 | 雙核 Cortex-A9 1.6–1.8 GHz | 512 MB–1 GB / 128–256 MB NAND | Linksys WRT1900ACS / WRT3200ACM / WRT32X、Turris Omnia | `arm_cortex-a9_vfpv3-d16` |
| Allwinner H3 | 四核 Cortex-A7 | 256 MB–1 GB / microSD | NanoPi NEO、Orange Pi | `arm_cortex-a7_neon-vfpv4` |
| Raspberry Pi 2 | 四核 Cortex-A7 900 MHz | 1 GB / microSD | — | `arm_cortex-a7_neon-vfpv4` |

- 這一類全部用同一個 32 位元 ARM 執行檔（硬體浮點）。
- IPQ40xx 有 128 MB 記憶體的版本：可以用，但建議只開預設清單。

## 3. MIPS（32 位元）—— 老將，存量很大，選記憶體夠的

MIPS 分**小端序**（`mipsel`）和**大端序**（`mips`）兩種，互不相容，一定要選對。

| 晶片 | CPU | 常見記憶體 / 儲存 | 代表機種 | 套件架構 |
|---|---|---|---|---|
| **MediaTek MT7621**（A / AT / DAT） | 雙核四執行緒 MIPS 1004Kc 880 MHz | 128–512 MB / 16 MB NOR–128 MB NAND | 小米 R3G、小米 4A 千兆版、紅米 AC2100、Newifi D2、Ubiquiti ER-X | **小端序** `mipsel_24kc` |
| MediaTek MT7620 / MT7628 / MT7688 | 單核 MIPS 24K 約 580 MHz | 大多 64 MB / 8–16 MB | 小米 mini、各種入門機 | **小端序** `mipsel_24kc` |
| **Qualcomm Atheros** QCA9563 / QCA9558 / QCA9531 | 單核 MIPS 74K / 24K 650–775 MHz | 64–128 MB / 16 MB NOR | TP-Link Archer C7、GL.iNet AR300M / AR750 | **大端序** `mips_24kc` |
| Lantiq / Intel xRX200 | 雙核 MIPS 34Kc 500 MHz | 128 MB / NAND | FritzBox 7360 / 7490、BT Home Hub 5 | **大端序** `mips_24kc` |

- **MT7621** 是 MIPS 裡最推薦的：雙核、128 MB 以上記憶體，黑潮 DNS 跑得很穩。
- **MT7620 / MT7628 / MT7688**：大多只有 64 MB 記憶體、8 MB 儲存，**跑不動**。少數 128 MB 記憶體、16 MB 儲存的機種可以試，但單核 580 MHz 很吃力，建議只開基本功能。
- **Atheros（ath79）**：128 MB 記憶體、16 MB 儲存的機種（例如 Archer C7 v2 以後）可以用；64 MB 的不支援。

## 4. x86 —— 軟路由，效能最好

| 平台 | 常見規格 | 代表 | 套件架構 |
|---|---|---|---|
| **x86_64**（64 位元） | Intel N100 / N5105 / J4125、AMD 低功耗處理器；4–16 GB / SSD | 小主機軟路由、虛擬機（Proxmox、ESXi、Hyper-V） | `x86_64` |

- 資源最充裕，全部功能、大型清單都沒問題。
- 不提供 32 位元 x86（i386）：那個年代的電腦連 PPPoE 撥號加 NAT 都吃力，不適合當路由器。
- 不跑 OpenWrt 的 x86 電腦：Linux 用 `x86_64` 靜態執行檔，Windows 10 / 11 用 Windows 版。

## 想買新機的話

| 需求 | 建議 |
|---|---|
| 一般家庭、要 Wi-Fi | **MediaTek Filogic（MT7981 / MT7986）**：價格親民、記憶體 256 MB 以上、OpenWrt 官方支援完整 |
| 效能優先、不在意 Wi-Fi | **x86_64 小主機（N100）** 或 **NanoPi R4S / R5S / R6S** |
| 手邊已有舊機 | **MT7621、IPQ40xx、IPQ806x、Armada 385** 都很適合 |
| 避開 | 記憶體 64 MB 以下、儲存 8 MB 的機種 |

## 下載與安裝

到 GitHub **Releases**（或 **Actions → Kuroshio DNS (Rust)**）下載 `kuroshio-openwrt-<OpenWrt 版本>-<套件架構>.zip`，例如 OpenWrt 24.10 的 NanoPi R2S 下載 `kuroshio-openwrt-24.10-aarch64_generic.zip`。壓縮檔裡有兩個套件與一鍵安裝腳本 `install.sh`，安裝方式見 [`openwrt/README.md`](../openwrt/README.md)。每次推送只會自動產生 x86_64 的套件；發布版本或手動執行「編譯所有 CPU 的 OpenWrt 套件」時，才會產生所有架構的套件。
