黑潮 DNS（Kuroshio DNS）OpenWrt 套件

這個壓縮檔裡有：
  kuroshio（核心）與 luci-app-kuroshio（LuCI 介面）兩個套件
  install.sh      一鍵安裝腳本
  PACKAGE_INFO    這包適用的 CPU 架構與 OpenWrt 版本

先確認下載對了：
  在路由器上執行 cat /etc/openwrt_release
  - DISTRIB_ARCH 要跟壓縮檔名最後一段相同（例如 aarch64_cortex-a53）
  - DISTRIB_RELEASE 是 24.10 就用 24.10 的壓縮檔（.ipk），25.12 以後用 25.12 的（.apk）
  不知道選哪個：https://github.com/candy999/kuroshio-dns/blob/main/docs/hardware.md

安裝方法一：一鍵安裝（推薦）
  1. 在電腦上解壓縮
  2. 把整個資料夾傳到路由器，例如：
       scp -O -r kuroshio-openwrt-24.10-x86_64 root@192.168.1.1:/tmp/
  3. SSH 登入路由器執行：
       sh /tmp/kuroshio-openwrt-24.10-x86_64/install.sh
  腳本會先檢查架構與版本，不符合就停下來告訴你該下載哪一個。

安裝方法二：用 LuCI 上傳
  系統 → 軟體套件 → 上傳套件，先上傳 kuroshio，再上傳 luci-app-kuroshio。
  （路由器要能連上網路，才能自動安裝相依套件）

安裝後：
  LuCI → 服務 → 黑潮 DNS，確認設定後按「啟用」。
  從 2.x（candydns）升級的話，舊的設定、自訂規則、憑證、社群金鑰會自動帶入。
