# kuroshio — 黑潮 DNS（Kuroshio DNS）3.0
# Rust 單一執行檔，不需要 node。執行檔由 CI 先用 cargo-zigbuild 編好（靜態連結 musl），
# 放在 <repo>/prebuilt/<OpenWrt ARCH>/kuroshio，這裡只負責打包。

include $(TOPDIR)/rules.mk

PKG_NAME:=kuroshio
PKG_VERSION:=3.0.0_alpha2
PKG_RELEASE:=1
PKG_MAINTAINER:=Kuroshio DNS contributors
PKG_LICENSE:=GPL-3.0-or-later
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk

REPO_ROOT:=$(CURDIR)/../..
PREBUILT:=$(REPO_ROOT)/prebuilt/$(ARCH)/kuroshio

define Package/kuroshio
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=IP Addresses and Names
  TITLE:=Kuroshio DNS: DNS server that keeps CDN traffic in Taiwan
  URL:=https://github.com/candy999/kuroshio-dns
  # 只在安裝時需要（不讓 SDK 去編譯）；25.12 起每項都要有版本條件
  EXTRA_DEPENDS:=ca-bundle (>=0), acme-acmesh (>=0), acme-acmesh-dnsapi (>=0)
endef

define Package/kuroshio/description
  黑潮 DNS（Kuroshio DNS）：區網 DNS、DoH / DoT / DoQ / DoH3、廣告 / 遙測 / 詐騙過濾、
  CDN 台灣節點置換、每日上游評測、Cloudflare DDNS、Let's Encrypt 憑證。
  Rust 單一執行檔，依硬體自動調整（128 MB 記憶體的路由器也能用）。
endef

define Package/kuroshio/conffiles
/etc/config/kuroshio
/etc/kuroshio/custom-rules.txt
/etc/kuroshio/cert.pem
/etc/kuroshio/key.pem
/etc/kuroshio/community/key.pem
endef

define Build/Prepare
	[ -f "$(PREBUILT)" ] || { echo "找不到 $(PREBUILT)：請先用 cargo zigbuild 編譯（見 .github/workflows/rust.yml）"; exit 1; }
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) $(PREBUILT) $(PKG_BUILD_DIR)/kuroshio
endef

define Build/Compile
endef

define Package/kuroshio/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/config $(1)/etc/init.d $(1)/etc/uci-defaults $(1)/usr/libexec/kuroshio $(1)/usr/libexec/rpcd
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/kuroshio $(1)/usr/bin/kuroshio
	$(INSTALL_CONF) ./files/kuroshio.config $(1)/etc/config/kuroshio
	$(INSTALL_BIN) ./files/kuroshio.init $(1)/etc/init.d/kuroshio
	$(INSTALL_BIN) ./files/kuroshio.uci-defaults $(1)/etc/uci-defaults/90-kuroshio
	$(INSTALL_BIN) ./files/takeover.sh $(1)/usr/libexec/kuroshio/takeover.sh
	$(INSTALL_BIN) ./files/guard.sh $(1)/usr/libexec/kuroshio/guard.sh
	$(INSTALL_DATA) ./files/lan.sh $(1)/usr/libexec/kuroshio/lan.sh
	$(INSTALL_BIN) ./files/acme.sh $(1)/usr/libexec/kuroshio/acme.sh
	$(INSTALL_BIN) ./files/access.sh $(1)/usr/libexec/kuroshio/access.sh
	$(INSTALL_BIN) ./files/rpcd.sh $(1)/usr/libexec/rpcd/kuroshio
	# 唯讀資料：種子、評測名單、CDN 官方範圍、公開網頁、共用儀表板、預設自訂規則
	$(INSTALL_DIR) $(1)/usr/share/kuroshio
	$(CP) $(REPO_ROOT)/data/seed $(1)/usr/share/kuroshio/seed
	$(CP) $(REPO_ROOT)/data/benchmark $(1)/usr/share/kuroshio/benchmark
	$(CP) $(REPO_ROOT)/data/cdn $(1)/usr/share/kuroshio/cdn
	$(CP) $(REPO_ROOT)/data/geo $(1)/usr/share/kuroshio/geo
	$(CP) $(REPO_ROOT)/data/site $(1)/usr/share/kuroshio/site
	$(CP) $(REPO_ROOT)/data/dashboard $(1)/usr/share/kuroshio/dashboard
	$(INSTALL_DATA) $(REPO_ROOT)/rules/default-custom-rules.txt $(1)/usr/share/kuroshio/default-custom-rules.txt
endef

define Package/kuroshio/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || /etc/init.d/rpcd reload
exit 0
endef

$(eval $(call BuildPackage,kuroshio))
