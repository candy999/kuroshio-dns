# LuCI 介面：狀態、儀表板、基本設定、廣告過濾、CDN 台灣節點、進階、日誌

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-kuroshio
PKG_VERSION:=3.1.0
PKG_RELEASE:=1
PKG_MAINTAINER:=Kuroshio DNS contributors
PKG_LICENSE:=GPL-3.0-or-later

include $(INCLUDE_DIR)/package.mk

# 共用儀表板（data/dashboard：公開頁、Windows 設定頁、LuCI 同一份）在 repo 的 data/ 底下
REPO_ROOT:=$(CURDIR)/../..

define Package/luci-app-kuroshio
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=LuCI support for Kuroshio DNS
  PKGARCH:=all
  DEPENDS:=+kuroshio
  EXTRA_DEPENDS:=luci-base (>=0)
endef

define Package/luci-app-kuroshio/description
  LuCI pages for kuroshio: status, dashboard, settings (simple / pro mode),
  filter lists and custom rules, CDN Taiwan nodes, advanced tuning, log.
endef

define Build/Compile
endef

define Package/luci-app-kuroshio/install
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view/kuroshio $(1)/www/luci-static/resources/kuroshio
	$(INSTALL_DATA) ./htdocs/luci-static/resources/view/kuroshio/*.js $(1)/www/luci-static/resources/view/kuroshio/
	$(INSTALL_DATA) ./htdocs/luci-static/resources/kuroshio/*.js $(1)/www/luci-static/resources/kuroshio/
	$(INSTALL_DATA) $(REPO_ROOT)/data/dashboard/dashboard.js $(REPO_ROOT)/data/dashboard/dashboard.css $(1)/www/luci-static/resources/kuroshio/
	$(INSTALL_DIR) $(1)/usr/share/luci/menu.d $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) ./root/usr/share/luci/menu.d/luci-app-kuroshio.json $(1)/usr/share/luci/menu.d/
	$(INSTALL_DATA) ./root/usr/share/rpcd/acl.d/luci-app-kuroshio.json $(1)/usr/share/rpcd/acl.d/
	# 介面版本（「關於」顯示，跟核心版本分開）
	$(INSTALL_DIR) $(1)/usr/share/luci-app-kuroshio
	echo "$(PKG_VERSION)-r$(PKG_RELEASE)" > $(1)/usr/share/luci-app-kuroshio/version
endef

define Package/luci-app-kuroshio/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	rm -f /tmp/luci-indexcache /tmp/luci-indexcache.*
	/etc/init.d/rpcd reload
}
exit 0
endef

$(eval $(call BuildPackage,luci-app-kuroshio))
