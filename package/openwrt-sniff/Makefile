include $(TOPDIR)/rules.mk

PKG_NAME:=openwrt-sniff
PKG_VERSION:=$(if $(OPENWRT_SNIFF_VERSION),$(OPENWRT_SNIFF_VERSION),0.5.0)
PKG_RELEASE:=1
PKG_LICENSE:=GPL-3.0-or-later
PKG_MAINTAINER:=eeelin

include $(INCLUDE_DIR)/package.mk

define Package/openwrt-sniff
  SECTION:=net
  CATEGORY:=Network
  TITLE:=On-demand passive traffic visibility for OpenWrt
endef

define Package/openwrt-sniff/description
 A low-overhead AF_PACKET observer with an in-memory live React dashboard.
 It never enters the forwarding path and writes no traffic history to disk.
endef

define Package/openwrt-sniff/conffiles
/etc/config/sniffd
endef

define Build/Compile
endef

define Package/openwrt-sniff/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/usr/bin/openwrt-sniff $(1)/usr/bin/sniffd
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/sniffd $(1)/etc/init.d/sniffd
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/sniffd $(1)/etc/config/sniffd
endef

define Package/openwrt-sniff/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
if [ -f /etc/config/openwrt-sniff ]; then
	cp /etc/config/openwrt-sniff /etc/config/sniffd
fi
if [ -x /etc/init.d/openwrt-sniff ]; then
	/etc/init.d/openwrt-sniff disable >/dev/null 2>&1 || true
	/etc/init.d/openwrt-sniff stop >/dev/null 2>&1 || true
	rm -f /etc/init.d/openwrt-sniff
fi
exit 0
endef

$(eval $(call BuildPackage,openwrt-sniff))
