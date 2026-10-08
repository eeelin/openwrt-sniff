include $(TOPDIR)/rules.mk

PKG_NAME:=openwrt-sniff
PKG_VERSION:=$(if $(OPENWRT_SNIFF_VERSION),$(OPENWRT_SNIFF_VERSION),0.1.0)
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
/etc/config/openwrt-sniff
endef

define Build/Compile
endef

define Package/openwrt-sniff/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/usr/bin/openwrt-sniff $(1)/usr/bin/openwrt-sniff
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/openwrt-sniff $(1)/etc/init.d/openwrt-sniff
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/openwrt-sniff $(1)/etc/config/openwrt-sniff
endef

$(eval $(call BuildPackage,openwrt-sniff))

