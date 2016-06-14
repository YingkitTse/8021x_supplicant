include $(TOPDIR)/rules.mk

PKG_NAME:=zdcclient

PKG_RELEASE:=1.2



PKG_FIXUP:=autoreconf
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  
  SECTION:=Utilities
  CATEGORY:=Utilities
  SUBMENU:=AOS
  DEPENDS:=+libpcap +libstdcpp
  TITLE:=shenzhoushuma 802.1x  supplicant  client
 
endef

define Package/$(PKG_NAME)/description
	山寨版的神州数码802.1x认证supplicant，基于pcap库的C语言的跨平台的原生客户端。
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	#$(Build/Compile/$(PKG_NAME))
	$(MAKE) -C $(PKG_BUILD_DIR)/ \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="$(TARGET_CPPFLAGS)"  \
		LIBS="$(STAGING_DIR)/usr/lib/libpcap.a"
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/zdclient $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/runzdclient $(1)/usr/bin/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
