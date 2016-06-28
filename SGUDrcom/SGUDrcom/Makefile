include $(TOPDIR)/rules.mk
include $(TOPDIR)/package.mk
PKG_NAME:=EasyDrcom
PKG_RELEASE:=1.0

PKG_INSTALL:=0

define Package/$(PKG_NAME)
	SECTION:=Utilities
	CATEGORY:=Utilities
	SUBMENU:=AOS
	DEPENDS:=+libpcap +libstdcpp
	TITLE:=DrCom 3th party supplicant
endef

define Package/$(PKG_NAME)/description
	DrCom 3th party supplicant
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
		CPPFLAGS="$(TARGET_CPPFLAGS)" \
		LIBS="$(STAGING_DIR)/usr/lib/libpcap.a"
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/EasyDrcom $(1)/usr/bin
endef

$(eval $(call BuildPackage,$(PKG_NAME)))

