include $(TOPDIR)/rules.mk

PKG_NAME:=nfqws2-strategy
PKG_MAINTAINER:=NFQWS2 Strategy
PKG_LICENSE:=NOASSERTION
PKG_URL:=https://github.com/Omn1z/nfqws2-keenetic-strategy-selector
include $(CURDIR)/version.mk
PKG_FILE_DEPENDS:=$(CURDIR)/payload $(CURDIR)/packages.mk $(CURDIR)/postinst $(CURDIR)/prerm
include $(INCLUDE_DIR)/package.mk

ifneq ($(DUMP),1)
  ifneq ($(ARCH_PACKAGES),$(N2S_ARCH))
    $(error Payload for $(N2S_ARCH) cannot be installed in SDK for $(ARCH_PACKAGES))
  endif
endif

# Cargo's release profile already strips these static executables. In
# particular, a second sstrip can remove the ABI headers on MIPS.
RSTRIP:=:

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
endef
Build/Configure:=
Build/Compile:=

define N2SPackage
  define Package/$(1)
    SECTION:=net
    CATEGORY:=Network
    TITLE:=$(2)
    DEPENDS:=$(addprefix +,$(3))
    EXTRA_DEPENDS:=$$(PINNED_$(1))
  endef
  define Package/$(1)/install
	mkdir -p $$(1)
	tar -xzf $(CURDIR)/payload/$(1).tar.gz -C $$(1)
  endef
endef

include $(CURDIR)/packages.mk

define Package/nfqws2-strategy-compact/postinst
$(file <$(CURDIR)/postinst)
endef
define Package/nfqws2-strategy-compact/prerm
$(file <$(CURDIR)/prerm)
endef

$(foreach pkg,$(N2S_PACKAGES),$(eval $(call BuildPackage,$(pkg))))
