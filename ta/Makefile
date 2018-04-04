CFG_TEE_TA_LOG_LEVEL ?= 4
CPPFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)

#LDFLAGS += /home/pedro/devel/optee/optee_examples/HCEMobile/libs/libsqlite3.a
#LDADD += -lsqlite3 -L/home/pedro/devel/optee/optee_examples/HCEMobile/libs
#LDADD += -ldl -L/home/pedro/devel/optee/toolchains/aarch64/aarch64-linux-gnu/libc/usr/lib
#LDADD += -lc -L/home/pedro/devel/optee/toolchains/aarch64/aarch64-linux-gnu/libc/usr/lib

#LDFLAGS += -static

# The UUID for the Trusted Application
BINARY=4b1459ae-feb4-49a9-a47a-e65b6b4d1f49

-include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

ifeq ($(wildcard $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk), )
clean:
	@echo 'Note: $$(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk not found, cannot clean TA'
	@echo 'Note: TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)'
endif
