###################### DBSTORE ######################
LOCAL_PATH := $(call my-dir)

OPTEE_CLIENT_EXPORT = $(LOCAL_PATH)/../../optee_client/out/export

include $(CLEAR_VARS)
LOCAL_CFLAGS += -DANDROID_BUILD
LOCAL_CFLAGS += -Wall

LOCAL_SRC_FILES += host/DBStoreLib.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)/ta/include \
		$(OPTEE_CLIENT_EXPORT)/include \

LOCAL_SHARED_LIBRARIES := libteec libsqlite3
LOCAL_MODULE := dbstore
LOCAL_MODULE_TAGS := optional
include $(BUILD_EXECUTABLE)

include $(LOCAL_PATH)/ta/Android.mk
