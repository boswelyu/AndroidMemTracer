LOCAL_PATH := $(call my-dir)  
  
include $(CLEAR_VARS)  
LOCAL_CFLAGS += -fPIE
LOCAL_LDFLAGS += -fPIE -pie
LOCAL_MODULE := commander   
LOCAL_SRC_FILES := commander.c
  
LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog  
  
include $(BUILD_EXECUTABLE)  