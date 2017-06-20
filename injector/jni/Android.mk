LOCAL_PATH := $(call my-dir)  
  
include $(CLEAR_VARS)  
LOCAL_CFLAGS += -fPIE
LOCAL_LDFLAGS += -fPIE -pie
LOCAL_MODULE := memtrace  
LOCAL_SRC_FILES := ptraceInject.c InjectModule.c
  
LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog  
  
include $(BUILD_EXECUTABLE)  