ARCHS = arm64

TARGET := iphone:clang:16.5:16.5

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = jb-detect-bypass

jb-detect-bypass_FILES = main.m
jb-detect-bypass_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
