ARCHS = arm64
THEOS_PACKAGE_SCHEME = rootless

TARGET := iphone:clang:16.5:16.5
INSTALL_TARGET_PROCESSES = applaunchmond

include $(THEOS)/makefiles/common.mk

TOOL_NAME = applaunchmond

applaunchmond_FILES = main.m
applaunchmond_CFLAGS = -fobjc-arc
applaunchmond_CODESIGN_FLAGS = -Sentitlements.plist
applaunchmond_INSTALL_PATH = /usr/local/libexec
applaunchmond_PRIVATE_FRAMEWORKS = MobileContainerManager BackBoardServices SpringBoardServices

include $(THEOS_MAKE_PATH)/tool.mk

SUBPROJECTS += jb-detect-bypass
include $(THEOS_MAKE_PATH)/aggregate.mk