# ==========================================================
# SecurityAuthDylib Makefile
# 目标: 编译生成 iOS arm64 架构的 SecurityAuth.dylib
# ==========================================================

TARGET_NAME = SecurityAuth.dylib
BUILD_DIR   = ../build

# 编译器与 SDK 配置 (macOS/Xcode 环境下自动定位，支持交叉编译)
CC          ?= xcrun -sdk iphoneos clang
SYSROOT     ?= $(shell xcrun --sdk iphoneos --show-sdk-path 2>/dev/null)

ARCH        = -arch arm64
MIN_IOS_VER = -miphoneos-version-min=14.0

CFLAGS      = $(ARCH) $(MIN_IOS_VER) -isysroot $(SYSROOT) \
              -fobjc-arc -O2 \
              -fvisibility=hidden \
              -I./include \
              -Wall

LDFLAGS     = $(ARCH) $(MIN_IOS_VER) -isysroot $(SYSROOT) \
              -dynamiclib \
              -install_name @rpath/Frameworks/$(TARGET_NAME) \
              -framework Foundation \
              -framework UIKit \
              -framework Security \
              -lSystem

SRCS        = src/Entry.m \
              src/Core/AuthConfig.m \
              src/Core/AuthManager.m \
              src/Security/AuthSecurity.m \
              src/Security/DeviceFingerprint.m \
              src/Crypto/CryptoEngine.m \
              src/Network/NetworkTransport.m \
              src/UI/AuthUIOverlay.m

all: $(BUILD_DIR)/$(TARGET_NAME)

$(BUILD_DIR)/$(TARGET_NAME): $(SRCS)
	@mkdir -p $(BUILD_DIR)
	@echo "[+] Compiling $(TARGET_NAME)..."
	$(CC) $(CFLAGS) $(LDFLAGS) $(SRCS) -o $@
	@echo "[✓] Build Success: $@"

clean:
	@rm -rf $(BUILD_DIR)
	@echo "[✓] Cleaned build directory."

.PHONY: all clean
