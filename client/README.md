# SecurityAuthDylib (iOS 注入动态库)

[![Platform](https://img.shields.io/badge/Platform-iOS%2014.0%2B-blue.svg)]()
[![Language](https://img.shields.io/badge/Language-Objective--C%20%7C%20C-orange.svg)]()
[![Architecture](https://img.shields.io/badge/Arch-arm64-green.svg)]()

本目录包含 **iOS 网络验证框架客户端核心动态库 (SecurityAuth.dylib)** 的完整实现代码。

---

## 1. 架构模块划分

| 模块 | 头文件 | 实现文件 | 核心职责 |
| :--- | :--- | :--- | :--- |
| **注入入口** | - | `src/Entry.m` | `__attribute__((constructor))` 引导函数，监听启动通知 |
| **状态机核心** | `include/AuthManager.h` | `src/Core/AuthManager.m` | 握手、激活、静默免密核验、心跳定时器、异常熔断 |
| **安全反调试** | `include/AuthSecurity.h` | `src/Security/AuthSecurity.m` | `ptrace`、`sysctl P_TRACED`、Frida 端口探针、越狱路径排查 |
| **设备指纹** | `include/DeviceFingerprint.h` | `src/Security/DeviceFingerprint.m` | Keychain 强持久化 UUID、IDFV、硬件特征复合 SHA256 指纹 |
| **密码学引擎** | `include/CryptoEngine.h` | `src/Crypto/CryptoEngine.m` | RSA-OAEP 公钥加密、AES-256-GCM 双向加解密、HMAC-SHA256 签名 |
| **安全通信** | `include/NetworkTransport.h` | `src/Network/NetworkTransport.m` | `NSURLSession` 封装、自动添加 Nonce、时间戳与签名 Header |
| **原生 UI** | `include/AuthUIOverlay.h` | `src/UI/AuthUIOverlay.m` | 纯原生 `UIWindowLevelAlert` 独立浮层、暗黑模式毛玻璃弹窗 |

---

## 2. 编译与构建

### 2.1 macOS / Xcode 环境原生编译
直接在 `client/SecurityAuthDylib/` 目录下执行：
```bash
make
```
构建成功后将在 `client/build/SecurityAuth.dylib` 生成 arm64 架构的动态库产物。

### 2.2 CMake 跨平台构建
```bash
mkdir build && cd build
cmake -DCMAKE_SYSTEM_NAME=iOS -DCMAKE_OSX_ARCHITECTURES=arm64 ..
cmake --build .
```

---

## 3. 部署与注入规范

生成的 `SecurityAuth.dylib` 依赖路径已预先设置为：
`@rpath/Frameworks/SecurityAuth.dylib`

使用配套的 `tools/ipa_patcher.py` 可自动化将其植入目标 IPA 的 `Frameworks/` 目录，并注入到 Mach-O 主二进制的 Load Commands 中。
