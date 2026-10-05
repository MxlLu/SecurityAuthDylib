# iOS 动态库注入与打包重签名工具链 (tools/)

[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blue.svg)]()
[![Python](https://img.shields.io/badge/Python-3.8%2B-green.svg)]()
[![Status](https://img.shields.io/badge/Tools-Production%20Ready-brightgreen.svg)]()

本目录包含一套**完全跨平台**（零外部 C 库依赖，Windows / Linux / macOS 通用）的 Mach-O 二进制注入与 IPA 补丁打包工具链。

---

## 1. 核心工具清单

| 脚本文件 | 适用系统 | 核心职责 |
| :--- | :--- | :--- |
| **`macho_inject.py`** | 跨平台 (Win/Mac/Linux) | 纯 Python 实现的 Mach-O 注入器，向 Thin/FAT 二进制注入 `LC_LOAD_DYLIB` |
| **`ipa_patcher.py`** | 跨平台 (Win/Mac/Linux) | 自动化解包 IPA $\to$ 注入 `SecurityAuth.dylib` $\to$ 写入加载命令 $\to$ 重打包 |
| **`resign.py`** | 跨平台 (Win/Mac/Linux) | 基于 `zsign` 的自动化 IPA 重签名脚本 (支持自定义 BundleID 与 App 名字) |
| **`test_inject.py`** | 跨平台 (Win/Mac/Linux) | Mach-O 注入器完整性与防重复注入单元自测脚本 |

---

## 2. 跨平台 Mach-O 注入原理

传统注入必须在 macOS 上使用编译型 `optool` 或 `insert_dylib`。
本工程中的 `macho_inject.py` 采用原生 Python `struct` 模块：
1. **Header 解析**：识别 64 位 (`MH_MAGIC_64`) 与 FAT 胖二进制 (`FAT_MAGIC`)；
2. **段间隙利用**：计算 Header 到第一个 Section 之间的对齐 Padding 空隙；
3. **命令构造**：按 8 字节边界对齐构造 `struct dylib_command`，写入目标库路径（如 `@rpath/Frameworks/SecurityAuth.dylib`）；
4. **Header 原子更新**：同步递增 `ncmds` 与 `sizeofcmds`，完成注入。

---

## 3. 实操使用指南

### 3.1 一键向 IPA 注入动态库
将目标 IPA 文件与编译好的 `SecurityAuth.dylib` 准备好后，执行：
```bash
python tools/ipa_patcher.py TargetApp.ipa --dylib client/build/SecurityAuth.dylib -o TargetApp_Injected.ipa
```
输出：
- 自动生成 `TargetApp_Injected.ipa`，动态库已植入 `Payload/*.app/Frameworks/SecurityAuth.dylib`，主二进制已注入加载命令，且旧签名目录 `_CodeSignature` 已安全清除。

### 3.2 对注入后的 IPA 重签名
配合开发者证书 (`.p12`) 与描述文件 (`.mobileprovision`)：
```bash
python tools/resign.py TargetApp_Injected.ipa -k my_cert.p12 -p cert_password -m embedded.mobileprovision -o TargetApp_Final.ipa
```
> **提示**：Windows 用户可将预编译的 `zsign.exe` 放入 `tools/` 目录或系统 PATH 中，脚本会自动优先调用。

### 3.3 单独注入单个 Mach-O 二进制文件
如果已经手动提取出 Mach-O 可执行文件：
```bash
python tools/macho_inject.py TargetBinary "@rpath/Frameworks/SecurityAuth.dylib"
```

### 3.4 运行注入器自检套件
```bash
python tools/test_inject.py
```
预期输出：`=== Mach-O 跨平台注入器测试全部通过！===`
