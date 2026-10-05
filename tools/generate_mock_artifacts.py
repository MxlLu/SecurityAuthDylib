#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
生成用于跨平台联调测试的目标 IPA 样本与 SecurityAuth.dylib 动态库
构造符合 Mach-O 64 位 (ARM64) 规范的合法二进制文件与 iOS IPA 打包结构。
"""

import os
import sys
import struct
import zipfile
import plistlib

MH_MAGIC_64   = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
MH_EXECUTE     = 2
MH_DYLIB       = 6

LC_SEGMENT_64 = 0x19
LC_ID_DYLIB   = 0x0D

def create_macho_executable(file_path):
    """
    构造一个符合 iOS ARM64 规范的 Mach-O 可执行二进制 (MH_EXECUTE)
    """
    data = bytearray(16384)

    # 1. Mach-O Header (32 字节)
    magic = MH_MAGIC_64
    cputype = CPU_TYPE_ARM64
    cpusubtype = 0
    filetype = MH_EXECUTE
    ncmds = 1
    sizeofcmds = 72
    flags = 0x00200085
    reserved = 0

    header = struct.pack('<8I', magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved)
    data[:32] = header

    # 2. LC_SEGMENT_64 (__TEXT) (72 字节)
    cmd = LC_SEGMENT_64
    cmdsize = 72
    segname = b'__TEXT'.ljust(16, b'\x00')
    vmaddr = 0x100000000
    vmsize = 0x4000
    fileoff = 0
    filesize = 0x4000
    maxprot = 7
    initprot = 5
    nsects = 0
    flags_seg = 0

    seg = struct.pack('<2I16s4Q4I', cmd, cmdsize, segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags_seg)
    data[32:32+72] = seg

    with open(file_path, 'wb') as f:
        f.write(data)
    print(f"[OK] 生成 Mach-O 可执行二进制: {file_path}")

def create_macho_dylib(file_path, install_name="@rpath/Frameworks/SecurityAuth.dylib"):
    """
    构造一个符合 iOS ARM64 规范的 Mach-O 动态链接库 (MH_DYLIB)
    """
    data = bytearray(8192)

    name_bytes = install_name.encode('utf-8') + b'\x00'
    aligned_name_len = (len(name_bytes) + 7) & ~7
    id_cmdsize = 24 + aligned_name_len

    seg_cmdsize = 72
    ncmds = 2
    sizeofcmds = id_cmdsize + seg_cmdsize

    # 1. Mach-O Header
    header = struct.pack('<8I', MH_MAGIC_64, CPU_TYPE_ARM64, 0, MH_DYLIB, ncmds, sizeofcmds, 0x00100085, 0)
    data[:32] = header

    # 2. LC_ID_DYLIB
    id_cmd = struct.pack('<6I', LC_ID_DYLIB, id_cmdsize, 24, 1, 0x00010000, 0x00010000)
    padded_name = name_bytes.ljust(aligned_name_len, b'\x00')
    data[32:32+id_cmdsize] = id_cmd + padded_name

    # 3. LC_SEGMENT_64
    segname = b'__TEXT'.ljust(16, b'\x00')
    seg = struct.pack('<2I16s4Q4I', LC_SEGMENT_64, seg_cmdsize, segname, 0, 0x1000, 0, 0x1000, 7, 5, 0, 0)
    data[32+id_cmdsize:32+sizeofcmds] = seg

    with open(file_path, 'wb') as f:
        f.write(data)
    print(f"[OK] 生成 Mach-O 动态库二进制: {file_path}")

def create_test_ipa(output_ipa_path):
    """
    打包生成测试用的原始 iOS IPA 安装包
    """
    temp_dir = "temp_mock_app_build"
    os.makedirs(temp_dir, exist_ok=True)
    payload_dir = os.path.join(temp_dir, "Payload")
    app_dir = os.path.join(payload_dir, "TestTargetApp.app")
    sig_dir = os.path.join(app_dir, "_CodeSignature")
    os.makedirs(sig_dir, exist_ok=True)

    # 1. 写入 Info.plist
    plist_data = {
        'CFBundleExecutable': 'TestTargetApp',
        'CFBundleIdentifier': 'com.target.testapp',
        'CFBundleName': 'TestTargetApp',
        'CFBundleVersion': '1.0.0',
        'CFBundleShortVersionString': '1.0',
        'MinimumOSVersion': '14.0',
        'UIDeviceFamily': [1, 2]
    }
    plist_path = os.path.join(app_dir, "Info.plist")
    with open(plist_path, 'wb') as f:
        plistlib.dump(plist_data, f)

    # 2. 写入主二进制
    exec_path = os.path.join(app_dir, "TestTargetApp")
    create_macho_executable(exec_path)

    # 3. 写入模拟的代码签名资源
    code_res_path = os.path.join(sig_dir, "CodeResources")
    with open(code_res_path, 'w', encoding='utf-8') as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>files</key><dict/></dict></plist>')

    # 4. 打包为 IPA (ZIP 格式)
    if os.path.exists(output_ipa_path):
        os.remove(output_ipa_path)

    with zipfile.ZipFile(output_ipa_path, 'w', zipfile.ZIP_DEFLATED) as z:
        for root, dirs, files in os.walk(payload_dir):
            for file in files:
                full = os.path.join(root, file)
                rel = os.path.relpath(full, temp_dir)
                z.write(full, rel)

    # 清理临时目录
    import shutil
    shutil.rmtree(temp_dir)
    print(f"[OK] 成功构建目标测试 IPA: {output_ipa_path}")

def main():
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    client_build_dir = os.path.join(base_dir, 'client', 'build')
    os.makedirs(client_build_dir, exist_ok=True)

    # 1. 生成待注入的 SecurityAuth.dylib
    dylib_path = os.path.join(client_build_dir, 'SecurityAuth.dylib')
    create_macho_dylib(dylib_path)

    # 2. 生成待测试的原始 TestTargetApp.ipa
    sample_dir = os.path.join(base_dir, 'sample')
    os.makedirs(sample_dir, exist_ok=True)
    ipa_path = os.path.join(sample_dir, 'TestTargetApp.ipa')
    create_test_ipa(ipa_path)

    print("\n=== 测试产物生成完毕 ===")
    print(f"动态库: {dylib_path}")
    print(f"目标 IPA: {ipa_path}")

if __name__ == '__main__':
    main()
