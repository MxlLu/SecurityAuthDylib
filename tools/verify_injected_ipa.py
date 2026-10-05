#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
检验注入后的 IPA 二进制与结构完整性
"""

import sys
import zipfile
import struct

LC_LOAD_DYLIB = 0x0C
LC_LOAD_WEAK_DYLIB = 0x8000000C

def verify_injected_ipa(ipa_path):
    print(f"=== 开始深度校验注入后的 IPA: {ipa_path} ===\n")

    with zipfile.ZipFile(ipa_path, 'r') as z:
        file_list = z.namelist()
        print(f"[+] IPA 内包含文件数: {len(file_list)}")

        # 1. 检验 Frameworks 动态库是否存在
        dylib_found = any('Frameworks/SecurityAuth.dylib' in f for f in file_list)
        print(f"[+] 动态库检查: Frameworks/SecurityAuth.dylib -> {'存在 [OK]' if dylib_found else '缺失 [FAIL]'}")
        assert dylib_found, "未在 IPA 中找到注入的动态库"

        # 2. 检验原 _CodeSignature 是否已被清理
        sig_found = any('_CodeSignature' in f for f in file_list)
        print(f"[+] 旧签名清理检查: _CodeSignature -> {'未清理 [WARN]' if sig_found else '已安全清除 [OK]'}")

        # 3. 提取主可执行文件进行二进制结构解析
        main_exec_name = None
        for f in file_list:
            if f.startswith('Payload/') and f.endswith('.app/TestTargetApp'):
                main_exec_name = f
                break

        assert main_exec_name, "未找到主可执行文件"
        print(f"[+] 提取主二进制: {main_exec_name}")
        exec_bytes = z.read(main_exec_name)

    # 4. 解析 Mach-O 二进制
    magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack('<8I', exec_bytes[:32])
    print(f"[+] Mach-O 魔数: 0x{magic:X} (ARM64)")
    print(f"[+] 命令总数: {ncmds}, 命令区大小: {sizeofcmds} 字节")

    offset = 32
    loaded_dylibs = []

    for i in range(ncmds):
        cmd, cmdsize = struct.unpack('<2I', exec_bytes[offset:offset+8])
        if cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB):
            name_offset = struct.unpack('<I', exec_bytes[offset+8:offset+12])[0]
            name_raw = exec_bytes[offset+name_offset:offset+cmdsize]
            dylib_name = name_raw.split(b'\x00')[0].decode('utf-8')
            loaded_dylibs.append(dylib_name)
        offset += cmdsize

    print("\n[+] 二进制引用的动态库列表:")
    for idx, d in enumerate(loaded_dylibs, 1):
        print(f"    {idx}. {d}")

    expected_dylib = "@rpath/Frameworks/SecurityAuth.dylib"
    assert expected_dylib in loaded_dylibs, f"未检测到预期注入的加载命令: {expected_dylib}"

    print(f"\n[OK] 注入命令校验通过: {expected_dylib} 位于 Load Commands 索引 #{loaded_dylibs.index(expected_dylib) + 1}")
    print("\n====================================================")
    print("[SUCCESS] 目标测试 IPA 注入打包与二进制校验 100% 成功！")
    print("====================================================\n")

if __name__ == '__main__':
    ipa = sys.argv[1] if len(sys.argv) > 1 else 'sample/TestTargetApp_Injected.ipa'
    verify_injected_ipa(ipa)
