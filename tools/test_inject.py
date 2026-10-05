#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mach-O 注入器自测脚本
构造最小合法 Mach-O 64 位二进制模型，验证 macho_inject.py 注入前后数据完整性。
"""

import os
import struct
from macho_inject import MachOInjector, MH_MAGIC_64, LC_SEGMENT_64, LC_LOAD_DYLIB

def create_mock_macho():
    # 模拟一个 16KB 的 Mach-O 64 位可执行文件
    data = bytearray(16384)

    # 1. Mach-O 64-bit Header (32 bytes)
    magic = MH_MAGIC_64
    cputype = 0x0100000C     # CPU_TYPE_ARM64
    cpusubtype = 0           # ALL
    filetype = 2             # MH_EXECUTE
    ncmds = 1
    sizeofcmds = 72          # 包含一个 LC_SEGMENT_64
    flags = 0x00200085
    reserved = 0

    header = struct.pack('<8I', magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved)
    data[:32] = header

    # 2. 构造一个 LC_SEGMENT_64 (72 bytes)
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

    segment_bytes = struct.pack('<2I16s4Q4I', cmd, cmdsize, segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags_seg)
    data[32:32+72] = segment_bytes

    # 模拟在 0x1000 (4096) 处开始有 section 数据，中间为 padding
    return data

def main():
    test_file = "mock_test_macho"
    try:
        mock_data = create_mock_macho()
        with open(test_file, 'wb') as f:
            f.write(mock_data)

        print("[+] 模拟 Mach-O 二进制创建完毕，准备执行注入...")
        injector = MachOInjector(test_file)
        dylib_to_inject = "@rpath/Frameworks/SecurityAuth.dylib"
        success = injector.inject(dylib_to_inject)

        assert success, "注入应该返回 True"

        # 重新读取并验证
        with open(test_file, 'rb') as f:
            res_data = f.read()

        magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack('<8I', res_data[:32])
        print(f"[+] 验证注入后结果: ncmds={ncmds}, sizeofcmds={sizeofcmds}")

        assert ncmds == 2, f"预期 ncmds 为 2，实际为 {ncmds}"

        # 检查第二个命令
        cmd2_offset = 32 + 72
        cmd, cmdsize, name_off = struct.unpack('<3I', res_data[cmd2_offset:cmd2_offset+12])
        assert cmd == LC_LOAD_DYLIB, f"预期为 LC_LOAD_DYLIB (12)，实际为 {cmd}"

        name_str = res_data[cmd2_offset + name_off:cmd2_offset + cmdsize].split(b'\x00')[0].decode('utf-8')
        assert name_str == dylib_to_inject, f"注入路径不匹配: {name_str}"

        print(f"[OK] 注入验证通过！成功读取到路径: {name_str}")

        # 测试重复注入防重
        print("[+] 测试重复注入防重逻辑...")
        injector2 = MachOInjector(test_file)
        dup_success = injector2.inject(dylib_to_inject)
        assert not dup_success, "重复注入应该被检测并跳过"
        print("[OK] 重复注入检测生效！")

        print("\n=== Mach-O 跨平台注入器测试全部通过！===")
    finally:
        if os.path.exists(test_file):
            os.remove(test_file)

if __name__ == '__main__':
    main()
