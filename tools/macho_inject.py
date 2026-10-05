#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mach-O 纯 Python 跨平台动态库注入工具
支持在 Windows / Linux / macOS 上直接修改 Mach-O 二进制文件，
向 Load Commands 中添加 LC_LOAD_DYLIB，无需外部 optool 或 macOS 环境。
"""

import sys
import os
import struct
import argparse

# Mach-O 常量定义
MH_MAGIC_64 = 0xFEEDFACF     # 64 位小端
MH_CIGAM_64 = 0xCFFAEDFE     # 64 位大端
MH_MAGIC    = 0xFEEDFACE     # 32 位小端
MH_CIGAM    = 0xCEFAEDFE     # 32 位大端

FAT_MAGIC   = 0xCAFEBABE     # FAT 胖二进制 (大端)
FAT_CIGAM   = 0xBEBAFECA
FAT_MAGIC_64= 0xCAFEBABB

LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0x0C
LC_LOAD_WEAK_DYLIB = 0x8000000C

def align8(val):
    return (val + 7) & ~7

class MachOInjector:
    def __init__(self, filepath):
        self.filepath = filepath
        with open(filepath, 'rb') as f:
            self.data = bytearray(f.read())

    def inject(self, dylib_path, weak=False):
        """
        向 Mach-O 二进制注入动态库加载命令
        """
        if len(self.data) < 4:
            raise ValueError("文件体积过小，非有效 Mach-O 文件")

        magic = struct.unpack('>I', self.data[:4])[0]
        injected_count = 0

        if magic == FAT_MAGIC:
            print("[+] 检测到 FAT Universal 胖二进制，开始遍历架构切片...")
            nfat_arch = struct.unpack('>I', self.data[4:8])[0]
            for i in range(nfat_arch):
                arch_entry = 8 + i * 20
                cputype, cpusubtype, offset, size, align = struct.unpack('>5I', self.data[arch_entry:arch_entry+20])
                print(f"[+] 处理架构切片 #{i}: cputype=0x{cputype:x}, offset=0x{offset:x}, size={size}")
                if self._inject_single_slice(offset, size, dylib_path, weak):
                    injected_count += 1
        else:
            # 单架构 Thin 二进制
            if self._inject_single_slice(0, len(self.data), dylib_path, weak):
                injected_count += 1

        if injected_count > 0:
            with open(self.filepath, 'wb') as f:
                f.write(self.data)
            print(f"[OK] 成功向 {injected_count} 个架构切片注入: {dylib_path}")
            return True
        else:
            print("[!] 未执行任何注入操作 (可能已存在或空间不足)")
            return False

    def _inject_single_slice(self, slice_offset, slice_size, dylib_path, weak=False):
        slice_data = self.data[slice_offset:slice_offset + slice_size]
        magic = struct.unpack('<I', slice_data[:4])[0]

        is_64 = False
        endian = '<'

        if magic == MH_MAGIC_64:
            is_64 = True
            endian = '<'
        elif magic == MH_CIGAM_64:
            is_64 = True
            endian = '>'
        elif magic == MH_MAGIC:
            is_64 = False
            endian = '<'
        elif magic == MH_CIGAM:
            is_64 = False
            endian = '>'
        else:
            print(f"[!] 架构切片 (offset=0x{slice_offset:x}) 魔数未知: 0x{magic:x}，跳过")
            return False

        header_size = 32 if is_64 else 28
        fmt = f'{endian}7I' if not is_64 else f'{endian}8I'
        header_tuple = struct.unpack(fmt, slice_data[:header_size])
        
        # 解析头字段: magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags [, reserved]
        ncmds = header_tuple[4]
        sizeofcmds = header_tuple[5]

        print(f"    - 原命令数: {ncmds}, 命令总大小: {sizeofcmds} 字节")

        # 遍历现有 Load Commands，检查是否已存在同名 dylib，并寻找可用空间边界
        cmd_offset = slice_offset + header_size
        min_section_offset = slice_size

        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack(f'{endian}2I', self.data[cmd_offset:cmd_offset + 8])
            if cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB):
                # 检查 dylib 名称
                name_offset = struct.unpack(f'{endian}I', self.data[cmd_offset + 8:cmd_offset + 12])[0]
                name_bytes = self.data[cmd_offset + name_offset:cmd_offset + cmdsize]
                current_dylib = name_bytes.split(b'\x00')[0].decode('utf-8', errors='ignore')
                if current_dylib == dylib_path:
                    print(f"    - 目标 dylib 已存在于命令中: {dylib_path}，跳过重复注入")
                    return False

            if cmd == LC_SEGMENT_64:
                # 寻找第一个 section 的起始文件偏移以确定 padding 上限
                nsects = struct.unpack(f'{endian}I', self.data[cmd_offset + 64:cmd_offset + 68])[0]
                sect_start = cmd_offset + 72
                for s in range(nsects):
                    sect_offset = struct.unpack(f'{endian}I', self.data[sect_start + s * 80 + 32:sect_start + s * 80 + 36])[0]
                    if 0 < sect_offset < min_section_offset:
                        min_section_offset = sect_offset

            cmd_offset += cmdsize

        # 构建新的 dylib_command
        # struct dylib_command {
        #     uint32_t cmd;
        #     uint32_t cmdsize;
        #     struct dylib {
        #         union lc_str name; (offset: uint32_t)
        #         uint32_t timestamp;
        #         uint32_t current_version;
        #         uint32_t compatibility_version;
        #     } dylib;
        # };
        path_bytes = dylib_path.encode('utf-8') + b'\x00'
        aligned_path_len = align8(len(path_bytes))
        padded_path = path_bytes.ljust(aligned_path_len, b'\x00')

        new_cmd = LC_LOAD_WEAK_DYLIB if weak else LC_LOAD_DYLIB
        new_cmdsize = 24 + aligned_path_len

        # 检查 Header Padding 空间是否足够容纳新命令
        space_available = min_section_offset - (header_size + sizeofcmds)
        if space_available < new_cmdsize:
            print(f"    [!] 空间不足: 剩余 padding 仅 {space_available} 字节，所需 {new_cmdsize} 字节")
            return False

        # 构造二进制命令数据
        dylib_cmd_bytes = struct.pack(
            f'{endian}6I',
            new_cmd,
            new_cmdsize,
            24,           # name_offset (相对于命令起始位置)
            2,            # timestamp
            0x00010000,   # current_version (1.0.0)
            0x00010000    # compatibility_version (1.0.0)
        ) + padded_path

        # 写入新命令到原有命令末尾
        insert_pos = slice_offset + header_size + sizeofcmds
        self.data[insert_pos:insert_pos + new_cmdsize] = dylib_cmd_bytes

        # 更新 Header 中的 ncmds 和 sizeofcmds
        new_ncmds = ncmds + 1
        new_sizeofcmds = sizeofcmds + new_cmdsize

        if is_64:
            new_header = struct.pack(
                fmt,
                header_tuple[0], header_tuple[1], header_tuple[2], header_tuple[3],
                new_ncmds, new_sizeofcmds, header_tuple[6], header_tuple[7]
            )
        else:
            new_header = struct.pack(
                fmt,
                header_tuple[0], header_tuple[1], header_tuple[2], header_tuple[3],
                new_ncmds, new_sizeofcmds, header_tuple[6]
            )

        self.data[slice_offset:slice_offset + header_size] = new_header
        print(f"    [OK] 写入新命令成功! 新命令数: {new_ncmds}, 新大小: {new_sizeofcmds} 字节")
        return True

def main():
    parser = argparse.ArgumentParser(description="Mach-O 二进制 LC_LOAD_DYLIB 跨平台注入工具")
    parser.add_argument("binary", help="目标 Mach-O 二进制文件路径")
    parser.add_argument("dylib", help="待注入的动态库路径 (例如 @rpath/Frameworks/SecurityAuth.dylib)")
    parser.add_argument("--weak", action="store_true", help="使用 LC_LOAD_WEAK_DYLIB 代替 LC_LOAD_DYLIB")

    args = parser.parse_args()

    if not os.path.exists(args.binary):
        print(f"错误: 文件不存在: {args.binary}")
        sys.exit(1)

    injector = MachOInjector(args.binary)
    success = injector.inject(args.dylib, args.weak)
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
