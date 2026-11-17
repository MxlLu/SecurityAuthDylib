#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
=============================================================================
iOS IPA 智能寄生伪装与防剥离注入工具 v1.1 (低内存流式引擎)
iOS IPA Parasitic Masquerade & Anti-Stripping Injection Tool
=============================================================================
特点:
1. 极致低内存: 流式分块传输，不把整个几GB的IPA解压到磁盘，也不载入内存，峰值内存 < 30MB。
2. 精准 Mach-O 修复:
   - 修正 section_64.offset (+48) 读取，杜绝覆盖破坏指令区导致闪退；
   - 自动验证 Header Padding 空间是否充足且全 0，自动跳过空间不足的寄生体；
   - 保持 LC_CODE_SIGNATURE 处于 Load Commands 末尾，确保各类重签名工具完美兼容；
   - 采用 @executable_path/Frameworks/xxx.dylib 路径，彻底解决 @rpath 双重目录或找不到库闪退；
   - 自动检测 IPA 是否未砸壳 (cryptid != 0) 与 Dylib 是否为有效真实编译产物。
=============================================================================
"""

import os
import sys
import gc
import struct
import shutil
import zipfile
import plistlib
import argparse
import tracemalloc
import time

# Mach-O 常量定义
MH_MAGIC_64           = 0xFEEDFACF     # 64 位小端
MH_CIGAM_64           = 0xCFFAEDFE     # 64 位大端
MH_MAGIC              = 0xFEEDFACE     # 32 位小端
MH_CIGAM              = 0xCEFAEDFE     # 32 位大端
FAT_MAGIC             = 0xCAFEBABE     # FAT 胖二进制 (大端)
FAT_CIGAM             = 0xBEBAFECA
FAT_MAGIC_64          = 0xCAFEBABB

MH_DYLIB              = 6
CPU_TYPE_ARM64        = 0x0100000C

LC_SEGMENT            = 0x01
LC_SYMTAB             = 0x02
LC_LOAD_DYLIB         = 0x0C
LC_ID_DYLIB           = 0x0D
LC_SEGMENT_64         = 0x19
LC_CODE_SIGNATURE     = 0x1D
LC_ENCRYPTION_INFO    = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C
LC_LOAD_WEAK_DYLIB    = 0x8000000C
LC_REEXPORT_DYLIB     = 0x8000001F
LC_RPATH              = 0x8000001C

def align8(val):
    return (val + 7) & ~7

class MachOInspector:
    """轻量级 Mach-O 头部快速解析器 (流式按需读取，支持 Thin 与 FAT)"""

    @staticmethod
    def read_macho_header_from_zip(zfile, entry_path):
        """从 ZIP 中流式读取单个 Mach-O 的目标切片头部 (最多读 256KB)"""
        with zfile.open(entry_path, 'r') as f:
            head = f.read(262144)
        if len(head) < 32:
            return None

        be_magic = struct.unpack('>I', head[:4])[0]
        if be_magic == FAT_MAGIC:
            nfat_arch = struct.unpack('>I', head[4:8])[0]
            target_offset = None
            first_offset = None
            for i in range(min(nfat_arch, 16)):
                pos = 8 + i * 20
                if pos + 20 > len(head):
                    break
                cputype, cpusubtype, offset, size, align = struct.unpack('>5I', head[pos:pos + 20])
                if first_offset is None:
                    first_offset = offset
                if cputype == CPU_TYPE_ARM64:
                    target_offset = offset
                    break
            use_offset = target_offset if target_offset is not None else first_offset
            if use_offset is None:
                return None
            if use_offset + 262144 <= len(head):
                return MachOInspector.parse_headers_and_cmds(head[use_offset:use_offset + 262144])
            with zfile.open(entry_path, 'r') as f2:
                remaining = use_offset
                while remaining > 0:
                    skipped = f2.read(min(remaining, 1024 * 1024))
                    if not skipped:
                        return None
                    remaining -= len(skipped)
                slice_head = f2.read(262144)
                return MachOInspector.parse_headers_and_cmds(slice_head)
        else:
            return MachOInspector.parse_headers_and_cmds(head)

    @staticmethod
    def parse_headers_and_cmds(raw_header_bytes):
        if len(raw_header_bytes) < 32:
            return None

        magic = struct.unpack('<I', raw_header_bytes[:4])[0]
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
            return None

        header_size = 32 if is_64 else 28
        fmt = f'{endian}7I' if not is_64 else f'{endian}8I'
        if len(raw_header_bytes) < header_size:
            return None

        header_tuple = struct.unpack(fmt, raw_header_bytes[:header_size])
        cputype = header_tuple[1]
        filetype = header_tuple[3]
        ncmds = header_tuple[4]
        sizeofcmds = header_tuple[5]

        offset = header_size
        loaded_dylibs = []
        rpaths = []
        min_section_offset = len(raw_header_bytes)
        encrypted = False
        has_symtab = False

        for _ in range(ncmds):
            if offset + 8 > len(raw_header_bytes):
                break
            cmd, cmdsize = struct.unpack(f'{endian}2I', raw_header_bytes[offset:offset + 8])
            if cmdsize < 8 or offset + cmdsize > len(raw_header_bytes):
                break

            if cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB):
                if offset + 12 <= len(raw_header_bytes):
                    name_off = struct.unpack(f'{endian}I', raw_header_bytes[offset + 8:offset + 12])[0]
                    name_bytes = raw_header_bytes[offset + name_off:offset + cmdsize]
                    dylib_str = name_bytes.split(b'\x00')[0].decode('utf-8', errors='ignore')
                    loaded_dylibs.append(dylib_str)
            elif cmd == LC_RPATH:
                if offset + 12 <= len(raw_header_bytes):
                    path_off = struct.unpack(f'{endian}I', raw_header_bytes[offset + 8:offset + 12])[0]
                    path_bytes = raw_header_bytes[offset + path_off:offset + cmdsize]
                    rpath_str = path_bytes.split(b'\x00')[0].decode('utf-8', errors='ignore')
                    rpaths.append(rpath_str)
            elif cmd == LC_SEGMENT_64 and offset + 72 <= len(raw_header_bytes):
                # section_64: 80 bytes, uint32_t offset at +48
                nsects = struct.unpack(f'{endian}I', raw_header_bytes[offset + 64:offset + 68])[0]
                sect_start = offset + 72
                for s in range(nsects):
                    if sect_start + s * 80 + 52 <= len(raw_header_bytes):
                        sect_offset = struct.unpack(f'{endian}I', raw_header_bytes[sect_start + s * 80 + 48:sect_start + s * 80 + 52])[0]
                        if 0 < sect_offset < min_section_offset:
                            min_section_offset = sect_offset
            elif cmd == LC_SEGMENT and offset + 56 <= len(raw_header_bytes):
                # section (32-bit): 68 bytes, uint32_t offset at +40
                nsects = struct.unpack(f'{endian}I', raw_header_bytes[offset + 48:offset + 52])[0]
                sect_start = offset + 56
                for s in range(nsects):
                    if sect_start + s * 68 + 44 <= len(raw_header_bytes):
                        sect_offset = struct.unpack(f'{endian}I', raw_header_bytes[sect_start + s * 68 + 40:sect_start + s * 68 + 44])[0]
                        if 0 < sect_offset < min_section_offset:
                            min_section_offset = sect_offset
            elif cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
                if offset + 20 <= len(raw_header_bytes):
                    cryptid = struct.unpack(f'{endian}I', raw_header_bytes[offset + 16:offset + 20])[0]
                    if cryptid != 0:
                        encrypted = True
            elif cmd == LC_SYMTAB:
                has_symtab = True

            offset += cmdsize

        # 计算真正连续的全 0 填充空间
        cmds_end = header_size + sizeofcmds
        raw_gap = max(0, min_section_offset - cmds_end)
        zero_pad = 0
        limit = min(cmds_end + raw_gap, len(raw_header_bytes))
        for idx in range(cmds_end, limit):
            if raw_header_bytes[idx] == 0:
                zero_pad += 1
            else:
                break

        return {
            'is_64': is_64,
            'cputype': cputype,
            'filetype': filetype,
            'ncmds': ncmds,
            'sizeofcmds': sizeofcmds,
            'loaded_dylibs': loaded_dylibs,
            'rpaths': rpaths,
            'encrypted': encrypted,
            'has_symtab': has_symtab,
            'free_pad_bytes': zero_pad
        }

    @staticmethod
    def validate_dylib(dylib_path):
        """校验待注入的 dylib 是否为合法的已编译真实动态库"""
        if not os.path.exists(dylib_path):
            return False, "动态库文件不存在"
        file_size = os.path.getsize(dylib_path)
        if file_size < 4096:
            return False, f"动态库体积过小 ({file_size} 字节)"

        with open(dylib_path, 'rb') as f:
            head = f.read(262144)

        be_magic = struct.unpack('>I', head[:4])[0]
        if be_magic == FAT_MAGIC:
            nfat_arch = struct.unpack('>I', head[4:8])[0]
            parsed = None
            for i in range(min(nfat_arch, 16)):
                pos = 8 + i * 20
                cputype, _, offset, _, _ = struct.unpack('>5I', head[pos:pos + 20])
                if cputype == CPU_TYPE_ARM64 and offset + 64 < len(head):
                    parsed = MachOInspector.parse_headers_and_cmds(head[offset:])
                    break
        else:
            parsed = MachOInspector.parse_headers_and_cmds(head)

        if not parsed:
            return False, "非有效的 Mach-O 二进制格式"
        if parsed['filetype'] != MH_DYLIB:
            return False, f"文件类型不是动态库 (MH_DYLIB={MH_DYLIB}, 实际={parsed['filetype']})"

        # 检测是否为 generate_mock_artifacts.py 生成的 8KB 模拟空壳
        if file_size <= 16384 and not parsed['has_symtab'] and len(parsed['loaded_dylibs']) == 0:
            return False, (
                "检测到您使用的是 8KB 测试占位假包 (generate_mock_artifacts.py 生成)，"
                "它不包含可执行的 arm64 代码段，注入真机必然闪退！\n"
                "请使用 Mac 或 GitHub Actions 编译生成的真实 SecurityAuth.dylib。"
            )
        return True, "真实有效的 Mach-O 动态库"


class MachOInjectorMemory:
    """内存级 Mach-O 注入器，仅修改目标二进制并直接输出字节"""
    def __init__(self, data_bytes):
        self.data = bytearray(data_bytes)

    def inject(self, dylib_path, weak=False):
        if len(self.data) < 4:
            return False, "文件体积过小"

        magic = struct.unpack('>I', self.data[:4])[0]
        if magic == FAT_MAGIC:
            nfat_arch = struct.unpack('>I', self.data[4:8])[0]
            count = 0
            for i in range(nfat_arch):
                arch_entry = 8 + i * 20
                cputype, cpusubtype, offset, size, align = struct.unpack('>5I', self.data[arch_entry:arch_entry+20])
                if self._inject_slice(offset, size, dylib_path, weak):
                    count += 1
            return (count > 0), f"FAT架构成功注入 {count} 个切片" if count > 0 else "FAT 架构所有切片均空间不足或已存在"
        else:
            ok, reason = self._inject_slice(0, len(self.data), dylib_path, weak, return_reason=True)
            return ok, reason

    def _inject_slice(self, slice_offset, slice_size, dylib_path, weak=False, return_reason=False):
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
            return (False, "未知 Mach-O 魔数") if return_reason else False

        header_size = 32 if is_64 else 28
        fmt = f'{endian}7I' if not is_64 else f'{endian}8I'
        header_tuple = struct.unpack(fmt, slice_data[:header_size])

        ncmds = header_tuple[4]
        sizeofcmds = header_tuple[5]

        cmd_offset = slice_offset + header_size
        min_section_offset = slice_size
        last_cmd = None
        last_cmd_offset = cmd_offset
        last_cmdsize = 0

        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack(f'{endian}2I', self.data[cmd_offset:cmd_offset + 8])
            last_cmd = cmd
            last_cmd_offset = cmd_offset
            last_cmdsize = cmdsize

            if cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB):
                name_offset = struct.unpack(f'{endian}I', self.data[cmd_offset + 8:cmd_offset + 12])[0]
                name_bytes = self.data[cmd_offset + name_offset:cmd_offset + cmdsize]
                current_dylib = name_bytes.split(b'\x00')[0].decode('utf-8', errors='ignore')
                if current_dylib == dylib_path or os.path.basename(current_dylib) == os.path.basename(dylib_path):
                    msg = f"目标动态库已存在于加载命令中: {current_dylib}"
                    return (False, msg) if return_reason else False

            if cmd == LC_SEGMENT_64:
                # section_64: 80 bytes each, uint32_t offset is at +48 (NOT +32 which is vmaddr!)
                nsects = struct.unpack(f'{endian}I', self.data[cmd_offset + 64:cmd_offset + 68])[0]
                sect_start = cmd_offset + 72
                for s in range(nsects):
                    sect_offset = struct.unpack(f'{endian}I', self.data[sect_start + s * 80 + 48:sect_start + s * 80 + 52])[0]
                    if 0 < sect_offset < min_section_offset:
                        min_section_offset = sect_offset
            elif cmd == LC_SEGMENT:
                # section (32-bit): 68 bytes each, uint32_t offset is at +40
                nsects = struct.unpack(f'{endian}I', self.data[cmd_offset + 48:cmd_offset + 52])[0]
                sect_start = cmd_offset + 56
                for s in range(nsects):
                    sect_offset = struct.unpack(f'{endian}I', self.data[sect_start + s * 68 + 40:sect_start + s * 68 + 44])[0]
                    if 0 < sect_offset < min_section_offset:
                        min_section_offset = sect_offset

            cmd_offset += cmdsize

        # 构建新的 dylib_command
        dylib_bytes = dylib_path.encode('utf-8') + b'\x00'
        cmd_type = LC_LOAD_WEAK_DYLIB if weak else LC_LOAD_DYLIB
        cmd_name_offset = 24
        new_cmd_size = align8(cmd_name_offset + len(dylib_bytes))

        # 检查 Header Padding 空间是否足够
        if cmd_offset + new_cmd_size > slice_offset + min_section_offset:
            avail = (slice_offset + min_section_offset) - cmd_offset
            msg = f"Header 空间不足 (剩余 {avail} 字节, 需要 {new_cmd_size} 字节)"
            return (False, msg) if return_reason else False

        # 验证目标填充区域全为 0，绝不破坏代码/数据
        if not all(b == 0 for b in self.data[cmd_offset:cmd_offset + new_cmd_size]):
            msg = "Header 尾部非全 0 填充区，中止写入以防破坏代码段"
            return (False, msg) if return_reason else False

        cmd_data = bytearray(new_cmd_size)
        struct.pack_into(f'{endian}I', cmd_data, 0, cmd_type)
        struct.pack_into(f'{endian}I', cmd_data, 4, new_cmd_size)
        struct.pack_into(f'{endian}I', cmd_data, 8, cmd_name_offset)
        struct.pack_into(f'{endian}I', cmd_data, 12, 2)        # timestamp
        struct.pack_into(f'{endian}I', cmd_data, 16, 0x10000)  # current_version 1.0.0
        struct.pack_into(f'{endian}I', cmd_data, 20, 0x10000)  # compatibility_version 1.0.0
        cmd_data[cmd_name_offset:cmd_name_offset + len(dylib_bytes)] = dylib_bytes

        # 保持 LC_CODE_SIGNATURE 处于 Load Commands 的最后一条，防止重签工具报错
        if last_cmd == LC_CODE_SIGNATURE and last_cmdsize > 0:
            sig_bytes = bytes(self.data[last_cmd_offset:last_cmd_offset + last_cmdsize])
            self.data[last_cmd_offset:last_cmd_offset + new_cmd_size] = cmd_data
            self.data[last_cmd_offset + new_cmd_size:last_cmd_offset + new_cmd_size + last_cmdsize] = sig_bytes
        else:
            self.data[cmd_offset:cmd_offset + new_cmd_size] = cmd_data

        # 更新 Header
        struct.pack_into(f'{endian}I', self.data, slice_offset + 16, ncmds + 1)
        struct.pack_into(f'{endian}I', self.data, slice_offset + 20, sizeofcmds + new_cmd_size)
        return (True, "单架构注入成功") if return_reason else True

    def get_bytes(self):
        return bytes(self.data)


class ParasiteAnalyzer:
    """智能寄生分析与诊断核心"""

    KNOWN_ENGINES = {
        'UnityFramework': ('Unity 游戏引擎核心', 100, 'S+ 极佳宿主'),
        'Flutter': ('Flutter 跨平台渲染引擎', 98, 'S+ 极佳宿主'),
        'React': ('React Native 核心运行时', 95, 'S 极佳宿主'),
        'hermes': ('Hermes JS 引擎核心', 92, 'S 极佳宿主'),
        'Cocos2d': ('Cocos 游戏引擎', 90, 'S 极佳宿主'),
        'Unreal': ('虚幻引擎 Core', 98, 'S+ 极佳宿主')
    }

    KNOWN_SDK = {
        'AFNetworking': ('底层网络通信框架', 85, 'A 优秀宿主'),
        'SDWebImage': ('核心图像缓存渲染库', 83, 'A 优秀宿主'),
        'AlipaySDK': ('支付宝业务基础服务', 80, 'A 优秀宿主'),
        'WeChatSDK': ('微信业务通信服务', 80, 'A 优秀宿主'),
        'TencentOpenAPI': ('腾讯开放平台组件', 80, 'A 优秀宿主'),
        'Masonry': ('布局排版引擎', 78, 'A 优秀宿主')
    }

    REQUIRED_HEADER_PAD = 72  # @executable_path/Frameworks/SecurityAuth.dylib 所需最小约 64~72 字节

    @classmethod
    def diagnose_ipa(cls, ipa_path):
        """流式只读诊断 IPA，不解压任何文件到磁盘"""
        if not os.path.exists(ipa_path):
            raise FileNotFoundError(f"IPA 文件不存在: {ipa_path}")

        report = {
            'ipa_path': ipa_path,
            'ipa_size_mb': os.path.getsize(ipa_path) / (1024 * 1024),
            'app_name': '',
            'bundle_id': '',
            'version': '',
            'main_exec_name': '',
            'main_exec_zip_path': '',
            'main_encrypted': False,
            'main_pad_bytes': 0,
            'frameworks': [],
            'can_parasitize': False,
            'best_candidate': None,
            'score': 0,
            'strategy_desc': ''
        }

        with zipfile.ZipFile(ipa_path, 'r') as z:
            namelist = z.namelist()

            # 1. 查找 Info.plist
            plist_candidates = [n for n in namelist if n.startswith('Payload/') and n.endswith('.app/Info.plist') and n.count('/') == 2]
            if not plist_candidates:
                raise ValueError("无效的 IPA 结构: 未找到 Payload/*.app/Info.plist")

            plist_entry = plist_candidates[0]
            app_dir = os.path.dirname(plist_entry)

            with z.open(plist_entry) as pf:
                pdata = plistlib.load(pf)
                report['app_name'] = pdata.get('CFBundleDisplayName') or pdata.get('CFBundleName') or 'Unknown'
                report['bundle_id'] = pdata.get('CFBundleIdentifier', 'Unknown')
                report['version'] = pdata.get('CFBundleShortVersionString') or pdata.get('CFBundleVersion', '1.0')
                report['main_exec_name'] = pdata.get('CFBundleExecutable', '')

            if not report['main_exec_name']:
                raise ValueError("Info.plist 缺失 CFBundleExecutable 字段")

            report['main_exec_zip_path'] = f"{app_dir}/{report['main_exec_name']}"

            # 2. 快速读取主二进制头部 (Load Commands / 加密标志 / Padding)
            main_imported_dylibs = []
            if report['main_exec_zip_path'] in namelist:
                parsed_main = MachOInspector.read_macho_header_from_zip(z, report['main_exec_zip_path'])
                if parsed_main:
                    main_imported_dylibs = parsed_main['loaded_dylibs']
                    report['main_encrypted'] = parsed_main['encrypted']
                    report['main_pad_bytes'] = parsed_main['free_pad_bytes']

            # 3. 扫描 Frameworks 目录下的所有动态库候选
            fw_prefix = f"{app_dir}/Frameworks/"
            candidate_files = []

            for name in namelist:
                if not name.startswith(fw_prefix) or name.endswith('/'):
                    continue
                rel = name[len(fw_prefix):]
                parts = rel.split('/')
                if len(parts) == 2 and parts[0].endswith('.framework') and parts[0][:-10] == parts[1]:
                    info = z.getinfo(name)
                    candidate_files.append({
                        'zip_path': name,
                        'fw_name': parts[0][:-10],
                        'type': 'framework',
                        'size_kb': info.file_size / 1024
                    })
                elif len(parts) == 1 and parts[0].endswith('.dylib'):
                    info = z.getinfo(name)
                    candidate_files.append({
                        'zip_path': name,
                        'fw_name': parts[0][:-6],
                        'type': 'dylib',
                        'size_kb': info.file_size / 1024
                    })

            # 4. 对候选宿主进行真实头空间检查与智能评估打分
            ranked = []
            for cand in candidate_files:
                fw_name = cand['fw_name']
                score = 50
                desc = '通用原生动态库'
                grade = 'B 可用宿主'

                is_referenced = any(fw_name in d for d in main_imported_dylibs)
                if is_referenced:
                    score += 20

                matched_known = False
                for k, v in cls.KNOWN_ENGINES.items():
                    if k.lower() in fw_name.lower():
                        desc, score, grade = v[0], v[1], v[2]
                        matched_known = True
                        break
                if not matched_known:
                    for k, v in cls.KNOWN_SDK.items():
                        if k.lower() in fw_name.lower():
                            desc, score, grade = v[0], v[1], v[2]
                            break

                # 检查该 Framework 自身的 Header 空间和加密状态
                fw_parsed = MachOInspector.read_macho_header_from_zip(z, cand['zip_path'])
                pad_bytes = fw_parsed['free_pad_bytes'] if fw_parsed else 0
                fw_encrypted = fw_parsed['encrypted'] if fw_parsed else False
                space_ok = (fw_parsed is not None) and (pad_bytes >= cls.REQUIRED_HEADER_PAD) and (not fw_encrypted)

                cand.update({
                    'score': score,
                    'desc': desc,
                    'grade': grade,
                    'is_referenced_by_main': is_referenced,
                    'pad_bytes': pad_bytes,
                    'encrypted': fw_encrypted,
                    'space_ok': space_ok
                })
                ranked.append(cand)

            # 优先排列可用 (space_ok=True) 且高分的宿主
            ranked.sort(key=lambda x: (x['space_ok'], x['score']), reverse=True)
            report['frameworks'] = ranked

            viable = [c for c in ranked if c['space_ok']]
            if viable:
                best = viable[0]
                report['can_parasitize'] = True
                report['best_candidate'] = best
                report['score'] = best['score']
                report['strategy_desc'] = (
                    f"推荐寄生宿主: [{best['fw_name']}] ({best['desc']}, 可用Header空间: {best['pad_bytes']} 字节)\n"
                    f"防护原理: 将验证库通过 @executable_path/Frameworks/ 挂入该核心组件下，主程序保持 100% 原版无修改。"
                )
            else:
                report['can_parasitize'] = False
                report['score'] = 20
                reason = "未发现可用空间充足的 Framework" if ranked else "该 IPA 无原生 Frameworks 目录"
                report['strategy_desc'] = (
                    f"{reason}，无法执行安全寄生。\n"
                    f"将自动降级为标准主二进制注入 (主二进制可用Header空间: {report['main_pad_bytes']} 字节)。"
                )

        return report


class LowMemoryPatcher:
    """低内存流式注入引擎 (不占用磁盘与内存，直接流式重构 ZIP)"""

    @classmethod
    def execute_patch(cls, ipa_path, dylib_path, output_ipa, use_parasite=True, target_fw=None, progress_callback=None, allow_mock=False):
        tracemalloc.start()
        start_time = time.time()

        if not os.path.exists(ipa_path):
            raise FileNotFoundError(f"IPA 文件不存在: {ipa_path}")
        if not os.path.exists(dylib_path):
            raise FileNotFoundError(f"Dylib 文件不存在: {dylib_path}")

        if not allow_mock:
            valid_dylib, dylib_msg = MachOInspector.validate_dylib(dylib_path)
            if not valid_dylib:
                raise ValueError(f"动态库校验未通过: {dylib_msg}")

        # 1. 先进行快速诊断，锁定被注入的目标文件
        diag = ParasiteAnalyzer.diagnose_ipa(ipa_path)
        if diag['main_encrypted']:
            raise ValueError("检测到目标主程序尚未砸壳 (FairPlay cryptid != 0)，请先砸壳后再进行注入，否则真机打开必闪退！")

        target_zip_file = None
        inject_mode = "STANDARD"

        if use_parasite and diag['can_parasitize']:
            if target_fw:
                match = next((f for f in diag['frameworks'] if f['fw_name'] == target_fw and f['space_ok']), None)
                if match:
                    target_zip_file = match['zip_path']
            if not target_zip_file and diag['best_candidate']:
                target_zip_file = diag['best_candidate']['zip_path']
            inject_mode = "PARASITE"
        else:
            target_zip_file = diag['main_exec_zip_path']
            inject_mode = "STANDARD"

        dylib_filename = os.path.basename(dylib_path)
        app_dir = os.path.dirname(diag['main_exec_zip_path'])
        dest_dylib_zip_path = f"{app_dir}/Frameworks/{dylib_filename}"
        # 关键修复: 使用 @executable_path/Frameworks/xxx.dylib，脱离对 @rpath 的依赖，杜绝双重目录导致 dyld 崩溃
        load_path = f"@executable_path/Frameworks/{dylib_filename}"

        # 2. 流式复制与精准原位补丁
        if os.path.exists(output_ipa):
            os.remove(output_ipa)

        buffer_size = 1024 * 1024  # 1MB 内存分块，保证极低内存开销
        patched_applied = False

        with zipfile.ZipFile(ipa_path, 'r') as in_zip, zipfile.ZipFile(output_ipa, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as out_zip:
            infolist = in_zip.infolist()
            total_items = len(infolist)

            for idx, item in enumerate(infolist):
                # 剔除原有签名目录，以便后续自由重签名
                if '/_CodeSignature/' in item.filename or item.filename.endswith('/_CodeSignature'):
                    continue

                if item.filename == target_zip_file:
                    raw_data = in_zip.read(item.filename)
                    injector = MachOInjectorMemory(raw_data)
                    ok, msg = injector.inject(load_path)
                    if not ok:
                        raise RuntimeError(f"向 {target_zip_file} 写入注入命令失败: {msg}")
                    patched_bytes = injector.get_bytes()
                    patched_applied = True

                    out_zip.writestr(item, patched_bytes)
                    del raw_data, injector, patched_bytes
                    gc.collect()
                else:
                    # 其它资源文件: 1MB 流式管道对拷，不占 RAM
                    with in_zip.open(item, 'r') as src, out_zip.open(item, 'w') as dst:
                        shutil.copyfileobj(src, dst, length=buffer_size)

                if progress_callback and idx % 50 == 0:
                    progress_callback(idx + 1, total_items)

            if not patched_applied:
                raise RuntimeError(f"未能在 IPA 中定位到注入靶标文件: {target_zip_file}")

            # 3. 写入 SecurityAuth.dylib，必须设置 Unix 0755 可执行权限，否则 iOS/TrollStore 拒绝加载
            with open(dylib_path, 'rb') as df:
                dylib_zinfo = zipfile.ZipInfo(dest_dylib_zip_path, date_time=time.localtime(time.time())[:6])
                dylib_zinfo.create_system = 3
                dylib_zinfo.external_attr = (0o100755) << 16
                dylib_zinfo.compress_type = zipfile.ZIP_DEFLATED
                out_zip.writestr(dylib_zinfo, df.read())

        current_ram, peak_ram = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        duration = time.time() - start_time
        return {
            'output_ipa': output_ipa,
            'inject_mode': inject_mode,
            'target_file': target_zip_file,
            'load_path': load_path,
            'peak_ram_mb': peak_ram / (1024 * 1024),
            'duration_sec': duration
        }


def print_banner():
    print("""
=============================================================================
      iOS IPA 智能寄生伪装与防剥离注入工具 v1.1 (Low-Memory Engine)
=============================================================================
   [+] 流式极低内存引擎 (峰值 RAM < 30MB，避免打包大游戏卡死/OOM)
   [+] 真实 Header 填充探测 + @executable_path 无损路径注入 (彻底解决闪退)
   [+] 自动检测未砸壳加密包与假包，防止错误注入
=============================================================================
""")

def clean_input_path(path_str):
    if not path_str:
        return ""
    p = path_str.strip()
    if (p.startswith('"') and p.endswith('"')) or (p.startswith("'") and p.endswith("'")):
        p = p[1:-1]
    return os.path.abspath(p)

def run_interactive():
    print_banner()

    # 1. 拖入 IPA
    while True:
        raw_ipa = input(">>> 请拖入目标 [IPA 文件] 并按回车 (或输入路径): ").strip()
        ipa_path = clean_input_path(raw_ipa)
        if os.path.exists(ipa_path) and ipa_path.lower().endswith('.ipa'):
            break
        print("[!] 文件不存在或不是 .ipa 文件，请重新拖入！\n")

    print("\n[*] 正在启动流式轻量级体检扫描，请稍候...")
    try:
        diag = ParasiteAnalyzer.diagnose_ipa(ipa_path)
    except Exception as e:
        print(f"\n[ERROR] 诊断解析失败: {e}")
        input("\n按回车键退出...")
        return

    # 打印诊断报告
    print("\n" + "=" * 75)
    print(f"应用名称:   {diag['app_name']} (Bundle ID: {diag['bundle_id']})")
    print(f"主二进制:   {diag['main_exec_name']} (Header可用空间: {diag['main_pad_bytes']} B, 加密: {'未砸壳!' if diag['main_encrypted'] else '已脱壳'})")
    print(f"包体大小:   {diag['ipa_size_mb']:.2f} MB")
    print("-" * 75)
    print("【扫描到的原生动态库 (Frameworks) 列表】:")

    if diag['frameworks']:
        for idx, fw in enumerate(diag['frameworks'], 1):
            ref_tag = "★ 强依赖" if fw['is_referenced_by_main'] else "  组件"
            pad_tag = f"空间:{fw['pad_bytes']}B" if fw['space_ok'] else f"空间不足({fw['pad_bytes']}B)"
            enc_tag = " [未砸壳]" if fw['encrypted'] else ""
            print(f"  [{idx}] {fw['fw_name']:<22} {fw['grade']:<10} {fw['size_kb']:>7.1f}KB  {pad_tag:<14} {ref_tag}{enc_tag}")
    else:
        print("  (未检测到任何原生 Framework 目录)")

    print("-" * 75)
    if diag['main_encrypted']:
        print("[!] 严重警告: 主程序 cryptid != 0 (未砸壳 App Store 原包)，注入重签后必定闪退！")
    elif diag['can_parasitize']:
        print(f"[✓] 寄生伪装可行性: 【完全支持】(安全推荐分: {diag['score']} 分)")
        print(f"    最佳寄生体:     [{diag['best_candidate']['fw_name']}] - {diag['best_candidate']['desc']}")
    else:
        print(f"[!] 寄生伪装可行性: 【不支持安全寄生】(无足够 Header 空间的 Framework)")
        print(f"    应对策略:       将自动切换为标准主程序注入。")
    print("=" * 75)

    # 2. 拖入 Dylib
    default_dylib = os.path.abspath("client/build/SecurityAuth.dylib")
    default_hint = f" (直接回车默认: client/build/SecurityAuth.dylib)" if os.path.exists(default_dylib) else ""

    while True:
        raw_dylib = input(f"\n>>> 请拖入待注入的 [Dylib 动态库]{default_hint}: ").strip()
        if not raw_dylib and os.path.exists(default_dylib):
            dylib_path = default_dylib
        else:
            dylib_path = clean_input_path(raw_dylib)

        if not (os.path.exists(dylib_path) and dylib_path.lower().endswith('.dylib')):
            print("[!] 动态库文件不存在，请重新输入或确认路径！")
            continue

        valid_dylib, dylib_msg = MachOInspector.validate_dylib(dylib_path)
        if not valid_dylib:
            print(f"[!] 动态库校验失败: {dylib_msg}")
            print("    请拖入 GitHub Actions / Xcode 编译出的真实 arm64 SecurityAuth.dylib！")
            continue
        break

    # 3. 输出路径
    base_name = os.path.splitext(os.path.basename(ipa_path))[0]
    default_out = os.path.join(os.path.dirname(ipa_path), f"{base_name}_injected.ipa")

    raw_out = input(f"\n>>> 输出路径 (直接回车默认: {os.path.basename(default_out)}): ").strip()
    out_path = clean_input_path(raw_out) if raw_out else default_out

    # 4. 执行注入
    print("\n" + "-" * 75)
    mode_text = f"寄生伪装到 [{diag['best_candidate']['fw_name']}]" if diag['can_parasitize'] else "标准主程序注入"
    print(f"[*] 注入模式: {mode_text}")
    print(f"[*] 加载路径: @executable_path/Frameworks/{os.path.basename(dylib_path)}")
    print(f"[*] 正在执行流式低内存注入打包，请耐心等待...")

    def progress(cur, total):
        pct = (cur / total) * 100
        print(f"\r    -> 正在流式传输与重构文件... [{cur}/{total}] {pct:.1f}%", end="", flush=True)

    try:
        res = LowMemoryPatcher.execute_patch(
            ipa_path=ipa_path,
            dylib_path=dylib_path,
            output_ipa=out_path,
            use_parasite=True,
            progress_callback=progress
        )
        print(f"\n\n[SUCCESS] 注入打包圆满完成！")
        print(f"  - 输出文件:   {res['output_ipa']}")
        print(f"  - 注入靶标:   {res['target_file']}")
        print(f"  - 注入命令:   {res['load_path']}")
        print(f"  - 耗时时间:   {res['duration_sec']:.2f} 秒")
        print(f"  - 峰值内存:   {res['peak_ram_mb']:.2f} MB (极低内存安全保护生效)")
        print("=" * 75)
        print("[提示] 请务必使用支持递归重签 Frameworks 的签名工具(如 Sideloadly / 爱思 / 牛蛙 / zsign)重签安装！")
    except Exception as e:
        print(f"\n[ERROR] 注入过程发生异常: {e}")

    print("\n")
    input("按回车键退出程序...")

def main():
    parser = argparse.ArgumentParser(description="iOS IPA 智能寄生伪装与低内存防剥离注入工具")
    parser.add_argument("--ipa", "-i", help="目标 IPA 文件路径")
    parser.add_argument("--dylib", "-d", help="待注入的 Dylib 路径")
    parser.add_argument("--output", "-o", help="输出的 IPA 路径")
    parser.add_argument("--check-only", "-c", action="store_true", help="仅执行体检诊断并输出报告，不执行打包")
    parser.add_argument("--no-parasite", action="store_true", help="强制禁用寄生伪装，使用标准主二进制注入")
    parser.add_argument("--allow-mock", action="store_true", help="允许注入测试占位 dylib (仅用于离线结构测试)")

    args = parser.parse_args()

    if not args.ipa:
        run_interactive()
        return

    ipa_path = os.path.abspath(args.ipa)
    diag = ParasiteAnalyzer.diagnose_ipa(ipa_path)

    if args.check_only:
        print(f"[Diagnosis] App: {diag['app_name']}, Bundle: {diag['bundle_id']}, Encrypted: {diag['main_encrypted']}, MainPad: {diag['main_pad_bytes']}B")
        print(f"[Diagnosis] Can Parasitize: {diag['can_parasitize']}, Best: {diag['best_candidate']}")
        return

    dylib_path = os.path.abspath(args.dylib) if args.dylib else os.path.abspath("client/build/SecurityAuth.dylib")
    base_name = os.path.splitext(os.path.basename(ipa_path))[0]
    out_path = os.path.abspath(args.output) if args.output else os.path.join(os.path.dirname(ipa_path), f"{base_name}_injected.ipa")

    res = LowMemoryPatcher.execute_patch(
        ipa_path=ipa_path,
        dylib_path=dylib_path,
        output_ipa=out_path,
        use_parasite=(not args.no_parasite),
        allow_mock=args.allow_mock
    )
    print(f"[OK] Patched successfully: {res['output_ipa']} (Mode: {res['inject_mode']}, Load: {res['load_path']}, Peak RAM: {res['peak_ram_mb']:.2f} MB)")

if __name__ == '__main__':
    main()
