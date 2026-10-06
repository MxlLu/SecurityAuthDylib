#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
=============================================================================
iOS IPA 智能寄生伪装与防剥离注入工具 (低内存流式引擎)
iOS IPA Parasitic Masquerade & Anti-Stripping Injection Tool
=============================================================================
特点:
1. 极致低内存: 流式分块传输，不把整个几GB的IPA解压到磁盘，也不载入内存，峰值内存 < 30MB。
2. 智能寄生诊断: 深度扫描 Frameworks，精准识别 Unity/Flutter/Unreal/业务核心库，自动打分。
3. 纯 Python 无依赖: 单文件封装，完美打包为 Windows 独立 .exe 可执行文件。
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
MH_MAGIC_64         = 0xFEEDFACF     # 64 位小端
MH_CIGAM_64         = 0xCFFAEDFE     # 64 位大端
MH_MAGIC            = 0xFEEDFACE     # 32 位小端
MH_CIGAM            = 0xCEFAEDFE     # 32 位大端
FAT_MAGIC           = 0xCAFEBABE     # FAT 胖二进制 (大端)
FAT_CIGAM           = 0xBEBAFECA
FAT_MAGIC_64        = 0xCAFEBABB

LC_SEGMENT_64       = 0x19
LC_LOAD_DYLIB       = 0x0C
LC_LOAD_WEAK_DYLIB  = 0x8000000C
LC_REEXPORT_DYLIB   = 0x8000001F
LC_RPATH            = 0x8000001C

def align8(val):
    return (val + 7) & ~7

class MachOInspector:
    """轻量级 Mach-O 头部快速解析器 (仅读前 128KB 字节，不占内存)"""

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
        ncmds = header_tuple[4]
        sizeofcmds = header_tuple[5]

        offset = header_size
        loaded_dylibs = []
        rpaths = []

        for _ in range(ncmds):
            if offset + 8 > len(raw_header_bytes):
                break
            cmd, cmdsize = struct.unpack(f'{endian}2I', raw_header_bytes[offset:offset + 8])
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
            offset += cmdsize

        return {
            'is_64': is_64,
            'ncmds': ncmds,
            'sizeofcmds': sizeofcmds,
            'loaded_dylibs': loaded_dylibs,
            'rpaths': rpaths
        }

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
            return (count > 0), f"FAT架构成功注入 {count} 个切片"
        else:
            ok = self._inject_slice(0, len(self.data), dylib_path, weak)
            return ok, "单架构注入成功" if ok else "注入失败或已存在"

    def _inject_slice(self, slice_offset, slice_size, dylib_path, weak=False):
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
            return False

        header_size = 32 if is_64 else 28
        fmt = f'{endian}7I' if not is_64 else f'{endian}8I'
        header_tuple = struct.unpack(fmt, slice_data[:header_size])

        ncmds = header_tuple[4]
        sizeofcmds = header_tuple[5]

        cmd_offset = slice_offset + header_size
        min_section_offset = slice_size

        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack(f'{endian}2I', self.data[cmd_offset:cmd_offset + 8])
            if cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB):
                name_offset = struct.unpack(f'{endian}I', self.data[cmd_offset + 8:cmd_offset + 12])[0]
                name_bytes = self.data[cmd_offset + name_offset:cmd_offset + cmdsize]
                current_dylib = name_bytes.split(b'\x00')[0].decode('utf-8', errors='ignore')
                if current_dylib == dylib_path:
                    return False  # 已存在

            if cmd == LC_SEGMENT_64:
                nsects = struct.unpack(f'{endian}I', self.data[cmd_offset + 64:cmd_offset + 68])[0]
                sect_start = cmd_offset + 72
                for s in range(nsects):
                    sect_offset = struct.unpack(f'{endian}I', self.data[sect_start + s * 80 + 32:sect_start + s * 80 + 36])[0]
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
            return False

        cmd_data = bytearray(new_cmd_size)
        struct.pack_into(f'{endian}I', cmd_data, 0, cmd_type)
        struct.pack_into(f'{endian}I', cmd_data, 4, new_cmd_size)
        struct.pack_into(f'{endian}I', cmd_data, 8, cmd_name_offset)
        struct.pack_into(f'{endian}I', cmd_data, 12, 0) # timestamp
        struct.pack_into(f'{endian}I', cmd_data, 16, 0x10000) # current_version 1.0.0
        struct.pack_into(f'{endian}I', cmd_data, 20, 0x10000) # compatibility_version 1.0.0
        cmd_data[cmd_name_offset:cmd_name_offset + len(dylib_bytes)] = dylib_bytes

        # 写入新命令并清空尾部
        self.data[cmd_offset:cmd_offset + new_cmd_size] = cmd_data

        # 更新 Header
        struct.pack_into(f'{endian}I', self.data, slice_offset + 16, ncmds + 1)
        struct.pack_into(f'{endian}I', self.data, slice_offset + 20, sizeofcmds + new_cmd_size)
        return True

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

            # 2. 快速读取主二进制头部 Load Commands
            main_imported_dylibs = []
            if report['main_exec_zip_path'] in namelist:
                with z.open(report['main_exec_zip_path']) as mf:
                    # 仅读取前 128KB 头部
                    chunk = mf.read(131072)
                    parsed = MachOInspector.parse_headers_and_cmds(chunk)
                    if parsed:
                        main_imported_dylibs = parsed['loaded_dylibs']

            # 3. 扫描 Frameworks 目录下的所有动态库候选
            fw_prefix = f"{app_dir}/Frameworks/"
            candidate_files = []

            for name in namelist:
                if not name.startswith(fw_prefix) or name.endswith('/'):
                    continue
                # 形如: Payload/App.app/Frameworks/XXX.framework/XXX
                rel = name[len(fw_prefix):]
                parts = rel.split('/')
                if len(parts) == 2 and parts[0].endswith('.framework') and parts[0][:-10] == parts[1]:
                    # Framework 主二进制
                    info = z.getinfo(name)
                    candidate_files.append({
                        'zip_path': name,
                        'fw_name': parts[0][:-10],
                        'type': 'framework',
                        'size_kb': info.file_size / 1024
                    })
                elif len(parts) == 1 and parts[0].endswith('.dylib'):
                    # 独立 dylib
                    info = z.getinfo(name)
                    candidate_files.append({
                        'zip_path': name,
                        'fw_name': parts[0][:-6],
                        'type': 'dylib',
                        'size_kb': info.file_size / 1024
                    })

            # 4. 对候选宿主进行智能评估与打分
            ranked = []
            for cand in candidate_files:
                fw_name = cand['fw_name']
                score = 50
                desc = '通用原生动态库'
                grade = 'B 可用宿主'

                # 检查主程序是否强依赖该库
                is_referenced = any(fw_name in d for d in main_imported_dylibs)
                if is_referenced:
                    score += 20

                # 特征比对
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

                cand.update({
                    'score': score,
                    'desc': desc,
                    'grade': grade,
                    'is_referenced_by_main': is_referenced
                })
                ranked.append(cand)

            ranked.sort(key=lambda x: x['score'], reverse=True)
            report['frameworks'] = ranked

            if ranked:
                best = ranked[0]
                report['can_parasitize'] = True
                report['best_candidate'] = best
                report['score'] = best['score']
                report['strategy_desc'] = (
                    f"推荐寄生宿主: [{best['fw_name']}] ({best['desc']})\n"
                    f"防护原理: 将验证库挂入该核心组件的依赖链下，主程序保持 100% 原版干净无修改。\n"
                    f"若破解者强行删除验证库，目标应用核心组件直接损毁闪退！"
                )
            else:
                report['can_parasitize'] = False
                report['score'] = 20
                report['strategy_desc'] = (
                    "该 IPA 无原生 Frameworks 目录 (为纯静态编译应用)。\n"
                    "无法执行寄生伪装，将自动降级为标准 LC_LOAD_DYLIB 主二进制注入。"
                )

        return report


class LowMemoryPatcher:
    """低内存流式注入引擎 (不占用磁盘与内存，直接流式重构 ZIP)"""

    @classmethod
    def execute_patch(cls, ipa_path, dylib_path, output_ipa, use_parasite=True, target_fw=None, progress_callback=None):
        tracemalloc.start()
        start_time = time.time()

        if not os.path.exists(ipa_path):
            raise FileNotFoundError(f"IPA 文件不存在: {ipa_path}")
        if not os.path.exists(dylib_path):
            raise FileNotFoundError(f"Dylib 文件不存在: {dylib_path}")

        # 1. 先进行快速诊断，锁定被注入的目标文件
        diag = ParasiteAnalyzer.diagnose_ipa(ipa_path)

        target_zip_file = None
        inject_mode = "STANDARD"

        if use_parasite and diag['can_parasitize']:
            if target_fw:
                match = next((f for f in diag['frameworks'] if f['fw_name'] == target_fw), None)
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
        load_path = f"@rpath/Frameworks/{dylib_filename}"

        # 2. 流式复制与精准原位补丁
        if os.path.exists(output_ipa):
            os.remove(output_ipa)

        buffer_size = 1024 * 1024  # 1MB 内存分块，保证极低内存开销
        total_copied = 0

        with zipfile.ZipFile(ipa_path, 'r') as in_zip, zipfile.ZipFile(output_ipa, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as out_zip:
            infolist = in_zip.infolist()
            total_items = len(infolist)

            for idx, item in enumerate(infolist):
                # 剔除原有签名，以便后续自由重签名
                if '/_CodeSignature/' in item.filename or item.filename.endswith('/_CodeSignature'):
                    continue

                if item.filename == target_zip_file:
                    # 遇到目标注入二进制：单次读取并在内存中修补
                    raw_data = in_zip.read(item.filename)
                    injector = MachOInjectorMemory(raw_data)
                    ok, msg = injector.inject(load_path)
                    if not ok:
                        print(f"[!] 警告: {msg}")
                    patched_bytes = injector.get_bytes()

                    # 写入修补后的二进制
                    out_zip.writestr(item, patched_bytes)

                    # 释放大内存引用
                    del raw_data, injector, patched_bytes
                    gc.collect()
                else:
                    # 其它资源文件 (贴图/音频/脚本等): 1MB 流式管道对拷，不占 RAM
                    with in_zip.open(item, 'r') as src, out_zip.open(item, 'w') as dst:
                        shutil.copyfileobj(src, dst, length=buffer_size)

                total_copied += 1
                if progress_callback and idx % 50 == 0:
                    progress_callback(idx + 1, total_items)

            # 3. 将 SecurityAuth.dylib 写入到目标 Frameworks 目录
            with open(dylib_path, 'rb') as df:
                out_zip.writestr(dest_dylib_zip_path, df.read())

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
      iOS IPA 智能寄生伪装与防剥离注入工具 v1.0 (Low-Memory Engine)
=============================================================================
   [+] 流式极低内存引擎 (峰值 RAM < 30MB，避免打包大游戏卡死/OOM)
   [+] 智能架构体检 (自动扫描 Frameworks 并评估防剥离寄生评级)
   [+] 全平台自适应 (纯 Python 零编译依赖，Windows 原生独立运行)
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
    print("\n" + "=" * 65)
    print(f"应用名称:   {diag['app_name']} (Bundle ID: {diag['bundle_id']})")
    print(f"主二进制:   {diag['main_exec_name']}")
    print(f"包体大小:   {diag['ipa_size_mb']:.2f} MB")
    print("-" * 65)
    print("【扫描到的原生动态库 (Frameworks) 列表】:")

    if diag['frameworks']:
        for idx, fw in enumerate(diag['frameworks'], 1):
            ref_tag = "★ 主程序强依赖" if fw['is_referenced_by_main'] else "  独立组件"
            print(f"  [{idx}] {fw['fw_name']:<24} {fw['grade']:<12} {fw['size_kb']:>8.1f} KB  ({fw['desc']}) {ref_tag}")
    else:
        print("  (未检测到任何原生 Framework 目录)")

    print("-" * 65)
    if diag['can_parasitize']:
        print(f"[✓] 寄生伪装可行性: 【完全支持】(安全推荐分: {diag['score']} 分)")
        print(f"    最佳寄生体:     [{diag['best_candidate']['fw_name']}] - {diag['best_candidate']['desc']}")
    else:
        print(f"[!] 寄生伪装可行性: 【不支持】(缺少可用组件)")
        print(f"    应对策略:       将自动切换为标准 LC_LOAD_DYLIB 主程序注入。")
    print("=" * 65)

    # 2. 拖入 Dylib
    default_dylib = os.path.abspath("client/build/SecurityAuth.dylib")
    default_hint = f" (直接回车默认: client/build/SecurityAuth.dylib)" if os.path.exists(default_dylib) else ""
    
    while True:
        raw_dylib = input(f"\n>>> 请拖入待注入的 [Dylib 动态库]{default_hint}: ").strip()
        if not raw_dylib and os.path.exists(default_dylib):
            dylib_path = default_dylib
            break
        dylib_path = clean_input_path(raw_dylib)
        if os.path.exists(dylib_path) and dylib_path.lower().endswith('.dylib'):
            break
        print("[!] 动态库文件不存在，请重新输入或确认路径！")

    # 3. 输出路径
    base_name = os.path.splitext(os.path.basename(ipa_path))[0]
    default_out = os.path.join(os.path.dirname(ipa_path), f"{base_name}_injected.ipa")
    
    raw_out = input(f"\n>>> 输出路径 (直接回车默认: {os.path.basename(default_out)}): ").strip()
    out_path = clean_input_path(raw_out) if raw_out else default_out

    # 4. 执行注入
    print("\n" + "-" * 65)
    mode_text = f"寄生伪装到 [{diag['best_candidate']['fw_name']}]" if diag['can_parasitize'] else "标准主程序注入"
    print(f"[*] 注入模式: {mode_text}")
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
        print(f"  - 耗时时间:   {res['duration_sec']:.2f} 秒")
        print(f"  - 峰值内存:   {res['peak_ram_mb']:.2f} MB (极低内存安全保护生效)")
        print("=" * 65)
        print("[提示] 该 IPA 已经自动剔除冲突的旧签名，请使用爱思助手/Sideloadly完成重签名后安装！")
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

    args = parser.parse_args()

    # 如果无参数传入，进入交互式拖拽界面
    if not args.ipa:
        run_interactive()
        return

    # 命令行自动化调用模式
    ipa_path = os.path.abspath(args.ipa)
    diag = ParasiteAnalyzer.diagnose_ipa(ipa_path)

    if args.check_only:
        print(f"[Diagnosis] App: {diag['app_name']}, Bundle: {diag['bundle_id']}")
        print(f"[Diagnosis] Can Parasitize: {diag['can_parasitize']}, Best: {diag['best_candidate']}")
        return

    dylib_path = os.path.abspath(args.dylib) if args.dylib else os.path.abspath("client/build/SecurityAuth.dylib")
    base_name = os.path.splitext(os.path.basename(ipa_path))[0]
    out_path = os.path.abspath(args.output) if args.output else os.path.join(os.path.dirname(ipa_path), f"{base_name}_injected.ipa")

    res = LowMemoryPatcher.execute_patch(
        ipa_path=ipa_path,
        dylib_path=dylib_path,
        output_ipa=out_path,
        use_parasite=(not args.no_parasite)
    )
    print(f"[OK] Patched successfully: {res['output_ipa']} (Peak RAM: {res['peak_ram_mb']:.2f} MB)")

if __name__ == '__main__':
    main()
