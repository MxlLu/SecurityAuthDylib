#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
自动化 IPA 补丁与动态库注入打包工具
无需 macOS 环境，可在 Windows / Linux / macOS 上一键向 IPA 注入 SecurityAuth.dylib。
"""

import os
import sys
import shutil
import zipfile
import plistlib
import argparse
from macho_inject import MachOInjector

def extract_ipa(ipa_path, temp_dir):
    print(f"[+] 正在解压 IPA: {ipa_path} -> {temp_dir}")
    with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
        zip_ref.extractall(temp_dir)

def find_app_dir(temp_dir):
    payload_dir = os.path.join(temp_dir, 'Payload')
    if not os.path.exists(payload_dir):
        raise FileNotFoundError(f"未找到 Payload 目录: {payload_dir}")

    for item in os.listdir(payload_dir):
        if item.endswith('.app'):
            return os.path.join(payload_dir, item)

    raise FileNotFoundError("Payload 目录下未找到 .app 目录")

def get_main_executable(app_dir):
    plist_path = os.path.join(app_dir, 'Info.plist')
    if not os.path.exists(plist_path):
        raise FileNotFoundError(f"未找到 Info.plist: {plist_path}")

    with open(plist_path, 'rb') as f:
        plist_data = plistlib.load(f)

    exec_name = plist_data.get('CFBundleExecutable')
    if not exec_name:
        raise ValueError("Info.plist 中未找到 CFBundleExecutable 字段")

    exec_path = os.path.join(app_dir, exec_name)
    if not os.path.exists(exec_path):
        raise FileNotFoundError(f"主二进制文件不存在: {exec_path}")

    return exec_path, exec_name

def repack_ipa(temp_dir, output_ipa_path):
    print(f"[+] 正在重新打包 IPA: {output_ipa_path}")
    if os.path.exists(output_ipa_path):
        os.remove(output_ipa_path)

    with zipfile.ZipFile(output_ipa_path, 'w', zipfile.ZIP_DEFLATED) as zip_out:
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, temp_dir)
                zip_out.write(full_path, rel_path)

def patch_ipa(ipa_path, dylib_path, output_ipa=None, weak=False):
    if not os.path.exists(ipa_path):
        raise FileNotFoundError(f"IPA 文件不存在: {ipa_path}")
    if not os.path.exists(dylib_path):
        raise FileNotFoundError(f"动态库文件不存在: {dylib_path}")

    base_name = os.path.splitext(os.path.basename(ipa_path))[0]
    if not output_ipa:
        output_ipa = os.path.join(os.path.dirname(ipa_path) or '.', f"{base_name}_injected.ipa")

    temp_work_dir = os.path.join(os.path.dirname(ipa_path) or '.', f"temp_{base_name}_patch")
    if os.path.exists(temp_work_dir):
        shutil.rmtree(temp_work_dir)
    os.makedirs(temp_work_dir, exist_ok=True)

    try:
        # 1. 解压
        extract_ipa(ipa_path, temp_work_dir)

        # 2. 定位 App 目录与主二进制
        app_dir = find_app_dir(temp_work_dir)
        exec_path, exec_name = get_main_executable(app_dir)
        print(f"[+] 目标应用: {os.path.basename(app_dir)}, 主二进制: {exec_name}")

        # 3. 创建 Frameworks 目录并复制 dylib
        frameworks_dir = os.path.join(app_dir, 'Frameworks')
        os.makedirs(frameworks_dir, exist_ok=True)
        dylib_name = os.path.basename(dylib_path)
        dest_dylib = os.path.join(frameworks_dir, dylib_name)
        shutil.copy2(dylib_path, dest_dylib)
        print(f"[+] 动态库已复制到: {dest_dylib}")

        # 4. 执行 Mach-O 注入
        load_path = f"@rpath/Frameworks/{dylib_name}"
        print(f"[+] 正在向主二进制注入加载命令: {load_path}")
        injector = MachOInjector(exec_path)
        success = injector.inject(load_path, weak=weak)
        if not success:
            print("[!] 警告: 注入未执行或已存在")

        # 5. 清理原代码签名以准备重签名
        code_sig_dir = os.path.join(app_dir, '_CodeSignature')
        if os.path.exists(code_sig_dir):
            shutil.rmtree(code_sig_dir)
            print("[+] 已清理原有 _CodeSignature 签名目录")

        # 6. 重新打包
        repack_ipa(temp_work_dir, output_ipa)
        print(f"\n[OK] 注入打包完成！输出文件: {output_ipa}")
        return output_ipa
    finally:
        if os.path.exists(temp_work_dir):
            shutil.rmtree(temp_work_dir)

def main():
    parser = argparse.ArgumentParser(description="自动化 IPA 动态库注入与打包工具")
    parser.add_argument("ipa", help="待注入的目标 IPA 文件路径")
    parser.add_argument("--dylib", default="../client/build/SecurityAuth.dylib", help="动态库路径 (默认 ../client/build/SecurityAuth.dylib)")
    parser.add_argument("--output", "-o", help="输出的注入后 IPA 路径")
    parser.add_argument("--weak", action="store_true", help="使用 LC_LOAD_WEAK_DYLIB")

    args = parser.parse_args()
    try:
        patch_ipa(args.ipa, args.dylib, args.output, args.weak)
    except Exception as e:
        print(f"\n[ERROR] 注入失败: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
