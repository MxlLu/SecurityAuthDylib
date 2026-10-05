#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
iOS IPA 跨平台重签名辅助工具
封装并调度 zsign / codesign 工具，实现对注入后 IPA 的一键签名。
"""

import os
import sys
import shutil
import subprocess
import argparse

def find_zsign():
    # 优先检查当前目录或 tools 目录下的 zsign 可执行文件
    local_zsign = os.path.join(os.path.dirname(__file__), 'zsign.exe' if sys.platform == 'win32' else 'zsign')
    if os.path.exists(local_zsign):
        return local_zsign

    # 检查环境变量 PATH
    cmd = shutil.which('zsign')
    if cmd:
        return cmd
    return None

def resign_ipa(ipa_path, p12_path, mobileprovision_path, password="", output_ipa=None, bundle_id=None, app_name=None):
    if not os.path.exists(ipa_path):
        raise FileNotFoundError(f"IPA 文件不存在: {ipa_path}")
    if not os.path.exists(p12_path):
        raise FileNotFoundError(f"P12 证书文件不存在: {p12_path}")
    if not os.path.exists(mobileprovision_path):
        raise FileNotFoundError(f"描述文件不存在: {mobileprovision_path}")

    base = os.path.splitext(os.path.basename(ipa_path))[0]
    if not output_ipa:
        output_ipa = os.path.join(os.path.dirname(ipa_path) or '.', f"{base}_resigned.ipa")

    zsign_bin = find_zsign()
    if not zsign_bin:
        print("[!] 未在系统环境中找到 zsign 工具。")
        print("    - Windows 用户建议下载编译好的 zsign.exe 并放入 tools/ 目录。")
        print("    - 项目主页: https://github.com/zhlynn/zsign")
        print("    - 或者在 macOS 设备上使用: codesign -f -s 'iPhone Developer: ...' ...")
        return False

    cmd = [
        zsign_bin,
        "-k", p12_path,
        "-m", mobileprovision_path,
        "-o", output_ipa,
        "-z", "9"
    ]
    if password:
        cmd.extend(["-p", password])
    if bundle_id:
        cmd.extend(["-b", bundle_id])
    if app_name:
        cmd.extend(["-n", app_name])

    cmd.append(ipa_path)

    print(f"[+] 正在调用 zsign 执行重签名: {' '.join(cmd)}")
    ret = subprocess.run(cmd)
    if ret.returncode == 0:
        print(f"[OK] 重签名成功！输出路径: {output_ipa}")
        return True
    else:
        print(f"[!] zsign 退出码异常: {ret.returncode}")
        return False

def main():
    parser = argparse.ArgumentParser(description="IPA 跨平台重签名工具")
    parser.add_argument("ipa", help="待重签名的 IPA 文件")
    parser.add_argument("-k", "--p12", required=True, help="Apple 开发者 P12 证书路径")
    parser.add_argument("-m", "--provision", required=True, help="mobileprovision 描述文件路径")
    parser.add_argument("-p", "--password", default="", help="P12 证书密码")
    parser.add_argument("-o", "--output", help="输出的 IPA 路径")
    parser.add_argument("-b", "--bundleid", help="自定义修改 Bundle Identifier")
    parser.add_argument("-n", "--name", help="自定义修改 App 显示名称")

    args = parser.parse_args()
    try:
        success = resign_ipa(
            args.ipa,
            args.p12,
            args.provision,
            args.password,
            args.output,
            args.bundleid,
            args.name
        )
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"[ERROR] 重签名失败: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
