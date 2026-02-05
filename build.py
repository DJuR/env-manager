#!/usr/bin/env python3
"""
环境变量管理器打包脚本
使用 PyInstaller 将 Python 脚本打包为可执行文件
"""

import os
import sys
import shutil
import subprocess
import platform
from pathlib import Path

# 配置信息
APP_NAME = "env-manager"
SCRIPT_FILE = "env-manager.py"
CONFIG_FILES = ["config.json", "README.md"]
DIST_DIR = "dist"
BUILD_DIR = "build"
SPEC_FILE = f"{APP_NAME}.spec"

def get_icon_path():
    """获取图标文件路径（如果存在）"""
    icon_files = ["icon.ico", "icon.png", "icon.icns"]
    for icon in icon_files:
        if os.path.exists(icon):
            return icon
    return None

def clean_build_dirs():
    """清理之前的构建目录"""
    print("清理构建目录...")
    dirs_to_clean = [DIST_DIR, BUILD_DIR]
    for d in dirs_to_clean:
        if os.path.exists(d):
            shutil.rmtree(d)
            print(f"  已删除: {d}")

def generate_spec_file():
    """生成 PyInstaller spec 文件"""
    print(f"生成 spec 文件: {SPEC_FILE}")

    system = platform.system().lower()
    icon = get_icon_path()

    # 根据平台选择不同的配置
    if system == "windows":
        console = "True"  # Windows 控制台应用
        exe_ext = ".exe"
    elif system == "darwin":
        console = "False"  # macOS 打包为 .app
        exe_ext = ""  # .app bundle
    else:  # Linux
        console = "True"
        exe_ext = ""

    spec_content = f'''# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['{SCRIPT_FILE}'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='{APP_NAME}',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console={console},
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='{icon}' if '{icon}' else None,
)
'''

    with open(SPEC_FILE, 'w', encoding='utf-8') as f:
        f.write(spec_content)

def build_app():
    """执行打包"""
    print("\n开始打包...")

    # 检查 PyInstaller 是否已安装
    try:
        import PyInstaller
        print(f"  PyInstaller 版本: {PyInstaller.__version__}")
    except ImportError:
        print("❌ PyInstaller 未安装")
        print("请运行: pip install pyinstaller")
        return False

    # 生成 spec 文件
    generate_spec_file()

    # 执行打包命令
    cmd = ["pyinstaller", "--clean", SPEC_FILE]
    print(f"  执行命令: {' '.join(cmd)}")

    result = subprocess.run(cmd, capture_output=False)
    if result.returncode != 0:
        print("\n❌ 打包失败")
        return False

    print("\n✅ 打包成功")
    return True

def prepare_distribution():
    """准备分发包（包含配置文件和文档）"""
    print("\n准备分发包...")

    # 目标目录结构：
    # dist/
    #   ├── env-manager (可执行文件)
    #   ├── config.json
    #   └── README.md

    dist_path = Path(DIST_DIR)

    # 复制配置文件
    for config_file in CONFIG_FILES:
        src = Path(config_file)
        if src.exists():
            dst = dist_path / config_file
            shutil.copy2(src, dst)
            print(f"  已复制: {config_file}")
        else:
            print(f"  跳过: {config_file} (不存在)")

    # 创建启动脚本（仅用于开发/调试）
    create_launch_scripts(dist_path)

    print(f"\n分发包已准备完成: {dist_path.absolute()}")

def create_launch_scripts(dist_path):
    """创建便捷的启动脚本"""
    system = platform.system().lower()

    # Windows 批处理脚本
    if system == "windows":
        bat_content = '''@echo off
REM 环境变量管理器启动脚本

REM 检查是否指定了命令
if "%1"=="" (
    env-manager.exe --help
) else (
    env-manager.exe %*
)
'''
        bat_file = dist_path / "env-manager.bat"
        with open(bat_file, 'w') as f:
            f.write(bat_content)
        print(f"  已创建启动脚本: env-manager.bat")

    # Unix shell 脚本
    else:
        sh_content = '''#!/bin/bash
# 环境变量管理器启动脚本

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

if [ $# -eq 0 ]; then
    ./env-manager --help
else
    ./env-manager "$@"
fi
'''
        sh_file = dist_path / "env-manager.sh"
        with open(sh_file, 'w') as f:
            f.write(sh_content)
        os.chmod(sh_file, 0o755)
        print(f"  已创建启动脚本: env-manager.sh")

def create_readme_for_dist():
    """创建分发版的 README"""
    readme_content = '''# 环境变量管理器 - 可执行版

这是环境变量管理器的独立可执行版本，无需安装 Python 即可运行。

## 快速开始

### Windows

直接双击 `env-manager.exe` 运行，或使用命令行：

```cmd
REM 查看帮助
env-manager.exe --help

REM 列出所有配置
env-manager.exe --list

REM 加载配置
env-manager.exe gpt --export
```

### Linux/macOS

```bash
# 添加执行权限
chmod +x env-manager
./env-manager --help
```

## 配置文件

配置文件 `config.json` 与可执行文件在同一目录，编辑此文件来管理您的配置。

详细使用说明请参考 `README.md` 文件。

## 功能说明

- 多配置环境变量管理
- 配置加密（如需使用需安装 cryptography）
- 永久环境变量设置（Windows 需安装 pywin32）
- .env 文件导入导出

## 系统要求

- Windows: Windows 7 或更高版本
- Linux: glibc 2.17 或更高版本
- macOS: macOS 10.13 或更高版本

## 支持的 Shell

- Windows: CMD, PowerShell
- Linux/macOS: Bash, Zsh, Fish

## 许可证

MIT License
'''

    dist_path = Path(DIST_DIR)
    readme_file = dist_path / "QUICKSTART.md"
    with open(readme_file, 'w', encoding='utf-8') as f:
        f.write(readme_content)
    print(f"  已创建快速开始文档: QUICKSTART.md")

def print_summary():
    """打印打包摘要"""
    system = platform.system().lower()
    dist_path = Path(DIST_DIR).absolute()

    print("\n" + "="*50)
    print("打包完成！")
    print("="*50)

    exe_name = APP_NAME + (".exe" if system == "windows" else "")
    exe_path = dist_path / exe_name

    print(f"\n可执行文件位置: {exe_path}")
    print(f"配置文件位置: {dist_path / 'config.json'}")

    print("\n文件列表:")
    for item in sorted(dist_path.iterdir()):
        size = item.stat().st_size
        size_str = f"{size:,} bytes" if size < 1024*1024 else f"{size/(1024*1024):.2f} MB"
        print(f"  {item.name:30s} {size_str:>15s}")

    print("\n" + "="*50)
    print("分发说明:")
    print("="*50)
    print(f"1. 将 {DIST_DIR} 目录下的所有文件打包分发")
    print(f"2. 用户无需安装 Python 即可使用")
    print(f"3. 配置文件 config.json 与可执行文件同目录")
    print("="*50)

def main():
    """主函数"""
    print("="*50)
    print("环境变量管理器 - 打包工具")
    print("="*50)
    print(f"平台: {platform.system()} {platform.machine()}")
    print(f"Python: {sys.version}")
    print("="*50)

    # 确认继续
    print("\n此脚本将:")
    print("1. 清理旧的构建目录")
    print("2. 生成 PyInstaller spec 文件")
    print("3. 打包可执行文件")
    print("4. 复制配置文件到 dist 目录")
    print("5. 创建启动脚本和文档")

    response = input("\n是否继续? [y/N]: ")
    if response.lower() != 'y':
        print("已取消")
        return

    # 执行打包流程
    if not build_app():
        sys.exit(1)

    prepare_distribution()
    create_readme_for_dist()
    print_summary()

if __name__ == "__main__":
    main()
