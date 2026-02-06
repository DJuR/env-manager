#!/usr/bin/env python3
"""
环境变量管理器
支持：Windows, Linux, macOS
用法: env-manager.py [配置名称] [--export|--print|--set]
"""

import os
import sys
import json
import argparse
import platform
import subprocess
import getpass
import shutil
from pathlib import Path
from typing import Optional, Dict, Any

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import base64
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


def get_base_dir():
    """
    获取程序基目录
    - 打包后（PyInstaller）：返回可执行文件所在目录
    - 开发模式：返回脚本所在目录
    """
    if getattr(sys, 'frozen', False):
        # 打包后的可执行文件
        return Path(sys.executable).parent
    else:
        # 开发模式，返回脚本所在目录
        return Path(__file__).parent.resolve()


def get_config_path(config_file: str = "config.json") -> Path:
    """
    获取配置文件完整路径
    首先查找程序同目录，然后查找用户配置目录
    """
    base_dir = get_base_dir()

    # 1. 优先查找程序同目录
    config_in_app_dir = base_dir / config_file
    if config_in_app_dir.exists():
        return config_in_app_dir

    # 2. 查找用户配置目录 ~/.config/env-manager/
    user_config_dir = Path.home() / ".config" / "env-manager"
    user_config_path = user_config_dir / config_file
    if user_config_path.exists():
        return user_config_path

    # 3. 默认返回程序同目录（用于创建新配置）
    return config_in_app_dir


class EnvManager:
    def __init__(self, config_file="config.json"):
        # 获取配置文件路径（支持打包后的可执行文件）
        self.config_path = get_config_path(config_file)
        self.config_file = str(self.config_path)

        self.system = platform.system().lower()
        self.configs = self.load_configs()

        # 加密文件路径与配置文件同目录
        self.encrypted_file = str(self.config_path.parent / (self.config_path.stem + ".enc"))

        # 用户配置目录（用于 .env 文件等）
        self.env_dir = Path.home() / ".config" / "env-manager"
        self.env_dir.mkdir(parents=True, exist_ok=True)
        
    def load_configs(self):
        """加载配置文件（支持本地覆盖）"""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                configs = json.load(f)
        except FileNotFoundError:
            print(f"错误: 找不到配置文件")
            print(f"  期望位置: {self.config_file}")

            # 提供创建模板的选项
            print(f"\n提示: 首次使用需要创建配置文件")
            print(f"  位置: {self.config_file}")

            # 尝试创建默认配置模板
            self.create_default_config()
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"错误: 配置文件格式不正确")
            print(f"  文件: {self.config_file}")
            print(f"  详情: {e}")
            sys.exit(1)

        # 加载本地覆盖配置（如果存在）
        local_config_path = get_config_path("local_config.json")
        if local_config_path.exists() and local_config_path != self.config_path:
            try:
                with open(local_config_path, 'r', encoding='utf-8') as f:
                    local_configs = json.load(f)
                    # 合并配置（本地配置覆盖默认配置）
                    for key, value in local_configs.items():
                        if not key.startswith('_'):  # 忽略注释项
                            configs[key] = value
            except Exception as e:
                print(f"警告: 加载本地配置失败: {e}")

        return configs

    def create_default_config(self):
        """创建默认配置模板"""
        default_config = {
            "example-config": {
                "OPENAI_API_KEY": "sk-your-api-key-here",
                "OPENAI_BASE_URL": "https://api.openai.com/v1",
                "MODEL": "gpt-4"
            },
            "notes": {
                "_comment": "复制 example-config 并重命名为你的配置名称",
                "_comment2": "将 YOUR_* 占位符替换为实际值"
            }
        }

        try:
            # 确保父目录存在
            self.config_path.parent.mkdir(parents=True, exist_ok=True)

            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(default_config, f, indent=2, ensure_ascii=False)

            print(f"\n✅ 已创建默认配置文件: {self.config_file}")
            print(f"\n请编辑配置文件后重新运行程序")
        except Exception as e:
            print(f"\n⚠️  自动创建配置文件失败: {e}")
            print(f"请手动创建配置文件: {self.config_file}")
            
    def get_config(self, config_name):
        """获取指定配置"""
        if config_name not in self.configs:
            print(f"错误: 配置 '{config_name}' 不存在")
            print("可用配置:", ", ".join(self.configs.keys()))
            sys.exit(1)
        return self.configs[config_name]
    
    def print_env_vars(self, config_name):
        """打印环境变量"""
        config = self.get_config(config_name)
        print(f"\n=== {config_name.upper()} 配置 ===")
        for key, value in config.items():
            print(f"{key}={value}")
        print()
        
    def export_to_shell(self, config_name, shell_type=None):
        """导出到当前shell环境"""
        config = self.get_config(config_name)
        
        if shell_type is None:
            # 自动检测shell类型
            if self.system == "windows":
                shell_type = "cmd"
            else:
                # 获取当前shell
                shell = os.environ.get('SHELL', '')
                if 'fish' in shell:
                    shell_type = "fish"
                elif 'zsh' in shell:
                    shell_type = "zsh"
                else:
                    shell_type = "bash"
        
        print(f"正在设置 {config_name} 配置到 {shell_type}...")
        
        commands = []
        for key, value in config.items():
            if self.system == "windows":
                if shell_type == "powershell":
                    commands.append(f'$env:{key}="{value}"')
                else:  # cmd
                    commands.append(f'set {key}={value}')
            else:
                if shell_type == "fish":
                    commands.append(f'set -gx {key} "{value}"')
                else:  # bash/zsh
                    commands.append(f'export {key}="{value}"')
        
        # 打印导出命令
        if self.system == "windows":
            print("\n复制以下命令到终端执行：\n")
            for cmd in commands:
                print(cmd)
                
            if shell_type == "cmd":
                print("\n或者运行: call env-manager.bat", config_name)
            elif shell_type == "powershell":
                print("\n或者运行: .\\env-manager.ps1", config_name)
        else:
            print("\n运行以下命令使环境变量生效：")
            for cmd in commands:
                print(cmd)
            print(f"\n或者运行: source <(python3 {sys.argv[0]} {config_name} --export)")
    
    def save_to_file(self, config_name, output_file=None):
        """保存环境变量到文件"""
        config = self.get_config(config_name)
        
        if output_file is None:
            if self.system == "windows":
                output_file = f"env_{config_name}.bat"
            else:
                output_file = f"env_{config_name}.sh"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            if self.system == "windows":
                f.write(f"@echo off\n")
                f.write(f"REM {config_name} 环境变量配置\n")
                for key, value in config.items():
                    f.write(f'set {key}={value}\n')
                f.write(f"echo 已加载 {config_name} 配置\n")
                print(f"已创建 {output_file}")
                print(f"运行: {output_file} 来设置环境变量")
            else:
                f.write(f"#!/bin/bash\n")
                f.write(f"# {config_name} 环境变量配置\n")
                for key, value in config.items():
                    f.write(f'export {key}="{value}"\n')
                f.write(f'echo "已加载 {config_name} 配置"\n')
                # 添加执行权限
                os.chmod(output_file, 0o755)
                print(f"已创建 {output_file}")
                print(f"运行: source {output_file} 来设置环境变量")
                
    def list_configs(self):
        """列出所有可用配置"""
        print("可用的配置方案：")
        for name, config in self.configs.items():
            print(f"\n{name}:")
            for key in config.keys():
                print(f"  - {key}")
    
    def validate_config(self, config_name):
        """验证配置是否完整"""
        config = self.get_config(config_name)
        required_keys = ['ANTHROPIC_API_KEY', 'ANTHROPIC_BASE_URL']
        
        print(f"验证 {config_name} 配置...")
        for key in required_keys:
            if key in config:
                value = config[key]
                if value.startswith("YOUR_") or value == "":
                    print(f"  ⚠️  {key}: 需要设置实际值")
                else:
                    print(f"  ✓ {key}: 已设置")
            else:
                print(f"  ✗ {key}: 缺失")
    
    def setup_current_shell(self, config_name):
        """尝试设置当前shell的环境变量（仅当前进程）"""
        config = self.get_config(config_name)
        
        print(f"为当前进程设置 {config_name} 配置...")
        for key, value in config.items():
            os.environ[key] = value
            print(f"  {key}={value}")
        
        print(f"\n✅ 已为当前Python进程设置 {config_name} 配置")
        print("注意: 这只会影响当前进程及其子进程")
        print("如需永久生效，请使用 --export 选项")

    # ==================== 永久设置环境变量功能 ====================

    def set_permanent_env(self, config_name, scope="user"):
        """
        永久设置环境变量
        scope: 'user' (当前用户) 或 'system' (全局，需要管理员权限)
        """
        config = self.get_config(config_name)

        if self.system == "windows":
            self._set_windows_permanent_env(config, scope)
        else:
            self._set_unix_permanent_env(config, scope)

    def _set_windows_permanent_env(self, config: Dict[str, str], scope: str):
        """Windows 永久设置环境变量（写入注册表）"""
        try:
            import winreg

            if scope == "system":
                key_path = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
                print("⚠️  正在写入系统环境变量，需要管理员权限...")
            else:
                key_path = r"Environment"
                print("正在写入用户环境变量...")

            # 尝试打开注册表
            try:
                if scope == "system":
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
                else:
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
            except PermissionError:
                print("❌ 权限不足！请以管理员身份运行或在用户权限下使用 --scope user")
                print("提示: 以管理员身份运行 PowerShell 或 CMD")
                return False

            for env_key, env_value in config.items():
                winreg.SetValueEx(key, env_key, 0, winreg.REG_EXPAND_SZ, str(env_value))
                print(f"  ✓ {env_key} = {env_value}")

            winreg.CloseKey(key)

            # 广播环境变量更改通知
            import ctypes
            HWND_BROADCAST = 0xFFFF
            WM_SETTINGCHANGE = 0x1A
            SMTO_ABORTIFHUNG = 0x0002
            result = ctypes.c_long()
            ctypes.windll.user32.SendMessageTimeoutW(
                HWND_BROADCAST, WM_SETTINGCHANGE, 0,
                "Environment", SMTO_ABORTIFHUNG, 5000, ctypes.byref(result)
            )

            print(f"\n✅ 已永久设置 {len(config)} 个环境变量")
            print("⚠️  请重启终端/应用程序使更改生效")
            return True

        except ImportError:
            print("❌ Windows 环境变量设置需要 pywin32，请运行: pip install pywin32")
            return False
        except Exception as e:
            print(f"❌ 设置环境变量失败: {e}")
            return False

    def _set_unix_permanent_env(self, config: Dict[str, str], scope: str):
        """Linux/macOS 永久设置环境变量（写入 shell 配置文件）"""
        print("正在写入 shell 配置文件...")

        # 检测当前 shell
        shell = os.environ.get('SHELL', '/bin/bash')
        shell_name = Path(shell).stem

        # 确定要写入的配置文件
        if scope == "system":
            config_files = ["/etc/environment", "/etc/profile"]
            print("⚠️  系统范围设置需要 sudo 权限")
        else:
            if shell_name == "zsh":
                config_files = [str(Path.home() / ".zshrc")]
            elif shell_name == "fish":
                config_files = [str(Path.home() / ".config" / "fish" / "config.fish")]
            else:
                config_files = [
                    str(Path.home() / ".bashrc"),
                    str(Path.home() / ".bash_profile"),
                    str(Path.home() / ".profile")
                ]

        # 生成环境变量块
        marker = f"# --- ENV-MANAGER: AUTO-GENERATED DO NOT EDIT BELOW ---"
        marker_end = f"# --- END ENV-MANAGER ---"

        env_block = [marker]
        for key, value in config.items():
            if shell_name == "fish":
                env_block.append(f"set -gx {key} \"{value}\"")
            else:
                env_block.append(f"export {key}=\"{value}\"")
        env_block.append(marker_end)
        env_block_str = "\n".join(env_block) + "\n"

        # 写入每个配置文件
        for config_file in config_files:
            if not os.path.exists(config_file) and scope == "user":
                # 用户配置文件不存在，创建它
                try:
                    Path(config_file).parent.mkdir(parents=True, exist_ok=True)
                    with open(config_file, 'w') as f:
                        f.write("")
                except Exception:
                    continue

            if os.path.exists(config_file):
                try:
                    with open(config_file, 'r+', encoding='utf-8') as f:
                        content = f.read()

                        # 移除旧的 env-manager 块
                        if marker in content:
                            lines = content.split('\n')
                            new_lines = []
                            skip = False
                            for line in lines:
                                if marker in line:
                                    skip = True
                                    new_lines.append(env_block_str)
                                elif skip:
                                    if marker_end in line:
                                        skip = False
                                    continue
                                else:
                                    new_lines.append(line)
                            content = '\n'.join(new_lines)
                        else:
                            content = content.rstrip() + "\n\n" + env_block_str

                        # 写回文件
                        f.seek(0)
                        f.truncate()
                        f.write(content)

                    print(f"  ✓ 已更新 {config_file}")
                except PermissionError:
                    print(f"  ⚠️  权限不足，跳过 {config_file}")
                except Exception as e:
                    print(f"  ⚠️  更新 {config_file} 失败: {e}")

        print(f"\n✅ 已永久设置 {len(config)} 个环境变量")
        print("⚠️  请运行以下命令使更改立即生效:")
        print(f"   source {config_files[0]}")
        print("   或重启终端")

    # ==================== 配置文件加密功能 ====================

    def check_crypto_support(self):
        """检查加密功能是否可用"""
        if not HAS_CRYPTO:
            print("❌ 加密功能需要 cryptography 库")
            print("请运行: pip install cryptography")
            return False
        return True

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """从密码派生加密密钥"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt_config(self, password: Optional[str] = None):
        """加密配置文件"""
        if not self.check_crypto_support():
            return False

        if password is None:
            password = getpass.getpass("请输入加密密码: ")
            password_confirm = getpass.getpass("请再次输入密码: ")
            if password != password_confirm:
                print("❌ 两次密码不一致")
                return False

        # 生成盐和密钥
        salt = os.urandom(16)
        key = self._derive_key(password, salt)

        # 加密配置
        fernet = Fernet(key)
        config_json = json.dumps(self.configs, indent=2, ensure_ascii=False)
        encrypted_data = fernet.encrypt(config_json.encode('utf-8'))

        # 保存加密文件 (salt + encrypted_data)
        encrypted_content = base64.urlsafe_b64encode(salt + encrypted_data).decode('utf-8')

        with open(self.encrypted_file, 'w', encoding='utf-8') as f:
            json.dump({
                'version': '1.0',
                'algorithm': 'AES-256-GCM',
                'encrypted': True,
                'data': encrypted_content
            }, f, indent=2)

        print(f"✅ 配置已加密并保存到 {self.encrypted_file}")
        print(f"⚠️  请妥善保管密码，解密需要相同密码")
        return True

    def decrypt_config(self, password: Optional[str] = None, output_file: Optional[str] = None):
        """解密配置文件"""
        if not self.check_crypto_support():
            return False

        if not os.path.exists(self.encrypted_file):
            print(f"❌ 找不到加密文件 {self.encrypted_file}")
            return False

        try:
            with open(self.encrypted_file, 'r', encoding='utf-8') as f:
                encrypted_data = json.load(f)

            if not encrypted_data.get('encrypted'):
                print("❌ 该文件不是加密文件")
                return False

            # 解码数据
            data = base64.urlsafe_b64decode(encrypted_data['data'].encode('utf-8'))
            salt = data[:16]
            encrypted_content = data[16:]

            # 获取密码
            if password is None:
                password = getpass.getpass("请输入解密密码: ")

            # 解密
            key = self._derive_key(password, salt)
            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(encrypted_content)
            decrypted_config = json.loads(decrypted_data.decode('utf-8'))

            # 保存解密后的配置
            output = output_file or self.config_file
            with open(output, 'w', encoding='utf-8') as f:
                json.dump(decrypted_config, f, indent=2, ensure_ascii=False)

            print(f"✅ 配置已解密并保存到 {output}")
            return True

        except Exception as e:
            print(f"❌ 解密失败: {e}")
            print("请检查密码是否正确")
            return False

    def edit_encrypted(self, password: Optional[str] = None):
        """编辑加密的配置文件（临时解密后重新加密）"""
        if not self.check_crypto_support():
            return False

        # 临时解密
        if not self.decrypt_config(password, self.config_file):
            return False

        print(f"\n请编辑 {self.config_file}，完成后按回车继续...")
        try:
            # 尝试打开默认编辑器
            editor = os.environ.get('EDITOR', 'notepad' if self.system == "windows" else 'nano')
            subprocess.call([editor, self.config_file])
        except:
            input("按回车继续...")

        # 询问密码并重新加密
        print("\n重新加密配置文件...")
        self.encrypt_config()

        # 删除临时明文文件
        try:
            os.remove(self.config_file)
            print(f"✅ 临时文件已清理")
        except:
            print(f"⚠️  请手动删除临时文件: {self.config_file}")

    # ==================== .env 文件支持 ====================

    def export_to_dotenv(self, config_name, output_file: Optional[str] = None):
        """导出配置为 .env 文件格式"""
        config = self.get_config(config_name)

        if output_file is None:
            output_file = f".env.{config_name}"
            if self.env_dir.exists():
                output_file = str(self.env_dir / f".env.{config_name}")

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"# Environment configuration for: {config_name}\n")
            f.write(f"# Generated by env-manager\n\n")

            for key, value in config.items():
                # 引号处理
                if ' ' in value or '"' in value or "'" in value:
                    f.write(f'{key}="{value}"\n')
                else:
                    f.write(f'{key}={value}\n')

        print(f"✅ 已创建 .env 文件: {output_file}")
        print(f"使用方法: export $(cat {output_file} | xargs)")
        print(f"或使用 python-dotenv: pip install python-dotenv")

    def import_from_dotenv(self, dotenv_file: str, config_name: str, overwrite: bool = False):
        """从 .env 文件导入配置"""
        if not os.path.exists(dotenv_file):
            print(f"❌ 找不到文件: {dotenv_file}")
            return False

        config = {}
        with open(dotenv_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # 解析 KEY=VALUE 格式
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()

                    # 去除引号
                    if (value.startswith('"') and value.endswith('"')) or \
                       (value.startswith("'") and value.endswith("'")):
                        value = value[1:-1]

                    config[key] = value

        if overwrite or config_name not in self.configs:
            self.configs[config_name] = config
            self._save_configs()
            print(f"✅ 已从 {dotenv_file} 导入配置到 {config_name}")
            print(f"包含 {len(config)} 个环境变量")
            return True
        else:
            print(f"❌ 配置 {config_name} 已存在，使用 --overwrite 覆盖")
            return False

    def _save_configs(self):
        """保存配置到文件"""
        with open(self.config_file, 'w', encoding='utf-8') as f:
            json.dump(self.configs, f, indent=2, ensure_ascii=False)

def main():
    parser = argparse.ArgumentParser(
        description="环境变量管理器 - 支持多配置切换",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 基本功能
  env-manager qwen3-coder-plus --print    # 显示配置
  env-manager gpt --export                # 导出到当前shell
  env-manager claude --save              # 保存为脚本文件
  env-manager --list                     # 列出所有配置
  env-manager deepseek --validate        # 验证配置
  env-manager gpt --set                  # 设置当前进程环境变量

  # 永久设置环境变量（需要管理员权限）
  env-manager gpt --permanent            # 永久设置到用户环境变量
  env-manager gpt --permanent --scope system  # 设置到系统环境变量（需要管理员）

  # 配置加密
  env-manager --encrypt                  # 加密配置文件
  env-manager --decrypt                  # 解密配置文件
  env-manager --edit-encrypted           # 编辑加密的配置文件

  # .env 文件支持
  env-manager gpt --to-dotenv            # 导出为 .env 文件
  env-manager --from-dotenv .env myconfig --overwrite  # 从 .env 导入配置

  # 应用信息
  env-manager --info                     # 显示应用和配置文件信息
  env-manager --init                     # 初始化配置文件
        """
    )

    parser.add_argument(
        "config",
        nargs="?",
        help="配置名称 (如: qwen3-coder-plus, gpt, claude, deepseek)"
    )
    
    parser.add_argument(
        "--export", "-e",
        action="store_true",
        help="导出环境变量到当前shell"
    )
    
    parser.add_argument(
        "--print", "-p",
        action="store_true",
        help="打印环境变量配置"
    )
    
    parser.add_argument(
        "--save", "-s",
        action="store_true",
        help="保存为脚本文件"
    )
    
    parser.add_argument(
        "--list", "-l",
        action="store_true",
        help="列出所有可用配置"
    )
    
    parser.add_argument(
        "--validate", "-v",
        action="store_true",
        help="验证配置完整性"
    )
    
    parser.add_argument(
        "--set", 
        action="store_true",
        help="为当前进程设置环境变量"
    )
    
    parser.add_argument(
        "--shell",
        choices=["bash", "zsh", "fish", "cmd", "powershell"],
        help="指定shell类型"
    )
    
    parser.add_argument(
        "--config-file",
        default="config.json",
        help="配置文件路径 (默认: config.json)"
    )

    # ==================== 永久设置环境变量 ====================
    parser.add_argument(
        "--permanent", "-P",
        action="store_true",
        help="永久设置环境变量到系统"
    )
    parser.add_argument(
        "--scope",
        choices=["user", "system"],
        default="user",
        help="设置范围: user (当前用户) 或 system (全局，需要管理员权限)"
    )

    # ==================== 配置加密 ====================
    parser.add_argument(
        "--encrypt",
        action="store_true",
        help="加密配置文件"
    )
    parser.add_argument(
        "--decrypt",
        action="store_true",
        help="解密配置文件"
    )
    parser.add_argument(
        "--edit-encrypted",
        action="store_true",
        help="编辑加密的配置文件"
    )
    parser.add_argument(
        "--password",
        help="加密/解密密码（不推荐，建议交互式输入）"
    )

    # ==================== .env 文件支持 ====================
    parser.add_argument(
        "--to-dotenv",
        action="store_true",
        help="导出为 .env 文件格式"
    )
    parser.add_argument(
        "--from-dotenv",
        metavar="FILE",
        help="从 .env 文件导入配置"
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="覆盖已存在的配置"
    )

    # ==================== 信息查看 ====================
    parser.add_argument(
        "--info",
        action="store_true",
        help="显示应用和配置文件信息"
    )

    # ==================== 初始化配置 ====================
    parser.add_argument(
        "--init",
        action="store_true",
        help="初始化配置文件（创建默认模板）"
    )

    args = parser.parse_args()

    # 初始化管理器
    manager = EnvManager(args.config_file)

    # ==================== 信息和初始化命令 ====================
    if args.info:
        print("\n" + "="*50)
        print("环境变量管理器 - 应用信息")
        print("="*50)
        print(f"应用路径: {get_base_dir()}")
        print(f"配置文件: {manager.config_file}")
        print(f"加密文件: {manager.encrypted_file}")
        print(f"工作目录: {os.getcwd()}")
        print(f"系统平台: {platform.system()} {platform.machine()}")
        print(f"Python版本: {sys.version.split()[0]}")
        print(f"打包状态: {'已打包' if getattr(sys, 'frozen', False) else '开发模式'}")
        print(f"加密支持: {'可用' if HAS_CRYPTO else '未安装 cryptography'}")
        print("="*50)
        if os.path.exists(manager.config_file):
            print(f"\n配置文件存在: 是")
            print(f"配置数量: {len(manager.configs)}")
            print(f"配置列表: {', '.join(manager.configs.keys())}")
        else:
            print(f"\n配置文件存在: 否")
            print(f"使用 --init 初始化配置文件")
        print("="*50)
        return

    if args.init:
        if os.path.exists(manager.config_file):
            print(f"⚠️  配置文件已存在: {manager.config_file}")
            response = input("是否覆盖? [y/N]: ")
            if response.lower() != 'y':
                print("已取消")
                return
        manager.create_default_config()
        return

    # ==================== 加密/解密命令（不需要配置名） ====================
    if args.encrypt:
        manager.encrypt_config(args.password)
        return
    if args.decrypt:
        manager.decrypt_config(args.password)
        return
    if args.edit_encrypted:
        manager.edit_encrypted(args.password)
        return

    # ==================== .env 导入命令 ====================
    if args.from_dotenv:
        if not args.config:
            print("❌ 导入 .env 文件需要指定配置名称")
            print("用法: env-manager.py --from-dotenv FILE [配置名称]")
            sys.exit(1)
        manager.import_from_dotenv(args.from_dotenv, args.config, args.overwrite)
        return

    # ==================== 其他命令 ====================
    if args.list:
        manager.list_configs()
        return

    if args.config is None:
        parser.print_help()
        print("\n当前可用配置:", ", ".join(manager.configs.keys()))
        return

    # 处理需要配置名的命令
    if args.permanent:
        manager.set_permanent_env(args.config, args.scope)
    elif args.to_dotenv:
        manager.export_to_dotenv(args.config)
    elif args.print:
        manager.print_env_vars(args.config)
    elif args.export:
        manager.export_to_shell(args.config, args.shell)
    elif args.save:
        manager.save_to_file(args.config)
    elif args.validate:
        manager.validate_config(args.config)
    elif args.set:
        manager.setup_current_shell(args.config)
    else:
        # 默认行为：打印配置
        manager.print_env_vars(args.config)
        print("使用 --export 导出到shell，或 --save 保存为脚本文件")
        print("使用 --permanent 永久设置到系统")
        print("使用 --to-dotenv 导出为 .env 文件")
        print("使用 --encrypt 加密配置文件")

if __name__ == "__main__":
    main()