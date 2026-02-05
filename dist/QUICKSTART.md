# 环境变量管理器 - 可执行版

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
