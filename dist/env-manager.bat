@echo off
REM 环境变量管理器启动脚本

REM 检查是否指定了命令
if "%1"=="" (
    env-manager.exe --help
) else (
    env-manager.exe %*
)
