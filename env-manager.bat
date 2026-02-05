@echo off
setlocal

REM 环境变量管理器 - Windows版
if "%1"=="" (
    echo 使用方法: %~n0 [配置名称]
    echo 可用配置: qwen3-coder-plus, gpt, claude, deepseek
    goto :end
)

python env-manager.py %* --export --shell cmd

:end
endlocal