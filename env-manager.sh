#!/bin/bash
# 环境变量管理器 - Shell版

if [ $# -eq 0 ]; then
    echo "使用方法: $0 [配置名称]"
    echo "可用配置: qwen3-coder-plus, gpt, claude, deepseek"
    exit 1
fi

python3 env-manager.py "$@" --export