# 环境变量管理器 - PowerShell版
param(
    [string]$ConfigName
)

if (-not $ConfigName) {
    Write-Host "使用方法: .\env-manager.ps1 [配置名称]" -ForegroundColor Yellow
    Write-Host "可用配置: qwen3-coder-plus, gpt, claude, deepseek" -ForegroundColor Cyan
    exit
}

python env-manager.py $ConfigName --export --shell powershell