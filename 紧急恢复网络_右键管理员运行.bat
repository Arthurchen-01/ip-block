@echo off
chcp 936 >nul
title EgressGuard 紧急恢复网络
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo ========================================================
echo   紧急恢复：把网络无条件还回来
echo ========================================================
echo.
echo 即将执行：
echo   1. 防火墙出站默认策略 -^> Allow
echo   2. 删除 EgressGuard 的全部防火墙规则
echo   3. 停止并删除计划任务 EgressGuard
echo.
echo （不会卸载、不会删数据；网络恢复后你可以重新安装）
echo.

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow -ErrorAction SilentlyContinue; " ^
  "Remove-NetFirewallRule -Group 'EgressGuard' -ErrorAction SilentlyContinue; " ^
  "Remove-NetFirewallRule -Group 'EgressGuard_STRICT_ALLOW' -ErrorAction SilentlyContinue; " ^
  "Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'EgressGuard::*' } | Remove-NetFirewallRule -ErrorAction SilentlyContinue; " ^
  "Stop-ScheduledTask -TaskName 'EgressGuard' -ErrorAction SilentlyContinue; " ^
  "Unregister-ScheduledTask -TaskName 'EgressGuard' -Confirm:$false -ErrorAction SilentlyContinue; " ^
  "Write-Host '网络已恢复放行，闸门已停止。' -ForegroundColor Green"

echo.
echo 校验当前状态：
powershell -NoProfile -Command "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultOutboundAction | Format-Table -AutoSize"
echo.
pause
