@echo off
chcp 936 >nul
title EgressGuard 仪表盘
cd /d "%~dp0"

rem 优先用打包好的 exe（无需 Python）。安装脚本会把 exe 复制到根目录，
rem 这样数据目录统一在 根目录\data，和命令行工具共用同一份配置。
if exist "%~dp0EgressGuard.exe"      ( start "" "%~dp0EgressGuard.exe"      & exit /b 0 )
if exist "%~dp0dist\EgressGuard.exe" ( start "" "%~dp0dist\EgressGuard.exe" & exit /b 0 )

set PYW=
for %%P in (pythonw.exe) do if not defined PYW set PYW=%%~$PATH:P
if not defined PYW (
    for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*") do (
        if exist "%%D\pythonw.exe" set PYW=%%D\pythonw.exe
    )
)
if not defined PYW (
    echo 找不到 EgressGuard.exe，也找不到 pythonw.exe。
    echo 请先跑 tools\build_exe.py 打包，或安装 Python 3.9+。
    pause
    exit /b 1
)
start "" "%PYW%" "%~dp0run_dashboard.py"
exit /b 0