@echo off
chcp 936 >nul
title EgressGuard 闸门状态
cd /d "%~dp0"
set OUT=%TEMP%\eg_check.json

if exist "%~dp0dist\EgressGuardCore.exe" (
    "%~dp0dist\EgressGuardCore.exe" --check --out "%OUT%"
    if exist "%OUT%" type "%OUT%"
    echo.
    pause
    exit /b 0
)

set PY=
for %%P in (python.exe) do if not defined PY set PY=%%~$PATH:P
if not defined PY (
    for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*") do (
        if exist "%%D\python.exe" set PY=%%D\python.exe
    )
)
if not defined PY ( echo 找不到 EgressGuardCore.exe 也找不到 python.exe & pause & exit /b 1 )
"%PY%" "%~dp0run_core.py" --check
echo.
pause
