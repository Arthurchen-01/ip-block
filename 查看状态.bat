@echo off
chcp 936 >nul
title EgressGuard 状态
cd /d "%~dp0"
set OUT=%TEMP%\eg_status.json

if exist "%~dp0EgressGuardCore.exe" (
    "%~dp0EgressGuardCore.exe" --status --out "%OUT%"
    if exist "%OUT%" type "%OUT%"
    echo. & pause & exit /b 0
)
if exist "%~dp0dist\EgressGuardCore.exe" (
    "%~dp0dist\EgressGuardCore.exe" --status --out "%OUT%"
    if exist "%OUT%" type "%OUT%"
    echo. & pause & exit /b 0
)

set PY=
for %%P in (python.exe) do if not defined PY set PY=%%~$PATH:P
if not defined PY (
    for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*") do (
        if exist "%%D\python.exe" set PY=%%D\python.exe
    )
)
if not defined PY ( echo 找不到 EgressGuardCore.exe 也找不到 python.exe & pause & exit /b 1 )
"%PY%" "%~dp0run_core.py" --status
echo. & pause