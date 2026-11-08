@echo off
setlocal EnableExtensions DisableDelayedExpansion
title NetGuard Agent Install
set "PS_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if defined PROCESSOR_ARCHITEW6432 set "PS_EXE=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
if /I "%~1"=="--check" goto check
"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
set "RESULT=%ERRORLEVEL%"
pause
exit /b %RESULT%

:check
"%PS_EXE%" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0install.ps1" -CheckOnly
exit /b %ERRORLEVEL%
