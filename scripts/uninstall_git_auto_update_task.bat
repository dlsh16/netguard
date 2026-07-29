@echo off
title Uninstall NetGuard Git Auto Update Task
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall_git_auto_update_task.ps1"
pause

