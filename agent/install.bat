@echo off
title NetGuard Agent Install
set "SCRIPT=%~dp0install.ps1"

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$p=$args[0]; $errors=$null; [System.Management.Automation.PSParser]::Tokenize((Get-Content -Raw -LiteralPath $p), [ref]$errors) | Out-Null; if($errors){$errors | Format-List *; exit 1}; Write-Host ('PowerShell syntax OK: ' + $p)" "%SCRIPT%"
if errorlevel 1 (
    pause
    exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%"
pause
