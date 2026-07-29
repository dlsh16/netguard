@echo off
title NetGuard Dashboard - Stop
powershell -ExecutionPolicy Bypass -File "%~dp0netguard.ps1" stop
pause
