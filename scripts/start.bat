@echo off
title NetGuard Dashboard
powershell -NoExit -ExecutionPolicy Bypass -File "%~dp0netguard.ps1" start
