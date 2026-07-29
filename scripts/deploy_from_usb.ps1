#Requires -RunAsAdministrator
# NetGuard USB Deploy Script
# Run on server: powershell -File "D:\NetGuard_update\scripts\deploy_from_usb.ps1"

$InstallDir = "C:\SNMP\Claude"
$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$UsbRoot    = Split-Path -Parent $ScriptDir

Write-Host ""
Write-Host "=== NetGuard USB Deploy ===" -ForegroundColor Cyan
Write-Host "USB  : $UsbRoot"    -ForegroundColor Gray
Write-Host "DEST : $InstallDir" -ForegroundColor Gray
Write-Host ""

if (-not (Test-Path "$InstallDir\backend\app.py")) {
    Write-Host "[ERROR] NetGuard not found at $InstallDir" -ForegroundColor Red
    exit 1
}

$confirm = Read-Host "Apply update? (y/N)"
if ($confirm -ne 'y' -and $confirm -ne 'Y') { Write-Host "Cancelled."; exit 0 }

# --- STEP 1: Stop service ---
Write-Host ""
Write-Host "[1/4] Stopping NetGuard service..." -ForegroundColor Yellow
$svc = Get-Service "NetGuard" -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Stop-Service "NetGuard" -Force
    Start-Sleep 2
    Write-Host "      Stopped." -ForegroundColor Green
} else {
    Write-Host "      Service not running, continuing." -ForegroundColor Gray
}

# --- STEP 2: Backup ---
Write-Host ""
Write-Host "[2/4] Backing up existing files..." -ForegroundColor Yellow
$date      = Get-Date -Format "yyyyMMdd_HHmmss"
$BackupDir = "C:\Backup\netguard\$date"
New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null

$backupList = @(
    "backend\app.py",
    "backend\config.py",
    "backend\database.py",
    "backend\api\routes.py",
    "frontend\index.html",
    "frontend\login.html",
    "frontend\js\dashboard.js",
    "frontend\css\style.css"
)
foreach ($f in $backupList) {
    $s = Join-Path $InstallDir $f
    if (Test-Path $s) {
        $d = Join-Path $BackupDir $f
        New-Item -ItemType Directory -Path (Split-Path $d) -Force | Out-Null
        Copy-Item $s $d -Force
    }
}
Write-Host "      Backup saved: $BackupDir" -ForegroundColor Green

# --- STEP 3: Copy files ---
Write-Host ""
Write-Host "[3/4] Copying files from USB..." -ForegroundColor Yellow

$files = @(
    "frontend\login.html",
    "frontend\index.html",
    "frontend\js\dashboard.js",
    "frontend\css\style.css",
    "backend\app.py",
    "backend\config.py",
    "backend\database.py",
    "backend\api\routes.py",
    "backend\api\agent_routes.py",
    "backend\auth\__init__.py",
    "backend\auth\jwt_handler.py",
    "backend\auth\routes.py"
)

$ok  = 0
$err = 0
foreach ($f in $files) {
    $src  = Join-Path $UsbRoot    $f
    $dest = Join-Path $InstallDir $f
    if (-not (Test-Path $src)) {
        Write-Host "      [MISS] $f" -ForegroundColor Yellow
        $err++
        continue
    }
    New-Item -ItemType Directory -Path (Split-Path $dest) -Force | Out-Null
    Copy-Item $src $dest -Force
    Write-Host "      [OK]   $f" -ForegroundColor Green
    $ok++
}
Write-Host ""
Write-Host "      Copied: $ok  /  Missing: $err" -ForegroundColor $(if ($err -eq 0) { 'Green' } else { 'Yellow' })

# --- STEP 4: Start service ---
Write-Host ""
Write-Host "[4/4] Starting NetGuard service..." -ForegroundColor Yellow
$svc2 = Get-Service "NetGuard" -ErrorAction SilentlyContinue
if ($svc2) {
    Start-Service "NetGuard"
    Start-Sleep 5
    $svc2.Refresh()
    if ($svc2.Status -eq 'Running') {
        Write-Host "      Service started OK." -ForegroundColor Green
    } else {
        Write-Host "      Service failed to start. Check log:" -ForegroundColor Red
        Write-Host "      Get-Content '$InstallDir\logs\service_stderr.log' -Tail 30"
    }
} else {
    Write-Host "      NetGuard service not registered (run install_windows.ps1 first)." -ForegroundColor Yellow
}

# --- Health check ---
Start-Sleep 2
try {
    $r = Invoke-RestMethod "http://localhost:8000/health" -TimeoutSec 5
    Write-Host "      Health: $($r.status)  $($r.timestamp)" -ForegroundColor Cyan
} catch {
    Write-Host "      No response yet (may still be starting up)." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Deploy complete ===" -ForegroundColor Green
Write-Host "URL    : http://localhost:8000"
Write-Host "Backup : $BackupDir"
Write-Host ""
