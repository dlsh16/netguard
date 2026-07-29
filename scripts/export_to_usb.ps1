#Requires -RunAsAdministrator
# NetGuard USB Export Script
# Run on dev PC: powershell -File "C:\SNMP\Claude\scripts\export_to_usb.ps1"

$SrcRoot = "C:\SNMP\Claude"

# --- Auto-detect USB drive ---
$usb = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 } | Select-Object -First 1
if ($usb) {
    $defaultUsb = "$($usb.DeviceID)\NetGuard_update"
    $freeGB = [math]::Round($usb.FreeSpace / 1GB, 1)
    Write-Host "USB detected: $($usb.DeviceID)  ($freeGB GB free)" -ForegroundColor Cyan
} else {
    $defaultUsb = "D:\NetGuard_update"
}

$usbInput = Read-Host "USB destination path [$defaultUsb]"
$UsbDst   = if ([string]::IsNullOrWhiteSpace($usbInput)) { $defaultUsb } else { $usbInput.Trim() }

Write-Host ""
Write-Host "Source : $SrcRoot" -ForegroundColor Gray
Write-Host "Target : $UsbDst"  -ForegroundColor Gray
Write-Host ""

# --- File list ---
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
    "backend\auth\routes.py",
    "agent\netguard_agent.py",
    "agent\netguard_agent.ps1",
    "agent\agent_config.json",
    "agent\install.ps1",
    "scripts\deploy_from_usb.ps1",
    "scripts\install_agent_linux.sh"
)

New-Item -ItemType Directory -Path $UsbDst -Force | Out-Null

$ok  = 0
$err = 0
foreach ($f in $files) {
    $src  = Join-Path $SrcRoot $f
    $dest = Join-Path $UsbDst  $f
    if (-not (Test-Path $src)) {
        Write-Host "[MISS] $f" -ForegroundColor Yellow
        $err++
        continue
    }
    New-Item -ItemType Directory -Path (Split-Path $dest) -Force | Out-Null
    Copy-Item $src $dest -Force
    Write-Host "[OK]   $f" -ForegroundColor Green
    $ok++
}

Write-Host ""
Write-Host "Done: $ok files copied  /  $err missing" -ForegroundColor $(if ($err -eq 0) { 'Green' } else { 'Yellow' })
Write-Host ""
Write-Host "On the server, run:" -ForegroundColor Yellow
Write-Host "  powershell -File `"$UsbDst\scripts\deploy_from_usb.ps1`"" -ForegroundColor White
Write-Host ""
