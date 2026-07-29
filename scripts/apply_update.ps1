#Requires -Version 5.1
# NetGuard Auto-Update Script
# Usage: .\apply_update.ps1 [-InstallDir "C:\SNMP\Claude"]

param(
    [string]$InstallDir = "C:\SNMP\Claude"
)

$UpdateDir = Split-Path -Parent $PSScriptRoot   # zip 루트 (scripts\ 한 단계 위)
$BackupDir = "$InstallDir\backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$VenvPy    = Join-Path $InstallDir "venv\Scripts\python.exe"

function Write-Log {
    param([string]$Color, [string]$Tag, [string]$Msg)
    $line = "[$(Get-Date -Format 'HH:mm:ss')] [$Tag] $Msg"
    Write-Host $line -ForegroundColor $Color
}

# ── 설치 경로 확인 ─────────────────────────────────────────────────────────────
if (-not (Test-Path "$InstallDir\backend\app.py")) {
    Write-Log Red "ERROR" "NetGuard installation not found at: $InstallDir"
    Write-Log Red "ERROR" "Usage: .\apply_update.ps1 -InstallDir <path>"
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""
Write-Host "=== NetGuard Auto-Update ===" -ForegroundColor Cyan
Write-Log Cyan "INFO " "Install dir : $InstallDir"
Write-Log Cyan "INFO " "Update dir  : $UpdateDir"
Write-Log Cyan "INFO " "Backup dir  : $BackupDir"
Write-Host ""

# ── 서비스 중지 ────────────────────────────────────────────────────────────────
Write-Log Yellow "STOP " "Stopping NetGuard service..."
$procs = Get-WmiObject Win32_Process | Where-Object {
    $_.Name -like "python*" -and $_.CommandLine -like "*uvicorn*app:app*"
}
if ($procs) {
    foreach ($p in $procs) {
        Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
        Write-Log Green "STOP " "Killed PID $($p.ProcessId)"
    }
    Start-Sleep -Seconds 2
} else {
    Write-Log Gray "STOP " "No running service found"
}

# ── 백업 ───────────────────────────────────────────────────────────────────────
Write-Log Yellow "BKUP " "Creating backup..."
New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null

$backupTargets = @(
    "backend\app.py",
    "backend\collectors\snmp_collector.py",
    "backend\api\agent_routes.py",
    "scripts\netguard.ps1",
    "scripts\start.bat",
    "scripts\stop.bat"
)
foreach ($rel in $backupTargets) {
    $src = Join-Path $InstallDir $rel
    if (Test-Path $src) {
        $dst = Join-Path $BackupDir $rel
        New-Item -ItemType Directory -Path (Split-Path $dst) -Force | Out-Null
        Copy-Item $src $dst -Force
    }
}
Write-Log Green "BKUP " "Backup saved to: $BackupDir"

# ── 파일 복사 ──────────────────────────────────────────────────────────────────
Write-Log Yellow "COPY " "Applying update files..."

$copyMap = @{
    "backend\app.py"                        = "backend\app.py"
    "backend\database.py"                   = "backend\database.py"
    "backend\collectors\snmp_collector.py"  = "backend\collectors\snmp_collector.py"
    "backend\api\agent_routes.py"           = "backend\api\agent_routes.py"
    "requirements.txt"                      = "requirements.txt"
    "agent\agent_config.json"               = "agent\agent_config.json"
    "agent\install.bat"                     = "agent\install.bat"
    "agent\install.ps1"                     = "agent\install.ps1"
    "agent\restart_agent.bat"               = "agent\restart_agent.bat"
    "agent\restart_agent.ps1"               = "agent\restart_agent.ps1"
    "agent\restart_agent.sh"                = "agent\restart_agent.sh"
    "agent\start_agent_background.bat"      = "agent\start_agent_background.bat"
    "agent\start_agent_background.ps1"      = "agent\start_agent_background.ps1"
    "agent\netguard_agent.ps1"              = "agent\netguard_agent.ps1"
    "agent\netguard_agent.py"               = "agent\netguard_agent.py"
    "docs\AGENT_RESTART_GUIDE.md"           = "docs\AGENT_RESTART_GUIDE.md"
    "docs\agent_install_windows.md"         = "docs\agent_install_windows.md"
    "docs\agent_install_linux.md"           = "docs\agent_install_linux.md"
    "scripts\netguard.ps1"                  = "scripts\netguard.ps1"
    "scripts\start.bat"                     = "scripts\start.bat"
    "scripts\stop.bat"                      = "scripts\stop.bat"
}

$ok = 0; $skip = 0
foreach ($rel in $copyMap.Keys) {
    $src = Join-Path $UpdateDir $rel
    $dst = Join-Path $InstallDir ($copyMap[$rel])
    if (Test-Path $src) {
        New-Item -ItemType Directory -Path (Split-Path $dst) -Force | Out-Null
        Copy-Item $src $dst -Force
        Write-Log Green "OK   " $rel
        $ok++
    } else {
        Write-Log Gray "SKIP " "$rel (not in update package)"
        $skip++
    }
}
Write-Log Cyan "COPY " "Applied: $ok files  |  Skipped: $skip files"

# ── pip 의존성 업데이트 ────────────────────────────────────────────────────────
$reqFile = Join-Path $InstallDir "requirements.txt"
if (Test-Path $reqFile) {
    Write-Log Yellow "PIP  " "Installing/updating Python dependencies..."
    $pipResult = & $VenvPy -m pip install -r $reqFile --quiet 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Log Green "PIP  " "Dependencies updated"
    } else {
        Write-Log Yellow "PIP  " "pip install warnings (check manually): $pipResult"
    }
}

# ── 서비스 재시작 ──────────────────────────────────────────────────────────────
$startScript = Join-Path $InstallDir "scripts\netguard.ps1"
if (Test-Path $startScript) {
    Write-Log Yellow "START" "Restarting NetGuard service..."
    & powershell -ExecutionPolicy Bypass -File $startScript start
} else {
    Write-Log Yellow "START" "netguard.ps1 not found - start manually:"
    Write-Host "  cd $InstallDir\backend"
    Write-Host "  ..\venv\Scripts\python.exe -m uvicorn app:app --host 0.0.0.0 --port 8000"
}

Write-Host ""
Write-Host "=== Update complete ===" -ForegroundColor Green
Write-Host "  Backup : $BackupDir"
Write-Host ""
Read-Host "Press Enter to exit"
