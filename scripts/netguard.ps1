#Requires -Version 5.1
# NetGuard Service Manager
# Usage: .\netguard.ps1 [start|stop|restart|status]

param(
    [ValidateSet("start","stop","restart","status")]
    [string]$Action = "status"
)

$RootDir  = Split-Path -Parent $PSScriptRoot
$VenvPy   = Join-Path $RootDir "venv\Scripts\python.exe"
$Backend  = Join-Path $RootDir "backend"
$LogFile  = Join-Path $RootDir "backend\logs\netguard.log"
$PidFile  = Join-Path $RootDir "backend\logs\netguard.pid"
$Port     = 8000

function Write-Status {
    param([string]$Color, [string]$Tag, [string]$Msg)
    Write-Host "[$Tag] $Msg" -ForegroundColor $Color
}

function Resolve-Python {
    # 1) venv python 동작 확인
    try {
        $null = & $VenvPy --version 2>&1
        if ($LASTEXITCODE -eq 0) { return $VenvPy }
    } catch {}

    # 2) 시스템 Python 탐색
    $candidates = @(
        "C:\Python313\python.exe", "C:\Python312\python.exe",
        "C:\Python311\python.exe", "C:\Python310\python.exe"
    )
    foreach ($u in @("Administrator","user",$env:USERNAME)) {
        $base = "C:\Users\$u\AppData\Local\Programs\Python"
        foreach ($v in @("Python313","Python312","Python311","Python310")) {
            $candidates += "$base\$v\python.exe"
        }
    }
    foreach ($p in ($candidates | Select-Object -Unique)) {
        if (-not (Test-Path $p)) { continue }
        try {
            $null = & $p --version 2>&1
            if ($LASTEXITCODE -ne 0) { continue }
            Write-Status Yellow "FIX   " "venv 경로 수정: $p"
            $cfg = Join-Path $RootDir "venv\pyvenv.cfg"
            if (Test-Path $cfg) {
                (Get-Content $cfg) -replace '^home\s*=.*', "home = $(Split-Path $p)" |
                    Set-Content $cfg -Encoding UTF8
            }
            return $VenvPy   # pyvenv.cfg 수정 후 venv python 재사용
        } catch {}
    }
    return $null
}

function Get-NetGuardProcess {
    Get-WmiObject Win32_Process | Where-Object {
        $_.Name -like "python*" -and $_.CommandLine -like "*uvicorn*app:app*"
    }
}

function Get-ServiceStatus {
    $procs = Get-NetGuardProcess
    $listening = netstat -an 2>$null | Select-String ":$Port\s.*LISTENING"
    return @{ Processes = $procs; Listening = [bool]$listening }
}

function Show-Status {
    $s = Get-ServiceStatus
    Write-Host ""
    Write-Host "=== NetGuard Service Status ===" -ForegroundColor Cyan
    if ($s.Processes) {
        foreach ($p in $s.Processes) {
            Write-Status Green "RUNNING" "PID $($p.ProcessId)  (started: $((Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue).StartTime))"
        }
    } else {
        Write-Status Yellow "STOPPED" "No running process found"
    }
    if ($s.Listening) {
        Write-Status Green "PORT   " "Listening on :$Port"
    } else {
        Write-Status Yellow "PORT   " "Not listening on :$Port"
    }
    Write-Host ""
}

function Start-NetGuard {
    $s = Get-ServiceStatus
    if ($s.Processes) {
        Write-Status Yellow "SKIP  " "Already running (PID $($s.Processes.ProcessId -join ', '))"
        return
    }

    $python = Resolve-Python
    if (-not $python) {
        Write-Status Red "ERROR " "Python을 찾을 수 없습니다. Python 3.10+ 설치 후 재시도하세요."
        exit 1
    }
    if (-not (Test-Path $Backend)) {
        Write-Status Red "ERROR " "Backend directory not found: $Backend"
        exit 1
    }

    New-Item -ItemType Directory -Path (Join-Path $Backend "logs") -Force | Out-Null

    Write-Status Cyan "START " "Launching NetGuard backend..."

    $proc = Start-Process -FilePath $python `
        -ArgumentList "-m uvicorn app:app --host 0.0.0.0 --port $Port" `
        -WorkingDirectory $Backend `
        -PassThru `
        -WindowStyle Normal
    $proc.Id | Out-File $PidFile -Encoding ascii

    Write-Status Cyan "WAIT  " "Waiting for port $Port to open..."
    $ready = $false
    for ($i = 0; $i -lt 15; $i++) {
        Start-Sleep -Seconds 1
        $test = Test-NetConnection -ComputerName 127.0.0.1 -Port $Port -WarningAction SilentlyContinue
        if ($test.TcpTestSucceeded) { $ready = $true; break }
    }

    if ($ready) {
        Write-Status Green "OK    " "NetGuard started (PID $($proc.Id))  http://0.0.0.0:$Port"
    } else {
        Write-Status Red "WARN  " "Process started but port $Port not responding yet. Check log:"
        Write-Host "       $LogFile"
    }
}

function Stop-NetGuard {
    $procs = Get-NetGuardProcess
    if (-not $procs) {
        Write-Status Yellow "SKIP  " "No running process found"
        return
    }
    foreach ($p in $procs) {
        try {
            Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop
            Write-Status Green "STOP  " "Killed PID $($p.ProcessId)"
        } catch {
            Write-Status Red "ERROR " "Failed to kill PID $($p.ProcessId): $_"
        }
    }
    if (Test-Path $PidFile) { Remove-Item $PidFile -Force }

    Start-Sleep -Seconds 2
    if (Get-NetGuardProcess) {
        Write-Status Red "WARN  " "Process still running after stop"
    } else {
        Write-Status Green "OK    " "NetGuard stopped"
    }
}

# ── Entry point ────────────────────────────────────────────────────────────────
switch ($Action) {
    "start"   { Start-NetGuard }
    "stop"    { Stop-NetGuard }
    "restart" { Stop-NetGuard; Start-Sleep -Seconds 1; Start-NetGuard }
    "status"  { Show-Status }
}
