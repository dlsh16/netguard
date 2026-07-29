#Requires -RunAsAdministrator
<#
.SYNOPSIS
    NetGuard SNMP Dashboard — Windows 자동 설치 스크립트

.DESCRIPTION
    Windows Server 2019/2022 또는 Windows 10/11 에서 NetGuard를 설치합니다.
    오프라인 환경을 지원하며, 사전에 수집한 패키지 파일들이 필요합니다.

    사전 조건:
      - PostgreSQL 17 가 이미 설치되어 있어야 합니다
        (postgresql-17.x-windows-x64.exe 실행 후 이 스크립트 실행)
      - C:\NetGuard_packages\pip_packages\ : Python wheel 파일
      - C:\NetGuard_packages\requirements.txt
      - nssm.exe 또는 nssm-2.24.zip (서비스 등록용)
      - timescaledb-postgresql-17_*.zip (TimescaleDB DLL)

.EXAMPLE
    # 관리자 PowerShell 에서 실행
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
    .\install_windows.ps1

.NOTES
    버전: 1.0.0 | 대상: Windows Server 2019/2022
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── 색상 출력 함수 ────────────────────────────────────────────────────────────
function Write-Step  { param($msg) Write-Host "`n[STEP] $msg" -ForegroundColor Cyan }
function Write-Ok    { param($msg) Write-Host "[OK]   $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Info  { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Gray }
function Write-Fail  { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red; exit 1 }

# ── 스크립트 경로 → 소스 루트 ─────────────────────────────────────────────────
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SourceDir = Split-Path -Parent $ScriptDir   # scripts/ 의 부모

# ── 배너 ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     NetGuard SNMP Dashboard — Windows 설치 마법사       ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ── 설치 전 입력값 수집 ───────────────────────────────────────────────────────
Write-Host "설치에 필요한 정보를 입력하세요. 기본값을 사용하려면 Enter를 누르세요." -ForegroundColor Yellow
Write-Host ""

function Prompt-Default {
    param($label, $default, [switch]$Secret)
    if ($Secret) {
        $input = Read-Host "$label [$('*' * $default.Length)]"
    } else {
        $input = Read-Host "$label [$default]"
    }
    if ([string]::IsNullOrWhiteSpace($input)) { return $default }
    return $input.Trim()
}

$InstallDir  = Prompt-Default "NetGuard 설치 경로  " "C:\SNMP\Claude"
$PgPass      = Prompt-Default "postgres 슈퍼유저 암호" "postgres"        -Secret
$DbPass      = Prompt-Default "NetGuard DB 비밀번호  " "NetGuard@2025!"  -Secret
$SnmpCom     = Prompt-Default "SNMP Community       " "public"
$SmtpHost    = Prompt-Default "SMTP 서버 주소       " "localhost"
$AlertEmail  = Prompt-Default "알림 이메일          " "admin@company.local"
$PkgDir      = Prompt-Default "pip 패키지 경로      " "C:\NetGuard_packages\pip_packages"
$NssmPath    = Prompt-Default "nssm.exe 경로        " "C:\Windows\System32\nssm.exe"
$TsdbZip     = Prompt-Default "TimescaleDB zip 경로 " ""

$PgBin    = "C:\Program Files\PostgreSQL\17\bin"
$PgData   = "C:\Program Files\PostgreSQL\17\data"
$PgLib    = "C:\Program Files\PostgreSQL\17\lib"
$PgShare  = "C:\Program Files\PostgreSQL\17\share\extension"

Write-Host ""
Write-Host "입력 요약:" -ForegroundColor Yellow
Write-Host "  설치 경로    : $InstallDir"
Write-Host "  DB 비밀번호  : ****"
Write-Host "  SNMP         : $SnmpCom"
Write-Host "  SMTP 서버    : $SmtpHost"
Write-Host "  알림 이메일  : $AlertEmail"
Write-Host "  pip 경로     : $PkgDir"
Write-Host ""
$confirm = Read-Host "위 정보로 설치를 시작합니까? (y/N)"
if ($confirm -ne 'y' -and $confirm -ne 'Y') {
    Write-Host "설치가 취소되었습니다."
    exit 0
}

# ── 2. PostgreSQL 17 PATH 설정 ─────────────────────────────────────────────────
Write-Step "PostgreSQL 17 환경 설정"

if (-not (Test-Path "$PgBin\psql.exe")) {
    Write-Fail "PostgreSQL 15를 찾을 수 없습니다 ($PgBin). postgresql-17.x-windows-x64.exe 를 먼저 설치하세요."
}

# PATH에 PostgreSQL bin 추가 (시스템 수준)
$syspath = [System.Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($syspath -notlike "*PostgreSQL\17\bin*") {
    [System.Environment]::SetEnvironmentVariable(
        "PATH", "$syspath;$PgBin",
        [System.EnvironmentVariableTarget]::Machine
    )
    $env:PATH = "$env:PATH;$PgBin"
    Write-Ok "PostgreSQL bin을 시스템 PATH에 추가했습니다."
} else {
    Write-Ok "PostgreSQL bin이 이미 PATH에 있습니다."
}

# PostgreSQL 서비스 자동 시작
$pgSvc = Get-Service -Name "postgresql-x64-17" -ErrorAction SilentlyContinue
if ($pgSvc) {
    Set-Service -Name "postgresql-x64-17" -StartupType Automatic
    if ($pgSvc.Status -ne 'Running') { Start-Service "postgresql-x64-17" }
    Write-Ok "PostgreSQL 서비스 실행 중 및 자동 시작 설정"
} else {
    Write-Warn "postgresql-x64-17 서비스를 찾을 수 없습니다."
}

# ── postgresql.conf 최적화 ────────────────────────────────────────────────────
Write-Step "PostgreSQL postgresql.conf 최적화"

$ram_gb  = [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 0)
$cpu     = (Get-WmiObject Win32_Processor | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
$maxConn = 100
$sb   = [math]::Min(8192, [math]::Round($ram_gb * 1024 * 0.25))
$ecs  = [math]::Round($ram_gb * 1024 * 0.75)
$wm   = [math]::Max(4, [math]::Floor($ram_gb * 1024 * 0.25 / $maxConn))
$mwm  = [math]::Min(2048, [math]::Round($ram_gb * 1024 * 0.05))
$mpw  = [math]::Max(2, [math]::Floor($cpu / 2))
$tsbg = [math]::Max(4, [math]::Min(16, $cpu))

Write-Info "RAM: ${ram_gb}GB, CPU: ${cpu}코어 → shared_buffers=${sb}MB, work_mem=${wm}MB"

$pgconf = "$PgData\postgresql.conf"
if (Test-Path $pgconf) {
    $content = Get-Content $pgconf -Raw

    function Set-PgParam {
        param($conf, $key, $val)
        if ($conf -match "(?m)^#?$key\s*=") {
            return $conf -replace "(?m)^#?$key\s*=.*", "$key = $val"
        } else {
            return $conf + "`n$key = $val"
        }
    }

    $content = Set-PgParam $content "listen_addresses"             "'localhost'"
    $content = Set-PgParam $content "max_connections"              $maxConn
    $content = Set-PgParam $content "shared_buffers"               "${sb}MB"
    $content = Set-PgParam $content "effective_cache_size"         "${ecs}MB"
    $content = Set-PgParam $content "work_mem"                     "${wm}MB"
    $content = Set-PgParam $content "maintenance_work_mem"         "${mwm}MB"
    $content = Set-PgParam $content "wal_buffers"                  "64MB"
    $content = Set-PgParam $content "min_wal_size"                 "512MB"
    $content = Set-PgParam $content "max_wal_size"                 "4GB"
    $content = Set-PgParam $content "checkpoint_completion_target" "0.9"
    $content = Set-PgParam $content "max_worker_processes"         "8"
    $content = Set-PgParam $content "max_parallel_workers"         $mpw
    $content = Set-PgParam $content "random_page_cost"             "1.1"
    $content = Set-PgParam $content "effective_io_concurrency"     "200"
    $content = Set-PgParam $content "logging_collector"            "on"
    $content = Set-PgParam $content "log_filename"                 "'postgresql-%Y-%m-%d.log'"
    $content = Set-PgParam $content "log_rotation_age"             "1d"
    $content = Set-PgParam $content "log_min_duration_statement"   "1000"

    # TimescaleDB 설정 추가
    if ($content -notmatch "timescaledb.telemetry_level") {
        $tsdb_block = @"

# TimescaleDB
shared_preload_libraries = 'timescaledb'
timescaledb.max_background_workers = $tsbg
timescaledb.telemetry_level = off
timescaledb.max_cached_chunks_per_hypertable = 10
timescaledb.enable_chunk_skipping = on
"@
        $content += $tsdb_block
    }

    $content | Set-Content $pgconf -Encoding utf8
    Write-Ok "postgresql.conf 최적화 완료"
} else {
    Write-Warn "postgresql.conf를 찾을 수 없습니다: $pgconf"
}

# pg_hba.conf 확인
$hbaconf = "$PgData\pg_hba.conf"
if (Test-Path $hbaconf) {
    $hba = Get-Content $hbaconf -Raw
    if ($hba -notmatch "netguard.*md5") {
        $hba += "`nhost    all    netguard    127.0.0.1/32    md5"
        $hba += "`nhost    all    netguard    ::1/128         md5"
        $hba | Set-Content $hbaconf -Encoding utf8
        Write-Ok "pg_hba.conf에 netguard 항목 추가"
    } else {
        Write-Ok "pg_hba.conf에 netguard 항목이 이미 있습니다."
    }
}

# ── 3. TimescaleDB 설치 ───────────────────────────────────────────────────────
Write-Step "TimescaleDB DLL 설치"

if ($TsdbZip -and (Test-Path $TsdbZip)) {
    $tempDir = "C:\timescaledb_temp_$(Get-Random)"
    Expand-Archive -Path $TsdbZip -DestinationPath $tempDir -Force

    # DLL 복사
    Get-ChildItem "$tempDir" -Filter "timescaledb*.dll" -Recurse | ForEach-Object {
        Copy-Item $_.FullName -Destination $PgLib -Force
        Write-Info "복사: $($_.Name) → $PgLib"
    }
    Get-ChildItem "$tempDir" -Filter "timescaledb.control" -Recurse | ForEach-Object {
        Copy-Item $_.FullName -Destination $PgShare -Force
    }
    Get-ChildItem "$tempDir" -Filter "timescaledb--*.sql" -Recurse | ForEach-Object {
        Copy-Item $_.FullName -Destination $PgShare -Force
    }

    Remove-Item -Recurse -Force $tempDir
    Write-Ok "TimescaleDB DLL 복사 완료"
} else {
    Write-Warn "TimescaleDB zip 경로가 지정되지 않았거나 파일이 없습니다. DLL 복사를 건너뜁니다."
    Write-Info "수동 설치: timescaledb-postgresql-17_*.zip 의 dll/control/sql 파일을 $PgLib, $PgShare 에 복사하세요."
}

# PostgreSQL 재시작 (TimescaleDB 적용)
Restart-Service "postgresql-x64-17" -ErrorAction SilentlyContinue
Start-Sleep 3
Write-Ok "PostgreSQL 재시작 완료"

# ── 4. Python 가상환경 생성 ───────────────────────────────────────────────────
Write-Step "Python 가상환경 생성 및 패키지 설치"

# Python 확인
$pythonCmd = $null
foreach ($p in @("python", "python3", "python3.11", "C:\Python311\python.exe")) {
    if (Get-Command $p -ErrorAction SilentlyContinue) { $pythonCmd = $p; break }
}
if (-not $pythonCmd) { Write-Fail "Python을 찾을 수 없습니다. python-3.11.x-amd64.exe 를 먼저 설치하세요." }
Write-Info "Python: $pythonCmd ($( & $pythonCmd --version 2>&1))"

# 가상환경
$venvDir = "$InstallDir\venv"
if (-not (Test-Path "$venvDir\Scripts\python.exe")) {
    & $pythonCmd -m venv $venvDir
    Write-Ok "가상환경 생성: $venvDir"
} else {
    Write-Ok "가상환경이 이미 존재합니다."
}

$venvPip = "$venvDir\Scripts\pip.exe"

# pip 패키지 오프라인 설치
$reqFile = "$InstallDir\requirements.txt"
if (-not (Test-Path $reqFile)) { $reqFile = "$SourceDir\requirements.txt" }
if (-not (Test-Path $reqFile)) { $reqFile = "C:\NetGuard_packages\requirements.txt" }

if ((Test-Path $PkgDir) -and (Test-Path $reqFile)) {
    & $venvPip install `
        --no-index `
        --find-links $PkgDir `
        -r $reqFile `
        --quiet
    Write-Ok "Python 패키지 오프라인 설치 완료"
} else {
    Write-Warn "패키지 경로($PkgDir) 또는 requirements.txt($reqFile)를 찾을 수 없습니다."
    Write-Info "나중에 수동 실행: $venvPip install --no-index --find-links <경로> -r requirements.txt"
}

# ── 5. 애플리케이션 디렉토리 구성 ─────────────────────────────────────────────
Write-Step "애플리케이션 디렉토리 구성"

New-Item -ItemType Directory -Path "$InstallDir\logs"       -Force | Out-Null
New-Item -ItemType Directory -Path "$InstallDir\data\nvd_cache" -Force | Out-Null
New-Item -ItemType Directory -Path "$InstallDir\config"     -Force | Out-Null

# 소스 파일이 아직 설치 경로에 없으면 복사
if (-not (Test-Path "$InstallDir\backend\app.py")) {
    if (Test-Path "$SourceDir\backend\app.py") {
        Copy-Item -Recurse "$SourceDir\*" "$InstallDir\" -Force -ErrorAction SilentlyContinue
        Write-Ok "소스 파일 복사: $SourceDir → $InstallDir"
    } else {
        Write-Warn "소스 파일을 찾을 수 없습니다. $InstallDir 에 수동으로 배포하세요."
    }
} else {
    Write-Ok "소스 파일이 이미 $InstallDir 에 있습니다."
}

Write-Ok "디렉토리 구성 완료"

# ── 6. 데이터베이스 초기화 ────────────────────────────────────────────────────
Write-Step "데이터베이스 초기화"

$env:PGPASSWORD = $PgPass
$psql = "$PgBin\psql.exe"

# DB 사용자 생성
& $psql -U postgres -h localhost -c @"
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'netguard') THEN
        CREATE USER netguard WITH PASSWORD '$DbPass';
    ELSE
        ALTER USER netguard WITH PASSWORD '$DbPass';
    END IF;
END
\$\$;
"@ 2>&1 | Out-Null

# DB 생성
$dbExists = & $psql -U postgres -h localhost -tAc "SELECT 1 FROM pg_database WHERE datname='netguard'"
if ($dbExists -ne '1') {
    & $psql -U postgres -h localhost -c "CREATE DATABASE netguard OWNER netguard;"
    Write-Ok "netguard 데이터베이스 생성"
} else {
    Write-Ok "netguard 데이터베이스가 이미 존재합니다."
}

& $psql -U postgres -h localhost -d netguard -c "GRANT ALL PRIVILEGES ON DATABASE netguard TO netguard;"
& $psql -U postgres -h localhost -d netguard -c "CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;" 2>&1 | Out-Null
& $psql -U postgres -h localhost -d netguard -c "GRANT ALL ON SCHEMA public TO netguard;"

Write-Ok "DB 사용자 및 권한 설정 완료"

# NetGuard 스키마 초기화
$setupScript = "$InstallDir\scripts\setup_db.py"
if (Test-Path $setupScript) {
    $env:NETGUARD_DB_PASSWORD = $DbPass
    & "$venvDir\Scripts\python.exe" $setupScript
    Write-Ok "NetGuard 스키마 초기화 완료"
} else {
    Write-Warn "setup_db.py를 찾을 수 없습니다. 서비스 첫 기동 시 자동으로 스키마가 생성됩니다."
}

$env:PGPASSWORD = ""

# ── 7. 설정 파일 작성 ─────────────────────────────────────────────────────────
Write-Step "설정 파일 작성"

$configFile = "$InstallDir\config\config.yaml"

if ((Test-Path $configFile) -and (Select-String -Path $configFile -Pattern "db_password:" -Quiet)) {
    Write-Warn "config.yaml이 이미 존재합니다. 덮어쓰지 않습니다."
    Write-Info "수정하려면: notepad $configFile"
} else {
    $configContent = @"
# ===== Database =====
db_host: localhost
db_port: 5432
db_user: netguard
db_password: "$DbPass"

# ===== SNMP =====
snmp_community: $SnmpCom
snmp_timeout: 5
snmp_retries: 2
snmp_poll_interval: 60

# ===== 이메일 알림 =====
smtp_host: $SmtpHost
smtp_port: 25
smtp_from: noreply@company.local
alert_emails:
  - $AlertEmail

# ===== 카카오톡 (오프라인 환경 false 유지) =====
kakao_enabled: false

# ===== 라즈베리파이 (연결 시 true 로 변경) =====
rpi_enabled: false
rpi_ip: 192.168.1.60
rpi_port: 8765

# ===== 임계값 =====
cpu_warn: 80.0
cpu_crit: 95.0
mem_warn: 75.0
mem_crit: 90.0
disk_warn: 80.0
disk_crit: 90.0
temp_warn: 27.0
temp_crit: 32.0
humi_warn_high: 60.0
humi_warn_low:  40.0
ups_batt_warn: 30.0
ups_batt_crit: 15.0
"@
    $configContent | Out-File -FilePath $configFile -Encoding utf8
    Write-Ok "config.yaml 작성 완료: $configFile"
}

# ── 8. NSSM Windows 서비스 등록 ───────────────────────────────────────────────
Write-Step "Windows 서비스 등록 (NSSM)"

# NSSM 찾기
if (-not (Test-Path $NssmPath)) {
    # 대안 경로들 시도
    foreach ($p in @("nssm.exe", ".\nssm.exe", "C:\nssm\nssm-2.24\win64\nssm.exe")) {
        if (Get-Command $p -ErrorAction SilentlyContinue) { $NssmPath = $p; break }
        if (Test-Path $p) { $NssmPath = $p; break }
    }
}

if (Test-Path $NssmPath) {
    # 기존 서비스 제거 후 재등록
    $existingSvc = Get-Service -Name "NetGuard" -ErrorAction SilentlyContinue
    if ($existingSvc) {
        Stop-Service "NetGuard" -Force -ErrorAction SilentlyContinue
        & $NssmPath remove NetGuard confirm 2>&1 | Out-Null
        Start-Sleep 2
        Write-Info "기존 NetGuard 서비스 제거됨"
    }

    & $NssmPath install NetGuard "$venvDir\Scripts\python.exe"
    & $NssmPath set NetGuard AppParameters "-m uvicorn app:app --host 0.0.0.0 --port 8000 --workers 2"
    & $NssmPath set NetGuard AppDirectory "$InstallDir\backend"
    & $NssmPath set NetGuard AppEnvironmentExtra "PYTHONPATH=$InstallDir\backend"
    & $NssmPath set NetGuard AppStdout "$InstallDir\logs\service_stdout.log"
    & $NssmPath set NetGuard AppStderr "$InstallDir\logs\service_stderr.log"
    & $NssmPath set NetGuard AppRotateFiles 1
    & $NssmPath set NetGuard AppRotateSeconds 86400
    & $NssmPath set NetGuard AppRestartDelay 5000
    & $NssmPath set NetGuard Start SERVICE_AUTO_START
    & $NssmPath set NetGuard DisplayName "NetGuard SNMP Dashboard"
    & $NssmPath set NetGuard Description "SNMP 통합 모니터링 대시보드 서비스"

    Write-Ok "NSSM 서비스 등록 완료"
} else {
    Write-Warn "nssm.exe를 찾을 수 없습니다. Windows 서비스 등록을 건너뜁니다."
    Write-Info "NSSM 다운로드 후 다음 명령어를 실행하세요:"
    Write-Info "  nssm install NetGuard $venvDir\Scripts\python.exe"
    Write-Info "  nssm set NetGuard AppParameters ""-m uvicorn app:app --host 0.0.0.0 --port 8000 --workers 2"""
    Write-Info "  nssm set NetGuard AppDirectory $InstallDir\backend"
}

# ── 9. 방화벽 규칙 설정 ───────────────────────────────────────────────────────
Write-Step "Windows 방화벽 규칙 설정"

$fwRule = Get-NetFirewallRule -DisplayName "NetGuard Dashboard" -ErrorAction SilentlyContinue
if (-not $fwRule) {
    New-NetFirewallRule -DisplayName "NetGuard Dashboard" `
        -Direction Inbound -Protocol TCP -LocalPort 8000 `
        -Action Allow -Profile Any | Out-Null
    Write-Ok "방화벽 규칙 추가: 8000/TCP 인바운드 허용"
} else {
    Write-Ok "방화벽 규칙이 이미 존재합니다."
}

$trapRule = Get-NetFirewallRule -DisplayName "SNMP Trap" -ErrorAction SilentlyContinue
if (-not $trapRule) {
    New-NetFirewallRule -DisplayName "SNMP Trap" `
        -Direction Inbound -Protocol UDP -LocalPort 162 `
        -Action Allow -Profile Any | Out-Null
    Write-Ok "방화벽 규칙 추가: 162/UDP (SNMP Trap)"
}

# ── 10. 자동 백업 스케줄 등록 ─────────────────────────────────────────────────
Write-Step "자동 백업 스케줄 등록 (매일 새벽 2시)"

$backupScript = "$InstallDir\scripts\backup.ps1"
$backupContent = @"
# NetGuard 자동 백업 스크립트
`$date = Get-Date -Format "yyyyMMdd"
`$dest = "E:\Backup\netguard"
New-Item -ItemType Directory -Path `$dest -Force | Out-Null

`$env:PGPASSWORD = "$DbPass"
& "C:\Program Files\PostgreSQL\17\bin\pg_dump.exe" ``
    -U netguard -h localhost -d netguard -Fc -Z 9 ``
    -f "`$dest\netguard_`$date.dump"
`$env:PGPASSWORD = ""

# 설정 파일 백업
Copy-Item "$InstallDir\config\config.yaml" "`$dest\config_`$date.yaml" -Force

# 30일 이상 된 백업 삭제
Get-ChildItem `$dest -Filter "*.dump" | Where-Object { `$_.LastWriteTime -lt (Get-Date).AddDays(-30) } | Remove-Item -Force
Get-ChildItem `$dest -Filter "*.yaml" | Where-Object { `$_.LastWriteTime -lt (Get-Date).AddDays(-30) } | Remove-Item -Force

Write-Host "`$(Get-Date) 백업 완료: netguard_`$date.dump"
"@
$backupContent | Out-File -FilePath $backupScript -Encoding utf8

$taskExists = Get-ScheduledTask -TaskName "NetGuard_Backup" -ErrorAction SilentlyContinue
if (-not $taskExists) {
    $action  = New-ScheduledTaskAction -Execute "powershell.exe" `
                   -Argument "-NonInteractive -File `"$backupScript`""
    $trigger = New-ScheduledTaskTrigger -Daily -At 2:00AM
    Register-ScheduledTask -TaskName "NetGuard_Backup" `
        -Action $action -Trigger $trigger -RunLevel Highest | Out-Null
    Write-Ok "백업 작업 스케줄 등록 완료 (매일 02:00)"
} else {
    Write-Ok "백업 스케줄이 이미 등록되어 있습니다."
}

# ── 서비스 시작 ───────────────────────────────────────────────────────────────
Write-Step "NetGuard 서비스 시작"

$svc = Get-Service -Name "NetGuard" -ErrorAction SilentlyContinue
if ($svc) {
    Start-Service "NetGuard" -ErrorAction SilentlyContinue
    Start-Sleep 4
    $svc.Refresh()
    if ($svc.Status -eq 'Running') {
        Write-Ok "NetGuard 서비스 시작 성공!"
    } else {
        Write-Warn "서비스 시작 실패. 로그를 확인하세요:"
        Write-Host "  Get-Content '$InstallDir\logs\service_stderr.log' -Tail 30"
    }
} else {
    Write-Warn "NetGuard 서비스가 등록되지 않았습니다. NSSM 설치 후 수동 등록이 필요합니다."
}

# ── 완료 요약 ─────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║            NetGuard 설치가 완료되었습니다!               ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""

$localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch "Loopback" } | Select-Object -First 1).IPAddress
Write-Host "  대시보드 URL  : " -NoNewline; Write-Host "http://${localIP}:8000" -ForegroundColor Cyan
Write-Host "  초기 계정     : admin / admin1234!"
Write-Host "  설정 파일     : $configFile"
Write-Host "  로그 파일     : $InstallDir\logs\netguard.log"
Write-Host ""
Write-Host "서비스 관리 명령어:" -ForegroundColor Yellow
Write-Host "  Start-Service NetGuard"
Write-Host "  Stop-Service NetGuard"
Write-Host "  Restart-Service NetGuard"
Write-Host "  Get-Content '$InstallDir\logs\service_stderr.log' -Tail 50"
Write-Host ""
Write-Host "다음 단계:" -ForegroundColor Yellow
Write-Host "  1. 브라우저에서 대시보드 접속 및 비밀번호 변경"
Write-Host "  2. 대시보드 → 장비 관리 → SNMP 장비 등록"
Write-Host "  3. NVD CVE 캐시 복사: $InstallDir\data\nvd_cache\"
Write-Host "  4. config.yaml 이메일/SMTP 설정 확인"
Write-Host ""

