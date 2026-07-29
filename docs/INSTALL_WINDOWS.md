# NetGuard SNMP Dashboard
# Windows 설치 및 운영 메뉴얼

> 대상 OS: Windows Server 2019 / 2022, Windows 10/11 (테스트)
> 작성일: 2026-05-08 | 최종 수정: 2026-05-11 | 버전: 1.2.0

> **v1.2.0 변경 사항 (2026-05-11 시뮬레이션 테스트 반영)**
> - PostgreSQL 17 기준으로 업데이트 (18 → 17)
> - `pyasn1==0.5.1` 버전 고정 필수 (0.6.x는 pysnmp 6.2.5와 호환 안 됨)
> - `database.py` TimescaleDB 미설치 환경 graceful 처리 (일반 PostgreSQL로 동작)
> - `backend/logs/` 디렉터리 사전 생성 필요

---

## 목차

1. [사전 준비 및 오프라인 패키지 수집](#1-사전-준비-및-오프라인-패키지-수집)
2. [PostgreSQL 17 설치](#2-postgresql-17-설치)
3. [TimescaleDB 확장 설치](#3-timescaledb-확장-설치)
4. [Python 3.11 설치](#4-python-313-설치)
5. [NetGuard 애플리케이션 설치](#5-netguard-애플리케이션-설치)
6. [데이터베이스 초기화](#6-데이터베이스-초기화)
7. [설정 파일 구성](#7-설정-파일-구성)
8. [Windows 서비스 등록 (NSSM)](#8-windows-서비스-등록-nssm)
9. [Windows 방화벽 설정](#9-windows-방화벽-설정)
10. [SNMP 장비 등록](#10-snmp-장비-등록)
11. [CVE 취약점 DB 오프라인 구성](#11-cve-취약점-db-오프라인-구성)
12. [라즈베리파이 센서 연동](#12-라즈베리파이-센서-연동)
13. [알림 설정 (이메일 / 카카오톡)](#13-알림-설정)
14. [운영 및 관리](#14-운영-및-관리)
15. [백업 및 복구](#15-백업-및-복구)
16. [업데이트 절차](#16-업데이트-절차)
17. [문제 해결](#17-문제-해결)

---

## 빠른 설치 (스크립트 사용)

> 아래 스크립트로 2.2~9절 설치 과정을 자동화할 수 있습니다.
> PostgreSQL, Python, NSSM 설치 파일(exe/zip)은 수동 설치가 필요합니다.

### 1단계: 인터넷 환경 PC에서 패키지 수집

```powershell
# 관리자 PowerShell에서 실행
.\scripts\collect_packages_windows.ps1
# 완료 후: C:\NetGuard_packages\ 폴더를 USB에 복사
```

### 2단계: 수동 설치 파일 준비 (USB에 복사)

| 파일 | 다운로드 위치 |
|------|-------------|
| `postgresql-17.x-windows-x64.exe` | postgresql.org/download/windows |
| `timescaledb-postgresql-17_*.zip` | packagecloud.io/timescale |
| `python-3.11.x-amd64.exe` | python.org/downloads |
| `nssm-2.24.zip` | nssm.cc/download |

### 3단계: 오프라인 서버에서 수동 설치 파일 먼저 설치

```
1. postgresql-17.x-windows-x64.exe  실행 → 섹션 2 참고
2. python-3.11.x-amd64.exe  실행     → 섹션 4 참고 (C:\Python311 경로 권장)
3. nssm-2.24.zip  압축 해제          → C:\Windows\System32\nssm.exe 복사
```

### 4단계: 자동 설치 스크립트 실행

```powershell
# 관리자 PowerShell에서 실행
.\scripts\install_windows.ps1
# 대화형 프롬프트: 설치 경로·DB 암호·SNMP Community 등 입력
# 설치 완료 → http://서버IP:8000 접속
```

> **TimescaleDB PG18 호환성 참고**
> TimescaleDB의 PostgreSQL 17 공식 지원 여부는 [docs.timescale.com](https://docs.timescale.com) 에서 확인하세요.
> 미지원 시 TimescaleDB DLL이 없어도 PostgreSQL 기본 테이블로 설치됩니다.

---

## 1. 사전 준비 및 오프라인 패키지 수집

### 1.1 오프라인 설치를 위한 패키지 수집 (인터넷 환경 PC)

> 인터넷이 되는 별도 PC(동일 OS 버전 권장)에서 아래 작업을 수행합니다.

#### 수집 목록
| 패키지 | 다운로드 위치 | 파일명 |
|--------|-------------|--------|
| PostgreSQL 17 | postgresql.org/download/windows | postgresql-17.x-windows-x64.exe |
| TimescaleDB | packagecloud.io/timescale/timescaledb | timescaledb-postgresql-17_x.x.x_windows-amd64.zip |
| Python 3.11 | python.org/downloads | python-3.11.x-amd64.exe |
| NSSM | nssm.cc/download | nssm-2.24.zip |
| Git (선택) | git-scm.com | Git-x.x.x-64-bit.exe |

#### Python 패키지 오프라인 수집

```powershell
# 인터넷 환경 PC에서 실행

# 1. 디렉토리 생성
New-Item -ItemType Directory -Path "C:\NetGuard_packages\pip_packages" -Force

# 2. NetGuard 소스의 requirements.txt 복사 (소스가 C:\SNMP\Claude 에 있을 경우)
Copy-Item "C:\SNMP\Claude\requirements.txt" "C:\NetGuard_packages\requirements.txt"
# 다른 경로에 있을 경우: Copy-Item "<소스경로>\requirements.txt" "C:\NetGuard_packages\requirements.txt"

# 3. 패키지 다운로드
pip download -r "C:\NetGuard_packages\requirements.txt" `
    -d "C:\NetGuard_packages\pip_packages" `
    --platform win_amd64 `
    --python-version 311 `
    --only-binary=:all:

# 4. 수집된 패키지 확인 (62개 내외)
Get-ChildItem "C:\NetGuard_packages\pip_packages" | Measure-Object | Select-Object Count
```

#### 수집 결과물을 USB/내부 공유에 복사

> **현재 PC 기준 수집 위치**: `C:\NetGuard_packages\`
> 이 폴더를 USB나 내부 파일 서버로 복사한 뒤 오프라인 서버에서 사용합니다.

```
C:\NetGuard_packages\                  ← 이 폴더 전체를 복사
├── requirements.txt
├── requirements_freeze.txt            ← 의존성 포함 전체 버전 고정 목록
├── pip_packages\                      ← pip wheel 파일 62개 (14 MB)
│   ├── fastapi-0.111.0-py3-none-any.whl
│   ├── uvicorn-0.29.0-py3-none-any.whl
│   └── ... (62개)
└── (설치 실행 파일은 별도 수집)
    ├── postgresql-17.x-windows-x64.exe
    ├── timescaledb-postgresql-17_x.x.x_windows-amd64.zip
    ├── python-3.11.x-amd64.exe
    └── nssm-2.24.zip
```

---

## 2. PostgreSQL 17 설치

### 2.1 설치 프로그램 실행

```
postgresql-17.x-windows-x64.exe 더블클릭
```

설치 옵션:
| 항목 | 설정값 |
|------|--------|
| 설치 경로 | `C:\Program Files\PostgreSQL\17` |
| 데이터 경로 | `C:\Program Files\PostgreSQL\17\data` |
| 포트 | `5432` (기본값) |
| superuser | `postgres` |
| 암호 | **강력한 암호 설정 (기록해 둘 것)** |
| Locale | `Korean, Korea` 또는 `C` |

> StackBuilder 화면에서 "건너뛰기(Skip)" 선택 — 오프라인이므로 불필요

### 2.2 환경 변수 등록

```powershell
# 관리자 PowerShell
[System.Environment]::SetEnvironmentVariable(
    "PATH",
    $env:PATH + ";C:\Program Files\PostgreSQL\17\bin",
    [System.EnvironmentVariableTarget]::Machine
)

# 적용 확인 (새 PowerShell 창에서)
psql --version
# 출력 예: psql (PostgreSQL) 18.x
```

### 2.3 PostgreSQL 서비스 확인

```powershell
Get-Service -Name "postgresql-x64-17"
# Status: Running 확인

# 서비스 자동 시작 설정
Set-Service -Name "postgresql-x64-17" -StartupType Automatic
```

### 2.4 postgresql.conf 수정

서버 RAM에 따라 아래 PowerShell 스크립트로 권장값을 자동 계산할 수 있습니다.

```powershell
# RAM / CPU 기반 권장값 자동 계산 (참고용 출력)
$ram_gb   = [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 0)
$cpu      = (Get-WmiObject Win32_Processor).NumberOfLogicalProcessors
$max_conn = 100

$sb   = [math]::Min(8192, [math]::Round($ram_gb * 1024 * 0.25))   # 최대 8GB
$ecs  = [math]::Round($ram_gb * 1024 * 0.75)
$wm   = [math]::Max(4,   [math]::Floor($ram_gb * 1024 * 0.25 / $max_conn))
$mwm  = [math]::Min(2048,[math]::Round($ram_gb * 1024 * 0.05))
$mpw  = [math]::Max(2,   [math]::Floor($cpu / 2))
$tsbg = [math]::Max(4,   [math]::Min(16, $cpu))

Write-Host "shared_buffers          = ${sb}MB"
Write-Host "effective_cache_size    = ${ecs}MB"
Write-Host "work_mem                = ${wm}MB"
Write-Host "maintenance_work_mem    = ${mwm}MB"
Write-Host "max_parallel_workers    = $mpw"
Write-Host "timescaledb.max_background_workers = $tsbg"
```

계산된 값을 참고하여 아래 설정을 적용합니다.

```powershell
notepad "C:\Program Files\PostgreSQL\17\data\postgresql.conf"
```

```ini
# =============================================
# 연결
# =============================================
listen_addresses = 'localhost'        # 외부 접근 필요 시 '*'
max_connections = 100
superuser_reserved_connections = 3

# =============================================
# 메모리  (RAM 32GB 기준 예시 — 위 스크립트로 계산)
# =============================================
shared_buffers = 8GB                  # RAM × 0.25, 최대 8GB
effective_cache_size = 24GB           # RAM × 0.75
work_mem = 81MB                       # (shared_buffers / max_connections)
maintenance_work_mem = 1GB            # VACUUM·CREATE INDEX 전용, 최대 2GB
temp_file_limit = 10GB                # 임시 파일 상한 (무한 디스크 사용 방지)

# =============================================
# WAL / 체크포인트
# =============================================
wal_buffers = 64MB                    # 보통 shared_buffers × 0.03 또는 64MB
min_wal_size = 512MB
max_wal_size = 4GB
checkpoint_completion_target = 0.9
checkpoint_timeout = 10min

# =============================================
# 병렬 처리
# =============================================
max_worker_processes = 8              # CPU 논리 코어 수 이상
max_parallel_workers_per_gather = 2   # 단일 쿼리 병렬 워커
max_parallel_workers = 4              # 전체 병렬 워커 (CPU 코어 수 / 2)
max_parallel_maintenance_workers = 2  # CREATE INDEX 병렬 워커

# =============================================
# 쿼리 플래너
# =============================================
default_statistics_target = 100
random_page_cost = 1.1                # SSD: 1.1 / HDD: 4.0
effective_io_concurrency = 200        # SSD: 200 / HDD: 2
jit = on

# =============================================
# 로그
# =============================================
log_destination = 'stderr'
logging_collector = on
log_directory = 'log'
log_filename = 'postgresql-%Y-%m-%d.log'
log_rotation_age = 1d
log_rotation_size = 100MB
log_min_duration_statement = 1000     # 1초 이상 쿼리 기록
log_checkpoints = on
log_connections = off
log_lock_waits = on
log_temp_files = 0
log_line_prefix = '%t [%p] %u@%d '
```

```powershell
Restart-Service -Name "postgresql-x64-17"
```

---

## 3. TimescaleDB 확장 설치

### 3.1 파일 압축 해제 및 복사

```powershell
# timescaledb-postgresql-17_x.x.x_windows-amd64.zip 압축 해제
Expand-Archive -Path "timescaledb-postgresql-17_x.x.x_windows-amd64.zip" `
               -DestinationPath "C:\timescaledb_temp"

# DLL 파일 복사
Copy-Item "C:\timescaledb_temp\timescaledb-tsl-*.dll" `
          "C:\Program Files\PostgreSQL\17\lib\"
Copy-Item "C:\timescaledb_temp\timescaledb.dll" `
          "C:\Program Files\PostgreSQL\17\lib\"
Copy-Item "C:\timescaledb_temp\timescaledb.control" `
          "C:\Program Files\PostgreSQL\17\share\extension\"
Copy-Item "C:\timescaledb_temp\timescaledb--*.sql" `
          "C:\Program Files\PostgreSQL\17\share\extension\"
```

### 3.2 postgresql.conf에 TimescaleDB 설정 추가

2.4에서 이미 편집한 `postgresql.conf`에 아래 내용을 **추가**합니다.

```powershell
notepad "C:\Program Files\PostgreSQL\17\data\postgresql.conf"
```

```ini
# =============================================
# TimescaleDB 로드 (반드시 첫 번째 라이브러리로)
# =============================================
shared_preload_libraries = 'timescaledb'

# =============================================
# TimescaleDB 전용 설정
# (timescaledb-tune Windows 미지원 → 수동 적용)
# =============================================

# 백그라운드 워커 수 — CPU 코어 수와 동일하게 설정 (최소 4, 최대 16)
# 청크 압축·보존정책·연속집계(Continuous Aggregates) 실행에 사용됨
timescaledb.max_background_workers = 8

# 텔레메트리 비활성화 (오프라인 환경 필수 — 외부 접속 시도 차단)
timescaledb.telemetry_level = off

# 청크 캐시 크기 — shared_buffers의 약 10% 권장
# 자주 접근하는 최신 청크를 메모리에 유지
timescaledb.max_cached_chunks_per_hypertable = 10

# 병렬 청크 스캔 허용 (PostgreSQL 병렬 설정과 연동)
timescaledb.enable_chunk_skipping = on
```

> **설정 항목 설명**
>
> | 항목 | 역할 | 오프라인 환경 주의 |
> |------|------|-----------------|
> | `shared_preload_libraries` | TimescaleDB DLL을 PostgreSQL 시작 시 로드 | 없으면 Extension 자체가 동작 안 함 |
> | `max_background_workers` | 압축·보존정책·연속집계 실행 워커 수 | CPU 코어 수와 `max_worker_processes`를 초과하면 안 됨 |
> | `telemetry_level = off` | Timescale 서버로 사용 통계 전송 차단 | **오프라인 환경 필수** — off 하지 않으면 접속 시도로 지연 발생 |
> | `max_cached_chunks_per_hypertable` | 핫 청크 메모리 캐시 | 값이 클수록 메모리 소비 증가 |
> | `enable_chunk_skipping` | WHERE 절로 불필요한 청크 스킵 | 시계열 쿼리 성능 향상 |

```powershell
Restart-Service -Name "postgresql-x64-17"

# 재시작 확인
Get-Service "postgresql-x64-17" | Select-Object Status, DisplayName
```

### 3.3 TimescaleDB 확장 활성화 확인

```powershell
psql -U postgres -c "CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;"
psql -U postgres -c "SELECT extname, extversion FROM pg_extension WHERE extname='timescaledb';"
# timescaledb | 2.x.x 출력 확인
```

---

## 4. Python 3.11 설치

### 4.1 설치 실행

```
python-3.11.x-amd64.exe 더블클릭
```

설치 옵션:
- ✅ `Add Python 3.11 to PATH` 체크
- `Customize installation` 선택
- ✅ pip, py launcher, for all users 모두 체크
- 설치 경로: `C:\Python311`

### 4.2 설치 확인

```powershell
python --version    # Python 3.11.x
pip --version       # pip xx.x from C:\Python311\...
```

---

## 5. NetGuard 애플리케이션 설치

### 5.1 애플리케이션 파일 배치

```powershell
# 설치 경로 생성
New-Item -ItemType Directory -Path "C:\SNMP\Claude" -Force

# USB 또는 파일 서버에서 zip 복사 후 압축 해제
# zip 파일 위치 예시: D:\배포\NetGuard_v1.0.0.zip
Expand-Archive -Path "D:\배포\NetGuard_v1.0.0.zip" -DestinationPath "C:\SNMP\Claude"

# 현재 PC에서 이미 C:\SNMP\Claude 에 파일이 있다면 이 단계 생략
# 디렉토리 확인
Get-ChildItem "C:\SNMP\Claude"
```

### 5.2 Python 가상환경 생성

```powershell
cd C:\SNMP\Claude

# 가상환경 생성
python -m venv venv

# 활성화
.\venv\Scripts\Activate.ps1

# 실행 정책 오류 시
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### 5.3 패키지 오프라인 설치

> USB 또는 파일 서버에서 복사한 `C:\NetGuard_packages\` 폴더가 있어야 합니다.
> 경로가 다를 경우 `--find-links` 뒤의 경로만 실제 경로로 바꾸면 됩니다.

```powershell
# 가상환경 활성화 상태에서 실행
# (.\venv\Scripts\Activate.ps1 으로 먼저 활성화)

pip install `
    --no-index `
    --find-links "C:\NetGuard_packages\pip_packages" `
    -r "C:\NetGuard_packages\requirements.txt"

# 설치 확인 — 아래 패키지들이 모두 보이면 성공
pip list | Select-String "fastapi|asyncpg|pysnmp|uvicorn"
```

### 5.4 디렉토리 구조 확인

```powershell
New-Item -ItemType Directory -Path "C:\SNMP\Claude\logs" -Force
New-Item -ItemType Directory -Path "C:\SNMP\Claude\data\nvd_cache" -Force

Get-ChildItem "C:\SNMP\Claude" -Recurse -Directory
```

---

## 6. 데이터베이스 초기화

### 6.1 NetGuard 전용 DB 사용자 및 DB 생성

```powershell
# postgres 계정으로 접속
psql -U postgres
```

psql 프롬프트에서:
```sql
-- 사용자 생성
CREATE USER netguard WITH PASSWORD 'NetGuard@2025!';

-- 데이터베이스 생성
CREATE DATABASE netguard OWNER netguard;

-- 권한 부여
GRANT ALL PRIVILEGES ON DATABASE netguard TO netguard;

-- netguard DB로 전환
\c netguard

-- TimescaleDB 확장 활성화
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

-- 스키마 권한
GRANT ALL ON SCHEMA public TO netguard;

\q
```

### 6.2 pg_hba.conf 설정 (로컬 인증)

```powershell
notepad "C:\Program Files\PostgreSQL\17\data\pg_hba.conf"
```

다음 줄 확인/수정 (md5 인증):
```
# TYPE  DATABASE  USER      ADDRESS     METHOD
local   all       postgres              md5
local   all       netguard              md5
host    all       all       127.0.0.1/32  md5
host    all       all       ::1/128       md5
```

```powershell
Restart-Service -Name "postgresql-x64-17"
```

### 6.3 NetGuard 스키마 초기화

```powershell
cd C:\SNMP\Claude
.\venv\Scripts\Activate.ps1

# 스크립트 실행
python scripts\setup_db.py
# postgres 슈퍼유저 암호 입력 프롬프트 → 입력
```

### 6.4 초기화 확인

```powershell
psql -U netguard -d netguard -h localhost -c "\dt"
# 테이블 목록: devices, metrics, events, thresholds, vulnerabilities 등 출력
```

---

## 7. 설정 파일 구성

```powershell
notepad "C:\SNMP\Claude\config\config.yaml"
```

```yaml
# ===== Database =====
db_host: localhost
db_port: 5432
db_user: netguard
db_password: "NetGuard@2025!"    # 6.1에서 설정한 암호

# ===== SNMP =====
snmp_community: public           # 장비 SNMP community string
snmp_timeout: 5
snmp_retries: 2
snmp_poll_interval: 60           # 수집 주기 (초)

# ===== 이메일 알림 =====
smtp_host: mail.company.local    # 내부 메일 서버
smtp_port: 25
smtp_from: noreply@company.local
alert_emails:
  - admin@company.local

# ===== 카카오톡 (오프라인 환경 false 유지) =====
kakao_enabled: false

# ===== 라즈베리파이 (연결 시 true로 변경) =====
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
```

### 7.1 동작 확인 (서버 기동 테스트)

```powershell
cd C:\SNMP\Claude\backend
..\venv\Scripts\Activate.ps1

uvicorn app:app --host 127.0.0.1 --port 8000
# INFO:     Application startup complete. 확인
# Ctrl+C로 중지
```

브라우저에서 `http://127.0.0.1:8000` 접속 → 대시보드 확인

---

## 8. Windows 서비스 등록 (NSSM)

### 8.1 NSSM 설치

```powershell
# 압축 해제
Expand-Archive -Path "nssm-2.24.zip" -DestinationPath "C:\nssm"

# 시스템 경로에 복사
Copy-Item "C:\nssm\nssm-2.24\win64\nssm.exe" "C:\Windows\System32\"

nssm version  # 확인
```

### 8.2 NetGuard 서비스 등록

```powershell
# 관리자 PowerShell 필수

# 서비스 등록
nssm install NetGuard "C:\SNMP\Claude\venv\Scripts\python.exe"

# 실행 인수 설정
nssm set NetGuard AppParameters `
    "-m uvicorn app:app --host 0.0.0.0 --port 8000 --workers 2"

# 작업 디렉토리
nssm set NetGuard AppDirectory "C:\SNMP\Claude\backend"

# 환경 변수
nssm set NetGuard AppEnvironmentExtra `
    "PYTHONPATH=C:\SNMP\Claude\backend"

# 로그 설정
nssm set NetGuard AppStdout "C:\SNMP\Claude\logs\service_stdout.log"
nssm set NetGuard AppStderr "C:\SNMP\Claude\logs\service_stderr.log"
nssm set NetGuard AppRotateFiles 1
nssm set NetGuard AppRotateSeconds 86400

# 자동 재시작 (5초 대기)
nssm set NetGuard AppRestartDelay 5000

# 시작 유형 (자동)
nssm set NetGuard Start SERVICE_AUTO_START

# 서비스 표시 이름
nssm set NetGuard DisplayName "NetGuard SNMP Dashboard"
nssm set NetGuard Description "SNMP 통합 모니터링 대시보드 서비스"

# 서비스 시작
nssm start NetGuard
```

### 8.3 서비스 상태 확인

```powershell
Get-Service -Name "NetGuard"
# Status: Running 확인

# 로그 확인
Get-Content "C:\SNMP\Claude\logs\service_stderr.log" -Tail 20
```

### 8.4 서비스 관리 명령어

```powershell
# 시작
Start-Service NetGuard

# 중지
Stop-Service NetGuard

# 재시작
Restart-Service NetGuard

# 서비스 제거 (필요 시)
nssm remove NetGuard confirm
```

---

## 9. Windows 방화벽 설정

```powershell
# 관리자 PowerShell

# 대시보드 웹 포트 허용 (인바운드)
New-NetFirewallRule -DisplayName "NetGuard Dashboard" `
    -Direction Inbound -Protocol TCP -LocalPort 8000 `
    -Action Allow -Profile Any

# SNMP 수신 포트 (SNMP Trap 수신 시)
New-NetFirewallRule -DisplayName "SNMP Trap" `
    -Direction Inbound -Protocol UDP -LocalPort 162 `
    -Action Allow -Profile Any

# 설정 확인
Get-NetFirewallRule -DisplayName "NetGuard*" | Select-Object DisplayName, Enabled, Direction
```

---

## 10. SNMP 장비 등록

### 10.1 Windows 서버 SNMP 서비스 활성화 (모니터링 대상 서버)

```powershell
# 대상 서버에서 실행 (모니터링 대상 Windows 서버)

# SNMP 서비스 설치
Add-WindowsFeature -Name SNMP-Service, SNMP-WMI-Provider -IncludeManagementTools

# 또는 Windows 기능에서:
# 제어판 → 프로그램 및 기능 → Windows 기능 켜기/끄기
# → 간단한 네트워크 관리 프로토콜(SNMP) 체크
```

Windows 10/11 또는 Windows Server에서 `Add-WindowsFeature`가 없는 경우 관리자 PowerShell에서 Capability 방식으로 설치합니다.

```powershell
# Windows 10/11, 일부 Windows Server 환경
Add-WindowsCapability -Online -Name "SNMP.Client~~~~0.0.1.0"
Add-WindowsCapability -Online -Name "WMI-SNMP-Provider.Client~~~~0.0.1.0"

# 설치 확인
Get-WindowsCapability -Online | Where-Object Name -like "*SNMP*"
Get-Service SNMP*
```

SNMP 서비스 설정:
```
서비스(services.msc) → SNMP Service → 속성
[보안] 탭:
  - "허용된 커뮤니티" → 추가: public (읽기 전용)
  - "다음 호스트에서 SNMP 패킷 허용" → 모니터링 서버 IP 추가
[에이전트] 탭:
  - 위치: 서버실 A랙
  - 연락처: admin@company.local
  - 서비스: Physical, Applications, Datalink, Internet, End-to-End 체크
```

레지스트리로 Community와 허용 호스트를 설정할 수도 있습니다.

```powershell
# Community 등록: 4 = READ ONLY
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" -Force
New-ItemProperty `
  -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" `
  -Name "stanley" `
  -Value 4 `
  -PropertyType DWord `
  -Force

# NetGuard 서버 IP만 허용
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers" -Force
New-ItemProperty `
  -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers" `
  -Name "1" `
  -Value "10.60.8.186" `
  -PropertyType String `
  -Force

Set-Service -Name SNMP -StartupType Automatic
Restart-Service -Name SNMP

New-NetFirewallRule `
  -DisplayName "SNMP UDP 161 Inbound" `
  -Direction Inbound `
  -Protocol UDP `
  -LocalPort 161 `
  -Action Allow `
  -Profile Any
```

NetGuard 서버에서 Windows SNMP 수집 항목을 확인합니다.

```bash
snmpwalk -v2c -c stanley 윈도우서버IP .1.3.6.1.2.1.1.1.0
snmpwalk -v2c -c stanley 윈도우서버IP .1.3.6.1.2.1.25.2.3.1.3
snmpwalk -v2c -c stanley 윈도우서버IP .1.3.6.1.2.1.25.4.2.1.2
```

`hrStorageDescr`에 `C:\`, `D:\`, `Physical Memory`가 보이면 디스크와 메모리 수집 준비가 정상입니다.

### 10.2 Linux 서버 SNMP 설정 (Rocky Linux 대상 서버)

```bash
# 대상 Linux 서버에서 실행
sudo dnf install -y net-snmp net-snmp-utils

sudo tee /etc/snmp/snmpd.conf << 'EOF'
# 읽기 전용 허용 (모니터링 서버 IP로 변경)
rocommunity  public  192.168.1.0/24
syslocation  "서버실 A랙"
syscontact   admin@company.local

# UCD-SNMP CPU/Memory MIB
view   systemview  included  .1.3.6.1.2.1.25
view   systemview  included  .1.3.6.1.4.1.2021

# 64-bit 카운터 허용
view   systemview  included  .1.3.6.1.2.1.31
EOF

sudo systemctl enable --now snmpd
sudo firewall-cmd --permanent --add-port=161/udp
sudo firewall-cmd --reload

# 동작 확인 (모니터링 서버에서)
snmpwalk -v2c -c public 192.168.1.10 1.3.6.1.2.1.1.1.0
```

### 10.3 Cisco 스위치 SNMP 설정

```
! Cisco IOS
conf t
snmp-server community public RO
snmp-server location "IDC A실"
snmp-server contact admin@company.local
snmp-server host 10.60.8.187 version 2c public
snmp-server enable traps
end
write memory
```

### 10.4 대시보드에서 장비 등록

1. 브라우저에서 `http://서버IP:8000` 접속
2. 좌측 메뉴 → `장비 관리` → `+ 장비 추가`
3. 정보 입력:
   - 장비명: `SRV-WEB-01`
   - 유형: `서버`
   - IP: `192.168.1.10`
   - SNMP 버전: `v2c`
   - Community: `public`
   - OS 버전: `Rocky Linux 9.3` (CVE 매핑에 사용)

### 10.5 SNMP 연결 테스트

```powershell
# PowerShell에서 SNMP 테스트 (Windows 내장)
# snmpwalk가 없는 경우 Net-SNMP for Windows 설치 필요

# 또는 Python으로 테스트
cd C:\SNMP\Claude\backend
..\venv\Scripts\Activate.ps1
python -c "
from pysnmp.hlapi import *
iterator = getCmd(
    SnmpEngine(),
    CommunityData('public', mpModel=1),
    UdpTransportTarget(('192.168.1.10', 161)),
    ContextData(),
    ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
)
errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
if errorIndication:
    print('Error:', errorIndication)
else:
    for varBind in varBinds:
        print(varBind.prettyPrint())
"
```

---

## 11. CVE 취약점 DB 오프라인 구성

### 11.1 인터넷 환경 PC에서 오프라인 반입용 NVD 피드 다운로드

```powershell
# 인터넷 환경 PC에서 실행
cd C:\NetGuard_temp
$env:NVD_API_KEY = '발급받은_NVD_API_KEY'
python scripts\download_nvd.py --years 2024 2025 2026

# 다운로드 파일 확인 (~2GB)
Get-ChildItem data\nvd_cache\ | Select-Object Name, Length
```

### 11.2 오프라인 서버로 복사

```powershell
# USB 또는 내부 파일 서버를 통해 복사
xcopy /E /I "C:\NetGuard_temp\data\nvd_cache\*" `
           "C:\SNMP\Claude\data\nvd_cache\"

# 파일 확인
Get-ChildItem "C:\SNMP\Claude\data\nvd_cache\" | Measure-Object
# Count: 대상 연도 파일 + cache_meta.json
```

### 11.3 CVE 로딩 확인

```powershell
# 서버 재시작 후 API 확인
Restart-Service NetGuard
Start-Sleep 10

Invoke-RestMethod http://localhost:8000/api/security/cves | ConvertTo-Json -Depth 2
```

### 11.4 실시간 증분 업데이트 (인터넷 연결 가능 환경)

```powershell
# 인터넷 환경 PC에서 최근 2시간 변경분 반영
$env:NVD_API_KEY = '발급받은_NVD_API_KEY'
python scripts\update_nvd_cache.py --hours 2

# 인터넷 가능한 별도 PC에 2시간 주기 작업 등록 예시
schtasks /Create /TN "NetGuard-NVD-Update" /SC HOURLY /MO 2 `
  /TR "powershell.exe -NoProfile -Command `"cd C:\NetGuard_temp; `$env:NVD_API_KEY='발급받은_NVD_API_KEY'; python scripts\update_nvd_cache.py --hours 2`"" `
  /F

# 업데이트된 파일을 오프라인 서버로 복사 후 서비스 재시작
Restart-Service NetGuard
```

> 운영 서버가 인터넷 차단 환경이면 Windows 작업 스케줄러는 운영 서버가 아니라 인터넷 가능한 별도 동기화 PC에만 구성한다.

---

## 12. 라즈베리파이 센서 연동

### 12.1 라즈베리파이 측 설정

라즈베리파이에서 다음 스크립트를 실행합니다.

```bash
# 라즈베리파이 (Raspbian/Raspberry Pi OS)
pip3 install flask adafruit-circuitpython-dht

cat > /home/pi/sensor_server.py << 'EOF'
from flask import Flask, jsonify
import adafruit_dht
import board
import time

app = Flask(__name__)
# DHT22 센서 GPIO 핀 설정
sensor = adafruit_dht.DHT22(board.D4)

@app.route('/sensor')
def get_sensor():
    for _ in range(3):
        try:
            return jsonify({
                'temperature': round(sensor.temperature, 1),
                'humidity': round(sensor.humidity, 1),
                'unit': 'celsius'
            })
        except Exception:
            time.sleep(2)
    return jsonify({'error': 'sensor_read_failed'}), 500

@app.route('/health')
def health():
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8765)
EOF

# systemd 서비스 등록
sudo tee /etc/systemd/system/sensor.service << 'EOF'
[Unit]
Description=NetGuard Sensor API
After=network.target

[Service]
ExecStart=/usr/bin/python3 /home/pi/sensor_server.py
Restart=always
User=pi

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now sensor
```

### 12.2 NetGuard 설정 활성화

```powershell
notepad "C:\SNMP\Claude\config\config.yaml"
```

```yaml
rpi_enabled: true
rpi_ip: 192.168.1.60     # 라즈베리파이 IP
rpi_port: 8765
```

```powershell
# 연결 테스트
Invoke-RestMethod http://192.168.1.60:8765/sensor

# 서비스 재시작
Restart-Service NetGuard
```

---

## 13. 알림 설정

### 13.1 이메일 설정 (내부 SMTP)

```powershell
notepad "C:\SNMP\Claude\config\config.yaml"
```

```yaml
smtp_host: mail.company.local
smtp_port: 25              # 내부 릴레이: 25 / STARTTLS: 587 / SSL: 465
smtp_user: ""              # 인증 불필요 시 비워둠
smtp_password: ""
smtp_from: noreply@company.local
alert_emails:
  - admin@company.local
  - ops@company.local
```

이메일 발송 테스트:
```
대시보드 → 알림 설정 → 테스트 메일 발송
```

### 13.2 카카오톡 알림 설정

> 카카오 API 서버에 외부 인터넷 접속이 가능할 경우에만 사용

1. [Kakao Developers](https://developers.kakao.com) → 내 애플리케이션 → 앱 추가
2. 카카오 채널 생성 → 채널 공개 설정
3. 앱 → 비즈니스 → 카카오톡 채널 연결
4. REST API 키 복사

```yaml
kakao_enabled: true
kakao_rest_key: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
kakao_channel_token: "xxxxxxxx"
```

### 13.3 알림 임계값 조정

```
대시보드 → 임계값 설정 → 슬라이더로 조정 → 설정 저장
```

---

## 14. 운영 및 관리

### 14.1 서비스 상태 모니터링

```powershell
# 실시간 서비스 상태
while ($true) {
    $svc = Get-Service NetGuard
    $pg  = Get-Service "postgresql-x64-17"
    Write-Host "$(Get-Date -Format 'HH:mm:ss') | NetGuard: $($svc.Status) | PostgreSQL: $($pg.Status)"
    Start-Sleep 30
}
```

### 14.2 로그 확인

```powershell
# 애플리케이션 로그 (실시간)
Get-Content "C:\SNMP\Claude\logs\netguard.log" -Wait -Tail 50

# 서비스 stdout/stderr
Get-Content "C:\SNMP\Claude\logs\service_stderr.log" -Tail 100

# PostgreSQL 로그
Get-ChildItem "C:\Program Files\PostgreSQL\17\data\log\" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1 |
    ForEach-Object { Get-Content $_.FullName -Tail 50 }
```

### 14.3 데이터베이스 모니터링

```sql
-- psql -U netguard -d netguard -h localhost

-- 테이블별 데이터 크기
SELECT
    hypertable_name,
    pg_size_pretty(hypertable_size(format('%I', hypertable_name)::regclass)) AS total_size
FROM timescaledb_information.hypertables;

-- 최근 수집 데이터 확인
SELECT d.name, m.metric_name, m.value, m.time
FROM metrics m
JOIN devices d ON d.id = m.device_id
WHERE m.time >= NOW() - INTERVAL '5 minutes'
ORDER BY m.time DESC LIMIT 20;

-- 활성 이벤트 수
SELECT severity, COUNT(*) FROM events
WHERE status = 'active'
GROUP BY severity ORDER BY severity;

-- DB 연결 수 확인
SELECT count(*) FROM pg_stat_activity WHERE datname = 'netguard';
```

### 14.4 성능 모니터링

```powershell
# CPU, 메모리 사용량 확인
Get-Process -Name "python" | Select-Object Name, CPU, WorkingSet64 |
    ForEach-Object { "$($_.Name) | CPU: $([math]::Round($_.CPU,1))s | RAM: $([math]::Round($_.WorkingSet64/1MB,1))MB" }

# 디스크 사용량
Get-PSDrive -Name E | Select-Object Used, Free |
    ForEach-Object { "Used: $([math]::Round($_.Used/1GB,1))GB | Free: $([math]::Round($_.Free/1GB,1))GB" }
```

### 14.5 Task Scheduler로 일일 리포트 자동 실행

```powershell
# 매일 오전 9시 일일 요약 이메일 전송 (선택)
$action = New-ScheduledTaskAction -Execute "C:\SNMP\Claude\venv\Scripts\python.exe" `
    -Argument "C:\SNMP\Claude\scripts\daily_report.py" `
    -WorkingDirectory "C:\SNMP\Claude\backend"

$trigger = New-ScheduledTaskTrigger -Daily -At 9:00AM

Register-ScheduledTask -TaskName "NetGuard_DailyReport" `
    -Action $action -Trigger $trigger -RunLevel Highest
```

---

## 15. 백업 및 복구

### 15.1 데이터베이스 백업

```powershell
# 백업 디렉토리
New-Item -ItemType Directory -Path "E:\Backup\netguard" -Force

# 전체 백업 (pg_dump)
$date = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFile = "E:\Backup\netguard\netguard_$date.dump"

& "C:\Program Files\PostgreSQL\17\bin\pg_dump.exe" `
    -U netguard -h localhost -d netguard `
    -Fc -Z 9 `
    -f $backupFile

Write-Host "Backup saved: $backupFile"
```

### 15.2 자동 백업 스케줄 (Task Scheduler)

```powershell
# 매일 새벽 2시 백업
$script = @'
$date = Get-Date -Format "yyyyMMdd"
$dest = "E:\Backup\netguard"
New-Item -ItemType Directory -Path $dest -Force | Out-Null
& "C:\Program Files\PostgreSQL\17\bin\pg_dump.exe" `
    -U netguard -h localhost -d netguard -Fc -Z 9 `
    -f "$dest\netguard_$date.dump"
# 30일 이상 된 백업 삭제
Get-ChildItem $dest -Filter "*.dump" |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } |
    Remove-Item -Force
'@
$script | Out-File "C:\SNMP\Claude\scripts\backup.ps1" -Encoding utf8

$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NonInteractive -File C:\SNMP\Claude\scripts\backup.ps1"
$trigger = New-ScheduledTaskTrigger -Daily -At 2:00AM

Register-ScheduledTask -TaskName "NetGuard_Backup" `
    -Action $action -Trigger $trigger -RunLevel Highest
```

### 15.3 백업 복구

```powershell
# 서비스 중지
Stop-Service NetGuard

# DB 복구
& "C:\Program Files\PostgreSQL\17\bin\pg_restore.exe" `
    -U netguard -h localhost -d netguard `
    --clean --if-exists `
    "E:\Backup\netguard\netguard_20250507.dump"

# 서비스 재시작
Start-Service NetGuard
```

### 15.4 설정 파일 백업

```powershell
# 설정 파일만 별도 백업
Copy-Item "C:\SNMP\Claude\config\config.yaml" `
    "E:\Backup\netguard\config_$(Get-Date -Format 'yyyyMMdd').yaml"
```

---

## 16. 업데이트 절차

### 16.1 애플리케이션 업데이트

```powershell
# 1. 현재 버전 백업
$date = Get-Date -Format "yyyyMMdd"
Copy-Item -Recurse "C:\SNMP\Claude\backend" "E:\Backup\netguard\backend_$date" -Force

# 2. 서비스 중지
Stop-Service NetGuard

# 3. 새 파일 배포 (C:\SNMP\Claude\backend\ 에 복사)
Copy-Item -Recurse "D:\update_package\backend\*" "C:\SNMP\Claude\backend\" -Force
Copy-Item -Recurse "D:\update_package\frontend\*" "C:\SNMP\Claude\frontend\" -Force

# 4. 패키지 업데이트 (오프라인)
cd C:\SNMP\Claude
.\venv\Scripts\Activate.ps1
pip install --no-index --find-links "D:\update_packages" -r requirements.txt

# 5. DB 마이그레이션 (있을 경우)
python scripts\migrate.py

# 6. 서비스 재시작
Start-Service NetGuard

# 7. 동작 확인
Start-Sleep 5
Invoke-RestMethod http://localhost:8000/health
```

### 16.2 Python 패키지만 업데이트

```powershell
Stop-Service NetGuard

cd C:\SNMP\Claude
.\venv\Scripts\Activate.ps1
pip install --no-index --find-links "D:\new_packages" pysnmp==6.2.x

Start-Service NetGuard
```

---

## 17. 문제 해결

### SNMP 응답 없음

```powershell
# 대상 장비 SNMP 포트 접근 테스트
Test-NetConnection -ComputerName 192.168.1.10 -Port 161

# Windows 방화벽 규칙 확인
Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*SNMP*" }

# snmpwalk 테스트 (net-snmp 설치 시)
snmpwalk -v2c -c public 192.168.1.10 .1.3.6.1.2.1.1
```

### 서비스가 시작되지 않음

```powershell
# 이벤트 로그 확인
Get-EventLog -LogName Application -Source NetGuard -Newest 10

# stderr 로그 확인
Get-Content "C:\SNMP\Claude\logs\service_stderr.log" -Tail 50

# 수동 실행으로 에러 확인
cd C:\SNMP\Claude\backend
..\venv\Scripts\Activate.ps1
python -m uvicorn app:app --host 127.0.0.1 --port 8000
```

### 데이터베이스 연결 실패

```powershell
# PostgreSQL 서비스 확인
Get-Service "postgresql-x64-17"

# 연결 테스트
psql -U netguard -h localhost -d netguard -c "SELECT NOW();"

# pg_hba.conf 권한 확인
notepad "C:\Program Files\PostgreSQL\17\data\pg_hba.conf"
# host all all 127.0.0.1/32 md5 라인 확인

Restart-Service "postgresql-x64-17"
```

### 포트 충돌 (8000번 사용 중)

```powershell
# 8000번 포트 사용 프로세스 확인
netstat -ano | findstr ":8000"

# PID로 프로세스 확인
Get-Process -Id <PID>

# config.yaml에서 포트 변경 후 NSSM 재설정
nssm set NetGuard AppParameters `
    "-m uvicorn app:app --host 0.0.0.0 --port 8001 --workers 2"
Restart-Service NetGuard
```

### TimescaleDB 관련 오류

```sql
-- psql에서 확인
SELECT * FROM timescaledb_information.hypertables;

-- 확장 재확인
SELECT extname, extversion FROM pg_extension;

-- 압축 정책 확인
SELECT * FROM timescaledb_information.compression_settings;
```

### 메모리 부족

```powershell
# 서버 RAM 확인
Get-WmiObject -Class Win32_ComputerSystem |
    Select-Object @{N='RAM_GB';E={[math]::Round($_.TotalPhysicalMemory/1GB,1)}}

# postgresql.conf shared_buffers 조정 (RAM의 25%)
notepad "C:\Program Files\PostgreSQL\17\data\postgresql.conf"
# shared_buffers = 1GB  ← 조정
Restart-Service "postgresql-x64-17"
```

---

*NetGuard SNMP Dashboard — Windows 설치 메뉴얼 v1.0.0 (2026-05-08)*
