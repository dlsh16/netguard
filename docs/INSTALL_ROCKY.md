# NetGuard SNMP Dashboard
# Rocky Linux 설치 및 운영 메뉴얼

> 대상 OS: Rocky Linux 8.x / 9.x (x86_64)
> 작성일: 2026-05-08 | 버전: 1.0.0

---

## 목차

1. [사전 준비 및 오프라인 패키지 수집](#1-사전-준비-및-오프라인-패키지-수집)
2. [시스템 기본 설정](#2-시스템-기본-설정)
3. [PostgreSQL 18 설치](#3-postgresql-18-설치)
4. [TimescaleDB 확장 설치](#4-timescaledb-확장-설치)
5. [Python 3.13 설치](#5-python-313-설치)
6. [NetGuard 애플리케이션 설치](#6-netguard-애플리케이션-설치)
7. [데이터베이스 초기화](#7-데이터베이스-초기화)
8. [설정 파일 구성](#8-설정-파일-구성)
9. [systemd 서비스 등록](#9-systemd-서비스-등록)
10. [방화벽 및 SELinux 설정](#10-방화벽-및-selinux-설정)
11. [SNMP 장비 등록](#11-snmp-장비-등록)
12. [CVE 취약점 DB 오프라인 구성](#12-cve-취약점-db-오프라인-구성)
13. [라즈베리파이 센서 연동](#13-라즈베리파이-센서-연동)
14. [알림 설정 (이메일 / 카카오톡)](#14-알림-설정)
15. [운영 및 관리](#15-운영-및-관리)
16. [백업 및 복구](#16-백업-및-복구)
17. [업데이트 절차](#17-업데이트-절차)
18. [문제 해결](#18-문제-해결)

---

## 빠른 설치 (스크립트 사용)

> 아래 두 스크립트로 2~10절 설치 과정을 자동화할 수 있습니다.
> 수동 제어가 필요하거나 문제가 발생한 경우 각 절을 참고하세요.

### 1단계: 인터넷 환경 Rocky Linux PC에서 패키지 수집

```bash
# root 권한 필요
sudo bash scripts/collect_packages_rocky.sh
# 완료 후: /opt/netguard_offline_packages.tar.gz 를 USB에 복사
```

### 2단계: 오프라인 서버에서 자동 설치

```bash
# USB에서 서버로 복사 후 실행
tar -xzf netguard_offline_packages.tar.gz -C /opt/
sudo bash scripts/install_rocky.sh
# 대화형 프롬프트: 호스트명·DB 암호·SNMP Community 입력
# 설치 완료 → http://서버IP:8000 접속
```

> **TimescaleDB PG18 호환성 참고**
> TimescaleDB의 PostgreSQL 18 공식 지원 여부는 [docs.timescale.com](https://docs.timescale.com) 에서 확인하세요.
> 미지원 시 `collect_packages_rocky.sh` 가 경고를 출력하며 TimescaleDB RPM 없이 진행합니다.
> 이 경우 PostgreSQL 기본 테이블로 설치되며, 시계열 압축·보존정책 기능은 사용 불가합니다.

---

## 1. 사전 준비 및 오프라인 패키지 수집

### 1.1 오프라인 환경을 위한 RPM 패키지 수집

> 동일한 Rocky Linux 버전의 인터넷 환경 PC(또는 Docker 컨테이너)에서 수행

```bash
# 인터넷 환경 Rocky Linux PC에서 실행
mkdir -p /opt/offline_packages/{rpm,pip}

# ===== PostgreSQL 18 RPM 수집 =====
# PostgreSQL 저장소 설정
sudo dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-9-x86_64/pgdg-redhat-repo-latest.noarch.rpm
sudo dnf -qy module disable postgresql

# RPM 다운로드 (설치 없이 파일만 수집)
sudo dnf download --resolve --destdir /opt/offline_packages/rpm \
    postgresql18 postgresql18-server postgresql18-contrib postgresql18-libs

# ===== TimescaleDB RPM 수집 =====
curl -s https://packagecloud.io/install/repositories/timescale/timescaledb/script.rpm.sh | sudo bash
sudo dnf download --resolve --destdir /opt/offline_packages/rpm \
    timescaledb-2-postgresql-18

# ===== Python 3.11 빌드 의존성 =====
sudo dnf download --resolve --destdir /opt/offline_packages/rpm \
    python3.13 python3.13-pip python3.13-devel gcc gcc-c++ make \
    openssl-devel libffi-devel bzip2-devel readline-devel

# ===== 기타 필수 도구 =====
sudo dnf download --resolve --destdir /opt/offline_packages/rpm \
    net-snmp net-snmp-utils vim curl wget rsync

# ===== Python pip 패키지 수집 =====
# 설치 서버에서 사용할 Python 버전과 같은 버전으로 수집합니다.
# 예: 설치 서버가 Python 3.12라면 수집 서버도 python3.12 또는 호환 Python 사용
PYTHON_BIN=$(command -v python3.13 2>/dev/null || command -v python3 || echo python3)
$PYTHON_BIN -m pip download -r /opt/netguard/requirements.txt \
    -d /opt/offline_packages/pip \
    --only-binary=:all:
```

> `PyYAML`, `fastapi`, `uvicorn`, `asyncpg` 등 wheel이 누락되면 서비스가 시작되지 않습니다.
> `/opt/offline_packages/pip`가 비어 있는 경우 자동 설치 스크립트는 온라인 `pip install`을 시도하고,
> 실패하면 서비스 시작 전 중단합니다.

### 1.2 수집 파일 전송

```bash
# 압축
tar -czf netguard_offline_packages.tar.gz /opt/offline_packages/

# USB 또는 내부 파일 서버로 복사 후 오프라인 서버에서 해제
scp netguard_offline_packages.tar.gz admin@10.60.8.187:/opt/
```

---

## 2. 시스템 기본 설정

```bash
# ===== 오프라인 서버에서 시작 =====

# 호스트명 설정
sudo hostnamectl set-hostname netguard-srv

# 시간 동기화 (내부 NTP 서버)
sudo timedatectl set-timezone Asia/Seoul
sudo timedatectl set-ntp true

# 내부 NTP가 있을 경우
sudo dnf install -y chrony    # 오프라인: RPM으로 설치
sudo tee /etc/chrony.conf << 'EOF'
server 192.168.1.1 iburst    # 내부 NTP 서버 IP
driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
EOF
sudo systemctl enable --now chronyd

# 시간 확인
timedatectl status

# 시스템 업데이트 (오프라인: 기존 RPM 있으면 적용, 없으면 스킵)
# sudo dnf update -y  ← 오프라인에서는 건너뜀

# 필수 도구 설치 (RPM 오프라인 설치)
sudo dnf localinstall /opt/offline_packages/rpm/vim*.rpm \
                      /opt/offline_packages/rpm/curl*.rpm 2>/dev/null || true
```

---

## 3. PostgreSQL 18 설치

### 3.1 오프라인 RPM 설치

```bash
# 수집된 패키지 압축 해제
tar -xzf /opt/netguard_offline_packages.tar.gz -C /opt/

# PostgreSQL RPM 오프라인 설치
sudo dnf localinstall --nogpgcheck \
    /opt/offline_packages/rpm/postgresql18-libs-*.rpm \
    /opt/offline_packages/rpm/postgresql18-18.*.rpm \
    /opt/offline_packages/rpm/postgresql18-server-*.rpm \
    /opt/offline_packages/rpm/postgresql18-contrib-*.rpm
```

### 3.2 데이터베이스 초기화

```bash
# 환경 변수 설정
export PGDATA=/var/lib/pgsql/18/data
export PATH=$PATH:/usr/pgsql-18/bin

# 영구 설정 (모든 사용자)
sudo tee /etc/profile.d/postgresql.sh << 'EOF'
export PATH=$PATH:/usr/pgsql-18/bin
export PGDATA=/var/lib/pgsql/18/data
EOF

# DB 초기화 (로케일: 한국어)
sudo /usr/pgsql-18/bin/postgresql-18-setup initdb

# 서비스 활성화 및 시작
sudo systemctl enable --now postgresql-18

# 상태 확인
sudo systemctl status postgresql-18
```

### 3.3 postgresql.conf 최적화

서버 RAM을 자동으로 읽어 권장값을 계산합니다.

```bash
# RAM / CPU 기반 권장값 계산 (참고용 출력)
RAM_GB=$(awk '/MemTotal/{printf "%.0f", $2/1024/1024}' /proc/meminfo)
CPU=$(nproc)
MAX_CONN=100

SB=$(( RAM_GB * 1024 / 4 ))
[ $SB -gt 8192 ] && SB=8192          # 최대 8GB
ECS=$(( RAM_GB * 1024 * 3 / 4 ))
WM=$(( RAM_GB * 1024 / 4 / MAX_CONN ))
[ $WM -lt 4 ] && WM=4
MWM=$(( RAM_GB * 1024 / 20 ))
[ $MWM -gt 2048 ] && MWM=2048
MPW=$(( CPU / 2 ))
[ $MPW -lt 2 ] && MPW=2
TSBG=$CPU
[ $TSBG -gt 16 ] && TSBG=16

echo "shared_buffers          = ${SB}MB"
echo "effective_cache_size    = ${ECS}MB"
echo "work_mem                = ${WM}MB"
echo "maintenance_work_mem    = ${MWM}MB"
echo "max_parallel_workers    = $MPW"
echo "timescaledb.max_background_workers = $TSBG"
```

계산된 값을 반영하여 설정 파일을 수정합니다.

```bash
sudo vi /var/lib/pgsql/18/data/postgresql.conf
```

```ini
# =============================================
# 연결
# =============================================
listen_addresses = 'localhost'
max_connections = 100
superuser_reserved_connections = 3
port = 5432

# =============================================
# 메모리  (RAM 8GB 기준 예시 — 위 스크립트로 계산)
# =============================================
shared_buffers = 2GB                  # RAM × 0.25, 최대 8GB
effective_cache_size = 6GB            # RAM × 0.75
work_mem = 20MB                       # (shared_buffers / max_connections)
maintenance_work_mem = 512MB          # VACUUM·CREATE INDEX 전용
temp_file_limit = 10GB                # 임시 파일 상한

# =============================================
# WAL / 체크포인트
# =============================================
wal_buffers = 64MB
min_wal_size = 512MB
max_wal_size = 4GB
checkpoint_completion_target = 0.9
checkpoint_timeout = 10min

# =============================================
# 병렬 처리
# =============================================
max_worker_processes = 8              # CPU 코어 수 이상
max_parallel_workers_per_gather = 2
max_parallel_workers = 4              # CPU 코어 수 / 2
max_parallel_maintenance_workers = 2

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
logging_collector = on
log_directory = '/var/log/postgresql'
log_filename = 'postgresql-%Y-%m-%d.log'
log_rotation_age = 1d
log_rotation_size = 100MB
log_min_duration_statement = 1000
log_checkpoints = on
log_connections = off
log_lock_waits = on
log_temp_files = 0
log_line_prefix = '%t [%p] %u@%d '

# TimescaleDB — 다음 섹션 4.2에서 아래 줄 추가
# shared_preload_libraries = 'timescaledb'
```

```bash
# 로그 디렉토리 생성
sudo mkdir -p /var/log/postgresql
sudo chown postgres:postgres /var/log/postgresql

sudo systemctl restart postgresql-18
```

### 3.4 pg_hba.conf 설정

```bash
sudo vi /var/lib/pgsql/18/data/pg_hba.conf
```

```
# TYPE  DATABASE  USER      ADDRESS       METHOD
local   all       postgres                peer
local   all       netguard                md5
host    all       netguard  127.0.0.1/32  md5
host    all       netguard  ::1/128       md5
```

```bash
sudo systemctl reload postgresql-18
```

---

## 4. TimescaleDB 확장 설치

### 4.1 오프라인 RPM 설치

```bash
sudo dnf localinstall --nogpgcheck \
    /opt/offline_packages/rpm/timescaledb-2-postgresql-18-*.rpm
```

### 4.2 TimescaleDB 설정 적용

3.3에서 편집한 `postgresql.conf` 끝에 아래 블록을 **추가**합니다.

```bash
sudo tee -a /var/lib/pgsql/18/data/postgresql.conf << 'EOF'

# =============================================
# TimescaleDB 로드 및 전용 설정
# =============================================

# TimescaleDB DLL을 PostgreSQL 시작 시 로드 (반드시 첫 번째 라이브러리)
shared_preload_libraries = 'timescaledb'

# 백그라운드 워커 수 — CPU 코어 수와 동일하게 설정 (최소 4, 최대 16)
# 청크 압축·보존정책·연속집계(Continuous Aggregates) 실행에 사용됨
# max_worker_processes 값을 초과하면 안 됨
timescaledb.max_background_workers = 8

# 텔레메트리 비활성화 (오프라인 환경 필수 — 외부 접속 시도 차단)
timescaledb.telemetry_level = off

# 청크 캐시 — 자주 접근하는 최신 청크를 메모리에 유지
timescaledb.max_cached_chunks_per_hypertable = 1024

# 불필요한 청크 스킵 허용 (WHERE 절 기반 — 시계열 쿼리 성능 향상)
timescaledb.enable_chunk_skipping = on
EOF
```

> **`timescaledb-tune` 사용 가능한 경우 (Rocky Linux 권장)**
>
> timescaledb-tune이 설치됐다면 수동 설정 대신 아래 명령어 한 줄로 대체할 수 있습니다.
> 단, 오프라인 설정(`telemetry_level = off`)은 수동으로 추가해야 합니다.
>
> ```bash
> sudo timescaledb-tune --quiet --yes \
>     --pg-config=/usr/pgsql-18/bin/pg_config
>
> # 오프라인 환경 필수 추가 설정
> echo "timescaledb.telemetry_level = off" | \
>     sudo tee -a /var/lib/pgsql/18/data/postgresql.conf
> ```

```bash
# 적용
sudo systemctl restart postgresql-18

# max_background_workers 적용 확인
sudo -u postgres psql -c "SHOW shared_preload_libraries;"
sudo -u postgres psql -c "SHOW timescaledb.max_background_workers;"
sudo -u postgres psql -c "SHOW timescaledb.max_cached_chunks_per_hypertable;"
sudo -u postgres psql -c "SHOW timescaledb.telemetry_level;"
```

### 4.3 TimescaleDB 활성화 확인

```bash
sudo -u postgres psql -c "CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;"
sudo -u postgres psql -c "SELECT extname, extversion FROM pg_extension WHERE extname='timescaledb';"
# timescaledb | 2.x.x 출력 확인
```

---

## 5. Python 3.13 설치

### 5.1 오프라인 RPM 설치

```bash
sudo dnf localinstall --nogpgcheck \
    /opt/offline_packages/rpm/python3.13-*.rpm \
    /opt/offline_packages/rpm/gcc-*.rpm \
    /opt/offline_packages/rpm/openssl-devel-*.rpm \
    /opt/offline_packages/rpm/libffi-devel-*.rpm 2>/dev/null || true

# 확인
python3.13 --version  # Python 3.11.x
```

### 5.2 대안 — pyenv로 소스 빌드 (Rocky Linux 8에서 Python 3.13이 없을 경우)

```bash
# 빌드 의존성 설치
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y openssl-devel bzip2-devel libffi-devel \
    zlib-devel readline-devel sqlite-devel xz-devel

# Python 3.11 소스 빌드 (오프라인: python-3.13.x.tar.gz 복사 후)
tar -xzf python-3.13.9.tgz
cd python-3.13.9
./configure --enable-optimizations --with-ensurepip=install
make -j$(nproc)
sudo make altinstall

python3.13 --version  # Python 3.11.9
```

---

## 6. NetGuard 애플리케이션 설치

### 6.1 전용 사용자 및 디렉토리 생성

```bash
# 서비스 전용 사용자 (로그인 불가)
sudo useradd -r -s /sbin/nologin -d /opt/netguard netguard

# 설치 디렉토리
sudo mkdir -p /opt/netguard
sudo chown netguard:netguard /opt/netguard
```

### 6.2 소스 파일 배포

```bash
# USB 또는 파일 서버에서 복사
sudo cp -r /media/usb/NetGuard_v1.0.0/* /opt/netguard/
sudo chown -R netguard:netguard /opt/netguard/
```

### 6.3 Python 가상환경 생성

```bash
cd /opt/netguard
sudo -u netguard python3.13 -m venv venv

# 가상환경 활성화
source venv/bin/activate
python --version  # Python 3.11.x
```

### 6.4 패키지 오프라인 설치

```bash
source /opt/netguard/venv/bin/activate

pip install --no-index \
    --find-links /opt/offline_packages/pip \
    -r /opt/netguard/requirements.txt

# 설치 확인
pip list | grep -E "fastapi|asyncpg|pysnmp|uvicorn|aiohttp"
```

### 6.5 디렉토리 권한 설정

```bash
sudo mkdir -p /opt/netguard/{logs,data/nvd_cache,config}
sudo chown -R netguard:netguard /opt/netguard/
sudo chmod 750 /opt/netguard/logs /opt/netguard/data /opt/netguard/config

# 설정 파일 권한
sudo chmod 640 /opt/netguard/config/config.yaml
sudo chown netguard:netguard /opt/netguard/config/config.yaml
```

---

## 7. 데이터베이스 초기화

### 7.1 DB 사용자 및 데이터베이스 생성

```bash
sudo -u postgres psql << 'EOF'
-- 전용 사용자 생성
CREATE USER netguard WITH PASSWORD 'NetGuard@2025!';

-- 데이터베이스 생성
CREATE DATABASE netguard OWNER netguard;

-- 권한 부여
GRANT ALL PRIVILEGES ON DATABASE netguard TO netguard;

-- netguard DB로 전환하여 확장 활성화
\c netguard
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
GRANT ALL ON SCHEMA public TO netguard;

\q
EOF
```

### 7.2 NetGuard 스키마 초기화

```bash
cd /opt/netguard
sudo -u netguard bash -c "
    source venv/bin/activate
    export PYTHONPATH=/opt/netguard/backend
    export NETGUARD_DB_HOST=localhost
    export NETGUARD_DB_PORT=5432
    export NETGUARD_DB_USER=netguard
    export NETGUARD_DB_PASSWORD='NetGuard@2025!'
    export NETGUARD_DB_NAME=netguard
    python - <<'PY'
import asyncio
from database import init_db, close_db_pool

async def main():
    await init_db()
    await close_db_pool()

asyncio.run(main())
PY
"
```

> `scripts/setup_db.py`는 수동 진단용 대화식 스크립트입니다.
> 자동 설치/운영 초기화에서는 `netguard` DB 사용자로 `database.init_db()`를 실행하세요.

### 7.3 초기화 확인

```bash
PGPASSWORD='NetGuard@2025!' psql -U netguard -h localhost -d netguard -c "\dt"
# devices, events, metrics, thresholds, vulnerabilities 등 출력 확인
```

---

## 8. 설정 파일 구성

```bash
sudo vi /opt/netguard/config/config.yaml
```

```yaml
# ===== Database =====
db_host: localhost
db_port: 5432
db_user: netguard
db_password: "NetGuard@2025!"    # 7.1에서 설정한 암호
db_name: netguard
nvd_cache_dir: /opt/netguard/data/nvd_cache

# ===== SNMP =====
snmp_community: public
snmp_timeout: 5
snmp_retries: 2
snmp_poll_interval: 60

# ===== 이메일 알림 =====
smtp_host: mail.company.local
smtp_port: 25
smtp_from: noreply@company.local
alert_emails:
  - admin@company.local
  - ops@company.local

# ===== 카카오톡 (오프라인 환경) =====
kakao_enabled: false

# ===== 라즈베리파이 =====
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
humi_warn_low: 40.0
ups_batt_warn: 30.0
ups_batt_crit: 15.0
```

### 8.1 기동 전 테스트

```bash
cd /opt/netguard/backend
source ../venv/bin/activate

python -m uvicorn app:app --host 127.0.0.1 --port 8000
# INFO:     Application startup complete. 확인 → Ctrl+C 종료
```

---

## 9. systemd 서비스 등록

```bash
sudo tee /etc/systemd/system/netguard.service << 'EOF'
[Unit]
Description=NetGuard SNMP Dashboard
Documentation=file:///opt/netguard/docs/GUIDE.md
After=network.target postgresql-18.service
Requires=postgresql-18.service

[Service]
Type=exec
User=netguard
Group=netguard
WorkingDirectory=/opt/netguard/backend
Environment=PYTHONPATH=/opt/netguard/backend
Environment=PYTHONUNBUFFERED=1
Environment=NETGUARD_LOG_DIR=/opt/netguard/logs
Environment=NETGUARD_NVD_CACHE_DIR=/opt/netguard/data/nvd_cache
ExecStart=/opt/netguard/venv/bin/uvicorn app:app \
    --host 0.0.0.0 \
    --port 8000 \
    --workers 1 \
    --log-level info \
    --access-log

Restart=on-failure
RestartSec=5
StartLimitInterval=60
StartLimitBurst=3

# 보안 강화
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/opt/netguard/logs /opt/netguard/data /opt/netguard/config

# 리소스 제한
LimitNOFILE=65536
MemoryMax=2G

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now netguard

# 상태 확인
sudo systemctl status netguard
```

### 9.1 서비스 관리 명령어

```bash
# 상태 확인
sudo systemctl status netguard

# 시작 / 중지 / 재시작
sudo systemctl start netguard
sudo systemctl stop netguard
sudo systemctl restart netguard

# 실시간 로그
sudo journalctl -u netguard -f

# 최근 100줄 로그
sudo journalctl -u netguard -n 100 --no-pager

# 금일 로그
sudo journalctl -u netguard --since today
```

---

## 10. 방화벽 및 SELinux 설정

### 10.1 firewalld 설정

```bash
# 대시보드 포트 허용
sudo firewall-cmd --permanent --add-port=8000/tcp

# SNMP Trap 수신 (선택)
sudo firewall-cmd --permanent --add-port=162/udp

# 내부망에서만 허용 (보안 강화)
sudo firewall-cmd --permanent --zone=internal \
    --add-source=192.168.1.0/24
sudo firewall-cmd --permanent --zone=internal \
    --add-port=8000/tcp

sudo firewall-cmd --reload

# 확인
sudo firewall-cmd --list-all
```

### 10.2 SELinux 설정

```bash
# SELinux 상태 확인
getenforce
# Enforcing / Permissive / Disabled

# SELinux가 Enforcing이고 포트 차단 시 포트 허용
sudo semanage port -a -t http_port_t -p tcp 8000

# Python 프로세스의 네트워크 바인딩 허용
sudo setsebool -P httpd_can_network_connect on

# SELinux 감사 로그 확인 (차단된 항목)
sudo ausearch -c uvicorn --raw | audit2allow -M netguard
sudo semodule -i netguard.pp

# SELinux 컨텍스트 설정 (필요 시)
sudo semanage fcontext -a -t bin_t "/opt/netguard/venv/bin(/.*)?"
sudo restorecon -Rv /opt/netguard/
```

### 10.3 SNMP 발신 허용 확인

```bash
# 모니터링 서버에서 장비로 UDP/161 발신 테스트
snmpwalk -v2c -c public 192.168.1.10 .1.3.6.1.2.1.1.1.0

# 실패 시 방화벽 아웃바운드 확인 (Rocky Linux는 기본 아웃바운드 허용)
sudo firewall-cmd --list-all | grep -E "forward|masquerade"
```

---

## 11. SNMP 장비 등록

### 11.1 Rocky Linux 서버 (모니터링 대상 서버) SNMP 설정

```bash
# 모니터링 대상 Rocky Linux 서버에서 실행
sudo dnf localinstall /opt/offline_packages/rpm/net-snmp*.rpm

sudo tee /etc/snmp/snmpd.conf << 'EOF'
# 읽기 전용 Community (모니터링 서버 IP 대역)
rocommunity  public  192.168.1.0/24

# 시스템 정보
syslocation  "서버실 A랙 1번"
syscontact   admin@company.local

# 허용 MIB 뷰
view   systemview  included  .1.3.6.1.2.1.1
view   systemview  included  .1.3.6.1.2.1.25      # Host Resources
view   systemview  included  .1.3.6.1.4.1.2021    # UCD SNMP
view   systemview  included  .1.3.6.1.2.1.2       # Interfaces
view   systemview  included  .1.3.6.1.2.1.31      # ifXTable (64bit)

# 접근 제어
access  notConfigGroup ""  any  noauth  exact  systemview  none  none
EOF

sudo systemctl enable --now snmpd
sudo firewall-cmd --permanent --add-port=161/udp
sudo firewall-cmd --reload

# 동작 확인 (모니터링 서버에서)
snmpwalk -v2c -c public 192.168.1.11 1.3.6.1.2.1.25.3.3.1.2
# hrProcessorLoad 값 출력 확인

# 디스크/파티션 상세: Linux는 파티션별, Windows는 디스크별 용량 표시의 원천 데이터
snmpwalk -v2c -c public 192.168.1.11 1.3.6.1.2.1.25.2.3.1.3
snmpwalk -v2c -c public 192.168.1.11 1.3.6.1.2.1.25.2.3.1.5

# 실행 중인 프로세스: hrSWRun/hrSWRunPerf 지원 여부 확인
snmpwalk -v2c -c public 192.168.1.11 1.3.6.1.2.1.25.4.2.1.2
snmpwalk -v2c -c public 192.168.1.11 1.3.6.1.2.1.25.5.1.1.2
```

### 11.2 SNMPv3 설정 (보안 강화)

```bash
# 서비스 중지 후 사용자 추가
sudo systemctl stop snmpd

# SNMPv3 사용자 생성 (SHA 인증, AES 암호화)
sudo net-snmp-create-v3-user -ro -A "AuthPassword2025!" \
    -a SHA -X "PrivPassword2025!" -x AES netguardv3

sudo systemctl start snmpd
```

config.yaml에서 특정 장비에 v3 사용:
```yaml
# 장비 등록 시 API 사용
# POST /api/devices
# {
#   "snmp_version": "v3",
#   "snmp_v3_user": "netguardv3",
#   "snmp_v3_auth": "AuthPassword2025!",
#   "snmp_v3_priv": "PrivPassword2025!"
# }
```

### 11.3 Cisco 스위치 SNMP 설정

```
! Cisco IOS / IOS XE
configure terminal

! SNMP v2c
snmp-server community public RO
snmp-server location "IDC 스위치룸"
snmp-server contact admin@company.local
snmp-server host 10.60.8.187 version 2c public

! 인터페이스 설명 추가 (포트맵에 표시됨)
interface GigabitEthernet1/0/1
 description SRV-WEB-01

! 저장
end
write memory

! 확인
show snmp
```

### 11.4 UPS SNMP 설정 (APC 예시)

```
APC UPS 웹 인터페이스 (http://UPS_IP):
  Configuration → SNMP → Community Name: public
  Configuration → SNMP → Access Type: Read Only
  Configuration → SNMP → NMS IP: 10.60.8.187 (모니터링 서버)
```

### 11.5 대시보드에서 장비 등록

```
http://10.60.8.187:8000 접속
→ 장비 관리 → + 장비 추가
→ 장비명, 유형, IP, SNMP 버전 입력
```

또는 API로 일괄 등록:
```bash
# 서버 등록 예시
curl -X POST http://localhost:8000/api/devices \
  -H "Content-Type: application/json" \
  -d '{
    "name": "SRV-WEB-01",
    "type": "server",
    "ip_address": "192.168.1.10",
    "snmp_version": "v2c",
    "community": "public",
    "os_version": "Rocky Linux 9.3",
    "location": "서버실 A랙"
  }'

# 스위치 등록
curl -X POST http://localhost:8000/api/devices \
  -H "Content-Type: application/json" \
  -d '{
    "name": "SW-CORE-01",
    "type": "switch",
    "ip_address": "192.168.1.1",
    "snmp_version": "v2c",
    "community": "public",
    "os_version": "Cisco IOS XE 17.9"
  }'
```

---

## 12. CVE 취약점 DB 오프라인 구성

### 12.1 인터넷 환경에서 오프라인 반입용 NVD 피드 다운로드

```bash
# 인터넷 환경 PC (Rocky Linux)
cd /opt/netguard
source venv/bin/activate
export NVD_API_KEY='발급받은_NVD_API_KEY'

python scripts/download_nvd.py --years 2024 2025 2026

# 파일 확인
ls -lh data/nvd_cache/
# nvdcve-20xx.json 파일들과 cache_meta.json
```

### 12.2 오프라인 서버로 전송

```bash
# rsync (내부 네트워크 파일 서버 경유)
rsync -avz data/nvd_cache/ admin@10.60.8.187:/opt/netguard/data/nvd_cache/

# USB를 통한 복사
cp -r data/nvd_cache/* /media/usb/nvd_cache/
# 오프라인 서버에서:
cp -r /media/usb/nvd_cache/* /opt/netguard/data/nvd_cache/
sudo chown -R netguard:netguard /opt/netguard/data/nvd_cache/
```

### 12.3 서비스 재시작 및 로딩 확인

```bash
sudo systemctl restart netguard

# 로딩 확인 (약 30초 소요)
sudo journalctl -u netguard -f | grep -E "CVE|nvd|vuln"
# "Loaded XXXXX CVE entries from local NVD cache" 출력 확인

# API 확인
curl -s http://localhost:8000/api/security/cves | python3 -m json.tool | head -30
```

### 12.4 실시간 증분 업데이트 (인터넷 연결 가능 환경)

```bash
# 수동 1회 증분 반영
export NVD_API_KEY='발급받은_NVD_API_KEY'
python scripts/update_nvd_cache.py --hours 2

# systemd timer 설치
sudo mkdir -p /etc/netguard
sudo tee /etc/netguard/nvd-update.env >/dev/null <<'EOF'
NVD_API_KEY=발급받은_NVD_API_KEY
EOF
sudo chmod 600 /etc/netguard/nvd-update.env
sudo cp deploy/systemd/netguard-nvd-update.service /etc/systemd/system/
sudo cp deploy/systemd/netguard-nvd-update.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now netguard-nvd-update.timer
systemctl list-timers netguard-nvd-update.timer
```

> 운영망이 완전 오프라인이면 timer는 사용하지 않고, 인터넷 가능한 별도 PC에서 생성한 `nvdcve-*.json`과 `cache_meta.json`만 반입한다.

---

## 13. 라즈베리파이 센서 연동

### 13.1 라즈베리파이 센서 서버 설치

```bash
# 라즈베리파이에서 실행 (인터넷 또는 오프라인 pip)
pip3 install flask adafruit-circuitpython-dht \
    adafruit-blinka RPi.GPIO

cat > /home/pi/sensor_server.py << 'EOF'
"""라즈베리파이 DHT22/BME280 센서 HTTP 서버"""
from flask import Flask, jsonify
import time

app = Flask(__name__)

# DHT22 사용 시
try:
    import adafruit_dht
    import board
    _sensor = adafruit_dht.DHT22(board.D4)
    SENSOR_TYPE = "DHT22"
except Exception:
    _sensor = None
    SENSOR_TYPE = "MOCK"

def read_dht22():
    for _ in range(5):
        try:
            return _sensor.temperature, _sensor.humidity
        except Exception:
            time.sleep(2)
    return None, None

@app.route('/sensor')
def get_sensor():
    if SENSOR_TYPE == "MOCK":
        return jsonify({'temperature': 23.4, 'humidity': 45.0, 'source': 'mock'})
    temp, humi = read_dht22()
    if temp is None:
        return jsonify({'error': 'sensor_read_failed'}), 500
    return jsonify({
        'temperature': round(temp, 1),
        'humidity': round(humi, 1),
        'source': SENSOR_TYPE,
        'unit': 'celsius'
    })

@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'sensor': SENSOR_TYPE})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8765)
EOF

# systemd 등록
sudo tee /etc/systemd/system/sensor.service << 'EOF'
[Unit]
Description=NetGuard Sensor API
After=network.target

[Service]
ExecStart=/usr/bin/python3 /home/pi/sensor_server.py
Restart=always
User=pi
WorkingDirectory=/home/pi

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now sensor

# 방화벽 (Raspberry Pi OS는 ufw 또는 iptables)
sudo ufw allow 8765/tcp
```

### 13.2 NetGuard 설정 활성화

```bash
sudo vi /opt/netguard/config/config.yaml
```

```yaml
rpi_enabled: true
rpi_ip: 192.168.1.60
rpi_port: 8765
```

```bash
# 연결 테스트
curl http://192.168.1.60:8765/sensor
# {"temperature": 23.4, "humidity": 45.0, ...}

sudo systemctl restart netguard
```

---

## 14. 알림 설정

### 14.1 내부 SMTP (Postfix 릴레이)

```bash
# 모니터링 서버에 Postfix 설치 (내부 릴레이로 사용)
sudo dnf localinstall /opt/offline_packages/rpm/postfix*.rpm

sudo tee -a /etc/postfix/main.cf << 'EOF'
# 내부 메일 릴레이 설정
myhostname = netguard-srv.company.local
mydomain = company.local
myorigin = $mydomain
relayhost = [mail.company.local]:25
EOF

sudo systemctl enable --now postfix

# 테스트
echo "Test from NetGuard" | mail -s "Test" admin@company.local
```

config.yaml:
```yaml
smtp_host: localhost
smtp_port: 25
smtp_from: noreply@netguard-srv.company.local
```

### 14.2 카카오톡 설정 (외부 인터넷 접속 가능 시)

```yaml
kakao_enabled: true
kakao_rest_key: "발급받은_REST_API_KEY"
kakao_channel_token: "채널_토큰"
```

```bash
sudo systemctl restart netguard
```

대시보드 → 알림 설정 → 테스트 메시지 발송으로 확인

### 14.3 알림 로그 확인

```bash
# 발송된 알림 로그
grep -E "ALERT|Email|Kakao" /opt/netguard/logs/netguard.log | tail -20

# 알림 이력 DB 조회
PGPASSWORD='NetGuard@2025!' psql -U netguard -d netguard -h localhost -c \
    "SELECT channel, recipient, status, time FROM notification_log ORDER BY time DESC LIMIT 10;"
```

---

## 15. 운영 및 관리

### 15.1 일상 점검 명령어 모음

```bash
# 서비스 전체 상태
echo "=== NetGuard ===" && systemctl is-active netguard
echo "=== PostgreSQL ===" && systemctl is-active postgresql-18

# 최근 에러 로그
sudo journalctl -u netguard -p err -n 20 --no-pager

# DB 연결 수
PGPASSWORD='NetGuard@2025!' psql -U netguard -d netguard -h localhost -c \
    "SELECT count(*) AS connections FROM pg_stat_activity WHERE datname='netguard';"

# 최신 수집 데이터 확인
PGPASSWORD='NetGuard@2025!' psql -U netguard -d netguard -h localhost -c \
    "SELECT d.name, m.metric_name, round(m.value::numeric,1) AS value, m.time
     FROM metrics m JOIN devices d ON d.id=m.device_id
     WHERE m.time >= NOW()-INTERVAL '5 min' ORDER BY m.time DESC LIMIT 20;"

# 활성 이벤트 확인
PGPASSWORD='NetGuard@2025!' psql -U netguard -d netguard -h localhost -c \
    "SELECT severity, count(*) FROM events WHERE status='active' GROUP BY severity;"

# 시스템 자원 사용량
echo "=== CPU/MEM ===" && top -b -n1 | head -5
echo "=== Disk ===" && df -h /opt/netguard
echo "=== DB Size ===" && PGPASSWORD='NetGuard@2025!' psql -U netguard -d netguard \
    -h localhost -c "SELECT pg_size_pretty(pg_database_size('netguard'));"
```

### 15.2 TimescaleDB 관리

```bash
# hypertable 통계
PGPASSWORD='NetGuard@2025!' psql -U netguard -d netguard -h localhost << 'EOF'
-- 청크 현황
SELECT
    hypertable_name,
    num_chunks,
    pg_size_pretty(hypertable_size(format('%I', hypertable_name)::regclass)) AS total_size,
    pg_size_pretty(hypertable_detailed_size(format('%I', hypertable_name)::regclass) ->> 'compressed_total_size') AS compressed_size
FROM timescaledb_information.hypertables;

-- 압축 통계
SELECT
    hypertable_name,
    num_compressed_chunks,
    pg_size_pretty(after_compression_total_bytes) AS after_compress,
    pg_size_pretty(before_compression_total_bytes) AS before_compress,
    round(100.0 * after_compression_total_bytes / NULLIF(before_compression_total_bytes, 0), 1) AS compression_ratio_pct
FROM timescaledb_information.hypertable_compression_stats;

-- 보존 정책 확인
SELECT * FROM timescaledb_information.jobs WHERE proc_name='policy_retention';
\q
EOF
```

### 15.3 로그 로테이션 설정

```bash
sudo tee /etc/logrotate.d/netguard << 'EOF'
/opt/netguard/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        systemctl reload netguard 2>/dev/null || true
    endscript
}
EOF

# 수동 테스트
sudo logrotate -d /etc/logrotate.d/netguard
```

### 15.4 성능 모니터링 (cron)

```bash
# 매 5분마다 시스템 상태 기록
crontab -e -u netguard
```

```cron
*/5 * * * * /usr/bin/curl -s http://localhost:8000/health >> /opt/netguard/logs/health.log 2>&1
0 * * * * /usr/bin/df -h /opt/netguard >> /opt/netguard/logs/disk.log 2>&1
```

---

## 16. 백업 및 복구

### 16.1 DB 백업 스크립트

```bash
sudo tee /opt/netguard/scripts/backup.sh << 'EOF'
#!/bin/bash
set -e

BACKUP_DIR="/opt/backup/netguard"
DATE=$(date +%Y%m%d_%H%M%S)
KEEP_DAYS=30

mkdir -p "$BACKUP_DIR"

# DB 덤프 (압축 포함)
PGPASSWORD='NetGuard@2025!' pg_dump \
    -U netguard -h localhost -d netguard \
    -Fc -Z 9 \
    -f "$BACKUP_DIR/netguard_$DATE.dump"

echo "[$(date)] Backup saved: netguard_$DATE.dump ($(du -sh $BACKUP_DIR/netguard_$DATE.dump | cut -f1))"

# 설정 파일 백업
cp /opt/netguard/config/config.yaml "$BACKUP_DIR/config_$DATE.yaml"

# 오래된 백업 삭제
find "$BACKUP_DIR" -name "*.dump" -mtime +$KEEP_DAYS -delete
find "$BACKUP_DIR" -name "*.yaml" -mtime +$KEEP_DAYS -delete

echo "[$(date)] Cleanup done. Current backups:"
ls -lh "$BACKUP_DIR" | tail -10
EOF

sudo chmod +x /opt/netguard/scripts/backup.sh

# cron 등록 (매일 새벽 2시)
echo "0 2 * * * /opt/netguard/scripts/backup.sh >> /opt/netguard/logs/backup.log 2>&1" | \
    sudo tee /etc/cron.d/netguard-backup
```

### 16.2 백업 복구

```bash
# 서비스 중지
sudo systemctl stop netguard

# DB 복구
PGPASSWORD='NetGuard@2025!' pg_restore \
    -U netguard -h localhost -d netguard \
    --clean --if-exists \
    /opt/backup/netguard/netguard_20250507_020000.dump

# 서비스 재시작
sudo systemctl start netguard

# 복구 확인
sudo journalctl -u netguard -n 20
curl http://localhost:8000/health
```

### 16.3 전체 시스템 복구 (신규 서버)

```bash
# 1. Rocky Linux 설치 (섹션 1~9 반복)
# 2. 백업에서 DB 복구 (섹션 16.2)
# 3. 설정 파일 복구
cp /opt/backup/netguard/config_latest.yaml /opt/netguard/config/config.yaml
# 4. NVD 캐시 복사
cp -r /opt/backup/nvd_cache/* /opt/netguard/data/nvd_cache/
# 5. 서비스 시작
sudo systemctl start netguard
```

---

## 17. 업데이트 절차

### 17.1 애플리케이션 업데이트

```bash
# 1. 현재 버전 백업
DATE=$(date +%Y%m%d)
sudo cp -r /opt/netguard/backend /opt/backup/netguard/backend_$DATE
sudo cp -r /opt/netguard/frontend /opt/backup/netguard/frontend_$DATE

# 2. 서비스 중지
sudo systemctl stop netguard

# 3. 새 파일 배포
sudo cp -r /media/usb/update/backend/* /opt/netguard/backend/
sudo cp -r /media/usb/update/frontend/* /opt/netguard/frontend/
sudo chown -R netguard:netguard /opt/netguard/

# 4. 패키지 업데이트 (있을 경우)
sudo -u netguard bash -c "
    source /opt/netguard/venv/bin/activate
    pip install --no-index --find-links /media/usb/update/pip \
        -r /opt/netguard/requirements.txt
"

# 5. DB 마이그레이션 (있을 경우)
cd /opt/netguard
sudo -u netguard bash -c "
    source venv/bin/activate && python scripts/migrate.py
"

# 6. 서비스 재시작
sudo systemctl start netguard

# 7. 동작 확인
sleep 5
curl http://localhost:8000/health
sudo journalctl -u netguard -n 20 --no-pager
```

### 17.2 가이드 문서 업데이트

```bash
# 업데이트 시마다 GUIDE.md 및 INSTALL_ROCKY.md의 업데이트 내역 섹션 수정
vi /opt/netguard/docs/GUIDE.md
# 업데이트 내역에 버전, 날짜, 변경사항 추가
```

---

## 18. 문제 해결

### SNMP 수집 실패

```bash
# 장비 접근 테스트
snmpwalk -v2c -c public -t 5 192.168.1.10 .1.3.6.1.2.1.1

# 방화벽 확인 (모니터링 서버에서 발신)
sudo iptables -L OUTPUT -n | grep 161

# tcpdump로 SNMP 패킷 추적
sudo tcpdump -i eth0 -n udp port 161 -c 20

# SELinux 차단 확인
sudo ausearch -c python3 --recent | grep denied
```

### Linux 메모리 사용률이 과도하게 높게 표시됨

Linux는 남는 메모리를 파일 cache/buffer로 적극 사용합니다. `top`에서 `buff/cache`가 큰 경우,
단순히 `(total - free) / total`로 계산하면 실제보다 높게 표시됩니다. NetGuard는 UCD-SNMP의
`memAvailReal`, `memBuffer`, `memCached`를 합산해 cache/buffer를 제외한 사용률로 계산합니다.

```bash
# 대상 Linux 서버에서 top 기준 확인
top

# NetGuard 서버에서 UCD-SNMP 메모리 OID 확인
snmpget -v2c -c stanley 대상서버IP \
  .1.3.6.1.4.1.2021.4.5.0 \
  .1.3.6.1.4.1.2021.4.6.0 \
  .1.3.6.1.4.1.2021.4.14.0 \
  .1.3.6.1.4.1.2021.4.15.0
```

예를 들어 `top`에서 아래처럼 보이면 실제 사용률은 약 31%입니다.

```text
total=8008948, free=224848, buff/cache=5307072
used_without_cache = total - free - buff/cache
```

SNMP 설정에서 `.1.3.6.1.4.1.2021` UCD-SNMP view가 막혀 있으면 buffer/cache 값이 수집되지 않아
메모리가 과대 표시될 수 있습니다. 이 경우 대상 서버의 `/etc/snmp/snmpd.conf`에 아래 view가 포함되어야 합니다.

```text
view   systemview  included  .1.3.6.1.4.1.2021
```

### Windows 서버 메모리 정보가 표시되지 않음

Windows SNMP Service는 Linux UCD-SNMP 메모리 OID(`.1.3.6.1.4.1.2021.4`)를 제공하지 않습니다.
NetGuard는 Windows 메모리를 Host Resources MIB의 `hrStorage` 중 `Physical Memory` 항목으로 계산합니다.

```bash
# NetGuard 서버에서 Windows 대상 서버 확인
snmpwalk -v2c -c stanley 대상서버IP .1.3.6.1.2.1.25.2.3.1.3
snmpwalk -v2c -c stanley 대상서버IP .1.3.6.1.2.1.25.2.3.1.5
snmpwalk -v2c -c stanley 대상서버IP .1.3.6.1.2.1.25.2.3.1.6
```

첫 번째 명령 결과에 `Physical Memory`가 보여야 합니다. 값이 없으면 Windows SNMP Service의 보안 탭에서
Community와 허용 호스트를 확인하고, Windows 방화벽에서 UDP/161 인바운드를 허용한 뒤 SNMP Service를 재시작합니다.

### 서비스 시작 실패

```bash
# 상세 오류 확인
sudo journalctl -u netguard -n 50 --no-pager

# 수동 기동으로 오류 메시지 확인
sudo -u netguard bash -c "
    source /opt/netguard/venv/bin/activate
    cd /opt/netguard/backend
    python -m uvicorn app:app --host 127.0.0.1 --port 8000
"

# DB 연결 오류 시
sudo -u netguard PGPASSWORD='NetGuard@2025!' psql \
    -U netguard -h localhost -d netguard -c "SELECT 1"
```

#### Python 모듈 누락

`ModuleNotFoundError: No module named 'yaml'`처럼 Python 모듈 오류가 나오면 venv 의존성이 설치되지 않은 상태입니다.

```bash
cd /opt/netguard
sudo /opt/netguard/venv/bin/pip install -r requirements.txt
sudo -u netguard /opt/netguard/venv/bin/python - <<'PY'
import yaml, fastapi, uvicorn, asyncpg, pysnmp, aiohttp, pydantic, apscheduler
print("python modules ok")
PY
sudo systemctl restart netguard
```

완전 오프라인 서버라면 인터넷 가능한 Rocky 서버에서 `scripts/collect_packages_rocky.sh`를 실행해
`/opt/offline_packages/pip`를 채운 뒤 다시 설치합니다.

#### 로그 경로/읽기 전용 파일시스템 오류

`OSError: [Errno 30] Read-only file system: '/opt/netguard/backend/logs/netguard.log'`가 보이면
서비스 환경변수와 쓰기 허용 경로가 빠진 상태입니다.

```bash
sudo mkdir -p /opt/netguard/logs
sudo chown netguard:netguard /opt/netguard/logs
sudo grep -q 'NETGUARD_LOG_DIR' /etc/systemd/system/netguard.service || \
sudo sed -i '/Environment=PYTHONUNBUFFERED=1/a Environment=NETGUARD_LOG_DIR=/opt/netguard/logs' /etc/systemd/system/netguard.service
sudo systemctl daemon-reload
sudo systemctl restart netguard
```

#### NVD 캐시 경로 오류

`OSError: [Errno 30] Read-only file system: 'data'`가 `CVEChecker`에서 발생하면
상대경로 `data/nvd_cache`가 `/opt/netguard/backend/data`로 해석된 것입니다.

```bash
sudo mkdir -p /opt/netguard/data/nvd_cache
sudo chown -R netguard:netguard /opt/netguard/data
sudo grep -q 'NETGUARD_NVD_CACHE_DIR' /etc/systemd/system/netguard.service || \
sudo sed -i '/Environment=NETGUARD_LOG_DIR=/a Environment=NETGUARD_NVD_CACHE_DIR=/opt/netguard/data/nvd_cache' /etc/systemd/system/netguard.service
sudo systemctl daemon-reload
sudo systemctl restart netguard
```

#### DB 초기화 동시 실행 오류

`duplicate key value violates unique constraint "pg_type_typname_nsp_index"`가 보이면
여러 uvicorn worker가 동시에 스키마를 만들며 충돌한 경우입니다.

```bash
sudo sed -i 's/--workers 2/--workers 1/' /etc/systemd/system/netguard.service
sudo systemctl daemon-reload
sudo systemctl restart netguard
```

현재 소스는 DB advisory lock을 사용해 동시 초기화 충돌을 방지하지만,
초기 설치 시에는 `--workers 1` 구성이 가장 안정적입니다.

### 데이터베이스 용량 급증

```bash
# 용량 확인
PGPASSWORD='NetGuard@2025!' psql -U netguard -d netguard -h localhost -c "
SELECT
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;"

# 수동 압축 (TimescaleDB)
PGPASSWORD='NetGuard@2025!' psql -U netguard -d netguard -h localhost -c "
SELECT compress_chunk(c) FROM show_chunks('metrics') c
WHERE create_time < NOW() - INTERVAL '7 days';"

# 오래된 데이터 수동 삭제
PGPASSWORD='NetGuard@2025!' psql -U netguard -d netguard -h localhost -c "
SELECT drop_chunks('metrics', INTERVAL '90 days');"
```

### 메모리 부족

```bash
# 메모리 사용 현황
free -h
ps aux --sort=-%mem | head -10

# PostgreSQL 메모리 설정 조정
sudo vi /var/lib/pgsql/18/data/postgresql.conf
# shared_buffers = 512MB  ← 줄임
sudo systemctl restart postgresql-18

# Python 워커 수 조정
sudo vi /etc/systemd/system/netguard.service
# --workers 2 → --workers 1
sudo systemctl daemon-reload
sudo systemctl restart netguard
```

### 시간 동기화 문제 (메트릭 시간 오류)

```bash
# 현재 시간 확인
date
timedatectl

# NTP 상태 확인
chronyc tracking

# 강제 동기화
sudo chronyc makestep
```

---

*NetGuard SNMP Dashboard — Rocky Linux 설치 메뉴얼 v1.2.1 (2026-05-14)*
