#!/bin/bash
# =============================================================================
# NetGuard SNMP Dashboard — Rocky Linux 자동 설치 스크립트
# 대상: Rocky Linux 8.x / 9.x (x86_64) — 오프라인 환경
#
# 사전 조건:
#   - /opt/offline_packages/rpm/   : PostgreSQL18, TimescaleDB, Python3.13 RPM
#   - /opt/offline_packages/pip/   : NetGuard Python 패키지 wheel 파일
#   - 소스코드가 이미 /opt/netguard/ 에 있거나 USB에서 복사 예정
#
# 실행: sudo bash install_rocky.sh
# =============================================================================
set -euo pipefail

# ── 색상 코드 ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

step()  { echo -e "\n${BLUE}[STEP]${NC} $1"; }
ok()    { echo -e "${GREEN}[OK]${NC}   $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
info()  { echo -e "${CYAN}[INFO]${NC} $1"; }

# ── 루트 확인 ─────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "이 스크립트는 root(sudo) 권한으로 실행해야 합니다."

# ── 스크립트 위치 → 소스 루트 ─────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# 스크립트가 소스의 scripts/ 안에 있을 경우 부모 디렉토리가 소스 루트
SOURCE_DIR="$(dirname "$SCRIPT_DIR")"

# ── 설치 경로 및 패키지 경로 ───────────────────────────────────────────────────
INSTALL_DIR="/opt/netguard"
RPM_DIR="/opt/offline_packages/rpm"
PIP_DIR="/opt/offline_packages/pip"
PG_DATA="/var/lib/pgsql/18/data"
PG_BIN="/usr/pgsql-18/bin"

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     NetGuard SNMP Dashboard — Rocky Linux 설치 마법사    ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── 설치 전 입력값 수집 ───────────────────────────────────────────────────────
echo -e "${YELLOW}설치에 필요한 정보를 입력하세요. [기본값]을 사용하려면 Enter를 누르세요.${NC}"
echo ""

read -rp "호스트명              [netguard-srv]: " INPUT_HOSTNAME
HOSTNAME_SET="${INPUT_HOSTNAME:-netguard-srv}"

read -rp "DB 비밀번호           [NetGuard@2025!]: " INPUT_DB_PASS
DB_PASS="${INPUT_DB_PASS:-NetGuard@2025!}"

read -rp "SNMP Community       [public]: " INPUT_COMMUNITY
SNMP_COMMUNITY="${INPUT_COMMUNITY:-public}"

read -rp "SMTP 서버 주소        [localhost]: " INPUT_SMTP
SMTP_HOST="${INPUT_SMTP:-localhost}"

read -rp "알림 이메일           [admin@company.local]: " INPUT_EMAIL
ALERT_EMAIL="${INPUT_EMAIL:-admin@company.local}"

read -rp "RPM 패키지 경로       [$RPM_DIR]: " INPUT_RPM
RPM_DIR="${INPUT_RPM:-$RPM_DIR}"

read -rp "pip 패키지 경로       [$PIP_DIR]: " INPUT_PIP
PIP_DIR="${INPUT_PIP:-$PIP_DIR}"

read -rp "소스코드 경로         [$SOURCE_DIR]: " INPUT_SRC
SOURCE_DIR="${INPUT_SRC:-$SOURCE_DIR}"

echo ""
echo -e "${YELLOW}입력 요약:${NC}"
echo "  호스트명     : $HOSTNAME_SET"
echo "  DB 비밀번호  : ****"
echo "  SNMP         : $SNMP_COMMUNITY"
echo "  SMTP 서버    : $SMTP_HOST"
echo "  알림 이메일  : $ALERT_EMAIL"
echo "  RPM 경로     : $RPM_DIR"
echo "  pip 경로     : $PIP_DIR"
echo "  소스 경로    : $SOURCE_DIR"
echo ""
read -rp "위 정보로 설치를 시작합니까? (y/N): " CONFIRM
[[ "${CONFIRM,,}" != "y" ]] && echo "설치가 취소되었습니다." && exit 0

# ── 2. 시스템 기본 설정 ───────────────────────────────────────────────────────
step "시스템 기본 설정"

hostnamectl set-hostname "$HOSTNAME_SET"
timedatectl set-timezone Asia/Seoul

# chrony (NTP) — RPM이 있으면 설치, 없으면 스킵
if ls "$RPM_DIR"/chrony*.rpm &>/dev/null; then
    dnf localinstall -y --nogpgcheck "$RPM_DIR"/chrony*.rpm 2>/dev/null || true
    systemctl enable --now chronyd 2>/dev/null || true
fi

ok "호스트명: $HOSTNAME_SET, 시간대: Asia/Seoul"

# ── 3. PostgreSQL 18 설치 ─────────────────────────────────────────────────────
step "PostgreSQL 18 설치"

if command -v psql &>/dev/null && psql --version 2>&1 | grep -q "18\."; then
    ok "PostgreSQL 18이 이미 설치되어 있습니다."
else
    if ls "$RPM_DIR"/postgresql18*.rpm &>/dev/null; then
        dnf localinstall -y --nogpgcheck \
            "$RPM_DIR"/postgresql18-libs-*.rpm \
            "$RPM_DIR"/postgresql18-18.*.rpm \
            "$RPM_DIR"/postgresql18-server-*.rpm \
            "$RPM_DIR"/postgresql18-contrib-*.rpm 2>/dev/null || \
        dnf localinstall -y --nogpgcheck "$RPM_DIR"/postgresql18*.rpm
        ok "PostgreSQL 18 RPM 설치 완료"
    else
        warn "RPM 파일을 찾을 수 없습니다 ($RPM_DIR). PostgreSQL 설치를 건너뜁니다."
    fi
fi

# 환경 변수 영구 설정
cat > /etc/profile.d/postgresql.sh << 'EOF'
export PATH=$PATH:/usr/pgsql-18/bin
export PGDATA=/var/lib/pgsql/18/data
EOF
source /etc/profile.d/postgresql.sh

# DB 초기화
if [[ ! -f "$PG_DATA/PG_VERSION" ]]; then
    "$PG_BIN/postgresql-18-setup" initdb
    ok "PostgreSQL 데이터베이스 초기화 완료"
else
    ok "PostgreSQL 데이터베이스가 이미 초기화되어 있습니다."
fi

# postgresql.conf 최적화 적용
RAM_GB=$(awk '/MemTotal/{printf "%.0f", $2/1024/1024}' /proc/meminfo)
CPU=$(nproc)
MAX_CONN=100
SB=$(( RAM_GB * 1024 / 4 )); [[ $SB -gt 8192 ]] && SB=8192
ECS=$(( RAM_GB * 1024 * 3 / 4 ))
WM=$(( RAM_GB * 1024 / 4 / MAX_CONN )); [[ $WM -lt 4 ]] && WM=4
MWM=$(( RAM_GB * 1024 / 20 )); [[ $MWM -gt 2048 ]] && MWM=2048
MPW=$(( CPU / 2 )); [[ $MPW -lt 2 ]] && MPW=2
TSBG=$CPU; [[ $TSBG -gt 16 ]] && TSBG=16

info "RAM: ${RAM_GB}GB, CPU: ${CPU}코어 → shared_buffers=${SB}MB, work_mem=${WM}MB"

# postgresql.conf 핵심 파라미터 적용 (sed로 기존 주석 라인 교체)
PG_CONF="$PG_DATA/postgresql.conf"

apply_conf() {
    local key=$1 val=$2
    if grep -qE "^#?${key}\s*=" "$PG_CONF"; then
        sed -i "s|^#\?${key}\s*=.*|${key} = ${val}|" "$PG_CONF"
    else
        echo "${key} = ${val}" >> "$PG_CONF"
    fi
}

apply_conf "listen_addresses"                "'localhost'"
apply_conf "max_connections"                 "$MAX_CONN"
apply_conf "shared_buffers"                  "${SB}MB"
apply_conf "effective_cache_size"            "${ECS}MB"
apply_conf "work_mem"                        "${WM}MB"
apply_conf "maintenance_work_mem"            "${MWM}MB"
apply_conf "wal_buffers"                     "64MB"
apply_conf "min_wal_size"                    "512MB"
apply_conf "max_wal_size"                    "4GB"
apply_conf "checkpoint_completion_target"    "0.9"
apply_conf "max_worker_processes"            "8"
apply_conf "max_parallel_workers"            "$MPW"
apply_conf "random_page_cost"               "1.1"
apply_conf "effective_io_concurrency"        "200"
apply_conf "logging_collector"               "on"
apply_conf "log_directory"                   "'/var/log/postgresql'"
apply_conf "log_filename"                    "'postgresql-%Y-%m-%d.log'"
apply_conf "log_rotation_age"                "1d"
apply_conf "log_min_duration_statement"      "1000"

# 로그 디렉토리
mkdir -p /var/log/postgresql
chown postgres:postgres /var/log/postgresql

# pg_hba.conf
cat > "$PG_DATA/pg_hba.conf" << 'EOF'
# TYPE  DATABASE  USER      ADDRESS       METHOD
local   all       postgres                peer
local   all       netguard                md5
host    all       netguard  127.0.0.1/32  md5
host    all       netguard  ::1/128       md5
EOF

systemctl enable --now postgresql-18
sleep 2
systemctl is-active postgresql-18 | grep -q active && ok "PostgreSQL 18 서비스 시작됨" || warn "PostgreSQL 서비스 상태를 확인하세요."

# ── 4. TimescaleDB 설치 ───────────────────────────────────────────────────────
step "TimescaleDB 설치"

if ls "$RPM_DIR"/timescaledb*.rpm &>/dev/null; then
    dnf localinstall -y --nogpgcheck "$RPM_DIR"/timescaledb-2-postgresql-18-*.rpm 2>/dev/null || \
    dnf localinstall -y --nogpgcheck "$RPM_DIR"/timescaledb*.rpm
    ok "TimescaleDB RPM 설치 완료"
else
    warn "TimescaleDB RPM을 찾을 수 없습니다. 수동 설치가 필요합니다."
fi

TIMESCALE_ENABLED=0
if rpm -q timescaledb-2-postgresql-18 &>/dev/null; then
    TIMESCALE_ENABLED=1
fi

if [[ "$TIMESCALE_ENABLED" -eq 1 ]]; then
    # TimescaleDB 설정 적용
    # postgresql.conf 기본값은 "#shared_preload_libraries = ''"처럼 주석 처리되어 있어
    # 단순 grep으로는 설정 여부를 판단하면 안 됩니다. apply_conf가 주석 라인도 치환합니다.
    apply_conf "shared_preload_libraries"                "'timescaledb'"
    apply_conf "timescaledb.max_background_workers"      "$TSBG"
    apply_conf "timescaledb.telemetry_level"             "off"
    apply_conf "timescaledb.max_cached_chunks_per_hypertable" "1024"
    apply_conf "timescaledb.enable_chunk_skipping"       "on"

    systemctl restart postgresql-18
    sleep 2
    systemctl is-active postgresql-18 &>/dev/null || error "PostgreSQL 재시작 실패. journalctl -u postgresql-18 -n 50 --no-pager 로 확인하세요."

    if sudo -u postgres psql -tAc "SHOW shared_preload_libraries;" | tr -d ' ' | grep -qw "timescaledb"; then
        ok "TimescaleDB 설정 적용 및 PostgreSQL 재시작 완료"
    else
        error "TimescaleDB preload 확인 실패: $PG_CONF 의 shared_preload_libraries 값을 확인하세요."
    fi
else
    warn "TimescaleDB 패키지가 설치되지 않아 PostgreSQL 기본 테이블 모드로 진행합니다."
fi

# ── 5. Python 3.13 설치 ───────────────────────────────────────────────────────
step "Python 3.13 설치"

if command -v python3.13 &>/dev/null; then
    ok "Python 3.13이 이미 설치되어 있습니다."
else
    if ls "$RPM_DIR"/python3.13*.rpm &>/dev/null; then
        dnf localinstall -y --nogpgcheck "$RPM_DIR"/python3.13*.rpm 2>/dev/null || true
        # gcc, openssl-devel 등도 설치 시도
        dnf localinstall -y --nogpgcheck \
            "$RPM_DIR"/gcc*.rpm \
            "$RPM_DIR"/openssl-devel*.rpm \
            "$RPM_DIR"/libffi-devel*.rpm 2>/dev/null || true
        ok "Python 3.13 RPM 설치 완료"
    else
        warn "Python 3.13 RPM을 찾을 수 없습니다. 시스템 기본 python3을 사용합니다."
    fi
fi

PYTHON_BIN=$(command -v python3.13 || command -v python3 || echo "python3")
info "사용할 Python: $PYTHON_BIN ($($PYTHON_BIN --version 2>&1))"

# ── 6. NetGuard 애플리케이션 설치 ─────────────────────────────────────────────
step "NetGuard 애플리케이션 설치"

# 전용 사용자 생성
if ! id netguard &>/dev/null; then
    useradd -r -s /sbin/nologin -d "$INSTALL_DIR" netguard
    ok "netguard 시스템 사용자 생성"
else
    ok "netguard 사용자 이미 존재"
fi

# 디렉토리 생성
mkdir -p "$INSTALL_DIR"/{logs,data/nvd_cache,config}
chown -R netguard:netguard "$INSTALL_DIR"

# 소스 파일 복사 (이미 있으면 스킵)
if [[ -f "$INSTALL_DIR/backend/app.py" ]]; then
    ok "소스 파일이 이미 $INSTALL_DIR 에 있습니다."
elif [[ -f "$SOURCE_DIR/backend/app.py" ]]; then
    cp -r "$SOURCE_DIR"/. "$INSTALL_DIR/"
    chown -R netguard:netguard "$INSTALL_DIR"
    ok "소스 파일 복사 완료: $SOURCE_DIR → $INSTALL_DIR"
else
    warn "소스 파일을 찾을 수 없습니다. $INSTALL_DIR 에 수동으로 배포하세요."
fi

# Python 가상환경
if [[ ! -f "$INSTALL_DIR/venv/bin/activate" ]]; then
    sudo -u netguard "$PYTHON_BIN" -m venv "$INSTALL_DIR/venv"
    ok "Python 가상환경 생성: $INSTALL_DIR/venv"
else
    ok "Python 가상환경 이미 존재"
fi

if [[ ! -x "$INSTALL_DIR/venv/bin/pip" ]]; then
    sudo -u netguard "$INSTALL_DIR/venv/bin/python" -m ensurepip --upgrade || \
        error "venv에 pip를 준비하지 못했습니다. python3-pip/ensurepip 설치 상태를 확인하세요."
fi

# pip 패키지 설치
REQ_FILE="$INSTALL_DIR/requirements.txt"
[[ ! -f "$REQ_FILE" ]] && REQ_FILE="$SOURCE_DIR/requirements.txt"

if [[ -d "$PIP_DIR" ]] && find "$PIP_DIR" -maxdepth 1 -type f | grep -q .; then
    if [[ -f "$REQ_FILE" ]]; then
        sudo -u netguard "$INSTALL_DIR/venv/bin/pip" install \
            --no-index \
            --find-links "$PIP_DIR" \
            -r "$REQ_FILE" \
            --quiet
        ok "Python 패키지 오프라인 설치 완료"
    else
        warn "requirements.txt를 찾을 수 없습니다. 패키지 설치를 건너뜁니다."
    fi
else
    warn "pip 패키지 디렉토리가 없거나 비어 있습니다 ($PIP_DIR)."
    if [[ -f "$REQ_FILE" ]]; then
        warn "온라인 pip 설치를 시도합니다. 완전 오프라인 환경이면 /opt/offline_packages/pip 에 wheel 파일을 먼저 준비하세요."
        if sudo -u netguard "$INSTALL_DIR/venv/bin/pip" install -r "$REQ_FILE"; then
            ok "Python 패키지 온라인 설치 완료"
        else
            error "Python 패키지 설치 실패. /opt/offline_packages/pip 에 wheel 파일을 준비한 뒤 다시 실행하세요."
        fi
    else
        error "requirements.txt를 찾을 수 없어 Python 패키지를 설치할 수 없습니다."
    fi
fi

# 필수 Python 모듈 검증: 누락된 상태로 서비스를 시작하면 systemd가 즉시 실패합니다.
if sudo -u netguard "$INSTALL_DIR/venv/bin/python" - <<'PY'
import importlib
mods = [
    "yaml",
    "fastapi",
    "uvicorn",
    "asyncpg",
    "psycopg2",
    "pysnmp",
    "aiohttp",
    "pydantic",
    "apscheduler",
]
missing = []
for mod in mods:
    try:
        importlib.import_module(mod)
    except Exception as exc:
        missing.append(f"{mod}: {exc}")
if missing:
    print("\n".join(missing))
    raise SystemExit(1)
PY
then
    ok "Python 필수 모듈 검증 완료"
else
    error "Python 필수 모듈이 누락되었습니다. pip 패키지 설치 상태를 확인하세요."
fi

# 로그 디렉토리 권한
chmod 750 "$INSTALL_DIR/logs" "$INSTALL_DIR/data" "$INSTALL_DIR/config"
chmod 640 "$INSTALL_DIR/config/config.yaml" 2>/dev/null || true
chown -R netguard:netguard "$INSTALL_DIR"

# ── 7. 데이터베이스 초기화 ────────────────────────────────────────────────────
step "데이터베이스 초기화"

# DB 사용자 및 데이터베이스 생성
sudo -u postgres psql << PSQL
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'netguard') THEN
        CREATE USER netguard WITH PASSWORD '${DB_PASS}';
    ELSE
        ALTER USER netguard WITH PASSWORD '${DB_PASS}';
    END IF;
END
\$\$;

PSQL

# CREATE DATABASE는 트랜잭션 블록 안에서 실행할 수 없으므로 psql DO/dblink를 쓰지 않습니다.
if sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='netguard'" | grep -qx "1"; then
    sudo -u postgres psql -c "ALTER DATABASE netguard OWNER TO netguard;"
else
    sudo -u postgres createdb -O netguard netguard
fi

sudo -u postgres psql -d netguard << PSQL
GRANT ALL PRIVILEGES ON DATABASE netguard TO netguard;
GRANT ALL ON SCHEMA public TO netguard;
PSQL

if [[ "$TIMESCALE_ENABLED" -eq 1 ]]; then
    sudo -u postgres psql -d netguard -c "CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;"
else
    warn "TimescaleDB 확장 생성을 건너뜁니다. NetGuard는 일반 PostgreSQL 모드로 동작합니다."
fi

ok "DB 사용자 및 데이터베이스 생성 완료"

# ── 8. 설정 파일 작성 ─────────────────────────────────────────────────────────
step "설정 파일 작성"

CONFIG_FILE="$INSTALL_DIR/config/config.yaml"

mkdir -p "$(dirname "$CONFIG_FILE")"
if [[ -f "$CONFIG_FILE" ]]; then
    BACKUP_CONFIG="${CONFIG_FILE}.bak.$(date +%Y%m%d_%H%M%S)"
    cp "$CONFIG_FILE" "$BACKUP_CONFIG"
    warn "기존 config.yaml을 백업했습니다: $BACKUP_CONFIG"
fi

cat > "$CONFIG_FILE" << YAML
# ===== Database =====
db_host: localhost
db_port: 5432
db_user: netguard
db_password: "${DB_PASS}"
db_name: netguard
nvd_cache_dir: /opt/netguard/data/nvd_cache

# ===== SNMP =====
snmp_community: ${SNMP_COMMUNITY}
snmp_timeout: 5
snmp_retries: 2
snmp_poll_interval: 60

# ===== 이메일 알림 =====
smtp_host: ${SMTP_HOST}
smtp_port: 25
smtp_from: noreply@company.local
alert_emails:
  - ${ALERT_EMAIL}

# ===== 카카오톡 (오프라인 환경) =====
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
humi_warn_low: 40.0
ups_batt_warn: 30.0
ups_batt_crit: 15.0
YAML
chmod 640 "$CONFIG_FILE"
chown netguard:netguard "$CONFIG_FILE"
ok "config.yaml 작성 완료: $CONFIG_FILE"

# NetGuard 스키마 초기화
step "NetGuard 스키마 초기화"

sudo -u netguard bash -c "
    source $INSTALL_DIR/venv/bin/activate
    cd $INSTALL_DIR
    export PYTHONPATH=$INSTALL_DIR/backend
    export NETGUARD_DB_HOST=localhost
    export NETGUARD_DB_PORT=5432
    export NETGUARD_DB_USER=netguard
    export NETGUARD_DB_PASSWORD='$DB_PASS'
    export NETGUARD_DB_NAME=netguard
    python - <<'PY'
import asyncio
from database import init_db, close_db_pool

async def main():
    await init_db()
    await close_db_pool()

asyncio.run(main())
PY
" && ok "NetGuard 스키마 초기화 완료" || error "NetGuard 스키마 초기화 실패. DB 접속 정보와 Python 패키지 설치 상태를 확인하세요."

# ── 9. systemd 서비스 등록 ────────────────────────────────────────────────────
step "systemd 서비스 등록"

cat > /etc/systemd/system/netguard.service << EOF
[Unit]
Description=NetGuard SNMP Dashboard
After=network.target postgresql-18.service
Requires=postgresql-18.service

[Service]
Type=exec
User=netguard
Group=netguard
WorkingDirectory=${INSTALL_DIR}/backend
Environment=PYTHONPATH=${INSTALL_DIR}/backend
Environment=PYTHONUNBUFFERED=1
Environment=NETGUARD_LOG_DIR=${INSTALL_DIR}/logs
Environment=NETGUARD_NVD_CACHE_DIR=${INSTALL_DIR}/data/nvd_cache
ExecStart=${INSTALL_DIR}/venv/bin/uvicorn app:app \\
    --host 0.0.0.0 \\
    --port 8000 \\
    --workers 1 \\
    --log-level info \\
    --access-log

Restart=on-failure
RestartSec=5
StartLimitInterval=60
StartLimitBurst=3

NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=${INSTALL_DIR}/logs ${INSTALL_DIR}/data ${INSTALL_DIR}/config

LimitNOFILE=65536
MemoryLimit=2G

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
ok "netguard.service 등록 완료"

# ── 10. 방화벽 설정 ───────────────────────────────────────────────────────────
step "방화벽 설정"

if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
    firewall-cmd --permanent --add-port=8000/tcp
    firewall-cmd --permanent --add-port=162/udp 2>/dev/null || true
    firewall-cmd --reload
    ok "firewalld: 8000/tcp, 162/udp 허용"
else
    warn "firewalld가 실행 중이지 않습니다. 방화벽 설정을 건너뜁니다."
fi

# SELinux 포트 허용 (Enforcing 환경)
if command -v getenforce &>/dev/null && [[ "$(getenforce)" == "Enforcing" ]]; then
    semanage port -a -t http_port_t -p tcp 8000 2>/dev/null || \
    semanage port -m -t http_port_t -p tcp 8000 2>/dev/null || true
    setsebool -P httpd_can_network_connect on 2>/dev/null || true
    info "SELinux: 8000/tcp 포트 허용 적용"
fi

# ── 11. logrotate 설정 ────────────────────────────────────────────────────────
step "logrotate 설정"

cat > /etc/logrotate.d/netguard << 'EOF'
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
ok "logrotate 설정 완료"

# ── 12. 자동 백업 설정 ────────────────────────────────────────────────────────
step "자동 백업 설정 (매일 새벽 2시)"

cat > "$INSTALL_DIR/scripts/backup.sh" << BACKUP_EOF
#!/bin/bash
set -e
BACKUP_DIR="/opt/backup/netguard"
DATE=\$(date +%Y%m%d_%H%M%S)
KEEP_DAYS=30

mkdir -p "\$BACKUP_DIR"

PGPASSWORD='${DB_PASS}' pg_dump \\
    -U netguard -h localhost -d netguard \\
    -Fc -Z 9 \\
    -f "\$BACKUP_DIR/netguard_\$DATE.dump"

cp ${INSTALL_DIR}/config/config.yaml "\$BACKUP_DIR/config_\$DATE.yaml"

find "\$BACKUP_DIR" -name "*.dump" -mtime +\$KEEP_DAYS -delete
find "\$BACKUP_DIR" -name "*.yaml" -mtime +\$KEEP_DAYS -delete

echo "[\$(date)] Backup: netguard_\$DATE.dump"
BACKUP_EOF

chmod +x "$INSTALL_DIR/scripts/backup.sh"
chown netguard:netguard "$INSTALL_DIR/scripts/backup.sh"

echo "0 2 * * * netguard ${INSTALL_DIR}/scripts/backup.sh >> ${INSTALL_DIR}/logs/backup.log 2>&1" \
    > /etc/cron.d/netguard-backup
ok "백업 cron 등록 완료 (매일 02:00)"

# ── 서비스 시작 ───────────────────────────────────────────────────────────────
step "NetGuard 서비스 시작"

systemctl enable --now netguard
sleep 3

if systemctl is-active netguard &>/dev/null; then
    ok "NetGuard 서비스 시작 성공!"
else
    warn "NetGuard 서비스 시작 실패. 로그를 확인하세요:"
    echo "  sudo journalctl -u netguard -n 30 --no-pager"
fi

# ── 완료 요약 ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              NetGuard 설치가 완료되었습니다!              ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  대시보드 URL  : ${CYAN}http://$(hostname -I | awk '{print $1}'):8000${NC}"
echo -e "  초기 계정     : admin / admin1234!"
echo -e "  설정 파일     : ${INSTALL_DIR}/config/config.yaml"
echo -e "  로그 파일     : ${INSTALL_DIR}/logs/netguard.log"
echo ""
echo -e "${YELLOW}서비스 관리 명령어:${NC}"
echo "  sudo systemctl {start|stop|restart|status} netguard"
echo "  sudo journalctl -u netguard -f"
echo ""
echo -e "${YELLOW}다음 단계:${NC}"
echo "  1. 브라우저에서 대시보드 접속 및 비밀번호 변경"
echo "  2. 대시보드 → 장비 관리 → SNMP 장비 등록"
echo "  3. NVD CVE 캐시 복사: /opt/netguard/data/nvd_cache/"
echo "  4. config.yaml 이메일/SMTP 설정 확인"
echo ""
