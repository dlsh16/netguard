#!/bin/bash
# =============================================================================
# NetGuard 오프라인 설치를 위한 패키지 수집 스크립트 (Rocky Linux)
# PostgreSQL 18 + Python 3.13
#
# 인터넷이 되는 Rocky Linux PC(또는 Docker 컨테이너)에서 실행합니다.
# 실행: sudo bash collect_packages_rocky.sh
# =============================================================================
set -euo pipefail

OUTPUT_DIR="/opt/offline_packages"
RPM_DIR="$OUTPUT_DIR/rpm"
PIP_DIR="$OUTPUT_DIR/pip"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$(dirname "$SCRIPT_DIR")"
REQ_FILE="$SOURCE_DIR/requirements.txt"

echo ""
echo "NetGuard 오프라인 패키지 수집 (Rocky Linux)"
echo "  PostgreSQL 18 + Python 3.13"
echo "  수집 경로: $OUTPUT_DIR"
echo ""

[[ $EUID -ne 0 ]] && echo "[ERROR] root 권한으로 실행하세요." && exit 1

# requirements.txt 확인
if [[ ! -f "$REQ_FILE" ]]; then
    read -rp "requirements.txt 경로를 입력하세요: " REQ_FILE
    [[ ! -f "$REQ_FILE" ]] && echo "[ERROR] 파일을 찾을 수 없습니다." && exit 1
fi
echo "[OK] requirements.txt: $REQ_FILE"

mkdir -p "$RPM_DIR" "$PIP_DIR"

# ── OS 버전 확인 ──────────────────────────────────────────────────────────────
if grep -q "release 9" /etc/redhat-release 2>/dev/null; then
    EL_VER=9
elif grep -q "release 8" /etc/redhat-release 2>/dev/null; then
    EL_VER=8
else
    EL_VER=9
fi
echo "[INFO] 감지된 OS: EL${EL_VER}"

# ── PostgreSQL 18 저장소 설정 및 RPM 수집 ─────────────────────────────────────
echo ""
echo "[STEP 1] PostgreSQL 18 RPM 수집..."

dnf install -y \
    "https://download.postgresql.org/pub/repos/yum/reporpms/EL-${EL_VER}-x86_64/pgdg-redhat-repo-latest.noarch.rpm" \
    2>/dev/null || true
dnf -qy module disable postgresql 2>/dev/null || true

dnf download --resolve --destdir "$RPM_DIR" \
    postgresql18 postgresql18-server postgresql18-contrib postgresql18-libs

echo "[OK] PostgreSQL 18 RPM 수집 완료"

# ── TimescaleDB 저장소 및 RPM 수집 ────────────────────────────────────────────
echo ""
echo "[STEP 2] TimescaleDB RPM 수집..."
echo "[NOTE]   TimescaleDB PG18 지원 여부를 https://docs.timescale.com 에서 확인하세요."

curl -s https://packagecloud.io/install/repositories/timescale/timescaledb/script.rpm.sh | bash
dnf download --resolve --destdir "$RPM_DIR" timescaledb-2-postgresql-18 2>/dev/null || \
    echo "[WARN]  timescaledb-2-postgresql-18 패키지를 찾을 수 없습니다. 수동 수집 필요."

echo "[OK] TimescaleDB RPM 수집 완료 (없으면 수동 확인 필요)"

# ── Python 3.13 RPM 수집 ──────────────────────────────────────────────────────
echo ""
echo "[STEP 3] Python 3.13 RPM 수집..."

dnf download --resolve --destdir "$RPM_DIR" \
    python3.13 python3.13-pip python3.13-devel \
    gcc gcc-c++ make openssl-devel libffi-devel \
    chrony net-snmp net-snmp-utils 2>/dev/null || true

echo "[OK] Python 3.13 RPM 수집 완료"

# ── pip 패키지 수집 ───────────────────────────────────────────────────────────
echo ""
echo "[STEP 4] Python pip 패키지 수집 (현재 Python 버전 기준)..."

PYTHON_BIN=$(command -v python3.13 2>/dev/null || command -v python3 || echo "python3")
echo "[INFO] pip 패키지 수집 Python: $($PYTHON_BIN --version 2>&1)"
"$PYTHON_BIN" -m pip download \
    -r "$REQ_FILE" \
    -d "$PIP_DIR" \
    --only-binary=:all:

COUNT=$(ls "$PIP_DIR" 2>/dev/null | wc -l)
echo "[OK] pip 패키지 수집 완료 (${COUNT}개)"

# ── 압축 ──────────────────────────────────────────────────────────────────────
echo ""
echo "[STEP 5] 패키지 압축..."
cp "$REQ_FILE" "$OUTPUT_DIR/requirements.txt"
tar -czf /opt/netguard_offline_packages.tar.gz -C /opt offline_packages/
echo "[OK] 압축 완료: /opt/netguard_offline_packages.tar.gz"

RPM_COUNT=$(ls "$RPM_DIR"/*.rpm 2>/dev/null | wc -l)
PIP_COUNT=$(ls "$PIP_DIR" 2>/dev/null | wc -l)
TAR_SIZE=$(du -sh /opt/netguard_offline_packages.tar.gz | cut -f1)

echo ""
echo "=== 수집 완료 ==="
echo "  RPM: ${RPM_COUNT}개  /  pip: ${PIP_COUNT}개  /  압축: ${TAR_SIZE}"
echo ""
echo "다음 단계:"
echo "  1. /opt/netguard_offline_packages.tar.gz 를 USB로 복사"
echo "  2. 오프라인 서버에서: tar -xzf netguard_offline_packages.tar.gz -C /opt/"
echo "  3. 오프라인 서버에서: sudo bash install_rocky.sh"
echo ""
