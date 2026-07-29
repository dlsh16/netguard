#!/bin/bash
# =============================================================================
# NetGuard Agent — Linux 설치 스크립트 (오프라인 환경 호환)
# 의존성: Python 3 (표준 라이브러리만 사용, pip 불필요)
#
# 실행: sudo bash install_agent_linux.sh
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC}   $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "${CYAN}[INFO]${NC} $1"; }

[[ $EUID -ne 0 ]] && echo "[ERROR] root 권한으로 실행하세요." && exit 1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$(dirname "$SCRIPT_DIR")"
AGENT_SRC="$SOURCE_DIR/agent"
INSTALL_DIR="/opt/netguard-agent"
SERVICE_FILE="/etc/systemd/system/netguard-agent.service"

echo ""
echo -e "${CYAN}=== NetGuard Agent Linux 설치 ===${NC}"
echo ""

# ── 입력 수집 ──────────────────────────────────────────────────────────────────
read -rp "NetGuard 서버 URL [http://10.60.8.187:8000]: " INPUT_URL
SERVER_URL="${INPUT_URL:-http://10.60.8.187:8000}"

read -rp "API Key          [netguard-agent-key-2026]: " INPUT_KEY
API_KEY="${INPUT_KEY:-netguard-agent-key-2026}"

read -rp "수집 간격 (초)   [60]: " INPUT_INTERVAL
INTERVAL="${INPUT_INTERVAL:-60}"

read -rp "장치 유형        [server]: " INPUT_TYPE
DEVICE_TYPE="${INPUT_TYPE:-server}"

read -rp "위치 설명        []: " INPUT_LOC
LOCATION="${INPUT_LOC:-}"

# ── Python 확인 ────────────────────────────────────────────────────────────────
PYTHON_BIN=""
for p in python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v "$p" &>/dev/null; then
        PYTHON_BIN="$p"
        break
    fi
done
[[ -z "$PYTHON_BIN" ]] && echo "[ERROR] Python 3 를 찾을 수 없습니다." && exit 1
info "Python: $PYTHON_BIN ($($PYTHON_BIN --version 2>&1))"

# ── 파일 설치 ──────────────────────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR"

if [[ -f "$AGENT_SRC/netguard_agent.py" ]]; then
    cp "$AGENT_SRC/netguard_agent.py" "$INSTALL_DIR/"
    ok "netguard_agent.py 복사 완료"
else
    echo "[ERROR] $AGENT_SRC/netguard_agent.py 를 찾을 수 없습니다." && exit 1
fi

# ── 설정 파일 작성 ────────────────────────────────────────────────────────────
HOSTNAME_VAL="$(hostname)"
CONFIG_FILE="$INSTALL_DIR/agent_config.json"

cat > "$CONFIG_FILE" << JSON
{
    "server_url":  "${SERVER_URL}",
    "api_key":     "${API_KEY}",
    "interval":    ${INTERVAL},
    "hostname":    "${HOSTNAME_VAL}",
    "device_type": "${DEVICE_TYPE}",
    "location":    "${LOCATION}",
    "log_file":    "${INSTALL_DIR}/agent.log"
}
JSON
chmod 640 "$CONFIG_FILE"
ok "agent_config.json 작성 완료"

# ── 전용 사용자 ────────────────────────────────────────────────────────────────
if ! id ngagent &>/dev/null; then
    useradd -r -s /sbin/nologin -d "$INSTALL_DIR" ngagent
    ok "ngagent 사용자 생성"
fi
chown -R ngagent:ngagent "$INSTALL_DIR"

# ── systemd 서비스 등록 ───────────────────────────────────────────────────────
cat > "$SERVICE_FILE" << EOF
[Unit]
Description=NetGuard Monitoring Agent
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=ngagent
WorkingDirectory=${INSTALL_DIR}
ExecStart=${PYTHON_BIN} ${INSTALL_DIR}/netguard_agent.py
Restart=on-failure
RestartSec=10
StartLimitInterval=60
StartLimitBurst=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now netguard-agent
sleep 2

if systemctl is-active netguard-agent &>/dev/null; then
    ok "netguard-agent 서비스 시작 성공!"
else
    warn "서비스 상태를 확인하세요:"
    echo "  sudo journalctl -u netguard-agent -n 20 --no-pager"
fi

echo ""
echo -e "${GREEN}=== 설치 완료 ===${NC}"
echo "  서버 URL : $SERVER_URL"
echo "  호스트명 : $HOSTNAME_VAL"
echo "  간격     : ${INTERVAL}s"
echo ""
echo "서비스 관리:"
echo "  sudo systemctl {start|stop|restart|status} netguard-agent"
echo "  sudo journalctl -u netguard-agent -f"
echo "  tail -f $INSTALL_DIR/agent.log"
echo ""
