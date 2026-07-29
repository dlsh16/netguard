#!/bin/bash
# NetGuard SNMP Dashboard - Linux (Rocky) 시작 스크립트

set -e

cd "$(dirname "$0")/.."

echo "[*] NetGuard SNMP Dashboard starting..."
echo "[*] URL: http://0.0.0.0:8000"

# 가상환경 활성화
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
fi

mkdir -p logs

cd backend
exec python -m uvicorn app:app \
    --host 0.0.0.0 \
    --port 8000 \
    --workers 2 \
    --log-level info \
    --access-log \
    --log-config ../config/log_config.yaml
