#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${1:-netguard-agent}"
LOG_FILE="/opt/netguard-agent/agent.log"

if [[ "${EUID}" -ne 0 ]]; then
  echo "[NetGuard-Agent] Please run as root: sudo $0"
  exit 1
fi

echo "[NetGuard-Agent] Restarting ${SERVICE_NAME}..."
systemctl restart "${SERVICE_NAME}"
sleep 3

echo "[NetGuard-Agent] Service status:"
systemctl status "${SERVICE_NAME}" --no-pager -l || true

if [[ -f "${LOG_FILE}" ]]; then
  echo
  echo "[NetGuard-Agent] Recent log:"
  tail -n 30 "${LOG_FILE}"
else
  echo
  echo "[NetGuard-Agent] Agent log not found: ${LOG_FILE}"
  echo "[NetGuard-Agent] Journal:"
  journalctl -u "${SERVICE_NAME}" -n 30 --no-pager || true
fi
