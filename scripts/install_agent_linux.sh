#!/usr/bin/env bash
# NetGuard Linux Agent 1.2.65. Offline: no dnf/apt/pip or network downloads.
set -euo pipefail
umask 077

info() { printf '[NetGuard-Agent] %s\n' "$*"; }
fail() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }
MODE=install
case "${1:-}" in
    --check) MODE=check ;;
    --update) MODE=update ;;
    --help|-h) printf 'Usage: sudo bash %s [--check|--update]\n' "$0"; exit 0 ;;
    '') ;;
    *) fail 'Unknown option; use --check, --update or no option for a new install.' ;;
esac
[[ $# -le 1 ]] || fail 'Too many arguments.'
[[ $(uname -s) == Linux ]] || fail 'This installer requires Linux with systemd.'
[[ $EUID -eq 0 ]] || fail 'Run with sudo/root (including --check to read installed configuration).'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
AGENT_SRC="$(dirname -- "$SCRIPT_DIR")/agent"
HELPER="$SCRIPT_DIR/linux_agent_setup.py"
INSTALL_DIR=/opt/netguard-agent
CONFIG_FILE="$INSTALL_DIR/agent_config.json"
SERVICE_FILE=/etc/systemd/system/netguard-agent.service
SERVICE=netguard-agent
for target in "$INSTALL_DIR" "$CONFIG_FILE" "$SERVICE_FILE" "$INSTALL_DIR/netguard_agent.py" "$INSTALL_DIR/software_inventory.py" "$INSTALL_DIR/restart_agent.sh"; do
    [[ ! -L $target ]] || fail "Refusing to replace a symbolic link: $target"
done

for command in systemctl systemd-analyze install mktemp useradd groupadd getent runuser flock; do
    command -v "$command" >/dev/null || fail "Required command missing: $command"
done
[[ -d /run/systemd/system ]] || fail 'systemd must be running as the system service manager.'
[[ -f $HELPER ]] || fail 'scripts/linux_agent_setup.py missing; extract the whole package.'
for file in netguard_agent.py software_inventory.py restart_agent.sh; do
    [[ -f $AGENT_SRC/$file ]] || fail "Required package file missing: agent/$file"
done
bash -n "$AGENT_SRC/restart_agent.sh"

PYTHON_BIN=''
for candidate in "${NETGUARD_AGENT_PYTHON:-}" python3.13 python3.12 python3.11 python3.10 python3.9 python3.8 python3.7 python3.6 python3; do
    [[ -n $candidate ]] || continue
    path=$(command -v "$candidate" 2>/dev/null) || { [[ -z ${NETGUARD_AGENT_PYTHON:-} ]] || fail 'Selected Python not found.'; continue; }
    if "$path" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 6) else 1)' 2>/dev/null; then
        PYTHON_BIN=$("$path" -c 'import os,sys; print(os.path.abspath(sys.executable))')
        break
    fi
    [[ -z ${NETGUARD_AGENT_PYTHON:-} ]] || fail 'Selected Python requires version 3.6 or later.'
done
[[ -n $PYTHON_BIN ]] || fail 'Python 3.6+ not found. Prepare approved offline OS packages first.'
[[ $PYTHON_BIN =~ ^/[a-zA-Z0-9_./-]+$ ]] || fail 'Use a system Python in an absolute path without spaces or systemd specifiers.'
info "Python: $PYTHON_BIN ($("$PYTHON_BIN" --version 2>&1))"
"$PYTHON_BIN" -B "$HELPER" check "$AGENT_SRC" "$CONFIG_FILE"
if [[ $MODE == check ]]; then
    info 'Preflight passed. No installed files, users or services were changed. Network delivery is not tested.'
    exit 0
fi

exec 9>/run/lock/netguard-agent-install.lock
flock -n 9 || fail 'Another NetGuard Agent installation is in progress.'

# Refuse implicit reinstallation; updates preserve config bytes and the existing unit.
if [[ $MODE == install ]]; then
    [[ ! -e $CONFIG_FILE && ! -e $SERVICE_FILE ]] || fail 'Existing installation found. Use --update; configuration will not be overwritten.'
    [[ $(systemctl show "$SERVICE" -p LoadState --value) == not-found ]] || fail 'An existing service already uses this name; review it before installing.'
else
    [[ -f $CONFIG_FILE && -f $SERVICE_FILE ]] || fail '--update requires an existing config and /etc/systemd/system/netguard-agent.service.'
    id ngagent >/dev/null 2>&1 && getent group ngagent >/dev/null || fail 'Existing ngagent user/group missing.'
    [[ $(id -u ngagent) != 0 ]] || fail 'ngagent must not be a root account.'
    [[ $(systemctl show "$SERVICE" -p User --value) == ngagent ]] || fail 'Nonstandard service user. Review the manual update procedure before changing files.'
    [[ $(systemctl show "$SERVICE" -p WorkingDirectory --value) == "$INSTALL_DIR" ]] || fail 'Nonstandard WorkingDirectory; use the manual update procedure.'
    runuser -u ngagent -- "$PYTHON_BIN" -B -c 'import ctypes, json, urllib.request'
fi

STAGE=$(mktemp -d /tmp/netguard-agent-install.XXXXXXXX)
trap 'rm -rf -- "$STAGE"' EXIT

if [[ $MODE == install ]]; then
    read -r -p 'NetGuard server URL [http://10.60.8.186:8000]: ' INPUT_URL
    read -r -s -p 'API key [netguard-agent-key-2026]: ' INPUT_KEY
    printf '\n'
    read -r -p 'Collection interval seconds [60]: ' INPUT_INTERVAL
    read -r -p 'Device type [server]: ' INPUT_TYPE
    read -r -p 'Location []: ' INPUT_LOC
    NG_URL="${INPUT_URL:-http://10.60.8.186:8000}" NG_KEY="${INPUT_KEY:-netguard-agent-key-2026}" \
    NG_INTERVAL="${INPUT_INTERVAL:-60}" NG_TYPE="${INPUT_TYPE:-server}" NG_LOCATION="$INPUT_LOC" \
        "$PYTHON_BIN" -B "$HELPER" config > "$STAGE/agent_config.json"
    unset INPUT_KEY
    "$PYTHON_BIN" -B "$HELPER" unit "$PYTHON_BIN" > "$STAGE/netguard-agent.service"
    systemd-analyze verify "$STAGE/netguard-agent.service"
else
    systemd-analyze verify "$SERVICE_FILE"
fi

BACKUP=''
if [[ $MODE == update ]]; then
    install -d -o root -g root -m 0755 /var/backups
    BACKUP=$(mktemp -d /var/backups/netguard-agent.XXXXXXXX)
    for file in netguard_agent.py software_inventory.py restart_agent.sh agent_config.json; do
        if [[ -f $INSTALL_DIR/$file ]]; then cp -p -- "$INSTALL_DIR/$file" "$BACKUP/"; fi
    done
    cp -p -- "$SERVICE_FILE" "$BACKUP/netguard-agent.service"
    info "Backup: $BACKUP (root-only). Configuration and unit contents will be preserved."
    systemctl stop "$SERVICE"
fi

if ! id ngagent >/dev/null 2>&1; then
    if ! getent group ngagent >/dev/null; then groupadd --system ngagent; fi
    useradd --system --gid ngagent --shell /sbin/nologin --home-dir "$INSTALL_DIR" ngagent
fi
getent group ngagent >/dev/null || fail 'The ngagent group is missing. Review the existing service account.'
[[ $(id -u ngagent) != 0 ]] || fail 'ngagent must not be a root account.'
install -d -o ngagent -g ngagent -m 0750 "$INSTALL_DIR"
install -o root -g ngagent -m 0640 "$AGENT_SRC/netguard_agent.py" "$AGENT_SRC/software_inventory.py" "$INSTALL_DIR/"
install -o root -g ngagent -m 0750 "$AGENT_SRC/restart_agent.sh" "$INSTALL_DIR/"
if [[ $MODE == install ]]; then
    install -o root -g ngagent -m 0640 "$STAGE/agent_config.json" "$CONFIG_FILE"
    install -o root -g root -m 0644 "$STAGE/netguard-agent.service" "$SERVICE_FILE"
fi

# Validate with the actual service account before attempting startup.
runuser -u ngagent -- "$PYTHON_BIN" -B - check-installed "$INSTALL_DIR" "$CONFIG_FILE" < "$HELPER"
systemctl daemon-reload
if [[ $MODE == install ]]; then systemctl enable "$SERVICE"; fi
systemctl reset-failed "$SERVICE"
systemctl restart "$SERVICE"
sleep 3
if ! systemctl is-active --quiet "$SERVICE"; then
    printf '[ERROR] Agent failed to stay active. Check journalctl -u netguard-agent -n 50 --no-pager.\n' >&2
    [[ -z $BACKUP ]] || info "Backup retained at: $BACKUP"
    exit 1
fi
info 'Agent is active. Confirm periodic OK entries in agent.log and the server last-seen timestamp.'
info "Autostart state: $(systemctl is-enabled "$SERVICE" 2>/dev/null || true)"
info 'Close this terminal normally; systemd owns the background process.'
