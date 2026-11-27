#!/bin/bash
set -euo pipefail
[[ $EUID == 0 && ${1:-} == --enable ]] || { echo 'Usage: sudo bash enable_remote_checks_linux.sh --enable'; exit 1; }
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
getent group ngagent >/dev/null
command -v timeout >/dev/null
command -v visudo >/dev/null
for path in /usr/local/libexec/netguard-checks /var/lib/netguard-checks /usr/local/sbin/netguard-run-check /etc/sudoers.d/netguard-checks; do
    [[ ! -L $path ]] || { echo 'Refusing symlink target'; exit 1; }
done
install -d -o root -g root -m 0755 /usr/local/libexec/netguard-checks
install -d -o root -g ngagent -m 0750 /var/lib/netguard-checks
install -o root -g root -m 0644 "$root/agent/check_scripts/cve_check_linux.sh" "$root/agent/check_scripts/maintenance_linux.sh" /usr/local/libexec/netguard-checks/
install -o root -g root -m 0755 "$root/scripts/netguard-run-check" /usr/local/sbin/netguard-run-check
temp=$(mktemp)
trap 'rm -f -- "$temp"' EXIT
printf 'ngagent ALL=(root) NOPASSWD: /usr/local/sbin/netguard-run-check\n' > "$temp"
visudo -cf "$temp"
install -o root -g root -m 0440 "$temp" /etc/sudoers.d/netguard-checks
echo 'Fixed security/maintenance runner enabled. Configure this device remote_checks token, then restart netguard-agent.'
