#!/usr/bin/env bash
set -u

IP="${1:-}"
COMMUNITY="${2:-}"
VERSION="${3:-2c}"

if [ -z "$IP" ] || [ -z "$COMMUNITY" ]; then
    echo "Usage: $0 <ip> <community> [version]"
    echo "Example: $0 10.60.8.134 stanry 2c"
    exit 2
fi

if ! command -v snmpwalk >/dev/null 2>&1 || ! command -v snmpget >/dev/null 2>&1; then
    echo "[ERROR] snmpwalk/snmpget command not found. Install net-snmp-utils first."
    exit 1
fi

STAMP="$(date +%Y%m%d_%H%M%S)"
SAFE_IP="$(echo "$IP" | tr '.:' '__')"
OUT_DIR="${OUT_DIR:-/tmp/netguard_env_oid_scan_${SAFE_IP}_${STAMP}}"
mkdir -p "$OUT_DIR"

SNMP_OPTS=(-v"$VERSION" -c "$COMMUNITY" -On -t 2 -r 1)

run_walk() {
    local root="$1"
    local label="$2"
    local file="$OUT_DIR/${label}.txt"

    echo "[STEP] Walking $root ($label)"
    if command -v timeout >/dev/null 2>&1; then
        timeout 120 snmpwalk "${SNMP_OPTS[@]}" "$IP" "$root" >"$file" 2>&1 || true
    else
        snmpwalk "${SNMP_OPTS[@]}" "$IP" "$root" >"$file" 2>&1 || true
    fi
    echo "       saved: $file ($(wc -l <"$file" 2>/dev/null || echo 0) lines)"
}

echo "=== NetGuard Env OID Finder ==="
echo "Target   : $IP"
echo "Version  : v$VERSION"
echo "Output   : $OUT_DIR"
echo

echo "[STEP] Basic system identity"
{
    snmpget "${SNMP_OPTS[@]}" "$IP" .1.3.6.1.2.1.1.1.0 || true
    snmpget "${SNMP_OPTS[@]}" "$IP" .1.3.6.1.2.1.1.2.0 || true
    snmpget "${SNMP_OPTS[@]}" "$IP" .1.3.6.1.2.1.1.5.0 || true
} | tee "$OUT_DIR/system.txt"
echo

run_walk ".1.3.6.1.2.1.99.1.1.1" "entity_sensor_mib"
run_walk ".1.3.6.1.2.1.33" "ups_mib"
run_walk ".1.3.6.1.4.1" "private_enterprise"

cat "$OUT_DIR"/*.txt >"$OUT_DIR/all.txt" 2>/dev/null || true

grep -Eiv "No Such|Timeout|Unknown Object|End of MIB" "$OUT_DIR/all.txt" \
    | grep -Ei "temp|temper|humid|humidity|rh|sensor|probe|degree|celsius" \
    >"$OUT_DIR/name_candidates.txt" || true

awk '
    /= (INTEGER|Gauge32|Unsigned32|Counter32|Counter64):/ {
        line=$0
        value=$NF
        gsub(/[^0-9.-]/, "", value)
        if (value != "" && value >= -500 && value <= 10000) {
            print line
        }
    }
' "$OUT_DIR/all.txt" >"$OUT_DIR/value_candidates.txt" || true

echo
echo "[RESULT] Name candidates (temperature/humidity words)"
if [ -s "$OUT_DIR/name_candidates.txt" ]; then
    head -100 "$OUT_DIR/name_candidates.txt"
else
    echo "No name-based candidates found."
fi

echo
echo "[RESULT] Numeric candidates (-500..10000)"
if [ -s "$OUT_DIR/value_candidates.txt" ]; then
    head -150 "$OUT_DIR/value_candidates.txt"
else
    echo "No numeric candidates found."
fi

echo
echo "[DONE] Send these files when temperature/humidity still show 0:"
echo "  $OUT_DIR/system.txt"
echo "  $OUT_DIR/name_candidates.txt"
echo "  $OUT_DIR/value_candidates.txt"
echo "  $OUT_DIR/private_enterprise.txt"
