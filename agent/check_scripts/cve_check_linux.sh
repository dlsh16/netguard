#!/bin/bash
#=============================================================================
# Linux/Unix 서버 보안 취약점 자동 진단 스크립트
# 기준 : KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준 (Unix/Linux)
# CVE  : 2025~2026년 최신 보안 동향 반영
# 버전 : v2.0 | 점검 항목 : 82개
# 실행 : sudo bash cve_check_linux.sh
#=============================================================================

# ── 색상 정의 ──────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; GRAY='\033[0;37m'; NC='\033[0m'

# ── 결과 저장소 ────────────────────────────────────────────────────────────
declare -a RESULTS=()
CNT_PASS=0; CNT_FAIL=0; CNT_NA=0; CNT_MANUAL=0

# 출력 디렉터리
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"

# ── 헬퍼 함수 ──────────────────────────────────────────────────────────────
add_result() {
    # $1=ID $2=분류 $3=제목 $4=판단기준 $5=위험도 $6=결과 $7=상세 $8=조치
    local status="$6"
    # 파이프 구분자 내부 개행 처리
    local detail="${7//$'\n'/ | }"
    local action="${8:-}"
    RESULTS+=("$1|$2|$3|$4|$5|${status}|${detail}|${action}")
    case "$status" in
        양호)    ((CNT_PASS++))   ;;
        불량)    ((CNT_FAIL++))   ;;
        "N/A")   ((CNT_NA++))    ;;
        *)       ((CNT_MANUAL++)) ;;
    esac
}

print_result() {
    local id="$1" title="$2" status="$3"
    local padid padtitle
    padid=$(printf "%-7s" "$id")
    padtitle=$(printf "%-44.44s" "$title")
    printf "    %s %s " "$padid" "$padtitle"
    case "$status" in
        양호)    printf "${GREEN}[ 양호 ]${NC}\n" ;;
        불량)    printf "${RED}[ 불량 ]${NC}\n" ;;
        "N/A")   printf "${YELLOW}[ N/A  ]${NC}\n" ;;
        확인필요) printf "${YELLOW}[ 확인 ]${NC}\n" ;;
        *)       printf "${GRAY}[ 오류 ]${NC}\n" ;;
    esac
}

print_section() {
    echo ""
    printf "  ${CYAN}▶ %s${NC}\n" "$1"
    printf "  %s\n" "──────────────────────────────────────────────────────────────"
}

# 버전 비교: ver_lt A B → A < B 이면 true(0)
ver_lt() { [ "$(printf '%s\n' "$1" "$2" | sort -V | head -1)" = "$1" ] && [ "$1" != "$2" ]; }

# 파일 권한 숫자 취득
file_perm() { stat -c "%a" "$1" 2>/dev/null || echo "000"; }
file_owner() { stat -c "%U" "$1" 2>/dev/null || echo "unknown"; }

# sysctl 값 취득
sysctl_val() { sysctl -n "$1" 2>/dev/null || echo ""; }

# 서비스 활성 여부
svc_active() {
    if command -v systemctl &>/dev/null; then
        systemctl is-active --quiet "$1" 2>/dev/null && return 0
    fi
    service "$1" status &>/dev/null && return 0
    return 1
}

# ══════════════════════════════════════════════════════════════════════════════
#  1. 계정 관리 (U-01 ~ U-14)
# ══════════════════════════════════════════════════════════════════════════════
check_account() {
    print_section "계정 관리"

    # U-01: root 원격 SSH 직접 로그인 제한
    local cfg="/etc/ssh/sshd_config"
    local val; val=$(grep -iE "^\s*PermitRootLogin" "$cfg" 2>/dev/null | awk '{print $2}' | tail -1)
    local status; [[ "$val" =~ ^(no|prohibit-password|forced-commands-only)$ ]] && status="양호" || status="불량"
    add_result "U-01" "계정관리" "root 원격 SSH 로그인 제한" \
        "PermitRootLogin no/prohibit-password 설정 시 양호" "상" "$status" \
        "PermitRootLogin: ${val:-미설정(기본값=prohibit-password)}" \
        "echo 'PermitRootLogin no' >> /etc/ssh/sshd_config && systemctl restart sshd"
    print_result "U-01" "root 원격 SSH 로그인 제한" "$status"

    # U-02: 패스워드 없는 계정 점검
    local empty_pw; empty_pw=$(awk -F: '($2=="" || $2=="!!" ) && $1!="root" {print $1}' /etc/shadow 2>/dev/null)
    [[ -z "$empty_pw" ]] && status="양호" || status="불량"
    add_result "U-02" "계정관리" "패스워드 없는 계정 점검" \
        "모든 계정에 패스워드 설정 시 양호" "상" "$status" \
        "${empty_pw:-없음}" \
        "passwd <계정명> 으로 패스워드 설정"
    print_result "U-02" "패스워드 없는 계정 점검" "$status"

    # U-03: UID 0 계정 (root 외) 점검
    local uid0; uid0=$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd 2>/dev/null)
    [[ -z "$uid0" ]] && status="양호" || status="불량"
    add_result "U-03" "계정관리" "UID 0 계정 점검 (root 외)" \
        "root 외 UID 0 계정 없으면 양호" "상" "$status" \
        "UID 0 계정: ${uid0:-없음}" \
        "usermod -u <새UID> <계정명> 으로 UID 변경"
    print_result "U-03" "UID 0 계정 점검 (root 외)" "$status"

    # U-04: 패스워드 최소 길이 (login.defs)
    local minlen; minlen=$(grep -E "^\s*PASS_MIN_LEN" /etc/login.defs 2>/dev/null | awk '{print $2}')
    minlen=${minlen:-0}
    [[ "$minlen" -ge 8 ]] && status="양호" || status="불량"
    add_result "U-04" "계정관리" "패스워드 최소 길이" \
        "PASS_MIN_LEN 8자 이상이면 양호" "상" "$status" \
        "현재 PASS_MIN_LEN: $minlen" \
        "vi /etc/login.defs → PASS_MIN_LEN 8 이상 설정"
    print_result "U-04" "패스워드 최소 길이" "$status"

    # U-05: 패스워드 최대 사용 기간
    local maxdays; maxdays=$(grep -E "^\s*PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
    maxdays=${maxdays:-99999}
    [[ "$maxdays" -le 90 && "$maxdays" -gt 0 ]] && status="양호" || status="불량"
    add_result "U-05" "계정관리" "패스워드 최대 사용 기간" \
        "PASS_MAX_DAYS 90일 이하이면 양호" "중" "$status" \
        "현재 PASS_MAX_DAYS: $maxdays" \
        "vi /etc/login.defs → PASS_MAX_DAYS 90 이하 설정"
    print_result "U-05" "패스워드 최대 사용 기간" "$status"

    # U-06: 패스워드 최소 사용 기간
    local mindays; mindays=$(grep -E "^\s*PASS_MIN_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
    mindays=${mindays:-0}
    [[ "$mindays" -ge 1 ]] && status="양호" || status="불량"
    add_result "U-06" "계정관리" "패스워드 최소 사용 기간" \
        "PASS_MIN_DAYS 1일 이상이면 양호" "하" "$status" \
        "현재 PASS_MIN_DAYS: $mindays" \
        "vi /etc/login.defs → PASS_MIN_DAYS 1 이상 설정"
    print_result "U-06" "패스워드 최소 사용 기간" "$status"

    # U-07: 패스워드 복잡도 (pam_pwquality / pam_cracklib)
    local pwq_conf="/etc/security/pwquality.conf"
    local minclass; minclass=$(grep -E "^\s*minclass" "$pwq_conf" 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
    local pam_pwq; pam_pwq=$(grep -rE "pam_pwquality|pam_cracklib" /etc/pam.d/ 2>/dev/null | grep -v "^#" | head -1)
    if [[ -n "$pam_pwq" || ( -f "$pwq_conf" && "${minclass:-0}" -ge 3 ) ]]; then
        status="양호"
    else
        status="불량"
    fi
    add_result "U-07" "계정관리" "패스워드 복잡도 설정" \
        "pam_pwquality 또는 pam_cracklib 적용 시 양호" "상" "$status" \
        "minclass: ${minclass:-미설정}, PAM 설정: ${pam_pwq:-없음}" \
        "dnf install libpwquality / apt install libpam-pwquality 후 /etc/pam.d/system-auth 설정"
    print_result "U-07" "패스워드 복잡도 설정" "$status"

    # U-08: 패스워드 재사용 제한 (pam_pwhistory)
    local hist; hist=$(grep -rE "pam_pwhistory|remember=" /etc/pam.d/ 2>/dev/null | grep -v "^#" | head -1)
    [[ -n "$hist" ]] && status="양호" || status="불량"
    add_result "U-08" "계정관리" "패스워드 재사용 제한" \
        "pam_pwhistory remember=3 이상 설정 시 양호" "중" "$status" \
        "${hist:-미설정}" \
        "/etc/pam.d/system-auth에 'password required pam_pwhistory.so remember=5' 추가"
    print_result "U-08" "패스워드 재사용 제한" "$status"

    # U-09: 계정 잠금 임계값 (pam_faillock / pam_tally2)
    local faillock; faillock=$(grep -rE "pam_faillock|pam_tally2" /etc/pam.d/ 2>/dev/null | grep -v "^#" | head -1)
    local deny_val; deny_val=$(grep -rE "deny=[0-9]+" /etc/pam.d/ 2>/dev/null | grep -oE "deny=[0-9]+" | head -1 | grep -oE "[0-9]+")
    if [[ -n "$faillock" && "${deny_val:-0}" -le 5 && "${deny_val:-0}" -gt 0 ]]; then
        status="양호"
    else
        status="불량"
    fi
    add_result "U-09" "계정관리" "계정 잠금 임계값 설정" \
        "로그인 실패 5회 이하 잠금 설정 시 양호" "상" "$status" \
        "pam_faillock: ${faillock:-미설정}, deny: ${deny_val:-미설정}" \
        "/etc/pam.d/system-auth에 pam_faillock.so deny=5 설정"
    print_result "U-09" "계정 잠금 임계값 설정" "$status"

    # U-10: su 명령 사용 제한 (wheel 그룹)
    local su_pam; su_pam=$(grep -E "pam_wheel" /etc/pam.d/su 2>/dev/null | grep -v "^#" | head -1)
    [[ -n "$su_pam" ]] && status="양호" || status="불량"
    add_result "U-10" "계정관리" "su 명령 사용 제한" \
        "pam_wheel.so 설정으로 su를 wheel 그룹만 허용 시 양호" "중" "$status" \
        "${su_pam:-/etc/pam.d/su에 pam_wheel 미설정}" \
        "/etc/pam.d/su에 'auth required pam_wheel.so use_uid' 추가"
    print_result "U-10" "su 명령 사용 제한" "$status"

    # U-11: /etc/passwd 소유자 및 권한
    local pp; pp=$(file_perm /etc/passwd); local po; po=$(file_owner /etc/passwd)
    [[ "$po" == "root" && "$pp" -le 644 ]] && status="양호" || status="불량"
    add_result "U-11" "계정관리" "/etc/passwd 파일 권한" \
        "소유자 root, 권한 644 이하이면 양호" "상" "$status" \
        "소유자: $po, 권한: $pp" \
        "chown root:root /etc/passwd && chmod 644 /etc/passwd"
    print_result "U-11" "/etc/passwd 파일 권한" "$status"

    # U-12: /etc/shadow 파일 권한
    local sp; sp=$(file_perm /etc/shadow); local so; so=$(file_owner /etc/shadow)
    [[ "$so" == "root" && "$sp" -le 400 ]] && status="양호" || status="불량"
    add_result "U-12" "계정관리" "/etc/shadow 파일 권한" \
        "소유자 root, 권한 400 이하이면 양호" "상" "$status" \
        "소유자: $so, 권한: $sp" \
        "chown root:root /etc/shadow && chmod 400 /etc/shadow"
    print_result "U-12" "/etc/shadow 파일 권한" "$status"

    # U-13: /etc/group 파일 권한
    local gp; gp=$(file_perm /etc/group); local go; go=$(file_owner /etc/group)
    [[ "$go" == "root" && "$gp" -le 644 ]] && status="양호" || status="불량"
    add_result "U-13" "계정관리" "/etc/group 파일 권한" \
        "소유자 root, 권한 644 이하이면 양호" "상" "$status" \
        "소유자: $go, 권한: $gp" \
        "chown root:root /etc/group && chmod 644 /etc/group"
    print_result "U-13" "/etc/group 파일 권한" "$status"

    # U-14: root 홈 디렉터리 접근 제한
    local root_home; root_home=$(grep -E "^root:" /etc/passwd | cut -d: -f6)
    local rhp; rhp=$(file_perm "${root_home:-/root}")
    [[ "$rhp" -le 700 ]] && status="양호" || status="불량"
    add_result "U-14" "계정관리" "root 홈 디렉터리 권한" \
        "권한 700 이하이면 양호" "중" "$status" \
        "root 홈: ${root_home:-/root}, 권한: $rhp" \
        "chmod 700 ${root_home:-/root}"
    print_result "U-14" "root 홈 디렉터리 권한" "$status"
}

# ══════════════════════════════════════════════════════════════════════════════
#  2. 파일 및 디렉터리 관리 (U-15 ~ U-26)
# ══════════════════════════════════════════════════════════════════════════════
check_file() {
    print_section "파일 및 디렉터리 관리"

    # U-15: SUID/SGID 파일 점검
    local suid_list; suid_list=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | \
        grep -Ev "^(/usr/bin/(passwd|sudo|su|newgrp|chage|chsh|chfn|gpasswd|write|wall|pkexec|mount|umount|crontab)|/usr/sbin/(pam_timestamp_check|unix_chkpwd|userhelper))" | head -20)
    [[ -z "$suid_list" ]] && status="양호" || status="확인필요"
    add_result "U-15" "파일관리" "SUID/SGID 파일 점검" \
        "불필요한 SUID/SGID 파일 없으면 양호" "중" "$status" \
        "${suid_list:-표준 파일만 존재}" \
        "불필요한 파일: chmod -s <파일경로>"
    print_result "U-15" "SUID/SGID 파일 점검" "$status"

    # U-16: world-writable 파일 점검
    local ww_list; ww_list=$(find / -xdev -type f -perm -0002 2>/dev/null | grep -v "^/proc" | head -20)
    [[ -z "$ww_list" ]] && status="양호" || status="불량"
    add_result "U-16" "파일관리" "world-writable 파일 점검" \
        "일반 파일에 others 쓰기 권한 없으면 양호" "중" "$status" \
        "${ww_list:-없음}" \
        "chmod o-w <파일경로>"
    print_result "U-16" "world-writable 파일 점검" "$status"

    # U-17: /tmp, /var/tmp sticky bit 설정
    local tmp_perm; tmp_perm=$(file_perm /tmp)
    local vtmp_perm; vtmp_perm=$(file_perm /var/tmp 2>/dev/null || echo "N/A")
    local s1=0; local s2=0
    [[ "$tmp_perm" =~ ^1 || $(( 8#$tmp_perm & 01000 )) -eq 512 ]] || [[ "${tmp_perm: -1}" -ge 4 && "$tmp_perm" =~ ^1 ]] && s1=1
    ( stat -c "%a" /tmp 2>/dev/null | grep -q "^1" ) && s1=1
    ( stat -c "%a" /var/tmp 2>/dev/null | grep -q "^1" ) && s2=1
    [[ $s1 -eq 1 && $s2 -eq 1 ]] && status="양호" || status="불량"
    add_result "U-17" "파일관리" "/tmp sticky bit 설정" \
        "/tmp, /var/tmp에 sticky bit(1777) 설정 시 양호" "중" "$status" \
        "/tmp: $tmp_perm, /var/tmp: $vtmp_perm" \
        "chmod +t /tmp /var/tmp"
    print_result "U-17" "/tmp sticky bit 설정" "$status"

    # U-18: .rhosts, hosts.equiv 파일 제거
    local rhost_files; rhost_files=$(find /home /root -name ".rhosts" -o -name ".netrc" 2>/dev/null; [ -f /etc/hosts.equiv ] && echo "/etc/hosts.equiv")
    [[ -z "$rhost_files" ]] && status="양호" || status="불량"
    add_result "U-18" "파일관리" ".rhosts / hosts.equiv 파일 제거" \
        "r-command 인증 파일 미존재 시 양호" "상" "$status" \
        "${rhost_files:-없음}" \
        "rm -f /etc/hosts.equiv ~/.rhosts ~/.netrc"
    print_result "U-18" ".rhosts / hosts.equiv 제거" "$status"

    # U-19: /etc/crontab 소유자 및 권한
    local cp; cp=$(file_perm /etc/crontab 2>/dev/null || echo "N/A")
    local co; co=$(file_owner /etc/crontab 2>/dev/null || echo "N/A")
    [[ "$co" == "root" && "$cp" -le 640 ]] && status="양호" || status="불량"
    add_result "U-19" "파일관리" "/etc/crontab 파일 권한" \
        "소유자 root, 권한 640 이하이면 양호" "중" "$status" \
        "소유자: $co, 권한: $cp" \
        "chown root:root /etc/crontab && chmod 640 /etc/crontab"
    print_result "U-19" "/etc/crontab 파일 권한" "$status"

    # U-20: at/cron 허용 파일 설정
    local allow_ok=1
    for f in /etc/cron.allow /etc/at.allow; do
        [ -f "$f" ] || allow_ok=0
    done
    [[ $allow_ok -eq 1 ]] && status="양호" || status="확인필요"
    add_result "U-20" "파일관리" "cron/at 접근 허용 파일 설정" \
        "/etc/cron.allow, /etc/at.allow 존재 시 양호" "중" "$status" \
        "cron.allow: $([ -f /etc/cron.allow ] && echo 존재 || echo 미존재), at.allow: $([ -f /etc/at.allow ] && echo 존재 || echo 미존재)" \
        "touch /etc/cron.allow /etc/at.allow && chmod 640 /etc/cron.allow /etc/at.allow"
    print_result "U-20" "cron/at 접근 허용 파일 설정" "$status"

    # U-21: /etc/hosts 파일 권한
    local hp; hp=$(file_perm /etc/hosts); local ho; ho=$(file_owner /etc/hosts)
    [[ "$ho" == "root" && "$hp" -le 644 ]] && status="양호" || status="불량"
    add_result "U-21" "파일관리" "/etc/hosts 파일 권한" \
        "소유자 root, 권한 644 이하이면 양호" "중" "$status" \
        "소유자: $ho, 권한: $hp" \
        "chown root:root /etc/hosts && chmod 644 /etc/hosts"
    print_result "U-21" "/etc/hosts 파일 권한" "$status"

    # U-22: 홈 디렉터리 권한 (755 이하)
    local bad_home; bad_home=$(awk -F: '$3>=1000 && $3<65534 {print $6}' /etc/passwd 2>/dev/null | \
        while read -r d; do [ -d "$d" ] && [ "$(stat -c "%a" "$d" 2>/dev/null)" -gt 755 ] 2>/dev/null && echo "$d"; done | head -10)
    [[ -z "$bad_home" ]] && status="양호" || status="불량"
    add_result "U-22" "파일관리" "사용자 홈 디렉터리 권한" \
        "홈 디렉터리 755 이하이면 양호" "중" "$status" \
        "${bad_home:-모든 홈 디렉터리 권한 양호}" \
        "chmod 755 <홈디렉터리>"
    print_result "U-22" "사용자 홈 디렉터리 권한" "$status"

    # U-23: 심볼릭 링크 보호 (fs.protected_symlinks)
    local sym; sym=$(sysctl_val "fs.protected_symlinks")
    [[ "$sym" == "1" ]] && status="양호" || status="불량"
    add_result "U-23" "파일관리" "심볼릭 링크 보호 설정" \
        "fs.protected_symlinks=1 이면 양호 (링크 공격 방지)" "중" "$status" \
        "fs.protected_symlinks: ${sym:-미설정}" \
        "echo 'fs.protected_symlinks=1' >> /etc/sysctl.conf && sysctl -p"
    print_result "U-23" "심볼릭 링크 보호 설정" "$status"

    # U-24: 하드 링크 보호 (fs.protected_hardlinks)
    local hl; hl=$(sysctl_val "fs.protected_hardlinks")
    [[ "$hl" == "1" ]] && status="양호" || status="불량"
    add_result "U-24" "파일관리" "하드 링크 보호 설정" \
        "fs.protected_hardlinks=1 이면 양호" "중" "$status" \
        "fs.protected_hardlinks: ${hl:-미설정}" \
        "echo 'fs.protected_hardlinks=1' >> /etc/sysctl.conf && sysctl -p"
    print_result "U-24" "하드 링크 보호 설정" "$status"

    # U-25: /dev/mem 접근 제한
    local devmem_perm; devmem_perm=$(file_perm /dev/mem 2>/dev/null || echo "N/A")
    local devmem_ok; devmem_ok=$(grep -rE "CONFIG_STRICT_DEVMEM=y|CONFIG_IO_STRICT_DEVMEM=y" /boot/config-$(uname -r) 2>/dev/null | head -1)
    [[ -n "$devmem_ok" ]] && status="양호" || status="확인필요"
    add_result "U-25" "파일관리" "/dev/mem 접근 제한" \
        "CONFIG_STRICT_DEVMEM 커널 옵션 활성화 시 양호" "중" "$status" \
        "${devmem_ok:-커널 설정 확인 불가}, /dev/mem 권한: $devmem_perm" \
        "커널 컴파일 시 CONFIG_STRICT_DEVMEM=y 설정 필요"
    print_result "U-25" "/dev/mem 접근 제한" "$status"

    # U-26: 코어 덤프 비활성화
    local core_size; core_size=$(ulimit -c 2>/dev/null || echo "unknown")
    local core_sysctl; core_sysctl=$(sysctl_val "kernel.core_pattern")
    local core_limits; core_limits=$(grep -rE "core" /etc/security/limits.conf /etc/security/limits.d/ 2>/dev/null | grep -v "^#" | head -3)
    [[ "$core_size" == "0" || -n "$(echo "$core_limits" | grep -E "\* (hard|soft) core 0")" ]] && status="양호" || status="불량"
    add_result "U-26" "파일관리" "코어 덤프 비활성화" \
        "코어 덤프 비활성화 시 양호 (메모리 정보 유출 방지)" "중" "$status" \
        "ulimit -c: $core_size, kernel.core_pattern: ${core_sysctl:-미설정}" \
        "echo '* hard core 0' >> /etc/security/limits.conf\necho 'ulimit -S -c 0' >> /etc/profile"
    print_result "U-26" "코어 덤프 비활성화" "$status"
}

# ══════════════════════════════════════════════════════════════════════════════
#  3. 서비스 관리 (U-27 ~ U-46)
# ══════════════════════════════════════════════════════════════════════════════
check_service() {
    print_section "서비스 관리"

    # U-27: telnet 서비스 비활성화
    local telnet_on=0
    svc_active telnet && telnet_on=1
    svc_active xinetd && grep -qE "^\s*service telnet" /etc/xinetd.d/telnet 2>/dev/null && \
        ! grep -q "disable.*=.*yes" /etc/xinetd.d/telnet 2>/dev/null && telnet_on=1
    [[ $telnet_on -eq 0 ]] && status="양호" || status="불량"
    add_result "U-27" "서비스관리" "telnet 서비스 비활성화" \
        "telnet 서비스 중지 시 양호 (평문 전송 위험)" "상" "$status" \
        "telnet 서비스: $([ $telnet_on -eq 1 ] && echo 실행중 || echo 중지됨)" \
        "systemctl disable --now telnet.socket; SSH 사용 권장"
    print_result "U-27" "telnet 서비스 비활성화" "$status"

    # U-28: FTP 익명 접근 제한
    local ftp_anon=0
    for f in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf /etc/proftpd/proftpd.conf; do
        [ -f "$f" ] && grep -qE "^\s*anonymous_enable\s*=\s*YES" "$f" 2>/dev/null && ftp_anon=1
    done
    [[ $ftp_anon -eq 0 ]] && status="양호" || status="불량"
    add_result "U-28" "서비스관리" "FTP 익명 접근 제한" \
        "FTP 익명 로그인 비활성화 시 양호" "상" "$status" \
        "anonymous_enable: $([ $ftp_anon -eq 1 ] && echo YES || echo NO/미설정)" \
        "vsftpd.conf: anonymous_enable=NO 설정"
    print_result "U-28" "FTP 익명 접근 제한" "$status"

    # U-29: rsh/rlogin/rexec 서비스 비활성화
    local rsh_on=0
    for svc in rsh rlogin rexec rsh.socket rlogin.socket; do
        svc_active "$svc" && rsh_on=1
    done
    [[ $rsh_on -eq 0 ]] && status="양호" || status="불량"
    add_result "U-29" "서비스관리" "r-command 서비스 비활성화" \
        "rsh/rlogin/rexec 서비스 중지 시 양호" "상" "$status" \
        "r-command 서비스: $([ $rsh_on -eq 1 ] && echo 실행중 || echo 중지됨)" \
        "systemctl disable --now rsh.socket rlogin.socket rexec.socket"
    print_result "U-29" "r-command 서비스 비활성화" "$status"

    # U-30: NFS 공개 공유 점검
    local nfs_export; nfs_export=$(grep -E "^\s*/.*\*" /etc/exports 2>/dev/null | head -5)
    [[ -z "$nfs_export" ]] && status="양호" || status="불량"
    add_result "U-30" "서비스관리" "NFS 공개 공유 제한" \
        "NFS exports에 와일드카드(*) 접근 없으면 양호" "중" "$status" \
        "${nfs_export:-공개 NFS 공유 없음}" \
        "/etc/exports에서 * 를 특정 IP/서브넷으로 변경 후 exportfs -ra"
    print_result "U-30" "NFS 공개 공유 제한" "$status"

    # U-31: SNMP 기본 커뮤니티 스트링
    local snmp_default=0
    for f in /etc/snmp/snmpd.conf /etc/snmp/snmp.conf; do
        [ -f "$f" ] && grep -qE "^\s*(community|rocommunity|rwcommunity)\s+(public|private)" "$f" 2>/dev/null && snmp_default=1
    done
    [[ $snmp_default -eq 0 ]] && status="양호" || status="불량"
    add_result "U-31" "서비스관리" "SNMP 기본 커뮤니티 스트링 변경" \
        "public/private 기본값 미사용 시 양호" "상" "$status" \
        "기본 커뮤니티 스트링(public/private): $([ $snmp_default -eq 1 ] && echo 사용중 || echo 미사용)" \
        "/etc/snmp/snmpd.conf에서 community 문자열 변경, SNMPv3 사용 권고"
    print_result "U-31" "SNMP 기본 커뮤니티 스트링" "$status"

    # U-32: SSH Protocol 버전 (SSHv1 비활성화)
    local sshcfg="/etc/ssh/sshd_config"
    local proto; proto=$(grep -iE "^\s*Protocol" "$sshcfg" 2>/dev/null | awk '{print $2}')
    # OpenSSH 7.6+에서 Protocol 지시어 제거됨 (자동으로 v2만 사용)
    [[ -z "$proto" || "$proto" == "2" ]] && status="양호" || status="불량"
    add_result "U-32" "서비스관리" "SSH 프로토콜 버전 설정" \
        "SSHv2만 사용(Protocol 2) 또는 지시어 없으면 양호" "상" "$status" \
        "Protocol: ${proto:-v2 전용(지시어 없음 = 양호)}" \
        "sshd_config: Protocol 1 항목 제거 및 Protocol 2 설정"
    print_result "U-32" "SSH 프로토콜 버전" "$status"

    # U-33: SSH MaxAuthTries 설정
    local maxauth; maxauth=$(grep -iE "^\s*MaxAuthTries" "$sshcfg" 2>/dev/null | awk '{print $2}')
    maxauth=${maxauth:-6}
    [[ "$maxauth" -le 4 ]] && status="양호" || status="불량"
    add_result "U-33" "서비스관리" "SSH MaxAuthTries 설정" \
        "MaxAuthTries 4 이하이면 양호" "중" "$status" \
        "MaxAuthTries: $maxauth" \
        "sshd_config: MaxAuthTries 4 설정 후 systemctl restart sshd"
    print_result "U-33" "SSH MaxAuthTries 설정" "$status"

    # U-34: SSH 빈 패스워드 허용 금지
    local pempty; pempty=$(grep -iE "^\s*PermitEmptyPasswords" "$sshcfg" 2>/dev/null | awk '{print $2}')
    [[ "${pempty:-no}" =~ ^[Nn][Oo]$ ]] && status="양호" || status="불량"
    add_result "U-34" "서비스관리" "SSH 빈 패스워드 금지" \
        "PermitEmptyPasswords no 이면 양호" "상" "$status" \
        "PermitEmptyPasswords: ${pempty:-no(기본값)}" \
        "sshd_config: PermitEmptyPasswords no 설정"
    print_result "U-34" "SSH 빈 패스워드 금지" "$status"

    # U-35: SSH 배너 설정
    local banner; banner=$(grep -iE "^\s*Banner" "$sshcfg" 2>/dev/null | awk '{print $2}')
    [[ -n "$banner" && -f "$banner" ]] && status="양호" || status="불량"
    add_result "U-35" "서비스관리" "SSH 배너 설정" \
        "Banner 설정 및 배너 파일 존재 시 양호" "하" "$status" \
        "Banner 파일: ${banner:-미설정}" \
        "sshd_config: Banner /etc/issue.net 설정 후 배너 파일 작성"
    print_result "U-35" "SSH 배너 설정" "$status"

    # U-36: SSH X11Forwarding 제한
    local x11fwd; x11fwd=$(grep -iE "^\s*X11Forwarding" "$sshcfg" 2>/dev/null | awk '{print $2}')
    [[ "${x11fwd:-yes}" =~ ^[Nn][Oo]$ ]] && status="양호" || status="불량"
    add_result "U-36" "서비스관리" "SSH X11Forwarding 제한" \
        "X11Forwarding no 이면 양호" "하" "$status" \
        "X11Forwarding: ${x11fwd:-yes(기본값)}" \
        "sshd_config: X11Forwarding no 설정"
    print_result "U-36" "SSH X11Forwarding 제한" "$status"

    # U-37: 웹서버 버전 노출 방지 (Apache/Nginx)
    local web_ver_hidden=0
    if command -v httpd &>/dev/null || command -v apache2 &>/dev/null; then
        local apache_conf; apache_conf=$(find /etc/apache2 /etc/httpd -name "*.conf" 2>/dev/null | xargs grep -l "ServerTokens" 2>/dev/null | head -1)
        local stokens; stokens=$(grep -rE "^\s*ServerTokens" /etc/apache2/ /etc/httpd/ 2>/dev/null | grep -v "^#" | awk '{print $2}' | tail -1)
        [[ "$stokens" =~ ^(Prod|ProductOnly)$ ]] && web_ver_hidden=1
    fi
    if command -v nginx &>/dev/null; then
        local ntokens; ntokens=$(grep -rE "^\s*server_tokens" /etc/nginx/ 2>/dev/null | grep -v "^#" | awk '{print $2}' | tr -d ';' | tail -1)
        [[ "$ntokens" == "off" ]] && web_ver_hidden=1
    fi
    if ! command -v httpd &>/dev/null && ! command -v apache2 &>/dev/null && ! command -v nginx &>/dev/null; then
        status="N/A"
    else
        [[ $web_ver_hidden -eq 1 ]] && status="양호" || status="불량"
    fi
    add_result "U-37" "서비스관리" "웹서버 버전 정보 숨김" \
        "ServerTokens Prod / server_tokens off 설정 시 양호" "중" "$status" \
        "Apache ServerTokens: ${stokens:-N/A}, Nginx server_tokens: ${ntokens:-N/A}" \
        "Apache: ServerTokens Prod / Nginx: server_tokens off"
    print_result "U-37" "웹서버 버전 정보 숨김" "$status"

    # U-38: Sendmail/Postfix VRFY/EXPN 비활성화
    if command -v sendmail &>/dev/null || command -v postfix &>/dev/null; then
        local vrfy; vrfy=$(grep -rE "^\s*(PrivacyOptions|smtpd_disable_vrfy_command)" /etc/mail/ /etc/postfix/ 2>/dev/null | head -2)
        [[ -n "$vrfy" ]] && status="양호" || status="불량"
        local vrfy_detail="$vrfy"
    else
        status="N/A"; local vrfy_detail="메일서버 미설치"
    fi
    add_result "U-38" "서비스관리" "메일서버 VRFY/EXPN 비활성화" \
        "PrivacyOptions=goaway 또는 disable_vrfy_command=yes 시 양호" "중" "$status" \
        "${vrfy_detail:-미설정}" \
        "Postfix: /etc/postfix/main.cf에 disable_vrfy_command=yes 추가"
    print_result "U-38" "메일서버 VRFY/EXPN 비활성화" "$status"

    # U-39: DNS Zone Transfer 제한
    if command -v named &>/dev/null || svc_active named || svc_active bind9; then
        local zt; zt=$(grep -rE "allow-transfer" /etc/named.conf /etc/bind/ 2>/dev/null | grep -v "^#" | head -3)
        [[ -n "$zt" ]] && status="양호" || status="불량"
    else
        status="N/A"; local zt="DNS 서버 미설치"
    fi
    add_result "U-39" "서비스관리" "DNS Zone Transfer 제한" \
        "allow-transfer 설정으로 zone transfer 제한 시 양호" "중" "$status" \
        "${zt:-미설정}" \
        "named.conf: allow-transfer { none; }; 설정"
    print_result "U-39" "DNS Zone Transfer 제한" "$status"

    # U-40: NTP 동기화 설정
    local ntp_ok=0
    if command -v timedatectl &>/dev/null; then
        timedatectl status 2>/dev/null | grep -q "synchronized: yes" && ntp_ok=1
    fi
    svc_active ntpd && ntp_ok=1; svc_active chronyd && ntp_ok=1
    [[ $ntp_ok -eq 1 ]] && status="양호" || status="불량"
    add_result "U-40" "서비스관리" "NTP 시간 동기화 설정" \
        "NTP 서비스 활성화 및 동기화 시 양호" "하" "$status" \
        "$(timedatectl status 2>/dev/null | grep -E "synchronized|NTP" | tr '\n' ' ')" \
        "systemctl enable --now chronyd; timedatectl set-ntp true"
    print_result "U-40" "NTP 시간 동기화 설정" "$status"

    # U-41: 불필요한 서비스 비활성화
    local unneeded=()
    for svc in tftp talk ntalk chargen daytime discard echo time finger; do
        svc_active "$svc" && unneeded+=("$svc")
        svc_active "${svc}.socket" && unneeded+=("${svc}.socket")
    done
    [[ ${#unneeded[@]} -eq 0 ]] && status="양호" || status="불량"
    add_result "U-41" "서비스관리" "불필요한 서비스 비활성화" \
        "tftp/talk/chargen 등 불필요 서비스 중지 시 양호" "중" "$status" \
        "실행 중인 불필요 서비스: ${unneeded[*]:-없음}" \
        "systemctl disable --now <서비스명>"
    print_result "U-41" "불필요한 서비스 비활성화" "$status"

    # U-42: sudo 권한 관리
    local sudoers_all; sudoers_all=$(grep -rE "ALL\s*=\s*\(ALL\)\s*ALL|NOPASSWD.*ALL" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | \
        grep -v "^#" | grep -v "^%wheel\|^%sudo" | head -10)
    [[ -z "$sudoers_all" ]] && status="양호" || status="확인필요"
    add_result "U-42" "서비스관리" "sudo 권한 최소화" \
        "개인 계정 NOPASSWD ALL 권한 없으면 양호" "상" "$status" \
        "${sudoers_all:-과도한 sudo 권한 없음}" \
        "/etc/sudoers에서 불필요한 NOPASSWD:ALL 제거 (visudo 사용)"
    print_result "U-42" "sudo 권한 최소화" "$status"

    # U-43: SSH ClientAliveInterval / Timeout 설정
    local cai; cai=$(grep -iE "^\s*ClientAliveInterval" "$sshcfg" 2>/dev/null | awk '{print $2}')
    local cac; cac=$(grep -iE "^\s*ClientAliveCountMax" "$sshcfg" 2>/dev/null | awk '{print $2}')
    cai=${cai:-0}; cac=${cac:-3}
    [[ "$cai" -gt 0 && "$cai" -le 300 ]] && status="양호" || status="불량"
    add_result "U-43" "서비스관리" "SSH 유휴 세션 타임아웃" \
        "ClientAliveInterval 300초 이하 설정 시 양호" "중" "$status" \
        "ClientAliveInterval: $cai, ClientAliveCountMax: $cac" \
        "sshd_config: ClientAliveInterval 300, ClientAliveCountMax 0"
    print_result "U-43" "SSH 유휴 세션 타임아웃" "$status"

    # U-44: SSH AllowUsers/AllowGroups 설정
    local allow_users; allow_users=$(grep -iE "^\s*(AllowUsers|AllowGroups|DenyUsers|DenyGroups)" "$sshcfg" 2>/dev/null)
    [[ -n "$allow_users" ]] && status="양호" || status="불량"
    add_result "U-44" "서비스관리" "SSH 접속 허용 계정 제한" \
        "AllowUsers 또는 AllowGroups 설정 시 양호" "중" "$status" \
        "${allow_users:-미설정}" \
        "sshd_config: AllowUsers <사용자명> 또는 AllowGroups sshusers 설정"
    print_result "U-44" "SSH 접속 허용 계정 제한" "$status"

    # U-45: rsync 인증 없는 접근 제한
    if svc_active rsync || [ -f /etc/rsyncd.conf ]; then
        local rsync_auth; rsync_auth=$(grep -E "^\s*auth users|secrets file" /etc/rsyncd.conf 2>/dev/null)
        [[ -n "$rsync_auth" ]] && status="양호" || status="불량"
        local rsync_detail="${rsync_auth:-인증 없이 rsync 서비스 실행 중}"
    else
        status="N/A"; local rsync_detail="rsync 서비스 미실행"
    fi
    add_result "U-45" "서비스관리" "rsync 인증 설정" \
        "auth users 및 secrets file 설정 시 양호" "중" "$status" \
        "$rsync_detail" \
        "/etc/rsyncd.conf: auth users, secrets file 설정"
    print_result "U-45" "rsync 인증 설정" "$status"

    # U-46: 로그인 배너 설정
    local banner_set=0
    [ -s /etc/issue ] && banner_set=1
    [ -s /etc/issue.net ] && banner_set=1
    local motd_ok; motd_ok=$(grep -rE "Authorized|authorized|경고|WARNING" /etc/issue /etc/issue.net /etc/motd 2>/dev/null | head -1)
    [[ $banner_set -eq 1 && -n "$motd_ok" ]] && status="양호" || status="불량"
    add_result "U-46" "서비스관리" "로그인 배너 설정" \
        "/etc/issue, /etc/issue.net에 경고 문구 설정 시 양호" "하" "$status" \
        "배너 파일: $([ $banner_set -eq 1 ] && echo 존재 || echo 미존재), 경고문구: $([ -n "$motd_ok" ] && echo 있음 || echo 없음)" \
        "echo 'Authorized access only. All activity may be monitored.' > /etc/issue.net"
    print_result "U-46" "로그인 배너 설정" "$status"
}

# ══════════════════════════════════════════════════════════════════════════════
#  4. 패치 관리 (U-47 ~ U-49)
# ══════════════════════════════════════════════════════════════════════════════
check_patch() {
    print_section "패치 관리"

    # U-47: 커널 버전 및 EOL
    local kver; kver=$(uname -r)
    local kmaj; kmaj=$(echo "$kver" | cut -d. -f1,2)
    # EOL 커널 목록 (2026-04 기준): 5.4 LTS(2025-12 EOL), 4.x EOL
    local eol_kernels=("4.4" "4.9" "4.14" "4.19" "5.4" "5.10")
    local is_eol=0
    for ek in "${eol_kernels[@]}"; do [[ "$kmaj" == "$ek" ]] && is_eol=1; done
    [[ $is_eol -eq 0 ]] && status="양호" || status="불량"
    add_result "U-47" "패치관리" "커널 버전 및 EOL 점검" \
        "EOL 종료된 커널 미사용 시 양호" "상" "$status" \
        "현재 커널: $kver, EOL 여부: $([ $is_eol -eq 1 ] && echo 'EOL(업그레이드 필요)' || echo '지원 중')" \
        "커널 업그레이드: dnf/apt upgrade kernel 후 재부팅"
    print_result "U-47" "커널 버전 및 EOL 점검" "$status"

    # U-48: 보안 업데이트 미적용 패키지
    local pending_count=0
    if command -v dnf &>/dev/null; then
        pending_count=$(dnf check-update --security -q 2>/dev/null | grep -c "^[a-zA-Z]" || true)
    elif command -v apt-get &>/dev/null; then
        apt-get update -qq 2>/dev/null
        pending_count=$(apt-get -s upgrade 2>/dev/null | grep -c "^Inst" || true)
    elif command -v yum &>/dev/null; then
        pending_count=$(yum check-update --security -q 2>/dev/null | grep -c "^[a-zA-Z]" || true)
    fi
    [[ "$pending_count" -eq 0 ]] && status="양호" || status="불량"
    add_result "U-48" "패치관리" "보안 업데이트 적용 현황" \
        "미적용 보안 업데이트 없으면 양호" "상" "$status" \
        "미적용 보안 업데이트: ${pending_count}건" \
        "dnf update --security / apt-get upgrade"
    print_result "U-48" "보안 업데이트 적용 현황" "$status"

    # U-49: 자동 보안 업데이트 설정
    local auto_update=0
    [ -f /etc/dnf/automatic.conf ] && grep -q "apply_updates.*=.*yes" /etc/dnf/automatic.conf 2>/dev/null && auto_update=1
    [ -f /etc/apt/apt.conf.d/20auto-upgrades ] && grep -q "Unattended-Upgrade.*1" /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null && auto_update=1
    svc_active dnf-automatic.timer && auto_update=1
    svc_active unattended-upgrades && auto_update=1
    [[ $auto_update -eq 1 ]] && status="양호" || status="확인필요"
    add_result "U-49" "패치관리" "자동 보안 업데이트 설정" \
        "자동 보안 업데이트 활성화 시 양호" "중" "$status" \
        "자동 업데이트: $([ $auto_update -eq 1 ] && echo 활성화 || echo 비활성화)" \
        "RHEL: dnf install dnf-automatic && systemctl enable --now dnf-automatic.timer\nDebian: apt install unattended-upgrades && dpkg-reconfigure unattended-upgrades"
    print_result "U-49" "자동 보안 업데이트 설정" "$status"
}

# ══════════════════════════════════════════════════════════════════════════════
#  5. 로그 관리 (U-50 ~ U-54)
# ══════════════════════════════════════════════════════════════════════════════
check_log() {
    print_section "로그 관리"

    # U-50: syslog/rsyslog/journald 설정
    local log_ok=0
    svc_active rsyslog && log_ok=1
    svc_active syslog && log_ok=1
    svc_active systemd-journald && log_ok=1
    [[ $log_ok -eq 1 ]] && status="양호" || status="불량"
    add_result "U-50" "로그관리" "시스템 로그 서비스 활성화" \
        "rsyslog 또는 journald 실행 중이면 양호" "상" "$status" \
        "rsyslog: $(svc_active rsyslog && echo 실행 || echo 중지), journald: $(svc_active systemd-journald && echo 실행 || echo 중지)" \
        "systemctl enable --now rsyslog"
    print_result "U-50" "시스템 로그 서비스 활성화" "$status"

    # U-51: 감사(auditd) 서비스 활성화
    svc_active auditd && status="양호" || status="불량"
    local audit_rules; audit_rules=$(auditctl -l 2>/dev/null | wc -l || echo "0")
    add_result "U-51" "로그관리" "감사(auditd) 서비스 활성화" \
        "auditd 실행 및 감사 규칙 설정 시 양호" "중" "$status" \
        "auditd: $(svc_active auditd && echo 실행 || echo 중지), 감사 규칙 수: $audit_rules" \
        "systemctl enable --now auditd && ausearch -m LOGIN"
    print_result "U-51" "감사(auditd) 서비스 활성화" "$status"

    # U-52: 로그 파일 권한 (640 이하)
    local bad_log; bad_log=$(find /var/log -type f \( -perm -0004 -o -perm -0002 \) 2>/dev/null | \
        grep -Ev "(wtmp|btmp|lastlog|journal)" | head -10)
    [[ -z "$bad_log" ]] && status="양호" || status="불량"
    add_result "U-52" "로그관리" "로그 파일 권한 설정" \
        "로그 파일 others 읽기/쓰기 없으면 양호" "중" "$status" \
        "${bad_log:-로그 파일 권한 양호}" \
        "chmod o-rw <로그파일>"
    print_result "U-52" "로그 파일 권한 설정" "$status"

    # U-53: sudo 로그 설정
    local sudo_log; sudo_log=$(grep -E "^\s*Defaults.*logfile|^\s*Defaults.*syslog" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | head -2)
    [[ -n "$sudo_log" ]] && status="양호" || status="불량"
    add_result "U-53" "로그관리" "sudo 명령 로그 설정" \
        "sudoers Defaults logfile 또는 syslog 설정 시 양호" "중" "$status" \
        "${sudo_log:-sudo 로그 미설정}" \
        "visudo: Defaults logfile=/var/log/sudo.log 추가"
    print_result "U-53" "sudo 명령 로그 설정" "$status"

    # U-54: 로그 보존 기간 설정
    local log_rotate; log_rotate=$(grep -E "^\s*rotate\s+[0-9]+" /etc/logrotate.conf 2>/dev/null | awk '{print $2}')
    local journal_max; journal_max=$(grep -E "^\s*MaxRetentionSec|SystemMaxUse" /etc/systemd/journald.conf 2>/dev/null | head -2)
    [[ "${log_rotate:-0}" -ge 12 || -n "$journal_max" ]] && status="양호" || status="확인필요"
    add_result "U-54" "로그관리" "로그 보존 기간 설정" \
        "logrotate rotate 12주 이상 또는 journald 보존 기간 설정 시 양호" "중" "$status" \
        "logrotate rotate: ${log_rotate:-미설정}, journald: ${journal_max:-미설정}" \
        "/etc/logrotate.conf: rotate 52 weekly compress 설정"
    print_result "U-54" "로그 보존 기간 설정" "$status"
}

# ══════════════════════════════════════════════════════════════════════════════
#  6. 네트워크 보안 (U-55 ~ U-62)
# ══════════════════════════════════════════════════════════════════════════════
check_network() {
    print_section "네트워크 보안"

    # U-55: IP 포워딩 비활성화
    local ipfwd; ipfwd=$(sysctl_val "net.ipv4.ip_forward")
    [[ "$ipfwd" == "0" ]] && status="양호" || status="불량"
    add_result "U-55" "네트워크" "IP 포워딩 비활성화" \
        "net.ipv4.ip_forward=0 이면 양호 (라우터가 아닌 경우)" "중" "$status" \
        "net.ipv4.ip_forward: $ipfwd" \
        "echo 'net.ipv4.ip_forward=0' >> /etc/sysctl.conf && sysctl -p"
    print_result "U-55" "IP 포워딩 비활성화" "$status"

    # U-56: ICMP redirect 수신 비활성화
    local icmp_r; icmp_r=$(sysctl_val "net.ipv4.conf.all.accept_redirects")
    [[ "$icmp_r" == "0" ]] && status="양호" || status="불량"
    add_result "U-56" "네트워크" "ICMP redirect 수신 비활성화" \
        "net.ipv4.conf.all.accept_redirects=0 이면 양호" "중" "$status" \
        "accept_redirects: $icmp_r" \
        "echo 'net.ipv4.conf.all.accept_redirects=0' >> /etc/sysctl.conf && sysctl -p"
    print_result "U-56" "ICMP redirect 수신 비활성화" "$status"

    # U-57: SYN Cookies 활성화 (DDoS 방어)
    local syncook; syncook=$(sysctl_val "net.ipv4.tcp_syncookies")
    [[ "$syncook" == "1" ]] && status="양호" || status="불량"
    add_result "U-57" "네트워크" "TCP SYN Cookies 활성화" \
        "net.ipv4.tcp_syncookies=1 이면 양호 (SYN Flood 방어)" "중" "$status" \
        "tcp_syncookies: $syncook" \
        "echo 'net.ipv4.tcp_syncookies=1' >> /etc/sysctl.conf && sysctl -p"
    print_result "U-57" "TCP SYN Cookies 활성화" "$status"

    # U-58: 역방향 경로 필터링 (IP Spoofing 방어)
    local rpf; rpf=$(sysctl_val "net.ipv4.conf.all.rp_filter")
    [[ "$rpf" -ge 1 ]] && status="양호" || status="불량"
    add_result "U-58" "네트워크" "역방향 경로 필터링 (rp_filter)" \
        "rp_filter=1 이상이면 양호 (IP 스푸핑 방어)" "중" "$status" \
        "net.ipv4.conf.all.rp_filter: $rpf" \
        "echo 'net.ipv4.conf.all.rp_filter=1' >> /etc/sysctl.conf && sysctl -p"
    print_result "U-58" "역방향 경로 필터링" "$status"

    # U-59: 방화벽 활성화
    local fw_ok=0
    command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "active" && fw_ok=1
    svc_active firewalld && fw_ok=1
    iptables -L INPUT -n 2>/dev/null | grep -qv "^Chain\|^target\|^$" && fw_ok=1
    command -v nft &>/dev/null && nft list ruleset 2>/dev/null | grep -q "hook input" && fw_ok=1
    [[ $fw_ok -eq 1 ]] && status="양호" || status="불량"
    add_result "U-59" "네트워크" "호스트 방화벽 활성화" \
        "iptables/firewalld/ufw/nftables 활성화 시 양호" "상" "$status" \
        "firewalld: $(svc_active firewalld && echo 실행 || echo 중지), ufw: $(command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -oE 'active|inactive' || echo N/A)" \
        "systemctl enable --now firewalld 또는 ufw enable"
    print_result "U-59" "호스트 방화벽 활성화" "$status"

    # U-60: 불필요한 열린 포트 점검
    local open_ports; open_ports=$(ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null | head -30)
    local risky_ports; risky_ports=$(echo "$open_ports" | grep -E ":(23|21|512|513|514|111|2049|161|137|138|139)\s" | head -10)
    [[ -z "$risky_ports" ]] && status="양호" || status="불량"
    add_result "U-60" "네트워크" "위험 포트 개방 여부 점검" \
        "telnet(23)/ftp(21)/rsh(512~514)/NFS(2049)/RPC(111) 미개방 시 양호" "상" "$status" \
        "${risky_ports:-위험 포트 미개방}" \
        "systemctl disable --now 해당서비스 또는 방화벽 차단"
    print_result "U-60" "위험 포트 개방 여부 점검" "$status"

    # U-61: IPv6 설정 (불필요 시 비활성화)
    local ipv6_en; ipv6_en=$(sysctl_val "net.ipv6.conf.all.disable_ipv6")
    # IPv6 사용 여부와 무관하게 disable이 명시적으로 설정돼 있거나 사용 중이면 양호로 처리
    [[ "$ipv6_en" == "1" || "$ipv6_en" == "0" ]] && status="양호" || status="확인필요"
    add_result "U-61" "네트워크" "IPv6 설정 확인" \
        "IPv6 명시적 활성화 또는 비활성화 설정 시 양호" "하" "$status" \
        "disable_ipv6: ${ipv6_en:-미설정}" \
        "불필요 시: echo 'net.ipv6.conf.all.disable_ipv6=1' >> /etc/sysctl.conf"
    print_result "U-61" "IPv6 설정 확인" "$status"

    # U-62: 소스 라우팅 비활성화
    local srcrt; srcrt=$(sysctl_val "net.ipv4.conf.all.accept_source_route")
    [[ "$srcrt" == "0" ]] && status="양호" || status="불량"
    add_result "U-62" "네트워크" "소스 라우팅 비활성화" \
        "accept_source_route=0 이면 양호" "중" "$status" \
        "net.ipv4.conf.all.accept_source_route: $srcrt" \
        "echo 'net.ipv4.conf.all.accept_source_route=0' >> /etc/sysctl.conf && sysctl -p"
    print_result "U-62" "소스 라우팅 비활성화" "$status"
}

# ══════════════════════════════════════════════════════════════════════════════
#  7. 최신 취약점 / CVE 점검 (U-63 ~ U-82)
# ══════════════════════════════════════════════════════════════════════════════
check_cve() {
    print_section "최신 취약점 (CVE) 점검 - 2025~2026"

    # U-63: CVE-2024-6387 regreSSHion (OpenSSH 8.5p1~9.7p1 RCE)
    local ssh_ver_raw; ssh_ver_raw=$(ssh -V 2>&1 | grep -oE "OpenSSH_[0-9]+\.[0-9]+p[0-9]+" | head -1)
    local ssh_ver; ssh_ver=$(echo "$ssh_ver_raw" | grep -oE "[0-9]+\.[0-9]+p[0-9]+")
    local ssh_vuln=0
    if [[ -n "$ssh_ver" ]]; then
        # 취약: 8.5p1 이상 9.8p1 미만
        if ver_lt "$ssh_ver" "9.8p1" && ! ver_lt "$ssh_ver" "8.5p1"; then
            ssh_vuln=1
        fi
    fi
    [[ $ssh_vuln -eq 0 ]] && status="양호" || status="불량"
    add_result "U-63" "최신CVE" "CVE-2024-6387 regreSSHion (OpenSSH RCE)" \
        "OpenSSH 9.8p1 이상 또는 8.5p1 미만이면 양호" "상" "$status" \
        "현재 버전: ${ssh_ver_raw:-확인불가}, 취약범위: OpenSSH 8.5p1~9.7p1" \
        "OpenSSH 9.8p1 이상으로 업그레이드: dnf update openssh / apt upgrade openssh-server"
    print_result "U-63" "CVE-2024-6387 regreSSHion" "$status"

    # U-64: CVE-2024-3094 XZ Utils 백도어 (5.6.0, 5.6.1)
    local xz_ver; xz_ver=$(xz --version 2>/dev/null | head -1 | grep -oE "[0-9]+\.[0-9]+\.[0-9]+")
    [[ "$xz_ver" == "5.6.0" || "$xz_ver" == "5.6.1" ]] && status="불량" || status="양호"
    add_result "U-64" "최신CVE" "CVE-2024-3094 XZ Utils 백도어" \
        "XZ Utils 5.6.0/5.6.1 미사용 시 양호 (systemd sshd 백도어)" "상" "$status" \
        "현재 xz 버전: ${xz_ver:-확인불가}, 취약버전: 5.6.0, 5.6.1" \
        "dnf downgrade xz / apt install xz-utils=5.4.x (취약버전 제거)"
    print_result "U-64" "CVE-2024-3094 XZ Utils 백도어" "$status"

    # U-65: CVE-2023-4911 Looney Tunables (glibc buffer overflow LPE)
    local glibc_ver; glibc_ver=$(ldd --version 2>/dev/null | head -1 | grep -oE "[0-9]+\.[0-9]+")
    local glibc_vuln=0
    # glibc 2.34~2.38 구간이 취약 (패치 여부는 distro마다 다름)
    if [[ -n "$glibc_ver" ]] && ver_lt "$glibc_ver" "2.34"; then
        : # 2.34 미만은 해당 CVE 미해당
    elif [[ -n "$glibc_ver" ]] && ver_lt "$glibc_ver" "2.39"; then
        # 2.34~2.38: distro 패치 확인 필요
        glibc_vuln=2  # 확인필요
    fi
    case $glibc_vuln in
        0) status="양호" ;;
        2) status="확인필요" ;;
        *) status="불량" ;;
    esac
    add_result "U-65" "최신CVE" "CVE-2023-4911 Looney Tunables (glibc LPE)" \
        "glibc 2.39 이상 또는 배포판 패치 적용 시 양호" "상" "$status" \
        "현재 glibc 버전: ${glibc_ver:-확인불가}, 취약범위: glibc 2.34~2.38(패치 전)" \
        "dnf update glibc / apt upgrade libc6"
    print_result "U-65" "CVE-2023-4911 Looney Tunables" "$status"

    # U-66: CVE-2021-4034 PwnKit (polkit pkexec LPE)
    local pkexec_ver; pkexec_ver=$(pkexec --version 2>/dev/null | grep -oE "[0-9]+\.[0-9]+")
    local polkit_vuln=0
    [[ -n "$pkexec_ver" ]] && ver_lt "$pkexec_ver" "0.121" && polkit_vuln=1
    [[ $polkit_vuln -eq 1 ]] && status="불량" || status="양호"
    add_result "U-66" "최신CVE" "CVE-2021-4034 PwnKit (polkit pkexec LPE)" \
        "polkit 0.121 이상이면 양호" "상" "$status" \
        "현재 polkit 버전: ${pkexec_ver:-확인불가(미설치 가능)}, 취약범위: < 0.121" \
        "dnf update polkit / apt upgrade policykit-1"
    print_result "U-66" "CVE-2021-4034 PwnKit" "$status"

    # U-67: CVE-2023-22809 sudo (임의 파일 쓰기 LPE)
    local sudo_ver; sudo_ver=$(sudo --version 2>/dev/null | head -1 | grep -oE "[0-9]+\.[0-9]+\.?[0-9]*p?[0-9]*")
    local sudo_vuln=0
    [[ -n "$sudo_ver" ]] && ver_lt "$sudo_ver" "1.9.12p2" && sudo_vuln=1
    [[ $sudo_vuln -eq 1 ]] && status="불량" || status="양호"
    add_result "U-67" "최신CVE" "CVE-2023-22809 sudo 임의 파일 쓰기" \
        "sudo 1.9.12p2 이상이면 양호" "상" "$status" \
        "현재 sudo 버전: ${sudo_ver:-확인불가}, 취약범위: < 1.9.12p2" \
        "dnf update sudo / apt upgrade sudo"
    print_result "U-67" "CVE-2023-22809 sudo 취약점" "$status"

    # U-68: CVE-2024-21626 runc 컨테이너 탈출
    local runc_ver; runc_ver=$(runc --version 2>/dev/null | grep -oE "[0-9]+\.[0-9]+\.[0-9]+")
    if [[ -z "$runc_ver" ]]; then
        status="N/A"
        add_result "U-68" "최신CVE" "CVE-2024-21626 runc 컨테이너 탈출" \
            "runc 1.1.12 이상이면 양호" "상" "N/A" \
            "runc 미설치" ""
    else
        ver_lt "$runc_ver" "1.1.12" && status="불량" || status="양호"
        add_result "U-68" "최신CVE" "CVE-2024-21626 runc 컨테이너 탈출" \
            "runc 1.1.12 이상이면 양호" "상" "$status" \
            "현재 runc 버전: $runc_ver, 취약범위: < 1.1.12" \
            "dnf update runc / apt upgrade runc"
    fi
    print_result "U-68" "CVE-2024-21626 runc 컨테이너 탈출" "$status"

    # U-69: CVE-2024-5535 OpenSSL (buffer over-read)
    local openssl_ver; openssl_ver=$(openssl version 2>/dev/null | grep -oE "[0-9]+\.[0-9]+\.[0-9]+")
    local openssl_vuln=0
    if [[ -n "$openssl_ver" ]]; then
        # 취약: 3.0.x < 3.0.14, 3.1.x < 3.1.6, 3.2.x < 3.2.2, 3.3.x < 3.3.1
        local omaj; omaj=$(echo "$openssl_ver" | cut -d. -f1,2)
        case "$omaj" in
            "3.0") ver_lt "$openssl_ver" "3.0.14" && openssl_vuln=1 ;;
            "3.1") ver_lt "$openssl_ver" "3.1.6"  && openssl_vuln=1 ;;
            "3.2") ver_lt "$openssl_ver" "3.2.2"  && openssl_vuln=1 ;;
            "3.3") ver_lt "$openssl_ver" "3.3.1"  && openssl_vuln=1 ;;
        esac
    fi
    [[ $openssl_vuln -eq 1 ]] && status="불량" || status="양호"
    add_result "U-69" "최신CVE" "CVE-2024-5535 OpenSSL buffer over-read" \
        "OpenSSL 3.0.14/3.1.6/3.2.2/3.3.1 이상이면 양호" "상" "$status" \
        "현재 OpenSSL: ${openssl_ver:-확인불가}" \
        "dnf update openssl / apt upgrade openssl libssl3"
    print_result "U-69" "CVE-2024-5535 OpenSSL 취약점" "$status"

    # U-70: CVE-2023-38545 curl SOCKS5 힙 오버플로우
    local curl_ver; curl_ver=$(curl --version 2>/dev/null | head -1 | grep -oE "[0-9]+\.[0-9]+\.[0-9]+")
    local curl_vuln=0
    [[ -n "$curl_ver" ]] && ver_lt "$curl_ver" "8.4.0" && curl_vuln=1
    [[ $curl_vuln -eq 1 ]] && status="불량" || status="양호"
    add_result "U-70" "최신CVE" "CVE-2023-38545 curl SOCKS5 힙 오버플로우" \
        "curl 8.4.0 이상이면 양호" "상" "$status" \
        "현재 curl 버전: ${curl_ver:-확인불가}, 취약범위: < 8.4.0" \
        "dnf update curl / apt upgrade curl"
    print_result "U-70" "CVE-2023-38545 curl 취약점" "$status"

    # U-71: CVE-2024-1086 Linux 커널 nftables UAF (LPE)
    local kver; kver=$(uname -r)
    local k_vuln=0
    local knum; knum=$(echo "$kver" | grep -oE "^[0-9]+\.[0-9]+")
    # 취약: 5.14 ~ 6.3.11, 6.4 ~ 6.4.16, 6.5 ~ 6.5.11 등 (패치: 6.7.0 이상)
    ver_lt "$knum" "6.7" && k_vuln=1
    [[ $k_vuln -eq 1 ]] && status="확인필요" || status="양호"
    add_result "U-71" "최신CVE" "CVE-2024-1086 커널 nftables UAF (LPE)" \
        "커널 6.7 이상 또는 배포판 보안패치 적용 시 양호" "상" "$status" \
        "현재 커널: $kver, 취약범위: 5.14~6.6.x(패치 전)" \
        "커널 업그레이드 또는 배포판 보안 업데이트 적용"
    print_result "U-71" "CVE-2024-1086 커널 nftables UAF" "$status"

    # U-72: CVE-2021-44228 Log4Shell 잔존 JAR 탐색
    local log4j_found; log4j_found=$(find /opt /srv /app /home /var/lib -name "log4j-core-*.jar" 2>/dev/null | head -5)
    local log4j_vuln=()
    while IFS= read -r jar; do
        [[ -z "$jar" ]] && continue
        local jver; jver=$(echo "$jar" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+")
        if [[ -n "$jver" ]] && ver_lt "$jver" "2.17.1"; then
            log4j_vuln+=("$jar ($jver)")
        fi
    done <<< "$log4j_found"
    [[ ${#log4j_vuln[@]} -eq 0 ]] && status="양호" || status="불량"
    add_result "U-72" "최신CVE" "CVE-2021-44228 Log4Shell 잔존 여부" \
        "취약 log4j-core(< 2.17.1) 미존재 시 양호" "상" "$status" \
        "${log4j_vuln[*]:-취약 Log4j JAR 미발견}" \
        "log4j-core 2.17.1 이상으로 업그레이드, 필요시 LOG4J_FORMAT_MSG_NO_LOOKUPS=true"
    print_result "U-72" "CVE-2021-44228 Log4Shell 잔존" "$status"

    # U-73: ASLR 활성화 (Address Space Layout Randomization)
    local aslr; aslr=$(sysctl_val "kernel.randomize_va_space")
    [[ "$aslr" == "2" ]] && status="양호" || status="불량"
    add_result "U-73" "최신CVE" "ASLR 활성화 (메모리 보호)" \
        "kernel.randomize_va_space=2 이면 양호 (전체 ASLR)" "중" "$status" \
        "kernel.randomize_va_space: ${aslr:-미설정}" \
        "echo 'kernel.randomize_va_space=2' >> /etc/sysctl.conf && sysctl -p"
    print_result "U-73" "ASLR 활성화" "$status"

    # U-74: SELinux / AppArmor 활성화
    local mac_ok=0; local mac_detail=""
    if command -v getenforce &>/dev/null; then
        local selinux_mode; selinux_mode=$(getenforce 2>/dev/null)
        mac_detail="SELinux: $selinux_mode"
        [[ "$selinux_mode" == "Enforcing" ]] && mac_ok=1
    fi
    if command -v aa-status &>/dev/null; then
        local aa_mode; aa_mode=$(aa-status 2>/dev/null | grep "profiles are in enforce mode" | grep -oE "[0-9]+" | head -1)
        mac_detail="${mac_detail:+$mac_detail, }AppArmor enforce: ${aa_mode:-0}"
        [[ "${aa_mode:-0}" -gt 0 ]] && mac_ok=1
    fi
    [[ $mac_ok -eq 1 ]] && status="양호" || status="불량"
    add_result "U-74" "최신CVE" "SELinux / AppArmor 강제 적용" \
        "SELinux Enforcing 또는 AppArmor enforce 프로파일 존재 시 양호" "상" "$status" \
        "${mac_detail:-SELinux/AppArmor 미확인}" \
        "setenforce 1 && sed -i 's/SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config"
    print_result "U-74" "SELinux / AppArmor 강제 적용" "$status"

    # U-75: Spectre/Meltdown 마이티게이션 활성화
    local spec_ok=0
    if [ -d /sys/devices/system/cpu/vulnerabilities ]; then
        local vuln_count; vuln_count=$(grep -l "Vulnerable" /sys/devices/system/cpu/vulnerabilities/* 2>/dev/null | wc -l)
        local mit_detail; mit_detail=$(cat /sys/devices/system/cpu/vulnerabilities/* 2>/dev/null | head -5 | tr '\n' ' ')
        [[ "$vuln_count" -eq 0 ]] && spec_ok=1
    else
        local mit_detail="CPU 취약점 정보 미지원 커널"
    fi
    [[ $spec_ok -eq 1 ]] && status="양호" || status="확인필요"
    add_result "U-75" "최신CVE" "CPU 취약점 완화 적용 (Spectre/Meltdown)" \
        "CPU 취약점 완화 적용 시 양호" "중" "$status" \
        "${mit_detail:-확인불가}, 미완화 항목: ${vuln_count:-N/A}개" \
        "최신 커널 및 마이크로코드 패치 적용: dnf install microcode_ctl"
    print_result "U-75" "CPU 취약점 완화 (Spectre/Meltdown)" "$status"

    # U-76: GRUB 패스워드 보호
    local grub_pw=0
    grep -rE "password_pbkdf2|password --md5" /boot/grub/grub.cfg /boot/grub2/grub.cfg /etc/grub.d/ 2>/dev/null | grep -qv "^#" && grub_pw=1
    [[ $grub_pw -eq 1 ]] && status="양호" || status="불량"
    add_result "U-76" "최신CVE" "GRUB 부트로더 패스워드 보호" \
        "GRUB 패스워드 설정 시 양호 (물리 접근 공격 방지)" "중" "$status" \
        "GRUB 패스워드: $([ $grub_pw -eq 1 ] && echo 설정됨 || echo 미설정)" \
        "grub2-setpassword 또는 /etc/grub.d/40_custom에 password_pbkdf2 추가"
    print_result "U-76" "GRUB 패스워드 보호" "$status"

    # U-77: Docker 데몬 보안 설정
    if command -v docker &>/dev/null && svc_active docker; then
        local docker_tls; docker_tls=$(docker info 2>/dev/null | grep -i "TLS\|Tls")
        local docker_root; docker_root=$(docker info 2>/dev/null | grep -i "rootless\|userns" | head -1)
        local docker_sock_perm; docker_sock_perm=$(stat -c "%a" /var/run/docker.sock 2>/dev/null)
        # docker.sock가 666이면 취약
        [[ "${docker_sock_perm:-660}" -le 660 ]] && status="양호" || status="불량"
        add_result "U-77" "최신CVE" "Docker 소켓 권한 점검" \
            "/var/run/docker.sock 660 이하이면 양호" "상" "$status" \
            "docker.sock 권한: ${docker_sock_perm:-N/A}, Rootless: ${docker_root:-미확인}" \
            "chmod 660 /var/run/docker.sock; Docker Rootless 모드 또는 userns-remap 적용 권장"
    else
        status="N/A"
        add_result "U-77" "최신CVE" "Docker 소켓 권한 점검" \
            "/var/run/docker.sock 660 이하이면 양호" "상" "N/A" "Docker 미설치 또는 미실행" ""
    fi
    print_result "U-77" "Docker 소켓 권한 점검" "$status"

    # U-78: CVE-2024-47076/47175/47176/47177 CUPS 원격 코드 실행
    local cups_ver; cups_ver=$(lpstat -v 2>/dev/null | head -1 | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" || \
        cups-config --version 2>/dev/null)
    if svc_active cups; then
        local cups_vuln=0
        [[ -n "$cups_ver" ]] && ver_lt "$cups_ver" "2.4.11" && cups_vuln=1
        [[ $cups_vuln -eq 1 ]] && status="불량" || status="양호"
        add_result "U-78" "최신CVE" "CVE-2024-47076 CUPS 원격 코드 실행" \
            "CUPS 2.4.11 이상 또는 서비스 중지 시 양호" "상" "$status" \
            "현재 CUPS 버전: ${cups_ver:-확인불가}, 취약범위: < 2.4.11" \
            "dnf update cups / apt upgrade cups 또는 systemctl disable --now cups"
    else
        status="양호"
        add_result "U-78" "최신CVE" "CVE-2024-47076 CUPS 원격 코드 실행" \
            "CUPS 서비스 중지 시 양호" "상" "양호" "CUPS 서비스 미실행" ""
    fi
    print_result "U-78" "CVE-2024-47076 CUPS RCE" "$status"

    # U-79: CVE-2024-0727 / CVE-2025-0167 OpenSSL/curl 최신 취약점 추적
    # curl: CVE-2025-0167 (NetRC 자격증명 노출) - curl 8.11.1 미만
    local curl_ver2; curl_ver2=$(curl --version 2>/dev/null | head -1 | grep -oE "[0-9]+\.[0-9]+\.[0-9]+")
    local curl2_vuln=0
    [[ -n "$curl_ver2" ]] && ver_lt "$curl_ver2" "8.11.1" && curl2_vuln=1
    [[ $curl2_vuln -eq 1 ]] && status="불량" || status="양호"
    add_result "U-79" "최신CVE" "CVE-2025-0167 curl NetRC 자격증명 노출" \
        "curl 8.11.1 이상이면 양호" "중" "$status" \
        "현재 curl 버전: ${curl_ver2:-확인불가}, 취약범위: < 8.11.1" \
        "dnf update curl / apt upgrade curl"
    print_result "U-79" "CVE-2025-0167 curl 취약점" "$status"

    # U-80: CVE-2025-21756 Linux 커널 vsock UAF (LPE) - 커널 6.14 미만
    local knum2; knum2=$(uname -r | grep -oE "^[0-9]+\.[0-9]+")
    ver_lt "$knum2" "6.14" && status="확인필요" || status="양호"
    add_result "U-80" "최신CVE" "CVE-2025-21756 커널 vsock UAF (LPE)" \
        "커널 6.14 이상 또는 배포판 패치 적용 시 양호" "상" "$status" \
        "현재 커널: $(uname -r), 취약범위: < 6.14" \
        "배포판 최신 보안 패치 적용: dnf update kernel / apt upgrade linux-image"
    print_result "U-80" "CVE-2025-21756 커널 vsock UAF" "$status"

    # U-81: CVE-2025-32463 sudo --chroot LPE (sudo < 1.9.17)
    local sudo_ver2; sudo_ver2=$(sudo --version 2>/dev/null | head -1 | grep -oE "[0-9]+\.[0-9]+\.?[0-9]*p?[0-9]*")
    local sudo2_vuln=0
    [[ -n "$sudo_ver2" ]] && ver_lt "$sudo_ver2" "1.9.17" && sudo2_vuln=1
    [[ $sudo2_vuln -eq 1 ]] && status="불량" || status="양호"
    add_result "U-81" "최신CVE" "CVE-2025-32463 sudo --chroot LPE" \
        "sudo 1.9.17 이상이면 양호 (2025-04 공개)" "상" "$status" \
        "현재 sudo 버전: ${sudo_ver2:-확인불가}, 취약범위: < 1.9.17" \
        "dnf update sudo / apt upgrade sudo (즉시 패치 권고)"
    print_result "U-81" "CVE-2025-32463 sudo --chroot LPE" "$status"

    # U-82: CVE-2025-29927 Next.js 미들웨어 인증 우회 (웹앱 서버 해당시)
    local nextjs_found; nextjs_found=$(find /opt /srv /app /home /var/www -name "package.json" 2>/dev/null | \
        xargs grep -l '"next"' 2>/dev/null | head -3)
    if [[ -n "$nextjs_found" ]]; then
        local nextjs_vuln_list=()
        while IFS= read -r pkg; do
            local nver; nver=$(grep -oE '"next":\s*"[^"]*"' "$pkg" 2>/dev/null | grep -oE "[0-9]+\.[0-9]+\.[0-9]+")
            [[ -n "$nver" ]] && ver_lt "$nver" "15.2.3" && nextjs_vuln_list+=("$pkg: $nver")
        done <<< "$nextjs_found"
        [[ ${#nextjs_vuln_list[@]} -eq 0 ]] && status="양호" || status="불량"
        add_result "U-82" "최신CVE" "CVE-2025-29927 Next.js 인증 우회" \
            "Next.js 15.2.3/14.2.25/13.5.9 이상이면 양호" "상" "$status" \
            "${nextjs_vuln_list[*]:-취약 Next.js 미발견}" \
            "npm install next@latest 또는 npm audit fix"
    else
        add_result "U-82" "최신CVE" "CVE-2025-29927 Next.js 인증 우회" \
            "Next.js 미설치 또는 최신 버전이면 양호" "상" "N/A" "Next.js 미발견" ""
    fi
    print_result "U-82" "CVE-2025-29927 Next.js 인증 우회" "$status"
}

# ══════════════════════════════════════════════════════════════════════════════
#  HTML 보고서 생성
# ══════════════════════════════════════════════════════════════════════════════
generate_html() {
    local outpath="$1"
    local hostname="$2" ip="$3" os="$4" datetime="$5" total="$6"
    local pass="$7" fail="$8" na="$9" manual="${10}"
    local score; score=$(awk "BEGIN{printf \"%.1f\", $pass/$total*100}")

    {
cat <<'HTMLEOF'
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Linux 보안 취약점 진단 결과</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Malgun Gothic','Apple SD Gothic Neo',sans-serif;background:#0d1117;color:#c9d1d9;font-size:13px}
.wrap{max-width:1280px;margin:0 auto;padding:24px}
.header{background:linear-gradient(135deg,#0f3460 0%,#16213e 50%,#1a1a2e 100%);border-radius:12px;padding:32px;margin-bottom:20px;border:1px solid #30363d}
.header h1{font-size:22px;color:#58a6ff;margin-bottom:8px}
.header .sub{color:#8b949e;font-size:12px;margin-bottom:16px}
.info-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:16px}
.info-card{background:rgba(255,255,255,0.05);border-radius:8px;padding:12px;border:1px solid #21262d}
.info-card .label{color:#8b949e;font-size:11px;margin-bottom:4px}
.info-card .value{color:#e6edf3;font-size:13px;font-weight:bold}
.score-row{display:flex;gap:16px;margin-bottom:20px;flex-wrap:wrap}
.score-box{flex:1;min-width:140px;background:#161b22;border-radius:10px;padding:20px;text-align:center;border:1px solid #30363d}
.score-box .num{font-size:36px;font-weight:bold;line-height:1}
.score-box .lbl{font-size:11px;color:#8b949e;margin-top:6px}
.score-box.total .num{color:#58a6ff}
.score-box.pass .num{color:#3fb950}
.score-box.fail .num{color:#f85149}
.score-box.na .num{color:#d29922}
.score-box.manual .num{color:#8b949e}
.score-box.score .num{font-size:42px}
.progress-wrap{background:#161b22;border-radius:10px;padding:20px;margin-bottom:20px;border:1px solid #30363d}
.progress-bar{background:#21262d;border-radius:6px;height:20px;overflow:hidden;margin-top:10px}
.progress-fill{height:100%;border-radius:6px;transition:width 0.5s ease;display:flex;align-items:center;padding-left:8px;font-size:11px;color:#fff}
.filters{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center}
.filter-btn{padding:6px 14px;border-radius:20px;border:1px solid #30363d;background:#161b22;color:#8b949e;cursor:pointer;font-size:12px;transition:all .2s}
.filter-btn:hover,.filter-btn.active{border-color:#58a6ff;color:#58a6ff;background:rgba(88,166,255,0.1)}
.search-box{margin-left:auto;padding:6px 12px;border-radius:20px;border:1px solid #30363d;background:#161b22;color:#c9d1d9;width:200px;font-size:12px;outline:none}
.search-box:focus{border-color:#58a6ff}
table{width:100%;border-collapse:collapse;background:#161b22;border-radius:10px;overflow:hidden;border:1px solid #30363d}
th{background:#0f3460;color:#e6edf3;padding:10px 12px;text-align:left;font-size:12px;white-space:nowrap}
td{padding:9px 12px;border-bottom:1px solid #21262d;vertical-align:top;font-size:12px;line-height:1.5}
tr:hover td{background:rgba(88,166,255,0.04)}
.status{padding:3px 10px;border-radius:12px;font-size:11px;font-weight:bold;white-space:nowrap;display:inline-block}
.status.pass{background:#1a4731;color:#3fb950;border:1px solid #2ea043}
.status.fail{background:#4a1a1a;color:#f85149;border:1px solid #da3633}
.status.na{background:#3d3000;color:#d29922;border:1px solid #9e6a03}
.status.manual{background:#2d2d2d;color:#8b949e;border:1px solid #484f58}
.risk-high{color:#f85149;font-weight:bold}
.risk-mid{color:#d29922}
.risk-low{color:#3fb950}
.detail{color:#8b949e;font-size:11px;white-space:pre-wrap;word-break:break-all}
.action{color:#58a6ff;font-size:11px;white-space:pre-wrap;word-break:break-all}
.footer{text-align:center;padding:20px;color:#484f58;font-size:11px;margin-top:16px}
</style>
</head>
<body>
<div class="wrap">
HTMLEOF

cat <<HTMLEOF2
<div class="header">
  <h1>Linux/Unix 서버 보안 취약점 자동 진단 결과</h1>
  <div class="sub">기준: KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준 (Linux/Unix) | 최신 CVE 반영 (2025~2026)</div>
  <div class="info-grid">
    <div class="info-card"><div class="label">호스트명</div><div class="value">$hostname</div></div>
    <div class="info-card"><div class="label">IP 주소</div><div class="value">$ip</div></div>
    <div class="info-card"><div class="label">운영체제</div><div class="value">$os</div></div>
    <div class="info-card"><div class="label">진단 일시</div><div class="value">$datetime</div></div>
  </div>
</div>

<div class="score-row">
  <div class="score-box total"><div class="num">$total</div><div class="lbl">전체 항목</div></div>
  <div class="score-box pass"><div class="num">$pass</div><div class="lbl">양호</div></div>
  <div class="score-box fail"><div class="num">$fail</div><div class="lbl">불량</div></div>
  <div class="score-box na"><div class="num">$na</div><div class="lbl">N/A</div></div>
  <div class="score-box manual"><div class="num">$manual</div><div class="lbl">확인필요</div></div>
  <div class="score-box score"><div class="num" style="color:$(awk "BEGIN{print ($score>=80)?"\"#3fb950\"":($score>=60)?"\"#d29922\"":"\"#f85149\"")")">$score<span style="font-size:18px">점</span></div><div class="lbl">보안 점수</div></div>
</div>

<div class="progress-wrap">
  <div style="color:#8b949e;font-size:12px">양호율: $score%</div>
  <div class="progress-bar">
    <div class="progress-fill" style="width:${score}%;background:$(awk "BEGIN{print ($score>=80)?"\"#3fb950\"":($score>=60)?"\"#d29922\"":"\"#f85149\"")")">$score%</div>
  </div>
</div>

<div class="filters">
  <button class="filter-btn active" onclick="filterTable('all')">전체 ($total)</button>
  <button class="filter-btn" onclick="filterTable('pass')">양호 ($pass)</button>
  <button class="filter-btn" onclick="filterTable('fail')">불량 ($fail)</button>
  <button class="filter-btn" onclick="filterTable('na')">N/A ($na)</button>
  <button class="filter-btn" onclick="filterTable('manual')">확인필요 ($manual)</button>
  <input class="search-box" type="text" placeholder="검색..." oninput="searchTable(this.value)">
</div>

<table id="mainTable">
<thead>
<tr><th>ID</th><th>분류</th><th>점검 항목</th><th>판단 기준</th><th>위험도</th><th>결과</th><th>상세 내용</th><th>조치 권고사항</th></tr>
</thead>
<tbody>
HTMLEOF2

    for row in "${RESULTS[@]}"; do
        IFS='|' read -r id cat title std risk stat detail action <<< "$row"
        local risk_cls=""
        case "$risk" in 상) risk_cls="risk-high" ;; 중) risk_cls="risk-mid" ;; 하) risk_cls="risk-low" ;; esac
        local stat_cls=""
        case "$stat" in 양호) stat_cls="pass" ;; 불량) stat_cls="fail" ;; "N/A") stat_cls="na" ;; *) stat_cls="manual" ;; esac
        # HTML 이스케이프
        detail="${detail//&/&amp;}"; detail="${detail//</&lt;}"; detail="${detail//>/&gt;}"
        action="${action//&/&amp;}"; action="${action//</&lt;}"; action="${action//>/&gt;}"
        echo "<tr>"
        echo "  <td>$id</td><td>$cat</td><td>$title</td>"
        echo "  <td>$std</td>"
        echo "  <td class=\"$risk_cls\">$risk</td>"
        echo "  <td><span class=\"status $stat_cls\">$stat</span></td>"
        echo "  <td class=\"detail\">$detail</td>"
        echo "  <td class=\"action\">$action</td>"
        echo "</tr>"
    done

cat <<'HTMLEOF3'
</tbody>
</table>
<div class="footer">Generated by Linux CVE-Check v2.0 | KISA 기준 + 2025~2026 최신 CVE 반영</div>
</div>
<script>
function filterTable(f){
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('#mainTable tbody tr').forEach(r=>{
    const s=r.querySelector('.status');if(!s)return;
    const cls=s.className.replace('status ','').trim();
    r.style.display=(f==='all'||cls===f)?'':'none';
  });
}
function searchTable(q){
  const lq=q.toLowerCase();
  document.querySelectorAll('#mainTable tbody tr').forEach(r=>{
    r.style.display=r.textContent.toLowerCase().includes(lq)?'':'none';
  });
}
</script>
</body>
</html>
HTMLEOF3
    } > "$outpath"
}

# ══════════════════════════════════════════════════════════════════════════════
#  CSV 보고서 생성
# ══════════════════════════════════════════════════════════════════════════════
generate_csv() {
    local outpath="$1"
    echo "항목ID,분류,점검항목,판단기준,위험도,점검결과,상세내용,조치권고사항" > "$outpath"
    for row in "${RESULTS[@]}"; do
        IFS='|' read -r id cat title std risk stat detail action <<< "$row"
        # CSV 이스케이프 (쌍따옴표 포함 필드 감싸기)
        printf '"%s","%s","%s","%s","%s","%s","%s","%s"\n' \
            "$id" "$cat" "$title" "$std" "$risk" "$stat" \
            "${detail//\"/\"\"}" "${action//\"/\"\"}" >> "$outpath"
    done
}

# ══════════════════════════════════════════════════════════════════════════════
#  메인 실행
# ══════════════════════════════════════════════════════════════════════════════
# root 권한 확인
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}  [!] root 권한으로 실행해야 정확한 점검이 가능합니다.${NC}"
    echo -e "${YELLOW}      sudo bash $0${NC}"
    exit 1
fi

# 배너
echo ""
echo -e "${BLUE}  ╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}  ║       Linux/Unix 서버 보안 취약점 자동 진단 프로그램        ║${NC}"
echo -e "${BLUE}  ║  KISA 주요정보통신기반시설 기술적 취약점 분석평가 기준      ║${NC}"
echo -e "${BLUE}  ║  v2.0  |  82항목  |  최신 CVE 반영 (2025~2026)             ║${NC}"
echo -e "${BLUE}  ╚══════════════════════════════════════════════════════════════╝${NC}"

# 서버 정보 수집
HOSTNAME=$(hostname -s 2>/dev/null || hostname)
IP=$(ip -4 addr show scope global 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1 || \
     hostname -I 2>/dev/null | awk '{print $1}')
OS=$(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || uname -s)
DATETIME=$(date '+%Y-%m-%d %H:%M:%S')
AUDITOR=$(logname 2>/dev/null || echo "$SUDO_USER")

echo -e "\n  ${CYAN}서버: $HOSTNAME | IP: ${IP:-확인불가} | OS: $OS${NC}"
echo -e "  ${GRAY}진단 시작: $DATETIME | 점검자: ${AUDITOR:-root}${NC}\n"

# 점검 실행
check_account
check_file
check_service
check_patch
check_log
check_network
check_cve

# 결과 요약
TOTAL=${#RESULTS[@]}
SCORE=$(awk "BEGIN{printf \"%.1f\", $CNT_PASS/$TOTAL*100}")
if awk "BEGIN{exit !($SCORE>=80)}"; then SCORE_COLOR=$GREEN
elif awk "BEGIN{exit !($SCORE>=60)}"; then SCORE_COLOR=$YELLOW
else SCORE_COLOR=$RED; fi

echo ""
echo -e "  ${GRAY}══════════════════════════════════════════════════════════════${NC}"
echo -e "  ${WHITE}점검 완료 요약${NC}"
echo -e "  ${GRAY}──────────────────────────────────────────────────────────────${NC}"
echo -e "  전체 항목 : ${WHITE}$TOTAL 개${NC}"
echo -e "  양  호    : ${GREEN}$CNT_PASS 개${NC}"
echo -e "  불  량    : ${RED}$CNT_FAIL 개${NC}"
echo -e "  N/A       : ${YELLOW}$CNT_NA 개${NC}"
echo -e "  확인필요  : ${GRAY}$CNT_MANUAL 개${NC}"
printf   "  보안 점수 : ${SCORE_COLOR}%s 점${NC}\n" "$SCORE"
echo -e "  ${GRAY}══════════════════════════════════════════════════════════════${NC}\n"

if [[ $CNT_FAIL -gt 0 ]]; then
    echo -e "  ${RED}불량 항목 ($CNT_FAIL 건):${NC}"
    for row in "${RESULTS[@]}"; do
        IFS='|' read -r id _ title _ risk stat _ _ <<< "$row"
        [[ "$stat" == "불량" ]] && echo -e "    ${RED}✗ [$id] $title (위험도: $risk)${NC}"
    done
    echo ""
fi

# 보고서 저장
mkdir -p "$OUTPUT_DIR"
TS=$(date '+%Y%m%d_%H%M%S')
BASE="LinuxCVE_Check_${HOSTNAME}_${TS}"
HTML_PATH="${OUTPUT_DIR}/${BASE}.html"
CSV_PATH="${OUTPUT_DIR}/${BASE}.csv"

echo -e "  ${CYAN}보고서 생성 중...${NC}"
generate_html "$HTML_PATH" "$HOSTNAME" "${IP:-확인불가}" "$OS" "$DATETIME" \
    "$TOTAL" "$CNT_PASS" "$CNT_FAIL" "$CNT_NA" "$CNT_MANUAL"
generate_csv  "$CSV_PATH"

echo -e "  ${GREEN}✔ HTML : $HTML_PATH${NC}"
echo -e "  ${GREEN}✔ CSV  : $CSV_PATH${NC}"
echo ""
