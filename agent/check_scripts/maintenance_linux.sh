#!/bin/bash
#=============================================================================
# Linux/Unix 서버 정기점검 자동화 스크립트
# 기준 : 서버 정기점검 표준 항목 (시스템/CPU/메모리/디스크/서비스/로그/네트워크)
# 버전 : v1.0 | 점검 항목 : 45개
# 실행 : sudo bash maintenance_linux.sh
#=============================================================================

# ── 색상 정의 ──────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; GRAY='\033[0;37m'; NC='\033[0m'

# ── 결과 저장소 ────────────────────────────────────────────────────────────
declare -a RESULTS=()
CNT_NORMAL=0; CNT_WARN=0; CNT_CRIT=0; CNT_MANUAL=0; CNT_NA=0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"

# ── 헬퍼 함수 ──────────────────────────────────────────────────────────────
add_result() {
    # $1=ID $2=분류 $3=제목 $4=판단기준 $5=결과 $6=상세 $7=조치
    local status="$5"
    local detail="${6//$'\n'/ | }"
    local action="${7:-}"
    RESULTS+=("$1|$2|$3|$4|${status}|${detail}|${action}")
    case "$status" in
        정상)    ((CNT_NORMAL++))  ;;
        주의)    ((CNT_WARN++))    ;;
        경고)    ((CNT_CRIT++))   ;;
        확인필요) ((CNT_MANUAL++)) ;;
        "N/A")   ((CNT_NA++))     ;;
    esac
}

print_result() {
    local id="$1" title="$2" status="$3"
    local padid padtitle
    padid=$(printf "%-7s" "$id")
    padtitle=$(printf "%-44.44s" "$title")
    printf "    %s %s " "$padid" "$padtitle"
    case "$status" in
        정상)    printf "${GREEN}[ 정상 ]${NC}\n" ;;
        주의)    printf "${YELLOW}[ 주의 ]${NC}\n" ;;
        경고)    printf "${RED}[ 경고 ]${NC}\n"   ;;
        확인필요) printf "${BLUE}[ 확인 ]${NC}\n" ;;
        "N/A")   printf "${GRAY}[ N/A  ]${NC}\n"  ;;
        *)       printf "${GRAY}[ 오류 ]${NC}\n"  ;;
    esac
}

print_section() {
    echo ""
    printf "  ${CYAN}▶ %s${NC}\n" "$1"
    printf "  %s\n" "──────────────────────────────────────────────────────────────"
}

# 서비스 활성 여부
svc_active() {
    if command -v systemctl &>/dev/null; then
        systemctl is-active --quiet "$1" 2>/dev/null && return 0
    fi
    service "$1" status &>/dev/null && return 0
    return 1
}

# 버전 비교: ver_lt A B → A < B 이면 true(0)
ver_lt() { [ "$(printf '%s\n' "$1" "$2" | sort -V | head -1)" = "$1" ] && [ "$1" != "$2" ]; }

# ══════════════════════════════════════════════════════════════════════════════
#  1. 시스템 기본 정보 (L-01 ~ L-05)
# ══════════════════════════════════════════════════════════════════════════════
check_sysinfo() {
    print_section "시스템 기본 정보"

    # L-01 OS 정보
    local os_name os_ver
    if [ -f /etc/os-release ]; then
        os_name=$(. /etc/os-release && echo "$PRETTY_NAME")
    else
        os_name=$(uname -s)
    fi
    os_ver=$(uname -r)
    add_result "L-01" "시스템정보" "운영체제 정보 확인" \
        "OS 배포판, 버전, 커널 확인" "확인필요" \
        "OS: $os_name | 커널: $os_ver" ""
    print_result "L-01" "운영체제 정보 확인" "확인필요"

    # L-02 호스트명 및 도메인
    local hostname fqdn
    hostname=$(hostname 2>/dev/null || echo "확인불가")
    fqdn=$(hostname -f 2>/dev/null || echo "확인불가")
    add_result "L-02" "시스템정보" "호스트명 및 FQDN 확인" \
        "호스트명, FQDN 기록" "확인필요" \
        "호스트명: $hostname | FQDN: $fqdn" ""
    print_result "L-02" "호스트명 및 FQDN 확인" "확인필요"

    # L-03 시리얼 번호 (DMI)
    local serial=""
    if command -v dmidecode &>/dev/null; then
        serial=$(dmidecode -s system-serial-number 2>/dev/null | head -1)
    fi
    [ -z "$serial" ] && serial="확인불가 (dmidecode 미설치 또는 권한 필요)"
    add_result "L-03" "시스템정보" "시스템 시리얼 번호 확인" \
        "하드웨어 S/N 기록" "확인필요" \
        "S/N: $serial" ""
    print_result "L-03" "시스템 시리얼 번호 확인" "확인필요"

    # L-04 CPU 정보
    local cpu_model cpu_cores cpu_threads
    cpu_model=$(grep -m1 "model name" /proc/cpuinfo 2>/dev/null | cut -d: -f2 | sed 's/^ *//')
    cpu_cores=$(grep "^cpu cores" /proc/cpuinfo 2>/dev/null | sort -u | awk '{print $4}')
    cpu_threads=$(grep -c "^processor" /proc/cpuinfo 2>/dev/null)
    add_result "L-04" "시스템정보" "CPU 정보 확인" \
        "CPU 모델, 코어 수, 스레드 수" "확인필요" \
        "CPU: ${cpu_model:-확인불가} | 코어: ${cpu_cores:-?} | 스레드: ${cpu_threads:-?}" ""
    print_result "L-04" "CPU 정보 확인" "확인필요"

    # L-05 시스템 업타임
    local uptime_str uptime_days status
    uptime_str=$(uptime -p 2>/dev/null || uptime | awk -F'up' '{print $2}' | awk -F',' '{print $1,$2}')
    uptime_days=$(awk '{print int($1/86400)}' /proc/uptime 2>/dev/null)
    if [ "${uptime_days:-0}" -gt 180 ]; then
        status="주의"
    else
        status="정상"
    fi
    add_result "L-05" "시스템정보" "시스템 업타임 확인" \
        "180일 초과 시 주의 - 정기 재부팅 일정 검토" "$status" \
        "업타임: $uptime_str (약 ${uptime_days:-?}일)" \
        "$([ "$status" = "주의" ] && echo "업타임 180일 초과 - 커널 업데이트 적용 후 재부팅 일정 수립")"
    print_result "L-05" "시스템 업타임 확인" "$status"
}

# ══════════════════════════════════════════════════════════════════════════════
#  2. CPU 성능 모니터링 (L-06 ~ L-09)
# ══════════════════════════════════════════════════════════════════════════════
check_cpu() {
    print_section "CPU 성능 모니터링"

    # L-06 로드 평균 (Load Average)
    local load1 load5 load15 cpu_count status
    read -r load1 load5 load15 _ < /proc/loadavg
    cpu_count=$(grep -c "^processor" /proc/cpuinfo 2>/dev/null)
    cpu_count=${cpu_count:-1}
    # 로드평균 / CPU코어 수 비율로 판단
    local load_ratio
    load_ratio=$(awk "BEGIN {printf \"%.1f\", $load1 / $cpu_count}")
    if awk "BEGIN {exit !($load_ratio >= 2.0)}"; then
        status="경고"
    elif awk "BEGIN {exit !($load_ratio >= 1.0)}"; then
        status="주의"
    else
        status="정상"
    fi
    add_result "L-06" "CPU" "시스템 로드 평균 (Load Average)" \
        "load/CPU코어 1.0 이상 주의, 2.0 이상 경고" "$status" \
        "Load Average: $load1 (1분) $load5 (5분) $load15 (15분) | CPU 코어: ${cpu_count}개 | 비율: ${load_ratio}" \
        "$([ "$status" != "정상" ] && echo "고부하 프로세스 확인: top -b -n1 | head -20")"
    print_result "L-06" "시스템 로드 평균" "$status"

    # L-07 CPU 사용률 (top 스냅샷)
    local cpu_idle cpu_use status
    cpu_idle=$(top -bn1 2>/dev/null | grep "^%Cpu\|^Cpu" | awk '{for(i=1;i<=NF;i++) if($i~/id,/) {gsub(",",""); print $(i-1)}}')
    if [ -z "$cpu_idle" ]; then
        cpu_idle=$(vmstat 1 2 2>/dev/null | tail -1 | awk '{print $15}')
    fi
    cpu_use=$(awk "BEGIN {printf \"%.1f\", 100 - ${cpu_idle:-100}}")
    if awk "BEGIN {exit !($cpu_use >= 90)}"; then
        status="경고"
    elif awk "BEGIN {exit !($cpu_use >= 80)}"; then
        status="주의"
    else
        status="정상"
    fi
    add_result "L-07" "CPU" "현재 CPU 사용률" \
        "80% 이상 주의, 90% 이상 경고" "$status" \
        "현재 CPU 사용률: ${cpu_use}% (유휴: ${cpu_idle:-?}%)" \
        "$([ "$status" != "정상" ] && echo "CPU 집중 프로세스 확인: top -b -n1 -c | head -20")"
    print_result "L-07" "현재 CPU 사용률" "$status"

    # L-08 CPU 점유율 상위 프로세스 (TOP 5)
    local top_procs
    top_procs=$(ps aux --sort=-%cpu 2>/dev/null | awk 'NR>1 && NR<=6 {printf "%s(%.1f%%) ", $11, $3}')
    add_result "L-08" "CPU" "CPU 점유율 상위 프로세스 (TOP 5)" \
        "CPU 사용량 상위 프로세스 현황 파악" "확인필요" \
        "${top_procs:-확인불가}" ""
    print_result "L-08" "CPU 상위 프로세스 (TOP 5)" "확인필요"

    # L-09 좀비 프로세스
    local zombie_count status
    zombie_count=$(ps aux 2>/dev/null | awk '$8=="Z"' | wc -l)
    if [ "${zombie_count:-0}" -ge 5 ]; then
        status="경고"
    elif [ "${zombie_count:-0}" -ge 1 ]; then
        status="주의"
    else
        status="정상"
    fi
    add_result "L-09" "CPU" "좀비 프로세스 확인" \
        "좀비 프로세스 없으면 정상" "$status" \
        "좀비 프로세스: ${zombie_count}개" \
        "$([ "${zombie_count:-0}" -ge 1 ] && echo "좀비 프로세스 부모 PID 확인: ps aux | awk '\$8==\"Z\"' 후 kill 부모 프로세스")"
    print_result "L-09" "좀비 프로세스 확인" "$status"
}

# ══════════════════════════════════════════════════════════════════════════════
#  3. 메모리 모니터링 (L-10 ~ L-12)
# ══════════════════════════════════════════════════════════════════════════════
check_memory() {
    print_section "메모리 모니터링"

    # L-10 메모리 사용량
    local total_mb used_mb free_mb available_mb use_pct status
    if command -v free &>/dev/null; then
        read -r _ total_kb used_kb free_kb _ available_kb < <(free -k | awk '/^Mem:/ {print}')
        total_mb=$((total_kb / 1024))
        used_mb=$((used_kb / 1024))
        free_mb=$((free_kb / 1024))
        available_mb=$((available_kb / 1024))
        use_pct=$(awk "BEGIN {printf \"%.1f\", $used_mb / $total_mb * 100}")
        if awk "BEGIN {exit !($use_pct >= 95)}"; then
            status="경고"
        elif awk "BEGIN {exit !($use_pct >= 85)}"; then
            status="주의"
        else
            status="정상"
        fi
        add_result "L-10" "메모리" "메모리 사용량" \
            "사용률 85% 이상 주의, 95% 이상 경고" "$status" \
            "총: ${total_mb}MB | 사용: ${used_mb}MB | 가용: ${available_mb}MB | 사용률: ${use_pct}%" \
            "$([ "$status" != "정상" ] && echo "메모리 집중 프로세스 확인: ps aux --sort=-%mem | head -10")"
    else
        status="N/A"
        add_result "L-10" "메모리" "메모리 사용량" \
            "사용률 85% 이상 주의, 95% 이상 경고" "N/A" \
            "free 명령어 없음" ""
    fi
    print_result "L-10" "메모리 사용량" "$status"

    # L-11 메모리 점유율 상위 프로세스 (TOP 5)
    local top_mem
    top_mem=$(ps aux --sort=-%mem 2>/dev/null | awk 'NR>1 && NR<=6 {printf "%s(%.1f%%) ", $11, $4}')
    add_result "L-11" "메모리" "메모리 점유율 상위 프로세스 (TOP 5)" \
        "메모리 사용량 상위 프로세스 현황 파악" "확인필요" \
        "${top_mem:-확인불가}" ""
    print_result "L-11" "메모리 상위 프로세스 (TOP 5)" "확인필요"

    # L-12 Swap 사용량
    local swap_total_kb swap_used_kb swap_pct status
    read -r _ swap_total_kb swap_used_kb _ < <(free -k 2>/dev/null | awk '/^Swap:/ {print}')
    if [ "${swap_total_kb:-0}" -gt 0 ]; then
        swap_pct=$(awk "BEGIN {printf \"%.1f\", ${swap_used_kb:-0} / ${swap_total_kb} * 100}")
        if awk "BEGIN {exit !($swap_pct >= 80)}"; then
            status="경고"
        elif awk "BEGIN {exit !($swap_pct >= 50)}"; then
            status="주의"
        else
            status="정상"
        fi
        add_result "L-12" "메모리" "Swap 사용량" \
            "50% 이상 주의, 80% 이상 경고 (물리 메모리 부족 신호)" "$status" \
            "총: $(( swap_total_kb / 1024 ))MB | 사용: $(( ${swap_used_kb:-0} / 1024 ))MB | 사용률: ${swap_pct}%" \
            "$([ "$status" != "정상" ] && echo "Swap 과다 사용 - 메모리 증설 또는 프로세스 최적화 검토")"
    else
        add_result "L-12" "메모리" "Swap 사용량" \
            "50% 이상 주의, 80% 이상 경고" "N/A" "Swap 없음 또는 미설정" ""
        status="N/A"
    fi
    print_result "L-12" "Swap 사용량" "$status"
}

# ══════════════════════════════════════════════════════════════════════════════
#  4. 디스크 모니터링 (L-13 ~ L-17)
# ══════════════════════════════════════════════════════════════════════════════
check_disk() {
    print_section "디스크 모니터링"

    # L-13 파티션별 디스크 사용량
    local worst_status="정상"
    local disk_details=""
    while IFS= read -r line; do
        local use_pct mount fs
        use_pct=$(echo "$line" | awk '{print $5}' | tr -d '%')
        mount=$(echo "$line" | awk '{print $6}')
        fs=$(echo "$line" | awk '{print $1}')
        [ -z "$use_pct" ] && continue
        if [ "$use_pct" -ge 90 ] 2>/dev/null; then
            worst_status="경고"
            disk_details="${disk_details}${mount}: ${use_pct}% [경고] | "
        elif [ "$use_pct" -ge 80 ] 2>/dev/null; then
            [ "$worst_status" = "정상" ] && worst_status="주의"
            disk_details="${disk_details}${mount}: ${use_pct}% [주의] | "
        else
            disk_details="${disk_details}${mount}: ${use_pct}% [정상] | "
        fi
    done < <(df -hP 2>/dev/null | grep -v "^Filesystem\|tmpfs\|devtmpfs\|udev" | head -20)
    disk_details="${disk_details%| }"
    add_result "L-13" "디스크" "파티션별 디스크 사용량" \
        "사용률 80% 이상 주의, 90% 이상 경고" "$worst_status" \
        "${disk_details:-df 명령 실행 실패}" \
        "$([ "$worst_status" != "정상" ] && echo "디스크 확장 또는 불필요한 파일 정리: du -sh /* 2>/dev/null | sort -rh | head -20")"
    print_result "L-13" "파티션별 디스크 사용량" "$worst_status"

    # L-14 inode 사용량
    local inode_worst="정상"
    local inode_details=""
    while IFS= read -r line; do
        local iuse mount
        iuse=$(echo "$line" | awk '{print $5}' | tr -d '%')
        mount=$(echo "$line" | awk '{print $6}')
        [ -z "$iuse" ] && continue
        if [ "$iuse" -ge 90 ] 2>/dev/null; then
            inode_worst="경고"
            inode_details="${inode_details}${mount}: inode ${iuse}% [경고] | "
        elif [ "$iuse" -ge 80 ] 2>/dev/null; then
            [ "$inode_worst" = "정상" ] && inode_worst="주의"
            inode_details="${inode_details}${mount}: inode ${iuse}% [주의] | "
        fi
    done < <(df -iP 2>/dev/null | grep -v "^Filesystem\|tmpfs\|devtmpfs\|udev" | head -20)
    [ -z "$inode_details" ] && inode_details="모든 파티션 inode 정상"
    inode_details="${inode_details%| }"
    add_result "L-14" "디스크" "파티션별 inode 사용량" \
        "inode 80% 이상 주의, 90% 이상 경고" "$inode_worst" \
        "$inode_details" \
        "$([ "$inode_worst" != "정상" ] && echo "소용량 파일 대량 존재 가능 - find / -xdev -type f | wc -l")"
    print_result "L-14" "파티션별 inode 사용량" "$inode_worst"

    # L-15 대용량 파일 탐지 (1GB 이상)
    local large_files
    large_files=$(find / -xdev -size +1G -type f 2>/dev/null | head -10)
    local large_count; large_count=$(echo "$large_files" | grep -c "^/" 2>/dev/null || echo 0)
    local status
    [ "${large_count:-0}" -ge 5 ] && status="주의" || status="정상"
    add_result "L-15" "디스크" "대용량 파일 탐지 (1GB 이상)" \
        "1GB 이상 파일 5개 이상 시 주의" "$status" \
        "${large_count}개 탐지: $(echo "$large_files" | head -3 | tr '\n' ' ')" \
        "$([ "${large_count:-0}" -ge 1 ] && echo "du -sh <파일경로> 로 확인 후 불필요한 파일 정리")"
    print_result "L-15" "대용량 파일 탐지 (1GB+)" "$status"

    # L-16 오래된 로그 파일 (90일 이상)
    local old_logs_90 old_count_90
    old_logs_90=$(find /var/log -type f -mtime +90 2>/dev/null | head -10)
    old_count_90=$(echo "$old_logs_90" | grep -c "/" 2>/dev/null || echo 0)
    local status
    [ "${old_count_90:-0}" -ge 10 ] && status="주의" || status="정상"
    add_result "L-16" "디스크" "오래된 로그 파일 (90일 이상)" \
        "90일 이상 로그 파일 10개 이상 시 주의 - 정리 필요" "$status" \
        "${old_count_90}개 존재 (예: $(echo "$old_logs_90" | head -2 | tr '\n' ', '))" \
        "$([ "${old_count_90:-0}" -ge 1 ] && echo "find /var/log -type f -mtime +90 -delete  # 또는 logrotate 설정 확인")"
    print_result "L-16" "오래된 로그 파일 (90일+)" "$status"

    # L-17 /tmp 디렉터리 크기
    local tmp_mb status
    tmp_mb=$(du -sm /tmp 2>/dev/null | awk '{print $1}')
    if [ "${tmp_mb:-0}" -ge 5000 ]; then
        status="주의"
    else
        status="정상"
    fi
    add_result "L-17" "디스크" "/tmp 디렉터리 크기" \
        "5GB 이상 시 주의 - 임시 파일 정리 필요" "$status" \
        "/tmp 크기: ${tmp_mb:-?}MB" \
        "$([ "$status" = "주의" ] && echo "find /tmp -type f -mtime +7 -delete  # 7일 이상 임시 파일 삭제")"
    print_result "L-17" "/tmp 디렉터리 크기" "$status"
}

# ══════════════════════════════════════════════════════════════════════════════
#  5. 프로세스 및 접속 현황 (L-18 ~ L-22)
# ══════════════════════════════════════════════════════════════════════════════
check_process() {
    print_section "프로세스 및 접속 현황"

    # L-18 실행 중인 프로세스 현황 (총 수)
    local proc_count status
    proc_count=$(ps aux 2>/dev/null | tail -n +2 | wc -l)
    [ "${proc_count:-0}" -ge 500 ] && status="주의" || status="정상"
    add_result "L-18" "프로세스" "실행 중인 프로세스 수" \
        "500개 이상 시 주의" "$status" \
        "현재 프로세스 수: ${proc_count}개" \
        "$([ "$status" = "주의" ] && echo "ps aux --sort=-%cpu | head -20 으로 이상 프로세스 확인")"
    print_result "L-18" "실행 중인 프로세스 수" "$status"

    # L-19 현재 로그온 사용자 세션
    local session_info session_count status
    session_info=$(w -h 2>/dev/null || who 2>/dev/null)
    session_count=$(echo "$session_info" | grep -v "^$" | wc -l)
    [ "${session_count:-0}" -ge 10 ] && status="주의" || status="정상"
    local session_detail
    session_detail=$(echo "$session_info" | awk '{print $1"("$2")"}' | head -5 | tr '\n' ' ')
    add_result "L-19" "프로세스" "현재 로그온 사용자 세션" \
        "10개 이상 동시 세션 시 주의" "$status" \
        "활성 세션: ${session_count}개 | ${session_detail}" \
        "$([ "$status" = "주의" ] && echo "w 명령으로 세션 확인 후 불필요한 세션 강제 종료: pkill -KILL -u <user>")"
    print_result "L-19" "현재 로그온 세션" "$status"

    # L-20 최근 접속 기록 (last - 최근 20건)
    local last_records
    last_records=$(last -n 20 2>/dev/null | head -20 | grep -v "^$\|^wtmp" | awk '{print $1"@"$3"("$4,$5,$6")"}'| head -5 | tr '\n' ' ')
    add_result "L-20" "프로세스" "최근 서버 접속 기록 (last)" \
        "접속 기록 확인 및 이상 접속 여부 파악" "확인필요" \
        "${last_records:-접속 기록 없음}" \
        "last -n 50 으로 전체 접속 이력 확인"
    print_result "L-20" "최근 서버 접속 기록" "확인필요"

    # L-21 실패한 로그인 시도 (최근 24시간)
    local fail_count status
    fail_count=0
    if [ -f /var/log/auth.log ]; then
        fail_count=$(grep -c "Failed password\|authentication failure" /var/log/auth.log 2>/dev/null || echo 0)
    elif [ -f /var/log/secure ]; then
        fail_count=$(grep -c "Failed password\|authentication failure" /var/log/secure 2>/dev/null || echo 0)
    fi
    if [ "${fail_count:-0}" -ge 100 ]; then
        status="경고"
    elif [ "${fail_count:-0}" -ge 20 ]; then
        status="주의"
    else
        status="정상"
    fi
    add_result "L-21" "프로세스" "로그인 실패 시도 횟수" \
        "20회 이상 주의, 100회 이상 경고 (무차별 대입 공격 의심)" "$status" \
        "로그인 실패: ${fail_count}회" \
        "$([ "${fail_count:-0}" -ge 20 ] && echo "fail2ban 설치 검토 또는 /etc/hosts.deny 에 공격 IP 차단")"
    print_result "L-21" "로그인 실패 시도 횟수" "$status"

    # L-22 네트워크 연결 상태 (ESTABLISHED)
    local conn_count status
    conn_count=$(ss -tn 2>/dev/null | grep -c "ESTAB" || netstat -tn 2>/dev/null | grep -c "ESTABLISHED" || echo 0)
    [ "${conn_count:-0}" -ge 1000 ] && status="주의" || status="정상"
    add_result "L-22" "프로세스" "네트워크 연결 수 (ESTABLISHED)" \
        "1000개 이상 시 주의" "$status" \
        "현재 연결 수: ${conn_count}개" \
        "$([ "$status" = "주의" ] && echo "ss -tnp | awk '{print \$5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -10")"
    print_result "L-22" "네트워크 연결 수" "$status"
}

# ══════════════════════════════════════════════════════════════════════════════
#  6. 서비스 상태 (L-23 ~ L-27)
# ══════════════════════════════════════════════════════════════════════════════
check_services() {
    print_section "서비스 / 데몬 상태 점검"

    # L-23 핵심 서비스 상태
    local core_svcs=("sshd" "rsyslog" "crond" "cron" "ntpd" "chronyd" "NetworkManager" "systemd-timesyncd")
    local stopped_svcs=()
    local checked_svcs=()
    for svc in "${core_svcs[@]}"; do
        if command -v systemctl &>/dev/null; then
            if systemctl list-unit-files "${svc}.service" &>/dev/null 2>&1 | grep -q "${svc}"; then
                if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
                    if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
                        stopped_svcs+=("$svc")
                    fi
                else
                    checked_svcs+=("$svc:실행중")
                fi
            fi
        fi
    done
    local status
    [ ${#stopped_svcs[@]} -eq 0 ] && status="정상" || status="주의"
    add_result "L-23" "서비스" "핵심 데몬 서비스 상태" \
        "활성화된 핵심 서비스 모두 실행 중이면 정상" "$status" \
        "실행중: $(IFS=', '; echo "${checked_svcs[*]:-없음}") | 중지: $(IFS=', '; echo "${stopped_svcs[*]:-없음}")" \
        "$([ ${#stopped_svcs[@]} -gt 0 ] && echo "systemctl start ${stopped_svcs[*]} && systemctl enable ${stopped_svcs[*]}")"
    print_result "L-23" "핵심 데몬 서비스 상태" "$status"

    # L-24 NTP 시간 동기화 상태
    local ntp_status ntp_ok=0 ntp_detail status
    if command -v chronyc &>/dev/null; then
        ntp_detail=$(chronyc tracking 2>/dev/null | grep -E "System time|Reference ID")
        chronyc tracking 2>/dev/null | grep -q "^System time" && ntp_ok=1
    elif command -v ntpq &>/dev/null; then
        ntp_detail=$(ntpq -p 2>/dev/null | head -5)
        ntpq -p 2>/dev/null | grep -q "^\*" && ntp_ok=1
    elif command -v timedatectl &>/dev/null; then
        ntp_detail=$(timedatectl 2>/dev/null | grep -E "synchronized|NTP")
        timedatectl 2>/dev/null | grep -q "NTP synchronized: yes\|synchronized: yes" && ntp_ok=1
    fi
    status=$([ $ntp_ok -eq 1 ] && echo "정상" || echo "주의")
    add_result "L-24" "서비스" "NTP 시간 동기화 상태" \
        "NTP 서버와 동기화 시 정상" "$status" \
        "${ntp_detail:-NTP 상태 확인 불가}" \
        "$([ $ntp_ok -eq 0 ] && echo "systemctl restart chronyd 또는 ntpdate -u pool.ntp.org")"
    print_result "L-24" "NTP 시간 동기화 상태" "$status"

    # L-25 방화벽 상태
    local fw_ok=0 fw_detail status
    if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld 2>/dev/null; then
        fw_ok=1; fw_detail="firewalld 활성"
    elif command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        fw_ok=1; fw_detail="ufw 활성"
    elif iptables -L INPUT -n 2>/dev/null | grep -qv "^Chain\|^target\|^$"; then
        fw_ok=1; fw_detail="iptables 규칙 적용됨"
    elif command -v nft &>/dev/null && nft list ruleset 2>/dev/null | grep -q "hook input"; then
        fw_ok=1; fw_detail="nftables 활성"
    else
        fw_detail="방화벽 미설정"
    fi
    status=$([ $fw_ok -eq 1 ] && echo "정상" || echo "경고")
    add_result "L-25" "서비스" "호스트 방화벽 활성화 상태" \
        "iptables/firewalld/ufw/nftables 활성화 시 정상" "$status" \
        "$fw_detail" \
        "$([ $fw_ok -eq 0 ] && echo "systemctl enable --now firewalld 또는 ufw enable")"
    print_result "L-25" "호스트 방화벽 상태" "$status"

    # L-26 위험 포트 개방 여부
    local risky_ports status
    risky_ports=$(ss -tlnp 2>/dev/null | grep -E ":(23|21|512|513|514|111|2049|161|23)\s" || \
                  netstat -tlnp 2>/dev/null | grep -E ":(23|21|512|513|514|111|2049|161)\s")
    if [ -n "$risky_ports" ]; then
        status="경고"
    else
        status="정상"
    fi
    add_result "L-26" "서비스" "위험 포트 개방 여부 (Telnet/FTP/rsh 등)" \
        "telnet(23)/ftp(21)/rsh(512~514)/NFS(2049)/RPC(111) 미개방 시 정상" "$status" \
        "${risky_ports:-위험 포트 미개방}" \
        "$([ -n "$risky_ports" ] && echo "systemctl disable --now 해당서비스 또는 방화벽에서 포트 차단")"
    print_result "L-26" "위험 포트 개방 여부" "$status"

    # L-27 LISTENING 포트 현황
    local listen_ports
    listen_ports=$(ss -tlnp 2>/dev/null | awk 'NR>1 {print $4}' | sort -t: -k2 -n | head -20 | tr '\n' ' ' || \
                   netstat -tlnp 2>/dev/null | awk 'NR>2 {print $4}' | sort | head -20 | tr '\n' ' ')
    add_result "L-27" "서비스" "현재 LISTENING 포트 현황" \
        "오픈된 포트 목록 기록 및 불필요한 포트 차단 검토" "확인필요" \
        "${listen_ports:-ss/netstat 실행 실패}" \
        "불필요한 서비스 중지: systemctl stop <서비스명> && systemctl disable <서비스명>"
    print_result "L-27" "LISTENING 포트 현황" "확인필요"
}

# ══════════════════════════════════════════════════════════════════════════════
#  7. 로그 관리 (L-28 ~ L-32)
# ══════════════════════════════════════════════════════════════════════════════
check_logs() {
    print_section "로그 관리"

    # L-28 시스템 로그 최근 오류 (syslog/messages)
    local syslog_err err_count status
    local syslog_file
    for f in /var/log/syslog /var/log/messages; do
        [ -f "$f" ] && syslog_file="$f" && break
    done
    if [ -n "$syslog_file" ]; then
        err_count=$(grep -c -iE "error|fail|critical|panic" "$syslog_file" 2>/dev/null || echo 0)
        syslog_err=$(grep -iE "error|fail|critical" "$syslog_file" 2>/dev/null | tail -3 | awk '{print $1,$2,$3,$4,$5}' | tr '\n' ' ')
        if [ "${err_count:-0}" -ge 100 ]; then
            status="경고"
        elif [ "${err_count:-0}" -ge 20 ]; then
            status="주의"
        else
            status="정상"
        fi
        add_result "L-28" "로그관리" "시스템 로그 오류/실패 건수" \
            "20건 이상 주의, 100건 이상 경고" "$status" \
            "오류/실패 ${err_count}건 | 최근: $syslog_err" \
            "$([ "$status" != "정상" ] && echo "journalctl -p err -n 50 또는 grep -iE 'error|fail' $syslog_file | tail -50")"
    else
        add_result "L-28" "로그관리" "시스템 로그 오류/실패 건수" \
            "20건 이상 주의, 100건 이상 경고" "N/A" "syslog/messages 파일 없음" ""
        status="N/A"
    fi
    print_result "L-28" "시스템 로그 오류 건수" "$status"

    # L-29 커널 메시지 오류 (dmesg)
    local kernel_err err_count status
    err_count=$(dmesg 2>/dev/null | grep -c -iE "error|fail|warning|oom" || echo 0)
    kernel_err=$(dmesg 2>/dev/null | grep -iE "error|fail|oom" | tail -3 | cut -c1-80 | tr '\n' ' ')
    if [ "${err_count:-0}" -ge 50 ]; then
        status="경고"
    elif [ "${err_count:-0}" -ge 10 ]; then
        status="주의"
    else
        status="정상"
    fi
    add_result "L-29" "로그관리" "커널 오류 메시지 (dmesg)" \
        "10건 이상 주의, 50건 이상 경고" "$status" \
        "오류 ${err_count}건 | 최근: ${kernel_err:-없음}" \
        "$([ "$status" != "정상" ] && echo "dmesg -T | grep -iE 'error|fail|oom' | tail -20 으로 상세 확인")"
    print_result "L-29" "커널 오류 메시지 (dmesg)" "$status"

    # L-30 logrotate 설정 확인
    local rotate_val status
    rotate_val=$(grep -rE "^rotate\s+[0-9]+" /etc/logrotate.conf /etc/logrotate.d/ 2>/dev/null | awk '{print $2}' | sort -n | head -1)
    if [ -z "$rotate_val" ]; then
        status="확인필요"
    elif [ "$rotate_val" -ge 12 ] 2>/dev/null; then
        status="정상"
    else
        status="주의"
    fi
    add_result "L-30" "로그관리" "logrotate 보존 기간 설정" \
        "rotate 12 이상(12주/12개월) 시 정상" "$status" \
        "logrotate rotate 값: ${rotate_val:-미설정}" \
        "$([ "$status" != "정상" ] && echo "vi /etc/logrotate.conf → rotate 12 이상 설정 및 compress 옵션 추가")"
    print_result "L-30" "logrotate 보존 기간 설정" "$status"

    # L-31 /var/log 디렉터리 크기
    local log_size_mb status
    log_size_mb=$(du -sm /var/log 2>/dev/null | awk '{print $1}')
    if [ "${log_size_mb:-0}" -ge 10000 ]; then
        status="경고"
    elif [ "${log_size_mb:-0}" -ge 5000 ]; then
        status="주의"
    else
        status="정상"
    fi
    add_result "L-31" "로그관리" "/var/log 디렉터리 크기" \
        "5GB 이상 주의, 10GB 이상 경고" "$status" \
        "/var/log 크기: ${log_size_mb:-?}MB" \
        "$([ "$status" != "정상" ] && echo "du -sh /var/log/* | sort -rh | head -10 으로 대용량 로그 파악 후 정리")"
    print_result "L-31" "/var/log 디렉터리 크기" "$status"

    # L-32 Tomcat 로그 정리 (설치된 경우)
    local tomcat_log_dirs=("/opt/tomcat" "/usr/local/tomcat" "/srv/tomcat" "$CATALINA_HOME")
    local tomcat_found=0 catalina_old status
    for tdir in "${tomcat_log_dirs[@]}"; do
        if [ -d "${tdir}/logs" ]; then
            tomcat_found=1
            catalina_old=$(find "${tdir}/logs" -name "catalina*" -mtime +30 2>/dev/null | wc -l)
            break
        fi
    done
    if [ $tomcat_found -eq 0 ]; then
        add_result "L-32" "로그관리" "Tomcat 로그 정리 현황" \
            "30일 이상 catalina 로그 없으면 정상" "N/A" "Tomcat 미설치" ""
        status="N/A"
    else
        [ "${catalina_old:-0}" -ge 1 ] && status="주의" || status="정상"
        add_result "L-32" "로그관리" "Tomcat 로그 정리 현황" \
            "30일 이상 catalina 로그 없으면 정상" "$status" \
            "30일 이상 catalina 로그: ${catalina_old}개" \
            "$([ "${catalina_old:-0}" -ge 1 ] && echo "find \${CATALINA_HOME}/logs -name 'catalina*' -mtime +30 -delete")"
    fi
    print_result "L-32" "Tomcat 로그 정리 현황" "$status"
}

# ══════════════════════════════════════════════════════════════════════════════
#  8. 파일 시스템 보안 (L-33 ~ L-37)
# ══════════════════════════════════════════════════════════════════════════════
check_filesystem() {
    print_section "파일 시스템 보안"

    # L-33 최근 1일 이내 변경된 파일 탐지 (시스템 디렉터리)
    local changed_files changed_count status
    changed_files=$(find /etc /usr/bin /usr/sbin /bin /sbin -type f -ctime -1 2>/dev/null | head -10)
    changed_count=$(echo "$changed_files" | grep -c "/" 2>/dev/null || echo 0)
    if [ "${changed_count:-0}" -ge 10 ]; then
        status="주의"
    else
        status="정상"
    fi
    add_result "L-33" "파일시스템" "시스템 디렉터리 최근 변경 파일 탐지 (1일)" \
        "시스템 경로 최근 변경 파일 10개 이상 시 주의" "$status" \
        "${changed_count}개 변경 감지: $(echo "$changed_files" | head -3 | tr '\n' ' ')" \
        "$([ "${changed_count:-0}" -ge 1 ] && echo "변경 파일 내용 확인: rpm -Va 또는 debsums -c")"
    print_result "L-33" "시스템 디렉터리 변경 파일 탐지" "$status"

    # L-34 소유자 없는 파일/디렉터리
    local noown_files noown_count status
    noown_files=$(find / -xdev \( -nouser -o -nogroup \) -type f 2>/dev/null | head -10)
    noown_count=$(echo "$noown_files" | grep -c "/" 2>/dev/null || echo 0)
    [ "${noown_count:-0}" -ge 1 ] && status="주의" || status="정상"
    add_result "L-34" "파일시스템" "소유자 없는 파일/디렉터리" \
        "소유자 없는 파일 없으면 정상" "$status" \
        "${noown_count}개 탐지: $(echo "$noown_files" | head -3 | tr '\n' ' ')" \
        "$([ "${noown_count:-0}" -ge 1 ] && echo "chown root:root <파일경로> 로 소유자 변경")"
    print_result "L-34" "소유자 없는 파일/디렉터리" "$status"

    # L-35 SUID/SGID 파일 현황
    local suid_files suid_count status
    suid_files=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | head -20)
    suid_count=$(echo "$suid_files" | grep -c "/" 2>/dev/null || echo 0)
    [ "${suid_count:-0}" -ge 30 ] && status="주의" || status="정상"
    add_result "L-35" "파일시스템" "SUID/SGID 설정 파일 현황" \
        "SUID/SGID 파일 30개 이상 시 주의 - 불필요한 항목 제거" "$status" \
        "${suid_count}개 탐지: $(echo "$suid_files" | head -5 | tr '\n' ' ')" \
        "$([ "${suid_count:-0}" -ge 1 ] && echo "불필요한 SUID 제거: chmod -s <파일경로>")"
    print_result "L-35" "SUID/SGID 설정 파일 현황" "$status"

    # L-36 월드 쓰기 가능 파일 (World-Writable)
    local ww_files ww_count status
    ww_files=$(find / -xdev -type f -perm -0002 2>/dev/null | grep -v "^/proc\|^/sys\|^/dev" | head -10)
    ww_count=$(echo "$ww_files" | grep -c "/" 2>/dev/null || echo 0)
    [ "${ww_count:-0}" -ge 1 ] && status="주의" || status="정상"
    add_result "L-36" "파일시스템" "월드 쓰기 가능 파일 (World-Writable)" \
        "월드 쓰기 파일 없으면 정상" "$status" \
        "${ww_count}개 탐지: $(echo "$ww_files" | head -3 | tr '\n' ' ')" \
        "$([ "${ww_count:-0}" -ge 1 ] && echo "chmod o-w <파일경로> 로 권한 제거")"
    print_result "L-36" "월드 쓰기 가능 파일" "$status"

    # L-37 /etc/crontab 및 cron 작업 현황
    local cron_detail
    cron_detail=$(crontab -l 2>/dev/null | grep -v "^#" | head -5 | tr '\n' ' ')
    local sys_cron
    sys_cron=$(cat /etc/crontab 2>/dev/null | grep -v "^#\|^$" | head -5 | tr '\n' ' ')
    add_result "L-37" "파일시스템" "Cron 작업 현황" \
        "등록된 cron 작업 목록 확인 및 비정상 작업 제거" "확인필요" \
        "사용자 cron: ${cron_detail:-없음} | 시스템 cron: ${sys_cron:-없음}" \
        "crontab -l 및 /etc/cron.d/ 디렉터리 확인"
    print_result "L-37" "Cron 작업 현황" "확인필요"
}

# ══════════════════════════════════════════════════════════════════════════════
#  9. 계정 및 보안 기본 설정 (L-38 ~ L-42)
# ══════════════════════════════════════════════════════════════════════════════
check_security_basic() {
    print_section "계정 및 보안 기본 설정"

    # L-38 현재 활성 계정 목록
    local active_users user_count
    active_users=$(awk -F: '$3>=1000 && $7!~/nologin|false/ {print $1}' /etc/passwd 2>/dev/null)
    user_count=$(echo "$active_users" | grep -c "[a-z]" 2>/dev/null || echo 0)
    add_result "L-38" "계정관리" "시스템 계정 현황" \
        "활성 사용자 계정 목록 확인 및 불필요한 계정 제거" "확인필요" \
        "활성 계정 ${user_count}개: $(echo "$active_users" | tr '\n' ' ')" \
        "불필요한 계정 잠금: passwd -l <계정명> 또는 usermod -s /sbin/nologin <계정명>"
    print_result "L-38" "시스템 계정 현황" "확인필요"

    # L-39 패스워드 만료 임박 계정 (30일 이내)
    local expire_soon status
    expire_soon=$(awk -F: 'NR>0 {
        if ($5 != "" && $5 != "99999" && $5 != "-1") {
            cmd = "echo $(( ($(date +%s) / 86400) - " $3 " + " $5 "))"
            cmd | getline days_left
            close(cmd)
            if (days_left+0 <= 30 && days_left+0 >= 0) print $1 "(잔여" days_left "일)"
        }
    }' /etc/shadow 2>/dev/null | head -5 | tr '\n' ' ')
    [ -n "$expire_soon" ] && status="주의" || status="정상"
    add_result "L-39" "계정관리" "패스워드 만료 임박 계정 (30일 이내)" \
        "만료 임박 계정 없으면 정상" "$status" \
        "${expire_soon:-만료 임박 계정 없음}" \
        "$([ -n "$expire_soon" ] && echo "passwd <계정명> 으로 패스워드 갱신 또는 chage -M 90 <계정명>")"
    print_result "L-39" "패스워드 만료 임박 계정" "$status"

    # L-40 SSH 루트 로그인 허용 여부
    local sshd_conf="/etc/ssh/sshd_config"
    local permit_root status
    permit_root=$(grep -iE "^\s*PermitRootLogin" "$sshd_conf" 2>/dev/null | awk '{print $2}' | tail -1)
    if [[ "$permit_root" =~ ^(no|prohibit-password|forced-commands-only)$ ]]; then
        status="정상"
    else
        status="경고"
    fi
    add_result "L-40" "계정관리" "SSH 루트 직접 로그인 제한" \
        "PermitRootLogin no/prohibit-password 설정 시 정상" "$status" \
        "PermitRootLogin: ${permit_root:-미설정(기본값 적용)}" \
        "$([ "$status" != "정상" ] && echo "echo 'PermitRootLogin no' >> /etc/ssh/sshd_config && systemctl restart sshd")"
    print_result "L-40" "SSH 루트 직접 로그인 제한" "$status"

    # L-41 패스워드 정책 확인 (최소 길이)
    local minlen status
    minlen=$(grep -E "^\s*PASS_MIN_LEN" /etc/login.defs 2>/dev/null | awk '{print $2}')
    minlen=${minlen:-0}
    [ "$minlen" -ge 8 ] 2>/dev/null && status="정상" || status="주의"
    add_result "L-41" "계정관리" "패스워드 최소 길이 설정" \
        "PASS_MIN_LEN 8자 이상이면 정상" "$status" \
        "현재 PASS_MIN_LEN: $minlen" \
        "$([ "$status" != "정상" ] && echo "vi /etc/login.defs → PASS_MIN_LEN 8 이상 설정")"
    print_result "L-41" "패스워드 최소 길이 설정" "$status"

    # L-42 패스워드 최대 사용 기간
    local maxdays status
    maxdays=$(grep -E "^\s*PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
    maxdays=${maxdays:-99999}
    if [ "$maxdays" -le 90 ] 2>/dev/null && [ "$maxdays" -gt 0 ] 2>/dev/null; then
        status="정상"
    else
        status="주의"
    fi
    add_result "L-42" "계정관리" "패스워드 최대 사용 기간" \
        "PASS_MAX_DAYS 90일 이하이면 정상" "$status" \
        "현재 PASS_MAX_DAYS: $maxdays" \
        "$([ "$status" != "정상" ] && echo "vi /etc/login.defs → PASS_MAX_DAYS 90 이하 설정")"
    print_result "L-42" "패스워드 최대 사용 기간" "$status"
}

# ══════════════════════════════════════════════════════════════════════════════
#  10. 시스템 업데이트 및 종합 (L-43 ~ L-45)
# ══════════════════════════════════════════════════════════════════════════════
check_update_misc() {
    print_section "시스템 업데이트 및 종합"

    # L-43 시스템 패키지 업데이트 가능 여부
    local update_count status
    update_count=0
    if command -v dnf &>/dev/null; then
        update_count=$(dnf check-update --quiet 2>/dev/null | grep -c "^[a-zA-Z]" || echo 0)
    elif command -v yum &>/dev/null; then
        update_count=$(yum check-update --quiet 2>/dev/null | grep -c "^[a-zA-Z]" || echo 0)
    elif command -v apt-get &>/dev/null; then
        apt-get update -qq 2>/dev/null
        update_count=$(apt-get upgrade -s 2>/dev/null | grep -c "^Inst" || echo 0)
    fi
    if [ "${update_count:-0}" -ge 50 ]; then
        status="경고"
    elif [ "${update_count:-0}" -ge 10 ]; then
        status="주의"
    else
        status="정상"
    fi
    add_result "L-43" "업데이트" "시스템 패키지 업데이트 현황" \
        "업데이트 10개 이상 주의, 50개 이상 경고" "$status" \
        "업데이트 가능한 패키지: ${update_count}개" \
        "$([ "${update_count:-0}" -ge 1 ] && echo "dnf update -y 또는 apt-get upgrade -y 로 패키지 업데이트")"
    print_result "L-43" "시스템 패키지 업데이트 현황" "$status"

    # L-44 최근 시스템 재부팅 이력
    local last_reboot
    last_reboot=$(last reboot 2>/dev/null | head -5 | awk '{print $5,$6,$7,$8}' | head -5 | tr '\n' ' ')
    add_result "L-44" "종합" "최근 시스템 재부팅 이력 (최근 5회)" \
        "재부팅 이력 기록" "확인필요" \
        "${last_reboot:-재부팅 기록 없음}" ""
    print_result "L-44" "최근 시스템 재부팅 이력" "확인필요"

    # L-45 점검 종합 의견
    local total=$((CNT_NORMAL + CNT_WARN + CNT_CRIT + CNT_MANUAL + CNT_NA))
    local pct opinion
    pct=$(awk "BEGIN {printf \"%.1f\", $CNT_NORMAL / ($total > 0 ? $total : 1) * 100}")
    if awk "BEGIN {exit !($pct >= 90)}"; then
        opinion="전반적으로 양호한 상태입니다."
    elif awk "BEGIN {exit !($pct >= 70)}"; then
        opinion="일부 항목 개선이 필요합니다."
    else
        opinion="다수의 점검 항목에서 조치가 필요합니다."
    fi
    add_result "L-45" "종합" "점검 종합 의견" \
        "전체 점검 항목 정상 비율" "확인필요" \
        "정상 ${pct}% (${CNT_NORMAL}/${total}) - $opinion" ""
    print_result "L-45" "점검 종합 의견" "확인필요"
}

# ══════════════════════════════════════════════════════════════════════════════
#  HTML 보고서 생성
# ══════════════════════════════════════════════════════════════════════════════
generate_html() {
    local html_path="$1"
    local hostname ip os_name datetime

    hostname=$(hostname 2>/dev/null)
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    os_name=$(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || uname -s -r)
    datetime=$(date '+%Y-%m-%d %H:%M:%S')

    local total=$((CNT_NORMAL + CNT_WARN + CNT_CRIT + CNT_MANUAL + CNT_NA))
    local score=0
    [ $total -gt 0 ] && score=$(awk "BEGIN {printf \"%.1f\", $CNT_NORMAL / $total * 100}")

    local score_color
    if awk "BEGIN {exit !($score >= 80)}"; then
        score_color="#27ae60"
    elif awk "BEGIN {exit !($score >= 60)}"; then
        score_color="#f39c12"
    else
        score_color="#e74c3c"
    fi

    # 카테고리별 집계
    declare -A cat_total cat_normal cat_warn cat_crit
    for row in "${RESULTS[@]}"; do
        IFS='|' read -r id cat title std status detail action <<< "$row"
        cat_total["$cat"]=$(( ${cat_total["$cat"]:-0} + 1 ))
        case "$status" in
            정상) cat_normal["$cat"]=$(( ${cat_normal["$cat"]:-0} + 1 )) ;;
            주의) cat_warn["$cat"]=$(( ${cat_warn["$cat"]:-0} + 1 )) ;;
            경고) cat_crit["$cat"]=$(( ${cat_crit["$cat"]:-0} + 1 )) ;;
        esac
    done

    # HTML 시작
    cat > "$html_path" << 'HTMLSTART'
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Linux 서버 정기점검 결과</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Nanum Gothic','맑은 고딕',sans-serif;background:#f0f2f5;color:#2c3e50;font-size:13px}
.container{max-width:1400px;margin:0 auto;padding:20px}
header{background:linear-gradient(135deg,#1a1a2e 0%,#16213e 50%,#0f3460 100%);color:#fff;padding:30px 40px;border-radius:12px;margin-bottom:24px;box-shadow:0 4px 20px rgba(0,0,0,.3)}
header h1{font-size:24px;margin-bottom:8px}
header p{font-size:12px;opacity:.8}
.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:8px;margin-top:16px}
.info-item{background:rgba(255,255,255,.1);border-radius:6px;padding:8px 12px}
.info-item label{font-size:10px;opacity:.7;display:block}
.info-item span{font-size:13px;font-weight:600}
.summary{display:grid;grid-template-columns:200px 1fr;gap:20px;margin-bottom:24px}
.score-card{background:#fff;border-radius:12px;padding:24px;text-align:center;box-shadow:0 2px 12px rgba(0,0,0,.08);display:flex;flex-direction:column;align-items:center;justify-content:center}
.stat-cards{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}
.stat-card{background:#fff;border-radius:12px;padding:16px;text-align:center;box-shadow:0 2px 12px rgba(0,0,0,.08)}
.stat-card .num{font-size:32px;font-weight:700;line-height:1}
.stat-card .lbl{font-size:11px;color:#7f8c8d;margin-top:4px}
.stat-card.s-normal .num{color:#27ae60}
.stat-card.s-warn .num{color:#f39c12}
.stat-card.s-crit .num{color:#e74c3c}
.stat-card.s-manual .num{color:#3498db}
.stat-card.s-na .num{color:#95a5a6}
.card{background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08);margin-bottom:20px;overflow:hidden}
.card-header{background:linear-gradient(90deg,#1a1a2e,#0f3460);color:#fff;padding:14px 20px;font-size:14px;font-weight:700}
table{width:100%;border-collapse:collapse}
th{background:#f8f9fa;padding:10px 12px;text-align:left;font-size:11px;font-weight:700;color:#5a6475;border-bottom:2px solid #e9ecef;white-space:nowrap}
td{padding:9px 12px;border-bottom:1px solid #f0f0f0;vertical-align:top;line-height:1.5}
tr:hover td{background:#f8faff}
td.id{font-weight:700;color:#2980b9;white-space:nowrap;font-size:12px}
td.title{font-weight:600;min-width:180px}
td.std{color:#555;font-size:12px;min-width:160px}
td.detail{max-width:300px;font-size:12px;color:#444;word-break:break-all}
td.action{max-width:280px;font-size:12px;color:#c0392b;background:#fff9f9;word-break:break-all}
td.status{text-align:center;font-weight:700;white-space:nowrap;font-size:12px}
td.s-normal{color:#27ae60} td.s-warn{color:#f39c12;background:#fffbf0}
td.s-crit{color:#e74c3c;background:#fff5f5} td.s-na{color:#95a5a6} td.s-manual{color:#3498db}
.bar-wrap{display:flex;align-items:center;gap:8px}
.bar{height:14px;border-radius:7px;min-width:4px}
.bar-wrap span{font-size:12px;font-weight:700;white-space:nowrap}
.filter-bar{padding:12px 20px;background:#f8f9fa;border-bottom:1px solid #e9ecef;display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.filter-btn{padding:5px 14px;border:1px solid #ddd;border-radius:20px;background:#fff;cursor:pointer;font-size:12px}
.filter-btn:hover,.filter-btn.active{background:#0f3460;color:#fff;border-color:#0f3460}
.search-box{padding:5px 12px;border:1px solid #ddd;border-radius:20px;font-size:12px;width:220px}
.issue-list{padding:16px 20px}
.issue-item{border-left:4px solid;padding:10px 14px;margin-bottom:10px;border-radius:0 8px 8px 0}
.issue-item.crit{border-color:#e74c3c;background:#fff5f5}
.issue-item.warn{border-color:#f39c12;background:#fffbf0}
.issue-item h4{font-size:13px;margin-bottom:4px}
.issue-item.crit h4{color:#c0392b} .issue-item.warn h4{color:#d35400}
.issue-item p{font-size:12px;color:#555;line-height:1.6}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700}
.badge.crit{background:#fde8e8;color:#e74c3c;border:1px solid #e74c3c}
.badge.warn{background:#fef9e7;color:#f39c12;border:1px solid #f39c12}
@media print{body{background:#fff}.container{padding:0}header{border-radius:0}.card{box-shadow:none;border:1px solid #ddd}}
</style>
</head>
<body>
<div class="container">
HTMLSTART

    # 동적 섹션 추가
    cat >> "$html_path" << HTMLMID
<header>
  <h1>🐧 Linux/Unix 서버 정기점검 결과</h1>
  <p>서버 정기점검 표준 항목 기반 | 시스템/CPU/메모리/디스크/서비스/로그/파일시스템/계정</p>
  <div class="info-grid">
    <div class="info-item"><label>서버명</label><span>${hostname}</span></div>
    <div class="info-item"><label>IP 주소</label><span>${ip:-확인불가}</span></div>
    <div class="info-item"><label>운영체제</label><span>${os_name}</span></div>
    <div class="info-item"><label>점검 일시</label><span>${datetime}</span></div>
    <div class="info-item"><label>점검자</label><span>$(whoami)</span></div>
    <div class="info-item"><label>점검 버전</label><span>v1.0 (45항목)</span></div>
  </div>
</header>

<div class="summary">
  <div class="score-card">
    <div style="font-size:56px;font-weight:700;color:${score_color};line-height:1">${score}</div>
    <div style="font-size:12px;color:#7f8c8d;margin-top:4px">정상 비율 (%)</div>
  </div>
  <div>
    <div class="stat-cards">
      <div class="stat-card"><div class="num">${total}</div><div class="lbl">전체 항목</div></div>
      <div class="stat-card s-normal"><div class="num">${CNT_NORMAL}</div><div class="lbl">정상</div></div>
      <div class="stat-card s-warn"><div class="num">${CNT_WARN}</div><div class="lbl">주의</div></div>
      <div class="stat-card s-crit"><div class="num">${CNT_CRIT}</div><div class="lbl">경고</div></div>
      <div class="stat-card s-manual"><div class="num">${CNT_MANUAL}</div><div class="lbl">확인필요</div></div>
    </div>
  </div>
</div>

<div class="card">
  <div class="card-header">📊 카테고리별 점검 결과</div>
  <table>
    <thead><tr><th>분류</th><th>전체</th><th>정상</th><th>주의</th><th>경고</th><th style="min-width:200px">정상률</th></tr></thead>
    <tbody>
HTMLMID

    # 카테고리별 행 출력
    for cat in "${!cat_total[@]}"; do
        local t=${cat_total[$cat]:-0}
        local n=${cat_normal[$cat]:-0}
        local w=${cat_warn[$cat]:-0}
        local c=${cat_crit[$cat]:-0}
        local r=0
        [ $t -gt 0 ] && r=$(awk "BEGIN {printf \"%.0f\", $n / $t * 100}")
        local rcolor="#27ae60"
        [ "$r" -lt 80 ] && rcolor="#f39c12"
        [ "$r" -lt 50 ] && rcolor="#e74c3c"
        echo "      <tr><td>$cat</td><td>$t</td><td class='s-normal'>$n</td><td class='s-warn'>$w</td><td class='s-crit'>$c</td><td><div class='bar-wrap'><div class='bar' style='width:${r}%;background:$rcolor'></div><span>${r}%</span></div></td></tr>" >> "$html_path"
    done

    local issue_count=$((CNT_WARN + CNT_CRIT))
    cat >> "$html_path" << HTMLMID2
    </tbody>
  </table>
</div>

<div class="card">
  <div class="card-header">⚠️ 조치 필요 항목 (${issue_count}건)</div>
  <div class="issue-list">
HTMLMID2

    local any_issue=0
    for row in "${RESULTS[@]}"; do
        IFS='|' read -r id cat title std status detail action <<< "$row"
        if [ "$status" = "주의" ] || [ "$status" = "경고" ]; then
            any_issue=1
            local cls="warn"
            [ "$status" = "경고" ] && cls="crit"
            local escaped_action="${action//&/&amp;}"
            escaped_action="${escaped_action//</&lt;}"
            escaped_action="${escaped_action//>/&gt;}"
            echo "    <div class='issue-item $cls'><h4>[${id}] ${title} <span class='badge $cls'>${status}</span></h4><p>${escaped_action:-조치 권고사항 없음}</p></div>" >> "$html_path"
        fi
    done
    [ $any_issue -eq 0 ] && echo "    <p style='color:#27ae60;padding:10px'>조치가 필요한 항목이 없습니다.</p>" >> "$html_path"

    cat >> "$html_path" << HTMLMID3
  </div>
</div>

<div class="card">
  <div class="card-header">📋 상세 점검 결과</div>
  <div class="filter-bar">
    <button class="filter-btn active" onclick="filterTable('all')">전체 (${total})</button>
    <button class="filter-btn" onclick="filterTable('s-normal')">정상 (${CNT_NORMAL})</button>
    <button class="filter-btn" onclick="filterTable('s-warn')">주의 (${CNT_WARN})</button>
    <button class="filter-btn" onclick="filterTable('s-crit')">경고 (${CNT_CRIT})</button>
    <button class="filter-btn" onclick="filterTable('s-manual')">확인필요 (${CNT_MANUAL})</button>
    <input class="search-box" type="text" placeholder="검색..." oninput="searchTable(this.value)">
  </div>
  <table id="mainTable">
    <thead><tr><th>항목ID</th><th>분류</th><th>점검 항목</th><th>판단 기준</th><th>결과</th><th>상세 내용</th><th>조치 권고사항</th></tr></thead>
    <tbody>
HTMLMID3

    for row in "${RESULTS[@]}"; do
        IFS='|' read -r id cat title std status detail action <<< "$row"
        local sc
        case "$status" in
            정상) sc="s-normal" ;; 주의) sc="s-warn" ;; 경고) sc="s-crit" ;;
            "N/A") sc="s-na" ;; *) sc="s-manual" ;;
        esac
        local esc_det="${detail//&/&amp;}"; esc_det="${esc_det//</&lt;}"; esc_det="${esc_det//>/&gt;}"
        local esc_act="${action//&/&amp;}"; esc_act="${esc_act//</&lt;}"; esc_act="${esc_act//>/&gt;}"
        local esc_tit="${title//&/&amp;}"; esc_tit="${esc_tit//</&lt;}"; esc_tit="${esc_tit//>/&gt;}"
        local esc_std="${std//&/&amp;}"; esc_std="${esc_std//</&lt;}"; esc_std="${esc_std//>/&gt;}"
        echo "      <tr><td class='id'>$id</td><td>$cat</td><td class='title'>$esc_tit</td><td class='std'>$esc_std</td><td class='status $sc'>$status</td><td class='detail'>$esc_det</td><td class='action'>$esc_act</td></tr>" >> "$html_path"
    done

    cat >> "$html_path" << HTMLEND
    </tbody>
  </table>
</div>

<div style="text-align:center;padding:20px;color:#aaa;font-size:11px">
  Generated by Linux Server Maintenance v1.0 | ${datetime}
</div>
</div>
<script>
function filterTable(f){
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('#mainTable tbody tr').forEach(r=>{
    const s=r.querySelector('.status');
    if(!s)return;
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
HTMLEND
}

# ══════════════════════════════════════════════════════════════════════════════
#  CSV 보고서 생성
# ══════════════════════════════════════════════════════════════════════════════
generate_csv() {
    local csv_path="$1"
    echo "항목ID,분류,점검항목,판단기준,점검결과,상세내용,조치권고사항" > "$csv_path"
    for row in "${RESULTS[@]}"; do
        IFS='|' read -r id cat title std status detail action <<< "$row"
        # CSV 이스케이프
        detail="${detail//\"/\"\"}"
        action="${action//\"/\"\"}"
        echo "\"$id\",\"$cat\",\"$title\",\"$std\",\"$status\",\"$detail\",\"$action\"" >> "$csv_path"
    done
}

# ══════════════════════════════════════════════════════════════════════════════
#  메인 실행
# ══════════════════════════════════════════════════════════════════════════════
echo ""
printf "${CYAN}"
echo "  ╔══════════════════════════════════════════════════════════════╗"
echo "  ║       Linux/Unix 서버 정기점검 자동화 프로그램              ║"
echo "  ║  시스템/CPU/메모리/디스크/서비스/로그/파일시스템/계정 점검  ║"
echo "  ║  v1.0  |  45항목                                            ║"
echo "  ╚══════════════════════════════════════════════════════════════╝"
printf "${NC}"

HOSTNAME=$(hostname 2>/dev/null)
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
DATETIME=$(date '+%Y-%m-%d %H:%M:%S')
echo ""
printf "  서버: ${HOSTNAME} (${IP:-확인불가}) | 점검 시작: ${DATETIME}\n"

# 점검 실행
check_sysinfo
check_cpu
check_memory
check_disk
check_process
check_services
check_logs
check_filesystem
check_security_basic
check_update_misc

# 결과 요약
TOTAL=$((CNT_NORMAL + CNT_WARN + CNT_CRIT + CNT_MANUAL + CNT_NA))
echo ""
printf "  ${GRAY}═══════════════════════════════════════════════════${NC}\n"
printf "  점검 완료: 전체 ${TOTAL}항목\n"
printf "  ${GREEN}정상: ${CNT_NORMAL}${NC}  ${YELLOW}주의: ${CNT_WARN}${NC}  ${RED}경고: ${CNT_CRIT}${NC}  ${BLUE}확인필요: ${CNT_MANUAL}${NC}  ${GRAY}N/A: ${CNT_NA}${NC}\n"
printf "  ${GRAY}═══════════════════════════════════════════════════${NC}\n"

# ── 네트워크 공유 설정 ────────────────────────────────────────────
NAS_HOST="10.60.8.169"
NAS_SHARE="//10.60.8.169/Server_maintenance"
NAS_USER="maintenance"
NAS_PASS='veQ5vU3&'

# ── 파일명: [호스트명]_[IP]_[날짜] ──────────────────────────────
DATE_STR=$(date '+%Y%m%d')
SAFE_IP=$(echo "${IP:-noip}" | tr ':/' '-')
BASE_NAME="${HOSTNAME}_${SAFE_IP}_${DATE_STR}"

# ── 로컬 저장 ─────────────────────────────────────────────────────
mkdir -p "$OUTPUT_DIR"
HTML_PATH="${OUTPUT_DIR}/${BASE_NAME}.html"
CSV_PATH="${OUTPUT_DIR}/${BASE_NAME}.csv"

generate_html "$HTML_PATH"
generate_csv  "$CSV_PATH"

echo ""
printf "  ${CYAN}보고서 저장 완료:${NC}\n"
printf "    HTML: ${HTML_PATH}\n"
printf "    CSV : ${CSV_PATH}\n"

# ── 네트워크 공유 저장 ────────────────────────────────────────────
echo ""
printf "  ${CYAN}네트워크 공유 저장 중... (${NAS_SHARE})${NC}\n"
if command -v smbclient &>/dev/null; then
    smbclient "$NAS_SHARE" \
        -U "${NAS_USER}%${NAS_PASS}" \
        -c "put \"${HTML_PATH}\" \"${BASE_NAME}.html\"; put \"${CSV_PATH}\" \"${BASE_NAME}.csv\"" \
        2>/dev/null
    if [ $? -eq 0 ]; then
        printf "    ${GREEN}공유 저장 완료: ${NAS_SHARE}/${BASE_NAME}.*${NC}\n"
    else
        printf "    ${YELLOW}[경고] 공유 저장 실패 — smbclient 오류${NC}\n"
        printf "    로컬에 저장된 파일을 수동으로 복사하세요.\n"
    fi
elif command -v mount &>/dev/null && grep -q cifs /proc/filesystems 2>/dev/null; then
    MNT_TMP=$(mktemp -d)
    mount -t cifs "$NAS_SHARE" "$MNT_TMP" \
        -o "username=${NAS_USER},password=${NAS_PASS},uid=$(id -u),gid=$(id -g)" \
        2>/dev/null
    if [ $? -eq 0 ]; then
        cp "$HTML_PATH" "$MNT_TMP/${BASE_NAME}.html" && \
        cp "$CSV_PATH"  "$MNT_TMP/${BASE_NAME}.csv"
        umount "$MNT_TMP" 2>/dev/null
        rmdir  "$MNT_TMP" 2>/dev/null
        printf "    ${GREEN}공유 저장 완료 (cifs mount): ${NAS_SHARE}${NC}\n"
    else
        umount "$MNT_TMP" 2>/dev/null
        rmdir  "$MNT_TMP" 2>/dev/null
        printf "    ${YELLOW}[경고] CIFS 마운트 실패 — 로컬에만 저장됨${NC}\n"
    fi
else
    printf "    ${YELLOW}[경고] smbclient / cifs 미설치 — 로컬에만 저장됨${NC}\n"
    printf "    설치 방법:\n"
    printf "      RHEL/CentOS : yum install samba-client cifs-utils\n"
    printf "      Ubuntu/Debian: apt install smbclient cifs-utils\n"
fi
echo ""
