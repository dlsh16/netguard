# Agent 중복 실행 및 IP 변경 운영 가이드

버전: v1.2.67 / 작성일: 2026-11-25

## 화면 해석과 변경 내용

화면에는 `MBCoTalent / 10.60.8.130`(11월 24일)과 `MBCoTalent (10.60.8.187) / 10.60.8.187`(11월 21일)의 서로 다른 수집 기록이 있다. 이는 중복 장비 기록의 증거이지 동시 실행 프로세스 두 개의 증거는 아니다. 예전 IP 기록, 여러 NIC, 다른 설치 위치/서비스, 이름이 같은 별도 서버를 구분해야 한다. `부분 수집 / process: access restricted`는 일부 실행 파일 메타데이터 접근 제한이며 중복 여부와 별개다. 이를 없애려고 Agent를 무조건 root로 변경하지 않는다.

- Windows MachineGuid, Linux machine-id의 SHA-256 해시를 `agent_id`로 전송한다. 원본 OS 식별값은 전송하지 않는다. 이름/IP/설치 폴더가 바뀌어도 같은 OS는 같은 ID를 사용한다. 인증키를 대체하는 보안 인증 기능은 아니다.
- 중앙 서버는 ID를 우선 사용한다. 기존 ID의 IP가 변경되면 같은 devices.id를 갱신하여 메트릭·인벤토리를 보존한다. 기존 IP의 메모리 캐시도 제거한다.
- 최초 업그레이드에서는 현재 IP에 정확히 한 개의 서버 기록이 있고 ID가 비어 있을 때만 연결한다. 이름만 같은 다른 IP, 다른 ID의 IP, 여러 기록이 같은 IP인 경우 409로 중단한다. 자동 병합·삭제는 하지 않는다.
- Windows/Linux 모두 NetGuard 서버로 향하는 IPv4 경로를 사용한다. 시작 시 결정한 IP/ID를 소프트웨어 수집 작업에도 전달한다. NIC/IP 변경 후 Agent를 재시작한다.
- Windows PowerShell/Python은 같은 전역 mutex를, Linux는 같은 네트워크 네임스페이스의 abstract Unix socket을 사용한다. 설치 경로/IP/계정이 달라도 두 번째 메인 프로세스는 전송 없이 종료한다. 소프트웨어 수집용 자식 프로세스가 하나 더 보이는 것은 정상이다.
- Windows 서비스가 존재하면 재시작/백그라운드 도우미는 같은 이름의 NetGuardAgent 예약 작업을 비활성화하고 중지한다. 다른 이름의 작업이나 구버전 수동 프로세스는 자동 종료하지 않는다.

## 적용 순서와 파일

**중앙 서버 패치 → 기존 Agent 프로세스/기동 등록 점검 → Agent 갱신 → 정상 수집 확인 → 기존 중복 기록 검토** 순서다. DB/Agent 설정을 초기화하지 않는다. NVD 재수집, pip 설치, 인터넷 연결, 추가 인바운드 포트는 필요 없다. 기존 HTTP(S) 포트를 그대로 사용한다.

패키지는 v1.2.63 이후 소프트웨어 인벤토리가 적용된 환경 기준이다. 운영 커스텀이 있으면 변경 파일을 비교하고 반영한다. 각 명령 실패 시 다음 단계로 진행하지 않는다.

| 파일 | 대상 |
|---|---|
| NetGuard-v1.2.67-agent-identity.zip | 중앙 서버의 변경 backend 4개 및 문서 |
| NetGuard-Agent-v1.2.67.zip | Windows Agent 전체 코드/설치 도우미, 문서 |
| NetGuard-Agent-Linux-v1.2.67.zip | Linux Agent 및 설치/갱신 도우미, 문서 |

중앙 서버 변경 파일: `backend/agent_identity.py`(신규), `backend/api/agent_routes.py`, `backend/database.py`, `backend/software_inventory.py`. 새 파일 누락 시 시작하지 못한다. 시작 시 nullable `devices.agent_id`와 고유 부분 인덱스를 추가하므로 DB 계정에 ALTER/CREATE 권한이 필요하다. 기존 데이터/사용자는 삭제하지 않는다. 실패 시 권한/로그를 확인하고 DB를 다시 만들지 않는다.

## Rocky 중앙 서버

기존 백업이 있으면 다른 이름을 지정한다. 먼저 DB 백업 성공과 패키지 무결성을 확인한다. 백업은 관리자만 접근하도록 보호한다.

```bash
sudo -u postgres pg_dump -Fc -f /var/lib/pgsql/netguard-before-v1267.dump netguard
sudo chmod 600 /var/lib/pgsql/netguard-before-v1267.dump
sudo systemctl stop netguard
sudo tar -czf /root/netguard-backend-before-v1267.tar.gz -C /opt/netguard backend
sudo chmod 600 /root/netguard-backend-before-v1267.tar.gz
sudo /opt/netguard/venv/bin/python -m zipfile -e /tmp/NetGuard-v1.2.67-agent-identity.zip /opt/netguard
sudo -u netguard env PYTHONPATH=/opt/netguard/backend /opt/netguard/venv/bin/python -B -c 'import agent_identity, software_inventory, api.agent_routes, database; print("imports ok")'
sudo systemctl start netguard
sudo systemctl status netguard --no-pager -l
sudo journalctl -u netguard --since '10 minutes ago' --no-pager
```

`Application startup complete`와 정상 API 접근을 확인한 뒤 Agent를 갱신한다. 서비스 unit/자동 시작 설정은 변경하지 않는다. 새 파일 소유권/읽기 권한은 운영 배포 정책에 맞춘다.

## Windows 중앙 서버

기존 절차로 PostgreSQL 백업을 완료한 뒤 관리자 PowerShell에서 실행한다. 경로와 `NetGuard` 서비스명은 실제 환경에 맞춘다. 다른 방식으로 구동 중이면 그 관리 도구로 중지/시작한다.

```powershell
$ErrorActionPreference = 'Stop'
$root = 'E:\SNMP\SNMP_Codex'
Stop-Service NetGuard
$backup = 'E:\SNMP\backend-before-v1267-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.zip'
Compress-Archive -LiteralPath "$root\backend" -DestinationPath $backup
Expand-Archive -LiteralPath 'E:\SNMP\NetGuard-v1.2.67-agent-identity.zip' -DestinationPath $root -Force
$env:PYTHONPATH = "$root\backend"
& "$root\venv\Scripts\python.exe" -B -c 'import agent_identity, software_inventory, api.agent_routes, database; print("imports ok")'
if ($LASTEXITCODE -ne 0) { throw 'Import failed; restore backend backup before starting' }
Start-Service NetGuard
Get-Service NetGuard
```

## Linux Agent 갱신 및 점검

ZIP을 `/tmp/netguard-agent-v1267`에 별도 해제한다. [Linux 설치·운영 매뉴얼](agent_install_linux.md)의 Python 3.6+ / root / systemd 조건과 백업 절차를 적용한다.

```bash
sudo systemctl status netguard-agent --no-pager -l
pgrep -af '[n]etguard_agent.py'
ip -4 addr show
ip -4 route get 10.60.8.186
sudo bash /tmp/netguard-agent-v1267/scripts/install_agent_linux.sh --check
sudo bash /tmp/netguard-agent-v1267/scripts/install_agent_linux.sh --update
sudo systemctl is-active netguard-agent
sudo journalctl -u netguard-agent -n 60 --no-pager
sudo tail -n 40 /opt/netguard-agent/agent.log
```

`--update`는 코드만 교체하고 설정/unit/기존 자동 시작 상태를 보존한다. Python이 PATH에 없으면 기존 문서의 `NETGUARD_AGENT_PYTHON`으로 승인된 런타임을 지정한다. OS 내부 platform-python을 교체하거나 python3 심볼릭 링크를 임의 생성하지 않는다.

기존 구버전이 여러 개면 실행 경로와 서비스/cron 소유자를 확인한다. 표준 서비스 외 구버전은 그 기동 주체를 중지하고 자동 시작도 해제한 뒤 갱신한다. PID를 확인하지 않은 `pkill python` 같은 광범위 종료는 금지한다. **구버전은 새 잠금에 참여하지 않아 파일 교체만으로 종료되지 않는다.**

## Windows Agent 갱신 및 점검

관리자 PowerShell에서 확인한다. 명령행에는 보안 점검 인자 등이 포함될 수 있어 외부 공유 전 비밀정보를 마스킹한다.

```powershell
Get-Service NetGuardAgent -ErrorAction SilentlyContinue
schtasks /Query /TN NetGuardAgent /V /FO LIST
Get-CimInstance Win32_Process | Where-Object {
    $_.Name -match '^(powershell|python|pythonw|python3)\.exe$' -and
    $_.CommandLine -match 'netguard_agent\.(ps1|py)'
} | Select-Object ProcessId, ParentProcessId, ExecutablePath, CommandLine
Get-NetIPAddress -AddressFamily IPv4
```

기존 설치에서 `install.bat`를 재실행하면 설정을 덮어쓸 수 있다. [Windows 설정 보존 갱신 절차](WINDOWS_AGENT_COMPATIBILITY.md#기존-에이전트-갱신)의 `$source`를 v1.2.67 해제 경로로 지정하고 **9개 코드 파일 전체**를 백업/교체한다. 서비스와 예약 작업을 모두 중지한 후 교체한다. 다른 경로/이름의 구버전 작업은 확인 후 개별 중지한다. 신규 설치만 `install.bat --check` 후 `install.bat`를 사용한다.

```powershell
& 'C:\NetGuard-Agent\restart_agent.bat'
Get-Content 'C:\NetGuard-Agent\agent.log' -Tail 40
```

정상 로그의 `Agent identity: ...; report IP: ...; PID: ...`, 이어지는 `OK cpu=...`, 소프트웨어 보고 버전 1.2.67을 확인한다. `already running`은 두 번째 프로세스 전송 차단을 뜻한다. 첫 프로세스가 서비스인지 수동 실행인지 확인한다. mutex 접근 거부도 무시하지 말고 계정/기존 프로세스를 점검한다.

## IP 고정 및 복제 서버

특정 관리 IP를 표시해야 하면 기존 `agent_config.json` 객체에 아래 필드만 추가/수정하고 Agent를 재시작한다. 전체 설정을 이 예제로 교체하지 않는다. **대상 서버에 실제 할당된 IP**여야 하며 중앙 NetGuard 서버 IP를 넣지 않는다. 미설정 시 통신 경로의 IP를 쓴다. report_ip는 보고용 식별 IP이며 HTTP 통신의 실제 출발지 IP를 강제하는 옵션은 아니다.

```json
"report_ip": "10.60.8.130"
```

OS 복제본이 MachineGuid/machine-id까지 같으면 동일 ID로 판단할 수 있다. 실제로 다른 서버임을 확인한 후 복제본에만 고유 `agent_id`(64자리 소문자 16진수)를 설정한다. 동일 서버의 IP 변경/업데이트 때문에 ID를 새로 만들면 안 된다. 아래는 값 생성만 하며 OS/설정을 변경하지 않는다. 생성값은 해당 서버의 설정 백업에 보존한다.

```bash
python3 -c 'import secrets; print(secrets.token_hex(32))'
```

```powershell
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
$bytes = New-Object byte[] 32
try { $rng.GetBytes($bytes); ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant() } finally { $rng.Dispose() }
```

Linux의 별도 컨테이너/네트워크 네임스페이스는 독립된 잠금 범위다. 컨테이너를 별도 장비로 수집하려면 명칭/IP/ID도 독립적으로 설계한다. OS 재설치/복제 후 같은 장비로 승계할지는 관리자가 확인한다. OS 식별값이 없는 장비는 시작을 중단하므로 고유 override를 설정한다.

## 기존 중복 기록 처리

패치만으로 과거 두 기록이 없어지지는 않는다. 아래는 **조회 전용**이다.

```bash
sudo -u postgres psql -d netguard -c "SELECT d.id,d.name,host(d.ip_address) AS ip,d.agent_id,d.enabled,d.updated_at,s.collected_at,s.agent_version FROM devices d LEFT JOIN software_inventory_status s ON s.device_id=d.id WHERE d.name ILIKE '%MBCoTalent%' OR d.ip_address IN ('10.60.8.130'::inet,'10.60.8.187'::inet) ORDER BY d.id;"
```

실제 서버와 두 IP의 할당 관계, Agent PID/실행 경로, 현재 정상 수집 IP를 대조한다. 구버전의 agent_id는 NULL이므로 과거 기록만으로 동일 장비임을 확정할 수 없다. 동일 서버의 과거 IP임이 확인되면 관리자 검토 후 오래된 장비의 `enabled`를 해제해 검색 대상에서 제외하는 방식을 우선 사용한다. 삭제/이력 병합은 별도 승인·백업 후 진행한다. 송신 중인 구버전을 먼저 중지하지 않으면 다시 활성화될 수 있다.

409 응답의 `identity`, `IP`, `Same name`, `Multiple devices`를 확인한다. 충돌 상태에서 ID를 임의 재발급하거나 DB를 초기화하지 않는다. 올바른 기존 장비를 확인한 후 별도 이관 절차로 연결한다.

## 원복 및 검증

Agent를 중지하고 같은 버전의 코드 전체를 백업에서 복원한다. 설정은 유지한다. Windows 서비스 제거 후 예약 작업 방식으로 전환할 경우 이 버전이 비활성화한 작업은 점검 후 다시 활성화해야 한다.

중앙 서버는 중지 후 백업 backend를 복원하고 재기동한다. 추가된 nullable 컬럼/인덱스는 구버전에서 무시하므로 삭제하지 않는다. 이 패치만 되돌리려고 운영 DB 전체를 복원하면 이후 데이터가 사라질 수 있다. 원복 후 새 중복 방지 기능은 적용되지 않는다.

검증 범위: Windows PowerShell 5.1/Python 잠금 상호 운용, 종료 후 잠금 해제, 동일 ID/IP 전송, PostgreSQL 최초 연결/동시 등록/IP 변경/이력 유지/충돌 거부, Rocky 8 Python 3.6.8 및 Rocky 9 Python 3.9 설치/설정 보존 갱신/수집. root 수동 실행과 ngagent 실행 충돌도 검사한다. **실제 운영 서버 적용, 신규 서비스 생성 및 재부팅 검증은 수행하지 않았다.**

2026-11-25 테스트 결과: Windows 전체 96개 중 87개 통과, Linux 전용 9개 제외. Rocky 8·9 설치/갱신/실수집 각 17개 통과로 Linux 항목을 별도 확인했다. 두 Linux 환경의 런타임 잠금 단위 테스트도 통과했다.

구현 참고: [Microsoft 전역 named mutex](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createmutexw), [Linux abstract Unix socket 수명](https://man7.org/linux/man-pages/man7/unix.7.html).
