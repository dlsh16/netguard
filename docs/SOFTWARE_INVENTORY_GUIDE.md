# 소프트웨어 검색 설치 및 운영 가이드

버전: v1.2.63 / 작성일: 2026-11-07 / 서버 적용 기준: v1.2.62

## 변경 내용

- 기존 독립 메뉴 `프로세스 모니터링`을 `소프트웨어 검색`으로 변경했다. 서버 상세 화면의 CPU/메모리/프로세스 지표는 유지한다.
- SentinelOne Vulnerabilities의 항목/연산자/값 검색과 필터 칩을 참고했다. SentinelOne API나 CVE 데이터에 연동하는 기능은 아니다.
- 기본 표는 **서버명 / IP / 소프트웨어 이름 / 소프트웨어 버전** 네 열이다. 소프트웨어를 누르면 출처·경로·게시자·수집 시각이 팝업으로 표시된다. 서버명을 누르면 서버 모니터링으로 이동한다.
- 이름·버전·서버·IP의 포함/일치/제외/시작 문자/값 없음 조건을 AND로 조합한다. Node.js와 nodejs 검색을 동일하게 취급한다. 버전은 문자열 조건이며 버전 범위나 취약 여부를 자동 판단하지 않는다.
- OS/출처/최근 24시간 필터, 정렬, 서버 측 페이지 조회(20/50/100건), 조건 저장, CSV 내보내기를 지원한다. CSV는 검색 결과 전체를 최대 10,000건까지 내보내며 초과 시 조건 축소를 요구한다.
- 저장한 검색은 현재 브라우저의 사용자별 저장소에 저장한다. 다른 PC/브라우저에는 공유되지 않는다. 운영자도 조회·조건 저장·CSV 내보내기가 가능하지만 서버 데이터를 등록/변경하거나 프로세스를 중지할 수 없다.
- 수집 실패, 부분 수집, 24시간 경과, 미수집은 `수집 현황`에서 구분한다. 미수집은 소프트웨어가 없다는 의미가 아니다.

**중요:** 이 목록은 소프트웨어 자산 검색이다. 취약한 제품/버전이 공지되면 담당자가 해당 이름과 버전으로 검색해 대상 서버를 확인한다. 검색된 항목을 취약 확정으로 간주하지 않는다. `버전 미확인`은 추정값으로 대체하지 않는다.

## 수집 범위와 주기

| 대상 | 수집 방법 | 제한 |
|---|---|---|
| Windows 설치 프로그램 | HKLM Uninstall 레지스트리 32/64비트의 DisplayName/DisplayVersion | 모든 사용자별 설치, 휴대용 프로그램까지 자동 탐색하지 않는다 |
| Windows 실행 프로그램 | 프로세스 실행 파일의 ProductName/ProductVersion/FileVersion | 권한/메타데이터가 없으면 프로세스명 또는 버전 미확인 |
| Rocky/Linux 패키지 | `rpm -qa` 또는 `dpkg-query`의 설치 패키지 이름/버전 | RPM 배포판 릴리스 접미사를 보존한다. 소스 설치/컨테이너 내부/npm 하위 의존성은 제외 |
| Linux 실행 프로그램 | `/proc`의 실행 파일/프로세스 이름 | 실행 파일을 실행하여 버전을 조회하지 않는다. 확실한 버전이 없으면 미확인; 설치 패키지 버전은 별도 행에서 검색 |
| Apache Tomcat | 발견한 홈의 `lib/catalina.jar` 안 ServerInfo.properties | 명령행의 catalina.home/base, Windows 서비스/설치 경로 및 제한된 기본 경로에서 찾는다. 임의 위치의 중지된 Tomcat은 `tomcat_homes` 등록 필요 |
| 사내 솔루션/특수 설치 | `extra_software`의 명시적 이름·버전·경로 | 관리자 제공 정보이며 자동 검출 버전이 아니다. 상세에 직접 등록 정보로 표시 |

기본은 설치된 소프트웨어와 실행 프로그램 모두 포함한다. 출처를 `실행 프로세스`로 선택하면 실행 파일 수집 결과만 조회한다. 해당 정보도 **수집 시점의 상태**이며 실시간 프로세스 실행 보장은 아니다. 동일 서버·제품명·버전은 한 행으로 묶고 여러 경로/출처를 팝업에 표시한다. 설치 패키지와 실행 파일의 제품명 또는 버전 정보가 다르면 별도 행이 될 수 있다.

에이전트 시작 후 첫 메트릭 주기에서 별도 수집 작업을 시작하고 기본 6시간마다 실행한다. 기존 60초 메트릭 전송과 별도 프로세스/PowerShell Job으로 동작한다. 작업 시간은 180초 제한이며 메트릭 주기에서 종료 여부를 점검한다. 전송/작업 실패는 5분 후 재시도한다. 부분 수집이 서버에 저장된 경우 정상 주기까지 기다리거나 원인 조치 후 에이전트만 재시작한다. 여러 서버의 동시 재시작은 피하고 순차 배포한다.

각 보고는 최대 10,000항목, Tomcat 후보 100경로, 직접 등록 1,000항목이다. 제한 초과/접근 권한 실패 출처는 이전 정보를 임의로 삭제하지 않는다. 성공적으로 전체 목록을 열거한 출처만 이전 스냅샷을 대체한다. 따라서 부분 수집 시 과거 항목이 남을 수 있으며 상세의 마지막 수집 시각을 확인해야 한다. 장비·사용자·기존 메트릭은 변경/초기화하지 않는다.

## 적용 패키지

- 서버: `NetGuard-v1.2.63-software-inventory.zip`. v1.2.62에 적용하는 변경 파일 패치다. 신규 설치용 전체 소스는 Git 저장소를 사용한다.
- 대상 장비 에이전트: `NetGuard-Agent-v1.2.63.zip`. `agent/`, `scripts/install_agent_linux.sh`, 설치/운영 문서를 포함한다.
- ZIP에는 운영 `config.yaml`, `agent_config.json`, 로그, DB, NVD 피드를 포함하지 않는다.
- **서버 먼저, 에이전트 나중** 순서로 적용한다. 서버만 갱신하면 기존 에이전트는 소프트웨어 정보를 보내지 않으므로 미수집으로 표시된다. SNMP만으로는 이번 인벤토리를 채울 수 없다.
- 외부 인터넷·NVD 재다운로드·신규 pip 패키지가 필요 없다. 기존 에이전트 → NetGuard HTTP(S) 주소/포트를 그대로 사용한다. 기본 직접 접속 포트는 TCP 8000이며 프록시 구성 시 기존 80/443을 따른다. 에이전트로 인바운드 포트를 새로 열지 않는다.

## Rocky Linux 서버 패치

운영 소스/설정 및 PostgreSQL 백업을 먼저 확보한다. 백업은 관리자/DB 서비스 계정만 접근 가능한 위치에 보관한다. 아래 예시는 설치 경로 `/opt/netguard`, 서비스명 `netguard`이다.

```bash
sudo systemctl stop netguard
sudo -u postgres pg_dump -Fc -f /var/lib/pgsql/netguard-before-v1263.dump netguard
sudo chmod 600 /var/lib/pgsql/netguard-before-v1263.dump
sudo tar -czf /root/netguard-source-before-v1263.tar.gz -C /opt/netguard backend frontend agent scripts docs
sudo /opt/netguard/venv/bin/python -m zipfile -e /tmp/NetGuard-v1.2.63-software-inventory.zip /opt/netguard
sudo -u netguard /opt/netguard/venv/bin/python -m py_compile /opt/netguard/backend/software_inventory.py /opt/netguard/backend/api/software_routes.py /opt/netguard/backend/api/agent_routes.py /opt/netguard/backend/database.py /opt/netguard/backend/app.py
sudo systemctl start netguard
sudo systemctl status netguard --no-pager -l
sudo journalctl -u netguard --since '10 minutes ago' --no-pager | grep -Ei 'software|startup|error|failed'
```

각 명령의 성공을 확인한 후 다음 명령을 실행한다. 백업 파일이 이미 존재하면 다른 이름을 사용한다. 서비스 시작 시 `software_inventory`, `software_inventory_status` 테이블과 인덱스를 추가한다. 기존 DB 연결 계정에 스키마 CREATE 권한이 필요하며 DB 초기화/재설치는 하지 않는다. systemd 자동 시작/SMTP/임계값 설정은 그대로 유지된다. 브라우저에서 `Ctrl+F5`로 갱신한다.

## Windows 서버 패치

관리자 PowerShell을 사용하고 서비스명과 설치 경로를 실제 환경에 맞춘다. 먼저 기존 PostgreSQL 백업 절차로 DB 백업을 완료한다. 아래 백업에는 소스만 포함되지만 접근 권한을 제한해 보관한다.

```powershell
$root = 'E:\SNMP\SNMP_Codex'
$ErrorActionPreference = 'Stop'
Stop-Service NetGuard
$backup = 'E:\SNMP\netguard-source-before-v1263-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.zip'
Compress-Archive -LiteralPath "$root\backend", "$root\frontend", "$root\agent", "$root\scripts", "$root\docs" -DestinationPath $backup
Expand-Archive -LiteralPath 'E:\SNMP\NetGuard-v1.2.63-software-inventory.zip' -DestinationPath $root -Force
& "$root\venv\Scripts\python.exe" -m py_compile "$root\backend\software_inventory.py" "$root\backend\api\software_routes.py" "$root\backend\api\agent_routes.py" "$root\backend\database.py" "$root\backend\app.py"
if ($LASTEXITCODE -ne 0) { throw 'Compile failed; restore backup before starting' }
Start-Service NetGuard
Get-Service NetGuard
```

서버의 기존 서비스 로그에서 Application startup complete를 확인하고 `Ctrl+F5`로 갱신한다. NSSM/작업 스케줄러 등 기존 실행 방식은 바꾸지 않는다. 실제 서비스명이 다르면 그 이름을 사용한다.

## Windows 에이전트 갱신

기존 설치에는 `install.bat`를 다시 실행하지 않는다. 설치 프로그램은 설정 파일을 다시 작성할 수 있다. 새 ZIP을 임시 폴더에 풀고 다음 **4개 파일**만 교체한 뒤 기존 재시작 도구를 실행한다. 설정 파일/로그/서비스 등록은 유지한다.

```powershell
$ErrorActionPreference = 'Stop'
Expand-Archive -LiteralPath 'C:\Temp\NetGuard-Agent-v1.2.63.zip' -DestinationPath 'C:\Temp\NetGuard-v1263' -Force
$source = 'C:\Temp\NetGuard-v1263\agent'
$target = 'C:\NetGuard-Agent'
$files = @('netguard_agent.ps1', 'netguard_agent.py', 'software_inventory.ps1', 'software_inventory.py')
$backup = Join-Path $target ('backup-v1263-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $backup | Out-Null
foreach ($file in $files) {
    if (Test-Path -LiteralPath (Join-Path $target $file)) { Copy-Item -LiteralPath (Join-Path $target $file) -Destination $backup }
    Copy-Item -LiteralPath (Join-Path $source $file) -Destination $target -Force
}
& "$target\restart_agent.bat"
Get-Content "$target\agent.log" -Tail 40
```

PowerShell 모드도 Python 모드도 두 보조 파일을 함께 배포한다. 최초 설치는 ZIP 전체를 푼 `agent\install.bat`를 관리자 권한으로 실행한다. Windows PowerShell 5.1 이상이 필요하다. 창을 닫아도 기존 서비스/시작 작업으로 동작하며 재부팅 자동 시작 설정은 유지된다. 실제 서비스/작업 확인은 [에이전트 재시작 가이드](AGENT_RESTART_GUIDE.md)를 따른다.

## Rocky Linux 에이전트 갱신

대상 서버에서 기존 에이전트 경로 `/opt/netguard-agent`, 계정 `ngagent`, 서비스 `netguard-agent`를 확인한다. ZIP을 별도 임시 경로에 풀고 코드만 교체한다. 운영 에이전트 폴더에 전체 ZIP을 직접 풀지 않는다.

```bash
python3 -m zipfile -e /tmp/NetGuard-Agent-v1.2.63.zip /tmp/netguard-agent-v1263
sudo systemctl stop netguard-agent
sudo cp -p /opt/netguard-agent/netguard_agent.py /opt/netguard-agent/netguard_agent.py.before-v1263
sudo install -o ngagent -g ngagent -m 640 /tmp/netguard-agent-v1263/agent/netguard_agent.py /opt/netguard-agent/netguard_agent.py
sudo install -o ngagent -g ngagent -m 640 /tmp/netguard-agent-v1263/agent/software_inventory.py /opt/netguard-agent/software_inventory.py
sudo systemctl start netguard-agent
sudo systemctl status netguard-agent --no-pager -l
sudo journalctl -u netguard-agent --since '10 minutes ago' --no-pager | grep -Ei 'software|error|failed|OK'
```

최초 설치는 압축 해제 폴더의 `scripts/install_agent_linux.sh`를 사용한다. 인벤토리 때문에 에이전트를 root로 변경하지 않는다. RPM DB와 Tomcat 경로에 필요한 최소 읽기/디렉터리 탐색 권한을 별도로 부여한다. `/proc` 접근 제한은 버전 미확인/부분 수집으로 표시될 수 있다.

## 선택 설정

기존 `agent_config.json`의 서버 URL/API 키/호스트명/보안 점검 항목을 보존하고 `software_inventory` 항목만 병합한다. 이 키가 없으면 활성화/6시간을 기본으로 사용한다. 예시 버전은 실제 확인한 값으로 대체한다.

```json
"software_inventory": {
  "enabled": true,
  "interval_hours": 6,
  "tomcat_homes": ["C:\\Apps\\Tomcat10"],
  "extra_software": [
    {
      "name": "Risk & Compliance Management Solution",
      "version": "실제 확인한 버전",
      "installation_path": "C:\\Apps\\RiskCompliance",
      "publisher": "실제 공급사"
    }
  ]
}
```

Linux의 `tomcat_homes`는 실제 경로를 JSON 배열의 큰따옴표로 작성한다. 예: `"tomcat_homes": ["/opt/company/tomcat"]`. 직접 등록 정보는 실제 설치/삭제 시 관리자가 갱신해야 한다. 알 수 없는 버전은 `""`로 둔다. 수집 간격은 1~168시간으로 제한된다. `enabled: false`이면 새 수집만 중지하며 DB의 과거 목록을 자동 삭제하지 않는다. 변경 후 에이전트만 재시작한다.

## 로그 및 장애 확인

정상 로그 예시:

```text
Software inventory started in background (agent 1.2.63)
Software inventory: status=ok items=208 collection=complete
```

`collection=partial`이면 일부 출처가 실패한 것이며 서버 화면의 수집 현황/상세를 확인한다. 오류가 있어도 기존 CPU/메모리 메트릭 전송은 계속되어야 한다. 최초 결과는 보통 다음 수 분 내에 표시되며 목록 새로고침은 수집을 강제 실행하지 않고 현재 DB를 다시 조회한다. 즉시 재수집은 에이전트 재시작으로 수행한다.

| 증상 | 확인할 내용 |
|---|---|
| 새 메뉴/API가 없음 | 서버 패치 전체 배포, 서비스 재시작, Ctrl+F5 |
| 구형 에이전트가 미수집 | 새 메인 파일과 두 보조 파일을 모두 배포했는지 확인 |
| helper missing | 에이전트 폴더에 software_inventory.ps1/.py 존재 여부 |
| HTTP 403 | 기존 API 키와 서버 에이전트 키 일치 여부; 키를 로그/공유 문서에 출력하지 않음 |
| HTTP 409 | 먼저 기존 register/metrics 전송으로 활성 서버 등록이 되었는지 확인; 호스트/IP 변경 여부 |
| HTTP 404 | 서버 패치가 먼저 반영되었는지 확인 |
| HTTP 422 | 에이전트/서버 시간 동기화, 시간대, 문자열/항목 수 제한 확인 |
| 버전 미확인 | 레지스트리/파일에 버전 메타데이터가 있는지, 읽기 권한, Tomcat 홈 설정 확인 |
| 삭제/패치 후 과거 버전 남음 | 출처별 마지막 시각과 부분 수집 여부 확인; 권한 문제를 해결하고 재수집 |
| 연결 실패/시간 초과 | 에이전트 로그, 기존 서버 URL/포트/방화벽, 소프트웨어 API 상태 확인 |

서버 DB 읽기 전용 확인:

```bash
sudo -u postgres psql -d netguard -c "SELECT d.name, host(d.ip_address) AS ip, s.status, s.collected_at, s.item_count, s.errors FROM devices d LEFT JOIN software_inventory_status s ON s.device_id=d.id WHERE d.type='server' ORDER BY d.name;"
sudo -u postgres psql -d netguard -c "SELECT d.name, i.name AS software, i.version, i.source, i.last_seen FROM software_inventory i JOIN devices d ON d.id=i.device_id WHERE i.present AND lower(i.name) LIKE '%tomcat%' ORDER BY d.name;"
```

원복은 서버/에이전트 서비스를 중지하고 백업한 코드로 복구한 후 재시작한다. 새 테이블은 그대로 두어도 이전 버전 동작에 영향을 주지 않으므로 삭제하지 않는다. 운영 DB 전체를 초기화하거나 장비/사용자 테이블을 재생성하지 않는다.

## 검증 범위

2026-11-07 개발 PC 검증: Python 자동 테스트 54개 및 브라우저 흐름 28개(소프트웨어 11, 기존 보안 12, 초기 로딩 5) 통과. 테스트 DB는 운영 DB와 분리된 로컬 PostgreSQL 17이며 TimescaleDB 확장 없는 구성이다.

- 분리된 로컬 PostgreSQL에서 인증, 검색, 정렬, 페이지, CSV 한도, 중복/역순 스냅샷, 부분 실패 보존, 기존 장비/사용자 보존 테스트.
- Windows PowerShell 5.1 실제 읽기 전용 수집, Tomcat 메타데이터 fixture, Python 백그라운드 실행/시간 제한, RPM/DEB 파서 테스트.
- Edge/Playwright 데스크톱·모바일 필터/팝업/저장 조건/CSV/오류/운영자 조회/화면 크기 검증.
- Rocky 실장비 수집, 운영 환경 에이전트 서비스 재시작, 운영 DB 배포는 개발 PC에서 실행하지 않았다. 운영 반영 후 대상 장비별 표본 검증이 필요하다.
- 샘플 미리보기는 합성 데이터이며 실제 장비나 취약점 결과가 아니다. 별도 미리보기 프로세스/테스트 DB는 운영에 배포하지 않는다.

수집 방식 참고: [Microsoft 설치 프로그램 조회](https://learn.microsoft.com/en-us/powershell/scripting/samples/working-with-software-installations?view=powershell-7.6), [Apache Tomcat ServerInfo](https://github.com/apache/tomcat/blob/main/java/org/apache/catalina/util/ServerInfo.properties), [RPM queryformat](https://rpm.org/docs/4.20.x/manual/queryformat.html). Windows에서는 설치 제품의 재구성을 유발할 수 있는 Win32_Product를 사용하지 않는다.
