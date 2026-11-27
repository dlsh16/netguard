# v1.2.68 설치 및 업데이트 안내

작성: 2026-11-27. 중앙 서버를 먼저 갱신하고 Agent를 갱신한다. DB를 재생성하거나 `setup_db.py`를 다시 실행하지 않는다. 이번 추가 테이블은 시작 시 자동 생성되며 기존 장비, 사용자, 수집 이력을 삭제하지 않는다. 폐쇄망에 새 pip/npm 패키지를 설치할 필요가 없다.

## 1. 중앙 서버 적용

먼저 PostgreSQL 백업과 현재 `backend`, `frontend`, `config` 백업을 확보한다. 압축 해제 경로는 예시이며 실제 반입 경로로 변경한다. 기존 `config/config.yaml`, `data`, `logs`, `venv`는 덮어쓰지 않는다. 이전 `apply_update.ps1`은 일부 파일만 복사하므로 이번 배포에는 아래 절차를 사용한다.

### Rocky Linux

```bash
sudo -u postgres pg_dump -Fc netguard > netguard-before-v1268.dump
sudo systemctl stop netguard
sudo cp -a /opt/netguard/backend /opt/netguard/backend.before-v1268
sudo cp -a /opt/netguard/frontend /opt/netguard/frontend.before-v1268
sudo cp -a /opt/netguard/config /opt/netguard/config.before-v1268
sudo cp -a /tmp/NetGuard-v1.2.68/backend/. /opt/netguard/backend/
sudo cp -a /tmp/NetGuard-v1.2.68/frontend/. /opt/netguard/frontend/
sudo install -d -o netguard -g netguard -m 0750 /opt/netguard/data/security_reports
sudo systemctl restart netguard
sudo systemctl status netguard --no-pager
```

애플리케이션 코드/템플릿은 서비스 계정에서 읽을 수 있어야 한다. `ReadWritePaths`에 `/opt/netguard/data`가 포함되어야 한다. 보고서 저장 기본 경로를 이전 `backend/data/security_reports`에서 `/opt/netguard/data/security_reports`로 변경했다. 기존 보고서는 DB에 저장된 경로로 계속 조회한다. 이전 파일을 임의 이동하지 않는다.

### Windows

관리자 PowerShell에서 설치 경로와 서비스명을 확인한 후 실행한다. 예시는 `C:\NetGuard`, 서비스명 `NetGuard`이다.

```powershell
$Install = 'C:\NetGuard'
$Source = 'C:\Temp\NetGuard-v1.2.68'
pg_dump.exe -U postgres -Fc -f C:\Temp\netguard-before-v1268.dump netguard
Stop-Service NetGuard
Copy-Item -LiteralPath "$Install\backend" -Destination "$Install\backend.before-v1268" -Recurse
Copy-Item -LiteralPath "$Install\frontend" -Destination "$Install\frontend.before-v1268" -Recurse
Copy-Item -LiteralPath "$Install\config" -Destination "$Install\config.before-v1268" -Recurse
Copy-Item -Path "$Source\backend\*" -Destination "$Install\backend" -Recurse -Force
Copy-Item -Path "$Source\frontend\*" -Destination "$Install\frontend" -Recurse -Force
New-Item -ItemType Directory -Path "$Install\data\security_reports" -Force
Start-Service NetGuard
Get-Service NetGuard
```

해당 서비스 계정에 보고서 디렉터리 쓰기 권한을 부여한다. 기존 서비스/작업 스케줄러 방식은 그대로 유지한다. 업데이트 완료 후 브라우저 강력 새로고침을 수행한다.

## 2. RSS 및 향후 C-TAS API

공식 RSS: https://www.boho.or.kr/kr/rss.do?bbsId=B0000133

KISA 공개 보안공지 RSS이며 로그인 후 열람하는 C-TAS 전체 콘텐츠가 아니다. 현재 확인한 피드는 최근 10건의 제목/링크/공개일을 제공하며 본문·취약 버전 범위를 포함하지 않는다. 주기적 수신으로 로컬 이력을 누적하지만 첫 동기화가 과거 전체 공지를 가져오는 것은 아니다. 원문 링크에서 상세 권고를 확인한다.

인터넷 연결이 승인된 중앙 서버는 기존 YAML 파일에 아래 항목을 추가/수정하고 서비스를 재시작한다.

```yaml
advisory_sync_enabled: true
advisory_sync_interval: 900
advisory_provider: kisa-rss
```

자동 동기화는 기본 15분, 최소 5분의 폴링이며 Push 방식의 즉시 알림은 아니다. 네트워크 연결이 없는 환경은 `false`를 유지한다. 수신 실패 시 기존 공지를 보존하며 화면에 마지막 성공 일자와 오류가 남는다. 메인 대시보드 진입 시 외부 동기화를 기다리지 않는다.

방화벽은 수집 서버에서 `www.boho.or.kr` TCP 443과 사내 DNS 접근을 승인한다. 고정 IP를 추정하여 등록하지 않는다. API 방화벽 대상은 추후 제공되는 최신 명세를 따른다. 서버명/IP/설치 소프트웨어 목록은 RSS 서버로 전송하지 않는다.

폐쇄망 반입 파일은 인터넷 허용 PC에서 다음과 같이 받는다.

```powershell
Invoke-WebRequest -UseBasicParsing -Uri 'https://www.boho.or.kr/kr/rss.do?bbsId=B0000133' -OutFile .\kisa-security.xml
Get-FileHash .\kisa-security.xml -Algorithm SHA256
```

```bash
curl --fail --proto '=https' --tlsv1.2 'https://www.boho.or.kr/kr/rss.do?bbsId=B0000133' -o kisa-security.xml
sha256sum kisa-security.xml
```

승인된 반입 절차 및 해시 대조 후 `취약점 > 보안 업데이트 권고 > RSS 파일 반입`에서 XML을 선택한다. UTF-8/BOM을 지원하며 5 MiB 제한, DTD/외부 엔티티 거부, 허용된 KISA HTTPS 원문만 저장한다. 같은 공지는 중복 생성하지 않는다.

소프트웨어 인벤토리와 OS 이름의 제품군 일치만 `영향 후보`로 표시한다. 제품명 일치는 취약 확정이 아니다. 해당 버전, 운영체제 패치/백포트, 구성 조건, 마지막 수신 일자를 검토한다. 수집되지 않은 제품을 안전하다고 판정하지 않는다. 직접 NVD/CVE 자동 매핑은 기존 NVD 검색 탭에 유지한다.

`backend/security/advisories.py`의 Provider `fetch()`는 `id/provider/title/url/summary/published_at` 정규화 레코드를 반환한다. 승인된 C-TAS API 명세를 확보하면 별도 Adapter를 추가할 수 있다. 현재 임의 API 주소·인증 방식·호출 제한은 구현하지 않았다.

승인/명세 문의: https://ctas.krcert.or.kr/index 에 안내된 `ctashelp@krcert.or.kr`, `02-405-6691` (2026-11-27 확인). 홈페이지 가입과 공유형 API 승인은 별개이다. 보안공지 제공 범위, 인증 방식, 페이지/증분 조회, 호출 제한, 방화벽 대상, 폐쇄망 반입 허용 범위를 요청한다. 키/토큰/비밀번호는 Git이나 채팅에 첨부하지 않는다.

공식 근거: https://www.boho.or.kr/kr/subPage.do?menuNo=205121 및 https://www.krcert.or.kr/kr/subPage.do?menuNo=205013

## 3. Agent 원격 점검 설정

원격 점검은 관리자만 요청한다. 운영자는 조회만 가능하다. 사용자 지정 명령, 임의 스크립트 경로, 스크립트 다운로드를 허용하지 않으며 `security`와 `maintenance` 작업만 실행한다. Agent가 중앙 서버의 기존 HTTP(S) 포트에 Outbound 접속하므로 Agent 측 신규 Inbound 포트/SSH는 필요 없다. 운영 환경은 HTTPS와 접근 IP 제한을 권장한다.

1. 중앙 서버 업데이트 후 Windows/Linux Agent 전체 파일을 갱신한다.
2. `점검 결과 저장 > 서버별 원격 점검`에서 대상 서버의 `연결키`를 발급한다. 발급 즉시 이전 키가 폐기되며 진행 중인 작업이 있으면 발급할 수 없다.
3. 표시된 `remote_checks` 객체를 해당 서버의 기존 `agent_config.json`에 병합한다. 기존 `server_url`, `api_key`, `hostname`, `agent_id`, `report_ip` 등은 보존한다. 다른 서버의 연결키를 재사용하지 않는다.
4. 해당 Agent만 재시작한다. 약 1회 수집 주기 후 `연결됨`이 표시되면 취약점 점검/정기 점검 버튼을 사용한다.

```json
"remote_checks": {
  "enabled": true,
  "token": "화면에서 발급받은 이 서버 전용 64자리 키"
}
```

JSON 예시는 전체 설정 파일이 아닌 추가할 속성이다. 기존 마지막 속성과 쉼표로 구분한다. 중앙 DB에는 토큰의 SHA-256 해시만 저장한다. Agent 설정 및 결과 파일 접근 권한을 제한하고 분실 시 재발급한다.

### Windows Agent

신규 설치는 `agent\install.bat` 관리자 실행. PowerShell 5.1 이상 필요. 설치 시 `remote_checks.py`, `remote_checks.ps1`, 두 Windows `check_scripts` 파일을 함께 배치한다. 기본 원격 실행은 비활성이다. 기존 설치 업데이트는 원격 점검이 실행 중이지 않을 때 서비스/작업을 중지하고 패키지의 Agent 코드 및 `check_scripts`를 갱신하되 `agent_config.json`은 보존한 후 `restart_agent.bat`를 관리자 실행한다.

Windows 무인 실행에서는 `-NoOpen -Unattended`로 입력 대기, Excel COM 자동화, 공유폴더 전송을 제외한다. 시스템 설정 자동 교정은 하지 않고 결과 CSV를 전송한다. Agent 디렉터리는 SYSTEM/Administrators만 접근하도록 설치 시 ACL을 제한한다. 이전 수동 설치도 동일하게 보호한다.

### Rocky/Linux Agent

```bash
sudo bash scripts/install_agent_linux.sh --update
sudo bash scripts/enable_remote_checks_linux.sh --enable
sudo systemctl restart netguard-agent
```

신규 설치는 `--update`를 제외한다. `/usr/libexec/platform-python` 3.6.8을 지원한다. Agent 본체는 계속 `ngagent` 계정으로 동작한다. 관리자 승인으로 고정된 두 점검만 실행하는 root 소유 wrapper와 제한 sudoers를 설치한다. `sudo`, `visudo`, `timeout`이 미설치면 승인된 OS 오프라인 패키지로 준비한다. `ngagent ALL=(ALL) NOPASSWD:ALL` 같은 광범위 권한은 부여하지 않는다.

root 실행 파일: `/usr/local/sbin/netguard-run-check`, root 소유 스크립트: `/usr/local/libexec/netguard-checks/`, 결과: `/var/lib/netguard-checks/<job_id>/`. 실행 종류와 숫자 작업 ID만 허용하고 신규 전용 디렉터리를 사용한다. 최대 30분 후 프로세스 그룹을 종료한다. 점검 스크립트 변경 시 enable 스크립트를 다시 실행해야 root 소유 사본도 갱신된다.

Linux 무인 점검에서는 패키지 저장소 갱신/조회 및 SMB 공유 전송을 실행하지 않는다. 외부 패키지 보안 업데이트 적용 여부는 `확인필요`로 저장한다. 수동 공유 저장이 필요한 경우에만 별도 승인 후 `NETGUARD_REPORT_SHARE/USER/PASSWORD` 환경변수를 설정한다. Linux 결과의 `불량`은 취약(fail)으로 분류한다.

## 4. 실행 이력 및 결과

서버 선택과 시작/종료일로 요청 날짜를 검색한다. 화면에는 요청, 실제 실행 시작, 완료 날짜가 별도로 표시된다. 종료일을 포함하며 시간 표시는 브라우저 지역 시간이다. 서버별 하나의 작업만 대기/실행 가능하다. 대기 15분 경과는 만료, 실행 결과 45분 미수신은 `결과 미확인`이다. Agent 재시작/통신 실패 시 완료 결과만 재전송하며 점검 자체를 자동 재실행하지 않는다. 대기 작업만 취소 가능하다. 실행 중 작업 강제 취소는 제공하지 않는다.

점검 결과는 기존 장비 ID에 귀속된다. CSV 내 hostname/IP로 새 장비를 만들거나 기존 장비를 변경하지 않는다. 같은 작업 결과 재전송은 같은 run_id로 응답한다. 결과 CSV는 4 MiB 이하이며 파싱 가능한 항목이 없으면 성공으로 표시하지 않는다. Agent 출력/스크립트 로그는 별도 로컬 작업 폴더에 남는다. 보고서는 보안 정보이므로 보존 기간에 맞춰 백업 후 정리한다.

Bundled 점검 스크립트는 기준 시점의 설정/버전 점검이며 최신 취약점 전체를 보장하지 않는다. 보안공지의 취약 버전/백포트 확인과 별도 검토한다. 장시간 파일 시스템 탐색은 부하를 유발하므로 정기 점검 시간대에 실행한다.

## 5. XLSX 자산목록

장비관리의 `엑셀 다운로드`는 관리자만 가능하다. 첨부 양식에서 서버 28열, 네트워크 22열, 부대설비 16열의 헤더/그룹을 반영한 별도 템플릿을 제공한다. 원본 엑셀/개인정보는 Git과 패키지에 포함하지 않는다.

- 서버: No, 자산명/Hostname(등록명), 위치, IP, OS, 수집된 WEB/WAS 및 DBMS 이름·버전.
- 스위치: No, 자산명/Hostname(등록명), 위치, IP, OS/펌웨어.
- 부대설비: No, 자산명, 장비 유형, 장비 레코드당 대수 1, 위치, 비고(IP).
- 미수집 모델/일련번호/자산번호/하드웨어 사양/책임자/중요도는 공란. CPU 사용률을 CPU 사양으로 잘못 기록하지 않는다.
- SNMP Community, Agent 토큰, 비밀번호는 내보내지 않는다. 입력 문자열은 Excel 수식으로 실행되지 않는다.

## 6. 스위치 링크 Up/Down

확인한 문제: 수집 누락의 기본 상태가 Down이었고, 서비스 초기 수집 시 기존 Down 이벤트를 일괄 해제했다. 실제 해당 포트가 물리적으로 Flapping 했는지는 운영 스위치 로그와 시각 대조가 필요하다.

변경 후 ifOperStatus와 ifAdminStatus를 확인한다. 관리상 Up인 포트의 유효한 Up/Down을 연속 2회 관측해야 전이로 확정한다. 초기 상태는 기준만 설정하고 알람을 만들지 않는다. 응답 누락/unknown/testing, 관리상 Down, Vlan/Null/Loopback/Tunnel 인터페이스는 링크 장애로 판단하지 않는다. ifInErrors/ifOutErrors는 더 이상 수집하지 않는다.

확정된 Up→Down은 경고 1건, Down→Up은 복구 정보 1건으로 기록하고 Down 사건을 해결한다. 상태는 DB에 남아 서비스 재시작 후에도 유지된다. 60초 폴링 기준 감지에는 보통 1~2주기가 필요하며 그 사이의 짧은 Flap은 놓칠 수 있다. SNMP Trap 수신은 이번 범위에 포함하지 않는다.

기존 형식의 Down 이벤트는 해당 이름의 포트에서 안정된 Up이 확인될 때만 해제하며, 기존 이력 전체를 삭제하지 않는다. 수동 삭제한 Down을 계속 Down 상태라는 이유만으로 재생성하지 않는다.

## 7. 검증과 롤백

관리자/운영자 권한, RSS BOM/날짜/중복/실패 보존, 작업 동시 claim/서버별 토큰 격리/결과 중복 저장 방지, 링크 debounce/재시작 보존, XLSX 구조/수식 차단을 테스트한다. 미리보기는 합성 데이터이며 실제 운영 서버 점검을 실행하지 않는다. 운영 적용 후 대상 서버 1대로 승인된 시간대에 시험한다.

개발 PC 검증 결과: unittest 113건, 실패 0건, 환경별 20건 skip. 별도 Rocky 8(Python 3.6.8)/Rocky 9(Python 3.9) 컨테이너에서는 Linux 설치 테스트 각각 17건 통과 및 실제 두 점검 CSV 생성/네트워크 접근 차단/재실행 거부 확인. Windows PowerShell 5.1 무인 실행은 가짜 점검 스크립트와 로컬 HTTP 서버로 검증했다. Playwright에서 RSS 검색, 원격 요청/취소/결과 조회, XLSX 다운로드, 운영자 권한, 모바일 화면과 기존 NVD 검색 12개 흐름을 확인했다. 실제 고객 서버의 점검 실행 및 SMTP 발송은 수행하지 않았다.

배포 ZIP은 `scripts/build_release.py --version 1.2.68 --output-dir <출력폴더>`로 생성한다. 중앙 서버/Windows Agent/Linux Agent를 분리하고 Git 커밋 ID와 파일별 SHA-256을 `release-manifest.json`에 기록한다. 실제 설정/수집 데이터/원본 자산 엑셀은 제외한다. Python/OS 설치 파일과 기존 외부 라이브러리는 포함하지 않는 소스 업데이트 패키지이다.

롤백은 서비스를 중지하고 백업 코드/화면을 복원한 뒤 재시작한다. 추가 테이블은 삭제하지 않아도 이전 코드에 영향을 주지 않는다. 배포 전 생성한 DB 백업을 덮어 복구하면 이후 데이터가 손실되므로 단순 코드 롤백에 DB 복구를 사용하지 않는다. 원격 기능 중단 시 Agent `remote_checks.enabled=false` 후 재시작하고 필요하면 `/etc/sudoers.d/netguard-checks`만 제거한다. 진행 중 작업이 없는지 먼저 확인한다.

중요: 기존 Windows/Linux 점검 스크립트에 있던 공유폴더 자격증명 상수를 제거했다. 과거 Git 커밋/반입본에 포함되었을 가능성이 있으므로 해당 계정 비밀번호를 교체하고 접근 이력을 확인한다. Git 이력은 이번 작업에서 강제 재작성하지 않았다.

## 8. 변경 파일

백엔드: `backend/operations_schema.py`, `switch_links.py`, `asset_export.py`, `templates/asset_inventory.xlsx`, `security/advisories.py`, `security/check_reports.py`, `api/advisory_routes.py`, `api/check_job_routes.py`, `api/asset_routes.py`, `app.py`, `config.py`, `database.py`, `alerts/alert_manager.py`, `collectors/snmp_collector.py`.

화면: `frontend/index.html`, `frontend/js/dashboard.js`, `frontend/js/operations.js`, `frontend/css/operations.css`.

Agent/설치: `agent/remote_checks.py`, `remote_checks.ps1`, `netguard_agent.py`, `netguard_agent.ps1`, `software_inventory.py`, `software_inventory.ps1`, `install.ps1`, `check_scripts` 4개 파일, `scripts/install_agent_linux.sh`, `linux_agent_setup.py`, `enable_remote_checks_linux.sh`, `netguard-run-check`.

기타: `config/config.example.yaml`, `.gitignore`, 운영/설치 가이드, 테스트와 로컬 미리보기. 실제 목록은 `git show --stat v1.2.68`로 조회한다.
