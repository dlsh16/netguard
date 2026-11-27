# Windows 운영 메뉴얼

v1.2.68 / 2026-11-27. 설치·파일 갱신은 [업데이트 안내](OPERATIONS_UPDATE_GUIDE.md)를 따른다.

## 중앙 서버

```powershell
Get-Service NetGuard
Get-Content C:\NetGuard\logs\netguard.log -Tail 100 -Wait
```

실제 설치 경로/서비스명이 다르면 변경한다. `netguard.advisories`에서 RSS 수신 건수/오류, `netguard.check_jobs`에서 요청 작업 ID와 결과 저장을 확인한다. `데이터 없음`과 `동기화 실패`를 구분하고 마지막 성공 일자를 확인한다. 자동 RSS는 YAML `advisory_sync_enabled` 설정 후 중앙 서버 재시작으로 반영한다. 인터넷 차단 환경에서는 파일 반입을 사용한다.

## Agent

```powershell
Get-Service NetGuardAgent -ErrorAction SilentlyContinue
Get-ScheduledTask -TaskName NetGuardAgent -ErrorAction SilentlyContinue
Get-Content C:\NetGuard-Agent\agent.log -Tail 50 -Wait
```

설치 방식에 따라 서비스 또는 작업 스케줄러 한 가지만 등록된다. Agent만 재시작하려면 관리자 권한으로 `C:\NetGuard-Agent\restart_agent.bat`를 실행한다. 콘솔 창 종료가 수집을 중단시키지 않아야 한다. 원격 점검 중 재시작은 피한다.

원격 점검 연결키는 해당 서버의 `agent_config.json`에만 보관한다. `check_output\<job_id>\runner.log`, `runner-error.log`, CSV를 확인한다. Python 모드 로그는 `remote_check_runner.log`이다. 통신 실패 시 `remote_check_pending.json`을 수동 삭제하지 않는다. 재전송 후 서버 완료 이력이 확인되면 자동 제거된다. 결과에 계정/설정 정보가 포함될 수 있으므로 Agent 디렉터리를 SYSTEM/Administrators로 제한한다.

## 일상 점검

- 원격 작업이 `결과 미확인`이면 로컬 출력과 실행 프로세스를 먼저 확인하고 관리자 판단으로 새 요청한다.
- 서버/날짜 필터로 과거 실행 결과를 조회한다. 시작/완료 시각과 요청 시각을 구별한다.
- 자산목록 XLSX를 열어 장비 수와 IP를 대조한다. 미수집 자산 속성은 공란이다.
- 스위치 링크 이벤트는 연속 2회 상태 확인으로 생성된다. 실제 Flap 여부는 스위치 로그와 대조한다.
- 중앙 DB와 `data/security_reports`를 같은 보존 정책으로 백업한다. 설정/비밀번호를 Git에 올리지 않는다.

재부팅 자동 실행 확인: 서비스는 `Get-CimInstance Win32_Service -Filter "Name='NetGuard'" | Select-Object Name,StartMode,State`, Agent 작업은 `Get-ScheduledTask -TaskName NetGuardAgent | Select-Object -ExpandProperty Triggers`로 시작 트리거를 확인한다. 기존 설치에 따라 서비스명은 달라질 수 있다.
