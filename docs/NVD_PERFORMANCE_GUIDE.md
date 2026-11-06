# NetGuard 첫 접속 지연 개선

버전: v1.2.62 / 작성일: 2026-11-07 / 적용 기준: v1.2.60~v1.2.61

## 확인한 원인과 서버 정보

기존 브라우저 초기화 코드가 장비 조회, 취약점 조회, 점검 결과를 모두 기다린 후 화면 표시와 WebSocket 연결을 시작했다. NVD 피드 170,527건의 최초 처리 시간이 대시보드 전체 대기 시간에 포함되었다. 원본 JSON을 매번 프로세스 메모리에 크게 펼치고, 반복 제품 매칭과 전체 결과 복사를 수행했다.

제공된 운영 서버 정보는 가상 CPU 2개, RAM 약 15.4 GiB(통상 16GB 구성), MemAvailable 약 10.5 GiB, 사용 중인 swap 약 1.9 GiB이다. 메모리 출력 한 번만으로 현재 swap 입출력이나 CPU 병목을 확정하지 않는다. 물리 CPU 모델의 전체 코어 수가 아니라 VM에 표시된 processor 0, 1을 기준으로 한다. 하드웨어 변경 전에 아래 코드 개선을 적용하고 부하를 관찰한다. 임의의 swap 해제, OS 캐시 삭제 또는 Uvicorn worker 증설은 수행하지 않는다.

## 변경 내용

- 장비·서버·스위치 현황과 실시간 연결을 우선 시작한다. CVE 요약은 독립적으로 받아 해당 카드만 갱신한다. 조회 중은 `로딩중`, 실패는 `취약점 조회 실패`로 표시한다.
- NVD 원본에서 필요한 항목을 정리한 JSONL 캐시를 `data/nvd_cache/.parsed-v1/`에 파일별로 보관한다. 재기동 시 원본 전체 JSON 대신 정리된 파일을 한 항목씩 읽는다. 별도 DB나 pip 패키지는 필요하지 않다.
- 캐시는 원본 파일 크기/수정 시각(ns)/캐시 형식 버전으로 검증한다. 원본 변경, 캐시 누락·손상·불완전 기록 시 원본으로 재생성한다. 캐시 저장 불가 시 원본 읽기는 유지하고 경고 로그를 남긴다.
- 각 연도 로딩 후 원본 객체를 해제하고, CPE 제품 조건이 있는 CVE에는 사용하지 않는 설명 키워드를 중복 보관하지 않는다.
- 동일 제품의 장비 매칭을 재사용한다. 등록 장비 연관 조회는 이미 매칭된 후보만 순회하고, 전체 검색은 요청한 페이지의 결과 객체만 만든다.
- 서버에서 동일 조건 결과를 최대 16개 보관한다. NVD/장비 변경 시 비우고, 완료 ID 집합이 달라지면 다시 계산한다. 완료·복원·운영자 권한과 결과 범위는 유지한다.
- 취약점 화면의 동일 조건 자동 재조회는 60초 이내 재사용하며 진행 중 요청도 합친다. 명시적 새로고침과 패치 완료·복원은 즉시 조회한다.

## 실데이터 비교

동일 개발 PC의 별도 Python 프로세스에서 공식 피드 170,527건과 고정 테스트 인벤토리 20개(스위치 16, 서버 4)로 측정했다. 운영 서버의 실제 응답 시간이나 전체 NetGuard 메모리 사용량은 아니다.

| 항목 | 기존 | 개선 후 최초 캐시 생성 | 개선 후 캐시 재사용 |
|---|---:|---:|---:|
| 첫 CVE 요약 | 28.336초 | 28.349초 | 6.809초 |
| 전체 카탈로그 조회 | 2.052초 | 0.373초 | 0.372초 |
| 최대 프로세스 메모리 | 4,147.5 MiB | 3,554.8 MiB | 1,216.2 MiB |
| 검색 카탈로그 | 166,549건 | 166,549건 | 166,549건 |
| 테스트 인벤토리 영향 후보 | 4,966건 | 4,966건 | 4,966건 |

첫 캐시 생성 시에는 원본 파싱 비용이 남는다. 따라서 운영 적용 전에 아래 준비 명령으로 별도 프로세스에서 캐시를 생성하고 서비스를 시작하는 것을 권장한다. 원본 피드를 다음에 갱신한 경우에도 다시 준비한다. 준비 프로세스 종료 시 해당 프로세스의 메모리가 반환된다. 캐시는 파생 데이터이며 원본 NVD, 장비 DB, 사용자, 알림 설정을 삭제하거나 변경하지 않는다.

이번 피드의 파생 캐시는 디스크 약 268 MiB를 추가로 사용한다. 재생성 중 임시 파일 공간도 필요하다. 파일을 바꿀 때 크기와 수정 시각을 모두 동일하게 강제로 유지하면 변경 감지가 되지 않으므로, 일반적인 파일 교체/반입 절차를 사용한다.

## Rocky Linux 적용

1. 변경 소스와 기존 설정의 백업을 확보한 뒤 `NetGuard-v1.2.62-nvd-performance.zip`을 `/tmp/`로 반입한다. 패치에는 소스·테스트·문서만 있으며 NVD 피드나 운영 설정은 없다.
2. 서비스 중지 상태에서 패치와 캐시 준비를 수행한다. 캐시 경로가 환경변수로 변경되어 있다면 실제 경로를 사용한다.

```bash
sudo systemctl stop netguard
sudo /opt/netguard/venv/bin/python -m zipfile -e /tmp/NetGuard-v1.2.62-nvd-performance.zip /opt/netguard
sudo install -d -o netguard -g netguard -m 750 /opt/netguard/data/nvd_cache/.parsed-v1
cd /opt/netguard
sudo -u netguard ./venv/bin/python scripts/prepare_nvd_cache.py --cache-dir /opt/netguard/data/nvd_cache
```

3. `Prepared ... CVEs from ... feeds`를 확인한다. 오류 또는 실패 종료 코드가 있으면 먼저 파일 권한/원본/용량을 확인한다. `ReadWritePaths`를 사용하는 systemd 설정은 `/opt/netguard/data` 쓰기를 허용해야 한다. 이 프로젝트의 기존 설정을 유지하면 된다.

```bash
sudo systemctl start netguard
sudo systemctl status netguard --no-pager -l
sudo journalctl -u netguard --since '10 minutes ago' --no-pager | grep -Ei 'parsed NVD cache|Loaded .* CVE|Failed to load|Cannot persist|error'
```

4. 브라우저 `Ctrl+F5`로 갱신한다. 첫 접속에서 장비 정보가 먼저 표시되고 CVE 카드만 잠시 로딩 중이어야 한다. `Loaded parsed NVD cache` 로그가 있으면 캐시가 재사용되고 있다. 서비스 재시작 후 첫 검색에서 인덱스를 만드는 시간은 남지만 장비 화면 초기화가 이를 기다리지 않는다.

DB 초기화·마이그레이션·에이전트 재설치·NVD 재다운로드는 필요하지 않다. 기존 `netguard.service` 자동 시작 설정은 변경하지 않는다.

## Windows 적용

관리자 PowerShell에서 실제 서비스명/설치 경로/Python 경로를 사용한다. 서비스 계정에 `data\nvd_cache\.parsed-v1` 읽기/쓰기 권한이 있어야 한다.

```powershell
$root = 'E:\SNMP\SNMP_Codex'
Stop-Service NetGuard -ErrorAction Stop
Expand-Archive -LiteralPath 'E:\SNMP\NetGuard-v1.2.62-nvd-performance.zip' -DestinationPath $root -Force -ErrorAction Stop
Set-Location $root
& "$root\venv\Scripts\python.exe" scripts\prepare_nvd_cache.py --cache-dir "$root\data\nvd_cache"
if ($LASTEXITCODE -ne 0) { throw 'NVD cache preparation failed' }
Start-Service NetGuard -ErrorAction Stop
Get-Service NetGuard
```

이후 브라우저 `Ctrl+F5`로 갱신한다. 작업 PC에서만 테스트하는 경우 운영 서비스를 임의로 설치/시작하지 않는다.

## 운영 부하 확인

페이지를 새로 여는 동안 아래 결과를 수집한다. `vmstat`의 첫 줄은 부팅 이후 평균이므로 이후 줄의 `si`/`so`(swap 입출력), `wa`(I/O 대기), `us`/`sy`/`id`(CPU)를 확인한다. swap 사용량이 남아 있다는 이유만으로 swap을 끄지 않는다.

```bash
free -h
vmstat 1 10
pid=$(systemctl show netguard -p MainPID --value)
ps -p "$pid" -o pid,%cpu,%mem,rss,etime,args
sudo journalctl -u netguard --since '10 minutes ago' --no-pager | tail -60
```

개발/점검 환경에서 독립적인 비교 측정은 `python scripts/benchmark_nvd.py`로 수행한다. 실제 DB에는 연결하지 않으며 고정 테스트 인벤토리를 사용한다. 실행 자체가 NVD를 로딩하므로 운영 서비스와 동시에 반복 실행하지 않는다.

## 검증 및 변경 파일

검색 회귀 12개, 캐시/성능 동작 5개 테스트와 브라우저 17개 시나리오를 확인했다. NVD 응답을 대기시켜도 대시보드 장비 정보와 WebSocket이 먼저 준비되는지, 늦게 도착한 CVE 카드 갱신, 조회 실패 표시, 동일 조건 요청 억제, 수동 갱신, 검색/완료/복원/권한을 검증했다. 실제 운영 서버의 적용 후 성능은 별도 확인해야 한다.

- 백엔드: `backend/security/cve_checker.py`, `backend/security/vulnerability_search.py`, `backend/security/nvd_cache.py`.
- 프론트엔드: `frontend/index.html`, `frontend/js/dashboard.js`, `frontend/js/security-search.js`.
- 도구/검증: `scripts/prepare_nvd_cache.py`, `scripts/benchmark_nvd.py`, `scripts/preview_security_search.py`, `tests/test_nvd_performance.py`, `tests/dashboard_startup_browser.cjs`.
- 문서: 이 문서, `docs/GUIDE.md`, `docs/NVD_LOCAL_UPDATE.md`, `docs/VULNERABILITY_SEARCH_GUIDE.md`.
