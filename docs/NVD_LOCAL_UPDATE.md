# NetGuard 로컬 NVD 업데이트

작성일: 2026-11-07 / 업데이트 도구: v1.2.61 / 기존 NetGuard v1.2.60 호환

> v1.2.62 이상에서는 새 피드 반입 후 서비스를 시작하기 전에 `scripts/prepare_nvd_cache.py --cache-dir 실제캐시경로`로 파생 캐시를 준비하면 첫 조회 비용을 줄일 수 있다. Windows/Rocky 명령과 성능 비교는 [NVD_PERFORMANCE_GUIDE.md](NVD_PERFORMANCE_GUIDE.md)를 참고한다. v1.2.60/61에 이 스크립트만 복사하지 말고 성능 패치 전체를 먼저 적용한다.

## 데이터 범위와 경로

인터넷 가능한 PC에서 NIST 공식 NVD JSON 2.0 연도별 피드를 다운로드하고 폐쇄망 서버에 반입한다. 이 방식에는 API 키가 필요하지 않으며 외부로 장비 정보를 보내지 않는다. 공식 출처: [NVD Data Feeds](https://nvd.nist.gov/vuln/data-feeds).

이번 대상은 **2024·2025·2026년 CVE ID**이다. 전체 연도의 취약점 DB가 아니며 2023년 이전 취약점도 검색하려면 해당 연도 피드를 추가한다. NVD의 2002 피드에는 2002년 이전 항목도 포함된다. 연도별 피드는 게시일 범위가 아닌 CVE ID의 연도 기준이다.

현재 개발 PC의 설정 `nvd_cache_dir: data/nvd_cache`는 `E:\SNMP\SNMP_Codex\data\nvd_cache`를 의미한다. `backend\data\nvd_cache`에 있던 기존 파일은 보존했으며 현재 경로에는 포함되지 않는다. 운영 서버는 `NETGUARD_NVD_CACHE_DIR` 환경변수를 우선 확인한다. 일반적인 Rocky 경로는 `/opt/netguard/data/nvd_cache`이다.

## 인터넷 PC에서 다운로드

기존 `download_nvd.py`는 연간 API 조회 실패 시 기존 파일을 비우거나 불완전한 결과를 저장할 수 있으므로 전체 갱신에는 사용하지 않는다. 아래 신규 도구를 사용한다. Python 표준 라이브러리만 필요하며 별도 pip 설치가 없다.

Windows PowerShell:

```powershell
Set-Location E:\SNMP\SNMP_Codex
python scripts\download_nvd_feeds.py --years 2024 2025 2026 `
  --cache-dir E:\SNMP\SNMP_Codex\data\nvd_cache `
  --bundle E:\SNMP\NetGuard-NVD-2024-2026-20261107.zip
```

Rocky/Linux의 인터넷 가능한 별도 동기화 서버:

```bash
cd /opt/netguard
./venv/bin/python scripts/download_nvd_feeds.py --years 2024 2025 2026 \
  --cache-dir /opt/netguard/data/nvd_cache \
  --bundle /tmp/NetGuard-NVD-2024-2026-20261107.zip
```

- 공식 `.meta`의 압축 크기, 원본 크기, 원본 SHA256과 JSON 건수를 검사한다. 손상·네트워크 실패·빈 피드를 정상 업데이트로 처리하지 않는다.
- 모든 선택 연도의 다운로드/검증이 끝난 다음 반영한다. 기존 파일은 `.backups/실행시각/`에 복사하고 각 파일을 원자적으로 교체한다. 전체 디렉터리 단위 트랜잭션은 아니므로 운영 서버 반입 중에는 서비스를 중지한다.
- 동일 해시의 정상 파일은 재다운로드하지 않는다. API 키나 로그인 토큰을 요구하지 않는다.
- `.nvd-feed-update.lock`이 있으면 동시 실행을 거부한다. 비정상 강제 종료 후 남은 잠금은 기존 업데이트 프로세스가 없음을 확인한 뒤 제거한다.
- `cache_meta.json`의 `last_updated`는 선택한 공식 피드 중 최신 원본 시각, `downloaded_at`은 다운로드 완료 시각이다. 다운로드 당일과 원본 갱신일은 다를 수 있다.
- 네트워크 허용 대상은 `nvd.nist.gov`, TCP 443이다. 고정 IP 대신 FQDN 정책을 사용하며 폐쇄망 운영 서버가 아니라 동기화 PC에만 허용한다.

## 2026-11-07 준비 결과

| CVE ID 연도 | 원본 CVE 수 | 공식 피드 갱신 시각 (한국시간) |
|---|---:|---|
| 2024 | 39,367 | 2026-11-06 17:01:37 |
| 2025 | 45,473 | 2026-11-06 17:01:08 |
| 2026 | 85,687 | 2026-11-06 17:00:22 |
| 합계 | 170,527 | |

검색 엔진은 취소(Rejected) 항목을 제외하고 CVE ID를 중복 제거하므로 화면의 로컬 NVD 건수는 원본 건수보다 작을 수 있다. `등록 자산 연관` 범위는 이 중 등록 제품명과 연결된 영향 후보만 표시한다.

개발 PC의 실제 `CVEChecker` 검증 결과: 원본 170,527건 로딩, 검색 카탈로그 166,549건, 피드 3개, 로딩 오류 0건. 원본 피드의 SHA256 및 크기를 검증했다. 반입 ZIP은 약 90.7 MiB이며 SHA256은 다음과 같다.

```text
3467442B5A1E719273BDD9ACC3D57FFE073ED91BA390B6C251602943D6C07D46
```

같은 ZIP 경로에 나중에 재다운로드한 결과를 덮어쓴 경우 해시와 건수가 달라질 수 있으므로 다시 계산한다.

## Rocky Linux 반입

ZIP에는 `data/nvd_cache/` 아래 피드 3개, META 3개, `cache_meta.json`만 들어 있다. 소스코드·장비·사용자 DB·설정·API 키는 포함하지 않는다. 운영 서버를 직접 갱신한 것이 아니므로 아래 반입 단계가 필요하다.

1. ZIP을 승인된 반입 절차로 `/tmp/NetGuard-NVD-2024-2026-20261107.zip`에 전달한다. 전달 전후 `Get-FileHash -Algorithm SHA256` / `sha256sum`으로 ZIP 해시를 비교한다.
2. 실제 캐시 경로를 확인한다. 아래 명령은 기본 경로일 때 사용한다.

```bash
sudo systemctl show netguard -p Environment
sudo systemctl stop netguard
sudo tar -czf /opt/netguard/nvd-cache-before-20261107-$(date +%H%M%S).tar.gz -C /opt/netguard/data nvd_cache
sudo /opt/netguard/venv/bin/python -m zipfile -t /tmp/NetGuard-NVD-2024-2026-20261107.zip
sudo /opt/netguard/venv/bin/python -m zipfile -e /tmp/NetGuard-NVD-2024-2026-20261107.zip /opt/netguard
sudo chown netguard:netguard /opt/netguard/data/nvd_cache/nvdcve-2024.json /opt/netguard/data/nvd_cache/nvdcve-2025.json /opt/netguard/data/nvd_cache/nvdcve-2026.json /opt/netguard/data/nvd_cache/cache_meta.json
sudo systemctl start netguard
sudo systemctl status netguard --no-pager -l
sudo journalctl -u netguard --since '10 minutes ago' --no-pager | grep -Ei 'Loaded .* CVE|Failed to load|NVD cache|error'
```

각 단계에 오류가 있으면 다음 단계로 진행하지 않는다. 이전 데이터 백업은 `nvd_cache` 밖에 보관해야 피드로 중복 로딩되지 않는다. 이전에 다른 파일명(`nvdcve-2.0-2024.json`, `.json.gz` 등)으로 동일 연도 피드를 설치한 경우 새 피드 검증 후 해당 이전 파일만 별도 백업 디렉터리로 옮긴다. 다른 연도 피드나 운영 DB는 삭제하지 않는다.

## Windows 반입

관리자 PowerShell에서 서비스명과 설치 경로를 실제 환경에 맞춘다. 아래 ZIP을 검사/해제하기 위한 Python 경로도 설치된 경로를 사용한다.

```powershell
$root = 'E:\SNMP\SNMP_Codex'
$bundle = 'E:\SNMP\NetGuard-NVD-2024-2026-20261107.zip'
$backup = Join-Path $root ('data\nvd-backup-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
Stop-Service NetGuard -ErrorAction Stop
Copy-Item -LiteralPath "$root\data\nvd_cache" -Destination $backup -Recurse -ErrorAction Stop
& "$root\venv\Scripts\python.exe" -m zipfile -t $bundle
if ($LASTEXITCODE -ne 0) { throw 'ZIP integrity check failed' }
Expand-Archive -LiteralPath $bundle -DestinationPath $root -Force -ErrorAction Stop
Start-Service NetGuard -ErrorAction Stop
Get-Service NetGuard
Get-Content "$root\logs\netguard.log" -Tail 150 | Select-String 'Loaded .* CVE|Failed to load|NVD cache|error'
```

이번 개발 PC 다운로드는 위 서비스 명령을 실행하지 않았다. 서비스로 운영 중인 실제 Windows 서버에서만 적용한다.

## 화면 확인 및 이후 갱신

보안 > 취약점에서 새로고침 후 `로컬 NVD 전체` 범위로 전환한다. 상단 원본 갱신일과 카탈로그 건수를 확인하고 실제 CVE ID로 검색한다. 파일 변경은 다음 검색 요청에서 자동 감지한다. 최초 대용량 적재 시 메모리와 시간이 필요하다. 샘플 미리보기(`127.0.0.1:8769`)는 별도 가상 데이터를 사용하므로 이번 데이터 반입 여부 확인 용도가 아니다.

정기 갱신은 인터넷 PC에서 같은 다운로드 명령을 다시 실행한 뒤 검증된 ZIP을 반입한다. 연도별 피드는 일 단위로 갱신되므로 일 1회 정도 확인하면 된다. 장기간 업데이트가 중단된 캐시에 `--hours 2` 증분만 적용하면 공백 기간을 복구하지 못한다. 이 경우 전체 연도 피드를 다시 받아야 한다. 기존 API 증분/키 발급 내용은 [CVE_NVD_UPDATE_GUIDE.md](CVE_NVD_UPDATE_GUIDE.md)를 참고하되 전체 갱신과 증분 작업을 동시에 실행하지 않는다.

## 변경 파일

- `scripts/download_nvd_feeds.py`: 공식 연도별 피드 다운로드, 검증, 기존 파일 백업, 오프라인 ZIP.
- `tests/test_nvd_feeds.py`: 검증 실패/후속 연도 실패 시 기존 데이터 보존, 동일 피드 재실행, 잠금, ZIP 등 5개 테스트.
- `docs/GUIDE.md`, `docs/CVE_NVD_UPDATE_GUIDE.md`, 이 문서: 적용 방법과 실제 갱신 내역.

NVD 원본과 반입 ZIP은 대용량 런타임 데이터이므로 Git에 올리지 않는다. 도구·테스트·문서만 Git으로 관리한다.
