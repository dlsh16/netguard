# NetGuard CVE/NVD 데이터 운영 가이드

> 대상: NetGuard 운영자 / 보안 담당자  
> 작성 기준: 2026-05-18  
> 적용 환경: 오프라인 운영 서버 + 인터넷 가능한 별도 동기화 PC

---

## 1. 문서 목적

이 문서는 NetGuard의 CVE/CWE 기능에 필요한 NVD 데이터를 준비하고 유지하는 전체 절차를 설명한다.

운영 흐름은 다음과 같다.

1. NVD API 인증키 발급
2. 인터넷 가능한 PC에서 최초 전체 데이터 다운로드
3. 오프라인 NetGuard 서버로 파일 반입
4. 서비스 재시작 및 로딩 확인
5. 이후 증분 업데이트 또는 정기 반입

---

## 2. 운영 방식

### 2.1 완전 오프라인 운영 서버

- 운영 서버는 외부 인터넷에 직접 연결하지 않는다.
- 인터넷 가능한 별도 PC에서 NVD 데이터를 내려받아 USB 또는 내부 파일 서버로 반입한다.
- 운영 서버에는 `nvdcve-*.json`과 `cache_meta.json`만 복사한다.

### 2.2 인터넷 연결 가능한 동기화 PC

- 최초 1회 전체 데이터를 내려받는다.
- 이후에는 최근 변경분만 증분 반영한다.
- Rocky Linux는 `systemd timer`, Windows는 작업 스케줄러로 자동화할 수 있다.

---

## 3. NVD API 인증키 발급

### 3.1 발급 절차

1. 인터넷 가능한 PC에서 NVD API Key Request 페이지에 접속한다.  
   `https://nvd.nist.gov/developers/request-an-api-key`
2. 아래 3개 항목을 입력한다.
   - Organization Name
   - Email Address
   - Organization Type
3. 약관을 끝까지 확인한 뒤 `I agree to the Terms of Use`에 체크한다.
4. 제출 후 입력한 이메일로 도착한 활성화 메일을 확인한다.
5. 메일 안의 1회용 링크를 열어 API Key를 활성화하고 즉시 안전한 위치에 저장한다.

### 3.2 주의 사항

- 활성화 링크는 7일 안에 사용해야 한다.
- 같은 이메일 주소로 새 키를 발급하고 활성화하면 기존 키는 무효화된다.
- 잊어버린 키를 다시 조회하는 절차는 제공되지 않으므로, 발급 즉시 안전한 비밀 저장소에 보관한다.
- API Key는 다른 사람이나 다른 조직과 공유하지 않는다.

### 3.3 저장 권장 방식

Rocky Linux:

```bash
sudo mkdir -p /etc/netguard
sudo tee /etc/netguard/nvd-update.env >/dev/null <<'EOF'
NVD_API_KEY=발급받은_NVD_API_KEY
EOF
sudo chmod 600 /etc/netguard/nvd-update.env
```

Windows PowerShell:

```powershell
$env:NVD_API_KEY = '발급받은_NVD_API_KEY'
```

장기 보관이 필요하면 Windows 작업 스케줄러용 별도 스크립트나 안전한 자격 증명 저장소를 사용한다.

---

## 4. 최초 전체 데이터 다운로드

### 4.1 Rocky Linux / Linux 계열

```bash
cd /opt/netguard
source venv/bin/activate
export NVD_API_KEY='발급받은_NVD_API_KEY'

python scripts/download_nvd.py --years 2024 2025 2026
```

### 4.2 Windows

```powershell
cd C:\NetGuard_temp
$env:NVD_API_KEY = '발급받은_NVD_API_KEY'

python scripts\download_nvd.py --years 2024 2025 2026
```

### 4.3 생성 파일

```text
data/nvd_cache/nvdcve-2024.json
data/nvd_cache/nvdcve-2025.json
data/nvd_cache/nvdcve-2026.json
data/nvd_cache/cache_meta.json
```

`cache_meta.json`의 `last_updated` 값은 CVE/CWE 화면의 `NVD 데이터베이스 마지막 업데이트` 표시에 사용된다.

---

## 5. 오프라인 운영 서버 반입

### 5.1 Rocky Linux 서버

```bash
# 인터넷 가능 PC에서 파일 전송
rsync -avz data/nvd_cache/ admin@10.60.8.187:/opt/netguard/data/nvd_cache/

# 운영 서버에서 권한 보정
sudo chown -R netguard:netguard /opt/netguard/data/nvd_cache/
```

USB 반입 시:

```bash
sudo cp -r /media/usb/nvd_cache/* /opt/netguard/data/nvd_cache/
sudo chown -R netguard:netguard /opt/netguard/data/nvd_cache/
```

### 5.2 Windows 서버

```powershell
xcopy /E /I "C:\NetGuard_temp\data\nvd_cache\*" `
           "C:\SNMP\Claude\data\nvd_cache\"
```

---

## 6. 서비스 재시작 및 반영 확인

### 6.1 Rocky Linux

```bash
sudo systemctl restart netguard

sudo journalctl -u netguard -n 120 --no-pager | egrep -i "Loaded .* CVE|No NVD cache|Failed to load"

curl -s http://localhost:8000/api/security/cves | python3 -m json.tool | head -30
```

정상 예시:

```text
Loaded 123456 CVE entries from local NVD cache
```

### 6.2 Windows

```powershell
Restart-Service NetGuard
Start-Sleep 10

Invoke-RestMethod http://localhost:8000/api/security/cves | ConvertTo-Json -Depth 3
```

---

## 7. 이후 업데이트 방법

### 7.1 완전 오프라인 운영

1. 인터넷 가능한 PC에서 새 파일을 생성한다.
2. 변경된 `nvdcve-*.json`과 `cache_meta.json`을 운영 서버로 복사한다.
3. NetGuard 서비스를 재시작한다.

### 7.2 수동 증분 업데이트

Rocky Linux / Linux 계열:

```bash
cd /opt/netguard
source venv/bin/activate
export NVD_API_KEY='발급받은_NVD_API_KEY'

python scripts/update_nvd_cache.py --hours 2
```

Windows:

```powershell
cd C:\NetGuard_temp
$env:NVD_API_KEY = '발급받은_NVD_API_KEY'

python scripts\update_nvd_cache.py --hours 2
```

### 7.3 Rocky Linux 자동 업데이트

```bash
sudo mkdir -p /etc/netguard
sudo tee /etc/netguard/nvd-update.env >/dev/null <<'EOF'
NVD_API_KEY=발급받은_NVD_API_KEY
EOF
sudo chmod 600 /etc/netguard/nvd-update.env

sudo cp deploy/systemd/netguard-nvd-update.service /etc/systemd/system/
sudo cp deploy/systemd/netguard-nvd-update.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now netguard-nvd-update.timer

systemctl list-timers netguard-nvd-update.timer
```

### 7.4 Windows 자동 업데이트

```powershell
schtasks /Create /TN "NetGuard-NVD-Update" /SC HOURLY /MO 2 `
  /TR "powershell.exe -NoProfile -Command `"cd C:\NetGuard_temp; `$env:NVD_API_KEY='발급받은_NVD_API_KEY'; python scripts\update_nvd_cache.py --hours 2`"" `
  /F
```

> 운영 서버가 인터넷 차단 환경이면 자동 업데이트는 운영 서버가 아니라 인터넷 가능한 별도 동기화 PC에만 구성한다.

---

## 8. 권장 업데이트 주기

- 최초 데이터는 전체 다운로드로 채운다.
- 이후 자동 증분 업데이트는 2시간 간격 이상으로 운용한다.
- API 요청이 여러 페이지로 이어질 때는 요청 사이에 6초 대기를 둔다.
- NetGuard의 `update_nvd_cache.py`는 최근 변경분만 반영하도록 설계되어 있다.

---

## 9. 화면에서 확인할 항목

### 9.1 CVE/CWE 메뉴

- `NVD 데이터베이스 마지막 업데이트`
- Critical / High / Medium / Low 건수
- CVE 목록과 영향 장비 분포

### 9.2 확인 기준

- `last_updated` 날짜가 최근 반입 또는 동기화 일자와 일치해야 한다.
- CVE 건수가 `0`으로만 표시되면 캐시 파일 로딩 로그를 먼저 확인한다.

---

## 10. 자주 발생하는 문제

### 10.1 파일이 있는데도 CVE가 0건

로그 예시:

```text
Unexpected UTF-8 BOM (decode using utf-8-sig)
Loaded 0 CVE entries from local NVD cache
```

조치:

- 최신 NetGuard는 `utf-8-sig`로 BOM 포함 파일도 읽는다.
- 운영 서버 소스가 최신인지 확인하고 서비스를 재시작한다.

### 10.2 `NVD 데이터베이스 마지막 업데이트: --`

확인:

```bash
cat /opt/netguard/data/nvd_cache/cache_meta.json
ls -lh /opt/netguard/data/nvd_cache/
```

조치:

- `cache_meta.json`이 있으면 그 안의 `last_updated`가 표시된다.
- 메타 파일이 없어도 `nvdcve-*.json` 파일이 정상 로드되면 가장 최근 파일 수정 시각을 대신 표시한다.

### 10.3 API Key 오류 또는 호출 제한

조치:

- `NVD_API_KEY` 값이 올바른지 확인한다.
- 동일 이메일로 새 키를 활성화한 적이 있다면 기존 키는 더 이상 유효하지 않을 수 있다.
- 자동화는 너무 자주 돌리지 말고 2시간 간격 이상으로 운용한다.

---

## 11. 점검 체크리스트

| 점검 항목 | 확인 |
|----------|------|
| API Key 발급 및 안전 보관 | [ ] |
| 최초 전체 다운로드 완료 | [ ] |
| `nvdcve-*.json` 생성 확인 | [ ] |
| `cache_meta.json` 생성 확인 | [ ] |
| 오프라인 서버 반입 완료 | [ ] |
| 서비스 재시작 완료 | [ ] |
| CVE 로딩 로그 확인 | [ ] |
| 화면의 마지막 업데이트 일자 확인 | [ ] |
| 자동 업데이트 또는 정기 반입 절차 확정 | [ ] |

---

## 12. 공식 참고 문서

- NVD API Key Request
- NVD Developers - Start Here
- NVD API User Workflows
- NVD Vulnerability APIs
- NVD API Transition Guide

