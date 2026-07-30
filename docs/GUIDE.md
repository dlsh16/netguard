# NetGuard SNMP 통합 모니터링 대시보드 - 설치 및 운영 가이드

> 버전: 1.2.52 | 최종 업데이트: 2026-07-30

---

## 플랫폼별 상세 설치 메뉴얼

| 플랫폼 | 메뉴얼 |
|--------|--------|
| **Windows** Server 2019/2022, Windows 10/11 | [INSTALL_WINDOWS.md](INSTALL_WINDOWS.md) |
| **Rocky Linux** 8.x / 9.x | [INSTALL_ROCKY.md](INSTALL_ROCKY.md) |
| **CVE/NVD 운영** | [CVE_NVD_UPDATE_GUIDE.md](CVE_NVD_UPDATE_GUIDE.md) |
| **점검/취약점 에이전트** | [SECURITY_CHECK_AGENT_USAGE.md](SECURITY_CHECK_AGENT_USAGE.md) |

> 아래 내용은 공통 개요입니다. 실제 설치는 위 플랫폼별 메뉴얼을 따르세요.

---

## 목차
1. [시스템 개요](#1-시스템-개요)
2. [아키텍처 및 기술 스택](#2-아키텍처-및-기술-스택)
3. [DB 선택 이유 (TimescaleDB)](#3-db-선택-이유)
4. [설치 요구사항](#4-설치-요구사항)
5. [Rocky Linux 설치 (요약)](#5-rocky-linux-설치)
6. [Windows 설치 (요약)](#6-windows-설치)
7. [초기 설정](#7-초기-설정)
8. [장비 등록 (SNMP)](#8-장비-등록)
9. [CVE 취약점 DB 오프라인 사용](#9-cve-취약점-db-오프라인-사용)
10. [라즈베리파이 센서 연동](#10-라즈베리파이-센서-연동)
11. [알림 설정 (이메일/카카오톡)](#11-알림-설정)
12. [대시보드 사용법](#12-대시보드-사용법)
13. [업데이트 내역](#13-업데이트-내역)
14. [문제 해결](#14-문제-해결)

---

## 1. 시스템 개요

NetGuard는 Zabbix/Grafana를 단일 대시보드로 통합한 SNMP 기반 인프라 모니터링 플랫폼입니다.

### 모니터링 대상
| 장비 유형 | 수집 항목 |
|----------|----------|
| 서버 | CPU, Memory, Disk, Network, 프로세스 |
| 스위치 | 포트 상태, 트래픽(In/Out), 에러, VLAN |
| 항온항습기 | 온도, 습도 (SNMP/라즈베리파이) |
| UPS | 배터리 잔량, 부하율, 입출력 전압, 백업 시간 |
| 라즈베리파이 | 전산실 온도/습도 (DHT22/BME280 센서) |

### 알림 채널
- **이메일**: SMTP를 통한 HTML 형식 알림 (내부 메일 서버 지원)
- **카카오톡**: KakaoTalk REST API (오프라인 환경에서 비활성화 가능)

### 보안 기능
- CVE/CWE/CVSS 취약점 모니터링 (오프라인 NVD 캐시 기반)
- 영향받는 장비 자동 매핑
- 서버 점검/취약점 스크립트 결과 저장 및 원본 파일 보관
- 이상탐지: Z-score 기반 급증 탐지, 알려진 공격 패턴 탐지

---

## 2. 아키텍처 및 기술 스택

```
┌─────────────────────────────────────────────────────────┐
│                     브라우저 (Dashboard UI)               │
│              HTML5 + CSS3 + JavaScript + Chart.js        │
└───────────────────────┬─────────────────────────────────┘
                        │ HTTP / WebSocket
┌───────────────────────▼─────────────────────────────────┐
│                  FastAPI Backend (Python)                 │
│  ┌─────────────┐ ┌─────────────┐ ┌───────────────────┐  │
│  │SNMP Collector│ │Alert Manager│ │   CVE Checker     │  │
│  │(pysnmp)     │ │(Email/Kakao)│ │(NVD 로컬 캐시)    │  │
│  └──────┬──────┘ └─────────────┘ └───────────────────┘  │
└─────────┼───────────────────────────────────────────────┘
          │ asyncpg
┌─────────▼───────────────────────────────────────────────┐
│              TimescaleDB (PostgreSQL + 확장)              │
│  metrics (hypertable) | devices | events | thresholds    │
│  vulnerabilities | device_vulnerabilities                │
└─────────────────────────────────────────────────────────┘

[수집 대상]
서버(SNMP) ──┐
스위치(SNMP)─┤──▶ SNMP Collector ──▶ TimescaleDB
UPS(SNMP) ───┤
항온항습(SNMP)┘
라즈베리파이 (HTTP REST) ──▶ EnvCollector
```

---

## 3. DB 선택 이유

### TimescaleDB 선택 이유

| 비교 항목 | TimescaleDB | InfluxDB | PostgreSQL 단독 |
|----------|------------|---------|----------------|
| 시계열 최적화 | ✅ 매우 우수 | ✅ 매우 우수 | ❌ 기본 |
| SQL 호환 | ✅ 완전 호환 | ❌ InfluxQL | ✅ |
| Rocky Linux 지원 | ✅ | ✅ | ✅ |
| Windows 지원 | ✅ | ✅ | ✅ |
| 오프라인 설치 | ✅ RPM/EXE | ✅ | ✅ |
| 자동 압축 | ✅ 7일 후 | ✅ | ❌ |
| 데이터 보존 정책 | ✅ 자동 | ✅ 자동 | ❌ 수동 |
| 관계형 데이터 | ✅ JOIN 지원 | ❌ | ✅ |
| 라이선스 | Apache 2.0 | MIT | PostgreSQL |

**결론**: TimescaleDB는 PostgreSQL의 완전한 SQL 인터페이스를 유지하면서 시계열 데이터 압축·보존 자동화를 제공합니다. SNMP 수집 데이터(시계열) + 장비 정보(관계형)를 하나의 DB로 처리할 수 있습니다.

---

## 4. 설치 요구사항

### 최소 사양
| 항목 | 최소 | 권장 |
|------|------|------|
| CPU | 2코어 | 4코어 |
| RAM | 4GB | 8GB |
| Disk | 50GB | 200GB (SSD) |
| OS | Rocky Linux 8/9, Windows Server 2019+ | Rocky Linux 9 |
| Python | 3.10+ | 3.12 |
| PostgreSQL | 14+ | 18 |
| TimescaleDB | 2.10+ | 2.27 |

### 네트워크
- 모니터링 서버 → 장비: UDP/161 (SNMP), UDP/162 (SNMP Trap)
- 브라우저 → 서버: TCP/8000 (대시보드)
- 라즈베리파이 → 서버: TCP/8765 (센서 API)

---

## 5. Rocky Linux 설치

> 상세 설치와 장애 조치 절차는 [INSTALL_ROCKY.md](INSTALL_ROCKY.md)를 기준으로 합니다.
> 현재 자동 설치 스크립트는 PostgreSQL 18, TimescaleDB for PG18, systemd `workers=1`,
> `/opt/netguard/logs`, `/opt/netguard/data/nvd_cache` 운영 경로를 사용합니다.

### 5.1 TimescaleDB 설치

```bash
# PostgreSQL 18 설치
sudo dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-9-x86_64/pgdg-redhat-repo-latest.noarch.rpm
sudo dnf -qy module disable postgresql
sudo dnf install -y postgresql18-server postgresql18 postgresql18-contrib

# DB 초기화
sudo /usr/pgsql-18/bin/postgresql-18-setup initdb
sudo systemctl enable --now postgresql-18

# TimescaleDB RPM 오프라인 설치
# (인터넷 환경에서 RPM 다운로드 후 복사)
sudo dnf localinstall timescaledb-2-postgresql-18-*.rpm

# TimescaleDB 설정
sudo timescaledb-tune --quiet --yes --pg-config=/usr/pgsql-18/bin/pg_config
sudo systemctl restart postgresql-18
```

### 5.2 Python 환경

```bash
# Python 3.12+ 또는 3.13
sudo dnf install -y python3 python3-pip gcc

# 가상환경 생성
cd /opt/netguard
python3 -m venv venv
source venv/bin/activate

# 의존성 설치 (오프라인: pip download로 미리 받은 패키지 사용)
pip install -r requirements.txt
```

### 5.3 오프라인 pip 설치

```bash
# 인터넷 환경 (별도 PC):
pip download -r requirements.txt -d packages/

# 오프라인 환경:
pip install --no-index --find-links packages/ -r requirements.txt
```

### 5.4 서비스 등록 (systemd)

```bash
sudo tee /etc/systemd/system/netguard.service <<EOF
[Unit]
Description=NetGuard SNMP Dashboard
After=postgresql-18.service network.target
Requires=postgresql-18.service

[Service]
Type=exec
User=netguard
WorkingDirectory=/opt/netguard/backend
Environment=PYTHONPATH=/opt/netguard/backend
Environment=PYTHONUNBUFFERED=1
Environment=NETGUARD_LOG_DIR=/opt/netguard/logs
Environment=NETGUARD_NVD_CACHE_DIR=/opt/netguard/data/nvd_cache
ExecStart=/opt/netguard/venv/bin/uvicorn app:app \
    --host 0.0.0.0 --port 8000 --workers 1
Restart=on-failure
RestartSec=5
ProtectSystem=strict
ReadWritePaths=/opt/netguard/logs /opt/netguard/data /opt/netguard/config
MemoryMax=2G

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now netguard
```

### 5.5 방화벽 설정

```bash
sudo firewall-cmd --permanent --add-port=8000/tcp
sudo firewall-cmd --permanent --add-port=161/udp    # SNMP (수신용)
sudo firewall-cmd --permanent --add-port=162/udp    # SNMP Trap
sudo firewall-cmd --reload
```

---

## 6. Windows 설치

### 6.1 TimescaleDB on Windows

```powershell
# 1. PostgreSQL 15 Windows 설치 프로그램 실행
#    다운로드: https://www.postgresql.org/download/windows/
#    (오프라인: 설치 파일 복사 후 실행)

# 2. TimescaleDB Windows 확장 설치
#    다운로드: https://docs.timescale.com/install/latest/self-hosted/installation-windows/
#    설치 후 postgresql.conf 수정:
#    shared_preload_libraries = 'timescaledb'

# 3. PostgreSQL 재시작
Restart-Service postgresql-x64-15
```

### 6.2 Python 환경 (Windows)

```powershell
# Python 3.11 설치 (오프라인: python-3.11.x-amd64.exe 복사 후 실행)

# 프로젝트 디렉토리
cd C:\SNMP\Claude

# 가상환경
python -m venv venv
.\venv\Scripts\Activate.ps1

# 의존성 설치
pip install -r requirements.txt
```

### 6.3 Windows 서비스 등록 (NSSM 사용)

```powershell
# NSSM 다운로드 후 설치
nssm install NetGuard "C:\SNMP\Claude\venv\Scripts\python.exe"
nssm set NetGuard AppParameters "-m uvicorn app:app --host 0.0.0.0 --port 8000"
nssm set NetGuard AppDirectory "C:\SNMP\Claude\backend"
nssm set NetGuard Start SERVICE_AUTO_START
nssm start NetGuard
```

---

## 7. 초기 설정

### 7.1 config.yaml 수정

```yaml
# C:\SNMP\Claude\config\config.yaml

db_host: localhost
db_password: "강력한패스워드로변경"    # 반드시 변경!

smtp_host: mail.company.local
alert_emails:
  - admin@company.local

# SNMP 기본 커뮤니티 스트링
snmp_community: public
```

### 7.2 DB 초기화

```bash
# Rocky Linux
cd /opt/netguard
sudo -u netguard bash -c "
    source venv/bin/activate
    export PYTHONPATH=/opt/netguard/backend
    export NETGUARD_DB_PASSWORD='강력한패스워드로변경'
    python - <<'PY'
import asyncio
from database import init_db, close_db_pool

async def main():
    await init_db()
    await close_db_pool()

asyncio.run(main())
PY
"

# Windows
cd C:\SNMP\Claude
.\venv\Scripts\Activate.ps1
python scripts\setup_db.py
```

### 7.3 서버 시작

```bash
# Rocky Linux
./scripts/start.sh

# Windows
scripts\start.bat

# 또는 직접 실행
cd backend
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

### 7.4 대시보드 접속

브라우저에서 `http://서버IP:8000` 접속

---

## 8. 장비 등록

### 8.1 대시보드에서 등록

`장비 관리` → `+ 장비 추가` → IP, SNMP 버전, Community 입력

### 8.2 API로 일괄 등록

```bash
curl -X POST http://localhost:8000/api/devices \
  -H "Content-Type: application/json" \
  -d '{
    "name": "SRV-WEB-01",
    "type": "server",
    "ip_address": "192.168.1.10",
    "snmp_version": "v2c",
    "community": "public",
    "os_version": "Rocky Linux 9.3"
  }'
```

### 8.3 SNMP 설정 (장비 측)

#### Linux 서버 (net-snmp)
```bash
sudo dnf install -y net-snmp net-snmp-utils

sudo tee /etc/snmp/snmpd.conf <<EOF
# 접근 허용 (모니터링 서버 IP로 변경)
rocommunity public 192.168.1.0/24
syslocation "서버실 A랙 3번"
syscontact admin@company.local

# 확장 MIB (CPU, Memory 상세)
extend .1.3.6.1.4.1.2021.13.15.1.1.3 cpu /bin/cat /proc/stat
EOF

sudo systemctl enable --now snmpd
sudo firewall-cmd --permanent --add-port=161/udp
sudo firewall-cmd --reload
```

디스크/파티션과 프로세스 상세 표시에는 Host Resources MIB가 필요합니다. 모니터링 서버에서 아래 값이 조회되어야 서버 상세보기의 디스크 표와 실행 중인 프로세스 표가 표시됩니다.

```bash
# Windows 서버 메모리도 hrStorage의 "Physical Memory" 항목을 사용합니다.
snmpwalk -v2c -c public <대상IP> .1.3.6.1.2.1.25.2.3.1.3

# 파티션/디스크 용량: hrStorage
snmpwalk -v2c -c public <대상IP> .1.3.6.1.2.1.25.2.3.1.3
snmpwalk -v2c -c public <대상IP> .1.3.6.1.2.1.25.2.3.1.5

# 실행 중인 프로세스: hrSWRun / hrSWRunPerf
snmpwalk -v2c -c public <대상IP> .1.3.6.1.2.1.25.4.2.1.2
snmpwalk -v2c -c public <대상IP> .1.3.6.1.2.1.25.5.1.1.2
```

#### Windows 서버
```
1. 제어판 → 프로그램 및 기능 → Windows 기능 → SNMP 서비스 설치
2. 서비스 → SNMP Service → 속성 → 보안 탭
3. Community: public (읽기 전용)
4. 허용 호스트: 모니터링 서버 IP 추가
```

#### Cisco 스위치
```
conf t
snmp-server community public RO
snmp-server host 10.60.8.187 public
```

---

## 9. CVE 취약점 DB 오프라인 사용

### 9.1 오프라인 반입용 NVD 파일 생성

```bash
# 인터넷이 되는 PC에서 실행
export NVD_API_KEY='발급받은_NVD_API_KEY'
python scripts/download_nvd.py --years 2024 2025 2026

# 생성 파일
# data/nvd_cache/nvdcve-2024.json
# data/nvd_cache/nvdcve-2025.json
# data/nvd_cache/nvdcve-2026.json
# data/nvd_cache/cache_meta.json
```

### 9.2 오프라인 서버로 복사

```bash
# USB 또는 내부 파일 서버를 통해 복사
scp -r data/nvd_cache/ admin@10.60.8.187:/opt/netguard/data/

# 또는 Windows
xcopy /E data\nvd_cache C:\SNMP\Claude\data\nvd_cache\
```

### 9.3 실시간 업데이트 구성 (인터넷 연결 가능 환경)

```bash
# 최초 1회 전체 다운로드 후, 최근 변경분만 반영
export NVD_API_KEY='발급받은_NVD_API_KEY'
python scripts/update_nvd_cache.py --hours 2

# Rocky Linux systemd timer 설치
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

- 오프라인 운영 서버는 위 timer를 직접 사용하지 않고, 인터넷 가능한 별도 PC에서 `download_nvd.py` 또는 `update_nvd_cache.py`를 실행한 뒤 생성 파일을 반입한다.
- `cache_meta.json`의 `last_updated` 값이 CVE/CWE 화면의 `NVD 데이터베이스 마지막 업데이트`에 표시된다. 메타 파일이 없으면 가장 최근 피드 파일의 수정 시각을 대신 표시한다.

### 9.4 취약점-장비 매핑 원리

CVE 체커는 장비의 `os_version` 필드와 NVD CVE 설명 키워드를 매칭합니다.

| OS 설정 | 매칭 키워드 |
|---------|-----------|
| `Rocky Linux 9.3` | linux, rhel, centos, rocky, glibc, kernel, openssl |
| `Windows Server 2022` | windows, microsoft, iis, smb, rdp, ntlm |
| `IOS XE 17.9` | cisco, ios, catalyst, iosxe |
| `HP ProCurve 2530` | hp, procurve, hpe |

---

## 10. 라즈베리파이 센서 연동

### 10.1 라즈베리파이 설정

```python
# 라즈베리파이에서 실행할 센서 서버 (rpi_sensor.py)
# DHT22 또는 BME280 센서 사용

from flask import Flask, jsonify
import Adafruit_DHT  # pip install Adafruit_DHT

app = Flask(__name__)
SENSOR = Adafruit_DHT.DHT22
PIN = 4  # GPIO 핀 번호

@app.route('/sensor')
def sensor():
    humidity, temperature = Adafruit_DHT.read_retry(SENSOR, PIN)
    return jsonify({
        'temperature': round(temperature, 1),
        'humidity': round(humidity, 1)
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8765)
```

### 10.2 config.yaml 설정

```yaml
rpi_enabled: true
rpi_ip: 192.168.1.60
rpi_port: 8765
```

---

## 11. 알림 설정

### 11.1 이메일 (내부 SMTP)

```yaml
# config.yaml
smtp_host: mail.company.local
smtp_port: 25              # 내부 릴레이는 보통 25
smtp_from: noreply@company.local
alert_emails:
  - admin@company.local
  - ops@company.local
```

### 11.2 카카오톡 설정

1. [Kakao Developers](https://developers.kakao.com) → 앱 생성
2. 카카오 채널 연결 및 채널 토큰 발급
3. config.yaml 수정:

```yaml
kakao_enabled: true
kakao_rest_key: "발급받은REST API KEY"
kakao_channel_token: "채널토큰"
```

> **오프라인 환경**: `kakao_enabled: false` 유지. 이메일만 사용.

### 11.3 알림 레벨 기준

| 심각도 | 조건 | 알림 |
|--------|------|------|
| CRITICAL | CPU≥95%, MEM≥90%, 장비 오프라인, 포트 다운 | 즉시 이메일+카카오톡 |
| WARNING | CPU≥80%, MEM≥75%, 디스크≥80%, 온도≥27°C | 즉시 이메일 |
| INFO | 상태 복구, 정기 리포트 | 이메일 |

---

## 12. 대시보드 사용법

### 화면 구성

```
┌─────────┬────────────────────────────────────────┐
│ 사이드바 │ 상단바 (타이틀 | 갱신 시간 | 알림벨)     │
│         ├────────────────────────────────────────┤
│ 전체    │ 알림 배너 (활성 경보 요약)               │
│ 대시보드 ├────────────────────────────────────────┤
│ 서버    │                                         │
│ 스위치  │         페이지 콘텐츠                    │
│ 항온항습 │                                        │
│ 프로세스 │                                        │
│─────────│                                        │
│ CVE     │                                        │
│ 이벤트  │                                        │
│─────────│                                        │
│ 임계값  │                                        │
│ 알림    │                                        │
│ 장비관리 │                                       │
└─────────┴────────────────────────────────────────┘
```

### 주요 화면별 기능

| 화면 | 주요 기능 |
|------|----------|
| 전체 대시보드 | 장비 상태 그리드, CPU/네트워크 차트, 최근 이벤트 |
| 서버 모니터링 | CPU/MEM/Disk 바 차트, 클릭 시 상세(디스크/파티션 용량, 프로세스 목록) |
| 스위치 모니터링 | 포트맵 시각화, 포트별 트래픽/에러 테이블 |
| 항온항습/UPS | 반원형 게이지, 24시간 추이 차트 |
| CVE 취약점 | CVSS 분포 차트, 장비별 취약점 목록, 패치 상태 |
| 이벤트 로그 | 심각도/날짜 필터, 확인/해결 처리 |
| 임계값 설정 | 슬라이더로 경고/위험 값 조정, 이상탐지 기준 설정 |

---

## 13. 업데이트 내역

### v1.2.52 (2026-07-30) - SMTP STARTTLS 설정 분리

#### 현장 확인 결과
- `mail.hlcompany.com:25`는 `220` SMTP 배너와 `250-STARTTLS` EHLO 응답을 정상 반환한다.
- `mail.hlcompany.com:587`, `mail.hlcompany.com:465`는 NetGuard 서버에서 타임아웃이다.
- 따라서 현재 환경의 기본 설정은 25번 내부 릴레이 방식이다.

#### 변경 사항
- `backend/config.py`: `SMTP_STARTTLS` 기본값 추가
- `backend/api/routes.py`: 알림 설정 조회/저장 API에 `smtp_starttls` 추가
- `backend/api/routes.py`: 테스트 메일 발송 시 `smtp_starttls=true`이면 계정 유무와 별개로 STARTTLS 수행
- `backend/alerts/alert_manager.py`: 실제 이벤트 메일 발송에도 동일한 STARTTLS 분리 로직 적용
- `frontend/index.html`, `frontend/js/dashboard.js`: 알림 설정 화면에 `STARTTLS 사용` 체크박스 추가
- `config/config.example.yaml`: `smtp_starttls: false` 예시 추가

#### 현장 권장 설정

현재 확인된 Exchange 25번 릴레이 환경에서는 우선 아래처럼 설정한다.

```text
SMTP 서버: mail.hlcompany.com
포트: 25
계정: 비움
비밀번호: 비움
STARTTLS 사용: 해제
발신 이메일: 메일 서버 릴레이 정책에 허용된 주소
```

위 설정에서 릴레이 거부가 나오면 메일 서버에서 NetGuard 서버 IP `10.60.8.186`과 발신 주소를 릴레이 허용해야 한다.

### v1.2.51 (2026-07-30) - Git 자동 커밋 변경 파일 목록 기록

#### 변경 사항
- `scripts/watch_git_auto_update.ps1`: 자동 커밋 제목에 변경 파일 개수를 포함하도록 수정
- `scripts/watch_git_auto_update.ps1`: 자동 커밋 본문에 변경 파일 목록을 최대 20개까지 기록하고, 초과 파일 수를 별도 표시
- `scripts/watch_git_auto_update.ps1`: 자동 갱신 로그에도 커밋 대상 파일 목록을 남기도록 개선
- `docs/GIT_WORKFLOW.md`: 태그명은 짧은 버전명으로 유지하고, 변경 파일 상세는 커밋 본문에 남기는 운영 기준 추가

#### 자동 커밋 예시

```text
Auto update 2026-07-30 09:20:15 (3 files)

Changed files:

- backend/api/routes.py
- frontend/js/dashboard.js
- docs/GUIDE.md

Total changed files: 3
```

### v1.2.50 (2026-07-30) - SMTP 포트별 연결 방식 및 타임아웃 보강

#### 현장 확인 결과
- `mail.hlcompany.com`은 `10.21.14.20`으로 DNS 해석된다.
- `25/tcp`는 TCP 연결이 된다.
- `587/tcp`, `465/tcp`는 타임아웃이다.

#### 판단
- NetGuard 알림 설정은 우선 `SMTP 서버=mail.hlcompany.com`, `포트=25`로 설정해야 한다.
- 587/465는 현재 NetGuard 서버에서 접근할 수 없으므로 사용하지 않는다.
- 25번 연결은 열려 있지만 SMTP 배너/EHLO 응답이 정상인지 별도 확인이 필요하다.
- 내부 릴레이 방식이면 SMTP 계정/비밀번호는 비워두고, 메일 서버에서 NetGuard 서버 IP의 릴레이 허용이 필요하다.

#### 변경 사항
- `backend/config.py`: `SMTP_TIMEOUT` 기본값 30초 추가
- `backend/api/routes.py`, `backend/alerts/alert_manager.py`: SMTP 연결 타임아웃을 설정값으로 사용
- `backend/api/routes.py`, `backend/alerts/alert_manager.py`: 465번 포트 사용 시 `SMTP_SSL` 방식으로 연결
- `config/config.example.yaml`: `smtp_timeout: 30` 예시 추가

#### 추가 확인 명령

25번 포트에서 SMTP 배너와 EHLO 응답을 확인한다.

```bash
printf 'EHLO netguard-srv\r\nQUIT\r\n' | nc -v -w 15 mail.hlcompany.com 25
```

정상 예시는 `220`, `250` 응답이 보여야 한다. 아무 응답 없이 타임아웃이면 메일 서버가 NetGuard 서버 IP에 SMTP 응답을 주지 않는 상태이므로 메일 서버 릴레이/방화벽 정책을 확인한다.

Python SMTP 직접 테스트:

```bash
sudo -u netguard /opt/netguard/venv/bin/python - <<'PY'
import smtplib
host = "mail.hlcompany.com"
port = 25
with smtplib.SMTP(host, port, timeout=30) as smtp:
    print(smtp.noop())
PY
```

NetGuard 알림 설정 권장값:

```text
SMTP 서버: mail.hlcompany.com
포트: 25
계정: 비움
비밀번호: 비움
발신 이메일: 메일 서버 릴레이 정책에 허용된 주소
```

### v1.2.49 (2026-07-29) - SMTP 서버 응답 타임아웃 진단 보강

#### 확인된 로그
- `POST /api/alert-config/test-email` 요청은 NetGuard 서버까지 정상 도착했다.
- 알림 설정 저장도 `POST /api/alert-config HTTP/1.1" 200 OK`로 정상 처리되었다.
- 테스트 메일 단계에서 `SMTP test email failed: Connection unexpectedly closed: timed out`가 발생했다.

#### 판단
- `Name or service not known` 단계와 달리, 이번 증상은 SMTP 서버명 해석 이후의 문제다.
- SMTP 서버가 지정 포트에서 SMTP 배너/EHLO 응답을 주지 않거나, 방화벽/릴레이 정책/TLS 방식/포트 설정이 맞지 않는 상태로 판단한다.

#### 변경 사항
- `backend/api/routes.py`: `SMTPServerDisconnected` 예외를 별도 분류해 SMTP 포트, TLS/STARTTLS, 릴레이 허용 정책을 점검하도록 메시지 개선
- `backend/alerts/alert_manager.py`: 실제 이벤트 메일 발송 실패 로그에도 같은 분류 적용

#### 현장 확인 명령

```bash
getent hosts mail.hlcompany.com
nc -vz mail.hlcompany.com 25
nc -vz mail.hlcompany.com 587
nc -vz mail.hlcompany.com 465
```

포트별 SMTP 응답 확인:

```bash
timeout 10 bash -c 'cat < /dev/tcp/mail.hlcompany.com/25'
openssl s_client -starttls smtp -connect mail.hlcompany.com:587 -crlf
openssl s_client -connect mail.hlcompany.com:465 -crlf
```

운영 기준:
- 내부 릴레이 25번 포트를 사용하는 경우 SMTP 계정/비밀번호를 비워두고, 메일 서버에서 NetGuard 서버 IP의 릴레이를 허용해야 한다.
- 587번 포트를 사용하는 경우 STARTTLS와 계정 인증이 필요할 수 있다.
- 465번 포트는 SMTPS 방식이므로 현재 NetGuard 기본 SMTP 테스트 방식과 다를 수 있다.

### v1.2.48 (2026-07-29) - Git 자동 갱신 감시 구성

#### 변경 사항
- `scripts/watch_git_auto_update.ps1`: 파일 변경을 감지해 안전한 소스/문서 변경분을 자동 `git add`, `commit`, `push`하는 감시 스크립트 추가
- `scripts/install_git_auto_update_task.ps1`, `.bat`: Windows 작업 스케줄러에 `NetGuardGitAutoUpdate` 작업을 등록하고 로그인 시 자동 실행되도록 구성
- `scripts/uninstall_git_auto_update_task.ps1`, `.bat`: 자동 갱신 작업 제거 스크립트 추가
- `scripts/start_git_auto_update.bat`: 콘솔에서 감시 스크립트를 직접 실행하는 배치 파일 추가
- `docs/GIT_WORKFLOW.md`: 자동 갱신 감시 실행, 작업 스케줄러 등록/해제, 로그 확인 절차 추가

#### 보호 기준
- 자동 커밋 대상에서 `config/config.yaml`, `agent/*_config.json`, `logs/`, `data/`, `backend/data/`, `__pycache__/`, 점검 결과물, 압축 파일, 로컬 DB 파일은 제외한다.
- 자동 갱신 로그는 `logs/git_auto_update.log`에 남기며 Git에는 커밋하지 않는다.

#### 실행 방법

```powershell
cd E:\SNMP\SNMP_Codex
.\scripts\install_git_auto_update_task.bat
```

상태 확인:

```powershell
Get-ScheduledTask -TaskName NetGuardGitAutoUpdate
Get-Content E:\SNMP\SNMP_Codex\logs\git_auto_update.log -Tail 50
```

### v1.2.47 (2026-07-29) - Git 형상 관리 구성

#### 변경 사항
- `.gitignore`: 로그, 캐시, `__pycache__`, 가상환경, 로컬 DB, NVD JSON, 운영 설정 파일, Agent 로컬 설정 파일, 점검 결과물, 생성 압축 파일을 Git 추적 대상에서 제외
- `.gitattributes`: Windows Agent 스크립트(`*.ps1`, `*.bat`)는 CRLF, Python/JS/CSS/HTML/문서/배포 파일은 LF 기준으로 줄바꿈 정책 정의
- `config/config.example.yaml`: 운영 비밀번호와 토큰을 제외한 샘플 설정 파일 추가
- `docs/GIT_WORKFLOW.md`: 초기화, 커밋, 태그, 배포용 소스 압축, 운영 데이터 별도 이관 기준 문서화

#### 운영 기준
- `config/config.yaml`, `agent/agent_config.json`, `data/nvd_cache/*.json`은 Git에 커밋하지 않는다.
- 기능 수정 후에는 GUIDE 문서까지 함께 갱신하고 커밋한다.
- 오프라인 운영 환경에서는 `git archive`로 소스만 압축하고, NVD 캐시와 운영 설정은 별도 매체로 이관한다.

### v1.2.46 (2026-07-29) - SMTP 테스트 메일 DNS 오류 메시지 개선

#### 장애 증상
- 알림 설정에서 테스트 메일 발송 시 `SMTP test email failed: [Errno -2] Name or service not known` 오류가 표시된다.
- 이는 SMTP 인증 또는 수신자 문제가 아니라, NetGuard 서버에서 SMTP 호스트명을 IP로 변환하지 못하는 DNS 이름 해석 실패다.

#### 변경 사항
- `backend/api/routes.py`: `/api/alert-config/test-email` 실패 시 DNS 실패, 접속 실패, 인증 실패, 발신/수신 거부를 구분해 반환하도록 보강
- `backend/alerts/alert_manager.py`: 실제 이벤트 메일 발송 실패 로그도 동일하게 원인별 메시지로 기록
- 운영자가 `journalctl -u netguard`만 보고 DNS, 방화벽, 인증 중 어느 계층 문제인지 구분할 수 있게 개선

#### 현장 조치

SMTP 서버가 `mail.hlcompany.com`인 경우 NetGuard 서버에서 먼저 이름 해석을 확인한다.

```bash
getent hosts mail.hlcompany.com
nslookup mail.hlcompany.com
```

폐쇄망이라 DNS가 없으면 `/etc/hosts`에 SMTP 서버 IP를 등록한다.

```bash
sudo vi /etc/hosts
```

예시:

```text
10.60.8.xxx mail.hlcompany.com
```

또는 알림 설정의 SMTP 서버 값을 도메인 대신 실제 IP 주소로 입력한다.

포트 확인:

```bash
nc -vz mail.hlcompany.com 25
nc -vz mail.hlcompany.com 587
```

설정 반영 후 NetGuard를 재시작하고 테스트 메일을 다시 발송한다.

```bash
sudo systemctl restart netguard
sudo journalctl -u netguard -n 100 --no-pager | egrep -i "smtp|email|mail|failed|error"
```

### v1.2.45 (2026-07-29) - Windows Agent 작업 스케줄러 등록 실패 보정

#### 장애 증상
- Windows Agent 설치 중 `Register-ScheduledTask : 매개 변수가 틀립니다.`가 출력된 뒤에도 `[OK] Task Scheduler registered`가 표시될 수 있었다.
- 실제로는 `NetGuardAgent` 작업이 생성되지 않아 `Start-ScheduledTask : 지정된 파일을 찾을 수 없습니다.`가 이어지고, Agent 로그/메트릭 전송이 시작되지 않았다.

#### 변경 사항
- `agent/install.ps1`: `Register-ScheduledTask`에 `-ErrorAction Stop`을 적용해 스케줄러 등록 실패를 정상 성공으로 표시하지 않도록 수정
- `agent/install.ps1`: PowerShell ScheduledTasks 모듈 등록이 실패하면 `schtasks.exe /Create /RU SYSTEM /RL HIGHEST` 방식으로 자동 우회 등록
- `agent/install.ps1`: 작업 시작도 `Start-ScheduledTask` 실패 시 `schtasks.exe /Run`으로 자동 우회
- `agent/start_agent_background.ps1`: 설치 후 백그라운드 기동 확인 시 동일한 스케줄러 등록/시작 우회 로직 적용
- `agent/restart_agent.ps1`: `restart_agent.bat` 실행 시에도 동일한 스케줄러 등록/시작 우회 로직 적용
- `agent/install.ps1`: 설치 배너를 `NetGuard Agent Windows Install 2026-07-29-scheduler-fallback`로 변경

#### 현장 재설치 절차

관리자 권한 PowerShell 또는 `install.bat` 실행 전 기존 실패 작업을 정리한다.

```powershell
schtasks /Delete /TN NetGuardAgent /F 2>$null
sc.exe delete NetGuardAgent
```

최신 `agent` 폴더의 아래 파일을 설치 PC의 실행 폴더에 함께 둔 뒤 `install.bat`를 실행한다.

```text
install.bat
install.ps1
netguard_agent.ps1
restart_agent.ps1
restart_agent.bat
start_agent_background.ps1
start_agent_background.bat
```

설치 후 확인 명령:

```powershell
schtasks /Query /TN NetGuardAgent /V /FO LIST
Get-Content "C:\NetGuard-Agent\agent.log" -Tail 30
Test-NetConnection 10.60.8.186 -Port 8000
```

#### 검증 기준
- `install.ps1`: 283줄, SHA256 `80321F436176903D7C342E5E6DF92F1858CFAFBD4C7913D8197394B3D5880765`
- `start_agent_background.ps1`: 215줄, SHA256 `E2BA0534E81AD3224A1119EEB5482DBA4C4454244CAFE65EE24169C9BA4071EB`
- `restart_agent.ps1`: 230줄, SHA256 `35766F0F192D4D718B5E0838AD2A515259733851EF52378060F64BFDA94FC312`
- PowerShell 파서 문법 검사 대상 4개 파일(`install.ps1`, `start_agent_background.ps1`, `restart_agent.ps1`, `netguard_agent.ps1`) 모두 정상

### v1.2.44 (2026-07-29) - Windows Agent 설치 스크립트 안전 버전 재작성

#### 변경 사항
- `agent/install.ps1`: 파일 전체를 ASCII 기반 안전 버전으로 재작성하여 전송/인코딩 중 따옴표가 깨져도 영향을 받을 수 있는 한글/깨진 문자열 제거
- `agent/install.ps1`: 설치 시작 시 `NetGuard Agent Windows Install 2026-07-29-safe` 버전 배너 출력
- `agent/install.ps1`: PowerShell Agent를 우선 사용하고, PowerShell Agent가 없을 때만 Python Agent를 사용하도록 정리
- `agent/install.bat`: `install.ps1` 실행 전 PowerShell 파서 문법 검사를 수행하도록 보강
- `agent/install.bat`: 문법 오류가 있으면 설치를 진행하지 않고 오류 위치를 먼저 표시

#### 검증 기준
- 최신 `install.ps1`은 204줄이며 SHA256은 `CF150E03F3E47A36274544AD8E5E97A4124BF5C8778AA2DC93B3A8C55BD80D37`이다.
- 현장에서 다시 `install.ps1:239` 오류가 나오면 최신 파일이 아니라 이전 파일을 실행 중인 것이다.

#### 운영 확인 명령

```powershell
(Get-Content ".\install.ps1" | Measure-Object -Line).Lines
Get-FileHash ".\install.ps1" -Algorithm SHA256
Get-Content ".\install.ps1" -TotalCount 3
```

정상 첫 줄:

```text
# NetGuard Agent - Windows Install Script
# Version: 2026-07-29-safe
```

### v1.2.43 (2026-07-29) - Windows Agent 설치 스크립트 종료 대기 구문 보정

#### 변경 사항
- `agent/install.ps1`: 일부 Windows PowerShell 환경에서 마지막 `Read-Host "Press Enter to exit"` 줄이 전송/인코딩 문제로 파싱 오류를 일으킬 수 있어 제거
- `agent/install.ps1`: 설치 완료 후 안내 메시지만 출력하고, 창 유지와 종료 대기는 `install.bat`의 `pause`가 담당하도록 정리

#### 운영 참고
- 오류 예: `install.ps1:239 char:31`, `The string is missing the terminator: "`
- 운영 장비에는 최신 `agent/install.ps1`와 `agent/install.bat`를 같은 폴더에 복사한 뒤 `install.bat`를 다시 실행한다.
- PowerShell에서 직접 실행하는 경우 아래 명령으로 사전 문법 검사를 수행할 수 있다.

```powershell
$errors=$null
[System.Management.Automation.PSParser]::Tokenize((Get-Content -Raw ".\install.ps1"), [ref]$errors) | Out-Null
$errors
```

### v1.2.42 (2026-07-07) - NetGuard 서비스 계정의 config.yaml 저장 허용

#### 변경 사항
- `scripts/install_rocky.sh`: `/opt/netguard/config` 디렉토리 권한을 `netguard` 계정이 접근 가능하도록 설정
- `scripts/install_rocky.sh`: systemd `ReadWritePaths`에 `/opt/netguard/config`를 추가해 `ProtectSystem=strict` 환경에서도 `config.yaml` 저장 허용
- `docs/INSTALL_ROCKY.md`, `docs/GUIDE.md`: Rocky Linux 설치 및 systemd 서비스 예시에 `/opt/netguard/config` 쓰기 허용 경로 추가

#### 운영 반영

기존 운영 서버는 아래 명령으로 즉시 반영한다.

```bash
sudo chown -R netguard:netguard /opt/netguard/config
sudo chmod 750 /opt/netguard/config
sudo chmod 640 /opt/netguard/config/config.yaml

sudo systemctl edit netguard
```

편집기에 아래 내용을 입력한다.

```ini
[Service]
ReadWritePaths=
ReadWritePaths=/opt/netguard/logs /opt/netguard/data /opt/netguard/config
```

적용:

```bash
sudo systemctl daemon-reload
sudo systemctl restart netguard
sudo systemctl show netguard -p ReadWritePaths
```

### v1.2.41 (2026-07-07) - 알림 설정 저장 500 오류 원인 표시 및 런타임 반영

#### 변경 사항
- `backend/api/routes.py`: `/api/alert-config` 저장 중 예외가 발생하면 상세 원인을 `detail`로 반환하도록 보강
- `backend/api/routes.py`: `config.yaml` 권한 문제로 파일 저장이 실패해도 런타임 설정은 먼저 반영하여 테스트 메일 발송을 계속 진행할 수 있도록 개선
- `frontend/js/dashboard.js`: 설정은 반영됐지만 파일 저장이 실패한 경우 권한 확인 안내 토스트 표시
- `frontend/index.html`: `dashboard.js` 캐시 버전을 `20260707-1`로 갱신

#### 운영 참고
- `POST /api/alert-config: 500`이 발생하면 `journalctl -u netguard`에서 `Alert config update failed` 또는 `Alert config file save permission failed` 로그를 확인한다.
- 운영 서버에서 `/opt/netguard/config/config.yaml`이 `root` 소유이면 NetGuard 서비스 계정이 저장하지 못할 수 있다.
- 권한 문제 조치 예:

```bash
sudo chown netguard:netguard /opt/netguard/config/config.yaml
sudo chmod 640 /opt/netguard/config/config.yaml
sudo systemctl restart netguard
```

### v1.2.40 (2026-06-23) - 테스트 메일 버튼 무반응 보정

#### 변경 사항
- `frontend/index.html`: `dashboard.js` 캐시 버전을 `20260623-1`로 갱신해 브라우저가 기존 더미 `testEmail()` 함수를 계속 사용하는 문제 방지
- `frontend/js/dashboard.js`: 테스트 메일 클릭 즉시 `테스트 이메일 발송 요청 중...` 토스트를 표시하도록 보강
- `frontend/js/dashboard.js`: inline `onclick`에서 알림 설정 함수가 확실히 호출되도록 `window.saveAlertConfig`, `window.testEmail`, `window.testKakao` 명시 등록
- `frontend/js/dashboard.js`: 관리자 권한이 아닌 경우 테스트/저장 함수에서 권한 필요 메시지를 표시하도록 보강

#### 운영 참고
- 운영 반영 후 브라우저에서 강력 새로고침 또는 캐시 삭제가 필요할 수 있다.
- 테스트 메일 버튼 클릭 시 즉시 토스트가 보이지 않으면 이전 JS 캐시가 로드된 상태일 가능성이 높다.

### v1.2.39 (2026-06-23) - 알림 설정 저장 로직 실제 반영

#### 변경 사항
- `frontend/index.html`: 알림 설정 입력 필드에 SMTP/Kakao 설정용 고정 ID 추가
- `frontend/js/dashboard.js`: 알림 설정 페이지 진입 시 `/api/alert-config`에서 현재 설정을 조회하도록 연결
- `frontend/js/dashboard.js`: 기존 토스트만 표시하던 `saveAlertConfig()`를 실제 `/api/alert-config` 저장 API 호출로 변경
- `frontend/js/dashboard.js`: 테스트 메일 버튼이 저장 후 `/api/alert-config/test-email`을 호출하도록 변경
- `backend/api/routes.py`: 알림 설정 조회, 저장, SMTP 테스트 메일 발송 API 추가
- `backend/api/routes.py`: 알림 설정 저장 시 `config/config.yaml` 파일과 실행 중인 `config.settings` 객체를 함께 갱신해 서비스 재시작 없이 다음 알림부터 반영되도록 보강

#### 운영 참고
- 기존 문제는 화면에서 `알림 설정 저장`을 눌러도 실제 API 호출 없이 토스트만 표시되어 시스템 설정에 반영되지 않던 구조였다.
- 운영 서버 반영 후 `sudo systemctl restart netguard`를 1회 수행하면 신규 API/프론트 코드가 로드된다.
- 이후 알림 설정 화면에서 저장하면 `config.yaml`과 런타임 설정이 같이 갱신된다.

### v1.2.38 (2026-06-19) - Agent 서버 주소 오타 보정

#### 변경 사항
- `agent/netguard_agent.ps1`, `agent/netguard_agent.py`: 기본 `server_url`을 `http://10.60.8.186:8000`으로 보정
- `agent/install.ps1`, `agent/agent_config.json`: 신규 설치 기본 서버 주소를 `http://10.60.8.186:8000`으로 보정
- Agent 설치/운영 문서의 통신 테스트 예시를 `10.60.8.186:8000` 기준으로 정리

#### 운영 참고
- `agent.log`에 `Server : http://10.6.8.186:8000`으로 표시되고 `GetRequestStream ... 작업 시간이 초과되었습니다`가 반복되면 서버 주소 오타다.
- 운영 장비의 `C:\NetGuard-Agent\agent_config.json`에서 `server_url`을 `http://10.60.8.186:8000`으로 변경한 뒤 Agent를 재기동한다.

### v1.2.37 (2026-06-19) - PowerShell Agent JSON 응답 처리 오류 수정

#### 변경 사항
- `agent/netguard_agent.ps1`: `Send-Json` 함수의 요청 본문 변수 `$Body`와 응답 본문 변수 `$body`가 PowerShell에서 같은 변수로 처리되어 정상 서버 응답을 오류로 오인하던 문제 수정
- `agent/netguard_agent.ps1`: 요청 본문은 `$Payload`, 응답 본문은 `$responseText`로 분리하고 JSON 변환 실패 시 원문 응답을 반환하도록 보강
- `docs/AGENT_RESTART_GUIDE.md`: `"System.String" 유형의 ... 값을 "System.Collections.Hashtable" 유형으로 변환할 수 없습니다` 오류 조치 절차 추가

#### 운영 참고
- 서버 응답이 `{"status":"ok","device_id":...}`로 정상이어도 Agent 로그에 변환 오류가 반복되면 최신 `netguard_agent.ps1`를 `C:\NetGuard-Agent`에 복사 후 재기동한다.
- 재기동 후 `agent.log`에 `OK cpu=... mem=... disk=...` 로그가 다시 남으면 정상이다.

### v1.2.36 (2026-06-19) - Windows Agent 재기동 런처 누락 대응

#### 변경 사항
- `agent/restart_agent.ps1`: `C:\NetGuard-Agent\start_agent_background.ps1` 파일이 없어도 자체 내장 로직으로 서비스/예약 작업을 재기동하도록 보강
- `agent/restart_agent.ps1`: 런처 누락 시 경고만 표시하고, 예약 작업 재생성 및 `agent.log` 갱신 확인을 계속 수행
- `docs/AGENT_RESTART_GUIDE.md`: `Background launcher not found` 메시지 발생 시 조치 절차 추가

#### 운영 참고
- 즉시 조치는 최신 `start_agent_background.ps1`, `start_agent_background.bat`, `restart_agent.ps1`, `restart_agent.bat`를 `C:\NetGuard-Agent`에 복사하는 것이다.
- 최신 `restart_agent.ps1`는 런처 파일이 누락되어도 Agent 재기동을 계속 수행한다.

### v1.2.35 (2026-06-19) - Windows/Linux Agent 기본 서버 주소 변경 (v1.2.38에서 오타 보정)

#### 변경 사항
- `agent/netguard_agent.ps1`, `agent/netguard_agent.py`: Agent 내장 기본 `server_url` 변경 작업 수행
- `agent/install.ps1`, `agent/agent_config.json`: 설치 프롬프트와 기본 설정 파일의 서버 주소 변경 작업 수행
- `docs/agent_install_windows.md`, `docs/agent_install_linux.md`, `docs/SECURITY_CHECK_AGENT_USAGE.md`, `docs/AGENT_RESTART_GUIDE.md`: Agent 설치/운영 예시 주소와 통신 테스트 명령을 신규 기본 주소로 정리

#### 운영 참고
- 이 버전의 `10.6.8.186` 주소는 오타였으며, v1.2.38에서 `http://10.60.8.186:8000`으로 보정했다.
- 신규 설치는 `install.ps1`의 기본값이 신규 주소로 표시된다.

### v1.2.34 (2026-06-19) - Windows Agent 재기동 후 로그 전송 중단 방지

#### 변경 사항
- `agent/start_agent_background.ps1`: 기존 예약 작업을 최신 실행 설정으로 재생성할 수 있도록 `-Restart`, `-ForceTaskRecreate` 옵션 추가
- `agent/start_agent_background.ps1`: 서비스/예약 작업 시작 후 최대 75초 동안 `agent.log` 갱신 여부를 확인하도록 보강
- `agent/start_agent_background.ps1`: 예약 작업이 이미 실행 중이면 중복 시작하지 않고 상태 확인만 수행하도록 수정
- `agent/restart_agent.ps1`: 서비스가 없고 예약 작업 방식인 경우 기존 작업을 재생성한 뒤 시작하도록 변경
- `agent/install.bat`, `agent/restart_agent.bat`: 중복 백그라운드 호출을 제거하고 PowerShell 스크립트의 검증 흐름을 따르도록 단순화
- `docs/AGENT_RESTART_GUIDE.md`: Agent 재기동 및 백그라운드 기동 절차를 정상 한글 문서로 재작성

#### 운영 참고
- 운영 Windows Agent 장비에는 `start_agent_background.ps1`, `restart_agent.ps1`, `install.bat`, `restart_agent.bat`를 `C:\NetGuard-Agent`에 갱신한다.
- 이후 `C:\NetGuard-Agent\restart_agent.bat`를 실행하면 재기동 후 로그 갱신 여부까지 확인한다.
- 재기동 후 1분 이상 `agent.log`가 증가하지 않으면 `Test-NetConnection <NetGuard서버IP> -Port 8000`와 `agent_stderr.log`를 함께 확인한다.

### v1.2.33 (2026-06-19) - Agent 설치/재기동 후 백그라운드 자동 기동

#### 변경 사항
- `agent/install.bat`, `agent/install.ps1`: 설치 완료 후 `start_agent_background.ps1`을 자동 실행해 Agent 백그라운드 기동 상태를 보장
- `agent/restart_agent.bat`, `agent/restart_agent.ps1`: Agent 재기동 후 `start_agent_background.ps1`을 자동 실행해 콘솔 종료와 무관한 백그라운드 상태를 재확인
- `docs/AGENT_RESTART_GUIDE.md`: Agent 단독 재기동 및 백그라운드 기동 문서를 정상 한글로 재작성
- `docs/agent_install_windows.md`: 설치/재기동 후 백그라운드 자동 기동 안내 추가

#### 운영 참고
- 운영자는 `install.bat` 또는 `restart_agent.bat`만 실행해도 백그라운드 기동 확인까지 자동 처리된다.
- 수동 콘솔 실행은 테스트용이며, 운영 기동은 서비스/작업 스케줄러 백그라운드 방식을 사용한다.

### v1.2.32 (2026-06-19) - Windows Agent 백그라운드 기동 보강

#### 변경 사항
- `agent/start_agent_background.ps1`, `agent/start_agent_background.bat`: 콘솔 창을 닫아도 Agent가 종료되지 않도록 서비스/작업 스케줄러 백그라운드 기동 스크립트 추가
- `agent/install.ps1`: Windows Agent 설치 시 백그라운드 시작 스크립트를 함께 복사하고 PowerShell Agent 실행을 숨김/비대화형 모드로 보강
- `scripts/apply_update.ps1`: Agent 재기동/백그라운드 기동 스크립트가 업데이트 배포에 포함되도록 복사 대상 추가
- `docs/AGENT_RESTART_GUIDE.md`, `docs/agent_install_windows.md`: `netguard_agent.ps1/.py` 직접 실행 시 콘솔 종료와 함께 Agent도 종료되는 점을 명시하고 백그라운드 기동 명령 추가

#### 운영 참고
- Windows 운영 환경에서는 `C:\NetGuard-Agent\start_agent_background.ps1`로 Agent를 기동한다.
- `netguard_agent.ps1` 또는 `netguard_agent.py` 직접 실행은 테스트용으로만 사용한다.

### v1.2.31 (2026-06-19) - Agent 단독 재기동 절차 추가

#### 변경 사항
- `agent/restart_agent.ps1`, `agent/restart_agent.bat`: Windows Agent만 재시작하는 운영 스크립트 추가
- `agent/restart_agent.sh`: Rocky/Linux Agent만 재시작하고 상태/로그를 확인하는 운영 스크립트 추가
- `agent/install.ps1`: Windows 설치 시 재기동 스크립트를 `C:\NetGuard-Agent`로 함께 복사하도록 변경
- `docs/AGENT_RESTART_GUIDE.md`: Windows/Rocky Linux Agent 단독 재기동 절차 신규 문서 추가
- `docs/agent_install_windows.md`, `docs/agent_install_linux.md`: Agent 단독 재기동 명령어 추가

#### 운영 참고
- Agent 다운 시 NetGuard 서버 서비스 재시작은 필요하지 않다.
- Windows는 `C:\NetGuard-Agent\restart_agent.ps1`, Rocky/Linux는 `/opt/netguard-agent/restart_agent.sh`를 사용한다.
- 기존 설치본은 스크립트 파일만 대상 서버의 Agent 설치 경로에 복사한 뒤 실행하면 된다.

### v1.2.30 (2026-06-16) - 대시보드 한글 표시 및 스위치 포트 오류 알림 제외

#### 변경 사항
- `frontend/index.html`, `frontend/js/dashboard.js`: 상단 서버/스위치/항온항습기/UPS/CVE 카드, 최근 이벤트, 알림 패널, 주요 메뉴의 한글 깨짐 문구 수정
- `frontend/js/dashboard.js`: 네트워크 트래픽 그래프 범례에서 장비명 뒤 `수신`/`송신` 문구를 제거하고 장비명만 표시
- `backend/alerts/alert_manager.py`: 알림 메시지 한글 깨짐을 정상화하고 스위치 포트 오류 카운트 급증 알림 생성을 중단
- `backend/app.py`, `backend/api/routes.py`: 스위치 포트 오류 이벤트를 신규 저장/조회/대시보드 카운트에서 제외
- `frontend/index.html`: 프론트엔드 캐시 버전을 `20260616-1`로 갱신

#### 운영 참고
- 기존 DB에 남아 있는 `포트 ... 에러 급증 (in:... out:...)` 이벤트는 화면 조회와 카운트에서 제외된다.
- 스위치 포트 다운/복구 감지는 유지되며, 오류 카운트 기반 알림만 제외된다.

### v1.2.29 (2026-06-15) - 장비관리 한글/버튼 정렬 및 네트워크 범례 보정

#### 변경 사항
- `frontend/js/dashboard.js`: 장비관리 목록의 수정/삭제/조회 전용 문구와 저장/삭제 알림 메시지 한글 깨짐 수정
- `frontend/js/dashboard.js`: 네트워크 트래픽 범례에서 장비명 뒤에 깨져 보이던 수신/송신 지표명을 정상 한글로 표시
- `frontend/css/style.css`: 장비관리 상태 표시와 액션 버튼이 줄바꿈/밀림 없이 한 줄로 정렬되도록 보정
- `frontend/index.html`: 프론트엔드 캐시 버전을 `20260615-2`로 갱신

#### 운영 참고
- 웹 브라우저에서 기존 화면이 계속 보이면 `Ctrl + F5`로 강력 새로고침 후 확인한다.

### v1.2.28 (2026-06-15) - 대시보드/스위치 모니터링 표시 정책 보정

#### 변경 사항
- `frontend/js/dashboard.js`: 스위치 모니터링 포트맵/포트 테이블에서 오류 카운트 취합 표시와 오류 초기화 버튼을 제거
- `frontend/js/dashboard.js`: 스위치 포트 테이블은 Alias 정보를 유지해 포트 식별 정보를 중심으로 표시
- `frontend/js/dashboard.js`, `frontend/css/style.css`: 대시보드 `장비 상태 현황`을 `Switch`, `Server`, `Utility` 그룹으로 분류 표시
- `frontend/js/dashboard.js`: 운영자(`operator`)는 장비관리 메뉴를 숨기고 `devices` 페이지 직접 접근 시 대시보드로 이동
- `frontend/index.html`: 프론트엔드 캐시 버전을 `20260615-1`로 갱신

#### 운영 참고
- Utility 그룹에는 UPS, 항온항습기, 라즈베리파이/환경 센서 장비가 포함된다.
- 장비 등록/수정/삭제는 관리자 권한에서만 접근 가능하다.

### v1.2.27 (2026-06-10) - 항온항습기 0518 정상 수집 로직 병합

#### 변경 사항
- `backend/collectors/snmp_collector_0529.py`: SNMP v3, 스위치 `ifName/ifAlias`, NULL 응답 처리 등 0529 개선사항은 유지
- `backend/collectors/snmp_collector_0529.py`: 항온항습기 수집 순서를 0518 정상 파일 기준으로 보정
  - 사용자 지정 OID가 유효하면 우선 사용
  - 기존 Cisco 예시 OID 확인
  - ENTITY-SENSOR-MIB 확인
  - FLS LinkNet V3.0 / DDC400R-V2 private OID 확인
- `backend/collectors/snmp_collector_0529.py`: 0518 정상 파일에 있던 FLS 보조 습도 OID `.58.0` 복원
- `backend/collectors/snmp_collector.py`: 운영 import 경로(`collectors.snmp_collector`)에 맞춰 수정본을 배포용 파일명으로 생성

#### 항온항습기 수집 순서
```text
1. env_temp_oid / env_humidity_oid 사용자 지정 OID
2. 1.3.6.1.4.1.9.9.13.1.3.1.3.1, 1.3.6.1.4.1.9.9.13.1.3.1.4.1
3. ENTITY-SENSOR-MIB
4. FLS LinkNet private OID
   - 온도: 1.3.6.1.4.1.22210.2.1.54.0
   - 습도: 1.3.6.1.4.1.22210.2.1.53.0
   - 보조 습도: 1.3.6.1.4.1.22210.2.1.58.0
```

#### 운영 반영
```bash
cd /opt/netguard
sudo cp backend/collectors/snmp_collector.py /opt/netguard/backend/collectors/snmp_collector.py
sudo -u netguard /opt/netguard/venv/bin/python -m py_compile /opt/netguard/backend/collectors/snmp_collector.py
sudo systemctl restart netguard
```


### v1.2.26 (2026-05-29) - 장비 중복 이름 저장 복구

#### 변경 사항
- `backend/api/routes.py`: `POST /api/devices` 호출 시 같은 이름의 장비가 이미 있으면 신규 생성 실패 대신 기존 장비를 입력값으로 갱신하고 `enabled=TRUE`로 복구
- `frontend/js/dashboard.js`: 장비 추가 응답이 기존 장비 복구/갱신인 경우에도 목록에 중복으로 추가하지 않고 기존 항목을 갱신
- `frontend/index.html`: 프론트엔드 캐시 버전을 `20260529-7`로 갱신

#### 운영 참고
NetGuard의 장비 삭제는 실제 삭제가 아니라 `enabled=FALSE` 처리다. 따라서 같은 이름으로 다시 등록하면 `devices_name_key` 중복 오류가 날 수 있으며, 이번 보정 후에는 기존 장비가 복구된다.

기존 항온항습기 장비 확인:

```bash
sudo -u postgres psql -d netguard -c "
select id, name, type, ip_address, community, snmp_version, enabled
from devices
where name='항온항습기';
"
```

### v1.2.25 (2026-05-29) - 항온항습기 NULL OID 응답 fallback 보정

#### 변경 사항
- `backend/collectors/snmp_collector.py`: SNMP 응답값이 `NULL`, `No Such...`, `No More...`이면 유효 수집값으로 보지 않도록 공통 보정
- 사용자 지정 OID(`env_temp_oid`, `env_humidity_oid`)가 설정되어 있어도 해당 OID가 `NULL`이면 `0`으로 저장하지 않고 다음 fallback OID로 진행

#### 확인 결과
현장 장비 `10.60.8.134`는 SNMP 통신 자체는 정상이며, 기존 5월 25일 OID는 현재 `NULL`로 응답한다.

```text
SNMPv2-MIB::sysDescr.0 = STRING: FLS LinkNet V3.0
SNMPv2-SMI::enterprises.9.9.13.1.3.1.3.1 = NULL
SNMPv2-SMI::enterprises.9.9.13.1.3.1.4.1 = NULL
```

따라서 기존 OID가 `NULL`일 때는 FLS private OID(`.53.0`, `.54.0`)로 넘어가야 정상이다.

### v1.2.24 (2026-05-29) - 5월 25일 정상 수집 OID 우선순위 복원

#### 변경 사항
- `backend/collectors/snmp_collector.py`: 2026-05-25 정상 수집 파일 기준으로 항온항습기 기존 OID를 FLS private OID보다 먼저 시도하도록 순서 보정
- 기존 정상 수집 OID:
  - 온도: `1.3.6.1.4.1.9.9.13.1.3.1.3.1`, 수집값 `/ 10`
  - 습도: `1.3.6.1.4.1.9.9.13.1.3.1.4.1`, 수집값 그대로 사용
- 수집 순서: 사용자 지정 OID -> 5월 25일 기존 OID -> FLS DDC400R-V2 private OID -> ENTITY-SENSOR-MIB

#### 운영 참고
정상 수집 당시 파일에는 `1.3.6.1.4.1.22210...` OID가 없었다. 운영 서버에서 아래 명령으로 기존 OID 응답을 먼저 확인한다.

```bash
snmpget -v2c -c stanry 10.60.8.134 \
  1.3.6.1.2.1.1.1.0 \
  1.3.6.1.4.1.9.9.13.1.3.1.3.1 \
  1.3.6.1.4.1.9.9.13.1.3.1.4.1
```

기존 OID가 정상 응답하면 `/opt/netguard/config/config.yaml`의 `env_temp_oid`, `env_humidity_oid`는 빈 값으로 둔다.

### v1.2.23 (2026-05-29) - 항온항습기 private OID 생존 확인 보정

#### 변경 사항
- `backend/collectors/snmp_collector.py`: 항온항습기 타입(`env`, `rpi`, `environment`, `sensor`)은 표준 `sysDescr`가 응답하지 않아도 FLS DDC400R-V2 private OID가 응답하면 online으로 처리
- 확인 OID: 온도 `.54.0`, 습도 `.53.0`, 모델명 `.300.0`

#### 운영 참고
아래처럼 private OID는 응답하지만 NetGuard에서 오프라인으로 표시되면 표준 `sysDescr` 생존 확인 단계에서 차단된 상태일 수 있다.

```bash
snmpget -v2c -c stanry 10.60.8.134 \
  1.3.6.1.2.1.1.1.0 \
  1.3.6.1.4.1.22210.2.1.53.0 \
  1.3.6.1.4.1.22210.2.1.54.0 \
  1.3.6.1.4.1.22210.2.1.300.0
```

반영 후 재시작:

```bash
sudo -u netguard /opt/netguard/venv/bin/python -m py_compile /opt/netguard/backend/collectors/snmp_collector.py
sudo systemctl restart netguard
sudo journalctl -u netguard -n 80 --no-pager | egrep -i "항온|env|10.60.8.134|Failed to poll|SNMP"
```

### v1.2.22 (2026-05-29) - FLS LinkNet DDC400R-V2 항온항습기 OID 자동 수집

#### 변경 사항
- `backend/collectors/snmp_collector.py`: FLS LinkNet V3.0 / DDC400R-V2 항온항습기 사설 OID를 자동 fallback 수집 대상으로 추가
- 확인된 온도 OID `1.3.6.1.4.1.22210.2.1.54.0`은 원시값 `28917`을 `0.001` 배율로 계산해 `28.9°C`로 저장
- 확인된 습도 OID `1.3.6.1.4.1.22210.2.1.53.0`은 원시값 `44`를 `44%`로 저장

#### 운영 적용
Rocky Linux 운영 서버에서 코드 반영 후 서비스 재시작:

```bash
cd /opt/netguard
sudo cp backend/collectors/snmp_collector.py /opt/netguard/backend/collectors/snmp_collector.py
sudo -u netguard /opt/netguard/venv/bin/python -m py_compile /opt/netguard/backend/collectors/snmp_collector.py
sudo systemctl restart netguard
```

기존에 잘못 저장된 `0` 값 정리:

```bash
sudo -u postgres psql -d netguard -c "
delete from metrics
where metric_name in ('temp_c','humidity_pct')
  and value <= 0
  and device_id in (select id from devices where type in ('env','rpi','environment','sensor'));
"
```

수집 확인:

```bash
sudo -u postgres psql -d netguard -c "
select d.name, d.type, m.metric_name, m.value, m.time
from metrics m
join devices d on d.id = m.device_id
where d.type in ('env','rpi','environment','sensor')
order by m.time desc
limit 20;
"
```

장비에서 직접 OID 확인:

```bash
snmpget -v2c -c stanry 10.60.8.134 \
  1.3.6.1.4.1.22210.2.1.53.0 \
  1.3.6.1.4.1.22210.2.1.54.0
```

### v1.2.21 (2026-05-29) - 항온항습기 0값 저장 방지

#### 변경 사항
- `backend/app.py`: 항온항습기 온도/습도 값이 `0` 이하이면 유효 수집값으로 저장하지 않도록 보정
- 표준 OID가 실제 장비 OID와 맞지 않아 `0`이 반복 저장되는 경우 화면/알람에 잘못 반영되지 않도록 차단

#### 운영 참고
DB에 아래처럼 `temp_c=0`, `humidity_pct=0`만 반복 저장되면 수집 성공이 아니라 OID 불일치 상태다.

```sql
select d.name, d.type, m.metric_name, m.value, m.time
from metrics m
join devices d on d.id = m.device_id
where d.type in ('env','rpi')
order by m.time desc
limit 20;
```

기존 0값 정리:

```bash
sudo -u postgres psql -d netguard -c "
delete from metrics
where metric_name in ('temp_c','humidity_pct')
  and value <= 0
  and device_id in (select id from devices where type in ('env','rpi','environment','sensor'));
"
```

이후 `scripts/find_env_oids.sh`로 실제 온도/습도 OID를 찾고 `config/config.yaml`의 `env_temp_oid`, `env_humidity_oid`, scale 값을 설정한다.

### v1.2.20 (2026-05-29) - 항온항습기 화면 표시 보정

#### 변경 사항
- `backend/api/routes.py`: `/api/metrics/latest` 최신값 조회 범위를 최근 10분에서 24시간으로 확대해 수집 주기 지연 시에도 환경 게이지가 비지 않도록 보정
- `backend/collectors/snmp_collector.py`, `backend/alerts/alert_manager.py`, `backend/app.py`: 환경 장비 타입을 `env`, `rpi` 외에 `environment`, `sensor`까지 인식하도록 확대
- `frontend/js/dashboard.js`: 환경 장비 판별을 타입뿐 아니라 장비명/OS 설명의 `항온`, `습도`, `temperature`, `humidity` 키워드까지 확인하도록 보강

#### 운영 참고
- DB에는 `temp_c`, `humidity_pct`가 들어오는데 화면에 `수집 대기중`으로 보이면 장비 타입/최신값 조회 범위 문제일 가능성이 높다.
- 반영 후 `Ctrl+F5` 새로고침하고, `/api/metrics/latest` 응답에 해당 장비의 `temp_c`, `humidity_pct`가 포함되는지 확인한다.

### v1.2.19 (2026-05-29) - 항온항습기 수집 경로 보강

#### 변경 사항
- `backend/config.py`, `config/config.yaml`: 항온항습기 전용 SNMP OID 설정(`env_temp_oid`, `env_humidity_oid`, `env_temp_scale`, `env_humidity_scale`) 추가
- `backend/collectors/snmp_collector.py`: 장비별 private OID를 설정하면 해당 OID를 우선 사용해 온도/습도를 수집
- `backend/collectors/snmp_collector.py`: 표준/ENTITY-SENSOR-MIB에서 유효값을 찾지 못하면 `0.0` 저장 대신 `None`으로 처리해 잘못된 0도 표시 방지
- `frontend/js/dashboard.js`: 환경 장비가 등록되어 있어도 라즈베리/공통 환경 수집값이 있으면 화면에 표시되도록 fallback 보강

#### 운영 참고
- 항온항습기 vendor OID가 표준 MIB와 다르면 `scripts/find_env_oids.sh`로 후보 OID를 찾은 뒤 `config/config.yaml` 또는 환경변수에 등록한다.
- 예: 원시 온도값이 `289`이고 실제 온도가 `28.9°C`이면 `env_temp_scale: 0.1`로 설정한다.

### v1.2.18 (2026-05-29) - 스위치 오류 초기화 버튼 표시 보정

#### 변경 사항
- `frontend/js/dashboard.js`: 스위치 포트 테이블의 실제 DOM 구조에 맞춰 `오류 초기화` 버튼 삽입 위치를 보정
- 스위치를 변경해도 버튼이 현재 선택된 스위치 ID로 동작하도록 클릭 대상을 갱신

#### 운영 참고
- `오류 초기화` 버튼은 관리자 계정에서만 표시된다.
- 운영자 계정은 조회 전용 정책에 따라 버튼이 표시되지 않는다.

### v1.2.17 (2026-05-29) - NetGuard 기준 스위치 오류 카운터 초기화

#### 변경 사항
- `backend/database.py`: 스위치 포트별 오류 카운터 기준선을 저장하는 `switch_error_baselines` 테이블 추가
- `backend/api/routes.py`: 현재 SNMP 오류 카운터 값을 NetGuard 기준선으로 저장하는 `/api/switches/{device_id}/error-counters/reset` API 추가
- `backend/app.py`: 수집된 `ifInErrors`, `ifOutErrors`에서 저장된 기준선을 차감해 화면/알람에는 기준선 이후 증가분만 반영
- `frontend/js/dashboard.js`: 스위치 포트 상태 테이블에 `오류 초기화` 버튼 추가

#### 운영 참고
- 장비에서 CLI 오류 카운터를 클리어해도 표준 SNMP 카운터가 계속 누적값을 반환하는 장비가 있다.
- 이 경우 스위치 모니터링 화면의 `오류 초기화` 버튼을 누르면 현재 값을 NetGuard 기준선으로 저장하고 이후 증가분만 표시한다.
- 초기화 버튼은 현재 수집된 포트 전체에 적용되며, 기존 오류 이벤트도 해결 상태로 전환한다.

### v1.2.16 (2026-05-29) - 스위치 오류 카운터 이벤트 자동 해제

> 현재 정책(v1.2.30 이후): 스위치 포트 오류 카운트 기반 이벤트는 더 이상 생성/집계/조회하지 않는다. 아래 내용은 과거 동작 기록이다.

#### 변경 사항
- `backend/app.py`: 스위치 포트 오류 이벤트도 현재 SNMP 수집값을 기준으로 자동 해제하도록 보강
- 장비에서 `ifInErrors`, `ifOutErrors`가 정상 범위로 내려오면 기존 `포트 에러 급증` 이벤트를 `resolved`로 전환
- 이벤트 메시지의 포트명과 현재 수집된 `name`, `ifName`, `ifDescr`를 비교해 장비별 포트명 표기 차이를 흡수

#### 운영 참고
- 장비에서 오류 카운터를 클리어한 뒤 NetGuard에는 다음 SNMP 수집 주기 이후 반영된다.
- 기본 수집 주기는 60초이므로 클리어 직후에는 최대 1분 정도 기존 값/이벤트가 보일 수 있다.
- 장비 CLI 카운터와 표준 IF-MIB `ifInErrors`/`ifOutErrors` 카운터가 분리된 장비는 SNMP 조회값 기준으로 표시된다.

### v1.2.15 (2026-05-29) - 스위치 포트 순서 정렬 보정

#### 변경 사항
- `frontend/js/dashboard.js`: 스위치 포트맵과 포트 상태 테이블을 실제 물리 포트 번호 기준으로 `1번`부터 정렬
- `frontend/js/dashboard.js`: `Vlan`, `Null`, `Loopback` 계열 가상 인터페이스는 물리 포트 뒤쪽에 배치
- 포트명이 `GigabitEthernet1/0/1`, `XGigabitEthernet1/0/48`처럼 장비별 접두어가 달라도 마지막 포트 번호를 기준으로 정렬

#### 운영 참고
- HPE/Comware 장비처럼 SNMP `ifIndex` 순서가 실제 포트 순서와 다른 경우에도 화면은 물리 포트 번호 중심으로 표시한다.
- `Vlan-interface`, `NULL`, `LoopBack` 등은 실제 스위치 포트가 아니므로 포트맵 마지막 영역에서 확인한다.

### v1.2.14 (2026-05-29) - 스위치 포트 테이블 전체 표시 및 오류 카운터 개선

#### 변경 사항
- `frontend/js/dashboard.js`: 스위치 모니터링 포트 상태 테이블의 24개 제한을 제거하고 전체 인터페이스를 표시
- `frontend/js/dashboard.js`: 포트맵은 SNMP `ifIndex` 대신 실제 포트명에서 추출한 포트 번호를 우선 표시하도록 개선
- `frontend/js/dashboard.js`: 포트 상태 테이블에 `ifIndex`, 수신/송신 오류 카운터, 오류 합계, Alias 정보를 확인할 수 있도록 개선
- `backend/collectors/snmp_collector.py`: IF-MIB의 `ifName`, `ifAlias`를 추가 수집해 장비별 포트 표기 차이를 줄임
- `frontend/css/style.css`: 오류 카운터가 있는 포트는 포트맵에 빨간 점으로 표시

#### 운영 참고
- 오류 카운터는 SNMP 표준 `ifInErrors`, `ifOutErrors` 누적값이다. 값이 증가하는 포트는 물리 링크, 케이블, Duplex/Speed 협상, CRC/FCS 오류 가능성을 함께 확인한다.
- 일부 장비는 실제 포트번호와 SNMP `ifIndex`가 다르므로, 화면에는 `ifName`/`ifDescr` 기반 포트명을 우선 표시하고 `ifIndex`는 테이블에서 별도 확인한다.

### v1.2.13 (2026-05-18) - 네트워크 기간별 X축 표시 보정

#### 변경 사항
- `frontend/js/dashboard.js`: 네트워크 트래픽 그래프가 선택한 기간 전체를 X축으로 생성하도록 변경
- `frontend/js/dashboard.js`: `1시간`, `6시간`, `24시간`, `7일` 선택 시 기간별 버킷 간격을 적용하고, 장기 구간은 날짜와 시간을 함께 표시
- 과거 데이터가 일부만 있어도 선택한 조회 기간 전체가 축에 반영되며, 데이터가 없는 구간은 빈 값으로 남도록 보정

#### 운영 참고
- 네트워크 그래프에서 기간을 바꾸면 데이터 존재 여부와 무관하게 X축 범위가 즉시 함께 바뀌어야 정상이다.

### v1.2.12 (2026-05-18) - 네트워크 기간 선택 및 운영자 읽기 전용 권한

#### 변경 사항
- `frontend/js/dashboard.js`: 네트워크 트래픽 그래프에 `1시간`, `6시간`, `24시간`, `7일` 독립 기간 선택 추가
- `backend/api/routes.py`: 운영자(`operator`)가 장비 등록/수정/삭제, 임계값 저장, CVE 패치 완료, 이벤트 확인/해결을 호출하지 못하도록 관리자 권한 검증 추가
- `frontend/js/dashboard.js`: 운영자 화면에서는 장비 액션, 임계값 저장, 알림 설정, CVE 패치 완료, 알림 확인/해결 UI를 숨기거나 비활성화
- 운영자는 알림/이벤트 삭제만 허용하고 그 외 기능은 조회 전용으로 제한

### v1.2.11 (2026-05-18) - CVE/NVD 운영 가이드 문서 추가

#### 변경 사항
- `docs/CVE_NVD_UPDATE_GUIDE.md`: NVD API 인증키 발급부터 전체 다운로드, 오프라인 반입, 증분 업데이트, 자동화, 장애 조치까지 별도 문서로 정리
- `docs/GUIDE.md`: 플랫폼별 문서 표에 CVE/NVD 운영 가이드 링크 추가

### v1.2.10 (2026-05-18) - 네트워크 메트릭 저장 루프 오류 수정

#### 변경 사항
- `backend/app.py`: 네트워크 메트릭 저장 시 잘못된 변수명 `device_data`를 `result`로 수정
- 최근 네트워크 그래프 패치 후 수집 루프가 예외로 중단되어 장비가 `대기중`으로 남는 문제 수정

#### 운영 참고
- 오류가 있던 버전에서는 `journalctl -u netguard`에 `name 'device_data' is not defined`가 남을 수 있다.
- 수정본 반영 후 서비스 재시작 뒤 다음 수집 주기부터 장비 상태가 다시 갱신된다.

### v1.2.9 (2026-05-18) - 취약점 영향 장비 분포 막대그래프 전환

#### 변경 사항
- `frontend/js/dashboard.js`: 취약점 영향 장비 분포 차트를 원형에서 막대그래프로 변경
- `frontend/index.html`, `frontend/css/style.css`: CVSS 점수 분포와 동일한 비율로 보이도록 두 보안 차트의 레이아웃을 1:1로 재조정
- 영향 장비 막대그래프는 취약점 수가 많은 장비 순으로 표시

#### 운영 참고
- 보안 화면 상단의 두 차트는 이제 동일한 폭과 높이를 사용한다.

### v1.2.8 (2026-05-18) - 대시보드 네트워크 트래픽 선형 그래프 전환

#### 변경 사항
- `backend/app.py`: 스위치 활성 포트의 수신/송신 누적 트래픽 합계를 `net_in_mb`, `net_out_mb` 메트릭으로 시계열 저장
- `frontend/index.html`, `frontend/js/dashboard.js`: 대시보드 네트워크 트래픽 막대 그래프를 스위치별 선형 그래프로 변경
- `frontend/index.html`, `frontend/js/dashboard.js`: 네트워크 그래프에 `수신` / `송신` 선택 토글 추가

#### 운영 참고
- 배포 직후에는 새 메트릭 누적이 시작되므로, 과거 이력이 없는 스위치는 첫 수집 뒤부터 선형 그래프가 채워진다.
- 네트워크 그래프는 CPU/Memory 그래프와 별도로 `1시간`, `6시간`, `24시간`, `7일` 범위를 선택한다.

### v1.2.7 (2026-05-18) - CVE 상세 모달 고정 및 패치 완료 액션 정리

#### 변경 사항
- `frontend/index.html`, `frontend/css/style.css`: 취약점 영향 장비 분포 원형 차트를 한 단계 더 축소
- `frontend/js/dashboard.js`: CVE 상세 모달을 `body` 최상위로 이동해 항상 독립 팝업으로 표시되도록 보강
- `frontend/js/dashboard.js`: CVE 액션 버튼 문구를 `패치 완료`로 변경하고 상태 표시를 `패치 대기`로 정리

#### 운영 참고
- `상세` 버튼은 화면 하단 알림이 아니라 중앙 팝업 모달로 열려야 정상이다.
- `패치 완료`를 누른 CVE는 목록과 집계에서 즉시 제외된다.

### v1.2.6 (2026-05-18) - CVE 완료 처리 및 영향 장비 차트 축소

#### 변경 사항
- `frontend/css/style.css`: 취약점 영향 장비 분포 도넛 차트의 최대 폭과 높이를 축소
- `backend/database.py`: 완료 처리한 CVE를 보존하는 `cve_completions` 테이블 추가
- `backend/api/routes.py`, `backend/security/cve_checker.py`: 완료 처리한 CVE를 요약/목록/차트 집계에서 제외하도록 보강
- `frontend/js/dashboard.js`: CVE 목록 액션에 `완료` 버튼 추가, 완료 처리 직후 화면에서 해당 CVE 제거

#### 운영 참고
- 완료 처리한 CVE는 새로고침 후에도 목록에서 계속 제외된다.
- 현재 기능은 CVE 단위 완료 처리다. 같은 CVE가 여러 장비에 연결되어 있어도 한 번 완료하면 전체 목록에서 숨긴다.

### v1.2.5 (2026-05-18) - NVD 갱신일 표시 및 증분 업데이트 구성

#### 변경 사항
- `backend/security/cve_checker.py`: NVD 캐시 메타데이터(`cache_meta.json`) 또는 피드 파일 수정 시각을 읽어 `last_updated`, `feed_count`, `loaded_entries`를 CVE 요약 API에 포함
- `backend/security/cve_checker.py`: 피드 파일 또는 `cache_meta.json` 변경을 감지하면 다음 CVE 조회 시 로컬 DB를 자동 재로딩
- `scripts/download_nvd.py`: 전체 다운로드 완료 시 `cache_meta.json` 생성, `NVD_API_KEY` 환경변수 지원, NVD 권장 간격에 맞춰 요청 간 대기 시간 보강
- `scripts/update_nvd_cache.py`: `lastModStartDate`/`lastModEndDate` 기반 증분 업데이트 스크립트 신규 추가
- `deploy/systemd/netguard-nvd-update.service`, `deploy/systemd/netguard-nvd-update.timer`: Rocky Linux용 2시간 주기 증분 업데이트 예시 신규 추가
- `frontend/js/dashboard.js`: CVE 화면의 로컬 DB 업데이트 안내 문구를 실제 오프라인 운영 방식에 맞게 수정

#### 운영 참고
- 오프라인 서버는 외부 NVD API에 직접 접근하지 않으므로, 인터넷 가능한 별도 PC에서 파일을 생성해 반입하는 방식이 기본이다.
- 인터넷 연결이 허용되는 별도 동기화 서버에서는 systemd timer를 켜 두면 최근 변경 CVE를 2시간 간격으로 반영할 수 있고, 새 파일 반입 후 다음 CVE 조회 때 자동 재로딩된다.

### v1.2.4 (2026-05-18) - CVE 상세 보기 개선

#### 변경 사항
- `backend/api/routes.py`: CVE 상세 API가 목록과 동일한 필드명(`cve_id`, `cvss`, `description`)도 함께 반환하도록 보강
- `frontend/index.html`, `frontend/css/style.css`, `frontend/js/dashboard.js`: 기존 토스트 기반 `상세` 동작을 전용 모달로 변경
- CVE ID, Severity, CVSS, CWE, Published, Vector, 설명 전문을 한 화면에서 확인할 수 있도록 개선

#### 운영 참고
- 취약점 목록의 `상세` 버튼을 누르면 우측 하단 알림이 아니라 상세 모달이 열려야 정상이다.

### v1.2.3 (2026-05-18) - NVD BOM 파일 로드 보정

#### 변경 사항
- `backend/security/cve_checker.py`: Windows에서 반입한 UTF-8 BOM 포함 NVD JSON 파일도 읽을 수 있도록 인코딩을 `utf-8-sig`로 변경
- NVD 피드 파일이 실제로 존재하지만 로그에 `Unexpected UTF-8 BOM`과 `Loaded 0 CVE entries`가 남는 문제 수정

#### 운영 참고
- 운영 서버에 `/opt/netguard/data/nvd_cache/nvdcve-*.json` 파일이 있고도 CVE가 0건이면 `journalctl -u netguard`에서 BOM 오류를 먼저 확인한다.
- `utf-8-sig`는 일반 UTF-8 파일과 BOM 포함 UTF-8 파일을 모두 처리하므로, 기존 정상 파일에도 호환된다.

### v1.2.2 (2026-05-18) - 임계값 저장/알람 판정 연동 보정

#### 변경 사항
- `frontend/index.html`, `frontend/js/dashboard.js`: 임계값 화면의 슬라이더 값이 실제 `/api/thresholds` 저장 API를 호출하도록 연결
- `frontend/js/dashboard.js`: 임계값 화면 진입 전 `/api/thresholds/effective`에서 현재 적용값을 읽어 슬라이더에 반영
- `backend/api/routes.py`, `backend/database.py`: 전역 임계값(`device_id IS NULL`) 저장과 조회를 지원하고, 전역 metric 중복 방지 인덱스 추가
- `backend/alerts/alert_manager.py`: 알람 판정 시 30초 주기로 저장된 전역 임계값을 다시 읽어 `config.yaml` 고정 기본값 대신 실제 설정값을 사용
- `backend/config.py`, `config/config.yaml`, `frontend/index.html`: 항온항습기 기본 온도 임계값을 고객 기준인 경고 `30°C`, 위험 `35°C`로 정렬
- 항온항습기 온도 경고를 화면에서 30°C로 저장하면 이후 신규 이벤트도 `경고: 30.0°C` 기준으로 판정되도록 수정

#### 운영 참고
- 기존에 이미 생성된 `active` 이벤트는 과거 기준으로 남아 있을 수 있으므로, 임계값 수정 후 필요 시 이벤트 로그에서 확인/해결 처리한다.
- 저장 직후 신규 수집부터 새 임계값을 사용하며, 백엔드 캐시 갱신 주기는 최대 30초다.

### v1.2.1 (2026-05-14) - Rocky Linux 설치 안정화

#### 변경 사항
- `scripts/install_rocky.sh`: PostgreSQL 18 감지 조건 수정, TimescaleDB preload 검증 추가
- `scripts/install_rocky.sh`: pip wheel 누락 시 온라인 설치 시도 및 필수 Python 모듈 검증 추가
- `scripts/install_rocky.sh`: systemd `workers=1`, `NETGUARD_LOG_DIR`, `NETGUARD_NVD_CACHE_DIR`, `MemoryMax` 반영
- `backend/app.py`: 로그 파일 경로를 `NETGUARD_LOG_DIR` 또는 프로젝트 루트 `logs`로 보정
- `backend/database.py`: 다중 worker 동시 스키마 초기화 충돌 방지를 위한 PostgreSQL advisory lock 추가
- `backend/security/cve_checker.py`: 상대 NVD 캐시 경로를 프로젝트 루트 기준으로 보정
- `backend/collectors/snmp_collector.py`: Linux 메모리 사용률 계산 시 buffer/cache를 제외하도록 보정
- `backend/collectors/snmp_collector.py`: Windows SNMP 메모리를 UCD-SNMP 대신 hrStorage `Physical Memory` 기준으로 fallback 계산
- `backend/collectors/snmp_collector.py`: hrStorage 용량 상세값과 hrSWRun/hrSWRunPerf 프로세스 수집 추가
- `frontend/index.html`, `frontend/js/dashboard.js`: 서버 상세보기에서 Linux는 파티션별, Windows는 디스크별 용량 표 표시
- `frontend/js/dashboard.js`: CPU/메모리 현황 등 차트 시간 라벨을 브라우저 로컬 시간 기준으로 변환
- `agent/netguard_agent.ps1`, `agent/netguard_agent.py`, `agent/install.ps1`: `server_url`에 `http://`가 빠져도 자동 보정
- `agent/netguard_agent.ps1`, `agent/netguard_agent.py`, `backend/api/agent_routes.py`: 에이전트 방식에서도 디스크/프로세스 상세를 SNMP와 동일한 구조로 전송 및 표시
- `backend/app.py`: SNMP 수집 대상에서 에이전트 장비를 제외하고 에이전트 live payload를 WebSocket 메트릭에 병합
- `backend/app.py`, `backend/api/agent_routes.py`: WebSocket live payload에 `device_id`를 포함하여 장비명 변경 후에도 같은 장비로 매칭
- `frontend/js/dashboard.js`: WebSocket 지연/재접속 상태에서도 `/api/metrics/latest` 최신 DB 값을 읽어 대시보드 대기중 표시를 보정
- `frontend/js/dashboard.js`: 대시보드 `전체 서버 CPU / Memory 현황` 그래프가 등록된 전체 서버의 CPU와 Memory를 함께 표시하도록 수정
- `frontend/index.html`, `frontend/css/style.css`, `frontend/js/dashboard.js`: `전체 서버 CPU / Memory 현황` 카드에 CPU/MEMORY 선택 버튼 추가, 선택한 지표를 전체 등록 서버 기준으로 표시
- `frontend/index.html`, `frontend/js/dashboard.js`: CPU/MEMORY 선택 버튼 이벤트를 JS에서도 직접 바인딩하고, agent 장비도 전체 서버 그래프 대상에 포함하며 CSS/JS 캐시 버전 갱신
- `backend/collectors/snmp_collector.py`, `backend/api/routes.py`, `backend/database.py`, `frontend/index.html`, `frontend/js/dashboard.js`: SNMP v3 장비별 Security Level, Auth Protocol, Priv Protocol 입력/저장/수집 지원
- `frontend/js/dashboard.js`: SNMP 버전 `v3` 선택 시 숨겨진 v3 입력 필드가 실제로 표시되도록 `display:block` 처리
- `backend/app.py`: 서비스 재시작 후 에이전트 live 메모리가 초기화되어도 최근 10분 DB 메트릭으로 에이전트 상태를 복원
- `backend/api/routes.py`, `frontend/js/dashboard.js`: 장비 저장 시 SNMP v3 컬럼을 API에서 보장하고, 저장 실패 상세 오류를 화면에 표시
- `frontend/index.html`, `frontend/js/dashboard.js`: UPS 상단 요약에 `예상 대기 시간` 표시, 항온항습/UPS 메뉴 라벨 변경, UPS 요약 아이콘을 배터리 형태로 변경
- `backend/collectors/snmp_collector.py`: 항온항습기 온습도 기본 OID가 0일 때 ENTITY-SENSOR-MIB 표준 센서 테이블을 fallback으로 수집
- `backend/alerts/alert_manager.py`: 스위치 포트 알람을 초기 미연결 `down` 상태가 아니라, 한 번 `up`으로 관측된 포트가 `down`으로 전환될 때만 발생하도록 변경
- `backend/app.py`, `frontend/js/dashboard.js`: 배포 후 첫 수집에서 기존 방식의 스위치 포트 다운 알람을 자동 해결하고, 이후 포트가 `up`으로 복구되면 기존 이벤트를 자동 `resolved` 처리하여 화면에 즉시 반영
- `frontend/js/dashboard.js`: 스위치 장비 상태 카드를 현재 `down` 포트 수가 아니라 실제 활성 이벤트 기준으로 표시하여, 미연결 포트가 있어도 경보 상태로 보이지 않도록 변경
- `backend/alerts/alert_manager.py`, `backend/config.py`, `frontend/index.html`, `frontend/js/dashboard.js`: 항온항습 알람에서 정상 범위 하한 기준을 제거하고, 온도/습도가 설정된 상한 임계값을 초과할 때만 경고하도록 변경
- `scripts/find_env_oids.sh`: 항온항습기에서 Cisco 예시 OID와 ENTITY-SENSOR-MIB가 `NULL`로 응답할 때 private enterprise OID 후보를 현장에서 추출하는 스캔 도구 추가
- `agent/netguard_agent.ps1`: Windows 디스크 상세값을 `PSCustomObject`로 전송하여 `used_pct` 속성 누락 오류 수정
- `backend/api/agent_routes.py`: 에이전트 등록 시 중복 장비명/기존 IP 장비가 있어도 500 오류 없이 기존 장비를 agent 모드로 갱신
- `backend/api/agent_routes.py`: 기존 비활성 장비가 에이전트로 재등록될 때 `enabled=TRUE`로 복구하여 대시보드 장비 목록에 표시
- `agent/install.ps1`: 에이전트 설치 시 NetGuard 표시 장비명(`hostname`)을 별도로 지정하는 프롬프트 추가
- `backend/api/agent_routes.py`: 같은 IP의 기존 SNMP 장비가 에이전트로 등록되면 `snmp_version='agent'`로 전환하여 SNMP 응답 없음 경보 방지
- `backend/collectors/snmp_collector.py`, `backend/app.py`: SNMP `sysDescr`를 OS/펌웨어 정보로 저장
- `docs/agent_install_windows.md`: Windows Agent `server_url` URI 오류 조치 절차 반영
- `docs/INSTALL_ROCKY.md`: 실제 Rocky Linux 설치 중 확인한 장애 조치 절차와 최종 성공 절차 반영

#### 검증 결과
| 항목 | 결과 |
|------|------|
| Python 의존성 설치 | 정상 |
| PostgreSQL 18 + TimescaleDB 확장 | 정상 |
| DB 스키마 생성 | 10개 테이블 생성 확인 |
| systemd 서비스 | `active (running)` 확인 |
| 헬스체크 | `GET /health` → `status: ok` |

#### 항온항습기 온도/습도 OID 확인 절차

일부 항온항습기는 SNMP v2c 연결은 되지만 Cisco 예시 OID(`1.3.6.1.4.1.9.9.13...`)나 ENTITY-SENSOR-MIB(`1.3.6.1.2.1.99...`)를 `NULL`로 응답한다. 이 경우 장비 제조사 private OID를 찾아 수집기에 반영해야 한다.

```bash
cd /opt/netguard
bash scripts/find_env_oids.sh 10.60.8.134 stanry 2c
```

결과는 `/tmp/netguard_env_oid_scan_<IP>_<시간>/` 아래에 저장된다. 우선 `name_candidates.txt`, `value_candidates.txt`, `private_enterprise.txt`를 확인한다.

FLS LinkNet V3.0 / DDC400R-V2는 아래 OID로 확인되었다.

| 항목 | OID | 원시값 예 | 배율 | 저장값 예 |
|------|-----|-----------|------|-----------|
| 습도 | `1.3.6.1.4.1.22210.2.1.53.0` | `44` | `1.0` | `44%` |
| 온도 | `1.3.6.1.4.1.22210.2.1.54.0` | `28917` | `0.001` | `28.9°C` |

`1.3.6.1.4.1.22210.2.1.58.0`도 습도와 같은 `44`로 보일 수 있으나 NetGuard 기본 수집은 온도/습도가 인접한 `.53.0`, `.54.0` 조합을 우선 사용한다.

### v1.2.0 (2026-05-11) - 시뮬레이션 테스트 및 안정화

#### 변경 사항
- `requirements.txt`: `pyasn1==0.5.1`, `pyasn1-modules==0.3.0` 버전 고정 추가
  - pyasn1 0.6.x에서 `compat.octets` 모듈 제거 → pysnmp 6.2.5와 충돌 해결
- `backend/database.py`: TimescaleDB 미설치 환경 graceful 처리
  - `CREATE EXTENSION timescaledb` try-except 래핑 → 일반 PostgreSQL만으로도 기동 가능
- `backend/api/agent_routes.py`: `/api/agent/` 경로 JWT 인증 제외 (`_PUBLIC_PREFIXES` 추가)
- `scripts/netguard.ps1`: `Resolve-Python()` 함수 추가 — pyvenv.cfg home 경로 자동 수정
- `scripts/apply_update.ps1`: pip install 단계 자동화, database.py/requirements.txt 복사 포함
- `agent/netguard_agent.ps1`: PowerShell 에이전트 — Python 의존성 없이 WMI 기반 수집
- `docs/agent_install_windows.md`: Windows 에이전트 설치 매뉴얼 신규 작성
- `docs/agent_install_linux.md`: Linux 에이전트 설치 매뉴얼 신규 작성
- `docs/INSTALL_WINDOWS.md`: PostgreSQL 17 기준으로 전면 업데이트 (기존 18 → 17)

#### 시뮬레이션 테스트 결과 (2026-05-11)
| 항목 | 결과 |
|------|------|
| Python 3.11 / venv / 의존성 | PASS |
| PostgreSQL 17 연결 / 스키마 초기화 | PASS |
| uvicorn 기동 / `/health` 응답 | PASS |
| 에이전트 등록 `/api/agent/register` | PASS |
| 메트릭 전송 `/api/agent/metrics` | PASS |
| DB 적재 확인 | PASS |

---

### v1.0.0 (2025-05-07) - 초기 릴리즈

#### 신규 기능
- Tanium 스타일 다크 테마 대시보드 UI
- SNMP v2c / v3 수집 엔진 (pysnmp 기반)
- 서버: CPU, Memory, Disk, Network, 프로세스 모니터링
- 스위치: 포트 상태 맵, 트래픽 차트
- 항온항습기 / UPS SNMP 수집
- 라즈베리파이 DHT22/BME280 센서 HTTP 연동
- TimescaleDB 시계열 저장 (자동 압축·보존 정책)
- CVE/CWE/CVSS 취약점 모니터링 (오프라인 NVD 캐시)
- 취약점-장비 자동 매핑 (OS 키워드 기반)
- Z-score 기반 이상탐지
- 이메일 HTML 알림 (SMTP)
- 카카오톡 REST API 알림 (오프라인 비활성화 가능)
- WebSocket 실시간 메트릭 푸시
- FastAPI REST API
- Rocky Linux 9 systemd 서비스 (INSTALL_ROCKY.md)
- Windows NSSM 서비스 (INSTALL_WINDOWS.md)

#### 문서
- `docs/GUIDE.md` — 공통 개요 및 기능 설명
- `docs/INSTALL_WINDOWS.md` — Windows 전용 설치/운영 메뉴얼 (17개 섹션)
- `docs/INSTALL_ROCKY.md` — Rocky Linux 전용 설치/운영 메뉴얼 (18개 섹션)

### v1.0.3 (2026-05-08) - 실수집 데이터 전면 적용

#### 변경 사항
- `frontend/js/dashboard.js`: 하드코딩·랜덤 데이터 완전 제거, SNMP 실수집 데이터만 표시
  - `generateRandomSeries` 제거 → `fetchHistory(deviceId, metric, hours)` — `GET /api/metrics/{id}` 실API 호출
  - 모든 차트 함수를 `async`로 전환, TimescaleDB 5분 버킷 데이터 사용
  - `emptyChartPlugin` 전역 등록 — 수집 데이터 없을 때 "데이터 수집 대기중" 표시
  - 항온항습·UPS 게이지: null/undefined 체크 → 미등록 시 "장비 미등록" / 수집 대기 시 "SNMP 수집 대기중"
  - 이벤트 확인/해결 버튼: DB id 없는 이벤트는 비활성(opacity 0.4), id 있을 때만 동작
  - `normalizeEvent(e)`: API 응답과 WebSocket 푸시 양쪽 포맷 정규화
  - `state.live`: WebSocket 60초 주기 실시간 업데이트, 하드코딩 없음
- `backend/app.py`: 이벤트 DB 저장 및 WebSocket 브로드캐스트 보완
  - `_save_events()` 추가 — 알림을 events 테이블에 INSERT, DB id와 함께 반환
  - `collection_loop()`: 매 60초 DB에서 장비 목록 조회 → `snmp_collector.set_devices()` 호출 (미호출 버그 수정)
  - WebSocket 브로드캐스트 이벤트에 DB id 포함 → 프론트엔드 확인/해결 버튼 정상 동작
- `backend/api/routes.py`: `PUT /devices/{id}` 엔드포인트 및 `DeviceUpdate` 모델 추가
- `frontend/index.html`: 사이드바 NetGuard 로고 클릭 → 대시보드 이동, 장비 타입 select value 영문화

---

### v1.0.2 (2025-05-08) - 오프라인 완전 지원

#### 변경 사항
- `frontend/js/chart.umd.min.js`: Chart.js 4.4.0 로컬 파일 추가 (200 KB) — CDN 의존 제거
- `frontend/index.html`: Chart.js 참조를 CDN → 로컬 파일(`js/chart.umd.min.js`)로 변경 — 완전 오프라인 동작 보장
- `NetGuard_v1.0.0.zip`: chart.umd.min.js 포함하여 재생성 (140 KB, 25개 파일)

---

### v1.0.1 (2025-05-07) - 문서 보완

#### 변경 사항
- `INSTALL_WINDOWS.md` 섹션 2.4: postgresql.conf 메모리·WAL·병렬처리·로그 설정 전체 항목으로 확장, RAM 기반 자동 계산 PowerShell 스크립트 추가
- `INSTALL_WINDOWS.md` 섹션 3.2: TimescaleDB `timescaledb.max_background_workers` 1개 항목 → 전체 전용 설정 블록으로 확장 (`telemetry_level`, `max_cached_chunks_per_hypertable`, `enable_chunk_skipping` 추가 및 각 항목 설명 표 포함)
- `INSTALL_ROCKY.md` 섹션 3.3: postgresql.conf 동일 수준으로 확장, RAM 자동 계산 bash 스크립트 추가
- `INSTALL_ROCKY.md` 섹션 4.2: `timescaledb-tune` 사용 가능 경우와 수동 설정 경우 모두 안내, 오프라인 환경 필수 항목(`telemetry_level = off`) 강조
- `requirements.txt`: 한글 주석 제거 (Windows PowerShell 인코딩 오류 방지)
- `C:\NetGuard_packages\pip_packages`: 오프라인 이관용 wheel 62개 수집 완료

---

## 14. 문제 해결

### SNMP 응답 없음
```bash
# 장비 SNMP 응답 테스트
snmpwalk -v2c -c public 192.168.1.10 1.3.6.1.2.1.1.1.0

# 방화벽 확인 (모니터링 서버)
sudo firewall-cmd --list-ports | grep 161

# 장비 방화벽 확인 (대상 서버)
sudo ss -ulnp | grep 161
```

### SNMP v3 UPS 연결 실패
```bash
# authPriv + SHA/AES 예시
snmpwalk -v3 -l authPriv -u <user> -a SHA -A '<auth_password>' -x AES -X '<priv_password>' <UPS_IP> 1.3.6.1.2.1.1.1.0

# authPriv + MD5/DES 예시
snmpwalk -v3 -l authPriv -u <user> -a MD5 -A '<auth_password>' -x DES -X '<priv_password>' <UPS_IP> 1.3.6.1.2.1.1.1.0

# authNoPriv 예시
snmpwalk -v3 -l authNoPriv -u <user> -a SHA -A '<auth_password>' <UPS_IP> 1.3.6.1.2.1.1.1.0
```

- 장비 관리에서 SNMP 버전을 `v3`로 선택하면 User, Security Level, Auth/Priv Protocol과 Password를 입력한다.
- UPS 제조사 기본값이 SHA/AES가 아닐 수 있다. `snmpwalk`로 성공한 조합을 NetGuard에 그대로 입력한다.
- 운영 서버 반영 후 재시작하면 `snmp_v3_security_level`, `snmp_v3_auth_protocol`, `snmp_v3_priv_protocol` 컬럼이 자동 추가된다.

### TimescaleDB 연결 실패
```bash
# PostgreSQL 상태
sudo systemctl status postgresql-15

# 연결 테스트
psql -U netguard -h localhost -d netguard -c "SELECT 1"

# pg_hba.conf 확인 (md5 인증 허용)
sudo cat /var/lib/pgsql/15/data/pg_hba.conf
```

### 테스트 메일 실패: Name or service not known

```text
SMTP test email failed: [Errno -2] Name or service not known
```

- NetGuard 서버가 SMTP 호스트명을 IP로 해석하지 못하는 상태다.
- 알림 설정의 SMTP 서버가 `mail.hlcompany.com`이면 NetGuard 서버에서 아래를 확인한다.

```bash
getent hosts mail.hlcompany.com
nslookup mail.hlcompany.com
```

DNS를 사용할 수 없는 폐쇄망이면 `/etc/hosts`에 SMTP 서버 IP를 등록하거나, 알림 설정의 SMTP 서버를 IP 주소로 입력한다.

```bash
sudo vi /etc/hosts

# 예시
10.60.8.xxx mail.hlcompany.com
```

이름 해석 후 포트 연결을 확인한다.

```bash
nc -vz mail.hlcompany.com 25
nc -vz mail.hlcompany.com 587
```

로그 확인:

```bash
sudo journalctl -u netguard -n 100 --no-pager | egrep -i "smtp|email|mail|failed|error"
```

### 대시보드 빈 화면
```bash
# 백엔드 로그 확인
tail -f logs/netguard.log

# API 직접 테스트
curl http://localhost:8000/health
curl http://localhost:8000/api/devices
curl http://localhost:8000/api/metrics/latest
```

### DB에는 데이터가 있는데 화면이 대기중으로 보임
```bash
# 최근 수집 데이터 확인
PGPASSWORD='NetGuard@2025!' psql -h 127.0.0.1 -U netguard -d netguard \
  -c "select d.name, d.ip_address, d.snmp_version, m.metric_name, m.value, m.time from metrics m join devices d on d.id=m.device_id order by m.time desc limit 20;"

# WebSocket/수집 루프 로그 확인
sudo journalctl -u netguard -n 120 --no-pager | egrep -i "Collection|WebSocket|agent|snmp|error|failed"
```

- 장비명을 에이전트 설치 시 변경한 경우에도 프론트엔드는 `device_id`/IP 기준으로 실시간 값을 매칭한다.
- WebSocket이 늦게 연결되어도 `/api/metrics/latest`의 최근 10분 데이터를 읽어 CPU/메모리/디스크 값을 표시한다.

### Windows Agent 등록 500 또는 used_pct 오류
```powershell
# 에이전트 서버에서 최신 netguard_agent.ps1 반영 후 수동 테스트
powershell -ExecutionPolicy Bypass -File "C:\NetGuard-Agent\netguard_agent.ps1"
```

- `Measure-Object ... used_pct` 오류는 구버전 PowerShell 에이전트가 디스크 항목을 hashtable로 반환할 때 발생한다.
- `/api/agent/register` 500은 동일 장비명이 이미 등록되어 있거나 같은 IP의 SNMP 장비가 남아 있을 때 발생할 수 있으며, 최신 API는 기존 장비를 `snmp_version='agent'`로 갱신한다.
- 등록 후 대시보드에 장비가 보이지 않으면 기존 장비가 `enabled=false`였는지 확인하고 최신 API를 반영한다.

### CVE 데이터 없음
```
1. data/nvd_cache/ 폴더에 nvdcve-*.json 파일 존재 확인
2. python scripts/download_nvd.py 실행 (인터넷 환경)
3. 파일 복사 후 서버 재시작
```

파일이 있는데도 아래 로그가 보이면 Windows 반입 파일의 UTF-8 BOM 문제다.

```text
Unexpected UTF-8 BOM (decode using utf-8-sig)
Loaded 0 CVE entries from local NVD cache
```

이 경우 `backend/security/cve_checker.py`가 `encoding='utf-8-sig'`를 사용해야 한다.

### CVE 화면의 마지막 업데이트가 `--`로 남음
```bash
# 캐시 메타 파일 확인
cat /opt/netguard/data/nvd_cache/cache_meta.json

# 메타 파일이 없으면 전체 다운로드 스크립트를 다시 실행하거나,
# 최소한 피드 파일 수정 시각이 읽히는지 확인
ls -lh /opt/netguard/data/nvd_cache/
```

- `cache_meta.json`이 있으면 그 안의 `last_updated` 값을 표시한다.
- 메타 파일이 없더라도 `nvdcve-*.json` 파일이 정상 로드되면 가장 최근 파일 수정 시각을 표시한다.

---

*NetGuard SNMP Dashboard - 이관 예정: Rocky Linux 9 / Windows Server 2022*

