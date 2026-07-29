# NetGuard Agent - Linux 설치 매뉴얼

## 개요

NetGuard Agent Python 버전은 Linux 서버에 설치하여 CPU·메모리·디스크·네트워크 지표를 NetGuard 서버로 전송합니다.  
Python 3.6+ 표준 라이브러리만 사용하며(psutil 선택적), systemd 서비스로 자동 실행됩니다.

---

## 사전 요구 사항

| 항목 | 최소 요구 사항 |
|------|---------------|
| OS | Ubuntu 18.04 / CentOS 7 / Rocky Linux 8 이상 |
| Python | 3.6 이상 |
| 네트워크 | NetGuard 서버(포트 8000) 접근 가능 |
| 권한 | root 또는 sudo 계정 |

---

## 설치 방법

### 방법 1 — 자동 설치 스크립트 (권장)

```bash
# 1. 에이전트 파일 복사
sudo mkdir -p /opt/netguard-agent
sudo cp netguard_agent.py agent_config.json /opt/netguard-agent/
sudo chmod +x /opt/netguard-agent/netguard_agent.py

# 2. 설정 파일 편집
sudo nano /opt/netguard-agent/agent_config.json
```

`agent_config.json` 내용:
```json
{
    "server_url":  "http://10.60.8.186:8000",
    "api_key":     "netguard-agent-key-2026",
    "interval":    60,
    "hostname":    "",
    "device_type": "server",
    "location":    "서버실 A랙",
    "log_file":    "/opt/netguard-agent/agent.log"
}
```

```bash
# 3. systemd 서비스 등록
sudo tee /etc/systemd/system/netguard-agent.service > /dev/null << 'EOF'
[Unit]
Description=NetGuard Monitoring Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/netguard-agent/netguard_agent.py
WorkingDirectory=/opt/netguard-agent
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# 4. 서비스 활성화 및 시작
sudo systemctl daemon-reload
sudo systemctl enable netguard-agent
sudo systemctl start  netguard-agent
sudo systemctl status netguard-agent
```

---

### 방법 2 — psutil 설치 (선택 — 더 정확한 수집)

psutil이 설치되어 있으면 에이전트가 자동으로 감지하여 더 정확한 지표를 수집합니다.

```bash
# pip 방식
pip3 install psutil

# 패키지 방식 (Ubuntu/Debian)
sudo apt-get install python3-psutil

# 패키지 방식 (Rocky/CentOS)
sudo dnf install python3-psutil
```

---

## 서비스 관리

| 작업 | 명령어 |
|------|--------|
| 시작 | `sudo systemctl start  netguard-agent` |
| 중지 | `sudo systemctl stop   netguard-agent` |
| 재시작 | `sudo systemctl restart netguard-agent` |
| 상태 확인 | `sudo systemctl status  netguard-agent` |
| 실시간 로그 | `sudo journalctl -u netguard-agent -f` |
| 파일 로그 확인 | `tail -f /opt/netguard-agent/agent.log` |
| 수동 실행 테스트 | `python3 /opt/netguard-agent/netguard_agent.py` |

---

## 설정 파일 항목 설명

| 항목 | 설명 | 기본값 |
|------|------|--------|
| `server_url` | NetGuard 서버 주소 | `http://10.60.8.186:8000` |
| `api_key` | 인증 키 | `netguard-agent-key-2026` |
| `interval` | 메트릭 전송 주기(초) | `60` |
| `hostname` | 표시될 장치명 (비워두면 자동) | `` |
| `device_type` | 장치 유형 (`server` / `switch` / `ups`) | `server` |
| `location` | 장치 위치 | `` |
| `log_file` | 로그 파일 경로 (비워두면 stdout만) | `` |

---

## 수집 지표

| 지표 | 수집 방법 (기본) | 수집 방법 (psutil) |
|------|-----------------|-------------------|
| CPU 사용률 | `/proc/stat` 파싱 | `psutil.cpu_percent()` |
| 메모리 사용률 | `/proc/meminfo` 파싱 | `psutil.virtual_memory()` |
| 디스크 사용률 | `df -k /` 명령 | `psutil.disk_usage('/')` |
| 네트워크 IN/OUT | `/proc/net/dev` 파싱 | `psutil.net_io_counters()` |

---

## 배포판별 Python 버전 확인

```bash
python3 --version

# Ubuntu 20.04+ — Python 3.8 이상 기본 탑재
# Rocky Linux 8  — python3 패키지 설치 필요
sudo dnf install python3   # Rocky/CentOS
sudo apt install python3   # Ubuntu/Debian
```

---

## 방화벽 설정 (서버 측 — NetGuard 서버에서 실행)

```bash
# firewalld (Rocky/CentOS)
sudo firewall-cmd --permanent --add-port=8000/tcp
sudo firewall-cmd --reload

# ufw (Ubuntu)
sudo ufw allow 8000/tcp
```

---

## 문제 해결

**서비스가 시작되지 않을 때**
```bash
sudo journalctl -u netguard-agent -n 50 --no-pager
```

**서버 연결 오류**
```bash
# 서버 접근 가능 여부 확인
curl -s http://10.60.8.186:8000/health

# 포트 연결 테스트
nc -zv 10.60.8.186 8000
```

**401 Unauthorized**
- `agent_config.json`의 `api_key`가 서버 설정(`netguard-agent-key-2026`)과 일치하는지 확인

**Python 버전 오류**
```bash
python3 --version   # 3.6 이상 필요
which python3       # 경로 확인

# systemd 서비스의 ExecStart 경로를 실제 python3 경로로 수정
sudo which python3  # → /usr/bin/python3 또는 /usr/local/bin/python3
```

---

## 제거 방법

```bash
sudo systemctl stop    netguard-agent
sudo systemctl disable netguard-agent
sudo rm /etc/systemd/system/netguard-agent.service
sudo systemctl daemon-reload
sudo rm -rf /opt/netguard-agent
```

---

## Agent 단독 재기동

NetGuard 서버를 재시작하지 않고 Rocky/Linux Agent만 재기동할 때 사용합니다.

```bash
sudo /opt/netguard-agent/restart_agent.sh
```

기존 설치본에 스크립트가 없으면 먼저 복사합니다.

```bash
sudo cp agent/restart_agent.sh /opt/netguard-agent/
sudo chmod +x /opt/netguard-agent/restart_agent.sh
sudo /opt/netguard-agent/restart_agent.sh
```

수동으로 처리할 경우:

```bash
sudo systemctl restart netguard-agent
sudo systemctl status netguard-agent --no-pager -l
sudo journalctl -u netguard-agent -n 50 --no-pager
tail -n 30 /opt/netguard-agent/agent.log
```

상세 절차는 `docs/AGENT_RESTART_GUIDE.md`를 참고합니다.
