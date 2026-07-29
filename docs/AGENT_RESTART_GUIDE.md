# NetGuard Agent 단독 재기동 및 백그라운드 기동 가이드

NetGuard 서버를 재시작하지 않고, 모니터링 대상 서버의 Agent만 기동하거나 재기동하는 절차입니다.

## 1. Windows Agent

Windows Agent는 `NetGuardAgent` Windows 서비스 또는 작업 스케줄러 작업으로 백그라운드 실행합니다.

운영 중에는 `netguard_agent.ps1` 또는 `netguard_agent.py`를 직접 실행하지 않습니다. 직접 실행한 콘솔 창을 닫으면 Agent도 같이 종료될 수 있습니다.

### 1.1 Agent 백그라운드 기동

관리자 PowerShell에서 실행합니다.

```powershell
powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\NetGuard-Agent\start_agent_background.ps1"
```

또는 아래 배치 파일을 실행합니다.

```text
C:\NetGuard-Agent\start_agent_background.bat
```

### 1.2 Agent 재기동

아래 파일을 실행하면 Agent를 재기동하고, 서비스 또는 작업 스케줄러 상태를 다시 확인합니다.

```text
C:\NetGuard-Agent\restart_agent.bat
```

또는 관리자 PowerShell에서 직접 실행합니다.

```powershell
powershell -ExecutionPolicy Bypass -File "C:\NetGuard-Agent\restart_agent.ps1"
```

`restart_agent.ps1`는 다음 작업을 수행합니다.

- Windows 서비스가 있으면 서비스를 재기동합니다.
- 서비스가 없고 작업 스케줄러 작업이 있으면 기존 작업을 최신 설정으로 재생성한 뒤 시작합니다.
- 서비스와 작업이 모두 없으면 작업 스케줄러 작업을 새로 등록하고 시작합니다.
- 시작 후 최대 75초 동안 `C:\NetGuard-Agent\agent.log` 갱신 여부를 확인합니다.
- `start_agent_background.ps1` 파일이 누락되어도 내장 재기동 로직으로 Agent를 재기동합니다.

### 1.3 `start_agent_background.ps1` 누락 메시지 조치

아래 메시지가 나오면 운영 장비에 백그라운드 런처 파일이 복사되지 않은 상태입니다.

```text
[NetGuard-Agent] Background launcher not found: C:\NetGuard-Agent\start_agent_background.ps1
```

최신 `restart_agent.ps1`는 이 파일이 없어도 내장 로직으로 재기동을 진행합니다. 표준 구성으로 맞추려면 배포 폴더의 아래 파일을 `C:\NetGuard-Agent`에 복사합니다.

```text
start_agent_background.ps1
start_agent_background.bat
restart_agent.ps1
restart_agent.bat
```

### 1.4 상태 확인 명령

서비스 방식:

```powershell
Get-Service NetGuardAgent
Get-Content "C:\NetGuard-Agent\agent.log" -Tail 30
```

작업 스케줄러 방식:

```powershell
Get-ScheduledTask -TaskName "NetGuardAgent" | Select-Object TaskName, State
(Get-ScheduledTaskInfo -TaskName "NetGuardAgent").LastTaskResult
Get-Content "C:\NetGuard-Agent\agent.log" -Tail 30
```

로그가 1분 이상 증가하지 않으면 아래 파일을 확인합니다.

```powershell
Get-Content "C:\NetGuard-Agent\agent.log" -Tail 50
Get-Content "C:\NetGuard-Agent\agent_stderr.log" -Tail 50
Get-Content "C:\NetGuard-Agent\agent_stdout.log" -Tail 50
```

아래 오류가 반복되면 구버전 PowerShell Agent의 `Send-Json` 변수명 충돌 문제입니다.

```text
"System.String" 유형의 "{"status":"ok","device_id":35}" 값을 "System.Collections.Hashtable" 유형으로 변환할 수 없습니다.
```

최신 `netguard_agent.ps1`를 `C:\NetGuard-Agent`에 복사한 뒤 Agent를 재기동합니다.

```powershell
Copy-Item ".\netguard_agent.ps1" "C:\NetGuard-Agent\netguard_agent.ps1" -Force
C:\NetGuard-Agent\restart_agent.bat
```

### 1.5 통신 확인

Agent PC에서 NetGuard 서버 API 포트를 확인합니다.

```powershell
Test-NetConnection 10.60.8.186 -Port 8000
```

`TcpTestSucceeded : True`가 나오면 Agent 전송 포트는 정상입니다.

## 2. Rocky Linux Agent

Rocky Linux Agent는 `netguard-agent.service` systemd 서비스로 실행합니다.

### 2.1 Agent 단독 재기동

```bash
sudo /opt/netguard-agent/restart_agent.sh
```

스크립트가 아직 배포되지 않은 기존 설치본은 아래처럼 복사 후 실행 권한을 부여합니다.

```bash
sudo cp agent/restart_agent.sh /opt/netguard-agent/
sudo chmod +x /opt/netguard-agent/restart_agent.sh
sudo /opt/netguard-agent/restart_agent.sh
```

### 2.2 상태 확인 명령

```bash
sudo systemctl restart netguard-agent
sudo systemctl status netguard-agent --no-pager -l
sudo journalctl -u netguard-agent -n 50 --no-pager
tail -n 30 /opt/netguard-agent/agent.log
```

## 3. 운영 참고

- Agent 작업 중 NetGuard 서버 서비스인 `netguard`를 재시작할 필요는 없습니다.
- Windows 운영 기동은 `start_agent_background.ps1`, 재기동은 `restart_agent.ps1` 또는 `restart_agent.bat`를 사용합니다.
- `install.ps1`와 `restart_agent.ps1`는 실행 후 백그라운드 기동 확인을 자동 수행합니다.
- 재기동 후 1분 이내에 Agent가 `/api/agent/metrics`로 메트릭을 다시 전송하면 대시보드 상태가 갱신됩니다.
