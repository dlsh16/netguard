# NetGuard Agent - Windows 설치 매뉴얼

## 개요

NetGuard Agent는 모니터링 대상 Windows 서버에 설치하여 CPU·메모리·디스크·네트워크 지표를 NetGuard 서버로 전송합니다.  
Python 없이 PowerShell만으로 동작하며, Windows 서비스(Scheduled Task)로 자동 실행됩니다.

---

## 사전 요구 사항

| 항목 | 최소 요구 사항 |
|------|---------------|
| OS | Windows Server 2016 / Windows 10 이상 |
| PowerShell | 5.1 이상 (기본 탑재) |
| 네트워크 | NetGuard 서버(포트 8000) 접근 가능 |
| 권한 | 관리자(Administrator) 계정 |

---

## 설치 방법

### 방법 1 — 자동 설치 (권장)

1. 에이전트 파일을 대상 서버에 복사합니다.
   ```
   agent\
     install.bat
     install.ps1
     netguard_agent.ps1
     netguard_agent.py
     agent_config.json
   ```

2. `install.bat`를 **마우스 우클릭 → 관리자 권한으로 실행**합니다.

3. 설치 프롬프트에 값을 입력합니다.
   ```
   Server URL [http://10.60.8.186:8000] : (Enter)
   API Key [netguard-agent-key-2026]     : (Enter)
   Interval (sec) [60]                   : (Enter)
   Device display name [WIN-SRV-01]      : DB-WIN-01
   Device type [server]                  : server
   Location                              : 서버실 A랙
   ```

   `Server URL`은 `http://` 또는 `https://`를 포함하는 형식이 권장됩니다. 최신 에이전트는 `10.60.8.186:8000`처럼 입력해도 자동으로 `http://10.60.8.186:8000`으로 보정합니다.

4. 설치 완료 메시지를 확인합니다.
   ```
   [OK] NetGuard Agent installed  →  C:\NetGuard-Agent
   [OK] Scheduled Task registered: NetGuardAgent
   ```

---

### 방법 2 — 수동 설치

**1단계 — 파일 복사**
```powershell
New-Item -ItemType Directory -Path "C:\NetGuard-Agent" -Force
Copy-Item agent\* "C:\NetGuard-Agent\" -Force
```

**2단계 — 설정 파일 편집**

`C:\NetGuard-Agent\agent_config.json`을 메모장으로 열어 수정합니다.
```json
{
    "server_url":  "http://10.60.8.186:8000",
    "api_key":     "netguard-agent-key-2026",
    "interval":    60,
    "hostname":    "",
    "device_type": "server",
    "location":    "서버실 A랙"
}
```
> `hostname`을 비워두면 자동으로 컴퓨터 이름을 사용합니다.

**3단계 — Scheduled Task 등록**
```powershell
$action  = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NonInteractive -ExecutionPolicy Bypass -File C:\NetGuard-Agent\netguard_agent.ps1"
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "NetGuardAgent" -Action $action `
    -Trigger $trigger -RunLevel Highest -Force
Start-ScheduledTask -TaskName "NetGuardAgent"
```

---

## 서비스 관리

| 작업 | 명령어 |
|------|--------|
| 시작 | `Start-ScheduledTask -TaskName "NetGuardAgent"` |
| 중지 | `Stop-ScheduledTask  -TaskName "NetGuardAgent"` |
| 상태 확인 | `Get-ScheduledTask  -TaskName "NetGuardAgent" \| Select-Object State` |
| 로그 확인 | `Get-Content "C:\NetGuard-Agent\agent.log" -Tail 20` |
| 즉시 실행 테스트 | `powershell -ExecutionPolicy Bypass -File "C:\NetGuard-Agent\netguard_agent.ps1"` |

---

## 설정 파일 항목 설명

| 항목 | 설명 | 기본값 |
|------|------|--------|
| `server_url` | NetGuard 서버 주소 | `http://10.60.8.186:8000` |
| `api_key` | 인증 키 | `netguard-agent-key-2026` |
| `interval` | 메트릭 전송 주기(초) | `60` |
| `hostname` | NetGuard에 표시될 장치명 | 컴퓨터 이름 |
| `device_type` | 장치 유형 (`server` / `switch` / `ups`) | `server` |
| `location` | 장치 위치 | `` |

> 설치 중 `Device display name`에 원하는 장비명을 입력하면 NetGuard 장비 목록에는 컴퓨터 이름 대신 해당 이름으로 등록됩니다. 기존 설치본은 `C:\NetGuard-Agent\agent_config.json`의 `hostname` 값을 수정한 뒤 작업을 재시작하면 다음 등록/전송 시 반영됩니다.

> 기존 설치본에서 `"server_url": "10.60.8.186:8000"`처럼 저장되어 있으면 PowerShell의 `System.Net.WebRequest`가 URI로 인식하지 못합니다. 이 경우 `"server_url": "http://10.60.8.186:8000"`으로 수정하거나 최신 에이전트 파일로 교체합니다.

---

## 수집 지표

| 지표 | 수집 방법 |
|------|-----------|
| CPU 사용률 | `Win32_Processor.LoadPercentage` (WMI) |
| 메모리 사용률 | `Win32_OperatingSystem` (WMI) |
| 디스크 사용률 | `Win32_LogicalDisk` 고정 드라이브 전체 (WMI) |
| 디스크 상세 | 드라이브별 전체/사용/여유/사용률을 SNMP `hrStorage`와 동일한 화면 형식으로 전송 |
| 프로세스 상세 | `Get-Process` 상위 50개 프로세스를 SNMP `hrSWRun`과 동일한 화면 형식으로 전송 |
| 네트워크 IN/OUT | `Win32_PerfRawData_Tcpip_NetworkInterface` (WMI) |

---

## 문제 해결

**에이전트가 시작되지 않을 때**
```powershell
# Scheduled Task 최근 실행 결과 확인
(Get-ScheduledTaskInfo -TaskName "NetGuardAgent").LastTaskResult
# 0 = 성공 / 그 외 = 오류코드
```

**서버 연결 오류 (WARN: Send failed)**
- `agent_config.json`의 `server_url` 확인
- `"잘못된 URI: URI 체계가 잘못되었습니다"` 오류가 나오면 `server_url` 앞에 `http://`가 빠진 상태입니다.
  ```powershell
  $config = Get-Content "C:\NetGuard-Agent\agent_config.json" -Raw | ConvertFrom-Json
  $config.server_url = "http://10.60.8.186:8000"
  $config | ConvertTo-Json | Set-Content "C:\NetGuard-Agent\agent_config.json" -Encoding UTF8
  ```
- 방화벽에서 포트 8000 허용 여부 확인
- `Test-NetConnection -ComputerName 10.60.8.186 -Port 8000`으로 연결 테스트

**401 Unauthorized**
- `api_key`가 서버 설정(`netguard-agent-key-2026`)과 일치하는지 확인

---

## 제거 방법

```powershell
Stop-ScheduledTask  -TaskName "NetGuardAgent" -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "NetGuardAgent" -Confirm:$false
Remove-Item "C:\NetGuard-Agent" -Recurse -Force
```

---

## Agent 단독 재기동

NetGuard 서버를 재시작하지 않고 Windows Agent만 재기동할 때 사용합니다.

운영 중에는 `netguard_agent.ps1` 또는 `netguard_agent.py`를 직접 실행하지 않습니다. 직접 실행한 콘솔 창을 닫으면 Agent도 같이 종료됩니다.

백그라운드로 기동:

```powershell
powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\NetGuard-Agent\start_agent_background.ps1"
```

재기동:

```powershell
powershell -ExecutionPolicy Bypass -File "C:\NetGuard-Agent\restart_agent.ps1"
```

수동으로 처리할 경우:

```powershell
# 서비스 방식
Restart-Service NetGuardAgent
Get-Service NetGuardAgent

# 작업 스케줄러 방식
Stop-ScheduledTask  -TaskName "NetGuardAgent"
Start-ScheduledTask -TaskName "NetGuardAgent"
Get-ScheduledTask   -TaskName "NetGuardAgent" | Select-Object TaskName, State

# 로그 확인
Get-Content "C:\NetGuard-Agent\agent.log" -Tail 30
```

상세 절차는 `docs/AGENT_RESTART_GUIDE.md`를 참고합니다.

---

## 설치/재기동 후 백그라운드 자동 기동

운영 환경에서는 `netguard_agent.ps1` 또는 `netguard_agent.py`를 직접 실행하지 않습니다. 직접 실행한 창을 닫으면 Agent도 같이 종료됩니다.

아래 파일은 실행 후 `start_agent_background.ps1`을 자동으로 호출합니다.

```text
install.bat
restart_agent.bat
```

PowerShell로 직접 실행하는 경우도 동일하게 자동 확인이 수행됩니다.

```powershell
powershell -ExecutionPolicy Bypass -File "C:\NetGuard-Agent\restart_agent.ps1"
```

백그라운드 기동만 별도로 확인하려면 아래 명령을 실행합니다.

```powershell
powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\NetGuard-Agent\start_agent_background.ps1"
```

---

## install.ps1 문법 오류 확인

설치 실행 시 아래 오류가 발생하면 현장 폴더의 `install.ps1`이 최신 파일이 아니거나 파일 전송 중 따옴표가 깨진 상태입니다.

```text
The string is missing the terminator: "
```

최신 안전 버전은 실행 시작 시 아래 배너를 출력합니다.

```text
NetGuard Agent Windows Install 2026-07-29-safe
```

설치 전 확인:

```powershell
(Get-Content ".\install.ps1" | Measure-Object -Line).Lines
Get-FileHash ".\install.ps1" -Algorithm SHA256
Get-Content ".\install.ps1" -TotalCount 3
```

정상 기준:

```text
Line count: 204
SHA256: CF150E03F3E47A36274544AD8E5E97A4124BF5C8778AA2DC93B3A8C55BD80D37
Version: 2026-07-29-safe
```

---

## 2026-07-29 추가 조치: 작업 스케줄러 등록 실패 대응

### 증상

설치 중 아래 오류가 표시되고 최종적으로 Agent가 연결되지 않는 경우:

```text
Register-ScheduledTask : 매개 변수가 틀립니다.
Start-ScheduledTask : 지정된 파일을 찾을 수 없습니다.
Get-ScheduledTask : 'NetGuardAgent' TaskName 개체가 없습니다.
```

원인은 PowerShell `Register-ScheduledTask`가 실패했는데도 기존 스크립트가 성공처럼 계속 진행하여 실제 `NetGuardAgent` 작업이 생성되지 않는 문제다.

### 수정 내용

- `install.ps1`, `start_agent_background.ps1`, `restart_agent.ps1`에 작업 스케줄러 등록 실패 감지 로직 추가
- PowerShell ScheduledTasks 등록 실패 시 `schtasks.exe /Create /RU SYSTEM /RL HIGHEST`로 자동 우회 등록
- `Start-ScheduledTask` 실패 시 `schtasks.exe /Run`으로 자동 우회 시작
- 실패 시 `[OK]`를 출력하지 않고 실제 오류를 표시하도록 변경

### 최신 파일 확인

```powershell
Get-Content ".\install.ps1" -TotalCount 3
(Get-Content ".\install.ps1" | Measure-Object -Line).Lines
Get-FileHash ".\install.ps1" -Algorithm SHA256
```

정상 기준:

```text
Version: 2026-07-29-scheduler-fallback
Line count: 283
SHA256: 80321F436176903D7C342E5E6DF92F1858CFAFBD4C7913D8197394B3D5880765
```

### 재설치 전 정리

관리자 권한 PowerShell에서 기존 실패 작업을 정리한다.

```powershell
schtasks /Delete /TN NetGuardAgent /F 2>$null
sc.exe delete NetGuardAgent
```

### 설치 후 확인

```powershell
schtasks /Query /TN NetGuardAgent /V /FO LIST
Get-Content "C:\NetGuard-Agent\agent.log" -Tail 30
Test-NetConnection 10.60.8.186 -Port 8000
```

`agent.log`에 아래 형태가 반복되면 정상이다.

```text
[INFO] NetGuard Agent (PowerShell) starting
[INFO] Server  : http://10.60.8.186:8000
[INFO] OK  cpu=... mem=... disk=...
```

최신 `install.bat`는 `install.ps1` 실행 전에 PowerShell 문법 검사를 먼저 수행합니다.
