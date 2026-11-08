# Windows Agent 설치 오류 및 구형 서버 점검

버전: v1.2.64 / 작성일: 2026-11-08

## 이번 오류의 원인

| 화면의 오류 | 판단 및 수정 |
|---|---|
| Get-Content의 LiteralPath가 null | 이전 install.bat의 -Command 경로 전달 오류. -File 방식으로 변경하고 검사 실패 시 종료 코드를 유지한다. |
| PowerShell syntax OK가 오류 뒤에도 출력됨 | 파일 누락/구문 오류를 종료 오류로 처리하고 모든 파일 검사를 통과해야 성공을 표시한다. |
| System.String에 IsNullOrWhiteSpace 메서드가 없음 | 구형 CLR에서 나타날 수 있는 오류. 해당 입력 처리를 수정했지만 에이전트 전체는 Windows PowerShell 5.1이 필요하다. OS/런타임 확인 없이 지원 여부를 단정하지 않는다. |

**ZIP 교체만으로 PowerShell 2.0에서 에이전트가 동작하는 것은 아니다.** 사전 조건 미충족 시 파일 복사, 설정 작성, 서비스/작업 변경, 설치 질문 전에 중단한다. .NET의 CLR 표시가 4.0이어도 Framework 4.5.2 이상인지는 별도 Release 레지스트리 값으로 검사한다.

## 대상 서버 확인

오류가 발생한 서버의 Windows PowerShell에서 실행한다. 아래 명령은 설정을 변경하지 않으며 PowerShell 2.0에서도 사용할 수 있다.

```powershell
$PSVersionTable
[Environment]::Version
Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version, ServicePackMajorVersion, OSArchitecture
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release -ErrorAction SilentlyContinue
```

운영 기본 대상은 Windows Server 2016 이상이다. 구형 서버는 다음 표와 Microsoft 사전 조건을 확인한 후 별도 검증한다. 구형 OS의 일반 지원 종료 상태를 이 패치가 변경하지 않으며, 가능한 경우 지원 중인 OS로 이관한다.

| 확인된 OS | 조치 |
|---|---|
| Server 2016 이상 | 기본 Windows PowerShell 5.1 확인. PowerShell 7/pwsh 또는 -Version 2로 실행하지 않는다. |
| Server 2012 / 2012 R2 | 해당 OS용 WMF 5.1과 .NET Framework 사전 조건을 확인한다. |
| Server 2008 R2 SP1 | Microsoft가 제공한 OS 전용 WMF 5.1 설치 경로가 있다. 업무 앱 호환성 검토 및 변경 승인 후 적용한다. 실제 NetGuard 동작은 해당 서버에서 검증해야 한다. |
| Server 2008 R2 SP1 미적용 | 먼저 OS/SP 지원 조건 검토. WMF 설치를 강제하지 않는다. |
| Server 2008(non-R2) / 2003 | WMF 5.1 대상이 아니다. 현재 에이전트를 설치하지 말고 OS 이관 또는 별도 구형 수집 방식 검토. |

## 폐쇄망 사전 준비

1. OS 명칭, SP, 32/64비트를 확인하고 업무 애플리케이션 공급사의 .NET/WMF 호환성 및 백업/복구 계획을 검토한다.
2. 인터넷 가능한 준비 PC에서 Microsoft 공식 문서의 해당 OS용 WMF 5.1 패키지와 .NET Framework 사전 조건을 확보한다. WMF 5.1의 최소 .NET Framework는 4.5.2다. 최소 버전을 신규 운영 권장 버전으로 해석하지 말고 OS와 업무 앱이 지원하는 패치된 Framework 버전을 선택한다.
3. 파일의 Microsoft 서명과 승인된 반입 경로를 확인한다. 전송 전후 SHA256을 비교한다. 임의 사이트의 재포장 설치 파일을 사용하지 않는다.
4. 승인된 유지보수 시간에 공식 설치 순서로 적용하고 필요한 재부팅을 진행한다. 에이전트 설치기는 WMF/.NET 설치나 서버 재부팅을 자동 수행하지 않는다. Server 2008 R2의 WMF 3.0 충돌 등은 공식 사전 조건을 따른다.
5. 재부팅 후 새 Windows PowerShell 창에서 버전을 재확인하고 아래 사전 검사를 수행한다. .NET 8/9 또는 PowerShell 7만 설치하는 것은 이 에이전트의 Windows PowerShell 사전 조건을 충족하지 않는다.

공식 근거: [WMF 지원 OS](https://learn.microsoft.com/en-us/powershell/scripting/windows-powershell/wmf-overview?view=powershell-7.5), [WMF 5.1 설치 및 사전 조건](https://learn.microsoft.com/en-us/previous-versions/powershell/scripting/windows-powershell/wmf/setup/install-configure?view=powershell-7.3), [.NET Framework Release 값 확인](https://learn.microsoft.com/en-us/dotnet/framework/install/how-to-determine-which-versions-are-installed).

## 신규 설치

`NetGuard-Agent-v1.2.64.zip` 전체를 탐색기로 별도 폴더에 압축 해제한다. 예: `C:\Temp\NetGuard-v1264`. ZIP 안에서 직접 실행하거나 install.bat만 단독 복사하지 않는다.

```powershell
cd C:\Temp\NetGuard-v1264\agent
.\install.bat --check
$LASTEXITCODE
```

종료 코드 0과 `Preflight passed`를 확인한다. 이 명령은 파일/서비스/작업을 변경하지 않는다. 전체 패키지 파일, PowerShell 5.1, Desktop 런타임, .NET Framework 4.5.2 이상, 필수 명령, IPv4, 작업 스케줄러 COM 접근을 검사한다. **NetGuard 서버 통신 및 메일 발송을 검사하는 명령은 아니다.**

점검 통과 후 처음 설치하는 장비에서만 `install.bat`를 관리자 권한으로 실행한다. 서버 주소는 기본 `http://10.60.8.186:8000`이며 실제 주소/API 키/장비명을 확인한다. NSSM이 있으면 서비스, 없으면 SYSTEM 시작 작업으로 등록한다. 설치 후 로그가 실제 갱신되는지 반드시 확인한다.

## 기존 에이전트 갱신

기존 `agent_config.json`을 유지하려면 install.bat를 다시 실행하지 않는다. 아래는 Windows PowerShell 5.1, 기존 설치 경로 `C:\NetGuard-Agent` 기준이다. 백업에는 API 키가 있으므로 관리자만 접근하도록 보호한다. 명령 중 실패하면 다음 단계로 넘어가지 않고 원인을 확인한다.

```powershell
$ErrorActionPreference = 'Stop'
$source = 'C:\Temp\NetGuard-v1264\agent'
$target = 'C:\NetGuard-Agent'
& "$source\install.bat" --check
if ($LASTEXITCODE -ne 0) { throw 'Preflight failed; update stopped.' }
if (-not (Test-Path -LiteralPath "$target\agent_config.json")) { throw 'Existing agent configuration not found.' }
$files = @('windows_agent_common.ps1', 'netguard_agent.ps1', 'netguard_agent.py',
    'software_inventory.ps1', 'software_inventory.py', 'restart_agent.ps1',
    'restart_agent.bat', 'start_agent_background.ps1', 'start_agent_background.bat')
$backup = Join-Path $target ('backup-v1264-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $backup | Out-Null
foreach ($file in ($files + @('agent_config.json'))) {
    if (Test-Path -LiteralPath (Join-Path $target $file)) {
        Copy-Item -LiteralPath (Join-Path $target $file) -Destination $backup
    }
}
. "$source\windows_agent_common.ps1"
$service = Get-Service NetGuardAgent -ErrorAction SilentlyContinue
if ($service) { Stop-Service NetGuardAgent -ErrorAction Stop }
Stop-AgentTask 'NetGuardAgent'
foreach ($file in $files) {
    Copy-Item -LiteralPath (Join-Path $source $file) -Destination $target -Force
}
& "$target\restart_agent.bat"
Get-Content "$target\agent.log" -Tail 40
```

필수 공통 파일 `windows_agent_common.ps1`도 반드시 함께 배포한다. 이전 4개 파일 교체 절차만 사용하면 새 버전에서 공통 파일 누락으로 시작하지 못한다. 원복 시 에이전트를 중지하고 백업한 같은 버전의 코드 파일 전체를 되돌린 뒤 재기동한다. 새로 추가된 공통 파일은 구버전에서 참조하지 않으므로 남겨도 된다. 운영 설정을 기본 예제로 덮어쓰지 않는다.

이번 패치는 중앙 NetGuard 서버 코드/DB를 변경하지 않는다. Rocky/Windows 중앙 서버 재시작 및 NVD 갱신은 필요 없다. 소프트웨어 검색 기능 자체를 처음 적용한다면 별도 [v1.2.63 서버 적용 절차](SOFTWARE_INVENTORY_GUIDE.md)가 먼저 필요하다.

## 기동 및 수집 확인

```powershell
Get-Service NetGuardAgent -ErrorAction SilentlyContinue
schtasks.exe /Query /TN NetGuardAgent /V /FO LIST
Get-Content 'C:\NetGuard-Agent\agent.log' -Tail 40
```

서비스 방식에서는 작업이 없을 수 있고, 작업 방식에서는 서비스가 없을 수 있다. `Running`만 보지 말고 설정된 주기마다 `OK cpu=...` 로그와 서버 화면의 마지막 수집 시각이 증가하는지 확인한다. 설치 창을 닫은 뒤에도 갱신되는지 확인하고, 다음 승인된 서버 재부팅 이후 자동 시작을 검증한다. 소프트웨어 인벤토리는 별도 백그라운드 작업이므로 최초 수집에 수 분이 걸릴 수 있다.

Get-NetIPAddress가 없는 환경에서는 WMI로 IPv4를 조회한다. 루프백/APIPA만 있는 경우 잘못된 IP로 등록하지 않고 오류를 낸다. 여러 NIC가 있는 서버는 로그와 등록 IP가 올바른지 확인한다. ScheduledTasks PowerShell 모듈이 없어도 COM으로 작업 상태를 조회하며 기존 schtasks.exe 등록/기동 대체 경로를 이용한다.

## 검증 범위 및 변경 파일

- 개발 PC Windows PowerShell 5.1에서 읽기 전용 사전 검사, 한글/공백/특수문자 경로, 실제 없는 작업 COM 조회를 검증했다.
- 구형 런타임/낮은 Framework/파일 누락/구문 오류 중단, WMI 대체 조회, 작업 상태/중지/삭제는 테스트 대역으로 검증했다. 실제 PS2/Server 2008 R2에서 설치·재부팅한 결과는 아니다.
- 이번 설치 테스트 10건과 기존 소프트웨어 수집 테스트 9건은 통과했다. 전체 회귀 64건 중 63건 통과, 이번 수정과 별개인 NVD 피드 백업 테스트 1건은 연속 실행 시 동일 시각의 백업 디렉터리 이름 충돌로 실패했다. NVD 코드는 이번 패치에서 변경하지 않았다.
- 코드: `agent/install.bat`, `agent/install.ps1`, `agent/check_agent_environment.ps1`, `agent/windows_agent_common.ps1`, `agent/restart_agent.ps1`, `agent/start_agent_background.ps1`, `agent/netguard_agent.ps1/.py`, `agent/software_inventory.ps1/.py`.
- 테스트: `tests/test_agent_installer.py`, `tests/test_software_agent.py`. 설치/재시작/인벤토리 가이드 및 Guide 업데이트 이력도 함께 갱신했다.
