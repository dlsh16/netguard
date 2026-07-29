#Requires -Version 5.1
<#
.SYNOPSIS
    Windows 서버 정기점검 자동화 스크립트
.DESCRIPTION
    서버 정기점검 표준 항목 기반 (OS/CPU/메모리/디스크/서비스/로그/네트워크)
    행정안전부 윈도우 서버 보안 점검 체크리스트 항목 포함
    Python/외부 라이브러리 불필요 - PowerShell 5.1 이상이면 단독 실행 가능
    점검 항목: 55개 (기본 45 + 행안부 10)
.NOTES
    관리자 권한 실행 권장
    실행: powershell -ExecutionPolicy Bypass -File Maintenance_Windows.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputDir = "",
    [switch]$NoOpen
)

Set-StrictMode -Off
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference    = "SilentlyContinue"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding          = [System.Text.Encoding]::UTF8

# $PSScriptRoot 비어있을 때 폴백 처리 (EXE 실행 등 다양한 환경 대응)
if (-not $OutputDir) {
    $ScriptBase = if ($PSScriptRoot) { $PSScriptRoot }
                  elseif ($PSCommandPath) { Split-Path $PSCommandPath }
                  elseif ($MyInvocation.MyCommand.Path) { Split-Path $MyInvocation.MyCommand.Path }
                  else { $PWD.Path }
    $OutputDir = Join-Path $ScriptBase "output"
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  결과 저장소
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
$Global:Results = [System.Collections.Generic.List[hashtable]]::new()
$Global:CntNormal  = 0
$Global:CntWarning = 0
$Global:CntCritical= 0
$Global:CntManual  = 0
$Global:CntNA      = 0

function Add-Result {
    param(
        [string]$ID,
        [string]$Category,
        [string]$Title,
        [string]$Standard,
        [string]$Status,   # 정상/주의/경고/확인필요/N/A
        [string]$Detail,
        [string]$Action = ""
    )
    $Global:Results.Add(@{
        ID       = $ID
        Category = $Category
        Title    = $Title
        Standard = $Standard
        Status   = $Status
        Detail   = $Detail
        Action   = $Action
    })
    switch ($Status) {
        "정상"    { $Global:CntNormal++   }
        "주의"    { $Global:CntWarning++  }
        "경고"    { $Global:CntCritical++ }
        "확인필요" { $Global:CntManual++  }
        "N/A"     { $Global:CntNA++       }
    }
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  콘솔 출력 헬퍼
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
function Write-Section([string]$Title) {
    Write-Host ""
    Write-Host "  ▶ $Title" -ForegroundColor Cyan
    Write-Host ("  " + "─" * 62) -ForegroundColor DarkGray
}

function Write-CheckResult([string]$ID, [string]$Title, [string]$Status) {
    $padID    = $ID.PadRight(7)
    $padTitle = if ($Title.Length -gt 42) { $Title.Substring(0,42) } else { $Title.PadRight(42) }
    Write-Host "    $padID $padTitle " -NoNewline
    switch ($Status) {
        "정상"    { Write-Host "[ 정상 ]" -ForegroundColor Green  }
        "주의"    { Write-Host "[ 주의 ]" -ForegroundColor Yellow }
        "경고"    { Write-Host "[ 경고 ]" -ForegroundColor Red    }
        "확인필요" { Write-Host "[ 확인 ]" -ForegroundColor Yellow }
        "N/A"     { Write-Host "[ N/A  ]" -ForegroundColor DarkGray }
        default   { Write-Host "[ 오류 ]" -ForegroundColor DarkGray }
    }
}

function Get-RegVal([string]$Path, [string]$Name) {
    try { return (Get-ItemProperty -Path $Path -Name $Name -EA Stop).$Name }
    catch { return $null }
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  1. 시스템 기본 정보 (M-01 ~ M-05)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
function Check-SystemInfo {
    Write-Section "시스템 기본 정보"

    # M-01 OS 버전 및 빌드
    $os = Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue
    $osCaption = if ($os) { $os.Caption } else { [System.Environment]::OSVersion.VersionString }
    $osBuild   = if ($os) { "빌드 $($os.BuildNumber)" } else { "" }
    $osArch    = if ($os) { $os.OSArchitecture } else { "" }
    Add-Result "M-01" "시스템정보" "운영체제 버전 확인" `
        "OS 버전, 빌드번호, 아키텍처 확인" "확인필요" `
        "$osCaption $osBuild ($osArch)" `
        "EOL 운영체제 사용 시 업그레이드 또는 지원 연장 검토"
    Write-CheckResult "M-01" "운영체제 버전 확인" "확인필요"

    # M-02 시리얼 번호 (BIOS)
    $bios = Get-CimInstance Win32_BIOS -EA SilentlyContinue
    $serial   = if ($bios) { $bios.SerialNumber } else { "확인불가" }
    $biosVer  = if ($bios) { $bios.SMBIOSBIOSVersion } else { "확인불가" }
    $biosDate = if ($bios) { $bios.ReleaseDate.ToString("yyyy-MM-dd") } else { "확인불가" }
    Add-Result "M-02" "시스템정보" "시리얼 번호 및 BIOS 정보" `
        "하드웨어 시리얼, BIOS 버전 기록" "확인필요" `
        "S/N: $serial | BIOS: $biosVer | 날짜: $biosDate" ""
    Write-CheckResult "M-02" "시리얼 번호 및 BIOS 정보" "확인필요"

    # M-03 CPU 정보
    $cpus = Get-CimInstance Win32_Processor -EA SilentlyContinue
    $cpuName  = if ($cpus) { ($cpus | Select-Object -First 1).Name.Trim() } else { "확인불가" }
    $cpuCores = if ($cpus) { ($cpus | Measure-Object -Property NumberOfCores -Sum).Sum } else { 0 }
    $cpuLogic = if ($cpus) { ($cpus | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum } else { 0 }
    Add-Result "M-03" "시스템정보" "CPU 정보 확인" `
        "CPU 모델, 코어 수, 논리 프로세서 수" "확인필요" `
        "$cpuName | 물리코어: ${cpuCores}개 | 논리코어: ${cpuLogic}개" ""
    Write-CheckResult "M-03" "CPU 정보 확인" "확인필요"

    # M-04 메모리 총량
    $totalRAM = if ($os) { [math]::Round($os.TotalVisibleMemorySize / 1MB, 1) } else { 0 }
    Add-Result "M-04" "시스템정보" "메모리 총량 확인" `
        "설치된 물리 메모리 총량 확인" "확인필요" `
        "총 메모리: ${totalRAM} GB" ""
    Write-CheckResult "M-04" "메모리 총량 확인" "확인필요"

    # M-05 시스템 업타임
    $lastBoot = if ($os) { $os.LastBootUpTime } else { $null }
    if ($lastBoot) {
        $uptime    = (Get-Date) - $lastBoot
        $uptimeStr = "{0}일 {1}시간 {2}분" -f [int]$uptime.TotalDays, $uptime.Hours, $uptime.Minutes
        $status    = if ($uptime.TotalDays -gt 180) { "주의" } else { "정상" }
        $action    = if ($uptime.TotalDays -gt 180) { "업타임 180일 초과 - 정기 재부팅 일정 검토" } else { "" }
    } else {
        $uptimeStr = "확인불가"; $status = "확인필요"; $action = ""
    }
    Add-Result "M-05" "시스템정보" "시스템 업타임 확인" `
        "마지막 재부팅 이후 경과 시간 (180일 초과 시 주의)" $status `
        "업타임: $uptimeStr | 마지막 부팅: $($lastBoot.ToString('yyyy-MM-dd HH:mm'))" $action
    Write-CheckResult "M-05" "시스템 업타임 확인" $status
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  2. CPU 성능 모니터링 (M-06 ~ M-08)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
function Check-CPU {
    Write-Section "CPU 성능 모니터링"

    # M-06 현재 CPU 사용률
    $cpuLoad = (Get-CimInstance Win32_Processor -EA SilentlyContinue | Measure-Object -Property LoadPercentage -Average).Average
    $cpuLoad = [math]::Round($cpuLoad, 1)
    $status  = if ($cpuLoad -ge 90) { "경고" } elseif ($cpuLoad -ge 80) { "주의" } else { "정상" }
    Add-Result "M-06" "CPU" "현재 CPU 사용률" `
        "80% 이상 주의, 90% 이상 경고" $status `
        "현재 CPU 사용률: ${cpuLoad}%" `
        $(if($status -ne "정상"){"CPU 집중 프로세스 확인: Get-Process | Sort-Object CPU -Desc | Select-Object -First 10"} else {""})
    Write-CheckResult "M-06" "현재 CPU 사용률" $status

    # M-07 CPU TOP 프로세스 (사용률 기준)
    $topProc = Get-Process -EA SilentlyContinue | Sort-Object CPU -Descending | Select-Object -First 5
    $topStr  = ($topProc | ForEach-Object { "$($_.Name) (CPU: $([math]::Round($_.CPU,1))s, PID: $($_.Id))" }) -join " | "
    Add-Result "M-07" "CPU" "CPU 점유율 상위 프로세스 (TOP 5)" `
        "CPU 사용량 상위 프로세스 현황 파악" "확인필요" `
        $topStr ""
    Write-CheckResult "M-07" "CPU 상위 프로세스 (TOP 5)" "확인필요"

    # M-08 실행 중인 프로세스 수
    $procCount = (Get-Process -EA SilentlyContinue).Count
    $status    = if ($procCount -gt 300) { "주의" } else { "정상" }
    Add-Result "M-08" "CPU" "실행 중인 프로세스 수" `
        "300개 이상 시 주의" $status `
        "현재 실행 중인 프로세스: ${procCount}개" `
        $(if($status -ne "정상"){"비정상 프로세스 여부 확인: Get-Process | Sort-Object WorkingSet -Desc"} else {""})
    Write-CheckResult "M-08" "실행 중인 프로세스 수" $status
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  3. 메모리 모니터링 (M-09 ~ M-11)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
function Check-Memory {
    Write-Section "메모리 모니터링"

    $os = Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue

    # M-09 메모리 사용량
    if ($os) {
        $totalMB = [math]::Round($os.TotalVisibleMemorySize / 1KB, 0)
        $freeMB  = [math]::Round($os.FreePhysicalMemory / 1KB, 0)
        $usedMB  = $totalMB - $freeMB
        $usePct  = [math]::Round($usedMB / $totalMB * 100, 1)
        $status  = if ($usePct -ge 95) { "경고" } elseif ($usePct -ge 85) { "주의" } else { "정상" }
        $detail  = "총: ${totalMB}MB | 사용: ${usedMB}MB | 가용: ${freeMB}MB | 사용률: ${usePct}%"
    } else {
        $usePct = 0; $status = "확인필요"; $detail = "메모리 정보 확인 불가"
    }
    Add-Result "M-09" "메모리" "메모리 사용량" `
        "사용률 85% 이상 주의, 95% 이상 경고" $status $detail `
        $(if($status -ne "정상"){"메모리 집중 프로세스 확인: Get-Process | Sort-Object WorkingSet -Desc | Select-Object -First 10"} else {""})
    Write-CheckResult "M-09" "메모리 사용량" $status

    # M-10 메모리 상위 프로세스 (TOP 5)
    $topMem = Get-Process -EA SilentlyContinue | Sort-Object WorkingSet -Descending | Select-Object -First 5
    $topStr = ($topMem | ForEach-Object { "$($_.Name) ($([math]::Round($_.WorkingSet/1MB,0))MB)" }) -join " | "
    Add-Result "M-10" "메모리" "메모리 점유율 상위 프로세스 (TOP 5)" `
        "메모리 사용량 상위 프로세스 현황 파악" "확인필요" $topStr ""
    Write-CheckResult "M-10" "메모리 상위 프로세스 (TOP 5)" "확인필요"

    # M-11 페이징 파일(가상 메모리) 사용량
    $pf = Get-CimInstance Win32_PageFileUsage -EA SilentlyContinue | Select-Object -First 1
    if ($pf) {
        $pfUsePct = [math]::Round($pf.CurrentUsage / $pf.AllocatedBaseSize * 100, 1)
        $status   = if ($pfUsePct -ge 80) { "주의" } else { "정상" }
        $detail   = "파일: $($pf.Name) | 할당: $($pf.AllocatedBaseSize)MB | 사용: $($pf.CurrentUsage)MB | 사용률: ${pfUsePct}%"
    } else {
        $status = "N/A"; $detail = "페이징 파일 사용 정보 없음 (자동 관리)"
    }
    Add-Result "M-11" "메모리" "페이징 파일(가상 메모리) 사용량" `
        "사용률 80% 이상 시 주의 - 물리 메모리 증설 검토" $status $detail `
        $(if($status -eq "주의"){"물리 메모리 부족으로 과도한 페이징 발생 - 메모리 증설 권장"} else {""})
    Write-CheckResult "M-11" "페이징 파일 사용량" $status
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  4. 디스크 모니터링 (M-12 ~ M-15)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
function Check-Disk {
    Write-Section "디스크 모니터링"

    # M-12 드라이브별 디스크 사용량
    $drives = Get-PSDrive -PSProvider FileSystem -EA SilentlyContinue | Where-Object { $_.Used -ne $null -and $_.Free -ne $null }
    $worstStatus = "정상"
    $driveDetails = @()
    foreach ($d in $drives) {
        $totalGB = [math]::Round(($d.Used + $d.Free) / 1GB, 1)
        $usedGB  = [math]::Round($d.Used / 1GB, 1)
        $freePct = if (($d.Used + $d.Free) -gt 0) { [math]::Round($d.Free / ($d.Used + $d.Free) * 100, 1) } else { 0 }
        $usePct  = 100 - $freePct
        $dStatus = if ($usePct -ge 90) { "경고"; $worstStatus="경고" }
                   elseif ($usePct -ge 80) { if ($worstStatus -ne "경고") {$worstStatus="주의"}; "주의" }
                   else { "정상" }
        $driveDetails += "$($d.Name): 전체 ${totalGB}GB | 사용 ${usedGB}GB | 사용률 ${usePct}% [$dStatus]"
    }
    Add-Result "M-12" "디스크" "드라이브별 디스크 사용량" `
        "사용률 80% 이상 주의, 90% 이상 경고" $worstStatus `
        ($driveDetails -join "`n") `
        $(if($worstStatus -ne "정상"){"디스크 정리 또는 용량 증설 검토 - cleanmgr.exe 실행"} else {""})
    Write-CheckResult "M-12" "드라이브별 디스크 사용량" $worstStatus

    # M-13 임시 파일 디렉터리 크기
    $tempPaths = @($env:TEMP, $env:TMP, "C:\Windows\Temp") | Select-Object -Unique
    $tempDetails = @()
    foreach ($tp in $tempPaths) {
        if (Test-Path $tp) {
            $sizeMB = [math]::Round((Get-ChildItem $tp -Recurse -EA SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB, 1)
            $tempDetails += "${tp}: ${sizeMB}MB"
        }
    }
    $totalTempMB = ($tempDetails | ForEach-Object { [double]($_ -replace ".+: (.+)MB", '$1') } | Measure-Object -Sum).Sum
    $status = if ($totalTempMB -ge 5000) { "주의" } else { "정상" }
    Add-Result "M-13" "디스크" "임시 파일 디렉터리 크기" `
        "TEMP 디렉터리 5GB 이상 시 정리 권장" $status `
        ($tempDetails -join " | ") `
        $(if($status -ne "정상"){"임시 파일 정리: cleanmgr /sageset:1 & cleanmgr /sagerun:1"} else {""})
    Write-CheckResult "M-13" "임시 파일 디렉터리 크기" $status

    # M-14 이벤트 로그 파일 크기
    $logs = @("System","Application","Security") | ForEach-Object {
        $l = Get-WinEvent -ListLog $_ -EA SilentlyContinue
        if ($l) { "${_}: $([math]::Round($l.FileSize/1MB,1))MB / $([math]::Round($l.MaximumSizeInBytes/1MB,1))MB" }
    }
    Add-Result "M-14" "디스크" "이벤트 로그 파일 크기" `
        "로그 파일 용량 현황 확인" "확인필요" ($logs -join " | ") ""
    Write-CheckResult "M-14" "이벤트 로그 파일 크기" "확인필요"

    # M-15 Windows 업데이트 임시 파일 (SoftwareDistribution)
    $sdPath = "C:\Windows\SoftwareDistribution\Download"
    if (Test-Path $sdPath) {
        $sdMB = [math]::Round((Get-ChildItem $sdPath -Recurse -EA SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB, 1)
        $status = if ($sdMB -ge 10000) { "주의" } else { "정상" }
        $detail = "SoftwareDistribution\Download: ${sdMB}MB"
    } else {
        $status = "N/A"; $detail = "경로 없음"
    }
    Add-Result "M-15" "디스크" "Windows Update 캐시 크기" `
        "10GB 이상 시 정리 권장" $status $detail `
        $(if($status -eq "주의"){"서비스 중지 후 정리: net stop wuauserv & del /q/f/s $sdPath\*"} else {""})
    Write-CheckResult "M-15" "Windows Update 캐시 크기" $status
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  5. 서비스 상태 (M-16 ~ M-18)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
function Check-Services {
    Write-Section "서비스 상태 점검"

    # M-16 핵심 시스템 서비스 상태
    $coreServices = @(
        @{ Name="EventLog";    Desc="Windows 이벤트 로그" },
        @{ Name="Winmgmt";     Desc="WMI (Windows Management)" },
        @{ Name="W32Time";     Desc="Windows 시간 동기화(NTP)" },
        @{ Name="wuauserv";    Desc="Windows Update" },
        @{ Name="Schedule";    Desc="작업 스케줄러" },
        @{ Name="LanmanServer";Desc="파일 공유(Server)" },
        @{ Name="Dhcp";        Desc="DHCP 클라이언트" }
    )
    $stopped = @()
    foreach ($svc in $coreServices) {
        $s = Get-Service -Name $svc.Name -EA SilentlyContinue
        if ($s -and $s.Status -ne "Running") { $stopped += "$($svc.Desc)($($svc.Name)): $($s.Status)" }
        elseif (-not $s) { $stopped += "$($svc.Desc)($($svc.Name)): 미설치" }
    }
    $status = if ($stopped.Count -eq 0) { "정상" } else { "경고" }
    Add-Result "M-16" "서비스" "핵심 시스템 서비스 상태" `
        "핵심 서비스 모두 Running 상태이면 정상" $status `
        $(if($stopped){"중지된 서비스:`n" + ($stopped -join "`n")} else {"핵심 서비스 모두 정상 실행 중"}) `
        $(if($stopped){"services.msc 또는 net start <서비스명> 으로 재시작"} else {""})
    Write-CheckResult "M-16" "핵심 시스템 서비스 상태" $status

    # M-17 자동 시작 서비스 중 중지된 서비스
    $autoStopped = Get-Service -EA SilentlyContinue | Where-Object { $_.StartType -eq "Automatic" -and $_.Status -ne "Running" }
    $autoStoppedNames = ($autoStopped | ForEach-Object { $_.DisplayName }) -join "`n"
    $status = if ($autoStopped.Count -eq 0) { "정상" } elseif ($autoStopped.Count -le 3) { "주의" } else { "경고" }
    Add-Result "M-17" "서비스" "자동 시작 서비스 중 중지 항목" `
        "자동 시작으로 설정된 서비스가 미실행 시 주의" $status `
        $(if($autoStopped.Count -gt 0){"중지된 자동시작 서비스 ${autoStopped.Count}개:`n$autoStoppedNames"} else {"모든 자동시작 서비스 정상 실행 중"}) `
        $(if($autoStopped.Count -gt 0){"해당 서비스의 중지 원인 및 이벤트 로그 확인"} else {""})
    Write-CheckResult "M-17" "자동 시작 서비스 중 중지 항목" $status

    # M-18 NTP 시간 동기화 상태
    $ntpStatus = (w32tm /query /status 2>$null) -join "`n"
    $ntpSource = (w32tm /query /source 2>$null) -join ""
    $synced    = $ntpStatus -match "Synchronized|Source:"
    $status    = if ($synced -and $ntpSource -notmatch "Local") { "정상" } else { "주의" }
    Add-Result "M-18" "서비스" "NTP 시간 동기화 상태" `
        "외부 NTP 서버와 동기화 시 정상" $status `
        "NTP 소스: $ntpSource" `
        $(if($status -ne "정상"){"w32tm /config /manualpeerlist:time.windows.com /syncfromflags:manual /update && w32tm /resync"} else {""})
    Write-CheckResult "M-18" "NTP 시간 동기화 상태" $status
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  6. Windows Update / 패치 (M-19 ~ M-21)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
function Check-WindowsUpdate {
    Write-Section "Windows Update / 패치 관리"

    # M-19 최근 Windows Update 설치 날짜
    $latestHotfix = Get-HotFix -EA SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($latestHotfix -and $latestHotfix.InstalledOn) {
        $daysSince = ((Get-Date) - $latestHotfix.InstalledOn).Days
        $status    = if ($daysSince -gt 90) { "경고" } elseif ($daysSince -gt 30) { "주의" } else { "정상" }
        $detail    = "최근 업데이트: $($latestHotfix.HotFixID) ($($latestHotfix.InstalledOn.ToString('yyyy-MM-dd'))) | ${daysSince}일 경과"
    } else {
        $status = "확인필요"; $detail = "업데이트 이력 확인 불가"
    }
    Add-Result "M-19" "패치관리" "최근 Windows Update 적용 날짜" `
        "30일 이내 업데이트 시 정상, 90일 초과 시 경고" $status $detail `
        $(if($status -ne "정상"){"Windows Update 즉시 실행 - 설정 > Windows 업데이트"} else {""})
    Write-CheckResult "M-19" "최근 Windows Update 적용" $status

    # M-20 설치된 핫픽스 목록 (최근 10개)
    $recentHotfixes = Get-HotFix -EA SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 10
    $hfDetail = ($recentHotfixes | ForEach-Object { "$($_.HotFixID) ($($_.InstalledOn.ToString('yyyy-MM-dd')))" }) -join " | "
    Add-Result "M-20" "패치관리" "최근 설치된 핫픽스 목록 (TOP 10)" `
        "최근 설치된 패치 이력 기록" "확인필요" $hfDetail ""
    Write-CheckResult "M-20" "최근 설치 핫픽스 목록" "확인필요"

    # M-21 자동 업데이트 설정 여부
    $auReg = Get-RegVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate"
    $auEnabled = ($auReg -ne 1)
    $status = if ($auEnabled) { "정상" } else { "주의" }
    Add-Result "M-21" "패치관리" "자동 업데이트 활성화 여부" `
        "자동 업데이트 활성화 시 정상" $status `
        "자동 업데이트: $(if($auEnabled){'활성화'} else {'비활성화'})" `
        $(if(-not $auEnabled){"설정 > Windows 업데이트 > 고급 옵션 > 자동 업데이트 활성화"} else {""})
    Write-CheckResult "M-21" "자동 업데이트 활성화 여부" $status
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  7. 이벤트 로그 점검 (M-22 ~ M-25)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
function Check-EventLog {
    Write-Section "이벤트 로그 점검"

    $since24h = (Get-Date).AddHours(-24)
    $since7d  = (Get-Date).AddDays(-7)

    # M-22 시스템 로그 오류 (24시간)
    $sysErr = Get-WinEvent -FilterHashtable @{LogName="System";Level=2;StartTime=$since24h} -EA SilentlyContinue
    $sysErrCount = ($sysErr | Measure-Object).Count
    $status = if ($sysErrCount -ge 20) { "경고" } elseif ($sysErrCount -ge 5) { "주의" } else { "정상" }
    $topSysErr = ($sysErr | Select-Object -First 3 | ForEach-Object { "[$($_.Id)] $($_.Message.Substring(0,[math]::Min(80,$_.Message.Length)))" }) -join " | "
    Add-Result "M-22" "이벤트로그" "시스템 로그 오류 (최근 24시간)" `
        "5건 이상 주의, 20건 이상 경고" $status `
        "오류 ${sysErrCount}건 | $topSysErr" `
        $(if($status -ne "정상"){"이벤트 뷰어(eventvwr.msc) > Windows 로그 > 시스템 확인"} else {""})
    Write-CheckResult "M-22" "시스템 로그 오류 (24시간)" $status

    # M-23 응용 프로그램 로그 오류 (24시간)
    $appErr = Get-WinEvent -FilterHashtable @{LogName="Application";Level=2;StartTime=$since24h} -EA SilentlyContinue
    $appErrCount = ($appErr | Measure-Object).Count
    $status = if ($appErrCount -ge 20) { "경고" } elseif ($appErrCount -ge 5) { "주의" } else { "정상" }
    Add-Result "M-23" "이벤트로그" "응용 프로그램 로그 오류 (최근 24시간)" `
        "5건 이상 주의, 20건 이상 경고" $status `
        "오류 ${appErrCount}건" `
        $(if($status -ne "정상"){"이벤트 뷰어(eventvwr.msc) > Windows 로그 > 응용 프로그램 확인"} else {""})
    Write-CheckResult "M-23" "응용 프로그램 로그 오류 (24시간)" $status

    # M-24 보안 로그 실패 감사 (24시간)
    $secFail = Get-WinEvent -FilterHashtable @{LogName="Security";Keywords=4503599627370496;StartTime=$since24h} -EA SilentlyContinue
    $secFailCount = ($secFail | Measure-Object).Count
    $status = if ($secFailCount -ge 100) { "경고" } elseif ($secFailCount -ge 20) { "주의" } else { "정상" }
    Add-Result "M-24" "이벤트로그" "보안 로그 실패 감사 (최근 24시간)" `
        "20건 이상 주의, 100건 이상 경고 (로그인 실패 등)" $status `
        "실패 감사 ${secFailCount}건" `
        $(if($status -ne "정상"){"이벤트 뷰어 > 보안 로그 > 이벤트 4625(로그온 실패) 집중 확인"} else {""})
    Write-CheckResult "M-24" "보안 로그 실패 감사 (24시간)" $status

    # M-25 시스템 중요 이벤트 (7일) - 블루스크린/예상치 못한 종료
    $critEvents = Get-WinEvent -FilterHashtable @{LogName="System";Id=@(41,1001,6008);StartTime=$since7d} -EA SilentlyContinue
    $critCount  = ($critEvents | Measure-Object).Count
    $status     = if ($critCount -ge 1) { "경고" } else { "정상" }
    $critDetail = ($critEvents | Select-Object -First 3 | ForEach-Object { "[$($_.TimeCreated.ToString('MM-dd HH:mm'))] ID:$($_.Id)" }) -join " | "
    Add-Result "M-25" "이벤트로그" "비정상 종료/BSOD 이벤트 (최근 7일)" `
        "발생 없음 시 정상 (이벤트 ID: 41/1001/6008)" $status `
        $(if($critCount -gt 0){"${critCount}건 발생: $critDetail"} else {"비정상 종료 이벤트 없음"}) `
        $(if($status -ne "정상"){"메모리 검사 mdsched.exe 및 드라이버 확인 권장"} else {""})
    Write-CheckResult "M-25" "비정상 종료/BSOD 이벤트 (7일)" $status
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  8. 네트워크 모니터링 (M-26 ~ M-29)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
function Check-Network {
    Write-Section "네트워크 모니터링"

    # M-26 네트워크 어댑터 상태
    $adapters = Get-NetAdapter -EA SilentlyContinue | Where-Object { $_.Status -eq "Up" }
    $adpDetail = ($adapters | ForEach-Object { "$($_.Name): $($_.LinkSpeed) [$($_.Status)]" }) -join " | "
    $status    = if (($adapters | Measure-Object).Count -eq 0) { "경고" } else { "정상" }
    Add-Result "M-26" "네트워크" "네트워크 어댑터 상태" `
        "활성 어댑터 존재 시 정상" $status `
        $(if($adpDetail){"활성 어댑터: $adpDetail"} else {"활성 어댑터 없음"}) ""
    Write-CheckResult "M-26" "네트워크 어댑터 상태" $status

    # M-27 IP 주소 현황
    $ips = Get-NetIPAddress -AddressFamily IPv4 -EA SilentlyContinue | Where-Object { $_.InterfaceAlias -notmatch "Loopback" }
    $ipDetail = ($ips | ForEach-Object { "$($_.InterfaceAlias): $($_.IPAddress)/$($_.PrefixLength)" }) -join " | "
    Add-Result "M-27" "네트워크" "IP 주소 현황" `
        "네트워크 인터페이스 IP 주소 확인" "확인필요" `
        $(if($ipDetail){$ipDetail} else {"IP 정보 확인불가"}) ""
    Write-CheckResult "M-27" "IP 주소 현황" "확인필요"

    # M-28 현재 네트워크 연결 (ESTABLISHED)
    $conns = netstat -an 2>$null | Select-String "ESTABLISHED"
    $connCount = ($conns | Measure-Object).Count
    $status = if ($connCount -gt 1000) { "주의" } else { "정상" }
    Add-Result "M-28" "네트워크" "현재 네트워크 연결 수 (ESTABLISHED)" `
        "1000개 이상 시 주의" $status `
        "현재 연결 수: ${connCount}개" `
        $(if($status -ne "정상"){"netstat -an | findstr ESTABLISHED 로 연결 확인"} else {""})
    Write-CheckResult "M-28" "현재 네트워크 연결 수" $status

    # M-29 DNS 해석 확인
    $dnsTest = Resolve-DnsName "www.google.com" -EA SilentlyContinue
    $status = if ($dnsTest) { "정상" } else { "경고" }
    Add-Result "M-29" "네트워크" "외부 DNS 해석 확인" `
        "외부 도메인(google.com) DNS 해석 성공 시 정상" $status `
        $(if($dnsTest){"DNS 해석 정상 - $($dnsTest | Select-Object -First 1 -ExpandProperty IPAddress)"} else {"DNS 해석 실패 - 네트워크 또는 DNS 서버 확인 필요"}) `
        $(if($status -ne "정상"){"ipconfig /flushdns && nslookup www.google.com 로 DNS 확인"} else {""})
    Write-CheckResult "M-29" "외부 DNS 해석 확인" $status
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  9. 스케줄 작업 / 계정 (M-30 ~ M-34)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
function Check-TasksAndAccounts {
    Write-Section "스케줄 작업 / 계정 관리"

    # M-30 최근 실패한 스케줄 작업
    $since7d     = (Get-Date).AddDays(-7)
    $failedTasks = Get-ScheduledTask -EA SilentlyContinue | Where-Object { $_.State -ne "Disabled" } | ForEach-Object {
        $info = $_ | Get-ScheduledTaskInfo -EA SilentlyContinue
        if ($info -and $info.LastRunTime -gt $since7d -and $info.LastTaskResult -ne 0 -and $info.LastTaskResult -ne 267011) {
            "$($_.TaskName): 결과코드 $($info.LastTaskResult)"
        }
    } | Where-Object { $_ }
    $status = if (($failedTasks | Measure-Object).Count -gt 0) { "주의" } else { "정상" }
    Add-Result "M-30" "스케줄작업" "최근 실패한 스케줄 작업 (7일)" `
        "실패 작업 없으면 정상" $status `
        $(if($failedTasks){"실패 작업:`n" + ($failedTasks -join "`n")} else {"최근 7일 스케줄 작업 실패 없음"}) `
        $(if($status -ne "정상"){"작업 스케줄러(taskschd.msc)에서 실패 작업 확인 및 조치"} else {""})
    Write-CheckResult "M-30" "최근 실패 스케줄 작업 (7일)" $status

    # M-31 로컬 계정 현황
    $localUsers = Get-LocalUser -EA SilentlyContinue
    $activeCount  = ($localUsers | Where-Object { $_.Enabled }).Count
    $disabledCount= ($localUsers | Where-Object { -not $_.Enabled }).Count
    $userDetail   = ($localUsers | ForEach-Object { "$($_.Name) [$(if($_.Enabled){'활성'}else{'비활성'})]" }) -join " | "
    Add-Result "M-31" "계정관리" "로컬 계정 현황" `
        "로컬 계정 목록 및 활성화 상태 확인" "확인필요" `
        "활성: ${activeCount}개 | 비활성: ${disabledCount}개 | $userDetail" `
        "불필요한 계정 비활성화 또는 삭제 검토"
    Write-CheckResult "M-31" "로컬 계정 현황" "확인필요"

    # M-32 장기 미사용 계정 (90일 이상 미로그온)
    $threshold90  = (Get-Date).AddDays(-90)
    $inactiveUsers= Get-LocalUser -EA SilentlyContinue | Where-Object { $_.Enabled -and ($_.LastLogon -lt $threshold90 -or $_.LastLogon -eq $null) }
    $status = if (($inactiveUsers | Measure-Object).Count -gt 0) { "주의" } else { "정상" }
    Add-Result "M-32" "계정관리" "장기 미사용 계정 점검 (90일)" `
        "90일 이상 미로그온 활성 계정 없으면 정상" $status `
        $(if($inactiveUsers){"미사용 계정: " + (($inactiveUsers | Select-Object -ExpandProperty Name) -join ", ")} else {"90일 이상 미사용 계정 없음"}) `
        $(if($status -ne "정상"){"Disable-LocalUser -Name '<계정명>' 으로 계정 비활성화"} else {""})
    Write-CheckResult "M-32" "장기 미사용 계정 점검" $status

    # M-33 로컬 그룹 구성원 현황 (Administrators)
    $admins = Get-LocalGroupMember -Group "Administrators" -EA SilentlyContinue | Select-Object -ExpandProperty Name
    $adminCount = ($admins | Measure-Object).Count
    $status     = if ($adminCount -gt 3) { "주의" } else { "정상" }
    Add-Result "M-33" "계정관리" "Administrators 그룹 구성원" `
        "관리자 그룹 3명 이하 권장" $status `
        "구성원 ${adminCount}명: $($admins -join ', ')" `
        $(if($status -ne "정상"){"불필요한 관리자 계정 제거 - lusrmgr.msc"} else {""})
    Write-CheckResult "M-33" "Administrators 그룹 구성원" $status

    # M-34 로그온 세션 현황 (현재 접속자)
    $sessions = query session 2>$null | Select-String "Active|활성"
    $sessionCount = ($sessions | Measure-Object).Count
    $status       = if ($sessionCount -gt 5) { "주의" } else { "정상" }
    Add-Result "M-34" "계정관리" "현재 로그온 세션 현황" `
        "5개 이상 동시 세션 시 주의" $status `
        "현재 활성 세션: ${sessionCount}개" ""
    Write-CheckResult "M-34" "현재 로그온 세션 현황" $status
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  10. 시스템 보안 기본 설정 (M-35 ~ M-40)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
function Check-SecurityBasic {
    Write-Section "시스템 보안 기본 설정"

    # M-35 Windows Defender 상태
    $defStatus = Get-MpComputerStatus -EA SilentlyContinue
    if ($defStatus) {
        $avEnabled  = $defStatus.AntivirusEnabled
        $rtEnabled  = $defStatus.RealTimeProtectionEnabled
        $sigDate    = if ($defStatus.AntivirusSignatureLastUpdated) { $defStatus.AntivirusSignatureLastUpdated.ToString("yyyy-MM-dd") } else { "확인불가" }
        $daysSinceSig = if ($defStatus.AntivirusSignatureLastUpdated) { ((Get-Date) - $defStatus.AntivirusSignatureLastUpdated).Days } else { 999 }
        $status     = if (-not $avEnabled -or -not $rtEnabled -or $daysSinceSig -gt 7) { "경고" } elseif ($daysSinceSig -gt 3) { "주의" } else { "정상" }
        $detail     = "Antivirus: $(if($avEnabled){'활성'}else{'비활성'}) | 실시간보호: $(if($rtEnabled){'활성'}else{'비활성'}) | DB갱신: $sigDate (${daysSinceSig}일 전)"
    } else {
        $status = "확인필요"; $detail = "Windows Defender 상태 확인 불가 (타 백신 사용 가능)"
    }
    Add-Result "M-35" "보안기본" "Windows Defender 상태" `
        "실시간 보호 활성 + 서명 DB 7일 이내 갱신 시 정상" $status $detail `
        $(if($status -ne "정상"){"Windows 보안 센터에서 바이러스 및 위협 보호 업데이트"} else {""})
    Write-CheckResult "M-35" "Windows Defender 상태" $status

    # M-36 Windows 방화벽 상태
    $fwProfiles = Get-NetFirewallProfile -EA SilentlyContinue
    $allEnabled  = ($fwProfiles | Where-Object { -not $_.Enabled }).Count -eq 0
    $fwDetail    = ($fwProfiles | ForEach-Object { "$($_.Name): $(if($_.Enabled){'활성'}else{'비활성'})" }) -join " | "
    $status      = if ($allEnabled) { "정상" } else { "경고" }
    Add-Result "M-36" "보안기본" "Windows 방화벽 상태" `
        "모든 프로파일(도메인/개인/공용) 활성화 시 정상" $status `
        $fwDetail `
        $(if(-not $allEnabled){"netsh advfirewall set allprofiles state on"} else {""})
    Write-CheckResult "M-36" "Windows 방화벽 상태" $status

    # M-37 UAC(사용자 계정 컨트롤) 활성화
    $uacReg = Get-RegVal "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA"
    $status = if ($uacReg -eq 1) { "정상" } else { "경고" }
    Add-Result "M-37" "보안기본" "UAC(사용자 계정 컨트롤) 활성화" `
        "EnableLUA=1 이면 정상" $status `
        "EnableLUA: $uacReg" `
        $(if($status -ne "정상"){"secpol.msc > 보안 옵션 > '사용자 계정 컨트롤' 활성화"} else {""})
    Write-CheckResult "M-37" "UAC 활성화 여부" $status

    # M-38 원격 데스크톱(RDP) 활성화 여부 확인
    $rdpReg = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections"
    $rdpEnabled = ($rdpReg -eq 0)
    $rdpPort    = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "PortNumber"
    $status     = "확인필요"
    Add-Result "M-38" "보안기본" "원격 데스크톱(RDP) 설정 확인" `
        "RDP 사용 현황 및 포트 번호 확인 (불필요 시 비활성화)" $status `
        "RDP: $(if($rdpEnabled){'활성화'}else{'비활성화'}) | 포트: $rdpPort" `
        $(if($rdpEnabled){"RDP 불필요 시: sysdm.cpl > 원격 탭 > 원격 연결 허용 해제"} else {""})
    Write-CheckResult "M-38" "원격 데스크톱(RDP) 설정" $status

    # M-39 공유 폴더 현황
    $shares = Get-SmbShare -EA SilentlyContinue | Where-Object { $_.Name -notmatch '^\$' -and $_.Name -ne "IPC$" }
    $shareCount = ($shares | Measure-Object).Count
    $shareDetail = ($shares | ForEach-Object { "$($_.Name) -> $($_.Path)" }) -join " | "
    $status = if ($shareCount -gt 0) { "확인필요" } else { "정상" }
    Add-Result "M-39" "보안기본" "공유 폴더 현황 (비관리용)" `
        "비관리용 공유 폴더 없으면 정상 (필요 최소화)" $status `
        $(if($shareCount -gt 0){"공유 폴더 ${shareCount}개: $shareDetail"} else {"비관리용 공유 폴더 없음"}) `
        $(if($shareCount -gt 0){"불필요한 공유 폴더 제거: Remove-SmbShare -Name '<공유명>'"} else {""})
    Write-CheckResult "M-39" "공유 폴더 현황" $status

    # M-40 원격 레지스트리 서비스
    $remReg = Get-Service -Name "RemoteRegistry" -EA SilentlyContinue
    $status  = if ($remReg -and $remReg.Status -eq "Running") { "주의" } else { "정상" }
    Add-Result "M-40" "보안기본" "원격 레지스트리 서비스 상태" `
        "원격 레지스트리 서비스 중지 시 정상" $status `
        "RemoteRegistry: $(if($remReg){$remReg.Status}else{'미설치'})" `
        $(if($status -ne "정상"){"sc config RemoteRegistry start=disabled && sc stop RemoteRegistry"} else {""})
    Write-CheckResult "M-40" "원격 레지스트리 서비스" $status
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  11. 종합 점검 / 기타 (M-41 ~ M-45)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
function Check-Miscellaneous {
    Write-Section "종합 점검 / 기타"

    # M-41 환경 변수 및 시스템 경로
    $sysPath = $env:PATH
    $pathLen = $sysPath.Length
    $status  = if ($pathLen -gt 2048) { "주의" } else { "정상" }
    Add-Result "M-41" "기타" "시스템 PATH 환경 변수 길이" `
        "PATH 환경 변수 2048자 이하 권장" $status `
        "PATH 길이: ${pathLen}자" `
        $(if($status -ne "정상"){"시스템 환경 변수에서 불필요한 경로 제거 - sysdm.cpl > 고급 > 환경 변수"} else {""})
    Write-CheckResult "M-41" "시스템 PATH 환경 변수" $status

    # M-42 시스템 드라이브 조각 모음 (SSD 여부 확인)
    $c = Get-PhysicalDisk -EA SilentlyContinue | Where-Object { $_.DeviceId -eq 0 }
    $diskType = if ($c) { $c.MediaType } else { "확인불가" }
    Add-Result "M-42" "기타" "시스템 디스크 타입 확인" `
        "디스크 타입(SSD/HDD) 확인 - SSD는 조각 모음 불필요" "확인필요" `
        "디스크 타입: $diskType" ""
    Write-CheckResult "M-42" "시스템 디스크 타입 확인" "확인필요"

    # M-43 최근 시스템 재부팅 이력
    $bootEvents = Get-WinEvent -FilterHashtable @{LogName="System";Id=6005} -MaxEvents 5 -EA SilentlyContinue
    $bootTimes  = ($bootEvents | ForEach-Object { $_.TimeCreated.ToString("yyyy-MM-dd HH:mm") }) -join " | "
    Add-Result "M-43" "기타" "최근 시스템 재부팅 이력 (최근 5회)" `
        "재부팅 이력 기록" "확인필요" `
        $(if($bootTimes){"재부팅 시각: $bootTimes"} else {"재부팅 이력 없음"}) ""
    Write-CheckResult "M-43" "최근 시스템 재부팅 이력" "확인필요"

    # M-44 설치된 소프트웨어 수
    $sw32 = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -EA SilentlyContinue | Where-Object { $_.DisplayName }
    $sw64 = Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -EA SilentlyContinue | Where-Object { $_.DisplayName }
    $swAll = @($sw32) + @($sw64) | Select-Object -Unique -ExpandProperty DisplayName
    $swCount = ($swAll | Measure-Object).Count
    Add-Result "M-44" "기타" "설치된 소프트웨어 현황" `
        "설치된 소프트웨어 목록 기록 및 불필요한 소프트웨어 제거 검토" "확인필요" `
        "설치된 소프트웨어: ${swCount}개" `
        "제어판 > 프로그램 및 기능에서 불필요한 소프트웨어 제거 검토"
    Write-CheckResult "M-44" "설치된 소프트웨어 현황" "확인필요"

    # M-45 점검 종합 의견
    $total = $Global:Results.Count
    $pct   = if ($total -gt 0) { [math]::Round($Global:CntNormal / $total * 100, 1) } else { 0 }
    $opinion = if ($pct -ge 90) { "전반적으로 양호한 상태입니다." } elseif ($pct -ge 70) { "일부 항목 개선이 필요합니다." } else { "다수의 점검 항목에서 조치가 필요합니다." }
    Add-Result "M-45" "기타" "점검 종합 의견" `
        "전체 점검 항목 정상 비율" "확인필요" `
        "정상 ${pct}% (${Global:CntNormal}/${total}) - $opinion" ""
    Write-CheckResult "M-45" "점검 종합 의견" "확인필요"
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  12. 행정안전부 점검 기준 추가 항목 (A-01 ~ A-10)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
function Check-MogaItems {
    Write-Section "행정안전부 점검 기준 항목"

    # A-01 AutoLogon 비활성화
    # 자동 로그온 설정 시 재부팅 후 패스워드 없이 로그인 가능 - 물리 접근 공격에 취약
    $autoLogonPw  = Get-RegVal "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "DefaultPassword"
    $autoLogonEna = Get-RegVal "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AutoAdminLogon"
    $autoLogonOn  = ($autoLogonEna -eq "1" -and $null -ne $autoLogonPw)
    $status = if ($autoLogonOn) { "경고" } else { "정상" }
    Add-Result "A-01" "행안부" "AutoLogon 자동 로그온 비활성화" `
        "AutoAdminLogon=0 또는 DefaultPassword 미설정 시 정상" $status `
        "AutoAdminLogon: $(if($null -ne $autoLogonEna){$autoLogonEna}else{'미설정'}) | DefaultPassword: $(if($autoLogonPw){'설정됨'}else{'미설정'})" `
        $(if($autoLogonOn){"HKLM:\...\Winlogon\AutoAdminLogon = 0 및 DefaultPassword 값 삭제"} else {""})
    Write-CheckResult "A-01" "AutoLogon 자동 로그온 비활성화" $status

    # A-02 마지막 로그온 사용자 이름 표시 제한
    # 로그인 화면에 마지막 사용자 이름 표시 시 계정 정보 노출
    $dontDisplay = Get-RegVal "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DontDisplayLastUserName"
    $status = if ($dontDisplay -eq 1) { "정상" } else { "주의" }
    Add-Result "A-02" "행안부" "마지막 로그온 사용자 이름 표시 제한" `
        "DontDisplayLastUserName=1 이면 정상" $status `
        "DontDisplayLastUserName: $(if($null -ne $dontDisplay){$dontDisplay}else{'미설정(기본값=0)'})" `
        $(if($status -ne "정상"){"secpol.msc > 보안 옵션 > '대화형 로그온: 마지막 사용자 이름 표시 안 함' 활성화"} else {""})
    Write-CheckResult "A-02" "마지막 로그온 사용자 표시 제한" $status

    # A-03 익명(Anonymous) 접근 제한
    # NULL 세션을 통한 익명 SAM 계정 및 공유 정보 열거 방지
    $restrictAnon = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous"
    $restrictSAM  = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymousSAM"
    $status = if ($restrictAnon -ge 1 -and $restrictSAM -eq 1) { "정상" } else { "주의" }
    Add-Result "A-03" "행안부" "익명(Anonymous) 접근 제한" `
        "RestrictAnonymous >= 1, RestrictAnonymousSAM = 1 이면 정상" $status `
        "RestrictAnonymous: $(if($null -ne $restrictAnon){$restrictAnon}else{'미설정'}) | RestrictAnonymousSAM: $(if($null -ne $restrictSAM){$restrictSAM}else{'미설정'})" `
        $(if($status -ne "정상"){"secpol.msc > 보안 옵션 > '네트워크 접근: SAM 계정 익명 열거 허용 안 함' 활성화"} else {""})
    Write-CheckResult "A-03" "익명(Anonymous) 접근 제한" $status

    # A-04 SNMP 커뮤니티 스트링 'public' 변경 여부
    # 기본 커뮤니티 문자열 사용 시 네트워크 정보 무단 열람 가능
    $snmpSvc = Get-Service -Name "SNMP" -EA SilentlyContinue
    if ($snmpSvc -and $snmpSvc.Status -eq "Running") {
        $snmpComm = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" "public"
        $status   = if ($null -ne $snmpComm) { "경고" } else { "정상" }
        $detail   = "SNMP 서비스 실행 중 | 'public' 커뮤니티: $(if($snmpComm){'사용 중'}else{'미사용'})"
        $action   = if ($null -ne $snmpComm) { "SNMP 서비스 속성 > 보안 탭에서 'public' 커뮤니티 문자열 제거 후 고유 이름으로 변경" } else { "" }
    } else {
        $status = "N/A"; $detail = "SNMP 서비스 미설치 또는 중지 상태"; $action = ""
    }
    Add-Result "A-04" "행안부" "SNMP 커뮤니티 스트링 'public' 변경" `
        "'public' 기본 커뮤니티 미사용 시 정상 (SNMP 미사용 시 N/A)" $status $detail $action
    Write-CheckResult "A-04" "SNMP 커뮤니티 스트링 변경" $status

    # A-05 CMD.exe 실행 권한 제한 (Administrators 소유)
    # 일반 사용자의 cmd.exe 실행을 차단하여 명령어 기반 공격 방지
    $cmdPath = "$env:SystemRoot\System32\cmd.exe"
    if (Test-Path $cmdPath) {
        $cmdAcl    = Get-Acl $cmdPath -EA SilentlyContinue
        $cmdOwner  = $cmdAcl.Owner
        $allUsers  = $cmdAcl.Access | Where-Object { $_.IdentityReference -match "Everyone|모든 사용자|Users|사용자" -and $_.FileSystemRights -match "Execute|FullControl" }
        $status    = if ($allUsers) { "주의" } else { "정상" }
        Add-Result "A-05" "행안부" "CMD.exe 실행 권한 제한" `
            "일반 사용자(Users/Everyone) 실행 권한 없으면 정상" $status `
            "소유자: $cmdOwner | 일반사용자 실행권한: $(if($allUsers){'있음'}else{'없음'})" `
            $(if($allUsers){"cmd.exe 속성 > 보안 탭에서 Users 그룹 실행 권한 제거"} else {""})
        Write-CheckResult "A-05" "CMD.exe 실행 권한 제한" $status
    } else {
        Add-Result "A-05" "행안부" "CMD.exe 실행 권한 제한" "일반 사용자 실행 권한 없으면 정상" "N/A" "cmd.exe 파일 없음" ""
        Write-CheckResult "A-05" "CMD.exe 실행 권한 제한" "N/A"
    }

    # A-06 화면 보호기 패스워드 보호 설정
    # 자리 비울 때 무단 접근 방지 - 화면 보호기 및 잠금 설정
    $scrTimeout  = Get-RegVal "HKCU:\Control Panel\Desktop" "ScreenSaveTimeOut"
    $scrActive   = Get-RegVal "HKCU:\Control Panel\Desktop" "ScreenSaveActive"
    $scrSecure   = Get-RegVal "HKCU:\Control Panel\Desktop" "ScreenSaverIsSecure"
    $scrOk = ($scrActive -eq "1" -and $scrSecure -eq "1" -and ([int](if($null -ne $scrTimeout){$scrTimeout}else{9999})) -le 600)
    $status = if ($scrOk) { "정상" } else { "주의" }
    Add-Result "A-06" "행안부" "화면 보호기 패스워드 보호 설정" `
        "화면 보호기 활성화 + 잠금 + 대기시간 10분 이하 시 정상" $status `
        "활성화: $(if($null -ne $scrActive){$scrActive}else{'미설정'}) | 잠금: $(if($null -ne $scrSecure){$scrSecure}else{'미설정'}) | 대기: $(if($null -ne $scrTimeout){$scrTimeout}else{'미설정'})초" `
        $(if(-not $scrOk){"설정 > 잠금 화면 > 화면 보호기 설정 > 활성화 + 패스워드 보호 + 대기 10분 이하"} else {""})
    Write-CheckResult "A-06" "화면 보호기 패스워드 보호" $status

    # A-07 원격 데스크탑 NLA(네트워크 수준 인증) 활성화
    # NLA 미설정 시 인증 전 RDP 세션 수립으로 DoS 및 무차별 대입 공격에 취약
    $rdpDeny = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections"
    $rdpEnabled = ($rdpDeny -eq 0)
    if ($rdpEnabled) {
        $nlaReg = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication"
        $status = if ($nlaReg -eq 1) { "정상" } else { "주의" }
        $detail = "RDP 활성화 | NLA(네트워크 수준 인증): $(if($nlaReg -eq 1){'활성화'}else{'비활성화'})"
        $action = if ($nlaReg -ne 1) { "sysdm.cpl > 원격 탭 > '네트워크 수준 인증을 사용하는 원격 데스크톱' 선택" } else { "" }
    } else {
        $status = "N/A"; $detail = "RDP 비활성화 상태 - NLA 점검 불필요"; $action = ""
    }
    Add-Result "A-07" "행안부" "원격 데스크탑 NLA(네트워크 수준 인증)" `
        "RDP 사용 시 NLA 활성화 필수 (RDP 미사용 시 N/A)" $status $detail $action
    Write-CheckResult "A-07" "원격 데스크탑 NLA 활성화" $status

    # A-08 감사 정책 - 로그온/로그오프 성공·실패 모두 기록
    # 무차별 대입 공격, 권한 없는 접근 탐지에 필수
    $logonAudit = (auditpol /get /subcategory:"Logon" 2>$null) -join " "
    $logonBoth  = $logonAudit -match "성공 및 실패|Success and Failure"
    $logonSucc  = $logonAudit -match "성공|Success"
    $status = if ($logonBoth) { "정상" } elseif ($logonSucc) { "주의" } else { "경고" }
    Add-Result "A-08" "행안부" "감사 정책 - 로그온 성공/실패 기록" `
        "로그온 성공 및 실패 모두 감사 시 정상" $status `
        "로그온 감사: $(if($logonBoth){'성공 및 실패'}elseif($logonSucc){'성공만'}else{'미설정'})" `
        $(if(-not $logonBoth){'auditpol /set /subcategory:"Logon" /success:enable /failure:enable'} else {""})
    Write-CheckResult "A-08" "감사 정책 로그온 기록" $status

    # A-09 IIS 웹 서비스 디렉터리 리스팅 제한
    # 디렉터리 리스팅 허용 시 서버 파일 구조 노출 및 샘플 파일 경로 파악 가능
    $iisSvc = Get-Service -Name "W3SVC" -EA SilentlyContinue
    if ($iisSvc -and $iisSvc.Status -eq "Running") {
        try {
            Import-Module WebAdministration -EA Stop
            $dirBrowse = (Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/directoryBrowse" -name "enabled" -EA SilentlyContinue).Value
            $status = if ($dirBrowse -eq $false) { "정상" } else { "경고" }
            $detail = "IIS 실행 중 | 디렉터리 탐색(리스팅): $(if($dirBrowse){'허용됨'}else{'차단됨'})"
            $action = if ($dirBrowse) { "IIS 관리자 > 기본 웹 사이트 > 디렉터리 검색 > 비활성화`nSet-WebConfigurationProperty -filter system.webServer/directoryBrowse -name enabled -value false" } else { "" }
        } catch {
            $status = "확인필요"; $detail = "IIS 실행 중 - WebAdministration 모듈로 수동 확인 필요"; $action = "IIS 관리자 > 디렉터리 검색 기능 비활성화 여부 수동 확인"
        }
    } else {
        $status = "N/A"; $detail = "IIS(W3SVC) 미설치 또는 중지 상태"; $action = ""
    }
    Add-Result "A-09" "행안부" "IIS 웹 서비스 디렉터리 리스팅 제한" `
        "디렉터리 탐색 비활성화 시 정상 (IIS 미사용 시 N/A)" $status $detail $action
    Write-CheckResult "A-09" "IIS 디렉터리 리스팅 제한" $status

    # A-10 Kerberos 공격 차단 - NTP 서버 시간 동기화 (W32Time 외부 소스)
    # Kerberos 인증은 시간 차이 5분 이내 요구 - NTP 미동기화 시 인증 우회 가능
    $ntpSource  = (w32tm /query /source 2>$null) -join "" -replace "\s",""
    $ntpStatus  = (w32tm /query /status 2>$null) -join "`n"
    $isExternal = $ntpSource -notmatch "Local|로컬|VM" -and $ntpSource -match "\.|ntp|time"
    $timeDiff   = if ($ntpStatus -match "RootDelay:\s*([\d\.\-]+)") { [math]::Abs([double]$matches[1]) } else { 999 }
    $status     = if ($isExternal -and $timeDiff -lt 5) { "정상" } elseif ($isExternal) { "주의" } else { "경고" }
    Add-Result "A-10" "행안부" "Kerberos 방어 - NTP 외부 시간 동기화" `
        "외부 NTP 서버 동기화 + 시간차 5분 이내 시 정상" $status `
        "NTP 소스: $ntpSource | 지연: $(if($timeDiff -lt 999){"${timeDiff}초"}else{'확인불가'})" `
        $(if($status -ne "정상"){"w32tm /config /manualpeerlist:time.windows.com /syncfromflags:manual /reliable:yes /update && w32tm /resync /force"} else {""})
    Write-CheckResult "A-10" "Kerberos 방어 NTP 동기화" $status
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  HTML 보고서 생성
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
function New-HtmlReport {
    param([hashtable]$ServerInfo, [string]$OutPath)

    $total    = $Global:Results.Count
    $normal   = $Global:CntNormal
    $warning  = $Global:CntWarning
    $critical = $Global:CntCritical
    $manual   = $Global:CntManual
    $na       = $Global:CntNA
    $score    = if ($total -gt 0) { [math]::Round($normal / $total * 100, 1) } else { 0 }

    $catStats = $Global:Results | Group-Object Category | ForEach-Object {
        $n = ($_.Group | Where-Object {$_.Status -eq "정상"}).Count
        $w = ($_.Group | Where-Object {$_.Status -eq "주의"}).Count
        $c = ($_.Group | Where-Object {$_.Status -eq "경고"}).Count
        $t = $_.Count
        [PSCustomObject]@{ Name=$_.Name; Total=$t; Normal=$n; Warning=$w; Critical=$c; Rate=[math]::Round($n/$t*100,0) }
    }

    $catRows = ($catStats | ForEach-Object {
        $rateColor = if ($_.Rate -ge 80) { "#27ae60" } elseif ($_.Rate -ge 50) { "#f39c12" } else { "#e74c3c" }
        "<tr><td>$($_.Name)</td><td>$($_.Total)</td><td class='s-normal'>$($_.Normal)</td><td class='s-warn'>$($_.Warning)</td><td class='s-crit'>$($_.Critical)</td><td><div class='bar-wrap'><div class='bar' style='width:$($_.Rate)%;background:$rateColor'></div><span>$($_.Rate)%</span></div></td></tr>"
    }) -join "`n"

    $detailRows = ($Global:Results | ForEach-Object {
        $sc = switch ($_.Status) { "정상"{"s-normal"} "주의"{"s-warn"} "경고"{"s-crit"} "N/A"{"s-na"} default{"s-manual"} }
        $det = [System.Web.HttpUtility]::HtmlEncode($_.Detail) -replace "`n","<br>"
        $act = [System.Web.HttpUtility]::HtmlEncode($_.Action) -replace "`n","<br>"
        $tit = [System.Web.HttpUtility]::HtmlEncode($_.Title)
        $std = [System.Web.HttpUtility]::HtmlEncode($_.Standard)
        "<tr><td class='id'>$($_.ID)</td><td>$($_.Category)</td><td class='title'>$tit</td><td class='std'>$std</td><td class='status $sc'>$($_.Status)</td><td class='detail'>$det</td><td class='action'>$act</td></tr>"
    }) -join "`n"

    $issueRows = ($Global:Results | Where-Object { $_.Status -in @("주의","경고") } | ForEach-Object {
        $tit = [System.Web.HttpUtility]::HtmlEncode($_.Title)
        $act = [System.Web.HttpUtility]::HtmlEncode($_.Action) -replace "`n","<br>"
        $sc  = if ($_.Status -eq "경고") { "crit" } else { "warn" }
        "<div class='issue-item $sc'><h4>[$($_.ID)] $tit <span class='badge $sc'>$($_.Status)</span></h4><p>$act</p></div>"
    }) -join "`n"

    $scoreColor = if ($score -ge 80) { "#27ae60" } elseif ($score -ge 60) { "#f39c12" } else { "#e74c3c" }

    $html = @"
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Windows 서버 정기점검 결과</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'맑은 고딕','Malgun Gothic',sans-serif;background:#f0f2f5;color:#2c3e50;font-size:13px}
.container{max-width:1400px;margin:0 auto;padding:20px}
header{background:linear-gradient(135deg,#1a1a2e 0%,#16213e 50%,#0f3460 100%);color:#fff;padding:30px 40px;border-radius:12px;margin-bottom:24px;box-shadow:0 4px 20px rgba(0,0,0,.3)}
header h1{font-size:24px;margin-bottom:8px;letter-spacing:1px}
header p{font-size:12px;opacity:.8}
.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:8px;margin-top:16px}
.info-item{background:rgba(255,255,255,.1);border-radius:6px;padding:8px 12px}
.info-item label{font-size:10px;opacity:.7;display:block}
.info-item span{font-size:13px;font-weight:600}
.summary{display:grid;grid-template-columns:200px 1fr;gap:20px;margin-bottom:24px}
.score-card{background:#fff;border-radius:12px;padding:24px;text-align:center;box-shadow:0 2px 12px rgba(0,0,0,.08);display:flex;flex-direction:column;align-items:center;justify-content:center}
.score-num{font-size:56px;font-weight:700;color:$scoreColor;line-height:1}
.score-label{font-size:12px;color:#7f8c8d;margin-top:4px}
.stat-cards{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}
.stat-card{background:#fff;border-radius:12px;padding:16px;text-align:center;box-shadow:0 2px 12px rgba(0,0,0,.08)}
.stat-card .num{font-size:32px;font-weight:700;line-height:1}
.stat-card .lbl{font-size:11px;color:#7f8c8d;margin-top:4px}
.stat-card.s-normal .num{color:#27ae60}
.stat-card.s-warn .num{color:#f39c12}
.stat-card.s-crit .num{color:#e74c3c}
.stat-card.s-manual .num{color:#3498db}
.stat-card.s-na .num{color:#95a5a6}
.card{background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08);margin-bottom:20px;overflow:hidden}
.card-header{background:linear-gradient(90deg,#1a1a2e,#0f3460);color:#fff;padding:14px 20px;font-size:14px;font-weight:700;letter-spacing:.5px}
table{width:100%;border-collapse:collapse}
th{background:#f8f9fa;padding:10px 12px;text-align:left;font-size:11px;font-weight:700;color:#5a6475;border-bottom:2px solid #e9ecef;white-space:nowrap}
td{padding:9px 12px;border-bottom:1px solid #f0f0f0;vertical-align:top;line-height:1.5}
tr:hover td{background:#f8faff}
td.id{font-weight:700;color:#2980b9;white-space:nowrap;font-size:12px}
td.title{font-weight:600;min-width:180px}
td.std{color:#555;font-size:12px;min-width:160px}
td.detail{max-width:300px;font-size:12px;color:#444;word-break:break-all}
td.action{max-width:280px;font-size:12px;color:#c0392b;background:#fff9f9;word-break:break-all}
td.status{text-align:center;font-weight:700;white-space:nowrap;font-size:12px}
td.s-normal{color:#27ae60} td.s-warn{color:#f39c12;background:#fffbf0}
td.s-crit{color:#e74c3c;background:#fff5f5} td.s-na{color:#95a5a6} td.s-manual{color:#3498db}
.bar-wrap{display:flex;align-items:center;gap:8px}
.bar{height:14px;border-radius:7px;min-width:4px}
.bar-wrap span{font-size:12px;font-weight:700;white-space:nowrap}
.filter-bar{padding:12px 20px;background:#f8f9fa;border-bottom:1px solid #e9ecef;display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.filter-btn{padding:5px 14px;border:1px solid #ddd;border-radius:20px;background:#fff;cursor:pointer;font-size:12px;transition:all .2s}
.filter-btn:hover,.filter-btn.active{background:#0f3460;color:#fff;border-color:#0f3460}
.search-box{padding:5px 12px;border:1px solid #ddd;border-radius:20px;font-size:12px;width:220px}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700}
.badge.warn{background:#fef9e7;color:#f39c12;border:1px solid #f39c12}
.badge.crit{background:#fde8e8;color:#e74c3c;border:1px solid #e74c3c}
.issue-item{border-left:4px solid;padding:10px 14px;margin-bottom:10px;border-radius:0 8px 8px 0}
.issue-item.crit{border-color:#e74c3c;background:#fff5f5}
.issue-item.warn{border-color:#f39c12;background:#fffbf0}
.issue-item h4{font-size:13px;margin-bottom:4px}
.issue-item.crit h4{color:#c0392b}
.issue-item.warn h4{color:#d35400}
.issue-item p{font-size:12px;color:#555;line-height:1.6}
.issue-list{padding:16px 20px}
@media print{body{background:#fff}.container{padding:0}header{border-radius:0}.card{box-shadow:none;border:1px solid #ddd}}
</style>
</head>
<body>
<div class="container">
<header>
  <h1>🖥️ Windows 서버 정기점검 결과</h1>
  <p>서버 정기점검 표준 항목 기반 | 시스템/CPU/메모리/디스크/서비스/로그/네트워크/보안</p>
  <div class="info-grid">
    <div class="info-item"><label>서버명</label><span>$($ServerInfo.Hostname)</span></div>
    <div class="info-item"><label>IP 주소</label><span>$($ServerInfo.IP)</span></div>
    <div class="info-item"><label>운영체제</label><span>$($ServerInfo.OS)</span></div>
    <div class="info-item"><label>점검 일시</label><span>$($ServerInfo.DateTime)</span></div>
    <div class="info-item"><label>점검자</label><span>$($ServerInfo.Auditor)</span></div>
    <div class="info-item"><label>점검 버전</label><span>v1.1 (55항목 / 행안부 기준 포함)</span></div>
  </div>
</header>

<div class="summary">
  <div class="score-card">
    <div class="score-num">$score</div>
    <div class="score-label">정상 비율 (%)</div>
  </div>
  <div>
    <div class="stat-cards">
      <div class="stat-card"><div class="num">$total</div><div class="lbl">전체 항목</div></div>
      <div class="stat-card s-normal"><div class="num">$normal</div><div class="lbl">정상</div></div>
      <div class="stat-card s-warn"><div class="num">$warning</div><div class="lbl">주의</div></div>
      <div class="stat-card s-crit"><div class="num">$critical</div><div class="lbl">경고</div></div>
      <div class="stat-card s-manual"><div class="num">$manual</div><div class="lbl">확인필요</div></div>
    </div>
  </div>
</div>

<div class="card">
  <div class="card-header">📊 카테고리별 점검 결과</div>
  <table>
    <thead><tr><th>분류</th><th>전체</th><th>정상</th><th>주의</th><th>경고</th><th style="min-width:200px">정상률</th></tr></thead>
    <tbody>$catRows</tbody>
  </table>
</div>

<div class="card">
  <div class="card-header">⚠️ 조치 필요 항목 ($($warning+$critical)건)</div>
  <div class="issue-list">
    $(if($issueRows){$issueRows}else{"<p style='color:#27ae60;padding:10px'>조치가 필요한 항목이 없습니다.</p>"})
  </div>
</div>

<div class="card">
  <div class="card-header">📋 상세 점검 결과</div>
  <div class="filter-bar">
    <button class="filter-btn active" onclick="filterTable('all')">전체 ($total)</button>
    <button class="filter-btn" onclick="filterTable('s-normal')">정상 ($normal)</button>
    <button class="filter-btn" onclick="filterTable('s-warn')">주의 ($warning)</button>
    <button class="filter-btn" onclick="filterTable('s-crit')">경고 ($critical)</button>
    <button class="filter-btn" onclick="filterTable('s-manual')">확인필요 ($manual)</button>
    <input class="search-box" type="text" placeholder="검색..." oninput="searchTable(this.value)">
  </div>
  <table id="mainTable">
    <thead><tr><th>항목ID</th><th>분류</th><th>점검 항목</th><th>판단 기준</th><th>결과</th><th>상세 내용</th><th>조치 권고사항</th></tr></thead>
    <tbody>$detailRows</tbody>
  </table>
</div>

<div style="text-align:center;padding:20px;color:#aaa;font-size:11px">
  Generated by Windows Server Maintenance v1.0 | $($ServerInfo.DateTime)
</div>
</div>
<script>
function filterTable(f){
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('#mainTable tbody tr').forEach(r=>{
    const s=r.querySelector('.status');
    if(!s)return;
    const cls=s.className.replace('status ','').trim();
    r.style.display=(f==='all'||cls===f)?'':'none';
  });
}
function searchTable(q){
  const lq=q.toLowerCase();
  document.querySelectorAll('#mainTable tbody tr').forEach(r=>{
    r.style.display=r.textContent.toLowerCase().includes(lq)?'':'none';
  });
}
</script>
</body>
</html>
"@
    $html | Out-File -LiteralPath $OutPath -Encoding UTF8
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CSV 보고서 생성
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
function New-CsvReport([string]$OutPath) {
    $Global:Results | ForEach-Object {
        [PSCustomObject]@{
            항목ID      = $_.ID
            분류        = $_.Category
            점검항목    = $_.Title
            판단기준    = $_.Standard
            점검결과    = $_.Status
            상세내용    = $_.Detail -replace "`n"," | "
            조치권고사항 = $_.Action -replace "`n"," | "
        }
    } | Export-Csv -LiteralPath $OutPath -Encoding UTF8 -NoTypeInformation
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  메인 실행
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Add-Type -AssemblyName System.Web

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║         Windows 서버 정기점검 자동화 프로그램               ║" -ForegroundColor Cyan
Write-Host "  ║  시스템/CPU/메모리/디스크/서비스/로그/네트워크/보안 점검    ║" -ForegroundColor Cyan
Write-Host "  ║  v1.1  |  55항목  |  행정안전부 점검 기준 포함             ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

$hostname = $env:COMPUTERNAME
$ip = (Get-NetIPAddress -AddressFamily IPv4 -EA SilentlyContinue | Where-Object {$_.InterfaceAlias -notmatch "Loopback"} | Select-Object -First 1).IPAddress
$osInfo = (Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue).Caption
$auditor = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

$ServerInfo = @{
    Hostname = $hostname
    IP       = if ($ip) { $ip } else { "확인불가" }
    OS       = if ($osInfo) { $osInfo } else { [System.Environment]::OSVersion.VersionString }
    DateTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Auditor  = $auditor
}

Write-Host ""
Write-Host "  서버: $hostname ($($ServerInfo.IP)) | OS: $($ServerInfo.OS)" -ForegroundColor DarkGray
Write-Host "  점검 시작: $($ServerInfo.DateTime)" -ForegroundColor DarkGray

# 점검 실행
Check-SystemInfo
Check-CPU
Check-Memory
Check-Disk
Check-Services
Check-WindowsUpdate
Check-EventLog
Check-Network
Check-TasksAndAccounts
Check-SecurityBasic
Check-Miscellaneous
Check-MogaItems

# 결과 요약
$total = $Global:Results.Count
Write-Host ""
Write-Host "  ═══════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host "  점검 완료: 전체 ${total}항목" -ForegroundColor White
Write-Host "  정상: $($Global:CntNormal)  " -NoNewline -ForegroundColor Green
Write-Host "주의: $($Global:CntWarning)  " -NoNewline -ForegroundColor Yellow
Write-Host "경고: $($Global:CntCritical)  " -NoNewline -ForegroundColor Red
Write-Host "확인필요: $($Global:CntManual)  " -NoNewline -ForegroundColor Blue
Write-Host "N/A: $($Global:CntNA)" -ForegroundColor DarkGray
Write-Host "  ═══════════════════════════════════════════════════" -ForegroundColor DarkGray

# ── 네트워크 공유 설정 ────────────────────────────────────────────
$NasShare = "\\10.60.8.169\Server_maintenance"
$NasUser  = "maintenance"
$NasPass  = "veQ5vU3&"

# ── 파일명: [호스트명]_[IP]_[날짜] ──────────────────────────────
$dateStr  = (Get-Date).ToString("yyyyMMdd")
$safeIp   = ($ServerInfo.IP) -replace '[:/\\]', '-'
$baseName = "${hostname}_${safeIp}_${dateStr}"
$htmlPath = "$OutputDir\${baseName}.html"
$csvPath  = "$OutputDir\${baseName}.csv"

# ── 로컬 저장 ─────────────────────────────────────────────────────
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
New-HtmlReport -ServerInfo $ServerInfo -OutPath $htmlPath
New-CsvReport  -OutPath $csvPath

Write-Host ""
Write-Host "  보고서 저장 완료:" -ForegroundColor Cyan
Write-Host "    HTML: $htmlPath" -ForegroundColor White
Write-Host "    CSV : $csvPath" -ForegroundColor White

# ── 네트워크 공유 저장 ────────────────────────────────────────────
Write-Host ""
Write-Host "  네트워크 공유 저장 중... ($NasShare)" -ForegroundColor Cyan
$netOut = (net use $NasShare /user:$NasUser $NasPass 2>&1) -join " "
$connected = ($LASTEXITCODE -eq 0) -or ($netOut -match "이미 연결|already")
if (-not $connected) {
    # 이미 연결된 경우 재시도
    net use $NasShare /delete /yes 2>&1 | Out-Null
    $netOut    = (net use $NasShare /user:$NasUser $NasPass 2>&1) -join " "
    $connected = ($LASTEXITCODE -eq 0)
}
if ($connected) {
    try {
        Copy-Item -LiteralPath $htmlPath -Destination "$NasShare\${baseName}.html" -Force -EA Stop
        Copy-Item -LiteralPath $csvPath  -Destination "$NasShare\${baseName}.csv"  -Force -EA Stop
        Write-Host "    공유 저장 완료: $NasShare\$baseName.*" -ForegroundColor Green
    } catch {
        Write-Host "    [경고] 공유 저장 실패: $_" -ForegroundColor Yellow
    } finally {
        net use $NasShare /delete /yes 2>&1 | Out-Null
    }
} else {
    Write-Host "    [경고] 네트워크 공유 연결 실패 — 로컬에만 저장됨" -ForegroundColor Yellow
    Write-Host "    $netOut" -ForegroundColor DarkGray
}

if (-not $NoOpen -and (Test-Path $htmlPath)) {
    Start-Process $htmlPath
}
Write-Host ""
