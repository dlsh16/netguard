#Requires -Version 5.1
<#
.SYNOPSIS
    Windows 서버 보안 취약점 자동 진단 프로그램
.DESCRIPTION
    KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준 (Windows) 기반
    ISO 27001:2022 / ISMS-P (2023-1호 고시) / KISA 2026년 04월 기준 반영
    Python/외부 라이브러리 불필요 - PowerShell 5.1 이상이면 단독 실행 가능
    점검 항목: 70개 (계정관리 18 + 접근관리 22 + 패치관리 3 + 로그관리 4 + 기능관리 20 + 최신CVE 3)
.NOTES
    관리자 권한 실행 필요
    실행: powershell -ExecutionPolicy Bypass -File CVE_Check.ps1
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

function Add-Result {
    param(
        [string]$ID,
        [string]$Category,
        [string]$Title,
        [string]$Description,
        [string]$Standard,
        [string]$Risk,        # 상/중/하
        [string]$Status,      # 양호/취약/N/A/확인필요/오류
        [string]$Detail,
        [string]$Action = ""
    )
    $Global:Results.Add(@{
        ID          = $ID
        Category    = $Category
        Title       = $Title
        Description = $Description
        Standard    = $Standard
        Risk        = $Risk
        Status      = $Status
        Detail      = $Detail
        Action      = $Action
    })
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  콘솔 출력 헬퍼
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
function Write-Section([string]$Title) {
    Write-Host "`n  " -NoNewline
    Write-Host "▶ $Title" -ForegroundColor Cyan
    Write-Host "  " + ("─" * 62) -ForegroundColor DarkGray
}

function Write-CheckResult([string]$ID, [string]$Title, [string]$Status) {
    $padID    = $ID.PadRight(7)
    $padTitle = $Title.PadRight(42).Substring(0,42)
    Write-Host "    $padID $padTitle " -NoNewline
    switch ($Status) {
        "양호"    { Write-Host "[ 양호 ]" -ForegroundColor Green }
        "취약"    { Write-Host "[ 취약 ]" -ForegroundColor Red }
        "N/A"     { Write-Host "[ N/A  ]" -ForegroundColor Yellow }
        "확인필요" { Write-Host "[ 확인 ]" -ForegroundColor Yellow }
        default   { Write-Host "[ 오류 ]" -ForegroundColor DarkGray }
    }
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  레지스트리 / 서비스 헬퍼
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
function Get-RegVal([string]$Path, [string]$Name) {
    try { return (Get-ItemProperty -Path $Path -Name $Name -EA Stop).$Name }
    catch { return $null }
}

function Get-SvcStatus([string]$Name) {
    $s = Get-Service -Name $Name -EA SilentlyContinue
    if (-not $s) { return "NotInstalled" }
    return $s.Status.ToString()
}

function Get-SvcStartType([string]$Name) {
    $s = Get-Service -Name $Name -EA SilentlyContinue
    if (-not $s) { return "NotInstalled" }
    return $s.StartType.ToString()
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  1. 계정 관리 (W-01 ~ W-18)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
function Check-AccountManagement {
    Write-Section "계정 관리"

    # W-01 Administrator 계정 이름 변경
    $adminUser = Get-LocalUser | Where-Object { $_.SID -like "S-1-5-*-500" }
    $adminName = if ($adminUser) { $adminUser.Name } else { "확인불가" }
    $status = if ($adminName -notin @("Administrator","administrator","관리자")) { "양호" } else { "취약" }
    Add-Result "W-01" "계정 관리" "Administrator 계정 이름 변경" `
        "기본 Administrator 계정 이름 변경 여부" `
        "기본명('Administrator') 외 다른 이름 사용 시 양호" "중" $status `
        "현재 내장 관리자 계정명: $adminName" `
        $(if($status -eq "취약"){"secpol.msc > 보안 옵션 > '계정: Administrator 계정 이름 바꾸기'"} else {""})
    Write-CheckResult "W-01" "Administrator 계정 이름 변경" $status

    # W-02 Guest 계정 비활성화
    $guest = Get-LocalUser -Name "Guest" -EA SilentlyContinue
    $guestEnabled = if ($guest) { $guest.Enabled } else { $false }
    $status = if (-not $guestEnabled) { "양호" } else { "취약" }
    Add-Result "W-02" "계정 관리" "Guest 계정 비활성화" `
        "Guest 계정 활성화 여부 점검" "Guest 계정 비활성화 상태이면 양호" "상" $status `
        "Guest 계정 활성화: $guestEnabled" `
        $(if($status -eq "취약"){"net user guest /active:no"} else {""})
    Write-CheckResult "W-02" "Guest 계정 비활성화" $status

    # W-03 불필요한 계정 제거
    $activeUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true } |
        ForEach-Object { "$($_.Name) (마지막 로그온: $($_.LastLogon))" }
    $detail = "활성 계정 목록:`n" + ($activeUsers -join "`n")
    Add-Result "W-03" "계정 관리" "불필요한 계정 제거" `
        "장기 미사용 활성 계정 존재 여부" "90일 이상 미사용 계정 없으면 양호" "중" "확인필요" `
        $detail "장기 미사용 계정 비활성화 또는 삭제 (90일 기준)"
    Write-CheckResult "W-03" "불필요한 계정 제거" "확인필요"

    # W-04 관리자 그룹 최소화
    $admins = Get-LocalGroupMember -Group "Administrators" -EA SilentlyContinue |
        Select-Object -ExpandProperty Name
    $nonDefault = $admins | Where-Object { $_ -notmatch "Administrator|관리자" }
    $status = if (($nonDefault | Measure-Object).Count -le 1) { "양호" } else { "취약" }
    Add-Result "W-04" "계정 관리" "Administrators 그룹 최소화" `
        "Administrators 그룹 구성원 점검" "불필요한 계정 없으면 양호" "상" $status `
        "구성원: $($admins -join ', ')" `
        $(if($status -eq "취약"){"Administrators 그룹에서 불필요한 계정 제거"} else {""})
    Write-CheckResult "W-04" "Administrators 그룹 최소화" $status

    # W-05 계정 잠금 임계값
    $netAcc = net accounts 2>$null
    $threshold = ($netAcc | Select-String "Lockout threshold|잠금 임계값") -replace ".*:\s*",""
    $threshNum = [int]($threshold -replace "\D","" -replace "^$","0")
    $status = if ($threshNum -gt 0 -and $threshNum -le 5) { "양호" } else { "취약" }
    Add-Result "W-05" "계정 관리" "계정 잠금 임계값" `
        "로그인 실패 시 계정 잠금 임계값 설정" "5회 이하로 설정 시 양호" "상" $status `
        "현재 임계값: $threshold" `
        $(if($status -eq "취약"){"secpol.msc > 계정 잠금 정책 > 임계값 5회 이하"} else {""})
    Write-CheckResult "W-05" "계정 잠금 임계값" $status

    # W-06 계정 잠금 기간
    $duration = ($netAcc | Select-String "Lockout duration|잠금 기간") -replace ".*:\s*",""
    $durNum = [int]($duration -replace "\D","" -replace "^$","0")
    $status = if ($durNum -ge 30) { "양호" } else { "취약" }
    Add-Result "W-06" "계정 관리" "계정 잠금 기간" `
        "계정 잠금 후 자동 해제 시간 설정" "30분 이상이면 양호" "중" $status `
        "현재 잠금 기간: $duration" `
        $(if($status -eq "취약"){"secpol.msc > 계정 잠금 정책 > 잠금 기간 30분 이상"} else {""})
    Write-CheckResult "W-06" "계정 잠금 기간" $status

    # W-07 로그온 실패 카운터 초기화 시간
    $resetTime = ($netAcc | Select-String "Lockout observation window|카운터 초기화") -replace ".*:\s*",""
    $resetNum = [int]($resetTime -replace "\D","" -replace "^$","0")
    $status = if ($resetNum -ge 30) { "양호" } else { "취약" }
    Add-Result "W-07" "계정 관리" "로그온 실패 카운터 초기화 시간" `
        "로그온 실패 카운터 초기화 시간 설정" "30분 이상이면 양호" "하" $status `
        "현재 초기화 시간: $resetTime" `
        $(if($status -eq "취약"){"secpol.msc > 계정 잠금 정책 > 관찰 기간 30분"} else {""})
    Write-CheckResult "W-07" "로그온 실패 카운터 초기화 시간" $status

    # W-08 최소 패스워드 길이
    $minLen = ($netAcc | Select-String "Minimum password length|최소 암호 길이") -replace ".*:\s*",""
    $minLenNum = [int]($minLen -replace "\D","" -replace "^$","0")
    $status = if ($minLenNum -ge 12) { "양호" } else { "취약" }
    Add-Result "W-08" "계정 관리" "최소 패스워드 길이" `
        "패스워드 최소 길이 설정 (ISMS-P 2.5.1 강화기준)" "12자 이상이면 양호" "상" $status `
        "현재 최소 길이: $minLen 자" `
        $(if($status -eq "취약"){"secpol.msc > 암호 정책 > 최소 암호 길이 12자 이상 (ISMS-P 강화기준)"} else {""})
    Write-CheckResult "W-08" "최소 패스워드 길이" $status

    # W-09 패스워드 복잡도
    $tmpCfg = "$env:TEMP\sec_audit.cfg"
    secedit /export /cfg $tmpCfg /quiet 2>$null
    $complexity = if (Test-Path $tmpCfg) {
        (Get-Content $tmpCfg | Select-String "PasswordComplexity") -replace ".*=\s*",""
    } else { "0" }
    $status = if ($complexity -eq "1") { "양호" } else { "취약" }
    Add-Result "W-09" "계정 관리" "패스워드 복잡도" `
        "대소문자+숫자+특수문자 복잡도 요구 설정" "복잡도 활성화 시 양호" "상" $status `
        "PasswordComplexity 값: $complexity" `
        $(if($status -eq "취약"){"secpol.msc > 암호 정책 > '암호는 복잡성을 만족해야 함' 활성화"} else {""})
    Write-CheckResult "W-09" "패스워드 복잡도" $status

    # W-10 패스워드 최대 사용 기간
    $maxAge = ($netAcc | Select-String "Maximum password age|최대 암호 사용 기간") -replace ".*:\s*",""
    $maxAgeNum = [int]($maxAge -replace "\D","" -replace "^$","999")
    $status = if ($maxAgeNum -gt 0 -and $maxAgeNum -le 90) { "양호" } else { "취약" }
    Add-Result "W-10" "계정 관리" "패스워드 최대 사용 기간" `
        "패스워드 변경 주기 설정" "90일 이하이면 양호 (0=무제한은 취약)" "중" $status `
        "현재 최대 사용 기간: $maxAge" `
        $(if($status -eq "취약"){"net accounts /maxpwage:90"} else {""})
    Write-CheckResult "W-10" "패스워드 최대 사용 기간" $status

    # W-11 패스워드 최소 사용 기간
    $minAge = ($netAcc | Select-String "Minimum password age|최소 암호 사용 기간") -replace ".*:\s*",""
    $minAgeNum = [int]($minAge -replace "\D","" -replace "^$","0")
    $status = if ($minAgeNum -ge 1) { "양호" } else { "취약" }
    Add-Result "W-11" "계정 관리" "패스워드 최소 사용 기간" `
        "패스워드 변경 후 재변경 최소 기간 설정" "1일 이상이면 양호" "하" $status `
        "현재 최소 사용 기간: $minAge" `
        $(if($status -eq "취약"){"net accounts /minpwage:1"} else {""})
    Write-CheckResult "W-11" "패스워드 최소 사용 기간" $status

    # W-12 이전 패스워드 기억
    $history = ($netAcc | Select-String "password history|암호 기록") -replace ".*:\s*",""
    $histNum = [int]($history -replace "\D","" -replace "^$","0")
    $status = if ($histNum -ge 3) { "양호" } else { "취약" }
    Add-Result "W-12" "계정 관리" "이전 패스워드 기억" `
        "패스워드 재사용 방지 설정" "이전 3개 이상 기억 시 양호" "중" $status `
        "현재 기억 개수: $history 개" `
        $(if($status -eq "취약"){"net accounts /uniquepw:3"} else {""})
    Write-CheckResult "W-12" "이전 패스워드 기억" $status

    # W-13 자동 로그온 비활성화
    $autoLogon = Get-RegVal "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AutoAdminLogon"
    $status = if ($autoLogon -ne "1") { "양호" } else { "취약" }
    Add-Result "W-13" "계정 관리" "자동 로그온 비활성화" `
        "시스템 자동 로그온 설정 여부 점검" "자동 로그온 비활성화 시 양호" "상" $status `
        "AutoAdminLogon 값: $autoLogon" `
        $(if($status -eq "취약"){"HKLM\...\Winlogon\AutoAdminLogon = 0"} else {""})
    Write-CheckResult "W-13" "자동 로그온 비활성화" $status

    # W-14 마지막 로그온 사용자 이름 표시 안 함
    $dontDisplay = Get-RegVal "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DontDisplayLastUserName"
    $status = if ($dontDisplay -eq 1) { "양호" } else { "취약" }
    Add-Result "W-14" "계정 관리" "마지막 로그온 사용자 이름 숨김" `
        "로그온 화면에 마지막 사용자 이름 표시 여부" "표시 안 함(1) 설정 시 양호" "중" $status `
        "DontDisplayLastUserName: $dontDisplay" `
        $(if($status -eq "취약"){"secpol.msc > 보안 옵션 > '대화형 로그온: 마지막 로그인한 사용자 이름 표시 안 함'"} else {""})
    Write-CheckResult "W-14" "마지막 로그온 사용자 이름 숨김" $status

    # W-15 Ctrl+Alt+Del 로그온 요구
    $cad = Get-RegVal "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableCAD"
    $status = if ($cad -ne 1) { "양호" } else { "취약" }
    Add-Result "W-15" "계정 관리" "Ctrl+Alt+Del 로그온 요구" `
        "로그온 시 Ctrl+Alt+Del 요구 설정" "Ctrl+Alt+Del 요구 활성화 시 양호" "중" $status `
        "DisableCAD 값: $cad" `
        $(if($status -eq "취약"){"secpol.msc > 보안 옵션 > '대화형 로그온: Ctrl+Alt+Del 필요'"} else {""})
    Write-CheckResult "W-15" "Ctrl+Alt+Del 로그온 요구" $status

    # W-16 로컬 계정 빈 암호 사용 제한
    $limitBlank = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LimitBlankPasswordUse"
    $status = if ($limitBlank -eq 1) { "양호" } else { "취약" }
    Add-Result "W-16" "계정 관리" "빈 암호 로컬 계정 제한" `
        "빈 암호 계정의 콘솔 로그온만 허용 설정" "LimitBlankPasswordUse=1 이면 양호" "상" $status `
        "LimitBlankPasswordUse: $limitBlank" `
        $(if($status -eq "취약"){"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse = 1"} else {""})
    Write-CheckResult "W-16" "빈 암호 로컬 계정 제한" $status

    # W-17 화면 보호기 설정
    $ssActive  = Get-RegVal "HKCU:\Control Panel\Desktop" "ScreenSaveActive"
    $ssSecure  = Get-RegVal "HKCU:\Control Panel\Desktop" "ScreenSaverIsSecure"
    $ssTimeout = [int]((Get-RegVal "HKCU:\Control Panel\Desktop" "ScreenSaveTimeOut") -replace "\D","" -replace "^$","9999")
    $status = if ($ssActive -eq "1" -and $ssSecure -eq "1" -and $ssTimeout -le 600) { "양호" } else { "취약" }
    Add-Result "W-17" "계정 관리" "화면 보호기 보안 설정" `
        "화면 보호기 활성화 및 재개 시 암호 요구 설정" "활성화+잠금+10분이하 타임아웃이면 양호" "하" $status `
        "활성화:$ssActive, 잠금:$ssSecure, 타임아웃:${ssTimeout}초" `
        $(if($status -eq "취약"){"제어판 > 개인설정 > 화면 보호기 > 활성화 + '재개 시 로그온 화면' 체크 + 10분 이하"} else {""})
    Write-CheckResult "W-17" "화면 보호기 보안 설정" $status

    # W-18 LAPS (로컬 관리자 암호 솔루션) - 최신 트렌드
    $lapsReg  = Get-RegVal "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" "AdmPwdEnabled"
    $lapsReg2 = Get-RegVal "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" "BackupDirectory"
    $lapsInstalled = (Get-Module -ListAvailable -Name LAPS -EA SilentlyContinue) -ne $null
    $status = if ($lapsReg -eq 1 -or $lapsReg2 -ne $null -or $lapsInstalled) { "양호" } else { "취약" }
    Add-Result "W-18" "계정 관리" "LAPS(로컬 관리자 암호 솔루션)" `
        "로컬 관리자 암호 자동 관리(LAPS) 적용 여부" "LAPS 설치 및 활성화 시 양호" "상" $status `
        "AdmPwdEnabled:$lapsReg, BackupDirectory:$lapsReg2, 모듈:$lapsInstalled" `
        $(if($status -eq "취약"){"Microsoft LAPS 또는 Windows LAPS(Server 2022/Win 11 22H2+) 적용 권고`nhttps://learn.microsoft.com/windows-server/identity/laps/laps-overview"} else {""})
    Write-CheckResult "W-18" "LAPS(로컬 관리자 암호 솔루션)" $status
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  2. 접근 관리 (W-19 ~ W-40)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
function Check-AccessManagement {
    Write-Section "접근 관리"

    # W-19 익명 접근 제한 (SAM 열거)
    $restAnon    = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous"
    $restAnonSAM = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymousSAM"
    $status = if ($restAnon -ge 1 -and $restAnonSAM -eq 1) { "양호" } else { "취약" }
    Add-Result "W-19" "접근 관리" "SAM 계정 익명 열거 제한" `
        "익명 연결을 통한 SAM 계정/공유 열거 제한" "RestrictAnonymous>=1, RestrictAnonymousSAM=1 이면 양호" "상" $status `
        "RestrictAnonymous:$restAnon, RestrictAnonymousSAM:$restAnonSAM" `
        $(if($status -eq "취약"){"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa`nRestrictAnonymous=1, RestrictAnonymousSAM=1"} else {""})
    Write-CheckResult "W-19" "SAM 계정 익명 열거 제한" $status

    # W-20 LAN Manager 인증 수준 (NTLMv2)
    $lmLevel = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel"
    $status = if ($lmLevel -ge 4) { "양호" } else { "취약" }
    $lmDesc  = @{0="LM+NTLM(매우취약)";1="LM+NTLM+NTLMv2협상";2="NTLM만";3="NTLMv2만";4="NTLMv2만(LM거부)";5="NTLMv2만(LM+NTLM거부)"}
    Add-Result "W-20" "접근 관리" "LAN Manager 인증 수준(NTLMv2)" `
        "NTLMv2 이상 인증 강제 설정" "LmCompatibilityLevel 4 이상이면 양호" "상" $status `
        "현재 수준: $lmLevel - $($lmDesc[[int]$lmLevel])" `
        $(if($status -eq "취약"){"secpol.msc > 보안 옵션 > 'LAN 관리자 인증 수준' = NTLMv2만/LM+NTLM 거부(5)"} else {""})
    Write-CheckResult "W-20" "LAN Manager 인증 수준(NTLMv2)" $status

    # W-21 Null 세션 제한
    $nullSess = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RestrictNullSessAccess"
    $status = if ($nullSess -eq 1) { "양호" } else { "취약" }
    Add-Result "W-21" "접근 관리" "Null 세션 접근 제한" `
        "인증 없는 Null 세션 연결 제한 설정" "RestrictNullSessAccess=1 이면 양호" "상" $status `
        "RestrictNullSessAccess: $nullSess" `
        $(if($status -eq "취약"){"HKLM:\...\LanmanServer\Parameters\RestrictNullSessAccess = 1"} else {""})
    Write-CheckResult "W-21" "Null 세션 접근 제한" $status

    # W-22 원격 데스크톱(RDP) NLA 인증
    $rdpDeny = Get-RegVal "HKLM:\System\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections"
    $nlAuth  = Get-RegVal "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication"
    if ($rdpDeny -eq 1) {
        $status = "양호"; $detail = "RDP가 비활성화되어 있습니다."
    } elseif ($nlAuth -eq 1) {
        $status = "양호"; $detail = "RDP 활성화, NLA 인증 설정됨"
    } else {
        $status = "취약"; $detail = "RDP 활성화, NLA 미설정 (fDenyTS:$rdpDeny, NLA:$nlAuth)"
    }
    Add-Result "W-22" "접근 관리" "RDP NLA(네트워크 수준 인증)" `
        "원격 데스크톱 NLA 인증 활성화 여부" "RDP 비활성화 또는 NLA 활성화 시 양호" "상" $status $detail `
        $(if($status -eq "취약"){"시스템 속성 > 원격 > '네트워크 수준 인증을 사용하는 원격 데스크톱만 허용'"} else {""})
    Write-CheckResult "W-22" "RDP NLA(네트워크 수준 인증)" $status

    # W-23 RDP 포트 기본값 변경
    $rdpPort = Get-RegVal "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "PortNumber"
    $status = if ($rdpPort -ne 3389 -or $rdpDeny -eq 1) { "양호" } else { "취약" }
    Add-Result "W-23" "접근 관리" "RDP 기본 포트(3389) 변경" `
        "RDP 서비스 기본 포트 변경 여부" "기본 3389 외 포트 사용 또는 비활성화 시 양호" "중" $status `
        "현재 RDP 포트: $rdpPort" `
        $(if($status -eq "취약"){"RDP 포트를 3389 외 다른 포트로 변경 권고`nHKLM:\...\RDP-Tcp\PortNumber 수정 후 방화벽 룰 변경"} else {""})
    Write-CheckResult "W-23" "RDP 기본 포트(3389) 변경" $status

    # W-24 Windows 방화벽 활성화
    $fwProfiles = Get-NetFirewallProfile -EA SilentlyContinue
    $allEnabled = ($fwProfiles | Where-Object { $_.Enabled -eq $false } | Measure-Object).Count -eq 0
    $status = if ($allEnabled) { "양호" } else { "취약" }
    $fwDetail = ($fwProfiles | ForEach-Object { "$($_.Name): $($_.Enabled)" }) -join ", "
    Add-Result "W-24" "접근 관리" "Windows 방화벽 활성화" `
        "도메인/개인/공용 모든 프로파일 방화벽 활성화" "모든 프로파일 Enabled=True 이면 양호" "상" $status `
        $fwDetail `
        $(if($status -eq "취약"){"Set-NetFirewallProfile -All -Enabled True"} else {""})
    Write-CheckResult "W-24" "Windows 방화벽 활성화" $status

    # W-25 불필요한 공유 폴더 제거
    $nonAdminShares = Get-SmbShare -EA SilentlyContinue | Where-Object { $_.Name -notmatch '\$$' }
    $status = if (($nonAdminShares | Measure-Object).Count -eq 0) { "양호" } else { "취약" }
    $shareDetail = if ($nonAdminShares) { ($nonAdminShares | ForEach-Object {"$($_.Name) -> $($_.Path)"}) -join "`n" } else { "일반 공유 폴더 없음" }
    Add-Result "W-25" "접근 관리" "불필요한 공유 폴더 제거" `
        "업무 외 불필요한 네트워크 공유 폴더 점검" "불필요한 공유 없으면 양호" "중" $status `
        $shareDetail `
        $(if($status -eq "취약"){"불필요한 공유 제거: net share [공유명] /delete"} else {""})
    Write-CheckResult "W-25" "불필요한 공유 폴더 제거" $status

    # W-26 SMBv1 비활성화 (EternalBlue 취약점)
    $smb1 = Get-SmbServerConfiguration -EA SilentlyContinue | Select-Object -ExpandProperty EnableSMB1Protocol
    $status = if ($smb1 -eq $false) { "양호" } else { "취약" }
    Add-Result "W-26" "접근 관리" "SMBv1 비활성화 (EternalBlue)" `
        "SMBv1 프로토콜 비활성화 여부 (WannaCry/EternalBlue 취약점)" "SMBv1 비활성화 시 양호" "상" $status `
        "SMBv1 활성화 여부: $smb1" `
        $(if($status -eq "취약"){"Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force`n(재부팅 필요)"} else {""})
    Write-CheckResult "W-26" "SMBv1 비활성화 (EternalBlue)" $status

    # W-27 SMB 서명 활성화
    $smbSign = Get-SmbServerConfiguration -EA SilentlyContinue | Select-Object -ExpandProperty RequireSecuritySignature
    $status = if ($smbSign -eq $true) { "양호" } else { "취약" }
    Add-Result "W-27" "접근 관리" "SMB 서명(Signing) 활성화" `
        "SMB 패킷 서명 요구 설정 (중간자 공격 방지)" "RequireSecuritySignature=True 이면 양호" "상" $status `
        "SMB 서명 요구: $smbSign" `
        $(if($status -eq "취약"){"Set-SmbServerConfiguration -RequireSecuritySignature $true -Force"} else {""})
    Write-CheckResult "W-27" "SMB 서명(Signing) 활성화" $status

    # W-28 Telnet 서비스 비활성화
    $telnetStatus = Get-SvcStatus "TlntSvr"
    $status = if ($telnetStatus -in @("Stopped","NotInstalled")) { "양호" } else { "취약" }
    Add-Result "W-28" "접근 관리" "Telnet 서비스 비활성화" `
        "Telnet 서비스 실행 여부 (평문 전송 취약)" "중지 또는 미설치 시 양호" "상" $status `
        "Telnet 서비스 상태: $telnetStatus" `
        $(if($status -eq "취약"){"sc stop TlntSvr && sc config TlntSvr start=disabled"} else {""})
    Write-CheckResult "W-28" "Telnet 서비스 비활성화" $status

    # W-29 FTP 서비스 비활성화
    $ftpStatus = @("FTPSVC","MSFTPSVC") | ForEach-Object { Get-SvcStatus $_ } | Where-Object { $_ -eq "Running" }
    $status = if (-not $ftpStatus) { "양호" } else { "취약" }
    Add-Result "W-29" "접근 관리" "FTP 서비스 비활성화" `
        "FTP 서비스 실행 여부 (평문 계정 정보 전송)" "중지 또는 미설치 시 양호" "상" $status `
        "FTP 실행 중: $($ftpStatus -join ', ')" `
        $(if($status -eq "취약"){"FTP 대신 SFTP/FTPS 사용, FTP 서비스 비활성화"} else {""})
    Write-CheckResult "W-29" "FTP 서비스 비활성화" $status

    # W-30 SNMP 서비스 점검
    $snmpStatus = Get-SvcStatus "SNMP"
    if ($snmpStatus -eq "Running") {
        $snmpComm = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" "public"
        $status = if ($snmpComm -ne $null) { "취약" } else { "취약" }
        $detail = "SNMP 실행 중. 기본 커뮤니티 'public' 사용: $($snmpComm -ne $null)"
    } else {
        $status = "양호"; $detail = "SNMP 서비스 상태: $snmpStatus"
    }
    Add-Result "W-30" "접근 관리" "SNMP 서비스 및 커뮤니티 문자열" `
        "SNMP 서비스 실행 및 기본 커뮤니티 문자열 점검" "SNMP 비활성화 또는 커뮤니티 문자열 변경 시 양호" "중" $status $detail `
        $(if($status -eq "취약"){"SNMP 비활성화 또는 커뮤니티 문자열 변경 + SNMPv3 사용 권고"} else {""})
    Write-CheckResult "W-30" "SNMP 서비스 및 커뮤니티 문자열" $status

    # W-31 원격 레지스트리 서비스 비활성화
    $remReg = Get-SvcStatus "RemoteRegistry"
    $remRegStart = Get-SvcStartType "RemoteRegistry"
    $status = if ($remReg -in @("Stopped","NotInstalled") -and $remRegStart -in @("Disabled","NotInstalled")) { "양호" } else { "취약" }
    Add-Result "W-31" "접근 관리" "원격 레지스트리 서비스 비활성화" `
        "원격 레지스트리 편집 서비스 실행 여부" "중지 및 비활성화 시 양호" "상" $status `
        "상태:$remReg, 시작유형:$remRegStart" `
        $(if($status -eq "취약"){"sc stop RemoteRegistry && sc config RemoteRegistry start=disabled"} else {""})
    Write-CheckResult "W-31" "원격 레지스트리 서비스 비활성화" $status

    # W-32 LLMNR 비활성화 (Responder 공격 방어)
    $llmnr = Get-RegVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast"
    $status = if ($llmnr -eq 0) { "양호" } else { "취약" }
    Add-Result "W-32" "접근 관리" "LLMNR 비활성화" `
        "Link-Local Multicast Name Resolution 비활성화 (Responder/MITM 공격 방어)" "EnableMulticast=0 이면 양호" "중" $status `
        "EnableMulticast: $llmnr" `
        $(if($status -eq "취약"){"GPO: 컴퓨터구성 > 관리템플릿 > DNS 클라이언트 > '멀티캐스트 이름 해석 끄기' 활성화`n또는: HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast=0"} else {""})
    Write-CheckResult "W-32" "LLMNR 비활성화" $status

    # W-33 NetBIOS over TCP/IP 비활성화
    $nics = Get-WmiObject Win32_NetworkAdapterConfiguration -EA SilentlyContinue | Where-Object { $_.IPEnabled }
    $netbiosEnabled = $nics | Where-Object { $_.TcpipNetbiosOptions -ne 2 }
    $status = if (-not $netbiosEnabled) { "양호" } else { "취약" }
    Add-Result "W-33" "접근 관리" "NetBIOS over TCP/IP 비활성화" `
        "NetBIOS over TCP/IP 비활성화 여부" "모든 NIC에서 비활성화 시 양호" "중" $status `
        "NetBIOS 활성화 NIC 수: $(($netbiosEnabled | Measure-Object).Count)" `
        $(if($status -eq "취약"){"네트워크 어댑터 속성 > TCP/IPv4 > 고급 > WINS 탭 > 'NetBIOS over TCP/IP 비활성화'"} else {""})
    Write-CheckResult "W-33" "NetBIOS over TCP/IP 비활성화" $status

    # W-34 mDNS 비활성화
    $mdns = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" "EnableMDNS"
    $status = if ($mdns -eq 0) { "양호" } else { "취약" }
    Add-Result "W-34" "접근 관리" "mDNS 비활성화" `
        "Multicast DNS 비활성화 여부 (정보 노출 방지)" "EnableMDNS=0 이면 양호" "하" $status `
        "EnableMDNS: $mdns" `
        $(if($status -eq "취약"){"HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\EnableMDNS = 0"} else {""})
    Write-CheckResult "W-34" "mDNS 비활성화" $status

    # W-35 TLS 1.0/1.1 비활성화
    $tls10 = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" "Enabled"
    $tls11 = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" "Enabled"
    $status = if ($tls10 -eq 0 -and $tls11 -eq 0) { "양호" } else { "취약" }
    Add-Result "W-35" "접근 관리" "TLS 1.0/1.1 비활성화" `
        "취약한 TLS 버전(1.0, 1.1) 비활성화 여부" "TLS 1.0 및 1.1 비활성화 시 양호" "상" $status `
        "TLS 1.0: $tls10, TLS 1.1: $tls11" `
        $(if($status -eq "취약"){"SCHANNEL 레지스트리에서 TLS 1.0/1.1 Server/Client Enabled=0, DisabledByDefault=1 설정"} else {""})
    Write-CheckResult "W-35" "TLS 1.0/1.1 비활성화" $status

    # W-36 WDigest 인증 비활성화 (자격 증명 평문 메모리 저장 방지)
    $wdigest = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential"
    $status = if ($wdigest -eq 0) { "양호" } else { "취약" }
    Add-Result "W-36" "접근 관리" "WDigest 인증 비활성화" `
        "WDigest 인증 비활성화 (메모리 평문 자격증명 저장 방지, Mimikatz 대응)" "UseLogonCredential=0 이면 양호" "상" $status `
        "UseLogonCredential: $wdigest" `
        $(if($status -eq "취약"){"HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 0"} else {""})
    Write-CheckResult "W-36" "WDigest 인증 비활성화" $status

    # W-37 UAC(사용자 계정 컨트롤) 설정
    $uacEnabled    = Get-RegVal "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA"
    $uacBehavior   = Get-RegVal "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin"
    $status = if ($uacEnabled -eq 1 -and $uacBehavior -ge 2) { "양호" } else { "취약" }
    Add-Result "W-37" "접근 관리" "UAC(사용자 계정 컨트롤) 설정" `
        "UAC 활성화 및 관리자 권한 상승 동작 설정" "UAC 활성화 + 동의 프롬프트(2이상) 이면 양호" "중" $status `
        "EnableLUA:$uacEnabled, ConsentPromptBehaviorAdmin:$uacBehavior" `
        $(if($status -eq "취약"){"secpol.msc > 보안 옵션 > '사용자 계정 컨트롤: ...' 설정"} else {""})
    Write-CheckResult "W-37" "UAC(사용자 계정 컨트롤) 설정" $status

    # W-38 익명 SID/이름 변환 허용 안 함
    $anonSid = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "TurnOffAnonymousBlock"
    $status = if ($anonSid -ne 1) { "양호" } else { "취약" }
    Add-Result "W-38" "접근 관리" "익명 SID/이름 변환 허용 안 함" `
        "익명 연결을 통한 SID/이름 변환 허용 여부" "TurnOffAnonymousBlock != 1 이면 양호" "중" $status `
        "TurnOffAnonymousBlock: $anonSid" `
        $(if($status -eq "취약"){"secpol.msc > 보안 옵션 > '네트워크 액세스: 모든 사용자에게 Everyone 사용 허가 적용'"} else {""})
    Write-CheckResult "W-38" "익명 SID/이름 변환 허용 안 함" $status

    # W-39 IP 소스 라우팅 비활성화
    $srcRoute = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "DisableIPSourceRouting"
    $status = if ($srcRoute -eq 2) { "양호" } else { "취약" }
    Add-Result "W-39" "접근 관리" "IP 소스 라우팅 비활성화" `
        "IP 소스 라우팅 비활성화 (스푸핑 방어)" "DisableIPSourceRouting=2 이면 양호" "중" $status `
        "DisableIPSourceRouting: $srcRoute" `
        $(if($status -eq "취약"){"HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting = 2"} else {""})
    Write-CheckResult "W-39" "IP 소스 라우팅 비활성화" $status

    # W-40 ICMP 리디렉션 비활성화
    $icmpRedir = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "EnableICMPRedirect"
    $status = if ($icmpRedir -eq 0) { "양호" } else { "취약" }
    Add-Result "W-40" "접근 관리" "ICMP 리디렉션 비활성화" `
        "ICMP 라우팅 리디렉션 비활성화 (라우팅 테이블 조작 방어)" "EnableICMPRedirect=0 이면 양호" "중" $status `
        "EnableICMPRedirect: $icmpRedir" `
        $(if($status -eq "취약"){"HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect = 0"} else {""})
    Write-CheckResult "W-40" "ICMP 리디렉션 비활성화" $status
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  3. 패치 관리 (W-41 ~ W-43)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
function Check-PatchManagement {
    Write-Section "패치 관리"

    # W-41 최근 보안 패치 적용 (90일 기준)
    $hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5
    $lastPatch = $hotfixes | Select-Object -First 1
    $daysSince = if ($lastPatch -and $lastPatch.InstalledOn) {
        [int]((Get-Date) - $lastPatch.InstalledOn).TotalDays
    } else { 999 }
    $status = if ($daysSince -le 90) { "양호" } else { "취약" }
    $patchList = ($hotfixes | ForEach-Object { "$($_.HotFixID) ($($_.InstalledOn.ToString('yyyy-MM-dd')))" }) -join "`n"
    Add-Result "W-41" "패치 관리" "최근 보안 패치 적용 (90일)" `
        "최근 90일 이내 보안 패치/누적 업데이트 적용 여부" "90일 이내 패치 적용 시 양호" "상" $status `
        "마지막 패치: ${daysSince}일 전`n$patchList" `
        $(if($status -eq "취약"){"Windows Update를 통해 최신 누적 업데이트 적용"} else {""})
    Write-CheckResult "W-41" "최근 보안 패치 적용 (90일)" $status

    # W-42 OS 버전 지원 여부 (EOS 확인)
    $osInfo = Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue
    $osCaption = if ($osInfo) { $osInfo.Caption } else { [System.Environment]::OSVersion.VersionString }
    $eosMap = @{
        "2008 R2"="2020-01-14"; "2008"="2020-01-14";
        "2012 R2"="2023-10-10"; "2012"="2023-10-10";
        "2016"="2027-01-12"; "2019"="2029-01-09"; "2022"="2031-10-14";
        "2025"="2034-10-10"; "Windows 10"="2025-10-14"; "Windows 11 21H2"="2023-10-10";
        "Windows 11 22H2"="2024-10-08"; "Windows 11 23H2"="2025-11-11";
        "Windows 11 24H2"="2027-10-12"
    }
    # Windows 10은 2025-10-14 EOS 도달 — 이후 사용 시 취약 판정
    $eosDate = $null
    foreach ($k in $eosMap.Keys) { if ($osCaption -match $k) { $eosDate = $eosMap[$k]; break } }
    if ($eosDate) {
        $eosDateParsed = [datetime]::ParseExact($eosDate,"yyyy-MM-dd",$null)
        $status = if ((Get-Date) -gt $eosDateParsed) { "취약" } else { "양호" }
        $detail = "OS: $osCaption`n지원 종료일: $eosDate"
    } else {
        $status = "확인필요"; $detail = "OS: $osCaption`nEOS 날짜 확인 필요"
    }
    Add-Result "W-42" "패치 관리" "OS 제조사 지원 여부 (EOS)" `
        "현재 운영체제가 제조사 지원 종료된 버전인지 점검" "지원 종료(EOS) 전 버전이면 양호" "상" $status $detail `
        $(if($status -eq "취약"){"지원 종료된 OS. 최신 지원 버전으로 업그레이드 필요"} else {""})
    Write-CheckResult "W-42" "OS 제조사 지원 여부 (EOS)" $status

    # W-43 백신 소프트웨어 설치 및 업데이트
    $avProducts = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct -EA SilentlyContinue
    $wdStatus   = Get-MpComputerStatus -EA SilentlyContinue
    if ($avProducts) {
        $status = "양호"; $detail = "백신: " + ($avProducts.displayName -join ", ")
    } elseif ($wdStatus -and $wdStatus.AntivirusEnabled) {
        $lastUpdate = if ($wdStatus.AntivirusSignatureLastUpdated) { $wdStatus.AntivirusSignatureLastUpdated.ToString("yyyy-MM-dd") } else { "알 수 없음" }
        $daysSinceAV = if ($wdStatus.AntivirusSignatureLastUpdated) { [int]((Get-Date) - $wdStatus.AntivirusSignatureLastUpdated).TotalDays } else { 999 }
        $status = if ($daysSinceAV -le 7) { "양호" } else { "취약" }
        $detail = "Windows Defender 활성화`n정의 파일 최종 업데이트: $lastUpdate (${daysSinceAV}일 전)"
    } else {
        $status = "취약"; $detail = "백신 소프트웨어를 확인할 수 없습니다."
    }
    Add-Result "W-43" "패치 관리" "백신 소프트웨어 설치 및 업데이트" `
        "백신 프로그램 설치 및 최신 정의 파일 업데이트 여부" "백신 설치 + 7일 이내 정의 업데이트 시 양호" "상" $status $detail `
        $(if($status -eq "취약"){"백신 프로그램 설치 또는 정의 파일 업데이트 필요"} else {""})
    Write-CheckResult "W-43" "백신 소프트웨어 설치 및 업데이트" $status
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  4. 로그 관리 (W-44 ~ W-47)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
function Check-LogManagement {
    Write-Section "로그 관리"

    function Get-AuditSetting([string]$Sub) {
        $out = auditpol /get /subcategory:"$Sub" 2>$null
        foreach ($line in $out) {
            if ($line -match $Sub -or $line -match "로그온|성공|Logon") {
                if ($line -match "Success and Failure|성공 및 실패") { return "성공 및 실패" }
                if ($line -match "Success|성공") { return "성공" }
                if ($line -match "Failure|실패") { return "실패" }
            }
        }
        return "감사 없음"
    }

    # W-44 로그온 이벤트 감사
    $logonAudit = Get-AuditSetting "Logon"
    $status = if ($logonAudit -eq "성공 및 실패") { "양호" } else { "취약" }
    Add-Result "W-44" "로그 관리" "로그온 이벤트 감사" `
        "로그온/로그오프 이벤트 감사 설정" "성공 및 실패 모두 감사 시 양호" "상" $status `
        "현재 설정: $logonAudit" `
        $(if($status -eq "취약"){"auditpol /set /subcategory:Logon /success:enable /failure:enable"} else {""})
    Write-CheckResult "W-44" "로그온 이벤트 감사" $status

    # W-45 계정 관리 감사
    $acctAudit = Get-AuditSetting "User Account Management"
    $status = if ($acctAudit -in @("성공 및 실패","성공")) { "양호" } else { "취약" }
    Add-Result "W-45" "로그 관리" "계정 관리 감사" `
        "계정 생성/변경/삭제 이벤트 감사 설정" "성공 감사 이상 설정 시 양호" "중" $status `
        "현재 설정: $acctAudit" `
        $(if($status -eq "취약"){'auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable'} else {""})
    Write-CheckResult "W-45" "계정 관리 감사" $status

    # W-46 정책 변경 감사
    $polAudit = Get-AuditSetting "Audit Policy Change"
    $status = if ($polAudit -in @("성공 및 실패","성공")) { "양호" } else { "취약" }
    Add-Result "W-46" "로그 관리" "정책 변경 감사" `
        "보안 정책 변경 이벤트 감사 설정" "성공 감사 이상 설정 시 양호" "중" $status `
        "현재 설정: $polAudit" `
        $(if($status -eq "취약"){'auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable'} else {""})
    Write-CheckResult "W-46" "정책 변경 감사" $status

    # W-47 이벤트 로그 크기 및 보존
    $secLog = Get-WinEvent -ListLog "Security" -EA SilentlyContinue
    $secSizeMB = if ($secLog) { [math]::Round($secLog.MaximumSizeInBytes/1MB, 1) } else { 0 }
    $secMode   = if ($secLog) { $secLog.LogMode } else { "알 수 없음" }
    $status = if ($secSizeMB -ge 100) { "양호" } else { "취약" }
    Add-Result "W-47" "로그 관리" "이벤트 로그 크기 설정" `
        "보안 이벤트 로그 최대 크기 및 보존 정책" "보안 로그 100MB 이상이면 양호" "중" $status `
        "보안 로그 크기: ${secSizeMB}MB, 보존방식: $secMode" `
        $(if($status -eq "취약"){"eventvwr.msc > 보안 로그 속성 > 최대 크기 100MB(102400KB) 이상 설정"} else {""})
    Write-CheckResult "W-47" "이벤트 로그 크기 설정" $status
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  5. 기능 관리 (W-48 ~ W-67) + 최신 보안 트렌드
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
function Check-FunctionManagement {
    Write-Section "기능 관리 및 최신 보안 설정"

    # W-48 자동 실행(AutoRun/AutoPlay) 비활성화
    $autoRun = Get-RegVal "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun"
    $status = if ($autoRun -eq 255) { "양호" } else { "취약" }
    Add-Result "W-48" "기능 관리" "자동 실행(AutoRun) 비활성화" `
        "USB 등 외부 미디어 자동 실행 방지 설정" "NoDriveTypeAutoRun=0xFF(255) 이면 양호" "중" $status `
        "NoDriveTypeAutoRun: $autoRun" `
        $(if($status -eq "취약"){"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun = 255"} else {""})
    Write-CheckResult "W-48" "자동 실행(AutoRun) 비활성화" $status

    # W-49 불필요한 서비스 비활성화
    $svcsToCheck = @(
        @("Spooler","Print Spooler (미사용시)"),
        @("RemoteAccess","Routing and Remote Access"),
        @("simptcp","Simple TCP/IP Services"),
        @("SCardSvr","Smart Card (미사용시)"),
        @("XboxGipSvc","Xbox 관련 서비스")
    )
    $runningSvcs = @()
    foreach ($svc in $svcsToCheck) {
        $s = Get-Service -Name $svc[0] -EA SilentlyContinue
        if ($s -and $s.Status -eq "Running") { $runningSvcs += "$($svc[1]) ($($svc[0]))" }
    }
    $status = if ($runningSvcs.Count -eq 0) { "양호" } else { "취약" }
    Add-Result "W-49" "기능 관리" "불필요한 서비스 비활성화" `
        "업무에 불필요한 서비스 실행 여부 점검" "불필요한 서비스 없으면 양호" "중" $status `
        $(if($runningSvcs){"실행 중: " + ($runningSvcs -join "`n")} else {"점검 대상 서비스 미실행"}) `
        $(if($status -eq "취약"){"services.msc에서 불필요한 서비스 중지 및 비활성화"} else {""})
    Write-CheckResult "W-49" "불필요한 서비스 비활성화" $status

    # W-50 NTP 시간 동기화
    $ntpStatus = w32tm /query /status 2>$null
    $synced = $ntpStatus | Select-String "Synchronized|Source:|동기화"
    $status = if ($synced) { "양호" } else { "취약" }
    Add-Result "W-50" "기능 관리" "NTP 서버 시간 동기화" `
        "시스템 시간 NTP 동기화 설정" "NTP 서버와 동기화 시 양호" "하" $status `
        ($ntpStatus -join "`n") `
        $(if($status -eq "취약"){"w32tm /config /manualpeerlist:time.windows.com /syncfromflags:manual /update"} else {""})
    Write-CheckResult "W-50" "NTP 서버 시간 동기화" $status

    # W-51 DLL 검색 순서 보안 (SafeDllSearchMode)
    $safeDll = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "SafeDllSearchMode"
    $status = if ($safeDll -eq 1) { "양호" } else { "취약" }
    Add-Result "W-51" "기능 관리" "DLL 검색 순서 보안 설정" `
        "SafeDllSearchMode 설정으로 DLL 하이재킹 방지" "SafeDllSearchMode=1 이면 양호" "중" $status `
        "SafeDllSearchMode: $safeDll" `
        $(if($status -eq "취약"){"HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode = 1"} else {""})
    Write-CheckResult "W-51" "DLL 검색 순서 보안 설정" $status

    # W-52 LSA 보호 활성화 (Mimikatz 대응)
    $lsaProtect = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL"
    $status = if ($lsaProtect -eq 1) { "양호" } else { "취약" }
    Add-Result "W-52" "기능 관리" "LSA 보호(PPL) 활성화" `
        "LSA를 Protected Process Light로 실행 (Mimikatz 등 자격증명 덤프 방어)" "RunAsPPL=1 이면 양호" "상" $status `
        "RunAsPPL: $lsaProtect" `
        $(if($status -eq "취약"){"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1 (재부팅 필요)`nSecure Boot 환경 권장"} else {""})
    Write-CheckResult "W-52" "LSA 보호(PPL) 활성화" $status

    # W-53 Credential Guard 설정 (가상화 기반 보안)
    $cgEnabled = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" "EnableVirtualizationBasedSecurity"
    $cgCred    = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LsaCfgFlags"
    $status = if ($cgEnabled -eq 1 -and $cgCred -ge 1) { "양호" } else { "취약" }
    Add-Result "W-53" "기능 관리" "Credential Guard(자격증명 보호)" `
        "VBS 기반 Credential Guard 활성화 (Pass-the-Hash 공격 방어)" "활성화 시 양호 (Windows 10/Server 2016+)" "상" $status `
        "VBS:$cgEnabled, LsaCfgFlags:$cgCred" `
        $(if($status -eq "취약"){"GPO: 컴퓨터구성 > 관리템플릿 > 시스템 > Device Guard > Credential Guard 활성화"} else {""})
    Write-CheckResult "W-53" "Credential Guard(자격증명 보호)" $status

    # W-54 PowerShell Script Block Logging
    $sbLogging = Get-RegVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging"
    $status = if ($sbLogging -eq 1) { "양호" } else { "취약" }
    Add-Result "W-54" "기능 관리" "PowerShell 스크립트 블록 로깅" `
        "PowerShell Script Block 로깅 활성화 (공격 탐지용)" "EnableScriptBlockLogging=1 이면 양호" "중" $status `
        "EnableScriptBlockLogging: $sbLogging" `
        $(if($status -eq "취약"){"GPO: 관리템플릿 > Windows 구성요소 > PowerShell > '스크립트 블록 로깅 켜기'"} else {""})
    Write-CheckResult "W-54" "PowerShell 스크립트 블록 로깅" $status

    # W-55 PowerShell 실행 정책
    $psPolicy = Get-ExecutionPolicy -Scope LocalMachine
    $status = if ($psPolicy -in @("AllSigned","RemoteSigned","Restricted")) { "양호" } else { "취약" }
    Add-Result "W-55" "기능 관리" "PowerShell 실행 정책" `
        "PowerShell 스크립트 실행 정책 설정" "AllSigned 또는 RemoteSigned 이면 양호" "중" $status `
        "실행 정책: $psPolicy" `
        $(if($status -eq "취약"){"Set-ExecutionPolicy RemoteSigned -Scope LocalMachine"} else {""})
    Write-CheckResult "W-55" "PowerShell 실행 정책" $status

    # W-56 PowerShell v2 비활성화 (다운그레이드 공격 방어)
    $ps2 = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -EA SilentlyContinue
    $ps2State = if ($ps2) { $ps2.State } else { "알 수 없음" }
    $status = if ($ps2State -eq "Disabled" -or $ps2State -eq "알 수 없음") { "양호" } else { "취약" }
    Add-Result "W-56" "기능 관리" "PowerShell v2 비활성화" `
        "PowerShell v2 비활성화 (로깅 우회 다운그레이드 공격 방어)" "Disabled 상태이면 양호" "중" $status `
        "PowerShell v2 상태: $ps2State" `
        $(if($status -eq "취약"){"Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root"} else {""})
    Write-CheckResult "W-56" "PowerShell v2 비활성화" $status

    # W-57 Windows Defender 실시간 보호
    $mpStatus = Get-MpComputerStatus -EA SilentlyContinue
    $rtEnabled = if ($mpStatus) { $mpStatus.RealTimeProtectionEnabled } else { $false }
    $status = if ($rtEnabled) { "양호" } else { "취약" }
    Add-Result "W-57" "기능 관리" "Windows Defender 실시간 보호" `
        "Windows Defender 실시간 보호 활성화 여부" "실시간 보호 활성화 시 양호" "상" $status `
        "실시간 보호: $rtEnabled" `
        $(if($status -eq "취약"){"Set-MpPreference -DisableRealtimeMonitoring $false"} else {""})
    Write-CheckResult "W-57" "Windows Defender 실시간 보호" $status

    # W-58 Windows Defender 방화벽 고급 로깅
    $fwLogDrop = (Get-NetFirewallProfile -Profile Domain -EA SilentlyContinue).LogBlocked
    $status = if ($fwLogDrop -eq $true) { "양호" } else { "취약" }
    Add-Result "W-58" "기능 관리" "방화벽 차단 패킷 로깅" `
        "방화벽 차단 패킷 로깅 활성화 여부" "도메인 프로파일 LogBlocked=True 이면 양호" "하" $status `
        "방화벽 차단 로깅: $fwLogDrop" `
        $(if($status -eq "취약"){"Set-NetFirewallProfile -All -LogBlocked True"} else {""})
    Write-CheckResult "W-58" "방화벽 차단 패킷 로깅" $status

    # W-59 AppLocker / WDAC 설정
    $applSvc = Get-SvcStatus "AppIDSvc"
    $wdacReg = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config" "VulnerableDriverBlocklistEnable"
    $status = if ($applSvc -eq "Running" -or $wdacReg -eq 1) { "양호" } else { "취약" }
    Add-Result "W-59" "기능 관리" "AppLocker / WDAC 애플리케이션 제어" `
        "허가되지 않은 프로그램 실행 방지 정책 적용 여부" "AppLocker 활성화 또는 WDAC 정책 적용 시 양호" "중" $status `
        "AppIDSvc:$applSvc, WDAC:$wdacReg" `
        $(if($status -eq "취약"){"secpol.msc > 응용 프로그램 제어 정책 > AppLocker 규칙 설정`n또는 Windows Defender Application Control(WDAC) 정책 배포"} else {""})
    Write-CheckResult "W-59" "AppLocker / WDAC 애플리케이션 제어" $status

    # W-60 Spectre/Meltdown 완화 패치
    $spectreReg = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "FeatureSettingsOverride"
    $status = if ($spectreReg -ne $null) { "양호" } else { "취약" }
    Add-Result "W-60" "기능 관리" "Spectre/Meltdown 완화 패치" `
        "CPU 취약점(Spectre/Meltdown) 완화 패치 적용 여부" "FeatureSettingsOverride 레지스트리 설정 시 양호" "상" $status `
        "FeatureSettingsOverride: $spectreReg" `
        $(if($status -eq "취약"){"최신 Windows 누적 업데이트 적용 및 마이크로코드 업데이트 확인`nhttps://support.microsoft.com/kb/4073119"} else {""})
    Write-CheckResult "W-60" "Spectre/Meltdown 완화 패치" $status

    # W-61 Secure Boot 활성화
    $secureBoot = Confirm-SecureBootUEFI -EA SilentlyContinue
    $status = if ($secureBoot -eq $true) { "양호" } elseif ($secureBoot -eq $false) { "취약" } else { "N/A" }
    Add-Result "W-61" "기능 관리" "Secure Boot 활성화" `
        "UEFI Secure Boot 활성화 여부 (부트킷 방어)" "Secure Boot 활성화 시 양호" "중" $status `
        "Secure Boot: $secureBoot" `
        $(if($status -eq "취약"){"UEFI/BIOS 설정에서 Secure Boot 활성화"} else {""})
    Write-CheckResult "W-61" "Secure Boot 활성화" $status

    # W-62 BitLocker 드라이브 암호화
    $bl = Get-BitLockerVolume -EA SilentlyContinue | Where-Object { $_.VolumeType -eq "OperatingSystem" }
    $blStatus = if ($bl) { $bl.ProtectionStatus } else { "알 수 없음" }
    $status = if ($blStatus -eq "On") { "양호" } elseif ($blStatus -eq "알 수 없음") { "확인필요" } else { "취약" }
    Add-Result "W-62" "기능 관리" "BitLocker 드라이브 암호화" `
        "OS 드라이브 BitLocker 암호화 활성화 여부" "OS 볼륨 BitLocker 보호 활성화 시 양호" "중" $status `
        "BitLocker 상태: $blStatus" `
        $(if($status -eq "취약"){"BitLocker 활성화: manage-bde -on C: -RecoveryPassword"} else {""})
    Write-CheckResult "W-62" "BitLocker 드라이브 암호화" $status

    # W-63 인터넷 익스플로러 / 레거시 브라우저 비활성화
    $ieFeature = Get-WindowsOptionalFeature -Online -FeatureName "Internet-Explorer-Optional-amd64" -EA SilentlyContinue
    $ieState = if ($ieFeature) { $ieFeature.State } else { "알 수 없음" }
    $status = if ($ieState -eq "Disabled" -or $ieState -eq "알 수 없음") { "양호" } else { "취약" }
    Add-Result "W-63" "기능 관리" "Internet Explorer 비활성화" `
        "레거시 Internet Explorer 비활성화 여부" "IE 비활성화 시 양호" "중" $status `
        "IE 상태: $ieState" `
        $(if($status -eq "취약"){"Disable-WindowsOptionalFeature -FeatureName Internet-Explorer-Optional-amd64 -Online"} else {""})
    Write-CheckResult "W-63" "Internet Explorer 비활성화" $status

    # W-64 Windows Script Host 비활성화 (VBScript/WSH 공격 방어)
    $wsh = Get-RegVal "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" "Enabled"
    $status = if ($wsh -eq 0) { "양호" } else { "취약" }
    Add-Result "W-64" "기능 관리" "Windows Script Host(WSH) 비활성화" `
        "VBScript/JScript 실행 엔진 비활성화 (스크립트 악성코드 방어)" "Enabled=0 이면 양호" "중" $status `
        "WSH Enabled: $wsh" `
        $(if($status -eq "취약"){"HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings\Enabled = 0"} else {""})
    Write-CheckResult "W-64" "Windows Script Host(WSH) 비활성화" $status

    # W-65 Windows 자동 업데이트 설정
    $auReg = Get-RegVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate"
    $status = if ($auReg -ne 1) { "양호" } else { "취약" }
    Add-Result "W-65" "기능 관리" "Windows 자동 업데이트 설정" `
        "Windows 자동 업데이트 비활성화 여부" "자동 업데이트 활성화 시 양호" "상" $status `
        "NoAutoUpdate: $auReg" `
        $(if($status -eq "취약"){"설정 > Windows 업데이트 > 고급 옵션 > 자동 업데이트 활성화"} else {""})
    Write-CheckResult "W-65" "Windows 자동 업데이트 설정" $status

    # W-66 Windows Defender Exploit Protection (EMET 대체)
    $epReg = Get-RegVal "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" "MitigationOptions"
    $epStatus = Get-ProcessMitigation -System -EA SilentlyContinue
    $status = if ($epStatus) { "양호" } else { "취약" }
    Add-Result "W-66" "기능 관리" "Exploit Protection 활성화" `
        "Windows Defender Exploit Protection(DEP/CFG/ASLR 등) 활성화" "시스템 Exploit Protection 설정 시 양호" "중" $status `
        "Exploit Protection 시스템 정책 적용 여부" `
        $(if($status -eq "취약"){"Windows 보안 센터 > 앱 및 브라우저 컨트롤 > Exploit Protection 설정"} else {""})
    Write-CheckResult "W-66" "Exploit Protection 활성화" $status

    # W-67 DNS over HTTPS (DoH) 설정
    $doh = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" "EnableAutoDoh"
    $status = if ($doh -eq 2) { "양호" } else { "취약" }
    Add-Result "W-67" "기능 관리" "DNS over HTTPS (DoH) 설정" `
        "DNS 쿼리 암호화(DoH) 설정으로 DNS 스누핑 방어" "EnableAutoDoh=2(자동) 이면 양호" "하" $status `
        "EnableAutoDoh: $doh" `
        $(if($status -eq "취약"){"HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\EnableAutoDoh = 2`n또는 Windows 설정 > 개인정보 및 보안 > 보안 DNS"} else {""})
    Write-CheckResult "W-67" "DNS over HTTPS (DoH) 설정" $status

    # ── 2026년 04월 신규 항목 (ISO 27001 A.8.2 / ISMS-P 2.6.2) ─────────────

    # W-68 NTLM 완전 비활성화 (MS Zero Trust 2026 권고)
    # KB5040442 이후 MS는 도메인 환경 NTLM 완전 차단 정책을 강제 추진
    $ntlmPolicy = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "RestrictReceivingNTLMTraffic"
    $ntlmSend   = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "RestrictSendingNTLMTraffic"
    if ($ntlmPolicy -ge 2 -or $ntlmSend -ge 2) {
        $status = "양호"; $ntlmDetail = "NTLM 수신제한:$ntlmPolicy, 송신제한:$ntlmSend (차단 설정됨)"
    } elseif ($ntlmPolicy -ge 1 -or $ntlmSend -ge 1) {
        $status = "취약"; $ntlmDetail = "NTLM 부분 제한만 적용 (완전 차단 필요) — 수신:$ntlmPolicy, 송신:$ntlmSend"
    } else {
        $status = "취약"; $ntlmDetail = "NTLM 제한 미설정 (RestrictReceivingNTLMTraffic/RestrictSendingNTLMTraffic 미존재)"
    }
    Add-Result "W-68" "기능 관리" "NTLM 완전 비활성화 (Zero Trust)" `
        "NTLM 인증 완전 차단으로 Pass-the-Hash / Relay 공격 원천 방지" `
        "RestrictReceivingNTLMTraffic=2, RestrictSendingNTLMTraffic=2 이면 양호" "상" $status `
        $ntlmDetail `
        $(if($status -eq "취약"){"GPO: 컴퓨터구성>보안설정>로컬정책>보안옵션>'NTLM 제한 수신/발신' 거부 전체 설정`nHKLM:\...\MSV1_0\RestrictReceivingNTLMTraffic=2"} else {""})
    Write-CheckResult "W-68" "NTLM 완전 비활성화 (Zero Trust)" $status

    # W-69 CVE-2024-38063 Windows TCP/IP IPv6 원격코드실행 (CVSS 9.8)
    # 2024-08-13 MS Patch Tuesday, 패치: KB5041580(Server 2022), KB5041585(Server 2019) 등
    $ipv6Disabled = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "DisabledComponents"
    $kb5041580 = Get-HotFix -Id "KB5041580" -EA SilentlyContinue
    $kb5041585 = Get-HotFix -Id "KB5041585" -EA SilentlyContinue
    $kb5041578 = Get-HotFix -Id "KB5041578" -EA SilentlyContinue
    if ($kb5041580 -or $kb5041585 -or $kb5041578) {
        $status = "양호"; $cve38063Detail = "CVE-2024-38063 패치 적용됨 (누적 업데이트 확인됨)"
    } elseif ($ipv6Disabled -band 0xFF -eq 0xFF) {
        $status = "양호"; $cve38063Detail = "IPv6 완전 비활성화(DisabledComponents=0xFF)로 노출 면제"
    } else {
        $status = "취약"; $cve38063Detail = "CVE-2024-38063 패치 미확인 — IPv6 활성화 상태에서 원격코드실행 위험`nDisabledComponents: $ipv6Disabled"
    }
    Add-Result "W-69" "기능 관리" "CVE-2024-38063 TCP/IP IPv6 RCE" `
        "Windows TCP/IP 스택 IPv6 원격코드실행 취약점 패치 여부 (CVSS 9.8)" `
        "2024-08 누적 업데이트 적용 또는 IPv6 비활성화 시 양호" "상" $status `
        $cve38063Detail `
        $(if($status -eq "취약"){"Windows Update > KB5041580/KB5041585 적용`n임시: HKLM:\...\Tcpip6\Parameters\DisabledComponents=0xFF (IPv6 비활성화)"} else {""})
    Write-CheckResult "W-69" "CVE-2024-38063 TCP/IP IPv6 RCE" $status

    # W-70 CVE-2025-21298 Windows OLE 원격코드실행 (2025-01 Patch Tuesday, CVSS 9.8)
    # RTF/OLE 오브젝트 처리 시 메모리 오염 → 이메일 클라이언트에서 프리뷰만으로 실행 가능
    $kb5050009 = Get-HotFix -Id "KB5050009" -EA SilentlyContinue
    $kb5050008 = Get-HotFix -Id "KB5050008" -EA SilentlyContinue
    $kb5049981 = Get-HotFix -Id "KB5049981" -EA SilentlyContinue
    if ($kb5050009 -or $kb5050008 -or $kb5049981) {
        $status = "양호"; $cve21298Detail = "CVE-2025-21298 패치 적용됨 (2025-01 누적 업데이트)"
    } else {
        $daysSince38 = 999
        $latestHF = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
        if ($latestHF -and $latestHF.InstalledOn) {
            $daysSince38 = [int]((Get-Date) - $latestHF.InstalledOn).TotalDays
        }
        if ($daysSince38 -le 30) {
            $status = "확인필요"; $cve21298Detail = "최근 패치 적용됨 — KB5050009/5050008/5049981 직접 확인 필요"
        } else {
            $status = "취약"; $cve21298Detail = "CVE-2025-21298 패치 미확인 — OLE 처리 RCE 위험 (CVSS 9.8)"
        }
    }
    Add-Result "W-70" "기능 관리" "CVE-2025-21298 Windows OLE RCE" `
        "Windows OLE 컴포넌트 원격코드실행 취약점 패치 여부 (CVSS 9.8, 2025-01)" `
        "2025-01 누적 업데이트(KB5050009 등) 적용 시 양호" "상" $status `
        $cve21298Detail `
        $(if($status -eq "취약"){"Windows Update > 2025-01 누적 업데이트 즉시 적용`nOutlook 사용 환경에서 RTF 미리보기 즉시 비활성화"} else {""})
    Write-CheckResult "W-70" "CVE-2025-21298 Windows OLE RCE" $status
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  HTML 보고서 생성
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
function New-HtmlReport {
    param([hashtable]$ServerInfo, [string]$OutPath)

    $total = $Global:Results.Count
    $good  = ($Global:Results | Where-Object { $_.Status -eq "양호" }).Count
    $bad   = ($Global:Results | Where-Object { $_.Status -eq "취약" }).Count
    $na    = ($Global:Results | Where-Object { $_.Status -eq "N/A" }).Count
    $etc   = $total - $good - $bad - $na
    $score = if ($total -gt 0) { [math]::Round($good / $total * 100, 1) } else { 0 }

    # 카테고리별 집계
    $catStats = $Global:Results | Group-Object Category | ForEach-Object {
        $g = ($_.Group | Where-Object {$_.Status -eq "양호"}).Count
        $b = ($_.Group | Where-Object {$_.Status -eq "취약"}).Count
        $t = $_.Count
        [PSCustomObject]@{ Name=$_.Name; Total=$t; Good=$g; Bad=$b; Rate=[math]::Round($g/$t*100,0) }
    }

    $catRows = ($catStats | ForEach-Object {
        $rateColor = if ($_.Rate -ge 80) { "#27ae60" } elseif ($_.Rate -ge 50) { "#f39c12" } else { "#e74c3c" }
        "<tr><td>$($_.Name)</td><td>$($_.Total)</td><td class='good'>$($_.Good)</td><td class='bad'>$($_.Bad)</td><td><div class='bar-wrap'><div class='bar' style='width:$($_.Rate)%;background:$rateColor'></div><span>$($_.Rate)%</span></div></td></tr>"
    }) -join "`n"

    $detailRows = ($Global:Results | ForEach-Object {
        $sc = switch ($_.Status) { "양호"{"good"} "취약"{"bad"} "N/A"{"na"} default{"etc"} }
        $rc = switch ($_.Risk)   { "상"{"risk-h"} "중"{"risk-m"} default{"risk-l"} }
        $det = [System.Web.HttpUtility]::HtmlEncode($_.Detail) -replace "`n","<br>"
        $act = [System.Web.HttpUtility]::HtmlEncode($_.Action) -replace "`n","<br>"
        $tit = [System.Web.HttpUtility]::HtmlEncode($_.Title)
        $std = [System.Web.HttpUtility]::HtmlEncode($_.Standard)
        "<tr><td class='id'>$($_.ID)</td><td>$($_.Category)</td><td class='title'>$tit</td><td class='std'>$std</td><td class='$rc'>$($_.Risk)</td><td class='status $sc'>$($_.Status)</td><td class='detail'>$det</td><td class='action'>$act</td></tr>"
    }) -join "`n"

    $scoreColor = if ($score -ge 80) { "#27ae60" } elseif ($score -ge 60) { "#f39c12" } else { "#e74c3c" }

    $html = @"
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Windows 서버 보안 취약점 진단 결과</title>
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
.stat-cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
.stat-card{background:#fff;border-radius:12px;padding:16px;text-align:center;box-shadow:0 2px 12px rgba(0,0,0,.08)}
.stat-card .num{font-size:32px;font-weight:700;line-height:1}
.stat-card .lbl{font-size:11px;color:#7f8c8d;margin-top:4px}
.stat-card.good .num{color:#27ae60} .stat-card.bad .num{color:#e74c3c}
.stat-card.na .num{color:#f39c12}   .stat-card.etc .num{color:#95a5a6}
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
td.status{text-align:center;font-weight:700;white-space:nowrap;border-radius:4px;font-size:12px}
td.good{color:#27ae60} td.bad{color:#e74c3c;background:#fff5f5}
td.na{color:#f39c12}   td.etc{color:#95a5a6}
td.risk-h{color:#e74c3c;font-weight:700;text-align:center}
td.risk-m{color:#f39c12;font-weight:700;text-align:center}
td.risk-l{color:#27ae60;font-weight:700;text-align:center}
.bar-wrap{display:flex;align-items:center;gap:8px}
.bar{height:14px;border-radius:7px;min-width:4px;transition:width .3s}
.bar-wrap span{font-size:12px;font-weight:700;white-space:nowrap}
.filter-bar{padding:12px 20px;background:#f8f9fa;border-bottom:1px solid #e9ecef;display:flex;gap:8px;flex-wrap:wrap}
.filter-btn{padding:5px 14px;border:1px solid #ddd;border-radius:20px;background:#fff;cursor:pointer;font-size:12px;transition:all .2s}
.filter-btn:hover,.filter-btn.active{background:#0f3460;color:#fff;border-color:#0f3460}
.search-box{padding:5px 12px;border:1px solid #ddd;border-radius:20px;font-size:12px;width:220px}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700}
.badge.good{background:#d5f5e3;color:#27ae60}
.badge.bad{background:#fde8e8;color:#e74c3c}
.vuln-list{padding:16px 20px}
.vuln-item{border-left:4px solid #e74c3c;padding:10px 14px;margin-bottom:10px;background:#fff5f5;border-radius:0 8px 8px 0}
.vuln-item h4{font-size:13px;color:#c0392b;margin-bottom:4px}
.vuln-item p{font-size:12px;color:#555;line-height:1.6}
@media print{body{background:#fff}.container{padding:0}header{border-radius:0}.card{box-shadow:none;border:1px solid #ddd}}
</style>
</head>
<body>
<div class="container">
<header>
  <h1>🔐 Windows 서버 보안 취약점 진단 결과</h1>
  <p>ISO 27001:2022 / ISMS-P (2023-1호) / KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준 | 2026년 04월 기준</p>
  <div class="info-grid">
    <div class="info-item"><label>서버명</label><span>$($ServerInfo.Hostname)</span></div>
    <div class="info-item"><label>IP 주소</label><span>$($ServerInfo.IP)</span></div>
    <div class="info-item"><label>운영체제</label><span>$($ServerInfo.OS)</span></div>
    <div class="info-item"><label>진단 일시</label><span>$($ServerInfo.DateTime)</span></div>
    <div class="info-item"><label>진단자</label><span>$($ServerInfo.Auditor)</span></div>
    <div class="info-item"><label>점검 버전</label><span>v2.0 (KISA 82항목+)</span></div>
  </div>
</header>

<div class="summary">
  <div class="score-card">
    <div class="score-num">$score</div>
    <div class="score-label">보안 점수 (/100점)</div>
  </div>
  <div>
    <div class="stat-cards">
      <div class="stat-card"><div class="num">$total</div><div class="lbl">전체 항목</div></div>
      <div class="stat-card good"><div class="num">$good</div><div class="lbl">양호</div></div>
      <div class="stat-card bad"><div class="num">$bad</div><div class="lbl">취약</div></div>
      <div class="stat-card na"><div class="num">$na</div><div class="lbl">N/A</div></div>
    </div>
  </div>
</div>

<div class="card">
  <div class="card-header">📊 카테고리별 점검 결과</div>
  <table>
    <thead><tr><th>분류</th><th>전체</th><th>양호</th><th>취약</th><th style="min-width:200px">양호율</th></tr></thead>
    <tbody>$catRows</tbody>
  </table>
</div>

<div class="card">
  <div class="card-header">⚠️ 취약 항목 요약 ($bad건)</div>
  <div class="vuln-list">
$(
    ($Global:Results | Where-Object { $_.Status -eq "취약" } | ForEach-Object {
        $tit = [System.Web.HttpUtility]::HtmlEncode($_.Title)
        $act = [System.Web.HttpUtility]::HtmlEncode($_.Action) -replace "`n","<br>"
        "<div class='vuln-item'><h4>[$($_.ID)] $tit <span class='badge bad'>위험도 $($_.Risk)</span></h4><p>$act</p></div>"
    }) -join "`n"
)
  </div>
</div>

<div class="card">
  <div class="card-header">📋 상세 점검 결과</div>
  <div class="filter-bar">
    <button class="filter-btn active" onclick="filterTable('all')">전체 ($total)</button>
    <button class="filter-btn" onclick="filterTable('good')">양호 ($good)</button>
    <button class="filter-btn" onclick="filterTable('bad')">취약 ($bad)</button>
    <button class="filter-btn" onclick="filterTable('na')">N/A ($na)</button>
    <input class="search-box" type="text" placeholder="검색..." oninput="searchTable(this.value)">
  </div>
  <table id="mainTable">
    <thead><tr><th>항목ID</th><th>분류</th><th>점검 항목</th><th>판단 기준</th><th>위험도</th><th>결과</th><th>상세 내용</th><th>조치 권고사항</th></tr></thead>
    <tbody>$detailRows</tbody>
  </table>
</div>

<div style="text-align:center;padding:20px;color:#aaa;font-size:11px">
  Generated by Windows CVE-Check v2.0 | $($ServerInfo.DateTime)
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
            위험도      = $_.Risk
            점검결과    = $_.Status
            상세내용    = $_.Detail -replace "`n"," | "
            조치권고사항 = $_.Action -replace "`n"," | "
        }
    } | Export-Csv -LiteralPath $OutPath -Encoding UTF8 -NoTypeInformation
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Excel 보고서 생성 (COM 자동화 - Excel 설치 시)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
function New-ExcelReport([string]$OutPath) {
    try {
        $xl  = New-Object -ComObject Excel.Application -EA Stop
        $xl.Visible = $false; $xl.DisplayAlerts = $false
        $wb  = $xl.Workbooks.Add()

        # ── 요약 시트 ──
        $ws1 = $wb.Sheets.Item(1); $ws1.Name = "요약"
        $ws1.Cells.Item(1,1) = "Windows 서버 보안 취약점 진단 결과 요약"
        $ws1.Range("A1:H1").Merge() | Out-Null
        $ws1.Cells.Item(1,1).Font.Bold = $true
        $ws1.Cells.Item(1,1).Font.Size = 16
        $ws1.Cells.Item(1,1).Interior.Color = 0x1F3864
        $ws1.Cells.Item(1,1).Font.Color     = 0xFFFFFF
        $ws1.Cells.Item(1,1).HorizontalAlignment = -4108

        $total = $Global:Results.Count
        $good  = ($Global:Results | Where-Object {$_.Status -eq "양호"}).Count
        $bad   = ($Global:Results | Where-Object {$_.Status -eq "취약"}).Count
        $score = [math]::Round($good/$total*100,1)

        $row = 3
        @("서버명","IP 주소","운영체제","진단 일시","진단자") | ForEach-Object {
            $ws1.Cells.Item($row,1) = $_; $row++
        }

        # ── 상세 시트 ──
        $ws2 = $wb.Sheets.Add([System.Type]::Missing, $wb.Sheets.Item($wb.Sheets.Count))
        $ws2.Name = "상세 점검결과"
        $headers = @("항목ID","분류","점검 항목","판단 기준","위험도","점검 결과","상세 내용","조치 권고사항")
        for ($c=1; $c -le $headers.Count; $c++) {
            $cell = $ws2.Cells.Item(1,$c)
            $cell.Value2 = $headers[$c-1]
            $cell.Font.Bold = $true
            $cell.Interior.Color = 0x0F3460
            $cell.Font.Color = 0xFFFFFF
        }
        $row = 2
        foreach ($r in $Global:Results) {
            $ws2.Cells.Item($row,1) = $r.ID
            $ws2.Cells.Item($row,2) = $r.Category
            $ws2.Cells.Item($row,3) = $r.Title
            $ws2.Cells.Item($row,4) = $r.Standard
            $ws2.Cells.Item($row,5) = $r.Risk
            $ws2.Cells.Item($row,6) = $r.Status
            $ws2.Cells.Item($row,7) = $r.Detail
            $ws2.Cells.Item($row,8) = $r.Action
            $statusCell = $ws2.Cells.Item($row,6)
            switch ($r.Status) {
                "양호" { $statusCell.Interior.Color = 0xC6EFCE; $statusCell.Font.Color = 0x276221 }
                "취약" { $statusCell.Interior.Color = 0xFFC7CE; $statusCell.Font.Color = 0x9C0006 }
                "N/A"  { $statusCell.Interior.Color = 0xFFEB9C; $statusCell.Font.Color = 0x9C5700 }
            }
            $row++
        }
        $ws2.Columns.AutoFit() | Out-Null

        $wb.SaveAs($OutPath, 51)  # 51 = xlOpenXMLWorkbook
        $wb.Close($false)
        $xl.Quit()
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($xl) | Out-Null
        return $true
    } catch {
        return $false
    }
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  메인 실행
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Add-Type -AssemblyName System.Web

# 관리자 권한 확인
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "`n  [!] 관리자 권한으로 실행해야 정확한 점검이 가능합니다." -ForegroundColor Red
    Write-Host "      마우스 우클릭 > '관리자 권한으로 실행' 후 재시작하세요.`n" -ForegroundColor Yellow
    Read-Host "  Enter 키를 누르면 종료합니다"
    exit 1
}

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Blue
Write-Host "  ║       Windows Server 보안 취약점 자동 진단 프로그램         ║" -ForegroundColor Blue
Write-Host "  ║  KISA 주요정보통신기반시설 기술적 취약점 분석평가 기준      ║" -ForegroundColor Blue
Write-Host "  ║  v3.0  |  70항목+  |  ISO27001/ISMS-P/KISA 2026년 04월      ║" -ForegroundColor Blue
Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Blue

# 서버 정보 수집
$hostname = $env:COMPUTERNAME
$ip = (Get-NetIPAddress -AddressFamily IPv4 -EA SilentlyContinue | Where-Object {$_.InterfaceAlias -notmatch "Loopback"} | Select-Object -First 1).IPAddress
$osInfo = (Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue).Caption
$ServerInfo = @{
    Hostname = $hostname
    IP       = if ($ip) { $ip } else { "확인불가" }
    OS       = if ($osInfo) { $osInfo } else { [System.Environment]::OSVersion.VersionString }
    DateTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Auditor  = $env:USERNAME
}

Write-Host "`n  서버: $($ServerInfo.Hostname) | IP: $($ServerInfo.IP) | OS: $($ServerInfo.OS)" -ForegroundColor Cyan
Write-Host "  진단 시작: $($ServerInfo.DateTime)`n" -ForegroundColor Gray

# 점검 실행
Check-AccountManagement
Check-AccessManagement
Check-PatchManagement
Check-LogManagement
Check-FunctionManagement

# 결과 요약
$total = $Global:Results.Count
$good  = ($Global:Results | Where-Object {$_.Status -eq "양호"}).Count
$bad   = ($Global:Results | Where-Object {$_.Status -eq "취약"}).Count
$na    = ($Global:Results | Where-Object {$_.Status -eq "N/A"}).Count
$etc   = $total - $good - $bad - $na
$score = [math]::Round($good / $total * 100, 1)
$scoreColor = if ($score -ge 80) {"Green"} elseif ($score -ge 60) {"Yellow"} else {"Red"}

Write-Host "`n  ══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host "  점검 완료 요약" -ForegroundColor White
Write-Host "  ──────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "  전체 항목 : $total 개" -ForegroundColor White
Write-Host "  양호       : $good 개" -ForegroundColor Green
Write-Host "  취약       : $bad 개" -ForegroundColor Red
Write-Host "  N/A        : $na 개" -ForegroundColor Yellow
Write-Host "  확인 필요  : $etc 개" -ForegroundColor Gray
Write-Host "  보안 점수  : " -NoNewline; Write-Host "$score 점" -ForegroundColor $scoreColor
Write-Host "  ══════════════════════════════════════════════════════════════`n" -ForegroundColor DarkGray

if ($bad -gt 0) {
    Write-Host "  취약 항목 ($bad 건):" -ForegroundColor Red
    $Global:Results | Where-Object {$_.Status -eq "취약"} | ForEach-Object {
        Write-Host "    ✗ [$($_.ID)] $($_.Title) (위험도: $($_.Risk))" -ForegroundColor Red
    }
    Write-Host ""
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  보고서 저장 (로컬 + 네트워크)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
$dateStr  = (Get-Date).ToString("yyyyMMdd")
$ipStr    = $ServerInfo.IP -replace '[:/\\]', '-'
$baseName = "CVE_Check_${hostname}_${ipStr}_${dateStr}"

# ── 로컬 보고서 생성 ──────────────────────────────────────────────
$htmlPath = Join-Path $OutputDir "$baseName.html"
$csvPath  = Join-Path $OutputDir "$baseName.csv"
$xlsxPath = Join-Path $OutputDir "$baseName.xlsx"

Write-Host "`n  [로컬] 보고서 생성 중..." -ForegroundColor Cyan
Write-Host "  저장 경로: $OutputDir" -ForegroundColor DarkGray

try {
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force -EA Stop | Out-Null
    }
} catch {
    Write-Host "  ✗ 출력 폴더 생성 실패: $_" -ForegroundColor Red
}

try {
    New-HtmlReport -ServerInfo $ServerInfo -OutPath $htmlPath
    if (Test-Path -LiteralPath $htmlPath) { Write-Host "  ✓ HTML : $htmlPath" -ForegroundColor Green }
    else { Write-Host "  ✗ HTML 생성 실패 (파일이 존재하지 않음)" -ForegroundColor Red }
} catch { Write-Host "  ✗ HTML 오류: $_" -ForegroundColor Red }

try {
    New-CsvReport -OutPath $csvPath
    if (Test-Path -LiteralPath $csvPath) { Write-Host "  ✓ CSV  : $csvPath" -ForegroundColor Green }
    else { Write-Host "  ✗ CSV 생성 실패 (파일이 존재하지 않음)" -ForegroundColor Red }
} catch { Write-Host "  ✗ CSV 오류: $_" -ForegroundColor Red }

$xlResult = New-ExcelReport -OutPath $xlsxPath
if ($xlResult) {
    Write-Host "  ✓ Excel: $xlsxPath" -ForegroundColor Green
} else {
    Write-Host "  ⚠ Excel 미설치 - HTML/CSV 보고서를 사용하세요" -ForegroundColor Yellow
}

# ── 네트워크 보고서 생성 ──────────────────────────────────────────
$netShare = "\\10.60.8.169\Server_check"
$netUser  = "maintenance"
$netPass  = "veQ5vU3&"

Write-Host "`n  [네트워크] 보고서 생성 중... ($netShare)" -ForegroundColor Cyan
try {
    $netCmd = net use $netShare /user:$netUser $netPass /persistent:no 2>&1
    if ($LASTEXITCODE -eq 0 -or ($netCmd -match "이미 연결|already")) {
        $netHtml = Join-Path $netShare "$baseName.html"
        $netCsv  = Join-Path $netShare "$baseName.csv"
        $netXlsx = Join-Path $netShare "$baseName.xlsx"

        New-HtmlReport -ServerInfo $ServerInfo -OutPath $netHtml
        Write-Host "  ✓ HTML : $netHtml" -ForegroundColor Green
        New-CsvReport -OutPath $netCsv
        Write-Host "  ✓ CSV  : $netCsv" -ForegroundColor Green
        if ($xlResult) {
            Copy-Item -LiteralPath $xlsxPath -Destination $netXlsx -Force -EA SilentlyContinue
            Write-Host "  ✓ Excel: $netXlsx" -ForegroundColor Green
        }
    } else {
        Write-Host "  ✗ 네트워크 연결 실패 - 로컬 보고서만 저장됨" -ForegroundColor Yellow
        Write-Host "    └ $netCmd" -ForegroundColor DarkGray
    }
} catch {
    Write-Host "  ✗ 네트워크 저장 오류: $_ - 로컬 보고서는 정상 저장됨" -ForegroundColor Red
} finally {
    net use $netShare /delete /yes 2>&1 | Out-Null
}

Write-Host ""
if (-not $NoOpen) {
    $ans = Read-Host "  HTML 보고서를 지금 여시겠습니까? (Y/N)"
    if ($ans -match "^[Yy]") { Start-Process $htmlPath }
}

Write-Host "`n  진단이 완료되었습니다.`n" -ForegroundColor Cyan
Read-Host "  Enter 키를 누르면 종료합니다"
