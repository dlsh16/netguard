#Requires -RunAsAdministrator
<#
.SYNOPSIS
    NetGuard 오프라인 설치를 위한 패키지 수집 스크립트 (Windows)

.DESCRIPTION
    인터넷이 되는 PC에서 실행하여 오프라인 설치에 필요한 패키지를 수집합니다.
    수집 결과를 USB 또는 파일 서버로 복사한 뒤 오프라인 서버에서 사용합니다.

.EXAMPLE
    # 인터넷이 되는 PC의 관리자 PowerShell에서 실행
    .\collect_packages_windows.ps1

.NOTES
    수집 결과 경로: C:\NetGuard_packages\
#>

$OutputDir   = "C:\NetGuard_packages"
$PipPkgDir   = "$OutputDir\pip_packages"
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$SourceDir   = Split-Path -Parent $ScriptDir
$ReqFile     = "$SourceDir\requirements.txt"

Write-Host ""
Write-Host "NetGuard 오프라인 패키지 수집 스크립트" -ForegroundColor Cyan
Write-Host "수집 경로: $OutputDir" -ForegroundColor Cyan
Write-Host ""

# requirements.txt 확인
if (-not (Test-Path $ReqFile)) {
    $ReqFile = Read-Host "requirements.txt 경로를 입력하세요"
    if (-not (Test-Path $ReqFile)) {
        Write-Host "requirements.txt를 찾을 수 없습니다." -ForegroundColor Red
        exit 1
    }
}
Write-Host "requirements.txt: $ReqFile" -ForegroundColor Green

# 디렉토리 생성
New-Item -ItemType Directory -Path $PipPkgDir -Force | Out-Null

# requirements.txt 복사
Copy-Item $ReqFile "$OutputDir\requirements.txt" -Force

# pip 패키지 다운로드 (Windows AMD64, Python 3.13)
Write-Host ""
Write-Host "pip 패키지 다운로드 중 (Windows AMD64, Python 3.13)..." -ForegroundColor Yellow

pip download `
    -r "$OutputDir\requirements.txt" `
    -d $PipPkgDir `
    --platform win_amd64 `
    --python-version 313 `
    --only-binary=:all:

$count = (Get-ChildItem $PipPkgDir | Measure-Object).Count
Write-Host ""
Write-Host "수집 완료! 패키지 수: $count" -ForegroundColor Green
Write-Host ""
Write-Host "수집 결과 경로:" -ForegroundColor Yellow
Write-Host "  $OutputDir\"
Write-Host ""
Write-Host "다음 단계:" -ForegroundColor Yellow
Write-Host "  1. C:\NetGuard_packages\ 폴더 전체를 USB에 복사"
Write-Host "  2. 별도로 수집 필요한 설치파일:"
Write-Host "     - postgresql-18.x-windows-x64.exe  (postgresql.org/download/windows)"
Write-Host "     - timescaledb-postgresql-18_*.zip  (packagecloud.io/timescale)"
Write-Host "     - python-3.13.x-amd64.exe          (python.org/downloads)"
Write-Host "     - nssm-2.24.zip                    (nssm.cc/download)"
Write-Host "  3. 오프라인 서버에서 install_windows.ps1 실행"
Write-Host ""
