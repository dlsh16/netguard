# 이 파일은 agent\install.ps1 로 통합되었습니다.
# 아래 명령어를 실행하세요:
#
#   powershell -ExecutionPolicy Bypass -File "agent\install.ps1"

$newScript = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "..\agent\install.ps1"
if (Test-Path $newScript) {
    Write-Host "[INFO] agent\install.ps1 로 리다이렉트합니다..." -ForegroundColor Yellow
    & powershell -ExecutionPolicy Bypass -File $newScript @args
} else {
    Write-Host "[ERROR] agent\install.ps1 을 찾을 수 없습니다: $newScript" -ForegroundColor Red
    exit 1
}
