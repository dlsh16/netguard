#Requires -Version 5.1
param([string]$ConfigPath = (Join-Path $PSScriptRoot 'agent_config.json'))
$ErrorActionPreference = 'Stop'
$cfg = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
if (-not $cfg.remote_checks.enabled) { return }
if ([string]$cfg.remote_checks.token -notmatch '^[a-f0-9]{64}$') { throw 'Remote check token missing or invalid' }
$root = Split-Path -Parent $ConfigPath
$state = Join-Path $root 'remote_check_pending.json'
function Post-Check($Path, $Payload) {
    Invoke-RestMethod -Uri ($cfg.server_url.TrimEnd('/') + '/api/agent/check-jobs/' + $Path) -Method Post `
        -Headers @{ 'X-Check-Token' = $cfg.remote_checks.token } -ContentType 'application/json; charset=utf-8' `
        -Body ([Text.Encoding]::UTF8.GetBytes(($Payload | ConvertTo-Json -Depth 8 -Compress))) -TimeoutSec 30
}
function Save-Pending($Value) {
    $temp = $state + '.tmp'
    [IO.File]::WriteAllText($temp,($Value | ConvertTo-Json -Depth 8 -Compress),[Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temp -Destination $state -Force
}
if (Test-Path -LiteralPath $state) {
    $pending = Get-Content -LiteralPath $state -Raw -Encoding UTF8 | ConvertFrom-Json
} else {
    $job = (Post-Check 'poll' @{}).job
    if (-not $job) { return }
    $names = @{ security='CVE_Check.ps1'; maintenance='Maintenance_Windows.ps1' }
    if (-not $names.ContainsKey([string]$job.run_type) -or [string]$job.id -notmatch '^[1-9][0-9]*$') { throw 'Invalid check job' }
    $pending = @{ id=$job.id; result=@{status='failed';detail='Agent interrupted; execution state unknown. Not automatically rerun.'} }
    Save-Pending $pending
    try {
        $output = Join-Path $root ('check_output\' + $job.id)
        New-Item -ItemType Directory -Path $output -ErrorAction Stop | Out-Null
        $scriptPath = Join-Path (Join-Path $root 'check_scripts') $names[[string]$job.run_type]
        $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -OutputDir "{1}" -NoOpen -Unattended' -f $scriptPath,$output
        $process = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList $arguments -WindowStyle Hidden `
            -RedirectStandardOutput (Join-Path $output 'runner.log') -RedirectStandardError (Join-Path $output 'runner-error.log') -PassThru
        $null = $process.Handle
        if (-not $process.WaitForExit(1800000)) {
            & taskkill.exe /PID $process.Id /T /F | Out-Null
            throw 'Check timed out'
        }
        if ($process.ExitCode -ne 0) { throw ('Check exit code: ' + $process.ExitCode) }
        $reports = @(Get-ChildItem -LiteralPath $output -Filter '*.csv' -File)
        if ($reports.Count -ne 1 -or $reports[0].Length -gt 4194304) { throw 'Expected one CSV report, at most 4 MiB' }
        $pending.result = @{status='completed';content_base64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($reports[0].FullName))}
    } catch {
        $pending.result = @{status='failed';detail=([string]$_).Substring(0,[Math]::Min(500,([string]$_).Length))}
    }
    Save-Pending $pending
}
Post-Check ($pending.id.ToString() + '/result') $pending.result | Out-Null
Remove-Item -LiteralPath $state
Write-Output ('Remote check result delivered: job=' + $pending.id + ' status=' + $pending.result.status)
