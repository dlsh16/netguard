# Read-only preflight; suitable for launching from PowerShell 2.0 or later.
$ErrorActionPreference = 'Stop'
$sourceDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$common = Join-Path $sourceDir 'windows_agent_common.ps1'
if (-not (Test-Path -LiteralPath $common -PathType Leaf)) {
    throw 'windows_agent_common.ps1 missing. Extract the complete NetGuard Agent package.'
}
. $common
Write-Host ('[NetGuard-Agent] PowerShell: ' + $PSVersionTable.PSVersion + ' / CLR: ' + [Environment]::Version)
Assert-AgentRuntime
Write-Host ('[NetGuard-Agent] .NET Framework release: ' + (Get-AgentFrameworkRelease))
$os = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop
Write-Host ('[NetGuard-Agent] OS: ' + $os.Caption + ' / ' + $os.Version + ' / SP' + $os.ServicePackMajorVersion)
$required = @('install.ps1', 'netguard_agent.ps1', 'netguard_agent.py', 'software_inventory.ps1', 'software_inventory.py',
    'restart_agent.ps1', 'restart_agent.bat', 'start_agent_background.ps1', 'start_agent_background.bat',
    'check_agent_environment.ps1', 'windows_agent_common.ps1')
foreach ($name in $required) {
    $path = Join-Path $sourceDir $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required package file missing: $name" }
    if ($name.EndsWith('.ps1')) {
        $tokens = $null; $parseErrors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$parseErrors) | Out-Null
        if ($parseErrors.Count -gt 0) { throw ("Syntax error in " + $name + ': ' + $parseErrors[0].Message) }
    }
}
Write-Host '[NetGuard-Agent] Package syntax OK.'
Write-Host ('[NetGuard-Agent] IPv4: ' + (Get-AgentIPv4))
if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) {
    Write-Host '[NetGuard-Agent] ScheduledTasks module unavailable; COM query and schtasks registration fallback will be used.'
}
$null = Get-AgentTaskFolder
Write-Host '[NetGuard-Agent] Preflight passed. No files, services or scheduled tasks were changed.' -ForegroundColor Green
