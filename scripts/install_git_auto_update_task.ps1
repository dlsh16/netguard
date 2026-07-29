# Installs NetGuard Git auto update watcher as a Windows scheduled task.

param(
    [string]$RepoPath = "E:\SNMP\SNMP_Codex",
    [string]$TaskName = "NetGuardGitAutoUpdate",
    [int]$IntervalSeconds = 60,
    [int]$StableSeconds = 30,
    [switch]$NoPush
)

$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message, [string]$Color = "Cyan")
    Write-Host "[NetGuard-Git] $Message" -ForegroundColor $Color
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    $argList = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", "`"$PSCommandPath`"",
        "-RepoPath", "`"$RepoPath`"",
        "-TaskName", "`"$TaskName`"",
        "-IntervalSeconds", "$IntervalSeconds",
        "-StableSeconds", "$StableSeconds"
    )
    if ($NoPush) {
        $argList += "-NoPush"
    }
    Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -ArgumentList ($argList -join " ")
    exit
}

$watcher = Join-Path $RepoPath "scripts\watch_git_auto_update.ps1"
if (-not (Test-Path $watcher)) {
    throw "Watcher script not found: $watcher"
}

$args = @(
    "-WindowStyle", "Hidden",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy", "Bypass",
    "-File", "`"$watcher`"",
    "-RepoPath", "`"$RepoPath`"",
    "-IntervalSeconds", "$IntervalSeconds",
    "-StableSeconds", "$StableSeconds"
)
if ($NoPush) {
    $args += "-NoPush"
}

$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Highest
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument ($args -join " ") -WorkingDirectory $RepoPath
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -MultipleInstances IgnoreNew

Write-Step "Registering scheduled task: $TaskName"
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null

Write-Step "Starting scheduled task: $TaskName"
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 3

$task = Get-ScheduledTask -TaskName $TaskName
Write-Step "Task state: $($task.State)" $(if ($task.State -eq "Running") { "Green" } else { "Yellow" })

Write-Step "Log: $(Join-Path $RepoPath 'logs\git_auto_update.log')" "Green"
