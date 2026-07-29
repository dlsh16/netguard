# NetGuard Agent - Windows Install Script
# Version: 2026-07-29-scheduler-fallback
# Run: install.bat

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$InstallDir = "C:\NetGuard-Agent"
$ServiceName = "NetGuardAgent"
$TaskName = "NetGuardAgent"

function Write-Step {
    param([string]$Message, [string]$Color = "Cyan")
    Write-Host "[NetGuard-Agent] $Message" -ForegroundColor $Color
}

function Read-WithDefault {
    param([string]$Prompt, [string]$Default)
    $value = Read-Host "$Prompt [$Default]"
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return $value.Trim()
}

function Normalize-ServerUrl {
    param([string]$Url)
    $value = $Url.Trim()
    if ($value -notmatch '^https?://') {
        $value = "http://$value"
    }
    return $value.TrimEnd("/")
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Find-Python {
    foreach ($path in @("python", "python3", "C:\Python313\python.exe", "C:\Python312\python.exe", "C:\Python311\python.exe")) {
        $cmd = Get-Command $path -ErrorAction SilentlyContinue
        if (-not $cmd) {
            if (Test-Path $path) { return $path }
            continue
        }
        if ($cmd.Source -and $cmd.Source -notlike "*WindowsApps*") { return $cmd.Source }
    }
    return $null
}

function Find-Nssm {
    foreach ($path in @("nssm.exe", (Join-Path $ScriptDir "nssm.exe"), "C:\Windows\System32\nssm.exe", "C:\nssm\nssm-2.24\win64\nssm.exe")) {
        if (Test-Path $path -ErrorAction SilentlyContinue) { return $path }
        $cmd = Get-Command $path -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
    }
    return $null
}

function Stop-And-Remove-Existing {
    param([string]$NssmPath)

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Step "Removing existing service: $ServiceName" "Yellow"
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        if ($NssmPath) {
            & $NssmPath remove $ServiceName confirm 2>&1 | Out-Null
        } else {
            sc.exe delete $ServiceName | Out-Null
        }
        Start-Sleep -Seconds 2
    }

    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        Write-Step "Removing existing scheduled task: $TaskName" "Yellow"
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
}

function New-AgentTaskAction {
    param([string]$AgentMode, [string]$PythonCmd)

    if ($AgentMode -eq "powershell") {
        $agent = Join-Path $InstallDir "netguard_agent.ps1"
        return New-ScheduledTaskAction -Execute "powershell.exe" `
            -Argument "-WindowStyle Hidden -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$agent`"" `
            -WorkingDirectory $InstallDir
    }

    $agent = Join-Path $InstallDir "netguard_agent.py"
    return New-ScheduledTaskAction -Execute $PythonCmd -Argument "`"$agent`"" -WorkingDirectory $InstallDir
}

function New-AgentTaskCommand {
    param([string]$AgentMode, [string]$PythonCmd)

    if ($AgentMode -eq "powershell") {
        $agent = Join-Path $InstallDir "netguard_agent.ps1"
        return "powershell.exe -WindowStyle Hidden -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$agent`""
    }

    $agent = Join-Path $InstallDir "netguard_agent.py"
    return "`"$PythonCmd`" `"$agent`""
}

function Register-AgentTaskWithFallback {
    param([string]$AgentMode, [string]$PythonCmd)

    $registered = $false
    try {
        $action = New-AgentTaskAction -AgentMode $AgentMode -PythonCmd $PythonCmd
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $settings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -RestartCount 999 `
            -RestartInterval (New-TimeSpan -Minutes 1) `
            -ExecutionTimeLimit ([TimeSpan]::Zero) `
            -MultipleInstances IgnoreNew
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force -ErrorAction Stop | Out-Null
        $registered = $true
        Write-Step "Scheduled task registered by PowerShell cmdlet" "Green"
    } catch {
        Write-Step "PowerShell task registration failed: $_" "Yellow"
    }

    if (-not $registered) {
        $taskRun = New-AgentTaskCommand -AgentMode $AgentMode -PythonCmd $PythonCmd
        Write-Step "Registering scheduled task by schtasks.exe fallback" "Yellow"
        & schtasks.exe /Create /TN $TaskName /SC ONSTART /RU "SYSTEM" /RL HIGHEST /TR $taskRun /F | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "schtasks.exe task registration failed. exit=$LASTEXITCODE"
        }
        Write-Step "Scheduled task registered by schtasks.exe" "Green"
    }
}

function Start-AgentTask {
    try {
        Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    } catch {
        Write-Step "Start-ScheduledTask failed. Trying schtasks.exe /Run: $_" "Yellow"
        & schtasks.exe /Run /TN $TaskName | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "schtasks.exe task start failed. exit=$LASTEXITCODE"
        }
    }
}

function Register-Agent {
    param([string]$AgentMode, [string]$PythonCmd, [string]$NssmPath)

    if ($NssmPath) {
        if ($AgentMode -eq "powershell") {
            $agent = Join-Path $InstallDir "netguard_agent.ps1"
            & $NssmPath install $ServiceName "powershell.exe"
            & $NssmPath set $ServiceName AppParameters "-WindowStyle Hidden -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$agent`""
        } else {
            $agent = Join-Path $InstallDir "netguard_agent.py"
            & $NssmPath install $ServiceName $PythonCmd
            & $NssmPath set $ServiceName AppParameters "`"$agent`""
        }
        & $NssmPath set $ServiceName AppDirectory $InstallDir
        & $NssmPath set $ServiceName AppStdout (Join-Path $InstallDir "agent_stdout.log")
        & $NssmPath set $ServiceName AppStderr (Join-Path $InstallDir "agent_stderr.log")
        & $NssmPath set $ServiceName AppRotateFiles 1
        & $NssmPath set $ServiceName AppRestartDelay 10000
        & $NssmPath set $ServiceName Start SERVICE_AUTO_START
        & $NssmPath set $ServiceName DisplayName "NetGuard Monitoring Agent"
        & $NssmPath set $ServiceName Description "NetGuard agent - sends system metrics"
        Write-Step "NSSM service registered" "Green"
        return
    }

    Register-AgentTaskWithFallback -AgentMode $AgentMode -PythonCmd $PythonCmd
}

if (-not (Test-IsAdmin)) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

Write-Host ""
Write-Step "NetGuard Agent Windows Install 2026-07-29-scheduler-fallback"
Write-Host ""

$ServerUrl = Normalize-ServerUrl (Read-WithDefault "Server URL" "http://10.60.8.186:8000")
$ApiKey = Read-WithDefault "API Key" "netguard-agent-key-2026"
$Interval = Read-WithDefault "Interval seconds" "60"
$Hostname = Read-WithDefault "Device display name" $env:COMPUTERNAME
$DeviceType = Read-WithDefault "Device type" "server"
$Location = Read-WithDefault "Location optional" ""

$psSource = Join-Path $ScriptDir "netguard_agent.ps1"
$pySource = Join-Path $ScriptDir "netguard_agent.py"
$PythonCmd = Find-Python

if (Test-Path $psSource) {
    $AgentMode = "powershell"
    $AgentScript = "netguard_agent.ps1"
} elseif ($PythonCmd -and (Test-Path $pySource)) {
    $AgentMode = "python"
    $AgentScript = "netguard_agent.py"
} else {
    Write-Step "Agent script not found in $ScriptDir" "Red"
    Write-Host "Required: netguard_agent.ps1 or netguard_agent.py"
    exit 1
}

$NssmPath = Find-Nssm
if ($NssmPath) {
    Write-Step "NSSM detected: $NssmPath"
} else {
    Write-Step "NSSM not found. Task Scheduler will be used." "Yellow"
}
Write-Step "Agent mode: $AgentMode"

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $ScriptDir $AgentScript) -Destination $InstallDir -Force
foreach ($helper in @("restart_agent.ps1", "restart_agent.bat", "start_agent_background.ps1", "start_agent_background.bat")) {
    $src = Join-Path $ScriptDir $helper
    if (Test-Path $src) {
        Copy-Item -LiteralPath $src -Destination $InstallDir -Force
    }
}
Write-Step "Agent files copied to $InstallDir" "Green"

$config = @{
    server_url = $ServerUrl
    api_key = $ApiKey
    interval = [int]$Interval
    hostname = $Hostname
    device_type = $DeviceType
    location = $Location
    log_file = (Join-Path $InstallDir "agent.log")
}
$config | ConvertTo-Json -Depth 8 | Out-File -FilePath (Join-Path $InstallDir "agent_config.json") -Encoding UTF8
Write-Step "agent_config.json created" "Green"

Stop-And-Remove-Existing -NssmPath $NssmPath
Register-Agent -AgentMode $AgentMode -PythonCmd $PythonCmd -NssmPath $NssmPath

try {
    if ($NssmPath) {
        Start-Service -Name $ServiceName -ErrorAction Stop
        Start-Sleep -Seconds 3
        $svc = Get-Service -Name $ServiceName
        Write-Step "Service status: $($svc.Status)" $(if ($svc.Status -eq "Running") { "Green" } else { "Yellow" })
    } else {
        Start-AgentTask
        Start-Sleep -Seconds 3
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($task) {
            Write-Step "Task state: $($task.State)" $(if ($task.State -eq "Running") { "Green" } else { "Yellow" })
        } else {
            Write-Step "Task start command was sent. Use schtasks /Query /TN $TaskName to verify." "Yellow"
        }
    }
} catch {
    Write-Step "Start failed: $_" "Yellow"
}

$bgStart = Join-Path $InstallDir "start_agent_background.ps1"
if (Test-Path $bgStart) {
    try {
        & $bgStart
    } catch {
        Write-Step "Background startup check failed: $_" "Yellow"
    }
}

Write-Host ""
Write-Step "Install complete" "Green"
Write-Host "  Server   : $ServerUrl"
Write-Host "  Hostname : $Hostname"
Write-Host "  Agent    : $AgentMode"
Write-Host "  Path     : $InstallDir"
Write-Host "  Log      : $(Join-Path $InstallDir 'agent.log')"
