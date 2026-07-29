# NetGuard Agent restart helper for Windows.
# Run as Administrator:
#   powershell -ExecutionPolicy Bypass -File C:\NetGuard-Agent\restart_agent.ps1

$ErrorActionPreference = "Stop"
$ServiceName = "NetGuardAgent"
$TaskName = "NetGuardAgent"
$InstallDir = "C:\NetGuard-Agent"

function Write-Step {
    param([string]$Message, [string]$Color = "Cyan")
    Write-Host "[NetGuard-Agent] $Message" -ForegroundColor $Color
}

function Find-Python {
    foreach ($p in @("python", "python3", "C:\Python313\python.exe", "C:\Python312\python.exe", "C:\Python311\python.exe")) {
        $cmd = Get-Command $p -ErrorAction SilentlyContinue
        if (-not $cmd) {
            if (Test-Path $p) { return $p }
            continue
        }
        if ($cmd.Source -and $cmd.Source -notlike "*WindowsApps*") { return $cmd.Source }
    }
    return $null
}

function New-AgentTaskAction {
    $psAgent = Join-Path $InstallDir "netguard_agent.ps1"
    $pythonAgent = Join-Path $InstallDir "netguard_agent.py"
    $python = Find-Python

    if (Test-Path $psAgent) {
        return New-ScheduledTaskAction -Execute "powershell.exe" `
            -Argument "-WindowStyle Hidden -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$psAgent`"" `
            -WorkingDirectory $InstallDir
    }

    if ($python -and (Test-Path $pythonAgent)) {
        return New-ScheduledTaskAction -Execute $python -Argument "`"$pythonAgent`"" -WorkingDirectory $InstallDir
    }

    throw "Agent script not found in $InstallDir"
}

function New-AgentTaskCommand {
    $psAgent = Join-Path $InstallDir "netguard_agent.ps1"
    $pythonAgent = Join-Path $InstallDir "netguard_agent.py"
    $python = Find-Python

    if (Test-Path $psAgent) {
        return "powershell.exe -WindowStyle Hidden -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$psAgent`""
    }

    if ($python -and (Test-Path $pythonAgent)) {
        return "`"$python`" `"$pythonAgent`""
    }

    throw "Agent script not found in $InstallDir"
}

function Register-AgentTask {
    $registered = $false
    try {
        $action = New-AgentTaskAction
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $settings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -RestartCount 999 `
            -RestartInterval (New-TimeSpan -Minutes 1) `
            -ExecutionTimeLimit ([TimeSpan]::Zero) `
            -MultipleInstances IgnoreNew
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest

        Register-ScheduledTask -TaskName $TaskName `
            -Action $action -Trigger $trigger `
            -Settings $settings -Principal $principal `
            -Force -ErrorAction Stop | Out-Null
        $registered = $true
        Write-Step "Scheduled task registered by PowerShell cmdlet" "Green"
    } catch {
        Write-Step "PowerShell task registration failed: $_" "Yellow"
    }

    if (-not $registered) {
        $taskRun = New-AgentTaskCommand
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

function Test-AgentLogAdvanced {
    param([datetime]$Before)

    $log = Join-Path $InstallDir "agent.log"
    for ($i = 0; $i -lt 75; $i += 5) {
        Start-Sleep -Seconds 5
        if (Test-Path $log) {
            $item = Get-Item $log
            if ($item.LastWriteTime -gt $Before) {
                Write-Step "Agent log updated: $($item.LastWriteTime)" "Green"
                return $true
            }
        }
    }
    Write-Step "Agent log did not update within 75 seconds. Check agent.log/agent_stderr.log." "Yellow"
    return $false
}

function Invoke-EmbeddedRestart {
    $log = Join-Path $InstallDir "agent.log"
    $before = Get-Date "2000-01-01"
    if (Test-Path $log) { $before = (Get-Item $log).LastWriteTime }

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Step "Restarting Windows service: $ServiceName"
        if ($svc.Status -ne "Stopped") {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
        }
        Start-Service -Name $ServiceName -ErrorAction Stop
        Start-Sleep -Seconds 3
        $svc = Get-Service -Name $ServiceName
        Write-Step "Service status: $($svc.Status)" $(if ($svc.Status -eq "Running") { "Green" } else { "Yellow" })
        [void](Test-AgentLogAdvanced -Before $before)
        return
    }

    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        Write-Step "Stopping scheduled task: $TaskName"
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        Write-Step "Recreating scheduled task with embedded restart settings: $TaskName"
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    } else {
        Write-Step "Scheduled task not found. Registering scheduled task: $TaskName" "Yellow"
    }

    Register-AgentTask
    Write-Step "Starting scheduled task: $TaskName"
    Start-AgentTask
    Start-Sleep -Seconds 3
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        Write-Step "Task state: $($task.State)" $(if ($task.State -eq "Running") { "Green" } else { "Yellow" })
    } else {
        Write-Step "Task start command was sent. Use schtasks /Query /TN $TaskName to verify." "Yellow"
    }

    $info = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($info) {
        Write-Step "LastTaskResult: $($info.LastTaskResult)"
    }
    [void](Test-AgentLogAdvanced -Before $before)
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) {
    Start-Process powershell -Verb RunAs -ArgumentList "-NoExit -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

if (-not (Test-Path $InstallDir)) {
    Write-Step "Install directory not found: $InstallDir" "Red"
    exit 1
}

$bgStart = Join-Path $InstallDir "start_agent_background.ps1"
if (Test-Path $bgStart) {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Step "Restarting Windows service through background launcher: $ServiceName"
        & $bgStart -Restart
    } else {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($task) {
            Write-Step "Restarting scheduled task with refreshed settings: $TaskName"
            & $bgStart -Restart -ForceTaskRecreate
        } else {
            Write-Step "Service/task not found. Registering scheduled task: $TaskName" "Yellow"
            & $bgStart -ForceTaskRecreate
        }
    }
} else {
    Write-Step "Background launcher not found: $bgStart" "Yellow"
    Write-Step "Using embedded restart logic. Copy start_agent_background.ps1 later for standard operation." "Yellow"
    Invoke-EmbeddedRestart
}

$log = Join-Path $InstallDir "agent.log"
if (Test-Path $log) {
    Write-Step "Recent log:"
    Get-Content $log -Tail 30
} else {
    Write-Step "Log file not found: $log" "Yellow"
}

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    Write-Step "Final service status: $($svc.Status)" $(if ($svc.Status -eq "Running") { "Green" } else { "Yellow" })
} else {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        Write-Step "Final task state: $($task.State)" $(if ($task.State -eq "Running") { "Green" } else { "Yellow" })
        $info = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($info) {
            Write-Step "Final LastTaskResult: $($info.LastTaskResult)"
        }
    }
}
