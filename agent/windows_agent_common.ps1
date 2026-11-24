# Shared Windows checks. Keep this file parseable on PowerShell 2.0 so old
# hosts can report the prerequisite failure before any installation changes.

function Get-AgentRuntimeProblems {
    param([version]$PowerShellVersion, [version]$ClrVersion, [string]$Edition)
    if ($PowerShellVersion -lt [version]'5.1') {
        'Windows PowerShell 5.1 is required. Detected: ' + $PowerShellVersion
    }
    if ($Edition -and $Edition -ne 'Desktop') {
        'Use Windows PowerShell (powershell.exe), not PowerShell Core (pwsh.exe).'
    }
    if ($ClrVersion.Major -lt 4) {
        '.NET CLR 4 is required. Detected: ' + $ClrVersion
    }
}

function Get-AgentFrameworkRelease {
    return [int][Microsoft.Win32.Registry]::GetValue(
        'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full', 'Release', 0)
}

function Assert-AgentRuntime {
    $problems = @(Get-AgentRuntimeProblems $PSVersionTable.PSVersion ([Environment]::Version) $PSVersionTable.PSEdition)
    if ($problems.Count -gt 0) {
        throw (($problems -join ' ') + ' Check docs/WINDOWS_AGENT_COMPATIBILITY.md for OS-specific offline prerequisites. No agent files or services were changed.')
    }
    if ((Get-AgentFrameworkRelease) -lt 379893) {
        throw '.NET Framework 4.5.2 or later is required. Check docs/WINDOWS_AGENT_COMPATIBILITY.md. No agent files or services were changed.'
    }
    foreach ($command in @('ConvertTo-Json', 'ConvertFrom-Json', 'Get-WmiObject', 'Get-CimInstance')) {
        if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
            throw "Required command missing: $command. Repair Windows PowerShell/WMF before installing."
        }
    }
}

function Test-AgentIPv4 {
    param([string]$Address)
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$parsed)) { return $false }
    return $parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and
        $Address -notmatch '^(127\.|169\.254\.|0\.)'
}

function Get-AgentIPv4 {
    param([string]$ServerUrl, [string]$ReportIP)
    if ($ServerUrl) {
        if ($ServerUrl -notmatch '^https?://') { $ServerUrl = 'http://' + $ServerUrl }
        $target = [Uri]$ServerUrl
        $remote = @([Net.Dns]::GetHostAddresses($target.DnsSafeHost) | Where-Object { $_.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork })
        if ($remote.Count -eq 0) { throw 'NetGuard server has no IPv4 route target' }
        $socket = New-Object Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork, [Net.Sockets.SocketType]::Dgram, [Net.Sockets.ProtocolType]::Udp)
        try {
            if ($ReportIP) {
                $address = [Net.IPAddress]::Parse($ReportIP)
                if ($address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
                    $ReportIP -match '^(0\.|169\.254\.|22[4-9]\.|23[0-9]\.)') { throw 'report_ip must be a local unicast IPv4 address' }
                $socket.Bind((New-Object Net.IPEndPoint($address, 0)))
            }
            $socket.Connect((New-Object Net.IPEndPoint($remote[0], $target.Port)))
            return $socket.LocalEndPoint.Address.ToString()
        } finally { $socket.Dispose() }
    }
    if (Get-Command Get-NetIPAddress -ErrorAction SilentlyContinue) {
        try {
            $addresses = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
                Where-Object { $_.InterfaceAlias -notmatch 'Loopback|vEthernet' } |
                Sort-Object PrefixLength
            foreach ($address in $addresses) {
                if (Test-AgentIPv4 $address.IPAddress) { return [string]$address.IPAddress }
            }
        } catch {}
    }
    # NetTCPIP is not supplied by WMF on every older Windows release.
    $adapters = @(Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' -ErrorAction Stop | Sort-Object Index)
    foreach ($adapter in $adapters) {
        foreach ($address in @($adapter.IPAddress)) {
            if (Test-AgentIPv4 $address) { return [string]$address }
        }
    }
    throw 'No usable IPv4 address found. Check the network adapter; loopback/APIPA will not be registered.'
}

function Get-AgentIdentity {
    param($Config)
    if ($Config.agent_id) {
        if ([string]$Config.agent_id -cnotmatch '^[0-9a-f]{64}$') { throw 'agent_id override must be 64 lowercase hexadecimal characters' }
        return [string]$Config.agent_id
    }
    $root = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $key = $root.OpenSubKey('SOFTWARE\Microsoft\Cryptography')
        try { $machine = [string]$key.GetValue('MachineGuid') } finally { if ($key) { $key.Dispose() } }
    } finally { $root.Dispose() }
    if ($machine.Trim() -notmatch '^[0-9a-fA-F-]{32,36}$') { throw 'OS machine identity missing; configure a unique agent_id before starting' }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes('netguard:windows:' + $machine.Trim().ToLowerInvariant())))).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}

function Enter-AgentInstance {
    $mutex = New-Object Threading.Mutex($false, 'Global\NetGuardAgent.Main.v1') -ErrorAction Stop
    try {
        try { $acquired = $mutex.WaitOne(0) }
        catch [Threading.AbandonedMutexException] { $acquired = $true }
        if ($acquired) { return $mutex }
        $mutex.Dispose()
        return $null
    } catch { $mutex.Dispose(); throw }
}

function Get-AgentTaskFolder {
    $scheduler = New-Object -ComObject 'Schedule.Service'
    $scheduler.Connect()
    return $scheduler.GetFolder('\')
}

function Get-AgentTask {
    param([string]$TaskName)
    $folder = Get-AgentTaskFolder
    try { $task = $folder.GetTask($TaskName) }
    catch {
        $exception = $_.Exception
        while ($exception.InnerException) { $exception = $exception.InnerException }
        if ($exception.HResult -eq -2147024894) { return $null }
        throw
    }
    $states = @('Unknown', 'Disabled', 'Queued', 'Ready', 'Running')
    return New-Object PSObject -Property @{
        TaskName = $task.Name; State = $states[[int]$task.State]
        LastTaskResult = $task.LastTaskResult; NativeTask = $task
    }
}

function Stop-AgentTask {
    param([string]$TaskName)
    $task = Get-AgentTask $TaskName
    if ($task -and (@('Running', 'Queued') -contains $task.State)) { $task.NativeTask.Stop(0) }
}

function Disable-AgentServiceDuplicateTask {
    param([string]$TaskName)
    $task = Get-AgentTask $TaskName
    if ($task) {
        # The caller has confirmed the Windows service exists; keep one owner.
        $task.NativeTask.Enabled = $false
        if (@('Running', 'Queued') -contains $task.State) { $task.NativeTask.Stop(0) }
    }
}

function Remove-AgentTask {
    param([string]$TaskName)
    if (Get-AgentTask $TaskName) {
        $folder = Get-AgentTaskFolder
        $folder.DeleteTask($TaskName, 0)
    }
}
