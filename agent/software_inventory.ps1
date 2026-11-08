#Requires -Version 5.1
param([switch]$Collect, [switch]$Send, [string]$ConfigPath = (Join-Path $PSScriptRoot 'agent_config.json'))

. (Join-Path $PSScriptRoot 'windows_agent_common.ps1')
Assert-AgentRuntime

function New-SoftwareItem {
    param([string]$Name, [string]$Version = '', [string]$Path = '', [string]$Publisher = '', [string]$Source = 'process')
    $values = @($Name.Trim(), $Version.Trim(), $Path, $Publisher)
    $limits = @(300, 150, 1024, 300)
    for ($i = 0; $i -lt $values.Count; $i++) {
        if ($values[$i].Length -gt $limits[$i]) { $values[$i] = $values[$i].Substring(0, $limits[$i]) }
    }
    return @{ name = $values[0]; version = $values[1]; installation_path = $values[2]; publisher = $values[3]; source = $Source }
}

function Read-TomcatInventory {
    param([string]$TomcatHome)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $jar = [System.IO.Compression.ZipFile]::OpenRead((Join-Path $TomcatHome 'lib\catalina.jar'))
    try {
        $entry = $jar.GetEntry('org/apache/catalina/util/ServerInfo.properties')
        if ($null -eq $entry -or $entry.Length -gt 65536) { throw 'Invalid Tomcat metadata' }
        $reader = New-Object System.IO.StreamReader($entry.Open())
        try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
        $version = ''
        if ($text -match '(?m)^server.info=Apache Tomcat/([^\r\n]+)') { $version = $Matches[1].Trim() }
        elseif ($text -match '(?m)^server.number=([^\r\n]+)') { $version = $Matches[1].Trim() }
        if ($version.Contains('@')) { $version = '' }
        return New-SoftwareItem 'Apache Tomcat' $version $TomcatHome 'Apache Software Foundation' 'tomcat'
    } finally { $jar.Dispose() }
}

function Get-SoftwareInventory {
    param($Options = @{})
    $items = New-Object 'System.Collections.Generic.List[object]'
    $errors = New-Object 'System.Collections.Generic.List[string]'
    $complete = New-Object 'System.Collections.Generic.List[string]'
    $homes = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($tomcatHome in @($Options.tomcat_homes)) { if ($tomcatHome) { [void]$homes.Add([string]$tomcatHome) } }
    $registryOk = $true
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
        $root = $null; $uninstall = $null
        try {
            $root = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
            $uninstall = $root.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
            if ($null -eq $uninstall) { continue }
            foreach ($keyName in $uninstall.GetSubKeyNames()) {
                $key = $null
                try {
                    $key = $uninstall.OpenSubKey($keyName)
                    $name = [string]$key.GetValue('DisplayName')
                    if (-not [string]::IsNullOrWhiteSpace($name)) {
                        $path = [string]$key.GetValue('InstallLocation')
                        $items.Add((New-SoftwareItem $name ([string]$key.GetValue('DisplayVersion')) $path ([string]$key.GetValue('Publisher')) 'registry'))
                        if ($name -match 'Tomcat' -and $path) { [void]$homes.Add($path) }
                    }
                } catch { $registryOk = $false } finally { if ($key) { $key.Dispose() } }
            }
        } catch { $registryOk = $false } finally {
            if ($uninstall) { $uninstall.Dispose() }; if ($root) { $root.Dispose() }
        }
    }
    if ($registryOk) { $complete.Add('registry') } else { $errors.Add('registry: installed software enumeration incomplete') }
    $commands = New-Object 'System.Collections.Generic.List[string]'
    try {
        $processes = @(Get-CimInstance Win32_Process -ErrorAction Stop)
        $processAccessLimited = $false
        foreach ($process in $processes | Select-Object -First 10000) {
            $name = [string]$process.Name; $version = ''; $publisher = ''; $path = [string]$process.ExecutablePath
            if (-not $path -and $process.ProcessId -gt 4) { $processAccessLimited = $true }
            if ($path -and (Test-Path -LiteralPath $path -PathType Leaf)) {
                try {
                    $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($path)
                    if ($info.ProductName) { $name = $info.ProductName }
                    if ($info.ProductVersion) { $version = $info.ProductVersion } elseif ($info.FileVersion) { $version = $info.FileVersion }
                    $publisher = $info.CompanyName
                } catch {}
            }
            if ($name) { $items.Add((New-SoftwareItem $name $version $path $publisher 'process')) }
            if ($process.CommandLine) { $commands.Add([string]$process.CommandLine) }
        }
        if ($processAccessLimited) { $errors.Add('process: access restricted; some executable metadata unavailable') }
        elseif ($processes.Count -le 10000) { $complete.Add('process') } else { $errors.Add('process: enumeration limit reached') }
    } catch { $errors.Add('process: enumeration failed') }
    try {
        foreach ($service in Get-CimInstance Win32_Service -ErrorAction Stop) {
            if ($service.PathName) {
                $commands.Add([string]$service.PathName)
                if ($service.PathName -match '^"?([^"\r\n]*?tomcat[^"\r\n]*?\.exe)') {
                    [void]$homes.Add((Split-Path -Parent (Split-Path -Parent $Matches[1])))
                }
            }
        }
    } catch { $errors.Add('tomcat: service paths unavailable') }
    foreach ($command in $commands) {
        foreach ($match in [regex]::Matches($command, '-Dcatalina\.(?:home|base)=(?:"([^"]+)"|([^\s"]+))')) {
            $tomcatHome = if ($match.Groups[1].Success) { $match.Groups[1].Value } else { $match.Groups[2].Value }
            [void]$homes.Add($tomcatHome)
        }
    }
    foreach ($pattern in @("$env:ProgramFiles\Apache Software Foundation\Tomcat*", 'C:\Tomcat*')) {
        Get-ChildItem -Path $pattern -Directory -ErrorAction SilentlyContinue | ForEach-Object { [void]$homes.Add($_.FullName) }
    }
    $tomcatOk = $true
    foreach ($tomcatHome in @($homes) | Select-Object -First 100) {
        try {
            if (Test-Path -LiteralPath (Join-Path $tomcatHome 'lib\catalina.jar') -PathType Leaf) {
                $items.Add((Read-TomcatInventory $tomcatHome))
            } elseif (@($Options.tomcat_homes) -contains $tomcatHome) {
                $tomcatOk = $false
            }
        } catch { $tomcatOk = $false }
    }
    if ($tomcatOk -and $homes.Count -le 100 -and -not ($errors -contains 'tomcat: service paths unavailable')) {
        $complete.Add('tomcat')
    } else { $errors.Add('tomcat: discovery incomplete; check configured home paths') }
    foreach ($definition in @($Options.extra_software) | Select-Object -First 1000) {
        if ($definition.name) { $items.Add((New-SoftwareItem $definition.name $definition.version $definition.installation_path $definition.publisher 'configured')) }
    }
    if (@($Options.extra_software).Count -le 1000) { $complete.Add('configured') }
    else { $errors.Add('configured: entry limit reached') }
    $unique = @{}
    foreach ($entry in $items) {
        $key = @($entry.source, $entry.name.ToLowerInvariant(), $entry.version, $entry.installation_path) | ConvertTo-Json -Compress
        $unique[$key] = $entry
    }
    if ($unique.Count -gt 10000) { $complete.Clear(); $errors.Add('inventory: item limit reached; snapshot is not authoritative') }
    return @{ items = @($unique.Values | Select-Object -First 10000); complete_sources = @($complete.ToArray()); errors = @($errors.ToArray() | Select-Object -Unique -First 20); os_family = 'windows' }
}

if ($Collect -or $Send) {
    $ErrorActionPreference = 'Stop'
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
    $config = @{}
    if (Test-Path -LiteralPath $ConfigPath) { $config = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json }
    $options = if ($config.software_inventory) { $config.software_inventory } else { @{} }
    $report = Get-SoftwareInventory $options
    $report.hostname = if ($config.hostname) { $config.hostname } else { $env:COMPUTERNAME }
    $report.ip_address = Get-AgentIPv4
    $report.collected_at = [DateTime]::UtcNow.ToString('o')
    $report.agent_version = '1.2.64'
    $json = $report | ConvertTo-Json -Depth 8 -Compress
    if ($Send) {
        $base = [string]$config.server_url
        if (-not $base) { throw 'server_url is required' }
        if ($base -notmatch '^https?://') { $base = 'http://' + $base }
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        $request = [System.Net.WebRequest]::Create($base.TrimEnd('/') + '/api/agent/software')
        $request.Method = 'POST'; $request.ContentType = 'application/json'; $request.Timeout = 30000
        $request.Headers.Add('X-Agent-Key', [string]$config.api_key); $request.ContentLength = $bytes.Length
        $stream = $request.GetRequestStream()
        try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
        $response = $request.GetResponse()
        try {
            $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
            try { $result = $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
            Write-Output "Software inventory: status=$($result.status) items=$($result.items) collection=$($result.collection_status)"
        } finally { $response.Dispose() }
    } else { Write-Output $json }
}
