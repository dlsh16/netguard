#Requires -Version 5.1
# NetGuard Agent (PowerShell) - Python 불필요, 표준 라이브러리만 사용
# 실행: powershell -NonInteractive -File netguard_agent.ps1

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$ConfigFile = Join-Path $ScriptDir "agent_config.json"
$LogFile    = Join-Path $ScriptDir "agent.log"

# ── 설정 로드 ──────────────────────────────────────────────────────────────────
$DefaultConfig = @{
    server_url  = "http://10.60.8.186:8000"
    api_key     = "netguard-agent-key-2026"
    interval    = 60
    hostname    = $env:COMPUTERNAME
    device_type = "server"
    location    = ""
    security_checks = @{
        enabled = $false
        interval_hours = 24
        scripts = @()
    }
}

function Load-Config {
    if (Test-Path $ConfigFile) {
        $raw = Get-Content $ConfigFile -Raw | ConvertFrom-Json
        foreach ($key in @($DefaultConfig.Keys)) {
            if ($null -ne $raw.$key -and $raw.$key -ne "") {
                $DefaultConfig[$key] = $raw.$key
            }
        }
    }
    return $DefaultConfig
}

# ── 로깅 ──────────────────────────────────────────────────────────────────────
function Normalize-ServerUrl {
    param([string]$Url)
    $u = $Url.Trim()
    if ($u -notmatch '^https?://') {
        $u = "http://$u"
    }
    return $u.TrimEnd("/")
}

function Write-Log {
    param([string]$Level, [string]$Message)
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
}

# ── 로컬 IP 탐지 ───────────────────────────────────────────────────────────────
function Get-LocalIP {
    try {
        $ip = (Get-NetIPAddress -AddressFamily IPv4 |
               Where-Object { $_.InterfaceAlias -notmatch "Loopback|vEthernet" } |
               Sort-Object PrefixLength |
               Select-Object -First 1).IPAddress
        if ($ip) { return $ip } else { return "127.0.0.1" }
    } catch { return "127.0.0.1" }
}

# ── 메트릭 수집 ───────────────────────────────────────────────────────────────
$PrevNet = @{ rx = 0; tx = 0; ts = 0 }

function Get-DiskMetrics {
    $disks = @()
    try {
        $volumes = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3"
        foreach ($d in $volumes) {
            if ($d.Size -le 0) { continue }
            $used = [double]$d.Size - [double]$d.FreeSpace
            $pct = [math]::Round($used / [double]$d.Size * 100, 1)
            $disks += [pscustomobject]@{
                path = $d.DeviceID
                used_pct = $pct
                size_gb = [math]::Round([double]$d.Size / 1GB, 1)
                used_gb = [math]::Round($used / 1GB, 1)
                free_gb = [math]::Round([double]$d.FreeSpace / 1GB, 1)
            }
        }
    } catch {}
    return $disks
}

function Get-ProcessMetrics {
    $items = @()
    try {
        $items = Get-Process |
            Sort-Object -Property WorkingSet64 -Descending |
            Select-Object -First 50 |
            ForEach-Object {
                $cpuSeconds = 0.0
                if ($null -ne $_.CPU) { $cpuSeconds = [double]$_.CPU }
                [pscustomobject]@{
                    name = $_.ProcessName
                    pid = $_.Id
                    cpu_centisec = [int]($cpuSeconds * 100)
                    mem_kb = [int]([double]$_.WorkingSet64 / 1KB)
                }
            }
    } catch {}
    return @($items)
}

function Get-Metrics {
    # CPU
    $cpu = 0.0
    try {
        $cpu = (Get-WmiObject Win32_Processor |
                Measure-Object -Property LoadPercentage -Average).Average
    } catch {}

    # Memory
    $mem = 0.0
    try {
        $os    = Get-WmiObject Win32_OperatingSystem
        $total = [double]$os.TotalVisibleMemorySize
        $free  = [double]$os.FreePhysicalMemory
        if ($total -gt 0) { $mem = [math]::Round(($total - $free) / $total * 100, 1) }
    } catch {}

    # Disk (all fixed drives)
    $disks = @(Get-DiskMetrics)
    $disk = 0.0
    if ($disks.Count -gt 0) {
        $maxDisk = ($disks | ForEach-Object { [double]$_.used_pct } | Measure-Object -Maximum).Maximum
        if ($null -ne $maxDisk) { $disk = [math]::Round([double]$maxDisk, 1) }
    }

    # Network (cumulative bytes via Win32_PerfRawData)
    $netInBps = 0.0; $netOutBps = 0.0
    try {
        $nics = Get-WmiObject Win32_PerfRawData_Tcpip_NetworkInterface |
                Where-Object { $_.Name -notmatch "Loopback|Teredo" }
        $rx = ($nics | Measure-Object -Property BytesReceivedPerSec -Sum).Sum
        $tx = ($nics | Measure-Object -Property BytesSentPerSec -Sum).Sum
        $now = [double](Get-Date -UFormat %s)
        if ($script:PrevNet.ts -gt 0) {
            $dt = $now - $script:PrevNet.ts
            if ($dt -gt 0) {
                $netInBps  = [math]::Max(0, ($rx - $script:PrevNet.rx) / $dt)
                $netOutBps = [math]::Max(0, ($tx - $script:PrevNet.tx) / $dt)
            }
        }
        $script:PrevNet = @{ rx = $rx; tx = $tx; ts = $now }
    } catch {}

    return @{
        cpu_pct      = [math]::Round([double]$cpu, 1)
        mem_pct      = [math]::Round([double]$mem, 1)
        disk_max_pct = [math]::Round([double]$disk, 1)
        net_in_bps   = [math]::Round($netInBps, 1)
        net_out_bps  = [math]::Round($netOutBps, 1)
        disks        = $disks
        processes    = @(Get-ProcessMetrics)
    }
}

# ── HTTP POST (JSON) ───────────────────────────────────────────────────────────
function Send-Json {
    param([string]$Url, [hashtable]$Payload, [string]$ApiKey)
    $json  = $Payload | ConvertTo-Json -Depth 8 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $req   = [System.Net.WebRequest]::Create($Url)
    $req.Method        = "POST"
    $req.ContentType   = "application/json"
    $req.ContentLength = $bytes.Length
    $req.Timeout       = 10000
    $req.Headers.Add("X-Agent-Key", $ApiKey)
    $stream = $req.GetRequestStream()
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Close()
    $resp = $req.GetResponse()
    $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
    $responseText = $reader.ReadToEnd()
    $reader.Close()
    $resp.Close()
    if ($responseText) {
        try {
            return ($responseText | ConvertFrom-Json)
        } catch {
            return $responseText
        }
    }
}

# ── 점검/취약점 스크립트 실행 및 결과 업로드 ─────────────────────────────────
function Expand-AgentValue {
    param([string]$Value, [string]$OutputDir = "")
    $checkScriptDir = Join-Path $ScriptDir "check_scripts"
    return $Value.Replace("{script_dir}", $ScriptDir).
                  Replace("{check_script_dir}", $checkScriptDir).
                  Replace("{output_dir}", $OutputDir)
}

function Resolve-AgentPath {
    param([string]$Value)
    $expanded = Expand-AgentValue $Value
    if ([System.IO.Path]::IsPathRooted($expanded)) { return $expanded }
    return (Join-Path $ScriptDir $expanded)
}

function Send-ReportFile {
    param(
        [string]$Path,
        [string]$RunType,
        [hashtable]$Config,
        [string]$BaseUrl,
        [string]$ApiKey,
        [string]$IpAddress
    )
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $payload = @{
        hostname = $Config.hostname
        ip_address = $IpAddress
        filename = [System.IO.Path]::GetFileName($Path)
        content_base64 = [Convert]::ToBase64String($bytes)
        run_type = $RunType
        os_type = (Get-WmiObject Win32_OperatingSystem).Caption
    }
    $result = Send-Json -Url "$BaseUrl/api/agent/security-report" -ApiKey $ApiKey -Payload $payload
    Write-Log "INFO" "Uploaded check report: $($payload.filename) run=$($result.id) rows=$($result.imported_results)"
}

function Invoke-SecurityChecks {
    param([hashtable]$Config, [string]$BaseUrl, [string]$ApiKey, [string]$IpAddress)
    $checkCfg = $Config.security_checks
    if ($null -eq $checkCfg -or -not $checkCfg.enabled) { return }
    $scripts = @($checkCfg.scripts)
    if ($scripts.Count -eq 0) {
        Write-Log "INFO" "Security checks enabled but no scripts configured"
        return
    }

    foreach ($item in $scripts) {
        $name = if ($item.name) { $item.name } else { "check-script" }
        $runType = if ($item.run_type) { $item.run_type } else { "security" }
        $outputDir = Resolve-AgentPath $(if ($item.output_dir) { $item.output_dir } else { "output\$runType" })
        if (-not (Test-Path $outputDir)) { New-Item -ItemType Directory -Force -Path $outputDir | Out-Null }
        $started = Get-Date
        $command = @($item.command)
        if ($command.Count -eq 0) {
            Write-Log "WARN" "Check script skipped ($name): command is empty"
            continue
        }
        $expanded = @()
        foreach ($part in $command) { $expanded += (Expand-AgentValue -Value $part -OutputDir $outputDir) }
        Write-Log "INFO" "Running check script: $name"
        try {
            $exe = $expanded[0]
            $args = @()
            if ($expanded.Count -gt 1) { $args = $expanded[1..($expanded.Count - 1)] }
            & $exe @args
            if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) {
                Write-Log "WARN" "Check script failed ($name): exit=$LASTEXITCODE"
                continue
            }
        } catch {
            Write-Log "ERROR" "Check script error ($name): $_"
            continue
        }

        $files = Get-ChildItem -Path $outputDir -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in @(".csv", ".html", ".htm", ".xlsx") -and $_.LastWriteTime -ge $started.AddSeconds(-5) } |
            Sort-Object LastWriteTime
        if (-not $files) {
            Write-Log "WARN" "Check script produced no report files: $name"
            continue
        }
        foreach ($file in $files) {
            try {
                Send-ReportFile -Path $file.FullName -RunType $runType -Config $Config -BaseUrl $BaseUrl -ApiKey $ApiKey -IpAddress $IpAddress
            } catch {
                Write-Log "ERROR" "Report upload failed ($($file.Name)): $_"
            }
        }
    }
}

# ── 메인 루프 ──────────────────────────────────────────────────────────────────
$cfg = Load-Config
$cfg.server_url = Normalize-ServerUrl $cfg.server_url

Write-Log "INFO" "NetGuard Agent (PowerShell) starting"
Write-Log "INFO" "Server  : $($cfg.server_url)"
Write-Log "INFO" "Hostname: $($cfg.hostname)"
Write-Log "INFO" "Interval: $($cfg.interval)s"

$localIp = Get-LocalIP
$base    = $cfg.server_url

# 초기 장치 등록
try {
    Send-Json -Url "$base/api/agent/register" -ApiKey $cfg.api_key -Payload @{
        hostname    = $cfg.hostname
        ip_address  = $localIp
        device_type = $cfg.device_type
        location    = $cfg.location
        os          = (Get-WmiObject Win32_OperatingSystem).Caption
    }
    Write-Log "INFO" "Device registered on server"
} catch {
    Write-Log "WARN" "Register failed (will retry): $_"
}

# 예열
Get-Metrics | Out-Null
Start-Sleep 2
$NextCheckAt = Get-Date "2000-01-01"

while ($true) {
    $start = Get-Date
    try {
        $metrics = Get-Metrics
        $payload = @{
            hostname    = $cfg.hostname
            ip_address  = $localIp
            cpu_pct     = $metrics.cpu_pct
            mem_pct     = $metrics.mem_pct
            disk_max_pct = $metrics.disk_max_pct
            net_in_bps  = $metrics.net_in_bps
            net_out_bps = $metrics.net_out_bps
            disks       = $metrics.disks
            processes   = $metrics.processes
        }
        Send-Json -Url "$base/api/agent/metrics" -ApiKey $cfg.api_key -Payload $payload
        Write-Log "INFO" "OK  cpu=$($metrics.cpu_pct)%  mem=$($metrics.mem_pct)%  disk=$($metrics.disk_max_pct)%"
        if ($cfg.security_checks -and $cfg.security_checks.enabled -and (Get-Date) -ge $NextCheckAt) {
            Invoke-SecurityChecks -Config $cfg -BaseUrl $base -ApiKey $cfg.api_key -IpAddress $localIp
            $hours = [double]$(if ($cfg.security_checks.interval_hours) { $cfg.security_checks.interval_hours } else { 24 })
            $NextCheckAt = (Get-Date).AddHours([math]::Max(1.0, $hours))
        }
    } catch {
        Write-Log "WARN" "Send failed: $_"
    }
    $elapsed = ((Get-Date) - $start).TotalSeconds
    $sleep   = [math]::Max(1, $cfg.interval - $elapsed)
    Start-Sleep -Seconds ([int]$sleep)
}
