# NetGuard Git auto update watcher.
# Watches the repository and automatically commits/pushes safe tracked changes.

param(
    [string]$RepoPath = "E:\SNMP\SNMP_Codex",
    [string]$Branch = "main",
    [string]$Remote = "origin",
    [int]$IntervalSeconds = 60,
    [int]$StableSeconds = 30,
    [switch]$NoPush
)

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $logDir = Join-Path $RepoPath "logs"
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    $line = "{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Add-Content -LiteralPath (Join-Path $logDir "git_auto_update.log") -Value $line -Encoding UTF8
    Write-Host $line
}

function Invoke-Git {
    param([string[]]$Arguments)
    $output = & git @Arguments 2>&1
    $code = $LASTEXITCODE
    return [pscustomobject]@{
        Code = $code
        Output = ($output -join [Environment]::NewLine)
    }
}

function Get-StatusPorcelain {
    $result = Invoke-Git @("-C", $RepoPath, "status", "--porcelain")
    if ($result.Code -ne 0) {
        throw "git status failed: $($result.Output)"
    }
    return $result.Output.Trim()
}

function Test-BlockedPath {
    param([string]$Path)
    $normalized = $Path -replace "\\", "/"
    return (
        $normalized -match "^config/config\.yaml$" -or
        $normalized -match "^agent/.*_config\.json$" -or
        $normalized -match "^logs/" -or
        $normalized -match "^data/" -or
        $normalized -match "^backend/data/" -or
        $normalized -match "(^|/)__pycache__/" -or
        $normalized -match "^agent/check_scripts/output/" -or
        $normalized -match "\.(zip|tar|tar\.gz|tgz|7z|db|sqlite|sqlite3|log|out|err)$"
    )
}

function Get-StagedFiles {
    $result = Invoke-Git @("-C", $RepoPath, "diff", "--cached", "--name-only")
    if ($result.Code -ne 0) {
        throw "git diff --cached failed: $($result.Output)"
    }
    if ([string]::IsNullOrWhiteSpace($result.Output)) {
        return @()
    }
    return $result.Output -split "(`r`n|`n|`r)" | Where-Object { $_ }
}

function New-CommitBody {
    param([string[]]$Files)

    $maxFiles = 20
    $shown = @($Files | Select-Object -First $maxFiles)
    $lines = @(
        "Changed files:",
        ""
    )
    foreach ($file in $shown) {
        $lines += "- $file"
    }
    if ($Files.Count -gt $maxFiles) {
        $lines += "- ... and $($Files.Count - $maxFiles) more file(s)"
    }
    $lines += ""
    $lines += "Total changed files: $($Files.Count)"
    return ($lines -join [Environment]::NewLine)
}

function Invoke-AutoUpdate {
    $status = Get-StatusPorcelain
    if (-not $status) {
        return
    }

    Write-Log "Change detected. Waiting $StableSeconds seconds for files to settle."
    Start-Sleep -Seconds $StableSeconds

    $statusAfterWait = Get-StatusPorcelain
    if (-not $statusAfterWait) {
        Write-Log "No changes remain after settle wait."
        return
    }

    $add = Invoke-Git @("-C", $RepoPath, "add", "-A")
    if ($add.Code -ne 0) {
        Write-Log "git add failed: $($add.Output)" "ERROR"
        return
    }

    $staged = @(Get-StagedFiles)
    if ($staged.Count -eq 0) {
        Write-Log "No staged changes after git add."
        return
    }

    $blocked = @($staged | Where-Object { Test-BlockedPath $_ })
    if ($blocked.Count -gt 0) {
        Invoke-Git @("-C", $RepoPath, "restore", "--staged", "--", $blocked) | Out-Null
        Write-Log "Blocked unsafe files from auto commit: $($blocked -join ', ')" "WARN"
        $staged = @(Get-StagedFiles)
        if ($staged.Count -eq 0) {
            Write-Log "No safe staged files remain."
            return
        }
    }

    $message = "Auto update {0} ({1} file{2})" -f (
        Get-Date -Format "yyyy-MM-dd HH:mm:ss"),
        $staged.Count,
        $(if ($staged.Count -eq 1) { "" } else { "s" })
    $body = New-CommitBody -Files $staged
    $commit = Invoke-Git @("-C", $RepoPath, "commit", "-m", $message, "-m", $body)
    if ($commit.Code -ne 0) {
        Write-Log "git commit failed: $($commit.Output)" "ERROR"
        return
    }

    Write-Log "Committed: $message; files=$($staged -join ', ')"

    if ($NoPush) {
        Write-Log "NoPush enabled. Skipping push."
        return
    }

    $push = Invoke-Git @("-C", $RepoPath, "push", $Remote, $Branch)
    if ($push.Code -ne 0) {
        Write-Log "git push failed: $($push.Output)" "ERROR"
        return
    }

    Write-Log "Pushed to $Remote/$Branch"
}

if (-not (Test-Path (Join-Path $RepoPath ".git"))) {
    throw "Git repository not found: $RepoPath"
}

Write-Log "NetGuard Git auto update watcher started. Repo=$RepoPath Remote=$Remote Branch=$Branch Interval=${IntervalSeconds}s Stable=${StableSeconds}s Push=$(-not $NoPush)"

while ($true) {
    try {
        Invoke-AutoUpdate
    } catch {
        Write-Log $_ "ERROR"
    }
    Start-Sleep -Seconds $IntervalSeconds
}
