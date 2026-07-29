# NetGuard Git Change Management Guide

## Purpose

Use Git to track source code, scripts, deployment files, and documents while excluding local runtime data, logs, credentials, and large NVD cache files.

## Repository Setup

```powershell
cd E:\SNMP\SNMP_Codex
git status
```

If the repository is not initialized:

```powershell
git init
git config user.name "NetGuard Admin"
git config user.email "netguard-admin@example.local"
```

## Files Managed By Git

Include:

- `backend/`
- `frontend/`
- `agent/`
- `deploy/`
- `scripts/`
- `docs/`
- `requirements.txt`
- `config/config.example.yaml`

Exclude:

- `config/config.yaml`
- `agent/agent_config.json`
- `logs/`
- `data/`
- `backend/data/`
- `__pycache__/`
- NVD JSON cache files
- generated zip/tar packages

## Daily Workflow

Check changed files:

```powershell
git status
```

Review changes:

```powershell
git diff
```

Stage safe files:

```powershell
git add .
```

Commit:

```powershell
git commit -m "Update NetGuard dashboard and agent"
```

View history:

```powershell
git log --oneline --decorate -n 20
```

## Auto Update Watcher

NetGuard can automatically commit and push safe source/document changes when files are modified.

Run once in the foreground:

```powershell
cd E:\SNMP\SNMP_Codex
powershell -ExecutionPolicy Bypass -File .\scripts\watch_git_auto_update.ps1
```

Install as a Windows scheduled task:

```powershell
cd E:\SNMP\SNMP_Codex
.\scripts\install_git_auto_update_task.bat
```

The task name is `NetGuardGitAutoUpdate`. It runs at user logon and watches the repository every 60 seconds. When changes remain stable for 30 seconds, it commits and pushes them to `origin/main`.

Check watcher logs:

```powershell
Get-Content E:\SNMP\SNMP_Codex\logs\git_auto_update.log -Tail 50
```

Check task state:

```powershell
Get-ScheduledTask -TaskName NetGuardGitAutoUpdate
Get-ScheduledTaskInfo -TaskName NetGuardGitAutoUpdate
```

Stop/remove the automatic watcher:

```powershell
cd E:\SNMP\SNMP_Codex
.\scripts\uninstall_git_auto_update_task.bat
```

Run without pushing to GitHub:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\watch_git_auto_update.ps1 -NoPush
```

## Before Deployment

Create a release tag:

```powershell
git tag -a v1.2.47 -m "NetGuard v1.2.47"
```

Export source only:

```powershell
git archive --format zip --output E:\SNMP\netguard-source-v1.2.47.zip HEAD
```

Copy runtime files separately:

- `config/config.yaml`
- `data/nvd_cache/*.json`
- local logs only when needed for troubleshooting

## Important Rules

- Do not commit passwords, SMTP credentials, Kakao tokens, customer IP credentials, or private SNMP community strings.
- Do not commit NVD cache JSON files. They are large runtime data and should be transferred separately.
- Commit after each confirmed functional change and after updating the guide document.
- Use clear commit messages with the affected area, for example `Fix SMTP DNS error reporting`.
