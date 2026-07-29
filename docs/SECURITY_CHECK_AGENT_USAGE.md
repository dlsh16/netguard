# 점검/취약점 에이전트 사용법

NetGuard 에이전트는 기존 모니터링 메트릭 전송에 더해 서버 점검/취약점 스크립트를 실행하고 결과 파일을 대시보드에 저장할 수 있습니다.

## 1. 대시보드 메뉴

브라우저에서 NetGuard 접속 후 `보안 > 점검 결과 저장` 메뉴를 사용합니다.

- `결과 업로드`: 기존 스크립트가 만든 `.csv`, `.html`, `.xlsx` 파일을 수동 저장합니다.
- `최근 저장 결과`: 저장된 실행 이력과 원본 파일 다운로드를 제공합니다.
- `상세`: 항목별 점검 결과, 근거, 조치권고를 확인합니다.

## 2. 수동 업로드

1. `점검 결과 저장` 메뉴로 이동합니다.
2. 유형을 `취약점`, `점검`, `통합` 중 선택합니다.
3. 기존 스크립트 결과 파일을 선택합니다.
4. `결과 업로드`를 누릅니다.

지원 파일은 `CSV`, `HTML`, `XLSX`입니다. CSV/HTML은 기존 `Server Maintenance`, `Server Security Check` 스크립트 형식을 기준으로 자동 파싱됩니다.

## 3. 에이전트 자동 실행

에이전트 설정 파일은 `agent/agent_config.json`입니다.

```json
{
  "server_url": "http://10.60.8.186:8000",
  "api_key": "netguard-agent-key-2026",
  "interval": 60,
  "hostname": "",
  "device_type": "server",
  "location": "",
  "security_checks": {
    "enabled": true,
    "interval_hours": 24,
    "scripts": [
      {
        "name": "Windows maintenance check",
        "run_type": "maintenance",
        "command": [
          "powershell",
          "-ExecutionPolicy",
          "Bypass",
          "-File",
          "{check_script_dir}\\Maintenance_Windows.ps1",
          "-OutputDir",
          "{script_dir}\\output\\maintenance",
          "-NoOpen"
        ],
        "output_dir": "output\\maintenance",
        "timeout_sec": 3600
      },
      {
        "name": "Windows vulnerability check",
        "run_type": "security",
        "command": [
          "powershell",
          "-ExecutionPolicy",
          "Bypass",
          "-File",
          "{check_script_dir}\\CVE_Check.ps1",
          "-OutputDir",
          "{script_dir}\\output\\security",
          "-NoOpen"
        ],
        "output_dir": "output\\security",
        "timeout_sec": 3600
      }
    ]
  }
}
```

`enabled`를 `true`로 바꾸면 에이전트가 메트릭 전송 후 지정 주기마다 스크립트를 실행합니다. 새로 생성된 결과 파일은 `/api/agent/security-report`로 업로드되고 `점검 결과 저장` 메뉴에 표시됩니다.

## 4. Linux 예시

Linux 대상 서버에서는 `command`를 아래처럼 바꿉니다.

```json
{
  "name": "Linux vulnerability check",
  "run_type": "security",
  "command": [
    "bash",
    "{check_script_dir}/cve_check_linux.sh",
    "--output-dir",
    "{script_dir}/output/security"
  ],
  "output_dir": "output/security",
  "timeout_sec": 3600
}
```

스크립트 옵션이 서버 환경에 따라 다르면 실제 스크립트의 사용법에 맞춰 `command`만 조정하면 됩니다.

## 5. 경로 변수

에이전트 설정의 `command`와 `output_dir`에서 아래 변수를 사용할 수 있습니다.

| 변수 | 의미 |
|------|------|
| `{script_dir}` | 에이전트가 설치된 `agent` 폴더 |
| `{check_script_dir}` | `agent/check_scripts` 폴더 |
| `{output_dir}` | 해당 스크립트 설정의 출력 폴더 |

## 6. 원본 보관 위치

업로드된 원본 결과 파일은 서버의 `backend/data/security_reports` 폴더에 보관됩니다. DB에는 실행 이력, 항목, 결과, 원본 파일 경로가 함께 저장됩니다.
