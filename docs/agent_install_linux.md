# NetGuard Agent Linux 설치 및 운영 매뉴얼

버전: v1.2.65 / 업데이트: 2026-11-08

## 변경 내용

- 설치 전 파일/문법/Python/설정 검사 추가. `--check`는 설치 파일·계정·서비스를 변경하지 않는다.
- 기존 설치에서 일반 설치를 다시 실행하면 중단한다. `--update`는 설정 내용과 기존 서비스 파일, 부팅 자동 시작 활성화 상태를 보존하고 코드만 갱신한다.
- `restart_agent.sh`를 함께 설치한다. 시작/재시작 후 비활성 상태는 실패 종료 코드로 전달한다.
- JSON은 Python으로 생성하여 위치/API 키의 따옴표, 역슬래시 등을 보존한다. 수집 간격과 URL 형식을 검증한다.
- 신규 서비스는 절대 Python 경로, ngagent 전용 계정, 네트워크 준비 순서, 비정상 종료 재시도, 부팅 자동 시작을 설정한다.
- Python 3.6에서 지원하지 않는 보안 점검 subprocess 인자를 호환 방식으로 변경했다. IP 선택은 외부 8.8.8.8 대신 설정한 NetGuard 서버로 향하는 IPv4 경로를 사용한다. 경로/DNS 실패를 127.0.0.1로 위장하지 않는다.

이번 패치는 대상 장비의 에이전트용이다. 중앙 NetGuard 서버, PostgreSQL, NVD를 재설치하거나 재시작하지 않는다. 소프트웨어 검색 기능 자체를 아직 적용하지 않았다면 먼저 [v1.2.63 서버 적용 절차](SOFTWARE_INVENTORY_GUIDE.md)를 따른다.

## 사전 조건

| 항목 | 조건 |
|---|---|
| OS | Rocky Linux 8/9의 systemd 환경. 다른 배포판은 별도 검증 필요 |
| Python | 3.6 이상 호환 코드. 운영 버전은 OS 지원 패키지와 조직 정책에 따라 선택 |
| 계정 | 설치/갱신은 root 또는 sudo, 실행은 ngagent |
| 기본 도구 | bash, systemctl, systemd-analyze, install, useradd/groupadd, getent, runuser, flock |
| 통신 | 대상 서버에서 기존 NetGuard HTTP(S) 주소로 나가는 연결. 직접 접속은 TCP 8000, 프록시 사용 시 기존 포트 |
| 파일 | ZIP 전체를 별도 폴더에 해제. scripts와 agent의 상대 위치 유지 |

설치기는 dnf/apt/pip 또는 인터넷 다운로드를 실행하지 않는다. Python 등이 없으면 OS에 맞는 승인된 RPM과 의존성을 오프라인 반입하여 준비한다. psutil은 선택 사항이며 표준 라이브러리로도 수집한다. 에이전트 장비에 인바운드 포트를 새로 열 필요가 없다.

## 패키지 및 점검

`NetGuard-Agent-Linux-v1.2.65.zip`을 반입하고 `/tmp/netguard-agent-v1265`처럼 별도 폴더에 해제한다. 운영 `/opt/netguard-agent`에 ZIP 전체를 직접 덮어쓰지 않는다.

```text
agent/
  netguard_agent.py
  software_inventory.py
  restart_agent.sh
scripts/
  install_agent_linux.sh
  linux_agent_setup.py
docs/
  agent_install_linux.md
```

```bash
python3 --version
python3 -m zipfile -e /tmp/NetGuard-Agent-Linux-v1.2.65.zip /tmp/netguard-agent-v1265
cd /tmp/netguard-agent-v1265
sudo bash scripts/install_agent_linux.sh --check
```

버전별 실행 파일만 있거나 별도 Python을 사용할 때는 전체 경로를 지정한다.

```bash
sudo env NETGUARD_AGENT_PYTHON=/usr/bin/python3.9 bash scripts/install_agent_linux.sh --check
```

`Preflight passed`와 종료 코드 0을 확인한다. 이 검사는 서버 API 연결/인증, 실제 systemd 기동 또는 데이터 수신 성공을 보장하지 않는다. 기존 설정 JSON이 손상되었으면 원본을 보존한 뒤 해당 오류부터 수정한다.

## 신규 설치

기존 설치가 없는 장비에서 실행한다.

```bash
sudo bash scripts/install_agent_linux.sh
```

서버 URL, API 키, 수집 간격, 장비 유형, 위치를 입력한다. URL 기본값은 `http://10.60.8.186:8000`이다. API 키는 화면에 표시하지 않으며 중앙 서버의 실제 키와 일치해야 한다. 신규 생성 파일에는 기본 소프트웨어 수집 6시간 주기를 포함한다. 보안 점검 스크립트 실행은 별도 설정이며 자동 활성화하지 않는다.

설치 위치는 `/opt/netguard-agent`, 서비스명은 `netguard-agent`, 설정은 `agent_config.json`이다. 신규 서비스는 `systemctl enable`로 부팅 자동 시작을 설정한다. 터미널/SSH 연결을 닫아도 systemd가 에이전트를 유지한다.

신규 unit은 `After=network-online.target`, `Restart=on-failure`, `RestartSec=10`, `[Unit] StartLimitIntervalSec=0`을 사용한다. 시작 시 DNS/경로가 준비되지 않아 프로세스가 실패해도 10초 간격으로 다시 시도한다. 관리자에 의한 명시적 stop은 자동 재시작하지 않는다. 인터넷 연결을 기다리는 설정은 아니다. [systemd 서비스 설정](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html), [시작 제한 및 부팅 활성화](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html).

## 기존 설치 업데이트

먼저 실제 서비스 사용자와 실행 경로를 확인한다.

```bash
sudo systemctl cat netguard-agent
sudo systemctl show netguard-agent -p User -p WorkingDirectory -p ExecStart
sudo bash scripts/install_agent_linux.sh --check
sudo bash scripts/install_agent_linux.sh --update
```

`--update`는 다음 순서로 진행한다.

1. 기존 설정, 서비스 파일, ngagent 계정, `/opt/netguard-agent` 작업 경로를 검사한다.
2. `/var/backups/netguard-agent.XXXXXXXX`에 기존 코드/설정/unit을 백업한다. 이 폴더는 root만 접근하며 API 키를 포함하므로 외부 공유하지 않는다.
3. 에이전트를 중지하고 Python 파일 두 개와 재시작 스크립트를 교체한다. 기존 다른 점검 파일/설정 항목/로그는 제거하지 않는다.
4. 실제 서비스 계정의 코드/설정 읽기 및 로그 쓰기 권한을 확인하고 에이전트를 재시작한다.
5. 활성 상태와 기존 자동 시작 상태를 출력한다. 중간 실패 시 백업을 보존하며 실패를 설치 성공으로 표시하지 않는다.

설정 JSON과 기존 unit의 **내용은 그대로 유지**한다. ngagent가 아닌 사용자, 다른 설치 경로, 심볼릭 링크 구성은 자동으로 변경하지 않고 중단한다. 기존 root 실행 서비스를 이 도구로 자동 전환하지 않는다. 담당자가 권한과 점검 스크립트 의존성을 검토한 후 수동 이관해야 한다.

기존 unit의 ExecStart에 실제 Python 3.6 이상 실행 파일이 지정되어 있는지도 확인한다. `NETGUARD_AGENT_PYTHON`은 업데이트 검사용 Python 선택이며 기존 unit의 ExecStart를 바꾸지 않는다. 기존 unit을 수정해야 하면 백업 후 `systemctl edit netguard-agent`에서 다음 예시를 실제 경로에 맞춰 적용한다. 다른 사용자/설치 경로에는 그대로 적용하지 않는다.

```ini
[Unit]
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
ExecStart=
ExecStart=/usr/bin/python3 -B -u /opt/netguard-agent/netguard_agent.py
Restart=on-failure
RestartSec=10
```

```bash
sudo systemctl daemon-reload
sudo systemctl restart netguard-agent
sudo systemctl is-enabled netguard-agent
```

기존 서비스가 disabled였다면 업데이트 후에도 disabled로 유지한다. 부팅 자동 시작이 운영 정책상 필요하면 `sudo systemctl enable netguard-agent`를 별도로 실행한다. drop-in, ACL, SELinux 정책을 자동으로 변경하거나 SELinux를 비활성화하지 않는다.

## 운영 확인

```bash
sudo /opt/netguard-agent/restart_agent.sh
sudo systemctl status netguard-agent --no-pager -l
sudo systemctl is-enabled netguard-agent
sudo journalctl -u netguard-agent -n 50 --no-pager
sudo tail -n 40 /opt/netguard-agent/agent.log
```

`active`만으로 전송 성공을 판단하지 않는다. 설정된 주기마다 `OK cpu=...` 로그 및 중앙 서버 마지막 수집 시각이 증가하는지 확인한다. 소프트웨어 수집은 별도 작업이며 `Software inventory: status=ok`를 확인한다. 권한이 부족한 프로세스/Tomcat 경로는 부분 수집으로 표시할 수 있다. 수집을 위해 에이전트를 root로 변경하지 않는다.

IP는 NetGuard 서버로 향하는 IPv4 경로의 출발지 주소를 선택한다. 외부 인터넷 주소를 조회하지 않는다. DNS/경로가 없으면 로그에 오류가 남고 프로세스가 종료될 수 있으므로 서비스 재시도 설정과 내부 DNS/라우팅을 확인한다. IPv6 전용 연결은 이번 변경의 지원 범위가 아니다.

터미널을 닫은 뒤에도 로그가 증가하는지 확인하고, **다음 승인된 OS 재부팅 후** enabled/active 및 실제 전송 여부를 점검한다. 설치기는 OS를 재부팅하지 않는다.

## 실패 및 원복

- 파일 누락: 설치 스크립트만 옮기지 말고 ZIP 전체를 다시 반입한다.
- Python/명령 없음: OS에 맞는 오프라인 패키지를 준비한다. 중앙 NetGuard 서버의 venv를 복사하지 않는다.
- Permission denied: unit 사용자, 설정 읽기, 로그 경로 쓰기, SELinux AVC 로그를 확인한다. chmod 777 또는 SELinux 전체 해제는 사용하지 않는다.
- HTTP/DNS 실패: agent.log, 서버 URL, 내부 DNS, 기존 방화벽 경로를 확인한다. API 키를 로그/공유 문서에 출력하지 않는다.
- 갱신 후 실패: 중앙 서버는 재시작하지 않는다. 아래 예시의 백업 경로를 실제 출력값으로 바꿔 되돌린다. 백업에 없는 신규 restart_agent.sh는 남겨도 된다.

```bash
sudo systemctl stop netguard-agent
sudo cp -p /var/backups/netguard-agent.ACTUAL/netguard_agent.py /opt/netguard-agent/
sudo cp -p /var/backups/netguard-agent.ACTUAL/software_inventory.py /opt/netguard-agent/
sudo systemctl restart netguard-agent
sudo journalctl -u netguard-agent -n 50 --no-pager
```

변경한 unit/drop-in이 있으면 별도로 검토하여 복원한 후 daemon-reload한다. 업데이트는 기존 설정을 바꾸지 않으므로 설정을 기본 예제로 덮어쓰지 않는다. 백업의 이전 파일이 실제로 존재하는지 확인하고 각 명령 실패 시 다음 단계로 넘어가지 않는다.

## 검증 범위

- Rocky 8/Python 3.6.8, Rocky 9/Python 3.9.18에서 각각 14개 테스트 통과. 개발 PC 전체 회귀는 70개 통과, Linux 컨테이너 전용 8개는 Windows에서 제외 후 위 컨테이너에서 별도 실행했다.
- 네트워크 차단 Rocky Linux 컨테이너에서 설치/업데이트/실패 처리 및 실제 ngagent 파일 권한 검사를 수행했다.
- 실제 systemd-analyze로 신규 unit 문법을 검증했다. 테스트의 systemctl은 대역으로 호출/실패 분기를 검증하며 컨테이너에서 실제 OS 부팅을 검증한 것은 아니다.
- ngagent로 Python 에이전트를 실행하여 loopback 테스트 서버로 등록/메트릭/RPM 인벤토리를 전송했다. 운영 NetGuard 서버로는 전송하지 않았다.
- 운영 Rocky 서버의 SELinux 정책, 실제 부팅/네트워크 복구 동작은 배포 후 운영 확인이 필요하다.
- 개발 검증용 `tests/Dockerfile.linux-agent`는 OS 도구를 준비하는 이미지이며 고객 설치에 필요한 파일이 아니다. 이미지 준비 시 패키지 미러를 이용했고 실제 테스트는 `--network none`으로 외부 접속을 차단했다. 최소 컨테이너 이미지에는 systemd 도구가 없을 수 있으며 이 경우 사전 검사가 중단되는 것도 확인했다.
