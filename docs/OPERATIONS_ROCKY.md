# Rocky Linux 운영 메뉴얼

v1.2.68 / 2026-11-27. 설치·파일 갱신은 [업데이트 안내](OPERATIONS_UPDATE_GUIDE.md)를 따른다.

## 중앙 서버

```bash
sudo systemctl status netguard --no-pager
sudo systemctl is-enabled netguard
sudo journalctl -u netguard -n 100 --no-pager
sudo journalctl -u netguard -f --no-pager | grep --line-buffered -Ei 'advisories|check_jobs|link|error|failed'
```

RSS는 외부 접속이 승인된 경우에만 YAML에서 자동 동기화를 활성화한다. 오류 시 기존 공지를 보존한다. 폐쇄망은 공식 RSS XML 반입 후 마지막 성공 일자를 확인한다. 보고서 저장 경로 `/opt/netguard/data/security_reports`는 netguard 계정 쓰기 가능하며 systemd `ReadWritePaths`에 `/opt/netguard/data`가 포함되어야 한다.

```bash
sudo systemctl show netguard -p ReadWritePaths -p User
sudo -u netguard test -w /opt/netguard/data/security_reports && echo writable
```

## Agent

```bash
sudo systemctl status netguard-agent --no-pager
sudo systemctl is-enabled netguard-agent
sudo journalctl -u netguard-agent -n 80 --no-pager
sudo tail -n 50 /opt/netguard-agent/agent.log
sudo systemctl restart netguard-agent
```

Agent 본체는 ngagent 계정이다. 원격 점검은 root 소유 allowlist wrapper로만 승격하며 전체 sudo 권한을 주지 않는다. `sudo -l -U ngagent`, `sudo visudo -cf /etc/sudoers.d/netguard-checks`로 허용 범위를 점검한다. wrapper/점검 스크립트가 ngagent 쓰기 가능하면 안 된다.

점검 결과는 `/var/lib/netguard-checks/<job_id>/`, 전송 대기 상태는 `/opt/netguard-agent/remote_check_pending.json`, 실행 로그는 `/opt/netguard-agent/remote_check_runner.log`이다. 수집 로그는 계속 갱신되면서 점검이 별도로 수행되어야 한다. 대기 파일은 결과 재전송에 사용하므로 임의 삭제하지 않는다. 최대 실행 시간 30분, 서버에서 결과 미수신 판정 45분이다.

## 일상 점검 및 백업

- `queued` 15분 만료는 Agent 연결/연결키/방화벽을 확인한다. HTTP 403은 연결키를 확인하며 실제 키를 로그나 채팅으로 전달하지 않는다.
- `failed`는 작업 결과 상세와 로컬 runner 로그 확인. `unknown`은 자동 재실행하지 않으므로 실제 프로세스 종료와 보고서를 확인한 뒤 새 요청한다.
- 중앙 PostgreSQL과 `data/security_reports`, Agent 출력물을 승인된 보존 정책에 따라 백업한다. 실제 결과 파일 삭제 전에 서버 다운로드와 백업을 검증한다.
- 링크 Down은 ifAdminStatus=Up, 유효한 ifOperStatus=Down을 연속 2회 확인한 경우다. 장비 시간/서버 시간과 스위치 로그를 대조한다. 수집 실패를 물리 링크 Down으로 단정하지 않는다.
- 자동 시작은 `systemctl is-enabled netguard netguard-agent`로 확인한다. 두 서비스는 서로 다른 서버에 설치되는 경우가 일반적이므로 각 서버에서 해당 서비스만 조회한다.
