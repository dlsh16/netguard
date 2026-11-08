"""Offline validation/rendering for install_agent_linux.sh (Python 3.6+)."""
import json
import os
from pathlib import Path
import socket
import sys
from urllib.parse import urlsplit


def validate_config(config):
    if not isinstance(config, dict):
        raise ValueError('Configuration must be a JSON object')
    for key in ('server_url', 'api_key'):
        if not isinstance(config.get(key), str) or not config[key].strip():
            raise ValueError(key + ' must be a nonempty string')
    url = config['server_url'].strip()
    parsed = urlsplit(url if '://' in url else 'http://' + url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('server_url must be an HTTP(S) URL without embedded credentials')
    try:
        port = parsed.port
    except ValueError:
        raise ValueError('server_url port is invalid')
    if port == 0 or parsed.query or parsed.fragment or any(c.isspace() for c in url):
        raise ValueError('server_url contains an invalid port, whitespace, query or fragment')
    interval = config.get('interval', 60)
    if type(interval) is not int or not 1 <= interval <= 86400:
        raise ValueError('interval must be an integer from 1 to 86400 seconds')
    for key in ('hostname', 'location', 'log_file', 'device_type'):
        if key in config and not isinstance(config[key], str):
            raise ValueError(key + ' must be a string')
    for key in ('software_inventory', 'security_checks'):
        if config.get(key) is not None and not isinstance(config[key], dict):
            raise ValueError(key + ' must be a JSON object')
    return config


def new_config(env):
    url = env['NG_URL'].strip()
    if '://' not in url:
        url = 'http://' + url
    try:
        interval = int(env['NG_INTERVAL'])
    except ValueError:
        raise ValueError('interval must be an integer')
    return validate_config({
        'server_url': url.rstrip('/'), 'api_key': env['NG_KEY'], 'interval': interval,
        'hostname': socket.gethostname(), 'device_type': env['NG_TYPE'],
        'location': env['NG_LOCATION'], 'log_file': '/opt/netguard-agent/agent.log',
        'software_inventory': {'enabled': True, 'interval_hours': 6, 'tomcat_homes': [], 'extra_software': []},
    })


def check_files(source, config_path, installed=False):
    for name in ('netguard_agent.py', 'software_inventory.py'):
        path = Path(source) / name
        compile(path.read_bytes(), str(path), 'exec')
    if not (Path(source) / 'restart_agent.sh').is_file():
        raise ValueError('restart_agent.sh missing')
    if Path(config_path).is_file():
        with open(config_path, encoding='utf-8-sig') as file:
            config = validate_config(json.load(file))
        if installed:
            log = config.get('log_file', '')
            if log:
                target = Path(log)
                if not target.is_absolute():
                    target = Path(source) / target
                writable = target if target.exists() else target.parent
                if not os.access(str(writable), os.W_OK):
                    raise ValueError('Service account cannot write the configured log path')
    elif installed:
        raise ValueError('Installed configuration missing')
    print('Agent files and configuration checks passed.')


def unit(python):
    return '''[Unit]
Description=NetGuard Monitoring Agent
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=ngagent
Group=ngagent
WorkingDirectory=/opt/netguard-agent
ExecStart={} -B -u /opt/netguard-agent/netguard_agent.py
Restart=on-failure
RestartSec=10
KillMode=control-group
UMask=0027
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
'''.format(python)


def main():
    try:
        if sys.version_info < (3, 6):
            raise ValueError('Python 3.6 or later is required')
        command = sys.argv[1]
        if command in ('check', 'check-installed'):
            check_files(sys.argv[2], sys.argv[3], command == 'check-installed')
        elif command == 'config':
            print(json.dumps(new_config(os.environ), ensure_ascii=True, indent=2))
        elif command == 'unit':
            print(unit(sys.argv[2]), end='')
        else:
            raise ValueError('Unknown setup operation')
    except (ValueError, OSError, SyntaxError, KeyError, IndexError) as error:
        # Never echo submitted JSON or API key values in failure output.
        print('Agent setup validation failed: ' + str(error)[:200], file=sys.stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
