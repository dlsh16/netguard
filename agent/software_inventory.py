"""Read-only software inventory worker. No application binaries are executed."""
import argparse
import glob
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

AGENT_VERSION = '1.2.64'
MAX_ITEMS = 10000


def item(name, version='', path='', publisher='', source='process'):
    return {'name': str(name).strip()[:300], 'version': str(version or '').strip()[:150],
            'installation_path': str(path or '')[:1024], 'publisher': str(publisher or '')[:300], 'source': source}


def read_tomcat(home):
    archive = Path(home) / 'lib' / 'catalina.jar'
    with zipfile.ZipFile(str(archive)) as jar:
        info = jar.getinfo('org/apache/catalina/util/ServerInfo.properties')
        if info.file_size > 65536:
            raise ValueError('Tomcat version metadata too large')
        values = {}
        for line in jar.read(info).decode('utf-8', errors='replace').splitlines():
            if '=' in line and not line.lstrip().startswith(('#', '!')):
                key, value = line.split('=', 1)
                values[key.strip()] = value.strip()
    version = values.get('server.info', '').partition('/')[2] or values.get('server.number', '')
    if '@' in version:
        version = ''
    return item('Apache Tomcat', version, str(Path(home)), 'Apache Software Foundation', 'tomcat')


def parse_rpm(text):
    result = []
    for line in text.splitlines():
        fields = line.split('\t')
        if len(fields) >= 3 and fields[0]:
            result.append(item(fields[0], fields[1], publisher=fields[2].replace('(none)', ''), source='rpm'))
    return result


def parse_dpkg(text):
    result = []
    for line in text.splitlines():
        fields = line.split('\t')
        if len(fields) >= 3 and fields[2] == 'installed':
            result.append(item(fields[0], fields[1], source='dpkg'))
    return result


def binary_metadata(executable):
    path = Path(executable)
    name = path.name
    if name in ('node', 'nodejs'):
        return 'Node.js', ''
    if re.fullmatch(r'php(?:-fpm)?(?:\d+(?:\.\d+)*)?', name):
        # A nearby development header may belong to another installed version.
        return 'PHP', ''
    return name, ''


def tomcat_homes_from_args(arguments):
    return [arg.split('=', 1)[1] for arg in arguments if arg.startswith(('-Dcatalina.home=', '-Dcatalina.base='))]


def collect_linux(options):
    entries, errors, complete = [], [], []
    homes = set(options.get('tomcat_homes') or [])
    for pattern in ('/opt/tomcat*', '/usr/share/tomcat*', '/var/lib/tomcat*'):
        homes.update(glob.glob(pattern))
    env = dict(os.environ, LC_ALL='C')
    package_tool = shutil.which('rpm') or shutil.which('dpkg-query')
    if package_tool:
        rpm = Path(package_tool).name == 'rpm'
        source = 'rpm' if rpm else 'dpkg'
        args = [package_tool, '-qa', '--queryformat', '%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n'] if rpm else [package_tool, '-W', '-f=${binary:Package}\t${Version}\t${db:Status-Status}\n']
        try:
            response = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, env=env, universal_newlines=True)
            if response.returncode:
                raise ValueError('package query failed')
            entries.extend(parse_rpm(response.stdout) if rpm else parse_dpkg(response.stdout))
            complete.append(source)
        except Exception:
            errors.append(source + ': package list could not be read')
    else:
        errors.append('packages: rpm/dpkg-query unavailable')
    try:
        processes = [path for path in Path('/proc').iterdir() if path.name.isdigit()]
        seen = set()
        process_access_limited = False
        for process in processes[:10000]:
            try:
                executable = os.readlink(str(process / 'exe'))
                if executable.endswith(' (deleted)'):
                    executable = executable[:-10]
                if executable not in seen:
                    seen.add(executable)
                    name, version = binary_metadata(executable)
                    entries.append(item(name, version, executable))
                with (process / 'cmdline').open('rb') as command:
                    arguments = command.read(65536).decode(errors='replace').split('\0')
                homes.update(tomcat_homes_from_args(arguments))
            except (OSError, ValueError) as error:
                if isinstance(error, PermissionError):
                    process_access_limited = True
                try:
                    name = (process / 'comm').read_text().strip()
                    if name and name not in seen:
                        seen.add(name)
                        entries.append(item(name))
                except OSError:
                    pass
        if process_access_limited:
            errors.append('process: access restricted; some executable metadata unavailable')
        elif len(processes) <= 10000:
            complete.append('process')
        else:
            errors.append('process: enumeration limit reached')
    except OSError:
        errors.append('process: /proc could not be read')
    tomcat_ok = True
    for home in sorted(homes)[:100]:
        try:
            if (Path(home) / 'lib' / 'catalina.jar').is_file():
                entries.append(read_tomcat(home))
            elif home in (options.get('tomcat_homes') or []):
                errors.append('tomcat: configured home missing or unreadable')
                tomcat_ok = False
        except (OSError, ValueError, KeyError, zipfile.BadZipFile):
            tomcat_ok = False
            errors.append('tomcat: version metadata could not be read')
    if tomcat_ok and len(homes) <= 100:
        complete.append('tomcat')
    else:
        errors.append('tomcat: incomplete discovery')
    for definition in (options.get('extra_software') or [])[:1000]:
        if definition.get('name'):
            entries.append(item(definition['name'], definition.get('version'), definition.get('installation_path'), definition.get('publisher'), 'configured'))
    if len(options.get('extra_software') or []) <= 1000:
        complete.append('configured')
    else:
        errors.append('configured: entry limit reached')
    unique = {(entry['source'], entry['name'].casefold(), entry['version'], entry['installation_path']): entry for entry in entries}
    if len(unique) > MAX_ITEMS:
        errors.append('inventory: item limit reached; snapshot is not authoritative')
        complete = []
    return {'items': list(unique.values())[:MAX_ITEMS], 'complete_sources': complete, 'errors': list(dict.fromkeys(errors))[:20], 'os_family': 'linux'}


def collect_windows(config_path):
    script = Path(__file__).with_suffix('.ps1')
    args = ['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', str(script), '-Collect', '-ConfigPath', str(config_path)]
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=110,
                            encoding='utf-8-sig', creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if result.returncode:
        raise RuntimeError('Windows software collector failed')
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=Path(__file__).with_name('agent_config.json'))
    parser.add_argument('--send', action='store_true')
    args = parser.parse_args()
    from netguard_agent import load_config, local_ip, post_json
    config = load_config(args.config)
    try:
        report = collect_windows(args.config) if platform.system() == 'Windows' else collect_linux(config.get('software_inventory') or {})
        report.update(hostname=config['hostname'], ip_address=local_ip(), collected_at=datetime.now(timezone.utc).isoformat(), agent_version=AGENT_VERSION)
        if args.send:
            result = post_json(config['server_url'] + '/api/agent/software', report, config['api_key'], timeout=30)
            print('Software inventory: status={} items={} collection={}'.format(result.get('status'), result.get('items', 0), result.get('collection_status', '')))
        else:
            print(json.dumps(report, ensure_ascii=False))
    except Exception as error:
        print('Software inventory failed: ' + str(error)[:200], file=sys.stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
