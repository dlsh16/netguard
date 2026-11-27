"""Build source-only offline update ZIPs. Never include live settings or runtime data."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from zipfile import ZipFile, ZIP_DEFLATED, ZipInfo

ROOT = Path(__file__).resolve().parents[1]


def files():
    raw = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], cwd=ROOT)
    return sorted(set(raw.decode('utf-8').strip('\0').split('\0')))


def included(name, kind):
    if name.endswith(('.pyc', '.log')) or '__pycache__' in name:
        return False
    if name in ('config/config.yaml', 'agent/agent_config.json') or 'snmp_collector_0529' in name:
        return False
    if name.startswith('docs/'):
        return True
    if kind == 'server':
        return name == 'requirements.txt' or name == 'config/config.example.yaml' or name.startswith(
            ('backend/', 'frontend/', 'agent/', 'scripts/', 'deploy/', 'tests/'))
    if kind == 'windows':
        return name.startswith('agent/') and not name.endswith('.sh')
    return (name.startswith('agent/') and name.endswith(('.py', '.sh'))) or name in (
        'scripts/install_agent_linux.sh', 'scripts/linux_agent_setup.py',
        'scripts/enable_remote_checks_linux.sh', 'scripts/netguard-run-check')


def source_bytes(name):
    path = ROOT / name
    if path.is_symlink() or ROOT not in path.resolve().parents:
        raise ValueError('Unsafe source path: ' + name)
    data = path.read_bytes()
    # Preserve PowerShell BOM while standardizing line endings for the target OS.
    if path.suffix in ('.ps1', '.bat'):
        data = data.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')
    elif path.suffix in ('.sh', '.py', '.service', '.timer') or path.name == 'netguard-run-check':
        data = data.replace(b'\r\n', b'\n')
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', required=True)
    parser.add_argument('--output-dir', type=Path, default=ROOT.parent)
    args = parser.parse_args()
    if not re.fullmatch(r'\d+\.\d+\.\d+', args.version):
        parser.error('Use a numeric version, such as 1.2.68')
    args.output_dir.mkdir(parents=True, exist_ok=True)
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT).decode().strip()
    dirty = bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT))
    paths = files()
    checksums = []
    for kind, label in (('server', 'NetGuard'), ('windows', 'NetGuard-Agent-Windows'), ('linux', 'NetGuard-Agent-Linux')):
        base = '{}-v{}'.format(label, args.version)
        archive = args.output_dir / (base + '.zip')
        selected = [name for name in paths if included(name, kind)]
        manifest = {'version': args.version, 'revision': revision, 'dirty_source': dirty, 'files': {}}
        with ZipFile(archive, 'x', ZIP_DEFLATED) as target:
            for name in selected:
                data = source_bytes(name)
                entry = ZipInfo(base + '/' + name)
                entry.compress_type = ZIP_DEFLATED
                entry.create_system = 3
                executable = name.endswith('.sh') or name == 'scripts/netguard-run-check'
                entry.external_attr = (0o100755 if executable else 0o100644) << 16
                target.writestr(entry, data)
                manifest['files'][name] = hashlib.sha256(data).hexdigest()
            target.writestr(base + '/release-manifest.json', json.dumps(manifest, ensure_ascii=False, indent=2))
        with ZipFile(archive) as check:
            if check.testzip():
                raise RuntimeError('Archive verification failed: ' + str(archive))
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        checksums.append(digest + '  ' + archive.name)
        print('{} ({} files, {} bytes)'.format(archive, len(selected), archive.stat().st_size))
    checksum = args.output_dir / ('NetGuard-v' + args.version + '-SHA256.txt')
    with checksum.open('x', encoding='ascii') as file:
        file.write('\n'.join(checksums) + '\n')
    print(checksum)


if __name__ == '__main__':
    main()
