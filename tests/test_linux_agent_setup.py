"""Linux installer unit tests; optional integration requires an isolated Docker container."""
import importlib.util
import http.server
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'agent'))
import netguard_agent
spec = importlib.util.spec_from_file_location('linux_setup', ROOT / 'scripts/linux_agent_setup.py')
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


class LinuxSetupTests(unittest.TestCase):
    def test_display_name_default_custom_and_json_roundtrip(self):
        env = dict(NG_URL='10.60.8.186:8000', NG_KEY='fixture', NG_INTERVAL='60', NG_TYPE='server', NG_LOCATION='')
        with patch.object(setup.socket, 'gethostname', return_value='linux-os-host'):
            self.assertEqual(setup.new_config(env)['hostname'], 'linux-os-host')
            env['NG_HOSTNAME'] = '   '
            self.assertEqual(setup.new_config(env)['hostname'], 'linux-os-host')
            name = '\uC11C\uBC84 DB "A" \\ $(not-a-command)'
            env['NG_HOSTNAME'] = '  ' + name + '  '
            self.assertEqual(json.loads(json.dumps(setup.new_config(env)))['hostname'], name)

    def test_display_name_length_and_control_characters(self):
        env = dict(NG_URL='http://192.0.2.1:8000', NG_KEY='fixture', NG_INTERVAL='60', NG_TYPE='server', NG_LOCATION='')
        env['NG_HOSTNAME'] = 'A' * 100
        self.assertEqual(setup.new_config(env)['hostname'], env['NG_HOSTNAME'])
        for name in ('A' * 101, 'server\tname', 'server\nname', 'server\x00name', 'server\x7fname'):
            env['NG_HOSTNAME'] = name
            self.assertRaises(ValueError, setup.new_config, env)

    def test_config_escapes_unicode_quotes_and_backslashes(self):
        env = dict(NG_URL='10.60.8.186:8000/', NG_KEY='test-"\\key', NG_INTERVAL='60', NG_TYPE='server', NG_LOCATION='\uC11C\uBC84\uC2E4 "A" \\ rack')
        config = json.loads(json.dumps(setup.new_config(env)))
        self.assertEqual(config['api_key'], env['NG_KEY'])
        self.assertEqual(config['location'], env['NG_LOCATION'])
        self.assertEqual(config['server_url'], 'http://10.60.8.186:8000')
        for value in ('0', '-1', 'abc', '1.5', '999999999'):
            env['NG_INTERVAL'] = value
            self.assertRaises(ValueError, setup.new_config, env)

    def test_config_validation_does_not_mutate_custom_settings(self):
        config = {'server_url': 'https://netguard.internal:8443', 'api_key': 'fixture', 'interval': 30, 'software_inventory': {'enabled': False}, 'custom': {'keep': True}}
        before = json.dumps(config)
        setup.validate_config(config)
        self.assertEqual(json.dumps(config), before)
        for url in ('ftp://host', 'http://host:bad', 'http://host:0', 'http://user:password@host', 'http://host/?key=secret'):
            self.assertRaises(ValueError, setup.validate_config, dict(config, server_url=url))

    def test_unit_uses_unprivileged_account_network_order_and_absolute_python(self):
        text = setup.unit('/usr/bin/python3.9')
        self.assertIn('ExecStart=/usr/bin/python3.9 -B -u ', text)
        self.assertIn('User=ngagent', text)
        self.assertIn('After=network-online.target', text)
        self.assertIn('KillMode=control-group', text)
        self.assertIn('StartLimitIntervalSec=0', text.split('[Service]')[0])
        self.assertNotIn('StartLimit', text.split('[Service]')[1])

    def test_route_selection_uses_netguard_endpoint_and_closes_socket(self):
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.getsockname.return_value = ('192.0.2.10', 12345)
        with patch.object(netguard_agent.socket, 'socket', return_value=connection):
            self.assertEqual(netguard_agent.local_ip('https://netguard.internal:8443'), '192.0.2.10')
        connection.connect.assert_called_once_with(('netguard.internal', 8443))
        connection.__exit__.assert_called_once()
        connection.send.assert_not_called()

    def test_route_failure_is_not_registered_as_loopback(self):
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.connect.side_effect = OSError('no route')
        with patch.object(netguard_agent.socket, 'socket', return_value=connection):
            self.assertRaises(OSError, netguard_agent.local_ip, 'http://192.0.2.1:8000')
        connection.__exit__.assert_called_once()

    def test_security_subprocess_uses_python36_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            cfg = {'security_checks': {'enabled': True, 'scripts': [{'command': ['true'], 'output_dir': directory}]}}
            with patch.object(netguard_agent.subprocess, 'run', return_value=Mock(returncode=0)) as run:
                netguard_agent.run_security_checks(cfg, '', '', '', Mock())
            kwargs = run.call_args[1]
            self.assertNotIn('capture_output', kwargs)
            self.assertNotIn('text', kwargs)
            self.assertTrue(kwargs['universal_newlines'])


ISOLATED = os.getenv('NETGUARD_LINUX_INSTALL_TEST') == '1' and Path('/.dockerenv').exists() and sys.platform == 'linux'


@unittest.skipUnless(ISOLATED, 'Requires disposable Docker container; never a host/production server')
class LinuxInstallerIntegrationTests(unittest.TestCase):
    target = Path('/opt/netguard-agent')
    unit = Path('/etc/systemd/system/netguard-agent.service')

    def setUp(self):
        if self.target.exists() or self.unit.exists():
            raise RuntimeError('Refusing to overwrite a pre-existing agent installation')
        self.temp = tempfile.TemporaryDirectory(prefix='netguard-installer-')
        self.source = Path(self.temp.name) / 'package with spaces'
        (self.source / 'scripts').mkdir(parents=True)
        (self.source / 'agent').mkdir()
        for name in ('install_agent_linux.sh', 'linux_agent_setup.py'):
            shutil.copy2(ROOT / 'scripts' / name, self.source / 'scripts' / name)
        for name in ('netguard_agent.py', 'software_inventory.py', 'restart_agent.sh'):
            shutil.copy2(ROOT / 'agent' / name, self.source / 'agent' / name)
        self.bin = Path(self.temp.name) / 'bin'
        self.bin.mkdir()
        self.calls = Path(self.temp.name) / 'calls.jsonl'
        mock = self.bin / 'systemctl'
        mock.write_text('''#!%s
import json, os, sys
args = sys.argv[1:]
with open(os.environ['NG_TEST_CALLS'], 'a') as f: f.write(json.dumps(args) + '\\n')
if args[0] == 'show':
    prop = args[args.index('-p') + 1]
    print({'User': 'ngagent', 'WorkingDirectory': '/opt/netguard-agent', 'LoadState': 'not-found'}[prop])
elif args[0] == 'is-active': sys.exit(int(os.getenv('NG_TEST_START_FAIL', '0')))
elif args[0] == 'is-enabled': print('disabled' if os.getenv('NG_TEST_DISABLED') else 'enabled')
''' % sys.executable, encoding='ascii')
        mock.chmod(0o755)
        sleep = self.bin / 'sleep'
        sleep.write_text('#!/bin/sh\nexit 0\n', encoding='ascii')
        sleep.chmod(0o755)
        Path('/run/systemd/system').mkdir(parents=True, exist_ok=True)
        Path('/etc/systemd/system').mkdir(parents=True, exist_ok=True)
        Path('/run/lock').mkdir(parents=True, exist_ok=True)
        self.env = dict(os.environ, PATH=str(self.bin) + ':' + os.environ['PATH'], NG_TEST_CALLS=str(self.calls), NETGUARD_AGENT_PYTHON=sys.executable)

    def tearDown(self):
        # Only reached in the isolated container after setUp verified these absent.
        if self.target.exists(): shutil.rmtree(str(self.target))
        if self.unit.exists(): self.unit.unlink()
        self.temp.cleanup()

    def run_installer(self, *args, **kwargs):
        return subprocess.run(['bash', str(self.source / 'scripts/install_agent_linux.sh')] + list(args),
                              input=kwargs.get('input', '\n\n60\n\nserver\nfixture "A" \\ rack\n'),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                              env=self.env, timeout=30)

    def calls_list(self):
        return [json.loads(line) for line in self.calls.read_text().splitlines()] if self.calls.exists() else []

    def install(self, **kwargs):
        result = self.run_installer(**kwargs)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def test_check_and_missing_package_do_not_change_installation(self):
        result = self.run_installer('--check')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.target.exists())
        self.assertFalse(self.calls_list())
        (self.source / 'agent/software_inventory.py').unlink()
        self.assertNotEqual(self.run_installer('--check').returncode, 0)
        self.assertFalse(self.target.exists())

    def test_install_files_permissions_unit_and_enable(self):
        self.install()
        config = json.loads((self.target / 'agent_config.json').read_text())
        self.assertEqual(config['hostname'], socket.gethostname())
        self.assertEqual(config['location'], 'fixture "A" \\ rack')
        self.assertTrue((self.target / 'restart_agent.sh').stat().st_mode & 0o100)
        self.assertEqual((self.target / 'agent_config.json').stat().st_mode & 0o777, 0o640)
        self.assertEqual((self.target / 'netguard_agent.py').stat().st_uid, 0)
        self.assertIn(['enable', 'netguard-agent'], self.calls_list())
        self.assertIn(['restart', 'netguard-agent'], self.calls_list())
        self.assertIn('ExecStart=' + sys.executable, self.unit.read_text())
        result = subprocess.run(['runuser', '-u', 'ngagent', '--', sys.executable, '-B', '-c',
                                 'import sys; sys.path.insert(0,"/opt/netguard-agent"); import netguard_agent, software_inventory'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_update_preserves_config_unit_and_disabled_state_with_backup(self):
        original_os_name = socket.gethostname()
        custom_name = '\uC11C\uBC84 DB "Primary" \\ Rack-1'
        self.install(input='\n\n60\n' + custom_name + '\nserver\nfixture\n')
        cfg = self.target / 'agent_config.json'
        self.assertEqual(json.loads(cfg.read_text())['hostname'], custom_name)
        self.assertEqual(socket.gethostname(), original_os_name)
        content = cfg.read_bytes().replace(b'"interval": 60', b'"interval": 17')
        cfg.write_bytes(content)
        unit = self.unit.read_bytes()
        self.calls.unlink()
        self.env['NG_TEST_DISABLED'] = '1'
        result = self.run_installer('--update', input='')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(cfg.read_bytes(), content)
        self.assertEqual(self.unit.read_bytes(), unit)
        self.assertNotIn(['enable', 'netguard-agent'], self.calls_list())
        backups = list(Path('/var/backups').glob('netguard-agent.*/agent_config.json'))
        self.assertTrue(any(path.read_bytes() == content for path in backups))
        self.assertIn('disabled', result.stdout)

    def test_reinstall_refused_without_resetting_configuration(self):
        self.install()
        before = (self.target / 'agent_config.json').read_bytes()
        self.calls.unlink()
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Use --update', result.stderr)
        self.assertEqual((self.target / 'agent_config.json').read_bytes(), before)
        self.assertFalse(self.calls_list())

    def test_invalid_input_stops_before_install_and_service_changes(self):
        result = self.run_installer(input='\n\ninvalid\n\nserver\nlocation\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.target.exists())
        self.assertNotIn(['restart', 'netguard-agent'], self.calls_list())

    def test_invalid_display_name_stops_before_install(self):
        result = self.run_installer(input='\n\n60\n' + ('A' * 101) + '\nserver\nlocation\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('display name', result.stderr)
        self.assertFalse(self.target.exists())
        self.assertNotIn(['restart', 'netguard-agent'], self.calls_list())

    def test_bad_config_or_syntax_leaves_existing_agent_untouched(self):
        self.install()
        self.calls.unlink()
        cfg = self.target / 'agent_config.json'
        cfg.write_text('invalid json')
        self.assertNotEqual(self.run_installer('--update', input='').returncode, 0)
        self.assertEqual(cfg.read_text(), 'invalid json')
        self.assertFalse(self.calls_list())
        cfg.unlink()
        (self.source / 'agent/netguard_agent.py').write_text('syntax error @')
        self.assertNotEqual(self.run_installer('--check').returncode, 0)

    def test_inactive_start_and_restart_are_failures(self):
        self.env['NG_TEST_START_FAIL'] = '1'
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('Agent is active', result.stdout)
        result = subprocess.run(['bash', str(self.target / 'restart_agent.sh')], env=self.env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Restart failed', result.stderr)

    def test_real_python36_metrics_and_inventory_send_as_service_account(self):
        custom_name = '\uC11C\uBC84-LINUX-DB01'
        self.install(input='\n\n60\n' + custom_name + '\nserver\nfixture\n')
        reports = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                reports.append((self.path, body))
                reply = b'{"status":"ok","items":1,"collection_status":"complete"}'
                self.send_response(200)
                self.send_header('Content-Length', str(len(reply)))
                self.end_headers()
                self.wfile.write(reply)
        server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        cfg = self.target / 'agent_config.json'
        config = json.loads(cfg.read_text())
        config.update(server_url='http://127.0.0.1:' + str(server.server_port), interval=1)
        cfg.write_text(json.dumps(config))
        process = subprocess.Popen(['runuser', '-u', 'ngagent', '--', sys.executable, '-B', '-u', str(self.target / 'netguard_agent.py')],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
        try:
            deadline = time.monotonic() + 25
            expected = {'/api/agent/register', '/api/agent/metrics', '/api/agent/software'}
            while time.monotonic() < deadline and not expected.issubset({path for path, body in reports}):
                if process.poll() is not None:
                    self.fail(process.communicate()[1].decode(errors='replace'))
                time.sleep(.1)
            self.assertTrue(expected.issubset({path for path, body in reports}))
            inventory = next(body for path, body in reports if path.endswith('/software'))
            self.assertIn('rpm', inventory['complete_sources'])
            self.assertTrue(inventory['items'])
            self.assertTrue(all(body['ip_address'] == '127.0.0.1' for path, body in reports))
            self.assertTrue(all(body['hostname'] == custom_name for path, body in reports))
        finally:
            if process.poll() is None: os.killpg(process.pid, signal.SIGTERM)
            process.communicate(timeout=10)
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == '__main__':
    unittest.main()
