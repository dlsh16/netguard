"""Collector fixtures and nonblocking worker checks; never posts to a real server."""
import importlib.util
import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'agent'))
spec = importlib.util.spec_from_file_location('inventory_collector', ROOT / 'agent/software_inventory.py')
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)
import netguard_agent


class SoftwareCollectorTests(unittest.TestCase):
    def test_package_parsers(self):
        self.assertEqual(collector.parse_rpm('php\t8.2.28-1.el9\tRocky\n')[0]['version'], '8.2.28-1.el9')
        self.assertEqual(len(collector.parse_dpkg('php8.2\t8.2.28\tinstalled\nremoved\t1\tconfig-files\n')), 1)
        self.assertEqual(collector.binary_metadata('/usr/bin/node'), ('Node.js', ''))
        self.assertEqual(collector.binary_metadata('/usr/sbin/php-fpm'), ('PHP', ''))

    def test_tomcat_offline_metadata_and_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory); (home / 'lib').mkdir()
            for text, expected in [('server.info=Apache Tomcat/10.1.39\n', '10.1.39'), ('server.info=Apache Tomcat/@VERSION@\n', '')]:
                with zipfile.ZipFile(home / 'lib/catalina.jar', 'w') as archive:
                    archive.writestr('org/apache/catalina/util/ServerInfo.properties', text)
                self.assertEqual(collector.read_tomcat(home)['version'], expected)

    def test_tomcat_arguments_do_not_include_secrets(self):
        args = ['java', '-Dpassword=secret', '-Dcatalina.home=/opt/tomcat A', '-Dcatalina.base=/srv/tomcat']
        self.assertEqual(collector.tomcat_homes_from_args(args), ['/opt/tomcat A', '/srv/tomcat'])

    def test_missing_packages_preserve_source_and_custom_software(self):
        with patch.object(collector.shutil, 'which', return_value=None), patch.object(collector.glob, 'glob', return_value=[]), patch.object(Path, 'iterdir', side_effect=PermissionError):
            result = collector.collect_linux({'extra_software': [{'name': 'Risk & Compliance Management Solution', 'version': '3.4'}]})
        self.assertNotIn('rpm', result['complete_sources'])
        self.assertNotIn('process', result['complete_sources'])
        self.assertEqual(result['items'][0]['version'], '3.4')
        self.assertEqual(len(result['errors']), 2)

    def test_worker_launch_is_nonblocking_and_disabled_is_respected(self):
        logger = Mock()
        process = Mock(); process.poll.return_value = None
        with patch.object(netguard_agent.subprocess, 'Popen', return_value=process) as start:
            worker = netguard_agent.SoftwareInventoryWorker({}, logger)
            worker.tick(); worker.tick()
            start.assert_called_once()
            process.communicate.assert_not_called()
            process.wait.assert_not_called()
            self.assertIn('--send', start.call_args.args[0])
            netguard_agent.SoftwareInventoryWorker({'software_inventory': {'enabled': False}}, logger).tick()
            start.assert_called_once()

    def test_worker_timeout_retry_and_success_interval(self):
        process = Mock(returncode=1); process.poll.return_value = None; process.communicate.return_value = (b'', b'test')
        worker = netguard_agent.SoftwareInventoryWorker({}, Mock()); worker.process = process
        with patch.object(netguard_agent.time, 'monotonic', return_value=200):
            worker.tick()
        process.kill.assert_called_once(); self.assertEqual(worker.next_run, 500)
        process.poll.return_value = 0; process.returncode = 0; process.communicate.return_value = (b'OK', b'')
        worker.process = process
        with patch.object(netguard_agent.time, 'monotonic', return_value=600):
            worker.tick()
        self.assertEqual(worker.next_run, 600 + 6 * 3600)

    def test_config_bom_preserves_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            path.write_text(json.dumps({'server_url': 'http://127.0.0.1:9999', 'hostname': 'fixture', 'software_inventory': {'enabled': False}}), encoding='utf-8-sig')
            cfg = netguard_agent.load_config(path)
            self.assertEqual(cfg['hostname'], 'fixture')
            self.assertFalse(cfg['software_inventory']['enabled'])

    @unittest.skipUnless(os.name == 'nt', 'Windows PowerShell test')
    def test_windows_workers_send_valid_json_to_loopback_only(self):
        reports = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                reports.append((self.path, self.headers.get('X-Agent-Key'), json.loads(self.rfile.read(int(self.headers['Content-Length'])))))
                body = b'{"status":"ok","items":1,"collection_status":"complete"}'
                self.send_response(200); self.send_header('Content-Type', 'application/json'); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
        server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                config = Path(directory) / 'config.json'
                config.write_text(json.dumps({'server_url': 'http://127.0.0.1:' + str(server.server_port), 'api_key': 'fixture-only', 'hostname': 'fixture-agent'}), encoding='utf-8-sig')
                commands = [
                    ['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', str(ROOT / 'agent/software_inventory.ps1'), '-Send', '-ConfigPath', str(config)],
                    [sys.executable, str(ROOT / 'agent/software_inventory.py'), '--send', '--config', str(config)],
                ]
                for command in commands:
                    result = subprocess.run(command, capture_output=True, timeout=120)
                    self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
                    self.assertIn(b'status=ok', result.stdout)
            self.assertEqual(len(reports), 2)
            for endpoint, key, report in reports:
                self.assertEqual(endpoint, '/api/agent/software')
                self.assertEqual(key, 'fixture-only')
                self.assertEqual(report['hostname'], 'fixture-agent')
                self.assertEqual(report['agent_version'], '1.2.63')
                self.assertTrue(0 < len(report['items']) <= 10000)
                self.assertNotIn('command_line', json.dumps(report))
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=5)

    @unittest.skipUnless(os.name == 'nt', 'Windows PowerShell test')
    def test_powershell_51_metadata_and_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory); (home / 'lib').mkdir()
            with zipfile.ZipFile(home / 'lib/catalina.jar', 'w') as archive:
                archive.writestr('org/apache/catalina/util/ServerInfo.properties', 'server.info=Apache Tomcat/10.1.39\n')
            script = str(ROOT / 'agent/software_inventory.ps1').replace("'", "''")
            command = ". '" + script + "'; $item = Read-TomcatInventory '" + directory.replace("'", "''") + "'; if ($item.version -ne '10.1.39') { throw 'Wrong Tomcat version' }; $files = Get-ChildItem '" + str(ROOT / 'agent') + "' -Filter *.ps1; foreach ($file in $files) { $e=$null; $t=$null; [System.Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$t,[ref]$e) | Out-Null; if ($e) { throw $e[0] } }; Write-Output 'PASS'"
            result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', command], capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            self.assertIn(b'PASS', result.stdout)


if __name__ == '__main__':
    unittest.main()
