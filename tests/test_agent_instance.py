"""No service changes; locks use short-lived child processes and local fixtures."""
import json
import http.server
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'agent'))
import netguard_agent as agent


class InstanceTests(unittest.TestCase):
    def python(self, code):
        return [sys.executable, '-B', '-u', '-c',
                'import sys; sys.path.insert(0, ' + repr(str(ROOT / 'agent')) + '); import netguard_agent as a; ' + code]

    def powershell(self, code):
        return ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
                ". '" + str(ROOT / 'agent/windows_agent_common.ps1').replace("'", "''") + "'; $ErrorActionPreference='Stop'; " + code]

    def assert_lock_pair(self, owner_command, contender_command):
        owner = subprocess.Popen(owner_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.assertEqual(owner.stdout.readline().strip(), b'LOCKED')
            blocked = subprocess.run(contender_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            self.assertEqual(blocked.returncode, 0, blocked.stderr)
            self.assertIn(b'BLOCKED', blocked.stdout)
        finally:
            owner.kill()
            owner.communicate(timeout=10)
        recovered = subprocess.run(contender_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        self.assertIn(b'ACQUIRED', recovered.stdout)

    def test_python_duplicate_and_crash_release(self):
        self.assert_lock_pair(
            self.python("g=a.SingleInstance(); print('LOCKED' if g.acquire() else 'FAILED', flush=True); input()"),
            self.python("g=a.SingleInstance(); print('ACQUIRED' if g.acquire() else 'BLOCKED'); g.close()"))

    @unittest.skipUnless(os.name == 'nt', 'Windows mutex interoperability')
    def test_powershell_python_lock_in_both_directions(self):
        ps_owner = self.powershell("$g=Enter-AgentInstance; if (!$g) { throw 'busy' }; Write-Output 'LOCKED'; [Console]::ReadLine() | Out-Null")
        ps_probe = self.powershell("$g=Enter-AgentInstance; if ($g) { Write-Output 'ACQUIRED'; $g.ReleaseMutex(); $g.Dispose() } else { Write-Output 'BLOCKED' }")
        py_owner = self.python("g=a.SingleInstance(); print('LOCKED' if g.acquire() else 'FAILED', flush=True); input()")
        py_probe = self.python("g=a.SingleInstance(); print('ACQUIRED' if g.acquire() else 'BLOCKED'); g.close()")
        self.assert_lock_pair(ps_owner, py_probe)
        self.assert_lock_pair(py_owner, ps_probe)

    def test_identity_stable_across_ip_name_changes_and_override(self):
        # Linux containers used by tests may intentionally have no machine-id.
        with patch.object(agent, 'IS_WINDOWS', False), patch.object(Path, 'read_text', return_value='a' * 32):
            self.assertEqual(agent.agent_id({'hostname': 'before', 'report_ip': '192.0.2.1'}),
                             agent.agent_id({'hostname': 'after', 'report_ip': '192.0.2.2'}))
            with patch.object(Path, 'read_text', return_value='b' * 32):
                other = agent.agent_id()
            self.assertNotEqual(other, agent.agent_id())
        self.assertEqual(agent.agent_id({'agent_id': 'f' * 64}), 'f' * 64)
        self.assertRaises(ValueError, agent.agent_id, {'agent_id': 'invalid'})
        with patch.object(agent, 'IS_WINDOWS', False), patch.object(Path, 'read_text', return_value=''):
            self.assertRaises(RuntimeError, agent.agent_id)

    @unittest.skipUnless(os.name == 'nt', 'Windows identity/IP consistency')
    def test_windows_python_powershell_identity_and_route_match(self):
        command = self.powershell("@{id=Get-AgentIdentity @{}; ip=Get-AgentIPv4 -ServerUrl 'http://127.0.0.1:8999'} | ConvertTo-Json -Compress")
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data['id'], agent.agent_id())
        self.assertEqual(data['ip'], agent.local_ip('http://127.0.0.1:8999'))

    @unittest.skipUnless(os.name == 'nt', 'Windows service/task coordination')
    def test_service_preference_disables_and_stops_only_its_named_task(self):
        command = self.powershell('''
            $script:stopped=0
            $script:native=New-Object PSObject -Property @{Enabled=$true}
            $script:native | Add-Member ScriptMethod Stop { param($flags) $script:stopped++ }
            function Get-AgentTask { param($TaskName)
                if ($TaskName -ne 'NetGuardAgent') { throw 'wrong task' }
                return New-Object PSObject -Property @{State='Running';NativeTask=$script:native}
            }
            Disable-AgentServiceDuplicateTask 'NetGuardAgent'
            if ($script:native.Enabled -or $script:stopped -ne 1) { throw 'task still active' }
            function Get-AgentTask { return $null }
            Disable-AgentServiceDuplicateTask 'NetGuardAgent'
            Write-Output 'PASS'
        ''')
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b'PASS', result.stdout)

    @unittest.skipUnless(os.name == 'nt', 'Windows main loop integration; loopback only')
    def test_powershell_main_reports_identity_and_rejects_second_python_main(self):
        reports = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                reports.append((self.path, json.loads(self.rfile.read(int(self.headers['Content-Length'])))))
                reply = b'{"status":"ok","device_id":1}'
                self.send_response(200)
                self.send_header('Content-Length', str(len(reply)))
                self.end_headers()
                self.wfile.write(reply)
        server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                for name in ('netguard_agent.ps1', 'netguard_agent.py', 'windows_agent_common.ps1'):
                    shutil.copyfile(str(ROOT / 'agent' / name), str(root / name))
                (root / 'agent_config.json').write_text(json.dumps(dict(
                    hostname='fixture-main', server_url='http://127.0.0.1:' + str(server.server_port),
                    api_key='fixture-only', agent_id='e' * 64, report_ip='127.0.0.1', interval=1,
                    software_inventory={'enabled': False})), encoding='utf-8')
                owner = subprocess.Popen(['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                    '-File', str(root / 'netguard_agent.ps1')], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NO_WINDOW)
                try:
                    deadline = time.monotonic() + 45
                    while time.monotonic() < deadline and not any(path.endswith('/metrics') for path, _ in reports):
                        if owner.poll() is not None:
                            self.fail(repr(owner.communicate()))
                        time.sleep(.1)
                    self.assertTrue(any(path.endswith('/register') for path, _ in reports))
                    self.assertTrue(any(path.endswith('/metrics') for path, _ in reports))
                    self.assertTrue(all(body['agent_id'] == 'e' * 64 and body['ip_address'] == '127.0.0.1' for _, body in reports))
                    duplicate = subprocess.run([sys.executable, '-B', str(root / 'netguard_agent.py')],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
                    self.assertEqual(duplicate.returncode, 0, duplicate.stderr)
                    self.assertIn(b'already running', duplicate.stdout)
                finally:
                    owner.kill()
                    owner.communicate(timeout=10)
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=5)

    def test_worker_receives_main_identity_and_ip_without_reresolving(self):
        worker = agent.SoftwareInventoryWorker({'_report_ip': '192.0.2.30', '_agent_id': 'a' * 64}, Mock())
        with patch.object(agent.subprocess, 'Popen') as start:
            worker.tick()
        args = start.call_args[0][0]
        self.assertEqual(args[args.index('--report-ip') + 1], '192.0.2.30')
        self.assertEqual(args[args.index('--agent-id') + 1], 'a' * 64)

    def test_report_ip_must_be_assigned_locally(self):
        self.assertEqual(agent.local_ip('http://127.0.0.1:8999', '127.0.0.1'), '127.0.0.1')
        for value in ('not-an-ip', '0.0.0.0', '224.0.0.1', '169.254.1.1'):
            self.assertRaises(ValueError, agent.local_ip, 'http://127.0.0.1:8999', value)


if __name__ == '__main__':
    unittest.main()
