"""Read-only Windows installer checks; never installs or restarts a real agent."""
import base64
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == 'nt', 'Windows-only bootstrap tests')
class AgentInstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='netguard-installer-')
        self.folder = Path(self.temp.name) / "한글 O'Brien & (agent) !"
        self.folder.mkdir()
        for file in (ROOT / 'agent').iterdir():
            if file.is_file() and file.suffix in ('.ps1', '.bat', '.py'):
                shutil.copy2(file, self.folder / file.name)

    def tearDown(self):
        self.temp.cleanup()

    def batch(self, check=True):
        command = '""' + str(self.folder / 'install.bat') + '"' + (' --check' if check else '') + '"'
        return subprocess.run('cmd.exe /d /s /c ' + command, input=b'\n', capture_output=True, timeout=30)

    def powershell(self, code):
        common = str(self.folder / 'windows_agent_common.ps1').replace("'", "''")
        source = "$ErrorActionPreference='Stop'; . '" + common + "'; " + code
        encoded = base64.b64encode(source.encode('utf-16le')).decode('ascii')
        return subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], capture_output=True, timeout=30)

    def test_batch_handles_unicode_spaces_quotes_and_shell_characters(self):
        result = self.batch()
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        self.assertIn(b'Preflight passed', result.stdout)
        self.assertNotIn(b'Install complete', result.stdout)
        self.assertNotIn(b'LiteralPath', result.stderr)

    def test_missing_helper_fails_without_success_message(self):
        (self.folder / 'software_inventory.ps1').unlink()
        result = self.batch()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'software_inventory.ps1', result.stderr)
        self.assertNotIn(b'Package syntax OK', result.stdout)
        self.assertNotIn(b'Preflight passed', result.stdout)

    def test_malformed_helper_fails_without_success_message(self):
        (self.folder / 'software_inventory.ps1').write_text('Write-Host "unterminated\n', encoding='ascii')
        result = self.batch()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'Syntax error', result.stderr)
        self.assertNotIn(b'Preflight passed', result.stdout)

    def test_unsupported_runtime_aborts_before_prompt_or_install_and_preserves_exit(self):
        common = self.folder / 'windows_agent_common.ps1'
        with common.open('a', encoding='ascii') as file:
            file.write("\nfunction Get-AgentRuntimeProblems { 'Windows PowerShell 5.1 is required. Detected: 2.0 (test fixture)' }\n")
        result = self.batch(check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'5.1 is required', result.stderr)
        self.assertNotIn(b'Server URL [', result.stdout)
        self.assertNotIn(b'Agent files copied', result.stdout)
        self.assertNotIn(b'Install complete', result.stdout)

    def test_old_framework_aborts_before_install(self):
        common = self.folder / 'windows_agent_common.ps1'
        with common.open('a', encoding='ascii') as file:
            file.write("\nfunction Get-AgentFrameworkRelease { return 378389 }\n")
        result = self.batch(check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'.NET Framework 4.5.2', result.stderr)
        self.assertNotIn(b'Server URL [', result.stdout)
        self.assertNotIn(b'Install complete', result.stdout)

    def test_runtime_version_matrix(self):
        result = self.powershell("""
        if (@(Get-AgentRuntimeProblems ([version]'2.0') ([version]'2.0') '').Count -ne 2) { throw 'PS2 must fail' }
        if (@(Get-AgentRuntimeProblems ([version]'4.0') ([version]'4.0') '').Count -ne 1) { throw 'PS4 must fail' }
        if (@(Get-AgentRuntimeProblems ([version]'5.1') ([version]'4.0') 'Desktop').Count -ne 0) { throw 'PS5.1 must pass' }
        if (@(Get-AgentRuntimeProblems ([version]'7.4') ([version]'8.0') 'Core').Count -ne 1) { throw 'Core is not Windows PowerShell' }
        Write-Output 'PASS'
        """)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))

    def test_wmi_ipv4_fallback_and_invalid_address_rejection(self):
        result = self.powershell("""
        function Get-Command { param($Name, $ErrorAction) return $null }
        function Get-WmiObject { param($Class, $Filter, $ErrorAction)
            New-Object PSObject -Property @{ Index=1; IPAddress=@('::1','127.0.0.1','169.254.2.3','192.0.2.20') }
        }
        if ((Get-AgentIPv4) -ne '192.0.2.20') { throw 'WMI fallback failed' }
        function Get-WmiObject { New-Object PSObject -Property @{ Index=1; IPAddress=@('::1','127.0.0.1') } }
        $failed=$false
        try { Get-AgentIPv4 | Out-Null } catch { $failed=$true }
        if (-not $failed) { throw 'Loopback must not be registered' }
        Write-Output 'PASS'
        """)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))

    def test_modern_ipv4_path_matches_inventory_and_metrics(self):
        result = self.powershell("""
        function Get-Command { param($Name, $ErrorAction) return 'available' }
        function Get-NetIPAddress { param($AddressFamily, $ErrorAction)
            New-Object PSObject -Property @{ IPAddress='127.0.0.1'; InterfaceAlias='Loopback'; PrefixLength=8 }
            New-Object PSObject -Property @{ IPAddress='192.0.2.10'; InterfaceAlias='Ethernet'; PrefixLength=24 }
        }
        function Get-WmiObject { throw 'WMI must not be needed' }
        if ((Get-AgentIPv4) -ne '192.0.2.10') { throw 'Modern lookup failed' }
        Write-Output 'PASS'
        """)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))

    def test_com_query_missing_task_is_read_only(self):
        result = self.powershell("$task = Get-AgentTask ('NetGuard-Nonexistent-Test-' + [Guid]::NewGuid()); if ($null -ne $task) { throw 'Unexpected task' }; Write-Output 'PASS'")
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))

    def test_com_state_stop_remove_and_permission_errors_with_fakes(self):
        result = self.powershell("""
        $script:stops=0; $script:deletes=0
        $script:fakeTask = New-Object PSObject -Property @{ Name='Fixture'; State=4; LastTaskResult=0 }
        $script:fakeTask | Add-Member ScriptMethod Stop { param($flags) $script:stops++ }
        $script:fakeFolder = New-Object PSObject
        $script:fakeFolder | Add-Member ScriptMethod GetTask { param($name) return $script:fakeTask }
        $script:fakeFolder | Add-Member ScriptMethod DeleteTask { param($name,$flags) $script:deletes++ }
        function Get-AgentTaskFolder { return $script:fakeFolder }
        if ((Get-AgentTask 'Fixture').State -ne 'Running') { throw 'State mapping failed' }
        Stop-AgentTask 'Fixture'; Remove-AgentTask 'Fixture'
        if ($script:stops -ne 1 -or $script:deletes -ne 1) { throw 'Lifecycle calls failed' }
        $script:fakeFolder | Add-Member ScriptMethod GetTask { throw (New-Object Runtime.InteropServices.COMException -ArgumentList 'denied',-2147024891) } -Force
        $failed=$false; try { Get-AgentTask 'Fixture' | Out-Null } catch { $failed=$true }
        if (-not $failed) { throw 'Access denied must not look like a missing task' }
        Write-Output 'PASS'
        """)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))


if __name__ == '__main__':
    unittest.main()
