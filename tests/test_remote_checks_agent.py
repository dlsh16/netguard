"""Execute synthetic checks only, in a temporary installation and loopback HTTP server."""
import base64
import csv
import http.server
import json
import logging
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT/'agent'))
import remote_checks


class WorkerTests(unittest.TestCase):
    def test_pending_delivery_retries_without_reexecuting(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)
            cfg={'server_url':'http://127.0.0.1','remote_checks':{'enabled':True,'token':'a'*64}}
            worker=remote_checks.RemoteCheckWorker(cfg,logging.getLogger('fixture'))
            pending={'id':1,'result':{'status':'completed','content_base64':base64.b64encode(b'fixture').decode()}}
            (path/'remote_check_pending.json').write_text(json.dumps(pending),encoding='utf-8')
            with patch.object(remote_checks,'ROOT',path),patch.object(worker,'post',side_effect=OSError('offline')):
                worker.run_once()
            self.assertTrue((path/'remote_check_pending.json').exists())
            with patch.object(remote_checks,'ROOT',path),patch.object(worker,'post',return_value={'status':'completed'}) as post,patch.object(remote_checks.subprocess,'Popen') as process:
                worker.run_once();post.assert_called_once_with('1/result',pending['result']);process.assert_not_called()
            self.assertFalse((path/'remote_check_pending.json').exists())

    @unittest.skipUnless(os.name=='nt','Windows PowerShell runtime only')
    def test_powershell_worker_runs_allowlisted_fixture_without_prompt(self):
        received=[]
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                payload=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                self.server.assert_token=self.headers.get('X-Check-Token')
                if self.path.endswith('/poll'): reply={'job':{'id':7,'run_type':'security'}}
                else:received.append(payload);reply={'status':'completed','run_id':1}
                data=json.dumps(reply).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
            def log_message(self,*args):pass
        server=http.server.HTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with tempfile.TemporaryDirectory() as temp:
                path=Path(temp);(path/'check_scripts').mkdir()
                shutil.copyfile(ROOT/'agent/remote_checks.ps1',path/'remote_checks.ps1')
                (path/'agent_config.json').write_text(json.dumps({'server_url':'http://127.0.0.1:'+str(server.server_port),'remote_checks':{'enabled':True,'token':'a'*64}}))
                (path/'check_scripts/CVE_Check.ps1').write_text("param([string]$OutputDir,[switch]$NoOpen,[switch]$Unattended)\nif (-not $NoOpen -or -not $Unattended) { exit 9 }\n[IO.File]::WriteAllText((Join-Path $OutputDir 'fixture.csv'),'ID,Name,Status`nU-1,Fixture,pass')\n")
                result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(path/'remote_checks.ps1')],capture_output=True,timeout=40)
                self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
                self.assertEqual(server.assert_token,'a'*64)
                self.assertEqual(len(received),1)
                self.assertEqual(received[0]['status'],'completed',received)
                self.assertIn(b'Fixture',base64.b64decode(received[0]['content_base64']))
                self.assertFalse((path/'remote_check_pending.json').exists())
        finally:
            server.shutdown();server.server_close();thread.join()


@unittest.skipUnless(os.getenv('NETGUARD_LINUX_CHECK_TEST')=='1' and Path('/.dockerenv').exists(),
                     'Requires disposable network-isolated Docker container')
class LinuxCheckTests(unittest.TestCase):
    def test_fixed_runner_both_reports_offline_and_no_replay(self):
        subprocess.check_call(['groupadd','-f','ngagent'])
        scripts=Path('/usr/local/libexec/netguard-checks')
        scripts.mkdir(parents=True,exist_ok=True)
        Path('/var/lib/netguard-checks').mkdir(exist_ok=True)
        for name in ('cve_check_linux.sh','maintenance_linux.sh'):
            shutil.copyfile(ROOT/'agent/check_scripts'/name,scripts/name)
        with tempfile.TemporaryDirectory() as temp:
            marker=Path(temp)/'network-called'
            for name in ('dnf','yum','apt-get','smbclient','mount'):
                executable=Path(temp)/name
                executable.write_text('#!/bin/bash\ntouch "'+str(marker)+'"\nexit 99\n')
                executable.chmod(0o755)
            env=dict(os.environ,PATH=temp+':'+os.environ['PATH'])
            runner=['bash',str(ROOT/'scripts/netguard-run-check')]
            for kind,job in (('security','901'),('maintenance','902')):
                process=subprocess.run(runner+[kind,job],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180)
                output=Path('/var/lib/netguard-checks')/job
                log=(output/'runner.log').read_text(errors='replace') if output.exists() else ''
                self.assertEqual(process.returncode,0,log[-3000:])
                files=list(output.glob('*.csv'))
                self.assertEqual(len(files),1)
                with files[0].open(encoding='utf-8-sig') as file:
                    rows=list(csv.DictReader(file))
                self.assertGreater(len(rows),30)
                update=[r for r in rows if r.get('항목ID') in ('U-48','L-43')]
                self.assertEqual(len(update),1)
                self.assertIn('확인필요',update[0].values())
                replay=subprocess.run(runner+[kind,job],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                self.assertNotEqual(replay.returncode,0)
            self.assertFalse(marker.exists(),'Unattended checks must not access package repositories or shares')
            for args in (['shell','903'],['security','../903']):
                self.assertEqual(subprocess.call(runner+args),64)


if __name__=='__main__':unittest.main()
