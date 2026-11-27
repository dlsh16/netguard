"""Outbound-only, allowlisted remote checks. Python 3.6+, standard library only."""
import base64
import json
import os
from pathlib import Path
import subprocess
import threading
from urllib import request

ROOT = Path(__file__).resolve().parent


def command_for(kind, job_id, output):
    names = {'security':'CVE_Check.ps1','maintenance':'Maintenance_Windows.ps1'}
    if kind not in names or type(job_id) is not int or job_id <= 0:
        raise ValueError('Invalid remote check job')
    if os.name == 'nt':
        return ['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
                '-File',str(ROOT/'check_scripts'/names[kind]),'-OutputDir',str(output),'-NoOpen','-Unattended']
    return ['sudo','-n','/usr/local/sbin/netguard-run-check',kind,str(job_id)]


class RemoteCheckWorker:
    def __init__(self,cfg,logger):
        self.cfg,self.logger,self.thread=cfg,logger,None

    def tick(self):
        if not (self.cfg.get('remote_checks') or {}).get('enabled'):
            return
        if self.thread and self.thread.is_alive():
            return
        self.thread=threading.Thread(target=self.run_once,daemon=True)
        self.thread.start()

    def post(self,path,payload):
        token=(self.cfg.get('remote_checks') or {}).get('token','')
        if len(token)!=64:
            raise ValueError('remote_checks.token must be issued for this server')
        req=request.Request(self.cfg['server_url'].rstrip('/')+'/api/agent/check-jobs/'+path,
                            json.dumps(payload).encode('utf-8'),
                            {'Content-Type':'application/json','X-Check-Token':token})
        with request.urlopen(req,timeout=30) as response:
            return json.loads(response.read(65536).decode('utf-8'))

    def run_once(self):
        state=ROOT/'remote_check_pending.json'
        try:
            if state.exists():
                pending=json.loads(state.read_text(encoding='utf-8'))
            else:
                job=self.post('poll',{}).get('job')
                if not job:
                    return
                output=(ROOT/'check_output'/str(job['id'])) if os.name=='nt' else Path('/var/lib/netguard-checks')/str(job['id'])
                command=command_for(job['run_type'],job['id'],output)
                pending={'id':job['id'],'result':{'status':'failed','detail':'Agent interrupted; execution state unknown. Not automatically rerun.'}}
                self.save_pending(state,pending)
                self.logger.info('Remote check started: job=%s type=%s',job['id'],job['run_type'])
                if os.name=='nt':
                    output.mkdir(parents=True,exist_ok=False)
                try:
                    # Fixed root wrapper enforces the Linux process-tree timeout.
                    with (ROOT/'remote_check_runner.log').open('wb') as log:
                        proc=subprocess.Popen(command,stdout=log,stderr=log,stdin=subprocess.DEVNULL,
                            creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0) if os.name=='nt' else 0)
                        try:
                            rc=proc.wait(timeout=1830)
                        except subprocess.TimeoutExpired:
                            if os.name=='nt':
                                subprocess.call(['taskkill','/PID',str(proc.pid),'/T','/F'],stdout=log,stderr=log,
                                                creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                            else:
                                proc.kill()
                            proc.wait()
                            raise RuntimeError('Check timed out')
                    if rc:
                        raise RuntimeError('Check exited with code {}'.format(rc))
                    files=list(output.glob('*.csv'))
                    if len(files)!=1 or files[0].stat().st_size>4*1024*1024:
                        raise RuntimeError('Expected one CSV report, at most 4 MiB')
                    pending['result']={'status':'completed','content_base64':base64.b64encode(files[0].read_bytes()).decode('ascii')}
                except Exception as exc:
                    pending['result']={'status':'failed','detail':str(exc)[:500]}
                self.save_pending(state,pending)
            self.post(str(pending['id'])+'/result',pending['result'])
            state.unlink()
            self.logger.info('Remote check result delivered: job=%s status=%s',pending['id'],pending['result']['status'])
        except Exception as exc:
            self.logger.warning('Remote check worker: %s',str(exc)[:200])

    @staticmethod
    def save_pending(path,value):
        temp=path.with_suffix('.tmp')
        with temp.open('w',encoding='utf-8') as file:
            os.chmod(str(temp),0o600)
            json.dump(value,file)
        os.replace(str(temp),str(path))
