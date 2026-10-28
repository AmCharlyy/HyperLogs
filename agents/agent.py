"""Host telemetry + selected Windows security events; never accepts remote commands."""
import argparse
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import platform
import re
import socket
import subprocess
import time
import uuid

import psutil
from transport import Queue,config


def timestamp():return datetime.now(timezone.utc).isoformat()


def windows_events(queue):
    cursor=int(queue.get('windows_cursor','0'))
    if cursor==0:
        command="(Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop).RecordId"
        result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',command],capture_output=True,text=True,timeout=20,check=True)
        queue.put('windows_cursor',int(result.stdout.strip()));return
    # Only the integer cursor is interpolated; no shell/user-controlled command text.
    command='''$ErrorActionPreference='Stop'; $items=@(Get-WinEvent -LogName Security -FilterXPath '*[System[(EventRecordID > CURSOR) and (EventID=4624 or EventID=4625 or EventID=4720 or EventID=4732 or EventID=1102)]]' -Oldest -MaxEvents 100 -ErrorAction SilentlyContinue); $out=@(); foreach($e in $items){[xml]$x=$e.ToXml(); $d=@{}; foreach($n in $x.Event.EventData.Data){$d[$n.Name]=$n.InnerText}; $out+=@{record=[long]$e.RecordId;code=[int]$e.Id;time=$e.TimeCreated.ToUniversalTime().ToString('o');user=$d['TargetUserName'];ip=$d['IpAddress']}}; ConvertTo-Json -InputObject $out -Compress'''.replace('CURSOR',str(cursor))
    result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',command],capture_output=True,text=True,timeout=25,check=True)
    for row in json.loads(result.stdout or '[]'):
        ip=row.get('ip') or ''
        if ip in ('-','::1'):ip='' if ip=='-' else ip
        queue.add(dict(external_id='windows-security-'+str(row['record']),time=row['time'],kind={4624:'login_success',4625:'login_failed',1102:'audit_cleared'}.get(row['code'],'account_changed'),category='authentication',code=str(row['code']),user=row.get('user') or '',src_ip=ip,description='Selected Windows Security event '+str(row['code']),syslog_severity=4 if row['code']==4625 else 5))
        queue.put('windows_cursor',row['record'])


def collect(queue):
    metrics={'cpu':psutil.cpu_percent(interval=.1),'memory':psutil.virtual_memory().percent,'disk':psutil.disk_usage(Path.home().anchor or '/').percent}
    queue.add(dict(external_id='heartbeat-'+uuid.uuid4().hex,time=timestamp(),kind='heartbeat',code='HOST',description=platform.system()+' host telemetry',metrics=metrics))
    for file in queue.cfg.get('watch_files',[]):
        path=Path(file)
        if not path.is_file() or path.stat().st_size>10*1024*1024:continue
        hashed=hashlib.sha256(path.read_bytes()).hexdigest();key='file:'+str(path.resolve());previous=queue.get(key)
        if previous and previous!=hashed:
            queue.add(dict(external_id='file-'+uuid.uuid4().hex,time=timestamp(),kind='config_changed',category='integrity',code='SHA256',description='Monitored file changed: '+path.name+'; before='+previous+'; after='+hashed,syslog_severity=3))
        queue.put(key,hashed)
    if platform.system()=='Windows':
        try:windows_events(queue)
        except (subprocess.SubprocessError,ValueError):
            print('Windows Security collection unavailable: check Event Log Readers/audit policy.',flush=True)
    auth=queue.cfg.get('auth_log')
    if auth and Path(auth).is_file():
        path=Path(auth);size=path.stat().st_size;old=int(queue.get('auth_offset',str(size)))
        if size<old:old=0
        with path.open('rb') as stream:
            stream.seek(old)
            for _ in range(100):
                offset=stream.tell();raw=stream.readline(8192)
                if not raw:break
                text=raw.decode('utf-8',errors='replace')
                match=re.search(r'(Failed password|Accepted password|Accepted publickey) for (?:invalid user )?(\S+) from ([0-9a-fA-F:.]+)',text)
                if match:
                    queue.add(dict(external_id='auth-'+str(path.stat().st_ino)+'-'+str(offset),time=timestamp(),kind='login_failed' if match[1]=='Failed password' else 'login_success',category='authentication',code='SSH',user=match[2][:120],src_ip=match[3],description='SSH authentication event',syslog_severity=4 if match[1]=='Failed password' else 6))
            queue.put('auth_offset',stream.tell())
    queue.commit()


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--config',required=True);parser.add_argument('--once',action='store_true');args=parser.parse_args()
    queue=Queue(config(args.config));interval=max(10,int(queue.cfg.get('interval',30)))
    while True:
        collect(queue)
        try:
            count=queue.flush();print('Acknowledged events: '+str(count),flush=True)
        except Exception as exc:
            print('Delivery deferred ('+type(exc).__name__+'); batch kept locally.',flush=True)
        if args.once:break
        time.sleep(interval)


if __name__=='__main__':main()
