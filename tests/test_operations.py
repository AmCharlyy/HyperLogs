import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tarfile

import pytest
from test_system import client,login,PASSWORD
from backend import app as service


def test_backup_captures_wal_and_verifies_manifest(client,tmp_path):
    login(client)
    target=tmp_path/'backup.tar.gz'
    env={**os.environ,'HYPERLOGS_DATA':str(service.DATA),'HYPERLOGS_DEMO':'0'}
    result=subprocess.run([sys.executable,'-m','backend.manage','backup','--output',str(target)],env=env,capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    with tarfile.open(target) as archive:
        raw=archive.extractfile('hyperlogs.sqlite3').read()
        metadata=json.load(archive.extractfile('manifest.json'))
    import hashlib
    assert metadata['database_sha256']==hashlib.sha256(raw).hexdigest()
    copied=tmp_path/'restored.sqlite3';copied.write_bytes(raw)
    with sqlite3.connect(copied) as conn:
        assert conn.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
        assert conn.execute('SELECT count(*) FROM events').fetchone()[0]>0
    duplicate=subprocess.run([sys.executable,'-m','backend.manage','backup','--output',str(target)],env=env,capture_output=True,text=True)
    assert duplicate.returncode!=0


def test_production_http_smoke_in_isolated_process(tmp_path):
    script='''
from fastapi.testclient import TestClient
from backend.app import app
with TestClient(app,base_url='https://soc.example.test') as client:
    config=client.get('/api/config').json()
    assert config['demo'] is False and config['production'] is True
    assert config['downloads']['HyperLogsSetup.exe']['available'] is False
    assert client.get('/docs').status_code==404
    assert client.post('/api/demo/session',json={'role':'admin'}).status_code==404
    result=client.post('/api/auth/login',json={'username':'admin','password':'Only-for-automated-tests-7284'})
    assert result.status_code==200,result.text
    assert 'Secure' in result.headers['set-cookie'] and 'HttpOnly' in result.headers['set-cookie']
    client.headers['x-hyperlogs-csrf']=result.json()['csrf']
    assert client.get('/api/overview').status_code==200
    assert client.get('/api/playbooks').json()['enabled'] is False
    assert client.get('/api/health',headers={'host':'untrusted.test'}).status_code==400
print('production_http_checks_ok')
'''
    env={**os.environ,'HYPERLOGS_ENV':'production','HYPERLOGS_DEMO':'0','HYPERLOGS_LAB_ENABLED':'0','HYPERLOGS_DATA':str(tmp_path/'production'),'HYPERLOGS_ALLOWED_HOSTS':'soc.example.test','HYPERLOGS_PUBLIC_URL':'https://soc.example.test','HYPERLOGS_ADMIN_PASSWORD':PASSWORD}
    result=subprocess.run([sys.executable,'-c',script],env=env,capture_output=True,text=True)
    assert result.returncode==0,result.stderr+result.stdout
    assert 'production_http_checks_ok' in result.stdout


def test_file_restore_does_not_overwrite_later_changes(client):
    login(client)
    client.post('/api/demo/simulate/R03')
    alert=next(a for a in client.get('/api/alerts').json() if a['rule_id']=='R03')
    rid=client.post('/api/playbooks/PB02/request',json={'alert_id':alert['id']}).json()['id']
    login(client,'ciso');client.post(f'/api/runs/{rid}/approve',json={'approve':True})
    login(client,'soc2');client.post(f'/api/runs/{rid}/execute')
    path=service.DATA/'lab'/'service.conf';path.write_text('a later manual change',encoding='utf-8')
    result=client.post(f'/api/runs/{rid}/revert')
    assert result.json()['ok'] is False
    assert path.read_text()=='a later manual change'


def test_playbook_failures_are_recorded(client,monkeypatch):
    login(client)
    alert=next(a for a in client.get('/api/alerts').json() if a['rule_id']=='R03')
    rid=client.post('/api/playbooks/PB02/request',json={'alert_id':alert['id']}).json()['id']
    login(client,'ciso');client.post(f'/api/runs/{rid}/approve',json={'approve':True})
    login(client,'soc2')
    def fail(*args):raise OSError('internal location must not be exposed')
    monkeypatch.setattr(service,'write_atomic',fail)
    result=client.post(f'/api/runs/{rid}/execute')
    assert result.json()['status']=='failed'
    assert 'internal location' not in result.text
    assert client.get('/api/playbooks').json()['runs'][0]['status']=='failed'


def test_password_legacy_migrates(client):
    import hashlib
    salt='1a'*16
    legacy=salt+':'+hashlib.pbkdf2_hmac('sha256',PASSWORD.encode(),bytes.fromhex(salt),260000).hex()
    with service.db() as db:db.execute("UPDATE users SET password=? WHERE username='admin'",(legacy,))
    login(client)
    with service.db() as db:
        stored=db.execute("SELECT password FROM users WHERE username='admin'").fetchone()[0]
    assert stored.startswith('pbkdf2_sha256$600000$')


def test_agent_syslog_parser_and_tls_policy(tmp_path):
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'agents'))
    from syslog_bridge import parse
    from transport import config,Queue
    event=parse('<34>1 2026-10-27T12:00:00Z lab sshd 1 ID47 - authentication failure')
    assert event['syslog_severity']==2 and event['kind']=='syslog'
    structured=parse('<14>1 2026-10-27T12:00:00Z lab app 3 - [test@123 key="value"] message')
    assert structured['description'].endswith('message')
    with pytest.raises(ValueError):parse('not syslog')
    path=tmp_path/'agent.json'
    path.write_text(json.dumps({'server':'http://remote.example','token':'a'*40}))
    with pytest.raises(ValueError,match='HTTPS'):config(path)
    path.write_text(json.dumps({'server':'http://127.0.0.1:8000','token':'a'*40,'state':str(tmp_path/'queue.sqlite3')}))
    queue=Queue(config(path));queue.add(event);queue.commit()
    reopened=Queue(config(path))
    assert reopened.db.execute('SELECT count(*) FROM queue').fetchone()[0]==1
    queue.db.close();reopened.db.close()


def test_csv_formula_escaping(client):
    from test_system import source,ingest
    src=source(client)
    assert ingest(client,src['token'],[{'kind':'request_ok','user':'=1+1','external_id':'csv-1'}]).status_code==200
    result=client.get('/api/reports/export?format=csv')
    assert "'=1+1" in result.text


def test_file_action_attempts_recovery_after_partial_failure(client,monkeypatch):
    login(client)
    client.post('/api/demo/simulate/R03')
    path=service.DATA/'lab'/'service.conf';before=path.read_text()
    alert=next(a for a in client.get('/api/alerts').json() if a['rule_id']=='R03')
    rid=client.post('/api/playbooks/PB02/request',json={'alert_id':alert['id']}).json()['id']
    login(client,'ciso');client.post(f'/api/runs/{rid}/approve',json={'approve':True})
    login(client,'soc2')
    def partial(path,content):
        path.write_text(content,encoding='utf-8')
        raise OSError('failure after mutation')
    monkeypatch.setattr(service,'write_atomic',partial)
    result=client.post(f'/api/runs/{rid}/execute')
    assert result.json()['status']=='failed'
    assert result.json()['result']['recovery_verified']
    assert path.read_text()==before
