import hashlib
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone

os.environ.setdefault('HYPERLOGS_ALLOWED_HOSTS','localhost,127.0.0.1,testserver')

import pytest
from fastapi.testclient import TestClient
from backend import app as service
from backend import security

PASSWORD='Only-for-automated-tests-7284'


@pytest.fixture
def client(tmp_path,monkeypatch):
    monkeypatch.setattr(service,'DATA',tmp_path)
    monkeypatch.setattr(service,'DB',tmp_path/'hyperlogs.sqlite3')
    monkeypatch.setattr(service,'DEMO',True)
    monkeypatch.setattr(service,'LAB_ENABLED',True)
    monkeypatch.setenv('HYPERLOGS_ADMIN_PASSWORD',PASSWORD)
    with TestClient(service.app,base_url='http://localhost',raise_server_exceptions=False) as c:
        hashed=service.password_hash(PASSWORD)
        with service.db() as db:
            for role in ('soc1','soc2','ciso','auditor'):
                db.execute('INSERT INTO users(username,name,role,password) VALUES(?,?,?,?)',(role,role,role,hashed))
        yield c


def login(client,role='admin'):
    client.cookies.clear();client.headers.pop('x-hyperlogs-csrf',None)
    result=client.post('/api/auth/login',json={'username':role,'password':PASSWORD})
    assert result.status_code==200,result.text
    client.headers['x-hyperlogs-csrf']=result.json()['csrf']
    return result


def source(client,**overrides):
    login(client)
    result=client.post('/api/sources',json=dict(name='Real source',kind='application',ip='10.0.0.2',**overrides))
    assert result.status_code==200,result.text
    return result.json()


def ingest(client,token,events):
    return client.post('/api/ingest',headers={'x-source-token':token},json={'events':events})


def test_cookie_csrf_logout_and_no_browser_token(client):
    result=login(client)
    assert 'token' not in result.json()
    cookie=result.headers['set-cookie'].lower()
    assert 'httponly' in cookie and 'samesite=strict' in cookie and 'path=/api' in cookie
    assert client.get('/api/auth/me').json()['csrf']==client.headers['x-hyperlogs-csrf']
    csrf=client.headers.pop('x-hyperlogs-csrf')
    assert client.post('/api/users',json={'username':'extra','name':'Extra','role':'admin','password':PASSWORD}).status_code==403
    client.headers['x-hyperlogs-csrf']=csrf
    assert client.post('/api/auth/logout').status_code==200
    assert client.get('/api/overview').status_code==401


def test_origin_host_body_csp_and_docs(client):
    assert client.get('/api/health',headers={'host':'evil.example'}).status_code==400
    result=client.get('/api/health')
    assert "script-src 'self'" in result.headers['content-security-policy']
    assert result.headers['cache-control']=='no-store'
    assert client.post('/api/auth/login',headers={'Origin':'https://evil.example'},json={'username':'admin','password':PASSWORD}).status_code==403
    assert client.post('/api/auth/login',content='x',headers={'content-type':'text/plain'}).status_code==415
    assert client.post('/api/ingest',content='x'*(security.MAX_BODY+1),headers={'content-type':'application/json'}).status_code==413
    assert client.get('/api/not-a-route').status_code==404


def test_login_rate_limit(client):
    for _ in range(10):
        assert client.post('/api/auth/login',json={'username':'missing','password':'incorrect'}).status_code==401
    result=client.post('/api/auth/login',json={'username':'missing','password':'incorrect'})
    assert result.status_code==429 and result.headers['retry-after']=='600'


@pytest.mark.parametrize('role',['soc1','soc2','ciso','auditor'])
def test_roles_cannot_administer_sources_or_users(client,role):
    login(client,role)
    assert client.post('/api/sources',json={'name':'Unauthorized','kind':'windows'}).status_code==403
    assert client.post('/api/users',json={'username':'bad-user','name':'Bad','password':PASSWORD,'role':'admin'}).status_code==403
    assert client.post('/api/demo/simulate/R01').status_code==(200 if role=='soc2' else 403)


def test_auditor_read_only(client):
    login(client,'auditor')
    alert=client.get('/api/alerts').json()[0]
    assert client.post(f"/api/alerts/{alert['id']}/incident").status_code==403
    assert client.get('/api/audit').status_code==200
    assert client.get('/api/reports/export?format=json').status_code==200


def test_source_ingestion_validation_redaction_and_dedup(client):
    src=source(client)
    event={'kind':'request_ok','external_id':'stable-1','src_ip':'10.0.0.7','description':'password=do-not-store token="sensitive" Authorization: Bearer abcdef','metrics':{'cpu':25,'memory':40,'disk':20}}
    result=ingest(client,src['token'],[event]);assert result.status_code==200,result.text
    again=ingest(client,src['token'],[event]);assert result.json()['ids']==again.json()['ids']
    item=client.get('/api/events',params={'source':src['id']}).json()['items'][0]
    assert item['simulated']==0 and item['time']
    assert 'do-not-store' not in item['payload'] and 'sensitive' not in item['payload'] and 'abcdef' not in item['payload']
    assert hashlib.sha256(item['payload'].encode()).hexdigest()==item['hash']
    assert client.get('/api/events',params={'source':src['id']}).json()['total']==1
    assert ingest(client,src['token'],[dict(event,metrics={'cpu':101})]).status_code==422
    assert ingest(client,src['token'],[dict(event,src_ip='not-an-ip')]).status_code==422
    assert ingest(client,src['token'],[dict(event,time='2026-01-01T00:00:00')]).status_code==422
    assert ingest(client,src['token'],[dict(event,unknown='not-allowed')]).status_code==422


def test_source_rotation_and_revocation(client):
    src=source(client)
    result=client.post(f"/api/sources/{src['id']}/rotate")
    assert result.status_code==200
    assert ingest(client,src['token'],[{'kind':'heartbeat'}]).status_code==401
    assert ingest(client,result.json()['token'],[{'kind':'heartbeat'}]).status_code==200
    assert client.post(f"/api/sources/{src['id']}/revoke").status_code==200
    assert ingest(client,result.json()['token'],[{'kind':'heartbeat'}]).status_code==401


@pytest.mark.parametrize('rule',['R01','R02','R03','R04'])
def test_all_rules_reproducible(client,rule):
    login(client)
    result=client.post('/api/demo/simulate/'+rule)
    assert result.status_code==200,result.text
    detected=[a for a in client.get('/api/alerts').json() if a['rule_id']==rule]
    assert detected
    assert all(a['simulated'] for a in detected)
    assert len(json.loads(detected[0]['evidence']))>=({'R01':5,'R02':1,'R03':1,'R04':4}[rule])


def test_correlation_threshold_isolation_and_real_source(client):
    src=source(client)
    event={'kind':'login_failed','src_ip':'10.0.0.55','syslog_severity':6}
    assert ingest(client,src['token'],[dict(event,external_id=str(n)) for n in range(4)]).status_code==200
    assert not [a for a in client.get('/api/alerts').json() if a['source_id']==src['id']]
    ingest(client,src['token'],[dict(event,external_id='4')])
    results=[a for a in client.get('/api/alerts').json() if a['source_id']==src['id']]
    assert len(results)==1 and results[0]['rule_id']=='R01' and results[0]['simulated']==0


@pytest.mark.parametrize('rule,pid',[('R01','PB01'),('R03','PB02'),('R04','PB03')])
def test_playbook_full_lifecycle_and_private_rollback(client,rule,pid):
    login(client)
    client.post('/api/demo/simulate/'+rule)
    alert=next(a for a in client.get('/api/alerts').json() if a['rule_id']==rule)
    result=client.post(f'/api/playbooks/{pid}/request',json={'alert_id':alert['id']});assert result.status_code==200,result.text
    rid=result.json()['id']
    assert client.post(f'/api/runs/{rid}/execute').status_code==409
    assert client.post(f'/api/runs/{rid}/approve',json={'approve':True}).status_code==403
    login(client,'ciso')
    assert client.post(f'/api/runs/{rid}/approve',json={'approve':True}).status_code==200
    assert client.post(f'/api/runs/{rid}/execute').status_code==403
    login(client,'soc2')
    executed=client.post(f'/api/runs/{rid}/execute');assert executed.status_code==200,executed.text
    assert executed.json()['result']['verified'] and executed.json()['status']=='completed'
    assert client.post(f'/api/runs/{rid}/execute').status_code==409
    runs=client.get('/api/playbooks').json()['runs']
    assert all('reversal' not in r for r in runs)
    if pid!='PB02':
        assert not client.get('/api/lab/access',params={'source_id':alert['source_id'],'ip':alert['src_ip']}).json()['allowed']
    assert client.post(f'/api/runs/{rid}/revert').json()['verified']
    if pid!='PB02':
        assert client.get('/api/lab/access',params={'source_id':alert['source_id'],'ip':alert['src_ip']}).json()['allowed']
    assert client.get('/api/audit').json()['integrity']['valid']


def test_incident_requires_complete_closure(client):
    login(client)
    alert=client.get('/api/alerts').json()[0]
    iid=client.post(f"/api/alerts/{alert['id']}/incident").json()['id']
    assert client.patch(f'/api/incidents/{iid}',json={'status':'closed'}).status_code==422
    assert client.patch(f'/api/incidents/{iid}',json={'status':'closed','cause':'Test cause','impact':'Lab only','residual':'Low','note':'Evidence checked'}).status_code==200
    assert client.get(f'/api/incidents/{iid}').json()['incident']['closed']


def test_analytics_and_exports_consistency(client):
    login(client)
    for days in (7,14,30):
        result=client.get('/api/analytics',params={'days':days}).json()
        assert len(result['points'])==days+1
        assert result['total']==sum(p['total'] for p in result['points'])
    report=client.get('/api/reports/export?format=json')
    assert report.status_code==200
    value=report.json()
    assert value['counts']['events']==len(value['events']) and not value['truncated']
    assert all('reversal' not in r for r in value['runs'])
    assert value['integrity']['valid']
    csv=client.get('/api/reports/export?format=csv')
    assert csv.status_code==200 and csv.text.startswith('\ufeffid,')
    assert 'attachment' in csv.headers['content-disposition']


def test_filters_and_sql_injection_are_bounded(client):
    login(client)
    assert client.get('/api/events',params={'q':"' OR 1=1 --"}).json()['total']==0
    assert client.get('/api/events?page=-1').status_code==422
    assert client.get('/api/events?severity=8').status_code==422
    assert client.get('/api/events',params={'start':'not-a-date'}).status_code==422
    assert client.get('/api/events',params={'q':'x'*201}).status_code==422


def test_password_change_revokes_previous_sessions(client):
    login(client)
    old_cookie=client.cookies.get(security.COOKIE)
    result=client.post('/api/auth/password',json={'current_password':PASSWORD,'new_password':'A-new-test-password-9284'})
    assert result.status_code==200
    assert old_cookie!=client.cookies.get(security.COOKIE)
    client.cookies.clear();client.cookies.set(security.COOKIE,old_cookie,path='/api')
    assert client.get('/api/auth/me').status_code==401


def test_deactivation_revokes_access(client):
    login(client,'soc1');old=client.cookies.get(security.COOKIE)
    login(client)
    uid=next(u['id'] for u in client.get('/api/users').json() if u['username']=='soc1')
    assert client.patch(f'/api/users/{uid}',json={'role':'soc1','active':False}).status_code==200
    client.cookies.clear();client.cookies.set(security.COOKIE,old,path='/api')
    assert client.get('/api/overview').status_code==401


def test_production_config_fails_closed(monkeypatch):
    monkeypatch.setattr(security,'PRODUCTION',True)
    monkeypatch.setattr(security,'DEMO',True)
    with pytest.raises(RuntimeError,match='DEMO'):security.validate_environment()
    monkeypatch.setattr(security,'DEMO',False)
    monkeypatch.setattr(security,'PUBLIC_URL','http://unsafe.example')
    with pytest.raises(RuntimeError,match='HTTPS'):security.validate_environment()


def test_detects_audit_tampering(client):
    login(client)
    with service.db() as db:db.execute("UPDATE audit SET action='tampered' WHERE id=1")
    assert client.get('/api/audit').json()['integrity']['valid'] is False


def test_lab_disabled_in_production_mode(client,monkeypatch):
    login(client)
    monkeypatch.setattr(service,'LAB_ENABLED',False)
    assert client.post('/api/playbooks/PB01/request',json={'alert_id':1}).status_code==403
    assert client.get('/api/playbooks').json()['enabled'] is False
