import io
import json
import sys
from pathlib import Path

import pytest

from test_system import client, login, ingest

AGENTS=Path(__file__).resolve().parents[1]/'agents'
sys.path.insert(0,str(AGENTS))
import onboarding


def test_one_time_enrollment_creates_real_source(client):
    login(client)
    created=client.post('/api/enrollments',json={'name':'Laptop recepción','kind':'windows','ip':'192.168.2.45','simulated':False})
    assert created.status_code==200,created.text
    code=created.json()['code']
    assert len(code)==14 and created.json()['expires']
    client.cookies.clear();client.headers.pop('x-hyperlogs-csrf',None)
    claim=client.post('/api/enrollments/claim',json={'code':code,'hostname':'RECEPCION-PC','ip':'192.168.2.45','os_version':'Windows 11'})
    assert claim.status_code==200,claim.text
    result=claim.json()
    assert result['name']=='Laptop recepción' and len(result['token'])>=20
    assert client.post('/api/enrollments/claim',json={'code':code,'hostname':'RECEPCION-PC','ip':'192.168.2.45','os_version':'Windows 11'}).status_code==401
    accepted=ingest(client,result['token'],[{'kind':'heartbeat','description':'onboarding test','metrics':{'cpu':10,'memory':20,'disk':30}}])
    assert accepted.status_code==200 and accepted.json()['accepted']==1


def test_enrollment_is_admin_only(client):
    login(client,'soc1')
    assert client.post('/api/enrollments',json={'name':'PC Lab','kind':'windows','ip':'','simulated':False}).status_code==403


def test_onboarding_claim_and_atomic_config(tmp_path,monkeypatch):
    class Response(io.BytesIO):
        def __enter__(self):return self
        def __exit__(self,*args):self.close()
    def opener(request,timeout):
        assert request.full_url=='https://hyperlogs.local/api/enrollments/claim' and timeout==15
        sent=json.loads(request.data)
        assert sent['hostname']=='LAB-PC'
        return Response(json.dumps({'id':'src-1','name':'LAB-PC','token':'x'*32}).encode())
    result=onboarding.claim('https://hyperlogs.local/','ABCD-EFGH-JKLM',{'hostname':'LAB-PC','ip':'10.0.0.4','os_version':'Windows 11'},opener)
    monkeypatch.setattr(onboarding.platform,'system',lambda:'Windows')
    cfg=onboarding.make_config('https://hyperlogs.local',result['token'],tmp_path,protector=lambda value:'protected-'+value[-4:])
    assert 'token' not in cfg and cfg['token_protected']=='protected-xxxx'
    path=tmp_path/'agent.json';onboarding.write_config(path,cfg)
    assert json.loads(path.read_text())['state']==str(tmp_path/'agent-state.sqlite3')


def test_install_plan_is_isolated_and_quoted(tmp_path,monkeypatch):
    monkeypatch.setattr(onboarding.platform,'system',lambda:'Windows')
    plan=onboarding.install_windows(tmp_path/'HyperLogs Agent.exe',root=tmp_path,dry_run=True)
    assert plan['root']==str(tmp_path/'HyperLogs')
    assert plan['task'][0]=='schtasks.exe' and 'ONSTART' in plan['task']
    assert not (tmp_path/'HyperLogs').exists()


def test_install_uses_mocked_windows_tools_only(tmp_path,monkeypatch):
    monkeypatch.setattr(onboarding.platform,'system',lambda:'Windows')
    executable=tmp_path/'input-agent.exe';executable.write_bytes(b'isolated-agent')
    calls=[]
    class Result:returncode=0
    def runner(command,**kwargs):calls.append(command);return Result()
    result=onboarding.install_windows(executable,root=tmp_path/'program-data',runner=runner)
    assert Path(result['binary']).read_bytes()==b'isolated-agent'
    assert [call[0] for call in calls]==['icacls.exe','schtasks.exe','schtasks.exe']


@pytest.mark.parametrize('value',['http://192.168.2.20','https://host/path','https://user:pass@host','not-a-url'])
def test_server_origin_rejects_unsafe_values(value):
    with pytest.raises(ValueError):onboarding.normalize_server(value)
