import json
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi import HTTPException
from test_system import client, login
from backend import discovery
from backend import app as service


@pytest.mark.parametrize('value', ['8.8.8.0/24','127.0.0.0/24','169.254.0.0/24','0.0.0.0/24','192.168.3.0/24','192.168.2.0/23','192.168.2.7/24','::1/128','192.168.2.1;echo hi'])
def test_discovery_rejects_outside_or_invalid_networks(monkeypatch,value):
    monkeypatch.setenv('HYPERLOGS_DISCOVERY_NETWORKS','192.168.2.0/24')
    with pytest.raises(HTTPException):
        discovery.validate_network(value)


def test_discovery_permissions_inventory_and_registration(client,monkeypatch):
    monkeypatch.setenv('HYPERLOGS_DISCOVERY_NETWORKS','192.168.2.0/24')
    monkeypatch.setattr(discovery,'probe',lambda ip: {'ip':ip,'ports':[22],'method':'tcp','suggested_kind':'linux','hostname':'lab-pc','name_source':'dns'} if ip.endswith('.1') else None)
    assert client.get('/api/discovery').status_code==401
    login(client,'soc1')
    assert client.get('/api/discovery').status_code==200
    assert client.post('/api/discovery/scan',json={'network':'192.168.2.0/30'}).status_code==403
    login(client)
    csrf=client.headers.pop('x-hyperlogs-csrf')
    assert client.post('/api/discovery/scan',json={'network':'192.168.2.0/30'}).status_code==403
    client.headers['x-hyperlogs-csrf']=csrf
    started=client.post('/api/discovery/scan',json={'network':'192.168.2.0/30'})
    assert started.status_code==202,started.text
    for _ in range(100):
        value=client.get('/api/discovery').json()
        if value['job']['status']!='running': break
        time.sleep(.02)
    assert value['job']['status']=='completed'
    assert value['job']['checked']==2 and value['job']['found']==1
    assert value['assets'][0]['ports']==[22]
    assert value['assets'][0]['hostname']=='lab-pc'
    assert value['assets'][0]['source_id'] is None
    assert client.post('/api/discovery/scan',json={'network':'192.168.2.0/30'}).status_code==429
    result=client.post('/api/sources',json={'name':'Detected Linux','kind':'linux','ip':'192.168.2.1'})
    assert result.status_code==200
    assert client.get('/api/discovery').json()['assets'][0]['source_id']==result.json()['id']
    with service.db() as c:
        actions=[r[0] for r in c.execute("SELECT action FROM audit WHERE action LIKE 'discovery.%'")]
        assert 'discovery.started' in actions and 'discovery.completed' in actions
        assert c.execute('SELECT count(*) FROM sources WHERE ip=?',('192.168.2.1',)).fetchone()[0]==1


def test_discovery_does_not_accept_public_allowlist(monkeypatch):
    monkeypatch.setenv('HYPERLOGS_DISCOVERY_NETWORKS','8.8.8.0/24,0.0.0.0/24,127.0.0.0/24,192.168.2.0/24')
    assert [str(n) for n in discovery.allowed_networks()]==['192.168.2.0/24']


@pytest.mark.parametrize('response,expected',[(b'Reply: destination host unreachable.',False),(b'Reply from 192.168.2.1: bytes=32 time=1ms TTL=64',True)])
def test_windows_unreachable_is_not_an_active_host(monkeypatch,response,expected):
    from types import SimpleNamespace
    monkeypatch.setattr(discovery.platform,'system',lambda:'Windows')
    monkeypatch.setattr(discovery.subprocess,'run',lambda *a,**k:SimpleNamespace(returncode=0,stdout=response))
    def closed(*a,**k): raise OSError('closed')
    monkeypatch.setattr(discovery.socket,'create_connection',closed)
    monkeypatch.setattr(discovery,'resolve_device_name',lambda ip: ('',''))
    assert bool(discovery.probe('192.168.2.1')) is expected


def test_device_name_prefers_ptr_and_rejects_ip(monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(discovery.platform,'system',lambda:'Windows')
    monkeypatch.setattr(discovery.subprocess,'run',lambda *a,**k:SimpleNamespace(returncode=0,stdout='LAB-PC.example.local.\r\n'))
    assert discovery.resolve_device_name('192.168.2.10')==('LAB-PC.example.local','dns')
    assert discovery._clean_hostname('192.168.2.10')==''
