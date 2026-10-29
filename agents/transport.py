"""Durable delivery queue shared by the host agent and loopback Syslog bridge."""
import json
import os
from pathlib import Path
import sqlite3
import urllib.error
import urllib.parse
import urllib.request


def config(path):
    cfg=json.loads(Path(path).read_text(encoding='utf-8-sig'))
    if cfg.get('token_protected'):
        try:
            from windows_secret import unprotect
            cfg['token']=unprotect(cfg.pop('token_protected'))
        except Exception as exc:
            raise ValueError('Unable to decrypt the local source credential') from exc
    url=urllib.parse.urlsplit(cfg['server'])
    if url.username or url.password or url.query or url.fragment:
        raise ValueError('Server must be an origin without credentials/query')
    if url.scheme!='https' and not (url.scheme=='http' and url.hostname in ('localhost','127.0.0.1','::1')):
        raise ValueError('HTTPS required except for loopback testing')
    if len(cfg.get('token',''))<20 or cfg['token']=='REPLACE_WITH_SOURCE_TOKEN':raise ValueError('Configure the source token locally')
    cfg['server']=cfg['server'].rstrip('/')
    return cfg


class Queue:
    def __init__(self,cfg):
        self.cfg=cfg
        path=Path(cfg.get('state','agent-state.sqlite3')).resolve()
        path.parent.mkdir(parents=True,exist_ok=True)
        self.db=sqlite3.connect(path)
        try:os.chmod(path,0o600)
        except OSError:pass
        self.db.executescript('CREATE TABLE IF NOT EXISTS queue(id INTEGER PRIMARY KEY,payload TEXT); CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY,value TEXT);')

    def get(self,key,default=''):
        row=self.db.execute('SELECT value FROM state WHERE key=?',(key,)).fetchone()
        return row[0] if row else default

    def put(self,key,value):
        self.db.execute('INSERT INTO state VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',(key,str(value)))

    def add(self,event):
        if self.db.execute('SELECT count(*) FROM queue').fetchone()[0]>=100000:raise RuntimeError('Queue is full; restore delivery before collecting more events')
        self.db.execute('INSERT INTO queue(payload) VALUES(?)',(json.dumps(event,allow_nan=False),))

    def commit(self):self.db.commit()

    def flush(self):
        batch=self.db.execute('SELECT id,payload FROM queue ORDER BY id LIMIT 100').fetchall()
        if not batch:return 0
        request=urllib.request.Request(self.cfg['server']+'/api/ingest',data=json.dumps({'events':[json.loads(row[1]) for row in batch]}).encode(),headers={'Content-Type':'application/json','X-Source-Token':self.cfg['token']},method='POST')
        # urllib verifies TLS by default; no insecure certificate bypass.
        with urllib.request.urlopen(request,timeout=15) as response:
            result=json.load(response)
        if result.get('accepted')!=len(batch):raise RuntimeError('Unexpected acknowledgement; retained batch')
        self.db.executemany('DELETE FROM queue WHERE id=?',[(row[0],) for row in batch]);self.db.commit()
        return len(batch)
