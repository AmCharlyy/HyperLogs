"""HyperLogs: local-first SOC. No remote shell or arbitrary commands."""
import csv
import hashlib
import hmac
import io
import json
import math
import os
from pathlib import Path
import random
import secrets
import sqlite3
import statistics
import logging
import re
import ipaddress
import threading
from contextlib import contextmanager, asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import FastAPI, Depends, HTTPException, Request, Query
from fastapi.responses import FileResponse, Response, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator, ConfigDict
from starlette.middleware.trustedhost import TrustedHostMiddleware
from .security import PRODUCTION, DEMO, LAB_ENABLED, COOKIE, ALLOWED_HOSTS, BoundaryMiddleware, validate_environment, normalized_ip, redact

ROOT = Path(__file__).resolve().parents[1]
DATA = Path(os.getenv('HYPERLOGS_DATA', ROOT / 'data'))
DB = DATA / 'hyperlogs.sqlite3'
HASH_SLOTS = threading.BoundedSemaphore(4)
LOGGER = logging.getLogger('hyperlogs')
LOCK = threading.RLock()
ROLES = ('admin', 'soc1', 'soc2', 'ciso', 'auditor')
RULES = [
    dict(id='R01', name='Fuerza bruta', detail='5 fallos desde la misma IP y equipo en 120 s.', threshold=5, window=120, severity='critical', playbook='PB01'),
    dict(id='R02', name='Acceso fuera de horario', detail='Acceso exitoso fuera de 07:00–20:00, zona America/Mexico_City (UTC−6 en este laboratorio).', threshold=1, window=0, severity='warning', playbook=None),
    dict(id='R03', name='Integridad de configuración', detail='Cambio de un archivo vigilado sin autorización.', threshold=1, window=0, severity='critical', playbook='PB02'),
    dict(id='R04', name='Secuencia de acceso sospechosa', detail='3 accesos denegados y después un acceso administrativo exitoso desde la misma IP/equipo en 5 min.', threshold=3, window=300, severity='critical', playbook='PB03'),
]
PLAYBOOKS = [
    dict(id='PB01', name='Contener autenticación', rule='R01', action='Bloqueo de IP por 5 minutos en la aplicación de laboratorio.', steps=['Preservar eventos', 'Abrir expediente', 'Solicitar autorización', 'Bloquear en aplicación de prueba', 'Verificar bloqueo', 'Revertir o esperar expiración']),
    dict(id='PB02', name='Restaurar configuración', rule='R03', action='Preservar y restaurar exclusivamente data/lab/service.conf.', steps=['Conservar contenido y SHA-256', 'Abrir expediente', 'Solicitar autorización', 'Restaurar copia de referencia', 'Verificar SHA-256', 'Permitir reversión']),
    dict(id='PB03', name='Aislar acceso de laboratorio', rule='R04', action='Denegar al equipo el acceso a la aplicación de prueba. No modifica la red del sistema operativo.', steps=['Correlacionar evidencia', 'Abrir expediente', 'Solicitar autorización', 'Aislar en aplicación de prueba', 'Verificar denegación', 'Restablecer acceso']),
]

def now():
    return datetime.now(timezone.utc).isoformat()

def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()

def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))

def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    with HASH_SLOTS:
        hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 600000).hex()
    return 'pbkdf2_sha256$600000$' + salt + '$' + hashed


def password_matches(password, stored):
    try:
        if stored.startswith('pbkdf2_sha256$'):
            _, rounds, salt, hashed = stored.split('$')
            iterations = int(rounds)
            if not 260000 <= iterations <= 1200000:
                return False
        else:
            salt, hashed = stored.split(':')
            iterations = 260000  # legacy database; upgrade after successful login
        with HASH_SLOTS:
            actual = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), iterations).hex()
        return hmac.compare_digest(hashed, actual)
    except (ValueError, TypeError):
        return False


DUMMY_PASSWORD = password_hash(secrets.token_urlsafe(24))


class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid', allow_inf_nan=False)


@contextmanager
def db():
    with LOCK:
        connection = sqlite3.connect(DB, timeout=15)
        connection.row_factory = sqlite3.Row
        connection.execute('PRAGMA foreign_keys=ON')
        connection.execute('PRAGMA busy_timeout=15000')
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

def rows(c, sql, args=()):
    return [dict(x) for x in c.execute(sql, args).fetchall()]

def audit(c, actor, action, target, detail):
    detail=redact(detail)
    previous = c.execute('SELECT hash FROM audit ORDER BY id DESC LIMIT 1').fetchone()
    item = dict(time=now(), actor=actor, action=action, target=str(target), detail=detail, previous=previous['hash'] if previous else '0' * 64)
    hashed = digest(canonical(item))
    c.execute('INSERT INTO audit(time,actor,action,target,detail,previous,hash) VALUES(?,?,?,?,?,?,?)', (*[item[k] for k in ('time','actor','action','target')], canonical(detail), item['previous'], hashed))

def initialize():
    validate_environment()
    DATA.mkdir(parents=True, exist_ok=True)
    (DATA / 'lab').mkdir(exist_ok=True)
    for name in ('service.conf', 'service.baseline'):
        path = DATA / 'lab' / name
        if not path.exists():
            path.write_text('environment=lab\nadmin_access=restricted\n', encoding='utf-8')
    with db() as c:
        c.execute('PRAGMA journal_mode=WAL')
        c.executescript('''
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL,name TEXT NOT NULL,role TEXT NOT NULL,password TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INTEGER REFERENCES users(id),expires TEXT);
        CREATE TABLE IF NOT EXISTS sources(id TEXT PRIMARY KEY,name TEXT NOT NULL,kind TEXT,ip TEXT,simulated INTEGER NOT NULL,token_hash TEXT,created TEXT,last_seen TEXT,metrics TEXT DEFAULT '{}');
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,time TEXT,received TEXT,source_id TEXT REFERENCES sources(id),user TEXT,src_ip TEXT,dst_ip TEXT,kind TEXT,category TEXT,code TEXT,description TEXT,syslog_severity INTEGER,risk INTEGER,simulated INTEGER,payload TEXT,hash TEXT);
        CREATE INDEX IF NOT EXISTS events_time ON events(time);
        CREATE INDEX IF NOT EXISTS events_correlation ON events(source_id,src_ip,kind,time);
        CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY,rule_id TEXT,title TEXT,severity TEXT,source_id TEXT,src_ip TEXT,time TEXT,status TEXT DEFAULT 'open',evidence TEXT,simulated INTEGER);
        CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY,alert_id INTEGER UNIQUE REFERENCES alerts(id),title TEXT,status TEXT,owner TEXT,priority TEXT,cause TEXT DEFAULT '',impact TEXT DEFAULT '',residual TEXT DEFAULT '',created TEXT,closed TEXT);
        CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY,incident_id INTEGER REFERENCES incidents(id),time TEXT,actor TEXT,body TEXT);
        CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY,playbook TEXT,alert_id INTEGER REFERENCES alerts(id),incident_id INTEGER REFERENCES incidents(id),status TEXT,requested_by TEXT,approved_by TEXT,created TEXT,updated TEXT,result TEXT DEFAULT '{}',reversal TEXT DEFAULT '{}');
        CREATE TABLE IF NOT EXISTS controls(id INTEGER PRIMARY KEY,run_id INTEGER REFERENCES runs(id),source_id TEXT,ip TEXT,kind TEXT,expires TEXT,active INTEGER DEFAULT 1);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,time TEXT,actor TEXT,action TEXT,target TEXT,detail TEXT,previous TEXT,hash TEXT);
        CREATE TABLE IF NOT EXISTS auth_failures(ip TEXT,time TEXT);
        CREATE INDEX IF NOT EXISTS failures_time ON auth_failures(time);
        ''')
        c.execute('DELETE FROM sessions')
        if 'external_id' not in [r[1] for r in c.execute('PRAGMA table_info(events)')]:
            c.execute('ALTER TABLE events ADD COLUMN external_id TEXT')
        c.execute('CREATE UNIQUE INDEX IF NOT EXISTS event_dedup ON events(source_id, external_id) WHERE external_id IS NOT NULL')
        c.execute('CREATE INDEX IF NOT EXISTS alert_source_status ON alerts(source_id,status)')
        c.execute('CREATE INDEX IF NOT EXISTS source_token ON sources(token_hash)')
        if 'active' not in [r[1] for r in c.execute('PRAGMA table_info(users)')]:
            c.execute('ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1')
        if 'account' not in [r[1] for r in c.execute('PRAGMA table_info(auth_failures)')]:
            c.execute('ALTER TABLE auth_failures ADD COLUMN account TEXT')
        if not c.execute('SELECT 1 FROM users LIMIT 1').fetchone():
            password = os.getenv('HYPERLOGS_ADMIN_PASSWORD')
            if not password:
                raise RuntimeError('Create the initial admin with: python -m backend.manage bootstrap')
            if len(password) < 12:
                raise RuntimeError('HYPERLOGS_ADMIN_PASSWORD must have at least 12 characters')
            c.execute('INSERT INTO users(username,name,role,password) VALUES(?,?,?,?)', ('admin','Administrador','admin',password_hash(password)))
            audit(c, 'system', 'bootstrap', 'admin', {'role':'admin'})
        if DEMO and not c.execute('SELECT 1 FROM sources LIMIT 1').fetchone():
            seed(c)

def seed(c):
    definitions = [('srv-core','Servidor central','linux','192.168.10.10'),('win-01','Estación Windows','windows','192.168.10.21'),('web-01','Aplicación web','application','192.168.10.30'),('fw-01','Gateway / Syslog','syslog','192.168.10.1'),('lap-01','Laptop de pruebas','windows','192.168.10.24'),('db-01','Nodo de datos','linux','192.168.10.12')]
    for sid, name, kind, ip in definitions:
        c.execute('INSERT INTO sources(id,name,kind,ip,simulated,created,last_seen,metrics) VALUES(?,?,?,?,1,?,?,?)', (sid,name,kind,ip,now(),now(),canonical({'cpu':18,'memory':36,'disk':22})))
    rng = random.Random(42)
    reference = datetime.now(timezone.utc)
    for day in range(14, -1, -1):
        for n in range(28 + (day % 4) * 3):
            t = reference - timedelta(days=day, minutes=n*13)
            sid = definitions[rng.randrange(len(definitions))][0]
            kind = rng.choice(['heartbeat','login_success','request_ok','login_failed'])
            event = dict(time=t.isoformat(),source_id=sid,user='usuario.lab',src_ip='192.168.10.24',dst_ip='192.168.10.10',kind=kind,category='system' if kind=='heartbeat' else 'authentication',code='LAB',description='Evento sintético del escenario de demostración',syslog_severity=6,risk=15,simulated=True)
            insert_event(c,event,correlate=False)
    for rule in ('R01','R03'):
        simulate(c,rule,'system')
    audit(c,'system','demo.seed','laboratory',{'synthetic':True,'days':15})

@asynccontextmanager
async def lifespan(app):
    initialize()
    yield

app = FastAPI(title='HyperLogs', version='1.1.0', lifespan=lifespan, docs_url=None if PRODUCTION else '/docs', redoc_url=None if PRODUCTION else '/redoc', openapi_url=None if PRODUCTION else '/openapi.json')

app.add_middleware(BoundaryMiddleware)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)


@app.exception_handler(Exception)
async def internal_error(request, exc):
    # Log only class/path; payloads and secrets must not end up in logs.
    LOGGER.error('request_failed type=%s path=%s', type(exc).__name__, request.url.path)
    return JSONResponse({'detail': 'Error interno. Consulta al administrador.'}, status_code=500)


def current(request: Request):
    cookie = request.cookies.get(COOKIE, '')
    token = cookie or request.headers.get('authorization', '').removeprefix('Bearer ')
    if cookie and request.method in ('POST', 'PATCH', 'PUT', 'DELETE'):
        supplied = request.headers.get('x-hyperlogs-csrf', '')
        if not hmac.compare_digest(supplied, digest('csrf:' + token)):
            raise HTTPException(403, 'Verificación CSRF inválida. Recarga la página.')
    with db() as c:
        user = c.execute('SELECT u.id,u.username,u.name,u.role FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.token=? AND s.expires>? AND u.active=1', (digest(token), now())).fetchone()
    if not user or (PRODUCTION and user['username'].startswith('demo.')):
        raise HTTPException(401, 'Sesión expirada o inválida')
    return dict(user)


def allow(user, *roles):
    if user['role'] not in roles:
        raise HTTPException(403,'Tu rol no tiene permiso para esta operación')

def session(c, user, response):
    token = secrets.token_urlsafe(40)
    c.execute('DELETE FROM sessions WHERE expires<?',(now(),))
    c.execute('INSERT INTO sessions VALUES(?,?,?)',(digest(token),user['id'],(datetime.now(timezone.utc)+timedelta(hours=8)).isoformat()))
    response.set_cookie(COOKIE, token, max_age=8*3600, httponly=True, secure=PRODUCTION, samesite='strict', path='/api')
    return dict(csrf=digest('csrf:'+token), user={k:user[k] for k in ('id','username','name','role')})

class Login(StrictModel):
    username: str = Field(max_length=80)
    password: str = Field(max_length=256)

@app.post('/api/auth/login')
def login(body: Login, request: Request, response: Response):
    ip = request.client.host
    account = digest(body.username.strip())
    with db() as c:
        since = (datetime.now(timezone.utc)-timedelta(minutes=10)).isoformat()
        c.execute('DELETE FROM auth_failures WHERE time<?', (since,))
        failures = c.execute('SELECT count(*) FROM auth_failures WHERE ip=? OR account=?', (ip, account)).fetchone()[0]
        if failures >= 10:
            raise HTTPException(429, 'Demasiados intentos. Espera 10 minutos.', headers={'Retry-After':'600'})
        found = c.execute('SELECT * FROM users WHERE username=? AND active=1', (body.username.strip(),)).fetchone()
        user = dict(found) if found else None
    valid = password_matches(body.password, user['password'] if user else DUMMY_PASSWORD)
    if user and PRODUCTION and user['username'].startswith('demo.'):
        valid = False
    if not user or not valid:
        with db() as c:
            c.execute('INSERT INTO auth_failures(ip,time,account) VALUES(?,?,?)', (ip, now(), account))
            audit(c, 'anonymous', 'login.failed', 'session', {'ip':ip})
        raise HTTPException(401, 'Credenciales incorrectas')
    upgraded = password_hash(body.password) if not user['password'].startswith('pbkdf2_sha256$600000$') else None
    with db() as c:
        if upgraded:
            c.execute('UPDATE users SET password=? WHERE id=?', (upgraded, user['id']))
        audit(c, user['username'], 'login', 'session', {})
        return session(c, user, response)


class DemoRole(StrictModel):
    role: Literal['admin','soc1','soc2','ciso','auditor'] = 'admin'

@app.post('/api/demo/session')
def demo_session(body: DemoRole, request: Request, response: Response):
    if PRODUCTION or not DEMO or request.client.host not in ('127.0.0.1','::1') or request.url.hostname not in ('localhost','127.0.0.1','::1'):
        raise HTTPException(404,'No disponible')
    # Local-only demo. Never enable on a public reverse proxy.
    with db() as c:
        username='demo.'+body.role
        user=c.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
        if not user:
            c.execute('INSERT INTO users(username,name,role,password) VALUES(?,?,?,?)',(username,'Operador demo · '+body.role,body.role,password_hash(secrets.token_urlsafe(40))))
            user=c.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
        return session(c,user,response)

@app.get('/api/auth/me')
def me(request: Request, user=Depends(current)):
    token=request.cookies.get(COOKIE,'')
    return dict(user=user,demo=DEMO,csrf=digest('csrf:'+token) if token else '')

@app.post('/api/auth/logout')
def logout(request: Request,response: Response,user=Depends(current)):
    with db() as c:
        c.execute('DELETE FROM sessions WHERE token=?',(digest(request.cookies.get(COOKIE,'') or request.headers.get('authorization','').removeprefix('Bearer ')),))
        audit(c,user['username'],'logout','session',{})
    response.delete_cookie(COOKIE,path='/api',secure=PRODUCTION,httponly=True,samesite='strict')
    return {'ok':True}

class PasswordChange(StrictModel):
    current_password: str = Field(min_length=1,max_length=256)
    new_password: str = Field(min_length=12,max_length=256)


@app.post('/api/auth/password')
def change_password(body: PasswordChange, response: Response, user=Depends(current)):
    with db() as c:
        stored=c.execute('SELECT password FROM users WHERE id=?',(user['id'],)).fetchone()[0]
    if not password_matches(body.current_password,stored):
        raise HTTPException(403,'La contraseña actual no es correcta')
    hashed=password_hash(body.new_password)
    with db() as c:
        c.execute('UPDATE users SET password=? WHERE id=?',(hashed,user['id']))
        c.execute('DELETE FROM sessions WHERE user_id=?',(user['id'],))
        audit(c,user['username'],'password.changed',user['id'],{'sessions_revoked':True})
        return session(c,user,response)


class UserUpdate(StrictModel):
    role: Literal['admin','soc1','soc2','ciso','auditor']
    active: bool


@app.patch('/api/users/{uid}')
def update_user(uid:int,body:UserUpdate,user=Depends(current)):
    allow(user,'admin')
    if uid==user['id']: raise HTTPException(409,'No puedes cambiar tu propio rol ni desactivarte')
    with db() as c:
        target=c.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()
        if not target: raise HTTPException(404,'Usuario no encontrado')
        if target['role']=='admin' and (not body.active or body.role!='admin'):
            if c.execute("SELECT count(*) FROM users WHERE role='admin' AND active=1").fetchone()[0]<=1:
                raise HTTPException(409,'Debe permanecer un administrador activo')
        c.execute('UPDATE users SET role=?,active=? WHERE id=?',(body.role,int(body.active),uid))
        c.execute('DELETE FROM sessions WHERE user_id=?',(uid,))
        audit(c,user['username'],'user.updated',uid,body.model_dump())
    return {'ok':True}


class UserCreate(StrictModel):
    username: str = Field(pattern=r'^[a-zA-Z0-9_.-]{3,40}$')
    name: str = Field(min_length=2,max_length=80)
    password: str = Field(min_length=12,max_length=256)
    role: Literal['admin','soc1','soc2','ciso','auditor']

@app.get('/api/users')
def users(user=Depends(current)):
    allow(user,'admin','ciso','auditor')
    with db() as c:
        return rows(c,"SELECT id,username,name,role,active FROM users WHERE username NOT LIKE 'demo.%' OR ?=1", (int(DEMO),))

@app.post('/api/users')
def create_user(body: UserCreate,user=Depends(current)):
    allow(user,'admin')
    if body.username.startswith('demo.'):
        raise HTTPException(422,'El prefijo demo. está reservado')
    hashed=password_hash(body.password)
    with db() as c:
        try:
            c.execute('INSERT INTO users(username,name,role,password) VALUES(?,?,?,?)',(body.username,body.name,body.role,hashed))
        except sqlite3.IntegrityError:
            raise HTTPException(409,'El usuario ya existe')
        audit(c,user['username'],'user.created',body.username,{'role':body.role})
    return {'ok':True}

class SourceCreate(StrictModel):
    name: str = Field(min_length=2,max_length=80)
    kind: Literal['windows','linux','application','syslog']
    ip: str = Field(default='',max_length=64)
    simulated: bool = False

    @field_validator('name')
    @classmethod
    def trim_name(cls,value):
        value=value.strip()
        if len(value)<2: raise ValueError('El nombre no puede estar vacío')
        return value

    @field_validator('ip')
    @classmethod
    def check_ip(cls,value): return normalized_ip(value)

@app.get('/api/sources')
def sources(user=Depends(current)):
    with db() as c:
        return rows(c,"""SELECT s.id,s.name,s.kind,s.ip,s.simulated,s.created,s.last_seen,s.metrics,
        coalesce(e.total,0) AS events,coalesce(a.total,0) AS alerts
        FROM sources s LEFT JOIN (SELECT source_id,count(*) total FROM events GROUP BY source_id) e ON e.source_id=s.id
        LEFT JOIN (SELECT source_id,count(*) total FROM alerts WHERE status='open' GROUP BY source_id) a ON a.source_id=s.id
        ORDER BY s.created""")


@app.post('/api/sources')
def create_source(body: SourceCreate,user=Depends(current)):
    allow(user,'admin')
    sid='src-'+secrets.token_hex(8)
    token=secrets.token_urlsafe(32)
    with db() as c:
        c.execute('INSERT INTO sources(id,name,kind,ip,simulated,token_hash,created) VALUES(?,?,?,?,?,?,?)',(sid,body.name,body.kind,body.ip,int(body.simulated),digest(token),now()))
        audit(c,user['username'],'source.created',sid,body.model_dump())
    return dict(id=sid,token=token,warning='Guarda el token: solo se muestra una vez.')

@app.post('/api/sources/{sid}/rotate')
def rotate_source(sid:str,user=Depends(current)):
    allow(user,'admin')
    token=secrets.token_urlsafe(32)
    with db() as c:
        if not c.execute('SELECT 1 FROM sources WHERE id=?',(sid,)).fetchone(): raise HTTPException(404,'Fuente no encontrada')
        c.execute('UPDATE sources SET token_hash=? WHERE id=?',(digest(token),sid))
        audit(c,user['username'],'source.token_rotated',sid,{})
    return {'token':token,'id':sid}


@app.post('/api/sources/{sid}/revoke')
def revoke_source(sid:str,user=Depends(current)):
    allow(user,'admin')
    with db() as c:
        if not c.execute('SELECT 1 FROM sources WHERE id=?',(sid,)).fetchone(): raise HTTPException(404,'Fuente no encontrada')
        c.execute('UPDATE sources SET token_hash=NULL WHERE id=?',(sid,))
        audit(c,user['username'],'source.token_revoked',sid,{})
    return {'ok':True}


class EventIn(StrictModel):
    external_id: str | None = Field(default=None,min_length=1,max_length=160)
    time: str | None = None
    user: str = Field(default='',max_length=120)
    src_ip: str = Field(default='',max_length=64)
    dst_ip: str = Field(default='',max_length=64)
    kind: str = Field(min_length=1,max_length=80)
    category: str = Field(default='system',max_length=80)
    code: str = Field(default='',max_length=80)
    description: str = Field(default='',max_length=2000)
    syslog_severity: int = Field(default=6,ge=0,le=7)
    authorized: bool = False
    metrics: dict[str,float] = Field(default_factory=dict,max_length=10)

    @field_validator('src_ip','dst_ip')
    @classmethod
    def check_ip(cls,value): return normalized_ip(value)

    @field_validator('metrics')
    @classmethod
    def check_metrics(cls,value):
        if any(k not in ('cpu','memory','disk') or not math.isfinite(v) or not 0 <= v <= 100 for k,v in value.items()):
            raise ValueError('Métricas permitidas: cpu, memory, disk; valores finitos entre 0 y 100')
        return value

    @field_validator('time')
    @classmethod
    def valid_time(cls,value):
        if value is None:
            return now()
        try:
            parsed=datetime.fromisoformat(value.replace('Z','+00:00'))
            if parsed.tzinfo is None:
                raise ValueError('La fecha requiere zona horaria')
            if parsed > datetime.now(timezone.utc)+timedelta(minutes=5):
                raise ValueError('Fecha futura fuera de tolerancia')
            return parsed.astimezone(timezone.utc).isoformat(timespec='microseconds')
        except (TypeError,ValueError) as exc:
            raise ValueError('Fecha ISO 8601 con zona horaria, sin futuro >5 min') from exc

class Batch(StrictModel):
    events: list[EventIn] = Field(min_length=1,max_length=200)

def source_auth(c,request):
    token=request.headers.get('x-source-token','')
    source=c.execute('SELECT * FROM sources WHERE token_hash=?',(digest(token),)).fetchone()
    if not source:
        raise HTTPException(401,'Token de fuente inválido')
    return dict(source)

@app.post('/api/ingest')
def ingest(body: Batch,request: Request):
    ids=[]
    with db() as c:
        source=source_auth(c,request)
        for event in sorted(body.events, key=lambda e:e.time or now()):
            value=event.model_dump()
            value.update(source_id=source['id'],simulated=bool(source['simulated']),authorized=False,risk=max(70 if event.syslog_severity<=3 else 15,85 if event.kind=='config_changed' else 15))
            ids.append(insert_event(c,value))
        c.execute('UPDATE sources SET last_seen=?,metrics=? WHERE id=?',(now(),canonical(next((e.metrics for e in reversed(body.events) if e.metrics),json.loads(source['metrics']))),source['id']))
    return dict(accepted=len(ids),ids=ids)

def insert_event(c,event,correlate=True):
    event=redact(event)
    event['time']=event.get('time') or now()
    external_id=event.get('external_id')
    if external_id:
        previous=c.execute('SELECT id FROM events WHERE source_id=? AND external_id=?',(event['source_id'],external_id)).fetchone()
        if previous: return previous['id']
    # Allowlisted schema only: raw credentials are never collected.
    payload=canonical(event)
    fields=('time','source_id','user','src_ip','dst_ip','kind','category','code','description','syslog_severity','risk','simulated')
    cursor=c.execute('INSERT INTO events(time,received,source_id,user,src_ip,dst_ip,kind,category,code,description,syslog_severity,risk,simulated,payload,hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(event['time'],now(),*[event.get(k,'') for k in fields[1:]],payload,digest(payload)))
    eid=cursor.lastrowid
    if external_id: c.execute('UPDATE events SET external_id=? WHERE id=?',(external_id,eid))
    if correlate:
        correlate_event(c,event,eid)
    return eid

def correlate_event(c,e,eid):
    t=datetime.fromisoformat(e['time'])
    source=e['source_id']; ip=e['src_ip']; rule=None; evidence=[eid]
    if e['kind']=='login_failed':
        found=rows(c,"SELECT id FROM events WHERE source_id=? AND src_ip=? AND kind='login_failed' AND time>=? AND time<=?",(source,ip,(t-timedelta(seconds=120)).isoformat(),e['time']))
        if len(found)>=5:
            rule='R01'; evidence=[r['id'] for r in found][-200:]
    elif e['kind']=='login_success' and not 7 <= t.astimezone(timezone(timedelta(hours=-6))).hour < 20:
        rule='R02'
    elif e['kind']=='config_changed' and not e.get('authorized',False):
        rule='R03'
    elif e['kind']=='admin_success':
        found=rows(c,"SELECT id FROM events WHERE source_id=? AND src_ip=? AND kind='access_denied' AND time>=? AND time<=?",(source,ip,(t-timedelta(minutes=5)).isoformat(),e['time']))
        if len(found)>=3:
            rule='R04'; evidence=[r['id'] for r in found][-199:]+[eid]
    if rule:
        # One open alert per rule, source and origin. Close to allow another case.
        existing=c.execute("SELECT id FROM alerts WHERE rule_id=? AND source_id=? AND src_ip=? AND status='open'",(rule,source,ip)).fetchone()
        if existing:
            old=json.loads(c.execute('SELECT evidence FROM alerts WHERE id=?',(existing['id'],)).fetchone()[0])
            c.execute('UPDATE alerts SET evidence=? WHERE id=?',(canonical(sorted(set(old+evidence))[-200:]),existing['id']))
            return
        spec=next(r for r in RULES if r['id']==rule)
        aid=c.execute('INSERT INTO alerts(rule_id,title,severity,source_id,src_ip,time,evidence,simulated) VALUES(?,?,?,?,?,?,?,?)',(rule,spec['name'],spec['severity'],source,ip,now(),canonical(evidence),int(e['simulated']))).lastrowid
        audit(c,'correlation','alert.created',aid,{'rule':rule,'events':evidence})

@app.get('/api/events')
def events(q: str=Query('',max_length=200),source: str=Query('',max_length=80),kind: str=Query('',max_length=80),severity: int | None=Query(None,ge=0,le=7),start: str=Query('',max_length=50),end: str=Query('',max_length=50),page: int=Query(1,ge=1,le=100000),user=Depends(current)):
    if page<1 or page>100000 or len(q)>200:
        raise HTTPException(422,'Filtro o página inválida')
    try:
        def normalize_filter(value):
            parsed=datetime.fromisoformat(value.replace('Z','+00:00'))
            if parsed.tzinfo is None: raise ValueError('Timezone required')
            return parsed.astimezone(timezone.utc).isoformat(timespec='microseconds')
        if start: start=normalize_filter(start)
        if end: end=normalize_filter(end)
        if start and end and start>end: raise ValueError('range')
    except ValueError: raise HTTPException(422,'Rango de fechas inválido o sin zona horaria')
    conditions=['1=1']; args=[]
    for field,val in [('source_id',source),('kind',kind)]:
        if val: conditions.append(field+'=?'); args.append(val)
    if severity is not None: conditions.append('syslog_severity=?'); args.append(severity)
    if start: conditions.append('time>=?'); args.append(start)
    if end: conditions.append('time<=?'); args.append(end)
    if q:
        conditions.append('(description LIKE ? OR user LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR code LIKE ?)'); args += ['%'+q+'%']*5
    where=' AND '.join(conditions)
    with db() as c:
        total=c.execute('SELECT count(*) FROM events WHERE '+where,args).fetchone()[0]
        values=rows(c,'SELECT * FROM events WHERE '+where+' ORDER BY time DESC,id DESC LIMIT 40 OFFSET ?',(*args,(page-1)*40))
    return dict(items=values,total=total,page=page,pages=max(1,math.ceil(total/40)))

@app.get('/api/alerts')
def alerts(user=Depends(current)):
    with db() as c:
        return rows(c,'SELECT a.*,s.name AS source_name,i.id AS incident_id FROM alerts a LEFT JOIN sources s ON a.source_id=s.id LEFT JOIN incidents i ON i.alert_id=a.id ORDER BY a.id DESC LIMIT 500')

@app.get('/api/rules')
def rules(user=Depends(current)):
    return RULES

def open_incident(c,aid,actor):
    existing=c.execute('SELECT id FROM incidents WHERE alert_id=?',(aid,)).fetchone()
    if existing: return existing['id']
    alert=c.execute('SELECT * FROM alerts WHERE id=?',(aid,)).fetchone()
    if not alert: raise HTTPException(404,'Alerta no encontrada')
    iid=c.execute('INSERT INTO incidents(alert_id,title,status,owner,priority,created) VALUES(?,?,?,?,?,?)',(aid,alert['title'],'open',actor,alert['severity'],now())).lastrowid
    c.execute('INSERT INTO notes(incident_id,time,actor,body) VALUES(?,?,?,?)',(iid,now(),actor,'Expediente abierto y evidencia vinculada a eventos originales.'))
    audit(c,actor,'incident.opened',iid,{'alert':aid})
    return iid

@app.post('/api/alerts/{aid}/incident')
def create_incident(aid:int,user=Depends(current)):
    allow(user,'admin','soc1','soc2')
    with db() as c:
        return {'id':open_incident(c,aid,user['username'])}

@app.get('/api/incidents')
def incidents(user=Depends(current)):
    with db() as c:
        return rows(c,'SELECT i.*,a.source_id,a.evidence,a.simulated FROM incidents i JOIN alerts a ON i.alert_id=a.id ORDER BY i.id DESC')

@app.get('/api/incidents/{iid}')
def incident_detail(iid:int,user=Depends(current)):
    with db() as c:
        incident=c.execute('SELECT i.*,a.evidence,a.source_id,a.src_ip,a.simulated FROM incidents i JOIN alerts a ON i.alert_id=a.id WHERE i.id=?',(iid,)).fetchone()
        if not incident: raise HTTPException(404,'Expediente no encontrado')
        ids=json.loads(incident['evidence'])
        evidence=rows(c,'SELECT * FROM events WHERE id IN ('+','.join('?'*len(ids))+') ORDER BY time',ids)
        return dict(incident=dict(incident),events=evidence,notes=rows(c,'SELECT * FROM notes WHERE incident_id=? ORDER BY id',(iid,)),runs=rows(c,'SELECT id,playbook,alert_id,incident_id,status,requested_by,approved_by,created,updated,result FROM runs WHERE incident_id=?',(iid,)))

class IncidentUpdate(StrictModel):
    status: Literal['open','analysis','contained','closed']
    cause: str=Field(default='',max_length=2000)
    impact: str=Field(default='',max_length=2000)
    residual: str=Field(default='',max_length=2000)
    note: str=Field(default='',max_length=2000)

@app.patch('/api/incidents/{iid}')
def update_incident(iid:int,body:IncidentUpdate,user=Depends(current)):
    allow(user,'admin','soc2')
    if body.status=='closed' and not all([body.cause.strip(),body.impact.strip(),body.residual.strip(),body.note.strip()]):
        raise HTTPException(422,'Para cerrar, documenta causa, impacto, riesgo residual y verificación en la nota')
    with db() as c:
        item=c.execute('SELECT * FROM incidents WHERE id=?',(iid,)).fetchone()
        if not item: raise HTTPException(404,'Expediente no encontrado')
        pending=c.execute("SELECT 1 FROM runs WHERE incident_id=? AND status IN ('pending','approved','running')",(iid,)).fetchone()
        if body.status=='closed' and pending: raise HTTPException(409,'Resuelve las respuestas pendientes antes de cerrar')
        c.execute('UPDATE incidents SET status=?,cause=?,impact=?,residual=?,closed=? WHERE id=?',(body.status,body.cause,body.impact,body.residual,now() if body.status=='closed' else None,iid))
        c.execute('UPDATE alerts SET status=? WHERE id=?',('closed' if body.status=='closed' else 'open',item['alert_id']))
        if body.note.strip(): c.execute('INSERT INTO notes(incident_id,time,actor,body) VALUES(?,?,?,?)',(iid,now(),user['username'],body.note))
        audit(c,user['username'],'incident.updated',iid,body.model_dump())
    return {'ok':True}

@app.get('/api/playbooks')
def playbooks(user=Depends(current)):
    with db() as c:
        return dict(enabled=LAB_ENABLED,playbooks=PLAYBOOKS,runs=rows(c,'SELECT id,playbook,alert_id,incident_id,status,requested_by,approved_by,created,updated,result FROM runs ORDER BY id DESC LIMIT 200'))

class RunCreate(StrictModel):
    alert_id:int

@app.post('/api/playbooks/{pid}/request')
def request_run(pid:str,body:RunCreate,user=Depends(current)):
    if not LAB_ENABLED: raise HTTPException(403,'Las acciones de laboratorio están desactivadas en este entorno')
    allow(user,'admin','soc2')
    spec=next((p for p in PLAYBOOKS if p['id']==pid),None)
    if not spec: raise HTTPException(404,'Playbook no encontrado')
    with db() as c:
        alert=c.execute('SELECT * FROM alerts WHERE id=?',(body.alert_id,)).fetchone()
        if not alert or alert['rule_id']!=spec['rule'] or alert['status']!='open': raise HTTPException(422,'Selecciona una alerta abierta compatible')
        if c.execute("SELECT 1 FROM runs WHERE alert_id=? AND status IN ('pending','approved','running','completed')",(body.alert_id,)).fetchone(): raise HTTPException(409,'Ya existe una respuesta pendiente o ejecutada')
        iid=open_incident(c,body.alert_id,user['username'])
        rid=c.execute('INSERT INTO runs(playbook,alert_id,incident_id,status,requested_by,created,updated) VALUES(?,?,?,?,?,?,?)',(pid,body.alert_id,iid,'pending',user['username'],now(),now())).lastrowid
        audit(c,user['username'],'playbook.requested',rid,{'playbook':pid,'incident':iid})
    return dict(id=rid)

class Decision(StrictModel):
    approve:bool

@app.post('/api/runs/{rid}/approve')
def approve_run(rid:int,body:Decision,user=Depends(current)):
    allow(user,'ciso')
    with db() as c:
        run=c.execute('SELECT * FROM runs WHERE id=?',(rid,)).fetchone()
        if not run: raise HTTPException(404,'Respuesta no encontrada')
        if run['status']!='pending': raise HTTPException(409,'La respuesta ya fue revisada')
        if run['requested_by']==user['username']: raise HTTPException(403,'El solicitante no puede autorizar su propia respuesta')
        c.execute('UPDATE runs SET status=?,approved_by=?,updated=? WHERE id=?',('approved' if body.approve else 'rejected',user['username'],now(),rid))
        audit(c,user['username'],'playbook.approved' if body.approve else 'playbook.rejected',rid,{})
    return {'ok':True}

def lab_denied(c,source_id,ip):
    return bool(c.execute("SELECT 1 FROM controls WHERE active=1 AND (expires IS NULL OR expires>?) AND ((kind='block' AND ip=?) OR (kind='isolate' AND source_id=?))",(now(),ip,source_id)).fetchone())

def lab_file(name):
    if (DATA/'lab').is_symlink(): raise ValueError('Directorio de laboratorio inválido')
    root=(DATA/'lab').resolve()
    path=DATA/'lab'/name
    if path.is_symlink() or path.resolve().parent!=root:
        raise ValueError('Ruta de laboratorio inválida')
    if path.exists() and path.stat().st_size>65536:
        raise ValueError('Archivo de laboratorio demasiado grande')
    return path


def write_atomic(path,content):
    temp=path.with_name('.'+path.name+'.'+secrets.token_hex(5))
    try:
        fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w',encoding='utf-8',newline='') as handle:
            handle.write(content);handle.flush();os.fsync(handle.fileno())
        os.replace(temp,path)
    finally:
        if temp.exists():temp.unlink()


@app.post('/api/runs/{rid}/execute')
def execute_run(rid:int,user=Depends(current)):
    if not LAB_ENABLED: raise HTTPException(403,'Las acciones de laboratorio están desactivadas en este entorno')
    allow(user,'admin','soc2')
    with db() as c:
        run=c.execute('SELECT * FROM runs WHERE id=?',(rid,)).fetchone()
        if not run or run['status']!='approved': raise HTTPException(409,'Se necesita una respuesta aprobada')
        alert=c.execute('SELECT * FROM alerts WHERE id=?',(run['alert_id'],)).fetchone()
        try:
            if run['playbook']=='PB02':
                path=lab_file('service.conf'); before=path.read_text(encoding='utf-8'); baseline=lab_file('service.baseline').read_text(encoding='utf-8')
                reversal={'content':before,'original_hash':digest(before)}
                c.execute('UPDATE runs SET reversal=? WHERE id=?',(canonical(reversal),rid))
                write_atomic(path,baseline)
                verified=digest(path.read_text(encoding='utf-8'))==digest(baseline)
                result={'scope':'sandbox file','before_hash':digest(before),'after_hash':digest(baseline),'verified':verified}
            else:
                kind='block' if run['playbook']=='PB01' else 'isolate'
                expires=(datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat() if kind=='block' else None
                cid=c.execute('INSERT INTO controls(run_id,source_id,ip,kind,expires) VALUES(?,?,?,?,?)',(rid,alert['source_id'],alert['src_ip'],kind,expires)).lastrowid
                reversal={'control_id':cid}
                result={'scope':'lab application only','control_id':cid,'expires':expires,'verified':lab_denied(c,alert['source_id'],alert['src_ip'])}
            status='completed' if result['verified'] else 'failed'
            c.execute('UPDATE runs SET status=?,result=?,reversal=?,updated=? WHERE id=?',(status,canonical(result),canonical(reversal),now(),rid))
            if status=='completed': c.execute("UPDATE incidents SET status='contained' WHERE id=?",(run['incident_id'],))
            audit(c,user['username'],'playbook.'+status,rid,result)
        except (OSError,ValueError) as exc:
            recovery_verified=None
            if run['playbook']=='PB02' and 'before' in locals():
                try:
                    if digest(path.read_text(encoding='utf-8'))!=digest(before): write_atomic(path,before)
                except (OSError,ValueError): pass
                try: recovery_verified=digest(path.read_text(encoding='utf-8'))==digest(before)
                except OSError: recovery_verified=False
            result={'error':'No se pudo ejecutar la acción de laboratorio','verified':False,'recovery_verified':recovery_verified}
            c.execute("UPDATE runs SET status='failed',result=?,updated=? WHERE id=?",(canonical(result),now(),rid))
            audit(c,user['username'],'playbook.failed',rid,result)
    return {'status':status if 'status' in locals() else 'failed','result':result}

@app.post('/api/runs/{rid}/revert')
def revert_run(rid:int,user=Depends(current)):
    if not LAB_ENABLED: raise HTTPException(403,'Las acciones de laboratorio están desactivadas en este entorno')
    allow(user,'admin','soc2')
    with db() as c:
        run=c.execute('SELECT * FROM runs WHERE id=?',(rid,)).fetchone()
        if not run or run['status']!='completed': raise HTTPException(409,'Solo puedes revertir una ejecución completada')
        if c.execute('SELECT status FROM incidents WHERE id=?',(run['incident_id'],)).fetchone()[0]=='closed':
            raise HTTPException(409,'Reabre el expediente antes de revertir la respuesta')
        reversal=json.loads(run['reversal'])
        try:
            if run['playbook']=='PB02':
                path=lab_file('service.conf')
                if digest(path.read_text(encoding='utf-8'))!=json.loads(run['result'])['after_hash']:
                    raise ValueError('La configuración cambió después de la respuesta; no se sobrescribirá')
                write_atomic(path,reversal['content'])
                verified=digest(path.read_text(encoding='utf-8'))==reversal['original_hash']
            else:
                c.execute('UPDATE controls SET active=0 WHERE id=?',(reversal['control_id'],))
                verified=not c.execute('SELECT active FROM controls WHERE id=?',(reversal['control_id'],)).fetchone()[0]
            if not verified: raise ValueError('No se pudo verificar reversión')
        except (OSError,ValueError) as exc:
            audit(c,user['username'],'playbook.reversal_failed',rid,{'error':'No se pudo verificar la reversión'})
            return {'ok':False,'error':'No se pudo verificar la reversión'}
        c.execute("UPDATE runs SET status='reverted',updated=? WHERE id=?",(now(),rid))
        c.execute("UPDATE incidents SET status='analysis' WHERE id=?",(run['incident_id'],))
        audit(c,user['username'],'playbook.reverted',rid,{'verified':verified})
    return {'ok':True,'verified':verified}

@app.get('/api/lab/access')
def lab_access(source_id:str,ip:str,user=Depends(current)):
    with db() as c:
        denied=lab_denied(c,source_id,ip)
    return dict(allowed=not denied,scope='Aplicación de laboratorio; no es un bloqueo de red del sistema operativo')

def simulate(c,rule,actor):
    sid='web-01' if rule in ('R01','R04') else 'win-01'
    if not c.execute('SELECT 1 FROM sources WHERE id=? AND simulated=1',(sid,)).fetchone(): raise HTTPException(409,'La simulación requiere las fuentes de demostración')
    reference=datetime.now(timezone.utc)
    ip='192.168.10.'+str(random.randint(50,230))
    kinds={'R01':['login_failed']*5,'R02':['login_success'],'R03':['config_changed'],'R04':['access_denied']*3+['admin_success']}.get(rule)
    if not kinds: raise HTTPException(404,'Regla no encontrada')
    if rule=='R03': write_atomic(lab_file('service.conf'),'environment=lab\nadmin_access=unrestricted\n')
    ids=[]
    for index,kind in enumerate(kinds):
        t=reference-timedelta(seconds=(len(kinds)-index)*3)
        if rule=='R02':
            local=t.astimezone(timezone(timedelta(hours=-6)))
            t=local.replace(hour=3,minute=15).astimezone(timezone.utc)
            if t>reference: t-=timedelta(days=1)
        e=dict(time=t.isoformat(),source_id=sid,user='usuario.lab',src_ip=ip,dst_ip='192.168.10.10',kind=kind,category='integrity' if rule=='R03' else 'authentication',code=rule,description='Prueba controlada: '+next(r['name'] for r in RULES if r['id']==rule),syslog_severity=3,risk=85,simulated=True,authorized=False)
        ids.append(insert_event(c,e))
    c.execute('UPDATE sources SET last_seen=? WHERE id=?',(now(),sid))
    audit(c,actor,'simulation.executed',rule,{'events':ids,'synthetic':True})
    return dict(events=ids,rule=rule)

@app.post('/api/demo/simulate/{rule}')
def simulate_rule(rule:str,user=Depends(current)):
    allow(user,'admin','soc2')
    if PRODUCTION or not DEMO: raise HTTPException(403,'Modo demostración desactivado')
    with db() as c: return simulate(c,rule,user['username'])

def analytics_data(c,days=14):
    today=datetime.now(timezone.utc).date()
    first=(today-timedelta(days=days)).isoformat()
    grouped={r['day']:r for r in rows(c,"""SELECT substr(time,1,10) day,count(*) total,
       coalesce(sum(simulated),0) synthetic,sum(CASE WHEN risk>=70 THEN 1 ELSE 0 END) risky
       FROM events WHERE time>=? GROUP BY substr(time,1,10)""",(first,))}
    points=[]
    for offset in range(days,-1,-1):
        day=(today-timedelta(days=offset)).isoformat()
        points.append(grouped.get(day,dict(day=day,total=0,synthetic=0,risky=0)))
    history=[p['total'] for p in points[:-1]]
    baseline=statistics.mean(history) if history else 0
    std=statistics.pstdev(history) if len(history)>1 else 0
    z=(points[-1]['total']-baseline)/max(std,1)
    threshold=baseline+3*max(std,1)
    sufficient=sum(v>0 for v in history)>=7
    return dict(points=points,baseline=round(baseline,2),deviation=round(std,2),z_score=round(z,2),threshold=round(threshold,2),estimate_next_day=round(statistics.mean(history[-7:])) if history else 0,total=sum(p['total'] for p in points),synthetic=sum(p['synthetic'] for p in points),anomaly=sufficient and points[-1]['total']>threshold,sufficient=sufficient,method='Promedio móvil de 7 días completos para estimar el siguiente día; línea base y desviación de los días completos seleccionados; anomalía si volumen > media + 3σ (σ mínimo 1).',limitations='El día actual es parcial. La estimación es volumen de eventos, no probabilidad de ataque. Se necesitan al menos 7 días completos con datos. Los datos sintéticos no validan rendimiento predictivo real.',recommendation='Revisar fuentes y causas del aumento, sin asumir un ataque.' if sufficient and points[-1]['total']>threshold else 'Mantener la recolección y revisar accesos fuera de horario.')

@app.get('/api/analytics')
def analytics(days:int=14,user=Depends(current)):
    if days not in (7,14,30): raise HTTPException(422,'Período permitido: 7, 14 o 30 días')
    with db() as c: return analytics_data(c,days)

@app.get('/api/overview')
def overview(user=Depends(current)):
    with db() as c:
        total=c.execute('SELECT count(*) FROM events').fetchone()[0]
        simulated=c.execute('SELECT count(*) FROM events WHERE simulated=1').fetchone()[0]
        return dict(events=total,synthetic=simulated,sources=c.execute('SELECT count(*) FROM sources').fetchone()[0],real_sources=c.execute('SELECT count(*) FROM sources WHERE simulated=0 AND last_seen IS NOT NULL').fetchone()[0],open_alerts=c.execute("SELECT count(*) FROM alerts WHERE status='open'").fetchone()[0],critical=c.execute("SELECT count(*) FROM alerts WHERE status='open' AND severity='critical'").fetchone()[0],incidents=c.execute("SELECT count(*) FROM incidents WHERE status!='closed'").fetchone()[0],pending=c.execute("SELECT count(*) FROM runs WHERE status='pending'").fetchone()[0],demo=DEMO,series=analytics_data(c)['points'],latest=rows(c,'SELECT a.*,s.name AS source_name FROM alerts a LEFT JOIN sources s ON a.source_id=s.id ORDER BY a.id DESC LIMIT 5'))

def verify_audit(c):
    previous='0'*64
    for raw in c.execute('SELECT * FROM audit ORDER BY id'):
        item=dict(raw)
        value={k:item[k] for k in ('time','actor','action','target','previous')}; value['detail']=json.loads(item['detail'])
        if item['previous']!=previous or digest(canonical(value))!=item['hash']:
            return {'valid':False,'first_invalid':item['id']}
        previous=item['hash']
    return {'valid':True,'head':previous}

@app.get('/api/audit')
def audit_log(user=Depends(current)):
    with db() as c:
        return dict(items=rows(c,'SELECT * FROM audit ORDER BY id DESC LIMIT 300'),integrity=verify_audit(c))

@app.get('/api/reports/export')
def export_report(format:Literal['json','csv']='json',user=Depends(current)):
    limit=100000
    with db() as c:
        audit(c,user['username'],'report.exported','report',{'format':format,'maximum_rows_per_table':limit})
    def generate():
        # A separate WAL read transaction streams a consistent snapshot without the write lock.
        connection=sqlite3.connect(DB,timeout=15)
        connection.row_factory=sqlite3.Row
        try:
            connection.execute('BEGIN')
            if format=='csv':
                stream=io.StringIO(newline='');writer=csv.writer(stream)
                fields=['id','time','source_id','user','src_ip','kind','syslog_severity','risk','simulated','hash']
                writer.writerow(fields);yield '\ufeff'+stream.getvalue()
                for row in connection.execute('SELECT * FROM events ORDER BY id LIMIT ?',(limit,)):
                    stream.seek(0);stream.truncate(0)
                    values=[row[k] for k in fields]
                    writer.writerow([("'"+v) if isinstance(v,str) and v.lstrip().startswith(('=','+','-','@')) else v for v in values])
                    yield stream.getvalue()
            else:
                counts={table:connection.execute('SELECT count(*) FROM '+table).fetchone()[0] for table in ('events','alerts','incidents','runs','audit')}
                metadata={'generated':now(),'counts':counts,'maximum_rows_per_table':limit,'truncated':any(n>limit for n in counts.values()),'integrity':verify_audit(connection),'analytics':analytics_data(connection)}
                yield canonical(metadata)[:-1]
                for table in counts:
                    yield ',"'+table+'":['
                    fields='id,playbook,alert_id,incident_id,status,requested_by,approved_by,created,updated,result' if table=='runs' else '*'
                    separator=''
                    for row in connection.execute('SELECT '+fields+' FROM '+table+' ORDER BY id LIMIT ?',(limit,)):
                        yield separator+canonical(dict(row));separator=','
                    yield ']'
                yield '}'
        finally:
            connection.rollback();connection.close()
    return StreamingResponse(generate(),media_type='text/csv' if format=='csv' else 'application/json',headers={'Content-Disposition':'attachment; filename="hyperlogs-'+('events.csv' if format=='csv' else 'report.json')+'"'})


@app.get('/api/health')
def health():
    with db() as c: c.execute('SELECT 1').fetchone()
    return {'status':'ok','version':'1.1.0'}

@app.get('/api/config')
def public_config(): return {'demo':DEMO and not PRODUCTION,'production':PRODUCTION}

if (ROOT/'dist').exists():
    app.mount('/assets',StaticFiles(directory=ROOT/'dist'/'assets'),name='assets')
    @app.get('/{path:path}')
    def frontend(path:str):
        if path.startswith(('api/','docs','redoc','openapi')) or path=='api':
            raise HTTPException(404,'Ruta no encontrada')
        return FileResponse(ROOT/'dist'/'index.html')
