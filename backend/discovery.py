"""Bounded, unprivileged discovery on explicitly configured private LANs."""
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from fastapi import Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

PRIVATE_LANS = tuple(ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))


def _clean_hostname(value):
    value = (value or '').strip().rstrip('.')[:253]
    if not value or not re.fullmatch(r'[A-Za-z0-9_.-]+', value):
        return ''
    try:
        ipaddress.ip_address(value)
        return ''
    except ValueError:
        return value


def resolve_device_name(ip):
    """Best-effort PTR/NetBIOS lookup with strict process timeouts."""
    windows = platform.system() == 'Windows'
    try:
        if windows:
            command = ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
                       f"Resolve-DnsName -Name '{ip}' -Type PTR -DnsOnly -ErrorAction Stop | "
                       'Select-Object -First 1 -ExpandProperty NameHost']
        else:
            command = ['getent', 'hosts', ip]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=2,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), text=True)
        if result.returncode == 0:
            raw = result.stdout.split()[0 if windows else 1]
            name = _clean_hostname(raw)
            if name:
                return name, 'dns'
    except (OSError, subprocess.TimeoutExpired, IndexError):
        pass
    if windows:
        try:
            result = subprocess.run(['nbtstat', '-A', ip], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    timeout=2, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), text=True)
            for line in result.stdout.splitlines():
                match = re.match(r'\s*([^\s<]{1,63})\s+<00>\s+UNIQUE', line, re.IGNORECASE)
                if match:
                    name = _clean_hostname(match.group(1))
                    if name:
                        return name, 'netbios'
        except (OSError, subprocess.TimeoutExpired):
            pass
    return '', ''

def allowed_networks():
    result = []
    for value in os.getenv('HYPERLOGS_DISCOVERY_NETWORKS', '').split(','):
        if not value.strip():
            continue
        try:
            network = ipaddress.ip_network(value.strip(), strict=True)
            if network.version == 4 and network.prefixlen >= 16 and any(network.subnet_of(parent) for parent in PRIVATE_LANS):
                result.append(network)
        except ValueError:
            continue
    return result


def validate_network(value):
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError:
        raise HTTPException(422, 'Escribe una subred IPv4 válida, por ejemplo 192.168.1.0/24.')
    if network.version != 4 or network.prefixlen < 24 or network.prefixlen > 30:
        raise HTTPException(422, 'Selecciona una subred entre /24 y /30 (máximo 254 equipos).')
    if not any(network.subnet_of(parent) for parent in allowed_networks()):
        raise HTTPException(403, 'Esta subred no está autorizada en HYPERLOGS_DISCOVERY_NETWORKS del servidor.')
    return network


def probe(ip):
    """No banners, credentials, OS fingerprinting or remote execution."""
    reachable = False
    try:
        windows = platform.system() == 'Windows'
        command = ['ping', '-n', '1', '-w', '600', ip] if windows else ['ping', '-n', '-c', '1', '-W', '1', ip]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=2, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        # Windows can exit successfully after an ICMP "destination unreachable".
        reachable = result.returncode == 0 and (not windows or b'ttl=' in result.stdout.lower())
    except (OSError, subprocess.TimeoutExpired):
        pass
    ports = []
    for port in (22, 80, 443, 445, 3389):
        try:
            with socket.create_connection((ip, port), timeout=.18):
                ports.append(port)
        except OSError:
            pass
    if not reachable and not ports:
        return None
    hostname, name_source = resolve_device_name(ip)
    return {'ip': ip, 'ports': ports, 'method': 'icmp+tcp' if reachable and ports else 'icmp' if reachable else 'tcp',
            'suggested_kind': 'windows' if 445 in ports or 3389 in ports else 'linux' if 22 in ports else 'application' if ports else 'syslog',
            'hostname': hostname, 'name_source': name_source}


class ScanBody(BaseModel):
    model_config = ConfigDict(extra='forbid')
    network: str = Field(min_length=9, max_length=32)


def install(app, db, current, allow, audit, now):
    lock = threading.Lock()
    job = {'status': 'idle', 'checked': 0, 'total': 0, 'found': 0}
    last_started = [0.0]

    def initialize(c):
        c.execute('''CREATE TABLE IF NOT EXISTS discovered_assets(
            ip TEXT PRIMARY KEY, network TEXT NOT NULL, ports TEXT NOT NULL, method TEXT NOT NULL,
            suggested_kind TEXT NOT NULL, hostname TEXT NOT NULL DEFAULT '', name_source TEXT NOT NULL DEFAULT '',
            first_seen TEXT NOT NULL, last_seen TEXT NOT NULL)''')
        columns = {row[1] for row in c.execute('PRAGMA table_info(discovered_assets)')}
        if 'hostname' not in columns:
            c.execute("ALTER TABLE discovered_assets ADD COLUMN hostname TEXT NOT NULL DEFAULT ''")
        if 'name_source' not in columns:
            c.execute("ALTER TABLE discovered_assets ADD COLUMN name_source TEXT NOT NULL DEFAULT ''")

    def run(network, actor):
        checked = found = 0
        try:
            with ThreadPoolExecutor(max_workers=16, thread_name_prefix='lan-probe') as executor:
                tasks = [executor.submit(probe, str(ip)) for ip in network.hosts()]
                for future in as_completed(tasks):
                    item = future.result()
                    checked += 1
                    if item:
                        found += 1
                        timestamp = now()
                        with db() as c:
                            initialize(c)
                            c.execute('''INSERT INTO discovered_assets
                                (ip,network,ports,method,suggested_kind,hostname,name_source,first_seen,last_seen)
                                VALUES(?,?,?,?,?,?,?,?,?)
                                ON CONFLICT(ip) DO UPDATE SET network=excluded.network,ports=excluded.ports,
                                method=excluded.method,suggested_kind=excluded.suggested_kind,
                                hostname=CASE WHEN excluded.hostname<>'' THEN excluded.hostname ELSE discovered_assets.hostname END,
                                name_source=CASE WHEN excluded.name_source<>'' THEN excluded.name_source ELSE discovered_assets.name_source END,
                                last_seen=excluded.last_seen''',
                                (item['ip'], str(network), json.dumps(item['ports']), item['method'], item['suggested_kind'],
                                 item.get('hostname', ''), item.get('name_source', ''), timestamp, timestamp))
                    with lock:
                        job.update(checked=checked, found=found)
            with db() as c:
                audit(c, actor, 'discovery.completed', str(network), {'checked': checked, 'found': found})
            with lock:
                job.update(status='completed', finished=now())
        except Exception:
            try:
                with db() as c:
                    audit(c, actor, 'discovery.failed', str(network), {'checked': checked, 'found': found})
            except Exception:
                pass
            with lock:
                job.update(status='failed', error='No se pudo completar el descubrimiento. Revisa la conectividad y los permisos del servidor.')

    @app.get('/api/discovery')
    def state(user=Depends(current)):
        with db() as c:
            initialize(c)
            items = [dict(row) for row in c.execute('''SELECT d.*,s.id AS source_id,s.name AS source_name
                FROM discovered_assets d LEFT JOIN sources s ON s.ip=d.ip AND s.simulated=0 ORDER BY d.last_seen DESC,d.ip''')]
        for item in items:
            item['ports'] = json.loads(item['ports'])
        with lock:
            snapshot = dict(job)
        return {'networks': [str(n) for n in allowed_networks()], 'job': snapshot, 'assets': items,
                'scope': 'Equipos que responden a ICMP o TCP 22, 80, 443, 445, 3389. Un equipo silencioso puede no aparecer.'}

    @app.post('/api/discovery/scan', status_code=202)
    def start(body: ScanBody, user=Depends(current)):
        allow(user, 'admin')
        network = validate_network(body.network)
        with lock:
            if job['status'] == 'running':
                raise HTTPException(409, 'Ya hay un escaneo en curso.')
            if time.monotonic() - last_started[0] < 60:
                raise HTTPException(429, 'Espera un minuto entre escaneos.')
            with db() as c:
                initialize(c)
                audit(c, user['username'], 'discovery.started', str(network), {'maximum_hosts': network.num_addresses - 2})
            last_started[0] = time.monotonic()
            job.clear()
            job.update(status='running', network=str(network), checked=0, total=network.num_addresses - 2, found=0, started=now())
            snapshot = dict(job)
            threading.Thread(target=run, args=(network, user['username']), daemon=True, name='lan-discovery').start()
        return snapshot
