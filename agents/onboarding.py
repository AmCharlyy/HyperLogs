"""Enrollment and isolated install planning for HyperLogs Agent Setup."""
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import tempfile
import urllib.parse
import urllib.error
import urllib.request

from tls_context import verified_context

AUDIT_LOGON_GUID='{0CCE9215-69AE-11D9-BED3-505054503030}'


def normalize_server(value):
    value=value.strip().rstrip('/')
    parsed=urllib.parse.urlsplit(value)
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('','/'):
        raise ValueError('Escribe solo el origen del servidor, sin ruta ni credenciales.')
    if parsed.scheme!='https' and not (parsed.scheme=='http' and parsed.hostname in ('localhost','127.0.0.1','::1')):
        raise ValueError('HyperLogs requiere HTTPS, excepto en pruebas locales.')
    if not parsed.hostname:
        raise ValueError('La dirección del servidor no es válida.')
    return value


def device_info():
    hostname=socket.gethostname()[:80]
    ip=''
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
            sock.connect(('192.0.2.1',9));ip=sock.getsockname()[0]
    except OSError:
        try: ip=socket.gethostbyname(hostname)
        except OSError: pass
    return {'hostname':hostname,'ip':ip,'os_version':f'{platform.system()} {platform.release()} {platform.version()}'[:160]}


def claim(server,code,info=None,opener=urllib.request.urlopen,ca_cert=None):
    server=normalize_server(server);info=info or device_info()
    payload=dict(code=code.strip().upper(),**info)
    request=urllib.request.Request(server+'/api/enrollments/claim',data=json.dumps(payload).encode('utf-8'),
                                   headers={'Content-Type':'application/json'},method='POST')
    options={'timeout':15}
    if ca_cert:
        options['context']=verified_context(ca_cert)
    with opener(request,**options) as response:
        result=json.load(response)
    if len(result.get('token',''))<20 or not result.get('id'):
        raise RuntimeError('HyperLogs devolvió una vinculación incompleta.')
    return result


def server_health(server,ca_cert,opener=urllib.request.urlopen):
    server=normalize_server(server)
    request=urllib.request.Request(server+'/api/health',headers={'Accept':'application/json'})
    options={'timeout':10,'context':verified_context(ca_cert)}
    with opener(request,**options) as response:
        result=json.load(response)
    if result.get('status')!='ok':
        raise RuntimeError('El servidor respondió, pero su estado no es saludable.')
    return result


def make_config(server,token,root,watch_files=None,protector=None,ca_cert=None):
    root=Path(root)
    cfg={'server':normalize_server(server),'interval':30,'state':str(root/'agent-state.sqlite3'),
         'watch_files':watch_files or [r'C:\Windows\System32\drivers\etc\hosts'],'auth_log':''}
    if ca_cert:
        cfg['ca_cert']=str(Path(ca_cert).resolve())
    if platform.system()=='Windows':
        if protector is None:
            from windows_secret import protect
            protector=protect
        cfg['token_protected']=protector(token)
    else:
        cfg['token']=token
    return cfg


def write_config(path,cfg):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    handle,tmp=tempfile.mkstemp(prefix='.agent-',suffix='.json',dir=path.parent);os.close(handle)
    temp=Path(tmp)
    try:
        temp.write_text(json.dumps(cfg,ensure_ascii=False,indent=2),encoding='utf-8')
        os.chmod(temp,0o600);os.replace(temp,path)
    finally:
        temp.unlink(missing_ok=True)


def startup_command(agent_executable,config_path):
    return [str(agent_executable),'--config',str(config_path)]


def install_windows(agent_executable,root=None,runner=subprocess.run,dry_run=False,ca_certificate=None,start_task=True):
    if platform.system()!='Windows': raise OSError('La instalación automática solo está disponible en Windows.')
    root=Path(root or os.environ.get('ProgramData',r'C:\ProgramData'))/'HyperLogs'
    binary=root/'HyperLogsAgent.exe';config=root/'agent.json';ca_target=root/'caddy-root.crt'
    command=startup_command(binary,config)
    task=['schtasks.exe','/Create','/TN','HyperLogs Agent','/SC','ONSTART','/RU','SYSTEM','/RL','HIGHEST','/F',
          '/TR',subprocess.list2cmdline(command)]
    if dry_run:return {'root':str(root),'binary':str(binary),'config':str(config),'ca_cert':str(ca_target),'task':task}
    # End an older copy before replacing the executable. A missing task is harmless.
    runner(['schtasks.exe','/End','/TN','HyperLogs Agent'],capture_output=True,text=True,timeout=15)
    root.mkdir(parents=True,exist_ok=True);shutil.copy2(agent_executable,binary)
    if ca_certificate:
        source=Path(ca_certificate).resolve()
        if not source.is_file():raise RuntimeError('No se encontró caddy-root.crt junto al instalador.')
        shutil.copy2(source,ca_target)
    acl=runner(['icacls.exe',str(root),'/inheritance:r','/grant:r',
                '*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F'],capture_output=True,text=True,timeout=30)
    if acl.returncode:raise RuntimeError('Windows no pudo proteger la carpeta privada del agente.')
    result=runner(task,capture_output=True,text=True,timeout=30)
    if result.returncode:raise RuntimeError('Windows no pudo crear la tarea de inicio de HyperLogs Agent.')
    if start_task:
        result=runner(['schtasks.exe','/Run','/TN','HyperLogs Agent'],capture_output=True,text=True,timeout=15)
        if result.returncode:raise RuntimeError('La instalación terminó, pero Windows no pudo iniciar la tarea del agente.')
    return {'root':str(root),'binary':str(binary),'config':str(config),'ca_cert':str(ca_target),'task':task}


def enable_windows_auditing(runner=subprocess.run):
    if platform.system()!='Windows':return False
    result=runner(['auditpol.exe','/set','/subcategory:'+AUDIT_LOGON_GUID,
                   '/success:enable','/failure:enable'],capture_output=True,text=True,timeout=30)
    return result.returncode==0


def run_agent_once(binary,config_path,runner=subprocess.run):
    result=runner([str(binary),'--config',str(config_path),'--once'],capture_output=True,text=True,timeout=90)
    output=((result.stdout or '')+'\n'+(result.stderr or '')).strip()
    if result.returncode or 'Delivery deferred' in output or 'Acknowledged events:' not in output:
        raise RuntimeError('El agente se instaló, pero la prueba de envío falló. '+(output[-500:] or 'Sin detalles.'))
    return output


def start_windows_task(runner=subprocess.run):
    result=runner(['schtasks.exe','/Run','/TN','HyperLogs Agent'],capture_output=True,text=True,timeout=20)
    if result.returncode:raise RuntimeError('Windows no pudo iniciar la tarea automática del agente.')
    return True


def repair_config(path,server,ca_cert):
    path=Path(path)
    if not path.is_file():raise FileNotFoundError('No existe una instalación anterior para reparar.')
    cfg=json.loads(path.read_text(encoding='utf-8-sig'))
    if not cfg.get('token_protected') and not cfg.get('token'):
        raise ValueError('La configuración existente no contiene una credencial del agente.')
    cfg['server']=normalize_server(server)
    cfg['ca_cert']=str(Path(ca_cert).resolve())
    write_config(path,cfg)
    return cfg


def friendly_error(exc):
    import ssl
    if isinstance(exc,ssl.SSLCertVerificationError):
        return 'El certificado no corresponde a este servidor. Descarga nuevamente el instalador desde HyperLogs.'
    if isinstance(exc,urllib.error.URLError) and isinstance(getattr(exc,'reason',None),ssl.SSLCertVerificationError):
        return 'El certificado no corresponde a este servidor. Descarga nuevamente el instalador desde HyperLogs.'
    if isinstance(exc,urllib.error.HTTPError):
        if exc.code in (401,403):return 'El código de vinculación es incorrecto, venció o ya fue utilizado. Genera uno nuevo.'
        if exc.code==429:return 'Hubo demasiados intentos. Espera un minuto y vuelve a intentarlo.'
        return f'HyperLogs respondió con HTTP {exc.code}. Revisa el servidor e inténtalo de nuevo.'
    if isinstance(exc,(urllib.error.URLError,socket.timeout,TimeoutError)):
        return 'No fue posible llegar al servidor. Comprueba Wi-Fi, dirección, puerto 8443 y firewall.'
    if isinstance(exc,PermissionError):
        return 'Windows bloqueó un archivo o permiso. Ejecuta nuevamente el instalador como administrador.'
    if isinstance(exc,subprocess.TimeoutExpired):
        return 'Una comprobación de Windows tardó demasiado. Reinicia el equipo y usa Diagnosticar y reparar.'
    return str(exc) or 'No se pudo completar la configuración.'
