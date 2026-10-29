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
import urllib.request


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


def claim(server,code,info=None,opener=urllib.request.urlopen):
    server=normalize_server(server);info=info or device_info()
    payload=dict(code=code.strip().upper(),**info)
    request=urllib.request.Request(server+'/api/enrollments/claim',data=json.dumps(payload).encode('utf-8'),
                                   headers={'Content-Type':'application/json'},method='POST')
    with opener(request,timeout=15) as response:
        result=json.load(response)
    if len(result.get('token',''))<20 or not result.get('id'):
        raise RuntimeError('HyperLogs devolvió una vinculación incompleta.')
    return result


def make_config(server,token,root,watch_files=None,protector=None):
    root=Path(root)
    cfg={'server':normalize_server(server),'interval':30,'state':str(root/'agent-state.sqlite3'),
         'watch_files':watch_files or [r'C:\Windows\System32\drivers\etc\hosts'],'auth_log':''}
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


def install_windows(agent_executable,root=None,runner=subprocess.run,dry_run=False):
    if platform.system()!='Windows': raise OSError('La instalación automática solo está disponible en Windows.')
    root=Path(root or os.environ.get('ProgramData',r'C:\ProgramData'))/'HyperLogs'
    binary=root/'HyperLogsAgent.exe';config=root/'agent.json'
    command=startup_command(binary,config)
    task=['schtasks.exe','/Create','/TN','HyperLogs Agent','/SC','ONSTART','/RU','SYSTEM','/RL','HIGHEST','/F',
          '/TR',subprocess.list2cmdline(command)]
    if dry_run:return {'root':str(root),'binary':str(binary),'config':str(config),'task':task}
    root.mkdir(parents=True,exist_ok=True);shutil.copy2(agent_executable,binary)
    acl=runner(['icacls.exe',str(root),'/inheritance:r','/grant:r',
                '*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F'],capture_output=True,text=True,timeout=30)
    if acl.returncode:raise RuntimeError('Windows no pudo proteger la carpeta privada del agente.')
    result=runner(task,capture_output=True,text=True,timeout=30)
    if result.returncode:raise RuntimeError('Windows no pudo crear la tarea de inicio de HyperLogs Agent.')
    runner(['schtasks.exe','/Run','/TN','HyperLogs Agent'],capture_output=True,text=True,timeout=15)
    return {'root':str(root),'binary':str(binary),'config':str(config),'task':task}
