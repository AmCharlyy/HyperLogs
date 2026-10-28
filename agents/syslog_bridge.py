"""Loopback-only RFC 5424 UDP receiver. Use rsyslog for remote/TLS reception."""
import argparse
import re
import socket
import time
import uuid
from datetime import datetime,timezone
from transport import Queue,config

PATTERN=re.compile(r'^<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) (.*)$',re.DOTALL)


def parse(message):
    match=PATTERN.match(message)
    if not match or not 0<=int(match[1])<=191:raise ValueError('Expected RFC 5424 version 1')
    rest=match[7]
    if rest.startswith('- '):text=rest[2:]
    elif rest.startswith('['):
        # Skip structured-data blocks with escaped brackets; keep only MSG.
        end=0;escaped=False;quoted=False
        for i,char in enumerate(rest):
            if escaped:escaped=False;continue
            if char=='\\':escaped=True;continue
            if char=='"':quoted=not quoted
            if char==']' and not quoted and (i+1==len(rest) or rest[i+1]!='['):end=i+1;break
        if not end:raise ValueError('Invalid structured data')
        text=rest[end:].lstrip()
    elif rest=='-':text=''
    else:raise ValueError('Invalid structured data')
    stamp=match[2]
    if stamp=='-':stamp=datetime.now(timezone.utc).isoformat()
    return dict(external_id='syslog-'+uuid.uuid4().hex,time=stamp,kind='syslog',category='system',code=match[6][:80],description=(match[3]+' / '+match[4]+': '+text)[:2000],syslog_severity=int(match[1])%8)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--config',required=True);parser.add_argument('--port',type=int,default=5514);args=parser.parse_args()
    queue=Queue(config(args.config));sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.bind(('127.0.0.1',args.port));sock.settimeout(1);last=0
    print('Syslog bridge listening on loopback UDP '+str(args.port),flush=True)
    while True:
        try:
            raw,_=sock.recvfrom(8192)
            try:queue.add(parse(raw.decode('utf-8',errors='replace')));queue.commit()
            except ValueError:print('Rejected malformed RFC 5424 message',flush=True)
        except socket.timeout:pass
        if time.monotonic()-last>=2:
            last=time.monotonic()
            try:queue.flush()
            except Exception as exc:print('Delivery deferred ('+type(exc).__name__+')',flush=True)


if __name__=='__main__':main()
