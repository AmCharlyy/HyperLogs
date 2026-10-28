"""Local administration: never expose bootstrap/reset/backup as HTTP routes."""
import argparse
import getpass
import json
import os
from pathlib import Path
import sqlite3
import tarfile
from datetime import datetime, timezone
import tempfile


def main():
    parser=argparse.ArgumentParser(description='HyperLogs server administration')
    sub=parser.add_subparsers(dest='command',required=True)
    sub.add_parser('bootstrap')
    reset=sub.add_parser('set-password');reset.add_argument('username')
    backup=sub.add_parser('backup');backup.add_argument('--output',required=True)
    sub.add_parser('verify')
    args=parser.parse_args()
    if args.command=='bootstrap':
        password=getpass.getpass('Initial admin password (at least 12 characters): ')
        if len(password)<12 or password!=getpass.getpass('Repeat password: '):
            raise SystemExit('Passwords must match and have at least 12 characters')
        os.environ['HYPERLOGS_ADMIN_PASSWORD']=password
    from . import app as service
    if args.command=='bootstrap':
        if service.DB.exists():
            conn=sqlite3.connect(service.DB)
            exists=conn.execute("SELECT count(*) FROM sqlite_master WHERE name='users'").fetchone()[0]
            has_users=exists and conn.execute('SELECT count(*) FROM users').fetchone()[0]
            conn.close()
            if has_users: raise SystemExit('Already initialized. Use set-password to recover an account.')
        service.initialize()
        os.environ.pop('HYPERLOGS_ADMIN_PASSWORD',None)
        print('Administrator created. Username: admin. No password has been logged.')
    elif args.command=='set-password':
        password=getpass.getpass('New password: ')
        if len(password)<12 or password!=getpass.getpass('Repeat password: '): raise SystemExit('Passwords must match and have at least 12 characters')
        hashed=service.password_hash(password)
        with service.db() as c:
            user=c.execute('SELECT id FROM users WHERE username=?',(args.username,)).fetchone()
            if not user: raise SystemExit('Unknown account')
            c.execute('UPDATE users SET password=? WHERE id=?',(hashed,user['id']))
            c.execute('DELETE FROM sessions WHERE user_id=?',(user['id'],))
            service.audit(c,'local-admin','password.reset',args.username,{'sessions_revoked':True})
        print('Password updated; previous sessions revoked.')
    elif args.command=='backup':
        destination=Path(args.output).resolve()
        if destination.exists(): raise SystemExit('Refusing to overwrite an existing backup')
        destination.parent.mkdir(parents=True,exist_ok=True)
        # Backup API captures committed WAL contents; never copy the live .sqlite file alone.
        with tempfile.TemporaryDirectory() as scratch:
            path=Path(scratch)/'hyperlogs.sqlite3'
            source=sqlite3.connect(service.DB);target=sqlite3.connect(path)
            try: source.backup(target)
            finally: target.close();source.close()
            manifest={'created':datetime.now(timezone.utc).isoformat(),'database_sha256':__import__('hashlib').sha256(path.read_bytes()).hexdigest()}
            (Path(scratch)/'manifest.json').write_text(json.dumps(manifest,indent=2))
            # Exclusive creation + owner-only permissions, including the archive containing lab snapshots.
            fd=os.open(destination,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            with os.fdopen(fd,'wb') as raw,tarfile.open(fileobj=raw,mode='w:gz') as archive:
                archive.add(path,arcname='hyperlogs.sqlite3')
                archive.add(Path(scratch)/'manifest.json',arcname='manifest.json')
                if (service.DATA/'lab').exists(): archive.add(service.DATA/'lab',arcname='lab')
        print('Backup created: '+str(destination))
    elif args.command=='verify':
        with service.db() as c:
            database=c.execute('PRAGMA integrity_check').fetchone()[0]
            audit=service.verify_audit(c)
        print(json.dumps({'database':database,'audit':audit},indent=2))
        if database!='ok' or not audit['valid']: raise SystemExit(1)


if __name__=='__main__': main()
