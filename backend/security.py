"""HTTP boundary and input sanitization. No secrets are written to logs."""
import asyncio
import ipaddress
import os
import re
from urllib.parse import urlsplit

from starlette.responses import JSONResponse

PRODUCTION = os.getenv('HYPERLOGS_ENV', 'development') == 'production'
DEMO = os.getenv('HYPERLOGS_DEMO', '0') == '1'
LAB_ENABLED = os.getenv('HYPERLOGS_LAB_ENABLED', '0' if PRODUCTION else '1') == '1'
PUBLIC_URL = os.getenv('HYPERLOGS_PUBLIC_URL', '').rstrip('/')
ALLOWED_HOSTS = [v.strip() for v in os.getenv('HYPERLOGS_ALLOWED_HOSTS', 'localhost,127.0.0.1,::1').split(',') if v.strip()]
MAX_BODY = 1024 * 1024
COOKIE = 'hyperlogs_session'


def validate_environment():
    if os.getenv('HYPERLOGS_ENV','development') not in ('production','development'):
        raise RuntimeError('HYPERLOGS_ENV must be production or development')
    if PRODUCTION:
        if DEMO:
            raise RuntimeError('Production refuses HYPERLOGS_DEMO=1')
        url = urlsplit(PUBLIC_URL)
        if url.scheme != 'https' or not url.hostname or url.username or url.password or url.path not in ('', '/'):
            raise RuntimeError('Set HYPERLOGS_PUBLIC_URL to the HTTPS origin of the production site')
        if not os.getenv('HYPERLOGS_ALLOWED_HOSTS') or any('*' in host for host in ALLOWED_HOSTS) or url.hostname not in ALLOWED_HOSTS:
            raise RuntimeError('Production requires explicit ALLOWED_HOSTS including the public hostname')


def normalized_ip(value):
    if not value:
        return ''
    return str(ipaddress.ip_address(value))


SECRET_PATTERN = re.compile(r'''(?ix)(["']?\b(?:password|passwd|pwd|token|secret|api[_-]?key|authorization)\b["']?\s*[:=]\s*)("[^"\r\n]*"|'[^'\r\n]*'|[^\s,;\}\r\n]+)''')


def redact(value):
    if isinstance(value, str):
        value = re.sub(r'(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+', 'Bearer [REDACTED]', value)
        return SECRET_PATTERN.sub(lambda m: m.group(1) + '[REDACTED]', value)
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


class BoundaryMiddleware:
    """Bounded JSON requests, same-origin writes, and a self-hosted CSP."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        headers = dict(scope.get('headers', []))
        api = scope['path'].startswith('/api/')
        mutating = scope['method'] in ('POST', 'PATCH', 'PUT', 'DELETE')
        origin = headers.get(b'origin', b'').decode('latin1')
        if api and mutating and origin:
            allowed = {PUBLIC_URL} if PRODUCTION else {'http://localhost:8000', 'http://127.0.0.1:8000', 'http://localhost:5173', 'http://127.0.0.1:5173'}
            if origin not in allowed:
                return await JSONResponse({'detail': 'Origen no autorizado'}, 403)(scope, receive, send)
        if api and mutating and headers.get(b'sec-fetch-site') == b'cross-site':
            return await JSONResponse({'detail': 'Solicitud entre sitios rechazada'}, 403)(scope, receive, send)
        if api and mutating:
            content_type = headers.get(b'content-type', b'').split(b';')[0].lower()
            if content_type and content_type != b'application/json':
                return await JSONResponse({'detail': 'Usa application/json'}, 415)(scope, receive, send)
            try:
                length = int(headers.get(b'content-length', b'0'))
            except ValueError:
                return await JSONResponse({'detail': 'Longitud inválida'}, 400)(scope, receive, send)
            if length < 0 or length > MAX_BODY:
                return await JSONResponse({'detail': 'Solicitud demasiado grande (máximo 1 MiB)'}, 413)(scope, receive, send)
            body = bytearray()
            deadline=asyncio.get_running_loop().time()+10
            try:
                while True:
                    message = await asyncio.wait_for(receive(), timeout=max(.001,deadline-asyncio.get_running_loop().time()))
                    if message['type'] == 'http.disconnect':
                        return
                    body.extend(message.get('body', b''))
                    if len(body) > MAX_BODY:
                        return await JSONResponse({'detail': 'Solicitud demasiado grande'}, 413)(scope, receive, send)
                    if not message.get('more_body', False):
                        break
            except asyncio.TimeoutError:
                return await JSONResponse({'detail': 'Tiempo de recepción excedido'}, 408)(scope, receive, send)
            sent = False
            original_receive = receive

            async def buffered_receive():
                nonlocal sent
                if not sent:
                    sent = True
                    return {'type': 'http.request', 'body': bytes(body), 'more_body': False}
                return await original_receive()
            receive = buffered_receive

        async def secure_send(message):
            if message['type'] == 'http.response.start':
                values = list(message.get('headers', []))
                values += [
                    (b'x-content-type-options', b'nosniff'),
                    (b'x-frame-options', b'DENY'),
                    (b'referrer-policy', b'same-origin'),
                    (b'permissions-policy', b'camera=(), microphone=(), geolocation=()'),
                    (b'content-security-policy', b"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"),
                ]
                if api:
                    values.append((b'cache-control', b'no-store'))
                elif re.search(r'/assets/[^/]+-[A-Za-z0-9_-]{8}\.(?:js|css)$',scope['path']):
                    values.append((b'cache-control', b'public, max-age=31536000, immutable'))
                elif scope['path'].startswith('/assets/'):
                    values.append((b'cache-control', b'public, max-age=3600'))
                else:
                    values.append((b'cache-control', b'no-cache'))
                message['headers'] = values
            await send(message)
        await self.app(scope, receive, secure_send)
