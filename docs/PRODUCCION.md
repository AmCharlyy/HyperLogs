# Despliegue de una instancia en Debian/Linux

## Contenedores en Windows y desarrollo local

El perfil Compose incluido ejecuta la misma API compilada en modo producción, SQLite en un directorio persistente y Caddy como proxy HTTPS. De forma predeterminada se enlaza solo a `127.0.0.1`; mediante el `.env` puede exponerse de forma explícita a una LAN autorizada. En Windows requiere Docker Desktop con el motor Linux/WSL 2 iniciado.

```powershell
New-Item -ItemType Directory -Force .runtime/data/downloads
@'
HYPERLOGS_DISCOVERY_NETWORKS=192.168.2.0/24
HYPERLOGS_BIND_ADDRESS=0.0.0.0
HYPERLOGS_SITE_ADDRESS=192.168.2.114
HYPERLOGS_PUBLIC_URL=https://192.168.2.114:8443
HYPERLOGS_ALLOWED_HOSTS=192.168.2.114,localhost
'@ | Set-Content -Path .env
docker compose build
docker compose run --rm app python -m backend.manage bootstrap
docker compose up -d
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt .runtime/caddy-root.crt
python -m pip install -r agents/requirements.txt
powershell -ExecutionPolicy Bypass -File agents/build_windows.ps1
Copy-Item dist/HyperLogsSetup.exe .runtime/data/downloads/
Copy-Item dist/HyperLogsAgent.exe .runtime/data/downloads/
Copy-Item .runtime/caddy-root.crt .runtime/data/downloads/
docker compose ps
```

Cambia `192.168.2.0/24` por la subred IPv4 real y `192.168.2.114` por la IP fija o reservada del equipo anfitrión. El archivo `.env` es local, está excluido de Git y Compose lo usa para limitar el descubrimiento y definir el origen HTTPS. Si el panel será exclusivamente local, conserva los valores predeterminados y omite estas variables.

Para permitir el acceso desde otros equipos del mismo segmento, crea una regla acotada desde PowerShell **como administrador**:

```powershell
New-NetFirewallRule -DisplayName 'HyperLogs HTTPS LAN' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8443 -RemoteAddress 192.168.2.0/24 -Profile Any
```

El instalador publicado ya contiene la CA pública y la URL de esta instancia; el usuario descarga únicamente `HyperLogsSetup.exe`. Los otros archivos se conservan como componentes avanzados. Protege la clave privada de Caddy, que permanece en el volumen Docker y nunca debe copiarse.

El comando `bootstrap` solicita una contraseña nueva de forma interactiva; crea la cuenta `admin` y no imprime el secreto. No hay contraseña predeterminada. Luego entra en `https://localhost:8443`. Caddy crea una CA local privada y su certificado raíz se exporta a `.runtime/caddy-root.crt`. Los navegadores mostrarán una advertencia hasta que el usuario decida instalar esa raíz en el almacén de confianza de su perfil de Windows; no omitas las advertencias TLS. Si deseas confiarla manualmente, ejecuta en PowerShell: `Import-Certificate -FilePath .runtime/caddy-root.crt -CertStoreLocation Cert:\CurrentUser\Root`. Si no deseas confiarla, puedes detener el perfil con `docker compose down`.

La base SQLite, las fuentes y los archivos de descarga se conservan en `.runtime/data` incluso después de actualizar o recrear los contenedores. Para respaldar, detén brevemente la instancia y copia ese directorio completo; para una copia consistente mientras está activa, utiliza `docker compose exec app python -m backend.manage backup --output /var/lib/hyperlogs/backups/archivo.tar.gz`. No uses el modo demo para esta instancia.

Los escaneos de red permanecen desactivados (`HYPERLOGS_DISCOVERY_NETWORKS` vacío). Antes de habilitarlos, autoriza únicamente los segmentos que administras y evalúa el acceso desde la red Docker.

> Esta configuración es producción local con límites y TLS, no una publicación pública. Para acceder desde otros equipos hay que proporcionar un dominio/certificado de confianza, ampliar hosts autorizados y revisar firewall, respaldos fuera del equipo y despliegue en un host dedicado.

Usa un equipo dedicado o VM con Linux sin escritorio. La propuesta evita Docker, servicios de base de datos separados y compilaciones continuas en el servidor. Un solo proceso de API mantiene las escrituras SQLite y la cadena de auditoría coordinadas. Escalar a múltiples procesos requiere rediseñar esa coordinación; no aumentes `--workers` sin hacerlo.

## 1. Preparar archivos y usuario de servicio

Con permisos administrativos en Linux, instala Python 3.12+ con venv y Nginx desde los repositorios mantenidos de tu distribución. Copia el proyecto y el `dist/` compilado a `/opt/hyperlogs`. El paquete de entrega no incluye base de datos, usuarios, tokens, dependencias de desarrollo ni node_modules.

```bash
sudo useradd --system --home /var/lib/hyperlogs --shell /usr/sbin/nologin hyperlogs
sudo install -d -o hyperlogs -g hyperlogs -m 0700 /var/lib/hyperlogs
sudo install -d -o root -g hyperlogs -m 0750 /etc/hyperlogs
sudo python3 -m venv /opt/hyperlogs/.venv
sudo /opt/hyperlogs/.venv/bin/python -m pip install -r /opt/hyperlogs/requirements.txt
sudo chown -R root:root /opt/hyperlogs
sudo chmod -R a+rX /opt/hyperlogs
```

El código debe ser de solo lectura para el usuario del servicio. La base y los respaldos viven en `/var/lib/hyperlogs`, nunca dentro de `dist/`.

## 2. Configurar entorno

Copia `deploy/hyperlogs.env.example` a `/etc/hyperlogs/hyperlogs.env`, cambia el dominio e indica:

```ini
HYPERLOGS_ENV=production
HYPERLOGS_DEMO=0
HYPERLOGS_LAB_ENABLED=0
HYPERLOGS_DATA=/var/lib/hyperlogs
HYPERLOGS_PUBLIC_URL=https://tu-dominio.example
HYPERLOGS_ALLOWED_HOSTS=tu-dominio.example,localhost,127.0.0.1
```

No utilices comodines en hosts ni copies la base demo. Da al archivo permisos `root:hyperlogs`, modo `0640`. La URL pública es el origen exacto; no incluye rutas. Esta versión sirve frontend/API desde el mismo origen y no habilita CORS.

## 3. Bootstrap sin secretos en historial

Desde `/opt/hyperlogs`, ejecuta como usuario del servicio, configurando las mismas variables **no secretas** del archivo anterior. Por ejemplo:

```bash
sudo -u hyperlogs env HYPERLOGS_ENV=production HYPERLOGS_DEMO=0 \
 HYPERLOGS_DATA=/var/lib/hyperlogs \
 HYPERLOGS_PUBLIC_URL=https://tu-dominio.example \
 HYPERLOGS_ALLOWED_HOSTS=tu-dominio.example,localhost,127.0.0.1 \
 /opt/hyperlogs/.venv/bin/python -m backend.manage bootstrap
```

La contraseña se solicita con getpass. No se guarda en `.env`, scripts, reportes ni argumentos de shell. El usuario inicial es `admin`. Después crea cuentas individuales, especialmente la de CISO; no compartas la cuenta de administrador.

Recuperación de cuenta por un administrador del servidor: mismo entorno y `python -m backend.manage set-password nombre`. Esta operación revoca todas las sesiones de esa cuenta y deja auditoría.

## 4. HTTPS, proxy y servicio

Edita dominio y rutas de certificado en `deploy/nginx.conf`. Debes disponer de un certificado válido para ese dominio. Coloca `limit_req_zone` en el contexto `http{}` de Nginx y los bloques `server{}` en su configuración de sitio. Comprueba `sudo nginx -t` antes de recargar. El servidor interno escucha solo en `127.0.0.1:8000`; no publiques ese puerto. Nginx reemplaza X-Forwarded-For con la IP del cliente y Uvicorn confía únicamente en loopback.

```bash
sudo install -m 0644 /opt/hyperlogs/deploy/hyperlogs.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now hyperlogs
sudo systemctl status hyperlogs
curl --fail https://tu-dominio.example/api/health
```

Permite solo los accesos de red necesarios a SSH/HTTPS y los colectores que hayas configurado. El ejemplo Nginx agrega compresión y rate limit de login; las cookies de producción tienen Secure, HttpOnly y SameSite=Strict. No se usa modo reload. Los procesos tienen límites de concurrencia/memoria y permisos reducidos.

## 5. Respaldar y restaurar

Instala `hyperlogs-backup.service` y `.timer`, recarga systemd y activa `hyperlogs-backup.timer`. El horario se define en UTC y el nombre contiene fecha UTC; el comando no imprime contraseñas. Archivos con permisos `0600` en el directorio privado del servicio.

El respaldo usa SQLite Backup API para incorporar cambios confirmados del WAL; no copies solo la base abierta. Conserva además una copia **fuera de ese equipo**, con cifrado y retención definidos por tu organización. El timer local no implementa esa copia externa ni borrado automático.

Para restaurar una copia propia y confiable: detén el servicio, extrae el archivo en un directorio de revisión, verifica el SHA-256 de la base contra `manifest.json`, prueba `PRAGMA integrity_check`, preserva la instalación anterior y reemplaza la base y `lab/` con el servicio detenido. No reutilices `-wal`/`-shm` de otra base. Ajusta propiedad/permisos y reinicia. El inicio invalida sesiones anteriores. Los tokens de fuente del respaldo corresponden a su fecha; rota los que se hayan comprometido o cambiado desde entonces.

## 6. Antes de permitir usuarios reales

- Verifica login/logout, cookie Secure, recarga de sesión y protección CSRF sobre tu HTTPS real.
- Comprueba que demo, Swagger y acciones de laboratorio están desactivados.
- Registra al menos una fuente real y verifica fecha, procedencia, cola y alertas.
- Comprueba un respaldo y restauración en un entorno separado.
- Mide volumen de eventos, tiempo de consulta y espacio de disco con tu carga; 4 GB de RAM no garantizan cualquier volumen.
- Vigila disco y errores; define archivo/retención. No se borran evidencias automáticamente.

## Límites honestos

La API/web puede operar como un SOC pequeño de una instancia. No es una certificación, una prueba de penetración independiente ni un reemplazo completo de un SIEM empresarial. No se ha verificado systemd/Nginx/TLS en un host Linux real durante esta revisión. No incluye MFA, SSO, alta disponibilidad ni contención real de dispositivos. La cadena SHA-256 detecta alteraciones parciales; un administrador con control total del disco podría reconstruirla. Los backups/checkpoints externos son esenciales para anclar evidencias.

## Habilitar descubrimiento LAN

Antes de iniciar el servicio, configura `HYPERLOGS_DISCOVERY_NETWORKS` en `/etc/hyperlogs/hyperlogs.env` con las redes privadas del centro, por ejemplo `192.168.2.0/24` si coincide con su red real. Puedes dejarlo vacío para desactivar escaneos. Instala `iputils-ping` desde los repositorios de Debian y verifica conectividad desde la cuenta `hyperlogs`. Reinicia `hyperlogs.service`. Desde **Descubrir red**, el administrador inicia el escaneo y registra los equipos encontrados. La instalación de agentes y sus permisos siguen siendo necesarios. Consulta TECNICA.md para restricciones, puertos y tratamiento de DHCP.
