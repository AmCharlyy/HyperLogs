# Despliegue de una instancia en Debian/Linux

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
