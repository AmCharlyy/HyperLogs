# HyperLogs

Plataforma SOC local: React, FastAPI y SQLite. Incluye login por roles, fuentes autenticadas, normalización y búsqueda, cuatro reglas SIEM, expedientes, analítica descriptiva y tres playbooks **de laboratorio**. Interfaz en español.

## Ejecutar en desarrollo

Python 3.12+ y Node.js 22+ para compilar. El servidor desplegado no necesita Node.

```bash
python -m venv .venv
# Linux
source .venv/bin/activate
# Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
npm ci
npm run build
python -m backend.manage bootstrap
python -m uvicorn backend.app:app --host 127.0.0.1 --port 8000 --no-server-header
```

Abre `http://localhost:8000`. El bootstrap solicita la contraseña por terminal y no la imprime. No hay credenciales predeterminadas. Cada reinicio del servidor invalida las sesiones; los eventos y usuarios permanecen.

Para la demostración, define **antes de iniciar** `HYPERLOGS_DEMO=1`, utiliza una base separada mediante `HYPERLOGS_DATA` y conserva el enlace a loopback. Se crean seis fuentes sintéticas y un histórico rotulado como simulado. No habilites este modo detrás de un proxy público.

Desarrollo con recarga de interfaz: `npm run dev` y API en 8000. La configuración de Vite redirige `/api` a la API; las cookies permanecen en el mismo origen del navegador.

## Producción

El modo producción es explícito y falla al iniciar si habilitas el demo o no configuras origen HTTPS y hosts autorizados. Consulta [la guía de despliegue](docs/PRODUCCION.md). Se incluyen servicios systemd, Nginx, respaldo diario y dependencias Python bloqueadas.

**Estado del alcance:** aplicación preparada para un despliegue de una instancia con volumen moderado. No se ha instalado ni medido en tu Linux real. Las acciones SOAR suministradas son un sandbox, no administran Windows, reglas reales de firewall ni aíslan físicamente equipos. En producción están desactivadas por defecto. Una integración de contención real requiere su propio conector, permisos, pruebas y reversión.

## Conectar fuentes reales

1. Inicia sesión como administrador, abre **Configuración → Conectar fuente**.
2. Registra Windows, Linux, aplicación o Syslog. Elige procedencia real o sintética correctamente.
3. Guarda el token presentado una vez. Configúralo únicamente en el agente, nunca en el frontend.
4. Para el agente, copia `agents/agent-config.example.json` a una ubicación privada y edita servidor y token.

```bash
pip install -r agents/requirements.txt
python agents/agent.py --config /ruta/privada/agent-config.json --once
# Sin --once, continúa cada 30 segundos.
```

Linux/Windows: CPU, memoria, disco y cambios SHA-256 en archivos seleccionados. Windows: eventos Security 4624/4625/4720/4732/1102 si existen permisos y auditoría habilitada. Linux: autenticación SSH desde el archivo `auth_log` configurado. El agente no recibe órdenes remotas ni transmite el contenido de archivos vigilados. Tiene cola local persistente; las retransmisiones utilizan `external_id` para no duplicar eventos.

Syslog: `python agents/syslog_bridge.py --config /ruta/privada/syslog.json`. Usa una fuente y un archivo de estado distintos de los del agente del host. El receptor escucha **solo en 127.0.0.1:5514 UDP**. `deploy/rsyslog-hyperlogs.conf` contiene un ejemplo de reenvío local RFC 5424. Para tráfico remoto, recibe con rsyslog/TLS y reenvía localmente; no expongas este puente UDP a Internet.

Para aplicaciones propias, envía `POST /api/ingest` con `X-Source-Token` y `{"events":[...]}`. Campos admitidos y límites en [documentación técnica](docs/TECNICA.md). La web no conoce los tokens de agentes una vez cerrado su diálogo de creación/rotación.

### Asistente Windows

En **Conectar fuente → Windows**, el administrador puede generar un código temporal de un solo uso. Compila los ejecutables con `powershell -ExecutionPolicy Bypass -File agents/build_windows.ps1` y entrega juntos `dist/HyperLogsSetup.exe` y `dist/HyperLogsAgent.exe`. El asistente identifica el equipo, canjea el código, protege la credencial mediante DPAPI, restringe la carpeta local a SYSTEM/Administradores y crea la tarea `HyperLogs Agent` para iniciar con Windows. El código vence en diez minutos y nunca contiene el token permanente.

## Roles y respuesta

| Rol | Alcance |
|---|---|
| Administrador TI | Usuarios, fuentes, investigación, solicitudes y ejecución de respuestas autorizadas |
| SOC 1 | Consulta, alertas y apertura de expedientes |
| SOC 2 | Investigación, solicitud, ejecución y reversión de respuestas |
| CISO | Consulta y aprobación/rechazo de solicitudes |
| Auditor | Consulta y exportación; sin mutaciones de negocio |

Administrador puede crear cuentas y asignar roles; por ello es un rol de confianza. El solicitante de una respuesta no puede aprobarla. El backend valida permisos, no solo oculta botones. Cambiar rol, desactivar una cuenta o restablecer contraseña revoca sus sesiones.

## Validación

```bash
pip install -r requirements-dev.txt
python -m pytest tests -q
npm ci
npm run build
npm audit
# En un entorno de auditoría separado:
pip install pip-audit
python -m pip_audit -r requirements.lock
```

Resultados y límites: [REVISIÓN](docs/REVISION.md). Los resultados de escáneres dependen de sus bases de advisories y no certifican ausencia de vulnerabilidades.

## Descubrimiento de red

La opción **Descubrir red** encuentra activos que responden desde el servidor. Configura `HYPERLOGS_DISCOVERY_NETWORKS` con las subredes privadas autorizadas y reinicia el servicio. Registra los resultados y conecta sus agentes para recibir eventos y métricas. Consulta las condiciones y limitaciones en [TECNICA.md](docs/TECNICA.md#descubrimiento-de-activos-en-la-lan).

## Documento técnico

Consulta [el PDF técnico desarrollado](docs/HyperLogs-Documento-Tecnico.pdf), con objetivos, SRS, diagramas de componentes, despliegue, flujo de eventos y modelo de datos; incluye gobernanza, SIEM, SOAR, analítica, descubrimiento LAN, instalación, recuperación, revisión y trazabilidad académica.
