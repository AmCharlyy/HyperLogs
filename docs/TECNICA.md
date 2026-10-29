# Arquitectura, datos y políticas

## Flujo

Agente / aplicación / puente RFC 5424 → HTTPS `POST /api/ingest` → validación de fuente → normalización y redacción → SQLite WAL → reglas → alertas → expedientes → solicitud SOAR → CISO → ejecución/verificación/reversión del sandbox → auditoría.

El navegador recibe solo datos y una prueba CSRF en memoria. La sesión opaca reside en una cookie HttpOnly; el servidor almacena su SHA-256 y expiración. Expira a las 8 horas o al reinicio del servidor. Logout, cambio/restablecimiento de contraseña y cambios administrativos revocan sesiones.

## Modelo

- `users`, `sessions`: identidad, rol, estado activo y sesión.
- `sources`: tipo, procedencia, hash de token y última muestra.
- `events`: UTC, emisor, IP, usuario, clasificación, severidad original, riesgo, payload normalizado, SHA-256 y external_id opcional.
- `alerts`: regla, origen, prioridad y referencias a hasta 200 eventos recientes.
- `incidents`, `notes`: responsable, estado, causa, impacto, riesgo residual y cronología.
- `runs`, `controls`: solicitud, autorización, resultado y reversión privada. El contenido para revertir no se exporta ni se entrega al navegador.
- `audit`: decisiones y acciones encadenadas mediante SHA-256.

El riesgo es una puntuación de reglas, no una probabilidad de ataque. Syslog conserva 0–7 por separado. Eventos críticos por severidad tienen riesgo base 70, otros 15; cambios de configuración se elevan a 85. Las simulaciones usan 85. Las alertas se contextualizan por regla, fuente y origen.

## Ingesta

```json
{
  "events": [{
    "external_id": "host-log-record-123",
    "time": "2026-10-27T18:30:00-06:00",
    "kind": "login_failed",
    "user": "cuenta-de-prueba",
    "src_ip": "192.168.10.20",
    "dst_ip": "192.168.10.10",
    "category": "authentication",
    "code": "4625",
    "description": "Intento de autenticación fallido",
    "syslog_severity": 4,
    "metrics": {"cpu": 18, "memory": 36, "disk": 22}
  }]
}
```

Hasta 200 eventos por solicitud, cuerpo máximo 1 MiB. Las IP se validan, las fechas deben indicar zona y no exceder 5 minutos en el futuro. `external_id` deduplica por fuente. Su valor debe permanecer estable en una retransmisión y ser único por evento real. Los agentes no pueden establecer `source_id`, `risk` ni `simulated`; la procedencia se toma del registro de fuente. El campo `authorized` no suprime cambios reportados por fuentes: en esta versión se investiga conservadoramente.

Solo cpu/memory/disk, finitos entre 0 y 100. El receptor conserva la última muestra no vacía. Patrones conocidos de contraseña/token/Bearer se redactan antes de guardar/hash; esto es defensa adicional, no permiso para enviar secretos. Filtra esos datos en la fuente.

## Reglas SIEM

| ID | Condición | Alcance |
|---|---|---|
| R01 | 5 fallos en 120 s | Misma fuente y origen |
| R02 | Login exitoso fuera de 07:00–20:00 | Horario fijo UTC−6 del laboratorio |
| R03 | Configuración modificada | Se presume no autorizada hasta investigar |
| R04 | 3 denegaciones seguidas de acceso administrativo en 300 s | Misma fuente y origen |

Los lotes se ordenan por fecha. La correlación se ejecuta a la llegada; no hace reprocesamiento global de históricos fuera de orden. La política de horario corresponde al laboratorio y debe configurarse en código si tu organización opera en otra zona. Una alerta abierta acumula referencias recientes; los eventos originales no se modifican. No se implementa aprendizaje automático ni se atribuyen porcentajes de probabilidad.

## Analítica

Una consulta agrupada obtiene volumen/riesgo por día UTC. Promedio y desviación de días completos; estimación del día siguiente con promedio móvil de siete días. Señala un aumento si supera media + 3σ, con σ mínimo 1 y al menos siete días completos con datos. El día actual es parcial y los datos sintéticos están contabilizados explícitamente. La estimación no se presenta si no hay línea base suficiente.

## SOAR suministrado

PB01: bloqueo lógico de IP durante cinco minutos. PB02: restauración atómica del archivo `data/lab/service.conf` a su referencia. PB03: aislamiento lógico de la fuente en el sandbox. Se requieren solicitud de admin/SOC 2 y autorización de otra cuenta CISO. Ejecución y reversión quedan registradas; los fallos también. Una reversión de archivo no sobrescribe modificaciones posteriores. El sandbox no ejecuta comandos de shell ni modifica cuentas, procesos o firewall del host. `GET /api/lab/access` permite inspeccionar el control lógico; no protege por sí mismo otros servicios externos.

Producción desactiva estas acciones por defecto. Una plataforma en producción puede conservar SIEM, investigación, analítica y auditoría sin habilitar contención de laboratorio.

## Operación e integridad

Un proceso API. Conexiones SQLite con foreign_keys y busy_timeout; WAL. Serialización de escrituras/acciones con lock local. Reportes en streaming mediante otra transacción de lectura; hasta 100 000 filas por tabla, con metadatos de truncación. CSV escapa fórmulas. Las exportaciones se auditan y nunca incluyen hashes de contraseñas, hashes de tokens ni material de reversión.

La verificación de auditoría recorre la cadena, no la carga completa en memoria. En instalaciones grandes, su costo crece con la historia; archiva y ancla periódicamente reportes fuera del servidor. La aplicación no purga automáticamente registros vinculados a evidencia. Define archivo y retención antes de crecer.

## Cliente y rendimiento

React carga la escena 3D de forma diferida. Su render limita aproximadamente a 30 fps, respeta movimiento reducido, pausa fuera de pantalla/pestaña y reutiliza sombras estáticas. Las etiquetas solo actualizan React cuando cambian sus posiciones. Sin dependencias de fuentes o fotografías externas. La API agrupa históricos y cuenta fuentes sin consultas por equipo. El cliente evita consultas idénticas simultáneas, cancela búsquedas antiguas y muestra desconexión/expiración.

El UI conserva la estética aprobada. Formularios con etiquetas, diálogos con foco atrapado y restaurado, Escape, tablas navegables por teclado y mensajes de error. Las tablas amplias tienen desplazamiento horizontal en móvil; no se afirma conformidad WCAG integral sin una auditoría independiente.

## Descubrimiento de activos en la LAN

### Incorporación asistida de Windows

El administrador genera un código aleatorio de 60 bits, visible durante diez minutos y canjeable una sola vez. `HyperLogsSetup.exe` presenta nombre, IP y versión del equipo a `POST /api/enrollments/claim`; el servidor crea la fuente real y devuelve su token únicamente en esa respuesta. Los intentos fallidos se limitan por IP y quedan auditados. En Windows, el token se cifra con DPAPI en ámbito de máquina y su archivo queda restringido a SYSTEM y al grupo local de administradores. La tarea de inicio ejecuta `HyperLogsAgent.exe`; no instala control remoto ni acepta órdenes desde el servidor.

La construcción produce dos binarios: la interfaz elevada `HyperLogsSetup.exe` y el recolector sin interfaz `HyperLogsAgent.exe`. Las pruebas automatizadas usan directorios temporales y planes `dry_run`; no registran tareas ni cambian permisos del host.

La consola incluye **Descubrir red**. Un administrador inicia una búsqueda IPv4 de hasta 254 direcciones, en segundo plano, con progreso y auditoría. El servidor prueba ICMP y conexiones TCP a 22, 80, 443, 445 y 3389; no autentica, no lee banners ni ejecuta órdenes remotas. Las respuestas se conservan como inventario separado de las fuentes que envían eventos. Registrar abre el formulario de fuente con IP y tipo sugerido; el token y el agente completan la incorporación al monitoreo.

En el archivo de entorno del servidor define, con la red real del centro:

```ini
HYPERLOGS_DISCOVERY_NETWORKS=192.168.2.0/24
```

Puedes autorizar varias redes privadas separadas por comas. Solo se permiten bloques RFC1918 /16 o más pequeños; cada trabajo debe elegir una subred /24 a /30 contenida en la lista. Reinicia el servicio después de cambiarla. La instancia de desarrollo de esta computadora usa su Wi-Fi 192.168.2.0/24; esa dirección no debe asumirse en otro lugar. No se configura una red real por defecto en el paquete de producción.

Solo hay un trabajo simultáneo y un minuto mínimo entre inicios. Hasta 16 sondas se ejecutan en paralelo con tiempos de espera acotados. No requiere root; instala iputils-ping en Debian si falta ping. Si ICMP falla, se conserva la detección mediante los puertos TCP indicados. El servidor debe tener ruta y permisos de salida hacia los equipos. No expongas esa función a personas ajenas a la administración de la LAN.

La lista conserva primera y última detección; no afirma presencia actual. Un equipo que bloquea ICMP y los puertos probados puede no aparecer. VLAN, redes de invitados, aislamiento Wi-Fi y firewalls también limitan la visibilidad. No se identifica de forma confiable fabricante, MAC o sistema operativo; el tipo es una sugerencia editable. Una IP puede reasignarse por DHCP: para identidad duradera configura reservas y vincula agentes.

API: GET /api/discovery (inventario autenticado); POST /api/discovery/scan con {"network":"192.168.2.0/24"} (administrador y CSRF). Resultado 202; el cliente consulta el progreso cada dos segundos mientras el panel está abierto. Cerrar el panel no cancela el trabajo. Reiniciar el servidor interrumpe el trabajo activo pero conserva los activos ya guardados. El inventario queda en la misma base SQLite y se incluye en su respaldo.
