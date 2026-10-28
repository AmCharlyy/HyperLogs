# Revisión de HyperLogs 1.1.0

Fecha: 27 de octubre de 2026. Alcance: código React/FastAPI, SQLite, agentes, interfaz y configuración de despliegue. Revisión local; no constituye certificación ni prueba de penetración externa.

## Resultado

Se corrigieron los hallazgos siguientes y se preparó un despliegue de una instancia Linux mediante Nginx, HTTPS y systemd. No se ha desplegado ni validado el servicio en el equipo Linux del centro. Las automatizaciones actúan exclusivamente en el sandbox; no bloquean un firewall ni aíslan físicamente otras computadoras.

## Seguridad: hallazgos corregidos

| ID | Prioridad | Hallazgo y corrección | Evidencia |
|---|---|---|---|
| SEC-01 | Alta | Sesiones expuestas al JavaScript: sustituidas por cookie HttpOnly, SameSite Strict, Secure en producción y prueba CSRF en memoria. Revocación por contraseña, desactivación o cambio de rol. | backend/app.py:196; src/api.js:1; pruebas de sesión, CSRF y revocación |
| SEC-02 | Alta | Configuración de laboratorio utilizable por error: producción rechaza demostración, exige origen HTTPS y hosts explícitos; laboratorio desactivado por defecto. Sin contraseña predeterminada; alta local interactiva. | backend/security.py:19; backend/manage.py:13; prueba de proceso de producción aislado |
| SEC-03 | Alta | Acciones sin límites suficientemente explícitos: comprobación de rol en servidor, solicitud/aprobación separadas, operaciones limitadas al sandbox y rechazo de reversión sobre cambios posteriores. Contenido privado de recuperación excluido de las respuestas. | backend/app.py; pruebas de los tres ciclos de playbook, fallo parcial y conflicto de recuperación |
| SEC-04 | Alta | Fuentes y entradas no confiables: credenciales por fuente con rotación/revocación, procedencia determinada en servidor, validación de IP/fechas/métricas, deduplicación y redacción de secretos reconocibles. | backend/app.py:449; backend/security.py:41; pruebas de ingestión y tokens |
| SEC-05 | Media | Frontera HTTP insuficiente: hosts/origen, CSP, tipos JSON, límite de cuerpo y tiempo, cabeceras y rate limit de acceso. Contraseñas PBKDF2-SHA256 de 600000 iteraciones y actualización de hashes anteriores. | backend/security.py:52; backend/app.py:57; deploy/nginx.conf |
| SEC-06 | Media | Exportación y respaldo: neutralización de fórmulas CSV, consultas parametrizadas, límites declarados y respaldo consistente mediante SQLite Backup API con manifiesto SHA-256 y permisos privados. | backend/manage.py:48; tests/test_operations.py |

La redacción reconoce patrones comunes: no garantiza eliminar cualquier dato sensible de un log. La cadena hash permite detectar alteraciones internas; un administrador con escritura total puede reescribir la cadena. Para mayor garantía se requiere una copia externa inmutable o anclaje externo.

## Diseño, errores y fluidez

Se recorrieron login, consola, búsqueda, alertas, expediente, analítica, SOAR, auditoría, configuración y cuenta en navegador. Se verificó login y modal a 390 px sin desbordamiento horizontal. Se conservaron el diseño blanco, jerarquía visual y animación ambiental aprobados.

Correcciones: errores de conexión visibles con reintento; expiración vuelve a login; solicitudes duplicadas agrupadas y búsqueda anterior cancelada; protección frente a respuestas antiguas al cambiar sesión/rol; modales con foco, Escape y retorno de foco; controles según permisos; gráficos sin series ficticias y baseline insuficiente señalado.

La escena 3D se carga después de autenticar, limita aproximadamente a 30 fps y pausa fuera de pantalla o pestaña inactiva; respeta movimiento reducido y reutiliza sombras. Se sustituyó una constante obsoleta de sombras de Three.js y se asegura repintado tras redimensionar. JavaScript inicial: unos 315 kB, 93 kB gzip; escena diferida: unos 588 kB, 151 kB gzip. Vite advierte del tamaño de este chunk diferido; no impide compilar. El CSS conserva capas de iteraciones visuales y queda como deuda de mantenimiento, sin bloqueo funcional observado.

## Verificación reproducible

- 34 pruebas pytest aprobadas; cero fallos. Incluyen roles, reglas R01–R04, tres playbooks, auditoría alterada, exportación, backup WAL, agentes y configuración de producción aislada.
- Compilación de producción Vite correcta.
- npm audit: cero vulnerabilidades conocidas en el momento de la consulta.
- pip-audit: cero vulnerabilidades conocidas en las 13 dependencias runtime fijadas.
- Dos avisos de obsolescencia del entorno de pruebas (integración AnyIO/pytest y TestClient/httpx); no son fallos de ejecución de producción.
- Evidencias de pruebas y auditorías: docs/validation/.

Medición local con 5000 eventos sintéticos, Windows y ASGI TestClient: medianas de lectura entre 15 y 33 ms; p95 entre 17 y 36 ms. La medición excluye red y TLS y no es una garantía de capacidad en Linux o con hardware de 4 GB. La recepción del lote tardó 1.278 segundos en esa prueba aislada.

## Antes de prestar servicio real

Seguir PRODUCCION.md: configurar dominio y certificado válidos, usuario de servicio, directorio privado de datos, administrador propio y un solo worker. Ejecutar nginx -t, comprobar systemd/HTTPS y restaurar un respaldo de ensayo. Registrar y probar las fuentes reales con sus permisos de sistema; su colección Windows/Linux y el puente rsyslog no se han probado en los equipos del centro. La demostración local no representa esas conexiones.

Configurar retención de eventos y copias externas según el uso real; actualmente no hay purga automática ni política de retención organizacional. SQLite y la coordinación de auditoría están diseñados para una instancia con un proceso. No usar múltiples workers ni varias réplicas sin rediseñar esa coordinación. No se incluye MFA/SSO ni operación distribuida de alta disponibilidad.
