# Centinela: manual técnico

## 1. Arquitectura

```
                   victima-02 (Ubuntu)
 ┌──────────────────────────────────────────────────────────────────────┐
 │ auth.log  access.log ──► Fail2ban ──(Ban)──► iptables (contención)    │
 │                              │                                        │
 │                              └─ acción "centinela" ─► centinela ban   │
 │                                                        │              │
 │   parsers ─► clasificador ─► reportes (PDF) ─► db (SQLite) ◄──┐       │
 │                    │                 │                         │       │
 │                    ▼                 ▼                         │       │
 │              auditoria (SHA-256)  notificador (SMTP) ──► correo │       │
 │                                                                │       │
 │   servicio centinela-panel (Cheroot HTTPS :5000) ─ app (Flask) ┘       │
 │        └─ hilo vigilante: plazos legales y reintentos de correo        │
 └──────────────────────────────────────────────────────────────────────┘
                 ▲ HTTPS (TLS 1.2+)                  │ SMTP
          Navegador del operador               Buzón de laboratorio
     (panel.js: aviso, alarma, escritorio)     (Windows, herramientas/)
```

## 2. Módulos (`centinela/`)

| Módulo | Responsabilidad |
|---|---|
| `config.py` | Configuración por variables de entorno (`/etc/centinela/centinela.env`) |
| `parsers.py` | Lectura de `auth.log` (formatos syslog e ISO; `sshd` y `sshd-session`), `fail2ban.log` (Found/Ban, ráfagas por `findtime`, filtro por jaula) y `access.log` de Apache (firmas de Nikto, Gobuster, sqlmap…). Lee también el archivo rotado `.1` y usa el journal como respaldo |
| `taxonomia.py` | Transcripción de la Res. Ex. N.º 7/2025 (arts. 3.º y 4.º): 4 áreas, 11 efectos observables, 40 categorías |
| `clasificador.py` | Deduce el efecto observable desde la evidencia: intento contenido (sin efecto), fuerza bruta exitosa, exposición de `.git`/`.env`/respaldos/configuraciones |
| `significancia.py` | Criterios del DS 295/2024, art. 3.º (a–e); propuesta automática y validación de la decisión del delegado |
| `nucleo.py` | Flujo `procesar_ban` (evidencia → clasificación → registro o agrupación → alerta temprana → correo; idempotente), `evaluar` y `registrar_manual` |
| `reportes.py` | Campos de los 4 reportes según los arts. 5.º y 9 a 12 del DS 295, omisión de datos personales (art. 6.º), métricas TTD/TTC/TTN/TTR y PDF (reportlab) |
| `plazos.py` | Plazos del DS 295/2024 con sus reglas: informe final desde el envío de la alerta, plan de acción solo OIV, segundo reporte a 24 h solo con letra a), "no aplica" si no es reportable |
| `notificador.py` | Correo SMTP (sin cifrado, STARTTLS o SSL) con el PDF adjunto; registro de cada envío |
| `vigilante.py` | Hilo que cada 60 s avisa una vez por reporte por vencer o vencido, y reintenta correos fallidos |
| `seguridad.py` | Usuarios (hash scrypt), bloqueo por fuerza bruta, CSRF y cabeceras HTTP |
| `auditoria.py` | Bitácora encadenada con SHA-256, copia en `auditoria.log` y huellas de archivos |
| `estado.py` | Comprobaciones de salud del sistema |
| `app.py` | Panel Flask: rutas, sesión, API en vivo |
| `servidor.py` | Servidor de producción Cheroot con TLS e hilo vigilante |
| `cli.py` | Comandos `ban`, `panel`, `usuario`, `verificar`, `probar-correo`, `vigilar`, `exportar`, `demo` |
| `static/panel.js` | Cuenta regresiva, consulta en vivo cada 2 s, alarma Web Audio en bucle y notificaciones de escritorio |

## 3. Modelo de datos (SQLite, `/var/lib/centinela/centinela.db`)

| Tabla | Contenido |
|---|---|
| `incidentes` | IP, jaula, escenario (`E1`, `E2`, `manual`), clasificación (`impacto` = área, `categoria` = efecto observable, `subcategoria` = categoría), t0, conocimiento, contención, bloqueos (JSON), evidencia (JSON), `hash_evidencia`, detalle del escenario (incluye recursos expuestos), revisión del operador, `evaluacion` (JSON: criterios, decisión, importancia, justificación, usuario y fecha) |
| `reportes` | Cuatro por incidente: campos (JSON), primera generación (marca del TTN), envío, `folio` de la plataforma ANCI, ruta y `hash_pdf` |
| `notificaciones` | Envíos por correo por incidente y motivo (`incidente`, `escalamiento`, `plazo:<reporte>:<etapa>`), estado e intentos |
| `usuarios` | Nombre, hash scrypt de la contraseña, último acceso |
| `accesos_panel` | Intentos de inicio de sesión por IP (para el bloqueo por fuerza bruta) |
| `bitacora` | Registro de auditoría encadenado: `hash = SHA-256(hash_prev ‖ ts ‖ usuario ‖ acción ‖ incidente ‖ detalle)` |

Las bases creadas por versiones anteriores se migran solas al abrirse, sin perder datos.

## 4. Definición de las métricas

Corresponden a la Tabla N.º 6 de la tesis.

| Métrica | Desde → hasta | Fuente |
|---|---|---|
| TTD | t0 → detección (Ban) | auth.log / access.log y fail2ban.log |
| TTC | t0 → bloqueo (Ban) | auth.log / access.log y fail2ban.log |
| TTN | detección → alerta temprana generada | fail2ban.log y base de datos |
| TTR | detección → primera apertura del incidente en el panel | base de datos |

- **t0** es el primer intento fallido (o la primera petición) de la ráfaga que
  terminó en el bloqueo.
- Los intentos aislados separados por más de `findtime` no se consideran parte
  del ataque.
- Con `backend = systemd`, se usa la hora del intento que trae cada línea
  `Found`, no la hora en que Fail2ban la escribió.

## 5. Controles de seguridad

| Amenaza | Control |
|---|---|
| Intercepción del tráfico del panel | HTTPS (TLS 1.2+) con certificado de una autoridad local; HSTS |
| Acceso no autorizado al panel | Inicio de sesión obligatorio; contraseñas con hash scrypt (mínimo 10 caracteres); verificación de tiempo constante |
| Fuerza bruta contra el panel | 5 fallos en 10 min → IP bloqueada 10 min; cada intento queda auditado |
| CSRF | Token por sesión en todos los formularios POST; cookie `SameSite=Strict` |
| Robo de sesión | Cookie `HttpOnly` y `Secure`; expiración de 8 h |
| XSS y clickjacking | CSP sin scripts ni estilos incrustados; `X-Frame-Options: DENY`; escape automático de Jinja |
| Redirección abierta | El parámetro `siguiente` solo acepta rutas locales |
| Alteración de evidencia o reportes | Huellas SHA-256 de la evidencia y de los PDF; bitácora encadenada y verificable (`centinela verificar`) |
| Servicio comprometido | systemd con `NoNewPrivileges`, `ProtectSystem=full`, `ProtectHome`, `PrivateTmp` y `UMask=0077`; datos y configuración con permisos 700/600 |
| Fallas silenciosas | Página de Estado del sistema; errores de procesamiento auditados; reintento de correos |

## 6. Integración con Fail2ban

- `/etc/fail2ban/action.d/centinela.conf`: `actionban` ejecuta
  `centinela ban --ip <ip> --jail <name>` en segundo plano, para no retrasar el bloqueo.
- `/etc/fail2ban/jail.d/centinela.local`:
  - agrega la acción a `sshd`, conservando `maxretry = 5`, `findtime = 120` y
    `bantime = 120` de `jail.local`;
  - define la jaula `centinela-escaneo-web`: 20 errores 4xx en 60 s, `backend = auto`.
- `/etc/fail2ban/filter.d/centinela-escaneo-web.conf`: cuenta las respuestas
  400, 401, 403, 404 y 405 en `access.log`.

## 7. Configuración (`/etc/centinela/centinela.env`)

| Variable | Uso |
|---|---|
| `CENTINELA_DATA` | Datos (base, PDF, `auditoria.log`) |
| `CENTINELA_SECRET_KEY` | Firma de las sesiones (aleatoria) |
| `CENTINELA_PANEL_HOST`, `_PUERTO`, `CENTINELA_URL_PANEL` | Panel y enlace en los correos |
| `CENTINELA_TLS_CERT`, `_KEY`, `_CA` | Certificados HTTPS |
| `CENTINELA_JAULAS` | Jaulas comprobadas en Estado |
| `CENTINELA_AGRUPAR_MIN` | Ventana de agrupación de reincidencias (30) |
| `CENTINELA_OIV` | 1 → la institución es operador de importancia vital (plan de acción; segundo reporte a 24 h si se marca la letra a) |
| `CENTINELA_SERV_ESENCIAL` | Supuesto mientras no se evalúa el incidente: 1 → segundo reporte a 24 h (el más exigente) |
| `CENTINELA_ORG`, `_ORG_RUT`, `_ORG_DIRECCION`, `_ORG_CORREO` | Institución afectada (DS 295, art. 5.º a) |
| `CENTINELA_RESPONSABLE`, `_DELEGADO_CORREO`, `_DELEGADO_TELEFONO` | Delegado de ciberseguridad (art. 5.º b) |
| `CENTINELA_SMTP_*`, `CENTINELA_CORREO_*` | Correo |
| `CENTINELA_LOGIN_MAX_FALLOS`, `_VENTANA_MIN`, `_BLOQUEO_MIN` | Protección del inicio de sesión |

Después de cambiar la configuración: `sudo systemctl restart centinela-panel`.

## 8. Pruebas

`python -m pytest`. Son 50 pruebas automáticas y cubren:

- la lectura de los formatos de bitácora, los logs rotados y el filtro por jaula;
- la taxonomía completa de la Res. Ex. 7/2025 y la clasificación por efecto
  observable: intento contenido, fuerza bruta exitosa, exposición de `.git`;
- la detección de recursos sensibles en `access.log`;
- la evaluación de efecto significativo: propuesta, validación, efecto sobre los
  plazos y reinicio al escalar;
- los plazos: informe final desde el envío de la alerta, OIV/no OIV, 24/72 h y
  "no aplica";
- el registro manual de incidentes y el folio de la ANCI;
- la omisión de datos personales en los reportes (art. 6.º);
- la agrupación de reincidencias, la idempotencia y el cambio de zona horaria;
- la ráfaga de Found;
- la integridad: bitácora y PDF alterados;
- la migración de bases antiguas;
- el correo: adjunto, reintento y envío SMTP real al buzón de laboratorio;
- el vigilante de plazos;
- la seguridad: inicio de sesión, bloqueo por fuerza bruta, CSRF, cabeceras,
  cookies y redirección abierta;
- el funcionamiento del panel y de la alarma;
- la aplicación instalable: manifiesto, íconos y un service worker que no guarda
  datos de incidentes en el equipo.

El panel funciona como aplicación web instalable (PWA): `/manifest.webmanifest`
y `/sw.js`. El service worker no usa caché; solo muestra un aviso si el servidor
no responde. `herramientas/acceso_directo/` crea un acceso directo de Windows que
abre el panel con `msedge --app=…`, después de instalar la CA en el almacén del
usuario.

## 9. Trazabilidad normativa

| Norma | Exigencia | Dónde la cumple Centinela |
|---|---|---|
| Ley 21.663, art. 9.º; DS 295, art. 2.º | Reportar incidentes que puedan tener efecto significativo | `significancia.py`, sección "¿Debe reportarse?" |
| Ley 21.663, art. 27; DS 295, art. 3.º | Criterios a) a e) e importancia (personas, duración, extensión) | Formulario de evaluación; campo `evaluacion` |
| DS 295, art. 4.º | Las mantenciones planificadas no son incidentes | Motivo "Mantención planificada" |
| DS 295, art. 5.º | Contenido mínimo de los informes (letras a–i) | `reportes.CAMPOS` |
| DS 295, art. 6.º | Omitir datos personales (la IP no lo es) | `reportes.anonimizar` |
| DS 295, art. 8.º | Envío por la plataforma de la ANCI | "Marcar enviado" con folio |
| DS 295, arts. 9 a 12 | Plazos y contenido de cada reporte | `plazos.plazos_incidente` |
| DS 295, art. 13 | Informe parcial si el incidente no se gestionó en 15 días | Aviso en el detalle del incidente |
| Res. Ex. 7/2025, arts. 2.º a 4.º | Clasificar por efecto observable | `taxonomia.py`, `clasificador.py`, registro manual |

## 10. Limitaciones conocidas

- La autoridad de certificación es local. Cada navegador debe instalar
  `centinela-ca.crt` una vez para evitar la advertencia.
- Los navegadores exigen un clic del usuario antes de permitir sonido y
  notificaciones.
- El envío a la ANCI se registra manualmente ("Marcar enviado", con folio):
  Centinela genera los reportes, pero la plataforma oficial de la ANCI no ofrece
  una interfaz pública para enviarlos de forma automática.
- La detección automática cubre los escenarios del estudio (SSH y web). Los demás
  tipos de incidente se registran manualmente con la taxonomía completa.
- La evaluación de efecto significativo es una propuesta: la decisión y su
  responsabilidad son del delegado de ciberseguridad.
- La omisión de datos personales reemplaza las cuentas nominativas conocidas. El
  texto libre que escribe el operador debe redactarse sin datos personales.
- La bitácora encadenada detecta alteraciones de registros individuales. Un
  atacante con acceso de root podría recalcular la cadena completa;
  `auditoria.log` sirve como copia independiente para contrastar.
