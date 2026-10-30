# Runbook de respuesta a incidentes — Modelo ANCI (Ley 21.663)

Procedimiento operativo estandarizado para contención y reporte de incidentes
de ciberseguridad, alineado con **ISO/IEC 27035-1:2023** y **NIST SP 800-61 Rev. 3**,
y con los plazos del **DS 295/2024** y la taxonomía de la **Res. Ex. N.º 7/2025**.

## Roles
- **Operador de seguridad:** ejecuta el procedimiento y completa los reportes.
- **Responsable de notificación ANCI:** valida y envía los reportes a la ANCI.

## Fase 1 — Preparación
- Parámetros de Fail2ban fijados (`config/fail2ban/jail.local`).
- Relojes sincronizados por NTP, desfase <= 1 s (RNF-04).
- Plantillas de reporte disponibles (`/plantillas`).

## Fase 2 — Detección y análisis
1. Monitorear `auth.log` y `fail2ban.log`.
2. Ante patrón de fuerza bruta SSH: registrar **t0** (primer intento fallido).
3. Clasificar el incidente con la lista de verificación (`/taxonomia`).
   - Categoría esperada E1: *Uso no autorizado / intento de acceso no autorizado*.

## Fase 3 — Contención (automatizada)
- Fail2ban bloquea la IP atacante al superar `maxretry` dentro de `findtime`.
- **Criterio (RNF-01):** IP bloqueada en <= 60 s desde t0.
- Verificar con una conexión rechazada desde la IP atacante.
- Reset entre pruebas: `scripts/reset_estado.sh`.

## Fase 4 — Notificación (manual, guiada)
Completar y enviar a la ANCI dentro de los plazos legales:

| Reporte | Plazo (DS 295/2024) | Plantilla |
|---|---|---|
| Alerta temprana | <= 3 horas desde el conocimiento | `plantillas/alerta_temprana.md` |
| Actualización / 2.º reporte | <= 72 h (24 h si es OIV) | `plantillas/segundo_reporte.md` |
| Plan de acción | <= 7 días | `plantillas/plan_de_accion.md` |
| Informe final | <= 15 días | `plantillas/informe_final.md` |

- **Criterio (RNF-02):** alerta temprana completada en <= 180 min desde la detección.

## Fase 5 — Post-incidente
- Registrar lecciones aprendidas y ajustar parámetros/runbook.
- Archivar evidencias (logs sin modificar) con el id de la ejecución.
