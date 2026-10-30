# Casos de prueba (CP-01 a CP-05)

Verificación de los criterios de aceptación de los requisitos (OE2).
Cada requisito RF/RNF tiene al menos un caso asociado.

| ID | Requisito | Entrada | Resultado esperado | Estado |
|----|-----------|---------|--------------------|--------|
| CP-01 | RF-01 | Conexión SSH al puerto 22/TCP con credenciales válidas | Acceso concedido; servicio disponible y operativo | Pendiente de ejecución |
| CP-02 | RF-02 | Seis intentos de autenticación fallidos desde una misma IP | 100 % de los intentos registrados en `auth.log` | Pendiente de ejecución |
| CP-03 | RF-03, RNF-01, RNF-04 | Ataque de fuerza bruta SSH que supera el umbral | Incidente clasificado en la taxonomía ANCI; IP bloqueada en <= 60 s; desfase de relojes <= 1 s | Pendiente de ejecución |
| CP-04 | RF-04 | Generación de la alerta temprana a partir del incidente | Plantilla de alerta temprana con 100 % de campos obligatorios completos | Pendiente de ejecución |
| CP-05 | RF-05, RNF-02 | Elaboración del reporte de actualización dentro del plazo | Plantillas completas; notificación en <= 180 min | Pendiente de ejecución |

> **RNF-03 (replicabilidad):** se verifica repitiendo CP-01 a CP-05 con tres
> personas ajenas a la dupla, sin asistencia.
