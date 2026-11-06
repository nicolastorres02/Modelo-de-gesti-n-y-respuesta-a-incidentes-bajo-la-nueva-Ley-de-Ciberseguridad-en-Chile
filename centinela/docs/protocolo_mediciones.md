# Protocolo de mediciones con Centinela (escenario E1)

Objetivo: medir en 15 ejecuciones independientes el tiempo de notificación (TTN)
y el tiempo de contención (TTC) con Centinela, y compararlos con los de la tesis:

- TTN de la condición modelo con runbook y redacción manual (Tabla N.º 17): 4,26 min.
- TTC de la condición base (Tabla N.º 15).

## Qué se mide

Todas las marcas de tiempo provienen del reloj de victima-02: `auth.log`,
`fail2ban.log` y el servidor de Centinela. No hay cronómetro manual.

| Métrica | Desde → hasta | Para qué |
|---|---|---|
| TTC | t0 (primer intento fallido) → bloqueo de Fail2ban | Confirmar que Centinela no retrasa la contención |
| TTN automático | Detección → alerta temprana generada | Tramo que automatiza Centinela |
| **TTN total** | t0 → alerta temprana generada | **Comparable con la Tabla N.º 17**, que incluye detección, análisis y clasificación, y redacción |
| Revisión | Detección → el operador abre el incidente | Tiempo humano de reacción a la alarma |
| Decisión | Detección → el delegado registra si es reportable | Tiempo humano completo hasta la decisión de reporte (DS 295, art. 3.º) |

## Preparación (una sola vez)

1. victima-02 con la última versión de Centinela instalada y el snapshot tomado.
2. Reloj sincronizado en victima-02: `timedatectl` debe indicar
   `System clock synchronized: yes`.
3. En Windows:
   - el buzón de laboratorio abierto (`herramientas\iniciar_buzon.bat`);
   - el panel abierto con sesión iniciada y **Activar sonido** pulsado.
4. Anotar la **fecha y hora de inicio** de la campaña: sirve para filtrar las
   ejecuciones en el análisis.
5. Las mismas condiciones del estudio:
   - Hydra con `-l root -P rockyou.txt -t 2 -W 5`;
   - jaula `sshd` con `maxretry = 5`, `findtime = 120` y `bantime = 120`;
   - el mismo operador en las 15 ejecuciones.

## Cada ejecución (repetir 15 veces)

| Paso | Dónde | Acción |
|---|---|---|
| 1 | victima-02 | Desbloquear Kali: `sudo fail2ban-client set sshd unbanip 192.168.58.133` (si responde 0, no estaba bloqueada) |
| 2 | — | **Esperar al menos 3 minutos desde el final de la ejecución anterior**: más que el `findtime` (120 s), para que los intentos de una ejecución no se mezclen con los de la siguiente |
| 3 | Kali | `hydra -I -l root -P /usr/share/wordlists/rockyou.txt -t 2 -W 5 ssh://192.168.58.132` |
| 4 | Kali | Cuando Hydra muestre errores de conexión (la IP fue bloqueada), detenerlo con **Ctrl + C** |
| 5 | Panel | Cuando suene la alarma, pulsar **Ver incidente** |
| 6 | Panel | En **¿Debe reportarse?**, revisar la propuesta, escribir la justificación y pulsar **Guardar evaluación** |
| 7 | Panel | Pulsar **Cerrar incidente**. Así, la ejecución siguiente crea un incidente nuevo y no se agrupa con este |
| 8 | Planilla | Anotar el número de ejecución, el ID del incidente y cualquier anomalía |

El operador debe actuar a su ritmo normal en los pasos 5 a 7: sin adelantarse a
la alarma y sin demorarse a propósito.

### Ejecuciones inválidas

Se descartan, se repiten y se registran con su motivo. El script de análisis
detecta solo los casos marcados con (*):

- Hydra encontró la contraseña: hubo acceso exitoso y el escenario es otro.
- Se perdió la conectividad, o el panel o Fail2ban no respondían.
- El incidente agrupó dos bloqueos porque no se cerró el anterior (*).
- El ataque empezó antes de 3 minutos desde el anterior.

## Planilla de registro

| # | Hora de inicio | Incidente | ¿Válida? | Observaciones |
|---|---|---|---|---|
| 1 | | | | |
| 2 | | | | |
| … | | | | |
| 15 | | | | |

## Al terminar

1. Panel → **Métricas** → **Descargar CSV**. Guardarlo como
   `C:\Users\nicol\TESIS\mediciones\metricas_centinela.csv`.
2. Ejecutar el análisis:

   ```
   python herramientas\analisis_mediciones.py C:\Users\nicol\TESIS\mediciones\metricas_centinela.csv --desde "AAAA-MM-DD HH:MM"
   ```

   Si se tienen los 15 valores individuales del TTN de la Tabla N.º 17 (columna
   `ttn_min` o `ttn_s`), agregar `--manual archivo.csv` para usar la U de
   Mann-Whitney en vez de la comparación contra la mediana.
3. Resultado, en la misma carpeta:
   - `resultados_mediciones.md`: tablas, pruebas estadísticas y cumplimiento de
     RNF-01, RNF-02 y RF-04 con IC de Wilson;
   - `ejecuciones_validas.csv`;
   - `figura_ttn.png` y `figura_ttc.png`.

El script aplica los mismos métodos de la sección 3.x de la tesis: mediana, RIC,
U de Mann-Whitney unilateral, correlación biserial de rangos, δ de Cliff e IC de
Wilson. Además se verificó que reproduce exactamente los resultados publicados del
TTC: U = 18,0; p = 4,75 × 10⁻⁵; r = 0,84.
