# Resultados de las mediciones con Centinela (escenario E1)

Archivo: `metricas_centinela.csv` · ejecuciones válidas: **15** · descartadas: 7 · generado el 05-11-2026 23:27

## Ejecuciones

| # | Incidente | t0 | TTC (s) | TTN automático (s) | TTN total (s) | Revisión (s) | Decisión (s) | Campos sin completar |
|---|---|---|---|---|---|---|---|---|
| 1 | INC-20261105-008 | 2026-11-05 21:25:12 | 15,9 | 0,63 | 16,5 | 56,4 | 112,0 | 0 |
| 2 | INC-20261105-009 | 2026-11-05 22:00:49 | 15,4 | 0,27 | 15,6 | 62,7 | 122,6 | 0 |
| 3 | INC-20261105-010 | 2026-11-05 22:16:09 | 16,0 | 0,21 | 16,2 | 29,0 | 111,1 | 0 |
| 4 | INC-20261105-011 | 2026-11-05 22:20:12 | 9,5 | 0,36 | 9,8 | 28,4 | 58,0 | 0 |
| 5 | INC-20261105-012 | 2026-11-05 22:27:26 | 16,6 | 0,25 | 16,8 | 9,7 | 48,4 | 0 |
| 6 | INC-20261105-013 | 2026-11-05 22:32:42 | 9,2 | 0,32 | 9,5 | 59,6 | 107,9 | 0 |
| 7 | INC-20261105-014 | 2026-11-05 22:38:28 | 17,3 | 0,28 | 17,5 | 63,3 | 107,3 | 0 |
| 8 | INC-20261105-015 | 2026-11-05 22:43:30 | 8,9 | 0,26 | 9,2 | 12,4 | 40,9 | 0 |
| 9 | INC-20261105-016 | 2026-11-05 22:47:33 | 16,3 | 0,36 | 16,6 | 59,5 | 85,3 | 0 |
| 10 | INC-20261105-017 | 2026-11-05 22:53:14 | 9,6 | 0,26 | 9,8 | 27,9 | 52,1 | 0 |
| 11 | INC-20261105-018 | 2026-11-05 22:58:39 | 16,6 | 0,25 | 16,8 | 53,9 | 80,5 | 0 |
| 12 | INC-20261105-019 | 2026-11-05 23:05:35 | 9,1 | 0,27 | 9,4 | 65,4 | 119,3 | 0 |
| 13 | INC-20261105-020 | 2026-11-05 23:11:13 | 15,6 | 0,37 | 15,9 | 23,2 | 71,6 | 0 |
| 14 | INC-20261105-021 | 2026-11-05 23:18:34 | 9,0 | 0,25 | 9,3 | 73,3 | 120,8 | 0 |
| 15 | INC-20261105-022 | 2026-11-05 23:21:24 | 17,3 | 0,30 | 17,6 | 11,1 | 46,9 | 0 |

## Estadística descriptiva

| Métrica | n | Mediana | RIC | Mínimo | Máximo | Media | DE |
|---|---|---|---|---|---|---|---|
| TTC (s) | 15 | 15,57 | 9,33–16,41 | 8,93 | 17,32 | 13,48 | 3,64 |
| TTN automático: detección → alerta (s) | 15 | 0,27 | 0,25–0,34 | 0,21 | 0,63 | 0,31 | 0,10 |
| TTN total: t0 → alerta (s) | 15 | 15,94 | 9,66–16,72 | 9,18 | 17,62 | 13,79 | 3,66 |
| TTN total: t0 → alerta (min) | 15 | 0,27 | 0,16–0,28 | 0,15 | 0,29 | 0,23 | 0,06 |
| Detección → revisión del operador (s) | 15 | 53,85 | 25,56–61,18 | 9,73 | 73,35 | 42,38 | 22,61 |
| Detección → decisión del delegado (s) | 15 | 85,34 | 55,04–111,57 | 40,87 | 122,57 | 85,65 | 30,53 |
| t0 → decisión del delegado (s) | 15 | 101,60 | 66,20–127,54 | 49,80 | 137,94 | 99,12 | 30,79 |
| t0 → decisión del delegado (min) | 15 | 1,69 | 1,10–2,13 | 0,83 | 2,30 | 1,65 | 0,51 |

## TTN: Centinela frente al runbook con redacción manual (Tabla N.º 17)

- Mediana TTN total con Centinela: **15,9 s (0,27 min)**.
- Referencia de la tesis (runbook, redacción manual): **4,26 min (255,6 s)**.
- Reducción de la mediana: **93,8 %**.

No se entregaron los valores individuales del runbook (--manual): se usa la prueba de rangos con signo de Wilcoxon de una muestra contra la mediana de referencia, unilateral (H1: mediana TTN Centinela < 4,26 min): **W = 0,0; p = 3,05 × 10⁻⁵**.

### Incluyendo la revisión y la decisión humanas

La Tabla N.º 17 incluye etapas humanas (análisis, clasificación y redacción). La cadena equivalente con Centinela, incluido el tiempo del operador hasta registrar la decisión de reporte, es t0 → decisión del delegado:

- Mediana: **101,6 s (1,69 min)**, una reducción de **60,2 %** respecto de los 4,26 min; máximo 2,30 min.
- Wilcoxon de una muestra, unilateral: **W = 0,0; p = 3,05 × 10⁻⁵**.

## TTC: Centinela frente a la condición base (Tabla N.º 15)

- Mediana TTC Centinela: 15,6 s · base (manual): 26,0 s · modelo de la tesis: 9,2 s.
- U de Mann-Whitney unilateral (H1: TTC Centinela < base): **U = 18,0; p = 4,77 × 10⁻⁵**; r = 0,84; δ de Cliff = -0,84.
- Centinela no cambia la contención (la hace Fail2ban); se espera un TTC similar al del modelo de la tesis, lo que confirma que la herramienta no la retrasa.

## Cumplimiento de requisitos

| Requisito | Cumplen | IC 95 % (Wilson) |
|---|---|---|
| RNF-01: TTC ≤ 60 s | 15/15 (100,0 %) | 79,6 %–100,0 % |
| RNF-02: TTN ≤ 180 min | 15/15 (100,0 %) | 79,6 %–100,0 % |
| RF-04: alerta temprana con todos los campos | 15/15 (100,0 %) | 79,6 %–100,0 % |

## Registros descartados

| Incidente | Motivo |
|---|---|
| INC-20261105-007 | incidente DEMO |
| INC-20261105-006 | incidente DEMO |
| INC-20261105-005 | anterior al inicio de la campaña |
| INC-20261105-004 | anterior al inicio de la campaña |
| INC-20261105-003 | anterior al inicio de la campaña |
| INC-20261105-002 | anterior al inicio de la campaña |
| INC-20261105-001 | anterior al inicio de la campaña |
