"""Análisis estadístico de las mediciones de Centinela (OE3).

Lee el CSV que exporta Centinela (panel → Métricas → Descargar CSV, o
`sudo centinela exportar archivo.csv`) y calcula, para las ejecuciones del
escenario E1 hechas con la herramienta:

- Estadística descriptiva (n, mediana, RIC, mínimo, máximo, media, DE) de TTC,
  TTN total (t0 → alerta temprana, misma cadena que la Tabla N.º 17), tiempo
  hasta la revisión y tiempo hasta la decisión del delegado.
- Comparación del TTN con la condición modelo de la tesis (runbook con redacción
  manual, mediana 4,26 min):
    * si se entregan los 15 valores originales (--manual), U de Mann-Whitney
      unilateral, correlación biserial de rangos y δ de Cliff;
    * si no, prueba de rangos con signo de Wilcoxon de una muestra contra la mediana
      de referencia (unilateral).
- TTC de Centinela frente a la condición base de la Tabla N.º 15 (U de Mann-Whitney).
- Cumplimiento de RNF-01 (TTC ≤ 60 s), RNF-02 (TTN ≤ 180 min) y RF-04 (alerta con
  todos los campos), con intervalo de confianza de Wilson al 95 %.

Uso:
    python analisis_mediciones.py metricas_centinela.csv --desde "2026-11-06 10:00"
    python analisis_mediciones.py metricas_centinela.csv --manual ttn_runbook.csv

Genera en la carpeta del CSV: resultados_mediciones.md, ejecuciones_validas.csv y,
si matplotlib está instalado, figura_ttn.png y figura_ttc.png.
"""
import argparse
import csv
import math
import sys
from datetime import datetime
from pathlib import Path

import numpy as np
from scipy import stats

# Tabla N.º 15 de la tesis: TTC (s) por ejecución
TTC_BASE = [25, 23, 26, 15, 37, 27, 23, 36, 30, 15, 30, 30, 18, 26, 31]
TTC_MODELO_TESIS = [3.9, 6.8, 14.2, 6.8, 31.6, 9.2, 8.6, 22.6, 9.3, 11.6, 7.6, 14.3, 8.6, 16.2, 2.5]
# Tabla N.º 17 de la tesis: TTN total, condición modelo con runbook (redacción manual)
TTN_REFERENCIA_MIN = 4.26


def _num(v):
    try:
        return float(v) if v not in ("", None, "None") else None
    except ValueError:
        return None


def cargar(ruta: Path, desde, hasta, escenario: str):
    validas, descartadas = [], []
    with ruta.open(encoding="utf-8-sig") as f:
        for fila in csv.DictReader(f):
            motivo = None
            t0 = fila.get("t0") or ""
            if fila.get("demo") in ("1", "True"):
                motivo = "incidente DEMO"
            elif fila.get("escenario") != escenario:
                motivo = f"escenario {fila.get('escenario')}"
            elif desde and (not t0 or datetime.fromisoformat(t0) < desde):
                motivo = "anterior al inicio de la campaña"
            elif hasta and t0 and datetime.fromisoformat(t0) > hasta:
                motivo = "posterior al fin de la campaña"
            elif _num(fila.get("ttn_total_s")) is None or _num(fila.get("ttc_s")) is None:
                motivo = "sin t0 o sin alerta temprana"
            elif int(fila.get("bloqueos") or 1) > 1:
                motivo = "agrupó varios bloqueos (no se cerró el incidente anterior)"
            (descartadas if motivo else validas).append((fila, motivo))
    validas.sort(key=lambda x: x[0]["t0"])
    return [f for f, _ in validas], descartadas


def describir(x):
    x = np.asarray([v for v in x if v is not None], dtype=float)
    if len(x) == 0:
        return None
    q1, q3 = np.percentile(x, [25, 75])
    return {"n": len(x), "mediana": float(np.median(x)), "q1": float(q1), "q3": float(q3),
            "min": float(x.min()), "max": float(x.max()), "media": float(x.mean()),
            "de": float(x.std(ddof=1)) if len(x) > 1 else 0.0}


def wilson(exitos: int, n: int, z: float = 1.959964):
    if n == 0:
        return (float("nan"), float("nan"))
    p = exitos / n
    centro = (p + z * z / (2 * n)) / (1 + z * z / n)
    margen = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return (max(0.0, centro - margen), min(1.0, centro + margen))


def cliff_delta(a, b):
    """δ de Cliff: P(a > b) − P(a < b). Negativo = 'a' tiende a ser menor."""
    mayor = sum(1 for x in a for y in b if x > y)
    menor = sum(1 for x in a for y in b if x < y)
    return (mayor - menor) / (len(a) * len(b))


def mann_whitney_menor(a, b):
    """H1: 'a' es menor que 'b'. Devuelve U de 'a', p unilateral y r biserial de rangos."""
    res = stats.mannwhitneyu(a, b, alternative="less")
    r = 1 - 2 * res.statistic / (len(a) * len(b))      # positivo = 'a' menor
    return float(res.statistic), float(res.pvalue), float(r), cliff_delta(a, b)


def fmt(v, dec=2):
    return "—" if v is None else f"{v:.{dec}f}".replace(".", ",")


def fila_desc(nombre, d, unidad="s", factor=1.0):
    if not d:
        return f"| {nombre} | 0 | — | — | — | — | — | — |"
    f = lambda k: fmt(d[k] / factor)
    return (f"| {nombre} ({unidad}) | {d['n']} | {f('mediana')} | {f('q1')}–{f('q3')} | {f('min')} | "
            f"{f('max')} | {f('media')} | {f('de')} |")


def p_txt(p):
    if p >= 0.001:
        return fmt(p, 4)
    mantisa, exp = f"{p:.2e}".split("e")
    sup = str(int(exp)).translate(str.maketrans("-0123456789", "⁻⁰¹²³⁴⁵⁶⁷⁸⁹"))
    return f"{mantisa.replace('.', ',')} × 10{sup}"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv", type=Path)
    ap.add_argument("--desde", help="Inicio de la campaña de mediciones (AAAA-MM-DD HH:MM)")
    ap.add_argument("--hasta", help="Fin de la campaña de mediciones")
    ap.add_argument("--escenario", default="E1")
    ap.add_argument("--manual", type=Path,
                    help="CSV con los TTN de la condición modelo de la tesis (columna ttn_s o ttn_min)")
    ap.add_argument("--esperadas", type=int, default=15)
    a = ap.parse_args(argv)

    desde = datetime.fromisoformat(a.desde) if a.desde else None
    hasta = datetime.fromisoformat(a.hasta) if a.hasta else None
    filas, descartadas = cargar(a.csv, desde, hasta, a.escenario)
    if not filas:
        sys.exit("No hay ejecuciones válidas en el CSV con esos filtros.")

    col = lambda k: [_num(f[k]) for f in filas]
    ttc, ttn_total, ttn_auto = col("ttc_s"), col("ttn_total_s"), col("ttn_s")
    ttr, tte = col("ttr_s"), col("tte_s")
    # t0 → decisión del delegado: la cadena completa incluyendo el trabajo humano
    # (equivale a la Tabla N.º 17, donde análisis y redacción eran humanos)
    t0_decision = [a + b if a is not None and b is not None else None for a, b in zip(col("ttd_s"), tte)]
    d = {k: describir(v) for k, v in (("ttc", ttc), ("ttn_total", ttn_total), ("ttn_auto", ttn_auto),
                                        ("ttr", ttr), ("tte", tte), ("t0_dec", t0_decision))}
    n = len(filas)
    ref_s = TTN_REFERENCIA_MIN * 60

    lineas = [f"# Resultados de las mediciones con Centinela (escenario {a.escenario})", "",
              f"Archivo: `{a.csv.name}` · ejecuciones válidas: **{n}**"
              + (f" (se esperaban {a.esperadas})" if n != a.esperadas else "")
              + f" · descartadas: {len(descartadas)} · generado el {datetime.now():%d-%m-%Y %H:%M}", ""]
    if n < a.esperadas:
        lineas += [f"> **Atención:** faltan {a.esperadas - n} ejecuciones para completar la muestra.", ""]

    lineas += ["## Ejecuciones", "",
               "| # | Incidente | t0 | TTC (s) | TTN automático (s) | TTN total (s) | Revisión (s) | Decisión (s) | Campos sin completar |",
               "|---|---|---|---|---|---|---|---|---|"]
    for i, f in enumerate(filas, 1):
        lineas.append(f"| {i} | {f['id']} | {f['t0'][:19]} | {fmt(_num(f['ttc_s']), 1)} | "
                      f"{fmt(_num(f['ttn_s']), 2)} | {fmt(_num(f['ttn_total_s']), 1)} | "
                      f"{fmt(_num(f['ttr_s']), 1)} | {fmt(_num(f['tte_s']), 1)} | {f.get('campos_sin_completar', '—')} |")

    lineas += ["", "## Estadística descriptiva", "",
               "| Métrica | n | Mediana | RIC | Mínimo | Máximo | Media | DE |", "|---|---|---|---|---|---|---|---|",
               fila_desc("TTC", d["ttc"]),
               fila_desc("TTN automático: detección → alerta", d["ttn_auto"]),
               fila_desc("TTN total: t0 → alerta", d["ttn_total"]),
               fila_desc("TTN total: t0 → alerta", d["ttn_total"], "min", 60),
               fila_desc("Detección → revisión del operador", d["ttr"]),
               fila_desc("Detección → decisión del delegado", d["tte"]),
               fila_desc("t0 → decisión del delegado", d["t0_dec"]),
               fila_desc("t0 → decisión del delegado", d["t0_dec"], "min", 60), ""]

    # --- TTN frente a la tesis --------------------------------------------------------
    med = d["ttn_total"]["mediana"]
    reduccion = (1 - med / ref_s) * 100
    lineas += ["## TTN: Centinela frente al runbook con redacción manual (Tabla N.º 17)", "",
               f"- Mediana TTN total con Centinela: **{fmt(med, 1)} s ({fmt(med / 60, 2)} min)**.",
               f"- Referencia de la tesis (runbook, redacción manual): **{fmt(TTN_REFERENCIA_MIN)} min "
               f"({fmt(ref_s, 1)} s)**.",
               f"- Reducción de la mediana: **{fmt(reduccion, 1)} %**.", ""]
    if a.manual:
        manual = []
        with a.manual.open(encoding="utf-8-sig") as f:
            for r in csv.DictReader(f):
                v = _num(r.get("ttn_s")) if "ttn_s" in r else (_num(r.get("ttn_min")) or 0) * 60
                if v:
                    manual.append(v)
        u, p, rr, delta = mann_whitney_menor([v for v in ttn_total if v is not None], manual)
        lineas += [f"Prueba U de Mann-Whitney, unilateral (H1: TTN Centinela < TTN runbook), n = {n} y "
                   f"{len(manual)}: **U = {fmt(u, 1)}; p = {p_txt(p)}**; correlación biserial de rangos "
                   f"r = {fmt(rr)}; δ de Cliff = {fmt(delta)}.", ""]
    else:
        w = stats.wilcoxon(np.asarray([v for v in ttn_total if v is not None]) - ref_s, alternative="less")
        lineas += ["No se entregaron los valores individuales del runbook (--manual): se usa la prueba de "
                   "rangos con signo de Wilcoxon de una muestra contra la mediana de referencia, unilateral "
                   f"(H1: mediana TTN Centinela < {fmt(TTN_REFERENCIA_MIN)} min): "
                   f"**W = {fmt(float(w.statistic), 1)}; p = {p_txt(float(w.pvalue))}**.", ""]

    if d["t0_dec"]:
        x = np.asarray([v for v in t0_decision if v is not None])
        w2 = stats.wilcoxon(x - ref_s, alternative="less")
        md = d["t0_dec"]["mediana"]
        lineas += ["### Incluyendo la revisión y la decisión humanas", "",
                   "La Tabla N.º 17 incluye etapas humanas (análisis, clasificación y redacción). La cadena "
                   "equivalente con Centinela, incluido el tiempo del operador hasta registrar la decisión de "
                   "reporte, es t0 → decisión del delegado:", "",
                   f"- Mediana: **{fmt(md, 1)} s ({fmt(md / 60, 2)} min)**, una reducción de "
                   f"**{fmt((1 - md / ref_s) * 100, 1)} %** respecto de los {fmt(TTN_REFERENCIA_MIN)} min; "
                   f"máximo {fmt(d['t0_dec']['max'] / 60, 2)} min.",
                   f"- Wilcoxon de una muestra, unilateral: **W = {fmt(float(w2.statistic), 1)}; "
                   f"p = {p_txt(float(w2.pvalue))}**.", ""]

    # --- TTC frente a la condición base --------------------------------------------------
    u, p, rr, delta = mann_whitney_menor([v for v in ttc if v is not None], TTC_BASE)
    dm = describir(TTC_MODELO_TESIS)
    lineas += ["## TTC: Centinela frente a la condición base (Tabla N.º 15)", "",
               f"- Mediana TTC Centinela: {fmt(d['ttc']['mediana'], 1)} s · base (manual): "
               f"{fmt(float(np.median(TTC_BASE)), 1)} s · modelo de la tesis: {fmt(dm['mediana'], 1)} s.",
               f"- U de Mann-Whitney unilateral (H1: TTC Centinela < base): **U = {fmt(u, 1)}; "
               f"p = {p_txt(p)}**; r = {fmt(rr)}; δ de Cliff = {fmt(delta)}.",
               "- Centinela no cambia la contención (la hace Fail2ban); se espera un TTC similar al del "
               "modelo de la tesis, lo que confirma que la herramienta no la retrasa.", ""]

    # --- Cumplimiento de requisitos -----------------------------------------------------
    def cumple(nombre, ok):
        k = sum(ok)
        lo, hi = wilson(k, len(ok))
        return f"| {nombre} | {k}/{len(ok)} ({fmt(100 * k / len(ok), 1)} %) | {fmt(100 * lo, 1)} %–{fmt(100 * hi, 1)} % |"
    completas = [f.get("campos_sin_completar") == "0" for f in filas]
    lineas += ["## Cumplimiento de requisitos", "", "| Requisito | Cumplen | IC 95 % (Wilson) |", "|---|---|---|",
               cumple("RNF-01: TTC ≤ 60 s", [v <= 60 for v in ttc if v is not None]),
               cumple("RNF-02: TTN ≤ 180 min", [v <= 10800 for v in ttn_total if v is not None]),
               cumple("RF-04: alerta temprana con todos los campos", completas), ""]

    if descartadas:
        lineas += ["## Registros descartados", "", "| Incidente | Motivo |", "|---|---|"]
        lineas += [f"| {f['id']} | {m} |" for f, m in descartadas]

    salida = a.csv.parent / "resultados_mediciones.md"
    salida.write_text("\n".join(lineas) + "\n", encoding="utf-8")
    with (a.csv.parent / "ejecuciones_validas.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(filas[0]))
        w.writeheader()
        w.writerows(filas)
    print("\n".join(lineas))
    print(f"\nResultados guardados en {salida}")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("(matplotlib no está instalado: no se generan las figuras)")
        return
    plt.rcParams.update({"font.size": 11, "font.family": "DejaVu Sans"})
    fig, ax = plt.subplots(figsize=(6.4, 4.2))
    datos = [np.asarray(ttn_total, dtype=float) / 60]
    etiquetas = ["Alerta temprana\ngenerada\n(t0 → alerta)"]
    if d["t0_dec"]:
        datos.append(np.asarray([v for v in t0_decision if v is not None], dtype=float) / 60)
        etiquetas.append("Con revisión y\ndecisión del delegado\n(t0 → decisión)")
    ax.boxplot(datos, tick_labels=etiquetas, widths=0.45, showmeans=True,
               meanprops={"marker": "D", "markerfacecolor": "white", "markeredgecolor": "black"})
    ax.axhline(TTN_REFERENCIA_MIN, color="#a62a2a", linestyle="--",
               label=f"Runbook con redacción manual (mediana {fmt(TTN_REFERENCIA_MIN)} min)")
    ax.set_ylabel("Minutos desde el inicio del ataque")
    ax.set_ylim(0, max(TTN_REFERENCIA_MIN * 1.25, max(float(np.nanmax(x)) for x in datos) * 1.2))
    ax.set_title(f"Tiempo de notificación con Centinela (n = {n})")
    ax.legend(loc="upper right", fontsize=9)
    fig.tight_layout()
    fig.savefig(a.csv.parent / "figura_ttn.png", dpi=200)
    fig, ax = plt.subplots(figsize=(6.4, 4.2))
    ax.boxplot([TTC_BASE, TTC_MODELO_TESIS, [v for v in ttc if v is not None]],
               tick_labels=["Base\n(manual)", "Modelo\n(tesis)", "Centinela"], widths=0.5, showmeans=True,
               meanprops={"marker": "D", "markerfacecolor": "white", "markeredgecolor": "black"})
    ax.axhline(60, color="#8a5a00", linestyle=":", label="Umbral RNF-01 (60 s)")
    ax.set_ylabel("TTC (segundos)")
    ax.set_title("Tiempo de contención")
    ax.legend(loc="upper right", fontsize=9)
    fig.tight_layout()
    fig.savefig(a.csv.parent / "figura_ttc.png", dpi=200)
    print("Figuras: figura_ttn.png y figura_ttc.png")


if __name__ == "__main__":
    main()
