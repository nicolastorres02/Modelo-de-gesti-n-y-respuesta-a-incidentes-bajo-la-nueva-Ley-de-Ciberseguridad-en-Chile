"""Campos de los cuatro reportes al CSIRT Nacional y generación de PDF.

Cada campo sigue el contenido mínimo del DS 295/2024:

- Alerta temprana (art. 9.º): letras a), b), c), f) y g) del art. 5.º.
- Segundo reporte (art. 10): todos los campos del art. 5.º, la evaluación inicial
  de gravedad e impacto y los indicadores de compromiso.
- Plan de acción (art. 11, solo OIV): recuperación, responsabilidades y tiempo
  estimado de recuperación.
- Informe final (art. 12): letras a) a d) y, si un OIV vio afectados sus
  servicios esenciales, los tres antecedentes adicionales.

Los datos personales se omiten (art. 6.º): las cuentas nominativas se reemplazan
por "[cuenta omitida]"; la dirección IP no se considera dato personal.
Los campos que se obtienen de las bitácoras se completan automáticamente; el
resto lo completa el delegado en el panel.
"""
import re
from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from xml.sax.saxutils import escape

from . import config, db, plazos, significancia

R = "Responsable del reporte"
CAMPOS = {
    "alerta_temprana": [
        ("identificador", "Identificador del incidente"),
        ("institucion", "a) Institución afectada (nombre, RUT, dirección, correo)"),
        ("delegado", "b) Delegado de ciberseguridad y datos de contacto"),
        ("fecha_conocimiento", "c) Fecha y hora de conocimiento del incidente"),
        ("fecha_inicio", "c) Fecha estimada de inicio del incidente"),
        ("indicios", "f) Indicios de la ocurrencia del incidente"),
        ("tipo_incidente", "Clasificación (Res. Ex. N.º 7/2025: área, efecto observable, categoría)"),
        ("activos", "g) Activos y recursos potencialmente afectados"),
        ("contencion", "Acciones de contención iniciales"),
        ("evaluacion", "Evaluación de efecto significativo (DS 295/2024, art. 3.º)"),
        ("estado", "Estado actual"),
        ("responsable", R),
    ],
    "segundo_reporte": [
        ("identificador", "Identificador del incidente"),
        ("tipo_incidente", "Clasificación confirmada (Res. Ex. N.º 7/2025)"),
        ("descripcion", "Descripción actualizada del incidente"),
        ("gravedad", "Evaluación inicial de la gravedad e impacto"),
        ("ioc", "h) Indicadores de compromiso (tipo, fuente o ubicación)"),
        ("activos", "g) Activos y recursos afectados"),
        ("delito", "d) Evidencia de que responde a una acción tipificada como delito"),
        ("repercusiones", "e) Potenciales repercusiones en otras instituciones"),
        ("medidas", "Medidas de contención y mitigación aplicadas"),
        ("otros", "i) Otros datos útiles para la gestión del incidente"),
        ("responsable", R),
    ],
    "plan_accion": [
        ("identificador", "Identificador del incidente"),
        ("recuperacion", "Programa de recuperación de información"),
        ("responsabilidades", "Responsabilidades técnicas y administrativas"),
        ("tiempo_recuperacion", "Estimación del tiempo de recuperación de los servicios"),
        ("acciones", "Acciones correctivas y preventivas (con responsables y plazos)"),
        ("responsable", R),
    ],
    "informe_final": [
        ("identificador", "Identificador del incidente"),
        ("confirmacion", "Confirmación o actualización de los datos de los reportes anteriores"),
        ("descripcion_detallada", "a) Descripción detallada del incidente, incluyendo su gravedad e impacto"),
        ("causa", "b) Tipo de amenaza o causa principal que probablemente causó el incidente"),
        ("mitigacion", "c) Medidas de mitigación aplicadas y en curso"),
        ("transfronterizo", "d) Repercusiones transfronterizas (si procede)"),
        ("linea_tiempo", "Línea de tiempo del incidente"),
        ("vulnerabilidades", "OIV: vulnerabilidades explotadas y exploits utilizados"),
        ("controles", "OIV: controles que debieron prevenir o mitigar el incidente y causa de su falla"),
        ("alertas_csirt", "OIV: alertas del CSIRT Nacional vigentes y si fueron adoptadas"),
        ("lecciones", "Lecciones aprendidas"),
        ("responsable", R),
    ],
}
# Campos del informe final exigidos solo a un OIV con servicios esenciales afectados (art. 12)
SOLO_OIV_AFECTADO = {"vulnerabilidades", "controles", "alertas_csirt"}

# Cuentas genéricas o de sistema: no identifican a una persona y se pueden informar
CUENTAS_GENERICAS = {
    "root", "admin", "administrator", "administrador", "test", "testing", "user", "usuario", "guest",
    "invitado", "oracle", "postgres", "mysql", "ubuntu", "debian", "centos", "pi", "ftp", "ftpuser",
    "www-data", "nobody", "kali", "support", "soporte", "info", "backup", "git", "deploy", "operator",
    "demo", "default", "ansible", "jenkins", "tomcat", "nagios", "hadoop", "elastic", "redis", "docker",
    "vagrant", "ec2-user", "sysadmin", "webmaster", "service", "dev", "server",
}
OMITIDA = "[cuenta omitida]"


def _f(ts: datetime | None) -> str:
    return ts.strftime("%d-%m-%Y %H:%M:%S") if ts else "—"


def es_manual(inc: dict) -> bool:
    return inc.get("escenario") == "manual"


# --- Datos personales (DS 295/2024, art. 6.º) ---------------------------------------

def cuentas_nominativas(inc: dict) -> set:
    cuentas = set(inc.get("usuarios") or []) | {a[1] for a in inc.get("accesos_exitosos") or []}
    return {c for c in cuentas if c and c.lower() not in CUENTAS_GENERICAS}


def anonimizar(texto: str, inc: dict) -> str:
    for c in sorted(cuentas_nominativas(inc), key=len, reverse=True):
        texto = re.sub(rf"(?<![\w.-]){re.escape(c)}(?![\w.-])", OMITIDA, texto)
    return texto


def _cuentas_publicas(inc: dict) -> str:
    nominativas = cuentas_nominativas(inc)
    publicas = sorted(c for c in (inc.get("usuarios") or []) if c not in nominativas)
    if nominativas:
        publicas.append(f"{len(nominativas)} cuenta(s) nominativa(s) omitida(s) (DS 295, art. 6.º)")
    return ", ".join(publicas) or "—"


# --- Textos automáticos -------------------------------------------------------------

def _servicio(inc: dict) -> str:
    if es_manual(inc):
        return (inc.get("detalle") or {}).get("activos") or "(completar)"
    if inc.get("escenario") == "E2":
        return f"Servidor web Apache (80/TCP) en {config.NOMBRE_HOST}"
    if (inc.get("jail") or "").lower().startswith("ssh"):
        return f"Servicio de acceso remoto OpenSSH (22/TCP) en {config.NOMBRE_HOST}"
    return f"Servicio protegido por la jaula '{inc.get('jail')}' en {config.NOMBRE_HOST}"


def _bloqueos(inc: dict) -> list:
    return inc.get("bloqueos") or ([db.a_texto(inc["t_contencion"])] if inc.get("t_contencion") else [])


def _clasificacion(inc: dict) -> str:
    return f"Área: {inc['impacto']}\nEfecto observable: {inc['categoria']}\nCategoría: {inc['subcategoria']}"


def _linea_tiempo(inc: dict) -> str:
    if es_manual(inc):
        partes = [f"Inicio estimado: {_f(inc.get('t0'))}",
                  f"Conocimiento del incidente: {_f(inc['t_deteccion'])}",
                  f"Registro en Centinela y alerta temprana generada: {_f(inc['t_registro'])}"]
    else:
        primer = "primera petición del escaneo" if inc.get("escenario") == "E2" else "primer intento fallido"
        partes = [
            f"t0 {primer}: {_f(inc['t0'])}",
            f"Detección (alerta de Fail2ban): {_f(inc['t_deteccion'])}",
            f"Contención (Fail2ban Ban): {_f(inc['t_contencion'])}",
            f"Registro en Centinela y alerta temprana generada: {_f(inc['t_registro'])}",
        ]
        bl = _bloqueos(inc)
        if len(bl) > 1:
            partes.append(f"Reincidencia: {len(bl)} bloqueos de la misma IP; último: {bl[-1][:19]}")
    if inc.get("reconocido"):
        partes.append(f"Revisión del operador en el panel: {_f(inc['reconocido'])}")
    ev = inc.get("evaluacion")
    if ev:
        partes.append(f"Evaluación de efecto significativo ({ev.get('usuario', '')}): {ev.get('fecha', '')[:19]}")
    return "\n".join(partes)


def _descripcion(inc: dict) -> str:
    det = inc.get("detalle") or {}
    if es_manual(inc):
        return det.get("descripcion") or "(completar)"
    ip = inc["ip"]
    bl = _bloqueos(inc)
    reincidencia = (f" La IP fue bloqueada {len(bl)} veces (reincidió tras cada desbloqueo)."
                    if len(bl) > 1 else "")
    if inc.get("escenario") == "E2":
        herramientas = ", ".join(det.get("herramientas", [])) or "no identificada"
        texto = (f"Se registraron {det.get('peticiones', 0)} peticiones HTTP desde la IP {ip}, de las "
                 f"cuales {det.get('errores', 0)} correspondieron a recursos inexistentes o prohibidos "
                 f"(4xx), a partir de {_f(inc['t0'])}. Herramienta de reconocimiento detectada: "
                 f"{herramientas}. Patrón compatible con un escaneo automatizado de recursos web.")
        if det.get("expuestas"):
            texto += (f" El servidor entregó con éxito {len(det['expuestas'])} recurso(s) sensible(s): "
                      f"{', '.join(e[0] for e in det['expuestas'][:6])}.")
        else:
            texto += " No se obtuvieron recursos sensibles."
        return texto + reincidencia
    texto = (f"Se registraron {inc['intentos']} intentos fallidos de autenticación desde la IP {ip} "
             f"contra las cuentas: {_cuentas_publicas(inc)}, a partir de {_f(inc['t0'])}. Patrón "
             f"compatible con un ataque automatizado de adivinación de credenciales.")
    if inc.get("accesos_exitosos"):
        ts, usuario = inc["accesos_exitosos"][-1]
        texto += (f" ATENCIÓN: se registró un inicio de sesión exitoso de la cuenta '{usuario}' desde "
                  f"la IP atacante ({ts[:19]}); se presume compromiso de la cuenta.")
    else:
        texto += " No se registró ningún acceso exitoso."
    return anonimizar(texto + reincidencia, inc)


def _indicios(inc: dict) -> str:
    """DS 295, art. 5.º f): denegación, acceso no autorizado, exposición, malware, phishing u otro."""
    det = inc.get("detalle") or {}
    if es_manual(inc):
        base = det.get("indicios") or ""
    elif inc.get("accesos_exitosos"):
        base = "Acceso no autorizado a la red o al dispositivo."
    elif det.get("expuestas"):
        base = "Exposición, robo o fuga de datos (recursos sensibles entregados por el servidor web)."
    elif inc.get("escenario") == "E2":
        base = "Otro: reconocimiento automatizado de recursos web, contenido por Fail2ban."
    else:
        base = "Otro: intentos de acceso no autorizado contenidos por Fail2ban, sin acceso logrado."
    return f"{base}\n{_descripcion(inc)}".strip()


def _ioc(inc: dict) -> str:
    det = inc.get("detalle") or {}
    lineas = [f"IP de origen: {inc['ip'] or 'no identificada'}"]
    if es_manual(inc):
        lineas.append("Otros indicadores: (completar)")
    elif inc.get("escenario") == "E2":
        lineas += [f"Peticiones: {det.get('peticiones', 0)} (4xx: {det.get('errores', 0)})",
                   f"Herramientas: {', '.join(det.get('herramientas', [])) or '—'}",
                   f"User-Agent: {'; '.join(det.get('agentes', [])[:3]) or '—'}",
                   f"Rutas solicitadas (muestra): {', '.join(det.get('rutas', [])[:8]) or '—'}"]
        if det.get("expuestas"):
            lineas.append(f"Recursos sensibles entregados: {', '.join(e[0] for e in det['expuestas'][:10])}")
    else:
        lineas += [f"Cuentas objetivo: {_cuentas_publicas(inc)}",
                   f"Intentos fallidos: {inc['intentos']}"]
    if inc.get("hash_evidencia"):
        lineas.append(f"SHA-256 de la evidencia: {inc['hash_evidencia']}")
    return anonimizar("\n".join(lineas), inc)


def _evaluacion(inc: dict) -> str:
    ev = inc.get("evaluacion")
    texto = significancia.resumen(ev)
    if ev:
        for l in ev["criterios"]:
            texto += f"\n{l}) {significancia.TEXTO[l]}"
        extra = [f"Personas afectadas: {ev['personas_afectadas']}" if ev.get("personas_afectadas") else "",
                 f"Duración: {ev['duracion']}" if ev.get("duracion") else "",
                 f"Extensión geográfica: {ev['extension_geografica']}" if ev.get("extension_geografica") else ""]
        texto += "".join(f"\n{e}" for e in extra if e)
        texto += f"\nFundamento del delegado: {ev['justificacion']}"
    else:
        p = significancia.proponer(inc)
        texto += (f"\nPropuesta automática: {'reportable' if p['propuesta'] == 'reportable' else 'no reportable'}"
                  + (f" (letras {', '.join(p['criterios'])})" if p["criterios"] else ""))
    return texto


def _contencion(inc: dict, ttc: float | None) -> str:
    if es_manual(inc):
        return (inc.get("detalle") or {}).get("contencion") or "(completar)"
    ip = inc["ip"]
    puertos = "80/443" if inc.get("escenario") == "E2" else "22"
    texto = (f"Bloqueo automático de la IP {ip} en el cortafuegos (Fail2ban, jaula '{inc['jail']}', "
             f"acción iptables, puertos {puertos}) el {_f(inc['t_contencion'])}"
             + (f", {ttc:.1f} s después del inicio del ataque.".replace(".", ",", 1) if ttc is not None else "."))
    bl = _bloqueos(inc)
    if len(bl) > 1:
        texto += f" El bloqueo se aplicó {len(bl)} veces por reincidencia."
    return texto


def _institucion() -> str:
    partes = [config.ORGANIZACION,
              f"RUT {config.ORG_RUT}" if config.ORG_RUT else "RUT (completar)",
              config.ORG_DIRECCION or "Dirección (completar)",
              config.ORG_CORREO or "Correo institucional (completar)"]
    return "\n".join(partes)


def _delegado() -> str:
    partes = [config.RESPONSABLE]
    partes.append(config.DELEGADO_CORREO or "Correo (completar)")
    partes.append(config.DELEGADO_TELEFONO or "Teléfono (completar)")
    return "\n".join(partes)


def _gravedad(inc: dict) -> str:
    ev = inc.get("evaluacion")
    lineas = [f"Área de impacto: {inc['impacto']}", f"Efecto observable: {inc['categoria']}",
              significancia.resumen(ev)]
    if ev:
        for etiqueta, k in (("Personas afectadas", "personas_afectadas"), ("Duración", "duracion"),
                            ("Extensión geográfica", "extension_geografica")):
            if ev.get(k):
                lineas.append(f"{etiqueta}: {ev[k]}")
    return "\n".join(lineas)


def _delito(inc: dict) -> str:
    if inc.get("accesos_exitosos"):
        return ("El ingreso sin autorización podría constituir el delito de acceso ilícito (Ley N.º 21.459, "
                "art. 2.º). La evidencia se conserva con su huella SHA-256 para una eventual denuncia.")
    return ""


def campos_automaticos(tipo: str, inc: dict) -> dict:
    """Valores que Centinela completa sin intervención del operador."""
    ttc = metricas(inc)["ttc_s"]
    contencion = _contencion(inc, ttc)
    comunes = {"identificador": inc["id"], "responsable": config.RESPONSABLE}

    if tipo == "alerta_temprana":
        return comunes | {
            "institucion": _institucion(),
            "delegado": _delegado(),
            "fecha_conocimiento": _f(inc["t_deteccion"]),
            "fecha_inicio": _f(inc.get("t0")),
            "indicios": _indicios(inc),
            "tipo_incidente": _clasificacion(inc),
            "activos": _servicio(inc),
            "contencion": contencion,
            "evaluacion": _evaluacion(inc),
            "estado": ("IP bloqueada; cuenta posiblemente comprometida: en gestión"
                       if inc.get("t_contencion") and inc.get("accesos_exitosos")
                       else "Contenido (IP bloqueada)" if inc.get("t_contencion")
                       else "En gestión" if inc["estado"] == "abierto" else "Gestionado"),
        }
    if tipo == "segundo_reporte":
        return comunes | {
            "tipo_incidente": _clasificacion(inc),
            "descripcion": _descripcion(inc),
            "gravedad": _gravedad(inc),
            "ioc": _ioc(inc),
            "activos": _servicio(inc),
            "delito": _delito(inc),
            "medidas": contencion,
        }
    if tipo == "informe_final":
        return comunes | {"linea_tiempo": _linea_tiempo(inc), "descripcion_detallada": _descripcion(inc)}
    return comunes


def metricas(inc: dict, reportes: dict | None = None) -> dict:
    """Métricas de tiempo de cada incidente.

    - ttd_s: t0 (primer intento) → detección (Ban de Fail2ban).
    - ttc_s: t0 → contención (Ban).
    - ttn_s: detección → alerta temprana generada (tramo que automatiza Centinela).
    - ttn_total_s: t0 → alerta temprana generada. Misma cadena que la Tabla N.º 17 de
      la tesis (detección + análisis y clasificación + redacción), para comparar.
    - ttr_s: detección → el operador abre el incidente (se apaga la alarma).
    - tte_s: detección → el delegado registra la evaluación de efecto significativo
      (decisión de reportar o no, DS 295 art. 3.º): incluye el tiempo humano.
    """
    def seg(a, b):
        return (b - a).total_seconds() if a and b else None
    alerta = (reportes or {}).get("alerta_temprana")
    t_alerta = alerta["generado"] if alerta else None
    ev = inc.get("evaluacion") or {}
    t_eval = datetime.fromisoformat(ev["fecha"]) if ev.get("fecha") else None
    return {
        "ttd_s": seg(inc.get("t0"), inc["t_deteccion"]) if not es_manual(inc) else None,
        "ttc_s": seg(inc.get("t0"), inc.get("t_contencion")),
        "ttn_s": seg(inc["t_deteccion"], t_alerta),
        "ttn_total_s": seg(inc.get("t0"), t_alerta) if not es_manual(inc) else None,
        "ttr_s": seg(inc["t_deteccion"], inc.get("reconocido")),
        "tte_s": seg(inc["t_deteccion"], t_eval),
        "t_alerta": t_alerta,
        "t_evaluacion": t_eval,
    }


COLUMNAS_CSV = ["id", "ip", "jail", "escenario", "categoria", "subcategoria", "t0", "t_deteccion",
                "t_contencion", "t_alerta", "reconocido", "t_evaluacion", "bloqueos", "intentos",
                "ttd_s", "ttc_s", "ttn_s", "ttn_total_s", "ttr_s", "tte_s", "evaluacion",
                "campos_sin_completar", "estado", "demo"]


def fila_csv(inc: dict, reps: dict) -> dict:
    """Una fila de la exportación de métricas (panel y comando 'exportar')."""
    m = metricas(inc, reps)
    alerta = reps.get("alerta_temprana")
    # Completitud de la alerta temprana (RF-04): campos que quedaron sin dato
    sin_completar = (sum(1 for k, _ in CAMPOS["alerta_temprana"]
                         if not alerta["campos"].get(k) or "(completar)" in str(alerta["campos"].get(k)))
                     if alerta else None)
    r = lambda v: round(v, 3) if isinstance(v, float) else v
    return {
        "id": inc["id"], "ip": inc["ip"], "jail": inc["jail"], "escenario": inc["escenario"],
        "categoria": inc["categoria"], "subcategoria": inc["subcategoria"],
        "t0": db.a_texto(inc.get("t0")), "t_deteccion": db.a_texto(inc["t_deteccion"]),
        "t_contencion": db.a_texto(inc.get("t_contencion")), "t_alerta": db.a_texto(m["t_alerta"]),
        "reconocido": db.a_texto(inc.get("reconocido")), "t_evaluacion": db.a_texto(m["t_evaluacion"]),
        "bloqueos": len(inc.get("bloqueos") or []), "intentos": inc["intentos"],
        **{k: r(m[k]) for k in ("ttd_s", "ttc_s", "ttn_s", "ttn_total_s", "ttr_s", "tte_s")},
        "evaluacion": (inc.get("evaluacion") or {}).get("decision", "pendiente"),
        "campos_sin_completar": sin_completar, "estado": inc["estado"], "demo": inc["demo"],
    }


# --- PDF ----------------------------------------------------------------------

def _estilos():
    base = getSampleStyleSheet()
    return {
        "titulo": ParagraphStyle("t", parent=base["Title"], fontSize=16, spaceAfter=4),
        "sub": ParagraphStyle("s", parent=base["Normal"], fontSize=9, textColor=colors.HexColor("#555555")),
        "etq": ParagraphStyle("e", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=9),
        "val": ParagraphStyle("v", parent=base["Normal"], fontSize=9, leading=12),
        "pie": ParagraphStyle("p", parent=base["Normal"], fontSize=7.5, textColor=colors.HexColor("#777777")),
    }


def generar_pdf(tipo: str, inc: dict, campos: dict, generado: datetime,
                vence: datetime | None = None) -> Path:
    config.asegurar_directorios()
    ruta = config.PDF_DIR / f"{inc['id']}_{tipo}.pdf"
    est = _estilos()

    elementos = [
        Paragraph(f"{plazos.NOMBRES[tipo]} — Reporte de incidente de ciberseguridad", est["titulo"]),
        Paragraph(f"Base legal: {plazos.BASE_LEGAL[tipo]} · Ley N.º 21.663, art. 9.º · "
                  f"Plazo: {_f(vence) if vence else 'no aplica'}", est["sub"]),
    ]
    if inc.get("demo"):
        elementos.append(Paragraph("<b>DEMOSTRACIÓN — datos de ejemplo, no corresponde a un incidente real "
                                   "ni a mediciones del estudio.</b>", est["sub"]))
    elementos.append(Spacer(1, 0.4 * cm))

    oiv_afectado = plazos.segundo_reporte_24h(inc)
    filas = []
    for clave, etiqueta in CAMPOS[tipo]:
        if clave in SOLO_OIV_AFECTADO and not oiv_afectado:
            continue
        valor = anonimizar(str(campos.get(clave) or "(sin completar)"), inc)
        filas.append([Paragraph(escape(etiqueta), est["etq"]),
                      Paragraph(escape(valor).replace("\n", "<br/>"), est["val"])])
    tabla = Table(filas, colWidths=[5.6 * cm, 11.4 * cm])
    tabla.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#999999")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef1f5")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    elementos.append(tabla)

    if tipo == "alerta_temprana" and inc.get("justificacion"):
        elementos += [Spacer(1, 0.4 * cm),
                      Paragraph("Clasificación: lista de verificación Res. Ex. N.º 7/2025", est["etq"])]
        elementos += [Paragraph("• " + escape(anonimizar(j, inc)), est["val"]) for j in inc["justificacion"]]

    if tipo in ("alerta_temprana", "segundo_reporte") and inc.get("evidencia") and not es_manual(inc):
        fuente = "access.log" if inc.get("escenario") == "E2" else "auth.log"
        elementos += [Spacer(1, 0.4 * cm), Paragraph(f"Evidencia (extracto de {fuente})", est["etq"])]
        muestra = inc["evidencia"][:8]
        elementos += [Paragraph(escape(anonimizar(l[:180], inc)), est["pie"]) for l in muestra]
        if len(inc["evidencia"]) > len(muestra):
            elementos.append(Paragraph(f"… {len(inc['evidencia']) - len(muestra)} líneas más.", est["pie"]))

    if inc.get("hash_evidencia"):
        elementos += [Spacer(1, 0.3 * cm),
                      Paragraph(f"Huella SHA-256 de la evidencia completa ({len(inc.get('evidencia') or [])} "
                                f"líneas, sin anonimizar, conservada en Centinela): {inc['hash_evidencia']}",
                                est["pie"])]

    elementos += [Spacer(1, 0.6 * cm),
                  Paragraph(f"Generado por Centinela el {_f(generado)}. Documento para su envío al CSIRT "
                            f"Nacional a través de la plataforma de notificación de la Agencia Nacional de "
                            f"Ciberseguridad (DS 295/2024, art. 8.º). Conforme al art. 6.º se omiten los datos "
                            f"personales; la dirección IP no se considera dato personal. La huella SHA-256 "
                            f"de este PDF queda registrada en la bitácora de Centinela.", est["pie"])]

    SimpleDocTemplate(str(ruta), pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm,
                      topMargin=1.8 * cm, bottomMargin=1.8 * cm,
                      title=f"{plazos.NOMBRES[tipo]} {inc['id']}").build(elementos)
    return ruta
