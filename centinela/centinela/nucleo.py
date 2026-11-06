"""Flujo principal: de un bloqueo de Fail2ban a la notificación del incidente.

Se invoca desde la acción personalizada de Fail2ban (integracion/), cada vez
que una jaula bloquea una IP:

    Fail2ban Ban -> evidencia -> clasificación -> alerta temprana PDF
                 -> correo al delegado -> panel (aviso y alarma)

Si la misma IP vuelve a ser bloqueada por la misma jaula dentro de
CENTINELA_AGRUPAR_MIN minutos, el bloqueo se agrega al incidente abierto en
vez de crear uno nuevo (reincidencia).
"""
import ipaddress
import os
from datetime import datetime, timedelta

from . import (auditoria, clasificador, config, db, notificador, parsers, plazos, reportes,
               significancia, taxonomia)

# DS 295/2024, art. 5.º f): indicios de la ocurrencia del incidente
INDICIOS = [
    "Denegación, indisponibilidad o degradación de servicio",
    "Acceso no autorizado a la red o al dispositivo",
    "Exposición, robo o fuga de datos",
    "Código malicioso o malware",
    "Phishing o fraude",
    "Otro",
]

# Ventana hacia atrás desde el bloqueo en la que se buscan los intentos, solo
# si fail2ban.log no tiene eventos Found (debe ser >= findtime de Fail2ban).
VENTANA = timedelta(seconds=int(os.environ.get("CENTINELA_VENTANA_S", "600")))
MAX_EVIDENCIA = 500


def _evidencia(ip: str, jail: str, f2b, t_contencion, auth_log, access_log):
    """Lee la evidencia del ataque que terminó en este bloqueo."""
    if f2b.primer_found:
        desde = f2b.primer_found - timedelta(seconds=2)
    else:
        desde = t_contencion - VENTANA
    # Solo lo ocurrido hasta el bloqueo (más un margen por la escritura de
    # bitácoras) forma parte de este ataque.
    hasta = t_contencion + timedelta(seconds=5)

    if clasificador.es_jaula_web(jail):
        web = parsers.leer_access_log(ip, access_log, desde=desde, hasta=hasta)
        t0 = web.primera if web.primera and web.primera <= t_contencion else (f2b.primer_found or t_contencion)
        detalle = {"peticiones": web.peticiones, "errores": web.errores, "codigos": web.codigos,
                   "rutas": web.rutas, "agentes": sorted(web.agentes), "herramientas": sorted(web.herramientas),
                   "expuestas": web.expuestas}
        return {"t0": t0, "intentos": web.errores, "usuarios": set(), "accesos": [],
                "lineas": web.lineas, "detalle": detalle}

    auth = parsers.leer_auth_log(ip, auth_log, desde=desde, hasta=hasta)
    # t0: primer intento fallido del ataque (auth.log) o, si no está, primer Found
    if auth.primer_fallo and auth.primer_fallo <= t_contencion:
        t0 = auth.primer_fallo
    else:
        t0 = f2b.primer_found or t_contencion
    return {"t0": t0, "intentos": auth.intentos_fallidos, "usuarios": auth.usuarios,
            "accesos": [(ts.isoformat(sep=" "), u) for ts, u in auth.accesos_exitosos],
            "lineas": auth.lineas, "detalle": {}}


def _clasificar(jail, intentos, usuarios, accesos, detalle):
    return clasificador.clasificar(jail, intentos, usuarios, accesos, web=detalle or None)


def procesar_ban(ip: str, jail: str, ahora: datetime | None = None, auth_log=None, f2b_log=None,
                 access_log=None, demo: bool = False) -> str | None:
    """Registra (o agrupa) el incidente, genera la alerta temprana y notifica.
    Devuelve el id del incidente."""
    ahora = ahora or datetime.now()
    db.inicializar()

    f2b = parsers.leer_fail2ban_log(ip, f2b_log, jail=jail)
    # Conforme a la Tabla N.º 6 de la tesis, en la condición modelo el incidente
    # se identifica con la alerta de Fail2ban (evento Ban), que coincide con el
    # bloqueo. Ese instante es el "conocimiento" desde el que corren los plazos.
    t_contencion = f2b.ban or ahora
    jail = f2b.jail or jail
    ev = _evidencia(ip, jail, f2b, t_contencion, auth_log, access_log)
    marca = db.a_texto(t_contencion)

    with db.conexion() as con:
        # Idempotencia: el mismo bloqueo no se registra dos veces
        for inc in db.listar_incidentes(con):
            if inc["ip"] == ip and marca in (inc.get("bloqueos") or []):
                return inc["id"]

        previo = db.incidente_para_agrupar(con, ip, jail, t_contencion - timedelta(minutes=config.AGRUPAR_MIN))
        if previo:
            return _agrupar(con, previo, t_contencion, ev, demo)

        clas = _clasificar(jail, ev["intentos"], ev["usuarios"], ev["accesos"], ev["detalle"])
        lineas = ev["lineas"][:MAX_EVIDENCIA]
        inc = {
            "id": db.nuevo_id(con, t_contencion),
            "ip": ip,
            "jail": jail,
            "t0": ev["t0"],
            "t_deteccion": t_contencion,
            "t_contencion": t_contencion,
            "t_registro": ahora,
            "intentos": ev["intentos"],
            "usuarios": sorted(ev["usuarios"]),
            "accesos_exitosos": ev["accesos"],
            "categoria": clas.categoria,
            "subcategoria": clas.subcategoria,
            "escenario": clas.escenario,
            "impacto": clas.impacto,
            "justificacion": clas.justificacion,
            "requiere_revision": int(clas.requiere_revision),
            "evidencia": lineas,
            "hash_evidencia": auditoria.sha256_texto(lineas),
            "bloqueos": [marca],
            "ultimo_bloqueo": t_contencion,
            "detalle": ev["detalle"],
            "demo": int(demo),
        }
        db.guardar_incidente(con, inc)
        auditoria.registrar(con, "centinela", "incidente_registrado", inc["id"],
                            f"{clas.subcategoria}; ip={ip}; jaula={jail}; evidencia_sha256={inc['hash_evidencia']}")
        inc = db.obtener_incidente(con, inc["id"])

        # Alerta temprana: se completa y genera de inmediato, sin intervención
        _generar(con, inc, "alerta_temprana", reportes.campos_automaticos("alerta_temprana", inc),
                 datetime.now() if not demo else ahora, "centinela")
        con.commit()
        # Correo al delegado con la alerta adjunta (no detiene el flujo si falla)
        notificador.notificar(con, inc["id"], "incidente")
        return inc["id"]


def _agrupar(con, inc: dict, t_contencion: datetime, ev: dict, demo: bool) -> str:
    """Agrega un nuevo bloqueo de la misma IP al incidente abierto."""
    bloqueos = (inc.get("bloqueos") or []) + [db.a_texto(t_contencion)]
    evidencia = ((inc.get("evidencia") or []) + ev["lineas"])[:MAX_EVIDENCIA]
    usuarios = set(inc.get("usuarios") or []) | set(ev["usuarios"])
    accesos = (inc.get("accesos_exitosos") or []) + ev["accesos"]
    intentos = (inc.get("intentos") or 0) + ev["intentos"]
    detalle = dict(inc.get("detalle") or {})
    for k in ("peticiones", "errores"):
        if k in ev["detalle"]:
            detalle[k] = detalle.get(k, 0) + ev["detalle"][k]
    for k in ("herramientas", "agentes", "rutas"):
        if k in ev["detalle"]:
            detalle[k] = sorted(set(detalle.get(k, [])) | set(ev["detalle"][k]))[:30]
    if ev["detalle"].get("expuestas"):
        vistas = {e[0] for e in detalle.get("expuestas", [])}
        detalle["expuestas"] = (detalle.get("expuestas", [])
                                + [e for e in ev["detalle"]["expuestas"] if e[0] not in vistas])[:30]

    clas = _clasificar(inc["jail"], intentos, usuarios, accesos, detalle)
    cambios = {"bloqueos": bloqueos, "ultimo_bloqueo": t_contencion, "evidencia": evidencia,
               "hash_evidencia": auditoria.sha256_texto(evidencia), "usuarios": sorted(usuarios),
               "accesos_exitosos": accesos, "intentos": intentos, "detalle": detalle,
               "justificacion": clas.justificacion}
    escalado = clas.subcategoria != inc["subcategoria"]
    if escalado:
        # El incidente se agravó (p. ej. hubo un acceso exitoso): se vuelve a
        # activar la alarma, se avisa por correo y la evaluación de efecto
        # significativo debe hacerse de nuevo con los antecedentes nuevos.
        cambios.update({"categoria": clas.categoria, "subcategoria": clas.subcategoria,
                        "impacto": clas.impacto, "requiere_revision": int(clas.requiere_revision),
                        "reconocido": None, "evaluacion": None})
    db.actualizar_incidente(con, inc["id"], cambios)
    auditoria.registrar(con, "centinela", "reincidencia_agrupada", inc["id"],
                        f"bloqueo {len(bloqueos)} a las {t_contencion:%H:%M:%S}; intentos acumulados={intentos}")
    if escalado:
        auditoria.registrar(con, "centinela", "incidente_escalado", inc["id"],
                            f"{inc['subcategoria']} -> {clas.subcategoria}"
                            + ("; se reinicia la evaluación de efecto significativo" if inc.get("evaluacion") else ""))
        _regenerar_alerta(con, inc["id"])
        con.commit()
        notificador.notificar(con, inc["id"], "escalamiento")
    return inc["id"]


def _generar(con, inc: dict, tipo: str, campos: dict, generado: datetime, usuario: str) -> str:
    vence = plazos.vencimiento(inc, db.reportes_de(con, inc["id"]), tipo)
    ruta = reportes.generar_pdf(tipo, inc, campos, generado, vence)
    huella = auditoria.sha256_archivo(ruta)
    db.guardar_reporte(con, inc["id"], tipo, campos, generado, str(ruta), huella)
    auditoria.registrar(con, usuario, "reporte_generado", inc["id"], f"{tipo}; pdf_sha256={huella}")
    return str(ruta)


def _regenerar_alerta(con, inc_id: str, usuario: str = "centinela"):
    """Actualiza el PDF de la alerta temprana mientras no se haya enviado (p. ej. tras
    evaluar el incidente o tras un escalamiento). Conserva los campos que el
    operador ya editó y la marca 'generado' (TTN)."""
    rep = db.reportes_de(con, inc_id).get("alerta_temprana")
    if not rep or rep["enviado"]:
        return
    inc = db.obtener_incidente(con, inc_id)
    campos = reportes.campos_automaticos("alerta_temprana", inc)
    # Los campos que dependen del estado del incidente se recalculan; el resto
    # conserva lo guardado (incluido lo que el operador haya editado a mano).
    dinamicos = {"evaluacion", "tipo_incidente", "indicios", "estado", "contencion", "fecha_inicio"}
    campos.update({k: v for k, v in rep["campos"].items() if k not in dinamicos and v})
    _generar(con, inc, "alerta_temprana", campos, rep["generado"], usuario)


def evaluar(inc_id: str, form: dict, usuario: str) -> dict:
    """Registra la evaluación de efecto significativo hecha por el delegado (DS 295, art. 3.º)."""
    ev = significancia.validar(form)          # ValueError si falta algo
    with db.conexion() as con:
        inc = db.obtener_incidente(con, inc_id)
        if inc is None:
            raise KeyError(inc_id)
        propuesta = significancia.proponer(inc)
        ev = significancia.sello(ev | {"propuesta": propuesta["propuesta"]}, usuario)
        db.actualizar_incidente(con, inc_id, {"evaluacion": ev})
        difiere = " (distinta de la propuesta automática)" if ev["decision"] != propuesta["propuesta"] else ""
        auditoria.registrar(con, usuario, "evaluacion_significancia", inc_id,
                            f"{significancia.resumen(ev)}{difiere} Justificación: {ev['justificacion']}")
        _regenerar_alerta(con, inc_id, usuario)
    return ev


def _fecha_form(texto: str | None) -> datetime | None:
    if not texto:
        return None
    try:
        return datetime.fromisoformat(texto.strip())
    except ValueError:
        raise ValueError(f"Fecha no válida: {texto}")


def registrar_manual(form: dict, usuario: str, ahora: datetime | None = None) -> str:
    """Incidente que no detectó Fail2ban (p. ej. ransomware, caída de servicio, aviso de un
    proveedor). Sigue el mismo flujo de clasificación, plazos, reportes y avisos."""
    ahora = ahora or datetime.now()
    conocimiento = _fecha_form(form.get("conocimiento")) or ahora
    inicio = _fecha_form(form.get("inicio"))
    if conocimiento > ahora + timedelta(minutes=5):
        raise ValueError("La fecha de conocimiento no puede estar en el futuro.")
    if inicio and inicio > conocimiento:
        raise ValueError("El inicio estimado no puede ser posterior al conocimiento.")
    efecto, _, categoria = (form.get("clasificacion") or "").partition("|")
    if not taxonomia.es_valida(efecto, categoria):
        raise ValueError("Elija una categoría de la taxonomía (Res. Ex. N.º 7/2025).")
    descripcion = (form.get("descripcion") or "").strip()
    activos = (form.get("activos") or "").strip()
    if len(descripcion) < 20:
        raise ValueError("Describa el incidente (al menos 20 caracteres).")
    if not activos:
        raise ValueError("Indique los activos o servicios afectados (DS 295, art. 5.º g).")
    ip = (form.get("ip") or "").strip()
    if ip:
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            raise ValueError("La IP de origen no es válida (déjela en blanco si no se conoce).")
    indicios = form.get("indicios") or ""
    if indicios not in INDICIOS:
        raise ValueError("Elija el indicio principal (DS 295, art. 5.º f).")

    area = taxonomia.area_de(efecto)
    lineas = [f"{ahora:%Y-%m-%d %H:%M:%S} registro manual por '{usuario}': conocimiento "
              f"{conocimiento:%Y-%m-%d %H:%M}; {efecto} / {categoria}",
              f"Descripción: {descripcion}", f"Activos afectados: {activos}"]
    with db.conexion() as con:
        inc = {
            "id": db.nuevo_id(con, conocimiento),
            "ip": ip,
            "jail": "manual",
            "t0": inicio,
            "t_deteccion": conocimiento,
            "t_contencion": None,
            "t_registro": ahora,
            "intentos": 0,
            "usuarios": [],
            "accesos_exitosos": [],
            "categoria": efecto,
            "subcategoria": categoria,
            "escenario": "manual",
            "impacto": area,
            "justificacion": [f"Clasificación asignada por '{usuario}' según el efecto observable descrito "
                              f"({taxonomia.BASE_LEGAL}).",
                              f"Área: {area} · Efecto: {efecto} · Categoría: {categoria}."],
            "requiere_revision": 0,
            "evidencia": lineas,
            "hash_evidencia": auditoria.sha256_texto(lineas),
            "bloqueos": [],
            "detalle": {"descripcion": descripcion, "activos": activos, "indicios": indicios,
                        "contencion": (form.get("contencion") or "").strip(), "registrado_por": usuario},
            "reconocido": ahora,       # quien lo registra ya tomó conocimiento: no suena la alarma
            "demo": 0,
        }
        db.guardar_incidente(con, inc)
        auditoria.registrar(con, usuario, "incidente_registrado_manual", inc["id"],
                            f"{categoria}; conocimiento={conocimiento:%Y-%m-%d %H:%M}; "
                            f"evidencia_sha256={inc['hash_evidencia']}")
        inc = db.obtener_incidente(con, inc["id"])
        _generar(con, inc, "alerta_temprana", reportes.campos_automaticos("alerta_temprana", inc), ahora, usuario)
        con.commit()
        notificador.notificar(con, inc["id"], "incidente")
        return inc["id"]


def generar_reporte(inc_id: str, tipo: str, campos_operador: dict, usuario: str = "operador") -> str:
    """Genera (o regenera) un reporte combinando campos automáticos y del operador."""
    with db.conexion() as con:
        inc = db.obtener_incidente(con, inc_id)
        if inc is None:
            raise KeyError(inc_id)
        campos = reportes.campos_automaticos(tipo, inc)
        campos.update({k: v for k, v in campos_operador.items()
                       if k in dict(reportes.CAMPOS[tipo]) and v and v.strip()})
        return _generar(con, inc, tipo, campos, datetime.now(), usuario)


def verificar_reportes(con) -> list:
    """Compara la huella guardada de cada PDF con el archivo en disco."""
    out = []
    for r in con.execute("SELECT incidente_id, tipo, ruta_pdf, hash_pdf FROM reportes ORDER BY incidente_id"):
        actual = auditoria.sha256_archivo(r["ruta_pdf"]) if r["ruta_pdf"] else None
        out.append({"incidente_id": r["incidente_id"], "tipo": r["tipo"], "ruta": r["ruta_pdf"],
                    "integro": bool(r["hash_pdf"]) and actual == r["hash_pdf"],
                    "existe": actual is not None})
    return out
