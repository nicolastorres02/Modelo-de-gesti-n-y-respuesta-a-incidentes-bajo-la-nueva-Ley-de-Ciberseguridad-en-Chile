"""Notificación por correo electrónico al delegado de ciberseguridad.

Así el aviso llega aunque nadie tenga el panel abierto. Cada envío queda
registrado (tabla notificaciones y bitácora). Si falla, el vigilante lo
reintenta hasta CORREO_REINTENTOS veces.

Motivos:
    incidente                 nuevo incidente, con la alerta temprana adjunta
    escalamiento              el incidente se agravó (p. ej. acceso exitoso)
    plazo:<reporte>:<etapa>   un reporte a la ANCI está por vencer o venció
"""
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path

from . import auditoria, config, db, plazos, significancia


def canal_activo() -> bool:
    return bool(config.SMTP_HOST and config.CORREO_PARA)


def _enviar(asunto: str, cuerpo: str, adjuntos: list):
    msg = EmailMessage()
    msg["Subject"] = asunto
    msg["From"] = config.CORREO_DE
    msg["To"] = ", ".join(config.CORREO_PARA)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="centinela")
    msg["X-Priority"] = "1"
    msg.set_content(cuerpo)
    for ruta in adjuntos:
        p = Path(ruta)
        if p.exists():
            msg.add_attachment(p.read_bytes(), maintype="application", subtype="pdf", filename=p.name)

    contexto = ssl.create_default_context()
    if config.SMTP_SEGURIDAD == "ssl":
        servidor = smtplib.SMTP_SSL(config.SMTP_HOST, config.SMTP_PUERTO, timeout=20, context=contexto)
    else:
        servidor = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PUERTO, timeout=20)
    with servidor:
        if config.SMTP_SEGURIDAD == "starttls":
            servidor.starttls(context=contexto)
        if config.SMTP_USUARIO:
            servidor.login(config.SMTP_USUARIO, config.SMTP_CLAVE)
        servidor.send_message(msg)


def _mensaje(con, inc: dict, motivo: str) -> tuple[str, str, list]:
    reps = db.reportes_de(con, inc["id"])
    enlace = f"{config.URL_PANEL}/incidente/{inc['id']}"
    manual = inc.get("escenario") == "manual"
    resumen = (f"Incidente:      {inc['id']}\n"
               f"Área:           {inc['impacto']}\n"
               f"Efecto:         {inc['categoria']}\n"
               f"Categoría:      {inc['subcategoria']}\n"
               f"IP de origen:   {inc['ip'] or 'no identificada'}\n"
               + (f"Origen:         registro manual en el panel\n" if manual else
                  f"Servicio:       jaula '{inc['jail']}' en {config.NOMBRE_HOST}\n")
               + f"Conocimiento:   {inc['t_deteccion']:%d-%m-%Y %H:%M:%S}\n"
               + ("" if manual else
                  "Estado:         IP bloqueada por Fail2ban; cuenta posiblemente comprometida\n"
                  if inc.get("accesos_exitosos") else
                  "Estado:         Contenido (IP bloqueada por Fail2ban)\n")
               + f"Evaluación:     {significancia.resumen(inc.get('evaluacion'))}\n")
    venc = "\n".join(
        f"  - {p.nombre}: " + (f"vence el {p.vence:%d-%m-%Y %H:%M}" + (" (provisional)" if p.provisional else "")
                               if p.aplica else f"no aplica ({p.motivo})")
        for p in plazos.plazos_incidente(inc, reps))

    if motivo == "incidente":
        propuesta = significancia.proponer(inc)
        ev = inc.get("evaluacion")
        if ev:
            accion = (f"Evaluación registrada por {ev.get('usuario')} el {str(ev.get('fecha', ''))[:16]}: "
                      f"{significancia.resumen(ev)}\n\n")
        else:
            accion = (f"ACCIÓN REQUERIDA: evalúe en el panel si el incidente puede tener efecto significativo "
                      f"(DS 295/2024, art. 3.º). Propuesta automática: "
                      f"{'REPORTABLE' if propuesta['propuesta'] == 'reportable' else 'no reportable'}.\n\n")
        asunto = f"[Centinela] Nuevo incidente {inc['id']} — {inc['subcategoria']} — IP {inc['ip'] or 'no identificada'}"
        cuerpo = (f"Centinela {'registró' if manual else 'detectó y contuvo'} un incidente de ciberseguridad.\n\n"
                  f"{resumen}\n{accion}"
                  f"Se adjunta el borrador de alerta temprana generado automáticamente.\n\n"
                  f"Plazos de reporte al CSIRT Nacional (Ley N.º 21.663, art. 9.º; DS 295/2024):\n{venc}\n\n"
                  f"Revise el incidente en el panel: {enlace}\n")
        adjuntos = [reps["alerta_temprana"]["ruta_pdf"]] if "alerta_temprana" in reps else []
    elif motivo == "escalamiento":
        asunto = f"[Centinela] ESCALAMIENTO {inc['id']} — {inc['subcategoria']}"
        cuerpo = (f"El incidente {inc['id']} cambió de clasificación y requiere revisión inmediata.\n\n"
                  f"{resumen}\nRevise el incidente en el panel: {enlace}\n")
        adjuntos = []
    else:
        _, clave, etapa = motivo.split(":")
        vence = plazos.vencimiento(inc, reps, clave) or inc["t_deteccion"]
        texto = "VENCIÓ" if etapa == "vencido" else "está por vencer"
        asunto = f"[Centinela] {plazos.NOMBRES[clave]} de {inc['id']} {texto}"
        cuerpo = (f"El reporte '{plazos.NOMBRES[clave]}' del incidente {inc['id']} {texto}.\n"
                  f"Plazo legal ({plazos.BASE_LEGAL[clave]}): {vence:%d-%m-%Y %H:%M}\n\n"
                  f"{resumen}\nComplete y envíe el reporte desde el panel: {enlace}\n")
        adjuntos = []
    return asunto, cuerpo, adjuntos


def notificar(con, inc_id: str, motivo: str) -> str:
    """Envía (o reintenta) una notificación. Devuelve 'enviado', 'error' o 'desactivado'."""
    previa = db.notificacion(con, inc_id, motivo)
    if previa and previa["estado"] in ("enviado", "desactivado"):
        return previa["estado"]
    if not canal_activo():
        # Se registra igual, para que el panel muestre que no hubo correo
        db.registrar_notificacion(con, inc_id, motivo, "desactivado", "Correo no configurado")
        return "desactivado"
    inc = db.obtener_incidente(con, inc_id)
    if inc is None:
        return "error"
    asunto, cuerpo, adjuntos = _mensaje(con, inc, motivo)
    try:
        _enviar(asunto, cuerpo, adjuntos)
    except (OSError, smtplib.SMTPException) as e:
        db.registrar_notificacion(con, inc_id, motivo, "error", f"{type(e).__name__}: {e}")
        auditoria.registrar(con, "centinela", "correo_error", inc_id, f"{motivo}: {e}")
        return "error"
    db.registrar_notificacion(con, inc_id, motivo, "enviado", None)
    auditoria.registrar(con, "centinela", "correo_enviado", inc_id,
                        f"{motivo} a {', '.join(config.CORREO_PARA)}")
    return "enviado"


def probar() -> str:
    """Envía un correo de prueba. Devuelve un mensaje para el operador."""
    if not canal_activo():
        return "El correo no está configurado (CENTINELA_SMTP_HOST y CENTINELA_CORREO_PARA)."
    try:
        _enviar("[Centinela] Correo de prueba",
                f"Este es un correo de prueba de Centinela en {config.NOMBRE_HOST}.\n"
                f"Si lo recibe, las notificaciones de incidentes llegarán a esta casilla.\n", [])
    except (OSError, smtplib.SMTPException) as e:
        return f"Error al enviar: {type(e).__name__}: {e}"
    return f"Correo de prueba enviado a {', '.join(config.CORREO_PARA)} vía {config.SMTP_HOST}:{config.SMTP_PUERTO}."
