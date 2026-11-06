"""Estado del sistema: comprobaciones que muestra el panel para que una falla
de la integración (Fail2ban detenido, acción quitada, reloj desfasado, correo
caído) no pase inadvertida."""
import os
import ssl
import subprocess
from datetime import datetime
from pathlib import Path

from . import auditoria, config, db, notificador


def _cmd(*args, timeout=5):
    try:
        r = subprocess.run(list(args), capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or r.stderr).strip()
    except (OSError, subprocess.SubprocessError):
        return None, ""


def _item(nombre, ok, detalle):
    # ok: True (bien), False (problema), None (no se pudo comprobar)
    return {"nombre": nombre, "ok": ok, "detalle": detalle}


def comprobar() -> list:
    items = []

    rc, out = _cmd("fail2ban-client", "ping")
    if rc is None:
        items.append(_item("Fail2ban en ejecución", None, "fail2ban-client no disponible en este equipo"))
        fail2ban_ok = False
    else:
        fail2ban_ok = rc == 0 and "pong" in out
        items.append(_item("Fail2ban en ejecución", fail2ban_ok, out or "sin respuesta"))

    for jail in config.JAULAS:
        if not fail2ban_ok:
            items.append(_item(f"Jaula '{jail}' conectada a Centinela", None, "Fail2ban no responde"))
            continue
        rc, out = _cmd("fail2ban-client", "get", jail, "actions")
        if rc != 0:
            items.append(_item(f"Jaula '{jail}' conectada a Centinela", False, out or "jaula no activa"))
        else:
            items.append(_item(f"Jaula '{jail}' conectada a Centinela", "centinela" in out,
                               out.replace("\n", " ")))

    rc, out = _cmd("timedatectl", "show", "-p", "NTPSynchronized", "--value")
    if rc is None:
        items.append(_item("Reloj sincronizado (NTP)", None, "timedatectl no disponible"))
    else:
        _, zona = _cmd("timedatectl", "show", "-p", "Timezone", "--value")
        items.append(_item("Reloj sincronizado (NTP)", out == "yes", f"NTPSynchronized={out}; zona={zona}"))

    for nombre, ruta in (("auth.log", config.AUTH_LOG), ("fail2ban.log", config.FAIL2BAN_LOG),
                         ("access.log (Apache)", config.ACCESS_LOG)):
        p = Path(ruta)
        legible = p.exists() and os.access(p, os.R_OK)
        items.append(_item(f"Bitácora {nombre} legible", legible, str(p)))

    if notificador.canal_activo():
        detalle = f"{config.SMTP_HOST}:{config.SMTP_PUERTO} → {', '.join(config.CORREO_PARA)}"
        with db.conexion() as con:
            ultima = con.execute("SELECT estado, error, ultimo_intento FROM notificaciones "
                                 "WHERE canal = 'correo' AND estado != 'desactivado' "
                                 "ORDER BY ultimo_intento DESC LIMIT 1").fetchone()
        if ultima and ultima["estado"] == "error":
            items.append(_item("Correo al delegado", False, f"{detalle}; último error: {ultima['error']}"))
        else:
            items.append(_item("Correo al delegado", True, detalle))
    else:
        items.append(_item("Correo al delegado", False, "No configurado: los avisos solo se ven en el panel"))

    faltan = [n for n, v in (("RUT", config.ORG_RUT), ("dirección", config.ORG_DIRECCION),
                             ("correo institucional", config.ORG_CORREO),
                             ("correo del delegado", config.DELEGADO_CORREO),
                             ("teléfono del delegado", config.DELEGADO_TELEFONO)) if not v]
    items.append(_item("Datos de la institución y del delegado (DS 295, art. 5.º a y b)", not faltan,
                       f"{config.ORGANIZACION} · {'OIV' if config.ES_OIV else 'no OIV'}"
                       + (f" · faltan: {', '.join(faltan)} (/etc/centinela/centinela.env)" if faltan else "")))

    if config.TLS_CERT and Path(config.TLS_CERT).exists():
        try:
            info = ssl._ssl._test_decode_cert(config.TLS_CERT)
            vence = datetime.fromtimestamp(ssl.cert_time_to_seconds(info["notAfter"]))
            dias = (vence - datetime.now()).days
            items.append(_item("Certificado HTTPS del panel", dias > 30, f"vence el {vence:%d-%m-%Y} ({dias} días)"))
        except Exception as e:  # certificado ilegible
            items.append(_item("Certificado HTTPS del panel", False, f"no se pudo leer: {e}"))
    else:
        items.append(_item("Certificado HTTPS del panel", False, "Panel sin HTTPS"))

    with db.conexion() as con:
        cadena = auditoria.verificar(con)
        items.append(_item("Bitácora de auditoría íntegra", cadena["integra"],
                           f"{cadena['registros']} registros" +
                           ("" if cadena["integra"] else f"; alterada en el registro {cadena['falla_en']}")))
        errores = con.execute("SELECT COUNT(*) FROM bitacora WHERE accion = 'error_procesamiento' "
                              "AND ts >= datetime('now', 'localtime', '-1 day')").fetchone()[0]
        items.append(_item("Errores de procesamiento (24 h)", errores == 0, f"{errores} error(es)"))
        ultimo = con.execute("SELECT MAX(t_registro) FROM incidentes").fetchone()[0]
        items.append(_item("Último incidente recibido", True, ultimo[:19] if ultimo else "ninguno todavía"))
    return items
