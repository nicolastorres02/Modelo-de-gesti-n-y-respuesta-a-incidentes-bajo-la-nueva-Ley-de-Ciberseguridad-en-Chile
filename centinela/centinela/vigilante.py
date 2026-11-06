"""Vigilante: revisa cada minuto los plazos legales y reintenta correos fallidos.

Corre como hilo dentro del servicio del panel. Por cada reporte pendiente de
un incidente abierto avisa una sola vez cuando entra en 'por vencer' (último
25 % del plazo) y otra cuando vence.
"""
import threading
import time
import traceback
from datetime import datetime

from . import auditoria, config, db, notificador, plazos

INTERVALO_S = 60


def revisar(ahora: datetime | None = None) -> list:
    """Una pasada del vigilante. Devuelve las notificaciones intentadas."""
    ahora = ahora or datetime.now()
    intentadas = []
    with db.conexion() as con:
        for inc in db.listar_incidentes(con):
            if inc["estado"] != "abierto" or not inc["t_deteccion"]:
                continue
            reps = db.reportes_de(con, inc["id"])
            # Los plazos que no aplican (no reportable, o plan de acción de un no OIV) se omiten
            for e in plazos.plazos_incidente(inc, reps, ahora):
                if e.estado not in ("por_vencer", "vencido"):
                    continue
                motivo = f"plazo:{e.clave}:{e.estado}"
                if db.notificacion(con, inc["id"], motivo) is None:
                    auditoria.registrar(con, "centinela", f"plazo_{e.estado}", inc["id"], e.nombre)
                    intentadas.append((inc["id"], motivo, notificador.notificar(con, inc["id"], motivo)))
        # Reintento de correos que fallaron (p. ej. servidor de correo caído)
        for n in db.notificaciones_fallidas(con, config.CORREO_REINTENTOS):
            if n["ultimo_intento"] and (ahora - n["ultimo_intento"]).total_seconds() < INTERVALO_S:
                continue
            intentadas.append((n["incidente_id"], n["motivo"],
                               notificador.notificar(con, n["incidente_id"], n["motivo"])))
    return intentadas


def iniciar_en_segundo_plano():
    def bucle():
        while True:
            try:
                revisar()
            except Exception:  # el vigilante no debe detener el panel
                traceback.print_exc()
            time.sleep(INTERVALO_S)
    hilo = threading.Thread(target=bucle, name="vigilante", daemon=True)
    hilo.start()
    return hilo
