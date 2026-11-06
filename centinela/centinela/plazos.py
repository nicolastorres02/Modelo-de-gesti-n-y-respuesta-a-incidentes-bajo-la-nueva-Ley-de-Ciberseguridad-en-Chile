"""Plazos legales de reporte al CSIRT Nacional (Ley N.º 21.663, art. 9.º; DS 295/2024, arts. 9 a 12).

Desde cuándo corre cada plazo (texto del Reglamento):

- Alerta temprana: 3 horas desde que se toma conocimiento del incidente (art. 9.º).
- Segundo reporte: 72 horas desde el conocimiento; 24 horas si la institución es
  un operador de importancia vital (OIV) y se vio afectada la prestación de sus
  servicios esenciales (art. 10).
- Plan de acción: solo OIV, 7 días corridos desde el conocimiento (art. 11).
- Informe final: 15 días corridos *desde el envío de la alerta temprana* (art. 12).
  Mientras la alerta no se envía, se muestra un vencimiento provisional contado
  desde el conocimiento (el más exigente posible).

En Centinela el conocimiento es la alerta de Fail2ban (o la fecha que registra
el operador en un incidente manual). Si el delegado evalúa que el incidente no
es reportable (DS 295, art. 3.º), los plazos dejan de aplicar.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta

from . import config

# (clave, nombre, base legal)
REPORTES = [
    ("alerta_temprana", "Alerta temprana", "DS 295/2024, art. 9.º"),
    ("segundo_reporte", "Segundo reporte", "DS 295/2024, art. 10"),
    ("plan_accion", "Plan de acción", "DS 295/2024, art. 11"),
    ("informe_final", "Informe final", "DS 295/2024, art. 12"),
]
NOMBRES = {clave: nombre for clave, nombre, _ in REPORTES}
BASE_LEGAL = {clave: base for clave, _, base in REPORTES}


def duracion_plazo(clave: str, servicio_esencial: bool | None = None) -> timedelta:
    """servicio_esencial: OIV con servicios esenciales afectados (segundo reporte a 24 h)."""
    if servicio_esencial is None:
        servicio_esencial = config.ES_OIV and config.SERVICIO_ESENCIAL
    return {
        "alerta_temprana": timedelta(hours=3),
        "segundo_reporte": timedelta(hours=24 if servicio_esencial else 72),
        "plan_accion": timedelta(days=7),
        "informe_final": timedelta(days=15),
    }[clave]


@dataclass
class EstadoPlazo:
    clave: str
    nombre: str
    vence: datetime | None
    enviado: datetime | None
    estado: str          # enviado | enviado_tarde | pendiente | por_vencer | vencido | no_aplica
    restante_s: float    # segundos restantes (negativo si venció)
    desde: str = ""      # desde cuándo se cuenta el plazo
    provisional: bool = False
    motivo: str = ""     # por qué no aplica

    @property
    def aplica(self) -> bool:
        return self.estado != "no_aplica"


def estado_plazo(clave: str, conocimiento: datetime, enviado: datetime | None,
                 ahora: datetime | None = None, servicio_esencial: bool | None = None,
                 base: datetime | None = None) -> EstadoPlazo:
    """Estado de un plazo contado desde 'base' (por defecto, el conocimiento)."""
    ahora = ahora or datetime.now()
    plazo = duracion_plazo(clave, servicio_esencial)
    vence = (base or conocimiento) + plazo
    restante = (vence - ahora).total_seconds()
    if enviado:
        estado = "enviado" if enviado <= vence else "enviado_tarde"
    elif restante < 0:
        estado = "vencido"
    elif restante <= plazo.total_seconds() * 0.25:
        estado = "por_vencer"
    else:
        estado = "pendiente"
    return EstadoPlazo(clave, NOMBRES[clave], vence, enviado, estado, restante)


def _no_aplica(clave: str, motivo: str, enviado=None) -> EstadoPlazo:
    return EstadoPlazo(clave, NOMBRES[clave], None, enviado, "no_aplica", 0.0, motivo=motivo)


def segundo_reporte_24h(inc: dict) -> bool:
    """24 h solo si es OIV y el servicio esencial se vio afectado (DS 295, art. 10)."""
    if not config.ES_OIV:
        return False
    ev = inc.get("evaluacion")
    if ev:
        return "a" in (ev.get("criterios") or [])
    return config.SERVICIO_ESENCIAL     # sin evaluar: supuesto configurado (el más exigente)


def plazos_incidente(inc: dict, reps: dict, ahora: datetime | None = None) -> list:
    """Los cuatro plazos del incidente, con las reglas del DS 295/2024."""
    ahora = ahora or datetime.now()
    conocimiento = inc["t_deteccion"]
    ev = inc.get("evaluacion")
    enviado = {k: (reps.get(k) or {}).get("enviado") for k, _, _ in REPORTES}

    if ev and ev.get("decision") == "no_reportable":
        motivo = "Evaluado como no reportable (DS 295/2024, art. 3.º)"
        return [_no_aplica(k, motivo, enviado[k]) for k, _, _ in REPORTES]

    out = []
    alerta = estado_plazo("alerta_temprana", conocimiento, enviado["alerta_temprana"], ahora)
    alerta.desde = "conocimiento del incidente"
    out.append(alerta)

    es24 = segundo_reporte_24h(inc)
    segundo = estado_plazo("segundo_reporte", conocimiento, enviado["segundo_reporte"], ahora, es24)
    if es24 and not ev:
        segundo.desde = "conocimiento (24 h: se supone servicio esencial afectado hasta evaluar)"
    elif es24:
        segundo.desde = "conocimiento (24 h: OIV con servicio esencial afectado)"
    else:
        segundo.desde = "conocimiento (72 h)"
    out.append(segundo)

    if config.ES_OIV:
        plan = estado_plazo("plan_accion", conocimiento, enviado["plan_accion"], ahora)
        plan.desde = "conocimiento del incidente"
        out.append(plan)
    else:
        out.append(_no_aplica("plan_accion", "Solo para operadores de importancia vital (DS 295, art. 11)",
                              enviado["plan_accion"]))

    base_final = enviado["alerta_temprana"]
    final = estado_plazo("informe_final", conocimiento, enviado["informe_final"], ahora,
                         base=base_final or conocimiento)
    final.desde = "envío de la alerta temprana" if base_final else "conocimiento (provisional: alerta aún no enviada)"
    final.provisional = base_final is None
    out.append(final)
    return out


def vencimiento(inc: dict, reps: dict, clave: str) -> datetime | None:
    return next(p.vence for p in plazos_incidente(inc, reps) if p.clave == clave)
