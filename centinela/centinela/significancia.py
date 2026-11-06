"""Evaluación del deber de reportar: ¿el incidente puede tener efecto significativo?

La Ley N.º 21.663 (arts. 9.º y 27) y el DS 295/2024 (arts. 2.º y 3.º) obligan a
reportar al CSIRT Nacional los incidentes que *puedan tener efectos
significativos*. Centinela propone una evaluación a partir de la evidencia, pero
la decisión la toma y firma el delegado de ciberseguridad en el panel: queda
registrada en la bitácora con su justificación.

Mientras el incidente no se evalúa, los plazos corren igual (el de la alerta
temprana empieza con el conocimiento del incidente, DS 295 art. 9.º).
"""
from datetime import datetime

BASE_LEGAL = "DS 295/2024, art. 3.º; Ley N.º 21.663, art. 27"

# Letras del DS 295/2024, art. 3.º (texto literal)
CRITERIOS = [
    ("a", "Interrumpir la continuidad de un servicio esencial (considerando también los servicios "
          "entregados por proveedores y la cadena de suministro)."),
    ("b", "Afectar la integridad física o la salud de las personas."),
    ("c", "Afectar la integridad o confidencialidad de activos informáticos, o la disponibilidad de "
          "alguna red o sistema informático, aun cuando esto no produzca o hubiere producido "
          "afectación inmediata en la provisión del servicio."),
    ("d", "Utilizar o ingresar sin autorización a redes o sistemas informáticos, aun cuando esto no "
          "produzca o hubiere producido afectación inmediata en la provisión del servicio."),
    ("e", "Afectar sistemas informáticos que contengan datos personales."),
]
LETRAS = [l for l, _ in CRITERIOS]
TEXTO = dict(CRITERIOS)

# Motivos habituales para no reportar (se exige además una justificación escrita)
MOTIVOS_NO_REPORTE = [
    ("intento_contenido", "Intento contenido sin efecto observable (no se cumple ningún criterio del art. 3.º)"),
    ("falso_positivo", "Falso positivo: la actividad era legítima"),
    ("mantencion", "Mantención planificada: no se considera incidente (DS 295, art. 4.º)"),
    ("otro", "Otro motivo (detallar en la justificación)"),
]

# Áreas de la taxonomía -> criterio del art. 3.º que se cumple normalmente
_POR_AREA = {
    "Impacto en el uso legítimo de recursos": "d",
    "Impacto en la confidencialidad de la información": "c",
    "Impacto en la disponibilidad de un servicio esencial": "c",
    "Impacto en la integridad de la información": "c",
}


def proponer(inc: dict) -> dict:
    """Propuesta automática: criterios que la evidencia permite dar por cumplidos."""
    criterios, fundamentos = set(), []
    if inc.get("accesos_exitosos"):
        criterios.add("d")
        fundamentos.append("Se registró un inicio de sesión exitoso desde la IP atacante: ingreso sin "
                           "autorización a un sistema (letra d).")
    expuestas = (inc.get("detalle") or {}).get("expuestas") or []
    if expuestas:
        criterios.add("c")
        fundamentos.append(f"El servidor entregó {len(expuestas)} recurso(s) sensible(s): afectación de la "
                           f"confidencialidad de activos informáticos (letra c).")
    area = inc.get("impacto")
    if area in _POR_AREA and not criterios:
        criterios.add(_POR_AREA[area])
        fundamentos.append(f"El efecto observable registrado pertenece al área «{area}» (letra "
                           f"{_POR_AREA[area]}).")
    if (inc.get("subcategoria") or "") == "Filtración de datos personales":
        criterios.add("e")
        fundamentos.append("La categoría indica filtración de datos personales (letra e).")
    if (inc.get("impacto") or "") == "Impacto en la disponibilidad de un servicio esencial":
        fundamentos.append("Si el servicio esencial se interrumpió, marque también la letra a.")

    if criterios:
        propuesta = "reportable"
    else:
        propuesta = "no_reportable"
        fundamentos.append("No hay evidencia de ingreso, exposición, interrupción ni afectación de datos: el "
                           "intento fue contenido por Fail2ban antes de producir un efecto. Si existen "
                           "antecedentes adicionales (p. ej. campaña sostenida o afectación de "
                           "disponibilidad), el delegado puede decidir reportarlo.")
    return {"criterios": sorted(criterios), "propuesta": propuesta, "fundamentos": fundamentos}


def validar(form: dict) -> dict:
    """Convierte el formulario del panel en una evaluación. Lanza ValueError si falta algo."""
    decision = form.get("decision")
    if decision not in ("reportable", "no_reportable"):
        raise ValueError("Indique si el incidente es reportable o no.")
    criterios = sorted(l for l in LETRAS if form.get(f"criterio_{l}"))
    justificacion = (form.get("justificacion") or "").strip()
    motivo = form.get("motivo") or ""
    if decision == "reportable" and not criterios:
        raise ValueError("Para declararlo reportable marque al menos un criterio del art. 3.º.")
    if decision == "no_reportable":
        if motivo not in dict(MOTIVOS_NO_REPORTE):
            raise ValueError("Indique el motivo por el que no se reporta.")
        if criterios:
            raise ValueError("Marcó criterios de efecto significativo: si se cumple alguno, el incidente "
                             "es reportable.")
    if len(justificacion) < 15:
        raise ValueError("Escriba una justificación (al menos 15 caracteres): queda en la bitácora.")
    return {
        "decision": decision,
        "criterios": criterios,
        "motivo": motivo if decision == "no_reportable" else "",
        "personas_afectadas": (form.get("personas_afectadas") or "").strip()[:100],
        "duracion": (form.get("duracion") or "").strip()[:100],
        "extension_geografica": (form.get("extension_geografica") or "").strip()[:150],
        "justificacion": justificacion[:2000],
    }


def resumen(ev: dict | None) -> str:
    """Texto breve para reportes, correos y bitácora."""
    if not ev:
        return "Pendiente de evaluación por el delegado de ciberseguridad."
    if ev["decision"] == "reportable":
        letras = ", ".join(f"{l})" for l in ev["criterios"])
        return f"Reportable: cumple el DS 295/2024, art. 3.º, letra(s) {letras}."
    return f"No reportable: {dict(MOTIVOS_NO_REPORTE).get(ev.get('motivo'), ev.get('motivo'))}."


def servicio_esencial_afectado(ev: dict | None) -> bool | None:
    """Letra a) marcada -> el segundo reporte de un OIV vence a las 24 h (DS 295, art. 10)."""
    if not ev:
        return None
    return "a" in ev["criterios"]


def sello(ev: dict, usuario: str, cuando: datetime | None = None) -> dict:
    return ev | {"usuario": usuario, "fecha": (cuando or datetime.now()).isoformat(sep=" ", timespec="seconds")}
