"""Clasificación automática según la taxonomía oficial de la ANCI (Res. Ex. N.º 7/2025).

La resolución clasifica cada incidente por su *efecto observable* (art. 2.º)
dentro de cuatro áreas de impacto, once efectos y sus categorías (arts. 3.º y
4.º; ver taxonomia.py). Centinela deduce el efecto de la evidencia de las bitácoras:

- Fuerza bruta SSH con un acceso exitoso desde la IP atacante
    -> Uso no autorizado de redes y sistemas informáticos / Ataque de fuerza bruta exitoso
- Fuerza bruta SSH bloqueada sin acceso, o escaneo web sin recursos obtenidos
    -> sin efecto observable: el intento fue contenido antes de producir uno de
       los efectos de la taxonomía. Se registra y documenta igual, y el delegado
       evalúa si debe reportarse (DS 295/2024, art. 3.º; ver significancia.py).
- Escaneo web que obtuvo recursos sensibles (.git, .env, respaldos, configuraciones)
    -> Exfiltración y/o exposición de código fuente / configuraciones / datos

El campo 'categoria' guarda el efecto observable, 'subcategoria' la categoría y
'impacto' el área de impacto.
"""
from dataclasses import dataclass

from . import taxonomia

JAULAS_SSH = {"sshd", "ssh", "sshd-ddos"}
JAULAS_WEB = {"centinela-escaneo-web", "apache-noscript", "apache-badbots", "apache-botsearch",
              "apache-overflows", "apache-nohome", "nginx-botsearch"}

# Orden de gravedad para elegir la categoría cuando hay varias exposiciones
_PRIORIDAD = ["Filtración de secretos en rutas de aplicación",
              "Archivo(s) de control de versión expuestos en aplicación",
              "Documentos públicos con datos sensibles",
              "Filtración de configuraciones en rutas de aplicación"]


@dataclass
class Clasificacion:
    categoria: str          # efecto observable (Res. Ex. 7/2025, art. 3.º)
    subcategoria: str       # categoría (art. 4.º)
    escenario: str          # E1, E2 u "otro"
    impacto: str            # área de impacto (art. 3.º)
    justificacion: list     # respuestas de la lista de verificación
    requiere_revision: bool = False

    @property
    def con_efecto(self) -> bool:
        return self.categoria != taxonomia.SIN_EFECTO


def es_jaula_web(jail: str | None) -> bool:
    j = (jail or "").lower()
    return j in JAULAS_WEB or j.startswith("apache") or j.startswith("nginx")


def _sin_efecto(subcategoria: str, escenario: str, justificacion: list) -> Clasificacion:
    return Clasificacion(taxonomia.SIN_EFECTO, subcategoria, escenario, taxonomia.SIN_AREA, justificacion)


def clasificar(jail: str | None, intentos_fallidos: int = 0, usuarios=(), accesos_exitosos=(),
               web: dict | None = None) -> Clasificacion:
    jail = (jail or "").lower()

    if es_jaula_web(jail):
        web = web or {}
        herramientas = ", ".join(sorted(web.get("herramientas", []))) or "no identificada"
        justificacion = [
            f"Actividad observada: {web.get('peticiones', 0)} peticiones HTTP desde la misma IP, "
            f"{web.get('errores', 0)} de ellas a recursos inexistentes o prohibidos (4xx); "
            f"enumeración automatizada de recursos web (herramienta detectada: {herramientas}).",
        ]
        expuestas = web.get("expuestas") or []
        if expuestas:
            elegida = min(expuestas, key=lambda e: _PRIORIDAD.index(e[3]) if e[3] in _PRIORIDAD else 99)
            efecto, categoria = elegida[2], elegida[3]
            rutas = ", ".join(e[0] for e in expuestas[:6])
            justificacion += [
                f"¿Hubo un efecto observable? Sí: el servidor entregó con éxito (código 2xx) "
                f"{len(expuestas)} recurso(s) sensible(s): {rutas}.",
                f"Efecto: {efecto} → categoría «{categoria}» ({taxonomia.BASE_LEGAL}).",
                "Revisar el contenido expuesto y confirmar si incluye credenciales o datos personales.",
            ]
            return Clasificacion(efecto, categoria, "E2", taxonomia.area_de(efecto), justificacion,
                                 requiere_revision=True)
        justificacion += [
            "¿Hubo un efecto observable? No: el escaneo no obtuvo recursos sensibles y la IP fue "
            "bloqueada por Fail2ban.",
            "La Res. Ex. 7/2025 (art. 2.º) clasifica por efectos observables; el reconocimiento "
            "contenido no corresponde a ninguna de sus categorías. Se documenta como evento de "
            "seguridad y el delegado evalúa su reporte (DS 295/2024, art. 3.º).",
        ]
        return _sin_efecto("Escaneo de recursos web contenido por Fail2ban", "E2", justificacion)

    if jail in JAULAS_SSH or intentos_fallidos > 0:
        cuentas = len(set(usuarios))
        justificacion = [
            f"Actividad observada: {intentos_fallidos} intentos fallidos de autenticación SSH desde "
            f"la misma IP contra {cuentas} cuenta(s): adivinación automatizada de credenciales.",
        ]
        if accesos_exitosos:
            ultimo = list(accesos_exitosos)[-1]
            justificacion += [
                f"¿Hubo un efecto observable? Sí: inicio de sesión exitoso de la cuenta '{ultimo[1]}' "
                f"desde la IP atacante ({str(ultimo[0])[:19]}).",
                f"Efecto: Uso no autorizado de redes y sistemas informáticos → categoría «Ataque de "
                f"fuerza bruta exitoso» ({taxonomia.BASE_LEGAL}).",
                "Se presume compromiso de la cuenta: revisar la sesión y cambiar la contraseña.",
            ]
            efecto = "Uso no autorizado de redes y sistemas informáticos"
            return Clasificacion(efecto, "Ataque de fuerza bruta exitoso", "E1",
                                 taxonomia.area_de(efecto), justificacion, requiere_revision=True)
        justificacion += [
            "¿Hubo un efecto observable? No: no se registró ningún acceso exitoso desde la IP y "
            "Fail2ban la bloqueó.",
            "La categoría más cercana, «Ataque de fuerza bruta exitoso», exige un acceso logrado. "
            "El intento contenido se documenta como evento de seguridad y el delegado evalúa su "
            "reporte (DS 295/2024, art. 3.º).",
        ]
        return _sin_efecto("Intento de fuerza bruta SSH contenido por Fail2ban", "E1", justificacion)

    return Clasificacion(
        categoria="Sin clasificar",
        subcategoria="Requiere clasificación manual",
        escenario="otro",
        impacto="Por determinar",
        justificacion=[f"La jaula '{jail}' no tiene una regla de clasificación asociada: el "
                       f"operador debe asignar el efecto observable de la taxonomía."],
        requiere_revision=True,
    )
