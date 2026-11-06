"""Taxonomía oficial de incidentes de ciberseguridad de la ANCI.

Transcripción de la Resolución Exenta N.º 7/2025 de la Agencia Nacional de
Ciberseguridad (Diario Oficial, 1 de marzo de 2025):

- Artículo tercero: cuatro áreas de impacto y once efectos observables.
- Artículo cuarto: categorías de incidentes según el efecto observable.

El artículo segundo dispone que el incidente se clasifica por sus *efectos
observables*, "independientemente de cuál pueda ser su causa u origen".
"""

BASE_LEGAL = "Res. Ex. N.º 7/2025 de la ANCI, arts. 3.º y 4.º"

# área -> efecto observable -> categorías
TAXONOMIA = {
    "Impacto en el uso legítimo de recursos": {
        "Uso no autorizado de redes y sistemas informáticos": [
            "Acceso no autorizado a almacenamiento",
            "Ataque de fuerza bruta exitoso",
            "Explotación de vulnerabilidades de autenticación",
            "Uso de credenciales comprometidas",
        ],
        "Actividades de phishing o fraude en infraestructura propia": [
            "Envío de correo no deseado o phishing desde infraestructura propia",
            "Inclusión de sitio fraudulento en infraestructura propia",
        ],
        "Actividades de phishing o fraude relacionadas con la institución": [
            "Envío de correo no deseado o phishing sobre una organización",
            "Envío de correo no deseado o phishing usando remitentes de la institución",
        ],
        "Ejecución no autorizada de código": [
            "Ejecución remota de código a través de parámetros de aplicación",
            "Inyección de requerimientos (prompts) en modelos grandes de lenguaje (LLM)",
            "Inyección de consultas NoSQL",
            "Inyección de consultas SQL",
        ],
    },
    "Impacto en la confidencialidad de la información": {
        "Exfiltración y/o exposición de datos": [
            "Adversario en el medio (MitM)",
            "Apropiación de credenciales mediante phishing",
            "Base de datos sin protección (S3 buckets, Elasticsearch, MongoDB expuestos)",
            "Documentos públicos con datos sensibles",
            "Filtración de datos personales",
            "Keylogger en uso",
            "Divulgación de enumeraciones de usuarios y/o credenciales de usuarios en foros",
        ],
        "Exfiltración y/o exposición de configuraciones": [
            "Filtración de configuraciones en rutas de aplicación",
            "Filtración de secretos en rutas de aplicación",
        ],
        "Exfiltración y/o exposición de código fuente": [
            "Archivo(s) de control de versión expuestos en aplicación",
            "Sistema de control de versión expuesto",
        ],
    },
    "Impacto en la disponibilidad de un servicio esencial": {
        "Indisponibilidad y/o denegación de servicio": [
            "Agotamiento de conexiones TCP",
            "Apagado no autorizado de sistemas informáticos",
            "Ataque de amplificación DNS/NTP",
            "Ataque físico contra infraestructura TI",
            "Denegación de servicio a través de la explotación de vulnerabilidades",
            "Eliminación de configuraciones críticas",
            "Tráfico de red excesivo (volumétrico)",
        ],
        "Degradación de servicio": [
            "Secuestro de recursos (cryptojacking)",
            "Sobrecarga de bases de datos",
            "Uso excesivo de ancho de banda",
        ],
    },
    "Impacto en la integridad de la información": {
        "Modificación no autorizada de datos": [
            "Alteración de bases de datos",
            "Alteración de sitio web (defacement)",
            "Manipulación de datos no autentificados",
            "Modificación de logs de auditoría",
        ],
        "Manipulación no autorizada de configuración": [
            "Alteración de reglas de firewall",
            "Desactivación de registros de seguridad",
            "Modificación de políticas de acceso",
        ],
    },
}

# Para intentos que fueron contenidos antes de producir un efecto observable
SIN_EFECTO = "Sin efecto observable (intento contenido)"
SIN_AREA = "Ninguna: no se observó efecto en las cuatro áreas de impacto"


def area_de(efecto: str) -> str | None:
    for area, efectos in TAXONOMIA.items():
        if efecto in efectos:
            return area
    return None


def es_valida(efecto: str, categoria: str) -> bool:
    area = area_de(efecto)
    return bool(area) and categoria in TAXONOMIA[area][efecto]


def opciones() -> list:
    """[(área, [(valor, efecto, categoría), ...]), ...] para el formulario del panel."""
    out = []
    for area, efectos in TAXONOMIA.items():
        items = [(f"{efecto}|{cat}", efecto, cat) for efecto, cats in efectos.items() for cat in cats]
        out.append((area, items))
    return out
