"""Configuración de Centinela.

Todos los valores se leen de variables de entorno. En la VM víctima vienen del
archivo /etc/centinela/centinela.env (lo crea el instalador y lo cargan tanto
el comando 'centinela' como el servicio del panel). En un equipo de desarrollo
se usan los valores por defecto.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _bool(nombre: str, defecto: str) -> bool:
    return os.environ.get(nombre, defecto).strip().lower() in ("1", "si", "sí", "true", "yes")


# --- Datos ----------------------------------------------------------------------
DATA_DIR = Path(os.environ.get("CENTINELA_DATA", BASE_DIR / "datos"))
DB_PATH = DATA_DIR / "centinela.db"
PDF_DIR = DATA_DIR / "reportes"
LOG_AUDITORIA = DATA_DIR / "auditoria.log"

# --- Bitácoras que integra la herramienta ----------------------------------------
AUTH_LOG = Path(os.environ.get("CENTINELA_AUTH_LOG", "/var/log/auth.log"))
FAIL2BAN_LOG = Path(os.environ.get("CENTINELA_F2B_LOG", "/var/log/fail2ban.log"))
ACCESS_LOG = Path(os.environ.get("CENTINELA_ACCESS_LOG", "/var/log/apache2/access.log"))
LOG_CENTINELA = Path(os.environ.get("CENTINELA_LOG", "/var/log/centinela.log"))

# Si auth.log no existe o no tiene los intentos, leerlos del journal de systemd
USAR_JOURNAL = _bool("CENTINELA_JOURNAL", "1")

# findtime de la jaula sshd (jail.local del estudio: 120 s). Una pausa mayor
# entre dos intentos separa un ataque de intentos anteriores no relacionados.
FINDTIME_S = int(os.environ.get("CENTINELA_FINDTIME_S", "120"))

# Año de referencia para bitácoras syslog clásicas ("Nov  5 10:32:01", sin año)
LOG_YEAR = os.environ.get("CENTINELA_LOG_YEAR")

# Jaulas de Fail2ban que entregan sus bloqueos a Centinela
JAULAS = [j.strip() for j in os.environ.get("CENTINELA_JAULAS", "sshd,centinela-escaneo-web").split(",") if j.strip()]

# Una IP que vuelve a ser bloqueada dentro de este plazo desde su último
# bloqueo se agrega al mismo incidente en vez de crear uno nuevo.
AGRUPAR_MIN = int(os.environ.get("CENTINELA_AGRUPAR_MIN", "30"))

# --- Datos del operador que aparecen en los reportes a la ANCI ---------------------
# DS 295/2024, art. 5.º a) institución afectada y b) delegado de ciberseguridad
ORGANIZACION = os.environ.get("CENTINELA_ORG", "Operador de laboratorio (entorno simulado)")
ORG_RUT = os.environ.get("CENTINELA_ORG_RUT", "")
ORG_DIRECCION = os.environ.get("CENTINELA_ORG_DIRECCION", "")
ORG_CORREO = os.environ.get("CENTINELA_ORG_CORREO", "")
RESPONSABLE = os.environ.get("CENTINELA_RESPONSABLE", "Delegado de ciberseguridad")
DELEGADO_CORREO = os.environ.get("CENTINELA_DELEGADO_CORREO", "")
DELEGADO_TELEFONO = os.environ.get("CENTINELA_DELEGADO_TELEFONO", "")
NOMBRE_HOST = os.environ.get("CENTINELA_HOST", "victima-02")

# ¿La institución es operador de importancia vital (OIV)? Solo los OIV presentan
# plan de acción (DS 295, art. 11) y pueden tener el segundo reporte a 24 h (art. 10).
ES_OIV = _bool("CENTINELA_OIV", "1")
# Supuesto mientras el delegado no evalúa el incidente: ¿se vio afectado el
# servicio esencial? (sí = segundo reporte a 24 h, el escenario más exigente)
SERVICIO_ESENCIAL = _bool("CENTINELA_SERV_ESENCIAL", "1")

# --- Panel web ----------------------------------------------------------------------
HOST_PANEL = os.environ.get("CENTINELA_PANEL_HOST", "127.0.0.1")
PUERTO_PANEL = int(os.environ.get("CENTINELA_PANEL_PUERTO", "5000"))
# Dirección con la que se enlaza el panel desde los correos
URL_PANEL = os.environ.get("CENTINELA_URL_PANEL", f"https://{NOMBRE_HOST}:{PUERTO_PANEL}")
# Clave para firmar las sesiones (el instalador genera una aleatoria)
SECRET_KEY = os.environ.get("CENTINELA_SECRET_KEY", "")
# Certificado HTTPS (los genera el instalador con una autoridad propia)
TLS_CERT = os.environ.get("CENTINELA_TLS_CERT", "")
TLS_KEY = os.environ.get("CENTINELA_TLS_KEY", "")
TLS_CA = os.environ.get("CENTINELA_TLS_CA", "")
SESION_HORAS = int(os.environ.get("CENTINELA_SESION_HORAS", "8"))
# Protección contra fuerza bruta en el inicio de sesión del panel
LOGIN_MAX_FALLOS = int(os.environ.get("CENTINELA_LOGIN_MAX_FALLOS", "5"))
LOGIN_VENTANA_MIN = int(os.environ.get("CENTINELA_LOGIN_VENTANA_MIN", "10"))
LOGIN_BLOQUEO_MIN = int(os.environ.get("CENTINELA_LOGIN_BLOQUEO_MIN", "10"))

# --- Correo -------------------------------------------------------------------------
# Sin SMTP_HOST el canal de correo queda desactivado.
SMTP_HOST = os.environ.get("CENTINELA_SMTP_HOST", "")
SMTP_PUERTO = int(os.environ.get("CENTINELA_SMTP_PUERTO", "25"))
SMTP_SEGURIDAD = os.environ.get("CENTINELA_SMTP_SEGURIDAD", "ninguna")  # ninguna | starttls | ssl
SMTP_USUARIO = os.environ.get("CENTINELA_SMTP_USUARIO", "")
SMTP_CLAVE = os.environ.get("CENTINELA_SMTP_CLAVE", "")
CORREO_DE = os.environ.get("CENTINELA_CORREO_DE", "centinela@laboratorio.local")
CORREO_PARA = [c.strip() for c in os.environ.get("CENTINELA_CORREO_PARA", "").split(",") if c.strip()]
CORREO_REINTENTOS = int(os.environ.get("CENTINELA_CORREO_REINTENTOS", "5"))


def asegurar_directorios():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    PDF_DIR.mkdir(parents=True, exist_ok=True)
