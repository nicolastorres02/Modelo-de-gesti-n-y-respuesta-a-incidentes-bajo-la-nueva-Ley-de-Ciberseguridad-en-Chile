"""Lectura de bitácoras: auth.log (OpenSSH), access.log (Apache) y fail2ban.log.

Centinela no reemplaza a Fail2ban: lee las mismas bitácoras que el modelo
de la tesis usa como evidencia y extrae de ellas los instantes y los datos
necesarios para clasificar el incidente y completar los reportes.

Si logrotate rotó una bitácora durante el ataque (auth.log -> auth.log.1),
se leen ambos archivos para no perder evidencia.
"""
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from . import config

def archivos_con_rotacion(ruta: Path) -> list:
    """El archivo rotado más reciente (sin comprimir) seguido del actual."""
    rotado = ruta.with_name(ruta.name + ".1")
    return [p for p in (rotado, ruta) if p.exists()]


def _lineas(ruta: Path):
    for p in archivos_con_rotacion(ruta):
        with p.open(encoding="utf-8", errors="replace") as f:
            yield from f


# --- Marcas de tiempo -------------------------------------------------------

# Formato syslog clásico: "Nov  5 10:32:01 host proceso: mensaje"
_RE_SYSLOG = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<msg>.*)$")
# Formato ISO (Ubuntu 24.04+): "2026-11-05T10:32:01.123456-03:00 host proceso: mensaje"
_RE_ISO = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\S+)\s+(?P<host>\S+)\s+(?P<msg>.*)$")


def _parse_ts_auth(linea: str):
    m = _RE_ISO.match(linea)
    if m:
        ts = datetime.fromisoformat(m.group("ts"))
        if ts.tzinfo is not None:
            # Se lleva a la hora local del sistema, la misma que usa
            # fail2ban.log. Así las líneas escritas antes de un cambio de zona
            # horaria siguen siendo comparables con las nuevas.
            ts = ts.astimezone()
        return ts.replace(tzinfo=None), m.group("msg")
    m = _RE_SYSLOG.match(linea)
    if m:
        anio = int(config.LOG_YEAR) if config.LOG_YEAR else datetime.now().year
        ts = datetime.strptime(f"{anio} {m.group('ts')}", "%Y %b %d %H:%M:%S")
        return ts, m.group("msg")
    return None, None


# --- auth.log ----------------------------------------------------------------

# OpenSSH >= 9.8 (Ubuntu 24.10+) registra las sesiones como "sshd-session[pid]"
_SSHD = r"sshd(?:-session)?\[\d+\]: "
_RE_FALLIDO = re.compile(
    _SSHD + r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
_RE_INVALIDO = re.compile(_SSHD + r"Invalid user (?P<user>\S*) from (?P<ip>[\d.:a-fA-F]+)")
_RE_ACEPTADO = re.compile(
    _SSHD + r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")


@dataclass
class EvidenciaAuth:
    ip: str
    intentos_fallidos: int = 0
    primer_fallo: datetime | None = None   # t0 del incidente
    ultimo_fallo: datetime | None = None
    usuarios: set = field(default_factory=set)
    accesos_exitosos: list = field(default_factory=list)  # [(ts, usuario)]
    lineas: list = field(default_factory=list)            # evidencia textual


def leer_auth_log(ip: str, ruta: Path | None = None, desde: datetime | None = None,
                  hasta: datetime | None = None) -> EvidenciaAuth:
    """Extrae de auth.log la actividad SSH de una IP entre 'desde' y 'hasta'."""
    ruta = Path(ruta or config.AUTH_LOG)
    ev = EvidenciaAuth(ip=ip)
    _procesar_lineas_auth(_lineas(ruta), ev, ip, desde, hasta)
    if ev.intentos_fallidos == 0 and not ev.lineas and config.USAR_JOURNAL:
        # Sistemas sin rsyslog (sin auth.log): se lee el journal de systemd
        _procesar_lineas_auth(_lineas_journal(desde, hasta), ev, ip, desde, hasta)
    return ev


def _lineas_journal(desde: datetime | None, hasta: datetime | None):
    cmd = ["journalctl", "--no-pager", "-o", "short-iso-precise",
           "SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session"]
    if desde:
        cmd += ["--since", f"{desde:%Y-%m-%d %H:%M:%S}"]
    if hasta:
        cmd += ["--until", f"{hasta + timedelta(seconds=1):%Y-%m-%d %H:%M:%S}"]
    try:
        salida = subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    return salida.splitlines()


def _procesar_lineas_auth(lineas, ev: EvidenciaAuth, ip: str, desde, hasta):
    for linea in lineas:
        if ip not in linea:
            continue
        ts, msg = _parse_ts_auth(linea.rstrip("\n"))
        if ts is None or (desde and ts < desde) or (hasta and ts > hasta):
            continue
        m = _RE_FALLIDO.search(msg)
        if m and m.group("ip") == ip:
            ev.intentos_fallidos += 1
            ev.usuarios.add(m.group("user"))
            ev.primer_fallo = ev.primer_fallo or ts
            ev.ultimo_fallo = ts
            ev.lineas.append(linea.strip())
            continue
        m = _RE_INVALIDO.search(msg)
        if m and m.group("ip") == ip:
            ev.usuarios.add(m.group("user") or "(vacío)")
            ev.lineas.append(linea.strip())
            continue
        m = _RE_ACEPTADO.search(msg)
        if m and m.group("ip") == ip:
            ev.accesos_exitosos.append((ts, m.group("user")))
            ev.lineas.append(linea.strip())


# --- fail2ban.log ------------------------------------------------------------

_RE_F2B = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),(?P<ms>\d+)\s+fail2ban\.\S+\s+\[\d+\]:\s+\w+\s+"
    r"\[(?P<jail>[^\]]+)\]\s+(?P<evento>Found|Ban|Unban|Restore Ban)\s+(?P<ip>[\d.:a-fA-F]+)"
    # Los Found traen la hora del intento original: "Found IP - 2026-11-05 04:37:35"
    r"(?:\s+-\s+(?P<evt>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}))?")


@dataclass
class EvidenciaF2B:
    ip: str
    jail: str | None = None
    primer_found: datetime | None = None   # detección
    ban: datetime | None = None             # contención
    unban: datetime | None = None
    detecciones: int = 0


def _inicio_rafaga(founds: list, ban: datetime, brecha: timedelta) -> list:
    """Devuelve los Found que forman el ataque que terminó en este Ban.

    Recorre los Found hacia atrás desde el Ban y se detiene en la primera
    pausa mayor que 'brecha' (findtime de Fail2ban). Así se descartan
    intentos aislados de horas antes que nunca llegaron a un bloqueo, como
    los de un usuario legítimo que se equivoca de contraseña.
    """
    previos = [t for t in founds if t <= ban]
    rafaga = []
    siguiente = ban
    for t in reversed(previos):
        if siguiente - t > brecha:
            break
        rafaga.append(t)
        siguiente = t
    return list(reversed(rafaga))


def leer_fail2ban_log(ip: str, ruta: Path | None = None, desde: datetime | None = None,
                      brecha: timedelta | None = None, jail: str | None = None) -> EvidenciaF2B:
    """Obtiene los eventos Found/Ban/Unban de Fail2ban para una IP.

    Toma el último ciclo de baneo: si la IP fue baneada varias veces, se
    queda con el Ban más reciente y con la ráfaga de Found que lo produjo.
    Con 'jail' solo considera los eventos de esa jaula.
    """
    brecha = brecha or timedelta(seconds=config.FINDTIME_S)
    ruta = Path(ruta or config.FAIL2BAN_LOG)
    ev = EvidenciaF2B(ip=ip)
    founds = []
    for linea in _lineas(ruta):
        m = _RE_F2B.match(linea)
        if not m or m.group("ip") != ip or (jail and m.group("jail") != jail):
            continue
        # Precisión de milisegundos, como en la medición del TTC de la tesis
        ts = datetime.strptime(f"{m.group('ts')}.{m.group('ms')[:3]:0<3}", "%Y-%m-%d %H:%M:%S.%f")
        if desde and ts < desde:
            continue
        evento = m.group("evento")
        if evento == "Found":
            # Con backend=systemd Fail2ban puede escribir los Found en
            # ráfaga justo antes del Ban; la hora del intento es la real.
            evt = m.group("evt")
            founds.append(datetime.strptime(evt, "%Y-%m-%d %H:%M:%S") if evt else ts)
        elif evento in ("Ban", "Restore Ban"):
            ev.ban = ts
            ev.jail = m.group("jail")
            rafaga = _inicio_rafaga(founds, ts, brecha)
            ev.primer_found = rafaga[0] if rafaga else ts
            ev.detecciones = len(rafaga)
            founds = []
            ev.unban = None
        elif evento == "Unban":
            ev.unban = ts
    return ev


# --- access.log de Apache (escenario E2: escaneo web) -----------------------------

# Formato combinado: IP - - [05/Nov/2026:02:41:15 -0300] "GET /ruta HTTP/1.1" 404 437 "-" "agente"
_RE_ACCESS = re.compile(
    r'^(?P<ip>[\d.:a-fA-F]+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<metodo>[A-Z]+) (?P<ruta>\S+)[^"]*" '
    r'(?P<estado>\d{3}) \S+(?: "[^"]*" "(?P<agente>[^"]*)")?')

# Firmas de herramientas de reconocimiento en el User-Agent o en las rutas
HERRAMIENTAS = [
    ("Nikto", re.compile(r"nikto", re.I)),
    ("Gobuster", re.compile(r"gobuster", re.I)),
    ("sqlmap", re.compile(r"sqlmap", re.I)),
    ("Nmap NSE", re.compile(r"nmap", re.I)),
    ("dirb/dirbuster", re.compile(r"dirb", re.I)),
    ("WPScan", re.compile(r"wpscan", re.I)),
    ("ffuf", re.compile(r"ffuf", re.I)),
    ("curl", re.compile(r"^curl/", re.I)),
]


# Recursos sensibles: si el escaneo los obtuvo con éxito (2xx), hubo exposición de
# información y el incidente tiene un efecto observable (Res. Ex. 7/2025, art. 4.º).
# (patrón, efecto observable, categoría)
SENSIBLES = [
    (re.compile(r"/\.env(\.[\w-]+)?$|\.(pem|key|p12|pfx)$|id_rsa|/\.aws/credentials|\.htpasswd$|/\.ssh/", re.I),
     "Exfiltración y/o exposición de configuraciones", "Filtración de secretos en rutas de aplicación"),
    (re.compile(r"/\.(git|svn|hg|bzr)(/|$)", re.I),
     "Exfiltración y/o exposición de código fuente", "Archivo(s) de control de versión expuestos en aplicación"),
    (re.compile(r"(wp-config|config|configuration|settings|database|db)\.(php|inc|ini|ya?ml|json|xml|conf)"
                r"(\.bak|\.old|\.orig|\.save|~)?$|phpinfo\.php$|/server-status$|/server-info$|web\.config$"
                r"|\.(bak|old|orig|swp)$", re.I),
     "Exfiltración y/o exposición de configuraciones", "Filtración de configuraciones en rutas de aplicación"),
    (re.compile(r"\.(sql|sqlite|db|mdb|dump)(\.gz|\.zip)?$|/backup[^/]*\.(zip|tar|tgz|gz|7z|rar)$", re.I),
     "Exfiltración y/o exposición de datos", "Documentos públicos con datos sensibles"),
]


def recurso_sensible(ruta: str):
    """(efecto, categoría) si la ruta corresponde a un recurso sensible."""
    limpia = ruta.split("?", 1)[0]
    for patron, efecto, categoria in SENSIBLES:
        if patron.search(limpia):
            return efecto, categoria
    return None


@dataclass
class EvidenciaWeb:
    ip: str
    peticiones: int = 0
    errores: int = 0                       # respuestas 4xx
    primera: datetime | None = None        # t0 del incidente
    ultima: datetime | None = None
    codigos: dict = field(default_factory=dict)
    rutas: list = field(default_factory=list)       # muestra de rutas solicitadas
    agentes: set = field(default_factory=set)
    herramientas: set = field(default_factory=set)
    lineas: list = field(default_factory=list)
    # Recursos sensibles entregados con éxito: [ruta, código, efecto, categoría]
    expuestas: list = field(default_factory=list)


def leer_access_log(ip: str, ruta: Path | None = None, desde: datetime | None = None,
                    hasta: datetime | None = None) -> EvidenciaWeb:
    ruta = Path(ruta or config.ACCESS_LOG)
    ev = EvidenciaWeb(ip=ip)
    for linea in _lineas(ruta):
        if not linea.startswith(ip):
            continue
        m = _RE_ACCESS.match(linea)
        if not m or m.group("ip") != ip:
            continue
        try:
            ts = datetime.strptime(m.group("ts"), "%d/%b/%Y:%H:%M:%S %z").astimezone().replace(tzinfo=None)
        except ValueError:
            continue
        if (desde and ts < desde) or (hasta and ts > hasta):
            continue
        ev.peticiones += 1
        estado = m.group("estado")
        ev.codigos[estado] = ev.codigos.get(estado, 0) + 1
        if estado.startswith("4"):
            ev.errores += 1
        ev.primera = ev.primera or ts
        ev.ultima = ts
        if len(ev.rutas) < 15 and m.group("ruta") not in ev.rutas:
            ev.rutas.append(m.group("ruta"))
        if estado.startswith("2"):
            sensible = recurso_sensible(m.group("ruta"))
            if sensible and len(ev.expuestas) < 30 and all(e[0] != m.group("ruta") for e in ev.expuestas):
                ev.expuestas.append([m.group("ruta"), estado, *sensible])
        agente = m.group("agente") or ""
        if agente and agente != "-":
            ev.agentes.add(agente[:120])
        for nombre, patron in HERRAMIENTAS:
            if patron.search(agente) or (nombre == "Nikto" and "nikto" in m.group("ruta").lower()):
                ev.herramientas.add(nombre)
        if len(ev.lineas) < 500:
            ev.lineas.append(linea.strip())
    return ev
