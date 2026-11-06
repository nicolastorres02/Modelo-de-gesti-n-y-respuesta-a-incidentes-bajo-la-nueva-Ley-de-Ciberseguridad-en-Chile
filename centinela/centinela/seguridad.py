"""Seguridad del panel: usuarios, inicio de sesión, protección contra fuerza
bruta, CSRF y cabeceras HTTP de seguridad."""
import hmac
import secrets
from datetime import datetime, timedelta

from werkzeug.security import check_password_hash, generate_password_hash

from . import auditoria, config, db

LARGO_MINIMO_CLAVE = 10


# --- Usuarios ------------------------------------------------------------------------

def validar_clave(clave: str):
    if len(clave) < LARGO_MINIMO_CLAVE:
        raise ValueError(f"La contraseña debe tener al menos {LARGO_MINIMO_CLAVE} caracteres.")


def crear_usuario(con, nombre: str, clave: str, por: str = "sistema"):
    validar_clave(clave)
    nombre = nombre.strip().lower()
    if not nombre.isidentifier():
        raise ValueError("El nombre de usuario solo puede tener letras, números y guion bajo.")
    existe = con.execute("SELECT 1 FROM usuarios WHERE nombre = ?", (nombre,)).fetchone()
    # scrypt: función de derivación lenta, resistente a ataques de diccionario
    hash_clave = generate_password_hash(clave, method="scrypt")
    if existe:
        con.execute("UPDATE usuarios SET hash_clave = ? WHERE nombre = ?", (hash_clave, nombre))
        auditoria.registrar(con, por, "usuario_clave_cambiada", detalle=nombre)
    else:
        con.execute("INSERT INTO usuarios (nombre, hash_clave, creado) VALUES (?, ?, ?)",
                    (nombre, hash_clave, db.a_texto(datetime.now())))
        auditoria.registrar(con, por, "usuario_creado", detalle=nombre)


def eliminar_usuario(con, nombre: str, por: str = "sistema") -> bool:
    cur = con.execute("DELETE FROM usuarios WHERE nombre = ?", (nombre.strip().lower(),))
    if cur.rowcount:
        auditoria.registrar(con, por, "usuario_eliminado", detalle=nombre)
    return cur.rowcount > 0


def listar_usuarios(con) -> list:
    return [dict(r) for r in con.execute("SELECT nombre, creado, ultimo_acceso FROM usuarios ORDER BY nombre")]


def hay_usuarios(con) -> bool:
    return con.execute("SELECT 1 FROM usuarios LIMIT 1").fetchone() is not None


# --- Inicio de sesión con protección contra fuerza bruta -------------------------------

def bloqueado_hasta(con, ip: str, ahora: datetime | None = None) -> datetime | None:
    """Si la IP acumuló demasiados fallos recientes, devuelve hasta cuándo está bloqueada."""
    ahora = ahora or datetime.now()
    desde = ahora - timedelta(minutes=config.LOGIN_VENTANA_MIN + config.LOGIN_BLOQUEO_MIN)
    fallos = [datetime.fromisoformat(r["ts"]) for r in con.execute(
        "SELECT ts FROM accesos_panel WHERE ip = ? AND exito = 0 AND ts >= ? ORDER BY ts",
        (ip, db.a_texto(desde)))]
    ultimo_exito = con.execute("SELECT MAX(ts) FROM accesos_panel WHERE ip = ? AND exito = 1",
                               (ip,)).fetchone()[0]
    if ultimo_exito:
        fallos = [f for f in fallos if f > datetime.fromisoformat(ultimo_exito)]
    # Se busca una racha de LOGIN_MAX_FALLOS fallos dentro de LOGIN_VENTANA_MIN
    ventana = timedelta(minutes=config.LOGIN_VENTANA_MIN)
    for i in range(len(fallos) - config.LOGIN_MAX_FALLOS + 1):
        grupo = fallos[i:i + config.LOGIN_MAX_FALLOS]
        if grupo[-1] - grupo[0] <= ventana:
            hasta = grupo[-1] + timedelta(minutes=config.LOGIN_BLOQUEO_MIN)
            if hasta > ahora:
                return hasta
    return None


def autenticar(con, nombre: str, clave: str, ip: str) -> tuple[bool, str]:
    """Devuelve (éxito, mensaje). Registra cada intento en la bitácora."""
    ahora = datetime.now()
    hasta = bloqueado_hasta(con, ip, ahora)
    if hasta:
        auditoria.registrar(con, nombre or "-", "login_rechazado_bloqueo", detalle=f"ip={ip}")
        return False, f"Demasiados intentos fallidos. Intente nuevamente después de las {hasta:%H:%M}."
    nombre = (nombre or "").strip().lower()
    fila = con.execute("SELECT hash_clave FROM usuarios WHERE nombre = ?", (nombre,)).fetchone()
    # Se verifica aunque el usuario no exista, para no revelar qué usuarios existen
    hash_ref = fila["hash_clave"] if fila else generate_password_hash("x" * 16, method="scrypt")
    ok = check_password_hash(hash_ref, clave or "") and fila is not None
    con.execute("INSERT INTO accesos_panel (ip, ts, exito, nombre) VALUES (?, ?, ?, ?)",
                (ip, db.a_texto(ahora), int(ok), nombre))
    if ok:
        con.execute("UPDATE usuarios SET ultimo_acceso = ? WHERE nombre = ?", (db.a_texto(ahora), nombre))
        auditoria.registrar(con, nombre, "login_exitoso", detalle=f"ip={ip}")
        return True, ""
    auditoria.registrar(con, nombre or "-", "login_fallido", detalle=f"ip={ip}")
    if bloqueado_hasta(con, ip, ahora):
        auditoria.registrar(con, nombre or "-", "login_ip_bloqueada", detalle=f"ip={ip}")
        return False, (f"Demasiados intentos fallidos. Acceso bloqueado por "
                       f"{config.LOGIN_BLOQUEO_MIN} minutos.")
    return False, "Usuario o contraseña incorrectos."


# --- CSRF ------------------------------------------------------------------------------

def token_csrf(sesion) -> str:
    if "csrf" not in sesion:
        sesion["csrf"] = secrets.token_urlsafe(32)
    return sesion["csrf"]


def csrf_valido(sesion, recibido: str | None) -> bool:
    esperado = sesion.get("csrf")
    return bool(esperado and recibido and hmac.compare_digest(esperado, recibido))


# --- Cabeceras de seguridad ------------------------------------------------------------

def cabeceras(respuesta, https: bool):
    h = respuesta.headers
    h.setdefault("Content-Security-Policy",
                 # Sin scripts ni estilos incrustados: todo el JavaScript está en static/panel.js
                 "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                 "connect-src 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; "
                 "base-uri 'none'")
    h.setdefault("X-Frame-Options", "DENY")
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("Referrer-Policy", "no-referrer")
    h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if respuesta.mimetype in ("text/html", "application/json"):
        h["Cache-Control"] = "no-store"
    if https:
        h.setdefault("Strict-Transport-Security", "max-age=31536000")
    return respuesta
