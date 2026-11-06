"""Bitácora de auditoría con encadenamiento de huellas SHA-256.

Cada registro guarda la huella del registro anterior y la propia, calculada
sobre todos sus campos. Si alguien modifica o borra un registro directamente en
la base de datos, la cadena deja de cuadrar y la verificación lo detecta.
Además cada registro se copia a un archivo de texto (auditoria.log), que sirve
como segunda copia independiente de la cadena.
"""
import hashlib
from datetime import datetime

from . import config, db

GENESIS = "0" * 64


def _huella(prev: str, ts: str, usuario: str, accion: str, incidente_id, detalle) -> str:
    texto = "|".join([prev, ts, usuario, accion, incidente_id or "", detalle or ""])
    return hashlib.sha256(texto.encode("utf-8")).hexdigest()


def registrar(con, usuario: str, accion: str, incidente_id: str | None = None, detalle: str = ""):
    fila = con.execute("SELECT hash FROM bitacora ORDER BY id DESC LIMIT 1").fetchone()
    prev = fila["hash"] if fila else GENESIS
    ts = db.a_texto(datetime.now())
    h = _huella(prev, ts, usuario, accion, incidente_id, detalle)
    con.execute("""INSERT INTO bitacora (ts, usuario, accion, incidente_id, detalle, hash_prev, hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""", (ts, usuario, accion, incidente_id, detalle, prev, h))
    try:
        config.asegurar_directorios()
        with open(config.LOG_AUDITORIA, "a", encoding="utf-8") as f:
            f.write(f"{ts}\t{usuario}\t{accion}\t{incidente_id or '-'}\t{detalle}\t{h}\n")
    except OSError:
        pass


def verificar(con) -> dict:
    """Recalcula la cadena completa. Devuelve si está íntegra y dónde se rompe."""
    prev = GENESIS
    n = 0
    for r in con.execute("SELECT * FROM bitacora ORDER BY id"):
        n += 1
        esperado = _huella(prev, r["ts"], r["usuario"], r["accion"], r["incidente_id"], r["detalle"])
        if r["hash_prev"] != prev or r["hash"] != esperado:
            return {"integra": False, "registros": n, "falla_en": r["id"]}
        prev = r["hash"]
    return {"integra": True, "registros": n, "falla_en": None, "ultima_huella": prev}


def listar(con, limite: int = 300, incidente_id: str | None = None) -> list:
    if incidente_id:
        filas = con.execute("SELECT * FROM bitacora WHERE incidente_id = ? ORDER BY id DESC LIMIT ?",
                            (incidente_id, limite))
    else:
        filas = con.execute("SELECT * FROM bitacora ORDER BY id DESC LIMIT ?", (limite,))
    out = []
    for r in filas:
        d = dict(r)
        d["ts"] = datetime.fromisoformat(d["ts"])
        out.append(d)
    return out


def sha256_archivo(ruta) -> str | None:
    try:
        h = hashlib.sha256()
        with open(ruta, "rb") as f:
            for bloque in iter(lambda: f.read(65536), b""):
                h.update(bloque)
        return h.hexdigest()
    except OSError:
        return None


def sha256_texto(lineas: list) -> str:
    return hashlib.sha256("\n".join(lineas).encode("utf-8")).hexdigest()
