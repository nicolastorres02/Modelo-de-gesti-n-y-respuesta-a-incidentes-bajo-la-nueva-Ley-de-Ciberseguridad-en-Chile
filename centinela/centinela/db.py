"""Persistencia en SQLite: incidentes, reportes, usuarios, notificaciones y
bitácora de auditoría."""
import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime

from . import config

ESQUEMA = """
CREATE TABLE IF NOT EXISTS incidentes (
    id                TEXT PRIMARY KEY,
    ip                TEXT NOT NULL,
    jail              TEXT,
    t0                TEXT,      -- primer intento / primera petición del ataque
    t_deteccion       TEXT,      -- alerta de Fail2ban = conocimiento del incidente
    t_contencion      TEXT,      -- primer Ban de Fail2ban
    t_registro        TEXT NOT NULL,  -- instante en que Centinela recibió el evento
    intentos          INTEGER DEFAULT 0,
    usuarios          TEXT,      -- JSON
    accesos_exitosos  TEXT,      -- JSON
    categoria         TEXT,
    subcategoria      TEXT,
    escenario         TEXT,
    impacto           TEXT,
    justificacion     TEXT,      -- JSON
    requiere_revision INTEGER DEFAULT 0,
    evidencia         TEXT,      -- JSON (líneas de bitácora)
    estado            TEXT DEFAULT 'abierto',
    demo              INTEGER DEFAULT 0,
    reconocido        TEXT,      -- primera vez que el operador abrió el incidente
    bloqueos          TEXT,      -- JSON: instantes de cada Ban agrupado en el incidente
    ultimo_bloqueo    TEXT,
    detalle           TEXT,      -- JSON: datos propios del escenario (p. ej. escaneo web)
    hash_evidencia    TEXT,      -- SHA-256 de la evidencia
    evaluacion        TEXT       -- JSON: evaluación de efecto significativo (DS 295, art. 3.º)
);
CREATE TABLE IF NOT EXISTS reportes (
    incidente_id TEXT NOT NULL,
    tipo         TEXT NOT NULL,
    campos       TEXT NOT NULL,   -- JSON
    generado     TEXT,
    enviado      TEXT,
    ruta_pdf     TEXT,
    hash_pdf     TEXT,
    folio        TEXT,            -- comprobante de la plataforma de la ANCI (DS 295, art. 8.º)
    PRIMARY KEY (incidente_id, tipo),
    FOREIGN KEY (incidente_id) REFERENCES incidentes(id)
);
CREATE TABLE IF NOT EXISTS usuarios (
    nombre        TEXT PRIMARY KEY,
    hash_clave    TEXT NOT NULL,
    creado        TEXT NOT NULL,
    ultimo_acceso TEXT
);
CREATE TABLE IF NOT EXISTS accesos_panel (
    ip     TEXT NOT NULL,
    ts     TEXT NOT NULL,
    exito  INTEGER NOT NULL,
    nombre TEXT
);
CREATE TABLE IF NOT EXISTS notificaciones (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    incidente_id  TEXT NOT NULL,
    motivo        TEXT NOT NULL,   -- incidente | escalamiento | plazo:<reporte>:<etapa>
    canal         TEXT NOT NULL,   -- correo
    estado        TEXT NOT NULL,   -- enviado | error
    intentos      INTEGER DEFAULT 0,
    ultimo_intento TEXT,
    error         TEXT,
    UNIQUE (incidente_id, motivo, canal)
);
CREATE TABLE IF NOT EXISTS bitacora (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT NOT NULL,
    usuario      TEXT NOT NULL,
    accion       TEXT NOT NULL,
    incidente_id TEXT,
    detalle      TEXT,
    hash_prev    TEXT NOT NULL,
    hash         TEXT NOT NULL
);
"""

_JSON = {"usuarios", "accesos_exitosos", "justificacion", "evidencia", "campos", "bloqueos", "detalle",
         "evaluacion"}
_FECHAS = {"t0", "t_deteccion", "t_contencion", "t_registro", "generado", "enviado", "reconocido",
           "ultimo_bloqueo", "creado", "ultimo_acceso", "ultimo_intento"}

# Columnas agregadas en versiones posteriores: (tabla, columna, tipo)
_COLUMNAS_NUEVAS = [
    ("incidentes", "reconocido", "TEXT"),
    ("incidentes", "bloqueos", "TEXT"),
    ("incidentes", "ultimo_bloqueo", "TEXT"),
    ("incidentes", "detalle", "TEXT"),
    ("incidentes", "hash_evidencia", "TEXT"),
    ("reportes", "hash_pdf", "TEXT"),
    ("incidentes", "evaluacion", "TEXT"),
    ("reportes", "folio", "TEXT"),
]


def _migrar(con):
    """Actualiza bases creadas por versiones anteriores sin perder datos."""
    agregadas = set()
    for tabla, columna, tipo in _COLUMNAS_NUEVAS:
        columnas = {r[1] for r in con.execute(f"PRAGMA table_info({tabla})")}
        if columna not in columnas:
            con.execute(f"ALTER TABLE {tabla} ADD COLUMN {columna} {tipo}")
            agregadas.add((tabla, columna))
    # Los datos se completan después de agregar todas las columnas
    if ("incidentes", "reconocido") in agregadas:
        # Los incidentes existentes se dan por revisados, para que la alarma
        # no suene por incidentes antiguos.
        con.execute("UPDATE incidentes SET reconocido = t_registro")
    if ("incidentes", "bloqueos") in agregadas:
        con.execute("UPDATE incidentes SET bloqueos = json_array(t_contencion), "
                    "ultimo_bloqueo = t_contencion WHERE t_contencion IS NOT NULL")
    if ("incidentes", "hash_evidencia") in agregadas:
        # Huella de la evidencia ya registrada (mismo cálculo que auditoria.sha256_texto)
        for r in con.execute("SELECT id, evidencia FROM incidentes").fetchall():
            lineas = json.loads(r["evidencia"]) if r["evidencia"] else []
            con.execute("UPDATE incidentes SET hash_evidencia = ? WHERE id = ?",
                        (hashlib.sha256("\n".join(lineas).encode("utf-8")).hexdigest(), r["id"]))
    if ("reportes", "hash_pdf") in agregadas:
        # Los PDF generados por versiones anteriores reciben su huella al actualizar
        for r in con.execute("SELECT incidente_id, tipo, ruta_pdf FROM reportes").fetchall():
            try:
                huella = hashlib.sha256(open(r["ruta_pdf"], "rb").read()).hexdigest()
            except (OSError, TypeError):
                continue
            con.execute("UPDATE reportes SET hash_pdf = ? WHERE incidente_id = ? AND tipo = ?",
                        (huella, r["incidente_id"], r["tipo"]))
    if agregadas:
        con.commit()


def a_texto(valor):
    if isinstance(valor, datetime):
        return valor.isoformat(sep=" ", timespec="milliseconds")
    return valor


def _fila(row):
    if row is None:
        return None
    d = dict(row)
    for k in list(d):
        if k in _JSON and d[k] is not None:
            d[k] = json.loads(d[k])
        elif k in _FECHAS and d[k]:
            d[k] = datetime.fromisoformat(d[k])
    return d


@contextmanager
def conexion():
    config.asegurar_directorios()
    con = sqlite3.connect(config.DB_PATH, timeout=15)
    con.row_factory = sqlite3.Row
    # Si la base se borró con el panel en marcha, se recrean las tablas
    con.executescript(ESQUEMA)
    _migrar(con)
    try:
        yield con
        con.commit()
    finally:
        con.close()


def inicializar():
    with conexion():
        pass


# --- Incidentes --------------------------------------------------------------------

def nuevo_id(con, fecha: datetime) -> str:
    prefijo = f"INC-{fecha:%Y%m%d}-"
    fila = con.execute("SELECT MAX(id) FROM incidentes WHERE id LIKE ?", (prefijo + "%",)).fetchone()[0]
    n = int(fila.rsplit("-", 1)[1]) if fila else 0
    return f"{prefijo}{n + 1:03d}"


def _serializar(datos: dict) -> dict:
    return {k: (json.dumps(v, ensure_ascii=False, default=str) if k in _JSON else a_texto(v))
            for k, v in datos.items()}


def guardar_incidente(con, datos: dict):
    datos = _serializar(datos)
    cols = ", ".join(datos)
    marcas = ", ".join("?" for _ in datos)
    con.execute(f"INSERT INTO incidentes ({cols}) VALUES ({marcas})", tuple(datos.values()))


def actualizar_incidente(con, inc_id: str, datos: dict):
    datos = _serializar(datos)
    asignaciones = ", ".join(f"{k} = ?" for k in datos)
    con.execute(f"UPDATE incidentes SET {asignaciones} WHERE id = ?", (*datos.values(), inc_id))


def obtener_incidente(con, inc_id: str):
    return _fila(con.execute("SELECT * FROM incidentes WHERE id = ?", (inc_id,)).fetchone())


def listar_incidentes(con):
    return [_fila(r) for r in con.execute("SELECT * FROM incidentes ORDER BY t_registro DESC")]


def incidente_para_agrupar(con, ip: str, jail: str, desde: datetime):
    """Incidente abierto de la misma IP y jaula cuyo último bloqueo es reciente."""
    fila = con.execute(
        """SELECT * FROM incidentes WHERE ip = ? AND jail = ? AND estado = 'abierto'
           AND COALESCE(ultimo_bloqueo, t_contencion) >= ? ORDER BY t_registro DESC LIMIT 1""",
        (ip, jail, a_texto(desde))).fetchone()
    return _fila(fila)


def marcar_reconocido(con, inc_id: str, cuando: datetime) -> bool:
    """Registra la primera vez que el operador abre el incidente (apaga la alarma)."""
    cur = con.execute("UPDATE incidentes SET reconocido = ? WHERE id = ? AND reconocido IS NULL",
                      (a_texto(cuando), inc_id))
    return cur.rowcount > 0


def sin_reconocer(con) -> list:
    filas = con.execute("""SELECT id, ip, subcategoria FROM incidentes
                           WHERE reconocido IS NULL ORDER BY t_registro""")
    return [dict(r) for r in filas]


def actualizar_estado(con, inc_id: str, estado: str):
    con.execute("UPDATE incidentes SET estado = ? WHERE id = ?", (estado, inc_id))


# --- Reportes ----------------------------------------------------------------------

def guardar_reporte(con, inc_id: str, tipo: str, campos: dict, generado: datetime,
                    ruta_pdf: str, hash_pdf: str | None = None):
    con.execute(
        """INSERT INTO reportes (incidente_id, tipo, campos, generado, ruta_pdf, hash_pdf)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(incidente_id, tipo) DO UPDATE SET
             campos = excluded.campos, ruta_pdf = excluded.ruta_pdf, hash_pdf = excluded.hash_pdf""",
        # 'generado' conserva la primera generación: es la marca que usa el TTN.
        (inc_id, tipo, json.dumps(campos, ensure_ascii=False), a_texto(generado), ruta_pdf, hash_pdf))


def marcar_enviado(con, inc_id: str, tipo: str, cuando: datetime, folio: str | None = None) -> bool:
    cur = con.execute("UPDATE reportes SET enviado = ?, folio = ? WHERE incidente_id = ? AND tipo = ? "
                      "AND enviado IS NULL", (a_texto(cuando), folio or None, inc_id, tipo))
    return cur.rowcount > 0


def reportes_de(con, inc_id: str) -> dict:
    filas = con.execute("SELECT * FROM reportes WHERE incidente_id = ?", (inc_id,))
    return {r["tipo"]: _fila(r) for r in filas}


# --- Notificaciones ----------------------------------------------------------------

def notificacion(con, inc_id: str, motivo: str, canal: str = "correo"):
    return _fila(con.execute("SELECT * FROM notificaciones WHERE incidente_id = ? AND motivo = ? AND canal = ?",
                             (inc_id, motivo, canal)).fetchone())


def registrar_notificacion(con, inc_id: str, motivo: str, estado: str, error: str | None,
                           canal: str = "correo"):
    con.execute(
        """INSERT INTO notificaciones (incidente_id, motivo, canal, estado, intentos, ultimo_intento, error)
           VALUES (?, ?, ?, ?, 1, ?, ?)
           ON CONFLICT(incidente_id, motivo, canal) DO UPDATE SET
             estado = excluded.estado, intentos = notificaciones.intentos + 1,
             ultimo_intento = excluded.ultimo_intento, error = excluded.error""",
        (inc_id, motivo, canal, estado, a_texto(datetime.now()), error))


def notificaciones_de(con, inc_id: str) -> list:
    return [_fila(r) for r in con.execute(
        "SELECT * FROM notificaciones WHERE incidente_id = ? ORDER BY id", (inc_id,))]


def notificaciones_fallidas(con, max_intentos: int) -> list:
    return [_fila(r) for r in con.execute(
        "SELECT * FROM notificaciones WHERE estado = 'error' AND intentos < ? ORDER BY id", (max_intentos,))]
