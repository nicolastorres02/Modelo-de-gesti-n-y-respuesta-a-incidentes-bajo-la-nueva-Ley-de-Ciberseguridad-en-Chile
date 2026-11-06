import re
import sqlite3
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from centinela import (auditoria, clasificador, config, db, notificador, nucleo, parsers,
                       plazos, reportes, seguridad, significancia, taxonomia, vigilante)

IP = "192.168.58.133"
CLAVE = "clave-segura-123"


def _off(dt: datetime) -> str:
    """Desfase horario local para esa fecha, como lo escribe rsyslog (-03:00)."""
    z = dt.astimezone().strftime("%z")
    return f"{z[:3]}:{z[3:]}"


OFF = _off(datetime(2026, 11, 5, 10, 31))

AUTH = f"""\
2026-11-05T10:31:50.120000{OFF} victima-02 sshd[4100]: Failed password for root from 192.168.58.133 port 51000 ssh2
2026-11-05T10:31:55.300000{OFF} victima-02 sshd[4101]: Failed password for invalid user admin from 192.168.58.133 port 51001 ssh2
2026-11-05T10:31:56.000000{OFF} victima-02 sshd[4102]: Failed password for nicolas from 192.168.58.50 port 40000 ssh2
2026-11-05T10:32:00.000000{OFF} victima-02 sshd[4103]: Failed password for root from 192.168.58.133 port 51002 ssh2
Nov  5 10:32:03 victima-02 sshd[4104]: Failed password for root from 192.168.58.133 port 51003 ssh2
Nov  5 10:32:05 victima-02 sshd[4105]: Failed password for root from 192.168.58.133 port 51004 ssh2
"""

F2B = """\
2026-11-05 10:31:50,200 fail2ban.filter  [812]: INFO    [sshd] Found 192.168.58.133 - 2026-11-05 10:31:50
2026-11-05 10:31:55,400 fail2ban.filter  [812]: INFO    [sshd] Found 192.168.58.133 - 2026-11-05 10:31:55
2026-11-05 10:32:05,100 fail2ban.filter  [812]: INFO    [sshd] Found 192.168.58.133 - 2026-11-05 10:32:05
2026-11-05 10:32:05,450 fail2ban.actions [812]: NOTICE  [sshd] Ban 192.168.58.133
"""

OFF_APACHE = datetime(2026, 11, 5, 11).astimezone().strftime("%z")


def _access(n=25, inicio=datetime(2026, 11, 5, 11, 0, 0), agente="gobuster/3.8.2"):
    return "".join(
        f'{IP} - - [{(inicio + timedelta(seconds=i // 5)):%d/%b/%Y:%H:%M:%S} {OFF_APACHE}] '
        f'"GET /oculto{i} HTTP/1.1" 404 437 "-" "{agente}"\n' for i in range(n))


F2B_WEB = (
    "2026-11-05 11:00:00,100 fail2ban.filter  [812]: INFO    [centinela-escaneo-web] Found 192.168.58.133 - 2026-11-05 11:00:00\n"
    "2026-11-05 11:00:04,100 fail2ban.filter  [812]: INFO    [centinela-escaneo-web] Found 192.168.58.133 - 2026-11-05 11:00:04\n"
    "2026-11-05 11:00:04,300 fail2ban.actions [812]: NOTICE  [centinela-escaneo-web] Ban 192.168.58.133\n")


@pytest.fixture
def entorno(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "c.db")
    monkeypatch.setattr(config, "PDF_DIR", tmp_path / "pdf")
    monkeypatch.setattr(config, "LOG_AUDITORIA", tmp_path / "auditoria.log")
    monkeypatch.setattr(config, "LOG_YEAR", "2026")
    monkeypatch.setattr(config, "USAR_JOURNAL", False)
    monkeypatch.setattr(config, "SMTP_HOST", "")
    monkeypatch.setattr(config, "CORREO_PARA", [])
    monkeypatch.setattr(config, "AGRUPAR_MIN", 30)
    auth, f2b = tmp_path / "auth.log", tmp_path / "fail2ban.log"
    auth.write_text(AUTH, encoding="utf-8")
    f2b.write_text(F2B, encoding="utf-8")
    return auth, f2b


@pytest.fixture
def correo(monkeypatch):
    """Activa el canal de correo y captura los envíos en vez de usar SMTP."""
    enviados = []
    monkeypatch.setattr(config, "SMTP_HOST", "smtp.prueba")
    monkeypatch.setattr(config, "CORREO_PARA", ["delegado@lab"])
    monkeypatch.setattr(notificador, "_enviar", lambda a, c, adj: enviados.append((a, c, list(adj))))
    return enviados


def _cliente():
    from centinela.app import crear_app
    app = crear_app(https=False)
    app.config["TESTING"] = True
    return app.test_client()


def _csrf(cli) -> str:
    html = cli.get("/login").get_data(as_text=True)
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def _login(cli, usuario="admin", clave=CLAVE):
    with db.conexion() as con:
        if not con.execute("SELECT 1 FROM usuarios WHERE nombre = ?", (usuario,)).fetchone():
            seguridad.crear_usuario(con, usuario, CLAVE)
    return cli.post("/login", data={"csrf": _csrf(cli), "usuario": usuario, "clave": clave})


def _token(cli) -> str:
    with cli.session_transaction() as s:
        return s["csrf"]


# --- Lectura de bitácoras -------------------------------------------------------------

def test_auth_log_ambos_formatos(entorno):
    auth, _ = entorno
    ev = parsers.leer_auth_log(IP, auth)
    assert ev.intentos_fallidos == 5            # la IP .50 no se cuenta
    assert ev.usuarios == {"root", "admin"}
    assert ev.primer_fallo == datetime(2026, 11, 5, 10, 31, 50, 120000)
    assert ev.ultimo_fallo == datetime(2026, 11, 5, 10, 32, 5)


def test_openssh_nuevo_sshd_session(entorno):
    auth, _ = entorno
    auth.write_text(AUTH.replace("sshd[", "sshd-session["), encoding="utf-8")
    assert parsers.leer_auth_log(IP, auth).intentos_fallidos == 5


def test_log_rotado_se_lee(entorno):
    """Si logrotate movió auth.log a auth.log.1 durante el ataque, no se pierde evidencia."""
    auth, _ = entorno
    lineas = AUTH.splitlines(keepends=True)
    (auth.parent / "auth.log.1").write_text("".join(lineas[:3]), encoding="utf-8")
    auth.write_text("".join(lineas[3:]), encoding="utf-8")
    assert parsers.leer_auth_log(IP, auth).intentos_fallidos == 5


def test_fail2ban_log(entorno):
    _, f2b = entorno
    ev = parsers.leer_fail2ban_log(IP, f2b)
    assert ev.jail == "sshd"
    assert ev.primer_found == datetime(2026, 11, 5, 10, 31, 50)   # hora del intento
    assert ev.ban == datetime(2026, 11, 5, 10, 32, 5, 450000)


def test_fail2ban_filtra_por_jaula(entorno):
    _, f2b = entorno
    f2b.write_text(F2B + F2B_WEB, encoding="utf-8")
    assert parsers.leer_fail2ban_log(IP, f2b, jail="sshd").ban == datetime(2026, 11, 5, 10, 32, 5, 450000)
    assert parsers.leer_fail2ban_log(IP, f2b, jail="centinela-escaneo-web").ban == datetime(2026, 11, 5, 11, 0, 4, 300000)


def test_access_log_detecta_herramienta(entorno, tmp_path):
    acc = tmp_path / "access.log"
    acc.write_text(_access(25, agente="Mozilla/5.00 (Nikto/2.6.0) (Evasions:None)"), encoding="utf-8")
    ev = parsers.leer_access_log(IP, acc)
    assert ev.peticiones == 25 and ev.errores == 25
    assert ev.herramientas == {"Nikto"}
    assert ev.primera == datetime(2026, 11, 5, 11, 0, 0)


# --- Clasificación y plazos -------------------------------------------------------------

def test_clasificacion_fuerza_bruta_contenida_sin_efecto_observable():
    """Res. Ex. 7/2025 clasifica por efectos observables: un intento bloqueado no tiene categoría."""
    c = clasificador.clasificar("sshd", 5, {"root"}, [])
    assert c.categoria == taxonomia.SIN_EFECTO and not c.con_efecto
    assert "fuerza bruta" in c.subcategoria and not c.requiere_revision


def test_clasificacion_acceso_exitoso_categoria_oficial():
    c = clasificador.clasificar("sshd", 5, {"root"}, [("2026-11-05 10:00:00", "root")])
    assert c.requiere_revision and c.subcategoria == "Ataque de fuerza bruta exitoso"
    assert taxonomia.es_valida(c.categoria, c.subcategoria)
    assert c.impacto == "Impacto en el uso legítimo de recursos"


def test_clasificacion_escaneo_web_sin_exposicion():
    c = clasificador.clasificar("centinela-escaneo-web", web={"peticiones": 30, "errores": 28,
                                                              "herramientas": ["Gobuster"]})
    assert c.categoria == taxonomia.SIN_EFECTO and c.escenario == "E2"
    assert "Gobuster" in c.justificacion[0]


def test_clasificacion_escaneo_web_con_git_expuesto():
    c = clasificador.clasificar("centinela-escaneo-web", web={
        "peticiones": 30, "errores": 27, "herramientas": ["Nikto"],
        "expuestas": [["/.git/HEAD", "200", "Exfiltración y/o exposición de código fuente",
                       "Archivo(s) de control de versión expuestos en aplicación"]]})
    assert c.subcategoria == "Archivo(s) de control de versión expuestos en aplicación"
    assert taxonomia.es_valida(c.categoria, c.subcategoria) and c.requiere_revision
    assert c.impacto == "Impacto en la confidencialidad de la información"


def test_taxonomia_completa_res_ex_7():
    """4 áreas, 11 efectos observables y sus categorías (arts. 3.º y 4.º)."""
    assert len(taxonomia.TAXONOMIA) == 4
    assert sum(len(e) for e in taxonomia.TAXONOMIA.values()) == 11
    assert sum(len(c) for e in taxonomia.TAXONOMIA.values() for c in e.values()) == 40


def test_recursos_sensibles():
    assert parsers.recurso_sensible("/.git/config")[1].startswith("Archivo(s) de control")
    assert parsers.recurso_sensible("/.env")[1] == "Filtración de secretos en rutas de aplicación"
    assert parsers.recurso_sensible("/wp-config.php.bak")
    assert parsers.recurso_sensible("/backup.sql")
    assert parsers.recurso_sensible("/index.html") is None
    assert parsers.recurso_sensible("/icons/README") is None


def test_plazos():
    t = datetime(2026, 11, 5, 10, 0)
    assert plazos.estado_plazo("alerta_temprana", t, None, t + timedelta(hours=1)).estado == "pendiente"
    assert plazos.estado_plazo("alerta_temprana", t, None, t + timedelta(hours=2, minutes=30)).estado == "por_vencer"
    assert plazos.estado_plazo("alerta_temprana", t, None, t + timedelta(hours=4)).estado == "vencido"
    assert plazos.estado_plazo("alerta_temprana", t, t + timedelta(hours=1)).estado == "enviado"
    assert plazos.duracion_plazo("segundo_reporte", True) == timedelta(hours=24)
    assert plazos.duracion_plazo("segundo_reporte", False) == timedelta(hours=72)


def _inc(**extra):
    t = datetime(2026, 11, 5, 10, 0)
    return {"t_deteccion": t, "evaluacion": None} | extra


def test_informe_final_cuenta_desde_envio_de_la_alerta():
    """DS 295, art. 12: 15 días corridos desde el ENVÍO de la alerta temprana."""
    t = datetime(2026, 11, 5, 10, 0)
    sin_envio = {p.clave: p for p in plazos.plazos_incidente(_inc(), {}, t)}
    assert sin_envio["informe_final"].provisional
    assert sin_envio["informe_final"].vence == t + timedelta(days=15)
    reps = {"alerta_temprana": {"enviado": t + timedelta(hours=2)}}
    con_envio = {p.clave: p for p in plazos.plazos_incidente(_inc(), reps, t)}
    assert con_envio["informe_final"].vence == t + timedelta(days=15, hours=2)
    assert not con_envio["informe_final"].provisional


def test_plazos_oiv_y_servicio_esencial(monkeypatch):
    """Plan de acción solo OIV (art. 11); segundo reporte a 24 h solo si el OIV
    tiene sus servicios esenciales afectados (art. 10)."""
    t = datetime(2026, 11, 5, 10, 0)
    monkeypatch.setattr(config, "ES_OIV", True)
    sin_a = _inc(evaluacion={"decision": "reportable", "criterios": ["d"]})
    p = {x.clave: x for x in plazos.plazos_incidente(sin_a, {}, t)}
    assert p["segundo_reporte"].vence == t + timedelta(hours=72) and p["plan_accion"].aplica
    con_a = _inc(evaluacion={"decision": "reportable", "criterios": ["a", "d"]})
    p = {x.clave: x for x in plazos.plazos_incidente(con_a, {}, t)}
    assert p["segundo_reporte"].vence == t + timedelta(hours=24)
    monkeypatch.setattr(config, "ES_OIV", False)
    p = {x.clave: x for x in plazos.plazos_incidente(con_a, {}, t)}
    assert not p["plan_accion"].aplica and p["segundo_reporte"].vence == t + timedelta(hours=72)


def test_no_reportable_no_tiene_plazos():
    t = datetime(2026, 11, 5, 10, 0)
    inc = _inc(evaluacion={"decision": "no_reportable", "criterios": [], "motivo": "intento_contenido"})
    assert all(p.estado == "no_aplica" for p in plazos.plazos_incidente(inc, {}, t + timedelta(days=30)))


# --- Flujo principal ----------------------------------------------------------------------

def test_flujo_completo(entorno):
    auth, f2b = entorno
    inc_id = nucleo.procesar_ban(IP, "sshd", auth_log=auth, f2b_log=f2b)
    assert inc_id == "INC-20261105-001"
    assert nucleo.procesar_ban(IP, "sshd", auth_log=auth, f2b_log=f2b) == inc_id   # idempotente
    with db.conexion() as con:
        inc = db.obtener_incidente(con, inc_id)
        reps = db.reportes_de(con, inc_id)
    assert inc["intentos"] == 5
    assert (inc["t_contencion"] - inc["t0"]).total_seconds() == pytest.approx(15.33)
    assert inc["t_deteccion"] == inc["t_contencion"]
    assert inc["hash_evidencia"] == auditoria.sha256_texto(inc["evidencia"])
    assert len(inc["bloqueos"]) == 1
    pdf = reps["alerta_temprana"]["ruta_pdf"]
    assert open(pdf, "rb").read(4) == b"%PDF"
    assert reps["alerta_temprana"]["hash_pdf"] == auditoria.sha256_archivo(pdf)
    campos = reps["alerta_temprana"]["campos"]
    assert campos["estado"] == "Contenido (IP bloqueada)"
    assert "Pendiente de evaluación" in campos["evaluacion"]
    assert campos["fecha_inicio"].startswith("05-11-2026 10:31:50")


def test_found_en_rafaga_sin_auth_log(entorno):
    """backend=systemd: Fail2ban escribe los Found 0,2 s antes del Ban, pero cada
    uno trae la hora real del intento."""
    auth, f2b = entorno
    auth.unlink()
    f2b.write_text("".join(
        f"2026-11-05 04:37:41,{100 + i * 20} fail2ban.filter  [812]: INFO    [sshd] Found {IP} - 2026-11-05 04:37:{s}\n"
        for i, s in enumerate((30, 33, 36, 38, 41)))
        + f"2026-11-05 04:37:41,300 fail2ban.actions [812]: NOTICE  [sshd] Ban {IP}\n", encoding="utf-8")
    inc_id = nucleo.procesar_ban(IP, "sshd", auth_log=auth, f2b_log=f2b)
    with db.conexion() as con:
        inc = db.obtener_incidente(con, inc_id)
    assert (inc["t_contencion"] - inc["t0"]).total_seconds() == pytest.approx(11.3)


def test_intentos_antiguos_sin_ban_no_afectan_t0(entorno):
    auth, f2b = entorno
    auth.write_text(f"2026-11-04T19:20:00.000000{_off(datetime(2026, 11, 4, 19, 20))} victima-02 sshd[100]: "
                    f"Failed password for root from {IP} port 40000 ssh2\n" + AUTH, encoding="utf-8")
    f2b.write_text(f"2026-11-04 19:20:00,050 fail2ban.filter  [812]: INFO    [sshd] Found {IP} - "
                   "2026-11-04 19:20:00\n" + F2B, encoding="utf-8")
    inc_id = nucleo.procesar_ban(IP, "sshd", auth_log=auth, f2b_log=f2b)
    with db.conexion() as con:
        inc = db.obtener_incidente(con, inc_id)
    assert inc["t0"] == datetime(2026, 11, 5, 10, 31, 50, 120000) and inc["intentos"] == 5


def test_cambio_de_zona_horaria(entorno):
    auth, f2b = entorno
    antes = datetime(2026, 11, 5, 4, 4, 0, tzinfo=timezone.utc)
    viejo = "".join(f"{(antes + timedelta(seconds=5 * i)).isoformat(timespec='microseconds')} victima-02 "
                    f"sshd[90{i}]: Failed password for root from {IP} port 4100{i} ssh2\n" for i in range(5))
    auth.write_text(viejo + AUTH, encoding="utf-8")
    inc_id = nucleo.procesar_ban(IP, "sshd", auth_log=auth, f2b_log=f2b)
    with db.conexion() as con:
        inc = db.obtener_incidente(con, inc_id)
    assert inc["intentos"] == 5


def _segundo_ataque(auth, f2b, minuto="40", acceso=False):
    with auth.open("a", encoding="utf-8") as f:
        for s in range(10, 13):
            f.write(f"2026-11-05T10:{minuto}:{s}.000000{OFF} victima-02 sshd[5{s}]: "
                    f"Failed password for root from {IP} port 52{s} ssh2\n")
        if acceso:
            f.write(f"2026-11-05T10:{minuto}:12.500000{OFF} victima-02 sshd[599]: "
                    f"Accepted password for root from {IP} port 5299 ssh2\n")
    with f2b.open("a", encoding="utf-8") as f:
        for s in range(10, 13):
            f.write(f"2026-11-05 10:{minuto}:{s},100 fail2ban.filter  [812]: INFO    [sshd] Found {IP} - 2026-11-05 10:{minuto}:{s}\n")
        f.write(f"2026-11-05 10:{minuto}:12,300 fail2ban.actions [812]: NOTICE  [sshd] Ban {IP}\n")


def test_reincidencia_se_agrupa_en_el_mismo_incidente(entorno):
    auth, f2b = entorno
    inc1 = nucleo.procesar_ban(IP, "sshd", auth_log=auth, f2b_log=f2b)
    _segundo_ataque(auth, f2b)
    inc2 = nucleo.procesar_ban(IP, "sshd", auth_log=auth, f2b_log=f2b)
    assert inc2 == inc1
    with db.conexion() as con:
        inc = db.obtener_incidente(con, inc1)
        assert con.execute("SELECT COUNT(*) FROM incidentes").fetchone()[0] == 1
    assert len(inc["bloqueos"]) == 2 and inc["intentos"] == 8
    assert inc["t0"] == datetime(2026, 11, 5, 10, 31, 50, 120000)   # t0 del primer ataque
    assert nucleo.procesar_ban(IP, "sshd", auth_log=auth, f2b_log=f2b) == inc1   # idempotente


def test_ataque_lejano_crea_incidente_nuevo(entorno, monkeypatch):
    monkeypatch.setattr(config, "AGRUPAR_MIN", 5)
    auth, f2b = entorno
    nucleo.procesar_ban(IP, "sshd", auth_log=auth, f2b_log=f2b)
    _segundo_ataque(auth, f2b)                     # 8 minutos después
    assert nucleo.procesar_ban(IP, "sshd", auth_log=auth, f2b_log=f2b) == "INC-20261105-002"


def test_escalamiento_por_acceso_exitoso(entorno, correo):
    auth, f2b = entorno
    inc_id = nucleo.procesar_ban(IP, "sshd", auth_log=auth, f2b_log=f2b)
    with db.conexion() as con:
        db.marcar_reconocido(con, inc_id, datetime.now())
    _segundo_ataque(auth, f2b, acceso=True)
    nucleo.procesar_ban(IP, "sshd", auth_log=auth, f2b_log=f2b)
    with db.conexion() as con:
        inc = db.obtener_incidente(con, inc_id)
    assert inc["subcategoria"] == "Ataque de fuerza bruta exitoso" and inc["requiere_revision"]
    assert inc["reconocido"] is None                   # la alarma vuelve a sonar
    assert any("ESCALAMIENTO" in asunto for asunto, _, _ in correo)


def test_escalamiento_reinicia_la_evaluacion(entorno):
    """Un intento evaluado como no reportable que luego logra acceso debe evaluarse de nuevo."""
    auth, f2b = entorno
    inc_id = nucleo.procesar_ban(IP, "sshd", auth_log=auth, f2b_log=f2b)
    nucleo.evaluar(inc_id, {"decision": "no_reportable", "motivo": "intento_contenido",
                            "justificacion": "Intento bloqueado por Fail2ban sin acceso."}, "admin")
    _segundo_ataque(auth, f2b, acceso=True)
    nucleo.procesar_ban(IP, "sshd", auth_log=auth, f2b_log=f2b)
    with db.conexion() as con:
        inc = db.obtener_incidente(con, inc_id)
    assert inc["evaluacion"] is None
    p = significancia.proponer(inc)
    assert p["propuesta"] == "reportable" and "d" in p["criterios"]


def test_escaneo_web_completo(entorno, tmp_path):
    _, f2b = entorno
    f2b.write_text(F2B_WEB, encoding="utf-8")
    acc = tmp_path / "access.log"
    acc.write_text(_access(25), encoding="utf-8")
    inc_id = nucleo.procesar_ban(IP, "centinela-escaneo-web", f2b_log=f2b, access_log=acc)
    with db.conexion() as con:
        inc = db.obtener_incidente(con, inc_id)
        reps = db.reportes_de(con, inc_id)
    assert inc["escenario"] == "E2" and inc["categoria"] == taxonomia.SIN_EFECTO
    assert inc["detalle"]["herramientas"] == ["Gobuster"]
    assert inc["t0"] == datetime(2026, 11, 5, 11, 0, 0)
    campos = reps["alerta_temprana"]["campos"]
    assert "Gobuster" in campos["indicios"] and "Apache" in campos["activos"]
    assert significancia.proponer(inc)["propuesta"] == "no_reportable"


def test_escaneo_web_que_obtiene_git_es_reportable(entorno, tmp_path):
    _, f2b = entorno
    f2b.write_text(F2B_WEB, encoding="utf-8")
    acc = tmp_path / "access.log"
    acc.write_text(_access(24) + f'{IP} - - [05/Nov/2026:11:00:04 {OFF_APACHE}] "GET /.git/HEAD HTTP/1.1" '
                   f'200 23 "-" "Mozilla/5.00 (Nikto/2.5.0)"\n', encoding="utf-8")
    inc_id = nucleo.procesar_ban(IP, "centinela-escaneo-web", f2b_log=f2b, access_log=acc)
    with db.conexion() as con:
        inc = db.obtener_incidente(con, inc_id)
    assert inc["subcategoria"] == "Archivo(s) de control de versión expuestos en aplicación"
    p = significancia.proponer(inc)
    assert p["propuesta"] == "reportable" and p["criterios"] == ["c"]


# --- Integridad y auditoría ------------------------------------------------------------------

def test_bitacora_detecta_alteracion(entorno):
    auth, f2b = entorno
    nucleo.procesar_ban(IP, "sshd", auth_log=auth, f2b_log=f2b)
    with db.conexion() as con:
        assert auditoria.verificar(con)["integra"]
        con.execute("UPDATE bitacora SET detalle = 'manipulado' WHERE id = 1")
        con.commit()
        r = auditoria.verificar(con)
    assert not r["integra"] and r["falla_en"] == 1


def test_pdf_alterado_se_detecta(entorno):
    auth, f2b = entorno
    nucleo.procesar_ban(IP, "sshd", auth_log=auth, f2b_log=f2b)
    with db.conexion() as con:
        assert all(v["integro"] for v in nucleo.verificar_reportes(con))
        ruta = db.reportes_de(con, "INC-20261105-001")["alerta_temprana"]["ruta_pdf"]
        with open(ruta, "ab") as f:
            f.write(b"%modificado")
        assert not nucleo.verificar_reportes(con)[0]["integro"]


def test_migracion_base_antigua(entorno):
    viejo = """CREATE TABLE incidentes (id TEXT PRIMARY KEY, ip TEXT NOT NULL, jail TEXT, t0 TEXT,
      t_deteccion TEXT, t_contencion TEXT, t_registro TEXT NOT NULL, intentos INTEGER DEFAULT 0,
      usuarios TEXT, accesos_exitosos TEXT, categoria TEXT, subcategoria TEXT, escenario TEXT,
      impacto TEXT, justificacion TEXT, requiere_revision INTEGER DEFAULT 0, evidencia TEXT,
      estado TEXT DEFAULT 'abierto', demo INTEGER DEFAULT 0);
      CREATE TABLE reportes (incidente_id TEXT NOT NULL, tipo TEXT NOT NULL, campos TEXT NOT NULL,
      generado TEXT, enviado TEXT, ruta_pdf TEXT, PRIMARY KEY (incidente_id, tipo));"""
    pdf_viejo = config.DATA_DIR / "viejo.pdf"
    pdf_viejo.write_bytes(b"%PDF-1.4 version anterior")
    con = sqlite3.connect(config.DB_PATH)
    con.executescript(viejo)
    con.execute("INSERT INTO incidentes (id, ip, t_contencion, t_registro, evidencia) VALUES "
                "('INC-1', '1.2.3.4', '2026-11-05 01:00:00.000', '2026-11-05 01:00:00.000', '[\"linea 1\"]')")
    con.execute("INSERT INTO reportes (incidente_id, tipo, campos, ruta_pdf) VALUES "
                "('INC-1', 'alerta_temprana', '{}', ?)", (str(pdf_viejo),))
    con.commit()
    con.close()
    with db.conexion() as c:
        assert db.sin_reconocer(c) == []                       # no hace sonar la alarma
        inc = db.obtener_incidente(c, "INC-1")
        assert all(v["integro"] for v in nucleo.verificar_reportes(c))   # PDF antiguos no salen "alterados"
    assert inc["bloqueos"] == ["2026-11-05 01:00:00.000"]
    assert inc["hash_evidencia"] == auditoria.sha256_texto(["linea 1"])


# --- Notificaciones ---------------------------------------------------------------------------

def test_correo_con_alerta_adjunta(entorno, correo):
    auth, f2b = entorno
    inc_id = nucleo.procesar_ban(IP, "sshd", auth_log=auth, f2b_log=f2b)
    asunto, cuerpo, adjuntos = correo[0]
    assert inc_id in asunto and "fuerza bruta" in asunto
    assert adjuntos and adjuntos[0].endswith("alerta_temprana.pdf")
    assert "Alerta temprana: vence" in cuerpo
    assert "ACCIÓN REQUERIDA" in cuerpo and "Contenido (IP bloqueada" in cuerpo
    with db.conexion() as con:
        assert db.notificacion(con, inc_id, "incidente")["estado"] == "enviado"


def test_correo_reenviado_tras_evaluar_es_coherente(entorno, correo):
    """Si el correo sale después de evaluar (reintento), no pide evaluar de nuevo."""
    auth, f2b = entorno
    _segundo_ataque(auth, f2b, minuto="32", acceso=True)
    inc_id = nucleo.procesar_ban(IP, "sshd", auth_log=auth, f2b_log=f2b)
    nucleo.evaluar(inc_id, {"decision": "reportable", "criterio_d": "1",
                            "justificacion": "Ingreso exitoso con la cuenta root."}, "admin")
    with db.conexion() as con:
        con.execute("DELETE FROM notificaciones")
        notificador.notificar(con, inc_id, "incidente")
    cuerpo = correo[-1][1]
    assert "ACCIÓN REQUERIDA" not in cuerpo and "Evaluación registrada por admin" in cuerpo
    assert "cuenta posiblemente comprometida" in cuerpo


def test_correo_fallido_se_reintenta(entorno, monkeypatch):
    monkeypatch.setattr(config, "SMTP_HOST", "smtp.prueba")
    monkeypatch.setattr(config, "CORREO_PARA", ["delegado@lab"])

    def caido(*a):
        raise ConnectionRefusedError("servidor caído")
    monkeypatch.setattr(notificador, "_enviar", caido)
    auth, f2b = entorno
    inc_id = nucleo.procesar_ban(IP, "sshd", auth_log=auth, f2b_log=f2b)
    with db.conexion() as con:
        assert db.notificacion(con, inc_id, "incidente")["estado"] == "error"
    enviados = []
    monkeypatch.setattr(notificador, "_enviar", lambda a, c, adj: enviados.append(a))
    vigilante.revisar(datetime.now() + timedelta(minutes=2))
    with db.conexion() as con:
        n = db.notificacion(con, inc_id, "incidente")
    assert n["estado"] == "enviado" and n["intentos"] == 2 and enviados


def test_vigilante_avisa_plazo_una_sola_vez(entorno, correo):
    auth, f2b = entorno
    inc_id = nucleo.procesar_ban(IP, "sshd", auth_log=auth, f2b_log=f2b)
    correo.clear()
    momento = datetime(2026, 11, 5, 10, 32, 5) + timedelta(hours=2, minutes=40)   # alerta por vencer
    vigilante.revisar(momento)
    vigilante.revisar(momento + timedelta(minutes=1))
    avisos = [a for a, _, _ in correo if "Alerta temprana" in a]
    assert len(avisos) == 1 and "por vencer" in avisos[0]
    with db.conexion() as con:
        db.marcar_enviado(con, inc_id, "alerta_temprana", momento)
    vigilante.revisar(momento + timedelta(hours=1))      # ya enviado: no avisa que venció
    assert not any("VENCIÓ" in a and "Alerta temprana" in a for a, _, _ in correo)


def test_evaluacion_no_reportable_detiene_avisos_de_plazo(entorno, correo):
    auth, f2b = entorno
    inc_id = nucleo.procesar_ban(IP, "sshd", auth_log=auth, f2b_log=f2b)
    correo.clear()
    with pytest.raises(ValueError):                      # sin justificación no se acepta
        nucleo.evaluar(inc_id, {"decision": "no_reportable", "motivo": "intento_contenido"}, "admin")
    with pytest.raises(ValueError):                      # criterio marcado pero "no reportable"
        nucleo.evaluar(inc_id, {"decision": "no_reportable", "motivo": "otro", "criterio_d": "1",
                                "justificacion": "texto suficientemente largo"}, "admin")
    nucleo.evaluar(inc_id, {"decision": "no_reportable", "motivo": "intento_contenido",
                            "personas_afectadas": "0",
                            "justificacion": "Intento bloqueado por Fail2ban, sin acceso logrado."}, "admin")
    vigilante.revisar(datetime(2026, 11, 5, 14, 0))       # la alerta "vencería" a las 13:32
    assert not [a for a, _, _ in correo if "Alerta temprana" in a]
    with db.conexion() as con:
        inc = db.obtener_incidente(con, inc_id)
        acciones = [b["accion"] for b in auditoria.listar(con)]
        rep = db.reportes_de(con, inc_id)["alerta_temprana"]
    assert inc["evaluacion"]["decision"] == "no_reportable" and inc["evaluacion"]["usuario"] == "admin"
    assert "evaluacion_significancia" in acciones
    assert "No reportable" in rep["campos"]["evaluacion"]          # la alerta se regeneró
    assert rep["hash_pdf"] == auditoria.sha256_archivo(rep["ruta_pdf"])


def test_evaluacion_reportable_exige_criterio(entorno):
    auth, f2b = entorno
    inc_id = nucleo.procesar_ban(IP, "sshd", auth_log=auth, f2b_log=f2b)
    with pytest.raises(ValueError):
        nucleo.evaluar(inc_id, {"decision": "reportable", "justificacion": "texto suficientemente largo"}, "a")
    ev = nucleo.evaluar(inc_id, {"decision": "reportable", "criterio_c": "1", "criterio_a": "1",
                                 "justificacion": "Campaña sostenida que degradó el servicio SSH."}, "admin")
    assert ev["criterios"] == ["a", "c"] and ev["propuesta"] == "no_reportable"
    with db.conexion() as con:
        inc = db.obtener_incidente(con, inc_id)
        p = {x.clave: x for x in plazos.plazos_incidente(inc, db.reportes_de(con, inc_id))}
    assert p["segundo_reporte"].vence == inc["t_deteccion"] + timedelta(hours=24)


def test_incidente_manual(entorno, correo):
    form = {"conocimiento": "2026-11-05T09:00", "inicio": "2026-11-05T08:30",
            "clasificacion": "Indisponibilidad y/o denegación de servicio|Apagado no autorizado de sistemas informáticos",
            "indicios": "Denegación, indisponibilidad o degradación de servicio",
            "descripcion": "El servidor de base de datos se apagó sin autorización durante la noche.",
            "activos": "Servidor de base de datos db-01", "ip": ""}
    ahora = datetime(2026, 11, 5, 9, 10)
    inc_id = nucleo.registrar_manual(form, "admin", ahora)
    assert inc_id == "INC-20261105-001"
    with db.conexion() as con:
        inc = db.obtener_incidente(con, inc_id)
        reps = db.reportes_de(con, inc_id)
    assert inc["escenario"] == "manual" and inc["impacto"] == "Impacto en la disponibilidad de un servicio esencial"
    assert inc["t_deteccion"] == datetime(2026, 11, 5, 9, 0) and inc["reconocido"] is not None
    assert "db-01" in reps["alerta_temprana"]["campos"]["activos"]
    assert reportes.metricas(inc, reps)["ttn_s"] == pytest.approx(600)
    assert significancia.proponer(inc)["criterios"] == ["c"]
    assert correo and "Nuevo incidente" in correo[0][0]
    for malo in ({"clasificacion": "Inventada|Otra"}, {"descripcion": "corta"},
                 {"ip": "999.1.1.1"}, {"conocimiento": "2030-01-01T00:00"}):
        with pytest.raises(ValueError):
            nucleo.registrar_manual(form | malo, "admin", ahora)


def test_datos_personales_omitidos_en_pdf(entorno):
    """DS 295, art. 6.º: las cuentas nominativas no salen en el reporte; root y la IP sí."""
    auth, f2b = entorno
    with auth.open("a", encoding="utf-8") as f:
        f.write(f"2026-11-05T10:32:04.000000{OFF} victima-02 sshd[4106]: Failed password for "
                f"benjamin from {IP} port 51005 ssh2\n")
    inc_id = nucleo.procesar_ban(IP, "sshd", auth_log=auth, f2b_log=f2b)
    with db.conexion() as con:
        inc = db.obtener_incidente(con, inc_id)
        campos = db.reportes_de(con, inc_id)["alerta_temprana"]["campos"]
    assert "benjamin" in inc["usuarios"]                         # la evidencia interna se conserva
    assert "benjamin" not in campos["indicios"] and "omitida" in campos["indicios"]
    assert "root" in campos["indicios"] and IP in campos["indicios"]
    assert reportes.anonimizar("Failed password for benjamin from x", inc) == \
        "Failed password for [cuenta omitida] from x"


def test_metricas_para_las_mediciones(entorno, tmp_path, monkeypatch):
    """TTN total = t0 → alerta (Tabla 17); decisión = detección → evaluación; CSV completo."""
    import csv as _csv
    from centinela import cli
    for k, v in (("ORG_RUT", "11.111.111-1"), ("ORG_DIRECCION", "Lab"), ("ORG_CORREO", "c@lab"),
                 ("DELEGADO_CORREO", "d@lab"), ("DELEGADO_TELEFONO", "+56 2 0000 0000")):
        monkeypatch.setattr(config, k, v)
    auth, f2b = entorno
    inc_id = nucleo.procesar_ban(IP, "sshd", auth_log=auth, f2b_log=f2b, ahora=datetime(2026, 11, 5, 10, 32, 6))
    with db.conexion() as con:
        db.marcar_reconocido(con, inc_id, datetime(2026, 11, 5, 10, 32, 40))
        db.actualizar_incidente(con, inc_id, {"evaluacion": {
            "decision": "no_reportable", "criterios": [], "fecha": "2026-11-05 10:33:05"}})
        inc = db.obtener_incidente(con, inc_id)
        reps = db.reportes_de(con, inc_id)
    m = reportes.metricas(inc, reps)
    assert m["ttn_total_s"] == pytest.approx(m["ttd_s"] + m["ttn_s"])
    assert m["ttr_s"] == pytest.approx(34.55) and m["tte_s"] == pytest.approx(59.55)
    salida = tmp_path / "m.csv"
    cli.main(["exportar", str(salida)])
    fila = next(_csv.DictReader(salida.open(encoding="utf-8")))
    assert set(reportes.COLUMNAS_CSV) == set(fila)
    assert fila["evaluacion"] == "no_reportable" and fila["campos_sin_completar"] == "0"
    assert float(fila["tte_s"]) == pytest.approx(59.55)


def test_buzon_de_laboratorio_recibe_correo_con_adjunto(entorno, monkeypatch, tmp_path):
    """Prueba de punta a punta del correo real (SMTP) con el buzón incluido."""
    import asyncio
    import socket
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "herramientas"))
    import buzon_laboratorio as buzon
    monkeypatch.setattr(buzon, "CARPETA", tmp_path / "buzon")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        puerto = s.getsockname()[1]
    bucle = asyncio.new_event_loop()
    threading.Thread(target=lambda: bucle.run_until_complete(buzon.principal("127.0.0.1", puerto)),
                     daemon=True).start()
    time.sleep(0.5)
    monkeypatch.setattr(config, "SMTP_HOST", "127.0.0.1")
    monkeypatch.setattr(config, "SMTP_PUERTO", puerto)
    monkeypatch.setattr(config, "CORREO_PARA", ["delegado@laboratorio.local"])
    auth, f2b = entorno
    nucleo.procesar_ban(IP, "sshd", auth_log=auth, f2b_log=f2b)
    recibidos = list((tmp_path / "buzon").glob("*"))
    assert any(p.suffix == ".eml" for p in recibidos)
    assert any(p.name.endswith("alerta_temprana.pdf") for p in recibidos)


# --- Panel: seguridad ----------------------------------------------------------------------

def test_panel_exige_inicio_de_sesion(entorno):
    cli = _cliente()
    r = cli.get("/")
    assert r.status_code == 302 and "/login" in r.headers["Location"]
    assert cli.get("/api/estado").status_code == 401


def test_login_y_cabeceras_de_seguridad(entorno):
    cli = _cliente()
    r = _login(cli)
    assert r.status_code == 302
    cookie = r.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
    r = cli.get("/")
    assert r.status_code == 200
    assert "script-src 'self'" in r.headers["Content-Security-Policy"]
    assert "unsafe-inline" not in r.headers["Content-Security-Policy"]
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Content-Type-Options"] == "nosniff"


def test_cookie_segura_con_https(entorno):
    from centinela.app import crear_app
    app = crear_app(https=True)
    cli = app.test_client()
    with db.conexion() as con:
        seguridad.crear_usuario(con, "admin", CLAVE)
    r = cli.post("/login", data={"csrf": _csrf(cli), "usuario": "admin", "clave": CLAVE},
                 base_url="https://localhost")
    assert "Secure" in r.headers["Set-Cookie"]
    assert "Strict-Transport-Security" in cli.get("/", base_url="https://localhost").headers


def test_login_fallido_y_bloqueo_por_fuerza_bruta(entorno):
    cli = _cliente()
    _login(cli)                                   # crea el usuario y entra
    cli = _cliente()
    for _ in range(config.LOGIN_MAX_FALLOS):
        r = _login(cli, clave="incorrecta-xx")
        assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "bloqueado" in html
    r = _login(cli)                               # clave correcta, pero la IP está bloqueada
    assert r.status_code == 200 and "Demasiados intentos" in r.get_data(as_text=True)
    with db.conexion() as con:
        acciones = [b["accion"] for b in auditoria.listar(con)]
    assert "login_ip_bloqueada" in acciones and "login_rechazado_bloqueo" in acciones


def test_csrf_obligatorio(entorno):
    auth, f2b = entorno
    inc_id = nucleo.procesar_ban(IP, "sshd", auth_log=auth, f2b_log=f2b)
    cli = _cliente()
    _login(cli)
    assert cli.post(f"/incidente/{inc_id}/reporte/alerta_temprana/enviado").status_code == 400
    r = cli.post(f"/incidente/{inc_id}/reporte/alerta_temprana/enviado", data={"csrf": _token(cli)})
    assert r.status_code == 302


def test_aplicacion_instalable(entorno):
    cli = _cliente()
    r = cli.get("/manifest.webmanifest")                  # público: el navegador lo pide sin sesión
    assert r.status_code == 200 and r.mimetype == "application/manifest+json"
    m = r.get_json()
    assert m["display"] == "standalone" and m["short_name"] == "Centinela"
    tamanos = {i["sizes"] for i in m["icons"]}
    assert {"192x192", "512x512"} <= tamanos
    for i in m["icons"]:
        assert cli.get(i["src"]).status_code == 200
    sw = cli.get("/sw.js")
    assert sw.status_code == 200 and "fetch" in sw.get_data(as_text=True)
    assert "caches" not in sw.get_data(as_text=True)      # no guarda incidentes en el equipo
    assert cli.get("/favicon.ico").status_code == 200
    html = cli.get("/login").get_data(as_text=True)
    assert 'rel="manifest"' in html and "app.js" in html
    _login(cli)
    r = cli.get("/login")                                 # con sesión abierta va directo al panel
    assert r.status_code == 302 and r.headers["Location"] == "/"
    assert 'rel="manifest"' in cli.get("/").get_data(as_text=True)


def test_login_no_redirige_a_otro_sitio(entorno):
    cli = _cliente()
    with db.conexion() as con:
        seguridad.crear_usuario(con, "admin", CLAVE)
    r = cli.post("/login", data={"csrf": _csrf(cli), "usuario": "admin", "clave": CLAVE,
                                 "siguiente": "//sitio-malicioso.com"})
    assert r.headers["Location"] == "/"


def test_clave_corta_rechazada(entorno):
    with db.conexion() as con, pytest.raises(ValueError):
        seguridad.crear_usuario(con, "corto", "123")


# --- Panel: funciones --------------------------------------------------------------------

def test_panel_completo(entorno):
    auth, f2b = entorno
    inc_id = nucleo.procesar_ban(IP, "sshd", auth_log=auth, f2b_log=f2b)
    cli = _cliente()
    _login(cli)
    assert inc_id.encode() in cli.get("/").data
    assert cli.get(f"/incidente/{inc_id}").status_code == 200
    assert cli.get(f"/incidente/{inc_id}/reporte/alerta_temprana/pdf").data[:4] == b"%PDF"
    r = cli.post(f"/incidente/{inc_id}/reporte/plan_accion",
                 data={"csrf": _token(cli), "recuperacion": "Restaurar desde respaldo", "campo_inventado": "x"})
    assert r.status_code == 302
    with db.conexion() as con:
        campos = db.reportes_de(con, inc_id)["plan_accion"]["campos"]
    assert campos["recuperacion"] == "Restaurar desde respaldo" and "campo_inventado" not in campos
    for tipo in ("alerta_temprana", "segundo_reporte", "plan_accion", "informe_final"):
        assert cli.get(f"/incidente/{inc_id}/reporte/{tipo}").status_code == 200, tipo
    for ruta in ("/metricas", "/metricas.csv", "/estado", "/bitacora", "/incidente/nuevo"):
        assert cli.get(ruta).status_code == 200, ruta


def test_panel_evaluacion_folio_y_registro_manual(entorno):
    auth, f2b = entorno
    inc_id = nucleo.procesar_ban(IP, "sshd", auth_log=auth, f2b_log=f2b)
    cli = _cliente()
    _login(cli)
    html = cli.get(f"/incidente/{inc_id}").get_data(as_text=True)
    assert "Falta evaluar" in html and "art. 3.º" in html
    # Evaluación incompleta: el error se muestra en la misma página
    cli.post(f"/incidente/{inc_id}/evaluacion", data={"csrf": _token(cli), "decision": "reportable"})
    assert "al menos un criterio" in cli.get(f"/incidente/{inc_id}").get_data(as_text=True)
    r = cli.post(f"/incidente/{inc_id}/evaluacion", data={
        "csrf": _token(cli), "decision": "reportable", "criterio_d": "1",
        "justificacion": "Se decide reportar por precaución ante la campaña."})
    assert r.status_code == 302
    assert "Reportable" in cli.get("/").get_data(as_text=True)
    cli.post(f"/incidente/{inc_id}/reporte/alerta_temprana/enviado",
             data={"csrf": _token(cli), "folio": "ANCI-2026-000123"})
    with db.conexion() as con:
        rep = db.reportes_de(con, inc_id)["alerta_temprana"]
        detalle = [b["detalle"] for b in auditoria.listar(con, incidente_id=inc_id)
                   if b["accion"] == "reporte_marcado_enviado"]
    assert rep["folio"] == "ANCI-2026-000123" and "ANCI-2026-000123" in detalle[0]
    assert "Folio ANCI-2026-000123" in cli.get(f"/incidente/{inc_id}").get_data(as_text=True)
    # Registro manual desde el panel
    r = cli.post("/incidente/nuevo", data={
        "csrf": _token(cli), "conocimiento": datetime.now().strftime("%Y-%m-%dT%H:%M"),
        "clasificacion": "Exfiltración y/o exposición de datos|Filtración de datos personales",
        "indicios": "Exposición, robo o fuga de datos",
        "descripcion": "Un proveedor informó la publicación de una planilla con datos de clientes.",
        "activos": "Repositorio documental"})
    assert r.status_code == 302 and "/incidente/INC-" in r.headers["Location"]
    nuevo = r.headers["Location"].rsplit("/", 1)[1]
    html = cli.get(f"/incidente/{nuevo}").get_data(as_text=True)
    assert "Registro manual" in html and "Filtración de datos personales" in html
    r = cli.post("/incidente/nuevo", data={"csrf": _token(cli), "descripcion": "x"})
    assert r.status_code == 200 and "taxonomía" in r.get_data(as_text=True)


def test_alarma_hasta_abrir_el_incidente(entorno):
    auth, f2b = entorno
    cli = _cliente()
    _login(cli)
    inc_id = nucleo.procesar_ban(IP, "sshd", auth_log=auth, f2b_log=f2b)
    cli.get("/")
    cli.get("/metricas")
    assert [p["id"] for p in cli.get("/api/estado").get_json()["sin_reconocer"]] == [inc_id]
    cli.get(f"/incidente/{inc_id}")
    assert cli.get("/api/estado").get_json()["sin_reconocer"] == []
    with db.conexion() as con:
        acciones = [b["accion"] for b in auditoria.listar(con, incidente_id=inc_id)]
    assert "incidente_revisado" in acciones


def test_api_informa_plazos_por_vencer(entorno):
    auth, f2b = entorno
    inc_id = nucleo.procesar_ban(IP, "sshd", auth_log=auth, f2b_log=f2b)
    with db.conexion() as con:   # se simula que la detección fue hace 2 h 40 min
        db.actualizar_incidente(con, inc_id, {"t_deteccion": datetime.now() - timedelta(hours=2, minutes=40)})
    cli = _cliente()
    _login(cli)
    plazos_api = cli.get("/api/estado").get_json()["plazos"]
    assert [(p["reporte"], p["estado"]) for p in plazos_api] == [("Alerta temprana", "por_vencer")]


def test_panel_sobrevive_borrado_de_base(entorno):
    cli = _cliente()
    _login(cli)
    config.DB_PATH.unlink()
    r = cli.get("/api/estado")
    assert r.status_code == 200
