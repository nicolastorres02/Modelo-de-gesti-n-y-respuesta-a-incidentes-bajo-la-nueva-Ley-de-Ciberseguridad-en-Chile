"""Panel web de Centinela: incidentes, plazos legales, reportes PDF, estado del
sistema y bitácora de auditoría. Requiere inicio de sesión."""
import csv
import io
import json
import secrets
import statistics
from datetime import datetime, timedelta
from pathlib import Path

from flask import (Flask, Response, abort, g, redirect, render_template, request,
                   send_file, session, url_for)

from . import (auditoria, config, db, estado, notificador, nucleo, plazos, reportes, seguridad,
               significancia, taxonomia)

ESTADO_TXT = {
    "enviado": "Enviado", "enviado_tarde": "Enviado fuera de plazo", "pendiente": "Pendiente",
    "por_vencer": "Por vencer", "vencido": "Vencido", "no_aplica": "No aplica",
}
PUBLICAS = {"login", "static", "certificado", "manifiesto", "service_worker", "favicon"}

# Service worker mínimo: permite instalar el panel como aplicación. No guarda nada en caché
# (la información de incidentes nunca queda en el equipo); solo muestra un aviso claro si la
# máquina de Centinela no responde.
SERVICE_WORKER = """'use strict';
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const url = (e.notification.data && e.notification.data.url) || '/';
  e.waitUntil(self.clients.matchAll({type: 'window', includeUncontrolled: true}).then((lista) => {
    for (const c of lista) { if ('focus' in c) { c.navigate(url); return c.focus(); } }
    return self.clients.openWindow(url);
  }));
});
self.addEventListener('fetch', (e) => {
  if (e.request.mode !== 'navigate') return;
  e.respondWith(fetch(e.request).catch(() => new Response(
    '<!doctype html><meta charset="utf-8"><title>Centinela sin conexión</title>' +
    '<body style="font-family:system-ui;background:#16233a;color:#fff;padding:40px">' +
    '<h1>Centinela no responde</h1><p>Compruebe que la máquina de Centinela esté encendida, ' +
    'que el servicio esté activo (<code>sudo systemctl status centinela</code>) y que este equipo ' +
    'esté conectado a la misma red. Luego recargue con F5.</p>',
    {status: 503, headers: {'Content-Type': 'text/html; charset=utf-8'}})));
});
"""


def _plazos_de(inc, reps, ahora):
    return [{"e": e, "reporte": reps.get(e.clave), "texto": ESTADO_TXT[e.estado]}
            for e in plazos.plazos_incidente(inc, reps, ahora)]


def _mediana(valores):
    v = [x for x in valores if x is not None]
    return statistics.median(v) if v else None


def crear_app(https: bool | None = None):
    app = Flask(__name__)
    https = bool(config.TLS_CERT) if https is None else https
    app.config.update(
        SECRET_KEY=config.SECRET_KEY or secrets.token_hex(32),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=https,
        SESSION_COOKIE_NAME="centinela_sesion",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=config.SESION_HORAS),
        MAX_CONTENT_LENGTH=256 * 1024,
    )
    db.inicializar()

    # --- Seguridad: sesión, CSRF y cabeceras -------------------------------------------
    @app.before_request
    def _proteger():
        g.usuario = session.get("usuario")
        if request.endpoint not in PUBLICAS and not g.usuario:
            if request.path.startswith("/api/"):
                return {"error": "sesion"}, 401
            return redirect(url_for("login", siguiente=request.path))
        if request.method == "POST":
            recibido = request.form.get("csrf") or request.headers.get("X-CSRF-Token")
            if not seguridad.csrf_valido(session, recibido):
                abort(400, "Token CSRF inválido. Recargue la página e intente de nuevo.")
        return None

    @app.after_request
    def _cabeceras(resp):
        return seguridad.cabeceras(resp, https)

    @app.context_processor
    def _plantillas():
        return {"csrf_token": lambda: seguridad.token_csrf(session), "usuario": session.get("usuario"),
                "config_max": config.LOGIN_MAX_FALLOS}

    @app.template_filter("fecha")
    def _fecha(ts):
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        return ts.strftime("%d-%m-%Y %H:%M:%S") if ts else "—"

    @app.template_filter("seg")
    def _seg(s):
        if s is None:
            return "—"
        if s >= 3600:
            return f"{int(s // 3600)} h {int(s % 3600 // 60)} min"
        if s >= 120:
            return f"{s / 60:.1f} min".replace(".", ",")
        return f"{s:.1f} s".replace(".", ",")

    def _ip():
        return request.remote_addr or "-"

    # --- Sesión ---------------------------------------------------------------------------
    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        siguiente = request.args.get("siguiente") or request.form.get("siguiente") or "/"
        if not siguiente.startswith("/") or siguiente.startswith("//"):
            siguiente = "/"   # evita redirecciones a otros sitios
        if request.method == "GET" and g.usuario:
            return redirect(siguiente)   # ya hay sesión abierta
        if request.method == "POST":
            with db.conexion() as con:
                ok, error = seguridad.autenticar(con, request.form.get("usuario", ""),
                                                 request.form.get("clave", ""), _ip())
            if ok:
                session.clear()
                session.permanent = True
                session["usuario"] = request.form.get("usuario", "").strip().lower()
                seguridad.token_csrf(session)
                return redirect(siguiente)
        with db.conexion() as con:
            sin_usuarios = not seguridad.hay_usuarios(con)
        return render_template("login.html", error=error, siguiente=siguiente, sin_usuarios=sin_usuarios)

    @app.route("/logout", methods=["POST"])
    def logout():
        with db.conexion() as con:
            auditoria.registrar(con, g.usuario, "logout", detalle=f"ip={_ip()}")
        session.clear()
        return redirect(url_for("login"))

    @app.route("/certificado")
    def certificado():
        """Certificado público de la autoridad local, para instalarlo en el navegador."""
        if not config.TLS_CA or not Path(config.TLS_CA).exists():
            abort(404)
        return send_file(config.TLS_CA, mimetype="application/x-x509-ca-cert",
                         download_name="centinela-ca.crt", as_attachment=True)

    # --- Aplicación instalable (PWA) -----------------------------------------------------
    @app.route("/manifest.webmanifest")
    def manifiesto():
        icono = lambda nombre, t, uso="any": {"src": url_for("static", filename=nombre),
                                              "sizes": f"{t}x{t}", "type": "image/png", "purpose": uso}
        datos = {
            "name": "Centinela · Notificación de incidentes",
            "short_name": "Centinela",
            "description": "Gestión y notificación de incidentes de ciberseguridad (Ley N.º 21.663)",
            "lang": "es-CL",
            "id": "/",
            "start_url": url_for("inicio"),
            "scope": "/",
            "display": "standalone",
            "background_color": "#16233a",
            "theme_color": "#16233a",
            "icons": [icono("icono-192.png", 192), icono("icono-512.png", 512),
                      icono("icono-maskable-512.png", 512, "maskable")],
        }
        resp = app.response_class(json.dumps(datos, ensure_ascii=False),
                                  mimetype="application/manifest+json")
        resp.headers["Cache-Control"] = "no-cache"
        return resp

    @app.route("/sw.js")
    def service_worker():
        resp = Response(SERVICE_WORKER, mimetype="text/javascript")
        resp.headers["Cache-Control"] = "no-cache"
        return resp

    @app.route("/favicon.ico")
    def favicon():
        return app.send_static_file("favicon.ico")

    # --- Incidentes -----------------------------------------------------------------------
    @app.route("/")
    def inicio():
        ahora = datetime.now()
        with db.conexion() as con:
            filas = []
            for inc in db.listar_incidentes(con):
                reps = db.reportes_de(con, inc["id"])
                filas.append({"inc": inc, "plazos": _plazos_de(inc, reps, ahora),
                              "m": reportes.metricas(inc, reps)})
        abiertos = [f for f in filas if f["inc"]["estado"] == "abierto"]
        estados = [p["e"].estado for f in abiertos for p in f["plazos"]]
        resumen = {
            "abiertos": len(abiertos),
            "por_evaluar": sum(1 for f in abiertos if not f["inc"].get("evaluacion")),
            "por_vencer": estados.count("por_vencer"),
            "vencidos": estados.count("vencido"),
            "mediana_ttn": _mediana(f["m"]["ttn_s"] for f in filas),
        }
        return render_template("inicio.html", filas=filas, resumen=resumen, ahora=ahora,
                               nombres=[n for _, n, _ in plazos.REPORTES])

    @app.route("/incidente/nuevo", methods=["GET", "POST"])
    def incidente_nuevo():
        """Registro de un incidente que no detectó Fail2ban (ransomware, caída de un
        servicio, aviso de un proveedor, phishing, etc.)."""
        error, valores = None, {}
        if request.method == "POST":
            valores = request.form.to_dict()
            try:
                inc_id = nucleo.registrar_manual(valores, g.usuario)
                return redirect(url_for("incidente", inc_id=inc_id))
            except ValueError as e:
                error = str(e)
        valores.setdefault("conocimiento", datetime.now().strftime("%Y-%m-%dT%H:%M"))
        return render_template("nuevo.html", error=error, v=valores, opciones=taxonomia.opciones(),
                               indicios=nucleo.INDICIOS, base_legal=taxonomia.BASE_LEGAL)

    @app.route("/incidente/<inc_id>")
    def incidente(inc_id):
        ahora = datetime.now()
        with db.conexion() as con:
            # Abrir el detalle es la señal de que el operador tomó conocimiento:
            # se registra la primera vez y con eso se apaga la alarma sonora.
            if db.marcar_reconocido(con, inc_id, ahora):
                auditoria.registrar(con, g.usuario, "incidente_revisado", inc_id)
            inc = db.obtener_incidente(con, inc_id) or abort(404)
            reps = db.reportes_de(con, inc_id)
            notifs = db.notificaciones_de(con, inc_id)
            bitacora = auditoria.listar(con, 100, inc_id)
            integridad = {v["tipo"]: v for v in nucleo.verificar_reportes(con) if v["incidente_id"] == inc_id}
        ev = inc.get("evaluacion")
        propuesta = significancia.proponer(inc)
        # Valores del formulario: la evaluación guardada o, si no hay, la propuesta automática
        form_ev = session.pop("form_evaluacion", None) or (
            {**{f"criterio_{l}": "1" for l in ev["criterios"]}, **ev} if ev else
            {**{f"criterio_{l}": "1" for l in propuesta["criterios"]}, "decision": propuesta["propuesta"],
             "motivo": "intento_contenido" if propuesta["propuesta"] == "no_reportable" else ""})
        return render_template("incidente.html", inc=inc, plazos=_plazos_de(inc, reps, ahora),
                               m=reportes.metricas(inc, reps), ahora=ahora, notifs=notifs,
                               bitacora=bitacora, integridad=integridad,
                               correo_activo=notificador.canal_activo(),
                               ev=ev, propuesta=propuesta, form_ev=form_ev,
                               error_ev=session.pop("error_evaluacion", None),
                               criterios=significancia.CRITERIOS, motivos=significancia.MOTIVOS_NO_REPORTE,
                               resumen_ev=significancia.resumen(ev), es_oiv=config.ES_OIV,
                               manual=reportes.es_manual(inc))

    @app.route("/incidente/<inc_id>/evaluacion", methods=["POST"])
    def evaluacion(inc_id):
        try:
            nucleo.evaluar(inc_id, request.form.to_dict(), g.usuario)
        except KeyError:
            abort(404)
        except ValueError as e:
            session["error_evaluacion"] = str(e)
            session["form_evaluacion"] = request.form.to_dict()
        return redirect(url_for("incidente", inc_id=inc_id) + "#evaluacion")

    @app.route("/incidente/<inc_id>/reporte/<tipo>", methods=["GET", "POST"])
    def reporte(inc_id, tipo):
        if tipo not in reportes.CAMPOS:
            abort(404)
        with db.conexion() as con:
            inc = db.obtener_incidente(con, inc_id) or abort(404)
            previo = db.reportes_de(con, inc_id).get(tipo)
        if request.method == "POST":
            nucleo.generar_reporte(inc_id, tipo, request.form.to_dict(), g.usuario)
            return redirect(url_for("incidente", inc_id=inc_id))
        auto = reportes.campos_automaticos(tipo, inc)
        valores = dict(previo["campos"]) if previo else {}
        for k, v in auto.items():
            valores.setdefault(k, v)
        campos = [(k, e) for k, e in reportes.CAMPOS[tipo]
                  if k not in reportes.SOLO_OIV_AFECTADO or plazos.segundo_reporte_24h(inc)]
        p = next(x for x in plazos.plazos_incidente(inc, db_reps(inc_id)) if x.clave == tipo)
        return render_template("reporte.html", inc=inc, tipo=tipo, nombre=plazos.NOMBRES[tipo],
                               campos=campos, valores=valores, auto=set(auto), plazo=p,
                               base_legal=plazos.BASE_LEGAL[tipo])

    def db_reps(inc_id):
        with db.conexion() as con:
            return db.reportes_de(con, inc_id)

    @app.route("/incidente/<inc_id>/reporte/<tipo>/pdf")
    def pdf(inc_id, tipo):
        with db.conexion() as con:
            r = db.reportes_de(con, inc_id).get(tipo)
            if not r or not r["ruta_pdf"] or not Path(r["ruta_pdf"]).exists():
                abort(404)
            auditoria.registrar(con, g.usuario, "reporte_descargado", inc_id, tipo)
        return send_file(r["ruta_pdf"], mimetype="application/pdf", download_name=Path(r["ruta_pdf"]).name)

    @app.route("/incidente/<inc_id>/reporte/<tipo>/enviado", methods=["POST"])
    def enviado(inc_id, tipo):
        folio = (request.form.get("folio") or "").strip()[:80]
        with db.conexion() as con:
            if db.marcar_enviado(con, inc_id, tipo, datetime.now(), folio):
                auditoria.registrar(con, g.usuario, "reporte_marcado_enviado", inc_id,
                                    f"{tipo}; folio ANCI: {folio or 'no informado'}")
        return redirect(url_for("incidente", inc_id=inc_id))

    @app.route("/incidente/<inc_id>/estado", methods=["POST"])
    def cambiar_estado(inc_id):
        nuevo = "cerrado" if request.form.get("estado") == "cerrado" else "abierto"
        with db.conexion() as con:
            db.actualizar_estado(con, inc_id, nuevo)
            auditoria.registrar(con, g.usuario, f"incidente_{nuevo}", inc_id)
        return redirect(url_for("incidente", inc_id=inc_id))

    @app.route("/incidente/<inc_id>/notificar", methods=["POST"])
    def reenviar_correo(inc_id):
        with db.conexion() as con:
            con.execute("DELETE FROM notificaciones WHERE incidente_id = ? AND motivo = 'incidente' "
                        "AND estado != 'enviado'", (inc_id,))
            auditoria.registrar(con, g.usuario, "correo_reintento_manual", inc_id)
            notificador.notificar(con, inc_id, "incidente")
        return redirect(url_for("incidente", inc_id=inc_id))

    # --- Métricas -------------------------------------------------------------------------
    @app.route("/metricas")
    def metricas():
        incluir_demo = request.args.get("demo") == "1"
        with db.conexion() as con:
            filas = []
            for inc in db.listar_incidentes(con):
                if inc["demo"] and not incluir_demo:
                    continue
                filas.append({"inc": inc, "m": reportes.metricas(inc, db.reportes_de(con, inc["id"]))})
        resumen = {k: _mediana(f["m"][k] for f in filas)
                   for k in ("ttd_s", "ttc_s", "ttn_s", "ttn_total_s", "ttr_s", "tte_s")}
        cumple_ttc = [f["m"]["ttc_s"] <= 60 for f in filas if f["m"]["ttc_s"] is not None]
        cumple_ttn = [f["m"]["ttn_s"] <= 180 * 60 for f in filas if f["m"]["ttn_s"] is not None]
        return render_template("metricas.html", filas=filas, resumen=resumen, incluir_demo=incluir_demo,
                               cumple_ttc=cumple_ttc, cumple_ttn=cumple_ttn)

    @app.route("/metricas.csv")
    def metricas_csv():
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(reportes.COLUMNAS_CSV)
        with db.conexion() as con:
            for inc in db.listar_incidentes(con):
                fila = reportes.fila_csv(inc, db.reportes_de(con, inc["id"]))
                w.writerow([fila[c] for c in reportes.COLUMNAS_CSV])
            auditoria.registrar(con, g.usuario, "metricas_exportadas")
        return Response(buf.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=metricas_centinela.csv"})

    # --- Estado del sistema y bitácora ----------------------------------------------------
    @app.route("/estado")
    def estado_sistema():
        return render_template("estado.html", items=estado.comprobar(), ahora=datetime.now())

    @app.route("/estado/probar-correo", methods=["POST"])
    def probar_correo():
        resultado = notificador.probar()
        with db.conexion() as con:
            auditoria.registrar(con, g.usuario, "correo_prueba", detalle=resultado)
        return render_template("estado.html", items=estado.comprobar(), ahora=datetime.now(),
                               resultado_correo=resultado)

    @app.route("/bitacora")
    def bitacora():
        with db.conexion() as con:
            registros = auditoria.listar(con, 300)
            cadena = auditoria.verificar(con)
            pdfs = nucleo.verificar_reportes(con)
        return render_template("bitacora.html", registros=registros, cadena=cadena, pdfs=pdfs)

    # --- Consulta en vivo -----------------------------------------------------------------
    @app.route("/api/estado")
    def api_estado():
        """Consulta liviana que el navegador hace cada pocos segundos para
        saber si hay incidentes nuevos o cambios, sin recargar la página."""
        ahora = datetime.now()
        with db.conexion() as con:
            n, ultimo_registro = con.execute("SELECT COUNT(*), MAX(t_registro) FROM incidentes").fetchone()
            cambios_inc = con.execute("SELECT MAX(COALESCE(ultimo_bloqueo, '')), SUM(estado = 'cerrado'), "
                                      "COUNT(evaluacion), MAX(COALESCE(json_extract(evaluacion, '$.fecha'), '')) "
                                      "FROM incidentes").fetchone()
            cambios_rep = con.execute(
                "SELECT COUNT(*), MAX(COALESCE(enviado, '')), MAX(COALESCE(generado, '')) FROM reportes").fetchone()
            pendientes = db.sin_reconocer(con)
            # Reportes por vencer o vencidos de incidentes abiertos
            alertas_plazo = []
            for inc in db.listar_incidentes(con):
                if inc["estado"] != "abierto":
                    continue
                for p in _plazos_de(inc, db.reportes_de(con, inc["id"]), ahora):
                    if p["e"].estado in ("por_vencer", "vencido"):
                        alertas_plazo.append({"id": inc["id"], "reporte": p["e"].nombre,
                                              "estado": p["e"].estado, "restante_s": p["e"].restante_s})
        return {
            "incidentes": n,
            "version": f"{n}|{ultimo_registro}|{tuple(cambios_inc)}|{tuple(cambios_rep)}|{len(pendientes)}",
            # Incidentes que nadie ha abierto todavía: mientras haya alguno, suena la alarma
            "sin_reconocer": pendientes,
            "plazos": alertas_plazo,
        }

    return app
