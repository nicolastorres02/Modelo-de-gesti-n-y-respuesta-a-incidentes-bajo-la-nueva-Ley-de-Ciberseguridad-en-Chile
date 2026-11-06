"""Línea de comandos de Centinela.

    centinela ban --ip IP --jail sshd          (lo ejecuta Fail2ban en cada bloqueo)
    centinela panel                            (panel web HTTPS)
    centinela usuario crear NOMBRE             (crear usuario o cambiar su contraseña)
    centinela usuario listar | eliminar NOMBRE
    centinela verificar                        (integridad de la bitácora y los PDF)
    centinela probar-correo                    (envía un correo de prueba)
    centinela vigilar                          (una revisión de plazos y reintentos)
    centinela exportar metricas.csv            (TTD/TTC/TTN/TTR a CSV)
    centinela demo [--web|--acceso|--exposicion]  (incidente de ejemplo, marcado DEMO)
"""
import argparse
import csv
import getpass
import secrets
import sys
import traceback
from datetime import datetime, timedelta

from . import auditoria, config, db, notificador, nucleo, reportes, seguridad, vigilante


def cmd_ban(a):
    try:
        inc_id = nucleo.procesar_ban(a.ip, a.jail)
    except Exception as e:
        # Un error no debe pasar inadvertido: queda en la bitácora y en el
        # panel (Estado del sistema), además de en /var/log/centinela.log.
        traceback.print_exc()
        try:
            with db.conexion() as con:
                auditoria.registrar(con, "centinela", "error_procesamiento", None,
                                    f"ip={a.ip}; jaula={a.jail}; {type(e).__name__}: {e}")
        except Exception:
            pass
        sys.exit(1)
    print(f"{datetime.now():%Y-%m-%d %H:%M:%S} Centinela: incidente {inc_id} registrado "
          f"(ip={a.ip}, jaula={a.jail}).", flush=True)


def cmd_panel(a):
    from .servidor import ejecutar
    ejecutar(a.host, a.puerto)


def cmd_usuario(a):
    with db.conexion() as con:
        if a.accion == "listar":
            for u in seguridad.listar_usuarios(con):
                print(f"{u['nombre']:<20} creado {u['creado'][:19]}  último acceso {(u['ultimo_acceso'] or '-')[:19]}")
            return
        if not a.nombre:
            sys.exit("Indique el nombre de usuario.")
        if a.accion == "eliminar":
            print("Usuario eliminado." if seguridad.eliminar_usuario(con, a.nombre, "cli") else "No existe.")
            return
        if a.generar:
            clave = secrets.token_urlsafe(12)
        else:
            clave = getpass.getpass("Contraseña nueva (mínimo 10 caracteres): ")
            if clave != getpass.getpass("Repita la contraseña: "):
                sys.exit("Las contraseñas no coinciden.")
        try:
            seguridad.crear_usuario(con, a.nombre, clave, "cli")
        except ValueError as e:
            sys.exit(str(e))
        print(f"Usuario '{a.nombre.lower()}' listo." + (f" Contraseña: {clave}" if a.generar else ""))


def cmd_verificar(a):
    with db.conexion() as con:
        cadena = auditoria.verificar(con)
        pdfs = nucleo.verificar_reportes(con)
    print(f"Bitácora: {'ÍNTEGRA' if cadena['integra'] else 'ALTERADA en el registro ' + str(cadena['falla_en'])} "
          f"({cadena['registros']} registros)")
    malos = [p for p in pdfs if not p["integro"]]
    print(f"PDF: {len(pdfs) - len(malos)}/{len(pdfs)} coinciden con su huella SHA-256")
    for p in malos:
        print(f"  ALTERADO o faltante: {p['incidente_id']} {p['tipo']} ({p['ruta']})")
    sys.exit(0 if cadena["integra"] and not malos else 2)


def cmd_probar_correo(a):
    print(notificador.probar())


def cmd_vigilar(a):
    for inc_id, motivo, resultado in vigilante.revisar():
        print(f"{inc_id} {motivo}: {resultado}")


def cmd_exportar(a):
    with db.conexion() as con:
        filas = [reportes.fila_csv(inc, db.reportes_de(con, inc["id"])) for inc in db.listar_incidentes(con)]
        auditoria.registrar(con, "cli", "metricas_exportadas", detalle=a.salida)
    with open(a.salida, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=reportes.COLUMNAS_CSV)
        w.writeheader()
        w.writerows(filas)
    print(f"{len(filas)} incidentes exportados a {a.salida}")


def cmd_demo(a):
    """Escribe bitácoras sintéticas con marcas cercanas al instante actual y las
    procesa, para mostrar el panel sin la VM. El incidente queda marcado DEMO y
    no debe usarse como medición del estudio."""
    config.asegurar_directorios()
    ip, host = "192.168.58.133", config.NOMBRE_HOST
    fin = datetime.now().replace(microsecond=0)
    t = [fin - timedelta(seconds=s) for s in (22, 17, 12, 7, 2)]
    f2b = config.DATA_DIR / "demo_fail2ban.log"
    a.web = a.web or a.exposicion
    jail = "centinela-escaneo-web" if a.web else "sshd"
    off = fin.astimezone().strftime("%z")
    with f2b.open("w", encoding="utf-8") as f:
        for ts in t:
            f.write(f"{ts:%Y-%m-%d %H:%M:%S},101 fail2ban.filter  [812]: INFO    [{jail}] Found {ip} - {ts:%Y-%m-%d %H:%M:%S}\n")
        f.write(f"{t[-1]:%Y-%m-%d %H:%M:%S},450 fail2ban.actions [812]: NOTICE  [{jail}] Ban {ip}\n")
    if a.web:
        acc = config.DATA_DIR / "demo_access.log"
        with acc.open("w", encoding="utf-8") as f:
            for i, ts in enumerate(t * 6):
                f.write(f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} {off}] "GET /admin{i} HTTP/1.1" 404 437 "-" '
                        f'"Mozilla/5.00 (Nikto/2.6.0) (Evasions:None) (Test:00{i})"\n')
            if a.exposicion:   # el escaneo encontró el repositorio .git publicado
                for ruta in ("/.git/HEAD", "/.git/config"):
                    f.write(f'{ip} - - [{t[-1]:%d/%b/%Y:%H:%M:%S} {off}] "GET {ruta} HTTP/1.1" 200 92 "-" '
                            f'"Mozilla/5.00 (Nikto/2.6.0) (Evasions:None) (Test:007)"\n')
        inc_id = nucleo.procesar_ban(ip, jail, f2b_log=f2b, access_log=acc, demo=True)
    else:
        auth = config.DATA_DIR / "demo_auth.log"
        with auth.open("w", encoding="utf-8") as f:
            for i, ts in enumerate(t):
                f.write(f"{ts.isoformat()}.000000{off[:3]}:{off[3:]} {host} sshd-session[{4100 + i}]: "
                        f"Failed password for root from {ip} port {51000 + i} ssh2\n")
            if a.acceso:       # la contraseña se adivinó: fuerza bruta exitosa
                f.write(f"{t[-1].isoformat()}.500000{off[:3]}:{off[3:]} {host} sshd-session[4199]: "
                        f"Accepted password for root from {ip} port 51099 ssh2\n")
        inc_id = nucleo.procesar_ban(ip, jail, auth_log=auth, f2b_log=f2b, demo=True)
    print(f"Incidente de demostración {inc_id} creado (marcado como DEMO).")


def main(argv=None):
    p = argparse.ArgumentParser(prog="centinela",
                                description="Notificación de incidentes a la ANCI integrada con Fail2ban.")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("ban", help="Procesar un bloqueo de Fail2ban")
    s.add_argument("--ip", required=True)
    s.add_argument("--jail", required=True)
    s.set_defaults(f=cmd_ban)

    s = sub.add_parser("panel", help="Iniciar el panel web (HTTPS)")
    s.add_argument("--host", default=config.HOST_PANEL)
    s.add_argument("--puerto", type=int, default=config.PUERTO_PANEL)
    s.set_defaults(f=cmd_panel)

    s = sub.add_parser("usuario", help="Gestionar usuarios del panel")
    s.add_argument("accion", choices=["crear", "listar", "eliminar"])
    s.add_argument("nombre", nargs="?")
    s.add_argument("--generar", action="store_true", help="Generar una contraseña aleatoria")
    s.set_defaults(f=cmd_usuario)

    s = sub.add_parser("verificar", help="Verificar la integridad de la bitácora y los PDF")
    s.set_defaults(f=cmd_verificar)

    s = sub.add_parser("probar-correo", help="Enviar un correo de prueba")
    s.set_defaults(f=cmd_probar_correo)

    s = sub.add_parser("vigilar", help="Revisar plazos y reintentar correos una vez")
    s.set_defaults(f=cmd_vigilar)

    s = sub.add_parser("exportar", help="Exportar métricas a CSV")
    s.add_argument("salida")
    s.set_defaults(f=cmd_exportar)

    s = sub.add_parser("demo", help="Crear un incidente de demostración con bitácoras de ejemplo")
    s.add_argument("--web", action="store_true", help="Escenario E2 (escaneo web)")
    s.add_argument("--acceso", action="store_true", help="E1 con acceso exitoso (fuerza bruta exitosa)")
    s.add_argument("--exposicion", action="store_true", help="E2 que obtiene /.git (exposición de código fuente)")
    s.set_defaults(f=cmd_demo)

    a = p.parse_args(argv)
    a.f(a)


if __name__ == "__main__":
    sys.exit(main())
