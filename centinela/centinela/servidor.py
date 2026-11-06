"""Servidor de producción del panel: Cheroot (WSGI multihilo) con HTTPS.

Reemplaza al servidor de desarrollo de Flask. Si no hay certificado
configurado, sirve por HTTP y lo advierte (solo para pruebas locales).
"""
import sys
from pathlib import Path

from cheroot import wsgi

from . import config, vigilante
from .app import crear_app


def ejecutar(host: str, puerto: int):
    tls = bool(config.TLS_CERT and Path(config.TLS_CERT).exists()
               and config.TLS_KEY and Path(config.TLS_KEY).exists())
    app = crear_app(https=tls)
    servidor = wsgi.Server((host, puerto), app, numthreads=12, server_name="centinela",
                           request_queue_size=50, timeout=30)
    if tls:
        from cheroot.ssl.builtin import BuiltinSSLAdapter
        servidor.ssl_adapter = BuiltinSSLAdapter(config.TLS_CERT, config.TLS_KEY)
        esquema = "https"
    else:
        print("ADVERTENCIA: panel sin HTTPS (no hay certificado configurado).", file=sys.stderr)
        esquema = "http"
    vigilante.iniciar_en_segundo_plano()
    print(f"Centinela: panel en {esquema}://{host}:{puerto}", flush=True)
    try:
        servidor.start()
    except KeyboardInterrupt:
        servidor.stop()
