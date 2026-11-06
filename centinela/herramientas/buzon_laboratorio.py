"""Buzón de correo de laboratorio para el equipo anfitrión (Windows).

Recibe los correos que Centinela envía desde la VM víctima, los guarda en la
carpeta buzon/ (archivo .eml, más los PDF adjuntos) y muestra un resumen en
pantalla. Solo usa la biblioteca estándar de Python: no requiere instalar nada.

Uso (en Windows, desde la carpeta centinela):
    python herramientas\\buzon_laboratorio.py
    python herramientas\\buzon_laboratorio.py --ip 192.168.58.1 --puerto 2525

Es un servidor SMTP mínimo para la red aislada del laboratorio: no reenvía
correos a Internet ni exige autenticación. No debe exponerse a otras redes.
"""
import argparse
import asyncio
import email
import email.policy
import re
from datetime import datetime
from pathlib import Path

CARPETA = Path(__file__).resolve().parent.parent / "buzon"


def guardar(datos: bytes) -> str:
    CARPETA.mkdir(exist_ok=True)
    msg = email.message_from_bytes(datos, policy=email.policy.default)
    marca = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    (CARPETA / f"{marca}.eml").write_bytes(datos)
    adjuntos = []
    for parte in msg.iter_attachments():
        nombre = re.sub(r"[^\w.\-]", "_", parte.get_filename() or "adjunto")
        (CARPETA / f"{marca}_{nombre}").write_bytes(parte.get_payload(decode=True))
        adjuntos.append(nombre)
    cuerpo = msg.get_body(preferencelist=("plain",))
    texto = cuerpo.get_content().strip() if cuerpo else ""
    print("=" * 78)
    print(f"{datetime.now():%d-%m-%Y %H:%M:%S}  CORREO RECIBIDO")
    print(f"De:      {msg['From']}\nPara:    {msg['To']}\nAsunto:  {msg['Subject']}")
    if adjuntos:
        print(f"Adjuntos: {', '.join(adjuntos)}  (guardados en {CARPETA})")
    print("-" * 78)
    print(texto[:1500])
    print("=" * 78, flush=True)
    return marca


async def atender(lector: asyncio.StreamReader, escritor: asyncio.StreamWriter):
    def enviar(linea: str):
        escritor.write((linea + "\r\n").encode())

    enviar("220 buzon-laboratorio Centinela ESMTP listo")
    await escritor.drain()
    try:
        while True:
            linea = await asyncio.wait_for(lector.readline(), timeout=120)
            if not linea:
                break
            cmd = linea.decode(errors="replace").strip()
            verbo = cmd.split(" ", 1)[0].upper()
            if verbo == "EHLO":
                enviar("250-buzon-laboratorio")
                enviar("250-SIZE 20971520")
                enviar("250 8BITMIME")
            elif verbo in ("HELO", "MAIL", "RCPT", "RSET", "NOOP"):
                enviar("250 OK")
            elif verbo == "DATA":
                enviar("354 Termine con <CRLF>.<CRLF>")
                await escritor.drain()
                datos = bytearray()
                while True:
                    l = await asyncio.wait_for(lector.readline(), timeout=120)
                    if l in (b".\r\n", b".\n", b""):
                        break
                    datos += l[1:] if l.startswith(b"..") else l
                marca = guardar(bytes(datos))
                enviar(f"250 OK guardado {marca}")
            elif verbo == "QUIT":
                enviar("221 Adiós")
                await escritor.drain()
                break
            else:
                enviar("502 Comando no implementado")
            await escritor.drain()
    except (asyncio.TimeoutError, ConnectionError):
        pass
    finally:
        escritor.close()


async def principal(ip: str, puerto: int):
    servidor = await asyncio.start_server(atender, ip, puerto)
    print(f"Buzón de laboratorio escuchando en {ip}:{puerto}. Correos en: {CARPETA}")
    print("Deje esta ventana abierta. Ctrl + C para detener.", flush=True)
    async with servidor:
        await servidor.serve_forever()


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Buzón SMTP de laboratorio para Centinela")
    p.add_argument("--ip", default="192.168.58.1", help="IP del anfitrión en la red de las VM")
    p.add_argument("--puerto", type=int, default=2525)
    a = p.parse_args()
    try:
        asyncio.run(principal(a.ip, a.puerto))
    except KeyboardInterrupt:
        print("\nBuzón detenido.")
    except OSError as e:
        if getattr(e, "winerror", None) == 10048 or e.errno in (48, 98, 10048):
            print(f"El puerto {a.puerto} ya está en uso: probablemente el buzón YA está abierto en otra "
                  f"ventana. Use esa ventana (o ciérrela y vuelva a abrir el buzón una sola vez).")
        elif getattr(e, "winerror", None) == 10049 or e.errno in (49, 99, 10049):
            print(f"La IP {a.ip} no existe en este equipo: ¿está encendido VMware (adaptador VMnet8)?")
        else:
            raise
        raise SystemExit(1)
