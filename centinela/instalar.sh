#!/usr/bin/env bash
# Instala o actualiza Centinela en la máquina víctima (Ubuntu con Fail2ban).
# No necesita Internet: las dependencias vienen en vendor/ y vendor_pil/.
#
# Uso:
#   sudo bash instalar.sh           panel HTTPS accesible desde la red del laboratorio
#   sudo bash instalar.sh --local   panel solo dentro de la VM (https://127.0.0.1:5000)
#   sudo bash instalar.sh --ip-extra 192.168.1.8
#        agrega otra IP al certificado (p. ej. la del Wi-Fi de Windows, para entrar
#        desde un celular a través del reenvío de puertos de VMware). Se recuerda.
#
# Al actualizar conserva: configuración (/etc/centinela), certificados,
# usuarios, incidentes y reportes (/var/lib/centinela).
set -euo pipefail

ORIGEN="$(cd "$(dirname "$0")" && pwd)"
DESTINO=/opt/centinela
DATOS=/var/lib/centinela
CONF=/etc/centinela
ENVF=$CONF/centinela.env
TLS=$CONF/tls

LOCAL=0
IPS_NUEVAS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --local) LOCAL=1 ;;
        --ip-extra)
            [[ "${2:-}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { echo "Uso: --ip-extra 192.168.1.8" >&2; exit 1; }
            IPS_NUEVAS+=("$2"); shift ;;
        *) echo "Opción desconocida: $1" >&2; exit 1 ;;
    esac
    shift
done

if [[ $EUID -ne 0 ]]; then echo "Ejecute con sudo: sudo bash instalar.sh" >&2; exit 1; fi
command -v fail2ban-client >/dev/null || { echo "Fail2ban no está instalado." >&2; exit 1; }
command -v openssl >/dev/null || { echo "Falta openssl (sudo apt install openssl)." >&2; exit 1; }

# 1. Python >= 3.10 -----------------------------------------------------------------
PY=$(command -v python3) || { echo "python3 no está instalado." >&2; exit 1; }
VER=$("$PY" -c 'import sys; print(f"{sys.version_info[0]}{sys.version_info[1]}")')
if (( VER < 310 )); then echo "Se requiere Python 3.10 o superior (hay $("$PY" -V))." >&2; exit 1; fi
echo "[1/8] Python $("$PY" -V | cut -d' ' -f2) detectado."

# 2. Archivos de la herramienta --------------------------------------------------------
rm -rf "$DESTINO"
mkdir -p "$DESTINO" "$DATOS" "$CONF" "$TLS"
chmod 700 "$DATOS" "$CONF"
cp -r "$ORIGEN/centinela" "$ORIGEN/vendor" "$DESTINO/"
if ! "$PY" -c 'import PIL' 2>/dev/null; then
    WHL=$(ls "$ORIGEN"/vendor_pil/pillow-*-cp${VER}-cp${VER}-*.whl 2>/dev/null | head -n1 || true)
    [[ -n "$WHL" ]] || { echo "No hay Pillow incluido para Python ${VER}. Instale python3-pil." >&2; exit 1; }
    "$PY" -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' "$WHL" "$DESTINO/vendor"
fi
find "$DESTINO" -name '__pycache__' -prune -exec rm -rf {} +
echo "[2/8] Archivos copiados en $DESTINO."

# 3. Configuración (se conserva al actualizar; solo se agregan claves nuevas) ----------
IP=$(hostname -I | awk '{print $1}')
RED=$(echo "$IP" | cut -d. -f1-3)
HOST_PANEL=0.0.0.0
(( LOCAL )) && HOST_PANEL=127.0.0.1
JAULAS=sshd
[[ -f /var/log/apache2/access.log ]] && JAULAS=sshd,centinela-escaneo-web
touch "$ENVF"; chmod 600 "$ENVF"
asegurar() {  # agrega VAR=valor solo si VAR no está definida
    grep -q "^$1=" "$ENVF" || echo "$1=$2" >> "$ENVF"
}
asegurar CENTINELA_DATA "$DATOS"
asegurar CENTINELA_SECRET_KEY "$("$PY" -c 'import secrets; print(secrets.token_hex(32))')"
asegurar CENTINELA_PANEL_HOST "$HOST_PANEL"
asegurar CENTINELA_PANEL_PUERTO 5000
asegurar CENTINELA_URL_PANEL "https://$IP:5000"
asegurar CENTINELA_TLS_CERT "$TLS/servidor.crt"
asegurar CENTINELA_TLS_KEY "$TLS/servidor.key"
asegurar CENTINELA_TLS_CA "$TLS/ca.crt"
asegurar CENTINELA_JAULAS "$JAULAS"
asegurar CENTINELA_ORG "\"Operador de laboratorio (entorno simulado)\""
# Datos de la institución y del delegado (DS 295/2024, art. 5.º a y b). En el
# laboratorio son ficticios: en una institución real se reemplazan aquí.
asegurar CENTINELA_ORG_RUT "\"11.111.111-1 (ficticio, laboratorio)\""
asegurar CENTINELA_ORG_DIRECCION "\"Laboratorio virtual UBO (entorno simulado)\""
asegurar CENTINELA_ORG_CORREO "ciberseguridad@laboratorio.local"
asegurar CENTINELA_RESPONSABLE "\"Delegado de ciberseguridad\""
asegurar CENTINELA_DELEGADO_CORREO "delegado@laboratorio.local"
asegurar CENTINELA_DELEGADO_TELEFONO "\"+56 2 0000 0000 (ficticio)\""
# ¿Operador de importancia vital? (plan de acción y segundo reporte a 24 h)
asegurar CENTINELA_OIV 1
asegurar CENTINELA_HOST "$(hostname)"
# Correo: por defecto, el buzón de laboratorio del equipo anfitrión (Windows).
# Para Gmail: SMTP_HOST=smtp.gmail.com, PUERTO=587, SEGURIDAD=starttls,
# USUARIO=su correo y CLAVE=contraseña de aplicación.
asegurar CENTINELA_SMTP_HOST "$RED.1"
asegurar CENTINELA_SMTP_PUERTO 2525
asegurar CENTINELA_SMTP_SEGURIDAD ninguna
asegurar CENTINELA_SMTP_USUARIO ""
asegurar CENTINELA_SMTP_CLAVE ""
asegurar CENTINELA_CORREO_DE "centinela@$(hostname).lab"
asegurar CENTINELA_CORREO_PARA "delegado@laboratorio.local"
# IP adicionales del certificado: las ya guardadas más las indicadas con --ip-extra
IPS_EXTRA=$(grep '^CENTINELA_IPS_EXTRA=' "$ENVF" | cut -d= -f2 || true)
for ip in "${IPS_NUEVAS[@]}"; do
    [[ ",$IPS_EXTRA," == *",$ip,"* ]] || IPS_EXTRA="${IPS_EXTRA:+$IPS_EXTRA,}$ip"
done
sed -i '/^CENTINELA_IPS_EXTRA=/d' "$ENVF"
[[ -n "$IPS_EXTRA" ]] && echo "CENTINELA_IPS_EXTRA=$IPS_EXTRA" >> "$ENVF"
echo "[3/8] Configuración en $ENVF."

# 4. Certificados HTTPS con una autoridad local --------------------------------------
# La autoridad se crea una sola vez (así el navegador que ya confía en ella sigue
# confiando). El certificado del servidor se vuelve a emitir si cambia alguna IP.
SAN="IP:$IP,IP:127.0.0.1"
for ip in ${IPS_EXTRA//,/ }; do SAN="$SAN,IP:$ip"; done
SAN="$SAN,DNS:$(hostname),DNS:localhost"
reemitir=0
if [[ ! -f "$TLS/servidor.crt" || ! -f "$TLS/ca.key" ]]; then
    reemitir=1
else
    ACTUAL=$(openssl x509 -in "$TLS/servidor.crt" -noout -ext subjectAltName 2>/dev/null || true)
    for ip in $IP ${IPS_EXTRA//,/ }; do
        grep -q "IP Address:$ip\$\|IP Address:$ip," <<< "$ACTUAL" || reemitir=1
    done
fi
if [[ ! -f "$TLS/ca.crt" || ! -f "$TLS/ca.key" ]]; then
    cat > "$TLS/ca.cnf" <<EOF
[req]
distinguished_name = dn
prompt = no
[dn]
CN = Centinela CA (laboratorio)
O = Centinela
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF
    openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 3650 -config "$TLS/ca.cnf" -extensions v3_ca \
        -keyout "$TLS/ca.key" -out "$TLS/ca.crt"
    chmod 600 "$TLS/ca.key"
    reemitir=1
fi
if (( reemitir )); then
    cat > "$TLS/servidor.cnf" <<EOF
[req]
distinguished_name = dn
prompt = no
[dn]
CN = $IP
O = Centinela
[v3_servidor]
subjectAltName = $SAN
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF
    openssl req -newkey rsa:2048 -nodes -sha256 -config "$TLS/servidor.cnf" \
        -keyout "$TLS/servidor.key" -out "$TLS/servidor.csr"
    openssl x509 -req -in "$TLS/servidor.csr" -CA "$TLS/ca.crt" -CAkey "$TLS/ca.key" -CAcreateserial \
        -out "$TLS/servidor.crt" -days 825 -sha256 -extfile "$TLS/servidor.cnf" -extensions v3_servidor
    rm -f "$TLS/servidor.csr"
    # Comprobación: el certificado del servidor debe validar contra la autoridad local
    openssl verify -CAfile "$TLS/ca.crt" "$TLS/servidor.crt" >/dev/null
    chmod 600 "$TLS"/*.key
    echo "[4/8] Certificado HTTPS emitido para: ${SAN//IP:/}"
else
    echo "[4/8] Certificados HTTPS existentes conservados."
fi

# 5. Comando 'centinela' (carga la configuración) -----------------------------------
cat > /usr/local/bin/centinela <<EOF
#!/bin/sh
set -a
. $ENVF
set +a
export PYTHONPATH=$DESTINO/vendor:$DESTINO
exec $PY -m centinela "\$@"
EOF
chmod 755 /usr/local/bin/centinela
/usr/local/bin/centinela --help >/dev/null
echo "[5/8] Comando 'centinela' disponible."

# 6. Integración con Fail2ban (no modifica jail.local ni sus parámetros) -------------
cp "$ORIGEN/integracion/fail2ban/action.d/centinela.conf" /etc/fail2ban/action.d/
cp "$ORIGEN/integracion/fail2ban/filter.d/centinela-escaneo-web.conf" /etc/fail2ban/filter.d/
if [[ "$JAULAS" == *escaneo-web* ]]; then
    cp "$ORIGEN/integracion/fail2ban/jail.d/centinela.local" /etc/fail2ban/jail.d/centinela.local
else
    sed '/^# Escenario E2/,$d' "$ORIGEN/integracion/fail2ban/jail.d/centinela.local" > /etc/fail2ban/jail.d/centinela.local
fi
fail2ban-client -t >/dev/null
systemctl restart fail2ban
echo "[6/8] Fail2ban conectado a Centinela (jaulas: $JAULAS)."

# 7. Primer usuario del panel ---------------------------------------------------------
CLAVE_NUEVA=""
if [[ -z "$(/usr/local/bin/centinela usuario listar)" ]]; then
    CLAVE_NUEVA=$(/usr/local/bin/centinela usuario crear admin --generar | sed -n 's/.*Contraseña: //p')
    echo "[7/8] Usuario 'admin' creado."
else
    echo "[7/8] Usuarios existentes conservados."
fi

# 8. Servicio del panel y rotación del registro ---------------------------------------
cat > /etc/systemd/system/centinela-panel.service <<EOF
[Unit]
Description=Centinela - panel web de incidentes y plazos ANCI
After=network.target fail2ban.service

[Service]
ExecStart=/usr/local/bin/centinela panel
Restart=on-failure
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=full
ReadWritePaths=$DATOS /var/log
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
cat > /etc/logrotate.d/centinela <<EOF
/var/log/centinela.log {
    weekly
    rotate 8
    compress
    missingok
    notifempty
}
EOF
systemctl daemon-reload
systemctl enable centinela-panel >/dev/null 2>&1
systemctl restart centinela-panel
echo "[8/8] Panel web iniciado."

echo
echo "Centinela instalado."
echo "  Panel:        https://$( [[ $HOST_PANEL == 127.0.0.1 ]] && echo 127.0.0.1 || echo "$IP" ):5000"
if [[ -n "$CLAVE_NUEVA" ]]; then
    echo "  Usuario:      admin"
    echo "  Contraseña:   $CLAVE_NUEVA   (anótela; cámbiela con: sudo centinela usuario crear admin)"
fi
echo "  Certificado:  descárguelo desde https://$IP:5000/certificado e instálelo en Windows"
echo "                (ver docs/manual_usuario.md) para que el navegador confíe en el panel."
echo "  Correo:       $(grep '^CENTINELA_SMTP_HOST=' "$ENVF" | cut -d= -f2):$(grep '^CENTINELA_SMTP_PUERTO=' "$ENVF" | cut -d= -f2) -> $(grep '^CENTINELA_CORREO_PARA=' "$ENVF" | cut -d= -f2)"
echo "  Configuración: $ENVF   Registro: /var/log/centinela.log   Datos: $DATOS"
for J in ${JAULAS//,/ }; do
    echo "  Jaula $J: $(fail2ban-client get "$J" actions 2>&1 | tail -n1 || true)"
done
