#!/bin/bash
# =====================================================================
#  medir_e1.sh  —  Medición automática del escenario E1 (fuerza bruta SSH)
#  Ejecutar EN victima-02 (donde están los logs).  Requiere sudo.
#
#  Uso:   sudo ./medir_e1.sh <condicion> <n_run> <operador>
#     condicion : base   (Fail2ban OFF, bloqueo manual)
#                 modelo (Fail2ban ON, bloqueo automático)
#     n_run     : número de la ejecución (1..15)
#     operador  : A o B
#
#  Mide con el reloj de ESTA máquina (evita el desfase entre VMs):
#     TTD = detección − t0      TTC = bloqueo − t0      TTN = alerta − detección
#  y agrega una fila a  resultados_e1.csv
# =====================================================================
set -u
AUTH=/var/log/auth.log
F2B=/var/log/fail2ban.log
ATACANTE_IP="192.168.58.133"     # <-- IP de Kali (ajusta si cambia)
CSV="resultados_e1.csv"
COND="${1:-}"; NRUN="${2:-}"; OP="${3:-A}"

if [[ "$COND" != "base" && "$COND" != "modelo" ]] || [[ -z "$NRUN" ]]; then
  echo "Uso: sudo $0 <base|modelo> <n_run> <operador>"; exit 1
fi
[[ -f "$CSV" ]] || echo "id_ejecucion,escenario,condicion,operador,TTD_s,TTC_s,TTN_min,clasificacion_correcta,completitud_reporte_pct,falsos_positivos_n,intentos_tras_bloqueo_n,valida,observaciones" > "$CSV"

echo "=============================================================="
echo " E1 | condición: $COND | ejecución: $NRUN | operador: $OP"
echo "=============================================================="

# ---------- RESET del estado ----------
echo "[*] Reiniciando estado..."
if [[ "$COND" == "modelo" ]]; then
  sudo fail2ban-client unban --all >/dev/null 2>&1
  sudo systemctl restart fail2ban;  sleep 2
  echo "    Fail2ban ACTIVO y sin baneos."
else
  sudo systemctl stop fail2ban >/dev/null 2>&1
  sudo iptables -D INPUT -s "$ATACANTE_IP" -j DROP 2>/dev/null   # quita bloqueo manual previo
  sudo ufw delete deny from "$ATACANTE_IP" >/dev/null 2>&1
  echo "    Fail2ban DETENIDO (condición base, bloqueo manual)."
fi

N0=$(wc -l < "$AUTH"); F0=$(wc -l < "$F2B" 2>/dev/null || echo 0)

echo
echo ">>> LANZA AHORA el ataque en Kali:"
echo "    hydra -t 2 -W 5 -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.58.132"
echo "    (el script detecta el inicio solo)..."

# ---------- t0 = primer intento fallido ----------
while :; do
  if sudo tail -n +$((N0+1)) "$AUTH" | grep -q "Failed password"; then break; fi
  sleep 0.3
done
T0=$(date +%s.%N)
echo "[t0] Primer intento fallido detectado."

if [[ "$COND" == "modelo" ]]; then
  # ---------- detección + bloqueo automático (Fail2ban) ----------
  echo "[*] Esperando que Fail2ban banee la IP..."
  while :; do
    if sudo tail -n +$((F0+1)) "$F2B" | grep -q "Ban $ATACANTE_IP"; then break; fi
    sleep 0.3
  done
  TBAN=$(date +%s.%N)
  TTD=$(echo "$TBAN - $T0" | bc); TTC=$TTD   # detección y bloqueo coinciden
  TDET=$TBAN
  echo "[ban] IP baneada. TTD=TTC=${TTC}s"
else
  # ---------- detección + bloqueo manual (operador) ----------
  read -p "[detección] Cuando IDENTIFIQUES el ataque en los logs, presiona ENTER..." _
  TDET=$(date +%s.%N); TTD=$(echo "$TDET - $T0" | bc)
  echo "    Ahora bloquea la IP (ej: sudo ufw deny from $ATACANTE_IP)."
  read -p "[bloqueo] Cuando TERMINES de bloquear, presiona ENTER..." _
  TBLK=$(date +%s.%N); TTC=$(echo "$TBLK - $T0" | bc)
  echo "    TTD=${TTD}s  TTC=${TTC}s"
fi

# ---------- TTN: llenar formulario de alerta temprana ----------
read -p "[notificación] Llena el formulario de alerta temprana. Presiona ENTER al terminar..." _
TNOT=$(date +%s.%N)
TTN_MIN=$(echo "scale=2; ($TNOT - $TDET)/60" | bc)
echo "    TTN=${TTN_MIN} min"

# ---------- Campos RF ----------
read -p "¿Clasificación ANCI correcta? (1=sí / 0=no): " CLAS
read -p "Completitud del reporte (0-100): " COMPL
read -p "Falsos positivos observados (0 normalmente): " FP
read -p "Intentos aceptados tras el bloqueo (0 normalmente): " ITB
read -p "Observaciones (ENTER si ninguna): " OBS

# redondear tiempos a 1 decimal
TTDr=$(printf "%.1f" "$TTD"); TTCr=$(printf "%.1f" "$TTC")
echo "E1-$COND-$(printf '%02d' $NRUN),E1,$COND,$OP,$TTDr,$TTCr,$TTN_MIN,${CLAS:-1},${COMPL:-100},${FP:-0},${ITB:-0},1,\"$OBS\"" >> "$CSV"
echo
echo "[OK] Fila agregada a $CSV"
echo "     Repite con:  sudo $0 $COND $((NRUN+1)) $OP"
