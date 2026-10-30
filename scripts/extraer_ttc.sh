#!/bin/bash
# extraer_ttc.sh — Extrae el TTC de la condición MODELO desde fail2ban.log.
# TTC = instante del 'Ban' - instante del primer 'Found' para la IP atacante.
# Uso: ./extraer_ttc.sh <IP_atacante> [ruta_fail2ban.log]
set -u
IP="${1:-192.168.58.133}"
LOG="${2:-/var/log/fail2ban.log}"
found=$(grep "Found $IP" "$LOG" | head -1 | awk '{print $1" "$2}')
ban=$(grep "Ban $IP"   "$LOG" | tail -1 | awk '{print $1" "$2}')
if [[ -z "$found" || -z "$ban" ]]; then echo "No se hallaron eventos Found/Ban para $IP"; exit 1; fi
t0=$(date -d "$found" +%s.%N); t1=$(date -d "$ban" +%s.%N)
echo "Found: $found"; echo "Ban:   $ban"
echo "TTC = $(echo "$t1 - $t0" | bc) s"
