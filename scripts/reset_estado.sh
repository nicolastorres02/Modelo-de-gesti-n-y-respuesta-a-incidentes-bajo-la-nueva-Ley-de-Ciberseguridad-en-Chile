#!/bin/bash
# reset_estado.sh — Deja el entorno limpio entre ejecuciones.
# Ejecutar en victima-02 con sudo.
set -u
ATACANTE_IP="${1:-192.168.58.133}"
echo "[*] Limpiando baneos de Fail2ban..."
sudo fail2ban-client unban --all >/dev/null 2>&1
echo "[*] Limpiando reglas manuales de iptables/ufw..."
sudo iptables -D INPUT -s "$ATACANTE_IP" -j DROP 2>/dev/null
sudo iptables -F INPUT 2>/dev/null
sudo ufw delete deny from "$ATACANTE_IP" >/dev/null 2>&1
echo "[*] Reiniciando Fail2ban..."
sudo systemctl restart fail2ban 2>/dev/null
echo "[OK] Estado reiniciado."
