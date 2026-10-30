# Sincronización de relojes (RNF-04: desfase <= 1 s)

Ambas máquinas virtuales (victima-02 y Kali) sincronizan su reloj contra un
servidor NTP común antes de cada serie de ejecuciones, para garantizar que el
desfase entre relojes sea <= 1 segundo (requisito RNF-04).

## Verificación del desfase antes de medir
```bash
# En cada VM
sudo chronyc tracking         # ver offset actual
sudo chronyc makestep         # forzar corrección si el offset es alto
timedatectl                   # confirmar 'System clock synchronized: yes'
```

Nota: el script `medir_e1.sh` mide TTD/TTC con el reloj de la propia máquina
víctima (donde están los logs), lo que evita que el desfase entre VMs afecte
la medición del TTC.
