# Modelo de gestión y respuesta a incidentes bajo la nueva Ley de Ciberseguridad en Chile

Repositorio de evidencias, código y configuración de la tesina **"Modelo de
gestión y respuesta a incidentes bajo la nueva Ley de Ciberseguridad en Chile"**.

- **Autores:** Nicolás Francisco Torres Sandoval · Benjamín Ignacio Alegría Prieto
- **Profesor guía:** Cristian Lorenzo Vidal Silva
- **Institución:** Universidad Bernardo O'Higgins — Ingeniería en Informática
- **Año:** 2026

## Objetivo
Diseñar y evaluar un modelo operativo (runbook + contención automatizada) que
permita a operadores de servicios esenciales cumplir los plazos y la taxonomía
de la ANCI, midiendo experimentalmente la reducción del **tiempo de contención (TTC)**.

## Estructura del repositorio
```
runbook/        Runbook de respuesta a incidentes (ISO 27035 / NIST 800-61)
config/         Configuración real del entorno (Fail2ban, SSH, NTP)
scripts/        Medición del escenario E1 y utilidades de reset/extracción
data/           Datos crudos del TTC (15 ejecuciones base + 15 modelo)
analysis/       Análisis estadístico (Mann-Whitney, tamaño de efecto, boxplot)
results/        Figuras y salidas del análisis
plantillas/     Plantillas de reporte a la ANCI (plazos DS 295/2024)
casos_prueba/   Casos de prueba CP-01 a CP-05 (verificación de RF/RNF)
taxonomia/      Lista de verificación para clasificar incidentes (Res. Ex. 7/2025)
```

## Cómo reproducir el experimento
1. **Entorno:** VMware Workstation con `victima-02` (Ubuntu + OpenSSH + Apache + Fail2ban)
   y `Kali Linux` (Nmap, Nikto, Gobuster, THC-Hydra), en red aislada.
2. **Configuración:** aplicar los archivos de `config/` y sincronizar relojes por NTP.
3. **Medición:** en `victima-02`, ejecutar 15 veces por condición:
   ```bash
   sudo ./scripts/medir_e1.sh base   1 A     # condición base (bloqueo manual)
   sudo ./scripts/medir_e1.sh modelo 1 A     # condición modelo (Fail2ban)
   ```
4. **Análisis:**
   ```bash
   pip install -r analysis/requirements.txt
   python analysis/analisis_ttc.py
   ```

## Justificación de las herramientas
| Herramienta | Por qué se eligió |
|---|---|
| **VMware Workstation** | Permite instantáneas (S0/S1) para reiniciar a un estado idéntico entre ejecuciones, clave para la repetibilidad. |
| **Fail2ban** | IPS de código abierto estándar que correlaciona logs y bloquea en el cortafuegos; materializa la contención automatizada del modelo. |
| **THC-Hydra** | Herramienta estándar de fuerza bruta; genera el vector E1 de forma controlada y parametrizable. |
| **Nmap / Nikto / Gobuster** | Reconocimiento y enumeración estándar de la industria; generan el escenario E2 y la actividad previa. |
| **OpenSSH + Apache** | Servicios reales y ubicuos en operadores de servicios esenciales; dan validez al escenario. |
| **Python + SciPy** | Estándar científico para la prueba U de Mann-Whitney y el tamaño de efecto, con resultados reproducibles. |

## Resultados principales (TTC)
- Mediana TTC: **26,0 s (base) -> 9,2 s (modelo)** = **reducción del 64,6 %**
- U de Mann-Whitney (unilateral): **U = 18,0; p = 4,75 × 10⁻⁵**
- Tamaño del efecto: **r = 0,84** (efecto grande)

## Licencia
Código y configuración bajo licencia MIT (ver `LICENSE`). Documentos y datos de la
tesina: uso académico.
