# Centinela

Centinela notifica incidentes de ciberseguridad a operadores regulados por la
Ley N.º 21.663. Se integra con **Fail2ban** y con las bitácoras `auth.log`,
`access.log` y `fail2ban.log`.

- **Detecta y contiene** con Fail2ban dos escenarios: fuerza bruta SSH (E1) y
  escaneo web con Gobuster o Nikto (E2).
- **Clasifica** cada incidente por su efecto observable, con la taxonomía oficial
  de la ANCI (Res. Ex. N.º 7/2025: 4 áreas, 11 efectos, 40 categorías). Detecta la
  fuerza bruta exitosa y la exposición de recursos (`.git`, `.env`, respaldos), y
  **escala** el incidente cuando se agrava.
- **Propone si el incidente debe reportarse**, con los criterios de efecto
  significativo del DS 295/2024, art. 3.º. El delegado decide y su justificación
  queda en la bitácora.
- **Genera la alerta temprana en PDF** de inmediato y prellena los otros tres
  reportes, con el contenido mínimo de los arts. 5.º y 9 a 12 del DS 295/2024 y
  la omisión de datos personales del art. 6.º.
- **Registra incidentes manuales** que Fail2ban no detecta (ransomware, caídas,
  phishing) con el mismo flujo, y guarda el **folio** de cada envío a la ANCI.
- **Notifica** sin depender del panel abierto:
  - correo al delegado con el PDF adjunto;
  - notificación de escritorio;
  - alarma sonora y aviso en el panel hasta que alguien revisa el incidente.
- **Controla los plazos legales**: el informe final se cuenta desde el envío de la
  alerta y el plan de acción aplica solo a los OIV. Avisa cuando un reporte está
  por vencer o venció.
- **Agrupa reincidencias** de la misma IP en un solo incidente.
- **Protege la evidencia** con huellas SHA-256 y una bitácora de auditoría encadenada.
- **Panel seguro:**
  - HTTPS y usuarios con contraseña cifrada (scrypt);
  - bloqueo por fuerza bruta y protección CSRF;
  - CSP estricta y servidor de producción (Cheroot).
- **Estado del sistema**: avisa si Fail2ban, las jaulas, el reloj, el correo o
  la auditoría fallan.

## Instalación en victima-02

```bash
sudo bash instalar.sh
```

El instalador funciona sin Internet, porque las dependencias vienen en
`vendor/` y `vendor_pil/`. Además:

- genera los certificados HTTPS y el usuario `admin`;
- conecta Fail2ban y deja el panel en `https://<IP>:5000`;
- al actualizar, conserva la configuración, los certificados, los usuarios y
  los incidentes.

Para recibir los correos en el laboratorio, en Windows:

```
python herramientas\buzon_laboratorio.py
```

## Documentación

- [Manual de usuario](docs/manual_usuario.md): panel, certificado, correo,
  alarma, reportes y pruebas con Kali.
- [Manual técnico](docs/manual_tecnico.md): arquitectura, módulos, modelo de
  datos, métricas, controles de seguridad, configuración y limitaciones.

## Pruebas

```bash
pip install -r requirements.txt
python -m pytest
```
