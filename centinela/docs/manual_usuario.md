# Centinela: manual de usuario

Centinela avisa de los incidentes de ciberseguridad que detecta Fail2ban.
Prepara los reportes que exige la Ley N.º 21.663 y controla sus plazos legales.
Este manual explica cómo usarla en el laboratorio de la tesis.

## 1. Cómo funciona

```
Atacante (Kali) ──► victima-02 ──► Fail2ban bloquea la IP ──► Centinela
                                                                 │
          ┌───────────────────────┬──────────────────────────────┤
          ▼                       ▼                              ▼
  Correo al delegado        Panel web (HTTPS):            Alerta temprana en PDF
  con el PDF adjunto        aviso, alarma sonora,         y control de los 4 plazos
                            notificación de escritorio    del DS 295/2024
```

### Clasificación (Res. Ex. N.º 7/2025)

La taxonomía oficial de la ANCI clasifica cada incidente por su **efecto
observable** (art. 2.º): 4 áreas de impacto, 11 efectos y 40 categorías
(arts. 3.º y 4.º). Centinela deduce el efecto a partir de la evidencia:

| Escenario | Qué se observó | Clasificación |
|---|---|---|
| E1 fuerza bruta SSH (Hydra), bloqueada | Intentos fallidos, sin acceso | **Sin efecto observable** (intento contenido) |
| E1 con acceso exitoso | Inicio de sesión desde la IP atacante | Uso no autorizado de redes y sistemas informáticos → **Ataque de fuerza bruta exitoso** |
| E2 escaneo web (Gobuster, Nikto), bloqueado | Solo errores 404/403 | **Sin efecto observable** (reconocimiento contenido) |
| E2 que obtuvo recursos sensibles | El servidor entregó `/.git`, `.env`, respaldos, etc. | Exfiltración y/o exposición de código fuente, configuraciones o datos |

Un intento bloqueado no tiene categoría en la taxonomía, porque esta solo
clasifica efectos. Igual queda registrado y documentado, y el delegado decide si
se reporta (ver la sección 5).

Si el atacante llega a iniciar sesión, el incidente se **escala**: cambia de
clasificación, vuelve a sonar la alarma, llega un correo de escalamiento y la
evaluación de efecto significativo debe hacerse de nuevo.

Los incidentes que Fail2ban no detecta (ransomware, caída de un servicio,
phishing, aviso de un proveedor) se registran con **Registrar incidente
manual**. Ahí se elige la categoría en una lista con la taxonomía completa, y
el incidente sigue el mismo flujo.

## 2. Primer ingreso al panel

1. Abra `https://192.168.58.132:5000` en el navegador de Windows.
2. **La primera vez**, el navegador advertirá que la conexión no es privada.
   Esto pasa porque el certificado lo emitió una autoridad propia del
   laboratorio. Para que el navegador confíe en ella:
   1. Acepte la advertencia una vez, para entrar.
   2. Descargue el certificado desde `https://192.168.58.132:5000/certificado`.
   3. Haga doble clic en `centinela-ca.crt` → **Instalar certificado…** →
      **Usuario actual** → **Colocar todos los certificados en el siguiente almacén** →
      **Entidades de certificación raíz de confianza** → Finalizar → Sí.
   4. Cierre y vuelva a abrir el navegador. Ya no aparecerá la advertencia.
      Además, las notificaciones de escritorio de Windows requieren este paso.
3. Ingrese con el usuario y la contraseña que mostró el instalador.
   - Cambiar la contraseña: `sudo centinela usuario crear admin`
   - Crear otro usuario: `sudo centinela usuario crear nombre`
   - Tras 5 intentos fallidos en 10 minutos, el acceso desde esa IP se bloquea
     por 10 minutos y queda registrado en la bitácora.
4. Haga **un clic en cualquier parte del panel**. Los navegadores no permiten
   que una página emita sonido ni notificaciones hasta que el usuario hace un
   clic. Mientras falte ese clic, aparece una barra amarilla que lo indica.
   Pulse **Probar sonido** para comprobar el volumen.

### Acceso directo en el escritorio (aplicación Centinela)

La carpeta `herramientas\acceso_directo\` sirve para usar el panel como una
aplicación. Se puede copiar a cualquier computador con Windows que esté en la
red del laboratorio.

1. Haga doble clic en `instalar_centinela.bat`.
2. El programa descarga el certificado de Centinela y lo instala; Windows pide
   confirmar (compare la huella y pulse **Sí**).
3. Queda el ícono **Centinela** en el escritorio y en el menú Inicio. Al abrirlo,
   el panel se abre en su propia ventana, sin barra del navegador (con Edge o Chrome).

Otra opción, desde Edge o Chrome: en la pantalla de inicio de sesión pulse
**Instalar como aplicación de escritorio**. Este botón aparece solo cuando el
certificado ya está instalado.

### En el iPhone (o Android)

La red de VMware solo existe dentro del PC, así que el celular entra a través de
Windows:

1. En Windows, doble clic en `herramientas\celular\habilitar_acceso_celular.bat`
   (pide permiso de administrador). VMware reenvía el puerto 5000 a la VM y el
   firewall lo admite solo desde la red local. Al final muestra la IP del PC en el Wi-Fi.
2. En victima-02: `sudo bash instalar.sh --ip-extra IP_DEL_PC`, para que el
   certificado incluya esa IP. La autoridad no cambia.
3. En el iPhone, con Safari:
   1. Abra `https://IP_DEL_PC:5000/certificado` → **Permitir**.
   2. Vaya a **Ajustes → Perfil descargado → Instalar**.
   3. Luego **Ajustes → General → Información → Ajustes de confianza de certificados**
      y active **Centinela CA (laboratorio)**.
4. Abra `https://IP_DEL_PC:5000`, pulse **Compartir → Agregar a inicio**. Queda el
   ícono Centinela, que se abre a pantalla completa como una app.

Hay una limitación propia de iOS: el sonido y los avisos funcionan mientras la
app está abierta en pantalla. iOS suspende las páginas web en segundo plano.
Para recibir avisos con el teléfono bloqueado, use el correo.

## 3. Recibir los correos en el laboratorio

La red del laboratorio no tiene un servidor de correo, así que Centinela
incluye un **buzón de laboratorio** que corre en Windows:

```
cd C:\Users\nicol\TESIS\centinela
python herramientas\buzon_laboratorio.py
```

Deje esa ventana abierta. Cada correo aparece en pantalla y se guarda en la
carpeta `buzon\`, junto con el PDF adjunto. En la página **Estado** del panel,
el botón **Enviar correo de prueba** sirve para comprobarlo.

Para usar un correo real (por ejemplo Gmail), edite en la VM
`/etc/centinela/centinela.env` (`sudo nano /etc/centinela/centinela.env`):

```
CENTINELA_SMTP_HOST=smtp.gmail.com
CENTINELA_SMTP_PUERTO=587
CENTINELA_SMTP_SEGURIDAD=starttls
CENTINELA_SMTP_USUARIO=sucorreo@gmail.com
CENTINELA_SMTP_CLAVE=contraseña-de-aplicación
CENTINELA_CORREO_PARA=delegado@ejemplo.cl
```

Luego ejecute `sudo systemctl restart centinela-panel`. La VM necesita salida
a Internet para esto.

## 4. Qué pasa cuando hay un incidente

| Aviso | Dónde | Hasta cuándo |
|---|---|---|
| Franja roja "Nuevo incidente detectado" | En todas las páginas del panel | Hasta que se abra el incidente |
| Alarma sonora (dos tonos) | Navegador, incluso en segundo plano | Hasta que se abra el incidente |
| Notificación de escritorio | Windows | Hasta que se cierre |
| Correo con la alerta temprana en PDF | Casilla del delegado | — |

**Abrir el detalle del incidente** registra que el operador tomó conocimiento:
se apagan la alarma y la franja, y queda la hora en "Revisado por el operador".

Si la misma IP vuelve a atacar dentro de 30 minutos, el bloqueo se **agrega
al mismo incidente** (aparece "Reincidente · N bloqueos"), para no llenar el
panel de incidentes repetidos.

## 5. ¿Hay que reportarlo? Evaluación de efecto significativo

La ley obliga a reportar al CSIRT Nacional los incidentes que **puedan tener
efecto significativo** (Ley N.º 21.663, arts. 9.º y 27; DS 295/2024, arts. 2.º
y 3.º). En el detalle de cada incidente, la sección **¿Debe reportarse?**
muestra los cinco criterios del art. 3.º:

- a) interrumpir un servicio esencial;
- b) afectar la integridad física o la salud de las personas;
- c) afectar la integridad o confidencialidad de activos, o la disponibilidad de una red o sistema;
- d) usar o ingresar sin autorización a redes o sistemas;
- e) afectar sistemas con datos personales.

Centinela **propone** una evaluación a partir de la evidencia:

| Evidencia | Propuesta |
|---|---|
| Acceso exitoso | Reportable, letra d) |
| Recursos sensibles expuestos | Reportable, letra c) |
| Intento bloqueado sin efecto | No reportable |

El **delegado decide**: confirma o cambia los criterios, completa la
importancia (personas afectadas, duración, extensión geográfica), elige
"Reportable" o "No reportable" y escribe una justificación. Todo queda en la
bitácora, indicando si la decisión fue distinta de la propuesta.

- Mientras no se evalúa, **los plazos corren**: la alerta temprana vence a las 3 h
  desde el conocimiento.
- Si se declara **no reportable**, los plazos pasan a "No aplica" y dejan de
  llegar avisos de vencimiento.
- Si el incidente se escala, la evaluación se reinicia.

## 6. Reportes al CSIRT Nacional

Cada incidente tiene los reportes del DS 295/2024, con su cuenta regresiva:

| Reporte | Plazo (desde cuándo) | Contenido mínimo |
|---|---|---|
| Alerta temprana | 3 h desde el conocimiento (art. 9.º) | **Automática**. Art. 5.º a) institución, b) delegado, c) fechas, f) indicios, g) activos |
| Segundo reporte | 72 h desde el conocimiento; **24 h** si es OIV y se afectó un servicio esencial, letra a) (art. 10) | Todo el art. 5.º, evaluación de gravedad e impacto, IoC |
| Plan de acción | 7 días, **solo OIV** (art. 11) | Recuperación de información, responsabilidades, tiempo de recuperación |
| Informe final | **15 días desde el envío de la alerta temprana** (art. 12) | a) descripción, b) causa, c) mitigación, d) efectos transfronterizos; más antecedentes adicionales si es OIV con servicio afectado |

Mientras la alerta no se marca como enviada, el informe final muestra un
vencimiento **provisional** contado desde el conocimiento. Si el incidente
sigue sin gestionarse al vencer, se envía un informe parcial cada 15 días (art. 13).

- **Completar / Editar** abre el formulario. Los campos marcados `auto` los
  llenó Centinela desde las bitácoras.
- **PDF** descarga el reporte. En los PDF se **omiten los datos personales**
  (art. 6.º): las cuentas nominativas aparecen como `[cuenta omitida]`. `root` y
  las demás cuentas genéricas se informan, y la IP no es dato personal. La
  evidencia completa se conserva en Centinela con su huella SHA-256.
- **Marcar enviado** registra la entrega en la plataforma de la ANCI (art. 8.º).
  Anote el **folio o comprobante** que entrega la plataforma: queda en el panel y
  en la bitácora.
- Cuando un reporte entra en su último 25 % de plazo aparece una franja
  amarilla y se envía un correo. Si vence, la franja se pone roja y llega
  otro correo.

Los datos de la institución y del delegado (RUT, dirección, correos, teléfono)
y la condición de OIV se configuran en `/etc/centinela/centinela.env`. La
página **Estado** avisa si falta alguno.

## 7. Integridad y auditoría

- Cada PDF y cada conjunto de evidencia tiene una **huella SHA-256**. La
  columna "Integridad PDF" del detalle indica si el archivo sigue intacto.
- La página **Bitácora** muestra todas las acciones: incidentes, reportes,
  correos, inicios de sesión y revisiones. Los registros están encadenados,
  así que cualquier modificación de la base de datos se detecta.
- En la VM: `sudo centinela verificar` comprueba la bitácora y todos los PDF.

## 8. Estado del sistema

La página **Estado** comprueba:

- que Fail2ban esté activo;
- que las jaulas sigan conectadas a Centinela;
- que el reloj esté sincronizado;
- que las bitácoras se puedan leer;
- el correo;
- el certificado HTTPS;
- los datos de la institución y del delegado (art. 5.º a y b);
- la integridad de la auditoría;
- los errores de procesamiento.

Si algo falla, se marca como **PROBLEMA**.

## 9. Probar los escenarios desde Kali

Antes de cada prueba, desbloquee Kali en victima-02:
`sudo fail2ban-client set sshd unbanip 192.168.58.133` (o `centinela-escaneo-web`).

| Escenario | Comando en Kali |
|---|---|
| E1 fuerza bruta SSH | `hydra -I -l root -P /usr/share/wordlists/rockyou.txt -t 2 -W 5 ssh://192.168.58.132` |
| E2 enumeración web | `gobuster dir -u http://192.168.58.132 -w /usr/share/wordlists/dirb/common.txt` |
| E2 escaneo de vulnerabilidades | `nikto -h http://192.168.58.132` |

Para mostrar los casos con efecto observable sin atacar de verdad:

| Demostración (en victima-02) | Resultado |
|---|---|
| `sudo centinela demo` | Fuerza bruta bloqueada: sin efecto, propuesta no reportable |
| `sudo centinela demo --acceso` | Fuerza bruta exitosa: escala el incidente anterior, propuesta reportable (d) |
| `sudo centinela demo --exposicion` | Escaneo que obtiene `/.git`: exposición de código fuente, reportable (c) |

## 10. Exportar métricas

- Panel → **Métricas** → **Descargar CSV**, o en la VM:
  `sudo centinela exportar ~/metricas.csv`.
- Columnas: TTD, TTC, TTN, tiempo hasta la revisión, bloqueos, intentos y
  la decisión de la evaluación (reportable, no reportable o pendiente).
- Los incidentes **DEMO** (`centinela demo`) usan bitácoras sintéticas y no
  deben usarse como mediciones del estudio.
