# Lista de verificación: clasificación de incidentes (Res. Ex. N.º 7/2025)

Instrumento de clasificación usado por ambos evaluadores (concordancia: kappa de Cohen).

> **Nota de corrección (noviembre de 2026).** La versión anterior de esta lista
> (disponible en el historial del repositorio) usaba las categorías
> "Usos no autorizados de redes y sistemas / Intento de acceso no autorizado" y
> "Recopilación de información / Escaneo". Esas categorías **no figuran** en la
> Res. Ex. N.º 7/2025 de la ANCI, que clasifica los incidentes por su **efecto
> observable** (art. 2.º): 4 áreas de impacto, 11 efectos observables y 40
> categorías (arts. 3.º y 4.º). Esta versión sigue el texto oficial publicado en
> el Diario Oficial del 1 de marzo de 2025. La herramienta Centinela aplica la
> misma regla de forma automática (`centinela/centinela/taxonomia.py` y
> `clasificador.py`).

## Regla general

1. **¿Se observó un efecto?**
   - Ejemplos: acceso logrado, datos o configuraciones expuestos, servicio interrumpido o degradado, datos o configuración modificados.
   - **No** → el intento fue contenido antes de producir un efecto. No corresponde
     a ninguna categoría de la taxonomía: se documenta como **evento de seguridad
     sin efecto observable**, y el delegado evalúa si debe reportarse
     (DS 295/2024, art. 3.º).
   - **Sí** → identificar el área, el efecto y la categoría del art. 4.º.

## Escenario E1: fuerza bruta SSH (Hydra)

- [ ] ¿Hubo un inicio de sesión exitoso desde la IP atacante (`Accepted password` en `auth.log`)?
  - **No** (Fail2ban bloqueó la IP) → **Sin efecto observable (intento contenido)**.
  - **Sí** → Área *Impacto en el uso legítimo de recursos* · Efecto *Uso no
    autorizado de redes y sistemas informáticos* · Categoría **Ataque de fuerza
    bruta exitoso**.

## Escenario E2: enumeración web (Gobuster, Nikto)

- [ ] ¿El servidor entregó con éxito (código 2xx) algún recurso sensible?
  - **No** (solo respuestas 4xx; IP bloqueada) → **Sin efecto observable (reconocimiento contenido)**.
  - `.git`, `.svn` → Área *Impacto en la confidencialidad de la información* ·
    Efecto *Exfiltración y/o exposición de código fuente* · Categoría **Archivo(s)
    de control de versión expuestos en aplicación**.
  - `.env`, claves, credenciales → Efecto *Exfiltración y/o exposición de
    configuraciones* · Categoría **Filtración de secretos en rutas de aplicación**.
  - Archivos de configuración, `phpinfo`, respaldos `.bak` → Categoría
    **Filtración de configuraciones en rutas de aplicación**.
  - Volcados `.sql` o respaldos de datos → Efecto *Exfiltración y/o exposición de
    datos* · Categoría **Documentos públicos con datos sensibles**.

## Taxonomía oficial completa (Res. Ex. N.º 7/2025, arts. 3.º y 4.º)

| Área de impacto | Efecto observable | Categorías |
|---|---|---|
| a. Uso legítimo de recursos | i. Uso no autorizado de redes y sistemas informáticos | Acceso no autorizado a almacenamiento · Ataque de fuerza bruta exitoso · Explotación de vulnerabilidades de autenticación · Uso de credenciales comprometidas |
| | ii. Phishing o fraude en infraestructura propia | Envío de correo no deseado o phishing desde infraestructura propia · Inclusión de sitio fraudulento en infraestructura propia |
| | iii. Phishing o fraude relacionado con la institución | Envío de correo no deseado o phishing sobre una organización · Envío de correo no deseado o phishing usando remitentes de la institución |
| | iv. Ejecución no autorizada de código | Ejecución remota de código a través de parámetros de aplicación · Inyección de requerimientos (prompts) en LLM · Inyección de consultas NoSQL · Inyección de consultas SQL |
| b. Confidencialidad de la información | v. Exfiltración y/o exposición de datos | Adversario en el medio (MitM) · Apropiación de credenciales mediante phishing · Base de datos sin protección · Documentos públicos con datos sensibles · Filtración de datos personales · Keylogger en uso · Divulgación de enumeraciones de usuarios y/o credenciales en foros |
| | vi. Exfiltración y/o exposición de configuraciones | Filtración de configuraciones en rutas de aplicación · Filtración de secretos en rutas de aplicación |
| | vii. Exfiltración y/o exposición de código fuente | Archivo(s) de control de versión expuestos en aplicación · Sistema de control de versión expuesto |
| c. Disponibilidad de un servicio esencial | viii. Indisponibilidad y/o denegación de servicio | Agotamiento de conexiones TCP · Apagado no autorizado de sistemas informáticos · Ataque de amplificación DNS/NTP · Ataque físico contra infraestructura TI · Denegación de servicio por explotación de vulnerabilidades · Eliminación de configuraciones críticas · Tráfico de red excesivo (volumétrico) |
| | ix. Degradación de servicio | Secuestro de recursos (cryptojacking) · Sobrecarga de bases de datos · Uso excesivo de ancho de banda |
| d. Integridad de la información | x. Modificación no autorizada de datos | Alteración de bases de datos · Alteración de sitio web (defacement) · Manipulación de datos no autentificados · Modificación de logs de auditoría |
| | xi. Manipulación no autorizada de configuración | Alteración de reglas de firewall · Desactivación de registros de seguridad · Modificación de políticas de acceso |

## ¿Debe reportarse? (DS 295/2024, art. 3.º)

Solo se reportan los incidentes que puedan tener **efecto significativo**, es
decir, que sean capaces de:

- a) interrumpir la continuidad de un servicio esencial;
- b) afectar la integridad física o la salud de las personas;
- c) afectar la integridad o confidencialidad de activos informáticos, o la disponibilidad de una red o sistema;
- d) utilizar o ingresar sin autorización a redes o sistemas informáticos;
- e) afectar sistemas informáticos que contengan datos personales.

La importancia se pondera por el número de personas afectadas, la duración y
la extensión geográfica.

## Campos a registrar por incidente

- Efecto observable y categoría asignados (evaluador A):
- Efecto observable y categoría asignados (evaluador B):
- ¿Coinciden? (sí/no):
- ¿Reportable? Criterios del art. 3.º que se cumplen:
- Observaciones:

Fuente: Resolución Exenta N.º 7, de 2025, de la Agencia Nacional de
Ciberseguridad (Diario Oficial, 1 de marzo de 2025, CVE 2617388); Decreto Supremo
N.º 295, de 2024 (Diario Oficial, 1 de marzo de 2025, CVE 2617387).
