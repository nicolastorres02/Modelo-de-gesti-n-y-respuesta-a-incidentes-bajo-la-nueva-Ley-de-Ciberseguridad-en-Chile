// Panel de Centinela: cuenta regresiva de plazos, actualización en vivo,
// alarma sonora y notificaciones de escritorio.
(function () {
  'use strict';
  const cuerpo = document.body;
  const API = cuerpo.dataset.api, BASE = cuerpo.dataset.base, LOGIN = cuerpo.dataset.login;
  const $ = id => document.getElementById(id);

  // --- Cuenta regresiva de plazos legales ---------------------------------------
  // El servidor envía los segundos restantes (data-restante) calculados con el
  // reloj de la VM, así el desfase horario del navegador no afecta la cuenta.
  let cargada = Date.now();
  function fmt(s) {
    const neg = s < 0; s = Math.abs(Math.floor(s));
    const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600),
          m = Math.floor(s % 3600 / 60), x = s % 60;
    const t = (d ? d + 'd ' : '') + String(h).padStart(2, '0') + ':' +
              String(m).padStart(2, '0') + ':' + String(x).padStart(2, '0');
    return neg ? 'vencido hace ' + t : t;
  }
  function tick() {
    const transcurrido = (Date.now() - cargada) / 1000;
    document.querySelectorAll('[data-restante]').forEach(el => {
      el.textContent = fmt(parseFloat(el.dataset.restante) - transcurrido);
    });
  }
  tick(); setInterval(tick, 1000);

  // --- Alarma sonora --------------------------------------------------------------
  // Patrón de dos tonos (880 Hz + 660 Hz, 1,2 s) generado una vez y reproducido
  // en bucle dentro del motor de audio: sigue sonando aunque la pestaña esté en
  // segundo plano, donde el navegador frena los temporizadores. Los navegadores
  // solo permiten sonido después de un clic del usuario en la página.
  const AudioCtx = window.AudioContext || window.webkitAudioContext;
  const audio = AudioCtx ? new AudioCtx() : null;
  const botonSonido = $('sonido'), botonSonidoAviso = $('aviso-sonido'), barraActivar = $('activar-audio');
  let alarma = false, fuente = null, patron = null;

  function crearPatron() {
    const sr = audio.sampleRate, b = audio.createBuffer(1, Math.round(sr * 1.2), sr);
    const d = b.getChannelData(0);
    const tonos = [[0, 0.25, 880], [0.28, 0.25, 660]];   // [inicio, duración, Hz]
    for (let i = 0; i < d.length; i++) {
      const t = i / sr;
      for (const [ini, dur, f] of tonos) {
        const u = t - ini;
        if (u >= 0 && u < dur) {
          const env = Math.min(1, u / 0.015, (dur - u) / 0.03);   // sin chasquidos
          d[i] = 0.25 * env * Math.sign(Math.sin(2 * Math.PI * f * u));
        }
      }
    }
    return b;
  }
  function reproducir(enBucle) {
    const s = audio.createBufferSource();
    patron = patron || crearPatron();
    s.buffer = patron; s.loop = enBucle;
    s.connect(audio.destination); s.start();
    return s;
  }
  function sonidoActivo() { return !!audio && audio.state === 'running'; }
  function mostrarEstadoSonido() {
    const activo = sonidoActivo();
    botonSonido.textContent = activo ? 'Sonido activo' : 'Activar sonido';
    botonSonido.classList.toggle('activo', activo);
    botonSonidoAviso.hidden = activo || !alarma;
    barraActivar.hidden = activo || !audio;
    // Si la alarma estaba pendiente y el audio recién se habilitó, empieza a sonar
    if (alarma && activo && !fuente) fuente = reproducir(true);
    window.__sonando = !!fuente;
  }
  function activar() {
    if (audio && audio.state !== 'running') audio.resume().then(mostrarEstadoSonido);
    // El mismo clic sirve para pedir permiso de notificaciones de escritorio
    if ('Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission();
    }
  }
  ['pointerdown', 'keydown'].forEach(ev => document.addEventListener(ev, activar));
  if (audio) audio.onstatechange = mostrarEstadoSonido;
  function probarSonido() {
    if (audio) audio.resume().then(() => { reproducir(false); mostrarEstadoSonido(); });
  }
  function alarmaSonora(encender) {
    alarma = encender;
    if (!encender && fuente) { fuente.stop(); fuente.disconnect(); fuente = null; }
    window.__alarma = alarma;
    mostrarEstadoSonido();
  }
  botonSonido.addEventListener('click', activar);
  botonSonidoAviso.addEventListener('click', activar);
  barraActivar.addEventListener('click', activar);
  $('probar-sonido').addEventListener('click', probarSonido);

  // --- Notificaciones de escritorio ---------------------------------------------------
  // Aparecen en Windows aunque el navegador esté minimizado. Se recuerda qué
  // incidentes ya se notificaron para no repetirlas al cambiar de página.
  function yaNotificados() {
    try { return JSON.parse(localStorage.getItem('centinela_notificados') || '[]'); } catch (e) { return []; }
  }
  // Windows/macOS aceptan new Notification(); iPhone (app en la pantalla de inicio)
  // solo acepta notificaciones a través del service worker. Se intenta en ese orden.
  function mostrarNotificacion(titulo, opciones) {
    const porConstructor = () => {
      try {
        const n = new Notification(titulo, opciones);
        n.onclick = () => { window.focus(); location.href = opciones.data.url; };
        return true;
      } catch (e) { return false; }
    };
    if (porConstructor()) return;
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.ready.then(r => r.showNotification(titulo, opciones)).catch(() => {});
    }
  }
  function notificarEscritorio(pendientes) {
    if (!('Notification' in window) || Notification.permission !== 'granted') return;
    const vistos = yaNotificados();
    for (const p of pendientes) {
      if (vistos.includes(p.id)) continue;
      const titulo = 'Centinela: nuevo incidente ' + p.id;
      const opciones = {body: p.subcategoria + ' · IP ' + p.ip, tag: p.id, requireInteraction: true,
                        icon: '/static/icono-192.png', data: {url: BASE + 'incidente/' + p.id}};
      mostrarNotificacion(titulo, opciones);
      vistos.push(p.id);
    }
    try { localStorage.setItem('centinela_notificados', JSON.stringify(vistos.slice(-200))); } catch (e) { /* sin almacenamiento */ }
  }

  // --- Avisos fijos -------------------------------------------------------------------
  const tituloOriginal = document.title;
  function mostrarPendientes(pendientes) {
    const aviso = $('aviso-nuevo');
    if (!pendientes.length) {
      aviso.hidden = true; document.title = tituloOriginal; alarmaSonora(false);
      return;
    }
    const u = pendientes[pendientes.length - 1];   // el más reciente
    $('aviso-titulo').textContent = pendientes.length === 1
      ? 'Nuevo incidente detectado' : pendientes.length + ' incidentes sin revisar';
    $('aviso-texto').textContent = u.id + ' · ' + u.subcategoria + ' · IP ' + u.ip;
    $('aviso-enlace').href = BASE + 'incidente/' + u.id;
    aviso.hidden = false;
    document.title = '(' + pendientes.length + ') Nuevo incidente · Centinela';
    alarmaSonora(true);
    notificarEscritorio(pendientes);
  }
  function mostrarPlazos(lista) {
    const aviso = $('aviso-plazo');
    if (!lista.length) { aviso.hidden = true; return; }
    const vencidos = lista.filter(p => p.estado === 'vencido');
    const p = (vencidos[0] || lista[0]);
    $('plazo-titulo').textContent = vencidos.length
      ? vencidos.length + ' reporte(s) a la ANCI vencido(s)' : lista.length + ' reporte(s) por vencer';
    $('plazo-texto').textContent = p.reporte + ' de ' + p.id + ' · ' +
      (p.estado === 'vencido' ? fmt(p.restante_s) : 'quedan ' + fmt(p.restante_s));
    $('plazo-enlace').href = BASE + 'incidente/' + p.id;
    aviso.classList.toggle('vencido', vencidos.length > 0);
    aviso.hidden = false;
  }

  // --- Actualización en vivo ------------------------------------------------------------
  // Cada 2 s se consulta la API. En las páginas de listado además se reemplaza
  // el contenido sin recargar (en las de formulario no, para no perder lo que
  // el operador está escribiendo).
  const modo = cuerpo.dataset.enVivo;
  const indicador = $('en-vivo');
  let version = null;

  async function refrescarContenido() {
    const r = await fetch(location.href, {cache: 'no-store', credentials: 'same-origin'});
    if (!r.ok) return;
    const html = new DOMParser().parseFromString(await r.text(), 'text/html');
    const nuevo = html.getElementById('contenido');
    if (nuevo) {
      $('contenido').innerHTML = nuevo.innerHTML;
      cargada = Date.now(); tick();
    }
  }
  async function consultar() {
    try {
      const r = await fetch(API, {cache: 'no-store', credentials: 'same-origin'});
      if (r.status === 401) { location.href = LOGIN; return; }   // sesión expirada
      if (!r.ok) throw new Error(r.status);
      const estado = await r.json();
      indicador.classList.remove('caido');
      mostrarPendientes(estado.sin_reconocer);
      mostrarPlazos(estado.plazos || []);
      mostrarEstadoSonido();   // el estado del audio puede cambiar sin aviso
      if (version !== null && estado.version !== version && modo === 'contenido') {
        await refrescarContenido();
      }
      version = estado.version;
    } catch (e) {
      indicador.classList.add('caido');   // el panel no responde
    }
  }
  window.__audio = audio;
  window.__fuente = () => fuente;
  mostrarEstadoSonido();
  consultar(); setInterval(consultar, 2000);
})();
