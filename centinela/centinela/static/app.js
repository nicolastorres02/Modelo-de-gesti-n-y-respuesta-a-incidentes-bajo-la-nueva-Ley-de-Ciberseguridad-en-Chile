'use strict';
// Permite instalar el panel como aplicación de escritorio (PWA) en Edge y Chrome.
(function () {
  if ('serviceWorker' in navigator && window.isSecureContext) {
    navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch(function () {});
  }
  var boton = document.getElementById('instalar-app');
  if (!boton) return;
  var solicitud = null;
  window.addEventListener('beforeinstallprompt', function (e) {
    e.preventDefault();
    solicitud = e;
    boton.hidden = false;
  });
  boton.addEventListener('click', function () {
    if (!solicitud) return;
    solicitud.prompt();
    solicitud.userChoice.finally(function () { solicitud = null; boton.hidden = true; });
  });
  window.addEventListener('appinstalled', function () { boton.hidden = true; });
})();
