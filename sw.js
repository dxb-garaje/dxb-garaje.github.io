/* Guarda la app en el teléfono para que abra sin cobertura (en el showroom).
   Siempre intenta la versión nueva primero; si no hay red, usa la guardada. */
const CACHE = "dxb-garaje-v14";
const ARCHIVOS = ["./", "index.html", "cargador.js", "cargador.css", "app.cifrada.js", "manifest.webmanifest", "logo.png", "icono-180.png", "icono-512.png", "icono-192.png", "icono-maskable-192.png", "icono-maskable-512.png", "lib/zxing.min.js", "lib/tesseract.min.js", "lib/jspdf.umd.min.js", "lib/pdf-lib.min.js", "lib/pdf.min.js", "lib/pdf.worker.min.js"];

self.addEventListener("install", (e) => { e.waitUntil(caches.open(CACHE).then((c) => c.addAll(ARCHIVOS))); self.skipWaiting(); });
self.addEventListener("activate", (e) => {
  e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k)))));
  self.clients.claim();
});
self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== "GET" || url.origin !== location.origin) return; // cambio de moneda y VIN: siempre por red
  e.respondWith(
    fetch(e.request).then((r) => { const copia = r.clone(); caches.open(CACHE).then((c) => c.put(e.request, copia)); return r; })
      .catch(() => caches.match(e.request, { ignoreSearch: true }).then((r) => r || caches.match("index.html")))
  );
});
