/*
  Cargador de DXB Garaje. Es lo único legible que se publica: la app entera (pantallas, cálculos,
  reglas) va cifrada en app.cifrada.js (AES-256-GCM) y solo se abre con:
    - el código de acceso (llave derivada con PBKDF2-SHA256), o
    - Face ID / huella, que libera la llave guardada en el teléfono sin poder sacarla de él.
  Cada apertura pide una de las dos. Volver tras más de un minuto fuera = abrir de nuevo.
*/
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const C = window.APP_CIFRADA;
  const CLAVE_BIO = "compra.bio.v1", CLAVE_NO_BIO = "compra.bio.no";
  const LS = {
    leer: (k, d) => { try { const v = localStorage.getItem(k); return v ? JSON.parse(v) : d; } catch (e) { return d; } },
    poner: (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} },
    quitar: (k) => { try { localStorage.removeItem(k); } catch (e) {} },
  };
  const bytes = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const normaliza = (c) => String(c || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
  const b64u = {
    a: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
    de: (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0)),
  };

  /* ---- llave guardada en el teléfono (IndexedDB, no exportable: no se puede leer ni copiar) ---- */
  const almacen = {
    abrir: () => new Promise((ok, mal) => { const r = indexedDB.open("dxb-garaje", 1); r.onupgradeneeded = () => r.result.createObjectStore("llaves"); r.onsuccess = () => ok(r.result); r.onerror = () => mal(r.error); }),
    async op(modo, f) { const db = await this.abrir(); return new Promise((ok) => { const t = f(db.transaction("llaves", modo).objectStore("llaves")); t.onsuccess = () => ok(t.result); t.onerror = () => ok(null); }); },
    leer(k) { return this.op("readonly", (s) => s.get(k)).catch(() => null); },
    poner(k, v) { return this.op("readwrite", (s) => s.put(v, k)).catch(() => null); },
    quitar(k) { return this.op("readwrite", (s) => s.delete(k)).catch(() => null); },
  };

  async function llaveDelCodigo(codigo) {
    const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(normaliza(codigo)), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "PBKDF2", salt: bytes(C.salt), iterations: C.it, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  }
  async function descifrar(llave) {
    const plano = await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes(C.iv) }, llave, bytes(C.ct));
    return JSON.parse(new TextDecoder().decode(plano));
  }

  /* ---- Face ID / huella (WebAuthn, comprobado aquí mismo con la firma del teléfono) ---- */
  async function bioDisponible() {
    try { return !!(window.PublicKeyCredential && await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()); } catch (e) { return false; }
  }
  async function crearBio() {
    const cred = await navigator.credentials.create({ publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)), rp: { name: "DXB Garaje", id: location.hostname },
      user: { id: crypto.getRandomValues(new Uint8Array(16)), name: "DXB Garaje", displayName: "DXB Garaje" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required", residentKey: "preferred" },
      attestation: "none", timeout: 60000 } });
    const r = cred.response, pk = r.getPublicKey && r.getPublicKey();
    if (!pk) throw new Error("Este teléfono no permite Face ID en la app");
    LS.poner(CLAVE_BIO, { id: b64u.a(cred.rawId), pk: b64u.a(pk), alg: r.getPublicKeyAlgorithm ? r.getPublicKeyAlgorithm() : -7 });
  }
  function derARaw(der) {
    let i = 2; if (der[1] & 0x80) i = 2 + (der[1] & 0x7f);
    const entero = () => { i++; const n = der[i++]; let v = der.slice(i, i + n); i += n; while (v.length > 32 && v[0] === 0) v = v.slice(1); const o = new Uint8Array(32); o.set(v, 32 - v.length); return o; };
    const r = entero(), s = entero(), out = new Uint8Array(64); out.set(r); out.set(s, 32); return out;
  }
  async function comprobarBio() {
    const b = LS.leer(CLAVE_BIO, null), reto = crypto.getRandomValues(new Uint8Array(32));
    const a = await navigator.credentials.get({ publicKey: { challenge: reto, rpId: location.hostname, userVerification: "required", timeout: 60000,
      allowCredentials: [{ type: "public-key", id: b64u.de(b.id) }] } });
    const r = a.response, cd = JSON.parse(new TextDecoder().decode(r.clientDataJSON)), ad = new Uint8Array(r.authenticatorData);
    if (cd.type !== "webauthn.get" || cd.challenge !== b64u.a(reto) || cd.origin !== location.origin) throw new Error("Respuesta no válida");
    if (!(ad[32] & 0x04)) throw new Error("El teléfono no comprobó tu identidad");
    const datos = new Uint8Array(ad.length + 32); datos.set(ad); datos.set(new Uint8Array(await crypto.subtle.digest("SHA-256", r.clientDataJSON)), ad.length);
    const ok = b.alg === -257
      ? await crypto.subtle.verify("RSASSA-PKCS1-v1_5", await crypto.subtle.importKey("spki", b64u.de(b.pk), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]), r.signature, datos)
      : await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, await crypto.subtle.importKey("spki", b64u.de(b.pk), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]), derARaw(new Uint8Array(r.signature)), datos);
    if (!ok) throw new Error("Firma no válida");
  }

  /* ---- abrir la app ---- */
  let llaveActual = null, abierta = false;
  function cargarScript(src) { return new Promise((ok) => { const s = document.createElement("script"); s.src = src; s.onload = ok; s.onerror = ok; document.body.appendChild(s); }); }
  async function montar(paquete) {
    const estilo = document.createElement("style"); estilo.textContent = paquete.css; document.head.appendChild(estilo);
    $("app").innerHTML = paquete.html; // marcado propio, sale del paquete cifrado
    window.REGLAS = paquete.reglas;
    window.APP_VERSION = paquete.version;
    window.BUSQUEDA = paquete.busqueda || null;
    window.SYNC = paquete.sync || null; // llave de los datos compartidos con los socios (solo dentro del paquete cifrado)
    for (const src of paquete.librerias || []) await cargarScript(src);
    for (const codigo of paquete.js) { const s = document.createElement("script"); s.textContent = codigo; document.body.appendChild(s); }
    abierta = true; paso(null);
  }
  function paso(id) {
    ["paso-codigo", "paso-bio", "paso-activar"].forEach((p) => ($(p).style.display = p === id ? "block" : "none"));
    $("candado").style.display = id ? "flex" : "none";
    $("candado-error").textContent = "";
  }

  $("b-entrar").onclick = async () => {
    $("candado-error").textContent = ""; $("b-entrar").disabled = true;
    try {
      const llave = await llaveDelCodigo($("codigo").value);
      const paquete = await descifrar(llave); // falla si el código no es el bueno
      $("codigo").value = ""; llaveActual = llave;
      if (LS.leer(CLAVE_BIO, null)) await almacen.poner("llave", llave);
      else if (!LS.leer(CLAVE_NO_BIO, false) && await bioDisponible()) { window.__paquete = paquete; return paso("paso-activar"); }
      await montar(paquete);
    } catch (e) { $("candado-error").textContent = window.crypto && crypto.subtle ? "Código incorrecto." : "Este navegador no puede abrir la app."; }
    finally { $("b-entrar").disabled = false; }
  };
  $("codigo").addEventListener("keydown", (e) => { if (e.key === "Enter") $("b-entrar").click(); });
  $("b-bio").onclick = async () => {
    try {
      await comprobarBio();
      const llave = await almacen.leer("llave");
      if (!llave) return paso("paso-codigo");
      let paquete;
      try { paquete = await descifrar(llave); } catch (e) { await almacen.quitar("llave"); $("candado-error").textContent = "Hay que volver a entrar con el código."; return paso("paso-codigo"); }
      llaveActual = llave; await montar(paquete);
    } catch (e) { $("candado-error").textContent = e && e.name === "NotAllowedError" ? "No se pudo comprobar. Vuelve a intentarlo o usa el código." : (e.message || "No se pudo comprobar"); }
  };
  $("b-usar-codigo").onclick = () => paso("paso-codigo");
  $("b-activar-bio").onclick = async () => {
    try { await crearBio(); await almacen.poner("llave", llaveActual); LS.quitar(CLAVE_NO_BIO); const p = window.__paquete; window.__paquete = null; await montar(p); }
    catch (e) { $("candado-error").textContent = e && e.name === "NotAllowedError" ? "Cancelado. Puedes activarlo luego en Ajustes." : (e.message || "No se pudo activar"); }
  };
  $("b-no-bio").onclick = async () => { LS.poner(CLAVE_NO_BIO, true); const p = window.__paquete; window.__paquete = null; await montar(p); };

  // Lo que la app puede pedir desde Ajustes
  window.Acceso = {
    bioActivo: () => !!LS.leer(CLAVE_BIO, null),
    bioDisponible,
    async activarBio() { await crearBio(); await almacen.poner("llave", llaveActual); LS.quitar(CLAVE_NO_BIO); },
    async quitarBio() { LS.quitar(CLAVE_BIO); LS.poner(CLAVE_NO_BIO, true); await almacen.quitar("llave"); },
    async cerrar() { LS.quitar(CLAVE_BIO); await almacen.quitar("llave"); location.reload(); },
  };

  // volver a la app tras más de un minuto fuera = abrirla otra vez (se borra de memoria y se vuelve a pedir)
  let ocultaDesde = 0;
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) { ocultaDesde = Date.now(); return; }
    if (abierta && ocultaDesde && Date.now() - ocultaDesde > 60000) location.reload();
  });
  window.addEventListener("pageshow", (e) => { if (e.persisted) location.reload(); });

  if ("serviceWorker" in navigator && location.protocol === "https:") navigator.serviceWorker.register("sw.js").catch(() => {});

  // arranque: Face ID si está activado y hay llave guardada; si no, el código
  (async () => {
    if (!C || !window.crypto || !crypto.subtle) { paso("paso-codigo"); $("candado-error").textContent = "Este navegador no puede abrir la app."; return; }
    paso(LS.leer(CLAVE_BIO, null) && await almacen.leer("llave") ? "paso-bio" : "paso-codigo");
  })();
})();
