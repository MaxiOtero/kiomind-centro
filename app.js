/* KioMind Centro — licencias y control de kioscos.
 * Todo corre en el dispositivo: la clave privada nunca sale de acá.
 * Bóveda cifrada (AES-GCM, clave derivada con PBKDF2) en localStorage.
 */
(function () {
  "use strict";

  /* ------------------------------------------------------------ utils */
  const $ = (sel, root = document) => root.querySelector(sel);
  const app = $("#app");
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  const STORAGE_VAULT = "kmc.vault";
  const STORAGE_META = "kmc.meta";
  const PBKDF2_ITER = 310000;

  function b64(bytes) {
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s);
  }
  function unb64(str) {
    const s = atob(str);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }
  function b64url(bytes) {
    return b64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function todayKey(d = new Date()) {
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
  }
  function fmtDate(iso) {
    if (!iso) return "—";
    const ymd = String(iso).match(/^(\d{4})-(\d{2})-(\d{2})$/);
    if (ymd) return `${ymd[3]}/${ymd[2]}/${ymd[1]}`;
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toLocaleDateString("es-AR", { day: "2-digit", month: "2-digit", year: "numeric" });
  }
  function fmtDateTime(iso) {
    if (!iso) return "—";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toLocaleString("es-AR", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" });
  }
  function esc(s) {
    return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  }
  function randomId(len) {
    const bytes = crypto.getRandomValues(new Uint8Array(len));
    let out = "";
    for (const b of bytes) out += ALPHABET[b % 32];
    return out;
  }
  function normalizeMachineCode(text) {
    const cleaned = String(text || "").toUpperCase().replace(/[^0-9A-Z]/g, "");
    const body = cleaned.startsWith("KM") ? cleaned.slice(2) : cleaned;
    if (body.length !== 8) return null;
    for (const ch of body) if (!ALPHABET.includes(ch)) return null;
    return `KM-${body.slice(0, 4)}-${body.slice(4)}`;
  }

  let toastTimer = null;
  function toast(msg) {
    const el = $("#toast");
    el.textContent = msg;
    el.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => (el.hidden = true), 2400);
  }

  async function copyText(text, label = "Copiado") {
    try {
      await navigator.clipboard.writeText(text);
      toast(label);
    } catch {
      toast("No se pudo copiar. Seleccioná el texto y copialo a mano.");
    }
  }

  /* ----------------------------------------------------------- crypto */
  async function deriveKey(password, salt, iterations) {
    const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
      base,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function encryptVault(vault, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(password, salt, PBKDF2_ITER);
    const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(vault)));
    return {
      kind: "kiomind-centro-vault",
      v: 1,
      iter: PBKDF2_ITER,
      salt: b64(salt),
      iv: b64(iv),
      data: b64(new Uint8Array(data)),
      publicKey: vault.keys.publicKey,
      savedAt: new Date().toISOString(),
    };
  }

  async function decryptVault(blob, password) {
    const key = await deriveKey(password, unb64(blob.salt), blob.iter || PBKDF2_ITER);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(blob.iv) }, key, unb64(blob.data));
    return JSON.parse(dec.decode(plain));
  }

  /* ---------------------------------------------------------- storage */
  function readBlob() {
    try {
      const raw = localStorage.getItem(STORAGE_VAULT);
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  }
  function readMeta() {
    try {
      return JSON.parse(localStorage.getItem(STORAGE_META) || "{}");
    } catch {
      return {};
    }
  }
  function writeMeta(patch) {
    const next = { ...readMeta(), ...patch };
    localStorage.setItem(STORAGE_META, JSON.stringify(next));
    return next;
  }

  const session = { vault: null, password: null };

  async function persist() {
    if (!session.vault || !session.password) return;
    const blob = await encryptVault(session.vault, session.password);
    localStorage.setItem(STORAGE_VAULT, JSON.stringify(blob));
    writeMeta({ publicKey: session.vault.keys.publicKey, dirtySince: readMeta().dirtySince || new Date().toISOString() });
  }

  function newVault() {
    const kp = nacl.sign.keyPair();
    return {
      v: 1,
      createdAt: new Date().toISOString(),
      keys: { publicKey: b64(kp.publicKey), secretKey: b64(kp.secretKey) },
      kioscos: [],
      revoked: [],
    };
  }

  /* --------------------------------------------------------- licencias */
  function buildLicense(machine, name, expiresAt) {
    const payload = { v: 1, i: `LIC-${randomId(6)}`, m: machine, n: name, d: todayKey(), e: expiresAt || null };
    const payloadBytes = enc.encode(JSON.stringify(payload));
    const sig = nacl.sign.detached(payloadBytes, unb64(session.vault.keys.secretKey));
    return { payload, text: `KM1.${b64url(payloadBytes)}.${b64url(sig)}` };
  }

  function backupPending() {
    const meta = readMeta();
    if (!meta.lastBackupAt) return true;
    return Boolean(meta.dirtySince && meta.dirtySince > meta.lastBackupAt);
  }

  /* --------------------------------------------------------- backups */
  async function downloadBackup() {
    const blob = await encryptVault(session.vault, session.password);
    blob.kind = "kiomind-centro-backup";
    const json = JSON.stringify(blob, null, 2);
    const stamp = todayKey().replace(/-/g, "");
    const fileName = `kiomind-centro-${stamp}.kmc`;
    const file = new File([json], fileName, { type: "application/json" });
    let shared = false;
    if (navigator.canShare && navigator.canShare({ files: [file] })) {
      try {
        await navigator.share({ files: [file], title: "Copia KioMind Centro" });
        shared = true;
      } catch (err) {
        if (err && err.name === "AbortError") return false;
      }
    }
    if (!shared) {
      const url = URL.createObjectURL(file);
      const a = document.createElement("a");
      a.href = url;
      a.download = fileName;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 4000);
    }
    writeMeta({ lastBackupAt: new Date().toISOString(), dirtySince: null });
    toast("Copia de seguridad generada");
    return true;
  }

  function readFileAsText(file) {
    return new Promise((resolve, reject) => {
      const r = new FileReader();
      r.onload = () => resolve(String(r.result));
      r.onerror = () => reject(r.error);
      r.readAsText(file);
    });
  }

  /* -------------------------------------------------------------- QR */
  function openQrScanner(onCode) {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      toast("Este navegador no permite usar la cámara.");
      return;
    }
    const modal = document.createElement("div");
    modal.className = "qr-modal";
    modal.innerHTML = `
      <p>Apuntá al QR que muestra KioMind</p>
      <video playsinline muted autoplay></video>
      <p class="small muted" id="qr-status">Iniciando cámara…</p>
      <button class="btn secondary" style="max-width:320px" id="qr-cancel">Cancelar</button>`;
    document.body.appendChild(modal);
    const video = $("video", modal);
    const status = $("#qr-status", modal);
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    let stream = null;
    let stopped = false;

    function stop() {
      stopped = true;
      if (stream) stream.getTracks().forEach((t) => t.stop());
      modal.remove();
    }
    $("#qr-cancel", modal).onclick = stop;

    navigator.mediaDevices
      .getUserMedia({ video: { facingMode: { ideal: "environment" } }, audio: false })
      .then((s) => {
        stream = s;
        video.srcObject = s;
        status.textContent = "Buscando código…";
        const tick = () => {
          if (stopped) return;
          if (video.readyState === video.HAVE_ENOUGH_DATA) {
            canvas.width = video.videoWidth;
            canvas.height = video.videoHeight;
            ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
            const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
            const code = jsQR(img.data, img.width, img.height, { inversionAttempts: "dontInvert" });
            if (code && code.data) {
              const normalized = normalizeMachineCode(code.data);
              if (normalized) {
                stop();
                onCode(normalized);
                return;
              }
              status.textContent = "Ese QR no es un código de equipo KioMind.";
            }
          }
          requestAnimationFrame(tick);
        };
        requestAnimationFrame(tick);
      })
      .catch(() => {
        status.textContent = "No se pudo abrir la cámara. Escribí el código a mano.";
      });
  }

  /* ---------------------------------------------------------- router */
  function route() {
    return location.hash.replace(/^#\/?/, "") || "home";
  }
  function go(path) {
    location.hash = `#/${path}`;
  }
  window.addEventListener("hashchange", render);

  /* ------------------------------------------------------------ views */
  function shell(title, sub, body, { tabs = true, fab = null } = {}) {
    const current = route().split("/")[0];
    const tabsHtml = tabs
      ? `<nav class="tabs">
          <a href="#/home" class="${current === "home" || current === "kiosco" ? "active" : ""}"><span class="ic">🏪</span>Kioscos</a>
          <a href="#/nueva" class="${current === "nueva" ? "active" : ""}"><span class="ic">🔑</span>Licencia</a>
          <a href="#/backup" class="${current === "backup" ? "active" : ""}"><span class="ic">💾</span>Copia</a>
          <a href="#/config" class="${current === "config" ? "active" : ""}"><span class="ic">⚙️</span>Ajustes</a>
        </nav>`
      : "";
    app.innerHTML = `
      <header class="topbar">
        <div class="brand">K</div>
        <div style="flex:1;min-width:0">
          <h1>${esc(title)}</h1>
          ${sub ? `<div class="sub">${esc(sub)}</div>` : ""}
        </div>
      </header>
      ${body}
      ${fab ? `<div class="fab">${fab}</div>` : ""}
      ${tabsHtml}`;
  }

  function viewSetup(mode) {
    const restoring = mode === "restore";
    shell(
      "KioMind Centro",
      "Primera vez en este dispositivo",
      `
      <div class="card">
        <h3>${restoring ? "Restaurar una copia" : "Crear la llave de licencias"}</h3>
        <p class="small muted">${
          restoring
            ? "Elegí el archivo .kmc de tu copia de seguridad y escribí la contraseña con la que la hiciste."
            : "Se genera acá la llave privada que firma las licencias. Queda cifrada con una contraseña que solo sabés vos. Sin esa contraseña nadie puede usar este dispositivo para emitir licencias."
        }</p>
        <form id="setup-form">
          ${
            restoring
              ? `<div class="field"><label>Archivo de copia (.kmc)</label><input class="input" type="file" id="setup-file" accept=".kmc,application/json" required /></div>`
              : ""
          }
          <div class="field"><label>Contraseña</label><input class="input" type="password" id="setup-pass" autocomplete="new-password" required minlength="6" /></div>
          ${
            restoring
              ? ""
              : `<div class="field"><label>Repetir contraseña</label><input class="input" type="password" id="setup-pass2" autocomplete="new-password" required minlength="6" /></div>
                 <div class="alert warn small">Anotala en un lugar seguro. No hay forma de recuperarla.</div>`
          }
          <div class="actions">
            <button class="btn" type="submit">${restoring ? "Restaurar" : "Crear"}</button>
            <button class="btn ghost" type="button" id="setup-switch">${restoring ? "Crear una llave nueva" : "Tengo una copia de seguridad"}</button>
          </div>
        </form>
      </div>`,
      { tabs: false }
    );
    $("#setup-switch").onclick = () => viewSetup(restoring ? "create" : "restore");
    $("#setup-form").onsubmit = async (e) => {
      e.preventDefault();
      const pass = $("#setup-pass").value;
      if (restoring) {
        const file = $("#setup-file").files[0];
        if (!file) return;
        try {
          const blob = JSON.parse(await readFileAsText(file));
          const vault = await decryptVault(blob, pass);
          if (!vault?.keys?.secretKey) throw new Error("archivo inválido");
          session.vault = vault;
          session.password = pass;
          localStorage.setItem(STORAGE_VAULT, JSON.stringify({ ...blob, kind: "kiomind-centro-vault" }));
          writeMeta({ publicKey: vault.keys.publicKey, lastBackupAt: new Date().toISOString(), dirtySince: null });
          toast("Copia restaurada");
          go("home");
        } catch {
          toast("No se pudo abrir la copia. ¿Contraseña incorrecta?");
        }
        return;
      }
      if (pass !== $("#setup-pass2").value) {
        toast("Las contraseñas no coinciden");
        return;
      }
      session.vault = newVault();
      session.password = pass;
      await persist();
      writeMeta({ lastBackupAt: null, dirtySince: new Date().toISOString() });
      toast("Llave creada");
      go("backup");
    };
  }

  function viewUnlock() {
    shell(
      "KioMind Centro",
      "Ingresá tu contraseña",
      `
      <div class="card">
        <form id="unlock-form">
          <div class="field"><label>Contraseña</label><input class="input" type="password" id="unlock-pass" autocomplete="current-password" autofocus required /></div>
          <div class="actions"><button class="btn" type="submit">Entrar</button></div>
        </form>
        <div class="divider"></div>
        <p class="small muted">¿Dispositivo nuevo o perdiste la contraseña? Podés <a href="#" id="unlock-restore">restaurar una copia de seguridad</a> (reemplaza lo que hay acá).</p>
      </div>`,
      { tabs: false }
    );
    $("#unlock-restore").onclick = (e) => {
      e.preventDefault();
      if (confirm("Restaurar una copia reemplaza la llave y la lista de kioscos de este dispositivo. ¿Seguir?")) {
        viewSetup("restore");
      }
    };
    $("#unlock-form").onsubmit = async (e) => {
      e.preventDefault();
      const pass = $("#unlock-pass").value;
      const btn = $("button[type=submit]", e.target);
      btn.disabled = true;
      try {
        session.vault = await decryptVault(readBlob(), pass);
        session.password = pass;
        go("home");
        render();
      } catch {
        toast("Contraseña incorrecta");
        btn.disabled = false;
      }
    };
  }

  function statusBadge(k) {
    if (k.status === "baja") return `<span class="badge off">BAJA</span>`;
    if (k.expiresAt && k.expiresAt < todayKey()) return `<span class="badge warn">VENCIDA</span>`;
    return `<span class="badge ok">ACTIVO</span>`;
  }

  function viewHome() {
    const v = session.vault;
    const q = (viewHome.query || "").toLowerCase();
    const activos = v.kioscos.filter((k) => k.status !== "baja");
    const bajas = v.kioscos.filter((k) => k.status === "baja");
    const list = v.kioscos
      .filter((k) => !q || `${k.name} ${k.machine} ${k.licenseId}`.toLowerCase().includes(q))
      .sort((a, b) => (a.status === "baja") - (b.status === "baja") || a.name.localeCompare(b.name));
    const pending = backupPending();
    shell(
      "KioMind Centro",
      `${activos.length} kiosco${activos.length === 1 ? "" : "s"} activo${activos.length === 1 ? "" : "s"}`,
      `
      ${pending ? `<div class="alert warn">Hay cambios sin copia de seguridad. <a href="#/backup">Hacer copia ahora</a></div>` : ""}
      <div class="card">
        <div class="stats">
          <div class="stat"><div class="n">${activos.length}</div><div class="l">Activos</div></div>
          <div class="stat"><div class="n">${bajas.length}</div><div class="l">Bajas</div></div>
          <div class="stat"><div class="n">${v.kioscos.reduce((a, k) => a + (k.history?.length || 1), 0)}</div><div class="l">Licencias</div></div>
        </div>
      </div>
      <div class="card">
        <h2>Kioscos</h2>
        <input class="input search" id="home-search" placeholder="Buscar por nombre o código" value="${esc(viewHome.query || "")}" />
        ${
          list.length === 0
            ? `<p class="muted small">${v.kioscos.length === 0 ? "Todavía no emitiste ninguna licencia." : "Sin resultados."}</p>`
            : `<div class="list">${list
                .map(
                  (k) => `
              <button class="item" data-id="${esc(k.id)}">
                <div class="t"><b>${esc(k.name)}</b><span class="mono">${esc(k.machine)}</span> · <span>${esc(fmtDate(k.issuedAt))}</span></div>
                ${statusBadge(k)}
              </button>`
                )
                .join("")}</div>`
        }
      </div>`,
      { fab: `<a class="btn" href="#/nueva">＋ Nueva licencia</a>` }
    );
    $("#home-search").oninput = (e) => {
      viewHome.query = e.target.value;
      const pos = e.target.selectionStart;
      viewHome();
      const input = $("#home-search");
      input.focus();
      input.setSelectionRange(pos, pos);
    };
    app.querySelectorAll(".item").forEach((el) => (el.onclick = () => go(`kiosco/${el.dataset.id}`)));
  }

  function viewNueva(prefill = {}) {
    const renew = prefill.renewId ? session.vault.kioscos.find((k) => k.id === prefill.renewId) : null;
    shell(
      renew ? "Renovar equipo" : "Nueva licencia",
      renew ? renew.name : "Para un kiosco nuevo",
      `
      <div class="card">
        <form id="nueva-form">
          <div class="field">
            <label>Código de equipo (lo muestra KioMind)</label>
            <div class="row">
              <input class="input mono" id="n-machine" placeholder="KM-XXXX-XXXX" autocapitalize="characters" autocomplete="off" value="${esc(prefill.machine || "")}" required />
              <button class="btn secondary sm fit" type="button" id="n-scan">📷 QR</button>
            </div>
          </div>
          <div class="field"><label>Nombre del kiosco</label><input class="input" id="n-name" placeholder="Ej: Max Candy Centro" value="${esc(prefill.name || (renew ? renew.name : ""))}" required maxlength="60" /></div>
          <div class="field">
            <label>Vencimiento</label>
            <div class="row">
              <select class="input" id="n-exp-mode">
                <option value="none" ${!renew?.expiresAt ? "selected" : ""}>Sin vencimiento</option>
                <option value="date" ${renew?.expiresAt ? "selected" : ""}>Con fecha</option>
              </select>
              <input class="input" type="date" id="n-exp" value="${esc(renew?.expiresAt || "")}" style="${renew?.expiresAt ? "" : "display:none"}" />
            </div>
          </div>
          <div class="field"><label>Notas (opcional)</label><input class="input" id="n-notes" placeholder="Dirección, teléfono, responsable…" value="${esc(renew?.notes || "")}" maxlength="200" /></div>
          <div class="actions">
            <button class="btn ok" type="submit">Generar licencia</button>
            ${renew ? `<a class="btn ghost" href="#/kiosco/${esc(renew.id)}">Cancelar</a>` : ""}
          </div>
        </form>
      </div>`
    );
    const expMode = $("#n-exp-mode");
    expMode.onchange = () => ($("#n-exp").style.display = expMode.value === "date" ? "" : "none");
    $("#n-scan").onclick = () => openQrScanner((code) => ($("#n-machine").value = code));
    $("#n-machine").oninput = (e) => {
      const n = normalizeMachineCode(e.target.value);
      if (n) e.target.value = n;
    };
    $("#nueva-form").onsubmit = async (e) => {
      e.preventDefault();
      const machine = normalizeMachineCode($("#n-machine").value);
      if (!machine) {
        toast("El código de equipo tiene 8 letras/números: KM-XXXX-XXXX");
        return;
      }
      const name = $("#n-name").value.trim();
      const expiresAt = expMode.value === "date" ? $("#n-exp").value || null : null;
      if (expMode.value === "date" && !expiresAt) {
        toast("Elegí la fecha de vencimiento");
        return;
      }
      const dup = session.vault.kioscos.find((k) => k.machine === machine && k.status !== "baja" && k.id !== renew?.id);
      if (dup && !confirm(`Ya hay una licencia activa para ${machine} (${dup.name}). ¿Generar otra igual?`)) return;

      const lic = buildLicense(machine, name, expiresAt);
      const entry = { at: new Date().toISOString(), event: renew ? "renovación" : "alta", licenseId: lic.payload.i, machine };
      if (renew) {
        renew.history = renew.history || [];
        renew.history.push(entry);
        renew.machine = machine;
        renew.name = name;
        renew.licenseId = lic.payload.i;
        renew.licenseText = lic.text;
        renew.issuedAt = lic.payload.d;
        renew.expiresAt = expiresAt;
        renew.notes = $("#n-notes").value.trim();
        renew.status = "activo";
      } else {
        session.vault.kioscos.push({
          id: `K${randomId(8)}`,
          name,
          machine,
          licenseId: lic.payload.i,
          licenseText: lic.text,
          issuedAt: lic.payload.d,
          expiresAt,
          notes: $("#n-notes").value.trim(),
          status: "activo",
          createdAt: new Date().toISOString(),
          history: [entry],
        });
      }
      writeMeta({ dirtySince: new Date().toISOString() });
      await persist();
      const id = renew ? renew.id : session.vault.kioscos[session.vault.kioscos.length - 1].id;
      go(`kiosco/${id}?nueva=1`);
    };
  }

  function shareButtons(k) {
    const msg = `Licencia KioMind para ${k.name} (equipo ${k.machine}):\n\nlicencia ${k.licenseText}`;
    return `
      <div class="actions inline">
        <button class="btn" id="k-copy">Copiar licencia</button>
        <a class="btn ok" id="k-wa" href="https://wa.me/?text=${encodeURIComponent(msg)}" target="_blank" rel="noopener">WhatsApp</a>
        ${navigator.share ? `<button class="btn secondary" id="k-share">Compartir</button>` : ""}
      </div>`;
  }

  function viewKiosco(idWithQuery) {
    const [id, query] = idWithQuery.split("?");
    const k = session.vault.kioscos.find((x) => x.id === id);
    if (!k) return go("home");
    const justCreated = /nueva=1/.test(query || "");
    shell(
      k.name,
      k.machine,
      `
      ${justCreated ? `<div class="alert ok">Licencia generada. Mandásela al kiosco: la pegan en la pantalla de activación, o si ya tiene WhatsApp vinculado escribile <b>licencia KM1…</b> por WhatsApp y se activa sola.</div>` : ""}
      <div class="card">
        <div class="row" style="justify-content:space-between"><h3 style="margin:0">Estado</h3>${statusBadge(k)}</div>
        <dl class="kv" style="margin-top:10px">
          <dt>Equipo</dt><dd class="mono">${esc(k.machine)}</dd>
          <dt>Licencia</dt><dd class="mono">${esc(k.licenseId)}</dd>
          <dt>Emitida</dt><dd>${esc(fmtDate(k.issuedAt))}</dd>
          <dt>Vence</dt><dd>${k.expiresAt ? esc(fmtDate(k.expiresAt)) : "Sin vencimiento"}</dd>
          ${k.notes ? `<dt>Notas</dt><dd>${esc(k.notes)}</dd>` : ""}
          <dt>Alta</dt><dd>${esc(fmtDateTime(k.createdAt))}</dd>
        </dl>
      </div>
      <div class="card">
        <h2>Licencia</h2>
        <div class="license-box">${esc(k.licenseText)}</div>
        ${shareButtons(k)}
      </div>
      <div class="card">
        <h2>Acciones</h2>
        <div class="actions">
          <a class="btn secondary" href="#/nueva/${esc(k.id)}">🔄 Renovar equipo (PC nueva o cambio de datos)</a>
          ${
            k.status === "baja"
              ? `<button class="btn ok" id="k-reactivar">Reactivar (genera licencia nueva)</button>`
              : `<button class="btn danger" id="k-baja">Dar de baja</button>`
          }
        </div>
        <p class="small muted" style="margin-top:10px">La baja deja de contar el kiosco como activo y agrega la licencia a la lista de revocadas (Ajustes). Para que el kiosco deje de funcionar hay que publicar una versión de KioMind con esa lista.</p>
      </div>
      ${
        k.history && k.history.length > 1
          ? `<div class="card"><h2>Historial</h2><div class="list">${k.history
              .slice()
              .reverse()
              .map((h) => `<div class="item" style="cursor:default"><div class="t"><b>${esc(h.event)}</b><span>${esc(fmtDateTime(h.at))} · ${esc(h.machine)} · ${esc(h.licenseId)}</span></div></div>`)
              .join("")}</div></div>`
          : ""
      }
      <div class="actions"><a class="btn ghost" href="#/home">← Volver</a></div>`
    );
    $("#k-copy").onclick = () => copyText(k.licenseText, "Licencia copiada");
    const share = $("#k-share");
    if (share) {
      share.onclick = () =>
        navigator.share({ title: `Licencia KioMind ${k.name}`, text: `licencia ${k.licenseText}` }).catch(() => {});
    }
    const baja = $("#k-baja");
    if (baja) {
      baja.onclick = async () => {
        if (!confirm(`¿Dar de baja a ${k.name}?`)) return;
        k.status = "baja";
        k.history = k.history || [];
        k.history.push({ at: new Date().toISOString(), event: "baja", licenseId: k.licenseId, machine: k.machine });
        if (!session.vault.revoked.includes(k.licenseId)) session.vault.revoked.push(k.licenseId);
        writeMeta({ dirtySince: new Date().toISOString() });
        await persist();
        render();
      };
    }
    const re = $("#k-reactivar");
    if (re) re.onclick = () => go(`nueva/${k.id}`);
  }

  function viewBackup() {
    const meta = readMeta();
    const pending = backupPending();
    shell(
      "Copia de seguridad",
      pending ? "Pendiente" : "Al día",
      `
      ${
        pending
          ? `<div class="alert warn">Si perdés este dispositivo sin copia, no vas a poder emitir más licencias con esta llave.</div>`
          : `<div class="alert ok">Última copia: ${esc(fmtDateTime(meta.lastBackupAt))}</div>`
      }
      <div class="card">
        <h3>Guardar copia</h3>
        <p class="small muted">Genera un archivo <b>.kmc</b> cifrado con tu contraseña, con la llave y la lista de kioscos. Guardalo en Google Drive, mandátelo por mail o pasalo a la PC. Sin la contraseña el archivo no sirve.</p>
        <div class="actions"><button class="btn" id="b-download">💾 Guardar copia ahora</button></div>
      </div>
      <div class="card">
        <h3>Restaurar en este dispositivo</h3>
        <p class="small muted">Reemplaza la llave y los kioscos actuales por los de la copia. Usalo en un celular nuevo.</p>
        <div class="field"><input class="input" type="file" id="b-file" accept=".kmc,application/json" /></div>
        <div class="actions"><button class="btn secondary" id="b-restore">Restaurar desde archivo</button></div>
      </div>`
    );
    $("#b-download").onclick = async () => {
      await downloadBackup();
      render();
    };
    $("#b-restore").onclick = async () => {
      const file = $("#b-file").files[0];
      if (!file) return toast("Elegí el archivo .kmc");
      const pass = prompt("Contraseña de esa copia:");
      if (pass == null) return;
      try {
        const blob = JSON.parse(await readFileAsText(file));
        const vault = await decryptVault(blob, pass);
        if (!vault?.keys?.secretKey) throw new Error();
        if (session.vault && vault.keys.publicKey !== session.vault.keys.publicKey) {
          if (!confirm("La copia tiene OTRA llave. Las licencias emitidas con la llave actual dejarían de poder renovarse desde acá. ¿Reemplazar igual?")) return;
        }
        session.vault = vault;
        session.password = pass;
        await persist();
        writeMeta({ lastBackupAt: new Date().toISOString(), dirtySince: null });
        toast("Copia restaurada");
        go("home");
      } catch {
        toast("No se pudo abrir la copia. ¿Contraseña incorrecta?");
      }
    };
  }

  function viewConfig() {
    const v = session.vault;
    shell(
      "Ajustes",
      "Llave, contraseña y revocadas",
      `
      <div class="card">
        <h3>Clave pública</h3>
        <p class="small muted">Esta clave va dentro de KioMind para que reconozca tus licencias. Se carga <b>una sola vez</b> en la PC de programación con: <span class="mono">npm run centro:clave -- &lt;clave&gt;</span>. No es secreta.</p>
        <div class="license-box">${esc(v.keys.publicKey)}</div>
        <div class="actions inline"><button class="btn secondary" id="c-copy-pub">Copiar clave pública</button></div>
        <p class="small muted" style="margin-top:8px">Llave creada: ${esc(fmtDateTime(v.createdAt))}</p>
      </div>
      <div class="card">
        <h3>Licencias revocadas</h3>
        <p class="small muted">Ids de los kioscos dados de baja. Para que dejen de funcionar, pegá esta lista en <span class="mono">src/lib/license/revoked-licenses.json</span> de KioMind y publicá una versión.</p>
        <div class="license-box">${esc(JSON.stringify(v.revoked))}</div>
        <div class="actions inline"><button class="btn secondary" id="c-copy-rev" ${v.revoked.length ? "" : "disabled"}>Copiar lista</button></div>
      </div>
      <div class="card">
        <h3>Cambiar contraseña</h3>
        <form id="c-pass-form">
          <div class="field"><label>Contraseña actual</label><input class="input" type="password" id="c-old" required /></div>
          <div class="field"><label>Nueva</label><input class="input" type="password" id="c-new" required minlength="6" /></div>
          <div class="field"><label>Repetir nueva</label><input class="input" type="password" id="c-new2" required minlength="6" /></div>
          <div class="actions"><button class="btn secondary" type="submit">Cambiar</button></div>
        </form>
        <p class="small muted">Las copias de seguridad viejas siguen abriéndose con la contraseña vieja.</p>
      </div>
      <div class="card">
        <h3>Sesión</h3>
        <div class="actions">
          <button class="btn secondary" id="c-lock">🔒 Bloquear (pedir contraseña)</button>
          <button class="btn danger" id="c-wipe">Borrar todo de este dispositivo</button>
        </div>
      </div>
      <p class="small muted center">KioMind Centro · v1</p>`
    );
    $("#c-copy-pub").onclick = () => copyText(v.keys.publicKey, "Clave pública copiada");
    $("#c-copy-rev").onclick = () => copyText(JSON.stringify(v.revoked), "Lista copiada");
    $("#c-lock").onclick = () => {
      session.vault = null;
      session.password = null;
      render();
    };
    $("#c-wipe").onclick = () => {
      if (prompt('Esto borra la llave y los kioscos de este dispositivo. Escribí BORRAR para confirmar:') !== "BORRAR") return;
      localStorage.removeItem(STORAGE_VAULT);
      localStorage.removeItem(STORAGE_META);
      session.vault = null;
      session.password = null;
      render();
    };
    $("#c-pass-form").onsubmit = async (e) => {
      e.preventDefault();
      if ($("#c-old").value !== session.password) return toast("La contraseña actual no es correcta");
      if ($("#c-new").value !== $("#c-new2").value) return toast("Las nuevas no coinciden");
      session.password = $("#c-new").value;
      await persist();
      writeMeta({ dirtySince: new Date().toISOString() });
      toast("Contraseña cambiada. Hacé una copia nueva.");
      go("backup");
    };
  }

  function render() {
    const blob = readBlob();
    if (!blob) return viewSetup("create");
    if (!session.vault) return viewUnlock();
    const r = route();
    const [name, ...rest] = r.split("/");
    const arg = rest.join("/");
    switch (name) {
      case "nueva":
        return viewNueva(arg ? { renewId: arg } : {});
      case "kiosco":
        return viewKiosco(arg);
      case "backup":
        return viewBackup();
      case "config":
        return viewConfig();
      default:
        return viewHome();
    }
  }

  /* ------------------------------------------------------------- init */
  if ("serviceWorker" in navigator && location.protocol !== "file:") {
    navigator.serviceWorker.register("./sw.js").catch(() => {});
  }
  if (typeof nacl === "undefined" || !crypto.subtle) {
    app.innerHTML = `<div class="card alert danger">Este navegador no soporta las funciones de seguridad necesarias. Abrí KioMind Centro en Chrome, Edge o Safari actualizados.</div>`;
  } else {
    render();
  }
})();
