(() => {
"use strict";

const $ = (id) => document.getElementById(id);

function rotl(x, n) {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

function sha1(bytes) {
  const msg = Array.from(bytes);
  const bitLenHi = Math.floor((msg.length * 8) / 0x100000000);
  const bitLenLo = (msg.length * 8) >>> 0;

  msg.push(0x80);
  while ((msg.length % 64) !== 56) msg.push(0);

  msg.push(
    (bitLenHi >>> 24) & 255, (bitLenHi >>> 16) & 255,
    (bitLenHi >>> 8) & 255, bitLenHi & 255,
    (bitLenLo >>> 24) & 255, (bitLenLo >>> 16) & 255,
    (bitLenLo >>> 8) & 255, bitLenLo & 255
  );

  let h0 = 0x67452301 >>> 0;
  let h1 = 0xEFCDAB89 >>> 0;
  let h2 = 0x98BADCFE >>> 0;
  let h3 = 0x10325476 >>> 0;
  let h4 = 0xC3D2E1F0 >>> 0;

  const w = new Uint32Array(80);

  for (let off = 0; off < msg.length; off += 64) {
    for (let i = 0; i < 16; i++) {
      const j = off + i * 4;
      w[i] = (((msg[j] << 24) | (msg[j+1] << 16) | (msg[j+2] << 8) | msg[j+3]) >>> 0);
    }
    for (let i = 16; i < 80; i++) {
      w[i] = rotl((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]) >>> 0, 1);
    }

    let a = h0, b = h1, c = h2, d = h3, e = h4;

    for (let i = 0; i < 80; i++) {
      let f, k;
      if (i < 20) {
        f = ((b & c) | ((~b) & d)) >>> 0;
        k = 0x5A827999;
      } else if (i < 40) {
        f = (b ^ c ^ d) >>> 0;
        k = 0x6ED9EBA1;
      } else if (i < 60) {
        f = ((b & c) | (b & d) | (c & d)) >>> 0;
        k = 0x8F1BBCDC;
      } else {
        f = (b ^ c ^ d) >>> 0;
        k = 0xCA62C1D6;
      }
      const temp = (rotl(a,5) + f + e + k + w[i]) >>> 0;
      e = d; d = c; c = rotl(b,30); b = a; a = temp;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
  }

  const out = new Uint8Array(20);
  [h0,h1,h2,h3,h4].forEach((v, i) => {
    out[i*4] = (v >>> 24) & 255;
    out[i*4+1] = (v >>> 16) & 255;
    out[i*4+2] = (v >>> 8) & 255;
    out[i*4+3] = v & 255;
  });
  return out;
}

function hmacSha1(key, data) {
  let k = Uint8Array.from(key);
  if (k.length > 64) k = sha1(k);
  const block = new Uint8Array(64);
  block.set(k);

  const ipad = new Uint8Array(64);
  const opad = new Uint8Array(64);
  for (let i=0; i<64; i++) {
    ipad[i] = block[i] ^ 0x36;
    opad[i] = block[i] ^ 0x5c;
  }

  const inner = new Uint8Array(ipad.length + data.length);
  inner.set(ipad, 0); inner.set(data, ipad.length);
  const innerHash = sha1(inner);

  const outer = new Uint8Array(opad.length + innerHash.length);
  outer.set(opad, 0); outer.set(innerHash, opad.length);
  return sha1(outer);
}

function utf8(s) {
  return new TextEncoder().encode(s);
}

function decodeHex(s) {
  const clean = s.replace(/\s+/g, "").toLowerCase();
  if (!/^[0-9a-f]+$/.test(clean) || clean.length % 2 !== 0) {
    throw new Error("Secret HEX non valido.");
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i=0; i<out.length; i++) out[i] = parseInt(clean.slice(i*2, i*2+2), 16);
  return out;
}

function decodeBase32(s) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = s.toUpperCase().replace(/[\s=-]/g, "");
  if (!clean || /[^A-Z2-7]/.test(clean)) throw new Error("Secret Base32 non valido.");
  let bits = 0, value = 0;
  const out = [];
  for (const ch of clean) {
    value = (value << 5) | alphabet.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Uint8Array.from(out);
}

function ocraSha1QN08(secretBytes, challenge, suite, digits) {
  if (!/^OCRA-1:HOTP-SHA1-[678]:QN08$/.test(suite)) {
    throw new Error("OCRA Suite non supportata.");
  }
  if (!/^\d{1,8}$/.test(challenge)) {
    throw new Error("La challenge deve contenere da 1 a 8 cifre numeriche.");
  }

  const suiteDigits = Number(suite.match(/SHA1-(\d):/)[1]);
  if (suiteDigits !== Number(digits)) {
    throw new Error("Il numero di cifre non coincide con la OCRA Suite.");
  }

  const suiteBytes = utf8(suite);
  let qHex = BigInt(challenge).toString(16);
  qHex = (qHex + "0".repeat(256)).slice(0, 256);
  const qBytes = decodeHex(qHex);

  const data = new Uint8Array(suiteBytes.length + 1 + 128);
  data.set(suiteBytes, 0);
  data[suiteBytes.length] = 0x00;
  data.set(qBytes, suiteBytes.length + 1);

  const mac = hmacSha1(secretBytes, data);
  const offset = mac[mac.length - 1] & 0x0f;
  const bin =
    ((mac[offset] & 0x7f) << 24) |
    ((mac[offset+1] & 0xff) << 16) |
    ((mac[offset+2] & 0xff) << 8) |
    (mac[offset+3] & 0xff);

  const modulo = 10 ** Number(digits);
  return String((bin >>> 0) % modulo).padStart(Number(digits), "0");
}

const $ = (id) => document.getElementById(id);
const PROFILE_KEY = "ocra_profiles_v3";
let activeProfile = null;

function setStatus(id, msg, kind="") {
  const el = $(id);
  el.textContent = msg;
  el.className = "small " + kind;
}

function getProfiles() {
  try {
    const parsed = JSON.parse(localStorage.getItem(PROFILE_KEY) || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function setProfiles(profiles) {
  localStorage.setItem(PROFILE_KEY, JSON.stringify(profiles));
}

function validateSecret(format, secret) {
  return format === "hex" ? decodeHex(secret) : decodeBase32(secret);
}

function syncDigitsFromSuite() {
  const m = $("suite").value.match(/SHA1-(\d):/);
  if (m) $("digits").value = m[1];
}

function syncSuiteFromDigits() {
  $("suite").value = `OCRA-1:HOTP-SHA1-${$("digits").value}:QN08`;
}

function clearConfigForm() {
  $("name").value = "";
  $("secret").value = "";
  $("format").value = "base32";
  $("digits").value = "6";
  $("suite").value = "OCRA-1:HOTP-SHA1-6:QN08";
  setStatus("saveStatus", "Campi pronti per un nuovo token.");
  $("name").focus();
}

function renderProfiles(selectedId="") {
  const select = $("profile");
  const profiles = getProfiles();
  select.innerHTML = '<option value="">— Seleziona un token —</option>';
  for (const p of profiles) {
    const opt = document.createElement("option");
    opt.value = p.id;
    opt.textContent = p.name;
    select.appendChild(opt);
  }
  if (selectedId && profiles.some(p => p.id === selectedId)) {
    select.value = selectedId;
  }
}

function saveProfile() {
  const name = $("name").value.trim();
  const secret = $("secret").value.trim();
  const format = $("format").value;
  const digits = Number($("digits").value);
  const suite = $("suite").value;

  if (!name) {
    setStatus("saveStatus", "Inserisci il nome del token.", "err");
    return;
  }
  if (!secret) {
    setStatus("saveStatus", "Inserisci il secret.", "err");
    return;
  }
  try {
    validateSecret(format, secret);
  } catch (e) {
    setStatus("saveStatus", e.message || String(e), "err");
    return;
  }

  const suiteDigits = Number((suite.match(/SHA1-(\d):/) || [,"0"])[1]);
  if (suiteDigits !== digits) {
    setStatus("saveStatus", "Cifre e OCRA Suite non coincidono.", "err");
    return;
  }

  const profiles = getProfiles();
  const existing = profiles.find(p => p.name.toLowerCase() === name.toLowerCase());
  let id;

  if (existing) {
    id = existing.id;
    Object.assign(existing, { name, secret, format, digits, suite });
  } else {
    id = "p_" + Date.now().toString(36) + "_" + Math.random().toString(36).slice(2,8);
    profiles.push({ id, name, secret, format, digits, suite });
  }

  setProfiles(profiles);
  renderProfiles(id);
  selectProfile(id);
  setStatus("saveStatus", existing ? "Token aggiornato." : "Token salvato.", "ok");
}

function selectProfile(id) {
  const profiles = getProfiles();
  const p = profiles.find(x => x.id === id) || null;
  activeProfile = p;

  if (!p) {
    $("profile").value = "";
    $("activeToken").textContent = "nessuno";
    $("selectedInfo").textContent = "Nessun token selezionato.";
    $("otp").textContent = "------";
    setStatus("selectStatus", "");
    return;
  }

  $("profile").value = p.id;
  $("activeToken").textContent = p.name;
  $("selectedInfo").innerHTML =
    `<b>${escapeHtml(p.name)}</b><br>` +
    `Formato: ${escapeHtml(p.format.toUpperCase())}<br>` +
    `Cifre: ${escapeHtml(String(p.digits))}<br>` +
    `Suite: <span class="mono">${escapeHtml(p.suite)}</span>`;

  // Carica anche i dati nel riquadro configurazione per eventuale modifica.
  $("name").value = p.name;
  $("secret").value = p.secret;
  $("format").value = p.format;
  $("digits").value = String(p.digits);
  $("suite").value = p.suite;

  $("otp").textContent = "------";
  setStatus("selectStatus", "Token selezionato.", "ok");
  setStatus("status", "");
}

function deleteProfile() {
  if (!activeProfile) {
    setStatus("selectStatus", "Seleziona prima un token.", "err");
    return;
  }
  const name = activeProfile.name;
  const profiles = getProfiles().filter(p => p.id !== activeProfile.id);
  setProfiles(profiles);
  activeProfile = null;
  renderProfiles();
  $("activeToken").textContent = "nessuno";
  $("selectedInfo").textContent = "Nessun token selezionato.";
  $("otp").textContent = "------";
  clearConfigForm();
  setStatus("selectStatus", `Token eliminato: ${name}.`, "ok");
}

function generate() {
  if (!activeProfile) {
    $("otp").textContent = "------";
    setStatus("status", "Seleziona prima un token salvato.", "err");
    return;
  }

  try {
    const key = validateSecret(activeProfile.format, activeProfile.secret);
    const otp = ocraSha1QN08(
      key,
      $("challenge").value.trim(),
      activeProfile.suite,
      activeProfile.digits
    );
    $("otp").textContent = otp;
    setStatus("status", `Codice generato usando ${activeProfile.name}.`, "ok");
  } catch (e) {
    $("otp").textContent = "------";
    setStatus("status", e.message || String(e), "err");
  }
}

function runTest() {
  try {
    const key = decodeHex("3132333435363738393031323334353637383930");
    const otp = ocraSha1QN08(
      key,
      "00000000",
      "OCRA-1:HOTP-SHA1-6:QN08",
      6
    );
    $("otp").textContent = otp;
    if (otp === "237653") {
      setStatus("status", "TEST OK — risultato RFC 6287 corretto: 237653.", "ok");
    } else {
      setStatus("status", `TEST FALLITO — ottenuto ${otp}, atteso 237653.`, "err");
    }
  } catch (e) {
    setStatus("status", "Errore test: " + e.message, "err");
  }
}

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

$("saveProfile").addEventListener("click", saveProfile);
$("clearForm").addEventListener("click", clearConfigForm);
$("deleteProfile").addEventListener("click", deleteProfile);
$("generate").addEventListener("click", generate);
$("test").addEventListener("click", runTest);

$("profile").addEventListener("change", () => selectProfile($("profile").value));
$("digits").addEventListener("change", syncSuiteFromDigits);
$("suite").addEventListener("change", syncDigitsFromSuite);

$("showSecret").addEventListener("change", () => {
  $("secret").type = $("showSecret").checked ? "text" : "password";
});

$("challenge").addEventListener("keydown", (e) => {
  if (e.key === "Enter") generate();
});

renderProfiles();

if ("serviceWorker" in navigator && location.protocol.startsWith("http")) {
  navigator.serviceWorker.register("sw.js").catch(() => {});
}
})();