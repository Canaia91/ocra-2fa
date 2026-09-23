(() => {
"use strict";

const PROFILE_KEY = "ocra_profiles_v4";
const LEGACY_KEYS = ["ocra_profiles_v3", "ocra_profiles_v2"];

function byId(id) {
  return document.getElementById(id);
}

function setMessage(id, text, type) {
  const el = byId(id);
  el.textContent = text || "";
  el.className = "small" + (type ? " " + type : "");
}

function rotl(x, n) {
  return (((x << n) | (x >>> (32 - n))) >>> 0);
}

function sha1(inputBytes) {
  const msg = Array.from(inputBytes);
  const totalBits = msg.length * 8;
  const bitLenHi = Math.floor(totalBits / 0x100000000);
  const bitLenLo = totalBits >>> 0;

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

  for (let offset = 0; offset < msg.length; offset += 64) {
    for (let i = 0; i < 16; i++) {
      const j = offset + i * 4;
      w[i] = (((msg[j] << 24) | (msg[j + 1] << 16) | (msg[j + 2] << 8) | msg[j + 3]) >>> 0);
    }
    for (let i = 16; i < 80; i++) {
      w[i] = rotl((w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]) >>> 0, 1);
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

      const temp = (rotl(a, 5) + f + e + k + w[i]) >>> 0;
      e = d;
      d = c;
      c = rotl(b, 30);
      b = a;
      a = temp;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
  }

  const out = new Uint8Array(20);
  [h0, h1, h2, h3, h4].forEach((v, i) => {
    out[i * 4] = (v >>> 24) & 255;
    out[i * 4 + 1] = (v >>> 16) & 255;
    out[i * 4 + 2] = (v >>> 8) & 255;
    out[i * 4 + 3] = v & 255;
  });
  return out;
}

function hmacSha1(keyBytes, dataBytes) {
  let key = Uint8Array.from(keyBytes);
  if (key.length > 64) key = sha1(key);

  const block = new Uint8Array(64);
  block.set(key);

  const ipad = new Uint8Array(64);
  const opad = new Uint8Array(64);

  for (let i = 0; i < 64; i++) {
    ipad[i] = block[i] ^ 0x36;
    opad[i] = block[i] ^ 0x5c;
  }

  const inner = new Uint8Array(64 + dataBytes.length);
  inner.set(ipad, 0);
  inner.set(dataBytes, 64);

  const innerHash = sha1(inner);
  const outer = new Uint8Array(64 + innerHash.length);
  outer.set(opad, 0);
  outer.set(innerHash, 64);

  return sha1(outer);
}

function utf8(text) {
  return new TextEncoder().encode(text);
}

function decodeHex(text) {
  const clean = text.replace(/\s+/g, "").toLowerCase();
  if (!clean || !/^[0-9a-f]+$/.test(clean) || clean.length % 2 !== 0) {
    throw new Error("Secret HEX non valido.");
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function decodeBase32(text) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = text.toUpperCase().replace(/[\s=-]/g, "");
  if (!clean || /[^A-Z2-7]/.test(clean)) {
    throw new Error("Secret Base32 non valido.");
  }

  let bits = 0;
  let value = 0;
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

function decodeSecret(format, secret) {
  return format === "hex" ? decodeHex(secret) : decodeBase32(secret);
}

function generateOcra(secretBytes, challenge, suite, digits) {
  if (!/^OCRA-1:HOTP-SHA1-[678]:QN08$/.test(suite)) {
    throw new Error("OCRA Suite non supportata.");
  }
  if (!/^\d{1,8}$/.test(challenge)) {
    throw new Error("La challenge deve contenere da 1 a 8 cifre.");
  }

  const suiteMatch = suite.match(/SHA1-(\d):/);
  const suiteDigits = Number(suiteMatch[1]);
  if (suiteDigits !== Number(digits)) {
    throw new Error("Cifre e OCRA Suite non coincidono.");
  }

  const suiteBytes = utf8(suite);

  // RFC 6287 reference behavior for QN: decimal challenge -> hex string,
  // then right-pad the 128-byte Q field with zeroes.
  let qHex = BigInt(challenge).toString(16);
  qHex = (qHex + "0".repeat(256)).slice(0, 256);
  const qBytes = decodeHex(qHex);

  const data = new Uint8Array(suiteBytes.length + 1 + 128);
  data.set(suiteBytes, 0);
  data[suiteBytes.length] = 0x00;
  data.set(qBytes, suiteBytes.length + 1);

  const mac = hmacSha1(secretBytes, data);
  const offset = mac[mac.length - 1] & 0x0f;
  const binary =
      ((mac[offset] & 0x7f) << 24)
    | ((mac[offset + 1] & 0xff) << 16)
    | ((mac[offset + 2] & 0xff) << 8)
    |  (mac[offset + 3] & 0xff);

  const modulo = 10 ** Number(digits);
  return String((binary >>> 0) % modulo).padStart(Number(digits), "0");
}

function getProfiles() {
  try {
    const data = JSON.parse(localStorage.getItem(PROFILE_KEY) || "[]");
    return Array.isArray(data) ? data : [];
  } catch {
    return [];
  }
}

function saveProfiles(profiles) {
  localStorage.setItem(PROFILE_KEY, JSON.stringify(profiles));
}

function migrateLegacyProfiles() {
  if (getProfiles().length > 0) return;

  for (const key of LEGACY_KEYS) {
    try {
      const legacy = JSON.parse(localStorage.getItem(key) || "[]");
      if (Array.isArray(legacy) && legacy.length > 0) {
        const cleaned = legacy.map((p, idx) => {
          const digits = Number(p.digits || ((p.suite || "").match(/SHA1-(\d):/) || [,"6"])[1]);
          return {
            id: p.id || ("legacy_" + idx + "_" + Date.now()),
            name: p.name || ("Token " + (idx + 1)),
            secret: p.secret || "",
            format: p.format === "hex" ? "hex" : "base32",
            digits: [6,7,8].includes(digits) ? digits : 6,
            suite: p.suite || ("OCRA-1:HOTP-SHA1-" + (digits || 6) + ":QN08")
          };
        }).filter(p => p.secret);
        if (cleaned.length) {
          saveProfiles(cleaned);
          break;
        }
      }
    } catch {}
  }
}

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

let activeProfileId = "";

function renderTokenSelect(selectId) {
  const select = byId("tokenSelect");
  const profiles = getProfiles();

  select.innerHTML = '<option value="">— Seleziona un token —</option>';
  for (const profile of profiles) {
    const option = document.createElement("option");
    option.value = profile.id;
    option.textContent = profile.name;
    select.appendChild(option);
  }

  if (selectId && profiles.some(p => p.id === selectId)) {
    select.value = selectId;
  } else {
    select.value = "";
  }
}

function clearTokenForm() {
  byId("tokenName").value = "";
  byId("secret").value = "";
  byId("secretFormat").value = "base32";
  byId("digits").value = "6";
  byId("suite").value = "OCRA-1:HOTP-SHA1-6:QN08";
  setMessage("saveStatus", "Campi pronti per un nuovo token.", "");
}

function showSelectedToken(profile) {
  if (!profile) {
    activeProfileId = "";
    byId("activeTokenName").textContent = "nessuno";
    byId("tokenInfo").textContent = "Nessun token selezionato.";
    byId("otp").textContent = "------";
    return;
  }

  activeProfileId = profile.id;
  byId("activeTokenName").textContent = profile.name;
  byId("tokenInfo").innerHTML =
      "<b>" + escapeHtml(profile.name) + "</b><br>"
    + "Formato: " + escapeHtml(profile.format.toUpperCase()) + "<br>"
    + "Cifre: " + escapeHtml(String(profile.digits)) + "<br>"
    + 'Suite: <span class="mono">' + escapeHtml(profile.suite) + "</span>";

  // Also load into edit form.
  byId("tokenName").value = profile.name;
  byId("secret").value = profile.secret;
  byId("secretFormat").value = profile.format;
  byId("digits").value = String(profile.digits);
  byId("suite").value = profile.suite;
}

function selectTokenById(id) {
  const profile = getProfiles().find(p => p.id === id) || null;
  showSelectedToken(profile);
  if (profile) {
    setMessage("selectStatus", "Token selezionato.", "ok");
  } else {
    setMessage("selectStatus", "", "");
  }
}

function saveToken() {
  const name = byId("tokenName").value.trim();
  const secret = byId("secret").value.trim();
  const format = byId("secretFormat").value;
  const digits = Number(byId("digits").value);
  const suite = byId("suite").value;

  if (!name) {
    setMessage("saveStatus", "Inserisci il nome del token.", "err");
    return;
  }
  if (!secret) {
    setMessage("saveStatus", "Inserisci il secret.", "err");
    return;
  }

  try {
    decodeSecret(format, secret);
  } catch (error) {
    setMessage("saveStatus", error.message, "err");
    return;
  }

  const suiteDigits = Number((suite.match(/SHA1-(\d):/) || [,"0"])[1]);
  if (suiteDigits !== digits) {
    setMessage("saveStatus", "Cifre e OCRA Suite non coincidono.", "err");
    return;
  }

  const profiles = getProfiles();
  let profile = null;

  // If an existing token is selected, update that one.
  if (activeProfileId) {
    profile = profiles.find(p => p.id === activeProfileId) || null;
  }

  // Otherwise update same-name token or create a new one.
  if (!profile) {
    profile = profiles.find(p => p.name.toLowerCase() === name.toLowerCase()) || null;
  }

  let savedId;
  let updated = false;

  if (profile) {
    profile.name = name;
    profile.secret = secret;
    profile.format = format;
    profile.digits = digits;
    profile.suite = suite;
    savedId = profile.id;
    updated = true;
  } else {
    savedId = "tok_" + Date.now().toString(36) + "_" + Math.random().toString(36).slice(2, 8);
    profiles.push({ id: savedId, name, secret, format, digits, suite });
  }

  saveProfiles(profiles);
  renderTokenSelect(savedId);
  selectTokenById(savedId);

  setMessage(
    "saveStatus",
    updated ? "Token aggiornato e selezionato." : "Token salvato e selezionato.",
    "ok"
  );
}

function deleteSelectedToken() {
  if (!activeProfileId) {
    setMessage("selectStatus", "Seleziona prima un token.", "err");
    return;
  }

  const profiles = getProfiles();
  const selected = profiles.find(p => p.id === activeProfileId);
  const remaining = profiles.filter(p => p.id !== activeProfileId);

  saveProfiles(remaining);
  activeProfileId = "";
  renderTokenSelect("");
  showSelectedToken(null);
  clearTokenForm();

  setMessage(
    "selectStatus",
    "Token eliminato" + (selected ? ": " + selected.name : "") + ".",
    "ok"
  );
}

function generateCurrentOcra() {
  if (!activeProfileId) {
    byId("otp").textContent = "------";
    setMessage("generatorStatus", "Seleziona prima un token salvato.", "err");
    return;
  }

  const profile = getProfiles().find(p => p.id === activeProfileId);
  if (!profile) {
    byId("otp").textContent = "------";
    setMessage("generatorStatus", "Il token selezionato non esiste più.", "err");
    return;
  }

  try {
    const key = decodeSecret(profile.format, profile.secret);
    const otp = generateOcra(
      key,
      byId("challenge").value.trim(),
      profile.suite,
      profile.digits
    );
    byId("otp").textContent = otp;
    setMessage("generatorStatus", "Codice generato usando " + profile.name + ".", "ok");
  } catch (error) {
    byId("otp").textContent = "------";
    setMessage("generatorStatus", error.message, "err");
  }
}

function runRfcTest() {
  try {
    const key = decodeHex("3132333435363738393031323334353637383930");
    const result = generateOcra(
      key,
      "00000000",
      "OCRA-1:HOTP-SHA1-6:QN08",
      6
    );

    byId("otp").textContent = result;

    if (result === "237653") {
      setMessage("generatorStatus", "TEST OK — risultato RFC corretto: 237653.", "ok");
    } else {
      setMessage("generatorStatus", "TEST FALLITO — ottenuto " + result + ", atteso 237653.", "err");
    }
  } catch (error) {
    setMessage("generatorStatus", "Errore test: " + error.message, "err");
  }
}

function setup() {
  migrateLegacyProfiles();
  renderTokenSelect("");

  byId("showSecret").addEventListener("change", function () {
    byId("secret").type = this.checked ? "text" : "password";
  });

  byId("digits").addEventListener("change", function () {
    byId("suite").value = "OCRA-1:HOTP-SHA1-" + this.value + ":QN08";
  });

  byId("suite").addEventListener("change", function () {
    const match = this.value.match(/SHA1-(\d):/);
    if (match) byId("digits").value = match[1];
  });

  byId("saveToken").addEventListener("click", saveToken);

  byId("newToken").addEventListener("click", function () {
    activeProfileId = "";
    byId("tokenSelect").value = "";
    showSelectedToken(null);
    clearTokenForm();
  });

  byId("tokenSelect").addEventListener("change", function () {
    selectTokenById(this.value);
  });

  byId("deleteToken").addEventListener("click", deleteSelectedToken);
  byId("generate").addEventListener("click", generateCurrentOcra);
  byId("testRfc").addEventListener("click", runRfcTest);

  byId("challenge").addEventListener("keydown", function (event) {
    if (event.key === "Enter") generateCurrentOcra();
  });

  setMessage("saveStatus", "Pronto.", "");
}

setup();

if ("serviceWorker" in navigator && location.protocol.startsWith("http")) {
  navigator.serviceWorker.register("sw.js?v=4").then(registration => {
    registration.update().catch(() => {});
  }).catch(() => {});
}
})();