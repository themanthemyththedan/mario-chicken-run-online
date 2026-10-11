// Password gate for the published copy (tools/publish_web.mjs has the file layouts).
//
// The site serves the game's code in the clear and every ripped file (sprites, tiles,
// music, sounds) only inside pack.bin, encrypted. lock.bin holds a private key encrypted
// under PBKDF2-SHA256(password); that key opens pack.bin (ECDH + HKDF -> AES-256-GCM).
// A wrong password fails GCM's tag check. The private key (not the password) is
// remembered per browser, tied to lock.bin's salt, so a new password shuts out every
// browser that remembered the old one.
//
// After unlocking, fetch() and <img>.src answer the asset paths from memory, then the
// game's bundle is imported: its loaders do not know the difference.

const ENTRY = document.querySelector("script[data-entry]").dataset.entry;
const KEY_ITEM = "mcr-web-key";
const $ = (id) => document.getElementById(id);
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const unhex = (s) => new Uint8Array(s.match(/../g).map((x) => parseInt(x, 16)));
const ascii = (b) => String.fromCharCode(...b);
const subtle = crypto.subtle;

function msg(text, bad) {
  $("gate-msg").textContent = text;
  $("gate-msg").className = bad ? "msg bad" : "msg";
}

async function get(name, progress) {
  const r = await fetch(name, { cache: "no-cache" });
  if (!r.ok) throw new Error(name + " is missing from the site (" + r.status + ")");
  const total = Number(r.headers.get("content-length")) || 0;
  if (!progress || !total || !r.body) return new Uint8Array(await r.arrayBuffer());
  const out = new Uint8Array(total);
  const reader = r.body.getReader();
  let n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (n + value.length > out.length) return new Uint8Array(await new Blob([out.subarray(0, n), value]).arrayBuffer());
    out.set(value, n);
    n += value.length;
    progress(n / total);
  }
  return out.subarray(0, n);
}

// lock.bin: "MCRLOCK1" | u32 iterations | salt 16 | site public key 65 | iv 12 | AES-GCM(pkcs8)
function parseLock(b) {
  if (ascii(b.subarray(0, 8)) !== "MCRLOCK1") throw new Error("lock.bin is not a lock file");
  const iters = new DataView(b.buffer, b.byteOffset).getUint32(8, true);
  return { iters, salt: b.slice(12, 28), iv: b.slice(93, 105), body: b.slice(105) };
}

async function privateKeyFromPassword(lock, password) {
  const base = await subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  const kek = await subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt: lock.salt, iterations: lock.iters },
    base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  try { return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: lock.iv }, kek, lock.body)); }
  catch { throw new Error("wrong"); }
}

// pack.bin: "MCRPACK1" | ephemeral public key 65 | iv 12 | AES-GCM(gzip(payload))
// payload: u32 header length | JSON {files: [[path, type, offset, length]...]} | file bytes
async function openPack(pack, pkcs8) {
  if (ascii(pack.subarray(0, 8)) !== "MCRPACK1") throw new Error("pack.bin is not a pack");
  const eph = pack.slice(8, 73), iv = pack.slice(73, 85);
  const priv = await subtle.importKey("pkcs8", pkcs8, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const pub = await subtle.importKey("raw", eph, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = await subtle.deriveBits({ name: "ECDH", public: pub }, priv, 256);
  const hk = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const key = await subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: eph, info: new TextEncoder().encode("mcr-pack-v1") },
    hk, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  let zipped;
  try { zipped = await subtle.decrypt({ name: "AES-GCM", iv }, key, pack.subarray(85)); }
  catch { throw new Error("wrong"); }
  const raw = new Uint8Array(await new Response(new Blob([zipped]).stream()
    .pipeThrough(new DecompressionStream("gzip"))).arrayBuffer());
  const len = new DataView(raw.buffer).getUint32(0, true);
  const head = JSON.parse(new TextDecoder().decode(raw.subarray(4, 4 + len)));
  const data = raw.subarray(4 + len);
  const files = new Map();
  for (const [path, type, off, size] of head.files) files.set(path, { type, bytes: data.subarray(off, off + size), url: "" });
  return files;
}

function remembered(lock) {
  try {
    const k = JSON.parse(localStorage.getItem(KEY_ITEM) || "null");
    if (k && k.salt === hex(lock.salt)) return unhex(k.key);
    if (k) forget(); // the password was changed since
    return null;
  } catch { return null; }
}
function remember(lock, pkcs8) {
  try { localStorage.setItem(KEY_ITEM, JSON.stringify({ salt: hex(lock.salt), key: hex(pkcs8) })); } catch { /* blocked */ }
}
function forget() { try { localStorage.removeItem(KEY_ITEM); } catch { /* blocked */ } }

/** Asset paths ("./sprites/x.png", "/sprites/x.png", absolute URLs) -> the pack's file, served from memory. */
function serve(files) {
  const base = new URL("./", document.baseURI).pathname;
  const find = (u) => {
    try {
      const x = new URL(typeof u === "string" ? u : u instanceof Request ? u.url : String(u), document.baseURI);
      if (x.origin !== location.origin || !x.protocol.startsWith("http")) return null;
      let p = decodeURIComponent(x.pathname);
      // Root-absolute paths ("/sprites/...") miss the Pages sub-folder; take them as base-relative.
      p = p.startsWith(base) ? p.slice(base.length) : p.replace(/^\/+/, "");
      return files.get(p) ?? null;
    } catch { return null; }
  };
  const blob = (f) => new Blob([f.bytes], { type: f.type });
  const realFetch = window.fetch.bind(window);
  window.fetch = (input, init) => {
    const f = find(input);
    if (!f) return realFetch(input, init);
    return Promise.resolve(new Response(blob(f), { status: 200, headers: { "content-type": f.type, "content-length": String(f.bytes.length) } }));
  };
  const src = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, "src");
  Object.defineProperty(HTMLImageElement.prototype, "src", {
    configurable: true, enumerable: src.enumerable, get: src.get,
    set(v) {
      const f = find(v);
      if (f && !f.url) f.url = URL.createObjectURL(blob(f));
      src.set.call(this, f ? f.url : v);
    },
  });
}

async function start(files) {
  msg("Starting...");
  serve(files);
  await import(ENTRY);
  $("gate").remove();
  $("forget").style.display = "block";
}

async function unlockWith(lock, pkcs8) {
  msg("Loading the game... 0%");
  const pack = await get("pack.bin", (f) => msg("Loading the game... " + Math.floor(f * 100) + "%"));
  msg("Unpacking...");
  return openPack(pack, pkcs8);
}

async function main() {
  $("forget").addEventListener("click", (e) => { e.preventDefault(); forget(); location.reload(); });
  if (!crypto.subtle || typeof DecompressionStream === "undefined") {
    msg("This browser is too old for this page (needs https and a current Chrome, Firefox, Edge or Safari).", true);
    return;
  }
  const lock = parseLock(await get("lock.bin"));
  const saved = remembered(lock);
  if (saved) {
    try { return await start(await unlockWith(lock, saved)); }
    catch (e) { if (e.message !== "wrong") throw e; forget(); }
  }
  const form = $("gate-form"), pw = $("gate-pw"), go = $("gate-go");
  form.hidden = false;
  msg("");
  pw.focus();
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!pw.value) return;
    go.disabled = pw.disabled = true;
    msg("Checking...");
    try {
      const pkcs8 = await privateKeyFromPassword(lock, pw.value);
      const files = await unlockWith(lock, pkcs8);
      remember(lock, pkcs8);
      form.hidden = true;
      await start(files);
    } catch (err) {
      msg(err.message === "wrong" ? "That is not the password." : String(err.message || err), true);
      go.disabled = pw.disabled = false;
      pw.select();
    }
  });
}

main().catch((e) => msg(String(e.message || e), true));
