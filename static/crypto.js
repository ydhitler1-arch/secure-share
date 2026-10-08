// End-to-end encryption helpers (Web Crypto). Runs only in the browser.
// Layout of the stored blob: IV(12) || AES-GCM( len(4) || meta JSON || file bytes )
(() => {
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const PBKDF2_ITERATIONS = 600000;

  const b64 = {
    enc: (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
    dec: (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)),
  };

  // No password: the random 256-bit link key is the AES key.
  // Password: AES key = PBKDF2(password, salt = link key), so the link alone is not enough.
  async function aesKey(linkKey, password) {
    if (!password) return crypto.subtle.importKey("raw", linkKey, "AES-GCM", false, ["encrypt", "decrypt"]);
    const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: linkKey, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
      base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }

  async function encryptFile(file, password) {
    const linkKey = crypto.getRandomValues(new Uint8Array(32));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const meta = enc.encode(JSON.stringify({ name: file.name }));
    const body = new Uint8Array(4 + meta.length + file.size);
    new DataView(body.buffer).setUint32(0, meta.length);
    body.set(meta, 4);
    body.set(new Uint8Array(await file.arrayBuffer()), 4 + meta.length);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await aesKey(linkKey, password), body));
    const out = new Uint8Array(12 + ct.length);
    out.set(iv);
    out.set(ct, 12);
    return { blob: new Blob([out]), key: b64.enc(linkKey) };
  }

  // Throws (OperationError) on a wrong key/password or tampered data.
  async function decryptBlob(buf, key, password) {
    const data = new Uint8Array(buf);
    const plain = new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: data.slice(0, 12) }, await aesKey(b64.dec(key), password), data.slice(12)));
    const n = new DataView(plain.buffer).getUint32(0);
    const meta = JSON.parse(dec.decode(plain.slice(4, 4 + n)));
    return { name: String(meta.name || "file"), bytes: plain.slice(4 + n) };
  }

  // Full flows, also used by the page scripts.
  async function shareFile(file, password, hours, maxDownloads) {
    const { blob, key } = await encryptFile(file, password);
    const form = new FormData();
    form.append("blob", blob, "data.bin");
    form.append("hours", hours);
    form.append("max_downloads", maxDownloads);
    const csrf = document.querySelector('meta[name="csrf-token"]');
    const r = await fetch("/upload", {
      method: "POST", body: form, headers: { "X-CSRF-Token": csrf ? csrf.content : "" },
    });
    if (!r.ok) {
      let msg = "Upload failed (" + r.status + ")";
      try { msg = (await r.json()).error || msg; } catch { /* not JSON: keep generic message */ }
      throw new Error(msg);
    }
    const res = await r.json();
    res.link += "#k=" + key + (password ? "&p=1" : "");
    return res;
  }

  window.SS = { b64, encryptFile, decryptBlob, shareFile };
})();
