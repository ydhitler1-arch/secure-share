const form = document.getElementById("dl-form");
const msg = document.getElementById("msg");
const params = new URLSearchParams(location.hash.slice(1));
const key = params.get("k");
const needsPassword = params.get("p") === "1";
let cipher = null; // fetched once, so wrong-password retries don't use up downloads

if (!key) {
  msg.textContent = "This link is missing its decryption key (the part after #).";
  form.hidden = true;
}
if (needsPassword) document.getElementById("pw-row").hidden = false;

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = form.querySelector("button");
  btn.disabled = true;
  msg.className = "muted";
  msg.textContent = "Working...";
  try {
    if (!cipher) {
      const r = await fetch(form.dataset.blobUrl, { method: "POST" });
      if (!r.ok) throw new Error("This file is no longer available.");
      cipher = await r.arrayBuffer();
    }
    let file;
    try {
      file = await SS.decryptBlob(cipher, key, needsPassword ? form.password.value : "");
    } catch {
      msg.className = "err";
      msg.textContent = needsPassword ? "Wrong password, or the link is damaged." : "Could not decrypt: the link is damaged.";
      btn.disabled = false;
      return;
    }
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([file.bytes], { type: "application/octet-stream" }));
    a.download = file.name;
    document.body.append(a);
    a.click();
    a.remove();
    msg.textContent = "Decrypted. Your download should start.";
    form.hidden = true;
  } catch (err) {
    msg.className = "err";
    msg.textContent = err.message;
    btn.disabled = false;
  }
});
