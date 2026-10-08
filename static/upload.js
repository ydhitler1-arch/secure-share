const form = document.getElementById("upload-form");
const result = document.getElementById("result");
const status = document.getElementById("status");
const MAX = Number(form.dataset.maxMb) * 1024 * 1024;

// Lets the dashboard show names and copyable links for files uploaded from this browser.
function remember(name, link) {
  try {
    const token = new URL(link).pathname.split("/").pop();
    const all = JSON.parse(localStorage.getItem("ss_files") || "{}");
    all[token] = { name, link };
    localStorage.setItem("ss_files", JSON.stringify(all));
  } catch { /* storage unavailable: dashboard just shows "Encrypted" */ }
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const file = form.file.files[0];
  if (!file) return;
  if (file.size > MAX) { status.textContent = "File is too large."; return; }
  const btn = form.querySelector("button");
  btn.disabled = true;
  status.textContent = "Encrypting in your browser and uploading...";
  try {
    const res = await SS.shareFile(file, form.password.value, form.hours.value, form.max_downloads.value);
    remember(file.name, res.link);
    document.getElementById("link").textContent = res.link;
    document.getElementById("delete-link").textContent = res.delete_link;
    document.getElementById("meta").textContent =
      (form.password.value ? "Password protected. " : "") +
      "Expires in " + res.hours + "h or after " + res.max_downloads + " download(s).";
    form.hidden = true;
    status.textContent = "";
    result.hidden = false;
  } catch (err) {
    status.textContent = err.message;
    btn.disabled = false;
  }
});
