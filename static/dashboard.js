// Local timestamps, remembered names/links for this browser, copy and delete-confirm.
function remembered() {
  try { return JSON.parse(localStorage.getItem("ss_files") || "{}"); } catch { return {}; }
}
const known = remembered();

document.querySelectorAll("time[data-ts]").forEach((t) => {
  t.textContent = new Date(Number(t.dataset.ts) * 1000).toLocaleString();
});

document.querySelectorAll("tr[data-token]").forEach((row) => {
  const info = known[row.dataset.token];
  if (!info) return;
  const cell = row.querySelector(".fname");
  cell.textContent = info.name;
  cell.classList.remove("muted");
  const btn = row.querySelector(".copy");
  btn.hidden = false;
  btn.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(info.link); btn.textContent = "Copied"; }
    catch { btn.textContent = "Copy failed"; }
    setTimeout(() => (btn.textContent = "Copy link"), 1500);
  });
});

document.querySelectorAll(".act-file").forEach((c) => {
  const info = known[c.dataset.token];
  if (info) c.textContent = info.name;
});

document.querySelectorAll(".del-form").forEach((f) =>
  f.addEventListener("submit", (e) => {
    if (!confirm("Delete this file now? The share link will stop working.")) e.preventDefault();
  }));
