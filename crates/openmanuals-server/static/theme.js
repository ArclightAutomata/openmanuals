// The header's theme switch: System (follow the OS), Light or Dark. The
// choice is kept in localStorage ("om-theme"); an inline script in <head>
// applies it before the first paint. Other open tabs follow a change.
(() => {
  const KEY = "om-theme";
  const root = document.documentElement;
  const sw = document.querySelector(".theme-switch");
  if (!sw) return;
  const valid = (v) => v === "light" || v === "dark";
  const apply = (v) => { if (valid(v)) root.dataset.theme = v; else delete root.dataset.theme; render(); };
  function render() {
    const current = root.dataset.theme || "system";
    for (const b of sw.querySelectorAll("button")) b.setAttribute("aria-pressed", String(b.value === current));
  }
  sw.addEventListener("click", (e) => {
    const b = e.target.closest("button[value]");
    if (!b) return;
    apply(b.value);
    try { if (valid(b.value)) localStorage.setItem(KEY, b.value); else localStorage.removeItem(KEY); } catch {}
  });
  window.addEventListener("storage", (e) => { if (e.key === KEY) apply(e.newValue); });
  sw.hidden = false;
  render();
})();
