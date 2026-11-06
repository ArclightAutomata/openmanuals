// Content script on the configured OpenManuals server's pages only (registered
// at runtime for that origin, see background/site.ts). It adds the same small
// "⋯" button to every hooked fact, copy and file, so the page can't tell which
// facts are yours, and an edit button to a manual's title and models; a click
// only asks the service worker to open the side panel (or a window). It also reports the page's hooks (ids only)
// for the side panel, which fetches and checks each one itself. Nothing here
// signs, and nothing on the page is trusted beyond the ids.
import { keyOf } from "../core/panel.ts";
import { actionFor, type SiteAction } from "../core/site.ts";

const HOOKS = "[data-om-fact], [data-om-location], [data-om-file], [data-om-manual]";

/** The button's text and tooltip. */
function label(a: SiteAction): [string, string] {
  if (a.action === "manual") {
    if (a.focus === "add") return ["+ Add model", "Add a model this manual covers (OpenManuals extension)"];
    if (a.focus?.startsWith("product:")) return ["✎", "Edit or remove this model (OpenManuals extension)"];
    return ["✎", "Edit this manual's title, type and models (OpenManuals extension)"];
  }
  return ["⋯", a.action === "fact" ? "Retract or report this fact (OpenManuals extension)" : "Report or retract (OpenManuals extension)"];
}

function addButtons(root: ParentNode): void {
  for (const el of root.querySelectorAll<HTMLElement>(HOOKS)) {
    const a = actionFor(el);
    if (!a) continue;
    // This element's own slot, not one of a nested hook's (a copy inside a file section).
    const slot = [...el.querySelectorAll<HTMLElement>(".om-actions")].find((s) => s.closest(HOOKS) === el);
    if (!slot || slot.querySelector("button.om-act")) continue;
    const b = document.createElement("button");
    b.type = "button";
    b.className = a.action === "manual" ? "om-act om-edit" : "om-act";
    [b.textContent, b.title] = label(a);
    b.setAttribute("aria-label", b.title);
    b.addEventListener("click", (e) => {
      e.preventDefault();
      // Only a real click by the user; the page can dispatch synthetic ones.
      if (!e.isTrusted) return;
      void chrome.runtime.sendMessage({ type: "siteAction", ...a }).catch(() => {});
    });
    slot.append(b);
  }
}

/** The page's hooks in page order (validated again by the service worker and the panel). */
function hooks(): { el: HTMLElement; a: SiteAction }[] {
  const out: { el: HTMLElement; a: SiteAction }[] = [];
  for (const el of document.querySelectorAll<HTMLElement>(HOOKS)) {
    const a = actionFor(el);
    if (a) out.push({ el, a });
  }
  return out;
}

let reported = "";
function report(): void {
  const items = hooks().map((h) => h.a);
  const sig = JSON.stringify(items);
  if (sig === reported) return;
  reported = sig;
  void chrome.runtime.sendMessage({ type: "sitePage", items }).catch(() => {});
}

let highlighted: HTMLElement | null = null;
function highlight(key: string | null): void {
  highlighted?.classList.remove("om-highlight");
  highlighted = null;
  if (!key) return;
  const h = hooks().find((x) => keyOf(x.a) === key);
  if (!h) return;
  highlighted = h.el;
  h.el.classList.add("om-highlight");
  h.el.scrollIntoView({ block: "nearest", behavior: "smooth" });
}

void (async () => {
  const hello = (await chrome.runtime.sendMessage({ type: "siteHello" }).catch(() => null)) as { ok?: boolean; upload?: boolean } | null;
  // Ends the "checking" state that content-site.css shows (and, for "no", brings back the install notes).
  document.documentElement.dataset.omExt = hello?.ok ? "ok" : "no";
  if (!hello?.ok) return;
  for (const h of document.querySelectorAll<HTMLElement>(".om-ext-hint")) h.hidden = true;
  // "Help preserve a manual": say whether a download here would be preserved.
  // (An older service worker doesn't say; then neither note is shown.)
  const upload = typeof hello.upload === "boolean" ? (hello.upload ? "on" : "off") : null;
  for (const h of document.querySelectorAll<HTMLElement>("[data-om-upload]")) h.hidden = h.dataset.omUpload !== upload;
  for (const b of document.querySelectorAll<HTMLElement>("[data-om-open-options]")) {
    b.addEventListener("click", (e) => {
      e.preventDefault();
      if (!e.isTrusted) return;
      void chrome.runtime.sendMessage({ type: "openOptions", section: "archive" }).catch(() => {});
    });
  }
  addButtons(document);
  report();
  // Pages that change (load more, filters) are followed, debounced.
  let t: ReturnType<typeof setTimeout> | undefined;
  new MutationObserver(() => {
    clearTimeout(t);
    t = setTimeout(() => { addButtons(document); report(); }, 400);
  }).observe(document.body, { childList: true, subtree: true });
  // Hovering a row in the side panel outlines it here (cosmetic).
  chrome.runtime.onMessage.addListener((msg: { type?: string; key?: string | null }, sender) => {
    if (sender.id !== chrome.runtime.id || msg?.type !== "omHighlight") return;
    highlight(typeof msg.key === "string" ? msg.key : null);
  });
})();
