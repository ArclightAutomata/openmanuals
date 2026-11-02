// Elektrotanya adapter. /<slug>/download.html builds, after a random delay, a
// <form name="getmanual" action="/cgi-bin/download2.cgi"> whose "Download"
// link is javascript:document.getmanual.submit() — a programmatic submit fires
// no submit event, so we rewire that link when the form appears.
import { init, type Adapter, type InterceptRequest } from "./common.ts";

const ET_SLUG = /^\/([^/?#]+)\/download\.html$/i;

function slug(): string | null {
  const m = ET_SLUG.exec(location.pathname);
  return m ? m[1] : null;
}

const adapter: Adapter = {
  site: "elektrotanya",
  getMeta() {
    const title = document.title.replace(/\s+download,\s*schematics.*$/i, "").replace(/\s+/g, " ").trim();
    const tokens = title.split(" ");
    const products = tokens.length >= 2 ? [{ brand: tokens[0], model: tokens.slice(1).join(" ").replace(/\s+(sm|service manual|schematic|sch|user manual|um)$/i, "") }] : [];
    return { title, sourceUrl: location.href.split(/[?#]/)[0], products };
  },
  hookDownloads(intercept: (r: InterceptRequest) => void) {
    const wire = (form: HTMLFormElement) => {
      if (form.dataset.omHooked) return;
      form.dataset.omHooked = "1";
      const a = form.querySelector("a");
      if (!a) return;
      a.setAttribute("href", "#");
      a.addEventListener("click", (ev) => {
        ev.preventDefault();
        ev.stopImmediatePropagation();
        const params = new URLSearchParams();
        form.querySelectorAll<HTMLInputElement>("input[name]").forEach((i) => params.set(i.name, i.value));
        const url = new URL((form.getAttribute("action") || "/cgi-bin/download2.cgi") + "?" + params.toString(), location.href).href;
        intercept({ url, mode: "download", filenameHint: form.querySelector<HTMLInputElement>('input[name="file"]')?.value || undefined });
      }, true);
    };
    const scan = () => document.querySelectorAll<HTMLFormElement>('form[name="getmanual"]').forEach(wire);
    scan();
    new MutationObserver(scan).observe(document.documentElement, { childList: true, subtree: true });
  },
  collectListLinks() {
    const here = slug();
    const out: { el: HTMLAnchorElement; sourceId: string }[] = [];
    for (const a of document.querySelectorAll<HTMLAnchorElement>('a[href*="/download.html"]')) {
      let path: string;
      try { path = new URL(a.getAttribute("href") ?? "", location.href).pathname; } catch { continue; }
      const m = ET_SLUG.exec(path);
      if (!m || (here && m[1] === here) || !a.textContent?.trim()) continue;
      out.push({ el: a, sourceId: m[1] });
    }
    return out;
  },
};

void init(adapter);
