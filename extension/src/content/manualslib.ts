// ManualsLib adapter. Manual pages: /manual/<id>/<slug>.html. The download
// page /download/<id>/<slug>.html shows a reCAPTCHA, then reveals
// a.download-url / a.view-url with a signed link to the PDF — those are what
// we intercept.
import { init, type Adapter, type InterceptRequest } from "./common.ts";

const ML_ID = /\/manual\/(\d+)\//i;
const PAGE = /^\/(manual|download)\/(\d+)\/([^/?#]*)/i;

function page() {
  const m = PAGE.exec(location.pathname);
  return m ? { kind: m[1].toLowerCase(), id: m[2], slug: m[3] } : null;
}

function cleanTitle(): string {
  let title = (document.querySelector("h1")?.textContent ?? "").trim();
  if (!title || /^download manual$/i.test(title)) title = document.title;
  return title.replace(/^download\s+/i, "").replace(/\s*(pdf download)?\s*\|\s*manualslib.*$/i, "").replace(/\s+/g, " ").trim();
}

/** Brand and models from the breadcrumb, the title and the "also suitable for" list. */
function products(title: string): { brand: string; model: string }[] {
  const out: { brand: string; model: string }[] = [];
  let brand = "";
  const crumbs = Array.from(document.querySelectorAll('a[href*="/brand/"]')).map((a) => a.textContent?.replace(/\s+manuals?$/i, "").trim() ?? "").filter(Boolean);
  if (crumbs.length) brand = crumbs[0];
  if (!brand) brand = title.split(/\s+/)[0] ?? "";
  const add = (model: string) => { model = model.replace(/\s+/g, " ").trim(); if (brand && model) out.push({ brand, model }); };
  const breadcrumbModel = Array.from(document.querySelectorAll('a[href*="/products/"]')).map((a) => a.textContent?.trim() ?? "").filter(Boolean)[0];
  if (breadcrumbModel) add(breadcrumbModel);
  else {
    const t = title.replace(new RegExp("^" + brand.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\s+", "i"), "");
    const model = t.replace(/\s+(service|user|owner'?s?|instruction|instructions|operating|operation|installation|quick start|setup|repair|parts|schematic|wiring).*$/i, "").trim();
    if (model && model !== t) add(model);
  }
  // "This manual is also suitable for:" list
  const suit = Array.from(document.querySelectorAll("*")).find((el) => /also suitable for/i.test(el.textContent ?? "") && el.children.length < 30 && (el.textContent ?? "").length < 2000);
  if (suit) for (const a of suit.querySelectorAll("a")) add(a.textContent ?? "");
  return out;
}

const adapter: Adapter = {
  site: "manualslib",
  getMeta() {
    const p = page();
    const title = cleanTitle();
    const pages = /(\d+)\s+pages?/i.exec(document.body.innerText ?? "");
    const lang = (document.documentElement.lang || "").split("-")[0] || undefined;
    return {
      title, description: pages ? `${pages[1]} pages` : undefined, language: lang && lang !== "en" ? lang : undefined,
      sourceUrl: p ? `https://www.manualslib.com/manual/${p.id}/${p.slug}` : location.href.split("#")[0],
      products: products(title),
    };
  },
  offersFile(url: string) {
    const p = page();
    if (!p || p.kind !== "download") return false;
    return [...document.querySelectorAll<HTMLAnchorElement>("a.download-url[href], a.view-url[href]")]
      .some((a) => { try { return new URL(a.getAttribute("href")!, location.href).href === url; } catch { return false; } });
  },
  hookDownloads(intercept: (r: InterceptRequest) => void) {
    const p = page();
    if (!p || p.kind !== "download") return;
    const hint = p.slug.replace(/\.html?$/i, "") + ".pdf";
    const hook = (a: HTMLAnchorElement, mode: "download" | "view") => {
      if (a.dataset.omHooked) return;
      a.dataset.omHooked = "1";
      a.addEventListener("click", (ev) => {
        const href = a.getAttribute("href");
        if (!href || /^(javascript:|#)/i.test(href) || ev.button !== 0 || ev.metaKey || ev.ctrlKey) return;
        ev.preventDefault();
        ev.stopImmediatePropagation();
        const url = new URL(href, location.href).href;
        const base = url.split(/[?#]/)[0].split("/").pop() ?? "";
        intercept({ url, mode, newTab: a.target === "_blank", filenameHint: /\.pdf$/i.test(base) ? decodeURIComponent(base) : hint });
      }, true);
    };
    const scan = () => {
      document.querySelectorAll<HTMLAnchorElement>("a.download-url[href]").forEach((a) => hook(a, "download"));
      document.querySelectorAll<HTMLAnchorElement>("a.view-url[href]").forEach((a) => hook(a, "view"));
    };
    scan();
    new MutationObserver(scan).observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ["href"] });
  },
  collectListLinks() {
    const p = page();
    const out: { el: HTMLAnchorElement; sourceId: string }[] = [];
    for (const a of document.querySelectorAll<HTMLAnchorElement>('a[href*="/manual/"]')) {
      const m = ML_ID.exec(a.getAttribute("href") ?? "");
      if (!m || (p && m[1] === p.id) || a.querySelector("img") || !a.textContent?.trim()) continue;
      out.push({ el: a, sourceId: m[1] });
    }
    return out;
  },
};

void init(adapter);
