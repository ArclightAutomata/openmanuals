// FreeServiceManuals.info adapter. Three kinds of page, each a table
// whose model number is the download link (a.typedownload):
//   /<lang>/servicemanuals/viewmanual/<Brand>/<TypeA>/…/  Brand, Type number,
//     "This manual also covers", Product, Year; the link opens an image
//     captcha, and the site's script posts it to /<lang>/servicemanuals/decaptcha/
//     and gets back the file's URL;
//   /<lang>/bookcats/<Publisher>/<Author>/<Title>/  Title, Author, Publisher;
//     no captcha, the URL is in the page's script (/bookcats/download/<file>);
//   /<lang>/tubedata/<Type>/ (or /<lang>/datasheets/<Type>/)  Type a/b/c and
//     Product (the component kind); no captcha, /media//tubedata/<file>. No
//     brand, so a datasheet names no products.
// Each time the script then appends <a id="captchalink" href="<file>"> and
// clicks it, so we catch that click: once the site has handed out the file.
import { init, type Adapter, type InterceptRequest } from "./common.ts";

const DOWNLOAD_PATH = /\/(?:bookcats|servicemanuals)\/download\/|\/media\/+tubedata\//i;

type Section = "servicemanuals" | "bookcats" | "datasheets";
function section(): Section {
  const p = location.pathname.toLowerCase();
  if (/^(\/[a-z]{2})?\/bookcats\//.test(p)) return "bookcats";
  if (/^(\/[a-z]{2})?\/(tubedata|datasheets)\//.test(p)) return "datasheets";
  return "servicemanuals";
}

interface Product { brand: string; model: string }

const clean = (s: string | null | undefined) => (s ?? "").replace(/\s+/g, " ").trim();

/** The site's placeholders where a brand or publisher goes: no product under those. */
const NO_BRAND = /^(?:none|unknown|miscellaneous|various|[^\p{L}\p{N}]*)$/iu;

/** The info table as label → cell. */
function rows(): Map<string, HTMLTableCellElement> {
  const out = new Map<string, HTMLTableCellElement>();
  for (const tr of document.querySelectorAll("table tr")) {
    const [label, value] = Array.from(tr.querySelectorAll<HTMLTableCellElement>("td"));
    if (label && value) out.set(clean(label.textContent).toLowerCase(), value);
  }
  return out;
}

/** A cell's lines (the site separates model numbers with <br>). */
function lines(cell: HTMLTableCellElement | undefined): string[] {
  if (!cell) return [];
  const out: string[] = [];
  let cur = "";
  for (const n of Array.from(cell.childNodes)) {
    if (n.nodeName === "BR") { out.push(cur); cur = ""; } else cur += n.textContent ?? "";
  }
  out.push(cur);
  return out.map(clean).filter(Boolean);
}

/** The model number: the download link's text (the cell also holds the captcha form). */
const linkText = (cell: HTMLTableCellElement | undefined) => clean(cell?.querySelector("a.typedownload")?.textContent) || clean(cell?.textContent);

function products(): Product[] {
  const r = rows();
  if (section() === "datasheets") return [];
  if (section() === "bookcats") {
    const brand = clean(r.get("publisher")?.textContent);
    const model = linkText(r.get("title"));
    return brand && model && !NO_BRAND.test(brand) ? [{ brand, model }] : [];
  }
  const brand = clean(r.get("brand")?.textContent);
  const models = [linkText(r.get("type number")), ...lines(r.get("this manual also covers"))].filter(Boolean);
  return brand && !NO_BRAND.test(brand) ? Array.from(new Set(models), (model) => ({ brand, model })) : [];
}

const isFileUrl = (url: string): boolean => {
  try {
    const u = new URL(url, location.href);
    return u.origin === location.origin && DOWNLOAD_PATH.test(u.pathname);
  } catch { return false; }
};

const adapter: Adapter = {
  site: "freeservicemanuals",
  offersFile: isFileUrl,
  getMeta() {
    const sourceUrl = location.href.split(/[?#]/)[0];
    // Page titles end in "Service Manual PDF Free Download" on books pages
    // too, which are often user manuals or brochures; keep that part only
    // for service manuals.
    const bare = clean(document.title.replace(/\s+(Service Manual\s+)?PDF( Free)? Download\s*$/i, ""));
    switch (section()) {
      case "datasheets": {
        const r = rows();
        const kind = clean(r.get("product")?.textContent);
        return { title: `${bare.replace(/\s+datasheet$/i, "")} datasheet`, ...(kind ? { description: kind } : {}), sourceUrl, products: [] };
      }
      case "bookcats": return { title: bare, sourceUrl, products: products() };
      default: return { title: clean(document.title.replace(/\s+PDF Free Download\s*$/i, "")), sourceUrl, products: products() };
    }
  },
  hookDownloads(intercept: (r: InterceptRequest) => void) {
    // The site's own script clicks a link it has just added, so listen on the
    // whole document rather than on a link.
    document.addEventListener("click", (ev) => {
      const a = (ev.target as Element | null)?.closest?.("a");
      if (!(a instanceof HTMLAnchorElement) || ev.button !== 0 || ev.metaKey || ev.ctrlKey || ev.shiftKey) return;
      const href = a.getAttribute("href") ?? "";
      if (a.id !== "captchalink" && !isFileUrl(href)) return;
      if (!/^(https?:|\/)/i.test(href)) return;
      ev.preventDefault();
      ev.stopImmediatePropagation();
      const url = new URL(href, location.href).href;
      let name = "";
      try { name = decodeURIComponent(new URL(url).pathname.split("/").pop() ?? ""); } catch { /* bad escape */ }
      intercept({ url, mode: "download", filenameHint: name || undefined });
    }, true);
  },
};

void init(adapter);
