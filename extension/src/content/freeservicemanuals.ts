// FreeServiceManuals.info adapter. Two kinds of manual page, both a table
// whose model number is the download link (a.typedownload):
//   /<lang>/servicemanuals/viewmanual/<Brand>/<TypeA>/…/  Brand, Type number,
//     "This manual also covers", Product, Year; the link opens an image
//     captcha, and the site's script posts it to /<lang>/servicemanuals/decaptcha/
//     and gets back the file's URL;
//   /<lang>/bookcats/<Publisher>/<Author>/<Title>/  Title, Author, Publisher;
//     no captcha, the URL is in the page's script (/bookcats/download/<file>).
// Either way the script then appends <a id="captchalink" href="<file>"> and
// clicks it, so we catch that click: once the site has handed out the file.
import { init, type Adapter, type InterceptRequest } from "./common.ts";

const DOWNLOAD_PATH = /\/(?:bookcats|servicemanuals)\/download\//i;

interface Product { brand: string; model: string }

const clean = (s: string | null | undefined) => (s ?? "").replace(/\s+/g, " ").trim();

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
  if (location.pathname.toLowerCase().includes("/bookcats/")) {
    const brand = clean(r.get("publisher")?.textContent);
    const model = linkText(r.get("title"));
    return brand && model ? [{ brand, model }] : [];
  }
  const brand = clean(r.get("brand")?.textContent);
  const models = [linkText(r.get("type number")), ...lines(r.get("this manual also covers"))].filter(Boolean);
  return brand ? Array.from(new Set(models), (model) => ({ brand, model })) : [];
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
    const title = clean(document.title.replace(/\s+PDF Free Download\s*$/i, ""));
    return { title, sourceUrl: location.href.split(/[?#]/)[0], products: products() };
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
