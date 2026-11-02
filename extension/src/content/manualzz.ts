// Manualzz adapter. Manual pages: /doc/<id>/<slug>. The download page
// /download/<id> shows a reCAPTCHA, then a "Download PDF" link whose onclick
// calls download_source(): it submits <form id="download"> (POST
// /download/check with documentId, format and g-recaptcha-response, target
// _blank), and the answer redirects to the PDF. We post that form ourselves.
import { init, type Adapter, type InterceptRequest } from "./common.ts";

const PAGE = /^\/(doc|download)\/(\d+)(?:\/([^/?#]*))?/i;
const DOC_ID = /\/doc\/(\d+)(?:[/?#]|$)/i;

function page() {
  const m = PAGE.exec(location.pathname);
  return m ? { kind: m[1].toLowerCase() === "doc" ? "manual" : "download", id: m[2], slug: m[3] ?? "" } : null;
}

const cleanTitle = (): string =>
  ((document.querySelector("h1")?.textContent ?? "").trim() || document.title.replace(/\s*\|\s*manualzz\s*$/i, "")).replace(/\s+/g, " ").trim();

/** The manual page's slug, on the download page from its "Back to online viewer" link. */
function docSlug(id: string): string {
  const p = page();
  if (p?.kind === "manual") return p.slug;
  for (const a of document.querySelectorAll<HTMLAnchorElement>(`a[href*="/doc/${id}/"]`)) {
    const m = new RegExp(`/doc/${id}/([^/?#]+)`).exec(a.getAttribute("href") ?? "");
    if (m) return m[1];
  }
  return "";
}

interface Product { brand: string; model: string }
const productKey = (id: string) => `om-manualzz-products:${id}`;

/**
 * Brand and model from the manual page's breadcrumb ("Hitachi" → /brand/…,
 * "CM721F - 19" CRT Display" → /manual/Hitachi/…), kept for the tab so the
 * download page, which has no breadcrumb, can use it.
 */
function breadcrumbProducts(id: string): Product[] | null {
  const brand = document.querySelector('a[href*="/brand/"]')?.textContent?.trim();
  const product = Array.from(document.querySelectorAll<HTMLAnchorElement>('a[href*="/manual/"]')).map((a) => a.textContent?.trim() ?? "").find(Boolean);
  if (!brand || !product) return null;
  const model = product.split(/\s+-\s+/)[0].trim();
  const out = model ? [{ brand, model }] : [];
  try { sessionStorage.setItem(productKey(id), JSON.stringify(out)); } catch { /* storage off */ }
  return out;
}

/** "Hitachi CM721F - 19" CRT Display User manual" → Hitachi / CM721F. */
function titleProducts(title: string): Product[] {
  const [brand, ...rest] = title.split(/\s+/);
  const model = rest.join(" ").split(/\s+-\s+/)[0].replace(/\s+(service|user|owner'?s?|instruction|operating|installation|quick start|setup|repair|parts)\b.*$/i, "").trim();
  return brand && model ? [{ brand, model }] : [];
}

function products(id: string, title: string): Product[] {
  const here = breadcrumbProducts(id);
  if (here) return here;
  try {
    const saved = sessionStorage.getItem(productKey(id));
    if (saved) return JSON.parse(saved) as Product[];
  } catch { /* storage off or bad JSON */ }
  return titleProducts(title);
}

const adapter: Adapter = {
  site: "manualzz",
  getMeta() {
    const p = page();
    const title = cleanTitle();
    if (!p) return { title, sourceUrl: location.href.split(/[?#]/)[0], products: [] };
    const slug = docSlug(p.id);
    return { title, sourceUrl: `https://manualzz.com/doc/${p.id}${slug ? `/${slug}` : ""}`, products: products(p.id, title) };
  },
  hookDownloads(intercept: (r: InterceptRequest) => void) {
    const p = page();
    if (!p) return;
    if (p.kind === "manual") { breadcrumbProducts(p.id); return; }
    const hook = (a: HTMLAnchorElement) => {
      if (a.dataset.omHooked) return;
      a.dataset.omHooked = "1";
      a.addEventListener("click", (ev) => {
        const form = document.querySelector<HTMLFormElement>("form#download");
        const token = form?.querySelector<HTMLTextAreaElement>('[name="g-recaptcha-response"]')?.value;
        // Before the captcha is done the site handles the click itself.
        if (!form || !token || ev.button !== 0 || ev.metaKey || ev.ctrlKey) return;
        ev.preventDefault();
        ev.stopImmediatePropagation();
        const body = new URLSearchParams();
        for (const el of Array.from(form.elements) as HTMLInputElement[]) if (el.name) body.set(el.name, el.value);
        const format = /download_source\(\s*['"]([a-z0-9]+)['"]/i.exec(a.getAttribute("onclick") ?? "")?.[1] ?? "pdf";
        body.set("format", format);
        const slug = docSlug(p.id);
        intercept({
          url: new URL(form.getAttribute("action") || "/download/check", location.href).href,
          form: body.toString(),
          mode: "download",
          filenameHint: `${slug || p.id}.${format}`,
          // Replays the site's own download (a new tab that receives the file).
          fallback: () => { (form.querySelector<HTMLInputElement>('[name="format"]') ?? { value: "" }).value = format; form.submit(); },
        });
      }, true);
    };
    const scan = () => document.querySelectorAll<HTMLAnchorElement>('a[onclick*="download_source"]').forEach(hook);
    scan();
    new MutationObserver(scan).observe(document.documentElement, { childList: true, subtree: true });
  },
  collectListLinks() {
    const p = page();
    const out: { el: HTMLAnchorElement; sourceId: string }[] = [];
    for (const a of document.querySelectorAll<HTMLAnchorElement>('a[href*="/doc/"]')) {
      const m = DOC_ID.exec(a.getAttribute("href") ?? "");
      if (!m || (p && m[1] === p.id) || a.querySelector("img") || !a.textContent?.trim()) continue;
      out.push({ el: a, sourceId: m[1] });
    }
    return out;
  },
};

void init(adapter);
