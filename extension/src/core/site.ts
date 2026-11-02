// Acting on the OpenManuals server's own pages. The pages carry `data-om-*`
// hooks; the content script turns each hooked element into a request to open
// the extension's confirmation window, which re-fetches and re-checks
// everything itself. Nothing read from a page is trusted beyond "which id did
// the user click".

export const FACT_ID_RE = /^sha256:[0-9a-f]{64}$/;
/** A file reference: sha256 hex, or `sha1:<hex>` for legacy files. */
export const FILE_ID_RE = /^(?:[0-9a-f]{64}|sha1:[0-9a-f]{40})$/;
export const REPORT_VALUES = ["wrong-file", "spam", "malware", "impersonation"] as const;
export type ReportValue = (typeof REPORT_VALUES)[number];

/** What a click asks for. The confirm window decides what is actually possible. */
export type SiteAction =
  | { action: "fact"; fact: string }
  | { action: "copy"; location: string; file: string }
  | { action: "file"; file: string };

/** Accept only the exact shapes above, with well-formed ids; anything else is null. */
export function validAction(x: unknown): SiteAction | null {
  if (!x || typeof x !== "object") return null;
  const o = x as Record<string, unknown>;
  const str = (k: string) => (typeof o[k] === "string" ? (o[k] as string) : "");
  switch (o.action) {
    case "fact": return FACT_ID_RE.test(str("fact")) ? { action: "fact", fact: str("fact") } : null;
    case "copy": return FACT_ID_RE.test(str("location")) && FILE_ID_RE.test(str("file")) ? { action: "copy", location: str("location"), file: str("file") } : null;
    case "file": return FILE_ID_RE.test(str("file")) ? { action: "file", file: str("file") } : null;
    default: return null;
  }
}

export function toQuery(a: SiteAction): string {
  return new URLSearchParams(Object.entries(a)).toString();
}

export function fromQuery(search: string): SiteAction | null {
  const p = new URLSearchParams(search);
  const o: Record<string, string> = {};
  for (const k of ["action", "fact", "location", "file"]) { const v = p.get(k); if (v !== null) o[k] = v; }
  return validAction(o);
}

/** The minimal view of a DOM element the hook reader needs (tests pass plain objects). */
export interface HookElement { getAttribute(name: string): string | null; hasAttribute(name: string): boolean }

/**
 * The action a hooked element offers, or null (hidden by moderation, or not a
 * hook). A copy (has a location) wins over its file; a fact row is a fact.
 */
export function actionFor(el: HookElement): SiteAction | null {
  if (el.hasAttribute("data-om-hidden")) return null;
  const fact = el.getAttribute("data-om-fact");
  if (fact !== null) return validAction({ action: "fact", fact });
  const location = el.getAttribute("data-om-location");
  const file = el.getAttribute("data-om-file");
  if (location !== null) return validAction({ action: "copy", location, file });
  if (file !== null) return validAction({ action: "file", file });
  return null;
}

/** A few body fields as short "key: value" lines for the confirmation window. */
export function summarizeBody(body: Record<string, unknown>, max = 8): string[] {
  const out: string[] = [];
  for (const [k, v] of Object.entries(body)) {
    if (out.length >= max) { out.push("…"); break; }
    let s = typeof v === "string" ? v : JSON.stringify(v);
    if (s.length > 90) s = s.slice(0, 87) + "…";
    out.push(`${k}: ${s}`);
  }
  return out;
}
