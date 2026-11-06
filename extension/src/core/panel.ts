// The side panel's model: the facts, copies and files a server page shows,
// what each one allows, and bulk plans. Pure (no chrome.*), so it is tested
// directly. What the page reports is untrusted: only well-formed ids survive,
// and every row is re-fetched and verified by the panel before it offers
// anything.
import type { Fact } from "./facts.ts";
import { FACT_ID_RE, FILE_ID_RE, REPORT_VALUES, summarizeBody, validAction, type ReportValue, type SiteAction } from "./site.ts";

/** Most hooks one page may report; more are ignored. */
export const MAX_PAGE_ITEMS = 500;
/** Most operations one bulk request may carry. */
export const MAX_BULK = 2000;
/** How long a single action waits for "Undo" before it is signed. */
export const UNDO_MS = 8000;

/** A stable key per item: the fact id, the copy's location fact id, file:<id>, or manual:<id> (every edit hook of a manual is one item). */
export function keyOf(a: SiteAction): string {
  switch (a.action) {
    case "fact": return a.fact;
    case "copy": return a.location;
    case "file": return `file:${a.file}`;
    case "manual": return `manual:${a.manual}`;
  }
}

/** The page's hooks, validated and de-duplicated, in page order. */
export function pageItems(raw: unknown): SiteAction[] {
  if (!Array.isArray(raw)) return [];
  const seen = new Set<string>();
  const out: SiteAction[] = [];
  for (const x of raw) {
    const a = validAction(x);
    if (!a) continue;
    const k = keyOf(a);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(a);
    if (out.length >= MAX_PAGE_ITEMS) break;
  }
  return out;
}

export interface Row {
  key: string;
  action: SiteAction;
  /** loading: being fetched; ok: verified; hidden: hidden by moderation; error: didn't check out. */
  status: "loading" | "ok" | "hidden" | "error";
  error?: string;
  /** The verified fact (fact and copy rows). */
  fact?: Fact;
  retracted?: boolean;
  /** Set after an action from this panel went through. */
  done?: "retracted" | "reported";
}

export type Op = "retract" | "report";

export type BulkOp =
  | { op: "retract"; fact: string }
  | { op: "report"; target: string; value: ReportValue; sha256?: string; author?: string; url?: string };

/** Your own verified fact or copy, not retracted, not itself a retraction. */
export function canRetract(r: Row, me: string | null): boolean {
  return r.status === "ok" && r.action.action !== "file" && r.action.action !== "manual" && !!r.fact && me !== null && r.fact.author === me
    && !r.retracted && r.fact.type !== "retract" && r.done === undefined;
}

/** Someone else's verified fact or copy, or a file. */
export function canReport(r: Row, me: string | null): boolean {
  if (r.done !== undefined) return false;
  if (r.action.action === "file") return r.status === "ok";
  return r.status === "ok" && !!r.fact && r.fact.author !== me;
}

export const can = (r: Row, me: string | null, op: Op) => (op === "retract" ? canRetract(r, me) : canReport(r, me));

const isSha256 = (s: string) => /^[0-9a-f]{64}$/.test(s);

/** The operation `op` on a row, or null when it isn't allowed. */
export function opFor(r: Row, op: Op, me: string | null, value: ReportValue = "spam"): BulkOp | null {
  if (!can(r, me, op)) return null;
  const a = r.action;
  if (a.action === "manual") return null;
  if (op === "retract") return { op: "retract", fact: r.key };
  if (a.action === "file") return { op: "report", target: `file:${a.file}`, value, ...(isSha256(a.file) ? { sha256: a.file } : {}) };
  const f = r.fact!;
  if (a.action === "copy") {
    const url = typeof f.body.url === "string" ? f.body.url : undefined;
    return { op: "report", target: a.location, value, author: f.author, ...(isSha256(a.file) ? { sha256: a.file } : {}), ...(url ? { url } : {}) };
  }
  return { op: "report", target: a.fact, value, author: f.author };
}

/** A bulk plan for the selected rows: the allowed operations, and how many selected rows were skipped. */
export function planBulk(rows: Row[], selected: ReadonlySet<string>, op: Op, me: string | null, value: ReportValue = "spam"): { ops: BulkOp[]; rows: Row[]; skipped: number } {
  const ops: BulkOp[] = [], picked: Row[] = [];
  let skipped = 0;
  for (const r of rows) {
    if (!selected.has(r.key)) continue;
    const o = opFor(r, op, me, value);
    if (o) { ops.push(o); picked.push(r); } else skipped++;
  }
  return { ops, rows: picked, skipped };
}

/** Keys of the rows matching `pred` (for "select all of …" helpers). */
export function selectWhere(rows: Row[], pred: (r: Row) => boolean): Set<string> {
  return new Set(rows.filter(pred).map((r) => r.key));
}

/** What a row is, for grouping and "select all of type": the fact type, or "file". */
export const kindOf = (r: Row) => (r.action.action === "file" ? "file" : r.fact?.type ?? r.action.action);

/** Counts per kind and per author, for the selection helpers. */
export function groups(rows: Row[]): { kinds: [string, number][]; authors: [string, number][] } {
  const k = new Map<string, number>(), a = new Map<string, number>();
  for (const r of rows) {
    if (r.status !== "ok") continue;
    k.set(kindOf(r), (k.get(kindOf(r)) ?? 0) + 1);
    if (r.fact) a.set(r.fact.author, (a.get(r.fact.author) ?? 0) + 1);
  }
  const sort = (m: Map<string, number>) => [...m].sort((x, y) => y[1] - x[1] || x[0].localeCompare(y[0]));
  return { kinds: sort(k), authors: sort(a) };
}

/** A one-line description of a row. */
export function describeRow(r: Row): string {
  if (r.action.action === "file") return `File ${r.action.file.slice(0, 16)}…`;
  if (r.action.action === "manual") return `Manual ${r.action.manual}`;
  if (!r.fact) return r.key.slice(0, 18) + "…";
  const f = r.fact;
  const b = f.body;
  const pick = (k: string) => (typeof b[k] === "string" ? (b[k] as string) : undefined);
  const main =
    f.type === "product" ? [pick("brand"), pick("model")].filter(Boolean).join(" ")
    : f.type === "manual" ? pick("title")
    : f.type === "location" ? pick("url")
    : f.type === "label" ? `${pick("value") ?? ""} → ${(pick("target") ?? "").slice(0, 20)}`
    : f.type === "retract" ? `retracts ${(pick("fact") ?? "").slice(0, 18)}…`
    : summarizeBody(b, 1)[0];
  const s = `${f.type}${main ? ": " + main : ""}`;
  return s.length > 120 ? s.slice(0, 117) + "…" : s;
}

/** Validate a bulk request before anything is signed (the panel is trusted, but check anyway). */
export function validOps(x: unknown): BulkOp[] | null {
  if (!Array.isArray(x) || x.length === 0 || x.length > MAX_BULK) return null;
  const out: BulkOp[] = [];
  for (const o of x as Record<string, unknown>[]) {
    if (!o || typeof o !== "object") return null;
    const str = (k: string) => (typeof o[k] === "string" ? (o[k] as string) : undefined);
    if (o.op === "retract") {
      const fact = str("fact");
      if (!fact || !FACT_ID_RE.test(fact)) return null;
      out.push({ op: "retract", fact });
    } else if (o.op === "report") {
      const target = str("target") ?? "", value = str("value") as ReportValue;
      const okTarget = FACT_ID_RE.test(target) || (target.startsWith("file:") && FILE_ID_RE.test(target.slice(5)));
      if (!okTarget || !(REPORT_VALUES as readonly string[]).includes(value)) return null;
      const sha256 = str("sha256"), author = str("author"), url = str("url");
      if (sha256 !== undefined && !isSha256(sha256)) return null;
      if (author !== undefined && !/^[A-Z2-7]{26}$/.test(author)) return null;
      if (url !== undefined && (url.length > 2048 || !/^https?:\/\//i.test(url))) return null;
      out.push({ op: "report", target, value, ...(sha256 ? { sha256 } : {}), ...(author ? { author } : {}), ...(url ? { url } : {}) });
    } else return null;
  }
  return out;
}
