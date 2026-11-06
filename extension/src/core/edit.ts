// Editing a manual: what it is now (from its verified `manual` and `covers`
// facts) and the facts that turn it into what the editor shows. Pure (no
// chrome.*), so it is tested directly.
//
// How an edit is expressed, given how the build folds facts:
// - title and type: a newer `manual` fact with the same id (newest wins per
//   field, from any author);
// - a model added: a `product` fact and a `covers` fact;
// - a model removed: a retraction of your own `covers` facts for it. Someone
//   else's `covers` can't be retracted by you, so that model stays.
import { bodies, nowIso, type Fact, type UnsignedFact } from "./facts.ts";

export const DOC_TYPES = ["user", "service", "schematic", "parts", "other"] as const;
/** How each type reads, as the website labels it. */
export const DOC_LABELS: Record<(typeof DOC_TYPES)[number], string> = {
  user: "User manual", service: "Service manual", schematic: "Schematic", parts: "Parts list", other: "Other document",
};
export const MAX_TITLE = 300;
export const MAX_NAME = 120;

/** A fact as `GET /api/manual/{id}/facts` serves it, already checked (signature, id). */
export interface CheckedFact { id: string; cursor: string; hidden: boolean; retracted: boolean; fact: Fact | null }

export interface Model {
  key: string;
  brand: string;
  model: string;
  /** The live `covers` facts naming this product, in ledger order. */
  covers: { id: string; author: string }[];
}

export interface ManualState { id: string; title: string; docType: string; models: Model[] }

/** What the editor's fields hold. */
export interface Draft { title: string; docType: string; models: { brand: string; model: string }[] }

/** A display name for a product key when the server has none yet (`brand|MODEL`). */
export function nameFromKey(key: string): { brand: string; model: string } {
  const i = key.indexOf("|");
  return i < 0 ? { brand: "", model: key } : { brand: key.slice(0, i), model: key.slice(i + 1) };
}

/**
 * The manual as the build will show it, from its facts in ledger order:
 * hidden and retracted facts don't count, and facts about other manuals are
 * ignored (the server shouldn't send them, but nothing it sends is trusted).
 */
export function manualState(id: string, facts: CheckedFact[], names: Record<string, { brand?: unknown; model?: unknown }> = {}): ManualState {
  let title = "", docType = "";
  const models = new Map<string, Model>();
  const sorted = [...facts].sort((a, b) => (a.cursor < b.cursor ? -1 : a.cursor > b.cursor ? 1 : 0));
  for (const s of sorted) {
    const f = s.fact;
    if (s.hidden || s.retracted || !f) continue;
    const b = f.body;
    if (f.type === "manual" && b.id === id) {
      if (typeof b.title === "string") title = b.title;
      if (typeof b.doc_type === "string") docType = b.doc_type;
    } else if (f.type === "covers" && b.manual === id && typeof b.product === "string") {
      const key = b.product;
      let m = models.get(key);
      if (!m) {
        const n = names[key];
        const fb = nameFromKey(key);
        m = { key, brand: typeof n?.brand === "string" ? n.brand : fb.brand, model: typeof n?.model === "string" ? n.model : fb.model, covers: [] };
        models.set(key, m);
      }
      m.covers.push({ id: s.id, author: f.author });
    }
  }
  return { id, title, docType, models: [...models.values()] };
}

/** The draft the editor starts from. */
export function draftOf(s: ManualState): Draft {
  return { title: s.title, docType: s.docType, models: s.models.map((m) => ({ brand: m.brand, model: m.model })) };
}

export interface EditPlan {
  /** The facts to sign, in order (empty: nothing to change). */
  facts: UnsignedFact[];
  /** One line per change, for the review step. */
  changes: string[];
  /** Things the edit can't do, said plainly (another author's model stays). */
  notes: string[];
  /** Why the draft can't be saved, if it can't. */
  error?: string;
}

const label = (t: string) => (DOC_LABELS as Record<string, string>)[t] ?? (t || "none");
const clean = (s: string) => s.replace(/\s+/g, " ").trim();

/**
 * The facts that turn `s` into `d`, signed as `me`. `productKey` is
 * openmanuals-core's (`om.product_key`), so keys match the server's.
 */
export function planEdit(s: ManualState, d: Draft, me: string | null, productKey: (brand: string, model: string) => string | undefined, at: string = nowIso()): EditPlan {
  const plan: EditPlan = { facts: [], changes: [], notes: [] };
  const fail = (error: string): EditPlan => ({ facts: [], changes: [], notes: [], error });
  if (!me) return fail("No signing key in this browser.");
  const title = clean(d.title);
  if (!title) return fail("The title can't be empty.");
  if (title.length > MAX_TITLE) return fail(`The title is longer than ${MAX_TITLE} characters.`);
  if (!(DOC_TYPES as readonly string[]).includes(d.docType)) return fail("Pick a document type.");

  // The models the draft asks for, by key (two spellings of one product are one model).
  const want = new Map<string, { brand: string; model: string }>();
  for (const row of d.models) {
    const brand = clean(row.brand), model = clean(row.model);
    if (!brand && !model) continue;
    if (!brand || !model) return fail(`“${brand || model}” needs both a brand and a model.`);
    if (brand.length > MAX_NAME || model.length > MAX_NAME) return fail(`“${brand} ${model}” is too long.`);
    const key = productKey(brand, model);
    if (!key) return fail(`“${brand} ${model}” isn't a model name.`);
    if (!want.has(key)) want.set(key, { brand, model });
  }

  if (title !== s.title || d.docType !== s.docType) {
    plan.facts.push({ type: "manual", at, body: bodies.manual(s.id, title, d.docType) });
    if (title !== s.title) plan.changes.push(`Title: “${s.title}” → “${title}”`);
    if (d.docType !== s.docType) plan.changes.push(`Type: ${label(s.docType)} → ${label(d.docType)}`);
  }
  for (const m of s.models) {
    if (want.has(m.key)) continue;
    const mine = m.covers.filter((c) => c.author === me);
    const others = m.covers.length - mine.length;
    for (const c of mine) plan.facts.push({ type: "retract", at, body: bodies.retract(c.id) });
    const name = `${m.brand} ${m.model}`;
    if (mine.length && !others) plan.changes.push(`Remove model: ${name}`);
    else if (mine.length) {
      plan.changes.push(`Withdraw your listing of ${name}`);
      plan.notes.push(`${name} stays on the page: someone else listed it too.`);
    } else plan.notes.push(`${name} was listed by someone else, so you can't remove it.`);
  }
  const have = new Set(s.models.map((m) => m.key));
  for (const [key, p] of want) {
    if (have.has(key)) continue;
    plan.facts.push({ type: "product", at, body: bodies.product(p.brand, p.model) });
    plan.facts.push({ type: "covers", at, body: bodies.covers(s.id, key) });
    plan.changes.push(`Add model: ${p.brand} ${p.model}`);
  }
  return plan;
}
