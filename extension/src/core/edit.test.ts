// node --test src/core/edit.test.ts — the manual editor's model: the current
// state from facts, and the facts an edit signs.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { ensureWasm } from "./wasm.ts";
import type { Fact } from "./facts.ts";
import { draftOf, manualState, nameFromKey, planEdit, type CheckedFact } from "./edit.ts";

const om = await ensureWasm(readFileSync(new URL("../../vendor/openmanuals-wasm/openmanuals_wasm_bg.wasm", import.meta.url)));
const pk = (b: string, m: string) => om.product_key(b, m) ?? undefined;

const M = "01M69JSKVAY3Z9RCYD22GCY64Q";
const ME = "QPRGVPJNWDXH4ESK2RYDTZJLTE";
const THEM = "AAAAAAAAAAAAAAAAAAAAAAAAAA";
const AT = "2026-11-05T12:00:00Z";
let n = 0;
const served = (type: string, author: string, body: Record<string, unknown>, extra: Partial<CheckedFact> = {}): CheckedFact => {
  n++;
  return { id: "sha256:" + n.toString(16).padStart(64, "0"), cursor: `C${n.toString().padStart(4, "0")}`, hidden: false, retracted: false,
    fact: { v: 1, type, author, at: AT, body } as Fact, ...extra };
};

const KEY_WRONG = pk("Philips", "14PV1OO")!;
const KEY_KEPT = pk("Philips", "21PT1354")!;
const facts = [
  served("manual", ME, { id: M, title: "Old title", doc_type: "user" }),
  served("covers", ME, { manual: M, product: KEY_WRONG }),
  served("covers", THEM, { manual: M, product: KEY_KEPT }),
  served("manual", THEM, { id: M, title: "Newer title" }),
  served("covers", ME, { manual: M, product: pk("Philips", "GONE") }, { retracted: true }),
  served("covers", THEM, { manual: M, product: pk("Philips", "HIDDEN") }, { hidden: true, fact: null }),
  served("covers", ME, { manual: "01M69JSKVAY3Z9RCYD22GCY64R", product: pk("Philips", "OTHER") }),
];
const names = { [KEY_WRONG]: { brand: "Philips", model: "14PV1OO" }, [KEY_KEPT]: { brand: "Philips", model: "21PT1354" } };

test("state: newest title per field; live covers of this manual only", () => {
  const s = manualState(M, [...facts].reverse(), names);
  assert.equal(s.title, "Newer title");
  assert.equal(s.docType, "user", "a manual fact without doc_type leaves it");
  assert.deepEqual(s.models.map((m) => [m.brand, m.model, m.covers.map((c) => c.author)]), [["Philips", "14PV1OO", [ME]], ["Philips", "21PT1354", [THEM]]]);
});

test("state: a product without a name yet shows its key's parts", () => {
  assert.deepEqual(nameFromKey("philips|14PV100"), { brand: "philips", model: "14PV100" });
  const s = manualState(M, [served("covers", ME, { manual: M, product: "philips|14PV100" })]);
  assert.deepEqual([s.models[0].brand, s.models[0].model], ["philips", "14PV100"]);
});

test("an edit: title and type, a typo fixed, a model added; someone else's model stays", () => {
  const s = manualState(M, facts, names);
  const d = draftOf(s);
  d.title = "  Philips 14PV100   service manual ";
  d.docType = "service";
  d.models = [{ brand: "Philips", model: "14PV100" }, { brand: "philips", model: "14-PV-100" }, { brand: "Philips", model: "21PT1354" }, { brand: "", model: "" }];
  const p = planEdit(s, d, ME, pk, AT);
  assert.equal(p.error, undefined);
  assert.deepEqual(p.facts, [
    { type: "manual", at: AT, body: { id: M, title: "Philips 14PV100 service manual", doc_type: "service" } },
    { type: "retract", at: AT, body: { fact: facts[1].id } },
    { type: "product", at: AT, body: { brand: "Philips", model: "14PV100" } },
    { type: "covers", at: AT, body: { manual: M, product: pk("Philips", "14PV100") } },
  ]);
  assert.deepEqual(p.changes, ["Title: “Newer title” → “Philips 14PV100 service manual”", "Type: user → service", "Remove model: Philips 14PV1OO", "Add model: Philips 14PV100"]);
  assert.deepEqual(p.notes, []);

  const theirs = draftOf(s);
  theirs.models = theirs.models.filter((m) => m.model !== "21PT1354");
  const q = planEdit(s, theirs, ME, pk, AT);
  assert.deepEqual(q.facts, []);
  assert.deepEqual(q.notes, ["Philips 21PT1354 was listed by someone else, so you can't remove it."]);
});

test("a model listed by you and someone else: your listing is withdrawn, the model stays", () => {
  const s = manualState(M, [served("covers", ME, { manual: M, product: KEY_KEPT }), served("covers", THEM, { manual: M, product: KEY_KEPT })], names);
  const p = planEdit(s, { title: "T", docType: "user", models: [] }, ME, pk, AT);
  assert.deepEqual(p.facts.filter((f) => f.type === "retract").length, 1);
  assert.deepEqual(p.changes.slice(-1), ["Withdraw your listing of Philips 21PT1354"]);
  assert.match(p.notes[0], /stays on the page/);
});

test("nothing changed, and drafts that can't be saved", () => {
  const s = manualState(M, facts, names);
  assert.deepEqual(planEdit(s, draftOf(s), ME, pk, AT), { facts: [], changes: [], notes: [] });
  const bad = (d: Partial<ReturnType<typeof draftOf>>, me: string | null = ME) => planEdit(s, { ...draftOf(s), ...d }, me, pk, AT).error;
  assert.match(bad({ title: "   " })!, /title can't be empty/);
  assert.match(bad({ title: "x".repeat(301) })!, /longer than 300/);
  assert.match(bad({ docType: "novel" })!, /document type/);
  assert.match(bad({ models: [{ brand: "Philips", model: "" }] })!, /both a brand and a model/);
  assert.match(bad({ models: [{ brand: "Philips", model: "--" }] })!, /isn't a model name/);
  assert.match(bad({}, null)!, /No signing key/);
});
