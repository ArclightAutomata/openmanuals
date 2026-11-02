// node --test src/core/site.test.ts — page hooks, action validation, served-fact checks.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { ensureWasm } from "./wasm.ts";
import { keyFromEd25519Seed } from "./keys.ts";
import { hexToBytes } from "./b64.ts";
import { factId, signFact } from "./facts.ts";
import { actionFor, fromQuery, summarizeBody, toQuery, validAction, type HookElement } from "./site.ts";
import { checkServedFact } from "./site-check.ts";

const root = new URL("../../../", import.meta.url);
const vectors = JSON.parse(readFileSync(new URL("crates/openmanuals-core/vectors/vectors.json", root), "utf8"));
await ensureWasm(readFileSync(new URL("extension/vendor/openmanuals-wasm/openmanuals_wasm_bg.wasm", root)));
const key = await keyFromEd25519Seed(hexToBytes(vectors.keys[0].seed_hex), vectors.keys[0].jwk.x);

const F = "sha256:" + "a".repeat(64);
const L = "sha256:" + "b".repeat(64);
const S = "c".repeat(64);
const el = (attrs: Record<string, string>): HookElement => ({ getAttribute: (n) => attrs[n] ?? null, hasAttribute: (n) => n in attrs });

test("hooks map to actions; hidden and malformed ones to none", () => {
  assert.deepEqual(actionFor(el({ "data-om-fact": F, "data-om-author": "X", "data-om-type": "location" })), { action: "fact", fact: F });
  assert.deepEqual(actionFor(el({ "data-om-location": L, "data-om-file": S, "data-om-author": "X" })), { action: "copy", location: L, file: S });
  assert.deepEqual(actionFor(el({ "data-om-file": "sha1:" + "d".repeat(40) })), { action: "file", file: "sha1:" + "d".repeat(40) });
  assert.equal(actionFor(el({ "data-om-fact": F, "data-om-hidden": "" })), null);
  assert.equal(actionFor(el({ "data-om-fact": "sha256:" + "A".repeat(64) })), null, "uppercase hex isn't an id");
  assert.equal(actionFor(el({ "data-om-fact": F + "\" onclick=x" })), null);
  assert.equal(actionFor(el({ "data-om-location": L })), null, "a copy needs its file");
  assert.equal(actionFor(el({})), null);
});

test("actions are validated strictly and survive the confirm URL", () => {
  for (const a of [{ action: "fact", fact: F }, { action: "copy", location: L, file: S }, { action: "file", file: S }] as const) {
    assert.deepEqual(fromQuery("?" + toQuery(a)), a);
  }
  assert.equal(validAction({ action: "sign", fact: F }), null, "unknown actions are ignored");
  assert.equal(validAction({ action: "fact", fact: 7 }), null);
  assert.equal(validAction(null), null);
  assert.equal(fromQuery("?action=file&file=../etc"), null);
  // Extra parameters are dropped, not passed along.
  assert.deepEqual(fromQuery(`?action=fact&fact=${F}&then=retract`), { action: "fact", fact: F });
});

test("a served fact must verify and hash to the id asked for", async () => {
  const f = await signFact(key, { type: "product", at: "2026-10-31T12:00:00Z", body: { brand: "Acme", model: "X1" } });
  const id = await factId(f);
  const served = { id, cursor: "01", folded: true, hidden: false, retracted: false, fact: f };
  assert.equal((await checkServedFact(JSON.parse(JSON.stringify(served)), id)).fact?.author, f.author);
  await assert.rejects(checkServedFact({ ...served, fact: { ...f, body: { brand: "Acme", model: "X2" } } }, id), /signature/);
  const other = await signFact(key, { type: "product", at: "2026-10-31T12:00:00Z", body: { brand: "Acme", model: "X2" } });
  await assert.rejects(checkServedFact({ ...served, fact: other }, id), /hashes to/);
  await assert.rejects(checkServedFact({ ...served, id: F }, id), /different fact/);
  assert.equal((await checkServedFact({ ...served, hidden: true, fact: null }, id)).fact, null);
});

test("body summaries are short", () => {
  const lines = summarizeBody({ url: "https://x/" + "y".repeat(200), kind: "mirror", n: 3 });
  assert.equal(lines.length, 3);
  assert.ok(lines[0].length <= 96 && lines[0].endsWith("…"));
  assert.equal(lines[2], "n: 3");
});
