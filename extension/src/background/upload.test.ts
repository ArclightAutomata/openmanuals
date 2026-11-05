// node --test src/background/upload.test.ts — the fact bundle an upload emits.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

// The pipeline modules reference chrome.* lazily; give them a minimal global.
(globalThis as unknown as { chrome: unknown }).chrome = { runtime: { getManifest: () => ({ version: "0.0.0" }), sendMessage: async () => null }, storage: { local: { get: async (d: unknown) => d, set: async () => {} }, session: { get: async () => ({}), set: async () => {} } }, alarms: { create: async () => {}, onAlarm: { addListener() {} } } };

const { buildBundle, safeFilename } = await import("./upload.ts");
const { ensureWasm } = await import("../core/wasm.ts");
const { keyFromEd25519Seed } = await import("../core/keys.ts");
const { signFacts, verifyFact } = await import("../core/facts.ts");
const { hexToBytes } = await import("../core/b64.ts");

const root = new URL("../../../", import.meta.url);
const vectors = JSON.parse(readFileSync(new URL("crates/openmanuals-core/vectors/vectors.json", root), "utf8"));
const om = await ensureWasm(readFileSync(new URL("extension/vendor/openmanuals-wasm/openmanuals_wasm_bg.wasm", root)));

const h = (seed: string) => ({ sha256: seed.repeat(64).slice(0, 64), sha1: seed.repeat(40).slice(0, 40), md5: seed.repeat(32).slice(0, 32), size: 1234, mime: "application/pdf" });
const job = {
  type: "begin" as const, filename: "av2168tee.pdf", contentType: "application/pdf", size: 1234,
  metadata: { title: "JVC AV-2168TEE Service Manual", description: "40 pages", products: [{ brand: "JVC", model: "AV-2168TEE" }, { brand: "JVC", model: "AV 2168/TEE" }, { brand: "JVC", model: "AV-2168TAE" }] },
  sourceInfo: { source: "manualslib", sourceId: "331384", sourceUrl: "https://www.manualslib.com/manual/331384/Jvc-Av-2168tee.html" },
  addCopy: false,
};

test("bundle for a stripped upload of a new manual", async () => {
  const facts = buildBundle({ job, original: h("a"), uploaded: h("b"), stripped: { changed: true, version: "om-strip-rs/1" }, identifier: "openmanuals-bbbbbbbbbbbbbbbb-01arz3ndektsv4rrffq69g5fav", filename: "av2168tee.pdf", manualId: null, productKey: (b, m) => om.product_key(b, m), at: "2026-10-23T18:00:00Z" });
  const types = facts.map((f) => f.type);
  assert.deepEqual(types, ["file", "location", "file", "derivation", "location", "manual", "product", "covers", "product", "covers", "manual_file", "manual_file"]);
  const covers = facts.filter((f) => f.type === "covers").map((f) => f.body.product);
  assert.deepEqual(covers, ["jvc|AV2168TEE", "jvc|AV2168TAE"]); // the spelling variant collapsed
  const archive = facts.find((f) => f.type === "location" && f.body.kind === "archive")!;
  assert.equal(archive.body.url, "https://archive.org/download/openmanuals-bbbbbbbbbbbbbbbb-01arz3ndektsv4rrffq69g5fav/av2168tee.pdf");
  assert.equal(archive.body.file, h("b").sha256);
  const deriv = facts.find((f) => f.type === "derivation")!;
  assert.deepEqual(deriv.body, { derived: h("b").sha256, source: h("a").sha256, transform: "watermark-stripped", tool: "om-strip", tool_version: "om-strip-rs/1" });
  const manual = facts.find((f) => f.type === "manual")!;
  assert.equal(manual.body.doc_type, "service");
  // The source page, so lookups and the per-site counts find it.
  assert.equal(manual.body.source, "manualslib");
  assert.equal(manual.body.source_id, "331384");
  assert.equal(manual.body.source_url, "https://www.manualslib.com/manual/331384/Jvc-Av-2168tee.html");
  assert.match(String(manual.body.id), /^[0-9A-HJKMNP-TV-Z]{26}$/);

  // Signed, every fact verifies with openmanuals-core and fits the size cap.
  const key = await keyFromEd25519Seed(hexToBytes(vectors.keys[0].seed_hex), vectors.keys[0].jwk.x);
  const signed = await signFacts(key, facts);
  for (const f of signed) {
    assert.equal(f.author, vectors.keys[0].fingerprint);
    await verifyFact(f);
    assert.ok(JSON.stringify(f).length < 16 * 1024);
  }
});

test("bundle for an unchanged file of a known manual, no upload", () => {
  const facts = buildBundle({ job, original: h("a"), uploaded: h("a"), stripped: { changed: false, version: "" }, identifier: null, filename: "x.pdf", manualId: "01ARZ3NDEKTSV4RRFFQ69G5FAV", productKey: (b, m) => om.product_key(b, m) });
  assert.deepEqual(facts.map((f) => f.type), ["file", "location", "manual_file"]);
  assert.equal(facts[2].body.manual, "01ARZ3NDEKTSV4RRFFQ69G5FAV");
});

test("safe filenames", () => {
  assert.equal(safeFilename("../x/y:z.pdf", "pdf"), "y_z.pdf");
  assert.equal(safeFilename("", "pdf"), "manual.pdf");
  assert.equal(safeFilename("sm", "zip"), "sm.zip");
});
