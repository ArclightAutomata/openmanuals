// node --test src/core/facts.test.ts — the TS signer against openmanuals-core's vectors,
// through the real openmanuals-wasm module.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { ensureWasm } from "./wasm.ts";
import { keyFromEd25519Seed } from "./keys.ts";
import { hexToBytes } from "./b64.ts";
import { signFact, verifyFact, factId, type Fact } from "./facts.ts";
import { signProfile, decodeProfile, aspeUri } from "./asp.ts";

const root = new URL("../../../", import.meta.url);
const vectors = JSON.parse(readFileSync(new URL("crates/openmanuals-core/vectors/vectors.json", root), "utf8"));
const wasmBytes = readFileSync(new URL("extension/vendor/openmanuals-wasm/openmanuals_wasm_bg.wasm", root));
const om = await ensureWasm(wasmBytes);

const edKey = await keyFromEd25519Seed(hexToBytes(vectors.keys[0].seed_hex), vectors.keys[0].jwk.x);

test("Ed25519 vector fact: canonical, id and signature are byte-identical", async () => {
  const v = vectors.facts.find((f: { alg: string }) => f.alg === "Ed25519");
  const f = v.fact as Fact;
  const signed = await signFact(edKey, { type: f.type, at: f.at, body: f.body });
  assert.equal(om.fact_canonical(JSON.stringify(signed)), v.canonical);
  assert.equal(await factId(signed), v.id);
  assert.deepEqual(signed, f);
  assert.equal(await verifyFact(signed), v.id);
});

test("openmanuals-core verifies every vector fact and rejects tampering", async () => {
  const all = vectors.facts.map((f: { fact: Fact }) => f.fact);
  for (const f of all) {
    const id = await verifyFact(f);
    assert.equal(id, om.fact_id(JSON.stringify(f)));
    const bad = structuredClone(f);
    bad.body.size = 99;
    await assert.rejects(verifyFact(bad));
    const wrongAuthor = structuredClone(f);
    wrongAuthor.author = "QPRGVPJNWDXH4ESK2RYDTZJLTE";
    await assert.rejects(verifyFact(wrongAuthor));
  }
});

test("profile JWS signed in TS equals the openmanuals-core vector and verifies", async () => {
  const p = vectors.profile;
  const dec = decodeProfile(p.jws);
  const jws = await signProfile(edKey, { name: dec.name, claims: dec.claims, description: dec.description });
  assert.equal(jws, p.jws);
  const verified = JSON.parse(om.verify_profile(jws));
  assert.equal(verified.fingerprint, p.fingerprint);
  assert.deepEqual(verified.claims, p.claims);
  assert.equal(aspeUri("openmanuals.org", p.fingerprint), p.aspe);
  assert.equal(om.aspe_uri("openmanuals.org", p.fingerprint), p.aspe);
});

test("identifiers, page parsing and product keys via wasm match the vectors", () => {
  for (const l of vectors.identifiers.legacy) assert.equal(om.legacy_identifier(l.source, l.source_id) ?? null, l.identifier);
  for (const u of vectors.identifiers.upload) assert.equal(om.upload_identifier(u.sha256, u.ulid), u.identifier);
  for (const p of vectors.identifiers.pages) assert.deepEqual(JSON.parse(om.parse_page_url(p.url) ?? "null"), p.page);
  for (const p of vectors.products) assert.equal(om.product_key(p.brand, p.model) ?? null, p.key);
  assert.equal(om.fingerprint(JSON.stringify(vectors.asp_spec_example.jwk)), vectors.asp_spec_example.fingerprint);
  assert.equal(om.sniff(new TextEncoder().encode("%PDF-1.4 ...")), "pdf");
  assert.equal(om.sniff(new TextEncoder().encode("<html>")), undefined);
  assert.equal(om.sniff(new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x14, 0, 0, 0])), undefined, "zip archives are refused");
  assert.equal(om.sniff(new Uint8Array([0x4d, 0x5a, 0x90, 0, 3, 0, 0, 0])), undefined, "executables are refused");
  assert.equal(om.canonical_json('{"b":1.0,"a":[true,null,"é"]}'), '{"a":[true,null,"é"],"b":1}');
});
