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

/** A zip with these files, stored (no compression), as any zip tool writes one. */
function storedZip(files: [string, Uint8Array][]): Uint8Array {
  const crc = (b: Uint8Array) => {
    let c = ~0;
    for (const x of b) { c ^= x; for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1)); }
    return ~c >>> 0;
  };
  const parts: number[] = [], central: number[] = [];
  const u16 = (a: number[], v: number) => a.push(v & 0xff, v >>> 8);
  const u32 = (a: number[], v: number) => { u16(a, v & 0xffff); u16(a, v >>> 16); };
  for (const [name, data] of files) {
    const n = new TextEncoder().encode(name), off = parts.length, c = crc(data);
    u32(parts, 0x04034b50); u16(parts, 20); u16(parts, 0); u16(parts, 0); u32(parts, 0); u32(parts, c); u32(parts, data.length); u32(parts, data.length); u16(parts, n.length); u16(parts, 0);
    parts.push(...n, ...data);
    u32(central, 0x02014b50); u16(central, 20); u16(central, 20); u16(central, 0); u16(central, 0); u32(central, 0); u32(central, c); u32(central, data.length); u32(central, data.length);
    u16(central, n.length); u16(central, 0); u16(central, 0); u16(central, 0); u16(central, 0); u32(central, 0); u32(central, off); central.push(...n);
  }
  const end: number[] = [];
  u32(end, 0x06054b50); u16(end, 0); u16(end, 0); u16(end, files.length); u16(end, files.length); u32(end, central.length); u32(end, parts.length); u16(end, 0);
  return new Uint8Array([...parts, ...central, ...end]);
}

test("a zip is a document only when it holds nothing but PDF and DjVu files", () => {
  const pdf = new TextEncoder().encode("%PDF-1.4\n%%EOF\n");
  const docs = storedZip([["q2500/Seite 1.pdf", pdf], ["q2500/board/88175h_PCB.pdf", pdf]]);
  assert.equal(om.sniff(docs), "zip");
  assert.deepEqual(JSON.parse(om.zip_documents(docs)).map((d: { name: string; type: string }) => [d.name, d.type]), [["q2500/Seite 1.pdf", "pdf"], ["q2500/board/88175h_PCB.pdf", "pdf"]]);
  assert.throws(() => om.zip_documents(storedZip([["a.pdf", pdf], ["setup.exe", new Uint8Array([0x4d, 0x5a, 0x90, 0])]])), /setup\.exe isn't a PDF or DjVu/);
});

test("identifiers, page parsing and product keys via wasm match the vectors", () => {
  for (const l of vectors.identifiers.legacy) assert.equal(om.legacy_identifier(l.source, l.source_id) ?? null, l.identifier);
  for (const u of vectors.identifiers.upload) assert.equal(om.upload_identifier(u.sha256, u.ulid), u.identifier);
  for (const p of vectors.identifiers.pages) assert.deepEqual(JSON.parse(om.parse_page_url(p.url) ?? "null"), p.page);
  for (const p of vectors.products) assert.equal(om.product_key(p.brand, p.model) ?? null, p.key);
  assert.equal(om.fingerprint(JSON.stringify(vectors.asp_spec_example.jwk)), vectors.asp_spec_example.fingerprint);
  assert.equal(om.sniff(new TextEncoder().encode("%PDF-1.4 ...")), "pdf");
  assert.equal(om.sniff(new TextEncoder().encode("<html>")), undefined);
  assert.equal(om.sniff(new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x14, 0, 0, 0])), "zip", "a zip, a document only if zip_documents accepts it");
  assert.equal(om.sniff(new Uint8Array([0x4d, 0x5a, 0x90, 0, 3, 0, 0, 0])), undefined, "executables are refused");
  assert.equal(om.canonical_json('{"b":1.0,"a":[true,null,"é"]}'), '{"a":[true,null,"é"],"b":1}');
});
