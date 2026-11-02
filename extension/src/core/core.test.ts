// node --test src/core/core.test.ts — primitives that need no wasm.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { md5Hex } from "./md5.ts";
import { b64url, b64urlDecode, base32, hex, hexToBytes, utf8 } from "./b64.ts";
import { ulid, ULID_RE } from "./ulid.ts";
import { fingerprint } from "./fingerprint.ts";
import { createKey, importBackup, keyFromEd25519Seed, signRaw } from "./keys.ts";
import { hashAll } from "./hash.ts";

const vectors = JSON.parse(readFileSync(new URL("../../../crates/openmanuals-core/vectors/vectors.json", import.meta.url), "utf8"));

test("md5 matches known digests", () => {
  assert.equal(md5Hex(utf8.encode("")), "d41d8cd98f00b204e9800998ecf8427e");
  assert.equal(md5Hex(utf8.encode("test")), "098f6bcd4621d373cade4e832627b4f6");
  assert.equal(md5Hex(utf8.encode("The quick brown fox jumps over the lazy dog")), "9e107d9d372bb6826bd81d3542a419d6");
  const big = new Uint8Array(1_000_003).fill(0x61);
  assert.equal(md5Hex(big), md5Hex(big)); // deterministic, and exercises multi-block + odd tail
});

test("hashAll reproduces the vector file fact", async () => {
  const h = await hashAll(utf8.encode("test"));
  const body = vectors.facts[0].fact.body;
  assert.equal(h.sha256, body.sha256);
  assert.equal(h.sha1, body.sha1);
  assert.equal(h.md5, body.md5);
  assert.equal(h.size, body.size);
});

test("base64url and base32 round trips", () => {
  const bytes = hexToBytes("00ff10a5b7c8");
  assert.equal(hex(b64urlDecode(b64url(bytes))), "00ff10a5b7c8");
  assert.equal(base32(utf8.encode("foobar")), "MZXW6YTBOI");
});

test("ulid shape", () => {
  const u = ulid();
  assert.match(u, ULID_RE);
  assert.notEqual(ulid(), u);
});

test("fingerprints match openmanuals-core vectors and the ASP spec example", async () => {
  for (const k of vectors.keys) assert.equal(await fingerprint(k.jwk), k.fingerprint);
  assert.equal(await fingerprint(vectors.asp_spec_example.jwk), vectors.asp_spec_example.fingerprint);
});

test("key creation: non-extractable key, backup round trip, wrong passphrase rejected", async () => {
  const { record, backup } = await createKey("correct horse", { iterations: 1000 });
  assert.equal(record.privateKey.extractable, false);
  assert.equal(backup.format, "om-key-backup");
  assert.equal(backup.fingerprint, record.fingerprint);
  const restored = await importBackup(JSON.parse(JSON.stringify(backup)), "correct horse");
  assert.equal(restored.fingerprint, record.fingerprint);
  assert.equal(restored.privateKey.extractable, false);
  await assert.rejects(importBackup(backup, "wrong"), /wrong passphrase/);
  // both keys sign for the same public key
  const msg = utf8.encode("hello");
  const s1 = await signRaw(record, msg), s2 = await signRaw(restored, msg);
  assert.equal(s1.length, 64);
  assert.equal(record.alg, "Ed25519", "new keys are always Ed25519");
  assert.equal(hex(s1), hex(s2));
});

test("a backup of any other key type is refused", async () => {
  const { backup } = await createKey("pw", { iterations: 1000 });
  const p256 = { ...backup, alg: "ES256" } as unknown as typeof backup;
  await assert.rejects(importBackup(p256, "pw"), /only Ed25519/);
});

test("seed import yields the vector key", async () => {
  const k = vectors.keys[0];
  const rec = await keyFromEd25519Seed(hexToBytes(k.seed_hex), k.jwk.x);
  assert.equal(rec.fingerprint, k.fingerprint);
});
