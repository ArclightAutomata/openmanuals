// node --test src/core/passkey.test.ts — passkey wrapping with a fake PRF output (no WebAuthn).
import test from "node:test";
import assert from "node:assert/strict";
import { backupOf, createKey, importBackup, backupWraps, withWraps, signRaw, type KeyBackup, type Protect } from "./keys.ts";
import { keyWrapMessage, mergeWraps, PasskeyMismatchError, unwrapPrivateKey, wrapPrivateKey, type KeyWrap } from "./passkey.ts";
import { hex, utf8 } from "./b64.ts";

const prfA = new Uint8Array(32).fill(7);
const prfB = new Uint8Array(32).fill(9);
const protectWith = (prf: Uint8Array, credential: string): Protect => async (k, info) => [await wrapPrivateKey(k, prf, { ...info, credential, rp: "chrome-extension://test" })];

async function sameKey(a: Parameters<typeof signRaw>[0], b: Parameters<typeof signRaw>[0]) {
  const msg = utf8.encode("same key?");
  assert.equal(hex(await signRaw(a, msg)), hex(await signRaw(b, msg)));
}

test("wrap and unwrap round trip: same fingerprint, non-extractable", async () => {
  const { record, backup, wraps } = await createKey("pw", { iterations: 1000, protect: protectWith(prfA, "Y3JlZC1h") });
  assert.equal(wraps.length, 1);
  const w = JSON.parse(JSON.stringify(wraps[0])) as KeyWrap; // as stored on the server
  assert.equal(w.fingerprint, record.fingerprint);
  assert.equal(w.credential, "Y3JlZC1h");
  assert.equal(backup.v, 2);
  assert.deepEqual(backup.wraps, wraps);
  const restored = await unwrapPrivateKey(w, prfA);
  assert.equal(restored.fingerprint, record.fingerprint);
  assert.equal(restored.reason, "passkey");
  assert.equal(restored.privateKey.extractable, false);
  await assert.rejects(crypto.subtle.exportKey("pkcs8", restored.privateKey));
  await sameKey(record, restored);
});

test("a different passkey's PRF, or a tampered wrap, fails loudly", async () => {
  const { wraps } = await createKey("pw", { iterations: 1000, protect: protectWith(prfA, "Y3JlZC1h") });
  await assert.rejects(unwrapPrivateKey(wraps[0], prfB), PasskeyMismatchError);
  // The AAD binds the credential id and the fingerprint.
  await assert.rejects(unwrapPrivateKey({ ...wraps[0], credential: "b3RoZXI" }, prfA), PasskeyMismatchError);
  const other = (await createKey("pw", { iterations: 1000 })).record;
  await assert.rejects(unwrapPrivateKey({ ...wraps[0], publicJwk: other.publicJwk }, prfA), /fingerprint mismatch/);
  await assert.rejects(unwrapPrivateKey({ ...wraps[0], publicJwk: other.publicJwk, fingerprint: other.fingerprint }, prfA), PasskeyMismatchError);
  await assert.rejects(unwrapPrivateKey({ ...wraps[0], format: "nope" } as unknown as KeyWrap, prfA), /not an OpenManuals key wrap/);
});

test("a failing passkey still creates the key with its backup", async () => {
  const r = await createKey("pw", { iterations: 1000, protect: async () => { throw new Error("cancelled"); } });
  assert.equal(r.protectError?.message, "cancelled");
  assert.deepEqual(r.wraps, []);
  assert.equal((await importBackup(r.backup, "pw")).fingerprint, r.record.fingerprint);
});

test("passkey only: no backup file, the wrap alone restores the key", async () => {
  const r = await createKey(null, { iterations: 1000, protect: protectWith(prfA, "Y3JlZC1h") });
  assert.equal(r.backup, null);
  assert.equal(r.wraps.length, 1);
  await sameKey(r.record, await unwrapPrivateKey(r.wraps[0], prfA));
});

test("a backup file made later, from a passkey-unlocked copy", async () => {
  const { record, wraps } = await createKey(null, { iterations: 1000, protect: protectWith(prfA, "Y3JlZC1h") });
  await assert.rejects(backupOf(record, "pw", wraps), /isn't extractable/);
  const unlocked = await unwrapPrivateKey(wraps[0], prfA, true);
  const b = await backupOf({ ...unlocked, createdAt: record.createdAt }, "later pw", wraps, { iterations: 1000 }); // as manage.ts does
  assert.equal(b.v, 2);
  assert.equal(b.fingerprint, record.fingerprint);
  assert.equal(b.createdAt, record.createdAt);
  assert.deepEqual(backupWraps(b).map((w) => w.credential), ["Y3JlZC1h"]);
  const imported = await importBackup(JSON.parse(JSON.stringify(b)), "later pw");
  assert.equal(imported.privateKey.extractable, false);
  await sameKey(record, imported);
  await assert.rejects(importBackup(b, "wrong"), /wrong passphrase/);
});

test("a backup file without a passphrase holds the key in the clear", async () => {
  const { record, wraps } = await createKey(null, { iterations: 1000, protect: protectWith(prfA, "Y3JlZC1h") });
  const unlocked = await unwrapPrivateKey(wraps[0], prfA, true);
  const b = await backupOf({ ...unlocked, createdAt: record.createdAt }, "", wraps);
  assert.equal(b.kdf, undefined);
  assert.equal(b.ciphertext, undefined);
  assert.equal(typeof b.privateJwk?.d, "string");
  assert.deepEqual(backupWraps(b).map((w) => w.credential), ["Y3JlZC1h"]);
  await sameKey(record, await importBackup(JSON.parse(JSON.stringify(b)), ""));
  await assert.rejects(importBackup({ ...b, privateJwk: undefined }, ""), /not an OpenManuals key backup/);
});

test("backup v2 round trip, and v1 still imports", async () => {
  const { record, backup } = await createKey("pw", { iterations: 1000, protect: protectWith(prfA, "Y3JlZC1h") });
  const v2 = JSON.parse(JSON.stringify(backup)) as KeyBackup;
  const imported = await importBackup(v2, "pw");
  assert.equal(imported.fingerprint, record.fingerprint);
  assert.equal(imported.privateKey.extractable, false);
  assert.equal(backupWraps(v2).length, 1);
  // The wraps in the file restore the key without the passphrase.
  await sameKey(record, await unwrapPrivateKey(backupWraps(v2)[0], prfA));

  const v1 = { ...v2, v: 1 } as KeyBackup;
  delete v1.wraps;
  assert.equal((await importBackup(v1, "pw")).fingerprint, record.fingerprint);
  assert.deepEqual(backupWraps(v1), []);
  await assert.rejects(importBackup({ ...v2, v: 3 } as unknown as KeyBackup, "pw"), /not an OpenManuals key backup/);
});

test("adding a passkey later: from the backup file (extractable once) or from an existing passkey", async () => {
  const { record, backup } = await createKey("pw", { iterations: 1000 });
  // via the backup file
  const src = await importBackup(backup, "pw", { extractable: true });
  assert.equal(src.privateKey.extractable, true);
  const wA = await wrapPrivateKey(src.privateKey, prfA, { fingerprint: record.fingerprint, publicJwk: record.publicJwk, credential: "Y3JlZC1h", rp: "x" });
  const updated = withWraps(backup, [wA]);
  assert.equal(updated.v, 2);
  assert.equal(updated.ciphertext, backup.ciphertext, "same encrypted key, no passphrase needed");
  // via the first passkey, unwrapped extractable just for this
  const fromA = await unwrapPrivateKey(wA, prfA, true);
  const wB = await wrapPrivateKey(fromA.privateKey, prfB, { fingerprint: record.fingerprint, publicJwk: record.publicJwk, credential: "Y3JlZC1i", rp: "x" });
  const both = withWraps(updated, [wB]);
  assert.deepEqual(backupWraps(both).map((w) => w.credential).sort(), ["Y3JlZC1h", "Y3JlZC1i"]);
  await sameKey(record, await unwrapPrivateKey(wB, prfB));
  // wraps for another key are not added to this backup
  const stranger = (await createKey("pw", { iterations: 1000, protect: protectWith(prfA, "c3RyYW5nZXI") })).wraps;
  assert.equal(backupWraps(withWraps(both, stranger)).length, 2);
});

test("mergeWraps keeps one wrap per credential, newest first wins", async () => {
  const { wraps } = await createKey("pw", { iterations: 1000, protect: protectWith(prfA, "Y3JlZC1h") });
  const newer = { ...wraps[0], createdAt: "2999-01-01T00:00:00.000Z", iv: "AAAAAAAAAAAAAAAA" };
  assert.deepEqual(mergeWraps(wraps, [newer], [wraps[0]]), [newer]);
  assert.deepEqual(mergeWraps([{ bogus: true } as unknown as KeyWrap]), []);
});

test("key-wrap request message matches the server's format", async () => {
  const m = utf8.decode(await keyWrapMessage("PUT", "AAAAAAAAAAAAAAAAAAAAAAAAAA", "Y3JlZC1h", "w", "2026-10-31T12:00:00.000Z"));
  // sha256("w")
  assert.equal(m, "openmanuals key-wrap v1\nPUT\nAAAAAAAAAAAAAAAAAAAAAAAAAA\nY3JlZC1h\n50e721e49c013f00c62cf59f2163542a9d8df02464efeb615d31051b0fddc326\n2026-10-31T12:00:00.000Z");
  assert.equal(utf8.decode(await keyWrapMessage("DELETE", "F", "C", null, "T")), "openmanuals key-wrap v1\nDELETE\nF\nC\n\nT");
});
