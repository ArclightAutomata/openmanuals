// node --test src/rangedb/rangedb.test.ts
// Snapshot lookups over (simulated) HTTP Range requests: hashing, page
// verification, the SQLite VFS, the lookup queries, and manifest signatures.
import test from "node:test";
import assert from "node:assert/strict";
import sqlite3InitModule from "@sqlite.org/sqlite-wasm";
import { sha256, sha256Hex } from "./sha256.ts";
import { IntegrityError, PageReader, type FetchRange, type SnapshotRef } from "./pages.ts";
import { installRangeVfs, VFS_NAME } from "./vfs.ts";
import { lookup, manualsForUrl, parseFileRef } from "./lookup.ts";
import { fetchManifest } from "./manifest.ts";
import { fingerprint } from "../core/fingerprint.ts";

const hexOf = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

test("sha256 matches WebCrypto at block boundaries and beyond", async () => {
  for (const n of [0, 1, 55, 56, 63, 64, 65, 119, 120, 1000, 16384, 70001]) {
    const data = Uint8Array.from({ length: n }, (_, i) => (i * 131 + n) & 255);
    const want = hexOf(new Uint8Array(await crypto.subtle.digest("SHA-256", data)));
    assert.equal(sha256Hex(data), want, `length ${n}`);
    assert.equal(sha256(data).length, 32);
  }
});

// The tables and columns the lookup reads, as openmanuals-ledger's build writes them.
const SCHEMA = `
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE manuals (
  id TEXT PRIMARY KEY, title TEXT NOT NULL, doc_type TEXT NOT NULL, language TEXT, year INTEGER,
  source TEXT, source_id TEXT, source_url TEXT, author TEXT NOT NULL, cursor TEXT NOT NULL,
  canonical_file TEXT, brand TEXT, model TEXT
) WITHOUT ROWID;
CREATE INDEX manuals_source_url ON manuals(source_url);
CREATE INDEX manuals_source ON manuals(source, source_id);
CREATE TABLE files (
  id TEXT PRIMARY KEY, sha256 TEXT, sha1 TEXT, md5 TEXT, size INTEGER, mime TEXT, pages INTEGER,
  author TEXT NOT NULL, cursor TEXT NOT NULL, derived_from TEXT, transform TEXT, tool TEXT, tool_version TEXT,
  report_weight REAL NOT NULL, flagged INTEGER NOT NULL, canonical_location TEXT
) WITHOUT ROWID;
CREATE TABLE manual_files (manual TEXT NOT NULL, file TEXT NOT NULL, role TEXT NOT NULL, PRIMARY KEY (manual, file, role)) WITHOUT ROWID;
CREATE INDEX manual_files_file ON manual_files(file);
CREATE TABLE locations (
  id TEXT PRIMARY KEY, file TEXT NOT NULL, url TEXT NOT NULL, host TEXT NOT NULL, kind TEXT NOT NULL,
  status TEXT NOT NULL, verified_at TEXT, final_url TEXT, ia_identifier TEXT, ia_filename TEXT,
  author TEXT NOT NULL, cursor TEXT NOT NULL, report_weight REAL NOT NULL, flagged INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX locations_file ON locations(file);
CREATE INDEX locations_url ON locations(url);
`;
const A = "A".repeat(26);
const F1 = "1".repeat(64), F2 = "2".repeat(64), S1 = "sha1:" + "a".repeat(40);
const L = (n: string) => "sha256:" + n.repeat(64);

const sqlite3 = await sqlite3InitModule();
const vfs = installRangeVfs(sqlite3);

/** A snapshot built like the server builds one, padded with filler rows so it spans many pages. */
function buildSnapshot(): Uint8Array {
  const db = new sqlite3.oo1.DB(":memory:");
  db.exec("PRAGMA page_size = 4096; VACUUM;");
  db.exec(SCHEMA);
  db.exec({ sql: "INSERT INTO meta VALUES ('head', ?)", bind: ["01M5PNH70A7FSDC7KMA1ZE7QVB"] });
  const man = "INSERT INTO manuals VALUES (?,?,?,NULL,NULL,?,?,?,'K',?,?,?,?)";
  db.exec({ sql: man, bind: ["01ARZ3NDEKTSV4RRFFQ69G5FAV", "JVC AV-2168TEE", "service", "manualslib", "331384", "https://www.manualslib.com/manual/331384/Jvc-Av-2168tee.html", "C1", F2, "JVC", "AV-2168TEE"] });
  db.exec({ sql: man, bind: ["01BX5ZZKBKACTAV9WEVGEMMVRZ", "Sony KV", "service", "elektrotanya", "sony_kv-1400,sm.pdf", "https://elektrotanya.com/sony_kv-1400,sm.pdf/download.html", "C2", null, "Sony", "KV-1400"] });
  for (let i = 0; i < 3000; i++) db.exec({ sql: man, bind: [`01C${String(i).padStart(23, "0")}`, `Filler manual number ${i} `.repeat(3), "user", "manualslib", String(100000 + i), `https://www.manualslib.com/manual/${100000 + i}/Filler.html`, "C3", null, "Brand", `M${i}`] });
  const file = "INSERT INTO files VALUES (?,?,NULL,NULL,?,'application/pdf',NULL,'K','C',?,?,NULL,?,0.0,0,?)";
  db.exec({ sql: file, bind: [F1, F1, 4, null, null, null, L("b")] });
  db.exec({ sql: file, bind: [F2, F2, 3, F1, "watermark-stripped", "om-strip/2", L("c")] });
  db.exec({ sql: file, bind: [S1, null, 9, null, null, null, null] });
  // A held-back file (risky content): attached, but never offered.
  db.exec({ sql: "INSERT INTO files VALUES (?,?,NULL,NULL,1,'application/pdf',NULL,'K','C',NULL,NULL,NULL,NULL,0.0,1,?)", bind: ["3".repeat(64), "3".repeat(64), L("g")] });
  db.exec({ sql: "INSERT INTO manual_files VALUES (?,?,'primary')", bind: ["01ARZ3NDEKTSV4RRFFQ69G5FAV", "3".repeat(64)] });
  for (const [m, f] of [["01ARZ3NDEKTSV4RRFFQ69G5FAV", F1], ["01ARZ3NDEKTSV4RRFFQ69G5FAV", F2], ["01BX5ZZKBKACTAV9WEVGEMMVRZ", S1]]) db.exec({ sql: "INSERT INTO manual_files VALUES (?,?,'primary')", bind: [m, f] });
  const loc = "INSERT INTO locations VALUES (?,?,?,?,?,?,?,NULL,?,NULL,?,?,0.0,?)";
  db.exec({ sql: loc, bind: [L("b"), F1, "https://archive.org/download/x/a.pdf", "archive.org", "archive", "verified", "2026-10-01T00:00:00Z", "x", "K", "C5", 0] });
  db.exec({ sql: loc, bind: [L("c"), F2, "https://mirror.example.org/b.pdf", "mirror.example.org", "mirror", "verified", "2026-10-02T00:00:00Z", null, "K", "C9", 0] });
  db.exec({ sql: loc, bind: [L("d"), F2, "https://archive.org/download/y/b.pdf", "archive.org", "archive", "verified", "2026-10-03T00:00:00Z", "y", "K", "C1", 0] });
  db.exec({ sql: loc, bind: [L("e"), F2, "https://bad.example.org/b.pdf", "bad.example.org", "mirror", "verified", null, null, "K", "C0", 1] });
  db.exec({ sql: loc, bind: [L("f"), S1, "https://www.manualsbase.com/manual/7/sony/", "www.manualsbase.com", "origin", "origin", null, null, "K", "C7", 0] });
  db.exec("VACUUM"); // contiguous tables, like a published snapshot
  const bytes = sqlite3.capi.sqlite3_js_db_export(db.pointer!) as Uint8Array;
  db.close();
  return bytes;
}

/** What the server publishes alongside it: page hashes and their groups. */
function publish(bytes: Uint8Array, pageSize = 4096, group = 128): { ref: SnapshotRef; hashes: Uint8Array } {
  const count = bytes.length / pageSize;
  const hashes = new Uint8Array(count * 32);
  for (let i = 0; i < count; i++) hashes.set(sha256(bytes.subarray(i * pageSize, (i + 1) * pageSize)), i * 32);
  const groups: string[] = [];
  for (let g = 0; g < Math.ceil(count / group); g++) groups.push(sha256Hex(hashes.subarray(g * group * 32, Math.min((g + 1) * group, count) * 32)));
  return { ref: { base: "https://mirror.test/db/", version: "v1", file: "v1.db", size: bytes.length, pages: { file: "v1.pages", page_size: pageSize, count, group, groups } }, hashes };
}

const snapshot = buildSnapshot();
const { ref, hashes } = publish(snapshot);

function server(db: Uint8Array, pages: Uint8Array, log: { url: string; start: number; end: number }[] = []): FetchRange {
  return (url, start, end) => {
    log.push({ url, start, end });
    const src = url.endsWith(".db") ? db : url.endsWith(".pages") ? pages : null;
    if (!src) throw new Error("404 " + url);
    return src.slice(start, end);
  };
}

let n = 0;
function openDb(fetchRange: FetchRange, r: SnapshotRef = ref) {
  const reader = new PageReader(r, fetchRange, sha256Hex);
  const name = `t${n++}`;
  vfs.register(name, reader);
  return { reader, db: new sqlite3.oo1.DB(`file:${name}?vfs=${VFS_NAME}&immutable=1&mode=ro`, "r") };
}

test("the snapshot spans many pages", () => {
  assert.ok(ref.pages.count > 128, `${ref.pages.count} pages, so several hash groups`);
});

test("lookups by page URL, by source id, by origin copy and by file", () => {
  const { db, reader } = openDb(server(snapshot, hashes));
  const r = lookup(db, "https://om.test", { page: { url: "https://www.manualslib.com/manual/331384/Jvc-Av-2168tee.html?page=2#p", source: "manualslib", sourceIds: ["331384"], legacy: ["manualslib-id-331384"] } });
  assert.equal(r.known, true);
  assert.equal((r.manual as { url: string }).url, "https://om.test/manual/01ARZ3NDEKTSV4RRFFQ69G5FAV");
  assert.deepEqual(r.legacy_identifiers, ["manualslib-id-331384"]);
  assert.deepEqual(r.files.map((f) => f!.id), [F1, F2], "the held-back file is left out");
  const stripped = r.files[1]!;
  assert.equal(stripped.canonical, true);
  assert.deepEqual(stripped.copies.map((c) => c.id), [L("c"), L("d")], "canonical copy first, then by cursor; flagged copy hidden");
  // Elektrotanya: the comma spelling is found from the %2C URL through the decoded source id.
  const e = manualsForUrl(db, { url: "https://elektrotanya.com/sony_kv-1400%2Csm.pdf/download.html", source: "elektrotanya", sourceIds: ["sony_kv-1400%2Csm.pdf", "sony_kv-1400,sm.pdf"], legacy: [] });
  assert.deepEqual(e, ["01BX5ZZKBKACTAV9WEVGEMMVRZ"]);
  // A site we don't parse: matched through its origin location.
  assert.deepEqual(manualsForUrl(db, { url: "https://www.manualsbase.com/manual/7/sony/#top", legacy: [] }), ["01BX5ZZKBKACTAV9WEVGEMMVRZ"]);
  const f = lookup(db, "https://om.test", { file: "sha1:" + "A".repeat(40) });
  assert.equal(f.known, true);
  assert.equal((f.manual as { id: string }).id, "01BX5ZZKBKACTAV9WEVGEMMVRZ");
  assert.equal(lookup(db, "x", { page: { url: "https://www.manualslib.com/manual/1/Nope.html", source: "manualslib", sourceIds: ["1"], legacy: [] } }).known, false);
  assert.equal(parseFileRef(" " + "AB".repeat(32)), "ab".repeat(32));
  // Index lookups read a handful of pages, not the table.
  assert.ok(reader.stats.pagesFetched < ref.pages.count / 4, `${reader.stats.pagesFetched} of ${ref.pages.count} pages`);
  db.close();
});

test("random reads fetch single pages; sequential scans read ahead", () => {
  const log: { url: string; start: number; end: number }[] = [];
  const { db } = openDb(server(snapshot, hashes, log));
  db.exec("SELECT count(*) FROM manuals WHERE title LIKE '%999%'"); // full scan
  const dbReads = log.filter((l) => l.url.endsWith(".db"));
  assert.ok(dbReads.some((l) => l.end - l.start >= 8 * 4096), "a scan grows its requests");
  assert.ok(dbReads.length < ref.pages.count / 4, `${dbReads.length} requests for ${ref.pages.count} pages`);
  const hashReads = log.filter((l) => l.url.endsWith(".pages"));
  assert.ok(hashReads.length <= Math.ceil(ref.pages.groups.length / 16), "page hashes come in 64 KiB chunks");
  db.close();
});

test("a tampered page or hash list is refused", () => {
  const bad = snapshot.slice();
  bad[ref.pages.page_size * (ref.pages.count - 2) + 100] ^= 1;
  const { db } = openDb(server(bad, hashes));
  // integrity_check reads every page; an unreadable one surfaces as an I/O
  // error or as a report row, never as "ok".
  let refused = false;
  try { refused = (db.selectValues("PRAGMA integrity_check") as string[]).join(" ") !== "ok"; } catch { refused = true; }
  assert.ok(refused, "tampered page must not read back");
  db.close();
  const badHeader = snapshot.slice();
  badHeader[300] ^= 1;
  assert.throws(() => openDb(server(badHeader, hashes)).db.exec("SELECT count(*) FROM manuals"));
  const badHashes = hashes.slice();
  badHashes[5] ^= 1;
  assert.throws(() => openDb(server(snapshot, badHashes)), /hash group 0|disk I\/O|SQLITE_IOERR|unable/i);
  assert.throws(() => new PageReader({ ...ref, size: ref.size + 1 }, server(snapshot, hashes), sha256Hex), IntegrityError);
  // A mirror that sends the wrong amount of data.
  const short: FetchRange = (u, s, e) => server(snapshot, hashes)(u, s, Math.max(s, e - 1));
  assert.throws(() => openDb(short));
});

test("manifests must be signed by the pinned server key", async () => {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
  const key = { kty: "OKP", crv: "Ed25519", x: jwk.x! };
  const fp = await fingerprint(key);
  const manifest = { version: 1, server: fp, server_key: key, latest: { version: "v1", head: "h", file: "v1.db", sha256: "", size: ref.size, pages: ref.pages, tables: {} } };
  const body = new TextEncoder().encode(JSON.stringify(manifest));
  const sigFor = async (b: Uint8Array) => {
    const s = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, new TextEncoder().encode(sha256Hex(b))));
    return btoa(String.fromCharCode(...s)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const sig = await sigFor(body);
  const mirror = (b: Uint8Array, s: string) => (async (u: string | URL | Request) =>
    String(u).endsWith("manifest.json") ? new Response(b as unknown as BodyInit) : String(u).endsWith(".sig") ? new Response(s) : new Response("", { status: 404 })) as typeof fetch;
  const fpSync = () => fp;
  const ok = await fetchManifest("https://m.test/db/", fp, fpSync, mirror(body, sig));
  assert.equal(ok.ref.version, "v1");
  assert.equal(ok.ref.base, "https://m.test/db/");
  await assert.rejects(fetchManifest("https://m.test/db/", "B".repeat(26), fpSync, mirror(body, sig)), /different server key/);
  const forged = new TextEncoder().encode(JSON.stringify({ ...manifest, latest: { ...manifest.latest, version: "v2" } }));
  await assert.rejects(fetchManifest("https://m.test/db/", fp, fpSync, mirror(forged, sig)), /bad manifest signature/);
  await assert.rejects(fetchManifest("https://m.test/db/", fp, fpSync, (async () => new Response("", { status: 404 })) as typeof fetch), /no manifest/);
});
