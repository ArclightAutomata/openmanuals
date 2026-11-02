// node --test src/background/filter.test.ts
// The local lookup filter: fetch/cache/revalidate, and how it gates
// GET /api/lookup in resolvePage (miss → no request; hit, no filter, corrupt
// filter, stale filter, or a page this browser submitted → request).
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const root = new URL("../../../", import.meta.url);
const wasmBytes = readFileSync(new URL("extension/vendor/openmanuals-wasm/openmanuals_wasm_bg.wasm", root));

const mem: Record<string, Record<string, unknown>> = { sync: {}, local: {}, session: {} };
const store = (area: string) => ({
  get: async (q: unknown) => {
    const m = mem[area];
    if (typeof q === "string") return q in m ? { [q]: structuredClone(m[q]) } : {};
    if (Array.isArray(q)) return Object.fromEntries(q.filter((k) => k in m).map((k) => [k, structuredClone(m[k])]));
    return { ...(q as object), ...Object.fromEntries(Object.entries(m).filter(([k]) => k in (q as object))) };
  },
  set: async (o: Record<string, unknown>) => { Object.assign(mem[area], structuredClone(o)); },
  remove: async (k: string | string[]) => { for (const key of ([] as string[]).concat(k)) delete mem[area][key]; },
});
const noop = { addListener() {} };
(globalThis as unknown as { chrome: unknown }).chrome = {
  runtime: { getManifest: () => ({ version: "9.9.9" }), getURL: (p: string) => "chrome-extension://om/" + p, onMessage: noop, onConnect: noop, sendMessage: async () => null },
  storage: { sync: store("sync"), local: store("local"), session: store("session"), onChanged: noop },
  tabs: { sendMessage: async () => {} },
  alarms: { create: async () => {}, onAlarm: noop },
};

// ---- fetch stub ----------------------------------------------------------------------
const API = "http://localhost:8000";
const calls: { url: string; headers: Record<string, string> }[] = [];
let filterResponse: () => Response = () => new Response("not found", { status: 404 });
globalThis.fetch = (async (input: string | URL | Request, init: RequestInit = {}) => {
  const u = String(input);
  calls.push({ url: u, headers: { ...((init.headers ?? {}) as Record<string, string>) } });
  const json = (o: unknown, status = 200) => new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json" } });
  if (u === "chrome-extension://om/openmanuals_wasm_bg.wasm") return new Response(wasmBytes, { headers: { "content-type": "application/wasm" } });
  if (u === API + "/db/lookup-filter.bin") return filterResponse();
  if (u.startsWith(API + "/api/lookup")) return json({ known: false, manual: null, files: [], legacy_identifiers: [] });
  if (u === API + "/api/facts") { const n = (JSON.parse(String(init.body)) as unknown[]).length; return json({ cursor: "c", accepted: Array.from({ length: n }, (_, i) => `sha256:${i}`), duplicate: [], rejected: [] }, 202); }
  if (u.startsWith("https://archive.org/services/check_identifier.php")) return json({ type: "success", code: "available" });
  throw new Error("unexpected fetch " + u);
}) as typeof fetch;

const { initWasm, resolvePage } = await import("./lookup.ts");
const filter = await import("./filter.ts");
const { useKeyStore } = await import("./identity.ts");
const { MemoryKeyStore } = await import("../core/keys.ts");
const { enqueue } = await import("./outbox.ts");
const { getSettings } = await import("../core/config.ts");
const { ensureWasm } = await import("../core/wasm.ts");
useKeyStore(new MemoryKeyStore());
await initWasm();
const om = await ensureWasm();

const page = (n: number) => `https://www.manualslib.com/manual/${n}/Page-${n}.html`;
const lookups = (url: string) => calls.filter((c) => c.url === `${API}/api/lookup?url=${encodeURIComponent(url)}`).length;
const filterFetches = () => calls.filter((c) => c.url === API + "/db/lookup-filter.bin");
const known = om.build_lookup_filter(["src:manualslib:100", "src:elektrotanya:sony_kv-1400,sm.pdf"]);
const serve = (bytes: Uint8Array, etag = '"v1"') => { filterResponse = () => new Response(new Uint8Array(bytes), { status: 200, headers: { etag } }); };

async function fresh() {
  filter.resetFilterMemory();
  delete mem.local.lookupFilter;
  mem.session = {};
  await filter.refreshFilter(await getSettings());
}

test("no filter published (404): every page is looked up", async () => {
  filterResponse = () => new Response("nope", { status: 404 });
  await fresh();
  assert.equal(await filter.currentFilter(await getSettings()), null);
  await resolvePage(page(1));
  assert.equal(lookups(page(1)), 1);
});

test("filter miss: no lookup request; archive.org is asked only with the advanced setting on", async () => {
  serve(known);
  await fresh();
  const r = await resolvePage(page(2));
  assert.equal(lookups(page(2)), 0, "a miss never reaches the server");
  assert.equal(r!.known, false);
  assert.equal(r!.identifier, "manualslib-id-2");
  assert.ok(!calls.some((c) => c.url.includes("check_identifier")), "no live archive.org check by default");
  mem.sync.legacyCheck = true;
  try {
    await resolvePage(page(2));
    assert.ok(calls.some((c) => c.url.includes("check_identifier") && c.url.includes("manualslib-id-2")), "legacy probe runs when enabled");
  } finally {
    delete mem.sync.legacyCheck;
  }
});

test("filter hit: looked up (manual and download page, both elektrotanya spellings)", async () => {
  serve(known);
  await fresh();
  await resolvePage(page(100));
  assert.equal(lookups(page(100)), 1);
  const dl = "https://www.manualslib.com/download/100/Page-100.html";
  await resolvePage(dl);
  assert.equal(lookups(dl), 1);
  for (const u of ["https://elektrotanya.com/sony_kv-1400%2Csm.pdf/download.html", "https://elektrotanya.com/sony_kv-1400,sm.pdf/download.html"]) {
    await resolvePage(u);
    assert.equal(lookups(u), 1, u);
  }
});

test("corrupt or truncated filter: ignored, every page is looked up", async () => {
  for (const bad of [new TextEncoder().encode("<html>oops</html>"), known.subarray(0, known.length - 3)]) {
    serve(bad);
    await fresh();
    assert.equal(await filter.currentFilter(await getSettings()), null);
    const u = page(3000 + bad.length);
    await resolvePage(u);
    assert.equal(lookups(u), 1);
  }
});

test("cached across worker restarts, revalidated with If-None-Match, 304 keeps it", async () => {
  serve(known, '"abc"');
  await fresh();
  const stored = mem.local.lookupFilter as { b64: string; etag: string; nextCheck: number };
  assert.equal(stored.etag, '"abc"');
  // Worker restart: memory gone, storage kept, not due → no fetch.
  filter.resetFilterMemory();
  const before = filterFetches().length;
  assert.ok(await filter.currentFilter(await getSettings()));
  await filter.refreshIfStale(await getSettings());
  assert.equal(filterFetches().length, before, "not refetched within 6 h");
  // Due: conditional request, 304.
  filterResponse = () => new Response(null, { status: 304 });
  stored.nextCheck = 0;
  filter.resetFilterMemory();
  await filter.refreshIfStale(await getSettings());
  const last = filterFetches().at(-1)!;
  assert.equal(last.headers["If-None-Match"], '"abc"');
  const f = await filter.currentFilter(await getSettings());
  assert.ok(f && f.contains_page(page(100)) && !f.contains_page(page(4)));
});

test("network error keeps the cached filter; a filter not confirmed for days is not trusted", async () => {
  serve(known);
  await fresh();
  filterResponse = () => { throw new TypeError("offline"); };
  (mem.local.lookupFilter as { nextCheck: number }).nextCheck = 0;
  filter.resetFilterMemory();
  await filter.refreshIfStale(await getSettings());
  assert.ok(await filter.currentFilter(await getSettings()), "kept while offline");
  (mem.local.lookupFilter as { confirmedAt: number }).confirmedAt = Date.now() - filter.MAX_AGE_MS - 1000;
  filter.resetFilterMemory();
  assert.equal(await filter.currentFilter(await getSettings()), null);
  await resolvePage(page(5));
  assert.equal(lookups(page(5)), 1);
});

test("pages this browser just submitted are looked up even when the filter predates them", async () => {
  serve(known);
  await fresh();
  const mine = "https://www.manualslib.com/manual/4242/Jvc.html";
  await resolvePage(mine);
  assert.equal(lookups(mine), 0);
  await enqueue([
    { v: 1, type: "file", author: "A", at: "2026-10-30T00:00:00Z", body: { sha256: "a".repeat(64) } },
    { v: 1, type: "location", author: "A", at: "2026-10-30T00:00:00Z", body: { file: "a".repeat(64), url: mine, kind: "origin" } },
  ], "upload: test");
  mem.session = {};
  await resolvePage("https://www.manualslib.com/download/4242/Jvc.html");
  assert.equal(lookups("https://www.manualslib.com/download/4242/Jvc.html"), 1);
});

test("a different server: the old filter is not used", async () => {
  serve(known);
  await fresh();
  const other = { ...(await getSettings()), apiBase: "http://127.0.0.1:9" };
  filterResponse = () => new Response("x", { status: 404 });
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (i: string | URL | Request, init?: RequestInit) => (String(i).startsWith("http://127.0.0.1:9") ? new Response("no", { status: 404 }) : realFetch(i, init))) as typeof fetch;
  assert.equal(await filter.mayBeKnown(other, page(6)), true);
  globalThis.fetch = realFetch;
});
