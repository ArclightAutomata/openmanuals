// node --test src/background/mirror.test.ts
// When the server is unreachable, resolvePage answers from a snapshot mirror
// (through the offscreen document), but only with a server key pinned earlier.
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
const sent: Record<string, unknown>[] = [];
let mirrorReply: unknown = null;
(globalThis as unknown as { chrome: unknown }).chrome = {
  runtime: {
    getManifest: () => ({ version: "9.9.9" }), getURL: (p: string) => "chrome-extension://om/" + p, onMessage: noop, onConnect: noop,
    getContexts: async () => [{ contextType: "OFFSCREEN_DOCUMENT" }],
    sendMessage: async (m: Record<string, unknown>) => { sent.push(m); return m.type === "offscreen:mirror" ? mirrorReply : null; },
  },
  offscreen: { createDocument: async () => {} },
  storage: { sync: store("sync"), local: store("local"), session: store("session"), onChanged: noop },
  tabs: { sendMessage: async () => {} },
  alarms: { create: async () => {}, onAlarm: noop },
};

const API = "http://localhost:8000";
let serverUp = false;
let serverKey: Record<string, string> = { kty: "OKP", crv: "Ed25519", x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" };
globalThis.fetch = (async (input: string | URL | Request) => {
  const u = String(input);
  const json = (o: unknown, status = 200) => new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json" } });
  if (u === "chrome-extension://om/openmanuals_wasm_bg.wasm") return new Response(wasmBytes, { headers: { "content-type": "application/wasm" } });
  if (u === API + "/db/lookup-filter.bin") return new Response("not found", { status: 404 });
  if (!serverUp && u.startsWith(API)) throw new TypeError("Failed to fetch");
  if (u.startsWith(API + "/api/lookup")) return json({ known: false, manual: null, files: [], legacy_identifiers: [] });
  if (u === API + "/api/server") return json({ server_key: serverKey });
  if (u.startsWith("https://archive.org/services/check_identifier.php")) return json({ type: "success", code: "available" });
  throw new Error("unexpected fetch " + u);
}) as typeof fetch;

const { initWasm, resolvePage, pageQuery } = await import("./lookup.ts");
const { pinServerKey, pinnedKey, mirrorBases } = await import("./mirror.ts");
const { getSettings, setSettings } = await import("../core/config.ts");
const { fingerprint } = await import("../core/fingerprint.ts");
await initWasm();

const PAGE = "https://www.manualslib.com/manual/331384/Jvc-Av-2168tee.html";
const known = { known: true, manual: { id: "01ARZ3NDEKTSV4RRFFQ69G5FAV", title: "JVC", url: API + "/manual/01ARZ3NDEKTSV4RRFFQ69G5FAV" }, legacy_identifiers: [],
  files: [{ id: "f".repeat(64), sha256: "f".repeat(64), canonical: true, size: 3, copies: [{ id: "sha256:" + "c".repeat(64), url: "https://archive.org/download/x/a.pdf", kind: "archive", host: "archive.org", status: "verified", author: "K", ia: { identifier: "x", filename: "a.pdf" } }] }] };

test("mirror bases: the server's /db/ first, then configured mirrors", async () => {
  await setSettings({ mirrors: "https://mirror.example.org/om\n  junk\nhttps://archive.org/download/openmanuals-snapshots/ " });
  assert.deepEqual(mirrorBases(await getSettings()), [API + "/db/", "https://mirror.example.org/om/", "https://archive.org/download/openmanuals-snapshots/"]);
});

test("page queries carry every spelling of the source id", () => {
  const q = pageQuery("https://elektrotanya.com/sony_kv-1400%2Csm.pdf/download.html");
  assert.equal(q.source, "elektrotanya");
  assert.deepEqual(q.sourceIds, ["sony_kv-1400%2Csm.pdf", "sony_kv-1400,sm.pdf"]);
  assert.deepEqual(pageQuery("https://example.com/x").sourceIds, []);
});

test("no pinned key: an unreachable server means no mirror lookup", async () => {
  serverUp = false;
  sent.length = 0;
  const r = await resolvePage(PAGE);
  assert.equal(r?.mirror, undefined);
  assert.equal(sent.filter((m) => m.type === "offscreen:mirror").length, 0);
});

test("the server key is pinned on first contact and a changed key is refused", async () => {
  serverUp = true;
  const s = await getSettings();
  assert.equal(await pinServerKey(s), true);
  const fp = await fingerprint(serverKey as never);
  assert.equal(await pinnedKey(API), fp);
  const old = serverKey;
  serverKey = { kty: "OKP", crv: "Ed25519", x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" };
  assert.equal(await pinServerKey(s), false);
  assert.equal(await pinnedKey(API), fp, "pin unchanged");
  serverKey = old;
});

test("server unreachable: the mirror answers, with the pinned key", async () => {
  serverUp = false;
  mem.session = {};
  sent.length = 0;
  mirrorReply = { ok: true, result: known, mirror: "https://mirror.example.org/om/", version: "v1" };
  const r = await resolvePage(PAGE);
  assert.equal(r?.known, true);
  assert.equal(r?.via, "openmanuals");
  assert.equal(r?.mirror, "https://mirror.example.org/om/");
  assert.equal(r?.download_url, "https://archive.org/download/x/a.pdf");
  const req = sent.find((m) => m.type === "offscreen:mirror")!.request as Record<string, unknown>;
  assert.equal(req.pinned, await pinnedKey(API));
  assert.equal((req.page as { source: string }).source, "manualslib");
  assert.deepEqual(req.mirrors, mirrorBases(await getSettings()));
});

test("server reachable: no mirror lookup, even for unknown pages", async () => {
  serverUp = true;
  mem.session = {};
  sent.length = 0;
  const r = await resolvePage(PAGE + "?x=1");
  assert.equal(r?.known, false);
  assert.equal(sent.filter((m) => m.type === "offscreen:mirror").length, 0);
});

test("all mirrors failing degrades to the legacy check", async () => {
  serverUp = false;
  mem.session = {};
  mirrorReply = { ok: false, error: "every mirror failed" };
  const r = await resolvePage(PAGE + "?y=2");
  assert.equal(r?.mirror, undefined);
  assert.equal(r?.known, false);
});
