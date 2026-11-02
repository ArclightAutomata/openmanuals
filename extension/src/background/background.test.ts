// node --test src/background/background.test.ts
// Drives the real service worker modules with a stubbed chrome.* and fetch():
// OpenManuals lookup, legacy archive.org lookup, list lookups, the full upload
// port flow (chunks → hash → S3 PUT → signed fact bundle → POST /api/facts),
// and reports with automatic muting.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const root = new URL("../../../", import.meta.url);
const wasmBytes = readFileSync(new URL("extension/vendor/openmanuals-wasm/openmanuals_wasm_bg.wasm", root));
const vectors = JSON.parse(readFileSync(new URL("crates/openmanuals-core/vectors/vectors.json", root), "utf8"));

// ---- chrome stub -----------------------------------------------------------------
const mem: Record<string, Record<string, unknown>> = { sync: {}, local: {}, session: {} };
const store = (area: string) => ({
  // Like chrome.storage, every get returns copies, never the stored objects.
  get: async (q: unknown) => {
    const m = mem[area];
    if (typeof q === "string") return structuredClone({ [q]: m[q] });
    if (Array.isArray(q)) return structuredClone(Object.fromEntries(q.map((k) => [k, m[k]])));
    return structuredClone({ ...(q as object), ...Object.fromEntries(Object.entries(m).filter(([k]) => k in (q as object))) });
  },
  set: async (o: Record<string, unknown>) => { Object.assign(mem[area], structuredClone(o)); },
  remove: async (k: string | string[]) => { for (const key of ([] as string[]).concat(k)) delete mem[area][key]; },
});
const listeners: Record<string, (...a: unknown[]) => unknown> = {};
const on = (name: string) => ({ addListener: (fn: (...a: unknown[]) => unknown) => { listeners[name] = fn; } });
const painted: [string, number, string][] = [];
const registered: { id: string; matches: string[] }[] = [];
const windows: string[] = [];
const sentToTabs: unknown[] = [];
const tabs: Record<number, string> = { 7: "https://www.manualslib.com/download/81994/Jvc-Av-2168tee.html", 8: "https://www.manualslib.com/manual/555/Sony-Kv.html" };
const WASM_URL = "chrome-extension://om/openmanuals_wasm_bg.wasm";
(globalThis as unknown as { chrome: unknown }).chrome = {
  runtime: { id: "om", getManifest: () => ({ version: "9.9.9" }), getURL: (p: string) => "chrome-extension://om/" + p, onMessage: on("message"), onConnect: on("connect"), onStartup: on("startup"), onInstalled: on("installed"), openOptionsPage() {}, sendMessage: async () => null, getContexts: async () => [] },
  action: { setIcon: async (o: { tabId: number; path: Record<number, string> }) => painted.push(["icon", o.tabId, o.path[16]]), setBadgeText: async (o: { tabId: number; text: string }) => painted.push(["badge", o.tabId, o.text]), setBadgeBackgroundColor: async () => {}, setBadgeTextColor: async () => {} },
  storage: { sync: store("sync"), local: store("local"), session: store("session"), onChanged: on("storageChanged") },
  tabs: { onUpdated: on("tabUpdated"), onRemoved: on("tabRemoved"), get: async (id: number) => ({ id, url: tabs[id] }), query: async (q: { url?: string[] }) => Object.entries(tabs).filter(([, u]) => !q.url || q.url.some((pat) => pat.includes("/download/") ? u.includes("/download/") : true)).map(([id, url]) => ({ id: Number(id), url })), sendMessage: async (id: number, msg: unknown) => sentToTabs.push([id, msg]), create: async () => ({}) },
  alarms: { create: async () => {}, onAlarm: on("alarm") },
  offscreen: { createDocument: async () => {} },
  scripting: {
    getRegisteredContentScripts: async () => registered.slice(),
    unregisterContentScripts: async () => { registered.length = 0; },
    registerContentScripts: async (s: { id: string; matches: string[] }[]) => { registered.push(...s); },
  },
  permissions: { onAdded: on("permAdded") },
  windows: { create: async (o: { url: string }) => { windows.push(o.url); return { id: 77 }; }, get: async () => { throw new Error("closed"); }, update: async () => ({}) },
};

// ---- fetch stub ------------------------------------------------------------------------
const calls: { url: string; method: string; headers: Record<string, string>; body?: unknown }[] = [];
const items: Record<string, { metadata: Record<string, string>; files: { name: string; source: string; size?: string }[] }> = {
  "manualslib-id-81994": { metadata: { title: "jvc AV-2168TEE instructions manual" }, files: [{ name: "av2168tee.pdf", source: "original", size: "960335" }] },
};
const omKnown: Record<string, unknown> = {};
let postedFacts: unknown[][] = [];
globalThis.fetch = (async (input: string | URL | Request, init: RequestInit = {}) => {
  const u = String(input);
  const headers = Object.fromEntries(Object.entries((init.headers ?? {}) as Record<string, string>));
  calls.push({ url: u, method: init.method ?? "GET", headers, body: init.body });
  const json = (obj: unknown, status = 200) => new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json" } });
  if (u === WASM_URL) return new Response(wasmBytes, { headers: { "content-type": "application/wasm" } });
  if (u.startsWith("https://archive.org/services/check_identifier.php")) {
    const id = decodeURIComponent(u.split("identifier=")[1]);
    return json({ identifier: id, type: "success", code: id in items ? "not_available" : "available" });
  }
  if (u.startsWith("https://archive.org/metadata/")) return json(items[decodeURIComponent(u.split("/metadata/")[1])] ?? {});
  if (u.startsWith("https://archive.org/advancedsearch.php")) {
    const q = decodeURIComponent(new URL(u).searchParams.get("q")!);
    return json({ response: { docs: Object.keys(items).filter((id) => q.includes(`"${id}"`)).map((identifier) => ({ identifier })) } });
  }
  if (u.startsWith("https://s3.us.archive.org/")) {
    const id = u.split("/")[3];
    items[id] = { metadata: { title: headers["x-archive-meta-title"] }, files: [{ name: decodeURIComponent(u.split("/")[4]), source: "original", size: String((init.body as Uint8Array).length) }] };
    return new Response("", { status: 200 });
  }
  if (u.startsWith("http://localhost:8000/api/lookup")) {
    const url = new URL(u).searchParams.get("url") ?? "";
    return json(omKnown[url] ?? { known: false, manual: null, files: [], legacy_identifiers: [] });
  }
  if (u === "http://localhost:8000/api/facts") {
    const facts = JSON.parse(init.body as string) as { v: number }[];
    postedFacts.push(facts);
    return json({ cursor: "01J", accepted: facts.map((_, i) => `sha256:${i}`), duplicate: [], rejected: [] }, 202);
  }
  throw new Error("unexpected fetch " + u);
}) as typeof fetch;

// ---- load the worker ---------------------------------------------------------------------------
await import("./index.ts");
const { useKeyStore } = await import("./identity.ts");
const { MemoryKeyStore, keyFromEd25519Seed } = await import("../core/keys.ts");
const { ensureWasm } = await import("../core/wasm.ts");
const { hexToBytes } = await import("../core/b64.ts");
const om = await ensureWasm();
const keyStore = new MemoryKeyStore();
useKeyStore(keyStore);

const EXT_PAGE = { id: "om", url: "chrome-extension://om/options.html" };
const send = (msg: unknown, sender: unknown = EXT_PAGE) => new Promise<unknown>((resolve) => { const r = listeners.message(msg, sender, resolve); if (r !== true) resolve(undefined); });
const tick = (ms = 30) => new Promise((r) => setTimeout(r, ms));

test("lookup: page known to OpenManuals with a verified copy", async () => {
  omKnown["https://www.manualslib.com/manual/555/Sony-Kv.html"] = {
    known: true, manual: { id: "01ARZ3NDEKTSV4RRFFQ69G5FAV", title: "Sony KV Service Manual", url: "http://localhost:8000/manual/01ARZ3NDEKTSV4RRFFQ69G5FAV" },
    files: [{ sha256: "a".repeat(64), size: 10, mime: "application/pdf", canonical: true, copies: [{ url: "https://archive.org/download/openmanuals-aaaaaaaaaaaaaaaa-01arz3ndektsv4rrffq69g5fav/sony.pdf", kind: "archive", host: "archive.org", status: "verified", author: "QPRGVPJNWDXH4ESK2RYDTZJLTE", ia: { identifier: "openmanuals-aaaaaaaaaaaaaaaa-01arz3ndektsv4rrffq69g5fav", filename: "sony.pdf" } }] }],
    legacy_identifiers: ["manualslib-id-555"],
  };
  const r = (await send({ type: "lookup", url: tabs[8] }, { tab: { id: 8 } })) as { archived: boolean; via: string; download_url: string; title: string; openmanuals_url: string };
  assert.equal(r.archived, true);
  assert.equal(r.via, "openmanuals");
  assert.equal(r.download_url, "https://archive.org/download/openmanuals-aaaaaaaaaaaaaaaa-01arz3ndektsv4rrffq69g5fav/sony.pdf");
  assert.equal(r.title, "Sony KV Service Manual");
  assert.ok(painted.some(([k, id, v]) => k === "badge" && id === 8 && v === "✓"));
  assert.ok(!calls.some((c) => c.url.includes("check_identifier") && c.url.includes("555")), "no archive.org probe when the server knows the page");
});

test("lookup: page unknown to OpenManuals falls back to the legacy identifier, details arrive later", async () => {
  mem.sync.legacyCheck = true; // the live archive.org check is an advanced setting (and always on without a server)
  const r = (await send({ type: "lookup", url: tabs[7] }, { tab: { id: 7 } })) as { archived: boolean; via: string; identifier: string; archive_url: string; page: { kind: string } };
  assert.equal(r.archived, true);
  assert.equal(r.via, "legacy");
  assert.equal(r.identifier, "manualslib-id-81994");
  assert.equal(r.archive_url, "https://archive.org/details/manualslib-id-81994");
  assert.equal(r.page.kind, "download");
  await tick(50);
  const details = (sentToTabs as [number, { type: string; lookup: { download_url: string } }][]).find(([id, m]) => id === 7 && m.type === "lookupDetails");
  assert.ok(details, "phase-2 details pushed to the tab");
  assert.equal(details![1].lookup.download_url, "https://archive.org/download/manualslib-id-81994/av2168tee.pdf");
});

test("lookupMany marks archived ids via the search index", async () => {
  const r = (await send({ type: "lookupMany", source: "manualslib", sourceIds: ["81994", "1", "2"] })) as { found: Record<string, { identifier: string }> };
  assert.deepEqual(Object.keys(r.found), ["81994"]);
  assert.equal(r.found["81994"].identifier, "manualslib-id-81994");
});

test("upload port: hash → S3 PUT with content-addressed identifier → signed bundle → POST /api/facts", async () => {
  await keyStore.put(await keyFromEd25519Seed(hexToBytes(vectors.keys[0].seed_hex), vectors.keys[0].jwk.x));
  Object.assign(mem.sync, { uploadEnabled: true });
  Object.assign(mem.local, { iaAccessKey: "AK", iaSecretKey: "SK" });
  const tabUrl = "https://www.manualslib.com/download/4242/Jvc-Av-2168tee.html";
  tabs[9] = tabUrl;
  await send({ type: "lookup", url: tabUrl }, { tab: { id: 9 } });

  const posted: { type: string; stage?: string; [k: string]: unknown }[] = [];
  let onMsg: (m: unknown) => void = () => {};
  const port = { name: "upload", sender: { tab: { id: 9 }, url: tabUrl }, onMessage: { addListener: (fn: (m: unknown) => void) => { onMsg = fn; } }, onDisconnect: { addListener() {} }, postMessage: (m: { type: string }) => posted.push(m), disconnect() {} };
  listeners.connect(port);
  const pdf = new TextEncoder().encode("%PDF-1.4 fake manual body ".repeat(100));
  onMsg({ type: "begin", filename: "av2168tee.pdf", contentType: "application/pdf", size: pdf.length, metadata: { title: "JVC AV-2168TEE Instructions Manual", products: [{ brand: "JVC", model: "AV-2168TEE" }] }, sourceInfo: { source: "manualslib", sourceId: "4242", sourceUrl: "https://www.manualslib.com/manual/4242/Jvc-Av-2168tee.html" }, addCopy: false });
  const b64 = Buffer.from(pdf).toString("base64");
  onMsg({ type: "chunk", data: b64.slice(0, 1000) });
  onMsg({ type: "chunk", data: b64.slice(1000) });
  onMsg({ type: "end" });
  for (let i = 0; i < 100 && !posted.some((m) => ["done", "error", "exists"].includes(String(m.stage))); i++) await tick(20);
  const done = posted.find((m) => m.stage === "done") as { facts: number; archive_url: string; sha256: string; stripped: boolean } | undefined;
  assert.ok(done, "upload reached done: " + JSON.stringify(posted));
  assert.equal(done!.stripped, false); // no offscreen document here, stripping is skipped gracefully
  assert.equal(done!.sha256, om.sha256_hex(pdf));

  const put = calls.find((c) => c.method === "PUT" && c.url.startsWith("https://s3.us.archive.org/"))!;
  const identifier = put.url.split("/")[3];
  assert.match(identifier, new RegExp(`^openmanuals-${done!.sha256.slice(0, 16)}-[0-9a-hjkmnp-tv-z]{26}$`));
  assert.equal(put.headers["x-archive-meta01-external-identifier"], `urn:sha256:${done!.sha256}`);
  assert.equal(put.headers["x-archive-meta-openmanuals-key"], vectors.keys[0].fingerprint);
  assert.equal(put.headers["x-archive-meta-source"], "https://www.manualslib.com/manual/4242/Jvc-Av-2168tee.html");
  assert.equal(put.headers.Authorization, "LOW AK:SK");
  assert.equal(done!.archive_url, `https://archive.org/details/${identifier}`);

  assert.equal(postedFacts.length, 1);
  const facts = postedFacts[0] as { type: string; author: string; body: Record<string, unknown> }[];
  assert.deepEqual(facts.map((f) => f.type), ["file", "location", "location", "manual", "product", "covers", "manual_file"]);
  for (const f of facts) { assert.equal(f.author, vectors.keys[0].fingerprint); om.verify_fact(JSON.stringify(f)); }
  assert.equal(facts[2].body.url, `https://archive.org/download/${identifier}/av2168tee.pdf`);
  assert.equal(done!.facts, 7);
  const hist = mem.local.history as { accepted: string[] }[];
  assert.equal(hist.length, 1);
  assert.equal(hist[0].accepted.length, 7);
  assert.equal((mem.local.outbox as unknown[]).length, 0);
  assert.ok(painted.some(([k, id, v]) => k === "badge" && id === 9 && v === "✓"));
});

test("reports: label fact sent, author auto-muted after three, muted copies skipped", async () => {
  postedFacts = [];
  for (const sha of ["b", "c", "d"]) {
    const r = (await send({ type: "report", sha256: sha.repeat(64), author: "ZZZZZZZZZZZZZZZZZZZZZZZZZZ", url: "https://x/", value: "wrong-file" })) as { ok: boolean; sent: boolean; muted: boolean };
    assert.equal(r.sent, true);
    assert.equal(r.muted, sha === "d");
  }
  await tick(80);
  assert.equal(postedFacts.length, 3);
  const label = (postedFacts[0] as { type: string; body: Record<string, string> }[])[0];
  assert.equal(label.type, "label");
  assert.equal(label.body.ns, "report");
  assert.equal(label.body.target, `file:${"b".repeat(64)}`);
  const muteState = mem.local.muteState as { muted: Record<string, unknown> };
  assert.ok(muteState.muted["ZZZZZZZZZZZZZZZZZZZZZZZZZZ"]);

  // A page whose only copy comes from the muted author no longer counts as archived.
  omKnown["https://www.manualslib.com/manual/777/X.html"] = { known: true, manual: { id: "01ARZ3NDEKTSV4RRFFQ69G5FAX", title: "X", url: "u" }, files: [{ sha256: "e".repeat(64), copies: [{ url: "https://x/e.pdf", kind: "mirror", host: "x", status: "verified", author: "ZZZZZZZZZZZZZZZZZZZZZZZZZZ" }] }], legacy_identifiers: [] };
  tabs[10] = "https://www.manualslib.com/manual/777/X.html";
  const r = (await send({ type: "lookup", url: tabs[10] }, { tab: { id: 10 } })) as { archived: boolean; known: boolean };
  assert.equal(r.known, true);
  assert.equal(r.archived, false);
});

test("outbox: a failed POST is kept and retried", async () => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    if (String(input) === "http://localhost:8000/api/facts") return new Response("down", { status: 503 });
    return realFetch(input, init);
  }) as typeof fetch;
  await send({ type: "submitFacts", facts: [{ type: "label", at: "2026-10-23T18:00:00Z", body: { target: "file:" + "f".repeat(64), ns: "report", value: "spam" } }], label: "t" });
  await tick(30);
  let st = (await send({ type: "outboxState" })) as { outbox: { attempts: number; lastError: string }[] };
  assert.equal(st.outbox.length, 1);
  assert.equal(st.outbox[0].attempts, 1);
  assert.match(st.outbox[0].lastError, /503/);
  globalThis.fetch = realFetch;
  // Force the retry now.
  (mem.local.outbox as { nextTry: number }[])[0].nextTry = 0;
  const after = (await send({ type: "flushOutbox" })) as { outbox: unknown[] };
  assert.equal(after.outbox.length, 0);
});

test("server pages: the script follows the setting; content scripts can't sign; clicks only open the confirm window", async () => {
  await tick(50);
  assert.deepEqual(registered.map((r) => r.matches), [["http://localhost/*"]], "registered for the default server");
  const server = { id: "om", url: "http://localhost:8000/ledger", tab: { id: 5 }, frameId: 0 };
  const other = { id: "om", url: "https://www.manualslib.com/manual/555/Sony-Kv.html", tab: { id: 8 }, frameId: 0 };
  // Signing and settings messages from any web page are dropped.
  postedFacts = [];
  for (const sender of [server, other]) {
    assert.equal(await send({ type: "submitFacts", facts: [{ type: "retract", at: "2026-10-31T12:00:00Z", body: { fact: "sha256:" + "a".repeat(64) } }], label: "x" }, sender), undefined);
    assert.equal(await send({ type: "report", sha256: "f".repeat(64), value: "spam" }, sender), undefined);
    assert.equal(await send({ type: "getIdentity" }, sender), undefined);
  }
  await tick(50);
  assert.equal(postedFacts.length, 0);
  // Only the configured server's exact origin, top frame.
  // The server's page learns only whether uploads are ready (for its "help preserve" prompt); other pages learn nothing.
  assert.deepEqual(await send({ type: "siteHello" }, server), { ok: true, upload: true });
  assert.deepEqual(await send({ type: "siteHello" }, other), { ok: false });
  assert.deepEqual(await send({ type: "siteHello" }, { ...server, url: "http://localhost:9999/ledger" }), { ok: false });
  assert.deepEqual(await send({ type: "siteHello" }, { ...server, frameId: 3 }), { ok: false });
  const F = "sha256:" + "a".repeat(64);
  assert.deepEqual(await send({ type: "siteAction", action: "fact", fact: F }, server), { ok: true });
  assert.deepEqual(await send({ type: "siteAction", action: "sign", fact: F }, server), { ok: false });
  assert.deepEqual(await send({ type: "siteAction", action: "fact", fact: F }, other), { ok: false });
  assert.deepEqual(windows, [`chrome-extension://om/confirm.html?action=fact&fact=${encodeURIComponent(F)}`]);
  // Changing the server moves the script.
  mem.sync.apiBase = "https://om.example.org";
  listeners.storageChanged({ apiBase: { newValue: "https://om.example.org" } }, "sync");
  await tick(50);
  assert.deepEqual(registered.map((r) => r.matches), [["https://om.example.org/*"]]);
  assert.deepEqual(await send({ type: "siteHello" }, server), { ok: false });
  delete mem.sync.apiBase;
  // Report targets: a copy's location fact, validated.
  postedFacts = [];
  const r = (await send({ type: "report", target: "sha256:" + "b".repeat(64), sha256: "c".repeat(64), value: "spam" })) as { sent: boolean };
  assert.equal(r.sent, true);
  assert.deepEqual(await send({ type: "report", target: "javascript:1", value: "spam" }), { error: "nothing to report" });
  assert.deepEqual(await send({ type: "report", sha256: "c".repeat(64), value: "rude" }), { error: "unknown report reason" });
  await tick(80);
  assert.equal(((postedFacts[0] as { body: Record<string, string> }[])[0]).body.target, "sha256:" + "b".repeat(64));
});

test("upload and fetch ports only from the manual sites", () => {
  let dropped = false;
  listeners.connect({ name: "upload", sender: { url: "http://localhost:8000/ledger", tab: { id: 5 } }, onMessage: { addListener() { throw new Error("listened"); } }, onDisconnect: { addListener() {} }, postMessage() {}, disconnect() { dropped = true; } });
  assert.equal(dropped, true);
});

test("fetch port: a Manualzz download form is posted back to its own site only", async () => {
  const realFetch = globalThis.fetch;
  const asked: { url: string; method: string; body: string }[] = [];
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    asked.push({ url: String(input), method: init?.method ?? "GET", body: String(init?.body ?? "") });
    return new Response(new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d]), { status: 200, headers: { "content-type": "application/pdf" } });
  }) as typeof fetch;
  const open = (url: string) => {
    const got: { type: string; message?: string }[] = [];
    let onMsg!: (m: unknown) => void;
    let dropped = false;
    listeners.connect({ name: "fetch", sender: { url, tab: { id: 9 } }, onMessage: { addListener(f: (m: unknown) => void) { onMsg = f; } }, onDisconnect: { addListener() {} }, postMessage(m: { type: string }) { got.push(m); }, disconnect() { dropped = true; } });
    return { got, send: (m: unknown) => onMsg?.(m), dropped: () => dropped };
  };
  const done = async (got: { type: string }[]) => { for (let i = 0; i < 50 && !got.some((m) => m.type === "end" || m.type === "error"); i++) await new Promise((r) => setTimeout(r, 2)); };
  try {
    const page = "https://manualzz.com/download/6961161";
    const ok = open(page);
    ok.send({ type: "fetch", url: "https://manualzz.com/download/check", form: "documentId=6961161&format=pdf", referer: page });
    await done(ok.got);
    assert.deepEqual(asked.at(-1), { url: "https://manualzz.com/download/check", method: "POST", body: "documentId=6961161&format=pdf" });
    assert.equal(ok.got.at(-1)?.type, "end");
    const n = asked.length;
    const elsewhere = open(page);
    elsewhere.send({ type: "fetch", url: "https://evil.example/collect", form: "x=1" });
    await done(elsewhere.got);
    assert.equal(asked.length, n, "not sent");
    assert.equal(elsewhere.got.at(-1)?.type, "error");
    assert.equal(open("https://example.com/").dropped(), true, "other sites can't open the port");
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("side panel: server pages report hooks; clicks open the panel (else the confirm window); only extension pages sign", async () => {
  const c = (globalThis as unknown as { chrome: Record<string, unknown> }).chrome;
  const panelOpts: unknown[] = [], opened: number[] = [];
  let canOpen = true;
  c.sidePanel = {
    setOptions: async (o: unknown) => { panelOpts.push(o); },
    open: async (o: { tabId: number }) => { if (!canOpen) throw new Error("needs a user gesture"); opened.push(o.tabId); },
  };
  const server = { id: "om", url: "http://localhost:8000/ledger", tab: { id: 5 }, frameId: 0 };
  const other = { id: "om", url: "https://www.manualslib.com/manual/555/Sony-Kv.html", tab: { id: 8 }, frameId: 0 };
  const F = "sha256:" + "a".repeat(64), G = "sha256:" + "b".repeat(64);
  const THEM = "AAAAAAAAAAAAAAAAAAAAAAAAAA";

  // The page's hooks are validated and kept for that tab's panel, which is enabled there.
  assert.deepEqual(await send({ type: "sitePage", items: [{ action: "fact", fact: F }, { action: "fact", fact: F }, { action: "sign", fact: G }, "x"] }, server), { ok: true });
  assert.deepEqual((mem.session["sitePage:5"] as { items: unknown[] }).items, [{ action: "fact", fact: F }]);
  assert.deepEqual(panelOpts.at(-1), { tabId: 5, path: "panel.html?tab=5", enabled: true });
  assert.deepEqual(await send({ type: "sitePage", items: [{ action: "fact", fact: F }] }, other), { ok: false });
  assert.equal(mem.session["sitePage:8"], undefined);

  // A click opens the panel and points it at the row; no window.
  windows.length = 0;
  assert.deepEqual(await send({ type: "siteAction", action: "fact", fact: F }, server), { ok: true, panel: true });
  assert.deepEqual(opened, [5]);
  assert.equal((mem.session["panelFocus:5"] as { key: string }).key, F);
  assert.equal(windows.length, 0);
  // When the panel can't open, the confirmation window is the fallback.
  canOpen = false;
  assert.deepEqual(await send({ type: "siteAction", action: "fact", fact: G }, server), { ok: true });
  assert.equal(windows.length, 1);
  assert.deepEqual(await send({ type: "siteAction", action: "fact", fact: G }, other), { ok: false });
  assert.equal(windows.length, 1);

  // Hover highlights go to the tab as a key, and only well-formed ones.
  sentToTabs.length = 0;
  await send({ type: "siteHighlight", tabId: 5, key: F });
  await send({ type: "siteHighlight", tabId: 5, key: "<img>" });
  assert.deepEqual(sentToTabs, [[5, { type: "omHighlight", key: F }], [5, { type: "omHighlight", key: null }]]);

  // Leaving the server forgets the page and disables the panel in that tab.
  listeners.tabUpdated(5, { status: "loading", url: "https://example.com/" }, { url: "https://example.com/" });
  await tick(50);
  assert.equal(mem.session["sitePage:5"], undefined);
  assert.deepEqual(panelOpts.at(-1), { tabId: 5, enabled: false });

  // Bulk signing: never from a web page; validated; one bundle for the lot.
  postedFacts = [];
  assert.equal(await send({ type: "siteBulk", ops: [{ op: "retract", fact: F }] }, server), undefined);
  assert.deepEqual(await send({ type: "siteBulk", ops: [{ op: "sign", fact: F }] }), { error: "invalid actions" });
  const r = (await send({ type: "siteBulk", ops: [{ op: "retract", fact: F }, { op: "report", target: G, value: "spam", author: THEM }, { op: "report", target: "file:" + "c".repeat(64), value: "wrong-file", sha256: "c".repeat(64) }] })) as { ok: boolean; results: { status: string }[] };
  assert.equal(r.ok, true);
  assert.deepEqual(r.results.map((x) => x.status), ["sent", "sent", "sent"]);
  assert.equal(postedFacts.length, 1, "one bundle");
  const posted = postedFacts[0] as { type: string; body: Record<string, string> }[];
  assert.deepEqual(posted.map((f) => [f.type, f.body.fact ?? f.body.target, f.body.value]), [["retract", F, undefined], ["label", G, "spam"], ["label", "file:" + "c".repeat(64), "wrong-file"]]);
  delete c.sidePanel;
});

test("archive.org: saved keys record their account; the session comes from the cookie", async () => {
  const realFetch = globalThis.fetch;
  const seen: string[] = [];
  let reject = false;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    if (String(input) === "https://s3.us.archive.org/?check_auth=1") {
      seen.push(String((init?.headers as Record<string, string>)?.Authorization));
      if (reject) return new Response(JSON.stringify({ error: "Invalid access key" }), { status: 403 });
      return new Response(JSON.stringify({ authorized: true, username: "alice@example.org", screenname: "Alice", itemname: "@alice" }), { status: 200 });
    }
    return realFetch(input, init);
  }) as typeof fetch;
  const cookies: Record<string, string> = { "logged-in-user": "bob%40example.org" };
  (chrome as unknown as { cookies: unknown }).cookies = { get: async (d: { name: string }) => (d.name in cookies ? { value: cookies[d.name] } : null) };
  try {
    const r = (await send({ type: "iaSaveKeys", accessKey: "AK", secretKey: "SK" }, EXT_PAGE)) as { ok: boolean; message: string; user: string };
    assert.equal(r.ok, true);
    assert.equal(r.user, "@alice (Alice)");
    assert.deepEqual(seen.slice(0, 1), ["LOW AK:SK"], "asked with the keys, not cookies");
    assert.deepEqual(mem.local.iaAccount, { itemname: "@alice", screenname: "Alice", email: "alice@example.org" });
    let st = (await send({ type: "iaStatus" }, EXT_PAGE)) as { session: string; sessionAccount: string | null; keys: string };
    assert.equal(st.session, "bob@example.org");
    assert.equal(st.keys, "@alice (Alice)");
    assert.equal((st as unknown as { keysHandle: string }).keysHandle, "@alice", "for the archive.org profile link");
    assert.equal(st.sessionAccount, null, "with keys saved, the browser's own sign-in isn't looked up");
    assert.equal((st as unknown as { keysValid: boolean }).keysValid, true);
    const checked = (st as unknown as { checkedAt: string }).checkedAt;
    assert.ok(checked && Date.now() - Date.parse(checked) < 5000, "the check time is recorded");
    assert.equal(seen.length, 1, "saving the keys checked them once; opening the page within 24 h reuses that");
    delete cookies["logged-in-user"];
    st = (await send({ type: "iaStatus" }, EXT_PAGE)) as { session: string; sessionAccount: string | null; keys: string };
    assert.equal(st.session, null);
    reject = true;
    const bad = (await send({ type: "iaStatus", force: true }, EXT_PAGE)) as { keysValid: boolean | null; keys: string };
    assert.equal(bad.keysValid, false, "keys archive.org rejects show as not working");
    assert.equal(bad.keys, "@alice (Alice)", "the recorded account is kept");
    reject = false;
    // archive.org unreachable: not judged, and the last good check is still reported.
    const realFetch2 = globalThis.fetch;
    await send({ type: "iaStatus", force: true }, EXT_PAGE); // a good check
    globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
      if (String(input) === "https://s3.us.archive.org/?check_auth=1") throw new TypeError("network down");
      return realFetch2(input, init);
    }) as typeof fetch;
    const down = (await send({ type: "iaStatus", force: true }, EXT_PAGE)) as { keysValid: boolean | null; checkedAt: string | null; lastValid: boolean | null };
    assert.equal(down.keysValid, null);
    assert.equal(down.lastValid, true);
    assert.ok(down.checkedAt);
    globalThis.fetch = realFetch2;
    // Web pages can't ask.
    assert.deepEqual(await send({ type: "iaStatus" }, { tab: { id: 7 }, url: tabs[7] }), undefined);
    assert.deepEqual(await send({ type: "iaSignOut" }, { tab: { id: 7 }, url: tabs[7] }), undefined);
    // Sign out: the keys, their account and uploads go.
    mem.sync.uploadEnabled = true;
    assert.deepEqual(await send({ type: "iaSignOut" }, EXT_PAGE), { ok: true });
    assert.equal(mem.local.iaAccessKey, "");
    assert.equal(mem.local.iaSecretKey, "");
    assert.equal(mem.local.iaAccount, undefined);
    assert.equal(mem.local.iaKeysCheck, undefined);
    assert.equal(mem.sync.uploadEnabled, false);
    // Without keys, a signed-in browser is named by its session keys' account (read, not saved), once per session.
    cookies["logged-in-user"] = "alice%40example.org";
    let keysPage = 0;
    globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
      if (String(input).startsWith("https://archive.org/account/s3.php")) { keysPage++; return new Response(JSON.stringify({ key: { s3accesskey: "AK2", s3secretkey: "SK2" } }), { status: 200 }); }
      return realFetch2(input, init);
    }) as typeof fetch;
    const signedIn = (await send({ type: "iaStatus" }, EXT_PAGE)) as { hasKeys: boolean; session: string; sessionAccount: unknown };
    assert.equal(signedIn.hasKeys, false);
    assert.deepEqual(signedIn.sessionAccount, { label: "@alice (Alice)", handle: "@alice" });
    assert.equal(mem.local.iaAccessKey, "", "the session's keys aren't saved by looking");
    const again = (await send({ type: "iaStatus" }, EXT_PAGE)) as { sessionAccount: unknown };
    assert.deepEqual(again.sessionAccount, { label: "@alice (Alice)", handle: "@alice" });
    assert.equal(keysPage, 1, "cached for the browser session");
    globalThis.fetch = realFetch2;
    delete cookies["logged-in-user"];
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("outbox: a bundle queued while a flush is posting isn't lost", async () => {
  const realFetch = globalThis.fetch;
  let release!: () => void;
  const gate = new Promise<void>((r) => { release = r; });
  let first = true;
  let stalled!: () => void;
  const reached = new Promise<void>((r) => { stalled = r; });
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    if (String(input) === "http://localhost:8000/api/facts" && first) { first = false; stalled(); await gate; }
    return realFetch(input, init);
  }) as typeof fetch;
  try {
    postedFacts = [];
    const label = (v: string) => [{ type: "label", at: "2026-10-23T18:00:00Z", body: { target: "file:" + "9".repeat(64), ns: "report", value: v } }];
    void send({ type: "submitFacts", facts: label("spam"), label: "first" }); // starts a flush that stalls on the gate
    await reached;
    await send({ type: "submitFacts", facts: label("wrong-file"), label: "second" }); // queued mid-flush
    await tick(10);
    release();
    await tick(80);
    await send({ type: "flushOutbox" });
    await tick(30);
    const values = postedFacts.flat().map((f) => (f as { body: { value: string } }).body.value);
    assert.ok(values.includes("spam") && values.includes("wrong-file"), `both bundles posted: ${values}`);
    const st = (await send({ type: "outboxState" })) as { outbox: unknown[] };
    assert.equal(st.outbox.length, 0);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("Save link as…: a ManualsLib file download is handed to the page that offers it", async () => {
  const { onCreated, installDownloadWatch } = await import("./downloads.ts");
  const FILE = "https://data2.manualslib.com/cpdf/4/18/1722/1a4ee2.pdf?take=binary";
  Object.assign(mem.sync, { uploadEnabled: true });
  Object.assign(mem.local, { iaAccessKey: "AK", iaSecretKey: "SK" });
  sentToTabs.length = 0;
  // Only download pages are asked (tab 7), never manual pages (tab 8); each page checks its own links.
  assert.ok((await onCreated({ url: FILE })) >= 1);
  await tick(10);
  const asked = new Map(sentToTabs.map((x) => x as [number, unknown]));
  assert.deepEqual(asked.get(7), { type: "capturedDownload", url: FILE });
  assert.ok(!asked.has(8), "manual pages aren't asked");
  for (const id of asked.keys()) assert.ok(tabs[id].includes("/download/"));
  // Not ManualsLib, started by an extension (our own delivered copy), or uploads off: nothing.
  assert.equal(await onCreated({ url: "https://example.com/x.pdf" }), 0);
  assert.equal(await onCreated({ url: FILE, byExtensionId: "om" }), 0);
  Object.assign(mem.sync, { uploadEnabled: false });
  assert.equal(await onCreated({ url: FILE }), 0);
  Object.assign(mem.sync, { uploadEnabled: true });
  // The listener is attached when the worker starts.
  const added: unknown[] = [];
  (chrome as unknown as { downloads: unknown }).downloads = { onCreated: { addListener: (fn: unknown) => added.push(fn) } };
  installDownloadWatch();
  assert.equal(added.length, 1);
  delete (chrome as unknown as { downloads?: unknown }).downloads;
});

test("outbox: a key blocked by a moderator gets a plain message and a long wait", async () => {
  const { postFacts, ApiError } = await import("./api.ts");
  const real = globalThis.fetch;
  globalThis.fetch = (async () => new Response(JSON.stringify({ accepted: [], duplicate: [], rejected: [{ index: 0, error: "key X is blocked by a moderator" }] }), { status: 403 })) as typeof fetch;
  try {
    await assert.rejects(postFacts({ apiBase: "http://localhost:8000" } as never, []), (e: unknown) => e instanceof ApiError && e.message === "Your key is blocked by this server's moderators." && e.retryAfter === 6 * 3600);
  } finally {
    globalThis.fetch = real;
  }
});

test("the popup asks the worker whether a tab is a manual page on a supported site", async () => {
  tabs[41] = "https://example.com/manual/1/X.html";
  try {
    assert.equal(await send({ type: "isSourcePage", tabId: 7 }), true, "a ManualsLib download page");
    assert.equal(await send({ type: "isSourcePage", tabId: 8 }), true, "a ManualsLib manual page");
    assert.equal(await send({ type: "isSourcePage", tabId: 41 }), false);
  } finally {
    delete tabs[41];
  }
});
