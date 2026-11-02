// End to end: acting on the server's own pages through the extension. Chrome
// with the extension and a throwaway openmanuals-server. Not part of `npm test`.
//
//   cargo build --release -p openmanuals-server
//   cd extension && npm run build && node test/site-e2e.mjs [--headful] [--chrome /path/to/chrome] [--port 18732]
//
// Steps: create a key (passphrase flow, no passkey needed); sign facts as
// that key and post facts from another key; open the server's ledger page and
// check every hooked row gets the same button (the page can't tell which
// facts are yours) and a synthetic click does nothing; really click your fact's
// button, retract it in the extension's confirmation window, and check the
// server and page show it retracted; report the other key's fact and a file
// page, and check the label facts.
import { Browser } from "./cdp.mjs";
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { ensureWasm } from "../src/core/wasm.ts";
import { keyFromEd25519Seed } from "../src/core/keys.ts";
import { hexToBytes } from "../src/core/b64.ts";
import { signFact, factId } from "../src/core/facts.ts";

const arg = (name, dflt) => { const i = process.argv.indexOf(name); return i > 0 ? process.argv[i + 1] : dflt; };
const headless = !process.argv.includes("--headful");
const chrome = arg("--chrome", "google-chrome");
const port = Number(arg("--port", "18732"));
const repo = fileURLToPath(new URL("../../", import.meta.url));
const dist = fileURLToPath(new URL("../dist", import.meta.url));
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const step = (s) => console.log(`\n== ${s}`);
const until = async (what, fn, ms = 20000) => {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn().catch(() => null);
    if (v) return v;
    if (Date.now() > end) throw new Error(`timed out: ${what}`);
    await wait(150);
  }
};

// The other contributor, signed here with the core's own signer.
await ensureWasm(readFileSync(join(repo, "extension/vendor/openmanuals-wasm/openmanuals_wasm_bg.wasm")));
const vectors = JSON.parse(readFileSync(join(repo, "crates/openmanuals-core/vectors/vectors.json"), "utf8"));
const other = await keyFromEd25519Seed(hexToBytes(vectors.keys[0].seed_hex), vectors.keys[0].jwk.x);

// ---- throwaway server --------------------------------------------------------------------
const tmp = mkdtempSync(join(process.env.SCRATCH ?? tmpdir(), "om-site-e2e-"));
mkdirSync(join(tmp, "data"));
execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "e2e server", "-f", join(tmp, "data/server.key")]);
const server = spawn(join(repo, "target/release/openmanuals-server"), ["--data-dir", join(tmp, "data"), "--ledger-dir", join(tmp, "ledger"),
  "serve", "--bind", `127.0.0.1:${port}`, "--fold-interval", "0", "--fold-debounce", "1", "--fold-max-delay", "2", "--verify-interval", "0"], { stdio: ["ignore", "ignore", "inherit"] });
const api = `http://127.0.0.1:${port}`;
await until("server start", async () => (await fetch(`${api}/api/server`)).ok);
const downloads = join(tmp, "downloads");
mkdirSync(downloads);
const feed = async () => (await (await fetch(`${api}/api/feed`)).json()).facts.map((x) => x.fact);
const served = async (id) => (await fetch(`${api}/api/fact/${id}`)).json();

const b = await Browser.launch({ chrome, headless, extension: dist });
let ok = false;
try {
  const ID = b.extensionId;
  const OPTIONS = `chrome-extension://${ID}/options.html`;
  await b.send("Browser.setDownloadBehavior", { behavior: "allow", downloadPath: downloads });
  const opts = await b.newPage("about:blank");
  const ready = `document.readyState === "complete" && !!document.getElementById("createKey")`;
  await opts.navigate(OPTIONS, ready);
  await opts.eval(`chrome.storage.sync.set({ apiBase: ${JSON.stringify(api)} })`);
  await opts.navigate(OPTIONS, ready);

  step("create a key (passphrase, no passkey)");
  await opts.eval(`document.getElementById("advanced").open = true; document.getElementById("passphrase").value = document.getElementById("passphrase2").value = "site e2e pass"; document.getElementById("usePasskey").checked = false; document.getElementById("createKeyBackup").click()`);
  const created = await until("key created", () => opts.eval(`(() => { const e = document.getElementById("advKeyMsg"); return /\\b(ok|bad)\\b/.test(e.className) ? { ok: e.className.includes("ok"), text: e.textContent } : null; })()`), 60000);
  assert.ok(created.ok, created.text);
  const me = await opts.eval(`chrome.runtime.sendMessage({ type: "getIdentity" }).then((i) => i.fingerprint)`);
  console.log({ me, other: other.fingerprint });

  step("my facts through the extension, the other key's straight to the server");
  const sha = "ab".repeat(32);
  const mine = [
    { type: "product", at: "2026-10-31T12:00:00Z", body: { brand: "Acme", model: "X1" } },
    { type: "file", at: "2026-10-31T12:00:00Z", body: { sha256: sha, sha1: "cd".repeat(20), md5: "ef".repeat(16), size: 1000, mime: "application/pdf" } },
  ];
  await opts.eval(`chrome.runtime.sendMessage({ type: "submitFacts", facts: ${JSON.stringify(mine)}, label: "e2e" }).then(() => chrome.runtime.sendMessage({ type: "flushOutbox" }))`);
  const theirs = await signFact(other, { type: "product", at: "2026-10-31T12:00:00Z", body: { brand: "Other", model: "Y2" } });
  const theirId = await factId(theirs);
  assert.equal((await fetch(`${api}/api/facts`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify([theirs]) })).status, 202);
  const myProduct = await until("my facts on the server", async () => {
    const f = (await feed()).find((x) => x.author === me && x.type === "product");
    return f ? factId(f) : null;
  });
  await until("ledger page lists them", async () => { const h = await (await fetch(`${api}/ledger`)).text(); return h.includes(myProduct) && h.includes(theirId); });

  step("the ledger page: the same button on every row; the hint hidden");
  const site = await b.newPage(`${api}/ledger`);
  await until("buttons added", () => site.eval(`document.querySelectorAll("button.om-act").length > 0`));
  const view = await site.eval(`(() => ({
    hooks: document.querySelectorAll("li.fact-row[data-om-fact]:not([data-om-hidden])").length,
    rowsWithButton: [...document.querySelectorAll("li.fact-row[data-om-fact]")].filter((r) => r.querySelector(".fact-side button.om-act")).length,
    labels: [...new Set([...document.querySelectorAll("li.fact-row button.om-act")].map((b) => b.textContent + "|" + b.title))],
    hint: document.querySelector(".om-ext-hint").hidden,
  }))()`);
  console.log(view);
  assert.ok(view.hooks >= 3 && view.rowsWithButton === view.hooks, "every row has one button");
  assert.equal(view.labels.length, 1, "identical on your facts and others'");
  assert.equal(view.hint, true);

  const confirmTargets = () => [...b.targets.values()].filter((t) => t.url.includes(`chrome-extension://${ID}/confirm.html`));
  const panelTargets = () => [...b.targets.values()].filter((t) => t.url.startsWith(`chrome-extension://${ID}/panel.html`));

  step("a synthetic click from the page opens nothing");
  await site.eval(`document.querySelector('[data-om-fact="${myProduct}"] .fact-side button.om-act').click()`);
  await wait(1200);
  assert.equal(confirmTargets().length + panelTargets().length, 0);

  // A real click opens the side panel (test/panel-e2e.mjs) or, when it can't,
  // the confirmation window. This test covers the confirmation window: when
  // the panel opened instead, the same window is opened directly.
  const openConfirm = async (selector, id, action = "fact") => {
    await site.click(selector);
    const q = action === "file" ? `action=file&file=${id}` : `action=fact&fact=${encodeURIComponent(id)}`;
    const confirm = () => confirmTargets().find((x) => x.url.includes(encodeURIComponent(id)));
    await until("panel or confirm window", async () => confirm() || panelTargets().length > 0);
    const t = confirm();
    const w = t ? await b.attach(t.targetId) : await b.newPage(`chrome-extension://${ID}/confirm.html?${q}`);
    await until("confirm loaded", () => w.eval(`document.getElementById("title").textContent !== "Loading…"`));
    return w;
  };
  const outcome = (w) => until("outcome", () => w.eval(`(() => { const e = document.getElementById("msg"); return /\\b(ok|bad)\\b/.test(e.className) ? { ok: e.className.includes("ok"), text: e.textContent } : null; })()`));

  step("retract my fact in the confirmation window");
  const w1 = await openConfirm(`[data-om-fact="${myProduct}"] .fact-side button.om-act`, myProduct);
  const s1 = await w1.eval(`({ title: document.getElementById("title").textContent, retract: !document.getElementById("retractBox").classList.contains("hidden"), report: !document.getElementById("reportBox").classList.contains("hidden") })`);
  console.log(s1);
  assert.deepEqual(s1, { title: "Your fact", retract: true, report: false });
  await w1.eval(`document.getElementById("retract").click()`);
  const r1 = await outcome(w1);
  console.log(r1);
  assert.ok(r1.ok, r1.text);
  await until("server marks it retracted", async () => (await served(myProduct)).retracted === true);
  const retract = (await feed()).find((x) => x.type === "retract" && x.author === me);
  assert.equal(retract.body.fact, myProduct);
  await site.navigate(`${api}/ledger`, `document.readyState === "complete"`);
  assert.equal(await site.eval(`document.querySelector('li.fact-row[data-om-fact="${myProduct}"]').matches("[data-om-retracted].is-retracted")`), true);

  step("report the other key's fact: no retract offered");
  await until("buttons again", () => site.eval(`document.querySelectorAll("button.om-act").length > 0`));
  const w2 = await openConfirm(`[data-om-fact="${theirId}"] .fact-side button.om-act`, theirId);
  const s2 = await w2.eval(`({ title: document.getElementById("title").textContent, retract: !document.getElementById("retractBox").classList.contains("hidden"), report: !document.getElementById("reportBox").classList.contains("hidden") })`);
  console.log(s2);
  assert.deepEqual(s2, { title: "Report a fact", retract: false, report: true });
  await w2.eval(`document.getElementById("reason").value = "spam"; document.getElementById("report").click()`);
  const r2 = await outcome(w2);
  assert.ok(r2.ok, r2.text);
  await until("label fact", async () => (await feed()).find((x) => x.type === "label" && x.author === me && x.body.target === theirId && x.body.value === "spam"));

  step("report a file from its page");
  await until("file page", async () => (await fetch(`${api}/file/${sha}`)).ok);
  await site.navigate(`${api}/file/${sha}`, `document.readyState === "complete"`);
  await until("file button", () => site.eval(`!!document.querySelector("h1 button.om-act")`));
  const w3 = await openConfirm(`h1 button.om-act`, sha, "file");
  assert.equal(await w3.eval(`document.getElementById("title").textContent`), "Report a file");
  await w3.eval(`document.getElementById("reason").value = "wrong-file"; document.getElementById("report").click()`);
  const r3 = await outcome(w3);
  assert.ok(r3.ok, r3.text);
  await until("file label", async () => (await feed()).find((x) => x.type === "label" && x.author === me && x.body.target === `file:${sha}`));

  step("help preserve a manual: the page shows whether uploads are ready");
  const contrib = await b.newPage("about:blank");
  // What shows at DOMContentLoaded, before content-site.js runs (document_idle): no install note.
  await contrib.send("Page.addScriptToEvaluateOnNewDocument", { source: `document.addEventListener("DOMContentLoaded", () => {
    const shown = (sel) => getComputedStyle(document.querySelector(sel)).display !== "none";
    window.__omEarly = { ext: document.documentElement.dataset.omExt ?? null, hint: shown(".om-ext-hint"), checking: shown(".om-ext-checking") };
  });` });
  await contrib.navigate(`${api}/contribute`, `document.readyState === "complete"`);
  const shownNow = (sel) => `getComputedStyle(document.querySelector(${JSON.stringify(sel)})).display !== "none"`;
  const readiness = () => contrib.eval(`(() => ({
    hint: ${shownNow(".om-ext-hint")},
    checking: ${shownNow(".om-ext-checking")},
    off: ${shownNow('[data-om-upload="off"]')},
    on: ${shownNow('[data-om-upload="on"]')},
  }))()`);
  // No archive.org keys in this profile, so uploads aren't ready.
  assert.deepEqual(await until("readiness shown", async () => { const r = await readiness(); return r.off || r.on ? r : null; }), { hint: false, checking: false, off: true, on: false });
  const early = await contrib.eval(`window.__omEarly`);
  console.log({ early });
  assert.deepEqual(early, { ext: null, hint: false, checking: true }, "the install note never shows with the extension; 'checking' stands in");
  // The settings tab is already open: it's brought forward and scrolled to the archive.org section.
  await opts.eval(`window.scrollTo(0, 0)`);
  await contrib.click('[data-om-open-options]');
  await until("settings show the archive.org section", () => opts.eval(`Math.abs(document.getElementById("archive").getBoundingClientRect().top) < 5 || null`));
  const nothingLeft = await fetch(`${api}/contribute/random`, { redirect: "manual" });
  assert.equal(nothingLeft.status, 303);
  assert.equal(nothingLeft.headers.get("location"), "/contribute?none=1");

  ok = true;
  console.log("\nPASS");
} finally {
  await b.close();
  server.kill();
  if (ok) rmSync(tmp, { recursive: true, force: true });
  else console.log(`kept ${tmp}`);
}
process.exit(ok ? 0 : 1);
