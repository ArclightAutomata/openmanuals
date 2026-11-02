// End to end: the side panel on the server's pages. Chrome with the extension
// and a throwaway openmanuals-server. Not part of `npm test`.
//
//   cargo build --release -p openmanuals-server
//   cd extension && npm run build && node test/panel-e2e.mjs [--headful] [--chrome /path/to/chrome] [--port 18733]
//
// Steps: create a key; sign facts as that key and post facts from another
// key; open the ledger page and check it reports its hooks for the tab; click
// a row's button for real and check the side panel opens on that row (Chrome
// 153 opens it even headless; if a build can't, the test falls back to the
// same page in a tab with ?tab=<id>); check every row is fetched and
// verified, yours marked; retract one of your facts and undo it (nothing is
// sent), retract another and let the undo lapse (the retraction reaches the
// server); select the other key's facts and report them in one confirmed bulk
// action (one bundle of label facts); and check the panel follows the tab to
// another page.
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
const port = Number(arg("--port", "18733"));
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

await ensureWasm(readFileSync(join(repo, "extension/vendor/openmanuals-wasm/openmanuals_wasm_bg.wasm")));
const vectors = JSON.parse(readFileSync(join(repo, "crates/openmanuals-core/vectors/vectors.json"), "utf8"));
const other = await keyFromEd25519Seed(hexToBytes(vectors.keys[0].seed_hex), vectors.keys[0].jwk.x);

// ---- throwaway server --------------------------------------------------------------------
const tmp = mkdtempSync(join(process.env.SCRATCH ?? tmpdir(), "om-panel-e2e-"));
mkdirSync(join(tmp, "data"));
execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "e2e server", "-f", join(tmp, "data/server.key")]);
const server = spawn(join(repo, "target/release/openmanuals-server"), ["--data-dir", join(tmp, "data"), "--ledger-dir", join(tmp, "ledger"),
  "serve", "--bind", `127.0.0.1:${port}`, "--fold-interval", "0", "--fold-debounce", "1", "--fold-max-delay", "2", "--verify-interval", "0"], { stdio: ["ignore", "ignore", "inherit"] });
const api = `http://127.0.0.1:${port}`;
await until("server start", async () => (await fetch(`${api}/api/server`)).ok);
const feed = async () => (await (await fetch(`${api}/api/feed`)).json()).facts.map((x) => x.fact);

const b = await Browser.launch({ chrome, headless, extension: dist });
let ok = false;
try {
  const ID = b.extensionId;
  const OPTIONS = `chrome-extension://${ID}/options.html`;
  const opts = await b.newPage("about:blank");
  const ready = `document.readyState === "complete" && !!document.getElementById("createKey")`;
  await opts.navigate(OPTIONS, ready);
  await opts.eval(`chrome.storage.sync.set({ apiBase: ${JSON.stringify(api)} })`);
  await opts.navigate(OPTIONS, ready);

  step("create a key (passphrase, no passkey)");
  await opts.eval(`document.getElementById("advanced").open = true; document.getElementById("passphrase").value = document.getElementById("passphrase2").value = "panel e2e pass"; document.getElementById("usePasskey").checked = false; document.getElementById("createKeyBackup").click()`);
  const created = await until("key created", () => opts.eval(`(() => { const e = document.getElementById("advKeyMsg"); return /\\b(ok|bad)\\b/.test(e.className) ? { ok: e.className.includes("ok"), text: e.textContent } : null; })()`), 60000);
  assert.ok(created.ok, created.text);
  const me = await opts.eval(`chrome.runtime.sendMessage({ type: "getIdentity" }).then((i) => i.fingerprint)`);

  step("facts: two of mine through the extension, three of the other key's");
  const mine = [
    { type: "product", at: "2026-10-31T12:00:00Z", body: { brand: "Acme", model: "Keep" } },
    { type: "product", at: "2026-10-31T12:00:00Z", body: { brand: "Acme", model: "Drop" } },
  ];
  await opts.eval(`chrome.runtime.sendMessage({ type: "submitFacts", facts: ${JSON.stringify(mine)}, label: "e2e" }).then(() => chrome.runtime.sendMessage({ type: "flushOutbox" }))`);
  const theirs = [];
  for (const model of ["S1", "S2", "S3"]) theirs.push(await signFact(other, { type: "product", at: "2026-10-31T12:00:00Z", body: { brand: "Spam", model } }));
  assert.equal((await fetch(`${api}/api/facts`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(theirs) })).status, 202);
  const theirIds = await Promise.all(theirs.map(factId));
  const myIds = await until("my facts on the server", async () => {
    const fs = (await feed()).filter((x) => x.author === me && x.type === "product");
    return fs.length === 2 ? Object.fromEntries(await Promise.all(fs.map(async (f) => [f.body.model, await factId(f)]))) : null;
  });
  await until("ledger lists them", async () => { const h = await (await fetch(`${api}/ledger`)).text(); return [...theirIds, myIds.Keep, myIds.Drop].every((x) => h.includes(x)); });

  step("the ledger page reports its hooks for its tab");
  const site = await b.newPage(`${api}/ledger`);
  await until("buttons added", () => site.eval(`document.querySelectorAll("button.om-act").length > 0`));
  const tabId = await until("site tab id", () => opts.eval(`chrome.tabs.query({}).then((ts) => ts.find((t) => (t.url ?? "").startsWith(${JSON.stringify(api + "/ledger")}))?.id ?? null)`));
  const page = await until("page stored", () => opts.eval(`chrome.storage.session.get("sitePage:${tabId}").then((x) => x["sitePage:${tabId}"] ?? null)`));
  const hooks = await site.eval(`document.querySelectorAll("li.fact-row[data-om-fact]:not([data-om-hidden])").length`);
  console.log({ tabId, items: page.items.length, hooks });
  assert.ok(page.items.length >= 5 && page.items.length >= hooks);

  step("a real click on a row's button: side panel, or the confirm window as the fallback");
  const panelTargets = () => [...b.targets.values()].filter((t) => t.url.startsWith(`chrome-extension://${ID}/panel.html`));
  const confirmTargets = () => [...b.targets.values()].filter((t) => t.url.startsWith(`chrome-extension://${ID}/confirm.html`));
  await site.click(`[data-om-fact="${myIds.Keep}"] .fact-side button.om-act`);
  await until("panel or confirm", async () => panelTargets().length || confirmTargets().length);
  const viaPanel = panelTargets().length > 0;
  console.log({ sidePanelOpened: viaPanel, confirmWindow: confirmTargets().length > 0 });
  let panel;
  if (viaPanel) {
    panel = await b.attach(panelTargets()[0].targetId);
    assert.equal(await opts.eval(`chrome.storage.session.get("panelFocus:${tabId}").then((x) => x["panelFocus:${tabId}"]?.key)`), myIds.Keep);
  } else {
    // Headless Chrome has no side panel; open the same page in a tab.
    panel = await b.newPage(`chrome-extension://${ID}/panel.html?tab=${tabId}`);
  }

  step("every row fetched and verified; mine marked; the right actions");
  const rows = () => panel.eval(`[...document.querySelectorAll("li.row")].map((li) => ({ key: li.dataset.key, cls: li.className, title: li.querySelector(".title").textContent, you: !!li.querySelector(".tag.you"), acts: [...li.querySelectorAll(".acts button")].map((b) => b.textContent) }))`);
  const shown = await until("rows verified", async () => { const r = await rows(); return r.length >= 5 && r.every((x) => x.title !== "Checking…") ? r : null; });
  const byKey = Object.fromEntries(shown.map((r) => [r.key, r]));
  console.log(shown.filter((r) => [myIds.Keep, myIds.Drop, ...theirIds].includes(r.key)));
  for (const k of [myIds.Keep, myIds.Drop]) assert.deepEqual([byKey[k].you, byKey[k].acts, byKey[k].cls.startsWith("row state-ok")], [true, ["Retract"], true]);
  for (const k of theirIds) assert.deepEqual([byKey[k].you, byKey[k].acts, byKey[k].cls.startsWith("row state-ok")], [false, ["Report"], true]);

  const clickIn = (key, text) => panel.eval(`[...document.querySelector('li.row[data-key="${key}"]').querySelectorAll("button")].find((b) => b.textContent === ${JSON.stringify(text)}).click()`);
  const retractsOf = async (id) => (await feed()).filter((x) => x.type === "retract" && x.author === me && x.body.fact === id);

  step("retract, then undo: nothing is sent");
  await clickIn(myIds.Keep, "Retract");
  assert.match(await panel.eval(`document.querySelector('li.row[data-key="${myIds.Keep}"] .pending').textContent`), /^Retracting in \d s/);
  await wait(1500);
  await clickIn(myIds.Keep, "Undo");
  assert.equal(await panel.eval(`!!document.querySelector('li.row[data-key="${myIds.Keep}"] .pending')`), false);
  await wait(9000);
  assert.equal((await retractsOf(myIds.Keep)).length, 0, "undone: no retraction");

  step("retract and let the undo lapse: the retraction is sent");
  await clickIn(myIds.Drop, "Retract");
  await until("retraction on the server", async () => (await retractsOf(myIds.Drop)).length === 1, 20000);
  await until("row marked", () => panel.eval(`!!document.querySelector('li.row[data-key="${myIds.Drop}"] .tag.done')`));
  console.log(await panel.eval(`document.getElementById("msg").textContent`));

  step("bulk: select the other key's facts, report them as spam with one confirmation");
  await panel.eval(`(() => { const s = document.getElementById("pick"); s.value = "author:${other.fingerprint}"; s.dispatchEvent(new Event("change")); })()`);
  const bulk = await panel.eval(`({ count: document.getElementById("count").textContent, retract: document.getElementById("bulkRetract").textContent, retractOff: document.getElementById("bulkRetract").disabled, report: document.getElementById("bulkReport").textContent })`);
  console.log(bulk);
  assert.deepEqual(bulk, { count: "3 selected", retract: "Retract 0", retractOff: true, report: "Report 3 as spam" });
  await panel.eval(`document.getElementById("bulkReport").click()`);
  const ask = await panel.eval(`({ shown: !document.getElementById("confirm").classList.contains("hidden"), text: document.getElementById("confirmText").textContent, examples: document.querySelectorAll("#confirmList li").length })`);
  console.log(ask);
  assert.deepEqual(ask, { shown: true, text: "Report 3 as spam?", examples: 3 });
  const before = (await feed()).filter((x) => x.type === "label" && x.author === me).length;
  await panel.eval(`document.getElementById("confirmGo").click()`);
  const labels = await until("three labels", async () => { const l = (await feed()).filter((x) => x.type === "label" && x.author === me); return l.length >= before + 3 ? l : null; });
  assert.deepEqual(labels.map((l) => [l.body.target, l.body.value]).sort(), theirIds.map((t) => [t, "spam"]).sort());
  const msg = await until("bulk outcome", () => panel.eval(`(() => { const e = document.getElementById("msg"); return /3 sent/.test(e.textContent) ? e.textContent : null; })()`));
  console.log(msg);
  const history = await opts.eval(`chrome.runtime.sendMessage({ type: "outboxState" }).then((s) => s.history.map((h) => h.label))`);
  assert.ok(history.includes("3 reports from the side panel"), "one bundle");

  step("the panel follows the tab to another page");
  await site.navigate(`${api}/fact/${myIds.Keep}`, `document.readyState === "complete"`);
  await until("panel shows the fact page", async () => { const r = await rows(); return r.length === 1 && r[0].key === myIds.Keep; });

  ok = true;
  console.log("\nPASS");
} finally {
  await b.close();
  server.kill();
  if (ok) rmSync(tmp, { recursive: true, force: true });
  else console.log(`kept ${tmp}`);
}
process.exit(ok ? 0 : 1);
