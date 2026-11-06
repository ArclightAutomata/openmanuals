// End to end: editing a manual from its page. Chrome with the extension and a
// throwaway openmanuals-server. Not part of `npm test`.
//
//   cargo build --release -p openmanuals-server
//   cd extension && npm run build && node test/edit-e2e.mjs [--headful] [--chrome /path/to/chrome] [--port 18734]
//
// Steps: create a key; post a manual with one model listed by you (a typo)
// and one by another key; open the manual page and check its brand and model
// links and the edit buttons; click a model's edit button for real and check
// the editor opens on that model (side panel, the edit window, or the panel
// in a tab when neither opens); fix the title, the type and the typo, and try
// to remove the other key's model; check the review, sign and send, and check
// the facts on the server and, after the build, the page; and the edit
// window's "+ Add model".
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
const port = Number(arg("--port", "18734"));
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

const om = await ensureWasm(readFileSync(join(repo, "extension/vendor/openmanuals-wasm/openmanuals_wasm_bg.wasm")));
const vectors = JSON.parse(readFileSync(join(repo, "crates/openmanuals-core/vectors/vectors.json"), "utf8"));
const other = await keyFromEd25519Seed(hexToBytes(vectors.keys[0].seed_hex), vectors.keys[0].jwk.x);

// ---- throwaway server --------------------------------------------------------------------
const tmp = mkdtempSync(join(process.env.SCRATCH ?? tmpdir(), "om-edit-e2e-"));
mkdirSync(join(tmp, "data"));
execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "e2e server", "-f", join(tmp, "data/server.key")]);
const server = spawn(join(repo, "target/release/openmanuals-server"), ["--data-dir", join(tmp, "data"), "--ledger-dir", join(tmp, "ledger"),
  "serve", "--bind", `127.0.0.1:${port}`, "--fold-interval", "0", "--fold-debounce", "1", "--fold-max-delay", "2", "--verify-interval", "0"], { stdio: ["ignore", "ignore", "inherit"] });
const api = `http://127.0.0.1:${port}`;
await until("server start", async () => (await fetch(`${api}/api/server`)).ok);
const feed = async () => (await (await fetch(`${api}/api/feed`)).json()).facts.map((x) => x.fact);
const html = async (path) => (await fetch(`${api}${path}`)).text();

const M = "01M69JSKVAY3Z9RCYD22GCY64Q";
const WRONG = om.product_key("Philips", "14PV1OO");
const KEPT = om.product_key("Philips", "21PT1354");
const RIGHT = om.product_key("Philips", "14PV100");

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
  await opts.eval(`document.getElementById("advanced").open = true; document.getElementById("passphrase").value = document.getElementById("passphrase2").value = "edit e2e pass"; document.getElementById("usePasskey").checked = false; document.getElementById("createKeyBackup").click()`);
  const created = await until("key created", () => opts.eval(`(() => { const e = document.getElementById("advKeyMsg"); return /\\b(ok|bad)\\b/.test(e.className) ? { ok: e.className.includes("ok"), text: e.textContent } : null; })()`), 60000);
  assert.ok(created.ok, created.text);
  const me = await opts.eval(`chrome.runtime.sendMessage({ type: "getIdentity" }).then((i) => i.fingerprint)`);

  step("a manual: your model (a typo) and another key's");
  const at = "2026-11-05T12:00:00Z";
  const mine = [
    { type: "manual", at, body: { id: M, title: "Philips 14PV1OO manual", doc_type: "user" } },
    { type: "product", at, body: { brand: "Philips", model: "14PV1OO" } },
    { type: "covers", at, body: { manual: M, product: WRONG } },
  ];
  await opts.eval(`chrome.runtime.sendMessage({ type: "submitFacts", facts: ${JSON.stringify(mine)}, label: "e2e" }).then(() => chrome.runtime.sendMessage({ type: "flushOutbox" }))`);
  const theirs = [
    await signFact(other, { type: "product", at, body: { brand: "Philips", model: "21PT1354" } }),
    await signFact(other, { type: "covers", at, body: { manual: M, product: KEPT } }),
  ];
  assert.equal((await fetch(`${api}/api/facts`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(theirs) })).status, 202);
  const myCovers = await until("my covers on the server", async () => { const f = (await feed()).find((x) => x.author === me && x.type === "covers"); return f ? factId(f) : null; });
  await until("manual page built", async () => { const h = await html(`/manual/${M}`); return h.includes(">14PV1OO</a>") && h.includes(">21PT1354</a>"); });

  step("the page: brand and model links; edit buttons with the extension");
  const site = await b.newPage(`${api}/manual/${M}`);
  await until("edit buttons", () => site.eval(`document.querySelectorAll("button.om-edit").length === 4`));
  const page = await site.eval(`({
    brands: [...document.querySelectorAll(".product-chip .product-brand")].map((a) => a.getAttribute("href")),
    models: [...document.querySelectorAll(".product-chip .product-model")].map((a) => a.getAttribute("href")),
    buttons: [...document.querySelectorAll("button.om-edit")].map((b) => b.textContent),
  })`);
  console.log(page);
  assert.deepEqual(page.brands, ["/manuals?brand=philips", "/manuals?brand=philips"]);
  assert.deepEqual(page.models, ["/product/Philips/14PV1OO", "/product/Philips/21PT1354"]);
  assert.deepEqual(page.buttons, ["✎", "✎", "✎", "+ Add model"]);
  const tabId = await until("site tab id", () => opts.eval(`chrome.tabs.query({}).then((ts) => ts.find((t) => (t.url ?? "").startsWith(${JSON.stringify(`${api}/manual/`)}))?.id ?? null)`));
  const stored = await until("page stored", () => opts.eval(`chrome.storage.session.get("sitePage:${tabId}").then((x) => x["sitePage:${tabId}"] ?? null)`));
  assert.equal(stored.items.filter((a) => a.action === "manual").length, 1, "the manual's edit hooks are one item");

  step("a real click on the typo's edit button opens the editor on it");
  const at_ = (prefix) => [...b.targets.values()].filter((t) => t.url.startsWith(`chrome-extension://${ID}/${prefix}`));
  await site.click(`[data-om-edit=${JSON.stringify(`product:${WRONG}`)}] button.om-edit`);
  await until("panel or edit window", async () => at_("panel.html").length || at_("edit.html").length, 5000).catch(() => null);
  let ed, via;
  if (at_("panel.html").length) { ed = await b.attach(at_("panel.html")[0].targetId); via = "side panel"; }
  else if (at_("edit.html").length) { ed = await b.attach(at_("edit.html")[0].targetId); via = "edit window"; }
  else { ed = await b.newPage(`chrome-extension://${ID}/panel.html?tab=${tabId}`); via = "panel in a tab"; }
  console.log({ via });
  const form = () => ed.eval(`(() => {
    const f = document.querySelector(".om-editor .ed-form");
    if (!f || f.classList.contains("hidden")) return null;
    return {
      title: document.getElementById("edTitle").value, type: document.getElementById("edType").value,
      rows: [...document.querySelectorAll(".ed-models li[data-key]")].map((li) => ({ key: li.dataset.key, brand: li.querySelectorAll("input")[0].value, model: li.querySelectorAll("input")[1].value, who: li.querySelector(".ed-who").textContent })),
      focused: document.activeElement?.closest?.("li")?.dataset.key ?? document.activeElement?.id ?? null,
    };
  })()`);
  const start = await until("editor loaded", form);
  console.log(start);
  assert.deepEqual([start.title, start.type], ["Philips 14PV1OO manual", "user"]);
  assert.deepEqual(start.rows.map((r) => [r.key, r.brand, r.model, r.who]), [[WRONG, "Philips", "14PV1OO", "listed by you"], [KEPT, "Philips", "21PT1354", "listed by others"]]);
  if (via !== "panel in a tab") assert.equal(start.focused, WRONG, "the clicked model has the cursor");

  step("fix the title, the type and the typo; try to remove the other key's model");
  await ed.eval(`(() => {
    const set = (el, v) => { el.value = v; el.dispatchEvent(new Event(el.tagName === "SELECT" ? "change" : "input")); };
    set(document.getElementById("edTitle"), "Philips 14PV100 service manual");
    set(document.getElementById("edType"), "service");
    set(document.querySelector('.ed-models li[data-key=${JSON.stringify(WRONG)}]').querySelectorAll("input")[1], "14PV100");
    [...document.querySelector('.ed-models li[data-key=${JSON.stringify(KEPT)}]').querySelectorAll("button")].find((b) => b.textContent === "Remove").click();
    [...document.querySelectorAll(".om-editor button")].find((b) => b.textContent === "Review changes").click();
  })()`);
  const rev = await until("review", () => ed.eval(`(() => { const r = document.querySelector(".ed-review"); return r && !r.classList.contains("hidden") ? { q: r.querySelector(".ed-q").textContent, changes: [...r.querySelectorAll("li")].map((li) => li.textContent), notes: [...r.querySelectorAll(".ed-note")].map((p) => p.textContent) } : null; })()`));
  console.log(rev);
  assert.deepEqual(rev, {
    q: "Sign and send 4 facts?",
    changes: ["Title: “Philips 14PV1OO manual” → “Philips 14PV100 service manual”", "Type: User manual → Service manual", "Remove model: Philips 14PV1OO", "Add model: Philips 14PV100"],
    notes: ["Philips 21PT1354 was listed by someone else, so you can't remove it."],
  });

  step("sign and send");
  await ed.eval(`[...document.querySelectorAll(".ed-review button")].find((b) => b.textContent === "Sign and send").click()`);
  const sent = await until("edit facts on the server", async () => {
    const f = (await feed()).filter((x) => x.author === me);
    const man = f.find((x) => x.type === "manual" && x.body.title === "Philips 14PV100 service manual");
    const ret = f.find((x) => x.type === "retract" && x.body.fact === myCovers);
    const cov = f.find((x) => x.type === "covers" && x.body.product === RIGHT);
    const prod = f.find((x) => x.type === "product" && x.body.model === "14PV100");
    return man && ret && cov && prod ? { man: man.body, cov: cov.body } : null;
  });
  assert.deepEqual(sent, { man: { id: M, title: "Philips 14PV100 service manual", doc_type: "service" }, cov: { manual: M, product: RIGHT } });
  const msg = await until("sent message", () => ed.eval(`(() => { const e = document.querySelector(".om-editor .ed-msg"); return e?.classList.contains("ok") ? e.textContent : null; })()`));
  console.log(msg);
  const after = await until("editor reloaded", async () => { const f = await form(); return f && f.title === "Philips 14PV100 service manual" ? f : null; });
  assert.deepEqual(after.rows.map((r) => r.model).sort(), ["14PV100", "21PT1354"]);

  step("after the build, the page shows the edit");
  await until("page updated", async () => {
    const h = await html(`/manual/${M}`);
    return h.includes(">Philips 14PV100 service manual<") && h.includes(">14PV100</a>") && h.includes(">21PT1354</a>") && !h.includes(">14PV1OO</a>") && h.includes(`<span class="doc-tag">service</span>`);
  }, 30000);

  step("the edit window (when the side panel can't open): + Add model starts a new row");
  const win = await b.newPage(`chrome-extension://${ID}/edit.html?action=manual&manual=${M}&focus=add`);
  const added = await until("edit window loaded", () => win.eval(`(() => {
    const f = document.querySelector(".om-editor .ed-form");
    if (!f || f.classList.contains("hidden")) return null;
    const last = [...document.querySelectorAll(".ed-models li")].pop();
    return { title: document.getElementById("edTitle").value, rows: document.querySelectorAll(".ed-models li").length, newRow: last.querySelector(".ed-who").textContent, brand: last.querySelectorAll("input")[0].value, focused: document.activeElement === last.querySelectorAll("input")[1] };
  })()`));
  console.log(added);
  assert.deepEqual(added, { title: "Philips 14PV100 service manual", rows: 3, newRow: "new", brand: "Philips", focused: true });

  ok = true;
  console.log("\nPASS");
} finally {
  await b.close();
  server.kill();
  if (ok) rmSync(tmp, { recursive: true, force: true });
  else console.log(`kept ${tmp}`);
}
process.exit(ok ? 0 : 1);
