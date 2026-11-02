// End to end: passkey-protected keys in real Chrome, with a CDP virtual
// authenticator (PRF on) and a throwaway openmanuals-server. Not part of
// `npm test` (it needs Chrome and the Rust binaries).
//
//   cargo build --release -p openmanuals-server -p openmanuals-cli
//   cd extension && npm run build && node test/passkey-e2e.mjs [--headful] [--chrome /path/to/chrome] [--port 18731]
//
// Steps: create a key with the default flow (passkey only: no passphrase, no
// download); check the wrapped copy is local and on the server; sign a profile
// fact; upload an avatar through the options page (the server serves the
// cropped WebP, the profile is re-signed with avatar_url); uninstall and reinstall the extension (all its storage is wiped, the
// passkey stays in the authenticator); sign in with the passkey; check the
// fingerprint, non-extractability, and that the key signs facts the server
// accepts and `om verify` passes. Along the way: a second passkey added by
// unlocking with the first, a backup file made later by unlocking with a
// passkey, removing a passkey, and adding one with the backup file. Then the
// advanced flow: sign out, create a key with a passphrase backup and a
// passkey, sign out, restore it from the file.
import { Browser } from "./cdp.mjs";
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deflateSync, crc32 } from "node:zlib";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";

const arg = (name, dflt) => { const i = process.argv.indexOf(name); return i > 0 ? process.argv[i + 1] : dflt; };
const headless = !process.argv.includes("--headful");
const chrome = arg("--chrome", "google-chrome");
const port = Number(arg("--port", "18731"));
const repo = fileURLToPath(new URL("../../", import.meta.url));
const dist = fileURLToPath(new URL("../dist", import.meta.url));
const bin = (n) => join(repo, "target/release", n);
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const step = (s) => console.log(`\n== ${s}`);

/** A valid w×h RGBA PNG (a gradient), for the avatar upload. */
function png(w, h) {
  const chunk = (type, data) => {
    const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
    const td = Buffer.concat([Buffer.from(type), data]);
    const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td));
    return Buffer.concat([len, td, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4); ihdr[8] = 8; ihdr[9] = 6;
  const raw = Buffer.alloc((w * 4 + 1) * h);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) raw.set([x % 256, y % 256, 128, 255], y * (w * 4 + 1) + 1 + x * 4);
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk("IHDR", ihdr), chunk("IDAT", deflateSync(raw)), chunk("IEND", Buffer.alloc(0))]);
}

// ---- throwaway server --------------------------------------------------------------------
const tmp = mkdtempSync(join(process.env.SCRATCH ?? tmpdir(), "om-e2e-"));
mkdirSync(join(tmp, "data"));
execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "e2e server", "-f", join(tmp, "data/server.key")]);
const server = spawn(bin("openmanuals-server"), ["--data-dir", join(tmp, "data"), "--ledger-dir", join(tmp, "ledger"),
  "serve", "--bind", `127.0.0.1:${port}`, "--fold-interval", "0", "--fold-debounce", "0", "--verify-interval", "0"], { stdio: ["ignore", "ignore", "inherit"] });
const api = `http://127.0.0.1:${port}`;
for (let i = 0; ; i++) {
  if (await fetch(`${api}/api/server`).then((r) => r.ok).catch(() => false)) break;
  if (i > 100) throw new Error("server did not start");
  await wait(100);
}
const downloads = join(tmp, "downloads");
mkdirSync(downloads);

const b = await Browser.launch({ chrome, headless, extension: dist });
let ok = false;
try {
  const ID = b.extensionId;
  const OPTIONS = `chrome-extension://${ID}/options.html`;
  step(`extension ${ID}, server ${api}`);
  await b.send("Browser.setDownloadBehavior", { behavior: "allow", downloadPath: downloads });
  const page = await b.newPage("about:blank");
  const auth = await page.addAuthenticator();
  const ready = `document.readyState === "complete" && !!document.getElementById("createKey")`;
  const setServer = async () => {
    await page.eval(`chrome.storage.sync.set({ apiBase: ${JSON.stringify(api)} })`);
    await page.navigate(OPTIONS, ready);
    await wait(300);
  };
  /** Click a button and wait for a message element to say ok or bad. */
  const click = async (button, msg, ms = 20000) => {
    await page.eval(`document.getElementById(${JSON.stringify(msg)}).className = "msg"; document.getElementById(${JSON.stringify(button)}).click()`);
    const end = Date.now() + ms;
    while (Date.now() < end) {
      const r = await page.eval(`(() => { const e = document.getElementById(${JSON.stringify(msg)}); return { cls: e.className, text: e.textContent }; })()`);
      if (/\b(ok|bad)\b/.test(r.cls)) return { ok: r.cls.includes("ok"), text: r.text };
      await wait(100);
    }
    throw new Error(`no answer in #${msg}`);
  };
  const keyInIdb = `new Promise((res, rej) => { const r = indexedDB.open("openmanuals", 2); r.onsuccess = () => { const g = r.result.transaction("keys").objectStore("keys").get("primary"); g.onsuccess = () => res(g.result ? { fingerprint: g.result.fingerprint, extractable: g.result.privateKey.extractable, reason: g.result.reason } : null); g.onerror = () => rej(g.error); }; r.onerror = () => rej(r.error); })`;
  const serverWraps = async (fp) => (await (await fetch(`${api}/api/key-wrap/${fp}`)).json()).wraps;
  /** Sign and queue a profile fact through the service worker; wait for the server to accept it. */
  const profileFact = async (fp, name) => {
    const mine = async () => (await (await fetch(`${api}/api/feed`)).json()).facts.map((x) => x.fact).filter((f) => f.type === "identity_profile" && f.author === fp);
    const before = (await mine()).length;
    await page.eval(`chrome.runtime.sendMessage({ type: "saveProfile", name: ${JSON.stringify(name)}, claims: [] })`);
    for (let i = 0; i < 100; i++) {
      const facts = await mine();
      if (facts.length > before) return facts[facts.length - 1];
      await wait(200);
    }
    throw new Error("profile fact never reached the server");
  };

  // ---- 1. create a key with a passkey ----
  await page.navigate(OPTIONS, ready);
  await setServer();
  step("PRF capability as reported by the browser");
  console.log(await page.eval(`PublicKeyCredential.getClientCapabilities ? PublicKeyCredential.getClientCapabilities().then(c => c["extension:prf"]) : "n/a"`));
  step("create key with the default flow (passkey only)");
  const created = await click("createKey", "keyMsg", 60000);
  console.log(created);
  assert.ok(created.ok, created.text);
  const k1 = await page.eval(keyInIdb);
  console.log(k1);
  assert.equal(k1.extractable, false);
  const fp = k1.fingerprint;
  const creds = (await page.send("WebAuthn.getCredentials", { authenticatorId: auth })).credentials;
  assert.equal(creds.length, 1);
  assert.equal(creds[0].rpId, `chrome-extension://${ID}`, "the passkey's RP is the extension");
  assert.equal(Buffer.from(creds[0].userHandle, "base64").toString(), fp, "user.id is the fingerprint");
  const local = await page.eval(`chrome.storage.local.get("keyWraps").then(x => x.keyWraps)`);
  assert.equal(local.length, 1);
  const onServer = await serverWraps(fp);
  assert.equal(onServer.length, 1);
  assert.equal(onServer[0].credential, local[0].credential);
  await wait(1000);
  assert.deepEqual(readdirSync(downloads), [], "nothing downloaded");
  console.log({ fp, credential: local[0].credential });

  step("the passkey list shows it, on the server");
  await wait(500);
  const list = await page.eval(`[...document.querySelectorAll("#passkeys li")].map(li => li.textContent)`);
  console.log(list);
  assert.ok(list.length === 1 && list[0].includes("on server"));

  step("adding a second passkey on the same authenticator is refused (excludeCredentials)");
  const again = await click("addPasskey", "passkeyMsg");
  console.log(again);
  assert.ok(!again.ok && /already holds a passkey/.test(again.text));

  step("a second passkey on another authenticator: unlock with the first, wrap under the second");
  // A security key, "untouched" until the unlock assertion is done: touching a
  // key that lacks the credential makes Chrome fail the get(), as with a real one.
  const auth2 = await page.addAuthenticator({ transport: "usb", automaticPresenceSimulation: false });
  const touch = (msg) => {
    if (msg.method !== "WebAuthn.credentialAsserted" || msg.params.authenticatorId !== auth) return;
    b.listeners.splice(b.listeners.indexOf(touch), 1);
    void page.send("WebAuthn.setAutomaticPresenceSimulation", { authenticatorId: auth2, enabled: true });
  };
  b.listeners.push(touch);
  const added = await click("addPasskey", "passkeyMsg");
  console.log(added);
  assert.ok(added.ok, added.text);
  assert.equal((await page.send("WebAuthn.getCredentials", { authenticatorId: auth2 })).credentials.length, 1);
  assert.equal((await serverWraps(fp)).length, 2);

  step("sign a fact with the new key");
  const f1 = await profileFact(fp, "E2E before");
  console.log({ type: f1.type, author: f1.author });

  step("unsaved profile edits are flagged until saved");
  await page.navigate(OPTIONS, ready);
  await wait(800);
  const dirty = () => page.eval(`!document.getElementById("profDirty").classList.contains("hidden")`);
  assert.equal(await page.eval(`document.getElementById("profName").value`), "E2E before", "the saved name is shown");
  assert.equal(await dirty(), false);
  await page.eval(`(() => { const e = document.getElementById("profName"); e.value = "E2E edited"; e.dispatchEvent(new Event("input")); })()`);
  assert.equal(await dirty(), true, "typing a different name shows Unsaved changes");
  await page.eval(`(() => { const e = document.getElementById("profName"); e.value = "E2E before"; e.dispatchEvent(new Event("input")); })()`);
  assert.equal(await dirty(), false, "typing it back clears it");
  await page.eval(`(() => { const e = document.getElementById("profName"); e.value = "E2E edited"; e.dispatchEvent(new Event("input")); })()`);
  const savedEdit = await click("saveProfile", "profMsg");
  assert.ok(savedEdit.ok, savedEdit.text);
  assert.equal(await dirty(), false, "saving clears it");

  step("upload an avatar: cropped, resized, WebP; fact first, then the bytes");
  const pngPath = join(tmp, "photo.png");
  writeFileSync(pngPath, png(400, 300));
  await page.navigate(OPTIONS, ready);
  await wait(500);
  const { root: r0 } = await page.send("DOM.getDocument");
  const { nodeId: fileNode } = await page.send("DOM.querySelector", { nodeId: r0.nodeId, selector: "#avatarFile" });
  await page.send("DOM.setFileInputFiles", { nodeId: fileNode, files: [pngPath] });
  await page.eval(`document.getElementById("avatarMsg").className = "msg"; document.getElementById("avatarFile").dispatchEvent(new Event("change"))`);
  let served = null;
  for (let i = 0; i < 100 && !served; i++) {
    const r = await fetch(`${api}/avatar/${fp}`);
    if (r.ok) served = { type: r.headers.get("content-type"), bytes: Buffer.from(await r.arrayBuffer()) };
    else await wait(200);
  }
  console.log({ avatarMsg: await page.eval(`document.getElementById("avatarMsg").textContent`), served: served && { type: served.type, size: served.bytes.length } });
  assert.ok(served, "the server serves the avatar");
  assert.equal(served.type, "image/webp");
  assert.equal(served.bytes.subarray(0, 4).toString(), "RIFF");
  assert.ok(served.bytes.length <= 128 * 1024);
  const vp8x = served.bytes.subarray(12, 16).toString();
  console.log({ webpChunk: vp8x });
  const feed = (await (await fetch(`${api}/api/feed`)).json()).facts.map((x) => x.fact);
  assert.ok(feed.some((f) => f.type === "avatar" && f.author === fp && f.body.mime === "image/webp"), "avatar fact on the server");
  const prof = feed.filter((f) => f.type === "identity_profile" && f.author === fp).pop();
  const payload = JSON.parse(Buffer.from(prof.body.jws.split(".")[1], "base64url").toString());
  assert.equal(payload["http://ariadne.id/avatar_url"], `${api}/avatar/${fp}`, "profile re-signed with avatar_url");

  // ---- 2. wipe: uninstall and reinstall (same path, same ID) ----
  step("uninstall + reinstall");
  await page.navigate("about:blank", "true");
  await b.send("Extensions.uninstall", { id: ID });
  const reId = await b.loadExtension(dist);
  assert.equal(reId, ID);
  await page.navigate(OPTIONS, ready);
  assert.equal(await page.eval(keyInIdb), null, "IndexedDB is empty");
  assert.equal(await page.eval(`chrome.storage.local.get("keyWraps").then(x => x.keyWraps ?? null)`), null, "local wraps are gone");
  assert.equal((await page.send("WebAuthn.getCredentials", { authenticatorId: auth })).credentials.length, 1, "the passkey is still in the authenticator");
  await setServer();

  // ---- 3. restore with the passkey (wrap from the server) ----
  step("sign in with passkey");
  const restored = await click("signInPasskey", "keyMsg");
  console.log(restored);
  assert.ok(restored.ok, restored.text);
  assert.ok(restored.text.includes("the server"));
  const k2 = await page.eval(keyInIdb);
  console.log(k2);
  assert.equal(k2.fingerprint, fp, "same fingerprint");
  assert.equal(k2.extractable, false, "non-extractable after restore");
  assert.equal(k2.reason, "passkey");
  assert.equal(await page.eval(`document.getElementById("fingerprint").textContent`), fp);

  step("the restored key signs facts the server accepts and om verify passes");
  const f2 = await profileFact(fp, "E2E after");
  const facts = join(tmp, "facts.jsonl");
  writeFileSync(facts, [f1, f2].map((f) => JSON.stringify(f)).join("\n") + "\n");
  console.log(execFileSync(bin("om"), ["verify", facts]).toString().trim());

  // ---- 4. a backup file made later; remove a passkey, add one back from the file ----
  step("download a backup file, unlocking with a passkey");
  const jsons = () => readdirSync(downloads).filter((f) => f.endsWith(".json"));
  await page.eval(`document.getElementById("newBackupPass").value = document.getElementById("newBackupPass2").value = "e2e passphrase"`);
  const made = await click("makeBackup", "backupMsg", 60000);
  console.log(made);
  assert.ok(made.ok, made.text);
  for (let i = 0; i < 50 && !jsons().length; i++) await wait(100);
  const backupPath = join(downloads, jsons()[0]);
  const backup = JSON.parse(readFileSync(backupPath, "utf8"));
  assert.equal(backup.v, 2);
  assert.equal(backup.fingerprint, fp);
  assert.equal(backup.wraps.length, 2);
  const backupCopy = join(tmp, "backup.json");
  writeFileSync(backupCopy, readFileSync(backupPath));
  rmSync(backupPath);

  step("remove the first passkey");
  await wait(500);
  await page.eval(`window.confirm = () => true`);
  const firstRow = await page.eval(`document.querySelector("#passkeys li span.u").textContent`);
  const first = (await serverWraps(fp)).find((w) => firstRow.includes(`(${w.credential.slice(0, 10)}…)`)).credential;
  await page.eval(`document.querySelector("#passkeys li button").click()`);
  for (let i = 0; i < 50 && (await serverWraps(fp)).length > 1; i++) await wait(100);
  const left = await serverWraps(fp);
  assert.equal(left.length, 1, "deleted on the server");
  assert.notEqual(left[0].credential, first);
  assert.deepEqual((await page.eval(`chrome.storage.local.get("keyWraps").then(x => x.keyWraps)`)).map((w) => w.credential), [left[0].credential], "deleted locally");

  step("add a passkey with the backup file + passphrase");
  await page.send("WebAuthn.setAutomaticPresenceSimulation", { authenticatorId: auth2, enabled: false });
  const { root } = await page.send("DOM.getDocument");
  const { nodeId } = await page.send("DOM.querySelector", { nodeId: root.nodeId, selector: "#pkBackupFile" });
  await page.send("DOM.setFileInputFiles", { nodeId, files: [backupCopy] });
  await page.eval(`document.getElementById("pkBackupPass").value = "e2e passphrase"`);
  const viaFile = await click("addPasskeyBackup", "passkeyMsg", 60000);
  console.log(viaFile);
  assert.ok(viaFile.ok, viaFile.text);
  assert.equal((await serverWraps(fp)).length, 2);
  // CDP's "allow" download behavior saves under the same name, replacing the first file.
  const newest = () => jsons().map((f) => JSON.parse(readFileSync(join(downloads, f), "utf8")))[0];
  let updated;
  for (let i = 0; i < 50 && !(updated = newest()); i++) await wait(100);
  assert.ok(updated, "updated backup downloaded");
  assert.equal(updated.ciphertext, backup.ciphertext);
  assert.deepEqual(updated.wraps.map((w) => w.credential).sort(), (await serverWraps(fp)).map((w) => w.credential).sort(), "updated backup has the current passkeys");
  for (const f of jsons()) rmSync(join(downloads, f));

  // ---- 5. advanced: a key with a passphrase backup file ----
  step("sign out, then create a key with a backup file and a passkey");
  await page.eval(`document.getElementById("forgetKey").click()`);
  for (let i = 0; i < 50 && (await page.eval(keyInIdb)); i++) await wait(100);
  assert.equal(await page.eval(keyInIdb), null, "signed out");
  await page.eval(`document.getElementById("advanced").open = true; document.getElementById("passphrase").value = document.getElementById("passphrase2").value = "adv passphrase"; document.getElementById("usePasskey").checked = true`);
  const adv = await click("createKeyBackup", "advKeyMsg", 60000);
  console.log(adv);
  assert.ok(adv.ok, adv.text);
  const k3 = await page.eval(keyInIdb);
  assert.notEqual(k3.fingerprint, fp);
  for (let i = 0; i < 50 && !jsons().length; i++) await wait(100);
  const advPath = join(downloads, jsons()[0]);
  const advBackup = JSON.parse(readFileSync(advPath, "utf8"));
  assert.equal(advBackup.fingerprint, k3.fingerprint);
  assert.equal(advBackup.wraps.length, 1);
  assert.equal((await serverWraps(k3.fingerprint)).length, 1);

  step("sign out, restore it from the file and passphrase");
  await page.eval(`document.getElementById("forgetKey").click()`);
  for (let i = 0; i < 50 && (await page.eval(keyInIdb)); i++) await wait(100);
  const doc2 = await page.send("DOM.getDocument");
  const file2 = await page.send("DOM.querySelector", { nodeId: doc2.root.nodeId, selector: "#backupFile" });
  await page.send("DOM.setFileInputFiles", { nodeId: file2.nodeId, files: [advPath] });
  await page.eval(`document.getElementById("importPass").value = "adv passphrase"`);
  const imp = await click("importKey", "importMsg", 60000);
  console.log(imp);
  assert.ok(imp.ok, imp.text);
  const k4 = await page.eval(keyInIdb);
  assert.equal(k4.fingerprint, k3.fingerprint);
  assert.equal(k4.extractable, false);
  ok = true;
  console.log("\nPASS");
} finally {
  await b.close();
  server.kill();
  if (ok) rmSync(tmp, { recursive: true, force: true });
  else console.log(`kept ${tmp}`);
}
process.exit(ok ? 0 : 1);
