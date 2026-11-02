import { BUILD_ID } from "../core/build-id.ts";
import { aspeDomain, getSettings, setSettings } from "../core/config.ts";
import type { Identity, OutboxEntry, HistoryEntry } from "../core/messages.ts";
import { aspeUri } from "../core/asp.ts";
import { getMuteState, setMuted } from "../background/mute.ts";
import { addPasskey, createAndStore, downloadBackup, forgetKey, importAndStore, listPasskeys, makeBackup, removePasskey, restoreWithPasskey } from "../identity/manage.ts";
import { prfCapability } from "../identity/passkey.ts";
import { hostsFor, matchClaim, SERVICES, verifyClaim } from "../identity/proofs.ts";
import { claimDisplay, isOutline, pickProvider, type Icon } from "../core/claim-display.ts";
import { AVATAR_MAX_BYTES, AVATAR_SIZE, avatarSrc, cropSquare, githubAvatarUrl, type AvatarBody } from "../core/avatar.ts";
import { bytesToB64 } from "../core/b64.ts";
import { sha256Hex } from "../core/hash.ts";

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const val = (id: string) => $<HTMLInputElement>(id).value.trim();
const say = (id: string, text: string, ok?: boolean) => { const e = $(id); e.textContent = text; e.className = "msg " + (ok === undefined ? "" : ok ? "ok" : "bad"); };
const send = <T,>(msg: unknown) => chrome.runtime.sendMessage(msg).catch((e) => ({ error: String(e) })) as Promise<T>;

// ---- same build as the service worker? --------------------------------------------------
void send<{ build?: string }>({ type: "buildId" }).then((r) => {
  if (r?.build !== BUILD_ID) $("staleBuild").classList.remove("hidden");
});

// ---- copy to clipboard ---------------------------------------------------------------
let toastTimer: ReturnType<typeof setTimeout> | undefined;
function toast(text: string) {
  const el = $("toast");
  el.textContent = text;
  el.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), 1800);
}
for (const [id, what] of [["fingerprint", "Fingerprint"], ["aspe", "Identifier"]] as const) {
  const el = $(id);
  const copy = async () => {
    const text = el.textContent?.trim() ?? "";
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      el.classList.add("copied");
      setTimeout(() => el.classList.remove("copied"), 1500);
      toast(`${what} copied to the clipboard`);
    } catch {
      toast("Couldn't copy; select the text and copy it instead");
    }
  };
  el.addEventListener("click", () => void copy());
  el.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); void copy(); } });
}

// ---- settings --------------------------------------------------------------------
const s = await getSettings();
$<HTMLInputElement>("uploadEnabled").checked = s.uploadEnabled;
$<HTMLInputElement>("apiBase").value = s.apiBase;
$<HTMLTextAreaElement>("mirrors").value = s.mirrors ?? "";
$<HTMLInputElement>("showBanner").checked = s.showBanner;
$<HTMLInputElement>("annotateLists").checked = s.annotateLists;
$<HTMLInputElement>("legacyCheck").checked = s.legacyCheck;
/** "just now", "5 minutes ago", "today at 10:42 AM", or a date and time. */
function when(iso: string): string {
  const t = new Date(iso), secs = (Date.now() - t.getTime()) / 1000;
  const time = t.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
  if (secs < 45) return "just now";
  if (secs < 3600) { const m = Math.round(secs / 60); return `${m} minute${m === 1 ? "" : "s"} ago (${time})`; }
  if (t.toDateString() === new Date().toDateString()) return `today at ${time}`;
  return t.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

/** The archive.org card: the saved keys' account, or (without keys) this browser's archive.org sign-in and ways to get keys. */
async function renderIaStatus(force = false) {
  const st = await send<{ session: string | null; sessionAccount: { label: string; handle: string | null } | null; hasKeys: boolean; keys: string; keysHandle: string | null; keysValid: boolean | null; checkedAt: string | null; lastValid: boolean | null; error?: string }>({ type: "iaStatus", force });
  if (!st || st.error) return;
  const show = (id: string, on: boolean) => $(id).classList.toggle("hidden", !on);
  const dot = (cls: string) => { $("iaAuthDot").className = "dot " + cls; };
  const text = $("iaAuthText");
  const setText = (...parts: (string | Node)[]) => text.replaceChildren(...parts);
  if (st.hasKeys) {
    const who = st.keys ? accountLink(st.keys, st.keysHandle) : "an account archive.org didn't name";
    if (st.keysValid === false) { dot("bad"); setText("Keys saved for ", who, ", but archive.org rejects them. Sign out, then sign in again for new keys."); }
    else if (st.keysValid === null) { dot("warn"); setText("Uploading as ", who, `. Couldn't reach archive.org to check the keys${st.checkedAt && st.lastValid ? ` (last worked ${when(st.checkedAt)})` : ""}.`); }
    else { dot("ok"); setText("Uploading as ", who); }
  } else if (st.session) {
    dot("");
    const a = st.sessionAccount;
    setText("Signed in to archive.org in this browser as ", ...(a ? [accountLink(a.label, a.handle), ` · ${st.session}`] : [st.session]), ". No upload keys saved yet.");
  } else {
    dot("");
    text.textContent = "Not signed in. Sign in to archive.org, then come back to this page.";
  }
  $("iaKeysChecked").textContent = st.hasKeys && st.checkedAt ? `Checked ${when(st.checkedAt)}` : "";
  show("iaRetest", st.hasKeys);
  show("iaSignOut", st.hasKeys);
  show("iaUseSession", !st.hasKeys && Boolean(st.session));
  show("iaSignIn", !st.hasKeys && !st.session);
  show("iaAlt", !st.hasKeys);
  $("iaPasswordSummary").textContent = st.session ? "Use a different archive.org account (email and password)" : "Sign in with email and password";
  // Upload needs keys archive.org accepts (an unreachable archive.org doesn't count against them).
  const keysOk = st.hasKeys && st.keysValid !== false;
  const up = $<HTMLInputElement>("uploadEnabled");
  up.disabled = !keysOk;
  if (!keysOk && up.checked) { up.checked = false; await setSettings({ uploadEnabled: false }); }
  show("uploadNeedsKeys", !keysOk);
  $("uploadNeedsKeys").textContent = keysOk ? ""
    : st.hasKeys ? "To turn this on, sign out above and sign in again (archive.org rejects the saved keys)."
    : st.session ? "To turn this on, click “Use this account” above."
    : "To turn this on, sign in to archive.org above.";
  iaKeysOk = keysOk;
  renderUploadRow();
}

/** "@handle (Name)" linked to the account's archive.org profile (plain text without a handle). */
function accountLink(label: string, handle: string | null): Node {
  if (!handle || !/^@[\w.-]+$/.test(handle)) return document.createTextNode(label);
  const a = document.createElement("a");
  a.href = `https://archive.org/details/${handle}`; a.target = "_blank"; a.rel = "noopener"; a.textContent = label;
  a.title = "Your archive.org profile";
  return a;
}

/** Whether the saved keys work, as the last status check found. */
let iaKeysOk = false;

/** The Uploads row (green when on, red when off) and the section's LED. */
function renderUploadRow() {
  const enabled = $<HTMLInputElement>("uploadEnabled").checked;
  const live = enabled && iaKeysOk;
  $("iaUploadDot").className = "dot " + (live ? "ok" : "bad");
  $("iaUploadText").textContent = live
    ? "On — manual downloads are watermark-stripped and preserved on archive.org"
    : "Off — downloads aren't uploaded";
  setLed("iaLed", live, live ? "Uploads are on, with working upload keys." : !iaKeysOk ? "No working upload keys saved." : "Uploads are turned off.");
}
$("uploadEnabled").addEventListener("change", renderUploadRow);

$("iaRetest").addEventListener("click", async () => {
  const b = $<HTMLButtonElement>("iaRetest");
  b.disabled = true; b.textContent = "Testing…";
  try { await renderIaStatus(true); } finally { b.disabled = false; b.textContent = "Re-test keys"; }
});
void renderIaStatus();
window.addEventListener("focus", () => void renderIaStatus());
// Signing in or out of archive.org in another tab updates the card right away.
chrome.cookies?.onChanged.addListener(({ cookie }) => {
  if (cookie.name === "logged-in-user" && /(^|\.)archive\.org$/.test(cookie.domain.replace(/^\./, ""))) void renderIaStatus();
});

for (const key of ["uploadEnabled", "showBanner", "annotateLists", "legacyCheck"] as const) $<HTMLInputElement>(key).addEventListener("change", () => setSettings({ [key]: $<HTMLInputElement>(key).checked }));

// ---- archive.org -----------------------------------------------------------------------
/** After keys were saved: clear the forms and show the new state. */
function keysSaved(message: string) {
  for (const id of ["iaPassword", "iaAccessKey", "iaSecretKey"]) $<HTMLInputElement>(id).value = "";
  for (const id of ["iaPasswordBox", "iaManualBox"]) $<HTMLDetailsElement>(id).open = false;
  say("iaMsg", message, true);
  void renderIaStatus();
}
$("iaUseSession").addEventListener("click", async () => {
  say("iaMsg", "Getting this account's upload keys…");
  const r = await send<{ ok: boolean; message: string; error?: string }>({ type: "iaFetchKeys" });
  if (r?.ok) keysSaved(r.message);
  else say("iaMsg", r?.error ?? r?.message ?? "Couldn't get the keys.", false);
});
$("iaSignOut").addEventListener("click", async () => {
  const r = await send<{ ok?: boolean; error?: string }>({ type: "iaSignOut" });
  if (r?.ok) { $<HTMLInputElement>("uploadEnabled").checked = false; say("iaMsg", "Signed out: the upload keys were removed from this browser.", true); }
  else say("iaMsg", r?.error ?? "Couldn't sign out.", false);
  void renderIaStatus();
});
$("iaPasswordLogin").addEventListener("click", async () => {
  const email = val("iaEmail"), password = $<HTMLInputElement>("iaPassword").value;
  if (!email || !password) return say("iaMsg", "Enter email and password.", false);
  say("iaMsg", "Signing in…");
  const r = await send<{ ok: boolean; message: string; error?: string }>({ type: "iaPasswordLogin", email, password });
  $<HTMLInputElement>("iaPassword").value = "";
  if (r?.ok) keysSaved(r.message);
  else say("iaMsg", r?.error ?? r?.message ?? "Sign-in failed.", false);
});
$("saveIa").addEventListener("click", async () => {
  if (!val("iaAccessKey") || !val("iaSecretKey")) return say("iaMsg", "Enter both keys first.", false);
  say("iaMsg", "Saving…");
  const r = await send<{ ok: boolean; message: string; error?: string }>({ type: "iaSaveKeys", accessKey: val("iaAccessKey"), secretKey: val("iaSecretKey") });
  if (r?.ok) keysSaved(r.message);
  else say("iaMsg", r?.error ?? r?.message ?? "Couldn't save the keys.", false);
});
$("testIa").addEventListener("click", async () => {
  const credentials = { accessKey: val("iaAccessKey"), secretKey: val("iaSecretKey") };
  if (!credentials.accessKey || !credentials.secretKey) return say("iaMsg", "Enter both keys first.", false);
  say("iaMsg", "Checking with archive.org…");
  const r = await send<{ ok: boolean; message?: string }>({ type: "checkCredentials", credentials });
  say("iaMsg", r?.ok ? "Keys accepted by archive.org." : (r?.message ?? "Check failed."), Boolean(r?.ok));
});

// ---- server ---------------------------------------------------------------------------------
async function ensureHostPermission(base: string): Promise<boolean> {
  if (!base) return true;
  let origin: string;
  try { origin = new URL(base).origin + "/*"; } catch { return false; }
  if (await chrome.permissions.contains({ origins: [origin] })) return true;
  return chrome.permissions.request({ origins: [origin] });
}
$("saveOm").addEventListener("click", async () => {
  const apiBase = val("apiBase").replace(/\/+$/, "");
  if (apiBase && !/^https?:\/\//i.test(apiBase)) return say("omMsg", "Server must start with http:// or https://", false);
  const mirrors = $<HTMLTextAreaElement>("mirrors").value.split(/\s+/).map((m) => m.trim()).filter(Boolean);
  const bad = mirrors.find((m) => !/^https?:\/\//i.test(m));
  if (bad) return say("omMsg", `Mirror must start with http:// or https://: ${bad}`, false);
  let granted = await ensureHostPermission(apiBase);
  for (const m of mirrors) granted = (await ensureHostPermission(m)) && granted;
  await setSettings({ apiBase, mirrors: mirrors.join("\n") });
  say("omMsg", granted ? "Saved." : "Saved, but without permission to contact that server the extension can't reach it.", granted);
  void renderIdentity();
});
$("testOm").addEventListener("click", async () => {
  const apiBase = val("apiBase").replace(/\/+$/, "");
  if (!apiBase) return say("omMsg", "No server configured.", true);
  if (!(await ensureHostPermission(apiBase))) return say("omMsg", "Permission to contact that server was not granted.", false);
  say("omMsg", "Contacting the server…");
  const r = await send<{ ok: boolean; message: string }>({ type: "checkServer", apiBase });
  say("omMsg", r.message, r.ok);
});

async function renderOutbox() {
  const st = await send<{ outbox: OutboxEntry[]; history: HistoryEntry[] }>({ type: "outboxState" });
  $("outboxInfo").textContent = st.outbox?.length ? `${st.outbox.length} bundle(s) waiting${st.outbox[0].lastError ? ` — last error: ${st.outbox[0].lastError}` : ""}.` : "Nothing waiting.";
  const t = $<HTMLTableElement>("history");
  t.replaceChildren();
  for (const h of (st.history ?? []).slice(0, 30)) {
    const tr = document.createElement("tr");
    for (const text of [new Date(h.acceptedAt).toLocaleString(), h.label, `${h.accepted.length} accepted, ${h.duplicate.length} duplicate${h.rejected.length ? `, ${h.rejected.length} rejected` : ""}`]) {
      const td = document.createElement("td"); td.textContent = text; tr.append(td);
    }
    t.append(tr);
  }
}

// ---- identity ---------------------------------------------------------------------------------
let claims: string[] = [];
let verified = new Map<string, { ok: boolean; service: string | null }>();

/** A section's LED: lit green when the section is set up and working. */
function setLed(id: string, on: boolean, why: string) {
  $(id).className = "led" + (on ? " on" : "");
  $(id).setAttribute("aria-label", on ? "On" : "Off");
  $(id).title = why;
  $(id + "Label").textContent = on ? "On" : "Off";
  $(id + "Label").className = "led-label" + (on ? " on" : "");
  $(id + "Label").title = why;
}

async function renderIdentity() {
  const id = await send<Identity>({ type: "getIdentity" });
  const settings = await getSettings();
  setLed("idLed", Boolean(id.hasKey), id.hasKey ? "You have a signing key: your contributions are signed and recorded." : "No signing key: nothing is recorded on the OpenManuals server.");
  $("noKey").classList.toggle("hidden", id.hasKey);
  $("hasKey").classList.toggle("hidden", !id.hasKey);
  if (!id.hasKey) return;
  $("fingerprint").textContent = id.fingerprint!;
  $("aspe").textContent = aspeUri(aspeDomain(settings), id.fingerprint!);
  $("keyInfo").textContent = `${id.alg} key. Profile page: ${settings.apiBase ? `${settings.apiBase}/k/${id.fingerprint}` : "set a server to host it"}.`;
  if (id.profile) {
    // Don't overwrite what's being typed; only refresh untouched fields.
    if (!profileDirty()) {
      $<HTMLInputElement>("profName").value = id.profile.name;
      $<HTMLInputElement>("profDesc").value = id.profile.description ?? "";
    }
    savedProfile = { name: id.profile.name.trim(), description: (id.profile.description ?? "").trim() };
    renderProfileDirty();
    claims = [...id.profile.claims];
  }
  renderClaims();
  void renderAvatar();
  void recheckClaims();
  void renderPasskeys();
}

// ---- passkeys ---------------------------------------------------------------------------------
const pkSupport = await prfCapability();
if (pkSupport === false) {
  // No passkeys with PRF here: only the passphrase flow works.
  $<HTMLButtonElement>("createKey").disabled = $<HTMLButtonElement>("signInPasskey").disabled = true;
  say("keyMsg", "This browser can't use passkeys to protect the key (no PRF support). Use a passphrase and backup file under Advanced options.", false);
  ($("advanced") as HTMLDetailsElement).open = true;
  $<HTMLInputElement>("usePasskey").checked = false;
  $<HTMLInputElement>("usePasskey").disabled = true;
  $("passkeyNote").textContent = "Not available in this browser. The backup file is your only copy.";
}

async function renderPasskeys() {
  const ul = $("passkeys");
  const { rows, serverError } = await listPasskeys().catch((e) => ({ rows: [], serverError: (e as Error).message }));
  ul.replaceChildren();
  if (!rows.length) {
    const li = document.createElement("li"); li.textContent = "No passkey yet. Only the backup file can restore this key elsewhere. Add a passkey with it under Advanced options."; ul.append(li);
  }
  for (const r of rows) {
    const li = document.createElement("li");
    const u = document.createElement("span"); u.className = "u"; u.textContent = `Passkey added ${new Date(r.createdAt).toLocaleString()} (${r.credential.slice(0, 10)}…)`;
    const badge = document.createElement("span");
    badge.className = "badge " + (r.server ? "ok" : r.server === false ? "bad" : "");
    badge.textContent = r.server ? "on server" : r.server === false ? "not on server" : "this browser";
    const rm = document.createElement("button"); rm.className = "secondary"; rm.textContent = "Remove";
    rm.addEventListener("click", async () => {
      if (!confirm("Stop using this passkey for this key? Its encrypted copy is deleted here and on the server. Also delete the passkey in your password manager.")) return;
      const e = await removePasskey(r.credential).catch((x) => (x as Error).message);
      say("passkeyMsg", e ? `Not removed: ${e}` : "Removed.", !e);
      void renderPasskeys();
    });
    li.append(u, badge, rm); ul.append(li);
  }
  if (serverError && rows.length) say("passkeyMsg", `Server: ${serverError}. The copies in this browser and your backup file still work.`, false);
  $<HTMLButtonElement>("addPasskey").disabled = !rows.length;
  $<HTMLButtonElement>("addPasskey").title = rows.length ? "Unlock with one of your passkeys, then create another" : "The key has no passkey yet: use the backup file below";
  $<HTMLButtonElement>("makeBackup").disabled = !rows.length;
  if (!rows.length) ($("keyAdvanced") as HTMLDetailsElement).open = true;
}

const addedMsg = (serverError: string | null) => serverError ? `Passkey added. Its copy is in this browser but not on the server yet (${serverError}); it's uploaded the next time this page can reach the server.` : "Passkey added.";
$("addPasskey").addEventListener("click", async () => {
  say("passkeyMsg", "Unlock with an existing passkey, then create the new one…");
  try {
    const r = await addPasskey("passkey");
    say("passkeyMsg", addedMsg(r.serverError), true);
  } catch (e) { say("passkeyMsg", (e as Error).message, false); }
  void renderPasskeys();
});
$("addPasskeyBackup").addEventListener("click", async () => {
  const f = $<HTMLInputElement>("pkBackupFile").files?.[0];
  if (!f) return say("passkeyMsg", "Choose the backup file first.", false);
  say("passkeyMsg", "Decrypting the backup, then create the passkey…");
  try {
    const r = await addPasskey({ backupJson: await f.text(), passphrase: $<HTMLInputElement>("pkBackupPass").value });
    $<HTMLInputElement>("pkBackupPass").value = "";
    if (r.backup) downloadBackup(r.backup);
    say("passkeyMsg", addedMsg(r.serverError) + " An updated backup file was downloaded; it replaces the old one.", true);
  } catch (e) { say("passkeyMsg", (e as Error).message, false); }
  void renderPasskeys();
});
$("signInPasskey").addEventListener("click", async () => {
  say("keyMsg", "Choose your OpenManuals passkey…");
  try {
    const f = $<HTMLInputElement>("backupFile").files?.[0];
    const r = await restoreWithPasskey(f ? await f.text() : undefined);
    say("keyMsg", `Signed in as ${r.record.fingerprint} (key from ${r.from}).`, true);
    void renderIdentity();
  } catch (e) { say("keyMsg", (e as Error).message, false); }
});
$("makeBackup").addEventListener("click", async () => {
  const p1 = $<HTMLInputElement>("newBackupPass").value, p2 = $<HTMLInputElement>("newBackupPass2").value;
  if (p1.length < 8) return say("backupMsg", "Use at least 8 characters.", false);
  if (p1 !== p2) return say("backupMsg", "Passphrases don't match.", false);
  say("backupMsg", "Unlock with one of your passkeys…");
  try {
    downloadBackup(await makeBackup(p1));
    $<HTMLInputElement>("newBackupPass").value = $<HTMLInputElement>("newBackupPass2").value = "";
    say("backupMsg", "Backup file downloaded. Keep it and the passphrase somewhere safe.", true);
  } catch (e) { say("backupMsg", (e as Error).message, false); }
});

// ---- avatar ---------------------------------------------------------------------------------
interface AvatarState { fingerprint: string; body: AvatarBody; setAt: string; pending?: string; error?: string }

async function renderAvatar() {
  const st = await send<AvatarState | null>({ type: "avatarState" });
  const settings = await getSettings();
  const box = $("avatarPreview");
  box.replaceChildren();
  const src = avatarSrc(st, settings.apiBase);
  if (src) {
    const img = document.createElement("img");
    img.alt = "";
    img.src = src;
    box.append(img);
  } else box.textContent = "none";
  $("avatarRemove").classList.toggle("hidden", !st || "none" in st.body);
  if (st?.pending) say("avatarMsg", `Uploading… (${st.error ?? "waiting for the server"})`);
  else if (st?.error) say("avatarMsg", st.error, false);
}

/** Center-crop, resize to AVATAR_SIZE square and encode as WebP, under the size limit. */
async function prepareAvatar(file: File): Promise<Uint8Array> {
  const bmp = await createImageBitmap(file).catch(() => { throw new Error("That file isn't an image this browser can read."); });
  const { sx, sy, side } = cropSquare(bmp.width, bmp.height);
  const canvas = new OffscreenCanvas(AVATAR_SIZE, AVATAR_SIZE);
  const g = canvas.getContext("2d")!;
  g.imageSmoothingQuality = "high";
  g.drawImage(bmp, sx, sy, side, side, 0, 0, AVATAR_SIZE, AVATAR_SIZE);
  bmp.close();
  for (const quality of [0.9, 0.8, 0.7, 0.6, 0.5]) {
    const blob = await canvas.convertToBlob({ type: "image/webp", quality });
    if (blob.type !== "image/webp") throw new Error("This browser can't encode WebP.");
    if (blob.size <= AVATAR_MAX_BYTES) return new Uint8Array(await blob.arrayBuffer());
  }
  throw new Error("The image is too detailed to fit the size limit.");
}

async function setAvatar(body: AvatarBody, bytes?: Uint8Array) {
  say("avatarMsg", "Saving…");
  const r = await send<AvatarState & { error?: string }>({ type: "setAvatar", body, ...(bytes ? { bytes: bytesToB64(bytes) } : {}) });
  if (!r || ("error" in r && !("body" in r))) return say("avatarMsg", (r as { error?: string })?.error ?? "Failed.", false);
  say("avatarMsg", "none" in body ? "Avatar removed." : r.pending ? "Saved; the image is sent once the server has your avatar fact." : "Avatar saved.", !r.error || Boolean(r.pending));
  void renderAvatar();
  void renderOutbox();
}

$("avatarUpload").addEventListener("click", () => $<HTMLInputElement>("avatarFile").click());
$("avatarFile").addEventListener("change", async () => {
  const f = $<HTMLInputElement>("avatarFile").files?.[0];
  $<HTMLInputElement>("avatarFile").value = "";
  if (!f) return;
  try {
    const bytes = await prepareAvatar(f);
    await setAvatar({ sha256: await sha256Hex(bytes), size: bytes.byteLength, mime: "image/webp" }, bytes);
  } catch (e) { say("avatarMsg", (e as Error).message, false); }
});
$("avatarGithub").addEventListener("click", () => {
  const url = githubAvatarUrl(claims);
  if (url) void setAvatar({ url });
});
$("avatarRemove").addEventListener("click", () => void setAvatar({ none: true }));

/** A 24×24 icon: brand logos filled in their color, generic ones stroked. */
function iconSvg(icon: Icon): SVGSVGElement {
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24"); svg.setAttribute("aria-hidden", "true"); svg.classList.add("claim-icon");
  const path = document.createElementNS(NS, "path");
  path.setAttribute("d", icon.path);
  if (isOutline(icon)) { path.setAttribute("fill", "none"); path.setAttribute("stroke", icon.color); path.setAttribute("stroke-width", "1.8"); path.setAttribute("stroke-linecap", "round"); path.setAttribute("stroke-linejoin", "round"); }
  else path.setAttribute("fill", icon.color);
  svg.append(path);
  return svg;
}

function renderClaims() {
  $("avatarGithub").classList.toggle("hidden", !githubAvatarUrl(claims));
  const ul = $("claims");
  ul.replaceChildren();
  if (!claims.length) { const li = document.createElement("li"); li.textContent = "No proofs yet."; ul.append(li); }
  for (const c of claims) {
    const li = document.createElement("li"); li.className = "claim";
    const d = claimDisplay(c, pickProvider(c, matchClaim(c).map((m) => m.id), verified.get(c)?.ok ? verified.get(c)?.service : null));
    const svc = document.createElement("span"); svc.className = "claim-service";
    svc.append(iconSvg(d.icon), d.service);
    // One line that trails off; the full URI is in the tooltip.
    const u = document.createElement("span"); u.className = "claim-uri"; u.title = c;
    if (d.href) {
      const a = document.createElement("a"); a.href = d.href; a.textContent = d.label; a.target = "_blank"; a.rel = "noopener noreferrer"; u.append(a);
    } else u.textContent = d.label; // dns:, aspe:, openpgp4fpr: aren't web pages
    const v = verified.get(c);
    const badge = document.createElement("span"); badge.className = "badge " + (v ? (v.ok ? "ok" : "bad") : ""); badge.textContent = v ? (v.ok ? "✓ verified" : "✗ not found") : "unchecked";
    const rm = document.createElement("button"); rm.className = "secondary"; rm.textContent = "Remove";
    rm.addEventListener("click", () => {
      if (!confirm(`Remove the ${d.service} proof (${d.label}) from your profile? Your profile is signed and published again without it. The proof itself (your gist, post or record) isn't touched.`)) return;
      claims = claims.filter((x) => x !== c); renderClaims(); void publishProfile();
    });
    li.append(svc, u, badge, rm);
    ul.append(li);
  }
}

$("createKey").addEventListener("click", async () => {
  say("keyMsg", "Create the passkey when asked…");
  try {
    const { passkey } = await createAndStore(null);
    say("keyMsg", passkey.serverError
      ? `Key created and protected with a passkey, but its copy isn't on the server yet (${passkey.serverError}). Until it is, you can't sign in on another computer; it's uploaded the next time this page can reach the server.`
      : "Key created and protected with your passkey. Sign in with it on any other computer.", !passkey.serverError);
    void renderIdentity();
  } catch (e) { say("keyMsg", `${(e as Error).message} No key was created.`, false); }
});
$("createKeyBackup").addEventListener("click", async () => {
  const p1 = $<HTMLInputElement>("passphrase").value, p2 = $<HTMLInputElement>("passphrase2").value;
  if (p1.length < 8) return say("advKeyMsg", "Use at least 8 characters.", false);
  if (p1 !== p2) return say("advKeyMsg", "Passphrases don't match.", false);
  const usePasskey = $<HTMLInputElement>("usePasskey").checked;
  say("advKeyMsg", usePasskey ? "Generating; create the passkey when asked…" : "Generating…");
  try {
    const { backup, passkey } = await createAndStore(p1, { passkey: usePasskey });
    if (backup) downloadBackup(backup);
    if (!usePasskey) say("advKeyMsg", "Key created. Keep the downloaded backup file somewhere safe; it's the only copy.", true);
    else if (!passkey.added) say("advKeyMsg", `Key created, but no passkey was added: ${passkey.error ?? "unknown error"} Keep the downloaded backup file somewhere safe; it's the only copy. You can add a passkey later.`, false);
    else say("advKeyMsg", `Key created and protected with a passkey.${passkey.serverError ? ` (Its copy isn't on the server yet: ${passkey.serverError}.)` : ""} Keep the downloaded backup file too, as a fallback.`, true);
    $<HTMLInputElement>("passphrase").value = $<HTMLInputElement>("passphrase2").value = "";
    void renderIdentity();
  } catch (e) { say("advKeyMsg", (e as Error).message, false); }
});
$("importKey").addEventListener("click", async () => {
  const f = $<HTMLInputElement>("backupFile").files?.[0];
  if (!f) return say("importMsg", "Choose the backup file first.", false);
  try {
    await importAndStore(await f.text(), $<HTMLInputElement>("importPass").value);
    say("importMsg", "Key restored.", true);
    void renderIdentity();
  } catch (e) { say("importMsg", (e as Error).message, false); }
});
$("forgetKey").addEventListener("click", async () => {
  const { rows } = await listPasskeys().catch(() => ({ rows: [] as { server: boolean | null }[] }));
  const warning = rows.some((r) => r.server)
    ? "Sign out on this computer? You can sign in again with your passkey."
    : "Sign out on this computer? None of this key's passkeys has a copy on the server, so only your backup file can bring it back. Without it, the key is gone for good.";
  if (!confirm(warning)) return;
  await forgetKey();
  say("keyMsg", "");
  void renderIdentity();
});

const sel = $<HTMLSelectElement>("service");
{ const o = document.createElement("option"); o.value = ""; o.textContent = "Choose where to add a proof…"; sel.append(o); }
for (const svc of SERVICES) { const o = document.createElement("option"); o.value = svc.id; o.textContent = svc.name; sel.append(o); }
sel.value = "";
sel.addEventListener("change", () => {
  $<HTMLButtonElement>("showInstructions").disabled = !sel.value;
  if (!$("instructions").classList.contains("hidden") && sel.value) $("showInstructions").click(); // switch the open instructions to the new service
});
/** Close the add-a-proof area and reset it. */
function cancelProof() {
  $("instructions").classList.add("hidden");
  $<HTMLInputElement>("claimUrl").value = "";
  $<HTMLButtonElement>("addClaim").disabled = true;
  say("claimMsg", "");
  sel.value = "";
  $<HTMLButtonElement>("showInstructions").disabled = true;
}
$("cancelClaim").addEventListener("click", cancelProof);
$("showInstructions").addEventListener("click", () => {
  const svc = SERVICES.find((x) => x.id === sel.value);
  if (!svc) return;
  $("instructions").classList.remove("hidden");
  $("instrText").replaceChildren();
  const p = document.createElement("p"); p.textContent = svc.where;
  const code = document.createElement("code"); code.textContent = $("aspe").textContent ?? "";
  const ex = document.createElement("p"); ex.textContent = `Claim URL looks like: ${svc.claimExample}`;
  $("instrText").append(p, code, ex);
  $<HTMLInputElement>("claimUrl").value = "";
  $<HTMLButtonElement>("addClaim").disabled = true;
  say("claimMsg", "");
});
/** Sign the profile (name, description, proofs) and queue it for the server. */
// ---- unsaved profile edits ------------------------------------------------------------
/** The name and description as last signed (empty until a profile exists). */
let savedProfile = { name: "", description: "" };
const profileDirty = () => val("profName") !== savedProfile.name || val("profDesc") !== savedProfile.description;
function renderProfileDirty() {
  const nameChanged = val("profName") !== savedProfile.name, descChanged = val("profDesc") !== savedProfile.description;
  $("profName").classList.toggle("changed", nameChanged);
  $("profDesc").classList.toggle("changed", descChanged);
  $("profDirty").classList.toggle("hidden", !(nameChanged || descChanged));
  $("profile").classList.toggle("dirty", nameChanged || descChanged);
}
for (const id of ["profName", "profDesc"]) $(id).addEventListener("input", renderProfileDirty);
// Leaving with unsaved edits asks first (the browser shows its own wording).
window.addEventListener("beforeunload", (e) => { if (!$("hasKey").classList.contains("hidden") && profileDirty()) e.preventDefault(); });

async function publishProfile(): Promise<boolean> {
  const name = val("profName");
  if (!name) { say("profMsg", "Enter a display name, then click Save profile to publish your proofs.", false); return false; }
  say("profMsg", "Signing…");
  const r = await send<{ ok?: boolean; error?: string }>({ type: "saveProfile", name, claims, description: val("profDesc") || undefined });
  say("profMsg", r?.ok ? "Profile signed and sent to the server." : (r?.error ?? "Failed."), Boolean(r?.ok));
  if (r?.ok) { savedProfile = { name, description: val("profDesc") }; renderProfileDirty(); }
  void renderOutbox();
  return Boolean(r?.ok);
}
/** Add a proof to the list and publish the profile right away. */
async function addAndPublish(uri: string) {
  if (!claims.includes(uri)) claims.push(uri);
  renderClaims();
  cancelProof();
  await publishProfile();
}
$("verifyClaim").addEventListener("click", async () => {
  const uri = val("claimUrl");
  if (!uri) return say("claimMsg", "Paste the claim URL first.", false);
  const hosts = hostsFor(uri, sel.value);
  if (hosts.length && !(await chrome.permissions.contains({ origins: hosts })) && !(await chrome.permissions.request({ origins: hosts }))) return say("claimMsg", "Permission to fetch the proof was not granted.", false);
  say("claimMsg", "Fetching the proof…");
  const r = await verifyClaim(uri, $("aspe").textContent ?? "");
  verified.set(uri, { ok: r.ok, service: r.service });
  if (r.ok) return addAndPublish(uri);
  say("claimMsg", r.errors.join(" "), false);
  $<HTMLButtonElement>("addClaim").disabled = false; // an unverified proof can still be added; the server checks again
});
$("addClaim").addEventListener("click", () => void addAndPublish(val("claimUrl")));
$("saveProfile").addEventListener("click", () => void publishProfile());

/** Re-check the listed proofs in the background, where permission to fetch them was already granted. */
async function recheckClaims() {
  const aspe = $("aspe").textContent ?? "";
  for (const c of claims) {
    const hosts = hostsFor(c, matchClaim(c)[0]?.id ?? "");
    if (hosts.length && !(await chrome.permissions.contains({ origins: hosts }))) continue;
    const r = await verifyClaim(c, aspe).catch(() => null);
    if (r) { verified.set(c, { ok: r.ok, service: r.service }); renderClaims(); }
  }
}

// ---- mutes ----------------------------------------------------------------------------------------
async function renderMuted() {
  const m = await getMuteState();
  const ul = $("muted");
  ul.replaceChildren();
  const entries = Object.entries(m.muted);
  if (!entries.length) { const li = document.createElement("li"); li.textContent = "Nobody muted."; ul.append(li); return; }
  for (const [fp, info] of entries) {
    const li = document.createElement("li");
    const u = document.createElement("span"); u.className = "u"; u.textContent = `${fp} (${info.reason}, ${new Date(info.at).toLocaleDateString()})`;
    const b = document.createElement("button"); b.className = "secondary"; b.textContent = "Unmute";
    b.addEventListener("click", async () => { await setMuted(fp, false); void renderMuted(); });
    li.append(u, b); ul.append(li);
  }
}

void renderIdentity();
void renderOutbox();
void renderMuted();
// A section to show, set by whoever opened this page (the popup, a link on the
// server's pages). Also when this tab was already open and just brought forward.
function jumpTo(selector: unknown) {
  if (typeof selector !== "string" || !/^#[a-z][\w-]*$/i.test(selector)) return;
  const target = document.querySelector(selector);
  target?.closest("details")?.setAttribute("open", ""); // e.g. a section inside Advanced settings
  target?.scrollIntoView();
  chrome.storage.session.remove("optionsJump").catch(() => {});
}
chrome.storage.onChanged.addListener((changes, area) => { if (area === "session" && changes.optionsJump?.newValue) jumpTo(changes.optionsJump.newValue); });
const { optionsJump } = await chrome.storage.session.get("optionsJump").catch(() => ({ optionsJump: null }));
jumpTo(optionsJump);
