// Service worker: per-tab lookups and icon state, message router, the upload
// and fetch ports, the outbox alarm, and archive.org sign-in.
import { BUILD_ID } from "../core/build-id.ts";
import { b64ToBytes, bytesToB64 } from "../core/b64.ts";
import { canUpload, getSettings, hasIaCredentials, setSettings } from "../core/config.ts";
import { bodies } from "../core/facts.ts";
import { hashAll } from "../core/hash.ts";
import type { LookupResult, Message, UploadJob, UploadStatus } from "../core/messages.ts";
import * as ia from "./ia.ts";
import { serverVersion } from "./api.ts";
import { refreshIfStale } from "./filter.ts";
import { identity, saveProfile, submit } from "./identity.ts";
import { initWasm, lookupMany, lookupProducts, parsePage, refreshTab, tabInfo } from "./lookup.ts";
import { recordReport } from "./mute.ts";
import { flush, installAlarm, state as outboxState } from "./outbox.ts";
import { avatarState, installAvatarAlarm, setAvatar, uploadPending } from "./avatar.ts";
import { installDownloadWatch } from "./downloads.ts";
import { runUpload } from "./upload.ts";
import { fromServerPage, recordPage, runBulk, siteAction, siteTabClosed, siteTabLoading, syncSiteScript } from "./site.ts";
import { FACT_ID_RE, FILE_ID_RE, REPORT_VALUES } from "../core/site.ts";
import { validOps } from "../core/panel.ts";

const wasmReady = initWasm();
// Lookup filter: load (and fetch if older than 6 h) at worker start.
void wasmReady.then(getSettings).then(refreshIfStale).catch(() => {});

// ---- toolbar icon ----------------------------------------------------------------

import { paint, stateFor } from "./icon.ts";

async function refresh(tabId: number, url: string): Promise<LookupResult | null> {
  await wasmReady;
  if (!parsePage(url)) { tabInfo.delete(tabId); paint(tabId, "none"); return null; }
  paint(tabId, "checking");
  const r = await refreshTab(tabId, url);
  paint(tabId, stateFor(r));
  return r;
}

chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status === "loading") void siteTabLoading(tabId, info.url);
  if ((info.status === "loading" && info.url) || info.status === "complete") if (tab.url) void refresh(tabId, tab.url);
});
chrome.tabs.onRemoved.addListener((tabId) => { tabInfo.delete(tabId); void siteTabClosed(tabId); });

chrome.storage.onChanged.addListener(async (changes, area) => {
  if (area === "session") return;
  if (area === "sync" && changes.apiBase) void syncSiteScript();
  const s = await getSettings();
  for (const [tabId, r] of tabInfo) {
    r.uploadEnabled = s.uploadEnabled; r.hasCredentials = hasIaCredentials(s); r.canUpload = canUpload(s);
    if (!r.archived) paint(tabId, stateFor(r));
  }
});

installAlarm();
installAvatarAlarm();
installDownloadWatch();
// The server-page script follows the configured server and its permission.
void syncSiteScript();
chrome.permissions.onAdded?.addListener(() => void syncSiteScript());
chrome.runtime.onStartup?.addListener(() => void flush().then(() => uploadPending()));
chrome.runtime.onInstalled.addListener(() => void flush().then(() => uploadPending()));

// ---- archive.org sign-in -------------------------------------------------------------

/** Save a key pair together with the archive.org account it belongs to. */
async function storeKeys(k: ia.Credentials | null): Promise<{ ok: boolean; message: string; user?: string }> {
  if (!k) return { ok: false, message: "Not signed in to archive.org in this browser yet." };
  const { valid, account } = await ia.checkKeys(k);
  const user = ia.accountLabel(account);
  await setSettings({ iaAccessKey: k.accessKey, iaSecretKey: k.secretKey, iaUser: user });
  await chrome.storage.local.set({ iaAccount: account, ...(valid !== null ? { iaKeysCheck: { at: new Date().toISOString(), valid, access: k.accessKey } satisfies KeysCheck } : {}) });
  return { ok: true, message: user ? `Keys saved for ${user}.` : "archive.org keys saved (archive.org didn't say which account they belong to).", user };
}

/** Forget the saved keys and their account; uploads go off with them. */
async function signOutKeys(): Promise<{ ok: true }> {
  await setSettings({ iaAccessKey: "", iaSecretKey: "", iaUser: "", uploadEnabled: false });
  await chrome.storage.local.remove(["iaAccount", "iaKeysCheck"]);
  return { ok: true };
}

/** An account's "@handle (Screen Name)" and its `@handle` (the profile is archive.org/details/@handle). */
interface AccountName { label: string; handle: string | null }

/**
 * The account this browser is signed in to. The login cookie only names the
 * email, so this reads that session's keys (without saving them) and asks
 * archive.org whose they are. Cached for the browser session per email; null
 * when archive.org doesn't say.
 */
async function sessionAccountName(email: string): Promise<AccountName | null> {
  const { iaSessionAccount: c } = (await chrome.storage.session.get("iaSessionAccount").catch(() => ({}))) as { iaSessionAccount?: AccountName & { email: string } };
  if (c?.email === email && c.label) return { label: c.label, handle: c.handle ?? null };
  try {
    const k = await ia.fetchKeysFromSession();
    const account = k ? await ia.accountOf(k) : null;
    const name = { label: ia.accountLabel(account), handle: account?.itemname ?? null };
    if (!name.label) return null;
    await chrome.storage.session.set({ iaSessionAccount: { email, ...name } }).catch(() => {});
    return name;
  } catch { return null; /* archive.org unreachable: the email is shown */ }
}

/** The last time archive.org answered about the saved keys, and what it said. */
interface KeysCheck { at: string; valid: boolean; access: string }

/** How long a key check is reused before the settings page asks archive.org again on its own. */
const KEYS_RECHECK_MS = 24 * 3600 * 1000;

/** The saved keys (whose, and whether archive.org takes them) and, without keys, which account this browser is signed in to. */
async function iaStatus(force = false): Promise<{ session: string | null; sessionAccount: AccountName | null; hasKeys: boolean; keys: string; keysHandle: string | null; keysValid: boolean | null; checkedAt: string | null; lastValid: boolean | null }> {
  let s = await getSettings();
  let { iaAccount } = (await chrome.storage.local.get("iaAccount")) as { iaAccount?: ia.IaAccount | null };
  const hasKeys = Boolean(s.iaAccessKey && s.iaSecretKey);
  let keysValid: boolean | null = null;
  const { iaKeysCheck: prev } = (await chrome.storage.local.get("iaKeysCheck")) as { iaKeysCheck?: KeysCheck };
  const fresh = hasKeys && prev?.access === s.iaAccessKey && Date.now() - Date.parse(prev.at) < KEYS_RECHECK_MS && iaAccount !== undefined;
  if (fresh && !force) keysValid = prev!.valid; // checked recently: don't ask archive.org again
  else if (hasKeys) {
    // Asking archive.org both checks the keys and names their account
    // (filled in here for keys saved before the account was recorded).
    const r = await ia.checkKeys({ accessKey: s.iaAccessKey, secretKey: s.iaSecretKey });
    keysValid = r.valid;
    if (r.valid !== null) await chrome.storage.local.set({ iaKeysCheck: { at: new Date().toISOString(), valid: r.valid, access: s.iaAccessKey } satisfies KeysCheck });
    if (r.valid && r.account && JSON.stringify(r.account) !== JSON.stringify(iaAccount ?? null)) {
      iaAccount = r.account;
      await chrome.storage.local.set({ iaAccount });
      await setSettings({ iaUser: ia.accountLabel(iaAccount) || s.iaUser });
      s = await getSettings();
    }
  }
  const session = await ia.sessionEmail();
  const sessionAccount = session && !hasKeys ? await sessionAccountName(session) : null;
  // Only a check of the keys saved now counts.
  const { iaKeysCheck: chk } = (await chrome.storage.local.get("iaKeysCheck")) as { iaKeysCheck?: KeysCheck };
  const check = hasKeys && chk?.access === s.iaAccessKey ? chk : null;
  return { session, sessionAccount, hasKeys, checkedAt: check?.at ?? null, lastValid: check?.valid ?? null, keys: hasKeys ? s.iaUser : "", keysHandle: hasKeys ? iaAccount?.itemname ?? null : null, keysValid };
}

// ---- message router ----------------------------------------------------------------

type Reply = (v: unknown) => void;

/** What a content script (any web page) may ask for. Everything else, signing above all, is for extension pages only. */
const CONTENT_SCRIPT_MESSAGES = new Set(["lookup", "lookupMany", "lookupProducts", "openOptions", "siteHello", "siteAction", "sitePage"]);
const fromExtensionPage = (sender: chrome.runtime.MessageSender) => sender.id === chrome.runtime.id && (sender.url ?? "").startsWith(chrome.runtime.getURL(""));

chrome.runtime.onMessage.addListener((msg: Message | { type: string; [k: string]: unknown }, sender, sendResponse: Reply) => {
  const tabId = sender.tab?.id;
  const run = (p: Promise<unknown>) => { p.then(sendResponse, (e) => sendResponse({ error: String((e as Error)?.message ?? e) })); return true; };
  if (!fromExtensionPage(sender) && !CONTENT_SCRIPT_MESSAGES.has(msg.type)) return false;
  switch (msg.type) {
    // The server's own pages: confirm the sender is that exact origin. The reply carries nothing
    // about the key; only whether uploads are ready, for the page's "help preserve a manual" prompt.
    case "siteHello": return run(fromServerPage(sender).then(async (ok) => (ok ? { ok, upload: canUpload(await getSettings()) } : { ok })));
    // Opens the side panel (needs the click's gesture, so no await before it), else the confirm window.
    case "siteAction": return run(siteAction(sender, msg));
    // The page's hooks (ids only) for the tab's side panel, which re-checks each one itself.
    case "sitePage": return run(recordPage(sender, (msg as { items?: unknown }).items));
    // From the side panel (an extension page): sign and send retractions and reports.
    case "siteBulk": return run((async () => {
      const ops = validOps((msg as { ops?: unknown }).ops);
      if (!ops) throw new Error("invalid actions");
      return runBulk(ops);
    })());
    case "siteHighlight": {
      const m = msg as { tabId?: unknown; key?: unknown };
      const key = typeof m.key === "string" && (FACT_ID_RE.test(m.key) || (m.key.startsWith("file:") && FILE_ID_RE.test(m.key.slice(5)))) ? m.key : null;
      if (typeof m.tabId !== "number") return false;
      void chrome.tabs.sendMessage(m.tabId, { type: "omHighlight", key }).catch(() => {});
      return false;
    }
    case "lookup": return run(refresh(tabId!, (msg as { url: string }).url));
    // A listing's products (turuta.md rows): only brand + model text leaves the page.
    case "lookupProducts": return run(wasmReady.then(() => lookupProducts(String((msg as { source?: unknown }).source ?? ""), Array.isArray((msg as { products?: unknown }).products) ? (msg as unknown as { products: { brand: string; model: string }[] }).products : [])));
    case "lookupMany": return run(wasmReady.then(() => lookupMany((msg as { source: string }).source, (msg as { sourceIds: string[] }).sourceIds ?? [])));
    // Whether a tab shows a manual page on a supported site (the core's page parser decides; one list for every site).
    case "isSourcePage": return run(chrome.tabs.get((msg as { tabId: number }).tabId).then((t) => Boolean(t?.url && parsePage(t.url)), () => false));
    case "getTabStatus": return run((async () => {
      const id = (msg as { tabId: number }).tabId;
      const tab = await chrome.tabs.get(id).catch(() => null);
      if (!tab?.url) return null;
      return tabInfo.get(id) ?? (await refresh(id, tab.url));
    })());
    case "checkCredentials": return run(ia.checkCredentials((msg as { credentials: ia.Credentials }).credentials));
    case "checkServer": return run(serverVersion((msg as { apiBase: string }).apiBase));
    case "iaFetchKeys": return run(ia.fetchKeysFromSession().then(storeKeys));
    case "iaStatus": return run(iaStatus(Boolean((msg as { force?: boolean }).force)));
    case "iaSignOut": return run(signOutKeys());
    case "buildId": return run(Promise.resolve({ build: BUILD_ID }));
    case "iaSaveKeys": {
      const m = msg as { accessKey: string; secretKey: string };
      return run(storeKeys(m.accessKey && m.secretKey ? { accessKey: m.accessKey, secretKey: m.secretKey } : null));
    }
    case "iaPasswordLogin": {
      const m = msg as { email: string; password: string };
      return run(ia.passwordLogin(m.email, m.password).then(storeKeys));
    }
    case "getIdentity": return run(identity());
    case "submitFacts": {
      const m = msg as { facts: Parameters<typeof submit>[0]; label: string };
      return run(submit(m.facts, m.label).then((f) => ({ ok: true, count: f.length })));
    }
    case "saveProfile": {
      const m = msg as { name: string; claims: string[]; description?: string };
      return run(saveProfile(m.name, m.claims, m.description).then((jws) => ({ ok: true, jws })));
    }
    case "report": {
      // `target` (a fact id, e.g. a copy's location fact, or file:<id>) defaults to the file.
      const m = msg as { sha256?: string; target?: string; author?: string; url?: string; value: string };
      return run((async () => {
        if (!(REPORT_VALUES as readonly string[]).includes(m.value)) throw new Error("unknown report reason");
        const target = m.target ?? (m.sha256 ? `file:${m.sha256}` : "");
        const okTarget = FACT_ID_RE.test(target) || (target.startsWith("file:") && FILE_ID_RE.test(target.slice(5)));
        if (!okTarget) throw new Error("nothing to report");
        const local = await recordReport(m.sha256 ?? target, m.author, m.value);
        let sent = false;
        try {
          await submit([{ type: "label", at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"), body: bodies.label(target, "report", m.value, m.url ? `copy: ${m.url}` : undefined) }], "report");
          sent = true;
        } catch { /* no key: local only */ }
        for (const [id, r] of tabInfo) { if (r.files.some((f) => f.sha256 === m.sha256)) { const tab = await chrome.tabs.get(id).catch(() => null); if (tab?.url) void refresh(id, tab.url); } }
        return { ok: true, sent, muted: local.muted };
      })());
    }
    case "addCopy": {
      const m = msg as { sha256: string; url: string };
      return run((async () => {
        const res = await fetch(m.url, { redirect: "follow" });
        if (!res.ok) throw new Error(`That URL answered HTTP ${res.status}.`);
        const bytes = new Uint8Array(await res.arrayBuffer());
        const h = await hashAll(bytes);
        if (h.sha256 !== m.sha256) throw new Error(`The file at that URL is different (sha256 ${h.sha256.slice(0, 12)}…).`);
        await submit([{ type: "location", at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"), body: bodies.location(m.sha256, m.url, "mirror") }], `copy: ${new URL(m.url).host}`);
        return { ok: true };
      })());
    }
    case "avatarState": return run(avatarState());
    case "setAvatar": {
      const m = msg as { body: Parameters<typeof setAvatar>[0]; bytes?: string };
      return run(setAvatar(m.body, m.bytes));
    }
    case "outboxState": return run(outboxState());
    case "flushOutbox": return run(flush().then(() => outboxState()));
    case "openOptions": {
      // An optional section to jump to; only the page's own anchors.
      const jump = (msg as { section?: unknown }).section;
      if (jump === "archive" || jump === "identity") void chrome.storage.session.set({ optionsJump: `#${jump}` }).catch(() => {});
      chrome.runtime.openOptionsPage();
      return false;
    }
    default: return false;
  }
});

// ---- ports: chunked binary transfer ------------------------------------------------------

function concat(chunks: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.length; }
  return out;
}
const safePost = (port: chrome.runtime.Port, msg: unknown) => { try { port.postMessage(msg); } catch { /* closed */ } };

/** The download/upload ports are for the manuals sites' content scripts only. */
function fromManualSite(port: chrome.runtime.Port): boolean {
  try { return /(^|\.)((manualslib|elektrotanya|manualzz)\.com|freeservicemanuals\.info)$/.test(new URL(port.sender?.url ?? "").hostname); } catch { return false; }
}

chrome.runtime.onConnect.addListener((port) => {
  if (!fromManualSite(port)) { port.disconnect(); return; }
  if (port.name === "upload") handleUploadPort(port);
  else if (port.name === "fetch") handleFetchPort(port);
});

/** Content script → us: {begin} {chunk}* {end}; us → it: {status stage ...}. */
function handleUploadPort(port: chrome.runtime.Port): void {
  let job: UploadJob | null = null;
  const chunks: Uint8Array[] = [];
  const status = (stage: UploadStatus["stage"], extra: Partial<UploadStatus> = {}) => safePost(port, { type: "status", stage, ...extra });
  port.onMessage.addListener((msg) => {
    if (msg.type === "begin") { job = msg as UploadJob; chunks.length = 0; status("receiving"); }
    else if (msg.type === "chunk") chunks.push(b64ToBytes(msg.data));
    else if (msg.type === "end" && job) {
      const tabId = port.sender?.tab?.id;
      runUpload(status, job, concat(chunks), tabId).catch((e) => { paint(tabId, stateFor(tabInfo.get(tabId ?? -1))); status("error", { message: String((e as Error).message ?? e) }); });
    }
    // "ping": keeps this worker alive during long uploads.
  });
}

/**
 * Cross-origin download fetched from here (host permissions ⇒ no CORS), streamed back in chunks.
 * `form` (urlencoded) makes it a POST, allowed only to the sending page's own origin.
 */
function handleFetchPort(port: chrome.runtime.Port): void {
  port.onMessage.addListener(async (msg) => {
    if (msg.type !== "fetch") return;
    try {
      const form = typeof msg.form === "string" ? msg.form : null;
      if (form !== null && new URL(msg.url).origin !== new URL(port.sender?.url ?? "").origin) throw new Error("a form is only posted to the page's own site");
      const headers: Record<string, string> = msg.referer ? { Referer: msg.referer } : {};
      if (form !== null) headers["Content-Type"] = "application/x-www-form-urlencoded";
      const res = await fetch(msg.url, { credentials: "include", headers, ...(form !== null ? { method: "POST", body: form } : {}) });
      const buf = new Uint8Array(await res.arrayBuffer());
      safePost(port, { type: "meta", status: res.status, ok: res.ok, contentType: res.headers.get("content-type") ?? "", contentDisposition: res.headers.get("content-disposition") ?? "", size: buf.length });
      for (let i = 0; i < buf.length; i += 1 << 20) safePost(port, { type: "chunk", data: bytesToB64(buf.subarray(i, i + (1 << 20))) });
      safePost(port, { type: "end" });
    } catch (e) {
      safePost(port, { type: "error", message: String((e as Error).message ?? e) });
    }
  });
}
