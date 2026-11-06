// The content script for the configured server's own pages: registered at
// runtime for that origin (it changes with the settings), and the only three
// messages it may send. Signing never happens on its behalf: sitePage reports
// the page's hooks (ids only) for the side panel, and siteAction opens the
// side panel (or, when it can't be opened, the confirmation window); both
// re-fetch and re-check everything before offering anything.
import { getSettings } from "../core/config.ts";
import { bodies, nowIso, signFacts, type UnsignedFact } from "../core/facts.ts";
import { keyOf, pageItems, type BulkOp } from "../core/panel.ts";
import { toQuery, validAction, type SiteAction } from "../core/site.ts";
import { getKey } from "./identity.ts";
import { recordReport } from "./mute.ts";
import { enqueue, flush, state as outboxState } from "./outbox.ts";

const SCRIPT_ID = "om-site";

export function serverOrigin(apiBase: string): string | null {
  try {
    const u = new URL(apiBase);
    return u.protocol === "https:" || u.protocol === "http:" ? u.origin : null;
  } catch { return null; }
}

let chain: Promise<void> = Promise.resolve();
/** (Re-)register the content script for the server in the settings; serialized. */
export function syncSiteScript(): Promise<void> {
  chain = chain.then(async () => {
    if (!chrome.scripting?.registerContentScripts) return;
    const existing = await chrome.scripting.getRegisteredContentScripts({ ids: [SCRIPT_ID] }).catch(() => []);
    if (existing.length) await chrome.scripting.unregisterContentScripts({ ids: [SCRIPT_ID] }).catch(() => {});
    const origin = serverOrigin((await getSettings()).apiBase);
    if (!origin) return;
    // Match patterns carry no port; the script checks the exact origin with siteHello.
    const u = new URL(origin);
    await chrome.scripting.registerContentScripts([{
      id: SCRIPT_ID, matches: [`${u.protocol}//${u.hostname}/*`], js: ["content-site.js"], css: ["content-site.css"],
      runAt: "document_idle", persistAcrossSessions: true,
    }]).catch((e) => console.warn("OpenManuals: couldn't register the server page script", e));
  });
  return chain;
}

/** Whether a message comes from a tab showing the configured server (exact origin). */
export async function fromServerPage(sender: chrome.runtime.MessageSender): Promise<boolean> {
  if (sender.id !== chrome.runtime.id || !sender.tab || !sender.url) return false;
  const origin = serverOrigin((await getSettings()).apiBase);
  try { return origin !== null && new URL(sender.url).origin === origin && (sender.frameId ?? 0) === 0; } catch { return false; }
}

let confirmWindow: number | null = null;

/** Open (or reuse) the confirmation window for a validated action. */
export async function openConfirm(params: unknown): Promise<{ ok: boolean; panel?: boolean }> {
  const a = validAction(params);
  if (!a) return { ok: false };
  // Editing a manual has its own page; everything else is the confirmation window.
  const url = chrome.runtime.getURL(`${a.action === "manual" ? "edit" : "confirm"}.html?${toQuery(a)}`);
  if (confirmWindow !== null) {
    const w = await chrome.windows.get(confirmWindow, { populate: true }).catch(() => null);
    const tab = w?.tabs?.[0];
    if (w && tab?.id !== undefined) {
      await chrome.tabs.update(tab.id, { url });
      await chrome.windows.update(w.id!, { focused: true });
      return { ok: true };
    }
  }
  const w = await chrome.windows.create({ url, type: "popup", width: 480, height: a.action === "manual" ? 680 : 560, focused: true });
  confirmWindow = w?.id ?? null;
  return { ok: true };
}

// ---- the side panel ---------------------------------------------------------------------

/** chrome.storage.session keys (extension pages only; content scripts can't read session storage). */
export const pageKey = (tabId: number) => `sitePage:${tabId}`;
export const focusKey = (tabId: number) => `panelFocus:${tabId}`;

export interface SitePage { url: string; items: SiteAction[]; at: number }

/** A server page reported its hooks: keep them for the tab's side panel, and enable the panel there. */
export async function recordPage(sender: chrome.runtime.MessageSender, items: unknown): Promise<{ ok: boolean }> {
  if (!(await fromServerPage(sender))) return { ok: false };
  const tabId = sender.tab!.id!;
  const page: SitePage = { url: sender.url!, items: pageItems(items), at: Date.now() };
  await chrome.storage.session.set({ [pageKey(tabId)]: page });
  await chrome.sidePanel?.setOptions({ tabId, path: `panel.html?tab=${tabId}`, enabled: true }).catch(() => {});
  return { ok: true };
}

/** A tab started loading: forget its page (the panel shows "loading"); off the server, disable its panel. */
export async function siteTabLoading(tabId: number, url?: string): Promise<void> {
  await chrome.storage.session.remove(pageKey(tabId)).catch(() => {});
  if (!url) return;
  const origin = serverOrigin((await getSettings()).apiBase);
  let here: string | null = null;
  try { here = new URL(url).origin; } catch { /* not a URL */ }
  if (here !== origin) await chrome.sidePanel?.setOptions({ tabId, enabled: false }).catch(() => {});
}

export async function siteTabClosed(tabId: number): Promise<void> {
  await chrome.storage.session.remove([pageKey(tabId), focusKey(tabId)]).catch(() => {});
}

/**
 * A click on a server page's button. chrome.sidePanel.open needs the click's
 * user gesture, so it is called before anything is awaited; the sender and
 * the action are checked after. The panel opens only on tabs where a
 * verified server page enabled it. When it can't open, the confirmation
 * window is the fallback.
 */
export function siteAction(sender: chrome.runtime.MessageSender, params: unknown): Promise<{ ok: boolean; panel?: boolean }> {
  const tabId = sender.tab?.id;
  let opening: Promise<boolean> = Promise.resolve(false);
  try {
    if (tabId !== undefined && chrome.sidePanel?.open) opening = chrome.sidePanel.open({ tabId }).then(() => true, () => false);
  } catch { /* no gesture or no API */ }
  return (async () => {
    const ok = await fromServerPage(sender);
    const a = validAction(params);
    if (!ok || !a) { await opening; return { ok: false }; }
    if (await opening) {
      await chrome.storage.session.set({ [focusKey(tabId!)]: { key: keyOf(a), ...(a.action === "manual" && a.focus ? { focus: a.focus } : {}), at: Date.now() } });
      return { ok: true, panel: true };
    }
    return openConfirm(a);
  })();
}

export interface BulkResult {
  ok: true;
  /** Per operation, in order: sent (accepted or already there), queued (waiting to be sent), or rejected by the server. */
  results: { status: "sent" | "queued" | "rejected"; error?: string }[];
  /** Authors muted by these reports (reports from this browser mute an author after a few). */
  muted: string[];
}

/** The server's per-request limit (MAX_BATCH in openmanuals-server). */
const BUNDLE = 500;

/** Sign and send validated panel operations (retractions and reports), in as few bundles as the server allows. */
export async function runBulk(ops: BulkOp[]): Promise<BulkResult> {
  const key = await getKey();
  if (!key) throw new Error("No signing key in this browser. Create one in the extension settings.");
  const at = nowIso();
  const muted: string[] = [];
  const unsigned: UnsignedFact[] = [];
  for (const o of ops) {
    if (o.op === "retract") unsigned.push({ type: "retract", at, body: bodies.retract(o.fact) });
    else {
      const r = await recordReport(o.sha256 ?? o.target, o.author, o.value);
      if (r.muted && o.author) muted.push(o.author);
      unsigned.push({ type: "label", at, body: bodies.label(o.target, "report", o.value, o.url ? `copy: ${o.url}` : undefined) });
    }
  }
  const entries: { id: string; from: number; n: number }[] = [];
  for (let i = 0; i < unsigned.length; i += BUNDLE) {
    const chunk = unsigned.slice(i, i + BUNDLE);
    const kinds = new Set(chunk.map((f) => f.type));
    const what = kinds.size > 1 ? "action" : kinds.has("retract") ? "retraction" : "report";
    const entry = await enqueue(await signFacts(key, chunk), `${chunk.length} ${what}${chunk.length > 1 ? "s" : ""} from the side panel`);
    entries.push({ id: entry.id, from: i, n: chunk.length });
  }
  await flush();
  const { outbox, history } = await outboxState();
  const results: BulkResult["results"] = ops.map(() => ({ status: "queued" }));
  for (const e of entries) {
    const h = history.find((x) => x.id === e.id);
    const waiting = outbox.find((x) => x.id === e.id);
    for (let j = 0; j < e.n; j++) {
      if (h) {
        const rej = h.rejected.find((r) => r.index === j);
        results[e.from + j] = rej ? { status: "rejected", error: rej.error } : { status: "sent" };
      } else results[e.from + j] = waiting?.lastError ? { status: "queued", error: waiting.lastError } : { status: "queued" };
    }
  }
  return { ok: true, results, muted };
}
