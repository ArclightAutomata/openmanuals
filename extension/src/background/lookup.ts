// Page resolution: OpenManuals first (what the server knows about this origin
// URL; skipped without a request when the local lookup filter says the server
// can't know it, see filter.ts), then, if enabled (settings.legacyCheck) or
// there is no server, the legacy deterministic archive.org identifiers for
// pages the server doesn't know. Results are cached in storage.session.
import { canUpload, getSettings, hasIaCredentials, type Settings } from "../core/config.ts";
import type { Copy, LookupResult, SourcePage } from "../core/messages.ts";
import { ensureWasm } from "../core/wasm.ts";
import * as ia from "./ia.ts";
import { tryLookupByUrl } from "./api.ts";
import { mirrorLookup, pinnedKey, pinServerKey } from "./mirror.ts";
import type { PageQuery } from "../rangedb/lookup.ts";
import { mayBeKnown } from "./filter.ts";
import { getMuteState, rankCopies } from "./mute.ts";
import { hasKey } from "./identity.ts";

const POSITIVE_TTL = 6 * 60 * 60 * 1000;
const NEGATIVE_TTL = 10 * 60 * 1000;
const OM_TTL = 10 * 60 * 1000;

// ---- caches -------------------------------------------------------------------

async function cacheGet(identifier: string): Promise<ia.ItemInfo | null> {
  const { iaCache = {} } = await chrome.storage.session.get("iaCache");
  const hit = iaCache[identifier];
  if (!hit) return null;
  return Date.now() - hit.at < (hit.info.exists ? POSITIVE_TTL : NEGATIVE_TTL) ? hit.info : null;
}

export async function cacheSet(identifier: string, info: ia.ItemInfo): Promise<void> {
  const { iaCache = {} } = await chrome.storage.session.get("iaCache");
  const keys = Object.keys(iaCache);
  if (keys.length > 3000) for (const k of keys.slice(0, 1000)) delete iaCache[k];
  iaCache[identifier] = { info, at: Date.now() };
  await chrome.storage.session.set({ iaCache });
}

async function omCacheGet(url: string) {
  const { omCache = {} } = await chrome.storage.session.get("omCache");
  const hit = omCache[url];
  return hit && Date.now() - hit.at < OM_TTL ? hit.res : undefined;
}
async function omCacheSet(url: string, res: unknown) {
  const { omCache = {} } = await chrome.storage.session.get("omCache");
  const keys = Object.keys(omCache);
  if (keys.length > 2000) for (const k of keys.slice(0, 500)) delete omCache[k];
  omCache[url] = { res, at: Date.now() };
  await chrome.storage.session.set({ omCache });
}
export async function omCacheDrop(url: string) {
  const { omCache = {} } = await chrome.storage.session.get("omCache");
  delete omCache[url];
  await chrome.storage.session.set({ omCache });
}

// ---- legacy archive.org lookup ---------------------------------------------------

/**
 * Two-phase legacy lookup. Phase 1 (fast, check_identifier) decides archived
 * or not; phase 2 (metadata API, often 10 s+) fetches the file link and is
 * pushed to the tab through `onDetails`.
 */
export async function lookupLegacy(identifiers: string[], onDetails?: (info: ia.ItemInfo) => void): Promise<ia.ItemInfo> {
  for (const id of identifiers) {
    let info = await cacheGet(id);
    if (info?.exists === false) continue;
    if (info?.exists && info.detailed) return info;
    if (!info) {
      const exists = await ia.checkExists(id);
      info = { exists, identifier: id, archive_url: exists ? ia.detailsUrl(id) : null, detailed: false };
      await cacheSet(id, info);
      if (!exists) continue;
    }
    ia.fetchItem(id).then(async (full) => {
      const detailed = { ...full, detailed: true };
      await cacheSet(id, detailed);
      onDetails?.(detailed);
    }).catch(() => {});
    return info;
  }
  return { exists: false, identifier: identifiers[0] ?? "" };
}

// ---- page resolution ---------------------------------------------------------------

export const tabInfo = new Map<number, LookupResult>();

/** What the snapshot lookup needs to know about a page (mirrors the server's parsing). */
export function pageQuery(url: string): PageQuery {
  const om = wasmSync();
  const p = parsePage(url);
  const prefix = p ? `src:${p.source}:` : "";
  const keys: string[] = p && om ? om.page_keys(url) : [];
  const sourceIds = p ? [...new Set([p.source_id, ...keys.filter((k) => k.startsWith(prefix)).map((k) => k.slice(prefix.length))])] : [];
  return { url, source: p?.source, sourceIds, legacy: p?.candidates ?? [] };
}

export function parsePage(url: string): SourcePage | null {
  const om = wasmSync();
  const s = om?.parse_page_url(url);
  return s ? (JSON.parse(s) as SourcePage) : null;
}

let wasmModule: Awaited<ReturnType<typeof ensureWasm>> | null = null;
export async function initWasm() { wasmModule = await ensureWasm(); }
const wasmSync = () => wasmModule;

function base(page: SourcePage, s: Settings, key: boolean): LookupResult {
  return {
    page, archived: false, via: "none", known: false, manual: null, files: [], copy: null,
    title: null, archive_url: null, download_url: null, filename: null, size: null,
    identifier: page.candidates[0] ?? null, openmanuals_url: null,
    uploadEnabled: s.uploadEnabled, hasCredentials: hasIaCredentials(s), canUpload: canUpload(s), hasKey: key,
    serverConfigured: Boolean(s.apiBase),
  };
}

export function bestCopy(files: LookupResult["files"], mute: Awaited<ReturnType<typeof getMuteState>>): { copy: Copy; sha256: string } | null {
  const ordered = [...files].sort((a, b) => Number(Boolean(b.canonical)) - Number(Boolean(a.canonical)));
  for (const f of ordered) {
    const ranked = rankCopies(f.copies ?? [], f.sha256, mute).filter((c) => !(c.author && mute.muted[c.author]));
    if (ranked[0]) return { copy: ranked[0], sha256: f.sha256 };
  }
  return null;
}

export async function resolvePage(url: string, tabId?: number): Promise<LookupResult | null> {
  const page = parsePage(url);
  if (!page) return null;
  const settings = await getSettings();
  const result = base(page, settings, await hasKey());
  const originUrl = url.split("#")[0];

  // 1. OpenManuals.
  if (settings.apiBase) {
    let res = await omCacheGet(originUrl);
    if (res === undefined) {
      // A filter miss means "unknown to OpenManuals": the legacy identifiers
      // the server would return are page.candidates, already in `result`.
      res = null;
      if (await mayBeKnown(settings, originUrl)) {
        const r = await tryLookupByUrl(settings, originUrl);
        res = r.res;
        if (r.unreachable) {
          // The server is down: answer from a snapshot mirror instead.
          const m = await mirrorLookup(settings, { page: pageQuery(originUrl) }).catch(() => null);
          if (m) {
            res = m.res;
            result.mirror = m.mirror;
          }
        } else if (!(await pinnedKey(settings.apiBase))) {
          void pinServerKey(settings);
        }
      }
      if (res) await omCacheSet(originUrl, res);
    }
    if (res?.known) {
      result.known = true;
      result.manual = res.manual;
      result.files = res.files ?? [];
      result.title = res.manual?.title ?? null;
      result.openmanuals_url = res.manual?.url ?? null;
      const best = bestCopy(result.files, await getMuteState());
      if (best) {
        result.archived = true;
        result.via = "openmanuals";
        result.copy = best.copy;
        result.download_url = best.copy.url;
        result.archive_url = best.copy.ia ? ia.detailsUrl(best.copy.ia.identifier) : best.copy.url;
        result.filename = best.copy.ia?.filename ?? best.copy.url.split("/").pop() ?? null;
        result.size = result.files.find((f) => f.sha256 === best.sha256)?.size ?? null;
        return result;
      }
    }
    if (res?.legacy_identifiers?.length) result.identifier = res.legacy_identifiers[0];
  }

  // 2. Legacy deterministic identifiers on archive.org (manualslib-id-…), asked
  // live. Slow (archive.org's check_identifier takes seconds), and the items are
  // in the ledger since the bulk import, so it's an advanced setting, off by
  // default; without a server it's the only check there is.
  if (settings.apiBase && !settings.legacyCheck) return result;
  const ids = page.candidates;
  if (!ids.length) return result;
  const onDetails = (full: ia.ItemInfo) => {
    const cur = tabId !== undefined ? tabInfo.get(tabId) : undefined;
    if (!cur || cur.identifier !== full.identifier) return;
    if (!full.exists) { Object.assign(cur, { archived: false, archive_url: null }); }
    else Object.assign(cur, { archive_url: full.archive_url, download_url: full.download_url, filename: full.filename, title: cur.title ?? full.title, size: full.size });
    if (tabId !== undefined) chrome.tabs.sendMessage(tabId, { type: "lookupDetails", lookup: cur }).catch(() => {});
  };
  try {
    const info = await lookupLegacy(ids, onDetails);
    if (info.exists) {
      Object.assign(result, {
        archived: true, via: "legacy", identifier: info.identifier, archive_url: info.archive_url ?? ia.detailsUrl(info.identifier),
        download_url: info.download_url ?? null, filename: info.filename ?? null, title: result.title ?? info.title ?? null, size: info.size ?? null,
      });
    }
  } catch {
    result.error = "archive_unreachable";
  }
  return result;
}

export async function refreshTab(tabId: number, url: string): Promise<LookupResult | null> {
  if (!parsePage(url)) { tabInfo.delete(tabId); return null; }
  const result = await resolvePage(url, tabId);
  if (result) tabInfo.set(tabId, result);
  return result;
}

/** List annotation: which of these source ids are archived (legacy search index + cache). */
export async function lookupMany(source: string, sourceIds: string[]): Promise<{ found: Record<string, { identifier: string; archive_url: string }> }> {
  const om = wasmSync();
  if (!om) return { found: {} };
  const wanted = new Map<string, string>();
  for (const sid of sourceIds) {
    const slugs = source === "elektrotanya" ? slugCandidates(sid) : [sid];
    for (const s of slugs) {
      const id = om.legacy_identifier(source, s);
      if (id) wanted.set(id, sid);
    }
  }
  const found: Record<string, { identifier: string; archive_url: string }> = {};
  const unknown: string[] = [];
  for (const id of wanted.keys()) {
    const hit = await cacheGet(id);
    if (hit === null) unknown.push(id);
    else if (hit.exists) found[wanted.get(id)!] = { identifier: id, archive_url: hit.archive_url ?? ia.detailsUrl(id) };
  }
  if (unknown.length) {
    const exists = await ia.searchIdentifiers(unknown);
    for (const id of unknown) {
      if (exists.has(id)) {
        const info = { exists: true, identifier: id, archive_url: ia.detailsUrl(id), detailed: false };
        found[wanted.get(id)!] = { identifier: id, archive_url: info.archive_url };
        await cacheSet(id, info);
      }
      // Search-index misses aren't cached: the index lags item creation.
    }
  }
  return { found };
}

function slugCandidates(slug: string): string[] {
  const out = [slug];
  if (/%[0-9a-f]{2}/i.test(slug)) {
    try { const d = decodeURIComponent(slug); if (d !== slug) out.push(d); } catch { /* keep raw */ }
  }
  return out;
}

// ---- products on a listing (turuta.md) -------------------------------------------

const productCache = new Map<string, { at: number; hit: ProductHit | null }>();
export interface ProductHit { url: string; title: string }

/**
 * The manual covering each listed product (aligned with `products`), from the
 * server's `POST /api/lookup/products`. A manual from `source` itself is
 * preferred, then any other. Null where none is known or there's no server.
 */
export async function lookupProducts(source: string, products: { brand: string; model: string }[]): Promise<{ found: (ProductHit | null)[] }> {
  const s = await getSettings();
  const om = wasmSync();
  if (!s.apiBase || !om) return { found: products.map(() => null) };
  const keys = products.slice(0, 1000).map((p) => (typeof p?.brand === "string" && typeof p?.model === "string" ? om.product_key(p.brand, p.model) ?? null : null));
  const now = Date.now();
  const todo = [...new Set(keys.filter((k): k is string => !!k && !(now - (productCache.get(`${source}\0${k}`)?.at ?? 0) < OM_TTL)))];
  for (let i = 0; i < todo.length; i += 300) {
    const batch = todo.slice(i, i + 300);
    try {
      const res = await fetch(`${s.apiBase}/api/lookup/products`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ keys: batch }) });
      if (!res.ok) break;
      const body = (await res.json()) as { found?: Record<string, { url: string; title: string; source?: string | null }[]> };
      for (const k of batch) {
        const ms = body.found?.[k] ?? [];
        const m = ms.find((x) => x.source === source) ?? ms[0];
        productCache.set(`${source}\0${k}`, { at: now, hit: m ? { url: m.url, title: m.title } : null });
      }
    } catch {
      break;
    }
  }
  if (productCache.size > 5000) for (const k of [...productCache.keys()].slice(0, 2000)) productCache.delete(k);
  return { found: keys.map((k) => (k ? productCache.get(`${source}\0${k}`)?.hit ?? null : null)).concat(products.slice(1000).map(() => null)) };
}
