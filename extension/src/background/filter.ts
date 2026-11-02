// Local lookup filter: a binary fuse filter (openmanuals-core `filter`) of every page
// the OpenManuals server knows, published with each snapshot at
// `GET {apiBase}/db/lookup-filter.bin`. A page whose keys all miss is certainly
// unknown to that snapshot, so the lookup never leaves the browser; a hit
// (~1/256 false positives) is confirmed with `GET /api/lookup`. With no usable
// filter (never fetched, 404, corrupt, too old) every page is asked about, as
// before.
//
// The bytes are cached in chrome.storage.local (base64, ~12 bits per page
// stored; ~190 KB for 120k keys), checked at most every REFRESH_MS with
// If-None-Match, and tied to the apiBase they came from.
import { b64ToBytes, bytesToB64 } from "../core/b64.ts";
import type { Settings } from "../core/config.ts";
import type { Fact } from "../core/facts.ts";
import { ensureWasm } from "../core/wasm.ts";

export const FILTER_PATH = "/db/lookup-filter.bin";
export const REFRESH_MS = 6 * 60 * 60 * 1000;
/** After a failed check (network error, 5xx) try again sooner than REFRESH_MS. */
const RETRY_MS = 15 * 60 * 1000;
/** A filter not confirmed current for this long is not trusted to hide pages. */
export const MAX_AGE_MS = 3 * 24 * 60 * 60 * 1000;
const STORE = "lookupFilter";
const LOCAL = "localKnownPages";
const LOCAL_TTL = 30 * 24 * 60 * 60 * 1000;
const LOCAL_MAX = 1000;

interface Stored {
  apiBase: string;
  b64: string | null;      // null: the server has no filter (404) or sent a bad one
  etag: string | null;
  confirmedAt: number;     // last time the server said these bytes are current
  nextCheck: number;
}

type Wasm = Awaited<ReturnType<typeof ensureWasm>>;
type LookupFilter = InstanceType<Wasm["LookupFilter"]>;

let mem: { apiBase: string; filter: LookupFilter | null; stored: Stored } | null = null;
let inflight: Promise<void> | null = null;

async function readStored(apiBase: string): Promise<Stored | null> {
  const { [STORE]: s } = await chrome.storage.local.get(STORE);
  return s && (s as Stored).apiBase === apiBase ? (s as Stored) : null;
}

function parse(om: Wasm, bytes: Uint8Array): LookupFilter | null {
  try { return new om.LookupFilter(bytes); } catch { return null; }
}

// Replaced filters are not free()d: a lookup may still hold one, and
// wasm-bindgen's FinalizationRegistry reclaims them.
function install(apiBase: string, filter: LookupFilter | null, stored: Stored): void {
  mem = { apiBase, filter, stored };
}

async function load(apiBase: string): Promise<void> {
  if (mem?.apiBase === apiBase) return;
  const om = await ensureWasm();
  const s = await readStored(apiBase);
  const filter = s?.b64 ? parse(om, b64ToBytes(s.b64)) : null;
  install(apiBase, filter, s ?? { apiBase, b64: null, etag: null, confirmedAt: 0, nextCheck: 0 });
}

/** Fetch (or revalidate) the filter now. Never throws. */
export function refreshFilter(s: Settings): Promise<void> {
  if (!s.apiBase) return Promise.resolve();
  if (inflight) return inflight;
  inflight = (async () => {
    const apiBase = s.apiBase;
    await load(apiBase);
    const prev = mem!.stored;
    const now = Date.now();
    const next: Stored = { ...prev, nextCheck: now + REFRESH_MS };
    let filter = mem!.filter;
    try {
      const headers: Record<string, string> = {};
      if (prev.etag && prev.b64 && filter) headers["If-None-Match"] = prev.etag;
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), 30000);
      let res: Response;
      try { res = await fetch(apiBase + FILTER_PATH, { headers, cache: "no-cache", signal: ctl.signal }); }
      finally { clearTimeout(timer); }
      if (res.status === 304 && filter) {
        next.confirmedAt = now;
      } else if (res.ok) {
        const bytes = new Uint8Array(await res.arrayBuffer());
        const parsed = parse(await ensureWasm(), bytes);
        filter = parsed;
        Object.assign(next, parsed
          ? { b64: bytesToB64(bytes), etag: res.headers.get("etag"), confirmedAt: now }
          : { b64: null, etag: null, confirmedAt: 0 });
      } else if (res.status === 404 || res.status === 410) {
        filter = null;
        Object.assign(next, { b64: null, etag: null, confirmedAt: 0 });
      } else {
        next.nextCheck = now + RETRY_MS; // 5xx, 429…: keep what we have, retry soon
      }
    } catch {
      next.nextCheck = now + RETRY_MS;   // offline / timeout
    }
    if (mem && mem.apiBase !== apiBase) return; // server changed meanwhile
    install(apiBase, filter, next);
    await chrome.storage.local.set({ [STORE]: next });
  })().finally(() => { inflight = null; });
  return inflight;
}

/** Refresh in the background when due (startup, before lookups). */
export async function refreshIfStale(s: Settings): Promise<void> {
  if (!s.apiBase) return;
  await load(s.apiBase);
  if (Date.now() >= mem!.stored.nextCheck) await refreshFilter(s);
}

/** The usable filter for this server, or null (then every page is looked up). */
export async function currentFilter(s: Settings): Promise<LookupFilter | null> {
  if (!s.apiBase) return null;
  await load(s.apiBase);
  if (Date.now() >= mem!.stored.nextCheck) void refreshFilter(s);
  const m = mem!;
  if (!m.filter || Date.now() - m.stored.confirmedAt > MAX_AGE_MS) return null;
  return m.filter;
}

/**
 * Should `url` be looked up on the server? False only when a current filter
 * says the server's snapshot can't know it and this browser didn't just
 * submit it itself.
 */
export async function mayBeKnown(s: Settings, url: string): Promise<boolean> {
  const filter = await currentFilter(s);
  if (!filter) return true;
  if (filter.contains_page(url)) return true;
  const om = await ensureWasm();
  const keys = om.page_keys(url);
  const { [LOCAL]: local = {} } = await chrome.storage.local.get(LOCAL);
  return keys.some((k) => k in (local as Record<string, number>));
}

/**
 * Remember the pages behind origin locations this browser submitted, so they
 * still get looked up while the published filter predates them.
 */
export async function rememberSubmitted(facts: Pick<Fact, "type" | "body">[]): Promise<void> {
  const urls = facts.filter((f) => f.type === "location" && f.body?.kind === "origin" && typeof f.body.url === "string").map((f) => f.body.url as string);
  if (!urls.length) return;
  const om = await ensureWasm();
  const { [LOCAL]: local = {} } = await chrome.storage.local.get(LOCAL);
  const now = Date.now();
  const entries = Object.entries(local as Record<string, number>).filter(([, at]) => now - at < LOCAL_TTL);
  for (const u of urls) for (const k of om.page_keys(u)) entries.push([k, now]);
  entries.sort((a, b) => b[1] - a[1]);
  await chrome.storage.local.set({ [LOCAL]: Object.fromEntries(entries.slice(0, LOCAL_MAX).reverse()) });
}

/** Test hook: forget the in-memory filter (storage is kept). */
export function resetFilterMemory(): void {
  mem = null;
}
