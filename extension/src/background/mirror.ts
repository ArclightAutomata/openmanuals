// Lookups from snapshot mirrors (HTTP Range requests against published
// snapshots, see src/rangedb/) for when the OpenManuals server is unreachable.
// Mirrors are trusted only through the server key pinned while the server was
// reachable: a mirror's manifest must be signed by it, and every page is
// checked against the manifest's page hashes.
import type { Settings } from "../core/config.ts";
import { fingerprint, type PublicJwk } from "../core/fingerprint.ts";
import type { LookupResponse } from "./api.ts";
import type { PageQuery } from "../rangedb/lookup.ts";
import { ensureOffscreen } from "./offscreen.ts";

const PINS = "serverKeys";

/** Mirror base URLs (ending in "/"): the server's own /db/ first, then the configured ones. */
export function mirrorBases(s: Settings): string[] {
  const out: string[] = [];
  if (s.apiBase) out.push(s.apiBase + "/db/");
  for (const line of (s.mirrors ?? "").split(/\s+/)) {
    const t = line.trim();
    if (/^https?:\/\//i.test(t)) out.push(t.endsWith("/") ? t : t + "/");
  }
  return [...new Set(out)];
}

export async function pinnedKey(apiBase: string): Promise<string | null> {
  const { [PINS]: pins = {} } = await chrome.storage.local.get(PINS);
  return (pins as Record<string, string>)[apiBase] ?? null;
}

/**
 * Record the server's key fingerprint the first time we reach it (trust on
 * first use). A later, different key is not silently accepted; returns false.
 */
export async function pinServerKey(s: Settings): Promise<boolean> {
  if (!s.apiBase) return false;
  try {
    const res = await fetch(s.apiBase + "/api/server", { cache: "no-store" });
    if (!res.ok) return false;
    const info = (await res.json()) as { server_key?: PublicJwk; fingerprint?: string };
    if (!info.server_key) return false;
    const fp = await fingerprint(info.server_key);
    if (info.fingerprint && info.fingerprint !== fp) return false;
    const { [PINS]: pins = {} } = await chrome.storage.local.get(PINS);
    const map = pins as Record<string, string>;
    if (map[s.apiBase] && map[s.apiBase] !== fp) return false;
    if (!map[s.apiBase]) await chrome.storage.local.set({ [PINS]: { ...map, [s.apiBase]: fp } });
    return true;
  } catch {
    return false;
  }
}

export interface MirrorAnswer { res: LookupResponse; mirror: string; version: string }

/** Answer a lookup from the first mirror that can; null when none can (or no key is pinned). */
export async function mirrorLookup(s: Settings, q: { page?: PageQuery; file?: string }): Promise<MirrorAnswer | null> {
  const pinned = s.apiBase ? await pinnedKey(s.apiBase) : null;
  const mirrors = mirrorBases(s);
  if (!pinned || !mirrors.length) return null;
  await ensureOffscreen();
  const reply = (await chrome.runtime.sendMessage({ type: "offscreen:mirror", request: { mirrors, pinned, publicUrl: s.apiBase, ...q } })) as
    { ok: boolean; result?: LookupResponse; mirror?: string; version?: string; error?: string } | undefined;
  if (!reply?.ok || !reply.result) {
    if (reply?.error) console.warn("mirror lookup failed:", reply.error);
    return null;
  }
  return { res: reply.result, mirror: reply.mirror ?? "", version: reply.version ?? "" };
}
