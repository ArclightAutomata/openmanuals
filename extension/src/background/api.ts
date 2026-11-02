// OpenManuals server client ("API" in README.md). Optional: an empty apiBase turns it off.
import type { Fact } from "../core/facts.ts";
import type { Settings } from "../core/config.ts";
import type { KnownFile } from "../core/messages.ts";

export interface LookupResponse {
  known: boolean;
  manual: { id: string; title: string; url: string } | null;
  files: KnownFile[];
  legacy_identifiers: string[];
}

export interface PostFactsResponse {
  cursor: string | null;
  accepted: string[];
  duplicate: string[];
  rejected: { index: number; error: string }[];
}

export class ApiError extends Error {
  status: number;
  retryAfter?: number;
  constructor(message: string, status: number, retryAfter?: number) { super(message); this.status = status; this.retryAfter = retryAfter; }
}

async function call<T>(s: Settings, path: string, init: RequestInit = {}, timeoutMs = 6000): Promise<T | null> {
  if (!s.apiBase) return null;
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const res = await fetch(s.apiBase + path, { ...init, signal: ctl.signal });
    if (res.status === 429) throw new ApiError("rate limited", 429, Number(res.headers.get("retry-after") ?? 60));
    if (!res.ok) throw new ApiError(`${res.status} ${await res.text().catch(() => "")}`.trim(), res.status);
    return (await res.json()) as T;
  } finally {
    clearTimeout(timer);
  }
}

export async function lookupByUrl(s: Settings, url: string): Promise<LookupResponse | null> {
  try { return await call<LookupResponse>(s, `/api/lookup?url=${encodeURIComponent(url)}`); } catch { return null; }
}
/** Like lookupByUrl, but says whether the server could not be reached (network error, timeout, 5xx). */
export async function tryLookupByUrl(s: Settings, url: string): Promise<{ res: LookupResponse | null; unreachable: boolean }> {
  try {
    return { res: await call<LookupResponse>(s, `/api/lookup?url=${encodeURIComponent(url)}`), unreachable: false };
  } catch (e) {
    const status = e instanceof ApiError ? e.status : 0;
    return { res: null, unreachable: status === 0 || status >= 500 };
  }
}
export async function lookupByFile(s: Settings, sha256: string): Promise<LookupResponse | null> {
  try { return await call<LookupResponse>(s, `/api/lookup?file=${encodeURIComponent(sha256)}`); } catch { return null; }
}

/** PUT an avatar image named by the key's current avatar fact. Throws ApiError (409: the fact isn't in yet). */
export async function putAvatar(s: Settings, sha256: string, bytes: Uint8Array): Promise<void> {
  const r = await call<{ ok: boolean }>(s, `/api/avatar/${sha256}`, { method: "PUT", headers: { "Content-Type": "application/octet-stream" }, body: bytes as BufferSource }, 20000);
  if (!r) throw new ApiError("no server configured", 0);
}

/** POST a bundle; throws ApiError on HTTP failure so the outbox can retry. */
export async function postFacts(s: Settings, facts: Fact[]): Promise<PostFactsResponse> {
  let r: PostFactsResponse | null;
  try {
    r = await call<PostFactsResponse>(s, "/api/facts", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(facts) }, 20000);
  } catch (e) {
    // A key a moderator blocked: kept (an unblock would let it through) but retried rarely.
    if (e instanceof ApiError && e.status === 403 && /blocked/.test(e.message)) throw new ApiError("Your key is blocked by this server's moderators.", 403, 6 * 3600);
    throw e;
  }
  if (!r) throw new ApiError("no server configured", 0);
  return r;
}

export async function serverVersion(apiBase: string): Promise<{ ok: boolean; message: string }> {
  try {
    const res = await fetch(apiBase + "/.well-known/aspe/version", { cache: "no-store" });
    if (!res.ok) return { ok: false, message: `Server answered ${res.status}` };
    const v = await res.json().catch(() => ({}));
    return { ok: true, message: `Server OK (profile hosting v${v?.version ?? "?"}).` };
  } catch (e) {
    return { ok: false, message: `Couldn't reach the server: ${(e as Error).message}` };
  }
}

/** Public URL of a manual / contributor on the configured server. */
export const manualUrl = (s: Settings, id: string) => (s.apiBase ? `${s.apiBase}/manual/${id}` : null);
export const keyUrl = (s: Settings, fp: string) => (s.apiBase ? `${s.apiBase}/k/${fp}` : null);

// ---- passkey-wrapped keys (/api/key-wrap), used by the options page ----

export interface ServerWrap { credential: string; wrap: string; updated_at: string }

/** The key's wrapped copies on the server (empty when none). Throws when unreachable. */
export async function getKeyWraps(apiBase: string, fp: string): Promise<ServerWrap[]> {
  const res = await fetch(`${apiBase}/api/key-wrap/${fp}`, { cache: "no-store" });
  if (!res.ok) throw new ApiError(`${res.status} ${await res.text().catch(() => "")}`.trim(), res.status);
  return ((await res.json()) as { wraps: ServerWrap[] }).wraps ?? [];
}

/**
 * A signed write. `sign` signs the message from core/passkey.ts keyWrapMessage;
 * body: { key, at, sig, wrap? }.
 */
export async function writeKeyWrap(apiBase: string, method: "PUT" | "DELETE", fp: string, credential: string, body: { key: unknown; at: string; sig: string; wrap?: string }): Promise<void> {
  const res = await fetch(`${apiBase}/api/key-wrap/${fp}/${credential}`, { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  if (!res.ok) {
    const msg = await res.json().then((j: { error?: string }) => j.error).catch(() => null);
    throw new ApiError(msg ?? `server answered ${res.status}`, res.status);
  }
}
