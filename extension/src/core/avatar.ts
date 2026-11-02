// `avatar` facts (see openmanuals_core::avatar): a key's profile picture.
// The body is exactly one of {sha256, size, mime} (an uploaded image whose
// bytes go to PUT /api/avatar/<sha256> after the fact is accepted), {url}
// (an https image the server copies), or {none: true}. Mirrors the Rust checks.

export const AVATAR_MAX_BYTES = 128 * 1024;
/** Uploads are center-cropped and resized to this square. */
export const AVATAR_SIZE = 256;
export const AVATAR_MIMES = ["image/webp", "image/png", "image/jpeg"] as const;
const MAX_URL = 2048;

export type AvatarBody =
  | { sha256: string; size: number; mime: (typeof AVATAR_MIMES)[number] }
  | { url: string }
  | { none: true };

export function validAvatarUrl(url: string): boolean {
  if (!url.startsWith("https://") || url.length > MAX_URL) return false;
  const authority = url.slice(8).split(/[/?#]/)[0];
  return authority.length > 0 && !authority.includes("@") && !authority.startsWith(":") && [...url].every((c) => c.charCodeAt(0) > 0x20 && c.charCodeAt(0) !== 0x7f);
}

/** Why `b` isn't a valid avatar body, or null when it is. */
export function avatarBodyError(b: unknown): string | null {
  if (!b || typeof b !== "object" || Array.isArray(b)) return "body must be an object";
  const o = b as Record<string, unknown>;
  const keys = Object.keys(o).sort().join(",");
  if (keys === "mime,sha256,size") {
    if (typeof o.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(o.sha256)) return "sha256 must be 64 lowercase hex characters";
    if (typeof o.size !== "number" || !Number.isInteger(o.size) || o.size < 1 || o.size > AVATAR_MAX_BYTES) return `size must be 1 to ${AVATAR_MAX_BYTES} bytes`;
    if (!AVATAR_MIMES.includes(o.mime as never)) return `mime must be one of ${AVATAR_MIMES.join(", ")}`;
    return null;
  }
  if (keys === "url") return typeof o.url === "string" && validAvatarUrl(o.url) ? null : "url must be an https URL";
  if (keys === "none") return o.none === true ? null : "none must be true";
  return "body must be {sha256, size, mime}, {url} or {none: true}";
}

/** The GitHub avatar URL for the first GitHub proof among `claims` (a gist or a github.com profile). */
export function githubAvatarUrl(claims: string[]): string | null {
  for (const c of claims) {
    const m = /^https:\/\/(?:gist\.)?github\.com\/([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))(?:[/?#]|$)/.exec(c);
    if (m) return `https://github.com/${m[1]}.png`;
  }
  return null;
}

/** The centered square to crop from a w×h image. */
export function cropSquare(w: number, h: number): { sx: number; sy: number; side: number } {
  const side = Math.min(w, h);
  return { sx: Math.floor((w - side) / 2), sy: Math.floor((h - side) / 2), side };
}

/**
 * Where to load a key's avatar from: the bytes still waiting to be sent, the
 * server's copy (versioned by hash so a new image isn't cached stale), or the
 * linked URL. Null when there is none to show.
 */
export function avatarSrc(st: { fingerprint: string; body: AvatarBody; pending?: string } | null, apiBase: string): string | null {
  if (!st) return null;
  if ("sha256" in st.body) return st.pending ? `data:${st.body.mime};base64,${st.pending}` : apiBase ? `${apiBase}/avatar/${st.fingerprint}?v=${st.body.sha256.slice(0, 16)}` : null;
  if ("url" in st.body) return st.body.url;
  return null;
}
