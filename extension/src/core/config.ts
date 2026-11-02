// Settings. Preferences live in chrome.storage.sync (they follow the Chrome
// profile); archive.org keys, reports and mutes stay in chrome.storage.local.
// The signing key is in IndexedDB (see keys.ts) and never in either.

export interface SyncSettings {
  apiBase: string;        // OpenManuals server; "" disables it
  uploadEnabled: boolean; // RECAP-style "Enable upload"
  annotateLists: boolean; // ✓ marks on listings
  showBanner: boolean;    // in-page banner
  mirrors: string;        // snapshot mirrors (base URLs of a snapshots directory), one per line
  legacyCheck: boolean;   // also ask archive.org live for old-style items (manualslib-id-…) the server doesn't know
}
export interface LocalSettings {
  iaAccessKey: string;
  iaSecretKey: string;
  iaUser: string;         // the keys' archive.org account, for display: "@handle (Screen Name)"
}
export type Settings = SyncSettings & LocalSettings;

export const SYNC_DEFAULTS: SyncSettings = { apiBase: "http://localhost:8000", uploadEnabled: false, annotateLists: true, showBanner: true, mirrors: "", legacyCheck: false };
export const LOCAL_DEFAULTS: LocalSettings = { iaAccessKey: "", iaSecretKey: "", iaUser: "" };

const trimBase = (s: unknown) => String(s ?? "").trim().replace(/\/+$/, "");

export async function getSettings(): Promise<Settings> {
  const [sync, local] = await Promise.all([chrome.storage.sync.get(SYNC_DEFAULTS), chrome.storage.local.get(LOCAL_DEFAULTS)]);
  const s = { ...SYNC_DEFAULTS, ...sync, ...LOCAL_DEFAULTS, ...local } as Settings;
  s.apiBase = trimBase(s.apiBase);
  for (const k of Object.keys(LOCAL_DEFAULTS) as (keyof LocalSettings)[]) s[k] = String(s[k] ?? "").trim();
  return s;
}

export async function setSettings(partial: Partial<Settings>): Promise<void> {
  const sync: Partial<SyncSettings> = {}, local: Partial<LocalSettings> = {};
  for (const [k, v] of Object.entries(partial)) {
    if (k in LOCAL_DEFAULTS) (local as Record<string, string>)[k] = String(v ?? "").trim();
    else if (k in SYNC_DEFAULTS) (sync as Record<string, unknown>)[k] = k === "apiBase" ? trimBase(v) : v;
  }
  await Promise.all([
    Object.keys(sync).length ? chrome.storage.sync.set(sync) : null,
    Object.keys(local).length ? chrome.storage.local.set(local) : null,
  ]);
}

export const hasIaCredentials = (s: Settings): boolean => Boolean(s.iaAccessKey && s.iaSecretKey);
/** Upload is on *and* we hold archive.org keys to do it with. */
export const canUpload = (s: Settings): boolean => Boolean(s.uploadEnabled) && hasIaCredentials(s);

/** The domain the identity profile is hosted on (`aspe:<domain>:<fp>`): the server's host. */
export function aspeDomain(s: Settings): string {
  try { return new URL(s.apiBase).host; } catch { return "openmanuals.org"; }
}
