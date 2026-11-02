// The contributor's avatar. The options page prepares the image (cropped,
// resized, WebP); here the `avatar` fact is signed and queued, and an
// uploaded image's bytes wait in chrome.storage.local until the server has
// the fact (PUT /api/avatar/<sha256> answers 409 until then), retried from an
// alarm. A saved profile is re-signed so its avatar_url points at the server.
import { getSettings } from "../core/config.ts";
import { avatarBodyError, type AvatarBody } from "../core/avatar.ts";
import { b64ToBytes } from "../core/b64.ts";
import { sha256Hex } from "../core/hash.ts";
import { ApiError, putAvatar } from "./api.ts";
import { getKey, saveProfile, submit } from "./identity.ts";
import { flush } from "./outbox.ts";

const KEY = "avatar";
const ALARM = "om-avatar";
const RETRY_MINUTES = 2;

export interface AvatarState {
  fingerprint: string;
  body: AvatarBody;
  setAt: string;
  /** The image bytes (base64) until the server has them. */
  pending?: string;
  /** Why the last upload failed. */
  error?: string;
}

async function load(): Promise<AvatarState | null> {
  const { [KEY]: s = null } = await chrome.storage.local.get(KEY);
  return s;
}

export async function avatarState(): Promise<AvatarState | null> {
  const s = await load();
  const key = await getKey();
  return s && key && s.fingerprint === key.fingerprint ? s : null;
}

/** Set (or clear, with {none: true}) the avatar. `bytesB64` is the image for a {sha256} body. */
export async function setAvatar(body: AvatarBody, bytesB64?: string): Promise<AvatarState> {
  const key = await getKey();
  if (!key) throw new Error("No contributor key yet.");
  const err = avatarBodyError(body);
  if (err) throw new Error(err);
  if ("sha256" in body) {
    if (!bytesB64) throw new Error("missing image bytes");
    const bytes = b64ToBytes(bytesB64);
    if (bytes.byteLength !== body.size || (await sha256Hex(bytes)) !== body.sha256) throw new Error("the image doesn't match its avatar fact");
  }
  const state: AvatarState = { fingerprint: key.fingerprint, body, setAt: new Date().toISOString(), ...("sha256" in body ? { pending: bytesB64 } : {}) };
  await chrome.storage.local.set({ [KEY]: state });
  await submit([{ type: "avatar", at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"), body: { ...body } }], "avatar");
  // Keep the signed profile's avatar_url in step.
  const { profile } = await chrome.storage.local.get("profile");
  if (profile?.name) await saveProfile(profile.name, profile.claims ?? [], profile.description).catch(() => {});
  await uploadPending();
  return (await load()) ?? state;
}

/** Send a waiting image once the server has its fact. Returns the state afterwards. */
export async function uploadPending(): Promise<AvatarState | null> {
  const s = await load();
  if (!s?.pending || !("sha256" in s.body)) return s;
  const settings = await getSettings();
  if (!settings.apiBase) return s;
  await flush(); // the fact first
  try {
    await putAvatar(settings, s.body.sha256, b64ToBytes(s.pending));
    delete s.pending;
    delete s.error;
    await chrome.alarms.clear(ALARM);
  } catch (e) {
    const status = e instanceof ApiError ? e.status : 0;
    if (status === 400 || status === 413) {
      // The server refused the image itself: retrying won't help.
      delete s.pending;
      s.error = (e as Error).message;
    } else {
      s.error = status === 409 ? "waiting for the server to accept the avatar fact" : (e as Error).message;
      await chrome.alarms.create(ALARM, { delayInMinutes: RETRY_MINUTES });
    }
  }
  // Another setAvatar may have replaced the state meanwhile.
  const now = await load();
  if (now?.setAt === s.setAt) await chrome.storage.local.set({ [KEY]: s });
  return s;
}

export function installAvatarAlarm(): void {
  chrome.alarms.onAlarm.addListener((a) => { if (a.name === ALARM) void uploadPending(); });
}
