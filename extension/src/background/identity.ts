// The service worker's view of the contributor key: sign facts, sign and
// submit profiles, answer "who am I". Key creation/import lives in the options
// page (same IndexedDB), see src/identity/manage.ts.
import { aspeDomain, getSettings } from "../core/config.ts";
import { signFacts, type Fact, type UnsignedFact, bodies } from "../core/facts.ts";
import { IdbKeyStore, type KeyRecord, type KeyStore } from "../core/keys.ts";
import type { Identity } from "../core/messages.ts";
import { aspeUri, signProfile } from "../core/asp.ts";
import { enqueue } from "./outbox.ts";

let store: KeyStore = new IdbKeyStore();
/** Tests swap in a MemoryKeyStore. */
export function useKeyStore(s: KeyStore): void { store = s; }

export async function getKey(): Promise<KeyRecord | null> {
  try { return await store.get(); } catch { return null; }
}
export async function hasKey(): Promise<boolean> {
  return Boolean(await getKey());
}

export async function identity(): Promise<Identity> {
  const key = await getKey();
  const s = await getSettings();
  const { profile = null } = await chrome.storage.local.get("profile");
  if (!key) return { hasKey: false, fingerprint: null, alg: null, reason: null, aspe: null, profile: null };
  return { hasKey: true, fingerprint: key.fingerprint, alg: key.alg, reason: key.reason, aspe: aspeUri(aspeDomain(s), key.fingerprint), profile };
}

/** Sign a bundle and queue it for delivery. Throws when there is no key. */
export async function submit(facts: UnsignedFact[], label: string): Promise<Fact[]> {
  const key = await getKey();
  if (!key) throw new Error("No contributor key yet. Create one in the extension settings.");
  const signed = await signFacts(key, facts);
  await enqueue(signed, label);
  return signed;
}

export async function saveProfile(name: string, claims: string[], description?: string): Promise<string> {
  const key = await getKey();
  if (!key) throw new Error("No contributor key yet.");
  // With an avatar, the profile points Keyoxide and others at the server's copy.
  const { apiBase } = await getSettings();
  const { avatar } = await chrome.storage.local.get("avatar");
  const has = avatar?.fingerprint === key.fingerprint && avatar.body && !("none" in avatar.body);
  const avatarUrl = has && apiBase ? `${apiBase}/avatar/${key.fingerprint}` : undefined;
  const jws = await signProfile(key, { name, claims, description, avatarUrl });
  await submit([{ type: "identity_profile", at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"), body: bodies.identityProfile(jws) }], "profile");
  await chrome.storage.local.set({ profile: { name, claims, description, jws, savedAt: new Date().toISOString() } });
  return jws;
}
