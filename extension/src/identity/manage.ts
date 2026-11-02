// Key creation, import and passkey protection for the options page (same
// IndexedDB the service worker reads). By default a key is protected by a
// passkey only, with no passphrase or backup file; a backup file is optional
// (at creation, or later by unlocking with a passkey). Passkey prompts and every wrap/unwrap happen here too, so the PRF
// output and the private key never cross chrome.runtime messaging.
//
// Passkey-wrapped copies (KeyWrap, see core/passkey.ts) are kept in three
// places: chrome.storage.local ("keyWraps"), the v2 backup file, and the
// server's /api/key-wrap (signed by the key). Any one of them plus the passkey
// restores the key.
import { getSettings } from "../core/config.ts";
import { backupOf, backupWraps, createKey, importBackup, IdbKeyStore, isBackup, signRaw, withWraps, type KeyBackup, type KeyRecord } from "../core/keys.ts";
import { isKeyWrap, keyWrapMessage, mergeWraps, unwrapPrivateKey, wrapPrivateKey, type KeyWrap } from "../core/passkey.ts";
import { b64url } from "../core/b64.ts";
import { FINGERPRINT_RE, type PublicJwk } from "../core/fingerprint.ts";
import { getKeyWraps, writeKeyWrap } from "../background/api.ts";
import { assertPrf, forgetPasskey, registerPasskey, rpOrigin } from "./passkey.ts";

const store = new IdbKeyStore();
const WRAPS = "keyWraps";

export const getKey = () => store.get();

// ---- local copies -------------------------------------------------------------------

async function allLocalWraps(): Promise<KeyWrap[]> {
  const { [WRAPS]: w = [] } = await chrome.storage.local.get(WRAPS);
  return mergeWraps(w as KeyWrap[]);
}
export async function localWraps(fp: string): Promise<KeyWrap[]> {
  return (await allLocalWraps()).filter((w) => w.fingerprint === fp);
}
async function saveLocalWraps(add: KeyWrap[]): Promise<void> {
  if (add.length) await chrome.storage.local.set({ [WRAPS]: mergeWraps(await allLocalWraps(), add) });
}
async function removeLocalWraps(pred: (w: KeyWrap) => boolean): Promise<void> {
  await chrome.storage.local.set({ [WRAPS]: (await allLocalWraps()).filter((w) => !pred(w)) });
}

// ---- server copies ------------------------------------------------------------------

async function serverWraps(apiBase: string, fp: string): Promise<KeyWrap[]> {
  const out: KeyWrap[] = [];
  for (const s of await getKeyWraps(apiBase, fp)) {
    try {
      const w = JSON.parse(s.wrap) as KeyWrap;
      if (isKeyWrap(w) && w.fingerprint === fp && w.credential === s.credential) out.push(w);
    } catch { /* not ours */ }
  }
  return out;
}

async function signedWrite(record: KeyRecord, method: "PUT" | "DELETE", credential: string, wrap: string | null) {
  const at = new Date().toISOString();
  const sig = b64url(await signRaw(record, await keyWrapMessage(method, record.fingerprint, credential, wrap, at)));
  return { key: record.publicJwk, at, sig, ...(wrap === null ? {} : { wrap }) };
}

/** Store a wrap on the server. Returns an error message, or null when stored (or no server is set). */
async function uploadWrap(record: KeyRecord, w: KeyWrap): Promise<string | null> {
  const { apiBase } = await getSettings();
  if (!apiBase) return "no server is configured";
  const wrap = JSON.stringify(w);
  try { await writeKeyWrap(apiBase, "PUT", record.fingerprint, w.credential, await signedWrite(record, "PUT", w.credential, wrap)); return null; }
  catch (e) { return (e as Error).message; }
}

// ---- passkeys -----------------------------------------------------------------------

/** Register a new passkey and wrap `privateKey` (extractable) under it. */
async function protectWithNewPasskey(privateKey: CryptoKey, info: { fingerprint: string; publicJwk: PublicJwk }, exclude: string[]): Promise<KeyWrap> {
  const { credential, prf } = await registerPasskey(info.fingerprint, exclude);
  try { return await wrapPrivateKey(privateKey, prf, { ...info, credential, rp: rpOrigin() }); } finally { prf.fill(0); }
}

export interface PasskeyOutcome { added: boolean; error?: string; serverError?: string | null }

/**
 * Create the key. With a passphrase, a backup file is made too, and the
 * passkey is optional (a failed one still keeps the key and its file). With
 * none, the passkey is the only copy outside this browser: if it can't be
 * made, nothing is kept.
 */
export async function createAndStore(passphrase: string | null, opts: { passkey?: boolean } = {}): Promise<{ record: KeyRecord; backup: KeyBackup | null; passkey: PasskeyOutcome }> {
  if (await store.get()) throw new Error("A key already exists.");
  const protect = async (k: CryptoKey, info: { fingerprint: string; publicJwk: PublicJwk }) => [await protectWithNewPasskey(k, info, [])];
  const r = passphrase === null ? await createKey(null, { protect })
    : await createKey(passphrase, opts.passkey ? { protect } : {});
  if (passphrase === null && !r.wraps.length) throw r.protectError ?? new Error("No passkey was made, so no key was kept.");
  await store.put(r.record);
  await saveLocalWraps(r.wraps);
  const passkey: PasskeyOutcome = { added: r.wraps.length > 0, error: r.protectError?.message };
  if (r.wraps.length) passkey.serverError = await uploadWrap(r.record, r.wraps[0]);
  return { record: r.record, backup: r.backup, passkey };
}

/** A backup file for the current key, unlocking it with one of its passkeys. */
export async function makeBackup(passphrase: string): Promise<KeyBackup> {
  const record = await store.get();
  if (!record) throw new Error("No key yet.");
  const known = await knownWraps(record);
  if (!known.length) throw new Error("This key has no passkey to unlock it with. Its backup file is the one made when it was created.");
  const a = await assertPrf(known.map((w) => w.credential));
  const w = known.find((x) => x.credential === a.credential);
  if (!a.prf || !w) throw new Error("That passkey didn't unlock the key.");
  let source: KeyRecord;
  try { source = await unwrapPrivateKey(w, a.prf, true); } finally { a.prf.fill(0); }
  return backupOf({ ...source, createdAt: record.createdAt }, passphrase, known);
}

export async function importAndStore(backupJson: string, passphrase: string): Promise<KeyRecord> {
  const backup = JSON.parse(backupJson) as KeyBackup;
  const record = await importBackup(backup, passphrase);
  await store.put(record);
  await saveLocalWraps(backupWraps(backup));
  return record;
}

function parseBackup(json: string | undefined): KeyBackup | null {
  if (!json) return null;
  try { const b = JSON.parse(json); return isBackup(b) ? b : null; } catch { return null; }
}

/**
 * Sign in on a new device: any passkey of this extension, then its wrap from
 * this browser, the given backup file (v2) or the server.
 */
export async function restoreWithPasskey(backupJson?: string): Promise<{ record: KeyRecord; from: string }> {
  if (await store.get()) throw new Error("A key already exists.");
  const a = await assertPrf();
  if (!a.prf) throw new Error("The passkey answered without the PRF secret that unlocks the key. Its provider may not support PRF here; if you made a backup file, restore from it under Advanced options.");
  const fileWraps = (() => { const b = parseBackup(backupJson); return b ? backupWraps(b) : []; })();
  const fp = a.userHandle && FINGERPRINT_RE.test(a.userHandle) ? a.userHandle : null;
  let found = [...(await allLocalWraps()), ...fileWraps].find((w) => w.credential === a.credential && (!fp || w.fingerprint === fp));
  let from = found ? (fileWraps.includes(found) ? "the backup file" : "this browser") : "";
  let fromServer: KeyWrap[] = [];
  if (!found) {
    const { apiBase } = await getSettings();
    if (!fp) throw new Error("This passkey doesn't name an OpenManuals key, and no wrapped copy for it is on this computer or in the chosen backup file.");
    if (!apiBase) throw new Error("No server is configured to fetch the wrapped key from. Set the server below and try again.");
    try { fromServer = await serverWraps(apiBase, fp); } catch (e) { throw new Error(`Couldn't fetch the wrapped key from the server: ${(e as Error).message}. Try again later, or choose your backup file under Advanced options if you made one.`); }
    found = fromServer.find((w) => w.credential === a.credential);
    from = "the server";
    if (!found) throw new Error(`The server has no copy of key ${fp} for this passkey (it may have been removed). If you made a backup file, restore from it under Advanced options.`);
  }
  try {
    const record = await unwrapPrivateKey(found, a.prf, false);
    await store.put(record);
    await saveLocalWraps([...fromServer, ...fileWraps.filter((w) => w.fingerprint === record.fingerprint), found]);
    return { record, from };
  } finally { a.prf.fill(0); }
}

/**
 * Protect the current key with another passkey. The key in IndexedDB is
 * non-extractable, so the raw key comes from an existing passkey's wrap
 * (unwrapped extractable for this one step) or from the backup file. Returns
 * the backup file updated to v2 with the new wrap when one was given.
 */
export async function addPasskey(via: { backupJson: string; passphrase: string } | "passkey"): Promise<{ wrap: KeyWrap; backup: KeyBackup | null; serverError: string | null }> {
  const record = await store.get();
  if (!record) throw new Error("No key yet.");
  const known = await knownWraps(record);
  let source: KeyRecord, backup: KeyBackup | null = null;
  if (via === "passkey") {
    if (!known.length) throw new Error("This key has no passkey yet; use the backup file.");
    const a = await assertPrf(known.map((w) => w.credential));
    const w = known.find((x) => x.credential === a.credential);
    if (!a.prf || !w) throw new Error("That passkey didn't unlock the key.");
    try { source = await unwrapPrivateKey(w, a.prf, true); } finally { a.prf.fill(0); }
  } else {
    backup = parseBackup(via.backupJson);
    if (!backup) throw new Error("That isn't an OpenManuals key backup.");
    if (backup.fingerprint !== record.fingerprint) throw new Error(`That backup is for key ${backup.fingerprint}, not this one.`);
    source = await importBackup(backup, via.passphrase, { extractable: true });
  }
  const wrap = await protectWithNewPasskey(source.privateKey, { fingerprint: record.fingerprint, publicJwk: record.publicJwk }, known.map((w) => w.credential));
  await saveLocalWraps([wrap]);
  const serverError = await uploadWrap(record, wrap);
  // The updated file carries the key's current wraps, not ones removed since the file was made.
  return { wrap, backup: backup ? withWraps({ ...backup, wraps: [] }, [...known, wrap]) : null, serverError };
}

async function knownWraps(record: KeyRecord): Promise<KeyWrap[]> {
  const { apiBase } = await getSettings();
  const remote = apiBase ? await serverWraps(apiBase, record.fingerprint).catch(() => []) : [];
  return mergeWraps(await localWraps(record.fingerprint), remote);
}

/** `server`: whether the server has its wrap (null: couldn't ask). Every row also has a copy in this browser. */
export interface PasskeyRow { credential: string; createdAt: string; server: boolean | null }

/**
 * The current key's passkeys, from this browser and the server. Wraps only
 * here are uploaded (e.g. after an offline creation or a backup import);
 * wraps only on the server are copied here.
 */
export async function listPasskeys(): Promise<{ rows: PasskeyRow[]; serverError: string | null }> {
  const record = await store.get();
  if (!record) return { rows: [], serverError: null };
  const local = await localWraps(record.fingerprint);
  const { apiBase } = await getSettings();
  let remote: KeyWrap[] | null = null, serverError: string | null = apiBase ? null : "no server is configured";
  if (apiBase) {
    try { remote = await serverWraps(apiBase, record.fingerprint); } catch (e) { serverError = (e as Error).message; }
  }
  if (remote) {
    for (const w of local) if (!remote.some((r) => r.credential === w.credential)) {
      const e = await uploadWrap(record, w);
      if (e) serverError = e; else remote.push(w);
    }
    await saveLocalWraps(remote);
  }
  return {
    rows: mergeWraps(local, remote ?? []).map((w) => ({ credential: w.credential, createdAt: w.createdAt, server: remote ? remote.some((r) => r.credential === w.credential) : null })),
    serverError,
  };
}

/** Stop using a passkey: delete its wrap here and on the server, and tell the provider. */
export async function removePasskey(credential: string): Promise<string | null> {
  const record = await store.get();
  if (!record) throw new Error("No key yet.");
  const { apiBase } = await getSettings();
  let serverError: string | null = null;
  if (apiBase) {
    try { await writeKeyWrap(apiBase, "DELETE", record.fingerprint, credential, await signedWrite(record, "DELETE", credential, null)); }
    catch (e) { serverError = (e as Error).message; }
  }
  if (!serverError) {
    await removeLocalWraps((w) => w.fingerprint === record.fingerprint && w.credential === credential);
    await forgetPasskey(credential);
  }
  return serverError;
}

export async function forgetKey(): Promise<void> {
  const record = await store.get();
  await store.clear();
  if (record) await removeLocalWraps((w) => w.fingerprint === record.fingerprint);
  await chrome.storage.local.remove(["profile"]);
}

export function downloadBackup(backup: KeyBackup): void {
  const blob = new Blob([JSON.stringify(backup, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = `openmanuals-key-${backup.fingerprint}.json`;
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60000);
}
