// The contributor's signing key.
//
// Generated with WebCrypto as a non-extractable key and kept as a CryptoKey in
// the extension's IndexedDB, so no script (ours included) can read the private
// bytes. The raw key exists only at creation, when it is wrapped under a
// passkey (see passkey.ts) and/or exported into a passphrase-encrypted backup
// (format `om-key-backup` v2), and then re-imported non-extractable. A passkey
// can later unwrap an extractable copy for one step (adding a passkey, making
// a backup file). Nothing here touches chrome.storage.sync.
import { b64url, b64urlDecode, utf8 } from "./b64.ts";
import { fingerprint, type Alg, type PublicJwk } from "./fingerprint.ts";
import { mergeWraps, type KeyWrap } from "./passkey.ts";

export interface KeyRecord {
  id: "primary";
  alg: Alg;
  publicJwk: PublicJwk;
  fingerprint: string;
  privateKey: CryptoKey;
  createdAt: string;
  /** Where the key came from: "created", "imported" (from a backup), "passkey" (restored with one) or "seed" (tests). */
  reason: string;
}

export interface KeyBackup {
  format: "om-key-backup";
  /** 2 adds `wraps`; 1 is still read. */
  v: 1 | 2;
  alg: Alg;
  fingerprint: string;
  publicJwk: PublicJwk;
  kdf: { name: "PBKDF2"; hash: "SHA-256"; iterations: number; salt: string };
  cipher: { name: "AES-GCM"; iv: string };
  /** AES-GCM ciphertext of the private JWK JSON (base64url). */
  ciphertext: string;
  createdAt: string;
  /** v2: passkey-wrapped copies (see passkey.ts); restoring with a passkey needs no passphrase. */
  wraps?: KeyWrap[];
}

/** Called by createKey while the private key is still extractable, to wrap it under passkeys. */
export type Protect = (privateKey: CryptoKey, info: { fingerprint: string; publicJwk: PublicJwk }) => Promise<KeyWrap[]>;

export const PBKDF2_ITERATIONS = 600_000;

/** Storage backend for the key record (IndexedDB in the extension, memory in tests). */
export interface KeyStore {
  get(): Promise<KeyRecord | null>;
  put(record: KeyRecord): Promise<void>;
  clear(): Promise<void>;
}

export class MemoryKeyStore implements KeyStore {
  private rec: KeyRecord | null = null;
  async get() { return this.rec; }
  async put(r: KeyRecord) { this.rec = r; }
  async clear() { this.rec = null; }
}

const DB_NAME = "openmanuals";
const STORE = "keys";

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 2);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE, { keyPath: "id" });
      if (!db.objectStoreNames.contains("blobs")) db.createObjectStore("blobs");
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function tx<T>(db: IDBDatabase, mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    const t = db.transaction(STORE, mode);
    const r = fn(t.objectStore(STORE));
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

export class IdbKeyStore implements KeyStore {
  async get(): Promise<KeyRecord | null> {
    const db = await openDb();
    try { return (await tx<KeyRecord | undefined>(db, "readonly", (s) => s.get("primary"))) ?? null; } finally { db.close(); }
  }
  async put(record: KeyRecord): Promise<void> {
    const db = await openDb();
    try { await tx(db, "readwrite", (s) => s.put(record)); } finally { db.close(); }
  }
  async clear(): Promise<void> {
    const db = await openDb();
    try { await tx(db, "readwrite", (s) => s.delete("primary")); } finally { db.close(); }
  }
}

export const keyAlgo = (_alg: Alg): AlgorithmIdentifier => ({ name: "Ed25519" });

export const signAlgo = (_alg: Alg): AlgorithmIdentifier => ({ name: "Ed25519" });

function stripJwk(jwk: JsonWebKey): PublicJwk {
  return { kty: jwk.kty!, crv: jwk.crv!, x: jwk.x! };
}

async function importPrivate(alg: Alg, jwk: JsonWebKey, extractable: boolean): Promise<CryptoKey> {
  return crypto.subtle.importKey("jwk", jwk, keyAlgo(alg), extractable, ["sign"]);
}

async function deriveWrapKey(passphrase: string, salt: Uint8Array, iterations: number): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey("raw", utf8.encode(passphrase) as BufferSource, "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: salt as BufferSource, iterations },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  );
}

/** Encrypt a private JWK under a passphrase as a backup file (v2). */
async function sealBackup(privJwk: JsonWebKey, info: { publicJwk: PublicJwk; fingerprint: string; createdAt: string }, passphrase: string, iterations: number, wraps: KeyWrap[]): Promise<KeyBackup> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrap = await deriveWrapKey(passphrase, salt, iterations);
  const plain = utf8.encode(JSON.stringify({ kty: privJwk.kty, crv: privJwk.crv, x: privJwk.x, d: privJwk.d }));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv as BufferSource }, wrap, plain as BufferSource));
  return {
    format: "om-key-backup", v: 2, alg: "Ed25519", fingerprint: info.fingerprint, publicJwk: info.publicJwk,
    kdf: { name: "PBKDF2", hash: "SHA-256", iterations, salt: b64url(salt) },
    cipher: { name: "AES-GCM", iv: b64url(iv) },
    ciphertext: b64url(ct), createdAt: info.createdAt, wraps: mergeWraps(wraps.filter((w) => w.fingerprint === info.fingerprint)),
  };
}

/**
 * Create the key. The private key exists in extractable form only inside this
 * function: wrapped under passkeys and/or exported to a passphrase backup,
 * then re-imported non-extractable. With no passphrase there is no backup
 * file, and the passkeys are the only way to restore the key elsewhere.
 */
export interface Created<B> { record: KeyRecord; backup: B; wraps: KeyWrap[]; protectError?: Error }
export async function createKey(passphrase: string, opts?: { iterations?: number; protect?: Protect }): Promise<Created<KeyBackup>>;
export async function createKey(passphrase: null, opts: { iterations?: number; protect: Protect }): Promise<Created<null>>;
export async function createKey(passphrase: string | null, opts: { iterations?: number; protect?: Protect } = {}): Promise<Created<KeyBackup | null>> {
  // Ed25519 only: WebCrypto has it from Chrome 137, the manifest's minimum.
  const alg: Alg = "Ed25519";
  const pair = (await crypto.subtle.generateKey(keyAlgo(alg), true, ["sign", "verify"])) as CryptoKeyPair;
  const privJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  const publicJwk = stripJwk(privJwk);
  const fp = await fingerprint(publicJwk);
  const createdAt = new Date().toISOString();

  // Passkey first (it prompts the user), then the slow PBKDF2. A failed or
  // cancelled passkey is reported in protectError; the caller decides whether
  // a key with only a backup file (or nothing) is kept.
  let wraps: KeyWrap[] = [], protectError: Error | undefined;
  if (opts.protect) {
    try { wraps = await opts.protect(pair.privateKey, { fingerprint: fp, publicJwk }); } catch (e) { protectError = e as Error; }
  }

  const backup = passphrase === null ? null
    : await sealBackup(privJwk, { publicJwk, fingerprint: fp, createdAt }, passphrase, opts.iterations ?? PBKDF2_ITERATIONS, wraps);
  const privateKey = await importPrivate(alg, privJwk, false);
  const record: KeyRecord = { id: "primary", alg, publicJwk, fingerprint: fp, privateKey, createdAt, reason: "created" };
  return { record, backup, wraps, protectError };
}

/**
 * A backup file for an existing key, from an extractable copy of it (unwrapped
 * with a passkey for this one step), for keys made without one.
 */
export async function backupOf(source: KeyRecord, passphrase: string, wraps: KeyWrap[], opts: { iterations?: number } = {}): Promise<KeyBackup> {
  if (!source.privateKey.extractable) throw new Error("the key isn't extractable here; unlock it with a passkey first");
  const privJwk = await crypto.subtle.exportKey("jwk", source.privateKey);
  if (await fingerprint(stripJwk(privJwk)) !== source.fingerprint) throw new Error("key fingerprint mismatch");
  return sealBackup(privJwk, source, passphrase, opts.iterations ?? PBKDF2_ITERATIONS, wraps);
}

export function isBackup(b: unknown): b is KeyBackup {
  const x = b as KeyBackup;
  return Boolean(x) && x.format === "om-key-backup" && (x.v === 1 || x.v === 2);
}

/** The backup's passkey wraps for its own key (v1 has none). */
export function backupWraps(backup: KeyBackup): KeyWrap[] {
  return mergeWraps(backup.wraps).filter((w) => w.fingerprint === backup.fingerprint);
}

/** The same backup (same encrypted key) as v2 with these wraps added. Needs no passphrase. */
export function withWraps(backup: KeyBackup, wraps: KeyWrap[]): KeyBackup {
  return { ...backup, v: 2, wraps: mergeWraps(backup.wraps, wraps.filter((w) => w.fingerprint === backup.fingerprint)) };
}

/**
 * Restore a key from a backup; the imported key is non-extractable unless
 * `extractable` (only for wrapping it under a passkey right away).
 */
export async function importBackup(backup: KeyBackup, passphrase: string, opts: { extractable?: boolean } = {}): Promise<KeyRecord> {
  if (!isBackup(backup)) throw new Error("not an OpenManuals key backup");
  if (backup.alg !== "Ed25519") throw new Error(`unsupported key algorithm ${String(backup.alg)}: only Ed25519 keys are supported`);
  const wrap = await deriveWrapKey(passphrase, b64urlDecode(backup.kdf.salt), backup.kdf.iterations);
  let plain: ArrayBuffer;
  try {
    plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64urlDecode(backup.cipher.iv) as BufferSource }, wrap, b64urlDecode(backup.ciphertext) as BufferSource);
  } catch {
    throw new Error("wrong passphrase");
  }
  const privJwk = JSON.parse(utf8.decode(new Uint8Array(plain))) as JsonWebKey;
  const publicJwk = stripJwk(privJwk);
  const fp = await fingerprint(publicJwk);
  if (fp !== backup.fingerprint) throw new Error("backup fingerprint mismatch");
  const privateKey = await importPrivate(backup.alg, privJwk, opts.extractable ?? false);
  return { id: "primary", alg: backup.alg, publicJwk, fingerprint: fp, privateKey, createdAt: backup.createdAt, reason: "imported" };
}

/** Raw Ed25519 signature bytes (64) over `msg`. */
export async function signRaw(record: KeyRecord, msg: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.sign(signAlgo(record.alg), record.privateKey, msg as BufferSource));
}

/** Import a known seed as a (test) key record. Ed25519 only. */
export async function keyFromEd25519Seed(seed: Uint8Array, x: string, extractable = false): Promise<KeyRecord> {
  const jwk: JsonWebKey = { kty: "OKP", crv: "Ed25519", x, d: b64url(seed) };
  const publicJwk = stripJwk(jwk);
  const privateKey = await importPrivate("Ed25519", jwk, extractable);
  return { id: "primary", alg: "Ed25519", publicJwk, fingerprint: await fingerprint(publicJwk), privateKey, createdAt: "2026-10-23T00:00:00Z", reason: "seed" };
}
