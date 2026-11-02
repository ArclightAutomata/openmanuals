// Passkey protection for the contributor key (no WebAuthn here; that's
// src/identity/passkey.ts). A passkey's PRF output for PRF_INPUT is stretched
// with HKDF-SHA256 into an AES-256-GCM key that wraps the Ed25519 private key
// (PKCS#8). The wrapped copy (a KeyWrap) is useless without the passkey, so it
// may be stored anywhere: chrome.storage.local, the backup file and the
// server's /api/key-wrap. Unwrapping gives a non-extractable key, except for
// the one "add another passkey" step that has to wrap it again.
import { b64url, b64urlDecode, hex, utf8 } from "./b64.ts";
import { fingerprint, FINGERPRINT_RE, type PublicJwk } from "./fingerprint.ts";
import type { KeyRecord } from "./keys.ts";

/** The PRF input (the "salt" WebAuthn hashes into the authenticator's hmac-secret). Fixed forever. */
export const PRF_INPUT = utf8.encode("openmanuals key wrap v1");
const HKDF_INFO = utf8.encode("openmanuals key wrap v1 aes-256-gcm");

export interface KeyWrap {
  format: "om-key-wrap";
  v: 1;
  alg: "Ed25519";
  fingerprint: string;
  publicJwk: PublicJwk;
  /** The passkey's credential id, base64url. */
  credential: string;
  /** The relying party the passkey belongs to (the extension's origin), for display. */
  rp: string;
  iv: string;
  /** AES-GCM(PKCS#8 private key), base64url. */
  wrapped: string;
  createdAt: string;
}

export class PasskeyMismatchError extends Error {
  constructor() {
    super("This passkey can't unlock the key: it is a different passkey, or its provider returned a different secret than when the key was protected. If you made a backup file, restore from it under Advanced options.");
  }
}

/** Binds a wrap to its key and credential, so a swapped blob fails to unwrap. */
const aad = (fp: string, credential: string) => utf8.encode(`openmanuals key wrap v1\n${fp}\n${credential}`);

async function wrappingKey(prf: Uint8Array): Promise<CryptoKey> {
  if (prf.length < 32) throw new Error("PRF output too short");
  const ikm = await crypto.subtle.importKey("raw", prf as BufferSource, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: HKDF_INFO as BufferSource }, ikm, { name: "AES-GCM", length: 256 }, false, ["wrapKey", "unwrapKey"]);
}

/** Wrap an *extractable* private key under a passkey's PRF output. */
export async function wrapPrivateKey(privateKey: CryptoKey, prf: Uint8Array, info: { fingerprint: string; publicJwk: PublicJwk; credential: string; rp: string }): Promise<KeyWrap> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrapped = await crypto.subtle.wrapKey("pkcs8", privateKey, await wrappingKey(prf), { name: "AES-GCM", iv: iv as BufferSource, additionalData: aad(info.fingerprint, info.credential) as BufferSource });
  return {
    format: "om-key-wrap", v: 1, alg: "Ed25519", fingerprint: info.fingerprint, publicJwk: info.publicJwk,
    credential: info.credential, rp: info.rp, iv: b64url(iv), wrapped: b64url(new Uint8Array(wrapped)),
    createdAt: new Date().toISOString(),
  };
}

export function isKeyWrap(w: unknown): w is KeyWrap {
  const x = w as KeyWrap;
  return Boolean(x) && x.format === "om-key-wrap" && x.v === 1 && x.alg === "Ed25519" && FINGERPRINT_RE.test(x.fingerprint)
    && typeof x.credential === "string" && typeof x.iv === "string" && typeof x.wrapped === "string" && Boolean(x.publicJwk?.x);
}

/**
 * Unwrap with a passkey's PRF output. Non-extractable unless `extractable` is
 * set (only for wrapping it under another passkey). Checks that the private
 * key belongs to the wrap's public key before returning it.
 */
export async function unwrapPrivateKey(w: KeyWrap, prf: Uint8Array, extractable = false): Promise<KeyRecord> {
  if (!isKeyWrap(w)) throw new Error("not an OpenManuals key wrap");
  const publicJwk: PublicJwk = { kty: w.publicJwk.kty, crv: w.publicJwk.crv, x: w.publicJwk.x };
  if ((await fingerprint(publicJwk)) !== w.fingerprint) throw new Error("key wrap fingerprint mismatch");
  let privateKey: CryptoKey;
  try {
    privateKey = await crypto.subtle.unwrapKey("pkcs8", b64urlDecode(w.wrapped) as BufferSource, await wrappingKey(prf),
      { name: "AES-GCM", iv: b64urlDecode(w.iv) as BufferSource, additionalData: aad(w.fingerprint, w.credential) as BufferSource },
      { name: "Ed25519" }, extractable, ["sign"]);
  } catch {
    throw new PasskeyMismatchError();
  }
  const pub = await crypto.subtle.importKey("jwk", { ...publicJwk }, { name: "Ed25519" }, false, ["verify"]);
  const probe = utf8.encode("openmanuals key wrap check");
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, privateKey, probe as BufferSource);
  if (!(await crypto.subtle.verify({ name: "Ed25519" }, pub, sig, probe as BufferSource))) throw new Error("unwrapped key does not match its public key");
  return { id: "primary", alg: "Ed25519", publicJwk, fingerprint: w.fingerprint, privateKey, createdAt: w.createdAt, reason: "passkey" };
}

/** Merge wrap lists, one per credential id (the newest wins). */
export function mergeWraps(...lists: (KeyWrap[] | undefined)[]): KeyWrap[] {
  const by = new Map<string, KeyWrap>();
  for (const w of lists.flat()) {
    if (!w || !isKeyWrap(w)) continue;
    const old = by.get(w.credential);
    if (!old || old.createdAt < w.createdAt) by.set(w.credential, w);
  }
  return [...by.values()].sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}

/** The message signed for a key-wrap write; mirrors openmanuals_server::keywrap::message. */
export async function keyWrapMessage(method: "PUT" | "DELETE", fp: string, credential: string, wrap: string | null, at: string): Promise<Uint8Array> {
  const hash = wrap === null ? "" : hex(new Uint8Array(await crypto.subtle.digest("SHA-256", utf8.encode(wrap) as BufferSource)));
  return utf8.encode(`openmanuals key-wrap v1\n${method}\n${fp}\n${credential}\n${hash}\n${at}`);
}
