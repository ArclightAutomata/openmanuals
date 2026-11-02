// WebAuthn for passkey-protected keys. Runs only in the options page: a
// passkey prompt needs a visible, focused page (not the service worker or the
// offscreen document). The relying party is the extension itself: rp.id is
// left out, so it defaults to the page's origin, and Chrome stores it as
// `chrome-extension://<id>`. Only this extension can
// therefore ask for these passkeys' PRF output.
import { b64urlDecode, utf8 } from "../core/b64.ts";
import { PRF_INPUT } from "../core/passkey.ts";

export class NoPrfError extends Error {
  constructor() {
    super("This passkey provider doesn't support the PRF extension that unlocks the key, so it can't protect it. Pick another provider, or use a passphrase and backup file (Advanced options). Google Password Manager, iCloud Keychain, Windows Hello (Windows 11, 2026 builds), 1Password and recent security keys support it.");
  }
}

type PrfResults = { enabled?: boolean; results?: { first?: BufferSource } };
const prfOf = (cred: PublicKeyCredential): PrfResults | undefined => (cred.getClientExtensionResults() as { prf?: PrfResults }).prf;
const bytes = (b: BufferSource | undefined | null): Uint8Array | null => (b ? new Uint8Array(ArrayBuffer.isView(b) ? b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) : b) : null);

/** The extension's relying-party origin, recorded in each wrap for display. */
export const rpOrigin = () => location.origin;

/**
 * Whether the browser says it can do PRF: true, false, or null when it can't
 * tell (no getClientCapabilities). `true` is only a hint: Chrome's local
 * profile authenticator says yes and has no PRF, so the result of create/get
 * is what counts.
 */
export async function prfCapability(): Promise<boolean | null> {
  if (typeof PublicKeyCredential === "undefined") return false;
  const gcc = (PublicKeyCredential as unknown as { getClientCapabilities?: () => Promise<Record<string, boolean>> }).getClientCapabilities;
  if (!gcc) return null;
  try { const c = await gcc.call(PublicKeyCredential); return "extension:prf" in c ? Boolean(c["extension:prf"]) : null; } catch { return null; }
}

function friendly(e: unknown): Error {
  const err = e as DOMException;
  if (err?.name === "NotAllowedError") return new Error("The passkey prompt was cancelled or timed out.");
  if (err?.name === "InvalidStateError") return new Error("This passkey provider already holds a passkey for this key. Pick a different provider (another password manager, phone or security key).");
  return err instanceof Error ? err : new Error(String(e));
}

/**
 * Create a discoverable passkey for the key `fingerprint` (its user.id, so
 * restoring needs no typing) and get its PRF output. Asks for the PRF at
 * creation; providers that only answer it on get() cost a second prompt.
 */
export async function registerPasskey(fingerprint: string, exclude: string[] = []): Promise<{ credential: string; prf: Uint8Array }> {
  let cred: PublicKeyCredential;
  try {
    cred = (await navigator.credentials.create({
      publicKey: {
        rp: { name: "OpenManuals" },
        user: { id: utf8.encode(fingerprint) as BufferSource, name: `OpenManuals key ${fingerprint}`, displayName: `OpenManuals key ${fingerprint.slice(0, 8)}…` },
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        pubKeyCredParams: [{ type: "public-key", alg: -8 }, { type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
        authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
        excludeCredentials: exclude.map((id) => ({ type: "public-key" as const, id: b64urlDecode(id) as BufferSource })),
        extensions: { prf: { eval: { first: PRF_INPUT as BufferSource } } } as AuthenticationExtensionsClientInputs,
      },
    })) as PublicKeyCredential;
  } catch (e) { throw friendly(e); }
  const credential = cred.id;
  const prf = prfOf(cred);
  const atCreate = bytes(prf?.results?.first);
  if (atCreate) return { credential, prf: atCreate };
  if (prf?.enabled === false || !prf) {
    await forgetPasskey(credential);
    throw new NoPrfError();
  }
  // enabled, but evaluated only on get (e.g. security keys without hmac-secret-mc).
  const a = await assertPrf([credential]);
  if (!a.prf) { await forgetPasskey(credential); throw new NoPrfError(); }
  return { credential, prf: a.prf };
}

/**
 * Ask for a passkey with PRF. With `allow`, only those credentials; without,
 * any discoverable passkey of this extension (restore), whose userHandle names
 * the key.
 */
export async function assertPrf(allow?: string[]): Promise<{ credential: string; prf: Uint8Array | null; userHandle: string | null }> {
  let a: PublicKeyCredential;
  try {
    a = (await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        userVerification: "required",
        ...(allow?.length ? { allowCredentials: allow.map((id) => ({ type: "public-key" as const, id: b64urlDecode(id) as BufferSource })) } : {}),
        extensions: { prf: { eval: { first: PRF_INPUT as BufferSource } } } as AuthenticationExtensionsClientInputs,
      },
    })) as PublicKeyCredential;
  } catch (e) { throw friendly(e); }
  const uh = bytes((a.response as AuthenticatorAssertionResponse).userHandle);
  return { credential: a.id, prf: bytes(prfOf(a)?.results?.first), userHandle: uh ? utf8.decode(uh) : null };
}

/** Tell the provider a passkey is no longer used (Chrome 132+), so it can offer to delete it. Best effort. */
export async function forgetPasskey(credential: string): Promise<void> {
  const signal = (PublicKeyCredential as unknown as { signalUnknownCredential?: (o: { rpId: string; credentialId: string }) => Promise<void> }).signalUnknownCredential;
  try { await signal?.call(PublicKeyCredential, { rpId: location.hostname, credentialId: credential }); } catch { /* not supported or refused */ }
}

