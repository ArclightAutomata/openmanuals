// Ariadne Signature Profile fingerprint: base32 (no padding) of the first 16
// bytes of SHA-512 over the compact JSON of {crv, kty, x} in that order.
// Mirrors openmanuals_core::key::PublicKey::fingerprint; checked against the vectors.
import { base32, utf8 } from "./b64.ts";
import { sha512 } from "./hash.ts";

/** The only signature algorithm: keys are Ed25519. */
export type Alg = "Ed25519";

export interface PublicJwk { kty: string; crv: string; x: string }

/** The minimal public JWK in RFC 7638 member order. */
export function minimalJwk(jwk: PublicJwk): PublicJwk {
  // insertion order crv, kty, x
  return { crv: jwk.crv, kty: jwk.kty, x: jwk.x } as PublicJwk;
}

export async function fingerprint(jwk: PublicJwk): Promise<string> {
  const s = JSON.stringify(minimalJwk(jwk));
  const digest = await sha512(utf8.encode(s));
  return base32(digest.subarray(0, 16));
}

export function algOf(jwk: PublicJwk): Alg {
  if (jwk.kty === "OKP" && jwk.crv === "Ed25519") return "Ed25519";
  throw new Error(`unsupported key ${jwk.kty}/${jwk.crv}`);
}

export const FINGERPRINT_RE = /^[A-Z2-7]{26}$/;
