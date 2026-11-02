// Ariadne Signature Profile (v0): the identity document of a key, as a JWS.
// Header and payload member order mirror openmanuals_core::asp::build so a profile
// signed here is byte-identical to one signed by the CLI for the same inputs.
import { b64url, utf8 } from "./b64.ts";
import { signRaw, type KeyRecord } from "./keys.ts";

export const NS = "http://ariadne.id/";

export interface ProfileInput { name: string; claims: string[]; description?: string; avatarUrl?: string }

export function buildProfile(key: KeyRecord, p: ProfileInput): { header: Record<string, unknown>; payload: Record<string, unknown> } {
  const jwk: Record<string, string> = { crv: key.publicJwk.crv, kty: key.publicJwk.kty, x: key.publicJwk.x };
  const header = { typ: "JWT", alg: "EdDSA", kid: key.fingerprint, jwk };
  const payload: Record<string, unknown> = {};
  payload[`${NS}version`] = 0;
  payload[`${NS}type`] = "profile";
  payload[`${NS}name`] = p.name;
  payload[`${NS}claims`] = p.claims;
  if (p.description !== undefined) payload[`${NS}description`] = p.description;
  if (p.avatarUrl !== undefined) payload[`${NS}avatar_url`] = p.avatarUrl;
  return { header, payload };
}

export async function signProfile(key: KeyRecord, p: ProfileInput): Promise<string> {
  const { header, payload } = buildProfile(key, p);
  const input = `${b64url(utf8.encode(JSON.stringify(header)))}.${b64url(utf8.encode(JSON.stringify(payload)))}`;
  const sig = await signRaw(key, utf8.encode(input));
  return `${input}.${b64url(sig)}`;
}

export function aspeUri(domain: string, fp: string): string {
  return `aspe:${domain}:${fp.toUpperCase()}`;
}

/** Decode (without verifying) a profile JWS payload. */
export function decodeProfile(jws: string): { fingerprint: string; name: string; claims: string[]; description?: string; avatarUrl?: string } {
  const [h, p] = jws.split(".");
  const dec = (s: string) => JSON.parse(utf8.decode(Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4)), (c) => c.charCodeAt(0))));
  const header = dec(h), payload = dec(p);
  return { fingerprint: header.kid, name: payload[`${NS}name`], claims: payload[`${NS}claims`] ?? [], description: payload[`${NS}description`], avatarUrl: payload[`${NS}avatar_url`] };
}
