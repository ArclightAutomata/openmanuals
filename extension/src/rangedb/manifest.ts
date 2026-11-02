// Fetch and check a mirror's signed manifest (/db/manifest.json; "The manifest" in README.md).
import type { SnapshotRef } from "./pages.ts";

export interface Manifest {
  version: number;
  server: string;
  server_key: JsonWebKey & { crv: string; kty: string; x: string };
  latest: { version: string; head: string; file: string; sha256: string; size: number; pages: SnapshotRef["pages"]; tables: Record<string, string> };
}

function b64urlDecode(s: string): Uint8Array {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
}
async function sha256Hex(b: Uint8Array): Promise<string> {
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", b as BufferSource))].map((x) => x.toString(16).padStart(2, "0")).join("");
}

/**
 * The manifest at `base` (a snapshots directory URL ending in `/`), verified
 * against its embedded server key, which must have fingerprint `pinned`.
 * `fingerprint` computes a key's fingerprint (openmanuals-wasm).
 */
export async function fetchManifest(base: string, pinned: string, fingerprint: (jwk: object) => string, fetchFn: typeof fetch = fetch): Promise<{ manifest: Manifest; ref: SnapshotRef }> {
  const [mr, sr] = await Promise.all([fetchFn(base + "manifest.json", { cache: "no-cache" }), fetchFn(base + "manifest.json.sig", { cache: "no-cache" })]);
  if (!mr.ok || !sr.ok) throw new Error(`mirror ${base} has no manifest (${mr.status}/${sr.status})`);
  const bytes = new Uint8Array(await mr.arrayBuffer());
  const sig = b64urlDecode((await sr.text()).trim());
  const manifest = JSON.parse(new TextDecoder().decode(bytes)) as Manifest;
  const key = manifest.server_key;
  if (!key || fingerprint(key) !== pinned) throw new Error(`mirror ${base} is signed by a different server key`);
  const msg = new TextEncoder().encode(await sha256Hex(bytes));
  let ok: boolean;
  if (key.kty === "OKP" && key.crv === "Ed25519") {
    const k = await crypto.subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: key.x }, { name: "Ed25519" }, false, ["verify"]);
    ok = await crypto.subtle.verify({ name: "Ed25519" }, k, sig as BufferSource, msg);
  } else throw new Error(`unsupported server key ${key.kty}/${key.crv}`);
  if (!ok) throw new Error(`mirror ${base}: bad manifest signature`);
  const l = manifest.latest;
  return { manifest, ref: { base, version: l.version, file: l.file, size: l.size, pages: l.pages } };
}
