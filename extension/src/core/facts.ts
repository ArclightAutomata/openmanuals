// Fact envelopes: build, sign (WebCrypto), and the bundle types the pipeline emits.
// Canonical bytes come from openmanuals-wasm so they are byte-identical to the server's.
import { b64url, utf8 } from "./b64.ts";
import type { PublicJwk, Alg } from "./fingerprint.ts";
import { signRaw, type KeyRecord } from "./keys.ts";
import { ensureWasm } from "./wasm.ts";

export interface Sig { alg: Alg; fmt: "raw"; key: PublicJwk; value: string }

export interface Fact {
  v: 1;
  type: string;
  author: string;
  at: string;
  body: Record<string, unknown>;
  sig?: Sig;
}

export type UnsignedFact = Omit<Fact, "sig" | "author" | "v"> & { author?: string };

export function nowIso(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

export function unsigned(type: string, body: Record<string, unknown>, at: string = nowIso()): UnsignedFact {
  return { type, body, at };
}

/** Sign one fact with the key; returns a fresh object with `author` and `sig`. */
export async function signFact(key: KeyRecord, f: UnsignedFact): Promise<Fact> {
  const om = await ensureWasm();
  const fact: Fact = { v: 1, type: f.type, author: key.fingerprint, at: f.at, body: f.body };
  const canonical = om.fact_canonical(JSON.stringify(fact));
  const sig = await signRaw(key, utf8.encode(canonical));
  // The minimal public JWK, member order crv/kty/x as openmanuals-core emits it.
  const jwk: PublicJwk = { crv: key.publicJwk.crv, kty: key.publicJwk.kty, x: key.publicJwk.x } as PublicJwk;
  fact.sig = { alg: key.alg, fmt: "raw", key: jwk, value: b64url(sig) };
  return fact;
}

export async function signFacts(key: KeyRecord, facts: UnsignedFact[]): Promise<Fact[]> {
  const out: Fact[] = [];
  for (const f of facts) out.push(await signFact(key, f));
  return out;
}

export async function factId(f: Fact): Promise<string> {
  return (await ensureWasm()).fact_id(JSON.stringify(f));
}

/** Verify a signed fact with openmanuals-core; returns its id or throws. */
export async function verifyFact(f: Fact): Promise<string> {
  return (await ensureWasm()).verify_fact(JSON.stringify(f));
}

// ---- body helpers -----------------------------------------------------------

export type LocationKind = "archive" | "origin" | "mirror" | "vendor";

export const bodies = {
  file: (h: { sha256: string; sha1: string; md5: string; size: number }, mime: string, pages?: number) =>
    ({ sha256: h.sha256, sha1: h.sha1, md5: h.md5, size: h.size, mime, ...(pages ? { pages } : {}) }),
  location: (file: string, url: string, kind: LocationKind, ia?: { identifier: string; filename: string }) =>
    ({ file, url, kind, ...(ia ? { ia } : {}) }),
  /** `src` names the source page (`manualslib`/`331384` and its URL): lookups, the lookup filter and the per-site counts use it. */
  manual: (id: string, title: string, doc_type: string, language?: string, src?: { source: string; sourceId: string; sourceUrl: string }) =>
    ({
      id, title, doc_type, ...(language ? { language } : {}),
      ...(src?.source && src.sourceId ? { source: src.source, source_id: src.sourceId, ...(src.sourceUrl ? { source_url: src.sourceUrl } : {}) } : {}),
    }),
  manualFile: (manual: string, file: string, role: "primary" | "supplement" = "primary") => ({ manual, file, role }),
  product: (brand: string, model: string) => ({ brand, model }),
  covers: (manual: string, product: string) => ({ manual, product }),
  derivation: (derived: string, source: string, transform: string, tool: string, tool_version: string) =>
    ({ derived, source, transform, tool, tool_version }),
  label: (target: string, ns: string, value: string, reason?: string) => ({ target, ns, value, ...(reason ? { reason } : {}) }),
  identityProfile: (jws: string) => ({ jws }),
  /** See core/avatar.ts: {sha256, size, mime}, {url} or {none: true}. */
  avatar: (b: import("./avatar.ts").AvatarBody) => ({ ...b }),
  retract: (fact: string) => ({ fact }),
};

/** Guess a manual's document type from its title. */
export function guessDocType(title: string): string {
  const t = title.toLowerCase();
  if (/service|repair|servicing/.test(t)) return "service";
  if (/schematic|circuit|wiring|diagram/.test(t)) return "schematic";
  if (/parts? (list|catalog)|spare parts|exploded/.test(t)) return "parts";
  if (/user|owner|operat|instruction|manual|guide|handbook|quick start|setup/.test(t)) return "user";
  return "other";
}
