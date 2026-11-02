// Identity proofs, Keyoxide style. The user places the identifier where only
// they can (a gist, a DNS record, a profile field); we fetch that resource
// and check it contains the identifier. Matching and the proof check come
// from doipjs; the fetching is ours (browser fetch + DNS-over-HTTPS), so no
// proxy and none of doipjs's Node fetchers are bundled.
import { data as providers, list as providerList } from "../../node_modules/doipjs/src/serviceProviders/index.js";
import { run } from "../../node_modules/doipjs/src/verifications.js";

export interface Service {
  id: string;
  name: string;
  /** Where the identifier must appear. */
  where: string;
  /** What claim URL to paste back. */
  claimExample: string;
  /** Host patterns we need permission for (optional host permission). */
  hosts: string[];
}

export const SERVICES: Service[] = [
  { id: "github", name: "GitHub", where: "Create a public gist with a file named proof.md (the filename matters) whose content is the identifier below.", claimExample: "https://gist.github.com/<user>/<gist id>", hosts: ["https://api.github.com/*"] },
  { id: "gitlab", name: "GitLab", where: "Create a public project named gitlab_proof whose description is the identifier below.", claimExample: "https://gitlab.com/<user>/gitlab_proof", hosts: ["https://gitlab.com/*"] },
  { id: "forgejo", name: "Codeberg / Forgejo", where: "Create a public repository named forgejo_proof (or gitea_proof) whose description is the identifier below.", claimExample: "https://codeberg.org/<user>/forgejo_proof", hosts: ["https://codeberg.org/*"] },
  { id: "activitypub", name: "Mastodon / Fediverse", where: "Add a profile metadata field (or put in your bio) the identifier below.", claimExample: "https://<instance>/@<user>", hosts: [] },
  { id: "dns", name: "DNS", where: "Add a TXT record on the domain containing the identifier below.", claimExample: "dns:<yourdomain.org>?type=TXT", hosts: ["https://cloudflare-dns.com/*"] },
  { id: "keyoxide", name: "Keyoxide identity", where: "Add the identifier below as a claim on your Keyoxide profile (for an OpenPGP key: the notation proof@ariadne.id=<identifier>; https://openmanuals.org/k/<fingerprint> works too). Then add your Keyoxide identity here; this signed profile listing it is the proof Keyoxide checks.", claimExample: "aspe:keyoxide.org:<fingerprint> or openpgp4fpr:<fingerprint>", hosts: [] },
  { id: "website", name: "Website", where: "Serve the identifier in the page body, or send it in an ariadne-identity-proof response header.", claimExample: "https://<yourdomain.org>/", hosts: [] },
];

/** Hosts the claim's proof is fetched from, for a permission request. */
export function hostsFor(claimUri: string, serviceId: string): string[] {
  const svc = SERVICES.find((s) => s.id === serviceId);
  const out = new Set(svc?.hosts ?? []);
  const aspe = /^aspe:([a-zA-Z0-9.\-_]+):/.exec(claimUri);
  if (aspe) out.add(`https://${aspe[1]}/*`);
  else if (/^openpgp4fpr:/i.test(claimUri)) out.add("https://keys.openpgp.org/*");
  else {
    try {
      const u = new URL(claimUri);
      if (u.protocol === "https:") out.add(`https://${u.host}/*`);
    } catch { /* dns: uri */ }
  }
  return [...out];
}

export interface ProofResult { ok: boolean; service: string | null; display: string | null; errors: string[]; fetched?: string }

/** Match a claim URI to doipjs service definitions. */
export function matchClaim(uri: string) {
  const matches: { id: string; def: ServiceProviderLike }[] = [];
  for (const name of providerList) {
    const p = providers[name];
    if (!p.reURI.test(uri)) continue;
    const def = p.processURI(uri);
    if (!def) continue;
    if (def.claim.uriIsAmbiguous) { matches.push({ id: name, def }); continue; }
    // An unambiguous definition is the answer; drop the ambiguous candidates (as doipjs does).
    return [{ id: name, def }];
  }
  return matches;
}

async function fetchProof(def: ServiceProviderLike): Promise<unknown> {
  const req = def.proof.request;
  const d = req.data as { url?: string; domain?: string; format?: string };
  switch (req.fetcher) {
    case "http": {
      const res = await fetch(d.url!, { headers: { Accept: d.format === "json" ? "application/json" : "text/plain, text/html;q=0.9, */*;q=0.8" }, cache: "no-store" });
      if (!res.ok) throw new Error(`${d.url} answered ${res.status}`);
      return d.format === "json" ? res.json() : res.text();
    }
    case "activitypub": {
      const res = await fetch(d.url!, { headers: { Accept: "application/activity+json, application/ld+json" }, cache: "no-store" });
      if (!res.ok) throw new Error(`${d.url} answered ${res.status}`);
      return res.json();
    }
    case "dns": {
      const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(d.domain!)}&type=TXT`, { headers: { Accept: "application/dns-json" }, cache: "no-store" });
      if (!res.ok) throw new Error(`DNS lookup failed (${res.status})`);
      const j = (await res.json()) as { Answer?: { type: number; data: string }[] };
      const txt = (j.Answer ?? []).filter((a) => a.type === 16).map((a) => [a.data.replace(/^"|"$/g, "").replace(/"\s*"/g, "")]);
      return { hostname: d.domain, records: { txt } };
    }
    case "aspe": {
      // Another ASP profile (e.g. on keyoxide.org): its claims must list ours.
      // Only a preview: the signature isn't checked here; the server's
      // verifier (doipjs) does that.
      const m = /^aspe:([a-zA-Z0-9.\-_]+):([a-zA-Z0-9]+)/.exec((req.data as { aspeUri?: string }).aspeUri ?? "");
      if (!m) throw new Error("not an aspe: URI");
      const url = `https://${m[1]}/.well-known/aspe/id/${m[2].toUpperCase()}`;
      const res = await fetch(url, { headers: { Accept: "application/asp+jwt" }, cache: "no-store" });
      if (!res.ok) throw new Error(`${url} answered ${res.status}`);
      return { claims: aspeClaims(await res.text()) };
    }
    default:
      throw new Error(`Proofs on ${def.about.name} need a fetcher this extension doesn't have (${req.fetcher}).`);
  }
}

/** The claims in an ASP profile JWS (payload only; the signature is not checked). */
export function aspeClaims(jws: string): string[] {
  const part = jws.trim().split(".")[1] ?? "";
  const b64 = part.replace(/-/g, "+").replace(/_/g, "/");
  const json = new TextDecoder().decode(Uint8Array.from(atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4)), (c) => c.charCodeAt(0)));
  const claims = (JSON.parse(json) as Record<string, unknown>)["http://ariadne.id/claims"];
  return Array.isArray(claims) ? claims.filter((c): c is string => typeof c === "string") : [];
}

/** Why a fetched proof didn't match, as specifically as we can tell. */
export function notFoundHint(service: string, proof: unknown): string {
  if (service === "github") {
    // doipjs reads only these two files of a gist.
    const files = Object.keys((proof as { files?: Record<string, unknown> })?.files ?? {});
    if (!files.includes("proof.md") && !files.includes("openpgp.md")) {
      return `the gist needs a file named "proof.md" containing the identifier${files.length ? ` (it has ${files.map((f) => `"${f}"`).join(", ")})` : ""}.`;
    }
    return `the gist's "proof.md" doesn't contain the identifier.`;
  }
  return "identifier not found in the proof.";
}

/** Verify one claim against the identity's `aspe:` URI. */
export async function verifyClaim(claimUri: string, aspe: string): Promise<ProofResult> {
  const matches = matchClaim(claimUri);
  if (!matches.length) return { ok: false, service: null, display: null, errors: ["No known service matches that URL."] };
  const errors: string[] = [];
  for (const m of matches) {
    try {
      const proof = await fetchProof(m.def);
      const r = await run(proof, m.def, aspe);
      if (r.result) return { ok: true, service: m.def.about.name, display: m.def.profile.display, errors: [] };
      errors.push(`${m.def.about.name}: ${notFoundHint(m.def.about.id, proof)}`);
    } catch (e) {
      errors.push(`${m.def.about.name}: ${(e as Error).message}`);
    }
  }
  return { ok: false, service: matches[0].def.about.name, display: matches[0].def.profile.display, errors };
}
