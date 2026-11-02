// Type shims for the parts of doipjs we import by path (its package exports map
// only exposes the full bundle, which drags in openpgp/xmpp/irc).
declare module "*/doipjs/src/serviceProviders/index.js" {
  export const data: Record<string, { reURI: RegExp; processURI(uri: string): ServiceProviderLike; tests?: unknown[] }>;
  export const list: string[];
}
declare module "*/doipjs/src/verifications.js" {
  export function run(proofData: unknown, claimData: ServiceProviderLike, fingerprint: string): Promise<{ result: boolean; completed: boolean; errors: unknown[] }>;
}
interface ServiceProviderLike {
  about: { id: string; name: string; homepage?: string };
  profile: { display: string; uri: string; qr: string | null };
  claim: { uriRegularExpression: string; uriIsAmbiguous: boolean };
  proof: {
    request: { uri: string | null; fetcher: string; accessRestriction: string; data: Record<string, unknown> };
    response: { format: string };
    target: Array<{ format: string; encoding: string; relation: string; path: string[] }>;
  };
}
