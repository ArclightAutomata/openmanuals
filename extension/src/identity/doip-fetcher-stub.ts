// Stands in for doipjs's fetcher/index.js in the extension bundle. The service
// provider definitions import it for post-processing (e.g. resolving a
// Fediverse display name); we fetch proofs ourselves in proofs.ts.
export const activitypub = { fn: async (): Promise<null> => null };
export const http = { fn: async (): Promise<null> => null };
export const dns = { fn: async (): Promise<null> => null };
export const graphql = { fn: async (): Promise<null> => null };
export const matrix = { fn: async (): Promise<null> => null };
export const irc = { fn: async (): Promise<null> => null };
export const xmpp = { fn: async (): Promise<null> => null };
export const telegram = { fn: async (): Promise<null> => null };
export const openpgp = { fn: async (): Promise<null> => null };
export const aspe = { fn: async (): Promise<null> => null };
