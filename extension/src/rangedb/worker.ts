// Web Worker (in the offscreen document) that answers lookups from a mirror of
// published snapshots with HTTP Range requests: SQLite runs here over a VFS
// whose pages are fetched with synchronous XHR and checked against the signed
// manifest. Used when the OpenManuals server is unreachable.
import sqlite3InitModule from "@sqlite.org/sqlite-wasm";
import { fingerprint, type PublicJwk } from "../core/fingerprint.ts";
import { fetchManifest } from "./manifest.ts";
import { lookup, type PageQuery } from "./lookup.ts";
import { IntegrityError, PageReader, xhrFetchRange, type SnapshotRef } from "./pages.ts";
import { sha256Hex } from "./sha256.ts";
import { installRangeVfs, VFS_NAME } from "./vfs.ts";

export interface MirrorRequest {
  id: number;
  mirrors: string[];
  /** Fingerprint of the server key the manifest must be signed by. */
  pinned: string;
  publicUrl: string;
  page?: PageQuery;
  file?: string;
}
export interface MirrorReply { id: number; ok: boolean; result?: unknown; mirror?: string; version?: string; error?: string; stats?: unknown }

// eslint-disable-next-line @typescript-eslint/no-explicit-any
let sqlite3: any = null;
interface Open { base: string; pinned: string; ref: SnapshotRef; reader: PageReader; db: { close(): void }; checked: number }
let current: Open | null = null;
const MANIFEST_TTL = 10 * 60 * 1000;

async function fp(jwk: object): Promise<string> { return fingerprint(jwk as PublicJwk); }

async function open(base: string, pinned: string, force = false): Promise<Open> {
  // Reuse only what was verified against the same pinned key.
  const same = (o: Open | null): o is Open => !!o && o.base === base && o.pinned === pinned;
  if (same(current) && !force && Date.now() - current.checked < MANIFEST_TTL) return current;
  sqlite3 ??= await sqlite3InitModule();
  const vfs = installRangeVfs(sqlite3);
  // fetchManifest wants a sync fingerprint: precompute it for the embedded key.
  const peek = await (await fetch(base + "manifest.json", { cache: "no-cache" })).json().catch(() => null);
  const keyFp = peek?.server_key ? await fp(peek.server_key) : "";
  const { ref } = await fetchManifest(base, pinned, () => keyFp);
  if (same(current) && current.ref.version === ref.version) {
    current.checked = Date.now();
    return current;
  }
  close();
  const reader = new PageReader(ref, xhrFetchRange, sha256Hex);
  const name = `${ref.version}@${base}`;
  vfs.register(name, reader);
  const db = new sqlite3.oo1.DB(`file:${encodeURIComponent(name)}?vfs=${VFS_NAME}&immutable=1&mode=ro`, "r");
  current = { base, pinned, ref, reader, db, checked: Date.now() };
  return current;
}

function close() {
  if (!current) return;
  try { current.db.close(); } catch { /* already gone */ }
  current = null;
}

async function answer(req: MirrorRequest): Promise<MirrorReply> {
  const errors: string[] = [];
  for (const base of req.mirrors) {
    for (const force of [false, true]) {
      try {
        const o = await open(base, req.pinned, force);
        const result = lookup(o.db, req.publicUrl, { page: req.page, file: req.file });
        return { id: req.id, ok: true, result, mirror: base, version: o.ref.version, stats: { ...o.reader.stats } };
      } catch (e) {
        errors.push(`${base}: ${(e as Error).message ?? e}`);
        close();
        // A pruned version (404) deserves one retry with a fresh manifest; bad
        // bytes mean this mirror is not to be trusted right now.
        if (e instanceof IntegrityError) break;
      }
    }
  }
  return { id: req.id, ok: false, error: errors.join("; ") || "no mirrors configured" };
}

self.onmessage = (ev: MessageEvent<MirrorRequest>) => {
  answer(ev.data).then((r) => (self as unknown as Worker).postMessage(r));
};
