// The server's /api/lookup (crates/openmanuals-server/src/api.rs), answered from a
// snapshot with SQL: same queries, same JSON. Every query uses an index, so
// over HTTP Range requests a lookup touches only a few pages.

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type DB = any; // sqlite3.oo1.DB

/** A source page as the background script parsed it (openmanuals-wasm). */
export interface PageQuery {
  url: string;
  /** Source and every spelling of its id the server would try (Elektrotanya: raw and decoded). */
  source?: string;
  sourceIds?: string[];
  legacy: string[];
}

type Row = Record<string, unknown>;

function rows(db: DB, sql: string, bind: unknown[]): Row[] {
  const out: Row[] = [];
  db.exec({ sql, bind, rowMode: "object", resultRows: out });
  return out;
}
function col(db: DB, sql: string, bind: unknown[]): string[] {
  return rows(db, sql, bind).map((r) => String(Object.values(r)[0]));
}

export function manualsForUrl(db: DB, q: PageQuery): string[] {
  const clean = q.url.split("#")[0];
  const ids: string[] = [];
  if (q.source) for (const sid of q.sourceIds ?? []) ids.push(...col(db, "SELECT id FROM manuals WHERE source = ?1 AND source_id = ?2 ORDER BY id", [q.source, sid]));
  ids.push(...col(db, "SELECT id FROM manuals WHERE source_url = ?1 OR source_url = ?2", [q.url, clean]));
  ids.push(...col(db, "SELECT mf.manual FROM locations l JOIN manual_files mf ON mf.file = l.file WHERE l.kind = 'origin' AND (l.url = ?1 OR l.url = ?2)", [q.url, clean]));
  return [...new Set(ids)].sort();
}

function copies(db: DB, fileId: string, canonical: string | null) {
  const out = rows(db, "SELECT id, url, kind, host, status, verified_at, author, ia_identifier, ia_filename FROM locations WHERE file = ?1 AND status = 'verified' AND flagged = 0 ORDER BY cursor", [fileId])
    .map((r) => ({
      id: r.id, url: r.url, kind: r.kind, host: r.host, status: r.status, verified_at: r.verified_at ?? null, author: r.author,
      ia: r.ia_identifier == null ? null : { identifier: r.ia_identifier, filename: r.ia_filename ?? null },
    }));
  return out.sort((a, b) => Number(a.id !== canonical) - Number(b.id !== canonical));
}

function fileJson(db: DB, fileId: string, canonicalForManual: string | null) {
  const r = rows(db, "SELECT id, sha256, sha1, md5, size, mime, pages, derived_from, transform, tool_version, canonical_location, author FROM files WHERE id = ?1 AND flagged = 0", [fileId])[0];
  if (!r) return null;
  return {
    id: r.id, sha256: r.sha256 ?? null, sha1: r.sha1 ?? null, md5: r.md5 ?? null, size: r.size ?? null, mime: r.mime ?? null, pages: r.pages ?? null,
    derived_from: r.derived_from ?? null, transform: r.transform ?? null, tool_version: r.tool_version ?? null,
    canonical: canonicalForManual === r.id, author: r.author,
    copies: copies(db, String(r.id), (r.canonical_location as string | null) ?? null),
  };
}

function manualJson(db: DB, publicUrl: string, id: string): [Row, string | null] | null {
  const r = rows(db, "SELECT id, title, doc_type, brand, model, canonical_file, source_url FROM manuals WHERE id = ?1", [id])[0];
  if (!r) return null;
  return [{ id: r.id, title: r.title, doc_type: r.doc_type, brand: r.brand ?? null, model: r.model ?? null, source_url: r.source_url ?? null, url: `${publicUrl}/manual/${r.id}` },
    (r.canonical_file as string | null) ?? null];
}

/** Lowercase sha256 hex or `sha1:<hex>` (openmanuals_ledger::model::parse_file_ref). */
export function parseFileRef(s: string): string | null {
  const t = s.trim();
  if (/^[0-9a-fA-F]{64}$/.test(t)) return t.toLowerCase();
  const m = /^sha1:([0-9a-fA-F]{40})$/.exec(t);
  return m ? `sha1:${m[1].toLowerCase()}` : null;
}

export function lookup(db: DB, publicUrl: string, q: { page?: PageQuery; file?: string }) {
  let manual: Row | null = null;
  let canonical: string | null = null;
  let fileIds: string[] = [];
  if (q.page) {
    const mid = manualsForUrl(db, q.page)[0];
    if (mid) {
      const m = manualJson(db, publicUrl, mid);
      if (m) [manual, canonical] = m;
      fileIds = col(db, "SELECT file FROM manual_files WHERE manual = ?1 ORDER BY file", [mid]);
    }
  } else if (q.file) {
    const id = parseFileRef(q.file);
    if (id) {
      if (rows(db, "SELECT 1 FROM files WHERE id = ?1", [id]).length) fileIds.push(id);
      const mid = col(db, "SELECT manual FROM manual_files WHERE file = ?1 ORDER BY manual LIMIT 1", [id])[0];
      if (mid) {
        const m = manualJson(db, publicUrl, mid);
        if (m) [manual, canonical] = m;
      }
    }
  }
  const files = fileIds.map((f) => fileJson(db, f, canonical)).filter((f) => f !== null);
  return { known: manual !== null || files.length > 0, manual, files, legacy_identifiers: q.page?.legacy ?? [], snapshot: true };
}
