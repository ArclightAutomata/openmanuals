// Reads a published snapshot page by page over HTTP Range requests and checks
// every page against the per-page hashes the signed manifest vouches for, so
// the bytes can come from any mirror. Synchronous on purpose: SQLite's VFS
// read callback is synchronous (this runs in a Web Worker with sync XHR).

/** Fetch bytes [start, end) of `url` synchronously. Must not return more or fewer. */
export type FetchRange = (url: string, start: number, end: number) => Uint8Array;
/** Synchronous sha256, lowercase hex. */
export type Sha256Hex = (bytes: Uint8Array) => string;

/** What the manifest's `latest` says about one version ("The manifest" in README.md). */
export interface SnapshotRef {
  /** Base URL of the snapshots directory, ending in `/`. */
  base: string;
  version: string;
  file: string;
  size: number;
  pages: { file: string; page_size: number; count: number; group: number; groups: string[] };
}

export interface ReaderStats { requests: number; bytes: number; pagesFetched: number; cacheHits: number; groupsFetched: number }

export class IntegrityError extends Error {}

/** Hash groups fetched per request (16 × 4 KiB). */
const HASH_CHUNK = 16;

export class PageReader {
  readonly stats: ReaderStats = { requests: 0, bytes: 0, pagesFetched: 0, cacheHits: 0, groupsFetched: 0 };
  private cache = new Map<number, Uint8Array>();
  private groups = new Map<number, Uint8Array>();
  private last = -2;
  private run = 1;

  readonly ref: SnapshotRef;
  private fetchRange: FetchRange;
  private sha256: Sha256Hex;
  private maxCachePages: number;
  private maxReadAhead: number;

  constructor(ref: SnapshotRef, fetchRange: FetchRange, sha256: Sha256Hex, maxCachePages = 2048, maxReadAhead = 64) {
    this.ref = ref;
    this.fetchRange = fetchRange;
    this.sha256 = sha256;
    this.maxCachePages = maxCachePages;
    this.maxReadAhead = maxReadAhead;
    const p = ref.pages;
    if (p.count * p.page_size !== ref.size) throw new IntegrityError("manifest page count does not match the file size");
    if (p.groups.length !== Math.ceil(p.count / p.group)) throw new IntegrityError("manifest page groups do not match the page count");
  }

  get size(): number { return this.ref.size; }

  /** Bytes [offset, offset + n), assembled from verified pages. */
  read(offset: number, n: number): Uint8Array {
    const ps = this.ref.pages.page_size;
    const out = new Uint8Array(n);
    let pos = offset;
    while (pos < offset + n) {
      const idx = Math.floor(pos / ps);
      const page = this.page(idx);
      const from = pos - idx * ps;
      const take = Math.min(ps - from, offset + n - pos);
      out.set(page.subarray(from, from + take), pos - offset);
      pos += take;
    }
    return out;
  }

  private page(i: number): Uint8Array {
    const hit = this.cache.get(i);
    if (hit) {
      this.stats.cacheHits++;
      this.cache.delete(i); // LRU: move to the end
      this.cache.set(i, hit);
      this.last = i;
      return hit;
    }
    // Sequential reads (table scans) fetch growing runs; random reads one page.
    this.run = i === this.last + 1 ? Math.min(this.run * 2, this.maxReadAhead) : 1;
    const { page_size: ps, count } = this.ref.pages;
    let n = Math.min(this.run, count - i);
    while (n > 1 && this.cache.has(i + n - 1)) n--;
    const bytes = this.get(this.ref.file, i * ps, (i + n) * ps);
    for (let k = 0; k < n; k++) {
      const pg = bytes.subarray(k * ps, (k + 1) * ps);
      this.verify(i + k, pg);
      this.put(i + k, pg);
    }
    this.stats.pagesFetched += n;
    this.last = i + n - 1;
    return this.cache.get(i)!;
  }

  private verify(i: number, page: Uint8Array) {
    const { group } = this.ref.pages;
    const hashes = this.group(Math.floor(i / group));
    const off = (i % group) * 32;
    if (hex(hashes.subarray(off, off + 32)) !== this.sha256(page)) throw new IntegrityError(`page ${i} does not match its hash`);
  }

  /**
   * The 32-byte hashes of one group of pages, checked against the manifest.
   * Fetched HASH_CHUNK groups at a time (64 KiB) to save round trips.
   */
  private group(g: number): Uint8Array {
    const hit = this.groups.get(g);
    if (hit) return hit;
    const { group, count, groups } = this.ref.pages;
    const g0 = g - (g % HASH_CHUNK);
    const g1 = Math.min(g0 + HASH_CHUNK, groups.length);
    const start = g0 * group * 32;
    const end = Math.min(g1 * group, count) * 32;
    const bytes = this.get(this.ref.pages.file, start, end);
    for (let k = g0; k < g1; k++) {
      const part = bytes.subarray((k - g0) * group * 32, Math.min((k - g0 + 1) * group * 32, bytes.length));
      if (this.sha256(part) !== groups[k]) throw new IntegrityError(`page hash group ${k} does not match the manifest`);
      this.groups.set(k, part.slice());
      this.stats.groupsFetched++;
    }
    return this.groups.get(g)!;
  }

  private get(file: string, start: number, end: number): Uint8Array {
    const b = this.fetchRange(this.ref.base + file, start, end);
    if (b.length !== end - start) throw new IntegrityError(`expected ${end - start} bytes of ${file}, got ${b.length}`);
    this.stats.requests++;
    this.stats.bytes += b.length;
    return b;
  }

  private put(i: number, page: Uint8Array) {
    this.cache.set(i, page.slice());
    while (this.cache.size > this.maxCachePages) this.cache.delete(this.cache.keys().next().value!);
  }
}

function hex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

/** Synchronous ranged GET for Web Workers (sync XHR is allowed there). */
export function xhrFetchRange(url: string, start: number, end: number): Uint8Array {
  const x = new XMLHttpRequest();
  x.open("GET", url, false);
  x.responseType = "arraybuffer";
  x.setRequestHeader("Range", `bytes=${start}-${end - 1}`);
  x.send();
  if (x.status !== 206) throw new Error(`range request to ${url} answered ${x.status}`);
  return new Uint8Array(x.response as ArrayBuffer);
}
