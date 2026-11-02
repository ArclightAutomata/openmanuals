// A read-only SQLite VFS over PageReaders, for @sqlite.org/sqlite-wasm.
// Databases are opened as `file:<name>?vfs=omrange&immutable=1&mode=ro`;
// <name> must have been registered with `register`.
import type { PageReader } from "./pages.ts";

// The sqlite-wasm module object; typed loosely, the API is large.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Sqlite3 = any;

export const VFS_NAME = "omrange";

export interface RangeVfs {
  register(name: string, reader: PageReader): void;
  unregister(name: string): void;
}

let installed: RangeVfs | null = null;

export function installRangeVfs(sqlite3: Sqlite3): RangeVfs {
  if (installed) return installed;
  const { capi, wasm } = sqlite3;
  const files = new Map<string, PageReader>();
  const open = new Map<number, PageReader>();
  let lastError: unknown = null;
  const fail = (e: unknown, rc = capi.SQLITE_IOERR) => { lastError = e; return rc; };

  const io = new capi.sqlite3_io_methods();
  io.$iVersion = 1;
  sqlite3.vfs.installVfs({
    io: {
      struct: io,
      methods: {
        xClose: (pFile: number) => { open.delete(Number(pFile)); return 0; },
        xRead: (pFile: number, pDest: number, n: number, offset64: bigint) => {
          const r = open.get(Number(pFile));
          if (!r) return capi.SQLITE_IOERR;
          try {
            const off = Number(offset64);
            const heap = wasm.heap8u();
            const avail = Math.max(0, Math.min(n, r.size - off));
            if (avail > 0) heap.set(r.read(off, avail), Number(pDest));
            if (avail < n) {
              heap.fill(0, Number(pDest) + avail, Number(pDest) + n);
              return capi.SQLITE_IOERR_SHORT_READ;
            }
            return 0;
          } catch (e) {
            return fail(e);
          }
        },
        xWrite: () => capi.SQLITE_READONLY,
        xTruncate: () => capi.SQLITE_READONLY,
        xSync: () => 0,
        xFileSize: (pFile: number, pSz64: number) => {
          const r = open.get(Number(pFile));
          if (!r) return capi.SQLITE_IOERR;
          wasm.poke64(pSz64, BigInt(r.size));
          return 0;
        },
        xLock: () => 0,
        xUnlock: () => 0,
        xCheckReservedLock: (_p: number, pOut: number) => { wasm.poke32(pOut, 0); return 0; },
        xFileControl: () => capi.SQLITE_NOTFOUND,
        xSectorSize: () => 4096,
        xDeviceCharacteristics: () => capi.SQLITE_IOCAP_IMMUTABLE,
      },
    },
  });

  const vfs = new capi.sqlite3_vfs();
  const dflt = new capi.sqlite3_vfs(capi.sqlite3_vfs_find(null));
  vfs.$iVersion = 2;
  vfs.$szOsFile = capi.sqlite3_file.structInfo.sizeof;
  vfs.$mxPathname = 1024;
  vfs.$xRandomness = dflt.$xRandomness;
  vfs.$xSleep = dflt.$xSleep;
  dflt.dispose();
  sqlite3.vfs.installVfs({
    vfs: {
      struct: vfs,
      name: VFS_NAME,
      methods: {
        xOpen: (_pVfs: number, zName: number, pFile: number, flags: number, pOutFlags: number) => {
          const name = zName ? wasm.cstrToJs(zName) : "";
          const r = files.get(name);
          if (!r || flags & capi.SQLITE_OPEN_READWRITE) return fail(new Error(`cannot open ${name}`), capi.SQLITE_CANTOPEN);
          open.set(Number(pFile), r);
          const f = new capi.sqlite3_file(pFile);
          f.$pMethods = io.pointer;
          f.dispose();
          wasm.poke32(pOutFlags, capi.SQLITE_OPEN_READONLY);
          return 0;
        },
        xAccess: (_pVfs: number, zName: number, _flags: number, pOut: number) => {
          wasm.poke32(pOut, files.has(wasm.cstrToJs(zName)) ? 1 : 0);
          return 0;
        },
        xDelete: () => 0,
        xFullPathname: (_pVfs: number, zName: number, nOut: number, pOut: number) => (wasm.cstrncpy(pOut, zName, nOut) < nOut ? 0 : capi.SQLITE_CANTOPEN),
        xCurrentTime: (_pVfs: number, pOut: number) => { wasm.poke(pOut, 2440587.5 + Date.now() / 864e5, "double"); return 0; },
        xCurrentTimeInt64: (_pVfs: number, pOut: number) => { wasm.poke(pOut, 0xbfc83e532200 + Date.now(), "i64"); return 0; },
        xGetLastError: (_pVfs: number, nOut: number, pOut: number) => {
          const msg = lastError ? String((lastError as Error).message ?? lastError) : "";
          lastError = null;
          if (msg && nOut > 0) {
            const scope = wasm.scopedAllocPush();
            try {
              const [c] = wasm.scopedAllocCString(msg, true);
              wasm.cstrncpy(pOut, c, nOut);
            } finally {
              wasm.scopedAllocPop(scope);
            }
          }
          return 0;
        },
      },
    },
  });

  installed = {
    register: (name, reader) => { files.set(name, reader); },
    unregister: (name) => { files.delete(name); },
  };
  return installed;
}
