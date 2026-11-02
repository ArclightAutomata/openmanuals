// Large byte buffers shared between the service worker and the offscreen
// document go through IndexedDB (same extension origin), since runtime
// messages are JSON-serialized.
const DB_NAME = "openmanuals";
const STORE = "blobs";

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 2);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains("keys")) db.createObjectStore("keys", { keyPath: "id" });
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function op<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return openDb().then((db) => new Promise<T>((resolve, reject) => {
    const t = db.transaction(STORE, mode);
    const r = fn(t.objectStore(STORE));
    r.onsuccess = () => { resolve(r.result); db.close(); };
    r.onerror = () => { reject(r.error); db.close(); };
  }));
}

export const putBlob = (key: string, bytes: Uint8Array) => op("readwrite", (s) => s.put(new Blob([bytes as BlobPart]), key));
export async function getBlob(key: string): Promise<Uint8Array | null> {
  const b = await op<Blob | undefined>("readonly", (s) => s.get(key));
  return b ? new Uint8Array(await b.arrayBuffer()) : null;
}
export const deleteBlob = (key: string) => op("readwrite", (s) => s.delete(key));
