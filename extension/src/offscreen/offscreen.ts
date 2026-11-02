// Offscreen document: hosts the stripper worker. The service worker leaves the
// input in IndexedDB under the job id and expects the output under `<id>:out`.
import { getBlob, putBlob } from "../core/blobs.ts";

interface WorkerReply { changed: boolean; bytes?: Uint8Array; version: string; log: string[]; error?: string }

function runWorker(bytes: Uint8Array): Promise<WorkerReply> {
  return new Promise((resolve, reject) => {
    const w = new Worker("strip-worker.js", { type: "module" });
    w.onmessage = (ev: MessageEvent<WorkerReply>) => { w.terminate(); resolve(ev.data); };
    w.onerror = (ev) => { w.terminate(); reject(new Error(ev.message)); };
    const copy = bytes.slice();
    w.postMessage({ bytes: copy }, [copy.buffer]);
  });
}

// One long-lived worker for mirror lookups, so its page cache survives between them.
let mirrorWorker: Worker | null = null;
let nextId = 1;
const pending = new Map<number, (r: unknown) => void>();
function mirror(req: Record<string, unknown>): Promise<unknown> {
  if (!mirrorWorker) {
    mirrorWorker = new Worker("rangedb-worker.js", { type: "module" });
    mirrorWorker.onmessage = (ev: MessageEvent<{ id: number }>) => { pending.get(ev.data.id)?.(ev.data); pending.delete(ev.data.id); };
    mirrorWorker.onerror = (ev) => {
      for (const [id, done] of pending) done({ id, ok: false, error: ev.message });
      pending.clear();
      mirrorWorker = null;
    };
  }
  const id = nextId++;
  return new Promise((resolve) => { pending.set(id, resolve); mirrorWorker!.postMessage({ ...req, id }); });
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === "offscreen:mirror") {
    mirror(msg.request).then(sendResponse, (e) => sendResponse({ ok: false, error: String((e as Error).message ?? e) }));
    return true;
  }
  if (msg?.type !== "offscreen:strip") return false;
  (async () => {
    const input = await getBlob(msg.jobId);
    if (!input) return { ok: false, error: "no input blob" };
    const r = await runWorker(input);
    if (r.error) return { ok: false, error: r.error };
    if (r.changed && r.bytes) await putBlob(msg.jobId + ":out", r.bytes);
    return { ok: true, changed: r.changed, version: r.version, log: r.log };
  })().then(sendResponse, (e) => sendResponse({ ok: false, error: String((e as Error).message ?? e) }));
  return true;
});
