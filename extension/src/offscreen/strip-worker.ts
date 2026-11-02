// Web Worker: runs the watermark stripper (openmanuals-strip as wasm) off the main
// thread. One worker per file, so the wasm memory it grew is freed after.
import { stripPdf } from "../strip/index.ts";

self.onmessage = async (ev: MessageEvent<{ bytes: Uint8Array }>) => {
  try {
    const r = await stripPdf(ev.data.bytes);
    const reply = { changed: r.changed, bytes: r.changed ? r.bytes : undefined, version: r.version, log: r.log };
    (self as unknown as Worker).postMessage(reply, reply.bytes ? [reply.bytes.buffer as ArrayBuffer] : []);
  } catch (e) {
    (self as unknown as Worker).postMessage({ changed: false, version: "", log: [], error: String((e as Error).message ?? e) });
  }
};
