// Runs the watermark stripper in an offscreen document (which hosts a Web
// Worker), handing bytes over through IndexedDB.
import { deleteBlob, getBlob, putBlob } from "../core/blobs.ts";
import { ulid } from "../core/ulid.ts";

const OFFSCREEN_URL = "offscreen.html";
const STRIP_TIMEOUT_MS = 10 * 60 * 1000;

let creating: Promise<void> | null = null;

export async function ensureOffscreen(): Promise<void> {
  const has = await chrome.runtime.getContexts?.({ contextTypes: ["OFFSCREEN_DOCUMENT" as chrome.runtime.ContextType] }).then((c) => c.length > 0).catch(() => false);
  if (has) return;
  if (!creating) {
    creating = chrome.offscreen.createDocument({
      url: OFFSCREEN_URL,
      reasons: ["WORKERS" as chrome.offscreen.Reason],
      justification: "Strip site watermarks from PDFs before uploading them, and look up manuals in snapshot mirrors when the server is unreachable",
    }).catch((e: Error) => { if (!/already exists|single offscreen/i.test(e.message)) throw e; }).finally(() => { creating = null; });
  }
  await creating;
}

export interface StripOutcome { changed: boolean; bytes: Uint8Array; version: string; log: string[] }

/** Strip a PDF; resolves with the input unchanged when stripping fails or times out. */
export async function stripViaOffscreen(bytes: Uint8Array): Promise<StripOutcome> {
  const jobId = "strip-" + ulid();
  try {
    await putBlob(jobId, bytes);
    await ensureOffscreen();
    const reply = await Promise.race([
      chrome.runtime.sendMessage({ type: "offscreen:strip", jobId }) as Promise<{ ok: boolean; changed?: boolean; version?: string; log?: string[]; error?: string }>,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("stripper timed out")), STRIP_TIMEOUT_MS)),
    ]);
    if (!reply?.ok) throw new Error(reply?.error ?? "stripper failed");
    if (!reply.changed) return { changed: false, bytes, version: reply.version ?? "", log: reply.log ?? [] };
    const out = await getBlob(jobId + ":out");
    if (!out) throw new Error("stripper produced no output");
    return { changed: true, bytes: out, version: reply.version ?? "", log: reply.log ?? [] };
  } catch (e) {
    return { changed: false, bytes, version: "", log: [`strip skipped: ${(e as Error).message}`] };
  } finally {
    await Promise.all([deleteBlob(jobId), deleteBlob(jobId + ":out")]).catch(() => {});
  }
}
