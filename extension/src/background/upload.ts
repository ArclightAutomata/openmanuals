// The upload pipeline: bytes from the content script → hash → strip → hash →
// upload to archive.org → sign and queue the fact bundle.
// Tool name recorded on derivation facts; matches STRIP_TOOL in src/strip/index.ts
// (not imported so the service worker doesn't bundle the stripper).
const STRIP_TOOL = "om-strip";
import { canUpload, getSettings } from "../core/config.ts";
import { bodies, guessDocType, nowIso, type UnsignedFact } from "../core/facts.ts";
import { hashAll, type Hashes } from "../core/hash.ts";
import type { LookupResult, UploadJob, UploadStatus } from "../core/messages.ts";
import { ulid } from "../core/ulid.ts";
import { ensureWasm } from "../core/wasm.ts";
import * as ia from "./ia.ts";
import { lookupByFile, manualUrl } from "./api.ts";
import { getKey, submit } from "./identity.ts";
import { stripViaOffscreen } from "./offscreen.ts";
import { omCacheDrop, tabInfo } from "./lookup.ts";
import { paint as paintIcon, stateFor } from "./icon.ts";

// Only documents are accepted (openmanuals-core sniff): PDF and DjVu.
const MIME: Record<string, string> = { pdf: "application/pdf", djvu: "image/vnd.djvu" };

export function safeFilename(name: string | undefined, kind: string): string {
  let n = String(name ?? "manual").split(/[\\/]/).pop()!.replace(/[\x00-\x1f"*:<>?|]/g, "_").trim();
  if (!n || n === "." || n === "..") n = "manual";
  if (!new RegExp(`\\.${kind}$`, "i").test(n)) n += `.${kind}`;
  return n;
}

type Status = (stage: UploadStatus["stage"], extra?: Partial<UploadStatus>) => void;

/** Build the fact bundle for one upload (pure; exported for tests). */
export function buildBundle(p: {
  job: UploadJob; original: Hashes & { mime: string }; uploaded: Hashes & { mime: string }; stripped: { changed: boolean; version: string };
  identifier: string | null; filename: string; manualId: string | null; productKey: (brand: string, model: string) => string | undefined; at?: string;
}): UnsignedFact[] {
  const at = p.at ?? nowIso();
  const facts: UnsignedFact[] = [];
  const f = (type: string, body: Record<string, unknown>) => facts.push({ type, at, body });
  f("file", bodies.file(p.original, p.original.mime));
  f("location", bodies.location(p.original.sha256, p.job.sourceInfo.sourceUrl, "origin"));
  if (p.stripped.changed) {
    f("file", bodies.file(p.uploaded, p.uploaded.mime));
    f("derivation", bodies.derivation(p.uploaded.sha256, p.original.sha256, "watermark-stripped", STRIP_TOOL, p.stripped.version));
  }
  if (p.identifier) {
    f("location", bodies.location(p.uploaded.sha256, ia.downloadUrl(p.identifier, p.filename), "archive", { identifier: p.identifier, filename: p.filename }));
  }
  const manual = p.manualId ?? ulid();
  if (!p.manualId) {
    const title = p.job.metadata.title || p.filename;
    f("manual", bodies.manual(manual, title, guessDocType(title), p.job.metadata.language));
    const seen = new Set<string>();
    for (const pr of p.job.metadata.products ?? []) {
      const key = p.productKey(pr.brand, pr.model);
      if (!key || seen.has(key)) continue;
      seen.add(key);
      f("product", bodies.product(pr.brand.trim(), pr.model.trim()));
      f("covers", bodies.covers(manual, key));
    }
  }
  f("manual_file", bodies.manualFile(manual, p.original.sha256));
  if (p.stripped.changed) f("manual_file", bodies.manualFile(manual, p.uploaded.sha256));
  return facts;
}

export async function runUpload(status: Status, job: UploadJob, bytes: Uint8Array, tabId?: number): Promise<void> {
  const om = await ensureWasm();
  const settings = await getSettings();
  if (!canUpload(settings)) return status("error", { message: "Upload is not enabled (or archive.org keys are missing)." });
  const key = await getKey();
  const kind = om.sniff(bytes);
  if (!kind) return status("error", { message: "That wasn't a document (the site returned a web page)." });
  const paint = (s: "uploading" | "archived" | "restore") => paintIcon(tabId, s === "restore" ? stateFor(tabInfo.get(tabId ?? -1)) : s);

  status("hashing");
  const original = { ...(await hashAll(bytes)), mime: MIME[kind] };

  let stripped = { changed: false, bytes, version: "", log: [] as string[] };
  if (kind === "pdf") {
    status("stripping");
    stripped = await stripViaOffscreen(bytes);
  }
  const outBytes = stripped.changed ? stripped.bytes : bytes;
  const uploaded = stripped.changed ? { ...(await hashAll(outBytes)), mime: MIME[kind] } : original;

  // Already archived (by anyone) and the user didn't ask for another copy?
  status("checking");
  const known = settings.apiBase ? await lookupByFile(settings, uploaded.sha256) : null;
  const liveCopies = known?.files?.find((f) => f.sha256 === uploaded.sha256)?.copies ?? [];
  const manualId = known?.manual?.id ?? tabInfo.get(tabId ?? -1)?.manual?.id ?? null;
  let identifier: string | null = null;
  const filename = safeFilename(job.filename, kind);

  if (liveCopies.length && !job.addCopy) {
    // Record what we learned (origin location, the file) without uploading.
    if (key) {
      const facts = buildBundle({ job, original, uploaded, stripped, identifier: null, filename, manualId, productKey: (b, m) => om.product_key(b, m) });
      await submit(facts, `facts: ${job.metadata.title || filename}`);
    }
    const c = liveCopies[0];
    return status("exists", { archive_url: c.ia ? ia.detailsUrl(c.ia.identifier) : c.url, download_url: c.url, sha256: uploaded.sha256, stripped: stripped.changed });
  }

  identifier = om.upload_identifier(uploaded.sha256, ulid());
  const metadata: Record<string, unknown> = {
    mediatype: "texts",
    title: job.metadata.title || identifier,
    subject: [job.sourceInfo.source, "manuals"].filter(Boolean),
    scanner: `OpenManuals browser extension ${chrome.runtime.getManifest().version}`,
    source: job.sourceInfo.sourceUrl,
    description: job.metadata.description,
    language: job.metadata.language,
    "external-identifier": [`urn:sha256:${uploaded.sha256}`, `urn:sha1:${uploaded.sha1}`, `urn:md5:${uploaded.md5}`],
    "openmanuals-key": key?.fingerprint,
    "openmanuals-original-sha256": stripped.changed ? original.sha256 : undefined,
  };

  status("uploading", { size: outBytes.byteLength, stripped: stripped.changed });
  void paint("uploading");
  const r = await ia.uploadFile({ identifier, filename, bytes: outBytes, contentType: MIME[kind], metadata, credentials: { accessKey: settings.iaAccessKey, secretKey: settings.iaSecretKey } });
  if (!r.ok) {
    void paint("restore");
    return status("error", { message: `archive.org refused the upload (${r.status} ${r.code}): ${r.message}`.trim() });
  }
  const archive_url = ia.detailsUrl(identifier);
  const download_url = ia.downloadUrl(identifier, filename);

  status("facts");
  let factCount = 0, pending = false;
  if (key) {
    const facts = buildBundle({ job, original, uploaded, stripped, identifier, filename, manualId, productKey: (b, m) => om.product_key(b, m) });
    await submit(facts, `upload: ${job.metadata.title || filename}`);
    factCount = facts.length;
    pending = true;
  }
  await omCacheDrop(job.sourceInfo.sourceUrl);
  const cur = tabId !== undefined ? tabInfo.get(tabId) : undefined;
  if (cur) Object.assign(cur, { archived: true, via: "openmanuals", archive_url, download_url, filename, size: outBytes.byteLength });
  void paint("archived");
  status("done", {
    archive_url, download_url, sha256: uploaded.sha256, stripped: stripped.changed, facts: factCount, pending,
    openmanuals_url: manualId ? manualUrl(settings, manualId) : null,
  });
}
