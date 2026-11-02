// Shared content-script runtime: banner UI, list annotation and the
// RECAP-style download interception (fetch once → hand the file to the user →
// upload the same bytes via the service worker). Site adapters call init().
import { b64ToBytes, bytesToB64 } from "../core/b64.ts";
import { canUpload, getSettings } from "../core/config.ts";
import type { LookupResult, UploadJob, UploadStatus } from "../core/messages.ts";

export interface Adapter {
  site: string;
  /** Whether this page offers a link to `url` (its download or view link). */
  offersFile?(url: string): boolean;
  getMeta(): { title: string; description?: string; language?: string; sourceUrl: string; products: { brand: string; model: string }[] };
  hookDownloads?(intercept: (req: InterceptRequest) => void): void;
  collectListLinks?(): { el: HTMLAnchorElement; sourceId: string }[];
}
export interface InterceptRequest {
  url: string;
  mode: "download" | "view";
  filenameHint?: string;
  newTab?: boolean;
  /** A form post (urlencoded body) instead of a GET, e.g. a captcha-gated download form. */
  form?: string;
  /** How to replay the site's own download when we don't take over (default: open `url`). */
  fallback?: () => void;
}

const MIME: Record<string, string> = { pdf: "application/pdf", zip: "application/zip", rar: "application/vnd.rar", djvu: "image/vnd.djvu" };

export const state = { lookup: null as LookupResult | null, adapter: null as Adapter | null, banner: null as HTMLDivElement | null, busy: false, addCopy: false };

// ---- banner ----------------------------------------------------------------

const fmtBytes = (n: number) => (n >= 1e6 ? `${(n / 1e6).toFixed(1)} MB` : `${Math.round(n / 1e3)} kB`);

function ensureBanner(): HTMLDivElement {
  if (state.banner && document.contains(state.banner)) return state.banner;
  const b = document.createElement("div");
  b.className = "openmanuals-banner";
  b.setAttribute("role", "status");
  document.body.insertBefore(b, document.body.firstChild);
  state.banner = b;
  return b;
}
function link(cls: string, href: string, text: string): HTMLAnchorElement {
  const a = document.createElement("a");
  a.className = cls; a.href = href; a.target = "_blank"; a.rel = "noopener"; a.textContent = text;
  return a;
}
function span(cls: string, text: string): HTMLSpanElement { const s = document.createElement("span"); s.className = cls; s.textContent = text; return s; }
function button(cls: string, text: string, onClick: () => void): HTMLButtonElement {
  const b = document.createElement("button"); b.type = "button"; b.className = cls; b.textContent = text; b.addEventListener("click", onClick); return b;
}
const openOptions = () => { void chrome.runtime.sendMessage({ type: "openOptions" }); };

export type View = { kind: "checking" | "archived" | "missing" | "unreachable" | "fetching" | "notdoc" } | ({ kind: UploadStatus["stage"] } & Partial<UploadStatus>);

export function renderBanner(view: View): void {
  const b = ensureBanner();
  b.replaceChildren();
  b.className = "openmanuals-banner om-" + view.kind;
  const L = state.lookup;
  const v = view as Partial<UploadStatus> & { kind: string };
  switch (view.kind) {
    case "checking":
      b.append(span("om-badge om-badge-muted", "Checking OpenManuals and the Internet Archive…"));
      break;
    case "archived": {
      const n = L?.files.reduce((s, f) => s + (f.copies?.length ?? 0), 0) ?? 0;
      b.append(span("om-badge", n > 1 ? `✓ Free to download (${n} copies)` : "✓ Free to download"), span("om-title", L?.title ?? ""));
      if (L?.openmanuals_url) b.append(link("om-link", L.openmanuals_url, "OpenManuals"));
      if (L?.archive_url) b.append(link("om-link", L.archive_url, L.copy?.host ?? "archive.org"));
      if (L?.download_url) b.append(link("om-dl", L.download_url, `Download ${L.filename?.split(".").pop()?.toUpperCase() ?? "file"} ↓`));
      else if (L?.archive_url) b.append(link("om-dl", L.archive_url, "Open on archive.org →"));
      if (L?.canUpload) {
        const t = button("om-btn om-btn-ghost", state.addCopy ? "✓ Will add my copy" : "Add another copy", () => { state.addCopy = !state.addCopy; renderBanner({ kind: "archived" }); });
        t.title = "When you download from this site, also upload your copy to archive.org and record it.";
        b.append(t);
      }
      break;
    }
    case "missing":
      b.append(span("om-badge om-badge-muted", "Not yet preserved"));
      if (L?.canUpload) b.append(span("om-title", `Upload is on: when you download this manual, the extension will preserve a copy on archive.org${L.hasKey ? " and record it on OpenManuals" : ""}.`));
      else if (L?.uploadEnabled && !L.hasCredentials) b.append(span("om-title", "Upload is on but you aren't signed in to archive.org."), button("om-btn", "Sign in", openOptions));
      else b.append(span("om-title", "Turn on upload and the extension will preserve this manual when you download it."), button("om-btn", "Enable upload", openOptions));
      break;
    case "unreachable":
      b.append(span("om-badge om-badge-muted", "Couldn't reach archive.org"), span("om-title", "The availability check failed; try reloading."));
      break;
    case "fetching":
      b.append(span("om-badge", "⏳ Fetching the manual…"), span("om-title", "The file is downloaded once, saved for you, then preserved."));
      break;
    case "notdoc":
      b.append(span("om-badge om-badge-muted", "The site didn't return a file"), span("om-title", "It sent a web page instead (daily limit or captcha?). Showing it to you as normal."));
      break;
    case "receiving": case "hashing":
      b.append(span("om-badge", "⏳ Preparing…"), span("om-title", "Hashing the file."));
      break;
    case "stripping":
      b.append(span("om-badge", "✂ Removing site watermarks…"), span("om-title", "Keep this tab open."));
      break;
    case "uploading":
      b.append(span("om-badge", `⬆ Uploading to the Internet Archive${v.size ? ` (${fmtBytes(v.size)})` : ""}…`), span("om-title", "Keep this tab open until it finishes."));
      break;
    case "facts":
      b.append(span("om-badge", "✍ Recording…"), span("om-title", "Signing the facts about this file."));
      break;
    case "exists":
      b.append(span("om-badge", "✓ Already preserved"), span("om-title", "This exact file is already archived; its origin was recorded."));
      if (v.archive_url) b.append(link("om-dl", v.archive_url, "Open the archived copy →"));
      break;
    case "done":
      b.append(span("om-badge", "✓ Preserved on the Internet Archive — thank you!"));
      b.append(span("om-title", `${v.stripped ? "Watermarks removed. " : ""}${v.facts ? `${v.facts} facts ${v.pending ? "queued for" : "sent to"} OpenManuals.` : "No contributor key, so nothing was recorded on OpenManuals."}`));
      if (v.openmanuals_url) b.append(link("om-link", v.openmanuals_url, "OpenManuals"));
      if (v.archive_url) b.append(link("om-dl", v.archive_url, "Open on archive.org →"));
      break;
    case "error":
      b.append(span("om-badge om-badge-muted", "Upload failed"), span("om-title", v.message ?? "Unknown error"));
      break;
  }
}

// ---- download interception ------------------------------------------------------

function filenameFromDisposition(cd: string | null): string | null {
  if (!cd) return null;
  let m = /filename\*\s*=\s*(?:UTF-8|utf-8)''([^;]+)/.exec(cd);
  if (m) { try { return decodeURIComponent(m[1].trim()); } catch { /* fall through */ } }
  m = /filename\s*=\s*"?([^";]+)"?/.exec(cd);
  return m ? m[1].trim() : null;
}

async function fetchBytes(url: string, form?: string): Promise<{ bytes: Uint8Array; filename: string | null }> {
  try {
    const post = form !== undefined ? { method: "POST", body: form, headers: { "Content-Type": "application/x-www-form-urlencoded" } } : {};
    const res = await fetch(url, { credentials: "include", ...post });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return { bytes: new Uint8Array(await res.arrayBuffer()), filename: filenameFromDisposition(res.headers.get("content-disposition")) };
  } catch (e) {
    if (!(e instanceof TypeError)) throw e; // real HTTP error, not a CORS block
    return fetchViaBackground(url, form);
  }
}

function fetchViaBackground(url: string, form?: string): Promise<{ bytes: Uint8Array; filename: string | null }> {
  return new Promise((resolve, reject) => {
    const port = chrome.runtime.connect({ name: "fetch" });
    const chunks: Uint8Array[] = [];
    let meta: { ok: boolean; status: number; contentDisposition: string } | null = null;
    port.onMessage.addListener((msg) => {
      if (msg.type === "meta") meta = msg;
      else if (msg.type === "chunk") chunks.push(b64ToBytes(msg.data));
      else if (msg.type === "end") {
        port.disconnect();
        if (!meta?.ok) return reject(new Error(`HTTP ${meta?.status}`));
        const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
        let off = 0; for (const c of chunks) { out.set(c, off); off += c.length; }
        resolve({ bytes: out, filename: filenameFromDisposition(meta.contentDisposition) });
      } else if (msg.type === "error") { port.disconnect(); reject(new Error(msg.message)); }
    });
    port.onDisconnect.addListener(() => reject(new Error("background fetch disconnected")));
    port.postMessage({ type: "fetch", url, referer: location.href, ...(form !== undefined ? { form } : {}) });
  });
}

function sniff(bytes: Uint8Array): string | null {
  const head = String.fromCharCode(...bytes.subarray(0, 8));
  if (head.startsWith("%PDF-")) return "pdf";
  if (head.startsWith("PK\x03\x04")) return "zip";
  if (head.startsWith("Rar!")) return "rar";
  if (head.startsWith("AT&T")) return "djvu";
  return null;
}

function deliver(bytes: Uint8Array, kind: string, filename: string, mode: "download" | "view"): void {
  const url = URL.createObjectURL(new Blob([bytes as BlobPart], { type: MIME[kind] }));
  if (mode === "view" && kind === "pdf") window.open(url, "_blank");
  else {
    const a = document.createElement("a");
    a.href = url; a.download = filename; a.style.display = "none";
    document.body.append(a); a.click(); a.remove();
  }
  setTimeout(() => URL.revokeObjectURL(url), 120000);
}

function uploadBytes(bytes: Uint8Array, kind: string, filename: string): Promise<UploadStatus | null> {
  return new Promise((resolve) => {
    const port = chrome.runtime.connect({ name: "upload" });
    const ping = setInterval(() => { try { port.postMessage({ type: "ping" }); } catch { clearInterval(ping); } }, 20000);
    const finish = (v: UploadStatus | null) => { clearInterval(ping); try { port.disconnect(); } catch { /* closed */ } resolve(v); };
    port.onMessage.addListener((msg: UploadStatus) => {
      if (msg.type !== "status") return;
      if (msg.stage === "exists" || msg.stage === "done" || msg.stage === "error") {
        if (msg.stage !== "error" && state.lookup) Object.assign(state.lookup, { archived: true, archive_url: msg.archive_url ?? state.lookup.archive_url, download_url: msg.download_url ?? state.lookup.download_url });
        renderBanner({ ...msg, kind: msg.stage });
        finish(msg);
      } else renderBanner({ ...msg, kind: msg.stage === "checking" ? "uploading" : msg.stage, size: msg.size ?? bytes.byteLength });
    });
    port.onDisconnect.addListener(() => { renderBanner({ kind: "error", message: "Lost contact with the extension during upload." }); finish(null); });
    const meta = state.adapter!.getMeta();
    const page = state.lookup!.page;
    const job: UploadJob = {
      type: "begin", filename, contentType: MIME[kind], size: bytes.byteLength,
      metadata: { title: meta.title, description: meta.description, language: meta.language, products: meta.products },
      sourceInfo: { source: page.source, sourceId: page.source_id, sourceUrl: meta.sourceUrl || location.href.split("#")[0] },
      addCopy: state.addCopy,
    };
    port.postMessage(job);
    for (let i = 0; i < bytes.length; i += 1 << 20) port.postMessage({ type: "chunk", data: bytesToB64(bytes.subarray(i, i + (1 << 20))) });
    port.postMessage({ type: "end" });
  });
}

function fallback(req: InterceptRequest): void {
  if (req.fallback) req.fallback();
  else if (req.mode === "view" || req.newTab) window.open(req.url, "_blank");
  else location.assign(req.url);
}

/** The adapter has preventDefault()ed the click; take over or replay the default. */
export async function interceptDownload(req: InterceptRequest): Promise<void> {
  const settings = await getSettings();
  const L = state.lookup;
  if (!canUpload(settings) || !L || L.error || (L.archived && !state.addCopy) || state.busy) return fallback(req);
  state.busy = true;
  try {
    renderBanner({ kind: "fetching" });
    let got: { bytes: Uint8Array; filename: string | null };
    try { got = await fetchBytes(req.url, req.form); }
    catch (e) { renderBanner({ kind: "error", message: `Couldn't fetch the file (${(e as Error).message}); falling back to the normal download.` }); return fallback(req); }
    const kind = sniff(got.bytes);
    if (!kind) { renderBanner({ kind: "notdoc" }); return fallback(req); }
    const filename = got.filename ?? req.filenameHint ?? `${L.page.slug || L.page.source_id}.${kind}`;
    deliver(got.bytes, kind, filename, req.mode);
    await uploadBytes(got.bytes, kind, filename);
  } finally {
    state.busy = false;
  }
}

/**
 * A file Chrome is already downloading from this page without our click
 * handler (Save link as…, middle-click): fetch it again and preserve it. The
 * user's own copy is left alone, so nothing is delivered here.
 */
export async function captureDownloaded(url: string): Promise<void> {
  if (!state.adapter?.offersFile?.(url)) return;
  const settings = await getSettings();
  const L = state.lookup;
  if (!canUpload(settings) || !L || L.error || (L.archived && !state.addCopy) || state.busy) return;
  state.busy = true;
  try {
    renderBanner({ kind: "fetching" });
    let got: { bytes: Uint8Array; filename: string | null };
    try { got = await fetchBytes(url); }
    catch (e) { renderBanner({ kind: "error", message: `Couldn't fetch the file to preserve it (${(e as Error).message}). Your download is unaffected.` }); return; }
    const kind = sniff(got.bytes);
    if (!kind) { renderBanner({ kind: "notdoc" }); return; }
    const base = url.split(/[?#]/)[0].split("/").pop() ?? "";
    const filename = got.filename ?? (/\.pdf$/i.test(base) ? decodeURIComponent(base) : `${L.page.slug || L.page.source_id}.${kind}`);
    await uploadBytes(got.bytes, kind, filename);
  } finally {
    state.busy = false;
  }
}

// ---- list annotation ----------------------------------------------------------------

const listKnown = new Map<string, { identifier: string; archive_url: string } | null>();

export async function annotateLists(adapter: Adapter): Promise<void> {
  const links = adapter.collectListLinks?.() ?? [];
  const firstFor = new Map<string, HTMLAnchorElement>();
  for (const { el, sourceId } of links) if (sourceId && !firstFor.has(sourceId)) firstFor.set(sourceId, el);
  const unknown = Array.from(firstFor.keys()).filter((sid) => !listKnown.has(sid));
  for (let i = 0; i < unknown.length; i += 60) {
    const batch = unknown.slice(i, i + 60);
    const res = await chrome.runtime.sendMessage({ type: "lookupMany", source: adapter.site, sourceIds: batch });
    for (const sid of batch) listKnown.set(sid, res?.found?.[sid] ?? null);
  }
  for (const [sid, el] of firstFor) {
    const hit = listKnown.get(sid);
    if (!hit || !document.contains(el) || el.parentElement?.querySelector(`a.om-mark[data-om-id="${CSS.escape(sid)}"]`)) continue;
    const mark = link("om-mark", hit.archive_url, "✓ archive.org");
    mark.title = "Free on the Internet Archive";
    mark.dataset.omId = sid;
    el.after(mark);
  }
}

function watchLists(adapter: Adapter): void {
  let timer: ReturnType<typeof setTimeout> | null = null;
  const run = () => annotateLists(adapter).catch(() => {});
  run();
  new MutationObserver((muts) => {
    if (!muts.some((m) => Array.from(m.addedNodes).some((n) => n.nodeType === 1 && !(n as Element).classList.contains("om-mark") && !(n as Element).classList.contains("openmanuals-banner")))) return;
    if (timer) clearTimeout(timer);
    timer = setTimeout(run, 800);
  }).observe(document.body, { childList: true, subtree: true });
}

// ---- init -----------------------------------------------------------------------------

chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type === "capturedDownload" && typeof msg.url === "string") { void captureDownloaded(msg.url); return; }
  if (msg?.type !== "lookupDetails" || !state.lookup || state.busy) return;
  state.lookup = { ...state.lookup, ...msg.lookup };
  if (state.banner && /om-(archived|missing|checking)/.test(state.banner.className)) renderBanner({ kind: state.lookup!.archived ? "archived" : "missing" });
});

export async function init(adapter: Adapter): Promise<void> {
  state.adapter = adapter;
  const settings = await getSettings();
  const lookup = (await chrome.runtime.sendMessage({ type: "lookup", url: location.href }).catch(() => null)) as LookupResult | null;
  if (lookup && !("error" in lookup && typeof lookup.error === "string" && !lookup.page)) state.lookup = lookup;
  if (state.lookup) {
    if (settings.showBanner) {
      if (state.lookup.error) renderBanner({ kind: "unreachable" });
      else renderBanner({ kind: state.lookup.archived ? "archived" : "missing" });
    }
    if (!state.lookup.error && adapter.hookDownloads) adapter.hookDownloads(interceptDownload);
  }
  if (settings.annotateLists && adapter.collectListLinks) watchLists(adapter);
}
