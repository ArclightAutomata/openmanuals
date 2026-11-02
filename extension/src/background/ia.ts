// archive.org client: fast existence probe, item metadata, batch search, S3
// upload, key check, and the two sign-in paths. Runs in the service worker,
// which holds host permissions for archive.org (no page CORS).

const METADATA = "https://archive.org/metadata/";
const SEARCH = "https://archive.org/advancedsearch.php";
const S3 = "https://s3.us.archive.org/";
const CHECK = "https://archive.org/services/check_identifier.php?output=json&identifier=";
const S3_KEYS_PAGE = "https://archive.org/account/s3.php?output_json=1";
const XAUTHN_LOGIN = "https://archive.org/services/xauthn/?op=login";
const DOC_FILE = /\.(pdf|zip|rar|djvu|7z)$/i;

export const detailsUrl = (id: string) => `https://archive.org/details/${id}`;
export const downloadUrl = (id: string, name: string) => `https://archive.org/download/${id}/${encodeURIComponent(name).replace(/%2F/gi, "/")}`;

export interface IaFile { name: string; source?: string; size?: string; sha1?: string; md5?: string }
export interface ItemInfo {
  exists: boolean; identifier: string; title?: string | null; uploader?: string | null; source?: string | null;
  archive_url?: string | null; download_url?: string | null; filename?: string | null; size?: number | null; detailed?: boolean;
}

/** The user-facing document in an item: an original pdf/zip/rar/djvu, pdf first, then largest. */
export function pickPrimaryFile(files: IaFile[] | undefined): IaFile | null {
  const isPdf = (f: IaFile) => (/\.pdf$/i.test(f.name) ? 1 : 0);
  return (files ?? [])
    .filter((f) => f.source === "original" && DOC_FILE.test(f.name) && !/^__ia_thumb/.test(f.name))
    .sort((a, b) => isPdf(b) - isPdf(a) || Number(b.size ?? 0) - Number(a.size ?? 0))[0] ?? null;
}

/** Fast existence probe. "not_available" means an item holds the identifier. */
export async function checkExists(identifier: string): Promise<boolean> {
  const res = await fetch(CHECK + encodeURIComponent(identifier), { cache: "no-store" });
  if (!res.ok) throw new Error(`archive.org check_identifier ${res.status}`);
  const data = await res.json();
  if (data?.type !== "success") throw new Error(`archive.org check_identifier: ${data?.message ?? "bad response"}`);
  return data.code === "not_available";
}

export async function fetchItem(identifier: string): Promise<ItemInfo> {
  const res = await fetch(METADATA + encodeURIComponent(identifier), { cache: "no-store" });
  if (!res.ok) throw new Error(`archive.org metadata ${res.status}`);
  const data = await res.json();
  if (!data || !Object.keys(data).length || data.is_dark) return { exists: false, identifier };
  const meta = data.metadata ?? {};
  const file = pickPrimaryFile(data.files);
  return {
    exists: true, identifier, title: meta.title ?? null, uploader: meta.uploader ?? null, source: meta.source ?? null,
    archive_url: detailsUrl(identifier), download_url: file ? downloadUrl(identifier, file.name) : null,
    filename: file?.name ?? null, size: file ? Number(file.size) || null : null,
  };
}

/** Which of these identifiers exist, via the search index (lags item creation; list marks only). */
export async function searchIdentifiers(identifiers: string[]): Promise<Set<string>> {
  const found = new Set<string>();
  const ids = Array.from(new Set(identifiers));
  for (let i = 0; i < ids.length; i += 30) {
    const chunk = ids.slice(i, i + 30);
    const q = "identifier:(" + chunk.map((id) => `"${id}"`).join(" OR ") + ")";
    const res = await fetch(`${SEARCH}?q=${encodeURIComponent(q)}&fl[]=identifier&rows=${chunk.length}&output=json`);
    if (!res.ok) throw new Error(`archive.org search ${res.status}`);
    const data = await res.json();
    for (const doc of data?.response?.docs ?? []) found.add(doc.identifier);
  }
  return found;
}

// ---- upload ------------------------------------------------------------------

export function metaValue(v: unknown): string {
  const s = String(v).replace(/[\r\n]+/g, " ").trim();
  return /^[\x20-\x7e]*$/.test(s) ? s : `uri(${encodeURIComponent(s)})`;
}

export function metaHeaders(metadata: Record<string, unknown>): Record<string, string> {
  const h: Record<string, string> = {};
  for (const [key, value] of Object.entries(metadata)) {
    if (value == null || value === "") continue;
    if (Array.isArray(value)) value.forEach((v, i) => { h[`x-archive-meta${String(i + 1).padStart(2, "0")}-${key}`] = metaValue(v); });
    else h[`x-archive-meta-${key}`] = metaValue(value);
  }
  return h;
}

const xmlTag = (text: string, tag: string) => (new RegExp(`<${tag}>([^<]*)</${tag}>`).exec(text ?? "") ?? [])[1] ?? "";

export interface Credentials { accessKey: string; secretKey: string }
export type UploadOutcome = { ok: true; status: number } | { ok: false; status: number; code: string; message: string };

/** PUT one file into (auto-created) item `identifier`. Never throws on an HTTP error. */
export async function uploadFile(p: { identifier: string; filename: string; bytes: Uint8Array; contentType: string; metadata: Record<string, unknown>; credentials: Credentials }): Promise<UploadOutcome> {
  const headers: Record<string, string> = {
    Authorization: `LOW ${p.credentials.accessKey}:${p.credentials.secretKey}`,
    "x-amz-auto-make-bucket": "1",
    "x-archive-queue-derive": "1",
    "x-archive-size-hint": String(p.bytes.byteLength),
    "Content-Type": p.contentType || "application/octet-stream",
    ...metaHeaders(p.metadata),
  };
  const res = await fetch(S3 + p.identifier + "/" + encodeURIComponent(p.filename), { method: "PUT", headers, body: p.bytes as BodyInit });
  const text = await res.text().catch(() => "");
  if (res.ok) return { ok: true, status: res.status };
  return { ok: false, status: res.status, code: xmlTag(text, "Code"), message: xmlTag(text, "Message") || text.slice(0, 200) };
}

/** An empty PUT to a nonexistent bucket without auto-make: 404 = keys good, 403 = keys bad; creates nothing. */
export async function checkCredentials(c: Credentials): Promise<{ ok: boolean; message?: string }> {
  const probe = "openmanuals-keycheck-" + Math.random().toString(36).slice(2, 10);
  const res = await fetch(S3 + probe + "/probe", { method: "PUT", headers: { Authorization: `LOW ${c.accessKey}:${c.secretKey}`, "Content-Length": "0" }, body: new Uint8Array(0) as BodyInit });
  const text = await res.text().catch(() => "");
  const code = xmlTag(text, "Code");
  if (res.status === 404) return { ok: true };
  if (res.status === 403) return { ok: false, message: code === "SignatureDoesNotMatch" ? "Secret key doesn't match the access key." : "Access key not recognized by archive.org." };
  return { ok: false, message: `Unexpected archive.org response ${res.status} ${code}`.trim() };
}

// ---- sign-in -------------------------------------------------------------------

/** Pull S3 keys out of whatever shape the keys page or xauthn returns. */
export function extractKeys(data: unknown, text = ""): Credentials | null {
  const find = (o: unknown, names: string[]): string | undefined => {
    if (!o || typeof o !== "object") return undefined;
    for (const [k, v] of Object.entries(o as Record<string, unknown>)) {
      if (names.includes(k.toLowerCase()) && typeof v === "string" && v) return v;
      const deep = find(v, names);
      if (deep) return deep;
    }
    return undefined;
  };
  let accessKey = find(data, ["s3accesskey", "access", "accesskey", "access_key"]);
  let secretKey = find(data, ["s3secretkey", "secret", "secretkey", "secret_key"]);
  if (!accessKey || !secretKey) {
    // Fall back to scraping the HTML keys page.
    const a = /access\s*key[^A-Za-z0-9]{0,40}([A-Za-z0-9]{16})\b/i.exec(text);
    const s = /secret\s*key[^A-Za-z0-9]{0,40}([A-Za-z0-9]{16})\b/i.exec(text);
    if (a && s) { accessKey = a[1]; secretKey = s[1]; }
  }
  if (!accessKey || !secretKey) return null;
  return { accessKey, secretKey };
}

/** The archive.org account a key pair belongs to. */
export interface IaAccount {
  /** The account's item name, `@handle`: what its profile URL shows. */
  itemname?: string;
  screenname?: string;
  email?: string;
}

const CHECK_AUTH = "https://s3.us.archive.org/?check_auth=1";

/** Read an account out of a check_auth / xauthn answer (field names vary). */
export function accountFrom(data: unknown): IaAccount | null {
  const find = (o: unknown, names: string[]): string | undefined => {
    if (!o || typeof o !== "object") return undefined;
    for (const [k, v] of Object.entries(o as Record<string, unknown>)) {
      if (names.includes(k.toLowerCase()) && typeof v === "string" && v) return v;
      const deep = find(v, names);
      if (deep) return deep;
    }
    return undefined;
  };
  const item = find(data, ["itemname"]);
  const screenname = find(data, ["screenname"]);
  const email = find(data, ["email", "username"]);
  const a: IaAccount = {
    ...(item ? { itemname: item.startsWith("@") ? item : `@${item}` } : {}),
    ...(screenname ? { screenname } : {}),
    ...(email && email.includes("@") && !email.startsWith("@") ? { email } : {}),
  };
  return a.itemname || a.screenname || a.email ? a : null;
}

/**
 * Which account these keys belong to (the `ia` tool's get_user_info): signed
 * with the keys, no cookies. Null when archive.org doesn't say.
 */
export async function accountOf(c: Credentials): Promise<IaAccount | null> {
  return (await checkKeys(c)).account;
}

/**
 * Whether archive.org accepts these keys (`valid`: null when it couldn't be
 * asked) and which account they belong to.
 */
export async function checkKeys(c: Credentials): Promise<{ valid: boolean | null; account: IaAccount | null }> {
  const res = await fetch(CHECK_AUTH, { headers: { Authorization: `LOW ${c.accessKey}:${c.secretKey}` }, credentials: "omit", cache: "no-store" }).catch(() => null);
  if (!res) return { valid: null, account: null };
  const data = await res.json().catch(() => null) as { error?: string; authorized?: boolean } | null;
  if (res.status === 401 || res.status === 403 || data?.error || data?.authorized === false) return { valid: false, account: null };
  if (!res.ok || !data) return { valid: null, account: null };
  return { valid: true, account: accountFrom(data) };
}

/** How to show an account: "@handle (Screen Name)", else whatever is known. */
export function accountLabel(a: IaAccount | null | undefined): string {
  if (!a) return "";
  if (a.itemname) return a.screenname && a.screenname !== a.itemname.slice(1) ? `${a.itemname} (${a.screenname})` : a.itemname;
  return a.screenname ?? a.email ?? "";
}

/**
 * The account this browser is signed in to on archive.org, from its
 * `logged-in-user` cookie (the email). Reads no keys. Null when signed out
 * or when the cookies API isn't available.
 */
export async function sessionEmail(): Promise<string | null> {
  const c = await chrome.cookies?.get({ url: "https://archive.org/", name: "logged-in-user" }).catch(() => null);
  if (!c?.value) return null;
  try { return decodeURIComponent(c.value); } catch { return c.value; }
}

/** Keys from the logged-in browser session (cookies included). Null when not logged in. */
export async function fetchKeysFromSession(): Promise<Credentials | null> {
  const res = await fetch(S3_KEYS_PAGE, { credentials: "include", cache: "no-store", redirect: "follow" });
  if (!res.ok) return null;
  if (/\/account\/login/.test(res.url)) return null;
  const text = await res.text();
  let data: unknown = null;
  try { data = JSON.parse(text); } catch { /* HTML page */ }
  return extractKeys(data, text);
}

/** The `ia configure` path: email + password → S3 keys. The password goes only to archive.org. */
export async function passwordLogin(email: string, password: string): Promise<Credentials | null> {
  const body = new URLSearchParams({ email, password });
  const res = await fetch(XAUTHN_LOGIN, { method: "POST", body, headers: { "Content-Type": "application/x-www-form-urlencoded" } });
  const text = await res.text();
  let data: unknown = null;
  try { data = JSON.parse(text); } catch { return null; }
  const d = data as { success?: boolean; values?: { reason?: string } };
  if (!d?.success) throw new Error(d?.values?.reason ?? "archive.org rejected the login");
  return extractKeys(data);
}
