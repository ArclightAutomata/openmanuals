// The side panel for the configured server's pages. It is an extension page,
// so the website can't script or click it: everything it shows is fetched and
// checked here (the fact must verify and hash to its id; a copy's location
// fact must name the page's file), and actions are signed only from here.
// Single actions wait UNDO_MS for "Undo"; bulk actions take one confirmation.
import { getSettings } from "../core/config.ts";
import type { Identity } from "../core/messages.ts";
import { can, describeRow, groups, keyOf, kindOf, opFor, pageItems, planBulk, selectWhere, UNDO_MS, type BulkOp, type Op, type Row } from "../core/panel.ts";
import type { ReportValue } from "../core/site.ts";
import { checkServedFact } from "../core/site-check.ts";

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const send = <T,>(msg: unknown) => chrome.runtime.sendMessage(msg).catch((e) => ({ error: String(e) })) as Promise<T>;
const say = (text: string, ok?: boolean) => { const e = $("msg"); e.textContent = text; e.className = ok === undefined ? "" : ok ? "ok" : "bad"; };

const params = new URLSearchParams(location.search);
let tabId = Number(params.get("tab"));
const pageKey = () => `sitePage:${tabId}`;
const focusKey = () => `panelFocus:${tabId}`;

let base = "";
let me: string | null = null;
let hasKey = false;
let order: string[] = [];
const rows = new Map<string, Row>();
const selected = new Set<string>();
const pending = new Map<string, { op: BulkOp; kind: Op; until: number; timer: ReturnType<typeof setTimeout> }>();
let plan: { op: Op; ops: BulkOp[]; rows: Row[] } | null = null;

const reason = () => $<HTMLSelectElement>("reason").value as ReportValue;
const visible = (): Row[] => order.map((k) => rows.get(k)!).filter(Boolean);

// ---- fetching and checking ------------------------------------------------------------

async function check(r: Row): Promise<void> {
  if (r.action.action === "file") { r.status = "ok"; return; }
  const id = r.key;
  try {
    const res = await fetch(`${base}/api/fact/${encodeURIComponent(id)}`, { cache: "no-store" });
    if (res.status === 404) throw new Error("not on the server");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const s = await checkServedFact(await res.json(), id);
    if (s.hidden || !s.fact) { r.status = "hidden"; return; }
    if (r.action.action === "copy" && (s.fact.type !== "location" || s.fact.body.file !== r.action.file)) throw new Error("the page's file doesn't match the copy's fact");
    r.fact = s.fact;
    r.retracted = s.retracted;
    r.status = "ok";
  } catch (e) {
    r.status = "error";
    r.error = (e as Error).message;
  }
}

/** Check rows a few at a time, re-rendering as they come in. */
async function checkAll(list: Row[]): Promise<void> {
  const queue = list.slice();
  const worker = async () => { for (let r = queue.shift(); r; r = queue.shift()) { await check(r); render(); } };
  await Promise.all(Array.from({ length: 6 }, worker));
}

async function loadPage(): Promise<void> {
  const got = await chrome.storage.session.get(pageKey());
  const page = got[pageKey()] as { items?: unknown; url?: string } | undefined;
  if (!page) { order = []; render("Waiting for an OpenManuals server page in this tab…"); return; }
  const items = pageItems(page.items);
  order = [];
  const fresh: Row[] = [], known: Row[] = [];
  for (const a of items) {
    const key = keyOf(a);
    order.push(key);
    const have = rows.get(key);
    if (have) known.push(have);
    else { const r: Row = { key, action: a, status: "loading" }; rows.set(key, r); fresh.push(r); }
  }
  for (const k of [...selected]) if (!order.includes(k)) selected.delete(k);
  render(items.length ? undefined : "Nothing on this page to act on.");
  // New rows first; rows already shown are re-checked quietly (they may have been retracted since).
  await checkAll(fresh);
  await checkAll(known.filter((r) => r.done === undefined && !pending.has(r.key)));
}

// ---- actions ------------------------------------------------------------------------------

async function execute(ops: BulkOp[], targets: Row[], kinds: Op[]): Promise<void> {
  say(`Signing and sending ${ops.length}…`);
  const r = await send<{ ok?: boolean; error?: string; results?: { status: string; error?: string }[]; muted?: string[] }>({ type: "siteBulk", ops });
  if (!r?.ok || !r.results) { say(r?.error ?? "Failed.", false); return; }
  let sent = 0, queued = 0, rejected = 0;
  let lastError = "";
  r.results.forEach((res, i) => {
    const row = targets[i];
    if (res.status === "rejected") { rejected++; row.error = res.error; lastError = res.error ?? ""; return; }
    res.status === "sent" ? sent++ : queued++;
    if (res.error) lastError = res.error;
    row.done = kinds[i] === "retract" ? "retracted" : "reported";
    if (kinds[i] === "retract") row.retracted = true;
    selected.delete(row.key);
  });
  const parts = [`${sent} sent`];
  if (queued) parts.push(`${queued} queued (sent when the server is reachable${lastError ? `: ${lastError}` : ""})`);
  if (rejected) parts.push(`${rejected} rejected${lastError ? `: ${lastError}` : ""}`);
  if (r.muted?.length) parts.push(`muted ${r.muted.length} author${r.muted.length > 1 ? "s" : ""}`);
  say(parts.join(" · ") + ".", rejected === 0);
  render();
}

/** One row, one click: wait UNDO_MS for "Undo", then sign and send. */
function startSingle(row: Row, kind: Op): void {
  const op = opFor(row, kind, me, reason());
  if (!op || pending.has(row.key)) return;
  const timer = setTimeout(() => {
    pending.delete(row.key);
    void execute([op], [row], [kind]);
  }, UNDO_MS);
  pending.set(row.key, { op, kind, until: Date.now() + UNDO_MS, timer });
  render();
}

function undo(key: string): void {
  const p = pending.get(key);
  if (!p) return;
  clearTimeout(p.timer);
  pending.delete(key);
  say("Undone; nothing was sent.");
  render();
}

// ---- rendering ----------------------------------------------------------------------------

function tag(text: string, cls = ""): HTMLElement { const s = document.createElement("span"); s.className = "tag " + cls; s.textContent = text; return s; }
function button(text: string, cls: string, onClick: () => void): HTMLButtonElement {
  const b = document.createElement("button"); b.type = "button"; b.className = cls; b.textContent = text;
  b.addEventListener("click", onClick); return b;
}

let hoverTimer: ReturnType<typeof setTimeout> | undefined;
const hover = (key: string | null) => { clearTimeout(hoverTimer); hoverTimer = setTimeout(() => void chrome.runtime.sendMessage({ type: "siteHighlight", tabId, key }).catch(() => {}), 80); };

function renderRow(r: Row): HTMLLIElement {
  const li = document.createElement("li");
  li.className = `row state-${r.status}`;
  li.dataset.key = r.key;
  const box = document.createElement("input"); box.type = "checkbox";
  box.checked = selected.has(r.key);
  box.disabled = r.status !== "ok" || r.done !== undefined;
  box.addEventListener("change", () => { box.checked ? selected.add(r.key) : selected.delete(r.key); plan = null; renderBulk(); });
  const main = document.createElement("div");
  const title = document.createElement("div"); title.className = "title"; title.textContent = r.status === "loading" ? "Checking…" : describeRow(r);
  const meta = document.createElement("div"); meta.className = "meta";
  if (r.fact) {
    meta.append(r.fact.author === me ? tag("you", "you") : document.createTextNode(`by ${r.fact.author.slice(0, 10)}…`), ` · ${r.fact.at.slice(0, 10)}`);
    if (r.action.action === "copy") meta.append(tag("copy"));
  } else if (r.action.action === "file") meta.textContent = r.action.file;
  if (r.retracted) meta.append(tag("retracted"));
  if (r.status === "hidden") meta.append(tag("hidden by moderation"));
  if (r.status === "error") meta.append(tag(`didn't check out: ${r.error}`, "bad"));
  else if (r.error) meta.append(tag(r.error, "bad"));
  if (r.done) meta.append(tag(r.done, "done"));
  main.append(title, meta);
  const acts = document.createElement("div"); acts.className = "acts";
  if (hasKey && !pending.has(r.key)) {
    if (can(r, me, "retract")) acts.append(button("Retract", "danger", () => startSingle(r, "retract")));
    if (can(r, me, "report")) acts.append(button("Report", "secondary", () => startSingle(r, "report")));
  }
  li.append(box, main, acts);
  const p = pending.get(r.key);
  if (p) {
    const d = document.createElement("div"); d.className = "pending";
    const secs = Math.max(0, Math.ceil((p.until - Date.now()) / 1000));
    d.append(`${p.kind === "retract" ? "Retracting" : `Reporting as ${(p.op as { value?: string }).value}`} in ${secs} s · `, button("Undo", "link", () => undo(r.key)));
    li.append(d);
  }
  li.addEventListener("mouseenter", () => hover(r.key));
  li.addEventListener("mouseleave", () => hover(null));
  return li;
}

function renderPick(list: Row[]): void {
  const pick = $<HTMLSelectElement>("pick");
  const g = groups(list);
  pick.replaceChildren();
  const opt = (value: string, text: string) => { const o = document.createElement("option"); o.value = value; o.textContent = text; pick.append(o); };
  opt("", "…");
  opt("all", "All");
  opt("none", "None");
  if (me) { opt("mine", "Mine"); opt("others", "Others'"); }
  for (const [k, n] of g.kinds) opt(`kind:${k}`, `All ${k} (${n})`);
  for (const [a, n] of g.authors) opt(`author:${a}`, `By ${a === me ? "you" : a.slice(0, 10) + "…"} (${n})`);
}

function renderBulk(): void {
  const list = visible();
  const n = list.filter((r) => selected.has(r.key)).length;
  $("bulk").classList.toggle("hidden", n === 0);
  if (!n) { plan = null; $("confirm").classList.add("hidden"); return; }
  const rp = planBulk(list, selected, "retract", me, reason()), pp = planBulk(list, selected, "report", me, reason());
  $("count").textContent = `${n} selected`;
  $<HTMLButtonElement>("bulkRetract").textContent = `Retract ${rp.ops.length}`;
  $<HTMLButtonElement>("bulkRetract").disabled = !hasKey || rp.ops.length === 0;
  $<HTMLButtonElement>("bulkReport").textContent = `Report ${pp.ops.length} as ${reason()}`;
  $<HTMLButtonElement>("bulkReport").disabled = !hasKey || pp.ops.length === 0;
  $("confirm").classList.toggle("hidden", plan === null);
}

function render(empty?: string): void {
  const list = visible();
  const ul = $("rows");
  ul.replaceChildren(...list.map(renderRow));
  $("empty").classList.toggle("hidden", list.length > 0);
  if (empty !== undefined || !list.length) $("empty").textContent = empty ?? "Nothing on this page to act on.";
  renderPick(list);
  renderBulk();
}

// Pending single actions count down.
setInterval(() => { if (pending.size) render(); }, 1000);

// ---- bulk -----------------------------------------------------------------------------------

function askBulk(op: Op): void {
  const p = planBulk(visible(), selected, op, me, reason());
  if (!p.ops.length) return;
  plan = { op, ops: p.ops, rows: p.rows };
  const what = op === "retract" ? `Retract ${p.ops.length} of your fact${p.ops.length > 1 ? "s" : ""}?` : `Report ${p.ops.length} as ${reason()}?`;
  $("confirmText").textContent = what + (p.skipped ? ` (${p.skipped} selected ${p.skipped > 1 ? "aren't" : "isn't"} eligible and will be skipped.)` : "");
  const ul = $("confirmList"); ul.replaceChildren();
  for (const r of p.rows.slice(0, 3)) { const li = document.createElement("li"); li.textContent = describeRow(r); ul.append(li); }
  if (p.rows.length > 3) { const li = document.createElement("li"); li.textContent = `and ${p.rows.length - 3} more`; ul.append(li); }
  $("confirm").classList.remove("hidden");
}

$("bulkRetract").addEventListener("click", () => askBulk("retract"));
$("bulkReport").addEventListener("click", () => askBulk("report"));
$("confirmCancel").addEventListener("click", () => { plan = null; renderBulk(); });
$("confirmGo").addEventListener("click", () => {
  if (!plan) return;
  const p = plan; plan = null;
  $("confirm").classList.add("hidden");
  void execute(p.ops, p.rows, p.ops.map(() => p.op));
});
$("clear").addEventListener("click", () => { selected.clear(); plan = null; render(); });
$("reason").addEventListener("change", () => { plan = null; renderBulk(); });
$<HTMLSelectElement>("pick").addEventListener("change", () => {
  const v = $<HTMLSelectElement>("pick").value;
  const list = visible().filter((r) => r.status === "ok" && r.done === undefined);
  let keys: Set<string> | null = null;
  if (v === "all") keys = selectWhere(list, () => true);
  else if (v === "none") keys = new Set();
  else if (v === "mine") keys = selectWhere(list, (r) => r.fact?.author === me);
  else if (v === "others") keys = selectWhere(list, (r) => !!r.fact && r.fact.author !== me || r.action.action === "file");
  else if (v.startsWith("kind:")) keys = selectWhere(list, (r) => kindOf(r) === v.slice(5));
  else if (v.startsWith("author:")) keys = selectWhere(list, (r) => r.fact?.author === v.slice(7));
  if (keys) { selected.clear(); for (const k of keys) selected.add(k); plan = null; }
  render();
});

// ---- focus from a click on the page ------------------------------------------------------------

async function applyFocus(): Promise<void> {
  const got = await chrome.storage.session.get(focusKey());
  const f = got[focusKey()] as { key?: string; at?: number } | undefined;
  if (!f?.key || Date.now() - (f.at ?? 0) > 15000) return;
  for (let i = 0; i < 40 && !document.querySelector(`li.row[data-key="${CSS.escape(f.key)}"]`); i++) await new Promise((r) => setTimeout(r, 100));
  const li = document.querySelector<HTMLLIElement>(`li.row[data-key="${CSS.escape(f.key)}"]`);
  if (!li) return;
  li.scrollIntoView({ block: "center" });
  li.classList.remove("focus"); void li.offsetWidth; li.classList.add("focus");
}

// ---- start --------------------------------------------------------------------------------------

async function main(): Promise<void> {
  if (!Number.isInteger(tabId) || tabId <= 0) {
    const [t] = await chrome.tabs.query({ active: true, currentWindow: true });
    tabId = t?.id ?? -1;
  }
  base = (await getSettings()).apiBase.replace(/\/+$/, "");
  if (!base) { say("No OpenManuals server is configured.", false); return; }
  const id = await send<Identity>({ type: "getIdentity" });
  me = id?.fingerprint ?? null;
  hasKey = Boolean(id?.hasKey);
  if (!hasKey) say("No signing key in this browser, so you can look but not act. Create one in the extension settings.", false);
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "session") return;
    if (pageKey() in changes) void loadPage();
    if (focusKey() in changes) void applyFocus();
  });
  await loadPage();
  void applyFocus();
}

main().catch((e) => say((e as Error).message, false));
