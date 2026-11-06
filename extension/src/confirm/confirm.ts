// The confirmation window for actions started on the server's pages. It is an
// extension page, so the website can't script or click it. Everything shown
// is re-fetched and re-checked here: the fact must verify and hash to the id
// that was clicked, and only your own facts can be retracted.
import { getSettings } from "../core/config.ts";
import { bodies, nowIso, type Fact } from "../core/facts.ts";
import type { Identity } from "../core/messages.ts";
import { fromQuery, summarizeBody, toQuery, type SiteAction } from "../core/site.ts";
import { checkServedFact, type ServedFact } from "../core/site-check.ts";

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const send = <T,>(msg: unknown) => chrome.runtime.sendMessage(msg).catch((e) => ({ error: String(e) })) as Promise<T>;
const say = (text: string, ok?: boolean) => { const e = $("msg"); e.textContent = text; e.className = "msg " + (ok === undefined ? "" : ok ? "ok" : "bad"); };
const show = (id: string) => $(id).classList.remove("hidden");
$("close").addEventListener("click", () => window.close());

async function getFact(apiBase: string, id: string): Promise<ServedFact> {
  const res = await fetch(`${apiBase}/api/fact/${encodeURIComponent(id)}`, { cache: "no-store" });
  if (res.status === 404) throw new Error("The server doesn't have that fact.");
  if (!res.ok) throw new Error(`The server answered HTTP ${res.status}.`);
  return checkServedFact(await res.json(), id);
}

function describe(f: Fact, me: string | null, extra: string[] = []): void {
  const box = $("what");
  box.replaceChildren();
  const add = (cls: string, text: string) => { const p = document.createElement("p"); p.className = cls; p.textContent = text; box.append(p); return p; };
  add("", `${f.type} fact`).style.fontWeight = "600";
  add("meta", `by ${f.author === me ? "you" : f.author} · ${f.at}`);
  for (const x of extra) add("meta", x);
  const ul = document.createElement("ul"); ul.className = "body";
  for (const line of summarizeBody(f.body)) { const li = document.createElement("li"); li.textContent = line; ul.append(li); }
  box.append(ul);
  show("what");
}

async function finish(p: Promise<{ ok?: boolean; sent?: boolean; error?: string }>, done: string): Promise<void> {
  for (const b of document.querySelectorAll("button")) if (b.id !== "close") (b as HTMLButtonElement).disabled = true;
  say("Signing…");
  const r = await p;
  if (r?.error) { say(r.error, false); return; }
  if (r?.sent === false) { say("Recorded here, but not sent: no signing key in this browser.", false); return; }
  const st = await send<{ outbox?: { lastError?: string }[] }>({ type: "flushOutbox" });
  const waiting = st?.outbox?.length ? ` It's queued and will be sent when the server is reachable${st.outbox[0].lastError ? ` (${st.outbox[0].lastError})` : ""}.` : "";
  say(done + waiting, true);
  setTimeout(() => window.close(), 4000);
}

async function main(a: SiteAction): Promise<void> {
  const { apiBase } = await getSettings();
  const base = apiBase.replace(/\/+$/, "");
  if (!base) throw new Error("No OpenManuals server is configured.");
  const id = await send<Identity>({ type: "getIdentity" });
  const me = id?.fingerprint ?? null;
  const reportOf = (target: string, extra: Record<string, string | undefined>) => () =>
    finish(send({ type: "report", target, value: $<HTMLSelectElement>("reason").value, ...extra }), "Report signed and sent.");

  if (a.action === "manual") {
    // Editing has its own window.
    location.replace(chrome.runtime.getURL(`edit.html?${toQuery(a)}`));
    return;
  }
  if (a.action === "file") {
    $("title").textContent = "Report a file";
    const box = $("what"); box.textContent = ""; const p = document.createElement("p"); p.className = "meta"; p.textContent = `File ${a.file}`; box.append(p); show("what");
    show("reportBox");
    $("report").addEventListener("click", reportOf(`file:${a.file}`, { sha256: /^[0-9a-f]{64}$/.test(a.file) ? a.file : undefined }));
    return;
  }

  const factId = a.action === "fact" ? a.fact : a.location;
  const served = await getFact(base, factId);
  if (served.hidden || !served.fact) { $("title").textContent = "Hidden by moderation"; say("This fact is hidden, so there's nothing to do here."); return; }
  const f = served.fact;
  if (a.action === "copy") {
    // The page's file id must be the one the location fact itself names.
    if (f.type !== "location" || f.body.file !== a.file) throw new Error("The page's details don't match the copy's fact.");
  }
  const mine = me !== null && f.author === me;
  describe(f, me, served.retracted ? ["Already retracted by its author."] : []);
  if (mine) {
    $("title").textContent = a.action === "copy" ? "Your copy" : "Your fact";
    if (served.retracted) { say("You already retracted this."); return; }
    if (f.type === "retract") { say("This is a retraction; to undo it, contact a moderator."); return; }
    if (!id?.hasKey) { say("No signing key in this browser.", false); return; }
    show("retractBox");
    $("retract").addEventListener("click", () => finish(
      send({ type: "submitFacts", facts: [{ type: "retract", at: nowIso(), body: bodies.retract(factId) }], label: `retract ${factId.slice(7, 17)}` }),
      "Retraction signed and sent. Reload the page to see it marked retracted.",
    ));
    return;
  }
  $("title").textContent = a.action === "copy" ? "Report a copy" : "Report a fact";
  show("reportBox");
  const url = typeof f.body.url === "string" ? f.body.url : undefined;
  $("report").addEventListener("click", a.action === "copy"
    ? reportOf(factId, { sha256: /^[0-9a-f]{64}$/.test(a.file) ? a.file : undefined, author: f.author, url })
    : reportOf(factId, { author: f.author }));
}

const action = fromQuery(location.search);
if (!action) { $("title").textContent = "Nothing to do"; say("This window was opened without a valid action.", false); }
else main(action).catch((e) => { $("title").textContent = "Can't do that"; say((e as Error).message, false); });
