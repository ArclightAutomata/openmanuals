import { getSettings } from "../core/config.ts";
import { avatarSrc, type AvatarBody } from "../core/avatar.ts";
import { factsLabel, fullCount } from "../core/count.ts";
import type { Identity, LookupResult, OutboxEntry } from "../core/messages.ts";

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const statusEl = $("status"), actionsEl = $("actions"), outboxEl = $("outbox"), idEl = $("identity");
const send = <T,>(msg: unknown) => chrome.runtime.sendMessage(msg).catch(() => null) as Promise<T | null>;
const openOptions = (hash = "") => { chrome.runtime.openOptionsPage(); if (hash) chrome.storage.session.set({ optionsJump: hash }).catch(() => {}); window.close(); };
$("options").addEventListener("click", (e) => { e.preventDefault(); openOptions(); });

const el = (tag: string, cls: string, text?: string) => { const n = document.createElement(tag); n.className = cls; if (text) n.textContent = text; return n; };
const btn = (text: string, href: string | null, cls = "") => {
  const a = document.createElement("a"); a.className = "btn " + cls; a.textContent = text;
  if (href) { a.href = href; a.target = "_blank"; a.rel = "noopener"; }
  return a;
};

async function renderIdentity() {
  const id = await send<Identity>({ type: "getIdentity" });
  const s = await getSettings();
  idEl.replaceChildren();
  if (!id?.hasKey) {
    const a = document.createElement("a"); a.href = "#"; a.textContent = "Create your contributor key →";
    a.addEventListener("click", (e) => { e.preventDefault(); openOptions("#identity"); });
    idEl.append(el("span", "", "No identity yet"), a);
    return;
  }
  const fp = id.fingerprint!;
  const name = id.profile?.name?.trim() ?? "";
  // The whole block (avatar, name, fingerprint) links to the public profile page.
  const who = document.createElement(s.apiBase ? "a" : "span");
  who.className = "who";
  if (who instanceof HTMLAnchorElement) { who.href = `${s.apiBase}/k/${fp}`; who.target = "_blank"; who.rel = "noopener"; who.title = "Your public profile"; }
  const st = await send<{ fingerprint: string; body: AvatarBody; pending?: string } | null>({ type: "avatarState" });
  const src = avatarSrc(st?.fingerprint === fp ? st : null, s.apiBase);
  const initial = el("span", "avatar blank", (name || fp).slice(0, 1).toUpperCase());
  if (src) {
    const img = document.createElement("img"); img.className = "avatar"; img.alt = ""; img.src = src;
    img.addEventListener("error", () => img.replaceWith(initial));
    who.append(img);
  } else who.append(initial);
  const text = el("span", "text");
  const fpLine = el("span", "fp", `${fp.slice(0, 8)}…`);
  text.append(el("span", "name", name || "Your profile"), fpLine);
  who.append(text);
  idEl.append(who);
  // Everything this key has signed, as the server counts it (not just this browser's).
  if (s.apiBase) {
    const stats = await fetch(`${s.apiBase}/api/key/${fp}/stats`).then((r) => r.ok ? r.json() as Promise<{ facts?: number }> : null).catch(() => null);
    if (typeof stats?.facts === "number" && stats.facts > 0) {
      const n = el("span", "count", ` · ${factsLabel(stats.facts)}`);
      n.title = `${fullCount(stats.facts)} facts signed by this key`;
      fpLine.append(n);
    }
  }
}

async function renderOutbox() {
  const st = await send<{ outbox: OutboxEntry[] }>({ type: "outboxState" });
  outboxEl.replaceChildren();
  if (!st?.outbox.length) return;
  outboxEl.append(el("span", "", `${st.outbox.length} bundle${st.outbox.length > 1 ? "s" : ""} waiting to be sent`));
  const b = el("a", "btn ghost", "Retry now") as HTMLAnchorElement;
  b.addEventListener("click", async () => { await send({ type: "flushOutbox" }); void renderOutbox(); });
  outboxEl.append(b);
  if (st.outbox[0].lastError) outboxEl.append(el("div", "muted", `Last error: ${st.outbox[0].lastError}`));
}

async function renderPage() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  // An OpenManuals server page (its content script reported it): offer the side panel.
  if (tab?.id && chrome.sidePanel?.open) {
    const key = `sitePage:${tab.id}`;
    const page = (await chrome.storage.session.get(key).catch(() => ({} as Record<string, unknown>)))[key] as { items?: unknown[] } | undefined;
    if (page) {
      statusEl.replaceChildren(el("span", "title", `${page.items?.length ?? 0} facts, copies and files on this page`));
      const b = btn("Retract or report in the side panel", null);
      b.href = "#";
      b.addEventListener("click", (e) => {
        e.preventDefault();
        // Called straight from the click, so the user gesture still counts.
        void chrome.sidePanel.open({ tabId: tab.id! }).then(() => window.close(), () => { statusEl.append(el("div", "warn", "Couldn't open the side panel.")); });
      });
      actionsEl.replaceChildren(b);
      return;
    }
  }
  if (!tab?.id || !(await send<boolean>({ type: "isSourcePage", tabId: tab.id }))) return;
  statusEl.textContent = "Checking…";
  const r = await send<LookupResult>({ type: "getTabStatus", tabId: tab.id });
  statusEl.replaceChildren();
  actionsEl.replaceChildren();
  if (!r || r.error) { statusEl.append(el("span", "warn", "Couldn't reach archive.org.")); return; }
  if (r.archived) {
    const n = r.files.reduce((s, f) => s + (f.copies?.length ?? 0), 0);
    statusEl.append(el("span", "ok", "✓ Free to download"), el("span", "title", r.title ?? r.identifier ?? ""));
    if (n > 1) statusEl.append(el("div", "copies", `${n} copies known`));
    if (r.download_url) actionsEl.append(btn(`Download ${r.filename ? r.filename.split(".").pop()!.toUpperCase() : "file"} ↓`, r.download_url));
    if (r.archive_url) actionsEl.append(btn(r.copy?.ia ? "View on archive.org" : `View on ${r.copy?.host ?? "the host"}`, r.archive_url, "secondary"));
    if (r.openmanuals_url) actionsEl.append(btn("On OpenManuals", r.openmanuals_url, "secondary"));
    const file = r.files.find((f) => f.copies?.some((c) => c.url === r.copy?.url)) ?? r.files[0];
    if (file && r.hasKey) {
      const row = el("div", "row");
      const wrong = btn("This file is wrong", null, "ghost");
      wrong.addEventListener("click", async () => {
        wrong.textContent = "Reporting…";
        const res = await send<{ ok: boolean; sent: boolean; muted: boolean }>({ type: "report", sha256: file.sha256, author: r.copy?.author, url: r.copy?.url, value: "wrong-file" });
        wrong.textContent = res?.ok ? (res.muted ? "Reported; author muted" : "Reported, thanks") : "Couldn't report";
      });
      const add = btn("Add a copy (URL)", null, "ghost");
      add.addEventListener("click", () => {
        const input = document.createElement("input"); input.className = "url"; input.placeholder = "https://… direct link to the same file";
        const go = btn("Check and record", null, "secondary");
        go.addEventListener("click", async () => {
          const url = input.value.trim();
          if (!/^https:\/\//.test(url)) { go.textContent = "Needs an https:// URL"; return; }
          const origin = new URL(url).origin + "/*";
          if (!(await chrome.permissions.contains({ origins: [origin] })) && !(await chrome.permissions.request({ origins: [origin] }))) { go.textContent = "Permission needed"; return; }
          go.textContent = "Fetching and hashing…";
          const res = await send<{ ok?: boolean; error?: string }>({ type: "addCopy", sha256: file.sha256, url });
          go.textContent = res?.ok ? "Recorded (pending verification)" : (res?.error ?? "Failed");
        });
        actionsEl.append(input, go);
        add.remove();
      });
      row.append(wrong, add);
      actionsEl.append(row);
    }
  } else {
    statusEl.append(el("span", "muted", "Not preserved yet."), document.createElement("br"));
    if (r.canUpload) statusEl.append(el("span", "blue", "↑ Download it here and the extension will preserve it."));
    else {
      const hint = el("span", "muted", "Turn on uploads in ");
      const a = document.createElement("a"); a.href = "#"; a.textContent = "Settings";
      a.addEventListener("click", (e) => { e.preventDefault(); openOptions("#archive"); });
      hint.append(a, " to preserve it when you download it.");
      statusEl.append(hint);
    }
    if (!r.hasKey) statusEl.append(document.createElement("br"), el("span", "muted", "Create a contributor key in Settings to get credit."));
  }
}

void renderIdentity();
void renderOutbox();
void renderPage();
