// The manual editor, shared by the side panel and the edit window (both
// extension pages, which the website can't script). It starts from the
// manual's facts as the server sends them (GET /api/manual/{id}/facts),
// checking every one itself (signature, id); the page only told us which
// manual. Saving shows the changes, and only "Sign and send" signs them.
import { DOC_LABELS, DOC_TYPES, draftOf, manualState, planEdit, type CheckedFact, type EditPlan, type ManualState } from "../core/edit.ts";
import { checkServedFact } from "../core/site-check.ts";
import { ensureWasm } from "../core/wasm.ts";

export interface EditorOptions {
  /** The server's base URL, no trailing slash. */
  base: string;
  manual: string;
  me: string | null;
  hasKey: boolean;
  send: <T>(msg: unknown) => Promise<T>;
}

export interface Editor {
  readonly manual: string;
  /** Put the cursor where the click on the page asked: "title", "add" or "product:<key>". */
  focus(where?: string): void;
  destroy(): void;
}

interface RowState { brand: string; model: string; key?: string; by?: "you" | "others" | "you and others" }

function el<K extends keyof HTMLElementTagNameMap>(tag: K, props: Partial<HTMLElementTagNameMap[K]> = {}, ...kids: (Node | string)[]): HTMLElementTagNameMap[K] {
  const e = Object.assign(document.createElement(tag), props);
  e.append(...kids);
  return e;
}

export function mountEditor(root: HTMLElement, o: EditorOptions): Editor {
  let alive = true;
  let state: ManualState | null = null;
  let rows: RowState[] = [];
  let plan: EditPlan | null = null;
  let pendingFocus: string | undefined;
  let busy = false;

  root.replaceChildren();
  root.classList.add("om-editor");
  const msg = el("p", { className: "ed-msg" });
  const say = (text: string, ok?: boolean) => { msg.textContent = text; msg.className = "ed-msg" + (ok === undefined ? "" : ok ? " ok" : " bad"); };
  const title = el("input", { type: "text", id: "edTitle", maxLength: 300, autocomplete: "off" });
  const type = el("select", { id: "edType" });
  for (const t of DOC_TYPES) type.append(el("option", { value: t, textContent: DOC_LABELS[t] }));
  const list = el("ul", { className: "ed-models" });
  const add = el("button", { type: "button", className: "secondary", textContent: "+ Add model" });
  const review = el("button", { type: "button", textContent: "Review changes" });
  const box = el("div", { className: "ed-review hidden" });
  const form = el("div", { className: "ed-form hidden" },
    el("label", { htmlFor: "edTitle" }, "Title"), title,
    el("label", { htmlFor: "edType" }, "Type"), type,
    el("div", { className: "ed-label" }, "Models"), list,
    el("div", { className: "ed-line" }, add, review),
    box,
  );
  root.append(el("h2", {}, "Edit this manual"), form, msg);

  const changed = () => { plan = null; box.classList.add("hidden"); };
  title.addEventListener("input", changed);
  type.addEventListener("change", changed);

  function renderRows(): void {
    list.replaceChildren(...rows.map((r, i) => {
      const brand = el("input", { type: "text", value: r.brand, placeholder: "Brand", maxLength: 120, autocomplete: "off" });
      const model = el("input", { type: "text", value: r.model, placeholder: "Model", maxLength: 120, autocomplete: "off" });
      brand.addEventListener("input", () => { r.brand = brand.value; changed(); });
      model.addEventListener("input", () => { r.model = model.value; changed(); });
      const remove = el("button", { type: "button", className: "link", textContent: "Remove", title: "Remove this model" });
      remove.addEventListener("click", () => { rows.splice(i, 1); changed(); renderRows(); });
      const who = el("span", { className: "ed-who", textContent: r.key ? `listed by ${r.by}` : "new" });
      const li = el("li", {}, brand, model, remove, who);
      if (r.key) li.dataset.key = r.key;
      return li;
    }));
    if (!rows.length) list.append(el("li", { className: "ed-none", textContent: "No models yet." }));
  }

  function addRow(): HTMLInputElement | null {
    const brand = rows.find((r) => r.brand.trim())?.brand ?? "";
    rows.push({ brand, model: "" });
    changed();
    renderRows();
    const inputs = list.querySelectorAll<HTMLInputElement>("li:last-child input");
    const target = inputs[brand ? 1 : 0] ?? null;
    target?.focus();
    return target;
  }
  add.addEventListener("click", () => addRow());

  function applyFocus(where?: string): void {
    if (!where) return;
    if (!state) { pendingFocus = where; return; }
    root.scrollIntoView({ block: "start" });
    if (where === "title") { title.focus(); title.select(); return; }
    if (where === "add") { addRow(); return; }
    if (where.startsWith("product:")) {
      const key = where.slice("product:".length);
      const li = [...list.querySelectorAll<HTMLLIElement>("li")].find((x) => x.dataset.key === key);
      if (!li) return;
      li.classList.remove("ed-flash"); void li.offsetWidth; li.classList.add("ed-flash");
      li.querySelectorAll<HTMLInputElement>("input")[1]?.focus();
    }
  }

  async function load(): Promise<void> {
    say("Loading the manual's facts…");
    const res = await fetch(`${o.base}/api/manual/${encodeURIComponent(o.manual)}/facts`, { cache: "no-store" });
    if (!res.ok) throw new Error(`The server answered HTTP ${res.status}.`);
    const body = (await res.json()) as { manual?: string; facts?: unknown[]; products?: Record<string, { brand?: unknown; model?: unknown }>; truncated?: boolean };
    if (body.manual !== o.manual || !Array.isArray(body.facts)) throw new Error("The server answered for a different manual.");
    const checked: CheckedFact[] = [];
    for (const raw of body.facts) {
      const id = (raw as { id?: unknown })?.id;
      if (typeof id !== "string") throw new Error("The server sent a fact without an id.");
      checked.push(await checkServedFact(raw, id));
    }
    const s = manualState(o.manual, checked, body.products ?? {});
    if (!s.title && !s.models.length) throw new Error("This manual isn't on the server yet.");
    if (!alive) return;
    state = s;
    const d = draftOf(s);
    title.value = d.title;
    type.value = (DOC_TYPES as readonly string[]).includes(d.docType) ? d.docType : "other";
    rows = s.models.map((m) => {
      const mine = m.covers.some((c) => c.author === o.me), theirs = m.covers.some((c) => c.author !== o.me);
      return { brand: m.brand, model: m.model, key: m.key, by: mine && theirs ? "you and others" : mine ? "you" : "others" };
    });
    renderRows();
    form.classList.remove("hidden");
    changed();
    review.disabled = !o.hasKey;
    say(o.hasKey ? (body.truncated ? "This manual has more facts than the server sends at once; some models may be missing." : "") : "No signing key in this browser, so you can look but not save. Create one in the extension settings.", o.hasKey ? undefined : false);
    const f = pendingFocus; pendingFocus = undefined;
    applyFocus(f);
  }

  function showReview(p: EditPlan): void {
    box.replaceChildren();
    if (p.changes.length) {
      box.append(el("p", { className: "ed-q", textContent: `Sign and send ${p.facts.length} fact${p.facts.length > 1 ? "s" : ""}?` }), el("ul", {}, ...p.changes.map((c) => el("li", { textContent: c }))));
    } else box.append(el("p", { className: "ed-q", textContent: "Nothing to change." }));
    for (const n of p.notes) box.append(el("p", { className: "ed-note", textContent: n }));
    if (p.facts.length) {
      const go = el("button", { type: "button", className: "danger", textContent: "Sign and send" });
      const cancel = el("button", { type: "button", className: "secondary", textContent: "Cancel" });
      go.addEventListener("click", () => void sign(p));
      cancel.addEventListener("click", () => changed());
      box.append(el("div", { className: "ed-line" }, go, cancel));
    }
    box.classList.remove("hidden");
  }

  review.addEventListener("click", async () => {
    if (!state || busy) return;
    const om = await ensureWasm();
    const p = planEdit(state, { title: title.value, docType: type.value, models: rows }, o.me, (b, m) => om.product_key(b, m) ?? undefined);
    if (p.error) { say(p.error, false); return; }
    say("");
    plan = p;
    showReview(p);
  });

  async function sign(p: EditPlan): Promise<void> {
    if (busy || plan !== p) return;
    busy = true;
    for (const b of box.querySelectorAll("button")) b.disabled = true;
    say("Signing…");
    try {
      const r = await o.send<{ ok?: boolean; error?: string }>({ type: "submitFacts", facts: p.facts, label: `edit ${o.manual}` });
      if (!r?.ok) { say(r?.error ?? "Failed.", false); for (const b of box.querySelectorAll("button")) b.disabled = false; return; }
      const st = await o.send<{ outbox?: { lastError?: string }[] }>({ type: "flushOutbox" });
      const waiting = st?.outbox?.length;
      changed();
      await load().catch(() => {});
      say(waiting
        ? `Signed. It's queued and will be sent when the server is reachable${st.outbox![0].lastError ? ` (${st.outbox![0].lastError})` : ""}.`
        : "Sent. The manual's page shows the change after the server's next update, usually within a minute.", true);
    } finally {
      busy = false;
    }
  }

  load().catch((e) => { if (alive) say((e as Error).message, false); });

  return {
    manual: o.manual,
    focus: applyFocus,
    destroy() { alive = false; root.replaceChildren(); root.classList.remove("om-editor"); },
  };
}
