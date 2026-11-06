// The edit window: the manual editor on its own, for when the side panel
// can't open. Opened by the service worker with a validated manual action.
import { getSettings } from "../core/config.ts";
import type { Identity } from "../core/messages.ts";
import { fromQuery } from "../core/site.ts";
import { mountEditor } from "./editor.ts";

const send = <T,>(msg: unknown) => chrome.runtime.sendMessage(msg).catch((e) => ({ error: String(e) })) as Promise<T>;
const fail = (text: string) => { document.getElementById("msg")!.textContent = text; };

async function main(): Promise<void> {
  const a = fromQuery(location.search);
  if (a?.action !== "manual") { fail("This window was opened without a manual to edit."); return; }
  const base = (await getSettings()).apiBase.replace(/\/+$/, "");
  if (!base) { fail("No OpenManuals server is configured."); return; }
  const id = await send<Identity>({ type: "getIdentity" });
  const editor = mountEditor(document.getElementById("editor")!, { base, manual: a.manual, me: id?.fingerprint ?? null, hasKey: Boolean(id?.hasKey), send });
  editor.focus(a.focus);
}

main().catch((e) => fail((e as Error).message));
