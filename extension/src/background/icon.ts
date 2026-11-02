// Toolbar badge per tab. The icon is always the logo; the badge (text and
// color) says whether the page's manual is preserved or will be uploaded.
import type { LookupResult } from "../core/messages.ts";

export type IconState = "none" | "checking" | "archived" | "missing" | "ready" | "uploading" | "error";
const ICON_STATES: Record<IconState, { color: string; badge: string }> = {
  none: { color: "gray", badge: "" },
  checking: { color: "gray", badge: "…" },
  archived: { color: "green", badge: "✓" },   // preserved; direct download available
  missing: { color: "gray", badge: "" },      // not preserved; upload off
  ready: { color: "blue", badge: "↑" },       // not preserved; a download will upload it
  uploading: { color: "blue", badge: "…" },
  error: { color: "gray", badge: "!" },
};
const COLORS: Record<string, string> = { gray: "#a1a1aa", green: "#2f7d5b", blue: "#2563eb" };

export function paint(tabId: number | undefined, state: IconState): void {
  if (tabId === undefined) return;
  const s = ICON_STATES[state] ?? ICON_STATES.none;
  chrome.action.setBadgeText({ tabId, text: s.badge }).catch(() => {});
  chrome.action.setBadgeBackgroundColor({ tabId, color: COLORS[s.color] }).catch(() => {});
  chrome.action.setBadgeTextColor?.({ tabId, color: "#ffffff" })?.catch?.(() => {});
}

export function stateFor(r: LookupResult | null | undefined): IconState {
  if (!r) return "none";
  if (r.error) return "error";
  if (r.archived) return "archived";
  return r.canUpload ? "ready" : "missing";
}
