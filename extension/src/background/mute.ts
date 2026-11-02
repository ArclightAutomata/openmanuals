// Reports and local mutes. A report is a signed fact that goes to the server;
// locally it also steers the extension away from that copy and, after a few
// reports against the same author, mutes that author (listed and reversible
// in the options page). Nothing here leaves chrome.storage.local.
import type { Copy } from "../core/messages.ts";

export const MUTE_AFTER = 3;

export interface MuteState {
  /** file sha256 → report info */
  reportedFiles: Record<string, { at: string; author?: string; value: string }>;
  /** author fingerprint → count of distinct files reported */
  reportCounts: Record<string, number>;
  /** author fingerprint → mute info */
  muted: Record<string, { at: string; reason: "auto" | "manual" }>;
}

const DEFAULTS: MuteState = { reportedFiles: {}, reportCounts: {}, muted: {} };

export async function getMuteState(): Promise<MuteState> {
  const { muteState } = await chrome.storage.local.get({ muteState: DEFAULTS });
  return { ...DEFAULTS, ...muteState };
}

async function save(s: MuteState) {
  await chrome.storage.local.set({ muteState: s });
}

/** Record a local report; returns whether the author got auto-muted by it. */
export async function recordReport(sha256: string, author: string | undefined, value: string): Promise<{ muted: boolean }> {
  const s = await getMuteState();
  const fresh = !s.reportedFiles[sha256];
  s.reportedFiles[sha256] = { at: new Date().toISOString(), author, value };
  let muted = false;
  if (author && fresh) {
    s.reportCounts[author] = (s.reportCounts[author] ?? 0) + 1;
    if (s.reportCounts[author] >= MUTE_AFTER && !s.muted[author]) {
      s.muted[author] = { at: new Date().toISOString(), reason: "auto" };
      muted = true;
    }
  }
  await save(s);
  return { muted };
}

export async function setMuted(author: string, on: boolean): Promise<void> {
  const s = await getMuteState();
  if (on) s.muted[author] = { at: new Date().toISOString(), reason: "manual" };
  else delete s.muted[author];
  await save(s);
}

/** Order copies: unmuted and unreported first, archive.org first, then as the server ranked them. */
export function rankCopies(copies: Copy[], sha256: string, s: MuteState): Copy[] {
  const reported = Boolean(s.reportedFiles[sha256]);
  const score = (c: Copy) => (c.author && s.muted[c.author] ? 100 : 0) + (reported && c.author === s.reportedFiles[sha256]?.author ? 10 : 0) + (c.kind === "archive" ? 0 : 1);
  return copies.map((c, i) => ({ c, i })).sort((a, b) => score(a.c) - score(b.c) || a.i - b.i).map((x) => x.c);
}
