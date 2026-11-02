// Signed bundles wait here until the server answers 202. Persisted in
// chrome.storage.local; retried with backoff from an alarm.
import { getSettings } from "../core/config.ts";
import type { Fact } from "../core/facts.ts";
import type { HistoryEntry, OutboxEntry } from "../core/messages.ts";
import { ulid } from "../core/ulid.ts";
import { ApiError, postFacts } from "./api.ts";
import { rememberSubmitted } from "./filter.ts";

const ALARM = "om-outbox";
const HISTORY_MAX = 200;
const BACKOFF = [30, 120, 600, 1800, 3600, 6 * 3600]; // seconds

async function load(): Promise<{ outbox: OutboxEntry[]; history: HistoryEntry[] }> {
  const { outbox = [], history = [] } = await chrome.storage.local.get({ outbox: [], history: [] });
  return { outbox, history };
}

export async function state() {
  return load();
}

// Every read-modify-write of the outbox goes through this lock, so an entry
// queued while a flush is posting can't be overwritten by the flush's write.
let lock: Promise<unknown> = Promise.resolve();
function locked<T>(fn: () => Promise<T>): Promise<T> {
  const run = lock.then(fn, fn);
  lock = run.catch(() => {});
  return run;
}

export async function enqueue(facts: Fact[], label: string): Promise<OutboxEntry> {
  const entry: OutboxEntry = { id: ulid(), createdAt: new Date().toISOString(), attempts: 0, nextTry: 0, label, facts };
  await locked(async () => {
    const { outbox } = await load();
    outbox.push(entry);
    await chrome.storage.local.set({ outbox });
  });
  await rememberSubmitted(facts).catch(() => {});
  void flush();
  return entry;
}

let flushing: Promise<void> | null = null;
let again = false;

/** Try to deliver everything that's due. Safe to call often; a call during a run queues one more run. */
export function flush(): Promise<void> {
  if (flushing) { again = true; return flushing; }
  flushing = (async () => {
    do { again = false; await doFlush(); } while (again);
  })().finally(() => { flushing = null; });
  return flushing;
}

async function doFlush(): Promise<void> {
  const settings = await getSettings();
  if (!settings.apiBase) return;
  const { outbox } = await load();
  if (!outbox.length) return;
  const now = Date.now();
  for (const entry of outbox) {
    if (entry.nextTry > now) continue;
    // Post outside the lock (it can take a while), then record the outcome
    // against the stored outbox as it is now: entries queued meanwhile stay.
    let done: HistoryEntry | null = null, failed: Pick<OutboxEntry, "attempts" | "nextTry" | "lastError"> | null = null;
    try {
      const r = await postFacts(settings, entry.facts);
      done = { id: entry.id, createdAt: entry.createdAt, acceptedAt: new Date().toISOString(), label: entry.label, accepted: r.accepted, duplicate: r.duplicate, rejected: r.rejected };
    } catch (e) {
      const attempts = entry.attempts + 1;
      const wait = e instanceof ApiError && e.retryAfter ? e.retryAfter : BACKOFF[Math.min(attempts - 1, BACKOFF.length - 1)];
      failed = { attempts, nextTry: Date.now() + wait * 1000, lastError: (e as Error).message };
    }
    await locked(async () => {
      const cur = await load();
      const i = cur.outbox.findIndex((x) => x.id === entry.id);
      if (done) {
        if (i >= 0) cur.outbox.splice(i, 1);
        cur.history.unshift(done);
      } else if (failed && i >= 0) Object.assign(cur.outbox[i], failed);
      await chrome.storage.local.set({ outbox: cur.outbox, history: cur.history.slice(0, HISTORY_MAX) });
    });
  }
  if ((await load()).outbox.length) await scheduleRetry();
}

async function scheduleRetry(): Promise<void> {
  const { outbox } = await load();
  const next = Math.min(...outbox.map((e) => e.nextTry));
  if (!Number.isFinite(next)) return;
  await chrome.alarms.create(ALARM, { when: Math.max(next, Date.now() + 15000) });
}

export function installAlarm(): void {
  chrome.alarms.onAlarm.addListener((a) => { if (a.name === ALARM) void flush(); });
}

/** Ids of facts that were accepted or duplicate, for showing "recorded" state. */
export async function deliveredIds(): Promise<Set<string>> {
  const { history } = await load();
  const out = new Set<string>();
  for (const h of history) for (const id of [...h.accepted, ...h.duplicate]) out.add(id);
  return out;
}
