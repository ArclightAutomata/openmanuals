// Checking a fact served by `GET /api/fact/{id}` (for the confirmation
// window). Separate from site.ts so the page content script doesn't bundle
// the wasm module.
import { verifyFact, type Fact } from "./facts.ts";

/** `GET /api/fact/{id}` as the server answers it. */
export interface ServedFact { id: string; cursor: string; folded: boolean; hidden: boolean; retracted: boolean; fact: Fact | null }

/**
 * Check a served fact is exactly the one asked for: well-formed, its signature
 * valid and its id, recomputed from the canonical bytes, equal to `id`. The
 * server (or anything between) can't swap in other content.
 */
export async function checkServedFact(served: unknown, id: string): Promise<ServedFact> {
  const s = served as ServedFact;
  if (!s || typeof s !== "object" || s.id !== id) throw new Error("The server answered for a different fact.");
  if (s.hidden) return { ...s, fact: null };
  if (!s.fact || typeof s.fact !== "object") throw new Error("The server didn't send the fact.");
  let got: string;
  try { got = await verifyFact(s.fact); } catch (e) { throw new Error(`The fact's signature doesn't check out: ${(e as Error).message}`); }
  if (got !== id) throw new Error(`The fact the server sent hashes to ${got}, not ${id}.`);
  return { ...s, retracted: Boolean(s.retracted), folded: Boolean(s.folded), hidden: false };
}
