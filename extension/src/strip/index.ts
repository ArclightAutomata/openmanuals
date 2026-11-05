// Watermark stripper: crates/openmanuals-strip compiled to wasm (crates/openmanuals-strip-wasm,
// generated into vendor/openmanuals-strip-wasm/). Removes what ManualsLib adds to a
// manual (wrapper pages, the per-page footer, link annotations) and the marks
// of sites the manual passed through before. See "The watermark stripper" in
// the README.
//
// Runs in a Web Worker or anywhere else without Node APIs. In the extension
// the .wasm ships next to the bundle; Node callers hand in the bytes with
// setStripWasm().
import init, * as om from "../../vendor/openmanuals-strip-wasm/openmanuals_strip_wasm.js";

export interface StripResult {
  /** True when anything was removed; `bytes` is then the rewritten file. */
  changed: boolean;
  /** The stripped file when changed, otherwise the input bytes unchanged. */
  bytes: Uint8Array;
  /** Identifies the algorithm, "om-strip-rs/2"; recorded on derivation facts as tool_version. */
  version: string;
  /** Human-readable notes on what was removed. */
  log: string[];
}

/** Tool name recorded on derivation facts (openmanuals_strip::STRIP_TOOL). */
export const STRIP_TOOL = "om-strip";
/** openmanuals_strip::STRIP_VERSION; the tests check it against the wasm. */
export const STRIP_VERSION = "om-strip-rs/2";

type Source = BufferSource | URL | string;
let source: Source | undefined;
let ready: Promise<typeof om> | null = null;

/** Where to load the .wasm from (tests and Node tools pass its bytes). Call before the first strip. */
export function setStripWasm(src: Source): void {
  source = src;
}

/** The loaded bindings. */
export function stripWasm(): Promise<typeof om> {
  ready ??= init({ module_or_path: source ?? new URL("openmanuals_strip_wasm_bg.wasm", import.meta.url) }).then(() => om, (e) => {
    ready = null;
    throw e;
  });
  return ready;
}

/**
 * Run `f` against the wasm. A Rust panic (or running out of memory) traps the
 * instance, which must not be used again: replace it and report a fault.
 */
async function call<T>(f: (m: typeof om) => T): Promise<T> {
  const m = await stripWasm();
  try {
    return f(m);
  } catch (e) {
    if (e instanceof WebAssembly.RuntimeError) {
      m.__wbg_reset_state();
      throw new Error(`stripper fault: ${e.message}`);
    }
    throw e;
  }
}

/**
 * Remove ManualsLib wrapper pages, footers and link annotations, plus known
 * third-party stamps, from a PDF. Deterministic: same input bytes, same output
 * bytes. Throws on unreadable input or a stripper fault; a PDF with nothing to
 * strip resolves with `changed: false` and the input bytes untouched.
 */
export async function stripPdf(bytes: Uint8Array): Promise<StripResult> {
  const r = await call((m) => m.strip(bytes));
  return { changed: r.changed, bytes: r.changed && r.bytes ? r.bytes : bytes, version: STRIP_VERSION, log: r.log };
}

/** What the stripper sees in a PDF, without changing it (tests and tools). */
export function inspectPdf(bytes: Uint8Array): Promise<ReturnType<typeof om.inspect>> {
  return call((m) => m.inspect(bytes));
}

/** Tests only: panic inside the wasm, through the same recovery path as a strip. */
export function _panicForTests(): Promise<void> {
  return call((m) => m.__panic_for_tests());
}
