// Loads openmanuals-wasm (the openmanuals-core bindings). In the extension the .wasm file ships
// next to the bundles; tests hand in the bytes.
import init, * as om from "../../vendor/openmanuals-wasm/openmanuals_wasm.js";

export type OmWasm = typeof om;

let ready: Promise<OmWasm> | null = null;

export function loadWasm(source?: BufferSource | URL | string): Promise<OmWasm> {
  if (!ready) {
    ready = (async () => {
      let src: BufferSource | URL | string | undefined = source;
      if (src === undefined && typeof chrome !== "undefined" && chrome.runtime?.getURL) src = chrome.runtime.getURL("openmanuals_wasm_bg.wasm");
      if (src === undefined) throw new Error("loadWasm: no wasm source");
      await init({ module_or_path: src });
      return om;
    })();
  }
  return ready;
}

/** The already-loaded module (throws if loadWasm hasn't resolved yet). */
export function wasm(): OmWasm {
  if (!loaded) throw new Error("openmanuals-wasm not loaded");
  return loaded;
}
let loaded: OmWasm | null = null;
export async function ensureWasm(source?: BufferSource | URL | string): Promise<OmWasm> {
  loaded = await loadWasm(source);
  return loaded;
}
