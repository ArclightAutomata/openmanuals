// Dev tool: node src/strip/smoke.ts <original.pdf>
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { inspectPdf, setStripWasm, stripPdf } from "./index.ts";
setStripWasm(readFileSync(new URL("../../vendor/openmanuals-strip-wasm/openmanuals_strip_wasm_bg.wasm", import.meta.url)));
const bytes = new Uint8Array(readFileSync(process.argv[2]));
const t0 = performance.now();
const r = await stripPdf(bytes);
const ms = Math.round(performance.now() - t0);
const before = await inspectPdf(bytes);
const after = await inspectPdf(r.bytes);
console.log(JSON.stringify({ changed: r.changed, ms, inBytes: bytes.length, outBytes: r.bytes.length, before, after, sha: createHash("sha256").update(r.bytes).digest("hex").slice(0, 12), log: r.log }));
