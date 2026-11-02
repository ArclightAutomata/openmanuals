// Validation against real ManualsLib downloads, through the wasm build of
// openmanuals-strip (the twin of crates/openmanuals-strip/tests/samples.rs).
// The expected results for 40 originals are in fixtures/reference.json, with
// paths relative to a corpus directory; skipped unless that directory is
// given. It is only ever read.
//
//   OM_STRIP_CORPUS=dir   the directory the fixture's paths are relative to
//   OM_STRIP_SAMPLES=10   limit the sample count
//   OM_STRIP_LARGE=file   also time stripping one (large) PDF
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { inspectPdf, setStripWasm, stripPdf } from "./index.ts";
import reference from "./fixtures/reference.json" with { type: "json" };

setStripWasm(readFileSync(new URL("../../vendor/openmanuals-strip-wasm/openmanuals_strip_wasm_bg.wasm", import.meta.url)));

const ROOT = process.env.OM_STRIP_CORPUS ?? "";
const samples = ROOT ? reference.samples.filter((s) => existsSync(join(ROOT, s.path))) : [];
const limit = Number(process.env.OM_STRIP_SAMPLES ?? samples.length);

test("real ManualsLib downloads match the reference page counts and lose every footer and link", { skip: samples.length === 0 && (ROOT ? "none of the samples are under OM_STRIP_CORPUS" : "set OM_STRIP_CORPUS") }, async () => {
  const mismatches: string[] = [];
  let checked = 0;
  let totalMs = 0;
  for (const s of samples.slice(0, limit)) {
    const bytes = new Uint8Array(readFileSync(join(ROOT, s.path)));
    const before = await inspectPdf(bytes);
    const t0 = performance.now();
    const r = await stripPdf(bytes);
    totalMs += performance.now() - t0;
    const after = await inspectPdf(r.bytes);
    checked++;
    if (before.pages !== s.pages_before || before.leading !== s.leading || before.trailing !== s.trailing || after.pages !== s.pages_after || r.changed !== s.modified || after.footer_pages || after.manualslib_links) {
      mismatches.push(`${s.path}: pages ${before.pages}->${after.pages} (expected ${s.pages_before}->${s.pages_after}), wrapper [${before.leading}, ${before.trailing}] (expected [${s.leading}, ${s.trailing}]), changed ${r.changed} (expected ${s.modified}), footers left ${after.footer_pages}, links left ${after.manualslib_links}; log: ${r.log.join("; ")}`);
    }
  }
  console.log(`samples: ${checked} checked, ${checked - mismatches.length} match, ${Math.round(totalMs)} ms total`);
  assert.deepEqual(mismatches, []);
});

test("a large PDF strips in reasonable time", { skip: !process.env.OM_STRIP_LARGE && "set OM_STRIP_LARGE to a PDF" }, async () => {
  const path = process.env.OM_STRIP_LARGE!;
  const bytes = new Uint8Array(readFileSync(path));
  const t0 = performance.now();
  const r = await stripPdf(bytes);
  const ms = Math.round(performance.now() - t0);
  console.log(`${path}: ${bytes.length} bytes in ${ms} ms, changed=${r.changed}, log: ${r.log.join("; ")}`);
  assert.ok(ms < 60_000);
});
