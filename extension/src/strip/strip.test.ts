// The TypeScript side of the stripper: the wasm binding and its error paths.
// The passes themselves are tested in crates/openmanuals-strip/tests/strip.rs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { _panicForTests, inspectPdf, setStripWasm, stripPdf, stripWasm, STRIP_TOOL, STRIP_VERSION } from "./index.ts";

setStripWasm(readFileSync(new URL("../../vendor/openmanuals-strip-wasm/openmanuals_strip_wasm_bg.wasm", import.meta.url)));

const sha = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");
const latin1 = (s: string) => Uint8Array.from(s, (c) => c.charCodeAt(0));

/** A minimal PDF: `objects[i]` becomes object i+1; object 1 must be the catalog. */
function pdf(objects: string[]): Uint8Array {
  let out = "%PDF-1.4\n";
  const offsets: number[] = [];
  objects.forEach((o, i) => {
    offsets.push(out.length);
    out += `${i + 1} 0 obj\n${o}\nendobj\n`;
  });
  const xref = out.length;
  out += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const off of offsets) out += `${String(off).padStart(10, "0")} 00000 n \n`;
  out += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return latin1(out);
}

const stream = (data: string) => `<< /Length ${data.length} >>\nstream\n${data}\nendstream`;
const link = (uri: string) => `<< /Type /Annot /Subtype /Link /Rect [0 0 10 10] /A << /S /URI /URI (${uri}) >> >>`;
const FOOTER = "q\n0 0 612 792 re W n\nBT /F1 8 Tf 20 10 Td (Downloaded from www.Manualslib.com manuals search engine) Tj ET\nQ\n";
const PREAMBLE = "q\n/GSa gs\n";

/** Pages given as [content, link URIs]; objects: 1 catalog, 2 pages, 3 font, then page + content pairs. */
function pages(specs: [string, string[]][]): Uint8Array {
  const objs = ["<< /Type /Catalog /Pages 2 0 R >>", "", "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"];
  const kids: string[] = [];
  for (const [content, links] of specs) {
    const page = objs.length + 1;
    kids.push(`${page} 0 R`);
    const annots = links.length ? ` /Annots [${links.map(link).join(" ")}]` : "";
    objs.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents ${page + 1} 0 R${annots} >>`);
    objs.push(stream(content));
  }
  objs[1] = `<< /Type /Pages /Kids [${kids.join(" ")}] /Count ${kids.length} >>`;
  return pdf(objs);
}

/** A wrapped manual like ManualsLib produces: cover + TOC, N manual pages with footers, a back page. */
function wrappedManual(n = 3): Uint8Array {
  return pages([
    [`${PREAMBLE}BT /F1 24 Tf 100 700 Td (Quick Links) Tj ET\nQ\n`, ["https://www.manualslib.com/manual/1/x.html"]],
    [`${PREAMBLE}BT /F1 12 Tf 100 700 Td (Table of contents) Tj ET\nQ\n`, []],
    ...Array.from({ length: n }, (_, i): [string, string[]] => [`BT /F1 12 Tf 72 700 Td (Manual page ${i + 1}) Tj ET\n${FOOTER}`, ["http://www.manualslib.com/", "https://example.com/not-removed"]]),
    [`${PREAMBLE}BT /F1 12 Tf 100 700 Td (Other ManualsLib Projects) Tj ET\nQ\n`, ["https://www.manualslib.de/"]],
  ]);
}

test("the TypeScript constants match the wasm's", async () => {
  const m = await stripWasm();
  assert.equal(STRIP_TOOL, m.strip_tool());
  assert.equal(STRIP_VERSION, m.strip_version());
  assert.equal(STRIP_VERSION, "om-strip-rs/1");
});

test("wrapper pages, footers and manualslib links are removed", async () => {
  const input = wrappedManual(3);
  assert.deepEqual(await inspectPdf(input), { pages: 6, leading: 2, trailing: 1, footer_pages: 3, manualslib_links: 5 });
  const r = await stripPdf(input);
  assert.equal(r.changed, true);
  assert.equal(r.version, STRIP_VERSION);
  assert.deepEqual(await inspectPdf(r.bytes), { pages: 3, leading: 0, trailing: 0, footer_pages: 0, manualslib_links: 0 });
  assert.ok(Buffer.from(r.bytes).includes("example.com/not-removed"), "other links survive");
  assert.ok(r.log.some((l) => l.includes("2 leading and 1 trailing")), r.log.join("; "));
});

test("a clean PDF comes back unchanged with the same bytes", async () => {
  const bytes = pages([["BT /F1 12 Tf 72 700 Td (Nothing to strip) Tj ET\n", []]]);
  const r = await stripPdf(bytes);
  assert.equal(r.changed, false);
  assert.equal(r.bytes, bytes);
});

test("output is deterministic and stripping is idempotent", async () => {
  const input = wrappedManual(2);
  const a = await stripPdf(input);
  const b = await stripPdf(input);
  assert.equal(sha(a.bytes), sha(b.bytes));
  assert.equal((await stripPdf(a.bytes)).changed, false);
});

test("unreadable input throws", async () => {
  await assert.rejects(() => stripPdf(new Uint8Array([1, 2, 3, 4])), /unreadable PDF/);
  await assert.rejects(() => stripPdf(latin1("%PDF-1.4\nnot really a pdf")), /unreadable PDF/);
  assert.equal((await stripPdf(wrappedManual(1))).changed, true, "still usable");
});

test("a panic traps the instance; it is replaced and the next strip works", async () => {
  const quiet = console.error;
  const reported: string[] = [];
  console.error = (msg: string) => reported.push(msg); // the panic hook writes there
  try {
    await assert.rejects(() => _panicForTests(), /stripper fault/);
  } finally {
    console.error = quiet;
  }
  assert.match(reported.join("\n"), /deliberate panic for tests/);
  const r = await stripPdf(wrappedManual(1));
  assert.equal(r.changed, true);
  assert.deepEqual(await inspectPdf(r.bytes), { pages: 1, leading: 0, trailing: 0, footer_pages: 0, manualslib_links: 0 });
});
