// End to end: a ManualsLib download that skips the page's click handler
// (Ctrl-click here; "Save link as…" and middle-click reach Chrome the same
// way, as a plain download) is still preserved. Not part of `npm test`.
//
//   cd extension && npm run build && node test/download-e2e.mjs [--headful] [--chrome /path/to/chrome]
//
// Nothing leaves this machine: Chrome resolves www/data2.manualslib.com,
// archive.org and s3.us.archive.org to a local HTTPS mock (self-signed,
// certificate errors ignored). The mock serves a ManualsLib download page and
// its PDF, says the item doesn't exist on archive.org, and records the S3 PUT.
import { Browser } from "./cdp.mjs";
import { createServer } from "node:https";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";

const arg = (name, dflt) => { const i = process.argv.indexOf(name); return i > 0 ? process.argv[i + 1] : dflt; };
const headless = !process.argv.includes("--headful");
const chrome = arg("--chrome", "google-chrome");
const dist = fileURLToPath(new URL("../dist/", import.meta.url));
const work = mkdtempSync(join(process.env.SCRATCH ?? tmpdir(), "om-dl-e2e-"));
const step = (s) => console.log(`\n== ${s}`);
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(what, fn, ms = 20000) {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn().catch(() => null);
    if (v) return v;
    if (Date.now() > end) throw new Error(`timed out: ${what}`);
    await wait(200);
  }
}

// ---- a small PDF ----------------------------------------------------------------------------
function makePdf() {
  const objs = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
    null,
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
  ];
  const text = "BT /F1 18 Tf 20 100 Td (Toshiba 27D46 test) Tj ET";
  objs[3] = `<< /Length ${text.length} >>\nstream\n${text}\nendstream`;
  let out = "%PDF-1.4\n";
  const offs = [];
  objs.forEach((o, i) => { offs.push(out.length); out += `${i + 1} 0 obj\n${o}\nendobj\n`; });
  const xref = out.length;
  out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n` + offs.map((o) => `${String(o).padStart(10, "0")} 00000 n \n`).join("");
  out += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(out, "latin1");
}
const PDF = makePdf();

// ---- the mock ------------------------------------------------------------------------------
execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=om-e2e",
  "-keyout", join(work, "key.pem"), "-out", join(work, "cert.pem")], { stdio: "ignore" });
const FILE_PATH = "/cpdf/4/18/1722/1a4ee2.pdf?take=binary";
const PAGE_PATH = "/download/172144/Toshiba-27d46.html";
const seen = [];
const puts = [];
const server = createServer({ key: readFileSync(join(work, "key.pem")), cert: readFileSync(join(work, "cert.pem")) }, (req, res) => {
  const host = (req.headers.host ?? "").split(":")[0];
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    const body = Buffer.concat(chunks);
    seen.push(`${req.method} ${host}${req.url}`);
    const json = (v) => { res.writeHead(200, { "content-type": "application/json", "access-control-allow-origin": "*" }); res.end(JSON.stringify(v)); };
    if (host === "www.manualslib.com" && req.url === PAGE_PATH) {
      res.writeHead(200, { "content-type": "text/html" });
      return res.end(`<!doctype html><title>Download Toshiba 27D46 Owner's Manual | ManualsLib</title>
        <h1>Download Toshiba 27D46 Owner's Manual</h1>
        <p><a class="download-url" href="https://data2.manualslib.com${FILE_PATH}">Download</a></p>`);
    }
    if (host === "data2.manualslib.com" && req.url === FILE_PATH) {
      res.writeHead(200, { "content-type": "binary/octet-stream", "content-disposition": 'attachment; filename="1a4ee2.pdf"', "content-length": PDF.length });
      return res.end(PDF);
    }
    if (host === "archive.org" && req.url.startsWith("/services/check_identifier.php")) return json({ type: "success", code: "available" });
    if (host === "archive.org" && req.url.startsWith("/metadata/")) return json({});
    if (host === "archive.org" && req.url.startsWith("/advancedsearch.php")) return json({ response: { docs: [] } });
    if (host === "s3.us.archive.org" && req.method === "PUT") { puts.push({ url: req.url, body }); res.writeHead(200); return res.end(); }
    res.writeHead(404); res.end();
  });
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const port = server.address().port;
const hosts = ["www.manualslib.com", "data2.manualslib.com", "archive.org", "s3.us.archive.org"];

const downloads = join(work, "downloads");
const b = await Browser.launch({
  chrome, headless, extension: dist,
  extraArgs: [`--host-resolver-rules=${hosts.map((h) => `MAP ${h} 127.0.0.1:${port}`).join(",")}`, "--ignore-certificate-errors"],
});
let ok = false;
try {
  await b.send("Browser.setDownloadBehavior", { behavior: "allow", downloadPath: downloads });
  const OPTIONS = `chrome-extension://${b.extensionId}/options.html`;
  const opts = await b.newPage(OPTIONS);
  await until("options page", () => opts.eval(`document.readyState === "complete"`));
  step("uploads on, archive.org keys saved, no OpenManuals server");
  await opts.eval(`Promise.all([chrome.storage.sync.set({ apiBase: "", uploadEnabled: true }), chrome.storage.local.set({ iaAccessKey: "AK", iaSecretKey: "SK" })])`);
  assert.equal(await opts.eval(`chrome.permissions.contains({ permissions: ["downloads"] })`), true);

  step("open the ManualsLib download page");
  const page = await b.newPage(`https://www.manualslib.com${PAGE_PATH}`);
  await until("content script hooked the link", () => page.eval(`document.querySelector("a.download-url")?.dataset.omHooked === "1"`));
  await until("lookup done (banner shown)", () => page.eval(`!!document.querySelector(".openmanuals-banner")`));

  step("Ctrl-click the link: Chrome downloads it itself, past the page's click handler");
  const at = await page.eval(`(() => { const r = document.querySelector("a.download-url").getBoundingClientRect(); return { x: r.x + r.width / 2, y: r.y + r.height / 2 }; })()`);
  for (const type of ["mousePressed", "mouseReleased"]) await page.send("Input.dispatchMouseEvent", { type, x: at.x, y: at.y, button: "left", clickCount: 1, modifiers: 2 });
  await until("the user's own copy is saved", async () => readdirSync(downloads).some((f) => f.endsWith(".pdf")) || null);

  step("the page fetched it again and uploaded it to (mock) archive.org");
  const put = await until("S3 PUT", async () => puts.find((p) => /\.pdf$/i.test(p.url.split("?")[0])) ?? null, 30000);
  console.log({ put: put.url, bytes: put.body.length });
  assert.ok(put.body.subarray(0, 5).toString() === "%PDF-");
  assert.ok(put.url.startsWith("/openmanuals-"), put.url);
  const banner = await until("banner says done", () => page.eval(`(() => { const b = document.querySelector(".openmanuals-banner"); return b && /om-done/.test(b.className) ? b.textContent : null; })()`));
  console.log({ banner: banner.trim().slice(0, 120) });
  ok = true;
} finally {
  if (!ok) console.log("requests seen:", seen);
  await b.close();
  server.close();
  if (ok) rmSync(work, { recursive: true, force: true });
  else console.log("kept", work);
}
console.log(ok ? "PASS" : "FAIL");
process.exit(ok ? 0 : 1);
