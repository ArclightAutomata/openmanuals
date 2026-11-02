// End to end: a Manualzz download is preserved. The download page's
// "Download PDF" link calls download_source(), which submits a form (POST
// /download/check with the captcha token) that redirects to the PDF; the
// extension posts that form itself, hands the file to the user and uploads it.
// Not part of `npm test`.
//
//   cd extension && npm run build && node test/manualzz-e2e.mjs [--headful] [--chrome /path/to/chrome]
//
// Nothing leaves this machine: Chrome resolves manualzz.com, s1p.manualzz.com,
// archive.org and s3.us.archive.org to a local HTTPS mock (self-signed,
// certificate errors ignored). The captcha is mocked as already solved.
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
const work = mkdtempSync(join(process.env.SCRATCH ?? tmpdir(), "om-mzz-e2e-"));
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

function makePdf() {
  const text = "BT /F1 18 Tf 20 100 Td (Hitachi CM721F test) Tj ET";
  const objs = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
    `<< /Length ${text.length} >>\nstream\n${text}\nendstream`,
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
  ];
  let out = "%PDF-1.4\n";
  const offs = [];
  objs.forEach((o, i) => { offs.push(out.length); out += `${i + 1} 0 obj\n${o}\nendobj\n`; });
  const xref = out.length;
  out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n` + offs.map((o) => `${String(o).padStart(10, "0")} 00000 n \n`).join("");
  out += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(out, "latin1");
}
const PDF = makePdf();

execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=om-e2e",
  "-keyout", join(work, "key.pem"), "-out", join(work, "cert.pem")], { stdio: "ignore" });
const ID = "6961161";
const SLUG = "hitachi-cm721f---19--crt-display-user-manual";
const DOC = `/doc/${ID}/${SLUG}`;
const FILE = `/store/data/00${ID}.pdf`;
const TOKEN = "captcha-token-" + "x".repeat(40);
const seen = [];
const puts = [];
const posts = [];
const server = createServer({ key: readFileSync(join(work, "key.pem")), cert: readFileSync(join(work, "cert.pem")) }, (req, res) => {
  const host = (req.headers.host ?? "").split(":")[0];
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    const body = Buffer.concat(chunks);
    seen.push(`${req.method} ${host}${req.url}`);
    const html = (s) => { res.writeHead(200, { "content-type": "text/html" }); res.end(s); };
    const json = (v) => { res.writeHead(200, { "content-type": "application/json", "access-control-allow-origin": "*" }); res.end(JSON.stringify(v)); };
    if (host === "manualzz.com" && req.url === DOC) {
      return html(`<!doctype html><title>Hitachi CM721F - 19" CRT Display User manual | Manualzz</title>
        <ol class="breadcrumb"><li><a href="/catalog/computers">Computers &amp; electronics</a></li><li><a href="/brand/285687">Hitachi</a></li>
        <li><a href="/manual/Hitachi/CM721F%2520-%252019%2522%2520CRT%2520Display">CM721F - 19" CRT Display</a></li><li><a href="${DOC}">User manual</a></li></ol>
        <h1>Hitachi CM721F - 19" CRT Display User manual</h1><a href="/download/${ID}">Download</a>`);
    }
    if (host === "manualzz.com" && req.url === `/download/${ID}`) {
      // As on the site: the link's onclick submits the form (target _blank); the captcha left its token in the textarea.
      return html(`<!doctype html><title>Hitachi CM721F - 19" CRT Display User manual | Manualzz</title>
        <h1>Hitachi CM721F - 19" CRT Display User manual</h1><a href="${DOC}">Back to online viewer</a>
        <form id="download" method="post" action="/download/check" target="_blank">
          <input type="hidden" name="documentId" value="${ID}"><input type="hidden" name="format" id="format" value="">
          <textarea name="g-recaptcha-response" style="display:none">${TOKEN}</textarea>
        </form>
        <a class="btn" href="javascript:" onclick="if (!window.__cfRLUnblockHandlers) return false; download_source()">Download PDF <small>1 KB</small></a>
        <script>window.__cfRLUnblockHandlers = true; window.siteDownloads = 0;
          function download_source(format) { window.siteDownloads++; document.getElementById("format").value = format || "pdf"; document.getElementById("download").submit(); }</script>`);
    }
    if (host === "manualzz.com" && req.method === "POST" && req.url === "/download/check") {
      posts.push(Object.fromEntries(new URLSearchParams(body.toString())));
      res.writeHead(302, { location: `https://s1p.manualzz.com${FILE}?sig=abc&expires=1` });
      return res.end();
    }
    if (host === "s1p.manualzz.com" && req.url.startsWith(FILE)) {
      const origin = req.headers.origin;
      res.writeHead(200, { "content-type": "application/pdf", "content-length": PDF.length, ...(origin ? { "access-control-allow-origin": origin, "access-control-allow-credentials": "true" } : {}) });
      return res.end(PDF);
    }
    if (host === "archive.org" && req.url.startsWith("/services/check_identifier.php")) return json({ type: "success", code: "available" });
    if (host === "archive.org" && req.url.startsWith("/metadata/")) return json({});
    if (host === "archive.org" && req.url.startsWith("/advancedsearch.php")) return json({ response: { docs: [] } });
    if (host === "s3.us.archive.org" && req.method === "PUT") { puts.push({ url: req.url, headers: req.headers, body }); res.writeHead(200); return res.end(); }
    res.writeHead(404); res.end();
  });
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const port = server.address().port;
const hosts = ["manualzz.com", "s1p.manualzz.com", "archive.org", "s3.us.archive.org"];

const downloads = join(work, "downloads");
const b = await Browser.launch({
  chrome, headless, extension: dist,
  extraArgs: [`--host-resolver-rules=${hosts.map((h) => `MAP ${h} 127.0.0.1:${port}`).join(",")}`, "--ignore-certificate-errors"],
});
let ok = false;
try {
  await b.send("Browser.setDownloadBehavior", { behavior: "allow", downloadPath: downloads });
  const opts = await b.newPage(`chrome-extension://${b.extensionId}/options.html`);
  await until("options page", () => opts.eval(`document.readyState === "complete"`));
  step("uploads on, archive.org keys saved, no OpenManuals server");
  await opts.eval(`Promise.all([chrome.storage.sync.set({ apiBase: "", uploadEnabled: true, legacyCheck: true }), chrome.storage.local.set({ iaAccessKey: "AK", iaSecretKey: "SK" })])`);

  step("the manual page: banner, and the breadcrumb's brand and model kept for the tab");
  const page = await b.newPage(`https://manualzz.com${DOC}`);
  await until("banner on the manual page", () => page.eval(`!!document.querySelector(".openmanuals-banner")`));
  const kept = await until("breadcrumb kept", () => page.eval(`sessionStorage.getItem("om-manualzz-products:${ID}")`));
  assert.deepEqual(JSON.parse(kept), [{ brand: "Hitachi", model: "CM721F" }]);

  step("the download page, captcha solved: click Download PDF");
  await page.navigate(`https://manualzz.com/download/${ID}`, `document.readyState === "complete"`);
  await until("content script hooked the link", () => page.eval(`document.querySelector('a[onclick*="download_source"]')?.dataset.omHooked === "1"`));
  await page.click('a[onclick*="download_source"]');

  step("the extension posted the form itself; the site's handler didn't run");
  await until("form posted", async () => posts.length > 0 || null);
  assert.deepEqual(posts[0], { documentId: ID, format: "pdf", "g-recaptcha-response": TOKEN });
  assert.equal(await page.eval(`window.siteDownloads`), 0);

  step("the user's copy is saved, and the same bytes went to (mock) archive.org");
  const saved = await until("download saved", async () => readdirSync(downloads).find((f) => f.endsWith(".pdf")) ?? null);
  assert.equal(saved, `${SLUG}.pdf`);
  assert.ok(readFileSync(join(downloads, saved)).equals(PDF));
  const put = await until("S3 PUT", async () => puts.find((p) => /\.pdf$/i.test(p.url.split("?")[0])) ?? null, 30000);
  assert.ok(put.body.equals(PDF));
  assert.ok(put.url.startsWith("/openmanuals-"), put.url);
  const meta = Object.fromEntries(Object.entries(put.headers).filter(([k]) => k.startsWith("x-archive-meta")));
  console.log(meta);
  assert.ok(Object.values(meta).some((v) => String(v).includes(`https://manualzz.com${DOC}`)), "source is the manual page");
  assert.equal(posts.length, 1, "the form was posted once");
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
