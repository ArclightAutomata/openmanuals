// End to end: FreeServiceManuals.info downloads are preserved, stamps
// stripped. Every kind of page ends the same way: the site's script appends
// <a id="captchalink" href="<file>"> and clicks it. Books and datasheet pages
// have no captcha (the URL is in the script); a service-manual page posts the
// captcha code to /<lang>/servicemanuals/decaptcha/ and gets the URL back as
// JSON.
// The extension catches that click, hands the file to the user and uploads
// the stripped copy. Not part of `npm test`.
//
//   cd extension && npm run build && node test/freeservicemanuals-e2e.mjs [--headful] [--chrome /path/to/chrome]
//
// Nothing leaves this machine: Chrome resolves freeservicemanuals.info,
// archive.org and s3.us.archive.org to a local HTTPS mock (self-signed,
// certificate errors ignored).
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
const work = mkdtempSync(join(process.env.SCRATCH ?? tmpdir(), "om-fsm-e2e-"));
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

/** A one-page PDF stamped the way the site stamps: Acrobat Header & Footer pieces, one naming the site. */
function makePdf(label) {
  const settings = "<HeaderFooterSettings><Header><Left>www.freeservicemanuals.info</Left></Header><Footer><Right>Not for sale!</Right></Footer></HeaderFooterSettings>";
  const piece = (text) => {
    const s = `BT /F1 9 Tf 1 0 0 rg 0 -7 Td (${text}) Tj ET`;
    return `<< /Type /XObject /Subtype /Form /BBox [0 -9 150 0] /Resources << /Font << /F1 5 0 R >> >> /PieceInfo << /ADBE_CompoundType << /Private /Header /LastModified (D:20251009150908+02'00') /DocSettings 8 0 R >> >> /Length ${s.length} >>\nstream\n${s}\nendstream`;
  };
  const text = `BT /F1 18 Tf 20 100 Td (${label}) Tj ET q 1 0 0 1 20 190 cm /Fm0 Do Q q 1 0 0 1 20 10 cm /Fm1 Do Q`;
  const objs = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> /XObject << /Fm0 6 0 R /Fm1 7 0 R >> >> >>",
    `<< /Length ${text.length} >>\nstream\n${text}\nendstream`,
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    piece("www.freeservicemanuals.info"),
    piece("Not for sale!"),
    `<< /Length ${settings.length} >>\nstream\n${settings}\nendstream`,
  ];
  let out = "%PDF-1.4\n";
  const offs = [];
  objs.forEach((o, i) => { offs.push(out.length); out += `${i + 1} 0 obj\n${o}\nendobj\n`; });
  const xref = out.length;
  out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n` + offs.map((o) => `${String(o).padStart(10, "0")} 00000 n \n`).join("");
  out += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(out, "latin1");
}
const BOOK_PDF = makePdf("DPS-375 test");
const SM_PDF = makePdf("Philips 14PV100 test");
const DS_PDF = makePdf("1N4148 test");

execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=om-e2e",
  "-keyout", join(work, "key.pem"), "-out", join(work, "cert.pem")], { stdio: "ignore" });

const BOOK = "/en/bookcats/DIGITAL%20PROCESSING%20SYSTEMS/TBC%20FRAMESTORE/DPS-375/";
const BOOK_FILE = "/bookcats/download/dps-375.pdf";
const SM = "/en/servicemanuals/viewmanual/Philips/14PV100/51TVB61/37TR216/DELTA2000/";
const SM_FILE = "/media/sm/14pv100.pdf"; // the real decaptcha answer's shape is unknown; any URL works
const CODE = "k7q2x";
const DS = "/nl/tubedata/1N4148_3/"; // Dutch, to cover the language prefix
const DS_FILE = "/media//tubedata/1N4148_3.pdf";

// The site's page: a table whose model number opens the (captcha) download box.
const page = ({ title, rows, start }) => `<!doctype html><title>${title} Service Manual PDF Free Download</title>
  <div class="table-responsive"><table class="table">${rows}</table></div>
  <script>
    window.siteClicks = 0;
    function show_captcha(sel, e) { document.querySelector(sel).style.display = "none"; document.getElementById("captcha").style.display = ""; e.stopPropagation();
      document.getElementById("download-button").onclick = start_download; }
    function go(url) { window.siteClicks++; const a = document.createElement("a"); a.id = "captchalink"; a.href = url; a.innerHTML = "&nbsp;"; document.body.append(a); a.click(); }
    ${start}
  </script>`;
const typeCell = (model, captcha) => `<a class="typedownload" href="javascript:;" onclick="show_captcha('.typedownload', event)">${model}</a>
  <input type="hidden" name="csrfmiddlewaretoken" value="tok123" />
  <span id="captcha" style="display: none">${captcha ? `<img src="/media/captchas/x-captcha.png" /><input class="form-control captcha-input" />` : ""}
  <button type="button" id="download-button">Download ${model}</button></span>`;

const seen = [];
const puts = [];
const decaptcha = [];
const fileGets = [];
const server = createServer({ key: readFileSync(join(work, "key.pem")), cert: readFileSync(join(work, "cert.pem")) }, (req, res) => {
  const host = (req.headers.host ?? "").split(":")[0];
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    const body = Buffer.concat(chunks);
    seen.push(`${req.method} ${host}${req.url}`);
    const html = (s) => { res.writeHead(200, { "content-type": "text/html; charset=utf-8" }); res.end(s); };
    const json = (v) => { res.writeHead(200, { "content-type": "application/json", "access-control-allow-origin": "*" }); res.end(JSON.stringify(v)); };
    const pdf = (b, name) => { fileGets.push(req.url); res.writeHead(200, { "content-type": "application/pdf", "content-length": b.length, "content-disposition": `attachment; filename=${name}` }); res.end(b); };
    if (host === "freeservicemanuals.info" && req.url === BOOK) {
      return html(page({
        title: "DPS-375 TBC FRAMESTORE DIGITAL PROCESSING SYSTEMS",
        rows: `<tr class="row1"><td>Title</td><td>${typeCell("DPS-375", false)}</td></tr>
          <tr class="row2"><td>Author</td><td>TBC FRAMESTORE</td></tr><tr class="row1"><td>Publisher</td><td>DIGITAL PROCESSING SYSTEMS</td></tr><tr><td>Year</td><td></td></tr>`,
        start: `function start_download() { go("${BOOK_FILE}"); }`,
      }));
    }
    if (host === "freeservicemanuals.info" && req.url === SM) {
      return html(page({
        title: "Philips 14PV100 51TVB61 37TR216 DELTA 2000",
        rows: `<tr class="row1"><td><b>Brand</b></td><td>Philips</td></tr><tr class="row2"><td><b>Type<br>number</b></td><td>${typeCell("14PV100", true)}</td></tr>
          <tr class="row1"><td><b>This manual also covers</b></td><td>51TVB61<br>37TR216<br>DELTA 2000<br></td></tr><tr><td><b>Product</b></td><td>TV/VCR COMBI</td></tr>`,
        start: `function start_download() {
          const body = new URLSearchParams({ csrfmiddlewaretoken: "tok123", captcha_code: document.querySelector("#captcha .captcha-input").value, encrypted_url: "61c6" });
          fetch("/en/servicemanuals/decaptcha/", { method: "POST", body }).then((r) => r.json()).then((d) => { if (d.url) go(d.url); });
        }`,
      }));
    }
    if (host === "freeservicemanuals.info" && req.url === DS) {
      return html(page({
        title: "1N4148_3 Datasheet PDF Download",
        rows: `<tr class="downloadwidth"><th colspan="2">Data Sheet Information</th></tr><tr class="row1"><td>Type a</td><td>${typeCell("1N4148_3", false)}</td></tr>
          <tr class="row2"><td>Type b</td><td></td></tr><tr class="row1"><td>Type c</td><td></td></tr><tr class="row2"><td>Product</td><td>Semi conducter</td></tr>`,
        start: `function start_download() { go("${DS_FILE}"); }`,
      }).replace(" Service Manual PDF Free Download</title>", "</title>"));
    }
    if (host === "freeservicemanuals.info" && req.method === "POST" && req.url === "/en/servicemanuals/decaptcha/") {
      const form = Object.fromEntries(new URLSearchParams(body.toString()));
      decaptcha.push(form);
      return json({ url: form.captcha_code === CODE ? SM_FILE : "" });
    }
    if (host === "freeservicemanuals.info" && req.url === BOOK_FILE) return pdf(BOOK_PDF, "dps-375.pdf");
    if (host === "freeservicemanuals.info" && req.url === SM_FILE) return pdf(SM_PDF, "14pv100.pdf");
    if (host === "freeservicemanuals.info" && req.url === DS_FILE) return pdf(DS_PDF, "1N4148_3.pdf");
    if (host === "archive.org" && req.url.startsWith("/services/check_identifier.php")) return json({ type: "success", code: "available" });
    if (host === "archive.org" && req.url.startsWith("/metadata/")) return json({});
    if (host === "archive.org" && req.url.startsWith("/advancedsearch.php")) return json({ response: { docs: [] } });
    if (host === "s3.us.archive.org" && req.method === "PUT") { puts.push({ url: req.url, headers: req.headers, body }); res.writeHead(200); return res.end(); }
    res.writeHead(404); res.end();
  });
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const port = server.address().port;
const hosts = ["freeservicemanuals.info", "archive.org", "s3.us.archive.org"];

const downloads = join(work, "downloads");
const b = await Browser.launch({
  chrome, headless, extension: dist,
  extraArgs: [`--host-resolver-rules=${hosts.map((h) => `MAP ${h} 127.0.0.1:${port}`).join(",")}`, "--ignore-certificate-errors"],
});

const metaOf = (put) => Object.fromEntries(Object.entries(put.headers).filter(([k]) => k.startsWith("x-archive-meta")));
async function checkPreserved({ tab, filename, original, sourcePage, models, title }) {
  const saved = await until(`${filename} saved`, async () => readdirSync(downloads).find((f) => f === filename) ?? null);
  assert.ok(readFileSync(join(downloads, saved)).equals(original), "the user gets the site's file as it is");
  const put = await until(`S3 PUT of ${filename}`, async () => puts.find((p) => /\.pdf$/i.test(p.url.split("?")[0]) && !p.done) ?? null, 30000);
  put.done = true;
  assert.ok(put.url.startsWith("/openmanuals-"), put.url);
  assert.ok(!put.body.equals(original), "the uploaded copy was stripped");
  assert.ok(!put.body.includes("freeservicemanuals"), "no site address left");
  assert.ok(!put.body.includes("Not for sale"), "the stamping's other line went too");
  assert.ok(put.body.includes("test"), "the manual's own text stays");
  const meta = metaOf(put);
  console.log(meta);
  const values = Object.values(meta).map(String);
  assert.ok(values.some((v) => v.includes(`https://freeservicemanuals.info${sourcePage}`)), "source is the manual page");
  for (const m of models) assert.ok(values.some((v) => v.includes(m)), `metadata names ${m}`);
  if (title) assert.ok(values.includes(title), `title is ${title}`);
  const banner = await until("banner says done", () => tab.eval(`(() => { const b = document.querySelector(".openmanuals-banner"); return b && /om-done/.test(b.className) ? b.textContent : null; })()`), 30000);
  console.log({ banner: banner.trim().slice(0, 120) });
}

let ok = false;
try {
  await b.send("Browser.setDownloadBehavior", { behavior: "allow", downloadPath: downloads });
  const opts = await b.newPage(`chrome-extension://${b.extensionId}/options.html`);
  await until("options page", () => opts.eval(`document.readyState === "complete"`));
  step("uploads on, archive.org keys saved, no OpenManuals server");
  await opts.eval(`Promise.all([chrome.storage.sync.set({ apiBase: "", uploadEnabled: true, legacyCheck: true }), chrome.storage.local.set({ iaAccessKey: "AK", iaSecretKey: "SK" })])`);

  step("a books page (no captcha): click the model number, then Download");
  const tab = await b.newPage(`https://freeservicemanuals.info${BOOK}`);
  await until("banner on the books page", () => tab.eval(`!!document.querySelector(".openmanuals-banner")`));
  await tab.click("a.typedownload");
  await tab.click("#download-button");
  await until("the site's script clicked its link", () => tab.eval(`window.siteClicks === 1`));
  await checkPreserved({ tab, filename: "dps-375.pdf", original: BOOK_PDF, sourcePage: BOOK, models: ["DPS-375", "DIGITAL PROCESSING SYSTEMS"], title: "DPS-375 TBC FRAMESTORE DIGITAL PROCESSING SYSTEMS" });
  assert.equal(fileGets.filter((u) => u === BOOK_FILE).length, 1, "the file was fetched once");

  step("a service-manual page: wrong captcha code does nothing, the right one downloads");
  await tab.navigate(`https://freeservicemanuals.info${SM}`, `document.readyState === "complete"`);
  await until("banner on the service-manual page", () => tab.eval(`!!document.querySelector(".openmanuals-banner")`));
  await tab.click("a.typedownload");
  await tab.eval(`document.querySelector("#captcha .captcha-input").value = "wrong"`);
  await tab.click("#download-button");
  await until("decaptcha posted", async () => decaptcha.length === 1 || null);
  await wait(500);
  assert.equal(await tab.eval(`window.siteClicks`), 0);
  await tab.eval(`document.querySelector("#captcha .captcha-input").value = "${CODE}"`);
  await tab.click("#download-button");
  await until("decaptcha posted again", async () => decaptcha.length === 2 || null);
  assert.equal(decaptcha[1].captcha_code, CODE);
  await checkPreserved({ tab, filename: "14pv100.pdf", original: SM_PDF, sourcePage: SM, models: ["14PV100", "51TVB61", "DELTA 2000", "Philips"] });
  assert.equal(fileGets.filter((u) => u === SM_FILE).length, 1, "the file was fetched once");

  step("a datasheet page, in Dutch (no captcha)");
  await tab.navigate(`https://freeservicemanuals.info${DS}`, `document.readyState === "complete"`);
  await until("banner on the datasheet page", () => tab.eval(`!!document.querySelector(".openmanuals-banner")`));
  await tab.click("a.typedownload");
  await tab.click("#download-button");
  await checkPreserved({ tab, filename: "1N4148_3.pdf", original: DS_PDF, sourcePage: DS, models: [], title: "1N4148_3 datasheet" });
  assert.equal(fileGets.filter((u) => u === DS_FILE).length, 1, "the file was fetched once");
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
