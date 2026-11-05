// esbuild: bundles the TypeScript entry points into dist/ and copies the
// static files (manifest, icons, HTML, CSS, wasm) next to them. Load dist/ as
// the unpacked extension.
import * as esbuild from "esbuild";
import { cpSync, mkdirSync, rmSync, readFileSync, writeFileSync } from "node:fs";

const watch = process.argv.includes("--watch");
const outdir = "dist";
rmSync(outdir, { recursive: true, force: true });
mkdirSync(outdir, { recursive: true });

// doipjs's service-provider definitions import its Node fetchers (dns, xmpp,
// irc…); the extension fetches proofs itself, so point that import at a stub.
const doipStub = {
  name: "doip-fetcher-stub",
  setup(build) {
    build.onResolve({ filter: /fetcher\/index\.js$/ }, (args) => (args.importer.includes("doipjs") ? { path: new URL("src/identity/doip-fetcher-stub.ts", import.meta.url).pathname } : undefined));
  },
};
// One id per build run, so a page can tell it isn't talking to the same build's service worker.
const BUILD_ID = Date.now().toString(36);
const common = { bundle: true, sourcemap: true, target: "chrome120", logLevel: "info", legalComments: "none", plugins: [doipStub], define: { __OM_BUILD__: JSON.stringify(BUILD_ID) } };

// Content scripts: classic scripts (no import.meta, no top-level await).
const content = esbuild.context({
  ...common, format: "iife",
  entryPoints: { "content-manualslib": "src/content/manualslib.ts", "content-elektrotanya": "src/content/elektrotanya.ts", "content-manualzz": "src/content/manualzz.ts", "content-freeservicemanuals": "src/content/freeservicemanuals.ts", "content-site": "src/content/site.ts" },
  outdir,
});
// Service worker, pages and the worker: ES modules.
const modules = esbuild.context({
  ...common, format: "esm",
  entryPoints: {
    background: "src/background/index.ts",
    popup: "src/popup/popup.ts",
    options: "src/options/options.ts",
    confirm: "src/confirm/confirm.ts",
    panel: "src/panel/panel.ts",
    offscreen: "src/offscreen/offscreen.ts",
    "strip-worker": "src/offscreen/strip-worker.ts",
    "rangedb-worker": "src/rangedb/worker.ts",
  },
  outdir,
  define: { ...common.define, "process.env.NODE_ENV": '"production"' },
});

function copyStatic() {
  cpSync("manifest.json", `${outdir}/manifest.json`);
  cpSync("icons", `${outdir}/icons`, { recursive: true });
  cpSync("../brand/logo.svg", `${outdir}/icons/logo.svg`);
  cpSync("content.css", `${outdir}/content.css`);
  cpSync("content-site.css", `${outdir}/content-site.css`);
  cpSync("src/confirm/confirm.html", `${outdir}/confirm.html`);
  cpSync("src/panel/panel.html", `${outdir}/panel.html`);
  cpSync("src/popup/popup.html", `${outdir}/popup.html`);
  cpSync("src/options/options.html", `${outdir}/options.html`);
  cpSync("src/offscreen/offscreen.html", `${outdir}/offscreen.html`);
  cpSync("vendor/openmanuals-wasm/openmanuals_wasm_bg.wasm", `${outdir}/openmanuals_wasm_bg.wasm`);
  cpSync("vendor/openmanuals-strip-wasm/openmanuals_strip_wasm_bg.wasm", `${outdir}/openmanuals_strip_wasm_bg.wasm`);
  cpSync("node_modules/@sqlite.org/sqlite-wasm/dist/sqlite3.wasm", `${outdir}/sqlite3.wasm`);
  const pkg = JSON.parse(readFileSync("package.json", "utf8"));
  const manifest = JSON.parse(readFileSync(`${outdir}/manifest.json`, "utf8"));
  manifest.version = pkg.version;
  writeFileSync(`${outdir}/manifest.json`, JSON.stringify(manifest, null, 2));
}

const [c, m] = await Promise.all([content, modules]);
if (watch) {
  copyStatic();
  await Promise.all([c.watch(), m.watch()]);
  console.log("watching…");
} else {
  await Promise.all([c.rebuild(), m.rebuild()]);
  await Promise.all([c.dispose(), m.dispose()]);
  copyStatic();
  console.log("built dist/");
}
