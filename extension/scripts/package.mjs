// Builds the Chrome Web Store zip: release/openmanuals-chrome-<version>.zip.
// Run `npm run package` (it builds first). The store copy drops the
// localhost/127.0.0.1 host permissions, which exist only for a local server
// and would otherwise show up in the install prompt.
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFileSync } from "node:child_process";

const root = resolve(import.meta.dirname, "..");
const dist = join(root, "dist");
if (!existsSync(join(dist, "manifest.json"))) throw new Error("dist/ is missing; run npm run build");

const stage = mkdtempSync(join(tmpdir(), "openmanuals-ext-"));
try {
  // Source maps stay out: they're most of the size and not needed by users.
  cpSync(dist, stage, { recursive: true, filter: (src) => !src.endsWith(".map") });
  for (const f of readdirSync(stage).filter((f) => f.endsWith(".js"))) {
    const p = join(stage, f);
    writeFileSync(p, readFileSync(p, "utf8").replace(/\n\/\/# sourceMappingURL=\S+\s*$/, "\n"));
  }
  const path = join(stage, "manifest.json");
  const m = JSON.parse(readFileSync(path, "utf8"));
  const local = (h) => /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?\//.test(h);
  m.host_permissions = m.host_permissions.filter((h) => !local(h));
  writeFileSync(path, JSON.stringify(m, null, 2) + "\n");

  const outDir = join(root, "release");
  mkdirSync(outDir, { recursive: true });
  const out = join(outDir, `openmanuals-chrome-${m.version}.zip`);
  rmSync(out, { force: true });
  // -X: no extra file attributes, so the same input gives the same zip.
  execFileSync("zip", ["-qrX", out, "."], { cwd: stage, stdio: "inherit" });
  console.log(`==> ${out}`);
} finally {
  rmSync(stage, { recursive: true, force: true });
}
