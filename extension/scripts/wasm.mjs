// Builds the two WebAssembly modules from the Rust crates into vendor/ (not
// committed): openmanuals-wasm (openmanuals-core) and openmanuals-strip-wasm
// (the watermark stripper). Runs before build, test and typecheck; cargo only
// recompiles what changed, and wasm-bindgen runs only when its input is newer.
//
//   node scripts/wasm.mjs [core|strip] [--force]
//
// Needs Rust with the wasm32-unknown-unknown target and wasm-bindgen-cli at the
// same version as the wasm-bindgen crate in Cargo.lock.
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ext = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const root = resolve(ext, "..");
const args = process.argv.slice(2);
const force = args.includes("--force");
const only = args.find((a) => !a.startsWith("--"));

const MODULES = {
  core: { crate: "openmanuals-wasm", profile: "release", name: "openmanuals_wasm", out: "vendor/openmanuals-wasm", bindgen: [] },
  strip: { crate: "openmanuals-strip-wasm", profile: "wasm", name: "openmanuals_strip_wasm", out: "vendor/openmanuals-strip-wasm", bindgen: ["--experimental-reset-state-function"] },
};

function fail(msg) {
  console.error(`\nCan't build the WebAssembly modules: ${msg}\n`);
  process.exit(1);
}

function run(cmd, argv, env) {
  const r = spawnSync(cmd, argv, { cwd: root, stdio: "inherit", env: { ...process.env, ...env } });
  if (r.error) fail(`${cmd}: ${r.error.message}`);
  if (r.status !== 0) process.exit(r.status ?? 1);
}

function output(cmd, argv) {
  try {
    return execFileSync(cmd, argv, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
  } catch {
    return null;
  }
}

// Tools.
const lock = readFileSync(join(root, "Cargo.lock"), "utf8");
const want = /name = "wasm-bindgen"\nversion = "([^"]+)"/.exec(lock)?.[1];
if (!want) fail("no wasm-bindgen version in Cargo.lock.");
if (output("cargo", ["--version"]) === null) fail("cargo isn't installed. Install Rust from https://rustup.rs.");
const targets = output("rustup", ["target", "list", "--installed"]);
if (targets !== null && !targets.split("\n").includes("wasm32-unknown-unknown")) {
  fail("the wasm target is missing. Run:\n  rustup target add wasm32-unknown-unknown");
}
const have = output("wasm-bindgen", ["--version"])?.trim().split(/\s+/)[1];
if (have !== want) {
  fail(`${have ? `wasm-bindgen ${have} is installed, but Cargo.lock needs ${want}` : "wasm-bindgen isn't installed"}. Run:\n  cargo install wasm-bindgen-cli --version ${want} --locked`);
}

// No local paths in the modules, so they come out the same on any machine.
const cargoHome = process.env.CARGO_HOME || join(homedir(), ".cargo");
const env = { RUSTFLAGS: `--remap-path-prefix=${cargoHome}/registry/src=/cargo/registry/src --remap-path-prefix=${root}=/openmanuals` };

for (const [key, m] of Object.entries(MODULES)) {
  if (only && only !== key) continue;
  run("cargo", ["build", "-p", m.crate, "--target", "wasm32-unknown-unknown", "--profile", m.profile], env);
  const input = join(root, "target/wasm32-unknown-unknown", m.profile, `${m.name}.wasm`);
  const made = join(ext, m.out, `${m.name}_bg.wasm`);
  if (!force && existsSync(made) && statSync(made).mtimeMs >= statSync(input).mtimeMs) continue;
  run("wasm-bindgen", ["--target", "web", ...m.bindgen, "--out-dir", join(ext, m.out), "--out-name", m.name, input]);
}
