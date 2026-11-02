// Minimal Chrome DevTools Protocol client over --remote-debugging-pipe, no
// dependencies. Branded Chrome ignores
// --load-extension, so extensions are loaded with CDP Extensions.loadUnpacked,
// which needs --remote-debugging-pipe and --enable-unsafe-extension-debugging.
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export class Browser {
  static async launch({ chrome, headless = true, extension, extraArgs = [] }) {
    const userDataDir = mkdtempSync(join(process.env.SCRATCH ?? tmpdir(), "om-e2e-profile-"));
    const args = [
      `--user-data-dir=${userDataDir}`, "--remote-debugging-pipe", "--enable-unsafe-extension-debugging",
      "--no-first-run", "--no-default-browser-check", "--disable-gpu", "--password-store=basic",
      ...(headless ? ["--headless=new"] : []), ...extraArgs, "about:blank",
    ];
    const proc = spawn(chrome, args, { stdio: ["ignore", "ignore", "pipe", "pipe", "pipe"] });
    const b = new Browser(proc, userDataDir);
    proc.stderr.on("data", () => {});
    await b.send("Target.setDiscoverTargets", { discover: true });
    if (extension) b.extensionId = await b.loadExtension(extension);
    return b;
  }

  constructor(proc, userDataDir) {
    Object.assign(this, { proc, userDataDir, id: 0, pending: new Map(), targets: new Map(), listeners: [] });
    this.out = proc.stdio[3];
    let buf = "";
    proc.stdio[4].on("data", (d) => {
      buf += d.toString();
      let i;
      while ((i = buf.indexOf("\0")) >= 0) {
        const msg = JSON.parse(buf.slice(0, i));
        buf = buf.slice(i + 1);
        if (msg.id && this.pending.has(msg.id)) {
          const { resolve, reject, method } = this.pending.get(msg.id);
          this.pending.delete(msg.id);
          msg.error ? reject(new Error(`${method}: ${msg.error.message}`)) : resolve(msg.result);
        } else {
          if (msg.method === "Target.targetCreated" || msg.method === "Target.targetInfoChanged") this.targets.set(msg.params.targetInfo.targetId, msg.params.targetInfo);
          if (msg.method === "Target.targetDestroyed") this.targets.delete(msg.params.targetId);
          for (const l of this.listeners) l(msg);
        }
      }
    });
  }

  send(method, params = {}, sessionId) {
    const id = ++this.id;
    this.out.write(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }) + "\0");
    return new Promise((resolve, reject) => this.pending.set(id, { resolve, reject, method }));
  }

  async loadExtension(path) {
    const id = (await this.send("Extensions.loadUnpacked", { path })).id;
    await this.waitForTarget((t) => t.type === "service_worker" && t.url.includes(id));
    return id;
  }

  async waitForTarget(pred, ms = 15000) {
    const end = Date.now() + ms;
    while (Date.now() < end) {
      for (const t of this.targets.values()) if (pred(t)) return t;
      await new Promise((r) => setTimeout(r, 100));
    }
    throw new Error("target not found; have: " + JSON.stringify([...this.targets.values()].map((t) => [t.type, t.url])));
  }

  async newPage(url) {
    const { targetId } = await this.send("Target.createTarget", { url });
    const { sessionId } = await this.send("Target.attachToTarget", { targetId, flatten: true });
    const s = new Session(this, sessionId);
    await s.send("Runtime.enable");
    await s.send("Page.enable");
    return s;
  }

  /** Attach to an existing page target (e.g. a window the extension opened). */
  async attach(targetId) {
    const { sessionId } = await this.send("Target.attachToTarget", { targetId, flatten: true });
    const s = new Session(this, sessionId);
    await s.send("Runtime.enable");
    await s.send("Page.enable");
    return s;
  }

  async close() {
    try { await Promise.race([this.send("Browser.close"), new Promise((r) => setTimeout(r, 3000))]); } catch {}
    this.proc.kill("SIGKILL");
    rmSync(this.userDataDir, { recursive: true, force: true });
  }
}

export class Session {
  constructor(browser, sessionId) { Object.assign(this, { browser, sessionId }); }
  send(method, params = {}) { return this.browser.send(method, params, this.sessionId); }

  /** Evaluate an expression (awaited, with a user gesture); returns its value or throws. */
  async eval(expression) {
    const r = await this.send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true, userGesture: true });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description ?? r.exceptionDetails.text);
    return r.result.value;
  }

  async navigate(url, ready) {
    await this.send("Page.navigate", { url });
    for (let i = 0; i < 100; i++) {
      if (await this.eval(ready).catch(() => false)) return;
      await new Promise((r) => setTimeout(r, 100));
    }
    throw new Error(`page not ready: ${url}`);
  }

  /** A real (isTrusted) mouse click in the middle of the element. */
  async click(selector) {
    const r = await this.eval(`(() => { const e = document.querySelector(${JSON.stringify(selector)}); if (!e) return null; e.scrollIntoView({ block: "center" }); const b = e.getBoundingClientRect(); return { x: b.x + b.width / 2, y: b.y + b.height / 2 }; })()`);
    if (!r) throw new Error(`no element ${selector}`);
    for (const type of ["mousePressed", "mouseReleased"]) await this.send("Input.dispatchMouseEvent", { type, x: r.x, y: r.y, button: "left", clickCount: 1 });
  }

  /** A virtual CTAP2.1 platform authenticator with UV and PRF (hmac-secret). */
  async addAuthenticator(extra = {}) {
    await this.send("WebAuthn.enable", { enableUI: false });
    const { authenticatorId } = await this.send("WebAuthn.addVirtualAuthenticator", {
      options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true,
        hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true,
        defaultBackupEligibility: true, defaultBackupState: true, ...extra },
    });
    return authenticatorId;
  }
}
