// node --test src/identity/proofs.test.ts — claim matching and the proof check
// without the network (doipjs's own definitions + verification runner).
import test from "node:test";
import assert from "node:assert/strict";
import { aspeClaims, hostsFor, matchClaim, notFoundHint, SERVICES } from "./proofs.ts";
import { run } from "../../node_modules/doipjs/src/verifications.js";

const ASPE = "aspe:openmanuals.org:QPRGVPJNWDXH4ESK2RYDTZJLTE";

test("claim URIs match the expected services", () => {
  assert.equal(matchClaim("https://gist.github.com/alice/0123abcd")[0].id, "github");
  assert.equal(matchClaim("dns:example.org?type=TXT")[0].id, "dns");
  assert.equal(matchClaim("https://codeberg.org/alice/forgejo_proof").map((m) => m.id).includes("forgejo"), true);
  assert.ok(matchClaim("https://gitlab.com/alice/gitlab_proof").some((m) => m.id === "gitlab"));
  assert.ok(matchClaim("https://mastodon.social/@alice").some((m) => m.id === "activitypub"));
  assert.deepEqual(matchClaim("mailto:nobody"), []);
});

test("verification runner finds the identifier in a gist and a TXT record", async () => {
  const gh = matchClaim("https://gist.github.com/alice/0123abcd")[0].def;
  const okGist = await run({ files: { "proof.md": { content: `Hello\n${ASPE}\n` } } }, gh, ASPE);
  assert.equal(okGist.result, true);
  const badGist = await run({ files: { "proof.md": { content: "aspe:openmanuals.org:SOMEBODYELSE" } } }, gh, ASPE);
  assert.equal(badGist.result, false);
  const dns = matchClaim("dns:example.org?type=TXT")[0].def;
  const okDns = await run({ hostname: "example.org", records: { txt: [["v=spf1 -all"], [ASPE]] } }, dns, ASPE);
  assert.equal(okDns.result, true);
});

test("a Keyoxide ASP profile proves a link when its claims list ours", async () => {
  const kx = matchClaim("aspe:keyoxide.org:6WJK26YKF6WUVPIZTS2I2BIT64");
  assert.deepEqual(kx.map((m) => m.id), ["aspe"]);
  const payload = (claims: string[]) => Buffer.from(JSON.stringify({ "http://ariadne.id/version": 0, "http://ariadne.id/claims": claims })).toString("base64url");
  const jws = (claims: string[]) => `eyJhbGciOiJFZERTQSJ9.${payload(claims)}.sig`;
  assert.deepEqual(aspeClaims(jws([ASPE, "https://gist.github.com/a/b"])), [ASPE, "https://gist.github.com/a/b"]);
  assert.equal((await run({ claims: aspeClaims(jws([ASPE])) }, kx[0].def, ASPE)).result, true);
  assert.equal((await run({ claims: aspeClaims(jws(["aspe:openmanuals.org:SOMEBODYELSE"])) }, kx[0].def, ASPE)).result, false);
  assert.deepEqual(hostsFor("aspe:keyoxide.org:6WJK26YKF6WUVPIZTS2I2BIT64", "keyoxide"), ["https://keyoxide.org/*"]);
  assert.deepEqual(hostsFor("openpgp4fpr:3637202523E7C1309AB79E99EF2DC5827B445F4B", "keyoxide"), ["https://keys.openpgp.org/*"]);
});

test("permission hosts for a claim", () => {
  assert.deepEqual(hostsFor("https://gist.github.com/alice/0123abcd", "github").sort(), ["https://api.github.com/*", "https://gist.github.com/*"]);
  assert.deepEqual(hostsFor("dns:example.org", "dns"), ["https://cloudflare-dns.com/*"]);
  assert.ok(SERVICES.length >= 6);
});

test("a gist without proof.md says so", () => {
  assert.equal(notFoundHint("github", { files: { "gistfile1.txt": { content: "aspe:x:Y" } } }), `the gist needs a file named "proof.md" containing the identifier (it has "gistfile1.txt").`);
  assert.equal(notFoundHint("github", { files: { "proof.md": { content: "nope" } } }), `the gist's "proof.md" doesn't contain the identifier.`);
  assert.equal(notFoundHint("gitlab", {}), "identifier not found in the proof.");
});
