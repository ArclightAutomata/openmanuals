// node --test src/core/claim-display.test.ts — how proofs are shown in the options page.
import test from "node:test";
import assert from "node:assert/strict";
import { claimDisplay, GLOBE, KEY, pickProvider } from "./claim-display.ts";
import { matchClaim } from "../identity/proofs.ts";

const show = (uri: string, confirmed?: string) => claimDisplay(uri, pickProvider(uri, matchClaim(uri).map((m) => m.id), confirmed));

test("a gist shows as GitHub with a short link", () => {
  const d = show("https://gist.github.com/alice/0123456789abcdef0123456789abcdef");
  assert.equal(d.service, "GitHub");
  assert.equal(d.label, "gist.github.com/alice/0123456789abcdef0123456789abcdef");
  assert.equal(d.href, "https://gist.github.com/alice/0123456789abcdef0123456789abcdef");
  assert.equal(d.icon.color, "#181717");
});

test("Codeberg, Mastodon, DNS, aspe and unknown sites", () => {
  assert.equal(show("https://codeberg.org/alice/forgejo_proof").service, "Codeberg");
  assert.equal(show("https://mastodon.social/@alice").service, "Mastodon");
  const dns = show("dns:example.org?type=TXT");
  assert.deepEqual([dns.service, dns.href, dns.icon], ["DNS", null, GLOBE]);
  const aspe = show("aspe:keyoxide.org:QPRGVPJNWDXH4ESK2RYDTZJLTE");
  assert.deepEqual([aspe.service, aspe.href, aspe.icon], ["Keyoxide", null, KEY]);
  assert.equal(show("https://git.example.org/alice/gitea_proof").service, "Gitea");
  assert.equal(show("https://git.example.org/alice/proofs", "Gitea").service, "Gitea", "the confirmed provider wins");
  const site = claimDisplay("https://www.example.org/about/");
  assert.deepEqual([site.service, site.label], ["Website", "example.org/about"]);
});
