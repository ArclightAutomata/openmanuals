// node --test src/core/avatar.test.ts — avatar fact bodies (same rules as openmanuals_core::avatar).
import test from "node:test";
import assert from "node:assert/strict";
import { AVATAR_MAX_BYTES, avatarBodyError, cropSquare, githubAvatarUrl } from "./avatar.ts";

const SHA = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

test("avatar bodies: the three shapes and nothing else", () => {
  assert.equal(avatarBodyError({ sha256: SHA, size: 1000, mime: "image/webp" }), null);
  assert.equal(avatarBodyError({ url: "https://github.com/alice.png" }), null);
  assert.equal(avatarBodyError({ none: true }), null);
  for (const bad of [
    {}, { none: false }, { none: true, url: "https://x.org/a.png" }, { url: "http://x.org/a.png" }, { url: "https://u@x.org/a" },
    { url: "https://x.org/a b.png" }, { sha256: SHA, size: 1000 }, { sha256: SHA.toUpperCase(), size: 1, mime: "image/png" },
    { sha256: SHA, size: 0, mime: "image/png" }, { sha256: SHA, size: AVATAR_MAX_BYTES + 1, mime: "image/png" },
    { sha256: SHA, size: 10, mime: "image/svg+xml" }, null, [],
  ]) assert.notEqual(avatarBodyError(bad), null, JSON.stringify(bad));
});

test("GitHub avatar from a GitHub proof", () => {
  assert.equal(githubAvatarUrl(["dns:example.org?type=TXT", "https://gist.github.com/alice/0123456789abcdef0123456789abcdef"]), "https://github.com/alice.png");
  assert.equal(githubAvatarUrl(["https://github.com/alice"]), "https://github.com/alice.png");
  assert.equal(githubAvatarUrl(["https://gitlab.com/alice/gitlab_proof", "https://evil.example/gist.github.com/x"]), null);
});

test("center crop", () => {
  assert.deepEqual(cropSquare(400, 300), { sx: 50, sy: 0, side: 300 });
  assert.deepEqual(cropSquare(300, 401), { sx: 0, sy: 50, side: 300 });
});
