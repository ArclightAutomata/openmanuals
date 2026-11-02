// node --test src/core/count.test.ts — short counts for the popup.
import { test } from "node:test";
import assert from "node:assert/strict";
import { compactCount, factsLabel } from "./count.ts";

test("compactCount shortens thousands and millions", () => {
  // Node's default locale in tests is en-US.
  assert.equal(compactCount(13), "13");
  assert.equal(compactCount(999), "999");
  assert.equal(compactCount(1340), "1.3K");
  assert.equal(compactCount(134123), "134K");
  assert.equal(compactCount(2_500_000), "2.5M");
});

test("factsLabel is singular for one", () => {
  assert.equal(factsLabel(1), "1 fact");
  assert.equal(factsLabel(0), "0 facts");
  assert.equal(factsLabel(134123), "134K facts");
});
