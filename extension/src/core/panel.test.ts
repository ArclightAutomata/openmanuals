// node --test src/core/panel.test.ts — the side panel's model: page items, eligibility, bulk plans.
import test from "node:test";
import assert from "node:assert/strict";
import type { Fact } from "./facts.ts";
import { can, describeRow, groups, keyOf, MAX_PAGE_ITEMS, opFor, pageItems, planBulk, selectWhere, validOps, type Row } from "./panel.ts";

const id = (c: string) => "sha256:" + c.repeat(64);
const ME = "QPRGVPJNWDXH4ESK2RYDTZJLTE";
const THEM = "AAAAAAAAAAAAAAAAAAAAAAAAAA";
const S = "c".repeat(64);
const fact = (type: string, author: string, body: Record<string, unknown> = {}): Fact =>
  ({ v: 1, type, author, at: "2026-10-31T12:00:00Z", body, sig: { alg: "Ed25519", fmt: "raw", key: { kty: "OKP", crv: "Ed25519", x: "x" }, value: "v" } }) as unknown as Fact;
const row = (key: string, f: Fact | undefined, extra: Partial<Row> = {}): Row =>
  ({ key, action: { action: "fact", fact: key }, status: "ok", fact: f, retracted: false, ...extra });

test("page items: validated, de-duplicated, in order, capped", () => {
  const raw = [
    { action: "fact", fact: id("a") },
    { action: "fact", fact: id("a") },
    { action: "copy", location: id("b"), file: S },
    { action: "file", file: S },
    { action: "fact", fact: "sha256:nope" },
    { action: "sign", fact: id("c") },
    "junk",
  ];
  assert.deepEqual(pageItems(raw).map(keyOf), [id("a"), id("b"), `file:${S}`]);
  assert.deepEqual(pageItems("x"), []);
  const many = Array.from({ length: MAX_PAGE_ITEMS + 50 }, (_, i) => ({ action: "fact", fact: "sha256:" + i.toString(16).padStart(64, "0") }));
  assert.equal(pageItems(many).length, MAX_PAGE_ITEMS);
});

test("eligibility: retract your own live facts, report others' and files", () => {
  const mine = row(id("a"), fact("product", ME));
  const theirs = row(id("b"), fact("product", THEM));
  const retracted = row(id("c"), fact("product", ME), { retracted: true });
  const aRetract = row(id("d"), fact("retract", ME, { fact: id("a") }));
  const loading = row(id("e"), undefined, { status: "loading" });
  const bad = row(id("f"), fact("product", THEM), { status: "error" });
  const file: Row = { key: `file:${S}`, action: { action: "file", file: S }, status: "ok" };
  const done = row(id("g"), fact("product", ME), { done: "retracted" });
  assert.deepEqual([mine, theirs, retracted, aRetract, loading, bad, file, done].map((r) => [can(r, ME, "retract"), can(r, ME, "report")]),
    [[true, false], [false, true], [false, false], [false, false], [false, false], [false, false], [false, true], [false, false]]);
  // Without an identity nothing is yours: nothing to retract, everything reportable.
  assert.equal(can(mine, null, "retract"), false);
  assert.equal(can(mine, null, "report"), true);
});

test("operations per row: copies report the location fact with file and url", () => {
  const copy: Row = { key: id("b"), action: { action: "copy", location: id("b"), file: S }, status: "ok", fact: fact("location", THEM, { file: S, url: "https://x.example/m.pdf", kind: "mirror" }) };
  assert.deepEqual(opFor(copy, "report", ME, "malware"), { op: "report", target: id("b"), value: "malware", author: THEM, sha256: S, url: "https://x.example/m.pdf" });
  assert.deepEqual(opFor(row(id("a"), fact("product", THEM)), "report", ME), { op: "report", target: id("a"), value: "spam", author: THEM });
  assert.deepEqual(opFor({ key: "file:sha1:" + "d".repeat(40), action: { action: "file", file: "sha1:" + "d".repeat(40) }, status: "ok" }, "report", ME, "wrong-file"),
    { op: "report", target: "file:sha1:" + "d".repeat(40), value: "wrong-file" });
  assert.deepEqual(opFor(row(id("a"), fact("product", ME)), "retract", ME), { op: "retract", fact: id("a") });
  assert.equal(opFor(row(id("a"), fact("product", ME)), "report", ME), null);
});

test("bulk: plans skip ineligible rows; helpers select by kind and author", () => {
  const rows = [
    row(id("1"), fact("product", ME)), row(id("2"), fact("product", THEM)), row(id("3"), fact("location", THEM, { url: "https://a/b" })),
    row(id("4"), fact("product", ME), { retracted: true }), row(id("5"), fact("manual", THEM, { title: "TV" }), { status: "error" }),
  ];
  const all = selectWhere(rows, () => true);
  const r = planBulk(rows, all, "retract", ME);
  assert.deepEqual(r.ops, [{ op: "retract", fact: id("1") }]);
  assert.equal(r.skipped, 4);
  const p = planBulk(rows, selectWhere(rows, (x) => x.fact?.author === THEM), "report", ME, "spam");
  assert.deepEqual(p.ops.map((o) => o.op === "report" && o.target), [id("2"), id("3")]);
  assert.equal(p.skipped, 1, "the row that didn't check out");
  const g = groups(rows);
  assert.deepEqual(g.kinds, [["product", 3], ["location", 1]]);
  assert.deepEqual(g.authors, [[THEM, 2], [ME, 2]], "ties alphabetical; rows that didn't check out don't count");
  assert.equal(describeRow(rows[0]).startsWith("product"), true);
  assert.equal(describeRow(rows[2]), "location: https://a/b");
});

test("bulk requests are validated before signing", () => {
  assert.deepEqual(validOps([{ op: "retract", fact: id("a") }, { op: "report", target: `file:${S}`, value: "spam", sha256: S }]),
    [{ op: "retract", fact: id("a") }, { op: "report", target: `file:${S}`, value: "spam", sha256: S }]);
  for (const bad of [
    [], "x", [{ op: "sign", fact: id("a") }], [{ op: "retract", fact: "sha256:zz" }],
    [{ op: "report", target: id("a"), value: "rude" }], [{ op: "report", target: "javascript:1", value: "spam" }],
    [{ op: "report", target: id("a"), value: "spam", author: "lower" }], [{ op: "report", target: id("a"), value: "spam", url: "javascript:alert(1)" }],
    Array.from({ length: 2001 }, () => ({ op: "retract", fact: id("a") })),
  ]) assert.equal(validOps(bad), null, JSON.stringify(bad).slice(0, 80));
});
