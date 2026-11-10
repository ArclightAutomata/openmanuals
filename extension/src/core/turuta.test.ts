import { test } from "node:test";
import assert from "node:assert/strict";
import { rowProduct } from "./turuta.ts";

test("turuta rows: model and brand from the cells", () => {
  assert.deepEqual(rowProduct(["", " 0.507A ", "NORDMENDE", "CRT TV", ""]), { brand: "NORDMENDE", model: "0.507A" });
  assert.equal(rowProduct(["", "X1", "???", "CRT TV", ""]), null);
  assert.equal(rowProduct(["", "", "SONY", "CRT TV", ""]), null);
  assert.equal(rowProduct(["a", "b"]), null);
});
