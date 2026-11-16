// Run with:  npm test   (uses Node's built-in test runner, no extra packages)
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildSegments } from "./highlight.js";

const sig = (severity, spans, title = "t") => ({ severity, spans, title });

test("splits text into plain and highlighted parts", () => {
  const segs = buildSegments("pay now at bit.ly/x", [sig("high", [[11, 19]])]);
  assert.deepEqual(segs.map((s) => s.text), ["pay now at ", "bit.ly/x"]);
  assert.equal(segs[1].severity, "high");
});

test("rebuilt text always equals the original", () => {
  const text = "URGENT pay the fee today at bit.ly/x";
  const segs = buildSegments(text, [sig("medium", [[0, 6], [28, 36]]), sig("high", [[28, 36]]), sig("low", [[15, 18]])]);
  assert.equal(segs.map((s) => s.text).join(""), text);
});

test("overlapping spans keep the most severe", () => {
  const segs = buildSegments("abcdefgh", [sig("medium", [[0, 5]]), sig("high", [[3, 8]])]);
  const marked = segs.filter((s) => s.severity);
  assert.equal(marked.length, 1);
  assert.equal(marked[0].severity, "high");
});

test("ignores out-of-range spans", () => {
  const segs = buildSegments("short", [sig("high", [[2, 99]]), sig("low", [[-1, 2]])]);
  assert.deepEqual(segs, [{ text: "short" }]);
});
