// DEMO-ISSUES C (a): an unapproved market directory answers Explore with no
// items and `needsApproval`. The empty shelf must still carry the approval
// note (`marketNotice()`), or the page reads as an empty market with no
// reason given (Home-7, 2026-11-16).
//
// Source-level: the page's only behaviour harness
// (scripts/marketplace-product-layout-smoke.mjs) has the `catalogNeedsApproval`
// stub but stops earlier, at its finality scenario, on this tree.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const PAGE = new URL("../marketplace.js", import.meta.url);

function emptyShelfBranch() {
  const source = readFileSync(PAGE, "utf8");
  const start = source.indexOf("function renderExploreSections()");
  assert.ok(start > 0, "renderExploreSections is in marketplace.js");
  const from = source.indexOf("if (!listings.length)", start);
  assert.ok(from > start, "the empty-shelf branch is in renderExploreSections");
  return source.slice(from, source.indexOf("return;", from));
}

test("empty Explore carries the market approval note", () => {
  assert.match(emptyShelfBranch(), /marketNotice\(\)/, "the empty shelf must say the market needs approval");
});

test("the approval note is said only when the market needs approval", () => {
  const source = readFileSync(PAGE, "utf8");
  const start = source.indexOf("function marketNotice()");
  const body = source.slice(start, source.indexOf("\n  }\n", start));
  assert.match(body, /state\.mediaTab !== "explore" \|\| !state\.catalogLoaded/);
  assert.match(body, /if \(state\.catalogNeedsApproval\)/);
});
