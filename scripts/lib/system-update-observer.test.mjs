import assert from "node:assert/strict";
import test from "node:test";
import { readSystemUpdateState } from "./system-update-observer.mjs";

for (const heading of ["Update to 2.0.3", "Updating to 2.0.3", "Update to ElastOS 2.0.3", "Updating to ElastOS 2.0.3", "ElastOS update"]) {
  test(`installed update observer reads ${heading}`, () => {
    const fields = { "update-heading": { textContent: heading }, "update-new-version": { textContent: "2.0.3" } };
    globalThis.document = { querySelector: selector => fields[selector.match(/^\[data-field="(.+)"\]$/)?.[1]] || null };
    globalThis.window = {};
    try {
      assert.equal(readSystemUpdateState().new_version, "2.0.3");
    } finally {
      delete globalThis.document;
      delete globalThis.window;
    }
  });
}
