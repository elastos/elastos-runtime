import assert from "node:assert/strict";
import test from "node:test";
import { readSystemUpdateState, readInboxUpdateNotice } from "./system-update-observer.mjs";

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

for (const fault of ["none", "title hidden", "body missing", "action hidden", "action disabled", "action missing"]) {
  test(`installed Inbox observer: ${fault}`, () => {
    const node = text => ({ textContent: text, disabled: false, getClientRects: () => [{}] });
    const title = node("Update available");
    const body = node("ElastOS 2.0.2-rc.2 is available.");
    const action = node("Open System");
    if (fault === "title hidden") title.getClientRects = () => [];
    if (fault === "action hidden") action.getClientRects = () => [];
    if (fault === "action disabled") action.disabled = true;
    globalThis.document = {
      querySelector: selector => selector.endsWith(".entry-title") ? title : fault === "body missing" ? null : body,
      querySelectorAll: () => fault === "action missing" ? [node("Dismiss")] : [node("Dismiss"), action],
    };
    try {
      const observed = readInboxUpdateNotice();
      assert.equal(observed.title, "Update available");
      assert.equal(observed.body, fault === "body missing" ? "" : "ElastOS 2.0.2-rc.2 is available.");
      assert.equal(observed.shown, !["title hidden", "body missing"].includes(fault));
      assert.equal(observed.open_system, !fault.startsWith("action"));
    } finally {
      delete globalThis.document;
    }
  });
}
