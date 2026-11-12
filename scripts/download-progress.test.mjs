import assert from "node:assert/strict";
import test from "node:test";
import { formatBytes, formatBytesOf } from "../capsules/_shared/byte-format.js";
import { createTransferProgress, announceTransferProgress } from "../capsules/_shared/transfer-progress.js";
import { createLibraryUploads } from "../capsules/library/browser/src/uploads.js";

class Element {
  constructor(tag) { this.tagName = tag; this.attributes = new Map(); this.children = []; this.dataset = {}; this.ownerDocument = doc; }
  setAttribute(name, value) { this.attributes.set(name, value); }
  append(...nodes) { this.children.push(...nodes); }
  querySelector() { return this.children.find(child => child.className === "transfer-announcement"); }
}
const doc = { createElement: tag => new Element(tag) };

test("one decimal size rule covers byte and decimal unit boundaries", () => {
  for (const [bytes, label] of [[0, "0 B"], [999, "999 B"], [1000, "1.0 KB"], [1050, "1.1 KB"],
    [999900, "999.9 KB"], [999949, "999.9 KB"], [999950, "1.0 MB"], [999999, "1.0 MB"], [1000000, "1.0 MB"], [1000000000, "1.0 GB"], [1000000000000, "1.0 TB"]]) {
    assert.equal(formatBytes(bytes), label);
  }
});

test("X of Y keeps the total's unit while the byte count crosses boundaries", () => {
  assert.equal(formatBytesOf(999, 2000000), "0.0 MB of 2.0 MB");
  assert.equal(formatBytesOf(999900, 2000000), "1.0 MB of 2.0 MB");
  assert.equal(formatBytesOf(1000000, 2000000), "1.0 MB of 2.0 MB");
  assert.equal(formatBytesOf(2000000, 2000000), "2.0 MB of 2.0 MB");
  assert.equal(formatBytesOf(999, 1000), "1.0 KB of 1.0 KB");
});

test("the shared native progress pattern supplies size, percentage and accessible text", () => {
  const root = createTransferProgress(25000000, 100000000, "Update download progress", doc);
  const [bar, detail] = root.children;
  assert.equal(bar.tagName, "progress");
  assert.equal(bar.max, 100000000);
  assert.equal(bar.value, 25000000);
  assert.equal(detail.textContent, "25.0 MB of 100.0 MB · 25%");
  assert.equal(bar.attributes.get("aria-label"), "Update download progress");
  assert.equal(bar.attributes.get("aria-valuetext"), detail.textContent);
});

for (const total of [undefined, null, 0]) test(`unknown total ${total} has an indeterminate bar and no percentage`, () => {
  const [bar, detail] = createTransferProgress(1500, total, "Upload progress", doc).children;
  assert.equal(Object.hasOwn(bar, "value"), false);
  assert.equal(detail.textContent, "1.5 KB received");
  assert.doesNotMatch(detail.textContent, /%| of /);
});

test("Library renders the actual shared pattern with file byte counts", t => {
  const previous = globalThis.document;
  globalThis.document = doc;
  t.after(() => { if (previous === undefined) delete globalThis.document; else globalThis.document = previous; });
  const meter = new Element("div");
  const container = { classList: { add() {}, remove() {} }, querySelectorAll: () => [meter] };
  createLibraryUploads({ container, perf: { uploadRenderCount: 0 }, state: { uploads: [
    { id: "upload", name: "Notes.txt", status: "Uploading", completed_bytes: 250, total_bytes: 1000 },
  ] } }).renderUploads();
  assert.equal(meter.children[0].children[0].attributes.get("aria-label"), "Upload progress for Notes.txt");
  assert.equal(meter.children[0].children[1].textContent, "0.3 KB of 1.0 KB · 25%");
});

test("progress announcements keep one polite region and change at milestones", () => {
  const host = new Element("div");
  announceTransferProgress(host, 250, 1000, "Download");
  const live = host.children[0];
  assert.equal(live.attributes.get("role"), "status");
  assert.equal(live.attributes.get("aria-live"), "polite");
  assert.equal(live.textContent, "Download: 0.3 KB of 1.0 KB, 25%.");
  announceTransferProgress(host, 290, 1000, "Download");
  assert.equal(host.children.length, 1);
  assert.equal(live.textContent, "Download: 0.3 KB of 1.0 KB, 25%.");
  announceTransferProgress(host, 300, 1000, "Download");
  assert.equal(live.textContent, "Download: 0.3 KB of 1.0 KB, 30%.");
});

for (const status of ["Complete", "Upload not confirmed. Check the destination before retrying."]) {
  test(`an empty Library file with status ${status} has no waiting-size bar`, t => {
    const previous = globalThis.document;
    globalThis.document = doc;
    t.after(() => { if (previous === undefined) delete globalThis.document; else globalThis.document = previous; });
    const meter = new Element("div");
    const container = { classList: { add() {}, remove() {} }, querySelectorAll: () => [meter] };
    createLibraryUploads({ container, perf: { uploadRenderCount: 0 }, state: { uploads: [
      { id: "empty", name: "Empty.txt", status, completed_bytes: 0, total_bytes: 0 },
    ] } }).renderUploads();
    assert.equal(meter.hidden, true);
    assert.equal(meter.children.length, 0);
  });
}

for (const value of [undefined, null, "", NaN, Infinity, -1]) test(`unknown file size ${value} has an explicit label`, () => {
  assert.equal(formatBytes(value), "Size unknown");
});

test("rounded total selects one unit for both sides of a transfer", () => {
  assert.equal(formatBytesOf(500000, 999950), "0.5 MB of 1.0 MB");
});

test("Browser disk-space refusal uses the shared size rule", async () => {
  const { friendlyOpenError } = await import("../capsules/browser/browser/browser-status.js");
  const message = friendlyOpenError({ payload: {
    outcome: { schema: "elastos.browser.open-outcome/v1", state: "terminal_pre_effect_failure",
      effects: { page_acquired: false, vm_acquired: false, stream_acquired: false } },
    refusal: { code: "insufficient_free_space", required_bytes: 2000000000, available_bytes: 999950 },
  } });
  assert.match(message, /2\.0 GB free.*1\.0 MB are free/);
});

test("update admission handles a missing candidate with an error", async () => {
  const { readFile } = await import("node:fs/promises");
  const source = await readFile(new URL("../elastos/crates/elastos-server/src/update.rs", import.meta.url), "utf8");
  assert.doesNotMatch(source, /next_admission\.take\(\)\.unwrap\(\)/);
});

test("changed capsule entry points use the download progress asset version", async () => {
  const { readFile } = await import("node:fs/promises");
  for (const name of ["system", "library", "archive-manager", "browser"]) {
    const html = await readFile(new URL(`../capsules/${name}/browser/index.html`, import.meta.url), "utf8");
    assert.match(html, /(?:system|app|archive-manager|browser)\.js\?v=download-progress-20261112/);
    if (name === "system") assert.match(html, /^<link rel="stylesheet" href="\.\/elastos-ui\.css">$/m);
  }
});

test("advisory progress writer uses atomic replacement without disk sync", async () => {
  const { readFile } = await import("node:fs/promises");
  const source = await readFile(new URL("../elastos/crates/elastos-server/src/update_controller.rs", import.meta.url), "utf8");
  const writer = source.slice(source.indexOf("fn write_advisory_progress("), source.indexOf("fn write_private(path:"));
  assert.match(writer, /fs::rename/);
  assert.match(writer, /libc::O_NOFOLLOW/);
  assert.doesNotMatch(writer, /sync_all|sync_data|write_private\(|write_new_private\(/);
});

test("vendored model views load the current shared progress modules", async () => {
  const { readFile } = await import("node:fs/promises");
  const model = await readFile(new URL("../capsules/_shared/model-management.js", import.meta.url), "utf8");
  for (const module of ["byte-format", "transfer-progress"]) {
    assert(model.includes(`./${module}.js?v=download-progress-20261112`));
  }
  for (const capsule of ["system", "marketplace"]) {
    const html = await readFile(new URL(`../capsules/${capsule}/browser/index.html`, import.meta.url), "utf8");
    assert.match(html, /model-management\.js\?v=download-progress-20261112/);
  }
});
