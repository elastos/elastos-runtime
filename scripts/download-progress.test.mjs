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

test("decimal size rule covers byte and decimal unit boundaries", () => {
  for (const [bytes, label] of [[0, "0 B"], [999, "999 B"], [1000, "1.0 KB"], [1050, "1.1 KB"],
    [999900, "999.9 KB"], [999949, "999.9 KB"], [999950, "1.0 MB"], [999999, "1.0 MB"], [1000000, "1.0 MB"], [1000000000, "1.00 GB"], [1000000000000, "1.0 TB"]]) {
    assert.equal(formatBytes(bytes), label);
  }
});

test("X of Y keeps the total's unit while the byte count crosses boundaries", () => {
  assert.equal(formatBytesOf(999, 2000000), "0.0 MB of 2.0 MB");
  assert.equal(formatBytesOf(999900, 2000000), "1.0 MB of 2.0 MB");
  assert.equal(formatBytesOf(1000000, 2000000), "1.0 MB of 2.0 MB");
  assert.equal(formatBytesOf(2000000, 2000000), "2.0 MB of 2.0 MB");
  assert.equal(formatBytesOf(999, 1000), "0.9 KB of 1.0 KB");
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
  assert.equal(detail.textContent, "1.5 KB received · Size unknown");
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
  assert.match(message, /2\.00 GB free.*999\.9 KB are free/);
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

for (const [size, expected] of [[undefined, "Size unknown"], [null, "Size unknown"], [0, "0 B"]]) {
  test(`Library properties preserve the size meaning for ${size}`, async () => {
    const { createLibraryDialog } = await import("../capsules/library/browser/src/dialog.js");
    const dialog = { classList: { remove() {} }, innerHTML: "" };
    const view = createLibraryDialog({ dialog, roots: () => [] });
    view.showProperties({ uri: "localhost://Users/fixture/Documents/notes.txt", name: "notes.txt", kind: "file", size });
    assert.match(dialog.innerHTML, new RegExp(expected));
  });
}

test("Library loads the current properties and list renderers", async () => {
  const { readFile } = await import("node:fs/promises");
  const app = await readFile(new URL("../capsules/library/browser/src/app.js", import.meta.url), "utf8");
  for (const module of ["dialog", "render"]) assert(app.includes(`./${module}.js?v=download-progress-20261112`));
});

for (const [done, total, percent] of [[99949999, 100000000, 99], [99950000, 100000000, 99],
  [99999999, 100000000, 99], [100000000, 100000000, 100], [999, 1000, 99], [998, 999, 99]]) {
  test(`true byte equality controls completion for ${done} of ${total}`, () => {
    const host = new Element("div");
    const [bar, detail] = createTransferProgress(done, total, "Download", doc).children;
    assert.equal(detail.textContent, `${formatBytesOf(done, total)} · ${percent}%`);
    announceTransferProgress(host, done, total, "Download");
    assert.equal(host.children[0].textContent, `Download: ${formatBytesOf(done, total)}, ${percent}%.`);
    assert.equal(bar.value === total, percent === 100);
  });
}

test("Browser disk refusal rounds requirements up and available bytes down", async () => {
  const { friendlyOpenError } = await import("../capsules/browser/browser/browser-status.js");
  for (const [required, available, labels] of [[2000000001, 2000000000, ["2.01 GB", "2.00 GB"]],
    [2000000000, 1999999999, ["2.00 GB", "1.99 GB"]], [1000000, 999999, ["1.0 MB", "999.9 KB"]]]) {
    const message = friendlyOpenError({ payload: {
      outcome: { schema: "elastos.browser.open-outcome/v1", state: "terminal_pre_effect_failure",
        effects: { page_acquired: false, vm_acquired: false, stream_acquired: false } },
      refusal: { code: "insufficient_free_space", required_bytes: required, available_bytes: available },
    } });
    assert(message.includes(`${labels[0]} free`), message);
    assert(message.includes(`${labels[1]} are free`), message);
  }
});

for (const [done, total, label] of [
  [950000000, 1000000000, "0.95 GB of 1.00 GB · 95%"],
  [999999999, 1000000000, "0.99 GB of 1.00 GB · 99%"],
  [1000000000, 1000000000, "1.00 GB of 1.00 GB · 100%"],
]) test(`GB progress uses true bytes at ${done}`, () => {
  const [bar, detail] = createTransferProgress(done, total, "Download", doc).children;
  assert.equal(detail.textContent, label);
  assert.equal(bar.value, done);
});

test("unfinished transfers keep distinct displayed counts at each unit", () => {
  for (const total of [999, 1000, 1050, 1000000, 1000000000, 1234567890, 1000000000000]) {
    for (const done of [total - 1, Math.floor(total * 0.95)]) {
      const [received, size] = formatBytesOf(done, total).split(" of ");
      assert.notEqual(received, size);
      assert.equal(formatBytesOf(total, total), `${size} of ${size}`);
    }
  }
});
