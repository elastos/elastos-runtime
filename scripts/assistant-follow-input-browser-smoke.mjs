#!/usr/bin/env node
// Import the real stream module in Chromium and, on macOS, system WKWebView.
// ASSISTANT_FOLLOW_REF serves a pinned module for fail-before evidence.
// ASSISTANT_FOLLOW_MATRIX=1 starts a live turn for develop/candidate comparison.
// ASSISTANT_FOLLOW_WEBKIT=1 also runs system WebKit with Accessibility access.
import { createHash } from "node:crypto";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { execFile, execFileSync } from "node:child_process";
import { promisify } from "node:util";
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { resolve, extname } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "./system-uiux-fixture.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const output = resolve(root, "output/assistant-follow-input");
const run = promisify(execFile);
const ref = process.env.ASSISTANT_FOLLOW_REF;
const matrix = process.env.ASSISTANT_FOLLOW_MATRIX === "1";
const native = process.env.ASSISTANT_FOLLOW_WEBKIT === "1";
const modes = process.env.ASSISTANT_FOLLOW_MODES
  ? process.env.ASSISTANT_FOLLOW_MODES.split(",").map(mode => mode === "normal" ? "" : mode)
  : native ? ["", "fallback", "swallow"] : ["", "fallback"];
assert.ok(modes.every(mode => ["", "fallback", "swallow"].includes(mode)), "known settlement modes");
const binary = resolve(output, "webkit");
const sourcePath = "capsules/assistant/browser/agent-stream.js";
const source = ref ? execFileSync("git", ["show", `${ref}:${sourcePath}`], { cwd: root }) : await readFile(resolve(root, sourcePath));
const sourceSha256 = createHash("sha256").update(source).digest("hex");
const reports = [];
const record = report => {
  report.sourceSha256 = sourceSha256;
  reports.push(report);
  console.log(JSON.stringify({ ref: ref || "worktree", ...report }));
};
const server = createServer(async (req, res) => {
  try {
    const path = new URL(req.url, "http://fixture").pathname;
    if (path === "/favicon.ico") { res.writeHead(204); res.end(); return; }
    const relative = path === "/" ? "scripts/fixtures/assistant-follow-input.html" : path.slice(1);
    assert.ok(relative.startsWith("capsules/assistant/browser/") || relative === "scripts/fixtures/assistant-follow-input.html");
    const file = resolve(root, relative);
    assert.ok(file.startsWith(root));
    const body = relative === sourcePath ? source : await readFile(file);
    res.writeHead(200, { "content-type": [".js", ".mjs"].includes(extname(file)) ? "text/javascript" : extname(file) === ".css" ? "text/css" : "text/html", "cache-control": "no-store" });
    res.end(body);
  } catch { res.writeHead(404); res.end(); }
});
let browser;
try {
  await mkdir(output, { recursive: true });
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  const url = `http://127.0.0.1:${server.address().port}/`;
  if (native) {
    assert.equal(process.platform, "darwin", "system WKWebView needs macOS");
    await run("swiftc", ["-O", "-module-cache-path", resolve(output, "module-cache"), "-o", binary,
      resolve(root, "scripts/fixtures/assistant-follow-input-webkit.swift")], { timeout: 60000 });
  }
  browser = await chromium.launch({ headless: !native, args: native ? ["--force-renderer-accessibility"] : [], ignoreDefaultArgs: ["--hide-scrollbars"],
    ...(process.env.BRAVE_BIN ? { executablePath: process.env.BRAVE_BIN } : {}) });
  for (const mode of modes) {
    const page = await browser.newPage({ viewport: native ? null : { width: 800, height: 600 } });
    const browserSession = native ? await browser.newBrowserCDPSession() : null;
    const browserPid = native ? (await browserSession.send("SystemInfo.getProcessInfo")).processInfo.find(p => p.type === "browser").id : null;
    const driverErrors = [];
    page.on("console", message => { if (message.type() === "error") driverErrors.push(message.text()); });
    await page.exposeFunction("driveInput", async request => {
      const b = request.rect;
      if (native) {
        await run(binary, ["--input", String(browserPid), JSON.stringify(request)], { timeout: 5000 });
      } else if (request.phase === "wheel") {
        await page.mouse.move(b.x + 120, b.y + 180);
        for (const delta of request.deltas) {
          await page.mouse.wheel(0, delta);
          await page.waitForTimeout(request.gapMs || 20);
        }
      } else if (["hold", "release"].includes(request.phase)) {
        await page.mouse.move(b.x + b.width - (request.content ? 40 : 3), b.y + b.height - 14);
        if (request.phase === "hold") await page.mouse.down();
        else await page.mouse.up();
      } else if (request.phase === "key") {
        await page.keyboard.press(request.key);
      } else {
        const selection = request.phase === "select";
        const back = request.phase === "drag-back";
        const x = selection ? b.x + 8 : b.x + b.width - 3;
        const y = selection ? b.y + b.height / 2 : b.y + (back ? 14 : b.height - 14);
        await page.mouse.move(x, y);
        await page.mouse.down();
        await page.mouse.move(selection ? b.x + b.width - 8 : x,
          selection ? y : b.y + (back ? b.height - 14 : 36), { steps: 16 });
        await page.mouse.up();
      }
    });
    await page.addInitScript(() => {
      window.webkit = { messageHandlers: { probe: { postMessage: async text => {
        const request = JSON.parse(text);
        if (request.phase === "done") return;
        try { await window.driveInput(request); window.__continue(true); }
        catch (error) { console.error(error); window.__continue(false); }
      } } } };
    });
    await page.goto(`${url}?${mode}${matrix ? "&matrix" : ""}#home_token=follow-fixture`);
    await page.waitForFunction(() => window.__report, null, { timeout: matrix ? 180000 : 55000 });
    record({ engine: "Chromium", input: native ? "CGEvent" : "Playwright", driverErrors, ...await page.evaluate(() => window.__report) });
    await page.close();
  }
  await browser.close(); browser = null;
  if (native) {
    for (const mode of modes) {
      const { stdout } = await run(binary, [`${url}?${mode}${matrix ? "&matrix" : ""}#home_token=follow-fixture`], { timeout: matrix ? 190000 : 60000 });
      record({ engine: "system WebKit", input: "CGEvent", ...JSON.parse(stdout.trim()) });
    }
  }
  await writeFile(resolve(output, `${(ref || "worktree").replaceAll("/", "-")}${matrix ? "-matrix" : ""}.json`), JSON.stringify(reports, null, 2));
  if (matrix && process.env.ASSISTANT_FOLLOW_BASELINE) {
    const baseline = JSON.parse(await readFile(process.env.ASSISTANT_FOLLOW_BASELINE, "utf8"));
    assert.equal(reports.length, baseline.length, "same engine/mode coverage");
    for (const report of reports) {
      const prior = baseline.find(r => r.engine === report.engine && r.fallback === report.fallback && r.swallow === report.swallow);
      assert.ok(prior, "matching baseline engine/mode");
      assert.deepEqual(report.driverErrors || [], [], "native driver and page console are clean");
      assert.deepEqual(report.failures.filter(f => !Object.hasOwn(report.checks, f) || /driver available|trusted .* received/.test(f)), [],
        "shared failures cannot hide fixture or input errors");
      assert.deepEqual(Object.keys(report.checks), Object.keys(prior.checks), "same matrix checks");
      assert.deepEqual(report.failures.filter(f => !prior.failures.includes(f)), [], "candidate has no new failures");
      for (const label of ["1px then 220ms quiet then 80px and growth", "stationary scrollbar hold with 150px growth",
        "stream growth and completion without Jump flash"]) assert.equal(report.checks[label], true, label);
      console.log(JSON.stringify({ engine: report.engine, fallback: report.fallback, swallow: report.swallow,
        sharedFailures: report.failures }));
    }
  } else {
    assert.deepEqual(reports.flatMap(r => r.failures.map(f => `${r.engine} fallback=${r.fallback} swallow=${r.swallow}: ${f}`)), []);
  }
  console.log(`PASS Assistant follow input: ${reports.length} engine/settlement runs`);
} finally {
  await browser?.close();
  server.close();
}
