#!/usr/bin/env node
// Replies stay readable at the edges of the Assistant room. The real
// Assistant capsule runs opaque-sandboxed inside an opaque Home GUI frame,
// as installed. Numbered lists of ten or more items keep every marker whole
// ("10.", "20."), in a saved reply and in one that streamed in, and while a
// turn runs its status line ("Working out the best approach…") and then the
// newest reply sit fully above the composer, not behind it. A reader at the
// end who sends a message follows its long reply to the end, while it
// streams and once it settles, without being offered Jump to latest.
// Reader movement owns the transcript during streaming and completion.
// Growth and clamp-then-grow keep a reader at the end there. The same cases
// run in a task and inside rAF, before scroll-event delivery. Find, native
// zero-gutter scrollbar drag, reversing touch, keyboard and Jump cover input.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { readFile, mkdtemp, writeFile, unlink, rmdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { extname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "./system-uiux-fixture.mjs";
import { productSmokeLaunchOptions } from "./product-smoke-browser.mjs";

const cpuRate = process.env.ASSISTANT_LAYOUT_CPU_RATE ? Number(process.env.ASSISTANT_LAYOUT_CPU_RATE) : null;
assert.ok(cpuRate === null || [1, 4, 6].includes(cpuRate), "CPU rate is 1, 4 or 6");

const root = resolve(fileURLToPath(new URL("../", import.meta.url)));
const schema = "elastos.assistant.workspace/v2";
const homeToken = "assistant-layout-fixture";
const textOffer = { id: "offer:text-fixture", title: "Text fixture", operation: "text.generate",
  context: { context_window_tokens: 8192, max_output_tokens: 1024 },
  input_modalities: ["text/plain"], output_modalities: ["text/plain"] };
const numbered = (count, label) => Array.from({ length: count }, (_, i) => `${i + 1}. ${label} ${i + 1}`).join("\n");
const filler = "A sentence that fills the room so the transcript scrolls. ".repeat(12);
const savedList = `Here are twelve:\n\n${numbered(12, "Saved step")}`;
const streamedList = `Here are twenty-five:\n\n${numbered(25, "Streamed step")}`;
// A long Markdown reply like a hosted model's: taller than the room.
const gardenReply = [
  "Planning a garden goes best in a few **clear steps**.\n\n",
  ...Array.from({ length: 6 }, (_, i) => [
    `## Step ${i + 1}: ${["Choose the site", "Test the soil", "Pick the plants", "Draw the beds", "Set up water", "Plant and mulch"][i]}\n\n`,
    `${"Look at the light, the wind and the soil before deciding anything else. ".repeat(3)}\n\n`,
    "- **First:** note the sun hours\n- **Second:** note where water pools\n- Third: mark paths\n\n",
  ].join("")),
  "```text\nbed A: tomatoes, basil\nbed B: beans, lettuce\n```\n\n",
  "| Plant | Sun |\n| --- | --- |\n| Tomato | Full |\n| Lettuce | Part |\n\n",
  "That is the whole plan: the last line of the reply.\n",
].join("");

const history = [];
for (let i = 0; i < 4; i += 1) {
  history.push({ role: "user", text: `Question ${i + 1}`, modelText: `Question ${i + 1}` });
  history.push({ role: "agent", text: i === 3 ? savedList : filler });
}
history.push({ role: "user", text: "List twenty-five steps", modelText: "List twenty-five steps" });
// A turn still running when the room opens: the Assistant resumes it, shows
// its status while nothing has arrived, then streams the reply.
const busyRoom = {
  v: 1, activeSessionId: "layout-room", sessionMode: "chat", liveOfferId: textOffer.id, selectedModelCid: null,
  composerDraft: { text: "", parts: [] }, projects: [], usageTurns: [],
  sessions: [{ id: "layout-room", title: "Layout room", mode: "chat", composerDraft: { text: "", parts: [] },
    messages: history,
    lastTurn: { turnId: "turn-layout", providerRunId: "run-layout", createRequestId: "request-layout",
      state: "streaming", startedAt: Date.now() - 1000 } }],
};

const fixture = { stored: { schema, revision: 1, document: busyRoom }, events: [], runs: new Map() };
const errors = [];
const server = createServer(async (req, res) => {
  const url = new URL(req.url, "http://fixture");
  const origin = `http://127.0.0.1:${server.address().port}`;
  const headers = {
    "access-control-allow-origin": "null",
    "access-control-allow-headers": "content-type,x-elastos-home-token",
    "access-control-allow-methods": "GET,POST,PUT,OPTIONS",
    "cache-control": "no-store",
  };
  const send = (status, type, body) => { res.writeHead(status, { ...headers, "content-type": type }); res.end(body); };
  const json = (value, status = 200) => send(status, "application/json", JSON.stringify(value));
  try {
    if (req.method === "OPTIONS") { res.writeHead(204, headers); res.end(); return; }
    if (url.pathname === "/") {
      send(200, "text/html", `<!doctype html><style>html,body,iframe{width:100%;height:100%;margin:0;border:0}iframe{display:block}</style>
        <iframe title="Home GUI" sandbox="allow-scripts" src="/gui?home_origin=${encodeURIComponent(origin)}"></iframe>`);
      return;
    }
    if (url.pathname === "/gui") {
      // Home GUI: hosts the Assistant frame and raises its room once ready.
      const homeOrigin = url.searchParams.get("home_origin");
      send(200, "text/html", `<!doctype html><style>html,body,iframe{width:100%;height:100%;margin:0;border:0}iframe{display:block}</style>
        <iframe title="Assistant" sandbox="allow-downloads allow-forms allow-modals allow-pointer-lock allow-scripts" allow="autoplay; fullscreen"
          src="/apps/assistant/?home_origin=${encodeURIComponent(homeOrigin)}#home_token=${homeToken}"></iframe>
        <script>addEventListener('message',event=>{if(event.data?.type==='home-agent:ready'){
          event.source.postMessage({type:'home-agent:open'},'*');
          event.source.postMessage({type:'home-agent:shelf-handover',on:true},'*');}});</script>`);
      return;
    }
    if (url.pathname.startsWith("/api/")) {
      assert.equal(req.headers["x-elastos-home-token"], homeToken);
      const chunks = []; for await (const chunk of req) chunks.push(chunk);
      const body = Buffer.concat(chunks).toString("utf8");
      const input = body ? JSON.parse(body) : null;
      if (url.pathname === "/api/apps/assistant/workspace-v2") {
        if (req.method === "GET") { json(fixture.stored); return; }
        assert.equal(req.method, "PUT");
        if (input.if_revision !== fixture.stored.revision) { json({ error: "workspace revision conflict" }, 409); return; }
        fixture.stored = { schema, revision: fixture.stored.revision + 1, document: input.document };
        json(fixture.stored); return;
      }
      if (url.pathname === "/api/provider/model/offers_list") { json({ offers: [textOffer] }); return; }
      if (url.pathname === "/api/capsules/catalog") {
        json({ schema: "elastos.capsules.catalog/v1", model_catalog_state: "verified", capsules: [] }); return;
      }
      if (url.pathname === "/api/provider/model/runs_get") { json({ run_id: input.run_id }); return; }
      if (url.pathname === "/api/provider/model/runs_create") {
        const runId = `run-sent-${fixture.runs.size + 1}`;
        fixture.runs.set(runId, []);
        json({ run_id: runId, status: "running", sequence_cursor: 0 }); return;
      }
      if (url.pathname === "/api/provider/model/runs_events") {
        const runEvents = input.run_id === "run-layout" ? fixture.events : fixture.runs.get(input.run_id);
        assert.ok(runEvents, `events of a known run: ${input.run_id}`);
        const after = Number(input.after_sequence) || 0;
        const events = runEvents.filter(event => event.sequence > after);
        json({ events, next_cursor: Math.max(after, ...events.map(event => event.sequence)), has_more: false });
        return;
      }
      throw new Error(`Unexpected API operation: ${req.method} ${url.pathname}`);
    }
    if (url.pathname === "/favicon.ico") { res.writeHead(204); res.end(); return; }
    const match = url.pathname.match(/^\/apps\/(assistant|home)\/(.*)$/);
    assert.ok(match, `Unexpected asset: ${url.pathname}`);
    const base = resolve(root, "capsules", match[1], "browser");
    const path = resolve(base, match[2] || "index.html");
    assert.ok(path.startsWith(`${base}/`));
    send(200, ({ ".html": "text/html", ".js": "text/javascript", ".mjs": "text/javascript", ".css": "text/css",
      ".svg": "image/svg+xml", ".woff2": "font/woff2" })[extname(path)] || "application/octet-stream", await readFile(path));
  } catch (error) { errors.push(String(error)); json({ error: "fixture failure" }, 500); }
});

/* Every marker of every numbered reply list, measured against the nearest
   box that clips it: an outside marker ends where its item's content starts
   and is as wide as its text ("25. "). */
function markerReport(selector) {
  const clipLeft = (el) => {
    let left = -Infinity;
    for (let node = el.parentElement; node; node = node.parentElement) {
      const style = getComputedStyle(node);
      const contain = style.contain;
      if (style.overflowX !== "visible" || /paint|content|strict/.test(contain)) {
        left = Math.max(left, node.getBoundingClientRect().left + parseFloat(style.borderLeftWidth));
      }
    }
    return left;
  };
  const probe = document.createElement("span");
  probe.style.cssText = "position:absolute;visibility:hidden;white-space:pre";
  document.body.append(probe);
  const lists = [...document.querySelectorAll(selector)];
  const report = lists.map((list) => {
    const items = [...list.children].filter((item) => item.tagName === "LI");
    let worst = Infinity;
    items.forEach((item, index) => {
      const style = getComputedStyle(item, "::marker");
      probe.style.font = getComputedStyle(item).font;
      probe.style.fontVariantNumeric = style.fontVariantNumeric;
      probe.textContent = `${(Number(list.getAttribute("start")) || 1) + index}. `;
      const markerLeft = item.getBoundingClientRect().left - probe.getBoundingClientRect().width;
      worst = Math.min(worst, markerLeft - clipLeft(list));
    });
    return { items: items.length, worstRoomPx: Number(worst.toFixed(1)) };
  });
  probe.remove();
  return report;
}

/* How far the newest block in the transcript sits above the composer's top
   edge (negative: it is behind the composer). */
function newestClearance(selector) {
  const scroller = document.querySelector("#agent-harness-stream");
  const composer = document.querySelector(".taskbar.is-agent-face");
  const column = document.querySelector("#agent-harness-stream-column");
  const blocks = [...column.children].filter((el) => !el.hidden && el.getBoundingClientRect().height > 0);
  const newest = blocks.at(-1);
  return {
    newest: newest.matches(selector),
    text: newest.textContent.trim().slice(-40),
    abovePx: Math.round(composer.getBoundingClientRect().top - newest.getBoundingClientRect().bottom),
    atEnd: scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight <= 1,
    scrollTop: scroller.scrollTop,
    scrollHeight: scroller.scrollHeight,
    clientHeight: scroller.clientHeight,
    composerHeight: composer.getBoundingClientRect().height,
    composerTop: composer.getBoundingClientRect().top,
    clearance: getComputedStyle(document.documentElement).getPropertyValue("--harness-composer-clearance"),
    t: Math.round(performance.now()),
  };
}

let browser, page, frame, cdp, stage = "launch";
let beforeClamp, launchScriptDir;
const pageErrors = [];
try {
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  const launch = { headless: true, ignoreDefaultArgs: ["--hide-scrollbars"],
    args: ["--enable-features=OverlayScrollbar"],
    ...productSmokeLaunchOptions() };
  if (process.platform === "darwin") {
    // Cocoa needs a separate value argument; Playwright only accepts switches.
    // Apply the overlay preference to this browser process with a tiny launcher.
    const probe = await chromium.launch({ ...launch, args: [...launch.args, "--enable-automation"] });
    let executable;
    try {
      const session = await probe.newBrowserCDPSession();
      executable = (await session.send("Browser.getBrowserCommandLine")).arguments[0];
    } finally { await probe.close(); }
    launchScriptDir = await mkdtemp(resolve(tmpdir(), "assistant-layout-"));
    launch.executablePath = resolve(launchScriptDir, "browser");
    const quoted = "'" + executable.replaceAll("'", "'\\''") + "'";
    await writeFile(launch.executablePath, `#!/bin/sh\nexec ${quoted} -AppleShowScrollBars WhenScrolling "$@"\n`, { mode: 0o755 });
  }
  browser = await chromium.launch(launch);
  page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
  cdp = await page.context().newCDPSession(page);
  await cdp.send("Emulation.setCPUThrottlingRate", { rate: cpuRate ?? 4 });
  page.on("pageerror", error => pageErrors.push(`${stage}: ${error}`));
  await page.goto(`http://127.0.0.1:${server.address().port}/`);
  const room = page.frameLocator("iframe").frameLocator("iframe");
  await room.locator(".agent-msg").nth(history.length - 1).waitFor({ state: "attached" });
  frame = page.frames().find(candidate => candidate.url().includes("/apps/assistant/"));

  for (const [name, iframe] of [["Home", page.locator("iframe")],
    ["GUI", page.frameLocator("iframe").locator("iframe")]]) {
    const viewport = await iframe.evaluate(node => {
      const scroller = node.ownerDocument.scrollingElement;
      return { height: scroller.clientHeight, contentHeight: scroller.scrollHeight };
    });
    assert.equal(viewport.contentHeight, viewport.height,
      `${name} fixture fills the viewport without an outer scrollbar: ${JSON.stringify(viewport)}`);
  }

  await frame.evaluate(() => {
    const s = document.querySelector("#agent-harness-stream");
    const c = document.querySelector("#agent-harness-stream-column");
    window.__scrollTrace = [];
    const trace = kind => {
      window.__scrollTrace.push({ kind, t: Math.round(performance.now()), top: s.scrollTop,
        end: s.scrollHeight - s.clientHeight, follow: s.classList.contains("is-follow-bottom"),
        phase: [...c.querySelectorAll(".agent-msg-agent")].at(-1)?.dataset.streamPhase });
      if (window.__scrollTrace.length > 120) window.__scrollTrace.shift();
    };
    document.addEventListener("scroll", e => { if (e.target === s) trace("scroll"); }, true);
    new ResizeObserver(() => trace("resize")).observe(c);
    new MutationObserver(() => trace("mutation")).observe(c, { childList: true, subtree: true, attributes: true, characterData: true });
  });
  const input = room.locator("#agent-composer-input");
  // Polls until the newest block is at the end and fully above the composer,
  // for up to 5 s; then asserts on the last measurement.
  const expectNewestAboveComposer = async (selector, label) => {
    const started = Date.now();
    const deadline = Date.now() + 5000;
    let seen = await frame.evaluate(newestClearance, selector);
    while (!(seen.newest && seen.atEnd && seen.abovePx >= 0) && Date.now() < deadline) {
      await page.waitForTimeout(50);
      seen = await frame.evaluate(newestClearance, selector);
    }
    seen.elapsedMs = Date.now() - started;
    assert.ok(seen.newest && seen.atEnd, `${label} is the newest block, at the end: ${JSON.stringify(seen)}`);
    assert.ok(seen.abovePx >= 0, `${label} sits fully above the composer: ${JSON.stringify(seen)}`);
    return seen.abovePx;
  };
  // A long follow-up being typed grows the composer upwards; wait for the
  // growth so the next measurement cannot pass on the old composer.
  const composerHeight = () => frame.evaluate(() => document.querySelector(".taskbar.is-agent-face").getBoundingClientRect().height);
  const typeLongFollowUp = async () => {
    const before = await composerHeight();
    await input.fill(Array.from({ length: 6 }, (_, i) => `Follow-up line ${i + 1}`).join("\n"));
    await frame.waitForFunction((height) =>
      document.querySelector(".taskbar.is-agent-face").getBoundingClientRect().height > height, before, { timeout: 5000 });
  };
  const seen = {};

  stage = "status line of a running turn";
  await room.locator(".agent-progress:not([hidden])").filter({ hasText: "Working out the best approach" })
    .waitFor({ timeout: 10000 });
  seen.status = await expectNewestAboveComposer(".agent-progress", "the status line");
  await typeLongFollowUp();
  seen.statusTyping = await expectNewestAboveComposer(".agent-progress", "the status line, while a follow-up is typed");

  // Let layout clamp the scroll position between the stream's final pin
  // and its idle Markdown render. A layout clamp is not a reader scrolling up.
  await frame.evaluate(() => {
    const scheduleIdle = window.requestIdleCallback;
    window.requestIdleCallback = (callback, options) => {
      window.requestIdleCallback = scheduleIdle;
      window.__finishReply = () => scheduleIdle(callback, options);
      return 0;
    };
  });

  stage = "streamed reply";
  fixture.events = [
    { sequence: 1, kind: "text_delta", data: { text: streamedList } },
    { sequence: 2, kind: "completed", data: {} },
  ];
  await room.locator(".agent-msg-agent.is-streaming").waitFor({ state: "detached", timeout: 15000 });
  await room.locator(".agent-msg-agent").last().filter({ hasText: "Streamed step 25" }).waitFor({ timeout: 5000 });
  await frame.waitForFunction(() => typeof window.__finishReply === "function", null, { timeout: 5000 });
  beforeClamp = await frame.evaluate(newestClearance, ".agent-msg-agent");
  const beforeShrink = beforeClamp.scrollTop;
  await page.setViewportSize({ width: 1280, height: 1600 });
  await input.fill("");
  await frame.waitForFunction((top) => {
    const scroller = document.querySelector("#agent-harness-stream");
    return scroller.scrollTop < top - 1 && scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight <= 1;
  }, beforeShrink, { timeout: 5000 });
  await frame.evaluate(() => new Promise(done => requestAnimationFrame(() => requestAnimationFrame(done))));
  await frame.evaluate(() => { window.__finishReply(); delete window.__finishReply; });
  await room.locator('.agent-msg-agent[data-stream-phase="presentation_done"]').last().waitFor({ timeout: 5000 });
  seen.reply = await expectNewestAboveComposer(".agent-msg-agent", "the newest reply");
  await cdp.send("Emulation.setCPUThrottlingRate", { rate: cpuRate ?? 1 });
  await page.setViewportSize({ width: 1280, height: 800 });
  await frame.evaluate(() => {
    const scroller = document.querySelector("#agent-harness-stream");
    scroller.scrollTop = scroller.scrollHeight;
    // Unchanged geometry notifications from queue rendering and resize can
    // arrive in a burst. They must keep observing the next composer growth.
    for (let i = 0; i < 9; i += 1) window.dispatchEvent(new Event("resize"));
  });
  await typeLongFollowUp();
  seen.replyTyping = await expectNewestAboveComposer(".agent-msg-agent", "the newest reply, while a follow-up is typed");

  stage = "numbered list markers";
  const markers = await frame.evaluate(markerReport, ".agent-msg-agent ol.agent-md-list");
  assert.deepEqual(markers.map(list => list.items), [12, 25], `saved and streamed lists render: ${JSON.stringify(markers)}`);
  for (const list of markers) {
    assert.ok(list.worstRoomPx >= 0, `every marker of a ${list.items}-item list is whole: ${JSON.stringify(markers)}`);
  }

  // The reader at the end sends a message. The status line shows, then a
  // fast hosted model's long reply streams in (taller than the room): the
  // status line giving way to the reply must not read as the reader
  // scrolling up. The room follows the reply while it streams and after it
  // settles into its history render.
  stage = "a sent message's long reply";
  await input.fill("");
  await frame.evaluate(() => {
    const scroller = document.querySelector("#agent-harness-stream");
    const previousReply = [...scroller.querySelectorAll(".agent-msg-agent")].at(-1);
    window.__follow = { on: true, samples: [] };
    const measure = () => {
      const jump = document.querySelector("[data-agent-jump-latest]");
      const newestReply = [...scroller.querySelectorAll(".agent-msg-agent")].at(-1);
      return { t: performance.now(), jump: Boolean(jump && !jump.hidden),
        scrollTop: scroller.scrollTop, scrollHeight: scroller.scrollHeight, clientHeight: scroller.clientHeight,
        following: scroller.classList.contains("is-follow-bottom"),
        buttonHeight: jump?.getBoundingClientRect().height || 0,
        phase: newestReply !== previousReply ? newestReply?.dataset.streamPhase : null,
        visibility: newestReply ? getComputedStyle(newestReply).contentVisibility : null,
        fromEnd: scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight };
    };
    const sample = () => {
      if (!window.__follow.on) return;
      const observed = measure();
      window.__follow.samples.push(observed);
      requestAnimationFrame(sample);
    };
    requestAnimationFrame(sample);
  });
  await input.fill("How do I plan a garden?");
  await input.press("Enter");
  await room.locator(".agent-progress:not([hidden])").last().filter({ hasText: "Working out the best approach" })
    .waitFor({ timeout: 10000 });
  // The model takes a few seconds to its first words (the status line has
  // settled). Its first chunk lands with the reply row's own scroll to the
  // end; the next scroll event then sees the end 200+ px away.
  await page.waitForTimeout(3000);
  const sent = fixture.runs.get("run-sent-1");
  assert.ok(sent, "the message started a run");
  const replyChunks = gardenReply.match(/[\s\S]{1,300}/g);
  for (const [index, text] of replyChunks.entries()) {
    sent.push({ sequence: index + 1, kind: "text_delta", data: { text } });
    await page.waitForTimeout(10);
  }
  sent.push({ sequence: replyChunks.length + 1, kind: "completed", data: {} });
  await room.locator('.agent-msg-agent[data-stream-phase="presentation_done"]').filter({ hasText: "the last line of the reply" })
    .waitFor({ state: "attached", timeout: 10000 });
  await frame.evaluate(() => new Promise(done => requestAnimationFrame(() => requestAnimationFrame(done))));
  seen.sentReply = await expectNewestAboveComposer(".agent-msg-agent", "a sent message's long reply, once settled");
  const follow = await frame.evaluate(() => {
    window.__follow.on = false;
    let behindMs = 0, since = null;
    for (const { t, fromEnd } of window.__follow.samples) {
      if (fromEnd > 8) { since ??= t; behindMs = Math.max(behindMs, t - since); } else since = null;
    }
    const completed = window.__follow.samples.filter(sample =>
      sample.phase === "finalizing" || sample.phase === "presentation_done");
    return { behindMs: Math.round(behindMs), jumpFrames: window.__follow.samples.filter(sample => sample.jump).length,
      completedFrames: completed.length, skippedNewest: completed.filter(sample => sample.visibility !== "visible"), completionGaps: completed.filter(sample => sample.fromEnd > 8) };
  });
  assert.ok(follow.completedFrames > 0, "completion frames were sampled");
  assert.deepEqual(follow.skippedNewest, [], "the newest reply cannot use the 400 px placeholder");
  assert.deepEqual(follow.completionGaps, [],
    `a reader at the end stays within 8 px on every completion frame: ${JSON.stringify(follow)}`);
  // Streaming flushes can precede their follow frame.
  assert.ok(follow.behindMs < 250, `the room follows the streaming reply: ${JSON.stringify(follow)}`);
  assert.equal(follow.jumpFrames, 0, `a reader who never left the end is not offered Jump to latest: ${JSON.stringify(follow)}`);
  seen.sentReplyBehindMs = follow.behindMs;
  seen.sentReplyCompletionFrames = follow.completedFrames;

  // A reader who moves up while a reply streams keeps their place, while more
  // of the reply keeps arriving. The move is explicit: ArrowUp and a 40 px
  // wheel, Shift+Space, or a scrollbar drag. Then Jump to latest is offered.
  const scrollState = () => frame.evaluate(() => {
    const scroller = document.querySelector("#agent-harness-stream");
    const jump = document.querySelector("[data-agent-jump-latest]");
    return { top: Math.round(scroller.scrollTop),
      fromEnd: Math.round(scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight),
      jump: Boolean(jump && !jump.hidden && jump.getBoundingClientRect().height > 0) };
  });
  const settled = () => frame.evaluate(() => new Promise(done => requestAnimationFrame(() => requestAnimationFrame(done))));
  const atEnd = () => frame.waitForFunction(() => {
    const scroller = document.querySelector("#agent-harness-stream");
    return scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight <= 8;
  }, null, { timeout: 5000 });
  // Beside the messages, inside the transcript (frame and page share
  // coordinates: both frames fill the page).
  const gutter = () => frame.evaluate(() => {
    const scroller = document.querySelector("#agent-harness-stream").getBoundingClientRect();
    const column = document.querySelector("#agent-harness-stream-column").getBoundingClientRect();
    return { x: Math.round((column.left + scroller.left) / 2), y: Math.round(scroller.top + scroller.height / 3) };
  });
  // Focus prepares keyboard scrolling without a pointer press, which leaves
  // follow. The keys below then own the reader movement.
  const focusTranscriptAWhileAgo = async () => {
    await frame.evaluate(() => {
      const scroller = document.querySelector("#agent-harness-stream");
      scroller.tabIndex = -1;
      scroller.focus({ preventScroll: true });
    });
    await page.waitForTimeout(1500);
    await atEnd();
  };
  stage = "reader leaves during the status line";
  await input.fill("Read earlier messages before the first chunk");
  await input.press("Enter");
  await room.locator(".agent-progress:not([hidden])").last().waitFor();
  const point = await gutter();
  await page.mouse.move(point.x, point.y);
  await page.mouse.wheel(0, -400);
  await page.waitForTimeout(400);
  const held = await scrollState();
  assert.ok(held.fromEnd > 300, "the reader leaves during the status line");
  const first = fixture.runs.get(`run-sent-${fixture.runs.size}`);
  first.push({ sequence: 1, kind: "reasoning_delta", data: { text: "Checking the garden plan" } });
  first.push({ sequence: 2, kind: "text_delta", data: { text: "The first chunk keeps the reader's place." } });
  first.push({ sequence: 3, kind: "completed", data: {} });
  await room.locator('.agent-msg-agent[data-stream-phase="presentation_done"]').filter({ hasText: "The first chunk keeps" }).waitFor();
  await settled();
  seen.firstChunk = { before: held, after: await scrollState() };
  assert.equal(seen.firstChunk.after.top, held.top, JSON.stringify(seen.firstChunk));

  const readerMovesUp = async (label, move, prepare = async () => {}, { sampleAfter = false, sampleOnInput = false } = {}) => {
    stage = `a reader who moves up with ${label} while a reply streams`;
    const runId = `run-sent-${fixture.runs.size + 1}`;
    const marker = `End of the reply read with ${label}.`;
    await input.fill(`Plan another garden (${label})`);
    await input.press("Enter");
    for (const deadline = Date.now() + 10000; !fixture.runs.has(runId);) {
      assert.ok(Date.now() < deadline, `${label}: the message started a run`);
      await page.waitForTimeout(20);
    }
    const run = fixture.runs.get(runId);
    const chunks = `${gardenReply}\n${marker}\n`.match(/[\s\S]{1,120}/g);
    let sent = 0;
    const pushChunk = async () => {
      if (sent >= chunks.length) return;
      run.push({ sequence: sent + 1, kind: "text_delta", data: { text: chunks[sent] } });
      sent += 1;
      await page.waitForTimeout(10);
    };
    while (sent < 8) await pushChunk();
    await room.locator(".agent-msg-agent.is-streaming").filter({ hasText: chunks[sent - 1].trim().slice(-15) }).waitFor({ timeout: 5000 });
    // A new message makes the room shrink and grow again as its reply starts
    // (the scroll position clamps down): the room still follows to the end.
    await atEnd().catch(async () => assert.fail(`${label}: the room follows the start of the reply: ${JSON.stringify(await scrollState())}`));
    await prepare(pushChunk);
    const before = await scrollState();
    // From the first move on, every frame: the reader is never pulled back
    // toward the end. A reversing gesture samples after the gesture, so the
    // reverse itself is not counted as a pull.
    const startSample = () => frame.evaluate(waitForInput => {
      const scroller = document.querySelector("#agent-harness-stream");
      window.__reader = { on: true, tops: [] };
      const sample = () => {
        if (!window.__reader.on) return;
        window.__reader.tops.push(scroller.scrollTop);
        requestAnimationFrame(sample);
      };
      const begin = () => {
        scroller.removeEventListener("pointerdown", begin);
        scroller.removeEventListener("scroll", moved);
        sample();
      };
      const moved = () => {
        if (scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight > 8) begin();
      };
      if (waitForInput) {
        // Follow may grow the reply while the pointer is still approaching.
        // Native controls can deliver the scroll without a DOM pointerdown.
        scroller.addEventListener("pointerdown", begin);
        scroller.addEventListener("scroll", moved);
      } else sample();
    }, sampleOnInput);
    if (!sampleAfter) await startSample();
    await move(pushChunk);
    const gestureEnd = sampleAfter ? await scrollState() : null;
    if (sampleAfter) await startSample();
    while (sent < chunks.length) await pushChunk();
    run.push({ sequence: chunks.length + 1, kind: "completed", data: {} });
    await room.locator('.agent-msg-agent[data-stream-phase="presentation_done"]').filter({ hasText: marker })
      .waitFor({ state: "attached", timeout: 10000 });
    await settled();
    const end = await scrollState();
    const pulled = await frame.evaluate(() => {
      window.__reader.on = false;
      const { tops } = window.__reader;
      let worst = 0;
      let worstAt = 0;
      for (let i = 1; i < tops.length; i += 1) {
        const delta = tops[i] - tops[i - 1];
        if (delta > worst) {
          worst = delta;
          worstAt = i;
        }
      }
      return {
        pulled: Math.round(worst),
        n: tops.length,
        worstAt,
        around: tops.slice(Math.max(0, worstAt - 3), worstAt + 4).map((top) => Math.round(top)),
        first: Math.round(tops[0] || 0),
        last: Math.round(tops.at(-1) || 0),
      };
    });
    const pulledBackPx = pulled.pulled;
    assert.ok(pulled.n > 0, `${label}: the reader's movement has frame samples`);
    assert.ok(pulledBackPx <= 2, `${label}: the reader is never pulled back toward the end (${pulledBackPx} px): ${JSON.stringify({ before, end, pulled })}`);
    const place = gestureEnd || before;
    assert.ok(end.top <= place.top + 2 && (gestureEnd ? end.fromEnd > 300 : end.top < before.top - 30 && end.fromEnd > 300),
      `${label}: the reader keeps their place above the end: ${JSON.stringify({ before, gestureEnd, end })}`);
    assert.ok(end.jump, `${label}: Jump to latest is offered: ${JSON.stringify(end)}`);
    return end.top - before.top;
  };
  seen.smallStepsMovedPx = await readerMovesUp("ArrowUp and a 40 px wheel", async (pushChunk) => {
    for (let step = 0; step < 4; step += 1) {
      await page.keyboard.press("ArrowUp");
      await pushChunk();
      await page.mouse.wheel(0, -40);
      await pushChunk();
    }
  }, async () => {
    await focusTranscriptAWhileAgo();
    const point = await gutter();
    await page.mouse.move(point.x, point.y);
  });
  seen.pageUpMovedPx = await readerMovesUp("PageUp", async () => {
    await page.keyboard.press("PageUp");
  }, focusTranscriptAWhileAgo);
  seen.shiftSpaceMovedPx = await readerMovesUp("Shift+Space", async (pushChunk) => {
    // More words arrive while the page-up scroll is still moving.
    await page.keyboard.press("Shift+Space");
    for (let i = 0; i < 4; i += 1) await pushChunk();
  }, focusTranscriptAWhileAgo);
  // Headless Chromium's window.find selects the match and does not scroll.
  // The Find bar scrolls that match into view. Do the same scroll here.
  const scrollFindMatchIntoView = () => frame.evaluate(() => {
    const scroller = document.querySelector("#agent-harness-stream");
    const before = scroller.scrollTop;
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "f", metaKey: true, bubbles: true }));
    document.querySelector("#agent-composer-input").focus({ preventScroll: true });
    const found = window.find("Choose the site", false, false, true);
    const sel = document.getSelection();
    const node = sel && sel.rangeCount ? sel.getRangeAt(0).startContainer : null;
    const el = node && (node.nodeType === 1 ? node : node.parentElement);
    el?.scrollIntoView({ block: "start" });
    if (scroller.scrollTop > 2) scroller.scrollTop -= 2;
    return {
      found,
      before: Math.round(before),
      after: Math.round(scroller.scrollTop),
      fromEnd: Math.round(scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight),
    };
  });
  seen.findMovedPx = await readerMovesUp("Find", async () => {
    const found = await scrollFindMatchIntoView();
    assert.ok(found.found, `Find locates earlier reply text while the composer has focus: ${JSON.stringify(found)}`);
    assert.ok(found.before - found.after > 30 && found.fromEnd > 300,
      `Find scrolls to earlier text: ${JSON.stringify(found)}`);
  }, async (pushChunk) => {
    for (let i = 0; i < 80; i += 1) await pushChunk();
    await atEnd().catch(async () => assert.fail(`Find: the room follows before the jump: ${JSON.stringify(await scrollState())}`));
  });
  seen.scrollbarMovedPx = await readerMovesUp("an overlay scrollbar drag", async (pushChunk) => {
    const box = await room.locator("#agent-harness-stream").boundingBox();
    assert.ok(box && box.width > 40 && box.height > 200, `the transcript can show a scrollbar: ${JSON.stringify(box)}`);
    // The native overlay thumb is inset from the outer edge of the scrollport.
    const x = Math.round(box.x + box.width - 6);
    // Start inside the thumb. Linux Chromium's bottom 8 px are outside
    // its draggable area, even when the scrollbar uses no layout gutter.
    const startY = Math.round(box.y + box.height - 20);
    const endY = Math.round(box.y + Math.max(24, box.height * 0.12));
    await frame.evaluate(() => {
      const scroller = document.querySelector("#agent-harness-stream");
      window.__nativeDrag = { startTop: scroller.scrollTop, moved: false };
      scroller.addEventListener("scroll", function moved() {
        if (scroller.scrollTop < window.__nativeDrag.startTop - 300) {
          window.__nativeDrag.moved = true;
          scroller.removeEventListener("scroll", moved);
        }
      });
    });
    await page.mouse.move(x, startY);
    await page.mouse.down();
    try {
      await page.mouse.move(x, endY, { steps: 14 });
      // A real upward scroll proves the native thumb took the drag. Keep
      // the final position and per-frame pull checks even after this event.
      await frame.waitForFunction(() => window.__nativeDrag.moved, null, { timeout: 5000 });
    } finally {
      await page.mouse.up();
    }
    await settled();
    const dragged = await scrollState();
    seen.scrollbarDragFromEnd = dragged.fromEnd;
    assert.ok(dragged.fromEnd > 300, `a native zero-gutter scrollbar drag moves the reader: ${JSON.stringify(dragged)}`);
    for (let i = 0; i < 2; i += 1) await pushChunk();
  }, async () => {
    const gutter = await frame.evaluate(() => {
      const scroller = document.querySelector("#agent-harness-stream");
      const natural = scroller.offsetWidth - scroller.clientWidth;
      // Keep the native thumb above the Shelf for pointer access.
      Object.assign(scroller.style, { height: "400px", maxHeight: "400px", flex: "none" });
      scroller.style.setProperty("scrollbar-width", "auto");
      scroller.style.setProperty("scrollbar-gutter", "auto");
      return { natural, overlay: scroller.offsetWidth - scroller.clientWidth };
    });
    seen.scrollbarGutterPx = gutter;
    assert.equal(gutter.overlay, 0, `the overlay scrollbar gutter takes no layout width: ${JSON.stringify(gutter)}`);
    await settled();
    await atEnd().catch(async () => assert.fail(`an overlay scrollbar: the room follows after the gutter change: ${JSON.stringify(await scrollState())}`));
    // Reveal the native overlay with actual scrolling, then return to follow
    // before sampling the drag. Hover and paint can leave a faded thumb inert.
    const box = await room.locator("#agent-harness-stream").boundingBox();
    await page.mouse.move(box.x + box.width - 40, box.y + box.height / 2);
    const startTop = (await scrollState()).top;
    await page.mouse.wheel(0, -40);
    await frame.waitForFunction(top => document.querySelector("#agent-harness-stream").scrollTop < top - 10,
      startTop, { timeout: 5000 });
    await room.locator("[data-agent-jump-latest]").click();
    await frame.waitForFunction(() => {
      const scroller = document.querySelector("#agent-harness-stream");
      return scroller.classList.contains("is-follow-bottom")
        && scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight <= 8;
    }, null, { timeout: 5000 });
  }, { sampleOnInput: true });
  await frame.evaluate(() => {
    const scroller = document.querySelector("#agent-harness-stream");
    for (const property of ["height", "max-height", "flex"]) scroller.style.removeProperty(property);
    scroller.style.removeProperty("scrollbar-width");
    scroller.style.removeProperty("scrollbar-gutter");
  });
  seen.touchReverseMovedPx = await readerMovesUp("a touch that changes direction", async () => {
    const box = await room.locator("#agent-harness-stream").boundingBox();
    assert.ok(box && box.height > 200, `the transcript can take a touch: ${JSON.stringify(box)}`);
    const x = Math.round(box.x + box.width / 2);
    const startY = Math.round(box.y + box.height * 0.65);
    const upY = Math.round(box.y + box.height * 0.20);
    const returnY = Math.round(box.y + box.height * 0.42);
    const beforeTouch = await scrollState();
    let afterTouch = beforeTouch;
    try {
      // Touch emulation turns these mouse moves into a touch. The move goes
      // into the sandboxed frame. A raw touch event stops on the outer iframe.
      await cdp.send("Emulation.setTouchEmulationEnabled", { enabled: true, maxTouchPoints: 1 });
      // Finger moves up, then reverses down while still above its start.
      await page.mouse.move(x, startY);
      await page.mouse.down();
      await page.mouse.move(x, upY, { steps: 16 });
      await page.mouse.move(x, returnY, { steps: 8 });
      await page.mouse.up();
      await settled();
      afterTouch = await scrollState();
    } finally {
      await cdp.send("Emulation.setTouchEmulationEnabled", { enabled: false });
    }
    await settled();
    const touchMoved = beforeTouch.top - afterTouch.top > 30;
    if (!touchMoved) {
      // Headless Chromium does not deliver that touch into the sandboxed frame.
      // The first upward finger travel clamps at the end; the downward
      // reversal then scrolls the reader away from the end.
      await frame.evaluate(() => {
        const scroller = document.querySelector("#agent-harness-stream");
        scroller.dispatchEvent(Object.assign(new Event("touchstart"), { touches: [{ clientY: 500 }] }));
        scroller.dispatchEvent(Object.assign(new Event("touchmove"), { touches: [{ clientY: 200 }] }));
        scroller.scrollBy(0, 900);
        scroller.dispatchEvent(Object.assign(new Event("touchmove"), { touches: [{ clientY: 400 }] }));
        scroller.scrollBy(0, -680);
      });
      afterTouch = await scrollState();
    }
    seen.touchGesture = { touchMoved, before: beforeTouch, after: afterTouch, startY, upY, returnY };
    assert.ok(afterTouch.fromEnd > 300 && afterTouch.top < beforeTouch.top - 300,
      `a reversing touch leaves the reader above the end: ${JSON.stringify(seen.touchGesture)}`);
  }, async () => {
    await page.waitForTimeout(700);
    await atEnd().catch(async () => assert.fail(`a reversing touch: the room follows before the gesture: ${JSON.stringify(await scrollState())}`));
  }, { sampleAfter: true });

  // The same scroll rule applies while streaming, before the idle Markdown
  // paint, and after completion. Hold only the painter, never a follow phase.
  const startReply = async (marker) => {
    const runId = `run-sent-${fixture.runs.size + 1}`;
    await input.fill(`Plan a garden: ${marker}`);
    await input.press("Enter");
    for (const deadline = Date.now() + 10000; !fixture.runs.has(runId);) {
      assert.ok(Date.now() < deadline, `${marker}: the run starts`);
      await page.waitForTimeout(20);
    }
    const run = fixture.runs.get(runId);
    run.push({ sequence: 1, kind: "text_delta", data: { text: `${gardenReply}\n${marker}` } });
    await room.locator(".agent-msg-agent.is-streaming").filter({ hasText: marker }).waitFor();
    await settled();
    return () => run.push({ sequence: 2, kind: "completed", data: {} });
  };
  const holdPaint = () => frame.evaluate(() => {
    const native = window.requestIdleCallback;
    window.requestIdleCallback = (callback) => {
      window.requestIdleCallback = native;
      window.__finishReply = callback;
      return 0;
    };
  });
  const finishPaint = () => frame.evaluate(() => { window.__finishReply(); delete window.__finishReply; });
  const waitForPaint = () => frame.waitForFunction(() => typeof window.__finishReply === "function");
  const holdCompletionFrame = () => frame.evaluate(() => {
    const native = window.requestAnimationFrame.bind(window);
    window.requestAnimationFrame = callback => {
      const newest = [...document.querySelectorAll(".agent-msg-agent")].at(-1);
      if (newest?.dataset.streamPhase === "presentation_done") {
        window.requestAnimationFrame = native;
        window.__cleanupReply = () => new Promise(done => native(time => { callback(time); done(); }));
        return 0;
      }
      return native(callback);
    };
  });
  const runCompletionFrame = () => frame.evaluate(async () => {
    await window.__cleanupReply();
    delete window.__cleanupReply;
  });
  const geometry = () => frame.evaluate(() => {
    const s = document.querySelector("#agent-harness-stream");
    const c = document.querySelector("#agent-harness-stream-column");
    window.__geometryStyles = [s.style.cssText, c.style.cssText];
    Object.assign(s.style, { height: "400px", maxHeight: "400px", flex: "none", padding: "0px", overflowAnchor: "none" });
    Object.assign(c.style, { height: "2600px", minHeight: "0px", overflow: "hidden" });
  });
  const restoreGeometry = () => frame.evaluate(() => {
    const s = document.querySelector("#agent-harness-stream");
    const c = document.querySelector("#agent-harness-stream-column");
    [s.style.cssText, c.style.cssText] = window.__geometryStyles;
    delete window.__geometryStyles;
  });
  const resetEnd = async () => {
    await frame.evaluate(() => {
      document.querySelector("#agent-harness-stream-column").style.height = "2600px";
      Object.assign(document.querySelector("#agent-harness-stream").style, { height: "400px", maxHeight: "400px" });
      document.querySelector("[data-agent-jump-latest]").click();
    });
    await settled();
    await settled();
    assert.equal((await scrollState()).top, 2200, "the real transcript starts at end 2200");
  };
  const layoutCase = async (label, kind, inFrame = false) => {
    stage = label;
    await resetEnd();
    const before = await frame.evaluate(async ({ kind, inFrame }) => {
      if (inFrame) await new Promise(requestAnimationFrame);
      const s = document.querySelector("#agent-harness-stream");
      const c = document.querySelector("#agent-harness-stream-column");
      let clamped = null;
      if (kind.includes("reader") || kind === "small-steps") s.dispatchEvent(new WheelEvent("wheel", { deltaY: -16, bubbles: true }));
      if (kind === "small-steps") {
        const steps = [];
        for (let i = 0; i < 3; i += 1) {
          const scrolled = new Promise(done => s.addEventListener("scroll", done, { once: true }));
          s.scrollBy(0, -3);
          await scrolled;
          steps.push(s.scrollTop);
        }
        clamped = steps;
        c.style.height = "2700px";
      } else if (kind === "small-reader-first" || kind === "large-reader-first") {
        s.scrollBy(0, kind === "small-reader-first" ? -16 : -400);
        clamped = s.scrollTop;
        c.style.height = "2700px";
      } else if (kind === "growth-then-resize") {
        c.style.height = "2700px";
        void s.scrollTop;
        s.style.height = "300px";
      } else if (kind === "resize-and-growth") {
        s.style.height = "300px";
        c.style.height = "2700px";
      } else if (kind === "clamp") {
        c.style.height = "2300px";
        clamped = s.scrollTop;
        c.style.height = "2400px";
      } else if (kind === "resize-growth" || kind === "resize-small-reader") {
        s.style.height = "300px";
        s.style.maxHeight = "300px";
        void s.clientHeight;
        if (kind === "resize-small-reader") s.scrollBy(0, -16);
      } else if (kind === "resize-reader") {
        s.style.height = "500px";
        s.style.maxHeight = "500px";
        void s.clientHeight;
        s.scrollBy(0, -16);
      } else {
        c.style.height = "2700px";
        if (kind === "small-reader") s.scrollBy(0, -16);
        if (kind === "large-reader") s.scrollBy(0, -400);
      }
      return { top: s.scrollTop, end: s.scrollHeight - s.clientHeight, clamped };
    }, { kind, inFrame });
    await settled();
    await settled();
    const after = await scrollState();
    if (kind === "clamp") assert.equal(before.clamped, 1900, `${label}: shrink clamps to 1900`);
    if (kind === "growth" || kind === "clamp" || kind === "resize-growth" || kind === "resize-and-growth" || kind === "growth-then-resize") {
      assert.ok(after.fromEnd <= 8, `${label}: layout follows: ${JSON.stringify({ before, after })}`);
      if (kind === "clamp") assert.equal(after.top, 2000, `${label}: growth pins to 2000`);
    } else {
      if (kind === "small-steps") assert.deepEqual(before.clamped, [2197, 2194, 2191], `${label}: small steps accumulate past 8 px`);
      if (kind.endsWith("-first")) assert.equal(before.top, before.clamped, `${label}: layout preserves input before growth`);
      assert.equal(after.top, before.top, `${label}: the reader owns the scroll: ${JSON.stringify({ before, after })}`);
      assert.equal(after.jump, true, `${label}: Jump is offered outside 8 px`);
    }
    return { before, after };
  };
  seen.layoutCases = {};
  for (const phase of ["streaming", "before finish", "at finish"]) {
    const marker = `End of the ${phase} regression reply.`;
    const complete = await startReply(marker);
    if (phase !== "streaming") {
      await holdPaint();
      complete();
      await waitForPaint();
      if (phase === "at finish") {
        await holdCompletionFrame();
        await finishPaint();
        await frame.waitForFunction(() => typeof window.__cleanupReply === "function");
      }
    }
    await geometry();
    for (const inFrame of [false, true]) {
      for (const kind of ["growth", "small-reader", "small-steps", "small-reader-first", "large-reader-first", "resize-reader", "resize-growth", "resize-and-growth", "growth-then-resize", "resize-small-reader", "clamp", "large-reader"]) {
        const label = `${phase}: ${kind} in ${inFrame ? "animation frame" : "task"}`;
        seen.layoutCases[label] = await layoutCase(label, kind, inFrame);
      }
    }
    await restoreGeometry();
    if (phase === "streaming") complete();
    if (phase === "before finish") await finishPaint();
    if (phase === "at finish") await runCompletionFrame();
    await room.locator('.agent-msg-agent[data-stream-phase="presentation_done"]').filter({ hasText: marker })
      .waitFor({ state: "attached", timeout: 10000 });
    await settled();
  }

  stage = "Find and Jump to latest while a reply finishes";
  const marker = "End of the Find and Jump regression reply.";
  const complete = await startReply(marker);
  await holdPaint();
  complete();
  await waitForPaint();
  const found = await scrollFindMatchIntoView();
  await settled();
  assert.equal(found.found, true, "Find selects earlier text at finish");
  const findTop = (await scrollState()).top;
  await finishPaint();
  await settled();
  assert.equal((await scrollState()).top, findTop, "completion preserves the Find result");
  seen.findAtFinish = await scrollState();

  stage = "Jump to latest before the finished paint";
  const jumpComplete = await startReply("End of the Jump regression reply.");
  await frame.evaluate(() => { const s = document.querySelector("#agent-harness-stream"); s.dispatchEvent(new WheelEvent("wheel", { deltaY: -500 })); s.scrollBy(0, -600); });
  await settled();
  await holdPaint();
  jumpComplete();
  await waitForPaint();
  await frame.evaluate(() => document.querySelector("[data-agent-jump-latest]").click());
  await finishPaint();
  await settled();
  await atEnd();
  seen.jumpDuringFinish = await scrollState();

  stage = "follow resumes across completion cleanup";
  const resumeComplete = await startReply("End of the cleanup resume regression reply.");
  await holdPaint();
  resumeComplete();
  await waitForPaint();
  await holdCompletionFrame();
  await finishPaint();
  await frame.waitForFunction(() => typeof window.__cleanupReply === "function");
  await settled();
  await frame.evaluate(() => { const s = document.querySelector("#agent-harness-stream"); s.dispatchEvent(new WheelEvent("wheel", { deltaY: -500 })); s.scrollBy(0, -500); });
  await settled();
  assert.equal((await scrollState()).jump, true);
  await frame.evaluate(() => { const s = document.querySelector("#agent-harness-stream"); s.dispatchEvent(new WheelEvent("wheel", { deltaY: s.scrollHeight })); s.scrollTop = s.scrollHeight; });
  await settled();
  await runCompletionFrame();
  await frame.evaluate(() => { const s = document.querySelector("#agent-harness-stream"); s.dispatchEvent(new WheelEvent("wheel", { deltaY: -500 })); s.scrollBy(0, -500); });
  await settled();
  assert.equal((await scrollState()).jump, true, "returning then leaving the end still shows Jump");
  seen.resume = await scrollState();

  const visibility = await frame.evaluate(() => {
    const rows = [...document.querySelectorAll(".agent-msg-agent")];
    return { newest: getComputedStyle(rows.at(-1)).contentVisibility,
      older: getComputedStyle(rows.at(-2)).contentVisibility,
      finalizing: document.querySelectorAll(".is-finalizing").length };
  });
  assert.deepEqual(visibility, { newest: "visible", older: "auto", finalizing: 0 }, "the newest row always stays laid out");

  assert.deepEqual(errors, []);
  assert.deepEqual(pageErrors, []);
  console.log(`PASS Assistant reply layout: px above the composer, longest ms behind a streaming reply ${JSON.stringify(seen)}; list markers whole (${markers.map(list => `${list.items} items, ${list.worstRoomPx}px spare`).join("; ")})`);
} catch (error) {
  console.error(`Assistant reply layout smoke failed at ${stage}`);
  if (frame) {
    const geometry = await frame.evaluate(newestClearance, ".agent-msg-agent").catch(probeError => ({ error: String(probeError) }));
    console.error(`Scroll trace: ${JSON.stringify(await frame.evaluate(() => window.__scrollTrace))}`);
    console.error(`Failure geometry: ${JSON.stringify({ beforeClamp, atFailure: geometry })}`);
  }
  console.error(JSON.stringify({ errors, pageErrors }, null, 1));
  throw error;
} finally {
  await browser?.close();
  if (launchScriptDir) {
    await unlink(resolve(launchScriptDir, "browser"));
    await rmdir(launchScriptDir);
  }
  server.close();
}
