// AUDIT-REPRO J3 (red, no fix): the Player's v1 loop and seeking.
//
// The harness (fake MediaSource, scripted fetch, manual timers) is copied
// verbatim from player.test.mjs, which does not export it.
import assert from "node:assert/strict";
import test from "node:test";

import { createPlayerController, LOOKAHEAD_SECONDS } from "./player.js";

const MINT = "a".repeat(64);
const HANDLE = "b".repeat(64);
const TOKEN = "home-token-1";

function openData(overrides = {}) {
  return {
    schema: "elastos.library.runtime-custody-viewer/v1",
    content_kind: "media",
    mint_id: MINT,
    viewer_session_handle: HANDLE,
    expires_at: 1_756_293_600,
    mime_type: "video/mp4",
    codecs: "avc1.640028,mp4a.40.2",
    has_init_segment: true,
    segment_count: 2,
    ...overrides,
  };
}

const VIDEO_V2 = { rendition: "video", mime_type: "video/mp4", codecs: "avc1.640028", segment_count: 2 };

function openDataV2(overrides = {}) {
  return {
    schema: "elastos.library.runtime-custody-viewer/v2",
    content_kind: "media",
    mint_id: MINT,
    viewer_session_handle: HANDLE,
    expires_at: 1_756_293_600,
    renditions: [VIDEO_V2],
    ...overrides,
  };
}

function within(promise, ms = 1000) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error("timed out")), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}
const turns = async (count = 8) => {
  for (let turn = 0; turn < count; turn += 1) await new Promise((r) => setImmediate(r));
};

function element(id) {
  return {
    id,
    textContent: "",
    dataset: {},
    hidden: false,
    type: "",
    className: "",
    childNodes: [],
    listeners: {},
    focused: 0,
    classList: { toggle() {} },
    appendChild(child) {
      this.childNodes.push(child);
      return child;
    },
    removeChild(child) {
      this.childNodes = this.childNodes.filter((node) => node !== child);
      return child;
    },
    addEventListener(name, handler) {
      (this.listeners[name] ||= []).push(handler);
    },
    removeAttribute() {},
    getAttribute() {
      return "";
    },
    focus() {
      this.focused += 1;
    },
    load() {},
    pause() {},
    play: async () => {},
  };
}

class FakeMediaSource {
  constructor() {
    this.readyState = "open";
    this.buffers = [];
    this.sourceBuffers = [];
    this.ended = 0;
  }

  addEventListener(name, handler) {
    // The engine opens the source on a later turn; one microtask is enough to
    // reproduce that ordering here.
    if (name === "sourceopen") queueMicrotask(handler);
  }

  addSourceBuffer(mimeType) {
    const buffer = {
      mimeType,
      appended: [],
      buffered: { length: 0, end: () => 0 },
      appendBuffer: (bytes) => {
        this.buffers.push(bytes);
        buffer.appended.push(bytes);
        for (const handler of buffer.updateEnd) handler();
      },
      updateEnd: [],
      addEventListener(name, handler) {
        if (name === "updateend") buffer.updateEnd.push(handler);
      },
      removeEventListener() {},
    };
    this.sourceBuffers.push(buffer);
    return buffer;
  }

  endOfStream() {
    this.ended += 1;
    this.readyState = "ended";
  }

  static isTypeSupported() {
    return true;
  }
}

/**
 * Gives the stub video an engine's `srcObject`: "accepts" takes a
 * MediaSource as WebKit does; "throws" refuses one with the TypeError
 * Chromium raises ("not of type MediaSourceHandle or MediaStream").
 */
function withSrcObject(video, engine) {
  video.srcObjectSet = [];
  Object.defineProperty(video, "srcObject", {
    get() {
      return video.srcObjectSet.at(-1) ?? null;
    },
    set(value) {
      if (engine === "throws" && value !== null) {
        throw new TypeError("The provided value is not of type '(MediaSourceHandle or MediaStream)'.");
      }
      video.srcObjectSet.push(value);
    },
  });
}

function harness({
  replies,
  now = 1_000_000,
  search = `?mint_id=${MINT}`,
  supported = () => true,
  srcObject = null,
}) {
  const elements = new Map(
    ["player-video", "player-status", "player-overlay", "player-overlay-text"].map((id) => [
      id,
      element(id),
    ]),
  );
  if (srcObject) withSrcObject(elements.get("player-video"), srcObject);
  const timers = [];
  const delays = [];
  const requests = [];
  const revoked = [];
  const created = [];
  let clock = now;
  let sources = [];

  const controller = createPlayerController({
    documentObject: {
      getElementById: (id) => elements.get(id),
      createElement: (tag) => element(`created-${tag}`),
    },
    windowObject: { addEventListener() {} },
    locationObject: { search, hash: `#home_token=${TOKEN}` },
    async fetchImpl(url, options) {
      requests.push({
        url,
        body: JSON.parse(options.body),
        token: options.headers["x-elastos-home-token"],
      });
      const reply = replies.shift();
      if (!reply) throw new Error("no reply queued");
      return { ok: reply.ok !== false, text: async () => JSON.stringify(reply.payload) };
    },
    mediaSourceClass: class extends FakeMediaSource {
      constructor() {
        super();
        sources.push(this);
      }

      static isTypeSupported(mimeType) {
        return supported(mimeType);
      }
    },
    urlObject: {
      createObjectURL: (value) => {
        created.push(value);
        return "blob:media";
      },
      revokeObjectURL: (value) => revoked.push(value),
    },
    nowSeconds: () => clock,
    setTimeoutImpl: (handler, ms) => {
      timers.push(handler);
      delays.push(ms);
      return timers.length;
    },
    clearTimeoutImpl: () => {},
  });

  return {
    controller,
    elements,
    requests,
    revoked,
    created,
    sources: () => sources,
    overlayText: () => elements.get("player-overlay-text").textContent,
    overlayChildren: () => elements.get("player-overlay").childNodes,
    advance: (seconds) => {
      clock += seconds;
    },
    async tick() {
      const pending = timers.splice(0, timers.length);
      for (const handler of pending) handler();
      for (let turn = 0; turn < 4; turn += 1) {
        await new Promise((resolve) => setImmediate(resolve));
      }
    },
    pendingTimers: () => timers.length,
    delays: () => delays.slice(),
  };
}

function partReply(text) {
  return {
    payload: {
      status: "ok",
      data: {
        schema: "elastos.library.runtime-custody-viewer-part/v1",
        mint_id: MINT,
        viewer_session_handle: HANDLE,
        encoding: "base64",
        data: Buffer.from(text).toString("base64"),
      },
    },
  };
}


const readsOf = (world) => world.requests.filter((request) => request.url.endsWith("read_viewer"));

// J3-F7 (= independent audit F10). v2 waits with `waitForLookahead` before
// each segment (player.js:998-1003); the v1 loop (player.js:1079-1084)
// appends every segment at once. Same pacing contract as the green v2 test
// "v2 reading waits while a rendition is buffered far ahead".
test("audit_j3_f7 v1 reading waits while the buffer is far ahead, and resumes on timeupdate", async () => {
  const world = harness({
    replies: [
      { payload: { status: "ok", data: openData({ segment_count: 4 }) } },
      partReply("init"),
      partReply("seg0"),
      partReply("seg1"),
      partReply("seg2"),
      partReply("seg3"),
    ],
  });
  const video = world.elements.get("player-video");
  video.currentTime = 0;
  let end = 0;
  const original = FakeMediaSource.prototype.addSourceBuffer;
  FakeMediaSource.prototype.addSourceBuffer = function (mime) {
    const buffer = original.call(this, mime);
    buffer.buffered = { get length() { return buffer.appended.length > 0 ? 1 : 0; }, end: () => end };
    return buffer;
  };
  try {
    // The init and segment 0 already reach far past the lookahead.
    end = LOOKAHEAD_SECONDS + 50;
    const running = world.controller.startPlayback();
    await turns(16);
    assert.equal(
      readsOf(world).length,
      2,
      "with the buffer far ahead of the playhead, segment 1 must wait for the playhead",
    );
    video.currentTime = 60;
    end = 60 + LOOKAHEAD_SECONDS;
    for (const handler of video.listeners.timeupdate || []) handler();
    await within(running);
  } finally {
    FakeMediaSource.prototype.addSourceBuffer = original;
  }
});

// J3-F8. The Player reads strictly forward and never re-reads a part
// (Runtime releases parts in order). It registers no `seeking`/`waiting`
// handler (player.js:1119-1126). A seek back into a range the browser has
// already evicted (coded-frame eviction on a long item) is never refilled and
// nothing is said: the video spins with the overlay hidden.
test("audit_j3_f8 a seek into a range that is no longer buffered is reported, not a silent spin", async () => {
  const world = harness({
    replies: [
      { payload: { status: "ok", data: openDataV2() } },
      partReply("vinit"),
      partReply("v0"),
      partReply("v1"),
    ],
  });
  const video = world.elements.get("player-video");
  await within(world.controller.startPlayback());
  assert.equal(world.sources()[0].ended, 1, "precondition: every part was read");
  assert.equal(world.elements.get("player-overlay").hidden, true, "precondition: playing");
  // The browser evicted the start; the person seeks back into it.
  const [buffer] = world.sources()[0].sourceBuffers;
  buffer.buffered = { length: 1, start: () => 100, end: () => 200 };
  video.currentTime = 10;
  for (const name of ["seeking", "waiting"]) {
    for (const handler of video.listeners[name] || []) handler();
  }
  await turns(16);
  const requestsAfter = world.requests.length;
  assert.ok(
    requestsAfter > 4 || world.elements.get("player-overlay").hidden === false,
    "a seek into an unbuffered range must either read it again or tell the person; " +
      `listeners: ${Object.keys(video.listeners).join(",")}`,
  );
});

// J3-F10 (unproven item, red; fix waits on a decision). One read that the
// pool drops (`library_error`, "Runtime custody decrypt provider is
// unavailable") stalls the Player with Try again, and the only automatic wake
// is the rights expiry (player.js readPart: `wakeInMs = untilExpiry * 1000`),
// minutes away. This is the pinned S4B-F1 (C3) rule "a read that fails before
// the rights expire stalls on the same handle until rights expiry", so a short
// automatic retry needs a decision.
test("audit_j3_f10 one dropped read is asked again within seconds, not at the rights expiry", async () => {
  const world = harness({
    replies: [
      { payload: { status: "ok", data: openData({ segment_count: 2, expires_at: 1_000_000 + 290 }) } },
      partReply("init"),
      partReply("seg0"),
      {
        ok: false,
        payload: {
          status: "error",
          code: "pool_read_unavailable",
          message: "This file isn't available from the pool right now. Try again later.",
        },
      },
      partReply("seg1"),
    ],
  });
  world.controller.startPlayback();
  await turns(16);
  const reads = world.requests.filter((request) => request.url.endsWith("read_viewer"));
  assert.equal(reads.length, 3, "precondition: the third read was dropped");
  const wake = world.delays().at(-1);
  assert.ok(
    wake !== undefined && wake <= 15_000,
    `one dropped read must be asked again within seconds; the Player waits ${wake} ms (the rights expiry)`,
  );
  world.controller.dispose();
});
