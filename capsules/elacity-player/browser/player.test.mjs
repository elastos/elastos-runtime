// What the player does between asking to open protected media and being given
// it, plus the parsing it refuses along the way.
//
// Playing is not a request that succeeds or fails once. Every first open of
// every protected item reaches a wallet that holds a rights-signature request,
// and the media arrives only after the person answers it. These tests drive
// that wait on a clock of their own, so the behaviour is checked without
// waiting through it.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  OPEN_PROGRESS_SCHEMA,
  PRESENTATION_CONTROLS_ONLY,
  PRESENTATION_IMAGE_TRACK,
  buildViewerMimeType,
  createPlayerController,
  LOOKAHEAD_SECONDS,
  MAX_VIEWER_SEGMENT_COUNT_V2,
  parseViewerOpen,
  parseViewerOpenData,
  parseViewerOpenDataV2,
  parseViewerPartData,
  presentationFor,
  readLaunchContext,
  POOL_SESSION_RENEWAL_REQUIRED,
  readOpenProgress,
  renditionHasImageTrack,
  singleFlight,
  waitingMessage,
} from "./player.js";

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

function progressPayload(overrides = {}) {
  return {
    status: "error",
    code: "library_error",
    message: "Runtime custody viewer release is pending exact Wallet approval",
    open_progress: {
      schema: OPEN_PROGRESS_SCHEMA,
      stage: "rights_approval",
      resumable: true,
      awaits_person: true,
      connector_id: "metamask",
      approval_request_id: "approval-7",
      expires_at: 1_000_290,
      ...overrides,
    },
  };
}

// ---------------------------------------------------------------------------
// The session answer
// ---------------------------------------------------------------------------

test("the launch context comes from the query and the hash, never the other way round", () => {
  assert.deepEqual(readLaunchContext({ search: `?mint_id=${MINT}`, hash: `#home_token=${TOKEN}` }), {
    mintId: MINT,
    homeToken: TOKEN,
  });
  // A token in the query is ignored: it must never travel anywhere a server
  // writes down.
  assert.deepEqual(readLaunchContext({ search: `?home_token=${TOKEN}`, hash: `#mint_id=${MINT}` }), {
    mintId: "",
    homeToken: "",
  });
});

test("a media session is read whole, and anything else is refused", () => {
  const session = parseViewerOpenData(openData(), MINT);
  assert.equal(session.segmentCount, 2);
  assert.equal(buildViewerMimeType(session.mimeType, session.codecs), 'video/mp4; codecs="avc1.640028,mp4a.40.2"');

  // A file session's geometry is a run of equal parts, not a segment ladder,
  // so it is refused here rather than misread field by field.
  assert.throws(() => parseViewerOpenData(openData({ content_kind: "object" }), MINT));
  // Another item's session, and an answer carrying a field this player does
  // not know, are both refused.
  assert.throws(() => parseViewerOpenData(openData({ mint_id: "c".repeat(64) }), MINT));
  assert.throws(() => parseViewerOpenData({ ...openData(), extra: 1 }, MINT));
  assert.throws(() => parseViewerOpenData(openData({ has_init_segment: false }), MINT));
  assert.throws(() => parseViewerOpenData(openData({ segment_count: 0 }), MINT));
});

test("a part is refused unless it belongs to this exact session", () => {
  const part = {
    schema: "elastos.library.runtime-custody-viewer-part/v1",
    mint_id: MINT,
    viewer_session_handle: HANDLE,
    encoding: "base64",
    data: Buffer.from("segment").toString("base64"),
  };
  assert.equal(parseViewerPartData(part, MINT, HANDLE).length, 7);
  assert.throws(() => parseViewerPartData(part, MINT, "d".repeat(64)));
  assert.throws(() => parseViewerPartData({ ...part, encoding: "hex" }, MINT, HANDLE));
  assert.throws(() => parseViewerPartData({ ...part, data: "" }, MINT, HANDLE));
});

test("presentation follows the rendition, and stands in for no picture it does not have", () => {
  assert.ok(renditionHasImageTrack("avc1.640028,mp4a.40.2"));
  assert.ok(!renditionHasImageTrack("mp4a.40.2"));
  assert.equal(presentationFor({ codecs: "avc1.640028" }, ""), PRESENTATION_IMAGE_TRACK);
  // Sound alone, with no poster: the frame collapses to its controls rather
  // than showing something invented.
  assert.equal(presentationFor({ codecs: "mp4a.40.2" }, ""), PRESENTATION_CONTROLS_ONLY);
});

// ---------------------------------------------------------------------------
// Reading the typed state
// ---------------------------------------------------------------------------

test("the typed open state is read from the answer, never from its sentence", () => {
  assert.deepEqual(readOpenProgress(progressPayload()), {
    stage: "rights_approval",
    resumable: true,
    awaitsPerson: true,
    connectorId: "metamask",
    expiresAt: 1_000_290,
    readyAt: 0,
  });
  assert.equal(readOpenProgress(progressPayload({ schema: "something.else/v1" })), null);
  assert.equal(readOpenProgress({ status: "error", message: "plain" }), null);
  assert.equal(
    readOpenProgress(progressPayload({ stage: "custody_recovery" })).resumable,
    false,
    "an unknown stage carries no resume policy, so it is not resumable here",
  );
});

test("the waiting sentence names where to go, and is this player's own wording", () => {
  const external = readOpenProgress(progressPayload());
  assert.match(waitingMessage(external), /metamask/);
  assert.doesNotMatch(waitingMessage(external), /Runtime|custody|release/i);
  const managed = readOpenProgress(progressPayload({ awaits_person: false, connector_id: null }));
  assert.doesNotMatch(waitingMessage(managed), /Approve/);
});

// ---------------------------------------------------------------------------
// A document stub, only as wide as the controller actually reaches
// ---------------------------------------------------------------------------

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

function harness({
  replies,
  now = 1_000_000,
  search = `?mint_id=${MINT}`,
  supported = () => true,
}) {
  const elements = new Map(
    ["player-video", "player-status", "player-overlay", "player-overlay-text"].map((id) => [
      id,
      element(id),
    ]),
  );
  const timers = [];
  const requests = [];
  const revoked = [];
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
      createObjectURL: () => "blob:media",
      revokeObjectURL: (value) => revoked.push(value),
    },
    nowSeconds: () => clock,
    setTimeoutImpl: (handler) => {
      timers.push(handler);
      return timers.length;
    },
    clearTimeoutImpl: () => {},
  });

  return {
    controller,
    elements,
    requests,
    revoked,
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

// ---------------------------------------------------------------------------
// Waiting through the ceremony
// ---------------------------------------------------------------------------

test("an open waiting on the wallet keeps waiting, and plays once the person answers", async () => {
  const world = harness({
    replies: [
      { ok: false, payload: progressPayload() },
      { payload: { status: "ok", data: openData() } },
      partReply("init"),
      partReply("seg0"),
      partReply("seg1"),
    ],
  });

  await world.controller.startPlayback();

  assert.match(world.overlayText(), /metamask/);
  assert.doesNotMatch(world.overlayText(), /unavailable/i);
  assert.equal(world.controller.getState().failed, false);
  assert.equal(world.controller.getState().waiting, true);
  assert.equal(world.pendingTimers(), 1);

  await world.tick();

  // The identical open is re-issued, so Runtime resumes the attempt it has.
  assert.deepEqual(world.requests[0].body, { mint_id: MINT });
  assert.deepEqual(world.requests[1].body, world.requests[0].body);
  assert.equal(world.controller.getState().waiting, false);
  assert.equal(world.controller.getSession().segmentCount, 2);
  // Init segment, segment 0, segment 1.
  assert.equal(world.sources()[0].buffers.length, 3);
  assert.equal(world.sources()[0].ended, 1);
});

test("a renewed Home token is used by the next viewer request", async () => {
  const world = harness({
    replies: [
      { ok: false, payload: progressPayload() },
      { ok: false, payload: progressPayload() },
    ],
  });

  await world.controller.startPlayback();
  assert.equal(world.controller.getState().waiting, true);
  // Home renewed this frame's launch authority while the open waited.
  world.controller.setHomeToken("home-token-2");
  await world.tick();

  assert.deepEqual(world.requests.map((request) => request.token), [TOKEN, "home-token-2"]);
});

test("a refusal Runtime calls final stops at once and offers nothing to press", async () => {
  const world = harness({
    replies: [
      {
        ok: false,
        payload: {
          status: "error",
          code: "library_error",
          message: "Runtime custody open is denied before purchase",
          open_progress: {
            schema: OPEN_PROGRESS_SCHEMA,
            stage: "denied",
            resumable: false,
            awaits_person: false,
          },
        },
      },
    ],
  });

  await world.controller.startPlayback();

  const state = world.controller.getState();
  assert.equal(state.failed, true);
  assert.equal(state.waiting, false);
  assert.equal(state.retryOffered, false);
  assert.equal(world.requests.length, 1, "a decided answer is not asked again");
});

test("the waiting stops when the wallet request lapses, and then the person may ask again", async () => {
  const world = harness({
    replies: [
      { ok: false, payload: progressPayload() },
      { ok: false, payload: progressPayload() },
    ],
  });

  await world.controller.startPlayback();
  assert.equal(world.controller.getState().waiting, true);

  world.advance(400);
  await world.tick();

  const state = world.controller.getState();
  assert.equal(state.failed, true);
  assert.equal(state.retryOffered, true);
  assert.equal(world.overlayChildren().length, 1, "one control, not a second sentence");
  assert.equal(world.pendingTimers(), 0);
});

test("the page going away gives back the media source and the object URL", async () => {
  const world = harness({
    replies: [
      { payload: { status: "ok", data: openData({ segment_count: 1 }) } },
      partReply("init"),
      partReply("seg0"),
      { payload: { status: "ok", data: { closed: true } } },
    ],
  });

  await world.controller.startPlayback();
  assert.equal(world.sources()[0].buffers.length, 2);

  world.controller.dispose();

  assert.equal(world.controller.getState().disposed, true);
  assert.deepEqual(world.revoked, ["blob:media"], "the object URL is given back exactly once");
  // The video element firing an error as its source is torn down repaints
  // nothing: a page that has gone away has nothing to show.
  assert.equal(world.controller.getState().failed, false);
});

test("a launch with nothing chosen explains where media comes from, once", async () => {
  const world = harness({ replies: [], search: "" });

  await world.controller.startPlayback();

  assert.match(world.overlayText(), /Library/);
  assert.doesNotMatch(world.overlayText(), /unavailable/i);
  assert.equal(world.requests.length, 0, "nothing is asked for");
  assert.equal(world.controller.getState().failed, false);
});

test("a copy awaiting chain finality is waited through, with an estimate and no wallet ask", () => {
  const now = 1_000_000;
  const finalizing = readOpenProgress(
    progressPayload({
      stage: "finalizing",
      resumable: true,
      awaits_person: false,
      connector_id: undefined,
      approval_request_id: undefined,
      expires_at: undefined,
      ready_at: now + 7 * 60 + 5,
    }),
  );
  assert.equal(finalizing.resumable, true);
  assert.equal(finalizing.readyAt, now + 7 * 60 + 5);
  const message = waitingMessage(finalizing, now);
  assert.match(message, /finalized/);
  assert.match(message, /about 8 min/);
  assert.match(message, /plays on its own/);
  assert.doesNotMatch(message, /Approve|Runtime|custody|release/i);
  // Past the estimate, the wait reads as imminent rather than as a time gone by.
  assert.match(waitingMessage(finalizing, now + 3600), /any moment/);
});

test("an open that fails without a stage offers Try again, and pressing it plays", async () => {
  const world = harness({
    replies: [
      {
        ok: false,
        payload: {
          status: "error",
          code: "library_error",
          message: "Runtime custody viewer release approval is unavailable",
        },
      },
      { payload: { status: "ok", data: openData({ segment_count: 1 }) } },
      partReply("init"),
      partReply("seg0"),
    ],
  });

  await world.controller.startPlayback();

  let state = world.controller.getState();
  assert.equal(state.failed, true);
  assert.equal(state.retryOffered, true, "the release can work on a second ask");
  assert.equal(world.pendingTimers(), 0, "a failure is not asked again on its own");
  assert.equal(world.requests.length, 1);
  const [button] = world.overlayChildren();
  assert.equal(button.textContent, "Try again");

  // Pressing it asks for the same media again, in this same page.
  button.listeners.click[0]();
  await world.tick();

  state = world.controller.getState();
  assert.equal(state.failed, false);
  assert.equal(state.retryOffered, false);
  assert.deepEqual(world.requests[1].body, { mint_id: MINT });
  assert.equal(world.sources()[0].buffers.length, 2);
});

test("a session that is not a media session offers nothing to press", async () => {
  const world = harness({
    replies: [{ payload: { status: "ok", data: openData({ content_kind: "object" }) } }],
  });

  await world.controller.startPlayback();

  const state = world.controller.getState();
  assert.equal(state.failed, true);
  assert.equal(state.retryOffered, false);
  assert.equal(world.overlayChildren().length, 0);
});

// ---------------------------------------------------------------------------
// v2: a video and an audio rendition, each in a SourceBuffer of its own
// ---------------------------------------------------------------------------

const VIDEO_V2 = { rendition: "video", mime_type: "video/mp4", codecs: "avc1.640028", segment_count: 2 };
const AUDIO_V2 = { rendition: "audio", mime_type: "audio/mp4", codecs: "mp4a.40.2", segment_count: 2 };

function openDataV2(overrides = {}) {
  return {
    schema: "elastos.library.runtime-custody-viewer/v2",
    content_kind: "media",
    mint_id: MINT,
    viewer_session_handle: HANDLE,
    expires_at: 1_756_293_600,
    renditions: [VIDEO_V2, AUDIO_V2],
    ...overrides,
  };
}

const text = (bytes) => Buffer.from(bytes).toString();

test("a v2 answer is read whole, ordered video first, and refused when it strays from the pins", () => {
  const session = parseViewerOpenDataV2(openDataV2({ renditions: [AUDIO_V2, VIDEO_V2] }), MINT);
  assert.deepEqual(
    session.renditions.map((r) => [r.kind, r.segmentCount]),
    [
      ["video", 2],
      ["audio", 2],
    ],
  );
  assert.equal(session.codecs, "avc1.640028,mp4a.40.2");
  assert.equal(parseViewerOpen(openDataV2(), MINT).renditions.length, 2);
  assert.equal(parseViewerOpen(openData(), MINT).segmentCount, 2, "v1 still parses as v1");

  assert.equal(parseViewerOpenDataV2(openDataV2({ renditions: [AUDIO_V2] }), MINT).renditions.length, 1);
  assert.throws(() => parseViewerOpenDataV2(openDataV2({ renditions: [] }), MINT));
  assert.throws(() => parseViewerOpenDataV2(openDataV2({ renditions: [VIDEO_V2, VIDEO_V2] }), MINT));
  assert.throws(() =>
    parseViewerOpenDataV2(openDataV2({ renditions: [VIDEO_V2, AUDIO_V2, AUDIO_V2] }), MINT),
  );
  assert.throws(() =>
    parseViewerOpenDataV2(openDataV2({ renditions: [{ ...VIDEO_V2, codecs: "hev1.1.6.L93.B0" }] }), MINT),
  );
  assert.throws(() =>
    parseViewerOpenDataV2(openDataV2({ renditions: [{ ...AUDIO_V2, codecs: "mp4a.40.5" }] }), MINT),
  );
  assert.throws(() =>
    parseViewerOpenDataV2(openDataV2({ renditions: [{ ...AUDIO_V2, mime_type: "video/mp4" }] }), MINT),
  );
  assert.throws(() =>
    parseViewerOpenDataV2(openDataV2({ renditions: [{ ...VIDEO_V2, segment_count: 0 }] }), MINT),
  );
  assert.throws(() =>
    parseViewerOpenDataV2(openDataV2({ renditions: [{ ...VIDEO_V2, extra: 1 }] }), MINT),
  );
  assert.throws(() => parseViewerOpenDataV2({ ...openDataV2(), extra: 1 }, MINT));
  assert.throws(() => parseViewerOpenDataV2(openDataV2({ mint_id: "c".repeat(64) }), MINT));
  assert.throws(() => parseViewerOpenDataV2(openDataV2({ content_kind: "object" }), MINT));
  assert.throws(() => parseViewerOpenDataV2(openDataV2({ schema: "x/v2" }), MINT));
});

test("v2 parts are read in the fixed interleave and land in the right buffer", async () => {
  const world = harness({
    replies: [
      { payload: { status: "ok", data: openDataV2() } },
      partReply("vinit"),
      partReply("ainit"),
      partReply("v0"),
      partReply("a0"),
      partReply("v1"),
      partReply("a1"),
    ],
  });
  const playedAfter = [];
  world.elements.get("player-video").play = async () => {
    playedAfter.push(world.requests.length);
  };

  await within(world.controller.startPlayback());

  assert.deepEqual(
    world.requests.slice(1).map((request) => request.body.segment_index ?? "init"),
    ["init", "init", 0, 0, 1, 1],
  );
  const [video, audio] = world.sources()[0].sourceBuffers;
  assert.equal(video.mimeType, 'video/mp4; codecs="avc1.640028"');
  assert.equal(audio.mimeType, 'audio/mp4; codecs="mp4a.40.2"');
  assert.deepEqual(video.appended.map(text), ["vinit", "v0", "v1"]);
  assert.deepEqual(audio.appended.map(text), ["ainit", "a0", "a1"]);
  assert.equal(world.sources()[0].ended, 1);
  assert.deepEqual(playedAfter, [1 + 2 + 2], "play follows the first segment pair, not before");
  assert.equal(world.controller.getState().failed, false);
});

test("v2 renditions whose counts differ by one skip the missing segment", async () => {
  const world = harness({
    replies: [
      { payload: { status: "ok", data: openDataV2({ renditions: [{ ...VIDEO_V2, segment_count: 3 }, AUDIO_V2] }) } },
      partReply("vinit"),
      partReply("ainit"),
      partReply("v0"),
      partReply("a0"),
      partReply("v1"),
      partReply("a1"),
      partReply("v2"),
    ],
  });

  await within(world.controller.startPlayback());

  const [video, audio] = world.sources()[0].sourceBuffers;
  assert.deepEqual(video.appended.map(text), ["vinit", "v0", "v1", "v2"]);
  assert.deepEqual(audio.appended.map(text), ["ainit", "a0", "a1"]);
  assert.equal(world.sources()[0].ended, 1);
  // Exactly seven parts were asked for: no read is made for the audio segment
  // that does not exist.
  assert.equal(world.requests.length, 1 + 7);
  assert.equal(world.controller.getState().failed, false);
});

test("an audio-only v2 item keeps the controls-only presentation and uses one buffer", async () => {
  const world = harness({
    replies: [
      { payload: { status: "ok", data: openDataV2({ renditions: [AUDIO_V2] }) } },
      partReply("ainit"),
      partReply("a0"),
      partReply("a1"),
    ],
  });
  const toggles = [];
  world.elements.get("player-video").classList = { toggle: (name, on) => toggles.push([name, on]) };

  await within(world.controller.startPlayback());

  assert.deepEqual(toggles, [["audio-only", true]]);
  assert.equal(world.sources()[0].sourceBuffers.length, 1);
  assert.equal(world.sources()[0].ended, 1);
});

test("a v2 item needs both mime types supported, or the browser is said not to play it", async () => {
  const world = harness({
    supported: (mime) => mime.startsWith("video/"),
    replies: [{ payload: { status: "ok", data: openDataV2() } }, { payload: { status: "ok", data: { closed: true } } }],
  });

  await within(world.controller.startPlayback());

  assert.equal(world.controller.getState().failed, true);
  assert.match(world.overlayText(), /cannot play/);
  assert.equal(world.requests.some((r) => r.url.endsWith("read_viewer")), false);
});

test("v2 reading waits while a rendition is buffered far ahead, and resumes on timeupdate", async () => {
  const world = harness({
    replies: [
      { payload: { status: "ok", data: openDataV2() } },
      partReply("vinit"),
      partReply("ainit"),
      partReply("v0"),
      partReply("a0"),
      partReply("v1"),
      partReply("a1"),
    ],
  });
  const video = world.elements.get("player-video");
  video.currentTime = 0;
  let videoEnd = 0;
  const original = FakeMediaSource.prototype.addSourceBuffer;
  FakeMediaSource.prototype.addSourceBuffer = function (mime) {
    const buffer = original.call(this, mime);
    if (mime.startsWith("video/")) {
      buffer.buffered = { get length() { return buffer.appended.length > 1 ? 1 : 0; }, end: () => videoEnd };
    }
    return buffer;
  };
  try {
    videoEnd = LOOKAHEAD_SECONDS + 50;
    const running = world.controller.startPlayback();
    for (let turn = 0; turn < 8; turn += 1) await new Promise((r) => setImmediate(r));
    // Both inits and the first pair are in; segment 1 is held back.
    assert.equal(world.requests.length, 1 + 2 + 2);

    video.currentTime = 40;
    videoEnd = 40 + LOOKAHEAD_SECONDS;
    for (const handler of video.listeners.timeupdate) handler();
    await within(running);

    assert.equal(world.requests.length, 1 + 2 + 4);
    assert.equal(world.sources()[0].ended, 1);
  } finally {
    FakeMediaSource.prototype.addSourceBuffer = original;
  }
});

test("a v2 page going away releases a read waiting on the playhead", async () => {
  const world = harness({
    replies: [
      { payload: { status: "ok", data: openDataV2() } },
      partReply("vinit"),
      partReply("ainit"),
      partReply("v0"),
      partReply("a0"),
      { payload: { status: "ok", data: { closed: true } } },
    ],
  });
  const original = FakeMediaSource.prototype.addSourceBuffer;
  FakeMediaSource.prototype.addSourceBuffer = function (mime) {
    const buffer = original.call(this, mime);
    buffer.buffered = { get length() { return buffer.appended.length > 1 ? 1 : 0; }, end: () => 1000 };
    return buffer;
  };
  try {
    const running = world.controller.startPlayback();
    for (let turn = 0; turn < 8; turn += 1) await new Promise((r) => setImmediate(r));
    world.controller.dispose();
    await within(running);
    assert.equal(world.controller.getState().disposed, true);
    assert.equal(world.requests.filter((r) => r.url.endsWith("read_viewer")).length, 4);
  } finally {
    FakeMediaSource.prototype.addSourceBuffer = original;
  }
});

test("a v2 part that does not arrive stalls on the same session with Try again (C3)", async () => {
  const world = harness({
    replies: [
      { payload: { status: "ok", data: openDataV2() } },
      partReply("vinit"),
      partReply("ainit"),
      { ok: false, payload: { status: "error", message: "part is unavailable" } },
    ],
  });

  world.controller.startPlayback();
  await turns(16);

  const state = world.controller.getState();
  assert.equal(state.failed, false);
  assert.equal(state.closed, false);
  assert.equal(state.retryOffered, true);
  assert.match(world.overlayText(), /part is unavailable/);
  assert.equal(world.requests.at(-1).url.endsWith("read_viewer"), true, "nothing is closed");
  world.controller.dispose();
});

// ---------------------------------------------------------------------------
// v2 fix round 1: exact pins, strict numbers, and the behaviours mutation found unguarded
// ---------------------------------------------------------------------------

// A parked read that is never released would hang a test; this turns that into
// a failed assertion.
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

/** Runs `body` with every new SourceBuffer passed through `patch(buffer, mime)`. */
async function withPatchedBuffers(patch, body) {
  const original = FakeMediaSource.prototype.addSourceBuffer;
  FakeMediaSource.prototype.addSourceBuffer = function (mime) {
    const buffer = original.call(this, mime);
    patch(buffer, mime);
    return buffer;
  };
  try {
    await body();
  } finally {
    FakeMediaSource.prototype.addSourceBuffer = original;
  }
}

const farAhead = (seconds) => (buffer) => {
  buffer.buffered = {
    get length() {
      return buffer.appended.length > 1 ? 1 : 0;
    },
    end: () => seconds,
  };
};

test("the v2 video codec is pinned exactly, not by family", () => {
  for (const codecs of ["avc1.64001f", "avc1.42e01e", "avc1.640029", "AVC1.640028", "avc1.640028 "]) {
    assert.throws(
      () => parseViewerOpenDataV2(openDataV2({ renditions: [{ ...VIDEO_V2, codecs }] }), MINT),
      undefined,
      codecs,
    );
  }
  assert.equal(parseViewerOpenDataV2(openDataV2({ renditions: [VIDEO_V2] }), MINT).codecs, "avc1.640028");
});

test("v2 numbers must be real integers, not strings or booleans", () => {
  for (const bad of ["2", true, " 2 ", 2.5, null]) {
    assert.throws(() =>
      parseViewerOpenDataV2(openDataV2({ renditions: [{ ...VIDEO_V2, segment_count: bad }] }), MINT),
    );
  }
  for (const bad of ["1756293600", true, 1.5, null]) {
    assert.throws(() => parseViewerOpenDataV2(openDataV2({ expires_at: bad }), MINT));
  }
});

test("the v2 segment count is bounded at 2^20", () => {
  const withCount = (segment_count) =>
    openDataV2({ renditions: [{ ...VIDEO_V2, segment_count }] });
  assert.equal(MAX_VIEWER_SEGMENT_COUNT_V2, 1 << 20);
  assert.equal(parseViewerOpenDataV2(withCount(1 << 20), MINT).renditions[0].segmentCount, 1 << 20);
  assert.throws(() => parseViewerOpenDataV2(withCount((1 << 20) + 1), MINT));
});

test("a video-only v2 item plays through one buffer", async () => {
  const world = harness({
    replies: [
      { payload: { status: "ok", data: openDataV2({ renditions: [VIDEO_V2] }) } },
      partReply("vinit"),
      partReply("v0"),
      partReply("v1"),
    ],
  });
  const toggles = [];
  world.elements.get("player-video").classList = { toggle: (name, on) => toggles.push([name, on]) };

  await within(world.controller.startPlayback());

  assert.deepEqual(toggles, [["audio-only", false]]);
  const [video] = world.sources()[0].sourceBuffers;
  assert.equal(world.sources()[0].sourceBuffers.length, 1);
  assert.deepEqual(video.appended.map(text), ["vinit", "v0", "v1"]);
  assert.equal(world.sources()[0].ended, 1);
  assert.equal(world.controller.getState().failed, false);
});

test("a buffer 20 s ahead is below the lookahead and is read without waiting", async () => {
  const world = harness({
    replies: [
      { payload: { status: "ok", data: openDataV2() } },
      partReply("vinit"),
      partReply("ainit"),
      partReply("v0"),
      partReply("a0"),
      partReply("v1"),
      partReply("a1"),
    ],
  });
  world.elements.get("player-video").currentTime = 0;
  await withPatchedBuffers(farAhead(20), async () => {
    await within(world.controller.startPlayback());
  });
  assert.equal(world.requests.length, 1 + 6);
  assert.equal(world.sources()[0].ended, 1);
});

test("a buffer exactly at the lookahead is read; one second past it waits", async () => {
  for (const [ahead, reads] of [
    [30, 6],
    [31, 4],
  ]) {
    const world = harness({
      replies: [
        { payload: { status: "ok", data: openDataV2() } },
        partReply("vinit"),
        partReply("ainit"),
        partReply("v0"),
        partReply("a0"),
        partReply("v1"),
        partReply("a1"),
      ],
    });
    world.elements.get("player-video").currentTime = 0;
    await withPatchedBuffers(farAhead(ahead), async () => {
      const running = world.controller.startPlayback();
      await turns();
      assert.equal(world.requests.length, 1 + reads, `ahead ${ahead}`);
      world.controller.dispose();
      await within(running);
    });
  }
});

test("a failure releases a read parked on the playhead", async () => {
  const world = harness({
    replies: [
      { payload: { status: "ok", data: openDataV2() } },
      partReply("vinit"),
      partReply("ainit"),
      partReply("v0"),
      partReply("a0"),
      { payload: { status: "ok", data: { closed: true } } },
    ],
  });
  const video = world.elements.get("player-video");
  video.currentTime = 0;
  await withPatchedBuffers(farAhead(1000), async () => {
    const running = world.controller.startPlayback();
    await turns();
    assert.equal(world.requests.length, 1 + 4, "segment 1 is held back");
    // The video element reports an error while the read is parked.
    for (const handler of video.listeners.error) handler();
    await within(running);
    assert.equal(world.controller.getState().failed, true);
    assert.equal(world.requests.filter((r) => r.url.endsWith("read_viewer")).length, 4);
  });
});

test("a page going away releases a parked read (asserted, not hung)", async () => {
  const world = harness({
    replies: [
      { payload: { status: "ok", data: openDataV2() } },
      partReply("vinit"),
      partReply("ainit"),
      partReply("v0"),
      partReply("a0"),
      { payload: { status: "ok", data: { closed: true } } },
    ],
  });
  world.elements.get("player-video").currentTime = 0;
  await withPatchedBuffers(farAhead(1000), async () => {
    const running = world.controller.startPlayback();
    await turns();
    world.controller.dispose();
    await within(running);
  });
});

function quotaError() {
  const error = new Error("The SourceBuffer is full.");
  error.name = "QuotaExceededError";
  return error;
}

test("a v2 buffer that throws QuotaExceededError goes through fail()", async () => {
  const world = harness({
    replies: [
      { payload: { status: "ok", data: openDataV2() } },
      partReply("vinit"),
      partReply("ainit"),
      partReply("v0"),
      partReply("a0"),
      { payload: { status: "ok", data: { closed: true } } },
    ],
  });
  await withPatchedBuffers(
    (buffer, mime) => {
      if (!mime.startsWith("audio/")) return;
      const append = buffer.appendBuffer;
      buffer.appendBuffer = (bytes) => {
        if (buffer.appended.length >= 1) throw quotaError();
        append(bytes);
      };
    },
    async () => within(world.controller.startPlayback()),
  );
  const state = world.controller.getState();
  assert.equal(state.failed, true);
  assert.equal(state.retryOffered, true);
  assert.match(world.overlayText(), /full/);
  assert.equal(world.requests.at(-1).url.endsWith("close_viewer"), true);
});

test("a v2 buffer that throws synchronously from appendBuffer on the first init goes through fail()", async () => {
  const world = harness({
    replies: [
      { payload: { status: "ok", data: openDataV2() } },
      partReply("vinit"),
      { payload: { status: "ok", data: { closed: true } } },
    ],
  });
  await withPatchedBuffers(
    (buffer, mime) => {
      if (!mime.startsWith("video/")) return;
      buffer.appendBuffer = () => {
        throw new Error("InvalidStateError");
      };
    },
    async () => within(world.controller.startPlayback()),
  );
  const state = world.controller.getState();
  assert.equal(state.failed, true);
  assert.match(world.overlayText(), /InvalidStateError/);
  assert.equal(world.requests.at(-1).url.endsWith("close_viewer"), true);
  assert.equal(world.requests.filter((r) => r.url.endsWith("read_viewer")).length, 1);
});

test("a v2 buffer error event goes through fail()", async () => {
  const world = harness({
    replies: [
      { payload: { status: "ok", data: openDataV2() } },
      partReply("vinit"),
      { payload: { status: "ok", data: { closed: true } } },
    ],
  });
  await withPatchedBuffers(
    (buffer, mime) => {
      if (!mime.startsWith("video/")) return;
      const handlers = [];
      buffer.addEventListener = (name, handler) => {
        if (name === "error") handlers.push(handler);
      };
      buffer.appendBuffer = () => handlers.forEach((handler) => handler());
    },
    async () => within(world.controller.startPlayback()),
  );
  assert.equal(world.controller.getState().failed, true);
  assert.match(world.overlayText(), /Media data is unavailable/);
});

// ---------------------------------------------------------------------------
// User decision 2026-11-13 13:05: the delivery key stays in the Runtime log;
// the approval message is the plain sentence
// ---------------------------------------------------------------------------

const DELIVERY_KEY = "0x0123456789abcdef";

test("approval_stage_shows_no_delivery_key", async () => {
  // Even an answer that still names a delivery key (an older Runtime) shows
  // only the plain approval sentence, and the key is not read.
  const world = harness({
    replies: [{ ok: false, payload: progressPayload({ delivery_key_fingerprint: DELIVERY_KEY }) }],
  });
  await world.controller.startPlayback();
  assert.equal(world.controller.getState().waiting, true);
  assert.match(world.overlayText(), /Approve playing this in metamask\. It plays on its own once you do\./);
  assert.doesNotMatch(world.overlayText(), /Delivery key/);
  const progress = readOpenProgress(progressPayload({ delivery_key_fingerprint: DELIVERY_KEY }));
  assert.equal("deliveryKeyFingerprint" in progress, false);
  assert.equal(waitingMessage(progress), "Approve playing this in metamask. It plays on its own once you do.");
  const managed = readOpenProgress(
    progressPayload({ awaits_person: false, connector_id: null, delivery_key_fingerprint: DELIVERY_KEY }),
  );
  assert.doesNotMatch(waitingMessage(managed), /Delivery key/);
});

// ---------------------------------------------------------------------------
// Plan B T4.5 (C3): one Wallet prompt at rights expiry, then the same place
// ---------------------------------------------------------------------------

const RENEWED = "c".repeat(64);

function partReplyFor(text, handle) {
  const reply = partReply(text);
  reply.payload.data.viewer_session_handle = handle;
  return reply;
}

function renewalRequired() {
  return {
    ok: false,
    payload: {
      status: "error",
      code: "pool_session_renewal_required",
      message: "Runtime custody viewer session needs a new approval",
    },
  };
}

const opensOf = (world) => world.requests.filter((request) => request.url.endsWith("open_viewer"));

test("renewal_required_reopens_and_resumes_at_the_same_position", async () => {
  const world = harness({
    replies: [
      { payload: { status: "ok", data: openData({ segment_count: 3 }) } },
      partReply("init"),
      partReply("seg0"),
      // The rights expired: this read is answered with the one reopen.
      renewalRequired(),
      { payload: { status: "ok", data: openData({ segment_count: 3, viewer_session_handle: RENEWED }) } },
      partReplyFor("seg1", RENEWED),
      partReplyFor("seg2", RENEWED),
    ],
  });

  await within(world.controller.startPlayback());

  assert.equal(world.controller.getState().failed, false);
  assert.equal(opensOf(world).length, 2, "one open for the session, one at rights expiry");
  assert.deepEqual(opensOf(world)[1].body, { mint_id: MINT });
  // The read that met the expiry is asked again, at the same segment, on the
  // new session; nothing before it is read twice.
  const reads = world.requests.filter((request) => request.url.endsWith("read_viewer"));
  assert.deepEqual(
    reads.map((request) => [request.body.segment_index ?? "init", request.body.viewer_session_handle]),
    [
      ["init", HANDLE],
      [0, HANDLE],
      [1, HANDLE],
      [1, RENEWED],
      [2, RENEWED],
    ],
  );
  assert.deepEqual(world.sources()[0].buffers.map(text), ["init", "seg0", "seg1", "seg2"]);
  assert.equal(world.sources().length, 1, "the same media source plays on");
  assert.equal(world.controller.getSession().viewerSessionHandle, RENEWED);
  assert.equal(world.sources()[0].ended, 1);
});

test("rights_expiry_shows_the_approval_stage_not_retry", async () => {
  const world = harness({
    replies: [
      { payload: { status: "ok", data: openData({ segment_count: 2 }) } },
      partReply("init"),
      partReply("seg0"),
      renewalRequired(),
      { ok: false, payload: progressPayload({ delivery_key_fingerprint: DELIVERY_KEY }) },
      { payload: { status: "ok", data: openData({ viewer_session_handle: RENEWED }) } },
      partReplyFor("seg1", RENEWED),
    ],
  });

  const playing = world.controller.startPlayback();
  await turns(16);

  // The one Wallet prompt: the approval stage, with nothing to press.
  let state = world.controller.getState();
  assert.equal(state.failed, false);
  assert.equal(state.retryOffered, false);
  assert.equal(state.waiting, true);
  assert.equal(state.waitingStage, "rights_approval");
  assert.equal(world.overlayChildren().length, 0, "no Retry button");
  assert.match(world.overlayText(), /Approve playing this in metamask/);
  assert.doesNotMatch(world.overlayText(), /Delivery key/);
  assert.doesNotMatch(world.overlayText(), /unavailable/i);

  // The person approves; the identical open is asked again and plays on.
  await world.tick();
  await within(playing);
  state = world.controller.getState();
  assert.equal(state.failed, false);
  assert.equal(state.waiting, false);
  assert.equal(opensOf(world).length, 3);
  assert.deepEqual(opensOf(world)[2].body, opensOf(world)[1].body);
  assert.deepEqual(world.sources()[0].buffers.map(text), ["init", "seg0", "seg1"]);
});

test("an early read error is not a reopen: no extra open, no Wallet", async () => {
  const world = harness({
    replies: [
      { payload: { status: "ok", data: openData({ segment_count: 2 }) } },
      partReply("init"),
      partReply("seg0"),
      {
        ok: false,
        payload: {
          status: "error",
          code: "library_error",
          message: "Runtime custody viewer session is unavailable",
        },
      },
    ],
  });

  world.controller.startPlayback();
  await turns(16);

  // C3 (S4B-F1): the read stalls on the same handle; nothing is closed.
  assert.equal(opensOf(world).length, 1, "zero extra opens before rights expiry");
  const state = world.controller.getState();
  assert.equal(state.failed, false);
  assert.equal(state.closed, false);
  assert.equal(state.retryOffered, true);
  assert.equal(closesOf(world).length, 0, "the session is kept");
  world.controller.dispose();
});

// S4B-F1 (C3): a read that fails before the rights expire keeps the same
// handle and its budget. Retry asks the same read again; only the rights
// expiry reopens, once, with the one Wallet prompt.

const EXPIRES = 1_000_100;

function serverLost() {
  return {
    ok: false,
    payload: {
      status: "error",
      code: "library_error",
      message: "Runtime custody decrypt provider is unavailable",
    },
  };
}

const closesOf = (world) => world.requests.filter((request) => request.url.endsWith("close_viewer"));
const readsOf = (world) =>
  world.requests
    .filter((request) => request.url.endsWith("read_viewer"))
    .map((request) => [request.body.segment_index ?? "init", request.body.viewer_session_handle]);

function pressRetry(world) {
  const [button] = world.overlayChildren();
  assert.equal(button?.textContent, "Try again");
  button.listeners.click[0]();
}

test("early budget exhaustion stalls on the same handle until rights expiry, then reopens once", async () => {
  const world = harness({
    replies: [
      { payload: { status: "ok", data: openData({ segment_count: 3, expires_at: EXPIRES }) } },
      partReply("init"),
      partReply("seg0"),
      // The byte budget is spent: the server gives no part before the expiry.
      serverLost(),
      serverLost(),
      // At the rights expiry the same read meets the session's end.
      renewalRequired(),
      {
        payload: {
          status: "ok",
          data: openData({ segment_count: 3, expires_at: EXPIRES + 600, viewer_session_handle: RENEWED }),
        },
      },
      partReplyFor("seg1", RENEWED),
      partReplyFor("seg2", RENEWED),
    ],
  });

  const playing = world.controller.startPlayback();
  await turns(16);
  let state = world.controller.getState();
  assert.equal(state.failed, false);
  assert.equal(state.closed, false);
  assert.equal(state.retryOffered, true);

  // Retry asks the same read on the same handle: no open, no close.
  pressRetry(world);
  await turns(16);
  assert.equal(opensOf(world).length, 1, "zero Wallet calls before expiry");
  assert.equal(closesOf(world).length, 0, "zero release calls before expiry");
  assert.deepEqual(readsOf(world), [
    ["init", HANDLE],
    [0, HANDLE],
    [1, HANDLE],
    [1, HANDLE],
  ]);
  assert.equal(world.controller.getState().retryOffered, true);

  // The rights expire: the stalled read is asked once more and reopens once.
  world.advance(EXPIRES - 1_000_000);
  await world.tick();
  await within(playing);

  state = world.controller.getState();
  assert.equal(state.failed, false);
  assert.equal(opensOf(world).length, 2, "exactly one open after expiry");
  assert.equal(closesOf(world).length, 0);
  assert.deepEqual(readsOf(world).slice(4), [
    [1, HANDLE],
    [1, RENEWED],
    [2, RENEWED],
  ]);
  assert.deepEqual(world.sources()[0].buffers.map(text), ["init", "seg0", "seg1", "seg2"]);
  assert.equal(world.sources().length, 1, "the same media source plays on");
});

test("an early server loss stalls; Retry reads on, and the rights expiry reopens once", async () => {
  const world = harness({
    replies: [
      { payload: { status: "ok", data: openData({ segment_count: 4, expires_at: EXPIRES }) } },
      partReply("init"),
      partReply("seg0"),
      serverLost(),
      // The server is back: Retry reads on with the same handle.
      partReply("seg1"),
      serverLost(),
      renewalRequired(),
      {
        payload: {
          status: "ok",
          data: openData({ segment_count: 4, expires_at: EXPIRES + 600, viewer_session_handle: RENEWED }),
        },
      },
      partReplyFor("seg2", RENEWED),
      partReplyFor("seg3", RENEWED),
    ],
  });

  const playing = world.controller.startPlayback();
  await turns(16);
  pressRetry(world);
  await turns(16);

  // The read after Retry played on; the next loss stalls again.
  assert.equal(world.controller.getState().failed, false);
  assert.equal(world.controller.getState().retryOffered, true);
  assert.equal(opensOf(world).length, 1, "zero Wallet calls before expiry");
  assert.equal(closesOf(world).length, 0, "zero release calls before expiry");

  world.advance(EXPIRES - 1_000_000);
  await world.tick();
  await within(playing);

  assert.equal(world.controller.getState().failed, false);
  assert.equal(opensOf(world).length, 2, "exactly one open after expiry");
  assert.equal(closesOf(world).length, 0);
  assert.deepEqual(readsOf(world), [
    ["init", HANDLE],
    [0, HANDLE],
    [1, HANDLE],
    [1, HANDLE],
    [2, HANDLE],
    [2, HANDLE],
    [2, RENEWED],
    [3, RENEWED],
  ]);
  assert.deepEqual(world.sources()[0].buffers.map(text), ["init", "seg0", "seg1", "seg2", "seg3"]);
});

test("a browser clock past the expiry never reopens without the Runtime's typed answer", async () => {
  const world = harness({
    replies: [
      // The browser clock (1_000_000) is already past this session's end.
      { payload: { status: "ok", data: openData({ segment_count: 3, expires_at: 999_000 }) } },
      partReply("init"),
      partReply("seg0"),
      // The Runtime still answers ordinary early failures.
      serverLost(),
      serverLost(),
      serverLost(),
      serverLost(),
      // Only its typed expiry answer reopens.
      renewalRequired(),
      {
        payload: {
          status: "ok",
          data: openData({ segment_count: 3, expires_at: 1_000_600, viewer_session_handle: RENEWED }),
        },
      },
      partReplyFor("seg1", RENEWED),
      partReplyFor("seg2", RENEWED),
    ],
  });

  const playing = world.controller.startPlayback();
  await turns(16);
  // The local timer only wakes the same read on the same handle, a bounded
  // number of times once it has elapsed.
  for (let wake = 0; wake < 3; wake += 1) await world.tick();
  assert.equal(world.pendingTimers(), 0, "no more automatic reads once the bound is reached");
  const state = world.controller.getState();
  assert.equal(state.failed, false);
  assert.equal(state.closed, false);
  assert.equal(state.retryOffered, true);
  assert.equal(opensOf(world).length, 1, "zero extra opens without the typed expiry");
  assert.equal(closesOf(world).length, 0, "zero closes");
  assert.deepEqual(readsOf(world), [
    ["init", HANDLE],
    [0, HANDLE],
    [1, HANDLE],
    [1, HANDLE],
    [1, HANDLE],
    [1, HANDLE],
  ]);

  // Retry reads the same handle; the typed answer reopens exactly once.
  pressRetry(world);
  await within(playing);
  assert.equal(world.controller.getState().failed, false);
  assert.equal(opensOf(world).length, 2, "exactly one reopen");
  assert.equal(closesOf(world).length, 0);
  assert.deepEqual(readsOf(world).slice(6), [
    [1, HANDLE],
    [1, RENEWED],
    [2, RENEWED],
  ]);
  assert.deepEqual(world.sources()[0].buffers.map(text), ["init", "seg0", "seg1", "seg2"]);
});

test("two concurrent renewal-required reads reopen once", async () => {
  let calls = 0;
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  const reopen = singleFlight(async () => {
    calls += 1;
    await gate;
    return "renewed";
  });
  const first = reopen();
  const second = reopen();
  assert.equal(first, second, "the second caller shares the reopen in flight");
  release();
  assert.deepEqual(await Promise.all([first, second]), ["renewed", "renewed"]);
  assert.equal(calls, 1);
  // Once settled, a later expiry reopens again.
  await reopen();
  assert.equal(calls, 2);
  assert.equal(POOL_SESSION_RENEWAL_REQUIRED, "pool_session_renewal_required");
});

test("a page going away while the reopen waits on the Wallet asks nothing more", async () => {
  const world = harness({
    replies: [
      { payload: { status: "ok", data: openData({ segment_count: 2 }) } },
      partReply("init"),
      partReply("seg0"),
      renewalRequired(),
      { ok: false, payload: progressPayload() },
    ],
  });

  const playing = world.controller.startPlayback();
  await turns(16);
  assert.equal(world.controller.getState().waitingStage, "rights_approval");

  world.controller.dispose();
  await world.tick();
  await within(playing);

  assert.equal(opensOf(world).length, 2, "no open after the page went away");
  assert.equal(world.controller.getState().disposed, true);
  assert.equal(world.controller.getState().failed, false);
  assert.deepEqual(world.revoked, ["blob:media"]);
});

test("a v1 open reply carrying read_ahead_segments is accepted, and the first request after it is read_viewer", async () => {
  const world = harness({
    replies: [
      { payload: { status: "ok", data: openData({ read_ahead_segments: 6 }) } },
      partReply("init"),
      partReply("seg0"),
      partReply("seg1"),
    ],
  });

  await world.controller.startPlayback();

  assert.equal(world.controller.getState().failed, false);
  assert.equal(world.requests[0].url.endsWith("open_viewer"), true);
  assert.equal(world.requests[1].url.endsWith("read_viewer"), true);
  assert.equal(
    world.requests.some((request) => request.url.endsWith("close_viewer")),
    false,
  );
});

test("a v2 open reply carrying read_ahead_segments is accepted by the parser", () => {
  assert.equal(parseViewerOpenDataV2(openDataV2({ read_ahead_segments: 6 }), MINT).renditions.length, 2);
  assert.equal(parseViewerOpen(openDataV2({ read_ahead_segments: 65535 }), MINT).renditions.length, 2);
  assert.equal(parseViewerOpen(openData({ read_ahead_segments: 1 }), MINT).segmentCount, 2);
});

test("read_ahead_segments outside 1..65535 or not a whole number is refused, and unknown keys still are", () => {
  for (const value of [0, 65536, 1.5, "6"]) {
    assert.throws(() => parseViewerOpenData(openData({ read_ahead_segments: value }), MINT), undefined, String(value));
    assert.throws(() => parseViewerOpenDataV2(openDataV2({ read_ahead_segments: value }), MINT), undefined, String(value));
  }
  assert.throws(() => parseViewerOpenData(openData({ read_ahead_segments: 6, extra: 1 }), MINT));
  assert.throws(() => parseViewerOpenDataV2(openDataV2({ read_ahead_segments: 6, extra: 1 }), MINT));
});

// OPEN-LOOP F2: once the Wallet signed, a pool refusal ends the open. The
// Runtime answers its typed `content_unavailable` code with no resumable
// stage; the player shows the words with Try again and asks for nothing on
// its own, so no second Wallet request starts until the person presses it.
test("a pool refusal after the approval shows Try again and opens nothing on its own", async () => {
  const message = "This file isn't available from the pool right now. Try again later.";
  const world = harness({
    replies: [
      { ok: false, payload: { status: "error", code: "content_unavailable", message } },
      { payload: { status: "ok", data: openData({ segment_count: 1 }) } },
      partReply("init"),
      partReply("seg0"),
    ],
  });

  await world.controller.startPlayback();

  const state = world.controller.getState();
  assert.equal(state.failed, true);
  assert.equal(state.retryOffered, true);
  assert.equal(world.overlayText(), message);
  assert.equal(world.pendingTimers(), 0, "nothing is scheduled");
  await world.tick();
  await world.tick();
  assert.equal(world.requests.length, 1, "no second open_viewer, so no second Wallet request");

  // Only the person's Retry opens again.
  const [button] = world.overlayChildren();
  assert.equal(button.textContent, "Try again");
  button.listeners.click[0]();
  await world.tick();
  assert.deepEqual(world.requests[1].body, { mint_id: MINT });
  assert.equal(world.controller.getState().failed, false);
});

// OPEN-LOOP F3: the Runtime's viewer contract, the one fixture its builders
// are tested against too. Every media entry (v1 and DASH v2) must parse here.
const VIEWER_CONTRACT = JSON.parse(
  readFileSync(
    new URL(
      "../../../elastos/crates/elastos-server/src/protected_content_runtime/viewer_contract.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

test("every media reply of the Runtime viewer contract parses", () => {
  const opens = VIEWER_CONTRACT.open.filter((entry) => entry.kind === "media" || entry.kind === "dash");
  const parts = VIEWER_CONTRACT.part.filter((entry) => entry.kind === "media");
  assert.ok(opens.length >= 4 && parts.length >= 1, "the contract names media replies");
  for (const { name, kind, reply } of opens) {
    const parse = kind === "dash" ? parseViewerOpenDataV2 : parseViewerOpenData;
    const session = parse(reply, reply.mint_id);
    assert.equal(session.viewerSessionHandle, reply.viewer_session_handle, name);
    assert.deepEqual(parseViewerOpen(reply, reply.mint_id), session, name);
  }
  for (const { name, reply } of parts) {
    const bytes = parseViewerPartData(reply, reply.mint_id, reply.viewer_session_handle);
    assert.ok(bytes.length > 0, name);
  }
});
