// The ceremony half of the reader: what it does between asking to open a
// protected file and being given one.
//
// Opening is not a request that succeeds or fails once. Every first open of
// every protected item reaches a wallet that holds a rights-signature request,
// and the file arrives only after the person answers it. These tests drive that
// wait on a clock of their own, so the behaviour is checked without waiting
// through it.

import assert from "node:assert/strict";
import test from "node:test";

import {
  OBJECT_CHUNK_BYTES,
  OPEN_PROGRESS_SCHEMA,
  POOL_SESSION_RENEWAL_REQUIRED,
  createReaderController,
  readOpenProgress,
  singleFlight,
  waitingMessage,
} from "./reader.js";

const MINT = "a".repeat(64);
const HANDLE = "b".repeat(64);
const TOKEN = "home-token-1";

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
// Reading the typed state
// ---------------------------------------------------------------------------

test("the typed open state is read from the answer, never from its sentence", () => {
  const progress = readOpenProgress(progressPayload());
  assert.deepEqual(progress, {
    stage: "rights_approval",
    resumable: true,
    awaitsPerson: true,
    connectorId: "metamask",
    expiresAt: 1_000_290,
    readyAt: 0,
  });

  // Refused: a state this reader has no way to wait through is not waited
  // through, whatever the answer claims about it.
  assert.equal(readOpenProgress(progressPayload({ schema: "something.else/v1" })), null);
  assert.equal(readOpenProgress(progressPayload({ stage: "" })), null);
  assert.equal(readOpenProgress({ status: "error", message: "plain" }), null);
  assert.equal(readOpenProgress(null), null);
  assert.equal(
    readOpenProgress(progressPayload({ stage: "custody_recovery", resumable: true })).resumable,
    false,
    "an unknown stage carries no resume policy, so it is not resumable here",
  );

  // Refused as final, which is the one a reader must stop asking about.
  const denied = readOpenProgress(
    progressPayload({ stage: "denied", resumable: false, awaits_person: false }),
  );
  assert.equal(denied.resumable, false);
});

test("the waiting sentence names where to go, and is this reader's own wording", () => {
  const external = readOpenProgress(progressPayload());
  assert.match(waitingMessage(external), /metamask/);
  // Runtime's own sentence names internal machinery; none of it reaches the
  // page.
  assert.doesNotMatch(waitingMessage(external), /Runtime|custody|release/i);

  const noConnector = readOpenProgress(progressPayload({ connector_id: null }));
  assert.match(waitingMessage(noConnector), /your wallet/);

  // A managed account is waiting too, and asks the person for nothing.
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
    disabled: false,
    dir: "",
    className: "",
    type: "",
    childNodes: [],
    listeners: {},
    focused: 0,
    get firstChild() {
      return this.childNodes[0] || null;
    },
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
    focus() {
      this.focused += 1;
    },
  };
}

function harness({ replies, now = 1_000_000, render = () => async () => ({ release() {} }) }) {
  const elements = new Map(
    [
      "reader-stage",
      "reader-status",
      "reader-kind",
      "reader-controls",
      "reader-previous",
      "reader-next",
      "reader-position",
    ].map((id) => [id, element(id)]),
  );
  const documentObject = {
    getElementById: (id) => elements.get(id),
    createElement: (tag) => element(`created-${tag}`),
  };
  const windowListeners = {};
  const windowObject = {
    addEventListener(name, handler) {
      (windowListeners[name] ||= []).push(handler);
    },
  };
  const timers = [];
  const requests = [];
  let clock = now;

  const controller = createReaderController({
    documentObject,
    windowObject,
    locationObject: { search: `?mint_id=${MINT}`, hash: `#home_token=${TOKEN}` },
    async fetchImpl(url, options) {
      requests.push({
        url,
        body: JSON.parse(options.body),
        token: options.headers["x-elastos-home-token"],
      });
      const reply = replies.shift();
      if (!reply) throw new Error("no reply queued");
      return {
        ok: reply.ok !== false,
        text: async () => JSON.stringify(reply.payload),
      };
    },
    urlObject: { createObjectURL: () => "blob:x", revokeObjectURL() {} },
    render,
    nowSeconds: () => clock,
    setTimeoutImpl: (handler) => {
      timers.push(handler);
      return timers.length;
    },
    clearTimeoutImpl: () => {},
  });

  return {
    controller,
    requests,
    elements,
    windowListeners,
    stageText: () =>
      (elements.get("reader-stage").childNodes[0]?.childNodes || [])
        .map((node) => node.textContent)
        .join(" "),
    statusText: () => elements.get("reader-status").textContent,
    advance: (seconds) => {
      clock += seconds;
    },
    /** Runs every timer the controller set, the way a clock eventually would. */
    async tick() {
      const pending = timers.splice(0, timers.length);
      for (const handler of pending) handler();
      await new Promise((resolve) => setImmediate(resolve));
      await new Promise((resolve) => setImmediate(resolve));
    },
    pendingTimers: () => timers.length,
  };
}

test("a renewed Home token is used by the next viewer request", async () => {
  const world = harness({
    replies: [
      { ok: false, payload: progressPayload() },
      { ok: false, payload: progressPayload() },
    ],
  });

  await world.controller.open();
  assert.equal(world.controller.getState().waiting, true);
  // Home renewed this frame's launch authority while the open waited.
  world.controller.setHomeToken("home-token-2");
  await world.tick();

  assert.deepEqual(world.requests.map((request) => request.token), [TOKEN, "home-token-2"]);
});

function openReply(extra = {}) {
  return {
    payload: {
      status: "ok",
      data: {
        schema: "elastos.library.runtime-custody-viewer/v1",
        content_kind: "object",
        mint_id: MINT,
        viewer_session_handle: HANDLE,
        expires_at: 1_756_293_600,
        content_type: "text/plain",
        plaintext_bytes: 5,
        chunk_count: 1,
        chunk_plaintext_bytes: 1024 * 1024,
        ...extra,
      },
    },
  };
}

function partReply() {
  return {
    payload: {
      status: "ok",
      data: {
        schema: "elastos.library.runtime-custody-viewer-part/v1",
        content_kind: "object",
        mint_id: MINT,
        viewer_session_handle: HANDLE,
        chunk_index: 0,
        encoding: "base64",
        data: Buffer.from("hello").toString("base64"),
      },
    },
  };
}

// ---------------------------------------------------------------------------
// Waiting through the ceremony
// ---------------------------------------------------------------------------

test("an open waiting on the wallet keeps waiting, and opens once the person answers", async () => {
  const world = harness({
    replies: [
      { ok: false, payload: progressPayload() },
      openReply(),
      partReply(),
    ],
  });

  await world.controller.open();

  // The person is told whose turn it is, and the file is not called
  // unavailable.
  assert.match(world.statusText(), /metamask/);
  assert.doesNotMatch(world.statusText(), /unavailable/i);
  assert.equal(world.controller.getState().failed, false);
  assert.equal(world.controller.getState().waiting, true);
  assert.equal(world.controller.getState().waitingStage, "rights_approval");
  assert.equal(world.pendingTimers(), 1);

  await world.tick();

  // The identical open is re-issued. Runtime resumes the attempt it already
  // has, so asking again is how the approval is collected.
  assert.equal(world.requests.length, 3);
  assert.deepEqual(world.requests[0].body, { mint_id: MINT });
  assert.deepEqual(world.requests[1].body, world.requests[0].body);
  assert.equal(world.requests[1].url, world.requests[0].url);

  const state = world.controller.getState();
  assert.equal(state.failed, false);
  assert.equal(state.waiting, false, "the waiting stops once the file is open");
  assert.equal(world.controller.getSession().contentType, "text/plain");
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

  await world.controller.open();

  const state = world.controller.getState();
  assert.equal(state.failed, true);
  assert.equal(state.waiting, false);
  assert.equal(state.retryOffered, false, "a decided answer gets no retry button");
  assert.equal(world.pendingTimers(), 0);
  assert.equal(world.requests.length, 1, "a decided answer is not asked again");
});

test("the waiting stops when the wallet request lapses, and then the person may ask again", async () => {
  const world = harness({
    replies: [
      { ok: false, payload: progressPayload() },
      { ok: false, payload: progressPayload() },
    ],
  });

  await world.controller.open();
  assert.equal(world.controller.getState().waiting, true);

  // The window Runtime sent closes while the person is away.
  world.advance(400);
  await world.tick();

  const state = world.controller.getState();
  assert.equal(state.failed, true);
  assert.equal(state.waiting, false);
  assert.equal(state.retryOffered, true, "asking again could still work, so it is offered");
  assert.equal(world.pendingTimers(), 0, "nothing is left ticking");
});

test("the page going away stops the waiting and leaves nothing ticking", async () => {
  const world = harness({ replies: [{ ok: false, payload: progressPayload() }] });

  await world.controller.open();
  assert.equal(world.controller.getState().waiting, true);

  world.controller.dispose();

  assert.equal(world.controller.getState().disposed, true);
  await world.tick();
  assert.equal(world.requests.length, 1, "a disposed page asks for nothing more");
});

test("a launch with nothing chosen explains where files come from, once", async () => {
  const world = harness({ replies: [] });
  const empty = createReaderController({
    documentObject: {
      getElementById: (id) => world.elements.get(id),
      createElement: (tag) => element(`created-${tag}`),
    },
    windowObject: { addEventListener() {} },
    locationObject: { search: "", hash: `#home_token=${TOKEN}` },
    fetchImpl: async () => {
      throw new Error("nothing should be asked for");
    },
    render: () => async () => ({ release() {} }),
  });

  await empty.open();

  assert.match(world.statusText(), /Library/);
  assert.doesNotMatch(world.statusText(), /unavailable/i);
  assert.equal(empty.getState().failed, false);
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
  assert.match(message, /opens on its own/);
  assert.doesNotMatch(message, /Approve|Runtime|custody|release/i);
  // Past the estimate, the wait reads as imminent rather than as a time gone by.
  assert.match(waitingMessage(finalizing, now + 3600), /any moment/);
});

// ---------------------------------------------------------------------------
// Asking again after a failure
// ---------------------------------------------------------------------------

/** The button the failure panel offers, if any. */
function retryButtonOf(world) {
  const panel = world.elements.get("reader-stage").childNodes[0];
  return (panel?.childNodes || []).find((node) => node.listeners?.click) || null;
}

test("an open that fails without a stage offers Try again, and pressing it opens the file", async () => {
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
      openReply(),
      partReply(),
    ],
  });

  await world.controller.open();

  let state = world.controller.getState();
  assert.equal(state.failed, true);
  assert.equal(state.retryOffered, true, "the release can work on a second ask");
  assert.equal(world.pendingTimers(), 0, "a failure is not asked again on its own");
  assert.equal(world.requests.length, 1);
  const button = retryButtonOf(world);
  assert.equal(button?.textContent, "Try again");
  assert.equal(button.focused, 1, "focus moves to the one control on the panel");

  // Pressing it asks for the same file again, in this same page.
  button.listeners.click[0]();
  await world.tick();

  state = world.controller.getState();
  assert.equal(state.failed, false);
  assert.equal(state.retryOffered, false);
  assert.equal(world.requests.length, 3);
  assert.deepEqual(world.requests[1].body, { mint_id: MINT });
  assert.equal(world.controller.getSession().contentType, "text/plain");
});

test("a refusal asking again cannot change offers nothing to press", async () => {
  const media = openReply();
  media.payload.data.content_kind = "media";
  const world = harness({ replies: [media, { payload: { status: "ok", data: {} } }] });

  await world.controller.open();

  const state = world.controller.getState();
  assert.equal(state.failed, true);
  assert.equal(state.retryOffered, false, "a media file never opens here");
  assert.match(world.statusText(), /Elacity Player/);
  assert.equal(retryButtonOf(world), null);
});

function sizedOpenReply(chunkCount, lastBytes) {
  const reply = openReply();
  reply.payload.data.content_type = "application/octet-stream";
  reply.payload.data.plaintext_bytes = (chunkCount - 1) * OBJECT_CHUNK_BYTES + lastBytes;
  reply.payload.data.chunk_count = chunkCount;
  return reply;
}

function sizedPartReply(index, bytes) {
  const reply = partReply();
  reply.payload.data.chunk_index = index;
  reply.payload.data.data = Buffer.alloc(bytes, (index % 250) + 1).toString("base64");
  return reply;
}

test("a file of more than sixty-four parts is read whole and handed to the renderer", async () => {
  const chunkCount = 70;
  const replies = [sizedOpenReply(chunkCount, 5)];
  for (let index = 0; index < chunkCount; index += 1) {
    replies.push(sizedPartReply(index, index === chunkCount - 1 ? 5 : OBJECT_CHUNK_BYTES));
  }
  let seen = null;
  const world = harness({
    replies,
    render: () => async ({ bytes }) => {
      seen = bytes;
      return { release() {} };
    },
  });

  await world.controller.open();

  assert.equal(world.controller.getState().failed, false);
  assert.equal(seen.length, 69 * OBJECT_CHUNK_BYTES + 5);
  for (const index of [0, 1, 63, 64, 68, 69]) {
    assert.equal(seen[index * OBJECT_CHUNK_BYTES], (index % 250) + 1, `part ${index} starts in place`);
  }
  assert.equal(seen[69 * OBJECT_CHUNK_BYTES + 4], (69 % 250) + 1);
});

test("a device that cannot hold the file says it is too large, with nothing to press", async () => {
  const original = Blob.prototype.arrayBuffer;
  Blob.prototype.arrayBuffer = async () => {
    throw new RangeError("Array buffer allocation failed");
  };
  try {
    const world = harness({ replies: [sizedOpenReply(2, 5), sizedPartReply(0, OBJECT_CHUNK_BYTES), sizedPartReply(1, 5)] });
    await world.controller.open();
    assert.equal(world.controller.getState().failed, true);
    assert.match(world.statusText(), /too large/i);
    assert.match(world.stageText(), /too large/i);
  } finally {
    Blob.prototype.arrayBuffer = original;
  }
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
  await world.controller.open();
  assert.equal(world.controller.getState().waiting, true);
  assert.match(world.statusText(), /Approve opening this file in metamask\. It opens on its own once you do\./);
  assert.doesNotMatch(world.statusText(), /Delivery key/);
  assert.doesNotMatch(world.stageText(), /Delivery key/);
  const progress = readOpenProgress(progressPayload({ delivery_key_fingerprint: DELIVERY_KEY }));
  assert.equal("deliveryKeyFingerprint" in progress, false);
  assert.equal(waitingMessage(progress), "Approve opening this file in metamask. It opens on its own once you do.");
  const managed = readOpenProgress(
    progressPayload({ awaits_person: false, connector_id: null, delivery_key_fingerprint: DELIVERY_KEY }),
  );
  assert.doesNotMatch(waitingMessage(managed), /Delivery key/);
});

// ---------------------------------------------------------------------------
// Plan B T4.5 (C3): one Wallet prompt at rights expiry, then the same place
// ---------------------------------------------------------------------------

const RENEWED = "c".repeat(64);

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

function renewedOpenReply(chunkCount, lastBytes) {
  const reply = sizedOpenReply(chunkCount, lastBytes);
  reply.payload.data.viewer_session_handle = RENEWED;
  return reply;
}

function renewedPartReply(index, bytes) {
  const reply = sizedPartReply(index, bytes);
  reply.payload.data.viewer_session_handle = RENEWED;
  return reply;
}

const opensOf = (world) => world.requests.filter((request) => request.url.endsWith("open_viewer"));
const settle = async (count = 16) => {
  for (let turn = 0; turn < count; turn += 1) await new Promise((r) => setImmediate(r));
};

test("renewal_required_reopens_and_resumes_at_the_same_position", async () => {
  let seen = null;
  const world = harness({
    replies: [
      sizedOpenReply(3, 5),
      sizedPartReply(0, OBJECT_CHUNK_BYTES),
      // The rights expired: this read is answered with the one reopen.
      renewalRequired(),
      renewedOpenReply(3, 5),
      renewedPartReply(1, OBJECT_CHUNK_BYTES),
      renewedPartReply(2, 5),
    ],
    render: () => async ({ bytes }) => {
      seen = bytes;
      return { release() {} };
    },
  });

  await world.controller.open();

  assert.equal(world.controller.getState().failed, false);
  assert.equal(opensOf(world).length, 2, "one open for the session, one at rights expiry");
  assert.deepEqual(opensOf(world)[1].body, { mint_id: MINT });
  const reads = world.requests.filter((request) => request.url.endsWith("read_viewer"));
  assert.deepEqual(
    reads.map((request) => [request.body.chunk_index, request.body.viewer_session_handle]),
    [
      [0, HANDLE],
      [1, HANDLE],
      [1, RENEWED],
      [2, RENEWED],
    ],
  );
  // The file is whole: the part read before the expiry is kept, not read twice.
  assert.equal(seen.length, 2 * OBJECT_CHUNK_BYTES + 5);
  assert.equal(seen[0], 1);
  assert.equal(seen[OBJECT_CHUNK_BYTES], 2);
  assert.equal(seen[2 * OBJECT_CHUNK_BYTES], 3);
  assert.equal(world.controller.getSession().viewerSessionHandle, RENEWED);
});

test("rights_expiry_shows_the_approval_stage_not_retry", async () => {
  const world = harness({
    replies: [
      sizedOpenReply(2, 5),
      sizedPartReply(0, OBJECT_CHUNK_BYTES),
      renewalRequired(),
      { ok: false, payload: progressPayload({ delivery_key_fingerprint: DELIVERY_KEY }) },
      renewedOpenReply(2, 5),
      renewedPartReply(1, 5),
    ],
  });

  const opening = world.controller.open();
  await settle();

  // The one Wallet prompt: the approval stage, with nothing to press.
  let state = world.controller.getState();
  assert.equal(state.failed, false);
  assert.equal(state.retryOffered, false);
  assert.equal(state.waiting, true);
  assert.equal(state.waitingStage, "rights_approval");
  assert.equal(retryButtonOf(world), null, "no Retry button");
  assert.match(world.statusText(), /Approve opening this file in metamask/);
  assert.doesNotMatch(world.statusText(), /Delivery key/);
  assert.doesNotMatch(world.statusText(), /unavailable/i);

  // The person approves; the identical open is asked again and reading goes on.
  await world.tick();
  await opening;
  await settle();
  state = world.controller.getState();
  assert.equal(state.failed, false);
  assert.equal(state.waiting, false);
  assert.equal(opensOf(world).length, 3);
  assert.deepEqual(opensOf(world)[2].body, opensOf(world)[1].body);
  assert.equal(world.controller.getSession().viewerSessionHandle, RENEWED);
});

test("an early read error is not a reopen: no extra open, no Wallet", async () => {
  const world = harness({
    replies: [
      sizedOpenReply(2, 5),
      sizedPartReply(0, OBJECT_CHUNK_BYTES),
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

  world.controller.open();
  await settle();

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

function expiringOpenReply(chunkCount, lastBytes) {
  const reply = sizedOpenReply(chunkCount, lastBytes);
  reply.payload.data.expires_at = EXPIRES;
  return reply;
}

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
    .map((request) => [request.body.chunk_index, request.body.viewer_session_handle]);

function pressRetry(world) {
  const button = retryButtonOf(world);
  assert.equal(button?.textContent, "Try again");
  button.listeners.click[0]();
}

test("early budget exhaustion stalls on the same handle until rights expiry, then reopens once", async () => {
  let seen = null;
  const world = harness({
    replies: [
      expiringOpenReply(3, 5),
      sizedPartReply(0, OBJECT_CHUNK_BYTES),
      // The byte budget is spent: the server gives no part before the expiry.
      serverLost(),
      serverLost(),
      // At the rights expiry the same read meets the session's end.
      renewalRequired(),
      renewedOpenReply(3, 5),
      renewedPartReply(1, OBJECT_CHUNK_BYTES),
      renewedPartReply(2, 5),
    ],
    render: () => async ({ bytes }) => {
      seen = bytes;
      return { release() {} };
    },
  });

  const opening = world.controller.open();
  await settle();
  let state = world.controller.getState();
  assert.equal(state.failed, false);
  assert.equal(state.closed, false);
  assert.equal(state.retryOffered, true);

  // Retry asks the same read on the same handle: no open, no close.
  pressRetry(world);
  await settle();
  assert.equal(opensOf(world).length, 1, "zero Wallet calls before expiry");
  assert.equal(closesOf(world).length, 0, "zero release calls before expiry");
  assert.deepEqual(readsOf(world), [
    [0, HANDLE],
    [1, HANDLE],
    [1, HANDLE],
  ]);
  assert.equal(world.controller.getState().retryOffered, true);

  // The rights expire: the stalled read is asked once more and reopens once.
  world.advance(EXPIRES - 1_000_000);
  await world.tick();
  await opening;

  state = world.controller.getState();
  assert.equal(state.failed, false);
  assert.equal(opensOf(world).length, 2, "exactly one open after expiry");
  assert.equal(closesOf(world).length, 0);
  assert.deepEqual(readsOf(world).slice(3), [
    [1, HANDLE],
    [1, RENEWED],
    [2, RENEWED],
  ]);
  assert.equal(seen.length, 2 * OBJECT_CHUNK_BYTES + 5);
});

test("an early server loss stalls; Retry reads on, and the rights expiry reopens once", async () => {
  let seen = null;
  const world = harness({
    replies: [
      expiringOpenReply(4, 5),
      sizedPartReply(0, OBJECT_CHUNK_BYTES),
      serverLost(),
      // The server is back: Retry reads on with the same handle.
      sizedPartReply(1, OBJECT_CHUNK_BYTES),
      serverLost(),
      renewalRequired(),
      renewedOpenReply(4, 5),
      renewedPartReply(2, OBJECT_CHUNK_BYTES),
      renewedPartReply(3, 5),
    ],
    render: () => async ({ bytes }) => {
      seen = bytes;
      return { release() {} };
    },
  });

  const opening = world.controller.open();
  await settle();
  pressRetry(world);
  await settle();

  // The read after Retry went on; the next loss stalls again.
  assert.equal(world.controller.getState().failed, false);
  assert.equal(world.controller.getState().retryOffered, true);
  assert.equal(opensOf(world).length, 1, "zero Wallet calls before expiry");
  assert.equal(closesOf(world).length, 0, "zero release calls before expiry");

  world.advance(EXPIRES - 1_000_000);
  await world.tick();
  await opening;

  assert.equal(world.controller.getState().failed, false);
  assert.equal(opensOf(world).length, 2, "exactly one open after expiry");
  assert.equal(closesOf(world).length, 0);
  assert.deepEqual(readsOf(world), [
    [0, HANDLE],
    [1, HANDLE],
    [1, HANDLE],
    [2, HANDLE],
    [2, HANDLE],
    [2, RENEWED],
    [3, RENEWED],
  ]);
  assert.equal(seen.length, 3 * OBJECT_CHUNK_BYTES + 5);
});

test("a browser clock past the expiry never reopens without the Runtime's typed answer", async () => {
  let seen = null;
  const stale = sizedOpenReply(3, 5);
  // The browser clock (1_000_000) is already past this session's end.
  stale.payload.data.expires_at = 999_000;
  const world = harness({
    replies: [
      stale,
      sizedPartReply(0, OBJECT_CHUNK_BYTES),
      // The Runtime still answers ordinary early failures.
      serverLost(),
      serverLost(),
      serverLost(),
      serverLost(),
      // Only its typed expiry answer reopens.
      renewalRequired(),
      renewedOpenReply(3, 5),
      renewedPartReply(1, OBJECT_CHUNK_BYTES),
      renewedPartReply(2, 5),
    ],
    render: () => async ({ bytes }) => {
      seen = bytes;
      return { release() {} };
    },
  });

  const opening = world.controller.open();
  await settle();
  // The local timer only wakes the same read on the same handle, a bounded
  // number of times once it has elapsed.
  for (let wake = 0; wake < 3; wake += 1) {
    await world.tick();
    await settle();
  }
  assert.equal(world.pendingTimers(), 0, "no more automatic reads once the bound is reached");
  const state = world.controller.getState();
  assert.equal(state.failed, false);
  assert.equal(state.closed, false);
  assert.equal(state.retryOffered, true);
  assert.equal(opensOf(world).length, 1, "zero extra opens without the typed expiry");
  assert.equal(closesOf(world).length, 0, "zero closes");
  assert.deepEqual(readsOf(world), [
    [0, HANDLE],
    [1, HANDLE],
    [1, HANDLE],
    [1, HANDLE],
    [1, HANDLE],
  ]);

  // Retry reads the same handle; the typed answer reopens exactly once.
  pressRetry(world);
  await opening;
  assert.equal(world.controller.getState().failed, false);
  assert.equal(opensOf(world).length, 2, "exactly one reopen");
  assert.equal(closesOf(world).length, 0);
  assert.deepEqual(readsOf(world).slice(5), [
    [1, HANDLE],
    [1, RENEWED],
    [2, RENEWED],
  ]);
  assert.equal(seen.length, 2 * OBJECT_CHUNK_BYTES + 5);
});

test("a reopened session of another shape is refused, not read", async () => {
  const world = harness({
    replies: [
      sizedOpenReply(2, 5),
      sizedPartReply(0, OBJECT_CHUNK_BYTES),
      renewalRequired(),
      renewedOpenReply(3, 5),
      { payload: { status: "ok", data: { closed: true } } },
    ],
  });

  await world.controller.open();

  assert.equal(world.controller.getState().failed, true);
  const reads = world.requests.filter((request) => request.url.endsWith("read_viewer"));
  assert.equal(reads.length, 2, "nothing is read from a session of another shape");
  const close = world.requests.at(-1);
  assert.equal(close.url.endsWith("close_viewer"), true);
  assert.equal(close.body.viewer_session_handle, RENEWED, "the session it opened is handed back");
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
  await reopen();
  assert.equal(calls, 2);
  assert.equal(POOL_SESSION_RENEWAL_REQUIRED, "pool_session_renewal_required");
});

test("a page going away while the reopen waits on the Wallet asks nothing more", async () => {
  const world = harness({
    replies: [
      sizedOpenReply(2, 5),
      sizedPartReply(0, OBJECT_CHUNK_BYTES),
      renewalRequired(),
      { ok: false, payload: progressPayload() },
    ],
  });

  const opening = world.controller.open();
  await settle();
  assert.equal(world.controller.getState().waitingStage, "rights_approval");

  world.controller.dispose();
  await world.tick();
  await opening;

  assert.equal(opensOf(world).length, 2, "no open after the page went away");
  assert.equal(world.controller.getState().disposed, true);
  assert.equal(world.pendingTimers(), 0);
});

test("a pool open reply carrying read_ahead_segments is accepted and the first request after it is read_viewer", async () => {
  const world = harness({ replies: [openReply({ read_ahead_segments: 6 }), partReply()] });

  await world.controller.open();

  assert.equal(world.controller.getState().failed, false);
  assert.equal(world.requests.length, 2);
  assert.equal(world.requests[0].url.endsWith("open_viewer"), true);
  assert.equal(world.requests[1].url.endsWith("read_viewer"), true);
  assert.equal(
    world.requests.some((request) => request.url.endsWith("close_viewer")),
    false,
  );
});

test("a pool open reply with an invalid read_ahead_segments is refused and closed", async () => {
  for (const value of [0, 65536, 1.5, "6"]) {
    const world = harness({ replies: [openReply({ read_ahead_segments: value }), { payload: { status: "ok", data: {} } }] });

    await world.controller.open();

    assert.equal(world.controller.getState().failed, true, String(value));
    assert.equal(world.requests[1]?.url.endsWith("close_viewer"), true, String(value));
  }
});

test("a pool open reply with an unknown extra key is still refused", async () => {
  const world = harness({
    replies: [openReply({ read_ahead_segments: 6, extra: 1 }), { payload: { status: "ok", data: {} } }],
  });

  await world.controller.open();

  assert.equal(world.controller.getState().failed, true);
});

// OPEN-LOOP F2: once the Wallet signed, a pool refusal ends the open. The
// Runtime answers its typed `content_unavailable` code with no resumable
// stage; the reader shows the words with Try again and asks for nothing on
// its own, so no second Wallet request starts until the person presses it.
const POOL_CONTENT_UNAVAILABLE = {
  ok: false,
  payload: {
    status: "error",
    code: "content_unavailable",
    message: "This file isn't available from the pool right now. Try again later.",
  },
};

test("a pool refusal after the approval shows Try again and opens nothing on its own", async () => {
  const world = harness({ replies: [POOL_CONTENT_UNAVAILABLE, openReply(), partReply()] });

  await world.controller.open();

  const state = world.controller.getState();
  assert.equal(state.failed, true);
  assert.equal(state.retryOffered, true);
  assert.equal(world.statusText(), POOL_CONTENT_UNAVAILABLE.payload.message);
  assert.equal(world.pendingTimers(), 0, "nothing is scheduled");
  await world.tick();
  await world.tick();
  assert.deepEqual(
    world.requests.map((request) => request.url),
    ["/api/provider/object/open_viewer"],
    "no second open_viewer, so no second Wallet request, without Retry",
  );

  // Only the person's Retry opens again.
  retryButtonOf(world).listeners.click[0]();
  await world.tick();
  assert.equal(
    world.requests.filter((request) => request.url.endsWith("/open_viewer")).length,
    2,
  );
  assert.equal(world.controller.getState().failed, false);
});
