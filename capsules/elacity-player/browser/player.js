const VIEWER_OPEN_SCHEMA = "elastos.library.runtime-custody-viewer/v1";
const VIEWER_OPEN_SCHEMA_V2 = "elastos.library.runtime-custody-viewer/v2";
const VIEWER_PART_SCHEMA = "elastos.library.runtime-custody-viewer-part/v1";
const VIEWER_HANDLE_HEX_RE = /^[0-9a-f]{64}$/;
const MINT_ID_HEX_RE = /^[0-9a-f]{64}$/;
export const MAX_VIEWER_SEGMENT_COUNT = 512;
export const MAX_VIEWER_MEDIA_PART_BYTES = 2 * 1024 * 1024;
const MAX_VIEWER_MEDIA_PART_BASE64_BYTES = Math.ceil(MAX_VIEWER_MEDIA_PART_BYTES / 3) * 4;
const VIEWER_CONTENT_KIND_MEDIA = "media";
const AUDIO_ONLY_CLASS = "audio-only";
// Codec families that paint a frame. A rendition whose declared codec list has
// one of these carries a picture the decoder draws for us; anything else (AAC,
// Opus, FLAC, ...) is sound only.
const IMAGE_TRACK_CODEC_PREFIXES = [
  "avc1.",
  "avc3.",
  "hev1.",
  "hvc1.",
  "hvc2.",
  "av01.",
  "vp08",
  "vp09",
  "vp8",
  "vp9",
  "mp4v.",
];
export const PRESENTATION_IMAGE_TRACK = "image-track";
export const PRESENTATION_POSTER = "poster";
export const PRESENTATION_CONTROLS_ONLY = "controls-only";
// v2 renditions, in the fixed order Runtime serves their parts: the video init,
// the audio init, then segment i of each rendition in turn.
const RENDITION_KINDS = ["video", "audio"];
// The pinned mime/codecs pairs of a v2 rendition, exactly as Runtime pins them.
const RENDITION_MIME_TYPES = { video: "video/mp4", audio: "audio/mp4" };
const RENDITION_CODECS_RES = { video: /^avc1\.640028$/, audio: /^mp4a\.40\.2$/ };
// v2 has no segment cap of its own; this only keeps a hostile answer from
// driving an unbounded read loop.
export const MAX_VIEWER_SEGMENT_COUNT_V2 = 1 << 20;
// How far past the playhead a rendition may be buffered before the next
// segment is read, so a long item never exhausts the SourceBuffer quota.
export const LOOKAHEAD_SECONDS = 30;
const MEDIA_UNAVAILABLE = "Protected media is unavailable.";
const NOTHING_CHOSEN = "Open something from your Library to play it here.";
const RETRY_LABEL = "Try again";
// C3: once the local clock says the rights expired, a stalled read is woken
// at most this many times on its own; then only Retry asks again.
const LATE_READ_RETRIES = 3;
const LATE_READ_RETRY_MS = 15_000;
// J3-F10 (D6): a read the pool dropped before the rights expire is asked
// again on its own, this many times at this interval, before the stall holds
// until the rights expiry. Try again stays offered the whole time.
export const EARLY_READ_RETRIES = 3;
export const EARLY_READ_RETRY_MS = 5_000;

/** Wire identity of the state Runtime answers an unfinished open with. */
export const OPEN_PROGRESS_SCHEMA = "elastos.protected-content.open-progress/v1";

/**
 * Plan B T4.5 (C3): a read answered at the end of a pool session, when the
 * signed rights expire. The player keeps its place, runs the open once more
 * (its approval stage is the one Wallet prompt) and reads on from there. Any
 * other read refusal is answered as before.
 */
export const POOL_SESSION_RENEWAL_REQUIRED = "pool_session_renewal_required";
/** Runtime's typed answer for a pool read that got no part (J3-F10, D6). */
export const POOL_READ_UNAVAILABLE = "pool_read_unavailable";

/**
 * Runs `run` once for every caller that asks while it is in flight: they all
 * get the same promise. A caller after it settled starts it again.
 */
export function singleFlight(run) {
  let inFlight = null;
  return () => {
    if (!inFlight) {
      inFlight = Promise.resolve()
        .then(run)
        .finally(() => {
          inFlight = null;
        });
    }
    return inFlight;
  };
}

/**
 * The stages an open can report, and how this player waits through each.
 *
 * Opening protected media is a ceremony, not a request: the wallet holds a
 * rights-signature request that the person approves, and only then does the
 * release run. Every first open of every protected item reaches this state, so
 * a player that treated it as a failure -- which this one did -- turned the
 * ordinary case into a dead end.
 */
const RESUME_POLICY = new Map([
  ["rights_approval", { intervalMs: 2000, maxAttempts: 180 }],
  ["unavailable", { intervalMs: 3000, maxAttempts: 3 }],
  // The acquisition is confirmed but not yet final on chain, and a key is only
  // released on final state. That usually takes 15-20 minutes; asking every
  // 15 s for up to 40 minutes covers it without hammering the chain.
  ["finalizing", { intervalMs: 15000, maxAttempts: 160 }],
]);

const OPEN_RESPONSE_KEYS = [
  "codecs",
  "content_kind",
  "expires_at",
  "has_init_segment",
  "mime_type",
  "mint_id",
  "schema",
  "segment_count",
  "viewer_session_handle",
];
const OPEN_RESPONSE_KEYS_V2 = [
  "content_kind",
  "expires_at",
  "mint_id",
  "renditions",
  "schema",
  "viewer_session_handle",
];
const RENDITION_KEYS_V2 = ["codecs", "mime_type", "rendition", "segment_count"];
const PART_RESPONSE_KEYS = [
  "data",
  "encoding",
  "mint_id",
  "schema",
  "viewer_session_handle",
];

/**
 * Reads the typed state Runtime attaches to an unfinished open.
 *
 * Returns `null` for anything this player does not recognise, so an answer of
 * an unexpected shape is treated as a plain failure rather than guessed at. A
 * stage with no resume policy is not resumable here whatever the `resumable`
 * flag says: the player has no rule for how to wait through it.
 */
export function readOpenProgress(payload) {
  const source = payload && typeof payload === "object" && !Array.isArray(payload) ? payload : null;
  const value = source?.open_progress;
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  if (value.schema !== OPEN_PROGRESS_SCHEMA) return null;
  const stage = String(value.stage || "");
  if (!stage) return null;
  const connectorId = typeof value.connector_id === "string" ? value.connector_id.trim() : "";
  return {
    stage,
    resumable: value.resumable === true && RESUME_POLICY.has(stage),
    awaitsPerson: value.awaits_person === true,
    connectorId,
    expiresAt: Number.isInteger(value.expires_at) && value.expires_at > 0 ? value.expires_at : 0,
    readyAt: Number.isInteger(value.ready_at) && value.ready_at > 0 ? value.ready_at : 0,
  };
}

/**
 * What to tell the person while an open waits.
 *
 * Composed here from the typed state rather than taken from the answer's own
 * sentence: that sentence is Runtime's stable wording for its operators, and it
 * names internal machinery a player should never put on screen.
 */
export function waitingMessage(progress, now = Math.floor(Date.now() / 1000)) {
  if (progress?.stage === "finalizing") {
    const minutes = Math.ceil((progress.readyAt - now) / 60);
    const when = progress.readyAt && minutes > 0 ? `in about ${minutes} min` : "any moment now";
    return `This is confirmed and being finalized on chain. It plays on its own ${when}.`;
  }
  if (progress?.stage !== "rights_approval") {
    return "This is not ready yet. Trying again...";
  }
  return approvalMessage(progress);
}

function approvalMessage(progress) {
  if (!progress.awaitsPerson) {
    return "Your wallet is approving this. It plays on its own.";
  }
  return progress.connectorId
    ? `Approve playing this in ${progress.connectorId}. It plays on its own once you do.`
    : "Approve playing this in your wallet. It plays on its own once you do.";
}

/**
 * `optionalKeys` may be present or absent; every other key must match exactly.
 */
function hasExactKeys(value, keys, optionalKeys = []) {
  const object = value && typeof value === "object" && !Array.isArray(value) ? value : null;
  if (!object) return false;
  const actual = Object.keys(object)
    .filter((key) => !optionalKeys.includes(key))
    .sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

/** Pacing hint a pool open adds: absent, or a whole number from 1 to 65535. */
const OPTIONAL_OPEN_KEYS = ["read_ahead_segments"];
function hasValidReadAhead(data) {
  if (!Object.hasOwn(data, "read_ahead_segments")) return true;
  const value = data.read_ahead_segments;
  return Number.isInteger(value) && value >= 1 && value <= 65535;
}

function readSearchParam(locationLike, key) {
  const search = typeof locationLike?.search === "string" ? locationLike.search : "";
  return new URLSearchParams(search).get(key) || "";
}

function readHashParam(locationLike, key) {
  const hash = typeof locationLike?.hash === "string" ? locationLike.hash.replace(/^#/, "") : "";
  return new URLSearchParams(hash).get(key) || "";
}

export function readLaunchContext(locationLike) {
  return {
    mintId: readSearchParam(locationLike, "mint_id").trim(),
    homeToken: readHashParam(locationLike, "home_token").trim(),
  };
}

function parseJsonObject(text) {
  const value = JSON.parse(text);
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Viewer response is unavailable.");
  }
  return value;
}

async function readResponseText(response) {
  return typeof response?.text === "function" ? response.text() : "";
}

/**
 * A refusal, carrying the typed state that came with it.
 *
 * The state rides the error because every caller already handles a refusal;
 * what changes is that some refusals are a stage of a ceremony the player waits
 * through rather than the end of one.
 */
function providerError(message, progress, code) {
  const error = new Error(message);
  if (progress) error.openProgress = progress;
  // The refusal's wire code, so a read can tell the end of its session
  // (`pool_session_renewal_required`) from every other refusal.
  if (typeof code === "string" && code) error.code = code;
  return error;
}

/**
 * A refusal that asking again cannot change, such as a session that is not a
 * media session. Every other failure of an open may answer differently a
 * moment later, so the person is offered a retry for it.
 */
function finalRefusal(message) {
  const error = new Error(message);
  error.final = true;
  return error;
}

async function readProviderEnvelope(response, fallback) {
  const text = await readResponseText(response);
  let payload = null;
  if (text) {
    try {
      payload = parseJsonObject(text);
    } catch {
      throw new Error(fallback);
    }
  }
  const progress = readOpenProgress(payload);
  if (!response?.ok) {
    const message =
      typeof payload?.message === "string" && payload.message.trim() ? payload.message : fallback;
    throw providerError(message, progress, payload?.code);
  }
  if (payload?.status === "error") {
    throw providerError(
      typeof payload?.message === "string" && payload.message.trim() ? payload.message : fallback,
      progress,
      payload?.code,
    );
  }
  if (payload?.status !== "ok" || !payload.data || typeof payload.data !== "object") {
    throw new Error(fallback);
  }
  return payload.data;
}

export function buildViewerMimeType(mimeType, codecs) {
  const mime = String(mimeType || "").trim();
  const codecValue = String(codecs || "").trim();
  if (!mime || !codecValue) {
    throw new Error("Viewer response is unavailable.");
  }
  return `${mime}; codecs="${codecValue}"`;
}

export function parseViewerOpenData(data, expectedMintId) {
  if (!hasExactKeys(data, OPEN_RESPONSE_KEYS, OPTIONAL_OPEN_KEYS) || !hasValidReadAhead(data)) {
    throw new Error("Viewer response is unavailable.");
  }
  const mintId = String(data.mint_id || "");
  const viewerSessionHandle = String(data.viewer_session_handle || "");
  const mimeType = String(data.mime_type || "");
  const codecs = String(data.codecs || "");
  const segmentCount = Number(data.segment_count);
  const expiresAt = Number(data.expires_at);
  // The player renders media sessions only: an object session's geometry is
  // not a segment ladder, so refuse it here rather than misread its fields.
  if (data.content_kind !== VIEWER_CONTENT_KIND_MEDIA) {
    throw finalRefusal("Viewer response is unavailable.");
  }
  if (
    data.schema !== VIEWER_OPEN_SCHEMA ||
    mintId !== expectedMintId ||
    !MINT_ID_HEX_RE.test(mintId) ||
    !VIEWER_HANDLE_HEX_RE.test(viewerSessionHandle) ||
    data.has_init_segment !== true ||
    !mimeType ||
    !codecs ||
    !Number.isInteger(segmentCount) ||
    segmentCount <= 0 ||
    segmentCount > MAX_VIEWER_SEGMENT_COUNT ||
    !Number.isInteger(expiresAt) ||
    expiresAt <= 0
  ) {
    throw new Error("Viewer response is unavailable.");
  }
  return {
    mintId,
    viewerSessionHandle,
    mimeType,
    codecs,
    segmentCount,
    expiresAt,
  };
}

function isPositiveInteger(value) {
  return typeof value === "number" && Number.isInteger(value) && value > 0;
}

/**
 * The v2 open answer: one or two renditions, each with its own segment count.
 *
 * Renditions come back sorted into the order their parts are served (video,
 * then audio), whatever order the answer listed them in.
 */
export function parseViewerOpenDataV2(data, expectedMintId) {
  if (!hasExactKeys(data, OPEN_RESPONSE_KEYS_V2, OPTIONAL_OPEN_KEYS) || !hasValidReadAhead(data)) {
    throw new Error("Viewer response is unavailable.");
  }
  const mintId = String(data.mint_id || "");
  const viewerSessionHandle = String(data.viewer_session_handle || "");
  const expiresAt = data.expires_at;
  if (data.content_kind !== VIEWER_CONTENT_KIND_MEDIA) {
    throw finalRefusal("Viewer response is unavailable.");
  }
  if (
    data.schema !== VIEWER_OPEN_SCHEMA_V2 ||
    mintId !== expectedMintId ||
    !MINT_ID_HEX_RE.test(mintId) ||
    !VIEWER_HANDLE_HEX_RE.test(viewerSessionHandle) ||
    !isPositiveInteger(expiresAt) ||
    !Array.isArray(data.renditions) ||
    data.renditions.length < 1 ||
    data.renditions.length > RENDITION_KINDS.length
  ) {
    throw new Error("Viewer response is unavailable.");
  }
  const byKind = new Map();
  for (const entry of data.renditions) {
    if (!hasExactKeys(entry, RENDITION_KEYS_V2)) {
      throw new Error("Viewer response is unavailable.");
    }
    const kind = entry.rendition;
    const segmentCount = entry.segment_count;
    if (
      !RENDITION_KINDS.includes(kind) ||
      byKind.has(kind) ||
      entry.mime_type !== RENDITION_MIME_TYPES[kind] ||
      typeof entry.codecs !== "string" ||
      !RENDITION_CODECS_RES[kind].test(entry.codecs) ||
      !isPositiveInteger(segmentCount) ||
      segmentCount > MAX_VIEWER_SEGMENT_COUNT_V2
    ) {
      throw new Error("Viewer response is unavailable.");
    }
    byKind.set(kind, { kind, mimeType: entry.mime_type, codecs: entry.codecs, segmentCount });
  }
  const renditions = RENDITION_KINDS.filter((kind) => byKind.has(kind)).map((kind) =>
    byKind.get(kind),
  );
  return {
    mintId,
    viewerSessionHandle,
    expiresAt,
    renditions,
    // The codecs of every rendition together, so the presentation rule reads a
    // v2 session the way it reads a v1 one.
    codecs: renditions.map((rendition) => rendition.codecs).join(","),
  };
}

/** Reads an open answer of whichever version it declares; v1 is the default. */
export function parseViewerOpen(data, expectedMintId) {
  return data?.schema === VIEWER_OPEN_SCHEMA_V2
    ? parseViewerOpenDataV2(data, expectedMintId)
    : parseViewerOpenData(data, expectedMintId);
}

function decodeBase64(base64Text) {
  const value = String(base64Text || "");
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error("Media data is unavailable.");
  }
  if (value.length > MAX_VIEWER_MEDIA_PART_BASE64_BYTES) {
    throw new Error("Media data is unavailable.");
  }
  try {
    if (typeof atob === "function") {
      const binary = atob(value);
      if (btoa(binary) !== value) {
        throw new Error("Media data is unavailable.");
      }
      const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
      if (bytes.length > MAX_VIEWER_MEDIA_PART_BYTES) {
        throw new Error("Media data is unavailable.");
      }
      return bytes;
    }
    const buffer = Buffer.from(value, "base64");
    if (buffer.toString("base64") !== value) {
      throw new Error("Media data is unavailable.");
    }
    if (buffer.length > MAX_VIEWER_MEDIA_PART_BYTES) {
      throw new Error("Media data is unavailable.");
    }
    return Uint8Array.from(buffer);
  } catch {
    throw new Error("Media data is unavailable.");
  }
}

export function parseViewerPartData(data, expectedMintId, expectedHandle) {
  if (!hasExactKeys(data, PART_RESPONSE_KEYS)) {
    throw new Error("Media data is unavailable.");
  }
  const mintId = String(data.mint_id || "");
  const viewerSessionHandle = String(data.viewer_session_handle || "");
  if (
    data.schema !== VIEWER_PART_SCHEMA ||
    mintId !== expectedMintId ||
    viewerSessionHandle !== expectedHandle ||
    data.encoding !== "base64" ||
    !MINT_ID_HEX_RE.test(mintId) ||
    !VIEWER_HANDLE_HEX_RE.test(viewerSessionHandle)
  ) {
    throw new Error("Media data is unavailable.");
  }
  const bytes = decodeBase64(String(data.data || ""));
  if (!bytes.length) {
    throw new Error("Media data is unavailable.");
  }
  return bytes;
}

/**
 * Whether the rendition carries an image track of its own. Read from the
 * declared codec list rather than the container type, so a rendition that
 * carries a picture is recognised whichever container it arrives in.
 */
export function renditionHasImageTrack(codecs) {
  return String(codecs || "")
    .split(",")
    .map((codec) => codec.trim().toLowerCase())
    .some((codec) => IMAGE_TRACK_CODEC_PREFIXES.some((prefix) => codec.startsWith(prefix)));
}

/**
 * How to present a session, highest precedence first:
 *
 *   1. the rendition's own image track - the decoder paints the frame;
 *   2. a poster set on the element - shown in the frame instead;
 *   3. neither - the frame collapses to the height of its own controls.
 *
 * Nothing is substituted at step 3: with no image track and no poster the
 * player shows no picture at all rather than standing in for one.
 */
export function presentationFor(session, poster) {
  if (renditionHasImageTrack(session?.codecs)) {
    return PRESENTATION_IMAGE_TRACK;
  }
  return String(poster || "").trim() ? PRESENTATION_POSTER : PRESENTATION_CONTROLS_ONLY;
}

function mediaSourceSupported(MediaSourceLike, mimeType) {
  return (
    MediaSourceLike &&
    typeof MediaSourceLike.isTypeSupported === "function" &&
    MediaSourceLike.isTypeSupported(mimeType)
  );
}

function createDeferred() {
  let resolve;
  let reject;
  const promise = new Promise((nextResolve, nextReject) => {
    resolve = nextResolve;
    reject = nextReject;
  });
  return { promise, resolve, reject };
}

function appendBytes(sourceBuffer, bytes) {
  if (!(bytes instanceof Uint8Array) || !bytes.length) {
    return Promise.reject(new Error("Media data is unavailable."));
  }
  const deferred = createDeferred();
  const onUpdateEnd = () => {
    cleanup();
    deferred.resolve();
  };
  const onError = () => {
    cleanup();
    deferred.reject(new Error("Media data is unavailable."));
  };
  const cleanup = () => {
    sourceBuffer.removeEventListener("updateend", onUpdateEnd);
    sourceBuffer.removeEventListener("error", onError);
  };
  sourceBuffer.addEventListener("updateend", onUpdateEnd, { once: true });
  sourceBuffer.addEventListener("error", onError, { once: true });
  try {
    sourceBuffer.appendBuffer(bytes);
  } catch (error) {
    cleanup();
    deferred.reject(error instanceof Error ? error : new Error("Media data is unavailable."));
  }
  return deferred.promise;
}

function responseFallback(op) {
  if (op === "open_viewer") return MEDIA_UNAVAILABLE;
  if (op === "read_viewer") return "Media data is unavailable.";
  return "Viewer session is unavailable.";
}

/**
 * Attaches `mediaSource` to `video` and returns the object URL to revoke,
 * or "" when none was made. An engine that takes a MediaSource as
 * `srcObject` (WebKit) needs no URL, which is also the only way it plays in
 * the Player's sandboxed document; Chromium refuses one there with a
 * TypeError and takes it only through a `blob:` URL.
 */
export function attachMediaSource(video, mediaSource, urlObject) {
  if ("srcObject" in video) {
    try {
      video.srcObject = mediaSource;
      return "";
    } catch (error) {
      if (error?.name !== "TypeError") throw error;
    }
  }
  const objectUrl = urlObject.createObjectURL(mediaSource);
  video.src = objectUrl;
  return objectUrl;
}

export function createPlayerController({
  documentObject = document,
  windowObject = window,
  locationObject = window.location,
  fetchImpl = fetch,
  mediaSourceClass = globalThis.MediaSource,
  urlObject = URL,
  // The clock and the timer are taken as inputs so the waiting can be driven
  // in a test without waiting through it.
  nowSeconds = () => Math.floor(Date.now() / 1000),
  setTimeoutImpl = (handler, delay) => setTimeout(handler, delay),
  clearTimeoutImpl = (handle) => clearTimeout(handle),
} = {}) {
  const video = documentObject.getElementById("player-video");
  const status = documentObject.getElementById("player-status");
  const overlay = documentObject.getElementById("player-overlay");
  const overlayText = documentObject.getElementById("player-overlay-text");
  const { mintId, homeToken: launchHomeToken } = readLaunchContext(locationObject);
  // Home renews this frame's launch authority before it expires; every
  // request reads the current token.
  let homeToken = launchHomeToken;
  let session = null;
  let objectUrl = "";
  let closed = false;
  let closePromise = null;
  let failed = false;
  // The ceremony's own state. `attempts` counts asks of one waiting stage, so
  // moving from one stage to another starts its bound afresh.
  let resumeTimer = null;
  let resumeStage = "";
  let attempts = 0;
  let disposed = false;
  let retryButton = null;
  let mediaSource = null;
  let lookaheadResolve = null;
  // Plan B T4.5: lets a reopen waiting on the Wallet go when the page does.
  let reopenWake = null;
  // J3-F8 (STAB-39): a v2 seek into a range the browser no longer holds. The
  // segment it lands in, read again on a reopened session; `null` otherwise.
  let seekTo = null;
  // The v2 SourceBuffers, one per rendition, while a v2 session plays.
  let renditionBuffers = [];
  // Whether the v2 read loop is running (a seek after it ended restarts it).
  let reading = false;

  /** Lets a read waiting on the playhead go and look at the page again. */
  function releaseLookahead() {
    const resolve = lookaheadResolve;
    lookaheadResolve = null;
    resolve?.();
  }

  function setStatus(message, state = "info") {
    status.textContent = message;
    status.dataset.state = state;
    overlayText.textContent = message;
  }

  function clearRetry() {
    if (retryButton && typeof overlay.removeChild === "function") {
      try {
        overlay.removeChild(retryButton);
      } catch {}
    }
    retryButton = null;
  }

  function showOverlay(message, state = "info", action = null) {
    setStatus(message, state);
    overlay.hidden = false;
    clearRetry();
    if (!action) return;
    const button = documentObject.createElement("button");
    button.type = "button";
    button.className = "player-action";
    button.textContent = action.label;
    button.addEventListener("click", action.run);
    overlay.appendChild(button);
    retryButton = button;
    // Focus follows the state that changed, so a person playing by keyboard
    // reaches the one control this overlay offers.
    try {
      button.focus?.();
    } catch {}
  }

  /** Stops the waiting. Called wherever the player stops caring about it. */
  function cancelResume() {
    if (resumeTimer !== null) {
      clearTimeoutImpl(resumeTimer);
      resumeTimer = null;
    }
  }

  function hideOverlay(message = "Ready") {
    status.textContent = message;
    status.dataset.state = "ready";
    overlay.hidden = true;
  }

  function clearMedia() {
    renditionBuffers = [];
    seekTo = null;
    try {
      video.pause?.();
    } catch {}
    // An open MediaSource holds its buffers until it is ended. Giving it back
    // before the object URL is revoked means neither outlives this page.
    if (mediaSource) {
      try {
        if (mediaSource.readyState === "open") mediaSource.endOfStream?.();
      } catch {}
      mediaSource = null;
    }
    if (objectUrl) {
      urlObject.revokeObjectURL?.(objectUrl);
      objectUrl = "";
    }
    if ("srcObject" in video && video.srcObject) video.srcObject = null;
    if (typeof video.removeAttribute === "function") {
      video.removeAttribute("src");
    } else {
      video.src = "";
    }
    video.load?.();
  }

  async function postProvider(op, body, options = {}) {
    if (!homeToken) {
      throw new Error(MEDIA_UNAVAILABLE);
    }
    const response = await fetchImpl(`/api/provider/object/${op}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-elastos-home-token": homeToken,
      },
      body: JSON.stringify(body),
      ...(options.keepalive ? { keepalive: true } : {}),
    });
    return readProviderEnvelope(response, responseFallback(op));
  }

  async function closeViewer(options = {}) {
    // A reopen waiting on the Wallet stops with the session (Plan B T4.5).
    wakeReopen();
    if (closePromise || closed || !session) {
      return closePromise || Promise.resolve();
    }
    closed = true;
    closePromise = postProvider(
      "close_viewer",
      {
        mint_id: session.mintId,
        viewer_session_handle: session.viewerSessionHandle,
      },
      options,
    ).catch(() => {
      if (!options.quiet) {
        throw new Error("Viewer session is unavailable.");
      }
    });
    return closePromise;
  }

  /**
   * The end of this attempt.
   *
   * `retry` is offered only where asking again could answer differently. A
   * refusal Runtime called final gets no button, because a button that cannot
   * work invites the person to keep trying something already decided.
   */
  async function fail(message, { retry = false } = {}) {
    // A page that has gone away has nothing to show and nothing to close. The
    // video element fires an error as its MediaSource is torn down, so without
    // this the overlay would be repainted on a page nobody is looking at.
    if (failed || disposed) {
      return;
    }
    failed = true;
    cancelResume();
    releaseLookahead();
    clearMedia();
    showOverlay(message, "error", retry ? { label: RETRY_LABEL, run: () => void restart() } : null);
    await closeViewer({ quiet: true });
  }

  /** An explicit retry after a terminal failure, asked for by the person. */
  async function restart() {
    if (disposed) return;
    failed = false;
    closed = false;
    closePromise = null;
    session = null;
    attempts = 0;
    resumeStage = "";
    clearRetry();
    await attemptPlayback();
  }

  /**
   * Waits, then asks again with the identical open.
   *
   * The same request is re-issued rather than a new one built: Runtime resumes
   * the attempt it already has, against the recipient the decrypt provider
   * still holds, so asking again is how the person's approval is collected --
   * not a second release.
   */
  function scheduleResume(progress) {
    if (disposed) return false;
    if (progress.stage !== resumeStage) {
      resumeStage = progress.stage;
      attempts = 0;
    }
    const policy = RESUME_POLICY.get(progress.stage);
    if (!policy) return false;
    attempts += 1;
    if (attempts > policy.maxAttempts) return false;
    // Runtime says when the wallet request lapses. Stopping with it means the
    // player stops asking at the moment there is nothing left to answer.
    if (progress.expiresAt && nowSeconds() >= progress.expiresAt) return false;
    showOverlay(waitingMessage(progress, nowSeconds()));
    cancelResume();
    resumeTimer = setTimeoutImpl(() => {
      resumeTimer = null;
      void attemptPlayback();
    }, policy.intervalMs);
    return true;
  }

  /** The page went away or closed while a reopen ran: stop, quietly. */
  function stopped() {
    const error = new Error(MEDIA_UNAVAILABLE);
    error.stopped = true;
    return error;
  }

  /** A reopen's own failure: it ends the playback, and is not waited through again. */
  function renewalFailure(error) {
    const failure = error instanceof Error ? error : new Error(MEDIA_UNAVAILABLE);
    failure.renewal = true;
    return failure;
  }

  function wakeReopen() {
    const wake = reopenWake;
    reopenWake = null;
    wake?.();
  }

  function waitBeforeReopen(intervalMs) {
    return new Promise((resolve) => {
      reopenWake = resolve;
      cancelResume();
      resumeTimer = setTimeoutImpl(() => {
        resumeTimer = null;
        wakeReopen();
      }, intervalMs);
    });
  }

  /** A reopened session reads on only if it is the same media, part for part. */
  function sameShape(next, current) {
    if (!current || Boolean(next.renditions) !== Boolean(current.renditions)) return false;
    if (!current.renditions) {
      return (
        next.mimeType === current.mimeType &&
        next.codecs === current.codecs &&
        next.segmentCount === current.segmentCount
      );
    }
    return (
      next.renditions.length === current.renditions.length &&
      next.renditions.every((rendition, index) => {
        const kept = current.renditions[index];
        return (
          rendition.kind === kept.kind &&
          rendition.mimeType === kept.mimeType &&
          rendition.codecs === kept.codecs &&
          rendition.segmentCount === kept.segmentCount
        );
      })
    );
  }

  /** Hands back a session opened after this page stopped caring about it. */
  async function closeHandle(opened) {
    try {
      await postProvider(
        "close_viewer",
        { mint_id: opened.mintId, viewer_session_handle: opened.viewerSessionHandle },
        { keepalive: true },
      );
    } catch {}
  }

  /**
   * Plan B T4.5 (C3): the session ended with the signed rights. The open runs
   * once more, through its own stages: its `rights_approval` stage is the one
   * Wallet prompt, shown as the approval stage with nothing to press. The old
   * handle is dropped; Runtime already ended its sessions.
   */
  async function reopenSession() {
    const stale = session;
    let stage = "";
    let tries = 0;
    for (;;) {
      if (disposed || closed || failed) throw stopped();
      try {
        const next = parseViewerOpen(await postProvider("open_viewer", { mint_id: mintId }), mintId);
        if (disposed || closed || failed) {
          await closeHandle(next);
          throw stopped();
        }
        // Kept first, so a refusal below still closes what this opened.
        session = next;
        cancelResume();
        resumeStage = "";
        attempts = 0;
        if (!sameShape(next, stale)) throw new Error(MEDIA_UNAVAILABLE);
        hideOverlay("Playing");
        return;
      } catch (error) {
        if (error?.stopped) throw error;
        const progress = error?.openProgress ?? null;
        const policy = progress?.resumable ? RESUME_POLICY.get(progress.stage) : null;
        if (!policy) throw renewalFailure(error);
        if (progress.stage !== stage) {
          stage = progress.stage;
          tries = 0;
        }
        tries += 1;
        if (tries > policy.maxAttempts || (progress.expiresAt && nowSeconds() >= progress.expiresAt)) {
          throw renewalFailure(error);
        }
        resumeStage = progress.stage;
        attempts = tries;
        showOverlay(waitingMessage(progress, nowSeconds()));
        await waitBeforeReopen(policy.intervalMs);
      }
    }
  }

  // Reads that meet the session's end together share one reopen.
  const reopenOnce = singleFlight(reopenSession);

  /**
   * C3 (S4B-F1): a read the server did not answer before the rights expire
   * keeps this handle and its budget. It stalls with Retry, and is asked
   * again on the same handle when the person presses it or when the rights
   * expire; nothing is closed and no open runs before then. The local clock
   * only wakes the same read: once it says the rights have expired, it wakes
   * it at most `LATE_READ_RETRIES` times, and only the Runtime's typed
   * `pool_session_renewal_required` reopens.
   */
  function stallRead(error, wakeInMs) {
    return new Promise((resolve) => {
      reopenWake = resolve;
      cancelResume();
      if (wakeInMs !== null) {
        resumeTimer = setTimeoutImpl(() => {
          resumeTimer = null;
          wakeReopen();
        }, wakeInMs);
      }
      const message = error instanceof Error && error.message ? error.message : MEDIA_UNAVAILABLE;
      showOverlay(message, "error", { label: RETRY_LABEL, run: wakeReopen });
    });
  }

  /**
   * One part of the session, by `segmentIndex` (`null` for an init). For a
   * v2 segment, `rendition` is the rendition this read is for: Runtime walks
   * the renditions of a segment in order, and a reopened session starts a
   * segment at rendition 0 (D6), so a renewal met at a later rendition asks
   * the caller to restart the segment (`error.restartSegment`).
   */
  async function readPart(segmentIndex = null, rendition = 0) {
    let renewed = false;
    let stalled = false;
    let earlyWakes = 0;
    let lateWakes = 0;
    for (;;) {
      // A seek owns the next segment now, including when this read woke
      // from a stall. Let the one segment loop hand back the old session.
      if (segmentIndex !== null && seekTo !== null) {
        const interrupted = new Error(MEDIA_UNAVAILABLE);
        interrupted.seekRequested = true;
        throw interrupted;
      }
      const current = session;
      try {
        const data = await postProvider("read_viewer", {
          mint_id: current.mintId,
          viewer_session_handle: current.viewerSessionHandle,
          ...(segmentIndex === null ? {} : { segment_index: segmentIndex }),
        });
        const part = parseViewerPartData(data, current.mintId, current.viewerSessionHandle);
        if (stalled) {
          clearRetry();
          hideOverlay("Playing");
        }
        return part;
      } catch (error) {
        if (error?.final === true) throw error;
        if (disposed || closed || failed) throw stopped();
        // A seek that arrived during this request uses its own reopen,
        // rather than first renewing the part the person left behind.
        if (segmentIndex !== null && seekTo !== null) continue;
        // Only the Runtime's typed end of the session reopens, once per part.
        if (error?.code === POOL_SESSION_RENEWAL_REQUIRED) {
          if (renewed) throw error;
          renewed = true;
          if (session === current) await reopenOnce();
          if (rendition > 0) {
            const restart = new Error(MEDIA_UNAVAILABLE);
            restart.restartSegment = true;
            throw restart;
          }
          continue;
        }
        const untilExpiry = current.expiresAt - nowSeconds();
        let wakeInMs = null;
        if (untilExpiry > 0) {
          // J3-F10 (D6): a read the pool dropped (Runtime's typed transient
          // code) is asked again within seconds, a few times; then, and for
          // every other early failure, the stall holds until the rights
          // expire (C3).
          wakeInMs = untilExpiry * 1000;
          if (error?.code === POOL_READ_UNAVAILABLE && earlyWakes < EARLY_READ_RETRIES) {
            earlyWakes += 1;
            wakeInMs = Math.min(wakeInMs, EARLY_READ_RETRY_MS);
          }
        } else if (lateWakes < LATE_READ_RETRIES) {
          lateWakes += 1;
          wakeInMs = LATE_READ_RETRY_MS;
        }
        stalled = true;
        await stallRead(error, wakeInMs);
        cancelResume();
        if (disposed || closed || failed) throw stopped();
        showOverlay("Loading media...");
      }
    }
  }

  async function startPlayback() {
    // A launch with nothing chosen is not a failure, so it is said once and
    // plainly: it names where media comes from instead of reporting that
    // something is unavailable, which would describe an item never named.
    if (!mintId) {
      showOverlay(NOTHING_CHOSEN);
      return;
    }
    if (!MINT_ID_HEX_RE.test(mintId)) {
      showOverlay(MEDIA_UNAVAILABLE, "error");
      return;
    }
    if (!mediaSourceClass) {
      showOverlay("This browser cannot play protected media.", "error");
      return;
    }
    await attemptPlayback();
  }

  /** Seconds of this rendition already buffered ahead of the playhead. */
  function bufferedAhead(sourceBuffer) {
    const ranges = sourceBuffer.buffered;
    if (!ranges || !ranges.length) return 0;
    return ranges.end(ranges.length - 1) - (Number(video.currentTime) || 0);
  }

  async function waitForLookahead(sourceBuffer) {
    while (
      !disposed &&
      !closed &&
      !failed &&
      seekTo === null &&
      bufferedAhead(sourceBuffer) > LOOKAHEAD_SECONDS
    ) {
      await new Promise((resolve) => {
        lookaheadResolve = resolve;
      });
    }
  }

  /** Whether `time` lies inside one of the ranges this SourceBuffer holds. */
  function isBuffered(sourceBuffer, time) {
    const ranges = sourceBuffer.buffered;
    if (!ranges || !ranges.length) return false;
    for (let index = 0; index < ranges.length; index += 1) {
      const start = typeof ranges.start === "function" ? ranges.start(index) : 0;
      if (start <= time && time <= ranges.end(index)) return true;
    }
    return false;
  }

  /**
   * The segment a v2 seek lands in, one back to be safe: segments are near
   * enough equal in length that `duration / segmentCount` places it, and a
   * segment read too early costs one read where one read too late leaves a
   * gap the playhead cannot cross. Segment 0 when the duration is not known.
   */
  function segmentFor(time) {
    const count = session.renditions[0].segmentCount;
    const duration = Number(video.duration);
    if (!(duration > 0) || !Number.isFinite(duration) || count < 1) return 0;
    const landed = Math.floor((Math.max(0, time) / duration) * count);
    return Math.max(0, Math.min(count - 1, landed) - 1);
  }

  /**
   * J3-F8 (STAB-39): a v2 seek into a range the browser evicted. Runtime
   * releases a session's parts in order and never again, so the range is
   * read on a reopened session, which starts where its first read asks
   * (D6): the same path a renewal takes, the Wallet prompt included.
   */
  function onSeeking() {
    if (disposed || closed || failed || !session?.renditions || !renditionBuffers.length) return;
    const time = Number(video.currentTime) || 0;
    if (renditionBuffers.every((sourceBuffer) => isBuffered(sourceBuffer, time))) return;
    seekTo = segmentFor(time);
    showOverlay("Loading media...");
    // A read waiting on the playhead, or stalled, looks at the seek now.
    releaseLookahead();
    wakeReopen();
    if (!reading) void runReader(renditionBuffers, seekTo);
  }

  /** The old session is handed back and a new one opened, as at a renewal. */
  async function reopenAtSeek() {
    const target = seekTo;
    seekTo = null;
    await closeHandle(session);
    await reopenOnce();
    return target;
  }

  /**
   * Segment `segmentIndex` of every rendition that has it, in Runtime's
   * order. `false` when the loop must stop here (the page went away, or a
   * seek asks for another segment).
   */
  async function readSegment(buffers, segmentIndex) {
    for (let index = 0; index < buffers.length; index += 1) {
      if (segmentIndex >= session.renditions[index].segmentCount) continue;
      await waitForLookahead(buffers[index]);
      // A page that closed part way through stops reading rather than
      // appending into a source nobody is watching.
      if (disposed || closed || failed || seekTo !== null) return false;
      let part;
      try {
        part = await readPart(segmentIndex, index);
      } catch (error) {
        if (error?.seekRequested) return false;
        // A renewal met past rendition 0: the segment restarts at 0.
        if (error?.restartSegment) {
          index = -1;
          continue;
        }
        throw error;
      }
      if (seekTo !== null) return false;
      await appendBytes(buffers[index], part);
    }
    return true;
  }

  /** The v2 segment loop from `start`; a seek moves it to another segment. */
  async function readSegmentsFrom(buffers, start) {
    reading = true;
    try {
      const longest = Math.max(...session.renditions.map((rendition) => rendition.segmentCount));
      let segmentIndex = start;
      let first = true;
      while (segmentIndex < longest) {
        if (seekTo !== null) {
          segmentIndex = await reopenAtSeek();
          first = true;
          continue;
        }
        if (!(await readSegment(buffers, segmentIndex))) {
          if (seekTo !== null) continue;
          return;
        }
        if (first) {
          first = false;
          hideOverlay("Playing");
          try {
            await video.play?.();
          } catch {}
        }
        segmentIndex += 1;
      }
      if (mediaSource) mediaSource.endOfStream?.();
    } finally {
      reading = false;
    }
  }

  /** The segment loop started on its own, after a seek past the loop's end. */
  async function runReader(buffers, start) {
    try {
      await readSegmentsFrom(buffers, start);
    } catch (error) {
      await endAttempt(error);
    }
  }

  /**
   * v2: one SourceBuffer per rendition, fed in the order Runtime serves parts:
   * every init, then segment i of each rendition in turn.
   */
  async function playRenditions(mimeTypes) {
    const buffers = mimeTypes.map((mimeType) => mediaSource.addSourceBuffer(mimeType));
    // Initialization owns the same reader as the segment loop. A seek
    // queues until all inits arrive, then the loop reopens at its target.
    reading = true;
    renditionBuffers = buffers;
    try {
      for (const sourceBuffer of buffers) {
        await appendBytes(sourceBuffer, await readPart());
      }
      await readSegmentsFrom(buffers, 0);
    } finally {
      reading = false;
    }
  }

  async function attemptPlayback() {
    if (disposed) return;
    showOverlay("Loading media...");
    try {
      session = parseViewerOpen(await postProvider("open_viewer", { mint_id: mintId }), mintId);
      // A page that went away while this open was in flight still opened a
      // session, so it is handed back rather than left to expire on its own.
      if (disposed) {
        await closeViewer({ keepalive: true, quiet: true });
        return;
      }
      // The ceremony finished, so nothing is waiting on it any more.
      cancelResume();
      resumeStage = "";
      attempts = 0;
      const mimeTypes = session.renditions
        ? session.renditions.map((rendition) =>
            buildViewerMimeType(rendition.mimeType, rendition.codecs),
          )
        : [buildViewerMimeType(session.mimeType, session.codecs)];
      if (!mimeTypes.every((mimeType) => mediaSourceSupported(mediaSourceClass, mimeType))) {
        await fail("This browser cannot play protected media.");
        return;
      }
      // Only a rendition with neither an image track nor a poster collapses to
      // the height of its own controls; either kind of picture keeps the frame.
      const presentation = presentationFor(session, video.getAttribute?.("poster") ?? video.poster);
      video.classList?.toggle?.(AUDIO_ONLY_CLASS, presentation === PRESENTATION_CONTROLS_ONLY);
      mediaSource = new mediaSourceClass();
      objectUrl = attachMediaSource(video, mediaSource, urlObject);
      const sourceOpen = createDeferred();
      mediaSource.addEventListener("sourceopen", () => sourceOpen.resolve(), { once: true });
      await sourceOpen.promise;
      if (session.renditions) {
        await playRenditions(mimeTypes);
        return;
      }
      const sourceBuffer = mediaSource.addSourceBuffer(mimeTypes[0]);
      await appendBytes(sourceBuffer, await readPart());
      await appendBytes(sourceBuffer, await readPart(0));
      hideOverlay("Playing");
      try {
        await video.play?.();
      } catch {}
      for (let segmentIndex = 1; segmentIndex < session.segmentCount; segmentIndex += 1) {
        // J3-F7: the same pacing as v2, so a long item never overflows the
        // SourceBuffer.
        await waitForLookahead(sourceBuffer);
        // A page that closed part way through stops reading rather than
        // appending into a source nobody is watching.
        if (disposed || closed || failed) return;
        await appendBytes(sourceBuffer, await readPart(segmentIndex));
      }
      if (mediaSource) mediaSource.endOfStream?.();
    } catch (error) {
      await endAttempt(error);
    }
  }

  /** How an attempt that threw ends: waited through, or failed with a choice. */
  async function endAttempt(error) {
    // The page went away or closed during a reopen: nothing to show.
    if (error?.stopped) return;
    const progress = error?.openProgress ?? null;
    // A stage the player knows how to wait through is waited through. Only
    // when the waiting itself is over does this become a failure, and then
    // the person is offered the choice to ask again. A failure with no stage
    // -- a release that ran out of time, a segment that did not arrive --
    // gets the same choice, unless it is a refusal asking again cannot change.
    // A reopen at rights expiry already waited through its own stages.
    if (!error?.renewal && progress?.resumable && scheduleResume(progress)) return;
    const message = error instanceof Error && error.message ? error.message : MEDIA_UNAVAILABLE;
    await fail(message, { retry: progress ? progress.resumable : error?.final !== true });
  }

  /**
   * Gives back everything this page is holding.
   *
   * Reached from the page going away and from nothing else, so it is the one
   * place the timer, the MediaSource, the object URL and the session are
   * released together.
   */
  function dispose() {
    if (disposed) return;
    disposed = true;
    cancelResume();
    wakeReopen();
    releaseLookahead();
    clearMedia();
    void closeViewer({ keepalive: true, quiet: true });
  }

  video.addEventListener("ended", () => {
    void closeViewer({ quiet: true });
  });
  video.addEventListener("timeupdate", releaseLookahead);
  video.addEventListener("seeking", onSeeking);
  video.addEventListener("error", () => {
    void fail("Playback failed.");
  });
  windowObject.addEventListener("pagehide", dispose, { once: true });

  return {
    startPlayback,
    closeViewer,
    dispose,
    /** Home renewed this frame's launch authority; later requests carry it. */
    setHomeToken(token) {
      if (typeof token === "string" && token.trim()) {
        homeToken = token.trim();
      }
    },
    getSession() {
      return session;
    },
    getState() {
      return {
        closed,
        failed,
        mintId,
        waiting: resumeTimer !== null,
        waitingStage: resumeStage,
        attempts,
        disposed,
        retryOffered: retryButton !== null,
      };
    },
  };
}

/**
 * Lets Home renew this frame's launch authority before it expires (#532).
 * Home serves its navigation client at an absolute path, so it is loaded in
 * the browser only, and this module stays importable under `node --test`.
 * A renewal relaunches the same item.
 */
function connectHomeNavigation(controller, locationLike) {
  const { mintId, homeToken } = readLaunchContext(locationLike);
  return import("/apps/home/home-navigation-client.js")
    .then(({ createHomeNavigationClient }) => {
      const navigation = createHomeNavigationClient({
        homeToken,
        homeOrigin: readSearchParam(locationLike, "home_origin").trim(),
        target: "elacity-player",
        onHomeToken: (token) => controller.setHomeToken(token),
      });
      if (mintId) {
        navigation.setQuery({ mint_id: mintId });
      }
      return navigation;
    })
    .catch((error) => {
      console.warn("Home cannot renew this window's access", error);
      return null;
    });
}

export function bootstrapPlayer() {
  const controller = createPlayerController();
  void connectHomeNavigation(controller, window.location);
  void controller.startPlayback();
  return controller;
}

if (typeof window !== "undefined" && typeof document !== "undefined") {
  bootstrapPlayer();
}
