// DEMO-ISSUES A: the Elacity Player in a real browser, under the document
// policy Runtime serves for it.
//
// The Player attaches every protected video through
// `URL.createObjectURL(MediaSource)` (player.js). Whether the browser lets a
// `blob:` URL load is decided by the document's `media-src`, which Runtime
// sets in `shell_content_security_policy` (browser_capsules.rs). This test
// builds that exact policy from the Runtime source, serves the real Player
// files under it, and plays a real DASH v2 item (avc1.640028 + mp4a.40.2,
// the Player's pinned pair) through stub `/api/provider/object/*` routes.
//
// The control serves the same Player and media under the same policy with
// only `blob:` added to `media-src`, so nothing else on the client path
// (open parse, MediaSource, append, play) is left unproven.
//
// Needs ffmpeg (libx264 + aac) and the product smoke browser with H.264/AAC.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { importProductSmokePlaywright, productSmokeLaunchOptions } from "./product-smoke-browser.mjs";

const repoRoot = fileURLToPath(new URL("../", import.meta.url));
const playerRoot = join(repoRoot, "capsules/elacity-player/browser");
const capsulePolicySource = join(
  repoRoot,
  "elastos/crates/elastos-server/src/api/browser_capsules.rs",
);
const MINT = "4".repeat(64);
const HANDLE = "5".repeat(64);

/**
 * The policy `shell_content_security_policy` returns for the
 * `elacity-player` document, read from the Runtime source so this test
 * follows the code rather than a copy of it.
 */
function runtimePlayerPolicy(homeSource) {
  const source = readFileSync(capsulePolicySource, "utf8");
  const media = source.match(/"elacity-player" => Some\(\("", format!\("([^"]+)"\)\)\)/);
  const template = source.match(
    /"(sandbox allow-scripts allow-forms allow-downloads; default-src \{home_source\};[^"]*\{media\}[^"]*)"/,
  );
  assert.ok(media, "browser_capsules.rs: the elacity-player media directive was not found");
  assert.ok(template, "browser_capsules.rs: the viewer policy template was not found");
  return template[1]
    .replaceAll("{script_eval}", "")
    .replaceAll("{media}", media[1])
    .replaceAll("{home_source}", homeSource);
}

function withBlobMedia(policy) {
  return policy.replace(/media-src ([^;]+)/, "media-src $1 blob:");
}

function ffmpegAvailable() {
  const probe = spawnSync("ffmpeg", ["-hide_banner", "-encoders"], { encoding: "utf8" });
  return probe.status === 0 && probe.stdout.includes("libx264");
}

/** A short DASH v2 item: one video and one audio rendition, 1 s segments. */
function makeDashItem(dir) {
  const result = spawnSync(
    "ffmpeg",
    [
      "-hide_banner", "-loglevel", "error",
      "-f", "lavfi", "-i", "testsrc=size=320x240:rate=25",
      "-f", "lavfi", "-i", "sine=frequency=440:sample_rate=48000",
      "-t", "3", "-map", "0:v", "-map", "1:a",
      "-c:v", "libx264", "-profile:v", "high", "-level", "4.0", "-pix_fmt", "yuv420p",
      "-g", "25", "-keyint_min", "25", "-sc_threshold", "0",
      "-c:a", "aac", "-b:a", "64k", "-ac", "2",
      "-f", "dash", "-seg_duration", "1", "-use_template", "1", "-use_timeline", "0",
      "-init_seg_name", "init-$RepresentationID$.m4s",
      "-media_seg_name", "chunk-$RepresentationID$-$Number%05d$.m4s",
      "-adaptation_sets", "id=0,streams=v id=1,streams=a",
      join(dir, "item.mpd"),
    ],
    { encoding: "utf8" },
  );
  assert.equal(result.status, 0, `ffmpeg failed: ${result.stderr}`);
  const mpd = readFileSync(join(dir, "item.mpd"), "utf8");
  assert.match(mpd, /codecs="avc1\.640028"/);
  assert.match(mpd, /codecs="mp4a\.40\.2"/);
  const segments = (rendition) =>
    readdirSync(dir)
      .filter((name) => name.startsWith(`chunk-${rendition}-`))
      .sort()
      .map((name) => readFileSync(join(dir, name)));
  const video = segments(0);
  const audio = segments(1);
  // The fixed v2 interleave Runtime serves: both inits, then segment i of
  // each rendition in turn, skipping a rendition that has no segment i.
  const parts = [
    { segmentIndex: null, bytes: readFileSync(join(dir, "init-0.m4s")) },
    { segmentIndex: null, bytes: readFileSync(join(dir, "init-1.m4s")) },
  ];
  for (let index = 0; index < Math.max(video.length, audio.length); index += 1) {
    if (index < video.length) parts.push({ segmentIndex: index, bytes: video[index] });
    if (index < audio.length) parts.push({ segmentIndex: index, bytes: audio[index] });
  }
  return {
    open: {
      schema: "elastos.library.runtime-custody-viewer/v2",
      content_kind: "media",
      mint_id: MINT,
      viewer_session_handle: HANDLE,
      expires_at: Math.floor(Date.now() / 1000) + 600,
      renditions: [
        { rendition: "video", mime_type: "video/mp4", codecs: "avc1.640028", segment_count: video.length },
        { rendition: "audio", mime_type: "audio/mp4", codecs: "mp4a.40.2", segment_count: audio.length },
      ],
    },
    parts,
  };
}

const CONTENT_TYPES = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".png": "image/png" };

function pendingOpen(stage) {
  const awaitingWallet = stage === "rights_approval";
  const now = Math.floor(Date.now() / 1000);
  return {
    status: "error",
    code: "library_error",
    message: "Runtime custody viewer release is pending",
    open_progress: {
      schema: "elastos.protected-content.open-progress/v1",
      stage,
      resumable: true,
      awaits_person: awaitingWallet,
      connector_id: awaitingWallet ? "metamask" : null,
      approval_request_id: awaitingWallet ? "approval-7" : null,
      expires_at: awaitingWallet ? now + 290 : null,
      ready_at: awaitingWallet ? null : now + 15,
    },
  };
}

/** The Player's own files under `policy`, and a provider that serves `item`. */
async function startPlayerHome(item, policyFor, waitForFinality) {
  const calls = { open_viewer: 0, read_viewer: 0, close_viewer: 0 };
  const openRequests = [];
  let nextPart = 0;
  const server = createServer((req, res) => {
    const url = new URL(req.url, "http://placeholder");
    const cors = {
      "access-control-allow-origin": "*",
      "access-control-allow-headers": "content-type, x-elastos-home-token",
      "access-control-allow-methods": "GET, POST",
      "cache-control": "no-store",
    };
    if (req.method === "OPTIONS") {
      res.writeHead(204, cors);
      res.end();
      return;
    }
    const send = (status, type, body, extra = {}) => {
      res.writeHead(status, { ...cors, "content-type": type, ...extra });
      res.end(body);
    };
    if (url.pathname.startsWith("/api/provider/object/")) {
      const op = url.pathname.slice("/api/provider/object/".length);
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        calls[op] = (calls[op] ?? 0) + 1;
        const json = (data) => send(200, "application/json", JSON.stringify({ status: "ok", data }));
        if (op === "open_viewer") {
          openRequests.push(JSON.parse(body));
          const stage = waitForFinality && ["finalizing", "rights_approval"][openRequests.length - 1];
          if (stage) return send(409, "application/json", JSON.stringify(pendingOpen(stage)));
          return json(item.open);
        }
        if (op === "close_viewer") return json({ closed: true });
        if (op === "read_viewer") {
          const request = JSON.parse(body);
          const part = item.parts[nextPart];
          const asked = request.segment_index ?? null;
          if (!part || asked !== part.segmentIndex) {
            return send(409, "application/json", JSON.stringify({ status: "error", message: "out of order" }));
          }
          nextPart += 1;
          return json({
            schema: "elastos.library.runtime-custody-viewer-part/v1",
            mint_id: MINT,
            viewer_session_handle: HANDLE,
            encoding: "base64",
            data: part.bytes.toString("base64"),
          });
        }
        send(404, "application/json", "{}");
      });
      return;
    }
    if (url.pathname === "/apps/home/home-navigation-client.js") {
      send(200, "text/javascript", "export function createHomeNavigationClient() { return { setQuery() {} }; }");
      return;
    }
    if (url.pathname.startsWith("/apps/elacity-player/")) {
      const relative = url.pathname.slice("/apps/elacity-player/".length) || "index.html";
      try {
        const bytes = readFileSync(join(playerRoot, relative));
        const extension = relative.slice(relative.lastIndexOf("."));
        const extra = relative === "index.html" ? { "content-security-policy": policyFor(origin) } : {};
        send(200, CONTENT_TYPES[extension] ?? "application/octet-stream", bytes, extra);
      } catch {
        send(404, "text/plain", "not found");
      }
      return;
    }
    send(404, "text/plain", "not found");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  return { origin, calls, openRequests, partsTotal: item.parts.length, partsRead: () => nextPart, close: () => server.close() };
}

/** Opens the Player as Home launches it and reports where playback ended. */
async function playUnder(policyFor, { waitForFinality = false } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "elacity-player-media-"));
  let home;
  let browser;
  const consoleLines = [];
  try {
    home = await startPlayerHome(makeDashItem(dir), policyFor, waitForFinality);
    const { chromium } = await importProductSmokePlaywright();
    browser = await chromium.launch({ ...productSmokeLaunchOptions(), headless: true });
    const page = await browser.newPage();
    page.on("console", (message) => consoleLines.push(`${message.type()}: ${message.text()}`));
    await page.goto(`${home.origin}/apps/elacity-player/?mint_id=${MINT}#home_token=demo-home-token`);
    if (waitForFinality) {
      const overlay = page.locator("#player-overlay-text");
      await overlay.filter({ hasText: /being finalized on chain/ }).waitFor({ timeout: 5_000 });
      assert.equal(home.calls.open_viewer, 1);
      assert.equal(home.calls.read_viewer, 0);
      assert.equal(await page.locator(".player-action").count(), 0);

      await overlay.filter({ hasText: /approve playing this in metamask/i }).waitFor({ timeout: 20_000 });
      assert.equal(home.calls.open_viewer, 2);
      assert.equal(home.calls.read_viewer, 0);
      assert.equal(await page.locator(".player-action").count(), 0);
    }
    await page
      .waitForFunction(
        () => {
          const status = document.getElementById("player-status")?.dataset.state;
          const video = document.getElementById("player-video");
          return status === "error" || (video && video.currentTime > 0.5);
        },
        undefined,
        { timeout: 20_000 },
      )
      .catch(() => {});
    const seen = await page.evaluate(() => {
      const video = document.getElementById("player-video");
      return {
        status: document.getElementById("player-status")?.textContent ?? "",
        state: document.getElementById("player-status")?.dataset.state ?? "",
        currentTime: video?.currentTime ?? 0,
        mediaError: video?.error ? video.error.code : null,
        src: video?.currentSrc ?? "",
      };
    });
    return { ...seen, calls: { ...home.calls }, openRequests: home.openRequests, partsRead: home.partsRead(), partsTotal: home.partsTotal, console: consoleLines };
  } finally {
    await browser?.close();
    home?.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

const skip = ffmpegAvailable() ? false : "ffmpeg with libx264 is not installed";

test("the Player plays a protected DASH v2 item under the policy Runtime serves for it", { skip }, async () => {
  const seen = await playUnder(runtimePlayerPolicy);
  assert.notEqual(
    seen.status,
    "Playback failed.",
    `the Player failed before reading any media: ${JSON.stringify(seen, null, 2)}`,
  );
  assert.equal(seen.partsRead, seen.partsTotal, JSON.stringify(seen, null, 2));
  assert.ok(seen.currentTime > 0.5, JSON.stringify(seen, null, 2));
});

test("control: the same Player and item play once media-src also allows blob:", { skip }, async () => {
  const seen = await playUnder((origin) => withBlobMedia(runtimePlayerPolicy(origin)));
  assert.equal(seen.mediaError, null, JSON.stringify(seen, null, 2));
  assert.equal(seen.calls.open_viewer, 1);
  assert.equal(seen.partsRead, seen.partsTotal, JSON.stringify(seen, null, 2));
  assert.ok(seen.currentTime > 0.5, JSON.stringify(seen, null, 2));
});

test("the Player retries after chain finality and plays once Wallet approval is ready", { skip }, async () => {
  const seen = await playUnder(runtimePlayerPolicy, { waitForFinality: true });
  assert.deepEqual(seen.openRequests, Array.from({ length: 3 }, () => ({ mint_id: MINT })));
  assert.equal(seen.partsRead, seen.partsTotal, JSON.stringify(seen, null, 2));
  assert.ok(seen.currentTime > 0.5, JSON.stringify(seen, null, 2));
});
