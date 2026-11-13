#!/usr/bin/env node

// Every state an Explore card's control can be in, rendered into a real
// browser DOM and read back the way a person meets it: what the control
// says, whether it can be pressed, and what pressing it does. The markup
// comes from the page's own module (`src/market-card.js`), so this checks
// exactly what Marketplace renders.

import { createServer } from "node:http";
import { createRequire } from "node:module";
import { readFile } from "node:fs/promises";
import { extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(fileURLToPath(new URL("../", import.meta.url)));
const browserRoot = join(repoRoot, "capsules/marketplace/browser");
const brave = process.env.BRAVE_BIN || "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser";
// The pinned Playwright the other product smokes use. A worktree without its
// own install names another checkout's engine directory here.
const engineDir = process.env.MARKETPLACE_PLAYWRIGHT_ENGINE_DIR
  || join(repoRoot, "elastos/tools/browser-playwright-engine");
const require = createRequire(join(engineDir, "package.json"));
const { chromium } = require("playwright");

function assert(condition, message, details = undefined) {
  if (!condition) {
    throw new Error(`${message}${details ? `\n${JSON.stringify(details, null, 2)}` : ""}`);
  }
}

// An ordinary Home: raw `/ipfs/` reads are refused, and `/content` answers
// only a request that carries the Home token.
const HOME_TOKEN = "fixture-home-token";
const COVER_CID = `bafy${"c".repeat(55)}`;
const METADATA_CID = `bafy${"d".repeat(55)}`;
const COVER_PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
  "base64",
);
const contentReads = [];

function serveHomeContent(url, request, response) {
  if (url.pathname.startsWith("/ipfs/")) {
    response.writeHead(404).end();
    return true;
  }
  if (!url.pathname.startsWith("/content/")) {
    return false;
  }
  const token = request.headers["x-elastos-home-token"] || "";
  contentReads.push({ path: url.pathname, token });
  if (token !== HOME_TOKEN) {
    response.writeHead(404).end();
  } else if (url.pathname === `/content/${COVER_CID}`) {
    response.writeHead(200, { "content-type": "image/png" }).end(COVER_PNG);
  } else if (url.pathname === `/content/${METADATA_CID}/metadata.json`) {
    response.writeHead(200, { "content-type": "application/json" })
      .end(JSON.stringify({ name: "Harbor at dawn", image: `ipfs://${COVER_CID}` }));
  } else {
    response.writeHead(404).end();
  }
  return true;
}

const types = { ".js": "text/javascript", ".mjs": "text/javascript", ".html": "text/html", ".css": "text/css" };

function startServer() {
  const server = createServer(async (request, response) => {
    const url = new URL(request.url, "http://localhost");
    if (serveHomeContent(url, request, response)) {
      return;
    }
    if (url.pathname === "/") {
      response.writeHead(200, { "content-type": "text/html" });
      response.end('<!doctype html><html><head><link rel="stylesheet" href="/marketplace.css"></head><body><div id="card"></div></body></html>');
      return;
    }
    const path = join(browserRoot, url.pathname);
    if (!path.startsWith(browserRoot)) {
      response.writeHead(403).end();
      return;
    }
    try {
      const body = await readFile(path);
      response.writeHead(200, { "content-type": types[extname(path)] || "application/octet-stream" });
      response.end(body);
    } catch {
      response.writeHead(404).end();
    }
  });
  return new Promise((resolveServer) => {
    server.listen(0, "127.0.0.1", () => resolveServer(server));
  });
}

const LEDGER = `0x${"e".repeat(40)}`;
const KEY = `${LEDGER}|0x3e`;
const cases = [
  {
    name: "no answer yet",
    listing: { accessState: "available" },
    ctx: { access: null },
    expect: { text: "Checking…", enabled: false, action: null },
  },
  {
    name: "a failed read waiting for its retry",
    listing: { accessState: "available" },
    ctx: { access: "transient" },
    expect: { text: "Checking…", enabled: false, action: null },
  },
  {
    name: "no access",
    listing: { accessState: "available" },
    ctx: { access: "available" },
    expect: { text: "Buy", enabled: true, action: "buy-listing" },
  },
  {
    name: "no wallet account to ask about",
    listing: { accessState: "available" },
    ctx: { access: "no_account" },
    expect: { text: "Buy", enabled: true, action: "buy-listing" },
  },
  {
    name: "access the chain grants",
    listing: { accessState: "available" },
    ctx: { access: "held" },
    expect: { text: "Open", enabled: true, action: "open-market-item" },
  },
  {
    name: "a granted copy being built",
    listing: { accessState: "available" },
    ctx: { access: "held", downloading: true },
    expect: { text: "Opening…", enabled: false, action: "open-market-item" },
  },
  {
    name: "a settled unknown",
    listing: { accessState: "available" },
    ctx: { access: "unknown" },
    expect: { text: "View", enabled: true, action: "view-listing" },
  },
  {
    name: "a pool this Home cannot reach",
    listing: { accessState: "available" },
    ctx: { access: "elsewhere" },
    expect: { text: "Pool not reachable", enabled: null, action: null },
  },
  {
    name: "a bought item whose pool this Home cannot reach",
    listing: { accessState: "purchased" },
    ctx: { access: "elsewhere", readability: "verified", hasItem: true },
    expect: { text: "Pool not reachable", enabled: null, action: null },
  },
  {
    name: "a bought item with no copy here",
    listing: { accessState: "purchased" },
    ctx: { readability: "verified", hasItem: true },
    expect: { text: "Download copy", enabled: true, action: "download-market-copy" },
  },
  {
    name: "a bought item whose copy is being built",
    listing: { accessState: "purchased" },
    ctx: { readability: "verified", hasItem: true, downloading: true },
    expect: { text: "Downloading…", enabled: false, action: "download-market-copy" },
  },
];

async function run() {
  const server = await startServer();
  const origin = `http://127.0.0.1:${server.address().port}`;
  const browser = await chromium.launch({ executablePath: brave, headless: true });
  try {
    const page = await browser.newPage();
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(String(error)));
    await page.goto(`${origin}/`);
    for (const entry of cases) {
      const seen = await page.evaluate(async ({ entry, ledger, key }) => {
        const { catalogCardControl } = await import("/src/market-card.js");
        const card = document.querySelector("#card");
        card.innerHTML = catalogCardControl(
          { ledger, tokenId: "0x3e", ...entry.listing },
          { key, size: "", ...entry.ctx },
        );
        const first = card.firstElementChild;
        const pressed = [];
        card.addEventListener("click", (event) => pressed.push(event.target.dataset.action || null), { once: true });
        first.click();
        return {
          tag: first.tagName.toLowerCase(),
          text: first.textContent,
          visible: first.getBoundingClientRect().width > 0,
          enabled: first.tagName === "BUTTON" ? !first.disabled : null,
          action: first.dataset.action || null,
          watched: first.dataset.accessKey || null,
          pressed,
          buy: [...card.querySelectorAll("button")].some((button) => button.textContent === "Buy"),
        };
      }, { entry, ledger: LEDGER, key: KEY });
      assert(seen.visible, `${entry.name}: the control is shown`, seen);
      assert(seen.text === entry.expect.text, `${entry.name}: it says ${entry.expect.text}`, seen);
      assert(seen.enabled === entry.expect.enabled, `${entry.name}: pressable is ${entry.expect.enabled}`, seen);
      assert(seen.action === entry.expect.action, `${entry.name}: it does ${entry.expect.action}`, seen);
      if (entry.expect.enabled === false) {
        assert(seen.pressed.length === 0, `${entry.name}: a disabled control does nothing when pressed`, seen);
      }
      if (entry.expect.text !== "Buy") {
        assert(!seen.buy, `${entry.name}: no Buy anywhere on the card`, seen);
      }
      if (entry.expect.text === "Checking…") {
        assert(seen.watched === KEY, `${entry.name}: the card is named for the access watch`, seen);
      }
    }
    // Covers and titles on an ordinary Home come from the token-carrying
    // content store; the raw `/ipfs/` route is refused.
    const cover = await page.evaluate(async ({ token, coverCid, metadataCid }) => {
      const { createContentReader, hydrateContentImages } = await import("/src/content-reads.js");
      const reader = createContentReader({ token });
      const metadata = await reader.json(metadataCid, "metadata.json");
      const card = document.querySelector("#card");
      card.innerHTML = `<div class="thumb app-icon-raster"><img class="app-icon-img" data-content-cid="${coverCid}" alt=""></div>
        <img class="raw" src="/ipfs/${coverCid}" alt="">`;
      const image = card.querySelector("img[data-content-cid]");
      const loaded = new Promise((resolve) => {
        image.addEventListener("load", () => resolve(true), { once: true });
        image.addEventListener("error", () => resolve(false), { once: true });
      });
      const raw = card.querySelector("img.raw");
      const rawSettled = raw.complete ? Promise.resolve() : new Promise((resolve) => {
        raw.addEventListener("load", resolve, { once: true });
        raw.addEventListener("error", resolve, { once: true });
      });
      hydrateContentImages(card, reader);
      const shown = await loaded;
      await rawSettled;
      return {
        title: metadata && metadata.name,
        shown,
        width: image.naturalWidth,
        blob: image.src.startsWith("blob:"),
        rawWidth: raw.naturalWidth,
      };
    }, { token: HOME_TOKEN, coverCid: COVER_CID, metadataCid: METADATA_CID });
    assert(cover.title === "Harbor at dawn", "The item title comes from its metadata read with the Home token", cover);
    assert(cover.shown && cover.width === 1 && cover.blob, "The cover renders from a blob URL", cover);
    assert(cover.rawWidth === 0, "The raw /ipfs/ route stays refused on an ordinary Home", cover);
    assert(contentReads.length === 2 && contentReads.every((read) => read.token === HOME_TOKEN),
      "Every content read carries the Home token, once per CID", contentReads);
    assert(pageErrors.length === 0, "The card module must render without page errors.", pageErrors);
  } finally {
    await browser.close();
    server.close();
  }
  console.log(`marketplace-card-states-dom-smoke: OK (${cases.length} states, token cover and title)`);
}

await run();
