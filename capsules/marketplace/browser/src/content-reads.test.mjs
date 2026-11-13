import assert from "node:assert/strict";
import test from "node:test";

import { contentReadPath, createContentReader, hydrateContentImages } from "./content-reads.js";

const CID = `bafy${"a".repeat(55)}`;

function response(body, ok = true) {
  return {
    ok,
    async json() {
      return JSON.parse(body);
    },
    async blob() {
      return { body };
    },
  };
}

test("Marketplace reads content only through this Home's token route", () => {
  assert.equal(contentReadPath(CID), `/content/${CID}`);
  assert.equal(contentReadPath(CID, "metadata.json"), `/content/${CID}/metadata.json`);
  assert.equal(contentReadPath(CID, "a b/c?.json"), `/content/${CID}/a%20b/c%3F.json`);
  for (const bad of ["", "not-a-cid", "../etc", `${CID}/x`]) {
    assert.equal(contentReadPath(bad), "", bad);
  }
});

test("Marketplace sends the Home token and reads metadata as JSON", async () => {
  const calls = [];
  const reader = createContentReader({
    token: "home-token",
    fetchImpl: async (route, init) => {
      calls.push({ route, init });
      return response('{"name":"Cover title"}');
    },
  });
  assert.deepEqual(await reader.json(CID, "metadata.json"), { name: "Cover title" });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].route, `/content/${CID}/metadata.json`);
  assert.equal(calls[0].init.headers["x-elastos-home-token"], "home-token");
});

test("A renewed Home token is used by the next content read", async () => {
  const tokens = [];
  const reader = createContentReader({
    token: "home-token",
    fetchImpl: async (route, init) => {
      tokens.push(init.headers["x-elastos-home-token"]);
      return response("{}");
    },
  });
  await reader.json(CID, "metadata.json");
  reader.setToken("renewed-token");
  await reader.json(CID, "other.json");
  assert.deepEqual(tokens, ["home-token", "renewed-token"]);
});

test("Marketplace reads each cover once and keeps its blob URL", async () => {
  let fetches = 0;
  const reader = createContentReader({
    token: "t",
    fetchImpl: async () => {
      fetches += 1;
      return response("png");
    },
    createObjectURL: (blob) => `blob:${blob.body}`,
  });
  const [first, second] = await Promise.all([reader.imageUrl(CID), reader.imageUrl(CID)]);
  assert.equal(first, "blob:png");
  assert.equal(second, "blob:png");
  assert.equal(fetches, 1);
});

test("Marketplace answers nothing for content this Home refuses or cannot reach", async () => {
  const refused = createContentReader({ token: "t", fetchImpl: async () => response("", false) });
  assert.equal(await refused.json(CID, "metadata.json"), null);
  assert.equal(await refused.imageUrl(CID), "");
  const offline = createContentReader({ token: "t", fetchImpl: async () => { throw new Error("down"); } });
  assert.equal(await offline.json(CID, "metadata.json"), null);
  assert.equal(await offline.imageUrl(CID), "");
});

test("Marketplace keeps at most the bounded number of reads in flight", async () => {
  let active = 0;
  let peak = 0;
  const releases = [];
  const reader = createContentReader({
    token: "t",
    limit: 2,
    fetchImpl: async () => {
      active += 1;
      peak = Math.max(peak, active);
      await new Promise((resolve) => releases.push(resolve));
      active -= 1;
      return response("{}");
    },
  });
  const reads = Array.from({ length: 5 }, () => reader.json(CID, "metadata.json"));
  for (let done = 0; done < 5; done += 1) {
    while (!releases.length) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    releases.shift()();
    await new Promise((resolve) => setImmediate(resolve));
  }
  await Promise.all(reads);
  assert.equal(peak, 2);
});

test("Marketplace gives each pending cover its blob URL or fails it once", async () => {
  const made = (cid) => {
    const image = {
      dataset: { contentCid: cid },
      src: "",
      events: [],
      dispatchEvent(event) {
        this.events.push(event.type);
      },
    };
    return image;
  };
  const shown = made(CID);
  const refused = made(`bafy${"b".repeat(55)}`);
  const root = { querySelectorAll: () => [shown, refused] };
  const reader = {
    imageUrl: async (cid) => (cid === CID ? "blob:cover" : ""),
  };
  hydrateContentImages(root, reader);
  hydrateContentImages(root, reader);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(shown.src, "blob:cover");
  assert.deepEqual(shown.events, []);
  assert.equal(refused.src, "");
  assert.deepEqual(refused.events, ["error"]);
});
