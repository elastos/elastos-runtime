import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile, mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { runtimeStorage } from "./walletconnect/runtime-storage.mjs";
import { configureRuntime, WebSocket } from "./walletconnect/runtime-websocket.mjs";

test("Runtime socket keeps relay credentials and launch authority out of URLs", () => {
  const opened = [];
  class Native {
    constructor(url) { this.url = url; this.sent = []; opened.push(this); }
    send(value) { this.sent.push(value); }
    close() { this.onclose(); }
  }
  configureRuntime({ url: "ws://home.test/api/apps/wallet-walletconnect/relay", token: "principal-a-token", WebSocket: Native });
  const relay = "wss://relay.walletconnect.org/?auth=fixture-secret&projectId=fixture-project";
  const socket = new WebSocket(relay);
  configureRuntime({ url: "ws://other.test/relay", token: "principal-b-token", WebSocket: Native });
  assert.equal(opened[0].url, "ws://home.test/api/apps/wallet-walletconnect/relay");
  opened[0].onopen();
  assert.deepEqual(JSON.parse(opened[0].sent[0]), { token: "principal-a-token", relay });
  assert.equal(socket.readyState, WebSocket.CONNECTING);
  assert.throws(() => socket.send("too-early"));
  let ready = 0; let payload;
  socket.onopen = () => { ready++; };
  socket.onmessage = event => { payload = event.data; };
  opened[0].onmessage({ data: '{"ready":true}' });
  assert.equal(ready, 1);
  socket.send("encrypted-request");
  assert.equal(opened[0].sent[1], "encrypted-request");
  opened[0].onmessage({ data: "encrypted-response" });
  assert.equal(payload, "encrypted-response");
  socket.close(); assert.equal(socket.readyState, WebSocket.CLOSED);
});

test("SDK storage serializes Runtime writes and recovers through a fresh adapter", async () => {
  let state = {};
  const writes = [];
  const api = async (path, input) => {
    assert.equal(path, "storage");
    if (input) {
      const { key, value } = JSON.parse(input.body);
      writes.push(key);
      if (value === null) delete state[key]; else state[key] = value;
    }
    return structuredClone(state);
  };
  const first = runtimeStorage(api);
  await Promise.all([first.setItem("session", { topic: "fixture", expiry: 100 }), first.setItem("keychain", "fixture-key")]);
  const second = runtimeStorage(api);
  assert.deepEqual(await second.getItem("session"), { topic: "fixture", expiry: 100 });
  assert.deepEqual(await second.getKeys(), ["session", "keychain"]);
  await second.removeItem("session");
  assert.equal(await second.getItem("session"), undefined);
  assert.deepEqual(writes, ["session", "keychain", "session"]);
  const broken = runtimeStorage(async () => { throw new Error("refused"); });
  await assert.rejects(broken.setItem("session", "x"), /refused/);
});

test("a refused or closed Runtime admission rejects SDK registration before ready", async () => {
  let native;
  class Native {
    constructor() { native = this; this.sent = []; }
    send(value) { this.sent.push(value); }
    close() { this.onclose(); }
  }
  configureRuntime({ url: "ws://home.test/relay", WebSocket: Native, authorize: async () => { throw new Error("refused"); } });
  const refused = new WebSocket("wss://relay.walletconnect.org/");
  let errors = 0; refused.onerror = () => { errors++; };
  await native.onopen();
  assert.equal(errors, 1);
  assert.equal(refused.readyState, WebSocket.CLOSED);
  assert.deepEqual(native.sent, []);
  configureRuntime({ url: "ws://home.test/relay", WebSocket: Native, token: "fixture" });
  const closed = new WebSocket("wss://relay.walletconnect.org/");
  closed.onerror = () => { errors++; };
  native.onclose();
  assert.equal(errors, 2, "the SDK register() promise receives an error before open");
});

test("the whole adapter dependency graph has registry integrity and exact roots", async () => {
  const manifest = JSON.parse(await readFile(new URL("./walletconnect/package.json", import.meta.url)));
  const lock = JSON.parse(await readFile(new URL("./walletconnect/package-lock.json", import.meta.url)));
  assert.deepEqual(lock.packages[""].dependencies, manifest.dependencies);
  for (const version of Object.values({ ...manifest.dependencies, ...manifest.devDependencies })) {
    assert.match(version, /^\d+\.\d+\.\d+$/);
  }
  for (const [path, entry] of Object.entries(lock.packages)) {
    if (!path) continue;
    assert.match(entry.resolved, /^https:\/\/registry\.npmjs\.org\//, path);
    assert.match(entry.integrity, /^sha512-/, path);
  }
});

test("the shipped bundle matches the locked graph and current adapter sources", async () => {
  const vendor = new URL("../capsules/wallet-walletconnect/vendor/", import.meta.url);
  const manifest = JSON.parse(await readFile(new URL("adapter.json", vendor)));
  const sha = bytes => createHash("sha256").update(bytes).digest("hex");
  assert.equal(manifest.sdk_sha256, sha(await readFile(new URL("reown-appkit.js", vendor))));
  assert.equal(manifest.dependency_lock_sha256, sha(await readFile(new URL("walletconnect/package-lock.json", import.meta.url))));
  assert.deepEqual(manifest.source_sha256, Object.fromEntries(await Promise.all(
    ["adapter.mjs", "runtime-storage.mjs", "runtime-websocket.mjs", "../vendor-walletconnect-adapter.sh"].map(async file =>
      [file, sha(await readFile(new URL(`walletconnect/${file}`, import.meta.url)))]),
  )));
});

test("release stage installs config automatically only from the operator file and the reviewed bundle", async () => {
  const dir = await mkdtemp(join(tmpdir(), "wc-release-"));
  try {
    const vendor = join(dir, "vendor"); await mkdir(vendor);
    const sdk = "export const fixture = true;";
    await writeFile(join(vendor, "reown-appkit.js"), sdk);
    await writeFile(join(vendor, "adapter.json"), JSON.stringify({
      sdk_package: "@walletconnect/ethereum-provider", sdk_version: "2.23.9",
      sdk_sha256: createHash("sha256").update(sdk).digest("hex"),
    }));
    const script = resolve("scripts/stage-walletconnect-release.mjs");
    const env = { ...process.env }; delete env.ELASTOS_WALLETCONNECT_PROJECT_FILE; delete env.ELASTOS_WALLETCONNECT_PROJECT_ID;
    execFileSync(process.execPath, [script, dir], { env });
    await assert.rejects(readFile(join(vendor, "connector.json")), /ENOENT/);
    const project = join(dir, "operator-project"); await writeFile(project, "fixture-project-id");
    env.ELASTOS_WALLETCONNECT_PROJECT_FILE = project;
    execFileSync(process.execPath, [script, dir], { env });
    const config = JSON.parse(await readFile(join(vendor, "connector.json")));
    assert.equal(config.schema, "elastos.walletconnect.connector/v1");
    assert.equal(config.project_id, "fixture-project-id");
    await writeFile(join(vendor, "reown-appkit.js"), "tampered");
    assert.throws(() => execFileSync(process.execPath, [script, dir], { env, stdio: "pipe" }), /failed/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
