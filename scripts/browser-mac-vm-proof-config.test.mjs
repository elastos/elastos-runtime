import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const proofPath = fileURLToPath(new URL("./browser-mac-vm-proof.sh", import.meta.url));
const generatorPath = fileURLToPath(new URL("./browser-source-home-config.mjs", import.meta.url));
const configPath = dataDir => path.join(dataDir, "config/browser-engine-adapter.json");
const adapter = socket => ({ id: "browser-vm-product", supervisor: { control_socket_path: socket } });

function fixture(t) {
  const root = mkdtempSync(path.join(os.tmpdir(), "browser-proof-config-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

function probe(dataDir, override = "") {
  // Run the actual consumer with inert HTTP and stop at its first socket probe,
  // before either virtual-auth journey can run.
  return spawnSync("bash", ["-c", `
exec 3>&2
curl() {
  while [[ $# -gt 0 ]]; do
    if [[ "$1" == "--unix-socket" ]]; then
      printf 'CONTROL_SOCKET=%s\\n' "$2" >&3
      exit 77
    fi
    shift
  done
  printf 'HOME_PROBE\\n' >&2
  printf '200'
}
export -f curl
exec bash "$1"
`, "proof-config-test", proofPath], {
    cwd: path.dirname(path.dirname(proofPath)),
    env: { ...process.env, ELASTOS_NODE_BIN: process.execPath,
      ELASTOS_MAC_BROWSER_DATA_DIR: dataDir, ELASTOS_BROWSER_VM_CONTROL_SOCKET: override,
      ELASTOS_BROWSER_MAC_VM_PROOF_AUTH_PROFILE: "" },
    encoding: "utf8", timeout: 10_000,
  });
}

function expectSocket(result, socket) {
  assert.equal(result.error, undefined);
  assert.equal(result.status, 77, result.stderr);
  assert.ok(result.stderr.includes(`CONTROL_SOCKET=${socket}\n`), result.stderr);
}

test("Mac proof follows each target's generated socket and selects the product adapter by ID", t => {
  const root = fixture(t);
  const sockets = [];
  for (const home of ["Home One", "Home Two"]) {
    const dataDir = path.join(root, home, "Library/Application Support/elastos");
    execFileSync(process.execPath, [generatorPath, "--data-dir", dataDir, "--platform", "darwin-arm64"]);
    const config = JSON.parse(readFileSync(configPath(dataDir), "utf8"));
    const socket = config.adapters.find(entry => entry.id === "browser-vm-product").supervisor.control_socket_path;
    config.adapters.unshift({ id: "other-engine", supervisor: { control_socket_path: "/tmp/foreign-engine.sock" } });
    writeFileSync(configPath(dataDir), JSON.stringify(config));
    expectSocket(probe(dataDir), socket);
    sockets.push(socket);
  }
  assert.notEqual(sockets[0], sockets[1]);
});

test("explicit socket override wins and works without target config", t => {
  const root = fixture(t);
  const socket = path.join(root, "explicit control.sock");
  expectSocket(probe(root, socket), socket);
  mkdirSync(path.dirname(configPath(root)), { recursive: true });
  writeFileSync(configPath(root), JSON.stringify({ adapters: [adapter("/tmp/configured.sock")] }));
  expectSocket(probe(root, socket), socket);
});

test("missing, malformed, ambiguous or invalid target config fails before Home is contacted", t => {
  const root = fixture(t);
  const cases = [
    undefined, "{broken-json", {},
    { adapters: [adapter("/tmp/one.sock"), adapter("/tmp/two.sock")] },
    { adapters: [adapter(undefined)] },
    { adapters: [adapter("relative.sock")] },
    { adapters: [adapter("/tmp/control.sock\n")] },
  ];
  for (const [index, config] of cases.entries()) {
    const dataDir = path.join(root, String(index));
    if (config !== undefined) {
      mkdirSync(path.dirname(configPath(dataDir)), { recursive: true });
      writeFileSync(configPath(dataDir), typeof config === "string" ? config : JSON.stringify(config));
    }
    const result = probe(dataDir);
    assert.equal(result.status, 2, result.stderr);
    assert.match(result.stderr, /Cannot resolve Browser VM control socket/);
    assert.doesNotMatch(result.stderr, /HOME_PROBE|CONTROL_SOCKET=/);
  }
});

function probeSmokeProfiles(root, { explicit = "", inherited = "", cleanup = "" } = {}) {
  const dataDir = path.join(root, "Home data");
  const trace = path.join(root, "smoke-invocations.jsonl");
  const nodeProbe = path.join(root, "node-probe.cjs");
  // Replace only the two smoke processes. The actual proof script still
  // chooses their environment. Stop after the second call, before VM proof
  // evaluation; curl is inert throughout.
  writeFileSync(nodeProbe, `#!/usr/bin/env node
const fs = require("node:fs"), path = require("node:path");
if (process.argv[2] !== "scripts/home-passkey-virtual-auth-smoke.mjs") throw Error("unexpected node call");
const trace = process.env.PROFILE_PROBE_TRACE;
const calls = fs.existsSync(trace) ? fs.readFileSync(trace, "utf8").trim().split("\\n").length : 0;
const profile = process.env.HOME_VIRTUAL_AUTH_PROFILE || fs.mkdtempSync(path.join(path.dirname(trace), "temporary-profile-"));
fs.mkdirSync(profile, { recursive: true });
const credential = path.join(profile, "fixture-owner");
const restored = fs.existsSync(credential);
if (calls === 0) fs.writeFileSync(credential, "inert fixture");
fs.appendFileSync(trace, JSON.stringify({ profile, restored,
  preserve: process.env.HOME_VIRTUAL_AUTH_PRESERVE_PROFILE,
  cleanup: process.env.HOME_VIRTUAL_AUTH_CLEANUP }) + "\\n");
console.log(calls === 0 || restored ? JSON.stringify({ ok: true }) : "SKIP missing fixture owner");
if (calls === 1) process.exit(77);
`);
  chmodSync(nodeProbe, 0o755);
  const result = spawnSync("bash", ["-c", `
curl() {
  if [[ "$*" == *--unix-socket* ]]; then printf '{}'; else printf '200'; fi
}
export -f curl
exec bash "$1"
`, "proof-profile-test", proofPath], {
    cwd: path.dirname(path.dirname(proofPath)),
    env: { ...process.env, ELASTOS_NODE_BIN: nodeProbe,
      ELASTOS_MAC_BROWSER_DATA_DIR: dataDir, ELASTOS_BROWSER_VM_CONTROL_SOCKET: "/fixture/control.sock",
      ELASTOS_BROWSER_MAC_VM_PROOF_AUTH_PROFILE: explicit, HOME_VIRTUAL_AUTH_PROFILE: inherited,
      HOME_VIRTUAL_AUTH_CLEANUP: cleanup, PROFILE_PROBE_TRACE: trace },
    encoding: "utf8", timeout: 10_000,
  });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 77, result.stderr);
  const calls = readFileSync(trace, "utf8").trim().split("\n").map(line => JSON.parse(line));
  assert.equal(calls.length, 2);
  return { calls, dataDir };
}

test("fresh proof restores the same owner profile for its second smoke without an option", t => {
  const { calls, dataDir } = probeSmokeProfiles(fixture(t));
  assert.deepEqual(calls.map(call => call.profile), Array(2).fill(path.join(dataDir, "browser-mac-vm-proof-auth")));
  assert.deepEqual(calls.map(call => call.restored), [false, true]);
  assert.ok(calls.every(call => call.preserve === "1" && call.cleanup === "0"));
});

test("explicit proof profile and cleanup override keep their existing behavior", t => {
  for (const cleanup of ["", "1"]) {
    const root = fixture(t);
    const explicit = path.join(root, "explicit profile");
    const { calls } = probeSmokeProfiles(root, { explicit, inherited: path.join(root, "other profile"), cleanup });
    assert.deepEqual(calls.map(call => call.profile), [explicit, explicit]);
    assert.ok(calls.every(call => call.preserve === "1" && call.cleanup === (cleanup || "0")));
  }
});

test("an inherited virtual-auth profile is shared when the proof option is absent", t => {
  const root = fixture(t);
  const inherited = path.join(root, "inherited profile");
  const { calls } = probeSmokeProfiles(root, { inherited });
  assert.deepEqual(calls.map(call => call.profile), [inherited, inherited]);
  assert.equal(calls[1].restored, true);
});
