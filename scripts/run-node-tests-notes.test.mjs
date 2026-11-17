import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";

const scripts = dirname(fileURLToPath(import.meta.url));
const runner = join(scripts, "run-node-tests.mjs");
const fixtures = join(scripts, "fixtures/node-test-runner");
const env = { ...process.env };
delete env.NODE_TEST_CONTEXT;
function run(name, args = [], extra = {}) {
  const result = spawnSync(process.execPath, [runner, ...args, join(fixtures, name)], {
    env: { ...env, ...extra }, encoding: "utf8", timeout: 10_000,
  });
  assert.ifError(result.error);
  return result;
}
function identity(pid) {
  try {
    const row = execFileSync("ps", ["-p", String(pid), "-o", "pid=,ppid=,pgid=,lstart=,stat=,command="], { encoding: "utf8", timeout: 5000 }).trim();
    const a = row.split(/\s+/);
    if (a.length < 10 || a[8].includes("Z")) return null;
    return { pid: Number(a[0]), parent: Number(a[1]), group: Number(a[2]), birth: a.slice(3, 8).join(" "), command: a.slice(9).join(" ") };
  } catch { return null; }
}
const same = (a, b) => Boolean(a && b && a.pid === b.pid && a.group === b.group && a.birth === b.birth && a.command === b.command);
async function until(predicate, limit = 3000) {
  const end = Date.now() + limit;
  while (Date.now() < end) {
    if (predicate()) return true;
    await delay(25);
  }
  return predicate();
}
async function stopChild(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const ended = once(child, "exit");
  child.kill("SIGKILL");
  await ended;
}

for (const signal of ["SIGHUP", "SIGKILL", "gate-group-SIGKILL"]) {
  test(`N1 workers end after ${signal} while a neighbour survives`, async t => {
    const root = mkdtempSync(join(tmpdir(), "node-guard-orphan-"));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const ready = join(root, "ready.json");
    const neighbour = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
    t.after(() => stopChild(neighbour));
    const gate = spawn(process.execPath, [join(fixtures, "supervisor-death-gate.mjs"), runner, join(fixtures, "orphan-blocked.mjs")], {
      detached: true, env: { ...env, NODE_TEST_GUARD_READY: ready }, stdio: ["ignore", "ignore", "pipe", "ipc"],
    });
    let errors = "";
    gate.stderr.on("data", data => { errors = (errors + data).slice(-8192); });
    t.after(() => stopChild(gate));
    const [{ supervisor }] = await once(gate, "message");
    const owned = [];
    t.after(() => {
      // Cleanup uses only exact recorded descendant PIDs, including on the
      // expected before-repair failure. It never signals a process group.
      for (const recorded of owned.reverse()) {
        if (same(recorded, identity(recorded.pid))) process.kill(recorded.pid, "SIGKILL");
      }
    });
    owned.push(identity(supervisor));
    assert.equal(await until(() => existsSync(ready)), true, "blocked test started");
    const pids = JSON.parse(readFileSync(ready, "utf8"));
    owned.push(identity(pids.worker));
    if (pids.runner !== pids.worker) owned.push(identity(pids.runner));
    owned.push(identity(pids.test));
    assert.ok(owned.every(Boolean));
    assert.equal(owned[0].parent, gate.pid);
    assert.equal(owned[0].group, gate.pid);
    assert.equal(owned[1].parent, supervisor);
    assert.equal(owned[1].group, pids.worker);
    for (let index = 2; index < owned.length; index++) {
      assert.equal(owned[index].parent, owned[index - 1].pid);
      assert.equal(owned[index].group, pids.worker);
    }
    assert.notEqual(identity(neighbour.pid).group, gate.pid);
    assert.notEqual(identity(neighbour.pid).group, pids.worker);
    gate.send(signal);
    assert.equal(await until(() => owned.every(p => !same(p, identity(p.pid)))) , true,
      `workers survived ${signal}: ${JSON.stringify(owned.map(p => identity(p.pid)))}\n${errors}`);
    assert.equal(process.kill(neighbour.pid, 0), true);
    assert.equal(neighbour.exitCode, null);
    console.log(`${signal}: supervisor and workers ended; neighbouring process survived`);
  });
}

test("N2 absolute symlink input completes without a false declaration", t => {
  const root = mkdtempSync(join(tmpdir(), "node-guard-symlink-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const alias = join(root, "alias");
  symlinkSync(fixtures, alias, "dir");
  const result = spawnSync(process.execPath, [runner, "--timeout=1500", join(alias, "pass.mjs")], {
    env, encoding: "utf8", timeout: 8000,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
});

for (const output of ["stdout", "stderr"]) {
  test(`N3 plain script ${output} refreshes file inactivity`, () => {
    const result = run("output-progress.mjs", ["--timeout=1500"], { NODE_TEST_GUARD_OUTPUT: output });
    assert.equal(result.status, 0, result.stderr);
    assert.ok((result.stdout + result.stderr).includes("script progress 7"));
  });
}

for (const [name, verdict, exit] of [["assertions.mjs", "PASS", 0], ["early-exit.mjs", "FAIL", 1]]) {
  test(`N4 closing verdict is ${verdict} with exit ${exit}`, () => {
    const result = run(name);
    assert.equal(result.status, exit);
    assert.equal(result.stdout.trim().split("\n").at(-1), `Node test guard: ${verdict} (exit ${exit})`);
  });
}

test("N5 developer entrypoint and changelog explain the completion gate", () => {
  const header = readFileSync(join(scripts, "test-behaviour.sh"), "utf8").split("set -euo")[0];
  for (const text of ["Node test guard:", "first unfinished", "exit 0", "exit 1"]) assert.ok(header.includes(text), text);
  const unreleased = readFileSync(join(scripts, "../elastos/CHANGELOG.md"), "utf8").split("## [Unreleased]")[1].split("\n## [")[0];
  assert.match(unreleased, /### Developer detail/);
  assert.match(unreleased, /behaviour.*(?:incomplete|missing).*test/i);
});

test("N6 early exit explains how a plain script should finish", () => {
  const result = run("early-exit.mjs");
  assert.equal(result.status, 1);
  assert.match(result.stderr, /finish naturally.*process\.exit\(0\).*process\.exitCode/);
});
