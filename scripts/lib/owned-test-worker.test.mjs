import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { once } from "node:events";
import test from "node:test";
import { canSignalWorkerGroup, spawnOwnedTestWorker } from "./owned-test-worker.mjs";

async function stopExactChild(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exit = once(child, "exit");
  child.kill("SIGKILL");
  await exit;
}

function group(pid) {
  return Number(execFileSync("ps", ["-p", String(pid), "-o", "pgid="], { encoding: "utf8", timeout: 5000 }).trim());
}

test("group signal policy rejects zero, own, foreign, exited and reused process identities", () => {
  const started = { pid: 400, parent: 200, group: 400, birth: "original start", state: "R" };
  const self = { pid: 200, group: 100 };
  assert.equal(canSignalWorkerGroup(started, started, self, false, 200), true);
  const invalid = [
    [undefined, started, self, false],
    [started, undefined, self, false],
    [started, started, undefined, false],
    [{ ...started, pid: 0, group: 0 }, { ...started, pid: 0, group: 0 }, self, false],
    [{ ...started, pid: 1, group: 1 }, { ...started, pid: 1, group: 1 }, self, false],
    [{ ...started, pid: -400 }, started, self, false],
    [started, { ...started, group: 0 }, self, false],
    [started, { ...started, group: 500 }, self, false],
    [{ ...started, group: 500 }, started, self, false],
    [started, started, { ...self, group: 400 }, false],
    [{ ...started, pid: 200, group: 200 }, { ...started, pid: 200, group: 200 }, self, false],
    [started, { ...started, parent: 999 }, self, false],
    [{ ...started, parent: 999 }, started, self, false],
    [started, { ...started, birth: "reused PID, new start" }, self, false],
    [started, { ...started, state: "Z" }, self, false],
    [started, started, self, true],
  ];
  for (const args of invalid) assert.equal(canSignalWorkerGroup(...args, 200), false, JSON.stringify(args));
});

test("verified new worker group stops while a neighbouring process survives", async t => {
  const neighbour = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
  t.after(() => stopExactChild(neighbour));
  const worker = spawnOwnedTestWorker(["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
  t.after(() => stopExactChild(worker.child));
  assert.equal(group(worker.child.pid), worker.child.pid);
  assert.notEqual(group(worker.child.pid), group(process.pid));
  assert.notEqual(group(neighbour.pid), group(worker.child.pid));
  const exit = once(worker.child, "exit");
  assert.equal(worker.stop(), true);
  const [code, signal] = await exit;
  assert.equal(code, null);
  assert.equal(signal, "SIGKILL");
  assert.equal(worker.stop(), false);
  assert.equal(process.kill(neighbour.pid, 0), true);
  assert.equal(neighbour.exitCode, null);
  assert.equal(neighbour.signalCode, null);
  console.log("owned worker stopped; neighbouring child still alive");
});

test("an exited worker cannot authorize a later group signal", async t => {
  const neighbour = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
  t.after(() => stopExactChild(neighbour));
  const worker = spawnOwnedTestWorker(["-e", ""], { stdio: "ignore" });
  await once(worker.child, "exit");
  assert.equal(worker.child.exitCode, 0);
  assert.equal(worker.stop(), false);
  assert.equal(process.kill(neighbour.pid, 0), true);
});
