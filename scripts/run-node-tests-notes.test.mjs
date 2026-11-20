import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

const scripts = dirname(fileURLToPath(import.meta.url));
const runner = join(scripts, "run-node-tests.mjs");
const fixtures = join(scripts, "fixtures/node-test-runner");
const processWait = 30_000; // Liveness bound, not a scheduling/performance assertion.
const env = { ...process.env };
delete env.NODE_TEST_CONTEXT;
function run(name, args = [], extra = {}, limit = 30_000) {
  const result = spawnSync(process.execPath, [runner, ...args, join(fixtures, name)], {
    env: { ...env, ...extra }, encoding: "utf8", timeout: limit,
  });
  assert.ifError(result.error);
  return result;
}
function identity(pid) {
  try {
    const row = execFileSync("ps", ["-p", String(pid), "-o", "pid=,ppid=,pgid=,lstart=,stat=,command="], { encoding: "utf8", timeout: 5000 }).trim();
    const a = row.split(/\s+/);
    assert.ok(a.length >= 10, `unreadable process identity: ${row}`);
    if (a[8].includes("Z")) return null; // A zombie has exited; reaping belongs to its parent.
    return { pid: Number(a[0]), parent: Number(a[1]), group: Number(a[2]), birth: a.slice(3, 8).join(" "), command: a.slice(9).join(" ") };
  } catch (error) {
    // ps exits 1 with empty output for an absent PID. Inspection errors are
    // failures, never evidence that a worker exited.
    if (error.status === 1 && !String(error.stdout).trim() && !String(error.stderr).trim()) return null;
    throw error;
  }
}
const same = (a, b) => Boolean(a && b && a.pid === b.pid && a.group === b.group && a.birth === b.birth && a.command === b.command);
async function until(predicate, limit = processWait) {
  const end = performance.now() + limit;
  while (performance.now() < end) {
    if (predicate()) return true;
    await delay(25);
  }
  return predicate();
}
async function stopChild(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const ended = once(child, "exit", { signal: AbortSignal.timeout(processWait) });
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
      detached: true, env: { ...env, NODE_TEST_GUARD_READY: ready,
        NODE_OPTIONS: `${env.NODE_OPTIONS ?? ""} --import=${pathToFileURL(join(fixtures, "pause-ready-write.mjs")).href}` }, stdio: ["ignore", "ignore", "pipe", "ipc"],
    });
    let errors = "";
    gate.stderr.on("data", data => { errors = (errors + data).slice(-8192); });
    t.after(() => stopChild(gate));
    const [{ supervisor }] = await once(gate, "message", { signal: AbortSignal.timeout(processWait) });
    const owned = [];
    t.after(() => {
      // Cleanup uses only exact recorded descendant PIDs, including on the
      // expected before-repair failure. It never signals a process group.
      for (const recorded of owned.reverse()) {
        if (recorded && same(recorded, identity(recorded.pid))) process.kill(recorded.pid, "SIGKILL");
      }
    });
    owned.push(identity(supervisor));
    // Hold the actual readiness writer after open and before write. The final
    // name must stay absent until the complete JSON is atomically published.
    assert.equal(await until(() => existsSync(`${ready}.opened`)), true, "readiness writer opened");
    assert.equal(existsSync(ready), false, "readiness published before its JSON write completed");
    writeFileSync(`${ready}.release`, "");
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
  const result = spawnSync(process.execPath, [runner, join(alias, "pass.mjs")], {
    env, encoding: "utf8", timeout: 30_000,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
});

for (const output of ["stdout", "stderr"]) {
  test(`N3 plain script ${output} refreshes file inactivity`, () => {
    const result = run("output-progress.mjs", ["--timeout=3000"], { NODE_TEST_GUARD_OUTPUT: output });
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
  const changelog = readFileSync(join(scripts, "../elastos/CHANGELOG.md"), "utf8");
  const requireEntry = text => {
    const sections = text.split(/^## \[/m).slice(1);
    const owners = sections.filter(section => {
      const detail = section.split(/^### Developer detail\s*$/m)[1]?.split(/^### /m)[0];
      return detail && /behaviour.*(?:incomplete|missing).*test/i.test(detail);
    });
    assert.equal(owners.length, 1, "one release section must carry the completion-gate Developer detail");
  };
  const cut = changelog.replace("## [Unreleased]", "## [2.0.2-rc.1]\n\n### Fixed\n\n- Candidate release.\n\n## [2.0.2]");
  for (const text of [changelog, cut]) {
    requireEntry(text);
    const missing = text.replace(/^- The behaviour gate[^\n]*(?:\n {2,}[^\n]*)*/m, "");
    assert.throws(() => requireEntry(missing), /completion-gate Developer detail/);
  }
});

test("N6 early exit explains how a plain script should finish", () => {
  const result = run("early-exit.mjs");
  assert.equal(result.status, 1);
  assert.match(result.stderr, /finish naturally.*process\.exit\(0\).*process\.exitCode/);
});

test("F1 a printing loop reaches the fixed file upper limit", () => {
  const result = run("printing-loop.mjs", ["--timeout=1500"], {}, 55_000);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /printing-loop.mjs: upper limit.*30000ms/);
  assert.match(result.stdout, /Node test guard: FAIL \(exit 1\)/);
  assert.match(readFileSync(join(scripts, "test-behaviour.sh"), "utf8"), /20-minute upper limit/);
});

for (const mode of ["unavailable", "wrong-group"]) {
  test(`F2 failed group check (${mode}) stops only the owned Node CLI`, async t => {
    const root = mkdtempSync(join(tmpdir(), "node-guard-check-failure-"));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const ready = join(root, "ready.json"), marker = join(root, "fail-check");
    const realPs = execFileSync("sh", ["-c", "command -v ps"], { encoding: "utf8" }).trim();
    const shim = join(root, "ps");
    writeFileSync(shim, `#!${process.execPath}\n` +
      `const {existsSync,unlinkSync}=require('node:fs'); const {spawnSync}=require('node:child_process');\n` +
      `const failing=existsSync(process.env.NODE_TEST_GUARD_FAIL_CHECK);\n` +
      `if(failing && process.env.NODE_TEST_GUARD_CHECK_MODE==='unavailable') process.exit(1);\n` +
      `const r=spawnSync(${JSON.stringify(realPs)},process.argv.slice(2),{encoding:'utf8'});\n` +
      `let text=r.stdout; if(failing) { unlinkSync(process.env.NODE_TEST_GUARD_FAIL_CHECK); text=text.replace(/^(\\s*\\d+\\s+\\d+\\s+)\\d+/gm,(_,prefix)=>prefix+'999999'); }\n` +
      `process.stdout.write(text); process.exitCode=r.status;\n`);
    chmodSync(shim, 0o755);
    const neighbour = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
    t.after(() => stopChild(neighbour));
    const gate = spawn(process.execPath, [join(fixtures, "supervisor-death-gate.mjs"), runner, join(fixtures, "orphan-blocked.mjs")], {
      detached: true, env: { ...env, PATH: `${root}:${env.PATH}`, NODE_TEST_GUARD_READY: ready,
        NODE_TEST_GUARD_FAIL_CHECK: marker, NODE_TEST_GUARD_CHECK_MODE: mode }, stdio: ["ignore", "ignore", "ignore", "ipc"],
    });
    t.after(() => stopChild(gate));
    const [{ supervisor }] = await once(gate, "message", { signal: AbortSignal.timeout(processWait) });
    const owned = [identity(supervisor)];
    t.after(() => {
      for (const p of owned.reverse()) if (p && same(p, identity(p.pid))) process.kill(p.pid, "SIGKILL");
    });
    assert.equal(await until(() => existsSync(ready)), true);
    const pids = JSON.parse(readFileSync(ready, "utf8"));
    const leader = identity(pids.worker), cli = identity(pids.runner), file = identity(pids.test);
    owned.push(leader, cli, file);
    assert.ok(owned.every(Boolean));
    assert.equal(leader.parent, supervisor);
    assert.equal(cli.parent, leader.pid);
    assert.equal(file.parent, cli.pid);
    assert.equal(file.group, leader.group);
    assert.notEqual(identity(neighbour.pid).group, leader.group);
    writeFileSync(marker, "fail only after startup\n");
    gate.send("SIGKILL");
    assert.equal(await until(() => !same(cli, identity(cli.pid))), true, "owned Node CLI survived failed group check");
    assert.equal(same(file, identity(file.pid)), true, "fallback signalled another member of the group");
    assert.equal(process.kill(neighbour.pid, 0), true);
    console.log(`${mode}: owned Node CLI ended; same-group test and outside neighbour survived`);
  });
}

test("F3 supervisor reports the signal that ended the Node CLI", () => {
  const result = run("kill-node-cli.mjs");
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Node test guard: Node process ended by SIGKILL/);
});
