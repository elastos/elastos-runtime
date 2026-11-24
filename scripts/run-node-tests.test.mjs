import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const scripts = dirname(fileURLToPath(import.meta.url));
const fixtures = join(scripts, "fixtures/node-test-runner");
const env = { ...process.env };
delete env.NODE_TEST_CONTEXT;

// Exercise the actual shell entry point with its real discovery arguments.
// Only its test files and Browser package receipts are replaced by tiny fixtures.
function suite(t, name, timeout = 10_000, overrides = {}) {
  const root = mkdtempSync(join(tmpdir(), "node-runner-guard-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(join(root, "scripts/lib"), { recursive: true });
  for (const file of ["test-behaviour.sh", "run-node-tests.mjs", "lib/node-test-events.mjs", "lib/owned-test-worker.mjs", "lib/node-test-worker-lifetime.mjs", "lib/browser-launch-recovery.mjs", "lib/webkit-macos-sandbox.mjs", "lib/owned_removal.py"]) {
    cpSync(join(scripts, file), join(root, "scripts", file));
  }
  const script = readFileSync(join(root, "scripts/test-behaviour.sh"), "utf8");
  const paths = script.split("\n").find(line => line.startsWith("exec ")).split(" ");
  const start = paths.indexOf("elastos/esp/projections.test.mjs");
  assert.ok(start > 0, "the suite supplies its explicit file list");
  for (const pattern of paths.slice(start)) {
    const file = join(root, pattern.replaceAll("*", "fixture"));
    mkdirSync(dirname(file), { recursive: true });
    cpSync(join(fixtures, overrides[pattern] ?? (pattern === "scripts/*.test.mjs" ? name : "pass.mjs")), file);
  }
  const inputs = join(root, "inputs");
  for (const [prefix, pkg, version] of [["browser", "playwright", "1.60.0"], ["core", "playwright-core", "1.59.1"]]) {
    const path = join(inputs, prefix, "node_modules", pkg);
    mkdirSync(path, { recursive: true });
    writeFileSync(join(path, "package.json"), JSON.stringify({ version }));
  }
  // Short timeouts belong only to this isolated copy of the runner.
  if (timeout !== 10_000) {
    const path = join(root, "scripts/test-behaviour.sh");
    writeFileSync(path, script.replace("scripts/run-node-tests.mjs ", `scripts/run-node-tests.mjs --timeout=${timeout} `));
  }
  return spawnSync("bash", [join(root, "scripts/test-behaviour.sh")], {
    cwd: root, env: { ...env, BEHAVIOUR_INPUTS: inputs }, encoding: "utf8", timeout: 60_000, maxBuffer: 5 * 1024 * 1024,
  });
}

for (const name of ["cut-off.mjs", "early-exit.mjs"]) {
  test(`behaviour gate rejects incomplete file: ${name}`, t => {
    const result = suite(t, name);
    assert.ifError(result.error);
    assert.notEqual(result.status, 0, result.stdout);
    assert.match(result.stderr, /scripts\/fixture.test.mjs: incomplete results/);
    if (name === "cut-off.mjs") assert.match(result.stderr, /first unfinished: first unfinished test/);
  });
}

test("behaviour gate accepts duplicates, nested tests, skips and todos", t => {
  const result = suite(t, "pass.mjs");
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /skipped [1-9]/);
  assert.match(result.stdout, /todo [1-9]/);
});

test("behaviour gate waits for tests declared by a live handle", t => {
  const result = suite(t, "late-declaration.mjs");
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /later declared test/);
});

test("runner bounds a hung test and names it", () => {
  const result = spawnSync(process.execPath, [join(scripts, "run-node-tests.mjs"), "--timeout=3000", join(fixtures, "hang.mjs")], {
    encoding: "utf8", timeout: 30_000,
  });
  assert.ifError(result.error);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /hang.mjs: timed out.*first unfinished: hung test/);
});

for (const [name, title] of [["blocked.mjs", "blocked event loop"], ["open-handle.mjs", "test with leaked interval"]]) {
  test(`runner stops ${name}`, () => {
    const result = spawnSync(process.execPath, [join(scripts, "run-node-tests.mjs"), "--timeout=3000", join(fixtures, name)], {
      encoding: "utf8", timeout: 30_000,
    });
    assert.ifError(result.error);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /timed out after 6000ms/);
    assert.ok(result.stderr.includes(title), result.stderr);
  });
}

test("runner names a killed test", () => {
  const result = spawnSync(process.execPath, [join(scripts, "run-node-tests.mjs"), join(fixtures, "killed.mjs")], { encoding: "utf8", timeout: 30_000 });
  assert.ifError(result.error);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /first unfinished: killed test/);
});

test("behaviour gate reports every result under pipe backpressure", t => {
  const result = suite(t, "pressure.mjs");
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.equal((result.stdout.match(/✔ declared /g) ?? []).length, 1000);
});

test("runner accepts a completed plain assertion script", () => {
  const result = spawnSync(process.execPath, [join(scripts, "run-node-tests.mjs"), join(fixtures, "assertions.mjs")], { encoding: "utf8", timeout: 30_000 });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /plain assertions completed/);
});

test("repository gate entry points keep the completion supervisor", () => {
  for (const file of ["scripts/test-behaviour.sh", "scripts/test-source-gate.sh", "justfile", "elastos/esp/package.json"]) {
    const source = readFileSync(join(scripts, "..", file), "utf8");
    assert.doesNotMatch(source, /node (?:--experimental-strip-types )?--test(?:\s|$)/, file);
    assert.ok(source.includes("scripts/run-node-tests.mjs"), file);
  }
});

test("runner permits a whole-file assertion journey beyond one test budget", () => {
  const result = spawnSync(process.execPath, [join(scripts, "run-node-tests.mjs"), "--timeout=3000", join(fixtures, "slow-assertions.mjs")], {
    encoding: "utf8", timeout: 30_000,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /whole-file assertions completed/);
});

test("completed worker stays complete when its summary is buffered behind another file", t => {
  const result = suite(t, "pass.mjs", 3000, {
    "capsules/*/browser/*.test.mjs": "progress.mjs",
    "scripts/model-preparation-failure-smoke.mjs": "long-progress.mjs",
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /long progress 15/);
});

test("two stalled workers shut down without a second process-group kill", t => {
  const root = mkdtempSync(join(tmpdir(), "node-runner-two-stalls-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const files = ["one.mjs", "two.mjs"].map(name => join(root, name));
  for (const file of files) cpSync(join(fixtures, "open-handle.mjs"), file);
  const result = spawnSync(process.execPath, [join(scripts, "run-node-tests.mjs"), "--timeout=3000", ...files], { encoding: "utf8", timeout: 30_000 });
  assert.ifError(result.error);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /timed out after 6000ms/);
  assert.doesNotMatch(result.stderr, /kill EPERM|run-node-tests.mjs:\d/);
});

test("supervisor delegates group signals to the ownership-checked worker", () => {
  const source = readFileSync(join(scripts, "run-node-tests.mjs"), "utf8");
  assert.doesNotMatch(source, /process\.kill\(-child\.pid/);
  assert.match(source, /spawnOwnedTestWorker/);
});

test("synchronous test starts refresh the deadline while reporter events are buffered", () => {
  const result = spawnSync(process.execPath, [join(scripts, "run-node-tests.mjs"), "--timeout=3000", join(fixtures, "synchronous-progress.mjs")], {
    encoding: "utf8", timeout: 30_000,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /pass 16/);
});

test('runner limits simultaneous files so Browser processes have a fixed memory bound', t => {
  const directory=mkdtempSync(join(tmpdir(),'node-runner-concurrency-'));
  t.after(()=>rmSync(directory,{recursive:true,force:true}));
  const log=join(directory,'events.jsonl');
  const files=[0,1,2].map(i=>{
    const file=join(directory,`case-${i}.mjs`);
    writeFileSync(file,`import test from 'node:test';import {appendFileSync} from 'node:fs';test('bounded file ${i}',async()=>{appendFileSync(${JSON.stringify(log)},JSON.stringify({kind:'start'})+'\\n');await new Promise(r=>setTimeout(r,200));appendFileSync(${JSON.stringify(log)},JSON.stringify({kind:'end'})+'\\n');});`);
    return file;
  });
  const result=spawnSync(process.execPath,[join(scripts,'run-node-tests.mjs'),...files],{encoding:'utf8',timeout:30000});
  assert.ifError(result.error);assert.equal(result.status,0,result.stderr);
  let active=0,max=0;for(const line of readFileSync(log,'utf8').trim().split('\n')){active+=JSON.parse(line).kind==='start'?1:-1;max=Math.max(max,active);}
  assert.equal(max,1);assert.equal(active,0);
});
