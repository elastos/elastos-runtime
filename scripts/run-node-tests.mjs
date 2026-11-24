// The supervisor owns the verdict. A zero child exit also needs a complete
// event stream from every file, even when the child calls process.exit(0).
import { spawnOwnedTestWorker } from "./lib/owned-test-worker.mjs";
import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync, writeSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

// The external verdict is last, including when setup throws before spawning.
process.on("exit", code => writeSync(1, `Node test guard: ${code === 0 ? "PASS" : "FAIL"} (exit ${code})\n`));

const args = process.argv.slice(2);
const timeout = args[0]?.startsWith("--timeout=") ? Number(args.shift().split("=")[1]) : 60_000;
if (!Number.isSafeInteger(timeout) || timeout < 1 || !args.length || args.some(arg => arg.startsWith("-"))) {
  throw new Error("usage: node scripts/run-node-tests.mjs [--timeout=milliseconds] FILE...");
}
// Plain assertion scripts cover a whole journey. Their file inactivity budget
// permits two per-test budgets; Node still enforces the per-test timeout.
const inactivityTimeout = timeout * 2;
// Fixed from file start, independent of output. Short fixture budgets scale
// down the same 20-minute production ceiling.
const upperTimeout = Math.min(timeout * 20, 20 * 60_000);
const files = new Map(args.map(file => [realpathSync(file), { pending: new Map(), summary: false, timer: null, last: null, required: true }]));
const canonical = file => {
  if (!file) return undefined;
  try { return realpathSync(file); } catch { return resolve(file); }
};
const key = data => JSON.stringify([data.testId, data.name, data.line, data.column, data.nesting]);
const label = data => data ? `${data.name.slice(0, 160)}${data.line ? ` (${data.line}:${data.column})` : ""}` : "<file setup or open handles>";
const reporter = fileURLToPath(new URL("./lib/node-test-events.mjs", import.meta.url));
const scratch = mkdtempSync(join(tmpdir(), "node-test-guard-"));
const starts = join(scratch, "starts.jsonl");
writeFileSync(starts, "", { mode: 0o600 });
const env = { ...process.env, NODE_TEST_GUARD_STARTS: starts };
delete env.NODE_TEST_CONTEXT;
const worker = spawnOwnedTestWorker([
  "--test", "--test-concurrency=1", `--import=${reporter}`, `--test-timeout=${timeout}`, "--test-reporter=spec", "--test-reporter-destination=stdout",
  `--test-reporter=${reporter}`, "--test-reporter-destination=stderr", ...args,
], { env, stdio: ["ignore", "inherit", "inherit", "pipe"] });
const { child } = worker;
let failed = false;
let stopping = false;
let summary = false;
function lastStarted(file, state) {
  const recorded = readFileSync(starts, "utf8").trim().split("\n").filter(Boolean).map(JSON.parse)
    .filter(data => canonical(data.file) === file).at(-1);
  return recorded ?? state.last;
}
const startup = setTimeout(() => { fail("runner startup timed out"); stop(); }, timeout);
function fail(message) {
  failed = true;
  console.error(`Node test guard: ${message}`);
}
function stop() {
  if (stopping) return;
  stopping = true;
  clearTimeout(startup);
  for (const state of files.values()) {
    clearTimeout(state.timer);
    clearTimeout(state.upperTimer);
  }
  try {
    if (!worker.stop()) child.kill("SIGKILL"); // Exact child handle; never guess a group.
  } catch (error) {
    fail(`worker group stop refused: ${error.message}`);
    child.kill("SIGKILL");
  }
}
function arm(file, state) {
  if (stopping || state.closed) return;
  if (!state.upperTimer) state.upperTimer = setTimeout(() => {
    if (stopping || state.closed) return;
    fail(`${relative(process.cwd(), file)}: upper limit of ${upperTimeout}ms reached; first unfinished: ${label(state.pending.values().next().value ?? lastStarted(file, state))}`);
    stop();
  }, upperTimeout);
  clearTimeout(state.timer);
  const reportedAt = Date.now();
  function check() {
    if (stopping || state.closed) return;
    // Synchronous tests can keep Node's reporter buffered across many results.
    // Their synchronous start records still prove progress within this file.
    const started = lastStarted(file, state);
    const remaining = inactivityTimeout - (Date.now() - Math.max(reportedAt, started?.startedAt ?? 0));
    if (remaining > 0) {
      state.timer = setTimeout(check, remaining);
      return;
    }
    fail(`${relative(process.cwd(), file)}: timed out after ${inactivityTimeout}ms; first unfinished: ${label(state.pending.values().next().value ?? lastStarted(file, state))}`);
    stop();
  }
  state.timer = setTimeout(check, inactivityTimeout);
}
const lines = createInterface({ input: child.stdio[3] });
lines.on("line", line => {
  try {
    const { type, data } = JSON.parse(line);
    if (type === "worker:signal") {
      fail(`Node process ended by ${data.signal}`);
      return;
    }
    if (type === "test:summary" && !data.file) {
      summary = true;
      if (!data.success) failed = true;
      return;
    }
    const output = type === "test:stdout" || type === "test:stderr";
    const file = canonical(output ? data.entryFile ?? data.file : data.file);
    if (!file) return;
    if (!files.has(file)) files.set(file, { pending: new Map(), summary: false, timer: null, last: null, required: false });
    const state = files.get(file);
    if (type === "test:dequeue") clearTimeout(startup);
    // Node's outer FileTest shares the child's test IDs; it is a process result,
    // not a verdict for any test declared inside that file.
    const wrapper = state.required && typeof data.name === "string" && canonical(data.name) === file;
    if (type === "test:summary") {
      state.summary = true;
      if (!data.success) failed = true;
    } else if (!wrapper && type === "test:enqueue") {
      state.pending.set(key(data), data);
    } else if (!wrapper && (type === "test:pass" || type === "test:fail")) {
      state.pending.delete(key(data));
      if (type === "test:fail" && !data.todo) failed = true;
    }
    if (!wrapper && type === "test:dequeue") state.last = data;
    if (state.required && (output || type === "test:dequeue" || type === "test:complete" || type === "test:summary")) arm(file, state);
    if (wrapper && type === "test:complete") {
      // Completion is execution-ordered; the child summary can arrive later
      // from Node's per-file declaration-order buffer. Keep the timer retired.
      state.closed = true;
      clearTimeout(state.timer);
      clearTimeout(state.upperTimer);
    }
  } catch (error) {
    fail(`invalid or unreadable event: ${error.message}`);
    stop();
  }
});
child.on("error", error => fail(error.message));
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(signal, () => { fail(`interrupted by ${signal}`); stop(); });
child.on("close", (code, signal) => {
  clearTimeout(startup);
  for (const [file, state] of files) {
    clearTimeout(state.timer);
    clearTimeout(state.upperTimer);
    if ((state.required && !state.summary) || state.pending.size) {
      fail(`${relative(process.cwd(), file)}: incomplete results; first unfinished: ${label(state.pending.values().next().value ?? lastStarted(file, state))}; ${state.pending.size} declared test(s) without a result; file summary ${state.summary ? "received" : "missing"}`);
      if (state.required && !state.summary && code === 0) {
        fail(`${relative(process.cwd(), file)}: finish naturally; replace process.exit(0) with process.exitCode = 0 so Node can send the file summary`);
      }
    }
  }
  if (!summary) fail("run summary missing");
  if (signal) fail(`runner killed by ${signal}`);
  rmSync(scratch, { recursive: true, force: true });
  process.exitCode = failed || code !== 0 ? 1 : 0;
});
