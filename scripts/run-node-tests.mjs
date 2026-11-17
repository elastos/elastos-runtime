// The supervisor owns the verdict. A zero child exit also needs a complete
// event stream from every file, even when the child calls process.exit(0).
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

const args = process.argv.slice(2);
const timeout = args[0]?.startsWith("--timeout=") ? Number(args.shift().split("=")[1]) : 60_000;
if (!Number.isSafeInteger(timeout) || timeout < 1 || !args.length || args.some(arg => arg.startsWith("-"))) {
  throw new Error("usage: node scripts/run-node-tests.mjs [--timeout=milliseconds] FILE...");
}
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
const child = spawn(process.execPath, [
  "--test", `--import=${reporter}`, `--test-timeout=${timeout}`, "--test-reporter=spec", "--test-reporter-destination=stdout",
  `--test-reporter=${reporter}`, "--test-reporter-destination=stderr", ...args,
], { env, detached: true, stdio: ["ignore", "inherit", "inherit", "pipe"] });
let failed = false;
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
  // This process group belongs only to this invocation, including test helpers.
  try { process.kill(-child.pid, "SIGKILL"); } catch (error) { if (error.code !== "ESRCH") throw error; }
}
function arm(file, state) {
  clearTimeout(state.timer);
  state.timer = setTimeout(() => {
    fail(`${relative(process.cwd(), file)}: timed out after ${timeout}ms; first unfinished: ${label(state.pending.values().next().value ?? lastStarted(file, state))}`);
    stop();
  }, timeout);
}
const lines = createInterface({ input: child.stdio[3] });
lines.on("line", line => {
  try {
    const { type, data } = JSON.parse(line);
    if (type === "test:summary" && !data.file) {
      summary = true;
      if (!data.success) failed = true;
      return;
    }
    const file = canonical(data.file);
    if (!file) return;
    if (!files.has(file)) files.set(file, { pending: new Map(), summary: false, timer: null, last: null, required: false });
    const state = files.get(file);
    if (type === "test:dequeue") clearTimeout(startup);
    // Node's outer FileTest shares the child's test IDs; it is a process result,
    // not a verdict for any test declared inside that file.
    const wrapper = state.required && (data.name === file || data.name === relative(process.cwd(), file));
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
    if (state.required && (type === "test:dequeue" || type === "test:complete" || type === "test:summary")) arm(file, state);
    if (wrapper && type === "test:complete") clearTimeout(state.timer);
  } catch (error) {
    fail(`invalid or unreadable event: ${error.message}`);
    stop();
  }
});
child.on("error", error => fail(error.message));
for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => { fail(`interrupted by ${signal}`); stop(); });
child.on("close", (code, signal) => {
  clearTimeout(startup);
  for (const [file, state] of files) {
    clearTimeout(state.timer);
    if ((state.required && !state.summary) || state.pending.size) {
      fail(`${relative(process.cwd(), file)}: incomplete results; first unfinished: ${label(state.pending.values().next().value ?? lastStarted(file, state))}; ${state.pending.size} declared test(s) without a result; file summary ${state.summary ? "received" : "missing"}`);
    }
  }
  if (!summary) fail("run summary missing");
  if (signal) fail(`runner killed by ${signal}`);
  rmSync(scratch, { recursive: true, force: true });
  process.exitCode = failed || code !== 0 ? 1 : 0;
});
