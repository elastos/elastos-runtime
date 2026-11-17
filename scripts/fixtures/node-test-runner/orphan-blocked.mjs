import test from "node:test";
import { renameSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
test("orphaned blocked worker", () => {
  const worker = Number(execFileSync("ps", ["-p", String(process.pid), "-o", "pgid="], { encoding: "utf8", timeout: 5000 }).trim());
  const ready = process.env.NODE_TEST_GUARD_READY;
  // File existence means complete JSON, including when the writer is paused.
  writeFileSync(`${ready}.pending`, JSON.stringify({ worker, runner: process.ppid, test: process.pid }));
  renameSync(`${ready}.pending`, ready);
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0);
});
