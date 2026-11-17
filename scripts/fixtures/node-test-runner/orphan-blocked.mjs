import test from "node:test";
import { writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
test("orphaned blocked worker", () => {
  const worker = Number(execFileSync("ps", ["-p", String(process.pid), "-o", "pgid="], { encoding: "utf8", timeout: 5000 }).trim());
  writeFileSync(process.env.NODE_TEST_GUARD_READY, JSON.stringify({ worker, runner: process.ppid, test: process.pid }));
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0);
});
