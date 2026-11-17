import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
for (let index = 0; index < 16; index++) {
  test(`synchronous progress ${index}`, () => {
    const result = spawnSync(process.execPath, ["-e", "Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500)"]);
    assert.equal(result.status, 0, result.stderr);
  });
}
