// Model descheduling after open(O_CREAT), before the readiness JSON write.
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
const write = fs.writeFileSync;
const ready = process.env.NODE_TEST_GUARD_READY;
fs.writeFileSync = function (path, data, ...options) {
  if (ready && (path === ready || path === `${ready}.pending`)) {
    const fd = fs.openSync(path, "w");
    write(`${ready}.opened`, "");
    while (!fs.existsSync(`${ready}.release`)) {
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
    }
    try { return write(fd, data, ...options); }
    finally { fs.closeSync(fd); }
  }
  return write(path, data, ...options);
};
syncBuiltinESMExports();
