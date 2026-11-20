import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
const child = spawn(process.execPath, process.argv.slice(2), { stdio: ["ignore", "inherit", "inherit"] });
process.send({ supervisor: child.pid });
process.on("message", signal => {
  if (signal === "gate-group-SIGKILL") {
    // This fixture was created as a new group leader by its guard. The signal
    // models the gate's group being killed; it is not agent housekeeping.
    const group = Number(execFileSync("ps", ["-p", String(process.pid), "-o", "pgid="], { encoding: "utf8", timeout: 5000 }).trim());
    assert.equal(group, process.pid);
    process.kill(-process.pid, "SIGKILL");
  } else child.kill(signal);
});
