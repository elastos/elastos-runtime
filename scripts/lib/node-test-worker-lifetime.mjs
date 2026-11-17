import { spawn } from "node:child_process";
import { Socket } from "node:net";
import { writeSync } from "node:fs";
import { inspect } from "./owned-test-worker.mjs";

// This is the group leader's entrypoint: Node --test defers --import preloads
// to test-file children. A blocked test cannot block this lifetime watcher.
const owner = Number(process.env.NODE_TEST_GUARD_OWNER);
const started = inspect(process.pid).worker;
if (!Number.isSafeInteger(owner) || owner <= 1 || started?.parent !== owner || started.group !== process.pid) {
  throw new Error("test worker did not start as its supervisor's new group leader");
}
let child;
let stopping = false;
function stopOwnGroup(checkError) {
  if (stopping) return;
  stopping = true;
  try {
    if (checkError) throw checkError;
    const current = inspect(process.pid).worker;
    if (current?.group !== process.pid || current.birth !== started.birth) {
      throw new Error("orphaned test worker could not verify its own group");
    }
    // The live session leader reserves its PID throughout inspection and signal.
    process.kill(-process.pid, "SIGKILL");
  } catch (error) {
    console.error(`Node test guard: group check failed; stopping only owned Node process: ${error.message}`);
    process.exitCode = 1;
    child?.kill("SIGKILL");
  }
}
const lifetime = new Socket({ fd: 4 });
lifetime.on("end", stopOwnGroup);
lifetime.on("error", () => stopOwnGroup());
lifetime.resume();
lifetime.unref(); // Normal completion does not wait for the supervisor to exit.
process.on("exit", () => {
  if (stopping) return;
  // process.ppid is a startup value in Node; inspect the live kernel parent.
  try {
    if (inspect(process.pid).worker?.parent !== owner) stopOwnGroup();
  } catch (error) { stopOwnGroup(error); }
});
const env = { ...process.env };
const events = env.NODE_TEST_GUARD_EVENTS === "1" ? 3 : "ignore";
delete env.NODE_TEST_GUARD_OWNER;
delete env.NODE_TEST_GUARD_EVENTS;
child = spawn(process.execPath, process.argv.slice(2), { env, stdio: ["ignore", "inherit", "inherit", events] });
child.on("error", error => { console.error(error.message); process.exitCode = 1; });
child.on("exit", (code, signal) => {
  if (signal && events === 3) {
    try { writeSync(3, `${JSON.stringify({ type: "worker:signal", data: { signal } })}\n`); }
    catch (error) { if (error.code !== "EPIPE") throw error; }
  }
  process.exitCode = code ?? 1;
});
