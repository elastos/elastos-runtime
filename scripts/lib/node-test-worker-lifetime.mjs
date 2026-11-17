import { spawn } from "node:child_process";
import { Socket } from "node:net";
import { inspect } from "./owned-test-worker.mjs";

// This is the group leader's entrypoint: Node --test defers --import preloads
// to test-file children. A blocked test cannot block this lifetime watcher.
const owner = Number(process.env.NODE_TEST_GUARD_OWNER);
const started = inspect(process.pid).worker;
if (!Number.isSafeInteger(owner) || owner <= 1 || started?.parent !== owner || started.group !== process.pid) {
  throw new Error("test worker did not start as its supervisor's new group leader");
}
function stopOwnGroup() {
  const current = inspect(process.pid).worker;
  if (current?.group !== process.pid || current.birth !== started.birth) {
    throw new Error("orphaned test worker could not verify its own group");
  }
  // The live session leader reserves its PID throughout inspection and signal.
  process.kill(-process.pid, "SIGKILL");
}
const lifetime = new Socket({ fd: 4 });
lifetime.on("end", stopOwnGroup);
lifetime.on("error", stopOwnGroup);
lifetime.resume();
lifetime.unref(); // Normal completion does not wait for the supervisor to exit.
process.on("exit", () => {
  // process.ppid is a startup value in Node; inspect the live kernel parent.
  if (inspect(process.pid).worker?.parent !== owner) stopOwnGroup();
});
const env = { ...process.env };
const events = env.NODE_TEST_GUARD_EVENTS === "1" ? 3 : "ignore";
delete env.NODE_TEST_GUARD_OWNER;
delete env.NODE_TEST_GUARD_EVENTS;
const child = spawn(process.execPath, process.argv.slice(2), { env, stdio: ["ignore", "inherit", "inherit", events] });
child.on("error", error => { console.error(error.message); process.exitCode = 1; });
child.on("exit", code => { process.exitCode = code ?? 1; });
