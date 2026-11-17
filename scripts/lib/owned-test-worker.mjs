import { execFileSync, spawn } from "node:child_process";

function inspect(pid) {
  const output = execFileSync("ps", ["-p", [process.pid, pid].filter(Number.isSafeInteger).join(","),
    "-o", "pid=,ppid=,pgid=,lstart=,stat="], { encoding: "utf8", timeout: 5000, maxBuffer: 64 * 1024 });
  const rows = new Map();
  for (const line of output.split("\n")) {
    const match = line.match(/^\s*(\d+)\s+(\d+)\s+(\d+)\s+(.+?)\s+(\S+)\s*$/);
    if (match) rows.set(Number(match[1]), { pid: Number(match[1]), parent: Number(match[2]),
      group: Number(match[3]), birth: match[4], state: match[5] });
  }
  return { worker: rows.get(pid), supervisor: rows.get(process.pid) };
}

export function canSignalWorkerGroup(started, current, supervisor, exited, supervisorPid) {
  return Boolean(!exited && started && current && supervisor &&
    Number.isSafeInteger(started.pid) && started.pid > 1 && started.pid !== supervisorPid &&
    supervisor.pid === supervisorPid && supervisor.group > 0 &&
    started.parent === supervisorPid && started.group === started.pid &&
    current.pid === started.pid && current.parent === supervisorPid &&
    current.group === started.pid && current.group !== supervisor.group &&
    typeof started.birth === "string" && started.birth.length > 0 && current.birth === started.birth &&
    typeof current.state === "string" && current.state.length > 0 && !current.state.includes("Z"));
}

export function spawnOwnedTestWorker(args, options) {
  inspect(); // Refuse a missing process inspector before starting any workers.
  const child = spawn(process.execPath, args, { ...options, detached: true });
  let exited = false;
  let signalled = false;
  child.once("exit", () => { exited = true; });
  child.once("error", () => { exited = true; });
  let started;
  try { started = inspect(child.pid).worker; }
  catch (error) { child.kill("SIGKILL"); throw error; }
  return {
    child,
    stop() {
      if (signalled || exited || child.exitCode !== null || child.signalCode !== null) return false;
      // Keep inspection and signal synchronous: the main loop cannot reap this
      // direct child between them, so its PID stays reserved even if it exits.
      const current = inspect(child.pid);
      if (!canSignalWorkerGroup(started, current.worker, current.supervisor,
        exited || child.exitCode !== null || child.signalCode !== null, process.pid)) return false;
      signalled = true;
      try { process.kill(-started.pid, "SIGKILL"); }
      catch (error) { if (error.code !== "ESRCH") throw error; return false; }
      return true;
    },
  };
}
