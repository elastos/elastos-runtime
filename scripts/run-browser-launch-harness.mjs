// The Rust caller owns the launch budget; all smoke children inherit its ledger.
import { spawn } from "node:child_process";
import { createBrowserLaunchRun } from "./lib/browser-launch-recovery.mjs";

const [command, ...args] = process.argv.slice(2);
if (!command) throw new Error("usage: node scripts/run-browser-launch-harness.mjs COMMAND [ARG...]");
const run = createBrowserLaunchRun({ reportRelaunches: true });
const child = spawn(command, args, {
  env: { ...process.env, ELASTOS_BROWSER_LAUNCH_LEDGER: run.ledger },
  stdio: "inherit",
});
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => child.kill(signal));
}
child.on("error", error => console.error(error));
child.on("close", code => { process.exitCode = run.finish(code ?? 1); });
