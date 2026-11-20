import { AsyncLocalStorage } from "node:async_hooks";
import { tracingChannel } from "node:diagnostics_channel";
import { appendFileSync, mkdtempSync, readFileSync, rmdirSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const currentTest = new AsyncLocalStorage();
tracingChannel("node.test").start.bindStore(currentTest, ({ name, file }) => ({ name, file }));
const wrapped = new WeakMap();
let localRelaunches = 0;
let standalone = false;

function summary(count) {
  console.log(`Browser launch summary: ${count} relaunch(es); limit 3; ${count > 3 ? "FAIL" : "PASS"}`);
  return count > 3;
}

// The outer test-worker leader owns one ledger across file processes, smoke
// children and nested supervisors. Isolated fixtures clear the inherited path.
export function createBrowserLaunchRun({ reportRelaunches = false } = {}) {
  if (process.env.ELASTOS_BROWSER_LAUNCH_LEDGER) {
    return { ledger: process.env.ELASTOS_BROWSER_LAUNCH_LEDGER, finish: code => code };
  }
  const directory = mkdtempSync(join(tmpdir(), "browser-launch-run-"));
  const ledger = join(directory, "relaunches");
  writeFileSync(ledger, "", { mode: 0o600 });
  return { ledger, finish(code) {
    try {
      const events = readFileSync(ledger, "utf8").split("\n").filter(Boolean);
      // Rust's command.output() captures some successful smoke output. Its
      // outer caller replays the ledger so every relaunch remains visible.
      if (reportRelaunches) for (const event of events) console.log(event);
      return summary(events.length) ? 1 : code;
    } finally {
      unlinkSync(ledger);
      rmdirSync(directory);
    }
  } };
}

function trackStandalone() {
  if (process.env.ELASTOS_BROWSER_LAUNCH_LEDGER || standalone) return;
  standalone = true;
  process.on("exit", () => {
    if (summary(localRelaunches)) process.exitCode = 1;
  });
}

export function startupCrashSignal(error) {
  const message = String(error?.message ?? error);
  if (["TimeoutError", "AssertionError"].includes(error?.name) || /Timeout \d+ms exceeded/.test(message)) return null;
  const signal = message.match(/<process did exit: exitCode=(?:null|-?\d+), signal=(SIG[A-Z0-9]+)>/)?.[1];
  if (signal) return signal;
  const received = message.match(/<launched> pid=\d+[\s\S]*Received signal (\d+)/)?.[1];
  if (received) return `signal ${received}`;
  return /^browserType\.launch: (?:Target page, context or browser has been closed|Browser (?:has been )?closed)[.!]?(?:\n|$)/.test(message)
    ? "unreported (browser closed)" : null;
}

async function launch(browserType, options, site) {
  trackStandalone();
  try {
    // Only this promise is retried. All context, page and product work belongs
    // to the caller, after the returned browser has escaped this boundary.
    return await browserType.launch(options);
  } catch (first) {
    const signal = startupCrashSignal(first);
    if (!signal) throw first;
    const { name, file } = currentTest.getStore() ?? {};
    const label = String(name ? `${file}: ${name}` : site).replace(/\s+/g, " ").slice(0, 600);
    const event = `Browser launch relaunch: ${label}; engine=${browserType.name()}; signal=${signal}; attempt=2/2`;
    console.log(event);
    const ledger = process.env.ELASTOS_BROWSER_LAUNCH_LEDGER;
    if (ledger) appendFileSync(ledger, event + "\n"); // One O_APPEND write per event across processes.
    else localRelaunches++;
    try { return await browserType.launch(options); }
    catch (second) {
      throw new AggregateError([first, second], `Browser launch failed twice for ${label} (${browserType.name()}).\nAttempt 1:\n${first.stack ?? first}\nAttempt 2:\n${second.stack ?? second}`);
    }
  }
}

export function withBrowserLaunchRecovery(playwright) {
  if (wrapped.has(playwright)) return wrapped.get(playwright);
  const types = new Map();
  const result = new Proxy(playwright, { get(target, key) {
    if (!["chromium", "firefox", "webkit"].includes(key)) return Reflect.get(target, key);
    if (!types.has(key)) {
      const type = Reflect.get(target, key);
      if (!type) return type;
      types.set(key, new Proxy(type, { get(browserType, method) {
        if (method === "launch") return options => launch(browserType, options,
          new Error().stack?.split("\n").find(line => line.includes(".mjs:") && !line.includes("browser-launch-recovery.mjs:")) ?? process.argv[1]);
        // Persistent launch creates its first context/page internally. Its
        // rejected promise cannot prove that they never existed: preserve it.
        const value = Reflect.get(browserType, method);
        return typeof value === "function" ? value.bind(browserType) : value;
      } }));
    }
    return types.get(key);
  } });
  wrapped.set(playwright, result);
  wrapped.set(result, result);
  return result;
}
