// Raw launches, deliberately outside recovery, measure both suite executables.
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { existsSync, readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { behaviourInputsDir, productSmokeLaunchOptions } from "./product-smoke-browser.mjs";

const count = Number(process.argv[2] || 600);
assert.ok(Number.isSafeInteger(count) && count >= 1);
const root = join(behaviourInputsDir(), "browser", "node_modules", "playwright");
const { chromium } = createRequire(join(root, "package.json"))(root);
console.log(JSON.stringify({ environment: { node: process.version, platform: process.platform,
  kernel: execFileSync("uname", ["-sr"], { encoding: "utf8" }).trim(),
  systemBus: existsSync("/run/dbus/system_bus_socket"),
  sharedMemory: execFileSync("df", ["-k", "/dev/shm"], { encoding: "utf8" }).trim(),
  cpu: readFileSync("/proc/cpuinfo", "utf8").match(/^model name\s*:\s*(.+)$/m)?.[1],
} }));
for (const [executable, options] of [
  ["full", { headless: true, ...productSmokeLaunchOptions() }],
  ["shell", { headless: true }],
]) {
  const started = performance.now();
  let crashes = 0;
  console.log(`STEP launch measurement ${executable}: ${count} attempts; ${options.executablePath || "Playwright default headless shell"}`);
  for (let attempt = 1; attempt <= count; attempt++) {
    let browser;
    try {
      browser = await chromium.launch(options);
    } catch (error) {
      const log = String(error);
      if (!/Target page, context or browser has been closed|signal=SIG[A-Z]+|Received signal \d+/.test(log) || /Timeout.*exceeded/.test(log)) throw error;
      crashes++;
      console.log(JSON.stringify({ executable, attempt, crash: log }));
    }
    if (browser) {
      try { assert.equal(browser.contexts().length, 0); }
      finally { await browser.close(); }
    }
    if (attempt % 100 === 0) console.log(`STEP ${executable} ${attempt}/${count}: ${crashes} startup crashes`);
  }
  console.log(JSON.stringify({ measurement: executable, attempts: count, crashes,
    rate: crashes / count, seconds: Number(((performance.now() - started) / 1000).toFixed(3)) }));
}
