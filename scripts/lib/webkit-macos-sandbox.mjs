import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { constants, cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const resources = "WebKit.framework/Versions/A/Resources";
const profiles = [
  ["com.apple.WebKit.NetworkProcess.sb", ["com.apple.analyticsd", "com.apple.ReportMemoryException"]],
  ["com.apple.WebProcess.sb", ["com.apple.tccd"]],
];

// Security.framework now opens CoreAnalytics while CFNetwork initializes cookie
// storage. The bundled development profile permits that service only on Apple
// internal hosts; the lookup can block page creation on other Macs (#41870):
// https://github.com/microsoft/playwright/issues/41870
// CFNetwork's cookie-store diagnostics also open ReportMemoryException.
// AppKit's launch disclosure initializes the user TCC connection in WebContent.
// Keep these three service lookups in a private test-engine copy. Home's frame
// policy and the shared Playwright installation retain their original bytes.
export function webkitMacOSLaunchOptions(browserType, options, {
  platform,
  cacheRoot = join(homedir(), ".cache/elastos-runtime/webkit-macos"),
}) {
  if (platform !== "darwin" || browserType.name?.() !== "webkit" || options?.executablePath) return options;
  const executable = browserType.executablePath();
  if (basename(executable) !== "pw_run.sh" || !existsSync(executable)) return options;
  const source = realpathSync(dirname(executable));
  const patches = profiles.map(([name, services]) => {
    const path = join(resources, name);
    const original = readFileSync(join(source, path), "utf8");
    const missing = services.map(service => `(allow mach-lookup (global-name "${service}"))`)
      .filter(rule => !original.split("\n").includes(rule));
    return { path, original, patched: missing.length
      ? `${original}\n; ElastOS test engine: allow macOS initialization service lookups.\n${missing.join("\n")}\n`
      : original };
  });
  if (patches.every(({ original, patched }) => original === patched)) return options;
  const key = createHash("sha256").update(source).update(JSON.stringify(patches)).digest("hex").slice(0, 20);
  mkdirSync(cacheRoot, { recursive: true });
  const cache = realpathSync(cacheRoot);
  const target = join(cache, `${basename(source)}-${key}`);
  if (!existsSync(target)) {
    const scratch = mkdtempSync(join(cache, ".prepare-"));
    const identity = lstatSync(scratch);
    try {
      cpSync(source, scratch, { recursive: true, verbatimSymlinks: true, mode: constants.COPYFILE_FICLONE });
      for (const { path, patched } of patches) writeFileSync(join(scratch, path), patched);
      try { renameSync(scratch, target); }
      catch (error) {
        // Another test process can publish the same complete copy first.
        if (!["EEXIST", "ENOTEMPTY"].includes(error.code)) throw error;
      }
    } finally {
      execFileSync("python3", [fileURLToPath(new URL("./owned_removal.py", import.meta.url)),
        cache, basename(scratch), "--expect", `${identity.dev}:${identity.ino}`], { timeout: 10000 });
    }
  }
  for (const { path, patched } of patches) {
    if (readFileSync(join(target, path), "utf8") !== patched) {
      throw new Error(`WebKit test-engine profile differs from its source: ${join(target, path)}`);
    }
  }
  return { ...options, executablePath: join(target, "pw_run.sh") };
}
