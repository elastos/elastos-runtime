import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { constants, cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const profilePath = "WebKit.framework/Versions/A/Resources/com.apple.WebKit.NetworkProcess.sb";
const serviceRules = ["com.apple.analyticsd", "com.apple.ReportMemoryException"]
  .map(service => `(allow mach-lookup (global-name "${service}"))`);

// Security.framework now opens CoreAnalytics while CFNetwork initializes cookie
// storage. The bundled development profile permits that service only on Apple
// internal hosts; the lookup can block page creation on other Macs (#41870):
// https://github.com/microsoft/playwright/issues/41870
// CFNetwork's cookie-store diagnostics also open ReportMemoryException.
// Keep these two service lookups in a private test-engine copy. Home's frame
// policy and the shared Playwright installation retain their original bytes.
export function webkitMacOSLaunchOptions(browserType, options, {
  platform,
  cacheRoot = join(homedir(), ".cache/elastos-runtime/webkit-macos"),
}) {
  if (platform !== "darwin" || browserType.name?.() !== "webkit" || options?.executablePath) return options;
  const executable = browserType.executablePath();
  if (basename(executable) !== "pw_run.sh" || !existsSync(executable)) return options;
  const source = realpathSync(dirname(executable));
  const profile = readFileSync(join(source, profilePath), "utf8");
  const missing = serviceRules.filter(rule => !profile.split("\n").includes(rule));
  if (!missing.length) return options;
  const patched = `${profile}\n; ElastOS test engine: allow macOS cookie-store diagnostic lookups.\n${missing.join("\n")}\n`;
  const key = createHash("sha256").update(source).update(patched).digest("hex").slice(0, 20);
  mkdirSync(cacheRoot, { recursive: true });
  const cache = realpathSync(cacheRoot);
  const target = join(cache, `${basename(source)}-${key}`);
  if (!existsSync(target)) {
    const scratch = mkdtempSync(join(cache, ".prepare-"));
    const identity = lstatSync(scratch);
    try {
      cpSync(source, scratch, { recursive: true, verbatimSymlinks: true, mode: constants.COPYFILE_FICLONE });
      writeFileSync(join(scratch, profilePath), patched);
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
  if (readFileSync(join(target, profilePath), "utf8") !== patched) {
    throw new Error(`WebKit test-engine profile differs from its source: ${target}`);
  }
  return { ...options, executablePath: join(target, "pw_run.sh") };
}
